std::shared_ptr<Libs::LibKernel::ExfatVolume> OpenExfatMountFixture(
    const std::filesystem::path& root, bool partial = false) {
  using Volume = Libs::LibKernel::ExfatVolume;
  using Backing = Libs::LibKernel::SectorBacking;
  auto bytes = ExfatTestFixture::Fixture();
  if (partial) bytes.resize(46 * 512);
  const auto image = root / (partial ? "exfat_mount_partial.bin" : "exfat_mount.bin");
  { std::ofstream output(image, std::ios::binary);
    output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    Check(output.good(), "write owned exfat mount fixture"); }
  Backing::Result media;
  std::shared_ptr<Backing> backing = Backing::Open(image, {}, 512, 2048 * 512,
      partial ? "0d6eb08e5edb11551a7fb7614f8b227eae11518751226f805f44743dede78256" :
                "0157195d5d05a1f7ba4707292771a374b9356ad00d85288988f0ca54ada1c63a", &media);
  Check(backing && media == Backing::Result::Ok, "open hash-bound readonly mount backing");
  Volume::Result result;
  std::shared_ptr<Volume> volume = Volume::Open(std::move(backing), &result);
  Check(volume && result == Volume::Result::Ok, "index verified exfat mount fixture");
  return volume;
}
void CheckExfatMountBackend(const std::filesystem::path& root) {
  namespace Mount = Libs::LibKernel::ExfatMount;
  namespace Kernel = Libs::LibKernel;
  auto volume = OpenExfatMountFixture(root);
  Check(Mount::Mount("/exfat-test", volume) == OK &&
        Mount::Mount("/exfat-test", volume) == Kernel::KERNEL_ERROR_EBUSY &&
        Mount::Mount("/EXFAT-TEST", volume) == Kernel::KERNEL_ERROR_EBUSY &&
        Mount::Mount("/exfat-test/sub", volume) == Kernel::KERNEL_ERROR_EBUSY &&
        !Mount::Contains("/exfat-tests/hello.bin"), "mount registry rejects overlap and respects component boundaries");
  std::shared_ptr<Mount::Handle> first, second, directory;
  Check(Mount::Open("/exfat-test/HELLO.BIN", 0, &first) == OK &&
        Mount::Open("/exfat-test/hello.bin", 0, &second) == OK &&
        Mount::Open("/exfat-test/sub", 0x20000, &directory) == OK,
        "readonly handles resolve case-insensitive names");
  std::array<char, 16> bytes {};
  Check(Mount::Read(first, bytes.data(), 2) == 2 && std::memcmp(bytes.data(), "HE", 2) == 0 &&
        Mount::Seek(first, 0, 1) == 2 && Mount::Seek(second, 0, 1) == 0 &&
        Mount::Pread(first, bytes.data(), 5, 0) == 5 && std::memcmp(bytes.data(), "HELLO", 5) == 0 &&
        Mount::Seek(first, 0, 1) == 2 && Mount::Read(first, bytes.data(), bytes.size()) == 3 &&
        std::memcmp(bytes.data(), "LLO", 3) == 0 && Mount::Read(first, nullptr, 0) == 0,
        "sequential reads advance one handle while positioned reads preserve offsets");
  Check(Mount::Seek(first, INT64_MIN, 1) == Kernel::KERNEL_ERROR_EINVAL &&
        Mount::Seek(first, INT64_MAX, 0) == INT64_MAX &&
        Mount::Seek(first, 1, 1) == Kernel::KERNEL_ERROR_EOVERFLOW &&
        Mount::Read(first, bytes.data(), 1) == 0, "seek overflow and past EOF retain coherent state");
  Mount::NodeStat stat {}, by_path {};
  Check(Mount::Fstat(first, &stat) == OK && Mount::Stat("/exfat-test/hello.bin", &by_path) == OK &&
        stat.inode == by_path.inode && stat.device == by_path.device && stat.size == 5 &&
        (stat.mode & 0170000) == 0100000, "path and descriptor metadata identify the same indexed node");
  std::vector<Mount::DirectoryEntry> entries;
  Check(Mount::Entries(directory, &entries) == OK && entries.size() == 1 && entries[0].name == "empty" &&
        Mount::Stat("/exfat-test/sub/empty", &stat) == OK && entries[0].inode == stat.inode,
        "directory entries use inode identity consistent with stat");
  std::shared_ptr<Mount::Handle> failed;
  Check(Mount::Open("/exfat-test/hello.bin", 2, &failed) == Kernel::KERNEL_ERROR_EROFS &&
        Mount::Open("/exfat-test/new", 0x200, &failed) == Kernel::KERNEL_ERROR_EROFS &&
        Mount::Open("/exfat-test/hello.bin", 3, &failed) == Kernel::KERNEL_ERROR_EINVAL &&
        Mount::Open("/exfat-test/hello.bin", 0x20000, &failed) == Kernel::KERNEL_ERROR_ENOTDIR &&
        Mount::ValidateTraversal("/exfat-test/hello.bin/../sub") == Kernel::KERNEL_ERROR_ENOTDIR &&
        Mount::Stat("/exfat-test/hello.bin/", &stat) == Kernel::KERNEL_ERROR_ENOTDIR &&
        Mount::Stat("/exfat-test/sub/../hello.bin", &stat) == OK &&
        Mount::Stat("/exfat-test/\xc0\xaf", &stat) == Kernel::KERNEL_ERROR_EILSEQ &&
        Mount::Open("/exfat-test/hello.bin", 0, nullptr) == Kernel::KERNEL_ERROR_EFAULT,
        "readonly mount preserves exact errors and validates traversal before dotdot");
  Check(Mount::Unmount("/EXFAT-TEST") == OK && !Mount::Contains("/exfat-test/hello.bin") &&
        Mount::Open("/exfat-test/hello.bin", 0, &failed) == Kernel::KERNEL_ERROR_ENOENT &&
        Mount::Pread(second, bytes.data(), 5, 0) == 5 && std::memcmp(bytes.data(), "HELLO", 5) == 0 &&
        Mount::Entries(directory, &entries) == OK,
        "unmount removes namespace while pinned file and directory handles remain usable");
  const auto old_device = by_path.device;
  Check(Mount::Mount("/exfat-test", volume) == OK && Mount::Stat("/exfat-test/hello.bin", &stat) == OK &&
        stat.device != old_device && Mount::Fstat(second, &by_path) == OK && by_path.device == old_device,
        "remount creates a distinct mount identity without rebinding old handles");
  Check(Mount::Unmount("/exfat-test") == OK && Mount::Close(first) == OK &&
        Mount::Close(second) == OK && Mount::Close(directory) == OK &&
        Mount::Close(first) == Kernel::KERNEL_ERROR_EBADF, "release independent pinned handles");
  auto partial = OpenExfatMountFixture(root, true);
  Check(Mount::Mount("/exfat-partial", partial) == OK &&
        Mount::Open("/exfat-partial/chain.bin", 0, &first) == OK,
        "mount known metadata with uncaptured file tail");
  std::array<uint8_t, 150> unchanged;
  unchanged.fill(0xa5);
  Check(Mount::Seek(first, 500, 0) == 500 &&
        Mount::Read(first, unchanged.data(), unchanged.size()) == Kernel::KERNEL_ERROR_EIO &&
        Mount::Seek(first, 0, 1) == 500 &&
        std::all_of(unchanged.begin(), unchanged.end(), [](auto byte) { return byte == 0xa5; }),
        "uncaptured extents fail atomically and preserve descriptor offset");
  Check(Mount::Pread(first, unchanged.data(), 100, 600) == 100 && unchanged[0] == 0 && unchanged[99] == 0 &&
        Mount::Unmount("/exfat-partial") == OK && Mount::Close(first) == OK,
        "logical valid-data zero range remains distinct from missing captured sectors");
}
