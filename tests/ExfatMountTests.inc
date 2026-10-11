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

#if !defined(KYTY_EXFAT_BACKEND_ONLY)
void CheckExfatGuestMount(const std::filesystem::path& root) {
  namespace Kernel = Libs::LibKernel;
  auto volume = OpenExfatMountFixture(root);
  const auto underlay = root / "exfat-underlay";
  Check(std::filesystem::create_directory(underlay) &&
        std::filesystem::create_directory(underlay / "media"), "create existing exfat mountpoint underlay");
  { std::ofstream hidden(underlay / "media" / "hello.bin", std::ios::binary);
    hidden.write("UNDERLAY", 8);
    Check(hidden.good(), "create distinct host file covered by exfat mount"); }
  FileSystem::MountReadOnly(underlay, "/exfat-underlay");
  FileSystem::MountReadOnly(underlay, "/exfat-underlay/media/host-child");
  FileSystem::FileStat underlay_stat {};
  Check(FileSystem::MountExfatReadOnly("/exfat-underlay/media", volume) == Kernel::KERNEL_ERROR_EBUSY &&
        FileSystem::MountExfatReadOnly("/exfat-underlay/MEDIA", volume) == Kernel::KERNEL_ERROR_EBUSY &&
        FileSystem::KernelStat("/exfat-underlay/media/hello.bin", &underlay_stat) == OK && underlay_stat.st_size == 8 &&
        !FileSystem::GetRealFilename("/exfat-underlay/media/hello.bin").empty(),
        "exfat mount cannot hide an existing host descendant or partially publish a failed mount");
  FileSystem::Umount("/exfat-underlay/media/host-child");
  Check(FileSystem::MountExfatReadOnly("/exfat-underlay/media", volume) == OK,
        "mount explicit verified volume through guest filesystem");
  const int ancestor_mount = FileSystem::MountTmpfs("/exfat-underlay", 0755, 262144, 32);
  std::printf("EXFAT_MIXED_ANCESTOR_REPRO result=0x%x expected=0x%x\n", ancestor_mount, Kernel::KERNEL_ERROR_EBUSY);
  if (ancestor_mount == OK) FileSystem::Umount("/exfat-underlay");
  Check(ancestor_mount == Kernel::KERNEL_ERROR_EBUSY &&
        FileSystem::MountTmpfs("/exfat-underlay/media/sub", 0755, 262144, 32) == Kernel::KERNEL_ERROR_EBUSY,
        "tmpfs cannot overlap an active exfat ancestor or descendant");
  FileSystem::MountReadOnly(underlay, "/exfat-underlay/media/sub");
  const int fd = FileSystem::KernelOpen("/exfat-underlay/media/hello.bin", 0, 0);
  const int directory = FileSystem::KernelOpen("/exfat-underlay/media/sub", 0x20000, 0);
  std::array<char, 1024> bytes {};
  const int alias = FileSystem::KernelOpen("/exfat-underlay/MEDIA/hello.bin", 0, 0);
  const auto alias_read = alias >= 3 ? FileSystem::KernelRead(alias, bytes.data(), 8) : alias;
  if (alias >= 3) Check(FileSystem::KernelClose(alias) == OK, "close case alias fixture descriptor");
  std::printf("EXFAT_CASE_ALIAS_REPRO bytes=%lld prefix=%.8s\n", static_cast<long long>(alias_read), bytes.data());
  Check(alias_read == 5 && std::memcmp(bytes.data(), "HELLO", 5) == 0 &&
        FileSystem::GetRealFilename("/exfat-underlay/MEDIA/hello.bin").empty(),
        "mountpoint case alias cannot reveal the covered host file");
  FileSystem::FileStat stat {}, by_path {};
  Check(fd >= 3 && directory >= 3 && FileSystem::KernelRead(fd, bytes.data(), 2) == 2 &&
        std::memcmp(bytes.data(), "HE", 2) == 0 && FileSystem::KernelLseek(fd, 0, 1) == 2 &&
        FileSystem::KernelPread(fd, bytes.data(), 5, 0) == 5 && std::memcmp(bytes.data(), "HELLO", 5) == 0 &&
        FileSystem::KernelLseek(fd, 0, 1) == 2 && FileSystem::KernelFstat(fd, &stat) == OK && stat.st_size == 5 &&
        FileSystem::KernelStat("/exfat-underlay/media/HELLO.BIN", &by_path) == OK && stat.st_ino == by_path.st_ino &&
        FileSystem::KernelGetdents(directory, bytes.data(), bytes.size()) > 0,
        "guest descriptor reads, positioned reads, stat and getdents use exfat data");
  Check(FileSystem::KernelPread(fd, reinterpret_cast<void*>(1), 1, 0) == Kernel::KERNEL_ERROR_EFAULT &&
        FileSystem::KernelOpen("/exfat-underlay/media/hello.bin", 2, 0) == Kernel::KERNEL_ERROR_EROFS &&
        FileSystem::KernelUnlink("/exfat-underlay/media/hello.bin") == Kernel::KERNEL_ERROR_EROFS &&
        FileSystem::KernelMkdir("/exfat-underlay/media/new", 0777) == Kernel::KERNEL_ERROR_EROFS &&
        FileSystem::KernelRename("/exfat-underlay/media/hello.bin", "/exfat-underlay/media/new") == Kernel::KERNEL_ERROR_EROFS &&
        FileSystem::KernelStat("/exfat-underlay/media/hello.bin/child", &by_path) == Kernel::KERNEL_ERROR_ENOTDIR,
        "guest mounted paths reject mutation and invalid pointers without host fallback");
  Check(FileSystem::GetRealFilename("/exfat-underlay/media/hello.bin").empty() &&
        FileSystem::KernelOpen("/exfat-underlay/media/hello.bin/../../outside", 0, 0) == Kernel::KERNEL_ERROR_ENOTDIR &&
        FileSystem::KernelGetdents(directory, reinterpret_cast<char*>(1), bytes.size()) == Kernel::KERNEL_ERROR_EFAULT &&
        FileSystem::KernelRead(fd, nullptr, 0) == 0 &&
        FileSystem::KernelWrite(fd, nullptr, 0) == Kernel::KERNEL_ERROR_EBADF &&
        FileSystem::KernelPwrite(fd, bytes.data(), 1, 0) == Kernel::KERNEL_ERROR_EBADF &&
        FileSystem::KernelFtruncate(fd, 0) == Kernel::KERNEL_ERROR_EBADF,
        "exfat descriptors preserve access errors and prevent traversal from escaping through a file");
  FileSystem::Umount("/exfat-underlay/MEDIA");
  const int restored = FileSystem::KernelOpen("/exfat-underlay/media/hello.bin", 0, 0);
  Check(restored >= 3 && FileSystem::KernelRead(restored, bytes.data(), 8) == 8 &&
        std::memcmp(bytes.data(), "UNDERLAY", 8) == 0 && FileSystem::KernelClose(restored) == OK &&
        FileSystem::KernelOpen("/exfat-underlay/media/sub/media", 0, 0) == Kernel::KERNEL_ERROR_ENOENT &&
        FileSystem::KernelPread(fd, bytes.data(), 5, 0) == 5 && std::memcmp(bytes.data(), "HELLO", 5) == 0 &&
        FileSystem::KernelLseek(directory, 0, 0) == 0 &&
        FileSystem::KernelGetdents(directory, bytes.data(), bytes.size()) > 0 &&
        FileSystem::KernelClose(fd) == OK && FileSystem::KernelClose(directory) == OK,
        "guest unmount hides namespace without invalidating existing file and directory handles");
  Check(FileSystem::MountTmpfs("/exfat-underlay/media", 0755, 262144, 32) == OK &&
        FileSystem::MountExfatReadOnly("/exfat-underlay", volume) == Kernel::KERNEL_ERROR_EBUSY &&
        FileSystem::MountExfatReadOnly("/exfat-underlay/media", volume) == Kernel::KERNEL_ERROR_EBUSY,
        "exfat cannot overlap an active tmpfs ancestor or descendant");
  Check(FileSystem::MountExfatReadOnly("/exfat-underlay/MEDIA", volume) == Kernel::KERNEL_ERROR_EBUSY,
        "case alias cannot evade tmpfs and exfat overlap guard");
  FileSystem::Umount("/exfat-underlay/media");
  FileSystem::Umount("/exfat-underlay");
}

void CheckExfatOriginalGuestMount(const std::filesystem::path& root,
    const std::filesystem::path& image, uint64_t capacity, const std::string& hash,
    const std::filesystem::path& extracted) {
  namespace Kernel = Libs::LibKernel;
  using Backing = Kernel::SectorBacking;
  using Volume = Kernel::ExfatVolume;
  Backing::Result media;
  std::shared_ptr<Backing> backing = Backing::Open(image, {}, 4096, capacity, hash, &media);
  Check(backing && media == Backing::Result::Ok, "open immutable hash-bound exfat image");
  Volume::Result indexed;
  std::shared_ptr<Volume> volume = Volume::Open(backing, &indexed);
  Check(volume && indexed == Volume::Result::Ok, "validate supplied image metadata");
  const auto underlay = root / "exfat-original-underlay";
  Check(std::filesystem::create_directory(underlay) && std::filesystem::create_directory(underlay / "media"),
        "create explicit image mountpoint");
  FileSystem::MountReadOnly(underlay, "/exfat-original-underlay");
  const std::string point = "/exfat-original-underlay/media";
  Check(FileSystem::MountExfatReadOnly(point, volume) == OK, "explicit image mounts without device publication");
  void* memory = nullptr;
  Check(Kernel::Memory::KernelMapNamedFlexibleMemory(&memory, 1024 * 1024, 3, 0,
        "original_exfat_guest_read") == OK, "allocate registered guest original-file read buffer");
  std::vector<uint8_t> expected(1024 * 1024);
  size_t files = 0, directories = 0;
  uint64_t compared = 0;
  const auto audit = [&](const auto& self, const std::u16string& path) -> void {
    std::vector<Volume::Entry> entries;
    Check(volume->List(path, &entries) == Volume::Result::Ok, "enumerate independently indexed directory");
    const auto relative_dir = std::filesystem::path(path.substr(1)).generic_u8string();
    const auto guest_dir = point + "/" + std::string(reinterpret_cast<const char*>(relative_dir.data()), relative_dir.size());
    const int directory = FileSystem::KernelOpen(guest_dir.c_str(), 0x20000, 0);
    Check(directory >= 3, "guest opens directory from sector-backed mount");
    std::vector<std::pair<std::string, uint32_t>> names;
    for (;;) {
      const int listed = FileSystem::KernelGetdents(directory, static_cast<char*>(memory), 1024 * 1024);
      Check(listed >= 0, "guest enumerates directory records");
      if (!listed) break;
      for (size_t offset = 0; offset < static_cast<size_t>(listed);) {
        const auto* record = static_cast<const uint8_t*>(memory) + offset;
        uint16_t length = 0;
        uint32_t inode = 0;
        Check(static_cast<size_t>(listed) - offset >= 8, "guest dirent header stays within returned bytes");
        std::memcpy(&length, record + 4, sizeof(length));
        std::memcpy(&inode, record, sizeof(inode));
        Check(length >= 9 && length <= static_cast<size_t>(listed) - offset &&
              record[7] < length - 8 && record[8 + record[7]] == 0 && (record[6] == 4 || record[6] == 8),
              "guest dirent record length, name and type are valid");
        std::string name(reinterpret_cast<const char*>(record + 8), record[7]);
        const auto found = std::find_if(entries.begin(), entries.end(), [&](const auto& entry) {
          const auto encoded = std::filesystem::path(entry.path.substr(entry.path.rfind(u'/') + 1)).generic_u8string();
          return name == std::string(reinterpret_cast<const char*>(encoded.data()), encoded.size());
        });
        Check(found != entries.end() && found->Directory() == (record[6] == 4),
              "guest dirent names and types match independently indexed records");
        Check(std::none_of(names.begin(), names.end(), [&](const auto& entry) { return entry.first == name; }),
              "guest directory stream does not repeat entries");
        names.emplace_back(std::move(name), inode);
        offset += length;
      }
    }
    Check(names.size() == entries.size() && FileSystem::KernelClose(directory) == OK,
          "guest directory stream lists every entry exactly once");
    for (const auto& entry: entries) {
      if (entry.Directory()) { ++directories; self(self, entry.path); continue; }
      const auto relative = std::filesystem::path(entry.path.substr(1)).generic_u8string();
      const auto guest = point + "/" + std::string(reinterpret_cast<const char*>(relative.data()), relative.size());
      const int fd = FileSystem::KernelOpen(guest.c_str(), 0, 0);
      FileSystem::FileStat stat {}, by_path {};
      Check(fd >= 3 && FileSystem::KernelFstat(fd, &stat) == OK && stat.st_size == static_cast<int64_t>(entry.size) &&
            FileSystem::KernelStat(guest.c_str(), &by_path) == OK && stat.st_ino == by_path.st_ino && stat.st_dev == by_path.st_dev,
            "guest path and descriptor stat agree for file");
      const auto basename16 = entry.path.substr(entry.path.rfind(u'/') + 1);
      const auto basename8 = std::filesystem::path(basename16).generic_u8string();
      const std::string basename(reinterpret_cast<const char*>(basename8.data()), basename8.size());
      const auto listed_name = std::find_if(names.begin(), names.end(), [&](const auto& name) { return name.first == basename; });
      Check(listed_name != names.end() && listed_name->second == stat.st_ino && FileSystem::GetRealFilename(guest).empty(),
            "guest directory inode agrees with stat and file bypasses host path fallback");
      const auto original = std::filesystem::path(L"\\\\?\\" +
          std::filesystem::absolute(extracted / std::filesystem::path(entry.path.substr(1))).wstring());
      std::ifstream source(original, std::ios::binary);
      Check(source.is_open(), "open independent extraction for guest file comparison");
      const auto prefix = FileSystem::KernelPread(fd, memory, 64, 0);
      Check(prefix == static_cast<int64_t>(std::min<uint64_t>(64, entry.size)) && FileSystem::KernelLseek(fd, 0, 1) == 0,
            "guest positioned read preserves independent sequential cursor");
      source.read(reinterpret_cast<char*>(expected.data()), prefix);
      Check(source.gcount() == prefix && std::memcmp(memory, expected.data(), static_cast<size_t>(prefix)) == 0,
            "guest positioned bytes match independent extraction");
      source.clear();
      source.seekg(0);
      uint64_t offset = 0;
      while (offset < entry.size) {
        const auto actual = FileSystem::KernelRead(fd, memory, expected.size());
        Check(actual > 0 && static_cast<uint64_t>(actual) <= entry.size - offset, "guest reads bytes through sector-backed descriptor");
        source.read(reinterpret_cast<char*>(expected.data()), actual);
        Check(source.gcount() == actual && std::memcmp(memory, expected.data(), static_cast<size_t>(actual)) == 0,
              "every guest-read byte matches independently extracted unchanged firmware");
        offset += static_cast<uint64_t>(actual);
      }
      Check(FileSystem::KernelRead(fd, memory, 1) == 0 && FileSystem::KernelLseek(fd, 0, 1) == static_cast<int64_t>(entry.size) &&
            FileSystem::KernelClose(fd) == OK, "guest file reaches EOF and releases descriptor");
      ++files;
      compared += offset;
    }
  };
  audit(audit, u"/");
  Check(Kernel::Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), 1024 * 1024) == OK,
        "release guest read buffer");
  FileSystem::Umount(point);
  FileSystem::Umount("/exfat-original-underlay");
  std::printf("EXFAT_ORIGINAL_GUEST_MOUNT files=%zu directories=%zu file_bytes=%llu original_bytes_compared=1 controller_activation=0 normal_boot=0\n",
      files, directories, static_cast<unsigned long long>(compared));
}

void CheckExfatMountPublicationRace(const std::filesystem::path& root) {
  namespace Kernel = Libs::LibKernel;
  auto volume = OpenExfatMountFixture(root);
  const auto underlay = root / "exfat-race-underlay";
  Check(std::filesystem::create_directory(underlay), "create mount publication race underlay");
  const std::string point = "/exfat-race";
  FileSystem::MountReadOnly(underlay, point);
  unsigned attempts = 0, both_succeeded = 0;
  bool wrong_result = false;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
  for (; attempts < 200 && std::chrono::steady_clock::now() < deadline; ++attempts) {
    std::atomic<unsigned> ready {0};
    std::promise<void> release;
    const auto started = release.get_future().share();
    int tmpfs_result = Kernel::KERNEL_ERROR_EIO, exfat_result = Kernel::KERNEL_ERROR_EIO;
    std::jthread tmpfs([&] {
      ready.fetch_add(1, std::memory_order_release);
      started.wait();
      tmpfs_result = FileSystem::MountTmpfs(point, 0755, 262144, 32);
    });
    std::jthread exfat([&] {
      ready.fetch_add(1, std::memory_order_release);
      started.wait();
      exfat_result = FileSystem::MountExfatReadOnly(point, volume);
    });
    const auto barrier_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (ready.load(std::memory_order_acquire) != 2 && std::chrono::steady_clock::now() < barrier_deadline)
      std::this_thread::yield();
    const bool both_ready = ready.load(std::memory_order_acquire) == 2;
    release.set_value();
    tmpfs.join(); exfat.join();
    if (exfat_result == OK) Check(Kernel::ExfatMount::Unmount(point) == OK, "remove exfat race winner directly after both threads join");
    if (tmpfs_result == OK) Check(Kernel::Tmpfs::Unmount(point) == OK, "remove tmpfs race winner directly after both threads join");
    if (tmpfs_result == OK && exfat_result == OK) {
      ++both_succeeded;
      std::printf("EXFAT_PUBLICATION_RACE_REPRO attempt=%u tmpfs=0x%x exfat=0x%x both_published=1\n",
          attempts + 1, tmpfs_result, exfat_result);
      ++attempts;
      break;
    }
    if (!both_ready || !((tmpfs_result == OK && exfat_result == Kernel::KERNEL_ERROR_EBUSY) ||
                        (exfat_result == OK && tmpfs_result == Kernel::KERNEL_ERROR_EBUSY))) {
      wrong_result = true;
      std::printf("EXFAT_PUBLICATION_RACE_UNEXPECTED attempt=%u tmpfs=0x%x exfat=0x%x barrier=%u\n",
          attempts + 1, tmpfs_result, exfat_result, both_ready ? 1u : 0u);
      ++attempts;
      break;
    }
  }
  FileSystem::Umount(point);
  std::printf("EXFAT_PUBLICATION_RACE attempts=%u both_succeeded=%u wrong_result=%u normal_boot=0\n",
      attempts, both_succeeded, wrong_result ? 1u : 0u);
  std::fflush(stdout);
  Check(attempts > 0 && both_succeeded == 0 && !wrong_result,
        "competing tmpfs and exfat wrapper calls publish exactly one provider");
}
#endif
