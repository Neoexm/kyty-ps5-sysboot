void CheckCapturedRootStartupCache(const std::filesystem::path& root,
                                   const std::filesystem::path& capture) {
  using namespace Libs::LibKernel;
  const auto cache = root / "captured_root_startup_cache";
  const auto build_id = std::string(64, 'c');
#if defined(_WIN32)
  Check(_putenv_s("KYTY_PS5_STARTUP_CACHE_DIR", Common::PathToString(cache).c_str()) == 0 &&
            _putenv_s("KYTY_PS5_STARTUP_CACHE_BUILD_ID", build_id.c_str()) == 0,
        "configure captured-root immutable metadata startup cache");
#else
  const auto cache_path = Common::PathToString(cache);
  Check(setenv("KYTY_PS5_STARTUP_CACHE_DIR", cache_path.c_str(), 1) == 0 &&
            setenv("KYTY_PS5_STARTUP_CACHE_BUILD_ID", build_id.c_str(), 1) == 0,
        "configure captured-root immutable metadata startup cache");
#endif
  FileSystem::FileStat stat {};
  Check(CapturedRootMetadata::Load(capture) == 0 && CapturedRootMetadata::Enabled() &&
            !CapturedRootMetadata::LastLoadUsedStartupCache() &&
            CapturedRootMetadata::Stat("/original_user", &stat) == 0 && stat.st_ino == 0x189 &&
            CapturedRootMetadata::Stat("/original_user/uncaptured", &stat) == KERNEL_ERROR_ENOENT,
        "authenticate captured root and prime immutable metadata cache");
  std::vector<std::filesystem::path> cache_files;
  for (const auto& item: std::filesystem::recursive_directory_iterator(cache))
    if (item.is_regular_file() && item.path().extension() == ".bin") cache_files.push_back(item.path());
  Check(cache_files.size() == 1, "authenticated captured root writes one immutable metadata artifact");
  CapturedRootMetadata::Shutdown();
  Check(CapturedRootMetadata::Load(capture) == 0 && CapturedRootMetadata::Enabled() &&
            CapturedRootMetadata::LastLoadUsedStartupCache() &&
            CapturedRootMetadata::Stat("/original_user", &stat) == 0 && stat.st_ino == 0x189 &&
            CapturedRootMetadata::Stat("/original_user/uncaptured", &stat) == KERNEL_ERROR_ENOENT,
        "unchanged captured root metadata reloads from persistent cache");
  CapturedRootMetadata::Shutdown();
  {
    std::fstream artifact(cache_files.front(), std::ios::binary | std::ios::in | std::ios::out);
    Check(artifact.good(), "open disposable captured-root startup cache for corruption test");
    artifact.seekg(-1, std::ios::end);
    char byte = 0;
    artifact.read(&byte, 1);
    Check(artifact.good(), "read disposable captured-root startup cache byte");
    byte ^= 0x5a;
    artifact.seekp(-1, std::ios::end);
    artifact.write(&byte, 1);
    artifact.flush();
    Check(artifact.good(), "corrupt disposable captured-root startup cache byte");
  }
  Check(CapturedRootMetadata::Load(capture) == 0 && CapturedRootMetadata::Enabled() &&
            !CapturedRootMetadata::LastLoadUsedStartupCache(),
        "corrupt captured-root cache falls through to full source authentication");
  CapturedRootMetadata::Shutdown();
  Check(CapturedRootMetadata::Load(capture) == 0 && CapturedRootMetadata::Enabled() &&
            CapturedRootMetadata::LastLoadUsedStartupCache(),
        "captured-root fallback repairs the persistent cache atomically");
  CapturedRootMetadata::Shutdown();
#if defined(_WIN32)
  Check(_putenv_s("KYTY_PS5_STARTUP_CACHE_DIR", "") == 0 &&
            _putenv_s("KYTY_PS5_STARTUP_CACHE_BUILD_ID", "") == 0,
        "clear captured-root immutable metadata startup cache");
#else
  Check(unsetenv("KYTY_PS5_STARTUP_CACHE_DIR") == 0 &&
            unsetenv("KYTY_PS5_STARTUP_CACHE_BUILD_ID") == 0,
        "clear captured-root immutable metadata startup cache");
#endif
  std::printf("CapturedRootStartupCacheTests: prime=pass hit=pass corruption_fallback=pass atomic_repair=pass\n");
}

void CheckCapturedRootIntegration(const std::filesystem::path& root,
                                  const std::filesystem::path& capture) {
  using namespace Libs::LibKernel;
  const auto directory = root / "captured_root_underlay";
  Check(std::filesystem::create_directory(directory), "create disposable captured-root underlay");
  FileSystem::MountReadOnly(directory, "/");
  Check(CapturedRootMetadata::Load(capture) == 0 && CapturedRootMetadata::Enabled(),
        "authenticate the captured kernel before publishing root metadata");
  FileSystem::FileStat stat {};
  const std::array<std::pair<const char*, uint32_t>, 5> targets {{
      {"/original_user", 0x189}, {"/original_system_data", 0x188},
      {"/devlog", 0xc3}, {"/devlog/app", 0xc1}, {"/devlog/system", 0xc2}}};
  for (const auto& [path, inode]: targets) {
    const int result = FileSystem::KernelStat(path, &stat);
    std::printf("CapturedRootIntegrationTests: path=%s result=0x%x inode=0x%x device=0x%x rdev=0x%x mode=0%o uid=%u gid=%u links=%u size=%lld block_size=%u\n",
                path, result, stat.st_ino, stat.st_dev, stat.st_rdev, stat.st_mode,
                stat.st_uid, stat.st_gid, stat.st_nlink, static_cast<long long>(stat.st_size), stat.st_blksize);
    Check(result == 0 && stat.st_ino == inode &&
              stat.st_dev == UINT32_MAX && stat.st_rdev == UINT32_MAX &&
              stat.st_mode == 0040777 && stat.st_uid == 0 && stat.st_gid == 0 &&
              stat.st_nlink == 1 && stat.st_size == 4096 && stat.st_blksize == 4096,
          "captured directory metadata supplies the covered vnode");
    Check(FileSystem::KernelCheckReachability(path) == 0 &&
              FileSystem::KernelOpen(path, 0x20000, 0) == KERNEL_ERROR_EIO,
          "positive metadata does not imply a complete directory listing");
  }
  stat.st_ino = 0x12345678;
  Check(FileSystem::KernelStat("/original_user/uncaptured", &stat) == KERNEL_ERROR_EIO &&
            stat.st_ino == 0x12345678 &&
            FileSystem::KernelStat("/original_user/uncaptured/..", &stat) == KERNEL_ERROR_EIO,
        "uncaptured entries stay unknown and cannot disappear through parent traversal");
  Check(FileSystem::MountNullfs("/original_user/uncaptured/..", "/devlog/app") == KERNEL_ERROR_EIO &&
            FileSystem::MountNullfs("/user", "/original_user/uncaptured/..") == KERNEL_ERROR_EIO &&
            !NullfsMount::Contains("/original_user") && !NullfsMount::Contains("/devlog/app"),
        "mount publication checks raw captured source and target traversal");
  Check(FileSystem::KernelStat("/devlog/app/..", &stat) == 0 && stat.st_ino == 0xc3,
        "observed captured parent traversal retains the original parent identity");
  Check(FileSystem::KernelStat("/original_user/uncaptured/../..", &stat) == KERNEL_ERROR_EIO &&
            FileSystem::KernelCheckReachability("/original_user/uncaptured/../..") == KERNEL_ERROR_EIO &&
            FileSystem::KernelOpen("/original_user/uncaptured/../..", 0x20000, 0) == KERNEL_ERROR_EIO &&
            FileSystem::GetRealFilename("/original_user/uncaptured/../..").empty(),
        "raw captured traversal cannot bypass unknown components through an existing host ancestor");
  FileSystem::MountReadOnly(directory, "/app0");
  Check(FileSystem::KernelStat("/app0/uncaptured", &stat) == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelCheckReachability("/app0/uncaptured") == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelOpen("/app0/uncaptured", 0, 0) == KERNEL_ERROR_ENOENT,
        "an explicit mounted host provider retains its authoritative missing-path result");
  FileSystem::Umount("/app0");
  Check(FileSystem::KernelStat("/dev/__uncaptured_native_device__", &stat) == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelStat("//dev/__uncaptured_native_device__", &stat) == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelCheckReachability("/dev/__uncaptured_native_device__") == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelOpen("/dev/__uncaptured_native_device__", 2, 0) == KERNEL_ERROR_ENOENT,
        "modeled device namespace retains its missing-device contract");
  Check(FileSystem::KernelStat("/dev/../original_user", &stat) == 0 && stat.st_ino == 0x189 &&
            FileSystem::KernelStat("/", &stat) == 0 && FileSystem::KernelCheckReachability("//") == 0,
        "checked parent traversal selects the resulting namespace and root walks terminate");
  Check(FileSystem::KernelStat("/original_user", nullptr) == KERNEL_ERROR_EINVAL &&
            FileSystem::KernelStat("/original_user", reinterpret_cast<FileSystem::FileStat*>(1)) == KERNEL_ERROR_EFAULT,
        "captured metadata retains checked guest output access");
  Check(FileSystem::KernelOpen("/original_user", 1, 0) == KERNEL_ERROR_EROFS &&
            FileSystem::KernelMkdir("/original_user/uncaptured", 0777) == KERNEL_ERROR_EROFS,
        "captured metadata never becomes writable host storage");
  const auto invalid = root / "invalid_root_capture.bin";
  {
    std::ofstream output(invalid, std::ios::binary);
    output << "unverified root";
  }
  Check(CapturedRootMetadata::Load(invalid) != 0 &&
            FileSystem::KernelStat("/original_user", &stat) == 0 && stat.st_ino == 0x189,
        "rejected captures cannot replace the published immutable snapshot");
  Check(FileSystem::MountTmpfs("/user", 0777, 65536, 32) == 0,
        "mount tmpfs over an observed original root directory");
  const int descriptor = FileSystem::KernelOpen("/user/shared", 0x202, 0600);
  Check(descriptor >= 0 && FileSystem::KernelWrite(descriptor, "root", 4) == 4 &&
            FileSystem::KernelClose(descriptor) == 0,
        "guest operation creates lower contents");
  Check(FileSystem::MountNullfs("/user", "/original_user") == 0,
        "publish nullfs over the captured original covered directory");
  FileSystem::FileStat lower {};
  Check(FileSystem::KernelStat("/user/shared", &lower) == 0 &&
            FileSystem::KernelStat("/original_user/shared", &stat) == 0 &&
            stat.st_dev == lower.st_dev && stat.st_ino == lower.st_ino,
        "mounted aliases expose lower identity rather than cached covered metadata");
  const int alias = FileSystem::KernelOpen("/original_user/shared", 0, 0);
  std::array<char, 4> bytes {};
  Check(alias >= 0 && FileSystem::KernelRead(alias, bytes.data(), bytes.size()) == 4 &&
            std::string(bytes.data(), bytes.size()) == "root" && FileSystem::KernelClose(alias) == 0,
        "captured mountpoint supports alias reads without seeded contents");
  FileSystem::Umount("/original_user");
  FileSystem::Umount("/user");
  Check(FileSystem::KernelStat("/original_user", &stat) == 0 && stat.st_ino == 0x189 &&
            FileSystem::KernelOpen("/original_user", 0x20000, 0) == KERNEL_ERROR_EIO,
        "unmount reveals the same partial captured covered vnode");
  Check(FileSystem::MountTmpfs("/system_tmp", 0755, 65536, 32) == 0,
        "system_tmp metadata replaces an artificial host underlay");
  FileSystem::Umount("/system_tmp");
  Check(std::filesystem::is_empty(directory), "no captured root directory was manufactured on disk");
  CapturedRootMetadata::Shutdown();
  Check(FileSystem::KernelStat("/original_user", &stat) == KERNEL_ERROR_ENOENT,
        "disabling the capture restores the host underlay result");
  FileSystem::Umount("/");
  std::printf("CapturedRootIntegrationTests: capture=pass covered_vnodes=pass nullfs=pass partial_listing_error=pass no_host_directories=pass\n");
}
