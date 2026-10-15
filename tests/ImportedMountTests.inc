void CheckImportedMounts(const std::filesystem::path& root) {
#if defined(_WIN32)
  using namespace Libs::LibKernel;
  const char* guard = std::getenv("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS");
  const std::string saved_guard = guard ? guard : "";
  Check(_putenv_s("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS", "1") == 0,
        "enable guard to verify the mount binding takes precedence");
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* symbol = symbols.Find({"3YnXspQNyw8", "libkernel", 1,
                                     "libkernel", 1, 1, Loader::SymbolType::Func});
  Check(symbol != nullptr && symbol->dbg_name == "KernelNmount",
        "resolve nmount import to its POSIX adapter");
  Check(_putenv_s("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS", saved_guard.c_str()) == 0,
        "restore native syscall guard setting");
  using Mount = int (KYTY_SYSV_ABI *)(const void*, uint32_t, int);
  const auto mount = reinterpret_cast<Mount>(symbol->vaddr);
  struct Iovec { uint64_t address; uint64_t length; };
  static_assert(sizeof(Iovec) == 16);
  void* memory = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&memory, 0x4000, 3, 0, "imported-mount-test") == OK,
        "map guest mount vectors and strings");
  auto* vectors = static_cast<Iovec*>(memory);
  const auto set = [&](const std::vector<std::string>& options) {
    Check(options.size() < 64, "bound imported mount fixture vectors");
    std::memset(memory, 0xa5, 0x4000);
    auto* strings = static_cast<char*>(memory) + 0x1000;
    size_t used = 0;
    for (size_t index = 0; index < options.size(); ++index) {
      const size_t size = options[index].size() + 1;
      Check(used + size <= 0x3000, "bound imported mount fixture strings");
      std::memcpy(strings + used, options[index].c_str(), size);
      vectors[index] = {reinterpret_cast<uint64_t>(strings + used), size};
      used += size;
    }
    return static_cast<uint32_t>(options.size());
  };
  const auto expect_error = [&](const void* input, uint32_t count, int flags, int error,
                                const char* text) {
    *Libs::Posix::GetErrorAddr() = 0;
    Check(mount(input, count, flags) == -1 && *Libs::Posix::GetErrorAddr() == error, text);
  };
  const auto namespace_root = root / "nullfs-namespace";
  Check(std::filesystem::create_directories(namespace_root) &&
            std::filesystem::create_directories(namespace_root / "source-type-target") &&
            std::filesystem::create_directories(namespace_root / "original_user") &&
            std::filesystem::create_directories(namespace_root / "original_system_data") &&
            std::filesystem::create_directories(namespace_root / "devlog" / "app") &&
            std::filesystem::create_directories(namespace_root / "devlog" / "system") &&
            std::filesystem::create_directories(namespace_root / "generic-nullfs-target"),
        "create nullfs target namespace fixtures");
  {
    std::ofstream fixture(namespace_root / "regular-target", std::ios::binary);
    fixture.put('x');
    Check(fixture.good(), "create nullfs regular-file target fixture");
  }
  FileSystem::MountReadOnly(namespace_root, "/");
  auto* io = static_cast<char*>(memory) + 0x3000;
  auto* entries = io + 0x200;
  const auto count_entry = [](const char* buffer, int bytes, std::string_view expected) {
    int found = 0;
    for (int offset = 0; offset < bytes;) {
      Check(bytes - offset >= 8, "directory record header fits");
      uint16_t length = 0;
      std::memcpy(&length, buffer + offset + 4, sizeof(length));
      const auto name_length = static_cast<uint8_t>(buffer[offset + 7]);
      Check(length >= 9 + name_length && length <= bytes - offset,
            "directory record stays within returned bytes");
      if (std::string_view(buffer + offset + 8, name_length) == expected) ++found;
      offset += length;
    }
    return found;
  };
  FileSystem::FileStat topology_stat {}, normalized_stat {}, topology_fstat {};
  Check(FileSystem::KernelStat("/data", &topology_stat) == OK &&
            FileSystem::KernelStat("/data/.", &normalized_stat) == OK &&
            FileSystem::KernelStat("/data/../data", &normalized_stat) == OK &&
            topology_stat.st_dev == normalized_stat.st_dev &&
            topology_stat.st_ino == normalized_stat.st_ino &&
            topology_stat.st_mode == 0040555u && topology_stat.st_nlink == 2 &&
            topology_stat.st_size == 0 && topology_stat.st_blocks == 0 &&
            topology_stat.st_blksize == 512,
        "read-only root supplies one stable immutable data topology directory");
  const int topology_fd = FileSystem::KernelOpen("/data", 0x20000, 0);
  std::memset(entries, 0, 512);
  Check(topology_fd >= 3 &&
            FileSystem::KernelStat("/data", reinterpret_cast<FileSystem::FileStat*>(1)) ==
                KERNEL_ERROR_EFAULT &&
            FileSystem::KernelFstat(topology_fd, reinterpret_cast<FileSystem::FileStat*>(1)) ==
                KERNEL_ERROR_EFAULT &&
            FileSystem::KernelFstat(topology_fd, &topology_fstat) == OK &&
            topology_fstat.st_dev == topology_stat.st_dev &&
            topology_fstat.st_ino == topology_stat.st_ino &&
            topology_fstat.st_mode == topology_stat.st_mode &&
            FileSystem::KernelGetdirentries(topology_fd, reinterpret_cast<char*>(1), 512, nullptr) ==
                KERNEL_ERROR_EFAULT &&
            FileSystem::KernelGetdirentries(topology_fd, entries, 512,
                reinterpret_cast<int64_t*>(1)) == KERNEL_ERROR_EFAULT &&
            FileSystem::KernelGetdents(topology_fd, entries, 512) == 0,
        "data topology opens as an empty directory with matching descriptor metadata");
  const int root_fd = FileSystem::KernelOpen("/", 0x20000, 0);
  std::memset(entries, 0, 512);
  const int root_bytes = root_fd >= 3 ? FileSystem::KernelGetdents(root_fd, entries, 512) : -1;
  Check(root_fd >= 3 && root_bytes > 0 && count_entry(entries, root_bytes, "data") == 1 &&
            FileSystem::KernelClose(root_fd) == OK,
        "read-only root enumeration publishes one data directory entry");
  Check(FileSystem::GetRealFilename("/data").empty() &&
            FileSystem::KernelStat("/data/missing", &normalized_stat) == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelStat("/data/missing/..", &normalized_stat) == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelCheckReachability("/data") == OK &&
            FileSystem::KernelCheckReachability("/data/missing") == KERNEL_ERROR_ENOENT,
        "data topology exposes no host path and preserves raw missing-component traversal");
  Check(FileSystem::KernelOpen("/data", 1, 0) == KERNEL_ERROR_EROFS &&
            FileSystem::KernelOpen("/data", 0x800, 0) == KERNEL_ERROR_EROFS &&
            FileSystem::KernelOpen("/data/new", 0x202, 0600) == KERNEL_ERROR_EROFS &&
            FileSystem::KernelMkdir("/data/new", 0755) == KERNEL_ERROR_EROFS &&
            FileSystem::KernelUnlink("/data/missing") == KERNEL_ERROR_EROFS &&
            FileSystem::KernelRmdir("/data") == KERNEL_ERROR_EROFS &&
            FileSystem::KernelRename("/data/missing", "/data/other") == KERNEL_ERROR_EROFS &&
            FileSystem::KernelRename("/data", "/moved-data") == KERNEL_ERROR_EXDEV,
        "data topology rejects mutations without creating host content");
  const auto nested_host = root / "nested-data-host";
  Check(std::filesystem::create_directories(nested_host),
        "create nested data host mount fixture");
  {
    std::ofstream fixture(nested_host / "marker.bin", std::ios::binary);
    fixture.write("NESTED", 6);
    Check(fixture.good(), "write nested data host mount fixture");
  }
  FileSystem::Mount(nested_host, "/data/direct");
  const auto nested_name = FileSystem::GetRealFilename("/data/direct/marker.bin");
  const int nested_fd = FileSystem::KernelOpen("/data/direct/marker.bin", 0, 0);
  std::memset(io, 0, 8);
  Check(!nested_name.empty() && nested_fd >= 3 && FileSystem::KernelRead(nested_fd, io, 6) == 6 &&
            std::memcmp(io, "NESTED", 6) == 0 && FileSystem::KernelClose(nested_fd) == OK,
        "more-specific host mount takes precedence beneath data topology");
  Check(FileSystem::GetRealFilename("/data/missing/../direct/marker.bin").empty() &&
            FileSystem::KernelOpen("/data/missing/../direct/marker.bin", 0, 0) ==
                KERNEL_ERROR_ENOENT,
        "missing data topology component cannot be erased into a nested host mount");
  FileSystem::Umount("/data/direct");
  Check(FileSystem::KernelOpen("/data/direct/marker.bin", 0, 0) == KERNEL_ERROR_ENOENT,
        "nested host unmount reveals the empty data topology");
  Check(FileSystem::MountTmpfs("/data", 0755u, 1024 * 1024, 64) == OK &&
            Tmpfs::Contains("/data"),
        "explicit tmpfs covers the data topology directory");
  const int covered = FileSystem::KernelOpen("/data/covered", 0x202, 0600);
  FileSystem::FileStat covered_stat {}, pinned_stat {};
  std::memset(entries, 0, 512);
  Check(covered >= 3 && FileSystem::KernelClose(covered) == OK &&
            FileSystem::KernelStat("/data", &covered_stat) == OK &&
            (covered_stat.st_dev != topology_stat.st_dev || covered_stat.st_ino != topology_stat.st_ino) &&
            FileSystem::KernelLseek(topology_fd, 0, 0) == 0 &&
            FileSystem::KernelGetdents(topology_fd, entries, 512) == 0 &&
            FileSystem::KernelFstat(topology_fd, &pinned_stat) == OK &&
            pinned_stat.st_dev == topology_stat.st_dev && pinned_stat.st_ino == topology_stat.st_ino,
        "covering mount wins while the pre-cover topology descriptor stays pinned");
  Check(Tmpfs::Unmount("/data") == OK &&
            FileSystem::KernelStat("/data", &normalized_stat) == OK &&
            normalized_stat.st_dev == topology_stat.st_dev &&
            normalized_stat.st_ino == topology_stat.st_ino &&
            FileSystem::KernelClose(topology_fd) == OK,
        "covering mount removal reveals the same data topology identity");
  Check(!NullfsMount::Contains("/data"), "original data alias is absent before the imported request");
  Check(Tmpfs::Mount("/user", 0755u, 16ull * 1024 * 1024, 512u) == OK,
        "model the current empty diagnostic user mount without seeding data");
  auto count = set({"fstype", "nullfs", "fspath", "/data", "target", "/user/data"});
  expect_error(vectors, count, 0, Libs::Posix::POSIX_ENOENT,
               "six-vector nullfs request reaches its missing lower directory");
  auto* source_end = reinterpret_cast<char*>(vectors[5].address) + vectors[5].length - 1;
  *source_end = 'x';
  expect_error(vectors, count, 0, Libs::Posix::POSIX_EINVAL,
               "nullfs validates the source string terminator");
  *source_end = '\0';
  vectors[5].length = 0;
  expect_error(vectors, count, 0, Libs::Posix::POSIX_EINVAL,
               "nullfs rejects an empty source vector");
  for (const std::vector<std::string>& options: {
           std::vector<std::string> {"fstype", "nullfs", "fspath", "/data"},
           {"fspath", "/data", "target", "/user/data"},
           {"fstype", "nullfs", "target", "/user/data"},
           {"fstype", "nullfs", "fspath", "/data", "target", "/user/data", "target", "/user"},
           {"fstype", "nullfs", "fspath", "/data", "from", "/user/data", "from", "/user"},
           {"fstype", "nullfs", "fspath", "/data", "target", "/user/data", "mode", "755"}}) {
    count = set(options);
    expect_error(vectors, count, 0, Libs::Posix::POSIX_EINVAL,
                 "nullfs rejects missing, duplicate and extraneous options");
  }
  Check(!NullfsMount::Contains("/data") && Tmpfs::Unmount("/user") == OK,
        "failed original mount leaves its namespace absent and its lower mount unchanged");

  NullfsMount::Resolution resolution {};
  Check(NullfsMount::Mount("/normalized//alias/.", "/lower/./tree") == OK &&
            NullfsMount::Resolve("/normalized/alias/child/../file", &resolution) == OK &&
            resolution.mounted && resolution.path == "/lower/tree/file",
        "nullfs normalizes absolute target, source and descendant paths");
  const auto stable_generation = resolution.generation;
  Check(NullfsMount::Resolve("/normalized/alias-other", &resolution) == OK &&
            !resolution.mounted && resolution.path == "/normalized/alias-other",
        "nullfs resolution requires a complete path-component prefix");
  Check(NullfsMount::Mount("relative", "/lower") == KERNEL_ERROR_EINVAL &&
            NullfsMount::Mount("/normalized/alias/sub", "/other") == KERNEL_ERROR_EBUSY &&
            NullfsMount::Mount("/lower/tree/sub", "/other") == KERNEL_ERROR_EBUSY &&
            NullfsMount::Mount("/cycle", "/cycle/lower") == KERNEL_ERROR_ELOOP &&
            !NullfsMount::Contains("/cycle") &&
            NullfsMount::Resolve("/normalized/alias/file", &resolution) == OK &&
            resolution.generation == stable_generation && resolution.path == "/lower/tree/file",
        "nullfs rejects invalid, overlapping and cyclic publications atomically");
  Check(NullfsMount::Unmount("/normalized/alias") == OK &&
            !NullfsMount::Contains("/normalized/alias"),
        "nullfs removes a normalized alias publication");

  const auto lower = root / "nullfs-lower";
  Check(std::filesystem::create_directories(lower / "subdirectory"),
        "create nullfs lower directory fixture");
  constexpr char lower_payload[] = "authentic lower path";
  {
    std::ofstream fixture(lower / "marker.bin", std::ios::binary);
    fixture.write(lower_payload, sizeof(lower_payload) - 1);
    Check(fixture.good(), "create nullfs lower file fixture");
  }
  FileSystem::Mount(lower, "/user/data");
  FileSystem::FileStat lower_stat {};
  Check(FileSystem::KernelStat("/user/data", &lower_stat) == OK &&
            (lower_stat.st_mode & 0170000u) == 0040000u,
        "publish the lower directory for the tuple");
  Check(FileSystem::MountNullfs("/user/data", "/missing-nullfs-target") ==
            KERNEL_ERROR_ENOENT && !NullfsMount::Contains("/missing-nullfs-target"),
        "nullfs requires its target mountpoint to exist");
  Check(FileSystem::MountNullfs("/user/data", "/regular-target") ==
            KERNEL_ERROR_ENOTDIR && !NullfsMount::Contains("/regular-target"),
        "nullfs requires its target mountpoint to be a directory");
  Check(FileSystem::MountNullfs("/user/data/marker.bin", "/source-type-target") ==
            KERNEL_ERROR_ENOTDIR && !NullfsMount::Contains("/source-type-target"),
        "nullfs requires the lower source to be a directory");
  FileSystem::Mount(lower, "/occupied-nullfs-target");
  Check(FileSystem::MountNullfs("/user/data", "/occupied-nullfs-target") ==
            KERNEL_ERROR_EBUSY && !NullfsMount::Contains("/occupied-nullfs-target"),
        "nullfs refuses an occupied target without replacing it");
  FileSystem::Umount("/occupied-nullfs-target");

  count = set({"fstype", "nullfs", "fspath", "/data", "target", "/user/data"});
  Check(mount(vectors, count, 0) == 0 && NullfsMount::Contains("/data") &&
            !Tmpfs::Contains("/data"),
        "nullfs tuple publishes a lower-path alias");
  FileSystem::FileStat alias_stat {};
  Check(FileSystem::KernelStat("/data", &alias_stat) == OK &&
            alias_stat.st_dev == lower_stat.st_dev && alias_stat.st_ino == lower_stat.st_ino &&
            alias_stat.st_mode == lower_stat.st_mode,
        "nullfs stat preserves lower filesystem metadata");
  Check(FileSystem::KernelStat("/data/missing/../marker.bin", &alias_stat) == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelOpen("/data/missing/../marker.bin", 0, 0) == KERNEL_ERROR_ENOENT &&
            FileSystem::GetRealFilename("/data/missing/../marker.bin").empty(),
        "nullfs does not erase a missing component before resolving the lower path");
  Check(FileSystem::KernelStat("/data/marker.bin/../subdirectory", &alias_stat) == KERNEL_ERROR_ENOTDIR &&
            FileSystem::KernelOpen("/data/marker.bin/../subdirectory", 0x20000, 0) == KERNEL_ERROR_ENOTDIR &&
            FileSystem::GetRealFilename("/data/marker.bin/../subdirectory").empty(),
        "nullfs cannot traverse through a regular file before dotdot");
  Check(FileSystem::KernelStat("/data/missing/../../data", &alias_stat) == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelStat("/data/subdirectory/..", &alias_stat) == OK &&
            alias_stat.st_ino == lower_stat.st_ino &&
            FileSystem::KernelStat("/data/..", &alias_stat) == OK &&
            FileSystem::KernelStat("/", &normalized_stat) == OK &&
            alias_stat.st_ino == normalized_stat.st_ino && alias_stat.st_dev == normalized_stat.st_dev,
        "nullfs dotdot preserves guest parents and validates components before leaving an alias");
  Check(FileSystem::MountNullfs("/data/subdirectory", "/generic-nullfs-target") == OK &&
            FileSystem::KernelRmdir("/generic-nullfs-target") == KERNEL_ERROR_EBUSY &&
            FileSystem::KernelRmdir("/generic-nullfs-target/.") == KERNEL_ERROR_EINVAL &&
            FileSystem::KernelRmdir("/data/subdirectory/..") == KERNEL_ERROR_EINVAL &&
            FileSystem::KernelRename("/generic-nullfs-target", "/data/moved-lower") == KERNEL_ERROR_EBUSY &&
            FileSystem::KernelStat("/data/subdirectory", &alias_stat) == OK,
        "alias mount roots and final special components cannot remove or rename lower directories");
  FileSystem::Umount("/generic-nullfs-target");
  {
    std::ofstream source(lower / "rename-source", std::ios::binary);
    std::ofstream target(lower / "rename-target", std::ios::binary);
    source.write("SOURCE", 6);
    target.write("TARGET", 6);
    Check(source.good() && target.good(), "create disposable host rename files");
  }
  const auto native_rename = [&](const std::string& from, const std::string& to) {
    set({from, to});
    return Libs::NativeKernelBridge::DispatchSyscall({0x80, {vectors[0].address, vectors[1].address}});
  };
  const auto same = native_rename("/data/rename-source", "/data/rename-source");
  Check(same.value == 0 && same.posix_errno == 0 &&
            std::filesystem::file_size(lower / "rename-source") == 6,
        "native same-file rename preserves the source");
  HANDLE locked_target = CreateFileW((lower / "rename-target").c_str(), GENERIC_READ,
      FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  Check(locked_target != INVALID_HANDLE_VALUE, "hold destination without delete sharing");
  const auto denied = native_rename("/data/rename-source", "/data/rename-target");
  std::array<char, 6> source_bytes {}, target_bytes {};
  {
    std::ifstream source(lower / "rename-source", std::ios::binary);
    std::ifstream target(lower / "rename-target", std::ios::binary);
    source.read(source_bytes.data(), source_bytes.size());
    target.read(target_bytes.data(), target_bytes.size());
  }
  Check(CloseHandle(locked_target) && denied.value == -1 && denied.posix_errno != 0 &&
            std::memcmp(source_bytes.data(), "SOURCE", 6) == 0 &&
            std::memcmp(target_bytes.data(), "TARGET", 6) == 0,
        "failed native replacement preserves both source and destination bytes");
  const auto replaced = native_rename("/data/rename-source", "/data/rename-target");
  {
    std::ifstream target(lower / "rename-target", std::ios::binary);
    target.read(target_bytes.data(), target_bytes.size());
  }
  Check(replaced.value == 0 && replaced.posix_errno == 0 &&
            !std::filesystem::exists(lower / "rename-source") &&
            std::memcmp(target_bytes.data(), "SOURCE", 6) == 0,
        "native rename atomically replaces an existing host file");
  const auto missing_parent = native_rename("/data/rename-target", "/data/absent-parent/target");
  Check(missing_parent.value == -1 && missing_parent.posix_errno == Libs::Posix::POSIX_ENOENT &&
            !std::filesystem::exists(lower / "absent-parent") &&
            std::filesystem::exists(lower / "rename-target"),
        "native rename reports a missing parent without creating directories or losing its source");

  const int pinned = FileSystem::KernelOpen("/data/marker.bin", 0, 0);
  Check(pinned >= 3 &&
            FileSystem::KernelPread(pinned, io, sizeof(lower_payload) - 1, 0) ==
                sizeof(lower_payload) - 1 &&
            std::memcmp(io, lower_payload, sizeof(lower_payload) - 1) == 0,
        "nullfs opens and reads through the lower filesystem");
  const int directory = FileSystem::KernelOpen("/data", 0x20000, 0);
  std::memset(entries, 0, 512);
  const int entry_bytes = directory >= 3 ? FileSystem::KernelGetdents(directory, entries, 512) : -1;
  bool found_marker = false;
  for (int offset = 0; offset < entry_bytes;) {
    Check(entry_bytes - offset >= 8, "nullfs directory record header fits");
    uint16_t length = 0;
    std::memcpy(&length, entries + offset + 4, sizeof(length));
    const auto name_length = static_cast<uint8_t>(entries[offset + 7]);
    Check(length >= 9 + name_length && length <= entry_bytes - offset,
          "nullfs directory record stays within the returned block");
    found_marker = found_marker ||
        std::string_view(entries + offset + 8, name_length) == "marker.bin";
    offset += length;
  }
  Check(directory >= 3 && entry_bytes > 0 && found_marker &&
            FileSystem::KernelClose(directory) == OK,
        "nullfs directory descriptors enumerate lower entries");
  const int synced_directory = FileSystem::KernelOpen("/data", 0x20000, 0);
  Check(synced_directory >= 3 && FileSystem::KernelFsync(synced_directory) == OK &&
            FileSystem::KernelClose(synced_directory) == OK &&
            FileSystem::KernelFsync(synced_directory) == KERNEL_ERROR_EBADF,
        "fsync on a directory vnode succeeds like kern_fsync and closed descriptors stay EBADF");

  Check(FileSystem::KernelCheckReachability("/data/marker.bin") == OK &&
            FileSystem::KernelCheckReachability("/data/missing") == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelMkdir("/data/new-directory", 0750) == OK,
        "nullfs delegates reachability and mkdir to the lower filesystem");
  std::memcpy(io, "written", 7);
  const int writable = FileSystem::KernelOpen("/data/new-file", 0x202, 0600);
  Check(writable >= 3 && FileSystem::KernelWrite(writable, io, 7) == 7 &&
            FileSystem::KernelClose(writable) == OK &&
            FileSystem::KernelRename("/data/new-file", "/data/renamed-file") == OK &&
            FileSystem::KernelStat("/user/data/renamed-file", &alias_stat) == OK,
        "nullfs delegates file creation and same-alias rename to the lower filesystem");
  Check(FileSystem::KernelRename("/data/renamed-file", "/user/data/escaped-file") ==
            KERNEL_ERROR_EXDEV &&
            FileSystem::KernelStat("/data/renamed-file", &alias_stat) == OK,
        "nullfs rejects rename across the alias mount boundary");
  Check(FileSystem::KernelUnlink("/data/renamed-file") == OK &&
            FileSystem::KernelRmdir("/data/new-directory") == OK &&
            !std::filesystem::exists(lower / "renamed-file") &&
            !std::filesystem::exists(lower / "new-directory"),
        "nullfs delegates unlink and rmdir without retaining alias state");

  FileSystem::Umount("/data");
  std::memset(io, 0, sizeof(lower_payload));
  FileSystem::FileStat revealed_stat {};
  Check(!NullfsMount::Contains("/data") &&
            FileSystem::KernelOpen("/data/marker.bin", 0, 0) == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelStat("/data", &revealed_stat) == OK &&
            revealed_stat.st_dev == topology_stat.st_dev &&
            revealed_stat.st_ino == topology_stat.st_ino &&
            FileSystem::KernelPread(pinned, io, sizeof(lower_payload) - 1, 0) ==
                sizeof(lower_payload) - 1 &&
            std::memcmp(io, lower_payload, sizeof(lower_payload) - 1) == 0 &&
            FileSystem::KernelClose(pinned) == OK,
        "nullfs unmount reveals topology while preserving a pinned lower descriptor");
  FileSystem::Umount("/user/data");
  Check(FileSystem::KernelStat("/user/data", &lower_stat) == KERNEL_ERROR_ENOENT,
        "nullfs test cleanup removes the lower host mount");

  const char* legacy = std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_NMOUNT_NULLFS_PASS");
  const std::string saved_legacy = legacy ? legacy : "";
  Check(_putenv_s("KYTY_DIAGNOSTIC_SAFE_MODE_NMOUNT_NULLFS_PASS", "") == 0,
        "disable legacy nullfs stand-ins");
  count = set({"fstype", "nullfs", "fspath", "/original_user", "from", "/user"});
  expect_error(vectors, count, 0, Libs::Posix::POSIX_ENOENT,
               "original from tuple reports the missing lower directory without diagnostics");
  Check(!Tmpfs::Contains("/original_user"), "disabled diagnostic nullfs creates no mount");
  FileSystem::Mount(lower, "/user");
  Check(mount(vectors, count, 0) == 0 && NullfsMount::Contains("/original_user") &&
            !Tmpfs::Contains("/original_user"),
        "original Mini from tuple publishes an alias without diagnostics");
  const int original_user = FileSystem::KernelOpen("/original_user/marker.bin", 0, 0);
  std::memset(io, 0, sizeof(lower_payload));
  Check(original_user >= 3 &&
            FileSystem::KernelRead(original_user, io, sizeof(lower_payload) - 1) == sizeof(lower_payload) - 1 &&
            std::memcmp(io, lower_payload, sizeof(lower_payload) - 1) == 0 &&
            FileSystem::KernelClose(original_user) == OK,
        "user alias reads existing lower bytes instead of an empty stand-in");
  FileSystem::Umount("/original_user");
  count = set({"fstype", "nullfs", "fspath", "/generic-nullfs-target",
               "target", "/user", "from", "/unavailable"});
  Check(mount(vectors, count, 0) == 0 && NullfsMount::Contains("/generic-nullfs-target"),
        "generic nullfs accepts target before from independently of executable paths");
  FileSystem::Umount("/generic-nullfs-target");
  count = set({"fstype", "nullfs", "fspath", "/generic-nullfs-target",
               "target", "/unavailable", "from", "/user"});
  expect_error(vectors, count, 0, Libs::Posix::POSIX_ENOENT,
               "a present unavailable target does not fall back to from");
  Check(!NullfsMount::Contains("/generic-nullfs-target"), "failed source lookup publishes no alias");
  FileSystem::Umount("/user");
  Check(Tmpfs::Mount("/user", 0755u, 1024 * 1024, 64) == OK &&
            FileSystem::KernelMkdir("/user/devlog", 0755) == OK &&
            FileSystem::KernelMkdir("/user/devlog/system", 0755) == OK,
        "create a shared lower devlog filesystem fixture");
  count = set({"fstype", "nullfs", "fspath", "/devlog/system", "from", "/user/devlog/system"});
  Check(mount(vectors, count, 0) == 0 && NullfsMount::Contains("/devlog/system") &&
            FileSystem::KernelMkdir("/devlog/system/visible", 0700) == OK &&
            FileSystem::KernelStat("/user/devlog/system/visible", &revealed_stat) == OK,
        "devlog alias writes to the existing lower tmpfs");
  Check(_putenv_s("KYTY_DIAGNOSTIC_SAFE_MODE_NMOUNT_NULLFS_PASS", "1") == 0,
        "enable diagnostics while retaining a devlog alias");
  expect_error(vectors, count, 0, Libs::Posix::POSIX_EBUSY,
               "diagnostics cannot hide an existing nullfs mount behind a stand-in");
  Check(!Tmpfs::Contains("/devlog/system") &&
            _putenv_s("KYTY_DIAGNOSTIC_SAFE_MODE_NMOUNT_NULLFS_PASS", "") == 0,
        "duplicate nullfs rejection publishes no hidden tmpfs");
  auto* native_path = static_cast<char*>(memory) + 0x1000;
  auto* native_other = static_cast<char*>(memory) + 0x1800;
  std::strcpy(native_path, "/devlog/system/missing/../../../escaped");
  const auto native_missing = Libs::NativeKernelBridge::DispatchSyscall(
      {0x88, {reinterpret_cast<uint64_t>(native_path), 0700}});
  Check(native_missing.value == -1 && native_missing.posix_errno == Libs::Posix::POSIX_ENOENT,
        "native mkdir validates raw alias traversal before leaving its mount");
  std::strcpy(native_path, "/devlog/system/native");
  std::strcpy(native_other, "/devlog/system/renamed");
  const auto native_mkdir = Libs::NativeKernelBridge::DispatchSyscall(
      {0x88, {reinterpret_cast<uint64_t>(native_path), 0700}});
  Check(native_mkdir.value == 0 && native_mkdir.posix_errno == 0 &&
            FileSystem::KernelStat("/user/devlog/system/native", &revealed_stat) == OK,
        "native mkdir reaches the same lower filesystem through nullfs");
  const auto renamed_directory = Libs::NativeKernelBridge::DispatchSyscall(
      {0x80, {reinterpret_cast<uint64_t>(native_path), reinterpret_cast<uint64_t>(native_other)}});
  Check(renamed_directory.value == 0 && renamed_directory.posix_errno == 0 &&
            FileSystem::KernelStat("/user/devlog/system/renamed", &revealed_stat) == OK,
        "native rename retains nullfs mount identity");
  const auto native_rmdir = Libs::NativeKernelBridge::DispatchSyscall(
      {0x89, {reinterpret_cast<uint64_t>(native_other)}});
  Check(native_rmdir.value == 0 && native_rmdir.posix_errno == 0 &&
            FileSystem::KernelStat("/user/devlog/system/renamed", &revealed_stat) == KERNEL_ERROR_ENOENT,
        "native rmdir removes the lower directory through its alias");
  const int native_file = FileSystem::KernelOpen(native_path, 0x202, 0600);
  Check(native_file >= 3 && FileSystem::KernelClose(native_file) == OK,
        "create native alias unlink fixture");
  std::strcpy(native_other, "/user/devlog/system/escaped");
  const auto native_cross = Libs::NativeKernelBridge::DispatchSyscall(
      {0x80, {reinterpret_cast<uint64_t>(native_path), reinterpret_cast<uint64_t>(native_other)}});
  Check(native_cross.value == -1 && native_cross.posix_errno == Libs::Posix::POSIX_EXDEV,
        "native rename rejects crossing from the alias into its lower mount");
  const auto native_unlink = Libs::NativeKernelBridge::DispatchSyscall(
      {0x0a, {reinterpret_cast<uint64_t>(native_path)}});
  Check(native_unlink.value == 0 && native_unlink.posix_errno == 0 &&
            FileSystem::KernelStat("/user/devlog/system/native", &revealed_stat) == KERNEL_ERROR_ENOENT,
        "native unlink removes the lower file through its alias");
  FileSystem::Umount("/devlog/system");
  Check(Tmpfs::Unmount("/user") == OK, "remove shared lower devlog fixture");
  count = set({"fstype", "nullfs", "fspath", "/original_user", "from", "/user"});
  Check(_putenv_s("KYTY_DIAGNOSTIC_SAFE_MODE_NMOUNT_NULLFS_PASS", "1") == 0,
        "enable existing legacy nullfs stand-in for compatibility checks");
  Check(mount(vectors, count, 0) == 0 && Tmpfs::Contains("/original_user") &&
            Tmpfs::Unmount("/original_user") == OK,
        "nullfs falls back to the existing diagnostic from option");
  count = set({"fstype", "nullfs", "fspath", "/original_user",
               "target", "/user/data", "from", "/user"});
  expect_error(vectors, count, 0, Libs::Posix::POSIX_ENOENT,
               "nullfs does not fall back to from when target is present");
  Check(!Tmpfs::Contains("/original_user"), "unsupported preferred source creates no mount");
  count = set({"fstype", "nullfs", "fspath", "/original_user",
               "target", "/user", "from", "/unavailable"});
  Check(mount(vectors, count, 0) == 0 && Tmpfs::Contains("/original_user") &&
            Tmpfs::Unmount("/original_user") == OK,
        "nullfs selects target before from for the explicitly diagnostic legacy pair");
  count = set({"fstype", "nullfs", "fspath", "/data", "target", "/user/data"});
  expect_error(vectors, count, 0, Libs::Posix::POSIX_ENOENT,
               "legacy diagnostics do not supply the missing lower directory");
  Check(!NullfsMount::Contains("/data") && !Tmpfs::Contains("/data") &&
            FileSystem::KernelStat("/data", &revealed_stat) == OK &&
            FileSystem::KernelStat("/user/data", &revealed_stat) == KERNEL_ERROR_ENOENT,
        "legacy diagnostics leave topology visible without creating the lower directory");
  Check(_putenv_s("KYTY_DIAGNOSTIC_SAFE_MODE_NMOUNT_NULLFS_PASS", saved_legacy.c_str()) == 0,
        "restore legacy nullfs setting");
  FileSystem::Umount("/");
  Check(FileSystem::KernelStat("/data", &revealed_stat) == KERNEL_ERROR_ENOENT,
        "unmounting the read-only root removes data topology lookups");

  const auto direct_root = root / "direct-data-root";
  Check(std::filesystem::create_directories(direct_root / "data"),
        "create direct root data fixture");
  {
    std::ofstream fixture(direct_root / "data" / "marker.bin", std::ios::binary);
    fixture.write("DIRECT", 6);
    Check(fixture.good(), "write direct root data fixture");
  }
  FileSystem::MountReadOnly(direct_root, "/");
  const auto direct_name = FileSystem::GetRealFilename("/data/marker.bin");
  const int direct_fd = FileSystem::KernelOpen("/data/marker.bin", 0, 0);
  std::memset(io, 0, 8);
  const int direct_root_fd = FileSystem::KernelOpen("/", 0x20000, 0);
  std::memset(entries, 0, 512);
  const int direct_root_bytes = direct_root_fd >= 3 ?
      FileSystem::KernelGetdents(direct_root_fd, entries, 512) : -1;
  Check(!direct_name.empty() && direct_fd >= 3 &&
            FileSystem::KernelRead(direct_fd, io, 6) == 6 && std::memcmp(io, "DIRECT", 6) == 0 &&
            direct_root_fd >= 3 && direct_root_bytes > 0 &&
            count_entry(entries, direct_root_bytes, "data") == 1 &&
            FileSystem::KernelClose(direct_root_fd) == OK &&
            FileSystem::KernelClose(direct_fd) == OK,
        "root data takes precedence and remains deduplicated in root enumeration");
  FileSystem::Umount("/");

  const auto underlay = root / "imported-mount";
  Check(std::filesystem::create_directories(underlay), "create immutable mount fixture underlay");
  FileSystem::MountReadOnly(underlay, "/imported_mount");
  count = set({"fstype", "tmpfs", "fspath", "/imported_mount", "mode", "755",
               "size", "262144", "inodes", "512"});
  expect_error(vectors, count - 1, 0, Libs::Posix::POSIX_EINVAL,
               "imported mount rejects an odd vector count");
  expect_error(reinterpret_cast<void*>(1), count, 0, Libs::Posix::POSIX_EFAULT,
               "imported mount validates the guest vector array");
  const auto original_vector = vectors[1];
  vectors[1].address = 1;
  expect_error(vectors, count, 0, Libs::Posix::POSIX_EFAULT,
               "imported mount validates guest option values");
  vectors[1] = original_vector;
  expect_error(vectors, count, 0x10000000, Libs::Posix::POSIX_EOPNOTSUPP,
               "imported mount preserves unsupported original flags");
  Check(!Tmpfs::Contains("/imported_mount"), "failed imported requests do not install a mount");
  Check(mount(vectors, count, 0) == 0 && Tmpfs::Contains("/imported_mount"),
        "imported mount installs supported tmpfs");
  const int fd = FileSystem::KernelOpen("/imported_mount/data", 0x202, 0600);
  auto* payload = static_cast<char*>(memory) + 0x3000;
  auto* output = payload + 32;
  std::memcpy(payload, "mounted", 8);
  Check(fd >= 3 && FileSystem::KernelWrite(fd, payload, 8) == 8 &&
            FileSystem::KernelPread(fd, output, 8, 0) == 8 &&
            std::memcmp(payload, output, 8) == 0 && FileSystem::KernelClose(fd) == OK,
        "imported tmpfs mount owns visible file contents");
  Check(Tmpfs::Unmount("/imported_mount") == OK &&
            !Tmpfs::Contains("/imported_mount") && std::filesystem::is_empty(underlay),
        "imported mount cleanup reveals an unchanged underlay");
  FileSystem::Umount("/imported_mount");
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), 0x4000) == OK,
        "release imported mount guest vectors");
  std::printf("KernelFileSystemTests: imported mount cases passed\n");
#endif
}
