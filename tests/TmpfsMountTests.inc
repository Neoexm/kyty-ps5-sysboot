int RunTmpfsChild(int argc, char** argv) {
  if (argc < 2 || std::strcmp(argv[1], "--tmpfs-child") != 0) return -1;
  if (argc != 4) return 2;
  namespace Tmpfs = Libs::LibKernel::Tmpfs;
  if (Tmpfs::Initialize(argv[2]) != OK) return 3;
  std::shared_ptr<Tmpfs::Handle> handle;
  int result = 4;
  if (Tmpfs::Open(argv[3], 2, 0, &handle) == OK) {
    std::array<char, 6> payload {};
    if (Tmpfs::Pread(handle, payload.data(), payload.size(), 0) == 6 &&
        std::memcmp(payload.data(), "parent", 6) == 0 &&
        Tmpfs::Pwrite(handle, "child", 5, 6) == 5) result = 0;
    if (Tmpfs::Close(handle) != OK) result = 5;
  }
  Tmpfs::Shutdown();
  return result;
}

struct ReadOnlyProviderTmpfsState {
  std::string scope;
  std::shared_ptr<Libs::LibKernel::Tmpfs::Handle> handle;
  Libs::LibKernel::Tmpfs::NodeStat stat {};
};

ReadOnlyProviderTmpfsState CreateReadOnlyProviderTmpfs() {
  namespace Tmpfs = Libs::LibKernel::Tmpfs;
  ReadOnlyProviderTmpfsState state;
  state.scope = "ro_provider_" + std::to_string(
      std::chrono::steady_clock::now().time_since_epoch().count());
  Tmpfs::Shutdown();
  Check(Tmpfs::Initialize(state.scope) == OK &&
            Tmpfs::Mount("/provider-shared", 0755, 262144, 32) == OK &&
            Tmpfs::Open("/provider-shared/sentinel", 0x202, 0600, &state.handle) == OK &&
            Tmpfs::Pwrite(state.handle, "shared-before-export", 20, 0) == 20 &&
            Tmpfs::Fstat(state.handle, &state.stat) == OK,
        "create a live shared tmpfs file before provider export");
  return state;
}

void CheckReadOnlyProviderTmpfs(const ReadOnlyProviderTmpfsState& state) {
  namespace Tmpfs = Libs::LibKernel::Tmpfs;
  std::array<char, 20> bytes {};
  Tmpfs::NodeStat stat {}, by_path {};
  Check(Tmpfs::Contains("/provider-shared") &&
            Tmpfs::Pread(state.handle, bytes.data(), bytes.size(), 0) == bytes.size() &&
            std::memcmp(bytes.data(), "shared-before-export", bytes.size()) == 0 &&
            Tmpfs::Fstat(state.handle, &stat) == OK &&
            Tmpfs::Stat("/provider-shared/sentinel", &by_path) == OK &&
            stat.device == state.stat.device && stat.inode == state.stat.inode &&
            stat.size == state.stat.size && by_path.device == stat.device &&
            by_path.inode == stat.inode && by_path.size == stat.size,
        "provider replay preserves the existing shared tmpfs bytes and identity");
}

#if defined(_WIN32)
class TmpfsNmountFixture {
public:
  struct Iovec { uint64_t address; uint64_t length; };

  TmpfsNmountFixture() {
    const char* flag = std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS");
    saved_flag = flag ? flag : "";
    _putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1");
    Check(Libs::LibKernel::Memory::KernelMapNamedFlexibleMemory(
        &memory, 0x4000, 3, 0, "tmpfs_nmount_fixture") == OK,
        "map registered native nmount vectors and strings");
    Set();
  }

  ~TmpfsNmountFixture() {
    Check(Libs::LibKernel::Memory::KernelMunmap(
        reinterpret_cast<uint64_t>(memory), 0x4000) == OK,
        "release native nmount fixture");
    _putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", saved_flag.c_str());
  }

  void Set(const std::vector<std::string>& options = {
      "fstype", "tmpfs", "fspath", "/system_tmp", "mode", "755",
      "size", "262144", "inodes", "512"}) {
    Check(options.size() < 64, "nmount fixture vector capacity");
    std::memset(memory, 0, 0x4000);
    auto* strings = static_cast<char*>(memory) + 0x1000;
    size_t used = 0;
    for (size_t i = 0; i < options.size(); ++i) {
      Check(used + options[i].size() + 1 <= 0x3000,
            "nmount fixture string capacity");
      std::memcpy(strings + used, options[i].data(), options[i].size());
      Vectors()[i] = {reinterpret_cast<uint64_t>(strings + used),
                      options[i].size() + 1};
      used += options[i].size() + 1;
    }
    count = options.size();
  }

  Iovec* Vectors() { return static_cast<Iovec*>(memory); }

  Libs::NativeKernelBridge::Reply Invoke(uint64_t flags = 0) {
    return Libs::NativeKernelBridge::DispatchSyscall(
        {0x17a, {reinterpret_cast<uint64_t>(memory), count, flags}});
  }

  void* memory = nullptr;
  uint64_t count = 0;
  std::string saved_flag;
};

void CheckTmpfsChild(const std::string& scope) {
  std::wstring executable(32768, L'\0');
  const auto length = GetModuleFileNameW(nullptr, executable.data(),
                                       static_cast<DWORD>(executable.size()));
  Check(length > 0 && length < executable.size(), "locate tmpfs child executable");
  executable.resize(length);
  const std::wstring wide_scope(scope.begin(), scope.end());
  auto command = L"\"" + executable + L"\" --tmpfs-child " + wide_scope +
                 L" /system_tmp/shared";
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process {};
  Check(CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process),
        "start independent tmpfs namespace reader");
  const auto wait = WaitForSingleObject(process.hProcess, 10000);
  if (wait != WAIT_OBJECT_0) {
    TerminateProcess(process.hProcess, 10);
    WaitForSingleObject(process.hProcess, 1000);
  }
  DWORD exit_code = 1;
  const bool exited = GetExitCodeProcess(process.hProcess, &exit_code) != FALSE;
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  Check(wait == WAIT_OBJECT_0 && exited && exit_code == 0,
        "independent process reads and modifies shared mount contents");
}

void CreateInitialDirectoryJunction(const std::filesystem::path& link,
                                    const std::filesystem::path& target) {
  Check(std::filesystem::create_directory(link), "create isolated junction fixture");
  const auto print_name = target.wstring();
  const auto substitute = L"\\??\\" + print_name;
  Check(target.is_absolute() && substitute.size() + print_name.size() < 4000,
        "bound disposable junction target path");
  const auto substitute_bytes = static_cast<uint16_t>(substitute.size() * sizeof(wchar_t));
  const auto print_bytes = static_cast<uint16_t>(print_name.size() * sizeof(wchar_t));
  std::vector<uint8_t> data(16 + substitute_bytes + sizeof(wchar_t) +
                            print_bytes + sizeof(wchar_t));
  const uint32_t tag = 0xa0000003u;
  const uint16_t fields[] {static_cast<uint16_t>(data.size() - 8), 0, 0,
      substitute_bytes, static_cast<uint16_t>(substitute_bytes + sizeof(wchar_t)), print_bytes};
  std::memcpy(data.data(), &tag, sizeof(tag));
  std::memcpy(data.data() + 4, fields, sizeof(fields));
  std::memcpy(data.data() + 16, substitute.c_str(), substitute_bytes + sizeof(wchar_t));
  std::memcpy(data.data() + 16 + substitute_bytes + sizeof(wchar_t),
              print_name.c_str(), print_bytes + sizeof(wchar_t));
  const auto handle = CreateFileW(link.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
      FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  Check(handle != INVALID_HANDLE_VALUE, "open disposable junction metadata");
  DWORD returned = 0;
  const bool created = DeviceIoControl(handle, 0x000900a4u, data.data(),
      static_cast<DWORD>(data.size()), nullptr, 0, &returned, nullptr) != FALSE;
  CloseHandle(handle);
  Check(created, "install directory redirection fixture without privileged symlink creation");
}

void CheckInitialSystemTmpDirectory(const std::filesystem::path& root) {
  namespace Kernel = Libs::LibKernel;
  namespace Tmpfs = Kernel::Tmpfs;
  const auto source = root / "initial-source";
  const auto underlay = root / "initial-underlay";
  const auto nonempty = root / "initial-nonempty";
  const auto conflict = root / "initial-conflict";
  const auto regular = root / "initial-regular";
  const auto writable_source = root / "initial-writable-source";
  Check(std::filesystem::create_directories(source / "already") &&
        std::filesystem::create_directories(writable_source / "system_tmp") &&
        std::filesystem::create_directory(source / "overlap") &&
        std::filesystem::create_directory(underlay) &&
        std::filesystem::create_directory(nonempty) &&
        std::filesystem::create_directory(conflict), "create isolated initial namespace fixtures");
  const auto write_fixture = [](const std::filesystem::path& path) {
    Common::File file;
    Check(file.Create(path), "create initial namespace backing fixture");
    file.Write("original", 8);
    file.Close();
  };
  for (const auto& path: {source / "root-marker", nonempty / "occupied",
                          conflict / "conflict-marker", regular}) write_fixture(path);
  FileSystem::Mount(writable_source, "/");
  Check(FileSystem::MountInitialSystemTmpDirectory(writable_source, underlay) ==
            Kernel::KERNEL_ERROR_EINVAL &&
        !Tmpfs::Contains("/system_tmp") &&
        FileSystem::GetRealFilename("/system_tmp") == writable_source / "system_tmp",
        "initial directory setup requires an already read-only supplied root");
  FileSystem::Umount("/");
  FileSystem::MountReadOnly(source, "/");
  FileSystem::FileStat stat {};
  const auto unchanged_missing = [&]() {
    Check(!Tmpfs::Contains("/system_tmp") &&
          FileSystem::KernelStat("/system_tmp", &stat) == Kernel::KERNEL_ERROR_ENOENT &&
          FileSystem::GetRealFilename("/system_tmp") == source / "system_tmp" &&
          !std::filesystem::exists(source / "system_tmp"),
          "invalid configuration leaves no directory mapping or tmpfs mount");
  };
  struct InvalidDirectory {
    std::filesystem::path path;
    int error;
    const char* label;
  };
  const InvalidDirectory invalid[] {
    {root / "initial-missing", Kernel::KERNEL_ERROR_ENOENT, "reject missing initial underlay"},
    {regular, Kernel::KERNEL_ERROR_ENOTDIR, "reject regular file initial underlay"},
    {nonempty, Kernel::KERNEL_ERROR_ENOTEMPTY, "reject nonempty initial underlay"},
    {"relative-underlay", Kernel::KERNEL_ERROR_EINVAL, "require absolute initial underlay"},
    {source / "overlap", Kernel::KERNEL_ERROR_EINVAL, "keep initial underlay outside source"},
    {underlay / ".." / "initial-underlay", Kernel::KERNEL_ERROR_EINVAL,
      "reject parent components in configured host directory"}
  };
  for (const auto& test: invalid) {
    Check(FileSystem::MountInitialSystemTmpDirectory(source, test.path) == test.error, test.label);
    unchanged_missing();
  }
  const auto redirected = root / "initial-redirected";
  CreateInitialDirectoryJunction(redirected, underlay);
  Check(FileSystem::MountInitialSystemTmpDirectory(source, redirected) == Kernel::KERNEL_ERROR_ELOOP &&
        FileSystem::MountInitialSystemTmpDirectory(source, redirected / "child") ==
            Kernel::KERNEL_ERROR_ELOOP, "reject redirected underlay and redirected ancestor");
  unchanged_missing();
  Check(RemoveDirectoryW(redirected.c_str()) != FALSE &&
        std::filesystem::is_empty(underlay), "remove only disposable junction and retain target");

  write_fixture(source / "system_tmp");
  Check(FileSystem::MountInitialSystemTmpDirectory(source, underlay) == Kernel::KERNEL_ERROR_ENOTDIR &&
        !Tmpfs::Contains("/system_tmp") &&
        FileSystem::GetRealFilename("/system_tmp") == source / "system_tmp" &&
        FileSystem::KernelStat("/system_tmp", &stat) == OK && stat.st_size == 8,
        "conflicting supplied file cannot be hidden by initial directory configuration");
  Check(std::filesystem::remove(source / "system_tmp"), "remove disposable conflicting file");
  CreateInitialDirectoryJunction(source / "system_tmp", underlay);
  Check(FileSystem::MountInitialSystemTmpDirectory(source, underlay) == Kernel::KERNEL_ERROR_ELOOP &&
        !Tmpfs::Contains("/system_tmp") && FileSystem::GetRealFilename("/system_tmp").empty(),
        "redirected supplied entry cannot be hidden by configured fallback");
  Check(RemoveDirectoryW((source / "system_tmp").c_str()) != FALSE,
        "remove redirected supplied fixture");
  unchanged_missing();

  Check(std::filesystem::create_directory(source / "system_tmp"), "create supplied directory");
  write_fixture(source / "system_tmp" / "covered");
  Check(FileSystem::MountInitialSystemTmpDirectory(source, root / "unused-missing") == OK &&
        !Tmpfs::Contains("/system_tmp") &&
        FileSystem::GetRealFilename("/system_tmp") == source / "system_tmp" &&
        FileSystem::KernelStat("/system_tmp/covered", &stat) == OK && stat.st_size == 8 &&
        FileSystem::KernelOpen("/system_tmp/covered", 2, 0) == Kernel::KERNEL_ERROR_EROFS,
        "prefer existing supplied directory and preserve its read-only contents");
  Check(std::filesystem::remove(source / "system_tmp" / "covered") &&
        std::filesystem::remove(source / "system_tmp"), "remove supplied directory fixture");
  unchanged_missing();

  FileSystem::MountReadOnly(conflict, "/system_tmp");
  Check(FileSystem::MountInitialSystemTmpDirectory(source, underlay) == Kernel::KERNEL_ERROR_EBUSY &&
        FileSystem::GetRealFilename("/system_tmp") == conflict &&
        FileSystem::KernelStat("/system_tmp/conflict-marker", &stat) == OK && stat.st_size == 8 &&
        !Tmpfs::Contains("/system_tmp"),
        "initial directory setup preserves an existing conflicting host mount");
  FileSystem::Umount("/system_tmp");
  unchanged_missing();
  FileSystem::Mount(underlay, "/system_tmp");
  Check(FileSystem::MountInitialSystemTmpDirectory(source, underlay) == Kernel::KERNEL_ERROR_EBUSY &&
        FileSystem::GetRealFilename("/system_tmp") == underlay &&
        !Tmpfs::Contains("/system_tmp"), "initial setup cannot silently upgrade a writable mount");
  FileSystem::Umount("/system_tmp");
  unchanged_missing();

  Check(FileSystem::MountInitialSystemTmpDirectory(source, underlay) == OK &&
        FileSystem::MountInitialSystemTmpDirectory(source, underlay) == OK &&
        !Tmpfs::Contains("/system_tmp") &&
        FileSystem::KernelStat("/system_tmp", &stat) == OK &&
        (stat.st_mode & 0170000u) == 0040000u &&
        FileSystem::GetRealFilename("/system_tmp") == underlay &&
        !std::filesystem::exists(source / "system_tmp"),
        "explicit empty underlay supplies an ordinary directory without mounting tmpfs");
  const int covered = FileSystem::KernelOpen("/system_tmp", 0x00020000, 0);
  Check(covered >= 3 && FileSystem::KernelClose(covered) == OK &&
        FileSystem::KernelOpen("/system_tmp/guest-file", 0x202, 0600) == Kernel::KERNEL_ERROR_EROFS &&
        FileSystem::KernelMkdir("/system_tmp/guest-dir", 0755) == Kernel::KERNEL_ERROR_EROFS &&
        FileSystem::KernelOpen("/root-marker", 2, 0) == Kernel::KERNEL_ERROR_EROFS &&
        FileSystem::KernelOpen("/system_tmp/../root-marker", 2, 0) == Kernel::KERNEL_ERROR_EROFS,
        "initial underlay opens as a directory and preserves read-only source traversal");

  struct DirectoryListing {
    std::vector<std::string> names;
    int64_t bytes = 0;
  };
  const auto directory_listing = [&](const char* path) {
    DirectoryListing listing;
    const int descriptor = FileSystem::KernelOpen(path, 0x00020000, 0);
    Check(descriptor >= 3, "open mapped directory listing");
    bool done = false;
    for (unsigned iteration = 0; iteration < 16; ++iteration) {
      std::array<char, 4096> buffer {};
      const int count = FileSystem::KernelGetdents(descriptor, buffer.data(),
                                                  static_cast<int>(buffer.size()));
      Check(count >= 0 && count <= static_cast<int>(buffer.size()), "read bounded directory listing");
      if (count == 0) { done = true; break; }
      listing.bytes += count;
      for (size_t offset = 0; offset < static_cast<size_t>(count);) {
        Check(offset + 8 <= static_cast<size_t>(count), "directory entry header fits");
        uint16_t length = 0;
        std::memcpy(&length, buffer.data() + offset + 4, sizeof(length));
        const auto name_length = static_cast<uint8_t>(buffer[offset + 7]);
        Check(length >= 9 + name_length && offset + length <= static_cast<size_t>(count) &&
              buffer[offset + 8 + name_length] == '\0', "directory entry record is complete");
        listing.names.emplace_back(buffer.data() + offset + 8, name_length);
        if (listing.names.back() == "system_tmp")
          Check(buffer[offset + 6] == 4, "mapped initial entry has directory type");
        offset += length;
      }
    }
    Check(done && FileSystem::KernelClose(descriptor) == OK, "directory enumeration completes");
    return listing;
  };
  FileSystem::MountReadOnly(underlay, "/already");
  FileSystem::MountReadOnly(underlay, "/unlisted/deeper");
  auto listing = directory_listing("/");
  Check(std::count(listing.names.begin(), listing.names.end(), "system_tmp") == 1 &&
        std::count(listing.names.begin(), listing.names.end(), "already") == 1 &&
        std::count(listing.names.begin(), listing.names.end(), "unlisted") == 0 &&
        std::count(listing.names.begin(), listing.names.end(), "deeper") == 0 &&
        std::count(listing.names.begin(), listing.names.end(), "root-marker") == 1 &&
        FileSystem::KernelStat("/", &stat) == OK && stat.st_size == listing.bytes,
        "parent listing merges immediate mounts once and preserves directory stat size");
  FileSystem::Umount("/already");
  FileSystem::Umount("/unlisted/deeper");
  Check(FileSystem::MountInitialSystemTmpDirectory(source, nonempty) ==
            Kernel::KERNEL_ERROR_ENOTEMPTY &&
        FileSystem::GetRealFilename("/system_tmp") == underlay && !Tmpfs::Contains("/system_tmp"),
        "failed reconfiguration preserves the existing valid underlay");

  TmpfsNmountFixture request;
  const auto mounted = request.Invoke();
  Check(mounted.value == 0 && mounted.posix_errno == 0 && Tmpfs::Contains("/system_tmp") &&
        FileSystem::KernelStat("/system_tmp", &stat) == OK && stat.st_mode == 040755,
        "unchanged native request creates tmpfs over explicit initial directory");
  const int contents = FileSystem::KernelOpen("/system_tmp/contents", 0x202, 0600);
  std::array<char, 8> bytes {};
  Check(contents >= 3 && FileSystem::KernelWrite(contents, "bootdata", 8) == 8 &&
        FileSystem::MountInitialSystemTmpDirectory(source, underlay) == OK &&
        FileSystem::KernelPread(contents, bytes.data(), bytes.size(), 0) == 8 &&
        std::memcmp(bytes.data(), "bootdata", 8) == 0 &&
        FileSystem::KernelClose(contents) == OK && std::filesystem::is_empty(underlay) &&
        !std::filesystem::exists(source / "system_tmp"),
        "active shared tmpfs retains contents during idempotent underlay registration");
  Check(Tmpfs::Unmount("/system_tmp") == OK &&
        FileSystem::KernelStat("/system_tmp", &stat) == OK &&
        FileSystem::GetRealFilename("/system_tmp") == underlay &&
        FileSystem::KernelStat("/system_tmp/contents", &stat) == Kernel::KERNEL_ERROR_ENOENT &&
        FileSystem::KernelOpen("/system_tmp/new", 0x202, 0600) == Kernel::KERNEL_ERROR_EROFS &&
        std::filesystem::is_empty(underlay), "unmount reveals unchanged empty read-only underlay");
  FileSystem::Umount("/system_tmp");
  unchanged_missing();
  listing = directory_listing("/");
  Check(std::count(listing.names.begin(), listing.names.end(), "system_tmp") == 0,
        "removing initial mapping removes its parent listing entry");
  Common::File original(source / "root-marker", Common::File::Mode::Read);
  const auto original_bytes = original.ReadWholeBuffer();
  original.Close();
  Check(original_bytes.size() == 8 && std::memcmp(original_bytes.data(), "original", 8) == 0 &&
        !std::filesystem::exists(underlay / "guest-file") &&
        !std::filesystem::exists(underlay / "guest-dir"),
        "initial directory and tmpfs operations leave source and underlay files unchanged");
  FileSystem::Umount("/");
  std::printf("KernelFileSystemTests: initial system_tmp directory cases passed\n");
}

void CheckTmpfsUmask() {
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* symbol = symbols.FindByNid("Rb6ziJKvCCQ", Loader::SymbolType::Func);
  Check(symbol != nullptr, "resolve original libkernel umask export");
  using Umask = int (KYTY_SYSV_ABI *)(int);
  const auto umask = reinterpret_cast<Umask>(symbol->vaddr);
  const int saved = umask(0077);
  const int private_file = FileSystem::KernelOpen("/system_tmp/private-mask", 0x202, 0666);
  FileSystem::FileStat stat {};
  Check(private_file >= 3 &&
        FileSystem::KernelFstat(private_file, &stat) == OK &&
        stat.st_mode == 0100600 && FileSystem::KernelClose(private_file) == OK &&
        FileSystem::KernelMkdir("/system_tmp/private-dir", 0777) == OK &&
        FileSystem::KernelStat("/system_tmp/private-dir", &stat) == OK &&
        stat.st_mode == 040700,
        "guest umask0077 limits newly created tmpfs files and directories");
  Check(umask(0022) == 0077, "guest umask returns previous creation mask");
  const int shared_file = FileSystem::KernelOpen("/system_tmp/shared-mask", 0x202, 0666);
  Check(shared_file >= 3 &&
        FileSystem::KernelFstat(shared_file, &stat) == OK &&
        stat.st_mode == 0100644 && FileSystem::KernelClose(shared_file) == OK &&
        FileSystem::KernelMkdir("/system_tmp/shared-dir", 0777) == OK &&
        FileSystem::KernelStat("/system_tmp/shared-dir", &stat) == OK &&
        stat.st_mode == 040755 &&
        FileSystem::KernelStat("/system_tmp/private-mask", &stat) == OK &&
        stat.st_mode == 0100600,
        "guest umask0022 affects later creation and preserves existing inode modes");
  Check(umask(saved) == 0022, "restore guest creation mask after fixture");
}

void CheckTmpfsNativeIo(TmpfsNmountFixture& request) {
  namespace Kernel = Libs::LibKernel;
  namespace Bridge = Libs::NativeKernelBridge;
  namespace Posix = Libs::Posix;
  const int fd = FileSystem::KernelOpen("/system_tmp/native-io", 0x202, 0600);
  Check(fd >= 3 && FileSystem::KernelWrite(fd, "native", 6) == 6,
        "create native tmpfs descriptor fixture");
  auto* output = reinterpret_cast<FileSystem::FileStat*>(
      static_cast<char*>(request.memory) + 0x3000);
  const auto native_stat = Bridge::DispatchSyscall(
      {0xbd, {static_cast<uint64_t>(fd), reinterpret_cast<uint64_t>(output)}});
  Check(native_stat.value == 0 && native_stat.posix_errno == 0 &&
        output->st_mode == 0100600 && output->st_size == 6,
        "native fstat reports tmpfs descriptor state");
  const auto native_truncate = Bridge::DispatchSyscall(
      {0x1e0, {static_cast<uint64_t>(fd), 3}});
  FileSystem::FileStat stat {};
  Check(native_truncate.value == 0 && native_truncate.posix_errno == 0 &&
        FileSystem::KernelFstat(fd, &stat) == OK && stat.st_size == 3,
        "native ftruncate changes tmpfs file length");
  const auto invalid_output = Bridge::DispatchSyscall(
      {0xbd, {static_cast<uint64_t>(fd), 1}});
  void* read_only = nullptr;
  Check(Kernel::Memory::KernelMapNamedFlexibleMemory(
      &read_only, 0x4000, 1, 0, "tmpfs_readonly_stat") == OK,
      "map read-only native output fixture");
  const auto protected_output = Bridge::DispatchSyscall(
      {0xbd, {static_cast<uint64_t>(fd), reinterpret_cast<uint64_t>(read_only)}});
  const auto negative_size = Bridge::DispatchSyscall(
      {0x1e0, {static_cast<uint64_t>(fd), static_cast<uint64_t>(-1)}});
  Check(invalid_output.value == -1 && invalid_output.posix_errno == Posix::POSIX_EFAULT &&
        protected_output.value == -1 && protected_output.posix_errno == Posix::POSIX_EFAULT &&
        negative_size.value == -1 && negative_size.posix_errno == Posix::POSIX_EINVAL &&
        FileSystem::KernelFstat(fd, &stat) == OK && stat.st_size == 3,
        "native tmpfs calls reject inaccessible outputs and negative size without mutation");
  Check(Kernel::Memory::KernelMunmap(reinterpret_cast<uint64_t>(read_only), 0x4000) == OK,
        "release read-only native output fixture");

  char first_source[] = "AB", second_source[] = "CDEF";
  const FileSystem::KernelIovec writes[] {
      {first_source, 2}, {nullptr, 0}, {second_source, 4}};
  Check(FileSystem::KernelLseek(fd, 7, 0) == 7 &&
        FileSystem::KernelPwritev(fd, writes, 3, 2) == 6 &&
        FileSystem::KernelLseek(fd, 0, 1) == 7,
        "positional vectored write stores all vectors without changing sequential offset");
  std::array<char, 8> data {};
  Check(FileSystem::KernelPread(fd, data.data(), data.size(), 0) == 8 &&
        std::memcmp(data.data(), "naABCDEF", 8) == 0,
        "vectored write produces exact ordered file contents");
  std::array<char, 2> first_output {};
  std::array<char, 4> second_output {};
  const FileSystem::KernelIovec reads[] {
      {first_output.data(), first_output.size()}, {nullptr, 0},
      {second_output.data(), second_output.size()}};
  Check(FileSystem::KernelPreadv(fd, reads, 3, 1) == 6 &&
        std::memcmp(first_output.data(), "aA", 2) == 0 &&
        std::memcmp(second_output.data(), "BCDE", 4) == 0 &&
        FileSystem::KernelLseek(fd, 0, 1) == 7,
        "positional vectored read fills buffers without changing sequential offset");
  char changed = 'X';
  const FileSystem::KernelIovec invalid_writes[] {{&changed, 1}, {nullptr, 1}};
  char untouched = 'Z';
  const FileSystem::KernelIovec invalid_reads[] {{&untouched, 1}, {nullptr, 1}};
  Check(FileSystem::KernelPwritev(fd, invalid_writes, 2, 0) == Kernel::KERNEL_ERROR_EFAULT &&
        FileSystem::KernelPreadv(fd, invalid_reads, 2, 0) == Kernel::KERNEL_ERROR_EFAULT &&
        untouched == 'Z' &&
        FileSystem::KernelPread(fd, data.data(), data.size(), 0) == 8 &&
        std::memcmp(data.data(), "naABCDEF", 8) == 0 &&
        FileSystem::KernelLseek(fd, 0, 1) == 7 &&
        FileSystem::KernelClose(fd) == OK,
        "invalid later vectors leave earlier destinations, file contents and offset unchanged");
}
#endif

void CheckTmpfsMounts(const std::filesystem::path& root) {
#if defined(_WIN32)
  namespace Kernel = Libs::LibKernel;
  namespace Tmpfs = Kernel::Tmpfs;
  namespace Posix = Libs::Posix;
  const auto scope = "tmpfs_mount_test_" + std::to_string(
      std::chrono::steady_clock::now().time_since_epoch().count());
  Tmpfs::Shutdown();
  Check(Tmpfs::Initialize(scope) == OK, "initialize isolated tmpfs test namespace");
  CheckInitialSystemTmpDirectory(root);
  const auto underlay = root / "tmpfs-underlay";
  Check(std::filesystem::create_directories(underlay / "system_tmp") &&
        std::filesystem::create_directory(underlay / "system") &&
        std::filesystem::create_directory(underlay / "system_ex"),
        "create tmpfs mountpoint fixture");
  Check(std::filesystem::create_directory(underlay / "quota") &&
        std::filesystem::create_directory(underlay / "inodes"),
        "create quota mountpoint fixtures");
  for (const auto& file : {underlay / "root-marker",
                           underlay / "regular-target",
                           underlay / "system_tmp" / "covered.dat",
                           root / "outside-host-only.dat"}) {
    Common::File fixture;
    Check(fixture.Create(file), "create immutable namespace fixture");
    fixture.Write("original", 8);
    fixture.Close();
  }
  FileSystem::MountReadOnly(underlay, "/");
  FileSystem::FileStat stat {};
  Check(FileSystem::MountTmpfs("/missing", 0755, 262144, 512) ==
            Kernel::KERNEL_ERROR_ENOENT &&
        !Tmpfs::Contains("/missing"), "mount requires an existing target");
  Check(FileSystem::MountTmpfs("/regular-target", 0755, 262144, 512) ==
            Kernel::KERNEL_ERROR_ENOTDIR &&
        !Tmpfs::Contains("/regular-target"), "mount requires a directory target");
  Check(FileSystem::MountTmpfs("/system_tmp", 0755, 0, 512) != OK &&
        FileSystem::MountTmpfs("/system_tmp", 0755, 262144, 0) != OK &&
        FileSystem::MountTmpfs("/system_tmp", 0755, Tmpfs::MaximumMountBytes + 1, 512) ==
            Kernel::KERNEL_ERROR_ENOTSUP &&
        !Tmpfs::Contains("/system_tmp"),
        "invalid and unsupported resource requests leave no partial mount");

  TmpfsNmountFixture request;
  const auto expect_error = [&](int expected, const char* label) {
    const auto reply = request.Invoke();
    Check(reply.value == -1 && reply.posix_errno == expected, label);
    Check(!Tmpfs::Contains("/system_tmp") &&
          FileSystem::KernelStat("/system_tmp/covered.dat", &stat) == OK &&
          stat.st_size == 8, "rejected native request preserves covered namespace");
    request.Set();
  };
  request.count = 9;
  expect_error(Posix::POSIX_EINVAL, "nmount rejects an odd vector count");
  request.count = 258;
  expect_error(Posix::POSIX_EINVAL, "nmount bounds vector count before reading");
  const auto bad_vectors = Libs::NativeKernelBridge::DispatchSyscall(
      {0x17a, {1, 10, 0}});
  Check(bad_vectors.value == -1 && bad_vectors.posix_errno == Posix::POSIX_EFAULT,
        "nmount checks vector-array readability");
  request.Vectors()[0].address = 1;
  expect_error(Posix::POSIX_EFAULT, "nmount checks option-name readability");
  request.Vectors()[1].address = 1;
  expect_error(Posix::POSIX_EFAULT, "nmount checks option-value readability");
  request.Vectors()[0].length = 0;
  expect_error(Posix::POSIX_EINVAL, "nmount rejects empty option vectors");
  request.Vectors()[1].length -= 1;
  expect_error(Posix::POSIX_EINVAL, "nmount requires a terminating NUL");
  *reinterpret_cast<char*>(request.Vectors()[1].address + 1) = '\0';
  expect_error(Posix::POSIX_EINVAL, "nmount rejects embedded string terminators");
  request.Set({"fstype", "tmpfs", "fspath", "/system_tmp", "mode", "888",
               "size", "262144", "inodes", "512"});
  expect_error(Posix::POSIX_EINVAL, "nmount parses mode as octal");
  request.Set({"fstype", "tmpfs", "fspath", "/system_tmp", "mode", "755",
               "size", "18446744073709551616", "inodes", "512"});
  expect_error(Posix::POSIX_EINVAL, "nmount rejects numeric overflow");
  request.Set({"fstype", "tmpfs", "fspath", "/system_tmp", "mode", "755",
               "size", "-1", "inodes", "512"});
  expect_error(Posix::POSIX_EINVAL, "nmount rejects signed size");
  request.Set({"fstype", "unknown", "fspath", "/system_tmp", "mode", "755",
               "size", "262144", "inodes", "512"});
  expect_error(Posix::POSIX_EOPNOTSUPP, "unsupported filesystem cannot report success");
  request.Set({"fstype", "tmpfs", "fspath", "/system_tmp", "mode", "755",
               "size", "262144", "unknown", "512"});
  expect_error(Posix::POSIX_EINVAL, "nmount rejects unknown options");
  request.Set({"fstype", "tmpfs", "fspath", "/regular-target/../system_tmp", "mode", "755",
               "size", "262144", "inodes", "512"});
  expect_error(Posix::POSIX_ENOTDIR, "nmount cannot normalize away a regular-file path component");
  request.Set({"fstype", "tmpfs", "fspath", "/missing/../system_tmp", "mode", "755",
               "size", "262144", "inodes", "512"});
  expect_error(Posix::POSIX_ENOENT, "nmount cannot normalize away a missing path component");
  const auto flags = request.Invoke(1);
  Check(flags.value == -1 && flags.posix_errno == Posix::POSIX_EOPNOTSUPP &&
        !Tmpfs::Contains("/system_tmp"), "unsupported mount flags do not mount");

  const std::vector<std::string> exfat_options = {
      "fstype", "exfatfs", "fspath", "/system", "from", "/dev/ssd0.system",
      "large", "yes", "timezone", "static", "async", "", "ignoreacl", "",
      "dirmask", "511", "mask", "511"};
  request.Set(exfat_options);
  auto exfat_reply = request.Invoke(1);
  Check(exfat_reply.value == -1 && exfat_reply.posix_errno == Posix::POSIX_ENOENT &&
        !Kernel::ExfatMount::Contains("/system"),
        "nmount does not infer an active system provider from system_b");
  request.Set(exfat_options);
  Check(request.Invoke().posix_errno == Posix::POSIX_EOPNOTSUPP,
        "writable exfat nmount remains unsupported for immutable media");
  auto duplicate_exfat = exfat_options;
  duplicate_exfat.insert(duplicate_exfat.end(), {"mask", "511"});
  request.Set(duplicate_exfat);
  Check(request.Invoke(1).posix_errno == Posix::POSIX_EINVAL,
        "exfat nmount rejects duplicate options");
  Check(exfat_reply.value == 0 && exfat_reply.posix_errno == 0 &&
        Kernel::ExfatMount::Contains("/system/hello.bin"),
        "exact exfat nmount vector mounts explicit sector backing");
  FileSystem::Umount("/system");
  Check(!Kernel::ExfatMount::Contains("/system/hello.bin"),
        "unmount removes the native exfat namespace");

  request.Set();
  const auto mounted = request.Invoke();
  Check(mounted.value == 0 && mounted.posix_errno == 0 &&
        Tmpfs::Contains("/system_tmp"), "ten-iovec request creates a mount");
  Check(FileSystem::KernelStat("/system_tmp", &stat) == OK &&
        stat.st_mode == 040755 && stat.st_uid == 0 && stat.st_gid == 0,
        "mounted root exposes requested mode and ownership");
  Check(FileSystem::KernelStat("/system_tmp/covered.dat", &stat) ==
            Kernel::KERNEL_ERROR_ENOENT &&
        FileSystem::GetRealFilename("/system_tmp/new").empty(),
        "tmpfs covers underlay and does not expose a writable host path");
  Check(FileSystem::MountTmpfs("/system_tmp", 0755, 262144, 512) ==
            Kernel::KERNEL_ERROR_ENOTSUP, "unsupported mount stacking does not replace contents");
  Check(FileSystem::KernelOpen("/system_tmp/missing/file", 0x202, 0600) ==
            Kernel::KERNEL_ERROR_ENOENT &&
        FileSystem::KernelMkdir("/system_tmp/missing/dir", 0755) ==
            Kernel::KERNEL_ERROR_ENOENT,
        "tmpfs creation requires existing parent directories");
  Check(FileSystem::KernelMkdir("/system_tmp/dir", 0755) == OK,
        "create tmpfs directory");
  const int fd = FileSystem::KernelOpen("/system_tmp/data", 0xa02, 0600);
  Check(fd >= 3 && FileSystem::KernelWrite(fd, "payload", 7) == 7,
        "guest creates and writes tmpfs contents");
  Check(FileSystem::KernelOpen("/system_tmp/data", 0xa02, 0600) ==
            Kernel::KERNEL_ERROR_EEXIST, "exclusive creation detects existing inode");
  Check(FileSystem::KernelOpen("/system_tmp/missing/../new", 0x202, 0600) ==
            Kernel::KERNEL_ERROR_ENOENT &&
        FileSystem::KernelOpen("/system_tmp/data/../new", 0x202, 0600) ==
            Kernel::KERNEL_ERROR_ENOTDIR &&
        FileSystem::KernelOpen("/system_tmp/missing/../../root-marker", 0, 0) ==
            Kernel::KERNEL_ERROR_ENOENT &&
        FileSystem::KernelStat("/system_tmp/new", &stat) ==
            Kernel::KERNEL_ERROR_ENOENT,
        "parent normalization cannot erase missing or non-directory path components");
  std::array<char, 16> data {};
  Check(FileSystem::KernelLseek(fd, 0, 0) == 0 &&
        FileSystem::KernelRead(fd, data.data(), 7) == 7 &&
        std::memcmp(data.data(), "payload", 7) == 0 &&
        FileSystem::KernelPwrite(fd, "X", 1, 2) == 1 &&
        FileSystem::KernelLseek(fd, 0, 1) == 7,
        "sequential and positional IO preserve their offset contracts");
  Check(FileSystem::KernelFtruncate(fd, 4) == OK &&
        FileSystem::KernelFtruncate(fd, 8) == OK &&
        FileSystem::KernelPread(fd, data.data(), 8, 0) == 8 &&
        std::memcmp(data.data(), "paXl", 4) == 0 &&
        data[4] == 0 && data[5] == 0 && data[6] == 0 && data[7] == 0,
        "truncate shrink discards bytes and extension reads as zeros");
  Check(FileSystem::KernelStat("/system_tmp/dir/../data", &stat) == OK &&
        stat.st_size == 8 &&
        FileSystem::KernelStat("/system_tmp/../root-marker", &stat) == OK &&
        stat.st_size == 8, "parent traversal works within mount and across mount root");
  Check(FileSystem::KernelOpen("/system_tmp/../root-marker", 2, 0) ==
            Kernel::KERNEL_ERROR_EROFS &&
        FileSystem::KernelOpen("/system_tmp/../../outside-host-only.dat", 0, 0) ==
            Kernel::KERNEL_ERROR_ENOENT,
        "traversal preserves immutable guest root and cannot escape into host parent");
  Check(FileSystem::KernelRename("/system_tmp/data", "/root-marker") ==
            Kernel::KERNEL_ERROR_EXDEV &&
        FileSystem::KernelStat("/system_tmp/data", &stat) == OK,
        "cross-filesystem rename preserves source and destination");
  Check(FileSystem::KernelRename("/system_tmp/data", "/system_tmp/renamed") == OK &&
        FileSystem::KernelStat("/system_tmp/data", &stat) == Kernel::KERNEL_ERROR_ENOENT &&
        FileSystem::KernelUnlink("/system_tmp/renamed") == OK &&
        FileSystem::KernelFstat(fd, &stat) == OK && stat.st_nlink == 0 &&
        FileSystem::KernelPread(fd, data.data(), 4, 0) == 4 &&
        std::memcmp(data.data(), "paXl", 4) == 0,
        "rename and unlink preserve open inode contents");
  const int replacement = FileSystem::KernelOpen("/system_tmp/renamed", 0x202, 0600);
  Check(replacement >= 3 && FileSystem::KernelWrite(replacement, "new", 3) == 3 &&
        FileSystem::KernelFstat(replacement, &stat) == OK && stat.st_size == 3 &&
        FileSystem::KernelFstat(fd, &stat) == OK && stat.st_size == 8 &&
        FileSystem::KernelClose(replacement) == OK && FileSystem::KernelClose(fd) == OK,
        "recreated pathname refers to a distinct inode");

  const int shared = FileSystem::KernelOpen("/system_tmp/shared", 0x202, 0600);
  Check(shared >= 3 && FileSystem::KernelWrite(shared, "parent", 6) == 6,
        "create shared-process tmpfs fixture");
  CheckTmpfsChild(scope);
  Check(FileSystem::KernelPread(shared, data.data(), 11, 0) == 11 &&
        std::memcmp(data.data(), "parentchild", 11) == 0 &&
        FileSystem::KernelClose(shared) == OK,
        "parent descriptor sees changes from independent process");

  const int directory = FileSystem::KernelOpen("/system_tmp", 0, 0);
  std::array<char, 1024> entries {};
  const int entry_bytes = FileSystem::KernelGetdents(
      directory, entries.data(), static_cast<int>(entries.size()));
  Check(directory >= 3 && entry_bytes > 0 &&
        static_cast<size_t>(entry_bytes) <= entries.size(),
        "guest directory enumeration returns tmpfs entries");
  bool found_shared = false, found_renamed = false;
  for (size_t offset = 0; offset < static_cast<size_t>(entry_bytes);) {
    Check(static_cast<size_t>(entry_bytes) - offset >= 8,
          "tmpfs directory record header fits");
    uint16_t length = 0;
    std::memcpy(&length, entries.data() + offset + 4, sizeof(length));
    const auto name_length = static_cast<uint8_t>(entries[offset + 7]);
    Check(length >= 9 + name_length &&
          length <= static_cast<size_t>(entry_bytes) - offset &&
          entries[offset + 8 + name_length] == '\0',
          "tmpfs directory records contain bounded terminated names");
    const std::string_view name(entries.data() + offset + 8, name_length);
    found_shared |= name == "shared";
    found_renamed |= name == "renamed";
    offset += length;
  }
  Check(found_shared && found_renamed && FileSystem::KernelClose(directory) == OK,
        "tmpfs directory entries match current linked names");
  Check(FileSystem::KernelMkdir("/system_tmp/dir/child", 0700) == OK &&
        FileSystem::KernelRmdir("/system_tmp/dir") == Kernel::KERNEL_ERROR_ENOTEMPTY &&
        FileSystem::KernelRename("/system_tmp/dir", "/system_tmp/dir/child/moved") ==
            Kernel::KERNEL_ERROR_EINVAL &&
        FileSystem::KernelRmdir("/system_tmp/dir/child") == OK,
        "directory removal and rename reject nonempty or cyclic changes");
  Check(FileSystem::KernelMkdir("/system_tmp/dot-parent", 0755) == OK &&
        FileSystem::KernelMkdir("/system_tmp/dot-parent/child", 0755) == OK,
        "create final-dot path fixtures");
  FileSystem::FileStat preserved_parent {}, preserved_child {};
  Check(FileSystem::KernelStat("/system_tmp/dot-parent", &preserved_parent) == OK &&
        FileSystem::KernelStat("/system_tmp/dot-parent/child", &preserved_child) == OK,
        "capture final-dot inode identities");
  for (const char* path : {"/system_tmp/dir/.", "/system_tmp/dir/./",
                           "/system_tmp/dot-parent/child/..",
                           "/system_tmp/dot-parent/child/../"}) {
    Check(FileSystem::KernelRmdir(path) == Kernel::KERNEL_ERROR_EINVAL,
          "rmdir rejects final dot or dot-dot before normalization");
    Check(FileSystem::KernelRename(path, "/system_tmp/dot-moved") ==
              Kernel::KERNEL_ERROR_EINVAL &&
          FileSystem::KernelRename("/system_tmp/renamed", path) ==
              Kernel::KERNEL_ERROR_EINVAL,
          "rename rejects final dot or dot-dot in either path");
    Check(FileSystem::KernelStat("/system_tmp/dir", &stat) == OK &&
          FileSystem::KernelStat("/system_tmp/dot-parent", &stat) == OK &&
          stat.st_ino == preserved_parent.st_ino &&
          FileSystem::KernelStat("/system_tmp/dot-parent/child", &stat) == OK &&
          stat.st_ino == preserved_child.st_ino &&
          FileSystem::KernelStat("/system_tmp/renamed", &stat) == OK &&
          stat.st_size == 3 &&
          FileSystem::KernelStat("/system_tmp/dot-moved", &stat) ==
              Kernel::KERNEL_ERROR_ENOENT,
          "final-dot rejection preserves source, destination and parent inodes");
  }
  const int already_open = FileSystem::KernelOpen("/system_tmp/renamed", 0, 0);
  Check(already_open >= 3, "open file before changing modeled credentials");
  Tmpfs::SetCredentials(1000, 1000);
  Check(FileSystem::KernelOpen("/system_tmp/renamed", 0, 0) ==
            Kernel::KERNEL_ERROR_EACCES &&
        FileSystem::KernelOpen("/system_tmp/denied", 0x202, 0600) ==
            Kernel::KERNEL_ERROR_EACCES &&
        FileSystem::KernelMkdir("/system_tmp/denied-dir", 0755) ==
            Kernel::KERNEL_ERROR_EACCES &&
        FileSystem::KernelPread(already_open, data.data(), 3, 0) == 3 &&
        std::memcmp(data.data(), "new", 3) == 0,
        "modeled credentials enforce open and directory permissions without revoking open descriptors");
  Tmpfs::SetCredentials(0, 0);
  Check(FileSystem::KernelClose(already_open) == OK &&
        FileSystem::KernelStat("/system_tmp/denied", &stat) ==
            Kernel::KERNEL_ERROR_ENOENT,
        "permission denial creates no inode");
  CheckTmpfsUmask();
  CheckTmpfsNativeIo(request);

  Check(FileSystem::MountTmpfs("/quota", 0755, 2 * Tmpfs::PageSize, 8) == OK,
        "mount bounded byte quota");
  const int quota = FileSystem::KernelOpen("/quota/data", 0x202, 0600);
  Tmpfs::Usage empty {}, full {}, shrunk {};
  Check(quota >= 3 && Tmpfs::QueryUsage("/quota", &empty) == OK,
        "query empty-file quota charge");
  std::vector<char> page(Tmpfs::PageSize, 'q');
  Check(FileSystem::KernelWrite(quota, page.data(), page.size()) ==
            static_cast<int64_t>(page.size()) &&
        Tmpfs::QueryUsage("/quota", &full) == OK &&
        full.charged_bytes > empty.charged_bytes &&
        full.charged_bytes <= full.byte_limit,
        "tmpfs charges committed data within mount limit");
  Check(FileSystem::KernelFtruncate(quota, 2 * Tmpfs::PageSize) ==
            Kernel::KERNEL_ERROR_ENOSPC &&
        FileSystem::KernelFstat(quota, &stat) == OK &&
        stat.st_size == static_cast<int64_t>(Tmpfs::PageSize) &&
        FileSystem::KernelPread(quota, data.data(), 1, 0) == 1 && data[0] == 'q',
        "quota exhaustion rolls back failed growth and preserves contents");
  char first_byte = 'A', second_byte = 'B';
  const FileSystem::KernelIovec quota_vectors[] {{&first_byte, 1}, {&second_byte, 1}};
  Tmpfs::Usage unchanged {};
  Check(FileSystem::KernelPwritev(quota, quota_vectors, 2, Tmpfs::PageSize - 1) ==
            Kernel::KERNEL_ERROR_ENOSPC &&
        FileSystem::KernelPread(quota, data.data(), 1, Tmpfs::PageSize - 1) == 1 &&
        data[0] == 'q' &&
        FileSystem::KernelFstat(quota, &stat) == OK &&
        stat.st_size == static_cast<int64_t>(Tmpfs::PageSize) &&
        Tmpfs::QueryUsage("/quota", &unchanged) == OK &&
        unchanged.charged_bytes == full.charged_bytes &&
        FileSystem::KernelLseek(quota, 0, 1) == static_cast<int64_t>(Tmpfs::PageSize),
        "combined vector quota failure preserves even an earlier in-range vector");
  Check(FileSystem::KernelFtruncate(quota, 0) == OK &&
        Tmpfs::QueryUsage("/quota", &shrunk) == OK &&
        shrunk.charged_bytes == empty.charged_bytes &&
        FileSystem::KernelWrite(quota, "q", 1) == Kernel::KERNEL_ERROR_ENOSPC &&
        FileSystem::KernelLseek(quota, 0, 0) == 0 &&
        FileSystem::KernelWrite(quota, "q", 1) == 1 &&
        FileSystem::KernelClose(quota) == OK,
        "shrinking releases pages while leaving the file offset unchanged");

  Check(FileSystem::MountTmpfs("/inodes", 0755, 262144, 2) == OK,
        "mount bounded inode quota");
  const int inode = FileSystem::KernelOpen("/inodes/one", 0x202, 0600);
  Tmpfs::Usage usage {};
  Check(inode >= 3 && Tmpfs::QueryUsage("/inodes", &usage) == OK &&
        usage.inodes == 2 &&
        FileSystem::KernelOpen("/inodes/two", 0x202, 0600) ==
            Kernel::KERNEL_ERROR_ENOSPC &&
        FileSystem::KernelMkdir("/inodes/dir", 0755) == Kernel::KERNEL_ERROR_ENOSPC,
        "root and files consume finite inode quota");
  Check(FileSystem::KernelUnlink("/inodes/one") == OK &&
        FileSystem::KernelOpen("/inodes/two", 0x202, 0600) ==
            Kernel::KERNEL_ERROR_ENOSPC &&
        FileSystem::KernelClose(inode) == OK,
        "unlinked open inode remains charged until final close");
  const int reused = FileSystem::KernelOpen("/inodes/two", 0x202, 0600);
  Check(reused >= 3 && FileSystem::KernelClose(reused) == OK,
        "final close reclaims unlinked inode quota");

  Check(Tmpfs::Unmount("/quota") == OK && Tmpfs::Unmount("/inodes") == OK &&
        Tmpfs::Unmount("/system_tmp") == OK,
        "unmount releases completed tmpfs fixtures");
  Check(FileSystem::KernelStat("/system_tmp/covered.dat", &stat) == OK &&
        stat.st_size == 8 &&
        FileSystem::KernelOpen("/system_tmp/covered.dat", 2, 0) ==
            Kernel::KERNEL_ERROR_EROFS &&
        !std::filesystem::exists(underlay / "system_tmp" / "data") &&
        !std::filesystem::exists(underlay / "system_tmp" / "shared"),
        "unmount reveals unchanged immutable underlay without leaked temporary files");
  Common::File original(underlay / "system_tmp" / "covered.dat", Common::File::Mode::Read);
  const auto original_bytes = original.ReadWholeBuffer();
  original.Close();
  Check(original_bytes.size() == 8 &&
        std::memcmp(original_bytes.data(), "original", 8) == 0,
        "temporary filesystem operations preserve original backing bytes");
  request.Set({"fstype", "tmpfs", "fspath", "/system_tmp", "mode", "755",
               "size", "-1", "inodes", "512", "size", "262144", "mode", "700"});
  const auto repeated = request.Invoke();
  Check(repeated.value == -1 && repeated.posix_errno == Posix::POSIX_EINVAL &&
        !Tmpfs::Contains("/system_tmp"), "nmount rejects duplicate options");
  request.Set();
  Check(request.Invoke().value == 0 &&
        FileSystem::KernelStat("/system_tmp", &stat) == OK && stat.st_mode == 040755,
        "valid nmount request still mounts after duplicate rejection");
  const int transient = FileSystem::KernelOpen("/system_tmp/transient", 0x202, 0600);
  Check(transient >= 3 && FileSystem::KernelWrite(transient, "boot", 4) == 4 &&
        FileSystem::KernelClose(transient) == OK,
        "populate mounted namespace before final attachment closes");
  Tmpfs::Shutdown();
  Check(Tmpfs::Initialize(scope) == OK && !Tmpfs::Contains("/system_tmp") &&
        !Tmpfs::Contains("/quota") && !Tmpfs::Contains("/inodes"),
        "new boot attachment after final shutdown has no stale mounts");
  FileSystem::Umount("/");
  std::printf("KernelFileSystemTests: tmpfs mount cases passed\n");
#else
  (void)root;
#endif
}
