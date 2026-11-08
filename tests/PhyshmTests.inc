int RunPhyshmChild(int argc, char** argv) {
#if defined(_WIN32)
  if (argc < 2 || std::strcmp(argv[1], "--physhm-child") != 0) return -1;
  if (argc != 4) return 2;
  using namespace Libs::LibKernel;
  namespace FS = Libs::LibKernel::FileSystem;
  namespace Memory = Libs::LibKernel::Memory;
  const auto evidence = Common::PathFromUtf8(argv[2]);
  if (_wfreopen(evidence.c_str(), L"wb", stdout) == nullptr) return 3;
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", argv[3]) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS", "") == 0,
        "select the physical-shm fixture scope without the broad raw guard");
  Common::InitializeThreads();
  Common::Subsystems subsystems;
  subsystems.Initialize<Config::Lifecycle>();
  Config::ConfigOptions options;
  options.printf_direction = Config::LogDirection::Console;
  Config::Load(options);
  subsystems.Initialize<Log::Lifecycle>();
  subsystems.Initialize<Memory::Lifecycle>();
  FS::Initialize();

  void* storage = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&storage, 0x4000, 3, 0, "physhm-fixture") == OK,
        "map guest argument storage for the physical-shm ABI");
  auto* page = static_cast<uint8_t*>(storage);
  auto* path = reinterpret_cast<char*>(page);
  auto* stat = reinterpret_cast<FS::FileStat*>(page + 0x800);
  const auto set_path = [&](const char* value) {
    const auto length = std::strlen(value) + 1;
    Check(length < 0x700, "physical-shm fixture path fits guest storage");
    std::memcpy(path, value, length);
  };

  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* open_symbol = symbols.FindByNid("n371J5cP+uo", Loader::SymbolType::Func);
  const auto* truncate_symbol = symbols.FindByNid("ih4CD9-gghM", Loader::SymbolType::Func);
  const auto* stat_symbol = symbols.FindByNid("mqQMh1zPPT8", Loader::SymbolType::Func);
  const auto* mmap_symbol = symbols.FindByNid("BPE9s9vQQXo", Loader::SymbolType::Func);
  const auto* name_symbol = symbols.FindByNid("DGMG3JshrZU", Loader::SymbolType::Func);
  Check(open_symbol != nullptr && truncate_symbol != nullptr && stat_symbol != nullptr &&
            mmap_symbol != nullptr && name_symbol != nullptr,
        "the original physical-shm helper NIDs all resolve without the raw guard");
  using Open = int (KYTY_SYSV_ABI *)(const char*, int, uint16_t, int);
  using Truncate = int (KYTY_SYSV_ABI *)(int, int64_t);
  using Stat = int64_t (KYTY_SYSV_ABI *)(int, FS::FileStat*);
  using Mmap = void* (KYTY_SYSV_ABI *)(void*, size_t, int, int, int, int64_t);
  using SetName = int (KYTY_SYSV_ABI *)(const void*, uint64_t, const char*);
  const auto open = reinterpret_cast<Open>(open_symbol->vaddr);
  const auto truncate = reinterpret_cast<Truncate>(truncate_symbol->vaddr);
  const auto fstat = reinterpret_cast<Stat>(stat_symbol->vaddr);
  const auto mmap = reinterpret_cast<Mmap>(mmap_symbol->vaddr);
  const auto set_name = reinterpret_cast<SetName>(name_symbol->vaddr);

  constexpr size_t BusSize = 0x8c7e0;
  set_path("/shmAinBusBuffer");
  const int fd = open(path, 0x202, 0666, 12);
  Check(fd >= 3 && FS::GetDescriptorFlags(fd) == 0,
        "the AudioIn tuple creates a non-cloexec descriptor");
  *Libs::Posix::GetErrorAddr() = 0;
  Check(truncate(fd, BusSize) == 0 && *Libs::Posix::GetErrorAddr() == 0,
        "the ftruncate import accepts the physical-shm descriptor");
  *stat = {};
  Check(fstat(fd, stat) == 0 && stat->st_size == BusSize,
        "the fstat import observes the physical-shm backing size");
  void* first = mmap(nullptr, BusSize, 3, 1, fd, 0);
  Check(first != reinterpret_cast<void*>(static_cast<intptr_t>(-1)),
        "the original mmap import creates the shared read-write mapping");
  Check(set_name(first, BusSize, path) == OK,
        "the range-name import names the mapping");
  Memory::VirtualQueryInfo query {};
  Check(Memory::KernelVirtualQuery(first, 0, &query, sizeof(query)) == OK &&
            std::strcmp(query.name, "/shmAinBusBuffer") == 0,
        "the mapping retains the original physical-shm name");
  auto* first_bytes = static_cast<volatile uint8_t*>(first);
  first_bytes[0] = 0x41;
  first_bytes[BusSize - 1] = 0x7e;

  const int reopened = open(path, 2, 0, 12);
  Check(reopened >= 3 && reopened != fd,
        "the same physical-shm name reopens without O_CREAT");
  *stat = {};
  Check(FS::KernelFstat(reopened, stat) == OK && stat->st_size == BusSize,
        "the reopened descriptor sees the existing object size");
  void* second = mmap(nullptr, BusSize, 3, 1, reopened, 0);
  Check(second != reinterpret_cast<void*>(static_cast<intptr_t>(-1)),
        "the reopened descriptor maps the same backing");
  auto* second_bytes = static_cast<volatile uint8_t*>(second);
  Check(second_bytes[0] == 0x41 && second_bytes[BusSize - 1] == 0x7e,
        "two mappings of the named physical object share bytes");
  Check(FS::KernelClose(fd) == OK && first_bytes[0] == 0x41 && second_bytes[0] == 0x41,
        "live mappings and a reopened descriptor survive creator-descriptor close");

  const int posix = FS::KernelShmOpen(path, 0x202, 0666);
  Check(posix >= 3, "the same visible name can exist in the separate POSIX shm namespace");
  *stat = {};
  Check(FS::KernelFstat(posix, stat) == OK && stat->st_size == 0,
        "the POSIX object does not alias the physical-shm backing");
  set_path("/.physhm/shmAinBusBuffer");
  Check(FS::KernelShmOpen(path, 2, 0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL &&
            FS::KernelShmOpen(path, 0x202, 0666) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL &&
            FS::KernelShmUnlink(path) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
        "ordinary POSIX shm cannot open, create or unlink the private physical namespace");
  set_path("/shmAinBusBuffer");
  const int after_alias_attempt = open(path, 2, 0, 12);
  *stat = {};
  Check(after_alias_attempt >= 3 && fstat(after_alias_attempt, stat) == 0 &&
            stat->st_size == BusSize && second_bytes[0] == 0x41,
        "rejected POSIX alias attempts leave the physical object intact");
  Check(FS::KernelClose(after_alias_attempt) == OK,
        "close the physical descriptor used after alias rejection");

  set_path("/shmAinBusOther");
  const int other = open(path, 0x202, 0600, 12);
  Check(other >= 3 && truncate(other, 0x4000) == 0,
        "a distinct valid name and mode create an independent physical object");
  Check(truncate(-1, 0x4000) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EBADF,
        "the ftruncate import preserves POSIX failure translation");
  *Libs::Posix::GetErrorAddr() = 0;
  Check(fstat(-1, stat) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EPERM,
        "the fstat import preserves the current invalid-descriptor translation");
  *Libs::Posix::GetErrorAddr() = 0;
  Check(mmap(nullptr, 0x4000, 3, 1, -1, 0) ==
            reinterpret_cast<void*>(static_cast<intptr_t>(-1)) &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOTSUP,
        "the original mmap import preserves the unsupported shared-descriptor failure");

  set_path("/shmAinBusBuffer");
  const int readonly = open(path, 0, 0, 12);
  Check(readonly >= 3 && FS::KernelFtruncate(readonly, 0x4000) == KERNEL_ERROR_EBADF,
        "a read-only physical descriptor cannot resize the backing");
  set_path("/shmAinBusCloexec");
  const int cloexec = open(path, 0x100202, 0600, 12);
  Check(cloexec >= 3 && FS::GetDescriptorFlags(cloexec) == 1,
        "the verified close-on-exec flag is retained on the descriptor");

  Check(FS::KernelClose(cloexec) == OK && FS::KernelClose(readonly) == OK &&
            FS::KernelClose(other) == OK && FS::KernelClose(posix) == OK &&
            FS::KernelClose(reopened) == OK,
        "all surviving physical and POSIX descriptors close through the normal path");
  set_path("/shmAinBusBuffer");
  const int after_close = open(path, 2, 0, 12);
  *stat = {};
  Check(after_close >= 3 && fstat(after_close, stat) == 0 && stat->st_size == BusSize &&
            second_bytes[0] == 0x41 && FS::KernelClose(after_close) == OK,
        "the named physical object and live mappings survive the last descriptor close");
  std::printf("PHYSHM_FIXTURE_PASS exact_nid=1 descriptor=1 shared_backing=1 namespace_separate=1 errors=1 descriptor_cleanup=1\n");
  std::fflush(stdout);
  FS::Shutdown();
  subsystems.Destroy();
  return 0;
#else
  (void)argc;
  (void)argv;
  return -1;
#endif
}
