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
  void* other_map = mmap(nullptr, 0x4000, 3, 1, other, 0);
  Check(other_map != reinterpret_cast<void*>(static_cast<intptr_t>(-1)) &&
            static_cast<volatile uint8_t*>(other_map)[0] == 0,
        "the distinct physical object starts with independent zeroed backing");
  static_cast<volatile uint8_t*>(other_map)[0] = 0x22;
  Check(second_bytes[0] == 0x41,
        "writes to a distinct physical object do not alias the AudioIn object");

  set_path("/shmAinBusBuffer");
  Check(open(path, 0xa02, 0666, 12) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EEXIST,
        "exclusive duplicate creation returns EEXIST");
  set_path("/shmAinBusMissing");
  Check(open(path, 2, 0, 12) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOENT,
        "opening a missing physical object without O_CREAT returns ENOENT");
  Check(open(path, 0x102, 0666, 12) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
        "unsupported open flags are rejected without a descriptor");
  Check(open(path, 0x202, 0x8000, 12) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
        "non-permission mode bits are rejected");
  Check(open(path, 0x202, 0666, 11) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOTSUP,
        "an unverified physical memory type is not silently admitted");
  set_path("shmAinBusRelative");
  Check(open(path, 0x202, 0666, 12) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
        "a relative physical-shm name is rejected");
  Check(open(nullptr, 0x202, 0666, 12) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT &&
            open(reinterpret_cast<const char*>(1), 0x202, 0666, 12) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT,
        "null and unreadable path pointers return EFAULT without a string read");
  path[0] = '/';
  std::memset(path + 1, 'x', 60);
  path[61] = '\0';
  Check(open(path, 0x202, 0666, 12) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENAMETOOLONG,
        "a name that cannot fit the bounded scope key returns ENAMETOOLONG");

  *Libs::Posix::GetErrorAddr() = 0;
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

void CheckPhyshm(const std::filesystem::path& root) {
#if defined(_WIN32)
  const auto evidence = root / "physhm_child.log";
  const auto scope = "ph" + std::to_string(GetCurrentProcessId() % 100000) + "_" +
                     std::to_string(GetTickCount64() % 1000000);
  std::wstring executable(32768, L'\0');
  const auto length = GetModuleFileNameW(nullptr, executable.data(),
                                         static_cast<DWORD>(executable.size()));
  Check(length > 0 && length < executable.size(), "locate the physical-shm fixture executable");
  executable.resize(length);
  const std::wstring wscope(scope.begin(), scope.end());
  auto command = L"\"" + executable + L"\" --physhm-child \"" +
                 evidence.native() + L"\" " + wscope;
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  Check(job != nullptr &&
            SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits,
                                    sizeof(limits)),
        "contain the physical-shm fixture in a kill-on-close job");
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process {};
  Check(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr,
                       &startup, &process),
        "start the isolated physical-shm production-path fixture");
  Check(AssignProcessToJobObject(job, process.hProcess) &&
            ResumeThread(process.hThread) != static_cast<DWORD>(-1),
        "assign and resume the physical-shm fixture");
  Check(WaitForSingleObject(process.hProcess, 30000) == WAIT_OBJECT_0,
        "physical-shm fixture completes within 30 seconds");
  DWORD exit_code = 0;
  Check(GetExitCodeProcess(process.hProcess, &exit_code) && exit_code == 0,
        "physical-shm fixture exits successfully");
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  CloseHandle(job);
  Common::File output(evidence, Common::File::Mode::Read);
  Check(!output.IsInvalid(), "open physical-shm fixture evidence");
  const auto bytes = output.ReadWholeBuffer();
  const std::string text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  Check(text.find("PHYSHM_FIXTURE_PASS exact_nid=1 descriptor=1 shared_backing=1 namespace_separate=1 errors=1 descriptor_cleanup=1") != std::string::npos,
        "physical-shm fixture retains the exact success marker");
#else
  (void)root;
#endif
}
