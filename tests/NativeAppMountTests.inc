#if defined(_WIN32)
// mini-syscore's spawn trampoline 0x40d0f0 with a budget: raw 0x2c2 through 0x472330, 0x4721f0(id, 1), 0x471520(getpid, block), then 571 and execve. The failure exit at 0x40d29e is 0x4721f0(id, 4) and 0x472190 (raw 0x2c3).
struct NativeAppMountBlock {
  uint8_t* block;
  int32_t* local;

  void Build(const char* title) {
    std::memset(block, 0, 0x180);
    if (title != nullptr) std::memcpy(block + 0x10, title, std::strlen(title));
    AppMountStore32(block + 0x50, 0x02000000);
    const uint64_t output = reinterpret_cast<uint64_t>(local);
    std::memcpy(block + 0xb0, &output, sizeof(output));
    *local = -1;
  }
  Libs::NativeKernelBridge::Reply Begin() const {
    return Libs::NativeKernelBridge::DispatchSyscall({0x2c2, {reinterpret_cast<uint64_t>(block), 1}});
  }
};

void NativeAppMountBecome(int pid, uint64_t authority, bool capture) {
  using namespace Libs::LibKernel;
  auto fixture = MakeAuthInfoScopeLifecycleFixture(pid);
  fixture.identity.authority_id = authority;
  AuthInfoScopeStore64(fixture.record.data(), authority);
  AuthInfoScopeStore64(fixture.record.data() + 8, 1ull << 62);
  Check(AuthInfo::BuildCaptureEnvelope(fixture.record, fixture.identity, &fixture.capture, nullptr), "build native app mount identity");
  Process::ClearVerifiedOriginalSelf();
  Process::InstallVerifiedOriginalSelf(fixture.identity);
  if (capture) Check(Process::InstallVerifiedAuthInfo(fixture.capture), "install native app mount capability");
}

Libs::NativeKernelBridge::Reply NativeAppMountEnd(const int32_t* id) {
  return Libs::NativeKernelBridge::DispatchSyscall({0x2c3, {reinterpret_cast<uint64_t>(id)}});
}

// {1,14,0x40,id} with oldp NULL and newlen 4, as 0x4721f0 sends it.
Libs::NativeKernelBridge::Reply NativeAppMountState(uint32_t* mib, int32_t id, uint32_t* value, uint64_t* length) {
  mib[0] = 1; mib[1] = 14; mib[2] = 0x40; mib[3] = static_cast<uint32_t>(id);
  return Libs::NativeKernelBridge::DispatchSyscall({0xca, {reinterpret_cast<uint64_t>(mib), 4,
      length != nullptr ? reinterpret_cast<uint64_t>(value) : 0, reinterpret_cast<uint64_t>(length),
      length == nullptr ? reinterpret_cast<uint64_t>(value) : 0, length == nullptr ? 4u : 0u}});
}
#endif

int RunNativeAppMountChild(int argc, char** argv) {
  if (argc < 2 || std::strcmp(argv[1], "--native-app-mount-child") != 0) return -1;
#if defined(_WIN32)
  if (argc != 4) return 2;
  using namespace Libs;
  using namespace Libs::LibKernel;
  Common::InitializeThreads();
  Common::Subsystems subsystems;
  subsystems.Initialize<Config::Lifecycle>();
  Config::ConfigOptions options;
  options.printf_direction = Config::LogDirection::Silent;
  Config::Load(options);
  subsystems.Initialize<Log::Lifecycle>();
  subsystems.Initialize<Memory::Lifecycle>();
  subsystems.Initialize<PthreadLifecycle>();
  const int32_t id = std::atoi(argv[2]);
  const int32_t expected = std::atoi(argv[3]);
  void* memory = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&memory, 0x4000, 3, 0, "native-app-mount-child") == OK, "map child app mount storage");
  auto* bytes = static_cast<uint8_t*>(memory);
  NativeAppMountBlock spawn {bytes, reinterpret_cast<int32_t*>(bytes + 0x200)};
  auto* mib = reinterpret_cast<uint32_t*>(bytes + 0x300);
  auto* value = reinterpret_cast<uint32_t*>(bytes + 0x320);
  auto* length = reinterpret_cast<uint64_t*>(bytes + 0x340);
  auto* end_id = reinterpret_cast<int32_t*>(bytes + 0x360);

  Process::ScopedGuestProcessPid as_child(7421);
  NativeAppMountBecome(7421, 0x4800000000000022ull, true);
  *length = 8;
  Check(NativeAppMountState(mib, id, value, length).value == 0 && value[0] == 4,
        "another host process sees the application and its failed-spawn state");
  *end_id = id;
  Check(NativeAppMountEnd(end_id).value == 0, "and ends it through 0x2c3");
  spawn.Build("NPXS45091");
  Check(spawn.Begin().value == 0 && *spawn.local == expected, "its next begin takes the freed slot from the shared free list");
  Process::ClearVerifiedOriginalSelf();
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), 0x4000) == OK, "release child app mount storage");
  std::printf("NativeAppMountTests: crosshost_child=pass\n");
  subsystems.Destroy();
  return 0;
#else
  return 2;
#endif
}

#if defined(_WIN32)
void CheckNativeAppMount() {
  using namespace Libs;
  using namespace Libs::LibKernel;
  using Budget::Entry;
  AuthInfoScopeLifecycleSavedEnvironment saved_scope("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE");
  AuthInfoScopeLifecycleSavedEnvironment saved_only("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY");
  AuthInfoScopeLifecycleSavedEnvironment saved_socket("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET");
  AuthInfoScopeLifecycleSavedEnvironment saved_entry("KYTY_PS5_BUDGET_SYSTEM_DMEM_ENTRY");
  AuthInfoScopeLifecycleSavedEnvironment saved_evidence("KYTY_PS5_BUDGET_SYSTEM_DMEM_EVIDENCE_SHA256");
  char scope[21] {};
  std::snprintf(scope, sizeof(scope), "n%08lx%08lx", GetCurrentProcessId(), static_cast<unsigned long>(GetTickCount()));
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", scope) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET", "") == 0 &&
            _putenv_s("KYTY_PS5_BUDGET_SYSTEM_DMEM_ENTRY", "1:1:1073741824") == 0 &&
            _putenv_s("KYTY_PS5_BUDGET_SYSTEM_DMEM_EVIDENCE_SHA256",
                      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") == 0,
        "scope native app mount");

  void* memory = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&memory, 0x8000, 3, 0, "native-app-mount") == OK, "map native app mount storage");
  auto* bytes = static_cast<uint8_t*>(memory);
  auto* guard = bytes + 0x4000;
  NativeAppMountBlock spawn {bytes, reinterpret_cast<int32_t*>(bytes + 0x200)};
  auto* mib = reinterpret_cast<uint32_t*>(bytes + 0x300);
  auto* value = reinterpret_cast<uint32_t*>(bytes + 0x320);
  auto* length = reinterpret_cast<uint64_t*>(bytes + 0x340);
  auto* end_id = reinterpret_cast<int32_t*>(bytes + 0x360);
  auto* in = reinterpret_cast<Entry*>(bytes + 0x400);
  auto* out = reinterpret_cast<Entry*>(bytes + 0x800);
  auto* count = reinterpret_cast<int32_t*>(bytes + 0xc00);
  auto* name = reinterpret_cast<char*>(bytes + 0xc40);
  auto* sysctl_mib = reinterpret_cast<uint32_t*>(bytes + 0xc80);
  auto* public_info = bytes + 0x1000;

  // the trap only turns 0x8002xxxx into errno when posix_errno is 0
  const auto refused = [](NativeKernelBridge::Reply reply, int code) {
    return reply.value == code && reply.posix_errno == 0;
  };
  const auto read_state = [&](int32_t id) {
    *length = 8;
    value[0] = value[1] = 0xcccccccc;
    return NativeAppMountState(mib, id, value, length);
  };
  const auto set_state = [&](int32_t id, uint32_t state) {
    value[0] = state;
    return NativeAppMountState(mib, id, value, nullptr);
  };
  const auto set_record = [&](int pid) {
    sysctl_mib[0] = 1; sysctl_mib[1] = 14; sysctl_mib[2] = 35; sysctl_mib[3] = static_cast<uint32_t>(pid);
    return NativeKernelBridge::DispatchSyscall({0xca, {reinterpret_cast<uint64_t>(sysctl_mib), 4, 0, 0,
        reinterpret_cast<uint64_t>(spawn.block), 0x98}});
  };
  // 0x40d1f9..0x40d176, after a successful begin
  const auto commit = [&](int pid) {
    std::memcpy(spawn.block, spawn.local, sizeof(int32_t));
    return set_state(*spawn.local, 1).value == 0 && set_record(pid).value == 0;
  };
  const auto budget_get = [] { return NativeKernelBridge::DispatchSyscall({0x261, {}}); };
  const auto budget_set = [](int64_t id) { return NativeKernelBridge::DispatchSyscall({0x23b, {static_cast<uint64_t>(id)}}); };

  constexpr int mini = 7410;
  constexpr int sysav = 7411;
  constexpr int orbis = 7412;
  constexpr int syscore = 7413;
  constexpr int failed = 7414;
  constexpr uint64_t mini_authority = 0x4800000000000022ull;
  int64_t system_id = -1;
  {
    Process::ScopedGuestProcessPid as_mini(mini);
    NativeAppMountBecome(mini, mini_authority, true);
    *count = 14;
    Check(NativeKernelBridge::DispatchSyscall({0x23a, {static_cast<uint64_t>(-4ll), reinterpret_cast<uint64_t>(out),
              reinterpret_cast<uint64_t>(count)}}).value == 0, "read the measured system pool");
    std::memcpy(in, out, sizeof(Entry) * 14);
    std::strcpy(name, "system budget");
    system_id = NativeKernelBridge::DispatchSyscall({0x238, {reinterpret_cast<uint64_t>(name), 2,
        reinterpret_cast<uint64_t>(in), 14, reinterpret_cast<uint64_t>(out)}}).value;
    Check(system_id == 0, "mini's system budget is id 0, so the children take the 0x2c2 branch");
  }

  Process::RegisterRforkChild(sysav, mini);
  {
    Process::ScopedGuestProcessPid as_child(sysav);
    Process::ClearVerifiedOriginalSelf();
    spawn.Build("NPXS40095");
    Check(refused(spawn.Begin(), KERNEL_ERROR_ENOSYS) && *spawn.local == -1, "an unknown authority creates nothing");
    NativeAppMountBecome(mini, 0x4800000010000004ull, true);
    Check(refused(NativeKernelBridge::DispatchSyscall({0x2c2, {1}}), KERNEL_ERROR_EPERM),
          "an unlisted authority is refused before the block is copied in");

    NativeAppMountBecome(mini, mini_authority, true);
    Check(refused(NativeKernelBridge::DispatchSyscall({0x2c2, {1}}), KERNEL_ERROR_EFAULT), "an unreadable block faults");
    Check(Memory::KernelMprotect(guard, 0x4000, 0) == OK, "protect native app mount guard");
    Check(refused(NativeKernelBridge::DispatchSyscall({0x2c2, {reinterpret_cast<uint64_t>(guard - 0x177)}}), KERNEL_ERROR_EFAULT),
          "a block whose 0x178 bytes cross into a guard page faults");
    Check(refused(NativeKernelBridge::DispatchSyscall({0x2c2, {reinterpret_cast<uint64_t>(guard - 0x178)}}), KERNEL_ERROR_EINVAL),
          "the kernel copies 0x178 bytes, not mini's 0x180 allocation");
    Check(Memory::KernelMprotect(guard, 0x4000, 3) == OK, "restore native app mount guard");
    std::memset(spawn.block + 0xb0, 0, 8);
    Check(refused(spawn.Begin(), KERNEL_ERROR_EINVAL), "a null +0xb0 output is EINVAL");
    for (const uint32_t category: {0u, 0x10000u, 0x02000100u, 0x03000000u}) {
      spawn.Build("NPXS40095");
      AppMountStore32(spawn.block + 0x50, category);
      Check(refused(spawn.Begin(), KERNEL_ERROR_ENOSYS) && *spawn.local == -1,
            "categories whose create path builds unmodelled state create nothing");
    }
    // ShellCore's public info has the category at +0 and the title at +4, so it reads as category 0 with no title.
    std::memset(public_info, 0, 0x180);
    AppMountStore32(public_info, 0x02000000);
    std::memcpy(public_info + 4, "NPXS40095", 9);
    std::memcpy(public_info + 0xb0, spawn.block + 0xb0, 8);
    Check(refused(NativeKernelBridge::DispatchSyscall({0x2c2, {reinterpret_cast<uint64_t>(public_info)}}), KERNEL_ERROR_ENOSYS) &&
              *spawn.local == -1,
          "the raw call reads the kernel block layout, not the libkernel public one");

    spawn.Build("NPXS40095");
    const auto reply = spawn.Begin();
    Check(reply.value == 0 && reply.posix_errno == 0 && *spawn.local == 1, "SysAv's untouched block gets app id 1 through +0xb0");
    Check(read_state(1).value == 0 && value[0] == 5 && value[1] == 0, "the new application is in state 5");
    Check(commit(sysav), "0x4721f0(id, 1) and the self {1,14,35} record succeed");
    int32_t attached = 0;
    Check(read_state(1).value == 0 && value[0] == 1 && AppMount::GetAttachedApp(sysav, &attached) && attached == 1,
          "SysAv is attached to its application in state 1");
    Check(budget_set(system_id).value == 0 && budget_get().value == system_id, "571 attaches the budget after the app steps");
  }

  Process::RegisterRforkChild(orbis, mini);
  {
    Process::ScopedGuestProcessPid as_child(orbis);
    spawn.Build(nullptr);
    Check(spawn.Begin().value == 0 && *spawn.local == 2 && commit(orbis), "the untitled orbis-itf child gets app id 2");
  }
  Process::RegisterRforkChild(syscore, mini);
  {
    Process::ScopedGuestProcessPid as_child(syscore);
    spawn.Build("NPXS45091");
    Check(spawn.Begin().value == 0 && *spawn.local == 3 && commit(syscore), "SysCore's block gets app id 3");
    Check(budget_set(system_id).value == 0, "SysCore's child attaches the budget");
    Check(Process::MarkRforkChildExecCommitted(syscore, GetCurrentProcessId(), "/system/sys/SceSysCore.elf"), "commit the SysCore exec");
    NativeAppMountBecome(syscore, 0x4800000000000007ull, true);
    int32_t attached = 0;
    Check(AppMount::GetAttachedApp(syscore, &attached) && attached == 3 && budget_get().value == system_id,
          "SysCore keeps its application and budget across exec");
    Check(AppMount::GetAttachedApp(sysav, &attached) && attached == 1 && AppMount::GetAttachedApp(orbis, &attached) && attached == 2,
          "each child holds only its own application");

    *end_id = 3;
    Check(refused(NativeAppMountEnd(end_id), KERNEL_ERROR_EBUSY) && read_state(3).value == 0 && value[0] == 1,
          "SysCore's authority cannot end a running application");
    NativeAppMountBecome(syscore, 0x4800000000000010ull, true);
    Check(refused(NativeAppMountEnd(end_id), KERNEL_ERROR_EBUSY), "nor can ShellCore's");
    NativeAppMountBecome(syscore, 0x4800000010000004ull, true);
    Check(refused(NativeAppMountEnd(nullptr), KERNEL_ERROR_EPERM), "0x2c3 checks the authority before the copyin");
    Process::ClearVerifiedOriginalSelf();
    Check(refused(NativeAppMountEnd(end_id), KERNEL_ERROR_ENOSYS), "and an unknown authority ends nothing");
  }

  Process::RegisterRforkChild(failed, mini);
  int32_t failed_id = 0;
  {
    Process::ScopedGuestProcessPid as_child(failed);
    NativeAppMountBecome(mini, mini_authority, true);
    Check(Memory::KernelMprotect(guard, 0x4000, 1) == OK, "make the id output read-only");
    spawn.Build("NPXS40095");
    std::memcpy(spawn.block + 0xb0, &guard, 8);
    Check(refused(spawn.Begin(), KERNEL_ERROR_EFAULT) && read_state(4).posix_errno == Posix::POSIX_ESRCH,
          "a failed id copyout destroys the application it created");
    Check(Memory::KernelMprotect(guard, 0x4000, 3) == OK, "restore the id output");
    spawn.Build("NPXS40095");
    Check(spawn.Begin().value == 0 && *spawn.local == 0x2004, "the destroyed slot is reused a generation on");
    failed_id = *spawn.local;

    // 0x40d29e after a failed 571 or execve.
    *end_id = failed_id;
    Check(set_state(failed_id, 4).value == 0, "0x4721f0(id, 4)");
    Check(refused(NativeAppMountEnd(reinterpret_cast<const int32_t*>(1)), KERNEL_ERROR_EFAULT), "0x2c3 faults on an unreadable id");
    *end_id = 0;
    Check(refused(NativeAppMountEnd(end_id), KERNEL_ERROR_ESRCH), "id 0 is never ended");
    *end_id = 4;
    Check(refused(NativeAppMountEnd(end_id), KERNEL_ERROR_ESRCH), "a stale generation does not match");
  }

  Process::NotifyRforkChildExited(failed, 255);
  Check(read_state(failed_id).value == 0 && value[0] == 4, "child exit leaves the application in place");
  const int32_t reused = 0x4000 | (failed_id & 0x1fff);
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  TempDirectory child_output;
  const auto child_log = child_output.Path() / "native_app_mount_child.log";
  SECURITY_ATTRIBUTES inherited {};
  inherited.nLength = sizeof(inherited);
  inherited.bInheritHandle = TRUE;
  HANDLE log_handle = CreateFileW(child_log.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &inherited, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  HANDLE null_input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherited, OPEN_EXISTING, 0, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  std::array<wchar_t, 32768> executable {};
  const DWORD executable_length = GetModuleFileNameW(nullptr, executable.data(), executable.size());
  Check(job != nullptr && log_handle != INVALID_HANDLE_VALUE && null_input != INVALID_HANDLE_VALUE && executable_length != 0 &&
            executable_length < executable.size() && SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
        "prepare native app mount child");
  std::wstring command = L"\"" + std::wstring(executable.data(), executable_length) + L"\" --native-app-mount-child " +
      std::to_wstring(failed_id) + L" " + std::to_wstring(reused);
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = log_handle;
  startup.hStdError = log_handle;
  startup.hStdInput = null_input;
  PROCESS_INFORMATION process {};
  Check(CreateProcessW(nullptr, command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup, &process) &&
            AssignProcessToJobObject(job, process.hProcess) && ResumeThread(process.hThread) != DWORD(-1),
        "launch the native app mount child in the same scope");
  if (WaitForSingleObject(process.hProcess, 30000) != WAIT_OBJECT_0) {
    TerminateJobObject(job, 10);
    WaitForSingleObject(process.hProcess, 1000);
  }
  DWORD child_exit = 1;
  const bool child_exited = GetExitCodeProcess(process.hProcess, &child_exit) != FALSE;
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  CloseHandle(job);
  FlushFileBuffers(log_handle);
  CloseHandle(log_handle);
  CloseHandle(null_input);
  if (!child_exited || child_exit != 0) {
    std::ifstream log(child_log, std::ios::binary);
    const std::string text {std::istreambuf_iterator<char>(log), std::istreambuf_iterator<char>()};
    std::fprintf(stderr, "native app mount child exited=%u status=0x%lx\n%s\n", child_exited ? 1u : 0u,
                 static_cast<unsigned long>(child_exit), text.c_str());
  }
  Check(child_exited && child_exit == 0, "the cross-host child ends the failed application and begins another");
  Check(read_state(failed_id).posix_errno == Posix::POSIX_ESRCH && read_state(reused).value == 0 && value[0] == 5,
        "this host sees the child's end and its new application");
  int32_t attached = 0;
  Check(AppMount::GetAttachedApp(syscore, &attached) && attached == 3 && read_state(3).value == 0 && value[0] == 1,
        "the running SysCore application is untouched");

  {
    Process::ScopedGuestProcessPid as_syscore(syscore);
    NativeAppMountBecome(syscore, 0x4800000000000007ull, true);
    std::memset(public_info, 0, 0x18b0);
    AppMountStore32(public_info, 0x05000000);
    std::memcpy(public_info + 4, "NPXS40082", 9);
    Check(KernelBeginAppMount2(public_info, 0, 0) == 5, "the libkernel wrapper still creates ShellCore's application");
  }
  {
    Process::ScopedGuestProcessPid as_mini(mini);
    NativeAppMountBecome(mini, mini_authority, true);
    *end_id = reused;
    Check(set_state(reused, 1).value == 0 && NativeAppMountEnd(end_id).value == 0 && read_state(reused).posix_errno == Posix::POSIX_ESRCH,
          "mini's authority ends an application outside states 4 and 5");
  }

  Process::NotifyRforkChildExited(syscore, 0);
  Process::NotifyRforkChildExited(orbis, 0);
  Process::NotifyRforkChildExited(sysav, 0);
  std::snprintf(scope, sizeof(scope), "o%08lx%08lx", GetCurrentProcessId(), static_cast<unsigned long>(GetTickCount()));
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", scope) == 0, "switch to an unrelated scope");
  {
    Process::ScopedGuestProcessPid as_mini(mini);
    NativeAppMountBecome(mini, mini_authority, true);
    Check(read_state(3).posix_errno == Posix::POSIX_ESRCH, "another scope has its own application table");
    spawn.Build("NPXS40095");
    Check(spawn.Begin().value == 0 && *spawn.local == 1, "and its own ids");
  }
  Process::ClearVerifiedOriginalSelf();
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), 0x8000) == OK, "release native app mount storage");
  std::printf("NativeAppMountTests: dispatch=pass sequence=pass cleanup=pass crosshost=pass\n");
}
#endif
