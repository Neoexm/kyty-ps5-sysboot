#if defined(_WIN32)
void AppRegistrationBecome(int pid, uint64_t authority, bool capture, bool bit62) {
  using namespace Libs::LibKernel;
  auto fixture = MakeAuthInfoScopeLifecycleFixture(pid);
  fixture.identity.authority_id = authority;
  AuthInfoScopeStore64(fixture.record.data(), authority);
  AuthInfoScopeStore64(fixture.record.data() + 8, bit62 ? 1ull << 62 : 0);
  Check(AuthInfo::BuildCaptureEnvelope(fixture.record, fixture.identity, &fixture.capture, nullptr),
        "build synthetic application-state authorization fixture");
  Process::ClearVerifiedOriginalSelf();
  Process::InstallVerifiedOriginalSelf(fixture.identity);
  if (capture) Check(Process::InstallVerifiedAuthInfo(fixture.capture), "install synthetic application-state capability");
}

Libs::NativeKernelBridge::Reply AppRegistrationSysctl(int selector, int32_t id, void* output,
    uint64_t* length, const void* input = nullptr, uint64_t input_size = 0) {
  const int32_t mib[4] {1, 14, selector, id};
  return Libs::NativeKernelBridge::DispatchSyscall({0xca, {reinterpret_cast<uint64_t>(mib), 4,
      reinterpret_cast<uint64_t>(output), reinterpret_cast<uint64_t>(length),
      reinterpret_cast<uint64_t>(input), input_size}});
}

Libs::LibKernel::AppMount::Record AppRegistrationMinimalPrefix(int32_t id) {
  Libs::LibKernel::AppMount::Record record {};
  std::memcpy(record.data(), &id, sizeof(id));
  std::memcpy(record.data() + 0x10, "NPXS40082", 9);
  record[0x1a] = 3;
  record[0x1d] = 0xff;
  record[0x49] = 0xff;
  AppMountStore32(record.data() + 0x50, 0x05000000);
  return record;
}
#endif

int RunAppRegistrationStateChild(int argc, char** argv) {
  if (argc < 2 || std::strcmp(argv[1], "--app-registration-state-child") != 0) return -1;
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
  const std::string scope = argv[2];
  const int32_t id = std::atoi(argv[3]);
  Process::ScopedGuestProcessPid as_child(7301);
  AppRegistrationBecome(7301, 0x4800000000000007ull, true, true);
  AppMount::Record record {};
  uint64_t length = record.size();
  Check(AppRegistrationSysctl(65, id, record.data(), &length).value == 0 &&
            record == AppRegistrationMinimalPrefix(id), "child sees the shared application prefix");
  std::array<uint32_t, 2> state {};
  length = sizeof(state);
  Check(AppRegistrationSysctl(0x40, id, state.data(), &length).value == 0 && state[0] == 5 && state[1] == 0,
        "child sees the production application's initial state");
  HANDLE ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, ("Local\\kyty_app_state_ready_" + scope).c_str());
  HANDLE go = OpenEventA(SYNCHRONIZE, FALSE, ("Local\\kyty_app_state_go_" + scope).c_str());
  Check(ready != nullptr && go != nullptr && SetEvent(ready) && WaitForSingleObject(go, 30000) == WAIT_OBJECT_0,
        "child waits for the parent to observe shared initial state");
  CloseHandle(ready);
  CloseHandle(go);
  for (uint32_t value = 0x10000000; value < 0x10000100; ++value) {
    Check(KernelSetAppState(id, value) == OK, "child commits synthetic concurrent state values through the export");
    length = sizeof(state);
    Check(AppRegistrationSysctl(0x40, id, state.data(), &length).value == 0 && state[0] == value && state[1] == 0,
          "child reads its committed shared state");
  }
  Check(KernelSetAppState(id, 1) == OK, "child commits the observed registration target state");
  Process::ClearVerifiedOriginalSelf();
  std::printf("AppRegistrationStateTests: crosshost_child=pass\n");
  subsystems.Destroy();
  return 0;
#else
  return 2;
#endif
}

void CheckAppRegistrationState() {
#if defined(_WIN32)
  using namespace Libs;
  using namespace Libs::LibKernel;
  AuthInfoScopeLifecycleSavedEnvironment saved_scope("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE");
  AuthInfoScopeLifecycleSavedEnvironment saved_only("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY");
  AuthInfoScopeLifecycleSavedEnvironment saved_socket("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET");
  char scope[21] {};
  std::snprintf(scope, sizeof(scope), "a%08lx%08lx", GetCurrentProcessId(), static_cast<unsigned long>(GetTickCount()));
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", scope) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET", "") == 0, "scope application registration tests");
  Process::ScopedGuestProcessPid as_syscore(7300);
  AppRegistrationBecome(7300, 0x4800000000000007ull, true, true);
  void* memory = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&memory, 0x8000, 3, 0, "application-registration-state") == OK,
        "map application registration guest storage");
  auto* base = static_cast<uint8_t*>(memory);
  auto* output = base + 0x2000;
  auto* input = base + 0x2200;
  auto* length = reinterpret_cast<uint64_t*>(base + 0x2400);
  auto* state = reinterpret_cast<uint32_t*>(base + 0x2420);
  auto* guard = base + 0x4000;
  auto* error = Posix::GetErrorAddr();
  std::memset(base, 0, 0x18b0);
  AppMountStore32(base, 0x05000000);
  std::memcpy(base + 4, "NPXS40082", 9);
  const int32_t id = KernelBeginAppMount2(base, 0, 0);
  Check(id == 1, "the observed first application id follows reserved id zero");
  // only title, category and id are set; the other public fields are zero
  const auto original = AppRegistrationMinimalPrefix(id);
  const auto query = [&](int32_t wanted = 1) {
    *length = original.size();
    return AppRegistrationSysctl(65, wanted, output, length);
  };
  Check(query().value == 0 && *length == original.size() && std::memcmp(output, original.data(), original.size()) == 0,
        "selector 65 reads the exact app-owned 0x98 prefix produced by the wrapper");
  const auto read_state = [&] {
    *length = 8;
    return AppRegistrationSysctl(0x40, id, state, length);
  };
  Check(read_state().value == 0 && state[0] == 5 && state[1] == 0, "created state is five with zero secondary state");
  for (const int32_t missing: {0, -1, 0x55, 0x2001, 0x10001}) {
    Check(query(missing).posix_errno == Posix::POSIX_ESRCH, "missing and stale generation-bearing ids do not alias the live object");
  }
  *length = 0;
  Check(AppRegistrationSysctl(65, id, nullptr, length).value == 0 && *length == 0x98,
        "null output returns the required information size");
  std::memset(output, 0xa5, 0x100);
  *length = 0x24;
  Check(AppRegistrationSysctl(65, id, output, length).posix_errno == Posix::POSIX_ENOMEM && *length == 0x24 &&
            std::memcmp(output, original.data(), 0x24) == 0 && output[0x24] == 0xa5,
        "short output copies only its capacity and returns ENOMEM");
  *length = 0x99;
  Check(AppRegistrationSysctl(65, id, output, length).posix_errno == Posix::POSIX_EINVAL && *length == 0x99,
        "oversized output is EINVAL without publishing a new length");
  *length = 0x98;
  Check(AppRegistrationSysctl(65, 0x55, reinterpret_cast<void*>(1), length).value == KERNEL_ERROR_EFAULT && *length == 0x98,
        "useracc failure precedes missing-id lookup and leaves oldlen unchanged");
  Check(AppRegistrationSysctl(65, id, output, reinterpret_cast<uint64_t*>(1)).value == KERNEL_ERROR_EFAULT,
        "invalid oldlen pointer faults safely");
  *length = 0x98;
  Check(AppRegistrationSysctl(65, 0x55, output, length, reinterpret_cast<void*>(1), 0x98).value == KERNEL_ERROR_EFAULT && *length == 0x98,
        "invalid new span faults before missing-id lookup");
  Check(Memory::KernelMprotect(guard, 0x4000, 0) == OK, "protect registration guard page");
  *length = 0x98;
  Check(AppRegistrationSysctl(65, id, guard - 0x97, length).value == KERNEL_ERROR_EFAULT && *length == 0x98,
        "a crossing output span is rejected before any partial copy");
  *length = 0;
  Check(AppRegistrationSysctl(65, id, reinterpret_cast<void*>(1), length).value == KERNEL_ERROR_EFAULT && *length == 0,
        "zero-length useracc still rejects an invalid unaligned address");
  Check(AppRegistrationSysctl(65, id, guard, length).posix_errno == Posix::POSIX_ENOMEM && *length == 0,
        "zero-length useracc accepts a mapped page boundary without checking its protection");
  Check(AppRegistrationSysctl(65, id, guard + 1, length).value == KERNEL_ERROR_EFAULT && *length == 0,
        "zero-length useracc at an unaligned address still requires the containing byte's protection");
  Check(AppRegistrationSysctl(65, id, nullptr, nullptr, reinterpret_cast<void*>(1), 0).value == KERNEL_ERROR_EFAULT,
        "a zero-length invalid new span faults before any write authorization check");
  void* unmapped = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&unmapped, 0x4000, 3, 0, "zero-length-unmapped-span") == OK &&
            Memory::KernelMunmap(reinterpret_cast<uint64_t>(unmapped), 0x4000) == OK,
        "prepare a known aligned unmapped address");
  Check(AppRegistrationSysctl(65, id, unmapped, length).value == KERNEL_ERROR_EFAULT && *length == 0,
        "zero-length useracc rejects an aligned address without a containing mapping");
  Check(Memory::KernelMprotect(guard, 0x4000, 3) == OK, "restore registration guard page");

  constexpr int shell = 7303;
  Process::RegisterRforkChild(shell, 7300);
  auto process_record = original;
  AppMountStore32(process_record.data() + 4, 1);
  std::memcpy(input, process_record.data(), process_record.size());
  Check(AppRegistrationSysctl(35, shell, nullptr, nullptr, input, process_record.size()).value == 0,
        "commit the distinct PID-owned ShellCore information record");
  Check(query().value == 0 && std::memcmp(output, original.data(), original.size()) == 0,
        "PID record commitment does not replace the app object's information prefix");
  Check(KernelGetAppInfo2(shell, output, 0x98) == OK && std::memcmp(output, process_record.data(), process_record.size()) == 0,
        "PID-owned lookup retains its own committed flags");
  int32_t attached = 0;
  Check(AppMount::GetAttachedApp(shell, &attached) && attached == id, "the process is attached to the application id");

  AppRegistrationBecome(7300, 0x480000000000001full, true, true);
  Check(query().value == 0, "SysAv's observed authority and measured bit 62 permit app-id reading");
  uint32_t field_2c = 1, category = 0;
  std::memcpy(&field_2c, output + 0x2c, 4);
  std::memcpy(&category, output + 0x50, 4);
  Check(!(field_2c != 0 && category < 0x20000) && category == 0x05000000,
        "the observed ShellCore category legitimately fails SysAv POST_BEGIN eligibility");
  Check(AppRegistrationSysctl(65, id, nullptr, nullptr, input, 0x98).posix_errno == Posix::POSIX_EPERM,
        "SysAv cannot mutate app-owned information");
  AppRegistrationBecome(7300, 0x480000000000001full, true, false);
  Check(query().posix_errno == Posix::POSIX_EPERM, "a measured clear read capability is EPERM");
  *length = 0x98;
  Check(AppRegistrationSysctl(65, id, reinterpret_cast<void*>(1), length).value == KERNEL_ERROR_EFAULT,
        "invalid output useracc precedes capability denial");
  AppRegistrationBecome(7300, 0x480000000000001full, false, false);
  Check(query().posix_errno == Posix::POSIX_ENOSYS, "an unobserved read capability remains unsupported");
  AppRegistrationBecome(7300, 0x4800000000000007ull, false, false);
  Check(query().value == 0, "the SysCore authority bypasses the selector-65 read capability gate");
  Check(AppRegistrationSysctl(65, id, nullptr, nullptr, input, 0x98).posix_errno == Posix::POSIX_ENOSYS,
        "generic native sysctl write authorization is still required for SysCore");
  Check(AppRegistrationSysctl(65, id, nullptr, nullptr, input, 0).posix_errno == Posix::POSIX_ENOSYS,
        "a valid non-null new pointer with zero length still requires known generic write authorization");
  AppRegistrationBecome(7300, 0x4800000000000007ull, true, true);

  auto changed = original;
  std::fill(changed.begin() + 0x58, changed.end(), 0x6b);
  std::memcpy(input, changed.data(), changed.size());
  *length = original.size();
  Check(AppRegistrationSysctl(65, id, output, length, input, changed.size()).value == 0 &&
            std::memcmp(output, original.data(), original.size()) == 0 && query().value == 0 &&
            std::memcmp(output, changed.data(), changed.size()) == 0,
        "authorized selector 65 copies out the previous prefix before atomically replacing it");
  Check(KernelGetAppInfo2(shell, output, 0x98) == OK && std::memcmp(output, process_record.data(), process_record.size()) == 0,
        "app-owned replacement leaves PID-owned information unchanged");
  std::memcpy(input, original.data(), original.size());
  Check(AppRegistrationSysctl(65, id, nullptr, nullptr, input, original.size() - 1).value == 0 &&
            query().value == 0 && std::memcmp(output, changed.data(), changed.size()) == 0,
        "a noncanonical newlen is the successful no-op rather than a partial setter");
  *length = 4;
  Check(AppRegistrationSysctl(65, id, output, length, input, original.size()).posix_errno == Posix::POSIX_ENOMEM &&
            query().value == 0 && std::memcmp(output, changed.data(), changed.size()) == 0,
        "short old output prevents the new app prefix from being committed");
  Check(AppRegistrationSysctl(65, id, nullptr, nullptr, input, original.size()).value == 0,
        "restore the minimal app prefix through the production setter");
  *error = Posix::POSIX_EBUSY;
  Check(KernelSetAppState(id, 1) == OK && *error == Posix::POSIX_EBUSY && read_state().value == 0 && state[0] == 1 && state[1] == 0,
        "the export marshals app id and state, commits five-to-one, and preserves errno on success");
  auto* readonly_length = reinterpret_cast<uint64_t*>(guard);
  *readonly_length = 8;
  AppMountStore32(input, 7);
  Check(Memory::KernelMprotect(guard, 0x4000, 1) == OK, "make the late oldlen copyout read-only");
  Check(AppRegistrationSysctl(0x40, id, state, readonly_length, input, 4).posix_errno == Posix::POSIX_EFAULT &&
            *readonly_length == 8 && state[0] == 1,
        "a late oldlen copyout fault follows old-state copyout and the valid state commit");
  Check(Memory::KernelMprotect(guard, 0x4000, 3) == OK && read_state().value == 0 && state[0] == 7 &&
            KernelSetAppState(id, 1) == OK,
        "the final oldlen EFAULT does not roll back the committed state");
  Check(KernelSetAppState(0x2001, 1) == KERNEL_ERROR_ESRCH && *error == Posix::POSIX_ESRCH,
        "the export maps a stale-id native error to the kernel return and errno");
  Check(KernelSetAppState(id, 0xffffffffu) == OK && read_state().value == 0 && state[0] == 0xffffffffu,
        "the native contract stores the full uint32 state without clamping to an enum range");
  AppRegistrationBecome(7300, 0x4800000000000010ull, true, true);
  Check(KernelSetAppState(id, 1) == KERNEL_ERROR_EPERM && *error == Posix::POSIX_EPERM &&
            read_state().value == 0 && state[0] == 0xffffffffu, "ShellCore can read state but cannot mutate it");
  AppRegistrationBecome(7300, 0x4800000000000007ull, true, false);
  Check(KernelSetAppState(id, 1) == KERNEL_ERROR_EPERM && *error == Posix::POSIX_EPERM,
        "a measured clear generic sysctl write capability refuses the export");
  Check(AppRegistrationSysctl(65, id, nullptr, nullptr, input, 0).posix_errno == Posix::POSIX_EPERM,
        "zero new length does not bypass a measured clear generic write capability");
  AppRegistrationBecome(7300, 0x4800000000000007ull, false, false);
  Check(KernelSetAppState(id, 1) == KERNEL_ERROR_ENOSYS && *error == Posix::POSIX_ENOSYS,
        "the export does not guess an unknown write capability");
  AppRegistrationBecome(7300, 0x4800000000000007ull, true, true);
  Check(KernelSetAppState(id, 5) == OK, "restore the synthetic cross-host initial state");
  int32_t got[2] {-1, -1};
  Check(read_state().value == 0 && KernelGetAppState(id, &got[0], &got[1]) == OK &&
            got[0] == static_cast<int32_t>(state[0]) && got[1] == static_cast<int32_t>(state[1]) && got[0] == 5,
        "GetAppState returns both words of the 8-byte oid");
  Check(KernelGetAppState(id, nullptr, nullptr) == OK, "both GetAppState outputs are optional");
  got[0] = 0x55;
  got[1] = 0x56;
  Check(KernelGetAppState(0x2001, &got[0], &got[1]) == KERNEL_ERROR_ESRCH && *error == Posix::POSIX_ESRCH &&
            got[0] == 0x55 && got[1] == 0x56,
        "a stale id fails before either output is written");
  std::memset(output, 0xcc, original.size());
  Check(KernelGetAppInfoByAppId(id, output) == OK && std::memcmp(output, original.data(), original.size()) == 0,
        "GetAppInfoByAppId reads the 0x98 record straight into the caller's buffer");
  Check(KernelGetAppInfoByAppId(0x2001, output) == KERNEL_ERROR_ESRCH && *error == Posix::POSIX_ESRCH,
        "GetAppInfoByAppId maps a stale id the same way");

  HANDLE ready = CreateEventA(nullptr, TRUE, FALSE, (std::string("Local\\kyty_app_state_ready_") + scope).c_str());
  HANDLE go = CreateEventA(nullptr, TRUE, FALSE, (std::string("Local\\kyty_app_state_go_") + scope).c_str());
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  TempDirectory child_output;
  const auto child_log = child_output.Path() / "application_state_child.log";
  SECURITY_ATTRIBUTES inherited {};
  inherited.nLength = sizeof(inherited);
  inherited.bInheritHandle = TRUE;
  HANDLE child_log_handle = CreateFileW(child_log.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &inherited, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  HANDLE child_input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherited, OPEN_EXISTING, 0, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  std::array<wchar_t, 32768> executable {};
  const DWORD executable_length = GetModuleFileNameW(nullptr, executable.data(), executable.size());
  Check(ready != nullptr && go != nullptr && job != nullptr && child_log_handle != INVALID_HANDLE_VALUE && child_input != INVALID_HANDLE_VALUE && executable_length != 0 &&
            executable_length < executable.size() && SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
        "prepare bounded shared application-state child");
  std::wstring command = L"\"" + std::wstring(executable.data(), executable_length) + L"\" --app-registration-state-child " +
      std::wstring(scope, scope + std::strlen(scope)) + L" " + std::to_wstring(id);
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = child_log_handle;
  startup.hStdError = child_log_handle;
  startup.hStdInput = child_input;
  PROCESS_INFORMATION process {};
  Check(CreateProcessW(nullptr, command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW | CREATE_SUSPENDED,
            nullptr, nullptr, &startup, &process) && AssignProcessToJobObject(job, process.hProcess) &&
            ResumeThread(process.hThread) != DWORD(-1), "launch child against the same production application table");
  const HANDLE ready_or_exit[2] {ready, process.hProcess};
  const bool child_ready = WaitForMultipleObjects(2, ready_or_exit, FALSE, 30000) == WAIT_OBJECT_0;
  bool concurrent_ok = child_ready && read_state().value == 0 && state[0] == 5 && SetEvent(go);
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
  while (concurrent_ok && WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT && std::chrono::steady_clock::now() < deadline) {
    concurrent_ok = read_state().value == 0 && state[1] == 0 &&
        (state[0] == 5 || state[0] == 1 || (state[0] >= 0x10000000 && state[0] < 0x10000100));
  }
  if (WaitForSingleObject(process.hProcess, 0) != WAIT_OBJECT_0) {
    TerminateJobObject(job, 10);
    WaitForSingleObject(process.hProcess, 1000);
  }
  DWORD child_exit = 1;
  const bool child_exited = GetExitCodeProcess(process.hProcess, &child_exit) != FALSE;
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  CloseHandle(job);
  CloseHandle(ready);
  CloseHandle(go);
  FlushFileBuffers(child_log_handle);
  CloseHandle(child_log_handle);
  CloseHandle(child_input);
  if (!concurrent_ok || !child_exited || child_exit != 0) {
    std::ifstream log(child_log, std::ios::binary);
    const std::string text {std::istreambuf_iterator<char>(log), std::istreambuf_iterator<char>()};
    std::fprintf(stderr, "application-state child ready=%u exited=%u status=0x%lx log=%s\n%s\n",
        child_ready ? 1u : 0u, child_exited ? 1u : 0u, static_cast<unsigned long>(child_exit), child_log.string().c_str(), text.c_str());
  }
  Check(concurrent_ok && child_exited && child_exit == 0, "bounded cross-host application-state child and concurrent queries pass");
  Check(read_state().value == 0 && state[0] == 1 && state[1] == 0 && query().value == 0 &&
            std::memcmp(output, original.data(), original.size()) == 0 && AppMount::GetAttachedApp(shell, &attached) && attached == id,
        "parent sees the child's committed state with unchanged app prefix and process attachment");
  Process::NotifyRforkChildExited(shell, 0);
  Process::ClearVerifiedOriginalSelf();
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), 0x8000) == OK, "release registration guest storage");
  std::printf("AppRegistrationStateTests: selector65=pass permissions=pass app_vs_pid=pass state_export=pass crosshost_concurrent=pass\n");
#endif
}
