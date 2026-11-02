void AppMountStore32(uint8_t* output, uint32_t value) {
  std::memcpy(output, &value, sizeof(value));
}

#if defined(_WIN32)
// SysCore's addShellCoreApp sequence against the kernel app model, rfork bookkeeping in place of peer processes
void CheckAppMountModel() {
  using namespace Libs;
  using namespace Libs::LibKernel;
  AuthInfoScopeLifecycleSavedEnvironment saved_scope("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE");
  AuthInfoScopeLifecycleSavedEnvironment saved_only("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY");
  AuthInfoScopeLifecycleSavedEnvironment saved_socket("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET");
  char scope[21] {};
  std::snprintf(scope, sizeof(scope), "m%08lx%08lx", GetCurrentProcessId(),
                static_cast<unsigned long>(GetTickCount()));
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", scope) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET", "") == 0,
        "scope the app model");

  void* memory = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&memory, 0x4000, 3, 0, "app-mount-model") == OK,
        "map app model guest storage");
  auto* info = static_cast<uint8_t*>(memory);
  auto* record = info + 0x1900;
  auto* mib = reinterpret_cast<uint32_t*>(info + 0x1a00);
  auto* length = reinterpret_cast<uint64_t*>(info + 0x1a20);
  auto* state = reinterpret_cast<uint32_t*>(info + 0x1a40);
  auto* value = reinterpret_cast<uint32_t*>(info + 0x1a60);
  auto* error = Posix::GetErrorAddr();

  const auto become = [](int pid, uint64_t authority, bool capture, bool bit62) {
    auto fixture = MakeAuthInfoScopeLifecycleFixture(pid);
    fixture.identity.authority_id = authority;
    AuthInfoScopeStore64(fixture.record.data(), authority);
    AuthInfoScopeStore64(fixture.record.data() + 8, bit62 ? 1ull << 62 : 0);
    Check(AuthInfo::BuildCaptureEnvelope(fixture.record, fixture.identity, &fixture.capture, nullptr),
          "build app model identity");
    Process::ClearVerifiedOriginalSelf();
    Process::InstallVerifiedOriginalSelf(fixture.identity);
    if (capture) Check(Process::InstallVerifiedAuthInfo(fixture.capture), "install app model capability");
  };
  const auto begin = [&](uint32_t category) {
    std::memset(info, 0, 0x18b0);
    AppMountStore32(info, category);
    std::memcpy(info + 4, "NPXS40082", 9);
    *error = 0;
    return KernelBeginAppMount2(info, 0, 0);
  };
  const auto app_info = [&](int pid, const void* input, uint64_t* output_length, void* output) {
    mib[0] = 1; mib[1] = 14; mib[2] = 35; mib[3] = static_cast<uint32_t>(pid);
    return NativeKernelBridge::DispatchSyscall({0xca, {reinterpret_cast<uint64_t>(mib), 4,
        reinterpret_cast<uint64_t>(output), reinterpret_cast<uint64_t>(output_length),
        reinterpret_cast<uint64_t>(input), input != nullptr ? 0x98u : 0u}});
  };
  const auto set_record = [&](int pid, int32_t app_id, uint32_t flags, const char* title) {
    std::memset(record, 0, 0x98);
    std::memcpy(record, &app_id, sizeof(app_id));
    AppMountStore32(record + 4, flags);
    std::memcpy(record + 0x10, title, std::strlen(title));
    AppMountStore32(record + 0x50, 0x05000000);
    return app_info(pid, record, nullptr, nullptr);
  };
  const auto app_state = [&](int32_t app_id, uint64_t* output_length, const uint32_t* input) {
    mib[0] = 1; mib[1] = 14; mib[2] = 0x40; mib[3] = static_cast<uint32_t>(app_id);
    return NativeKernelBridge::DispatchSyscall({0xca, {reinterpret_cast<uint64_t>(mib), 4,
        output_length != nullptr ? reinterpret_cast<uint64_t>(state) : 0, reinterpret_cast<uint64_t>(output_length),
        reinterpret_cast<uint64_t>(input), input != nullptr ? 4u : 0u}});
  };

  constexpr int syscore = 7100;
  constexpr int shellcore = 7103;
  constexpr int other = 7104;
  Process::RegisterRforkChild(shellcore, syscore);
  Process::RegisterRforkChild(other, syscore);

  {
    Process::ScopedGuestProcessPid as_child(shellcore);
    // no caps record, so bit 62 is unknown and only the self exemption applies
    become(syscore, 0x4800000000000007ull, false, false);
    Check(set_record(shellcore, -1, 0, "").value == 0, "an rfork child sets its own record without a capability");
  }

  Process::ScopedGuestProcessPid as_syscore(syscore);
  Process::ClearVerifiedOriginalSelf();
  Check(begin(0x05000000) == KERNEL_ERROR_ENOSYS && *error == Posix::POSIX_ENOSYS,
        "begin without a verified authority stays ENOSYS");
  become(syscore, 0x4800000010000004ull, true, true);
  Check(begin(0x05000000) == KERNEL_ERROR_EPERM && *error == Posix::POSIX_EPERM,
        "begin refuses an authority 0x9ede8290 does not list");
  become(syscore, 0x4800000000000007ull, true, true);
  Check(begin(0x02000100) == KERNEL_ERROR_ENOSYS && *error == Posix::POSIX_ENOSYS && begin(0x03000000) == KERNEL_ERROR_ENOSYS,
        "the 0x9da95b40 slot and the top-byte-3 copy are not modelled and create nothing");
  Check(begin(0x04000000) == KERNEL_ERROR_EINVAL && *error == 0, "the wrapper refuses 0x4000000 without touching errno");
  const int app_id = begin(0x05000000);
  Check(app_id == 1, "the first application id follows the parked id 0 object");

  *length = 8;
  Check(app_state(app_id, length, nullptr).value == 0 && *length == 8 && state[0] == 5 && state[1] == 0,
        "a created application starts in state 5");
  Check(app_state(0, length, nullptr).posix_errno == Posix::POSIX_ESRCH &&
            app_state(0x55, length, nullptr).posix_errno == Posix::POSIX_ESRCH,
        "appstate refuses id 0 and unknown ids");
  *length = 16;
  Check(app_state(app_id, length, nullptr).posix_errno == Posix::POSIX_EINVAL, "appstate refuses an oldlen above 8");

  auto* returned = info + 0x1b00;
  Check(KernelGetAppInfo2(shellcore, returned, 0x98) == OK && returned[0] == 0xff && returned[0x10] == 0,
        "GetAppInfo2 returns the child's own committed record");
  Check(KernelGetAppInfo2(shellcore, returned, 0x99) == KERNEL_ERROR_EINVAL &&
            KernelGetAppInfo2(7199, returned, 0x98) == KERNEL_ERROR_ESRCH,
        "GetAppInfo2 keeps the handler's size and pfind checks");
  *error = 0;
  Check(KernelGetAppInfo(other, returned) == KERNEL_ERROR_ENOSYS && *error == Posix::POSIX_ENOSYS &&
            KernelGetAppCategoryType(other, reinterpret_cast<int*>(info + 0x1a80)) == KERNEL_ERROR_ENOSYS,
        "a live child with no record and no peer metadata is not ESRCH");

  const auto raw_sysctl = [&](uint64_t output, uint64_t output_length, uint64_t input, uint64_t input_length) {
    return NativeKernelBridge::DispatchSyscall({0xca, {reinterpret_cast<uint64_t>(mib), 4, output, output_length,
        input, input_length}});
  };
  mib[0] = 1; mib[1] = 14; mib[2] = 35; mib[3] = 7199;
  Check(raw_sysctl(0, 0, 1, 0x98).posix_errno == Posix::POSIX_ESRCH,
        "a set for a missing pid is ESRCH before the record is copied in");
  mib[3] = shellcore;
  Check(raw_sysctl(0, 0, 1, 0x98).value == KERNEL_ERROR_EFAULT, "an unreadable new record faults at the copyin");
  *length = 0x98;
  Check(raw_sysctl(reinterpret_cast<uint64_t>(returned), reinterpret_cast<uint64_t>(length), 0, 0x98).value == 0 &&
            *length == 0x98 && returned[0] == 0xff,
        "a null new pointer is a plain get whatever its length");

  std::memset(record, 0, 0x98);
  std::memcpy(record, &app_id, sizeof(app_id));
  AppMountStore32(record + 4, 1);
  std::memcpy(record + 0x10, "NPXS40082", 9);
  AppMountStore32(record + 0x50, 0x05000000);
  std::memset(returned, 0, 0x98);
  *length = 0x98;
  mib[3] = shellcore;
  Check(raw_sysctl(reinterpret_cast<uint64_t>(returned), reinterpret_cast<uint64_t>(length),
                   reinterpret_cast<uint64_t>(record), 0x98).value == 0 && returned[0] == 0xff,
        "SysCore commits the ShellCore record, and the copyout before it returns the old one");
  int32_t attached = 0;
  Check(AppMount::GetAttachedApp(shellcore, &attached) && attached == app_id, "the record attaches the application");
  Check(KernelGetAppInfo2(shellcore, returned, 0x98) == OK &&
            std::memcmp(returned, record, 0x98) == 0,
        "later app queries see the committed record");
  auto* category = reinterpret_cast<int*>(info + 0x1a80);
  Check(KernelGetAppCategoryType(shellcore, category) == OK && *category == 0x05000000,
        "the category query reads the committed record");

  *value = 1;
  Check(app_state(app_id, nullptr, value).value == 0, "SysCore moves the application to state 1");
  *length = 8;
  Check(app_state(app_id, length, nullptr).value == 0 && state[0] == 1, "appstate reads the new state");
  *length = 4;
  *value = 3;
  Check(app_state(app_id, length, value).posix_errno == Posix::POSIX_ENOMEM, "a short old buffer fails first");
  *length = 8;
  Check(app_state(app_id, length, nullptr).value == 0 && state[0] == 1, "and leaves the state alone");
  mib[0] = 1; mib[1] = 14; mib[2] = 0x40; mib[3] = 0x55;
  Check(raw_sysctl(0, 0, 1, 4).value == KERNEL_ERROR_EFAULT, "native useracc rejects an unmapped new state before id lookup");
  mib[3] = static_cast<uint32_t>(app_id);
  state[0] = 0;
  Check(raw_sysctl(reinterpret_cast<uint64_t>(state), reinterpret_cast<uint64_t>(length), 1, 4).value == KERNEL_ERROR_EFAULT &&
            state[0] == 0 && app_state(app_id, length, nullptr).value == 0 && state[0] == 1,
        "native useracc rejects an unreadable new state before copyout and changes nothing");

  Check(set_record(other, 0, 1, "NPXS40082").posix_errno == Posix::POSIX_EBUSY,
        "a second live holder of the title is busy");
  Check(set_record(other, 0, 0, "NPXS40082").value == 0, "without flag bit 0 there is no busy check");
  const int second = begin(0x05000000);
  Check(second == 2, "ids continue from the allocator");
  Check(set_record(shellcore, second, 2, "NPXS40082").value == 0 && set_record(shellcore, second, 0, "").value == 0 &&
            KernelGetAppInfo2(shellcore, returned, 0x98) == OK && returned[4] == 2,
        "flag bit 1 survives later sets");
  Check(AppMount::GetAttachedApp(shellcore, &attached) && attached == app_id, "the first attachment stays");

  // ShellCore's launchApp: ShellUI is 0x1000000, NPXS40100/40102/40091 are 0x2000000.
  const int shell_ui = begin(0x01000000);
  const int daemon = begin(0x02000000);
  Check(shell_ui == 3 && daemon == 4, "the wrapper's category switch only picks the kind byte");
  uint8_t kinds[2] {};
  uint32_t categories[2] {};
  for (int i = 0; i < 2; i++) {
    const int id = i == 0 ? shell_ui : daemon;
    *length = 8;
    Check(app_state(id, length, nullptr).value == 0 && state[0] == 5, "launch applications start in state 5");
    Check(AppMount::AppInfoById(id, 0x98, 0, [&](AppMount::Record& info) {
      int32_t stored = 0;
      std::memcpy(&stored, info.data(), sizeof(stored));
      kinds[i] = info[0x1a];
      std::memcpy(&categories[i], info.data() + 0x50, sizeof(categories[i]));
      return stored == id ? 0 : Posix::POSIX_EINVAL;
    }) == 0, "the object holds the request with its id over +0");
  }
  Check(kinds[0] == 5 && kinds[1] == 2 && categories[0] == 0x01000000 && categories[1] == 0x02000000,
        "kind 5 for ShellUI and 2 for the daemons");
  Check(AppMount::GetAttachedApp(shellcore, &attached) && attached == app_id, "creation attaches nothing");

  // MediaCore's 4K video core (NPXS40038) is 0x20200, the one big-app category the model takes.
  const auto begin_big = [&](const char* param, uint64_t size, uint64_t flexible = 0) {
    std::memset(info, 0, 0x18b0);
    AppMountStore32(info, 0x20200);
    std::memcpy(info + 4, "NPXS40038", 9);
    std::memcpy(info + 0x1090, &flexible, sizeof(flexible));
    *error = 0;
    return KernelBeginAppMount2(info, reinterpret_cast<uint64_t>(param), size);
  };
  const auto end = [](int32_t id) { return AppMount::End([&](int32_t* output) { *output = id; return 0; }); };
  auto* param = reinterpret_cast<char*>(info + 0x2000);
  const char param_text[] = "{\"applicationCategoryType\":131584,\"titleId\":\"NPXS40038\"}";
  std::memcpy(param, param_text, sizeof(param_text));
  Check(begin(0x20000) == KERNEL_ERROR_ENOSYS && begin(0) == KERNEL_ERROR_ENOSYS, "the other big-app categories stay unmodelled");
  Check(begin_big(param, 0x100001) == KERNEL_ERROR_ENOMEM &&
            begin_big(reinterpret_cast<const char*>(uintptr_t {1}), 4) == KERNEL_ERROR_EFAULT,
        "0x9ede9290 bounds param.json and faults on its copyin");
  std::memcpy(param + 0x100, "[131584]", 8);
  Check(begin_big(param + 0x100, 8) == KERNEL_ERROR_EINVAL, "param.json has to be an object");
  std::memcpy(param + 0x100, "{\"kernel\":{}}", 13);
  Check(begin_big(param + 0x100, 13) == KERNEL_ERROR_ENOSYS && *error == Posix::POSIX_ENOSYS, "kernel properties are not modelled");
  for (int i = 0; i < 4; i++) {
    Check(begin_big(param, sizeof(param_text), 0x100000) == KERNEL_ERROR_EINVAL, "flexible memory below 2 MiB is refused");
  }
  const int big = begin_big(param, sizeof(param_text), 0x40000000);
  Check(big > 0, "a big app launches, and the refused ones before it kept neither a container nor the current slot");
  *length = 8;
  Check(app_state(big, length, nullptr).value == 0 && state[0] == 5 && begin_big(nullptr, 0) == KERNEL_ERROR_EBUSY &&
            *error == Posix::POSIX_EBUSY,
        "0x9ede8ce0 is busy while a big app sits in state 5");
  *value = 1;
  Check(app_state(big, nullptr, value).value == 0 && begin_big(nullptr, 0) == KERNEL_ERROR_EBUSY &&
            end(big) == Posix::POSIX_EBUSY,
        "and while it runs, when 0x2c3 will not take it either");
  *value = 4;
  Check(app_state(big, nullptr, value).value == 0 && end(big) == 0, "state 4 lets 0x2c3 end it");
  const int again = begin_big(nullptr, 0);
  Check(again > 0 && end(again) == 0, "the container is free again, and no param.json at all is an empty object");

  become(syscore, 0x4800000000000007ull, true, false);
  Check(KernelGetAppInfo2(shellcore, returned, 0x98) == KERNEL_ERROR_EPERM &&
            set_record(shellcore, app_id, 0, "").posix_errno == Posix::POSIX_EPERM,
        "a measured clear bit 62 refuses another process's record");
  Check(KernelGetAppInfo(shellcore, returned) == KERNEL_ERROR_EPERM &&
            KernelGetAppCategoryType(shellcore, category) == KERNEL_ERROR_EPERM,
        "the 0x58-byte and category queries take the same refusal");
  become(syscore, 0x4800000000000007ull, false, false);
  Check(KernelGetAppInfo2(shellcore, returned, 0x98) == KERNEL_ERROR_ENOSYS,
        "an unknown bit 62 is not guessed");
  Check(KernelGetAppInfo(shellcore, returned) == KERNEL_ERROR_ENOSYS &&
            KernelGetAppCategoryType(shellcore, category) == KERNEL_ERROR_ENOSYS,
        "nor answered from SFO metadata");
  become(syscore, 0x4800000000000010ull, true, true);
  *length = 8;
  *value = 7;
  Check(app_state(app_id, length, nullptr).value == 0 && app_state(app_id, nullptr, value).posix_errno == Posix::POSIX_EPERM,
        "authority 0x10 reads appstate but cannot set it");
  become(syscore, 0x4800000010000004ull, true, true);
  Check(app_state(app_id, length, nullptr).posix_errno == Posix::POSIX_EPERM, "unlisted authorities cannot read appstate");

  become(syscore, 0x4800000000000007ull, true, true);
  Process::NotifyRforkChildExited(shellcore, 0);
  Check(set_record(other, 0, 1, "NPXS40082").posix_errno == Posix::POSIX_EBUSY,
        "0x9e930f70 also matches the target's own earlier record");
  Process::NotifyRforkChildExited(other, 0);
  Process::RegisterRforkChild(7105, syscore);
  Check(set_record(7105, 0, 1, "NPXS40082").value == 0, "exited holders no longer make the title busy");

  int created = 4;
  int last = 0;
  while ((last = begin(0x05000000)) > 0) ++created;
  // XXX: teardown isn't modelled, so the kernel's EAGAIN at 0x20 can't be told apart from missed destroys
  Check(created == 0x20 && last == KERNEL_ERROR_ENOSYS && *error == Posix::POSIX_ENOSYS,
        "the table holds 0x20 applications");
  Check(begin(0x05000000) == KERNEL_ERROR_ENOSYS, "a full table keeps refusing");

  constexpr int lifecycle_child = 7106;
  Process::RegisterRforkChild(lifecycle_child, syscore);
  Check(set_record(lifecycle_child, daemon, 0, "NPXS40100").value == 0,
        "associate a live guest with the lifecycle fixture app");
  const char* source = nullptr;
  uint32_t host_pid = 0;
  Check(std::strcmp(AppMount::DiagnosticProcessState(
                        Process::QueryGuestProcessExists(lifecycle_child, &source, &host_pid)), "alive") == 0 &&
            std::strcmp(AppMount::DiagnosticProcessState(
                            Process::QueryGuestProcessExists(-1, &source, &host_pid)), "dead") == 0 &&
            std::strcmp(AppMount::DiagnosticProcessState(
                            Process::QueryGuestProcessExists(0, &source, &host_pid)), "unknown") == 0,
        "lifecycle diagnostics preserve alive, dead and unknown process states");
  become(syscore, 0x4800000000000022ull, true, true);
  Check(_putenv_s("KYTY_DIAGNOSTIC_APP_KILL_LIFECYCLE", "1") == 0,
        "enable lifecycle diagnostics");
  Check(AppMount::End([&](int32_t* output) { *output = daemon; return 0; }) == 0,
        "lifecycle diagnostics do not alter app teardown");
  Check(_putenv_s("KYTY_DIAGNOSTIC_APP_KILL_LIFECYCLE", "") == 0,
        "disable lifecycle diagnostics");
  Check(AppMount::AppInfoById(daemon, 0x98, 0, [](AppMount::Record&) { return 0; }) == Posix::POSIX_ESRCH,
        "lifecycle diagnostics retain the original removal outcome");
  Process::NotifyRforkChildExited(lifecycle_child, 0);

  Process::ClearVerifiedOriginalSelf();
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), 0x4000) == OK, "release app model guest storage");
}
#endif

void CheckAppMountContract() {
  using namespace Libs;
  using namespace Libs::LibKernel;

  constexpr size_t page = 0x4000;
  constexpr size_t info_size = 0x18b0;
  void* memory = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&memory, page * 2, 3, 0,
        "app-mount-contract") == OK, "map app-mount contract guest storage");
  auto* info = static_cast<uint8_t*>(memory);
  auto* query = info + 0x2000;
  auto* guard = info + page;
  auto* error = Posix::GetErrorAddr();

  const auto reset = [&] {
    std::memset(info, 0, info_size);
    AppMountStore32(info, 0x05000000);
    std::memcpy(info + 4, "NPXS40082", 9);
  };
  const auto expect_valid_unsupported = [&](const char* text, uint64_t arg1 = 0,
                                             uint64_t arg2 = 0) {
    std::array<uint8_t, info_size> before {};
    std::memcpy(before.data(), info, before.size());
    *error = Posix::POSIX_EBUSY;
    Check(KernelBeginAppMount2(info, arg1, arg2) == KERNEL_ERROR_ENOSYS &&
              *error == Posix::POSIX_ENOSYS &&
              std::memcmp(info, before.data(), before.size()) == 0,
          text);
  };
  const auto expect_invalid = [&](const char* text) {
    std::array<uint8_t, info_size> before {};
    std::memcpy(before.data(), info, before.size());
    *error = Posix::POSIX_EBUSY;
    Check(KernelBeginAppMount2(info, 0, 0) == KERNEL_ERROR_EINVAL &&
              *error == Posix::POSIX_EBUSY &&
              std::memcmp(info, before.data(), before.size()) == 0,
          text);
  };

  // no verified authority: every accepted block is ENOSYS on the kernel side
  Process::ClearVerifiedOriginalSelf();
  std::array<uint8_t, 0x58> query_before {};
  std::memset(query, 0xa5, query_before.size());
  const int query_result = KernelGetAppInfo(Process::GetPid(), query);
  std::memcpy(query_before.data(), query, query_before.size());

  reset();
  expect_valid_unsupported("ShellCore app-mount block remains unsupported and unchanged");
  reset();
  expect_valid_unsupported("wrapper-side validation accepts nonzero scalar arguments",
                           0x1122334455667788ull, 0x8877665544332211ull);

  *error = Posix::POSIX_EBUSY;
  Check(KernelBeginAppMount2(nullptr, 0, 0) == KERNEL_ERROR_EINVAL &&
            *error == Posix::POSIX_EBUSY,
        "wrapper rejects a null public-info pointer before changing errno");
  *error = Posix::POSIX_EBUSY;
  Check(KernelBeginAppMount2(reinterpret_cast<void*>(uintptr_t {1}), 0, 0) ==
            KERNEL_ERROR_EFAULT && *error == Posix::POSIX_EBUSY,
        "safe HLE boundary rejects an unreadable public-info pointer");

  const std::array<uint32_t, 26> accepted_categories {
      0, 0xf000, 0xf100, 0x10000, 0x10100, 0x10200, 0x10300,
      0x1f000, 0x1f100, 0x1f200, 0x1f300, 0x1f400, 0x1f500,
      0x20000, 0x20100, 0x20200, 0x2f000, 0x2f100,
      0x01000000, 0x02000000, 0x02000100, 0x0200f000, 0x0200f100,
      0x0200f200, 0x03000000, 0x05000000};
  for (const uint32_t category: accepted_categories) {
    reset();
    AppMountStore32(info, category);
    expect_valid_unsupported("wrapper accepts a category mapping before ENOSYS");
  }
  for (const uint32_t category: {0x04000000u, 0xdeadbeefu}) {
    reset();
    AppMountStore32(info, category);
    expect_invalid("wrapper rejects an unsupported application category");
  }

  for (const uint8_t mode: {uint8_t {0}, uint8_t {1}, uint8_t {2}, uint8_t {3},
                            uint8_t {0xff}}) {
    reset();
    info[0x49] = mode;
    expect_valid_unsupported("wrapper accepts an evidenced hardware mode");
  }
  reset();
  info[0x49] = 4;
  expect_invalid("wrapper rejects hardware mode four");

  reset();
  info[0x4b] = 0xff;
  expect_valid_unsupported("wrapper accepts sub-mode ff");
  reset();
  info[0x4b] = 2;
  expect_invalid("wrapper rejects sub-mode two");
  reset();
  info[0x4b] = 1;
  expect_invalid("low-energy sub-mode requires an evidenced enable flag");
  reset();
  info[0x4b] = 1;
  AppMountStore32(info + 0x18a8, 1);
  expect_valid_unsupported("low-energy sub-mode accepts the first evidenced enable flag");
  reset();
  info[0x4b] = 1;
  AppMountStore32(info + 0x18ac, 1);
  expect_valid_unsupported("low-energy sub-mode accepts the second evidenced enable flag");
  reset();
  info[0x49] = 1;
  info[0x4b] = 1;
  AppMountStore32(info + 0x18a8, 1);
  expect_invalid("low-energy sub-mode rejects nonzero hardware mode");

  reset();
  AppMountStore32(info + 0x10a0, 16);
  expect_valid_unsupported("wrapper accepts sixteen debug settings");
  reset();
  AppMountStore32(info + 0x10a0, 17);
  expect_invalid("wrapper rejects seventeen debug settings");

  Check(Memory::KernelMprotect(guard, page, 0) == OK,
        "protect app-mount contract guard page");
  *error = Posix::POSIX_EBUSY;
  Check(KernelBeginAppMount2(guard - info_size + 1, 0, 0) == KERNEL_ERROR_EFAULT &&
            *error == Posix::POSIX_EBUSY,
        "safe HLE boundary rejects a public block crossing a guard page");
  Check(Memory::KernelMprotect(guard, page, 3) == OK,
        "restore app-mount contract guard page");

  std::memset(query, 0xa5, query_before.size());
  Check(KernelGetAppInfo(Process::GetPid(), query) == query_result &&
            std::memcmp(query, query_before.data(), query_before.size()) == 0,
        "unsupported begin-app-mount does not alter existing application query state");
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), page * 2) == OK,
        "release app-mount contract guest storage");
#if defined(_WIN32)
  CheckAppMountModel();
#endif
}
