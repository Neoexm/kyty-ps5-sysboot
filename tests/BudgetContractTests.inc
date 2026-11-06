#if defined(_WIN32)
// Syscalls 609/571 (K+0x5a7f00, K+0x5a7900) with no budget created: only the gate, the ShellCore constant or absence
void CheckBudgetContract() {
  using namespace Libs;
  using namespace Libs::LibKernel;
  auto* error = Posix::GetErrorAddr();

  const auto become = [](int pid, uint64_t authority, bool capture, bool bit62) {
    auto fixture = MakeAuthInfoScopeLifecycleFixture(pid);
    fixture.identity.authority_id = authority;
    AuthInfoScopeStore64(fixture.record.data(), authority);
    AuthInfoScopeStore64(fixture.record.data() + 8, bit62 ? 1ull << 62 : 0);
    Check(AuthInfo::BuildCaptureEnvelope(fixture.record, fixture.identity, &fixture.capture, nullptr),
          "build budget identity");
    Process::ClearVerifiedOriginalSelf();
    Process::InstallVerifiedOriginalSelf(fixture.identity);
    if (capture) Check(Process::InstallVerifiedAuthInfo(fixture.capture), "install budget capability");
  };
  const auto get = [] { return NativeKernelBridge::DispatchSyscall({0x261, {}}); };
  const auto set = [](int id) {
    return NativeKernelBridge::DispatchSyscall({0x23b, {static_cast<uint64_t>(static_cast<int64_t>(id))}});
  };
  int64_t out = 0x5a5a;

  {
    // mini-syscore's authid, no caps record for it
    Process::ScopedGuestProcessPid as_mini(7200);
    become(7200, 0x4800000000000022ull, false, false);
    Check(get().value == KERNEL_ERROR_ENOSYS && set(1).value == KERNEL_ERROR_ENOSYS,
          "unmeasured bit 62 stays ENOSYS for get and set");
    *error = 0;
    Check(NativeSyscallGuards::KernelGetBudget(&out) == KERNEL_ERROR_ENOSYS &&
              *error == Posix::POSIX_ENOSYS && out == 0x5a5a,
          "the get wrapper leaves output alone on ENOSYS");
    become(7200, 0x4800000000000022ull, true, true);
    Check(set(1).value == KERNEL_ERROR_ESRCH, "a gated set does not spend the once-only flag");
  }
  {
    Process::ScopedGuestProcessPid as_clear(7201);
    become(7201, 0x4800000000000007ull, true, false);
    Check(get().value == KERNEL_ERROR_ENOSYS && set(1).value == KERNEL_ERROR_ENOSYS,
          "a measured clear bit 62 is ENOSYS");
  }
  {
    Process::ScopedGuestProcessPid as_syscore(7202);
    become(7202, 0x4800000000000007ull, true, true);
    Check(get().value == KERNEL_ERROR_ENOENT, "no attached budget is ENOENT, not an id");
    *error = 0;
    Check(NativeSyscallGuards::KernelGetBudget(&out) == KERNEL_ERROR_ENOENT &&
              *error == Posix::POSIX_ENOENT && out == 0x5a5a,
          "SysCore sees 0x80020002 and no output");
    Check(set(0).value == KERNEL_ERROR_ESRCH, "first set finds no budget object");
    Check(set(0).value == KERNEL_ERROR_EALREADY, "the failed set still spent the once-only flag");
    *error = 0;
    Check(NativeSyscallGuards::KernelSetBudget(5) == KERNEL_ERROR_EALREADY && *error == Posix::POSIX_EALREADY,
          "the set wrapper returns 0x80020025");
  }
  {
    Process::ScopedGuestProcessPid as_peer(7203);
    become(7203, 0x4800000000000007ull, true, true);
    Check(set(-1).value == KERNEL_ERROR_ESRCH, "the once-only flag is per process");
  }
  {
    Process::ScopedGuestProcessPid as_shellcore(7204);
    become(7204, 0x4800000000000010ull, true, true);
    Check(get().value == 0x7fffdead, "ShellCore's authority gets the kernel constant");
    out = 0;
    Check(NativeSyscallGuards::KernelGetBudget(&out) == OK && out == 0x7fffdead,
          "the get wrapper writes the sign-extended id");
    become(7204, 0x4800000000000010ull, false, false);
    Check(get().value == KERNEL_ERROR_ENOSYS, "the ShellCore constant still needs a measured bit 62");
  }
  Process::ClearVerifiedOriginalSelf();
}

// mini-syscore's bootstrap against the budget model: 570 on the pools, 568 creates, the builtin slots, then the spawn child's 571 and SysCore's inherited attachment.
void CheckBudgetModel() {
  using namespace Libs;
  using namespace Libs::LibKernel;
  using Budget::Entry;
  AuthInfoScopeLifecycleSavedEnvironment saved_scope("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE");
  AuthInfoScopeLifecycleSavedEnvironment saved_only("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY");
  AuthInfoScopeLifecycleSavedEnvironment saved_socket("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET");
  AuthInfoScopeLifecycleSavedEnvironment saved_entry("KYTY_PS5_BUDGET_SYSTEM_DMEM_ENTRY");
  AuthInfoScopeLifecycleSavedEnvironment saved_evidence("KYTY_PS5_BUDGET_SYSTEM_DMEM_EVIDENCE_SHA256");
  const auto enter_scope = [](char tag) {
    char scope[21] {};
    std::snprintf(scope, sizeof(scope), "%c%08lx%08lx", tag, GetCurrentProcessId(),
                  static_cast<unsigned long>(GetTickCount()));
    Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", scope) == 0 &&
              _putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1") == 0 &&
              _putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET", "") == 0,
          "scope the budget model");
  };

  void* memory = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&memory, 0x4000, 3, 0, "budget-model") == OK,
        "map budget model guest storage");
  auto* bytes = static_cast<uint8_t*>(memory);
  auto* in = reinterpret_cast<Entry*>(bytes);
  auto* out = reinterpret_cast<Entry*>(bytes + 0x400);
  auto* count = reinterpret_cast<int32_t*>(bytes + 0x800);
  auto* name = reinterpret_cast<char*>(bytes + 0x840);
  auto* mib = reinterpret_cast<uint32_t*>(bytes + 0x880);
  auto* length = reinterpret_cast<uint64_t*>(bytes + 0x8a0);
  auto* value = reinterpret_cast<int64_t*>(bytes + 0x8c0);

  const auto become = [](int pid, uint64_t authority, bool bit62) {
    auto fixture = MakeAuthInfoScopeLifecycleFixture(pid);
    fixture.identity.authority_id = authority;
    AuthInfoScopeStore64(fixture.record.data(), authority);
    AuthInfoScopeStore64(fixture.record.data() + 8, bit62 ? 1ull << 62 : 0);
    Check(AuthInfo::BuildCaptureEnvelope(fixture.record, fixture.identity, &fixture.capture, nullptr),
          "build budget model identity");
    Process::ClearVerifiedOriginalSelf();
    Process::InstallVerifiedOriginalSelf(fixture.identity);
    Check(Process::InstallVerifiedAuthInfo(fixture.capture), "install budget model capability");
  };
  const auto limits = [&](int32_t id, int32_t n) {
    *count = n;
    std::memset(out, 0xcc, sizeof(Entry) * 14);
    return NativeKernelBridge::DispatchSyscall({0x23a, {static_cast<uint64_t>(static_cast<int64_t>(id)),
        reinterpret_cast<uint64_t>(out), reinterpret_cast<uint64_t>(count)}});
  };
  const auto create = [&](const char* label, uint32_t ptype, uint32_t n) {
    std::strcpy(name, label);
    std::memset(out, 0xcc, sizeof(Entry) * 14);
    return NativeKernelBridge::DispatchSyscall({0x238, {reinterpret_cast<uint64_t>(name), ptype,
        reinterpret_cast<uint64_t>(in), n, reinterpret_cast<uint64_t>(out)}});
  };
  const auto remove = [](int32_t id) {
    return NativeKernelBridge::DispatchSyscall({0x239, {static_cast<uint64_t>(static_cast<int64_t>(id))}});
  };
  const auto set = [](int32_t id) {
    return NativeKernelBridge::DispatchSyscall({0x23b, {static_cast<uint64_t>(static_cast<int64_t>(id))}});
  };
  const auto get = [] { return NativeKernelBridge::DispatchSyscall({0x261, {}}); };
  const auto builtin = [&](uint32_t index, bool read, const int64_t* store) {
    mib[0] = 1; mib[1] = 14; mib[2] = 0x51; mib[3] = index;
    *length = 8;
    *value = 0x5a5a;
    if (store != nullptr) value[1] = *store;
    return NativeKernelBridge::DispatchSyscall({0xca, {reinterpret_cast<uint64_t>(mib), 4,
        read ? reinterpret_cast<uint64_t>(value) : 0, read ? reinterpret_cast<uint64_t>(length) : 0,
        store != nullptr ? reinterpret_cast<uint64_t>(value + 1) : 0, store != nullptr ? 8u : 0u}});
  };

  constexpr int mini = 7210;
  constexpr int spawn = 7212;
  constexpr int audiod = 7213;
  constexpr uint64_t mini_authority = 0x4800000000000022ull;
  const int64_t none = -1;

  {
    enter_scope('u');
    Check(_putenv_s("KYTY_PS5_BUDGET_SYSTEM_DMEM_ENTRY", "") == 0 &&
              _putenv_s("KYTY_PS5_BUDGET_SYSTEM_DMEM_EVIDENCE_SHA256", "") == 0,
          "no system dmem measurement");
    Process::ScopedGuestProcessPid as_mini(mini);
    become(mini, mini_authority, true);
    Check(limits(-4, 14).value == KERNEL_ERROR_ENOSYS && *count == 14,
          "the ptype 2 pool is unknown without the boot-time kind 1 limit");
    Check(limits(-2, 20).value == 0 && *count == 14 && out[0].kind == 0 && out[3].kind == 4 && out[3].unit == 6 &&
              out[3].limit == 0x1fff && out[4].kind == 5 && out[4].unit == 1 && out[4].limit == 0x102 &&
              out[13].kind == 14 && out[13].limit == 0x4e20 && out[13].used == 0,
          "the ptype 0 pool reports the init immediates, capped at 14 entries");
    Check(limits(-2, 0).value == KERNEL_ERROR_EINVAL && limits(-1, 1).value == KERNEL_ERROR_ESRCH &&
              limits(-7, 1).value == KERNEL_ERROR_ESRCH,
          "570 refuses a zero count and ids outside the pools");
    in[0] = {1, 0, 0x1000, 0};
    Check(create("system budget", 2, 1).value == KERNEL_ERROR_ENOSYS,
          "a kind 1 system budget is not created against an unmeasured pool");
    Check(create("x", 5, 1).value == KERNEL_ERROR_EINVAL && create("x", 0, 15).value == KERNEL_ERROR_EINVAL,
          "568 refuses ptype above 4 and more than 14 entries");
    Check(NativeKernelBridge::DispatchSyscall({0x238, {0, 0, reinterpret_cast<uint64_t>(in), 1,
              reinterpret_cast<uint64_t>(out)}}).value == KERNEL_ERROR_EINVAL,
          "568 refuses a null name");
    std::memset(name, 'n', 0x20);
    Check(NativeKernelBridge::DispatchSyscall({0x238, {reinterpret_cast<uint64_t>(name), 0,
              reinterpret_cast<uint64_t>(in), 0, reinterpret_cast<uint64_t>(out)}}).value ==
              KERNEL_ERROR_UNKNOWN + Posix::POSIX_ENAMETOOLONG,
          "the name copyin stops at 0x20 bytes");
    become(mini, mini_authority, false);
    Check(builtin(0, true, nullptr).posix_errno == Posix::POSIX_EPERM && create("x", 0, 0).value == KERNEL_ERROR_ENOSYS,
          "a clear bit 62 is EPERM on the sysctl and ENOSYS on the syscalls");
  }

  enter_scope('b');
  Check(_putenv_s("KYTY_PS5_BUDGET_SYSTEM_DMEM_ENTRY", "1:1:1073741824") == 0 &&
            _putenv_s("KYTY_PS5_BUDGET_SYSTEM_DMEM_EVIDENCE_SHA256",
                      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") == 0,
        "measured system dmem fixture");
  int64_t system_id = -1;
  {
    Process::ScopedGuestProcessPid as_mini(mini);
    become(mini, mini_authority, true);
    Check(limits(-4, 14).value == 0 && *count == 14 && out[0].kind == 1 && out[0].unit == 1 &&
              out[0].limit == 1073741824 && out[1].limit == 0x400000000ull && out[3].limit == 0xea00,
          "the ptype 2 pool carries the measured kind 1 entry");
    std::memcpy(in, out, sizeof(Entry) * 14);
    const auto created = create("system budget", 2, 14);
    system_id = created.value;
    Check(created.posix_errno == 0 && system_id == 0 && out[0].kind == 1 && out[0].unit == 1 &&
              out[0].limit == 1073741824 && out[3].unit == 6 && out[13].used == 0,
          "the first budget is id 0 and its entries come back with the pool units");
    Check(create("again", 2, 1).value == KERNEL_ERROR_EPERM && out[0].unit == 0x81000000,
          "the system budget took the whole counted pool");
    in[0] = {4, 0, 1, 0};
    in[1] = {4, 0, 1, 0};
    Check(create("dup", 0, 2).value == KERNEL_ERROR_EPERM && out[0].unit == 6 && out[1].unit == 0x82000000,
          "a duplicate kind is refused");
    in[0] = {5, 0, 0x102, 0};
    const int64_t app_id = create("system built-in app budget", 0, 1).value;
    Check(app_id == 1, "the app budget is id 1");
    Check(create("over", 0, 1).value == KERNEL_ERROR_EPERM, "the app budget holds the whole kind 5 pool");
    Check(limits(0, 14).value == KERNEL_ERROR_ENOSYS, "an object holding kinds 1..3 has an undecoded used figure");
    Check(limits(1, 14).value == 0 && *count == 1 && out[0].kind == 5 && out[0].limit == 0x102,
          "570 on an object returns its own entries");

    Check(builtin(0, false, &system_id).value == 0, "SetBuiltinBudget(0, system)");
    Check(builtin(1, false, &app_id).value == 0, "SetBuiltinBudget(1, app)");
    Check(builtin(0, true, nullptr).value == 0 && *value == 0 && *length == 8, "GetBuiltinBudget(0)");
    Check(builtin(2, true, nullptr).posix_errno == Posix::POSIX_EINVAL, "only two builtin slots");
    const int64_t missing = 0x55;
    Check(builtin(1, false, &missing).posix_errno == Posix::POSIX_ESRCH && remove(1).value == KERNEL_ERROR_ESRCH &&
              builtin(1, true, nullptr).value == 0 && *value == -1,
          "the slot drops its old budget before the lookup, so an unknown id frees the app budget");
    Check(create("refill", 0, 1).value == 0x2001, "the freed pool is reusable and the id comes back a generation on");
    Check(remove(0x2001).value == 0 && remove(0x2001).value == KERNEL_ERROR_ESRCH,
          "an unattached budget is freed at delete");

    auto* error = Posix::GetErrorAddr();
    *error = 0;
    Check(KernelGetResourceLimit(5, out, count) == KERNEL_ERROR_EINVAL && *error == 0,
          "GetResourceLimit refuses a process type above 4 without a syscall");
    *count = 14;
    Check(KernelGetResourceLimit(0, out, count) == OK && *count == 14 && out[4].kind == 5 && out[4].limit == 0x102,
          "GetResourceLimit(n) reads builtin pool -2-n");
    *count = 14;
    Check(KernelGetResourceLimit(2, out, count) == OK && out[0].kind == 1 && out[0].limit == 1073741824,
          "GetResourceLimit(2) is the measured ptype 2 pool");
    std::memset(out, 0xcc, sizeof(Entry));
    Check(KernelGetResourceOne(-2, 5, out) == OK && out[0].kind == 5 && out[0].unit == 1 && out[0].limit == 0x102,
          "GetResourceOne copies the matching entry");
    Check(KernelGetResourceOne(-2, 15, out) == KERNEL_ERROR_ENOENT, "a kind the budget does not hold is ENOENT");
    Check(KernelGetResourceOne(-1, 5, out) == KERNEL_ERROR_ESRCH && *error == Posix::POSIX_ESRCH,
          "GetResourceOne passes the lookup failure through");
    in[0] = {5, 0, 0x102, 0};
    std::strcpy(name, "export");
    int64_t made = -1;
    Check(KernelCreateBudget(&made, name, 0, in, 1, out) == OK && made == 0x4001 && out[0].kind == 5,
          "CreateBudget returns the id through the pointer");
    in[0] = {1, 0, 1, 0};
    int64_t refused = -1;
    Check(KernelCreateBudget(&refused, name, 2, in, 1, out) == KERNEL_ERROR_EPERM && *error == Posix::POSIX_EPERM &&
              refused == -1,
          "CreateBudget gives up on EPERM after its retries and leaves the id alone");
    Check(KernelDeleteBudget(static_cast<int32_t>(made)) == OK &&
              KernelDeleteBudget(static_cast<int32_t>(made)) == KERNEL_ERROR_ESRCH && *error == Posix::POSIX_ESRCH,
          "DeleteBudget frees once");

    Check(get().value == KERNEL_ERROR_ENOENT, "mini itself never attaches");
    Check(set(static_cast<int32_t>(system_id)).value == KERNEL_ERROR_ENOSYS,
          "a set on a live budget from a thread not known to be alone stays unknown");
    Check(set(99).value == KERNEL_ERROR_ESRCH && set(static_cast<int32_t>(system_id)).value == KERNEL_ERROR_EALREADY,
          "the unknown outcome spent nothing, the failed lookup did");
  }

  Process::RegisterRforkChild(spawn, mini);
  {
    Process::ScopedGuestProcessPid as_child(spawn);
    Check(get().value == KERNEL_ERROR_ENOENT, "the spawn child inherits mini's detached state");
    Check(set(static_cast<int32_t>(system_id)).value == 0 && get().value == system_id,
          "the spawn child attaches to the request's budget id");
    Check(set(static_cast<int32_t>(system_id)).value == KERNEL_ERROR_EALREADY, "571 is once per process");
    Check(Process::MarkRforkChildExecCommitted(spawn, GetCurrentProcessId(), "/system/sys/SceSysCore.elf"),
          "commit the SysCore exec");
    become(spawn, 0x4800000000000007ull, true);
    Check(get().value == system_id, "SysCore keeps the attachment across exec");
    Check(remove(static_cast<int32_t>(system_id)).value == KERNEL_ERROR_ENOSYS,
          "delete of id 0 after a set of 0 takes the undecoded td+0x3a8 path");
  }
  Process::RegisterRforkChild(audiod, spawn);
  {
    Process::ScopedGuestProcessPid as_audiod(audiod);
    Check(get().value == system_id, "the Audiod child inherits SysCore's budget");
    Check(set(static_cast<int32_t>(system_id)).value == 0, "and may still spend its own set");
  }
  Process::NotifyRforkChildExited(audiod, 0);
  {
    Process::ScopedGuestProcessPid as_mini(mini);
    become(mini, mini_authority, true);
    Check(remove(static_cast<int32_t>(system_id)).value == 0 &&
              limits(static_cast<int32_t>(system_id), 1).value == KERNEL_ERROR_ENOSYS,
          "delete only marks a budget SysCore and the slot still hold");
  }
  Process::NotifyRforkChildExited(spawn, 0);
  {
    Process::ScopedGuestProcessPid as_mini(mini);
    Check(limits(static_cast<int32_t>(system_id), 1).value == KERNEL_ERROR_ENOSYS, "the builtin slot still holds it");
    Check(builtin(0, false, &none).value == 0 && limits(static_cast<int32_t>(system_id), 1).value == KERNEL_ERROR_ESRCH,
          "the slot release frees it");
    in[0] = {1, 0, 1073741824, 0};
    Check(create("system budget", 2, 1).value == 0x2000, "and returns the pool");
  }
  {
    Process::ScopedGuestProcessPid as_shellcore(7214);
    become(7214, 0x4800000000000010ull, true);
    Check(create("x", 0, 0).value == 0x7fffdead && remove(0x55).value == 0,
          "ShellCore gets the kernel constant from 568 and 0 from 569");
  }
  Process::ClearVerifiedOriginalSelf();
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), 0x4000) == OK, "release budget model guest storage");
}
#endif
