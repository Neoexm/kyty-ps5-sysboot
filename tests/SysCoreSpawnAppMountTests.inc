#if defined(_WIN32)
// SysCore's spawn trampoline 0x3a30 when the child has a budget: H69MYqpNjCc on the builder's block with +0xb0 at a stack int set to -1, block+0 = id, QU57kCwF81U(id, 1), CkomU+GYCQ8(getpid, block), nzuKTmqQFXY(budget), execve. Its failure exit at 0x3bde runs QU57kCwF81U(id, 4) and CYIzY6OXyAs(id) only when the stack int is no longer -1.
void CheckSysCoreSpawnAppMount() {
  using namespace Libs;
  using namespace Libs::LibKernel;
  using Budget::Entry;
  AuthInfoScopeLifecycleSavedEnvironment saved_scope("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE");
  AuthInfoScopeLifecycleSavedEnvironment saved_only("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY");
  AuthInfoScopeLifecycleSavedEnvironment saved_socket("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET");
  AuthInfoScopeLifecycleSavedEnvironment saved_entry("KYTY_PS5_BUDGET_SYSTEM_DMEM_ENTRY");
  AuthInfoScopeLifecycleSavedEnvironment saved_evidence("KYTY_PS5_BUDGET_SYSTEM_DMEM_EVIDENCE_SHA256");
  char scope[21] {};
  std::snprintf(scope, sizeof(scope), "s%08lx%08lx", GetCurrentProcessId(), static_cast<unsigned long>(GetTickCount()));
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", scope) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET", "") == 0 &&
            _putenv_s("KYTY_PS5_BUDGET_SYSTEM_DMEM_ENTRY", "1:1:721420288") == 0 &&
            _putenv_s("KYTY_PS5_BUDGET_SYSTEM_DMEM_EVIDENCE_SHA256",
                      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") == 0,
        "scope SysCore spawn app mount");

  Loader::SymbolDatabase symbols;
  InitLibKernel_1(&symbols);
  const auto* begin_symbol = symbols.FindByNid("H69MYqpNjCc", Loader::SymbolType::Func);
  const auto* end_symbol = symbols.FindByNid("CYIzY6OXyAs", Loader::SymbolType::Func);
  const auto* state_symbol = symbols.FindByNid("QU57kCwF81U", Loader::SymbolType::Func);
  const auto* begin2_symbol = symbols.FindByNid("HRDq-RDIGmI", Loader::SymbolType::Func);
  Check(begin_symbol != nullptr && end_symbol != nullptr && state_symbol != nullptr && begin2_symbol != nullptr,
        "SysCore's app mount imports resolve in the libkernel export table");
  Check(begin_symbol->vaddr != begin2_symbol->vaddr, "H69MYqpNjCc is not routed to the BeginAppMount2 wrapper");
  const auto begin = reinterpret_cast<int (KYTY_SYSV_ABI*)(void*)>(begin_symbol->vaddr);
  const auto end = reinterpret_cast<int (KYTY_SYSV_ABI*)(int32_t)>(end_symbol->vaddr);
  const auto set_app_state = reinterpret_cast<int (KYTY_SYSV_ABI*)(int32_t, uint32_t)>(state_symbol->vaddr);
  const auto begin2 = reinterpret_cast<int (KYTY_SYSV_ABI*)(void*, uint64_t, uint64_t)>(begin2_symbol->vaddr);
  auto* error = Posix::GetErrorAddr();

  void* memory = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&memory, 0x8000, 3, 0, "syscore-spawn-app-mount") == OK, "map SysCore spawn storage");
  auto* bytes = static_cast<uint8_t*>(memory);
  auto* guard = bytes + 0x4000;
  NativeAppMountBlock spawn {bytes, reinterpret_cast<int32_t*>(bytes + 0x200)};
  auto* mib = reinterpret_cast<uint32_t*>(bytes + 0x300);
  auto* value = reinterpret_cast<uint32_t*>(bytes + 0x320);
  auto* length = reinterpret_cast<uint64_t*>(bytes + 0x340);
  auto* in = reinterpret_cast<Entry*>(bytes + 0x400);
  auto* out = reinterpret_cast<Entry*>(bytes + 0x800);
  auto* count = reinterpret_cast<int32_t*>(bytes + 0xc00);
  auto* name = reinterpret_cast<char*>(bytes + 0xc40);
  auto* sysctl_mib = reinterpret_cast<uint32_t*>(bytes + 0xc80);
  auto* before = bytes + 0xd00;
  auto* public_info = bytes + 0x1000;

  const auto read_state = [&](int32_t id) {
    *length = 8;
    value[0] = value[1] = 0xcccccccc;
    return NativeAppMountState(mib, id, value, length);
  };
  // CkomU+GYCQ8 is native libkernel code that ends in this sysctl.
  const auto set_record = [&](int pid) {
    sysctl_mib[0] = 1; sysctl_mib[1] = 14; sysctl_mib[2] = 35; sysctl_mib[3] = static_cast<uint32_t>(pid);
    return NativeKernelBridge::DispatchSyscall({0xca, {reinterpret_cast<uint64_t>(sysctl_mib), 4, 0, 0,
        reinterpret_cast<uint64_t>(spawn.block), 0x98}});
  };
  const auto fails = [&](int result, int code) { return result == KERNEL_ERROR_UNKNOWN + code && *error == code; };

  constexpr int mini = 7440;
  constexpr int syscore = 7441;
  constexpr uint64_t mini_authority = 0x4800000000000022ull;
  constexpr uint64_t syscore_authority = 0x4800000000000007ull;
  constexpr uint64_t shellcore_authority = 0x4800000000000010ull;
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
    Check(system_id == 0, "mini creates the system budget");
  }
  Process::RegisterRforkChild(syscore, mini);
  {
    Process::ScopedGuestProcessPid as_syscore(syscore);
    Check(NativeSyscallGuards::KernelSetBudget(static_cast<int>(system_id)) == OK, "SysCore's spawn attaches the system budget");
    Check(Process::MarkRforkChildExecCommitted(syscore, GetCurrentProcessId(), "/system/sys/SceSysCore.elf"), "commit the SysCore exec");
  }
  // rfork children keep SysCore's credentials until execve
  NativeAppMountBecome(syscore, syscore_authority, true);

  // sub_3720 (umd spawn), sub_3610 (ShellCore) and sub_3510 (fs_cleaner, fmemstats) only strlcpy a title and set 0x2000000.
  struct Child {
    int pid;
    const char* path;
    const char* title;
    int32_t id;
  };
  Child children[] {
      {7442, "/system/sys/orbis_audiod.elf", "NPXS40096", 0},
      {7443, "/system/sys/AgcCompositor.elf", "NPXS40135", 0},
      {7444, "/system/vsh/SceShellCore.elf", nullptr, 0},
      {7445, "/system/sys/fs_cleaner.elf", "NPXS45093", 0},
      {7446, "/system/sys_adm/fmemstats.elf", nullptr, 0},
      {7447, "/system/sys/decid.elf", nullptr, 0},
  };
  int32_t previous = 0;
  for (auto& child: children) {
    Process::RegisterRforkChild(child.pid, syscore);
    Process::ScopedGuestProcessPid as_child(child.pid);
    spawn.Build(child.title);
    std::memcpy(before, spawn.block, 0x180);
    *error = 0x5a5a;
    Check(begin(spawn.block) == OK && *error == 0x5a5a && *spawn.local > 0 && *spawn.local != previous,
          "the export writes a fresh application id through the caller's +0xb0");
    Check(std::memcmp(before, spawn.block, 0x180) == 0, "and leaves the caller's block as it was");
    child.id = previous = *spawn.local;
    Check(read_state(child.id).value == 0 && value[0] == 5 && value[1] == 0, "the child's application starts in state 5");
    std::memcpy(spawn.block, spawn.local, sizeof(int32_t));
    Check(set_app_state(child.id, 1) == OK && set_record(child.pid).value == 0, "QU57kCwF81U(id, 1) and the {1,14,35} record succeed");
    int32_t attached = 0;
    Check(read_state(child.id).value == 0 && value[0] == 1 && AppMount::GetAttachedApp(child.pid, &attached) && attached == child.id,
          "the child is attached to its own application in state 1");
    int64_t budget = -1;
    Check(NativeSyscallGuards::KernelGetBudget(&budget) == OK && budget == system_id, "the child inherits SysCore's budget");
    Check(NativeSyscallGuards::KernelSetBudget(static_cast<int>(system_id)) == OK, "nzuKTmqQFXY attaches the budget");
    Check(Process::MarkRforkChildExecCommitted(child.pid, GetCurrentProcessId(), child.path), "the child reaches its execve");
  }
  Check(children[0].id == 1 && children[5].id == 6, "six children take six consecutive ids from the scope table");

  constexpr int failing = 7448;
  Process::RegisterRforkChild(failing, syscore);
  int32_t failed_id = 0;
  {
    Process::ScopedGuestProcessPid as_child(failing);
    *error = 0;
    Check(fails(begin(nullptr), Posix::POSIX_EFAULT), "a null request faults and sets errno");
    Check(Memory::KernelMprotect(guard, 0x4000, 0) == OK, "protect SysCore spawn guard");
    Check(fails(begin(guard - 0x177), Posix::POSIX_EFAULT), "the 0x178-byte copy faults on a guard page");
    Check(Memory::KernelMprotect(guard, 0x4000, 3) == OK, "restore SysCore spawn guard");
    spawn.Build("NPXS40096");
    std::memset(spawn.block + 0xb0, 0, 8);
    Check(fails(begin(spawn.block), Posix::POSIX_EINVAL) && *spawn.local == -1, "a null output pointer is EINVAL");
    for (const uint32_t category: {0u, 0x10000u, 0x02000100u, 0x03000000u}) {
      spawn.Build("NPXS40096");
      AppMountStore32(spawn.block + 0x50, category);
      Check(fails(begin(spawn.block), Posix::POSIX_ENOSYS) && *spawn.local == -1, "unmodelled categories leave the output untouched");
    }
    std::memset(public_info, 0, 0x18b0);
    AppMountStore32(public_info, 0x02000000);
    std::memcpy(public_info + 4, "NPXS40096", 9);
    std::memcpy(public_info + 0xb0, spawn.block + 0xb0, 8);
    Check(fails(begin(public_info), Posix::POSIX_ENOSYS) && *spawn.local == -1, "the export reads the kernel block, not the public info");
    Process::ClearVerifiedOriginalSelf();
    spawn.Build("NPXS40096");
    Check(fails(begin(spawn.block), Posix::POSIX_ENOSYS) && *spawn.local == -1, "an unknown authority creates nothing");
    NativeAppMountBecome(syscore, syscore_authority, true);

    Check(Memory::KernelMprotect(guard, 0x4000, 1) == OK, "make the id output read-only");
    spawn.Build("NPXS40096");
    std::memcpy(spawn.block + 0xb0, &guard, 8);
    Check(fails(begin(spawn.block), Posix::POSIX_EFAULT) && read_state(7).posix_errno == Posix::POSIX_ESRCH,
          "a failed id copyout destroys the application");
    Check(Memory::KernelMprotect(guard, 0x4000, 3) == OK, "restore the id output");

    // The begin and the app steps succeed, then 571 or execve fails and 0x3bde unwinds.
    spawn.Build("NPXS40096");
    Check(begin(spawn.block) == OK && *spawn.local == 0x2007, "the destroyed slot comes back a generation on");
    failed_id = *spawn.local;
    std::memcpy(spawn.block, spawn.local, sizeof(int32_t));
    Check(set_app_state(failed_id, 1) == OK && set_record(failing).value == 0, "the failing child commits its app steps");
    Check(fails(end(failed_id), Posix::POSIX_EBUSY) && read_state(failed_id).value == 0 && value[0] == 1,
          "a state 1 application cannot be ended by SysCore's authority");
    Check(set_app_state(failed_id, 4) == OK, "QU57kCwF81U(id, 4)");
    *error = 0x5a5a;
    Check(end(failed_id) == OK && *error == 0x5a5a && read_state(failed_id).posix_errno == Posix::POSIX_ESRCH, "CYIzY6OXyAs(id) ends it");
    Check(fails(end(failed_id), Posix::POSIX_ESRCH), "a second end finds nothing");
    Check(fails(end(0), Posix::POSIX_ESRCH), "id 0 is never ended");
    Check(fails(end(-1), Posix::POSIX_ESRCH), "nor is the trampoline's -1");
    Process::ClearVerifiedOriginalSelf();
    Check(fails(end(children[0].id), Posix::POSIX_ENOSYS), "an unknown authority ends nothing");
    NativeAppMountBecome(syscore, shellcore_authority, true);
    Check(fails(end(children[0].id), Posix::POSIX_EBUSY) && read_state(children[0].id).value == 0 && value[0] == 1,
          "Audiod's running application survives");
    NativeAppMountBecome(syscore, syscore_authority, true);
  }
  Process::NotifyRforkChildExited(failing, 255);

  {
    Process::ScopedGuestProcessPid as_syscore(syscore);
    std::memset(public_info, 0, 0x18b0);
    AppMountStore32(public_info, 0x02000000);
    std::memcpy(public_info + 4, "NPXS40096", 9);
    *error = 0;
    Check(begin2(public_info, 0, 0) == 0x4007 && *error == 0, "HRDq-RDIGmI creates a 0x2000000 application in the freed slot");
    AppMountStore32(public_info, 0x05000000);
    std::memcpy(public_info + 4, "NPXS40082", 9);
    Check(begin2(public_info, 0, 0) == 8, "and ShellCore's application after it");
  }
  int32_t attached = 0;
  for (const auto& child: children) {
    Check(AppMount::GetAttachedApp(child.pid, &attached) && attached == child.id && read_state(child.id).value == 0 && value[0] == 1,
          "every executed child keeps its application");
  }

  for (const auto& child: children) Process::NotifyRforkChildExited(child.pid, 0);
  Process::NotifyRforkChildExited(syscore, 0);
  Process::ClearVerifiedOriginalSelf();
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), 0x8000) == OK, "release SysCore spawn storage");
  std::printf("SysCoreSpawnAppMountTests: export=pass children=6 errors=pass cleanup=pass begin2=pass\n");
}
#endif
