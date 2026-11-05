// Same 0x24c handler as the audio-shm test, but reached through ud2: the loader install rewrites SceSysAvControl's 68 syscall sites and the runtimeLinker VEH gate forwards the fault to DispatchSyscall.
// The install flag is a one-shot process global, so this runs in its own child.
void WriteSysAvRawSyscallElf(const std::filesystem::path& path) {
  using namespace Loader;
  static constexpr std::array<uint32_t, 68> sites = {
      0x6ef5au, 0x6ef8au, 0x6efaau, 0x6efcau, 0x6efeau, 0x6f00au, 0x6f02au, 0x6f04au,
      0x6f06au, 0x6f08au, 0x6f0aau, 0x6f0cau, 0x6f0eau, 0x6f10au, 0x6f12au, 0x6fecau,
      0x6feeau, 0x7079au, 0x707aau, 0x7092au, 0x7094au, 0x713cau, 0x713eau, 0x7140eu,
      0x7143au, 0x7145au, 0x71d6au, 0x71d8au, 0x71daau, 0x71dcau, 0x71deau, 0x71e0au,
      0x71e2au, 0x71e4au, 0x71eeau, 0x728aau, 0x72b1au, 0x72b4au, 0x72b7au, 0x731fau,
      0x7321au, 0x7555au, 0x7557au, 0x7606au, 0x762fau, 0x765dau, 0x772fau, 0x7731au,
      0x7733au, 0x7735au, 0x7737au, 0x7739au, 0x773bau, 0x7838au, 0x7880au, 0x78a2au,
      0x78c0au, 0x78c2au, 0x78c4au, 0x78c6au, 0x78c8au, 0x78caau, 0x78ccau, 0x7932au,
      0x7934au, 0x7936au, 0x793dau, 0x7b74au,
  };
  // single RWX load, so file offset == vaddr and a site index is its address
  std::vector<uint8_t> image(0x7c000, 0x90);
  const auto put = [&](uint64_t offset, const void* data, size_t size) {
    Check(offset <= image.size() && size <= image.size() - offset,
          "synthetic SysAv ELF field fits fixture");
    std::memcpy(image.data() + offset, data, size);
  };

  Elf64_Ehdr header {};
  const uint8_t ident[] = {0x7f, 'E', 'L', 'F', ELFCLASS64,
                           ELFDATA2LSB, EV_CURRENT, ELFOSABI_FREEBSD, 2};
  std::memcpy(header.e_ident, ident, sizeof(ident));
  header.e_type = ET_EXEC;
  header.e_machine = EM_X86_64;
  header.e_version = EV_CURRENT;
  header.e_entry = 0x400000 + 0x773b2;
  header.e_phoff = sizeof(Elf64_Ehdr);
  header.e_ehsize = sizeof(Elf64_Ehdr);
  header.e_phentsize = sizeof(Elf64_Phdr);
  header.e_phnum = 1;
  put(0, &header, sizeof(header));

  Elf64_Phdr load {};
  load.p_type = PT_LOAD;
  load.p_flags = PF_R | PF_W | PF_X;
  load.p_offset = 0;
  load.p_vaddr = 0x400000;
  load.p_filesz = image.size();
  load.p_memsz = image.size();
  load.p_align = 0x4000;
  put(header.e_phoff, &load, sizeof(load));

  const std::array<uint8_t, 2> syscall_site {0x0f, 0x05};
  for (const uint32_t offset: sites) {
    put(offset, syscall_site.data(), syscall_site.size());
  }
  // mov eax,0x24c ; mov r10,rcx ; syscall ; ret, with the syscall on site 0x773ba. No jb: the caller reads errno itself.
  const std::array<uint8_t, 11> wrapper {
      0xb8, 0x4c, 0x02, 0x00, 0x00, 0x49, 0x89, 0xca, 0x0f, 0x05, 0xc3};
  put(0x773b2, wrapper.data(), wrapper.size());
  const std::array<uint8_t, 24> ipmi_wrapper {
      0xb8, 0x6e, 0x02, 0x00, 0x00, 0x49, 0x89, 0xca, 0x0f, 0x05,
      0x0f, 0x92, 0xc2, 0x0f, 0xb6, 0xd2, 0x48, 0xc1, 0xe2, 0x20, 0x48, 0x09, 0xd0, 0xc3};
  put(0x6f0a2, ipmi_wrapper.data(), ipmi_wrapper.size());
  // same wrapper on guarded site 0x6f0ca: passes the number guard but isn't 0x46f0aa
  put(0x6f0c2, ipmi_wrapper.data(), ipmi_wrapper.size());
  const std::array<uint8_t, 2> original_ud2 {0x0f, 0x0b};
  put(0x6b535, original_ud2.data(), original_ud2.size());
  put(0x58671, original_ud2.data(), original_ud2.size());
  put(0x50000, original_ud2.data(), original_ud2.size());
  for (const auto [entry, target]: {std::pair {0x50010u, 0x6b535u}, std::pair {0x50030u, 0x50000u}}) {
    std::array<uint8_t, 10> jump {0xb8, 0x6e, 0x02, 0x00, 0x00, 0xe9};
    const int32_t relative = static_cast<int32_t>(target - entry - jump.size());
    std::memcpy(jump.data() + 6, &relative, 4);
    put(entry, jump.data(), jump.size());
  }

  Common::File file;
  Check(file.Create(path), "create synthetic SysAv trap ELF");
  uint32_t written = 0;
  file.Write(image.data(), static_cast<uint32_t>(image.size()), &written);
  Check(written == image.size() && file.Flush(), "write synthetic SysAv trap ELF");
  file.Close();
}

int RunSysAvRawSyscallTrapChild(int argc, char** argv) {
#if defined(_WIN32)
  if (argc < 2 || std::strcmp(argv[1], "--sysav-raw-syscall-trap-child") != 0) return -1;
  if (argc != 4 && argc != 5) return 2;
  using namespace Libs::LibKernel;
  const auto evidence = Common::PathFromUtf8(argv[2]);
  if (_wfreopen(evidence.c_str(), L"wb", stdout) == nullptr) return 3;
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
  // boot-event envs stay unset so nothing else gets injected
  Check(_putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1") == 0,
        "arm the SysAv raw-syscall trap install");
  Common::InitializeThreads();
  Common::Subsystems subsystems;
  subsystems.Initialize<Config::Lifecycle>();
  Config::ConfigOptions options;
  options.printf_direction = Config::LogDirection::Console;
  Config::Load(options);
  subsystems.Initialize<Log::Lifecycle>();
  subsystems.Initialize<Libs::LibKernel::Memory::Lifecycle>();
  std::printf("SYSAV_RAW_TRAP_CHILD_BEGIN\n");
  std::fflush(stdout);

  auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
  auto* program = linker->LoadProgram(Common::PathFromUtf8(argv[3]));
  Check(program != nullptr && program->base_vaddr == 0x400000,
        "the fixture SceSysAvControl maps static at its image base");
  const auto base = program->base_vaddr;
  const auto* site = reinterpret_cast<const uint8_t*>(base + 0x773ba);
  Check(site[0] == 0x0f && site[1] == 0x0b,
        "the install rewrote the 0x773ba syscall site to ud2 and armed the trap flag");
  std::printf("SYSAV_RAW_TRAP_INSTALLED\n");
  std::fflush(stdout);
  if (argc == 5) {
    const std::string mode = argv[4];
    if (mode == "disconnect_site") {
      Check(_putenv_s("KYTY_DIAGNOSTIC_SYSAV_IPMI_201_PASSTHROUGH", "1") == 0 &&
                _putenv_s("KYTY_DIAGNOSTIC_ORIGINAL_SYSCORE_APP_IPMI", "1") == 0 &&
                _putenv_s("KYTY_DIAGNOSTIC_SYSAV_IPMI_UNMATCHED_AUDIT", "1") == 0,
            "arm the 0x310 gate for the wrong-site call");
      int32_t out = 0x5a5a5a5a, completion = 0x5a5a5a5a;
      uint64_t record[1] {reinterpret_cast<uint64_t>(&completion)};
      reinterpret_cast<int64_t (KYTY_SYSV_ABI *)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)>(base + 0x6f0c2)(
          0x310, 0x20000001, reinterpret_cast<uint64_t>(&out), reinterpret_cast<uint64_t>(record), 8, 0);
      Check(false, "a well-formed 0x310 from another guarded site must not dispatch");
    }
    uint64_t entry = 0;
    if (mode == "original") entry = base + 0x50010;
    else if (mode == "unknown") entry = base + 0x50030;
    else if (mode == "mismatch") {
      const uint32_t wrong_number = 0x26f;
      std::memcpy(reinterpret_cast<void*>(base + 0x6f0a3), &wrong_number, 4);
      Check(FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(base + 0x6f0a2), 24) != FALSE,
            "flush changed fixture number");
      entry = base + 0x6f0a2;
    }
    Check(entry != 0, "known negative trap mode");
    reinterpret_cast<void (KYTY_SYSV_ABI *)()>(entry)();
    Check(false, "original, unknown and mismatched traps must not return as syscalls");
  }


  void* target = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&target, 0x4000, 3, 0, "audio-out-unnamed") == OK,
        "map the audio-out range the trapped syscall will name");
  void* strings = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&strings, 0x4000, 3, 0, "trap-name-strings") == OK,
        "map the guest string region the syscall points at");
  auto* names = static_cast<uint8_t*>(strings);
  std::strcpy(reinterpret_cast<char*>(names), "/SceAo2TVCorP");
  const auto guest = [](const void* p) { return reinterpret_cast<uint64_t>(p); };

  using RawSyscall = int64_t (KYTY_SYSV_ABI *)(uint64_t, uint64_t, uint64_t,
                                               uint64_t, uint64_t, uint64_t);
  const auto invoke = reinterpret_cast<RawSyscall>(base + 0x773b2);

  // ud2 at 0x773ba -> VEH gate -> DispatchSyscall -> SysAvNameAudioSharedMemory, then Rip+=2. r8=27 is a leftover fd.
  Check(invoke(guest(target), 0x4000, guest(names), 1, 27, 0) == 0,
        "the trapped 0x24c names the audio-out range and resumes with success");
  Memory::VirtualQueryInfo named {};
  Check(Memory::KernelVirtualQuery(target, 0, &named, sizeof(named)) == OK &&
            std::strcmp(named.name, "/SceAo2TVCorP") == 0,
        "the live audio-out range carries the /SceAo2TVCorP name set through the trap");
  std::printf("SYSAV_RAW_TRAP_NAME_OK\n");
  std::fflush(stdout);

  Check(invoke(0xdead0000, 0x4000, guest(names), 1, 27, 0) == Libs::Posix::POSIX_EFAULT,
        "naming an unmapped target returns EFAULT through the trap writeback");
  std::printf("SYSAV_RAW_TRAP_EFAULT_OK\n");
  std::fflush(stdout);

  char scope[21] {};
  std::snprintf(scope, sizeof(scope), "i%08lx%08lx", GetCurrentProcessId(),
                static_cast<unsigned long>(GetTickCount()));
  Check(_putenv_s("KYTY_DIAGNOSTIC_SYSAV_IPMI_201_PASSTHROUGH", "1") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_ORIGINAL_SYSCORE_APP_IPMI", "1") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_IPMI_SHARED_SCOPE", scope) == 0,
        "arm the IPMI invoke gate");
  void* ipmi_store = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&ipmi_store, 0x8000, 3, 0, "ipmi-invoke-trap") == OK,
        "map guest IPMI records");
  auto* store = static_cast<uint8_t*>(ipmi_store);
  std::memset(store, 0, 0x8000);
  const auto store_base = guest(store);
  const auto ipmi_invoke = reinterpret_cast<RawSyscall>(base + 0x6f0a2);
  auto bridge = [&](uint32_t op, uint64_t handle, uint64_t args, uint64_t size, uint64_t result = 0) {
    return Libs::NativeKernelBridge::DispatchSyscall(
        {0x26e, {op, handle, result ? result : store_base, args, size, 0}});
  };
  auto* result = reinterpret_cast<int32_t*>(store);
  auto* creation = reinterpret_cast<uint64_t*>(store + 0x40);
  creation[0] = store_base + 0x100;
  creation[1] = store_base + 0x200;
  creation[2] = store_base + 0x300;
  std::strcpy(reinterpret_cast<char*>(store + 0x200), "SceSysAvTrapClient");
  auto* config = reinterpret_cast<uint64_t*>(store + 0x300);
  config[0] = 336;
  config[1] = 1;
  config[2] = config[3] = 0x100;
  Check(bridge(2, 0, store_base + 0x40, 24).value == 0 && *result > 0,
        "create the owned client through the strict adapter");
  const auto client_id = static_cast<uint32_t>(*result);
  auto* invoke_args = reinterpret_cast<uint32_t*>(store + 0x600);
  auto* method_result = reinterpret_cast<int32_t*>(store + 0x680);
  auto* operation_result = reinterpret_cast<int32_t*>(store + 0x690);
  auto set64 = [&](size_t offset, uint64_t value) { std::memcpy(store + offset, &value, 8); };
  invoke_args[0] = 0x12340000;
  set64(0x620, store_base + 0x680);
  invoke_args[10] = 1;
  const auto trapped = [&](uint64_t handle, uint64_t args = 0, uint64_t size = 48, uint64_t out = 0) {
    return static_cast<uint64_t>(ipmi_invoke(0x320, handle, out ? out : store_base + 0x690,
        args ? args : store_base + 0x600, size, 0x12340000));
  };
  *method_result = 0x5a5a5a5a;
  Check(trapped(client_id) == 0 && *operation_result == KERNEL_ERROR_ENOTCONN &&
        *method_result == 0x5a5a5a5a, "disconnected invoke preserves the method result and clears carry");
  Check(trapped(0x20000fff) == 0 && *operation_result == KERNEL_ERROR_EBADF,
        "invalid client handle is a logical failure through the trap");
  {
    Process::ScopedGuestProcessPid foreign(Process::GetPid() + 99);
    Check(trapped(client_id) == 0 && *operation_result == KERNEL_ERROR_EBADF,
          "foreign client handle is rejected without losing resume");
  }
  for (const uint64_t length: {uint64_t {47}, uint64_t {49}, UINT64_MAX}) {
    Check(trapped(client_id, 0, length) == 0 && *operation_result == KERNEL_ERROR_EINVAL,
          "wrong invocation size is rejected before copying outside the declared record");
  }
  Check(trapped(client_id, 1) == 0 && *operation_result == KERNEL_ERROR_EFAULT,
        "unmapped invocation pointer is a logical copyin failure");
  *operation_result = 0x5a5a5a5a;
  Check(trapped(client_id, 0, 48, 1) == (uint64_t {1} << 32 | Libs::Posix::POSIX_EFAULT) &&
        *operation_result == 0x5a5a5a5a, "bad result pointer sets carry and errno while preserving output");
  Check(trapped(0x100000000ull) == (uint64_t {1} << 32 | Libs::Posix::POSIX_EINVAL),
        "noncanonical handle sets syscall carry and errno");
  set64(0x620, 1);
  Check(trapped(client_id) == 0 && *operation_result == KERNEL_ERROR_EFAULT,
        "bad nested method-result pointer is validated before transport");
  set64(0x620, store_base + 0x680);
  invoke_args[1] = 2;
  set64(0x610, 1);
  Check(trapped(client_id) == 0 && *operation_result == KERNEL_ERROR_EFAULT,
        "bad nested input descriptors are rejected before transport");
  invoke_args[1] = 0;
  invoke_args[2] = 1;
  set64(0x618, 1);
  Check(trapped(client_id) == 0 && *operation_result == KERNEL_ERROR_EFAULT,
        "bad nested output descriptors are rejected before transport");
  invoke_args[2] = 0;
  invoke_args[10] = 2;
  Check(trapped(client_id) == 0 && *operation_result == KERNEL_ERROR_EINVAL,
        "invalid method flag remains a logical error");
  invoke_args[10] = 1;

  // 0x46d710's record: one pointer to the completion word, length 8, and the 0xdeadbadecafebeaf magic in r9.
  auto* completion = reinterpret_cast<int32_t*>(store + 0x6a0);
  set64(0x6a8, store_base + 0x6a0);
  const auto disconnect = [&](uint64_t handle, uint64_t args = 0, uint64_t size = 8, uint64_t out = 0) {
    return static_cast<uint64_t>(ipmi_invoke(0x310, handle, out ? out : store_base + 0x690,
        args ? args : store_base + 0x6a8, size, 0xdeadbadecafebeafull));
  };
  *completion = 0x5a5a5a5a;
  Check(disconnect(client_id) == 0 && *operation_result == KERNEL_ERROR_ENOTCONN && *completion == 0x5a5a5a5a,
        "disconnect before connect is ENOTCONN and leaves the completion alone");
  Check(disconnect(0x20000fff) == 0 && *operation_result == KERNEL_ERROR_EBADF,
        "unknown client handle is EBADF through the trap");
  {
    Process::ScopedGuestProcessPid foreign(Process::GetPid() + 99);
    Check(disconnect(client_id) == 0 && *operation_result == KERNEL_ERROR_EBADF,
          "another process cannot disconnect this client");
  }
  for (const uint64_t length: {uint64_t {0}, uint64_t {7}, uint64_t {9}, UINT64_MAX}) {
    Check(disconnect(client_id, 0, length) == 0 && *operation_result == KERNEL_ERROR_EINVAL,
          "disconnect record must be exactly 8 bytes");
  }
  Check(disconnect(client_id, 1) == 0 && *operation_result == KERNEL_ERROR_EFAULT,
        "unmapped disconnect record is a logical copyin failure");
  set64(0x6a8, 1);
  Check(disconnect(client_id) == 0 && *operation_result == KERNEL_ERROR_EFAULT,
        "unwritable completion pointer is rejected before anything is queued");
  set64(0x6a8, store_base + 0x6a0);
  *operation_result = 0x5a5a5a5a;
  Check(disconnect(client_id, 0, 8, 1) == (uint64_t {1} << 32 | Libs::Posix::POSIX_EFAULT) &&
        *operation_result == 0x5a5a5a5a, "bad disconnect result pointer sets carry and errno");
  Check(disconnect(0x100000000ull) == (uint64_t {1} << 32 | Libs::Posix::POSIX_EINVAL),
        "noncanonical disconnect handle sets syscall carry and errno");

  AuthInfo::ImageIdentity identity {};
  identity.authority_id = 0x4800000000000007ull;
  identity.self_size = identity.elf_size = 7;
  identity.self_sha256 = identity.elf_sha256 = AuthInfo::Sha256("fixture", 7);
  Process::InstallVerifiedOriginalSelf(identity);
  AuthInfo::Record auth {};
  const uint64_t capability = 1ull << 62;
  std::memcpy(auth.data(), &identity.authority_id, 8);
  std::memcpy(auth.data() + 8, &capability, 8);
  AuthInfo::Capture capture;
  Check(AuthInfo::BuildCaptureEnvelope(auth, identity, &capture, nullptr) &&
        Process::InstallVerifiedAuthInfo(capture), "install child-only server admission fixture");
  std::memset(store + 0x300, 0, 0x150);
  Check(bridge(0, 0, store_base + 0x40, 24).value == 0 && *result > 0,
        "create a capability-admitted fixture server");
  const auto server_id = static_cast<uint32_t>(*result);
  auto* receive_info = reinterpret_cast<uint64_t*>(store + 0x800);
  auto* receive_args = reinterpret_cast<uint64_t*>(store + 0x840);
  receive_args[0] = store_base + 0x1000;
  receive_args[1] = 0x2900;
  receive_args[2] = store_base + 0x800;
  receive_args[3] = store_base + 0x880;
  *reinterpret_cast<uint32_t*>(store + 0x880) = 2000000;
  auto server = std::async(std::launch::async, [&] {
    auto call = [&](uint32_t op, uint64_t handle, uint64_t args, uint64_t size) {
      const auto answer = bridge(op, handle, args, size, store_base + 0x900);
      Check(answer.value == 0 && answer.posix_errno == 0, "fixture server syscall transport");
      return *reinterpret_cast<int32_t*>(store + 0x900);
    };
    Check(call(0x201, server_id, store_base + 0x840, 32) == 0 &&
          static_cast<uint32_t>(receive_info[1]) == 1, "server receives the connect packet");
    const uint64_t scope_client = receive_info[1] >> 32;
    auto* session_args = reinterpret_cast<uint64_t*>(store + 0x940);
    session_args[0] = store_base + 0x100;
    session_args[1] = store_base + 0x960;
    set64(0x960, 16);
    set64(0x968, 0x11);
    const int session = call(4, UINT32_MAX, store_base + 0x940, 16);
    Check(session > 0 && call(0x212, scope_client, store_base + 0x980, 4) == 0,
          "session creation and connect callback reply");
    for (int round = 0; round < 3; ++round) {
      Check(call(0x201, server_id, store_base + 0x840, 32) == 0 &&
            static_cast<uint32_t>(receive_info[1]) == 0x41,
            "server receives the queued method rather than another connect callback");
      uint32_t method = 0, count = 0;
      std::memcpy(&method, store + 0x1000 + 12, 4);
      std::memcpy(&count, store + 0x1000 + 16, 4);
      Check(method == 0x12340000 && count == 2 &&
            std::memcmp(store + 0x1000 + 28, "abc", 3) == 0,
            "server observes the declared method and copied input bytes");
      auto* reply_args = reinterpret_cast<uint32_t*>(store + 0xa00);
      reply_args[0] = round == 1 ? static_cast<uint32_t>(-123) : 0;
      reply_args[1] = round == 2 ? 1 : 0;
      set64(0xa08, store_base + 0xa40);
      reply_args[4] = 1;
      set64(0xa40, store_base + 0xa80);
      set64(0xa48, 3);
      set64(0xa50, 3);
      std::memcpy(store + 0xa80, "xyz", 3);
      Check(call(0x232, session, store_base + 0xa00, 24) == 0,
            "server replies to the received transaction");
    }
    Check(call(0x201, server_id, store_base + 0x840, 32) == 0 &&
          static_cast<uint32_t>(receive_info[1]) == 3 && receive_info[1] >> 32 == scope_client,
          "server receives the trapped client's disconnect packet");
    Check(call(5, session, 0, 0) == 0, "destroy the disconnected fixture session");
    *reinterpret_cast<int32_t*>(store + 0x984) = -7;
    Check(call(0x222, scope_client, store_base + 0x984, 4) == 0, "server answers the disconnect with its own completion word");
    Check(call(0x201, server_id, store_base + 0x840, 32) == 0 &&
          static_cast<uint32_t>(receive_info[1]) == 1, "server receives a second client's connect");
    const uint64_t second_client = receive_info[1] >> 32;
    Check(call(4, UINT32_MAX, store_base + 0x940, 16) > 0 && call(0x212, second_client, store_base + 0x980, 4) == 0,
          "second session accepted");
    Check(call(0x201, server_id, store_base + 0x840, 32) == 0 &&
          static_cast<uint32_t>(receive_info[1]) == 3 && receive_info[1] >> 32 == second_client,
          "second disconnect reaches the server");
    // No 0x222: the server goes away while the client is still waiting on the disconnect reply.
    Check(call(1, server_id, 0, 0) == 0, "server unregisters with the disconnect unanswered");
  });
  auto* connect_args = reinterpret_cast<uint64_t*>(store + 0xb00);
  connect_args[2] = store_base + 0xb40;
  *reinterpret_cast<int32_t*>(store + 0xb40) = -1;
  Check(ipmi_invoke(0x400, client_id, store_base + 0xb60, store_base + 0xb00, 32, 0) == 0 &&
        *reinterpret_cast<int32_t*>(store + 0xb60) == 0 &&
        *reinterpret_cast<int32_t*>(store + 0xb40) == 0, "connect returns only after the callback reply");
  invoke_args[1] = 2;
  set64(0x610, store_base + 0xc00);
  set64(0xc00, store_base + 0xc80);
  set64(0xc08, 3);
  set64(0xc10, store_base + 0xc90);
  set64(0xc18, 2);
  std::memcpy(store + 0xc80, "abc", 3);
  std::memcpy(store + 0xc90, "de", 2);
  for (int round = 0; round < 3; ++round) {
    invoke_args[2] = round == 2 ? 1 : 0;
    set64(0x618, store_base + 0xd00);
    set64(0xd00, store_base + 0xd40);
    set64(0xd08, 8);
    set64(0xd10, 0);
    *method_result = *operation_result = 0x5a5a5a5a;
    Check(trapped(client_id) == 0 && *operation_result == 0 &&
          *method_result == (round == 1 ? -123 : 0),
          "invoke reply separates successful transport from the method result and clears carry");
    if (round == 2) Check(std::memcmp(store + 0xd40, "xyz", 3) == 0 &&
        *reinterpret_cast<uint64_t*>(store + 0xd10) == 3, "reply copies output bytes and descriptor length");
  }
  std::printf("SYSAV_RAW_TRAP_INVOKE_OK request_reply=3 observed_shape=1 logical_failures=1 syscall_errno_carry=1\n");
  std::fflush(stdout);

  *completion = 0x5a5a5a5a;
  Check(disconnect(client_id) == 0 && *operation_result == 0 && *completion == -7,
        "disconnect returns after the server's reply and carries its completion word");
  *completion = 0x5a5a5a5a;
  Check(disconnect(client_id) == 0 && *operation_result == KERNEL_ERROR_ENOTCONN && *completion == 0x5a5a5a5a,
        "a repeated disconnect is ENOTCONN");
  Check(trapped(client_id) == 0 && *operation_result == KERNEL_ERROR_ENOTCONN, "no invoke after disconnect");
  Check(ipmi_invoke(3, client_id, store_base + 0x690, 0, 0, 0) == 0 && *operation_result == 0,
        "the disconnected client is destroyed through the trapped op 3");
  Check(disconnect(client_id) == 0 && *operation_result == KERNEL_ERROR_EBADF, "a destroyed client handle is EBADF");
  config[0] = 336;
  config[1] = 1;
  config[2] = config[3] = 0x100;
  Check(bridge(2, 0, store_base + 0x40, 24).value == 0 && *result > 0, "create a second owned client");
  const auto second_id = static_cast<uint32_t>(*result);
  *reinterpret_cast<int32_t*>(store + 0xb40) = -1;
  Check(ipmi_invoke(0x400, second_id, store_base + 0xb60, store_base + 0xb00, 32, 0) == 0 &&
        *reinterpret_cast<int32_t*>(store + 0xb60) == 0 &&
        *reinterpret_cast<int32_t*>(store + 0xb40) == 0, "second client connects");
  *completion = 0x5a5a5a5a;
  Check(disconnect(second_id) == 0 && *operation_result == KERNEL_ERROR_ECONNRESET && *completion == 0x5a5a5a5a,
        "server teardown during disconnect is ECONNRESET with no completion written");
  Check(disconnect(second_id) == 0 && *operation_result == KERNEL_ERROR_ENOTCONN,
        "the failed disconnect still cleared busy and connected");
  Check(ipmi_invoke(3, second_id, store_base + 0x690, 0, 0, 0) == 0 && *operation_result == 0,
        "the reset client is destroyed rather than left busy");
  server.get();
  Check(bridge(1, server_id, 0, 0).value == 0 && *result == KERNEL_ERROR_EBADF, "the fixture server is already gone");
  Process::ClearVerifiedOriginalSelf();
  std::printf("SYSAV_RAW_TRAP_DISCONNECT_OK reply=1 reset_cleanup=1 logical_failures=1 syscall_errno_carry=1\n");
  std::fflush(stdout);

  linker->Clear();
  std::printf("SYSAV_RAW_TRAP_CHILD_DONE\n");
  std::fflush(stdout);
  subsystems.Destroy();
  return 0;
#else
  (void)argc;
  (void)argv;
  return -1;
#endif
}

void CheckSysAvRawSyscallTrap(const std::filesystem::path& root) {
#if defined(_WIN32)
  const auto directory = root / "sysav_raw_syscall_trap";
  Check(std::filesystem::create_directory(directory), "create raw-syscall trap fixture directory");
  const auto fixture = directory / "SceSysAvControl.elf";
  WriteSysAvRawSyscallElf(fixture);
  for (const std::string mode: {"positive", "original", "unknown", "mismatch", "disconnect_site"}) {
    const auto evidence = directory / ("raw_trap_" + mode + ".log");
    std::wstring executable(32768, L'\0');
    const auto length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    Check(length > 0 && length < executable.size(), "locate raw-syscall trap executable");
    executable.resize(length);
    auto command = L"\"" + executable + L"\" --sysav-raw-syscall-trap-child \"" +
                   evidence.native() + L"\" \"" + fixture.native() + L"\"";
    if (mode != "positive") command += L" " + std::wstring(mode.begin(), mode.end());
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    Check(job != nullptr && SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
          "contain raw-syscall trap child");
    STARTUPINFOW startup {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process {};
    Check(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
                         CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup, &process),
          "start isolated raw-syscall trap child");
    if (!AssignProcessToJobObject(job, process.hProcess)) {
      TerminateProcess(process.hProcess, 90);
      WaitForSingleObject(process.hProcess, 1000);
      Check(false, "assign raw-syscall trap child before execution");
    }
    Check(ResumeThread(process.hThread) != DWORD(-1), "start contained trap child");
    const auto wait = WaitForSingleObject(process.hProcess, 15000);
    if (wait != WAIT_OBJECT_0) {
      TerminateJobObject(job, 126);
      WaitForSingleObject(process.hProcess, 1000);
    }
    DWORD exit_code = 0xffffffffu;
    const bool status_read = GetExitCodeProcess(process.hProcess, &exit_code) != FALSE;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    CloseHandle(job);
    Common::File log(evidence, Common::File::Mode::Read);
    Check(!log.IsInvalid(), "open trap child evidence");
    const auto bytes = log.ReadWholeBuffer();
    log.Close();
    const std::string text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    Check(wait == WAIT_OBJECT_0 && status_read &&
          text.find("SYSAV_RAW_TRAP_INSTALLED") != std::string::npos, "trap child completed within its bound");
    if (mode == "positive") {
      Check(exit_code == 0 && text.find("SYSAV_RAW_TRAP_NAME_OK") != std::string::npos &&
            text.find("SYSAV_RAW_TRAP_EFAULT_OK") != std::string::npos &&
            text.find("SYSAV_RAW_TRAP_INVOKE_OK") != std::string::npos &&
            text.find("SYSAV_RAW_TRAP_DISCONNECT_OK") != std::string::npos &&
            text.find("SYSAV_RAW_TRAP_CHILD_DONE") != std::string::npos,
            "the production guard, adapter, invoke, disconnect, server and reply all complete");
    } else if (mode == "disconnect_site") {
      Check(exit_code != 0 &&
            text.find("SYSAV_RAW_SYSCALL_TRAP site=0x000000000046f0ca") != std::string::npos &&
            text.find("SYSAV_IPMI_UNMATCHED_INVOCATION op=0x310") != std::string::npos &&
            text.find("site=0x000000000046f0ca") != std::string::npos &&
            text.find("SYSAV_IPMI_REQUEST") == std::string::npos &&
            text.find("NATIVE_IPMI_SHARED_ADAPTER") == std::string::npos,
            "0x310 is admitted only from the SysAv wrapper site");
    } else {
      const std::string classification = "classification=" + (mode == "original" ? std::string("original_ud2") :
          mode == "mismatch" ? std::string("guard_number_mismatch") : std::string("unknown"));
      Check(exit_code != 0 && text.find(classification) != std::string::npos &&
            text.find("NO_SYSCALL_DISPATCH") != std::string::npos &&
            text.find("NATIVE_IPMI_SHARED_ADAPTER") == std::string::npos &&
            text.find("SYSAV_RAW_SYSCALL_TRAP") == std::string::npos,
            "ud2, unknown and wrong-number traps never dispatch as native syscalls");
    }
  }

  std::printf("SysAvRawSyscallTrapTests: install=pass ud2_trap=pass gate_dispatch=pass "
              "range_name=pass efault_writeback=pass ipmi_invoke=pass replies=3 ipmi_disconnect=pass disconnect_reset=pass "
              "original_ud2=pass unknown=pass number_mismatch=pass disconnect_site=pass\n");
#endif
}
