void CheckAudiodExtendedMmap() {
#if defined(_WIN32)
  using Libs::NativeKernelBridge::DispatchSyscall;
  using Libs::NativeKernelBridge::SyscallRequest;
  namespace Memory = Libs::LibKernel::Memory;

  const auto saved_env = [](const char* name) {
    const char* value = std::getenv(name);
    return value != nullptr ? std::string(value) : std::string();
  };
  const std::string saved_traps = saved_env("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS");
  const std::string saved_audio = saved_env("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP");
  auto request = SyscallRequest {0x2d5,
      {0x200000000ull, 0xa0000, 2, 0x1000, 1, UINT32_MAX}, 0, true};
  const auto available = [] {
    size_t bytes = 0;
    Check(Memory::KernelAvailableFlexibleMemorySize(&bytes) == OK,
          "query flexible memory for the Audiod extended-mmap fixture");
    return bytes;
  };
  const auto rejected = [&](const SyscallRequest& candidate, int error,
                            const char* description) {
    const auto before = available();
    const auto reply = DispatchSyscall(candidate);
    Check(reply.value == -1 && reply.posix_errno == error && available() == before,
          description);
  };

  Check(_putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP", "1") == 0,
        "select the disabled-trap extended-mmap control");
  rejected(request, Libs::Posix::POSIX_ENOSYS,
           "0x2d5 remains unavailable without the static trap gate");
  Check(_putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP", "") == 0,
        "select the non-Audiod extended-mmap control");
  rejected(request, Libs::Posix::POSIX_ENOSYS,
           "0x2d5 remains unavailable outside the Audiod process gate");
  Check(_putenv_s("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP", "1") == 0,
        "arm the exact Audiod extended-mmap contract");

  auto missing_stack = request;
  missing_stack.stack_arg7_valid = false;
  rejected(missing_stack, Libs::Posix::POSIX_EFAULT,
           "0x2d5 requires a readable seventh stack argument");

  const std::array<std::pair<size_t, uint64_t>, 12> mutations {{
      {0, 0x200004000ull}, {0, 0x200000001ull},
      {1, 0}, {1, 0x3fff}, {1, 0x9c001},
      {2, 0}, {2, 7}, {3, 0x9000}, {4, 0}, {4, 3},
      {5, UINT64_MAX}, {5, 7}}};
  for (const auto& [index, value]: mutations) {
    auto changed = request;
    changed.args[index] = value;
    rejected(changed, Libs::Posix::POSIX_ENOSYS,
             "mutated 0x2d5 register tuple remains unsupported and unallocated");
  }
  auto nonzero_offset = request;
  nonzero_offset.stack_arg7 = 0x4000;
  rejected(nonzero_offset, Libs::Posix::POSIX_ENOSYS,
           "a nonzero 0x2d5 offset remains unsupported and unallocated");

  const auto mapped_and_released = [&](uint64_t size, uint64_t prot = 2, uint64_t mode = 1) {
    auto candidate = request;
    candidate.args[1] = size;
    candidate.args[2] = prot;
    candidate.args[4] = mode;
    const auto before = available();
    const auto reply = DispatchSyscall(candidate);
    Check(reply.value > 0 && reply.posix_errno == 0,
          "an observed Audiod 0x2d5 tuple returns a guest mapping");
    const uint64_t address = static_cast<uint64_t>(reply.value);
    Memory::VirtualQueryInfo query {};
    Check(Memory::KernelVirtualQuery(reinterpret_cast<void*>(address), 0,
                                    &query, sizeof(query)) == OK &&
              query.is_committed && query.is_flexible && query.start <= address &&
              query.end >= address + size && query.protection == static_cast<int32_t>(prot) &&
              address >= 0x200000000ull && (address & 0x3fff) == 0 &&
              before - available() == size,
          "the admitted 0x2d5 result owns a committed RW flexible range of the exact size");
    auto* bytes = reinterpret_cast<volatile uint8_t*>(address);
    bytes[0] = 0x41;
    bytes[size - 1] = 0xd5;
    Check(bytes[0] == 0x41 && bytes[size - 1] == 0xd5,
          "the admitted mode-1 range is readable and writable at both boundaries");
    Check(Memory::KernelMunmap(address, size) == OK && available() == before,
          "normal unmap returns the exact mode-1 allocation capacity");
    Memory::VirtualQueryInfo released {};
    Check(Memory::KernelVirtualQuery(reinterpret_cast<void*>(address), 0,
                                    &released, sizeof(released)) != OK ||
              !released.is_committed || released.start > address ||
              released.end < address + size,
          "the released mode-1 range is no longer a committed allocation");
  };
  mapped_and_released(0xa0000);
  mapped_and_released(0x18000);
  mapped_and_released(0x13000000, 3, 2);

  Check(_putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", saved_traps.c_str()) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP", saved_audio.c_str()) == 0,
        "restore Audiod extended-mmap fixture gates");
#endif
}

void WriteAudiodExtendedMmapElf(const std::filesystem::path& path) {
  using namespace Loader;
  std::vector<uint8_t> image(0x4000, 0x90);
  const auto put = [&](uint64_t offset, const void* data, size_t size) {
    Check(offset <= image.size() && size <= image.size() - offset,
          "synthetic Audiod libkernel field fits fixture");
    std::memcpy(image.data() + offset, data, size);
  };

  Elf64_Ehdr header {};
  const uint8_t ident[] = {0x7f, 'E', 'L', 'F', ELFCLASS64,
                           ELFDATA2LSB, EV_CURRENT, ELFOSABI_FREEBSD, 2};
  std::memcpy(header.e_ident, ident, sizeof(ident));
  header.e_type = ET_EXEC;
  header.e_machine = EM_X86_64;
  header.e_version = EV_CURRENT;
  header.e_entry = 0x900000000ull + 0x2ce0;
  header.e_phoff = sizeof(Elf64_Ehdr);
  header.e_ehsize = sizeof(Elf64_Ehdr);
  header.e_phentsize = sizeof(Elf64_Phdr);
  header.e_phnum = 1;
  put(0, &header, sizeof(header));

  Elf64_Phdr load {};
  load.p_type = PT_LOAD;
  load.p_flags = PF_R | PF_W | PF_X;
  load.p_offset = 0;
  load.p_vaddr = 0x900000000ull;
  load.p_filesz = image.size();
  load.p_memsz = image.size();
  load.p_align = 0x4000;
  put(header.e_phoff, &load, sizeof(load));

  const std::array<uint8_t, 2> syscall {0x0f, 0x05};
  put(0x186a, syscall.data(), syscall.size());
  put(0x1eaa, syscall.data(), syscall.size());
  const std::array<uint8_t, 26> wrapper {
      0x48, 0xc7, 0xc0, 0xd5, 0x02, 0x00, 0x00,
      0x49, 0x89, 0xca, 0x0f, 0x05,
      0x0f, 0x92, 0xc2, 0x0f, 0xb6, 0xd2,
      0x48, 0xc1, 0xe2, 0x20, 0x48, 0x09, 0xd0, 0xc3};
  put(0x2ce0, wrapper.data(), wrapper.size());

  Common::File file;
  Check(file.Create(path), "create synthetic Audiod libkernel ELF");
  uint32_t written = 0;
  file.Write(image.data(), static_cast<uint32_t>(image.size()), &written);
  Check(written == image.size() && file.Flush(),
        "write synthetic Audiod libkernel ELF");
  file.Close();
}

int RunAudiodExtendedMmapTrapChild(int argc, char** argv) {
#if defined(_WIN32)
  if (argc < 2 || std::strcmp(argv[1], "--audiod-extended-mmap-trap-child") != 0) return -1;
  if (argc != 4) return 2;
  using namespace Libs::LibKernel;
  const auto evidence = Common::PathFromUtf8(argv[2]);
  if (_wfreopen(evidence.c_str(), L"wb", stdout) == nullptr) return 3;
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
  Check(_putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP", "1") == 0,
        "arm the Audiod libkernel trap fixture");
  Common::InitializeThreads();
  Common::Subsystems subsystems;
  subsystems.Initialize<Config::Lifecycle>();
  Config::ConfigOptions options;
  options.printf_direction = Config::LogDirection::Console;
  Config::Load(options);
  subsystems.Initialize<Log::Lifecycle>();
  subsystems.Initialize<Memory::Lifecycle>();

  auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
  auto* program = linker->LoadProgram(Common::PathFromUtf8(argv[3]));
  Check(program != nullptr && program->base_vaddr == 0x900000000ull,
        "the synthetic Audiod libkernel maps at its fixture image base");
  const auto* site = reinterpret_cast<const uint8_t*>(program->base_vaddr + 0x2cea);
  Check(site[0] == 0x0f && site[1] == 0x0b,
        "the Audiod loader gate rewrites the exact extended-mmap syscall site");
  std::printf("AUDIOD_EXTENDED_MMAP_TRAP_INSTALLED\n");

  using ExtendedMmap = uint64_t (KYTY_SYSV_ABI *)(
      uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
  const auto invoke = reinterpret_cast<ExtendedMmap>(program->base_vaddr + 0x2ce0);
  size_t before = 0;
  Check(Memory::KernelAvailableFlexibleMemorySize(&before) == OK,
        "read capacity before trapped extended mmap");
  const auto invoke_and_release = [&](uint64_t size) {
    const uint64_t mapped = invoke(0x200000000ull, size, 2, 0x1000,
                                   1, UINT32_MAX, 0);
    Check((mapped >> 32) != 1 && mapped >= 0x200000000ull,
          "a trapped observed tuple resumes with a mapped address and clear carry");
    Memory::VirtualQueryInfo query {};
    size_t after = 0;
    Check(Memory::KernelVirtualQuery(reinterpret_cast<void*>(mapped), 0,
                                    &query, sizeof(query)) == OK &&
              query.is_committed && query.is_flexible && query.protection == 2 &&
              query.start <= mapped && query.end >= mapped + size &&
              Memory::KernelAvailableFlexibleMemorySize(&after) == OK &&
              before - after == size,
          "the trapped return identifies the production-path mapping");
    auto* bytes = reinterpret_cast<volatile uint8_t*>(mapped);
    bytes[0] = 0x2d;
    bytes[size - 1] = 0xd5;
    Check(bytes[0] == 0x2d && bytes[size - 1] == 0xd5,
          "the production-path mapping preserves RW boundary access");
    Check(Memory::KernelMunmap(mapped, size) == OK,
          "release the production-path mapping");
    size_t restored = 0;
    Check(Memory::KernelAvailableFlexibleMemorySize(&restored) == OK && restored == before,
          "the production-path unmap restores flexible-memory capacity");
  };
  invoke_and_release(0xa0000);
  invoke_and_release(0x18000);

  const uint64_t rejected = invoke(0x200000000ull, 0xa0000, 2, 0x1000,
                                   1, UINT32_MAX, 0x4000);
  size_t final_capacity = 0;
  Check(rejected == (uint64_t {1} << 32 | Libs::Posix::POSIX_ENOSYS) &&
            Memory::KernelAvailableFlexibleMemorySize(&final_capacity) == OK &&
            final_capacity == before,
        "the trapped seventh argument reaches the handler and a bad offset resumes with ENOSYS and carry");
  std::printf("AUDIOD_EXTENDED_MMAP_TRAP_OK mapped=1 rw=1 arg7=1 cf=1 resumed=1\n");
  linker->Clear();
  std::printf("AUDIOD_EXTENDED_MMAP_TRAP_CHILD_DONE\n");
  std::fflush(stdout);
  subsystems.Destroy();
  return 0;
#else
  (void)argc;
  (void)argv;
  return -1;
#endif
}

void CheckAudiodExtendedMmapTrap(const std::filesystem::path& root) {
#if defined(_WIN32)
  const auto directory = root / "audiod_extended_mmap_trap";
  Check(std::filesystem::create_directory(directory),
        "create Audiod extended-mmap trap fixture directory");
  const auto fixture = directory / "libkernel.sprx";
  const auto evidence = directory / "trap.log";
  WriteAudiodExtendedMmapElf(fixture);

  std::wstring executable(32768, L'\0');
  const auto length = GetModuleFileNameW(nullptr, executable.data(),
                                         static_cast<DWORD>(executable.size()));
  Check(length > 0 && length < executable.size(),
        "locate Audiod extended-mmap trap child executable");
  executable.resize(length);
  auto command = L"\"" + executable + L"\" --audiod-extended-mmap-trap-child \"" +
                 evidence.native() + L"\" \"" + fixture.native() + L"\"";
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  Check(job != nullptr &&
            SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                    &limits, sizeof(limits)),
        "contain Audiod extended-mmap trap child");
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process {};
  Check(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr,
                       &startup, &process),
        "start isolated Audiod extended-mmap trap child");
  if (!AssignProcessToJobObject(job, process.hProcess)) {
    TerminateProcess(process.hProcess, 90);
    WaitForSingleObject(process.hProcess, 1000);
    Check(false, "assign Audiod extended-mmap child before execution");
  }
  Check(ResumeThread(process.hThread) != DWORD(-1),
        "start contained Audiod extended-mmap trap child");
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
  Check(!log.IsInvalid(), "open Audiod extended-mmap trap evidence");
  const auto data = log.ReadWholeBuffer();
  log.Close();
  const std::string text(reinterpret_cast<const char*>(data.data()), data.size());
  Check(wait == WAIT_OBJECT_0 && status_read && exit_code == 0 &&
            text.find("AUDIOD_EXTENDED_MMAP_TRAP_INSTALLED") != std::string::npos &&
            text.find("AUDIOD_EXTENDED_MMAP_TRAP_OK") != std::string::npos &&
            text.find("AUDIOD_EXTENDED_MMAP_TRAP_CHILD_DONE") != std::string::npos,
        "the exact Audiod loader trap, arg7 copy, dispatch, context return and resume all complete");
#endif
}
