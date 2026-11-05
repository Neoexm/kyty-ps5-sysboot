// /SceAo2TVCorP lives in the scope shm namespace, which only exists if a scope is selected before Memory::Initialize. Hence the scoped child.
int RunSysAvAudioShmChild(int argc, char** argv) {
#if defined(_WIN32)
  if (argc < 2 || std::strcmp(argv[1], "--sysav-audio-shm-child") != 0) return -1;
  if (argc != 4 && argc != 5) return 2;
  using namespace Libs::LibKernel;
  namespace FS = Libs::LibKernel::FileSystem;
  using Libs::NativeKernelBridge::DispatchSyscall;
  const auto evidence = Common::PathFromUtf8(argv[2]);
  if (_wfreopen(evidence.c_str(), L"wb", stdout) == nullptr) return 3;
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
  // before FS::Initialize, which arms the SysAv bridge gates from the trap env
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", argv[3]) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1") == 0,
        "select child audio-shm scope and arm the SysAv trap dispatch");
  Common::InitializeThreads();
  Common::Subsystems subsystems;
  subsystems.Initialize<Config::Lifecycle>();
  Config::ConfigOptions options;
  // the peers' SCOPE_SHM_OPEN lines only come out through the console log
  options.printf_direction = argc == 5 ? Config::LogDirection::Console : Config::LogDirection::Silent;
  Config::Load(options);
  subsystems.Initialize<Log::Lifecycle>();
  subsystems.Initialize<Memory::Lifecycle>();
  FS::Initialize();
  std::printf("SYSAV_AUDIO_SHM_CHILD_BEGIN\n");
  std::fflush(stdout);

  void* storage = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&storage, 0x4000, 3, 0, "sysav-audio-shm") == OK,
        "map guest storage for the audio-shm path and stat buffer");
  auto* page = static_cast<uint8_t*>(storage);
  const auto guest = [&](const void* p) { return reinterpret_cast<uint64_t>(p); };
  auto* name = reinterpret_cast<char*>(page);
  std::strcpy(name, "/SceAo2TVCorP");
  auto* stat = reinterpret_cast<FS::FileStat*>(page + 0x200);

  if (argc == 5) {
    const auto event = [&](const char* suffix) {
      return OpenEventA(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, ("Local\\" + std::string(argv[3]) + suffix).c_str());
    };
    const HANDLE ready = event("_ready");
    const HANDLE done = event("_done");
    Check(ready != nullptr && done != nullptr, "open the peer handshake events");
    if (std::strcmp(argv[4], "create") == 0) {
      // SysAv side
      auto r = DispatchSyscall({0x1e2, {guest(name), 0x200202, 0x1b6, 0, 0, 0}});
      Check(r.value >= 3 && r.posix_errno == 0, "the creating peer makes /SceAo2TVCorP");
      const int fd = static_cast<int>(r.value);
      r = DispatchSyscall({0x1e0, {static_cast<uint64_t>(fd), 0x4000, 0, 0, 0, 0}});
      Check(r.value == 0 && r.posix_errno == 0, "the creating peer sizes it");
      r = DispatchSyscall({0x1dd, {0, 0x4000, 3, 1, static_cast<uint64_t>(fd), 0}});
      Check(r.value != -1 && r.posix_errno == 0, "the creating peer maps it");
      auto* window = reinterpret_cast<volatile uint32_t*>(static_cast<uintptr_t>(r.value));
      window[0] = 0x6b797479;
      window[0xfff] = 0x41756469;
      std::printf("SYSAV_AUDIO_SHM_PEER_CREATED\n");
      std::fflush(stdout);
      Check(SetEvent(ready) != FALSE && WaitForSingleObject(done, 15000) == WAIT_OBJECT_0,
            "the creating peer stays up until the other process has opened and written");
      Check(window[1] == 0x0a0d10e5, "the other process's write is in the creating peer's mapping");
      std::printf("SYSAV_AUDIO_SHM_PEER_READBACK_OK\n");
      Check(FS::KernelClose(fd) == 0, "close the creating peer's descriptor");
    } else {
      // Audiod side, like sceAudioOut2ShmMap: shm_open(O_RDWR, 0666), fstat, mmap(st_size, 0x33, MAP_SHARED)
      Check(WaitForSingleObject(ready, 0) == WAIT_OBJECT_0, "the block exists before the opening peer starts");
      const int fd = FS::KernelShmOpen("/SceAo2TVCorP", 2, 0x1b6);
      Check(fd >= 3, "a second process in the scope opens /SceAo2TVCorP without O_CREAT");
      stat->st_size = -1;
      Check(FS::KernelFstat(fd, stat) == 0 && stat->st_size == 0x4000, "the opening peer sees the creator's size");
      void* mapped = Memory::KernelMmap(nullptr, static_cast<size_t>(stat->st_size), 0x33, 1, fd, 0);
      Check(mapped != reinterpret_cast<void*>(static_cast<intptr_t>(-1)), "the opening peer maps it with Audiod's protection");
      auto* window = static_cast<volatile uint32_t*>(mapped);
      Check(window[0] == 0x6b797479 && window[0xfff] == 0x41756469, "the opening peer reads the creator's bytes");
      window[1] = 0x0a0d10e5;
      Check(FS::KernelShmOpen("/SceAo2TVCorQ", 2, 0x1b6) == -1 && *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOENT,
            "a name nobody created still misses with ENOENT");
      std::printf("SYSAV_AUDIO_SHM_PEER_OPENED\n");
      Check(FS::KernelClose(fd) == 0, "close the opening peer's descriptor");
    }
    CloseHandle(ready);
    CloseHandle(done);
    std::printf("SYSAV_AUDIO_SHM_CHILD_DONE\n");
    std::fflush(stdout);
    subsystems.Destroy();
    return 0;
  }

  const auto anon_baseline = Memory::TestGetAnonymousSharedMemoryStats();
  const int old_umask = FS::KernelUmask(0022);
  const auto open_anon = [&](uint64_t flags, uint64_t mode) {
    const int fd = FS::KernelShmOpen(reinterpret_cast<const char*>(1),
                                     static_cast<int>(flags), static_cast<uint16_t>(mode));
    return Libs::NativeKernelBridge::Reply {
        fd, fd < 0 ? *Libs::Posix::GetErrorAddr() : 0};
  };

  auto anon = open_anon(0xa02, 0x1a0);
  Check(anon.value >= 3 && anon.posix_errno == 0,
        "the Audiod SHM_ANON tuple reaches the shm_open export");
  const int anon_fd = static_cast<int>(anon.value);
  size_t anon_size = 1;
  Check(FS::GetDescriptorFlags(anon_fd) == 1 &&
            FS::GetSharedMemorySize(anon_fd, &anon_size) && anon_size == 0 &&
            !FS::IsSharedMemoryNamed(anon_fd, "") &&
            FS::KernelDup2(anon_fd, anon_fd) == anon_fd &&
            FS::KernelDup2(anon_fd, anon_fd + 100) == KERNEL_ERROR_EINVAL,
        "the anonymous descriptor is zero-sized, unnamed, close-on-exec and not broadly duplicated");
  *stat = {};
  Check(FS::KernelFstat(anon_fd, stat) == OK && stat->st_mode == 0100640 &&
            stat->st_size == 0 && stat->st_blksize == 0x4000 && stat->st_blocks == 0,
        "the fstat export reports only the retained mode and zero-sized object contract");

  Check(FS::KernelFtruncate(anon_fd, 0x20000) == OK,
        "the Audiod ftruncate creates an anonymous backing");
  *stat = {};
  Check(FS::KernelFstat(anon_fd, stat) == OK && stat->st_size == 0x20000 &&
            stat->st_blksize == 0x4000 && stat->st_blocks == 8,
        "fstat reports the grown anonymous object in guest pages");
  void* first_anon_mapping = Memory::KernelMmap(nullptr, 0x20000, 3, 1, anon_fd, 0);
  Check(first_anon_mapping != reinterpret_cast<void*>(static_cast<intptr_t>(-1)),
        "the Audiod MAP_SHARED request maps the anonymous backing");
  const auto first_anon_map = reinterpret_cast<uint64_t>(first_anon_mapping);
  void* second_anon_mapping = Memory::KernelMmap(nullptr, 0x20000, 3, 1, anon_fd, 0);
  Check(second_anon_mapping != reinterpret_cast<void*>(static_cast<intptr_t>(-1)),
        "a second mapping of the same anonymous object succeeds");
  const auto second_anon_map = reinterpret_cast<uint64_t>(second_anon_mapping);
  auto* first_anon_bytes = reinterpret_cast<volatile uint8_t*>(first_anon_map);
  auto independent_a = open_anon(2, 0600);
  auto independent_b = open_anon(2, 0600);
  Check(independent_a.value >= 3 && independent_b.value >= 3 &&
            independent_a.value != independent_b.value,
        "distinct SHM_ANON opens return distinct descriptors");
  const int independent_a_fd = static_cast<int>(independent_a.value);
  const int independent_b_fd = static_cast<int>(independent_b.value);
  Check(FS::KernelFtruncate(independent_a_fd, 0x4000) == OK &&
            FS::KernelFtruncate(independent_b_fd, 0x4000) == OK,
        "distinct anonymous objects acquire independent backing");
  void* independent_a_map = Memory::KernelMmap(nullptr, 0x4000, 3, 1, independent_a_fd, 0);
  void* independent_b_map = Memory::KernelMmap(nullptr, 0x4000, 3, 1, independent_b_fd, 0);
  Check(independent_a_map != reinterpret_cast<void*>(static_cast<intptr_t>(-1)) &&
            independent_b_map != reinterpret_cast<void*>(static_cast<intptr_t>(-1)),
        "distinct anonymous objects map");
  static_cast<volatile uint8_t*>(independent_a_map)[0] = 0x12;
  static_cast<volatile uint8_t*>(independent_b_map)[0] = 0x34;
  Check(static_cast<volatile uint8_t*>(independent_a_map)[0] == 0x12 &&
            static_cast<volatile uint8_t*>(independent_b_map)[0] == 0x34,
        "distinct anonymous objects do not alias");
  Check(FS::KernelClose(independent_a_fd) == OK && FS::KernelClose(independent_b_fd) == OK &&
            Memory::KernelMunmap(reinterpret_cast<uint64_t>(independent_a_map), 0x4000) == OK &&
            Memory::KernelMunmap(reinterpret_cast<uint64_t>(independent_b_map), 0x4000) == OK,
        "distinct anonymous objects close and release independently");

  auto resized = open_anon(2, 0600);
  Check(resized.value >= 3, "open the anonymous resize fixture");
  const int resized_fd = static_cast<int>(resized.value);
  Check(FS::KernelFtruncate(resized_fd, 0x2000) == OK,
        "grow the anonymous resize fixture within one guest page");
  void* resized_map = Memory::KernelMmap(nullptr, 0x2000, 3, 1, resized_fd, 0);
  Check(resized_map != reinterpret_cast<void*>(static_cast<intptr_t>(-1)),
        "map the anonymous resize fixture");
  auto* resized_bytes = static_cast<volatile uint8_t*>(resized_map);
  resized_bytes[0] = 0x55;
  resized_bytes[0x1000] = 0xaa;
  Check(FS::KernelFtruncate(resized_fd, 0x1000) == OK &&
            FS::KernelFtruncate(resized_fd, 0x3000) == OK &&
            resized_bytes[0] == 0x55 && resized_bytes[0x1000] == 0,
        "shrink and regrow preserve the prefix and zero the re-exposed bytes");
  const auto live_growth_before = Memory::TestGetAnonymousSharedMemoryStats();
  Memory::TestFailNextAnonymousSharedMemoryAllocation();
  Check(FS::KernelFtruncate(resized_fd, 0x5000) == KERNEL_ERROR_ENOMEM &&
            FS::GetSharedMemorySize(resized_fd, &anon_size) && anon_size == 0x3000 &&
            resized_bytes[0] == 0x55 && resized_bytes[0x1000] == 0 &&
            Memory::TestGetAnonymousSharedMemoryStats().backing_bytes ==
                live_growth_before.backing_bytes &&
            Memory::TestGetAnonymousSharedMemoryStats().mappings ==
                live_growth_before.mappings,
        "failed live-mapped growth preserves size, backing, bytes and lease counts");
  Check(FS::KernelFtruncate(resized_fd, 0x5000) == OK,
        "grow an actively mapped anonymous object through adjacent backing");
  void* resized_large = Memory::KernelMmap(nullptr, 0x5000, 3, 1, resized_fd, 0);
  Check(resized_large != reinterpret_cast<void*>(static_cast<intptr_t>(-1)) &&
            static_cast<volatile uint8_t*>(resized_large)[0] == 0x55 &&
            static_cast<volatile uint8_t*>(resized_large)[0x4fff] == 0,
        "the grown object preserves old bytes and supplies zeroed new bytes");
  Check(FS::KernelClose(resized_fd) == OK &&
            Memory::KernelMunmap(reinterpret_cast<uint64_t>(resized_map), 0x4000) == OK &&
            Memory::KernelMunmap(reinterpret_cast<uint64_t>(resized_large), 0x8000) == OK,
        "the grown object releases after its descriptor and mappings close");

  auto failed = open_anon(2, 0600);
  Check(failed.value >= 3, "open the anonymous allocation-failure fixture");
  const int failed_fd = static_cast<int>(failed.value);
  const auto failed_before = Memory::TestGetAnonymousSharedMemoryStats();
  Memory::TestFailNextAnonymousSharedMemoryAllocation();
  Check(FS::KernelFtruncate(failed_fd, 0x4000) == KERNEL_ERROR_ENOMEM &&
            FS::GetSharedMemorySize(failed_fd, &anon_size) && anon_size == 0,
        "a failed anonymous backing allocation returns ENOMEM without changing size");
  const auto failed_after = Memory::TestGetAnonymousSharedMemoryStats();
  Check(failed_after.backings == failed_before.backings &&
            failed_after.backing_bytes == failed_before.backing_bytes &&
            failed_after.mappings == failed_before.mappings && FS::KernelClose(failed_fd) == OK,
        "failed anonymous allocation leaves no backing or mapping leak");

  const auto readonly_open = open_anon(0, 0600);
  const auto writeonly_open = open_anon(1, 0600);
  const auto invalid_access_open = open_anon(3, 0600);
  const auto unknown_flags_open = open_anon(0x400002, 0600);
  Check(readonly_open.value == -1 && readonly_open.posix_errno == Libs::Posix::POSIX_EINVAL &&
            writeonly_open.value == -1 && writeonly_open.posix_errno == Libs::Posix::POSIX_EINVAL &&
            invalid_access_open.value == -1 && invalid_access_open.posix_errno == Libs::Posix::POSIX_EINVAL &&
            unknown_flags_open.value == -1 && unknown_flags_open.posix_errno == Libs::Posix::POSIX_EINVAL &&
            Memory::TestGetAnonymousSharedMemoryStats().objects == anon_baseline.objects,
        "invalid anonymous access modes and unsupported flags create no objects");
  const int contract_umask = FS::KernelUmask(0077);
  auto trunc_flags = open_anon(0x402, 0666);
  auto cloexec_flags = open_anon(0x100002, 0666);
  Check(contract_umask == 0022 && trunc_flags.value >= 3 && cloexec_flags.value >= 3,
        "O_TRUNC and O_CLOEXEC remain valid anonymous creation flags");
  *stat = {};
  Check(FS::KernelFstat(static_cast<int>(trunc_flags.value), stat) == OK &&
            stat->st_mode == 0100600 &&
            FS::GetDescriptorFlags(static_cast<int>(cloexec_flags.value)) == 1 &&
            FS::KernelClose(static_cast<int>(trunc_flags.value)) == OK &&
            FS::KernelClose(static_cast<int>(cloexec_flags.value)) == OK &&
            FS::KernelUmask(0022) == 0077,
        "anonymous mode honors the active umask and close-on-exec is forced");
  auto invalid = open_anon(2, 0600);
  Check(invalid.value >= 3, "open the anonymous negative mapping fixture");
  const int invalid_fd = static_cast<int>(invalid.value);
  Check(FS::KernelFtruncate(invalid_fd, 0x4000) == OK,
        "size the anonymous negative mapping fixture");
  Check(FS::KernelFtruncate(invalid_fd, -1) == KERNEL_ERROR_EINVAL,
        "the ftruncate export rejects a negative length");
  Check(FS::KernelFstat(invalid_fd, reinterpret_cast<FS::FileStat*>(1)) ==
            KERNEL_ERROR_EFAULT && FS::KernelFstat(invalid_fd, nullptr) == KERNEL_ERROR_EFAULT,
        "the original fstat export rejects invalid and null outputs");
  Check(Memory::KernelMmap(nullptr, 0x4000, 3, 1, invalid_fd, 0x4000) ==
            reinterpret_cast<void*>(static_cast<intptr_t>(-1)) &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOTSUP,
        "the existing mmap export does not admit an unsupported nonzero offset");
  Check(Memory::KernelMmap(nullptr, 0, 3, 1, invalid_fd, 0) ==
            reinterpret_cast<void*>(static_cast<intptr_t>(-1)) &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
        "zero-length anonymous mmap returns EINVAL");
  Check(Memory::KernelMmap(nullptr, 0x8000, 3, 1, invalid_fd, 0) ==
            reinterpret_cast<void*>(static_cast<intptr_t>(-1)) &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
        "oversize anonymous mmap returns EINVAL");
  Check(Memory::KernelMmap(nullptr, 0x4000, 4, 1, invalid_fd, 0) ==
            reinterpret_cast<void*>(static_cast<intptr_t>(-1)) &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EACCES,
        "executable anonymous mmap returns EACCES");
  Check(Memory::KernelMmap(nullptr, 0x4000, 3, 3, invalid_fd, 0) ==
            reinterpret_cast<void*>(static_cast<intptr_t>(-1)) &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOTSUP,
        "private-plus-shared anonymous mmap is not admitted");
  Check(Memory::KernelMmap(nullptr, 0x4000, 3, 0x18000001, invalid_fd, 0) ==
            reinterpret_cast<void*>(static_cast<intptr_t>(-1)) &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
        "unsupported anonymous alignment flags are not silently ignored");
  Check(FS::KernelShmUnlink(reinterpret_cast<const char*>(1)) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT &&
            FS::KernelClose(invalid_fd) == OK,
        "SHM_ANON cannot be unlinked and its negative fixture closes cleanly");
  FS::KernelUmask(old_umask);
  const auto anon_final = Memory::TestGetAnonymousSharedMemoryStats();
  Check(anon_final.objects == anon_baseline.objects &&
            anon_final.backings == anon_baseline.backings &&
            anon_final.backing_bytes == anon_baseline.backing_bytes &&
            anon_final.mappings == anon_baseline.mappings,
        "all anonymous fixtures leave object, backing and mapping counts unchanged");
  std::printf("SHM_ANON_PRODUCTION_PATH_OK\n");

  auto r = DispatchSyscall({0x1e2, {guest(name), 0x202, 0x1b6, 0, 0, 0}});
  Check(r.value >= 3 && r.posix_errno == 0, "trap shm_open creates the /SceAo2TVCorP block");
  const int fd = static_cast<int>(r.value);
  size_t probe = 0;
  Check(FS::GetSharedMemorySize(fd, &probe) && probe == 0 &&
            FS::IsSharedMemoryNamed(fd, "/SceAo2TVCorP"),
        "the fresh audio-out object is a zero-length Kyty shared descriptor by that name");

  const int64_t sized = 0x6000;
  r = DispatchSyscall({0x1e0, {static_cast<uint64_t>(fd), static_cast<uint64_t>(sized), 0, 0, 0, 0}});
  Check(r.value == 0 && r.posix_errno == 0, "trap ftruncate sizes the audio-out buffer");
  Check(FS::GetSharedMemorySize(fd, &probe) && probe == static_cast<size_t>(sized),
        "the audio-out object is resized to exactly the requested length");

  stat->st_size = -1;
  r = DispatchSyscall({0xbd, {static_cast<uint64_t>(fd), guest(stat), 0, 0, 0, 0}});
  Check(r.value == 0 && stat->st_size == sized, "trap fstat reports the sized audio-out length");

  r = DispatchSyscall({0x1dd, {0, static_cast<uint64_t>(sized), 3, 1, static_cast<uint64_t>(fd), 0}});
  Check(r.value != -1 && r.posix_errno == 0, "trap MAP_SHARED mmap maps the audio-out buffer");
  auto* window = reinterpret_cast<volatile uint32_t*>(static_cast<uintptr_t>(r.value));
  window[0] = 0xa5c30f1e;
  window[(sized / 4) - 1] = 0x5a3cf0e1;
  Check(window[0] == 0xa5c30f1e && window[(sized / 4) - 1] == 0x5a3cf0e1,
        "the mapped audio-out buffer is readable and writable end to end");
  std::printf("SYSAV_AUDIO_SHM_LIFECYCLE_OK size=0x%llx mapped=0x%llx\n",
              static_cast<unsigned long long>(probe),
              static_cast<unsigned long long>(r.value));
  std::fflush(stdout);

  // still goes through KernelFtruncate validation
  r = DispatchSyscall({0x1e0, {static_cast<uint64_t>(fd),
                               static_cast<uint64_t>(-1), 0, 0, 0, 0}});
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_EINVAL,
        "a negative ftruncate length still returns EINVAL through the sizing path");
  const int ro_fd = FS::KernelShmOpen("/SceAo2TVCorP", 0, 0x1b6);
  Check(ro_fd >= 3 && ro_fd != fd, "reopen the same audio-out object read-only");
  r = DispatchSyscall({0x1e0, {static_cast<uint64_t>(ro_fd),
                               static_cast<uint64_t>(sized), 0, 0, 0, 0}});
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_EBADF,
        "a read-only audio-out descriptor cannot be resized");
  r = DispatchSyscall({0x1dd, {0, 0x8000, 3, 1, static_cast<uint64_t>(fd), 0}});
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_EBADF,
        "mapping a length other than the sized one is rejected");

  // any other shm name falls through to the control family and is refused
  const int other_fd = FS::KernelShmOpen("/SceSysAvOtherTest", 0x202, 0x1b6);
  Check(other_fd >= 3, "open an unrelated shared-memory object");
  r = DispatchSyscall({0x1e0, {static_cast<uint64_t>(other_fd),
                               static_cast<uint64_t>(sized), 0, 0, 0, 0}});
  size_t other_probe = 1;
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_ENOSYS &&
            FS::GetSharedMemorySize(other_fd, &other_probe) && other_probe == 0,
        "ftruncate on a non-audio shm descriptor is refused and leaves it unsized");
  std::strcpy(name, "/SceSysAvOtherTest");
  r = DispatchSyscall({0x1e2, {guest(name), 0x202, 0x1b6, 0, 0, 0}});
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_ENOSYS,
        "shm_open of a non-audio path is not claimed by the audio branch");
  std::printf("SYSAV_AUDIO_SHM_NEGATIVES_OK\n");

  // guest names the mapped range with 0x24c after the mmap. r10=1/r8=fd are leftover registers the 3-arg handler ignores, so the fd varies below on purpose.
  std::strcpy(name, "/SceAo2TVCorP");
  void* audio = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&audio, 0x4000, 3, 0, "audio-out-unnamed") == OK,
        "map the audio-out range the naming syscall will tag");
  r = DispatchSyscall({0x24c, {guest(audio), 0x4000, guest(name), 1, static_cast<uint64_t>(fd), 0}});
  Check(r.value == 0 && r.posix_errno == 0, "trap 0x24c names the mapped audio-out range");
  Memory::VirtualQueryInfo named {};
  Check(Memory::KernelVirtualQuery(audio, 0, &named, sizeof(named)) == OK &&
            std::strcmp(named.name, "/SceAo2TVCorP") == 0,
        "the live audio-out range carries the /SceAo2TVCorP name after the syscall");

  r = DispatchSyscall({0x24c, {guest(audio), 0x6000, guest(name), 1, static_cast<uint64_t>(fd), 0}});
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_ENOSYS,
        "a non-0x4000 length is routed away from the audio naming branch");
  r = DispatchSyscall({0x24c, {0xdead0000, 0x4000, guest(name), 1, static_cast<uint64_t>(fd), 0}});
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_EFAULT,
        "naming an unmapped audio target faults through the range check, not the stack-guard fall-through");
  auto* wrong = reinterpret_cast<char*>(page + 0x400);
  std::strcpy(wrong, "/SceAvControl");
  r = DispatchSyscall({0x24c, {guest(audio), 0x4000, guest(wrong), 1, static_cast<uint64_t>(fd), 0}});
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_ENOSYS,
        "a 0x4000 range named with the wrong string is not claimed by the audio branch");

  void* control = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&control, 0x4000, 3, 0, "shared_mmap") == OK,
        "map the control range the original naming branch validates");
  auto* control_name = reinterpret_cast<char*>(page + 0x800);
  std::strcpy(control_name, "/SceAvControl");
  r = DispatchSyscall({0x24c, {guest(control), 0x2000, guest(control_name), 1, 9, 0}});
  Check(r.value == 0 && r.posix_errno == 0, "the 0x2000 control range still names through 0x24c");
  Memory::VirtualQueryInfo control_named {};
  Check(Memory::KernelVirtualQuery(control, 0, &control_named, sizeof(control_named)) == OK &&
            std::strcmp(control_named.name, "/SceAvControl") == 0,
        "the control range carries its /SceAvControl name");
  std::printf("SYSAV_AUDIO_SHM_NAME_OK\n");

  Check(FS::KernelClose(ro_fd) == 0 && FS::KernelClose(other_fd) == 0 &&
            FS::KernelClose(fd) == 0,
        "close every audio-out descriptor");
  std::printf("SYSAV_AUDIO_SHM_CHILD_DONE\n");
  std::fflush(stdout);
  subsystems.Destroy();
  return 0;
#else
  return -1;
#endif
}

void CheckSysAvAudioShm(const std::filesystem::path& root) {
#if defined(_WIN32)
  const auto directory = root / "sysav_audio_shm";
  Check(std::filesystem::create_directory(directory), "create audio-shm fixture directory");
  const auto evidence = directory / "audio_shm_child.log";

  const auto scope = "sa" + std::to_string(GetCurrentProcessId() % 100000) + "_" +
                     std::to_string(GetTickCount64() % 1000000);
  Check(scope.size() < 20, "audio-shm fixture scope fits the registry scope name limit");

  std::wstring executable(32768, L'\0');
  const auto length = GetModuleFileNameW(nullptr, executable.data(),
                                         static_cast<DWORD>(executable.size()));
  Check(length > 0 && length < executable.size(), "locate audio-shm child executable");
  executable.resize(length);
  const std::wstring wscope(scope.begin(), scope.end());
  auto command = L"\"" + executable + L"\" --sysav-audio-shm-child \"" +
                 evidence.native() + L"\" " + wscope;
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  Check(job != nullptr &&
            SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
        "contain audio-shm child in a kill-on-close job");
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process {};
  Check(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup, &process),
        "start isolated audio-shm child");
  if (!AssignProcessToJobObject(job, process.hProcess)) {
    TerminateProcess(process.hProcess, 90);
    WaitForSingleObject(process.hProcess, 1000);
    Check(false, "assign audio-shm child before execution");
  }
  Check(ResumeThread(process.hThread) != DWORD(-1), "start the contained audio-shm child");
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
  Check(!log.IsInvalid(), "open audio-shm child evidence");
  const auto bytes = log.ReadWholeBuffer();
  log.Close();
  const std::string text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  Check(wait == WAIT_OBJECT_0 && status_read && exit_code == 0 &&
            text.find("SYSAV_AUDIO_SHM_CHILD_BEGIN") != std::string::npos &&
            text.find("SYSAV_AUDIO_SHM_LIFECYCLE_OK") != std::string::npos &&
            text.find("SYSAV_AUDIO_SHM_NEGATIVES_OK") != std::string::npos &&
            text.find("SYSAV_AUDIO_SHM_NAME_OK") != std::string::npos &&
            text.find("SYSAV_AUDIO_SHM_CHILD_DONE") != std::string::npos,
        "audio-out shm open/size/stat/map/name lifecycle completes through the trap dispatch");

  // Audiod opens the block from its own process while SysAv is still running
  const auto peer_scope = "sp" + std::to_string(GetCurrentProcessId() % 100000) + "_" +
                          std::to_string(GetTickCount64() % 1000000);
  const HANDLE ready = CreateEventA(nullptr, TRUE, FALSE, ("Local\\" + peer_scope + "_ready").c_str());
  const HANDLE done = CreateEventA(nullptr, TRUE, FALSE, ("Local\\" + peer_scope + "_done").c_str());
  HANDLE peer_job = CreateJobObjectW(nullptr, nullptr);
  Check(ready != nullptr && done != nullptr && peer_job != nullptr &&
            SetInformationJobObject(peer_job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
        "contain both audio-shm peers in one kill-on-close job");
  const auto peer_log = [&](const char* role) { return directory / (std::string("audio_shm_") + role + ".log"); };
  const auto start = [&](const char* role) {
    const std::string tail = peer_scope + " " + role;
    auto line = L"\"" + executable + L"\" --sysav-audio-shm-child \"" + peer_log(role).native() + L"\" " +
                std::wstring(tail.begin(), tail.end());
    STARTUPINFOW peer_startup {};
    peer_startup.cb = sizeof(peer_startup);
    PROCESS_INFORMATION peer {};
    Check(CreateProcessW(executable.c_str(), line.data(), nullptr, nullptr, FALSE,
                         CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &peer_startup, &peer),
          "start an audio-shm peer");
    if (!AssignProcessToJobObject(peer_job, peer.hProcess)) {
      TerminateProcess(peer.hProcess, 90);
      WaitForSingleObject(peer.hProcess, 1000);
      Check(false, "assign the audio-shm peer before execution");
    }
    Check(ResumeThread(peer.hThread) != DWORD(-1), "run the contained audio-shm peer");
    CloseHandle(peer.hThread);
    return peer.hProcess;
  };
  const HANDLE creator = start("create");
  const HANDLE creating[2] = {ready, creator};
  Check(WaitForMultipleObjects(2, creating, FALSE, 15000) == WAIT_OBJECT_0, "the creating peer makes and fills the block");
  const HANDLE opener = start("open");
  const auto opened = WaitForSingleObject(opener, 15000);
  Check(SetEvent(done) != FALSE, "let the creating peer read back and exit");
  const auto finished = WaitForSingleObject(creator, 15000);
  if (opened != WAIT_OBJECT_0 || finished != WAIT_OBJECT_0) {
    TerminateJobObject(peer_job, 126);
    WaitForSingleObject(opener, 5000);
    WaitForSingleObject(creator, 5000);
  }
  DWORD creator_exit = 0xffffffffu;
  DWORD opener_exit = 0xffffffffu;
  GetExitCodeProcess(creator, &creator_exit);
  GetExitCodeProcess(opener, &opener_exit);
  CloseHandle(creator);
  CloseHandle(opener);
  CloseHandle(peer_job);
  CloseHandle(ready);
  CloseHandle(done);
  const auto peer_text = [&](const char* role) {
    Common::File peer_file(peer_log(role), Common::File::Mode::Read);
    Check(!peer_file.IsInvalid(), "open audio-shm peer evidence");
    const auto peer_bytes = peer_file.ReadWholeBuffer();
    peer_file.Close();
    return std::string(reinterpret_cast<const char*>(peer_bytes.data()), peer_bytes.size());
  };
  const auto created_text = peer_text("create");
  const auto opened_text = peer_text("open");
  const auto scope_tag = [](const std::string& peer, const std::string& line) {
    const auto at = peer.find("FIRST_FRAME_AUDIT SCOPE_SHM_OPEN " + line);
    const auto scope = at == std::string::npos ? at : peer.find(" scope=", at);
    return scope == std::string::npos ? std::string() : peer.substr(scope + 7, 8);
  };
  const auto object_index = [](const std::string& peer, const std::string& line) {
    const auto at = peer.find("FIRST_FRAME_AUDIT SCOPE_SHM_OPEN " + line);
    const auto object = at == std::string::npos ? at : peer.find(" object=", at);
    const auto end = object == std::string::npos ? object : peer.find(' ', object + 8);
    return end == std::string::npos ? std::string() : peer.substr(object + 8, end - object - 8);
  };
  const auto creator_line = "outcome=created name=/SceAo2TVCorP flags=0x200202 ";
  const auto opener_line = "outcome=opened name=/SceAo2TVCorP flags=0x2 ";
  const auto creator_tag = scope_tag(created_text, creator_line);
  const auto opener_tag = scope_tag(opened_text, opener_line);
  const auto creator_object = object_index(created_text, creator_line);
  const auto opener_object = object_index(opened_text, opener_line);
  Check(opened == WAIT_OBJECT_0 && finished == WAIT_OBJECT_0 && creator_exit == 0 && opener_exit == 0 &&
            created_text.find("SYSAV_AUDIO_SHM_PEER_CREATED") != std::string::npos &&
            created_text.find("SYSAV_AUDIO_SHM_PEER_READBACK_OK") != std::string::npos &&
            opened_text.find("SYSAV_AUDIO_SHM_PEER_OPENED") != std::string::npos &&
            opened_text.find("name=/SceAo2TVCorQ") == std::string::npos &&
            opened_text.find("outcome=created") == std::string::npos &&
            opened_text.find("scope memory: opened ") != std::string::npos &&
            creator_tag.size() == 8 && creator_tag == opener_tag &&
            !creator_object.empty() && creator_object == opener_object,
        "a second process in the scope opens, maps and writes the block the first one created, and both audit lines carry the same scope tag");
  std::printf("SysAvAudioShmTests: ftruncate_size=pass fstat_size=pass map_shared=pass "
              "invalid_length=pass readonly_ebadf=pass map_length_check=pass routing_gate=pass "
              "range_name=pass name_readback=pass control_name_preserved=pass cross_process_open=pass "
              "cross_process_bytes=pass scope_tag=pass\n");
#endif
}
