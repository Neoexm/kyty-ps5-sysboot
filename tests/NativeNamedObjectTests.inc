void CheckNativeNamedObjects() {
#if defined(_WIN32)
  RegistryTrapEnvironment environment;
  Check(_putenv_s("KYTY_DIAGNOSTIC_MINI_SYSCORE_NATIVE_TRAPS", "1") == 0 &&
        _putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1") == 0,
        "enable native named object dispatch");
  namespace Kernel = Libs::LibKernel;
  namespace Bridge = Libs::NativeKernelBridge;
  void* storage = nullptr;
  Check(Kernel::Memory::KernelMapNamedFlexibleMemory(&storage, 0x4000, 3, 0, "named-object-test") == OK,
        "allocate guest named object input");
  const auto name = reinterpret_cast<uint64_t>(storage);
  std::memcpy(storage, "SceAvControlSplash", sizeof("SceAvControlSplash"));
  const int fd = FileSystem::CreateNativeKqueueDescriptor();
  int64_t queue = 0;
  Check(fd >= 3 && FileSystem::ResolveNativeKqueueDescriptor(fd, &queue),
        "create guest queue for naming");
  const auto created = Bridge::DispatchSyscall({0x22d, {name, static_cast<uint64_t>(fd), 0x107}});
  Check(created.value > 0 && created.posix_errno == 0,
        "named equeue stores an opaque descriptor word");
  Kernel::EventQueue::KernelEvent event {};
  Kernel::KernelUseconds timeout = 0;
  int count = -1;
  Check(Kernel::EventQueue::KernelWaitEqueue(queue, &event, 1, &count, &timeout) == Kernel::KERNEL_ERROR_ETIMEDOUT && count == 0,
        "naming a queue does not synthesize an event");
  const auto id = static_cast<uint64_t>(created.value);
  {
    Kernel::Process::ScopedGuestProcessPid other(8765);
    const auto denied = Bridge::DispatchSyscall({0x22e, {id, 0x107}});
    Check(denied.value == -1 && denied.posix_errno == Libs::Posix::POSIX_ESRCH,
          "named records are private to their guest process");
  }
  const auto wrong_type = Bridge::DispatchSyscall({0x22e, {id, 0x101}});
  Check(wrong_type.value == -1 && wrong_type.posix_errno == Libs::Posix::POSIX_ESRCH,
        "named object deletion validates the stored type");
  const auto deleted = Bridge::DispatchSyscall({0x22e, {id, 0x107}});
  Check(deleted.value == 0 && FileSystem::ResolveNativeKqueueDescriptor(fd, &queue),
        "deleting the name leaves the original queue descriptor alive");
  const auto stale = Bridge::DispatchSyscall({0x22e, {id, 0x107}});
  Check(stale.value == -1 && stale.posix_errno == Libs::Posix::POSIX_ESRCH,
        "deleted named object identifiers stay invalid");
  const auto opaque = Bridge::DispatchSyscall({0x22d, {name, UINT64_MAX, 0x10000101}});
  Check(opaque.value > 0 && Bridge::DispatchSyscall({0x22e, {static_cast<uint64_t>(opaque.value), 0x101}}).value == 0,
        "kernel named objects retain raw words and normalize the sixteen bit type");
  const auto null_name = Bridge::DispatchSyscall({0x22d, {0, 0, 0x107}});
  Check(null_name.value == -1 && null_name.posix_errno == Libs::Posix::POSIX_EINVAL,
        "null names use the recovered kernel EINVAL result");
  std::memset(storage, 'n', 32);
  static_cast<char*>(storage)[32] = 0;
  const auto long_name = Bridge::DispatchSyscall({0x22d, {name, 0, 0x107}});
  Check(long_name.value == -1 && long_name.posix_errno == Libs::Posix::POSIX_ENAMETOOLONG,
        "named objects enforce the recovered thirty two byte copy limit");
  static_cast<char*>(storage)[31] = 0;
  const auto bounded = Bridge::DispatchSyscall({0x22d, {name, 0, 0x107}});
  Check(bounded.value > 0 && Bridge::DispatchSyscall({0x22e, {static_cast<uint64_t>(bounded.value), 0x107}}).value == 0,
        "thirty one byte names and zero object words are valid");
  std::strcpy(static_cast<char*>(storage), "NativeHandleKinds");
  const auto flag = Bridge::DispatchSyscall({0x21a, {name, 0x121, 0}});
  const auto alias = Bridge::DispatchSyscall({0x21c, {name}});
  Check(flag.value > 0 && alias.value > 0 && flag.value != alias.value,
        "native event create and open receive separate handle identities");
  const auto wrong_delete = Bridge::DispatchSyscall({0x21b, {static_cast<uint64_t>(alias.value)}});
  const auto wrong_close = Bridge::DispatchSyscall({0x21d, {static_cast<uint64_t>(flag.value)}});
  Check(wrong_delete.value == -1 && wrong_delete.posix_errno == Libs::Posix::POSIX_EPERM &&
        wrong_close.value == -1 && wrong_close.posix_errno == Libs::Posix::POSIX_EPERM,
        "native event delete and close preserve recovered owner versus open permissions");
  Check(Bridge::DispatchSyscall({0x220, {static_cast<uint64_t>(alias.value), 2}}).value == 0 &&
        Bridge::DispatchSyscall({0x21d, {static_cast<uint64_t>(alias.value)}}).value == 0 &&
        Bridge::DispatchSyscall({0x21b, {static_cast<uint64_t>(flag.value)}}).value == 0,
        "failed native owner operations preserve both event handles for later use");
  Check(FileSystem::KernelClose(fd) == OK &&
        Kernel::Memory::KernelMunmap(name, 0x4000) == OK,
        "release queue and guest test storage");
  std::printf("NativeNamedObjectTests: opaque word, type, owner, name bounds and queue lifetime passed\n");
#endif
}
