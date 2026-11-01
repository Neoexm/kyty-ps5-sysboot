void CheckNativeKeventSafety() {
#if defined(_WIN32)
  namespace EQ = Libs::LibKernel::EventQueue;
  using namespace Libs::LibKernel;
  using Libs::NativeKernelBridge::DispatchSyscall;
  NativeAvTest::Environment environment;
  NativeAvTest::Environment::Set("KYTY_DIAGNOSTIC_GUEST_EXECVE", "1");
  NativeAvTest::Environment::Set("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1");
  NativeAvTest::Environment::Set("KYTY_DIAGNOSTIC_SYSAV_AV_DEVICE_PROBE", "");
  FileSystem::ScopedGuestDescriptorTable descriptors;
  void* memory = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&memory, 0x4000, 3, 0, "native-kevent-safety") == OK,
        "map native kevent safety fixture");
  auto* bytes = static_cast<uint8_t*>(memory);
  auto* changes = reinterpret_cast<EQ::KernelEvent*>(bytes);
  auto* output = reinterpret_cast<EQ::KernelEvent*>(bytes + 0x400);
  auto* timeout = reinterpret_cast<KernelTimespec*>(bytes + 0x800);
  const auto address = [](const void* p) { return reinterpret_cast<uint64_t>(p); };
  const auto add = [&](int fd, uint64_t count) {
    return DispatchSyscall({0x16b, {static_cast<uint64_t>(fd), address(changes), count, 0, 0, 0}});
  };
  const auto poll = [&](int fd, EQ::KernelEvent* result) {
    return DispatchSyscall({0x16b, {static_cast<uint64_t>(fd), 0, 0, address(result), 1, address(timeout)}});
  };
  int first[2] {-1, -1}, second[2] {-1, -1};
  Check(FileSystem::CreateGuestSocketPair(first) == OK && FileSystem::CreateGuestSocketPair(second) == OK,
        "create native kevent safety socket sources");
  const int mbus = FileSystem::KernelOpen("/dev/mbus_av", 2, 0);
  Check(mbus >= 3, "open native kevent safety MBus source");
  for (uint64_t count : {uint64_t {1}, uint64_t {2}, uint64_t {5}}) {
    const int fd = FileSystem::CreateNativeKqueueDescriptor();
    Check(fd >= 3, "create arbitrary native registration queue");
    std::memset(changes, 0, 5 * sizeof(*changes));
    changes[0] = {1, EQ::KERNEL_EVFILT_NOTIFY, 1, 0, 16, reinterpret_cast<void*>(123)};
    changes[1] = {1, EQ::KERNEL_EVFILT_USER, 0x21, 0, 77, reinterpret_cast<void*>(88)};
    const int watched[3] {first[1], second[1], mbus};
    for (int i = 0; i < 3; ++i)
      changes[i + 2] = {static_cast<uintptr_t>(watched[i]), EQ::KERNEL_EVFILT_READ, 1, 0, 0, nullptr};
    *timeout = {0, 0};
    const auto registered = add(fd, count);
    const auto empty = poll(fd, output);
    Check(registered.value == 0 && registered.posix_errno == 0 && empty.value == 0 && empty.posix_errno == 0,
          "one, two and five native changes register without signalling readiness");
    Check(FileSystem::KernelClose(fd) == OK, "close arbitrary native registration queue");
  }

  const int fd = FileSystem::CreateNativeKqueueDescriptor();
  EQ::KernelEqueue queue = EQ::KERNEL_EQUEUE_INVALID;
  Check(fd >= 3 && FileSystem::ResolveNativeKqueueDescriptor(fd, &queue), "create native USER safety queue");
  changes[0] = {1, EQ::KERNEL_EVFILT_USER, 0x21, 0, 77, reinterpret_cast<void*>(88)};
  Check(add(fd, 1).value == 0, "register native USER with original data and udata");
  for (int repeat = 0; repeat < 2; ++repeat) {
    Check(EQ::KernelTriggerUserEvent(queue, 1, reinterpret_cast<void*>(999)) == OK,
          "explicitly trigger the offline native USER fixture");
    *timeout = {0, 0};
    const auto ready = poll(fd, output);
    Check(ready.value == 1 && ready.posix_errno == 0 && output->ident == 1 &&
              output->filter == EQ::KERNEL_EVFILT_USER && output->data == 77 &&
              output->udata == reinterpret_cast<void*>(88) && output->fflags == 0 && output->flags == 0x20,
          "native USER preserves saved data77 and udata88 and strips EV_ADD from output");
    Check(poll(fd, output).value == 0, "EV_CLEAR consumes only the explicit native USER trigger");
  }
  changes[0].data = 78;
  changes[0].udata = reinterpret_cast<void*>(89);
  Check(add(fd, 1).value == 0 && EQ::KernelTriggerUserEvent(queue, 1, nullptr) == OK,
        "re-register native USER with updated saved fields");
  auto result = poll(fd, output);
  Check(result.value == 1 && output->data == 78 && output->udata == reinterpret_cast<void*>(89) &&
            poll(fd, output).value == 0,
        "native USER re-registration replaces saved data and udata");

  changes[0] = {1, EQ::KERNEL_EVFILT_NOTIFY, 1, 0, 16, reinterpret_cast<void*>(123)};
  Check(add(fd, 1).value == 0, "register original native NOTIFY selector16");
  Check(EQ::KernelTriggerEvent(queue, 1, EQ::KERNEL_EVFILT_NOTIFY, reinterpret_cast<void*>(17)) == OK &&
            poll(fd, output).value == 0,
        "native NOTIFY rejects a mismatched fixture hint");
  constexpr uintptr_t hint = UINT64_C(0x010200000000ab10);
  Check(EQ::KernelTriggerEvent(queue, 1, EQ::KERNEL_EVFILT_NOTIFY, reinterpret_cast<void*>(hint)) == OK,
        "deliver an explicit native NOTIFY fixture hint");
  result = poll(fd, output);
  Check(result.value == 1 && output->ident == 1 && output->filter == EQ::KERNEL_EVFILT_NOTIFY &&
            output->flags == 0x20 && output->fflags == 0 &&
            static_cast<uintptr_t>(output->data) == (hint & UINT64_C(0xffffffffffff00ff)) &&
            output->udata == reinterpret_cast<void*>(123) && poll(fd, output).value == 0,
        "native NOTIFY retains high hint bits, masks byte1 and clears after delivery");
  changes[0].data = 17;
  changes[0].udata = reinterpret_cast<void*>(124);
  Check(add(fd, 1).value == 0 &&
            EQ::KernelTriggerEvent(queue, 1, EQ::KERNEL_EVFILT_NOTIFY, reinterpret_cast<void*>(16)) == OK &&
            poll(fd, output).value == 0 &&
            EQ::KernelTriggerEvent(queue, 1, EQ::KERNEL_EVFILT_NOTIFY, reinterpret_cast<void*>(17)) == OK,
        "native NOTIFY re-registration replaces the selector");
  result = poll(fd, output);
  Check(result.value == 1 && output->data == 17 && output->udata == reinterpret_cast<void*>(124) &&
            poll(fd, output).value == 0,
        "native NOTIFY reports only its new selector and udata");
  changes[0].data = 0;
  Check(add(fd, 1).value == 0 &&
            EQ::KernelTriggerEvent(queue, 1, EQ::KERNEL_EVFILT_NOTIFY, reinterpret_cast<void*>(0x120000)) == OK,
        "native NOTIFY selector zero accepts a nonzero matching hint");
  result = poll(fd, output);
  Check(result.value == 1 && output->data == 0x120000 &&
            EQ::KernelDeleteEvent(queue, 1, EQ::KERNEL_EVFILT_NOTIFY) == OK,
        "native NOTIFY distinguishes selector zero from a zero poll hint");

  for (const KernelTimespec invalid : {KernelTimespec {-1, 0}, KernelTimespec {0, -1},
                                     KernelTimespec {0, 1000000000}, KernelTimespec {4294967295LL, 0}}) {
    *timeout = invalid;
    const auto result = poll(fd, output);
    Check(result.value == -1 && result.posix_errno == Libs::Posix::POSIX_EINVAL,
          "invalid native kevent timespec returns EINVAL");
  }
  result = DispatchSyscall({0x16b, {static_cast<uint64_t>(fd), 0, 0, address(output), 1, 0x1000}});
  Check(result.value == -1 && result.posix_errno == Libs::Posix::POSIX_EFAULT,
        "unmapped native timespec returns EFAULT");
  *timeout = {0, 0};
  result = DispatchSyscall({0x16b, {static_cast<uint64_t>(fd), 0, 0, 0x1000, 1, address(timeout)}});
  Check(result.value == -1 && result.posix_errno == Libs::Posix::POSIX_EFAULT,
        "unmapped native event list returns EFAULT");

  std::atomic<bool> completed {false};
  std::atomic<bool> fallback_triggered {false};
  std::thread fallback([&] {
    const auto bound = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (!completed.load() && std::chrono::steady_clock::now() < bound)
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    if (!completed.load()) {
      fallback_triggered.store(true);
      EQ::KernelTriggerUserEvent(queue, 1, nullptr);
    }
  });
  *timeout = {0, 1};
  const auto started = std::chrono::steady_clock::now();
  result = poll(fd, output);
  const auto elapsed = std::chrono::steady_clock::now() - started;
  completed.store(true);
  fallback.join();
  Check(result.value == 0 && result.posix_errno == 0 && !fallback_triggered.load() &&
            elapsed < std::chrono::milliseconds(500),
        "one-nanosecond native timeout is finite and does not wait for a producer");

  for (bool unmap : {false, true}) {
    void* destination = nullptr;
    Check(Memory::KernelMapNamedFlexibleMemory(&destination, 0x4000, 3, 0, "native-kevent-race") == OK,
          "map an event list for blocked-wait invalidation");
    completed.store(false);
    std::atomic<bool> invalidated_while_pending {false};
    std::atomic<int> mutation_status {KERNEL_ERROR_EFAULT}, trigger_status {KERNEL_ERROR_EFAULT};
    std::thread invalidate([&] {
      std::this_thread::sleep_for(std::chrono::milliseconds(40));
      invalidated_while_pending.store(!completed.load());
      mutation_status.store(unmap ? Memory::KernelMunmap(address(destination), 0x4000)
                                  : Memory::KernelMprotect(destination, 0x4000, 1));
      trigger_status.store(EQ::KernelTriggerUserEvent(queue, 1, nullptr));
    });
    *timeout = {2, 0};
    result = poll(fd, static_cast<EQ::KernelEvent*>(destination));
    completed.store(true);
    invalidate.join();
    Check(invalidated_while_pending.load() && mutation_status.load() == OK && trigger_status.load() == OK &&
              result.value == -1 && result.posix_errno == Libs::Posix::POSIX_EFAULT,
          "native kevent safely returns EFAULT when its output is protected or unmapped during a wait");
    if (!unmap) {
      Check(Memory::KernelMprotect(destination, 0x4000, 3) == OK &&
                Memory::KernelMunmap(address(destination), 0x4000) == OK,
            "restore and release the protected event list");
    }
    *timeout = {0, 0};
    Check(poll(fd, output).value == 0, "failed native copyout leaves no stale USER trigger");
  }

  Check(EQ::KernelDeleteEvent(queue, 1, EQ::KERNEL_EVFILT_USER) == OK && FileSystem::KernelClose(fd) == OK &&
            FileSystem::KernelClose(first[0]) == OK && FileSystem::KernelClose(first[1]) == OK &&
            FileSystem::KernelClose(second[0]) == OK && FileSystem::KernelClose(second[1]) == OK &&
            FileSystem::KernelClose(mbus) == OK && Memory::KernelMunmap(address(memory), 0x4000) == OK,
        "release native kevent safety fixtures");
  std::printf("NativeKeventSafetyTests: generic_counts=pass user_fields=pass clear=pass action_flags=pass "
              "user_replace=pass notify_hint=pass notify_replace=pass notify_zero=pass "
              "invalid_timespec=pass finite_1ns=pass wait_protect=pass wait_unmap=pass\n");
#endif
}
