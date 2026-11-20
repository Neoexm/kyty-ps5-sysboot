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
  const char* guard_flag = std::getenv("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS");
  const char* equeue_flag = std::getenv("KYTY_DIAGNOSTIC_SYSCORE_EQUEUE_FD");
  const std::string saved_guard_flag = guard_flag ? guard_flag : "";
  const std::string saved_equeue_flag = equeue_flag ? equeue_flag : "";
  NativeAvTest::Environment::Set("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS", "");
  NativeAvTest::Environment::Set("KYTY_DIAGNOSTIC_SYSCORE_EQUEUE_FD", "1");
  Loader::SymbolDatabase direct_symbols;
  Libs::NativeSyscallGuards::Register(&direct_symbols);
  const auto* direct_kevent = direct_symbols.Find({"RW-GEfpnsqg", "libkernel", 1,
                                                  "libkernel", 1, 1, Loader::SymbolType::Func});
  Check(direct_kevent != nullptr &&
            direct_kevent->vaddr == reinterpret_cast<uint64_t>(&Libs::NativeSyscallGuards::NativeKevent),
        "early library registration binds direct kevent to the process-aware wrapper");
  NativeAvTest::Environment::Set("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS", saved_guard_flag.c_str());
  NativeAvTest::Environment::Set("KYTY_DIAGNOSTIC_SYSCORE_EQUEUE_FD", saved_equeue_flag.c_str());
  const char* mini_flag = std::getenv("KYTY_DIAGNOSTIC_MINI_SYSCORE_NATIVE_TRAPS");
  const std::string saved_mini_flag = mini_flag ? mini_flag : "";
  NativeAvTest::Environment::Set("KYTY_DIAGNOSTIC_MINI_SYSCORE_NATIVE_TRAPS", "1");
  const int direct_fd = static_cast<int>(Libs::NativeSyscallGuards::NativeKqueue(0, 0, 0, 0, 0, 0));
  Check(direct_fd >= 3, "direct kqueue import creates a guest-backed descriptor");
  changes[0] = {0, EQ::KERNEL_EVFILT_TIMER, 0x5, 0, 16, reinterpret_cast<void*>(123)};
  Check(Libs::NativeSyscallGuards::NativeKevent(direct_fd, address(changes), 1, 0, 0, 0) == 0,
        "direct kevent import registers an observed 16 ms timer");
  *timeout = {0, 250000000};
  const int first_tick = static_cast<int>(Libs::NativeSyscallGuards::NativeKevent(
      direct_fd, 0, 0, address(output), 1, address(timeout)));
  const int second_tick = static_cast<int>(Libs::NativeSyscallGuards::NativeKevent(
      direct_fd, 0, 0, address(output + 1), 1, address(timeout)));
  Check(first_tick == 1 && second_tick == 1 && output->ident == 0 &&
            output->filter == EQ::KERNEL_EVFILT_TIMER && output->data >= 1 &&
            output->udata == reinterpret_cast<void*>(123) && output[1].ident == 0 &&
            output[1].filter == EQ::KERNEL_EVFILT_TIMER && output[1].data >= 1,
        "direct kevent timer wakes twice from elapsed intervals");
  changes[0].data = 0;
  Check(Libs::NativeSyscallGuards::NativeKevent(direct_fd, address(changes), 1, 0, 0, 0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOSYS &&
            FileSystem::KernelClose(direct_fd) == OK,
        "invalid direct timer is rejected and its descriptor closes");
  NativeAvTest::Environment::Set("KYTY_DIAGNOSTIC_MINI_SYSCORE_NATIVE_TRAPS", saved_mini_flag.c_str());
  int first[2] {-1, -1}, second[2] {-1, -1};
  Check(FileSystem::CreateGuestSocketPair(first) == OK && FileSystem::CreateGuestSocketPair(second) == OK,
        "create native kevent safety socket sources");
  namespace Net = Libs::Network::Net;
  const std::array<const char*, 2> socket_keys {{
      "KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET", "KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE"}};
  std::array<std::string, 2> saved_socket_values;
  for (size_t i = 0; i < socket_keys.size(); ++i) {
    const char* value = std::getenv(socket_keys[i]);
    saved_socket_values[i] = value ? value : "";
  }
  const auto socket_scope = "nk" + std::to_string(GetCurrentProcessId()) + "_" +
      std::to_string(GetTickCount64() % 1000000);
  Check(socket_scope.size() <= 20 && _putenv_s(socket_keys[0], "1") == 0 &&
            _putenv_s(socket_keys[1], socket_scope.c_str()) == 0,
        "select an isolated native kevent socket scope");
  std::array<uint8_t, 106> redis_address {};
  redis_address[1] = 1;
  constexpr char redis_name[] = "/system_tmp/redis.sock";
  std::memcpy(redis_address.data() + 2, redis_name, sizeof(redis_name));
  const int listener = Net::Socket(1, 1, 0);
  int reuse = 1;
  Check(listener >= 0 && Net::Setsockopt(listener, 0xffff, 4, &reuse, sizeof(reuse)) == 0 &&
            Net::SetLocalSocketPolicy(listener, 1) == 0 &&
            Net::Bind(listener, redis_address.data(), redis_address.size()) == 0 &&
            Net::Listen(listener, 4) == 0,
        "create Redis's listening AF_UNIX socket before native read registration");
  const int socket_queue = FileSystem::CreateNativeKqueueDescriptor();
  Check(socket_queue >= 3, "create native queue for Redis's listener");
  changes[0] = {static_cast<uintptr_t>(listener), EQ::KERNEL_EVFILT_READ, 1, 0, 0,
                reinterpret_cast<void*>(321)};
  *timeout = {0, 0};
  const auto registered_socket = add(socket_queue, 1);
  Check(registered_socket.value == 0 && registered_socket.posix_errno == 0 &&
            poll(socket_queue, output).value == 0,
        "native kevent registers the real AF_UNIX listener without early readiness");
  for (int attempt = 0; attempt < 2; ++attempt) {
    const int client = Net::Socket(1, 1, 0);
    Check(client >= 0 && Net::Connect(client, redis_address.data(), redis_address.size()) == 0,
          "connect a real client to the native watched Redis listener");
    *timeout = {2, 0};
    const auto ready = poll(socket_queue, output);
    Check(ready.value == 1 && ready.posix_errno == 0 && output->ident == static_cast<uintptr_t>(listener) &&
              output->filter == EQ::KERNEL_EVFILT_READ && output->udata == reinterpret_cast<void*>(321),
          "native kevent reports real AF_UNIX listener readiness");
    const int accepted = Net::Accept(listener, nullptr, nullptr);
    *timeout = {0, 0};
    Check(accepted >= 0 && poll(socket_queue, output).value == 0 &&
              Net::SocketClose(accepted) == 0 && Net::SocketClose(client) == 0,
          "accept clears listener readiness and leaves registration armed");
  }
  Check(FileSystem::KernelClose(socket_queue) == OK && Net::SocketClose(listener) == 0,
        "close native queue and Redis listener after the second readiness event");
  char temp_dir[MAX_PATH] {};
  Check(GetTempPathA(MAX_PATH, temp_dir) != 0, "locate native kevent fixture sidecar");
  const auto policy_path = std::filesystem::path(temp_dir) /
      ("kyty_ps5_" + socket_scope + "_redis.sock.policy");
  std::error_code socket_cleanup;
  std::filesystem::remove(policy_path, socket_cleanup);
  Check(!socket_cleanup, "remove closed native kevent fixture sidecar");
  for (size_t i = 0; i < socket_keys.size(); ++i)
    Check(_putenv_s(socket_keys[i], saved_socket_values[i].c_str()) == 0,
          "restore native kevent socket scope");
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
  changes[0] = {1, EQ::KERNEL_EVFILT_NOTIFY, 0x5, 0, 20, reinterpret_cast<void*>(125)};
  Check(add(fd, 1).value == 0 &&
            EQ::KernelTriggerEvent(queue, 1, EQ::KERNEL_EVFILT_NOTIFY, reinterpret_cast<void*>(19)) == OK &&
            poll(fd, output).value == 0 &&
            EQ::KernelTriggerEvent(queue, 1, EQ::KERNEL_EVFILT_NOTIFY, reinterpret_cast<void*>(20)) == OK,
        "EV_ADD plus EV_ENABLE registers selector20 without a synthetic event");
  result = poll(fd, output);
  Check(result.value == 1 && output->ident == 1 && output->filter == EQ::KERNEL_EVFILT_NOTIFY &&
            output->flags == 0x20 && output->data == 20 &&
            output->udata == reinterpret_cast<void*>(125) && poll(fd, output).value == 0 &&
            EQ::KernelDeleteEvent(queue, 1, EQ::KERNEL_EVFILT_NOTIFY) == OK,
        "enabled native NOTIFY fires only for its matching original hint");

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
  std::printf("NativeKeventSafetyTests: socket_read=pass generic_counts=pass user_fields=pass clear=pass action_flags=pass "
              "user_replace=pass notify_hint=pass notify_replace=pass notify_zero=pass "
              "invalid_timespec=pass finite_1ns=pass wait_protect=pass wait_unmap=pass\n");
#endif
}
