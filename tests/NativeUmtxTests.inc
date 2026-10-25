void CheckNativeUmtxStartupWake() {
#if defined(_WIN32)
  namespace Kernel = Libs::LibKernel;
  namespace Bridge = Libs::NativeKernelBridge;
  const char* configured = std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS");
  const std::string saved = configured == nullptr ? "" : configured;
  Check(_putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1") == 0,
        "select native mutex dispatch for host fixture");
  void* storage = reinterpret_cast<void*>(0x200000000ull);
  Check(Kernel::Memory::KernelMapNamedFlexibleMemory(&storage, 0x4000, 3, 0x90, "native-umtx-test") == OK &&
        storage == reinterpret_cast<void*>(0x200000000ull),
        "map a fresh guest startup mutex without replacing existing memory");
  auto* words = reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(storage) + 0xa80);
  std::atomic_ref<uint32_t> owner(words[0]);
  words[1] = 0x400;
  const auto wake = [&] {
    return Bridge::DispatchSyscall({0x1c6, {0x200000a80ull, 23, 0x400, 0, 0, 0x1010002}});
  };
  for (unsigned iteration = 0; iteration < 64; ++iteration) {
    owner.store(0x1234, std::memory_order_release);
    auto waiter = std::async(std::launch::async, [] {
      return Bridge::DispatchSyscall({0x1c6, {0x200000a80ull, 17, 0, 0, 0, 0x1010002}});
    });
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!(owner.load(std::memory_order_acquire) & 0x80000000u)) {
      Check(std::chrono::steady_clock::now() < deadline,
            "native mutex waiter reaches contested state");
      std::this_thread::yield();
    }
    if (iteration & 1u) {
      owner.store(0x4567, std::memory_order_release);
      const auto preserved = wake();
      Check(preserved.value == 0 && preserved.posix_errno == 0 &&
            (owner.load(std::memory_order_acquire) & 0x7fffffffu) == 0x4567 &&
            waiter.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready,
            "wake preserves a replacement owner and does not release its blocked contender");
    }
    owner.store(0, std::memory_order_release);
    const auto notified = wake();
    Check(notified.value == 0 && notified.posix_errno == 0 &&
          waiter.wait_for(std::chrono::seconds(5)) == std::future_status::ready,
          "the startup mutex wake notifies a queued waiter");
    const auto result = waiter.get();
    Check(result.value == 0 && result.posix_errno == 0 &&
          (owner.load(std::memory_order_acquire) & 0x7fffffffu) == 0,
          "native wait returns after unlock without granting guest ownership");
  }
  owner.store(0x1234, std::memory_order_release);
  const auto unknown = Bridge::DispatchSyscall({0x1c6,
      {0x200000a80ull, 23, 0x400, 0, 0, 0xdeadbeef}});
  Check(unknown.value == -1 && unknown.posix_errno == Libs::Posix::POSIX_ENOSYS &&
        owner.load(std::memory_order_acquire) == 0x1234,
        "unverified startup mutex tuples remain unsupported and untouched");
  const auto contested = [](std::atomic_ref<uint32_t>& word, const char* what) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!(word.load(std::memory_order_acquire) & 0x80000000u)) {
      Check(std::chrono::steady_clock::now() < deadline, what);
      std::this_thread::yield();
    }
  };

  // A waiter woken by op 23 can lose the mutex to a fast-path relock before it re-reads the word; it has to put CONTESTED back or the relocker unlocks without a wake.
  unsigned resleeps = 0;
  for (unsigned iteration = 0; iteration < 64; ++iteration) {
    owner.store(0x1234, std::memory_order_release);
    auto waiter = std::async(std::launch::async, [] {
      return Bridge::DispatchSyscall({0x1c6, {0x200000a80ull, 17, 0, 0, 0, 0x1010002}});
    });
    contested(owner, "relock waiter reaches contested state");
    owner.store(0, std::memory_order_release);
    Check(wake().value == 0, "wake the queued startup mutex waiter");
    owner.store(0x5555, std::memory_order_release);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (waiter.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready &&
           !(owner.load(std::memory_order_acquire) & 0x80000000u)) {
      Check(std::chrono::steady_clock::now() < deadline,
            "a woken waiter either returns or re-asserts contention on the relocked word");
      std::this_thread::yield();
    }
    if (waiter.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
      ++resleeps;
      Check(owner.load(std::memory_order_acquire) == 0x80005555u,
            "the re-sleeping waiter keeps the relocking owner and marks it contested");
      owner.store(0, std::memory_order_release);
      Check(wake().value == 0, "the relocking owner's contested unlock wakes the waiter again");
    }
    Check(waiter.wait_for(std::chrono::seconds(5)) == std::future_status::ready && waiter.get().value == 0,
          "relock waiter eventually returns");
  }

  auto* second = reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(storage) + 0x980);
  std::atomic_ref<uint32_t> second_owner(second[0]);
  second[1] = 0x400;
  second_owner.store(0x2222, std::memory_order_release);
  auto second_waiter = std::async(std::launch::async, [] {
    return Bridge::DispatchSyscall({0x1c6, {0x200000980ull, 17, 0, 0, 0, 0xff010100u}});
  });
  contested(second_owner, "second mutex waiter reaches contested state");
  second_owner.store(0, std::memory_order_release);
  const auto second_wake = Bridge::DispatchSyscall({0x1c6, {0x200000980ull, 23, 0x400, 0, 0, 0xff010100u}});
  Check(second_wake.value == 0 && second_waiter.wait_for(std::chrono::seconds(5)) == std::future_status::ready &&
        second_waiter.get().value == 0,
        "the op 23 tuple wakes the second waiter");

  // other mutexes need the object's own m_flags and the id at +0x3c
  auto* third = reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(storage) + 0xb40);
  std::atomic_ref<uint32_t> third_owner(third[0]);
  third[1] = 0x400;
  third[15] = 0x1010004;
  third_owner.store(0x3333, std::memory_order_release);
  const auto wrong_wait = Bridge::DispatchSyscall({0x1c6, {0x200000b40ull, 17, 0, 0, 0, 0x1010005}});
  const auto wrong_flags = Bridge::DispatchSyscall({0x1c6, {0x200000b40ull, 23, 0, 0, 0, 0x1010004}});
  const auto wrong_id = Bridge::DispatchSyscall({0x1c6, {0x200000b40ull, 23, 0x400, 0, 0, 0x1010005}});
  third[1] = 0x404;
  const auto inherit = Bridge::DispatchSyscall({0x1c6, {0x200000b40ull, 17, 0, 0, 0, 0x1010004}});
  third[1] = 0x400;
  Check(wrong_wait.posix_errno == Libs::Posix::POSIX_ENOSYS && wrong_flags.posix_errno == Libs::Posix::POSIX_ENOSYS &&
        wrong_id.posix_errno == Libs::Posix::POSIX_ENOSYS && inherit.posix_errno == Libs::Posix::POSIX_ENOSYS &&
        third_owner.load(std::memory_order_acquire) == 0x3333,
        "mutex tuples that do not match the object's own flags and id stay unsupported");
  auto third_waiter = std::async(std::launch::async, [] {
    return Bridge::DispatchSyscall({0x1c6, {0x200000b40ull, 17, 0, 0, 0, 0x1010004}});
  });
  contested(third_owner, "self-identified mutex waiter reaches contested state");
  third_owner.store(0, std::memory_order_release);
  const auto third_wake = Bridge::DispatchSyscall({0x1c6, {0x200000b40ull, 23, 0x400, 0, 0, 0x1010004}});
  Check(third_wake.value == 0 && third_waiter.wait_for(std::chrono::seconds(5)) == std::future_status::ready &&
        third_waiter.get().value == 0,
        "a self-identified mutex wake reaches its queued waiter");

  auto* cv_mutex = reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(storage) + 0x3140);
  std::atomic_ref<uint32_t> cv_owner(cv_mutex[0]);
  cv_mutex[1] = 0x400;
  auto* timeout = reinterpret_cast<int64_t*>(static_cast<uint8_t*>(storage) + 0x3800);
  timeout[0] = 0;
  timeout[1] = 10000000;
  for (unsigned contenders = 1; contenders <= 2; ++contenders) {
    std::vector<std::future<Bridge::Reply>> queued;
    for (unsigned i = 0; i < contenders; ++i) {
      cv_owner.store(0x1234, std::memory_order_release);
      queued.push_back(std::async(std::launch::async, [] {
        return Bridge::DispatchSyscall({0x1c6, {0x200003140ull, 17, 0, 0, 0, 0x101000b}});
      }));
      contested(cv_owner, "condition mutex contender reaches contested state");
    }
    // fixture threads have guest tid 0, so a bare CONTESTED word means we hold it with waiters queued
    cv_owner.store(0x80000000u, std::memory_order_release);
    const auto timed = Bridge::DispatchSyscall({0x1c6, {0x200003244ull, 8, 8, 0x200003140ull, 0x200003800ull, 0x102000e}});
    Check(timed.value == -1 && timed.posix_errno == Libs::Posix::POSIX_ETIMEDOUT &&
          cv_owner.load(std::memory_order_acquire) == (contenders > 1 ? 0x80000000u : 0u),
          "CV_WAIT releases the mutex leaving CONTESTED only while more than one contender is queued");
    for (auto& contender : queued) {
      Check(contender.wait_for(std::chrono::seconds(5)) == std::future_status::ready && contender.get().value == 0,
            "CV_WAIT release wakes the queued mutex contenders");
    }
  }
  Check(Kernel::Memory::KernelMunmap(reinterpret_cast<uint64_t>(storage), 0x4000) == OK &&
        _putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", saved.c_str()) == 0,
        "release original-address fixture and restore native mutex setting");
  std::printf("NativeUmtxTests: 64 actual waits, startup wake, replacement owner, unknown tuple, %u/64 relock re-sleeps, m_flags 0x400 and self-identified tuples, CV_WAIT release passed\n", resleeps);
#endif
}
