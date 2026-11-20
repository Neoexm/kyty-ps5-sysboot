void CheckSemaphoreLifetimes() {
  using namespace Libs::LibKernel;
  namespace Sema = Libs::LibKernel::Semaphore;
  using Handle = Sema::KernelSema;
  const std::array<Handle, 3> invalid {
      nullptr, reinterpret_cast<Handle>(UINTPTR_MAX), reinterpret_cast<Handle>(0x50000001)};
  for (const auto handle: invalid) {
    KernelUseconds timeout = 17;
    int waiting = -71;
    Check(Sema::KernelDeleteSema(handle) == KERNEL_ERROR_ESRCH &&
          Sema::KernelCloseSema(handle) == KERNEL_ERROR_ESRCH &&
          Sema::KernelWaitSema(handle, 1, &timeout) == KERNEL_ERROR_ESRCH && timeout == 17 &&
          Sema::KernelWaitSema(handle, 0, &timeout) == KERNEL_ERROR_EINVAL && timeout == 17 &&
          Sema::KernelPollSema(handle, 1) == KERNEL_ERROR_ESRCH &&
          Sema::KernelSignalSema(handle, 1) == KERNEL_ERROR_ESRCH &&
          Sema::KernelCancelSema(handle, 0, &waiting) == KERNEL_ERROR_ESRCH && waiting == -71,
          "unknown semaphore tokens return ESRCH without guest-pointer dereference");
  }
  const int pid = Process::GetPid();
  const std::string name = "SemaLifetime" + std::to_string(pid);
  Handle creator = nullptr;
  Handle alias = reinterpret_cast<Handle>(UINTPTR_MAX);
  Check(Sema::KernelOpenSema(&alias, name.c_str()) == KERNEL_ERROR_ESRCH &&
        alias == reinterpret_cast<Handle>(UINTPTR_MAX) &&
        Sema::KernelOpenExistingSema(&alias, name.c_str()) == KERNEL_ERROR_ESRCH,
        "ordinary semaphore open cannot create an absent named object");
  Check(Sema::KernelCreateSema(&creator, name.c_str(), 0x101, 0, 2, nullptr) == OK &&
        reinterpret_cast<uintptr_t>(creator) >= 0x40000000 && reinterpret_cast<uintptr_t>(creator) <= 0x4fffffff,
        "semaphore creator receives a positive token in its host allocation partition");
  EventFlag::KernelEventFlag other_type = nullptr;
  uint64_t actual = 0;
  Check(EventFlag::KernelCreateEventFlag(&other_type, "SemaphoreTypeFixture", 0x11, 1, nullptr) == OK &&
        Sema::KernelDeleteSema(reinterpret_cast<Handle>(other_type)) == KERNEL_ERROR_ESRCH &&
        EventFlag::KernelPollEventFlag(other_type, 1, 1, &actual) == OK && actual == 1 &&
        EventFlag::KernelDeleteEventFlag(other_type) == OK,
        "semaphore lookup rejects a live handle from another kernel object family");
  Check(Sema::KernelCreateSema(&alias, name.c_str(), 0x101, 0, 2, nullptr) == KERNEL_ERROR_EEXIST &&
        alias == reinterpret_cast<Handle>(UINTPTR_MAX), "duplicate named create preserves output");
  {
    Process::ScopedGuestProcessPid foreign(pid + 701);
    Handle foreign_duplicate = reinterpret_cast<Handle>(UINTPTR_MAX);
    Check(Sema::KernelCreateSema(&foreign_duplicate, name.c_str(), 0x101, 0, 2, nullptr) ==
              KERNEL_ERROR_EPERM && foreign_duplicate == reinterpret_cast<Handle>(UINTPTR_MAX),
          "foreign guest creator receives EPERM without replacing the named semaphore");
  }
  Check(Sema::KernelOpenSema(&alias, name.c_str()) == OK && alias != creator &&
        Sema::KernelDeleteSema(alias) == KERNEL_ERROR_EPERM &&
        Sema::KernelCloseSema(creator) == KERNEL_ERROR_EPERM,
        "semaphore creator and opened handles retain native ownership kinds");
  Check(Sema::KernelSignalSema(alias, 1) == OK && Sema::KernelPollSema(creator, 1) == OK &&
        Sema::KernelPollSema(alias, 1) == KERNEL_ERROR_EBUSY,
        "opened alias shares semaphore count");
  {
    Process::ScopedGuestProcessPid foreign(pid + 701);
    Check(Sema::KernelDeleteSema(creator) == KERNEL_ERROR_ESRCH &&
          Sema::KernelSignalSema(alias, 1) == KERNEL_ERROR_ESRCH &&
          Sema::KernelCloseSema(alias) == KERNEL_ERROR_ESRCH,
          "semaphore handles remain owned by their guest process");
  }
  auto wait_for_count = [&](Handle handle, int count) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (Sema::KernelSemaWaiterCountForTesting(handle) != count) {
      Check(std::chrono::steady_clock::now() < deadline, "semaphore waiters enter within fixture bound");
      std::this_thread::yield();
    }
  };
  Handle closing = nullptr;
  Check(Sema::KernelOpenSema(&closing, name.c_str()) == OK, "open alias for pinned close fixture");
  auto close_waiter = std::async(std::launch::async, [=] {
    Process::ScopedGuestProcessPid owner(pid);
    return Sema::KernelWaitSema(closing, 1, nullptr);
  });
  wait_for_count(creator, 1);
  Check(Sema::KernelCloseSema(closing) == OK && Sema::KernelSignalSema(creator, 1) == OK &&
        close_waiter.wait_for(std::chrono::seconds(2)) == std::future_status::ready && close_waiter.get() == OK &&
        Sema::KernelWaitSema(closing, 1, nullptr) == KERNEL_ERROR_ESRCH,
        "closing an alias preserves an already pinned wait without cancelling it");
  auto first = std::async(std::launch::async, [=] {
    Process::ScopedGuestProcessPid owner(pid);
    return Sema::KernelWaitSema(creator, 1, nullptr);
  });
  auto second = std::async(std::launch::async, [=] {
    Process::ScopedGuestProcessPid owner(pid);
    return Sema::KernelWaitSema(alias, 1, nullptr);
  });
  wait_for_count(creator, 2);
  Check(Sema::KernelDeleteSema(creator) == OK &&
        first.wait_for(std::chrono::seconds(2)) == std::future_status::ready &&
        second.wait_for(std::chrono::seconds(2)) == std::future_status::ready &&
        first.get() == KERNEL_ERROR_EACCES && second.get() == KERNEL_ERROR_EACCES,
        "explicit delete wakes pinned creator and alias waiters with native EACCES");
  Check(Sema::KernelDeleteSema(creator) == KERNEL_ERROR_ESRCH &&
        Sema::KernelWaitSema(creator, 1, nullptr) == KERNEL_ERROR_ESRCH &&
        Sema::KernelWaitSema(alias, 1, nullptr) == KERNEL_ERROR_EACCES,
        "deleted creator is stale while open alias retains the deleted generation");
  Handle replacement = nullptr;
  Check(Sema::KernelOpenSema(&replacement, name.c_str()) == KERNEL_ERROR_ESRCH &&
        Sema::KernelCreateSema(&replacement, name.c_str(), 0x101, 1, 2, nullptr) == OK &&
        replacement != creator && replacement != alias && Sema::KernelPollSema(replacement, 1) == OK &&
        Sema::KernelWaitSema(alias, 1, nullptr) == KERNEL_ERROR_EACCES,
        "name recreation allocates a distinct generation without reviving old aliases");
  Check(Sema::KernelCloseSema(alias) == OK && Sema::KernelCloseSema(alias) == KERNEL_ERROR_ESRCH &&
        Sema::KernelDeleteSema(replacement) == OK, "release deleted alias and replacement generation");
  Handle canceled = nullptr;
  Check(Sema::KernelCreateSema(&canceled, "SemaCancelFixture", 1, 0, 2, nullptr) == OK,
        "create cancellation semaphore");
  auto pending = std::async(std::launch::async, [=] {
    Process::ScopedGuestProcessPid owner(pid);
    return Sema::KernelWaitSema(canceled, 1, nullptr);
  });
  wait_for_count(canceled, 1);
  int waiting = -1;
  Check(Sema::KernelCancelSema(canceled, 2, &waiting) == OK && waiting == 1 &&
        pending.wait_for(std::chrono::seconds(2)) == std::future_status::ready &&
        pending.get() == KERNEL_ERROR_ECANCELED && Sema::KernelPollSema(canceled, 2) == OK &&
        Sema::KernelSignalSema(canceled, 3) == KERNEL_ERROR_EINVAL &&
        Sema::KernelDeleteSema(canceled) == OK, "cancellation pins waiters and preserves count limits");
  for (int i = 0; i < 256; ++i) {
    Handle fresh = nullptr;
    Check(Sema::KernelCreateSema(&fresh, "SemaGenerationFixture", 1, 1, 1, nullptr) == OK &&
          fresh != creator && fresh != alias &&
          Sema::KernelSignalSema(creator, 1) == KERNEL_ERROR_ESRCH &&
          Sema::KernelPollSema(fresh, 1) == OK && Sema::KernelDeleteSema(fresh) == OK,
          "retired semaphore tokens never alias subsequently allocated objects");
  }
}
