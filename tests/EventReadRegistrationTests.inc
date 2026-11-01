void CheckReadEventRegistration() {
  namespace EQ = Libs::LibKernel::EventQueue;
  using namespace Libs::LibKernel;
  int pair[2] {-1, -1};
  Check(FileSystem::CreateGuestSocketPair(pair) == OK, "create read-registration socket pair");
  EQ::KernelEqueue queue = EQ::KERNEL_EQUEUE_INVALID;
  Check(EQ::KernelCreateEqueue(&queue, "read-registration") == OK, "create read-registration queue");
  uint32_t first = 1, second = 2;
  Check(EQ::KernelAddReadEvent(queue, pair[1], 1, &first) == OK &&
        EQ::KernelAddReadEvent(queue, pair[1], 4, &second) == OK,
        "increase an existing read event threshold");
  Check(FileSystem::KernelWrite(pair[0], "abc", 3) == 3, "queue fewer bytes than the new threshold");
  std::array<EQ::KernelEvent, 2> events {};
  int count = -1;
  const KernelUseconds zero = 0;
  Check(EQ::KernelWaitEqueue(queue, events.data(), 2, &count, &zero) == KERNEL_ERROR_ETIMEDOUT && count == 0,
        "re-added read event uses its new threshold");
  Check(FileSystem::KernelWrite(pair[0], "d", 1) == 1 &&
        EQ::KernelWaitEqueue(queue, events.data(), 2, &count, &zero) == OK && count == 1 &&
        events[0].ident == static_cast<uintptr_t>(pair[1]) && events[0].data == 4 &&
        events[0].fflags == 1 && events[0].udata == &second,
        "updated read event reports queued bytes and user data without duplicates");
  Check(EQ::KernelAddReadEvent(queue, pair[1], 8, &first) == OK &&
        EQ::KernelWaitEqueue(queue, events.data(), 2, &count, &zero) == KERNEL_ERROR_ETIMEDOUT && count == 0,
        "raising the threshold clears previously observed readiness");
  Check(EQ::KernelAddReadEvent(queue, pair[1], 0, &first) == OK &&
        EQ::KernelWaitEqueue(queue, events.data(), 2, &count, &zero) == OK && count == 1 &&
        events[0].data == 4 && events[0].fflags == 0 && events[0].udata == &first,
        "removing a custom threshold restores default read readiness");
  Check(EQ::KernelAddReadEvent(queue, pair[1], std::numeric_limits<size_t>::max(), &second) == KERNEL_ERROR_EINVAL &&
        EQ::KernelWaitEqueue(queue, events.data(), 2, &count, &zero) == OK && count == 1 &&
        events[0].fflags == 0 && events[0].udata == &first,
        "invalid threshold preserves the previous registration");
  std::array<char, 4> data {};
  Check(FileSystem::KernelRead(pair[1], data.data(), data.size()) == 4 &&
        std::memcmp(data.data(), "abcd", data.size()) == 0,
        "read events never consume the socket payload");
  Check(EQ::KernelAddReadEvent(queue, pair[1], 8, &second) == OK &&
        FileSystem::KernelClose(pair[0]) == OK &&
        EQ::KernelWaitEqueue(queue, events.data(), 2, &count, &zero) == OK && count == 1 &&
        events[0].data == 0 && (events[0].flags & 0x8000u) != 0 && events[0].udata == &second,
        "socket EOF remains readable below the updated threshold");
  Check(FileSystem::KernelClose(pair[1]) == OK &&
        EQ::KernelWaitEqueue(queue, events.data(), 2, &count, &zero) == KERNEL_ERROR_ETIMEDOUT && count == 0 &&
        EQ::KernelDeleteReadEvent(queue, pair[1]) == KERNEL_ERROR_ENOENT,
        "closing the watched socket removes its read registration");
  Check(EQ::KernelDeleteEqueue(queue) == OK, "delete read-registration queue");
  std::printf("EventReadRegistrationTests: threshold_update=pass default_threshold=pass invalid_update=pass eof=pass close=pass\n");
}

void CheckMbusDescriptorTeardown() {
#if defined(_WIN32)
  namespace EQ = Libs::LibKernel::EventQueue;
  using namespace Libs::LibKernel;
  NativeAvTest::Environment environment;
  NativeAvTest::Environment::Set("KYTY_DIAGNOSTIC_SYSAV_AV_DEVICE_PROBE", "");
  NativeAvTest::Environment::Set("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1");
  std::shared_ptr<FileSystem::NativeMbusReceiveQueue> torn_down;
  EQ::KernelEqueue owned_queue = EQ::KERNEL_EQUEUE_INVALID;
  {
    FileSystem::ScopedGuestDescriptorTable descriptors;
    const int mbus = FileSystem::KernelOpen("/dev/mbus_av", 2, 0);
    Check(mbus >= 3, "open MBus in a guest descriptor table");
    torn_down = FileSystem::PinNativeMbusReceiveQueue(mbus);
    const int queue_fd = FileSystem::CreateNativeKqueueDescriptor();
    Check(queue_fd >= 3 && FileSystem::ResolveNativeKqueueDescriptor(queue_fd, &owned_queue),
          "create a descriptor-owned native event queue");
  }
  {
    std::lock_guard lock(torn_down->mutex);
    Check(torn_down->closed, "guest descriptor teardown closes pinned MBus readers");
  }
  Check(!EQ::KernelPinEqueue(owned_queue), "guest descriptor teardown releases its native event queue");
  std::printf("EventReadRegistrationTests: mbus_bulk_close=pass owned_queue_release=pass\n");
#endif
}

void CheckMbusDescriptorIsolation() {
#if defined(_WIN32)
  namespace EQ = Libs::LibKernel::EventQueue;
  using namespace Libs::LibKernel;
  NativeAvTest::Environment environment;
  NativeAvTest::Environment::Set("KYTY_DIAGNOSTIC_SYSAV_AV_DEVICE_PROBE", "");
  {
    FileSystem::ScopedGuestDescriptorTable first_table;
    int first = FileSystem::KernelOpen("/dev/mbus_av", 6, 0);
    auto inbox = FileSystem::PinNativeMbusReceiveQueue(first);
    EQ::KernelEqueue queue = EQ::KERNEL_EQUEUE_INVALID;
    Check(first >= 3 && inbox && EQ::KernelCreateEqueue(&queue, "mbus-close-isolation") == OK &&
          EQ::KernelAddReadEvent(queue, first, 1, &first) == OK,
          "watch a mailbox owned by the first guest table");
    {
      FileSystem::ScopedGuestDescriptorTable second_table;
      const int second = FileSystem::KernelOpen("/dev/mbus_av", 6, 0);
      Check(second == first && FileSystem::KernelClose(second) == OK,
            "close the same descriptor number in a separate guest table");
    }
    {
      std::lock_guard lock(inbox->mutex);
      inbox->received.resize(80, 0x5a);
    }
    EQ::KernelEvent event {};
    int count = 0;
    const KernelUseconds zero = 0;
    Check(EQ::KernelWaitEqueue(queue, &event, 1, &count, &zero) == OK && count == 1 &&
          event.ident == static_cast<uintptr_t>(first) && event.data == 80 && event.udata == &first,
          "closing an unrelated guest mailbox preserves the original subscription");
    Check(FileSystem::KernelClose(first) == OK &&
          EQ::KernelWaitEqueue(queue, &event, 1, &count, &zero) == KERNEL_ERROR_ETIMEDOUT && count == 0 &&
          EQ::KernelDeleteReadEvent(queue, first) == KERNEL_ERROR_ENOENT,
          "closing the mailbox removes its own subscription");
    Check(EQ::KernelDeleteEqueue(queue) == OK, "release mailbox isolation event queue");
  }
  std::printf("EventReadRegistrationTests: descriptor_scope_isolation=pass\n");
#endif
}

void CheckMbusDescriptorLifetimes() {
  CheckMbusDescriptorTeardown();
  CheckMbusDescriptorIsolation();
}

void CheckNestedReadiness() {
  namespace EQ = Libs::LibKernel::EventQueue;
  using namespace Libs::LibKernel;
  int pair[2] {-1, -1};
  EQ::KernelEqueue inner = EQ::KERNEL_EQUEUE_INVALID, outer = EQ::KERNEL_EQUEUE_INVALID;
  Check(FileSystem::CreateGuestSocketPair(pair) == OK &&
        EQ::KernelCreateEqueue(&inner, "nested-read-source") == OK &&
        EQ::KernelCreateEqueue(&outer, "nested-read-watcher") == OK,
        "create nested event queues and a socket source");
  const int descriptor = FileSystem::CreateEqueueDescriptor(inner);
  Check(descriptor >= 3 && EQ::KernelAddReadEvent(inner, pair[1], 4, &pair) == OK &&
        EQ::KernelAddReadEvent(outer, descriptor, 1, &inner) == OK,
        "watch the source queue through its guest descriptor");
  EQ::KernelEvent event {};
  int count = -1;
  const KernelUseconds zero = 0;
  Check(EQ::KernelWaitEqueue(outer, &event, 1, &count, &zero) == KERNEL_ERROR_ETIMEDOUT && count == 0,
        "empty inner queue does not make its outer watcher readable");
  Check(FileSystem::KernelWrite(pair[0], "real", 4) == 4 &&
        EQ::KernelWaitEqueue(outer, &event, 1, &count, &zero) == OK && count == 1 &&
        event.ident == static_cast<uintptr_t>(descriptor) && event.udata == &inner,
        "nested queue discovers socket readiness before any inner wait");
  Check(EQ::KernelWaitEqueue(inner, &event, 1, &count, &zero) == OK && count == 1 &&
        event.ident == static_cast<uintptr_t>(pair[1]) && event.data == 4 && event.udata == &pair,
        "outer readiness polling leaves the inner socket event available");
  std::array<char, 4> data {};
  Check(FileSystem::KernelRead(pair[1], data.data(), data.size()) == 4 &&
        std::memcmp(data.data(), "real", data.size()) == 0 &&
        EQ::KernelWaitEqueue(outer, &event, 1, &count, &zero) == KERNEL_ERROR_ETIMEDOUT && count == 0,
        "outer readiness clears after its underlying socket is drained");
  Check(EQ::KernelDeleteReadEvent(inner, pair[1]) == OK &&
        FileSystem::KernelClose(pair[0]) == OK && FileSystem::KernelClose(pair[1]) == OK,
        "release the nested socket source");
  KernelTimespec delay {0, 10'000'000};
  const KernelUseconds bounded = 200'000;
  Check(EQ::KernelAddHRTimerEvent(inner, 47, &delay, &delay) == OK &&
        EQ::KernelWaitEqueue(outer, &event, 1, &count, &bounded) == OK && count == 1,
        "outer watcher observes an inner timer expiration without an inner wait");
  Check(EQ::KernelWaitEqueue(inner, &event, 1, &count, &zero) == OK && count == 1 &&
        event.ident == 47 && event.filter == EQ::KERNEL_EVFILT_HRTIMER && event.udata == &delay &&
        EQ::KernelWaitEqueue(outer, &event, 1, &count, &zero) == KERNEL_ERROR_ETIMEDOUT && count == 0,
        "outer polling preserves the one-shot timer until the inner wait consumes it");
  Check(FileSystem::KernelClose(descriptor) == OK && EQ::KernelDeleteEqueue(inner) == OK &&
        EQ::KernelDeleteEqueue(outer) == OK,
        "release nested event queues and descriptor alias");
  std::array<EQ::KernelEqueue, 2> cyclic {};
  std::array<int, 2> aliases {};
  for (size_t i = 0; i < cyclic.size(); ++i) {
    Check(EQ::KernelCreateEqueue(&cyclic[i], "nested-cycle") == OK,
          "create cyclic readiness fixture queues");
    aliases[i] = FileSystem::CreateEqueueDescriptor(cyclic[i]);
    Check(aliases[i] >= 3, "create cyclic readiness descriptor aliases");
  }
  Check(EQ::KernelAddReadEvent(cyclic[0], aliases[0], 1, nullptr) == KERNEL_ERROR_EINVAL &&
        EQ::KernelAddReadEvent(cyclic[0], aliases[1], 1, nullptr) == OK &&
        EQ::KernelAddReadEvent(cyclic[1], aliases[0], 1, nullptr) == OK,
        "preserve direct self-watch rejection and existing indirect watcher behavior");
  const auto poll_cycle = [&](EQ::KernelEqueue queue) {
    for (size_t i = 0; i < 128; ++i) {
      EQ::KernelEvent polled {};
      int received = -1;
      if (EQ::KernelWaitEqueue(queue, &polled, 1, &received, &zero) != KERNEL_ERROR_ETIMEDOUT || received != 0) {
        return false;
      }
    }
    return true;
  };
  auto first_poll = std::async(std::launch::async, poll_cycle, cyclic[0]);
  auto second_poll = std::async(std::launch::async, poll_cycle, cyclic[1]);
  Check(first_poll.wait_for(std::chrono::seconds(3)) == std::future_status::ready &&
        second_poll.wait_for(std::chrono::seconds(3)) == std::future_status::ready &&
        first_poll.get() && second_poll.get(),
        "concurrent empty cyclic watchers complete without deadlock or readiness");
  Check(EQ::KernelAddHRTimerEvent(cyclic[0], 48, &delay, &delay) == OK &&
        EQ::KernelWaitEqueue(cyclic[1], &event, 1, &count, &bounded) == OK && count == 1,
        "a cyclic watcher finds a timer source");
  std::array<EQ::KernelEvent, 2> cycle_events {};
  Check(EQ::KernelWaitEqueue(cyclic[0], cycle_events.data(), 2, &count, &zero) == OK &&
        std::any_of(cycle_events.begin(), cycle_events.begin() + count,
                    [](const auto& queued) { return queued.ident == 48 && queued.filter == EQ::KERNEL_EVFILT_HRTIMER; }) &&
        EQ::KernelWaitEqueue(cyclic[1], &event, 1, &count, &zero) == KERNEL_ERROR_ETIMEDOUT && count == 0,
        "cycles do not preserve readiness after the only source is consumed");
  for (size_t i = 0; i < cyclic.size(); ++i) {
    Check(FileSystem::KernelClose(aliases[i]) == OK && EQ::KernelDeleteEqueue(cyclic[i]) == OK,
          "release cyclic readiness resources");
  }
  std::array<EQ::KernelEqueue, 80> chain {};
  std::array<int, 80> chain_aliases {};
  for (size_t i = 0; i < chain.size(); ++i) {
    Check(EQ::KernelCreateEqueue(&chain[i], "nested-chain") == OK,
          "create a deep readiness graph");
    chain_aliases[i] = FileSystem::CreateEqueueDescriptor(chain[i]);
    Check(chain_aliases[i] >= 3, "create a deep readiness descriptor");
    if (i != 0) Check(EQ::KernelAddReadEvent(chain[i - 1], chain_aliases[i], 1, nullptr) == OK,
                      "link the deep readiness graph");
  }
  Check(EQ::KernelAddHRTimerEvent(chain.back(), 49, &delay, &delay) == OK &&
        EQ::KernelWaitEqueue(chain.front(), &event, 1, &count, &bounded) == OK && count == 1 &&
        EQ::KernelWaitEqueue(chain.back(), &event, 1, &count, &zero) == OK && count == 1 && event.ident == 49 &&
        EQ::KernelWaitEqueue(chain.front(), &event, 1, &count, &zero) == KERNEL_ERROR_ETIMEDOUT && count == 0,
        "deep watcher graphs find and preserve readiness without a recursion limit");
  for (size_t i = 0; i < chain.size(); ++i) {
    Check(FileSystem::KernelClose(chain_aliases[i]) == OK && EQ::KernelDeleteEqueue(chain[i]) == OK,
          "release deep readiness resources");
  }
  std::printf("EventReadRegistrationTests: nested_socket=pass nonconsuming=pass drained_state=pass nested_timer=pass\n");
  std::printf("EventReadRegistrationTests: empty_cycle=pass concurrent_poll=pass cycle_drain=pass depth80=pass\n");
}

void CheckWaitOutputCounts() {
  namespace EQ = Libs::LibKernel::EventQueue;
  using namespace Libs::LibKernel;
  EQ::KernelEqueue queue = EQ::KERNEL_EQUEUE_INVALID;
  Check(EQ::KernelCreateEqueue(&queue, "wait-error-count") == OK &&
        EQ::KernelAddUserEventEdge(queue, 91) == OK &&
        EQ::KernelTriggerUserEvent(queue, 91, reinterpret_cast<void*>(0x5a)) == OK,
        "queue an event before invalid wait arguments");
  EQ::KernelEvent event {};
  event.ident = 0xabcdef;
  int count = 123;
  const KernelUseconds zero = 0;
  const int invalid_count = EQ::KernelWaitEqueue(queue, &event, 0, &count, &zero);
  std::printf("EventWaitCountTests: invalid_count_result=0x%x output_count=%d\n", invalid_count, count);
  Check(invalid_count == KERNEL_ERROR_EINVAL && count == 0 && event.ident == 0xabcdef,
        "invalid event capacity clears output count without reading events");
  count = 123;
  Check(EQ::KernelWaitEqueue(EQ::KERNEL_EQUEUE_INVALID, nullptr, -1, &count, &zero) == KERNEL_ERROR_EINVAL && count == 0,
        "invalid capacity error precedes descriptor and event-buffer errors");
  count = 123;
  Check(EQ::KernelWaitEqueue(EQ::KERNEL_EQUEUE_INVALID, &event, 1, &count, &zero) == KERNEL_ERROR_EBADF && count == 0,
        "failed queue lookup clears output count");
  Check(EQ::KernelWaitEqueue(queue, &event, 1, &count, &zero) == OK && count == 1 &&
        event.ident == 91 && event.filter == EQ::KERNEL_EVFILT_USER && event.data == 0x5a,
        "invalid capacity never entered the kernel wait or consumed the edge event");
  count = 123;
  Check(EQ::KernelWaitEqueue(queue, &event, 1, &count, &zero) == KERNEL_ERROR_ETIMEDOUT && count == 0,
        "empty queue timeout reports zero events");
  std::atomic_int wait_count {123};
  auto waiting = std::async(std::launch::async, [&] {
    EQ::KernelEvent awaited {};
    int received = 123;
    const KernelUseconds timeout = 200'000;
    const int result = EQ::KernelWaitEqueue(queue, &awaited, 1, &received, &timeout);
    wait_count.store(received, std::memory_order_release);
    return result;
  });
  Check(waiting.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout,
        "empty queue wait stays pending before deletion");
  Check(EQ::KernelDeleteEqueue(queue) == OK &&
        waiting.wait_for(std::chrono::seconds(2)) == std::future_status::ready &&
        waiting.get() == KERNEL_ERROR_EBADF && wait_count.load(std::memory_order_acquire) == 0,
        "queue deletion returns its error with zero delivered events");
  std::printf("EventWaitCountTests: capacity_error=pass error_order=pass failed_wait_count=pass timeout_count=pass retained_edge=pass\n");
}
