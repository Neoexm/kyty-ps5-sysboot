void CheckNativeSystemMbus() {
#if defined(_WIN32)
  using namespace Libs::LibKernel;
  NativeAvTest::Environment environment;
  LocalSocketPolicySavedIdentity saved_identity;
  LocalSocketPolicyCredential(-1);
  Check(FileSystem::KernelOpen("/dev/mbus", 2, 0) == KERNEL_ERROR_EPERM,
        "system MBus rejects unknown capability 62");
  LocalSocketPolicyCredential(0);
  Check(FileSystem::KernelOpen("/dev/mbus", 2, 0) == KERNEL_ERROR_EPERM,
        "system MBus rejects a verified absent capability 62");
  LocalSocketPolicyCredential(1);
  const int fd = FileSystem::KernelOpen("/dev/mbus", 2, 0);
  Check(fd >= 3 && FileSystem::PinNativeMbusReceiveQueue(fd) != nullptr,
        "system MBus opens for the explicit credential fixture");
  namespace EQ = Libs::LibKernel::EventQueue;
  auto inbox = FileSystem::PinNativeMbusReceiveQueue(fd);
  Check(inbox->system != nullptr, "generic MBus has independent kernel queue state");
  const int second = FileSystem::KernelOpen("/dev/mbus", 0, 0);
  auto other = FileSystem::PinNativeMbusReceiveQueue(second);
  const int av = FileSystem::KernelOpen("/dev/mbus_av", 2, 0);
  auto av_inbox = FileSystem::PinNativeMbusReceiveQueue(av);
  Check(other && other != inbox && other->system == inbox->system && av_inbox && !av_inbox->system,
        "generic opens share only their system queues and remain separate from AV");
  Check(FileSystem::KernelOpen("/dev/mbus", 3, 0) == KERNEL_ERROR_EINVAL &&
        FileSystem::KernelOpen("/dev/mbus", 0x20000, 0) == KERNEL_ERROR_ENOTDIR &&
        FileSystem::KernelOpen("/dev/mbus", 0x402, 0) == KERNEL_ERROR_ENOSYS,
        "system MBus rejects invalid access and unsupported file mutations");
  void* memory = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&memory, 0x4000, 3, 0, "system-mbus-fixture") == OK,
        "map MBus request layouts");
  auto* change = static_cast<EQ::KernelEvent*>(memory);
  auto* event = reinterpret_cast<EQ::KernelEvent*>(static_cast<uint8_t*>(memory) + 0x100);
  auto* timeout = reinterpret_cast<KernelTimespec*>(static_cast<uint8_t*>(memory) + 0x200);
  auto* buffer = static_cast<uint8_t*>(memory) + 0x400;
  auto* stat = reinterpret_cast<FileSystem::FileStat*>(static_cast<uint8_t*>(memory) + 0x800);
  Check(FileSystem::KernelStat("/dev/mbus", stat) == OK && stat->st_mode == 0020600u &&
        FileSystem::KernelFstat(fd, stat) == OK && stat->st_mode == 0020600u &&
        stat->st_uid == 0 && stat->st_gid == 0,
        "system MBus exposes the registered device type and permissions");
  Check(FileSystem::KernelRead(fd, buffer, 79) == KERNEL_ERROR_EWOULDBLOCK &&
        FileSystem::KernelWrite(fd, buffer, 79) == KERNEL_ERROR_EWOULDBLOCK &&
        FileSystem::KernelWrite(second, buffer, 80) == KERNEL_ERROR_EBADF &&
        FileSystem::KernelWrite(fd, reinterpret_cast<void*>(1), 80) == KERNEL_ERROR_EFAULT &&
        FileSystem::KernelWrite(fd, buffer, 80) == KERNEL_ERROR_ENOSYS,
        "system MBus preserves record bounds, access rights and its unsupported transmit boundary");
  Check(FileSystem::KernelIoctl(fd, 0x1234, buffer) == KERNEL_ERROR_EINVAL &&
        FileSystem::KernelIoctl(fd, 0xc0288c00, buffer) == KERNEL_ERROR_EINVAL &&
        FileSystem::KernelIoctl(fd, 0xc0288c01, buffer) == KERNEL_ERROR_ENOSYS &&
        FileSystem::KernelLseek(fd, 0, 0) == KERNEL_ERROR_ESPIPE &&
        FileSystem::KernelPread(fd, buffer, 80, 0) == KERNEL_ERROR_ESPIPE,
        "generic ioctls remain distinct from AV and positioned access is rejected");
  const int queue_fd = FileSystem::CreateNativeKqueueDescriptor();
  EQ::KernelEqueue queue = 0;
  Check(queue_fd >= 3 && FileSystem::ResolveNativeKqueueDescriptor(queue_fd, &queue),
        "create a native kqueue descriptor for the worker ABI");
  const std::array<const char*, 2> keys {"KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS", "KYTY_DIAGNOSTIC_SYSCORE_EQUEUE_FD"};
  std::array<std::string, 2> saved;
  for (size_t i = 0; i != keys.size(); ++i) {
    const char* value = std::getenv(keys[i]);
    saved[i] = value ? value : "";
    NativeAvTest::Environment::Set(keys[i], i == 0 ? "" : "1");
  }
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  for (size_t i = 0; i != keys.size(); ++i) NativeAvTest::Environment::Set(keys[i], saved[i].c_str());
  const auto* symbol = symbols.FindByNid("RW-GEfpnsqg", Loader::SymbolType::Func);
  Check(symbol != nullptr, "resolve the SysCore kevent export");
  using Kevent = int64_t (KYTY_SYSV_ABI *)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
  const auto kevent = reinterpret_cast<Kevent>(symbol->vaddr);
  *change = {static_cast<uintptr_t>(fd), EQ::KERNEL_EVFILT_READ, 1, 0, 0, buffer};
  Check(kevent(queue_fd, reinterpret_cast<uint64_t>(change), 1, 0, 0, 0) == 0,
        "native ABI registers the generic MBus read filter");
  *change = {1, EQ::KERNEL_EVFILT_NOTIFY, 1, 0, 16, buffer};
  Check(kevent(queue_fd, reinterpret_cast<uint64_t>(change), 1, 0, 0, 0) == 0,
        "native ABI registers its passive global notification selector");
  *timeout = {0, 2'500'000};
  Check(kevent(queue_fd, 0, 0, reinterpret_cast<uint64_t>(event), 1, reinterpret_cast<uint64_t>(timeout)) == 0,
        "native timed wait observes no MBus or global notification merely from registration");
  timeout->tv_nsec = -1;
  Check(kevent(queue_fd, 0, 0, reinterpret_cast<uint64_t>(event), 1, reinterpret_cast<uint64_t>(timeout)) == -1 &&
        *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
        "native kevent rejects an invalid timespec");
  *timeout = {0, 0};
  Check(EQ::KernelTriggerEvent(queue, 1, EQ::KERNEL_EVFILT_NOTIFY, reinterpret_cast<void*>(17)) == OK &&
        kevent(queue_fd, 0, 0, reinterpret_cast<uint64_t>(event), 1, reinterpret_cast<uint64_t>(timeout)) == 0 &&
        EQ::KernelTriggerEvent(queue, 1, EQ::KERNEL_EVFILT_NOTIFY, reinterpret_cast<void*>(0x110)) == OK &&
        kevent(queue_fd, 0, 0, reinterpret_cast<uint64_t>(event), 1, reinterpret_cast<uint64_t>(timeout)) == 1 &&
        event->filter == EQ::KERNEL_EVFILT_NOTIFY && event->data == 16 && event->udata == buffer &&
        kevent(queue_fd, 0, 0, reinterpret_cast<uint64_t>(event), 1, reinterpret_cast<uint64_t>(timeout)) == 0,
        "notification fixtures match only the low-byte selector and clear after delivery");
  auto pending = std::async(std::launch::async, [&] { return FileSystem::KernelRead(fd, buffer, 160); });
  Check(pending.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout,
        "empty generic MBus blocks without generating a record");
  {
    std::lock_guard lock(inbox->system->mutex);
    inbox->system->received.resize(80, 0x31);
    inbox->system->cv.notify_all();
  }
  Check(pending.wait_for(std::chrono::seconds(2)) == std::future_status::ready && pending.get() == 80 && buffer[0] == 0x31,
        "a host-only fixture wakes a blocked read and returns one complete record");
  {
    std::lock_guard lock(inbox->system->mutex);
    inbox->system->received.resize(80, 0x32);
    inbox->system->priority.resize(80, 0x33);
  }
  Check(kevent(queue_fd, 0, 0, reinterpret_cast<uint64_t>(event), 1, reinterpret_cast<uint64_t>(timeout)) == 1 &&
        event->filter == EQ::KERNEL_EVFILT_READ && event->data == 0x20 &&
        FileSystem::KernelRead(second, buffer, 160) == 80 && buffer[0] == 0x33 &&
        FileSystem::KernelRead(second, reinterpret_cast<void*>(1), 80) == KERNEL_ERROR_EFAULT &&
        kevent(queue_fd, 0, 0, reinterpret_cast<uint64_t>(event), 1, reinterpret_cast<uint64_t>(timeout)) == 0,
        "generic priority, shared consumption, filter data and copyout failure match the kernel path");
  {
    std::lock_guard lock(av_inbox->mutex);
    Check(av_inbox->received.empty(), "system queue fixtures never enter the AV endpoint");
  }
  auto closing = std::async(std::launch::async, [&] { return FileSystem::KernelRead(fd, buffer, 80); });
  Check(closing.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout &&
        FileSystem::KernelClose(fd) == OK && closing.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout &&
        FileSystem::KernelRead(fd, buffer, 80) == KERNEL_ERROR_EBADF && !other->closed,
        "close retires the generic descriptor while an active read retains its file reference");
  {
    std::lock_guard lock(inbox->system->mutex);
    inbox->system->received.resize(80, 0x34);
    inbox->system->cv.notify_all();
  }
  Check(closing.wait_for(std::chrono::seconds(2)) == std::future_status::ready && closing.get() == 80 && buffer[0] == 0x34,
        "a pinned read completes from a queued fixture after descriptor close");
  Check(kevent(queue_fd, 0, 0, reinterpret_cast<uint64_t>(event), 1, reinterpret_cast<uint64_t>(timeout)) == 0 &&
        EQ::KernelDeleteReadEvent(queue, fd) == KERNEL_ERROR_ENOENT,
        "closed generic descriptors lose their read subscriptions");
  Check(FileSystem::KernelClose(second) == OK && FileSystem::KernelClose(av) == OK &&
        FileSystem::KernelClose(queue_fd) == OK && !EQ::KernelPinEqueue(queue),
        "close generic endpoint fixtures and their descriptor-owned queue");
  const int nonblocking = FileSystem::KernelOpen("/dev/mbus", 6, 0);
  Check(nonblocking >= 3, "open generic MBus with O_NONBLOCK");
  auto nonblocking_read = std::async(std::launch::async, [&] { return FileSystem::KernelRead(nonblocking, buffer, 80); });
  Check(nonblocking_read.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout &&
        FileSystem::KernelClose(nonblocking) == OK &&
        nonblocking_read.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout,
        "the captured generic read handler waits even with O_NONBLOCK and retains its file reference");
  {
    std::lock_guard lock(inbox->system->mutex);
    inbox->system->received.resize(80, 0x35);
    inbox->system->cv.notify_all();
  }
  Check(nonblocking_read.wait_for(std::chrono::seconds(2)) == std::future_status::ready && nonblocking_read.get() == 80,
        "finish the pinned O_NONBLOCK fixture without manufacturing device data");
  std::shared_ptr<FileSystem::NativeMbusReceiveQueue> torn_down;
  {
    FileSystem::ScopedGuestDescriptorTable descriptors;
    const int owned = FileSystem::KernelOpen("/dev/mbus", 6, 0);
    torn_down = FileSystem::PinNativeMbusReceiveQueue(owned);
    Check(torn_down != nullptr, "open generic MBus in a process descriptor table");
    {
      FileSystem::ScopedGuestDescriptorTable unrelated;
      const int reused = FileSystem::KernelOpen("/dev/mbus", 2, 0);
      Check(reused == owned && FileSystem::KernelClose(reused) == OK && !torn_down->closed,
            "closing the same descriptor number in another process preserves its unrelated open");
    }
    Check(FileSystem::KernelClose(owned) == OK && !torn_down->tearing_down,
          "an explicitly closed file pin remains associated with its owning process");
  }
  {
    std::lock_guard lock(torn_down->GetMutex());
    Check(torn_down->closed && torn_down->tearing_down, "process descriptor teardown closes and cancels its pinned generic endpoint");
  }
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), 0x4000) == OK,
        "release generic MBus fixture memory");
  std::printf("NativeSystemMbusTests: admission=pass distinct_endpoints=pass native_filters=pass timed_wait=pass blocking_read=pass priority=pass close=pass\n");
#endif
}

void CheckNativeMbusDevices() {
  CheckNativeSystemMbus();
#if defined(_WIN32)
  namespace EQ = Libs::LibKernel::EventQueue;
  using namespace Libs::LibKernel;
  NativeAvTest::Environment environment;
  NativeAvTest::Environment::Set("KYTY_DIAGNOSTIC_SYSAV_AV_DEVICE_PROBE", "");
  const int fd = FileSystem::KernelOpen("/dev/mbus_av", 2, 0);
  Check(fd >= 3, "native MBus opens without the diagnostic AV device probe");
  Check(!FileSystem::IsNativeAvProbeDescriptor(fd), "native MBus is not a discovery descriptor");
  auto inbox = FileSystem::PinNativeMbusReceiveQueue(fd);
  Check(inbox != nullptr, "native MBus has a receive queue");
  void* memory = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&memory, 0x4000, 3, 0, "native_mbus_fixture") == OK,
        "map native MBus guest output buffers");
  auto& stat = *static_cast<FileSystem::FileStat*>(memory);
  Check(FileSystem::KernelFstat(fd, &stat) == OK, "native MBus reports descriptor metadata");
  Check(stat.st_mode == 0020600u && stat.st_uid == 0 && stat.st_gid == 0 && stat.st_nlink == 1,
        "native MBus preserves observed character-device type and ownership");
  auto& buffer = *reinterpret_cast<std::array<uint8_t, 80>*>(static_cast<uint8_t*>(memory) + 0x100);
  buffer.fill(0);
  Check(FileSystem::KernelRead(fd, buffer.data(), 0) == KERNEL_ERROR_EWOULDBLOCK,
        "native MBus rejects reads smaller than one record");
  Check(FileSystem::KernelRead(fd, reinterpret_cast<void*>(1), buffer.size()) == KERNEL_ERROR_EFAULT,
        "native MBus rejects an invalid destination");
  Check(FileSystem::KernelRead(fd, buffer.data(), buffer.size() - 1) == KERNEL_ERROR_EWOULDBLOCK,
        "native MBus requires a complete 80-byte record");
  Check(FileSystem::KernelRead(fd, buffer.data(), buffer.size()) == KERNEL_ERROR_EWOULDBLOCK,
        "empty blocking-mode MBus reads return EWOULDBLOCK");
  Check(FileSystem::KernelIoctl(fd, 0x1234, nullptr) == KERNEL_ERROR_ENODEV,
        "native MBus preserves the captured ioctl response");
  Check(FileSystem::KernelWrite(fd, buffer.data(), buffer.size()) == KERNEL_ERROR_ENOSYS,
        "native MBus has no transmit contract");
  Check(FileSystem::KernelLseek(fd, 0, 0) == KERNEL_ERROR_ESPIPE, "native MBus is not seekable");
  Check(FileSystem::KernelPread(fd, buffer.data(), buffer.size(), 0) == KERNEL_ERROR_ESPIPE,
        "native MBus rejects positioned reads");

  EQ::KernelEqueue queue = 0;
  Check(EQ::KernelCreateEqueue(&queue, "native_mbus_host_fixture") == OK, "create MBus fixture event queue");
  Check(EQ::KernelAddReadEvent(queue, fd, 1, &buffer) == OK, "register MBus read notification");
  EQ::KernelEvent event {};
  int received = -1;
  const KernelUseconds zero = 0;
  Check(EQ::KernelWaitEqueue(queue, &event, 1, &received, &zero) == KERNEL_ERROR_ETIMEDOUT && received == 0,
        "opening MBus does not signal readiness");
  std::array<uint8_t, 80> host_fixture {};
  for (size_t i = 0; i < host_fixture.size(); ++i) host_fixture[i] = static_cast<uint8_t>(i + 1);
  {
    std::lock_guard lock(inbox->mutex);
    Check(inbox->received.empty() && !inbox->closed, "Mbus starts with no controller packets");
    inbox->received.insert(inbox->received.end(), host_fixture.begin(), host_fixture.end());
  }
  Check(EQ::KernelWaitEqueue(queue, &event, 1, &received, &zero) == OK && received == 1,
        "queued host fixture makes MBus readable");
  Check(event.ident == static_cast<uintptr_t>(fd) && event.data == 80 && event.udata == &buffer,
        "Mbus readiness reports queued bytes");
  Check(FileSystem::KernelRead(fd, reinterpret_cast<void*>(1), buffer.size()) == KERNEL_ERROR_EFAULT,
        "failed MBus copyout does not consume a host fixture");
  auto& oversized = *reinterpret_cast<std::array<uint8_t, 160>*>(static_cast<uint8_t*>(memory) + 0x200);
  oversized.fill(0);
  Check(FileSystem::KernelRead(fd, oversized.data(), oversized.size()) == 80 &&
            std::equal(host_fixture.begin(), host_fixture.end(), oversized.begin()),
        "Mbus returns one complete record from an oversized read");
  Check(EQ::KernelWaitEqueue(queue, &event, 1, &received, &zero) == KERNEL_ERROR_ETIMEDOUT,
        "draining MBus removes readiness");

  {
    std::lock_guard lock(inbox->mutex);
    inbox->received.insert(inbox->received.end(), host_fixture.begin(), host_fixture.end() - 1);
  }
  Check(EQ::KernelWaitEqueue(queue, &event, 1, &received, &zero) == KERNEL_ERROR_ETIMEDOUT &&
            FileSystem::KernelRead(fd, buffer.data(), buffer.size()) == KERNEL_ERROR_EWOULDBLOCK,
        "partial MBus records are neither readable nor returned");
  {
    std::lock_guard lock(inbox->mutex);
    inbox->received.push_back(host_fixture.back());
  }
  Check(EQ::KernelWaitEqueue(queue, &event, 1, &received, &zero) == OK && received == 1 && event.data == 80 &&
            FileSystem::KernelRead(fd, buffer.data(), buffer.size()) == 80 && buffer == host_fixture,
        "a complete queued MBus record becomes readable and is returned whole");
  Check(FileSystem::KernelClose(fd) == OK, "native MBus closes its descriptor");
  Check(EQ::KernelDeleteEqueue(queue) == OK, "delete MBus fixture event queue");
  const int nonblocking = FileSystem::KernelOpen("/dev/mbus_av", 6, 0);
  Check(nonblocking >= 3, "open nonblocking MBus");
  Check(FileSystem::KernelRead(nonblocking, buffer.data(), buffer.size()) == KERNEL_ERROR_EWOULDBLOCK,
        "empty nonblocking MBus returns EWOULDBLOCK");
  Check(FileSystem::KernelClose(nonblocking) == OK, "close nonblocking MBus");
  const int native_close_fd = FileSystem::KernelOpen("/dev/mbus_av", 2, 0);
  Check(native_close_fd >= 3, "open native syscall close fixture");
  const auto closed = Libs::NativeKernelBridge::DispatchSyscall({0x06, {static_cast<uint64_t>(native_close_fd)}});
  Check(closed.value == 0 && closed.posix_errno == 0,
        "SysAv close adapter releases a native MBus descriptor");
  Check(FileSystem::PinNativeMbusReceiveQueue(native_close_fd) == nullptr,
        "native SysAv close removes the mailbox descriptor");
  NativeAvTest::Environment::Set("KYTY_DIAGNOSTIC_SYSAV_AV_DEVICE_PROBE", "1");
  const int probe_fd = FileSystem::KernelOpen("/dev/mbus_av", 2, 0);
  Check(probe_fd >= 3 && FileSystem::IsNativeAvProbeDescriptor(probe_fd),
        "legacy MBus discovery mode remains explicitly diagnostic");
  Check(FileSystem::KernelRead(probe_fd, buffer.data(), buffer.size()) == KERNEL_ERROR_EWOULDBLOCK,
        "legacy diagnostic MBus read remains nonblocking without producing packets");
  Check(FileSystem::KernelClose(probe_fd) == OK, "close legacy diagnostic MBus descriptor");
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), 0x4000) == OK,
        "release native MBus guest fixture buffers");
#endif
}
