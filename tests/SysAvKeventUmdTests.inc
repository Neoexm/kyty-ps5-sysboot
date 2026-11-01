// Stand-in for SysCore umd::Manager: the child holds the SysCore end of a shared guest socketpair and does what sub_8E70 does.
int RunSysAvUmdCrossHostChild(int argc, char** argv) {
  if (argc < 2 || std::strcmp(argv[1], "--sysav-umd-crosshost-child") != 0) return -1;
  if (argc != 5) return 2;
#if defined(_WIN32)
  using namespace Libs::LibKernel;
  std::ifstream input(Common::PathFromUtf8(argv[2]), std::ios::binary);
  const std::string manifest {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
  const int fd = std::atoi(argv[3]);
  const std::string scope = argv[4];
  FileSystem::ScopedGuestDescriptorTable descriptors;
  Check(!manifest.empty() && FileSystem::ImportExecDescriptors(manifest) == OK,
        "child imports the exported SysCore UMD socket end");
  HANDLE imported = OpenEventA(EVENT_MODIFY_STATE, FALSE, ("Local\\kyty_sysav_umd_imported_" + scope).c_str());
  Check(imported != nullptr && SetEvent(imported) != FALSE, "child reports its SysCore end is held");
  CloseHandle(imported);
  HANDLE go = OpenEventA(SYNCHRONIZE, FALSE, ("Local\\kyty_sysav_umd_go_" + scope).c_str());
  Check(go != nullptr && WaitForSingleObject(go, 30000) == WAIT_OBJECT_0, "child waits for SysAv registration");
  CloseHandle(go);
  std::array<uint8_t, 36> request {};
  const std::array<uint32_t, 9> packet {0x554d4420, 0xffffffff, 0x22, 0, 1, 0, 0, 0, 0};
  const uint32_t magic = packet[0];
  std::memcpy(request.data(), packet.data(), request.size());
  Check(FileSystem::SendGuestSocket(fd, request.data(), request.size(), 0) == 36,
        "child sends one 36-byte UMD 0x22 request");
  std::array<uint8_t, 16> reply {};
  Check(FileSystem::RecvGuestSocket(fd, reply.data(), reply.size(), 0) == 16, "child blocks for the 16-byte reply");
  uint32_t reply_magic = 0, reply_status = 1;
  std::memcpy(&reply_magic, reply.data(), 4);
  std::memcpy(&reply_status, reply.data() + 4, 4);
  Check(reply_magic == magic && reply_status == 0, "child receives the reply bytes SysAv sent");
  std::printf("SysAvKeventUmdTests: child_request=pass child_reply=pass\n");
  return 0;
#else
  return 2;
#endif
}

void CheckSysAvKeventUmd() {
#if defined(_WIN32)
  namespace EQ = Libs::LibKernel::EventQueue;
  using namespace Libs::LibKernel;
  using Libs::NativeKernelBridge::DispatchSyscall;
  NativeAvTest::Environment environment;
  NativeAvTest::Environment::Set("KYTY_DIAGNOSTIC_GUEST_EXECVE", "1");
  NativeAvTest::Environment::Set("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1");
  NativeAvTest::Environment::Set("KYTY_DIAGNOSTIC_SYSAV_AV_DEVICE_PROBE", "");
  const auto scope = std::to_string(GetCurrentProcessId()) + "_" +
      std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
  TempDirectory temporary;
  const auto manifest_path = temporary.Path() / "sysav_umd_fds.txt";

  FileSystem::ScopedGuestDescriptorTable descriptors;
  int umd[2] {-1, -1};
  Check(FileSystem::CreateGuestSocketPair(umd) == OK, "create the SysCore/SysAv UMD socketpair");
  // otherwise the child's copy of the SysAv end keeps the reverse writer alive
  Check(FileSystem::SetDescriptorFlags(umd[1], 1) == OK, "keep the SysAv end out of the child");
  std::string manifest;
  Check(FileSystem::ExportExecDescriptors(&manifest) == OK && FileSystem::SetDescriptorFlags(umd[1], 0) == OK,
        "export the SysCore end for the child");
  { std::ofstream output(manifest_path, std::ios::binary); output << manifest;
    Check(output.good(), "write the child descriptor manifest"); }
  int other[2] {-1, -1};
  Check(FileSystem::CreateGuestSocketPair(other) == OK, "create the second SysAv UMD socket");
  const int mbus = FileSystem::KernelOpen("/dev/mbus_av", 2, 0);
  const int kq = FileSystem::CreateNativeKqueueDescriptor();
  EQ::KernelEqueue queue = EQ::KERNEL_EQUEUE_INVALID;
  Check(mbus >= 3 && kq >= 3 && FileSystem::ResolveNativeKqueueDescriptor(kq, &queue),
        "open /dev/mbus_av and a native kqueue");

  void* memory = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&memory, 0x4000, 3, 0, "sysav-kevent-umd") == OK,
        "map SysAv guest storage");
  auto* base = static_cast<uint8_t*>(memory);
  auto* changes = reinterpret_cast<EQ::KernelEvent*>(base);
  auto* received = reinterpret_cast<EQ::KernelEvent*>(base + 0x200);
  auto* timeout = reinterpret_cast<KernelTimespec*>(base + 0x300);
  auto* readfds = reinterpret_cast<uint64_t*>(base + 0x400);
  auto* request = base + 0x800;
  auto* reply = base + 0xc00;
  const auto guest = [&](const void* p) { return reinterpret_cast<uint64_t>(p); };
  const auto fill = [&](int read2, int read3, int read4) {
    std::memset(changes, 0, 5 * sizeof(EQ::KernelEvent));
    changes[0].ident = 1;
    changes[0].filter = EQ::KERNEL_EVFILT_NOTIFY;
    changes[0].flags = 1;
    changes[0].data = 16;
    changes[0].udata = reinterpret_cast<void*>(0x7b);
    changes[1].ident = 1;
    changes[1].filter = EQ::KERNEL_EVFILT_USER;
    changes[1].flags = 0x21;
    changes[1].data = 0x4d;
    changes[1].udata = reinterpret_cast<void*>(0x58);
    const int reads[3] {read2, read3, read4};
    for (int i = 0; i < 3; ++i) {
      changes[2 + i].ident = static_cast<uintptr_t>(reads[i]);
      changes[2 + i].filter = EQ::KERNEL_EVFILT_READ;
      changes[2 + i].flags = 1;
    }
  };
  const auto register5 = [&](int fd) {
    return DispatchSyscall({0x16b, {static_cast<uint64_t>(fd), guest(changes), 5, 0, 0, 0}});
  };
  const auto wait = [&](int64_t ms) {
    timeout->tv_sec = ms / 1000;
    timeout->tv_nsec = (ms % 1000) * 1000000;
    std::memset(received, 0xcc, sizeof(*received));
    return DispatchSyscall({0x16b, {static_cast<uint64_t>(kq), 0, 0, guest(received), 1, guest(timeout)}});
  };
  const auto nothing_registered = [&](EQ::KernelEqueue q) {
    return EQ::KernelDeleteEvent(q, 1, EQ::KERNEL_EVFILT_NOTIFY) == KERNEL_ERROR_ENOENT &&
           EQ::KernelDeleteEvent(q, 1, EQ::KERNEL_EVFILT_USER) == KERNEL_ERROR_ENOENT &&
           EQ::KernelDeleteReadEvent(q, umd[1]) == KERNEL_ERROR_ENOENT &&
           EQ::KernelDeleteReadEvent(q, other[1]) == KERNEL_ERROR_ENOENT &&
           EQ::KernelDeleteReadEvent(q, mbus) == KERNEL_ERROR_ENOENT;
  };

  fill(umd[1], other[1], mbus);
  auto r = register5(4093);
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_EBADF && nothing_registered(queue),
        "unknown kqueue fd is EBADF before any change");
  r = DispatchSyscall({0x16b, {static_cast<uint64_t>(kq), 0x1000, 5, 0, 0, 0}});
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_EFAULT && nothing_registered(queue),
        "unmapped changelist is EFAULT before any change");
  changes[4].fflags = 1;
  r = register5(kq);
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_ENOSYS && nothing_registered(queue),
        "unmodeled trailing change is refused with nothing applied");
  fill(umd[1], other[1], mbus);
  changes[1].flags = 0x61;
  r = register5(kq);
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_ENOSYS && nothing_registered(queue),
        "unmodeled USER flags is refused with nothing applied");

  {
    const int second_kq = FileSystem::CreateNativeKqueueDescriptor();
    EQ::KernelEqueue second = EQ::KERNEL_EQUEUE_INVALID;
    Check(second_kq >= 3 && FileSystem::ResolveNativeKqueueDescriptor(second_kq, &second), "create a second kqueue");
    fill(umd[1], 4090, mbus);
    r = register5(second_kq);
    Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_EBADF &&
          EQ::KernelDeleteEvent(second, 1, EQ::KERNEL_EVFILT_NOTIFY) == OK &&
          EQ::KernelDeleteEvent(second, 1, EQ::KERNEL_EVFILT_USER) == OK &&
          EQ::KernelDeleteReadEvent(second, umd[1]) == OK &&
          EQ::KernelDeleteReadEvent(second, mbus) == KERNEL_ERROR_ENOENT,
          "closed READ fd fails in order and keeps only the earlier changes, as FreeBSD kevent does");
    Check(FileSystem::KernelClose(second_kq) == OK, "close the second kqueue");
  }

  fill(umd[1], other[1], mbus);
  r = register5(kq);
  Check(r.value == 0 && r.posix_errno == 0, "SysAv's five-change registration succeeds");
  Check(changes[2].ident == static_cast<uintptr_t>(umd[1]) && changes[2].flags == 1 && changes[4].ident == static_cast<uintptr_t>(mbus),
        "changelist is not written back");
  r = wait(30);
  Check(r.value == 0 && r.posix_errno == 0, "registration alone makes nothing ready");
  r = register5(kq);
  Check(r.value == 0 && wait(30).value == 0, "re-registering replaces rather than duplicates");

  HANDLE go = CreateEventA(nullptr, TRUE, FALSE, ("Local\\kyty_sysav_umd_go_" + scope).c_str());
  HANDLE imported = CreateEventA(nullptr, TRUE, FALSE, ("Local\\kyty_sysav_umd_imported_" + scope).c_str());
  std::array<wchar_t, 32768> executable {};
  const DWORD length = GetModuleFileNameW(nullptr, executable.data(), executable.size());
  Check(go != nullptr && imported != nullptr && length != 0 && length < executable.size(), "prepare the SysCore child");
  const auto wide_manifest = manifest_path.wstring();
  const auto wide_fd = std::to_wstring(umd[0]);
  std::wstring command = L"\"" + std::wstring(executable.data(), length) + L"\" --sysav-umd-crosshost-child \"" +
      wide_manifest + L"\" " + wide_fd + L" " + std::wstring(scope.begin(), scope.end());
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  Check(job != nullptr && SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
        "contain the SysCore child in an owned job");
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process {};
  Check(CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED,
                       nullptr, nullptr, &startup, &process) &&
            AssignProcessToJobObject(job, process.hProcess) && ResumeThread(process.hThread) != DWORD(-1),
        "launch the SysCore child process");
  Check(WaitForSingleObject(imported, 30000) == WAIT_OBJECT_0, "child holds its imported SysCore end");
  CloseHandle(imported);
  Check(FileSystem::KernelClose(umd[0]) == OK, "parent drops its SysCore end so EOF tracks the child");
  Check(wait(200).value == 0, "no readiness before the child writes");
  Check(SetEvent(go) != FALSE, "release the child");

  r = wait(20000);
  Check(r.value == 1 && received->ident == static_cast<uintptr_t>(umd[1]) &&
            received->filter == EQ::KERNEL_EVFILT_READ && received->data == 36 &&
            (received->flags & 0x8000u) == 0 && received->udata == nullptr,
        "SysAv's timed kevent reports READ on its UMD end with 36 pending bytes");
  *readfds = (uint64_t {1} << umd[1]) | (uint64_t {1} << other[1]);
  const auto nfds = static_cast<uint64_t>(std::max(umd[1], other[1]) + 1);
  r = DispatchSyscall({0x5d, {nfds, guest(readfds), 0, 0, 0, 0}});
  Check(r.value == 1 && *readfds == (uint64_t {1} << umd[1]), "select reports only the socket with pending bytes");
  r = DispatchSyscall({0x1d, {static_cast<uint64_t>(umd[1]), guest(request), 36, 0, 0, 0}});
  std::array<uint8_t, 36> expected {};
  const std::array<uint32_t, 9> packet {0x554d4420, 0xffffffff, 0x22, 0, 1, 0, 0, 0, 0};
  const uint32_t magic = packet[0];
  std::memcpy(expected.data(), packet.data(), expected.size());
  Check(r.value == 36 && std::memcmp(request, expected.data(), 36) == 0, "recvfrom returns the child's request unchanged");
  Check(wait(50).value == 0, "reading the request clears level readiness");
  std::memset(reply, 0, 16);
  std::memcpy(reply, &magic, 4);
  r = DispatchSyscall({0x85, {static_cast<uint64_t>(umd[1]), guest(reply), 16, 0x20000, 0, 0}});
  Check(r.value == 16, "sendto delivers SysAv's 16-byte reply with its flags");
  const DWORD child_wait = WaitForSingleObject(process.hProcess, 30000);
  if (child_wait != WAIT_OBJECT_0) {
    TerminateJobObject(job, 10);
    WaitForSingleObject(process.hProcess, 1000);
  }
  DWORD code = 1;
  const bool exited = GetExitCodeProcess(process.hProcess, &code) != FALSE;
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  CloseHandle(job);
  CloseHandle(go);
  Check(child_wait == WAIT_OBJECT_0 && exited && code == 0, "child receives the reply and exits cleanly");

  r = wait(2000);
  Check(r.value == 1 && received->ident == static_cast<uintptr_t>(umd[1]) && received->data == 0 &&
            (received->flags & 0x8000u) != 0,
        "child exit surfaces EV_EOF on the SysAv end");
  r = DispatchSyscall({0x1d, {static_cast<uint64_t>(umd[1]), guest(request), 36, 0, 0, 0}});
  Check(r.value == 0, "recvfrom after peer exit reads EOF");

  r = DispatchSyscall({0x1d, {static_cast<uint64_t>(mbus), guest(request), 36, 0, 0, 0}});
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_ENOSYS, "recvfrom on a non-socket is not modeled");
  r = DispatchSyscall({0x1d, {static_cast<uint64_t>(other[1]), 0x1000, 36, 0, 0, 0}});
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_EFAULT, "recvfrom into unmapped memory is EFAULT");
  r = DispatchSyscall({0x1d, {static_cast<uint64_t>(other[1]), guest(request), 36, 0, guest(reply), 0}});
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_ENOSYS, "recvfrom with a source address is not modeled");
  r = DispatchSyscall({0x85, {static_cast<uint64_t>(other[1]), guest(reply), 16, 1, 0, 0}});
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_EOPNOTSUPP, "sendto rejects flags SysAv does not pass");
  *readfds = uint64_t {1} << other[1];
  r = DispatchSyscall({0x5d, {nfds, guest(readfds), guest(readfds), 0, 0, 0}});
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_ENOSYS, "select with a write set is not modeled");
  r = DispatchSyscall({0x5d, {nfds, 0x1000, 0, 0, 0, 0}});
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_EFAULT, "select on an unmapped read set is EFAULT");
  *readfds = uint64_t {1} << mbus;
  r = DispatchSyscall({0x5d, {static_cast<uint64_t>(mbus + 1), guest(readfds), 0, 0, 0, 0}});
  Check(r.value == -1 && r.posix_errno == Libs::Posix::POSIX_ENOSYS && *readfds == (uint64_t {1} << mbus),
        "select on a non-socket is refused without touching the set");

  // Kyty drops a closed fd's READ registration at the next poll rather than inside close.
  Check(FileSystem::KernelClose(umd[1]) == OK && wait(30).value == 0 &&
            EQ::KernelDeleteReadEvent(queue, umd[1]) == KERNEL_ERROR_ENOENT,
        "closing the SysAv end drops its READ registration without a stale event");
  Check(EQ::KernelDeleteReadEvent(queue, other[1]) == OK && EQ::KernelDeleteReadEvent(queue, other[1]) == KERNEL_ERROR_ENOENT &&
            EQ::KernelDeleteReadEvent(queue, mbus) == OK &&
            EQ::KernelDeleteEvent(queue, 1, EQ::KERNEL_EVFILT_USER) == OK &&
            EQ::KernelDeleteEvent(queue, 1, EQ::KERNEL_EVFILT_NOTIFY) == OK,
        "the remaining four registrations are present exactly once");

  std::atomic<int> failures {0};
  std::vector<std::thread> workers;
  for (int t = 0; t < 4; ++t) {
    workers.emplace_back([&, t] {
      FileSystem::ScopedGuestDescriptorTable table;
      int a[2] {-1, -1}, b[2] {-1, -1};
      const int own = FileSystem::CreateNativeKqueueDescriptor();
      auto* own_changes = reinterpret_cast<EQ::KernelEvent*>(base + 0x1000 + t * 0x400);
      auto* own_event = reinterpret_cast<EQ::KernelEvent*>(base + 0x1000 + t * 0x400 + 0x200);
      auto* own_timeout = reinterpret_cast<KernelTimespec*>(base + 0x1000 + t * 0x400 + 0x240);
      auto* own_buffer = base + 0x1000 + t * 0x400 + 0x280;
      if (FileSystem::CreateGuestSocketPair(a) != OK || FileSystem::CreateGuestSocketPair(b) != OK || own < 3) {
        failures.fetch_add(1);
        return;
      }
      std::memcpy(own_changes, changes, 2 * sizeof(EQ::KernelEvent));
      const int reads[3] {a[1], b[1], b[0]};
      for (int i = 0; i < 3; ++i) {
        own_changes[2 + i] = {};
        own_changes[2 + i].ident = static_cast<uintptr_t>(reads[i]);
        own_changes[2 + i].filter = EQ::KERNEL_EVFILT_READ;
        own_changes[2 + i].flags = 1;
      }
      for (int round = 0; round < 20; ++round) {
        if (DispatchSyscall({0x16b, {static_cast<uint64_t>(own), guest(own_changes), 5, 0, 0, 0}}).value != 0) {
          failures.fetch_add(1);
          return;
        }
        const size_t size = 10 + t;
        std::memset(own_buffer, 0x30 + t, size);
        if (FileSystem::SendGuestSocket(a[0], own_buffer, size, 0) != static_cast<int64_t>(size)) {
          failures.fetch_add(1);
          return;
        }
        own_timeout->tv_sec = 5;
        own_timeout->tv_nsec = 0;
        const auto got = DispatchSyscall({0x16b, {static_cast<uint64_t>(own), 0, 0, guest(own_event), 1, guest(own_timeout)}});
        std::memset(own_buffer, 0, size);
        const auto read = DispatchSyscall({0x1d, {static_cast<uint64_t>(a[1]), guest(own_buffer), size, 0, 0, 0}});
        if (got.value != 1 || own_event->ident != static_cast<uintptr_t>(a[1]) ||
            own_event->data != static_cast<intptr_t>(size) || read.value != static_cast<int64_t>(size) ||
            own_buffer[0] != 0x30 + t || own_buffer[size - 1] != 0x30 + t) {
          failures.fetch_add(1);
          return;
        }
      }
    });
  }
  for (auto& worker: workers) worker.join();
  Check(failures.load() == 0, "concurrent SysAv tables register, wake and read without cross-talk");

  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), 0x4000) == OK, "release SysAv guest storage");
  Check(FileSystem::KernelClose(other[0]) == OK && FileSystem::KernelClose(other[1]) == OK &&
            FileSystem::KernelClose(mbus) == OK && FileSystem::KernelClose(kq) == OK && !EQ::KernelPinEqueue(queue),
        "close every SysAv descriptor and release the kqueue");
  std::printf("SysAvKeventUmdTests: atomic_refusal=pass in_order_ebadf=pass no_premature_ready=pass crosshost_read=pass "
              "select=pass recv_bytes=pass level_clear=pass reply=pass eof=pass invalid=pass close=pass concurrency=pass\n");
#endif
}
