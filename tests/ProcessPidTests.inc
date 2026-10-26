#if defined(_WIN32)
PROCESS_INFORMATION StartProcessPidWorker(const std::string& scope,
                                         const std::filesystem::path& output,
                                         int guest_pid, bool nested, bool suspended) {
  std::array<wchar_t, 32768> executable {};
  const DWORD length = GetModuleFileNameW(nullptr, executable.data(), executable.size());
  Check(length != 0 && length < executable.size(), "find PID allocator test executable");
  std::wstring command = L"\"" + std::wstring(executable.data()) + L"\" --process-pid-child " +
      std::wstring(scope.begin(), scope.end()) + L" \"" + output.wstring() + L"\" " +
      std::to_wstring(guest_pid) + (nested ? L" nested" : L" leaf");
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process {};
  Check(CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW | (suspended ? CREATE_SUSPENDED : 0), nullptr, nullptr,
        &startup, &process) != FALSE, "start PID allocator subprocess");
  return process;
}

void FinishProcessPidWorker(PROCESS_INFORMATION& process, DWORD timeout) {
  Check(WaitForSingleObject(process.hProcess, timeout) == WAIT_OBJECT_0,
        "PID allocator subprocess finishes within bound");
  DWORD status = 1;
  Check(GetExitCodeProcess(process.hProcess, &status) && status == 0,
        "PID allocator subprocess passed");
  Check(CloseHandle(process.hThread) && CloseHandle(process.hProcess),
        "release PID allocator subprocess handles");
}
#endif

int RunProcessPidChild(int argc, char** argv) {
  if (argc != 6 || std::strcmp(argv[1], "--process-pid-child") != 0) return -1;
#if defined(_WIN32)
  using namespace Libs::LibKernel;
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", argv[2]) == 0 &&
        _putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1") == 0,
        "set subprocess PID allocation scope");
  Process::ScopedGuestProcessPid identity(std::atoi(argv[4]));
  const auto output = Common::PathFromUtf8(argv[3]);
  const std::string gate_name = "Local\\kyty_pid_test_" + std::string(argv[2]) + "_start";
  HANDLE gate = OpenEventA(SYNCHRONIZE, FALSE, gate_name.c_str());
  Check(gate != nullptr && WaitForSingleObject(gate, 20000) == WAIT_OBJECT_0,
        "wait for concurrent allocator workers");
  Check(CloseHandle(gate), "release allocator worker gate");
  const bool nested = std::strcmp(argv[5], "nested") == 0;
  std::vector<int> pids;
  for (unsigned i = 0; i < (nested ? 64u : 16u); ++i) {
    const int pid = Process::AllocateRforkChildPid();
    Check(pid >= 1000 && pid != Process::GetPid(), "subprocess reserves a distinct PID");
    pids.push_back(pid);
  }
  if (nested) {
    const int child_pid = Process::AllocateRforkChildPid();
    Check(child_pid >= 1000, "reserve nested host process PID");
    pids.push_back(child_pid);
    auto descendant = StartProcessPidWorker(argv[2], output.wstring() + L".nested", child_pid, false, false);
    FinishProcessPidWorker(descendant, 20000);
  }
  std::ofstream stream(output);
  for (const int pid: pids) stream << pid << '\n';
  Check(stream.good(), "write subprocess PID reservations");
  return 0;
#else
  return 2;
#endif
}

void CheckProcessPids(const std::filesystem::path& root) {
#if defined(_WIN32)
  using namespace Libs::LibKernel;
  const char* keys[] = {"KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE",
      "KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET"};
  std::array<std::string, 3> saved;
  for (size_t i = 0; i < saved.size(); ++i) {
    const char* value = std::getenv(keys[i]);
    saved[i] = value == nullptr ? "" : value;
    Check(_putenv_s(keys[i], "") == 0, "clear inherited PID allocation scope");
  }
  const int local = Process::AllocateRforkChildPid();
  Check(local >= 1000 && Process::AllocateRforkChildPid() == local + 1,
        "unscoped PID allocator retains its host-local sequence");
  char scope_bytes[21] {};
  std::snprintf(scope_bytes, sizeof(scope_bytes), "p%08lx%08lx",
      GetCurrentProcessId(), static_cast<unsigned long>(GetTickCount()));
  const std::string scope = scope_bytes;
  const auto set_scope = [&](const std::string& value) {
    Check(_putenv_s(keys[0], value.c_str()) == 0 && _putenv_s(keys[1], "1") == 0,
          "select isolated PID allocation scope");
  };
  Process::ScopedGuestProcessPid identity(100);
  set_scope(scope);
  Process::PublishToScope();
  const std::string allocation_name = "Local\\kyty_ps5_" + scope + "_pid_allocator_v1";
  HANDLE published = OpenFileMappingA(FILE_MAP_READ, FALSE, allocation_name.c_str());
  Check(published != nullptr && CloseHandle(published),
        "publishing a process retains its allocator before any child reservation");
  std::vector<int> pids {Process::AllocateRforkChildPid()};
  Check(pids.front() == 1000, "fresh scope starts its own PID allocation sequence");
  const std::string gate_name = "Local\\kyty_pid_test_" + scope + "_start";
  HANDLE gate = CreateEventA(nullptr, TRUE, FALSE, gate_name.c_str());
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  Check(gate != nullptr && job != nullptr &&
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
        "contain all PID allocator test descendants");
  std::array<PROCESS_INFORMATION, 4> workers {};
  for (size_t i = 0; i < workers.size(); ++i) {
    const int pid = Process::AllocateRforkChildPid();
    pids.push_back(pid);
    workers[i] = StartProcessPidWorker(scope, root / ("pid_worker_" + std::to_string(i)), pid, true, true);
    Check(AssignProcessToJobObject(job, workers[i].hProcess) &&
          ResumeThread(workers[i].hThread) != DWORD(-1), "contain and resume PID allocator worker");
  }
  Check(SetEvent(gate), "release concurrent PID allocator workers");
  const ULONGLONG deadline = GetTickCount64() + 30000;
  for (auto& worker: workers) {
    const ULONGLONG now = GetTickCount64();
    FinishProcessPidWorker(worker, now < deadline ? static_cast<DWORD>(deadline - now) : 0);
  }
  const auto append = [&](const std::filesystem::path& file, size_t expected) {
    std::ifstream stream(file);
    Check(stream.is_open(), "open cross-host PID results");
    size_t count = 0;
    for (int pid; stream >> pid;) {
      pids.push_back(pid);
      ++count;
    }
    Check(stream.eof() && count == expected, "cross-host PID result count");
  };
  for (size_t i = 0; i < workers.size(); ++i) {
    const auto output = root / ("pid_worker_" + std::to_string(i));
    append(output, 65);
    append(output.wstring() + L".nested", 16);
  }
  const int sequential_pid = Process::AllocateRforkChildPid();
  pids.push_back(sequential_pid);
  auto sequential = StartProcessPidWorker(scope, root / "pid_sequential", sequential_pid, false, true);
  Check(AssignProcessToJobObject(job, sequential.hProcess) &&
        ResumeThread(sequential.hThread) != DWORD(-1), "contain later PID allocator host");
  FinishProcessPidWorker(sequential, 20000);
  append(root / "pid_sequential", 16);
  pids.push_back(Process::AllocateRforkChildPid());
  std::sort(pids.begin(), pids.end());
  for (size_t i = 0; i < pids.size(); ++i) {
    Check(pids[i] == 1000 + static_cast<int>(i),
          "concurrent and nested hosts never reuse or skip reserved PID identities");
  }
  const std::string handoff_scope = scope + "h";
  const std::string handoff_gate_name = "Local\\kyty_pid_test_" + handoff_scope + "_start";
  HANDLE handoff_gate = CreateEventA(nullptr, TRUE, TRUE, handoff_gate_name.c_str());
  Check(handoff_gate != nullptr, "create independent host handoff gate");
  for (unsigned host = 0; host < 2; ++host) {
    const auto output = root / ("pid_handoff_" + std::to_string(host));
    auto worker = StartProcessPidWorker(handoff_scope, output, 100, false, true);
    Check(AssignProcessToJobObject(job, worker.hProcess) &&
          ResumeThread(worker.hThread) != DWORD(-1), "contain isolated handoff host");
    FinishProcessPidWorker(worker, 20000);
    std::ifstream stream(output);
    Check(stream.is_open(), "open sequential host handoff reservations");
    for (unsigned i = 0; i < 16; ++i) {
      int pid = 0;
      Check(bool(stream >> pid) && pid == 1000 + static_cast<int>(host * 16 + i),
            "allocator history survives all participating host handles closing");
    }
  }
  Check(CloseHandle(handoff_gate), "release host handoff gate");
  Check(CloseHandle(gate) && CloseHandle(job), "release PID allocator containment");
  set_scope(scope + "b");
  Check(Process::AllocateRforkChildPid() == 1000, "separate scope has independent PID identities");
  set_scope(scope);
  Check(Process::AllocateRforkChildPid() == pids.back() + 1,
        "returning to a live scope retains its allocation history");
  set_scope(scope + "x");
  {
    Process::ScopedGuestProcessPid last_parent(std::numeric_limits<int>::max() - 1);
    Check(Process::AllocateRforkChildPid() == std::numeric_limits<int>::max(),
          "last representable PID can be reserved above the parent");
  }
  Check(Process::AllocateRforkChildPid() == KERNEL_ERROR_EAGAIN &&
        Process::AllocateRforkChildPid() == KERNEL_ERROR_EAGAIN,
        "exhausted PID scope never wraps or reuses identities");
  const std::string invalid_scope = scope + "c";
  const auto invalid_path = std::filesystem::temp_directory_path() /
      ("kyty_ps5_" + invalid_scope + "_pids_v1.bin");
  const std::array<uint64_t, 2> invalid_state {0x0123456789abcdefULL, 1234};
  {
    std::ofstream stream(invalid_path, std::ios::binary);
    stream.write(reinterpret_cast<const char*>(invalid_state.data()), sizeof(invalid_state));
    Check(stream.good(), "write invalid existing allocator state");
  }
  set_scope(invalid_scope);
  Check(Process::AllocateRforkChildPid() == KERNEL_ERROR_EIO &&
        Process::AllocateRforkChildPid() == KERNEL_ERROR_EIO,
        "invalid existing scope state fails without a local PID fallback");
  std::array<uint64_t, 2> retained_state {};
  {
    std::ifstream stream(invalid_path, std::ios::binary);
    stream.read(reinterpret_cast<char*>(retained_state.data()), sizeof(retained_state));
    Check(stream.good() && retained_state == invalid_state,
          "invalid allocator state is preserved instead of reset");
  }
  Check(_putenv_s(keys[0], "") == 0, "leave scoped PID allocator");
  Check(Process::AllocateRforkChildPid() == local + 2,
        "scope allocations do not consume the unscoped host sequence");
  for (size_t i = 0; i < saved.size(); ++i) {
    Check(_putenv_s(keys[i], saved[i].c_str()) == 0, "restore PID allocation environment");
  }
  std::printf("ProcessPidTests: concurrent_hosts=4 nested_hosts=4 later_host=1 isolation=pass exhaustion=pass\n");
#endif
}

void CheckKernProcPid() {
#if defined(_WIN32)
  using namespace Libs::LibKernel;
  const char* keys[] = {"KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", "KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY"};
  std::array<std::string, 2> saved;
  for (size_t i = 0; i < saved.size(); ++i) {
    const char* value = std::getenv(keys[i]);
    saved[i] = value == nullptr ? "" : value;
    Check(_putenv_s(keys[i], "") == 0, "clear inherited kern.proc.pid scope");
  }
  void* guest = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&guest, 0x4000, 3, 0, "kern_proc_pid_fixture") == OK,
        "map kern.proc.pid guest fixture");
  auto* base = static_cast<uint8_t*>(guest);
  // per-thread mib/length/record slices so the race doesn't share guest memory
  const auto query = [&](size_t slice, int pid, uint64_t capacity, bool with_output) {
    auto* mib = reinterpret_cast<int32_t*>(base + slice);
    auto* length = reinterpret_cast<uint64_t*>(base + slice + 0x20);
    mib[0] = 1; mib[1] = 14; mib[2] = 1; mib[3] = pid;
    *length = capacity;
    std::memset(base + slice + 0x100, 0xA5, 0x448);
    return Libs::NativeKernelBridge::DispatchSyscall({0xca, {reinterpret_cast<uint64_t>(mib), 4,
        with_output ? reinterpret_cast<uint64_t>(base + slice + 0x100) : 0, reinterpret_cast<uint64_t>(length), 0, 0}});
  };
  const auto length_of = [&](size_t slice) { return *reinterpret_cast<uint64_t*>(base + slice + 0x20); };
  const auto field = [&](size_t offset) {
    int32_t value = 0;
    std::memcpy(&value, base + 0x100 + offset, sizeof(value));
    return value;
  };
  const auto failed = [](const Libs::NativeKernelBridge::Reply& reply, int error) {
    return reply.value == -1 && reply.posix_errno == error;
  };
  Process::ScopedGuestProcessPid identity(100);
  auto reply = query(0, 100, 0x448, true);
  bool clean = true;
  for (size_t i = 4; i < 0x448; ++i) {
    if (i >= 0x48 && i < 0x4c) continue;
    if (base[0x100 + i] != 0) clean = false;
  }
  Check(reply.value == 0 && reply.posix_errno == 0 && length_of(0) == 0x448 &&
        field(0) == 0x448 && field(0x48) == 100 && clean,
        "kern.proc.pid self read returns a zeroed kinfo_proc with structsize and pid");
  reply = query(0, 100, 0x448, false);
  Check(reply.value == 0 && reply.posix_errno == 0 && length_of(0) == 0x448,
        "kern.proc.pid size query reports 0x448 without output");
  reply = query(0, 100, 0x40, true);
  Check(failed(reply, Libs::Posix::POSIX_ENOMEM) && length_of(0) == 0x40 && field(0) == 0x448 &&
        base[0x100 + 0x40] == 0xA5,
        "kern.proc.pid short buffer copies the prefix and fails with ENOMEM");
  Check(failed(query(0, 1000, 0x448, true), Libs::Posix::POSIX_ENOSYS) && base[0x100] == 0xA5,
        "kern.proc.pid without a process registry does not guess a foreign pid");
  Check(failed(query(0, 0, 0x448, true), Libs::Posix::POSIX_ENOSYS) &&
        failed(query(0, 100000, 0x448, true), Libs::Posix::POSIX_ENOSYS) &&
        failed(query(0, -1, 0x448, true), Libs::Posix::POSIX_ESRCH),
        "kern.proc.pid leaves proc0 and thread ids unmodeled and rejects negative pids");
  {
    auto* mib = reinterpret_cast<int32_t*>(base);
    auto* length = reinterpret_cast<uint64_t*>(base + 0x20);
    mib[0] = 1; mib[1] = 14; mib[2] = 1; mib[3] = 100; *length = 0x448;
    std::memset(base + 0x100, 0xA5, 0x448);
    reply = Libs::NativeKernelBridge::DispatchSyscall({0xca, {reinterpret_cast<uint64_t>(mib), 4,
        reinterpret_cast<uint64_t>(base + 0x100), reinterpret_cast<uint64_t>(length),
        reinterpret_cast<uint64_t>(base + 0x800), 0x448}});
    Check(failed(reply, Libs::Posix::POSIX_ENOSYS) && base[0x100] == 0xA5,
          "kern.proc.pid write is not acknowledged");
    const auto three = Libs::NativeKernelBridge::DispatchSyscall({0xca, {reinterpret_cast<uint64_t>(mib), 3,
        reinterpret_cast<uint64_t>(base + 0x100), reinterpret_cast<uint64_t>(length), 0, 0}});
    const auto five = Libs::NativeKernelBridge::DispatchSyscall({0xca, {reinterpret_cast<uint64_t>(mib), 5,
        reinterpret_cast<uint64_t>(base + 0x100), reinterpret_cast<uint64_t>(length), 0, 0}});
    Check(three.value == KERNEL_ERROR_EINVAL && five.value == KERNEL_ERROR_EINVAL,
          "kern.proc nodes without exactly one pid level stay EINVAL");
  }
  char scope_bytes[21] {};
  std::snprintf(scope_bytes, sizeof(scope_bytes), "k%08lx%08lx",
      GetCurrentProcessId(), static_cast<unsigned long>(GetTickCount()));
  const std::string scope = scope_bytes;
  Check(_putenv_s(keys[0], scope.c_str()) == 0 && _putenv_s(keys[1], "1") == 0,
        "select isolated kern.proc.pid scope");
  Process::PublishToScope();
  const auto record_path = [&](int pid) {
    return std::filesystem::temp_directory_path() / ("kyty_ps5_" + scope + "_pid_" + std::to_string(pid) + ".txt");
  };
  const auto write_record = [&](int pid, const std::string& text) {
    std::ofstream stream(record_path(pid), std::ios::trunc);
    stream << text << '\n';
    Check(stream.good(), "write kern.proc.pid scope record");
  };
  const auto birth_of = [](HANDLE process) {
    FILETIME created {}, exited {}, kernel {}, user {};
    Check(GetProcessTimes(process, &created, &exited, &kernel, &user) != FALSE, "read fixture host birth");
    return (static_cast<uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
  };
  const auto birth_text = [](uint64_t birth) {
    char text[32] {};
    std::snprintf(text, sizeof(text), "birth=%016llx", static_cast<unsigned long long>(birth));
    return std::string(text);
  };
  const char* source = nullptr;
  uint32_t host_pid = 0;
  {
    Process::ScopedGuestProcessPid other(90001);
    Check(Process::QueryGuestProcessExists(100, &source, &host_pid) == 0 &&
          std::strcmp(source, "scope_record") == 0 && host_pid == GetCurrentProcessId() &&
          query(0, 100, 0x448, true).value == 0 && field(0x48) == 100,
          "kern.proc.pid finds a live published peer through its birth-pinned record");
  }
  Check(failed(query(0, 90002, 0x448, true), Libs::Posix::POSIX_ESRCH),
        "kern.proc.pid reports ESRCH for an unpublished pid");
  Process::RegisterRforkChild(90003, 100);
  Check(Process::QueryGuestProcessExists(90003, &source, &host_pid) == 0 &&
        std::strcmp(source, "rfork_child") == 0 && query(0, 90003, 0x448, true).value == 0,
        "kern.proc.pid sees a running in-process rfork child");
  Process::NotifyRforkChildExited(90003, 0);
  Check(failed(query(0, 90003, 0x448, true), Libs::Posix::POSIX_ESRCH),
        "kern.proc.pid rejects an exited unreaped child");
  uint32_t status = 0;
  Check(Process::WaitForChild(90003, &status, 1) == 90003 && Process::ReleaseReapedRforkChild(90003) &&
        failed(query(0, 90003, 0x448, true), Libs::Posix::POSIX_ESRCH),
        "kern.proc.pid rejects a reaped child");
  auto worker = StartProcessPidWorker(scope, record_path(90004).wstring() + L".out", 90004, false, true);
  // Check() aborts, and a suspended worker left behind keeps this exe locked for the next build.
  HANDLE worker_job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits {};
  job_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  Check(worker_job != nullptr &&
        SetInformationJobObject(worker_job, JobObjectExtendedLimitInformation, &job_limits, sizeof(job_limits)) &&
        AssignProcessToJobObject(worker_job, worker.hProcess), "tie kern.proc.pid fixture host to this test");
  const uint64_t worker_birth = birth_of(worker.hProcess);
  write_record(90004, std::to_string(worker.dwProcessId) + " 0 " + birth_text(worker_birth));
  Check(query(0, 90004, 0x448, true).value == 0 && field(0x48) == 90004,
        "kern.proc.pid accepts a live host whose creation time matches the record");
  write_record(90004, std::to_string(worker.dwProcessId) + " 0 " + birth_text(worker_birth + 1));
  Check(failed(query(0, 90004, 0x448, true), Libs::Posix::POSIX_ESRCH),
        "kern.proc.pid treats a reused host pid as a different process");
  write_record(90004, std::to_string(worker.dwProcessId) + " 0");
  Check(failed(query(0, 90004, 0x448, true), Libs::Posix::POSIX_ENOSYS),
        "kern.proc.pid does not trust a record without a birth marker");
  write_record(90004, std::to_string(worker.dwProcessId) + " 0 " + birth_text(worker_birth) + " " + birth_text(worker_birth));
  Check(failed(query(0, 90004, 0x448, true), Libs::Posix::POSIX_ENOSYS),
        "kern.proc.pid does not trust duplicate birth markers");
  Process::RegisterRforkChild(90005, 100);
  Check(Process::MarkRforkChildExecCommitted(90005, worker.dwProcessId, "/fixture/kern_proc_pid"),
        "commit fixture exec child");
  Check(!std::filesystem::exists(record_path(90005)) && Process::QueryGuestProcessExists(90005, &source, &host_pid) == 0 &&
        std::strcmp(source, "exec_commit") == 0 && host_pid == worker.dwProcessId && query(0, 90005, 0x448, true).value == 0,
        "kern.proc.pid sees an exec-committed child before it publishes its own record");
  write_record(90005, std::to_string(GetCurrentProcessId()) + " 0 " + birth_text(birth_of(GetCurrentProcess())));
  Check(query(0, 90005, 0x448, true).value == 0 && Process::QueryGuestProcessExists(90005, &source, &host_pid) == 0 &&
        host_pid == worker.dwProcessId,
        "kern.proc.pid answers an exec-committed child from the commit, not from its record");
  write_record(90004, std::to_string(worker.dwProcessId) + " 0 " + birth_text(worker_birth));
  Check(TerminateProcess(worker.hProcess, 7) && WaitForSingleObject(worker.hProcess, 20000) == WAIT_OBJECT_0,
        "end kern.proc.pid fixture host");
  Check(failed(query(0, 90004, 0x448, true), Libs::Posix::POSIX_ESRCH),
        "kern.proc.pid reports ESRCH once the recorded host has exited");
  Check(failed(query(0, 90005, 0x448, true), Libs::Posix::POSIX_ESRCH),
        "kern.proc.pid reports ESRCH for an exec child whose host exited before its status arrived");
  Check(failed(query(0, 99999, 0x448, true), Libs::Posix::POSIX_ESRCH) &&
        failed(query(0, 99999, 0x448, false), Libs::Posix::POSIX_ESRCH),
        "kern.proc.pid size and record queries both fail with ESRCH for an absent pid at PID_MAX");
  Process::NotifyRforkChildExited(90005, 0);
  Check(failed(query(0, 90005, 0x448, true), Libs::Posix::POSIX_ESRCH),
        "kern.proc.pid rejects an exec child after its exit status is recorded");
  Check(CloseHandle(worker.hThread) && CloseHandle(worker.hProcess) && CloseHandle(worker_job),
        "release kern.proc.pid fixture host");
  Process::RegisterRforkChild(90006, 100);
  std::atomic<bool> stop {false};
  std::atomic<uint32_t> live {0}, gone {0}, other_result {0}, revived {0};
  std::thread racer([&] {
    Process::ScopedGuestProcessPid racer_identity(100);
    bool seen_gone = false;
    while (!stop.load()) {
      const auto result = query(0x1000, 90006, 0x448, true);
      if (result.value == 0 && *reinterpret_cast<int32_t*>(base + 0x1100 + 0x48) == 90006) {
        ++live;
        if (seen_gone) ++revived;
      } else if (failed(result, Libs::Posix::POSIX_ESRCH)) {
        ++gone;
        seen_gone = true;
      } else {
        ++other_result;
      }
    }
  });
  while (live.load() < 64) std::this_thread::yield();
  Process::NotifyRforkChildExited(90006, 0);
  while (gone.load() < 64) std::this_thread::yield();
  stop = true;
  racer.join();
  Check(other_result.load() == 0 && revived.load() == 0 && failed(query(0, 90006, 0x448, true), Libs::Posix::POSIX_ESRCH),
        "kern.proc.pid racing a child exit only ever moves from live to ESRCH");
  Check(Process::WaitForChild(90006, &status, 1) == 90006 && Process::ReleaseReapedRforkChild(90006),
        "reap kern.proc.pid race child");
  std::error_code ignored;
  for (const int pid: {100, 90004, 90005}) std::filesystem::remove(record_path(pid), ignored);
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(guest), 0x4000) == OK, "unmap kern.proc.pid guest fixture");
  for (size_t i = 0; i < saved.size(); ++i) {
    Check(_putenv_s(keys[i], saved[i].c_str()) == 0, "restore kern.proc.pid environment");
  }
  std::printf("ProcessPidTests: kern_proc_pid self=pass size=pass short=pass record=pass reuse=pass exit=pass race=live%u/gone%u\n",
              live.load(), gone.load());
#endif
}
