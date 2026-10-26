class GuestWait7Environment {
public:
  GuestWait7Environment(const char* key, const char* value): m_key(key) {
    const char* current = std::getenv(key);
    m_present = current != nullptr;
    if (m_present) m_value = current;
    Set(value);
  }

  ~GuestWait7Environment() {
#if defined(_WIN32)
    _putenv_s(m_key.c_str(), m_present ? m_value.c_str() : "");
#else
    if (m_present) {
      setenv(m_key.c_str(), m_value.c_str(), 1);
    } else {
      unsetenv(m_key.c_str());
    }
#endif
  }

  KYTY_CLASS_NO_COPY(GuestWait7Environment);

private:
  void Set(const char* value) {
#if defined(_WIN32)
    Check(_putenv_s(m_key.c_str(), value) == 0, "set wait7 diagnostic environment");
#else
    Check(setenv(m_key.c_str(), value, 1) == 0, "set wait7 diagnostic environment");
#endif
  }

  std::string m_key;
  std::string m_value;
  bool m_present = false;
};

constexpr int kGuestWait7HotOwner = 0x71197002;

void CheckGuestWait7Frontier(bool log_audit, const std::filesystem::path& log_path) {
  using namespace Libs;
  using namespace Libs::LibKernel;

  GuestWait7Environment wait_enabled("KYTY_DIAGNOSTIC_MINI_SYSCORE_WAIT4_NATIVE_SYSCALL", "1");
  void* mapping = nullptr;
  constexpr size_t page_size = 0x4000;
  Check(Memory::KernelMapNamedFlexibleMemory(&mapping, page_size, 3, 0, "wait7-frontier") == OK,
        "map wait7 status page");
  auto* status = static_cast<uint32_t*>(mapping);
  constexpr uint32_t sentinel = 0xa5c31977u;
  constexpr int owner = 0x71197000;
  constexpr int other = 0x71197001;
  constexpr int child = 0x61197000;
  Process::RegisterRforkChild(child, owner);
  *status = sentinel;
  {
    Process::ScopedGuestProcessPid identity(other);
    const auto result = NativeKernelBridge::DispatchSyscall(
        {0x07, {static_cast<uint64_t>(static_cast<int64_t>(child)),
                reinterpret_cast<uint64_t>(status), 0, 0, 0, 0}});
    Check(result.value == -1 && result.posix_errno == Posix::POSIX_ECHILD &&
              *status == sentinel,
          "wait7 isolates child ownership and preserves status on ECHILD");
    Check(!Process::ReleaseReapedRforkChild(child),
          "wait7 refuses cleanup before a child is reaped");
  }

  std::atomic<bool> entered {false};
  std::atomic<bool> finished {false};
  NativeKernelBridge::Reply waited {};
  std::thread waiter([&] {
    Process::ScopedGuestProcessPid identity(owner);
    entered.store(true, std::memory_order_release);
    waited = NativeKernelBridge::DispatchSyscall(
        {0x07, {static_cast<uint64_t>(static_cast<int64_t>(child)),
                reinterpret_cast<uint64_t>(status), 0, 0, 0, 0}});
    finished.store(true, std::memory_order_release);
  });
  while (!entered.load(std::memory_order_acquire)) std::this_thread::yield();
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  Check(!finished.load(std::memory_order_acquire), "wait7 blocks while an owned child is live");
  constexpr uint32_t exit_status = 0x5a00;
  Process::NotifyRforkChildExited(child, exit_status);
  waiter.join();
  Check(waited.value == child && waited.posix_errno == 0 && *status == exit_status,
        "wait7 returns the exact reaped child and status");
  {
    Process::ScopedGuestProcessPid identity(other);
    Check(!Process::ReleaseReapedRforkChild(child) && Process::IsTrackedRforkChild(child),
          "wait7 rejects reaped-record cleanup by a foreign parent");
  }
  *status = sentinel;
  {
    Process::ScopedGuestProcessPid identity(owner);
    const auto result = NativeKernelBridge::DispatchSyscall(
        {0x07, {static_cast<uint64_t>(static_cast<int64_t>(child)),
                reinterpret_cast<uint64_t>(status), 0, 0, 0, 0}});
    Check(result.value == -1 && result.posix_errno == Posix::POSIX_ECHILD &&
              *status == sentinel,
          "wait7 cannot reap twice and preserves status on ECHILD");
    Check(Process::ReleaseReapedRforkChild(child) &&
              !Process::IsTrackedRforkChild(child),
          "wait7 releases only the owner's reaped fixture");
  }

  uint64_t samples = 0;
  for (uint64_t ordinal = 1; ordinal <= 100000; ++ordinal) {
    if (NativeKernelBridge::ShouldLogMiniSyscallTrace(ordinal)) ++samples;
  }
  Check(samples == 74 &&
            !NativeKernelBridge::ShouldLogMiniSyscallTrace(0) &&
            NativeKernelBridge::ShouldLogMiniSyscallTrace(64) &&
            !NativeKernelBridge::ShouldLogMiniSyscallTrace(65) &&
            NativeKernelBridge::ShouldLogMiniSyscallTrace(128) &&
            !NativeKernelBridge::ShouldLogMiniSyscallTrace(100000),
        "wait7 trace policy is bounded to the initial window and powers of two");

  constexpr int empty_owner = 0x71197003;
  {
    Process::ScopedGuestProcessPid identity(empty_owner);
    const auto invalid = NativeKernelBridge::DispatchSyscall(
        {0x07, {UINT64_MAX, 1, 0, 0, 0, 0}});
    Check(invalid.value == -1 && invalid.posix_errno == Posix::POSIX_EFAULT,
          "wait7 validates status before reporting ECHILD");
    *status = sentinel;
    const auto valid = NativeKernelBridge::DispatchSyscall(
        {0x07, {UINT64_MAX, reinterpret_cast<uint64_t>(status), 0, 0, 0, 0}});
    Check(valid.value == -1 && valid.posix_errno == Posix::POSIX_ECHILD &&
              *status == sentinel,
          "wait7 revalidates each status pointer and preserves it on ECHILD");
  }

  if (log_audit) {
    GuestWait7Environment trace_enabled(
        "KYTY_DIAGNOSTIC_SYSCORE_SIGPROCMASK_LOOP_TRACE", "1");
    Log::Flush();
    std::error_code error;
    const uintmax_t before = std::filesystem::file_size(log_path, error);
    Check(!error, "measure wait7 log before hot loop");
    *status = sentinel;
    {
      Process::ScopedGuestProcessPid identity(kGuestWait7HotOwner);
      for (uint64_t call = 0; call < 100000; ++call) {
        const auto result = NativeKernelBridge::DispatchSyscall(
            {0x07, {UINT64_MAX, reinterpret_cast<uint64_t>(status), 0, 0, 0, 0}});
        Check(result.value == -1 && result.posix_errno == Posix::POSIX_ECHILD &&
                  *status == sentinel,
              "wait7 hot loop preserves ECHILD and status");
      }
    }
    Log::Flush();
    const uintmax_t after = std::filesystem::file_size(log_path, error);
    Check(!error && after >= before && after - before <= 64 * 1024,
          "wait7 hot loop logging remains bounded");
    Memory::VirtualQueryInfo query {};
    Check(Memory::KernelVirtualQuery(status, 0, &query, sizeof(query)) == OK,
          "public virtual query remains available after silent validation");
    Log::Flush();
    const uintmax_t control = std::filesystem::file_size(log_path, error);
    Check(!error && control > after,
          "public virtual query still writes diagnostics after silent validation");
  }

  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(mapping), page_size) == OK,
        "unmap wait7 status page");
  std::printf("GuestWait7FrontierTests: wait_semantics=pass samples=%llu hot_calls=%u\n",
      static_cast<unsigned long long>(samples), log_audit ? 100000u : 0u);
}

void CheckGuestWait7FrontierLog(const std::filesystem::path& log_path) {
  std::ifstream input(log_path);
  Check(input.is_open(), "open wait7 focused log");
  std::vector<uint64_t> ordinals;
  uint64_t marker_lines = 0;
  uint64_t markers = 0;
  std::string line;
  const std::string parent = "parent_pid=" + std::to_string(kGuestWait7HotOwner);
  while (std::getline(input, line)) {
    if (line.find("FIRST_FRAME_AUDIT MINI_NON_SIGPROCMASK_SYSCALL") != std::string::npos) {
      unsigned long long idx = 0;
      unsigned long long ordinal = 0;
      unsigned long long sig_calls = 0;
      int pid = 0;
      unsigned number = 0;
      const int fields = std::sscanf(line.c_str(),
          "FIRST_FRAME_AUDIT MINI_NON_SIGPROCMASK_SYSCALL idx=%llu ordinal=%llu"
          " pid=%d num=0x%x sig_calls=%llu",
          &idx, &ordinal, &pid, &number, &sig_calls);
      Check(fields == 5 && idx + 1 == ordinal && pid == kGuestWait7HotOwner && number == 7,
            "wait7 focused trace record identity and ordinal");
      ordinals.push_back(ordinal);
    }
    if (line.find("GUEST_WAIT4_ECHILD") != std::string::npos) {
      ++marker_lines;
      if (line.find(parent) != std::string::npos &&
          line.find("requested_pid=-1") != std::string::npos &&
          line.find("parent_total=0") != std::string::npos &&
          line.find("request_total=0") != std::string::npos &&
          line.find("status_written=0") != std::string::npos) {
        ++markers;
      }
    }
  }
  std::vector<uint64_t> expected;
  for (uint64_t ordinal = 1; ordinal <= 100000; ++ordinal) {
    if (Libs::NativeKernelBridge::ShouldLogMiniSyscallTrace(ordinal)) expected.push_back(ordinal);
  }
  Check(input.eof() && ordinals == expected && marker_lines == 1 && markers == 1,
        "wait7 focused log contains exact bounded samples and one exhausted-state marker");
}
