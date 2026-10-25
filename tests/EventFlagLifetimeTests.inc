#if defined(_WIN32)
std::string EventFlagLifetimeGate(const std::string& scope, const std::string& mode,
                                  const char* suffix) {
  return "Local\\kyty_evf_test_" + scope + "_" + mode + "_" + suffix;
}

void WaitForEventFlagWaiter(Libs::LibKernel::EventFlag::KernelEventFlag flag) {
  namespace Event = Libs::LibKernel::EventFlag;
  const ULONGLONG deadline = GetTickCount64() + 5000;
  for (;;) {
    uint64_t actual = 0;
    const int status = Event::KernelPollEventFlag(flag, 0x80, 1, &actual);
    if (status == Libs::LibKernel::KERNEL_ERROR_EPERM) return;
    Check(status == Libs::LibKernel::KERNEL_ERROR_EBUSY && GetTickCount64() < deadline,
          "eventflag waiter enters the single-waiter queue");
    Sleep(1);
  }
}

struct EventFlagLifetimeWorker {
  HANDLE ready = nullptr;
  HANDLE finish = nullptr;
  PROCESS_INFORMATION process {};
};

EventFlagLifetimeWorker StartEventFlagLifetimeWorker(const std::string& scope,
                                                    const std::string& mode, HANDLE job) {
  EventFlagLifetimeWorker worker;
  worker.ready = CreateEventA(nullptr, TRUE, FALSE,
      EventFlagLifetimeGate(scope, mode, "ready").c_str());
  worker.finish = CreateEventA(nullptr, TRUE, FALSE,
      EventFlagLifetimeGate(scope, mode, "finish").c_str());
  std::array<wchar_t, 32768> executable {};
  const DWORD length = GetModuleFileNameW(nullptr, executable.data(), executable.size());
  Check(worker.ready != nullptr && worker.finish != nullptr &&
        length != 0 && length < executable.size(), "prepare eventflag subprocess gates");
  std::wstring command = L"\"" + std::wstring(executable.data()) +
      L"\" --eventflag-lifetime-child " + std::wstring(scope.begin(), scope.end()) +
      L" " + std::wstring(mode.begin(), mode.end());
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  Check(CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup, &worker.process) &&
        AssignProcessToJobObject(job, worker.process.hProcess) &&
        ResumeThread(worker.process.hThread) != DWORD(-1),
        "start contained eventflag subprocess");
  Check(WaitForSingleObject(worker.ready, 10000) == WAIT_OBJECT_0,
        "eventflag subprocess reaches its operation");
  return worker;
}

void FinishEventFlagLifetimeWorker(EventFlagLifetimeWorker& worker) {
  Check(WaitForSingleObject(worker.process.hProcess, 10000) == WAIT_OBJECT_0,
        "eventflag subprocess finishes within bound");
  DWORD status = 1;
  Check(GetExitCodeProcess(worker.process.hProcess, &status) && status == 0,
        "eventflag subprocess assertions pass");
  Check(CloseHandle(worker.process.hThread) && CloseHandle(worker.process.hProcess) &&
        CloseHandle(worker.ready) && CloseHandle(worker.finish),
        "release eventflag subprocess handles");
}
#endif

int RunEventFlagLifetimeChild(int argc, char** argv) {
  if (argc != 4 || std::strcmp(argv[1], "--eventflag-lifetime-child") != 0) return -1;
#if defined(_WIN32)
  using namespace Libs::LibKernel;
  namespace Event = Libs::LibKernel::EventFlag;
  Common::InitializeThreads();
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", argv[2]) == 0 &&
        _putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1") == 0,
        "set eventflag subprocess scope");
  Process::ScopedGuestProcessPid identity(5000);
  const std::string mode = argv[3];
  HANDLE ready = OpenEventA(EVENT_MODIFY_STATE, FALSE,
      EventFlagLifetimeGate(argv[2], mode, "ready").c_str());
  HANDLE finish = OpenEventA(SYNCHRONIZE, FALSE,
      EventFlagLifetimeGate(argv[2], mode, "finish").c_str());
  Check(ready != nullptr && finish != nullptr, "open eventflag subprocess gates");
  Event::KernelEventFlag flag = nullptr;
  if (mode == "creator" || mode == "synthetic_creator" || mode == "delayed_creator") {
    const bool synthetic_peer = mode == "synthetic_creator";
    if (mode == "delayed_creator") {
      Check(SetEvent(ready), "publish delayed eventflag creator start");
      Sleep(100);
    }
    Check(Event::KernelCreateEventFlag(&flag,
          synthetic_peer ? "SceBootStatusFlags" :
          mode == "delayed_creator" ? "SceVideoArbitration" : "LifetimeCrossHost", 0x111,
          synthetic_peer ? 0x80 : 0x21, nullptr) == OK,
          "subprocess creates the first eventflag generation");
    Check((mode == "delayed_creator" || SetEvent(ready)) &&
          WaitForSingleObject(finish, 10000) == WAIT_OBJECT_0,
          "creator remains alive until parent has opened its flag");
  } else if (mode == "missing") {
    Check(Event::KernelOpenEventFlag(&flag, "LifetimeCrossHost") == KERNEL_ERROR_ESRCH &&
          Event::KernelOpenExistingEventFlag(&flag, "LifetimeCrossHost") == KERNEL_ERROR_ESRCH,
          "fresh host cannot reopen a dead creator's unlinked name");
    Check(SetEvent(ready), "publish missing-name result");
  } else {
    const bool deleting = mode == "delete";
    Check(deleting || mode == "cancel", "known eventflag subprocess mode");
    const char* name = deleting ? "LifetimeDelete" : "LifetimeCancel";
    Check(Event::KernelOpenExistingEventFlag(&flag, name) == OK,
          "subprocess opens a parent-created flag");
    Check(Event::KernelDeleteEventFlag(flag) == KERNEL_ERROR_EPERM,
          "opened handle cannot delete another process's creator handle");
    Check(SetEvent(ready), "publish subprocess alias before waiting");
    KernelUseconds timeout = 10000000;
    uint64_t actual = 0;
    const int status = Event::KernelWaitEventFlag(flag, 0x80, 1, &actual, &timeout);
    Check(status == (deleting ? KERNEL_ERROR_EACCES : KERNEL_ERROR_ECANCELED),
          "cross-host waiter receives deletion or cancellation");
    if (deleting) {
      Check(Event::KernelPollEventFlag(flag, 1, 1, &actual) == KERNEL_ERROR_EACCES &&
            Event::KernelSetEventFlag(flag, 1) == KERNEL_ERROR_EACCES,
            "old cross-host alias remains deleted after wake");
      Check(WaitForSingleObject(finish, 10000) == WAIT_OBJECT_0,
            "replacement creator publishes a distinct generation");
      Event::KernelEventFlag replacement = nullptr;
      Check(Event::KernelOpenEventFlag(&replacement, name) == OK && replacement != flag &&
            Event::KernelPollEventFlag(replacement, 0x80, 1, &actual) == OK && actual == 0x80,
            "fresh cross-host open selects the recreated name only");
      Check(Event::KernelCloseEventFlag(replacement) == OK,
            "close cross-host replacement alias");
    } else {
      Check(actual == 2 && Event::KernelPollEventFlag(flag, 2, 1, &actual) == OK,
            "cross-host cancellation sets the supplied pattern and preserves object");
    }
    Check(Event::KernelCloseEventFlag(flag) == OK, "close cross-host old alias");
  }
  Check(CloseHandle(ready) && CloseHandle(finish), "release subprocess event gates");
  return 0;
#else
  return 2;
#endif
}

void CheckEventFlagLifetimes() {
#if defined(_WIN32)
  using namespace Libs::LibKernel;
  namespace Event = Libs::LibKernel::EventFlag;
  const char* keys[] = {"KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE",
      "KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET",
      "KYTY_DIAGNOSTIC_INJECT_BOOTSTATUS_A", "KYTY_DIAGNOSTIC_INJECT_SHELLUI_BOOT_BIT4",
      "KYTY_DIAGNOSTIC_INJECT_SYSTEM_STATE_WORKING", "KYTY_DIAGNOSTIC_INJECT_AUTOMOUNTER_M2_NO_DIALOG",
      "KYTY_DIAGNOSTIC_VIDEO_ARBITRATION_INIT"};
  std::array<std::string, 8> saved;
  for (size_t i = 0; i < saved.size(); ++i) {
    const char* value = std::getenv(keys[i]);
    saved[i] = value == nullptr ? "" : value;
    Check(_putenv_s(keys[i], "") == 0, "clear inherited eventflag lifetime environment");
  }
  Event::KernelEventFlag missing = nullptr;
  Check(Event::KernelOpenEventFlag(&missing, "LifetimeMissing") == KERNEL_ERROR_ESRCH &&
        Event::KernelOpenExistingEventFlag(&missing, "LifetimeMissing") == KERNEL_ERROR_ESRCH &&
        missing == nullptr, "ordinary missing-name open never creates a placeholder");
  Event::KernelEventFlag exact = nullptr, exact_alias = nullptr;
  Check(Event::KernelCreateEventFlag(&exact, "/evf_acap.restrict", 0x121, 0, nullptr) == OK &&
        Event::KernelOpenEventFlag(&exact_alias, "/evf_acap.restrict") == OK &&
        exact != exact_alias, "exact Audiod create path survives local shared-owner teardown");
  Event::KernelEventFlag duplicate = reinterpret_cast<Event::KernelEventFlag>(uintptr_t {0x3fffffff});
  Check(Event::KernelCreateEventFlag(&duplicate, "/evf_acap.restrict", 0x121, 0, nullptr) ==
            KERNEL_ERROR_EEXIST &&
        duplicate == reinterpret_cast<Event::KernelEventFlag>(uintptr_t {0x3fffffff}),
        "duplicate exact Audiod name preserves the original owner and output");
  uint64_t exact_bits = 1;
  Check(Event::KernelPollEventFlag(exact_alias, 1, 1, &exact_bits) == KERNEL_ERROR_EBUSY &&
        exact_bits == 0 && Event::KernelCloseEventFlag(exact_alias) == OK &&
        Event::KernelDeleteEventFlag(exact) == OK,
        "exact Audiod ownership remains usable through open close and creator delete");
  const auto invalid = reinterpret_cast<Event::KernelEventFlag>(uintptr_t {0x3ffffffe});
  Check(Event::KernelSetEventFlag(invalid, 1) == KERNEL_ERROR_ESRCH &&
        Event::KernelDeleteEventFlag(invalid) == KERNEL_ERROR_ESRCH &&
        Event::KernelCloseEventFlag(invalid) == KERNEL_ERROR_ESRCH,
        "foreign eventflag handles cannot acquire or release ownership");
  Event::KernelEventFlag local = nullptr, old = nullptr, replacement = nullptr;
  Check(Event::KernelCreateEventFlag(&local, "LifetimeLocal", 0x111, 1, nullptr) == OK &&
        Event::KernelOpenEventFlag(&old, "LifetimeLocal") == OK && local != old &&
        reinterpret_cast<uintptr_t>(local) >= 0x10000 &&
        reinterpret_cast<uintptr_t>(local) < 0x40000000 &&
        reinterpret_cast<uintptr_t>(old) >= 0x10000 &&
        reinterpret_cast<uintptr_t>(old) < 0x40000000,
        "same-host creator and alias use distinct handles in the reserved eventflag range");
  Check(Event::KernelDeleteEventFlag(old) == KERNEL_ERROR_EPERM,
        "same-host opened alias cannot delete the creator handle");
  uint64_t actual = 0;
  Check(Event::KernelPollEventFlag(old, 0x10, 1, &actual) == KERNEL_ERROR_EBUSY && actual == 1,
        "nonblocking missing bit returns EBUSY and the complete pattern");
  const auto start_wait = [&](Event::KernelEventFlag flag, std::promise<int>* status) {
    return std::thread([flag, status] {
      KernelUseconds timeout = 5000000;
      uint64_t bits = 0;
      status->set_value(Event::KernelWaitEventFlag(flag, 0x80, 1, &bits, &timeout));
    });
  };
  std::promise<int> canceled;
  auto cancellation = canceled.get_future();
  auto cancel_thread = start_wait(old, &canceled);
  WaitForEventFlagWaiter(local);
  int count = -1;
  Check(Event::KernelCancelEventFlag(local, 2, &count) == OK && count == 1 &&
        cancellation.wait_for(std::chrono::seconds(5)) == std::future_status::ready &&
        cancellation.get() == KERNEL_ERROR_ECANCELED,
        "same-host cancellation wakes the waiter with ECANCELED");
  cancel_thread.join();
  Check(Event::KernelPollEventFlag(old, 2, 1, &actual) == OK && actual == 2,
        "cancellation preserves a usable object with its new pattern");
  std::promise<int> deleted;
  auto deletion = deleted.get_future();
  auto delete_thread = start_wait(old, &deleted);
  WaitForEventFlagWaiter(local);
  Check(Event::KernelDeleteEventFlag(local) == OK &&
        Event::KernelCreateEventFlag(&replacement, "LifetimeLocal", 0x111, 0x80, nullptr) == OK &&
        replacement != old, "delete and recreate produces a distinct local generation");
  Check(deletion.wait_for(std::chrono::seconds(5)) == std::future_status::ready &&
        deletion.get() == KERNEL_ERROR_EACCES, "same-host deletion wakes the original waiter");
  delete_thread.join();
  Check(Event::KernelPollEventFlag(old, 2, 1, &actual) == KERNEL_ERROR_EACCES &&
        Event::KernelSetEventFlag(old, 4) == KERNEL_ERROR_EACCES &&
        Event::KernelPollEventFlag(replacement, 0x80, 1, &actual) == OK && actual == 0x80,
        "deleted aliases cannot mutate or read the replacement generation");
  Check(Event::KernelCloseEventFlag(old) == OK &&
        Event::KernelSetEventFlag(old, 4) == KERNEL_ERROR_ESRCH &&
        Event::KernelPollEventFlag(replacement, 0x80, 1, &actual) == OK && actual == 0x80 &&
        Event::KernelDeleteEventFlag(replacement) == OK,
        "release both local generations after waiter operations drain");

  char scope_bytes[21] {};
  std::snprintf(scope_bytes, sizeof(scope_bytes), "e%08lx%08lx",
      GetCurrentProcessId(), static_cast<unsigned long>(GetTickCount()));
  const std::string scope = scope_bytes;
  const auto set_scope = [&](const std::string& value) {
    Check(_putenv_s(keys[0], value.c_str()) == 0 && _putenv_s(keys[1], "1") == 0,
          "select eventflag scope");
  };
  set_scope(scope);
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  Check(job != nullptr && SetInformationJobObject(job, JobObjectExtendedLimitInformation,
        &limits, sizeof(limits)), "contain eventflag subprocesses");
  Check(_putenv_s(keys[7], "1") == 0, "enable exact VideoArbitration coordination wait");
  auto delayed_creator = StartEventFlagLifetimeWorker(scope, "delayed_creator", job);
  Event::KernelEventFlag delayed_alias = nullptr;
  const ULONGLONG delayed_start = GetTickCount64();
  Check(Event::KernelOpenEventFlag(&delayed_alias, "SceVideoArbitration") == OK &&
        GetTickCount64() - delayed_start >= 50,
        "exact VideoArbitration open waits for a delayed creator");
  Check(SetEvent(delayed_creator.finish), "release delayed VideoArbitration creator");
  FinishEventFlagLifetimeWorker(delayed_creator);
  Check(Event::KernelCloseEventFlag(delayed_alias) == OK && _putenv_s(keys[7], "") == 0,
        "close coordinated VideoArbitration alias and disable its wait");
  auto creator = StartEventFlagLifetimeWorker(scope, "creator", job);
  Event::KernelEventFlag survivor = nullptr;
  Check(Event::KernelOpenEventFlag(&survivor, "LifetimeCrossHost") == OK,
        "parent opens flag while creator host is alive");
  Check(SetEvent(creator.finish), "allow creator host to exit without Delete");
  FinishEventFlagLifetimeWorker(creator);
  Check(Event::KernelPollEventFlag(survivor, 0x21, 1, &actual) == OK && actual == 0x21,
        "existing alias preserves bits after creator host exits");
  Check(Event::KernelOpenEventFlag(&missing, "LifetimeCrossHost") == KERNEL_ERROR_ESRCH &&
        Event::KernelOpenExistingEventFlag(&missing, "LifetimeCrossHost") == KERNEL_ERROR_ESRCH,
        "cached host cannot resurrect the unlinked name");
  auto missing_host = StartEventFlagLifetimeWorker(scope, "missing", job);
  FinishEventFlagLifetimeWorker(missing_host);
  Event::KernelEventFlag fresh = nullptr, fresh_alias = nullptr;
  Check(Event::KernelCreateEventFlag(&fresh, "LifetimeCrossHost", 0x111, 0x80, nullptr) == OK &&
        Event::KernelOpenEventFlag(&fresh_alias, "LifetimeCrossHost") == OK && fresh != survivor &&
        Event::KernelSetEventFlag(survivor, 4) == OK &&
        Event::KernelPollEventFlag(survivor, 0x25, 1, &actual) == OK && actual == 0x25 &&
        Event::KernelPollEventFlag(fresh, 0x80, 1, &actual) == OK && actual == 0x80,
        "old live alias and recreated scoped name retain independent state");
  set_scope(scope + "b");
  Event::KernelEventFlag isolated = nullptr;
  Check(Event::KernelCreateEventFlag(&isolated, "LifetimeCrossHost", 0x111, 0x200, nullptr) == OK &&
        Event::KernelPollEventFlag(isolated, 0x200, 1, &actual) == OK && actual == 0x200 &&
        Event::KernelDeleteEventFlag(isolated) == OK, "same name remains isolated by scope");
  set_scope(scope);
  Check(Event::KernelCloseEventFlag(survivor) == OK &&
        Event::KernelCloseEventFlag(fresh_alias) == OK && Event::KernelDeleteEventFlag(fresh) == OK,
        "close creator-exit survivor and replacement generation");
  for (const std::string mode: {"delete", "cancel"}) {
    const char* name = mode == "delete" ? "LifetimeDelete" : "LifetimeCancel";
    Event::KernelEventFlag flag = nullptr;
    Check(Event::KernelCreateEventFlag(&flag, name, 0x111, 1, nullptr) == OK,
          "parent creates cross-host waiter flag");
    auto worker = StartEventFlagLifetimeWorker(scope, mode, job);
    WaitForEventFlagWaiter(flag);
    if (mode == "delete") {
      Check(Event::KernelDeleteEventFlag(flag) == OK &&
            Event::KernelCreateEventFlag(&replacement, name, 0x111, 0x80, nullptr) == OK &&
            SetEvent(worker.finish), "delete and recreate while old remote waiter is alive");
    } else {
      count = -1;
      Check(Event::KernelCancelEventFlag(flag, 2, &count) == OK && count == 1,
            "cross-host cancellation reports the queued waiter");
    }
    FinishEventFlagLifetimeWorker(worker);
    Check(Event::KernelDeleteEventFlag(mode == "delete" ? replacement : flag) == OK,
          "release cross-host waiter creator");
  }
  set_scope(scope + "s");
  Event::KernelEventFlag synthetic = nullptr, genuine = nullptr, genuine_alias = nullptr;
  Check(_putenv_s(keys[3], "1") == 0 &&
        Event::KernelOpenEventFlag(&synthetic, "SceBootStatusFlags") == OK &&
        Event::KernelPollEventFlag(synthetic, 0xa, 1, &actual) == OK && actual == 0xa &&
        _putenv_s(keys[3], "") == 0,
        "create explicitly gated local synthetic alias before a peer producer");
  Check(Event::KernelOpenExistingEventFlag(&missing, "SceBootStatusFlags") == KERNEL_ERROR_ESRCH,
        "peer lookup excludes the existing synthetic cache while producer is absent");
  auto genuine_creator = StartEventFlagLifetimeWorker(scope + "s", "synthetic_creator", job);
  Check(Event::KernelOpenExistingEventFlag(&genuine, "SceBootStatusFlags") == OK &&
        Event::KernelOpenEventFlag(&genuine_alias, "SceBootStatusFlags") == OK &&
        Event::KernelSetEventFlag(synthetic, 4) == OK &&
        Event::KernelPollEventFlag(synthetic, 0xe, 1, &actual) == OK && actual == 0xe &&
        Event::KernelPollEventFlag(genuine, 0x80, 1, &actual) == OK && actual == 0x80 &&
        Event::KernelPollEventFlag(genuine_alias, 0x80, 1, &actual) == OK && actual == 0x80,
        "peer lookup supersedes cached synthetic name without rebinding old alias");
  Check(SetEvent(genuine_creator.finish), "allow peer creator to exit");
  FinishEventFlagLifetimeWorker(genuine_creator);
  Check(Event::KernelOpenExistingEventFlag(&missing, "SceBootStatusFlags") == KERNEL_ERROR_ESRCH &&
        Event::KernelPollEventFlag(genuine, 0x80, 1, &actual) == OK && actual == 0x80 &&
        Event::KernelCloseEventFlag(genuine) == OK && Event::KernelCloseEventFlag(genuine_alias) == OK &&
        Event::KernelCloseEventFlag(synthetic) == OK,
        "creator exit unlinks name while both prior alias states retain their identities");
  Check(CloseHandle(job), "release eventflag subprocess containment");
  set_scope(scope + "x");
  for (unsigned i = 0; i < 128; ++i) {
    Event::KernelEventFlag flag = nullptr;
    Check(Event::KernelCreateEventFlag(&flag, "LifetimeBound", 0x111, i, nullptr) == OK &&
          Event::KernelDeleteEventFlag(flag) == OK, "consume a bounded scoped generation");
  }
  Check(Event::KernelCreateEventFlag(&missing, "LifetimeBound", 0x111, 0, nullptr) ==
        KERNEL_ERROR_ENOSPC, "scoped generation exhaustion returns a resource error");
  for (size_t i = 0; i < saved.size(); ++i)
    Check(_putenv_s(keys[i], saved[i].c_str()) == 0, "restore eventflag lifetime environment");
  std::printf("EventFlagLifetimeTests: local/cross-host recreation, creator exit, cancel, isolation and bounds passed\n");
#endif
}
