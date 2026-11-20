#if defined(_WIN32)
std::string SemaphoreCrossHostGate(const std::string& scope, const std::string& mode,
                                   const char* suffix) {
  return "Local\\kyty_sema_test_" + scope + "_" + mode + "_" + suffix;
}

// SceSysCoreEventSemaphore is a doorbell: the opener blocks on need=1 until the creating host signals. Waiters live in the shared mapping, so the parent sees the child's wait through its own handle.
void WaitForSemaphoreWaiter(Libs::LibKernel::Semaphore::KernelSema sem) {
  namespace Sema = Libs::LibKernel::Semaphore;
  const ULONGLONG deadline = GetTickCount64() + 5000;
  for (;;) {
    const int count = Sema::KernelSemaWaiterCountForTesting(sem);
    if (count >= 1) return;
    Check(count >= 0 && GetTickCount64() < deadline,
          "semaphore waiter enters the shared wait set");
    Sleep(1);
  }
}

struct SemaphoreCrossHostWorker {
  HANDLE ready = nullptr;
  HANDLE finish = nullptr;
  PROCESS_INFORMATION process {};
};

SemaphoreCrossHostWorker StartSemaphoreCrossHostWorker(const std::string& scope,
                                                       const std::string& mode, HANDLE job) {
  SemaphoreCrossHostWorker worker;
  worker.ready = CreateEventA(nullptr, TRUE, FALSE,
      SemaphoreCrossHostGate(scope, mode, "ready").c_str());
  worker.finish = CreateEventA(nullptr, TRUE, FALSE,
      SemaphoreCrossHostGate(scope, mode, "finish").c_str());
  std::array<wchar_t, 32768> executable {};
  const DWORD length = GetModuleFileNameW(nullptr, executable.data(), executable.size());
  Check(worker.ready != nullptr && worker.finish != nullptr &&
        length != 0 && length < executable.size(), "prepare semaphore subprocess gates");
  std::wstring command = L"\"" + std::wstring(executable.data()) +
      L"\" --semaphore-crosshost-child " + std::wstring(scope.begin(), scope.end()) +
      L" " + std::wstring(mode.begin(), mode.end());
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  Check(CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup, &worker.process) &&
        AssignProcessToJobObject(job, worker.process.hProcess) &&
        ResumeThread(worker.process.hThread) != DWORD(-1),
        "start contained semaphore subprocess");
  Check(WaitForSingleObject(worker.ready, 10000) == WAIT_OBJECT_0,
        "semaphore subprocess reaches its operation");
  return worker;
}

void FinishSemaphoreCrossHostWorker(SemaphoreCrossHostWorker& worker) {
  Check(WaitForSingleObject(worker.process.hProcess, 10000) == WAIT_OBJECT_0,
        "semaphore subprocess finishes within bound");
  DWORD status = 1;
  Check(GetExitCodeProcess(worker.process.hProcess, &status) && status == 0,
        "semaphore subprocess assertions pass");
  Check(CloseHandle(worker.process.hThread) && CloseHandle(worker.process.hProcess) &&
        CloseHandle(worker.ready) && CloseHandle(worker.finish),
        "release semaphore subprocess handles");
}
#endif

int RunSemaphoreCrossHostChild(int argc, char** argv) {
  if (argc != 4 || std::strcmp(argv[1], "--semaphore-crosshost-child") != 0) return -1;
#if defined(_WIN32)
  using namespace Libs::LibKernel;
  namespace Sema = Libs::LibKernel::Semaphore;
  Common::InitializeThreads();
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", argv[2]) == 0 &&
        _putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1") == 0,
        "set semaphore subprocess scope");
  Process::ScopedGuestProcessPid identity(5100);
  const std::string mode = argv[3];
  HANDLE ready = OpenEventA(EVENT_MODIFY_STATE, FALSE,
      SemaphoreCrossHostGate(argv[2], mode, "ready").c_str());
  HANDLE finish = OpenEventA(SYNCHRONIZE, FALSE,
      SemaphoreCrossHostGate(argv[2], mode, "finish").c_str());
  Check(ready != nullptr && finish != nullptr, "open semaphore subprocess gates");
  Sema::KernelSema sem = nullptr;
  if (mode == "creator") {
    Check(Sema::KernelCreateSema(&sem, "SemaCrossHost", 0x101, 5, 722, nullptr) == OK,
          "subprocess creates original named semaphore generation");
    Check(SetEvent(ready) && WaitForSingleObject(finish, 10000) == WAIT_OBJECT_0,
          "creator remains alive until parent has opened its semaphore");
  } else if (mode == "missing") {
    Check(Sema::KernelOpenSema(&sem, "SemaCrossHost") == KERNEL_ERROR_ESRCH &&
          Sema::KernelOpenExistingSema(&sem, "SemaCrossHost") == KERNEL_ERROR_ESRCH,
          "fresh host cannot reopen a dead creator's unlinked name");
    Check(SetEvent(ready), "publish missing-name result");
  } else if (mode == "signal") {
    sem = reinterpret_cast<Sema::KernelSema>(UINTPTR_MAX);
    Check(Sema::KernelCreateSema(&sem, "SemaDoorbell", 0x101, 0, 722, nullptr) ==
              KERNEL_ERROR_EPERM && sem == reinterpret_cast<Sema::KernelSema>(UINTPTR_MAX),
          "foreign host creator receives EPERM without replacing the named semaphore");
    Check(Sema::KernelOpenExistingSema(&sem, "SemaDoorbell") == OK,
          "opener resolves the cross-host doorbell by name");
    Sema::KernelSema duplicate = reinterpret_cast<Sema::KernelSema>(UINTPTR_MAX);
    Check(Sema::KernelCreateSema(&duplicate, "SemaDoorbell", 0x101, 0, 722, nullptr) ==
              KERNEL_ERROR_EPERM && duplicate == reinterpret_cast<Sema::KernelSema>(UINTPTR_MAX),
          "foreign host cached opener still receives EPERM on create");
    Check(Sema::KernelDeleteSema(sem) == KERNEL_ERROR_EPERM,
          "opened handle cannot delete the creating host's semaphore");
    Check(SetEvent(ready), "publish opener before blocking on the doorbell");
    KernelUseconds timeout = 10000000;
    Check(Sema::KernelWaitSema(sem, 1, &timeout) == OK,
          "cross-host wait is released by the creating host's signal");
    Check(Sema::KernelPollSema(sem, 1) == KERNEL_ERROR_EBUSY,
          "the signalled count is consumed exactly once across hosts");
    Check(Sema::KernelCloseSema(sem) == OK, "close cross-host doorbell opener");
  } else {
    const bool deleting = mode == "delete";
    Check(deleting || mode == "cancel", "known semaphore subprocess mode");
    const char* name = deleting ? "SemaDelete" : "SemaCancel";
    Check(Sema::KernelOpenExistingSema(&sem, name) == OK,
          "subprocess opens a parent-created semaphore");
    Check(Sema::KernelDeleteSema(sem) == KERNEL_ERROR_EPERM,
          "opened handle cannot delete another process's creator handle");
    Check(SetEvent(ready), "publish subprocess alias before waiting");
    KernelUseconds timeout = 10000000;
    const int status = Sema::KernelWaitSema(sem, 1, &timeout);
    Check(status == (deleting ? KERNEL_ERROR_EACCES : KERNEL_ERROR_ECANCELED),
          "cross-host waiter receives deletion or cancellation");
    if (deleting) {
      Check(Sema::KernelPollSema(sem, 1) == KERNEL_ERROR_EBUSY &&
            Sema::KernelSignalSema(sem, 1) == KERNEL_ERROR_EINVAL,
            "old cross-host alias remains deleted after wake");
      Check(WaitForSingleObject(finish, 10000) == WAIT_OBJECT_0,
            "replacement creator publishes a distinct generation");
      Sema::KernelSema replacement = nullptr;
      Check(Sema::KernelOpenSema(&replacement, name) == OK && replacement != sem &&
            Sema::KernelPollSema(replacement, 1) == OK,
            "fresh cross-host open selects the recreated name only");
      Check(Sema::KernelCloseSema(replacement) == OK, "close cross-host replacement alias");
    } else {
      Check(Sema::KernelPollSema(sem, 2) == OK,
            "cross-host cancellation leaves the supplied count and preserves object");
    }
    Check(Sema::KernelCloseSema(sem) == OK, "close cross-host old alias");
  }
  Check(CloseHandle(ready) && CloseHandle(finish), "release subprocess event gates");
  return 0;
#else
  return 2;
#endif
}

void CheckSemaphoreCrossHost() {
#if defined(_WIN32)
  using namespace Libs::LibKernel;
  namespace Sema = Libs::LibKernel::Semaphore;
  const char* keys[] = {"KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE",
      "KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET"};
  std::array<std::string, 3> saved;
  for (size_t i = 0; i < saved.size(); ++i) {
    const char* value = std::getenv(keys[i]);
    saved[i] = value == nullptr ? "" : value;
    Check(_putenv_s(keys[i], "") == 0, "clear inherited semaphore scope environment");
  }
  Sema::KernelSema missing = nullptr;
  Check(Sema::KernelOpenSema(&missing, "DoorbellMissing") == KERNEL_ERROR_ESRCH &&
        missing == nullptr, "ordinary missing-name open never creates a placeholder");

  char scope_bytes[21] {};
  std::snprintf(scope_bytes, sizeof(scope_bytes), "s%08lx%08lx",
      GetCurrentProcessId(), static_cast<unsigned long>(GetTickCount()));
  const std::string scope = scope_bytes;
  const auto set_scope = [&](const std::string& value) {
    Check(_putenv_s(keys[0], value.c_str()) == 0 && _putenv_s(keys[1], "1") == 0,
          "select semaphore scope");
  };
  set_scope(scope);
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  Check(job != nullptr && SetInformationJobObject(job, JobObjectExtendedLimitInformation,
        &limits, sizeof(limits)), "contain semaphore subprocesses");

  auto creator = StartSemaphoreCrossHostWorker(scope, "creator", job);
  Sema::KernelSema survivor = nullptr;
  Check(Sema::KernelOpenSema(&survivor, "SemaCrossHost") == OK,
        "parent opens semaphore while creator host is alive");
  Check(SetEvent(creator.finish), "allow creator host to exit without Delete");
  FinishSemaphoreCrossHostWorker(creator);
  Check(Sema::KernelPollSema(survivor, 5) == OK && Sema::KernelSignalSema(survivor, 1) == OK &&
        Sema::KernelPollSema(survivor, 1) == OK,
        "existing alias preserves count and stays usable after creator host exits");
  Check(Sema::KernelOpenSema(&missing, "SemaCrossHost") == KERNEL_ERROR_ESRCH,
        "cached host cannot resurrect the unlinked name");
  auto missing_host = StartSemaphoreCrossHostWorker(scope, "missing", job);
  FinishSemaphoreCrossHostWorker(missing_host);
  Check(Sema::KernelCloseSema(survivor) == OK, "release creator-exit survivor alias");

  Sema::KernelSema doorbell = nullptr;
  Check(Sema::KernelCreateSema(&doorbell, "SemaDoorbell", 0x101, 0, 722, nullptr) == OK,
        "parent creates cross-host doorbell");
  auto signaller = StartSemaphoreCrossHostWorker(scope, "signal", job);
  WaitForSemaphoreWaiter(doorbell);
  Check(Sema::KernelSignalSema(doorbell, 1) == OK,
        "parent signal releases the cross-host opener");
  FinishSemaphoreCrossHostWorker(signaller);
  Check(Sema::KernelDeleteSema(doorbell) == OK, "release doorbell creator");

  for (const std::string mode: {"delete", "cancel"}) {
    const char* name = mode == "delete" ? "SemaDelete" : "SemaCancel";
    Sema::KernelSema flag = nullptr;
    Check(Sema::KernelCreateSema(&flag, name, 0x101, 0, 722, nullptr) == OK,
          "parent creates cross-host waiter semaphore");
    auto worker = StartSemaphoreCrossHostWorker(scope, mode, job);
    WaitForSemaphoreWaiter(flag);
    if (mode == "delete") {
      Sema::KernelSema replacement = nullptr;
      Check(Sema::KernelDeleteSema(flag) == OK &&
            Sema::KernelCreateSema(&replacement, name, 0x101, 1, 722, nullptr) == OK &&
            SetEvent(worker.finish), "delete and recreate while old remote waiter is alive");
      FinishSemaphoreCrossHostWorker(worker);
      Check(Sema::KernelDeleteSema(replacement) == OK, "release recreated waiter generation");
    } else {
      int count = -1;
      Check(Sema::KernelCancelSema(flag, 2, &count) == OK && count == 1,
            "cross-host cancellation reports the queued waiter");
      FinishSemaphoreCrossHostWorker(worker);
      Check(Sema::KernelDeleteSema(flag) == OK, "release cancelled waiter creator");
    }
  }

  set_scope(scope + "b");
  Sema::KernelSema isolated = nullptr;
  Check(Sema::KernelCreateSema(&isolated, "SemaDoorbell", 0x101, 3, 722, nullptr) == OK &&
        Sema::KernelPollSema(isolated, 3) == OK && Sema::KernelDeleteSema(isolated) == OK,
        "same name remains isolated by scope");
  Check(CloseHandle(job), "release semaphore subprocess containment");

  set_scope(scope + "x");
  Sema::KernelSema stale = nullptr;
  Check(Sema::KernelCreateSema(&stale, "SemaBound", 0x101, 0, 1, nullptr) == OK &&
        Sema::KernelOpenSema(&missing, "SemaBound") == OK, "open a semaphore before it is deleted");
  Check(Sema::KernelDeleteSema(stale) == OK, "delete the opened semaphore");
  for (unsigned i = 0; i < 1100; ++i) {
    Sema::KernelSema bound = nullptr;
    Check(Sema::KernelCreateSema(&bound, "SemaBound", 0x101, 0, 1, nullptr) == OK &&
          Sema::KernelDeleteSema(bound) == OK, "deleted rows are reused past the table size");
  }
  Check(Sema::KernelSignalSema(missing, 1) == KERNEL_ERROR_EINVAL &&
        Sema::KernelCloseSema(missing) == OK, "stale opener cannot reach a reused row");
  std::vector<Sema::KernelSema> live;
  for (unsigned i = 0; i < 1024; ++i) {
    char name[32];
    std::snprintf(name, sizeof(name), "SemaBound%u", i);
    Sema::KernelSema bound = nullptr;
    Check(Sema::KernelCreateSema(&bound, name, 0x101, 0, 1, nullptr) == OK, "fill the scoped table");
    live.push_back(bound);
  }
  Check(Sema::KernelCreateSema(&missing, "SemaBoundFull", 0x101, 0, 1, nullptr) == KERNEL_ERROR_ENOSPC,
        "scoped table exhaustion returns a resource error");
  for (auto bound: live) Check(Sema::KernelDeleteSema(bound) == OK, "release the scoped table");

  for (size_t i = 0; i < saved.size(); ++i)
    Check(_putenv_s(keys[i], saved[i].c_str()) == 0, "restore semaphore scope environment");
  std::printf("SemaphoreCrossHostTests: doorbell wake, creator exit, delete, cancel, isolation and bounds passed\n");
#endif
}
