namespace NativeDceLeaseTest {

namespace Kernel = Libs::LibKernel;
namespace VO = Libs::VideoOut;

class Requests {
public:
  Requests() {
    Check(Kernel::Memory::KernelMapNamedFlexibleMemory(&memory, 0x4000, 3, 0, "dce_lease_test") == OK,
          "DCE lease test maps guest request memory");
    fd = FileSystem::KernelOpen("/dev/dce", 2, 0);
    Check(fd >= 3, "DCE lease test opens the device");
  }
  ~Requests() {
    Check(FileSystem::KernelClose(fd) == OK &&
          Kernel::Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), 0x4000) == OK,
          "DCE lease test releases its descriptor and request mapping");
  }
  int Create() {
    cookie = 0x123456789abcdef0ull;
    Put(0x100, cookie);
    Put(0, std::array<uint64_t, 4>{(uint64_t{1} << 32) | 1, uint64_t{8} << 32,
        reinterpret_cast<uint64_t>(memory) + 0x100, 0});
    const int result = FileSystem::KernelIoctl(fd, 0x80208218u, memory);
    std::memcpy(&cookie, static_cast<uint8_t*>(memory) + 0x100, sizeof(cookie));
    if (result != OK) Check(cookie == 0x123456789abcdef0ull, "failed DCE acquisition preserves copyout");
    return result;
  }
  int Close(uint64_t identity) {
    Put(0, std::array<uint64_t, 6>{1, identity, 0, 0, 0, 0});
    return FileSystem::KernelIoctl(fd, 0x80308217u, memory);
  }
  int Query(uint64_t identity) {
    Put(0, std::array<uint64_t, 6>{9, (uint64_t{8} << 32) | identity,
        reinterpret_cast<uint64_t>(memory) + 0x100, 0,
        reinterpret_cast<uint64_t>(memory) + 0x108, 8});
    return FileSystem::KernelIoctl(fd, 0x80308217u, memory);
  }
  template<class T> void Put(size_t offset, const T& value) {
    std::memcpy(static_cast<uint8_t*>(memory) + offset, &value, sizeof(value));
  }
  uint64_t cookie = 0;
private:
  void* memory = nullptr;
  int fd = -1;
};

#if defined(_WIN32)
constexpr const char* scope_keys[] = {"KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE",
    "KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS"};

class Environment {
public:
  Environment(const std::string& scope) {
    for (const char* key: scope_keys) {
      const char* value = std::getenv(key);
      saved.emplace_back(value == nullptr ? "" : value);
    }
    Check(_putenv_s(scope_keys[0], scope.c_str()) == 0 &&
          _putenv_s(scope_keys[1], "1") == 0 && _putenv_s(scope_keys[2], "1") == 0,
          "DCE lease fixture selects an isolated process scope");
  }
  ~Environment() {
    for (size_t i = 0; i < saved.size(); ++i)
      Check(_putenv_s(scope_keys[i], saved[i].c_str()) == 0, "DCE lease fixture restores environment");
  }
private:
  std::vector<std::string> saved;
};

struct Worker {
  PROCESS_INFORMATION process {};
  std::array<HANDLE, 5> events {};
  std::filesystem::path output;
  ~Worker() {
    if (process.hThread) CloseHandle(process.hThread);
    if (process.hProcess) CloseHandle(process.hProcess);
    for (HANDLE event: events) if (event) CloseHandle(event);
  }
  void Start(HANDLE job, const std::string& scope, const std::string& label,
             const std::string& mode, const std::filesystem::path& root) {
    const std::string prefix = "Local\\kyty_dce_test_" + scope + "_" + label;
    for (size_t i = 0; i < events.size(); ++i) {
      events[i] = CreateEventA(nullptr, TRUE, FALSE, (prefix + "_" + std::to_string(i)).c_str());
      Check(events[i] != nullptr, "create owned cross-host DCE test gate");
    }
    output = root / (scope + "_" + label + ".txt");
    std::array<wchar_t, 32768> executable {};
    const DWORD length = GetModuleFileNameW(nullptr, executable.data(), executable.size());
    Check(length != 0 && length < executable.size(), "find cross-host DCE test executable");
    std::wstring command = L"\"" + std::wstring(executable.data()) + L"\" --native-dce-lease-child " +
        std::wstring(scope.begin(), scope.end()) + L" " + std::wstring(mode.begin(), mode.end()) +
        L" " + std::wstring(prefix.begin(), prefix.end()) + L" \"" + output.wstring() + L"\"";
    STARTUPINFOW startup {};
    startup.cb = sizeof(startup);
    Check(CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE,
          CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup, &process),
          "create cross-host DCE worker");
    Check(AssignProcessToJobObject(job, process.hProcess) && ResumeThread(process.hThread) != DWORD(-1),
          "contain and resume cross-host DCE worker");
    Check(WaitForSingleObject(events[0], 20000) == WAIT_OBJECT_0, "wait for DCE worker result");
  }
  std::pair<int, uint64_t> Result() const {
    std::ifstream input(output);
    int result = 1;
    uint64_t cookie = 0;
    input >> result >> cookie;
    Check(!input.fail(), "read worker ioctl result");
    return {result, cookie};
  }
  void Signal(size_t index) const {
    Check(SetEvent(events[index]), "signal owned cross-host DCE test gate");
  }
  void Wait(size_t index) const {
    Check(WaitForSingleObject(events[index], 20000) == WAIT_OBJECT_0, "wait for bounded DCE worker phase");
  }
  void Finish() {
    Signal(4);
    Check(WaitForSingleObject(process.hProcess, 20000) == WAIT_OBJECT_0, "DCE worker exits within bound");
    DWORD status = 1;
    Check(GetExitCodeProcess(process.hProcess, &status) && status == 0, "DCE worker passed");
  }
};
#endif

}

int RunNativeDceLeaseChild(int argc, char** argv, Libs::Graphics::WindowContext& graphics) {
  if (argc != 6 || std::strcmp(argv[1], "--native-dce-lease-child") != 0) return -1;
#if defined(_WIN32)
  using namespace NativeDceLeaseTest;
  Environment environment(argv[2]);
  Kernel::Process::ScopedGuestProcessPid identity(7000 + static_cast<int>(GetCurrentProcessId() % 100000));
  static_cast<void>(VO::VideoOutInit(64, 64, *graphics.presenter));
  Check(VO::VideoOutIsInitialized(), "worker initializes a VideoOut backend");
  std::array<HANDLE, 5> events {};
  for (size_t i = 0; i < events.size(); ++i) {
    events[i] = OpenEventA(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE,
        (std::string(argv[4]) + "_" + std::to_string(i)).c_str());
    Check(events[i] != nullptr, "worker opens owned synchronization gate");
  }
  {
    Requests request;
    const int result = request.Create();
    const uint64_t cookie = request.cookie;
    {
      std::ofstream output(Common::PathFromUtf8(argv[5]));
      output << result << ' ' << cookie << '\n';
      Check(output.good(), "worker records DCE acquisition result");
    }
    Check(SetEvent(events[0]), "worker publishes ioctl result");
    const std::string mode = argv[3];
    if (mode == "owner") {
      Check(result == OK && WaitForSingleObject(events[1], 20000) == WAIT_OBJECT_0 &&
            request.Close(cookie) == OK && SetEvent(events[3]), "worker cleanly releases its live client");
      Check(WaitForSingleObject(events[2], 20000) == WAIT_OBJECT_0,
            "worker waits for replacement owner before stale release attempt");
      const int stale = request.Close(cookie);
      {
        std::ofstream output(Common::PathFromUtf8(argv[5]), std::ios::app);
        output << stale << '\n';
        Check(output.good(), "worker records stale-cookie close result");
      }
      Check(stale == Kernel::KERNEL_ERROR_EINVAL && SetEvent(events[3]),
            "old client cookie cannot release a replacement host lease");
      Check(WaitForSingleObject(events[4], 20000) == WAIT_OBJECT_0, "owner worker receives bounded finish");
    } else if (mode == "abandon") {
      Check(result == OK && WaitForSingleObject(events[4], 20000) == WAIT_OBJECT_0,
            "worker retains a live lease until abrupt process exit");
      ExitProcess(0);
    } else if (mode == "hold") {
      Check(result == OK && WaitForSingleObject(events[4], 20000) == WAIT_OBJECT_0 &&
            request.Close(cookie) == OK, "worker cleanly closes its held lease");
    } else {
      Check(mode == "probe", "worker selects a supported lease test mode");
      if (result == OK) Check(request.Close(cookie) == OK, "probe worker releases its client");
    }
  }
  for (HANDLE event: events) Check(CloseHandle(event), "worker releases synchronization handle");
  VO::VideoOutShutdown();
  return 0;
#else
  return 2;
#endif
}

void CheckNativeDceLeases(const std::filesystem::path& root, Libs::Graphics::WindowContext& graphics) {
#if defined(_WIN32)
  using namespace NativeDceLeaseTest;
  char scope_bytes[21] {};
  std::snprintf(scope_bytes, sizeof(scope_bytes), "d%08lx%08lx", GetCurrentProcessId(),
      static_cast<unsigned long>(GetTickCount()));
  const std::string scope = scope_bytes;
  Environment environment(scope);
  Kernel::Process::ScopedGuestProcessPid identity(100);
  static_cast<void>(VO::VideoOutInit(64, 64, *graphics.presenter));
  Check(VO::VideoOutIsInitialized(), "cross-host fixture initializes VideoOut");
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  Check(job != nullptr && SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
        "contain all DCE worker processes");
  {
    Worker owner;
    owner.Start(job, scope, "owner", "owner", root);
    const auto [created, first_cookie] = owner.Result();
    Check(created == OK, "first host owns the global MAIN lease");
    {
      Worker competitor;
      competitor.Start(job, scope, "competitor", "probe", root);
      Check(competitor.Result().first == Kernel::KERNEL_ERROR_EBUSY,
            "another live host cannot acquire an occupied MAIN port");
      competitor.Finish();
      Requests local;
      Check(local.Create() == Kernel::KERNEL_ERROR_EBUSY &&
            local.Query(first_cookie) == Kernel::KERNEL_ERROR_EINVAL,
            "global ownership does not disclose another host guest VA through a local descriptor");
    }
    owner.Signal(1);
    owner.Wait(3);
    Check(ResetEvent(owner.events[3]), "reset owned phase notification");
    Worker replacement;
    replacement.Start(job, scope, "replacement", "abandon", root);
    const auto [replaced, second_cookie] = replacement.Result();
    Check(replaced == OK && second_cookie != first_cookie,
          "clean client release permits a new host with a distinct global cookie");
    owner.Signal(2);
    owner.Wait(3);
    {
      std::ifstream output(owner.output);
      int result = 0, stale = 0;
      uint64_t cookie = 0;
      output >> result >> cookie >> stale;
      Check(!output.fail() && stale == Kernel::KERNEL_ERROR_EINVAL,
            "stale host close returns the invalid-cookie result");
      Worker probe;
      probe.Start(job, scope, "after_stale", "probe", root);
      Check(probe.Result().first == Kernel::KERNEL_ERROR_EBUSY,
            "stale cleanup preserves the replacement host's occupied port");
      probe.Finish();
    }
    owner.Finish();
    replacement.Finish();
    {
      Requests reclaimed;
      Check(reclaimed.Create() == OK && reclaimed.cookie != second_cookie,
            "proven exited owner is reclaimed with a new scope generation and cookie");
      Check(reclaimed.Query(reclaimed.cookie) == OK && reclaimed.Close(reclaimed.cookie) == OK,
            "reclaimed client has local guest memory and cleanly releases ownership");
    }
    Worker after_close;
    after_close.Start(job, scope, "after_close", "probe", root);
    Check(after_close.Result().first == OK, "clean reclaimed close makes the port available to another host");
    after_close.Finish();
  }
  {
    const std::string gap_scope = scope + "g";
    Worker first;
    first.Start(job, gap_scope, "gap_first", "abandon", root);
    const uint64_t old_cookie = first.Result().second;
    first.Finish();
    Worker later;
    later.Start(job, gap_scope, "gap_later", "probe", root);
    Check(later.Result().first == OK && later.Result().second != old_cookie,
          "scope cookie sequence survives a gap with no host mapping handles");
    later.Finish();
  }
  {
    Requests retained;
    Check(retained.Create() == OK && retained.Query(retained.cookie) == OK,
          "release-failure fixture owns a scoped client and guest mapping");
    const uint64_t cookie = retained.cookie;
    const std::string name = "Local\\kyty_ps5_" + scope + "_dce_leases_v1";
    const auto path = std::filesystem::temp_directory_path() / ("kyty_ps5_" + scope + "_dce_leases_v1.bin");
    const size_t bytes = static_cast<size_t>(std::filesystem::file_size(path));
    HANDLE mutex = OpenMutexA(SYNCHRONIZE | MUTEX_MODIFY_STATE, FALSE, (name + "_lock").c_str());
    HANDLE mapping = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, name.c_str());
    Check(mutex != nullptr && mapping != nullptr && bytes >= sizeof(uint64_t),
          "release-failure fixture opens only its owned isolated lease metadata");
    auto* view = static_cast<uint8_t*>(MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, bytes));
    Check(view != nullptr && WaitForSingleObject(mutex, 20000) == WAIT_OBJECT_0,
          "release-failure fixture locks its own shared metadata");
    const std::vector<uint8_t> snapshot(view, view + bytes);
    const uint64_t broken_magic = 0;
    std::memcpy(view, &broken_magic, sizeof(broken_magic));
    Check(FlushViewOfFile(view, bytes) && ReleaseMutex(mutex),
          "release-failure fixture invalidates only its own header magic");
    Check(retained.Close(cookie) == Kernel::KERNEL_ERROR_EIO &&
          retained.Query(cookie) == Kernel::KERNEL_ERROR_EINVAL,
          "failed shared release returns EIO without a live guest resource");
    {
      Requests local;
      Check(local.Create() == Kernel::KERNEL_ERROR_EBUSY,
            "failed close retains its local client identity for retry");
      Worker rejected;
      rejected.Start(job, scope, "during_release_failure", "probe", root);
      Check(rejected.Result().first == Kernel::KERNEL_ERROR_EIO,
            "corrupt shared metadata cannot hand the occupied port to another host");
      rejected.Finish();
    }
    Check(WaitForSingleObject(mutex, 20000) == WAIT_OBJECT_0 &&
          std::memcmp(view, &broken_magic, sizeof(broken_magic)) == 0 &&
          std::memcmp(view + sizeof(uint64_t), snapshot.data() + sizeof(uint64_t),
              bytes - sizeof(uint64_t)) == 0,
          "failed release preserves all occupied-owner metadata bytes");
    std::memcpy(view, snapshot.data(), sizeof(uint64_t));
    Check(FlushViewOfFile(view, bytes) && ReleaseMutex(mutex),
          "release-failure fixture restores the exact original header");
    {
      Worker occupied;
      occupied.Start(job, scope, "before_close_retry", "probe", root);
      Check(occupied.Result().first == Kernel::KERNEL_ERROR_EBUSY,
            "restored metadata still preserves the original occupied lease");
      occupied.Finish();
    }
    Check(retained.Close(cookie) == OK && retained.Create() == OK && retained.cookie != cookie &&
          retained.Close(retained.cookie) == OK,
          "retry releases the retained exact identity and permits a fresh client");
    Check(UnmapViewOfFile(view) && CloseHandle(mapping) && CloseHandle(mutex),
          "release-failure fixture closes its owned metadata handles");
  }
  {
    const auto retained = std::filesystem::temp_directory_path() / ("kyty_ps5_" + scope + "_dce_leases_v1.bin");
    std::vector<char> foreign(static_cast<size_t>(std::filesystem::file_size(retained)), char(0xa5));
    const std::string foreign_scope = scope + "b";
    const auto damaged = std::filesystem::temp_directory_path() /
        ("kyty_ps5_" + foreign_scope + "_dce_leases_v1.bin");
    Check(!std::filesystem::exists(damaged), "corrupt-header fixture owns a fresh isolated scope path");
    {
      std::ofstream output(damaged, std::ios::binary);
      output.write(foreign.data(), foreign.size());
      Check(output.good(), "write isolated foreign scope metadata without a valid header");
    }
    {
      Environment foreign_environment(foreign_scope);
      Requests rejected;
      Check(rejected.Create() == Kernel::KERNEL_ERROR_EIO,
            "DCE rejects foreign scope metadata instead of silently resetting it");
    }
    std::ifstream input(damaged, std::ios::binary);
    const std::vector<char> unchanged((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    Check(unchanged == foreign, "failed DCE scope attachment preserves every foreign metadata byte");
  }
  Check(CloseHandle(job), "release cross-host DCE worker containment");
  VO::VideoOutShutdown();
  std::printf("NativeDceLeaseTests: live_owner_conflict=pass clean_handoff=pass stale_release=pass "
              "dead_owner_reclaim=pass all_host_gap_sequence=pass release_failure_retry=pass "
              "foreign_metadata_preserved=pass\n");
#endif
}
