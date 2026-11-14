#if defined(_WIN32)
namespace NativeSshotTest {

namespace Kernel = Libs::LibKernel;
namespace FS = Libs::LibKernel::FileSystem;
namespace Memory = Libs::LibKernel::Memory;

constexpr int ProducerPid = 7771;
constexpr int ClientPid = 7772;
constexpr uint64_t BlockSize = 0x00200000;
constexpr uint64_t SpanSize = 0x0a200000;
constexpr size_t BlockCount = SpanSize / BlockSize;
constexpr uint64_t GuestBase = 0x0000004000000000;
constexpr uint64_t LocalGuestBase = 0x0000005000000000;
constexpr const char* MappingName = "CompositorShmScreenshotMem";

struct Request {
  uint32_t status;
  uint32_t reserved04;
  uint64_t region;
  uint64_t reserved10;
  uint32_t size;
  uint32_t block_size;
  uint32_t value;
  std::array<uint8_t, 0x4c> reserved24;
};
static_assert(sizeof(Request) == 0x70);

Request Canonical(uint64_t region) {
  Request request {};
  request.region = region;
  request.size = static_cast<uint32_t>(SpanSize);
  request.block_size = static_cast<uint32_t>(BlockSize);
  request.value = 0x60;
  return request;
}

void SelectScope(const char* scope) {
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", scope) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1") == 0,
        "select isolated screenshot direct-memory scope");
}

void InitializeChild(Common::Subsystems* subsystems) {
  Common::InitializeThreads();
  subsystems->Initialize<Config::Lifecycle>();
  Config::ConfigOptions options;
  options.printf_direction = Config::LogDirection::Silent;
  Config::Load(options);
  subsystems->Initialize<Log::Lifecycle>();
  subsystems->Initialize<Memory::Lifecycle>();
  FS::Initialize();
}

int RunProducer(const char* scope, const std::filesystem::path& record,
                const char* ready_name, const char* release_name) {
  auto evidence = record;
  evidence += L".producer.log";
  if (_wfreopen(evidence.c_str(), L"wb", stdout) == nullptr ||
      _wfreopen(evidence.c_str(), L"ab", stderr) == nullptr) return 3;
  SelectScope(scope);
  Common::Subsystems subsystems;
  InitializeChild(&subsystems);
  Kernel::Process::ScopedGuestProcessPid identity(ProducerPid);
  std::array<int64_t, BlockCount> physical {};
  for (size_t index = 0; index < physical.size(); ++index) {
    const int64_t start = index == 0 ? 0 : physical[index - 1] + BlockSize;
    Check(Memory::KernelAllocateDirectMemory(
              start, static_cast<int64_t>(Memory::KernelGetDirectMemorySize()), BlockSize,
              BlockSize, 11, &physical[index]) == OK &&
              (index == 0 || physical[index] == start),
          "producer allocates contiguous compositor direct-memory blocks");
    Check(Memory::KernelProtectDirectMemoryForPID(
              physical[index], BlockSize, 3, ClientPid) == OK,
          "producer grants each compositor block to the exact client pid");
  }
  {
    std::ofstream output(record, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(&physical[0]), sizeof(physical[0]));
    output.close();
    Check(static_cast<bool>(output), "publish bounded screenshot fixture offset");
  }
  HANDLE ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, ready_name);
  HANDLE release = OpenEventA(SYNCHRONIZE, FALSE, release_name);
  Check(ready != nullptr && release != nullptr && SetEvent(ready) != FALSE,
        "publish screenshot producer readiness");
  std::printf("NATIVE_SSHOT_PRODUCER_READY blocks=81 grants=81\n");
  std::fflush(stdout);
  Check(WaitForSingleObject(release, 120000) == WAIT_OBJECT_0,
        "producer remains alive through client completion");
  Check(CloseHandle(ready) && CloseHandle(release),
        "producer closes synchronization handles");
  for (auto it = physical.rbegin(); it != physical.rend(); ++it) {
    Check(Memory::KernelCheckedReleaseDirectMemory(*it, BlockSize) == OK,
          "producer releases each compositor block after client teardown");
  }
  std::printf("NATIVE_SSHOT_PRODUCER_DONE clean_release=1\n");
  std::fflush(stdout);
  FS::Shutdown();
  subsystems.Destroy();
  return 0;
}

int RunClient(const char* scope, int64_t physical, const std::filesystem::path& evidence) {
  if (_wfreopen(evidence.c_str(), L"wb", stdout) == nullptr ||
      _wfreopen(evidence.c_str(), L"ab", stderr) == nullptr) return 3;
  SelectScope(scope);
  Common::Subsystems subsystems;
  InitializeChild(&subsystems);
  Kernel::Process::ScopedGuestProcessPid identity(ClientPid);

  for (size_t index = 0; index < BlockCount; ++index) {
    void* address = reinterpret_cast<void*>(GuestBase + index * BlockSize);
    Check(Memory::KernelMapNamedDirectMemory(
              &address, BlockSize, 3, 0x10, physical + index * BlockSize,
              BlockSize, MappingName) == OK &&
              reinterpret_cast<uint64_t>(address) == GuestBase + index * BlockSize,
          "client imports each granted compositor block at the contiguous guest address");
  }

  void* request_page = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(
            &request_page, 0x4000, 3, 0, "native-sshot-request") == OK,
        "map guest screenshot request memory");
  auto* request = static_cast<Request*>(request_page);
  const auto put = [&](const Request& value) { std::memcpy(request, &value, sizeof(value)); };
  const auto expect_unchanged = [&](int descriptor, uint64_t command,
                                    const Request& value, int result, const char* message) {
    put(value);
    const auto before = *request;
    Check(FS::KernelIoctl(descriptor, command, request) == result &&
              std::memcmp(request, &before, sizeof(before)) == 0,
          message);
  };

  const std::array<int, 10> rejected_flags {{
      0, 1, 3, 0x100002, 0x202, 0x402, 0x00a, 0x802, 0x10002, 0x20002}};
  for (const auto flags: rejected_flags) {
    Check(FS::KernelOpen("/dev/sshot", flags, 0) == Kernel::KERNEL_ERROR_EINVAL,
          "bounded screenshot admission rejects every unobserved open flag tuple");
  }
  Check(FS::KernelOpen("/dev/sshot", 2, 1) == Kernel::KERNEL_ERROR_EINVAL,
        "screenshot device rejects an unobserved nonzero mode");

  const int descriptor = FS::KernelOpen("/dev/sshot", 2, 0);
  Check(descriptor >= 3, "open the production screenshot descriptor with the tuple");
  Request stack_request = Canonical(GuestBase);
  Check(FS::KernelIoctl(descriptor, 0xc0709d01u, nullptr) == Kernel::KERNEL_ERROR_EFAULT &&
            FS::KernelIoctl(descriptor, 0xc0709d01u, &stack_request) == Kernel::KERNEL_ERROR_EFAULT,
        "null and non-guest screenshot request pointers return EFAULT");
  auto* truncated = reinterpret_cast<uint8_t*>(request_page) + 0x3fc0;
  std::array<uint8_t, 0x40> truncated_before {};
  std::memset(truncated, 0x5a, truncated_before.size());
  std::memcpy(truncated_before.data(), truncated, truncated_before.size());
  Check(FS::KernelIoctl(descriptor, 0xc0709d01u, truncated) == Kernel::KERNEL_ERROR_EFAULT &&
            std::memcmp(truncated, truncated_before.data(), truncated_before.size()) == 0,
        "page-crossing truncated request returns EFAULT without mutation");
  put(Canonical(GuestBase));
  const auto readonly_before = *request;
  Check(Memory::KernelMprotect(request_page, 0x4000, 1) == OK &&
            FS::KernelIoctl(descriptor, 0xc0709d01u, request) == Kernel::KERNEL_ERROR_EFAULT &&
            std::memcmp(request, &readonly_before, sizeof(readonly_before)) == 0 &&
            Memory::KernelMprotect(request_page, 0x4000, 3) == OK,
        "read-only IOC_INOUT request returns EFAULT without state or byte changes");

  auto malformed = Canonical(GuestBase);
  malformed.status = 1;
  expect_unchanged(descriptor, 0xc0709d01u, malformed, Kernel::KERNEL_ERROR_EINVAL,
                   "nonzero screenshot status is rejected without mutation");
  malformed = Canonical(GuestBase);
  malformed.reserved04 = 1;
  expect_unchanged(descriptor, 0xc0709d01u, malformed, Kernel::KERNEL_ERROR_EINVAL,
                   "reserved screenshot word is rejected without mutation");
  malformed = Canonical(GuestBase);
  malformed.reserved10 = 1;
  expect_unchanged(descriptor, 0xc0709d01u, malformed, Kernel::KERNEL_ERROR_EINVAL,
                   "reserved screenshot qword is rejected without mutation");
  malformed = Canonical(GuestBase);
  --malformed.size;
  expect_unchanged(descriptor, 0xc0709d01u, malformed, Kernel::KERNEL_ERROR_EINVAL,
                   "wrong screenshot span is rejected without mutation");
  malformed = Canonical(GuestBase);
  malformed.block_size /= 2;
  expect_unchanged(descriptor, 0xc0709d01u, malformed, Kernel::KERNEL_ERROR_EINVAL,
                   "wrong screenshot block size is rejected without mutation");
  malformed = Canonical(GuestBase);
  ++malformed.value;
  expect_unchanged(descriptor, 0xc0709d01u, malformed, Kernel::KERNEL_ERROR_EINVAL,
                   "wrong screenshot control value is rejected without mutation");
  malformed = Canonical(GuestBase);
  malformed.reserved24.back() = 1;
  expect_unchanged(descriptor, 0xc0709d01u, malformed, Kernel::KERNEL_ERROR_EINVAL,
                   "nonzero screenshot tail is rejected without mutation");
  malformed = Canonical(GuestBase + 0x4000);
  expect_unchanged(descriptor, 0xc0709d01u, malformed, Kernel::KERNEL_ERROR_EINVAL,
                   "misaligned screenshot base is rejected without mutation");
  malformed = Canonical(UINT64_MAX - SpanSize + 1);
  expect_unchanged(descriptor, 0xc0709d01u, malformed, Kernel::KERNEL_ERROR_EINVAL,
                   "overflowing screenshot span is rejected without mutation");

  void* flexible = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(
            &flexible, SpanSize, 3, 21 << 24, MappingName) == OK,
        "map the correctly named but ineligible flexible-memory negative");
  expect_unchanged(descriptor, 0xc0709d01u,
                   Canonical(reinterpret_cast<uint64_t>(flexible)), Kernel::KERNEL_ERROR_EINVAL,
                   "renamed flexible memory cannot impersonate imported compositor backing");

  int64_t local_physical = 0;
  Check(Memory::KernelAllocateDirectMemory(
            0, static_cast<int64_t>(Memory::KernelGetDirectMemorySize()), SpanSize,
            BlockSize, 11, &local_physical) == OK,
        "allocate local direct-memory negative backing");
  void* local = reinterpret_cast<void*>(LocalGuestBase);
  Check(Memory::KernelMapNamedDirectMemory(
            &local, SpanSize, 3, 0x10, local_physical, BlockSize, MappingName) == OK,
        "map the correctly named but locally owned direct-memory negative");
  expect_unchanged(descriptor, 0xc0709d01u, Canonical(LocalGuestBase),
                   Kernel::KERNEL_ERROR_EINVAL,
                   "locally owned direct memory cannot impersonate imported compositor backing");

  Check(Memory::KernelSetVirtualRangeName(
            reinterpret_cast<void*>(GuestBase), BlockSize, "WrongScreenshotName") == OK,
        "replace one imported segment name for the negative case");
  expect_unchanged(descriptor, 0xc0709d01u, Canonical(GuestBase),
                   Kernel::KERNEL_ERROR_EINVAL,
                   "one wrong imported segment name rejects the full screenshot span");
  Check(Memory::KernelSetVirtualRangeName(
            reinterpret_cast<void*>(GuestBase), BlockSize, MappingName) == OK,
        "restore the imported segment name");
  Check(Memory::KernelMprotect(reinterpret_cast<void*>(GuestBase), BlockSize, 1) == OK,
        "make one imported segment read-only for the negative case");
  expect_unchanged(descriptor, 0xc0709d01u, Canonical(GuestBase),
                   Kernel::KERNEL_ERROR_EINVAL,
                   "one wrong imported segment protection rejects the full screenshot span");
  Check(Memory::KernelMprotect(reinterpret_cast<void*>(GuestBase), BlockSize, 3) == OK,
        "restore imported segment protection");
  Check(Memory::KernelMunmap(GuestBase + SpanSize - BlockSize, BlockSize) == OK,
        "remove one imported segment for the missing-span negative");
  expect_unchanged(descriptor, 0xc0709d01u, Canonical(GuestBase),
                   Kernel::KERNEL_ERROR_EINVAL,
                   "a missing imported segment rejects the full screenshot span");
  void* last = reinterpret_cast<void*>(GuestBase + SpanSize - BlockSize);
  Check(Memory::KernelMapNamedDirectMemory(
            &last, BlockSize, 3, 0x10, physical + SpanSize - BlockSize,
            BlockSize, MappingName) == OK,
        "restore the missing imported compositor segment");

  expect_unchanged(descriptor, 0xc0709d02u, Canonical(GuestBase),
                   Kernel::KERNEL_ERROR_EINVAL,
                   "bounded inactive-stop refusal leaves request and session unchanged");
  expect_unchanged(descriptor, 0xc0709d01u, Canonical(GuestBase), OK,
                   "exact screenshot start tuple reaches the imported backing");
  expect_unchanged(descriptor, 0xc0709d01u, Canonical(GuestBase),
                   Kernel::KERNEL_ERROR_EALREADY,
                   "bounded duplicate-start refusal preserves the active session");
  expect_unchanged(descriptor, 0xc4e09d03u, Canonical(GuestBase),
                   Kernel::KERNEL_ERROR_ENOTTY,
                   "unimplemented capture remains ENOTTY without manufacturing an image");
  expect_unchanged(descriptor, 0xc0709d99u, Canonical(GuestBase),
                   Kernel::KERNEL_ERROR_ENOTTY,
                   "unknown screenshot ioctl remains ENOTTY without changing the session");
  {
    Kernel::Process::ScopedGuestProcessPid foreign(ClientPid + 1);
    expect_unchanged(descriptor, 0xc0709d01u, Canonical(GuestBase),
                     Kernel::KERNEL_ERROR_EBADF,
                     "foreign pid cannot drive the owned screenshot descriptor");
    Check(FS::KernelClose(descriptor) == Kernel::KERNEL_ERROR_EBADF,
          "foreign pid cannot close the owned active screenshot descriptor");
  }
  expect_unchanged(descriptor, 0xc0709d01u, Canonical(GuestBase),
                   Kernel::KERNEL_ERROR_EALREADY,
                   "foreign failures leave the owner session active");
  expect_unchanged(descriptor, 0xc0709d02u, Canonical(GuestBase + BlockSize),
                   Kernel::KERNEL_ERROR_EINVAL,
                   "bounded mismatched-stop refusal leaves the owner session active");
  expect_unchanged(descriptor, 0xc0709d01u, Canonical(GuestBase),
                   Kernel::KERNEL_ERROR_EALREADY,
                   "failed stop does not clear the active session");
  expect_unchanged(descriptor, 0xc0709d02u, Canonical(GuestBase), OK,
                   "exact screenshot stop tuple releases the session");
  expect_unchanged(descriptor, 0xc0709d02u, Canonical(GuestBase),
                   Kernel::KERNEL_ERROR_EINVAL,
                   "bounded second-stop refusal leaves the inactive session unchanged");
  expect_unchanged(descriptor, 0xc0709d01u, Canonical(GuestBase), OK,
                   "owner can restart the stopped screenshot session");
  Check(FS::KernelClose(descriptor) == OK,
        "owner close tears down the active screenshot descriptor");

  const int reopened = FS::KernelOpen("/dev/sshot", 2, 0);
  Check(reopened >= 3, "reopen screenshot descriptor after active close");
  expect_unchanged(reopened, 0xc0709d02u, Canonical(GuestBase),
                   Kernel::KERNEL_ERROR_EINVAL,
                   "bounded inactive-stop refusal confirms reopened descriptor state");
  expect_unchanged(reopened, 0xc0709d01u, Canonical(GuestBase), OK,
                   "reopened screenshot descriptor starts a fresh session");
  Check(Memory::KernelMunmap(GuestBase + SpanSize - BlockSize, BlockSize) == OK,
        "remove one imported segment while the fresh session is active");
  expect_unchanged(reopened, 0xc4e09d03u, Canonical(GuestBase),
                   Kernel::KERNEL_ERROR_ENOTTY,
                   "unsupported capture stays ENOTTY after backing mutation without dereference");
  Check(FS::KernelClose(reopened) == OK,
        "explicit close clears the fresh session without dereferencing its backing");
  last = reinterpret_cast<void*>(GuestBase + SpanSize - BlockSize);
  Check(Memory::KernelMapNamedDirectMemory(
            &last, BlockSize, 3, 0x10, physical + SpanSize - BlockSize,
            BlockSize, MappingName) == OK,
        "restore the imported segment after safe active-session teardown");

  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(flexible), SpanSize) == OK &&
            Memory::KernelMunmap(LocalGuestBase, SpanSize) == OK &&
            Memory::KernelCheckedReleaseDirectMemory(local_physical, SpanSize) == OK,
        "negative screenshot backing fixtures release cleanly");
  const int bulk = FS::KernelOpen("/dev/sshot", 2, 0);
  Check(bulk >= 3, "open screenshot descriptor for bulk teardown");
  expect_unchanged(bulk, 0xc0709d01u, Canonical(GuestBase), OK,
                   "bulk teardown fixture owns a live screenshot session");
  FS::Shutdown();
  Check(Memory::KernelMunmap(GuestBase, SpanSize) == OK &&
            Memory::KernelMunmap(reinterpret_cast<uint64_t>(request_page), 0x4000) == OK,
        "client releases imported compositor and request mappings after descriptor teardown");
  std::printf("NATIVE_SSHOT_CLIENT_PASS imported_blocks=81 original_tuple_start=1 original_tuple_stop=1 bounded_refusals=1 ownership=1 close=1 bulk=1 capture_supported=0\n");
  std::fflush(stdout);
  subsystems.Destroy();
  return 0;
}

std::wstring ExecutablePath() {
  std::array<wchar_t, 32768> executable {};
  const DWORD length = GetModuleFileNameW(nullptr, executable.data(), executable.size());
  Check(length != 0 && length < executable.size(),
        "locate native screenshot fixture executable");
  return {executable.data(), length};
}

PROCESS_INFORMATION Start(HANDLE job, const std::wstring& executable,
                          std::wstring command) {
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process {};
  Check(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup, &process) &&
            AssignProcessToJobObject(job, process.hProcess) &&
            ResumeThread(process.hThread) != DWORD(-1),
        "start contained native screenshot fixture child");
  return process;
}

std::string ReadText(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void PrintFailureTail(const std::filesystem::path& path, const char* label) {
  auto text = ReadText(path);
  if (text.size() > 2048) text.erase(0, text.size() - 2048);
  for (auto& byte: text) {
    const auto value = static_cast<unsigned char>(byte);
    if (value != '\n' && value != '\r' && value != '\t' &&
        (value < 0x20 || value > 0x7e)) byte = '?';
  }
  std::fprintf(stderr, "NativeSshotTests: %s failure tail (%zu bytes):\n%s\n",
               label, text.size(), text.c_str());
}

}
#endif

int RunNativeSshotChild(int argc, char** argv) {
#if defined(_WIN32)
  if (argc < 2 || std::strcmp(argv[1], "--native-sshot-child") != 0) return -1;
  if (argc == 7 && std::strcmp(argv[2], "producer") == 0) {
    return NativeSshotTest::RunProducer(
        argv[3], Common::PathFromUtf8(argv[4]), argv[5], argv[6]);
  }
  if (argc == 6 && std::strcmp(argv[2], "client") == 0) {
    char* end = nullptr;
    const auto physical = _strtoi64(argv[4], &end, 16);
    Check(end != argv[4] && *end == '\0' && physical >= 0,
          "parse native screenshot physical offset");
    return NativeSshotTest::RunClient(
        argv[3], physical, Common::PathFromUtf8(argv[5]));
  }
  return 2;
#else
  (void)argc;
  (void)argv;
  return -1;
#endif
}

void CheckNativeSshot(const std::filesystem::path& root) {
#if defined(_WIN32)
  using namespace NativeSshotTest;
  char scope_bytes[21] {};
  std::snprintf(scope_bytes, sizeof(scope_bytes), "ss%08lx%08lx",
                GetCurrentProcessId(), static_cast<unsigned long>(GetTickCount()));
  const std::string scope = scope_bytes;
  const auto coordinate = root / "native_sshot_physical.bin";
  auto producer_evidence = coordinate;
  producer_evidence += L".producer.log";
  const auto client_evidence = root / "native_sshot_client.log";
  const auto ready_name = "Local\\kyty_sshot_" + scope + "_ready";
  const auto release_name = "Local\\kyty_sshot_" + scope + "_release";
  HANDLE ready = CreateEventA(nullptr, TRUE, FALSE, ready_name.c_str());
  HANDLE release = CreateEventA(nullptr, TRUE, FALSE, release_name.c_str());
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  Check(ready != nullptr && release != nullptr && job != nullptr &&
            SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                    &limits, sizeof(limits)),
        "create screenshot fixture events and kill-on-close job");
  const auto executable = ExecutablePath();
  const std::wstring wscope(scope.begin(), scope.end());
  const std::wstring wready(ready_name.begin(), ready_name.end());
  const std::wstring wrelease(release_name.begin(), release_name.end());
  auto producer_command = L"\"" + executable + L"\" --native-sshot-child producer " +
      wscope + L" \"" + coordinate.wstring() + L"\" \"" + wready + L"\" \"" +
      wrelease + L"\"";
  auto producer = Start(job, executable, std::move(producer_command));
  Check(WaitForSingleObject(ready, 60000) == WAIT_OBJECT_0,
        "wait for exact screenshot producer grants");
  int64_t physical = -1;
  {
    std::ifstream input(coordinate, std::ios::binary);
    input.read(reinterpret_cast<char*>(&physical), sizeof(physical));
    Check(static_cast<bool>(input) && physical >= 0,
          "read bounded screenshot fixture offset");
  }
  std::error_code ignored;
  std::filesystem::remove(coordinate, ignored);
  Check(!ignored && !std::filesystem::exists(coordinate),
        "remove transient screenshot fixture offset record");
  std::wostringstream physical_text;
  physical_text << std::hex << physical;
  auto client_command = L"\"" + executable + L"\" --native-sshot-child client " +
      wscope + L" " + physical_text.str() + L" \"" + client_evidence.wstring() + L"\"";
  auto client = Start(job, executable, std::move(client_command));
  Check(WaitForSingleObject(client.hProcess, 120000) == WAIT_OBJECT_0,
        "native screenshot client completes within two minutes");
  DWORD client_status = 1;
  const bool client_ok = GetExitCodeProcess(client.hProcess, &client_status) && client_status == 0;
  if (!client_ok) PrintFailureTail(client_evidence, "client");
  Check(client_ok,
        "native screenshot client exits successfully");
  Check(SetEvent(release) != FALSE &&
            WaitForSingleObject(producer.hProcess, 60000) == WAIT_OBJECT_0,
        "release and join native screenshot producer");
  DWORD producer_status = 1;
  const bool producer_ok = GetExitCodeProcess(producer.hProcess, &producer_status) && producer_status == 0;
  if (!producer_ok) PrintFailureTail(producer_evidence, "producer");
  Check(producer_ok,
        "native screenshot producer exits successfully");
  Check(ReadText(client_evidence).find(
            "NATIVE_SSHOT_CLIENT_PASS imported_blocks=81 original_tuple_start=1 original_tuple_stop=1 bounded_refusals=1 ownership=1 close=1 bulk=1 capture_supported=0") != std::string::npos &&
            ReadText(producer_evidence).find(
            "NATIVE_SSHOT_PRODUCER_DONE clean_release=1") != std::string::npos,
        "native screenshot cross-host fixture retains exact completion markers");
  CloseHandle(client.hThread);
  CloseHandle(client.hProcess);
  CloseHandle(producer.hThread);
  CloseHandle(producer.hProcess);
  CloseHandle(ready);
  CloseHandle(release);
  CloseHandle(job);
#else
  (void)root;
#endif
}




