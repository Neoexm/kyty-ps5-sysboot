#if defined(_WIN32)
struct AuthInfoScopeLifecycleFixture {
  Libs::LibKernel::AuthInfo::ImageIdentity identity {};
  Libs::LibKernel::AuthInfo::Record record {};
  Libs::LibKernel::AuthInfo::Capture capture {};
};

void AuthInfoScopeStore64(uint8_t* data, uint64_t value) {
  for (uint32_t i = 0; i != 8; ++i) data[i] = static_cast<uint8_t>(value >> (i * 8));
}

void AuthInfoScopeStore32(uint8_t* data, uint32_t value) {
  for (uint32_t i = 0; i != 4; ++i) data[i] = static_cast<uint8_t>(value >> (i * 8));
}

AuthInfoScopeLifecycleFixture MakeAuthInfoScopeLifecycleFixture(int guest_pid) {
  using namespace Libs::LibKernel::AuthInfo;
  AuthInfoScopeLifecycleFixture fixture;
  std::array<uint8_t, 193> self {};
  std::array<uint8_t, 521> elf {};
  const auto seed = static_cast<uint8_t>(guest_pid);
  for (size_t i = 0; i != self.size(); ++i) self[i] = static_cast<uint8_t>(seed + i * 17 + 3);
  for (size_t i = 0; i != elf.size(); ++i) elf[i] = static_cast<uint8_t>(seed * 3 + i * 29 + 7);
  fixture.identity.authority_id = 0x4800000010000004ull;
  fixture.identity.self_size = self.size();
  fixture.identity.elf_size = elf.size();
  fixture.identity.self_sha256 = Sha256(self.data(), self.size());
  fixture.identity.elf_sha256 = Sha256(elf.data(), elf.size());
  for (size_t i = 0; i != fixture.record.size(); ++i) {
    fixture.record[i] = static_cast<uint8_t>(seed + i * 5 + 11);
  }
  AuthInfoScopeStore64(fixture.record.data(), fixture.identity.authority_id);
  AuthInfoScopeStore64(fixture.record.data() + 8, 1ull << 62);
  Check(BuildCaptureEnvelope(fixture.record, fixture.identity, &fixture.capture, nullptr),
        "build scoped AuthInfo lifecycle fixture");
  return fixture;
}

Libs::LibKernel::AuthInfo::Observation MakeAuthInfoScopeLifecycleObservation(
    const Libs::LibKernel::AuthInfo::ImageIdentity& image, uint64_t known,
    uint64_t value, uint32_t native_pid = 52, uint32_t start_usec = 123456,
    int root_prison = -1) {
  using namespace Libs::LibKernel::AuthInfo;
  std::array<uint8_t, kObservationSize> encoded {};
  std::memcpy(encoded.data(), root_prison < 0 ? "KytyAO01" : "KytyAO02", 8);
  AuthInfoScopeStore32(encoded.data() + 8, root_prison < 0 ? 1 : 2);
  AuthInfoScopeStore32(encoded.data() + 12, encoded.size());
  AuthInfoScopeStore64(encoded.data() + 16, image.authority_id);
  AuthInfoScopeStore64(encoded.data() + 24, value);
  AuthInfoScopeStore64(encoded.data() + 32, known);
  std::copy(image.self_sha256.begin(), image.self_sha256.end(), encoded.begin() + 40);
  std::copy(image.elf_sha256.begin(), image.elf_sha256.end(), encoded.begin() + 72);
  encoded[104] = 1;
  AuthInfoScopeStore32(encoded.data() + 136, 0x13600007);
  AuthInfoScopeStore32(encoded.data() + 140, native_pid);
  AuthInfoScopeStore64(encoded.data() + 144, 100);
  AuthInfoScopeStore32(encoded.data() + 152, start_usec);
  if (root_prison >= 0) {
    AuthInfoScopeStore32(encoded.data() + 156,
                         1u | (root_prison != 0 ? 2u : 0u));
  }
  AuthInfoScopeStore64(encoded.data() + 160, 200);
  encoded[168] = 2;
  Observation observation;
  Check(ParseObservation(encoded.data(), encoded.size(),
          Sha256(encoded.data(), encoded.size()), image, &observation, nullptr),
        "build synthetic partial-knowledge observation fixture");
  return observation;
}

std::filesystem::path AuthInfoScopeLifecycleRecordPath(const std::string& scope,
                                                       const char* key, uint32_t id) {
  return std::filesystem::temp_directory_path() /
      ("kyty_ps5_" + scope + "_" + key + "_" + std::to_string(id) + ".txt");
}

std::filesystem::path AuthInfoScopeLifecycleSidecarPath(const std::string& scope,
                                                        int guest_pid) {
  return std::filesystem::temp_directory_path() /
      ("kyty_ps5_" + scope + "_authinfo_" + std::to_string(guest_pid) + ".bin");
}

std::filesystem::path AuthInfoScopeLifecycleObservationSidecarPath(
    const std::string& scope, int guest_pid) {
  return std::filesystem::temp_directory_path() /
      ("kyty_ps5_" + scope + "_authobs_" + std::to_string(guest_pid) + ".bin");
}

std::filesystem::path AuthInfoScopeLifecycleAllocatorPath(const std::string& scope) {
  return std::filesystem::temp_directory_path() /
      ("kyty_ps5_" + scope + "_pids_v1.bin");
}

uint64_t AuthInfoScopeLifecycleCurrentBirth() {
  FILETIME created {}, exited {}, kernel {}, user {};
  Check(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user) != FALSE,
        "read scoped AuthInfo lifecycle process birth time");
  return (static_cast<uint64_t>(created.dwHighDateTime) << 32) |
      created.dwLowDateTime;
}

void WriteAuthInfoScopeLifecycleFile(const std::filesystem::path& path,
                                     const void* data, size_t size) {
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  file.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
  file.close();
  Check(static_cast<bool>(file), "write scoped AuthInfo lifecycle file");
}

std::vector<uint8_t> ReadAuthInfoScopeLifecycleFile(const std::filesystem::path& path) {
  std::ifstream file(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

struct AuthInfoScopeLifecycleSavedEnvironment {
  std::string name;
  bool present = false;
  std::string value;

  explicit AuthInfoScopeLifecycleSavedEnvironment(const char* variable): name(variable) {
    char* current = nullptr;
    size_t size = 0;
    Check(_dupenv_s(&current, &size, name.c_str()) == 0,
          "read scoped AuthInfo lifecycle environment");
    if (current != nullptr) {
      present = true;
      value = current;
      std::free(current);
    }
  }

  ~AuthInfoScopeLifecycleSavedEnvironment() {
    Check(_putenv_s(name.c_str(), present ? value.c_str() : "") == 0,
          "restore scoped AuthInfo lifecycle environment");
  }
};

struct AuthInfoScopeLifecycleWorker {
  PROCESS_INFORMATION process {};
  HANDLE ready = nullptr;
  HANDLE release = nullptr;
  HANDLE revoked = nullptr;
  HANDLE finish = nullptr;
  std::string ready_name;
  std::string release_name;
  std::string revoked_name;
  std::string finish_name;
};

AuthInfoScopeLifecycleWorker StartAuthInfoScopeLifecycleWorker(const std::string& scope,
                                                               int guest_pid,
                                                               const char* mode,
                                                               HANDLE job) {
  std::array<wchar_t, 32768> executable {};
  const DWORD length = GetModuleFileNameW(nullptr, executable.data(), executable.size());
  Check(length != 0 && length < executable.size(),
        "find scoped AuthInfo lifecycle test executable");
  AuthInfoScopeLifecycleWorker worker;
  worker.ready_name = "Local\\kyty_authinfo_scope_" + scope + "_" +
      std::to_string(guest_pid) + "_ready";
  worker.release_name = "Local\\kyty_authinfo_scope_" + scope + "_" +
      std::to_string(guest_pid) + "_release";
  worker.revoked_name = "Local\\kyty_authinfo_scope_" + scope + "_" +
      std::to_string(guest_pid) + "_revoked";
  worker.finish_name = "Local\\kyty_authinfo_scope_" + scope + "_" +
      std::to_string(guest_pid) + "_finish";
  worker.ready = CreateEventA(nullptr, TRUE, FALSE, worker.ready_name.c_str());
  worker.release = CreateEventA(nullptr, TRUE, FALSE, worker.release_name.c_str());
  worker.revoked = CreateEventA(nullptr, TRUE, FALSE, worker.revoked_name.c_str());
  worker.finish = CreateEventA(nullptr, TRUE, FALSE, worker.finish_name.c_str());
  Check(worker.ready != nullptr && worker.release != nullptr &&
        worker.revoked != nullptr && worker.finish != nullptr,
        "create scoped AuthInfo lifecycle worker gates");
  std::wstring command = L"\"" + std::wstring(executable.data()) +
      L"\" --authinfo-scope-lifecycle-child " +
      std::wstring(scope.begin(), scope.end()) + L" " + std::to_wstring(guest_pid) + L" " +
      std::wstring(mode, mode + std::strlen(mode)) + L" " +
      std::wstring(worker.ready_name.begin(), worker.ready_name.end()) + L" " +
      std::wstring(worker.release_name.begin(), worker.release_name.end()) + L" " +
      std::wstring(worker.revoked_name.begin(), worker.revoked_name.end()) + L" " +
      std::wstring(worker.finish_name.begin(), worker.finish_name.end());
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  Check(CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup,
        &worker.process) != FALSE, "start scoped AuthInfo lifecycle subprocess");
  Check(AssignProcessToJobObject(job, worker.process.hProcess) &&
        ResumeThread(worker.process.hThread) != DWORD(-1),
        "contain and resume scoped AuthInfo lifecycle subprocess");
  Check(WaitForSingleObject(worker.ready, 15000) == WAIT_OBJECT_0,
        "scoped AuthInfo lifecycle subprocess publishes within bound");
  DWORD status = 0;
  Check(GetExitCodeProcess(worker.process.hProcess, &status) && status == STILL_ACTIVE,
        "scoped AuthInfo lifecycle subprocess remains live");
  return worker;
}

DWORD FinishAuthInfoScopeLifecycleWorker(AuthInfoScopeLifecycleWorker* worker,
                                         bool terminate) {
  if (terminate) {
    Check(TerminateProcess(worker->process.hProcess, 0x55) != FALSE,
          "terminate scoped AuthInfo lifecycle subprocess");
  } else {
    Check(SetEvent(worker->release) != FALSE,
          "release scoped AuthInfo lifecycle subprocess");
  }
  Check(WaitForSingleObject(worker->process.hProcess, 15000) == WAIT_OBJECT_0,
        "scoped AuthInfo lifecycle subprocess exits within bound");
  DWORD status = 0;
  Check(GetExitCodeProcess(worker->process.hProcess, &status),
        "read scoped AuthInfo lifecycle subprocess status");
  Check(CloseHandle(worker->process.hThread) && CloseHandle(worker->process.hProcess) &&
        CloseHandle(worker->ready) && CloseHandle(worker->release) &&
        CloseHandle(worker->revoked) && CloseHandle(worker->finish),
        "release scoped AuthInfo lifecycle subprocess handles");
  worker->process = {};
  worker->ready = nullptr;
  worker->release = nullptr;
  worker->revoked = nullptr;
  worker->finish = nullptr;
  return status;
}

bool WaitForAuthInfoScopeLifecycleAbsent(const std::filesystem::path& path) {
  const ULONGLONG deadline = GetTickCount64() + 5000;
  do {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
      const DWORD error = GetLastError();
      if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return true;
    }
    Sleep(10);
  } while (GetTickCount64() < deadline);
  return false;
}

void RemoveAuthInfoScopeLifecycleRecord(const std::string& scope, int guest_pid,
                                        uint32_t host_pid) {
  std::error_code ignored;
  std::filesystem::remove(AuthInfoScopeLifecycleRecordPath(
      scope, "pid", static_cast<uint32_t>(guest_pid)), ignored);
  std::filesystem::remove(AuthInfoScopeLifecycleRecordPath(scope, "host", host_pid), ignored);
}
#endif

int RunAuthInfoScopeLifecycleChild(int argc, char** argv) {
  if (argc != 9 || std::strcmp(argv[1], "--authinfo-scope-lifecycle-child") != 0) return -1;
#if defined(_WIN32)
  using namespace Libs::LibKernel;
  char* end = nullptr;
  const long parsed_pid = std::strtol(argv[3], &end, 10);
  Check(end != argv[3] && *end == 0 && parsed_pid > 0 &&
        parsed_pid <= std::numeric_limits<int>::max(),
        "parse scoped AuthInfo lifecycle guest PID");
  const int guest_pid = static_cast<int>(parsed_pid);
  const bool valid_mode = std::strcmp(argv[4], "return") == 0 ||
      std::strcmp(argv[4], "quick") == 0 || std::strcmp(argv[4], "wait") == 0 ||
      std::strcmp(argv[4], "identity") == 0 ||
      std::strcmp(argv[4], "clear-auth") == 0 ||
      std::strcmp(argv[4], "clear-self") == 0 ||
      std::strcmp(argv[4], "replace-auth") == 0 ||
      std::strcmp(argv[4], "replace-self") == 0 ||
      std::strcmp(argv[4], "observation") == 0 ||
      std::strcmp(argv[4], "observation-incomplete") == 0 ||
      std::strcmp(argv[4], "observation-hidden") == 0 ||
      std::strcmp(argv[4], "observation-clear-self") == 0;
  Check(valid_mode, "select scoped AuthInfo lifecycle child mode");
  const bool observation_mode = std::strncmp(argv[4], "observation", 11) == 0;
  const bool has_capture = std::strcmp(argv[4], "identity") != 0 && !observation_mode;
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", argv[2]) == 0 &&
        _putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1") == 0 &&
        _putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET", "") == 0,
        "set scoped AuthInfo lifecycle child environment");
  const bool hidden = std::strcmp(argv[4], "observation-hidden") == 0;
  auto fixture = MakeAuthInfoScopeLifecycleFixture(guest_pid);
  // ShellCore-style authority: the filtered record carries no authority id, only bits 60-62.
  if (hidden) fixture.identity.authority_id = 0x4800000000000010ull;
  Process::ClearVerifiedOriginalSelf();
  Process::InstallVerifiedOriginalSelf(fixture.identity);
  if (has_capture) {
    Check(Process::InstallVerifiedAuthInfo(fixture.capture),
          "install scoped AuthInfo lifecycle capture");
  }
  if (observation_mode) {
    const uint64_t known = std::strcmp(argv[4], "observation-incomplete") == 0
        ? uint64_t{1} << 62 : AuthInfo::kFilteredCapabilityMask;
    Check(Process::InstallVerifiedAuthorizationObservation(
              MakeAuthInfoScopeLifecycleObservation(
                  fixture.identity, known, hidden ? uint64_t{1} << 61 : uint64_t{1} << 62)),
          "install scoped authorization observation");
  }
  Process::ScopedGuestProcessPid identity(guest_pid);
  Process::PublishToScope();
  HANDLE ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, argv[5]);
  HANDLE release = OpenEventA(SYNCHRONIZE, FALSE, argv[6]);
  Check(ready != nullptr && release != nullptr && SetEvent(ready) != FALSE,
        "signal scoped AuthInfo lifecycle publication");
  Check(CloseHandle(ready), "release scoped AuthInfo lifecycle ready gate");
  Check(WaitForSingleObject(release, 15000) == WAIT_OBJECT_0,
        "wait for scoped AuthInfo lifecycle release");
  Check(CloseHandle(release), "release scoped AuthInfo lifecycle exit gate");
  const bool revoke = std::strcmp(argv[4], "clear-auth") == 0 ||
      std::strcmp(argv[4], "clear-self") == 0 ||
      std::strcmp(argv[4], "replace-auth") == 0 ||
      std::strcmp(argv[4], "replace-self") == 0 ||
      std::strcmp(argv[4], "observation-clear-self") == 0;
  if (revoke) {
    if (std::strcmp(argv[4], "clear-auth") == 0) {
      Process::ClearVerifiedAuthInfo();
    } else if (std::strcmp(argv[4], "clear-self") == 0) {
      Process::ClearVerifiedOriginalSelf();
    } else if (std::strcmp(argv[4], "replace-auth") == 0) {
      auto replacement_record = fixture.record;
      replacement_record[32] ^= 0xa5;
      AuthInfo::Capture replacement {};
      Check(AuthInfo::BuildCaptureEnvelope(replacement_record, fixture.identity,
            &replacement, nullptr) && Process::InstallVerifiedAuthInfo(replacement),
            "replace live scoped AuthInfo capture");
    } else if (std::strcmp(argv[4], "replace-self") == 0) {
      const auto replacement = MakeAuthInfoScopeLifecycleFixture(guest_pid + 1000);
      Process::InstallVerifiedOriginalSelf(replacement.identity);
    } else {
      Process::ClearVerifiedOriginalSelf();
    }
    HANDLE revoked = OpenEventA(EVENT_MODIFY_STATE, FALSE, argv[7]);
    HANDLE finish = OpenEventA(SYNCHRONIZE, FALSE, argv[8]);
    Check(revoked != nullptr && finish != nullptr && SetEvent(revoked) != FALSE,
          "signal scoped AuthInfo revocation");
    Check(CloseHandle(revoked), "release scoped AuthInfo revocation gate");
    Check(WaitForSingleObject(finish, 15000) == WAIT_OBJECT_0,
          "wait for scoped AuthInfo revocation verification");
    Check(CloseHandle(finish), "release scoped AuthInfo finish gate");
  }
  if (std::strcmp(argv[4], "quick") == 0) std::quick_exit(0);
  return 0;
#else
  return 2;
#endif
}

void CheckAuthInfoScopeLifecycle() {
#if defined(_WIN32)
  using namespace Libs::LibKernel;
  AuthInfoScopeLifecycleSavedEnvironment saved_scope(
      "KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE");
  AuthInfoScopeLifecycleSavedEnvironment saved_only(
      "KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY");
  AuthInfoScopeLifecycleSavedEnvironment saved_socket(
      "KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET");
  char scope_text[21] {};
  std::snprintf(scope_text, sizeof(scope_text), "a%08lx%08lx",
      GetCurrentProcessId(), static_cast<unsigned long>(GetTickCount()));
  const std::string scope = scope_text;
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", scope.c_str()) == 0 &&
        _putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1") == 0 &&
        _putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET", "") == 0,
        "set scoped AuthInfo lifecycle parent environment");
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  Check(job != nullptr && SetInformationJobObject(job,
        JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
        "contain scoped AuthInfo lifecycle subprocesses");
  void* output_memory = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&output_memory, 0x4000, 3, 0,
        "authinfo-scope-output") == OK,
        "map scoped AuthInfo guest output");
  auto* returned = static_cast<AuthInfo::Record*>(output_memory);
  Process::ScopedGuestProcessPid parent_identity(901);
  {
    Process::ClearVerifiedOriginalSelf();
    auto facts = Process::GetCurrentAuthorizationFacts();
    Check(!facts.has_authority && facts.known_capability0 == 0 &&
          !facts.root_prison_known,
          "absent image exposes no authorization facts");
    auto fixture = MakeAuthInfoScopeLifecycleFixture(901);
    AuthInfoScopeStore64(fixture.record.data() + 8, UINT64_MAX);
    Check(AuthInfo::BuildCaptureEnvelope(fixture.record, fixture.identity, &fixture.capture, nullptr),
          "build private-capability authorization fixture");
    Process::InstallVerifiedOriginalSelf(fixture.identity);
    facts = Process::GetCurrentAuthorizationFacts();
    Check(facts.has_authority && facts.authority_id == fixture.identity.authority_id &&
          facts.capability0 == 0 && facts.known_capability0 == 0,
          "verified SELF authority does not establish any capability bit");
    Check(Process::InstallVerifiedAuthInfo(fixture.capture), "install authorization facts fixture");
    facts = Process::GetCurrentAuthorizationFacts();
    Check(facts.has_authority && facts.capability0 == (1ull << 62) &&
          facts.known_capability0 == (1ull << 62) && !facts.root_prison_known,
          "authorization facts expose only the required capability bit");
    Process::ClearVerifiedAuthInfo();
    facts = Process::GetCurrentAuthorizationFacts();
    Check(facts.has_authority && facts.capability0 == 0 && facts.known_capability0 == 0,
          "clearing capture retains authority and revokes capability knowledge");
    Check(Process::InstallVerifiedAuthInfo(fixture.capture), "restore authorization facts fixture");
    ++fixture.identity.elf_size;
    Process::InstallVerifiedOriginalSelf(fixture.identity);
    facts = Process::GetCurrentAuthorizationFacts();
    Check(facts.has_authority && facts.known_capability0 == 0,
          "image size change revokes capability facts");
    Process::ClearVerifiedOriginalSelf();
    facts = Process::GetCurrentAuthorizationFacts();
    Check(!facts.has_authority && facts.known_capability0 == 0,
          "clearing image revokes all authorization facts");
  }

  {
    Process::ClearVerifiedOriginalSelf();
    const auto fixture = MakeAuthInfoScopeLifecycleFixture(901);
    Process::InstallVerifiedOriginalSelf(fixture.identity);
    const uint64_t bit = uint64_t{1} << 62;
    const uint64_t pair = bit | (uint64_t{1} << 60);
    Check(Process::InstallVerifiedAuthorizationObservation(
              MakeAuthInfoScopeLifecycleObservation(fixture.identity, bit, bit)),
          "install a single known capability without marking neighboring bits known");
    auto facts = Process::GetCurrentAuthorizationFacts();
    Check(facts.known_capability0 == bit && facts.capability0 == bit &&
          !facts.root_prison_known,
          "single-bit observation leaves bits60/61 unknown");
    AuthInfo::Record filtered;
    filtered.fill(0xa5);
    const auto untouched = filtered;
    Check(!Process::GetCurrentFilteredAuthInfo(&filtered) && filtered == untouched,
          "incomplete public knowledge yields no filtered syscall record");
    Check(Process::InstallVerifiedAuthorizationObservation(
              MakeAuthInfoScopeLifecycleObservation(fixture.identity, pair, bit)),
          "a compatible same-instance superset replaces the prior canonical observation");
    Check(!Process::InstallVerifiedAuthorizationObservation(
              MakeAuthInfoScopeLifecycleObservation(fixture.identity, bit, bit)),
          "replacement cannot discard previously verified capability knowledge");
    facts = Process::GetCurrentAuthorizationFacts();
    Check(facts.known_capability0 == pair && facts.capability0 == bit,
          "rejected narrower replacement preserves prior facts");
    Check(!Process::InstallVerifiedAuthorizationObservation(
              MakeAuthInfoScopeLifecycleObservation(
                  fixture.identity, AuthInfo::kFilteredCapabilityMask, 0)),
          "overlapping contradictory observation is rejected");
    Check(!Process::InstallVerifiedAuthorizationObservation(
              MakeAuthInfoScopeLifecycleObservation(
                  fixture.identity, AuthInfo::kFilteredCapabilityMask, bit, 53)) &&
          !Process::InstallVerifiedAuthorizationObservation(
              MakeAuthInfoScopeLifecycleObservation(
                  fixture.identity, AuthInfo::kFilteredCapabilityMask, bit, 52, 123457)),
          "different native process instances cannot replace existing observation scope");
    const auto other = MakeAuthInfoScopeLifecycleFixture(902);
    Check(!Process::InstallVerifiedAuthorizationObservation(
              MakeAuthInfoScopeLifecycleObservation(other.identity, pair, bit)),
          "another exact image cannot provide the installed process authorization");
    Check(Process::InstallVerifiedAuthorizationObservation(
              MakeAuthInfoScopeLifecycleObservation(
                  fixture.identity, AuthInfo::kFilteredCapabilityMask, bit)) &&
          Process::GetCurrentFilteredAuthInfo(&filtered),
          "all three public capability bits must be known before constructing a filtered record");
    Check(Process::InstallVerifiedAuthorizationObservation(
              MakeAuthInfoScopeLifecycleObservation(
                  fixture.identity, AuthInfo::kFilteredCapabilityMask, bit,
                  52, 123456, 1)),
          "same-instance version-two observation adds verified root-prison knowledge");
    facts = Process::GetCurrentAuthorizationFacts();
    Check(facts.root_prison_known && facts.root_prison &&
          facts.known_capability0 == AuthInfo::kFilteredCapabilityMask &&
          facts.capability0 == bit,
          "authorization facts preserve prison and capability knowledge separately");
    Check(!Process::InstallVerifiedAuthorizationObservation(
              MakeAuthInfoScopeLifecycleObservation(
                  fixture.identity, AuthInfo::kFilteredCapabilityMask, bit)) &&
          !Process::InstallVerifiedAuthorizationObservation(
              MakeAuthInfoScopeLifecycleObservation(
                  fixture.identity, AuthInfo::kFilteredCapabilityMask, bit,
                  52, 123456, 0)) &&
          !Process::InstallVerifiedAuthorizationObservation(
              MakeAuthInfoScopeLifecycleObservation(
                  fixture.identity, AuthInfo::kFilteredCapabilityMask, bit,
                  53, 123456, 1)),
          "replacement cannot discard, contradict or transplant verified prison knowledge");
    Check(Process::InstallVerifiedAuthInfo(fixture.capture),
          "compatible full capture can coexist with partial observation provenance");
    auto contradictory = MakeAuthInfoScopeLifecycleFixture(901);
    AuthInfoScopeStore64(contradictory.record.data() + 8, 0);
    Check(AuthInfo::BuildCaptureEnvelope(contradictory.record, contradictory.identity,
              &contradictory.capture, nullptr) &&
          !Process::InstallVerifiedAuthInfo(contradictory.capture),
          "full capture cannot contradict observed capability knowledge");
    Process::ClearVerifiedOriginalSelf();
    Process::InstallVerifiedOriginalSelf(fixture.identity);
    Check(Process::InstallVerifiedAuthInfo(fixture.capture) &&
          !Process::InstallVerifiedAuthorizationObservation(
              MakeAuthInfoScopeLifecycleObservation(fixture.identity, bit, 0)),
          "a partial observation cannot contradict an installed full capture");
    Process::ClearVerifiedOriginalSelf();
    facts = Process::GetCurrentAuthorizationFacts();
    Check(!facts.has_authority && facts.known_capability0 == 0 &&
          !facts.root_prison_known && !facts.root_prison,
          "clearing the image also revokes partial observation knowledge");
  }

  struct ExitCase {
    int guest_pid;
    const char* mode;
    bool terminate;
    DWORD expected_status;
  };
  const std::array<ExitCase, 3> exit_cases {{
      {31001, "return", false, 0},
      {31002, "quick", false, 0},
      {31003, "wait", true, 0x55},
  }};
  for (const auto& test: exit_cases) {
    const auto fixture = MakeAuthInfoScopeLifecycleFixture(test.guest_pid);
    auto worker = StartAuthInfoScopeLifecycleWorker(scope, test.guest_pid,
        test.mode, job);
    Process::PeerProcess peer;
    Check(Process::FindPeerByPid(test.guest_pid, &peer) &&
          peer.host_pid == worker.process.dwProcessId &&
          peer.auth_id == fixture.identity.authority_id && peer.has_auth_info &&
          peer.auth_info == fixture.record,
          "live cross-host scoped AuthInfo record is exact");
    const auto sidecar = AuthInfoScopeLifecycleSidecarPath(scope, test.guest_pid);
    Check(GetFileAttributesW(sidecar.c_str()) != INVALID_FILE_ATTRIBUTES,
          "live scoped AuthInfo sidecar has a published path");
    HANDLE writer = CreateFileW(sidecar.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    const DWORD write_error = GetLastError();
    Check(writer == INVALID_HANDLE_VALUE &&
          (write_error == ERROR_SHARING_VIOLATION || write_error == ERROR_ACCESS_DENIED),
          "live scoped AuthInfo sidecar denies a second writer");
    const uint32_t host_pid = worker.process.dwProcessId;
    Check(FinishAuthInfoScopeLifecycleWorker(&worker, test.terminate) ==
          test.expected_status, "scoped AuthInfo lifecycle subprocess exit status");
    Check(WaitForAuthInfoScopeLifecycleAbsent(sidecar),
          "host termination removes its scoped AuthInfo sidecar");
    Process::PeerProcess exited_peer;
    Check(!Process::FindPeerByPid(test.guest_pid, &exited_peer) ||
          !exited_peer.has_auth_info,
          "terminated host cannot expose scoped AuthInfo");
    RemoveAuthInfoScopeLifecycleRecord(scope, test.guest_pid, host_pid);
  }

  const std::array<std::pair<int, const char*>, 3> observation_cases {{
      {31013, "observation"},
      {31014, "observation-incomplete"},
      {31030, "observation-hidden"},
  }};
  for (const auto& test: observation_cases) {
    auto fixture = MakeAuthInfoScopeLifecycleFixture(test.first);
    auto worker = StartAuthInfoScopeLifecycleWorker(scope, test.first,
        test.second, job);
    Process::PeerProcess peer;
    const bool hidden = std::strcmp(test.second, "observation-hidden") == 0;
    const bool complete = std::strcmp(test.second, "observation-incomplete") != 0;
    auto expected = AuthInfo::Filter(fixture.record);
    if (hidden) {
      fixture.identity.authority_id = 0x4800000000000010ull;
      expected.fill(0);
      AuthInfoScopeStore64(expected.data() + 8, uint64_t{1} << 61);
    }
    Check(Process::FindPeerByPid(test.first, &peer) &&
          peer.host_pid == worker.process.dwProcessId &&
          peer.auth_id == fixture.identity.authority_id && !peer.has_auth_info &&
          peer.has_filtered_auth_info == complete &&
          (complete ? peer.filtered_auth_info == expected :
              std::all_of(peer.filtered_auth_info.begin(), peer.filtered_auth_info.end(),
                          [](uint8_t value) { return value == 0; })),
          "remote observation exposes only a complete exact filtered target record");
    returned->fill(0xcc);
    *Libs::Posix::GetErrorAddr() = 0;
    const int auth_result = Libs::KernelGetAuthinfo(test.first, returned->data());
    Check(complete ? auth_result == 0 && *returned == expected :
              auth_result == -1 && *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOENT &&
              std::all_of(returned->begin(), returned->end(), [](uint8_t value) { return value == 0xcc; }),
          "sceKernelGetAuthinfo returns a remote complete observation and ENOENT for an incomplete one");
    if (complete) {
      const auto copied = *returned;
      *Libs::Posix::GetErrorAddr() = 0;
      Check(Libs::KernelGetAuthinfo(test.first, reinterpret_cast<void*>(uintptr_t {1})) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT && *returned == copied,
            "sceKernelGetAuthinfo rejects an invalid guest output without corrupting valid storage");
    }
    // HLE sceKernelGetAuthinfo answers any live peer; the SysAv trap only answers for the IPMI client it's serving
    const char* trap_flag = std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS");
    const std::string saved_trap_flag = trap_flag ? trap_flag : "";
    _putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1");
    returned->fill(0xcc);
    const auto native_remote = Libs::NativeKernelBridge::DispatchSyscall(
        {0x24b, {static_cast<uint64_t>(test.first), reinterpret_cast<uint64_t>(returned->data())}});
    _putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", saved_trap_flag.c_str());
    Check(native_remote.value == -1 && native_remote.posix_errno == Libs::Posix::POSIX_ESRCH &&
          std::all_of(returned->begin(), returned->end(), [](uint8_t value) { return value == 0xcc; }),
          "native get_authinfo refuses a live remote peer record outside an IPMI transaction");
    const auto sidecar = AuthInfoScopeLifecycleObservationSidecarPath(scope, test.first);
    Check(GetFileAttributesW(sidecar.c_str()) != INVALID_FILE_ATTRIBUTES,
          "live scoped observation sidecar has a published path");
    HANDLE writer = CreateFileW(sidecar.c_str(), GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    const DWORD write_error = GetLastError();
    Check(writer == INVALID_HANDLE_VALUE &&
          (write_error == ERROR_SHARING_VIOLATION || write_error == ERROR_ACCESS_DENIED),
          "live scoped observation sidecar denies a second writer");
    const uint32_t host_pid = worker.process.dwProcessId;
    Check(FinishAuthInfoScopeLifecycleWorker(&worker, false) == 0,
          "scoped observation lifecycle subprocess exits cleanly");
    Check(WaitForAuthInfoScopeLifecycleAbsent(sidecar),
          "host exit removes its scoped observation sidecar");
    Process::PeerProcess exited_peer;
    Check(!Process::FindPeerByPid(test.first, &exited_peer) ||
          !exited_peer.has_filtered_auth_info,
          "terminated host cannot expose a filtered observation record");
    Check(Libs::KernelGetAuthinfo(test.first, returned->data()) == -1,
          "sceKernelGetAuthinfo fails once the observing host exits");
    RemoveAuthInfoScopeLifecycleRecord(scope, test.first, host_pid);
  }

  {
    const uint64_t bit62 = uint64_t{1} << 62;
    const int target_pid = 31031;
    auto target = MakeAuthInfoScopeLifecycleFixture(target_pid);
    target.identity.authority_id = 0x4800000000000010ull;
    auto worker = StartAuthInfoScopeLifecycleWorker(
        scope, target_pid, "observation-hidden", job);
    const auto caller = MakeAuthInfoScopeLifecycleFixture(901);
    AuthInfo::Record filtered_target {};
    AuthInfoScopeStore64(filtered_target.data() + 8, uint64_t{1} << 61);
    AuthInfo::Record partial_target = filtered_target;
    AuthInfoScopeStore64(partial_target.data(), target.identity.authority_id);
    const auto install_caller = [&](uint64_t known, uint64_t value,
                                    int root_prison) {
      Process::ClearVerifiedOriginalSelf();
      Process::InstallVerifiedOriginalSelf(caller.identity);
      Check(Process::InstallVerifiedAuthorizationObservation(
                MakeAuthInfoScopeLifecycleObservation(
                    caller.identity, known, value, 52, 123456, root_prison)),
            "install syscall 587 caller authorization fixture");
    };
    const auto check_filtered = [&](uint64_t known, uint64_t value,
                                    int root_prison, const char* message) {
      install_caller(known, value, root_prison);
      returned->fill(0xcc);
      *Libs::Posix::GetErrorAddr() = 0;
      Check(Libs::KernelGetAuthinfo(target_pid, returned->data()) == 0 &&
            *returned == filtered_target, message);
    };
    check_filtered(bit62, bit62, -1,
        "bit62 without prison knowledge keeps syscall 587 on filtered success");
    check_filtered(bit62, bit62, 0,
        "verified non-root prison keeps syscall 587 on filtered success");
    check_filtered(bit62, 0, 1,
        "verified root prison with clear bit62 keeps syscall 587 on filtered success");
    check_filtered(uint64_t{1} << 60, 0, 1,
        "verified root prison with unknown bit62 keeps syscall 587 on filtered success");
    install_caller(bit62, bit62, 1);
    returned->fill(0xcc);
    *Libs::Posix::GetErrorAddr() = 0;
    Check(Libs::KernelGetAuthinfo(target_pid, returned->data()) == 0 &&
          *returned == partial_target,
          "root-prison and bit62 privilege reveals only independently verified observation fields");
    const auto copied = *returned;
    Check(Libs::KernelGetAuthinfo(target_pid,
              reinterpret_cast<void*>(uintptr_t {1})) == -1 &&
          *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT &&
          *returned == copied,
          "privileged syscall 587 copyout failure preserves valid storage");
    const uint32_t observation_host_pid = worker.process.dwProcessId;
    Check(FinishAuthInfoScopeLifecycleWorker(&worker, false) == 0,
          "privileged partial-observation target exits cleanly");
    RemoveAuthInfoScopeLifecycleRecord(scope, target_pid, observation_host_pid);
    returned->fill(0xcc);
    *Libs::Posix::GetErrorAddr() = 0;
    Check(Libs::KernelGetAuthinfo(target_pid, returned->data()) == -1 &&
          *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ESRCH &&
          std::all_of(returned->begin(), returned->end(),
                      [](uint8_t value) { return value == 0xcc; }),
          "privilege cannot revive a terminated target or modify output");

    const int full_pid = 31032;
    const auto full_target = MakeAuthInfoScopeLifecycleFixture(full_pid);
    auto full_worker = StartAuthInfoScopeLifecycleWorker(
        scope, full_pid, "return", job);
    returned->fill(0xcc);
    *Libs::Posix::GetErrorAddr() = 0;
    Check(Libs::KernelGetAuthinfo(full_pid, returned->data()) == 0 &&
          *returned == full_target.record,
          "privileged syscall 587 returns a byte-exact verified target capture");
    const uint32_t full_host_pid = full_worker.process.dwProcessId;
    Check(FinishAuthInfoScopeLifecycleWorker(&full_worker, false) == 0,
          "privileged full-capture target exits cleanly");
    RemoveAuthInfoScopeLifecycleRecord(scope, full_pid, full_host_pid);
    Process::ClearVerifiedOriginalSelf();
  }

  {
    const int guest_pid = 31015;
    const auto fixture = MakeAuthInfoScopeLifecycleFixture(guest_pid);
    auto worker = StartAuthInfoScopeLifecycleWorker(scope, guest_pid,
        "observation-clear-self", job);
    Process::PeerProcess published;
    Check(Process::FindPeerByPid(guest_pid, &published) &&
          !published.has_auth_info && published.has_filtered_auth_info &&
          published.filtered_auth_info == AuthInfo::Filter(fixture.record),
          "live scoped observation is visible before image revocation");
    const auto sidecar = AuthInfoScopeLifecycleObservationSidecarPath(scope, guest_pid);
    Check(SetEvent(worker.release) != FALSE &&
          WaitForSingleObject(worker.revoked, 15000) == WAIT_OBJECT_0,
          "explicit scoped observation revocation completes within bound");
    DWORD status = 0;
    Check(GetExitCodeProcess(worker.process.hProcess, &status) && status == STILL_ACTIVE,
          "scoped observation owner remains live after revocation");
    Check(WaitForAuthInfoScopeLifecycleAbsent(sidecar),
          "image revocation removes the live observation sidecar");
    Process::PeerProcess revoked;
    Check(Process::FindPeerByPid(guest_pid, &revoked) &&
          !revoked.has_auth_info && !revoked.has_filtered_auth_info,
          "live host exposes no observation after image revocation");
    Check(SetEvent(worker.finish) != FALSE,
          "release explicitly revoked scoped observation subprocess");
    const uint32_t host_pid = worker.process.dwProcessId;
    Check(FinishAuthInfoScopeLifecycleWorker(&worker, false) == 0,
          "explicitly revoked scoped observation subprocess exits cleanly");
    RemoveAuthInfoScopeLifecycleRecord(scope, guest_pid, host_pid);
  }

  const std::array<std::pair<int, const char*>, 4> revoke_cases {{
      {31007, "clear-auth"},
      {31009, "clear-self"},
      {31010, "replace-auth"},
      {31011, "replace-self"},
  }};
  for (const auto& revoke_case: revoke_cases) {
    const int guest_pid = revoke_case.first;
    const auto fixture = MakeAuthInfoScopeLifecycleFixture(guest_pid);
    auto worker = StartAuthInfoScopeLifecycleWorker(scope, guest_pid,
        revoke_case.second, job);
    Process::PeerProcess published;
    Check(Process::FindPeerByPid(guest_pid, &published) && published.has_auth_info &&
          published.auth_info == fixture.record,
          "live scoped AuthInfo is visible before explicit revocation");
    const auto sidecar = AuthInfoScopeLifecycleSidecarPath(scope, guest_pid);
    Check(SetEvent(worker.release) != FALSE &&
          WaitForSingleObject(worker.revoked, 15000) == WAIT_OBJECT_0,
          "explicit scoped AuthInfo revocation completes within bound");
    DWORD status = 0;
    Check(GetExitCodeProcess(worker.process.hProcess, &status) && status == STILL_ACTIVE,
          "scoped AuthInfo owner remains live after explicit revocation");
    Check(WaitForAuthInfoScopeLifecycleAbsent(sidecar),
          "explicit AuthInfo clear removes the live scoped sidecar");
    Process::PeerProcess revoked;
    Check(Process::FindPeerByPid(guest_pid, &revoked) && !revoked.has_auth_info,
          "live host exposes no AuthInfo after explicit revocation");
    Check(SetEvent(worker.finish) != FALSE,
          "release explicitly revoked scoped AuthInfo subprocess");
    const uint32_t host_pid = worker.process.dwProcessId;
    Check(FinishAuthInfoScopeLifecycleWorker(&worker, false) == 0,
          "explicitly revoked scoped AuthInfo subprocess exits cleanly");
    RemoveAuthInfoScopeLifecycleRecord(scope, guest_pid, host_pid);
  }

  const std::array<uint8_t, 23> sentinel {{
      0x75, 0x6e, 0x6f, 0x77, 0x6e, 0x65, 0x64, 0x2d,
      0x61, 0x75, 0x74, 0x68, 0x69, 0x6e, 0x66, 0x6f,
      0x2d, 0x73, 0x69, 0x64, 0x65, 0x63, 0x61,
  }};
  for (const auto& test: std::array<std::pair<int, const char*>, 2> {{
           {31004, "return"}, {31005, "identity"}}}) {
    const auto sidecar = AuthInfoScopeLifecycleSidecarPath(scope, test.first);
    WriteAuthInfoScopeLifecycleFile(sidecar, sentinel.data(), sentinel.size());
    auto worker = StartAuthInfoScopeLifecycleWorker(scope, test.first,
        test.second, job);
    Check(ReadAuthInfoScopeLifecycleFile(sidecar) ==
          std::vector<uint8_t>(sentinel.begin(), sentinel.end()),
          "publication preserves an unowned scoped AuthInfo sentinel");
    Process::PeerProcess peer;
    Check(Process::FindPeerByPid(test.first, &peer) && !peer.has_auth_info,
          "failed or absent scoped AuthInfo publication exposes no record");
    const uint32_t host_pid = worker.process.dwProcessId;
    Check(FinishAuthInfoScopeLifecycleWorker(&worker, false) == 0,
          "sentinel scoped AuthInfo lifecycle subprocess exits cleanly");
    Check(ReadAuthInfoScopeLifecycleFile(sidecar) ==
          std::vector<uint8_t>(sentinel.begin(), sentinel.end()),
          "host exit preserves an unowned scoped AuthInfo sentinel");
    std::error_code ignored;
    std::filesystem::remove(sidecar, ignored);
    RemoveAuthInfoScopeLifecycleRecord(scope, test.first, host_pid);
  }

  {
    const int guest_pid = 31016;
    const auto sidecar = AuthInfoScopeLifecycleObservationSidecarPath(scope, guest_pid);
    WriteAuthInfoScopeLifecycleFile(sidecar, sentinel.data(), sentinel.size());
    auto worker = StartAuthInfoScopeLifecycleWorker(scope, guest_pid,
        "observation", job);
    Check(ReadAuthInfoScopeLifecycleFile(sidecar) ==
          std::vector<uint8_t>(sentinel.begin(), sentinel.end()),
          "observation publication preserves an unowned sidecar sentinel");
    Process::PeerProcess peer;
    Check(Process::FindPeerByPid(guest_pid, &peer) &&
          !peer.has_auth_info && !peer.has_filtered_auth_info,
          "failed observation publication exposes no filtered record");
    const uint32_t host_pid = worker.process.dwProcessId;
    Check(FinishAuthInfoScopeLifecycleWorker(&worker, false) == 0,
          "sentinel scoped observation subprocess exits cleanly");
    Check(ReadAuthInfoScopeLifecycleFile(sidecar) ==
          std::vector<uint8_t>(sentinel.begin(), sentinel.end()),
          "host exit preserves an unowned observation sentinel");
    std::error_code ignored;
    std::filesystem::remove(sidecar, ignored);
    RemoveAuthInfoScopeLifecycleRecord(scope, guest_pid, host_pid);
  }

  const int legacy_pid = 31006;
  const auto legacy_fixture = MakeAuthInfoScopeLifecycleFixture(legacy_pid);
  std::array<uint8_t, AuthInfo::kScopedCaptureSize> legacy_sidecar {};
  Check(AuthInfo::EncodeScopedCapture(legacy_fixture.capture, legacy_pid,
        GetCurrentProcessId(), &legacy_sidecar),
        "encode legacy scoped AuthInfo sidecar");
  const auto legacy_path = AuthInfoScopeLifecycleSidecarPath(scope, legacy_pid);
  WriteAuthInfoScopeLifecycleFile(legacy_path, legacy_sidecar.data(),
      legacy_sidecar.size());
  {
    std::ofstream record(AuthInfoScopeLifecycleRecordPath(
        scope, "pid", static_cast<uint32_t>(legacy_pid)), std::ios::trunc);
    record << GetCurrentProcessId() << ' ' << legacy_fixture.identity.authority_id
           << " self=" << AuthInfo::DigestHex(legacy_fixture.identity.self_sha256)
           << " elf=" << AuthInfo::DigestHex(legacy_fixture.identity.elf_sha256) << '\n';
    record.close();
    Check(static_cast<bool>(record), "write legacy scoped AuthInfo metadata");
  }
  Process::PeerProcess legacy_peer;
  Check(!Process::FindPeerByPid(legacy_pid, &legacy_peer) ||
        !legacy_peer.has_auth_info,
        "legacy metadata without lifecycle markers exposes no AuthInfo");
  std::error_code ignored;
  std::filesystem::remove(legacy_path, ignored);
  std::filesystem::remove(AuthInfoScopeLifecycleRecordPath(
      scope, "pid", static_cast<uint32_t>(legacy_pid)), ignored);

  const int wrong_birth_pid = 31008;
  const auto wrong_birth_fixture = MakeAuthInfoScopeLifecycleFixture(wrong_birth_pid);
  std::array<uint8_t, AuthInfo::kScopedCaptureSize> wrong_birth_sidecar {};
  Check(AuthInfo::EncodeScopedCapture(wrong_birth_fixture.capture, wrong_birth_pid,
        GetCurrentProcessId(), &wrong_birth_sidecar),
        "encode wrong-birth scoped AuthInfo sidecar");
  const auto wrong_birth_path = AuthInfoScopeLifecycleSidecarPath(scope, wrong_birth_pid);
  WriteAuthInfoScopeLifecycleFile(wrong_birth_path, wrong_birth_sidecar.data(),
      wrong_birth_sidecar.size());
  {
    std::ofstream record(AuthInfoScopeLifecycleRecordPath(
        scope, "pid", static_cast<uint32_t>(wrong_birth_pid)), std::ios::trunc);
    record << GetCurrentProcessId() << ' ' << wrong_birth_fixture.identity.authority_id
           << " birth=0000000000000001"
           << " self=" << AuthInfo::DigestHex(wrong_birth_fixture.identity.self_sha256)
           << " elf=" << AuthInfo::DigestHex(wrong_birth_fixture.identity.elf_sha256)
           << " authinfo=" << AuthInfo::DigestHex(
                wrong_birth_fixture.capture.envelope_sha256) << '\n';
    record.close();
    Check(static_cast<bool>(record), "write wrong-birth scoped AuthInfo metadata");
  }
  Process::PeerProcess wrong_birth_peer;
  Check(Process::FindPeerByPid(wrong_birth_pid, &wrong_birth_peer) &&
        !wrong_birth_peer.has_auth_info,
        "mismatched host birth time exposes no scoped AuthInfo");
  std::filesystem::remove(wrong_birth_path, ignored);
  std::filesystem::remove(AuthInfoScopeLifecycleRecordPath(
      scope, "pid", static_cast<uint32_t>(wrong_birth_pid)), ignored);

  const int tampered_pid = 31012;
  const auto tampered_fixture = MakeAuthInfoScopeLifecycleFixture(tampered_pid);
  std::array<uint8_t, AuthInfo::kScopedCaptureSize> tampered_sidecar {};
  Check(AuthInfo::EncodeScopedCapture(tampered_fixture.capture, tampered_pid,
        GetCurrentProcessId(), &tampered_sidecar),
        "encode tampered scoped AuthInfo sidecar");
  tampered_sidecar.back() ^= 0x80;
  const auto tampered_path = AuthInfoScopeLifecycleSidecarPath(scope, tampered_pid);
  WriteAuthInfoScopeLifecycleFile(tampered_path, tampered_sidecar.data(),
      tampered_sidecar.size());
  {
    std::ofstream record(AuthInfoScopeLifecycleRecordPath(
        scope, "pid", static_cast<uint32_t>(tampered_pid)), std::ios::trunc);
    record << GetCurrentProcessId() << ' ' << tampered_fixture.identity.authority_id
           << " birth=" << std::hex << std::setw(16) << std::setfill('0')
           << AuthInfoScopeLifecycleCurrentBirth()
           << " self=" << AuthInfo::DigestHex(tampered_fixture.identity.self_sha256)
           << " elf=" << AuthInfo::DigestHex(tampered_fixture.identity.elf_sha256)
           << " authinfo=" << AuthInfo::DigestHex(
                tampered_fixture.capture.envelope_sha256) << '\n';
    record.close();
    Check(static_cast<bool>(record), "write tampered scoped AuthInfo metadata");
  }
  Process::PeerProcess tampered_peer;
  Check(Process::FindPeerByPid(tampered_pid, &tampered_peer) &&
        !tampered_peer.has_auth_info,
        "tampered scoped AuthInfo sidecar exposes no record");
  std::filesystem::remove(tampered_path, ignored);
  std::filesystem::remove(AuthInfoScopeLifecycleRecordPath(
      scope, "pid", static_cast<uint32_t>(tampered_pid)), ignored);

  const uint64_t current_birth = AuthInfoScopeLifecycleCurrentBirth();
  const int observation_wrong_birth_pid = 31017;
  const auto observation_wrong_birth_fixture =
      MakeAuthInfoScopeLifecycleFixture(observation_wrong_birth_pid);
  const auto observation_wrong_birth = MakeAuthInfoScopeLifecycleObservation(
      observation_wrong_birth_fixture.identity, AuthInfo::kFilteredCapabilityMask,
      uint64_t{1} << 62);
  std::array<uint8_t, AuthInfo::kScopedObservationSize> observation_wrong_birth_sidecar {};
  Check(AuthInfo::EncodeScopedObservation(observation_wrong_birth,
        observation_wrong_birth_pid, GetCurrentProcessId(), current_birth,
        &observation_wrong_birth_sidecar),
        "encode wrong-birth scoped observation sidecar");
  const auto observation_wrong_birth_path =
      AuthInfoScopeLifecycleObservationSidecarPath(scope, observation_wrong_birth_pid);
  WriteAuthInfoScopeLifecycleFile(observation_wrong_birth_path,
      observation_wrong_birth_sidecar.data(), observation_wrong_birth_sidecar.size());
  {
    std::ofstream record(AuthInfoScopeLifecycleRecordPath(
        scope, "pid", static_cast<uint32_t>(observation_wrong_birth_pid)), std::ios::trunc);
    record << GetCurrentProcessId() << ' '
           << observation_wrong_birth_fixture.identity.authority_id
           << " birth=0000000000000001"
           << " self=" << AuthInfo::DigestHex(
                observation_wrong_birth_fixture.identity.self_sha256)
           << " elf=" << AuthInfo::DigestHex(
                observation_wrong_birth_fixture.identity.elf_sha256)
           << " authobs=" << AuthInfo::DigestHex(
                observation_wrong_birth.envelope_sha256) << '\n';
    record.close();
    Check(static_cast<bool>(record), "write wrong-birth scoped observation metadata");
  }
  Process::PeerProcess observation_wrong_birth_peer;
  Check(Process::FindPeerByPid(observation_wrong_birth_pid,
            &observation_wrong_birth_peer) &&
        !observation_wrong_birth_peer.has_auth_info &&
        !observation_wrong_birth_peer.has_filtered_auth_info,
        "mismatched host birth exposes no scoped observation");
  std::filesystem::remove(observation_wrong_birth_path, ignored);
  std::filesystem::remove(AuthInfoScopeLifecycleRecordPath(
      scope, "pid", static_cast<uint32_t>(observation_wrong_birth_pid)), ignored);

  const int observation_tampered_pid = 31018;
  const auto observation_tampered_fixture =
      MakeAuthInfoScopeLifecycleFixture(observation_tampered_pid);
  const auto observation_tampered = MakeAuthInfoScopeLifecycleObservation(
      observation_tampered_fixture.identity, AuthInfo::kFilteredCapabilityMask,
      uint64_t{1} << 62);
  std::array<uint8_t, AuthInfo::kScopedObservationSize> observation_tampered_sidecar {};
  Check(AuthInfo::EncodeScopedObservation(observation_tampered,
        observation_tampered_pid, GetCurrentProcessId(), current_birth,
        &observation_tampered_sidecar),
        "encode tampered scoped observation sidecar");
  observation_tampered_sidecar.back() ^= 0x80;
  const auto observation_tampered_path =
      AuthInfoScopeLifecycleObservationSidecarPath(scope, observation_tampered_pid);
  WriteAuthInfoScopeLifecycleFile(observation_tampered_path,
      observation_tampered_sidecar.data(), observation_tampered_sidecar.size());
  {
    std::ofstream record(AuthInfoScopeLifecycleRecordPath(
        scope, "pid", static_cast<uint32_t>(observation_tampered_pid)), std::ios::trunc);
    record << GetCurrentProcessId() << ' '
           << observation_tampered_fixture.identity.authority_id
           << " birth=" << std::hex << std::setw(16) << std::setfill('0') << current_birth
           << " self=" << AuthInfo::DigestHex(observation_tampered_fixture.identity.self_sha256)
           << " elf=" << AuthInfo::DigestHex(observation_tampered_fixture.identity.elf_sha256)
           << " authobs=" << AuthInfo::DigestHex(observation_tampered.envelope_sha256) << '\n';
    record.close();
    Check(static_cast<bool>(record), "write tampered scoped observation metadata");
  }
  Process::PeerProcess observation_tampered_peer;
  Check(Process::FindPeerByPid(observation_tampered_pid, &observation_tampered_peer) &&
        !observation_tampered_peer.has_auth_info &&
        !observation_tampered_peer.has_filtered_auth_info,
        "tampered scoped observation sidecar exposes no record");
  std::filesystem::remove(observation_tampered_path, ignored);
  std::filesystem::remove(AuthInfoScopeLifecycleRecordPath(
      scope, "pid", static_cast<uint32_t>(observation_tampered_pid)), ignored);

  const int conflicting_pid = 31019;
  const auto conflicting_fixture = MakeAuthInfoScopeLifecycleFixture(conflicting_pid);
  const auto conflicting_observation = MakeAuthInfoScopeLifecycleObservation(
      conflicting_fixture.identity, AuthInfo::kFilteredCapabilityMask, 0);
  std::array<uint8_t, AuthInfo::kScopedCaptureSize> conflicting_capture_sidecar {};
  std::array<uint8_t, AuthInfo::kScopedObservationSize> conflicting_observation_sidecar {};
  Check(AuthInfo::EncodeScopedCapture(conflicting_fixture.capture, conflicting_pid,
            GetCurrentProcessId(), &conflicting_capture_sidecar) &&
        AuthInfo::EncodeScopedObservation(conflicting_observation, conflicting_pid,
            GetCurrentProcessId(), current_birth, &conflicting_observation_sidecar),
        "encode contradictory scoped authorization evidence");
  const auto conflicting_capture_path =
      AuthInfoScopeLifecycleSidecarPath(scope, conflicting_pid);
  const auto conflicting_observation_path =
      AuthInfoScopeLifecycleObservationSidecarPath(scope, conflicting_pid);
  WriteAuthInfoScopeLifecycleFile(conflicting_capture_path,
      conflicting_capture_sidecar.data(), conflicting_capture_sidecar.size());
  WriteAuthInfoScopeLifecycleFile(conflicting_observation_path,
      conflicting_observation_sidecar.data(), conflicting_observation_sidecar.size());
  {
    std::ofstream record(AuthInfoScopeLifecycleRecordPath(
        scope, "pid", static_cast<uint32_t>(conflicting_pid)), std::ios::trunc);
    record << GetCurrentProcessId() << ' ' << conflicting_fixture.identity.authority_id
           << " birth=" << std::hex << std::setw(16) << std::setfill('0') << current_birth
           << " self=" << AuthInfo::DigestHex(conflicting_fixture.identity.self_sha256)
           << " elf=" << AuthInfo::DigestHex(conflicting_fixture.identity.elf_sha256)
           << " authinfo=" << AuthInfo::DigestHex(conflicting_fixture.capture.envelope_sha256)
           << " authobs=" << AuthInfo::DigestHex(conflicting_observation.envelope_sha256) << '\n';
    record.close();
    Check(static_cast<bool>(record), "write contradictory scoped authorization metadata");
  }
  Process::PeerProcess conflicting_peer;
  Check(Process::FindPeerByPid(conflicting_pid, &conflicting_peer) &&
        !conflicting_peer.has_auth_info && !conflicting_peer.has_filtered_auth_info,
        "contradictory full and observed evidence fails closed");
  std::filesystem::remove(conflicting_capture_path, ignored);
  std::filesystem::remove(conflicting_observation_path, ignored);
  std::filesystem::remove(AuthInfoScopeLifecycleRecordPath(
      scope, "pid", static_cast<uint32_t>(conflicting_pid)), ignored);

  const int duplicate_marker_pid = 31020;
  const auto duplicate_marker_fixture = MakeAuthInfoScopeLifecycleFixture(duplicate_marker_pid);
  const auto duplicate_marker_observation = MakeAuthInfoScopeLifecycleObservation(
      duplicate_marker_fixture.identity, AuthInfo::kFilteredCapabilityMask,
      uint64_t{1} << 62);
  std::array<uint8_t, AuthInfo::kScopedObservationSize> duplicate_marker_sidecar {};
  Check(AuthInfo::EncodeScopedObservation(duplicate_marker_observation,
        duplicate_marker_pid, GetCurrentProcessId(), current_birth,
        &duplicate_marker_sidecar),
        "encode duplicate-marker scoped observation sidecar");
  const auto duplicate_marker_path =
      AuthInfoScopeLifecycleObservationSidecarPath(scope, duplicate_marker_pid);
  WriteAuthInfoScopeLifecycleFile(duplicate_marker_path,
      duplicate_marker_sidecar.data(), duplicate_marker_sidecar.size());
  {
    const auto marker = AuthInfo::DigestHex(duplicate_marker_observation.envelope_sha256);
    std::ofstream record(AuthInfoScopeLifecycleRecordPath(
        scope, "pid", static_cast<uint32_t>(duplicate_marker_pid)), std::ios::trunc);
    record << GetCurrentProcessId() << ' ' << duplicate_marker_fixture.identity.authority_id
           << " birth=" << std::hex << std::setw(16) << std::setfill('0') << current_birth
           << " self=" << AuthInfo::DigestHex(duplicate_marker_fixture.identity.self_sha256)
           << " elf=" << AuthInfo::DigestHex(duplicate_marker_fixture.identity.elf_sha256)
           << " authobs=" << marker << " authobs=" << marker << '\n';
    record.close();
    Check(static_cast<bool>(record), "write duplicate scoped observation marker metadata");
  }
  Process::PeerProcess duplicate_marker_peer;
  Check(Process::FindPeerByPid(duplicate_marker_pid, &duplicate_marker_peer) &&
        !duplicate_marker_peer.has_auth_info &&
        !duplicate_marker_peer.has_filtered_auth_info,
        "duplicate observation markers fail closed");
  std::filesystem::remove(duplicate_marker_path, ignored);
  std::filesystem::remove(AuthInfoScopeLifecycleRecordPath(
      scope, "pid", static_cast<uint32_t>(duplicate_marker_pid)), ignored);

  std::filesystem::remove(AuthInfoScopeLifecycleAllocatorPath(scope), ignored);
  Process::ClearVerifiedOriginalSelf();
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(output_memory), 0x4000) == OK,
        "release scoped AuthInfo guest output");
  Check(CloseHandle(job), "release scoped AuthInfo lifecycle containment");
  std::printf("AuthInfoScopeLifecycleTests: live=pass return=pass quick_exit=pass terminate=pass clear_auth=pass clear_self=pass replace_auth=pass replace_self=pass observation=pass observation_revoke=pass collision=pass no_capture=pass legacy=pass wrong_birth=pass tamper=pass conflict=pass duplicate_marker=pass\n");
#endif
}
