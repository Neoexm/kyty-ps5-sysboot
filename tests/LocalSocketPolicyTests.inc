#if defined(_WIN32)
struct LocalSocketPolicySavedIdentity {
  Libs::LibKernel::AuthInfo::ImageIdentity identity {};
  Libs::LibKernel::AuthInfo::Capture capture {};
  bool has_identity = false, has_capture = false;

  LocalSocketPolicySavedIdentity() {
    namespace Process = Libs::LibKernel::Process;
    has_identity = Process::GetVerifiedOriginalSelfIdentity(&identity);
    has_capture = has_identity && Process::GetVerifiedAuthInfoForImage(identity, &capture);
  }

  ~LocalSocketPolicySavedIdentity() {
    namespace Process = Libs::LibKernel::Process;
    Process::ClearVerifiedOriginalSelf();
    if (has_identity) Process::InstallVerifiedOriginalSelf(identity);
    if (has_capture) Check(Process::InstallVerifiedAuthInfo(capture), "restore prior socket fixture authorization");
  }
};

Libs::LibKernel::AuthInfo::ImageIdentity LocalSocketPolicyIdentity() {
  using namespace Libs::LibKernel;
  AuthInfo::ImageIdentity identity {};
  identity.authority_id = 0x3800000000000011ull;
  constexpr char self[] = "socket-policy-fixture-self";
  constexpr char elf[] = "socket-policy-fixture-elf";
  identity.self_size = sizeof(self);
  identity.elf_size = sizeof(elf);
  identity.self_sha256 = AuthInfo::Sha256(self, sizeof(self));
  identity.elf_sha256 = AuthInfo::Sha256(elf, sizeof(elf));
  return identity;
}

void LocalSocketPolicyCredential(int state) {
  using namespace Libs::LibKernel;
  Process::ClearVerifiedOriginalSelf();
  if (state < 0) return;
  const auto identity = LocalSocketPolicyIdentity();
  AuthInfo::Record record {};
  std::memcpy(record.data(), &identity.authority_id, sizeof(identity.authority_id));
  const uint64_t capabilities = state == 0 ? 0 : uint64_t {1} << 62;
  std::memcpy(record.data() + 8, &capabilities, sizeof(capabilities));
  AuthInfo::Capture capture {};
  Check(AuthInfo::BuildCaptureEnvelope(record, identity, &capture, nullptr),
        "build explicit synthetic socket authorization fixture without production capture input");
  Process::InstallVerifiedOriginalSelf(identity);
  Check(Process::InstallVerifiedAuthInfo(capture), "install only test-created socket authorization facts");
}

void LocalSocketPolicyObservationCredential(int state, uint64_t known) {
  using namespace Libs::LibKernel;
  Process::ClearVerifiedOriginalSelf();
  if (state < 0) return;
  const auto identity = LocalSocketPolicyIdentity();
  Process::InstallVerifiedOriginalSelf(identity);
  std::array<uint8_t, AuthInfo::kObservationSize> encoded {};
  const auto store32 = [](uint8_t* out, uint32_t value) {
    for (unsigned i = 0; i != 4; ++i) out[i] = static_cast<uint8_t>(value >> (i * 8));
  };
  const auto store64 = [](uint8_t* out, uint64_t value) {
    for (unsigned i = 0; i != 8; ++i) out[i] = static_cast<uint8_t>(value >> (i * 8));
  };
  std::memcpy(encoded.data(), "KytyAO01", 8);
  store32(encoded.data() + 8, 1);
  store32(encoded.data() + 12, encoded.size());
  store64(encoded.data() + 16, identity.authority_id);
  store64(encoded.data() + 24, state == 0 ? 0 : uint64_t {1} << 62);
  store64(encoded.data() + 32, known);
  std::copy(identity.self_sha256.begin(), identity.self_sha256.end(), encoded.begin() + 40);
  std::copy(identity.elf_sha256.begin(), identity.elf_sha256.end(), encoded.begin() + 72);
  encoded[104] = encoded[168] = 1;
  store32(encoded.data() + 136, 0x13600007);
  store32(encoded.data() + 140, 52);
  store64(encoded.data() + 144, 100);
  store64(encoded.data() + 160, 200);
  AuthInfo::Observation observation;
  Check(AuthInfo::ParseObservation(encoded.data(), encoded.size(),
            AuthInfo::Sha256(encoded.data(), encoded.size()), identity, &observation, nullptr) &&
            Process::InstallVerifiedAuthorizationObservation(observation),
        "install image-bound filtered socket authorization observation");
  AuthInfo::Capture capture;
  Check(!Process::GetVerifiedAuthInfoForImage(identity, &capture),
        "filtered socket authorization observation does not manufacture full AuthInfo");
}

std::array<uint8_t, 106> LocalSocketPolicyAddress(int endpoint) {
  std::array<uint8_t, 106> address {};
  address[1] = 1;
  const auto* path = endpoint == 0 ? "/system_tmp/GnmCompositor" : "/system_tmp/AgcCompositorSppSocket";
  std::memcpy(address.data() + 2, path, std::strlen(path) + 1);
  return address;
}

int LocalSocketPolicyReady(int descriptor, int64_t microseconds) {
  std::array<uint64_t, 1024> readable {};
  readable[descriptor / 64] = uint64_t {1} << (descriptor % 64);
  const std::array<int64_t, 2> timeout {microseconds / 1000000, microseconds % 1000000};
  return Libs::Network::Net::Select(descriptor + 1, readable.data(), nullptr, nullptr, timeout.data());
}

struct LocalSocketPolicyChild {
  HANDLE job = nullptr;
  PROCESS_INFORMATION process {};

  explicit LocalSocketPolicyChild(const std::wstring& arguments) {
    std::array<wchar_t, 32768> executable {};
    const DWORD length = GetModuleFileNameW(nullptr, executable.data(), executable.size());
    Check(length != 0 && length < executable.size(), "locate socket policy child test executable");
    std::wstring command = L"\"" + std::wstring(executable.data(), length) + L"\" --local-socket-policy-child " + arguments;
    job = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    Check(job != nullptr && SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
          "contain socket policy child in its own kill-on-close job");
    STARTUPINFOW startup {};
    startup.cb = sizeof(startup);
    Check(CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED,
                         nullptr, nullptr, &startup, &process), "create bounded socket policy child");
    if (!AssignProcessToJobObject(job, process.hProcess)) {
      TerminateProcess(process.hProcess, 90);
      WaitForSingleObject(process.hProcess, 1000);
      Check(false, "assign socket policy child before execution");
    }
    Check(ResumeThread(process.hThread) != DWORD(-1), "start the contained socket policy child");
  }

  bool Wait() {
    const DWORD result = WaitForSingleObject(process.hProcess, 3000);
    if (result != WAIT_OBJECT_0) {
      TerminateJobObject(job, 91);
      WaitForSingleObject(process.hProcess, 1000);
    }
    DWORD code = 1;
    return result == WAIT_OBJECT_0 && GetExitCodeProcess(process.hProcess, &code) && code == 0;
  }

  void Crash() {
    Check(TerminateJobObject(job, 92) && WaitForSingleObject(process.hProcess, 1000) == WAIT_OBJECT_0,
          "terminate only the contained endpoint owner before stale-generation recovery");
  }

  ~LocalSocketPolicyChild() {
    if (process.hProcess != nullptr && WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT) {
      TerminateJobObject(job, 93);
      WaitForSingleObject(process.hProcess, 1000);
    }
    if (process.hThread != nullptr) CloseHandle(process.hThread);
    if (process.hProcess != nullptr) CloseHandle(process.hProcess);
    if (job != nullptr) CloseHandle(job);
  }
};
#endif

int RunLocalSocketPolicyChild(int argc, char** argv) {
  if (argc < 2 || std::strcmp(argv[1], "--local-socket-policy-child") != 0) return -1;
#if defined(_WIN32)
  if (argc != 6) return 2;
  namespace Net = Libs::Network::Net;
  using namespace Libs::LibKernel;
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET", "1") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", argv[2]) == 0,
        "select child socket policy scope");
  Common::InitializeThreads();
  Common::Subsystems subsystems;
  subsystems.Initialize<Config::Lifecycle>();
  Config::ConfigOptions options;
  options.printf_direction = Config::LogDirection::Silent;
  Config::Load(options);
  subsystems.Initialize<Log::Lifecycle>();
  subsystems.Initialize<Memory::Lifecycle>();
  LocalSocketPolicyCredential(-1);
  const int descriptor = Net::Socket(1, 1, 0);
  const int endpoint = std::strcmp(argv[4], "1") == 0 ? 1 : 0;
  const auto address = LocalSocketPolicyAddress(endpoint);
  Check(descriptor >= 0, "create independent host-process guest socket");
  if (std::strcmp(argv[3], "client") == 0) {
    char* end = nullptr;
    const long expected = std::strtol(argv[5], &end, 10);
    Check(end != argv[5] && *end == '\0' && expected >= 0 && expected <= 101,
          "parse bounded child expected socket error");
    const int result = Net::Connect(descriptor, address.data(), address.size());
    Check(expected == 0 ? result == 0 : result == -1 && *Libs::Posix::GetErrorAddr() == expected,
          "independent child obeys the parent's current guest socket policy");
    constexpr char payload[] = "cross-process-policy-bytes";
    if (expected == 0) Check(Net::Send(descriptor, payload, sizeof(payload), 0) == sizeof(payload),
                             "independent child sends bytes through the admitted connection");
    Check(Net::SocketClose(descriptor) == 0, "close the independent child socket");
    subsystems.Destroy();
    return 0;
  }
  Check(std::strcmp(argv[3], "serve") == 0, "select bounded crash-owner child mode");
  void* memory = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&memory, 0x4000, 3, 0, "socket-policy-child") == OK,
        "map the child ioctl payload as guest memory");
  *static_cast<int32_t*>(memory) = 1;
  Check(Net::Ioctl(descriptor, 0x80049301, memory) == 0 &&
            Net::Bind(descriptor, address.data(), address.size()) == 0 && Net::Listen(descriptor, 4) == 0,
        "child owns an enabled listener before deliberate owner termination");
  HANDLE ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, argv[5]);
  Check(ready != nullptr && SetEvent(ready), "publish child listener readiness to the fixture");
  CloseHandle(ready);
  Sleep(3000);
  Net::SocketClose(descriptor);
  Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), 0x4000);
  subsystems.Destroy();
  return 3;
#else
  return 2;
#endif
}

void CheckLocalSocketPolicy() {
#if defined(_WIN32)
  namespace Net = Libs::Network::Net;
  using namespace Libs::LibKernel;
  LocalSocketPolicySavedIdentity saved_identity;
  const std::array<const char*, 2> names {"KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET", "KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE"};
  std::array<std::string, 2> saved;
  for (size_t n = 0; n < names.size(); ++n) {
    const char* value = std::getenv(names[n]);
    saved[n] = value == nullptr ? "" : value;
  }
  const auto scope = "sp" + std::to_string(GetCurrentProcessId()) + "_" + std::to_string(GetTickCount64() % 1000000);
  Check(scope.size() < 20 && _putenv_s(names[0], "1") == 0 && _putenv_s(names[1], scope.c_str()) == 0,
        "select unique socket policy fixture scope");
  std::array<char, MAX_PATH + 1> temp {};
  const DWORD temp_length = GetTempPathA(MAX_PATH, temp.data());
  Check(temp_length != 0 && temp_length < MAX_PATH, "locate the backend's scoped socket directory");
  std::array<std::filesystem::path, 2> policy_paths;
  for (size_t n = 0; n < policy_paths.size(); ++n) {
    policy_paths[n] = std::filesystem::path(temp.data()) /
        ("kyty_ps5_" + scope + (n == 0 ? "_gnm.sock.policy" : "_spp.sock.policy"));
    Check(!std::filesystem::exists(policy_paths[n]), "own a fresh exact policy sidecar path before testing");
  }
  void* memory = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&memory, 0x8000, 3, 0, "socket-policy-test") == OK,
        "map ioctl input in guest memory");
  auto* payload = static_cast<int32_t*>(memory);
  const auto set = [&](int descriptor, int32_t value) {
    *payload = value;
    Check(Net::Ioctl(descriptor, 0x80049301, payload) == 0 && *payload == value,
          "socket policy setter reads exact int32 input without mutating guest memory");
  };
  LocalSocketPolicyCredential(-1);
  const auto first = LocalSocketPolicyAddress(0);
  const auto second = LocalSocketPolicyAddress(1);
  int listener = Net::Socket(1, 1, 0);
  Check(listener >= 0, "create policy fixture listener");
  set(listener, -7);
  Check(Net::Listen(listener, 4) == -1 && *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EDESTADDRREQ,
        "an unbound local listener reports EDESTADDRREQ");
  Check(FileSystem::KernelIoctl(-1, 0x80049301, nullptr) == KERNEL_ERROR_EFAULT &&
            FileSystem::KernelIoctl(-1, 0x80049301, payload) == KERNEL_ERROR_EBADF &&
            FileSystem::KernelIoctl(listener, 0x80049301, payload) == OK,
        "native ioctl dispatch copies input before descriptor lookup and applies the same policy state");
  Check(Net::Ioctl(listener, 0x80049301, nullptr) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT &&
            Net::Ioctl(-1, 0x80049301, nullptr) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT &&
            Net::Ioctl(-1, 0x80049301, payload) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EBADF,
        "payload fault precedes descriptor lookup while valid input preserves EBADF");
  Check(Net::Connect(-1, nullptr, 1) == -1 && *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL &&
            Net::Connect(-1, nullptr, 256) == -1 && *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENAMETOOLONG &&
            Net::Connect(-1, nullptr, 106) == -1 && *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT &&
            Net::Connect(-1, first.data(), first.size()) == -1 && *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EBADF,
        "connect length and input copy errors precede descriptor lookup");
  const auto invalid_pointer = reinterpret_cast<void*>(UINTPTR_MAX - 1);
  Check(Net::Ioctl(listener, 0x80049301, invalid_pointer) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT &&
            Net::Ioctl(listener, 0x8004937f, payload) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EOPNOTSUPP,
        "wrapping guest input and unknown local protocol controls fail without changing policy");
  Check(Memory::KernelMprotect(static_cast<uint8_t*>(memory) + 0x4000, 0x4000, 0) == OK &&
            Net::Ioctl(listener, 0x80049301, static_cast<uint8_t*>(memory) + 0x3ffe) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT &&
            Memory::KernelMprotect(static_cast<uint8_t*>(memory) + 0x4000, 0x4000, 3) == OK &&
            Memory::KernelMprotect(memory, 0x4000, 1) == OK &&
            Net::Ioctl(listener, 0x80049301, memory) == 0 &&
            Memory::KernelMprotect(memory, 0x4000, 3) == OK,
        "copyin rejects a four-byte boundary fault and accepts a read-only guest input page");
  for (int type: {1, 2}) {
    const int wrong = Net::Socket(2, type, 0);
    Check(wrong >= 0 && Net::Ioctl(wrong, 0x80049301, payload) == -1 &&
              *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EOPNOTSUPP && Net::SocketClose(wrong) == 0,
          "non-local stream and datagram sockets reject the local policy selector");
  }
  Check(Net::Bind(listener, first.data(), first.size()) == 0 && Net::Listen(listener, 4) == 0,
        "policy enabled before bind survives bind and listen");
  Check(Net::Connect(listener, first.data(), first.size()) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EOPNOTSUPP,
        "a listener cannot connect and reports EOPNOTSUPP before its own policy bit");
  const int already = Net::Socket(1, 1, 0);
  Check(already >= 0, "create source socket for its separate own-bit state check");
  set(already, 1);
  Check(Net::Connect(already, first.data(), first.size()) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EALREADY &&
            LocalSocketPolicyReady(listener, 0) == 0 && Net::SocketClose(already) == 0,
        "preexisting source bit0x10 reports EALREADY without connecting");
  const auto receive_child = [&](int server) {
    Check(LocalSocketPolicyReady(server, 2000000) == 1, "child made a host connection");
    const int accepted = Net::Accept(server, nullptr, nullptr);
    constexpr char expected[] = "cross-process-policy-bytes";
    std::array<char, sizeof(expected)> bytes {};
    Check(accepted >= 0 && LocalSocketPolicyReady(accepted, 2000000) == 1 &&
              Net::Recv(accepted, bytes.data(), bytes.size(), 0) == bytes.size() &&
              std::memcmp(bytes.data(), expected, bytes.size()) == 0 && Net::SocketClose(accepted) == 0,
          "accepted connection carries the child bytes with no other responder");
  };
  const auto child = [&](int endpoint, int error) {
    LocalSocketPolicyChild process(std::wstring(scope.begin(), scope.end()) + L" client " +
        std::to_wstring(endpoint) + L" " + std::to_wstring(error));
    Check(process.Wait(), "bounded child observed current cross-process policy state");
  };
  child(0, 0);
  receive_child(listener);
  set(listener, 0);
  child(0, Libs::Posix::POSIX_ENOSYS);
  Check(LocalSocketPolicyReady(listener, 0) == 0, "unknown authorization did not reach host accept queue");
  set(listener, INT32_MIN);
  child(0, 0);
  receive_child(listener);
  int other = Net::Socket(1, 1, 0);
  Check(other >= 0 && Net::Bind(other, second.data(), second.size()) == 0,
        "bind a separate default-policy endpoint before it listens");
  child(1, Libs::Posix::POSIX_ENOSYS);
  set(other, 1);
  child(1, Libs::Posix::POSIX_ECONNREFUSED);
  set(other, 0);
  Check(Net::Listen(other, 4) == 0, "publish listening state only after successful host listen");
  child(1, Libs::Posix::POSIX_ENOSYS);
  Check(LocalSocketPolicyReady(other, 0) == 0 && Net::SocketClose(other) == 0,
        "listener policy does not leak to a different scoped endpoint");
  const auto connect = [&](int server, const auto& address, int error) {
    const int client = Net::Socket(1, 1, 0);
    Check(client >= 0, "create caller socket with the fixture's current credentials");
    const int result = Net::Connect(client, address.data(), address.size());
    if (error != 0) {
      Check(result == -1 && *Libs::Posix::GetErrorAddr() == error && LocalSocketPolicyReady(server, 0) == 0,
            "credential denial or unknown facts prevent host connection");
    } else {
      Check(result == 0 && LocalSocketPolicyReady(server, 2000000) == 1,
            "known authorization permits a connection");
      const int accepted = Net::Accept(server, nullptr, nullptr);
      Check(accepted >= 0, "accept admitted fixture connection");
      set(accepted, 1);
      auto unsupported_name = address;
      unsupported_name[2] = 'x';
      Check(Net::Connect(accepted, address.data(), address.size()) == -1 &&
                *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EISCONN &&
                Net::Connect(client, unsupported_name.data(), unsupported_name.size()) == -1 &&
                *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EISCONN,
            "connected streams report EISCONN before source policy or target admission");
      set(accepted, 0);
      Check(Net::SocketClose(accepted) == 0, "accepted socket owns independently mutable policy state");
    }
    Check(Net::SocketClose(client) == 0, "close credential fixture caller socket");
  };
  connect(listener, first, 0);
  child(0, 0);
  receive_child(listener);
  Check(Net::SocketClose(listener) == 0, "close unknown-credential endpoint before a new creation generation");
  LocalSocketPolicyCredential(1);
  listener = Net::Socket(1, 1, 0);
  LocalSocketPolicyCredential(0);
  Check(listener >= 0 && Net::Bind(listener, first.data(), first.size()) == 0 && Net::Listen(listener, 4) == 0,
        "create a privileged-target fixture listener with captured creation credentials");
  LocalSocketPolicyCredential(0);
  connect(listener, first, Libs::Posix::POSIX_EPERM);
  LocalSocketPolicyCredential(-1);
  connect(listener, first, Libs::Posix::POSIX_ENOSYS);
  LocalSocketPolicyCredential(1);
  connect(listener, first, 0);
  LocalSocketPolicyObservationCredential(0, AuthInfo::kFilteredCapabilityMask);
  connect(listener, first, Libs::Posix::POSIX_EPERM);
  LocalSocketPolicyObservationCredential(0, uint64_t {1} << 61);
  connect(listener, first, Libs::Posix::POSIX_ENOSYS);
  LocalSocketPolicyObservationCredential(1, AuthInfo::kFilteredCapabilityMask);
  connect(listener, first, 0);
  Check(Net::SocketClose(listener) == 0, "release privileged creation credential endpoint");
  LocalSocketPolicyCredential(0);
  listener = Net::Socket(1, 1, 0);
  LocalSocketPolicyCredential(-1);
  Check(listener >= 0 && Net::Bind(listener, first.data(), first.size()) == 0 && Net::Listen(listener, 4) == 0,
        "create a known ordinary-target listener");
  LocalSocketPolicyCredential(-1);
  connect(listener, first, 0);
  Check(Net::SocketClose(listener) == 0, "creation credential remains effective after current identity is cleared");
  const auto ready_name = "Local\\kyty_socket_policy_ready_" + scope;
  HANDLE ready = CreateEventA(nullptr, TRUE, FALSE, ready_name.c_str());
  Check(ready != nullptr && GetLastError() != ERROR_ALREADY_EXISTS, "create unique child-owner readiness event");
  {
    LocalSocketPolicyChild owner(std::wstring(scope.begin(), scope.end()) + L" serve 1 " +
        std::wstring(ready_name.begin(), ready_name.end()));
    const DWORD result = WaitForSingleObject(ready, 3000);
    if (result == WAIT_OBJECT_0) owner.Crash();
    Check(result == WAIT_OBJECT_0, "independent child really bound and listened before termination");
  }
  CloseHandle(ready);
  other = Net::Socket(1, 1, 0);
  Check(other >= 0 && Net::Bind(other, second.data(), second.size()) == 0 && Net::Listen(other, 4) == 0,
        "new owner rebinds the endpoint after dead-owner cleanup");
  child(1, Libs::Posix::POSIX_ENOSYS);
  set(other, 1);
  child(1, 0);
  receive_child(other);
  Check(Net::SocketClose(other) == 0 && Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), 0x8000) == OK,
        "release all policy fixture endpoints and guest buffers");
  for (const auto& path: policy_paths) {
    std::error_code error;
    Check(std::filesystem::remove(path, error) && !error,
          "remove only the exact disposable policy sidecar after every endpoint handle is released");
  }
  for (size_t n = 0; n < names.size(); ++n) Check(_putenv_s(names[n], saved[n].c_str()) == 0,
                                                "restore socket policy environment");
  std::printf("LocalSocketPolicyTests: mapped_payload=pass original_errno=pass set_clear=pass cross_process=pass creation_credentials=pass observed_credentials=pass accepted_isolation=pass owner_crash_rebind=pass fixture_only=1\n");
#endif
}
