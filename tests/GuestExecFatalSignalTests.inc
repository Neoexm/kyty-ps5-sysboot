#if defined(_WIN32)
struct GuestExecFatalSignalHandoff {
  uint32_t magic;
  uint32_t version;
  uint32_t request_bytes;
  int32_t error;
  uint32_t guest_pid;
  uint32_t parent_host_pid;
  uint32_t child_host_pid;
  volatile LONG state;
  uint64_t entry;
  uint64_t stack;
  uint64_t params;
  volatile LONG guest_exit_known;
  uint32_t guest_wait_status;
  uint64_t reboot_options;
  uint32_t reboot_kind;
  uint32_t reboot_exit_code;
  uint32_t auth_info_present;
  uint32_t auth_info_bytes;
  uint8_t auth_info_sha256[32];
  uint8_t auth_info_capture[0x108];
  char request[1024 * 1024];
  volatile LONG startup_stage;
};

static_assert(offsetof(GuestExecFatalSignalHandoff, auth_info_present) == 80);
static_assert(offsetof(GuestExecFatalSignalHandoff, request) == 384);
static_assert(Libs::LibKernel::Process::kGuestSigillCoreWaitStatus == (4u | 0x80u));

struct GuestExecFatalSignalFixture {
  HANDLE mapping = nullptr;
  HANDLE prepared = nullptr;
  HANDLE release = nullptr;
  HANDLE job = nullptr;
  GuestExecFatalSignalHandoff* shared = nullptr;
  PROCESS_INFORMATION process {};

  ~GuestExecFatalSignalFixture() {
    if (process.hProcess != nullptr &&
        WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT) {
      TerminateProcess(process.hProcess, 0xe1195001u);
      WaitForSingleObject(process.hProcess, 1000);
    }
    if (shared != nullptr) UnmapViewOfFile(shared);
    for (HANDLE handle: {process.hThread, process.hProcess, prepared, release, mapping, job}) {
      if (handle != nullptr) CloseHandle(handle);
    }
  }
};

struct GuestExecAuthInfoFixture {
  std::vector<uint8_t> self;
  std::vector<uint8_t> elf;
  Libs::LibKernel::AuthInfo::ImageIdentity identity {};
  Libs::LibKernel::AuthInfo::Record record {};
  Libs::LibKernel::AuthInfo::Capture capture {};
};

GuestExecAuthInfoFixture MakeGuestExecAuthInfoFixture() {
  using namespace Libs::LibKernel::AuthInfo;
  GuestExecAuthInfoFixture fixture;
  constexpr uint64_t authority_id = 0x4800000010000011ull;
  Loader::Elf64_Ehdr elf_header {};
  std::memcpy(elf_header.e_ident, "\177ELF", 4);
  elf_header.e_ident[Loader::EI_CLASS] = Loader::ELFCLASS64;
  elf_header.e_ident[Loader::EI_DATA] = Loader::ELFDATA2LSB;
  elf_header.e_ehsize = sizeof(elf_header);
  elf_header.e_phoff = sizeof(elf_header);
  elf_header.e_phentsize = sizeof(Loader::Elf64_Phdr);
  elf_header.e_phnum = 1;
  Loader::Elf64_Phdr program_header {};
  program_header.p_type = Loader::PT_LOAD;
  program_header.p_flags = Loader::PF_R | Loader::PF_X;
  program_header.p_filesz = sizeof(elf_header) + sizeof(program_header);
  program_header.p_memsz = program_header.p_filesz;
  program_header.p_align = 0x10;
  fixture.elf.resize(sizeof(elf_header) + sizeof(program_header) + 19);
  std::memcpy(fixture.elf.data(), &elf_header, sizeof(elf_header));
  std::memcpy(fixture.elf.data() + elf_header.e_phoff, &program_header,
              sizeof(program_header));
  for (size_t i = sizeof(elf_header) + sizeof(program_header);
       i != fixture.elf.size(); ++i) {
    fixture.elf[i] = static_cast<uint8_t>(i * 11 + 9);
  }
  const uint64_t elf_offset = sizeof(Loader::SelfHeader);
  const uint64_t authority_offset =
      (elf_offset + elf_header.e_phoff + sizeof(program_header) + 15) & ~uint64_t {15};
  const size_t authenticated_size = authority_offset + sizeof(authority_id);
  fixture.self.resize(authenticated_size + 13);
  Loader::SelfHeader self_header {};
  std::memcpy(self_header.ident, "\x54\x14\xf5\xee", 4);
  self_header.size1 = static_cast<uint16_t>(authenticated_size);
  self_header.size2 = static_cast<uint16_t>(fixture.self.size() - authenticated_size);
  self_header.file_size = fixture.self.size();
  std::memcpy(fixture.self.data(), &self_header, sizeof(self_header));
  std::memcpy(fixture.self.data() + elf_offset, &elf_header, sizeof(elf_header));
  std::memcpy(fixture.self.data() + elf_offset + elf_header.e_phoff,
              &program_header, sizeof(program_header));
  std::memcpy(fixture.self.data() + authority_offset, &authority_id, sizeof(authority_id));
  for (size_t i = authenticated_size; i != fixture.self.size(); ++i) {
    fixture.self[i] = static_cast<uint8_t>(i * 7 + 5);
  }
  std::string reason;
  Check(ValidateImageIdentity(fixture.self.data(), fixture.self.size(),
          fixture.elf.data(), fixture.elf.size(), &fixture.identity, &reason),
        "construct the exec auth-info SELF and ELF identity");
  for (size_t i = 0; i != fixture.record.size(); ++i) {
    fixture.record[i] = static_cast<uint8_t>(i * 13 + 17);
  }
  std::memcpy(fixture.record.data(), &authority_id, sizeof(authority_id));
  const uint64_t capability = 1ull << 62;
  std::memcpy(fixture.record.data() + 8, &capability, sizeof(capability));
  Check(BuildCaptureEnvelope(fixture.record, fixture.identity, &fixture.capture, &reason),
        "build the exec auth-info v2 envelope");
  return fixture;
}

std::array<std::wstring, 4> GuestExecAuthInfoEnvironmentNames(
    const Libs::LibKernel::AuthInfo::ImageIdentity& identity) {
  const auto digest = Libs::LibKernel::AuthInfo::DigestHex(identity.self_sha256);
  const std::wstring suffix(digest.begin(), digest.end());
  return {
      L"kYtY_pS5_CaPtUrEd_AuThInFo",
      L"KyTy_Ps5_CaPtUrEd_AuThInFo_ShA256",
      L"kYtY_Ps5_cApTuReD_aUtHiNfO_" + suffix,
      L"KyTy_pS5_CaPtUrEd_AuThInFo_sHa256_" + suffix,
  };
}

bool GuestExecAuthInfoEnvironmentEntryPresent(const std::wstring& name) {
  wchar_t* value = nullptr;
  size_t size = 0;
  const bool present = _wdupenv_s(&value, &size, name.c_str()) == 0 && value != nullptr;
  std::free(value);
  return present;
}

bool GuestExecAuthInfoEnvironmentPresent(const std::array<std::wstring, 4>& names) {
  return std::all_of(names.begin(), names.end(), GuestExecAuthInfoEnvironmentEntryPresent);
}

std::string GuestExecJsonString(const std::string& value) {
  std::string encoded = "\"";
  for (const unsigned char character: value) {
    if (character == '\\' || character == '"') encoded += '\\';
    encoded += static_cast<char>(character);
  }
  encoded += '"';
  return encoded;
}

void WriteGuestExecAuthInfoFile(const std::filesystem::path& path,
                                const std::vector<uint8_t>& bytes) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  output.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  output.close();
  Check(static_cast<bool>(output), "write the exec auth-info image fixture");
}
#endif

int RunGuestExecFatalSignalChild(int argc, char** argv) {
  if (argc != 3) return -1;
#if defined(_WIN32)
  if (std::strcmp(argv[1], "--guest-exec-auth-handoff-accept-child") == 0) {
    const auto fixture = MakeGuestExecAuthInfoFixture();
    const auto names = GuestExecAuthInfoEnvironmentNames(fixture.identity);
    if (!GuestExecAuthInfoEnvironmentPresent(names)) return 4;
    if (!Libs::LibKernel::Process::InitializeExecChild(argv[2])) return 5;
    if (std::any_of(names.begin(), names.end(), GuestExecAuthInfoEnvironmentEntryPresent)) return 6;
    Libs::LibKernel::AuthInfo::Capture installed {};
    const bool exact = Libs::LibKernel::Process::GetVerifiedAuthInfoForImage(
        fixture.identity, &installed) && installed.record == fixture.record &&
        installed.envelope == fixture.capture.envelope &&
        installed.envelope_sha256 == fixture.capture.envelope_sha256;
    SecureZeroMemory(&installed, sizeof(installed));
    Libs::LibKernel::Process::ClearVerifiedOriginalSelf();
    return exact ? 0 : 7;
  }
  if (std::strcmp(argv[1], "--guest-exec-auth-handoff-reject-child") == 0) {
    return Libs::LibKernel::Process::InitializeExecChild(argv[2]) ? 3 : 0;
  }
  if (std::strcmp(argv[1], "--guest-exec-auth-json-value-child") == 0) {
    return Libs::LibKernel::Process::InitializeExecChild(argv[2]) ? 0 : 8;
  }
  // fixture pair for tests/emulator_root_self_launch.cmake
  if (std::strcmp(argv[1], "--write-root-self-fixture") == 0) {
    const auto image = MakeGuestExecAuthInfoFixture();
    const auto dir = Common::PathFromUtf8(argv[2]);
    WriteGuestExecAuthInfoFile(dir / "root.self", image.self);
    WriteGuestExecAuthInfoFile(dir / "root.elf", image.elf);
    // same ELF header with the first p_vaddr bumped, so it doesn't match the SELF
    auto other = image.elf;
    uint64_t phoff = 0;
    std::memcpy(&phoff, other.data() + 0x20, sizeof(phoff));
    other[phoff + 0x10] ^= 0x10;
    WriteGuestExecAuthInfoFile(dir / "other.elf", other);
    return 0;
  }
  if (std::strcmp(argv[1], "--guest-exec-fatal-signal-child") != 0) return -1;
  Check(Libs::LibKernel::Process::InitializeExecChild(argv[2]),
        "initialize an exec-child handoff mapping");
  Libs::LibKernel::Process::RecordExecChildExitStatus(
      Libs::LibKernel::Process::kGuestSigillCoreWaitStatus);
  return 0;
#else
  return 2;
#endif
}

void CheckGuestExecAuthInfoSlotAcceptance() {
#if defined(_WIN32)
  GuestExecFatalSignalFixture handoff;
  TempDirectory temporary;
  const auto auth_info = MakeGuestExecAuthInfoFixture();
  const auto self_path = temporary.Path() / "exec_auth_info.self";
  const auto elf_path = temporary.Path() / "exec_auth_info.elf";
  WriteGuestExecAuthInfoFile(self_path, auth_info.self);
  WriteGuestExecAuthInfoFile(elf_path, auth_info.elf);
  LARGE_INTEGER counter {};
  Check(QueryPerformanceCounter(&counter) != FALSE,
        "read a unique accepted auth-info handoff counter");
  std::array<char, 33> token {};
  const int token_size = std::snprintf(token.data(), token.size(), "%08lx%08lx%016llx",
      GetCurrentProcessId(), GetTickCount(),
      static_cast<unsigned long long>(counter.QuadPart));
  Check(token_size == 32, "format an accepted auth-info handoff endpoint token");
  const std::wstring endpoint(token.begin(), token.end() - 1);
  const std::wstring prefix = L"Local\\KytyExec_" + endpoint;
  handoff.mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
      static_cast<DWORD>(sizeof(GuestExecFatalSignalHandoff)), (prefix + L"_map").c_str());
  const bool mapping_created = handoff.mapping != nullptr && GetLastError() != ERROR_ALREADY_EXISTS;
  handoff.prepared = CreateEventW(nullptr, TRUE, FALSE, (prefix + L"_prepared").c_str());
  handoff.release = CreateEventW(nullptr, TRUE, FALSE, (prefix + L"_release").c_str());
  handoff.job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  Check(mapping_created && handoff.prepared != nullptr && handoff.release != nullptr &&
        handoff.job != nullptr && SetInformationJobObject(handoff.job,
            JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != FALSE,
        "create isolated accepted auth-info handoff objects");
  handoff.shared = static_cast<GuestExecFatalSignalHandoff*>(MapViewOfFile(
      handoff.mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(GuestExecFatalSignalHandoff)));
  Check(handoff.shared != nullptr, "map the accepted auth-info handoff fixture");
  std::memset(handoff.shared, 0, sizeof(*handoff.shared));
  constexpr uint32_t guest_pid = 6193;
  const std::string request =
      "{\"argv\":[],\"envp\":[],\"guest_pid\":" + std::to_string(guest_pid) +
      ",\"original_self\":" + GuestExecJsonString(Common::PathToString(self_path)) +
      ",\"host_path\":" + GuestExecJsonString(Common::PathToString(elf_path)) + "}";
  handoff.shared->magic = 0x45584543u;
  handoff.shared->version = 2;
  handoff.shared->request_bytes = static_cast<uint32_t>(request.size());
  handoff.shared->guest_pid = guest_pid;
  handoff.shared->parent_host_pid = GetCurrentProcessId();
  handoff.shared->auth_info_present = 1;
  handoff.shared->auth_info_bytes =
      static_cast<uint32_t>(auth_info.capture.envelope.size());
  std::memcpy(handoff.shared->auth_info_sha256,
              auth_info.capture.envelope_sha256.data(),
              auth_info.capture.envelope_sha256.size());
  std::memcpy(handoff.shared->auth_info_capture, auth_info.capture.envelope.data(),
              auth_info.capture.envelope.size());
  std::memcpy(handoff.shared->request, request.data(), request.size());
  const auto inherited_names = GuestExecAuthInfoEnvironmentNames(auth_info.identity);
  for (size_t i = 0; i != inherited_names.size(); ++i) {
    const auto* marker = i < 2 ? L"unkeyed-mixed-case-marker" : L"keyed-mixed-case-marker";
    Check(_wputenv_s(inherited_names[i].c_str(), marker) == 0,
          "set a mixed-case inherited auth-info variable");
  }
  struct EnvironmentGuard {
    const std::array<std::wstring, 4>& names;
    ~EnvironmentGuard() {
      for (const auto& name: names) _wputenv_s(name.c_str(), L"");
    }
  } environment_guard {inherited_names};
  std::array<wchar_t, 32768> executable {};
  const DWORD length = GetModuleFileNameW(nullptr, executable.data(), executable.size());
  Check(length != 0 && length < executable.size(),
        "locate the accepted auth-info handoff test executable");
  std::wstring command = L"\"" + std::wstring(executable.data(), length) +
      L"\" --guest-exec-auth-handoff-accept-child " + endpoint;
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  Check(CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup, &handoff.process) != FALSE,
        "create a suspended accepted auth-info handoff consumer");
  handoff.shared->child_host_pid = handoff.process.dwProcessId;
  Check(AssignProcessToJobObject(handoff.job, handoff.process.hProcess) != FALSE &&
        ResumeThread(handoff.process.hThread) != DWORD(-1),
        "contain and resume the accepted auth-info handoff consumer");
  DWORD exit_code = 0xffffffffu;
  Check(WaitForSingleObject(handoff.process.hProcess, 10000) == WAIT_OBJECT_0 &&
        GetExitCodeProcess(handoff.process.hProcess, &exit_code) != FALSE && exit_code == 0,
        "accepted auth-info handoff installs the exact child record");
  Check(handoff.shared->auth_info_present == 0 && handoff.shared->auth_info_bytes == 0 &&
        handoff.shared->request_bytes == 0 &&
        std::all_of(handoff.shared->request, handoff.shared->request + request.size(),
                    [](char byte) { return byte == 0; }) &&
        std::all_of(std::begin(handoff.shared->auth_info_sha256),
                    std::end(handoff.shared->auth_info_sha256), [](uint8_t byte) { return byte == 0; }) &&
        std::all_of(std::begin(handoff.shared->auth_info_capture),
                    std::end(handoff.shared->auth_info_capture), [](uint8_t byte) { return byte == 0; }),
        "accept and wipe the v2 auth-info slot and request bytes");
  std::printf("GuestExecFatalSignalTests: auth_info_handoff_v2 acceptance=pass exact_record=pass mixed_case_env_strip=pass slot_wipe=pass request_wipe=pass\n");
#endif
}

// The root has no exec request carrying a host path, only the /app0/<file> options main.cpp builds from --game <file>.
void CheckRootOriginalSelfFromApp0() {
#if defined(_WIN32)
  TempDirectory temporary;
  const auto image = MakeGuestExecAuthInfoFixture();
  const auto self_path = temporary.Path() / "root.self";
  WriteGuestExecAuthInfoFile(self_path, image.self);
  WriteGuestExecAuthInfoFile(temporary.Path() / "root.elf", image.elf);
  Check(_putenv_s("KYTY_DIAGNOSTIC_ORIGINAL_SELF", Common::PathToString(self_path).c_str()) == 0,
        "point the root at its SELF");
  Emulator::RunOptions options;
  options.app0_dir = temporary.Path();
  options.elf = std::filesystem::path("/app0") / "root.elf";
  Libs::LibKernel::Process::ClearVerifiedOriginalSelf();
  Libs::LibKernel::Process::InstallRootOriginalSelf(options);
  Libs::LibKernel::AuthInfo::ImageIdentity installed {};
  const bool exact = Libs::LibKernel::Process::GetVerifiedOriginalSelfIdentity(&installed) &&
      installed.self_sha256 == image.identity.self_sha256 && installed.elf_sha256 == image.identity.elf_sha256 &&
      installed.authority_id == image.identity.authority_id;
  // a byte-identical copy is still a different file
  std::filesystem::copy_file(temporary.Path() / "root.elf", temporary.Path() / "copy.elf");
  const bool same_file = Libs::LibKernel::Process::RootOriginalSelfIsLoadedFile(temporary.Path() / "root.elf");
  const bool copy_refused = !Libs::LibKernel::Process::RootOriginalSelfIsLoadedFile(temporary.Path() / "copy.elf");
  std::error_code locked;
  std::filesystem::remove(temporary.Path() / "root.elf", locked);
  Libs::LibKernel::Process::ReleaseValidatedElfForTests();
  std::error_code released;
  std::filesystem::remove(temporary.Path() / "root.elf", released);
  Libs::LibKernel::Process::ClearVerifiedOriginalSelf();
  _putenv_s("KYTY_DIAGNOSTIC_ORIGINAL_SELF", "");
  Check(exact, "validate the root SELF against the host file behind /app0");
  Check(same_file && copy_refused, "match the loaded ELF by file identity, not by contents");
  Check(static_cast<bool>(locked) && !released, "hold the validated ELF until the test releases it");
#endif
}

void CheckGuestExecLegacyAuthInfoJsonRejection();

void CheckGuestExecAuthInfoSlotRejection() {
#if defined(_WIN32)
  CheckGuestExecAuthInfoSlotAcceptance();
  GuestExecFatalSignalFixture fixture;
  LARGE_INTEGER counter {};
  Check(QueryPerformanceCounter(&counter) != FALSE,
        "read a unique auth-info handoff fixture counter");
  std::array<char, 33> token {};
  const int token_size = std::snprintf(token.data(), token.size(), "%08lx%08lx%016llx",
      GetCurrentProcessId(), GetTickCount(),
      static_cast<unsigned long long>(counter.QuadPart));
  Check(token_size == 32, "format a valid auth-info handoff endpoint token");
  const std::wstring endpoint(token.begin(), token.end() - 1);
  const std::wstring prefix = L"Local\\KytyExec_" + endpoint;
  fixture.mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
      static_cast<DWORD>(sizeof(GuestExecFatalSignalHandoff)), (prefix + L"_map").c_str());
  const bool mapping_created = fixture.mapping != nullptr && GetLastError() != ERROR_ALREADY_EXISTS;
  fixture.prepared = CreateEventW(nullptr, TRUE, FALSE, (prefix + L"_prepared").c_str());
  fixture.release = CreateEventW(nullptr, TRUE, FALSE, (prefix + L"_release").c_str());
  fixture.job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  Check(mapping_created && fixture.prepared != nullptr && fixture.release != nullptr &&
        fixture.job != nullptr && SetInformationJobObject(fixture.job,
            JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != FALSE,
        "create isolated auth-info handoff fixture objects");
  fixture.shared = static_cast<GuestExecFatalSignalHandoff*>(MapViewOfFile(
      fixture.mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(GuestExecFatalSignalHandoff)));
  Check(fixture.shared != nullptr, "map the auth-info handoff fixture");
  std::memset(fixture.shared, 0, sizeof(*fixture.shared));
  constexpr uint32_t guest_pid = 6194;
  std::array<wchar_t, 32768> executable {};
  const DWORD length = GetModuleFileNameW(nullptr, executable.data(), executable.size());
  Check(length != 0 && length < executable.size(),
        "locate the auth-info handoff test executable");
  const std::string request =
      "{\"argv\":[],\"envp\":[],\"guest_pid\":" + std::to_string(guest_pid) +
      ",\"host_path\":" + GuestExecJsonString(Common::PathToString(
          std::filesystem::path(executable.data(), executable.data() + length))) + "}";
  fixture.shared->magic = 0x45584543u;
  fixture.shared->version = 2;
  fixture.shared->request_bytes = static_cast<uint32_t>(request.size());
  fixture.shared->guest_pid = guest_pid;
  fixture.shared->parent_host_pid = GetCurrentProcessId();
  fixture.shared->auth_info_present = 1;
  fixture.shared->auth_info_bytes = 1;
  std::memset(fixture.shared->auth_info_sha256, 0x5a,
              sizeof(fixture.shared->auth_info_sha256));
  std::memset(fixture.shared->auth_info_capture, 0xa5,
              sizeof(fixture.shared->auth_info_capture));
  std::memcpy(fixture.shared->request, request.data(), request.size());
  std::wstring command = L"\"" + std::wstring(executable.data(), length) +
      L"\" --guest-exec-auth-handoff-reject-child " + endpoint;
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  Check(CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup, &fixture.process) != FALSE,
        "create a suspended invalid auth-info handoff consumer");
  fixture.shared->child_host_pid = fixture.process.dwProcessId;
  Check(AssignProcessToJobObject(fixture.job, fixture.process.hProcess) != FALSE &&
        ResumeThread(fixture.process.hThread) != DWORD(-1),
        "contain and resume the invalid auth-info handoff consumer");
  DWORD exit_code = 0xffffffffu;
  Check(WaitForSingleObject(fixture.process.hProcess, 10000) == WAIT_OBJECT_0 &&
        GetExitCodeProcess(fixture.process.hProcess, &exit_code) != FALSE && exit_code == 0,
        "invalid auth-info handoff is rejected by the exec child");
  Check(fixture.shared->error == Libs::LibKernel::KERNEL_ERROR_ENOEXEC &&
        fixture.shared->state == 2 &&
        fixture.shared->auth_info_present == 0 && fixture.shared->auth_info_bytes == 0 &&
        fixture.shared->request_bytes == 0 &&
        std::all_of(fixture.shared->request, fixture.shared->request + request.size(),
                    [](char byte) { return byte == 0; }) &&
        std::all_of(std::begin(fixture.shared->auth_info_sha256),
                    std::end(fixture.shared->auth_info_sha256), [](uint8_t byte) { return byte == 0; }) &&
        std::all_of(std::begin(fixture.shared->auth_info_capture),
                    std::end(fixture.shared->auth_info_capture), [](uint8_t byte) { return byte == 0; }),
        "reject and wipe invalid auth-info handoff and request bytes");
  std::printf("GuestExecFatalSignalTests: auth_info_handoff_v2 rejection=pass slot_wipe=pass request_wipe=pass\n");
  CheckGuestExecLegacyAuthInfoJsonRejection();
#endif
}

void CheckGuestExecLegacyAuthInfoJsonRejection() {
#if defined(_WIN32)
  constexpr uint32_t guest_pid = 6192;
  const std::string prefix =
      "{\"argv\":[],\"envp\":[],\"guest_pid\":" + std::to_string(guest_pid);
  auto run = [&](const std::string& request, bool accept) {
    GuestExecFatalSignalFixture fixture;
    LARGE_INTEGER counter {};
    Check(QueryPerformanceCounter(&counter) != FALSE,
          "read a unique legacy auth-info request counter");
    std::array<char, 33> token {};
    const int token_size = std::snprintf(token.data(), token.size(), "%08lx%08lx%016llx",
        GetCurrentProcessId(), GetTickCount(),
        static_cast<unsigned long long>(counter.QuadPart));
    Check(token_size == 32, "format a legacy auth-info endpoint token");
    const std::wstring endpoint(token.begin(), token.end() - 1);
    const std::wstring object_prefix = L"Local\\KytyExec_" + endpoint;
    fixture.mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
        static_cast<DWORD>(sizeof(GuestExecFatalSignalHandoff)),
        (object_prefix + L"_map").c_str());
    const bool mapping_created = fixture.mapping != nullptr &&
        GetLastError() != ERROR_ALREADY_EXISTS;
    fixture.prepared = CreateEventW(nullptr, TRUE, FALSE,
        (object_prefix + L"_prepared").c_str());
    fixture.release = CreateEventW(nullptr, TRUE, FALSE,
        (object_prefix + L"_release").c_str());
    fixture.job = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    Check(mapping_created && fixture.prepared != nullptr && fixture.release != nullptr &&
          fixture.job != nullptr && SetInformationJobObject(fixture.job,
              JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != FALSE,
          "create isolated legacy auth-info request objects");
    fixture.shared = static_cast<GuestExecFatalSignalHandoff*>(MapViewOfFile(
        fixture.mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(GuestExecFatalSignalHandoff)));
    Check(fixture.shared != nullptr, "map the legacy auth-info request fixture");
    std::memset(fixture.shared, 0, sizeof(*fixture.shared));
    fixture.shared->magic = 0x45584543u;
    fixture.shared->version = 2;
    fixture.shared->request_bytes = static_cast<uint32_t>(request.size());
    fixture.shared->guest_pid = guest_pid;
    fixture.shared->parent_host_pid = GetCurrentProcessId();
    std::memcpy(fixture.shared->request, request.data(), request.size());
    std::array<wchar_t, 32768> executable {};
    const DWORD length = GetModuleFileNameW(nullptr, executable.data(), executable.size());
    Check(length != 0 && length < executable.size(),
          "locate the legacy auth-info request test executable");
    const wchar_t* child_mode = accept ? L" --guest-exec-auth-json-value-child " :
        L" --guest-exec-auth-handoff-reject-child ";
    std::wstring command = L"\"" + std::wstring(executable.data(), length) +
        L"\"" + child_mode + endpoint;
    STARTUPINFOW startup {};
    startup.cb = sizeof(startup);
    Check(CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE,
              CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup,
              &fixture.process) != FALSE,
          "create a suspended legacy auth-info request consumer");
    fixture.shared->child_host_pid = fixture.process.dwProcessId;
    Check(AssignProcessToJobObject(fixture.job, fixture.process.hProcess) != FALSE &&
          ResumeThread(fixture.process.hThread) != DWORD(-1),
          "contain and resume the legacy auth-info request consumer");
    DWORD exit_code = 0xffffffffu;
    Check(WaitForSingleObject(fixture.process.hProcess, 10000) == WAIT_OBJECT_0 &&
          GetExitCodeProcess(fixture.process.hProcess, &exit_code) != FALSE && exit_code == 0,
          "legacy auth-info request has the expected exec-child result");
    const bool expected_state = accept ?
        fixture.shared->error == 0 && fixture.shared->state == 0 :
        fixture.shared->error == Libs::LibKernel::KERNEL_ERROR_ENOEXEC &&
            fixture.shared->state == 2;
    Check(expected_state && fixture.shared->request_bytes == 0 &&
          std::all_of(fixture.shared->request, fixture.shared->request + request.size(),
                      [](char byte) { return byte == 0; }),
          "apply the expected legacy auth-info decision and wipe request bytes");
  };
  run(prefix + ",\"container\":{\"auth_info_capt\\u0075re\":not-json}}", false);
  run(prefix + ",\"container\":{\"auth_info_capture_sha\\u0032\\u0035\\u0036\":not-json}}", false);
  std::array<wchar_t, 32768> self {};
  const DWORD self_length = GetModuleFileNameW(nullptr, self.data(), self.size());
  Check(self_length != 0 && self_length < self.size(),
        "locate the legacy auth-info value test executable");
  const std::string host_path = ",\"host_path\":" + GuestExecJsonString(Common::PathToString(
      std::filesystem::path(self.data(), self.data() + self_length)));
  run(prefix + host_path + ",\"label\":\"auth_info_capture\",\"nested\":["
      "\"auth_info_capture_sha256\",{\"safe\":\"auth_info_capture\"}]}", true);
  std::printf("GuestExecFatalSignalTests: legacy_auth_info_json escaped_key_rejection=pass value_acceptance=pass shared_request_wipe=pass\n");
#endif
}

void CheckGuestExecFatalSignalPublication() {
#if defined(_WIN32)
  GuestExecFatalSignalFixture fixture;
  LARGE_INTEGER counter {};
  Check(QueryPerformanceCounter(&counter) != FALSE,
        "read a unique exec-child fixture counter");
  std::array<char, 33> token {};
  const int token_size = std::snprintf(token.data(), token.size(), "%08lx%08lx%016llx",
      GetCurrentProcessId(), GetTickCount(),
      static_cast<unsigned long long>(counter.QuadPart));
  Check(token_size == 32, "format a valid exec-child endpoint token");
  const std::wstring endpoint(token.begin(), token.end() - 1);
  const std::wstring prefix = L"Local\\KytyExec_" + endpoint;
  fixture.mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
      static_cast<DWORD>(sizeof(GuestExecFatalSignalHandoff)), (prefix + L"_map").c_str());
  Check(fixture.mapping != nullptr && GetLastError() != ERROR_ALREADY_EXISTS,
        "create an isolated exec-child handoff mapping");
  fixture.prepared = CreateEventW(nullptr, TRUE, FALSE, (prefix + L"_prepared").c_str());
  fixture.release = CreateEventW(nullptr, TRUE, FALSE, (prefix + L"_release").c_str());
  fixture.job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  Check(fixture.prepared != nullptr && fixture.release != nullptr && fixture.job != nullptr &&
        SetInformationJobObject(fixture.job, JobObjectExtendedLimitInformation,
            &limits, sizeof(limits)) != FALSE,
        "create contained exec-child fixture objects");
  fixture.shared = static_cast<GuestExecFatalSignalHandoff*>(MapViewOfFile(
      fixture.mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(GuestExecFatalSignalHandoff)));
  Check(fixture.shared != nullptr, "map the exec-child handoff fixture");
  std::memset(fixture.shared, 0, sizeof(*fixture.shared));
  constexpr uint32_t guest_pid = 6195;
  std::array<wchar_t, 32768> executable {};
  const DWORD length = GetModuleFileNameW(nullptr, executable.data(), executable.size());
  Check(length != 0 && length < executable.size(),
        "locate the exec-child fatal-signal test executable");
  const std::string request =
      "{\"argv\":[],\"envp\":[],\"guest_pid\":" + std::to_string(guest_pid) +
      ",\"host_path\":" + GuestExecJsonString(Common::PathToString(
          std::filesystem::path(executable.data(), executable.data() + length))) + "}";
  fixture.shared->magic = 0x45584543u;
  fixture.shared->version = 2;
  fixture.shared->request_bytes = static_cast<uint32_t>(request.size());
  fixture.shared->guest_pid = guest_pid;
  fixture.shared->parent_host_pid = GetCurrentProcessId();
  std::memcpy(fixture.shared->request, request.data(), request.size());
  std::wstring command = L"\"" + std::wstring(executable.data(), length) +
      L"\" --guest-exec-fatal-signal-child " + endpoint;
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  Check(CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup, &fixture.process) != FALSE,
        "create a suspended exec-child fatal-signal publisher");
  fixture.shared->child_host_pid = fixture.process.dwProcessId;
  Check(AssignProcessToJobObject(fixture.job, fixture.process.hProcess) != FALSE &&
        ResumeThread(fixture.process.hThread) != DWORD(-1),
        "contain and resume the exec-child fatal-signal publisher");
  const DWORD waited = WaitForSingleObject(fixture.process.hProcess, 10000);
  DWORD exit_code = 0xffffffffu;
  Check(waited == WAIT_OBJECT_0 &&
        GetExitCodeProcess(fixture.process.hProcess, &exit_code) != FALSE && exit_code == 0,
        "exec-child fatal-signal publisher finishes successfully");
  const LONG known = InterlockedCompareExchange(&fixture.shared->guest_exit_known, 0, 0);
  const uint32_t status = fixture.shared->guest_wait_status;
  Check(known == 1 && status == Libs::LibKernel::Process::kGuestSigillCoreWaitStatus &&
        (status & 0x7fu) == 4u && (status & 0x80u) != 0 && (status >> 8u) == 0,
        "exec-child handoff publishes SIGILL with the core bit as wait status 0x84");
  std::printf("GuestExecFatalSignalTests: wait_status=0x%02x signal=4 core=1 publication=pass\n",
      status);
#endif
}

void CheckGuestExecFatalSignalTermination() {
#if defined(_WIN32)
  GuestExecFatalSignalFixture fixture;
  TempDirectory temporary;
  LARGE_INTEGER counter {};
  Check(QueryPerformanceCounter(&counter) != FALSE,
        "read a unique fatal-UD2 fixture counter");
  std::array<char, 33> token {};
  const int token_size = std::snprintf(token.data(), token.size(), "%08lx%08lx%016llx",
      GetCurrentProcessId(), GetTickCount(),
      static_cast<unsigned long long>(counter.QuadPart));
  Check(token_size == 32, "format a valid fatal-UD2 endpoint token");
  const std::wstring endpoint(token.begin(), token.end() - 1);
  const std::wstring prefix = L"Local\\KytyExec_" + endpoint;
  fixture.mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
      static_cast<DWORD>(sizeof(GuestExecFatalSignalHandoff)), (prefix + L"_map").c_str());
  Check(fixture.mapping != nullptr && GetLastError() != ERROR_ALREADY_EXISTS,
        "create an isolated fatal-UD2 handoff mapping");
  fixture.prepared = CreateEventW(nullptr, TRUE, FALSE, (prefix + L"_prepared").c_str());
  fixture.release = CreateEventW(nullptr, TRUE, FALSE, (prefix + L"_release").c_str());
  fixture.job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  Check(fixture.prepared != nullptr && fixture.release != nullptr && fixture.job != nullptr &&
        SetInformationJobObject(fixture.job, JobObjectExtendedLimitInformation,
            &limits, sizeof(limits)) != FALSE,
        "create contained fatal-UD2 fixture objects");
  fixture.shared = static_cast<GuestExecFatalSignalHandoff*>(MapViewOfFile(
      fixture.mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(GuestExecFatalSignalHandoff)));
  Check(fixture.shared != nullptr, "map the fatal-UD2 handoff fixture");
  std::memset(fixture.shared, 0, sizeof(*fixture.shared));
  constexpr uint32_t guest_pid = 6196;
  std::array<wchar_t, 32768> executable {};
  const DWORD length = GetModuleFileNameW(nullptr, executable.data(), executable.size());
  Check(length != 0 && length < executable.size(),
        "locate the fatal-UD2 test executable");
  const std::string request =
      "{\"argv\":[],\"envp\":[],\"guest_pid\":" + std::to_string(guest_pid) +
      ",\"host_path\":" + GuestExecJsonString(Common::PathToString(
          std::filesystem::path(executable.data(), executable.data() + length))) + "}";
  fixture.shared->magic = 0x45584543u;
  fixture.shared->version = 2;
  fixture.shared->request_bytes = static_cast<uint32_t>(request.size());
  fixture.shared->guest_pid = guest_pid;
  fixture.shared->parent_host_pid = GetCurrentProcessId();
  std::memcpy(fixture.shared->request, request.data(), request.size());
  std::wstring command = L"\"" + std::wstring(executable.data(), length) +
      L"\" --guest-exec-fatal-ud2-child " + endpoint + L" \"" +
      temporary.Path().wstring() + L"\"";
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  Check(CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup, &fixture.process) != FALSE,
        "create a suspended fatal-UD2 exec child");
  fixture.shared->child_host_pid = fixture.process.dwProcessId;
  Check(AssignProcessToJobObject(fixture.job, fixture.process.hProcess) != FALSE &&
        ResumeThread(fixture.process.hThread) != DWORD(-1),
        "contain and resume the fatal-UD2 exec child");
  const DWORD waited = WaitForSingleObject(fixture.process.hProcess, 10000);
  DWORD exit_code = 0xffffffffu;
  Check(waited == WAIT_OBJECT_0 &&
            GetExitCodeProcess(fixture.process.hProcess, &exit_code) != FALSE &&
            exit_code == static_cast<DWORD>(EXCEPTION_ILLEGAL_INSTRUCTION),
        "guest UD2 terminates its exec child with the native illegal-instruction code");
  const LONG known = InterlockedCompareExchange(&fixture.shared->guest_exit_known, 0, 0);
  const uint32_t status = fixture.shared->guest_wait_status;
  Check(known == 1 && status == Libs::LibKernel::Process::kGuestSigillCoreWaitStatus,
        "guest UD2 publishes wait status 0x84 before terminating its exec child");
  std::printf("GuestExecFatalSignalTests: original_ud2_host_exit=0x%08lx wait_status=0x%02x termination=pass\n",
      static_cast<unsigned long>(exit_code), status);
#endif
}

void TriggerGuestExecFatalSignalUd2(const std::filesystem::path& root) {
#if defined(_WIN32)
  const auto path = root / "guest_exec_fatal_signal_trigger.sprx";
  WriteModuleLifetimeElf(path, 7);
  std::ifstream input(path, std::ios::binary);
  Check(input.good(), "open the fatal-UD2 ELF fixture");
  const std::istreambuf_iterator<char> begin(input);
  const std::istreambuf_iterator<char> end;
  std::vector<uint8_t> image(begin, end);
  input.close();
  constexpr uint64_t original_offset = 0x4200;
  Check(image.size() > original_offset + 1, "read the fatal-UD2 ELF fixture");
  image[original_offset] = 0x0f;
  image[original_offset + 1] = 0x0b;
  auto* program = Common::Singleton<Loader::RuntimeLinker>::Instance()->LoadProgram(
      path, std::move(image));
  Check(program != nullptr, "load the fatal-UD2 ELF fixture");
  using Trap = void (*)();
  reinterpret_cast<Trap>(program->base_vaddr + original_offset)();
  Check(false, "a guest UD2 cannot resume its exec child");
#else
  (void)root;
#endif
}

void RunGuestExecFatalSignalClassifier(const std::filesystem::path& root) {
#if defined(_WIN32)
  const auto path = root / "guest_exec_fatal_signal.sprx";
  WriteModuleLifetimeElf(path, 7);
  const auto read_image = [](const std::filesystem::path& image_path) {
    std::ifstream input(image_path, std::ios::binary);
    Check(input.good(), "open a fatal-signal classifier ELF fixture");
    const std::istreambuf_iterator<char> begin(input);
    const std::istreambuf_iterator<char> end;
    return std::vector<uint8_t>(begin, end);
  };
  auto image = read_image(path);
  Check(image.size() == 0x8000, "read the fatal-signal classifier ELF fixture");
  auto* header = reinterpret_cast<Loader::Elf64_Ehdr*>(image.data());
  auto* segments = reinterpret_cast<Loader::Elf64_Phdr*>(image.data() + header->e_phoff);
  Check(header->e_phnum == 3 && segments[1].p_type == Loader::PT_LOAD &&
        (segments[1].p_flags & Loader::PF_X) != 0,
        "locate the classifier fixture executable segment");
  segments[1].p_filesz = 0x3fffu;
  constexpr uint64_t original_offset = 0x4200;
  constexpr uint64_t injected_offset = 0x4202;
  image[original_offset] = 0x0f;
  image[original_offset + 1] = 0x0b;
  auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
  auto* program = linker->LoadProgram(path, std::move(image));
  Check(program != nullptr, "load the fatal-signal classifier ELF fixture");
  const auto patch_ud2 = [](uint64_t address) {
    DWORD old_protection = 0;
    Check(VirtualProtect(reinterpret_cast<void*>(address), 2, PAGE_EXECUTE_READWRITE,
                         &old_protection) != FALSE,
          "make a classifier fixture site writable");
    const std::array<uint8_t, 2> bytes {0x0f, 0x0b};
    std::memcpy(reinterpret_cast<void*>(address), bytes.data(), bytes.size());
    DWORD ignored = 0;
    Check(VirtualProtect(reinterpret_cast<void*>(address), 2, old_protection, &ignored) != FALSE &&
              FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address), 2) != FALSE,
          "publish a classifier fixture UD2");
  };
  const uint64_t original = program->base_vaddr + original_offset;
  const uint64_t injected = program->base_vaddr + injected_offset;
  const uint64_t file_boundary = program->base_vaddr + 0x7ffe;
  patch_ud2(injected);
  patch_ud2(file_boundary);
  uint64_t owner_base = 0;
  std::filesystem::path owner_path;
  Check(linker->GetOriginalUd2ProgramInfo(original, &owner_base, &owner_path) &&
            owner_base == program->base_vaddr && owner_path == path,
        "accept a file-backed UD2 in executable guest code");
  Check(!linker->GetOriginalUd2ProgramInfo(injected, &owner_base, &owner_path),
        "reject a runtime-injected UD2 in executable guest code");
  Check(!linker->GetOriginalUd2ProgramInfo(file_boundary, &owner_base, &owner_path),
        "reject a UD2 that crosses the executable segment file boundary");
  Check(!linker->GetOriginalUd2ProgramInfo(program->base_vaddr + ModuleLifetimeDataOffset,
                                           &owner_base, &owner_path),
        "reject a non-executable guest mapping");
  linker->Clear();

  const auto static_path = root / "guest_exec_fatal_signal_static.elf";
  WriteModuleLifetimeElf(static_path, 6, nullptr, true);
  auto static_image = read_image(static_path);
  static_image[original_offset] = 0x0f;
  static_image[original_offset + 1] = 0x0b;
  auto* static_program = linker->LoadProgram(static_path, std::move(static_image));
  owner_base = 0;
  owner_path.clear();
  Check(static_program != nullptr && static_program->base_vaddr == ModuleLifetimeStaticBase &&
            linker->GetOriginalUd2ProgramInfo(
                static_program->base_vaddr + original_offset, &owner_base, &owner_path) &&
            owner_base == ModuleLifetimeStaticBase && owner_path == static_path,
        "accept a UD2 using static ELF image-base-relative mapping");
  linker->Clear();
#else
  (void)root;
#endif
}

void CheckGuestExecFatalSignalClassifier() {
#if defined(_WIN32)
  GuestExecFatalSignalFixture fixture;
  fixture.job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  Check(fixture.job != nullptr &&
            SetInformationJobObject(fixture.job, JobObjectExtendedLimitInformation,
                &limits, sizeof(limits)) != FALSE,
        "create a contained fatal-signal classifier job");
  std::array<wchar_t, 32768> executable {};
  const DWORD length = GetModuleFileNameW(nullptr, executable.data(), executable.size());
  Check(length != 0 && length < executable.size(),
        "locate the fatal-signal classifier test executable");
  std::wstring command = L"\"" + std::wstring(executable.data(), length) +
      L"\" --guest-exec-fatal-classifier-child";
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  Check(CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup, &fixture.process) != FALSE,
        "create a suspended fatal-signal classifier child");
  Check(AssignProcessToJobObject(fixture.job, fixture.process.hProcess) != FALSE &&
            ResumeThread(fixture.process.hThread) != DWORD(-1),
        "contain and resume the fatal-signal classifier child");
  const DWORD waited = WaitForSingleObject(fixture.process.hProcess, 10000);
  DWORD exit_code = 0xffffffffu;
  Check(waited == WAIT_OBJECT_0 &&
            GetExitCodeProcess(fixture.process.hProcess, &exit_code) != FALSE && exit_code == 0,
        "fatal-signal classifier child finishes successfully");
  std::printf("GuestExecFatalSignalTests: dynamic_original=accepted injected=rejected file_boundary=rejected static_original=accepted\n");
#endif
}
