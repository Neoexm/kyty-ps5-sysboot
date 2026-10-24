#if defined(_WIN32)

constexpr int32_t HOST_FAULT_FIXTURE_GUEST_PID = 7611;

struct HostFaultCaseResult {
	DWORD                                             exit_code = 0xffffffffu;
	DWORD                                             process_id = 0;
	DWORD                                             thread_id = 0;
	bool                                              record_present = false;
	Common::HostException::UnhandledFaultRecord       record {};
};

uint64_t HostFaultRecordChecksum(
    const Common::HostException::UnhandledFaultRecord& record) {
	auto copy = record;
	copy.checksum = 0;
	uint64_t hash = 1469598103934665603ull;
	const auto* bytes = reinterpret_cast<const uint8_t*>(&copy);
	for (size_t i = 0; i < sizeof(copy); i++) {
		hash = (hash ^ bytes[i]) * 1099511628211ull;
	}
	return hash;
}

bool HostFaultModuleNameIsBasename(const char* name) {
	return std::memchr(name, '\0', Common::HostException::UNHANDLED_FAULT_MODULE_NAME_SIZE) != nullptr &&
	       std::strchr(name, '/') == nullptr && std::strchr(name, '\\') == nullptr &&
	       std::strchr(name, ':') == nullptr;
}

__declspec(noinline) uint64_t HostFaultFixtureRead() {
	return *reinterpret_cast<volatile const uint64_t*>(uintptr_t {1});
}

__declspec(noinline) uint64_t HostFaultFixtureReadCaller() {
	volatile const uint64_t value = HostFaultFixtureRead();
	return value;
}

__declspec(noinline) int HostFaultFixtureUcrtStrcmp() {
	using Strcmp = int(__cdecl*)(const char*, const char*);
	auto* module = GetModuleHandleW(L"ucrtbased.dll");
	auto strcmp_fn = module == nullptr ? nullptr :
	    reinterpret_cast<Strcmp>(GetProcAddress(module, "strcmp"));
        Check(strcmp_fn != nullptr, "resolve the loaded UCRT strcmp fixture");
        return strcmp_fn(reinterpret_cast<const char *>(uintptr_t{1}), "x");
}

__declspec(noinline) void HostFaultFixtureWrite() {
  *reinterpret_cast<volatile uint64_t *>(uintptr_t{1}) = 0x1263;
}

__declspec(noinline) void HostFaultFixtureFrameA() {}
__declspec(noinline) void HostFaultFixtureFrameB() {}
__declspec(noinline) void HostFaultFixturePc() {}

Common::HostException::ExceptionInfo g_host_fault_reentry_info{};
bool g_host_stack_route_ran = false;
bool g_host_stack_route_used_fiber = false;
uint64_t g_host_stack_route_pc = 0;
uint64_t g_host_stack_nested_pc = 0;
bool g_host_stack_nested_enabled = false;
bool g_host_stack_nested_ran = false;
bool g_host_stack_post_action_enabled = false;
void *g_host_stack_original_fiber = nullptr;

void HostStackPostAction(void *) {
  ExitProcess(g_host_stack_route_ran && IsThreadAFiber() != FALSE &&
                      GetCurrentFiber() == g_host_stack_original_fiber
                  ? 47
                  : 48);
}

void HostFaultFixtureReentry() noexcept {
  Common::HostException::CaptureUnhandledFaultProvenance(
      g_host_fault_reentry_info);
}

bool HostStackRouteHandler(const Common::HostException::ExceptionInfo &info) {
  if (info.type != Common::HostException::ExceptionType::IllegalInstruction ||
      info.native_context == nullptr) {
    return false;
  }
  if (info.exception_address == g_host_stack_nested_pc &&
      g_host_stack_nested_pc != 0) {
    g_host_stack_nested_ran = IsThreadAFiber() != FALSE;
    auto *context = static_cast<CONTEXT *>(info.native_context);
    context->Rip += 2;
    return true;
  }
  if (info.exception_address != g_host_stack_route_pc)
    return false;
  g_host_stack_route_ran = true;
  g_host_stack_route_used_fiber = IsThreadAFiber() != FALSE;
  if (g_host_stack_post_action_enabled &&
      !Common::HostException::QueueNativeGuestPostHandlerAction(
          HostStackPostAction, nullptr)) {
    return false;
  }
  if (g_host_stack_nested_enabled) {
    reinterpret_cast<void (*)()>(g_host_stack_nested_pc)();
  }
  auto *context = static_cast<CONTEXT *>(info.native_context);
  context->Rip += 2;
  return true;
}

bool HostStackUnhandledHandler(
    const Common::HostException::ExceptionInfo &info) {
  Common::HostException::CaptureUnhandledFaultProvenance(info);
  std::_Exit(321);
}

int RunHostStackRouteFixture(const std::string &mode) {
  if (_putenv_s("KYTY_DIAGNOSTIC_NATIVE_SYSCALL_HOST_STACK", "1") != 0 ||
      !Common::HostException::InstallHandler(HostStackRouteHandler)) {
    return 20;
  }
  void *page = nullptr;
  for (uint64_t candidate = 0x300000000ull;
       page == nullptr && candidate < 0x380000000ull; candidate += 0x1000000) {
    page = VirtualAlloc(reinterpret_cast<void *>(candidate), 0x1000,
                        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  }
  if (page == nullptr || reinterpret_cast<uint64_t>(page) < 0x80000000ull)
    return 21;
  const std::array<uint8_t, 19> code{0x0f, 0x0b, 0xc3, 0x90, 0x90, 0x90, 0x90,
                                     0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                                     0x90, 0x90, 0x0f, 0x0b, 0xc3};
  std::memcpy(page, code.data(), code.size());
  FlushInstructionCache(GetCurrentProcess(), page, code.size());
  uint32_t token = 0;
  if (mode != "route-unregistered") {
    token = Common::HostException::RegisterGuestCodeProvenance(
        {reinterpret_cast<uint64_t>(page), 0x1000,
         reinterpret_cast<uint64_t>(page), 0,
         Common::HostException::FaultGuestCodeKind::ProgramExecutable,
         "route_fixture.elf", "host_stack_route"});
    if (token == 0)
      return 22;
		if (Common::HostException::QueryActiveGuestCodeKind(
		        reinterpret_cast<uint64_t>(page)) !=
		    Common::HostException::FaultGuestCodeKind::ProgramExecutable)
			return 26;
    if (mode == "route-retired") {
      Common::HostException::UnregisterGuestCodeProvenance(token);
			if (Common::HostException::QueryActiveGuestCodeKind(
			        reinterpret_cast<uint64_t>(page)) !=
			    Common::HostException::FaultGuestCodeKind::Unavailable)
				return 27;
    }
	} else if (Common::HostException::QueryActiveGuestCodeKind(
	               reinterpret_cast<uint64_t>(page)) !=
	           Common::HostException::FaultGuestCodeKind::Unavailable) {
		return 28;
  }
  g_host_stack_route_pc = reinterpret_cast<uint64_t>(page);
  g_host_stack_nested_enabled = mode == "route-nested";
  g_host_stack_post_action_enabled = mode == "route-post-action";
  g_host_stack_nested_pc =
      g_host_stack_nested_enabled ? reinterpret_cast<uint64_t>(page) + 16 : 0;
  if (g_host_stack_post_action_enabled) {
    if (!Common::HostException::
            PrepareNativeGuestHandlerHostStackForCurrentThread())
      return 24;
    g_host_stack_original_fiber = GetCurrentFiber();
  }
  reinterpret_cast<void (*)()>(page)();
  if (g_host_stack_post_action_enabled)
    return 25;
  const bool expect_fiber = mode == "route-registered";
  if (mode == "route-nested") {
    if (!g_host_stack_route_ran || !g_host_stack_route_used_fiber ||
        !g_host_stack_nested_ran)
      return 23;
  } else if (!g_host_stack_route_ran ||
             g_host_stack_route_used_fiber != expect_fiber) {
    return 23;
  }
  if (token != 0)
    Common::HostException::UnregisterGuestCodeProvenance(token);
  VirtualFree(page, 0, MEM_RELEASE);
  return 0;
}

[[noreturn]] void RunHostStackUnhandledFixture() {
  if (_putenv_s("KYTY_DIAGNOSTIC_NATIVE_SYSCALL_HOST_STACK", "1") != 0 ||
      !Common::HostException::InstallHandler(HostStackUnhandledHandler)) {
    ExitProcess(30);
  }
  void *page = nullptr;
  for (uint64_t candidate = 0x400000000ull;
       page == nullptr && candidate < 0x480000000ull; candidate += 0x1000000) {
    page = VirtualAlloc(reinterpret_cast<void *>(candidate), 0x1000,
                        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  }
  if (page == nullptr)
    ExitProcess(31);
  const std::array<uint8_t, 11> code{0x48, 0xa1, 0x01, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0xc3};
  std::memcpy(page, code.data(), code.size());
  FlushInstructionCache(GetCurrentProcess(), page, code.size());
  const auto token = Common::HostException::RegisterGuestCodeProvenance(
      {reinterpret_cast<uint64_t>(page), 0x1000,
       reinterpret_cast<uint64_t>(page), 0,
       Common::HostException::FaultGuestCodeKind::ProgramExecutable,
       "route_unhandled.elf", "host_stack_unhandled"});
  if (token == 0)
    ExitProcess(32);
  reinterpret_cast<void (*)()>(page)();
  ExitProcess(33);
}

void HostFaultFixtureExecutePrivate(bool registered, bool retired) {
	const std::array<uint8_t, 11> code {0x48, 0xa1, 0x01, 0x00, 0x00, 0x00,
	                                    0x00, 0x00, 0x00, 0x00, 0xc3};
	auto* page = static_cast<uint8_t*>(VirtualAlloc(nullptr, 0x1000,
	                                                MEM_RESERVE | MEM_COMMIT,
	                                                PAGE_EXECUTE_READWRITE));
	Check(page != nullptr, "allocate private executable fault fixture");
	std::memcpy(page, code.data(), code.size());
	FlushInstructionCache(GetCurrentProcess(), page, code.size());
	uint32_t token = 0;
	if (registered) {
		using namespace Common::HostException;
		Check(RegisterGuestCodeProvenance({reinterpret_cast<uint64_t>(page), 0,
		                                    reinterpret_cast<uint64_t>(page), 0,
		                                    FaultGuestCodeKind::ProgramExecutable,
		                                    "fixture_guest.elf", "invalid_zero_size"}) == 0 &&
		          RegisterGuestCodeProvenance({reinterpret_cast<uint64_t>(page), 0x1000,
		                                    reinterpret_cast<uint64_t>(page), 0,
		                                    FaultGuestCodeKind::ProgramExecutable,
		                                    "bad/path.elf", "invalid_owner"}) == 0,
		      "guest-code provenance rejects invalid ranges and owner paths");
		token = RegisterGuestCodeProvenance({
		    reinterpret_cast<uint64_t>(page), 0x1000,
		    reinterpret_cast<uint64_t>(page) - 0x1260, 0x1260,
		    FaultGuestCodeKind::ProgramExecutable,
		    "fixture_guest.elf", "private_execute_fixture"});
		Check(token != 0, "register bounded private executable provenance");
		if (retired) UnregisterGuestCodeProvenance(token);
	}
	reinterpret_cast<void (*)()>(page)();
}

void CaptureHostFaultFixture(bool unavailable) {
	struct Frame {
		uint64_t next;
		uint64_t ret;
	};
	Frame frames[2] {
	    {reinterpret_cast<uint64_t>(&frames[1]),
	     reinterpret_cast<uint64_t>(&HostFaultFixtureFrameA)},
	    {0, reinterpret_cast<uint64_t>(&HostFaultFixtureFrameB)}};
	Common::HostException::ExceptionInfo info {};
	info.type = Common::HostException::ExceptionType::AccessViolation;
	info.access_violation_type = Common::HostException::AccessViolationType::Read;
	info.access_violation_vaddr = 1;
	info.exception_address = reinterpret_cast<uint64_t>(&HostFaultFixturePc);
	info.rbp = unavailable ? 1 : reinterpret_cast<uint64_t>(&frames[0]);
	info.rsp = unavailable ? 1 : reinterpret_cast<uint64_t>(&frames[0]);
	info.native_code = EXCEPTION_ACCESS_VIOLATION;
	info.native_process_id = GetCurrentProcessId();
	info.native_thread_id = GetCurrentThreadId();
	info.platform_access_valid = 1;
	info.platform_access = 0;
	info.native_context_flags = CONTEXT_CONTROL | CONTEXT_INTEGER;
	info.original_context_pc = info.exception_address;
	info.original_context_rflags = 0x202;
	Check(Common::HostException::CaptureUnhandledFaultProvenance(info),
	      "capture injected host-fault provenance");
}

void CaptureHostFaultMissingMetadata() {
	Common::HostException::ExceptionInfo info {};
	info.type = Common::HostException::ExceptionType::AccessViolation;
	info.exception_address = reinterpret_cast<uint64_t>(&HostFaultFixturePc);
	info.original_context_pc = info.exception_address;
	info.original_context_rflags = 0x202;
	info.native_code = EXCEPTION_ACCESS_VIOLATION;
	info.native_process_id = GetCurrentProcessId();
	info.native_thread_id = GetCurrentThreadId();
	info.native_context_flags = CONTEXT_CONTROL | CONTEXT_INTEGER;
	Check(Common::HostException::CaptureUnhandledFaultProvenance(info),
	      "capture missing-metadata host-fault provenance");
}

int RunUnhandledHostExceptionDiagnosticsChild(int argc, char** argv) {
	if (argc < 2 || std::strcmp(argv[1], "--host-exception-provenance-child") != 0) return -1;
	if (argc != 5) return 2;
	const std::string mode = argv[2];
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
	if (_putenv_s("KYTY_DIAGNOSTIC_UNHANDLED_HOST_PROVENANCE_PREFIX",
	              mode == "disabled" ? "" : argv[3]) != 0) return 3;
	if (mode != "disabled" &&
	    !Common::HostException::PrepareUnhandledFaultProvenance(HOST_FAULT_FIXTURE_GUEST_PID)) {
		return 4;
	}
	if (mode == "route-unhandled") RunHostStackUnhandledFixture();
	if (mode == "route-registered" || mode == "route-retired" ||
	    mode == "route-unregistered" || mode == "route-nested" ||
	    mode == "route-post-action") {
		return RunHostStackRouteFixture(mode);
	}
	Common::InitializeThreads();
	Common::Subsystems subsystems;
	subsystems.Initialize<Config::Lifecycle>();
	Config::ConfigOptions options;
	options.printf_direction = Config::LogDirection::Silent;
	Config::Load(options);
	subsystems.Initialize<Log::Lifecycle>();
	subsystems.Initialize<Libs::LibKernel::Memory::Lifecycle>();
	auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
	if (linker->LoadProgram(Common::PathFromUtf8(argv[4])) == nullptr) return 5;
	if (mode == "direct") {
		CaptureHostFaultFixture(false);
		subsystems.Destroy();
		return 0;
	}
	if (mode == "unavailable") {
		CaptureHostFaultFixture(true);
		subsystems.Destroy();
		return 0;
	}
	if (mode == "missing-metadata") {
		CaptureHostFaultMissingMetadata();
		subsystems.Destroy();
		return 0;
	}
	if (mode == "reentrant") {
		g_host_fault_reentry_info.type = Common::HostException::ExceptionType::AccessViolation;
		g_host_fault_reentry_info.access_violation_type =
		    Common::HostException::AccessViolationType::Write;
		g_host_fault_reentry_info.access_violation_vaddr = 1;
		g_host_fault_reentry_info.exception_address =
		    reinterpret_cast<uint64_t>(&HostFaultFixturePc);
		g_host_fault_reentry_info.original_context_pc =
		    g_host_fault_reentry_info.exception_address;
		g_host_fault_reentry_info.native_process_id = GetCurrentProcessId();
		g_host_fault_reentry_info.native_thread_id = GetCurrentThreadId();
		g_host_fault_reentry_info.platform_access_valid = 1;
		g_host_fault_reentry_info.platform_access = 1;
		Common::HostException::SetUnhandledFaultReentryHookForTests(HostFaultFixtureReentry);
	}
	if (mode == "heap-lock" && !HeapLock(GetProcessHeap())) return 6;
	if (mode == "write") HostFaultFixtureWrite();
	if (mode == "execute") HostFaultFixtureExecutePrivate(false, false);
	if (mode == "execute-registered") HostFaultFixtureExecutePrivate(true, false);
	if (mode == "execute-retired") HostFaultFixtureExecutePrivate(true, true);
	if (mode == "strcmp") HostFaultFixtureUcrtStrcmp();
	if (mode == "read" || mode == "disabled" || mode == "heap-lock" ||
	    mode == "reentrant") {
		volatile const uint64_t value = HostFaultFixtureReadCaller();
		(void)value;
	}
	return 95;
}

std::filesystem::path
FindHostFaultRecord(const std::filesystem::path &directory) {
  std::filesystem::path found;
  for (const auto &entry : std::filesystem::directory_iterator(directory)) {
    const auto name = entry.path().filename().string();
    if (entry.is_regular_file() && name.rfind("fault.pid-", 0) == 0 &&
        entry.path().extension() == ".bin") {
      Check(found.empty(), "one fixed provenance record per child");
      found = entry.path();
    }
  }
  return found;
}

HostFaultCaseResult RunHostFaultCase(const std::filesystem::path &executable,
                                     const std::filesystem::path &fixture,
                                     const std::filesystem::path &root,
                                     const char *mode) {
  const auto directory = root / mode;
  Check(std::filesystem::create_directory(directory),
        "create isolated host-fault case directory");
  const auto prefix = directory / "fault";
  auto command = L"\"" + executable.native() +
                 L"\" --host-exception-provenance-child " +
                 Common::PathFromUtf8(mode).native() + L" \"" +
                 prefix.native() + L"\" \"" + fixture.native() + L"\"";
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  Check(job != nullptr &&
            SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                    &limits, sizeof(limits)),
        "contain host-fault fixture child");
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  Check(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr,
                       FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr,
                       nullptr, &startup, &process),
        "start host-fault fixture child");
  if (!AssignProcessToJobObject(job, process.hProcess)) {
    TerminateProcess(process.hProcess, 90);
    WaitForSingleObject(process.hProcess, 1000);
    Check(false, "assign host-fault child before execution");
  }
  HostFaultCaseResult result;
  result.process_id = process.dwProcessId;
  result.thread_id = process.dwThreadId;
  Check(ResumeThread(process.hThread) != DWORD(-1),
        "resume contained host-fault fixture child");
  const auto wait = WaitForSingleObject(process.hProcess, 15000);
  if (wait != WAIT_OBJECT_0) {
    TerminateJobObject(job, 126);
    WaitForSingleObject(process.hProcess, 1000);
  }
  Check(wait == WAIT_OBJECT_0 &&
            GetExitCodeProcess(process.hProcess, &result.exit_code),
        "host-fault fixture child terminates within its bound");
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  CloseHandle(job);
  const auto record_path = FindHostFaultRecord(directory);
  result.record_present =
      !record_path.empty() && std::filesystem::file_size(record_path) != 0;
  if (result.record_present) {
    Common::File file(record_path, Common::File::Mode::Read);
    Check(!file.IsInvalid(), "open fixed host-fault provenance record");
    const auto data = file.ReadWholeBuffer();
    file.Close();
    Check(data.size() == sizeof(result.record),
          "host-fault provenance has the exact bounded record size");
    std::memcpy(&result.record, data.data(), sizeof(result.record));
  }
  return result;
}

void CheckFaultRecordEnvelope(const HostFaultCaseResult& result) {
	using namespace Common::HostException;
	Check(result.record_present &&
	          std::memcmp(result.record.magic, "KYTYFPV3", sizeof(result.record.magic)) == 0 &&
	          result.record.version == 3 && result.record.size == sizeof(UnhandledFaultRecord) &&
	          result.record.checksum == HostFaultRecordChecksum(result.record) &&
	          result.record.complete == 0x434f4d50u,
	      "the fixed record envelope and checksum are exact");
	Check(result.record.native_process_id == result.process_id &&
	          result.record.native_thread_id == result.thread_id &&
	          result.record.guest_process_id == HOST_FAULT_FIXTURE_GUEST_PID,
	      "the fixed record identifies the original process and thread");
	Check(result.record.native_context_flags != 0 &&
	          result.record.original_context_rflags != 0 &&
	          result.record.emitter_matches_original_pc == 1 &&
	          result.record.expected_exit_status == 321,
	      "the fixed record retains the saved context and fatal outcome");
	Check(result.record.module_snapshot_count > 0 &&
	          result.record.module_snapshot_count <= 256 &&
	          result.record.guest_code_registry_count > 0 &&
	          result.record.guest_code_registry_count <= 4096 &&
	          result.record.guest_code_registry_overflow == 0 &&
	          result.record.handler_stack_status == HandlerStackStatus::Omitted &&
	          result.record.original_frame_count <= UNHANDLED_FAULT_MAX_FRAMES,
	      "the module and stack evidence stays inside its fixed bounds");
	Check((result.record.pc.address_class == FaultAddressClass::Image &&
	       result.record.pc.module_basename[0] != '\0') ||
	          (result.record.pc.address_class == FaultAddressClass::Private &&
	           result.record.pc.module_basename[0] == '\0'),
	      "the saved PC has a validated image basename or explicit private classification");
	Check(std::memcmp(&result.record.emitter_pc, &result.record.pc,
	                  sizeof(result.record.pc)) == 0,
	      "the emitter and saved PC share an exact attribution");
	Check(HostFaultModuleNameIsBasename(result.record.pc.module_basename) &&
	          HostFaultModuleNameIsBasename(result.record.target.module_basename) &&
	          HostFaultModuleNameIsBasename(result.record.context_rcx.module_basename) &&
	          HostFaultModuleNameIsBasename(result.record.context_rdx.module_basename) &&
	          HostFaultModuleNameIsBasename(result.record.context_r13.module_basename) &&
	          HostFaultModuleNameIsBasename(result.record.context_r14.module_basename) &&
	          HostFaultModuleNameIsBasename(result.record.context_r15.module_basename) &&
	          HostFaultModuleNameIsBasename(result.record.original_stack_top.module_basename),
	      "the fixed record retains basenames rather than paths");
	for (uint32_t i = 0; i < result.record.original_frame_count; i++) {
          Check(HostFaultModuleNameIsBasename(
                    result.record.original_frames[i].module_basename),
                "fault-context frames contain basenames rather than paths");
        }
}

void CheckUnhandledHostExceptionDiagnostics(const std::filesystem::path &root) {
  using namespace Common::HostException;
  const std::string long_qualified_name =
      "iCzcQSfuX-E[DbgThreadSanitizer_for_agc_driver_v1]"
      "[DbgThreadSanitizer_v1.1][Func]";
  const auto exact_nid = Loader::SymbolDatabase::GetNid(long_qualified_name);
  Check(long_qualified_name.size() == 80 && exact_nid == "iCzcQSfuX-E" &&
            Loader::SymbolDatabase::GetNid("plain_nid") == "plain_nid" &&
            Loader::SymbolDatabase::GetNid("[malformed]").empty(),
        "qualified symbol provenance retains the exact bounded NID");
  Check(RegisterGuestCodeProvenance(
            {0x500000000ull, 0x30, 0x900000000ull, 0x140e8,
             FaultGuestCodeKind::UnresolvedImportThunk, "libSceAgcDriver.sprx",
             long_qualified_name.c_str()}) == 0,
        "an oversized qualified symbol cannot enter the fixed fault record");
  const auto exact_nid_token = RegisterGuestCodeProvenance(
      {0x500000000ull, 0x30, 0x900000000ull, 0x140e8,
       FaultGuestCodeKind::UnresolvedImportThunk, "libSceAgcDriver.sprx",
       exact_nid.c_str()});
  Check(exact_nid_token != 0,
        "the exact NID enters the bounded fault record without truncation");
  UnregisterGuestCodeProvenance(exact_nid_token);
  const auto directory = root / "host_exception_provenance";
  Check(std::filesystem::create_directory(directory),
        "create host-fault provenance fixture directory");
  const auto fixture = directory / "libkernel.sprx";
  WriteAudiodExtendedMmapElf(fixture);
  std::wstring executable_name(32768, L'\0');
  const auto length =
      GetModuleFileNameW(nullptr, executable_name.data(),
                         static_cast<DWORD>(executable_name.size()));
  Check(length > 0 && length < executable_name.size(),
        "locate host-fault fixture executable");
  executable_name.resize(length);
  const std::filesystem::path executable(executable_name);

  const auto read = RunHostFaultCase(executable, fixture, directory, "read");
  const auto write = RunHostFaultCase(executable, fixture, directory, "write");
  const auto execute =
      RunHostFaultCase(executable, fixture, directory, "execute");
  const auto execute_registered =
      RunHostFaultCase(executable, fixture, directory, "execute-registered");
  const auto execute_retired =
      RunHostFaultCase(executable, fixture, directory, "execute-retired");
  const auto route_registered =
      RunHostFaultCase(executable, fixture, directory, "route-registered");
  const auto route_retired =
      RunHostFaultCase(executable, fixture, directory, "route-retired");
  const auto route_unregistered =
      RunHostFaultCase(executable, fixture, directory, "route-unregistered");
  const auto route_nested =
      RunHostFaultCase(executable, fixture, directory, "route-nested");
  const auto route_post_action =
      RunHostFaultCase(executable, fixture, directory, "route-post-action");
  const auto route_unhandled =
      RunHostFaultCase(executable, fixture, directory, "route-unhandled");
  const auto strcmp_fault =
      RunHostFaultCase(executable, fixture, directory, "strcmp");
  const auto disabled =
      RunHostFaultCase(executable, fixture, directory, "disabled");
  const auto heap_lock =
      RunHostFaultCase(executable, fixture, directory, "heap-lock");
  const auto reentrant =
      RunHostFaultCase(executable, fixture, directory, "reentrant");
  for (const auto *result :
       {&read, &write, &execute, &execute_registered, &execute_retired,
        &strcmp_fault, &heap_lock, &reentrant}) {
    Check(result->exit_code == 321,
          "diagnostics preserve the original fatal outcome");
    CheckFaultRecordEnvelope(*result);
  }
  Check(
      disabled.exit_code == 321 && !disabled.record_present,
      "disabled diagnostics preserve the same fatal outcome without a record");
  for (const auto *result : {&route_registered, &route_retired,
                             &route_unregistered, &route_nested}) {
    Check(result->exit_code == 0 && !result->record_present,
          "host-stack routing handles and resumes only the intended fixture");
  }
  Check(route_post_action.exit_code == 47 && !route_post_action.record_present,
        "a queued terminal action runs only after returning to the original "
        "fiber");
  Check(route_unhandled.exit_code == 321 && route_unhandled.record_present &&
            route_unhandled.record.handler_route ==
                FaultHandlerRoute::HostFiberRegisteredGuestCode &&
            route_unhandled.record.pc.guest_code.available == 1 &&
            route_unhandled.record.pc.guest_code.lifecycle ==
                FaultGuestCodeLifecycle::Active,
        "an unhandled registered fault stays fatal after host-fiber routing");
  char executable_path[MAX_PATH]{};
  Check(GetModuleFileNameA(nullptr, executable_path, sizeof(executable_path)) >
            0,
        "resolve the fixture executable basename");
  const auto expected_basename =
      std::filesystem::path(executable_path).filename().string();
  const auto image_base = reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
  const auto read_rva =
      reinterpret_cast<uint64_t>(&HostFaultFixtureRead) - image_base;
  const auto read_caller_rva =
      reinterpret_cast<uint64_t>(&HostFaultFixtureReadCaller) - image_base;
  const auto strcmp_caller_rva =
      reinterpret_cast<uint64_t>(&HostFaultFixtureUcrtStrcmp) - image_base;
  const auto write_rva =
      reinterpret_cast<uint64_t>(&HostFaultFixtureWrite) - image_base;
  Check(std::string(read.record.pc.module_basename) == expected_basename &&
            read.record.pc.relative_offset >= read_rva &&
            read.record.pc.relative_offset < read_rva + 64 &&
            std::string(write.record.pc.module_basename) == expected_basename &&
            write.record.pc.relative_offset >= write_rva &&
            write.record.pc.relative_offset < write_rva + 64,
        "saved fault PCs identify the exact fixture executable and faulting "
        "functions");
  Check(read.record.original_stack_top_status ==
                FaultStackTopStatus::Classified &&
            read.record.original_stack_top.address_class ==
                FaultAddressClass::Image &&
            std::string(read.record.original_stack_top.module_basename) ==
                expected_basename &&
            read.record.original_stack_top.relative_offset >= read_caller_rva &&
            read.record.original_stack_top.relative_offset <
                read_caller_rva + 128,
        "the saved stack-top word identifies the direct leaf-fault caller");
  Check(read.record.platform_access_valid == 1 &&
            read.record.platform_access == 0 &&
            read.record.normalized_access == AccessViolationType::Read &&
            static_cast<uint32_t>(read.record.normalized_access) == 1 &&
            read.record.pc.address_class == FaultAddressClass::Image &&
            read.record.target.address_class ==
                FaultAddressClass::LowUnmapped &&
            read.record.target.relative_offset == 1,
        "Windows read operation zero remains distinct from Kyty read enum one");
  Check(
      write.record.platform_access_valid == 1 &&
          write.record.platform_access == 1 &&
          write.record.normalized_access == AccessViolationType::Write &&
          static_cast<uint32_t>(write.record.normalized_access) == 2,
      "Windows write operation one remains distinct from Kyty write enum two");
  auto *ucrt = GetModuleHandleW(L"ucrtbased.dll");
  auto *strcmp_address =
      ucrt == nullptr ? nullptr : GetProcAddress(ucrt, "strcmp");
  const auto strcmp_rva = reinterpret_cast<uint64_t>(strcmp_address) -
                          reinterpret_cast<uint64_t>(ucrt);
  const bool file_hash_nonzero =
      std::any_of(std::begin(strcmp_fault.record.emitter_file_identity.sha256),
                  std::end(strcmp_fault.record.emitter_file_identity.sha256),
                  [](uint8_t value) { return value != 0; });
  const bool probe_hash_nonzero = std::any_of(
      std::begin(strcmp_fault.record.emitter_file_identity.loaded_probe_sha256),
      std::end(strcmp_fault.record.emitter_file_identity.loaded_probe_sha256),
      [](uint8_t value) { return value != 0; });
  Check(
      ucrt != nullptr && strcmp_address != nullptr &&
          strcmp_fault.record.pc.address_class == FaultAddressClass::Image &&
          std::string(strcmp_fault.record.pc.module_basename) ==
              "ucrtbased.dll" &&
          strcmp_fault.record.pc.relative_offset == strcmp_rva + 8 &&
          strcmp_fault.record.target.address_class ==
              FaultAddressClass::LowUnmapped &&
          strcmp_fault.record.target.relative_offset == 1 &&
          strcmp_fault.record.context_rcx.address_class ==
              FaultAddressClass::LowUnmapped &&
          strcmp_fault.record.context_rcx.relative_offset == 1 &&
          strcmp_fault.record.pc.image_identity_valid == 1 &&
          strcmp_fault.record.pc.image_machine == IMAGE_FILE_MACHINE_AMD64 &&
          strcmp_fault.record.emitter_file_identity.available == 1 &&
          strcmp_fault.record.emitter_file_identity.sha256_valid == 1 &&
          strcmp_fault.record.emitter_file_identity.file_size > 0 &&
          file_hash_nonzero &&
          strcmp_fault.record.emitter_file_identity.loaded_probe_valid == 1 &&
          strcmp_fault.record.emitter_file_identity.loaded_probe_rva ==
              0x185200 &&
          strcmp_fault.record.emitter_file_identity.loaded_probe_size == 64 &&
          probe_hash_nonzero &&
          strcmp_fault.record.original_stack_top_status ==
              FaultStackTopStatus::Classified &&
          strcmp_fault.record.original_stack_top.address_class ==
              FaultAddressClass::Image &&
          std::string(strcmp_fault.record.original_stack_top.module_basename) ==
              expected_basename &&
          strcmp_fault.record.original_stack_top.relative_offset >=
              strcmp_caller_rva &&
          strcmp_fault.record.original_stack_top.relative_offset <
              strcmp_caller_rva + 192,
      "the UCRT strcmp fault pins exact loaded identity and its immediate "
      "caller");
  Check(reentrant.record.platform_access == 0 &&
            reentrant.record.normalized_access == AccessViolationType::Read,
        "a recursive capture cannot replace the original fault record");
  Check(execute.record.pc.address_class == FaultAddressClass::Private &&
            execute.record.pc.module_basename[0] == '\0' &&
            execute.record.pc.guest_code.available == 0,
        "a private executable fault is not attributed to an image");
  Check(
      execute_registered.record.pc.address_class ==
              FaultAddressClass::Private &&
          execute_registered.record.pc.module_basename[0] == '\0' &&
          execute_registered.record.pc.guest_code.available == 1 &&
          execute_registered.record.pc.guest_code.kind ==
              FaultGuestCodeKind::ProgramExecutable &&
          execute_registered.record.pc.guest_code.lifecycle ==
              FaultGuestCodeLifecycle::Active &&
          execute_registered.record.pc.guest_code.region_offset == 0 &&
          execute_registered.record.pc.guest_code.owner_offset == 0x1260 &&
          execute_registered.record.pc.guest_code.source_offset == 0x1260 &&
          execute_registered.record.pc.guest_code.region_size == 0x1000 &&
          std::string(execute_registered.record.pc.guest_code.owner_basename) ==
              "fixture_guest.elf" &&
          std::string(execute_registered.record.pc.guest_code.detail) ==
              "private_execute_fixture",
      "registered private executable code gains exact guest provenance without "
      "changing failure");
  Check(execute_retired.record.pc.address_class == FaultAddressClass::Private &&
            execute_retired.record.pc.guest_code.available == 0,
        "retired guest-code provenance cannot attribute a later fault");

  const auto direct =
      RunHostFaultCase(executable, fixture, directory, "direct");
  const auto unavailable =
      RunHostFaultCase(executable, fixture, directory, "unavailable");
  const auto missing_metadata =
      RunHostFaultCase(executable, fixture, directory, "missing-metadata");
  for (const auto *result : {&direct, &unavailable, &missing_metadata}) {
    Check(result->exit_code == 0, "injected capture child completes normally");
    CheckFaultRecordEnvelope(*result);
  }
  Check((direct.record.original_stack_status == FaultStackStatus::Complete ||
         direct.record.original_stack_status == FaultStackStatus::Partial) &&
            direct.record.original_frame_count == 2 &&
            direct.record.original_frames[0].address_class ==
                FaultAddressClass::Image &&
            direct.record.original_frames[1].address_class ==
                FaultAddressClass::Image &&
            direct.record.pc.relative_offset ==
                reinterpret_cast<uint64_t>(&HostFaultFixturePc) - image_base &&
            direct.record.original_frames[0].relative_offset ==
                reinterpret_cast<uint64_t>(&HostFaultFixtureFrameA) -
                    image_base &&
            direct.record.original_frames[1].relative_offset ==
                reinterpret_cast<uint64_t>(&HostFaultFixtureFrameB) -
                    image_base,
        "the bounded stack comes from the supplied original frame context");
  Check(unavailable.record.original_stack_status ==
                FaultStackStatus::Unavailable &&
            unavailable.record.original_frame_count == 0 &&
            unavailable.record.original_stack_top_status ==
                FaultStackTopStatus::Unavailable,
        "an unreadable original context is reported unavailable without "
        "fallback data");
  Check(missing_metadata.record.platform_access_valid == 0 &&
            missing_metadata.record.normalized_access ==
                AccessViolationType::Unknown &&
            missing_metadata.record.target.address_class ==
                FaultAddressClass::Unavailable,
        "missing Windows AV metadata remains unknown and unavailable");
}

#else

int RunUnhandledHostExceptionDiagnosticsChild(int, char**) { return -1; }
void CheckUnhandledHostExceptionDiagnostics(const std::filesystem::path&) {}

#endif

