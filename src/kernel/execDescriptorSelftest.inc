#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
struct GuestSocketFixtureTraceScope {
	bool previous = g_guest_socket_fixture_trace.exchange(true);
	~GuestSocketFixtureTraceScope() { g_guest_socket_fixture_trace.store(previous); }
};

struct ExecDescriptorFixture {
	static constexpr uint32_t signature = 0x46445845;
	static constexpr size_t   bytes     = 2 * SharedGuestPipe::capacity + 257;
	struct Control {
		uint32_t      magic;
		uint32_t      version;
		uint32_t      mode;
		uint32_t      child_pid;
		uint32_t      manifest_size;
		int32_t       error;
		volatile LONG timed_out;
		char          manifest[16384];
	};
	std::string name;
	HANDLE      mapping  = nullptr;
	HANDLE      imported = nullptr;
	HANDLE      start    = nullptr;
	HANDLE      finished = nullptr;
	HANDLE      process  = nullptr;
	HANDLE      job      = nullptr;
	Control*    control  = nullptr;

	~ExecDescriptorFixture() {
		if (control != nullptr) {
			UnmapViewOfFile(control);
		}
		for (HANDLE handle: {mapping, imported, start, finished, process, job}) {
			if (handle != nullptr) {
				CloseHandle(handle);
			}
		}
	}

	static uint8_t Pattern(size_t offset) {
		return static_cast<uint8_t>((offset * 131u + (offset >> 8) * 17u + 0x5du) & 0xffu);
	}

	static bool Readable(int fd) {
		if (fd < 0 || fd >= 1024) {
			return false;
		}
		std::array<uint64_t, 16> reads {};
		reads[fd / 64] = uint64_t {1} << (fd % 64);
		const int64_t timeout[2] {5, 0};
		return Posix::select(fd + 1, reads.data(), nullptr, nullptr, timeout) == 1 &&
		       (reads[fd / 64] & (uint64_t {1} << (fd % 64))) != 0;
	}

	static std::vector<wchar_t> Environment(const std::string& token) {
		auto* block = GetEnvironmentStringsW();
		if (block == nullptr) {
			return {};
		}
		std::vector<std::wstring> entries;
		for (const wchar_t* cursor = block; *cursor != 0; cursor += std::wcslen(cursor) + 1) {
			std::wstring entry(cursor);
			const auto   equals = entry.find(L'=', entry[0] == L'=' ? 1 : 0);
			const auto   key    = entry.substr(0, equals);
			if (key.find(L"SELFTEST") != std::wstring::npos ||
			    _wcsicmp(key.c_str(), L"KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE") == 0 ||
			    _wcsicmp(key.c_str(), L"KYTY_DIAGNOSTIC_IPMI_SHARED_SCOPE") == 0 ||
			    _wcsicmp(key.c_str(), L"KYTY_DIAGNOSTIC_GUEST_PID") == 0 ||
			    _wcsicmp(key.c_str(), L"KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY") == 0) {
				continue;
			}
			entries.push_back(std::move(entry));
		}
		FreeEnvironmentStringsW(block);
		uint64_t identity = 14695981039346656037ull;
		for (unsigned char character: token) {
			identity = (identity ^ character) * 1099511628211ull;
		}
		char scope[20] {};
		std::snprintf(scope, sizeof(scope), "fd%016llx", static_cast<unsigned long long>(identity));
		const std::wstring scope_name(scope, scope + std::strlen(scope));
		const uint32_t     guest_pid = 0x40000000u | static_cast<uint32_t>(identity & 0x3fffffffu);
		entries.push_back(L"KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE=" + scope_name);
		entries.push_back(L"KYTY_DIAGNOSTIC_IPMI_SHARED_SCOPE=" + scope_name);
		entries.push_back(L"KYTY_DIAGNOSTIC_GUEST_PID=" + std::to_wstring(guest_pid));
		entries.push_back(L"KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY=1");
		entries.push_back(L"KYTY_DIAGNOSTIC_GUEST_DESCRIPTOR_TABLE_SELFTEST=1");
		entries.push_back(L"KYTY_DIAGNOSTIC_GUEST_EXEC_CROSS_HOST_SELFTEST_CHILD=" +
		                  std::wstring(token.begin(), token.end()));
		std::sort(entries.begin(), entries.end(),
		          [](const auto& a, const auto& b) { return _wcsicmp(a.c_str(), b.c_str()) < 0; });
		std::vector<wchar_t> result;
		for (const auto& entry: entries) {
			result.insert(result.end(), entry.begin(), entry.end());
			result.push_back(0);
		}
		result.push_back(0);
		return result;
	}

	static std::wstring Quote(const std::wstring& argument) {
		std::wstring quoted  = L"\"";
		size_t       slashes = 0;
		for (wchar_t character: argument) {
			if (character == L'\\') {
				++slashes;
				continue;
			}
			quoted.append(slashes * (character == L'"' ? 2 : 1), L'\\');
			slashes = 0;
			if (character == L'"') {
				quoted += L'\\';
			}
			quoted += character;
		}
		quoted.append(slashes * 2, L'\\');
		quoted += L'"';
		return quoted;
	}
};

static void DiagnosticExecDescriptorFixtureChild() {
	const char* token = std::getenv("KYTY_DIAGNOSTIC_GUEST_EXEC_CROSS_HOST_SELFTEST_CHILD");
	if (token == nullptr) {
		return;
	}
	const GuestSocketFixtureTraceScope trace_scope;
	const std::string                  name(token);
	if (!name.starts_with("Local\\KytyExecFdFixture.") || name.size() > 160 ||
	    name.find_first_not_of(
	        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._\\") !=
	        std::string::npos) {
		std::_Exit(91);
	}
	ExecDescriptorFixture fixture;
	fixture.name     = name;
	fixture.mapping  = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, name.c_str());
	fixture.imported = OpenEventA(EVENT_MODIFY_STATE, FALSE, (name + ".imported").c_str());
	fixture.start    = OpenEventA(SYNCHRONIZE, FALSE, (name + ".start").c_str());
	if (!fixture.mapping || !fixture.imported || !fixture.start) {
		std::_Exit(92);
	}
	fixture.control = static_cast<ExecDescriptorFixture::Control*>(MapViewOfFile(
	    fixture.mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ExecDescriptorFixture::Control)));
	if (fixture.control == nullptr || fixture.control->magic != ExecDescriptorFixture::signature ||
	    fixture.control->version != 1 || fixture.control->mode > 1 ||
	    fixture.control->child_pid != GetCurrentProcessId() ||
	    fixture.control->manifest_size >= sizeof(fixture.control->manifest)) {
		std::_Exit(93);
	}
	const std::string manifest(fixture.control->manifest, fixture.control->manifest_size);
	const int         imported = ImportExecDescriptors(manifest);
	fixture.control->error     = imported;
	SetEvent(fixture.imported);
	if (imported != OK || WaitForSingleObject(fixture.start, 20000) != WAIT_OBJECT_0) {
		std::_Exit(94);
	}
	if (fixture.control->mode == 1) {
		std::_Exit(23);
	}
	std::array<uint8_t, 32768> buffer {};
	size_t                     offset = 0;
	while (offset < ExecDescriptorFixture::bytes) {
		const size_t requested = std::min(buffer.size(), ExecDescriptorFixture::bytes - offset);
		if (!ExecDescriptorFixture::Readable(3)) {
			std::_Exit(95);
		}
		const int64_t count = Posix::recv(3, buffer.data(), requested, 0);
		if (count <= 0 || static_cast<uint64_t>(count) > requested) {
			std::_Exit(95);
		}
		for (size_t index = 0; index < static_cast<size_t>(count); ++index) {
			if (buffer[index] != ExecDescriptorFixture::Pattern(offset + index)) {
				std::_Exit(96);
			}
		}
		if (Posix::send(3, buffer.data(), static_cast<size_t>(count), 0x20000) != count) {
			std::_Exit(97);
		}
		offset += static_cast<size_t>(count);
	}
	if (KernelClose(3) != OK) {
		std::_Exit(98);
	}
	std::_Exit(0);
}

static void DiagnosticExecDescriptorCrossHostCase(uint32_t mode) {
	ExecDescriptorFixture       fixture;
	static std::atomic_uint64_t sequence {0};
	fixture.name = std::string("Local\\KytyExecFdFixture.") +
	               std::to_string(GetCurrentProcessId()) + "." +
	               std::to_string(SharedGuestPipe::Created(GetCurrentProcess())) + "." +
	               std::to_string(sequence.fetch_add(1));
	int pair[2] {-1, -1};
	EXIT_IF(CreateGuestSocketPair(pair) != OK);
	FileDescriptors old_image(true);
	EXIT_IF(g_primary_files->CloneGuestSocketPairInto(&old_image, pair[1]) != 3);
	std::string manifest;
	EXIT_IF(old_image.Export(&manifest) != OK);
	EXIT_IF(KernelClose(pair[1]) != OK);
	EXIT_IF(manifest.size() >= sizeof(ExecDescriptorFixture::Control::manifest));
	fixture.mapping =
	    CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
		                   sizeof(ExecDescriptorFixture::Control), fixture.name.c_str());
	EXIT_IF(fixture.mapping == nullptr || GetLastError() == ERROR_ALREADY_EXISTS);
	fixture.control  = static_cast<ExecDescriptorFixture::Control*>(MapViewOfFile(
	    fixture.mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ExecDescriptorFixture::Control)));
	fixture.imported = CreateEventA(nullptr, TRUE, FALSE, (fixture.name + ".imported").c_str());
	fixture.start    = CreateEventA(nullptr, TRUE, FALSE, (fixture.name + ".start").c_str());
	fixture.finished = CreateEventA(nullptr, TRUE, FALSE, nullptr);
	fixture.job      = CreateJobObjectW(nullptr, nullptr);
	EXIT_IF(!fixture.control || !fixture.imported || !fixture.start || !fixture.finished ||
	        !fixture.job);
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
	limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	EXIT_IF(!SetInformationJobObject(fixture.job, JobObjectExtendedLimitInformation, &limits,
	                                 sizeof(limits)));
	std::memset(fixture.control, 0, sizeof(*fixture.control));
	fixture.control->magic         = ExecDescriptorFixture::signature;
	fixture.control->version       = 1;
	fixture.control->mode          = mode;
	fixture.control->manifest_size = static_cast<uint32_t>(manifest.size());
	std::memcpy(fixture.control->manifest, manifest.data(), manifest.size());
	std::vector<wchar_t> executable(32768);
	const DWORD          length =
	    GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
	EXIT_IF(length == 0 || length >= executable.size());
	auto log = std::filesystem::absolute(Config::GetPrintfOutputFile());
	log += ".fd-fixture-" + fixture.name.substr(6) + ".log";
	auto working_directory = log;
	working_directory += ".work";
	std::error_code directory_error;
	EXIT_IF(!std::filesystem::create_directory(working_directory, directory_error));
	std::wstring command = GetCommandLineW();
	command += L" --printf-direction File --printf-output-file " +
	           ExecDescriptorFixture::Quote(log.wstring());
	auto environment = ExecDescriptorFixture::Environment(fixture.name);
	EXIT_IF(environment.empty());
	STARTUPINFOW startup {};
	startup.cb = sizeof(startup);
	PROCESS_INFORMATION process {};
	EXIT_IF(!CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE,
	                        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, environment.data(),
	                        working_directory.c_str(), &startup, &process));
	fixture.process            = process.hProcess;
	fixture.control->child_pid = process.dwProcessId;
	if (!AssignProcessToJobObject(fixture.job, fixture.process)) {
		TerminateProcess(fixture.process, 99);
		CloseHandle(process.hThread);
		EXIT("descriptor fixture job assignment failed\n");
	}
	EXIT_IF(ResumeThread(process.hThread) == static_cast<DWORD>(-1));
	CloseHandle(process.hThread);
	std::thread          watchdog([&] {
		if (WaitForSingleObject(fixture.finished, 20000) != WAIT_OBJECT_0) {
			InterlockedExchange(&fixture.control->timed_out, 1);
			TerminateProcess(fixture.process, 0xe0fd0001u);
			if (WaitForSingleObject(fixture.finished, 1000) != WAIT_OBJECT_0) {
				std::_Exit(102);
			}
		}
	});
	HANDLE               waits[] {fixture.imported, fixture.process};
	const DWORD          attached = WaitForMultipleObjects(2, waits, FALSE, 20000);
	bool                 success  = attached == WAIT_OBJECT_0 && fixture.control->error == OK;
	int64_t              written  = -1;
	std::vector<uint8_t> payload;
	if (success) {
		old_image.CloseAll();
		SetEvent(fixture.start);
		if (mode == 0) {
			payload.resize(ExecDescriptorFixture::bytes);
			for (size_t index = 0; index < payload.size(); ++index) {
				payload[index] = ExecDescriptorFixture::Pattern(index);
			}
			std::thread writer(
			    [&] { written = Posix::send(pair[0], payload.data(), payload.size(), 0x20000); });
			std::array<uint8_t, 32768> reply {};
			size_t                     offset = 0;
			while (offset < payload.size()) {
				const size_t requested = std::min(reply.size(), payload.size() - offset);
				if (!ExecDescriptorFixture::Readable(pair[0])) {
					success = false;
					TerminateProcess(fixture.process, 100);
					break;
				}
				const int64_t count = Posix::recv(pair[0], reply.data(), requested, 0);
				if (count <= 0 || static_cast<uint64_t>(count) > requested ||
				    std::memcmp(reply.data(), payload.data() + offset,
				                static_cast<size_t>(count)) != 0) {
					success = false;
					TerminateProcess(fixture.process, 100);
					break;
				}
				offset += static_cast<size_t>(count);
			}
			writer.join();
			success = success && written == static_cast<int64_t>(payload.size());
		}
		success         = WaitForSingleObject(fixture.process, 20000) == WAIT_OBJECT_0 && success;
		DWORD exit_code = STILL_ACTIVE;
		success         = GetExitCodeProcess(fixture.process, &exit_code) &&
		                  exit_code == (mode == 0 ? 0u : 23u) && success;
	} else {
		TerminateProcess(fixture.process, 101);
		WaitForSingleObject(fixture.process, 5000);
	}
	SetEvent(fixture.finished);
	watchdog.join();
	success = success && InterlockedCompareExchange(&fixture.control->timed_out, 0, 0) == 0;
	EXIT_IF(!success);
	const auto* endpoint = g_primary_files->GetFile(pair[0]);
	EXIT_IF(endpoint == nullptr || !endpoint->pipe->shared || !endpoint->socket_send->shared);
	const auto receive = endpoint->pipe->shared;
	const auto send    = endpoint->socket_send->shared;
	EXIT_IF(!receive->Lock());
	const auto receive_owners = receive->Owners(true);
	ReleaseMutex(receive->mutex);
	EXIT_IF(receive_owners.first != 1 || receive_owners.second != 0);
	EXIT_IF(!send->Lock());
	const auto send_owners = send->Owners(true);
	ReleaseMutex(send->mutex);
	EXIT_IF(send_owners.first != 0 || send_owners.second != 1);
	char eof = 0;
	EXIT_IF(!ExecDescriptorFixture::Readable(pair[0]));
	EXIT_IF(Posix::recv(pair[0], &eof, 1, 0) != 0);
	EXIT_IF(Posix::send(pair[0], &eof, 1, 0x20000) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_EPIPE);
	EXIT_IF(KernelClose(pair[0]) != OK);
	LOGF("PS5_GUEST_EXEC_CROSS_HOST_DESCRIPTOR_SELFTEST_CASE PASS"
	     " mode=%u parent_host=%lu child_host=%lu bytes_each_way=%zu"
	     " imported_before_old_table_close=1 EOF_and_EPIPE=1 posix_send_recv_select=1"
	     " host_fixture_only=1\n",
	     mode, GetCurrentProcessId(), process.dwProcessId,
	     mode == 0 ? ExecDescriptorFixture::bytes : size_t {0});
}

static void DiagnosticVerifyGuestSocketPosix() {
	int pair[2] {-1, -1};
	EXIT_IF(CreateGuestSocketPair(pair) != OK);
	std::array<uint8_t, 36> payload {};
	for (size_t index = 0; index < payload.size(); ++index) {
		payload[index] = ExecDescriptorFixture::Pattern(index);
	}
	std::array<uint8_t, 36> reply {};
	const auto              source  = PinGuestSocketReadSource(pair[1]);
	int64_t                 pending = -1;
	bool                    eof     = true;
	EXIT_IF(Posix::send(pair[0], nullptr, 0, 0) != 0);
	EXIT_IF(Posix::recv(pair[1], nullptr, 0, 0) != 0);
	EXIT_IF(QueryGuestSocketReadSource(source, &pending, &eof) != OK || pending != 0 || eof);
	EXIT_IF(Posix::send(pair[0], nullptr, 1, 0) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_EFAULT);
	EXIT_IF(Posix::recv(pair[1], nullptr, 1, 0) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_EFAULT);
	EXIT_IF(Posix::send(pair[0], payload.data(), payload.size(), 1) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_EOPNOTSUPP);
	EXIT_IF(Posix::send(pair[0], payload.data(), payload.size(), 0x20000) != 36);
	EXIT_IF(QueryGuestSocketReadSource(source, &pending, &eof) != OK || pending != 36 || eof);
	EXIT_IF(Posix::recv(pair[1], reply.data(), reply.size(), 1) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_EOPNOTSUPP);
	EXIT_IF(QueryGuestSocketReadSource(source, &pending, &eof) != OK || pending != 36 || eof);
	EXIT_IF(Posix::send(pair[0], reinterpret_cast<const void*>(1), 1, 0) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_EFAULT);
	EXIT_IF(Posix::recv(pair[1], reinterpret_cast<void*>(1), 1, 0) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_EFAULT);
	SYSTEM_INFO system_info {};
	GetSystemInfo(&system_info);
	const auto page_size = static_cast<size_t>(system_info.dwPageSize);
	auto*      guarded   = static_cast<uint8_t*>(
	    VirtualAlloc(nullptr, 2 * page_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	EXIT_IF(guarded == nullptr);
	guarded[page_size - 1] = 0x55;
	DWORD previous         = 0;
	EXIT_IF(
	    !VirtualProtect(guarded + page_size, page_size, PAGE_READWRITE | PAGE_GUARD, &previous));
	EXIT_IF(Posix::send(pair[0], guarded + page_size - 1, 2, 0) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_EFAULT);
	EXIT_IF(Posix::recv(pair[1], guarded + page_size - 1, 2, 0) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_EFAULT);
	EXIT_IF(guarded[page_size - 1] != 0x55);
	EXIT_IF(!VirtualProtect(guarded, page_size, PAGE_READONLY, &previous));
	EXIT_IF(Posix::recv(pair[1], guarded, 1, 0) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_EFAULT);
	EXIT_IF(!VirtualFree(guarded, 0, MEM_RELEASE));
	EXIT_IF(QueryGuestSocketReadSource(source, &pending, &eof) != OK || pending != 36 || eof);
	EXIT_IF(Posix::recv(pair[1], reply.data(), 7, 0) != 7);
	EXIT_IF(QueryGuestSocketReadSource(source, &pending, &eof) != OK || pending != 29 || eof);
	EXIT_IF(Posix::recv(pair[1], reply.data() + 7, reply.size() - 7, 0) != 29);
	EXIT_IF(reply != payload);
	EXIT_IF(QueryGuestSocketReadSource(source, &pending, &eof) != OK || pending != 0 || eof);
	EXIT_IF(Posix::send(pair[1], payload.data(), payload.size(), 0) != 36);
	EXIT_IF(KernelRead(pair[0], reply.data(), reply.size()) != 36 || reply != payload);
	const int nonsocket = KernelOpen("/dev/random", 0, 0);
	EXIT_IF(nonsocket < 0);
	EXIT_IF(Posix::send(nonsocket, payload.data(), 1, 0) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_ENOTSOCK);
	EXIT_IF(Posix::recv(nonsocket, reply.data(), 1, 0) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_ENOTSOCK);
	EXIT_IF(KernelClose(nonsocket) != OK);
	EXIT_IF(Posix::send(-1, payload.data(), 1, 0) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_EBADF);
	EXIT_IF(Posix::recv(-1, reply.data(), 1, 0) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_EBADF);
	EXIT_IF(KernelClose(pair[1]) != OK);
	EXIT_IF(Posix::recv(pair[1], reply.data(), 1, 0) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_EBADF);
	EXIT_IF(Posix::recv(pair[0], reply.data(), 1, 0) != 0);
	EXIT_IF(Posix::send(pair[0], payload.data(), 1, 0x20000) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_EPIPE);
	EXIT_IF(KernelClose(pair[0]) != OK);
	LOGF("PS5_GUEST_SOCKET_POSIX_SELFTEST PASS host_fixture_only=1"
	     " partial_36_byte_stream=1 bidirectional=1 zero_length=1"
	     " readiness_tracks_bytes=1 unsupported_flags_preserve_queue=1"
	     " inaccessible_guard_readonly_buffers_preserve_queue=1"
	     " EBADF_ENOTSOCK_EFAULT_EPIPE=1\n");
}

static void DiagnosticVerifyGuestSocketSelect() {
	int pair[2] {-1, -1};
	EXIT_IF(CreateGuestSocketPair(pair) != OK);
	std::array<uint64_t, 16> reads {};
	const auto               watch = [&](int fd) { reads[fd / 64] |= uint64_t {1} << (fd % 64); };
	const auto ready = [&](int fd) { return (reads[fd / 64] & (uint64_t {1} << (fd % 64))) != 0; };
	const int64_t poll[2] {0, 0};
	const int64_t timeout[2] {0, 20'000};
	const int64_t second[2] {1, 0};
	watch(pair[1]);
	EXIT_IF(Posix::select(pair[1] + 1, reads.data(), nullptr, nullptr, poll) != 0 ||
	        ready(pair[1]));
	watch(pair[1]);
	const auto started = std::chrono::steady_clock::now();
	EXIT_IF(Posix::select(pair[1] + 1, reads.data(), nullptr, nullptr, timeout) != 0 ||
	        ready(pair[1]));
	EXIT_IF(std::chrono::steady_clock::now() - started < std::chrono::microseconds(20'000));
	watch(pair[1]);
	const int64_t invalid[2] {0, 1'000'000};
	EXIT_IF(Posix::select(pair[1] + 1, reads.data(), nullptr, nullptr, invalid) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_EINVAL);
	EXIT_IF(Posix::select(pair[1] + 1, nullptr, reads.data(), nullptr, poll) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_EOPNOTSUPP);
	EXIT_IF(Posix::select(pair[1] + 1, nullptr, nullptr, reads.data(), poll) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_EOPNOTSUPP);
	const uint8_t payload = 0x5d;
	int64_t       sent    = -1;
	std::thread   writer([&] {
		Common::Thread::SleepMicro(20'000);
		sent = Posix::send(pair[0], &payload, 1, 0x20000);
	});
	const int     selected = Posix::select(pair[1] + 1, reads.data(), nullptr, nullptr, second);
	writer.join();
	EXIT_IF(sent != 1 || selected != 1 || !ready(pair[1]));
	EXIT_IF(Posix::select(pair[1] + 1, reads.data(), nullptr, nullptr, poll) != 1 ||
	        !ready(pair[1]));
	int64_t pending = 0;
	bool    eof     = true;
	EXIT_IF(QueryGuestSocketReadSource(PinGuestSocketReadSource(pair[1]), &pending, &eof) != OK ||
	        pending != 1 || eof);
	uint8_t received = 0;
	EXIT_IF(Posix::recv(pair[1], &received, 1, 0) != 1 || received != payload);

	const int native_read  = Network::Net::Socket(2, 2, 0);
	const int native_write = Network::Net::Socket(2, 2, 0);
	EXIT_IF(native_read < 0 || native_write < 0 || native_read >= 1024);
	std::array<uint8_t, 16> address {16, 2, 0, 0, 127, 0, 0, 1};
	uint32_t                address_size = static_cast<uint32_t>(address.size());
	EXIT_IF(Network::Net::Bind(native_read, address.data(), address_size) != 0);
	EXIT_IF(Network::Net::Getsockname(native_read, address.data(), &address_size) != 0);
	EXIT_IF(Network::Net::Sendto(native_write, &payload, 1, 0, address.data(), address_size) != 1);
	EXIT_IF(!ExecDescriptorFixture::Readable(native_read));
	EXIT_IF(Posix::send(pair[0], &payload, 1, 0x20000) != 1);
	reads.fill(0);
	watch(pair[1]);
	watch(native_read);
	const int nfds = std::max(pair[1], native_read) + 1;
	EXIT_IF(Posix::select(nfds, reads.data(), nullptr, nullptr, poll) != 2 || !ready(pair[1]) ||
	        !ready(native_read));
	EXIT_IF(Posix::recv(pair[1], &received, 1, 0) != 1 || received != payload);
	EXIT_IF(Posix::select(nfds, reads.data(), nullptr, nullptr, poll) != 1 || ready(pair[1]) ||
	        !ready(native_read));
	EXIT_IF(Posix::recv(native_read, &received, 1, 0) != 1 || received != payload);
	EXIT_IF(Network::Net::SocketClose(native_read) != 0 ||
	        Network::Net::SocketClose(native_write) != 0);

	reads.fill(0);
	watch(pair[1]);
	int         closed = -1;
	std::thread closer([&] {
		Common::Thread::SleepMicro(20'000);
		closed = KernelClose(pair[0]);
	});
	const int   selected_eof = Posix::select(pair[1] + 1, reads.data(), nullptr, nullptr, nullptr);
	closer.join();
	EXIT_IF(closed != OK || selected_eof != 1 || !ready(pair[1]));
	EXIT_IF(Posix::recv(pair[1], &received, 1, 0) != 0);
	EXIT_IF(KernelClose(pair[1]) != OK);
	EXIT_IF(Posix::select(pair[1] + 1, reads.data(), nullptr, nullptr, poll) != -1 ||
	        *Posix::GetErrorAddr() != Posix::POSIX_EBADF);
	LOGF("PS5_GUEST_SOCKET_SELECT_SELFTEST PASS host_fixture_only=1"
	     " empty_poll_and_timeout=1 delayed_bytes=1 nonconsuming=1"
	     " mixed_native_guest=1 peer_EOF_infinite_wait=1 EBADF_EINVAL_EOPNOTSUPP=1"
	     " readiness_from_queue=1\n");
}

static void DiagnosticVerifyExecDescriptorCrossHost() {
	const char* enabled = std::getenv("KYTY_DIAGNOSTIC_GUEST_EXEC_CROSS_HOST_SELFTEST");
	if (enabled == nullptr || std::strcmp(enabled, "1") != 0) {
		return;
	}
	const GuestSocketFixtureTraceScope trace_scope;
	LOGF("PS5_GUEST_EXEC_CROSS_HOST_DESCRIPTOR_SELFTEST_BEGIN watchdog_ms=20000\n");
	DiagnosticVerifyGuestSocketPosix();
	DiagnosticVerifyGuestSocketSelect();
	DiagnosticExecDescriptorCrossHostCase(0);
	DiagnosticExecDescriptorCrossHostCase(1);
	LOGF("PS5_GUEST_EXEC_CROSS_HOST_DESCRIPTOR_SELFTEST PASS"
	     " cross_host_manifest_import=1 ring_wrap_and_backpressure=1"
	     " byte_exact_bidirectional_echo=1 abrupt_host_exit_pruned=1"
	     " host_fixture_only=1\n");
}
#endif
