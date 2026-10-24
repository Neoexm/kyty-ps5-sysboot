#include "kernel/process.h"

#include "common/assert.h"
#include "common/logging/log.h"
#include "kernel/budget.h"
#include "kernel/fileSystem.h"
#include "kernel/eventQueue.h"
#include "kernel/execProcess.h"
#include "kernel/memory.h"
#include "loader/elf.h"
#include "loader/systemContent.h"
#include "libs/errno.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fmt/format.h>
#include <fstream>
#include <limits>
#include <memory>
#include <optional>
#include <thread>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#pragma comment(lib, "advapi32.lib")
#else
#include <unistd.h>
#endif

namespace Libs::LibKernel::Process {

static std::filesystem::path RecordPath(const std::string& scope, const char* key, uint32_t id) {
	return std::filesystem::temp_directory_path() /
	       fmt::format("kyty_ps5_{}_{}_{}.txt", scope, key, id);
}

static std::filesystem::path AuthInfoRecordPath(const std::string& scope, uint32_t id) {
	return std::filesystem::temp_directory_path() /
	       fmt::format("kyty_ps5_{}_authinfo_{}.bin", scope, id);
}

static std::filesystem::path AuthObservationRecordPath(const std::string& scope, uint32_t id) {
	return std::filesystem::temp_directory_path() /
	       fmt::format("kyty_ps5_{}_authobs_{}.bin", scope, id);
}

static void SecureWipe(void* data, size_t size) {
#if defined(_WIN32)
	if (data != nullptr && size != 0) SecureZeroMemory(data, size);
#else
	auto* bytes = static_cast<volatile uint8_t*>(data);
	while (bytes != nullptr && size-- != 0)
		*bytes++ = 0;
#endif
}

static void SecureWipeCapture(AuthInfo::Capture* capture) {
	if (capture != nullptr) SecureWipe(capture, sizeof(*capture));
}

#if defined(_WIN32)
static std::mutex                               g_scoped_auth_info_mutex;
static std::unordered_map<std::wstring, HANDLE> g_scoped_auth_info_files;
static std::unordered_map<std::wstring, HANDLE> g_scoped_auth_observation_files;

static uint64_t ProcessCreationTime(HANDLE process) {
	FILETIME created {}, exited {}, kernel {}, user {};
	if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return 0;
	return (static_cast<uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
}

static uint64_t CurrentProcessCreationTime() {
	return ProcessCreationTime(GetCurrentProcess());
}

template <size_t Size>
static bool PublishScopedRecord(const std::filesystem::path&              path,
                                const std::array<uint8_t, Size>&          data,
                                std::unordered_map<std::wstring, HANDLE>* files) {
	if (files == nullptr) return false;
	std::lock_guard lock(g_scoped_auth_info_mutex);
	const auto      key = path.native();
	if (const auto found = files->find(key); found != files->end()) {
		CloseHandle(found->second);
		files->erase(found);
	}
	PSECURITY_DESCRIPTOR descriptor = nullptr;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;OW)", SDDL_REVISION_1,
	                                                          &descriptor, nullptr))
		return false;
	SECURITY_ATTRIBUTES security {};
	security.nLength              = sizeof(security);
	security.lpSecurityDescriptor = descriptor;
	security.bInheritHandle       = FALSE;
	HANDLE file                   = CreateFileW(
	    path.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ | FILE_SHARE_DELETE,
	    &security, CREATE_NEW,
	    FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
	LocalFree(descriptor);
	if (file == INVALID_HANDLE_VALUE) return false;
	struct CloseOnExit {
		HANDLE file;
		~CloseOnExit() {
			if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
		}
	} close {file};
	bool   result = true;
	size_t offset = 0;
	while (result && offset != data.size()) {
		const DWORD requested = static_cast<DWORD>(
		    std::min<size_t>(data.size() - offset, std::numeric_limits<DWORD>::max()));
		DWORD count = 0;
		result =
		    WriteFile(file, data.data() + offset, requested, &count, nullptr) && count == requested;
		offset += count;
	}
	if (result) result = FlushFileBuffers(file) != FALSE;
	LARGE_INTEGER expected {};
	expected.QuadPart = static_cast<LONGLONG>(data.size());
	LARGE_INTEGER actual {};
	if (result)
		result = GetFileSizeEx(file, &actual) != FALSE && actual.QuadPart == expected.QuadPart;
	LARGE_INTEGER beginning {};
	if (result) result = SetFilePointerEx(file, beginning, nullptr, FILE_BEGIN) != FALSE;
	std::array<uint8_t, Size> verify {};
	offset = 0;
	while (result && offset != data.size()) {
		const DWORD requested = static_cast<DWORD>(data.size() - offset);
		DWORD       count     = 0;
		result = ReadFile(file, verify.data() + offset, requested, &count, nullptr) &&
		         count == requested;
		offset += count;
	}
	if (result) result = verify == data;
	if (result) {
		DWORD   count = 1;
		uint8_t extra = 0;
		result        = ReadFile(file, &extra, 1, &count, nullptr) != FALSE && count == 0;
	}
	if (result) {
		LARGE_INTEGER stable {};
		result = GetFileSizeEx(file, &stable) != FALSE && stable.QuadPart == expected.QuadPart;
	}
	SecureWipe(verify.data(), verify.size());
	if (!result) return false;
	const bool inserted = files->emplace(key, file).second;
	if (!inserted) return false;
	close.file = INVALID_HANDLE_VALUE;
	return true;
}

static bool PublishScopedAuthInfo(const std::filesystem::path&                             path,
                                  const std::array<uint8_t, AuthInfo::kScopedCaptureSize>& data) {
	return PublishScopedRecord(path, data, &g_scoped_auth_info_files);
}

static bool
PublishScopedAuthObservation(const std::filesystem::path&                                 path,
                             const std::array<uint8_t, AuthInfo::kScopedObservationSize>& data) {
	return PublishScopedRecord(path, data, &g_scoped_auth_observation_files);
}

static void ReleaseOwnedScopedRecord(const std::filesystem::path&              path,
                                     std::unordered_map<std::wstring, HANDLE>* files) {
	if (files == nullptr) return;
	std::lock_guard lock(g_scoped_auth_info_mutex);
	const auto      found = files->find(path.native());
	if (found == files->end()) return;
	CloseHandle(found->second);
	files->erase(found);
}

static void ReleaseOwnedScopedAuthInfo(const std::filesystem::path& path) {
	ReleaseOwnedScopedRecord(path, &g_scoped_auth_info_files);
}

static void ReleaseOwnedScopedAuthObservation(const std::filesystem::path& path) {
	ReleaseOwnedScopedRecord(path, &g_scoped_auth_observation_files);
}

static void ReleaseAllOwnedScopedRecords(std::unordered_map<std::wstring, HANDLE>* files) {
	if (files == nullptr) return;
	std::lock_guard lock(g_scoped_auth_info_mutex);
	for (const auto& [path, file]: *files) {
		(void)path;
		CloseHandle(file);
	}
	files->clear();
}

static void ReleaseAllOwnedScopedAuthInfo() {
	ReleaseAllOwnedScopedRecords(&g_scoped_auth_info_files);
}

static void ReleaseAllOwnedScopedAuthObservations() {
	ReleaseAllOwnedScopedRecords(&g_scoped_auth_observation_files);
}
#else
static uint64_t CurrentProcessCreationTime() {
	return 0;
}

static bool PublishScopedAuthInfo(const std::filesystem::path&                             path,
                                  const std::array<uint8_t, AuthInfo::kScopedCaptureSize>& data) {
	(void)path;
	(void)data;
	return false;
}

static bool
PublishScopedAuthObservation(const std::filesystem::path&                                 path,
                             const std::array<uint8_t, AuthInfo::kScopedObservationSize>& data) {
	(void)path;
	(void)data;
	return false;
}

static void ReleaseOwnedScopedAuthInfo(const std::filesystem::path&) {}
static void ReleaseOwnedScopedAuthObservation(const std::filesystem::path&) {}
static void ReleaseAllOwnedScopedAuthInfo() {}
static void ReleaseAllOwnedScopedAuthObservations() {}
#endif

static bool ReadScopedAuthInfo(const std::filesystem::path& path, int guest_pid, uint32_t host_pid,
                               uint64_t authority_id, const AuthInfo::Digest& self_sha256,
                               const AuthInfo::Digest& elf_sha256,
                               const AuthInfo::Digest& envelope_sha256,
                               AuthInfo::Capture*      capture) {
	if (capture == nullptr) return false;
	SecureWipeCapture(capture);
	std::array<uint8_t, AuthInfo::kScopedCaptureSize> encoded {};
	bool                                              read = false;
#if defined(_WIN32)
	HANDLE file = CreateFileW(
	    path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
	    OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
	if (file != INVALID_HANDLE_VALUE) {
		FILE_ATTRIBUTE_TAG_INFO attributes {};
		LARGE_INTEGER           before {};
		read          = GetFileInformationByHandleEx(file, FileAttributeTagInfo, &attributes,
		                                             sizeof(attributes)) != FALSE &&
		                (attributes.FileAttributes &
		                 (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
		                GetFileSizeEx(file, &before) != FALSE &&
		                before.QuadPart == static_cast<LONGLONG>(encoded.size());
		size_t offset = 0;
		while (read && offset != encoded.size()) {
			const DWORD requested = static_cast<DWORD>(encoded.size() - offset);
			DWORD       count     = 0;
			read = ReadFile(file, encoded.data() + offset, requested, &count, nullptr) != FALSE &&
			       count == requested;
			offset += count;
		}
		LARGE_INTEGER after {};
		if (read) read = GetFileSizeEx(file, &after) != FALSE && after.QuadPart == before.QuadPart;
		CloseHandle(file);
	}
#else
	(void)path;
#endif
	AuthInfo::Capture decoded {};
	const bool        valid =
	    read &&
	    AuthInfo::DecodeScopedCapture(encoded.data(), encoded.size(), guest_pid, host_pid,
		                              authority_id, self_sha256, elf_sha256, &decoded, nullptr) &&
	    decoded.envelope_sha256 == envelope_sha256;
	if (valid) *capture = decoded;
	SecureWipeCapture(&decoded);
	SecureWipe(encoded.data(), encoded.size());
	return valid;
}

static bool ReadScopedAuthObservation(const std::filesystem::path& path, int guest_pid,
                                      uint32_t host_pid, uint64_t host_birth, uint64_t authority_id,
                                      const AuthInfo::Digest& self_sha256,
                                      const AuthInfo::Digest& elf_sha256,
                                      const AuthInfo::Digest& envelope_sha256,
                                      AuthInfo::Observation*  observation) {
	if (observation == nullptr) return false;
	*observation = {};
	std::array<uint8_t, AuthInfo::kScopedObservationSize> encoded {};
	bool                                                  read = false;
#if defined(_WIN32)
	HANDLE file = CreateFileW(
	    path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
	    OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
	if (file != INVALID_HANDLE_VALUE) {
		FILE_ATTRIBUTE_TAG_INFO attributes {};
		LARGE_INTEGER           before {};
		read          = GetFileInformationByHandleEx(file, FileAttributeTagInfo, &attributes,
		                                             sizeof(attributes)) != FALSE &&
		                (attributes.FileAttributes &
		                 (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
		                GetFileSizeEx(file, &before) != FALSE &&
		                before.QuadPart == static_cast<LONGLONG>(encoded.size());
		size_t offset = 0;
		while (read && offset != encoded.size()) {
			const DWORD requested = static_cast<DWORD>(encoded.size() - offset);
			DWORD       count     = 0;
			read = ReadFile(file, encoded.data() + offset, requested, &count, nullptr) != FALSE &&
			       count == requested;
			offset += count;
		}
		LARGE_INTEGER after {};
		if (read) read = GetFileSizeEx(file, &after) != FALSE && after.QuadPart == before.QuadPart;
		CloseHandle(file);
	}
#else
	(void)path;
#endif
	AuthInfo::Observation decoded {};
	const bool            valid =
	    read &&
	    AuthInfo::DecodeScopedObservation(encoded.data(), encoded.size(), guest_pid, host_pid,
		                                  host_birth, authority_id, self_sha256, elf_sha256,
		                                  envelope_sha256, &decoded, nullptr) &&
	    decoded.envelope_sha256 == envelope_sha256;
	if (valid) *observation = decoded;
	SecureWipe(&decoded, sizeof(decoded));
	SecureWipe(encoded.data(), encoded.size());
	return valid;
}

static bool HostProcessAlive(uint32_t host_pid) {
	if (host_pid == 0) {
		return false;
	}
#if defined(_WIN32)
	HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, host_pid);
	if (process == nullptr) {
		return GetLastError() != ERROR_INVALID_PARAMETER;
	}
	const DWORD status = WaitForSingleObject(process, 0);
	CloseHandle(process);
	return status != WAIT_OBJECT_0;
#else
	return true;
#endif
}

static bool ParseUint64Hex(std::string_view text, uint64_t* value) {
	if (value == nullptr || text.size() != 16) return false;
	const auto parsed = std::from_chars(text.data(), text.data() + text.size(), *value, 16);
	return parsed.ec == std::errc {} && parsed.ptr == text.data() + text.size();
}

#if defined(_WIN32)
static HANDLE OpenMatchingLiveProcess(uint32_t host_pid, uint64_t expected_birth) {
	if (host_pid == 0 || expected_birth == 0) return nullptr;
	HANDLE process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, host_pid);
	if (process == nullptr) return nullptr;
	if (WaitForSingleObject(process, 0) != WAIT_TIMEOUT ||
	    ProcessCreationTime(process) != expected_birth) {
		CloseHandle(process);
		return nullptr;
	}
	return process;
}
#endif

namespace {
thread_local int g_thread_guest_pid = 0;
std::mutex       g_auth_info_update_mutex;
std::mutex       g_auth_info_mutex;
using OriginalSelfIdentity = AuthInfo::ImageIdentity;
std::optional<OriginalSelfIdentity>  g_original_self_identity;
std::optional<AuthInfo::Capture>     g_auth_info;
std::optional<AuthInfo::Observation> g_authorization_observation;
#if defined(_WIN32)
struct ScopePidAllocator {
	struct State {
		uint64_t magic;
		uint64_t next_pid;
	};
	HANDLE mutex   = nullptr;
	HANDLE file    = INVALID_HANDLE_VALUE;
	HANDLE mapping = nullptr;
	State* state   = nullptr;
	~ScopePidAllocator() {
		if (state != nullptr) UnmapViewOfFile(state);
		if (mapping != nullptr) CloseHandle(mapping);
		if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
		if (mutex != nullptr) CloseHandle(mutex);
	}
};
std::mutex                                                          g_pid_allocator_mutex;
std::unordered_map<std::string, std::unique_ptr<ScopePidAllocator>> g_pid_allocators;

ScopePidAllocator* AttachScopePidAllocator(const std::string& scope) {
	if (const auto found = g_pid_allocators.find(scope); found != g_pid_allocators.end())
		return found->second.get();
	auto              allocator = std::make_unique<ScopePidAllocator>();
	const std::string name      = "Local\\kyty_ps5_" + scope + "_pid_allocator_v1";
	const auto        path =
	    std::filesystem::temp_directory_path() / ("kyty_ps5_" + scope + "_pids_v1.bin");
	allocator->mutex = CreateMutexA(nullptr, FALSE, (name + "_lock").c_str());
	if (allocator->mutex == nullptr) return nullptr;
	const DWORD waited = WaitForSingleObject(allocator->mutex, 30000);
	if (waited != WAIT_OBJECT_0 && waited != WAIT_ABANDONED) return nullptr;
	allocator->file =
	    CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	const bool created =
	    allocator->file != INVALID_HANDLE_VALUE && GetLastError() != ERROR_ALREADY_EXISTS;
	LARGE_INTEGER length {};
	bool valid = allocator->file != INVALID_HANDLE_VALUE && GetFileSizeEx(allocator->file, &length);
	if (valid && created) {
		length.QuadPart = sizeof(ScopePidAllocator::State);
		valid           = SetFilePointerEx(allocator->file, length, nullptr, FILE_BEGIN) &&
		                  SetEndOfFile(allocator->file);
	}
	if (valid && length.QuadPart == sizeof(ScopePidAllocator::State)) {
		allocator->mapping = CreateFileMappingA(allocator->file, nullptr, PAGE_READWRITE, 0,
		                                        sizeof(ScopePidAllocator::State), name.c_str());
		if (allocator->mapping != nullptr && created && GetLastError() == ERROR_ALREADY_EXISTS)
			valid = false;
		if (valid && allocator->mapping != nullptr) {
			allocator->state = static_cast<ScopePidAllocator::State*>(MapViewOfFile(
			    allocator->mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ScopePidAllocator::State)));
		}
	}
	if (created && allocator->state != nullptr) {
		allocator->state->next_pid = 1000;
		allocator->state->magic    = 0x315049445954594bULL;
		valid = FlushViewOfFile(allocator->state, sizeof(ScopePidAllocator::State)) &&
		        FlushFileBuffers(allocator->file);
	}
	ReleaseMutex(allocator->mutex);
	if (!valid || allocator->state == nullptr || allocator->state->magic != 0x315049445954594bULL)
		return nullptr;
	return g_pid_allocators.emplace(scope, std::move(allocator)).first->second.get();
}
#endif
} // namespace

ScopedGuestProcessPid::ScopedGuestProcessPid(int pid) {
	EXIT_IF(pid <= 0);
	previous_pid       = g_thread_guest_pid;
	g_thread_guest_pid = pid;
}

ScopedGuestProcessPid::~ScopedGuestProcessPid() {
	g_thread_guest_pid = previous_pid;
}

int AllocateRforkChildPid() {
	std::string scope;
	if (GetScope(&scope)) {
#if defined(_WIN32)
		std::lock_guard lock(g_pid_allocator_mutex);
		auto*           retained = AttachScopePidAllocator(scope);
		if (retained == nullptr) return KERNEL_ERROR_EIO;
		auto&       allocator = *retained;
		const DWORD waited    = WaitForSingleObject(allocator.mutex, 30000);
		if (waited != WAIT_OBJECT_0 && waited != WAIT_ABANDONED) return KERNEL_ERROR_EIO;
		int pid = KERNEL_ERROR_EIO;
		if (allocator.state->magic == 0x315049445954594bULL && allocator.state->next_pid >= 1000) {
			const uint64_t candidate =
			    std::max(allocator.state->next_pid, uint64_t(std::max(GetPid(), 0)) + 1);
			if (candidate > uint64_t(std::numeric_limits<int>::max())) {
				allocator.state->next_pid = uint64_t(std::numeric_limits<int>::max()) + 1;
				pid                       = KERNEL_ERROR_EAGAIN;
			} else {
				allocator.state->next_pid = candidate + 1;
				pid                       = static_cast<int>(candidate);
			}
			if (!FlushViewOfFile(allocator.state, sizeof(ScopePidAllocator::State)) ||
			    !FlushFileBuffers(allocator.file))
				pid = KERNEL_ERROR_EIO;
		}
		ReleaseMutex(allocator.mutex);
		return pid;
#else
		return KERNEL_ERROR_ENOSYS;
#endif
	}
	static std::atomic<uint64_t> next_pid {1000};
	uint64_t                     candidate = next_pid.load(std::memory_order_relaxed);
	while (candidate <= uint64_t(std::numeric_limits<int>::max())) {
		if (next_pid.compare_exchange_weak(candidate, candidate + 1, std::memory_order_relaxed)) {
			return static_cast<int>(candidate);
		}
	}
	return KERNEL_ERROR_EAGAIN;
}

namespace {
std::mutex              g_rfork_children_mutex;
std::condition_variable g_rfork_children_changed;
struct RforkChild {
	int         parent_pid      = 0;
	bool        reaped          = false;
	bool        has_exit_status = false;
	uint32_t    exit_status     = 0;
	bool        exec_committed  = false;
	bool        context_retired = false;
	uint32_t    host_pid        = 0;
	uint64_t    host_birth      = 0;
	std::string executable_path;
	std::string app_exec_alias;
	std::string app_exec_real;
};
std::unordered_map<int, RforkChild> g_rfork_children;
struct WaitEchildKey {
	int parent    = 0;
	int requested = 0;
	int options   = 0;

	bool operator==(const WaitEchildKey& other) const {
		return parent == other.parent && requested == other.requested && options == other.options;
	}
};
struct WaitEchildKeyHash {
	size_t operator()(const WaitEchildKey& key) const {
		size_t value = std::hash<int> {}(key.parent);
		value ^= std::hash<int> {}(key.requested) + 0x9e3779b9u + (value << 6u) + (value >> 2u);
		value ^= std::hash<int> {}(key.options) + 0x9e3779b9u + (value << 6u) + (value >> 2u);
		return value;
	}
};
std::unordered_set<WaitEchildKey, WaitEchildKeyHash> g_wait_echild_logged;
} // namespace

void RegisterRforkChild(int pid, int parent_pid) {
	if (pid <= 0 || parent_pid <= 0) {
		return;
	}
	std::lock_guard lock(g_rfork_children_mutex);
	const auto [child, inserted] = g_rfork_children.try_emplace(pid);
	if (inserted) {
		child->second.parent_pid = parent_pid;
		Budget::Fork(parent_pid, pid);
	}
}

void SetRforkChildAppExec(int pid, const std::string& alias, const std::string& real) {
	if (pid <= 0 || alias.empty() || real.empty()) {
		return;
	}
	std::lock_guard lock(g_rfork_children_mutex);
	const auto      child = g_rfork_children.find(pid);
	if (child == g_rfork_children.end()) {
		return;
	}
	child->second.app_exec_alias = alias;
	child->second.app_exec_real  = real;
}

bool ResolveAppExecPath(const std::string& path, std::string* out) {
	const int pid = GetPid();
	if (pid <= 0) {
		return false;
	}
	std::lock_guard lock(g_rfork_children_mutex);
	const auto      child = g_rfork_children.find(pid);
	if (child == g_rfork_children.end()) {
		return false;
	}
	const std::string& alias = child->second.app_exec_alias;
	const std::string& real  = child->second.app_exec_real;
	if (alias.empty() || real.empty()) {
		return false;
	}
	if (path == alias) {
		*out = real;
		return true;
	}
	const auto alias_slash = alias.find_last_of('/');
	const auto real_slash  = real.find_last_of('/');
	if (alias_slash == std::string::npos || real_slash == std::string::npos) {
		return false;
	}
	const auto alias_dir = alias.substr(0, alias_slash);
	if (path.size() > alias_dir.size() && path.compare(0, alias_dir.size(), alias_dir) == 0 &&
	    path[alias_dir.size()] == '/') {
		*out = real.substr(0, real_slash) + path.substr(alias_dir.size());
		return true;
	}
	return false;
}

bool IsTrackedRforkChild(int pid) {
	std::lock_guard lock(g_rfork_children_mutex);
	return g_rfork_children.find(pid) != g_rfork_children.end();
}

bool IsRforkChildThread() {
	if (g_thread_guest_pid == 0) return false;
	std::lock_guard lock(g_rfork_children_mutex);
	const auto      child = g_rfork_children.find(g_thread_guest_pid);
	return child != g_rfork_children.end() && !child->second.has_exit_status &&
	       !child->second.exec_committed;
}

bool MarkRforkChildExecCommitted(int pid, uint32_t host_pid, const std::string& path) {
	if (pid <= 0 || host_pid == 0 || path.empty()) {
		return false;
	}
	uint64_t host_birth = 0;
#if defined(_WIN32)
	// The caller still holds the host handle here, so this pid cannot have been reused yet.
	if (HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, host_pid)) {
		host_birth = ProcessCreationTime(process);
		CloseHandle(process);
	}
#endif
	std::lock_guard lock(g_rfork_children_mutex);
	const auto      child = g_rfork_children.find(pid);
	if (child == g_rfork_children.end() || child->second.has_exit_status ||
	    child->second.exec_committed) {
		return false;
	}
	child->second.executable_path = path;
	child->second.host_pid        = host_pid;
	child->second.host_birth      = host_birth;
	child->second.exec_committed  = true;
	LOGF("SYSCORE_GUEST_EXEC_IMAGE_COMMITTED guest_pid=%d host_pid=%u path=%s"
	     " old_context_retired=0\n",
	     pid, host_pid, path.c_str());
	return true;
}

bool IsRforkChildExecCommitted(int pid) {
	std::lock_guard lock(g_rfork_children_mutex);
	const auto      child = g_rfork_children.find(pid);
	return child != g_rfork_children.end() && child->second.exec_committed;
}

bool IsRforkChildContextRetired(int pid) {
	std::lock_guard lock(g_rfork_children_mutex);
	const auto      child = g_rfork_children.find(pid);
	return child != g_rfork_children.end() && child->second.context_retired;
}

void NotifyRforkChildContextRetired(int pid) {
	std::lock_guard lock(g_rfork_children_mutex);
	const auto      child = g_rfork_children.find(pid);
	if (child == g_rfork_children.end() || !child->second.exec_committed ||
	    child->second.context_retired) {
		return;
	}
	child->second.context_retired = true;
	ReleaseCommittedExecChild(pid);
	EventQueue::KernelNotifyNativeProcExecForAll(pid);
	if (child->second.has_exit_status) {
		EventQueue::KernelNotifyNativeProcExitForAll(pid, child->second.exit_status);
	}
	g_rfork_children_changed.notify_all();
	LOGF("SYSCORE_GUEST_EXEC_OLD_CONTEXT_RETIRED guest_pid=%d host_pid=%u"
	     " path=%s exec_event_emitted=1\n",
	     pid, child->second.host_pid, child->second.executable_path.c_str());
}

bool GetRforkChildExitStatus(int pid, uint32_t* status) {
	if (status == nullptr) {
		return false;
	}
	std::lock_guard lock(g_rfork_children_mutex);
	const auto      child = g_rfork_children.find(pid);
	if (child == g_rfork_children.end() || !child->second.has_exit_status ||
	    (child->second.exec_committed && !child->second.context_retired)) {
		return false;
	}
	*status = child->second.exit_status;
	return true;
}

int WaitForChild(int pid, uint32_t* status, int options, bool guest_status) {
	if (pid == 0 || pid < -1 || (options & ~1) != 0) return KERNEL_ERROR_ENOSYS;
	const int        parent = GetPid();
	std::unique_lock lock(g_rfork_children_mutex);
	for (;;) {
		bool     has_child      = false;
		uint32_t parent_total   = 0;
		uint32_t parent_reaped  = 0;
		uint32_t parent_exited  = 0;
		uint32_t request_total  = 0;
		uint32_t request_reaped = 0;
		uint32_t request_exited = 0;
		for (auto& [child_pid, child]: g_rfork_children) {
			if (child.parent_pid != parent) continue;
			++parent_total;
			if (child.reaped) ++parent_reaped;
			if (child.has_exit_status) ++parent_exited;
			if (pid != -1 && pid != child_pid) continue;
			++request_total;
			if (child.reaped) ++request_reaped;
			if (child.has_exit_status) ++request_exited;
			if (child.reaped) continue;
			has_child = true;
			if (!child.has_exit_status || (child.exec_committed && !child.context_retired))
				continue;
			if (status != nullptr) {
				if (guest_status) {
					if (!Memory::CopyToGuest(status, &child.exit_status, sizeof(*status)))
						return KERNEL_ERROR_EFAULT;
				} else {
					*status = child.exit_status;
				}
			}
			child.reaped = true;
			g_rfork_children_changed.notify_all();
			LOGF("GUEST_WAIT4_REAP parent_pid=%d guest_pid=%d wait_status=0x%08x recorded_exit=1\n",
			     parent, child_pid, child.exit_status);
			return child_pid;
		}
		if (!has_child) {
			if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_SIGPROCMASK_LOOP_TRACE") != nullptr &&
			    g_wait_echild_logged.size() < 128 &&
			    g_wait_echild_logged.insert({parent, pid, options}).second) {
				LOGF("GUEST_WAIT4_ECHILD parent_pid=%d requested_pid=%d options=0x%x"
				     " parent_total=%u parent_unreaped=%u parent_reaped=%u parent_exited=%u"
				     " request_total=%u request_unreaped=%u request_reaped=%u request_exited=%u"
				     " status_written=0\n",
				     parent, pid, options, parent_total, parent_total - parent_reaped,
				     parent_reaped, parent_exited, request_total, request_total - request_reaped,
				     request_reaped, request_exited);
			}
			return KERNEL_ERROR_ECHILD;
		}
		if ((options & 1) != 0) return 0;
		g_rfork_children_changed.wait(lock);
	}
}

bool ReleaseReapedRforkChild(int pid) {
	if (pid <= 0) return false;
	const int       parent = GetPid();
	std::lock_guard lock(g_rfork_children_mutex);
	const auto      child = g_rfork_children.find(pid);
	if (child == g_rfork_children.end() || child->second.parent_pid != parent ||
	    !child->second.reaped)
		return false;
	g_rfork_children.erase(child);
	return true;
}

void NotifyRforkChildExited(int pid, uint32_t exit_status) {
	if (pid <= 0) {
		return;
	}
	{
		std::lock_guard lock(g_rfork_children_mutex);
		auto&           child = g_rfork_children[pid];
		if (child.has_exit_status) {
			return;
		}
		child.has_exit_status = true;
		child.exit_status     = exit_status;
		Budget::Exit(pid);
		if (child.exec_committed && !child.context_retired) {
			return;
		}
	}
	EventQueue::KernelNotifyNativeProcExitForAll(pid, exit_status);
	g_rfork_children_changed.notify_all();
	LOGF("SYSCORE_GUEST_RFORK_CHILD_CONFIRMED_EXIT guest_pid=%d"
	     " guest_exit_status=0x%08x\n",
	     pid, exit_status);
}

int GetPid() {
	if (g_thread_guest_pid != 0) {
		return g_thread_guest_pid;
	}
	static const int pid = [] {
		const char* value = std::getenv("KYTY_DIAGNOSTIC_GUEST_PID");
		return value != nullptr ? std::atoi(value) : 100;
	}();
	return pid;
}

bool GetScope(std::string* scope) {
	const char* shared = std::getenv("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE");
	if ((std::getenv("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET") == nullptr &&
	     std::getenv("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY") == nullptr) ||
	    shared == nullptr || shared[0] == 0) {
		return false;
	}
	*scope = shared;
	return scope->size() <= 20 && std::all_of(scope->begin(), scope->end(), [](char ch) {
		       return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			          (ch >= '0' && ch <= '9') || ch == '_';
	       });
}

void InstallVerifiedOriginalSelf(const AuthInfo::ImageIdentity& identity) {
	std::lock_guard update(g_auth_info_update_mutex);
	bool            incompatible = false;
	{
		std::lock_guard lock(g_auth_info_mutex);
		incompatible =
		    (g_original_self_identity.has_value() &&
			 (g_original_self_identity->authority_id != identity.authority_id ||
			  g_original_self_identity->self_size != identity.self_size ||
			  g_original_self_identity->elf_size != identity.elf_size ||
			  g_original_self_identity->self_sha256 != identity.self_sha256 ||
			  g_original_self_identity->elf_sha256 != identity.elf_sha256)) ||
		    (g_auth_info.has_value() && (g_auth_info->authority_id != identity.authority_id ||
			                             g_auth_info->self_sha256 != identity.self_sha256 ||
			                             g_auth_info->elf_sha256 != identity.elf_sha256));
		if (incompatible) {
			if (g_auth_info.has_value()) SecureWipeCapture(&*g_auth_info);
			g_auth_info.reset();
			g_authorization_observation.reset();
			g_original_self_identity.reset();
		} else {
			g_original_self_identity = identity;
		}
	}
	if (incompatible) {
		ReleaseAllOwnedScopedAuthInfo();
		ReleaseAllOwnedScopedAuthObservations();
		std::lock_guard lock(g_auth_info_mutex);
		g_original_self_identity = identity;
	}
}

void ClearVerifiedOriginalSelf() {
	std::lock_guard update(g_auth_info_update_mutex);
	{
		std::lock_guard lock(g_auth_info_mutex);
		if (g_auth_info.has_value()) SecureWipeCapture(&*g_auth_info);
		g_auth_info.reset();
		g_original_self_identity.reset();
		g_authorization_observation.reset();
	}
	ReleaseAllOwnedScopedAuthInfo();
	ReleaseAllOwnedScopedAuthObservations();
}

bool InstallVerifiedAuthInfo(const AuthInfo::Capture& capture) {
	AuthInfo::Capture canonical;
	if (!AuthInfo::ParseCaptureEnvelope(
	        capture.envelope.data(), capture.envelope.size(), capture.envelope_sha256,
	        capture.self_sha256, capture.elf_sha256, capture.authority_id, &canonical, nullptr)) {
		SecureWipeCapture(&canonical);
		return false;
	}
	std::lock_guard update(g_auth_info_update_mutex);
	bool            replacing = false;
	{
		std::lock_guard lock(g_auth_info_mutex);
		if (!g_original_self_identity.has_value() ||
		    g_original_self_identity->authority_id != canonical.authority_id ||
		    g_original_self_identity->self_sha256 != canonical.self_sha256 ||
		    g_original_self_identity->elf_sha256 != canonical.elf_sha256) {
			SecureWipeCapture(&canonical);
			return false;
		}
		if (g_authorization_observation &&
		    ((AuthInfo::Capability0(canonical.record) ^
		      g_authorization_observation->facts.capability0) &
		     g_authorization_observation->facts.known_capability0) != 0) {
			SecureWipeCapture(&canonical);
			return false;
		}
		replacing = g_auth_info.has_value();
		if (replacing) {
			SecureWipeCapture(&*g_auth_info);
			g_auth_info.reset();
		}
	}
	if (replacing) ReleaseAllOwnedScopedAuthInfo();
	{
		std::lock_guard lock(g_auth_info_mutex);
		if (!g_original_self_identity.has_value() ||
		    g_original_self_identity->authority_id != canonical.authority_id ||
		    g_original_self_identity->self_sha256 != canonical.self_sha256 ||
		    g_original_self_identity->elf_sha256 != canonical.elf_sha256 ||
		    g_auth_info.has_value()) {
			SecureWipeCapture(&canonical);
			return false;
		}
		g_auth_info = canonical;
	}
	SecureWipeCapture(&canonical);
	return true;
}

void ClearVerifiedAuthInfo() {
	std::lock_guard update(g_auth_info_update_mutex);
	{
		std::lock_guard lock(g_auth_info_mutex);
		if (g_auth_info.has_value()) SecureWipeCapture(&*g_auth_info);
		g_auth_info.reset();
	}
	ReleaseAllOwnedScopedAuthInfo();
}

static bool GetVerifiedOriginalSelf(OriginalSelfIdentity* identity) {
	std::lock_guard lock(g_auth_info_mutex);
	if (!g_original_self_identity.has_value()) return false;
	*identity = *g_original_self_identity;
	return true;
}

bool GetVerifiedOriginalSelfIdentity(AuthInfo::ImageIdentity* identity) {
	if (identity == nullptr) return false;
	*identity = {};
	OriginalSelfIdentity stored;
	if (!GetVerifiedOriginalSelf(&stored)) return false;
	*identity = stored;
	return true;
}

// NON_AUTHENTIC cap-62 stand-in: the env lists authority ids to give bit 62, as MediaCore and
// SceVideoCore2K carry 0x40. Kept off the observation path.
static bool DiagnosticCapability62StandinMatches(uint64_t authority_id) {
	const char* value = std::getenv("KYTY_DIAGNOSTIC_IPMI_CAPABILITY62_STANDIN");
	if (value == nullptr || *value == '\0') return false;
	std::string_view rest(value);
	while (!rest.empty()) {
		const auto       sep   = rest.find_first_of(",; \t");
		std::string_view token = rest.substr(0, sep);
		rest = sep == std::string_view::npos ? std::string_view() : rest.substr(sep + 1);
		if (token.size() >= 2 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X'))
			token.remove_prefix(2);
		if (token.empty() || token.size() > 16) continue;
		uint64_t   parsed = 0;
		const auto r      = std::from_chars(token.data(), token.data() + token.size(), parsed, 16);
		if (r.ec == std::errc {} && r.ptr == token.data() + token.size() && parsed == authority_id)
			return true;
	}
	return false;
}

AuthInfo::AuthorizationFacts GetCurrentAuthorizationFacts() {
	std::lock_guard              lock(g_auth_info_mutex);
	AuthInfo::AuthorizationFacts facts;
	if (!g_original_self_identity.has_value()) return facts;
	facts.has_authority = true;
	facts.authority_id  = g_original_self_identity->authority_id;
	if (g_auth_info.has_value() &&
	    g_auth_info->authority_id == g_original_self_identity->authority_id &&
	    g_auth_info->self_sha256 == g_original_self_identity->self_sha256 &&
	    g_auth_info->elf_sha256 == g_original_self_identity->elf_sha256) {
		facts.capability0       = AuthInfo::Capability0(g_auth_info->record) & (1ull << 62);
		facts.known_capability0 = 1ull << 62;
	}
	if (g_authorization_observation) {
		const auto& observed = g_authorization_observation->facts;
		facts.capability0 =
		    (facts.capability0 & ~observed.known_capability0) | observed.capability0;
		facts.known_capability0 |= observed.known_capability0;
		facts.root_prison_known = observed.root_prison_known;
		facts.root_prison       = observed.root_prison;
	}
	if (!(facts.known_capability0 & (1ull << 62)) &&
	    DiagnosticCapability62StandinMatches(facts.authority_id)) {
		facts.capability0 |= 1ull << 62;
		facts.known_capability0 |= 1ull << 62;
		static std::once_flag logged;
		std::call_once(logged, [&] {
			LOGF("IPMI_CAPABILITY62_STANDIN authority=0x%016" PRIx64
			     " self_sha256=%s basis=sibling_measured_avcore provenance=NON_AUTHENTIC\n",
			     facts.authority_id,
			     AuthInfo::DigestHex(g_original_self_identity->self_sha256).c_str());
		});
	}
	return facts;
}

bool InstallVerifiedAuthorizationObservation(const AuthInfo::Observation& observation) {
	std::lock_guard       update(g_auth_info_update_mutex);
	AuthInfo::Observation canonical;
	bool                  replacing = false;
	{
		std::lock_guard lock(g_auth_info_mutex);
		if (!g_original_self_identity) return false;
		if (!AuthInfo::ParseObservation(observation.encoded.data(), observation.encoded.size(),
		                                observation.envelope_sha256, *g_original_self_identity,
		                                &canonical, nullptr))
			return false;
		if (g_auth_info &&
		    ((AuthInfo::Capability0(g_auth_info->record) ^ canonical.facts.capability0) &
		     canonical.facts.known_capability0) != 0)
			return false;
		if (g_authorization_observation &&
		    ((g_authorization_observation->facts.known_capability0 &
		      ~canonical.facts.known_capability0) != 0 ||
		     !std::equal(g_authorization_observation->encoded.begin() + 136,
		                 g_authorization_observation->encoded.begin() + 156,
		                 canonical.encoded.begin() + 136) ||
		     (g_authorization_observation->facts.root_prison_known &&
		      !canonical.facts.root_prison_known) ||
		     (g_authorization_observation->facts.root_prison_known &&
		      canonical.facts.root_prison_known &&
		      g_authorization_observation->facts.root_prison != canonical.facts.root_prison) ||
		     ((g_authorization_observation->facts.capability0 ^ canonical.facts.capability0) &
		      g_authorization_observation->facts.known_capability0 &
		      canonical.facts.known_capability0) != 0))
			return false;
		replacing                   = g_authorization_observation.has_value();
		g_authorization_observation = canonical;
	}
	if (replacing) ReleaseAllOwnedScopedAuthObservations();
	return true;
}

bool GetCurrentFilteredAuthInfo(AuthInfo::Record* record) {
	if (record == nullptr) return false;
	std::lock_guard lock(g_auth_info_mutex);
	if (!g_original_self_identity) return false;
	if (g_auth_info) {
		*record = AuthInfo::Filter(g_auth_info->record);
		return true;
	}
	return g_authorization_observation &&
	       AuthInfo::BuildFilteredRecord(g_authorization_observation->facts, record);
}

static bool GetVerifiedAuthInfo(AuthInfo::Capture* capture) {
	if (capture == nullptr) return false;
	SecureWipeCapture(capture);
	std::lock_guard lock(g_auth_info_mutex);
	if (!g_original_self_identity.has_value() || !g_auth_info.has_value() ||
	    g_original_self_identity->authority_id != g_auth_info->authority_id ||
	    g_original_self_identity->self_sha256 != g_auth_info->self_sha256 ||
	    g_original_self_identity->elf_sha256 != g_auth_info->elf_sha256)
		return false;
	*capture = *g_auth_info;
	return true;
}

static bool GetVerifiedAuthorizationObservationForImage(const AuthInfo::ImageIdentity& identity,
                                                        AuthInfo::Observation* observation) {
	if (observation == nullptr) return false;
	*observation = {};
	std::lock_guard lock(g_auth_info_mutex);
	if (!g_original_self_identity || !g_authorization_observation ||
	    identity.authority_id != g_original_self_identity->authority_id ||
	    identity.self_size != g_original_self_identity->self_size ||
	    identity.elf_size != g_original_self_identity->elf_size ||
	    identity.self_sha256 != g_original_self_identity->self_sha256 ||
	    identity.elf_sha256 != g_original_self_identity->elf_sha256 ||
	    g_authorization_observation->image.authority_id != identity.authority_id ||
	    g_authorization_observation->image.self_size != identity.self_size ||
	    g_authorization_observation->image.elf_size != identity.elf_size ||
	    g_authorization_observation->image.self_sha256 != identity.self_sha256 ||
	    g_authorization_observation->image.elf_sha256 != identity.elf_sha256)
		return false;
	*observation = *g_authorization_observation;
	return true;
}

bool GetVerifiedAuthInfoForImage(const AuthInfo::ImageIdentity& identity,
                                 AuthInfo::Capture*             capture) {
	if (capture == nullptr) return false;
	SecureWipeCapture(capture);
	std::lock_guard lock(g_auth_info_mutex);
	if (!g_original_self_identity.has_value() || !g_auth_info.has_value() ||
	    identity.authority_id != g_original_self_identity->authority_id ||
	    identity.self_size != g_original_self_identity->self_size ||
	    identity.elf_size != g_original_self_identity->elf_size ||
	    identity.self_sha256 != g_original_self_identity->self_sha256 ||
	    identity.elf_sha256 != g_original_self_identity->elf_sha256 ||
	    identity.authority_id != g_auth_info->authority_id ||
	    identity.self_sha256 != g_auth_info->self_sha256 ||
	    identity.elf_sha256 != g_auth_info->elf_sha256)
		return false;
	*capture = *g_auth_info;
	return true;
}

static uint64_t GetAuthorityId() {
	OriginalSelfIdentity identity;
	if (GetVerifiedOriginalSelf(&identity)) return identity.authority_id;
	static const uint64_t id = [] {
		const char* original = std::getenv("KYTY_DIAGNOSTIC_ORIGINAL_SELF");
		if (original == nullptr) {
			return uint64_t {0};
		}
		std::ifstream      self(original, std::ios::binary);
		Loader::SelfHeader header {};
		Loader::Elf64_Ehdr elf {};
		uint64_t           authority_id = 0;
		self.read(reinterpret_cast<char*>(&header), sizeof(header));
		const uint64_t elf_pos = sizeof(header) + header.segments_num * sizeof(Loader::SelfSegment);
		self.seekg(static_cast<std::streamoff>(elf_pos));
		self.read(reinterpret_cast<char*>(&elf), sizeof(elf));
		// The extended info sits on the 16-byte boundary after the program headers and starts with
		// the id.
		self.seekg(static_cast<std::streamoff>(
		    (elf_pos + elf.e_phoff + elf.e_phnum * sizeof(Loader::Elf64_Phdr) + 15) &
		    ~uint64_t {15}));
		self.read(reinterpret_cast<char*>(&authority_id), sizeof(authority_id));
		EXIT_IF(!self || std::memcmp(elf.e_ident, "\177ELF", 4) != 0);
		return authority_id;
	}();
	return id;
}

// peers are separate host processes, so per-pid kernel state goes to files they can read
void PublishToScope() {
	if (std::getenv("KYTY_DIAGNOSTIC_GUEST_WAIT_SELFTEST") != nullptr) {
		constexpr int fixture = 0x70000000;
		const int     parent  = GetPid();
		LOGF("PS5_GUEST_WAIT_SELFTEST_BEGIN\n");
		{
			std::lock_guard lock(g_rfork_children_mutex);
			for (int i = 0; i != 5; ++i)
				EXIT_IF(g_rfork_children.contains(fixture + i));
		}
		RegisterRforkChild(fixture, parent);
		RegisterRforkChild(fixture + 1, parent);
		uint32_t status = 0x12345678;
		EXIT_IF(WaitForChild(fixture, &status, 1) != 0 || status != 0x12345678);
		EXIT_IF(WaitForChild(fixture, &status, 2) != KERNEL_ERROR_ENOSYS);
		{
			ScopedGuestProcessPid foreign(parent + 1);
			EXIT_IF(WaitForChild(fixture, &status, 1) != KERNEL_ERROR_ECHILD);
		}
		std::atomic<bool> waiting {false};
		std::atomic<bool> done {false};
		int               waited = 0;
		std::thread       waiter([&] {
			ScopedGuestProcessPid owner(parent);
			waiting = true;
			waited  = WaitForChild(fixture, &status, 0);
			done    = true;
		});
		while (!waiting.load())
			std::this_thread::yield();
		std::this_thread::sleep_for(std::chrono::milliseconds(20));
		EXIT_IF(done.load());
		NotifyRforkChildExited(fixture, 0x2a00);
		waiter.join();
		EXIT_IF(waited != fixture || status != 0x2a00);
		EXIT_IF(WaitForChild(fixture, &status, 1) != KERNEL_ERROR_ECHILD);
		uint32_t recorded = 0;
		EXIT_IF(!GetRforkChildExitStatus(fixture, &recorded) || recorded != 0x2a00);
		NotifyRforkChildExited(fixture + 1, 0x3300);
		int         results[2] {};
		std::thread first([&] {
			ScopedGuestProcessPid owner(parent);
			results[0] = WaitForChild(fixture + 1, nullptr, 0);
		});
		std::thread second([&] {
			ScopedGuestProcessPid owner(parent);
			results[1] = WaitForChild(fixture + 1, nullptr, 0);
		});
		first.join();
		second.join();
		EXIT_IF(!((results[0] == fixture + 1 && results[1] == KERNEL_ERROR_ECHILD) ||
		          (results[1] == fixture + 1 && results[0] == KERNEL_ERROR_ECHILD)));
		const int   nested_parent = parent + 11;
		std::thread child_first([&] { RegisterRforkChild(fixture + 2, nested_parent); });
		child_first.join();
		RegisterRforkChild(fixture + 2, nested_parent);
		NotifyRforkChildExited(fixture + 2, 0x4400);
		EXIT_IF(WaitForChild(fixture + 2, &status, 1) != KERNEL_ERROR_ECHILD);
		{
			ScopedGuestProcessPid nested(nested_parent);
			EXIT_IF(WaitForChild(fixture + 2, &status, 0) != fixture + 2 || status != 0x4400);
		}
		void*            mapped_status = nullptr;
		constexpr size_t page_size     = 0x4000;
		EXIT_IF(Memory::KernelMapNamedFlexibleMemory(&mapped_status, page_size, 3, 0,
		                                             "wait4-fixture") != OK);
		EXIT_IF(Memory::CanWriteGuest(reinterpret_cast<void*>(UINT64_MAX - 1), sizeof(status)));
		EXIT_IF(Memory::CanWriteGuest(nullptr, sizeof(status)));
		for (int i = 3; i != 5; ++i) {
			RegisterRforkChild(fixture + i, parent);
			std::atomic<bool> validated {false};
			int               copy_result = 0;
			std::thread       copy_waiter([&] {
				ScopedGuestProcessPid owner(parent);
				EXIT_IF(!Memory::CanWriteGuest(mapped_status, sizeof(status)));
				validated = true;
				copy_result =
				    WaitForChild(fixture + i, static_cast<uint32_t*>(mapped_status), 0, true);
			});
			while (!validated.load())
				std::this_thread::yield();
			if (i == 3) {
				EXIT_IF(Memory::KernelMprotect(mapped_status, page_size, 1) != OK);
			} else {
				EXIT_IF(Memory::KernelMunmap(reinterpret_cast<uint64_t>(mapped_status),
				                             page_size) != OK);
			}
			EXIT_IF(Memory::CanWriteGuest(mapped_status, sizeof(status)));
			NotifyRforkChildExited(fixture + i, 0x5500 + static_cast<uint32_t>(i << 8));
			copy_waiter.join();
			EXIT_IF(copy_result != KERNEL_ERROR_EFAULT);
			EXIT_IF(!GetRforkChildExitStatus(fixture + i, &recorded) ||
			        recorded != 0x5500 + static_cast<uint32_t>(i << 8));
			if (i == 3) {
				EXIT_IF(Memory::KernelMprotect(mapped_status, page_size, 3) != OK);
				EXIT_IF(WaitForChild(fixture + i, static_cast<uint32_t*>(mapped_status), 0, true) !=
				        fixture + i);
				EXIT_IF(*static_cast<uint32_t*>(mapped_status) != recorded);
			} else {
				EXIT_IF(WaitForChild(fixture + i, &status, 0) != fixture + i || status != recorded);
			}
			EXIT_IF(WaitForChild(fixture + i, nullptr, 1) != KERNEL_ERROR_ECHILD);
		}
		{
			std::lock_guard lock(g_rfork_children_mutex);
			for (int i = 0; i != 5; ++i)
				g_rfork_children.erase(fixture + i);
		}
		LOGF("PS5_GUEST_WAIT_SELFTEST PASS blocking_exit=1 nohang_unchanged=1 owner_isolation=1"
		     " single_reap=1 monitor_status_retained=1 unsupported_options=1 nested_child_first=1"
		     " protected_copyout=1 unmapped_copyout=1 failed_copyout_retains_child=1\n");
	}
	if (std::getenv("KYTY_DIAGNOSTIC_GUEST_PROCESS_PID_SELFTEST") != nullptr) {
		const int primary         = GetPid();
		int       sibling_default = 0;
		int       sibling_bound   = 0;
		{
			ScopedGuestProcessPid outer(primary + 11);
			EXIT_IF(GetPid() != primary + 11);
			{
				ScopedGuestProcessPid inner(primary + 12);
				EXIT_IF(GetPid() != primary + 12);
			}
			EXIT_IF(GetPid() != primary + 11);
			std::thread sibling([&] {
				sibling_default = GetPid();
				{
					ScopedGuestProcessPid child(primary + 13);
					sibling_bound = GetPid();
				}
				EXIT_IF(GetPid() != primary);
			});
			sibling.join();
			EXIT_IF(GetPid() != primary + 11);
		}
		EXIT_IF(GetPid() != primary);
		EXIT_IF(sibling_default != primary || sibling_bound != primary + 13);
		LOGF("PS5_GUEST_PROCESS_PID_THREAD_ISOLATION_SELFTEST"
		     " base=%d nested_restore=1 separate_host_thread=1\n",
		     primary);
	}
	if (std::getenv("KYTY_DIAGNOSTIC_GUEST_DESCRIPTOR_TABLE_SELFTEST") != nullptr) {
		Libs::LibKernel::FileSystem::DiagnosticVerifyGuestDescriptorIsolation();
	}
	std::string scope;
	if (!GetScope(&scope)) {
		return;
	}
#if defined(_WIN32)
	{
		std::lock_guard lock(g_pid_allocator_mutex);
		if (AttachScopePidAllocator(scope) == nullptr) {
			LOGF("PROCESS_SCOPE_PID_ALLOCATOR_UNAVAILABLE scope=%s\n", scope.c_str());
			return;
		}
	}
#endif
#if defined(_WIN32)
	const uint32_t host_pid = GetCurrentProcessId();
#else
	const auto host_pid = static_cast<uint32_t>(getpid());
#endif
	const int      guest_pid      = GetPid();
	const uint64_t host_birth     = CurrentProcessCreationTime();
	const auto     auth_info_path = AuthInfoRecordPath(scope, static_cast<uint32_t>(guest_pid));
	const auto     auth_observation_path =
	    AuthObservationRecordPath(scope, static_cast<uint32_t>(guest_pid));
	std::lock_guard         auth_info_update(g_auth_info_update_mutex);
	OriginalSelfIdentity    identity;
	const bool              has_identity = GetVerifiedOriginalSelf(&identity);
	AuthInfo::Capture       capture {};
	AuthInfo::Observation   observation {};
	AuthInfo::ImageIdentity image_identity {};
	if (has_identity) {
		image_identity = identity;
	}
	const bool has_auth_info =
	    has_identity && GetVerifiedAuthInfoForImage(image_identity, &capture);
	const bool has_auth_observation =
	    has_identity && GetVerifiedAuthorizationObservationForImage(image_identity, &observation);
	bool auth_info_published        = false;
	bool auth_observation_published = false;
#if defined(_WIN32)
	const bool can_publish_auth_info = host_birth != 0;
#else
	const bool can_publish_auth_info = false;
#endif
	if (has_auth_info && can_publish_auth_info) {
		std::array<uint8_t, AuthInfo::kScopedCaptureSize> encoded {};
		struct WipeEncodedOnExit {
			std::array<uint8_t, AuthInfo::kScopedCaptureSize>* encoded;
			~WipeEncodedOnExit() { SecureWipe(encoded->data(), encoded->size()); }
		} wipe_encoded {&encoded};
		auth_info_published =
		    AuthInfo::EncodeScopedCapture(capture, guest_pid, host_pid, &encoded) &&
		    PublishScopedAuthInfo(auth_info_path, encoded);
		SecureWipe(encoded.data(), encoded.size());
		if (auth_info_published) {
			const auto envelope = AuthInfo::DigestHex(capture.envelope_sha256);
			const auto self     = AuthInfo::DigestHex(identity.self_sha256);
			const auto elf      = AuthInfo::DigestHex(identity.elf_sha256);
			LOGF("AUTHINFO_SCOPE_PUBLISH provenance=captured envelope_sha256=%s self_sha256=%s "
			     "elf_sha256=%s status=verified\n",
			     envelope.c_str(), self.c_str(), elf.c_str());
		} else {
			LOGF("AUTHINFO_SCOPE_PUBLISH provenance=captured status=write_failed\n");
		}
	}
	if (has_auth_observation && can_publish_auth_info) {
		std::array<uint8_t, AuthInfo::kScopedObservationSize> encoded {};
		struct WipeEncodedOnExit {
			std::array<uint8_t, AuthInfo::kScopedObservationSize>* encoded;
			~WipeEncodedOnExit() { SecureWipe(encoded->data(), encoded->size()); }
		} wipe_encoded {&encoded};
		auth_observation_published = AuthInfo::EncodeScopedObservation(
		                                 observation, guest_pid, host_pid, host_birth, &encoded) &&
		                             PublishScopedAuthObservation(auth_observation_path, encoded);
		SecureWipe(encoded.data(), encoded.size());
		if (auth_observation_published) {
			const auto envelope = AuthInfo::DigestHex(observation.envelope_sha256);
			const auto self     = AuthInfo::DigestHex(identity.self_sha256);
			const auto elf      = AuthInfo::DigestHex(identity.elf_sha256);
			LOGF("AUTHORIZATION_OBSERVATION_SCOPE_PUBLISH provenance=observed envelope_sha256=%s "
			     "self_sha256=%s elf_sha256=%s status=verified\n",
			     envelope.c_str(), self.c_str(), elf.c_str());
		} else {
			LOGF("AUTHORIZATION_OBSERVATION_SCOPE_PUBLISH provenance=observed "
			     "status=write_failed\n");
		}
	}
	int32_t    category = 0;
	const bool has_category =
	    Loader::SystemContentParamSfoGetInt("APPLICATION_CATEGORY_TYPE", &category);
	std::ofstream  record(RecordPath(scope, "pid", static_cast<uint32_t>(GetPid())),
	                      std::ios::trunc);
	const uint64_t authority_id = has_identity ? identity.authority_id : GetAuthorityId();
	record << host_pid << ' ' << authority_id;
	if (has_category) record << ' ' << category;
	record << " birth=" << fmt::format("{:016x}", host_birth);
	if (has_identity) {
		record << " self=" << AuthInfo::DigestHex(identity.self_sha256)
		       << " elf=" << AuthInfo::DigestHex(identity.elf_sha256);
	}
	if (auth_info_published) {
		record << " authinfo=" << AuthInfo::DigestHex(capture.envelope_sha256);
	}
	if (auth_observation_published) {
		record << " authobs=" << AuthInfo::DigestHex(observation.envelope_sha256);
	}
	record << '\n';
	record.close();
	if (!record) {
		if (auth_info_published) ReleaseOwnedScopedAuthInfo(auth_info_path);
		if (auth_observation_published) ReleaseOwnedScopedAuthObservation(auth_observation_path);
		SecureWipeCapture(&capture);
		SecureWipe(&observation, sizeof(observation));
		return;
	}
	std::ofstream(RecordPath(scope, "host", host_pid), std::ios::trunc) << GetPid() << '\n';
	LOGF("process record: scope = %s, host pid = %u, pid = %d, authority id = 0x%016" PRIx64
	     ", category = 0x%x\n",
	     scope.c_str(), host_pid, GetPid(), authority_id, category);
	SecureWipeCapture(&capture);
	SecureWipe(&observation, sizeof(observation));
}

bool FindPeerByPid(int pid, PeerProcess* peer) {
	if (peer == nullptr) return false;
	*peer     = {};
	peer->pid = pid;
	if (pid == GetPid()) {
#if defined(_WIN32)
		peer->host_pid = GetCurrentProcessId();
#else
		peer->host_pid = static_cast<uint32_t>(getpid());
#endif
		peer->host_birth = CurrentProcessCreationTime();
		peer->auth_id    = GetAuthorityId();
		peer->has_category =
		    Loader::SystemContentParamSfoGetInt("APPLICATION_CATEGORY_TYPE", &peer->category);
		AuthInfo::Capture capture;
		if (GetVerifiedAuthInfo(&capture) && capture.authority_id == peer->auth_id) {
			peer->has_auth_info = true;
			peer->auth_info     = capture.record;
		}
		SecureWipeCapture(&capture);
		peer->has_filtered_auth_info = GetCurrentFilteredAuthInfo(&peer->filtered_auth_info);
		return true;
	}
	std::string scope;
	if (pid < 0 || !GetScope(&scope)) {
		return false;
	}
	std::ifstream record(RecordPath(scope, "pid", static_cast<uint32_t>(pid)));
	if (!(record >> peer->host_pid >> peer->auth_id)) {
		return false;
	}
	AuthInfo::Digest self_sha256 {};
	AuthInfo::Digest elf_sha256 {};
	AuthInfo::Digest auth_info_sha256 {};
	AuthInfo::Digest auth_observation_sha256 {};
	uint64_t         host_birth               = 0;
	uint32_t         self_markers             = 0;
	uint32_t         elf_markers              = 0;
	uint32_t         birth_markers            = 0;
	uint32_t         auth_info_markers        = 0;
	uint32_t         auth_observation_markers = 0;
	bool             auth_markers_valid       = true;
	std::string      field;
	while (record >> field) {
		if (field.starts_with("self=")) {
			++self_markers;
			AuthInfo::Digest parsed {};
			if (self_markers != 1 ||
			    !AuthInfo::ParseDigestHex(std::string_view(field).substr(5), &parsed)) {
				auth_markers_valid = false;
			} else {
				self_sha256 = parsed;
			}
		} else if (field.starts_with("elf=")) {
			++elf_markers;
			AuthInfo::Digest parsed {};
			if (elf_markers != 1 ||
			    !AuthInfo::ParseDigestHex(std::string_view(field).substr(4), &parsed)) {
				auth_markers_valid = false;
			} else {
				elf_sha256 = parsed;
			}
		} else if (field.starts_with("birth=")) {
			++birth_markers;
			uint64_t parsed = 0;
			if (birth_markers != 1 || !ParseUint64Hex(std::string_view(field).substr(6), &parsed)) {
				auth_markers_valid = false;
			} else {
				host_birth = parsed;
			}
		} else if (field.starts_with("authinfo=")) {
			++auth_info_markers;
			AuthInfo::Digest parsed {};
			if (auth_info_markers != 1 ||
			    !AuthInfo::ParseDigestHex(std::string_view(field).substr(9), &parsed)) {
				auth_markers_valid = false;
			} else {
				auth_info_sha256 = parsed;
			}
		} else if (field.starts_with("authobs=")) {
			++auth_observation_markers;
			AuthInfo::Digest parsed {};
			if (auth_observation_markers != 1 ||
			    !AuthInfo::ParseDigestHex(std::string_view(field).substr(8), &parsed)) {
				auth_markers_valid = false;
			} else {
				auth_observation_sha256 = parsed;
			}
		} else if (!peer->has_category) {
			int32_t    category = 0;
			const auto parsed =
			    std::from_chars(field.data(), field.data() + field.size(), category);
			if (parsed.ec != std::errc {} || parsed.ptr != field.data() + field.size())
				return false;
			peer->category     = category;
			peer->has_category = true;
		} else {
			return false;
		}
	}
	if (!HostProcessAlive(peer->host_pid)) return false;
	if (auth_markers_valid && birth_markers == 1) peer->host_birth = host_birth;
	const bool has_auth_commit = auth_markers_valid && self_markers == 1 && elf_markers == 1 &&
	                             birth_markers == 1 && auth_info_markers == 1;
	const bool has_auth_observation_commit = auth_markers_valid && self_markers == 1 &&
	                                         elf_markers == 1 && birth_markers == 1 &&
	                                         auth_observation_markers == 1;
	AuthInfo::Capture     capture {};
	AuthInfo::Observation observation {};
	bool                  auth_decoded             = false;
	bool                  auth_observation_decoded = false;
#if defined(_WIN32)
	HANDLE process = nullptr;
	if (has_auth_commit || has_auth_observation_commit)
		process = OpenMatchingLiveProcess(peer->host_pid, host_birth);
	if (process != nullptr && has_auth_commit) {
		auth_decoded = ReadScopedAuthInfo(AuthInfoRecordPath(scope, static_cast<uint32_t>(pid)),
		                                  pid, peer->host_pid, peer->auth_id, self_sha256,
		                                  elf_sha256, auth_info_sha256, &capture);
	}
	if (process != nullptr && has_auth_observation_commit) {
		auth_observation_decoded =
		    ReadScopedAuthObservation(AuthObservationRecordPath(scope, static_cast<uint32_t>(pid)),
			                          pid, peer->host_pid, host_birth, peer->auth_id, self_sha256,
			                          elf_sha256, auth_observation_sha256, &observation);
	}
	const bool still_alive = process != nullptr && WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
	if (process != nullptr) CloseHandle(process);
#else
	if (has_auth_commit) {
		auth_decoded = ReadScopedAuthInfo(AuthInfoRecordPath(scope, static_cast<uint32_t>(pid)),
		                                  pid, peer->host_pid, peer->auth_id, self_sha256,
		                                  elf_sha256, auth_info_sha256, &capture);
	}
	if (has_auth_observation_commit) {
		auth_observation_decoded =
		    ReadScopedAuthObservation(AuthObservationRecordPath(scope, static_cast<uint32_t>(pid)),
			                          pid, peer->host_pid, host_birth, peer->auth_id, self_sha256,
			                          elf_sha256, auth_observation_sha256, &observation);
	}
	const bool still_alive = HostProcessAlive(peer->host_pid);
#endif
	if (!still_alive) {
		auth_decoded             = false;
		auth_observation_decoded = false;
	}
	if (auth_decoded && auth_observation_decoded &&
	    ((AuthInfo::Capability0(capture.record) ^ observation.facts.capability0) &
	     observation.facts.known_capability0) != 0) {
		auth_decoded             = false;
		auth_observation_decoded = false;
	}
	if (auth_decoded) {
		peer->has_auth_info          = true;
		peer->auth_info              = capture.record;
		peer->has_filtered_auth_info = true;
		peer->filtered_auth_info     = AuthInfo::Filter(capture.record);
	}
	if (auth_observation_decoded) {
		AuthInfo::Record filtered {};
		if (AuthInfo::BuildFilteredRecord(observation.facts, &filtered)) {
			if (peer->has_filtered_auth_info && peer->filtered_auth_info != filtered) {
				peer->has_auth_info = false;
				peer->auth_info.fill(0);
				peer->has_filtered_auth_info = false;
				peer->filtered_auth_info.fill(0);
			} else {
				peer->has_filtered_auth_info = true;
				peer->filtered_auth_info     = filtered;
			}
		}
		SecureWipe(filtered.data(), filtered.size());
	}
	SecureWipeCapture(&capture);
	SecureWipe(&observation, sizeof(observation));
	return true;
}

bool FindPeerByHostPid(uint32_t host_pid, PeerProcess* peer) {
	std::string scope;
	if (!GetScope(&scope)) {
		return false;
	}
	int           pid = 0;
	std::ifstream record(RecordPath(scope, "host", host_pid));
	return (record >> pid) && FindPeerByPid(pid, peer) && peer->host_pid == host_pid;
}

int QueryGuestProcessExists(int pid, const char** source, uint32_t* host_pid) {
	*source   = "none";
	*host_pid = 0;
	// 13.60 sysctl_kern_proc sends pid 0 to proc0 and pids above PID_MAX down the thread-id path;
	// neither is modeled.
	if (pid == 0 || pid > 99999) return KERNEL_ERROR_ENOSYS;
	if (pid < 0) return KERNEL_ERROR_ESRCH;
	if (pid == GetPid()) {
		*source = "self";
#if defined(_WIN32)
		*host_pid = GetCurrentProcessId();
#else
		*host_pid = static_cast<uint32_t>(getpid());
#endif
		return 0;
	}
	uint32_t committed_host  = 0;
	uint64_t committed_birth = 0;
	{
		std::lock_guard lock(g_rfork_children_mutex);
		const auto      child = g_rfork_children.find(pid);
		if (child != g_rfork_children.end()) {
			*source   = "rfork_child";
			*host_pid = child->second.host_pid;
			// sysctl_out_proc re-runs pfind after the copy, so a zombie still fails with ESRCH.
			if (child->second.has_exit_status) return KERNEL_ERROR_ESRCH;
			if (!child->second.exec_committed) return 0;
			committed_host  = child->second.host_pid;
			committed_birth = child->second.host_birth;
		}
	}
	if (committed_host != 0) {
		// the child writes its scope record only after the commit wait returns
		*source = "exec_commit";
		if (committed_birth == 0) return KERNEL_ERROR_ENOSYS;
#if defined(_WIN32)
		HANDLE process = OpenMatchingLiveProcess(committed_host, committed_birth);
		if (process == nullptr) return KERNEL_ERROR_ESRCH;
		CloseHandle(process);
		return 0;
#else
		return KERNEL_ERROR_ENOSYS;
#endif
	}
	std::string scope;
	if (!GetScope(&scope)) return KERNEL_ERROR_ENOSYS;
	std::ifstream record(RecordPath(scope, "pid", static_cast<uint32_t>(pid)));
	uint32_t      recorded_host = 0;
	uint64_t      authority_id  = 0;
	if (!(record >> recorded_host >> authority_id)) return KERNEL_ERROR_ESRCH;
	*source                   = "scope_record";
	*host_pid                 = recorded_host;
	uint64_t    birth         = 0;
	uint32_t    birth_markers = 0;
	bool        birth_valid   = true;
	std::string field;
	while (record >> field) {
		if (!field.starts_with("birth=")) continue;
		if (++birth_markers != 1 || !ParseUint64Hex(std::string_view(field).substr(6), &birth))
			birth_valid = false;
	}
	// Without a creation time a live host pid could belong to an unrelated reused process.
	if (!birth_valid || birth_markers != 1 || birth == 0) return KERNEL_ERROR_ENOSYS;
#if defined(_WIN32)
	HANDLE process = OpenMatchingLiveProcess(recorded_host, birth);
	if (process == nullptr) return KERNEL_ERROR_ESRCH;
	CloseHandle(process);
	return 0;
#else
	return KERNEL_ERROR_ENOSYS;
#endif
}

static std::string g_name;

void SetName(const std::string& name) {
	g_name = name;
	std::string scope;
	if (GetScope(&scope)) {
		std::ofstream(RecordPath(scope, "name", static_cast<uint32_t>(GetPid())), std::ios::trunc)
		    << name << '\n';
	}
}

bool FindNameByPid(int pid, std::string* name) {
	if (pid == GetPid()) {
		*name = g_name;
		return true;
	}
	std::string scope;
	if (pid < 0 || !GetScope(&scope)) {
		return false;
	}
	PeerProcess peer;
	if (!FindPeerByPid(pid, &peer)) {
		return false;
	}
	std::ifstream record(RecordPath(scope, "name", static_cast<uint32_t>(pid)));
	return static_cast<bool>(std::getline(record, *name));
}

} // namespace Libs::LibKernel::Process
