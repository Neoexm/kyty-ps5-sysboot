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
#include <windows.h>
#include <sddl.h>
#pragma comment(lib, "advapi32.lib")
#else
#include <unistd.h>
#endif
namespace Libs::LibKernel::Process {
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
#endif
namespace {
thread_local int g_thread_guest_pid = 0;
std::mutex       g_auth_info_update_mutex;
std::mutex       g_auth_info_mutex;
using OriginalSelfIdentity = AuthInfo::ImageIdentity;
std::optional<OriginalSelfIdentity>  g_original_self_identity;
std::optional<AuthInfo::Capture>     g_auth_info;
std::optional<AuthInfo::Observation> g_authorization_observation;
} // namespace
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
static bool GetVerifiedOriginalSelf(OriginalSelfIdentity* identity) {
	std::lock_guard lock(g_auth_info_mutex);
	if (!g_original_self_identity.has_value()) return false;
	*identity = *g_original_self_identity;
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
}
} // namespace Libs::LibKernel::Process
