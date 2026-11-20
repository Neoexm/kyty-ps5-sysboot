#include "kernel/ipmiManager.h"
#include "kernel/ipmiScope.h"
#include "kernel/appMount.h"
#include "kernel/budget.h"
#include "kernel/memory.h"
#include "kernel/process.h"
#include "common/logging/log.h"
#include "libs/errno.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace Libs::LibKernel {
bool CanAccessCurrentThreadStack(const void* pointer, uint64_t size, bool writable);
}

namespace Libs::Jemspace {
bool QueryAllocation(const void* pointer, uint64_t size, uint64_t* offset_out,
                     uint64_t* allocation_size_out);
bool CopyFromAllocation(void* destination, const void* source, uint64_t size);
bool CopyToAllocation(void* destination, const void* source, uint64_t size);
} // namespace Libs::Jemspace

namespace Libs::LibJson2 {
bool ContainsCString(const void* pointer, uint64_t size);
}

namespace Libs::LibKernel::IpmiManager {

namespace {
unsigned long long IpmiMonotonicMs() {
#if defined(_WIN32)
	return GetTickCount64();
#else
	return 0;
#endif
}
} // namespace

int IpmiFail(const char* op, int32_t handle, uint32_t request, int code) {
	LOGF("ORIGINAL_APP_IPMI_%s_ERROR pid=%d handle=%d request=%u errno=%08x\n", op,
	     Process::GetPid(), handle, request, static_cast<unsigned>(code));
	return code;
}
#define IPMI_FAIL(op, handle_, request_, code_) IpmiFail(op, handle_, request_, code_)

int ValidateServerConfig(const void* config) {
	std::array<uint8_t, 0x38> bytes {};
	std::memcpy(bytes.data(), config, bytes.size());
	auto qword = [&](size_t offset) {
		uint64_t value = 0;
		std::memcpy(&value, bytes.data() + offset, sizeof(value));
		return value;
	};
	auto dword = [&](size_t offset) {
		uint32_t value = 0;
		std::memcpy(&value, bytes.data() + offset, sizeof(value));
		return value;
	};
	if (qword(0) > 0x38 || qword(8) > 0x2000 || qword(0x10) > 0x100000) return KERNEL_ERROR_EINVAL;
	if (dword(0x18) > 1 || dword(0x1c) > 1 || dword(0x20) > 1) return KERNEL_ERROR_EINVAL;
	return OK;
}

int ValidateServerAuthorization(std::string_view name, const AuthInfo::Record& auth_info) {
	return ValidateServerAuthorization(
	    name,
	    AuthInfo::AuthorizationFacts {true, AuthInfo::AuthorityId(auth_info),
		                              AuthInfo::Capability0(auth_info) & (1ull << 62), 1ull << 62});
}

int ValidateServerAuthorization(std::string_view name, const AuthInfo::AuthorizationFacts& facts) {
	if (!facts.has_authority || AuthInfo::IsFilteredAuthorityVisible(facts.authority_id))
		return KERNEL_ERROR_ENOSYS;
	if (!(facts.known_capability0 & (1ull << 62))) return KERNEL_ERROR_ENOSYS;
	const bool sce_name = name.size() >= 3 && name[0] == 'S' && name[1] == 'c' && name[2] == 'e';
	const bool system   = (facts.capability0 & (1ull << 62)) != 0;
	return sce_name == system ? OK : KERNEL_ERROR_EPERM;
}

static bool DiagnosticPupUtilAdmission(std::string_view                    name,
                                       const AuthInfo::AuthorizationFacts& facts) {
	const auto* gate = std::getenv("KYTY_DIAGNOSTIC_PUPUTIL_IPMI_ADMISSION");
	if (gate == nullptr || std::strcmp(gate, "1") != 0 || name != "SceUpdatePupUtilService" ||
	    !facts.has_authority || facts.authority_id != 0x480000000000100dull ||
	    (facts.known_capability0 & (1ull << 62)) == 0 || (facts.capability0 & (1ull << 62)) != 0)
		return false;

	static constexpr AuthInfo::Digest expected_self {
	    0xfb, 0xfb, 0x75, 0x88, 0x36, 0x55, 0xae, 0x35, 0xc2, 0x69, 0x81,
	    0x40, 0x2f, 0x59, 0xdb, 0xd4, 0xc5, 0xa3, 0x5c, 0xe1, 0xb3, 0x5d,
	    0xd9, 0xdc, 0x26, 0xec, 0xf8, 0x9e, 0xdf, 0xff, 0xe1, 0xf2,
	};
	static constexpr AuthInfo::Digest expected_elf {
	    0x8e, 0xb9, 0x44, 0x02, 0xb0, 0xd0, 0x55, 0xad, 0x02, 0x76, 0xa0,
	    0xbf, 0xc1, 0xfe, 0x34, 0xe2, 0x13, 0x5a, 0xc3, 0x49, 0xca, 0xd4,
	    0x4d, 0x4c, 0xbe, 0x42, 0xcf, 0x68, 0xe9, 0x03, 0x49, 0xb0,
	};
	AuthInfo::ImageIdentity identity;
	if (!Process::GetVerifiedOriginalSelfIdentity(&identity) ||
	    identity.authority_id != facts.authority_id || identity.self_size != 283036 ||
	    identity.elf_size != 669468 || identity.self_sha256 != expected_self ||
	    identity.elf_sha256 != expected_elf)
		return false;

	static std::atomic<uint32_t> logged {0};
	if (logged.fetch_add(1, std::memory_order_relaxed) == 0) {
		LOGF("NON_AUTHENTIC_IPMI_PUPUTIL_ADMISSION service=SceUpdatePupUtilService"
		     " generalized_name_policy_bypassed=1\n");
	}
	return true;
}

namespace {
// 0xfc00 max message_limit plus invoke framing. Same as ipmiScope kMaxPacket
constexpr size_t kPacketLimit         = 0x10000;
constexpr size_t kOutstandingRequests = 32;
struct Packet {
	uint32_t             request = 0;
	uint32_t             client  = 0;
	std::vector<uint8_t> bytes;
};
struct Server {
	int         pid     = 0;
	uint32_t    scope   = 0;
	uint64_t    handler = 0;
	std::string name;
};
struct Client {
	int                      pid    = 0;
	uint32_t                 scope  = 0;
	uint32_t                 server = 0;
	std::string              name;
	std::array<uint8_t, 336> params {};
	uint32_t                 event_generation = 0;
	bool                     connected        = false;
	bool                     busy             = false;
	uint32_t                 active_command   = 0;
	uint32_t                 active_invokes   = 0;
	// kernel conn+0x448, wraps at 0xffff
	uint32_t next_ticket = 0;
};
struct Session {
	int                   pid    = 0;
	uint32_t              server = 0;
	uint32_t              client = 0;
	uint64_t              object = 0;
	std::vector<uint32_t> requests;
	uint64_t              user_data = 0;
	// async dispatches not yet freed by 0x444 (conn+0x900)
	uint32_t async_inflight = 0;
};
struct ServingContext {
	int32_t  session = 0;
	uint32_t server  = 0;
	uint32_t client  = 0;
	uint32_t request = 0;
};
struct ConnectContext {
	uint32_t server                = 0;
	uint32_t client                = 0;
	uint32_t request               = 0;
	int32_t  authorization_session = 0;
	uint32_t authorization_peer    = 0;
};
std::mutex                           state_mutex;
std::unordered_map<int32_t, Server>  servers;
std::unordered_map<int32_t, Client>  clients;
std::unordered_map<int32_t, Session> sessions;
uint32_t                             next_server  = 1;
uint32_t                             next_client  = 1;
uint32_t                             next_session = 1;
thread_local ConnectContext          connecting;
thread_local ConnectContext          disconnecting;
// Uncompleted method requests received on this thread. Kernel slot table is keyed by serving tid
// (0x9ee7d362), so match from the back when receives nest.
thread_local std::deque<ServingContext> serving;
thread_local uint32_t                   received_kind = 0;

class InvokeLease {
public:
	explicit InvokeLease(int32_t handle): m_handle(handle) {}
	InvokeLease(const InvokeLease&)            = delete;
	InvokeLease& operator=(const InvokeLease&) = delete;
	~InvokeLease() { Release(false); }

	void Complete(int result) { Release(result == KERNEL_ERROR_ECONNRESET); }

private:
	void Release(bool disconnected) {
		if (!m_active) return;
		std::lock_guard lock(state_mutex);
		auto            found = clients.find(m_handle);
		if (found != clients.end()) {
			if (found->second.active_invokes != 0) found->second.active_invokes--;
			if (disconnected) found->second.connected = false;
		}
		m_active = false;
	}

	int32_t m_handle = 0;
	bool    m_active = true;
};

enum class AdmissionReason : uint8_t {
	PeerMissing,
	AuthInfoMissing,
	FilteredAuthority,
	CapabilityMismatch,
};

struct AdmissionTraceKey {
	int             pid                    = 0;
	uint64_t        public_authority       = 0;
	bool            public_authority_valid = false;
	bool            authority_known        = false;
	bool            capability62_known     = false;
	AdmissionReason reason                 = AdmissionReason::PeerMissing;
	std::string     name;
};

std::mutex                     admission_trace_mutex;
std::vector<AdmissionTraceKey> admission_trace_keys;

const char* AdmissionReasonName(AdmissionReason reason) {
	switch (reason) {
		case AdmissionReason::PeerMissing: return "peer_missing";
		case AdmissionReason::AuthInfoMissing: return "authinfo_missing";
		case AdmissionReason::FilteredAuthority: return "filtered_authority";
		case AdmissionReason::CapabilityMismatch: return "capability_mismatch";
	}
	return "unknown";
}

std::string ServiceHex(std::string_view name) {
	constexpr char digits[] = "0123456789abcdef";
	const auto     size     = std::min<size_t>(name.size(), 96);
	std::string    result;
	result.reserve(size * 2);
	for (size_t i = 0; i < size; ++i) {
		const auto ch    = name[i];
		const auto value = static_cast<uint8_t>(ch);
		result.push_back(digits[value >> 4]);
		result.push_back(digits[value & 15]);
	}
	return result;
}

void TraceAdmissionDecision(int pid, std::string_view name, const AuthInfo::Record* auth_info,
                            AdmissionReason reason, int rc,
                            const AuthInfo::AuthorizationFacts* facts = nullptr) {
	if (Log::IsSilent()) return;
	uint64_t public_authority       = 0;
	bool     public_authority_valid = false;
	if (auth_info != nullptr) {
		const auto filtered    = AuthInfo::Filter(*auth_info);
		public_authority       = AuthInfo::AuthorityId(filtered);
		public_authority_valid = public_authority != 0;
	}
	const bool authority_known    = facts && facts->has_authority;
	const bool capability62_known = facts && (facts->known_capability0 & (1ull << 62));
	bool       emit               = false;
	{
		std::lock_guard lock(admission_trace_mutex);
		const bool      seen = std::any_of(
		    admission_trace_keys.begin(), admission_trace_keys.end(), [&](const auto& key) {
			    return key.pid == pid && key.public_authority == public_authority &&
				       key.public_authority_valid == public_authority_valid &&
				       key.authority_known == authority_known &&
				       key.capability62_known == capability62_known && key.reason == reason &&
				       key.name == name;
		    });
		if (!seen && admission_trace_keys.size() < 128) {
			admission_trace_keys.push_back({pid, public_authority, public_authority_valid,
			                                authority_known, capability62_known, reason,
			                                std::string(name)});
			emit = true;
		}
	}
	if (!emit) return;
	const auto service_hex = ServiceHex(name);
	LOGF("ORIGINAL_APP_IPMI_ADMISSION_DECISION pid=%d service_hex=%s public_authority=%016llx"
	     " public_authority_valid=%u reason=%s kernel_result=%08x posix_errno=%d"
	     " config_read=0 registration_attempted=0 authority_known=%u capability62_known=%u "
	     "full_record_required=0\n",
	     pid, service_hex.c_str(), static_cast<unsigned long long>(public_authority),
	     public_authority_valid ? 1u : 0u, AdmissionReasonName(reason), static_cast<unsigned>(rc),
	     KernelToPosix(rc), authority_known ? 1u : 0u, capability62_known ? 1u : 0u);
}

struct ReceivedRequest {
	uint32_t server;
	uint32_t request;
	int32_t  session   = 0;
	bool     committed = false;
	~ReceivedRequest() {
		if (!committed) {
			std::lock_guard lock(state_mutex);
			auto            found = sessions.find(session);
			if (found != sessions.end()) {
				auto& requests = found->second.requests;
				requests.erase(std::remove(requests.begin(), requests.end(), request),
				               requests.end());
			}
			IpmiScope::RequeueRequest(server, request);
		}
	}
};

bool Read(uint64_t address, void* out, size_t size) {
	if (size == 0) return true;
	if (!address || size > UINT64_MAX - address) return false;
	for (uint64_t cursor = address; cursor < address + size;) {
		Memory::VirtualQueryInfo region {};
		if (Memory::KernelVirtualQuery(reinterpret_cast<void*>(cursor), 0, &region,
		                               sizeof(region)) != OK ||
		    !region.is_committed || region.start > cursor || region.end <= cursor ||
		    !(region.protection & 1))
			return false;
		cursor = std::min<uint64_t>(region.end, address + size);
	}
#if defined(_WIN32)
	SIZE_T copied = 0;
	return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), out, size,
	                         &copied) &&
	       copied == size;
#else
	std::memcpy(out, reinterpret_cast<void*>(address), size);
	return true;
#endif
}
bool Write(uint64_t address, const void* data, size_t size) {
	return Memory::CopyToGuest(reinterpret_cast<void*>(address), data, size);
}
const char* PointerDomain(uint64_t address, uint64_t size, bool writable) {
	if (address == 0 || size > UINT64_MAX - address) return "invalid";
	const auto end   = address + size;
	bool       guest = true;
	for (auto cursor = address; cursor < end;) {
		Memory::VirtualQueryInfo region {};
		if (!Memory::QueryGuestRangeNoTrace(reinterpret_cast<void*>(cursor), &region) ||
		    !region.is_committed || region.start > cursor || region.end <= cursor ||
		    !(region.protection & (writable ? 2 : 1))) {
			guest = false;
			break;
		}
		cursor = std::min<uint64_t>(region.end, end);
	}
	if (guest) return "guest";
	if (Jemspace::QueryAllocation(reinterpret_cast<void*>(address), size, nullptr, nullptr))
		return "jemspace";
	if (LibJson2::ContainsCString(reinterpret_cast<void*>(address), size) && !writable)
		return "json2_cstring";
	if (CanAccessCurrentThreadStack(reinterpret_cast<void*>(address), size, writable))
		return "native_stack";
	return "unowned";
}
bool ReadInvokeSpan(uint64_t address, void* out, uint64_t size) {
	if (size == 0) return true;
	if (!address || out == nullptr || size > UINT64_MAX - address) return false;
	auto* source = reinterpret_cast<void*>(address);
	if (Memory::CopyFromGuest(out, source, size)) return true;
	if (Jemspace::CopyFromAllocation(out, source, size)) return true;
	if (LibJson2::ContainsCString(source, size)) {
#if defined(_WIN32)
		// The range can outlive a later mutation of its string, like a native c_str pointer, and freed heap may be decommitted.
		SIZE_T copied = 0;
		return ReadProcessMemory(GetCurrentProcess(), source, out, size, &copied) && copied == size;
#else
		std::memcpy(out, source, size);
		return true;
#endif
	}
	if (!CanAccessCurrentThreadStack(source, size, false)) return false;
	std::memcpy(out, source, size);
	return true;
}
bool CanWriteInvokeSpan(uint64_t address, uint64_t size) {
	if (size == 0) return true;
	if (!address || size > UINT64_MAX - address) return false;
	auto* destination = reinterpret_cast<void*>(address);
	return Memory::CanWriteGuest(destination, size) ||
	       Jemspace::QueryAllocation(destination, size, nullptr, nullptr) ||
	       CanAccessCurrentThreadStack(destination, size, true);
}
bool WriteInvokeSpan(uint64_t address, const void* data, uint64_t size) {
	if (size == 0) return true;
	if (!address || data == nullptr || size > UINT64_MAX - address) return false;
	auto* destination = reinterpret_cast<void*>(address);
	if (Memory::CopyToGuest(destination, data, size)) return true;
	if (Jemspace::CopyToAllocation(destination, data, size)) return true;
	if (!CanAccessCurrentThreadStack(destination, size, true)) return false;
	std::memcpy(destination, data, size);
	return true;
}
template <class T>
T Load(const uint8_t* data) {
	T value {};
	std::memcpy(&value, data, sizeof(value));
	return value;
}
void PutTrace(uint32_t type, const uint8_t* data) {
	std::array<char, 32> name {};
	const int32_t        handle = Load<int32_t>(data);
	if (handle != -1) {
		std::lock_guard lock(state_mutex);
		const auto      server = servers.find(handle);
		if (server != servers.end() && server->second.pid == Process::GetPid()) {
			const auto& source = server->second.name;
			std::memcpy(name.data(), source.data(), std::min(source.size(), name.size() - 1));
		}
	}
	uint16_t   kid  = 0xffff;
	uint32_t   code = 0, code2 = 0;
	uint64_t   payload = UINT64_MAX;
	const bool known   = type >= 0x1f00 && type <= 0x1f05;
	if (known) {
		kid     = Load<uint16_t>(data);
		payload = 0;
		if (type == 0x1f00) {
			payload = Load<uint64_t>(data + 8);
			code    = Load<uint32_t>(data + 0x10);
		} else if (type == 0x1f02) {
			name.fill(0);
			for (size_t i = 0; i < 25 && data[8 + i]; ++i)
				name[i] = static_cast<char>(data[8 + i]);
			kid  = 0xffff;
			code = Load<uint32_t>(data + 0x24);
		} else {
			code = Load<uint32_t>(data + 8);
			if (type == 0x1f04) {
				payload = Load<uint64_t>(data + 0x10);
				code2   = Load<uint32_t>(data + 0x18);
			}
		}
	}
	constexpr char        hex[] = "0123456789abcdef";
	std::array<char, 129> record_hex {};
	std::array<char, 65>  name_hex {};
	for (size_t i = 0; i < 64; ++i) {
		record_hex[i * 2]     = hex[data[i] >> 4];
		record_hex[i * 2 + 1] = hex[data[i] & 15];
	}
	for (size_t i = 0; i < name.size(); ++i) {
		const auto ch       = static_cast<uint8_t>(name[i]);
		name_hex[i * 2]     = hex[ch >> 4];
		name_hex[i * 2 + 1] = hex[ch & 15];
	}
#if defined(_WIN32)
	const auto host_thread = static_cast<uint64_t>(GetCurrentThreadId());
#else
	const auto host_thread =
	    static_cast<uint64_t>(std::hash<std::thread::id> {}(std::this_thread::get_id()));
#endif
	LOGF("ORIGINAL_APP_IPMI_TRACE pid=%d host_tid=%llu suboperation=%08x known=%u kid=%04x"
	     " code=%08x code2=%08x payload=%016llx name_hex=%s record_hex=%s\n",
	     Process::GetPid(), static_cast<unsigned long long>(host_thread), type, known ? 1u : 0u,
	     static_cast<unsigned>(kid), code, code2, static_cast<unsigned long long>(payload),
	     name_hex.data(), record_hex.data());
}

void TraceCall(uint32_t type, int32_t* result, void* args, size_t size, int* status) {
	int32_t rc = static_cast<int32_t>(0x800e0001u);
	if (size <= 64) {
		if (!args || size != 64) {
			*Posix::GetErrorAddr() = Posix::POSIX_EINVAL;
			*status                = -1;
			return;
		}
		std::array<uint8_t, 64> record {};
		if (!Read(reinterpret_cast<uint64_t>(args), record.data(), record.size())) {
			*Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
			*status                = -1;
			return;
		}
		PutTrace(type, record.data());
		rc = OK;
	}
	*status = Write(reinterpret_cast<uint64_t>(result), &rc, sizeof(rc)) ? OK : -1;
	if (*status == -1) *Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
}
template <class T>
void Append(std::vector<uint8_t>* data, T value) {
	const auto offset = data->size();
	data->resize(offset + sizeof(value));
	std::memcpy(data->data() + offset, &value, sizeof(value));
}
int Name(uint64_t address, std::string* name) {
	name->clear();
	for (size_t i = 0; i < 25; ++i) {
		char ch = 0;
		if (address > UINT64_MAX - i || !Read(address + i, &ch, 1)) return KERNEL_ERROR_EFAULT;
		if (!ch) return name->empty() ? KERNEL_ERROR_EFAULT : OK;
		name->push_back(ch);
	}
	return KERNEL_ERROR_ENAMETOOLONG;
}
bool Timeout(uint64_t address, uint32_t* timeout) {
	*timeout = UINT32_MAX;
	return !address || Read(address, timeout, sizeof(*timeout));
}
int WaitReply(uint32_t client, uint32_t request, uint32_t timeout, std::vector<uint8_t>* reply) {
	const auto start = std::chrono::steady_clock::now();
	for (;;) {
		if (IpmiScope::TryReadReply(client, request, reply)) return OK;
		uint32_t server = 0, pid = 0;
		if (!IpmiScope::InspectClient(client, &server, &pid)) return KERNEL_ERROR_ECONNRESET;
		if (timeout != UINT32_MAX &&
		    std::chrono::steady_clock::now() - start >= std::chrono::microseconds(timeout))
			return timeout ? KERNEL_ERROR_ETIMEDOUT : KERNEL_ERROR_EAGAIN;
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}

bool ValidEventMode(uint32_t mode) {
	const uint32_t condition = mode & 3;
	return (condition == 1 || condition == 2) && (mode & 0x30) != 0x30;
}

int EventStatusResult(IpmiScope::EventStatus status) {
	switch (status) {
		case IpmiScope::EventStatus::Matched: return OK;
		case IpmiScope::EventStatus::Pending: return KERNEL_ERROR_EBUSY;
		case IpmiScope::EventStatus::InvalidIndex: return KERNEL_ERROR_EINVAL;
		case IpmiScope::EventStatus::Missing: return KERNEL_ERROR_ESRCH;
		case IpmiScope::EventStatus::Unavailable: return KERNEL_ERROR_EAGAIN;
	}
	return KERNEL_ERROR_EIO;
}

uint32_t RemainingTimeout(std::chrono::steady_clock::time_point start, uint32_t timeout) {
	const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
	                         std::chrono::steady_clock::now() - start)
	                         .count();
	return elapsed >= timeout ? 0 : timeout - static_cast<uint32_t>(elapsed);
}

int ClientEvent(int32_t handle, const uint8_t* args, bool wait) {
	const uint32_t index           = Load<uint32_t>(args);
	const uint64_t desired         = Load<uint64_t>(args + 8);
	const uint32_t mode            = Load<uint32_t>(args + 16);
	const uint64_t output_address  = Load<uint64_t>(args + 24);
	const uint64_t timeout_address = wait ? Load<uint64_t>(args + 32) : 0;
	if (!ValidEventMode(mode)) return KERNEL_ERROR_EINVAL;
	uint32_t timeout = UINT32_MAX;
	if (wait && !Timeout(timeout_address, &timeout)) return KERNEL_ERROR_EFAULT;
	Client client;
	{
		std::lock_guard lock(state_mutex);
		const auto      found = clients.find(handle);
		if (found == clients.end() || found->second.pid != Process::GetPid())
			return KERNEL_ERROR_EBADF;
		client = found->second;
	}
	if (!client.connected || !client.scope) return KERNEL_ERROR_ESRCH;
	const auto start = std::chrono::steady_clock::now();
	LOGF("ORIGINAL_APP_IPMI_EVENT_%s_BEGIN pid=%d handle=%d client=%u index=%u desired=%016llx "
	     "mode=%x timeout_us=%u timeout_pointer=%u\n",
	     wait ? "WAIT" : "POLL", client.pid, handle, client.scope, index,
	     static_cast<unsigned long long>(desired), mode, timeout, timeout_address ? 1u : 0u);
	for (;;) {
		uint64_t   current  = 0;
		const auto event    = IpmiScope::PollClientEvent(client.scope, index, desired, mode,
		                                                 client.event_generation, &current);
		int        rc       = EventStatusResult(event);
		const bool terminal = event != IpmiScope::EventStatus::Pending || !wait;
		if (terminal) {
			if ((event == IpmiScope::EventStatus::Matched ||
			     event == IpmiScope::EventStatus::Pending) &&
			    output_address && !Write(output_address, &current, sizeof(current)))
				rc = KERNEL_ERROR_EFAULT;
			if (wait && timeout_address) {
				const uint32_t remaining = RemainingTimeout(start, timeout);
				if (!Write(timeout_address, &remaining, sizeof(remaining)))
					rc = KERNEL_ERROR_EFAULT;
			}
			LOGF("ORIGINAL_APP_IPMI_EVENT_%s_RESULT pid=%d handle=%d client=%u index=%u "
			     "desired=%016llx mode=%x current=%016llx result=%08x matched=%u\n",
			     wait ? "WAIT" : "POLL", client.pid, handle, client.scope, index,
			     static_cast<unsigned long long>(desired), mode,
			     static_cast<unsigned long long>(current), static_cast<unsigned>(rc),
			     event == IpmiScope::EventStatus::Matched ? 1u : 0u);
			return rc;
		}
		if (timeout_address && RemainingTimeout(start, timeout) == 0) {
			rc = KERNEL_ERROR_EAGAIN;
			if (output_address && !Write(output_address, &current, sizeof(current)))
				rc = KERNEL_ERROR_EFAULT;
			const uint32_t remaining = 0;
			if (timeout_address && !Write(timeout_address, &remaining, sizeof(remaining)))
				rc = KERNEL_ERROR_EFAULT;
			LOGF("ORIGINAL_APP_IPMI_EVENT_WAIT_RESULT pid=%d handle=%d client=%u index=%u "
			     "desired=%016llx mode=%x current=%016llx result=%08x matched=0\n",
			     client.pid, handle, client.scope, index, static_cast<unsigned long long>(desired),
			     mode, static_cast<unsigned long long>(current), static_cast<unsigned>(rc));
			return rc;
		}
		uint32_t milliseconds = 50;
		if (timeout_address) {
			const uint32_t remaining = RemainingTimeout(start, timeout);
			milliseconds = std::max<uint32_t>(1, std::min<uint32_t>(50, (remaining + 999) / 1000));
		}
		if (!IpmiScope::WaitClientEventHint(client.scope, milliseconds))
			std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
	}
}

int SetSessionEvent(int32_t handle, const uint8_t* args) {
	const uint32_t         index = Load<uint32_t>(args);
	const uint64_t         bits  = Load<uint64_t>(args + 8);
	Session                session;
	IpmiScope::EventStatus event = IpmiScope::EventStatus::Missing;
	{
		std::lock_guard lock(state_mutex);
		const auto      found = sessions.find(handle);
		if (found == sessions.end() || found->second.pid != Process::GetPid())
			return KERNEL_ERROR_EBADF;
		session = found->second;
		event   = IpmiScope::SetClientEvent(session.server, session.client, index, bits);
	}
	const int rc = EventStatusResult(event);
	LOGF("ORIGINAL_APP_IPMI_EVENT_SET pid=%d handle=%d server=%u client=%u index=%u bits=%016llx "
	     "result=%08x\n",
	     session.pid, handle, session.server, session.client, index,
	     static_cast<unsigned long long>(bits), static_cast<unsigned>(rc));
	return rc;
}

int Create(uint32_t command, const uint8_t* args) {
	const uint64_t object         = Load<uint64_t>(args);
	const uint64_t name_address   = Load<uint64_t>(args + 8);
	const uint64_t params_address = Load<uint64_t>(args + 16);
	std::string    name;
	if (!object) return KERNEL_ERROR_EFAULT;
	const int name_result = Name(name_address, &name);
	if (name_result != OK) return name_result;
	const int pid = Process::GetPid();
	if (command == 0) {
		Process::PeerProcess process;
		if (!Process::FindPeerByPid(pid, &process)) {
			TraceAdmissionDecision(pid, name, nullptr, AdmissionReason::PeerMissing,
			                       KERNEL_ERROR_ENOSYS);
			return KERNEL_ERROR_ENOSYS;
		}
		const auto facts         = Process::GetCurrentAuthorizationFacts();
		const int  authorization = ValidateServerAuthorization(name, facts);
		if (authorization != OK && !DiagnosticPupUtilAdmission(name, facts)) {
			const auto reason = !facts.has_authority ? AdmissionReason::AuthInfoMissing
			                    : AuthInfo::IsFilteredAuthorityVisible(facts.authority_id)
			                        ? AdmissionReason::FilteredAuthority
			                    : !(facts.known_capability0 & (1ull << 62))
			                        ? AdmissionReason::AuthInfoMissing
			                        : AdmissionReason::CapabilityMismatch;
			TraceAdmissionDecision(pid, name, process.has_auth_info ? &process.auth_info : nullptr,
			                       reason, authorization, &facts);
			return authorization;
		}
		std::array<uint8_t, 56> params {};
		if (!params_address) return KERNEL_ERROR_EINVAL;
		if (!Read(params_address, params.data(), params.size())) return KERNEL_ERROR_EFAULT;
		const int validation = ValidateServerConfig(params.data());
		if (validation != OK) return validation;
		uint32_t scope     = 0;
		bool     duplicate = false;
		if (!IpmiScope::Register(name, pid, &scope, &duplicate))
			return duplicate ? KERNEL_ERROR_EEXIST : KERNEL_ERROR_EBUSY;
		std::lock_guard lock(state_mutex);
		const int32_t   handle = 0x10000000 | next_server++;
		servers.emplace(handle, Server {pid, scope, Load<uint64_t>(params.data() + 48), name});
		LOGF("ORIGINAL_APP_IPMI_SERVER name=%s pid=%d handle=%d scope=%u handler=%016llx\n",
		     name.c_str(), pid, handle, scope,
		     static_cast<unsigned long long>(Load<uint64_t>(params.data() + 48)));
		return handle;
	}
	Client client;
	client.pid  = pid;
	client.name = name;
	if (!params_address) return KERNEL_ERROR_EINVAL;
	if (!Read(params_address, client.params.data(), client.params.size()))
		return KERNEL_ERROR_EFAULT;
	const auto*    config        = client.params.data();
	const uint64_t message_limit = name == "SceSaveData"      ? 0x100000
	                               : name == "SceNpEntAccess" ? 0x18000
	                                                          : 0xfc00;
	if (Load<uint64_t>(config) > client.params.size() || Load<uint32_t>(config + 8) > 16 ||
	    Load<uint64_t>(config + 0x10) > 0x100000 || Load<uint64_t>(config + 0x18) > message_limit ||
	    Load<uint32_t>(config + 0x20) > 16 || Load<uint64_t>(config + 0x28) > 0x100000 ||
	    Load<uint64_t>(config + 0x30) > 0x100000 || Load<uint32_t>(config + 0x38) > 32 ||
	    Load<uint32_t>(config + 0x140) > 16 || Load<uint32_t>(config + 0x144) > 1)
		return KERNEL_ERROR_EINVAL;
	for (uint32_t i = 0; i < Load<uint32_t>(config + 0x38); ++i) {
		const auto length = Load<uint64_t>(config + 0x40 + i * 8);
		if (!length || length > 0x80000) return KERNEL_ERROR_EINVAL;
	}
	if (!Load<uint32_t>(config + 0x144)) {
		const uint32_t count = 1;
		std::memcpy(client.params.data() + 8, &count, sizeof(count));
	}
	std::lock_guard lock(state_mutex);
	const int32_t   handle = 0x20000000 | next_client++;
	clients.emplace(handle, client);
	LOGF("ORIGINAL_APP_IPMI_CLIENT name=%s pid=%d handle=%d scope=%u server=%u\n", name.c_str(),
	     pid, handle, client.scope, client.server);
	return handle;
}
int Connect(int32_t handle, const uint8_t* args) {
	const uint64_t user_data       = Load<uint64_t>(args);
	const uint64_t user_size       = Load<uint64_t>(args + 8);
	const uint64_t status_address  = Load<uint64_t>(args + 16);
	const uint64_t timeout_address = Load<uint64_t>(args + 24);
	uint32_t       timeout         = 0;
	if (!Memory::CanWriteGuest(reinterpret_cast<void*>(status_address), 4) ||
	    !Timeout(timeout_address, &timeout))
		return KERNEL_ERROR_EFAULT;
	if (user_size > kPacketLimit - 344) return KERNEL_ERROR_EMSGSIZE;
	Client client;
	{
		std::lock_guard lock(state_mutex);
		auto            found = clients.find(handle);
		if (found == clients.end() || found->second.pid != Process::GetPid())
			return KERNEL_ERROR_EBADF;
		auto& entry = found->second;
		if (entry.connected) return KERNEL_ERROR_EISCONN;
		if (entry.busy || entry.active_invokes != 0) return KERNEL_ERROR_EBUSY;
		entry.busy           = true;
		entry.active_command = 0x400;
		client               = entry;
	}
	std::vector<uint8_t> packet(344 + user_size);
	const uint32_t       kind = 1;
	std::memcpy(packet.data(), &kind, 4);
	std::memcpy(packet.data() + 4, &client.pid, 4);
	std::memcpy(packet.data() + 12, client.params.data() + 8, 48);
	std::memcpy(packet.data() + 60, client.params.data() + 320, 4);
	std::memcpy(packet.data() + 68, client.params.data() + 56, 264);
	const auto length = static_cast<uint32_t>(user_size);
	std::memcpy(packet.data() + 340, &length, 4);
	int rc = OK;
	if (!Read(user_data, packet.data() + 344, user_size)) rc = KERNEL_ERROR_EFAULT;
	const auto start = std::chrono::steady_clock::now();
	if (rc == OK && !IpmiScope::Enabled()) rc = KERNEL_ERROR_ENOSYS;
	if (rc == OK && client.scope) {
		uint32_t   server = 0, owner = 0;
		const auto state = IpmiScope::QueryClient(client.scope, &server, &owner);
		if (state == IpmiScope::ClientStatus::Unavailable)
			rc = KERNEL_ERROR_EAGAIN;
		else if (state == IpmiScope::ClientStatus::Missing)
			client.scope = client.server = 0;
	}
	bool waiting_logged = false;
	while (rc == OK && !client.scope) {
		uint32_t server = 0, owner = 0, host = 0;
		if (IpmiScope::Lookup(client.name, &server, &owner, &host)) {
			if (!IpmiScope::OpenClient(
			        client.name, client.pid, &client.scope, &client.server,
			        Load<uint32_t>(client.params.data() + 0x140),
			        Load<uint32_t>(client.params.data() + 0x38),
			        reinterpret_cast<const uint64_t*>(client.params.data() + 0x40)))
				rc = KERNEL_ERROR_EAGAIN;
			break;
		}
		if (timeout_address && timeout == 0) {
			rc = KERNEL_ERROR_ESRCH;
			break;
		}
		if (timeout != UINT32_MAX &&
		    std::chrono::steady_clock::now() - start >= std::chrono::microseconds(timeout)) {
			rc = KERNEL_ERROR_EAGAIN;
			break;
		}
		if (!waiting_logged) {
#if defined(_WIN32)
			const auto host_thread = static_cast<uint64_t>(GetCurrentThreadId());
#else
			const auto host_thread =
			    static_cast<uint64_t>(std::hash<std::thread::id> {}(std::this_thread::get_id()));
#endif
			LOGF("ORIGINAL_APP_IPMI_CONNECT_WAIT pid=%d host_tid=%llu service_hex=%s timeout_us=%u "
			     "timeout_pointer=%d server_present=0\n",
			     client.pid, static_cast<unsigned long long>(host_thread),
			     ServiceHex(client.name).c_str(), timeout, timeout_address != 0);
			Log::Flush();
			waiting_logged = true;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	uint32_t reply_timeout = timeout == 0 ? UINT32_MAX : timeout;
	if (rc == OK && reply_timeout != UINT32_MAX) {
		const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
		                         std::chrono::steady_clock::now() - start)
		                         .count();
		if (elapsed >= timeout)
			rc = KERNEL_ERROR_EAGAIN;
		else
			reply_timeout -= static_cast<uint32_t>(elapsed);
	}
	uint32_t request          = 0;
	uint32_t event_generation = 0;
	if (rc == OK && client.scope) {
		const auto reset = IpmiScope::ResetClientEvents(
		    client.scope, Load<uint32_t>(client.params.data() + 0x140), &event_generation);
		if (reset != IpmiScope::EventStatus::Matched) rc = EventStatusResult(reset);
	}
	if (rc == OK && !IpmiScope::QueueRequest(client.scope, packet.data(), packet.size(), &request))
		rc = KERNEL_ERROR_EAGAIN;
	std::vector<uint8_t> reply;
	if (rc == OK) rc = WaitReply(client.scope, request, reply_timeout, &reply);
	if (rc != OK && request) IpmiScope::CancelRequest(client.scope, request);
	if (rc == OK && reply.size() != 4) rc = KERNEL_ERROR_EIO;
	// servers reply session ordinals (SysAv: 0,1,2,...), so only negative rejects. 1 is libSceIpmi
	// 0x523's reject path (0x8002000d)
	const int32_t reply_status = rc == OK ? Load<int32_t>(reply.data()) : 0;
	if (rc == OK && !Write(status_address, &reply_status, 4)) rc = KERNEL_ERROR_EFAULT;
	const bool rejected = rc == OK && reply_status < 0;
	{
		std::lock_guard lock(state_mutex);
		auto            found = clients.find(handle);
		if (found != clients.end()) {
			found->second.scope            = client.scope;
			found->second.server           = client.server;
			found->second.event_generation = event_generation;
			found->second.busy             = false;
			found->second.active_command   = 0;
			found->second.connected        = rc == OK && !rejected;
		}
	}
	// kept off ORIGINAL_APP_IPMI_CONNECT so exact matches on it still work
	LOGF("ORIGINAL_APP_IPMI_CONNECT_IDENTITY pid=%d handle=%d client=%u request=%u transport=%08x "
	     "service_hex=%s\n",
	     client.pid, handle, client.scope, request, static_cast<unsigned>(rc),
	     ServiceHex(client.name).c_str());
	LOGF("ORIGINAL_APP_IPMI_CONNECT pid=%d client=%u request=%u transport=%08x callback=%08x\n",
	     client.pid, client.scope, request, static_cast<unsigned>(rc),
	     static_cast<unsigned>(reply_status));
	if (rejected) {
		LOGF("ORIGINAL_APP_IPMI_CONNECT_REJECTED pid=%d client=%u request=%u server_value=%08x\n",
		     client.pid, client.scope, request, static_cast<unsigned>(reply_status));
		return 1;
	}
	return rc;
}
int Receive(int32_t handle, const uint8_t* args) {
	const uint64_t buffer       = Load<uint64_t>(args);
	const uint64_t capacity     = Load<uint64_t>(args + 8);
	const uint64_t info_address = Load<uint64_t>(args + 16);
	uint32_t       timeout      = 0;
	if (capacity > SIZE_MAX || !Memory::CanWriteGuest(reinterpret_cast<void*>(buffer), capacity) ||
	    !Memory::CanWriteGuest(reinterpret_cast<void*>(info_address), 24) ||
	    !Timeout(Load<uint64_t>(args + 24), &timeout))
		return IPMI_FAIL("RECEIVE", handle, 0, KERNEL_ERROR_EFAULT);
	uint32_t server  = 0;
	uint64_t handler = 0;
	{
		std::lock_guard lock(state_mutex);
		auto            found = servers.find(handle);
		if (found == servers.end() || found->second.pid != Process::GetPid())
			return IPMI_FAIL("RECEIVE", handle, 0, KERNEL_ERROR_EBADF);
		server  = found->second.scope;
		handler = found->second.handler;
	}
	Packet     packet;
	uint32_t   peer_pid = 0;
	const auto start    = std::chrono::steady_clock::now();
	for (;;) {
		{
			std::lock_guard lock(state_mutex);
			auto            found = servers.find(handle);
			if (found == servers.end()) return IPMI_FAIL("RECEIVE", handle, 0, KERNEL_ERROR_EBADF);
		}
		if (packet.request ||
		    IpmiScope::TryReceive(server, &packet.request, &packet.client, &packet.bytes)) {
			// A client that closed between queueing and dequeue has withdrawn the request; libSceIpmi ud2s on any receive error but EAGAIN, so it is never delivered.
			if (!packet.client || IpmiScope::InspectPeerClient(server, packet.client, &peer_pid))
				break;
			LOGF("ORIGINAL_APP_IPMI_RECEIVE_WITHDRAWN server=%u client=%u pid=%d request=%u\n", server,
			     packet.client, Process::GetPid(), packet.request);
			packet = {};
			continue;
		}
		if (timeout != UINT32_MAX &&
		    std::chrono::steady_clock::now() - start >= std::chrono::microseconds(timeout))
			return timeout ? IPMI_FAIL("RECEIVE", handle, 0, KERNEL_ERROR_ETIMEDOUT)
			               : KERNEL_ERROR_EAGAIN;
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	if (!packet.client) {
		// 0x9ebce7e1: type 1 message -> kind 0xb0 from client -1, data buffer untouched
		if (packet.bytes.size() != 4 || Load<uint32_t>(packet.bytes.data()) != 1)
			return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_EIO);
		const uint64_t info[3] {0, 0xffffffff000000b0ull, handler};
		if (!Write(info_address, info, sizeof(info)))
			return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_EFAULT);
		received_kind = 0xb0;
		LOGF("ORIGINAL_APP_IPMI_RECEIVE server=%u client=-1 pid=%d request=%u type=b0 "
		     "method=00000000 bytes=0\n",
		     server, Process::GetPid(), packet.request);
		return OK;
	}
	ReceivedRequest receipt {server, packet.request};
	if (packet.bytes.size() < 4)
		return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_EIO);
	const auto kind = Load<uint32_t>(packet.bytes.data());
	std::vector<uint8_t> body;
	uint64_t             output_offset  = 0;
	int32_t              session_handle = 0;
	if (kind == 1) {
		if (packet.bytes.size() < 344 || Load<uint32_t>(packet.bytes.data() + 4) != peer_pid ||
		    Load<uint32_t>(packet.bytes.data() + 340) != packet.bytes.size() - 344)
			return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_EIO);
		body.assign(packet.bytes.begin() + 4, packet.bytes.end());
	} else if (kind == 3) {
		if (packet.bytes.size() != 4)
			return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_EIO);
		std::lock_guard lock(state_mutex);
		for (const auto& [id, entry]: sessions) {
			if (entry.server == server && entry.client == packet.client &&
			    entry.pid == Process::GetPid()) {
				if (!entry.requests.empty())
					return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_EBUSY);
				Append(&body, entry.object);
				break;
			}
		}
		if (body.empty())
			return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_ENOTCONN);
	} else if (kind == 0x41 || kind == 0x51 || kind == 0x43 || kind == 0x53) {
		// async 0x43/0x53: {handle@0, method@8, ticket@0xc, in_count@0x10, blobs@0x14}, inputs only
		const bool async_request = kind == 0x43 || kind == 0x53;
		if (packet.bytes.size() < 16)
			return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_EIO);
		const auto in_count  = Load<uint32_t>(packet.bytes.data() + (async_request ? 12 : 8));
		const auto out_count = async_request ? 0 : Load<uint32_t>(packet.bytes.data() + 12);
		if (in_count > 10 || out_count > 10)
			return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_EIO);
		uint64_t object = 0;
		{
			std::lock_guard lock(state_mutex);
			for (auto& [id, entry]: sessions) {
				if (entry.server == server && entry.client == packet.client &&
				    entry.pid == Process::GetPid()) {
					if (entry.requests.size() >= kOutstandingRequests)
						return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_EAGAIN);
					if (std::find(entry.requests.begin(), entry.requests.end(), packet.request) !=
					    entry.requests.end())
						return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_EBUSY);
					session_handle = id;
					object         = entry.object;
					entry.requests.push_back(packet.request);
					if (async_request) entry.async_inflight++;
					break;
				}
			}
		}
		if (!session_handle)
			return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_ENOTCONN);
		receipt.session = session_handle;
		Append(&body, object);
		if (!async_request) Append(&body, peer_pid);
		body.insert(body.end(), packet.bytes.begin() + 4, packet.bytes.end());
		size_t cursor = 16;
		for (uint32_t i = 0; i < in_count; ++i) {
			if (cursor + 4 > packet.bytes.size())
				return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_EIO);
			const auto length = Load<uint32_t>(packet.bytes.data() + cursor);
			if (length > packet.bytes.size() - cursor - 4)
				return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_EIO);
			cursor += 4 + length;
		}
		if (async_request) {
			if (cursor != packet.bytes.size())
				return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_EIO);
		} else {
			if (packet.bytes.size() - cursor != out_count * 4)
				return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_EIO);
			output_offset = (body.size() + 7) & ~size_t(7);
			size_t total  = output_offset;
			for (uint32_t i = 0; i < out_count; ++i) {
				const auto length = Load<uint32_t>(packet.bytes.data() + cursor + i * 4);
				if (length > kPacketLimit || total > kPacketLimit - length)
					return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_EMSGSIZE);
				total += length;
			}
			body.resize(total);
		}
	} else
		return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_ENOSYS);
	if (body.size() > capacity)
		return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_EMSGSIZE);
	const uint64_t info[3] {
	    output_offset, static_cast<uint64_t>(kind) | (static_cast<uint64_t>(packet.client) << 32),
	    handler};
	if (!Write(buffer, body.data(), body.size()) || !Write(info_address, info, sizeof(info)))
		return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_EFAULT);
	received_kind = kind;
	if (kind == 1)
		connecting = {server, packet.client, packet.request};
	else if (kind == 3)
		disconnecting = {server, packet.client, packet.request};
	else {
		std::lock_guard lock(state_mutex);
		auto            found = sessions.find(session_handle);
		if (found == sessions.end() ||
		    std::find(found->second.requests.begin(), found->second.requests.end(),
		              packet.request) == found->second.requests.end())
			return IPMI_FAIL("RECEIVE", handle, packet.request, KERNEL_ERROR_EBADF);
		serving.push_back({session_handle, server, packet.client, packet.request});
	}
	receipt.committed = true;
	LOGF("ORIGINAL_APP_IPMI_RECEIVE monotonic_ms=%llu server=%u client=%u pid=%u request=%u "
	     "type=%x method=%08x bytes=%zu\n",
	     IpmiMonotonicMs(), server, packet.client, peer_pid, packet.request, kind,
	     kind == 0x41 || kind == 0x51 || kind == 0x43 || kind == 0x53
	         ? Load<uint32_t>(packet.bytes.data() + 4)
			 : 0,
	     body.size());
	return OK;
}
int Invoke(int32_t handle, const uint8_t* args) {
	const auto                  method        = Load<uint32_t>(args);
	const auto                  in_count      = Load<uint32_t>(args + 4);
	const auto                  out_count     = Load<uint32_t>(args + 8);
	const auto                  inputs        = Load<uint64_t>(args + 16);
	const auto                  outputs       = Load<uint64_t>(args + 24);
	const auto                  method_result = Load<uint64_t>(args + 32);
	const auto                  flag          = Load<uint32_t>(args + 40);
	static std::atomic_uint32_t rnps_trace_count {0};
	const bool  rnps_trace      = std::getenv("KYTY_DIAGNOSTIC_SHELLUI_RNPS_INVOKE") != nullptr &&
	                              (method == 0x30009 || method == 0x3000e) &&
	                              rnps_trace_count.fetch_add(1) < 32;
	uint64_t    input_bytes     = 0;
	uint64_t    output_capacity = 0;
	const char* pointer_domain  = "not_checked";
	uint64_t    fault_address   = 0;
	uint64_t    fault_size      = 0;
	static std::atomic_uint32_t efault_count {0};
	auto        trace_rnps      = [&](const char* stage, int result, int index) {
		if (result == KERNEL_ERROR_EFAULT && fault_address != 0 && efault_count.fetch_add(1) < 64) {
			LOGF("ORIGINAL_APP_IPMI_INVOKE_EFAULT pid=%d handle=%d method=%08x stage=%s index=%d"
			     " address=%016llx size=%llu pointer_domain=%s\n",
			     Process::GetPid(), handle, method, stage, index,
			     static_cast<unsigned long long>(fault_address),
			     static_cast<unsigned long long>(fault_size), pointer_domain);
		}
		if (rnps_trace) {
			LOGF("SHELLUI_RNPS_IPMI_PROVENANCE pid=%d handle=%d method=%08x"
			     " in_count=%u out_count=%u flag=%u stage=%s index=%d"
			     " input_bytes=%llu output_capacity=%llu pointer_domain=%s"
			     " result=%08x\n",
			     Process::GetPid(), handle, method, in_count, out_count, flag, stage, index,
			     static_cast<unsigned long long>(input_bytes),
			     static_cast<unsigned long long>(output_capacity), pointer_domain,
			     static_cast<unsigned>(result));
		}
		return result;
	};
	if (in_count > 10 || out_count > 10)
		return IPMI_FAIL("INVOKE", handle, 0, trace_rnps("header_count", KERNEL_ERROR_EINVAL, -1));
	if (flag > 1)
		return IPMI_FAIL("INVOKE", handle, 0, trace_rnps("header_flag", KERNEL_ERROR_EINVAL, -1));
	if (!CanWriteInvokeSpan(method_result, 4)) {
		fault_address  = method_result;
		fault_size     = 4;
		pointer_domain = PointerDomain(method_result, 4, true);
		return IPMI_FAIL("INVOKE", handle, 0, trace_rnps("method_result", KERNEL_ERROR_EFAULT, -1));
	}
	std::vector<uint8_t> packet;
	// 0x9ee7aeb0: flag 0 is the raw form (ClientImpl 0x6a0), kind 0x51
	Append<uint32_t>(&packet, flag ? 0x41 : 0x51);
	Append(&packet, method);
	Append(&packet, in_count);
	Append(&packet, out_count);
	for (uint32_t i = 0; i < in_count; ++i) {
		uint64_t descriptor[2] {};
		if (inputs > UINT64_MAX - i * 16)
			return IPMI_FAIL(
			    "INVOKE", handle, 0,
			    trace_rnps("input_descriptor_overflow", KERNEL_ERROR_EFAULT, static_cast<int>(i)));
		if (!ReadInvokeSpan(inputs + i * 16, descriptor, sizeof(descriptor))) {
			fault_address  = inputs + i * 16;
			fault_size     = sizeof(descriptor);
			pointer_domain = PointerDomain(inputs + i * 16, sizeof(descriptor), false);
			return IPMI_FAIL(
			    "INVOKE", handle, 0,
			    trace_rnps("input_descriptor", KERNEL_ERROR_EFAULT, static_cast<int>(i)));
		}
		if (descriptor[1] > kPacketLimit || packet.size() + 4 + descriptor[1] > kPacketLimit) {
			LOGF("ORIGINAL_APP_IPMI_EMSGSIZE pid=%u handle=%d method=%08x site=input index=%u "
			     "len=%llu limit=%zu\n",
			     Process::GetPid(), handle, method, i,
			     static_cast<unsigned long long>(descriptor[1]), kPacketLimit);
			return IPMI_FAIL(
			    "INVOKE", handle, 0,
			    trace_rnps("input_length", KERNEL_ERROR_EMSGSIZE, static_cast<int>(i)));
		}
		input_bytes += descriptor[1];
		Append(&packet, static_cast<uint32_t>(descriptor[1]));
		const auto offset = packet.size();
		packet.resize(offset + descriptor[1]);
		if (!ReadInvokeSpan(descriptor[0], packet.data() + offset, descriptor[1])) {
			fault_address  = descriptor[0];
			fault_size     = descriptor[1];
			pointer_domain = PointerDomain(descriptor[0], descriptor[1], false);
			return IPMI_FAIL("INVOKE", handle, 0,
			                 trace_rnps("input_payload", KERNEL_ERROR_EFAULT, static_cast<int>(i)));
		}
	}
	// {ptr, capacity, size}, written length goes back at +16
	std::vector<std::array<uint64_t, 3>> out(out_count);
	size_t                               reply_size = 8 + out_count * 4;
	for (uint32_t i = 0; i < out_count; ++i) {
		if (outputs > UINT64_MAX - i * 24)
			return IPMI_FAIL(
			    "INVOKE", handle, 0,
			    trace_rnps("output_descriptor_overflow", KERNEL_ERROR_EFAULT, static_cast<int>(i)));
		if (!ReadInvokeSpan(outputs + i * 24, out[i].data(), 24)) {
			fault_address  = outputs + i * 24;
			fault_size     = 24;
			pointer_domain = PointerDomain(outputs + i * 24, 24, false);
			return IPMI_FAIL(
			    "INVOKE", handle, 0,
			    trace_rnps("output_descriptor", KERNEL_ERROR_EFAULT, static_cast<int>(i)));
		}
		if (!CanWriteInvokeSpan(out[i][0], out[i][1])) {
			fault_address  = out[i][0];
			fault_size     = out[i][1];
			pointer_domain = PointerDomain(out[i][0], out[i][1], true);
			return IPMI_FAIL("INVOKE", handle, 0,
			                 trace_rnps("output_buffer", KERNEL_ERROR_EFAULT, static_cast<int>(i)));
		}
		if (out[i][1] > kPacketLimit || reply_size > kPacketLimit - out[i][1]) {
			LOGF("ORIGINAL_APP_IPMI_EMSGSIZE pid=%u handle=%d method=%08x site=output index=%u "
			     "len=%llu reply=%zu limit=%zu\n",
			     Process::GetPid(), handle, method, i, static_cast<unsigned long long>(out[i][1]),
			     reply_size, kPacketLimit);
			return IPMI_FAIL(
			    "INVOKE", handle, 0,
			    trace_rnps("output_length", KERNEL_ERROR_EMSGSIZE, static_cast<int>(i)));
		}
		output_capacity += out[i][1];
		reply_size += out[i][1];
		Append(&packet, static_cast<uint32_t>(out[i][1]));
	}
	if (packet.size() > kPacketLimit) {
		LOGF("ORIGINAL_APP_IPMI_EMSGSIZE pid=%u handle=%d method=%08x site=packet len=%zu "
		     "limit=%zu\n",
		     Process::GetPid(), handle, method, packet.size(), kPacketLimit);
		return IPMI_FAIL("INVOKE", handle, 0,
		                 trace_rnps("packet_length", KERNEL_ERROR_EMSGSIZE, -1));
	}
	if (method == 0xce110007 || method == 0xce110040) {
		// SceSysCore ce110007 -> sub_5B6A0 (a3 userId, a7 caller pid), ce110040 -> sub_59520(mode)
		char words[96] = "-";
		if (packet.size() >= 20) {
			const auto len = Load<uint32_t>(packet.data() + 16);
			words[0]       = 0;
			for (uint32_t w = 0; w * 4 + 4 <= len && 20 + w * 4 + 4 <= packet.size() &&
			                     std::strlen(words) + 10 <= sizeof(words);
			     ++w)
				std::snprintf(words + std::strlen(words), sizeof(words) - std::strlen(words),
				              "%s%08x", w ? " " : "", Load<uint32_t>(packet.data() + 20 + w * 4));
		}
		LOGF("ORIGINAL_APP_IPMI_MBUS_ARGS monotonic_ms=%llu pid=%d method=%08x words=%s\n",
		     IpmiMonotonicMs(), Process::GetPid(), method, words);
	}
	Client client;
	{
		std::lock_guard lock(state_mutex);
		auto            found = clients.find(handle);
		if (found == clients.end() || found->second.pid != Process::GetPid())
			return IPMI_FAIL("INVOKE", handle, 0,
			                 trace_rnps("client_owner", KERNEL_ERROR_EBADF, -1));
		auto& entry = found->second;
		if (!entry.connected)
			return IPMI_FAIL("INVOKE", handle, 0,
			                 trace_rnps("client_connection", KERNEL_ERROR_ENOTCONN, -1));
		if (entry.busy) {
			LOGF("ORIGINAL_APP_IPMI_INVOKE_BUSY pid=%d handle=%d client=%u"
			     " attempted_method=%08x active_command=%03x active_invokes=%u"
			     " result=%08x\n",
			     Process::GetPid(), handle, entry.scope, method, entry.active_command,
			     entry.active_invokes, static_cast<unsigned>(KERNEL_ERROR_EBUSY));
			return IPMI_FAIL("INVOKE", handle, 0,
			                 trace_rnps("client_lifecycle", KERNEL_ERROR_EBUSY, -1));
		}
		client = entry;
		entry.active_invokes++;
	}
	trace_rnps("queue_ready", OK, -1);
	InvokeLease          lease(handle);
	uint32_t             request = 0;
	std::vector<uint8_t> reply;
	int rc = IpmiScope::QueueRequest(client.scope, packet.data(), packet.size(), &request)
	             ? OK
	             : KERNEL_ERROR_EAGAIN;
	if (rc == OK) rc = WaitReply(client.scope, request, UINT32_MAX, &reply);
	if (rc != OK && request) IpmiScope::CancelRequest(client.scope, request);
	if (rc == OK && reply.size() < 8) rc = KERNEL_ERROR_EIO;
	// count is checked on the client side (0x9ee7c6b0), not in 0x232
	if (rc == OK && Load<uint32_t>(reply.data() + 4) != out_count) rc = KERNEL_ERROR_EBADMSG;
	size_t cursor = 8;
	if (rc == OK) {
		for (uint32_t i = 0; i < out_count; ++i) {
			if (cursor + 4 > reply.size()) {
				rc = KERNEL_ERROR_EIO;
				break;
			}
			const auto length = Load<uint32_t>(reply.data() + cursor);
			cursor += 4;
			if (length > reply.size() - cursor) {
				rc = KERNEL_ERROR_EIO;
				break;
			}
			if (length > out[i][1]) {
				rc = KERNEL_ERROR_EBADMSG;
				break;
			}
			cursor += length;
		}
		if (rc == OK && cursor != reply.size()) rc = KERNEL_ERROR_EIO;
	}
	if (rc == OK) {
		cursor = 8;
		for (uint32_t i = 0; i < out_count; ++i) {
			const auto length = Load<uint32_t>(reply.data() + cursor);
			cursor += 4;
			out[i][2] = length;
			if (!WriteInvokeSpan(out[i][0], reply.data() + cursor, length)) {
				rc = KERNEL_ERROR_EFAULT;
				break;
			}
			cursor += length;
		}
		if (rc == OK && out_count && !WriteInvokeSpan(outputs, out.data(), out_count * 24))
			rc = KERNEL_ERROR_EFAULT;
		if (rc == OK && !WriteInvokeSpan(method_result, reply.data(), 4)) rc = KERNEL_ERROR_EFAULT;
	}
	lease.Complete(rc);
	LOGF("ORIGINAL_APP_IPMI_INVOKE monotonic_ms=%llu client=%u request=%u method=%08x "
	     "transport=%08x method_result=%08x\n",
	     IpmiMonotonicMs(), client.scope, request, method, static_cast<unsigned>(rc),
	     rc == OK ? Load<uint32_t>(reply.data()) : 0);
	return rc == OK ? OK : IPMI_FAIL("INVOKE", handle, request, rc);
}
// ClientImpl::invokeAsyncMethod (libSceIpmi 0x241)
// uap: +0 method, +4 eventId, +8 eventPattern, +0x10 numData, +0x18 DataInfo*, +0x20 pTicket, +0x28
// form. Ticket is copied out once queued, result comes later via the server's 0x242.
int InvokeAsync(int32_t handle, const uint8_t* args) {
	const auto method   = Load<uint32_t>(args);
	const auto event_id = Load<uint32_t>(args + 4);
	// ORed into the client's event flag at result time (slot+0x18), not a handler
	const auto event_pattern = Load<uint64_t>(args + 8);
	const auto num_data      = Load<uint32_t>(args + 16);
	const auto data_info     = Load<uint64_t>(args + 24);
	const auto p_ticket      = Load<uint64_t>(args + 32);
	const auto form          = Load<uint32_t>(args + 40);
	if (num_data > 10 || form > 1) return IPMI_FAIL("INVOKE_ASYNC", handle, 0, KERNEL_ERROR_EINVAL);
	std::vector<uint8_t> inputs;
	for (uint32_t i = 0; i < num_data; ++i) {
		uint64_t descriptor[2] {};
		if (data_info > UINT64_MAX - i * 16)
			return IPMI_FAIL("INVOKE_ASYNC", handle, 0, KERNEL_ERROR_EFAULT);
		if (!ReadInvokeSpan(data_info + i * 16, descriptor, sizeof(descriptor)))
			return IPMI_FAIL("INVOKE_ASYNC", handle, 0, KERNEL_ERROR_EFAULT);
		if (descriptor[1] > kPacketLimit || inputs.size() + 4 + descriptor[1] > kPacketLimit)
			return IPMI_FAIL("INVOKE_ASYNC", handle, 0, KERNEL_ERROR_EMSGSIZE);
		Append(&inputs, static_cast<uint32_t>(descriptor[1]));
		const auto offset = inputs.size();
		inputs.resize(offset + descriptor[1]);
		if (!ReadInvokeSpan(descriptor[0], inputs.data() + offset, descriptor[1]))
			return IPMI_FAIL("INVOKE_ASYNC", handle, 0, KERNEL_ERROR_EFAULT);
	}
	Client   client;
	uint32_t ticket = 0;
	{
		std::lock_guard lock(state_mutex);
		auto            found = clients.find(handle);
		if (found == clients.end() || found->second.pid != Process::GetPid())
			return IPMI_FAIL("INVOKE_ASYNC", handle, 0, KERNEL_ERROR_EBADF);
		auto& entry = found->second;
		if (!entry.connected) return IPMI_FAIL("INVOKE_ASYNC", handle, 0, KERNEL_ERROR_ENOTCONN);
		if (entry.busy) return IPMI_FAIL("INVOKE_ASYNC", handle, 0, KERNEL_ERROR_EBUSY);
		// conn+0x190 bound; 0xffffffff = no event
		if (event_id != 0xffffffff && event_id >= Load<uint32_t>(entry.params.data() + 0x140)) {
			LOGF("FIRST_FRAME_AUDIT IPMI_ASYNC_EVENT_INDEX pid=%d client=%u event=%u limit=%u\n",
			     entry.pid, entry.scope, event_id, Load<uint32_t>(entry.params.data() + 0x140));
			return IPMI_FAIL("INVOKE_ASYNC", handle, 0, KERNEL_ERROR_EINVAL);
		}
		client = entry;
		entry.active_invokes++;
		ticket            = entry.next_ticket;
		entry.next_ticket = ticket + 1 == 0xffff ? 0 : ticket + 1;
	}
	InvokeLease          lease(handle);
	std::vector<uint8_t> packet;
	Append<uint32_t>(&packet, form ? 0x43 : 0x53);
	Append(&packet, method);
	Append(&packet, ticket);
	Append(&packet, num_data);
	packet.insert(packet.end(), inputs.begin(), inputs.end());
	if (packet.size() > kPacketLimit)
		return IPMI_FAIL("INVOKE_ASYNC", handle, 0, KERNEL_ERROR_EMSGSIZE);
	uint32_t              request = 0;
	IpmiScope::AsyncIssue issue {event_id, ticket, event_pattern};
	bool                  table_full = false;
	int                   rc;
	if (IpmiScope::QueueRequest(client.scope, packet.data(), packet.size(), &request, &issue,
	                            &table_full)) {
		rc = Write(p_ticket, &ticket, sizeof(ticket)) ? OK : KERNEL_ERROR_EFAULT;
	} else if (table_full) {
		// kernel fails before the counter moves
		std::lock_guard lock(state_mutex);
		auto            found = clients.find(handle);
		if (found != clients.end()) found->second.next_ticket = ticket;
		rc = KERNEL_ERROR_EBUSY;
	} else {
		rc = KERNEL_ERROR_EAGAIN;
	}
	lease.Complete(rc);
	LOGF("ORIGINAL_APP_IPMI_INVOKE_ASYNC monotonic_ms=%llu client=%u request=%u method=%08x "
	     "event=%u ticket=%u pattern=%016llx transport=%08x queued=%u\n",
	     IpmiMonotonicMs(), client.scope, request, method, event_id, ticket,
	     static_cast<unsigned long long>(event_pattern), static_cast<unsigned>(rc),
	     request ? 1u : 0u);
	return rc == OK ? OK : IPMI_FAIL("INVOKE_ASYNC", handle, request, rc);
}
// sceIpmiMgrCompleteAsyncMethodDispatch (0x444), called after the app handler returns. Only frees
// the dispatch slot; the result goes through 0x242.
int CompleteAsyncDispatch(int32_t handle, const uint8_t* args) {
	const auto argument = Load<uint32_t>(args);
	// kid is a session handle, a server handle or the session's client scope id
	int32_t session_handle = 0;
	{
		std::lock_guard lock(state_mutex);
		auto            found = sessions.find(handle);
		if (found != sessions.end() && found->second.pid == Process::GetPid())
			session_handle = handle;
		else {
			const auto server = servers.find(handle);
			if (server != servers.end() && server->second.pid == Process::GetPid()) {
				for (auto it = serving.rbegin(); it != serving.rend(); ++it)
					if (it->server == server->second.scope) {
						session_handle = it->session;
						break;
					}
			}
			if (!session_handle) {
				for (auto it = serving.rbegin(); it != serving.rend(); ++it) {
					const auto session = sessions.find(it->session);
					if (session != sessions.end() && session->second.pid == Process::GetPid() &&
					    session->second.client == static_cast<uint32_t>(handle)) {
						session_handle = it->session;
						break;
					}
				}
			}
		}
	}
	if (!session_handle) return IPMI_FAIL("ASYNC_COMPLETE", handle, 0, KERNEL_ERROR_EBADF);
	const auto serving_it = std::find_if(
	    serving.rbegin(), serving.rend(),
	    [session_handle](const ServingContext& entry) { return entry.session == session_handle; });
	const ServingContext expected = serving_it == serving.rend() ? ServingContext {} : *serving_it;
	uint32_t             async_inflight = 0;
	{
		std::lock_guard lock(state_mutex);
		auto            found = sessions.find(session_handle);
		if (found == sessions.end()) {
			if (serving_it != serving.rend()) serving.erase(std::next(serving_it).base());
			return IPMI_FAIL("ASYNC_COMPLETE", handle, expected.request, KERNEL_ERROR_EBADF);
		}
		if (found->second.pid != Process::GetPid())
			return IPMI_FAIL("ASYNC_COMPLETE", handle, expected.request, KERNEL_ERROR_EBADF);
		if (!expected.request) return IPMI_FAIL("ASYNC_COMPLETE", handle, 0, KERNEL_ERROR_EINVAL);
		auto& session = found->second;
		if (session.server != expected.server || session.client != expected.client ||
		    std::find(session.requests.begin(), session.requests.end(), expected.request) ==
		        session.requests.end())
			return IPMI_FAIL("ASYNC_COMPLETE", handle, expected.request, KERNEL_ERROR_EBADF);
		if (!session.async_inflight)
			return IPMI_FAIL("ASYNC_COMPLETE", handle, expected.request, KERNEL_ERROR_EINVAL);
		session.requests.erase(
		    std::find(session.requests.begin(), session.requests.end(), expected.request));
		serving.erase(std::next(serving_it).base());
		async_inflight = --session.async_inflight;
	}
	LOGF("ORIGINAL_APP_IPMI_ASYNC_COMPLETE monotonic_ms=%llu server=%u client=%u request=%u "
	     "arg=%08x inflight=%u\n",
	     IpmiMonotonicMs(), expected.server, expected.client, expected.request, argument,
	     async_inflight);
	return OK;
}
// SessionImpl::sendInvokeAsyncMethodRes (0x242). uap {methodId@0, ticket@4, result@8,
// numOutData@0xc, blobs@0x10, flag@0x18}, blobs are {ptr, size}
int SendAsyncResult(int32_t handle, const uint8_t* args) {
	const auto method_id = Load<uint32_t>(args);
	const auto ticket    = Load<uint32_t>(args + 4);
	const auto result    = Load<uint32_t>(args + 8);
	const auto count     = Load<uint32_t>(args + 12);
	const auto descs     = Load<uint64_t>(args + 16);
	const auto flag      = Load<uint32_t>(args + 24);
	if (count > 10 || flag > 1) return IPMI_FAIL("ASYNC_RESULT", handle, 0, KERNEL_ERROR_EINVAL);
	std::vector<uint8_t> msg;
	for (uint32_t i = 0; i < count; ++i) {
		uint64_t descriptor[2] {};
		if (descs > UINT64_MAX - i * 16 || !Read(descs + i * 16, descriptor, sizeof(descriptor)))
			return IPMI_FAIL("ASYNC_RESULT", handle, 0, KERNEL_ERROR_EFAULT);
		if (descriptor[1] > kPacketLimit || msg.size() + 4 + descriptor[1] > kPacketLimit)
			return IPMI_FAIL("ASYNC_RESULT", handle, 0, KERNEL_ERROR_EMSGSIZE);
		Append(&msg, static_cast<uint32_t>(descriptor[1]));
		const auto offset = msg.size();
		msg.resize(offset + descriptor[1]);
		if (!Read(descriptor[0], msg.data() + offset, descriptor[1]))
			return IPMI_FAIL("ASYNC_RESULT", handle, 0, KERNEL_ERROR_EFAULT);
	}
	Session session;
	{
		std::lock_guard lock(state_mutex);
		auto            found = sessions.find(handle);
		if (found == sessions.end() || found->second.pid != Process::GetPid())
			return IPMI_FAIL("ASYNC_RESULT", handle, 0, KERNEL_ERROR_EBADF);
		session = found->second;
	}
	uint32_t event_index   = 0;
	uint64_t event_pattern = 0;
	if (!IpmiScope::PostAsyncResult(session.server, session.client, ticket, method_id, result,
	                                count, msg.data(), msg.size(), &event_index, &event_pattern))
		return IPMI_FAIL("ASYNC_RESULT", handle, 0, KERNEL_ERROR_EINVAL);
	// set even when the pattern is 0
	if (event_index != 0xffffffff)
		IpmiScope::SetClientEvent(session.server, session.client, event_index, event_pattern);
	LOGF("ORIGINAL_APP_IPMI_ASYNC_RESULT monotonic_ms=%llu server=%u client=%u ticket=%u "
	     "method=%08x result=%08x count=%u event=%u pattern=%016llx\n",
	     IpmiMonotonicMs(), session.server, session.client, ticket, method_id, result, count,
	     event_index, static_cast<unsigned long long>(event_pattern));
	return OK;
}
int Reply(int32_t handle, const uint8_t* args) {
	const auto method_result = Load<int32_t>(args);
	const auto count         = Load<uint32_t>(args + 4);
	const auto outputs       = Load<uint64_t>(args + 8);
	if (count > 10 || Load<uint32_t>(args + 16) > 1)
		return IPMI_FAIL("REPLY", handle, 0, KERNEL_ERROR_EINVAL);
	const auto serving_it =
	    std::find_if(serving.rbegin(), serving.rend(),
		             [handle](const ServingContext& entry) { return entry.session == handle; });
	const ServingContext expected = serving_it == serving.rend() ? ServingContext {} : *serving_it;
	Session              session;
	{
		std::lock_guard lock(state_mutex);
		auto            found = sessions.find(handle);
		if (found == sessions.end()) {
			if (serving_it != serving.rend()) serving.erase(std::next(serving_it).base());
			return IPMI_FAIL("REPLY", handle, expected.request, KERNEL_ERROR_EBADF);
		}
		if (found->second.pid != Process::GetPid())
			return IPMI_FAIL("REPLY", handle, expected.request, KERNEL_ERROR_EBADF);
		session = found->second;
	}
	if (!expected.request) return IPMI_FAIL("REPLY", handle, 0, KERNEL_ERROR_EINVAL);
	if (session.server != expected.server || session.client != expected.client ||
	    std::find(session.requests.begin(), session.requests.end(), expected.request) ==
	        session.requests.end())
		return IPMI_FAIL("REPLY", handle, expected.request, KERNEL_ERROR_EBADF);
	std::vector<uint8_t> reply;
	Append(&reply, method_result);
	Append(&reply, count);
	for (uint32_t i = 0; i < count; ++i) {
		uint64_t descriptor[3] {};
		if (outputs > UINT64_MAX - i * 24 ||
		    !Read(outputs + i * 24, descriptor, sizeof(descriptor)))
			return IPMI_FAIL("REPLY", handle, expected.request, KERNEL_ERROR_EFAULT);
		// 0x9ee7ce10 ignores capacity; the raw responder (0x3880) sends {ptr, len, len}
		if (descriptor[2] > kPacketLimit || reply.size() + 4 + descriptor[2] > kPacketLimit)
			return IPMI_FAIL("REPLY", handle, expected.request, KERNEL_ERROR_EMSGSIZE);
		Append(&reply, static_cast<uint32_t>(descriptor[2]));
		const auto offset = reply.size();
		reply.resize(offset + descriptor[2]);
		if (!Read(descriptor[0], reply.data() + offset, descriptor[2]))
			return IPMI_FAIL("REPLY", handle, expected.request, KERNEL_ERROR_EFAULT);
	}
	{
		std::lock_guard lock(state_mutex);
		auto            found = sessions.find(handle);
		if (found == sessions.end() || found->second.server != expected.server ||
		    found->second.client != expected.client) {
			serving.erase(std::next(serving_it).base());
			return IPMI_FAIL("REPLY", handle, expected.request, KERNEL_ERROR_EBADF);
		}
		auto&      requests = found->second.requests;
		const auto request  = std::find(requests.begin(), requests.end(), expected.request);
		if (request == requests.end()) {
			serving.erase(std::next(serving_it).base());
			return IPMI_FAIL("REPLY", handle, expected.request, KERNEL_ERROR_EBADF);
		}
		const bool sent =
		    IpmiScope::Reply(expected.server, expected.request, reply.data(), reply.size());
		requests.erase(request);
		serving.erase(std::next(serving_it).base());
		if (!sent) return IPMI_FAIL("REPLY", handle, expected.request, KERNEL_ERROR_ECONNRESET);
	}
	LOGF("ORIGINAL_APP_IPMI_REPLY monotonic_ms=%llu server=%u client=%u request=%u "
	     "method_result=%08x outputs=%u\n",
	     IpmiMonotonicMs(), expected.server, expected.client, expected.request,
	     static_cast<unsigned>(method_result), count);
	return OK;
}
int Disconnect(int32_t handle, const uint8_t* args) {
	const auto completion = Load<uint64_t>(args);
	if (!Memory::CanWriteGuest(reinterpret_cast<void*>(completion), 4)) return KERNEL_ERROR_EFAULT;
	Client client;
	{
		std::lock_guard lock(state_mutex);
		auto            found = clients.find(handle);
		if (found == clients.end() || found->second.pid != Process::GetPid())
			return KERNEL_ERROR_EBADF;
		if (!found->second.connected) return KERNEL_ERROR_ENOTCONN;
		if (found->second.busy || found->second.active_invokes != 0) return KERNEL_ERROR_EBUSY;
		found->second.busy           = true;
		found->second.active_command = 0x310;
		client                       = found->second;
	}
	const uint32_t       kind    = 3;
	uint32_t             request = 0;
	std::vector<uint8_t> reply;
	int                  rc =
	    IpmiScope::QueueRequest(client.scope, reinterpret_cast<const uint8_t*>(&kind), 4, &request)
	        ? OK
	        : KERNEL_ERROR_EAGAIN;
	if (rc == OK) rc = WaitReply(client.scope, request, UINT32_MAX, &reply);
	if (rc != OK && request) IpmiScope::CancelRequest(client.scope, request);
	if (rc == OK && reply.size() != 4) rc = KERNEL_ERROR_EIO;
	if (rc == OK && !Write(completion, reply.data(), 4)) rc = KERNEL_ERROR_EFAULT;
	if (rc == OK) {
		const auto cancelled = IpmiScope::CancelClientEvents(client.scope);
		if (cancelled != IpmiScope::EventStatus::Matched) rc = EventStatusResult(cancelled);
	} else if (rc == KERNEL_ERROR_ECONNRESET) {
		IpmiScope::CancelClientEvents(client.scope);
	}
	{
		std::lock_guard lock(state_mutex);
		auto            found = clients.find(handle);
		if (found != clients.end()) {
			found->second.busy           = false;
			found->second.active_command = 0;
			if (rc == OK || rc == KERNEL_ERROR_ECONNRESET) found->second.connected = false;
		}
	}
	LOGF("ORIGINAL_APP_IPMI_DISCONNECT client=%u request=%u transport=%08x\n", client.scope,
	     request, static_cast<unsigned>(rc));
	return rc;
}
// trySendMsg (0x254) / sendMsg (0x253). libSceIpmi maps 0x80020023 -> 0x8002003c, 0x80020002 ->
// 0x80020003
int SendUserMessage(int32_t handle, const uint8_t* args, bool wait) {
	const auto              index           = Load<uint32_t>(args);
	const auto              buffer          = Load<uint64_t>(args + 8);
	const auto              size            = Load<uint64_t>(args + 16);
	const auto              timeout_address = wait ? Load<uint64_t>(args + 24) : 0;
	std::array<uint8_t, 16> head {};
	const auto              head_len = static_cast<size_t>(std::min<uint64_t>(size, head.size()));
	char                    head_hex[33] = "-";
	if (head_len && buffer && Read(buffer, head.data(), head_len)) {
		for (size_t i = 0; i < head_len; ++i)
			std::snprintf(head_hex + i * 2, 3, "%02x", head[i]);
	}
	const auto fail = [&](int code) {
		LOGF(
		    "ORIGINAL_APP_IPMI_SEND_MSG pid=%d handle=%d index=%u bytes=%llu head=%s result=%08x\n",
		    Process::GetPid(), handle, index, static_cast<unsigned long long>(size), head_hex,
		    static_cast<unsigned>(code));
		return code;
	};
	if (size == 0 || !buffer) return fail(KERNEL_ERROR_EINVAL);
	if (size > 0x7fff8) return fail(KERNEL_ERROR_ENOMEM);
	uint32_t timeout = UINT32_MAX;
	if (wait && !Timeout(timeout_address, &timeout)) return fail(KERNEL_ERROR_EFAULT);
	std::vector<uint8_t> bytes(size);
	if (!Read(buffer, bytes.data(), size)) return fail(KERNEL_ERROR_EFAULT);
	Session session;
	{
		std::lock_guard lock(state_mutex);
		auto            found = sessions.find(handle);
		if (found == sessions.end() || found->second.pid != Process::GetPid())
			return fail(KERNEL_ERROR_EBADF);
		session = found->second;
	}
	bool trace_sends = false;
	bool send_logged = false;
	{
		std::lock_guard lock(state_mutex);
		for (const auto& entry: servers)
			if (entry.second.scope == session.server) {
				trace_sends = entry.second.name == "SceUserService";
				break;
			}
	}
	const auto start = std::chrono::steady_clock::now();
	for (;;) {
		const auto status = IpmiScope::QueueUserMessage(session.server, session.client, index,
		                                                bytes.data(), bytes.size());
		if (trace_sends && !send_logged) {
			send_logged = true;
			LOGF("ORIGINAL_APP_IPMI_USERMSG_SEND monotonic_ms=%llu pid=%d server=%u client=%u "
			     "index=%u bytes=%zu payload=%s status=%d\n",
			     IpmiMonotonicMs(), Process::GetPid(), session.server, session.client, index,
			     bytes.size(), head_hex, static_cast<int>(status));
		}
		if (status == IpmiScope::MessageStatus::Queued) {
			if (wait) {
				const uint32_t remaining = RemainingTimeout(start, timeout);
				Write(timeout_address, &remaining, sizeof(remaining));
			}
			LOGF("ORIGINAL_APP_IPMI_SEND_MSG pid=%d handle=%d server=%u client=%u index=%u "
			     "bytes=%zu head=%s result=0\n",
			     session.pid, handle, session.server, session.client, index, bytes.size(),
			     head_hex);
			return OK;
		}
		if (status == IpmiScope::MessageStatus::Missing) return fail(static_cast<int>(0x80020002u));
		if (status == IpmiScope::MessageStatus::Unavailable) return fail(KERNEL_ERROR_ENOSYS);
		if (status == IpmiScope::MessageStatus::Invalid) return fail(KERNEL_ERROR_EINVAL);
		if (status == IpmiScope::MessageStatus::OverCapacity) return fail(KERNEL_ERROR_ENOMEM);
		if (!wait || (timeout != UINT32_MAX && std::chrono::steady_clock::now() - start >=
		                                           std::chrono::microseconds(timeout))) {
			if (wait) {
				const uint32_t remaining = RemainingTimeout(start, timeout);
				Write(timeout_address, &remaining, sizeof(remaining));
			}
			return fail(static_cast<int>(0x80020023u));
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}
// tryGetMsg (0x252) / getMsg (0x251). uap {index, buf, &written_size, buf_size, timeout*}
int GetUserMessage(int32_t handle, const uint8_t* args, bool wait) {
	const auto index           = Load<uint32_t>(args);
	const auto buffer          = Load<uint64_t>(args + 8);
	const auto meta_address    = Load<uint64_t>(args + 16);
	const auto capacity        = Load<uint64_t>(args + 24);
	const auto timeout_address = wait ? Load<uint64_t>(args + 32) : 0;
	if (capacity > SIZE_MAX ||
	    !Memory::CanWriteGuest(reinterpret_cast<void*>(buffer), capacity ? capacity : 1) ||
	    !Memory::CanWriteGuest(reinterpret_cast<void*>(meta_address), 8))
		return IPMI_FAIL("GET_MSG", handle, 0, KERNEL_ERROR_EFAULT);
	uint32_t timeout = UINT32_MAX;
	if (wait && !Timeout(timeout_address, &timeout))
		return IPMI_FAIL("GET_MSG", handle, 0, KERNEL_ERROR_EFAULT);
	Client client;
	{
		std::lock_guard lock(state_mutex);
		auto            found = clients.find(handle);
		if (found == clients.end() || found->second.pid != Process::GetPid())
			return IPMI_FAIL("GET_MSG", handle, 0, KERNEL_ERROR_EBADF);
		if (!found->second.connected) return IPMI_FAIL("GET_MSG", handle, 0, KERNEL_ERROR_ENOTCONN);
		client = found->second;
	}
	const auto start = std::chrono::steady_clock::now();
	for (;;) {
		std::vector<uint8_t> msg;
		const auto status = IpmiScope::ReadUserMessage(client.scope, index, capacity, &msg);
		if (status == IpmiScope::FetchStatus::Got) {
			const uint64_t meta = msg.size();
			if (!Write(buffer, msg.data(), msg.size()) || !Write(meta_address, &meta, sizeof(meta)))
				return IPMI_FAIL("GET_MSG", handle, 0, KERNEL_ERROR_EFAULT);
			if (wait) {
				const uint32_t remaining = RemainingTimeout(start, timeout);
				Write(timeout_address, &remaining, sizeof(remaining));
			}
			LOGF("ORIGINAL_APP_IPMI_GET_MSG pid=%d handle=%d client=%u index=%u bytes=%zu "
			     "result=0\n",
			     client.pid, handle, client.scope, index, msg.size());
			if (client.name == "SceUserService") {
				char       msg_hex[33] = "-";
				const auto msg_len     = std::min<size_t>(msg.size(), 16);
				for (size_t i = 0; i < msg_len; ++i)
					std::snprintf(msg_hex + i * 2, 3, "%02x", msg[i]);
				LOGF("ORIGINAL_APP_IPMI_USERMSG_RECV monotonic_ms=%llu pid=%d server=%u client=%u "
				     "index=%u bytes=%zu payload=%s\n",
				     IpmiMonotonicMs(), client.pid, client.server, client.scope, index, msg.size(),
				     msg_hex);
			}
			return OK;
		}
		// too small: message stays queued
		if (status == IpmiScope::FetchStatus::TooBig)
			return IPMI_FAIL("GET_MSG", handle, 0, KERNEL_ERROR_ENOMEM);
		if (status == IpmiScope::FetchStatus::Missing)
			return IPMI_FAIL("GET_MSG", handle, 0, KERNEL_ERROR_ECONNRESET);
		if (status == IpmiScope::FetchStatus::Unavailable)
			return IPMI_FAIL("GET_MSG", handle, 0, KERNEL_ERROR_ENOSYS);
		if (!wait || (timeout != UINT32_MAX && std::chrono::steady_clock::now() - start >=
		                                           std::chrono::microseconds(timeout))) {
			if (wait) {
				const uint32_t remaining = RemainingTimeout(start, timeout);
				Write(timeout_address, &remaining, sizeof(remaining));
			}
			return static_cast<int>(0x80020023u);
		}
		if (!IpmiScope::WaitClientEventHint(client.scope, 20))
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}
// 0x255 is a kernel stub returning internal 0x4e; the guest wrapper turns it into 0x8002004e.
int FlushUserMessage(int32_t, const uint8_t*) {
	return static_cast<int>(0x8002004eu);
}
// 0x243 syscallReceiveInvokeAsyncMethodRes (ClientImpl vtable +0x68), non-blocking.
// No ticket: EINVAL. Empty: 0x80020023. Header or descriptor mismatch: 0x80020059, message left
// queued
int ReceiveAsyncResult(int32_t handle, const uint8_t* args) {
	const auto selector       = Load<uint32_t>(args);
	const auto ticket         = Load<uint32_t>(args + 4);
	const auto result_address = Load<uint64_t>(args + 8);
	const auto out_count      = Load<uint32_t>(args + 16);
	const auto out_descs      = Load<uint64_t>(args + 24);
	const auto flag           = Load<uint32_t>(args + 32);
	if (ticket == 0xffffffff || out_count > 10 || flag > 1 || !result_address ||
	    (out_count && !out_descs))
		return IPMI_FAIL("RECV_ASYNC_RESULT", handle, 0, KERNEL_ERROR_EINVAL);
	if (!CanWriteInvokeSpan(result_address, 4))
		return IPMI_FAIL("RECV_ASYNC_RESULT", handle, 0, KERNEL_ERROR_EFAULT);
	std::vector<std::array<uint64_t, 3>> out(out_count);
	std::vector<uint64_t>                caps(out_count);
	for (uint32_t i = 0; i < out_count; ++i) {
		if (out_descs > UINT64_MAX - i * 24 ||
		    !ReadInvokeSpan(out_descs + i * 24, out[i].data(), 24) ||
		    !CanWriteInvokeSpan(out[i][0], out[i][1]))
			return IPMI_FAIL("RECV_ASYNC_RESULT", handle, 0, KERNEL_ERROR_EFAULT);
		caps[i] = out[i][1];
	}
	Client client;
	{
		std::lock_guard lock(state_mutex);
		auto            found = clients.find(handle);
		if (found == clients.end() || found->second.pid != Process::GetPid())
			return IPMI_FAIL("RECV_ASYNC_RESULT", handle, 0, KERNEL_ERROR_EBADF);
		if (!found->second.connected)
			return IPMI_FAIL("RECV_ASYNC_RESULT", handle, 0, KERNEL_ERROR_ENOTCONN);
		client = found->second;
	}
	uint32_t             result = 0;
	std::vector<uint8_t> payload;
	const auto status = IpmiScope::FetchAsyncResult(client.scope, selector, ticket, out_count,
	                                                caps.data(), &result, &payload);
	int        rc     = OK;
	if (status == IpmiScope::AsyncFetchStatus::Missing)
		rc = KERNEL_ERROR_EINVAL;
	else if (status == IpmiScope::AsyncFetchStatus::Empty)
		rc = static_cast<int>(0x80020023u);
	else if (status == IpmiScope::AsyncFetchStatus::Mismatch) {
		LOGF("ORIGINAL_APP_IPMI_ASYNC_MISMATCH monotonic_ms=%llu client=%u sel=%08x ticket=%u "
		     "count=%u kernel_would_raise_signo=a0020320\n",
		     IpmiMonotonicMs(), client.scope, selector, ticket, out_count);
		rc = KERNEL_ERROR_EBADMSG;
	} else if (status != IpmiScope::AsyncFetchStatus::Got)
		rc = KERNEL_ERROR_EBADF;
	if (rc == OK) {
		size_t cursor = 0;
		for (uint32_t i = 0; i < out_count; ++i) {
			const auto length = Load<uint32_t>(payload.data() + cursor);
			cursor += 4;
			out[i][2] = length;
			if (!WriteInvokeSpan(out[i][0], payload.data() + cursor, length)) {
				rc = KERNEL_ERROR_EFAULT;
				break;
			}
			cursor += length;
		}
		if (rc == OK && out_count && !WriteInvokeSpan(out_descs, out.data(), out_count * 24))
			rc = KERNEL_ERROR_EFAULT;
		if (rc == OK && !WriteInvokeSpan(result_address, &result, sizeof(result)))
			rc = KERNEL_ERROR_EFAULT;
	}
	LOGF("ORIGINAL_APP_IPMI_RECV_ASYNC_RESULT monotonic_ms=%llu client=%u sel=%08x ticket=%u "
	     "count=%u transport=%08x result=%08x\n",
	     IpmiMonotonicMs(), client.scope, selector, ticket, out_count, static_cast<unsigned>(rc),
	     result);
	return rc == OK ? OK : IPMI_FAIL("RECV_ASYNC_RESULT", handle, 0, rc);
}
// Caller holds state_mutex.
bool OwnsSysAvServer(int pid, uint32_t scope) {
	return std::any_of(servers.begin(), servers.end(), [&](const auto& item) {
		const auto& server = item.second;
		return server.pid == pid && server.scope == scope && server.name == "SceSysAvControlIpc";
	});
}
} // namespace

bool ValidateCurrentAuthorizationPeer(int target_pid, uint32_t* host_pid, uint64_t* host_birth) {
	if (target_pid <= 0 || received_kind != 1 || !connecting.request ||
	    !connecting.authorization_session ||
	    connecting.authorization_peer != static_cast<uint32_t>(target_pid))
		return false;
	const int  pid           = Process::GetPid();
	const auto expected      = connecting;
	auto       state_matches = [&] {
		std::lock_guard lock(state_mutex);
		const bool      server_matches = OwnsSysAvServer(pid, expected.server);
		const auto      session        = sessions.find(expected.authorization_session);
		return server_matches && session != sessions.end() && session->second.pid == pid &&
		       session->second.server == expected.server &&
		       session->second.client == expected.client && session->second.requests.empty();
	};
	if (!state_matches()) return false;
	uint32_t peer = 0;
	if (!IpmiScope::IsReceivedRequest(expected.server, expected.client, expected.request) ||
	    !IpmiScope::InspectPeerClient(expected.server, expected.client, &peer, host_pid,
	                                  host_birth) ||
	    peer != static_cast<uint32_t>(target_pid))
		return false;
	return connecting.server == expected.server && connecting.client == expected.client &&
	       connecting.request == expected.request &&
	       connecting.authorization_session == expected.authorization_session &&
	       connecting.authorization_peer == expected.authorization_peer && state_matches();
}

// only the sender of the request this thread is serving, rechecked against the shared queue
bool ValidateCurrentRequestPeer(int target_pid, uint32_t* host_pid, uint64_t* host_birth) {
	if (target_pid <= 0 || serving.empty()) return false;
	const int  pid      = Process::GetPid();
	const auto expected = serving.back();
	{
		std::lock_guard lock(state_mutex);
		const auto      session = sessions.find(expected.session);
		if (!OwnsSysAvServer(pid, expected.server) || session == sessions.end() ||
		    session->second.pid != pid || session->second.server != expected.server ||
		    session->second.client != expected.client ||
		    std::find(session->second.requests.begin(), session->second.requests.end(),
		              expected.request) == session->second.requests.end())
			return false;
	}
	uint32_t peer = 0;
	return IpmiScope::IsReceivedRequest(expected.server, expected.client, expected.request) &&
	       IpmiScope::InspectPeerClient(expected.server, expected.client, &peer, host_pid,
	                                    host_birth) &&
	       peer == static_cast<uint32_t>(target_pid);
}

bool ValidateCurrentRemotePeer(int target_pid, uint32_t* host_pid, uint64_t* host_birth) {
	return ValidateCurrentAuthorizationPeer(target_pid, host_pid, host_birth) ||
	       ValidateCurrentRequestPeer(target_pid, host_pid, host_birth);
}

// pid records are keyed by guest pid only, so match the host process too
bool FindCurrentRemotePeer(int target_pid, Process::PeerProcess* peer) {
	uint32_t host_pid   = 0;
	uint64_t host_birth = 0;
	return ValidateCurrentRemotePeer(target_pid, &host_pid, &host_birth) &&
	       Process::FindPeerByPid(target_pid, peer) && peer->host_pid == host_pid &&
	       peer->host_birth == host_birth && ValidateCurrentRemotePeer(target_pid);
}

bool TryCall(uint32_t command, int32_t handle, int32_t* result, void* args, size_t size,
             uint64_t magic, int* status) {
	if (!std::getenv("KYTY_DIAGNOSTIC_ORIGINAL_SYSCORE_APP_IPMI")) return false;
	if (command == 0x10) {
		TraceCall(static_cast<uint32_t>(handle), result, args, size, status);
		return true;
	}
	const int pid     = Process::GetPid();
	bool      managed = (static_cast<uint32_t>(handle) & 0x70000000) != 0 || command == 0 ||
	                    command == 2 || command == 0x46a || command == 0x46b;
	if (command == 4 || command == 0x212 || command == 0x444 || command == 0x468) managed = true;
	if (command == 0x222 && disconnecting.request) managed = true;
	if (!managed) return false;
	// 0x468 writes *result last
	if (command != 0x468 && !Memory::CanWriteGuest(result, sizeof(*result))) {
		*Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
		*status                = -1;
		return true;
	}
	int                     rc = KERNEL_ERROR_ENOSYS;
	std::array<uint8_t, 64> local {};
	(void)magic;
	// 0x9ebccd80: 0x40 byte copyin, larger gets 0x800e0001
	// XXX: only 0x468 returns a failed copyin as errno, the rest still put EFAULT in *result
	if ((command == 0x202 || command == 0x468) && size > local.size())
		rc = static_cast<int>(0x800e0001u);
	else if (command != 0x202 && command != 0x468 && size > 48)
		rc = KERNEL_ERROR_EINVAL;
	else if (!Read(reinterpret_cast<uint64_t>(args), local.data(), size)) {
		rc = KERNEL_ERROR_EFAULT;
		if (command == 0x468) {
			*Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
			*status                = -1;
			return true;
		}
	} else if (command == 0 || command == 2)
		rc = size == 24 ? Create(command, local.data()) : KERNEL_ERROR_EINVAL;
	else if (command == 4) {
		uint64_t params[2] {};
		uint32_t peer = 0;
		if (size != 16 || handle != -1 || !connecting.request)
			rc = KERNEL_ERROR_EINVAL;
		else if (!IpmiScope::InspectPeerClient(connecting.server, connecting.client, &peer) ||
		         !IpmiScope::IsReceivedRequest(connecting.server, connecting.client,
		                                       connecting.request))
			rc = KERNEL_ERROR_ECONNRESET;
		else if (!Read(Load<uint64_t>(local.data() + 8), params, sizeof(params)))
			rc = KERNEL_ERROR_EFAULT;
		// 0x9e787610 takes params[0] <= 16 (libSceIpmi sends 16); params[1] is the 0x468 user data
		else if (params[0] != 16 || !Load<uint64_t>(local.data()))
			rc = KERNEL_ERROR_EINVAL;
		else {
			std::lock_guard lock(state_mutex);
			bool            duplicate = false;
			for (const auto& [id, entry]: sessions) {
				if (entry.server == connecting.server && entry.client == connecting.client)
					duplicate = true;
			}
			if (duplicate)
				rc = KERNEL_ERROR_EEXIST;
			else {
				rc = 0x30000000 | next_session++;
				sessions.emplace(rc, Session {pid,
				                              connecting.server,
				                              connecting.client,
				                              Load<uint64_t>(local.data()),
				                              {},
				                              params[1]});
			}
			LOGF("ORIGINAL_APP_IPMI_SESSION pid=%d handle=%d server=%u client=%u object=%016llx\n",
			     pid, rc, connecting.server, connecting.client,
			     static_cast<unsigned long long>(Load<uint64_t>(local.data())));
		}
	} else if (command == 0x212) {
		if (size != 4 || !connecting.request || static_cast<uint32_t>(handle) != connecting.client)
			rc = KERNEL_ERROR_EINVAL;
		else {
			rc = IpmiScope::Reply(connecting.server, connecting.request, local.data(), 4)
			         ? OK
			         : KERNEL_ERROR_ECONNRESET;
			// session value, negative rejects
			if (rc != OK || Load<int32_t>(local.data()) < 0) {
				std::lock_guard lock(state_mutex);
				for (auto it = sessions.begin(); it != sessions.end();) {
					if (it->second.server == connecting.server &&
					    it->second.client == connecting.client)
						it = sessions.erase(it);
					else
						++it;
				}
			}
			connecting = {};
		}
	} else if (command == 0x222 && disconnecting.request) {
		if (size != 4 || static_cast<uint32_t>(handle) != disconnecting.client)
			rc = KERNEL_ERROR_EINVAL;
		else {
			rc = IpmiScope::Reply(disconnecting.server, disconnecting.request, local.data(), 4)
			         ? OK
			         : KERNEL_ERROR_ECONNRESET;
			disconnecting = {};
		}
	} else if (command == 0x202) {
		// 0x9ef57e60: args before handle, then type 1 to the caller's own server, anything else
		// ENOENT. *result untouched on error
		uint32_t server = 0, request = 0;
		{
			std::lock_guard lock(state_mutex);
			auto            found = servers.find(handle);
			if (found != servers.end() && found->second.pid == pid) server = found->second.scope;
		}
		bool missing = false;
		if (Load<int32_t>(local.data()) != 1 || Load<uint64_t>(local.data() + 8) ||
		    Load<uint64_t>(local.data() + 16))
			rc = KERNEL_ERROR_EINVAL;
		else if (!server)
			rc = KERNEL_ERROR_ENOENT;
		else if (!IpmiScope::Enabled())
			rc = KERNEL_ERROR_ENOSYS;
		else if (IpmiScope::QueueServerEvent(server, 1, &request, &missing))
			rc = OK;
		else
			rc = missing ? KERNEL_ERROR_ENOENT : KERNEL_ERROR_ENOMEM;
		LOGF("ORIGINAL_APP_IPMI_SERVER_POST handle=%d pid=%d server=%u request=%u bytes=%zu "
		     "rc=%08x\n",
		     handle, pid, server, request, size, static_cast<unsigned>(rc));
		if (rc != OK) {
			*Posix::GetErrorAddr() = KernelToPosix(rc);
			*status                = -1;
			return true;
		}
	} else if (command == 0x468) {
		// 0x9ebd05a0: own session handle else ENOENT, including after cmd 5
		// XXX: behaviour after a bare client disconnect is unverified, the only 0x10000 setter
		// found is 0x9e688940
		bool     found     = false;
		uint64_t user_data = 0;
		{
			std::lock_guard lock(state_mutex);
			auto            session = sessions.find(handle);
			if (session != sessions.end() && session->second.pid == pid) {
				found     = true;
				user_data = session->second.user_data;
			}
		}
		if (!found)
			rc = KERNEL_ERROR_ENOENT;
		else
			rc = Write(Load<uint64_t>(local.data()), &user_data, sizeof(user_data))
			         ? OK
			         : KERNEL_ERROR_EFAULT;
		LOGF("ORIGINAL_APP_IPMI_SESSION_USER_DATA handle=%d pid=%d bytes=%zu rc=%08x\n", handle,
		     pid, size, static_cast<unsigned>(rc));
		if (rc != OK) {
			*Posix::GetErrorAddr() = KernelToPosix(rc);
			*status                = -1;
			return true;
		}
	} else {
		bool       owned_server = false, owned_client = false, owned_session = false,
		           session_client = false;
		const bool lifecycle_diagnostic =
		    command == 0x254 && std::getenv("KYTY_DIAGNOSTIC_APP_KILL_LIFECYCLE") != nullptr;
		Session lifecycle {};
		bool    lifecycle_found = false;
		{
			std::lock_guard lock(state_mutex);
			auto            s = servers.find(handle);
			auto            c = clients.find(handle);
			auto            p = sessions.find(handle);
			owned_server      = s != servers.end() && s->second.pid == pid;
			owned_client      = c != clients.end() && c->second.pid == pid;
			owned_session     = p != sessions.end() && p->second.pid == pid;
			// 0x444 passes the client scope id
			for (const auto& [id, entry]: sessions)
				if (entry.pid == pid && entry.client == static_cast<uint32_t>(handle))
					session_client = true;
			if (lifecycle_diagnostic && p != sessions.end()) {
				lifecycle       = p->second;
				lifecycle_found = true;
			}
		}
		uint32_t   lifecycle_peer = 0;
		const bool lifecycle_peer_known =
		    lifecycle_found &&
		    IpmiScope::InspectPeerClient(lifecycle.server, lifecycle.client, &lifecycle_peer,
			                             nullptr, nullptr, false);
		if (command == 0x490)
			rc = size == 40 ? ClientEvent(handle, local.data(), true) : KERNEL_ERROR_EINVAL;
		else if (command == 0x491)
			rc = size == 32 ? ClientEvent(handle, local.data(), false) : KERNEL_ERROR_EINVAL;
		else if (!(owned_server || owned_client || owned_session || session_client))
			rc = KERNEL_ERROR_EBADF;
		else if ((command == 0x46a || command == 0x46b) && (owned_server || owned_client)) {
			// 0x46a/0x46b: same name lookup
			std::array<char, 32> name {};
			{
				std::lock_guard lock(state_mutex);
				auto            s = servers.find(handle);
				auto            c = clients.find(handle);
				if (s == servers.end() && c == clients.end()) {
					rc      = KERNEL_ERROR_EBADF;
					*status = Write(reinterpret_cast<uint64_t>(result), &rc, 4) ? OK : -1;
					return true;
				}
				const auto& source = s != servers.end() ? s->second.name : c->second.name;
				std::memcpy(name.data(), source.data(), std::min(source.size(), name.size() - 1));
			}
			rc = size != 8 ? KERNEL_ERROR_EINVAL
			     : Write(Load<uint64_t>(local.data()), name.data(), name.size())
			         ? OK
			         : KERNEL_ERROR_EFAULT;
		} else if (command == 0x400 && owned_client)
			rc = size == 32 ? Connect(handle, local.data()) : KERNEL_ERROR_EINVAL;
		else if (command == 0x310 && owned_client)
			rc = size == 8 ? Disconnect(handle, local.data()) : KERNEL_ERROR_EINVAL;
		else if (command == 0x201 && owned_server)
			rc = size == 32 ? Receive(handle, local.data()) : KERNEL_ERROR_EINVAL;
		else if (command == 0x320 && owned_client)
			rc = size == 48 ? Invoke(handle, local.data()) : KERNEL_ERROR_EINVAL;
		else if (command == 0x241 && owned_client)
			rc = size == 48 ? InvokeAsync(handle, local.data()) : KERNEL_ERROR_EINVAL;
		else if (command == 0x232 && owned_session)
			rc = size == 24 ? Reply(handle, local.data()) : KERNEL_ERROR_EINVAL;
		else if (command == 0x444 && (owned_session || owned_server || session_client))
			rc = size == 4 ? CompleteAsyncDispatch(handle, local.data()) : KERNEL_ERROR_EINVAL;
		else if (command == 0x242 && owned_session)
			rc = size == 32 ? SendAsyncResult(handle, local.data()) : KERNEL_ERROR_EINVAL;
		else if (command == 0x493 && owned_session)
			rc = size == 16 ? SetSessionEvent(handle, local.data()) : KERNEL_ERROR_EINVAL;
		else if (command == 0x254 && owned_session)
			rc = size == 24 ? SendUserMessage(handle, local.data(), false) : KERNEL_ERROR_EINVAL;
		else if (command == 0x253 && owned_session)
			rc = size == 32 ? SendUserMessage(handle, local.data(), true) : KERNEL_ERROR_EINVAL;
		else if (command == 0x255 && owned_session)
			rc = size == 4 ? FlushUserMessage(handle, local.data()) : KERNEL_ERROR_EINVAL;
		else if (command == 0x252 && owned_client)
			rc = size == 32 ? GetUserMessage(handle, local.data(), false) : KERNEL_ERROR_EINVAL;
		else if (command == 0x251 && owned_client)
			rc = size == 40 ? GetUserMessage(handle, local.data(), true) : KERNEL_ERROR_EINVAL;
		else if (command == 0x243 && owned_client)
			rc = size == 40 ? ReceiveAsyncResult(handle, local.data()) : KERNEL_ERROR_EINVAL;
		else if ((command == 0x463 || command == 0x464) && owned_session) {
			// SessionGetClientAppId (0x463), GetClientProcTypeBySessionKid (0x464): {u64 out_ptr}
			// -> u32
			Session session;
			{
				std::lock_guard lock(state_mutex);
				auto            found = sessions.find(handle);
				if (found != sessions.end()) session = found->second;
			}
			uint32_t peer  = 0;
			int32_t  value = 0;
			bool     known = false;
			if (size != 8)
				rc = KERNEL_ERROR_EINVAL;
			else if (!IpmiScope::InspectPeerClient(session.server, session.client, &peer))
				rc = KERNEL_ERROR_ECONNRESET;
			else if (command == 0x463)
				known = AppMount::GetAttachedApp(static_cast<int>(peer), &value);
			else
				known = Budget::Ptype(static_cast<int>(peer), &value);
			if (rc == KERNEL_ERROR_ENOSYS && size == 8) {
				rc = !known                                           ? KERNEL_ERROR_ENOENT
				     : Write(Load<uint64_t>(local.data()), &value, 4) ? OK
				                                                      : KERNEL_ERROR_EFAULT;
			}
			if (rc == OK || rc == KERNEL_ERROR_EFAULT || rc == KERNEL_ERROR_ENOENT) {
				static std::atomic<uint32_t> logged {0};
				if (logged.fetch_add(1) < 32) {
					LOGF("ORIGINAL_APP_IPMI_SESSION_PEER_%s handle=%d pid=%d peer=%u value=%08x "
					     "rc=%08x\n",
					     command == 0x463 ? "APP_ID" : "PROC_TYPE", handle, pid, peer,
					     static_cast<unsigned>(value), static_cast<unsigned>(rc));
				}
			}
		} else if (command == 0x302 && owned_session) {
			Session session;
			{
				std::lock_guard lock(state_mutex);
				auto            found = sessions.find(handle);
				if (found != sessions.end()) session = found->second;
			}
			uint32_t peer = 0;
			if (size != 8)
				rc = KERNEL_ERROR_EINVAL;
			else if (!IpmiScope::InspectPeerClient(session.server, session.client, &peer))
				rc = KERNEL_ERROR_ECONNRESET;
			else {
				rc = Write(Load<uint64_t>(local.data()), &peer, 4) ? OK : KERNEL_ERROR_EFAULT;
				if (rc == OK && connecting.request && session.pid == pid &&
				    session.server == connecting.server && session.client == connecting.client &&
				    IpmiScope::IsReceivedRequest(connecting.server, connecting.client,
				                                 connecting.request)) {
					connecting.authorization_session = handle;
					connecting.authorization_peer    = peer;
				}
			}
		} else if (command == 1 && owned_server) {
			std::lock_guard lock(state_mutex);
			auto            found  = servers.find(handle);
			const auto      server = found != servers.end() ? found->second.scope : 0;
			rc = server && IpmiScope::Unregister(server) ? OK : KERNEL_ERROR_EBADF;
			if (rc == OK) {
				servers.erase(handle);
				for (auto it = sessions.begin(); it != sessions.end();) {
					if (it->second.server == server)
						it = sessions.erase(it);
					else
						++it;
				}
			}
		} else if (command == 3 && owned_client) {
			std::lock_guard lock(state_mutex);
			auto            found = clients.find(handle);
			if (found == clients.end())
				rc = KERNEL_ERROR_EBADF;
			else if (found->second.busy || found->second.active_invokes != 0)
				rc = KERNEL_ERROR_EBUSY;
			else {
				uint32_t   server = 0, owner = 0;
				const auto state = found->second.scope ? IpmiScope::QueryClient(found->second.scope,
				                                                                &server, &owner)
				                                       : IpmiScope::ClientStatus::Missing;
				if (state == IpmiScope::ClientStatus::Unavailable)
					rc = KERNEL_ERROR_EAGAIN;
				else if (state == IpmiScope::ClientStatus::Missing)
					rc = OK;
				else if (found->second.connected)
					rc = KERNEL_ERROR_EBUSY;
				else
					rc = IpmiScope::CloseClient(found->second.scope) ? OK : KERNEL_ERROR_EAGAIN;
				if (rc == OK) clients.erase(handle);
			}
		} else if (command == 5 && owned_session) {
			std::lock_guard lock(state_mutex);
			auto            found = sessions.find(handle);
			if (found == sessions.end())
				rc = KERNEL_ERROR_EBADF;
			else if (!found->second.requests.empty())
				rc = KERNEL_ERROR_EBUSY;
			else {
				sessions.erase(handle);
				rc = OK;
			}
		}
		if (lifecycle_diagnostic) {
			LOGF("APP_KILL_LIFECYCLE_IPMI command=0x254 pid=%d handle=%d bytes=%zu"
			     " owned_server=%d owned_client=%d owned_session=%d session_found=%d"
			     " server=%u client=%u request=%u peer_known=%d peer_pid=%u"
			     " result=0x%08x outcome=UNCHANGED\n",
			     pid, handle, size, owned_server ? 1 : 0, owned_client ? 1 : 0,
			     owned_session ? 1 : 0, lifecycle_found ? 1 : 0, lifecycle.server, lifecycle.client,
			     lifecycle.requests.empty() ? 0 : lifecycle.requests.front(),
			     lifecycle_peer_known ? 1 : 0, lifecycle_peer, static_cast<unsigned>(rc));
		}
	}
	if (((command == 0 || command == 2) && rc < 0) ||
	    (command == 0x202 && rc == KERNEL_ERROR_EFAULT)) {
		*Posix::GetErrorAddr() = KernelToPosix(rc);
		*status                = -1;
		LOGF("ORIGINAL_APP_IPMI_%s_REJECTED pid=%d errno=%d result_untouched=1\n",
		     command == 0   ? "SERVER"
		     : command == 2 ? "CLIENT"
		                    : "SERVER_POST",
		     pid, *Posix::GetErrorAddr());
		return true;
	}
	if (rc == KERNEL_ERROR_ENOSYS)
		LOGF("ORIGINAL_APP_IPMI_UNIMPLEMENTED command=%x handle=%d pid=%d bytes=%zu\n", command,
		     handle, pid, size);
	*status = Write(reinterpret_cast<uint64_t>(result), &rc, 4) ? OK : -1;
	if (*status == -1) *Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
	return true;
}
} // namespace Libs::LibKernel::IpmiManager
