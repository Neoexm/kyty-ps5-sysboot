#include "kernel/ipmiScope.h"
#include "common/logging/log.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace Libs::LibKernel::IpmiScope {
namespace {

constexpr uint32_t kMagic   = 0x49504D49; // IPMI, versioned host-only layout
constexpr uint32_t kVersion = 14;
// host table sizes; ShellCore alone makes well over 64 servers at init
constexpr size_t kSlots      = 512;
constexpr size_t kNameLength = 96;
constexpr size_t kClients    = 256;
constexpr size_t kRequests   = 32;
constexpr size_t kMaxPacket  = 0x10000;
constexpr size_t kEventFlags = 16;
constexpr size_t kMessages   = 64;
// kernel sendMessage global bound: size >= 0x7fff9 -> ENOMEM (kernel-13.60 0xffffffff9ef333e0)
constexpr size_t   kMaxMessage      = 0x7fff8;
constexpr uint32_t kMaxQueueIndexes = 32;

struct ServiceRecord {
	uint32_t id                 = 0;
	uint32_t guest_pid          = 0;
	uint32_t host_pid           = 0;
	uint32_t reserved           = 0;
	uint64_t host_creation_time = 0;
	char     name[kNameLength] {};
};
struct ClientRecord {
	uint32_t                          id                 = 0;
	uint32_t                          service_id         = 0;
	uint32_t                          guest_pid          = 0;
	uint32_t                          host_pid           = 0;
	uint64_t                          host_creation_time = 0;
	uint32_t                          event_count        = 0;
	uint32_t                          events_cancelled   = 0;
	uint32_t                          event_generation   = 0;
	uint32_t                          event_reserved     = 0;
	std::array<uint64_t, kEventFlags> event_bits {};
	// wire +0x38 queue count, +0x40 capacity per index, one MQCh channel each
	// (sub_FFFFFFFF9EAE1650)
	uint32_t                               queue_count    = 0;
	uint32_t                               queue_reserved = 0;
	std::array<uint64_t, kMaxQueueIndexes> queue_capacity {};
};
struct KernelPacket {
	// State 0 vacant, 1 queued, 2 received by server, 3 replied, 4 async result posted by 0x242.
	uint32_t state             = 0;
	uint32_t id                = 0;
	uint32_t client_id         = 0;
	uint32_t service_id        = 0;
	uint32_t request_size      = 0;
	uint32_t reply_size        = 0;
	uint32_t async_event_index = 0xffffffff;
	// 16-bit rolling counter, so 0xffffffff marks a non-async packet; ticket 0 is valid.
	uint32_t async_ticket = 0xffffffff;
	// posted 0x44 result: methodId, result word for pResult, out blob count
	uint32_t                        async_sel           = 0;
	uint32_t                        async_result        = 0;
	uint32_t                        async_out_count     = 0;
	uint64_t                        async_event_pattern = 0;
	std::array<uint8_t, kMaxPacket> request {};
	std::array<uint8_t, kMaxPacket> response {};
};
struct KernelMessage {
	// 0 vacant, 1 queued; ids in issue order
	uint32_t                         state       = 0;
	uint32_t                         id          = 0;
	uint32_t                         client_id   = 0;
	uint32_t                         server_id   = 0;
	uint32_t                         queue_index = 0;
	uint32_t                         size        = 0;
	std::array<uint8_t, kMaxMessage> bytes {};
};
struct SharedDirectory {
	uint32_t                             magic    = 0;
	uint32_t                             version  = 0;
	uint32_t                             next_id  = 1;
	uint32_t                             reserved = 0;
	std::array<ServiceRecord, kSlots>    services {};
	std::array<ClientRecord, kClients>   clients {};
	std::array<KernelPacket, kRequests>  packets {};
	uint32_t                             next_packet  = 1;
	uint32_t                             next_message = 1;
	uint64_t                             reaped_ms    = 0;
	std::array<KernelMessage, kMessages> messages {};
};
static_assert(sizeof(ServiceRecord) == 120);

bool GetScopeName(std::string* out) {
	const char* raw = std::getenv("KYTY_DIAGNOSTIC_IPMI_SHARED_SCOPE");
	if (raw == nullptr || raw[0] == '\0') return false;
	const std::string value(raw);
	if (value.size() > 20 || !std::all_of(value.begin(), value.end(), [](unsigned char ch) {
		    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			       (ch >= '0' && ch <= '9') || ch == '_';
	    }))
		return false;
	*out = value;
	return true;
}

#if defined(_WIN32)
struct HostDirectory {
	HANDLE           mapping = nullptr;
	HANDLE           mutex   = nullptr;
	SharedDirectory* entries = nullptr;
	std::string      scope;

	~HostDirectory() {
		if (entries) UnmapViewOfFile(entries);
		if (mapping) CloseHandle(mapping);
		if (mutex) CloseHandle(mutex);
	}
};
HostDirectory& State() {
	static HostDirectory instance;
	return instance;
}
std::mutex& StateMutex() {
	static std::mutex mutex;
	return mutex;
}
bool Attach(const std::string& scope) {
	auto& state = State();
	if (state.entries) return state.scope == scope;
	const std::string base = "Local\\KytyPS5_IPMI_Kernel_v8_" + scope;
	state.mutex            = CreateMutexA(nullptr, FALSE, (base + "_mutex").c_str());
	if (!state.mutex) return false;
	state.mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
	                                   sizeof(SharedDirectory), (base + "_directory").c_str());
	if (!state.mapping) return false;
	state.entries = static_cast<SharedDirectory*>(MapViewOfFile(
	    state.mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(SharedDirectory)));
	if (!state.entries) return false;
	state.scope = scope;
	return true;
}
struct NamedLock {
	HANDLE handle   = nullptr;
	bool   acquired = false;
	explicit NamedLock(HANDLE mutex): handle(mutex) {
		const DWORD result = WaitForSingleObject(handle, 5000);
		acquired           = result == WAIT_OBJECT_0 || result == WAIT_ABANDONED;
	}
	~NamedLock() {
		if (acquired) ReleaseMutex(handle);
	}
};
bool HeaderReady(SharedDirectory* directory) {
	if (directory->magic == 0 && directory->version == 0) {
		std::memset(directory, 0, sizeof(*directory));
		directory->magic        = kMagic;
		directory->version      = kVersion;
		directory->next_id      = 1;
		directory->next_packet  = 1;
		directory->next_message = 1;
	}
	return directory->magic == kMagic && directory->version == kVersion;
}
uint64_t ProcessCreationTime(HANDLE handle) {
	FILETIME create {}, exit {}, kernel {}, user {};
	if (!GetProcessTimes(handle, &create, &exit, &kernel, &user)) return 0;
	return (static_cast<uint64_t>(create.dwHighDateTime) << 32) | create.dwLowDateTime;
}
bool OwnerAlive(const ServiceRecord& record) {
	if (record.host_pid == 0) return false;
	HANDLE process =
	    OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, record.host_pid);
	if (!process) {
		return GetLastError() != ERROR_INVALID_PARAMETER;
		// access denied or unknown counts as alive
	}
	const DWORD    status = WaitForSingleObject(process, 0);
	const uint64_t birth  = ProcessCreationTime(process);
	CloseHandle(process);
	if (record.host_creation_time != 0 && birth != 0 && record.host_creation_time != birth)
		return false;
	return status != WAIT_OBJECT_0;
}
uint64_t CurrentCreationTime() {
	return ProcessCreationTime(GetCurrentProcess());
}
// Every poll from every process runs under the one named mutex, and a full pass probes each owner process, so pollers share one pass per 50 ms; paths that create state or authorize a peer pass force.
void ReapExited(SharedDirectory* dir, bool force) {
	const uint64_t now = GetTickCount64();
	if (!force && now - dir->reaped_ms < 50) return;
	dir->reaped_ms = now;
	// one probe per owner process per pass
	struct Probe {
		uint32_t host_pid;
		uint64_t creation_time;
		bool     alive;
	};
	std::vector<Probe> probes;
	auto               alive = [&probes](const ServiceRecord& record) {
		for (const auto& probe: probes) {
			if (probe.host_pid == record.host_pid &&
			    probe.creation_time == record.host_creation_time)
				return probe.alive;
		}
		probes.push_back({record.host_pid, record.host_creation_time, OwnerAlive(record)});
		return probes.back().alive;
	};
	for (auto& record: dir->services) {
		if (record.id != 0 && !alive(record)) record = {};
	}
	for (auto& client: dir->clients) {
		if (client.id == 0) continue;
		ServiceRecord candidate {};
		candidate.host_pid           = client.host_pid;
		candidate.host_creation_time = client.host_creation_time;
		const bool has_service       = std::any_of(dir->services.begin(), dir->services.end(),
		                                           [&client](const ServiceRecord& row) {
			                                     return row.id == client.service_id && row.id != 0;
		                                           });
		if (!alive(candidate) || !has_service) client = {};
	}
	for (auto& packet: dir->packets) {
		if (packet.state == 0) continue;
		if (packet.client_id == 0) {
			const bool service_exists = std::any_of(
			    dir->services.begin(), dir->services.end(), [&packet](const ServiceRecord& row) {
				    return row.id == packet.service_id && row.id != 0;
			    });
			if (!service_exists) packet = {};
			continue;
		}
		const bool client_exists = std::any_of(
		    dir->clients.begin(), dir->clients.end(), [&packet](const ClientRecord& client) {
			    return client.id == packet.client_id && client.id != 0;
		    });
		if (!client_exists) packet = {};
	}
	for (auto& message: dir->messages) {
		if (message.state == 0) continue;
		const bool client_exists = std::any_of(
		    dir->clients.begin(), dir->clients.end(), [&message](const ClientRecord& client) {
			    return client.id == message.client_id && client.id != 0;
		    });
		if (!client_exists) message = {};
	}
}
void SignalKernelWaiter(const std::string& scope, char role, uint32_t id) {
	// wake-up hints only, state lives in the mapping
	const std::string name =
	    "Local\\KytyPS5_IPMI_Kernel_v8_" + scope + "_signal_" + role + std::to_string(id);
	HANDLE event = CreateEventA(nullptr, FALSE, FALSE, name.c_str());
	if (event) {
		SetEvent(event);
		CloseHandle(event);
	}
}
#endif
} // namespace

bool Enabled() {
	std::string scope;
	return GetScopeName(&scope);
}
bool Register(const std::string& service, uint32_t guest_pid, uint32_t* assigned_id,
              bool* duplicate) {
	if (duplicate) *duplicate = false;
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || assigned_id == nullptr || guest_pid == 0 || service.empty() ||
	    service.size() >= kNameLength ||
	    !std::all_of(service.begin(), service.end(),
	                 [](unsigned char ch) { return ch >= 0x21 && ch <= 0x7e; }))
		return false;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return false;
	NamedLock lock(State().mutex);
	if (!lock.acquired || !HeaderReady(State().entries)) return false;
	auto* dir = State().entries;
	ReapExited(dir, true);
	for (const auto& row: dir->services) {
		if (row.id != 0 && service == row.name) {
			if (duplicate) *duplicate = true;
			return false;
		}
	}
	for (auto& row: dir->services) {
		if (row.id != 0) continue;
		if (dir->next_id == 0 || dir->next_id >= INT32_MAX) return false;
		const uint32_t id      = dir->next_id++;
		row.id                 = id;
		row.guest_pid          = guest_pid;
		row.host_pid           = GetCurrentProcessId();
		row.host_creation_time = CurrentCreationTime();
		std::memcpy(row.name, service.data(), service.size());
		row.name[service.size()] = '\0';
		*assigned_id             = id;
		LOGF("FIRST_FRAME_AUDIT SHARED_GUEST_IPMI_REGISTER"
		     " scope=%s service=%s id=%u owner_guest_pid=%u"
		     " owner_host_pid=%u\n",
		     scope.c_str(), row.name, id, row.guest_pid, row.host_pid);
		return true;
	}
	return false;
#else
	(void)service;
	(void)guest_pid;
	(void)assigned_id;
	return false;
#endif
}
bool Lookup(const std::string& service, uint32_t* service_id, uint32_t* owner_guest_pid,
            uint32_t* owner_host_pid) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || service.empty() || !service_id || !owner_guest_pid ||
	    !owner_host_pid)
		return false;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return false;
	NamedLock lock(State().mutex);
	if (!lock.acquired || !HeaderReady(State().entries)) return false;
	ReapExited(State().entries, false);
	for (const auto& row: State().entries->services) {
		if (row.id == 0 || service != row.name) continue;
		*service_id      = row.id;
		*owner_guest_pid = row.guest_pid;
		*owner_host_pid  = row.host_pid;
		LOGF("FIRST_FRAME_AUDIT SHARED_GUEST_IPMI_LOOKUP"
		     " scope=%s service=%s id=%u owner_guest_pid=%u owner_host_pid=%u"
		     " live_owner=1\n",
		     scope.c_str(), row.name, row.id, row.guest_pid, row.host_pid);
		return true;
	}
#else
	(void)service;
	(void)service_id;
	(void)owner_guest_pid;
	(void)owner_host_pid;
#endif
	return false;
}

bool OpenClient(const std::string& service, uint32_t guest_pid, uint32_t* client_id,
                uint32_t* server_id, uint32_t event_count, uint32_t queue_count,
                const uint64_t* queue_capacities) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || !client_id || !server_id || service.empty() || guest_pid == 0 ||
	    event_count > kEventFlags)
		return false;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return false;
	NamedLock lock(State().mutex);
	if (!lock.acquired || !HeaderReady(State().entries)) return false;
	auto* dir = State().entries;
	ReapExited(dir, true);
	uint32_t matching = 0;
	for (const auto& service_row: dir->services) {
		if (service_row.id && service == service_row.name) {
			matching = service_row.id;
			break;
		}
	}
	if (!matching) return false;
	for (auto& client: dir->clients) {
		if (client.id != 0) continue;
		if (dir->next_id == 0 || dir->next_id >= INT32_MAX) return false;
		const uint32_t id         = dir->next_id++;
		client.id                 = id;
		client.service_id         = matching;
		client.guest_pid          = guest_pid;
		client.host_pid           = GetCurrentProcessId();
		client.host_creation_time = CurrentCreationTime();
		client.event_count        = event_count;
		client.event_generation   = 1;
		client.queue_count        = std::min(queue_count, kMaxQueueIndexes);
		if (queue_capacities) {
			std::copy_n(queue_capacities, client.queue_count, client.queue_capacity.begin());
		}
		*client_id = id;
		*server_id = matching;
		if (queue_capacities) {
			char  caps[kMaxQueueIndexes * 17 + 1] {};
			char* out = caps;
			for (uint32_t i = 0; i < client.queue_count; ++i)
				out += std::snprintf(out, sizeof(caps) - (out - caps), "%llx%s",
				                     static_cast<unsigned long long>(client.queue_capacity[i]),
				                     i + 1 < client.queue_count ? "," : "");
			LOGF("FIRST_FRAME_AUDIT SHARED_GUEST_IPMI_CLIENT_QUEUES service=%s owner_guest_pid=%u "
			     "queue_count=%u capacities=%s\n",
			     service.c_str(), guest_pid, queue_count, caps);
		}
		LOGF("FIRST_FRAME_AUDIT SHARED_GUEST_IPMI_CLIENT_OPEN"
		     " service=%s client_id=%u server_id=%u"
		     " owner_guest_pid=%u owner_host_pid=%u"
		     " event_count=%u\n",
		     service.c_str(), id, matching, guest_pid, client.host_pid, event_count);
		return true;
	}
#else
	(void)service;
	(void)guest_pid;
	(void)client_id;
	(void)server_id;
	(void)event_count;
	(void)message_limit;
#endif
	return false;
}
ClientStatus QueryClient(uint32_t client_id, uint32_t* server_id, uint32_t* owner_guest_pid) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || client_id == 0 || !server_id || !owner_guest_pid)
		return ClientStatus::Unavailable;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return ClientStatus::Unavailable;
	NamedLock lock(State().mutex);
	if (!lock.acquired || !HeaderReady(State().entries)) return ClientStatus::Unavailable;
	const auto birth = CurrentCreationTime();
	if (!birth) return ClientStatus::Unavailable;
	auto* dir = State().entries;
	ReapExited(dir, false);
	for (const auto& client: dir->clients) {
		if (client.id != client_id || client.host_pid != GetCurrentProcessId()) continue;
		if (!client.host_creation_time) return ClientStatus::Unavailable;
		if (client.host_creation_time != birth) continue;
		const auto service = std::find_if(
		    dir->services.begin(), dir->services.end(),
		    [&client](const ServiceRecord& row) { return row.id == client.service_id; });
		if (service == dir->services.end()) return ClientStatus::Missing;
		*server_id       = client.service_id;
		*owner_guest_pid = client.guest_pid;
		return ClientStatus::Live;
	}
#else
	(void)client_id;
	(void)server_id;
	(void)owner_guest_pid;
	return ClientStatus::Unavailable;
#endif
	return ClientStatus::Missing;
}
bool InspectClient(uint32_t client_id, uint32_t* server_id, uint32_t* owner_guest_pid) {
	return QueryClient(client_id, server_id, owner_guest_pid) == ClientStatus::Live;
}
bool InspectPeerClient(uint32_t server_id, uint32_t client_id, uint32_t* guest_pid,
                       uint32_t* host_pid, uint64_t* host_creation_time, bool reap_exited) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || !guest_pid || server_id == 0 || client_id == 0) return false;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return false;
	NamedLock lock(State().mutex);
	if (!lock.acquired || !HeaderReady(State().entries)) return false;
	auto* dir = State().entries;
	if (reap_exited) ReapExited(dir, true);
	bool owns_server = false;
	for (const auto& server: dir->services) {
		if (server.id == server_id && server.host_pid == GetCurrentProcessId() &&
		    server.host_creation_time == CurrentCreationTime())
			owns_server = true;
	}
	if (!owns_server) return false;
	for (const auto& client: dir->clients) {
		if (client.id == client_id && client.service_id == server_id) {
			*guest_pid = client.guest_pid;
			if (host_pid) *host_pid = client.host_pid;
			if (host_creation_time) *host_creation_time = client.host_creation_time;
			return true;
		}
	}
#else
	(void)server_id;
	(void)client_id;
	(void)guest_pid;
	(void)host_pid;
	(void)host_creation_time;
	(void)reap_exited;
#endif
	return false;
}

bool Unregister(uint32_t server_id) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || server_id == 0) return false;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return false;
	NamedLock lock(State().mutex);
	if (!lock.acquired || !HeaderReady(State().entries)) return false;
	std::vector<uint32_t> clients;
	for (auto& server: State().entries->services) {
		if (server.id == server_id && server.host_pid == GetCurrentProcessId() &&
		    server.host_creation_time == CurrentCreationTime()) {
			for (const auto& client: State().entries->clients) {
				if (client.id && client.service_id == server_id) clients.push_back(client.id);
			}
			server = {};
			ReapExited(State().entries, true);
			for (const auto client: clients)
				SignalKernelWaiter(scope, 'e', client);
			return true;
		}
	}
#else
	(void)server_id;
#endif
	return false;
}

bool CloseClient(uint32_t client_id) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || client_id == 0) return false;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return false;
	NamedLock lock(State().mutex);
	if (!lock.acquired || !HeaderReady(State().entries)) return false;
	bool closed = false;
	for (auto& client: State().entries->clients) {
		if (client.id != client_id || client.host_pid != GetCurrentProcessId() ||
		    client.host_creation_time != CurrentCreationTime())
			continue;
		for (auto& request: State().entries->packets) {
			if (request.state && request.client_id == client_id) request = {};
		}
		for (auto& message: State().entries->messages) {
			if (message.state && message.client_id == client_id) message = {};
		}
		client = {};
		closed = true;
		break;
	}
	if (closed) SignalKernelWaiter(scope, 'e', client_id);
	return closed;
#else
	(void)client_id;
#endif
	return false;
}
bool QueueRequest(uint32_t client_id, const uint8_t* bytes, size_t length, uint32_t* request_id,
                  const AsyncIssue* async, bool* table_full) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || client_id == 0 || !bytes || !request_id || length == 0 ||
	    length > kMaxPacket)
		return false;
	*request_id = 0;
	if (table_full) *table_full = false;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return false;
	uint32_t recipient = 0;
	{
		NamedLock lock(State().mutex);
		if (!lock.acquired || !HeaderReady(State().entries)) return false;
		auto* dir = State().entries;
		ReapExited(dir, true);
		for (const auto& client: dir->clients) {
			if (client.id == client_id && client.host_pid == GetCurrentProcessId() &&
			    client.host_creation_time == CurrentCreationTime()) {
				recipient = client.service_id;
				break;
			}
		}
		if (!recipient) return false;
		// Stamp before state 1, or a parked server can post 0x242 before the ticket lands. Check
		// the 16-slot table (conn+0x3f8) first so a full table doesn't move the counter.
		if (async) {
			size_t issued = 0;
			for (const auto& entry: dir->packets) {
				if (entry.client_id == client_id && entry.async_ticket != 0xffffffff) ++issued;
			}
			if (issued >= 16) {
				if (table_full) *table_full = true;
				return false;
			}
		}
		for (auto& request: dir->packets) {
			if (request.state != 0) continue;
			if (dir->next_packet == 0 || dir->next_packet >= INT32_MAX) return false;
			const uint32_t id    = dir->next_packet++;
			request.id           = id;
			request.client_id    = client_id;
			request.service_id   = recipient;
			request.request_size = static_cast<uint32_t>(length);
			std::memcpy(request.request.data(), bytes, length);
			request.async_ticket        = async ? async->ticket : 0xffffffff;
			request.async_event_index   = async ? async->event_index : 0xffffffff;
			request.async_event_pattern = async ? async->pattern : 0;
			request.state               = 1;
			*request_id                 = id;
			LOGF("FIRST_FRAME_AUDIT SHARED_GUEST_IPMI_REQUEST_QUEUED"
			     " monotonic_ms=%llu client=%u server=%u request=%u bytes=%zu\n",
			     static_cast<unsigned long long>(GetTickCount64()), client_id, recipient, id,
			     length);
			break;
		}
		if (*request_id == 0) return false;
	}
	SignalKernelWaiter(scope, 's', recipient);
	return true;
#else
	(void)client_id;
	(void)bytes;
	(void)length;
	(void)request_id;
	(void)async;
	(void)table_full;
	return false;
#endif
}
bool PostAsyncResult(uint32_t server_id, uint32_t client_id, uint32_t ticket, uint32_t selector,
                     uint32_t result, uint32_t out_count, const uint8_t* msg, size_t msg_size,
                     uint32_t* event_index, uint64_t* event_pattern) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || !server_id || !client_id || msg_size > kMaxPacket) return false;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return false;
	NamedLock lock(State().mutex);
	if (!lock.acquired || !HeaderReady(State().entries)) return false;
	auto* dir = State().entries;
	for (auto& entry: dir->packets) {
		if (entry.client_id != client_id || entry.service_id != server_id ||
		    entry.async_ticket == 0xffffffff || entry.async_ticket != ticket || entry.state != 2)
			continue;
		entry.async_sel       = selector;
		entry.async_result    = result;
		entry.async_out_count = out_count;
		if (msg_size) std::memcpy(entry.response.data(), msg, msg_size);
		entry.reply_size = static_cast<uint32_t>(msg_size);
		entry.state      = 4;
		*event_index     = entry.async_event_index;
		*event_pattern   = entry.async_event_pattern;
		return true;
	}
#else
	(void)server_id;
	(void)client_id;
	(void)ticket;
	(void)selector;
	(void)result;
	(void)out_count;
	(void)msg;
	(void)msg_size;
	(void)event_index;
	(void)event_pattern;
#endif
	return false;
}
AsyncFetchStatus FetchAsyncResult(uint32_t client_id, uint32_t selector, uint32_t ticket,
                                  uint32_t out_count, const uint64_t* caps, uint32_t* result,
                                  std::vector<uint8_t>* payload) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || !client_id || out_count > 10 || !result || !payload)
		return AsyncFetchStatus::Unavailable;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return AsyncFetchStatus::Unavailable;
	NamedLock lock(State().mutex);
	if (!lock.acquired || !HeaderReady(State().entries)) return AsyncFetchStatus::Unavailable;
	auto* dir         = State().entries;
	bool  owns_client = false;
	for (const auto& client: dir->clients) {
		if (client.id == client_id && client.host_pid == GetCurrentProcessId() &&
		    client.host_creation_time == CurrentCreationTime())
			owns_client = true;
	}
	if (!owns_client) return AsyncFetchStatus::Missing;
	KernelPacket* slot = nullptr;
	for (auto& packet: dir->packets) {
		if (packet.client_id != client_id || packet.async_ticket == 0xffffffff ||
		    packet.async_ticket != ticket || packet.state == 0)
			continue;
		slot = &packet;
		break;
	}
	if (!slot) return AsyncFetchStatus::Missing;
	if (slot->state != 4) return AsyncFetchStatus::Empty;
	if (slot->async_sel != selector || slot->async_out_count != out_count)
		return AsyncFetchStatus::Mismatch;
	// a short 24-byte descriptor cancels the receive, the message stays queued
	size_t cursor = 0;
	for (uint32_t i = 0; i < out_count; ++i) {
		if (cursor + 4 > slot->reply_size) return AsyncFetchStatus::Mismatch;
		uint32_t blob = 0;
		std::memcpy(&blob, slot->response.data() + cursor, 4);
		if (cursor + 4 + blob > slot->reply_size || blob > caps[i])
			return AsyncFetchStatus::Mismatch;
		cursor += 4 + blob;
	}
	auto packet = *slot;
	*slot       = {};
	*result     = packet.async_result;
	payload->assign(packet.response.begin(), packet.response.begin() + packet.reply_size);
	return AsyncFetchStatus::Got;
#else
	(void)client_id;
	(void)selector;
	(void)ticket;
	(void)out_count;
	(void)caps;
	(void)result;
	(void)payload;
	return AsyncFetchStatus::Unavailable;
#endif
}
bool QueueServerEvent(uint32_t server_id, uint32_t type, uint32_t* request_id, bool* missing) {
#if defined(_WIN32)
	std::string scope;
	if (missing) *missing = false;
	if (!GetScopeName(&scope) || server_id == 0 || !request_id) return false;
	*request_id = 0;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return false;
	{
		NamedLock lock(State().mutex);
		if (!lock.acquired || !HeaderReady(State().entries)) return false;
		auto* dir = State().entries;
		ReapExited(dir, true);
		bool owns_server = false;
		for (const auto& server: dir->services) {
			if (server.id == server_id && server.host_pid == GetCurrentProcessId() &&
			    server.host_creation_time == CurrentCreationTime())
				owns_server = true;
		}
		if (!owns_server) {
			if (missing) *missing = true;
			return false;
		}
		for (auto& packet: dir->packets) {
			if (packet.state != 0) continue;
			if (dir->next_packet == 0 || dir->next_packet >= INT32_MAX) return false;
			packet.id           = dir->next_packet++;
			packet.client_id    = 0;
			packet.service_id   = server_id;
			packet.request_size = 4;
			std::memcpy(packet.request.data(), &type, 4);
			packet.state = 1;
			*request_id  = packet.id;
			LOGF("FIRST_FRAME_AUDIT SHARED_GUEST_IPMI_SERVER_EVENT_QUEUED"
			     " server=%u request=%u type=%x posted_by_owner no_client\n",
			     server_id, packet.id, type);
			break;
		}
		if (*request_id == 0) return false;
	}
	SignalKernelWaiter(scope, 's', server_id);
	return true;
#else
	(void)server_id;
	(void)type;
	(void)request_id;
	(void)missing;
	return false;
#endif
}
bool TryReceive(uint32_t server_id, uint32_t* request_id, uint32_t* client_id,
                std::vector<uint8_t>* bytes) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || server_id == 0 || !request_id || !client_id || !bytes)
		return false;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return false;
	NamedLock lock(State().mutex);
	if (!lock.acquired || !HeaderReady(State().entries)) return false;
	auto* dir = State().entries;
	ReapExited(dir, false);
	bool owns_server = false;
	for (const auto& server: dir->services) {
		if (server.id == server_id && server.host_pid == GetCurrentProcessId() &&
		    server.host_creation_time == CurrentCreationTime())
			owns_server = true;
	}
	if (!owns_server) return false;
	// kernel queue is FIFO (+0xd8 tail, +0xd0 head); slots get reused, so take the oldest id
	KernelPacket* oldest = nullptr;
	for (auto& packet: dir->packets) {
		if (packet.state != 1 || packet.service_id != server_id || packet.request_size == 0 ||
		    packet.request_size > kMaxPacket)
			continue;
		if (!oldest || packet.id < oldest->id) oldest = &packet;
	}
	if (oldest) {
		auto& packet = *oldest;
		bytes->assign(packet.request.begin(), packet.request.begin() + packet.request_size);
		*request_id = packet.id;
		*client_id  = packet.client_id;
		if (packet.client_id == 0) {
			LOGF("FIRST_FRAME_AUDIT SHARED_GUEST_IPMI_SERVER_EVENT_RECEIVED"
			     " server=%u request=%u bytes=%u consumed\n",
			     server_id, packet.id, packet.request_size);
			packet = {};
			return true;
		}
		packet.state = 2;
		LOGF("FIRST_FRAME_AUDIT SHARED_GUEST_IPMI_REQUEST_RECEIVED"
		     " monotonic_ms=%llu server=%u client=%u request=%u bytes=%u"
		     " kernel_copied_between_address_spaces\n",
		     static_cast<unsigned long long>(GetTickCount64()), server_id, packet.client_id,
		     packet.id, packet.request_size);
		return true;
	}
#else
	(void)server_id;
	(void)request_id;
	(void)client_id;
	(void)bytes;
#endif
	return false;
}
bool Reply(uint32_t server_id, uint32_t request_id, const uint8_t* bytes, size_t length) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || server_id == 0 || request_id == 0 ||
	    (bytes == nullptr && length != 0) || length > kMaxPacket)
		return false;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return false;
	uint32_t recipient = 0;
	{
		NamedLock lock(State().mutex);
		if (!lock.acquired || !HeaderReady(State().entries)) return false;
		auto* dir = State().entries;
		ReapExited(dir, false);
		bool owns_server = false;
		for (const auto& server: dir->services) {
			if (server.id == server_id && server.host_pid == GetCurrentProcessId() &&
			    server.host_creation_time == CurrentCreationTime())
				owns_server = true;
		}
		if (!owns_server) return false;
		for (auto& request: dir->packets) {
			if (request.state != 2 || request.service_id != server_id || request.id != request_id)
				continue;
			if (length) std::memcpy(request.response.data(), bytes, length);
			request.reply_size = static_cast<uint32_t>(length);
			recipient          = request.client_id;
			request.state      = 3;
			LOGF("FIRST_FRAME_AUDIT SHARED_GUEST_IPMI_REPLY_READY"
			     " monotonic_ms=%llu server=%u client=%u request=%u bytes=%zu\n",
			     static_cast<unsigned long long>(GetTickCount64()), server_id, recipient,
			     request_id, length);
			break;
		}
		if (!recipient) return false;
	}
	SignalKernelWaiter(scope, 'c', recipient);
	return true;
#else
	(void)server_id;
	(void)request_id;
	(void)bytes;
	(void)length;
	return false;
#endif
}
bool TryReadReply(uint32_t client_id, uint32_t request_id, std::vector<uint8_t>* bytes) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || !bytes || !client_id || !request_id) return false;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return false;
	NamedLock lock(State().mutex);
	if (!lock.acquired || !HeaderReady(State().entries)) return false;
	auto* dir = State().entries;
	ReapExited(dir, false);
	bool owns_client = false;
	for (const auto& client: dir->clients) {
		if (client.id == client_id && client.host_pid == GetCurrentProcessId() &&
		    client.host_creation_time == CurrentCreationTime())
			owns_client = true;
	}
	if (!owns_client) return false;
	for (auto& request: dir->packets) {
		if (request.state != 3 || request.id != request_id || request.client_id != client_id ||
		    request.reply_size > kMaxPacket)
			continue;
		bytes->assign(request.response.begin(), request.response.begin() + request.reply_size);
		request = {};
		return true;
	}
#else
	(void)client_id;
	(void)request_id;
	(void)bytes;
#endif
	return false;
}
bool CancelRequest(uint32_t client_id, uint32_t request_id) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || !client_id || !request_id) return false;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return false;
	NamedLock lock(State().mutex);
	if (!lock.acquired || !HeaderReady(State().entries)) return false;
	bool owned = false;
	for (const auto& client: State().entries->clients) {
		if (client.id == client_id && client.host_pid == GetCurrentProcessId() &&
		    client.host_creation_time == CurrentCreationTime())
			owned = true;
	}
	if (!owned) return false;
	for (auto& packet: State().entries->packets) {
		if (packet.state && packet.client_id == client_id && packet.id == request_id) {
			packet = {};
			return true;
		}
	}
#else
	(void)client_id;
	(void)request_id;
#endif
	return false;
}
bool IsReceivedRequest(uint32_t server_id, uint32_t client_id, uint32_t request_id) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || !server_id || !client_id || !request_id) return false;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return false;
	NamedLock lock(State().mutex);
	if (!lock.acquired || !HeaderReady(State().entries)) return false;
	ReapExited(State().entries, false);
	bool owned = false;
	for (const auto& server: State().entries->services) {
		if (server.id == server_id && server.host_pid == GetCurrentProcessId() &&
		    server.host_creation_time == CurrentCreationTime())
			owned = true;
	}
	if (!owned) return false;
	for (const auto& packet: State().entries->packets) {
		if (packet.state == 2 && packet.service_id == server_id && packet.client_id == client_id &&
		    packet.id == request_id)
			return true;
	}
#else
	(void)server_id;
	(void)client_id;
	(void)request_id;
#endif
	return false;
}
bool RequeueRequest(uint32_t server_id, uint32_t request_id) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || !server_id || !request_id) return false;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return false;
	NamedLock lock(State().mutex);
	if (!lock.acquired || !HeaderReady(State().entries)) return false;
	bool owned = false;
	for (const auto& server: State().entries->services) {
		if (server.id == server_id && server.host_pid == GetCurrentProcessId() &&
		    server.host_creation_time == CurrentCreationTime())
			owned = true;
	}
	if (!owned) return false;
	for (auto& packet: State().entries->packets) {
		if (packet.state == 2 && packet.service_id == server_id && packet.id == request_id) {
			packet.state = 1;
			return true;
		}
	}
#else
	(void)server_id;
	(void)request_id;
#endif
	return false;
}

EventStatus PollClientEvent(uint32_t client_id, uint32_t index, uint64_t desired, uint32_t mode,
                            uint32_t generation, uint64_t* current) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || !client_id || !generation || !current)
		return EventStatus::Unavailable;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return EventStatus::Unavailable;
	NamedLock lock(State().mutex);
	if (!lock.acquired || !HeaderReady(State().entries)) return EventStatus::Unavailable;
	auto* dir = State().entries;
	ReapExited(dir, false);
	for (auto& client: dir->clients) {
		if (client.id != client_id || client.host_pid != GetCurrentProcessId() ||
		    client.host_creation_time != CurrentCreationTime())
			continue;
		if (client.events_cancelled || client.event_generation != generation)
			return EventStatus::Missing;
		if (index >= client.event_count) return EventStatus::InvalidIndex;
		const uint64_t before   = client.event_bits[index];
		*current                = before;
		const uint64_t selected = before & desired;
		const bool     matched  = (mode & 1) ? selected == desired : selected != 0;
		if (!matched) return EventStatus::Pending;
		if (mode & 0x10)
			client.event_bits[index] = 0;
		else if (mode & 0x20)
			client.event_bits[index] = before & ~desired;
		return EventStatus::Matched;
	}
#else
	(void)client_id;
	(void)index;
	(void)desired;
	(void)mode;
	(void)generation;
	(void)current;
#endif
	return EventStatus::Missing;
}

EventStatus SetClientEvent(uint32_t server_id, uint32_t client_id, uint32_t index, uint64_t bits) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || !server_id || !client_id) return EventStatus::Unavailable;
	{
		std::lock_guard host_lock(StateMutex());
		if (!Attach(scope)) return EventStatus::Unavailable;
		NamedLock lock(State().mutex);
		if (!lock.acquired || !HeaderReady(State().entries)) return EventStatus::Unavailable;
		auto* dir = State().entries;
		ReapExited(dir, false);
		const auto server = std::find_if(
		    dir->services.begin(), dir->services.end(), [server_id](const ServiceRecord& row) {
			    return row.id == server_id && row.host_pid == GetCurrentProcessId() &&
				       row.host_creation_time == CurrentCreationTime();
		    });
		if (server == dir->services.end()) return EventStatus::Missing;
		const auto client =
		    std::find_if(dir->clients.begin(), dir->clients.end(),
			             [server_id, client_id](const ClientRecord& row) {
			                 return row.id == client_id && row.service_id == server_id;
		                 });
		if (client == dir->clients.end()) return EventStatus::Missing;
		if (client->events_cancelled) return EventStatus::Missing;
		if (index >= client->event_count) return EventStatus::InvalidIndex;
		client->event_bits[index] |= bits;
	}
	SignalKernelWaiter(scope, 'e', client_id);
	return EventStatus::Matched;
#else
	(void)server_id;
	(void)client_id;
	(void)index;
	(void)bits;
	return EventStatus::Unavailable;
#endif
}

EventStatus ResetClientEvents(uint32_t client_id, uint32_t event_count, uint32_t* generation) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || !client_id || event_count > kEventFlags || !generation)
		return EventStatus::Unavailable;
	{
		std::lock_guard host_lock(StateMutex());
		if (!Attach(scope)) return EventStatus::Unavailable;
		NamedLock lock(State().mutex);
		if (!lock.acquired || !HeaderReady(State().entries)) return EventStatus::Unavailable;
		auto* dir = State().entries;
		ReapExited(dir, false);
		for (auto& client: dir->clients) {
			if (client.id != client_id || client.host_pid != GetCurrentProcessId() ||
			    client.host_creation_time != CurrentCreationTime())
				continue;
			if (++client.event_generation == 0) client.event_generation = 1;
			client.event_count      = event_count;
			client.events_cancelled = 0;
			client.event_bits.fill(0);
			*generation = client.event_generation;
			SignalKernelWaiter(scope, 'e', client_id);
			return EventStatus::Matched;
		}
	}
#else
	(void)client_id;
	(void)event_count;
	(void)generation;
#endif
	return EventStatus::Missing;
}

EventStatus CancelClientEvents(uint32_t client_id) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || !client_id) return EventStatus::Unavailable;
	{
		std::lock_guard host_lock(StateMutex());
		if (!Attach(scope)) return EventStatus::Unavailable;
		NamedLock lock(State().mutex);
		if (!lock.acquired || !HeaderReady(State().entries)) return EventStatus::Unavailable;
		auto* dir = State().entries;
		ReapExited(dir, false);
		for (auto& client: dir->clients) {
			if (client.id != client_id || client.host_pid != GetCurrentProcessId() ||
			    client.host_creation_time != CurrentCreationTime())
				continue;
			if (++client.event_generation == 0) client.event_generation = 1;
			client.event_bits.fill(0);
			client.events_cancelled = 1;
			SignalKernelWaiter(scope, 'e', client_id);
			return EventStatus::Matched;
		}
	}
#else
	(void)client_id;
#endif
	return EventStatus::Missing;
}

MessageStatus QueueUserMessage(uint32_t server_id, uint32_t client_id, uint32_t index,
                               const uint8_t* bytes, size_t length) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || server_id == 0 || client_id == 0 || !bytes || length == 0 ||
	    length > kMaxMessage)
		return MessageStatus::Unavailable;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return MessageStatus::Unavailable;
	{
		NamedLock lock(State().mutex);
		if (!lock.acquired || !HeaderReady(State().entries)) return MessageStatus::Unavailable;
		auto* dir = State().entries;
		ReapExited(dir, false);
		const auto server = std::find_if(
		    dir->services.begin(), dir->services.end(), [server_id](const ServiceRecord& row) {
			    return row.id == server_id && row.host_pid == GetCurrentProcessId() &&
				       row.host_creation_time == CurrentCreationTime();
		    });
		if (server == dir->services.end()) return MessageStatus::Unavailable;
		const auto client =
		    std::find_if(dir->clients.begin(), dir->clients.end(),
			             [server_id, client_id](const ClientRecord& row) {
			                 return row.id == client_id && row.service_id == server_id;
		                 });
		if (client == dir->clients.end()) return MessageStatus::Missing;
		if (index >= client->queue_count) return MessageStatus::Invalid;
		const uint64_t capacity = client->queue_capacity[index];
		if (length + 8 > capacity) return MessageStatus::OverCapacity;
		uint64_t       used   = 0;
		KernelMessage* vacant = nullptr;
		for (auto& message: dir->messages) {
			if (message.state == 0) {
				if (!vacant) vacant = &message;
				continue;
			}
			if (message.client_id == client_id && message.queue_index == index)
				used += message.size + 8;
		}
		if (!vacant || capacity - used < length + 8) {
			LOGF("FIRST_FRAME_AUDIT SHARED_GUEST_IPMI_USER_MSG_FULL"
			     " server=%u client=%u index=%u bytes=%zu capacity=%llu used=%llu free_slot=%u\n",
			     server_id, client_id, index, length, static_cast<unsigned long long>(capacity),
			     static_cast<unsigned long long>(used), vacant ? 1u : 0u);
			return MessageStatus::Full;
		}
		if (dir->next_message == 0 || dir->next_message >= INT32_MAX) return MessageStatus::Full;
		vacant->id          = dir->next_message++;
		vacant->client_id   = client_id;
		vacant->server_id   = server_id;
		vacant->queue_index = index;
		vacant->size        = static_cast<uint32_t>(length);
		std::memcpy(vacant->bytes.data(), bytes, length);
		vacant->state = 1;
		LOGF("FIRST_FRAME_AUDIT SHARED_GUEST_IPMI_USER_MSG_QUEUED"
		     " server=%u client=%u index=%u request=%u bytes=%zu\n",
		     server_id, client_id, index, vacant->id, length);
	}
	SignalKernelWaiter(scope, 'e', client_id);
	return MessageStatus::Queued;
#else
	(void)server_id;
	(void)client_id;
	(void)index;
	(void)bytes;
	(void)length;
	return MessageStatus::Unavailable;
#endif
}
FetchStatus ReadUserMessage(uint32_t client_id, uint32_t index, size_t capacity,
                            std::vector<uint8_t>* bytes) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || client_id == 0 || !bytes) return FetchStatus::Unavailable;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return FetchStatus::Unavailable;
	NamedLock lock(State().mutex);
	if (!lock.acquired || !HeaderReady(State().entries)) return FetchStatus::Unavailable;
	auto* dir = State().entries;
	ReapExited(dir, false);
	bool owns_client = false;
	for (const auto& client: dir->clients) {
		if (client.id == client_id && client.host_pid == GetCurrentProcessId() &&
		    client.host_creation_time == CurrentCreationTime())
			owns_client = true;
	}
	if (!owns_client) return FetchStatus::Missing;
	KernelMessage* oldest = nullptr;
	for (auto& message: dir->messages) {
		if (message.state != 1 || message.client_id != client_id || message.queue_index != index)
			continue;
		if (!oldest || message.id < oldest->id) oldest = &message;
	}
	if (!oldest) return FetchStatus::Empty;
	if (oldest->size > capacity || oldest->size > kMaxMessage) return FetchStatus::TooBig;
	bytes->assign(oldest->bytes.begin(), oldest->bytes.begin() + oldest->size);
	LOGF("FIRST_FRAME_AUDIT SHARED_GUEST_IPMI_USER_MSG_READ"
	     " server=%u client=%u index=%u request=%u bytes=%u\n",
	     oldest->server_id, client_id, index, oldest->id, oldest->size);
	oldest->state       = 0;
	oldest->id          = 0;
	oldest->client_id   = 0;
	oldest->server_id   = 0;
	oldest->queue_index = 0;
	oldest->size        = 0;
	return FetchStatus::Got;
#else
	(void)client_id;
	(void)index;
	(void)capacity;
	(void)bytes;
	return FetchStatus::Unavailable;
#endif
}
bool FlushUserMessages(uint32_t server_id, uint32_t client_id, uint32_t index) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || server_id == 0 || client_id == 0) return false;
	std::lock_guard host_lock(StateMutex());
	if (!Attach(scope)) return false;
	NamedLock lock(State().mutex);
	if (!lock.acquired || !HeaderReady(State().entries)) return false;
	auto*      dir    = State().entries;
	const auto server = std::find_if(
	    dir->services.begin(), dir->services.end(), [server_id](const ServiceRecord& row) {
		    return row.id == server_id && row.host_pid == GetCurrentProcessId() &&
			       row.host_creation_time == CurrentCreationTime();
	    });
	if (server == dir->services.end()) return false;
	for (auto& message: dir->messages) {
		if (message.state && message.client_id == client_id && message.queue_index == index)
			message = {};
	}
	return true;
#else
	(void)server_id;
	(void)client_id;
	(void)index;
	return false;
#endif
}
bool WaitClientEventHint(uint32_t client_id, uint32_t milliseconds) {
#if defined(_WIN32)
	std::string scope;
	if (!GetScopeName(&scope) || !client_id) return false;
	const std::string name =
	    "Local\\KytyPS5_IPMI_Kernel_v8_" + scope + "_signal_e" + std::to_string(client_id);
	HANDLE event = CreateEventA(nullptr, FALSE, FALSE, name.c_str());
	if (!event) return false;
	const DWORD result = WaitForSingleObject(event, milliseconds);
	CloseHandle(event);
	return result == WAIT_OBJECT_0 || result == WAIT_TIMEOUT;
#else
	(void)client_id;
	(void)milliseconds;
	return false;
#endif
}
} // namespace Libs::LibKernel::IpmiScope
