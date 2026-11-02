#include "kernel/appMount.h"

#include "common/logging/log.h"
#include "common/threads.h"
#include "kernel/process.h"
#include "libs/errno.h"

#include <nlohmann/json.hpp>

#include <bit>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace Libs::LibKernel::AppMount {

// Kernel app objects (create 0x9ede8ce0, id table 0xffffffffa0953dc0) and proc+0x460 app-info
// records, linked by proc+0x580 (set in 0x9e930b50). Shared across host processes like
// semaphore.cpp's table.
struct ScopeApps {
	static constexpr uint32_t MaxIds    = 0x1000;
	static constexpr uint32_t MaxApps   = 0x20;
	static constexpr uint32_t MaxProcs  = 256;
	static constexpr uint64_t Signature = 0x315050415954594bull;

	struct Id {
		uint16_t link;
		uint8_t  state;
		uint32_t generation;
	};
	struct App {
		bool     used;
		int32_t  id;
		uint32_t state;
		uint32_t state2;
		uint32_t container;
		uint8_t  info[0x98];
	};
	struct Proc {
		bool    used;
		int32_t pid;
		int32_t app;
		Record  record;
	};

	uint64_t signature;
	uint32_t next_id;
	uint32_t count;
	uint32_t containers;
	int32_t  bigapp;
	Id       ids[MaxIds];
	App      apps[MaxApps];
	Proc     procs[MaxProcs];
};

struct AppContext {
	ScopeApps* table = nullptr;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	HANDLE mutex   = nullptr;
	HANDLE section = nullptr;
	~AppContext() {
		if (section != nullptr && table != nullptr) UnmapViewOfFile(table);
		if (section != nullptr) CloseHandle(section);
		if (mutex != nullptr) CloseHandle(mutex);
	}
#endif
};

static Common::Mutex                                      g_mutex;
static ScopeApps                                          g_local {};
static std::map<std::string, std::unique_ptr<AppContext>> g_contexts;

namespace {

int32_t AllocateId(ScopeApps& table) {
	const uint32_t index = table.next_id;
	if (index >= ScopeApps::MaxIds) return -1;
	auto& entry   = table.ids[index];
	table.next_id = entry.state == 0 ? index + 1 : entry.link;
	entry.state   = 2;
	return static_cast<int32_t>(((entry.generation << 13) | index) & 0xffff);
}

// 0x9d889e30: back on the free list head, generation bumped so stale ids miss
void FreeId(ScopeApps& table, int32_t id) {
	const uint32_t index = static_cast<uint32_t>(id) & 0x1fff;
	auto&          entry = table.ids[index];
	entry.state          = 1;
	entry.link           = static_cast<uint16_t>(table.next_id);
	table.next_id        = index;
	++entry.generation;
}

void Initialize(ScopeApps* table) {
	table->signature = ScopeApps::Signature;
	// 0x9edf4440 parks an unlisted, uncounted object on id 0, so the first application gets id 1.
	AllocateId(*table);
	// 0xffffffffa1fa412c with no big app running
	table->containers = 0xe;
}

AppContext* GetContext() {
	std::string scope;
	if (!Process::GetScope(&scope)) {
		static AppContext local;
		if (local.table == nullptr) {
			Initialize(&g_local);
			local.table = &g_local;
		}
		return &local;
	}
	const auto found = g_contexts.find(scope);
	if (found != g_contexts.end()) return found->second.get();
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	auto              context = std::make_unique<AppContext>();
	const std::string name    = "Local\\kyty_ps5_" + scope + "_app_v2";
	context->mutex            = CreateMutexA(nullptr, FALSE, (name + "_lock").c_str());
	if (context->mutex == nullptr) return nullptr;
	const auto wait = WaitForSingleObject(context->mutex, INFINITE);
	if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) return nullptr;
	context->section   = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
	                                        sizeof(ScopeApps), (name + "_state").c_str());
	const bool created = GetLastError() != ERROR_ALREADY_EXISTS;
	if (context->section != nullptr) {
		context->table = static_cast<ScopeApps*>(MapViewOfFile(
		    context->section, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(ScopeApps)));
	}
	if (context->table != nullptr && created) Initialize(context->table);
	ReleaseMutex(context->mutex);
	if (context->table == nullptr || context->table->signature != ScopeApps::Signature)
		return nullptr;
	auto* result = context.get();
	g_contexts.emplace(scope, std::move(context));
	return result;
#else
	return nullptr;
#endif
}

class TableLock {
public:
	TableLock() {
		g_mutex.Lock();
		auto* context = GetContext();
		if (context == nullptr) {
			LOGF("APP_TABLE_UNAVAILABLE no_app_state\n");
			return;
		}
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		if (context->mutex != nullptr) {
			const auto result = WaitForSingleObject(context->mutex, INFINITE);
			if (result != WAIT_OBJECT_0 && result != WAIT_ABANDONED) {
				LOGF("APP_TABLE_UNAVAILABLE wait=%lu no_app_state\n",
				     static_cast<unsigned long>(result));
				return;
			}
			mutex = context->mutex;
		}
#endif
		table = context->table;
	}
	~TableLock() {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		if (mutex != nullptr) ReleaseMutex(mutex);
#endif
		g_mutex.Unlock();
	}
	ScopeApps* table = nullptr;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	HANDLE mutex = nullptr;
#endif
	KYTY_CLASS_NO_COPY(TableLock);
};

// stands in for pfind(); guest pids aren't reused within a scope
bool ProcessExists(int pid) {
	if (pid == Process::GetPid()) return true;
	uint32_t status = 0;
	if (Process::IsTrackedRforkChild(pid) && !Process::GetRforkChildExitStatus(pid, &status))
		return true;
	Process::PeerProcess peer;
	return Process::FindPeerByPid(pid, &peer);
}

// Another process's record needs caps0 bit 62 (0x9e9f8f90); self is exempt.
int CheckCapability(int pid) {
	if (pid == Process::GetPid()) return 0;
	constexpr uint64_t bit   = uint64_t {1} << 62;
	const auto         facts = Process::GetCurrentAuthorizationFacts();
	if (!facts.has_authority || (facts.known_capability0 & bit) == 0) {
		LOGF("APP_INFO_CAPABILITY_UNKNOWN caller=%d target=%d bit=62\n", Process::GetPid(), pid);
		return Posix::POSIX_ENOSYS;
	}
	const bool ok = (facts.capability0 & bit) != 0;
	LOGF("APP_INFO_CHECKCAP caller=%d target=%d authority=0x%016" PRIx64 " cap0=0x%016" PRIx64
	     " known0=0x%016" PRIx64 " result=%d\n",
	     Process::GetPid(), pid, facts.authority_id, facts.capability0, facts.known_capability0,
	     ok ? 1 : 0);
	return ok ? 0 : Posix::POSIX_EPERM;
}

bool FullAccess(uint64_t authority) {
	switch (authority) {
		case 0x4800000000000007ull:
		case 0x4800000000000022ull:
		case 0x480000000000002eull:
		case 0x480000000000101full:
		case 0x4800000000000021ull:
		case 0x480000000000002dull: return true;
		default: return false;
	}
}

ScopeApps::App* FindApp(ScopeApps& table, int32_t id) {
	for (auto& app: table.apps) {
		if (app.used && app.id == id) return &app;
	}
	return nullptr;
}

ScopeApps::Proc* FindProc(ScopeApps& table, int pid) {
	for (auto& proc: table.procs) {
		if (proc.used && proc.pid == pid) return &proc;
	}
	return nullptr;
}

// Authority list shared by 0x2c2 and 0x2c3 (0x9d75d0a0 for 0x10, then
// 0x9daf9110/0x9daf90d0/0x9daf90a0).
int CheckMountAuthority(const AuthInfo::AuthorizationFacts& facts, const char* call) {
	if (!facts.has_authority) {
		LOGF("%s_AUTHORITY_UNKNOWN\n", call);
		return Posix::POSIX_ENOSYS;
	}
	if (!FullAccess(facts.authority_id) && facts.authority_id != 0x4800000000000010ull) {
		LOGF("%s_AUTHORITY_DENIED authority=0x%016" PRIx64 "\n", call, facts.authority_id);
		return Posix::POSIX_EPERM;
	}
	return 0;
}

void RemoveApp(ScopeApps& table, ScopeApps::App* app) {
	app->used = false;
	--table.count;
	FreeId(table, app->id);
}

// 0x9edeb4e0
void ReleaseBigApp(ScopeApps& table, const ScopeApps::App& app) {
	if (app.container == 0) return;
	table.containers |= 1u << app.container;
	if (table.bigapp == app.id) table.bigapp = 0;
}

// big-app part of 0x9ede8290, category 0x20200 only. Caller destroys the object on error
int LaunchBigApp(ScopeApps& table, ScopeApps::App* app, const Request& request,
                 const std::function<int(uint64_t, void*, uint64_t)>& read) {
	uint64_t param      = 0;
	uint64_t param_size = 0;
	std::memcpy(&param, request.data() + 0xa0, sizeof(param));
	std::memcpy(&param_size, request.data() + 0xa8, sizeof(param_size));
	uint64_t padding = 0;
	// 0x9ede9290: must parse to an object, empty text is an empty object
	if (param_size >= 0x100001) return Posix::POSIX_ENOMEM;
	if (param_size != 0) {
		std::string text(param_size, '\0');
		const int   fault = read(param, text.data(), param_size);
		if (fault != 0) return fault;
		const size_t length = text.find_last_not_of('\0') + 1;
		padding             = param_size - length;
		const auto json = nlohmann::json::parse(text.data(), text.data() + length, nullptr, false);
		if (json.is_discarded()) {
			// TODO: 0x9ef4ab50 not reversed, so text nlohmann rejects has no known kernel result
			LOGF("APP_MOUNT2_PARAM_JSON_UNMODELED app_id=%d size=%" PRIu64 " trailing_nul=%" PRIu64
			     " reason=host_parser_rejected\n",
			     app->id, param_size, padding);
			return Posix::POSIX_ENOSYS;
		}
		if (!json.is_object()) return Posix::POSIX_EINVAL;
		if (json.contains("kernel")) {
			// extendedDynlibMemorySize (0x9ede9d50) and the 0x9edf29f0 size properties move the
			// memory figures below.
			LOGF("APP_MOUNT2_PARAM_JSON_UNMODELED app_id=%d size=%" PRIu64
			     " reason=kernel_properties\n",
			     app->id, param_size);
			return Posix::POSIX_ENOSYS;
		}
	}

	int64_t dmem = 0;
	std::memcpy(&dmem, request.data() + 0xc8, sizeof(dmem));
	// 0x9ede9cc0 bound is 0xffffffffa1fa5418 >> 20, which is 0
	if (dmem != 0 && dmem != -1) return Posix::POSIX_EINVAL;

	if (table.bigapp != 0) {
		// 0x9ede87a1 panics (0xaa) here. XXX: suspend/resume (0x9edef6f0/0x9edefbc0) also move this
		// slot
		LOGF("APP_MOUNT2_BIGAPP_CURRENT_UNMODELED app_id=%d current=%d\n", app->id, table.bigapp);
		return Posix::POSIX_ENOSYS;
	}

	// 0x9edea210
	const uint32_t container = static_cast<uint32_t>(std::countr_zero(table.containers));
	if (table.containers == 0 || container == 0) return Posix::POSIX_ENOMEM;
	table.containers &= ~(1u << container);
	app->container = container;
	table.bigapp   = app->id;

	uint32_t settings = 0;
	std::memcpy(&settings, request.data() + 0xd0, sizeof(settings));
	uint64_t flexible = 0;
	std::memcpy(&flexible, request.data() + 0xc0, sizeof(flexible));
	int error = 0;
	// 0x9ea43ad0 only looks at the settings themselves up to category 0xfff.
	if (settings > 0x10) error = Posix::POSIX_EINVAL;
	// 0x9edea7b0 for 0x20200: flexible memory 2 MiB to 0x70000000 in 2 MiB steps, 0x70000000 when
	// the block leaves it 0.
	else if (flexible != 0 &&
	         ((flexible & 0x1fffff) != 0 || flexible < 0x200000 || flexible > 0x70000000))
		error = Posix::POSIX_EINVAL;
	if (error != 0) {
		ReleaseBigApp(table, *app);
		return error;
	}
	if (flexible == 0) flexible = 0x70000000;

	LOGF("APP_MOUNT2_BIGAPP app_id=%d container=%u flexible=0x%" PRIx64 " param_json=%" PRIu64
	     " trailing_nul=%" PRIu64 " dmem=%" PRId64 " settings=%u hw_mode=%u mode2=%u\n",
	     app->id, container, flexible, param_size, padding, dmem, settings, request[0x48],
	     request[0x4a]);
	return 0;
}

} // namespace

int Begin(const std::function<int(Request&)>&                  copyin,
          const std::function<int(uint64_t, int32_t)>&         copyout,
          const std::function<int(uint64_t, void*, uint64_t)>& read) {
	const auto facts  = Process::GetCurrentAuthorizationFacts();
	const int  access = CheckMountAuthority(facts, "APP_MOUNT2");
	if (access != 0) return access;
	Request   request {};
	const int fault = copyin(request);
	if (fault != 0) return fault;
	uint64_t output = 0;
	std::memcpy(&output, request.data() + 0xb0, sizeof(output));
	if (output == 0) return Posix::POSIX_EINVAL;
	uint32_t category = 0;
	std::memcpy(&category, request.data() + 0x50, sizeof(category));
	// no title-dependent branch above 0xffffff, so mini's 0x2000000 goes the same way as
	// ShellCore's 0x5000000
	// TODO: big apps other than 0x20200, 0x2000100 (0x9da95b40), top byte 3 (copies +0xb8)
	const bool big = category <= 0xffffff;
	if ((big && category != 0x20200) || category == 0x2000100 || (category >> 24) == 3) {
		LOGF("APP_MOUNT2_CATEGORY_UNMODELED category=0x%x\n", category);
		return Posix::POSIX_ENOSYS;
	}

	int32_t id = 0;
	{
		TableLock lock;
		if (lock.table == nullptr) return Posix::POSIX_ENOSYS;
		auto& table = *lock.table;
		// kernel says EAGAIN, but a process exiting without 0x2c3 leaves its app here
		if (table.count >= ScopeApps::MaxApps || table.next_id >= ScopeApps::MaxIds) {
			LOGF("APP_MOUNT2_CAPACITY_TEARDOWN_UNMODELED count=%u next_id=%u\n", table.count,
			     table.next_id);
			return Posix::POSIX_ENOSYS;
		}
		id = AllocateId(table);
		if (big) {
			// EBUSY while another big app is running, in transit (3-5) or suspended with state2 1
			for (const auto& other: table.apps) {
				uint32_t held = 0;
				std::memcpy(&held, other.info + 0x50, sizeof(held));
				if (!other.used || held > 0xffffff) continue;
				if (other.state == 1 || (other.state >= 3 && other.state <= 5) ||
				    (other.state == 2 && other.state2 == 1)) {
					FreeId(table, id);
					LOGF("APP_MOUNT2_BIGAPP_BUSY category=0x%x holder=%d state=%u state2=%u\n",
					     category, other.id, other.state, other.state2);
					return Posix::POSIX_EBUSY;
				}
			}
		}
		auto* app = table.apps;
		while (app->used)
			++app;
		app->used      = true;
		app->id        = id;
		app->state     = 5;
		app->state2    = 0;
		app->container = 0;
		std::memcpy(app->info, request.data(), sizeof(app->info));
		std::memcpy(app->info, &id, sizeof(id));
		++table.count;
		// arg1/arg2 (+0xa0/+0xa8) only parsed if 0xffffffff9fcd446c == 4 (0x9eef7920), it's 1
		LOGF("APP_MOUNT2_CREATED app_id=%d category=0x%x title=%.10s state=5 count=%u\n", id,
		     category, reinterpret_cast<const char*>(request.data() + 0x10), table.count);
		if (big) {
			const int error = LaunchBigApp(table, app, request, read);
			if (error != 0) {
				RemoveApp(table, app);
				LOGF("APP_MOUNT2_BIGAPP_FAILED app_id=%d errno=%d destroyed=1 count=%u\n", id,
				     error, table.count);
				return error;
			}
		}
	}

	const int error = copyout(output, id);
	if (error == 0) return 0;
	// 0x9ede9960 only takes an object back while its state is 4 or 5.
	TableLock lock;
	if (lock.table == nullptr) return error;
	auto*      app       = FindApp(*lock.table, id);
	const bool destroyed = app != nullptr && (app->state & ~1u) == 4;
	if (destroyed) RemoveApp(*lock.table, app);
	LOGF("APP_MOUNT2_COPYOUT_FAILED app_id=%d errno=%d destroyed=%d count=%u\n", id, error,
	     destroyed ? 1 : 0, lock.table->count);
	return error;
}

const char* DiagnosticProcessState(int query) {
	if (query == 0) return "alive";
	if (query == KERNEL_ERROR_ESRCH) return "dead";
	return "unknown";
}

int End(const std::function<int(int32_t*)>& copyin) {
	const auto facts  = Process::GetCurrentAuthorizationFacts();
	const int  access = CheckMountAuthority(facts, "APP_MOUNT_END");
	if (access != 0) return access;
	int32_t   id    = 0;
	const int fault = copyin(&id);
	if (fault != 0) return fault;
	if (id == 0) return Posix::POSIX_ESRCH;

	TableLock lock;
	if (lock.table == nullptr) return Posix::POSIX_ENOSYS;
	auto& table = *lock.table;
	auto* app   = FindApp(table, id);
	if (app == nullptr) return Posix::POSIX_ESRCH;
	const uint64_t authority = facts.authority_id;
	const bool any_state = authority == 0x4800000000000022ull ||
	                       authority == 0x480000000000002eull || authority == 0x480000000000101full;
	if (!any_state && (app->state & ~1u) != 4) {
		LOGF("APP_MOUNT_END_BUSY app_id=%d state=%u authority=0x%016" PRIx64 "\n", id, app->state,
		     authority);
		return Posix::POSIX_EBUSY;
	}
	const auto state = app->state;
	if (std::getenv("KYTY_DIAGNOSTIC_APP_KILL_LIFECYCLE") != nullptr) {
		uint32_t associated = 0;
		uint32_t alive      = 0;
		uint32_t dead       = 0;
		uint32_t unknown    = 0;
		for (const auto& proc: table.procs) {
			if (!proc.used || proc.app != id) continue;
			const char* source   = "none";
			uint32_t    host_pid = 0;
			const int   query    = Process::QueryGuestProcessExists(proc.pid, &source, &host_pid);
			++associated;
			if (query == 0)
				++alive;
			else if (query == KERNEL_ERROR_ESRCH)
				++dead;
			else
				++unknown;
			LOGF("APP_KILL_LIFECYCLE_END app_id=%d guest_pid=%d process=%s source=%s host_pid=%u"
			     " query=0x%08x\n",
			     id, proc.pid, DiagnosticProcessState(query), source, host_pid,
			     static_cast<unsigned>(query));
		}
		LOGF("APP_KILL_LIFECYCLE_END_SUMMARY app_id=%d associated=%u alive=%u dead=%u unknown=%u\n",
		     id, associated, alive, dead, unknown);
	}
	ReleaseBigApp(table, *app);
	RemoveApp(table, app);
	// proc+0x580 stays, as in 0x9edebb70
	LOGF("APP_MOUNT_END app_id=%d state=%u count=%u\n", id, state, table.count);
	return 0;
}

int SetAppInfo(int pid, const Record& input) {
	if (!ProcessExists(pid)) return Posix::POSIX_ESRCH;
	const int access = CheckCapability(pid);
	if (access != 0) return access;

	Record   record   = input;
	uint32_t flags    = 0;
	uint32_t category = 0;
	int32_t  app_id   = 0;
	std::memcpy(&flags, record.data() + 4, sizeof(flags));
	std::memcpy(&category, record.data() + 0x50, sizeof(category));
	std::memcpy(&app_id, record.data(), sizeof(app_id));
	const auto* title = reinterpret_cast<const char*>(record.data() + 0x10);

	TableLock lock;
	if (lock.table == nullptr) return Posix::POSIX_ENOSYS;
	auto& table = *lock.table;
	// retail branch of 0x9e930b50; 0x9eebce10/0x9eebce50 are 0 since 0xffffffffa20b1390 is
	// 0xffffffff
	const uint8_t kind = record[0x1a];
	if ((kind & 0xfd) != 4 && kind != 7 && title[0] != '\0' && (flags & 1) != 0) {
		// 0x9e930f70 walks allproc, the target included.
		for (const auto& proc: table.procs) {
			if (!proc.used ||
			    std::strncmp(title, reinterpret_cast<const char*>(proc.record.data() + 0x10), 10) !=
			        0 ||
			    !ProcessExists(proc.pid)) {
				continue;
			}
			LOGF("APP_INFO_SET_BUSY pid=%d title=%.10s flags=0x%x holder=%d\n", pid, title, flags,
			     proc.pid);
			return Posix::POSIX_EBUSY;
		}
	}

	auto* proc = FindProc(table, pid);
	if (proc == nullptr) {
		for (auto& candidate: table.procs) {
			if (!candidate.used) {
				proc = &candidate;
				break;
			}
		}
		for (auto& candidate: table.procs) {
			if (proc != nullptr) break;
			if (!ProcessExists(candidate.pid)) proc = &candidate;
		}
		if (proc == nullptr) {
			LOGF("APP_INFO_TABLE_FULL pid=%d slots=%u\n", pid, ScopeApps::MaxProcs);
			return Posix::POSIX_ENOSYS;
		}
		proc->used = true;
		proc->pid  = pid;
		proc->app  = 0;
		proc->record.fill(0);
	}
	record[4] |= proc->record[4] & 2;
	const auto* app = app_id > 0 ? FindApp(table, app_id) : nullptr;
	proc->record    = record;
	if (proc->app == 0 && app != nullptr) proc->app = app->id;
	LOGF("APP_INFO_SET pid=%d app_id=%d flags=0x%x kind=%u category=0x%x title=%.10s "
	     "attached_app=%d\n",
	     pid, app_id, flags | (record[4] & 2), kind, category, title, proc->app);
	return 0;
}

int GetAppInfo(int pid, uint64_t size, Record* record, bool* committed) {
	*committed = false;
	if (size > sizeof(Record)) return Posix::POSIX_EINVAL;
	if (!ProcessExists(pid)) return Posix::POSIX_ESRCH;
	const int access = CheckCapability(pid);
	if (access != 0) return access;
	TableLock lock;
	if (lock.table == nullptr) return Posix::POSIX_ENOSYS;
	const auto* proc = FindProc(*lock.table, pid);
	if (proc != nullptr) {
		*record    = proc->record;
		*committed = true;
	}
	return 0;
}

int AppInfoById(int32_t app_id, uint64_t old_size, uint64_t new_size,
                const std::function<int(Record&)>& transfer) {
	const auto facts = Process::GetCurrentAuthorizationFacts();
	if (!facts.has_authority) return Posix::POSIX_ENOSYS;
	if (facts.authority_id != 0x4800000000000007ull) {
		if (new_size != 0) return Posix::POSIX_EPERM;
		if ((facts.known_capability0 & (1ull << 62)) == 0) return Posix::POSIX_ENOSYS;
		if ((facts.capability0 & (1ull << 62)) == 0) return Posix::POSIX_EPERM;
	}
	if (old_size > sizeof(Record)) return Posix::POSIX_EINVAL;
	if (app_id == 0) return Posix::POSIX_ESRCH;
	TableLock lock;
	if (lock.table == nullptr) return Posix::POSIX_ENOSYS;
	auto* app = FindApp(*lock.table, app_id);
	if (app == nullptr) return Posix::POSIX_ESRCH;
	Record info {};
	std::memcpy(info.data(), app->info, info.size());
	const int result = transfer(info);
	if (result == 0 && new_size == sizeof(Record)) std::memcpy(app->info, info.data(), info.size());
	return result;
}

int AppState(int32_t app_id, uint64_t old_size, uint64_t new_size,
             const std::function<int(std::array<uint32_t, 2>&)>& transfer) {
	const auto facts = Process::GetCurrentAuthorizationFacts();
	if (!facts.has_authority) {
		LOGF("APP_STATE_AUTHORITY_UNKNOWN app_id=%d\n", app_id);
		return Posix::POSIX_ENOSYS;
	}
	const uint64_t authority = facts.authority_id;
	const bool reader = authority == 0x4800000000010003ull || authority == 0x4800000000000006ull ||
	                    authority == 0x4800000000000010ull;
	if (!FullAccess(authority) && !(reader && new_size == 0)) return Posix::POSIX_EPERM;
	if (old_size > 8) return Posix::POSIX_EINVAL;
	if (app_id == 0) return Posix::POSIX_ESRCH;
	TableLock lock;
	if (lock.table == nullptr) return Posix::POSIX_ENOSYS;
	auto* app = FindApp(*lock.table, app_id);
	if (app == nullptr) return Posix::POSIX_ESRCH;
	std::array<uint32_t, 2> state {app->state, app->state2};
	const int               result = transfer(state);
	if (result == 0 && new_size == 4) {
		const auto previous = app->state;
		app->state          = state[0];
		LOGF("APP_STATE_SET app_id=%d state=%u previous=%u committed=%u secondary=%u\n", app_id,
		     state[0], previous, app->state, app->state2);
	}
	return result;
}

bool GetAttachedApp(int pid, int32_t* app_id) {
	TableLock lock;
	if (lock.table == nullptr) return false;
	const auto* proc = FindProc(*lock.table, pid);
	if (proc == nullptr || proc->app == 0) return false;
	*app_id = proc->app;
	return true;
}

} // namespace Libs::LibKernel::AppMount
