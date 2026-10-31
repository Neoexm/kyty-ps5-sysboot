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
ScopeApps::Proc* FindProc(ScopeApps& table, int pid) {
	for (auto& proc: table.procs) {
		if (proc.used && proc.pid == pid) return &proc;
	}
	return nullptr;
}
} // namespace
bool GetAttachedApp(int pid, int32_t* app_id) {
	TableLock lock;
	if (lock.table == nullptr) return false;
	const auto* proc = FindProc(*lock.table, pid);
	if (proc == nullptr || proc->app == 0) return false;
	*app_id = proc->app;
	return true;
}
} // namespace Libs::LibKernel::AppMount
