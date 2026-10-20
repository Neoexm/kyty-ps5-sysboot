#include "kernel/budget.h"

#include "common/logging/log.h"
#include "common/threads.h"
#include "kernel/process.h"
#include "libs/errno.h"

#include <algorithm>
#include <atomic>
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

namespace Libs::LibKernel::Budget {
// Id table K+0x3684bb8, 5 x 15 pools K+0x36844b0, builtin slots K+0x1ae69a0, per-proc
// p+0x5cc/p+0x5d0/p+0xb4 bit 0x80. One section per guest scope, like appMount.cpp.
struct ScopeBudgets {
	static constexpr uint32_t MaxIds     = 0x1000;
	static constexpr uint32_t MaxBudgets = 0x40;
	static constexpr uint32_t MaxProcs   = 256;
	static constexpr uint64_t Signature  = 0x3154474455425954ull;

	struct Id {
		uint16_t link;
		uint8_t  state;
		uint32_t generation;
	};
	struct Object {
		bool     used;
		int32_t  id;
		uint32_t ptype;
		uint32_t count;
		int32_t  refcount;
		uint32_t deleted;
		char     name[0x20];
		Entry    entries[14];
	};
	struct Proc {
		bool    used;
		int32_t pid;
		int32_t budget;
		int32_t ptype;
		bool    set_once;
		bool    zero_set;
	};

	uint64_t signature;
	uint32_t next_id;
	bool     system_dmem_measured;
	Entry    pools[5][15];
	int32_t  builtin[2];
	Id       ids[MaxIds];
	Object   objects[MaxBudgets];
	Proc     procs[MaxProcs];
};
struct BudgetContext {
	ScopeBudgets* table = nullptr;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	HANDLE mutex   = nullptr;
	HANDLE section = nullptr;
	~BudgetContext() {
		if (section != nullptr && table != nullptr) UnmapViewOfFile(table);
		if (section != nullptr) CloseHandle(section);
		if (mutex != nullptr) CloseHandle(mutex);
	}
#endif
};
static Common::Mutex                                         g_mutex;
static ScopeBudgets                                          g_local {};
static std::map<std::string, std::unique_ptr<BudgetContext>> g_contexts;
namespace {
// K+0x5a8740 init immediates, [ptype][kind]; ptype 2 kind 1 isn't one
constexpr uint64_t DefaultLimits[5][15] = {
    {0, 0, 0, 0, 0x1fff, 0x102, 0x80, 0x100, 0x100, 0x100, 0x200, 0x100, 0, 0, 0x4e20},
    {0, 0, 0, 0, 0x1fff, 0x104, 0x100, 0x100, 0x100, 0x100, 0x400, 0x300, 0, 0, 0x4e20},
    {0, 0, 0x400000000ull, 0x200000000ull, 0xea00, 0x400, 0x200, 0x200, 0x100, 0x100, 0x800, 0x1c00,
	 0x40, 0, 0x4e20},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x4e20},
    {0, 0, 0, 0, 0x1fff, 0x100, 0x172, 0x100, 0x100, 0x100, 0x200, 0x100, 0x18e, 0x80, 0x4e20},
};

bool Counted(uint32_t unit) {
	return (unit & 5) == 1;
}
bool ParseDecimal(const char* text, uint64_t* value) {
	if (text == nullptr || *text == '\0' || std::strlen(text) > 20) return false;
	uint64_t result = 0;
	for (const char* p = text; *p != '\0'; ++p) {
		if (*p < '0' || *p > '9') return false;
		const uint64_t digit = static_cast<uint64_t>(*p - '0');
		if (result > (UINT64_MAX - digit) / 10) return false;
		result = result * 10 + digit;
	}
	*value = result;
	return true;
}
// K+0x3d0ae0 sets ptype 2 kind 1 from boot-time region bounds; supplied as kind:unit:limit plus a
// sha256.
void LoadSystemDmem(ScopeBudgets* table) {
	const char* entry    = std::getenv("KYTY_PS5_BUDGET_SYSTEM_DMEM_ENTRY");
	const char* evidence = std::getenv("KYTY_PS5_BUDGET_SYSTEM_DMEM_EVIDENCE_SHA256");
	if (entry == nullptr && evidence == nullptr) {
		LOGF("BUDGET_SYSTEM_DMEM_INPUT status=unmeasured ptype2_kind1=enosys\n");
		return;
	}
	bool hash_ok = evidence != nullptr && std::strlen(evidence) == 64;
	for (const char* p = evidence; hash_ok && *p != '\0'; ++p) {
		hash_ok = (*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f');
	}
	std::string fields = entry != nullptr ? entry : "";
	const auto  first  = fields.find(':');
	const auto  second = first == std::string::npos ? first : fields.find(':', first + 1);
	uint64_t    kind   = 0;
	uint64_t    unit   = 0;
	uint64_t    limit  = 0;
	const bool parsed = second != std::string::npos &&
	                    ParseDecimal(fields.substr(0, first).c_str(), &kind) &&
	                    ParseDecimal(fields.substr(first + 1, second - first - 1).c_str(), &unit) &&
	                    ParseDecimal(fields.substr(second + 1).c_str(), &limit);
	if (!hash_ok || !parsed || kind != 1 || unit > UINT32_MAX) {
		LOGF("BUDGET_SYSTEM_DMEM_INPUT status=rejected evidence=%d parsed=%d kind=%" PRIu64
		     " ptype2_kind1=enosys\n",
		     hash_ok ? 1 : 0, parsed ? 1 : 0, kind);
		return;
	}
	auto& pool                  = table->pools[2][1];
	pool.kind                   = 1;
	pool.unit                   = static_cast<uint32_t>(unit);
	pool.limit                  = limit;
	table->system_dmem_measured = true;
	LOGF("BUDGET_SYSTEM_DMEM_INPUT status=measured kind=1 unit=%u limit=%" PRIu64
	     " evidence_sha256=%s\n",
	     pool.unit, limit, evidence);
}
void RemoveId(ScopeBudgets& table, int32_t id) {
	const uint32_t index = static_cast<uint32_t>(id) & 0x1fff;
	auto&          entry = table.ids[index];
	entry.state          = 1;
	entry.link           = static_cast<uint16_t>(table.next_id);
	table.next_id        = index;
	++entry.generation;
}
void Initialize(ScopeBudgets* table) {
	table->signature = ScopeBudgets::Signature;
	for (uint32_t ptype = 0; ptype != 5; ++ptype) {
		for (uint32_t kind = 1; kind != 15; ++kind) {
			if (kind < 4 && (ptype != 2 || kind == 1)) continue;
			table->pools[ptype][kind] = {kind, kind == 4 ? 6u : 1u, DefaultLimits[ptype][kind], 0};
		}
	}
	table->builtin[0] = -1;
	table->builtin[1] = -1;
	LoadSystemDmem(table);
}
BudgetContext* GetContext() {
	std::string scope;
	if (!Process::GetScope(&scope)) {
		static BudgetContext local;
		if (local.table == nullptr) {
			Initialize(&g_local);
			local.table = &g_local;
		}
		return &local;
	}
	const auto found = g_contexts.find(scope);
	if (found != g_contexts.end()) return found->second.get();
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	auto              context = std::make_unique<BudgetContext>();
	const std::string name    = "Local\\kyty_ps5_" + scope + "_budget_v1";
	context->mutex            = CreateMutexA(nullptr, FALSE, (name + "_lock").c_str());
	if (context->mutex == nullptr) return nullptr;
	const auto wait = WaitForSingleObject(context->mutex, INFINITE);
	if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) return nullptr;
	context->section   = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
	                                        sizeof(ScopeBudgets), (name + "_state").c_str());
	const bool created = GetLastError() != ERROR_ALREADY_EXISTS;
	if (context->section != nullptr) {
		context->table = static_cast<ScopeBudgets*>(MapViewOfFile(
		    context->section, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(ScopeBudgets)));
	}
	if (context->table != nullptr && created) Initialize(context->table);
	ReleaseMutex(context->mutex);
	if (context->table == nullptr || context->table->signature != ScopeBudgets::Signature)
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
			LOGF("BUDGET_TABLE_UNAVAILABLE no_budget_state\n");
			return;
		}
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		if (context->mutex != nullptr) {
			const auto result = WaitForSingleObject(context->mutex, INFINITE);
			if (result != WAIT_OBJECT_0 && result != WAIT_ABANDONED) {
				LOGF("BUDGET_TABLE_UNAVAILABLE wait=%lu no_budget_state\n",
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
	ScopeBudgets* table = nullptr;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	HANDLE mutex = nullptr;
#endif
	KYTY_CLASS_NO_COPY(TableLock);
};
// K+0x608f90 tests cred caps0 bit 62; ENOSYS while the bit is unknown
const char* Gate(const AuthInfo::AuthorizationFacts& facts) {
	if (!facts.has_authority || (facts.known_capability0 & (1ull << 62)) == 0)
		return "capability62_unmeasured";
	if ((facts.capability0 & (1ull << 62)) == 0) return "capability62_clear";
	return nullptr;
}
ScopeBudgets::Object* Lookup(ScopeBudgets& table, int32_t id) {
	if (id < 0 || id > 0xffff) return nullptr;
	const uint32_t index = static_cast<uint32_t>(id) & 0x1fff;
	if (index >= ScopeBudgets::MaxIds) return nullptr;
	const auto& entry = table.ids[index];
	if (entry.state != 2 || static_cast<int32_t>(((entry.generation << 13) | index) & 0xffff) != id)
		return nullptr;
	for (auto& object: table.objects) {
		if (object.used && object.id == id) return &object;
	}
	return nullptr;
}
ScopeBudgets::Proc* FindProc(ScopeBudgets& table, int pid) {
	for (auto& proc: table.procs) {
		if (proc.used && proc.pid == pid) return &proc;
	}
	return nullptr;
}
// proc ctor values, p+0x5cc = p+0x5d0 = -1
ScopeBudgets::Proc* GetProc(ScopeBudgets& table, int pid) {
	if (auto* proc = FindProc(table, pid)) return proc;
	for (auto& proc: table.procs) {
		if (!proc.used) {
			proc = {true, pid, -1, -1, false, false};
			return &proc;
		}
	}
	LOGF("BUDGET_PROC_TABLE_FULL pid=%d slots=%u\n", pid, ScopeBudgets::MaxProcs);
	return nullptr;
}
// K+0x5a7200 / K+0x5a7530. Rejected entries have a negative unit.
void Release(ScopeBudgets& table, uint32_t ptype, const Entry* entries, uint32_t count) {
	for (uint32_t i = 0; i != count; ++i) {
		if (static_cast<int32_t>(entries[i].unit) < 0 || entries[i].kind >= 15) continue;
		auto& pool = table.pools[ptype][entries[i].kind];
		if (Counted(pool.unit)) pool.used -= entries[i].limit;
	}
}
void Free(ScopeBudgets& table, ScopeBudgets::Object& object) {
	Release(table, object.ptype, object.entries, object.count);
	RemoveId(table, object.id);
	object.used = false;
}
// K+0x5a7b50.
void Detach(ScopeBudgets& table, ScopeBudgets::Proc& proc) {
	if (proc.budget != -1) {
		if (auto* object = Lookup(table, proc.budget)) {
			if (--object->refcount <= 0 && object->deleted != 0) Free(table, *object);
		}
	}
	proc.budget = -1;
}
} // namespace
// K+0xcb1b80 and K+0x5a6b00: the child inherits the parent's attachment and ptype but not the
// set-once bit.
void Fork(int parent_pid, int child_pid) {
	TableLock lock;
	if (lock.table == nullptr) return;
	auto&         table  = *lock.table;
	const auto*   parent = FindProc(table, parent_pid);
	const int32_t budget = parent != nullptr ? parent->budget : -1;
	const int32_t ptype  = parent != nullptr ? parent->ptype : -1;
	if (budget == -1 && ptype == -1 && FindProc(table, child_pid) == nullptr) return;
	auto* child = GetProc(table, child_pid);
	if (child == nullptr) return;
	Detach(table, *child);
	*child = {true, child_pid, -1, ptype, false, false};
	if (budget != -1) {
		if (auto* object = Lookup(table, budget)) {
			++object->refcount;
			child->budget = budget;
		}
	}
	LOGF("BUDGET_FORK parent=%d child=%d budget=%d ptype=%d\n", parent_pid, child_pid,
	     child->budget, ptype);
}
void Exit(int pid) {
	TableLock lock;
	if (lock.table == nullptr) return;
	auto* proc = FindProc(*lock.table, pid);
	if (proc == nullptr) return;
	const int32_t budget = proc->budget;
	Detach(*lock.table, *proc);
	proc->used = false;
	if (budget != -1) LOGF("BUDGET_EXIT pid=%d detached=%d\n", pid, budget);
}
} // namespace Libs::LibKernel::Budget
