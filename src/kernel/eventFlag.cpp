#include "kernel/eventFlag.h"

#include "common/common.h"
#include "common/logging/log.h"
#include "common/singleton.h"
#include "common/threads.h"
#include "common/timer.h"
#include "kernel/process.h"
#include "libs/errno.h"
#include "libs/libs.h"
#include "loader/runtimeLinker.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace Libs::LibKernel::EventFlag {

LIB_NAME("libkernel", "libkernel");

struct ScopeEventFlags {
	static constexpr uint32_t MaxFlags   = 1024;
	static constexpr uint32_t MaxWaiters = 64;
	static constexpr uint32_t MaxHolders = 8;
	static constexpr uint64_t Signature  = 0x325646455954594bull;

	struct Flag {
		char     name[32];
		uint64_t generation;
		uint64_t creator_birth;
		uint32_t creator;
		bool     linked;
		bool     deleted;
		bool     single;
		uint32_t canceled;
		uint64_t bits;
		uint64_t waiters;
		// Peer processes that opened the name; an unlinked row stays pinned while any of them lives.
		uint32_t holders[MaxHolders];
		uint64_t holder_births[MaxHolders];
		bool     holders_overflowed;
	};

	uint64_t signature;
	uint64_t next_generation;
	Flag     flags[MaxFlags];
};

struct ScopeEventFlagContext {
	std::string      name;
	ScopeEventFlags* table = nullptr;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	HANDLE mutex   = nullptr;
	HANDLE section = nullptr;
	~ScopeEventFlagContext() {
		if (table != nullptr) UnmapViewOfFile(table);
		if (section != nullptr) CloseHandle(section);
		if (mutex != nullptr) CloseHandle(mutex);
	}
#endif
};

class KernelEventFlagState {
public:
	enum class Result { Ok, AlreadyWaiting, TimedOut, Canceled, Deleted, NoSpace, Failed };
	enum class ClearMode { None, All, Bits };
	enum class WaitMode { And, Or };
	enum class Operation { Set, Clear, Cancel, Delete, Unlink };

	KernelEventFlagState(std::string name, bool single, uint64_t bits)
	    : name(std::move(name)), single(single), bits(bits) {}

	Result Wait(uint64_t wanted, WaitMode mode, ClearMode clear, uint64_t* result,
	            uint32_t* micros);
	int    Change(Operation operation, uint64_t pattern, int* waiting, uint64_t caller);
	void   Trace(Operation operation, uint64_t before, uint64_t after, uint64_t caller);

	std::string                            name;
	std::string                            key;
	bool                                   single;
	uint64_t                               generation = 0;
	std::shared_ptr<ScopeEventFlagContext> scope;
	ScopeEventFlags::Flag*                 shared    = nullptr;
	bool                                   synthetic = false;

private:
	Common::Mutex           mutex;
	Common::CondVar         cond;
	bool                    deleted  = false;
	uint32_t                canceled = 0;
	int                     waiters  = 0;
	uint64_t                bits;
	std::array<uint32_t, 5> trace_counts {};
};

namespace {

struct EventFlagEntry {
	std::shared_ptr<KernelEventFlagState> flag;
	bool                                  creator = false;
};

struct EventFlagOpenTrace {
	const char* stage                  = "validation";
	std::string scope                  = "unavailable";
	const char* scope_state            = "not_captured";
	const char* row_state              = "not_captured";
	bool        local_present          = false;
	bool        row_present            = false;
	bool        stale_row_present      = false;
	bool        linked                 = false;
	bool        deleted                = false;
	bool        creator_alive          = false;
	bool        creator_liveness_known = false;
	uint64_t    generation             = 0;
	int         raw_result             = KERNEL_ERROR_EINVAL;
};

std::mutex                                                    g_registry_mutex;
std::map<KernelEventFlag, EventFlagEntry>                     g_handles;
std::map<std::string, std::shared_ptr<KernelEventFlagState>>  g_names;
uintptr_t                                                     g_next_handle = 0x10000;
std::map<std::string, std::shared_ptr<ScopeEventFlagContext>> g_scopes;
std::atomic_uint64_t                                          g_generation {1};

class ScopeLock {
public:
	explicit ScopeLock(ScopeEventFlagContext* scope): scope(scope) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		const auto result = WaitForSingleObject(scope->mutex, INFINITE);
		locked            = result == WAIT_OBJECT_0 || result == WAIT_ABANDONED;
#endif
	}
	~ScopeLock() {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		if (locked) ReleaseMutex(scope->mutex);
#endif
	}
	ScopeEventFlagContext* scope;
	bool                   locked = false;
	KYTY_CLASS_NO_COPY(ScopeLock);
};

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
uint64_t ProcessBirth(HANDLE process) {
	FILETIME created {}, exited {}, kernel {}, user {};
	if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return 0;
	return (uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime;
}

struct CreatorLiveness {
	bool alive;
	bool known;
};

CreatorLiveness QueryLiveness(uint32_t pid, uint64_t expected_birth) {
	HANDLE process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (process == nullptr) {
		return GetLastError() == ERROR_INVALID_PARAMETER ? CreatorLiveness {false, true}
		                                                 : CreatorLiveness {true, false};
	}
	const DWORD    status = WaitForSingleObject(process, 0);
	const uint64_t birth  = ProcessBirth(process);
	CloseHandle(process);
	if (status == WAIT_OBJECT_0 || (birth != 0 && birth != expected_birth)) return {false, true};
	if (status == WAIT_TIMEOUT && birth != 0) return {true, true};
	return {true, false};
}

CreatorLiveness QueryCreatorLiveness(const ScopeEventFlags::Flag& flag) {
	return QueryLiveness(flag.creator, flag.creator_birth);
}

bool CreatorAlive(const ScopeEventFlags::Flag& flag) {
	return QueryCreatorLiveness(flag).alive;
}

std::string WakeName(const ScopeEventFlagContext& scope, const ScopeEventFlags::Flag& flag,
                     uint32_t waiter) {
	return scope.name + "_g" + std::to_string(flag.generation) + "_w" + std::to_string(waiter);
}

int Wake(ScopeEventFlagContext& scope, ScopeEventFlags::Flag& flag, bool signal = true) {
	int count = 0;
	for (uint32_t waiter = 0; waiter < ScopeEventFlags::MaxWaiters; ++waiter) {
		if ((flag.waiters & (1ull << waiter)) == 0) continue;
		HANDLE event = OpenEventA(EVENT_MODIFY_STATE, FALSE, WakeName(scope, flag, waiter).c_str());
		if (event == nullptr) {
			flag.waiters &= ~(1ull << waiter);
			continue;
		}
		if (signal) SetEvent(event);
		CloseHandle(event);
		++count;
	}
	return count;
}

void AddHolder(ScopeEventFlags::Flag& flag, uint32_t pid, uint64_t birth) {
	if (pid == flag.creator && birth == flag.creator_birth) return;
	for (uint32_t i = 0; i < ScopeEventFlags::MaxHolders; ++i) {
		if (flag.holders[i] == pid && flag.holder_births[i] == birth) return;
	}
	for (uint32_t i = 0; i < ScopeEventFlags::MaxHolders; ++i) {
		if (flag.holders[i] != 0 && QueryLiveness(flag.holders[i], flag.holder_births[i]).alive)
			continue;
		flag.holders[i]       = pid;
		flag.holder_births[i] = birth;
		return;
	}
	flag.holders_overflowed = true;
}

// A deleted row is unreachable because every access compares generations; a row orphaned by creator exit is reusable once no recorded opener is alive.
bool Reclaimable(ScopeEventFlagContext& scope, ScopeEventFlags::Flag& flag) {
	if (flag.generation == 0) return true;
	if (flag.linked) return false;
	// A sleeper still clears its waiter bit in this row when it wakes.
	Wake(scope, flag, false);
	if (flag.waiters != 0) return false;
	if (flag.deleted) return true;
	if (flag.holders_overflowed) return false;
	for (uint32_t i = 0; i < ScopeEventFlags::MaxHolders; ++i) {
		if (flag.holders[i] != 0 && QueryLiveness(flag.holders[i], flag.holder_births[i]).alive)
			return false;
	}
	return true;
}

void UnlinkDeadCreators(ScopeEventFlagContext& scope) {
	for (auto& flag: scope.table->flags) {
		if (!flag.linked || CreatorAlive(flag)) continue;
		flag.linked = false;
		LOGF("NATIVE_EVENTFLAG_CHANGE source=common operation=namespace_unlink name=%s"
		     " generation=%llu scope=%s pid=%d caller=0x0 before=0x%016llx after=0x%016llx"
		     " creator_host_pid=%u creator_birth=%llu reason=creator_exit\n",
		     flag.name, static_cast<unsigned long long>(flag.generation), scope.name.c_str(),
		     Process::GetPid(), static_cast<unsigned long long>(flag.bits),
		     static_cast<unsigned long long>(flag.bits), flag.creator,
		     static_cast<unsigned long long>(flag.creator_birth));
	}
}
#endif

std::string NamespaceKey(const char* name) {
	std::string scope;
	return (Process::GetScope(&scope) ? scope : std::string()) + "\n" + name;
}

int GetScopeContext(std::shared_ptr<ScopeEventFlagContext>* output) {
	std::string scope;
	if (!Process::GetScope(&scope)) return OK;
	const auto found = g_scopes.find(scope);
	if (found != g_scopes.end()) {
		*output = found->second;
		return OK;
	}
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	auto context   = std::make_shared<ScopeEventFlagContext>();
	context->name  = "Local\\kyty_ps5_" + scope + "_evf_v3";
	context->mutex = CreateMutexA(nullptr, FALSE, (context->name + "_lock").c_str());
	if (context->mutex == nullptr) return KERNEL_ERROR_EIO;
	ScopeLock lock(context.get());
	if (!lock.locked) return KERNEL_ERROR_EIO;
	context->section =
	    CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
		                   sizeof(ScopeEventFlags), (context->name + "_state").c_str());
	if (context->section == nullptr) return KERNEL_ERROR_EIO;
	const bool created = GetLastError() != ERROR_ALREADY_EXISTS;
	context->table     = static_cast<ScopeEventFlags*>(MapViewOfFile(
	    context->section, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(ScopeEventFlags)));
	if (context->table == nullptr) return KERNEL_ERROR_EIO;
	if (created) {
		context->table->signature       = ScopeEventFlags::Signature;
		context->table->next_generation = 1;
	}
	if (context->table->signature != ScopeEventFlags::Signature ||
	    context->table->next_generation == 0)
		return KERNEL_ERROR_EIO;
	g_scopes.emplace(scope, context);
	*output = std::move(context);
	return OK;
#else
	return KERNEL_ERROR_ENOSYS;
#endif
}

int Attach(KernelEventFlagState& flag, bool create, uint64_t initial = 0) {
	const int status = GetScopeContext(&flag.scope);
	if (status != OK || flag.scope == nullptr) return status;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	ScopeLock lock(flag.scope.get());
	if (!lock.locked) return KERNEL_ERROR_EIO;
	UnlinkDeadCreators(*flag.scope);
	const uint64_t birth = ProcessBirth(GetCurrentProcess());
	if (birth == 0) return KERNEL_ERROR_EIO;
	for (auto& candidate: flag.scope->table->flags) {
		if (!candidate.linked || flag.name != candidate.name) continue;
		if (create) return KERNEL_ERROR_EEXIST;
		AddHolder(candidate, GetCurrentProcessId(), birth);
		flag.shared     = &candidate;
		flag.generation = candidate.generation;
		return OK;
	}
	if (!create) return KERNEL_ERROR_ENOENT;
	ScopeEventFlags::Flag* empty = nullptr;
	for (auto& candidate: flag.scope->table->flags) {
		if (Reclaimable(*flag.scope, candidate)) {
			empty = &candidate;
			break;
		}
	}
	if (empty == nullptr || flag.scope->table->next_generation == UINT64_MAX)
		return KERNEL_ERROR_ENOSPC;
	*empty = {};
	std::strcpy(empty->name, flag.name.c_str());
	empty->generation    = flag.scope->table->next_generation++;
	empty->creator       = GetCurrentProcessId();
	empty->creator_birth = birth;
	empty->single        = flag.single;
	empty->bits          = initial;
	empty->linked        = true;
	flag.shared          = empty;
	flag.generation      = empty->generation;
#endif
	return OK;
}

KernelEventFlag AllocateHandle() {
	if (g_next_handle >= 0x40000000) return nullptr;
	return reinterpret_cast<KernelEventFlag>(g_next_handle++);
}

std::shared_ptr<KernelEventFlagState> Acquire(KernelEventFlag handle) {
	std::lock_guard lock(g_registry_mutex);
	const auto      found = g_handles.find(handle);
	return found != g_handles.end() ? found->second.flag : nullptr;
}

bool NameLinked(KernelEventFlagState& flag) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (flag.shared != nullptr) {
		ScopeLock lock(flag.scope.get());
		if (!lock.locked) return false;
		UnlinkDeadCreators(*flag.scope);
		return flag.shared->generation == flag.generation && flag.shared->linked &&
		       !flag.shared->deleted;
	}
#endif
	return true;
}

int OpenResult(EventFlagOpenTrace* trace, const char* stage, int result) {
	if (trace != nullptr) {
		trace->stage      = stage;
		trace->raw_result = result;
	}
	return result;
}

void CaptureScopeRow(const KernelEventFlagState& flag, EventFlagOpenTrace* trace) {
	if (trace == nullptr) return;
	if (flag.scope == nullptr) {
		trace->row_state = "scope_unavailable";
		return;
	}
	trace->scope       = flag.scope->name;
	trace->scope_state = "attached";
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	ScopeLock lock(flag.scope.get());
	if (!lock.locked) {
		trace->row_state = "lock_unavailable";
		return;
	}
	if (flag.scope->table == nullptr) {
		trace->row_state = "table_unavailable";
		return;
	}
	const ScopeEventFlags::Flag* selected = nullptr;
	if (flag.shared != nullptr) {
		selected         = flag.shared;
		trace->row_state = "selected";
	}
	for (const auto& candidate: flag.scope->table->flags) {
		if (candidate.generation == 0 || flag.name != candidate.name || &candidate == selected)
			continue;
		if (candidate.linked && selected == nullptr) {
			selected         = &candidate;
			trace->row_state = "linked_match";
		} else if (!candidate.linked) {
			trace->stale_row_present = true;
		}
	}
	if (selected != nullptr) {
		const auto liveness           = QueryCreatorLiveness(*selected);
		trace->row_present            = true;
		trace->linked                 = selected->linked;
		trace->deleted                = selected->deleted;
		trace->generation             = selected->generation;
		trace->creator_alive          = liveness.alive;
		trace->creator_liveness_known = liveness.known;
	} else {
		trace->row_state = trace->stale_row_present ? "stale_only" : "missing";
	}
#endif
}

uint64_t EventFlagMonotonicMs() {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	return GetTickCount64();
#else
	return 0;
#endif
}

int TraceVideoArbitrationCreateFailure(const char* name, const char* stage, int result) {
	if (std::getenv("KYTY_DIAGNOSTIC_VIDEO_ARBITRATION_INIT") != nullptr && name != nullptr &&
	    std::strcmp(name, "SceVideoArbitration") == 0) {
		LOGF("VIDEO_ARBITRATION_EVENTFLAG_CREATE_FAILURE monotonic_ms=%llu guest_pid=%d"
		     " stage=%s result=%08x\n",
		     static_cast<unsigned long long>(EventFlagMonotonicMs()), Process::GetPid(), stage,
		     static_cast<unsigned>(result));
	}
	return result;
}

int Decode(uint32_t raw, KernelEventFlagState::WaitMode* wait,
           KernelEventFlagState::ClearMode* clear) {
	if ((raw & ~0x3fu) != 0) return KERNEL_ERROR_EINVAL;
	switch (raw & 0xfu) {
		case 1: *wait = KernelEventFlagState::WaitMode::And; break;
		case 2: *wait = KernelEventFlagState::WaitMode::Or; break;
		default: return KERNEL_ERROR_EINVAL;
	}
	switch (raw & 0xf0u) {
		case 0: *clear = KernelEventFlagState::ClearMode::None; break;
		case 0x10: *clear = KernelEventFlagState::ClearMode::All; break;
		case 0x20: *clear = KernelEventFlagState::ClearMode::Bits; break;
		default: return KERNEL_ERROR_EINVAL;
	}
	return OK;
}

int WaitStatus(KernelEventFlagState::Result result, bool poll) {
	switch (result) {
		case KernelEventFlagState::Result::Ok: return OK;
		case KernelEventFlagState::Result::AlreadyWaiting: return KERNEL_ERROR_EPERM;
		case KernelEventFlagState::Result::TimedOut:
			return poll ? KERNEL_ERROR_EBUSY : KERNEL_ERROR_ETIMEDOUT;
		case KernelEventFlagState::Result::Canceled: return KERNEL_ERROR_ECANCELED;
		case KernelEventFlagState::Result::Deleted: return KERNEL_ERROR_EACCES;
		case KernelEventFlagState::Result::NoSpace: return KERNEL_ERROR_EAGAIN;
		case KernelEventFlagState::Result::Failed: return KERNEL_ERROR_EIO;
	}
	return KERNEL_ERROR_EIO;
}

} // namespace

void KernelEventFlagState::Trace(Operation operation, uint64_t before, uint64_t after,
                                 uint64_t caller) {
	const auto index = static_cast<size_t>(operation);
	if (trace_counts[index] >= 256 ||
	    (before == after && trace_counts[index] >= 4 && operation != Operation::Delete &&
	     operation != Operation::Unlink))
		return;
	++trace_counts[index];
	const char* names[] = {"set", "clear", "cancel", "delete", "namespace_unlink"};
	LOGF("NATIVE_EVENTFLAG_CHANGE source=common operation=%s name=%s generation=%llu"
	     " scope=%s pid=%d caller=0x%016llx before=0x%016llx after=0x%016llx\n",
	     names[index], name.c_str(), static_cast<unsigned long long>(generation),
	     scope != nullptr ? scope->name.c_str() : "local", Process::GetPid(),
	     static_cast<unsigned long long>(caller), static_cast<unsigned long long>(before),
	     static_cast<unsigned long long>(after));
}

int KernelEventFlagState::Change(Operation operation, uint64_t pattern, int* waiting,
                                 uint64_t caller) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (shared != nullptr) {
		ScopeLock lock(scope.get());
		if (!lock.locked) return KERNEL_ERROR_EIO;
		if (shared->generation != generation || shared->deleted) return KERNEL_ERROR_EACCES;
		const uint64_t before = shared->bits;
		switch (operation) {
			case Operation::Set: shared->bits |= pattern; break;
			case Operation::Clear: shared->bits &= pattern; break;
			case Operation::Cancel:
				shared->bits = pattern;
				++shared->canceled;
				break;
			case Operation::Delete:
				shared->deleted = true;
				shared->linked  = false;
				break;
			case Operation::Unlink: shared->linked = false; break;
		}
		Trace(operation, before, shared->bits, caller);
		if (operation == Operation::Delete) Trace(Operation::Unlink, before, shared->bits, caller);
		const int count =
		    Wake(*scope, *shared, operation != Operation::Clear && operation != Operation::Unlink);
		if (waiting != nullptr) *waiting = count;
		return OK;
	}
#endif
	Common::LockGuard lock(mutex);
	if (deleted) return KERNEL_ERROR_EACCES;
	const uint64_t before = bits;
	switch (operation) {
		case Operation::Set: bits |= pattern; break;
		case Operation::Clear: bits &= pattern; break;
		case Operation::Cancel:
			bits = pattern;
			++canceled;
			break;
		case Operation::Delete: deleted = true; break;
		case Operation::Unlink: break;
	}
	Trace(operation, before, bits, caller);
	if (operation == Operation::Delete) Trace(Operation::Unlink, before, bits, caller);
	if (waiting != nullptr) *waiting = waiters;
	if (operation != Operation::Clear && operation != Operation::Unlink) cond.SignalAll();
	return OK;
}

KernelEventFlagState::Result KernelEventFlagState::Wait(uint64_t wanted, WaitMode mode,
                                                        ClearMode clear, uint64_t* result,
                                                        uint32_t* micros) {
	const uint32_t duration = micros != nullptr ? *micros : 0;
	Common::Timer  timer;
	timer.Start();
	uint64_t   elapsed = 0;
	const auto matches = [&](uint64_t actual) {
		return mode == WaitMode::And ? (actual & wanted) == wanted : (actual & wanted) != 0;
	};
	const auto remaining = [&]() {
		return elapsed >= duration ? 0u : duration - static_cast<uint32_t>(elapsed);
	};
	const auto consume = [&](uint64_t& actual) {
		if (clear == ClearMode::All) actual = 0;
		if (clear == ClearMode::Bits) actual &= ~wanted;
	};
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (shared != nullptr) {
		ScopeLock lock(scope.get());
		if (!lock.locked) return Result::Failed;
		if (shared->generation != generation || shared->deleted) return Result::Deleted;
		Wake(*scope, *shared, false);
		if (shared->single && shared->waiters != 0) return Result::AlreadyWaiting;
		const uint32_t serial = shared->canceled;
		Result         status = Result::Ok;
		while (!matches(shared->bits)) {
			if (micros != nullptr && elapsed >= duration) {
				status = Result::TimedOut;
				break;
			}
			if (shared->waiters == UINT64_MAX) {
				status = Result::NoSpace;
				break;
			}
			uint32_t waiter = 0;
			while ((shared->waiters & (1ull << waiter)) != 0)
				++waiter;
			HANDLE event =
			    CreateEventA(nullptr, FALSE, FALSE, WakeName(*scope, *shared, waiter).c_str());
			if (event == nullptr) {
				status = Result::Failed;
				break;
			}
			shared->waiters |= 1ull << waiter;
			ReleaseMutex(scope->mutex);
			lock.locked          = false;
			const DWORD timeout  = micros == nullptr ? INFINITE : (remaining() + 999ull) / 1000;
			const DWORD waited   = WaitForSingleObject(event, timeout);
			const DWORD acquired = WaitForSingleObject(scope->mutex, INFINITE);
			lock.locked          = acquired == WAIT_OBJECT_0 || acquired == WAIT_ABANDONED;
			if (!lock.locked) {
				CloseHandle(event);
				return Result::Failed;
			}
			shared->waiters &= ~(1ull << waiter);
			CloseHandle(event);
			elapsed = static_cast<uint64_t>(timer.GetTimeS() * 1000000.0);
			if (shared->generation != generation || shared->deleted) {
				status = Result::Deleted;
				break;
			}
			if (shared->canceled != serial) {
				status = Result::Canceled;
				break;
			}
			if (waited == WAIT_FAILED) {
				status = Result::Failed;
				break;
			}
		}
		if (result != nullptr) *result = shared->bits;
		if (micros != nullptr) *micros = remaining();
		if (status == Result::Ok) consume(shared->bits);
		return status;
	}
#endif
	Common::LockGuard lock(mutex);
	if (deleted) return Result::Deleted;
	if (single && waiters != 0) return Result::AlreadyWaiting;
	const uint32_t serial = canceled;
	Result         status = Result::Ok;
	while (!matches(bits)) {
		if (micros != nullptr && elapsed >= duration) {
			status = Result::TimedOut;
			break;
		}
		++waiters;
		if (micros == nullptr)
			cond.Wait(&mutex);
		else
			cond.WaitFor(&mutex, remaining());
		--waiters;
		elapsed = static_cast<uint64_t>(timer.GetTimeS() * 1000000.0);
		if (deleted) {
			status = Result::Deleted;
			break;
		}
		if (canceled != serial) {
			status = Result::Canceled;
			break;
		}
	}
	if (result != nullptr) *result = bits;
	if (micros != nullptr) *micros = remaining();
	if (status == Result::Ok) consume(bits);
	return status;
}

int KYTY_SYSV_ABI KernelCreateEventFlag(KernelEventFlag* output, const char* name, uint32_t attr,
                                        uint64_t initial, const void* param) {
	PRINT_NAME();
	if (output == nullptr || name == nullptr || param != nullptr || (attr & ~0x133u) != 0)
		return KERNEL_ERROR_EINVAL;
	if (std::strlen(name) >= 32)
		return TraceVideoArbitrationCreateFailure(name, "name", KERNEL_ERROR_ENAMETOOLONG);
	if ((attr & 0xfu) > 2 ||
	    ((attr & 0xf0u) != 0 && (attr & 0xf0u) != 0x10 && (attr & 0xf0u) != 0x20))
		return TraceVideoArbitrationCreateFailure(name, "attributes", KERNEL_ERROR_EINVAL);
	auto flag = std::make_shared<KernelEventFlagState>(name, (attr & 0xf0u) != 0x20, initial);
	flag->generation = g_generation.fetch_add(1);
	flag->key        = NamespaceKey(name);
	std::lock_guard lock(g_registry_mutex);
	const auto      handle = AllocateHandle();
	if (handle == nullptr)
		return TraceVideoArbitrationCreateFailure(name, "handle", KERNEL_ERROR_ENOSPC);
	bool name_inserted     = false;
	long owners_after_name = flag.use_count();
	if ((attr & 0x100u) != 0) {
		auto found = g_names.find(flag->key);
		if (found != g_names.end()) {
			if (!found->second->synthetic && NameLinked(*found->second))
				return TraceVideoArbitrationCreateFailure(name, "duplicate", KERNEL_ERROR_EEXIST);
			g_names.erase(found);
		}
		const int status = Attach(*flag, true, initial);
		if (status != OK) return TraceVideoArbitrationCreateFailure(name, "attach", status);
		name_inserted     = g_names.emplace(flag->key, flag).second;
		owners_after_name = flag.use_count();
	}
	const bool handle_inserted     = g_handles.emplace(handle, EventFlagEntry {flag, true}).second;
	const long owners_after_handle = flag.use_count();
	*output                        = handle;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	const auto host_tid = static_cast<unsigned long>(GetCurrentThreadId());
#else
	const auto host_tid = static_cast<unsigned long>(Common::Thread::GetThreadIdUnique());
#endif
	LOGF("\tEventFlag create: %s, generation=%llu, attr=0x%x, name_inserted=%u,"
	     " handle_inserted=%u, owners_after_name=%ld, owners_after_handle=%ld,"
	     " guest_pid=%d, host_tid=%lu, caller=0x%016llx\n",
	     name, static_cast<unsigned long long>(flag->generation), attr, name_inserted ? 1u : 0u,
	     handle_inserted ? 1u : 0u, owners_after_name, owners_after_handle, Process::GetPid(),
	     host_tid,
	     static_cast<unsigned long long>(reinterpret_cast<uint64_t>(__builtin_return_address(0))));
	if (std::getenv("KYTY_DIAGNOSTIC_VIDEO_ARBITRATION_INIT") != nullptr &&
	    std::strcmp(name, "SceVideoArbitration") == 0) {
		LOGF("VIDEO_ARBITRATION_EVENTFLAG_CREATE monotonic_ms=%llu guest_pid=%d host_tid=%lu"
		     " scope=%s generation=%llu linked=1 deleted=0 creator_alive=1 result=00000000\n",
		     static_cast<unsigned long long>(EventFlagMonotonicMs()), Process::GetPid(), host_tid,
		     flag->scope != nullptr ? flag->scope->name.c_str() : "local",
		     static_cast<unsigned long long>(flag->generation));
	}
	return OK;
}

int KYTY_SYSV_ABI KernelDeleteEventFlag(KernelEventFlag handle) {
	PRINT_NAME();
	std::lock_guard lock(g_registry_mutex);
	const auto      found = g_handles.find(handle);
	if (found == g_handles.end()) return KERNEL_ERROR_ESRCH;
	if (!found->second.creator) return KERNEL_ERROR_EPERM;
	const auto flag   = found->second.flag;
	const int  status = flag->Change(KernelEventFlagState::Operation::Delete, 0, nullptr,
	                                 reinterpret_cast<uint64_t>(__builtin_return_address(0)));
	if (status != OK) return status;
	const auto named = g_names.find(flag->key);
	if (named != g_names.end() && named->second == flag) g_names.erase(named);
	g_handles.erase(found);
	return OK;
}

int OpenEventFlag(KernelEventFlag* output, const char* name, bool synthetic_allowed,
                  EventFlagOpenTrace* trace = nullptr) {
	if (output == nullptr || name == nullptr)
		return OpenResult(trace, "validation", KERNEL_ERROR_EINVAL);
	if (std::strlen(name) >= 32) return OpenResult(trace, "validation", KERNEL_ERROR_ENAMETOOLONG);
	if (trace != nullptr) {
		std::string scope;
		if (Process::GetScope(&scope)) {
			trace->scope       = "Local\\kyty_ps5_" + scope + "_evf_v3";
			trace->scope_state = "requested";
		} else {
			trace->scope       = "local";
			trace->scope_state = "local";
		}
	}
	std::lock_guard                       lock(g_registry_mutex);
	const std::string                     key = NamespaceKey(name);
	std::shared_ptr<KernelEventFlagState> cached_synthetic;
	auto                                  named = g_names.find(key);
	if (named != g_names.end()) {
		if (trace != nullptr) trace->local_present = true;
		if (named->second->synthetic) {
			cached_synthetic = named->second;
		} else if (NameLinked(*named->second)) {
			CaptureScopeRow(*named->second, trace);
			const auto handle = AllocateHandle();
			if (handle == nullptr) return OpenResult(trace, "handle", KERNEL_ERROR_ENOSPC);
			g_handles.emplace(handle, EventFlagEntry {named->second, false});
			*output = handle;
			return OpenResult(trace, "local_cache", OK);
		}
		if (cached_synthetic == nullptr) g_names.erase(named);
	}
	auto flag        = std::make_shared<KernelEventFlagState>(name, false, 0);
	flag->key        = key;
	flag->generation = g_generation.fetch_add(1);
	int status       = Attach(*flag, false);
	if (status == OK && flag->scope == nullptr) status = KERNEL_ERROR_ENOENT;
	CaptureScopeRow(*flag, trace);
	if (status != OK) {
		if (cached_synthetic != nullptr) {
			if (!synthetic_allowed || status != KERNEL_ERROR_ENOENT)
				return OpenResult(trace, status == KERNEL_ERROR_ENOENT ? "lookup" : "attach",
				                  status);
			flag = cached_synthetic;
		} else {
			uint64_t injected  = 0;
			bool     synthetic = false;
			if (synthetic_allowed && std::getenv("KYTY_DIAGNOSTIC_INJECT_BOOTSTATUS_A") &&
			    std::strcmp(name, "SceBootStatusFlags") == 0) {
				injected  = std::getenv("KYTY_DIAGNOSTIC_INJECT_SHELLUI_BOOT_BIT4") ? 0xe : 0xa;
				synthetic = true;
			}
			if (synthetic_allowed && std::getenv("KYTY_DIAGNOSTIC_INJECT_SYSTEM_STATE_WORKING") &&
			    std::strcmp(name, "SceSystemStateMgrInfo") == 0) {
				injected  = 0x1000003e8ull;
				synthetic = true;
			}
			if (synthetic_allowed &&
			    std::getenv("KYTY_DIAGNOSTIC_INJECT_AUTOMOUNTER_M2_NO_DIALOG") &&
			    std::strcmp(name, "SceAutoMounterUIM2Evf") == 0) {
				injected  = 1;
				synthetic = true;
			}
			if (!synthetic || status != KERNEL_ERROR_ENOENT)
				return OpenResult(trace, status == KERNEL_ERROR_ENOENT ? "lookup" : "attach",
				                  status);
			flag->scope.reset();
			flag->shared    = nullptr;
			flag->synthetic = true;
			flag->Change(KernelEventFlagState::Operation::Set, injected, nullptr,
			             reinterpret_cast<uint64_t>(__builtin_return_address(0)));
			LOGF("FIRST_FRAME_AUDIT SYNTHETIC_EVENTFLAG name=%s bits=0x%llx NON_AUTHENTIC\n", name,
			     static_cast<unsigned long long>(injected));
		}
	}
	const auto handle = AllocateHandle();
	if (handle == nullptr) return OpenResult(trace, "handle", KERNEL_ERROR_ENOSPC);
	g_handles.emplace(handle, EventFlagEntry {flag, false});
	g_names.insert_or_assign(key, flag);
	*output = handle;
	return OpenResult(trace, "complete", OK);
}

int KYTY_SYSV_ABI KernelOpenEventFlag(KernelEventFlag* output, const char* name) {
	PRINT_NAME();
	const bool diagnostic = std::getenv("KYTY_DIAGNOSTIC_VIDEO_ARBITRATION_INIT") != nullptr &&
	                        output != nullptr && name != nullptr &&
	                        std::strcmp(name, "SceVideoArbitration") == 0;
	EventFlagOpenTrace trace;
	int                status = OpenEventFlag(output, name, true, diagnostic ? &trace : nullptr);
	uint32_t           wait_attempts = 0;
	if (diagnostic && status == KERNEL_ERROR_ENOENT) {
		constexpr uint32_t WaitStepMicros = 20'000;
		constexpr uint32_t WaitLimit      = 250;
		LOGF("VIDEO_ARBITRATION_EVENTFLAG_COORDINATION_WAIT monotonic_ms=%llu guest_pid=%d"
		     " state=begin step_us=%u limit=%u creator_required=1 NON_AUTHENTIC=1\n",
		     static_cast<unsigned long long>(EventFlagMonotonicMs()), Process::GetPid(),
		     WaitStepMicros, WaitLimit);
		while (wait_attempts < WaitLimit && status == KERNEL_ERROR_ENOENT) {
			Common::Thread::SleepMicro(WaitStepMicros);
			++wait_attempts;
			trace  = {};
			status = OpenEventFlag(output, name, true, &trace);
		}
		LOGF("VIDEO_ARBITRATION_EVENTFLAG_COORDINATION_WAIT monotonic_ms=%llu guest_pid=%d"
		     " state=end attempts=%u waited_ms=%u raw_result=%08x creator_observed=%d"
		     " NON_AUTHENTIC=1\n",
		     static_cast<unsigned long long>(EventFlagMonotonicMs()), Process::GetPid(),
		     wait_attempts, wait_attempts * WaitStepMicros / 1000, static_cast<unsigned>(status),
		     status == OK ? 1 : 0);
	}
	const int result = status == KERNEL_ERROR_ENOENT ? KERNEL_ERROR_ESRCH : status;
	if (diagnostic) {
		const auto caller  = reinterpret_cast<uint64_t>(__builtin_return_address(0));
		auto*      linker  = Common::Singleton<Loader::RuntimeLinker>::ExistingInstance();
		auto*      program = linker == nullptr ? nullptr : linker->FindProgramByAddr(caller);
		const auto module  = program == nullptr
		                         ? std::string("unknown")
		                         : Common::PathToString(program->file_name.filename());
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		const auto host_tid = static_cast<unsigned long>(GetCurrentThreadId());
#else
		const auto host_tid = static_cast<unsigned long>(Common::Thread::GetThreadIdUnique());
#endif
		LOGF(
		    "VIDEO_ARBITRATION_EVENTFLAG_OPEN monotonic_ms=%llu guest_pid=%d host_tid=%lu"
		    " caller_module=%s caller_rva=0x%016" PRIx64
		    " name=SceVideoArbitration scope=%s scope_state=%s stage=%s row_state=%s"
		    " local_present=%d row_present=%d stale_row_present=%d"
		    " linked=%d deleted=%d creator_alive=%d creator_liveness_known=%d"
		    " generation=%llu raw_result=%08x"
		    " mapped_result=%08x output_written=%d\n",
		    static_cast<unsigned long long>(EventFlagMonotonicMs()), Process::GetPid(), host_tid,
		    Log::EscapeField(module).c_str(), program == nullptr ? 0 : caller - program->base_vaddr,
		    trace.scope.c_str(), trace.scope_state, trace.stage, trace.row_state,
		    trace.local_present ? 1 : 0, trace.row_present ? 1 : 0, trace.stale_row_present ? 1 : 0,
		    trace.linked ? 1 : 0, trace.deleted ? 1 : 0, trace.creator_alive ? 1 : 0,
		    trace.creator_liveness_known ? 1 : 0, static_cast<unsigned long long>(trace.generation),
		    static_cast<unsigned>(status), static_cast<unsigned>(result), result == OK ? 1 : 0);
	}
	return result;
}

int KernelOpenExistingEventFlag(KernelEventFlag* output, const char* name) {
	const int status = OpenEventFlag(output, name, false);
	return status == KERNEL_ERROR_ENOENT ? KERNEL_ERROR_ESRCH : status;
}

int KYTY_SYSV_ABI KernelCloseEventFlag(KernelEventFlag handle) {
	PRINT_NAME();
	std::lock_guard lock(g_registry_mutex);
	const auto      found = g_handles.find(handle);
	if (found == g_handles.end()) return KERNEL_ERROR_ESRCH;
	if (found->second.creator) return KERNEL_ERROR_EPERM;
	g_handles.erase(found);
	return OK;
}

int KYTY_SYSV_ABI KernelWaitEventFlag(KernelEventFlag handle, uint64_t bits, uint32_t mode,
                                      uint64_t* result, KernelUseconds* timeout) {
	PRINT_NAME();
	const auto flag = Acquire(handle);
	if (flag == nullptr) return KERNEL_ERROR_ESRCH;
	KernelEventFlagState::WaitMode  wait;
	KernelEventFlagState::ClearMode clear;
	const int                       status = Decode(mode, &wait, &clear);
	if (status != OK || bits == 0) return KERNEL_ERROR_EINVAL;
	static const bool diag = std::getenv("KYTY_DIAGNOSTIC_SHELLUI_EVENT_WAIT") != nullptr;
	if (diag) {
		static std::atomic_uint32_t count {0};
		if (count.fetch_add(1) < 64) {
			LOGF("FIRST_FRAME_AUDIT SHELLUI_EVENT_WAIT before name=%s bits=0x%016llx"
			     " mode=0x%08x caller=0x%016llx timeout=%s\n",
			     flag->name.c_str(), static_cast<unsigned long long>(bits), mode,
			     static_cast<unsigned long long>(
			         reinterpret_cast<uint64_t>(__builtin_return_address(0))),
			     timeout == nullptr ? "infinite" : "bounded");
		}
		const auto start = std::chrono::steady_clock::now();
		const auto ret   = flag->Wait(bits, wait, clear, result, timeout);
		const auto ms    = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - start)
		                    .count();
		// only long waits, the short ones are frame pacing
		if (ms >= 100) {
			LOGF("FIRST_FRAME_AUDIT SHELLUI_EVENT_WAIT slow name=%s bits=0x%016llx caller=0x%016llx"
			     " elapsed_ms=%lld got=0x%016llx\n",
			     flag->name.c_str(), static_cast<unsigned long long>(bits),
			     static_cast<unsigned long long>(
			         reinterpret_cast<uint64_t>(__builtin_return_address(0))),
			     static_cast<long long>(ms),
			     static_cast<unsigned long long>(result != nullptr ? *result : 0));
		}
		return WaitStatus(ret, false);
	}
	return WaitStatus(flag->Wait(bits, wait, clear, result, timeout), false);
}

int KYTY_SYSV_ABI KernelPollEventFlag(KernelEventFlag handle, uint64_t bits, uint32_t mode,
                                      uint64_t* result) {
	PRINT_NAME();
	const auto flag = Acquire(handle);
	if (flag == nullptr) return KERNEL_ERROR_ESRCH;
	KernelEventFlagState::WaitMode  wait;
	KernelEventFlagState::ClearMode clear;
	const int                       status = Decode(mode, &wait, &clear);
	if (status != OK || bits == 0) return KERNEL_ERROR_EINVAL;
	uint32_t timeout = 0;
	return WaitStatus(flag->Wait(bits, wait, clear, result, &timeout), true);
}

int KernelResolveOriginalBootStatusHandle(uint32_t original, KernelEventFlag* output) {
	if (output == nullptr || original == 0) return KERNEL_ERROR_EINVAL;
	*output = nullptr;
	std::lock_guard lock(g_registry_mutex);
	const auto      named = g_names.find(NamespaceKey("SceBootStatusFlags"));
	if (named == g_names.end() || named->second->synthetic || !NameLinked(*named->second))
		return KERNEL_ERROR_ESRCH;
	for (const auto& [handle, entry]: g_handles) {
		if (entry.creator && entry.flag == named->second &&
		    static_cast<uint32_t>(reinterpret_cast<uintptr_t>(handle)) == original) {
			*output = handle;
			return OK;
		}
	}
	return KERNEL_ERROR_ESRCH;
}

int KernelSetRegisteredEventFlag(KernelEventFlag handle, uint64_t bits) {
	if (bits == 0) return KERNEL_ERROR_EINVAL;
	const auto flag = Acquire(handle);
	return flag != nullptr ? flag->Change(KernelEventFlagState::Operation::Set, bits, nullptr,
	                                      reinterpret_cast<uint64_t>(__builtin_return_address(0)))
	                       : KERNEL_ERROR_ESRCH;
}

int KYTY_SYSV_ABI KernelSetEventFlag(KernelEventFlag handle, uint64_t bits) {
	PRINT_NAME();
	const auto flag = Acquire(handle);
	return flag != nullptr ? flag->Change(KernelEventFlagState::Operation::Set, bits, nullptr,
	                                      reinterpret_cast<uint64_t>(__builtin_return_address(0)))
	                       : KERNEL_ERROR_ESRCH;
}

int KYTY_SYSV_ABI KernelClearEventFlag(KernelEventFlag handle, uint64_t bits) {
	PRINT_NAME();
	const auto flag = Acquire(handle);
	return flag != nullptr ? flag->Change(KernelEventFlagState::Operation::Clear, bits, nullptr,
	                                      reinterpret_cast<uint64_t>(__builtin_return_address(0)))
	                       : KERNEL_ERROR_ESRCH;
}

int KYTY_SYSV_ABI KernelCancelEventFlag(KernelEventFlag handle, uint64_t bits, int* waiting) {
	PRINT_NAME();
	const auto flag = Acquire(handle);
	return flag != nullptr ? flag->Change(KernelEventFlagState::Operation::Cancel, bits, waiting,
	                                      reinterpret_cast<uint64_t>(__builtin_return_address(0)))
	                       : KERNEL_ERROR_ESRCH;
}

} // namespace Libs::LibKernel::EventFlag
