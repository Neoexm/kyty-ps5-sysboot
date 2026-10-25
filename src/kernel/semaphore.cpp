#include "kernel/semaphore.h"

#include "common/assert.h"
#include "common/logging/log.h"
#include "common/stringUtils.h"
#include "common/threads.h"
#include "common/timer.h"
#include "libs/errno.h"
#include "libs/libs.h"
#include "kernel/memory.h"
#include "kernel/process.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <unordered_map>
#include <vector>

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace Libs::LibKernel {
void KernelDispatchPendingSignalForCurrentThread();
bool CanAccessCurrentThreadStack(const void* pointer, uint64_t size, bool writable);
} // namespace Libs::LibKernel

namespace Libs::Jemspace {
bool QueryAllocation(const void* pointer, uint64_t size, uint64_t* offset_out,
                     uint64_t* allocation_size_out);
bool CopyToAllocation(void* destination, const void* source, uint64_t size);
bool CopyFromAllocation(void* destination, const void* source, uint64_t size);
} // namespace Libs::Jemspace

namespace Libs::LibKernel::Semaphore {

LIB_NAME("libkernel", "libkernel");

constexpr uint32_t SIGNAL_APC_POLL_MICROS = 10000;

// Cross-process named semaphores, like the event-flag table in eventFlag.cpp. Keyed on
// Process::GetScope() so SysCore and ShellCore share one SceSysCoreEventSemaphore count.
struct ScopeSemaphores {
	static constexpr uint32_t MaxSemas   = 128;
	static constexpr uint32_t MaxWaiters = 64;
	static constexpr uint64_t Signature  = 0x324d45535954594bull;

	struct Sema {
		char     name[32];
		uint64_t generation;
		uint64_t creator_birth;
		uint32_t creator;
		bool     linked;
		bool     deleted;
		bool     fifo;
		uint32_t canceled;
		int32_t  count;
		int32_t  init_count;
		int32_t  max_count;
		uint64_t waiters;
	};

	uint64_t signature;
	uint64_t next_generation;
	Sema     semas[MaxSemas];
};

struct ScopeSemaphoreContext {
	std::string      name;
	ScopeSemaphores* table = nullptr;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	HANDLE mutex   = nullptr;
	HANDLE section = nullptr;
	~ScopeSemaphoreContext() {
		if (table != nullptr) UnmapViewOfFile(table);
		if (section != nullptr) CloseHandle(section);
		if (mutex != nullptr) CloseHandle(mutex);
	}
#endif
};

class KernelSemaPrivate {
public:
	enum class Result { Ok, TimedOut, Canceled, Deleted, InvalCount };

	KernelSemaPrivate(const std::string& name, bool fifo, int init_count, int max_count)
	    : m_name(name), m_fifo_order(fifo), m_count(init_count), m_init_count(init_count),
	      m_max_count(max_count) {};
	virtual ~KernelSemaPrivate() = default;

	KYTY_CLASS_NO_COPY(KernelSemaPrivate);

	Result Cancel(int set_count, int* num_waiting_threads);
	Result Signal(int signal_count);
	Result Wait(int need_count, uint32_t* ptr_micros);
	void   Delete();
	int    WaitingCount();

	Result Poll(int need_count) {
		uint32_t micros = 0;
		return Wait(need_count, &micros);
	}

	[[nodiscard]] const std::string& GetName() const { return m_name; }

	std::shared_ptr<ScopeSemaphoreContext> scope;
	ScopeSemaphores::Sema*                 shared     = nullptr;
	uint64_t                               generation = 0;
	std::string                            key;

private:
	enum class Status { Set, Deleted };

	struct WaitingThread {
		int    id         = 0;
		int    priority   = 700;
		int    need_count = 0;
		Result result     = Result::TimedOut;
		bool   ready      = false;
	};

	void AddWaiter(WaitingThread* waiter);
	void RemoveWaiter(WaitingThread* waiter);
	void WakeWaiters();
	Result WaitShared(int need_count, uint32_t* ptr_micros);

	Common::Mutex               m_mutex;
	Common::CondVar             m_cond_var;
	std::string                 m_name;
	Status                      m_status = Status::Set;
	std::vector<WaitingThread*> m_waiting_threads;
	bool                        m_fifo_order;
	int                         m_count;
	int                         m_init_count;
	int                         m_max_count;
};

struct SemaHandle {
	std::shared_ptr<KernelSemaPrivate> sem;
	int                                pid;
	bool                               creator;
};

static Common::Mutex                                                       g_named_semas_mutex;
static std::unordered_map<std::string, std::shared_ptr<KernelSemaPrivate>> g_named_semas;
static std::unordered_map<KernelSema, SemaHandle>                          g_semas;
static std::map<std::string, std::shared_ptr<ScopeSemaphoreContext>>       g_scopes;
static uint64_t                                                            g_next_sema = 0x40000000;

namespace {

class ScopeLock {
public:
	explicit ScopeLock(ScopeSemaphoreContext* scope): scope(scope) {
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
	ScopeSemaphoreContext* scope;
	bool                   locked = false;
	KYTY_CLASS_NO_COPY(ScopeLock);
};

int CountWaiters(uint64_t mask) {
	int n = 0;
	for (uint32_t i = 0; i < ScopeSemaphores::MaxWaiters; ++i) {
		if ((mask & (1ull << i)) != 0) ++n;
	}
	return n;
}

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
uint64_t ProcessBirth(HANDLE process) {
	FILETIME created {}, exited {}, kernel {}, user {};
	if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return 0;
	return (uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime;
}

bool CreatorAlive(const ScopeSemaphores::Sema& sema) {
	HANDLE process =
	    OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, sema.creator);
	if (process == nullptr) return GetLastError() != ERROR_INVALID_PARAMETER;
	const DWORD    status = WaitForSingleObject(process, 0);
	const uint64_t birth  = ProcessBirth(process);
	const bool     alive  = status != WAIT_OBJECT_0 && (birth == 0 || birth == sema.creator_birth);
	CloseHandle(process);
	return alive;
}

std::string WakeName(const ScopeSemaphoreContext& scope, const ScopeSemaphores::Sema& sema,
                     uint32_t waiter) {
	return scope.name + "_g" + std::to_string(sema.generation) + "_w" + std::to_string(waiter);
}

int Wake(ScopeSemaphoreContext& scope, ScopeSemaphores::Sema& sema) {
	int count = 0;
	for (uint32_t waiter = 0; waiter < ScopeSemaphores::MaxWaiters; ++waiter) {
		if ((sema.waiters & (1ull << waiter)) == 0) continue;
		HANDLE event = OpenEventA(EVENT_MODIFY_STATE, FALSE, WakeName(scope, sema, waiter).c_str());
		if (event == nullptr) {
			sema.waiters &= ~(1ull << waiter);
			continue;
		}
		SetEvent(event);
		CloseHandle(event);
		++count;
	}
	return count;
}

void UnlinkDeadCreators(ScopeSemaphoreContext& scope) {
	for (auto& sema: scope.table->semas) {
		if (!sema.linked || CreatorAlive(sema)) continue;
		sema.linked = false;
	}
}
#endif

std::string NamespaceKey(const char* name) {
	std::string scope;
	return (Process::GetScope(&scope) ? scope : std::string()) + "\n" + name;
}

int GetScopeContext(std::shared_ptr<ScopeSemaphoreContext>* output) {
	std::string scope;
	if (!Process::GetScope(&scope)) return OK;
	const auto found = g_scopes.find(scope);
	if (found != g_scopes.end()) {
		*output = found->second;
		return OK;
	}
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	auto context   = std::make_shared<ScopeSemaphoreContext>();
	context->name  = "Local\\kyty_ps5_" + scope + "_sema_v2";
	context->mutex = CreateMutexA(nullptr, FALSE, (context->name + "_lock").c_str());
	if (context->mutex == nullptr) return KERNEL_ERROR_EIO;
	ScopeLock lock(context.get());
	if (!lock.locked) return KERNEL_ERROR_EIO;
	context->section =
	    CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
		                   sizeof(ScopeSemaphores), (context->name + "_state").c_str());
	if (context->section == nullptr) return KERNEL_ERROR_EIO;
	const bool created = GetLastError() != ERROR_ALREADY_EXISTS;
	context->table     = static_cast<ScopeSemaphores*>(MapViewOfFile(
	    context->section, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(ScopeSemaphores)));
	if (context->table == nullptr) return KERNEL_ERROR_EIO;
	if (created) {
		context->table->signature       = ScopeSemaphores::Signature;
		context->table->next_generation = 1;
	}
	if (context->table->signature != ScopeSemaphores::Signature ||
	    context->table->next_generation == 0)
		return KERNEL_ERROR_EIO;
	g_scopes.emplace(scope, context);
	*output = std::move(context);
	return OK;
#else
	return KERNEL_ERROR_ENOSYS;
#endif
}

int Attach(KernelSemaPrivate& sema, bool create, int init = 0, int max = 0, bool fifo = false) {
	const int status = GetScopeContext(&sema.scope);
	if (status != OK || sema.scope == nullptr) return status;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	ScopeLock lock(sema.scope.get());
	if (!lock.locked) return KERNEL_ERROR_EIO;
	UnlinkDeadCreators(*sema.scope);
	ScopeSemaphores::Sema* empty = nullptr;
	for (auto& candidate: sema.scope->table->semas) {
		if (candidate.generation == 0 && empty == nullptr) empty = &candidate;
		if (!candidate.linked || sema.GetName() != candidate.name) continue;
		if (create) return KERNEL_ERROR_EEXIST;
		sema.shared     = &candidate;
		sema.generation = candidate.generation;
		return OK;
	}
	if (!create) return KERNEL_ERROR_ENOENT;
	if (empty == nullptr || sema.scope->table->next_generation == UINT64_MAX)
		return KERNEL_ERROR_ENOSPC;
	const uint64_t birth = ProcessBirth(GetCurrentProcess());
	if (birth == 0) return KERNEL_ERROR_EIO;
	std::strcpy(empty->name, sema.GetName().c_str());
	empty->generation    = sema.scope->table->next_generation++;
	empty->creator       = GetCurrentProcessId();
	empty->creator_birth = birth;
	empty->fifo          = fifo;
	empty->count         = init;
	empty->init_count    = init;
	empty->max_count     = max;
	empty->canceled      = 0;
	empty->deleted       = false;
	empty->waiters       = 0;
	empty->linked        = true;
	sema.shared          = empty;
	sema.generation      = empty->generation;
#endif
	return OK;
}

bool NameLinked(KernelSemaPrivate& sema) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (sema.shared != nullptr) {
		ScopeLock lock(sema.scope.get());
		if (!lock.locked) return false;
		UnlinkDeadCreators(*sema.scope);
		return sema.shared->linked && !sema.shared->deleted;
	}
#endif
	return true;
}

KernelSema NewHandle() {
	return g_next_sema <= 0x4fffffff ? reinterpret_cast<KernelSema>(g_next_sema++) : nullptr;
}

bool FindEntry(KernelSema handle, std::shared_ptr<KernelSemaPrivate>* object) {
	Common::LockGuard lock(g_named_semas_mutex);
	const auto        found = g_semas.find(handle);
	if (found == g_semas.end() || found->second.pid != Process::GetPid()) return false;
	*object = found->second.sem;
	return true;
}

} // namespace

void KernelSemaPrivate::Delete() {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (shared != nullptr) {
		ScopeLock lock(scope.get());
		if (!lock.locked) return;
		shared->deleted = true;
		shared->linked  = false;
		Wake(*scope, *shared);
		return;
	}
#endif
	Common::LockGuard lock(m_mutex);

	m_status = Status::Deleted;

	for (auto* waiter: m_waiting_threads) {
		if (!waiter->ready) {
			waiter->result = Result::Deleted;
			waiter->ready  = true;
		}
	}

	m_cond_var.SignalAll();
}

int KernelSemaPrivate::WaitingCount() {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (shared != nullptr) {
		ScopeLock lock(scope.get());
		if (!lock.locked) return 0;
		return CountWaiters(shared->waiters);
	}
#endif
	Common::LockGuard lock(m_mutex);
	return static_cast<int>(
	    std::count_if(m_waiting_threads.begin(), m_waiting_threads.end(),
		              [](const WaitingThread* waiter) { return !waiter->ready; }));
}

KernelSemaPrivate::Result KernelSemaPrivate::Cancel(int set_count, int* num_waiting_threads) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (shared != nullptr) {
		ScopeLock lock(scope.get());
		if (!lock.locked) return Result::Deleted;
		if (set_count > shared->max_count) return Result::InvalCount;
		if (shared->deleted) return Result::Deleted;
		if (num_waiting_threads != nullptr) *num_waiting_threads = CountWaiters(shared->waiters);
		shared->count = (set_count < 0 ? shared->init_count : set_count);
		++shared->canceled;
		Wake(*scope, *shared);
		return Result::Ok;
	}
#endif
	Common::LockGuard lock(m_mutex);

	if (set_count > m_max_count) {
		return Result::InvalCount;
	}

	if (m_status == Status::Deleted) {
		return Result::Deleted;
	}

	if (num_waiting_threads != nullptr) {
		*num_waiting_threads = static_cast<int>(
		    std::count_if(m_waiting_threads.begin(), m_waiting_threads.end(),
		                  [](const WaitingThread* waiter) { return !waiter->ready; }));
	}

	m_count = (set_count < 0 ? m_init_count : set_count);

	for (auto* waiter: m_waiting_threads) {
		if (!waiter->ready) {
			waiter->result = Result::Canceled;
			waiter->ready  = true;
		}
	}

	m_cond_var.SignalAll();

	return Result::Ok;
}

KernelSemaPrivate::Result KernelSemaPrivate::Signal(int signal_count) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (shared != nullptr) {
		ScopeLock lock(scope.get());
		if (!lock.locked) return Result::Deleted;
		if (shared->deleted) return Result::Deleted;
		if (signal_count < 0 || signal_count > shared->max_count - shared->count)
			return Result::InvalCount;
		shared->count += signal_count;
		Wake(*scope, *shared);
		return Result::Ok;
	}
#endif
	Common::LockGuard lock(m_mutex);

	if (m_status == Status::Deleted) {
		return Result::Deleted;
	}

	if (signal_count < 0 || signal_count > m_max_count - m_count) {
		return Result::InvalCount;
	}

	m_count += signal_count;

	WakeWaiters();

	m_cond_var.SignalAll();

	return Result::Ok;
}

void KernelSemaPrivate::AddWaiter(WaitingThread* waiter) {
	if (m_fifo_order) {
		m_waiting_threads.push_back(waiter);
		return;
	}

	auto it = m_waiting_threads.begin();
	while (it != m_waiting_threads.end() && (*it)->priority <= waiter->priority) {
		++it;
	}
	m_waiting_threads.insert(it, waiter);
}

void KernelSemaPrivate::RemoveWaiter(WaitingThread* waiter) {
	auto it = std::find(m_waiting_threads.begin(), m_waiting_threads.end(), waiter);
	if (it != m_waiting_threads.end()) {
		m_waiting_threads.erase(it);
	}
}

void KernelSemaPrivate::WakeWaiters() {
	for (auto* waiter: m_waiting_threads) {
		if (!waiter->ready && waiter->need_count <= m_count) {
			m_count -= waiter->need_count;
			waiter->result = Result::Ok;
			waiter->ready  = true;
		}
	}
}

// Shared-count Wait. Slices capped at the 10ms APC cadence. Wakes in lock-arrival order, not
// FIFO/priority; fine for the one-consumer doorbell.
KernelSemaPrivate::Result KernelSemaPrivate::WaitShared(int need_count, uint32_t* ptr_micros) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	const bool     infinitely = (ptr_micros == nullptr);
	const uint32_t micros     = infinitely ? 0 : *ptr_micros;

	Common::Timer t;
	t.Start();
	uint32_t elapsed = 0;

	ScopeLock lock(scope.get());
	if (!lock.locked) return Result::Deleted;
	if (need_count < 1 || need_count > shared->max_count) return Result::InvalCount;
	if (shared->deleted) return Result::Deleted;

	const uint32_t serial = shared->canceled;
	Result         status = Result::TimedOut;

	for (;;) {
		if (shared->deleted) {
			status = Result::Deleted;
			break;
		}
		if (shared->canceled != serial) {
			status = Result::Canceled;
			break;
		}
		if (shared->count >= need_count) {
			shared->count -= need_count;
			status = Result::Ok;
			break;
		}
		if (!infinitely && elapsed >= micros) {
			status = Result::TimedOut;
			break;
		}

		uint32_t waiter = 0;
		while (waiter < ScopeSemaphores::MaxWaiters && (shared->waiters & (1ull << waiter)) != 0)
			++waiter;
		HANDLE event = nullptr;
		if (waiter < ScopeSemaphores::MaxWaiters) {
			event = CreateEventA(nullptr, FALSE, FALSE, WakeName(*scope, *shared, waiter).c_str());
			if (event != nullptr) shared->waiters |= 1ull << waiter;
		}

		uint32_t slice = SIGNAL_APC_POLL_MICROS;
		if (!infinitely) slice = std::min(slice, micros - elapsed);

		ReleaseMutex(scope->mutex);
		lock.locked = false;
		if (event != nullptr)
			WaitForSingleObject(event, (slice + 999u) / 1000u);
		else
			Sleep((slice + 999u) / 1000u);
		LibKernel::KernelDispatchPendingSignalForCurrentThread();
		const DWORD acquired = WaitForSingleObject(scope->mutex, INFINITE);
		lock.locked          = acquired == WAIT_OBJECT_0 || acquired == WAIT_ABANDONED;
		if (event != nullptr) {
			if (lock.locked) shared->waiters &= ~(1ull << waiter);
			CloseHandle(event);
		}
		if (!lock.locked) return Result::Deleted;
		elapsed = static_cast<uint32_t>(t.GetTimeS() * 1000000.0);
	}

	if (ptr_micros != nullptr) *ptr_micros = (elapsed >= micros ? 0 : micros - elapsed);
	return status;
#else
	(void)need_count;
	(void)ptr_micros;
	return Result::Deleted;
#endif
}

KernelSemaPrivate::Result KernelSemaPrivate::Wait(int need_count, uint32_t* ptr_micros) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (shared != nullptr) return WaitShared(need_count, ptr_micros);
#endif
	Common::LockGuard lock(m_mutex);

	if (need_count < 1 || need_count > m_max_count) {
		return Result::InvalCount;
	}

	if (m_status == Status::Deleted) {
		return Result::Deleted;
	}

	uint32_t micros     = 0;
	bool     infinitely = true;
	if (ptr_micros != nullptr) {
		micros     = *ptr_micros;
		infinitely = false;
	}

	uint32_t      elapsed = 0;
	Common::Timer t;
	t.Start();

	int id = Common::Thread::GetThreadIdUnique();

	if (m_count >= need_count) {
		m_count -= need_count;
		if (ptr_micros != nullptr) {
			*ptr_micros = micros;
		}
		return Result::Ok;
	}

	if (!infinitely && micros == 0) {
		return Result::TimedOut;
	}

	WaitingThread waiter {};
	waiter.id         = id;
	waiter.priority   = (m_fifo_order ? 0 : Libs::LibKernel::PthreadGetCurrentPriorityForKernel());
	waiter.need_count = need_count;
	AddWaiter(&waiter);

	while (!waiter.ready) {
		if ((elapsed >= micros && !infinitely)) {
			RemoveWaiter(&waiter);
			*ptr_micros = 0;
			return Result::TimedOut;
		}

		if (infinitely) {
			m_cond_var.WaitFor(&m_mutex, SIGNAL_APC_POLL_MICROS);
		} else {
			m_cond_var.WaitFor(&m_mutex, micros - elapsed);
		}

		m_mutex.Unlock();
		LibKernel::KernelDispatchPendingSignalForCurrentThread();
		m_mutex.Lock();

		elapsed = static_cast<uint32_t>(t.GetTimeS() * 1000000.0);
	}

	RemoveWaiter(&waiter);

	if (ptr_micros != nullptr) {
		*ptr_micros = (elapsed >= micros ? 0 : micros - elapsed);
	}

	return waiter.result;
}

int KYTY_SYSV_ABI KernelCreateSema(KernelSema* sem, const char* name, uint32_t attr, int init,
                                   int max, void* opt) {
	PRINT_NAME();

	if (sem == nullptr) return KERNEL_ERROR_EFAULT;

	const auto order = attr & 0x3u;
	if (name == nullptr || (attr & ~0x103u) != 0 || order > 2 || init < 0 || max <= 0 ||
	    init > max) {
		return KERNEL_ERROR_EINVAL;
	}
	if ((attr & 0x100u) != 0 && std::strlen(name) >= sizeof(ScopeSemaphores::Sema::name)) {
		return KERNEL_ERROR_ENAMETOOLONG;
	}

	bool fifo = false;

	switch (order) {
		case 0x01: fifo = true; break;
		case 0x02:
		default: fifo = false; break;
	}

	auto created = std::make_shared<KernelSemaPrivate>(std::string(name), fifo, init, max);
	created->key = NamespaceKey(name);
	Common::LockGuard lock(g_named_semas_mutex);
	const auto        handle = NewHandle();
	if (handle == nullptr) return KERNEL_ERROR_EMFILE;
	if ((attr & 0x100u) != 0) {
		auto found = g_named_semas.find(created->key);
		if (found != g_named_semas.end()) {
			if (NameLinked(*found->second)) return KERNEL_ERROR_EEXIST;
			g_named_semas.erase(found);
		}
		const int status = Attach(*created, true, init, max, fifo);
		if (status != OK) return status;
		g_named_semas.emplace(created->key, created);
	}
	g_semas.emplace(handle, SemaHandle {created, Process::GetPid(), true});
	*sem = handle;

	return OK;
}

int KYTY_SYSV_ABI KernelOpenSema(KernelSema* sem, const char* name) {
	PRINT_NAME();

	if (sem == nullptr) {
		return KERNEL_ERROR_EFAULT;
	}
	if (name == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	const std::string key = NamespaceKey(name);
	Common::LockGuard lock(g_named_semas_mutex);
	auto              it = g_named_semas.find(key);
	if (it != g_named_semas.end()) {
		if (NameLinked(*it->second)) {
			const auto handle = NewHandle();
			if (handle == nullptr) return KERNEL_ERROR_EMFILE;
			g_semas.emplace(handle, SemaHandle {it->second, Process::GetPid(), false});
			*sem = handle;
			LOGF("\t named sem open: %s -> 0x%016" PRIx64 "\n", name,
			     reinterpret_cast<uint64_t>(*sem));
			return OK;
		}
		g_named_semas.erase(it);
	}

	auto meta        = std::make_shared<KernelSemaPrivate>(std::string(name), true, 0, 0);
	meta->key        = key;
	const int status = Attach(*meta, false);
	if (status != OK || meta->scope == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}
	const auto handle = NewHandle();
	if (handle == nullptr) return KERNEL_ERROR_EMFILE;
	g_named_semas.emplace(key, meta);
	g_semas.emplace(handle, SemaHandle {meta, Process::GetPid(), false});
	*sem = handle;
	LOGF("FIRST_FRAME_AUDIT SHARED_KERNEL_SEMA_OPEN_GUEST name=%s generation=%llu -> 0x%016" PRIx64
	     "\n",
	     name, static_cast<unsigned long long>(meta->generation), reinterpret_cast<uint64_t>(*sem));
	return OK;
}

int KernelOpenExistingSema(KernelSema* sem, const char* name) {
	return KernelOpenSema(sem, name);
}

int KYTY_SYSV_ABI KernelCloseSema(KernelSema sem) {
	PRINT_NAME();

	Common::LockGuard lock(g_named_semas_mutex);
	const auto        found = g_semas.find(sem);
	if (found == g_semas.end() || found->second.pid != Process::GetPid()) return KERNEL_ERROR_ESRCH;
	if (found->second.creator) return KERNEL_ERROR_EPERM;
	g_semas.erase(found);
	return OK;
}

int KYTY_SYSV_ABI KernelDeleteSema(KernelSema sem) {
	PRINT_NAME();

	Common::LockGuard lock(g_named_semas_mutex);
	const auto        found = g_semas.find(sem);
	if (found == g_semas.end() || found->second.pid != Process::GetPid()) return KERNEL_ERROR_ESRCH;
	if (!found->second.creator) return KERNEL_ERROR_EPERM;
	const auto object = found->second.sem;
	object->Delete();
	const auto named = g_named_semas.find(object->key);
	if (named != g_named_semas.end() && named->second == object) {
		g_named_semas.erase(named);
	}
	g_semas.erase(found);
	return OK;
}

int KernelSemaWaiterCountForTesting(KernelSema sem) {
	std::shared_ptr<KernelSemaPrivate> object;
	if (!FindEntry(sem, &object)) return -1;
	return object->WaitingCount();
}

int KYTY_SYSV_ABI KernelWaitSema(KernelSema sem, int need, KernelUseconds* time) {
	if (need <= 0) return KERNEL_ERROR_EINVAL;
	std::shared_ptr<KernelSemaPrivate> object;
	if (!FindEntry(sem, &object)) {
		return KERNEL_ERROR_ESRCH;
	}

	auto result = object->Wait(need, time);

	int ret = OK;

	switch (result) {
		case KernelSemaPrivate::Result::Ok: ret = OK; break;
		case KernelSemaPrivate::Result::InvalCount: ret = KERNEL_ERROR_EINVAL; break;
		case KernelSemaPrivate::Result::TimedOut: ret = KERNEL_ERROR_ETIMEDOUT; break;
		case KernelSemaPrivate::Result::Canceled: ret = KERNEL_ERROR_ECANCELED; break;
		case KernelSemaPrivate::Result::Deleted: ret = KERNEL_ERROR_EACCES; break;
	}

	return ret;
}

int KYTY_SYSV_ABI KernelPollSema(KernelSema sem, int need) {
	PRINT_NAME();

	std::shared_ptr<KernelSemaPrivate> object;
	if (!FindEntry(sem, &object)) {
		return KERNEL_ERROR_ESRCH;
	}

	auto result = object->Poll(need);

	int ret = OK;

	switch (result) {
		case KernelSemaPrivate::Result::Ok: ret = OK; break;
		case KernelSemaPrivate::Result::InvalCount: ret = KERNEL_ERROR_EINVAL; break;
		case KernelSemaPrivate::Result::TimedOut:
		case KernelSemaPrivate::Result::Canceled:
		case KernelSemaPrivate::Result::Deleted: ret = KERNEL_ERROR_EBUSY; break;
	}

	return ret;
}

int KYTY_SYSV_ABI KernelSignalSema(KernelSema sem, int count) {
	std::shared_ptr<KernelSemaPrivate> object;
	if (!FindEntry(sem, &object)) {
		return KERNEL_ERROR_ESRCH;
	}

	auto result = object->Signal(count);

	int ret = OK;

	switch (result) {
		case KernelSemaPrivate::Result::Ok: ret = OK; break;
		case KernelSemaPrivate::Result::InvalCount:
		case KernelSemaPrivate::Result::TimedOut:
		case KernelSemaPrivate::Result::Canceled:
		case KernelSemaPrivate::Result::Deleted: ret = KERNEL_ERROR_EINVAL; break;
	}

	return ret;
}

int KYTY_SYSV_ABI KernelCancelSema(KernelSema sem, int count, int* threads) {
	PRINT_NAME();

	std::shared_ptr<KernelSemaPrivate> object;
	if (!FindEntry(sem, &object)) {
		return KERNEL_ERROR_ESRCH;
	}

	auto result = object->Cancel(count, threads);

	int ret = OK;

	switch (result) {
		case KernelSemaPrivate::Result::Ok: ret = OK; break;
		case KernelSemaPrivate::Result::InvalCount:
		case KernelSemaPrivate::Result::TimedOut:
		case KernelSemaPrivate::Result::Canceled:
		case KernelSemaPrivate::Result::Deleted: ret = KERNEL_ERROR_EINVAL; break;
	}

	return ret;
}

} // namespace Libs::LibKernel::Semaphore

namespace Libs::Posix {

LIB_NAME("Posix", "libkernel");

namespace {

constexpr uint16_t POSIX_SEM_MAGIC        = 0x736d;
constexpr uint16_t POSIX_SEM_UNNAMED_ID   = 0xffff;
constexpr int      POSIX_SEM_VALUE_MAX    = 0x7fffffff;
constexpr uint32_t SIGNAL_APC_POLL_MICROS = 10000;
constexpr size_t   POSIX_SEM_NAME_CAP     = 32;

struct PosixSemGuest {
	uint16_t          magic;
	uint16_t          nameid;
	volatile uint32_t has_waiters;
	volatile uint32_t count;
	uint32_t          flags;
};

static_assert(sizeof(PosixSemGuest) == 16);
static_assert(offsetof(PosixSemGuest, magic) == 0);
static_assert(offsetof(PosixSemGuest, nameid) == 2);
static_assert(offsetof(PosixSemGuest, has_waiters) == 4);
static_assert(offsetof(PosixSemGuest, count) == 8);
static_assert(offsetof(PosixSemGuest, flags) == 12);

static bool ReadGuestOrStack(void* destination, const void* source, size_t size);
static bool WriteGuestOrStack(void* destination, const void* source, size_t size);

class PosixSemPrivate {
public:
	PosixSemPrivate(PosixSemGuest* guest, unsigned int value, uint32_t flags)
	    : m_guest(guest), m_count(static_cast<int>(value)), m_flags(flags) {}

	bool InitializeGuest() {
		Common::LockGuard lock(m_mutex);
		return SyncGuest();
	}

	int Wait(uint32_t* micros) {
		Common::LockGuard lock(m_mutex);

		uint32_t      elapsed    = 0;
		const bool    timed_wait = (micros != nullptr);
		Common::Timer timer;
		timer.Start();

		while (m_count <= 0) {
			if (timed_wait && elapsed >= *micros) {
				SyncGuest();
				return POSIX_ETIMEDOUT;
			}

			m_waiters++;
			SyncGuest();

			if (timed_wait) {
				// a pending signal or suspend request is only seen between slices
				m_cond_var.WaitFor(&m_mutex, std::min(*micros - elapsed, SIGNAL_APC_POLL_MICROS));
			} else {
				m_cond_var.WaitFor(&m_mutex, SIGNAL_APC_POLL_MICROS);
			}

			m_mutex.Unlock();
			LibKernel::KernelDispatchPendingSignalForCurrentThread();
			m_mutex.Lock();

			m_waiters--;
			elapsed = static_cast<uint32_t>(timer.GetTimeS() * 1000000.0);
		}

		m_count--;
		SyncGuest();

		return OK;
	}

	int TryWait() {
		Common::LockGuard lock(m_mutex);

		if (m_count <= 0) {
			SyncGuest();
			return POSIX_EAGAIN;
		}

		m_count--;
		SyncGuest();

		return OK;
	}

	int Post() {
		Common::LockGuard lock(m_mutex);

		if (m_count == POSIX_SEM_VALUE_MAX) {
			return POSIX_EOVERFLOW;
		}

		m_count++;
		SyncGuest();
		m_cond_var.Signal();

		return OK;
	}

	int GetValue() {
		Common::LockGuard lock(m_mutex);

		return m_count;
	}

	uint16_t GetNameId() {
		Common::LockGuard lock(m_mutex);
		return m_name_id;
	}

	bool SetNameId(uint16_t name_id) {
		Common::LockGuard lock(m_mutex);
		const uint16_t    previous = m_name_id;
		m_name_id                  = name_id;
		if (SyncGuest()) {
			return true;
		}
		m_name_id = previous;
		return false;
	}

private:
	bool SyncGuest() {
		PosixSemGuest state {};
		state.magic       = POSIX_SEM_MAGIC;
		state.nameid      = m_name_id;
		state.has_waiters = (m_waiters > 0 ? 1u : 0u);
		state.count       = static_cast<uint32_t>(m_count);
		state.flags       = m_flags;
		return m_guest != nullptr && WriteGuestOrStack(m_guest, &state, sizeof(state));
	}

	Common::Mutex   m_mutex;
	Common::CondVar m_cond_var;
	PosixSemGuest*  m_guest   = nullptr;
	int             m_count   = 0;
	uint32_t        m_waiters = 0;
	uint16_t        m_name_id = POSIX_SEM_UNNAMED_ID;
	uint32_t        m_flags   = 0;
};

struct PosixSemNameMetadata {
	uint16_t                             id     = POSIX_SEM_UNNAMED_ID;
	uint8_t                              length = 0;
	uint64_t                             digest = 0;
	std::array<char, POSIX_SEM_NAME_CAP> bytes {};
};

Common::Mutex                                        g_posix_sem_mutex;
std::unordered_map<PosixSemGuest*, PosixSemPrivate*> g_posix_sems;
std::unordered_map<PosixSemGuest*, PosixSemNameMetadata> g_posix_sem_names;
std::array<bool, POSIX_SEM_UNNAMED_ID>                   g_posix_sem_name_ids {};
uint16_t                                                 g_posix_sem_next_name_id = 0;

static uint64_t NameDigest(const char* bytes, size_t length) {
	uint64_t digest = 1469598103934665603ull;
	for (size_t i = 0; i < length; ++i) {
		digest ^= static_cast<uint8_t>(bytes[i]);
		digest *= 1099511628211ull;
	}
	return digest;
}

static bool ReadGuestOrStack(void* destination, const void* source, size_t size) {
	if (LibKernel::Memory::CopyFromGuest(destination, source, size)) {
		return true;
	}
	if (Jemspace::CopyFromAllocation(destination, source, size)) {
		return true;
	}
	if (!LibKernel::CanAccessCurrentThreadStack(source, size, false)) {
		return false;
	}
	std::memcpy(destination, source, size);
	return true;
}

static bool WriteGuestOrStack(void* destination, const void* source, size_t size) {
	if (LibKernel::Memory::CopyToGuest(destination, source, size)) {
		return true;
	}
	if (Jemspace::CopyToAllocation(destination, source, size)) {
		return true;
	}
	if (!LibKernel::CanAccessCurrentThreadStack(destination, size, true)) {
		return false;
	}
	std::memcpy(destination, source, size);
	return true;
}

static int ReadPosixSemName(const char* name, PosixSemNameMetadata* metadata) {
	if (name == nullptr || metadata == nullptr) {
		return POSIX_EFAULT;
	}
	const auto address = reinterpret_cast<uint64_t>(name);
	for (size_t i = 0; i < metadata->bytes.size(); ++i) {
		if (address > UINT64_MAX - i ||
		    !ReadGuestOrStack(&metadata->bytes[i], reinterpret_cast<const void*>(address + i), 1)) {
			return POSIX_EFAULT;
		}
		if (metadata->bytes[i] == '\0') {
			metadata->length = static_cast<uint8_t>(i);
			metadata->digest = NameDigest(metadata->bytes.data(), i);
			return OK;
		}
	}
	return POSIX_ENAMETOOLONG;
}

static uint16_t AllocatePosixSemNameIdLocked() {
	for (uint32_t i = 0; i < POSIX_SEM_UNNAMED_ID - 1; ++i) {
		g_posix_sem_next_name_id = static_cast<uint16_t>(g_posix_sem_next_name_id % 0xfffeu + 1u);
		if (!g_posix_sem_name_ids[g_posix_sem_next_name_id]) {
			g_posix_sem_name_ids[g_posix_sem_next_name_id] = true;
			return g_posix_sem_next_name_id;
		}
	}
	return POSIX_SEM_UNNAMED_ID;
}

static void ReleasePosixSemNameLocked(PosixSemGuest* guest) {
	const auto found = g_posix_sem_names.find(guest);
	if (found == g_posix_sem_names.end()) {
		return;
	}
	if (found->second.id != 0 && found->second.id != POSIX_SEM_UNNAMED_ID) {
		g_posix_sem_name_ids[found->second.id] = false;
	}
	g_posix_sem_names.erase(found);
}

static int PosixToKernel(int posix_errno) {
	return (posix_errno >= 0 && posix_errno <= 102 ? posix_errno - 2147352576
	                                               : LibKernel::KERNEL_ERROR_EINVAL);
}

static PosixSemPrivate* GetSem(void* sem) {
	if (sem == nullptr) {
		return nullptr;
	}

	Common::LockGuard lock(g_posix_sem_mutex);

	const auto it = g_posix_sems.find(static_cast<PosixSemGuest*>(sem));
	return (it != g_posix_sems.end() ? it->second : nullptr);
}

static int SetErrnoReturn(int posix_errno) {
	*GetErrorAddr() = posix_errno;
	return -1;
}

static int SemInitImpl(void* sem, int pshared, unsigned int value, const char* name) {
	if (sem == nullptr || value > POSIX_SEM_VALUE_MAX) {
		return POSIX_EINVAL;
	}

	auto* guest = static_cast<PosixSemGuest*>(sem);
	auto*            obj               = new PosixSemPrivate(guest, value, pshared != 0 ? 1u : 0u);
	PosixSemPrivate* previous          = nullptr;
	bool             guest_init_failed = false;

	{
		Common::LockGuard lock(g_posix_sem_mutex);
		if (!obj->InitializeGuest()) {
			guest_init_failed = true;
		} else if (auto it = g_posix_sems.find(guest); it != g_posix_sems.end()) {
			ReleasePosixSemNameLocked(guest);
			previous   = it->second;
			it->second = obj;
		} else {
			g_posix_sems.insert({guest, obj});
		}
	}
	if (guest_init_failed) {
		delete obj;
		log_state("efault");
		return POSIX_EFAULT;
	}
	delete previous;
	log_state("initialized");

	static std::atomic<uint32_t> log_count {0};
	const auto                   count = log_count.fetch_add(1);
	if (count < 32) {
		LOGF("\t POSIX semaphore init: %s, value = %u, pshared = %d\n",
		     (name != nullptr ? name : "sem"), value, pshared);
	}

	return OK;
}

static int SemDestroyImpl(void* sem) {
	if (sem == nullptr) {
		return POSIX_EINVAL;
	}

	auto*            guest = static_cast<PosixSemGuest*>(sem);
	PosixSemPrivate* obj   = nullptr;

	{
		Common::LockGuard lock(g_posix_sem_mutex);

		const auto it = g_posix_sems.find(guest);
		if (it == g_posix_sems.end()) {
			return POSIX_EINVAL;
		}
		PosixSemGuest state {};
		if (!ReadGuestOrStack(&state, guest, sizeof(state))) {
			return POSIX_EFAULT;
		}
		if (state.magic != POSIX_SEM_MAGIC || (state.flags & 0x2u) != 0) {
			return POSIX_EINVAL;
		}
		const uint16_t cleared_magic = 0;
		if (!WriteGuestOrStack(&guest->magic, &cleared_magic, sizeof(cleared_magic))) {
			return POSIX_EFAULT;
		}

		obj = it->second;
		g_posix_sems.erase(it);
		ReleasePosixSemNameLocked(guest);
	}

	delete obj;

	return OK;
}

static int SemTimedwaitImpl(void* sem, uint32_t* micros) {
	auto* obj = GetSem(sem);
	if (obj == nullptr) {
		return POSIX_EINVAL;
	}

	return obj->Wait(micros);
}

static bool AbsTimespecToMicros(const LibKernel::KernelTimespec* abstime, uint32_t* micros) {
	if (abstime == nullptr || micros == nullptr || abstime->tv_sec < 0 || abstime->tv_nsec < 0 ||
	    abstime->tv_nsec >= 1000000000) {
		return false;
	}

	LibKernel::KernelTimespec now {};
	if (LibKernel::KernelClockGettime(0, &now) != OK) {
		return false;
	}

	const int64_t sec_delta  = abstime->tv_sec - now.tv_sec;
	const int64_t nsec_delta = abstime->tv_nsec - now.tv_nsec;
	const int64_t usec_delta = sec_delta * 1000000 + nsec_delta / 1000;

	if (usec_delta <= 0) {
		*micros = 0;
	} else if (usec_delta > std::numeric_limits<uint32_t>::max()) {
		*micros = std::numeric_limits<uint32_t>::max();
	} else {
		*micros = static_cast<uint32_t>(usec_delta);
	}

	return true;
}

} // namespace

int KYTY_SYSV_ABI sem_init(void* sem, int pshared, unsigned int value) {
	PRINT_NAME();

	const int result = SemInitImpl(sem, pshared, value, nullptr);
	return (result == OK ? 0 : SetErrnoReturn(result));
}

int KYTY_SYSV_ABI sem_setname(void* sem, const char* name) {
	if (sem == nullptr) {
		return SetErrnoReturn(POSIX_EINVAL);
	}
	auto*    guest            = static_cast<PosixSemGuest*>(sem);
	uint16_t installed_id     = POSIX_SEM_UNNAMED_ID;
	uint32_t installed_length = 0;
	{
		Common::LockGuard lock(g_posix_sem_mutex);
		const auto        found = g_posix_sems.find(guest);
		if (found == g_posix_sems.end()) {
			return SetErrnoReturn(POSIX_EINVAL);
		}
		auto* obj = found->second;
		if (obj->GetNameId() != POSIX_SEM_UNNAMED_ID) {
			return SetErrnoReturn(POSIX_EAGAIN);
		}
		uint32_t first_word = 0;
		if (!ReadGuestOrStack(&first_word, guest, sizeof(first_word))) {
			return SetErrnoReturn(POSIX_EFAULT);
		}
		if (static_cast<uint16_t>(first_word >> 16u) != POSIX_SEM_UNNAMED_ID) {
			return SetErrnoReturn(POSIX_EAGAIN);
		}
		PosixSemNameMetadata metadata;
		const int            copy_result = ReadPosixSemName(name, &metadata);
		if (copy_result != OK) {
			return SetErrnoReturn(copy_result);
		}
		if (static_cast<uint16_t>(first_word) != POSIX_SEM_MAGIC) {
			return SetErrnoReturn(POSIX_EAGAIN);
		}
		const uint16_t id = AllocatePosixSemNameIdLocked();
		if (id == POSIX_SEM_UNNAMED_ID) {
			return SetErrnoReturn(POSIX_EAGAIN);
		}
		metadata.id = id;
		try {
			const auto [entry, inserted] = g_posix_sem_names.emplace(guest, metadata);
			if (!inserted) {
				g_posix_sem_name_ids[id] = false;
				return SetErrnoReturn(POSIX_EAGAIN);
			}
		} catch (const std::bad_alloc&) {
			g_posix_sem_name_ids[id] = false;
			return SetErrnoReturn(POSIX_ENOMEM);
		}
		if (!obj->SetNameId(id)) {
			ReleasePosixSemNameLocked(guest);
			return SetErrnoReturn(POSIX_EFAULT);
		}
		installed_id     = id;
		installed_length = metadata.length;
	}
	static std::atomic<uint32_t> log_count {0};
	if (log_count.fetch_add(1) < 32) {
		LOGF("FIRST_FRAME_AUDIT SEM_SETNAME_STATE pid=%d result=installed id=%u name_length=%u "
		     "abi_transition=1\n",
		     LibKernel::Process::GetPid(), installed_id, installed_length);
	}
	return 0;
}

int KYTY_SYSV_ABI sem_destroy(void* sem) {
	PRINT_NAME();

	const int result = SemDestroyImpl(sem);
	return (result == OK ? 0 : SetErrnoReturn(result));
}

int KYTY_SYSV_ABI sem_wait(void* sem) {
	const int result = SemTimedwaitImpl(sem, nullptr);
	return (result == OK ? 0 : SetErrnoReturn(result));
}

int KYTY_SYSV_ABI sem_trywait(void* sem) {
	auto* obj = GetSem(sem);
	if (obj == nullptr) {
		return SetErrnoReturn(POSIX_EINVAL);
	}

	const int result = obj->TryWait();
	return (result == OK ? 0 : SetErrnoReturn(result));
}

int KYTY_SYSV_ABI sem_reltimedwait_np(void* sem, uint32_t usec) {
	const int result = SemTimedwaitImpl(sem, &usec);
	return (result == OK ? 0 : SetErrnoReturn(result));
}

int KYTY_SYSV_ABI sem_timedwait(void* sem, const LibKernel::KernelTimespec* abstime) {
	uint32_t micros = 0;
	if (!AbsTimespecToMicros(abstime, &micros)) {
		return SetErrnoReturn(POSIX_EINVAL);
	}

	const int result = SemTimedwaitImpl(sem, &micros);
	return (result == OK ? 0 : SetErrnoReturn(result));
}

int KYTY_SYSV_ABI sem_post(void* sem) {
	auto* obj = GetSem(sem);
	if (obj == nullptr) {
		return SetErrnoReturn(POSIX_EINVAL);
	}

	const int result = obj->Post();
	return (result == OK ? 0 : SetErrnoReturn(result));
}

int KYTY_SYSV_ABI sem_getvalue(void* sem, int* value) {
	auto* obj = GetSem(sem);
	if (obj == nullptr || value == nullptr) {
		return SetErrnoReturn(POSIX_EINVAL);
	}

	*value = obj->GetValue();

	return 0;
}

bool PosixSemNameSnapshotForTesting(void* sem, PosixSemNameSnapshot* snapshot) {
	if (snapshot == nullptr) {
		return false;
	}
	Common::LockGuard lock(g_posix_sem_mutex);
	*snapshot               = {};
	snapshot->live_names    = g_posix_sem_names.size();
	snapshot->allocated_ids = static_cast<size_t>(
	    std::count(g_posix_sem_name_ids.begin(), g_posix_sem_name_ids.end(), true));
	const auto object = g_posix_sems.find(static_cast<PosixSemGuest*>(sem));
	if (object == g_posix_sems.end()) {
		return false;
	}
	snapshot->name_id   = object->second->GetNameId();
	const auto metadata = g_posix_sem_names.find(static_cast<PosixSemGuest*>(sem));
	if (metadata != g_posix_sem_names.end()) {
		snapshot->name_length = metadata->second.length;
		snapshot->name_digest = metadata->second.digest;
	}
	return true;
}

} // namespace Libs::Posix

namespace Libs::LibKernel::Semaphore {

int KYTY_SYSV_ABI PthreadSemInit(void* sem, int flag, unsigned int value, const char* name) {
	PRINT_NAME();

	if (flag != 0) {
		return KERNEL_ERROR_EINVAL;
	}

	const int result = Posix::SemInitImpl(sem, 0, value, name);
	return (result == OK ? OK : Posix::PosixToKernel(result));
}

int KYTY_SYSV_ABI PthreadSemDestroy(void* sem) {
	PRINT_NAME();

	const int result = Posix::SemDestroyImpl(sem);
	return (result == OK ? OK : Posix::PosixToKernel(result));
}

int KYTY_SYSV_ABI PthreadSemWait(void* sem) {
	const int result = Posix::SemTimedwaitImpl(sem, nullptr);
	return (result == OK ? OK : Posix::PosixToKernel(result));
}

int KYTY_SYSV_ABI PthreadSemTrywait(void* sem) {
	auto* obj = Posix::GetSem(sem);
	if (obj == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	const int result = obj->TryWait();
	return (result == OK ? OK : Posix::PosixToKernel(result));
}

int KYTY_SYSV_ABI PthreadSemTimedwait(void* sem, KernelUseconds usec) {
	uint32_t  micros = usec;
	const int result = Posix::SemTimedwaitImpl(sem, &micros);
	return (result == OK ? OK : Posix::PosixToKernel(result));
}

int KYTY_SYSV_ABI PthreadSemPost(void* sem) {
	auto* obj = Posix::GetSem(sem);
	if (obj == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	const int result = obj->Post();
	return (result == OK ? OK : Posix::PosixToKernel(result));
}

int KYTY_SYSV_ABI PthreadSemGetvalue(void* sem, int* value) {
	auto* obj = Posix::GetSem(sem);
	if (obj == nullptr || value == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	*value = obj->GetValue();

	return OK;
}

} // namespace Libs::LibKernel::Semaphore
