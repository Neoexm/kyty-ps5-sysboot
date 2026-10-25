#include "kernel/pthread.h"

#include "common/assert.h"
#include "common/common.h"
#include "common/dateTime.h"
#include "common/emulatorConfig.h"
#include "common/hostException.h"
#include "common/logging/log.h"
#include "common/singleton.h"
#include "common/stringUtils.h"
#include "common/threads.h"
#include "common/timer.h"
#include "kernel/execProcess.h"
#include "kernel/memory.h"
#include "kernel/process.h"
#include "kernel/fileSystem.h"
#include "libs/errno.h"
#include "libs/libs.h"
#include "loader/runtimeLinker.h"
#include "loader/timer.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <mutex>
#include <new>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#ifndef NOMINMAX
#define NOMINMAX
#endif
#if defined(_M_X64) || defined(__x86_64__)
#include <intrin.h>
#endif
#include <windows.h>
#endif

#if KYTY_PLATFORM == KYTY_PLATFORM_LINUX
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <pthread.h>

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#include <fmt/format.h>
#include <pthread_time.h>
#elif !defined(__APPLE__)
#include <sys/syscall.h>
#include <unistd.h>
#endif

#if KYTY_PLATFORM != KYTY_PLATFORM_WINDOWS
#include <csignal> // pthread_kill is declared here, not in <pthread.h>
#endif

#if KYTY_PLATFORM != KYTY_PLATFORM_WINDOWS && (defined(_M_X64) || defined(__x86_64__))
#include <x86intrin.h>
#endif

#ifdef pthread_attr_getguardsize
#undef pthread_attr_getguardsize
#endif

namespace Libs {

namespace LibcInternalExt {
void RunThreadAtexitDestructors();
} // namespace LibcInternalExt

namespace LibKernel {

LIB_NAME("libkernel", "libkernel");

// macOS's <pthread.h>/<limits.h> define PTHREAD_STACK_MIN as a macro; the emulator
// wants its own guest-side value with the same name, so drop the host macro here.
#ifdef PTHREAD_STACK_MIN
#undef PTHREAD_STACK_MIN
#endif

constexpr int      KEYS_MAX                = 256;
constexpr int      DESTRUCTOR_ITERATIONS   = 4;
constexpr size_t   PTHREAD_STACK_DEFAULT   = 0x100000;
constexpr size_t   GUEST_PTHREAD_STACK_MIN = 0x4000;
constexpr size_t   PTHREAD_STACK_PAGE      = 0x4000;
constexpr size_t   PTHREAD_STACK_INITIAL   = 0x200000;
constexpr size_t   PTHREAD_STACK_EXTRA     = 0x100000;
constexpr uint64_t PTHREAD_STACK_TOP       = 0x7efff8000ull;
constexpr uint64_t PTHREAD_STACK_BOTTOM    = 0x0000040000ull;
constexpr uint32_t SIGNAL_APC_POLL_MICROS  = 10000;

static constexpr KernelClockid KERNEL_CLOCK_REALTIME          = 0;
static constexpr KernelClockid KERNEL_CLOCK_VIRTUAL           = 1;
static constexpr KernelClockid KERNEL_CLOCK_PROF              = 2;
static constexpr KernelClockid KERNEL_CLOCK_MONOTONIC         = 4;
static constexpr KernelClockid KERNEL_CLOCK_UPTIME            = 5;
static constexpr KernelClockid KERNEL_CLOCK_UPTIME_PRECISE    = 7;
static constexpr KernelClockid KERNEL_CLOCK_UPTIME_FAST       = 8;
static constexpr KernelClockid KERNEL_CLOCK_REALTIME_PRECISE  = 9;
static constexpr KernelClockid KERNEL_CLOCK_REALTIME_FAST     = 10;
static constexpr KernelClockid KERNEL_CLOCK_MONOTONIC_PRECISE = 11;
static constexpr KernelClockid KERNEL_CLOCK_MONOTONIC_FAST    = 12;
static constexpr KernelClockid KERNEL_CLOCK_SECOND            = 13;
static constexpr KernelClockid KERNEL_CLOCK_THREAD_CPUTIME_ID = 14;
static constexpr KernelClockid KERNEL_CLOCK_PROCTIME          = 15;
static constexpr KernelClockid KERNEL_CLOCK_EXT_NETWORK       = 16;
static constexpr KernelClockid KERNEL_CLOCK_EXT_DEBUG_NETWORK = 17;
static constexpr KernelClockid KERNEL_CLOCK_EXT_AD_NETWORK    = 18;
static constexpr KernelClockid KERNEL_CLOCK_EXT_RAW_NETWORK   = 19;

static constexpr int KERNEL_PTHREAD_MUTEX_ERRORCHECK = 1;
static constexpr int KERNEL_PTHREAD_MUTEX_RECURSIVE  = 2;
static constexpr int KERNEL_PTHREAD_MUTEX_NORMAL     = 3;
static constexpr int KERNEL_PTHREAD_MUTEX_ADAPTIVE   = 4;

#if KYTY_PLATFORM != KYTY_PLATFORM_WINDOWS
// OS-level thread id reported to the guest.
static uint64_t GetHostThreadId() {
#if defined(__APPLE__)
	uint64_t tid = 0;
	pthread_threadid_np(nullptr, &tid);
	return tid;
#else
	return static_cast<uint64_t>(::syscall(SYS_gettid));
#endif
}
#endif

static uint64_t KernelReadTscNative() {
#if defined(_M_X64) || defined(__x86_64__)
	return __rdtsc();
#else
	return Common::Timer::QueryPerformanceCounter();
#endif
}

static uint64_t KernelGetTscFrequencyNative() {
	static const uint64_t frequency = [] {
#if defined(_M_X64) || defined(__x86_64__)
		const auto host_frequency = Common::Timer::QueryPerformanceFrequency();
		if (host_frequency == 0) {
			return uint64_t {1000000000};
		}

		KernelReadTscNative();
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
		KernelReadTscNative();

		const auto host_start = Common::Timer::QueryPerformanceCounter();
		const auto tsc_start  = KernelReadTscNative();
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		const auto host_end = Common::Timer::QueryPerformanceCounter();
		const auto tsc_end  = KernelReadTscNative();

		const auto host_delta = host_end - host_start;
		const auto tsc_delta  = tsc_end - tsc_start;
		if (host_delta == 0 || tsc_delta == 0) {
			return host_frequency;
		}

		auto freq = static_cast<uint64_t>(
		    (static_cast<long double>(tsc_delta) * static_cast<long double>(host_frequency)) /
		    static_cast<long double>(host_delta));
		static constexpr uint64_t ROUND_TO = 100000;
		const auto                mod      = freq % ROUND_TO;
		freq = (mod >= ROUND_TO / 2 ? freq - mod + ROUND_TO : freq - mod);

		return freq != 0 ? freq : host_frequency;
#else
		return Common::Timer::QueryPerformanceFrequency();
#endif
	}();

	return frequency;
}

static uint64_t KernelGetInitialTsc() {
	static const uint64_t initial_tsc = KernelReadTscNative();
	return initial_tsc;
}

static uint64_t KernelGetElapsedTsc() {
	const auto initial_tsc = KernelGetInitialTsc();
	const auto current_tsc = KernelReadTscNative();
	return current_tsc >= initial_tsc ? current_tsc - initial_tsc : 0;
}

static uint64_t KernelGetProcessTimeUsNative() {
	const auto frequency = KernelGetTscFrequencyNative();
	if (frequency == 0) {
		return static_cast<uint64_t>(Loader::Timer::GetTimeMs() * 1000.0);
	}

	const auto elapsed = KernelGetElapsedTsc();
	return static_cast<uint64_t>((static_cast<long double>(elapsed) * 1000000.0L) /
	                             static_cast<long double>(frequency));
}

static void KernelUsToTimespec(uint64_t us, KernelTimespec* tp) {
	EXIT_IF(tp == nullptr);
	tp->tv_sec  = static_cast<int64_t>(us / 1000000);
	tp->tv_nsec = static_cast<int64_t>((us % 1000000) * 1000);
}

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
static uint64_t KernelFiletimeTo100ns(FILETIME ft) {
	ULARGE_INTEGER v {};
	v.LowPart  = ft.dwLowDateTime;
	v.HighPart = ft.dwHighDateTime;
	return v.QuadPart;
}

static void Kernel100nsToTimespec(uint64_t value, KernelTimespec* tp) {
	EXIT_IF(tp == nullptr);
	tp->tv_sec  = static_cast<int64_t>(value / 10000000);
	tp->tv_nsec = static_cast<int64_t>((value % 10000000) * 100);
}

static bool KernelRealtimeToTimespec(bool precise, KernelTimespec* tp) {
	EXIT_IF(tp == nullptr);

	FILETIME ft {};
	if (precise) {
		GetSystemTimePreciseAsFileTime(&ft);
	} else {
		GetSystemTimeAsFileTime(&ft);
	}

	static constexpr uint64_t WINDOWS_UNIX_EPOCH_DELTA_100NS = 116444736000000000ULL;
	const auto                value                          = KernelFiletimeTo100ns(ft);
	if (value < WINDOWS_UNIX_EPOCH_DELTA_100NS) {
		return false;
	}

	Kernel100nsToTimespec(value - WINDOWS_UNIX_EPOCH_DELTA_100NS, tp);
	return true;
}

static bool KernelMonotonicToTimespec(KernelTimespec* tp) {
	EXIT_IF(tp == nullptr);

	const auto frequency = Common::Timer::QueryPerformanceFrequency();
	if (frequency == 0) {
		return false;
	}

	const auto counter = Common::Timer::QueryPerformanceCounter();
	tp->tv_sec         = static_cast<int64_t>(counter / frequency);
	tp->tv_nsec        = static_cast<int64_t>(((counter % frequency) * 1000000000ull) / frequency);
	return true;
}

static bool KernelClockGettimeSpecial(KernelClockid clock_id, KernelTimespec* tp, int* error) {
	EXIT_IF(tp == nullptr);
	EXIT_IF(error == nullptr);

	if (clock_id == KERNEL_CLOCK_PROCTIME) {
		KernelUsToTimespec(KernelGetProcessTimeUsNative(), tp);
		return true;
	}

	FILETIME create_time {};
	FILETIME exit_time {};
	FILETIME kernel_time {};
	FILETIME user_time {};

	switch (clock_id) {
		case KERNEL_CLOCK_REALTIME:
		case KERNEL_CLOCK_REALTIME_PRECISE:
			if (!KernelRealtimeToTimespec(true, tp)) {
				*error = KERNEL_ERROR_EFAULT;
			}
			return true;
		case KERNEL_CLOCK_REALTIME_FAST:
		case KERNEL_CLOCK_SECOND:
			if (!KernelRealtimeToTimespec(false, tp)) {
				*error = KERNEL_ERROR_EFAULT;
			}
			if (clock_id == KERNEL_CLOCK_SECOND) {
				tp->tv_nsec = 0;
			}
			return true;
		case KERNEL_CLOCK_MONOTONIC:
		case KERNEL_CLOCK_UPTIME:
		case KERNEL_CLOCK_UPTIME_PRECISE:
		case KERNEL_CLOCK_UPTIME_FAST:
		case KERNEL_CLOCK_MONOTONIC_PRECISE:
		case KERNEL_CLOCK_MONOTONIC_FAST:
		case KERNEL_CLOCK_EXT_NETWORK:
		case KERNEL_CLOCK_EXT_DEBUG_NETWORK:
		case KERNEL_CLOCK_EXT_AD_NETWORK:
		case KERNEL_CLOCK_EXT_RAW_NETWORK:
			if (!KernelMonotonicToTimespec(tp)) {
				*error = KERNEL_ERROR_EFAULT;
			}
			return true;
		case KERNEL_CLOCK_THREAD_CPUTIME_ID:
			if (!GetThreadTimes(GetCurrentThread(), &create_time, &exit_time, &kernel_time,
			                    &user_time)) {
				*error = KERNEL_ERROR_EFAULT;
				return true;
			}
			Kernel100nsToTimespec(
			    KernelFiletimeTo100ns(kernel_time) + KernelFiletimeTo100ns(user_time), tp);
			return true;
		case KERNEL_CLOCK_VIRTUAL:
			if (!GetProcessTimes(GetCurrentProcess(), &create_time, &exit_time, &kernel_time,
			                     &user_time)) {
				*error = KERNEL_ERROR_EFAULT;
				return true;
			}
			Kernel100nsToTimespec(KernelFiletimeTo100ns(user_time), tp);
			return true;
		case KERNEL_CLOCK_PROF:
			if (!GetProcessTimes(GetCurrentProcess(), &create_time, &exit_time, &kernel_time,
			                     &user_time)) {
				*error = KERNEL_ERROR_EFAULT;
				return true;
			}
			Kernel100nsToTimespec(KernelFiletimeTo100ns(kernel_time), tp);
			return true;
		default: return false;
	}
}
#else
static bool KernelClockGettimeSpecial(KernelClockid clock_id, KernelTimespec* tp, int* error) {
	EXIT_IF(tp == nullptr);
	EXIT_IF(error == nullptr);

	if (clock_id == KERNEL_CLOCK_PROCTIME) {
		KernelUsToTimespec(KernelGetProcessTimeUsNative(), tp);
		return true;
	}

	return false;
}
#endif

struct PthreadMutexPrivate {
	uint8_t                 reserved[256];
	std::string             name;
	std::mutex              m;
	std::condition_variable cv;
	Pthread                 owner     = nullptr;
	uint32_t                count     = 0;
	int                     type      = 1;
	int                     pprotocol = PTHREAD_PRIO_NONE;
};

struct PthreadMutexattrPrivate {
	uint8_t             reserved[64];
	pthread_mutexattr_t p;
	int                 pprotocol;
	int                 type;
};

struct PthreadAttrPrivate {
	uint8_t        reserved[64];
	KernelCpumask  affinity;
	size_t         guard_size;
	void*          stack_addr;
	size_t         stack_size;
	bool           stack_user;
	uint64_t       stack_map_addr;
	size_t         stack_map_size;
	int            policy;
	int            guest_priority;
	int            inherit_sched;
	int            solosched;
	bool           detached;
	pthread_attr_t p;
};

struct PthreadGuestData {
	int32_t thread_id;
	uint8_t reserved[4092];
};

static_assert(sizeof(PthreadGuestData) == 4096);

struct PthreadPrivate {
	PthreadGuestData      guest;
	std::string           name;
	pthread_t             p;
	PthreadAttr           attr;
	pthread_entry_func_t  entry;
	void*                 arg;
	int                     guest_process_pid  = 0;
	int                     guest_parent_pid   = 0;
	uint64_t                rfork_stack_top    = 0;
	bool                    rfork_exit_known   = false;
	uint32_t                rfork_exit_status  = 0;
	bool                    rfork_exec_retired = false;
	int                   unique_id;
	std::atomic_bool      detached;
	std::atomic_bool      almost_done;
	std::atomic_bool      free;
	uint64_t              host_thread_id;
	uintptr_t             guest_host_rbx;
	uintptr_t             guest_host_rsp;
	uintptr_t             guest_host_rbp;
	uint64_t              cond_sequence = 0;
	std::condition_variable cond_cv;
	std::atomic<uint64_t> pending_signal_mask {0};
	std::atomic<uint64_t>   blocked_signal_mask[2] {};
	std::atomic_int         suspend_requests {0};
	std::atomic_bool        suspend_parked {false};
	uint64_t                guest_tcb         = 0;
	uint64_t                guest_pthread_obj = 0;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	uintptr_t guest_host_gs8;
	uintptr_t guest_host_gs10;
#endif
};

static PthreadAttrPrivate* GetPthreadAttrValue(const PthreadAttr* attr, const char* func_name) {
	if (attr == nullptr) {
		return nullptr;
	}

	auto* attr_value = *attr;
	if (attr_value == nullptr || reinterpret_cast<uint64_t>(attr_value) < 0x10000u) {
		(void)func_name;
		return nullptr;
	}

	return attr_value;
}

struct PthreadRwlockPrivate {
	struct Reader {
		Pthread  thread = nullptr;
		uint32_t count  = 0;
	};

	uint8_t                 reserved[256];
	std::string             name;
	std::mutex              m;
	std::condition_variable cv;
	Pthread                 writer          = nullptr;
	uint32_t                writer_count    = 0;
	uint32_t                reader_count    = 0;
	uint32_t                waiting_writers = 0;
	std::vector<Reader>     readers;
};

struct PthreadRwlockattrPrivate {
	uint8_t              reserved[64];
	int                  type;
	pthread_rwlockattr_t p;
};

struct PthreadCondattrPrivate {
	uint8_t            reserved[64];
	pthread_condattr_t p;
	KernelClockid      clock_id = KERNEL_CLOCK_REALTIME;
};

struct PthreadCondPrivate {
	uint8_t                 reserved[256];
	std::string             name;
	std::mutex              m;
	KernelClockid           clock_id = KERNEL_CLOCK_REALTIME;
	std::vector<Pthread>    waiters;
};

static void CondAddWaiter(PthreadCondPrivate* cond, Pthread thread) {
	EXIT_IF(cond == nullptr);
	EXIT_IF(thread == nullptr);

	cond->waiters.push_back(thread);
}

static void CondRemoveWaiter(PthreadCondPrivate* cond, Pthread thread) {
	EXIT_IF(cond == nullptr);
	EXIT_IF(thread == nullptr);

	std::erase(cond->waiters, thread);
}

static void CondWakeWaiter(PthreadCondPrivate* cond, Pthread thread) {
	EXIT_IF(cond == nullptr);

	if (thread == nullptr) {
		if (cond->waiters.empty()) {
			return;
		}
		thread = cond->waiters.front();
	}

	auto it = std::find(cond->waiters.begin(), cond->waiters.end(), thread);
	if (it == cond->waiters.end()) {
		return;
	}

	cond->waiters.erase(it);
	thread->cond_sequence++;
	// Notify while holding cond->m so the selected waiter cannot exit and be freed first.
	thread->cond_cv.notify_one();
}

void PthreadWakeForSignal(Pthread thread) {
	if (thread != nullptr) {
		thread->cond_cv.notify_one();
	}
}

void KernelDispatchPendingSignalForCurrentThread();

static void SchedulerBackoffOnce() {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (SwitchToThread() == 0) {
		Sleep(0);
	}
#else
	std::this_thread::yield();
#endif
}

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
void PthreadParkForSuspend(Pthread thread) {
	// a signal helper runs with the target's Pthread as self but isn't the suspended host thread
	if (thread->suspend_requests == 0 || thread->host_thread_id != GetCurrentThreadId()) {
		return;
	}

	// pthread_suspend_user_context_np takes a thread stopped in this window as holding no host
	// lock, so nothing in here may take one.
	thread->suspend_parked = true;
	while (thread->suspend_requests != 0) {
		SchedulerBackoffOnce();
	}
	thread->suspend_parked = false;
}
#endif

static void SleepMicroWithSignalPoll(uint64_t microseconds) {
	if (microseconds == 0) {
		KernelDispatchPendingSignalForCurrentThread();
		return;
	}

	while (microseconds > 0) {
		const auto step = std::min<uint64_t>(microseconds, SIGNAL_APC_POLL_MICROS);
		Common::Thread::SleepMicro(step);
		microseconds -= step;
		KernelDispatchPendingSignalForCurrentThread();
	}
}

static void SleepNanoWithSignalPoll(uint64_t nanoseconds) {
	if (nanoseconds == 0) {
		KernelDispatchPendingSignalForCurrentThread();
		return;
	}

	constexpr uint64_t poll_nanos = static_cast<uint64_t>(SIGNAL_APC_POLL_MICROS) * 1000ull;
	while (nanoseconds > 0) {
		const auto step = std::min<uint64_t>(nanoseconds, poll_nanos);
		Common::Thread::SleepNano(step);
		nanoseconds -= step;
		KernelDispatchPendingSignalForCurrentThread();
	}
}

struct PthreadStaticObject {
	enum class Type { Mutex, Cond, Rwlock };

	Type             type;
	uint64_t         vaddr;
	Loader::Program* program;
};

class PthreadStaticObjects {
public:
	PthreadStaticObjects() { EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread()); }
	virtual ~PthreadStaticObjects() { KYTY_NOT_IMPLEMENTED; }

	KYTY_CLASS_NO_COPY(PthreadStaticObjects);

	void* CreateObject(void* addr, PthreadStaticObject::Type type);
	void  DeleteObjects(Loader::Program* program);

private:
	std::vector<PthreadStaticObject*> m_objects;
	Common::Mutex                     m_mutex;
};

struct PthreadSpecificValue {
	uint64_t generation = 0;
	void*    data       = nullptr;
};

struct PthreadKeyState {
	// Odd generations are allocated; deletion advances to the next even generation.
	std::atomic<uint64_t>         generation {0};
	pthread_key_destructor_func_t destructor = nullptr;
};

static std::array<PthreadKeyState, KEYS_MAX>                g_pthread_keys;
static std::mutex                                           g_pthread_keys_mutex;
static thread_local std::unique_ptr<PthreadSpecificValue[]> g_pthread_specific;

static std::mutex                            g_guest_pthread_mutex;
static std::unordered_map<uint64_t, Pthread> g_guest_pthread_objects;

class PthreadPool {
public:
	PthreadPool() { EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread()); }
	virtual ~PthreadPool() { KYTY_NOT_IMPLEMENTED; }

	KYTY_CLASS_NO_COPY(PthreadPool);

	Pthread Create();
	bool    CopyNameByGuestId(int guest_tid, char* name);

	void FreeDetachedThreads();

private:
	std::vector<Pthread> m_threads;
	Common::Mutex        m_mutex;
};

class PThreadContext {
public:
	PThreadContext() { EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread()); }
	virtual ~PThreadContext() { KYTY_NOT_IMPLEMENTED; }

	KYTY_CLASS_NO_COPY(PThreadContext);

	PthreadAttr*       GetDefaultAttr() { return &m_default_attr; }
	void               SetDefaultAttr(PthreadAttr attr) { m_default_attr = attr; }
	PthreadCondattr*   GetDefaultCondattr() { return &m_default_condattr; }
	void               SetDefaultCondattr(PthreadCondattr attr) { m_default_condattr = attr; }
	PthreadMutexattr*  GetDefaultMutexattr() { return &m_default_mutexattr; }
	void               SetDefaultMutexattr(PthreadMutexattr attr) { m_default_mutexattr = attr; }
	PthreadRwlockattr* GetDefaultRwlockattr() { return &m_default_rwlockattr; }
	void               SetDefaultRwlockattr(PthreadRwlockattr attr) { m_default_rwlockattr = attr; }
	PthreadPool*       GetPthreadPool() { return m_pthread_pool; }
	void               SetPthreadPool(PthreadPool* pool) { m_pthread_pool = pool; }
	PthreadStaticObjects* GetPthreadStaticObjects() { return m_pthread_static_objects; }
	void SetPthreadStaticObjects(PthreadStaticObjects* objs) { m_pthread_static_objects = objs; }

	[[nodiscard]] thread_dtors_func_t GetThreadDtors() const { return m_thread_dtors; }
	void SetThreadDtors(thread_dtors_func_t dtors) { m_thread_dtors = dtors; }

private:
	// Common::Mutex           m_mutex;
	PthreadMutexattr      m_default_mutexattr      = nullptr;
	PthreadRwlockattr     m_default_rwlockattr     = nullptr;
	PthreadCondattr       m_default_condattr       = nullptr;
	PthreadAttr           m_default_attr           = nullptr;
	PthreadPool*          m_pthread_pool           = nullptr;
	PthreadStaticObjects* m_pthread_static_objects = nullptr;

	std::atomic<thread_dtors_func_t> m_thread_dtors = nullptr;
};

thread_local Pthread        g_pthread_self           = nullptr;
static Pthread              g_pthread_main           = nullptr;
PThreadContext*             g_pthread_context        = nullptr;
thread_local uintptr_t      g_guest_entry_return_rsp = 0;
static std::atomic<int32_t> g_pthread_thread_id      = 0;

static Common::Mutex g_guest_stack_mutex;
static uint64_t      g_guest_stack_last = 0;
struct CachedGuestStack {
	uint64_t address;
	size_t   map_size;
	size_t   guard_size;
};
static std::vector<CachedGuestStack> g_guest_stack_cache;

static size_t RoundStackSize(size_t size) {
	return ((size + PTHREAD_STACK_PAGE - 1) / PTHREAD_STACK_PAGE) * PTHREAD_STACK_PAGE;
}

static int CreateGuestStack(PthreadAttr attr) {
	if (attr == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	if (attr->stack_addr != nullptr) {
		attr->guard_size     = 0;
		attr->stack_user     = true;
		attr->stack_map_addr = 0;
		attr->stack_map_size = 0;
		return OK;
	}

	const auto stack_size = RoundStackSize(attr->stack_size);
	const auto guard_size = RoundStackSize(attr->guard_size);
	const auto map_size   = stack_size + guard_size;

	uint64_t stack_addr = 0;
	bool     cached     = false;
	{
		Common::LockGuard lock(g_guest_stack_mutex);

		auto cached_stack =
		    std::find_if(g_guest_stack_cache.begin(), g_guest_stack_cache.end(),
		                 [map_size, guard_size](const auto& stack) {
			                 return stack.map_size == map_size && stack.guard_size == guard_size;
		                 });
		if (cached_stack != g_guest_stack_cache.end()) {
			stack_addr = cached_stack->address;
			g_guest_stack_cache.erase(cached_stack);
			cached = true;
		} else {
			if (g_guest_stack_last == 0) {
				g_guest_stack_last = PTHREAD_STACK_TOP - PTHREAD_STACK_INITIAL - PTHREAD_STACK_PAGE;
			}
			if (map_size > g_guest_stack_last - PTHREAD_STACK_BOTTOM) {
				return KERNEL_ERROR_EAGAIN;
			}
			stack_addr = g_guest_stack_last - map_size;
			g_guest_stack_last -= map_size;
		}
	}

	int result = OK;
	if (!cached) {
		stack_addr = Memory::AllocateGuestStackMemory(
		    stack_addr, map_size, Common::VirtualMemory::Mode::ReadWrite, "stack");
		if (stack_addr == 0) {
			return KERNEL_ERROR_EAGAIN;
		}
	}

	if (guard_size != 0) {
		result = Memory::KernelMprotect(reinterpret_cast<void*>(stack_addr), guard_size, 0);
		if (result != OK) {
			Memory::KernelMunmap(stack_addr, map_size);
			return KERNEL_ERROR_EAGAIN;
		}
	}

	attr->stack_addr     = reinterpret_cast<void*>(stack_addr + guard_size);
	attr->stack_size     = stack_size;
	attr->stack_user     = false;
	attr->stack_map_addr = stack_addr;
	attr->stack_map_size = map_size;

	std::memset(attr->stack_addr, 0, stack_size);

	return OK;
}

static void FreeGuestStack(PthreadAttr attr) {
	if (attr == nullptr || attr->stack_user || attr->stack_map_addr == 0 ||
	    attr->stack_map_size == 0) {
		return;
	}

	const auto guard_size = attr->stack_map_size - attr->stack_size;
	{
		Common::LockGuard lock(g_guest_stack_mutex);
		g_guest_stack_cache.push_back({attr->stack_map_addr, attr->stack_map_size, guard_size});
	}

	attr->stack_addr     = nullptr;
	attr->stack_map_addr = 0;
	attr->stack_map_size = 0;
}

#if defined(KYTY_VIRTUAL_MEMORY_ALLOCATION_TESTS)
bool TestGuestStackOwnerLifecycle(uint64_t* first_address, uint64_t* second_address,
                                  uint64_t* map_size) {
	if (first_address == nullptr || second_address == nullptr || map_size == nullptr) {
		return false;
	}

	size_t flexible_before = 0;
	if (Memory::KernelAvailableFlexibleMemorySize(&flexible_before) != OK) {
		return false;
	}

	PthreadAttr attr = nullptr;
	if (PthreadAttrInit(&attr) != OK) {
		return false;
	}
	if (CreateGuestStack(attr) != OK) {
		PthreadAttrDestroy(&attr);
		return false;
	}
	*first_address = attr->stack_map_addr;
	*map_size      = attr->stack_map_size;
	const bool first_owned =
	    Memory::TestGuestAddressRangeIsOwned(*first_address, static_cast<uint64_t>(*map_size));
	uint64_t   backing_value = 0;
	const bool first_private =
	    !Memory::TryReadBacking(*first_address, &backing_value, sizeof(backing_value));
	size_t     flexible_during_first = 0;
	const bool first_capacity_unchanged =
	    Memory::KernelAvailableFlexibleMemorySize(&flexible_during_first) == OK &&
	    flexible_during_first == flexible_before;
	FreeGuestStack(attr);

	if (CreateGuestStack(attr) != OK) {
		PthreadAttrDestroy(&attr);
		return false;
	}
	*second_address = attr->stack_map_addr;
	const bool second_owned =
	    Memory::TestGuestAddressRangeIsOwned(*second_address, static_cast<uint64_t>(*map_size));
	const bool second_private =
	    !Memory::TryReadBacking(*second_address, &backing_value, sizeof(backing_value));
	size_t     flexible_during_second = 0;
	const bool second_capacity_unchanged =
	    Memory::KernelAvailableFlexibleMemorySize(&flexible_during_second) == OK &&
	    flexible_during_second == flexible_before;
	FreeGuestStack(attr);

	CachedGuestStack cached {};
	bool             found = false;
	{
		Common::LockGuard lock(g_guest_stack_mutex);
		const auto        entry = std::find_if(
		    g_guest_stack_cache.begin(), g_guest_stack_cache.end(),
		    [second_address](const auto& stack) { return stack.address == *second_address; });
		if (entry != g_guest_stack_cache.end()) {
			cached = *entry;
			g_guest_stack_cache.erase(entry);
			found = true;
		}
	}

	const bool unmapped = found && Memory::KernelMunmap(cached.address, cached.map_size) == OK;
	size_t     flexible_after = 0;
	const bool final_capacity_unchanged =
	    Memory::KernelAvailableFlexibleMemorySize(&flexible_after) == OK &&
	    flexible_after == flexible_before;
	return PthreadAttrDestroy(&attr) == OK && first_owned && first_private &&
	       first_capacity_unchanged && second_owned && second_private &&
	       second_capacity_unchanged && unmapped && final_capacity_unchanged;
}
#endif

static KYTY_SYSV_ABI void* RunOnGuestStack(void* arg, pthread_entry_func_t func, void* stack_top) {
#if defined(__x86_64__) || defined(_M_X64)
	void*      ret = nullptr;
	const auto aligned_stack_top =
	    reinterpret_cast<uintptr_t>(stack_top) & ~static_cast<uintptr_t>(0x0f);
	const auto guest_rsp = aligned_stack_top - 2u * sizeof(uintptr_t);
	const auto guest_rbp = guest_rsp;

	auto* guest_root_frame = reinterpret_cast<uintptr_t*>(guest_rbp);
	guest_root_frame[0]    = 0;
	guest_root_frame[1]    = 0;

	g_guest_entry_return_rsp = guest_rsp - sizeof(uint64_t);

	uintptr_t host_rsp = 0;
	uintptr_t host_rbp = 0;
	uintptr_t host_rbx = 0;
	asm volatile("movq %%rsp, %0\n\t"
	             "movq %%rbp, %1\n\t"
	             "movq %%rbx, %2\n\t"
	             : "=r"(host_rsp), "=r"(host_rbp), "=r"(host_rbx)
	             :
	             : "memory");

	if (g_pthread_self != nullptr) {
		g_pthread_self->guest_host_rbx = host_rbx;
#if defined(__APPLE__)
		g_pthread_self->guest_host_rsp = host_rsp - (2u * sizeof(uint64_t));
#else
		g_pthread_self->guest_host_rsp = host_rsp - (4u * sizeof(uint64_t));
#endif
		g_pthread_self->guest_host_rbp = host_rbp;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		uintptr_t host_gs8  = 0;
		uintptr_t host_gs10 = 0;
		asm volatile("movq %%gs:0x08, %0\n\t"
		             "movq %%gs:0x10, %1\n\t"
		             : "=r"(host_gs8), "=r"(host_gs10)
		             :
		             : "memory");
		g_pthread_self->guest_host_gs8  = host_gs8;
		g_pthread_self->guest_host_gs10 = host_gs10;
#endif
	}

	// The guest ABI expects the entry argument in rdi and a 16-byte aligned stack before call.
#if defined(__APPLE__)
	// Keep inputs out of r12/r13.
	register uintptr_t guest_rsp_reg asm("r14") = guest_rsp;
	register uintptr_t guest_rbp_reg asm("r15") = guest_rbp;
	asm volatile("pushq %%r12\n\t"
	             "pushq %%r13\n\t"
	             "movq %%rsp, %%r12\n\t"
	             "movq %%rbp, %%r13\n\t"
	             "movq %[guest_rsp], %%rsp\n\t"
	             "movq %[guest_rbp], %%rbp\n\t"
	             "callq *%%rsi\n\t"
	             "movq %%r13, %%rbp\n\t"
	             "movq %%r12, %%rsp\n\t"
	             "popq %%r13\n\t"
	             "popq %%r12\n\t"
	             : "=a"(ret), "+D"(arg), "+S"(func)
	             : [guest_rsp] "r"(guest_rsp_reg), [guest_rbp] "r"(guest_rbp_reg)
	             : "cc", "memory", "rcx", "rdx", "r8", "r9", "r10", "r11", "xmm0", "xmm1", "xmm2",
	               "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11",
	               "xmm12", "xmm13", "xmm14", "xmm15");
#else
	// PthreadExit resumes at this frame, so all four saved registers stay on the host stack.
	asm volatile("pushq %%r12\n\t"
	             "pushq %%r13\n\t"
	             "pushq %%r14\n\t"
	             "pushq %%r15\n\t"
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	             "movq %%gs:0x08, %%r14\n\t"
	             "movq %%gs:0x10, %%r15\n\t"
	             "xorq %%rcx, %%rcx\n\t"
	             "movq %%rcx, %%gs:0x08\n\t"
	             "movq %%rcx, %%gs:0x10\n\t"
#endif
	             "movq %%rsp, %%r12\n\t"
	             "movq %%rbp, %%r13\n\t"
	             "movq %[guest_rsp], %%rsp\n\t"
	             "movq %[guest_rbp], %%rbp\n\t"
	             "callq *%%rsi\n\t"
	             "movq %%r13, %%rbp\n\t"
	             "movq %%r12, %%rsp\n\t"
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	             "movq %%r14, %%gs:0x08\n\t"
	             "movq %%r15, %%gs:0x10\n\t"
#endif
	             "popq %%r15\n\t"
	             "popq %%r14\n\t"
	             "popq %%r13\n\t"
	             "popq %%r12\n\t"
	             : "=a"(ret), "+D"(arg), "+S"(func)
	             : [guest_rsp] "r"(guest_rsp), [guest_rbp] "r"(guest_rbp)
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	             : "cc", "memory", "rcx", "rdx", "r8", "r9", "r10", "r11", "xmm0", "xmm1", "xmm2",
	               "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11",
	               "xmm12", "xmm13", "xmm14", "xmm15");
#else
	             : "cc", "memory", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "xmm0",
	               "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10",
	               "xmm11", "xmm12", "xmm13", "xmm14", "xmm15");
#endif
#endif

	g_guest_entry_return_rsp = 0;
	if (g_pthread_self != nullptr) {
		g_pthread_self->guest_host_rbx = 0;
		g_pthread_self->guest_host_rsp = 0;
		g_pthread_self->guest_host_rbp = 0;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		g_pthread_self->guest_host_gs8  = 0;
		g_pthread_self->guest_host_gs10 = 0;
#endif
	}

	return ret;
#else
	(void)stack_top;
	return func(arg);
#endif
}

static void UpdateCurrentThreadStackAttr(PthreadAttr* attr) {
	if (attr == nullptr || *attr == nullptr) {
		return;
	}

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	ULONG_PTR low  = 0;
	ULONG_PTR high = 0;
	GetCurrentThreadStackLimits(&low, &high);

	if (low != 0 && high > low) {
		(*attr)->stack_addr = reinterpret_cast<void*>(low);
		(*attr)->stack_size = high - low;
		(*attr)->stack_user = true;
	}
#elif defined(__APPLE__)
	// macOS reports a stack top and size.
	void*        top  = pthread_get_stackaddr_np(pthread_self());
	const size_t size = pthread_get_stacksize_np(pthread_self());

	if (top != nullptr && size != 0) {
		(*attr)->stack_addr = static_cast<void*>(static_cast<uint8_t*>(top) - size);
		(*attr)->stack_size = size;
		(*attr)->stack_user = true;
	}
#else
	// Record the main thread's stack bounds.
	pthread_attr_t self_attr {};
	if (pthread_getattr_np(pthread_self(), &self_attr) == 0) {
		void*  base = nullptr;
		size_t size = 0;
		if (pthread_attr_getstack(&self_attr, &base, &size) == 0 && base != nullptr && size != 0) {
			(*attr)->stack_addr = base;
			(*attr)->stack_size = size;
			(*attr)->stack_user = true;
		}
		pthread_attr_destroy(&self_attr);
	}
#endif
}

static void FreeDetachedThreads(void* /*arg*/) {
	PRINT_NAME_ENABLE(false);

	auto* pthread_pool = g_pthread_context->GetPthreadPool();

	while (true) {
		std::this_thread::sleep_for(std::chrono::milliseconds(10000));
		pthread_pool->FreeDetachedThreads();
	}
}

void PthreadDeleteStaticObjects(Loader::Program* program) {

	auto* pthread_static_objects = g_pthread_context->GetPthreadStaticObjects();

	pthread_static_objects->DeleteObjects(program);
}

void PthreadInitSelfForMainThread() {
	EXIT_IF(g_pthread_self != nullptr);

#if KYTY_PLATFORM == KYTY_PLATFORM_LINUX
	if (!Common::HostException::InitializeThreadSignalStack()) {
		EXIT("Failed to initialize the thread signal stack\n");
	}
#endif

	const auto inherited_mask = PthreadGetSignalMask(nullptr);
	g_pthread_self = new PthreadPrivate {};
	PthreadSetSignalMask(g_pthread_self, inherited_mask);
	PthreadAttrInit(&g_pthread_self->attr);
	UpdateCurrentThreadStackAttr(&g_pthread_self->attr);
	g_pthread_self->p               = pthread_self();
	g_pthread_self->name            = "MainThread";
	g_pthread_self->guest.thread_id = ++g_pthread_thread_id;
	g_pthread_self->unique_id       = Common::Thread::GetThreadIdUnique();
	g_pthread_self->free            = false;
	g_pthread_self->detached        = false;
	g_pthread_self->almost_done     = false;
	g_pthread_self->entry           = nullptr;
	g_pthread_self->arg             = nullptr;

	uint64_t os_thread_id = 0;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	os_thread_id = static_cast<uint64_t>(GetCurrentThreadId());
#else
	os_thread_id = GetHostThreadId();
#endif
	g_pthread_self->host_thread_id = os_thread_id;
	g_pthread_main                 = g_pthread_self;

	LOGF("\tPthread main self: id = %d, os_thread_id = %" PRIu64 ", stack_addr = 0x%016" PRIx64
	     ", stack_size = %" PRIu64 "\n",
	     g_pthread_self->unique_id, os_thread_id,
	     reinterpret_cast<uint64_t>(g_pthread_self->attr->stack_addr),
	     static_cast<uint64_t>(g_pthread_self->attr->stack_size));
}

void* PthreadCreateMainGuestStack() {
	EXIT_IF(g_pthread_self == nullptr);
	EXIT_IF(g_pthread_self->attr == nullptr);

	if (g_pthread_self->attr->stack_map_addr != 0) {
		return reinterpret_cast<void*>(
		    (reinterpret_cast<uintptr_t>(g_pthread_self->attr->stack_addr) +
		     g_pthread_self->attr->stack_size) &
		    ~static_cast<uintptr_t>(0x0f));
	}

	g_pthread_self->attr->stack_addr     = nullptr;
	g_pthread_self->attr->stack_size     = PTHREAD_STACK_DEFAULT + PTHREAD_STACK_EXTRA;
	g_pthread_self->attr->stack_user     = false;
	g_pthread_self->attr->stack_map_addr = 0;
	g_pthread_self->attr->stack_map_size = 0;

	const auto result = CreateGuestStack(g_pthread_self->attr);
	EXIT_NOT_IMPLEMENTED(result != OK);

	auto* stack_top =
	    reinterpret_cast<void*>((reinterpret_cast<uintptr_t>(g_pthread_self->attr->stack_addr) +
	                             g_pthread_self->attr->stack_size) &
	                            ~static_cast<uintptr_t>(0x0f));

	LOGF("\tPthread main guest stack: stack_addr = 0x%016" PRIx64 ", stack_size = %" PRIu64
	     ", stack_top = 0x%016" PRIx64 "\n",
	     reinterpret_cast<uint64_t>(g_pthread_self->attr->stack_addr),
	     static_cast<uint64_t>(g_pthread_self->attr->stack_size),
	     reinterpret_cast<uint64_t>(stack_top));

	return stack_top;
}

uint64_t PthreadGetMainGuestStackTop() {
	uint64_t stack_addr = 0;
	uint64_t stack_size = 0;
	if (!PthreadGetGuestStack(g_pthread_main, &stack_addr, &stack_size) ||
	    stack_addr > UINT64_MAX - stack_size) {
		return 0;
	}
	return (stack_addr + stack_size) & ~uint64_t {0xf};
}

void Initialize() {
	PRINT_NAME_ENABLE(false);

	EXIT_IF(g_pthread_context != nullptr);

	g_pthread_context = new PThreadContext;

	g_pthread_context->SetPthreadStaticObjects(new PthreadStaticObjects);
	g_pthread_context->SetPthreadPool(new PthreadPool);
	Common::CondVar::SetWaitPollCallback(KernelDispatchPendingSignalForCurrentThread);

	PthreadMutexattr  default_mutexattr  = nullptr;
	PthreadRwlockattr default_rwlockattr = nullptr;
	PthreadCondattr   default_condattr   = nullptr;
	PthreadAttr       default_attr       = nullptr;

	PthreadAttrInit(&default_attr);
	PthreadMutexattrInit(&default_mutexattr);
	PthreadRwlockattrInit(&default_rwlockattr);
	PthreadCondattrInit(&default_condattr);

	g_pthread_context->SetDefaultMutexattr(default_mutexattr);
	g_pthread_context->SetDefaultRwlockattr(default_rwlockattr);
	g_pthread_context->SetDefaultCondattr(default_condattr);
	g_pthread_context->SetDefaultAttr(default_attr);

	PRINT_NAME_ENABLE(true);

	Common::Thread thread(FreeDetachedThreads, nullptr);
	thread.Detach();
}

static int PthreadAttrCopy(PthreadAttr* dst, const PthreadAttr* src) {
	if (dst == nullptr || *dst == nullptr || src == nullptr || *src == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	KernelCpumask    mask          = 0;
	int              state         = 0;
	size_t           guard_size    = 0;
	int              inherit_sched = 0;
	KernelSchedParam param         = {};
	int              policy        = 0;
	int              solosched     = 0;
	void*            stack_addr    = nullptr;
	size_t           stack_size    = 0;

	int result = 0;

	result = (result == 0 ? PthreadAttrGetaffinity(src, &mask) : result);
	result = (result == 0 ? PthreadAttrGetdetachstate(src, &state) : result);
	result = (result == 0 ? PthreadAttrGetguardsize(src, &guard_size) : result);
	result = (result == 0 ? PthreadAttrGetinheritsched(src, &inherit_sched) : result);
	result = (result == 0 ? PthreadAttrGetschedparam(src, &param) : result);
	result = (result == 0 ? PthreadAttrGetschedpolicy(src, &policy) : result);
	result = (result == 0 ? PthreadAttrGetsolosched(src, &solosched) : result);
	result = (result == 0 ? PthreadAttrGetstackaddr(src, &stack_addr) : result);
	result = (result == 0 ? PthreadAttrGetstacksize(src, &stack_size) : result);

	result = (result == 0 ? PthreadAttrSetaffinity(dst, mask) : result);
	result = (result == 0 ? PthreadAttrSetdetachstate(dst, state) : result);
	result = (result == 0 ? PthreadAttrSetguardsize(dst, guard_size) : result);
	result = (result == 0 ? PthreadAttrSetinheritsched(dst, inherit_sched) : result);
	result = (result == 0 ? PthreadAttrSetschedparam(dst, &param) : result);
	result = (result == 0 ? PthreadAttrSetschedpolicy(dst, policy) : result);
	result = (result == 0 ? PthreadAttrSetsolosched(dst, solosched) : result);
	if (stack_addr != nullptr) {
		result = (result == 0 ? PthreadAttrSetstackaddr(dst, stack_addr) : result);
	}
	if (stack_size != 0) {
		result = (result == 0 ? PthreadAttrSetstacksize(dst, stack_size) : result);
	}
	return result;
}

static void PthreadAttrDbgPrint(const PthreadAttr* src) {
	KernelCpumask    mask          = 0;
	int              state         = 0;
	size_t           guard_size    = 0;
	int              inherit_sched = 0;
	KernelSchedParam param         = {};
	int              policy        = 0;
	int              solosched     = 0;
	void*            stack_addr    = nullptr;
	size_t           stack_size    = 0;

	PthreadAttrGetaffinity(src, &mask);
	PthreadAttrGetdetachstate(src, &state);
	PthreadAttrGetguardsize(src, &guard_size);
	PthreadAttrGetinheritsched(src, &inherit_sched);
	PthreadAttrGetschedparam(src, &param);
	PthreadAttrGetschedpolicy(src, &policy);
	PthreadAttrGetsolosched(src, &solosched);
	PthreadAttrGetstackaddr(src, &stack_addr);
	PthreadAttrGetstacksize(src, &stack_size);

	LOGF("\tcpu_mask       = 0x%" PRIx64 "\n"
	     "\tdetach_state   = %d\n"
	     "\tguard_size     = %" PRIu64 "\n"
	     "\tinherit_sched  = %d\n"
	     "\tsched_priority = %d\n"
	     "\tpolicy         = %d\n"
	     "\tsolosched      = %d\n"
	     "\tstack_addr     = 0x%016" PRIx64 "\n"
	     "\tstack_size    = %" PRIu64 "\n",
	     mask, state, guard_size, inherit_sched, param.sched_priority, policy, solosched,
	     reinterpret_cast<uint64_t>(stack_addr), static_cast<uint64_t>(stack_size));
}

static constexpr int32_t DST_NONE = 0;
static constexpr int32_t DST_MET  = 4;

static int32_t GetDstSeconds() {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	TIME_ZONE_INFORMATION tzi {};
	const DWORD           result = GetTimeZoneInformation(&tzi);
	return (result == TIME_ZONE_ID_DAYLIGHT ? -tzi.DaylightBias * 60 : 0);
#else
	const std::time_t now = std::time(nullptr);
	std::tm           local_tm {};
	localtime_r(&now, &local_tm);
	return (local_tm.tm_isdst > 0 ? 3600 : 0);
#endif
}

static bool GetPosixClockId(KernelClockid clock_id, clockid_t* out) {
	EXIT_IF(out == nullptr);

	switch (clock_id) {
		case KERNEL_CLOCK_REALTIME:
		case KERNEL_CLOCK_REALTIME_PRECISE:
		case KERNEL_CLOCK_REALTIME_FAST:
		case KERNEL_CLOCK_SECOND: *out = CLOCK_REALTIME; return true;
		case KERNEL_CLOCK_MONOTONIC:
		case KERNEL_CLOCK_UPTIME:
		case KERNEL_CLOCK_UPTIME_PRECISE:
		case KERNEL_CLOCK_UPTIME_FAST:
		case KERNEL_CLOCK_MONOTONIC_PRECISE:
		case KERNEL_CLOCK_MONOTONIC_FAST:
		case KERNEL_CLOCK_EXT_NETWORK:
		case KERNEL_CLOCK_EXT_DEBUG_NETWORK:
		case KERNEL_CLOCK_EXT_AD_NETWORK:
		case KERNEL_CLOCK_EXT_RAW_NETWORK: *out = CLOCK_MONOTONIC; return true;
		default: return false;
	}
}

static bool NativeClockGettime(KernelClockid clock_id, KernelTimespec* tp) {
	EXIT_IF(tp == nullptr);

	int error = OK;
	if (KernelClockGettimeSpecial(clock_id, tp, &error)) {
		return error == OK;
	}

	clockid_t native_clock_id {};
	if (!GetPosixClockId(clock_id, &native_clock_id)) {
		return false;
	}

	timespec native_time {};
	if (::clock_gettime(native_clock_id, &native_time) != 0) {
		return false;
	}

	tp->tv_sec  = native_time.tv_sec;
	tp->tv_nsec = native_time.tv_nsec;
	return true;
}

static int PthreadMutexInitNamed(PthreadMutex* mutex, const PthreadMutexattr* attr,
                                 const char* name, int static_type = 0);
static int PthreadRwlockInitNamed(PthreadRwlock* rwlock, const PthreadRwlockattr* attr,
                                  const char* name);
static int PthreadCondInitNamed(PthreadCond* cond, const PthreadCondattr* attr, const char* name);

static int NativeMutexLock(PthreadMutexPrivate* mutex, KernelUseconds* timeout_us) {
	EXIT_IF(mutex == nullptr);

	auto* self = g_pthread_self;
	EXIT_NOT_IMPLEMENTED(self == nullptr);

	std::unique_lock lock(mutex->m);

	if (mutex->owner == self) {
		if (mutex->type == 2) {
			if (mutex->count == UINT32_MAX) {
				return EAGAIN;
			}
			mutex->count++;
			return OK;
		}
		if (timeout_us != nullptr) {
			if (*timeout_us > 0) {
				mutex->cv.wait_for(lock, std::chrono::microseconds(*timeout_us));
			}
			return ETIMEDOUT;
		}
		return EDEADLK;
	}

	if (timeout_us == nullptr) {
		while (mutex->owner != nullptr) {
			mutex->cv.wait_for(lock, std::chrono::microseconds(SIGNAL_APC_POLL_MICROS));
			if (mutex->owner != nullptr) {
				lock.unlock();
				KernelDispatchPendingSignalForCurrentThread();
				lock.lock();
			}
		}
	} else if (*timeout_us == 0) {
		if (mutex->owner != nullptr) {
			return ETIMEDOUT;
		}
	} else {
		const auto deadline =
		    std::chrono::steady_clock::now() + std::chrono::microseconds(*timeout_us);
		while (mutex->owner != nullptr) {
			const auto now = std::chrono::steady_clock::now();
			if (now >= deadline) {
				return ETIMEDOUT;
			}

			const auto remaining = deadline - now;
			const auto poll      = (remaining < std::chrono::microseconds(SIGNAL_APC_POLL_MICROS)
			                            ? remaining
			                            : std::chrono::steady_clock::duration(
			                                  std::chrono::microseconds(SIGNAL_APC_POLL_MICROS)));
			mutex->cv.wait_for(lock, poll);
			if (mutex->owner != nullptr) {
				lock.unlock();
				KernelDispatchPendingSignalForCurrentThread();
				lock.lock();
			}
		}
	}

	mutex->owner = self;
	mutex->count = 1;
	return OK;
}

static int NativeMutexTrylock(PthreadMutexPrivate* mutex) {
	EXIT_IF(mutex == nullptr);

	auto* self = g_pthread_self;
	EXIT_NOT_IMPLEMENTED(self == nullptr);

	std::unique_lock lock(mutex->m);

	if (mutex->owner == self) {
		if (mutex->type == 2) {
			if (mutex->count == UINT32_MAX) {
				return EAGAIN;
			}
			mutex->count++;
			return OK;
		}
		return EBUSY;
	}

	if (mutex->owner != nullptr) {
		return EBUSY;
	}

	mutex->owner = self;
	mutex->count = 1;
	return OK;
}

static int NativeMutexUnlock(PthreadMutexPrivate* mutex, uint32_t* recurse = nullptr) {
	EXIT_IF(mutex == nullptr);

	auto* self = g_pthread_self;
	EXIT_NOT_IMPLEMENTED(self == nullptr);

	std::unique_lock lock(mutex->m);

	if (mutex->owner != self) {
		return EPERM;
	}

	if (recurse != nullptr) {
		*recurse     = mutex->count;
		mutex->count = 1;
	}

	if (mutex->type == 2 && mutex->count > 1) {
		mutex->count--;
		return OK;
	}

	mutex->owner = nullptr;
	mutex->count = 0;
	lock.unlock();
	mutex->cv.notify_one();

	return OK;
}

static int NativeMutexLockRecurse(PthreadMutexPrivate* mutex, uint32_t recurse) {
	EXIT_IF(mutex == nullptr);

	int result = NativeMutexLock(mutex, nullptr);
	if (result == OK) {
		std::lock_guard lock(mutex->m);
		mutex->count = std::max<uint32_t>(recurse, 1);
	}
	return result;
}

static bool NativeCondDeadlineFromAbs(KernelClockid clock_id, const KernelTimespec* abstime,
                                      std::chrono::steady_clock::time_point* out) {
	if (abstime == nullptr || out == nullptr || abstime->tv_sec < 0 || abstime->tv_nsec < 0 ||
	    abstime->tv_nsec >= 1000000000) {
		return false;
	}

	KernelTimespec now {};
	if (!NativeClockGettime(clock_id, &now)) {
		return false;
	}

	auto delta = std::chrono::seconds(abstime->tv_sec - now.tv_sec) +
	             std::chrono::nanoseconds(abstime->tv_nsec - now.tv_nsec);
	*out       = std::chrono::steady_clock::now() +
	             std::chrono::duration_cast<std::chrono::steady_clock::duration>(delta);
	return true;
}

void* PthreadStaticObjects::CreateObject(void* addr, PthreadStaticObject::Type type) {
	if (addr == nullptr) {
		return addr;
	}

	auto*      current       = static_cast<void**>(addr);
	auto       current_ref   = std::atomic_ref<void*>(*current);
	auto*      current_value = current_ref.load(std::memory_order_acquire);
	auto*      rt                  = Common::Singleton<Loader::RuntimeLinker>::Instance();
	const auto native_static_mutex = [rt, type](void* value) {
		if (type != PthreadStaticObject::Type::Mutex || value == nullptr ||
		    reinterpret_cast<uintptr_t>(value) <= 2) {
			return false;
		}
		const auto* program = rt->FindProgramByAddr(reinterpret_cast<uint64_t>(value));
		return program != nullptr && program->file_name.filename() == "libkernel.sprx" &&
		       reinterpret_cast<uint64_t>(value) == program->base_vaddr + 0xa1e80;
	};
	const bool adaptive_static_mutex =
	    (type == PthreadStaticObject::Type::Mutex &&
	     current_value == reinterpret_cast<void*>(static_cast<uintptr_t>(1)));

	if (current_value != nullptr && !adaptive_static_mutex && !native_static_mutex(current_value)) {
		return addr;
	}

	Common::LockGuard lock(m_mutex);

	current_value = current_ref.load(std::memory_order_acquire);
	const bool adaptive_static_mutex_after_lock =
	    (type == PthreadStaticObject::Type::Mutex &&
	     current_value == reinterpret_cast<void*>(static_cast<uintptr_t>(1)));

	if (current_value != nullptr && !adaptive_static_mutex_after_lock &&
	    !native_static_mutex(current_value)) {
		return addr;
	}

	if (native_static_mutex(current_value)) {
		LOGF("KERNEL_PTHREAD native static mutex sentinel at 0x%016" PRIx64 "\n",
		     reinterpret_cast<uint64_t>(addr));
	}
	auto  vaddr   = reinterpret_cast<uint64_t>(addr);
	auto* program = rt->FindProgramByAddr(vaddr);

	std::string name = fmt::format("Static{:016x}", vaddr);

	int result = OK;
	switch (type) {
		case PthreadStaticObject::Type::Mutex:
			result = PthreadMutexInitNamed(static_cast<PthreadMutex*>(addr), nullptr, name.c_str(),
			                               adaptive_static_mutex_after_lock ? 4 : 0);
			break;
		case PthreadStaticObject::Type::Cond:
			result = PthreadCondInitNamed(static_cast<PthreadCond*>(addr), nullptr, name.c_str());
			break;
		case PthreadStaticObject::Type::Rwlock:
			result =
			    PthreadRwlockInitNamed(static_cast<PthreadRwlock*>(addr), nullptr, name.c_str());
			break;
		default: EXIT("unknown type: %d\n", static_cast<int>(type));
	}

	EXIT_NOT_IMPLEMENTED(result != OK);

	// Heap-backed lazy pthread objects are valid. Initialize them without requiring
	// an owning ELF segment; only segment-backed objects need module-unload cleanup bookkeeping.
	if (program == nullptr) {
		return addr;
	}

	auto* obj    = new PthreadStaticObject;
	obj->program = program;
	obj->type    = type;
	obj->vaddr   = vaddr;

	const auto it = std::find(m_objects.begin(), m_objects.end(), nullptr);
	if (it != m_objects.end()) {
		*it = obj;
	} else {
		m_objects.push_back(obj);
	}

	return addr;
}

void PthreadStaticObjects::DeleteObjects(Loader::Program* program) {
	Common::LockGuard lock(m_mutex);

	for (auto& obj: m_objects) {
		if (obj != nullptr && obj->program == program) {
			int result = OK;
			switch (obj->type) {
				case PthreadStaticObject::Type::Mutex:
					result = PthreadMutexDestroy(reinterpret_cast<PthreadMutex*>(obj->vaddr));
					break;
				case PthreadStaticObject::Type::Cond:
					result = PthreadCondDestroy(reinterpret_cast<PthreadCond*>(obj->vaddr));
					break;
				case PthreadStaticObject::Type::Rwlock:
					result = PthreadRwlockDestroy(reinterpret_cast<PthreadRwlock*>(obj->vaddr));
					break;
				default: EXIT("unknown type: %d\n", static_cast<int>(obj->type));
			}

			EXIT_NOT_IMPLEMENTED(result != OK);

			delete obj;
			obj = nullptr;
		}
	}
}

Pthread PthreadPool::Create() {
	Common::LockGuard lock(m_mutex);

	for (auto* p: m_threads) {
		if (p->free) {
			if (p->guest_pthread_obj != 0) {
				std::lock_guard lock(g_guest_pthread_mutex);
				g_guest_pthread_objects.erase(p->guest_pthread_obj);
				p->guest_pthread_obj = 0;
				p->guest_tcb         = 0;
			}
			p->free = false;
			return p;
		}
	}

	auto* ret = new PthreadPrivate {};

	ret->free        = false;
	ret->detached    = false;
	ret->almost_done = false;
	ret->attr        = nullptr;

	m_threads.push_back(ret);

	return ret;
}

void PthreadPool::FreeDetachedThreads() {
	Common::LockGuard lock(m_mutex);

	for (auto* p: m_threads) {
		if (p->detached && p->almost_done && !p->free) {
			PthreadJoin(p, nullptr);
		}
	}
}

static void DestructPthreadSpecific() {
	if (g_pthread_specific == nullptr) {
		return;
	}

	std::unique_lock lock(g_pthread_keys_mutex);
	for (int iter = 0; iter < DESTRUCTOR_ITERATIONS; iter++) {
		bool called = false;
		for (int index = 0; index < KEYS_MAX; index++) {
			const auto value = std::exchange(g_pthread_specific[index], {});
			if (value.data == nullptr) {
				continue;
			}

			const auto& entry      = g_pthread_keys[index];
			const auto  generation = entry.generation.load(std::memory_order_relaxed);
			if ((generation & 1u) == 0 || generation != value.generation ||
			    entry.destructor == nullptr) {
				continue;
			}
			const auto destructor = entry.destructor;
			lock.unlock();
			destructor(value.data);
			lock.lock();
			called = true;
		}
		if (!called) {
			break;
		}
	}
	g_pthread_specific.reset();
}

int KYTY_SYSV_ABI PthreadMutexattrInit(PthreadMutexattr* attr) {
	// PRINT_NAME();

	EXIT_NOT_IMPLEMENTED(attr == nullptr);

	*attr = new PthreadMutexattrPrivate {};

	int result = pthread_mutexattr_init(&(*attr)->p);

	result = (result == 0 ? PthreadMutexattrSettype(attr, 1) : result);
	result = (result == 0 ? PthreadMutexattrSetprotocol(attr, 0) : result);

	switch (result) {
		case 0: return OK;
		case ENOMEM: return KERNEL_ERROR_ENOMEM;
		default: return KERNEL_ERROR_EINVAL;
	}
}

int KYTY_SYSV_ABI PthreadMutexattrDestroy(PthreadMutexattr* attr) {
	// PRINT_NAME();

	EXIT_NOT_IMPLEMENTED(attr == nullptr || *attr == nullptr);

	int result = pthread_mutexattr_destroy(&(*attr)->p);

	delete *attr;
	*attr = nullptr;

	switch (result) {
		case 0: return OK;
		case ENOMEM: return KERNEL_ERROR_ENOMEM;
		default: return KERNEL_ERROR_EINVAL;
	}
}

int KYTY_SYSV_ABI PthreadMutexattrSettype(PthreadMutexattr* attr, int type) {
	// PRINT_NAME();

	EXIT_NOT_IMPLEMENTED(attr == nullptr || *attr == nullptr);

	int ptype = PTHREAD_MUTEX_DEFAULT;
	switch (type) {
		case KERNEL_PTHREAD_MUTEX_ERRORCHECK: ptype = PTHREAD_MUTEX_ERRORCHECK; break;
		case KERNEL_PTHREAD_MUTEX_RECURSIVE: ptype = PTHREAD_MUTEX_RECURSIVE; break;
		case KERNEL_PTHREAD_MUTEX_NORMAL:
		case KERNEL_PTHREAD_MUTEX_ADAPTIVE: ptype = PTHREAD_MUTEX_NORMAL; break;
		default: return KERNEL_ERROR_EINVAL;
	}

	int result = pthread_mutexattr_settype(&(*attr)->p, ptype);

	if (result == 0) {
		(*attr)->type = type;
		return OK;
	}

	return KERNEL_ERROR_EINVAL;
}

int KYTY_SYSV_ABI PthreadMutexattrSetprotocol([[maybe_unused]] PthreadMutexattr* attr,
                                              int                                protocol) {
	// PRINT_NAME();

	EXIT_NOT_IMPLEMENTED(attr == nullptr || *attr == nullptr);

	[[maybe_unused]] int pprotocol = PTHREAD_PRIO_NONE;
	switch (protocol) {
		case 0: pprotocol = PTHREAD_PRIO_NONE; break;
		case 1: pprotocol = PTHREAD_PRIO_INHERIT; break;
		case 2: pprotocol = PTHREAD_PRIO_PROTECT; break;
		default: EXIT("invalid protocol: %d\n", protocol);
	}

	// protocol doesn't work in winpthreads
	int result         = 0; // pthread_mutexattr_setprotocol(&(*attr)->p, pprotocol);
	(*attr)->pprotocol = pprotocol;

	if (result == 0) {
		return OK;
	}

	return KERNEL_ERROR_EINVAL;
}

static int PthreadMutexInitNamed(PthreadMutex* mutex, const PthreadMutexattr* attr,
                                 const char* name, int static_type) {
	if (name != nullptr && name[0] != '\0') {
		PRINT_NAME();
	}

	// EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());
	if (mutex == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	PthreadMutexattrPrivate static_attr {};
	PthreadMutexattr        static_attr_ptr = nullptr;

	if (static_type != 0) {
		static_attr_ptr = &static_attr;
		pthread_mutexattr_init(&static_attr.p);
		PthreadMutexattrSettype(&static_attr_ptr, static_type);
		PthreadMutexattrSetprotocol(&static_attr_ptr, 0);
		attr = &static_attr_ptr;
	} else if (attr == nullptr) {

		attr = g_pthread_context->GetDefaultMutexattr();
	}

	auto* new_mutex = new PthreadMutexPrivate {};

	new_mutex->name      = (name != nullptr ? name : "");
	new_mutex->type      = (*attr)->type;
	new_mutex->pprotocol = (*attr)->pprotocol;

	int result = 0;

	if (static_attr_ptr != nullptr) {
		pthread_mutexattr_destroy(&static_attr.p);
	}

	if (name != nullptr && name[0] != '\0') {
		LOGF("\tmutex init: %s, %d\n", new_mutex->name.c_str(), result);
	}

	std::atomic_ref<PthreadMutexPrivate*>(*mutex).store(new_mutex, std::memory_order_release);

	switch (result) {
		case 0: return OK;
		case EAGAIN: return KERNEL_ERROR_EAGAIN;
		case EINVAL: return KERNEL_ERROR_EINVAL;
		case ENOMEM: return KERNEL_ERROR_ENOMEM;
		default: return KERNEL_ERROR_EINVAL;
	}
}

int KYTY_SYSV_ABI PthreadMutexInit(PthreadMutex* mutex, const PthreadMutexattr* attr,
                                   const char* name) {
	return PthreadMutexInitNamed(mutex, attr, name);
}

int KYTY_SYSV_ABI PthreadMutexDestroy(PthreadMutex* mutex) {
	// Hot path for Python/Ren'Py startup; keep this quiet unless it fails.

	if (mutex == nullptr || *mutex == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	int result = ((*mutex)->owner == nullptr ? 0 : EBUSY);

	if (result != 0) {
		LOGF("\tmutex destroy: %s, %d\n", (*mutex)->name.c_str(), result);
		switch (result) {
			case EBUSY: return KERNEL_ERROR_EBUSY;
			case EINVAL:
			default: return KERNEL_ERROR_EINVAL;
		}
	}

	delete *mutex;
	*mutex = nullptr;

	switch (result) {
		case 0: return OK;
		case EBUSY: return KERNEL_ERROR_EBUSY;
		case EINVAL:
		default: return KERNEL_ERROR_EINVAL;
	}
}

int KYTY_SYSV_ABI PthreadMutexLock(PthreadMutex* mutex) {
	// PRINT_NAME();

	auto* pthread_static_objects = g_pthread_context->GetPthreadStaticObjects();

	mutex = static_cast<PthreadMutex*>(
	    pthread_static_objects->CreateObject(mutex, PthreadStaticObject::Type::Mutex));

	if (mutex == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*mutex == nullptr);

	int result = NativeMutexLock(*mutex, nullptr);
	if (result != 0) {
		const auto* object   = *mutex;
		const auto  owner_id = object->owner != nullptr ? object->owner->unique_id : -1;
		const auto  self_id  = g_pthread_self != nullptr ? g_pthread_self->unique_id : -1;
		if (auto* file = std::fopen("_Build/vsh/mutex_fail.log", "a"); file != nullptr) {
			std::fprintf(file,
			             "guest=%016" PRIx64 " object=%016" PRIx64
			             " name=%s type=%d count=%u result=%d owner=%d self=%d caller=%016" PRIx64
			             "\n",
			             reinterpret_cast<uint64_t>(mutex), reinterpret_cast<uint64_t>(object),
			             object->name.c_str(), object->type, object->count, result, owner_id,
			             self_id, reinterpret_cast<uint64_t>(__builtin_return_address(0)));
			std::fclose(file);
		}
		std::fprintf(stderr,
		             "mutex lock failed: guest=%016" PRIx64 " object=%016" PRIx64
		             " name=%s type=%d count=%u result=%d owner=%d self=%d caller=%016" PRIx64 "\n",
		             reinterpret_cast<uint64_t>(mutex), reinterpret_cast<uint64_t>(object),
		             object->name.c_str(), object->type, object->count, result, owner_id, self_id,
		             reinterpret_cast<uint64_t>(__builtin_return_address(0)));
		std::fflush(stderr);
	}

	// LOGF("\tmutex lock: %s, %d\n", (*mutex)->name.c_str(), result);

	switch (result) {
		case 0: return OK;
		case EAGAIN: return KERNEL_ERROR_EAGAIN;
		case EINVAL: return KERNEL_ERROR_EINVAL;
		case EDEADLK: return KERNEL_ERROR_EDEADLK;
		default: return KERNEL_ERROR_EINVAL;
	}
}

int KYTY_SYSV_ABI PthreadMutexTrylock(PthreadMutex* mutex) {
	// PRINT_NAME();

	auto* pthread_static_objects = g_pthread_context->GetPthreadStaticObjects();

	mutex = static_cast<PthreadMutex*>(
	    pthread_static_objects->CreateObject(mutex, PthreadStaticObject::Type::Mutex));

	if (mutex == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*mutex == nullptr);

	int result = NativeMutexTrylock(*mutex);

	// LOGF("\tmutex trylock: %s, %d\n", (*mutex)->name.c_str(), result);

	switch (result) {
		case 0: return OK;
		case EAGAIN: return KERNEL_ERROR_EAGAIN;
		case EBUSY: return KERNEL_ERROR_EBUSY;
		case EINVAL:
		default: return KERNEL_ERROR_EINVAL;
	}
}

int KYTY_SYSV_ABI PthreadMutexTimedlock(PthreadMutex* mutex, KernelUseconds usec) {
	// PRINT_NAME();

	auto* pthread_static_objects = g_pthread_context->GetPthreadStaticObjects();

	mutex = static_cast<PthreadMutex*>(
	    pthread_static_objects->CreateObject(mutex, PthreadStaticObject::Type::Mutex));

	if (mutex == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*mutex == nullptr);

	int result = NativeMutexLock(*mutex, &usec);

	switch (result) {
		case 0: return OK;
		case ETIMEDOUT: return KERNEL_ERROR_ETIMEDOUT;
		case EAGAIN: return KERNEL_ERROR_EAGAIN;
		case EDEADLK: return KERNEL_ERROR_EDEADLK;
		case EINVAL:
		default: return KERNEL_ERROR_EINVAL;
	}
}

int KYTY_SYSV_ABI PthreadMutexUnlock(PthreadMutex* mutex) {
	// PRINT_NAME();

	auto* pthread_static_objects = g_pthread_context->GetPthreadStaticObjects();

	mutex = static_cast<PthreadMutex*>(
	    pthread_static_objects->CreateObject(mutex, PthreadStaticObject::Type::Mutex));

	if (mutex == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*mutex == nullptr);

	int result = NativeMutexUnlock(*mutex);

	if (result != 0) {
		LOGF("\tmutex unlock: %s, %d, thread_id = %d\n", (*mutex)->name.c_str(), result,
		     Common::Thread::GetThreadIdUnique());
	}

	switch (result) {
		case 0: return OK;

		case EINVAL: return KERNEL_ERROR_EINVAL;
		case EPERM: return KERNEL_ERROR_EPERM;
		default: return KERNEL_ERROR_EINVAL;
	}
}

static int TracePthreadAttrResult(const char* operation, bool native_called, int native_result,
                                  int result, uint64_t caller) {
	if (std::getenv("KYTY_DIAGNOSTIC_VIDEO_ARBITRATION_INIT") == nullptr) return result;
	auto*      linker  = Common::Singleton<Loader::RuntimeLinker>::ExistingInstance();
	auto*      program = linker == nullptr ? nullptr : linker->FindProgramByAddr(caller);
	const auto module  = program == nullptr ? std::string("unavailable")
	                                        : Common::PathToString(program->file_name.filename());
	const bool target  = module == "libSceVideoArbitration.sprx";
	if (target || result != OK) {
		LOGF("PTHREAD_ATTR_%s guest_pid=%d operation=%s caller_module=%s"
		     " caller_rva=0x%016" PRIx64 " native_called=%d native_result=%d"
		     " mapped_result=%08x\n",
		     target ? "RESULT" : "FAILURE", Process::GetPid(), operation,
		     Log::EscapeField(module).c_str(),
		     program == nullptr ? 0 : caller - program->base_vaddr, native_called ? 1 : 0,
		     native_result, static_cast<unsigned>(result));
	}
	return result;
}

int KYTY_SYSV_ABI PthreadAttrInit(PthreadAttr* attr) {
	// PRINT_NAME();

	*attr = new PthreadAttrPrivate {};

	const int native_result = pthread_attr_init(&(*attr)->p);
	int       result        = native_result;

	(*attr)->affinity       = 0x7f;
	(*attr)->guard_size     = 0x1000;
	(*attr)->stack_addr     = nullptr;
	(*attr)->stack_size     = PTHREAD_STACK_DEFAULT;
	(*attr)->stack_user     = false;
	(*attr)->stack_map_addr = 0;
	(*attr)->stack_map_size = 0;

	KernelSchedParam param;
	param.sched_priority = 700;

	int inherit_result     = 0x7fffffff;
	int schedparam_result  = 0x7fffffff;
	int schedpolicy_result = 0x7fffffff;
	int detach_result      = 0x7fffffff;
	int stacksize_result   = 0x7fffffff;
	if (result == 0) result = inherit_result = PthreadAttrSetinheritsched(attr, 4);
	if (result == 0) result = schedparam_result = PthreadAttrSetschedparam(attr, &param);
	if (result == 0) result = schedpolicy_result = PthreadAttrSetschedpolicy(attr, 1);
	if (result == 0) result = detach_result = PthreadAttrSetdetachstate(attr, 0);
	if (result == 0)
		result = stacksize_result = PthreadAttrSetstacksize(attr, PTHREAD_STACK_DEFAULT);

	int mapped_result = KERNEL_ERROR_EINVAL;
	if (result == 0)
		mapped_result = OK;
	else if (result == ENOMEM)
		mapped_result = KERNEL_ERROR_ENOMEM;
	if (result != 0 && std::getenv("KYTY_DIAGNOSTIC_VIDEO_ARBITRATION_INIT") != nullptr) {
		const auto caller  = reinterpret_cast<uint64_t>(__builtin_return_address(0));
		auto*      linker  = Common::Singleton<Loader::RuntimeLinker>::ExistingInstance();
		auto*      program = linker == nullptr ? nullptr : linker->FindProgramByAddr(caller);
		const auto module  = program == nullptr
		                         ? std::string("unavailable")
		                         : Common::PathToString(program->file_name.filename());
		LOGF("PTHREAD_ATTR_INIT_FAILURE guest_pid=%d caller_module=%s caller_rva=0x%016" PRIx64
		     " native_called=1 native_result=%d inherit_called=%d inherit_result=%d"
		     " schedparam_called=%d schedparam_result=%d schedpolicy_called=%d"
		     " schedpolicy_result=%d detach_called=%d detach_result=%d"
		     " stacksize_called=%d stacksize_result=%d sequence_result=%d mapped_result=%08x\n",
		     Process::GetPid(), Log::EscapeField(module).c_str(),
		     program == nullptr ? 0 : caller - program->base_vaddr, native_result,
		     inherit_result != 0x7fffffff ? 1 : 0, inherit_result,
		     schedparam_result != 0x7fffffff ? 1 : 0, schedparam_result,
		     schedpolicy_result != 0x7fffffff ? 1 : 0, schedpolicy_result,
		     detach_result != 0x7fffffff ? 1 : 0, detach_result,
		     stacksize_result != 0x7fffffff ? 1 : 0, stacksize_result, result,
		     static_cast<unsigned>(mapped_result));
	}

	if (false && PRINT_NAME_ENABLED) {
		PthreadAttrDbgPrint(attr);
	}

	return TracePthreadAttrResult("init", true, native_result, mapped_result,
	                              reinterpret_cast<uint64_t>(__builtin_return_address(0)));
}

int KYTY_SYSV_ABI PthreadAttrDestroy(PthreadAttr* attr) {
	// PRINT_NAME();

	auto* attr_value = GetPthreadAttrValue(attr, "PthreadAttrDestroy");
	if (attr_value == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	int result = pthread_attr_destroy(&attr_value->p);

	delete *attr;
	*attr = nullptr;

	if (result == 0) {
		return OK;
	}
	return KERNEL_ERROR_EINVAL;
}

int KYTY_SYSV_ABI PthreadAttrGet(Pthread thread, PthreadAttr* attr) {
	// PRINT_NAME();

	thread = PthreadHostObjectFor(thread);
	if (thread == nullptr || attr == nullptr || *attr == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	return PthreadAttrCopy(attr, &thread->attr);
}

int KYTY_SYSV_ABI PthreadAttrGetaffinity(const PthreadAttr* attr, KernelCpumask* mask) {
	// PRINT_NAME();

	if (mask == nullptr || attr == nullptr || *attr == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	*mask = (*attr)->affinity;

	return OK;
}

int KYTY_SYSV_ABI PthreadAttrGetdetachstate(const PthreadAttr* attr, int* state) {
	// PRINT_NAME();

	if (state == nullptr || attr == nullptr || *attr == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	// int result = pthread_attr_getdetachstate(&(*attr)->p, state);
	int result = 0;

	*state = ((*attr)->detached ? PTHREAD_CREATE_DETACHED : PTHREAD_CREATE_JOINABLE);

	switch (*state) {
		case PTHREAD_CREATE_JOINABLE: *state = 0; break;
		case PTHREAD_CREATE_DETACHED: *state = 1; break;
		default: EXIT("unknown state: %d\n", *state);
	}

	if (result == 0) {
		return OK;
	}
	return KERNEL_ERROR_EINVAL;
}

int KYTY_SYSV_ABI PthreadAttrGetguardsize(const PthreadAttr* attr, size_t* guard_size) {
	// PRINT_NAME();

	if (guard_size == nullptr || attr == nullptr || *attr == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	*guard_size = (*attr)->guard_size;

	return OK;
}

int KYTY_SYSV_ABI PthreadAttrGetinheritsched(const PthreadAttr* attr, int* inherit_sched) {
	// PRINT_NAME();

	if (inherit_sched == nullptr || attr == nullptr || *attr == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	*inherit_sched = (*attr)->inherit_sched;

	switch (*inherit_sched) {
		case 0:
		case 4: break;
		default: EXIT("unknown inherit_sched: %d\n", *inherit_sched);
	}

	return OK;
}

int KYTY_SYSV_ABI PthreadAttrGetschedparam(const PthreadAttr* attr, KernelSchedParam* param) {
	// PRINT_NAME();

	if (param == nullptr || attr == nullptr || *attr == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	int result = pthread_attr_getschedparam(&(*attr)->p, param);

	// Host priority mapping is lossy; return the exact guest value.
	param->sched_priority = (*attr)->guest_priority;

	if (result == 0) {
		return OK;
	}
	return KERNEL_ERROR_EINVAL;
}

int KYTY_SYSV_ABI PthreadAttrGetschedpolicy(const PthreadAttr* attr, int* policy) {
	// PRINT_NAME();

	if (policy == nullptr || attr == nullptr || *attr == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	int result = pthread_attr_getschedpolicy(&(*attr)->p, policy);

	switch (*policy) {
		case SCHED_OTHER: *policy = (*attr)->policy; break;
		case SCHED_FIFO: *policy = 1; break;
		case SCHED_RR: *policy = 3; break;
		default: EXIT("unknown policy: %d\n", *policy);
	}

	if (result == 0) {
		return OK;
	}
	return KERNEL_ERROR_EINVAL;
}

int KYTY_SYSV_ABI PthreadAttrGetsolosched(const PthreadAttr* attr, int* solosched) {
	// PRINT_NAME();

	if (solosched == nullptr || attr == nullptr || *attr == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	*solosched = (*attr)->solosched;

	return OK;
}

int KYTY_SYSV_ABI PthreadAttrGetstack(const PthreadAttr* __restrict attr,
                                      void** __restrict stack_addr, size_t* __restrict stack_size) {
	// PRINT_NAME();

	if (stack_size == nullptr || stack_addr == nullptr || attr == nullptr || *attr == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	*stack_addr = (*attr)->stack_addr;
	*stack_size = (*attr)->stack_size;

	return OK;
}

int KYTY_SYSV_ABI PthreadAttrGetstackaddr(const PthreadAttr* attr, void** stack_addr) {
	// PRINT_NAME();

	if (stack_addr == nullptr || attr == nullptr || *attr == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	*stack_addr = (*attr)->stack_addr;

	return OK;
}

int KYTY_SYSV_ABI PthreadAttrGetstacksize(const PthreadAttr* attr, size_t* stack_size) {
	// PRINT_NAME();

	if (stack_size == nullptr || attr == nullptr || *attr == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	*stack_size = (*attr)->stack_size;

	return OK;
}

int KYTY_SYSV_ABI PthreadAttrSetaffinity(PthreadAttr* attr, KernelCpumask mask) {
	// PRINT_NAME();
	const auto caller = reinterpret_cast<uint64_t>(__builtin_return_address(0));

	auto* attr_value = GetPthreadAttrValue(attr, "PthreadAttrSetaffinity");
	if (attr_value == nullptr) {
		return TracePthreadAttrResult("setaffinity", false, 0, KERNEL_ERROR_EINVAL, caller);
	}

	attr_value->affinity = mask;

	return TracePthreadAttrResult("setaffinity", false, 0, OK, caller);
}

int KYTY_SYSV_ABI PthreadAttrSetdetachstate(PthreadAttr* attr, int state) {
	// PRINT_NAME();

	auto* attr_value = GetPthreadAttrValue(attr, "PthreadAttrSetdetachstate");
	if (attr_value == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	int pstate = PTHREAD_CREATE_JOINABLE;
	switch (state) {
		case 0: pstate = PTHREAD_CREATE_JOINABLE; break;
		case 1: pstate = PTHREAD_CREATE_DETACHED; break;
		default: EXIT("unknown state: %d\n", state);
	}

	// int result = pthread_attr_setdetachstate(&(*attr)->p, pstate);
	int result = 0;

	attr_value->detached = (pstate == PTHREAD_CREATE_DETACHED);

	if (result == 0) {
		return OK;
	}
	return KERNEL_ERROR_EINVAL;
}

int KYTY_SYSV_ABI PthreadAttrSetguardsize(PthreadAttr* attr, size_t guard_size) {
	// PRINT_NAME();

	auto* attr_value = GetPthreadAttrValue(attr, "PthreadAttrSetguardsize");
	if (attr_value == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	attr_value->guard_size = guard_size;

	return OK;
}

int KYTY_SYSV_ABI PthreadAttrSetinheritsched(PthreadAttr* attr, int inherit_sched) {
	// PRINT_NAME();
	const auto caller = reinterpret_cast<uint64_t>(__builtin_return_address(0));

	auto* attr_value = GetPthreadAttrValue(attr, "PthreadAttrSetinheritsched");
	if (attr_value == nullptr) {
		return TracePthreadAttrResult("setinheritsched", false, 0, KERNEL_ERROR_EINVAL, caller);
	}

	int pinherit_sched = PTHREAD_INHERIT_SCHED;
	switch (inherit_sched) {
		case 0: pinherit_sched = PTHREAD_EXPLICIT_SCHED; break;
		case 4: pinherit_sched = PTHREAD_INHERIT_SCHED; break;
		default: EXIT("unknown inherit_sched: %d\n", inherit_sched);
	}

	// Keep this in Kyty state. winpthreads' inheritsched support is not needed for guest-visible
	// behavior, and some guest attr flows can leave the native attr in a shape that crashes inside
	// winpthreads.
	attr_value->inherit_sched = inherit_sched;
	(void)pinherit_sched;

	return TracePthreadAttrResult("setinheritsched", false, 0, OK, caller);
}

int KYTY_SYSV_ABI PthreadAttrSetschedparam(PthreadAttr* attr, const KernelSchedParam* param) {
	// PRINT_NAME();
	const auto caller = reinterpret_cast<uint64_t>(__builtin_return_address(0));

	auto* attr_value = GetPthreadAttrValue(attr, "PthreadAttrSetschedparam");
	if (param == nullptr || attr_value == nullptr) {
		return TracePthreadAttrResult("setschedparam", false, 0, KERNEL_ERROR_EINVAL, caller);
	}

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	KernelSchedParam pparam {};
	if (param->sched_priority <= 478) {
		pparam.sched_priority = +2;
	} else if (param->sched_priority >= 733) {
		pparam.sched_priority = -2;
	} else {
		pparam.sched_priority = 0;
	}

	const int native_result = pthread_attr_setschedparam(&attr_value->p, &pparam);
	if (native_result != 0) {
		return TracePthreadAttrResult("setschedparam", true, native_result, KERNEL_ERROR_EINVAL,
		                              caller);
	}
#else
	const int native_result = 0;
#endif

	attr_value->guest_priority = param->sched_priority;
	return TracePthreadAttrResult("setschedparam",
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	                              true,
#else
	                              false,
#endif
	                              native_result, OK, caller);
}

int KYTY_SYSV_ABI PthreadAttrSetschedpolicy(PthreadAttr* attr, int policy) {
	// PRINT_NAME();
	const auto caller = reinterpret_cast<uint64_t>(__builtin_return_address(0));

	auto* attr_value = GetPthreadAttrValue(attr, "PthreadAttrSetschedpolicy");
	if (attr_value == nullptr) {
		return TracePthreadAttrResult("setschedpolicy", false, 0, KERNEL_ERROR_EINVAL, caller);
	}

	// winpthreads supports only SCHED_OTHER policy
	int ppolicy = SCHED_OTHER;

	attr_value->policy = policy;

	int result = pthread_attr_setschedpolicy(&attr_value->p, ppolicy);

	if (result == 0) {
		return TracePthreadAttrResult("setschedpolicy", true, result, OK, caller);
	}
	return TracePthreadAttrResult("setschedpolicy", true, result, KERNEL_ERROR_EINVAL, caller);
}

int KYTY_SYSV_ABI PthreadAttrSetsolosched(PthreadAttr* attr, int solosched) {
	// PRINT_NAME();

	auto* attr_value = GetPthreadAttrValue(attr, "PthreadAttrSetsolosched");
	if (attr_value == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	attr_value->solosched = solosched;

	return OK;
}

int KYTY_SYSV_ABI PthreadAttrSetstack(PthreadAttr* attr, void* addr, size_t size) {
	// PRINT_NAME();

	auto* attr_value = GetPthreadAttrValue(attr, "PthreadAttrSetstack");
	if (addr == nullptr || size < GUEST_PTHREAD_STACK_MIN || attr_value == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	attr_value->stack_addr     = addr;
	attr_value->stack_size     = size;
	attr_value->stack_user     = true;
	attr_value->stack_map_addr = 0;
	attr_value->stack_map_size = 0;

	return OK;
}

int KYTY_SYSV_ABI PthreadAttrSetstackaddr(PthreadAttr* attr, void* addr) {
	// PRINT_NAME();

	auto* attr_value = GetPthreadAttrValue(attr, "PthreadAttrSetstackaddr");
	if (addr == nullptr || attr_value == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	attr_value->stack_addr     = addr;
	attr_value->stack_user     = true;
	attr_value->stack_map_addr = 0;
	attr_value->stack_map_size = 0;

	return OK;
}

int KYTY_SYSV_ABI PthreadAttrSetstacksize(PthreadAttr* attr, size_t stack_size) {
	// PRINT_NAME();

	auto* attr_value = GetPthreadAttrValue(attr, "PthreadAttrSetstacksize");
	if (stack_size < GUEST_PTHREAD_STACK_MIN || attr_value == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	attr_value->stack_size = stack_size;

	return OK;
}

int KYTY_SYSV_ABI PthreadRwlockDestroy(PthreadRwlock* rwlock) {
	PRINT_NAME();

	if (rwlock == nullptr || *rwlock == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	{
		std::lock_guard lock((*rwlock)->m);
		if ((*rwlock)->writer != nullptr || (*rwlock)->reader_count != 0) {
			return KERNEL_ERROR_EBUSY;
		}
	}

	LOGF("\trwlock destroy: %s, 0\n", (*rwlock)->name.c_str());

	delete *rwlock;
	*rwlock = nullptr;

	return OK;
}

static int PthreadRwlockInitNamed(PthreadRwlock* rwlock, const PthreadRwlockattr* attr,
                                  const char* name) {
	PRINT_NAME();

	if (rwlock == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	if (attr == nullptr) {

		attr = g_pthread_context->GetDefaultRwlockattr();
	}

	auto* new_rwlock = new PthreadRwlockPrivate {};

	new_rwlock->name = (name != nullptr ? name : "");

	LOGF("\trwlock init: %s, 0\n", new_rwlock->name.c_str());

	std::atomic_ref<PthreadRwlockPrivate*>(*rwlock).store(new_rwlock, std::memory_order_release);

	return OK;
}

int KYTY_SYSV_ABI PthreadRwlockInit(PthreadRwlock* rwlock, const PthreadRwlockattr* attr,
                                    const char* name) {
	return PthreadRwlockInitNamed(rwlock, attr, name);
}

static PthreadRwlockPrivate::Reader* RwlockFindReader(PthreadRwlock rwlock, Pthread thread) {
	EXIT_IF(rwlock == nullptr);

	for (auto& reader: rwlock->readers) {
		if (reader.thread == thread) {
			return &reader;
		}
	}

	return nullptr;
}

static void RwlockAddReader(PthreadRwlock rwlock, Pthread thread) {
	if (auto* reader = RwlockFindReader(rwlock, thread); reader != nullptr) {
		reader->count++;
	} else {
		rwlock->readers.push_back({thread, 1});
	}
	rwlock->reader_count++;
}

static bool RwlockRemoveReader(PthreadRwlock rwlock, Pthread thread) {
	for (auto it = rwlock->readers.begin(); it != rwlock->readers.end(); ++it) {
		if (it->thread == thread) {
			it->count--;
			rwlock->reader_count--;
			if (it->count == 0) {
				rwlock->readers.erase(it);
			}
			return true;
		}
	}

	return false;
}

static int RwlockLockCooperative(PthreadRwlock rwlock, bool write, KernelUseconds* timeout_us) {
	EXIT_IF(rwlock == nullptr);

	auto* self = g_pthread_self;
	if (self == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	const auto has_timeout = (timeout_us != nullptr);
	const auto deadline =
	    (has_timeout ? std::chrono::steady_clock::now() + std::chrono::microseconds(*timeout_us)
	                 : std::chrono::steady_clock::time_point {});
	bool writer_wait_registered = false;

	for (;;) {
		{
			std::unique_lock lock(rwlock->m);

			auto unregister_writer_wait = [&rwlock, &writer_wait_registered] {
				if (writer_wait_registered) {
					rwlock->waiting_writers--;
					writer_wait_registered = false;
				}
			};

			if (write) {
				if (rwlock->writer == self || RwlockFindReader(rwlock, self) != nullptr) {
					unregister_writer_wait();
					return KERNEL_ERROR_EDEADLK;
				}
				if (rwlock->writer == nullptr && rwlock->reader_count == 0) {
					unregister_writer_wait();
					rwlock->writer       = self;
					rwlock->writer_count = 1;
					return OK;
				}
				if (!writer_wait_registered) {
					rwlock->waiting_writers++;
					writer_wait_registered = true;
				}
			} else {
				const bool already_reader = (RwlockFindReader(rwlock, self) != nullptr);
				if ((rwlock->writer == nullptr &&
				     (rwlock->waiting_writers == 0 || already_reader)) ||
				    rwlock->writer == self) {
					RwlockAddReader(rwlock, self);
					return OK;
				}
			}

			if (has_timeout) {
				const auto now = std::chrono::steady_clock::now();
				if (*timeout_us == 0 || now >= deadline) {
					unregister_writer_wait();
					return KERNEL_ERROR_ETIMEDOUT;
				}

				const auto remaining = deadline - now;
				const auto poll = (remaining < std::chrono::microseconds(SIGNAL_APC_POLL_MICROS)
				                       ? remaining
				                       : std::chrono::steady_clock::duration(
				                             std::chrono::microseconds(SIGNAL_APC_POLL_MICROS)));
				rwlock->cv.wait_for(lock, poll);
			} else {
				rwlock->cv.wait_for(lock, std::chrono::microseconds(SIGNAL_APC_POLL_MICROS));
			}
		}

		KernelDispatchPendingSignalForCurrentThread();
	}
}

int KYTY_SYSV_ABI PthreadRwlockRdlock(PthreadRwlock* rwlock) {
	// Hot path for some PS5 titles; per-call name logging can dominate runtime.

	auto* pthread_static_objects = g_pthread_context->GetPthreadStaticObjects();

	rwlock = static_cast<PthreadRwlock*>(
	    pthread_static_objects->CreateObject(rwlock, PthreadStaticObject::Type::Rwlock));

	if (rwlock == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*rwlock == nullptr);

	return RwlockLockCooperative(*rwlock, false, nullptr);
}

int KYTY_SYSV_ABI PthreadRwlockTimedrdlock(PthreadRwlock* rwlock, KernelUseconds usec) {
	PRINT_NAME();

	auto* pthread_static_objects = g_pthread_context->GetPthreadStaticObjects();

	rwlock = static_cast<PthreadRwlock*>(
	    pthread_static_objects->CreateObject(rwlock, PthreadStaticObject::Type::Rwlock));

	if (rwlock == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*rwlock == nullptr);

	return RwlockLockCooperative(*rwlock, false, &usec);
}

int KYTY_SYSV_ABI PthreadRwlockTimedwrlock(PthreadRwlock* rwlock, KernelUseconds usec) {
	PRINT_NAME();

	auto* pthread_static_objects = g_pthread_context->GetPthreadStaticObjects();

	rwlock = static_cast<PthreadRwlock*>(
	    pthread_static_objects->CreateObject(rwlock, PthreadStaticObject::Type::Rwlock));

	if (rwlock == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*rwlock == nullptr);

	return RwlockLockCooperative(*rwlock, true, &usec);
}

int KYTY_SYSV_ABI PthreadRwlockTryrdlock(PthreadRwlock* rwlock) {
	PRINT_NAME();

	auto* pthread_static_objects = g_pthread_context->GetPthreadStaticObjects();

	rwlock = static_cast<PthreadRwlock*>(
	    pthread_static_objects->CreateObject(rwlock, PthreadStaticObject::Type::Rwlock));

	if (rwlock == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*rwlock == nullptr);

	auto* self = g_pthread_self;
	if (self == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	{
		std::lock_guard lock((*rwlock)->m);
		const bool      already_reader = (RwlockFindReader(*rwlock, self) != nullptr);
		if (((*rwlock)->writer == nullptr && ((*rwlock)->waiting_writers == 0 || already_reader)) ||
		    (*rwlock)->writer == self) {
			RwlockAddReader(*rwlock, self);
			return OK;
		}
	}

	return KERNEL_ERROR_EBUSY;
}

int KYTY_SYSV_ABI PthreadRwlockTrywrlock(PthreadRwlock* rwlock) {
	PRINT_NAME();

	if (rwlock == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*rwlock == nullptr);

	auto* self = g_pthread_self;
	if (self == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	{
		std::lock_guard lock((*rwlock)->m);
		if ((*rwlock)->writer == self || RwlockFindReader(*rwlock, self) != nullptr) {
			return KERNEL_ERROR_EDEADLK;
		}
		if ((*rwlock)->writer == nullptr && (*rwlock)->reader_count == 0) {
			(*rwlock)->writer       = self;
			(*rwlock)->writer_count = 1;
			return OK;
		}
	}

	return KERNEL_ERROR_EBUSY;
}

int KYTY_SYSV_ABI PthreadRwlockUnlock(PthreadRwlock* rwlock) {
	// PRINT_NAME();

	auto* pthread_static_objects = g_pthread_context->GetPthreadStaticObjects();

	rwlock = static_cast<PthreadRwlock*>(
	    pthread_static_objects->CreateObject(rwlock, PthreadStaticObject::Type::Rwlock));

	if (rwlock == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*rwlock == nullptr);

	auto* self = g_pthread_self;
	if (self == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	{
		std::lock_guard lock((*rwlock)->m);
		if (RwlockRemoveReader(*rwlock, self)) {
			(*rwlock)->cv.notify_all();
			return OK;
		}
		if ((*rwlock)->writer == self) {
			EXIT_IF((*rwlock)->writer_count == 0);
			(*rwlock)->writer_count--;
			if ((*rwlock)->writer_count == 0) {
				(*rwlock)->writer = nullptr;
				(*rwlock)->cv.notify_all();
			}
			return OK;
		}

		return KERNEL_ERROR_EPERM;
	}
}

int KYTY_SYSV_ABI PthreadRwlockWrlock(PthreadRwlock* rwlock) {
	// PRINT_NAME();

	auto* pthread_static_objects = g_pthread_context->GetPthreadStaticObjects();

	rwlock = static_cast<PthreadRwlock*>(
	    pthread_static_objects->CreateObject(rwlock, PthreadStaticObject::Type::Rwlock));

	if (rwlock == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*rwlock == nullptr);

	return RwlockLockCooperative(*rwlock, true, nullptr);
}

int KYTY_SYSV_ABI PthreadRwlockattrDestroy(PthreadRwlockattr* attr) {
	PRINT_NAME();

	if (attr == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*attr == nullptr);

	int result = pthread_rwlockattr_destroy(&(*attr)->p);

	delete *attr;
	*attr = nullptr;

	if (result == 0) {
		return OK;
	}
	return KERNEL_ERROR_EINVAL;
}

int KYTY_SYSV_ABI PthreadRwlockattrInit(PthreadRwlockattr* attr) {
	PRINT_NAME();

	*attr = new PthreadRwlockattrPrivate {};

	int result = pthread_rwlockattr_init(&(*attr)->p);

	result = (result == 0 ? PthreadRwlockattrSettype(attr, 1) : result);

	switch (result) {
		case 0: return OK;
		case ENOMEM: return KERNEL_ERROR_ENOMEM;
		default: return KERNEL_ERROR_EINVAL;
	}
}

int KYTY_SYSV_ABI PthreadRwlockattrGettype(PthreadRwlockattr* attr, int* type) {
	PRINT_NAME();

	if (type == nullptr || attr == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	*type = (*attr)->type;

	return OK;
}

int KYTY_SYSV_ABI PthreadRwlockattrSettype(PthreadRwlockattr* attr, int type) {
	PRINT_NAME();

	if (attr == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	(*attr)->type = type;

	return OK;
}

int KYTY_SYSV_ABI PthreadCondattrDestroy(PthreadCondattr* attr) {
	PRINT_NAME();

	if (attr == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*attr == nullptr);

	int result = pthread_condattr_destroy(&(*attr)->p);

	delete *attr;
	*attr = nullptr;

	if (result == 0) {
		return OK;
	}
	return KERNEL_ERROR_EINVAL;
}

int KYTY_SYSV_ABI PthreadCondattrInit(PthreadCondattr* attr) {
	PRINT_NAME();

	*attr = new PthreadCondattrPrivate {};

	int result        = pthread_condattr_init(&(*attr)->p);
	(*attr)->clock_id = KERNEL_CLOCK_REALTIME;

	switch (result) {
		case 0: return OK;
		case ENOMEM: return KERNEL_ERROR_ENOMEM;
		default: return KERNEL_ERROR_EINVAL;
	}
}

int KYTY_SYSV_ABI PthreadCondattrSetclock(PthreadCondattr* attr, KernelClockid clock_id) {
	PRINT_NAME();

	if (attr == nullptr || *attr == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	clockid_t pclock_id = {};
	if (!GetPosixClockId(clock_id, &pclock_id)) {
		LOGF("\tunknown clock_id: %d\n", clock_id);
		return KERNEL_ERROR_EINVAL;
	}

#if defined(__APPLE__)
	(void)pclock_id;
	int result = 0;
#else
	int result = pthread_condattr_setclock(&(*attr)->p, pclock_id);
#endif
	(*attr)->clock_id = clock_id;

	LOGF("\tcondattr setclock: clock_id = %d, native = %d, result = %d\n", clock_id,
	     static_cast<int>(pclock_id), result);

	if (result == EINVAL && pclock_id == CLOCK_MONOTONIC) {
		LOGF("\tcondattr setclock: host rejected CLOCK_MONOTONIC, keeping emulated attribute\n");
		return OK;
	}

	switch (result) {
		case 0: return OK;
		case EINVAL:
		default: return KERNEL_ERROR_EINVAL;
	}
}

int KYTY_SYSV_ABI PthreadCondBroadcast(PthreadCond* cond) {
	// PRINT_NAME();

	auto* pthread_static_objects = g_pthread_context->GetPthreadStaticObjects();

	cond = static_cast<PthreadCond*>(
	    pthread_static_objects->CreateObject(cond, PthreadStaticObject::Type::Cond));

	if (cond == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*cond == nullptr);

	std::lock_guard lock((*cond)->m);
	for (auto* thread: (*cond)->waiters) {
		thread->cond_sequence++;
		thread->cond_cv.notify_one();
	}
	(*cond)->waiters.clear();
	return OK;
}

int KYTY_SYSV_ABI PthreadCondDestroy(PthreadCond* cond) {
	PRINT_NAME();

	if (cond == nullptr || *cond == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	int result = 0;

	LOGF("\tcond destroy: %s, %d\n", (*cond)->name.c_str(), result);

	delete *cond;
	*cond = nullptr;

	switch (result) {
		case 0: return OK;
		case EINVAL: return KERNEL_ERROR_EINVAL;
		case EBUSY: return KERNEL_ERROR_EBUSY;
		default: return KERNEL_ERROR_EINVAL;
	}
}

static int PthreadCondInitNamed(PthreadCond* cond, const PthreadCondattr* attr, const char* name) {
	if (name != nullptr && name[0] != '\0') {
		PRINT_NAME();
	}

	if (cond == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	if (attr == nullptr) {

		attr = g_pthread_context->GetDefaultCondattr();
	}

	auto* new_cond = new PthreadCondPrivate {};

	new_cond->name     = (name != nullptr ? name : "");
	new_cond->clock_id = (*attr)->clock_id;

	int result = 0;

	if (name != nullptr && name[0] != '\0') {
		LOGF("\tcond init: %s, cond=0x%016" PRIx64 ", caller=0x%016" PRIx64 ", %d\n",
		     new_cond->name.c_str(), reinterpret_cast<uint64_t>(cond),
		     reinterpret_cast<uint64_t>(__builtin_return_address(0)), result);
	}

	std::atomic_ref<PthreadCondPrivate*>(*cond).store(new_cond, std::memory_order_release);

	switch (result) {
		case 0: return OK;
		case EAGAIN: return KERNEL_ERROR_EAGAIN;
		case EINVAL: return KERNEL_ERROR_EINVAL;
		case ENOMEM: return KERNEL_ERROR_ENOMEM;
		default: return KERNEL_ERROR_EINVAL;
	}
}

int KYTY_SYSV_ABI PthreadCondInit(PthreadCond* cond, const PthreadCondattr* attr,
                                  const char* name) {
	return PthreadCondInitNamed(cond, attr, name);
}

int KYTY_SYSV_ABI PthreadCondSignal(PthreadCond* cond) {
	// PRINT_NAME();

	auto* pthread_static_objects = g_pthread_context->GetPthreadStaticObjects();

	cond = static_cast<PthreadCond*>(
	    pthread_static_objects->CreateObject(cond, PthreadStaticObject::Type::Cond));

	if (cond == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*cond == nullptr);

	std::lock_guard lock((*cond)->m);
	CondWakeWaiter(*cond, nullptr);
	return OK;
}

int KYTY_SYSV_ABI PthreadCondSignalto(PthreadCond* cond, Pthread thread) {
	// PRINT_NAME();

	thread = PthreadHostObjectFor(thread);

	auto* pthread_static_objects = g_pthread_context->GetPthreadStaticObjects();

	cond = static_cast<PthreadCond*>(
	    pthread_static_objects->CreateObject(cond, PthreadStaticObject::Type::Cond));

	if (cond == nullptr || thread == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*cond == nullptr);

	std::lock_guard lock((*cond)->m);
	CondWakeWaiter(*cond, thread);
	return OK;
}

int KYTY_SYSV_ABI PthreadCondTimedwait(PthreadCond* cond, PthreadMutex* mutex,
                                       KernelUseconds usec) {
	// PRINT_NAME();

	auto* pthread_static_objects = g_pthread_context->GetPthreadStaticObjects();

	cond = static_cast<PthreadCond*>(
	    pthread_static_objects->CreateObject(cond, PthreadStaticObject::Type::Cond));
	mutex = static_cast<PthreadMutex*>(
	    pthread_static_objects->CreateObject(mutex, PthreadStaticObject::Type::Mutex));

	if (cond == nullptr || mutex == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*cond == nullptr);
	EXIT_NOT_IMPLEMENTED(*mutex == nullptr);

	auto* cond_value  = *cond;
	auto* mutex_value = *mutex;

	if (mutex_value->owner != g_pthread_self) {
		return KERNEL_ERROR_EPERM;
	}

	if (std::getenv("KYTY_DIAGNOSTIC_PSM_WAITS") != nullptr) {
		static std::atomic<uint32_t> trace_count {0};
		if (trace_count.fetch_add(1) < 96) {
			LOGF("PSM_WAIT_TIMED caller=0x%016" PRIx64 " thread=%s usec=%" PRIu64
			     " cond=0x%016" PRIx64 "\n",
			     reinterpret_cast<uint64_t>(__builtin_return_address(0)),
			     g_pthread_self != nullptr ? g_pthread_self->name.c_str() : "(unknown)",
			     static_cast<uint64_t>(usec), reinterpret_cast<uint64_t>(cond_value));
		}
	}

	std::unique_lock cond_lock(cond_value->m);
	auto*            thread          = g_pthread_self;
	const auto       thread_sequence = thread->cond_sequence;
	CondAddWaiter(cond_value, thread);

	uint32_t recurse = 0;
	int      result  = NativeMutexUnlock(mutex_value, &recurse);
	if (result != OK) {
		CondRemoveWaiter(cond_value, thread);
		return (result == EPERM ? KERNEL_ERROR_EPERM : KERNEL_ERROR_EINVAL);
	}

	const auto deadline = std::chrono::steady_clock::now() + std::chrono::microseconds(usec);
	auto ready = [thread, thread_sequence] { return thread->cond_sequence != thread_sequence; };

	if (usec == 0) {
		result = ETIMEDOUT;
	} else {
		while (!ready()) {
			const auto now = std::chrono::steady_clock::now();
			if (now >= deadline) {
				break;
			}

			const auto remaining = deadline - now;
			const auto poll      = (remaining < std::chrono::microseconds(SIGNAL_APC_POLL_MICROS)
			                            ? remaining
			                            : std::chrono::steady_clock::duration(
			                                  std::chrono::microseconds(SIGNAL_APC_POLL_MICROS)));
			thread->cond_cv.wait_for(cond_lock, poll);

			if (!ready()) {
				cond_lock.unlock();
				KernelDispatchPendingSignalForCurrentThread();
				cond_lock.lock();
			}
		}

		result = (ready() ? OK : ETIMEDOUT);
	}
	CondRemoveWaiter(cond_value, thread);
	cond_lock.unlock();

	int lock_result = NativeMutexLockRecurse(mutex_value, recurse);
	if (result == OK) {
		result = lock_result;
	}

	// LOGF("\tcond timedwait: %s, %d\n", (*cond)->name.c_str(), result);

	switch (result) {
		case 0: return OK;
		case ETIMEDOUT: return KERNEL_ERROR_ETIMEDOUT;
		case EPERM: return KERNEL_ERROR_EPERM;
		case EINVAL:
		default: return KERNEL_ERROR_EINVAL;
	}
}

int KYTY_SYSV_ABI PthreadCondTimedwaitAbs(PthreadCond* cond, PthreadMutex* mutex,
                                          const KernelTimespec* abstime) {
	// PRINT_NAME();

	auto* pthread_static_objects = g_pthread_context->GetPthreadStaticObjects();

	cond = static_cast<PthreadCond*>(
	    pthread_static_objects->CreateObject(cond, PthreadStaticObject::Type::Cond));
	mutex = static_cast<PthreadMutex*>(
	    pthread_static_objects->CreateObject(mutex, PthreadStaticObject::Type::Mutex));

	if (cond == nullptr || mutex == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*cond == nullptr);
	EXIT_NOT_IMPLEMENTED(*mutex == nullptr);

	auto* cond_value  = *cond;
	auto* mutex_value = *mutex;

	std::chrono::steady_clock::time_point deadline {};
	if (!NativeCondDeadlineFromAbs(cond_value->clock_id, abstime, &deadline)) {
		return KERNEL_ERROR_EINVAL;
	}

	if (mutex_value->owner != g_pthread_self) {
		return KERNEL_ERROR_EPERM;
	}

	std::unique_lock cond_lock(cond_value->m);
	auto*            thread          = g_pthread_self;
	const auto       thread_sequence = thread->cond_sequence;
	CondAddWaiter(cond_value, thread);

	uint32_t recurse = 0;
	int      result  = NativeMutexUnlock(mutex_value, &recurse);
	if (result != OK) {
		CondRemoveWaiter(cond_value, thread);
		return (result == EPERM ? KERNEL_ERROR_EPERM : KERNEL_ERROR_EINVAL);
	}

	auto ready = [thread, thread_sequence] { return thread->cond_sequence != thread_sequence; };

	while (!ready()) {
		const auto now = std::chrono::steady_clock::now();
		if (now >= deadline) {
			break;
		}

		const auto remaining = deadline - now;
		const auto poll      = (remaining < std::chrono::microseconds(SIGNAL_APC_POLL_MICROS)
		                            ? remaining
		                            : std::chrono::steady_clock::duration(
		                                  std::chrono::microseconds(SIGNAL_APC_POLL_MICROS)));
		thread->cond_cv.wait_for(cond_lock, poll);

		if (!ready()) {
			cond_lock.unlock();
			KernelDispatchPendingSignalForCurrentThread();
			cond_lock.lock();
		}
	}

	result = (ready() ? OK : ETIMEDOUT);
	CondRemoveWaiter(cond_value, thread);
	cond_lock.unlock();

	int lock_result = NativeMutexLockRecurse(mutex_value, recurse);
	if (result == OK) {
		result = lock_result;
	}

	switch (result) {
		case 0: return OK;
		case ETIMEDOUT: return KERNEL_ERROR_ETIMEDOUT;
		case EPERM: return KERNEL_ERROR_EPERM;
		case EINVAL:
		default: return KERNEL_ERROR_EINVAL;
	}
}

int KYTY_SYSV_ABI PthreadCondWait(PthreadCond* cond, PthreadMutex* mutex) {
	PRINT_NAME();

	auto* pthread_static_objects = g_pthread_context->GetPthreadStaticObjects();

	cond = static_cast<PthreadCond*>(
	    pthread_static_objects->CreateObject(cond, PthreadStaticObject::Type::Cond));
	mutex = static_cast<PthreadMutex*>(
	    pthread_static_objects->CreateObject(mutex, PthreadStaticObject::Type::Mutex));

	if (cond == nullptr || mutex == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_NOT_IMPLEMENTED(*cond == nullptr);
	EXIT_NOT_IMPLEMENTED(*mutex == nullptr);

	auto* cond_value  = *cond;
	auto* mutex_value = *mutex;

	if (mutex_value->owner != g_pthread_self) {
		return KERNEL_ERROR_EPERM;
	}

	if (std::getenv("KYTY_DIAGNOSTIC_PSM_WAITS") != nullptr) {
		static std::atomic<uint32_t> trace_count {0};
		if (trace_count.fetch_add(1) < 96) {
			LOGF("PSM_WAIT_COND caller=0x%016" PRIx64 " thread=%s cond=0x%016" PRIx64 "\n",
			     reinterpret_cast<uint64_t>(__builtin_return_address(0)),
			     g_pthread_self != nullptr ? g_pthread_self->name.c_str() : "(unknown)",
			     reinterpret_cast<uint64_t>(cond_value));
		}
	}

	std::unique_lock cond_lock(cond_value->m);
	auto*            thread          = g_pthread_self;
	const auto       thread_sequence = thread->cond_sequence;
	CondAddWaiter(cond_value, thread);

	uint32_t recurse = 0;
	int      result  = NativeMutexUnlock(mutex_value, &recurse);
	if (result != OK) {
		CondRemoveWaiter(cond_value, thread);
		return (result == EPERM ? KERNEL_ERROR_EPERM : KERNEL_ERROR_EINVAL);
	}

	auto ready = [thread, thread_sequence] { return thread->cond_sequence != thread_sequence; };

	while (!ready()) {
		thread->cond_cv.wait_for(cond_lock, std::chrono::microseconds(SIGNAL_APC_POLL_MICROS));
		if (!ready()) {
			cond_lock.unlock();
			KernelDispatchPendingSignalForCurrentThread();
			cond_lock.lock();
		}
	}
	CondRemoveWaiter(cond_value, thread);
	cond_lock.unlock();

	result = NativeMutexLockRecurse(mutex_value, recurse);

	switch (result) {
		case 0: return OK;
		case EPERM: return KERNEL_ERROR_EPERM;
		case EINVAL:
		default: return KERNEL_ERROR_EINVAL;
	}
}

// libkernel reads fixed pthread fields via fs:[0x10]: +0x00 tid, +0x08/+0x0c umtx, +0x2c/+0x30
// counters, +0x58 list link, +0x90/+0x98 sched, +0xd0..+0xdc cancel, +0x184 join. Exec-child
// threads get a separate guest object; pthread_t is its address.
static uint64_t EnsureGuestPthreadObject(Pthread thread) {
	if (!Process::IsExecChild() || thread == nullptr) {
		return 0;
	}
	std::lock_guard lock(g_guest_pthread_mutex);
	if (thread->guest_pthread_obj != 0) {
		return thread->guest_pthread_obj;
	}
	constexpr uint64_t TCB_SIZE = 0x40;
	constexpr uint64_t OBJ_SIZE = 0x400;
	const auto         tcb      = Memory::AllocateRuntimeMemory(
	    0, TCB_SIZE + OBJ_SIZE, Common::VirtualMemory::Mode::ReadWrite, "guest_pthread_tcb");
	EXIT_IF(tcb == 0);
	auto*      tcb_words              = reinterpret_cast<uint64_t*>(tcb);
	const auto obj                    = tcb + TCB_SIZE;
	tcb_words[0]                      = tcb;
	tcb_words[2]                      = obj;
	*reinterpret_cast<uint32_t*>(obj) = static_cast<uint32_t>(thread->guest.thread_id);
	thread->guest_tcb                 = tcb;
	thread->guest_pthread_obj         = obj;
	g_guest_pthread_objects[obj]      = thread;
	LOGF("EXEC_GUEST_PTHREAD_OBJECT guest_pid=%d guest_tid=%d"
	     " tcb=0x%016" PRIx64 " pthread_obj=0x%016" PRIx64 " fs10_libkernel_fields\n",
	     Process::GetPid(), thread->guest.thread_id, tcb, obj);
	return obj;
}

Pthread PthreadHostObjectFor(Pthread thread) {
	if (thread == nullptr) {
		return nullptr;
	}
	std::lock_guard lock(g_guest_pthread_mutex);
	const auto      it = g_guest_pthread_objects.find(reinterpret_cast<uint64_t>(thread));
	return it != g_guest_pthread_objects.end() ? it->second : thread;
}

uint64_t PthreadPrepareGuestTcbForCurrentThread() {
	if (!Process::IsExecChild() || g_pthread_self == nullptr) {
		return 0;
	}
	EnsureGuestPthreadObject(g_pthread_self);
	Loader::SetExecNativeThreadFsBase(g_pthread_self->guest_tcb);
	return g_pthread_self->guest_tcb;
}

Pthread KYTY_SYSV_ABI PthreadSelf() {
	// PRINT_NAME();

	EXIT_NOT_IMPLEMENTED(g_pthread_self == nullptr);

	if (const auto obj = EnsureGuestPthreadObject(g_pthread_self); obj != 0) {
		return reinterpret_cast<Pthread>(obj);
	}

	return g_pthread_self;
}

Pthread PthreadSelfOrNull() {
	return g_pthread_self;
}

Pthread PthreadSwapSelfForSignal(Pthread thread) {
	auto* previous = g_pthread_self;
	g_pthread_self = thread;

	if (Process::IsExecChild() && thread != nullptr && EnsureGuestPthreadObject(thread) != 0) {
		Loader::SetExecNativeThreadFsBase(thread->guest_tcb);
	}

	return previous;
}

uint64_t PthreadGetHostThreadId(Pthread thread) {
	return thread != nullptr ? thread->host_thread_id : 0;
}

static_assert(std::atomic<uint64_t>::is_always_lock_free);
static thread_local std::atomic<uint64_t> g_unattached_signal_mask[2] {};

PthreadSignalMask PthreadGetSignalMask(Pthread thread) {
	auto* words = thread != nullptr ? thread->blocked_signal_mask : g_unattached_signal_mask;
	return {{words[0].load(std::memory_order_acquire), words[1].load(std::memory_order_acquire)}};
}

void PthreadSetSignalMask(Pthread thread, PthreadSignalMask mask) {
	mask.words[0] &= ~((1ull << 8) | (1ull << 16) | (1ull << 31));
	auto* words = thread != nullptr ? thread->blocked_signal_mask : g_unattached_signal_mask;
	words[0].store(mask.words[0], std::memory_order_release);
	words[1].store(mask.words[1], std::memory_order_release);
}

bool PthreadIsSignalBlocked(Pthread thread, int signum) {
	if (signum < 1 || signum > 128) {
		return false;
	}
	auto*      words = thread != nullptr ? thread->blocked_signal_mask : g_unattached_signal_mask;
	const auto bit   = static_cast<unsigned>(signum - 1);
	return (words[bit / 64].load(std::memory_order_acquire) & (1ull << (bit % 64))) != 0;
}

#if KYTY_PLATFORM != KYTY_PLATFORM_WINDOWS
// Raise a host signal on another guest thread.
bool PthreadKillHost(Pthread thread, int host_signal) {
	if (thread == nullptr || thread->free) {
		return false;
	}

	return ::pthread_kill(thread->p, host_signal) == 0;
}
#endif

void PthreadQueuePendingSignal(Pthread thread, int signum) {
	if (thread == nullptr || signum < 0 || signum >= 64) {
		return;
	}

	thread->pending_signal_mask.fetch_or(1ull << static_cast<uint32_t>(signum),
	                                     std::memory_order_release);
}

bool PthreadHasPendingSignal(Pthread thread, int signum) {
	if (thread == nullptr || signum < 0 || signum >= 64) {
		return false;
	}

	const auto mask = 1ull << static_cast<uint32_t>(signum);
	return (thread->pending_signal_mask.load(std::memory_order_acquire) & mask) != 0;
}

bool PthreadTakePendingSignal(Pthread thread, int signum) {
	if (thread == nullptr || signum < 0 || signum >= 64) {
		return false;
	}

	const auto mask = 1ull << static_cast<uint32_t>(signum);
	return (thread->pending_signal_mask.fetch_and(~mask, std::memory_order_acq_rel) & mask) != 0;
}

bool PthreadGetGuestStack(Pthread thread, uint64_t* stack_addr, uint64_t* stack_size) {
	thread = PthreadHostObjectFor(thread);
	if (thread == nullptr || thread->attr == nullptr || stack_addr == nullptr ||
	    stack_size == nullptr) {
		return false;
	}

	auto* addr = thread->attr->stack_addr;
	auto  size = thread->attr->stack_size;
	if (addr == nullptr || size == 0) {
		return false;
	}

	*stack_addr = reinterpret_cast<uint64_t>(addr);
	*stack_size = static_cast<uint64_t>(size);
	return true;
}

int PthreadGetPriorityForKernel(Pthread thread) {
	if (thread == nullptr) {
		return 700;
	}

	sched_param param {};
	int         pol = 0;

	if (pthread_getschedparam(thread->p, &pol, &param) != 0) {
		return 700;
	}

	if (param.sched_priority <= -2) {
		return 767;
	}
	if (param.sched_priority >= +2) {
		return 256;
	}
	return 700;
}

int PthreadGetCurrentPriorityForKernel() {
	return PthreadGetPriorityForKernel(g_pthread_self);
}

static void CleanupThread(void* arg) {
	auto* thread = static_cast<Pthread>(arg);

	if (!thread->rfork_exec_retired) {
		LibcInternalExt::RunThreadAtexitDestructors();

		auto thread_dtors = g_pthread_context->GetThreadDtors();

		if (thread_dtors != nullptr) {
			thread_dtors();
		}

		DestructPthreadSpecific();
	} else {
		g_pthread_specific.reset();
	}

	auto* rt = Common::Singleton<Loader::RuntimeLinker>::Instance();
	if (thread->rfork_exec_retired) {
		rt->DiscardTlssForExec(thread->unique_id);
	} else {
		rt->DeleteTlss(thread->unique_id);
	}

	if (thread->guest_process_pid > 0 && !thread->rfork_exec_retired) {
		if (thread->rfork_exit_known) {
			Process::NotifyRforkChildExited(thread->guest_process_pid, thread->rfork_exit_status);
		} else {
			LOGF("SYSCORE_GUEST_RFORK_CHILD_EXIT_STATUS_UNKNOWN guest_pid=%d"
			     " exit_not_notified\n",
			     thread->guest_process_pid);
		}
	}
	thread->almost_done = true;
}

static void* RunThread(void* arg) {

#if KYTY_PLATFORM == KYTY_PLATFORM_LINUX
	if (!Common::HostException::InitializeThreadSignalStack()) {
		EXIT("Failed to initialize the thread signal stack\n");
	}
#endif

	auto* thread = static_cast<Pthread>(arg);
	void* ret    = nullptr;

	thread->unique_id = Common::Thread::GetThreadIdUnique();

	g_pthread_self = thread;
	std::unique_ptr<Process::ScopedGuestProcessPid>         rfork_pid_scope;
	std::unique_ptr<FileSystem::ScopedGuestDescriptorTable> rfork_fd_scope;
	if (thread->guest_process_pid > 0) {
		Process::RegisterRforkChild(thread->guest_process_pid, thread->guest_parent_pid);
		rfork_pid_scope =
		    std::make_unique<Process::ScopedGuestProcessPid>(thread->guest_process_pid);
		rfork_fd_scope = std::make_unique<FileSystem::ScopedGuestDescriptorTable>();
		LOGF("SYSCORE_NATIVE_RFORK_CHILD_THREAD_START guest_pid=%d host_thread_id=%" PRIu64
		     " guest_entry=%016" PRIx64 " guest_stack_top=%016" PRIx64
		     " isolated_guest_file_table=1\n",
		     thread->guest_process_pid, static_cast<uint64_t>(Common::Thread::GetThreadIdUnique()),
		     reinterpret_cast<uint64_t>(thread->entry), thread->rfork_stack_top);
		// sc_spawn trampoline args: a[1] path, a[2] argv, a[3] prework fd (sub_468BF0), a[5] signed
		// auth fd, a[6] fd handoff (-1 = syscall 0x261, else fd for 0x23b), a[8] stdio flag, a[9]
		// title-id ptr
		if (thread->arg != nullptr) {
			const auto* a = reinterpret_cast<const uint64_t*>(thread->arg);
			LOGF("SYSCORE_RFORK_ARG_DUMP guest_pid=%d arg_ptr=%p"
			     " a0=%016" PRIx64 " a1=%016" PRIx64 " a2=%016" PRIx64 " a3=%016" PRIx64
			     " a4=%016" PRIx64 " a5=%016" PRIx64 " a6=%016" PRIx64 " a7=%016" PRIx64
			     " a8=%016" PRIx64 " a9=%016" PRIx64 "\n",
			     thread->guest_process_pid, thread->arg, a[0], a[1], a[2], a[3], a[4], a[5], a[6],
			     a[7], a[8], a[9]);
			char       buf[256] {};
			const auto path_ptr = a[1];
			if (path_ptr != 0 && path_ptr < 0xffff'ffff'0000'0000ull) {
				const auto* p = reinterpret_cast<const char*>(path_ptr);
				for (size_t i = 0; i < sizeof(buf) - 1; ++i) {
					char c = p[i];
					if (c == 0) break;
					buf[i] = (c >= 0x20 && c < 0x7f) ? c : '?';
				}
				LOGF("SYSCORE_RFORK_ARG_PATH guest_pid=%d path=\"%s\"\n", thread->guest_process_pid,
				     buf);
			}
			const auto alias_ptr = a[0];
			if (alias_ptr != 0 && alias_ptr < 0xffff'ffff'0000'0000ull && buf[0] != 0) {
				const auto* ap = reinterpret_cast<const char*>(alias_ptr);
				char        alias_buf[256] {};
				for (size_t i = 0; i < sizeof(alias_buf) - 1; ++i) {
					char c = ap[i];
					if (c == 0) break;
					alias_buf[i] = (c >= 0x20 && c < 0x7f) ? c : '?';
				}
				// only app children have a /app0 alias in a0, daemons exec their package path
				// directly
				if (std::strncmp(alias_buf, "/app0", 5) == 0) {
					Process::SetRforkChildAppExec(thread->guest_process_pid, alias_buf, buf);
					LOGF("SYSCORE_RFORK_APP_EXEC_PATHS guest_pid=%d alias=\"%s\" package=\"%s\"\n",
					     thread->guest_process_pid, alias_buf, buf);
				}
			}
		}
	}

	uint64_t os_thread_id = 0;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	os_thread_id = static_cast<uint64_t>(GetCurrentThreadId());
#else
	os_thread_id = GetHostThreadId();
#endif
	thread->host_thread_id = os_thread_id;

	LOGF("\tPthread run begin: %s, id = %d, os_thread_id = %" PRIu64 ", entry = 0x%016" PRIx64
	     ", arg = 0x%016" PRIx64 ", stack_addr = 0x%016" PRIx64 ", stack_size = %" PRIu64 "\n",
	     thread->name.c_str(), thread->unique_id, os_thread_id,
	     reinterpret_cast<uint64_t>(thread->entry), reinterpret_cast<uint64_t>(thread->arg),
	     reinterpret_cast<uint64_t>(thread->attr->stack_addr),
	     static_cast<uint64_t>(thread->attr->stack_size));

	// NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
	pthread_cleanup_push(CleanupThread, thread);

	auto* stack_top = reinterpret_cast<void*>(
	    (reinterpret_cast<uintptr_t>(thread->attr->stack_addr) + thread->attr->stack_size) &
	    ~static_cast<uintptr_t>(0x0f));
	if (thread->rfork_stack_top != 0) {
		stack_top = reinterpret_cast<void*>(thread->rfork_stack_top);
	}
	if (!Common::HostException::PrepareNativeGuestHandlerHostStackForCurrentThread()) {
		EXIT("Failed to prepare the native guest handler host stack\n");
	}
	Common::HostException::SetCurrentGuestStackBounds(
	    reinterpret_cast<uint64_t>(thread->attr->stack_addr),
	    static_cast<uint64_t>(thread->attr->stack_size));
	PthreadPrepareGuestTcbForCurrentThread();
	ret = RunOnGuestStack(thread->arg, thread->entry, stack_top);
	Common::HostException::ClearCurrentGuestStackBounds();
	if (std::getenv("KYTY_DIAGNOSTIC_PSM_THREAD_LIFECYCLE") != nullptr) {
		static std::atomic<uint32_t> trace_count {0};
		if (trace_count.fetch_add(1) < 1024) {
			const auto result = reinterpret_cast<uint64_t>(ret);
			LOGF("PSM_THREAD_RETURN guest_pid=%d guest_tid=%d name=%s"
			     " result_class=%s result_low32=0x%08x\n",
			     Process::GetPid(), thread->guest.thread_id, Log::EscapeField(thread->name).c_str(),
			     result == 0            ? "zero"
			     : result <= UINT32_MAX ? "scalar"
			                            : "pointer",
			     result <= UINT32_MAX ? static_cast<uint32_t>(result) : 0u);
		}
	}
	if (thread->guest_process_pid > 0 && !thread->rfork_exec_retired) {
		thread->rfork_exit_status =
		    (static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ret)) & 0xffu) << 8;
		thread->rfork_exit_known = true;
	}

	// NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
	pthread_cleanup_pop(1);

	if (thread->rfork_exec_retired) {
		const int pid = thread->guest_process_pid;
		rfork_fd_scope.reset();
		rfork_pid_scope.reset();
		Process::NotifyRforkChildContextRetired(pid);
	}

	return ret;
}

static int KYTY_SYSV_ABI PthreadCreateImpl(Pthread* thread, const PthreadAttr* attr,
                                           pthread_entry_func_t entry, void* arg, const char* name,
                                           int guest_process_pid, uint64_t rfork_stack_top,
                                           uint64_t creator) {
	PRINT_NAME();

	if (thread == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	auto* pthread_pool = g_pthread_context->GetPthreadPool();

	if (attr == nullptr) {
		attr = g_pthread_context->GetDefaultAttr();
	}
	if (GetPthreadAttrValue(attr, "PthreadCreate") == nullptr) {
		attr = g_pthread_context->GetDefaultAttr();
	}

	PRINT_NAME_ENABLE(false);

	auto* created_thread = pthread_pool->Create();
	*thread              = created_thread;

	if (created_thread->attr != nullptr) {
		PthreadAttrDestroy(&created_thread->attr);
	}

	PthreadAttrInit(&created_thread->attr);

	int result = PthreadAttrCopy(&created_thread->attr, attr);

	if (result == 0) {
		EXIT_IF(created_thread->free);

		if (created_thread->attr->stack_addr == nullptr) {
			created_thread->attr->stack_size += PTHREAD_STACK_EXTRA;
		}

		result = CreateGuestStack(created_thread->attr);
	}

	if (result == 0) {
		created_thread->name            = (name != nullptr ? name : "");
		created_thread->entry           = entry;
		created_thread->arg             = arg;
		created_thread->guest_process_pid  = guest_process_pid;
		created_thread->guest_parent_pid   = Process::GetPid();
		created_thread->rfork_stack_top    = rfork_stack_top;
		created_thread->rfork_exit_known   = false;
		created_thread->rfork_exit_status  = 0;
		created_thread->rfork_exec_retired = false;
		created_thread->guest.thread_id = ++g_pthread_thread_id;
		created_thread->almost_done     = false;
		created_thread->detached        = created_thread->attr->detached;
		created_thread->unique_id       = -1;
		created_thread->pending_signal_mask.store(0, std::memory_order_release);
		PthreadSetSignalMask(created_thread, PthreadGetSignalMask(PthreadSelfOrNull()));
		result =
		    pthread_create(&created_thread->p, &created_thread->attr->p, RunThread, created_thread);
		if (result == 0 && std::getenv("KYTY_DIAGNOSTIC_PSM_THREAD_LIFECYCLE") != nullptr) {
			static std::atomic<uint32_t> trace_count {0};
			if (trace_count.fetch_add(1) < 1024) {
				auto* linker          = Common::Singleton<Loader::RuntimeLinker>::Instance();
				auto* creator_program = linker->FindProgramByAddr(creator);
				auto* entry_program = linker->FindProgramByAddr(reinterpret_cast<uint64_t>(entry));
				const auto creator_module =
				    creator_program == nullptr
				        ? std::string("unknown")
				        : Common::PathToString(creator_program->file_name.filename());
				const auto entry_module =
				    entry_program == nullptr
				        ? std::string("unknown")
				        : Common::PathToString(entry_program->file_name.filename());
				LOGF("PSM_THREAD_CREATE guest_pid=%d guest_tid=%d name=%s result=0"
				     " creator_module=%s creator_rva=0x%016" PRIx64
				     " entry_module=%s entry_rva=0x%016" PRIx64 "\n",
				     Process::GetPid(), created_thread->guest.thread_id,
				     Log::EscapeField(created_thread->name).c_str(), creator_module.c_str(),
				     creator_program == nullptr ? 0 : creator - creator_program->base_vaddr,
				     entry_module.c_str(),
				     entry_program == nullptr
				         ? 0
						 : reinterpret_cast<uint64_t>(entry) - entry_program->base_vaddr);
			}
		}

		if (result != 0) {
			FreeGuestStack(created_thread->attr);
		}
	}

	if (result != 0) {
		created_thread->free = true;
	}

	LOGF("\tthread create: %s, id = %d, %d\n", created_thread->name.c_str(),
	     created_thread->unique_id, result);

	PthreadAttrDbgPrint(&created_thread->attr);

	PRINT_NAME_ENABLE(true);

	if (result < 0) {
		return result;
	}

	if (result == 0) {
		if (const auto obj = EnsureGuestPthreadObject(created_thread); obj != 0) {
			*thread = reinterpret_cast<Pthread>(obj);
		}
	}

	switch (result) {
		case 0: return OK;
		case ENOMEM: return KERNEL_ERROR_ENOMEM;
		case EAGAIN: return KERNEL_ERROR_EAGAIN;
		case EDEADLK: return KERNEL_ERROR_EDEADLK;
		case EPERM: return KERNEL_ERROR_EPERM;
		default: return KERNEL_ERROR_EINVAL;
	}
}

int KYTY_SYSV_ABI PthreadCreate(Pthread* thread, const PthreadAttr* attr,
                                pthread_entry_func_t entry, void* arg, const char* name) {
	return PthreadCreateImpl(thread, attr, entry, arg, name, 0, 0,
	                         reinterpret_cast<uint64_t>(__builtin_return_address(0)));
}

int PthreadCreateGuestRfork(Pthread* thread, const PthreadAttr* attr, pthread_entry_func_t entry,
                            void* arg, const char* name, int guest_process_pid,
                            uint64_t rfork_stack_top) {
	const int parent_pid = Process::GetPid();
	const int rc =
	    PthreadCreateImpl(thread, attr, entry, arg, name, guest_process_pid, rfork_stack_top, 0);
	if (rc == OK) {
		Process::RegisterRforkChild(guest_process_pid, parent_pid);
	}
	return rc;
}

int KYTY_SYSV_ABI PthreadDetach(Pthread thread) {
	PRINT_NAME();

	thread = PthreadHostObjectFor(thread);
	if (thread == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	LOGF("\tthread detach: %s, %d\n", thread->name.c_str(), 0);

	thread->detached = true;

	return OK;
}

int KYTY_SYSV_ABI PthreadJoin(Pthread thread, void** value) {
	PRINT_NAME();

	thread = PthreadHostObjectFor(thread);
	if (thread == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}
	if (std::getenv("KYTY_DIAGNOSTIC_PSM_WAITS") != nullptr) {
		LOGF("PSM_WAIT_JOIN caller=0x%016" PRIx64 " target=%s\n",
		     reinterpret_cast<uint64_t>(__builtin_return_address(0)), thread->name.c_str());
	}

	void* captured_value = nullptr;
	int   result         = pthread_join(thread->p, value != nullptr ? value : &captured_value);
	if (std::getenv("KYTY_DIAGNOSTIC_PSM_THREAD_LIFECYCLE") != nullptr) {
		static std::atomic<uint32_t> trace_count {0};
		if (trace_count.fetch_add(1) < 1024) {
			const auto joined =
			    result == 0 ? reinterpret_cast<uint64_t>(value != nullptr ? *value : captured_value)
				            : 0;
			LOGF("PSM_THREAD_JOIN guest_pid=%d guest_tid=%d name=%s result=%d"
			     " return_class=%s return_low32=0x%08x\n",
			     Process::GetPid(), thread->guest.thread_id, Log::EscapeField(thread->name).c_str(),
			     result,
			     result != 0            ? "unavailable"
			     : joined == 0          ? "zero"
			     : joined <= UINT32_MAX ? "scalar"
			                            : "pointer",
			     result == 0 && joined <= UINT32_MAX ? static_cast<uint32_t>(joined) : 0u);
		}
	}

	if (PRINT_NAME_ENABLED) {
		LOGF("\tthread join: %s, %d\n", thread->name.c_str(), result);
	}

	if (result == 0) {
		FreeGuestStack(thread->attr);

		thread->almost_done = false;
		thread->free        = true;
	}

	switch (result) {
		case 0: return OK;
		case ESRCH: return KERNEL_ERROR_ESRCH;
		case EDEADLK: return KERNEL_ERROR_EDEADLK;
		case EOPNOTSUPP: return KERNEL_ERROR_EOPNOTSUPP;
		default: return KERNEL_ERROR_EINVAL;
	}
}

int KYTY_SYSV_ABI PthreadCancel(Pthread thread) {
	PRINT_NAME();

	thread = PthreadHostObjectFor(thread);
	if (thread == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	int result = pthread_cancel(thread->p);

	LOGF("\tthread cancel: %s, %d\n", thread->name.c_str(), result);

	switch (result) {
		case 0: return OK;
		case ESRCH: return KERNEL_ERROR_ESRCH;
		default: return KERNEL_ERROR_EINVAL;
	}
}

int KYTY_SYSV_ABI PthreadSetaffinity(Pthread thread, KernelCpumask mask) {
	PRINT_NAME();

	thread = PthreadHostObjectFor(thread);
	if (thread == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}

	auto result = PthreadAttrSetaffinity(&thread->attr, mask);

	return result;
}

int KYTY_SYSV_ABI PthreadGetaffinity(Pthread thread, KernelCpumask* mask) {
	PRINT_NAME();

	thread = PthreadHostObjectFor(thread);
	if (thread == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}
	if (mask == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	return PthreadAttrGetaffinity(&thread->attr, mask);
}

int KYTY_SYSV_ABI PthreadSetcancelstate(int state, int* old_state) {
	PRINT_NAME();

	int pstate = PTHREAD_CANCEL_DISABLE;

	switch (state) {
		case 0: pstate = PTHREAD_CANCEL_ENABLE; break;
		case 1: pstate = PTHREAD_CANCEL_DISABLE; break;
		default: EXIT("unknown state: %d", state);
	}

	int result = pthread_setcancelstate(pstate, old_state);

	LOGF("\tthread setcancelstate: %d\n", result);

	if (old_state != nullptr) {
		switch (*old_state) {
			case PTHREAD_CANCEL_ENABLE: *old_state = 0; break;
			case PTHREAD_CANCEL_DISABLE: *old_state = 1; break;
			default: EXIT("unknown old_state: %d", *old_state);
		}
	}

	if (result == 0) {
		return OK;
	}
	return KERNEL_ERROR_EINVAL;
}

int KYTY_SYSV_ABI PthreadSetcanceltype(int type, int* old_type) {
	PRINT_NAME();

	int ptype = PTHREAD_CANCEL_DEFERRED;

	switch (type) {
		case 0: ptype = PTHREAD_CANCEL_DEFERRED; break;
		case 2: ptype = PTHREAD_CANCEL_ASYNCHRONOUS; break;
		default: EXIT("unknown type: %d", type);
	}

	int result = pthread_setcanceltype(ptype, old_type);

	LOGF("\tthread setcanceltype: %d\n", result);

	if (old_type != nullptr) {
		switch (*old_type) {
			case PTHREAD_CANCEL_DEFERRED: *old_type = 0; break;
			case PTHREAD_CANCEL_ASYNCHRONOUS: *old_type = 2; break;
			default: EXIT("unknown type: %d", *old_type);
		}
	}

	if (result == 0) {
		return OK;
	}
	return KERNEL_ERROR_EINVAL;
}

int KYTY_SYSV_ABI PthreadGetprio(Pthread thread, int* prio) {
	PRINT_NAME();

	thread = PthreadHostObjectFor(thread);
	if (thread == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}

	EXIT_NOT_IMPLEMENTED(prio == nullptr);

	sched_param native_param {};
	int         native_policy = 0;
	if (pthread_getschedparam(thread->p, &native_policy, &native_param) != 0) {
		return KERNEL_ERROR_EINVAL;
	}

	*prio = thread->attr->guest_priority;
	LOGF("\t PthreadGetprio: %d, %d\n", thread->unique_id, *prio);
	return OK;
}

int KYTY_SYSV_ABI PthreadSetprio(Pthread thread, int prio) {
	PRINT_NAME();

	thread = PthreadHostObjectFor(thread);
	if (thread == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}

	sched_param param {};
	int         pol = 0;

	int result = pthread_getschedparam(thread->p, &pol, &param);

	if (result != 0) {
		return KERNEL_ERROR_EINVAL;
	}

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (prio <= 478) {
		param.sched_priority = +2;
	} else if (prio >= 733) {
		param.sched_priority = -2;
	} else {
		param.sched_priority = 0;
	}

	if (pthread_setschedparam(thread->p, pol, &param) != 0) {
		return KERNEL_ERROR_EINVAL;
	}
#endif

	thread->attr->guest_priority = prio;
	LOGF("\t PthreadSetprio: %d, %d\n", thread->unique_id, prio);
	return OK;
}

int KYTY_SYSV_ABI PthreadSetprioAndAffinity(Pthread thread, int prio, KernelCpumask mask) {
	PRINT_NAME();

	thread = PthreadHostObjectFor(thread);
	if (mask == 0) {
		return KERNEL_ERROR_EINVAL;
	}

	int result = PthreadSetprio(thread, prio);
	if (result == OK) {
		result = PthreadSetaffinity(thread, mask);
	}

	return result;
}

void KYTY_SYSV_ABI PthreadTestcancel() {
	PRINT_NAME();

	pthread_testcancel();
}

void KYTY_SYSV_ABI PthreadExit(void* value) {
	PRINT_NAME();
	if (g_pthread_self != nullptr && g_pthread_self->guest_process_pid > 0 &&
	    !g_pthread_self->rfork_exec_retired) {
		g_pthread_self->rfork_exit_status =
		    (static_cast<uint32_t>(reinterpret_cast<uintptr_t>(value)) & 0xffu) << 8;
		g_pthread_self->rfork_exit_known = true;
	}

#if defined(__x86_64__) || defined(_M_X64)
	if (g_guest_entry_return_rsp != 0) {
		const auto return_rsp    = g_guest_entry_return_rsp;
		g_guest_entry_return_rsp = 0;

		if (g_pthread_self != nullptr && g_pthread_self->guest_host_rsp != 0) {
			const auto host_rbx = g_pthread_self->guest_host_rbx;
			const auto host_rsp = g_pthread_self->guest_host_rsp;
			const auto host_rbp = g_pthread_self->guest_host_rbp;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
			const auto host_gs8  = g_pthread_self->guest_host_gs8;
			const auto host_gs10 = g_pthread_self->guest_host_gs10;
#endif

			asm volatile("movq %2, %%rbx\n\t"
			             "movq %3, %%r12\n\t"
			             "movq %4, %%r13\n\t"
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
			             "movq %5, %%r14\n\t"
			             "movq %6, %%r15\n\t"
#endif
			             "movq %0, %%rax\n\t"
			             "movq %1, %%rsp\n\t"
			             "retq\n\t"
			             :
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
			             : "m"(value), "m"(return_rsp), "m"(host_rbx), "m"(host_rsp), "m"(host_rbp),
			               "m"(host_gs8), "m"(host_gs10)
#else
			             : "m"(value), "m"(return_rsp), "m"(host_rbx), "m"(host_rsp), "m"(host_rbp)
#endif
			             : "rax", "memory");
			__builtin_unreachable();
		}
	}
#endif

	pthread_exit(value);
}

[[noreturn]] void PthreadRetireRforkChildForExec() {
	EXIT_IF(g_pthread_self == nullptr || g_pthread_self->guest_process_pid <= 0 ||
	        g_pthread_self->guest_host_rsp == 0 || g_guest_entry_return_rsp == 0 ||
	        !Process::IsRforkChildExecCommitted(g_pthread_self->guest_process_pid));
	g_pthread_self->rfork_exec_retired = true;
	PthreadExit(nullptr);
	__builtin_unreachable();
}

static void RetireRforkChildForExecAfterHandler(void*) {
	PthreadRetireRforkChildForExec();
}

void PthreadRequestRetireRforkChildForExec() {
	if (Common::HostException::QueueNativeGuestPostHandlerAction(
	        RetireRforkChildForExecAfterHandler, nullptr)) {
		return;
	}
	PthreadRetireRforkChildForExec();
}

int KYTY_SYSV_ABI PthreadEqual(Pthread thread1, Pthread thread2) {
	static std::atomic<uint32_t> log_count {0};

	thread1 = PthreadHostObjectFor(thread1);
	thread2 = PthreadHostObjectFor(thread2);

	const int result = (thread1 == thread2 ? 1 : 0);

	const auto count = log_count.fetch_add(1);
	if (count < 32 || (result != 0 && count < 128)) {
		LOGF("\tPthreadEqual: t1 = 0x%016" PRIx64 ", t2 = 0x%016" PRIx64 ", result = %d\n",
		     reinterpret_cast<uint64_t>(thread1), reinterpret_cast<uint64_t>(thread2), result);
	}

	return result;
}

int KYTY_SYSV_ABI PthreadGetname(Pthread thread, char* name) {
	PRINT_NAME();

	thread = PthreadHostObjectFor(thread);
	if (thread == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}

	if (name == nullptr) {
		return KERNEL_ERROR_EFAULT;
	}

	strncpy(name, thread->name.c_str(), 32);
	name[31] = '\0';
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LAUNCH_TRACE") != nullptr) {
		static std::atomic_uint32_t trace_count {0};
		if (trace_count.fetch_add(1) < 24) {
			LOGF("SYSCORE_PTHREAD_GETNAME_ABI guest_caller=%p"
			     " thread=%p output=%p name=%s\n",
			     __builtin_return_address(0), static_cast<void*>(thread), static_cast<void*>(name),
			     name);
		}
	}

	return OK;
}

bool PthreadPool::CopyNameByGuestId(int guest_tid, char* name) {
	Common::LockGuard lock(m_mutex);
	for (auto* thread: m_threads) {
		if (thread != nullptr && !thread->free && thread->guest.thread_id == guest_tid) {
			std::memset(name, 0, 32);
			std::strncpy(name, thread->name.c_str(), 31);
			return true;
		}
	}
	return false;
}

int PthreadGetNameByGuestThreadId(int guest_tid, char* name) {
	if (name == nullptr) {
		return KERNEL_ERROR_EFAULT;
	}
	if (guest_tid <= 0 || g_pthread_context == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}
	if (g_pthread_main != nullptr && g_pthread_main->guest.thread_id == guest_tid) {
		return PthreadGetname(g_pthread_main, name);
	}
	auto* pool = g_pthread_context->GetPthreadPool();
	return pool != nullptr && pool->CopyNameByGuestId(guest_tid, name) ? OK : KERNEL_ERROR_ESRCH;
}

int KYTY_SYSV_ABI PthreadRename(Pthread thread, const char* name) {
	PRINT_NAME();

	thread = PthreadHostObjectFor(thread);
	if (thread == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	if (name == nullptr) {
		return OK;
	}

	const auto previous = thread->name;
	thread->name = std::string(name);
	if (std::getenv("KYTY_DIAGNOSTIC_PSM_THREAD_LIFECYCLE") != nullptr) {
		LOGF("PSM_THREAD_RENAME guest_pid=%d guest_tid=%d old=%s new=%s\n", Process::GetPid(),
		     thread->guest.thread_id, Log::EscapeField(previous).c_str(),
		     Log::EscapeField(thread->name).c_str());
	}

	return OK;
}

void KYTY_SYSV_ABI PthreadYield() {
	SchedulerBackoffOnce();
}

int KYTY_SYSV_ABI PthreadGetthreadid() {
	// PRINT_NAME();

	return g_pthread_self != nullptr ? g_pthread_self->guest.thread_id : 0;
}

int KYTY_SYSV_ABI KernelClockGetres(KernelClockid clock_id, KernelTimespec* tp) {
	PRINT_NAME();

	if (tp == nullptr) {
		return KERNEL_ERROR_EFAULT;
	}

	if (clock_id == KERNEL_CLOCK_PROCTIME || clock_id == KERNEL_CLOCK_THREAD_CPUTIME_ID ||
	    clock_id == KERNEL_CLOCK_VIRTUAL || clock_id == KERNEL_CLOCK_PROF) {
		const auto frequency = KernelGetTscFrequencyNative();
		tp->tv_sec           = 0;
		tp->tv_nsec          = static_cast<int64_t>(
		    frequency != 0 ? std::max<uint64_t>((1000000000 + (frequency >> 1)) / frequency, 1)
		                   : 1);
		return OK;
	}

	clockid_t pclock_id = {};
	if (!GetPosixClockId(clock_id, &pclock_id)) {
		LOGF("\tunknown clock_id: %d\n", clock_id);
		return KERNEL_ERROR_EINVAL;
	}

	timespec t {};

	int result = clock_getres(pclock_id, &t);

	tp->tv_sec  = t.tv_sec;
	tp->tv_nsec = t.tv_nsec;

	if (result == 0) {
		return OK;
	}
	return KERNEL_ERROR_EINVAL;
}

int KYTY_SYSV_ABI KernelClockGettime(KernelClockid clock_id, KernelTimespec* tp) {
	// Called constantly by Python frame/timer code.

	if (tp == nullptr) {
		return KERNEL_ERROR_EFAULT;
	}

	int special_error = OK;
	if (KernelClockGettimeSpecial(clock_id, tp, &special_error)) {
		return special_error;
	}

	clockid_t pclock_id = {};
	if (!GetPosixClockId(clock_id, &pclock_id)) {
		LOGF("\tunknown clock_id: %d\n", clock_id);
		return KERNEL_ERROR_EINVAL;
	}

	timespec t {};

	int result = clock_gettime(pclock_id, &t);

	tp->tv_sec  = t.tv_sec;
	tp->tv_nsec = t.tv_nsec;

	if (result == 0) {
		return OK;
	}
	return KERNEL_ERROR_EINVAL;
}

int KYTY_SYSV_ABI KernelGettimeofday(KernelTimeval* tp) {
	// PRINT_NAME();

	if (tp == nullptr) {
		return KERNEL_ERROR_EFAULT;
	}

	int result = 0;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	FILETIME ft {};
	GetSystemTimePreciseAsFileTime(&ft);
	uint64_t ticks = ft.dwHighDateTime;
	ticks <<= 32;
	ticks |= ft.dwLowDateTime;
	ticks /= 10;
	ticks -= 11644473600000000ULL;
	tp->tv_sec  = static_cast<int64_t>(ticks / 1000000);
	tp->tv_usec = static_cast<int64_t>(ticks % 1000000);
#else
	struct timespec ts {};
	result = ::clock_gettime(CLOCK_REALTIME, &ts);
	if (result == 0) {
		tp->tv_sec  = static_cast<int64_t>(ts.tv_sec);
		tp->tv_usec = static_cast<int64_t>(ts.tv_nsec / 1000);
	}
#endif

	if (result == 0) {
		return OK;
	}
	return KERNEL_ERROR_EINVAL;
}

int KYTY_SYSV_ABI KernelGettimezone(KernelTimezone* tz) {
	// Hot path in Unity's time/date code.

	if (tz == nullptr) {
		return KERNEL_ERROR_EFAULT;
	}

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	TIME_ZONE_INFORMATION tzi {};
	const DWORD           result = GetTimeZoneInformation(&tzi);

	tz->tz_minuteswest = tzi.Bias;
	tz->tz_dsttime     = (result == TIME_ZONE_ID_UNKNOWN ? DST_NONE : DST_MET);
#else
	const std::time_t now = std::time(nullptr);
	std::tm           local_tm {};
	std::tm           utc_tm {};
	localtime_r(&now, &local_tm);
	gmtime_r(&now, &utc_tm);
	const auto local = std::mktime(&local_tm);
	const auto utc   = std::mktime(&utc_tm);

	tz->tz_minuteswest = static_cast<int32_t>((utc - local) / 60);
	tz->tz_dsttime     = (local_tm.tm_isdst > 0 ? DST_MET : DST_NONE);
#endif

	return OK;
}

int KYTY_SYSV_ABI KernelConvertLocaltimeToUtc(int64_t  local_time, int64_t /*reserved*/,
                                              int64_t* utc_time, KernelTimezone* timezone,
                                              int32_t* dst_seconds) {
	// Hot path in Unity's time/date code.

	if (timezone == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	KernelTimezone local_timezone {};
	auto           ret = KernelGettimezone(&local_timezone);
	if (ret != OK) {
		return ret;
	}

	const auto dst_sec = GetDstSeconds();
	*timezone          = local_timezone;

	if (utc_time != nullptr) {
		*utc_time = local_time + static_cast<int64_t>(local_timezone.tz_minuteswest) * 60 - dst_sec;
	}
	if (dst_seconds != nullptr) {
		*dst_seconds = dst_sec;
	}

	return OK;
}

int KYTY_SYSV_ABI KernelConvertUtcToLocaltime(int64_t utc_time, int64_t* local_time,
                                              KernelTimesec* st, uint64_t* dst_sec) {
	// Hot path in Unity's time/date code.

	KernelTimezone tz {};
	auto           ret = KernelGettimezone(&tz);
	if (ret != OK) {
		return ret;
	}

	const auto dst  = static_cast<int64_t>(GetDstSeconds());
	const auto west = static_cast<int64_t>(tz.tz_minuteswest) * 60;
	if (local_time != nullptr) {
		*local_time = utc_time - west + dst;
	}
	if (st != nullptr) {
		st->t        = utc_time;
		st->west_sec = static_cast<uint32_t>(-west);
		st->dst_sec  = static_cast<uint32_t>(dst);
	}
	if (dst_sec != nullptr) {
		*dst_sec = static_cast<uint64_t>(dst);
	}

	return OK;
}

uint64_t KYTY_SYSV_ABI KernelGetTscFrequency() {
	return KernelGetTscFrequencyNative();
}

uint64_t KYTY_SYSV_ABI KernelReadTsc() {
	return KernelReadTscNative();
}

uint64_t KYTY_SYSV_ABI KernelGetProcessTime() {
	const auto frequency = KernelGetTscFrequencyNative();
	if (frequency == 0) {
		return static_cast<uint64_t>(Loader::Timer::GetTimeMs() * 1000.0);
	}

	const auto elapsed = KernelGetElapsedTsc();
	return static_cast<uint64_t>((static_cast<long double>(elapsed) * 1000000.0L) /
	                             static_cast<long double>(frequency));
}

uint64_t KYTY_SYSV_ABI KernelGetProcessTimeCounter() {
	return KernelGetElapsedTsc();
}

uint64_t KYTY_SYSV_ABI KernelGetProcessTimeCounterFrequency() {
	return KernelGetTscFrequencyNative();
}

void KYTY_SYSV_ABI KernelSetThreadDtors(thread_dtors_func_t dtors) {
	PRINT_NAME();

	// EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());
	EXIT_NOT_IMPLEMENTED(g_pthread_context->GetThreadDtors() != nullptr);

	g_pthread_context->SetThreadDtors(dtors);
	// g_thread_dtors = dtors;
}

int KYTY_SYSV_ABI KernelUsleep(KernelUseconds microseconds) {
	SleepMicroWithSignalPoll(microseconds);
	return OK;
}

unsigned int KYTY_SYSV_ABI KernelSleep(unsigned int seconds) {
	SleepMicroWithSignalPoll(static_cast<uint64_t>(seconds) * 1000000ull);
	return OK;
}

int KYTY_SYSV_ABI KernelNanosleep(const KernelTimespec* rqtp, KernelTimespec* rmtp) {
	if (rqtp == nullptr) {
		return KERNEL_ERROR_EFAULT;
	}

	if (rqtp->tv_sec < 0 || rqtp->tv_nsec < 0 || rqtp->tv_nsec >= 1000000000) {
		return KERNEL_ERROR_EINVAL;
	}

	if (static_cast<uint64_t>(rqtp->tv_sec) >
	    (UINT64_MAX - static_cast<uint64_t>(rqtp->tv_nsec)) / 1000000000ull) {
		return KERNEL_ERROR_EINVAL;
	}

	uint64_t nanos =
	    static_cast<uint64_t>(rqtp->tv_sec) * 1000000000ull + static_cast<uint64_t>(rqtp->tv_nsec);

	SleepNanoWithSignalPoll(nanos);

	if (rmtp != nullptr) {
		rmtp->tv_sec  = 0;
		rmtp->tv_nsec = 0;
	}

	return OK;
}

int KYTY_SYSV_ABI PthreadKeyCreate(PthreadKey* key, pthread_key_destructor_func_t destructor) {
	if (key == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	std::lock_guard lock(g_pthread_keys_mutex);
	for (int index = 0; index < KEYS_MAX; index++) {
		auto&      entry      = g_pthread_keys[index];
		const auto generation = entry.generation.load(std::memory_order_relaxed);
		if ((generation & 1u) == 0) {
			entry.destructor = destructor;
			entry.generation.store(generation + 1, std::memory_order_release);
			*key = index;
			return OK;
		}
	}
	return KERNEL_ERROR_EAGAIN;
}

int KYTY_SYSV_ABI PthreadKeyDelete(PthreadKey key) {
	if (key < 0 || key >= KEYS_MAX) {
		return KERNEL_ERROR_EINVAL;
	}

	std::lock_guard lock(g_pthread_keys_mutex);
	auto&           entry      = g_pthread_keys[key];
	const auto      generation = entry.generation.load(std::memory_order_relaxed);
	if ((generation & 1u) == 0) {
		return KERNEL_ERROR_EINVAL;
	}
	entry.generation.store(generation + 1, std::memory_order_release);
	entry.destructor = nullptr;
	return OK;
}

int KYTY_SYSV_ABI PthreadSetspecific(PthreadKey key, void* value) {
	if (key < 0 || key >= KEYS_MAX) {
		return KERNEL_ERROR_EINVAL;
	}
	const auto generation = g_pthread_keys[key].generation.load(std::memory_order_acquire);
	if ((generation & 1u) == 0) {
		return KERNEL_ERROR_EINVAL;
	}
	if (g_pthread_specific == nullptr) {
		if (value == nullptr) {
			return OK;
		}
		g_pthread_specific.reset(new (std::nothrow) PthreadSpecificValue[KEYS_MAX] {});
		if (g_pthread_specific == nullptr) {
			return KERNEL_ERROR_ENOMEM;
		}
	}
	g_pthread_specific[key] = {generation, value};
	return OK;
}

void* KYTY_SYSV_ABI PthreadGetspecific(PthreadKey key) {
	if (key < 0 || key >= KEYS_MAX || g_pthread_specific == nullptr) {
		return nullptr;
	}
	const auto  generation = g_pthread_keys[key].generation.load(std::memory_order_acquire);
	const auto& value      = g_pthread_specific[key];
	if ((generation & 1u) != 0 && generation == value.generation) {
		return value.data;
	}
	return nullptr;
}

} // namespace LibKernel

namespace Posix {

LIB_NAME("Posix", "libkernel");

struct PthreadOnce {
	int                     state;
	LibKernel::PthreadMutex mutex;
};

static_assert(sizeof(PthreadOnce) == 0x10);

constexpr int PTHREAD_ONCE_NEEDS_INIT  = 0;
constexpr int PTHREAD_ONCE_DONE_INIT   = 1;
constexpr int PTHREAD_ONCE_IN_PROGRESS = 2;
constexpr int PTHREAD_ONCE_WAIT        = 3;

static std::mutex              g_pthread_once_mutex;
static std::condition_variable g_pthread_once_cv;

int KYTY_SYSV_ABI pthread_once(void* once_control, void(KYTY_SYSV_ABI* init_routine)()) {
	PRINT_NAME();

	if (once_control == nullptr || init_routine == nullptr) {
		return POSIX_EINVAL;
	}

	auto* once = static_cast<PthreadOnce*>(once_control);

	{
		std::unique_lock lock(g_pthread_once_mutex);

		for (;;) {
			switch (once->state) {
				case PTHREAD_ONCE_DONE_INIT: return OK;
				case PTHREAD_ONCE_NEEDS_INIT: once->state = PTHREAD_ONCE_IN_PROGRESS; goto run_init;
				case PTHREAD_ONCE_IN_PROGRESS:
				case PTHREAD_ONCE_WAIT:
					once->state = PTHREAD_ONCE_WAIT;
					while (once->state == PTHREAD_ONCE_WAIT) {
						g_pthread_once_cv.wait_for(
						    lock, std::chrono::microseconds(LibKernel::SIGNAL_APC_POLL_MICROS));
						if (once->state == PTHREAD_ONCE_WAIT) {
							lock.unlock();
							LibKernel::KernelDispatchPendingSignalForCurrentThread();
							lock.lock();
						}
					}
					break;
				default: return POSIX_EINVAL;
			}
		}
	}

run_init:
	init_routine();

	{
		std::lock_guard lock(g_pthread_once_mutex);
		once->state = PTHREAD_ONCE_DONE_INIT;
	}
	g_pthread_once_cv.notify_all();

	return OK;
}

int KYTY_SYSV_ABI pthread_create(LibKernel::Pthread* thread, const LibKernel::PthreadAttr* attr,
                                 LibKernel::pthread_entry_func_t entry, void* arg) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadCreate(thread, attr, entry, arg, ""));
}

int KYTY_SYSV_ABI pthread_create_name_np(LibKernel::Pthread*             thread,
                                         const LibKernel::PthreadAttr*   attr,
                                         LibKernel::pthread_entry_func_t entry, void* arg,
                                         const char* name) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(
	    LibKernel::PthreadCreate(thread, attr, entry, arg, (name != nullptr ? name : "")));
}

int KYTY_SYSV_ABI pthread_detach(LibKernel::Pthread thread) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadDetach(thread));
}

void KYTY_SYSV_ABI pthread_exit(void* value) {
	PRINT_NAME();

	LibKernel::PthreadExit(value);
}

LibKernel::Pthread KYTY_SYSV_ABI pthread_self() {
	PRINT_NAME();

	return LibKernel::PthreadSelf();
}

int KYTY_SYSV_ABI pthread_rename_np(LibKernel::Pthread thread, const char* name) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadRename(thread, name));
}

int KYTY_SYSV_ABI pthread_setcancelstate(int state, int* old_state) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadSetcancelstate(state, old_state));
}

int KYTY_SYSV_ABI pthread_setprio(LibKernel::Pthread thread, int prio) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadSetprio(thread, prio));
}

int KYTY_SYSV_ABI pthread_getschedparam(LibKernel::Pthread thread, int* policy,
                                        LibKernel::KernelSchedParam* param) {
	PRINT_NAME();

	thread = PthreadHostObjectFor(thread);
	if (thread == nullptr || policy == nullptr || param == nullptr) {
		return POSIX_EINVAL;
	}

	int result = LibKernel::PthreadAttrGetschedpolicy(&thread->attr, policy);
	result = (result == OK ? LibKernel::PthreadAttrGetschedparam(&thread->attr, param) : result);

	return (result == OK ? 0 : LibKernel::KernelToPosix(result));
}

int KYTY_SYSV_ABI pthread_setschedparam(LibKernel::Pthread thread, int policy,
                                        const LibKernel::KernelSchedParam* param) {
	PRINT_NAME();

	thread = PthreadHostObjectFor(thread);
	if (thread == nullptr || param == nullptr) {
		return POSIX_EINVAL;
	}

	int result = LibKernel::PthreadAttrSetschedpolicy(&thread->attr, policy);
	result = (result == OK ? LibKernel::PthreadAttrSetschedparam(&thread->attr, param) : result);

	return (result == OK ? 0 : LibKernel::KernelToPosix(result));
}

void KYTY_SYSV_ABI pthread_yield() {
	PRINT_NAME();

	LibKernel::PthreadYield();
}

int KYTY_SYSV_ABI sched_get_priority_max(int policy) {
	PRINT_NAME();

	LOGF("\t policy = %d\n", policy);
	// default max=256,min=767 makes PSM's range check reject ScePsP:AudioOutDrv; the env gate swaps
	// them for SCHED_FIFO
	if (policy == 1 && std::getenv("KYTY_DIAGNOSTIC_PSM_SCHED_RANGE") != nullptr) {
		LOGF("FIRST_FRAME_AUDIT PSM_SCHED_MAX policy=1 result=767\n");
		return 767;
	}

	return 256;
}

int KYTY_SYSV_ABI sched_get_priority_min(int policy) {
	PRINT_NAME();

	LOGF("\t policy = %d\n", policy);
	if (policy == 1 && std::getenv("KYTY_DIAGNOSTIC_PSM_SCHED_RANGE") != nullptr) {
		LOGF("FIRST_FRAME_AUDIT PSM_SCHED_MIN policy=1 result=256\n");
		return 256;
	}

	return 767;
}

int KYTY_SYSV_ABI pthread_join(LibKernel::Pthread thread, void** value) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadJoin(thread, value));
}

int KYTY_SYSV_ABI pthread_attr_init(LibKernel::PthreadAttr* attr) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadAttrInit(attr));
}

int KYTY_SYSV_ABI pthread_attr_destroy(LibKernel::PthreadAttr* attr) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadAttrDestroy(attr));
}

int KYTY_SYSV_ABI pthread_attr_get_np(LibKernel::Pthread thread, LibKernel::PthreadAttr* attr) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadAttrGet(thread, attr));
}

int KYTY_SYSV_ABI pthread_attr_getdetachstate(const LibKernel::PthreadAttr* attr, int* state) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadAttrGetdetachstate(attr, state));
}

int KYTY_SYSV_ABI pthread_attr_getguardsize(const LibKernel::PthreadAttr* attr,
                                            size_t*                       guard_size) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadAttrGetguardsize(attr, guard_size));
}

int KYTY_SYSV_ABI pthread_attr_getinheritsched(const LibKernel::PthreadAttr* attr,
                                               int*                          inherit_sched) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadAttrGetinheritsched(attr, inherit_sched));
}

int KYTY_SYSV_ABI pthread_attr_getschedparam(const LibKernel::PthreadAttr* attr,
                                             LibKernel::KernelSchedParam*  param) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadAttrGetschedparam(attr, param));
}

int KYTY_SYSV_ABI pthread_attr_getschedpolicy(const LibKernel::PthreadAttr* attr, int* policy) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadAttrGetschedpolicy(attr, policy));
}

int KYTY_SYSV_ABI pthread_attr_getstack(const LibKernel::PthreadAttr* __restrict attr,
                                        void** __restrict stack_addr,
                                        size_t* __restrict stack_size) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadAttrGetstack(attr, stack_addr, stack_size));
}

int KYTY_SYSV_ABI pthread_attr_getstacksize(const LibKernel::PthreadAttr* attr,
                                            size_t*                       stack_size) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadAttrGetstacksize(attr, stack_size));
}

int KYTY_SYSV_ABI pthread_attr_setdetachstate(LibKernel::PthreadAttr* attr, int state) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadAttrSetdetachstate(attr, state));
}

int KYTY_SYSV_ABI pthread_attr_setguardsize(LibKernel::PthreadAttr* attr, size_t guard_size) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadAttrSetguardsize(attr, guard_size));
}

int KYTY_SYSV_ABI pthread_attr_setinheritsched(LibKernel::PthreadAttr* attr, int inherit_sched) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadAttrSetinheritsched(attr, inherit_sched));
}

int KYTY_SYSV_ABI pthread_attr_setschedparam(LibKernel::PthreadAttr*            attr,
                                             const LibKernel::KernelSchedParam* param) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadAttrSetschedparam(attr, param));
}

int KYTY_SYSV_ABI pthread_attr_setschedpolicy(LibKernel::PthreadAttr* attr, int policy) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadAttrSetschedpolicy(attr, policy));
}

int KYTY_SYSV_ABI pthread_attr_setstack(LibKernel::PthreadAttr* attr, void* addr, size_t size) {
	return POSIX_PTHREAD_CALL(LibKernel::PthreadAttrSetstack(attr, addr, size));
}

int KYTY_SYSV_ABI pthread_attr_setstacksize(LibKernel::PthreadAttr* attr, size_t stack_size) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadAttrSetstacksize(attr, stack_size));
}

int KYTY_SYSV_ABI pthread_cond_broadcast(LibKernel::PthreadCond* cond) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadCondBroadcast(cond));
}

int KYTY_SYSV_ABI pthread_cond_signal(LibKernel::PthreadCond* cond) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadCondSignal(cond));
}

int KYTY_SYSV_ABI pthread_cond_init(LibKernel::PthreadCond*           cond,
                                    const LibKernel::PthreadCondattr* attr) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadCondInit(cond, attr, nullptr));
}

int KYTY_SYSV_ABI pthread_condattr_setclock(LibKernel::PthreadCondattr* attr,
                                            LibKernel::KernelClockid    clock_id) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadCondattrSetclock(attr, clock_id));
}

int KYTY_SYSV_ABI pthread_condattr_init(LibKernel::PthreadCondattr* attr) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadCondattrInit(attr));
}

int KYTY_SYSV_ABI pthread_condattr_destroy(LibKernel::PthreadCondattr* attr) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadCondattrDestroy(attr));
}

int KYTY_SYSV_ABI pthread_cond_wait(LibKernel::PthreadCond* cond, LibKernel::PthreadMutex* mutex) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadCondWait(cond, mutex));
}

int KYTY_SYSV_ABI pthread_cond_timedwait(LibKernel::PthreadCond*          cond,
                                         LibKernel::PthreadMutex*         mutex,
                                         const LibKernel::KernelTimespec* abstime) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadCondTimedwaitAbs(cond, mutex, abstime));
}

int KYTY_SYSV_ABI pthread_cond_reltimedwait_np(LibKernel::PthreadCond*   cond,
                                               LibKernel::PthreadMutex*  mutex,
                                               LibKernel::KernelUseconds usec) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadCondTimedwait(cond, mutex, usec));
}

int KYTY_SYSV_ABI pthread_mutex_lock(LibKernel::PthreadMutex* mutex) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadMutexLock(mutex));
}

int KYTY_SYSV_ABI pthread_mutex_trylock(LibKernel::PthreadMutex* mutex) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadMutexTrylock(mutex));
}

int KYTY_SYSV_ABI pthread_mutex_timedlock(LibKernel::PthreadMutex*         mutex,
                                          const LibKernel::KernelTimespec* abstime) {
	PRINT_NAME();

	if (abstime == nullptr || abstime->tv_sec < 0 || abstime->tv_nsec < 0 ||
	    abstime->tv_nsec >= 1000000000) {
		return POSIX_PTHREAD_CALL(LibKernel::KERNEL_ERROR_EINVAL);
	}

	LibKernel::KernelTimespec now {};
	if (LibKernel::KernelClockGettime(0, &now) != OK) {
		return POSIX_PTHREAD_CALL(LibKernel::KERNEL_ERROR_EINVAL);
	}

	int64_t sec_delta  = abstime->tv_sec - now.tv_sec;
	int64_t nsec_delta = abstime->tv_nsec - now.tv_nsec;
	if (nsec_delta < 0) {
		sec_delta--;
		nsec_delta += 1000000000;
	}

	uint64_t usec = 0;
	if (sec_delta > 0 || (sec_delta == 0 && nsec_delta > 0)) {
		usec = (static_cast<uint64_t>(sec_delta) > UINT32_MAX / 1000000ull
		            ? UINT32_MAX
		            : static_cast<uint64_t>(sec_delta) * 1000000ull);
		usec = std::min<uint64_t>(UINT32_MAX, usec + static_cast<uint64_t>(nsec_delta / 1000));
	}

	return POSIX_PTHREAD_CALL(
	    LibKernel::PthreadMutexTimedlock(mutex, static_cast<LibKernel::KernelUseconds>(usec)));
}

int KYTY_SYSV_ABI pthread_mutex_unlock(LibKernel::PthreadMutex* mutex) {
	// PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadMutexUnlock(mutex));
}

int KYTY_SYSV_ABI pthread_rwlock_rdlock(LibKernel::PthreadRwlock* rwlock) {
	// Hot path for some PS5 titles; per-call name logging can dominate runtime.

	return POSIX_PTHREAD_CALL(LibKernel::PthreadRwlockRdlock(rwlock));
}

int KYTY_SYSV_ABI pthread_rwlock_unlock(LibKernel::PthreadRwlock* rwlock) {
	// Hot path for some PS5 titles; per-call name logging can dominate runtime.

	return POSIX_PTHREAD_CALL(LibKernel::PthreadRwlockUnlock(rwlock));
}

int KYTY_SYSV_ABI pthread_rwlock_wrlock(LibKernel::PthreadRwlock* rwlock) {
	// Hot path for some PS5 titles; per-call name logging can dominate runtime.

	return POSIX_PTHREAD_CALL(LibKernel::PthreadRwlockWrlock(rwlock));
}

int KYTY_SYSV_ABI pthread_rwlock_destroy(LibKernel::PthreadRwlock* rwlock) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadRwlockDestroy(rwlock));
}

int KYTY_SYSV_ABI pthread_rwlock_init(LibKernel::PthreadRwlock*           rwlock,
                                      const LibKernel::PthreadRwlockattr* attr) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadRwlockInit(rwlock, attr, nullptr));
}

int KYTY_SYSV_ABI pthread_key_create(LibKernel::PthreadKey*                   key,
                                     LibKernel::pthread_key_destructor_func_t destructor) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadKeyCreate(key, destructor));
}

int KYTY_SYSV_ABI pthread_key_delete(LibKernel::PthreadKey key) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadKeyDelete(key));
}

int KYTY_SYSV_ABI pthread_setspecific(LibKernel::PthreadKey key, void* value) {
	return POSIX_PTHREAD_CALL(LibKernel::PthreadSetspecific(key, value));
}

void* KYTY_SYSV_ABI pthread_getspecific(LibKernel::PthreadKey key) {
	return LibKernel::PthreadGetspecific(key);
}

int KYTY_SYSV_ABI pthread_mutex_destroy(LibKernel::PthreadMutex* mutex) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadMutexDestroy(mutex));
}

int KYTY_SYSV_ABI pthread_mutex_init(LibKernel::PthreadMutex*           mutex,
                                     const LibKernel::PthreadMutexattr* attr) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadMutexInit(mutex, attr, nullptr));
}

int KYTY_SYSV_ABI pthread_mutexattr_init(LibKernel::PthreadMutexattr* attr) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadMutexattrInit(attr));
}

int KYTY_SYSV_ABI pthread_mutexattr_settype(LibKernel::PthreadMutexattr* attr, int type) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadMutexattrSettype(attr, type));
}

int KYTY_SYSV_ABI pthread_mutexattr_setprotocol(LibKernel::PthreadMutexattr* attr, int protocol) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadMutexattrSetprotocol(attr, protocol));
}

int KYTY_SYSV_ABI pthread_mutexattr_destroy(LibKernel::PthreadMutexattr* attr) {
	PRINT_NAME();

	return POSIX_PTHREAD_CALL(LibKernel::PthreadMutexattrDestroy(attr));
}

int KYTY_SYSV_ABI pthread_getstack(const LibKernel::PthreadAttr* __restrict attr,
                                   void** __restrict stack_addr, size_t* __restrict stack_size) {
	PRINT_NAME();

	return pthread_attr_getstack(attr, stack_addr, stack_size);
}

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
int KYTY_SYSV_ABI pthread_suspend_user_context_np(LibKernel::Pthread thread) {
	thread = PthreadHostObjectFor(thread);
	if (thread == nullptr) {
		return POSIX_EINVAL;
	}
	if (thread->free || thread->almost_done) {
		LOGF("FIRST_FRAME_AUDIT SUSPEND_ESRCH reason=flagged free=%d almost_done=%d host_tid=%llu "
		     "name=%s\n",
		     thread->free ? 1 : 0, thread->almost_done ? 1 : 0,
		     static_cast<unsigned long long>(thread->host_thread_id), thread->name.c_str());
		return POSIX_ESRCH;
	}
	// TODO: chosen value, native result for suspending self not checked
	if (thread == LibKernel::PthreadSelfOrNull()) {
		return POSIX_EDEADLK;
	}

	HANDLE host_thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE,
	                                static_cast<DWORD>(thread->host_thread_id));
	if (host_thread == nullptr) {
		LOGF("FIRST_FRAME_AUDIT SUSPEND_ESRCH reason=open_thread_failed host_tid=%llu name=%s "
		     "gle=%lu\n",
		     static_cast<unsigned long long>(thread->host_thread_id), thread->name.c_str(),
		     GetLastError());
		return POSIX_ESRCH;
	}

	thread->suspend_requests++;
	LibKernel::PthreadWakeForSignal(thread);

	int      result             = 0;
	bool     forced             = false;
	bool     memory_lock_logged = false;
	uint64_t last_rip           = 0;
	uint64_t last_rsp           = 0;
	uint64_t stalled_since      = GetTickCount64();

	for (uint32_t attempt = 0;; attempt++) {
		// SuspendThread only queues the suspend, GetThreadContext is what waits for it to land.
		CONTEXT ctx {};
		ctx.ContextFlags = CONTEXT_CONTROL;
		if (SuspendThread(host_thread) == static_cast<DWORD>(-1)) {
			LOGF("FIRST_FRAME_AUDIT SUSPEND_ESRCH reason=suspend_failed host_tid=%llu name=%s "
			     "gle=%lu\n",
			     static_cast<unsigned long long>(thread->host_thread_id), thread->name.c_str(),
			     GetLastError());
			result = POSIX_ESRCH;
			break;
		}
		if (GetThreadContext(host_thread, &ctx) == 0) {
			const DWORD gle = GetLastError();
			// Already stopped. The context read only feeds the in_host heuristic; libmonosgen
			// rereads via pthread_get_user_context_np.
			if (!forced && GetTickCount64() - stalled_since >= 50) {
				LOGF("\tpthread_suspend_user_context_np: %s context unreadable at suspend (gle=%lu "
				     "attempts=%u)"
				     ", leaving it suspended\n",
				     thread->name.c_str(), gle, attempt + 1);
				forced = true;
			}
			if (forced) {
				result = 0;
				break;
			}
			ResumeThread(host_thread);
			continue;
		}

		// A thread stopped in host code may own a lock the caller needs. Kyty's image is at
		// 0x140000000, below the guest modules, so any mapped image or anything above the guest
		// range is host.
		MEMORY_BASIC_INFORMATION code {};
		VirtualQuery(reinterpret_cast<void*>(ctx.Rip), &code, sizeof(code));
		const bool in_host = (code.Type == MEM_IMAGE || ctx.Rip >= 0xfc00000000ull);
		const bool moved   = (ctx.Rip != last_rip || ctx.Rsp != last_rsp);
		// read while stopped, or the suspender's own next mmap blocks on the VM lock
		const bool holds_memory_lock =
		    LibKernel::Memory::MemoryOperationOwnerThreadId() == thread->host_thread_id;
		if (!in_host || thread->suspend_parked || (forced && !moved && !holds_memory_lock)) {
			break;
		}

		ResumeThread(host_thread);

		const auto now = GetTickCount64();
		if (moved) {
			last_rip      = ctx.Rip;
			last_rsp      = ctx.Rsp;
			stalled_since = now;
			forced        = false;
		} else if (holds_memory_lock) {
			if (!memory_lock_logged && now - stalled_since >= 50) {
				LOGF("\tpthread_suspend_user_context_np: %s holds the memory lock in host code at "
				     "0x%016" PRIx64 ", waiting for it to release\n",
				     thread->name.c_str(), static_cast<uint64_t>(ctx.Rip));
				memory_lock_logged = true;
			}
		} else if (!forced && now - stalled_since >= 50) {
			// a host wait that skips KernelDispatchPendingSignalForCurrentThread stalls the caller;
			// logged after resume, a stopped thread may hold the log lock
			LOGF("\tpthread_suspend_user_context_np: %s stays in host code at 0x%016" PRIx64
			     ", suspending it there\n",
			     thread->name.c_str(), static_cast<uint64_t>(ctx.Rip));
			if (std::getenv("KYTY_DIAGNOSTIC_SUSPEND_HOST_STACK") != nullptr) {
				// may exit now, so copy its stack with a non-faulting read. Words above rsp
				// pointing into Kyty's code are mostly return addresses naming the wait.
				MEMORY_BASIC_INFORMATION mem {};
				VirtualQuery(reinterpret_cast<void*>(ctx.Rsp), &mem, sizeof(mem));
				const auto top = reinterpret_cast<uint64_t>(mem.BaseAddress) + mem.RegionSize;
				std::vector<uint64_t> stack(std::min<uint64_t>(2048, (top - ctx.Rsp) / 8));
				SIZE_T                copied = 0;
				ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(ctx.Rsp),
				                  stack.data(), stack.size() * 8, &copied);
				std::string words;
				int         found = 0;
				for (size_t i = 0; i < copied / 8 && found < 16; i++) {
					MEMORY_BASIC_INFORMATION image {};
					VirtualQuery(reinterpret_cast<void*>(stack[i]), &image, sizeof(image));
					if (image.AllocationBase == GetModuleHandleW(nullptr) &&
					    image.Protect == PAGE_EXECUTE_READ) {
						words += fmt::format(" 0x{:x}", stack[i]);
						found++;
					}
				}
				auto* self = LibKernel::PthreadSelfOrNull();
				LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_SUSPEND_HOST_STACK t=%.3f by=%s thread=%s"
				     " rsp=0x%016" PRIx64 " image_base=0x%016" PRIx64 " code_words=%s\n",
				     Loader::Timer::GetTimeMs() / 1000.0,
				     self != nullptr ? self->name.c_str() : "(unknown)", thread->name.c_str(),
				     static_cast<uint64_t>(ctx.Rsp),
				     reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr)), words.c_str());
			}
			forced = true;
		}

		if (attempt < 16) {
			LibKernel::SchedulerBackoffOnce();
		} else {
			Common::Thread::SleepMicro(200);
		}
	}

	if (result != 0) {
		thread->suspend_requests--;
	}
	CloseHandle(host_thread);

	return result;
}

// Guest ucontext as libmonosgen reads it, for a signal handler as well: 0x500 bytes with the
// FreeBSD amd64 mcontext at 0x40.
struct UserContext {
	uint8_t  uc_head[0x48];
	uint64_t mc_rdi;
	uint64_t mc_rsi;
	uint64_t mc_rdx;
	uint64_t mc_rcx;
	uint64_t mc_r8;
	uint64_t mc_r9;
	uint64_t mc_rax;
	uint64_t mc_rbx;
	uint64_t mc_rbp;
	uint64_t mc_r10;
	uint64_t mc_r11;
	uint64_t mc_r12;
	uint64_t mc_r13;
	uint64_t mc_r14;
	uint64_t mc_r15;
	uint8_t  mc_trap[0x20];
	uint64_t mc_rip;
	uint8_t  mc_cs_rflags[0x10];
	uint64_t mc_rsp;
	uint8_t  uc_tail[0x400];
};

static_assert(offsetof(UserContext, mc_rip) == 0xe0);
static_assert(sizeof(UserContext) == 0x500);

int KYTY_SYSV_ABI pthread_get_user_context_np(LibKernel::Pthread thread, void* ucontext) {
	thread = PthreadHostObjectFor(thread);
	if (thread == nullptr) {
		return POSIX_EINVAL;
	}
	if (thread->free || thread->almost_done) {
		return POSIX_ESRCH;
	}

	HANDLE host_thread =
	    OpenThread(THREAD_GET_CONTEXT, FALSE, static_cast<DWORD>(thread->host_thread_id));
	if (host_thread == nullptr) {
		return POSIX_ESRCH;
	}

	CONTEXT ctx {};
	ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
	// can fail while the suspension lands; the thread is already stopped
	bool captured = false;
	for (int attempt = 0; attempt < 50 && !captured; attempt++) {
		captured = (GetThreadContext(host_thread, &ctx) != 0);
		if (!captured) Common::Thread::SleepMicro(1000);
	}
	CloseHandle(host_thread);
	if (!captured) {
		LOGF("FIRST_FRAME_AUDIT GETCTX_ESRCH host_tid=%llu name=%s gle=%lu\n",
		     static_cast<unsigned long long>(thread->host_thread_id), thread->name.c_str(),
		     GetLastError());
		return POSIX_ESRCH;
	}

	// Host registers as-is even in host code: HLE runs on the guest stack, so Mono's scan up from
	// rsp covers the spilled guest registers.
	auto* uc = static_cast<UserContext*>(ucontext);
	std::memset(uc, 0, sizeof(UserContext));
	uc->mc_rdi = ctx.Rdi;
	uc->mc_rsi = ctx.Rsi;
	uc->mc_rdx = ctx.Rdx;
	uc->mc_rcx = ctx.Rcx;
	uc->mc_r8  = ctx.R8;
	uc->mc_r9  = ctx.R9;
	uc->mc_rax = ctx.Rax;
	uc->mc_rbx = ctx.Rbx;
	uc->mc_rbp = ctx.Rbp;
	uc->mc_r10 = ctx.R10;
	uc->mc_r11 = ctx.R11;
	uc->mc_r12 = ctx.R12;
	uc->mc_r13 = ctx.R13;
	uc->mc_r14 = ctx.R14;
	uc->mc_r15 = ctx.R15;
	uc->mc_rip = ctx.Rip;
	uc->mc_rsp = ctx.Rsp;

	return 0;
}

int KYTY_SYSV_ABI pthread_resume_user_context_np(LibKernel::Pthread thread) {
	thread = PthreadHostObjectFor(thread);
	if (thread == nullptr) {
		return POSIX_EINVAL;
	}
	if (thread->free || thread->almost_done) {
		return POSIX_ESRCH;
	}

	HANDLE host_thread =
	    OpenThread(THREAD_SUSPEND_RESUME, FALSE, static_cast<DWORD>(thread->host_thread_id));
	if (host_thread == nullptr) {
		return POSIX_ESRCH;
	}

	const auto previous = ResumeThread(host_thread);
	CloseHandle(host_thread);
	if (previous == static_cast<DWORD>(-1)) {
		return POSIX_ESRCH;
	}
	if (previous != 0) {
		thread->suspend_requests--;
	}

	return 0;
}
#endif

} // namespace Posix

} // namespace Libs

#if KYTY_PLATFORM == KYTY_PLATFORM_LINUX
#pragma GCC diagnostic pop
#endif
