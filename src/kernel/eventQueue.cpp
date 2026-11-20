#include "kernel/eventQueue.h"

#include "common/assert.h"
#include "common/common.h"
#include "common/logging/log.h"
#include "common/stringUtils.h"
#include "common/threads.h"
#include "common/timer.h"
#include "kernel/fileSystem.h"
#include "kernel/process.h"
#include "libs/errno.h"
#include "libs/libs.h"
#include "libs/network.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <fmt/format.h>
#include <limits>
#include <list>
#include <unordered_map>
#include <vector>

namespace Libs::LibKernel::EventQueue {

LIB_NAME("libkernel", "libkernel");

constexpr uint16_t EV_ADD     = 0x01;
constexpr uint16_t EV_ENABLE  = 0x04;
constexpr uint16_t EV_ONESHOT = 0x10;
constexpr uint16_t EV_CLEAR   = 0x20;
constexpr uint16_t EV_ERROR   = 0x4000;
constexpr uint16_t EV_EOF     = 0x8000;
constexpr uint32_t NOTE_LOWAT = 0x01;

static uint64_t MonotonicTimeNs() {
	return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
	                                 std::chrono::steady_clock::now().time_since_epoch())
	                                 .count());
}

static std::unordered_map<KernelEqueue, KernelEqueueRef> g_equeues;
static Common::Mutex                                     g_equeues_mutex;
static uint64_t                                          g_next_equeue = 1;

static void NativeOriginalUserEventTriggerFunc(KernelEqueueEvent* event, void* trigger_data);
static void NativeNotificationTrigger(KernelEqueueEvent* event, void* trigger_data);

class KernelEqueuePrivate {
public:
	explicit KernelEqueuePrivate(KernelEqueue handle): m_handle(handle) {}
	virtual ~KernelEqueuePrivate();

	KYTY_CLASS_NO_COPY(KernelEqueuePrivate);

	[[nodiscard]] const std::string& GetName() const { return m_name; }
	void                             SetName(const std::string& m_name) { this->m_name = m_name; }

	int AddEvent(const KernelEqueueEvent& event);
	int TriggerEvent(uintptr_t ident, int16_t filter, void* trigger_data);
	int DeleteEvent(uintptr_t ident, int16_t filter);

	int  GetTriggeredEvents(KernelEvent* ev, int num);
	int  WaitForEvents(KernelEvent* ev, int num, uint32_t micros);
	bool PollPendingSources(std::vector<KernelEqueue>* sources);
	void Close();

private:
	void TriggerExpiredTimers(uint64_t now_ns);
	bool GetNextTimerWaitMicros(uint64_t now_ns, uint32_t* wait_micros) const;
	void PollReadEvents(bool nested = true);
	void RefreshReadiness() {
		const bool direct_pending =
		    std::any_of(m_events.begin(), m_events.end(), [](const auto& e) {
			    return e.triggered && e.watched_kqueue == KERNEL_EQUEUE_INVALID;
		    });
		m_has_pending_direct_events.store(direct_pending, std::memory_order_release);
	}

	std::list<KernelEqueueEvent> m_events;
	Common::Mutex                m_mutex;
	Common::CondVar              m_cond_var;
	std::string                  m_name;
	KernelEqueue                 m_handle = KERNEL_EQUEUE_INVALID;
	bool                         m_closed = false;
	std::atomic_bool             m_has_pending_direct_events {false};
};

KernelEqueuePrivate::~KernelEqueuePrivate() {
	Close();
}

void KernelEqueuePrivate::Close() {
	Common::LockGuard lock(m_mutex);

	if (m_closed) {
		return;
	}
	m_closed = true;
	for (auto& event: m_events) {
		if (event.filter.delete_event_func != nullptr) {
			auto owner = event.filter.owner;
			event.filter.delete_event_func(m_handle, &event);
		}
	}
	m_events.clear();
	m_has_pending_direct_events.store(false, std::memory_order_release);
	m_cond_var.SignalAll();
}

int KernelEqueuePrivate::GetTriggeredEvents(KernelEvent* ev, int num) {
	Common::LockGuard lock(m_mutex);

	EXIT_IF(num < 1);
	if (m_closed) {
		return KERNEL_ERROR_EBADF;
	}

	TriggerExpiredTimers(MonotonicTimeNs());
	PollReadEvents();

	int ret = 0;

	for (auto it = m_events.begin(); it != m_events.end();) {
		auto& event = *it;
		bool  erase = false;
		while (event.triggered) {
			ev[ret++] = event.event;
			if ((event.event.flags & EV_ONESHOT) != 0) {
				erase = true;
				break;
			}

			if (event.filter.reset_func != nullptr) {
				event.filter.reset_func(&event);
			} else if ((event.event.flags & EV_CLEAR) != 0) {
				event.triggered    = false;
				event.event.fflags = 0;
				event.event.data   = 0;
			}

			if (!event.pending_events.empty()) {
				event.event = event.pending_events.front();
				event.pending_events.pop_front();
				event.triggered = true;
			} else {
				// A persistent level is delivered again by the next wait, not this batch.
				break;
			}

			if (ret >= num) {
				break;
			}
		}
		it = (erase ? m_events.erase(it) : std::next(it));
		if (ret >= num) {
			break;
		}
	}

	RefreshReadiness();
	return ret;
}

void KernelEqueuePrivate::TriggerExpiredTimers(uint64_t now_ns) {
	for (auto& event: m_events) {
		if (event.deadline_ns != 0 && event.deadline_ns <= now_ns) {
			if (event.event.filter == KERNEL_EVFILT_TIMER) {
				const auto count = event.interval_ns == 0 ? !event.triggered :
				    1 + (now_ns - event.deadline_ns) / event.interval_ns;
				event.event.data += static_cast<intptr_t>(count);
				event.deadline_ns += count * event.interval_ns;
			}
			event.triggered = true;
		}
	}
	RefreshReadiness();
}

bool KernelEqueuePrivate::GetNextTimerWaitMicros(uint64_t now_ns, uint32_t* wait_micros) const {
	EXIT_IF(wait_micros == nullptr);

	uint64_t nearest_deadline = UINT64_MAX;
	for (const auto& event: m_events) {
		if (!event.triggered && event.deadline_ns != 0) {
			nearest_deadline = std::min(nearest_deadline, event.deadline_ns);
		}
	}
	if (nearest_deadline == UINT64_MAX) {
		return false;
	}

	const auto remaining_ns = nearest_deadline > now_ns ? nearest_deadline - now_ns : 0;
	const auto rounded_us   = std::max<uint64_t>(1, (remaining_ns + 999u) / 1000u);
	*wait_micros            = static_cast<uint32_t>(std::min<uint64_t>(rounded_us, UINT32_MAX));
	return true;
}

// A socket filter is a level: it follows the descriptor's state at each wait instead of latching.
void KernelEqueuePrivate::PollReadEvents(bool nested) {
	m_events.remove_if([](const auto& event) {
		if (event.watched_mbus_receive) {
			std::lock_guard lock(event.watched_mbus_receive->GetMutex());
			return event.watched_mbus_receive->closed;
		}
		if (!event.watched_guest_socket) return false;
		int64_t pending = 0;
		bool    eof     = false;
		return FileSystem::QueryGuestSocketReadSource(event.watched_guest_socket, &pending, &eof) ==
		       KERNEL_ERROR_EBADF;
	});
	for (auto& event: m_events) {
		if (event.event.filter != KERNEL_EVFILT_READ) {
			continue;
		}
		if (event.watched_kqueue != KERNEL_EQUEUE_INVALID) {
			if (!nested) continue;
			const bool ready = KernelEqueueHasPendingEvents(event.watched_kqueue);
			event.triggered  = ready;
			event.event.data = ready ? 1 : 0;
			event.event.flags &= static_cast<uint16_t>(~EV_EOF);
			continue;
		}
		if (event.watched_mbus_receive) {
			std::lock_guard lock(event.watched_mbus_receive->GetMutex());
			const auto&     inbox = *event.watched_mbus_receive;
			if (inbox.system) {
				event.triggered =
				    !inbox.closed && !inbox.system->shutting_down &&
				    (inbox.system->priority.size() >= 80 || inbox.system->received.size() >= 80);
				event.event.data = 0x20;
				event.event.flags &= static_cast<uint16_t>(~EV_EOF);
				continue;
			}
			const uint64_t received = inbox.closed ? 0 : inbox.received.size();
			event.triggered         = received >= 80;
			event.event.data        = static_cast<intptr_t>(received);
			event.event.flags &= static_cast<uint16_t>(~EV_EOF);
			continue;
		}
		int64_t   pending = 0;
		bool      eof     = false;
		const int result =
		    event.watched_guest_socket
		        ? FileSystem::QueryGuestSocketReadSource(event.watched_guest_socket, &pending, &eof)
		        : Network::Net::SocketReadReady(static_cast<int>(event.event.ident), &pending,
		                                        &eof);
		if (result < 0) {
			event.triggered = false;
			continue;
		}
		const auto lowat = std::max<int64_t>(1, reinterpret_cast<intptr_t>(event.filter.data));
		event.triggered  = eof || pending >= lowat;
		event.event.data = static_cast<intptr_t>(pending);
		if (event.watched_guest_socket && event.triggered &&
		    std::getenv("KYTY_DIAGNOSTIC_GUEST_SOCKET_IO")) {
			static std::atomic_uint32_t logged {0};
			if (logged.fetch_add(1) < 128) {
				LOGF("GUEST_SOCKET_READ_READY guest_pid=%d queue=%" PRId64 " fd=%" PRIuPTR
				     " pending=%" PRId64 " eof=%u\n",
				     Process::GetPid(), m_handle, event.event.ident, pending, eof ? 1u : 0u);
				Log::Flush();
			}
		}
		if (eof) {
			event.event.flags |= EV_EOF;
		} else {
			event.event.flags &= static_cast<uint16_t>(~EV_EOF);
		}
	}
	RefreshReadiness();
}

bool KernelEqueuePrivate::PollPendingSources(std::vector<KernelEqueue>* sources) {
	if (!m_mutex.TryLock()) return m_has_pending_direct_events.load(std::memory_order_acquire);
	struct Unlock {
		Common::Mutex& mutex;
		~Unlock() { mutex.Unlock(); }
	} unlock {m_mutex};
	if (m_closed) return false;
	TriggerExpiredTimers(MonotonicTimeNs());
	PollReadEvents(false);
	for (const auto& event: m_events) {
		if (event.watched_kqueue != KERNEL_EQUEUE_INVALID) sources->push_back(event.watched_kqueue);
	}
	return m_has_pending_direct_events.load(std::memory_order_acquire);
}

int KernelEqueuePrivate::WaitForEvents(KernelEvent* ev, int num, uint32_t micros) {
	Common::LockGuard lock(m_mutex);

	EXIT_IF(num < 1);
	if (m_closed) {
		return KERNEL_ERROR_EBADF;
	}

	uint32_t      elapsed = 0;
	Common::Timer t;
	t.Start();

	for (;;) {
		int ret = GetTriggeredEvents(ev, num);

		if (ret != 0 || (elapsed >= micros && micros != 0)) {
			return ret;
		}

		uint32_t timer_wait = 0;
		bool     has_timer  = GetNextTimerWaitMicros(MonotonicTimeNs(), &timer_wait);
		// nothing signals socket readability, so resample after a short sleep
		if (std::any_of(m_events.begin(), m_events.end(),
		                [](const auto& e) { return e.event.filter == KERNEL_EVFILT_READ; })) {
			timer_wait = has_timer ? std::min<uint32_t>(timer_wait, 10000) : 10000;
			has_timer  = true;
		}
		if (micros == 0 && !has_timer) {
			m_cond_var.Wait(&m_mutex);
		} else {
			const auto external_wait = micros != 0 ? micros - elapsed : UINT32_MAX;
			m_cond_var.WaitFor(&m_mutex,
			                   has_timer ? std::min(external_wait, timer_wait) : external_wait);
		}

		elapsed = static_cast<uint32_t>(t.GetTimeS() * 1000000.0);
	}

	return 0;
}

int KernelEqueuePrivate::AddEvent(const KernelEqueueEvent& event) {
	Common::LockGuard lock(m_mutex);

	if (m_closed) {
		return KERNEL_ERROR_EBADF;
	}
	auto it = std::find_if(m_events.begin(), m_events.end(),
	                       [ident = event.event.ident, filter = event.event.filter](const auto& e) {
		                       return e.event.ident == ident && e.event.filter == filter;
	                       });
	if (it != m_events.end()) {
		TriggerExpiredTimers(MonotonicTimeNs());
		it->deadline_ns = event.deadline_ns;
		it->interval_ns = event.interval_ns;
		it->watched_kqueue = event.watched_kqueue;
		if (event.event.filter == KERNEL_EVFILT_READ) {
			it->filter               = event.filter;
			it->watched_guest_socket = event.watched_guest_socket;
			it->watched_mbus_receive = event.watched_mbus_receive;
			it->event.flags          = event.event.flags;
			it->event.fflags         = event.event.fflags;
			it->event.data           = 0;
			it->triggered            = false;
			it->pending_events.clear();
		}
		if (event.filter.trigger_func == NativeOriginalUserEventTriggerFunc) {
			it->event     = event.event;
			it->filter    = event.filter;
			it->triggered = false;
			it->pending_events.clear();
		}
		if (event.filter.trigger_func == NativeNotificationTrigger) it->filter = event.filter;
		if (event.event.filter == KERNEL_EVFILT_PROC && event.filter.owner != nullptr) {
			it->filter = event.filter;
		}
		it->event.udata = event.event.udata;
		for (auto& pending: it->pending_events) {
			pending.udata = event.event.udata;
		}
	} else {
		m_events.push_back(event);
	}
	RefreshReadiness();

	m_cond_var.Signal();
	return OK;
}

int KernelEqueuePrivate::TriggerEvent(uintptr_t ident, int16_t filter, void* trigger_data) {
	Common::LockGuard lock(m_mutex);

	if (m_closed) {
		return KERNEL_ERROR_EBADF;
	}
	auto it = std::find_if(m_events.begin(), m_events.end(), [ident, filter](const auto& e) {
		return e.event.ident == ident && e.event.filter == filter;
	});
	if (it != m_events.end()) {
		auto& event = *it;

		if (event.filter.trigger_func != nullptr) {
			event.filter.trigger_func(&event, trigger_data);
		} else {
			event.triggered = true;
		}
		RefreshReadiness();

		m_cond_var.Signal();

		return OK;
	}

	return KERNEL_ERROR_ENOENT;
}

static void UserEventTriggerFunc(KernelEqueueEvent* event, void* trigger_data) {
	EXIT_IF(event == nullptr);
	event->triggered   = true;
	event->event.data  = reinterpret_cast<intptr_t>(trigger_data);
	event->event.udata = trigger_data;
}

static void NativeOriginalUserEventTriggerFunc(KernelEqueueEvent* event, void* trigger_data) {
	EXIT_IF(event == nullptr);
	event->triggered = true;
}

static void NativeUserEventReset(KernelEqueueEvent* event) {
	event->triggered    = false;
	event->event.fflags = 0;
}

static void AmprEventTriggerFunc(KernelEqueueEvent* event, void* trigger_data) {
	EXIT_IF(event == nullptr);
	auto triggered_event = event->event;
	triggered_event.data = static_cast<intptr_t>(reinterpret_cast<uintptr_t>(trigger_data));
	if (event->triggered) {
		event->pending_events.push_back(triggered_event);
	} else {
		event->event     = triggered_event;
		event->triggered = true;
	}
}

static void UserEventResetFunc(KernelEqueueEvent* event) {
	EXIT_IF(event == nullptr);
	if ((event->event.flags & EV_CLEAR) != 0) {
		event->triggered    = false;
		event->event.fflags = 0;
		event->event.data   = 0;
	}
}

static void NativeNotificationTrigger(KernelEqueueEvent* event, void* trigger_data) {
	const auto value = reinterpret_cast<uintptr_t>(trigger_data);
	const auto hint  = value & 0xffu;
	if (value == 0 || hint != reinterpret_cast<uintptr_t>(event->filter.data)) return;
	event->triggered  = true;
	event->event.data = static_cast<intptr_t>(value & UINT64_C(0xffffffffffff00ff));
}

int KernelEqueuePrivate::DeleteEvent(uintptr_t ident, int16_t filter) {
	Common::LockGuard lock(m_mutex);

	if (m_closed) {
		return KERNEL_ERROR_EBADF;
	}
	auto it = std::find_if(m_events.begin(), m_events.end(), [ident, filter](const auto& e) {
		return e.event.ident == ident && e.event.filter == filter;
	});
	if (it != m_events.end()) {
		auto& event = *it;

		if (event.filter.delete_event_func != nullptr) {
			auto owner = event.filter.owner;
			event.filter.delete_event_func(m_handle, &event);
		}

		m_events.erase(it);
		RefreshReadiness();

		return OK;
	}

	return KERNEL_ERROR_ENOENT;
}

KernelEqueueRef KernelPinEqueue(KernelEqueue eq) {
	if (eq == KERNEL_EQUEUE_INVALID) {
		return {};
	}

	Common::LockGuard lock(g_equeues_mutex);
	const auto        entry = g_equeues.find(eq);
	return entry != g_equeues.end() ? entry->second : KernelEqueueRef {};
}

bool KernelEqueueHasPendingEvents(KernelEqueue eq) {
	std::vector<KernelEqueue> sources {eq};
	std::vector<KernelEqueue> visited;
	for (size_t index = 0; index < sources.size(); ++index) {
		const auto source = sources[index];
		if (std::find(visited.begin(), visited.end(), source) != visited.end()) continue;
		visited.push_back(source);
		const auto owner = KernelPinEqueue(source);
		if (owner && owner->PollPendingSources(&sources)) return true;
	}
	return false;
}

int KYTY_SYSV_ABI KernelCreateEqueue(KernelEqueue* eq, const char* name) {
	PRINT_NAME();

	if (eq == nullptr || name == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	{
		Common::LockGuard lock(g_equeues_mutex);
		if (g_next_equeue > static_cast<uint64_t>(std::numeric_limits<KernelEqueue>::max())) {
			EXIT("event queue handle space exhausted\n");
		}
		*eq        = static_cast<KernelEqueue>(g_next_equeue++);
		auto owner = std::make_shared<KernelEqueuePrivate>(*eq);
		owner->SetName(std::string(name));
		g_equeues.emplace(*eq, std::move(owner));
	}

	LOGF("\tEqueue create: %s\n", name);

	return OK;
}

int KYTY_SYSV_ABI KernelAddEvent(KernelEqueue eq, const KernelEqueueEvent& event) {
	auto owner = KernelPinEqueue(eq);
	if (!owner) {
		return KERNEL_ERROR_EBADF;
	}

	return owner->AddEvent(event);
}

int KYTY_SYSV_ABI KernelTriggerEvent(KernelEqueue eq, uintptr_t ident, int16_t filter,
                                     void* trigger_data) {
	auto owner = KernelPinEqueue(eq);
	if (!owner) {
		return KERNEL_ERROR_EBADF;
	}

	return owner->TriggerEvent(ident, filter, trigger_data);
}

int KernelAddNativeNotificationEvent(KernelEqueue eq, const KernelEvent& original) {
	if (original.filter != KERNEL_EVFILT_NOTIFY ||
	    (original.flags != EV_ADD && original.flags != (EV_ADD | EV_ENABLE)) ||
	    original.fflags != 0 || original.data < 0 || original.data > 255)
		return KERNEL_ERROR_ENOSYS;
	KernelEqueueEvent event {};
	event.event = original;
	event.event.flags |= EV_CLEAR;
	event.event.data          = 0;
	event.filter.data         = reinterpret_cast<void*>(original.data);
	event.filter.trigger_func = NativeNotificationTrigger;
	event.filter.reset_func   = UserEventResetFunc;
	const int result          = KernelAddEvent(eq, event);
	if (result == OK) {
		LOGF("NATIVE_NOTIFICATION_FILTER_REGISTER pid=%d queue=%" PRId64 " ident=%" PRIuPTR
		     " filter=-19 selector=%" PRIdPTR " pending=0\n",
		     Process::GetPid(), eq, original.ident, original.data);
		Log::Flush();
	}
	return result;
}

int KYTY_SYSV_ABI KernelDeleteEvent(KernelEqueue eq, uintptr_t ident, int16_t filter) {
	auto owner = KernelPinEqueue(eq);
	if (!owner) {
		return KERNEL_ERROR_EBADF;
	}

	return owner->DeleteEvent(ident, filter);
}

int KYTY_SYSV_ABI KernelDeleteEqueue(KernelEqueue eq) {
	PRINT_NAME();

	KernelEqueueRef owner;

	{
		Common::LockGuard lock(g_equeues_mutex);
		const auto        entry = g_equeues.find(eq);
		if (entry == g_equeues.end()) {
			return KERNEL_ERROR_EBADF;
		}
		owner = std::move(entry->second);
		g_equeues.erase(entry);
	}

	LOGF("\tEqueue delete: %s\n", owner->GetName().c_str());
	owner->Close();

	return OK;
}

int KYTY_SYSV_ABI KernelWaitEqueue(KernelEqueue eq, KernelEvent* ev, int num, int* out,
                                   const KernelUseconds* timo) {
	PRINT_NAME();

	if (num < 1) {
		if (out != nullptr) *out = 0;
		return KERNEL_ERROR_EINVAL;
	}

	auto owner = KernelPinEqueue(eq);
	if (!owner) {
		if (out != nullptr) *out = 0;
		return KERNEL_ERROR_EBADF;
	}

	if (ev == nullptr) {
		if (out != nullptr) *out = 0;
		return KERNEL_ERROR_EFAULT;
	}

	EXIT_NOT_IMPLEMENTED(out == nullptr);

	LOGF("\tEqueue wait: %s, caller = 0x%016" PRIx64 ", eq = 0x%016" PRIx64 ", ev = 0x%016" PRIx64
	     ", num = %d, timo = %s, thread_id = %d\n",
	     owner->GetName().c_str(), reinterpret_cast<uint64_t>(__builtin_return_address(0)),
	     static_cast<uint64_t>(eq), reinterpret_cast<uint64_t>(ev), num,
	     (timo == nullptr ? "inf" : fmt::format("{}", *timo).c_str()),
	     Common::Thread::GetThreadIdUnique());

	const int received = timo == nullptr ? owner->WaitForEvents(ev, num, 0)
	                     : *timo == 0    ? owner->GetTriggeredEvents(ev, num)
	                                     : owner->WaitForEvents(ev, num, *timo);
	*out               = received < 0 ? 0 : received;
	if (received < 0) return received;
	if (*out == 0) {
		LOGF("\tEqueue wait timedout: %s\n", owner->GetName().c_str());
		return KERNEL_ERROR_ETIMEDOUT;
	}

	LOGF("\tEqueue wait received %u events: ident = 0x%016" PRIx64
	     ", filter = %d, flags = 0x%04" PRIx16 ", fflags = 0x%08" PRIx32 ", data = 0x%016" PRIx64
	     ", udata = 0x%016" PRIx64 "\n",
	     *out, static_cast<uint64_t>(ev[0].ident), ev[0].filter, ev[0].flags, ev[0].fflags,
	     static_cast<uint64_t>(ev[0].data), reinterpret_cast<uint64_t>(ev[0].udata));

	return OK;
}

int KYTY_SYSV_ABI KernelAddDynlibEvent(KernelEqueue eq, int id) {
	PRINT_NAME();

	LOGF("\t dynlib event add: eq = 0x%016" PRIx64 ", id = %d\n", static_cast<uint64_t>(eq), id);

	KernelEqueueEvent event {};
	event.event.ident  = static_cast<uintptr_t>(id);
	event.event.filter = KERNEL_EVFILT_DYNLIB;
	event.event.flags  = EV_ADD;

	return KernelAddEvent(eq, event);
}

int KYTY_SYSV_ABI KernelAddReadEvent(KernelEqueue eq, int fd, size_t size, void* udata) {
	PRINT_NAME();

	LOGF("\t read event add: eq = 0x%016" PRIx64 ", fd = %d, size = %" PRIu64
	     ", udata = 0x%016" PRIx64 "\n",
	     static_cast<uint64_t>(eq), fd, static_cast<uint64_t>(size),
	     reinterpret_cast<uint64_t>(udata));

	// a guest kqueue fd is readable while its queue has triggered events
	KernelEqueue watched_queue = KERNEL_EQUEUE_INVALID;
	if (LibKernel::FileSystem::ResolveNativeKqueueDescriptor(fd, &watched_queue)) {
		if (watched_queue == eq || size > 1) {
			return KERNEL_ERROR_EINVAL;
		}
		KernelEqueueEvent event {};
		event.event.ident    = static_cast<uintptr_t>(fd);
		event.event.filter   = KERNEL_EVFILT_READ;
		event.event.flags    = EV_ADD;
		event.event.fflags   = size == 1 ? NOTE_LOWAT : 0;
		event.event.udata    = udata;
		event.watched_kqueue = watched_queue;
		const int rc         = KernelAddEvent(eq, event);
		if (rc == OK) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_NESTED_KQUEUE_READ_REGISTERED"
			     " watching_queue=%" PRId64 " source_queue=%" PRId64 " source_guest_fd=%d\n",
			     eq, watched_queue, fd);
		}
		return rc;
	}
	if (auto inbox = LibKernel::FileSystem::PinNativeMbusReceiveQueue(fd)) {
		if (size > 1) return KERNEL_ERROR_EINVAL;
		KernelEqueueEvent event {};
		event.event.ident          = static_cast<uintptr_t>(fd);
		event.event.filter         = KERNEL_EVFILT_READ;
		event.event.flags          = EV_ADD;
		event.event.fflags         = size == 1 ? NOTE_LOWAT : 0;
		event.event.udata          = udata;
		event.watched_mbus_receive = std::move(inbox);
		const int rc               = KernelAddEvent(eq, event);
		if (rc == OK) {
			if (event.watched_mbus_receive->system) {
				LOGF("SYSTEM_MBUS_READ_FILTER_REGISTER guest_pid=%d source_fd=%d queue=%" PRId64
				     " queued_records=0\n",
				     Process::GetPid(), fd, eq);
				Log::Flush();
			}
			LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_MBUS_RX_READ_REGISTERED"
			     " source_guest_fd=%d destination_queue=%" PRId64 " RX_BUFFER_EMPTY\n",
			     fd, eq);
		}
		return rc;
	}
	auto guest_socket = FileSystem::PinGuestSocketReadSource(fd);
	if (guest_socket && size > static_cast<size_t>(INT64_MAX)) return KERNEL_ERROR_EINVAL;
	int64_t   pending = 0;
	bool      eof     = false;
	const int result  = guest_socket
	                        ? FileSystem::QueryGuestSocketReadSource(guest_socket, &pending, &eof)
	                        : Network::Net::SocketReadReady(fd, &pending, &eof);
	if (result < 0) {
		return guest_socket ? result : KERNEL_ERROR_UNKNOWN + *Posix::GetErrorAddr();
	}

	KernelEqueueEvent event {};
	event.event.ident          = static_cast<uintptr_t>(fd);
	event.event.filter         = KERNEL_EVFILT_READ;
	event.event.flags          = EV_ADD;
	event.event.fflags         = size != 0 ? NOTE_LOWAT : 0;
	event.event.udata          = udata;
	event.filter.data          = reinterpret_cast<void*>(size);
	event.watched_guest_socket = std::move(guest_socket);

	const int rc = KernelAddEvent(eq, event);
	if (rc == OK && event.watched_guest_socket) {
		LOGF("GUEST_SOCKET_READ_EVENT_REGISTERED guest_pid=%d fd=%d queue=%" PRId64
		     " pending=%" PRId64 " eof=%u lowat=%zu\n",
		     Process::GetPid(), fd, eq, pending, eof ? 1u : 0u, size);
		Log::Flush();
	}
	return rc;
}

int KYTY_SYSV_ABI KernelDeleteReadEvent(KernelEqueue eq, int fd) {
	PRINT_NAME();

	LOGF("\t read event delete: eq = 0x%016" PRIx64 ", fd = %d\n", static_cast<uint64_t>(eq), fd);

	return KernelDeleteEvent(eq, static_cast<uintptr_t>(fd), KERNEL_EVFILT_READ);
}

void KYTY_SYSV_ABI KernelDeleteReadEventForAll(int fd) {
	std::vector<KernelEqueueRef> queues;

	{
		Common::LockGuard lock(g_equeues_mutex);
		queues.reserve(g_equeues.size());
		for (const auto& [handle, queue]: g_equeues) {
			queues.push_back(queue);
		}
	}
	for (const auto& eq: queues) {
		eq->DeleteEvent(static_cast<uintptr_t>(fd), KERNEL_EVFILT_READ);
	}
}

int KYTY_SYSV_ABI KernelAddUserEvent(KernelEqueue eq, int id) {
	PRINT_NAME();

	LOGF("\t user event add: eq = 0x%016" PRIx64 ", id = %d\n", static_cast<uint64_t>(eq), id);

	KernelEqueueEvent event {};
	event.event.ident         = static_cast<uintptr_t>(id);
	event.event.filter        = KERNEL_EVFILT_USER;
	event.event.flags         = EV_ADD;
	event.event.fflags        = 0;
	event.event.data          = 0;
	event.event.udata         = nullptr;
	event.filter.trigger_func = UserEventTriggerFunc;
	event.filter.reset_func   = UserEventResetFunc;

	return KernelAddEvent(eq, event);
}

int KYTY_SYSV_ABI KernelAddUserEventEdge(KernelEqueue eq, int id) {
	PRINT_NAME();

	LOGF("\t user event edge add: eq = 0x%016" PRIx64 ", id = %d\n", static_cast<uint64_t>(eq), id);

	KernelEqueueEvent event {};
	event.event.ident         = static_cast<uintptr_t>(id);
	event.event.filter        = KERNEL_EVFILT_USER;
	event.event.flags         = EV_ADD | EV_CLEAR;
	event.event.fflags        = 0;
	event.event.data          = 0;
	event.event.udata         = nullptr;
	event.filter.trigger_func = UserEventTriggerFunc;
	event.filter.reset_func   = UserEventResetFunc;

	return KernelAddEvent(eq, event);
}

int KernelAddOriginalNativeUserEvent(KernelEqueue eq, const KernelEvent& original) {
	if (original.ident > INT32_MAX || original.filter != KERNEL_EVFILT_USER ||
	    original.flags != (EV_ADD | EV_CLEAR) || original.fflags != 0) {
		return KERNEL_ERROR_EINVAL;
	}
	KernelEqueueEvent event {};
	event.event               = original;
	event.filter.trigger_func = NativeOriginalUserEventTriggerFunc;
	event.filter.reset_func   = NativeUserEventReset;
	const int rc              = KernelAddEvent(eq, event);
	if (rc == OK) {
		LOGF("NATIVE_USER_EVENT_REGISTERED"
		     " queue=%" PRId64 " ident=%" PRIuPTR " flags=EV_ADD|EV_CLEAR data=%" PRIdPTR
		     " udata=0x%016" PRIxPTR " nothing_triggered\n",
		     eq, original.ident, original.data, reinterpret_cast<uintptr_t>(original.udata));
	}
	return rc;
}

// FreeBSD NOTE_EXIT and NOTE_EXEC, as seen in SceSysCore's process-watch request (0xa0000000).
constexpr uint32_t NATIVE_PROC_NOTE_EXIT = 0x80000000u;
constexpr uint32_t NATIVE_PROC_NOTE_EXEC = 0x20000000u;

struct NativeProcWatch {
	uint32_t subscribed = 0;
};

struct NativeProcNotification {
	uint32_t note;
	uint32_t exit_status;
};

static void NativeProcTrigger(KernelEqueueEvent* event, void* trigger_data) {
	EXIT_IF(event == nullptr);
	const auto* notification = static_cast<const NativeProcNotification*>(trigger_data);
	auto*       watch        = static_cast<NativeProcWatch*>(event->filter.data);
	if (notification == nullptr || watch == nullptr ||
	    (watch->subscribed & notification->note) == 0) {
		return;
	}
	event->triggered = true;
	event->event.fflags |= notification->note;
	if (notification->note == NATIVE_PROC_NOTE_EXIT) {
		event->event.data = notification->exit_status;
		event->event.flags |= EV_EOF | EV_ONESHOT;
	}
}

static void NativeProcReset(KernelEqueueEvent* event) {
	EXIT_IF(event == nullptr);
	event->triggered    = false;
	event->event.fflags = 0;
	event->event.data   = 0;
}

int KernelAddNativeProcEvent(KernelEqueue eq, const KernelEvent& original) {
	const bool shape_ok =
	    original.filter == KERNEL_EVFILT_PROC && original.flags == EV_ADD && original.fflags != 0 &&
	    (original.fflags & ~(NATIVE_PROC_NOTE_EXIT | NATIVE_PROC_NOTE_EXEC)) == 0 &&
	    original.data == 0 && original.udata == nullptr && original.ident != 0;
	const bool rfork_pid = shape_ok && original.ident <= INT32_MAX &&
	                       Process::IsTrackedRforkChild(static_cast<int>(original.ident));
	const bool kernel_pointer_dormant =
	    shape_ok && !rfork_pid && original.ident > INT32_MAX &&
	    std::getenv("KYTY_DIAGNOSTIC_SYSCORE_ACCEPT_KERNEL_POINTER_PROC_IDENTS") != nullptr;
	if (!rfork_pid && !kernel_pointer_dormant) {
		return KERNEL_ERROR_EINVAL;
	}
	KernelEqueueEvent event {};
	event.event               = original;
	event.event.fflags        = 0;
	auto watch                = std::make_shared<NativeProcWatch>();
	watch->subscribed         = original.fflags;
	event.filter.owner        = watch;
	event.filter.data         = watch.get();
	event.filter.trigger_func = NativeProcTrigger;
	event.filter.reset_func   = NativeProcReset;
	const int rc              = KernelAddEvent(eq, event);
	if (rc != OK) {
		return rc;
	}
	if (rfork_pid) {
		uint32_t real_exit_status = 0;
		// The child may have exited before the parent registered.
		if (Process::GetRforkChildExitStatus(static_cast<int>(original.ident), &real_exit_status)) {
			NativeProcNotification notification {NATIVE_PROC_NOTE_EXIT, real_exit_status};
			KernelTriggerEvent(eq, original.ident, KERNEL_EVFILT_PROC, &notification);
		}
		LOGF("SYSCORE_NATIVE_PROC_WATCH_REGISTERED queue=%" PRId64 " child_guest_pid=%" PRIuPTR
		     " filter=EVFILT_PROC flags=EV_ADD"
		     " subscribed_notes=0x%08x\n",
		     eq, original.ident, original.fflags);
		return OK;
	}
	LOGF("SYSCORE_KERNEL_POINTER_PROC_WATCH_DORMANT_NON_AUTHENTIC queue=%" PRId64
	     " ident=0x%016" PRIx64 " filter=EVFILT_PROC flags=EV_ADD"
	     " subscribed_notes=0x%08x\n",
	     eq, static_cast<uint64_t>(original.ident), original.fflags);
	return OK;
}

static void NotifyNativeProcForAll(int pid, uint32_t note, uint32_t exit_status) {
	NativeProcNotification       notification {note, exit_status};
	std::vector<KernelEqueueRef> queues;
	{
		Common::LockGuard lock(g_equeues_mutex);
		for (const auto& [handle, owner]: g_equeues) {
			(void)handle;
			queues.push_back(owner);
		}
	}
	for (const auto& owner: queues) {
		owner->TriggerEvent(static_cast<uintptr_t>(pid), KERNEL_EVFILT_PROC, &notification);
	}
}

void KernelNotifyNativeProcExitForAll(int pid, uint32_t exit_status) {
	NotifyNativeProcForAll(pid, NATIVE_PROC_NOTE_EXIT, exit_status);
}

void KernelNotifyNativeProcExecForAll(int pid) {
	NotifyNativeProcForAll(pid, NATIVE_PROC_NOTE_EXEC, 0);
}

int KYTY_SYSV_ABI KernelTriggerUserEvent(KernelEqueue eq, int id, void* udata) {
	PRINT_NAME();

	LOGF("\t user event trigger: eq = 0x%016" PRIx64 ", id = %d, udata = 0x%016" PRIx64 "\n",
	     static_cast<uint64_t>(eq), id, reinterpret_cast<uint64_t>(udata));

	return KernelTriggerEvent(eq, static_cast<uintptr_t>(id), KERNEL_EVFILT_USER, udata);
}

int KYTY_SYSV_ABI KernelTriggerUserEventForAll(int id, void* udata) {
	int                          triggered = 0;
	std::vector<KernelEqueueRef> queues;

	{
		Common::LockGuard lock(g_equeues_mutex);
		queues.reserve(g_equeues.size());
		for (const auto& [handle, queue]: g_equeues) {
			queues.push_back(queue);
		}
	}
	for (const auto& eq: queues) {
		if (eq->TriggerEvent(static_cast<uintptr_t>(id), KERNEL_EVFILT_USER, udata) == OK) {
			triggered++;
		}
	}

	return (triggered > 0 ? OK : KERNEL_ERROR_ENOENT);
}

int KYTY_SYSV_ABI KernelDeleteUserEvent(KernelEqueue eq, int id) {
	PRINT_NAME();

	LOGF("\t user event delete: eq = 0x%016" PRIx64 ", id = %d\n", static_cast<uint64_t>(eq), id);

	return KernelDeleteEvent(eq, static_cast<uintptr_t>(id), KERNEL_EVFILT_USER);
}

static int AddTimerEvent(KernelEqueue eq, int id, uint64_t delay_ns, bool periodic, void* udata) {
	const auto now_ns = MonotonicTimeNs();
	KernelEqueueEvent event {};
	event.deadline_ns  = delay_ns <= UINT64_MAX - now_ns ? now_ns + delay_ns : UINT64_MAX;
	event.interval_ns  = periodic ? delay_ns : 0;
	event.event.ident  = static_cast<uintptr_t>(id);
	event.event.filter = periodic ? KERNEL_EVFILT_TIMER : KERNEL_EVFILT_HRTIMER;
	event.event.flags  = EV_ADD | (periodic ? EV_CLEAR : EV_ONESHOT);
	event.event.udata  = udata;
	return KernelAddEvent(eq, event);
}

int KYTY_SYSV_ABI KernelAddTimerEvent(KernelEqueue eq, int id, KernelUseconds usec, void* udata) {
	return AddTimerEvent(eq, id, static_cast<uint64_t>(usec) * 1000, true, udata);
}

int KYTY_SYSV_ABI KernelAddHRTimerEvent(KernelEqueue eq, int id, const KernelTimespec* ts,
                                        void* udata) {
	if (ts == nullptr) {
		return KERNEL_ERROR_EFAULT;
	}
	if (ts->tv_sec < 0 || ts->tv_nsec < 0 || ts->tv_nsec >= 1000000000ll ||
	    static_cast<uint64_t>(ts->tv_sec) >
	        (UINT64_MAX - static_cast<uint64_t>(ts->tv_nsec)) / 1000000000ull) {
		return KERNEL_ERROR_EINVAL;
	}

	const auto delay_ns =
	    static_cast<uint64_t>(ts->tv_sec) * 1000000000ull + static_cast<uint64_t>(ts->tv_nsec);
	return AddTimerEvent(eq, id, delay_ns, false, udata);
}

int KYTY_SYSV_ABI KernelDeleteHRTimerEvent(KernelEqueue eq, int id) {
	return KernelDeleteEvent(eq, static_cast<uintptr_t>(id), KERNEL_EVFILT_HRTIMER);
}

int KYTY_SYSV_ABI KernelAddAmprEvent(KernelEqueue eq, int id, void* udata) {
	PRINT_NAME();

	LOGF("\t AMPR event add: eq = 0x%016" PRIx64 ", id = %d, udata = 0x%016" PRIx64 "\n",
	     static_cast<uint64_t>(eq), id, reinterpret_cast<uint64_t>(udata));

	if (eq != KERNEL_EQUEUE_INVALID) {
		KernelEqueueEvent event {};
		event.event.ident         = static_cast<uintptr_t>(id);
		event.event.filter        = KERNEL_EVFILT_AMPR;
		event.event.flags         = EV_ADD | EV_CLEAR;
		event.event.fflags        = 0;
		event.event.data          = 0;
		event.event.udata         = udata;
		event.filter.trigger_func = AmprEventTriggerFunc;
		event.filter.reset_func   = UserEventResetFunc;
		(void)KernelAddEvent(eq, event);
	}

	return OK;
}

int KYTY_SYSV_ABI KernelAddAmprSystemEvent(KernelEqueue eq, int id, void* udata) {
	PRINT_NAME();

	LOGF("\t AMPR system event add: eq = 0x%016" PRIx64 ", id = %d, udata = 0x%016" PRIx64 "\n",
	     static_cast<uint64_t>(eq), id, reinterpret_cast<uint64_t>(udata));

	return KernelAddAmprEvent(eq, id, udata);
}

int KYTY_SYSV_ABI KernelDeleteAmprEvent(KernelEqueue eq, int id) {
	PRINT_NAME();

	LOGF("\t AMPR event delete: eq = 0x%016" PRIx64 ", id = %d\n", static_cast<uint64_t>(eq), id);

	if (eq != KERNEL_EQUEUE_INVALID) {
		(void)KernelDeleteEvent(eq, static_cast<uintptr_t>(id), KERNEL_EVFILT_AMPR);
	}

	return OK;
}

int KYTY_SYSV_ABI KernelDeleteAmprSystemEvent(KernelEqueue eq, int id) {
	PRINT_NAME();

	LOGF("\t AMPR system event delete: eq = 0x%016" PRIx64 ", id = %d\n", static_cast<uint64_t>(eq),
	     id);

	return KernelDeleteAmprEvent(eq, id);
}

intptr_t KYTY_SYSV_ABI KernelGetEventData(const KernelEvent* ev) {
	PRINT_NAME();

	if (ev != nullptr) {
		return ev->data;
	}

	return 0;
}

intptr_t KYTY_SYSV_ABI KernelGetEventFflags(const KernelEvent* ev) {
	PRINT_NAME();

	if (ev != nullptr) {
		return ev->fflags;
	}

	return 0;
}

int KYTY_SYSV_ABI KernelGetEventFilter(const KernelEvent* ev) {
	PRINT_NAME();

	if (ev != nullptr) {
		return ev->filter;
	}

	return 0;
}

uintptr_t KYTY_SYSV_ABI KernelGetEventId(const KernelEvent* ev) {
	PRINT_NAME();

	if (ev != nullptr) {
		return ev->ident;
	}

	return 0;
}

void* KYTY_SYSV_ABI KernelGetEventUserData(const KernelEvent* ev) {
	PRINT_NAME();

	if (ev != nullptr) {
		return ev->udata;
	}

	return nullptr;
}

int KYTY_SYSV_ABI KernelGetEventError(const KernelEvent* ev) {
	PRINT_NAME();

	if (ev != nullptr && (ev->flags & EV_ERROR) != 0) {
		return static_cast<int>(ev->data);
	}

	return 0;
}

} // namespace Libs::LibKernel::EventQueue
