#include "kernel/eventFlag.h"

#include "common/assert.h"
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
	static constexpr uint32_t MaxFlags   = 128;
	static constexpr uint32_t MaxWaiters = 64;
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

EventFlagWaitMode DecodeEventFlagWaitMode(uint32_t wait_mode) {
	EventFlagWaitMode mode;

	switch (wait_mode & 0xfu) {
		case 0x01: mode.wait = KernelEventFlagPrivate::WaitMode::And; break;
		case 0x02: mode.wait = KernelEventFlagPrivate::WaitMode::Or; break;
		default: EXIT("unknown mode: %u\n", wait_mode);
	}

	switch (wait_mode & 0xf0u) {
		case 0x00: mode.clear = KernelEventFlagPrivate::ClearMode::None; break;
		case 0x10: mode.clear = KernelEventFlagPrivate::ClearMode::All; break;
		case 0x20: mode.clear = KernelEventFlagPrivate::ClearMode::Bits; break;
		default: EXIT("unknown mode: %u\n", wait_mode);
	}

	return mode;
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

KernelEventFlagPrivate::Result KernelEventFlagPrivate::Wait(uint64_t bits, WaitMode wait_mode,
                                                            ClearMode clear_mode, uint64_t* result,
                                                            uint32_t* ptr_micros) {
	Common::LockGuard lock(m_mutex);

	uint32_t micros     = 0;
	bool     infinitely = true;
	if (ptr_micros != nullptr) {
		micros     = *ptr_micros;
		infinitely = false;
	}

	uint32_t      elapsed = 0;
	Common::Timer t;
	t.Start();

	auto update_timeout = [&]() {
		if (ptr_micros != nullptr) {
			*ptr_micros = (elapsed >= micros ? 0 : micros - elapsed);
		}
	};

	if (m_single_thread && m_waiting_threads > 0) {
		return Result::AlreadyWaiting;
	}

	while (!((wait_mode == WaitMode::And && (m_bits & bits) == bits) ||
	         (wait_mode == WaitMode::Or && (m_bits & bits) != 0))) {
		if ((elapsed >= micros && !infinitely)) {
			if (result != nullptr) {
				*result = m_bits;
			}
			update_timeout();
			return Result::TimedOut;
		}

		m_waiting_threads++;

		if (infinitely) {
			m_cond_var.Wait(&m_mutex);
		} else {
			m_cond_var.WaitFor(&m_mutex, micros - elapsed);
		}

		m_waiting_threads--;

		elapsed = static_cast<uint32_t>(t.GetTimeS() * 1000000.0);

		switch (m_status) {
			case Status::Canceled:
				if (result != nullptr) {
					*result = m_bits;
				}
				update_timeout();
				return Result::Canceled;
			case Status::Deleted:
				if (result != nullptr) {
					*result = m_bits;
				}
				update_timeout();
				return Result::Deleted;
			case Status::Set: break;
		}
	}

	if (result != nullptr) {
		*result = m_bits;
	}
	update_timeout();

	switch (clear_mode) {
		case ClearMode::All: m_bits = 0; break;
		case ClearMode::Bits: m_bits &= ~bits; break;
		case ClearMode::None: break;
	}

	return Result::Ok;
}

void KernelEventFlagPrivate::Set(uint64_t bits) {
	Common::LockGuard lock(m_mutex);

	EXIT_NOT_IMPLEMENTED(m_status == Status::Deleted);

	while (m_status != Status::Set) {
		m_mutex.Unlock();
		Common::Thread::SleepMicro(10);
		m_mutex.Lock();
	}

	m_bits |= bits;

	m_cond_var.SignalAll();
}

void KernelEventFlagPrivate::Clear(uint64_t bits) {
	Common::LockGuard lock(m_mutex);

	EXIT_NOT_IMPLEMENTED(m_status == Status::Deleted);

	while (m_status != Status::Set) {
		m_mutex.Unlock();
		Common::Thread::SleepMicro(10);
		m_mutex.Lock();
	}

	m_bits &= bits;
}

void KernelEventFlagPrivate::Cancel(uint64_t bits, int* num_waiting_threads) {
	Common::LockGuard lock(m_mutex);

	EXIT_NOT_IMPLEMENTED(m_status == Status::Deleted);

	while (m_status != Status::Set) {
		m_mutex.Unlock();
		Common::Thread::SleepMicro(10);
		m_mutex.Lock();
	}

	if (num_waiting_threads != nullptr) {
		*num_waiting_threads = m_waiting_threads;
	}

	m_status = Status::Canceled;
	m_bits   = bits;

	m_cond_var.SignalAll();

	while (m_waiting_threads > 0) {
		m_mutex.Unlock();
		Common::Thread::SleepMicro(10);
		m_mutex.Lock();
	}

	m_status = Status::Set;
}

int KYTY_SYSV_ABI KernelCreateEventFlag(KernelEventFlag* ef, const char* name, uint32_t attr,
                                        uint64_t init_pattern, const void* param) {
	PRINT_NAME();

	if (ef == nullptr || name == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	if (param != nullptr || (attr & ~0x33u) != 0) {
		return KERNEL_ERROR_EINVAL;
	}

	bool single = true;
	bool fifo   = true;

	switch (attr & 0x0fu) {
		case 0x00:
		case 0x01: fifo = true; break;
		case 0x02: fifo = false; break;
		default: return KERNEL_ERROR_EINVAL;
	}

	switch (attr & 0xf0u) {
		case 0x00:
		case 0x10: single = true; break;
		case 0x20: single = false; break;
		default: return KERNEL_ERROR_EINVAL;
	}

	*ef = new KernelEventFlagPrivate(std::string(name), single, fifo, init_pattern);

	LOGF("\tEventFlag create: %s\n", name);

	return OK;
}

int KYTY_SYSV_ABI KernelDeleteEventFlag(KernelEventFlag ef) {
	PRINT_NAME();

	if (ef == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}

	delete ef;

	return OK;
}

int KYTY_SYSV_ABI KernelWaitEventFlag(KernelEventFlag ef, uint64_t bit_pattern, uint32_t wait_mode,
                                      uint64_t* result_pat, KernelUseconds* timeout) {
	PRINT_NAME();

	if (ef == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}

	if (bit_pattern == 0) {
		return KERNEL_ERROR_EINVAL;
	}

	const auto mode   = DecodeEventFlagWaitMode(wait_mode);
	auto       result = ef->Wait(bit_pattern, mode.wait, mode.clear, result_pat, timeout);

	int ret = OK;

	switch (result) {
		case KernelEventFlagPrivate::Result::Ok: ret = OK; break;
		case KernelEventFlagPrivate::Result::AlreadyWaiting: ret = KERNEL_ERROR_EPERM; break;
		case KernelEventFlagPrivate::Result::TimedOut: ret = KERNEL_ERROR_ETIMEDOUT; break;
		case KernelEventFlagPrivate::Result::Canceled: ret = KERNEL_ERROR_ECANCELED; break;
		case KernelEventFlagPrivate::Result::Deleted: ret = KERNEL_ERROR_EACCES; break;
	}

	return ret;
}

int KYTY_SYSV_ABI KernelPollEventFlag(KernelEventFlag ef, uint64_t bit_pattern, uint32_t wait_mode,
                                      uint64_t* result_pat) {
	PRINT_NAME();

	if (ef == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}

	if (bit_pattern == 0) {
		return KERNEL_ERROR_EINVAL;
	}

	const auto mode   = DecodeEventFlagWaitMode(wait_mode);
	auto       result = ef->Poll(bit_pattern, mode.wait, mode.clear, result_pat);

	int ret = OK;

	switch (result) {
		case KernelEventFlagPrivate::Result::Ok: ret = OK; break;
		case KernelEventFlagPrivate::Result::AlreadyWaiting: ret = KERNEL_ERROR_EPERM; break;
		case KernelEventFlagPrivate::Result::TimedOut:
		case KernelEventFlagPrivate::Result::Canceled:
		case KernelEventFlagPrivate::Result::Deleted: ret = KERNEL_ERROR_EBUSY; break;
	}

	return ret;
}

int KYTY_SYSV_ABI KernelSetEventFlag(KernelEventFlag ef, uint64_t bit_pattern) {
	PRINT_NAME();

	if (ef == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}

	ef->Set(bit_pattern);

	return OK;
}

int KYTY_SYSV_ABI KernelClearEventFlag(KernelEventFlag ef, uint64_t bit_pattern) {
	PRINT_NAME();

	if (ef == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}

	ef->Clear(bit_pattern);

	return OK;
}

int KYTY_SYSV_ABI KernelCancelEventFlag(KernelEventFlag ef, uint64_t set_pattern,
                                        int* num_wait_threads) {
	PRINT_NAME();

	if (ef == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}

	ef->Cancel(set_pattern, num_wait_threads);

	return OK;
}

} // namespace Libs::LibKernel::EventFlag
