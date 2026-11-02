#include "libs/nativeSyscallGuards.h"
#include "kernel/eventQueue.h"
#include "kernel/fileSystem.h"
#include "kernel/memory.h"
#include "common/abi.h"
#include "common/logging/log.h"
#include "libs/errno.h"
#include "libs/libs.h"
#include "libs/nativeKernelBridge.h"
#include "loader/symbolDatabase.h"
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <inttypes.h>

namespace Libs::NativeSyscallGuards {
// keep directly-imported 13.60 syscall wrapper NIDs off the Windows kernel with ENOSYS
template <uint64_t Number>
static int64_t KYTY_SYSV_ABI Unsupported(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                                         uint64_t a4, uint64_t a5) {
	static std::atomic<uint32_t> calls {0};
	if (calls.fetch_add(1) < 15) {
		LOGF("PS5_NATIVE_SYSCALL_GUARD id=0x%016" PRIx64 " args=%016" PRIx64 ",%016" PRIx64
		     ",%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64 " ENOSYS\n",
		     Number, a0, a1, a2, a3, a4, a5);
	}
	// A failed syscall leaves the firmware wrappers through cerror (libkernel +0xd4): errno takes
	// the code and rax is -1.
	*Posix::GetErrorAddr() = Posix::POSIX_ENOSYS;
	return -1;
}
// libkernel_sys 0x46c30 and 0x46aa0: raw 609/571, then 0x80020000|errno on failure; get
// sign-extends the 32-bit id into *out only on success.
int KYTY_SYSV_ABI KernelGetBudget(int64_t* out) {
	const auto reply = NativeKernelBridge::DispatchSyscall({0x261, {}});
	if (reply.value < 0) {
		*Posix::GetErrorAddr() = LibKernel::KernelToPosix(static_cast<int>(reply.value));
		return static_cast<int>(reply.value);
	}
	*out = static_cast<int32_t>(reply.value);
	return 0;
}
int KYTY_SYSV_ABI KernelSetBudget(int id) {
	const auto reply = NativeKernelBridge::DispatchSyscall(
	    {0x23b, {static_cast<uint64_t>(static_cast<int64_t>(id))}});
	if (reply.value < 0) {
		*Posix::GetErrorAddr() = LibKernel::KernelToPosix(static_cast<int>(reply.value));
		return static_cast<int>(reply.value);
	}
	return 0;
}
static int64_t KYTY_SYSV_ABI OriginalSyscoreKevent(uint64_t fd, uint64_t changelist,
                                                   uint64_t nchanges, uint64_t eventlist,
                                                   uint64_t nevents, uint64_t timeout) {
	if (fd <= INT32_MAX && changelist == 0 && nchanges == 0 && eventlist != 0 && nevents == 1) {
		LibKernel::KernelUseconds micros = 0;
		if (timeout != 0) {
			LibKernel::KernelTimespec value {};
			if (!LibKernel::Memory::CopyFromGuest(&value, reinterpret_cast<const void*>(timeout),
			                                      sizeof(value))) {
				*Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
				return -1;
			}
			if (value.tv_sec < 0 || value.tv_sec > UINT32_MAX / 1000000 || value.tv_nsec < 0 ||
			    value.tv_nsec >= 1000000000) {
				*Posix::GetErrorAddr() = Posix::POSIX_EINVAL;
				return -1;
			}
			const uint64_t total = static_cast<uint64_t>(value.tv_sec) * 1000000 +
			                       (static_cast<uint64_t>(value.tv_nsec) + 999) / 1000;
			if (total > UINT32_MAX) {
				*Posix::GetErrorAddr() = Posix::POSIX_EINVAL;
				return -1;
			}
			micros = static_cast<LibKernel::KernelUseconds>(total);
		}
		LibKernel::Memory::VirtualQueryInfo destination {};
		if (eventlist > UINT64_MAX - sizeof(LibKernel::EventQueue::KernelEvent) ||
		    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(eventlist), 0,
		                                          &destination, sizeof(destination)) != 0 ||
		    !destination.is_committed || destination.start > eventlist ||
		    destination.end < eventlist + sizeof(LibKernel::EventQueue::KernelEvent) ||
		    (destination.protection & 2u) == 0) {
			*Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
			return -1;
		}
		int64_t queue = 0;
		if (!LibKernel::FileSystem::ResolveNativeKqueueDescriptor(static_cast<int>(fd), &queue)) {
			*Posix::GetErrorAddr() = Posix::POSIX_EBADF;
			return -1;
		}
		static std::atomic<uint32_t> wait_count {0};
		if (wait_count.fetch_add(1) < 8) {
			LOGF("SYSCORE_PROC_MONITOR_KEVENT_WAIT fd=%" PRIu64 " queue=%" PRId64
			     " timeout_pointer=%u timeout_us=%u\n",
			     fd, queue, timeout != 0, micros);
			Log::Flush();
		}
		int                                received = 0;
		LibKernel::EventQueue::KernelEvent event {};
		const int rc = LibKernel::EventQueue::KernelWaitEqueue(queue, &event, 1, &received,
		                                                       timeout != 0 ? &micros : nullptr);
		if (rc == LibKernel::KERNEL_ERROR_ETIMEDOUT) {
			return 0;
		}
		if (rc != 0) {
			*Posix::GetErrorAddr() = LibKernel::KernelToPosix(rc);
			return -1;
		}
		event.flags &= 0xfef0u;
		if (received != 0 && !LibKernel::Memory::CopyToGuest(reinterpret_cast<void*>(eventlist),
		                                                     &event, sizeof(event))) {
			*Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
			return -1;
		}
		return received;
	}
	if (fd > INT32_MAX || changelist == 0 || nchanges != 1 || eventlist != 0 || nevents != 0 ||
	    timeout != 0) {
		return Unsupported<0x16b>(fd, changelist, nchanges, eventlist, nevents, timeout);
	}
	LibKernel::Memory::VirtualQueryInfo memory {};
	if (changelist > UINT64_MAX - sizeof(LibKernel::EventQueue::KernelEvent) ||
	    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(changelist), 0, &memory,
	                                          sizeof(memory)) != 0 ||
	    !memory.is_committed || memory.start > changelist ||
	    memory.end < changelist + sizeof(LibKernel::EventQueue::KernelEvent) ||
	    (memory.protection & 1u) == 0) {
		*Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
		return -1;
	}
	LibKernel::EventQueue::KernelEvent event {};
	if (!LibKernel::Memory::CopyFromGuest(&event, reinterpret_cast<const void*>(changelist),
	                                      sizeof(event))) {
		*Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
		return -1;
	}
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD") != nullptr) {
		static std::atomic<uint32_t> observed {0};
		if (observed.fetch_add(1) < 16) {
			LOGF("SYSCORE_RFORK_KEVENT_CHANGE_AUDIT"
			     " fd=%" PRIu64 " ident=%" PRIu64 " filter=%d flags=0x%04x fflags=0x%08x"
			     " data=%" PRIdPTR " udata=0x%016" PRIx64 "\n",
			     fd, static_cast<uint64_t>(event.ident), event.filter, event.flags, event.fflags,
			     event.data, reinterpret_cast<uint64_t>(event.udata));
		}
	}
	if ((event.filter == LibKernel::EventQueue::KERNEL_EVFILT_READ && event.flags == 1 &&
	     event.fflags == 0 && event.data == 0 && event.ident <= INT32_MAX) ||
	    event.filter == LibKernel::EventQueue::KERNEL_EVFILT_NOTIFY) {
		int64_t queue = 0;
		if (!LibKernel::FileSystem::ResolveNativeKqueueDescriptor(static_cast<int>(fd), &queue)) {
			*Posix::GetErrorAddr() = Posix::POSIX_EBADF;
			return -1;
		}
		const int rc = event.filter == LibKernel::EventQueue::KERNEL_EVFILT_READ
		                   ? LibKernel::EventQueue::KernelAddReadEvent(
		                         queue, static_cast<int>(event.ident), 0, event.udata)
		                   : LibKernel::EventQueue::KernelAddNativeNotificationEvent(queue, event);
		if (rc != 0) {
			*Posix::GetErrorAddr() = LibKernel::KernelToPosix(rc);
			return -1;
		}
		return 0;
	}
	if (event.filter == LibKernel::EventQueue::KERNEL_EVFILT_PROC &&
	    std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD") != nullptr) {
		int64_t queue = 0;
		if (!LibKernel::FileSystem::ResolveNativeKqueueDescriptor(static_cast<int>(fd), &queue)) {
			*Posix::GetErrorAddr() = Posix::POSIX_EBADF;
			return -1;
		}
		const int rc = LibKernel::EventQueue::KernelAddNativeProcEvent(queue, event);
		if (rc != 0) {
			*Posix::GetErrorAddr() = LibKernel::KernelToPosix(rc);
			return -1;
		}
		return 0;
	}
	if (event.ident != 0 || event.filter != LibKernel::EventQueue::KERNEL_EVFILT_USER ||
	    event.flags != 0x21 || event.fflags != 0 || event.data != 0 || event.udata != nullptr) {
		return Unsupported<0x16b>(fd, changelist, nchanges, eventlist, nevents, timeout);
	}
	int64_t queue = 0;
	if (!LibKernel::FileSystem::ResolveNativeKqueueDescriptor(static_cast<int>(fd), &queue)) {
		*Posix::GetErrorAddr() = Posix::POSIX_EBADF;
		return -1;
	}
	const int result = LibKernel::EventQueue::KernelAddUserEventEdge(queue, 0);
	if (result != 0) {
		*Posix::GetErrorAddr() = Posix::POSIX_EINVAL;
		return -1;
	}
	LOGF("SYSCORE_PROC_MONITOR_EV_REGISTER fd=%" PRIu64 " queue=%" PRId64
	     " ident=0 filter=EVFILT_USER flags=EV_ADD|EV_CLEAR"
	     "\n",
	     fd, queue);
	return 0;
}
} // namespace Libs::NativeSyscallGuards
