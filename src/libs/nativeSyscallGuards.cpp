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
LIB_VERSION("libkernel", 1, "libkernel", 1, 1);
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

static int KYTY_SYSV_ABI DevToolLogNosys(uint64_t, uint64_t, uint64_t) {
	static std::atomic_uint32_t calls {0};
	if (calls.fetch_add(1) < 4) {
		LOGF("DEVTOOLLOG_RETAIL_NOSYS syscall=573 wrapper_result=8001ffff errno=78\n");
	}
	*Posix::GetErrorAddr() = Posix::POSIX_ENOSYS;
	return LibKernel::KERNEL_ERROR_UNKNOWN - 1;
}

static int KYTY_SYSV_ABI KernelFstatfs(int fd, LibKernel::FileSystem::KernelStatfs* output) {
	const int result = LibKernel::FileSystem::KernelFstatfs(fd, output);
	if (result == 0) return 0;
	*Posix::GetErrorAddr() = LibKernel::KernelToPosix(result);
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

// libkernel_sys 0x447c0: raw 652 retried on EINTR, then 0x80020000|errno
static int KYTY_SYSV_ABI KernelTerminateProcess(int pid, int* status) {
	const auto reply = NativeKernelBridge::DispatchSyscall(
	    {0x28c, {static_cast<uint64_t>(static_cast<int64_t>(pid)), reinterpret_cast<uint64_t>(status)}});
	if (reply.value < 0) {
		*Posix::GetErrorAddr() = LibKernel::KernelToPosix(static_cast<int>(reply.value));
		return static_cast<int>(reply.value);
	}
	return 0;
}

static int KYTY_SYSV_ABI GetSelfAuthInfo(const char* path, void* output) {
	const auto reply = NativeKernelBridge::DispatchSyscall(
	    {0x25f, {reinterpret_cast<uint64_t>(path), reinterpret_cast<uint64_t>(output)}});
	if (reply.value != 0) {
		*Posix::GetErrorAddr() = reply.posix_errno != 0
		                             ? reply.posix_errno
		                             : LibKernel::KernelToPosix(static_cast<int>(reply.value));
		return -1;
	}
	return 0;
}

// The app spawn trampoline (SceSysCore 0x900018880) sets up the child sandbox with high wrappers no
// daemon uses. Routed to nativeKernelBridge.cpp like KernelGetBudget so NPXS40087 reaches execve.
// NIDs from SceSysCore.elf's PLT.
static int64_t KYTY_SYSV_ABI AppSandboxPath(uint64_t a0, uint64_t, uint64_t, uint64_t, uint64_t,
                                            uint64_t) {
	const auto reply = NativeKernelBridge::DispatchSyscall({0x258, {a0}});
	if (reply.value < 0) {
		*Posix::GetErrorAddr() = reply.posix_errno != 0
		                             ? reply.posix_errno
		                             : LibKernel::KernelToPosix(static_cast<int>(reply.value));
		return -1;
	}
	return reply.value;
}

static int64_t KYTY_SYSV_ABI AppRandomizedPath(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t,
                                               uint64_t, uint64_t) {
	const auto reply = NativeKernelBridge::DispatchSyscall({0x25a, {a0, a1, a2}});
	if (reply.value < 0) {
		*Posix::GetErrorAddr() = reply.posix_errno != 0
		                             ? reply.posix_errno
		                             : LibKernel::KernelToPosix(static_cast<int>(reply.value));
		return -1;
	}
	return reply.value;
}

static int64_t KYTY_SYSV_ABI AppIsInSandbox(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                            uint64_t) {
	const auto reply = NativeKernelBridge::DispatchSyscall({0x249, {}});
	if (reply.value < 0) {
		*Posix::GetErrorAddr() = reply.posix_errno != 0
		                             ? reply.posix_errno
		                             : LibKernel::KernelToPosix(static_cast<int>(reply.value));
		return -1;
	}
	return reply.value;
}

static int64_t KYTY_SYSV_ABI AppBudgetGetPtype(uint64_t a0, uint64_t, uint64_t, uint64_t, uint64_t,
                                               uint64_t) {
	const auto reply = NativeKernelBridge::DispatchSyscall({0x262, {a0}});
	if (reply.value < 0) {
		*Posix::GetErrorAddr() = reply.posix_errno != 0
		                             ? reply.posix_errno
		                             : LibKernel::KernelToPosix(static_cast<int>(reply.value));
		return -1;
	}
	return reply.value;
}

static int64_t KYTY_SYSV_ABI AppChdir(uint64_t a0, uint64_t, uint64_t, uint64_t, uint64_t,
                                      uint64_t) {
	const auto reply = NativeKernelBridge::DispatchSyscall({0xc, {a0}});
	if (reply.value < 0) {
		*Posix::GetErrorAddr() = reply.posix_errno != 0
		                             ? reply.posix_errno
		                             : LibKernel::KernelToPosix(static_cast<int>(reply.value));
		return -1;
	}
	return reply.value;
}

static int64_t KYTY_SYSV_ABI AppChroot(uint64_t a0, uint64_t, uint64_t, uint64_t, uint64_t,
                                       uint64_t) {
	const auto reply = NativeKernelBridge::DispatchSyscall({0x3d, {a0}});
	if (reply.value < 0) {
		*Posix::GetErrorAddr() = reply.posix_errno != 0
		                             ? reply.posix_errno
		                             : LibKernel::KernelToPosix(static_cast<int>(reply.value));
		return -1;
	}
	return reply.value;
}

// 603 sys_rdup on the two fds from the child arg struct, like the bridge's rdup path minus its env
// gate
static int64_t KYTY_SYSV_ABI AppRdup(uint64_t a0, uint64_t a1, uint64_t, uint64_t, uint64_t,
                                     uint64_t) {
	if (a0 > INT32_MAX || a1 > INT32_MAX) {
		*Posix::GetErrorAddr() = Posix::POSIX_EBADF;
		return -1;
	}
	const int fd = LibKernel::FileSystem::DuplicateParentSocketForRdup(static_cast<int>(a0),
	                                                                   static_cast<int>(a1));
	LOGF("SYSCORE_APP_SPAWN rdup a0=%d a1=%d result=%d\n", static_cast<int>(a0),
	     static_cast<int>(a1), fd);
	if (fd < 0) {
		*Posix::GetErrorAddr() = LibKernel::KernelToPosix(fd);
		return -1;
	}
	return fd;
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

static int64_t KYTY_SYSV_ABI OriginalSyscoreRdup(uint64_t parent_pid, uint64_t source_fd, uint64_t,
                                                 uint64_t, uint64_t, uint64_t) {
	if (parent_pid > INT32_MAX || source_fd > INT32_MAX) {
		*Posix::GetErrorAddr() = Posix::POSIX_EBADF;
		return -1;
	}
	const int fd = LibKernel::FileSystem::DuplicateParentSocketForRdup(static_cast<int>(parent_pid),
	                                                                   static_cast<int>(source_fd));
	if (fd < 0) {
		*Posix::GetErrorAddr() = LibKernel::KernelToPosix(fd);
		return -1;
	}
	return fd;
}

static int64_t KYTY_SYSV_ABI OriginalSyscoreSocketPair(uint64_t domain, uint64_t type,
                                                       uint64_t protocol, uint64_t output,
                                                       uint64_t arg4, uint64_t arg5) {
	if (domain != 1 || type != 1 || protocol != 0) {
		return Unsupported<0x87>(domain, type, protocol, output, arg4, arg5);
	}
	LibKernel::Memory::VirtualQueryInfo memory {};
	if (output == 0 || output > UINT64_MAX - sizeof(int32_t) * 2 ||
	    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(output), 0, &memory,
	                                          sizeof(memory)) != 0 ||
	    !memory.is_committed || memory.start > output ||
	    memory.end < output + sizeof(int32_t) * 2 || (memory.protection & 2u) == 0) {
		*Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
		return -1;
	}
	LibKernel::Memory::InvalidateMemory(output, sizeof(int32_t) * 2);
	const int result =
	    LibKernel::FileSystem::CreateGuestSocketPair(reinterpret_cast<int32_t*>(output));
	if (result != 0) {
		*Posix::GetErrorAddr() = Posix::POSIX_EINVAL;
		return -1;
	}
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LAUNCH_TRACE") != nullptr) {
		const auto* actual_fds = reinterpret_cast<const int32_t*>(output);
		LOGF("SYSCORE_SOCKETPAIR_GUEST_CALLER return=%p"
		     " domain=%" PRIu64 " type=%" PRIu64 " protocol=%" PRIu64 " output=%016" PRIx64
		     " fd0=%d fd1=%d\n",
		     __builtin_return_address(0), domain, type, protocol, output, actual_fds[0],
		     actual_fds[1]);
	}
	return 0;
}

LIB_DEFINE(Register) {
	{
		constexpr char g_library[] = "libkernel_devtoollog";
		LIB_FUNC("ilQLkGlAjWA", DevToolLogNosys);
		LIB_FUNC("W7Vpt62Xtf4", DevToolLogNosys);
		LIB_FUNC("JFpAREOJnag", DevToolLogNosys);
	}
	LIB_FUNC("OX9wtyjVAJY", KernelGetBudget);
	LIB_FUNC("nzuKTmqQFXY", KernelSetBudget);
	LIB_FUNC("VinlCA8Vkg8", KernelTerminateProcess);
	LIB_FUNC("7KuwdAt0kQQ", Unsupported<0x23d>);
	// app spawn trampoline pre-execve sandbox wrappers; the daemon trampoline doesn't call them
	LIB_FUNC("ASVb7Y-pR4Y", AppSandboxPath);    // 600 sys_sandbox_path
	LIB_FUNC("p2suRCR4KqE", AppRandomizedPath); // 602 sys_randomized_path (set form)
	LIB_FUNC("LxIacrWiJ3w", AppRdup);           // 603 sys_rdup
	LIB_FUNC("xeu-pV8wkKs", AppIsInSandbox);    // 585 sys_is_in_sandbox
	LIB_FUNC("+g+UP8Pyfmo", AppBudgetGetPtype); // 610 sys_budget_get_ptype
	LIB_FUNC("6mMQ1MSPW-Q", AppChdir);          // 12 chdir
	LIB_FUNC("AKknh8Cx-V8", AppChroot);         // 61 chroot
	LIB_FUNC("n371J5cP+uo", LibKernel::FileSystem::KernelPhyshmOpen);
	LIB_FUNC("+rWFNYiNaEM", KernelFstatfs);
	LIB_FUNC("17Mfe1B3X6U", KernelFstatfs);
	if (std::getenv("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS") == nullptr) {
		if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_EQUEUE_FD") != nullptr) {
			LIB_FUNC("RW-GEfpnsqg", OriginalSyscoreKevent);
			LIB_FUNC("MZb0GKT3mo8", OriginalSyscoreSocketPair);
		}
		return;
	}
	LIB_FUNC("6mMQ1MSPW-Q", Unsupported<0xc>);
	LIB_FUNC("gnyVA6Tj-ak", Unsupported<0xd>);
	LIB_FUNC("+2HAuc7yVbc", Unsupported<0x10>);
	LIB_FUNC("dmfMGDoshB4", Unsupported<0x15>);
	LIB_FUNC("tpThrBsInto", Unsupported<0x16>);
	LIB_FUNC("JVmUZwK-HJU", Unsupported<0x17>);
	LIB_FUNC("kg4x8Prhfxw", Unsupported<0x18>);
	LIB_FUNC("tvpHe5kBO4E", Unsupported<0x19>);
	LIB_FUNC("PcKApW9kVoQ", Unsupported<0x1b>);
	LIB_FUNC("+L22kkFiXok", Unsupported<0x1c>);
	LIB_FUNC("gPcQ3OrFBUA", Unsupported<0x1d>);
	LIB_FUNC("B+zfF7bMswI", Unsupported<0x1e>);
	LIB_FUNC("TXFFFiNldU8", Unsupported<0x1f>);
	LIB_FUNC("rTNM7adVYog", Unsupported<0x1f>);
	LIB_FUNC("6Gwl39KKUEI", Unsupported<0x20>);
	LIB_FUNC("8vE6Z6VEYyk", Unsupported<0x21>);
	LIB_FUNC("ixrw0h2tWuI", Unsupported<0x22>);
	LIB_FUNC("UJrQCyYpyic", Unsupported<0x23>);
	LIB_FUNC("Y2OqwJQ3lr8", Unsupported<0x24>);
	LIB_FUNC("W0xkN0+ZkCE", Unsupported<0x25>);
	LIB_FUNC("e6ovBo9ZvJc", Unsupported<0x27>);
	LIB_FUNC("iiQjzvfWDq0", Unsupported<0x29>);
	LIB_FUNC("72rYuYoDTWk", Unsupported<0x2b>);
	LIB_FUNC("CpF21FIEKVQ", Unsupported<0x2c>);
	LIB_FUNC("3IO4pYlBzGU", Unsupported<0x2d>);
	LIB_FUNC("AfuS23bX6kg", Unsupported<0x2f>);
	LIB_FUNC("GCpDdYK0M6U", Unsupported<0x32>);
	LIB_FUNC("sHziAegVp74", Unsupported<0x35>);
	LIB_FUNC("gJZRi5WuXZI", Unsupported<0x37>);
	LIB_FUNC("jEWIILUU0vA", Unsupported<0x38>);
	LIB_FUNC("waIF+5fE5HQ", Unsupported<0x39>);
	LIB_FUNC("-3nj+K1elI0", Unsupported<0x3b>);
	LIB_FUNC("kdguLiAheLI", Unsupported<0x3b>);
	LIB_FUNC("AKknh8Cx-V8", Unsupported<0x3d>);
	LIB_FUNC("Jahsnh4KKkg", Unsupported<0x4b>);
	LIB_FUNC("+hFjyohmOU0", Unsupported<0x4e>);
	LIB_FUNC("3yjZbSvan2g", Unsupported<0x4f>);
	LIB_FUNC("M8VZ3iIlmyg", Unsupported<0x50>);
	LIB_FUNC("8fryvN6BDtY", Unsupported<0x52>);
	LIB_FUNC("hPWDGx8ioXQ", Unsupported<0x53>);
	LIB_FUNC("Q-AesC937KM", Unsupported<0x55>);
	LIB_FUNC("J1H1QRCJf2Q", Unsupported<0x56>);
	LIB_FUNC("sZuwaDPATKs", Unsupported<0x59>);
	LIB_FUNC("TUC9xC1YQjs", Unsupported<0x60>);
	LIB_FUNC("KFDGyLj80MY", Unsupported<0x62>);
	LIB_FUNC("zsTvhCDrOjQ", Unsupported<0x63>);
	LIB_FUNC("miQ1wVwSexE", Unsupported<0x64>);
	LIB_FUNC("UTR6wAkajxk", Unsupported<0x65>);
	LIB_FUNC("Wx2+2t1mX1E", Unsupported<0x66>);
	LIB_FUNC("4boImm4wxu0", Unsupported<0x68>);
	LIB_FUNC("a4KKvF-ME4M", Unsupported<0x69>);
	LIB_FUNC("6EYF3tXjXbU", Unsupported<0x6a>);
	LIB_FUNC("t+rTx5NW+qU", Unsupported<0x72>);
	LIB_FUNC("cL2QUlo9Vnk", Unsupported<0x76>);
	LIB_FUNC("+WRlkKjZvag", Unsupported<0x78>);
	LIB_FUNC("YSHRBRLn2pI", Unsupported<0x79>);
	LIB_FUNC("VdXIDAbJ3tQ", Unsupported<0x7a>);
	LIB_FUNC("ruyD9QkP8dI", Unsupported<0x7b>);
	LIB_FUNC("n01yNbQO5W4", Unsupported<0x7c>);
	LIB_FUNC("X86Q0qQJ1m0", Unsupported<0x7d>);
	LIB_FUNC("6w8tPp+Yk6E", Unsupported<0x7e>);
	LIB_FUNC("ROILLZdYZPc", Unsupported<0x7f>);
	LIB_FUNC("NN01qLRhiqU", Unsupported<0x80>);
	LIB_FUNC("lvDhwhUC05E", Unsupported<0x85>);
	LIB_FUNC("TUuiYS2kE8s", Unsupported<0x86>);
	LIB_FUNC("MZb0GKT3mo8", Unsupported<0x87>);
	LIB_FUNC("c7ZnT7V1B98", Unsupported<0x89>);
	LIB_FUNC("GDuV00CHrUg", Unsupported<0x8a>);
	LIB_FUNC("2t3V7tfWY5s", Unsupported<0x8c>);
	LIB_FUNC("2M+dFM8Wmq4", Unsupported<0x8d>);
	LIB_FUNC("edJoqV2FIWs", Unsupported<0x93>);
	LIB_FUNC("b7uXQmnfB2s", Unsupported<0xa5>);
	LIB_FUNC("4oKwKmeOKjM", Unsupported<0xb6>);
	LIB_FUNC("HTxb6gmexa0", Unsupported<0xb7>);
	LIB_FUNC("A0O5kF5x4LQ", Unsupported<0xbd>);
	LIB_FUNC("oc98+zOImus", Unsupported<0xbf>);
	LIB_FUNC("FKPT9p58MAQ", Unsupported<0xc0>);
	LIB_FUNC("cZq1zIzFN7s", Unsupported<0xc0>);
	LIB_FUNC("Wh7HbV7JFqc", Unsupported<0xc2>);
	LIB_FUNC("4X0QwvuCfjc", Unsupported<0xc3>);
	LIB_FUNC("f09KvIPy-QY", Unsupported<0xc4>);
	LIB_FUNC("sfKygSjIbI8", Unsupported<0xc4>);
	LIB_FUNC("mTBZfEal2Bw", Unsupported<0xcb>);
	LIB_FUNC("OG4RsDwLguo", Unsupported<0xcc>);
	LIB_FUNC("+0EDo7YzcoU", Unsupported<0xce>);
	LIB_FUNC("d7nUj1LOdDU", Unsupported<0xe9>);
	LIB_FUNC("SFjw4+HOVOQ", Unsupported<0xeb>);
	LIB_FUNC("Uyss1eAFtWo", Unsupported<0xec>);
	LIB_FUNC("ZWNwgNgglzA", Unsupported<0xed>);
	LIB_FUNC("mZlElqorITk", Unsupported<0xee>);
	LIB_FUNC("tj-nUlJCp-8", Unsupported<0xef>);
	LIB_FUNC("msfSXXy-8H8", Unsupported<0xf0>);
	LIB_FUNC("AxUhC3zNrhk", Unsupported<0xfd>);
	LIB_FUNC("WsAtWvLkO7Q", Unsupported<0xfe>);
	LIB_FUNC("kaLFzWxqkFY", Unsupported<0xff>);
	LIB_FUNC("IiofFKEgSew", Unsupported<0x100>);
	LIB_FUNC("2G6i6hMIUUY", Unsupported<0x110>);
	LIB_FUNC("wVo8f0DV38E", Unsupported<0x112>);
	LIB_FUNC("PmZfv0lup1c", Unsupported<0x114>);
	LIB_FUNC("ZaRzaapAZwM", Unsupported<0x121>);
	LIB_FUNC("FCcmRZhWtOk", Unsupported<0x122>);
	LIB_FUNC("wxmwEoR8Uuw", Unsupported<0x130>);
	LIB_FUNC("WBl4xQV+Nnk", Unsupported<0x131>);
	LIB_FUNC("VOOKKun85lw", Unsupported<0x132>);
	LIB_FUNC("POwLLYzZufU", Unsupported<0x133>);
	LIB_FUNC("tvdntvBP5GM", Unsupported<0x134>);
	LIB_FUNC("qJzB+g1dUq4", Unsupported<0x135>);
	LIB_FUNC("gokWod7GAH4", Unsupported<0x136>);
	LIB_FUNC("OZOh7OPG41I", Unsupported<0x13a>);
	LIB_FUNC("phnjLKz4njM", Unsupported<0x13c>);
	LIB_FUNC("YD9sqo0Q620", Unsupported<0x13d>);
	LIB_FUNC("x7g7Ebeo8-U", Unsupported<0x144>);
	LIB_FUNC("NpLBpgVV7PU", Unsupported<0x145>);
	LIB_FUNC("Qsxbb+aty0U", Unsupported<0x146>);
	LIB_FUNC("yawdym+zDvw", Unsupported<0x147>);
	LIB_FUNC("O6gKl8uvGyE", Unsupported<0x148>);
	LIB_FUNC("puT82CSQzDE", Unsupported<0x149>);
	LIB_FUNC("SD7oNCIQWvE", Unsupported<0x14a>);
	LIB_FUNC("PrsRaaSO-X0", Unsupported<0x14e>);
	LIB_FUNC("O-ZI7tPijow", Unsupported<0x14f>);
	LIB_FUNC("40NtJm4om0A", Unsupported<0x151>);
	LIB_FUNC("hpoDTzy9Yy0", Unsupported<0x157>);
	LIB_FUNC("kT7ArRAAzRA", Unsupported<0x167>);
	LIB_FUNC("nh2IFMgKTv8", Unsupported<0x16a>);
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_EQUEUE_FD") != nullptr) {
		LIB_FUNC("RW-GEfpnsqg", OriginalSyscoreKevent);
	} else {
		LIB_FUNC("RW-GEfpnsqg", Unsupported<0x16b>);
	}
	LIB_FUNC("3YnXspQNyw8", Unsupported<0x17a>);
	LIB_FUNC("t5Buq8foIvg", Unsupported<0x186>);
	LIB_FUNC("DPd5RrM+-+A", Unsupported<0x187>);
	LIB_FUNC("PlmVIwQdarI", Unsupported<0x188>);
	LIB_FUNC("YA0r4LCkfeY", Unsupported<0x189>);
	LIB_FUNC("EARPL-r8jf0", Unsupported<0x18b>);
	LIB_FUNC("ngZnQWyUvGI", Unsupported<0x18c>);
	LIB_FUNC("pv9M2jHJ6iw", Unsupported<0x190>);
	LIB_FUNC("s8gWJrY1W-k", Unsupported<0x191>);
	LIB_FUNC("rQvMIxmFD6A", Unsupported<0x192>);
	LIB_FUNC("gVaofuRvLdU", Unsupported<0x193>);
	LIB_FUNC("TEwqtzAmezo", Unsupported<0x194>);
	LIB_FUNC("k5QQrJEpRYY", Unsupported<0x195>);
	LIB_FUNC("tvkQRDe6hNo", Unsupported<0x196>);
	LIB_FUNC("rOT0UMvtCCA", Unsupported<0x197>);
	LIB_FUNC("asSKL30+heA", Unsupported<0x198>);
	LIB_FUNC("mo0bFmWppIw", Unsupported<0x1a1>);
	LIB_FUNC("mrbHXqK8wkg", Unsupported<0x1ad>);
	LIB_FUNC("vE+WlomLSh4", Unsupported<0x1b9>);
	LIB_FUNC("TJG6tf+yJlY", Unsupported<0x1c8>);
	LIB_FUNC("3VpUbHUfQLM", Unsupported<0x1c9>);
	LIB_FUNC("adCOiUc2758", Unsupported<0x1ca>);
	LIB_FUNC("AUbtwPEbmXo", Unsupported<0x1cb>);
	LIB_FUNC("IMb6dZxKqrY", Unsupported<0x1cc>);
	LIB_FUNC("wl-GeZ-8gGQ", Unsupported<0x1cd>);
	LIB_FUNC("NTkdvODRVXA", Unsupported<0x1ce>);
	LIB_FUNC("j64iXjsjnCY", Unsupported<0x1d1>);
	LIB_FUNC("2I2RV6LyNng", Unsupported<0x1d2>);
	LIB_FUNC("itioQwmJGys", Unsupported<0x1e4>);
	LIB_FUNC("BiHHifIvX88", Unsupported<0x1e5>);
	LIB_FUNC("DGY7qWLcHGA", Unsupported<0x1e6>);
	LIB_FUNC("Pdgml4rbxYk", Unsupported<0x1e7>);
	LIB_FUNC("0Ma-LQjv6So", Unsupported<0x1e8>);
	LIB_FUNC("nsBDTu22CBU", Unsupported<0x1ea>);
	LIB_FUNC("ZUcBjUH-Agc", Unsupported<0x1eb>);
	LIB_FUNC("t6haf4s-eE0", Unsupported<0x1ed>);
	LIB_FUNC("Fc-j1ASNCfc", Unsupported<0x1ee>);
	LIB_FUNC("WwV9Mv0aV2A", Unsupported<0x1ef>);
	LIB_FUNC("uHkueep1tc8", Unsupported<0x1f0>);
	LIB_FUNC("bGVEgWXy6dg", Unsupported<0x1f3>);
	LIB_FUNC("3P7i3vxeZ18", Unsupported<0x1f5>);
	LIB_FUNC("-f6yjokBu4U", Unsupported<0x1f6>);
	LIB_FUNC("tCFbw1wGrqk", Unsupported<0x1f7>);
	LIB_FUNC("7NwggrWJ5cA", Unsupported<0x214>);
	LIB_FUNC("XujojypwYYc", Unsupported<0x217>);
	LIB_FUNC("YbAunrti+54", Unsupported<0x218>);
	LIB_FUNC("kPGXeSQeoWc", Unsupported<0x227>);
	LIB_FUNC("raO+bB7q2cY", Unsupported<0x228>);
	LIB_FUNC("3CNY4Z0Luc8", Unsupported<0x22d>);
	LIB_FUNC("E7CmfLfeSuQ", Unsupported<0x22e>);
	LIB_FUNC("zdaF5N-Xe2M", Unsupported<0x230>);
	LIB_FUNC("-rXkJO1hOk0", Unsupported<0x231>);
	LIB_FUNC("6wXisPohifE", Unsupported<0x232>);
	LIB_FUNC("MGrj20+EK+U", Unsupported<0x233>);
	LIB_FUNC("iZFJYJJoZS8", Unsupported<0x234>);
	LIB_FUNC("vS-RnoD1BSY", Unsupported<0x235>);
	LIB_FUNC("ztNqqNCl1Tw", Unsupported<0x236>);
	LIB_FUNC("h+4DJpAXs4I", Unsupported<0x237>);
	LIB_FUNC("WaThXSvAQNc", Unsupported<0x249>);
	LIB_FUNC("nZHk+lpqwVQ", Unsupported<0x252>);
	LIB_FUNC("GQli4UAXTfQ", Unsupported<0x253>);
	LIB_FUNC("LYbbZxXNAns", Unsupported<0x259>);
	LIB_FUNC("n0ErFZ2hmKs", Unsupported<0x25a>);
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD") != nullptr) {
		LIB_FUNC("9Iem9Wk07xU", OriginalSyscoreRdup);
	} else {
		LIB_FUNC("9Iem9Wk07xU", Unsupported<0x25b>);
	}
	LIB_FUNC("7OpNDDNMJyo", Unsupported<0x25c>);
	LIB_FUNC("jTPE1AS7uak", Unsupported<0x25d>);
	LIB_FUNC("O-hEvSnv2o4", Unsupported<0x25e>);
	LIB_FUNC("p2xgfB-30g8", GetSelfAuthInfo);
	LIB_FUNC("nG-FYqFutUo", Unsupported<0x264>);
	LIB_FUNC("EeVthQocE3Y", Unsupported<0x26b>);
	LIB_FUNC("Hx-KCms9n4s", Unsupported<0x270>);
	LIB_FUNC("PIt9WYaoBqU", Unsupported<0x271>);
	LIB_FUNC("IglowNcOePQ", Unsupported<0x272>);
	LIB_FUNC("AUqJNkobQ1c", Unsupported<0x276>);
	LIB_FUNC("NTNdYQluihk", Unsupported<0x277>);
	LIB_FUNC("mm0znr-xjqI", Unsupported<0x27d>);
	LIB_FUNC("ByogDrS-Xw8", Unsupported<0x280>);
	LIB_FUNC("fi+JX2wq2XU", Unsupported<0x287>);
	LIB_FUNC("6eh9QGpaRWw", Unsupported<0x289>);
	LIB_FUNC("JVgZfJt3ZqQ", Unsupported<0x28d>);
	LIB_FUNC("99XpfyBTg9c", Unsupported<0x28e>);
	LIB_FUNC("KZchfealTT4", Unsupported<0x28f>);
	LIB_FUNC("K7xiuldOPKw", Unsupported<0x290>);
	LIB_FUNC("-pOg5A6Yr6g", Unsupported<0x291>);
	LIB_FUNC("KIbJFQ0I1Cg", Unsupported<0x292>);
	LIB_FUNC("P0jjY6bxakI", Unsupported<0x293>);
	LIB_FUNC("nTc+tFajGqQ", Unsupported<0x294>);
	LIB_FUNC("WtR7OVvUgSo", Unsupported<0x29f>);
	LIB_FUNC("vpo3SbGFuEk", Unsupported<0x2a0>);
	LIB_FUNC("Tzmvl2b3kLA", Unsupported<0x2cc>);
	LIB_FUNC("lCp17SqY3Nc", Unsupported<0x2cd>);
	LIB_FUNC("tGtH2GTWbyE", Unsupported<0x2d5>);
	LIB_FUNC("8YkbXeSRxnM", Unsupported<0x2dc>);
	LOGF("PS5_NATIVE_SYSCALL_GUARD registered 222 known-firmware direct wrappers\n");
}
} // namespace Libs::NativeSyscallGuards
