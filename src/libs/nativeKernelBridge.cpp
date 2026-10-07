#include "libs/nativeKernelBridge.h"

#include "common/logging/log.h"
#include "common/singleton.h"
#include "graphics/presentation/videoOut.h"
#include "kernel/appMount.h"
#include "kernel/budget.h"
#include "kernel/directoryPassthrough.h"
#include "kernel/fileSystem.h"
#include "kernel/ipmiManager.h"
#include "kernel/ipmiScope.h"
#include "kernel/eventFlag.h"
#include "kernel/eventQueue.h"
#include "kernel/memory.h"
#include "kernel/process.h"
#include "kernel/execProcess.h"
#include "kernel/pthread.h"
#include "kernel/regMgr.h"
#include "kernel/semaphore.h"
#include "kernel/tmpfs.h"
#include "loader/decryptedModuleOverlay.h"
#include "loader/elf.h"
#include "loader/runtimeLinker.h"
#include "libs/errno.h"
#include "libs/audio.h"
#include "libs/network.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <climits>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <inttypes.h>
#include <memory>
#include <mutex>
#include <new>
#include <pthread.h>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#endif

namespace Libs {
}

namespace Libs::NativeKernelBridge {

namespace {
bool ReadExecveGuestMemory(uint64_t address, void* data, size_t size) {
	if (address == 0 || size > UINT64_MAX - address) return false;
	auto*  output = static_cast<uint8_t*>(data);
	size_t copied = 0;
	while (copied < size) {
		const auto                          current = address + copied;
		LibKernel::Memory::VirtualQueryInfo region {};
		if (LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(current), 0,
		                                          &region, sizeof(region)) != 0 ||
		    !region.is_committed || region.start > current || region.end <= current ||
		    (region.protection & 1u) == 0) {
			return false;
		}
		const auto length = std::min<size_t>(size - copied, region.end - current);
		std::memcpy(output + copied, reinterpret_cast<const void*>(current), length);
		copied += length;
	}
	return true;
}
int ReadExecveGuestString(uint64_t address, size_t max_size, int overflow_error,
                          std::string* result) {
	result->clear();
	if (address == 0) return LibKernel::KERNEL_ERROR_EFAULT;
	for (size_t n = 0; n < max_size; ++n) {
		if (n > UINT64_MAX - address) return LibKernel::KERNEL_ERROR_EFAULT;
		char character = 0;
		if (!ReadExecveGuestMemory(address + n, &character, 1)) {
			return LibKernel::KERNEL_ERROR_EFAULT;
		}
		if (character == '\0') return 0;
		result->push_back(character);
	}
	return overflow_error;
}
bool NativeTmpfsWritableSpan(uint64_t address, uint64_t length) {
	if (length == 0) return true;
	if (address == 0 || length > UINT64_MAX - address) return false;
	const uint64_t end = address + length;
	for (uint64_t current = address; current < end;) {
		LibKernel::Memory::VirtualQueryInfo region {};
		if (LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(current), 0,
		                                          &region, sizeof(region)) != 0 ||
		    !region.is_committed || region.start > current || region.end <= current ||
		    (region.protection & 2u) == 0) {
			return false;
		}
		current = std::min<uint64_t>(region.end, end);
	}
	return true;
}
bool DispatchGetdirentriesSyscall(const SyscallRequest& request, Reply* reply) try {
	if (request.number != 0xc4) return false;
	auto finish = [reply](int64_t result) {
		*reply = result >= 0 ? Reply {result, 0}
		                     : Reply {-1, LibKernel::KernelToPosix(static_cast<int>(result))};
		return true;
	};
	const int fd = static_cast<int32_t>(request.args[0]);
	if (request.args[2] > INT_MAX) return finish(LibKernel::KERNEL_ERROR_EINVAL);
	const auto count  = static_cast<uint32_t>(request.args[2]);
	const int  result = LibKernel::FileSystem::KernelGetdirentries(
	    fd, reinterpret_cast<char*>(request.args[1]), static_cast<int>(count),
	    reinterpret_cast<int64_t*>(request.args[3]));
	finish(result);
	if (std::getenv("KYTY_DIAGNOSTIC_SHELLCORE_RNPS_GETDIRENTRIES") != nullptr) {
		static std::atomic_uint32_t calls {0};
		if (calls.fetch_add(1, std::memory_order_relaxed) < 128) {
			LOGF("RNPS_GETDIRENTRIES_RAW syscall=0xc4 pid=%d fd=%d count=%u"
			     " base_requested=%d result=%" PRId64 " errno=%d\n",
			     LibKernel::Process::GetPid(), fd, count, request.args[3] != 0 ? 1 : 0,
			     reply->value, reply->posix_errno);
		}
	}
	return true;
} catch (const std::bad_alloc&) {
	*reply = {-1, Libs::Posix::POSIX_ENOMEM};
	return true;
}
bool DispatchTmpfsSyscall(const SyscallRequest& request, Reply* reply) try {
	auto finish = [reply](int64_t result) {
		*reply = result >= 0 ? Reply {result, 0}
		                     : Reply {-1, LibKernel::KernelToPosix(static_cast<int>(result))};
		return true;
	};
	switch (request.number) {
		case 0x03:
		case 0x06:
		case 0xbd:
		case 0x1de:
		case 0x1e0: {
			const int fd = static_cast<int32_t>(request.args[0]);
			if (!LibKernel::FileSystem::IsTmpfsDescriptor(fd)) return false;
			switch (request.number) {
				case 0x03:
					if (request.args[2] > INT64_MAX) return finish(LibKernel::KERNEL_ERROR_EINVAL);
					if (!NativeTmpfsWritableSpan(request.args[1], request.args[2])) {
						return finish(LibKernel::KERNEL_ERROR_EFAULT);
					}
					return finish(LibKernel::FileSystem::KernelRead(
					    fd, reinterpret_cast<void*>(request.args[1]),
					    static_cast<size_t>(request.args[2])));
				case 0x06: return finish(LibKernel::FileSystem::KernelClose(fd));
				case 0xbd:
					if (!NativeTmpfsWritableSpan(request.args[1],
					                             sizeof(LibKernel::FileSystem::FileStat))) {
						return finish(LibKernel::KERNEL_ERROR_EFAULT);
					}
					return finish(LibKernel::FileSystem::KernelFstat(
					    fd, reinterpret_cast<LibKernel::FileSystem::FileStat*>(request.args[1])));
				case 0x1de: {
					const int whence = static_cast<int32_t>(request.args[2]);
					if (whence < 0 || whence > 2) return finish(LibKernel::KERNEL_ERROR_EINVAL);
					return finish(LibKernel::FileSystem::KernelLseek(
					    fd, static_cast<int64_t>(request.args[1]), whence));
				}
				case 0x1e0:
					if (request.args[1] > INT64_MAX) return finish(LibKernel::KERNEL_ERROR_EINVAL);
					return finish(LibKernel::FileSystem::KernelFtruncate(
					    fd, static_cast<int64_t>(request.args[1])));
			}
			return false;
		}
		case 0x0a:
		case 0x80:
		case 0x88:
		case 0x89: {
			std::array<std::string, 2> paths;
			const size_t               count = request.number == 0x80 ? 2 : 1;
			for (size_t index = 0; index < count; ++index) {
				const int read = ReadExecveGuestString(
				    request.args[index], 1024, LibKernel::KERNEL_ERROR_ENAMETOOLONG, &paths[index]);
				if (read != 0) return finish(read);
				if (paths[index].empty()) return finish(LibKernel::KERNEL_ERROR_ENOENT);
				if (paths[index][0] != '/') return false;
			}
			switch (request.number) {
				case 0x0a: return finish(LibKernel::FileSystem::KernelUnlink(paths[0].c_str()));
				case 0x80:
					return finish(
					    LibKernel::FileSystem::KernelRename(paths[0].c_str(), paths[1].c_str()));
				case 0x88:
					return finish(LibKernel::FileSystem::KernelMkdir(
					    paths[0].c_str(), static_cast<uint16_t>(request.args[1])));
				case 0x89: return finish(LibKernel::FileSystem::KernelRmdir(paths[0].c_str()));
			}
			return false;
		}
		default: return false;
	}
} catch (const std::bad_alloc&) {
	*reply = {-1, Libs::Posix::POSIX_ENOMEM};
	return true;
}
Reply MiniSyscoreWrite(const SyscallRequest& request) {
	const uint64_t fd      = request.args[0];
	const uint64_t address = request.args[1];
	const uint64_t length  = request.args[2];
	if (fd > INT32_MAX) {
		return {-1, Libs::Posix::POSIX_EBADF};
	}
	if (length > 0x1000000) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	if (length != 0) {
		LibKernel::Memory::VirtualQueryInfo region {};
		if (address == 0 || length > UINT64_MAX - address ||
		    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(address), 0,
		                                          &region, sizeof(region)) != 0 ||
		    !region.is_committed || region.start > address || region.end < address + length ||
		    (region.protection & 1u) == 0) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
	}
	const auto written = LibKernel::FileSystem::KernelWrite(
	    static_cast<int>(fd), reinterpret_cast<const void*>(address), static_cast<size_t>(length));
	const Reply reply = written >= 0
	                        ? Reply {written, 0}
	                        : Reply {-1, LibKernel::KernelToPosix(static_cast<int>(written))};
	static std::atomic<uint32_t> logged {0};
	if (logged.fetch_add(1) < 16) {
		LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_NATIVE_WRITE"
		     " fd=%" PRIu64 " buffer=0x%016" PRIx64 " size=%" PRIu64 " actual=%" PRId64
		     " errno=%d\n",
		     fd, address, length, reply.value, reply.posix_errno);
	}
	static const bool dump_bufs = std::getenv("KYTY_DIAGNOSTIC_MINI_WRITE_DUMP") != nullptr;
	if (dump_bufs && length != 0 && reply.posix_errno == 0) {
		static std::atomic<uint32_t> dumped {0};
		const uint32_t               idx = dumped.fetch_add(1);
		if (idx < 64 || (idx < 4096 && (idx & 0x1ff) == 0)) {
			const auto*  bytes = reinterpret_cast<const unsigned char*>(address);
			const size_t clip  = std::min<size_t>(static_cast<size_t>(length), 96);
			char         hex[96 * 3 + 1];
			char         asc[96 + 1];
			size_t       h = 0;
			for (size_t i = 0; i < clip; ++i) {
				h +=
				    static_cast<size_t>(std::snprintf(hex + h, sizeof(hex) - h, "%02x ", bytes[i]));
				asc[i] = (bytes[i] >= 0x20 && bytes[i] < 0x7f) ? static_cast<char>(bytes[i]) : '.';
			}
			asc[clip] = '\0';
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_NATIVE_WRITE_DUMP idx=%u fd=%" PRIu64
			     " size=%" PRIu64 " clip=%zu hex=%sasc=\"%s\"\n",
			     idx, fd, length, clip, hex, asc);
		}
	}
	return reply;
}
} // namespace
bool ShouldLogMiniSyscallTrace(uint64_t ordinal) {
	return ordinal != 0 && (ordinal <= 64 || (ordinal & (ordinal - 1)) == 0);
}
Reply DispatchSyscall(const SyscallRequest& request) {
	Reply result {LibKernel::KERNEL_ERROR_ENOSYS, 0};
	if (DispatchGetdirentriesSyscall(request, &result)) return result;
	if (DispatchTmpfsSyscall(request, &result)) return result;
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_SIGPROCMASK_LOOP_TRACE") != nullptr) {
		static std::atomic<uint64_t> sigprocmask_running {0};
		static std::atomic<uint64_t> non_sigprocmask_seen {0};
		if (request.number == 0x154) {
			sigprocmask_running.fetch_add(1, std::memory_order_relaxed);
		} else {
			const uint64_t sig_count = sigprocmask_running.load(std::memory_order_relaxed);
			const uint64_t ordinal =
			    non_sigprocmask_seen.fetch_add(1, std::memory_order_relaxed) + 1;
			if (ShouldLogMiniSyscallTrace(ordinal)) {
				LOGF("FIRST_FRAME_AUDIT MINI_NON_SIGPROCMASK_SYSCALL idx=%" PRIu64
				     " ordinal=%" PRIu64 " pid=%d num=0x%x sig_calls=%" PRIu64 " a0=0x%" PRIx64
				     " a1=0x%" PRIx64 " a2=0x%" PRIx64 " a3=0x%" PRIx64 " a4=0x%" PRIx64
				     " a5=0x%" PRIx64 "\n",
				     ordinal - 1, ordinal, LibKernel::Process::GetPid(), request.number, sig_count,
				     request.args[0], request.args[1], request.args[2], request.args[3],
				     request.args[4], request.args[5]);
			}
		}
	}
}
} // namespace Libs::NativeKernelBridge
