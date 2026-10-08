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
constexpr uint64_t           kGuestPageSize = 0x4000;
void Trace(const char* name, const Request& request, int64_t rc, int guest_errno) {
	static std::atomic<uint32_t> count {0};
	const uint32_t               nth = count.fetch_add(1);
	if (nth >= 96) {
		return;
	}
	LOGF("PS5_NATIVE_KERNEL_BRIDGE service=%s args=%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64
	     ",%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64 " result=%016" PRIx64 " errno=%d\n",
	     name, request.args[0], request.args[1], request.args[2], request.args[3], request.args[4],
	     request.args[5], static_cast<uint64_t>(rc), guest_errno);
}
Reply MapNative(const Request& request) {
	const auto address = reinterpret_cast<void**>(request.args[0]);
	const auto size    = static_cast<size_t>(request.args[1]);
	const int  prot    = static_cast<int>(request.args[2]);
	const int  flags   = static_cast<int>(request.args[3]);
	const auto mode    = request.args[4];

	// dYK287SsmDs (+0x17d70, body +0x17c10) rejects these before it reads *address.
	// args[5] is the caller's return address, only used for callers in 0x800000000-0x83fffffff
	if (mode > 3 || size < kGuestPageSize || (size % kGuestPageSize) != 0 ||
	    (prot & 0xfffffc08) != 0 || (flags & 0xffb77f6f) != 0) {
		return {LibKernel::KERNEL_ERROR_EINVAL, 0};
	}
	if (mode != 0) {
		// modes 1-3 go to syscall 0x2d5 (tGtH2GTWbyE), not modelled
		LOGF("PS5_NATIVE_KERNEL_BRIDGE dYK287SsmDs mode=%" PRIu64 " needs syscall 0x2d5, ENOSYS\n",
		     mode);
		return {LibKernel::KERNEL_ERROR_ENOSYS, 0};
	}
	// mode 0: mmap(*address, size, prot & ~PROT_EXEC, flags | MAP_ANON, -1, 0); errors are
	// 0x80020000 + errno
	void*     mapped = *address;
	const int rc = LibKernel::Memory::KernelMapNamedFlexibleMemory(&mapped, size, prot & ~4, flags,
	                                                               "NativeKernelBridge");
	if (rc == 0) {
		*address = mapped;
	}
	return {rc, 0};
}
Reply SysconfNative(const Request& request) {
	if (request.args[0] != 47) {
		return {-1, Libs::Posix::POSIX_EINVAL};
	}
	int32_t     mib[2]    = {9, 20};
	int32_t     page_size = 0;
	size_t      length    = sizeof(page_size);
	const Reply syscall   = DispatchSyscall(
	    {0xca,
		 {reinterpret_cast<uint64_t>(mib), 2, reinterpret_cast<uint64_t>(&page_size),
		  reinterpret_cast<uint64_t>(&length), 0, 0}});
	if (syscall.value != 0 || length != sizeof(page_size)) {
		return {-1, Libs::Posix::POSIX_EINVAL};
	}
	return {page_size, 0};
}
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
int ReadExecveGuestVector(uint64_t address, bool optional, std::vector<std::string>* values) {
	constexpr size_t max_elements       = 256;
	constexpr size_t max_argument_bytes = 262144;
	values->clear();
	if (address == 0) return optional ? 0 : LibKernel::KERNEL_ERROR_EFAULT;
	size_t total_bytes = 0;
	for (size_t n = 0; n < max_elements; ++n) {
		if (n > (UINT64_MAX - address) / sizeof(uint64_t)) {
			return LibKernel::KERNEL_ERROR_EFAULT;
		}
		uint64_t element = 0;
		if (!ReadExecveGuestMemory(address + n * sizeof(uint64_t), &element, sizeof(element))) {
			return LibKernel::KERNEL_ERROR_EFAULT;
		}
		if (element == 0) return 0;
		std::string value;
		const int   rc = ReadExecveGuestString(element, max_argument_bytes - total_bytes,
		                                       LibKernel::KERNEL_ERROR_E2BIG, &value);
		if (rc != 0) return rc;
		total_bytes += value.size() + 1;
		if (total_bytes > max_argument_bytes) return LibKernel::KERNEL_ERROR_E2BIG;
		values->push_back(std::move(value));
	}
	return LibKernel::KERNEL_ERROR_E2BIG;
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
Reply NativePwrite(const SyscallRequest& request) {
	const uint64_t fd = request.args[0], address = request.args[1];
	const uint64_t length = request.args[2], offset = request.args[3];
	if (fd > INT32_MAX) return {-1, Libs::Posix::POSIX_EBADF};
	if (offset > INT64_MAX) return {-1, Libs::Posix::POSIX_EINVAL};
	if (length > 0x1000000) return {-1, Libs::Posix::POSIX_ENOSYS};
	if (length && (address == 0 || length > UINT64_MAX - address))
		return {-1, Libs::Posix::POSIX_EFAULT};
	for (uint64_t current = address; length && current < address + length;) {
		LibKernel::Memory::VirtualQueryInfo region {};
		if (LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(current), 0,
		                                          &region, sizeof(region)) != 0 ||
		    !region.is_committed || region.start > current || region.end <= current ||
		    (region.protection & 1u) == 0)
			return {-1, Libs::Posix::POSIX_EFAULT};
		current = std::min<uint64_t>(region.end, address + length);
	}
	const int64_t result = LibKernel::FileSystem::KernelPwrite(
	    static_cast<int>(fd), reinterpret_cast<const void*>(address), static_cast<size_t>(length),
	    static_cast<int64_t>(offset));
	return result >= 0 ? Reply {result, 0}
	                   : Reply {-1, LibKernel::KernelToPosix(static_cast<int>(result))};
}
Reply MiniSyscorePread(const SyscallRequest& request) {
	const uint64_t fd      = request.args[0];
	const uint64_t address = request.args[1];
	const uint64_t length  = request.args[2];
	const uint64_t offset  = request.args[3];
	if (fd > INT32_MAX) {
		return {-1, Libs::Posix::POSIX_EBADF};
	}
	if (offset > INT64_MAX) {
		return {-1, Libs::Posix::POSIX_EINVAL};
	}
	if (length > 0x1000000) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	if (address == 0 || length > UINT64_MAX - address) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	if (length != 0) {
		LibKernel::Memory::VirtualQueryInfo region {};
		if (LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(address), 0,
		                                          &region, sizeof(region)) != 0 ||
		    !region.is_committed || region.start > address || region.end < address + length ||
		    (region.protection & 2u) == 0) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
	}
	const int64_t bytes_read = LibKernel::FileSystem::KernelPread(
	    static_cast<int>(fd), reinterpret_cast<void*>(address), static_cast<size_t>(length),
	    static_cast<int64_t>(offset));
	const Reply reply = bytes_read >= 0
	                        ? Reply {bytes_read, 0}
	                        : Reply {-1, LibKernel::KernelToPosix(static_cast<int>(bytes_read))};
	static std::atomic<uint32_t> logged {0};
	if (logged.fetch_add(1) < 16) {
		LOGF("FIRST_FRAME_AUDIT NATIVE_PREAD"
		     " fd=%" PRIu64 " buffer=0x%016" PRIx64 " size=0x%" PRIx64 " offset=0x%" PRIx64
		     " bytes=%" PRId64 " errno=%d\n",
		     fd, address, length, offset, reply.value, reply.posix_errno);
	}
	return reply;
}
Reply MiniSyscoreSocketpair(const SyscallRequest& request) {
	if (request.args[0] != 1 || request.args[1] != 1 || request.args[2] != 0) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	auto* output = reinterpret_cast<int*>(request.args[3]);
	int   pair[2];
	if (!LibKernel::Memory::CanWriteGuest(output, sizeof(pair))) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	const int rc = LibKernel::FileSystem::CreateGuestSocketPair(pair);
	if (rc != 0) return {-1, LibKernel::KernelToPosix(rc)};
	if (!LibKernel::Memory::CopyToGuest(output, pair, sizeof(pair))) {
		LibKernel::FileSystem::KernelClose(pair[0]);
		LibKernel::FileSystem::KernelClose(pair[1]);
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	LOGF("MINI_SYSCORE_NATIVE_SOCKETPAIR fd0=%d fd1=%d bidirectional_queues=1\n", pair[0], pair[1]);
	return {0, 0};
}
Reply ReadlinkSyscall(const SyscallRequest& request) {
	const auto* path   = reinterpret_cast<const char*>(request.args[0]);
	const auto* output = reinterpret_cast<char*>(request.args[1]);
	const auto  length = static_cast<size_t>(request.args[2]);

	if (path == nullptr || output == nullptr) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	if (length == 0) {
		return {-1, Libs::Posix::POSIX_EINVAL};
	}

	const auto mapped = LibKernel::FileSystem::GetRealFilename(path);
	if (mapped.empty()) {
		return {-1, Libs::Posix::POSIX_ENOENT};
	}
	std::error_code ec;
	const auto      status = std::filesystem::symlink_status(mapped, ec);
	if (ec || !std::filesystem::exists(status)) {
		return {-1, Libs::Posix::POSIX_ENOENT};
	}
	if (std::filesystem::is_symlink(status)) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	return {-1, Libs::Posix::POSIX_EINVAL};
}
bool ValidateSysctlSpan(const void* pointer, uint64_t size, bool writable,
                        bool allow_registered = true) {
	const auto address = reinterpret_cast<uint64_t>(pointer);
	if (size == 0) return true;
	if (pointer == nullptr || size > UINT64_MAX - address) return false;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	const auto end        = address + size;
	ULONG_PTR  stack_low  = 0;
	ULONG_PTR  stack_high = 0;
	GetCurrentThreadStackLimits(&stack_low, &stack_high);
	for (auto cursor = address; cursor < end;) {
		LibKernel::Memory::VirtualQueryInfo guest {};
		const bool                          has_guest =
		    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(cursor), 1, &guest,
			                                      sizeof(guest)) == 0;
		if (!allow_registered && has_guest && guest.start < end) return false;
		if (has_guest && guest.start <= cursor) {
			const uint32_t permission = writable ? 2u : 1u;
			if (!guest.is_committed || guest.end <= cursor || (guest.protection & permission) == 0)
				return false;
			cursor = std::min<uint64_t>(guest.end, end);
			continue;
		}
		if (cursor < stack_low || cursor >= stack_high) return false;
		MEMORY_BASIC_INFORMATION host {};
		if (VirtualQuery(reinterpret_cast<const void*>(cursor), &host, sizeof(host)) !=
		        sizeof(host) ||
		    host.State != MEM_COMMIT || (host.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
			return false;
		}
		const auto base = reinterpret_cast<uint64_t>(host.BaseAddress);
		if (base > cursor || host.RegionSize > UINT64_MAX - base) return false;
		const auto host_end = base + host.RegionSize;
		if (host_end <= cursor) return false;
		const auto protection = host.Protect & 0xffu;
		const bool can_write  = protection == PAGE_READWRITE || protection == PAGE_WRITECOPY ||
		                        protection == PAGE_EXECUTE_READWRITE ||
		                        protection == PAGE_EXECUTE_WRITECOPY;
		const bool can_read =
		    can_write || protection == PAGE_READONLY || protection == PAGE_EXECUTE_READ;
		if (writable ? !can_write : !can_read) return false;
		auto next = std::min<uint64_t>(end, std::min<uint64_t>(host_end, stack_high));
		if (has_guest) next = std::min<uint64_t>(next, guest.start);
		if (next <= cursor) return false;
		cursor = next;
	}
#else
	(void)writable;
	(void)allow_registered;
#endif
	return true;
}
bool ReadSysctlMemory(const void* source, void* destination, uint64_t size) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (LibKernel::Memory::CopyFromGuest(destination, source, size)) return true;
	if (!ValidateSysctlSpan(source, size, false, false)) return false;
#else
	if (!ValidateSysctlSpan(source, size, false)) return false;
#endif
	if (size != 0) std::memcpy(destination, source, static_cast<size_t>(size));
	return true;
}
bool ValidateAppSysctlSpan(const void* pointer, uint64_t size, bool writable) {
	if (size != 0) return ValidateSysctlSpan(pointer, size, writable);
	const auto                          address = reinterpret_cast<uint64_t>(pointer);
	LibKernel::Memory::VirtualQueryInfo region {};
	if (LibKernel::Memory::KernelVirtualQuery(pointer, 0, &region, sizeof(region)) == 0 &&
	    region.start <= address && address < region.end && (address & 0x3fff) == 0)
		return true;
	return ValidateSysctlSpan(pointer, 1, writable);
}
bool WriteSysctlMemory(void* destination, const void* source, uint64_t size) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (LibKernel::Memory::CopyToGuest(destination, source, size)) return true;
	if (!ValidateSysctlSpan(destination, size, true, false)) return false;
#else
	if (!ValidateSysctlSpan(destination, size, true)) return false;
#endif
	if (size != 0) std::memcpy(destination, source, static_cast<size_t>(size));
	return true;
}
Reply PublishSysctlValue(void* output, void* length, uint64_t capacity, const void* value,
                         uint64_t value_size) {
	const uint64_t copied           = output != nullptr ? std::min(capacity, value_size) : 0;
	const uint64_t published_length = output != nullptr ? copied : value_size;
	if (length != nullptr && !ValidateSysctlSpan(length, sizeof(published_length), true)) {
		return {LibKernel::KERNEL_ERROR_EFAULT, 0};
	}
	if (copied != 0 && !WriteSysctlMemory(output, value, copied)) {
		return {LibKernel::KERNEL_ERROR_EFAULT, 0};
	}
	if (length != nullptr &&
	    !WriteSysctlMemory(length, &published_length, sizeof(published_length))) {
		return {LibKernel::KERNEL_ERROR_EFAULT, 0};
	}
	return output != nullptr && capacity < value_size ? Reply {-1, Libs::Posix::POSIX_ENOMEM}
	                                                  : Reply {0, 0};
}
// Syscalls 568-571 and 609. Handlers and state live in kernel/budget.cpp.
Reply BudgetReply(int result, int64_t value) {
	return result == 0 ? Reply {value, 0} : Reply {LibKernel::KERNEL_ERROR_UNKNOWN + result, 0};
}
// 568 {name, ptype, entries, count, out_entries}
Reply BudgetCreate(const SyscallRequest& request) {
	const auto* name        = reinterpret_cast<const char*>(request.args[0]);
	const auto* entries     = reinterpret_cast<const LibKernel::Budget::Entry*>(request.args[2]);
	auto*       out_entries = reinterpret_cast<LibKernel::Budget::Entry*>(request.args[4]);
	int64_t     id          = 0;
	const int   result      = LibKernel::Budget::Create(
	    name != nullptr, static_cast<uint32_t>(request.args[1]),
	    static_cast<uint32_t>(request.args[3]),
	    [&](std::string* value) {
		    for (size_t i = 0; i != 0x20; ++i) {
			    char c = 0;
			    if (!ReadSysctlMemory(name + i, &c, 1)) return Libs::Posix::POSIX_EFAULT;
			    if (c == '\0') return 0;
			    value->push_back(c);
		    }
		    return Libs::Posix::POSIX_ENAMETOOLONG;
	    },
	    [&](LibKernel::Budget::Entry* in, uint32_t count) {
		    return ReadSysctlMemory(entries, in, sizeof(*in) * count) ? 0
			                                                          : Libs::Posix::POSIX_EFAULT;
	    },
	    [&](const LibKernel::Budget::Entry* out, uint32_t count) {
		    return WriteSysctlMemory(out_entries, out, sizeof(*out) * count)
		               ? 0
					   : Libs::Posix::POSIX_EFAULT;
	    },
	    &id);
	return BudgetReply(result, id);
}
Reply BudgetDelete(const SyscallRequest& request) {
	int64_t   value  = 0;
	const int result = LibKernel::Budget::Delete(static_cast<int32_t>(request.args[0]), &value);
	return BudgetReply(result, value);
}
// 570 {id, entries_out, count_inout}
Reply BudgetGetResourceLimit(const SyscallRequest& request) {
	auto*     entries = reinterpret_cast<LibKernel::Budget::Entry*>(request.args[1]);
	auto*     count   = reinterpret_cast<int32_t*>(request.args[2]);
	const int result  = LibKernel::Budget::GetResourceLimit(
	    static_cast<int32_t>(request.args[0]),
	    [&](int32_t* value) {
		    return ReadSysctlMemory(count, value, sizeof(*value)) ? 0 : Libs::Posix::POSIX_EFAULT;
	    },
	    [&](const LibKernel::Budget::Entry* out, uint32_t n) {
		    return WriteSysctlMemory(entries, out, sizeof(*out) * n) ? 0
			                                                         : Libs::Posix::POSIX_EFAULT;
	    },
	    [&](int32_t value) {
		    return WriteSysctlMemory(count, &value, sizeof(value)) ? 0 : Libs::Posix::POSIX_EFAULT;
	    });
	return BudgetReply(result, 0);
}
// 0x2c2 {block}. AppMount::Begin does both the 0x178-byte copyin and the +0xb0 id copyout
Reply AppMountBegin(const SyscallRequest& request) {
	const auto* block  = reinterpret_cast<const void*>(request.args[0]);
	const int   result = LibKernel::AppMount::Begin(
	    [&](LibKernel::AppMount::Request& in) {
		    return ReadSysctlMemory(block, in.data(), in.size()) ? 0 : Libs::Posix::POSIX_EFAULT;
	    },
	    [&](uint64_t output, int32_t id) {
		    return WriteSysctlMemory(reinterpret_cast<void*>(output), &id, sizeof(id))
		               ? 0
					   : Libs::Posix::POSIX_EFAULT;
	    },
	    [&](uint64_t address, void* buffer, uint64_t size) {
		    return ReadSysctlMemory(reinterpret_cast<const void*>(address), buffer, size)
		               ? 0
					   : Libs::Posix::POSIX_EFAULT;
	    });
	return BudgetReply(result, 0);
}
// 0x2c3 {&id}
Reply AppMountEnd(const SyscallRequest& request) {
	const auto* id     = reinterpret_cast<const int32_t*>(request.args[0]);
	const int   result = LibKernel::AppMount::End([&](int32_t* value) {
		return ReadSysctlMemory(id, value, sizeof(*value)) ? 0 : Libs::Posix::POSIX_EFAULT;
	});
	return BudgetReply(result, 0);
}
Reply SysctlPageSize(const SyscallRequest& request) {
	// sysconf(47): sysctl {9,20}, read back as a signed int
	const uint32_t count = static_cast<uint32_t>(request.args[1]);
	if (count != 2 && count != 3 && count != 4) {
		static std::atomic<uint32_t> logged {0};
		if (logged.fetch_add(1) < 32) {
			LOGF("FIRST_FRAME_AUDIT SYSCTL_UNMODELED reason=namelen namelen=%u op=%s "
			     "new_len=%" PRIu64 " caller_pid=%d caller_tid=%d result=EINVAL\n",
			     count,
			     request.args[4] != 0   ? "write"
			     : request.args[2] != 0 ? "read"
			                            : "size",
			     request.args[4] != 0 ? request.args[5] : 0, LibKernel::Process::GetPid(),
			     LibKernel::PthreadGetthreadid());
		}
		return {LibKernel::KERNEL_ERROR_EINVAL, 0};
	}
	std::array<int32_t, 4> mib {};
	if (!ReadSysctlMemory(reinterpret_cast<const void*>(request.args[0]), mib.data(),
	                      count * sizeof(mib[0]))) {
		return {LibKernel::KERNEL_ERROR_EFAULT, 0};
	}
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
