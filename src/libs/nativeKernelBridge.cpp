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
int KYTY_SYSV_ABI KernelGetAppInfo(int pid, void* info);
}

namespace Libs::NativeKernelBridge {

namespace {
constexpr uint64_t           kGuestPageSize = 0x4000;
// libkernel stubs may sign-extend a 32-bit handle into the 64-bit register
static bool OriginalNativeHandle32IsCanonical(uint64_t raw) {
	if (raw == 0) return false;
	const auto low = static_cast<uint32_t>(raw);
	return raw == static_cast<uint64_t>(low) ||
	       raw == static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(low)));
}
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
Reply ReadlinkNative(const Request& request) {
	return DispatchSyscall({0x3a, request.args});
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
Reply SyscoreExecvePreflight(const SyscallRequest& request) {
	std::string path;
	const int   path_rc =
	    ReadExecveGuestString(request.args[0], 4096, LibKernel::KERNEL_ERROR_ENAMETOOLONG, &path);
	if (path_rc != 0) return {path_rc, 0};
	if (path.empty()) return {LibKernel::KERNEL_ERROR_ENOENT, 0};

	// app children exec the /app0 alias; rebase it onto the package path sc_spawn recorded
	const std::string requested_path = path;
	std::string       app_resolved;
	bool              app_remapped = false;
	if (LibKernel::Process::ResolveAppExecPath(path, &app_resolved)) {
		LOGF("SYSCORE_GUEST_EXECVE_APP0_REMAP guest_pid=%d from=%s to=%s\n",
		     LibKernel::Process::GetPid(), path.c_str(), app_resolved.c_str());
		path         = std::move(app_resolved);
		app_remapped = true;
	}

	std::vector<std::string> argv;
	std::vector<std::string> envp;
	const int                argv_rc = ReadExecveGuestVector(request.args[1], false, &argv);
	if (argv_rc != 0) return {argv_rc, 0};
	const int envp_rc = ReadExecveGuestVector(request.args[2], true, &envp);
	if (envp_rc != 0) return {envp_rc, 0};

	auto host_path            = LibKernel::FileSystem::GetRealFilename(path);
	bool passthrough_resolved = false;
	if (host_path.empty() &&
	    std::getenv("KYTY_DIAGNOSTIC_SYSCORE_EXECVE_PASSTHROUGH_RESOLVE") != nullptr) {
		std::filesystem::path via_passthrough;
		if (LibKernel::DirectoryPassthrough::ResolveHostPath(path, &via_passthrough) == 0) {
			host_path            = std::move(via_passthrough);
			passthrough_resolved = true;
		}
	}
	std::error_code error;
	if (host_path.empty() || !std::filesystem::is_regular_file(host_path, error)) {
		return {LibKernel::KERNEL_ERROR_ENOENT, 0};
	}
	std::filesystem::path app0_dir;
	std::string           app0_elf;
	if (app_remapped) {
		app0_dir = std::filesystem::weakly_canonical(host_path.parent_path(), error);
		if (error || app0_dir.empty() || !std::filesystem::is_directory(app0_dir, error) || error ||
		    !requested_path.starts_with("/app0/") ||
		    requested_path.find("..") != std::string::npos ||
		    requested_path.find('\\') != std::string::npos) {
			return {LibKernel::KERNEL_ERROR_ENOEXEC, 0};
		}
		app0_elf = requested_path;
		LOGF("SYSCORE_GUEST_EXECVE_APP0_PROVIDER guest_pid=%d root=%s elf=%s "
		     "source=pre_overlay_package\n",
		     LibKernel::Process::GetPid(), Common::PathToString(app0_dir).c_str(),
		     app0_elf.c_str());
	}
	// exec_check_permissions tests the entered vnode's mount before the image header is read
	if (LibKernel::FileSystem::IsNullfsNoExec(path)) {
		LOGF("SYSCORE_GUEST_EXECVE_REJECTED guest_pid=%d path=%s reason=mnt_noexec errno=EACCES\n",
		     LibKernel::Process::GetPid(), path.c_str());
		return {LibKernel::KERNEL_ERROR_EACCES, 0};
	}
	// encrypted /system_ex SELF -> its decrypted ELF, as module loads do; the header check takes
	// only a bare ELF
	if (path.rfind("/system_ex/", 0) == 0 || path.rfind("/system/vsh/app/", 0) == 0) {
		std::ifstream        self_input(host_path, std::ios::binary | std::ios::ate);
		std::vector<uint8_t> self_image;
		if (self_input) {
			const std::streamoff self_size = self_input.tellg();
			if (self_size > 0) {
				self_image.resize(static_cast<size_t>(self_size));
				self_input.seekg(0);
				self_input.read(reinterpret_cast<char*>(self_image.data()),
				                static_cast<std::streamsize>(self_size));
			}
		}
		std::vector<uint8_t>  decrypted;
		std::filesystem::path decrypted_path;
		std::string           detail;
		const auto resolution = Loader::DecryptedModuleOverlay::ResolveDecryptedModuleImage(
		    path, self_image, &decrypted, &detail, &decrypted_path);
		if (resolution == Loader::DecryptedModuleOverlay::Resolution::Substituted) {
			LOGF("SYSCORE_GUEST_EXECVE_DECRYPTED_OVERLAY guest_pid=%d path=%s %s\n",
			     LibKernel::Process::GetPid(), path.c_str(), detail.c_str());
			host_path = std::move(decrypted_path);
		} else if (resolution != Loader::DecryptedModuleOverlay::Resolution::NotApplicable) {
			LOGF("SYSCORE_GUEST_EXECVE_DECRYPTED_OVERLAY guest_pid=%d path=%s result=rejected %s\n",
			     LibKernel::Process::GetPid(), path.c_str(), detail.c_str());
		}
	}
	std::array<uint8_t, 64> header {};
	std::ifstream           input(host_path, std::ios::binary);
	if (!input) return {LibKernel::KERNEL_ERROR_EACCES, 0};
	input.read(reinterpret_cast<char*>(header.data()), header.size());
	if (input.gcount() != static_cast<std::streamsize>(header.size()) || header[0] != 0x7f ||
	    header[1] != 'E' || header[2] != 'L' || header[3] != 'F' || header[4] != 2 ||
	    header[5] != 1 ||
	    !((header[16] == 0x10 && header[17] == 0xfe) || (header[16] == 2 && header[17] == 0)) ||
	    header[18] != 0x3e || header[19] != 0) {
		return {LibKernel::KERNEL_ERROR_ENOEXEC, 0};
	}
	size_t total_bytes = 0;
	for (const auto* values: {&argv, &envp}) {
		for (const auto& value: *values)
			total_bytes += value.size() + 1;
	}
	if (total_bytes > 262144) return {LibKernel::KERNEL_ERROR_E2BIG, 0};
	LOGF("SYSCORE_GUEST_EXECVE_VALIDATED_REQUEST"
	     " guest_pid=%d path=%s argc=%zu envc=%zu passthrough_resolved=%d\n",
	     LibKernel::Process::GetPid(), path.c_str(), argv.size(), envp.size(),
	     passthrough_resolved ? 1 : 0);
	return {LibKernel::Process::ExecImage(path, host_path, argv, envp, app0_dir, app0_elf), 0};
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
Reply NativeNmount(const SyscallRequest& request) try {
	const auto count = static_cast<uint32_t>(request.args[1]);
	if (count < 4 || count > 256 || (count & 1u) != 0) {
		return {-1, Libs::Posix::POSIX_EINVAL};
	}
	const auto flags = static_cast<int32_t>(request.args[2]);
	LOGF("NATIVE_NMOUNT_ENTRY iovcnt=%" PRIu32 " flags=0x%08x\n", count,
	     static_cast<uint32_t>(flags));
	struct GuestIovec {
		uint64_t address;
		uint64_t length;
	};
	static_assert(sizeof(GuestIovec) == 16);
	std::vector<GuestIovec> vectors(count);
	if (!ReadExecveGuestMemory(request.args[0], vectors.data(),
	                           vectors.size() * sizeof(GuestIovec))) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	std::unordered_map<std::string, std::string> options;
	size_t                                       total = 0;
	for (size_t index = 0; index < vectors.size(); index += 2) {
		std::array<std::string, 2> strings;
		for (size_t part = 0; part < strings.size(); ++part) {
			const auto& vector = vectors[index + part];
			// vfs_buildopts keeps a zero-length value as NULL; processMount sends "ro" that way
			if (part == 1 && vector.length == 0) continue;
			if (vector.length == 0 || vector.length > 4096 || vector.length > 65536 - total) {
				return {-1, Libs::Posix::POSIX_EINVAL};
			}
			total += static_cast<size_t>(vector.length);
			auto& value = strings[part];
			value.resize(static_cast<size_t>(vector.length));
			if (!ReadExecveGuestMemory(vector.address, value.data(), value.size())) {
				return {-1, Libs::Posix::POSIX_EFAULT};
			}
			if (value.back() != '\0' || value.find('\0') != value.size() - 1) {
				return {-1, Libs::Posix::POSIX_EINVAL};
			}
			value.pop_back();
		}
		const auto& name = strings[0];
		if (name != "fstype" && name != "fspath" && name != "mode" && name != "size" &&
		    name != "inodes" && name != "from" && name != "target" && name != "large" &&
		    name != "timezone" && name != "async" && name != "ignoreacl" && name != "dirmask" &&
		    name != "mask" && name != "ro") {
			LOGF("NATIVE_NMOUNT_OPTION_REJECTED name=%s\n",
			     name.size() <= 64 ? name.c_str() : "<long>");
			return {-1, Libs::Posix::POSIX_EINVAL};
		}
		LOGF("NATIVE_NMOUNT_OPTION name=%s name_bytes=%" PRIu64 " value_bytes=%" PRIu64
		     " value=\"%s\"\n",
		     name.c_str(), vectors[index].length, vectors[index + 1].length,
		     strings[1].size() <= 128 ? strings[1].c_str() : "<long>");
		if (!options.emplace(name, std::move(strings[1])).second)
			return {-1, Libs::Posix::POSIX_EINVAL};
	}
	const auto type   = options.find("fstype");
	const auto target = options.find("fspath");
	if (type == options.end() || target == options.end() || type->second.empty() ||
	    target->second.empty()) {
		return {-1, Libs::Posix::POSIX_EINVAL};
	}
	if (type->second == "exfatfs") {
		if (flags != 1 && flags != 0) return {-1, Libs::Posix::POSIX_EOPNOTSUPP};
		if (options.size() != 9 || !options.contains("from") || !options.contains("large") ||
		    !options.contains("timezone") || !options.contains("async") ||
		    !options.contains("ignoreacl") || !options.contains("dirmask") ||
		    !options.contains("mask") || options.at("large") != "yes" ||
		    options.at("timezone") != "static" || !options.at("async").empty() ||
		    !options.at("ignoreacl").empty() || options.at("dirmask") != "511" ||
		    options.at("mask") != "511") {
			return {-1, Libs::Posix::POSIX_EINVAL};
		}
		const auto& source = options.at("from");
		const bool  passthrough =
		    std::getenv("KYTY_DIAGNOSTIC_FSCK_PARTITION_PASSTHROUGH") != nullptr;
		// /update exfat slot is RW (flags=0) and empty on cold boot
		const bool update_pair =
		    flags == 0 && ((target->second == "/update" && source == "/dev/ssd0.update") ||
			               (target->second == "/update_b" && source == "/dev/ssd0.update_b"));
		if (update_pair) {
			if (std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_NMOUNT_EXFATFS_UPDATE_PASS") == nullptr) {
				return {-1, Libs::Posix::POSIX_EOPNOTSUPP};
			}
			const int result =
			    LibKernel::Tmpfs::Mount(target->second, 0755u, 16ull * 1024 * 1024, 512u);
			const int error = result == 0 ? 0 : LibKernel::KernelToPosix(result);
			LOGF("NATIVE_NMOUNT fstype=exfatfs path=%s from=%s iovcnt=%" PRIu32
			     " flags=0 errno=%d backend=tmpfs_stand_in NON_AUTHENTIC=1\n",
			     target->second.c_str(), source.c_str(), count, error);
			return result == 0 ? Reply {0, 0} : Reply {-1, error};
		}
		if (flags != 1) return {-1, Libs::Posix::POSIX_EOPNOTSUPP};
		const bool preinst_pair =
		    (target->second == "/preinst" && source == "/dev/ssd0.preinst") ||
		    (target->second == "/preinst_b" && source == "/dev/ssd0.preinst_b");
		if (preinst_pair) {
			if (LibKernel::FileSystem::HasCapturedPartitionPassthrough(source)) {
				const int result = LibKernel::FileSystem::MountRegisteredPartitionPassthrough(
				    source, target->second);
				const int error = result == 0 ? 0 : LibKernel::KernelToPosix(result);
				LOGF("NATIVE_NMOUNT fstype=exfatfs path=%s from=%s flags=1 "
				     "backend=captured_directory errno=%d read_only=1\n",
				     target->second.c_str(), source.c_str(), error);
				return result == 0 ? Reply {0, 0} : Reply {-1, error};
			}
			if (std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_NMOUNT_EXFATFS_PREINST_PASS") == nullptr) {
				return {-1, Libs::Posix::POSIX_EOPNOTSUPP};
			}
			const int result =
			    LibKernel::Tmpfs::Mount(target->second, 0755u, 16ull * 1024 * 1024, 512u);
			const int error = result == 0 ? 0 : LibKernel::KernelToPosix(result);
			LOGF("NATIVE_NMOUNT fstype=exfatfs path=%s from=%s iovcnt=%" PRIu32
			     " flags=1 errno=%d backend=tmpfs_stand_in NON_AUTHENTIC=1\n",
			     target->second.c_str(), source.c_str(), count, error);
			return result == 0 ? Reply {0, 0} : Reply {-1, error};
		}
		const bool authentic_pair =
		    (target->second == "/system" && source == "/dev/ssd0.system") ||
		    (target->second == "/system_ex" && source == "/dev/ssd0.system_ex");
		const bool diagnostic_pair =
		    passthrough &&
		    ((target->second == "/system_b" && source == "/dev/ssd0.system_b") ||
			 (target->second == "/system_ex_b" && source == "/dev/ssd0.system_ex_b") ||
			 (target->second == "/system_data" && source == "/dev/ssd0.system_data") ||
			 (target->second == "/system_data_b" && source == "/dev/ssd0.system_data_b") ||
			 (target->second == "/update" && source == "/dev/ssd0.update") ||
			 (target->second == "/update_b" && source == "/dev/ssd0.update_b"));
		if (!authentic_pair && !diagnostic_pair) return {-1, Libs::Posix::POSIX_EINVAL};
		const int result =
		    passthrough
		        ? LibKernel::FileSystem::MountRegisteredPartitionPassthrough(source, target->second)
		        : LibKernel::FileSystem::MountRegisteredExfatReadOnly(source, target->second);
		const int error = result == 0 ? 0 : LibKernel::KernelToPosix(result);
		if (passthrough) {
			LOGF("NATIVE_NMOUNT fstype=exfatfs path=%s from=%s iovcnt=%" PRIu32
			     " flags=1 backend=passthrough errno=%d NON_AUTHENTIC=1\n",
			     target->second.c_str(), source.c_str(), count, error);
		} else {
			LOGF("NATIVE_NMOUNT fstype=exfatfs path=%s from=%s iovcnt=%" PRIu32
			     " flags=1 errno=%d\n",
			     target->second.c_str(), source.c_str(), count, error);
		}
		return result == 0 ? Reply {0, 0} : Reply {-1, error};
	}
	if (type->second == "ufs") {
		const bool passthrough =
		    std::getenv("KYTY_DIAGNOSTIC_FSCK_PARTITION_PASSTHROUGH") != nullptr;
		if (!passthrough) return {-1, Libs::Posix::POSIX_EOPNOTSUPP};
		if (options.size() != 3 || !options.contains("from"))
			return {-1, Libs::Posix::POSIX_EINVAL};
		const auto& source    = options.at("from");
		const bool  rnps_pair = target->second == "/mnt/rnps" && source == "/dev/lvd0";
		if (rnps_pair && static_cast<uint32_t>(flags) != 0x10000000u) {
			return {-1, Libs::Posix::POSIX_EOPNOTSUPP};
		}
		const bool diagnostic_pair =
		    (target->second == "/system_data" && source == "/dev/ssd0.system_data") ||
		    (target->second == "/system_data_b" && source == "/dev/ssd0.system_data_b") ||
		    rnps_pair || (target->second == "/update" && source == "/dev/ssd0.update") ||
		    (target->second == "/update_b" && source == "/dev/ssd0.update_b");
		if (!diagnostic_pair) return {-1, Libs::Posix::POSIX_EINVAL};
		const int result = LibKernel::FileSystem::MountRegisteredPartitionPassthrough(
		    source, target->second, (flags & 0x1) == 0);
		const int error = result == 0 ? 0 : LibKernel::KernelToPosix(result);
		LOGF("NATIVE_NMOUNT fstype=ufs path=%s from=%s iovcnt=%" PRIu32 " flags=0x%" PRIx32
		     " backend=passthrough errno=%d NON_AUTHENTIC=1\n",
		     target->second.c_str(), source.c_str(), count, flags, error);
		return result == 0 ? Reply {0, 0} : Reply {-1, error};
	}
	if (type->second == "bfs") {
		if (flags != 0) return {-1, Libs::Posix::POSIX_EOPNOTSUPP};
		if (options.size() != 3 || !options.contains("from"))
			return {-1, Libs::Posix::POSIX_EINVAL};
		const auto& source = options.at("from");
		// sub_402D30:loc_404C91 passes "ssd0.user" without /dev/, FindSectorPayload wants
		// "/dev/ssd0.user"
		const bool authentic_pair = (target->second == "/user" && source == "ssd0.user");
		if (!authentic_pair) return {-1, Libs::Posix::POSIX_EINVAL};
		const std::string device = "/dev/" + source;
		int  result   = LibKernel::FileSystem::MountRegisteredBfs(device, target->second);
		bool stand_in = false;
		if (result != 0 && std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_NMOUNT_BFS_PASS") != nullptr) {
			result =
			    LibKernel::FileSystem::MountTmpfs(target->second, 0755u, 16ull * 1024 * 1024, 512u);
			stand_in = (result == 0);
		}
		const int error = result == 0 ? 0 : LibKernel::KernelToPosix(result);
		LOGF("NATIVE_NMOUNT fstype=bfs path=%s from=%s device=%s iovcnt=%" PRIu32
		     " flags=0 errno=%d%s\n",
		     target->second.c_str(), source.c_str(), device.c_str(), count, error,
		     stand_in ? " backend=tmpfs_stand_in NON_AUTHENTIC=1" : "");
		return result == 0 ? Reply {0, 0} : Reply {-1, error};
	}
	if (type->second == "nullfs") {
		// sandbox helper: MNT_NOEXEC for non-app0 aliases, callers add MNT_RDONLY
		if ((static_cast<uint32_t>(flags) & ~0x5u) != 0) return {-1, Libs::Posix::POSIX_EOPNOTSUPP};
		const bool has_target = options.contains("target");
		const bool has_from   = options.contains("from");
		const bool has_ro     = options.contains("ro");
		if ((!has_target && !has_from) || options.size() != 2u + has_target + has_from + has_ro)
			return {-1, Libs::Posix::POSIX_EINVAL};
		const auto& source = options.at(has_target ? "target" : "from");
		// vfs_donmount folds an "ro" option into MNT_RDONLY whatever its value
		const uint32_t mount_flags = static_cast<uint32_t>(flags) | (has_ro ? 0x1u : 0u);
		const int mounted = LibKernel::FileSystem::MountNullfs(source, target->second, mount_flags);
		const int mount_error           = mounted == 0 ? 0 : LibKernel::KernelToPosix(mounted);
		const bool diagnostic_namespace = LibKernel::Tmpfs::Contains(source);
		LOGF("NATIVE_NMOUNT fstype=nullfs path=%s %s=%s iovcnt=%" PRIu32
		     " flags=0x%x errno=%d backend=nullfs%s\n",
		     target->second.c_str(), has_target ? "target" : "from", source.c_str(), count,
		     mount_flags, mount_error,
		     diagnostic_namespace ? " source_namespace=tmpfs NON_AUTHENTIC=1" : "");
		if (mounted == 0) return {0, 0};
		// sub_40f240: sandbox2 pair. devlog_mount: /devlog/{app,system} from /user
		const bool diagnostic_pair =
		    (target->second == "/original_user" && source == "/user") ||
		    (target->second == "/original_system_data" && source == "/system_data") ||
		    (target->second == "/devlog/app" && source == "/user/devlog/app") ||
		    (target->second == "/devlog/system" && source == "/user/devlog/system");
		if (!diagnostic_pair || mounted != LibKernel::KERNEL_ERROR_ENOENT) return {-1, mount_error};
		if (std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_NMOUNT_NULLFS_PASS") == nullptr) {
			return {-1, mount_error};
		}
		// MountTmpfs rejects a missing final component, Tmpfs::Mount creates it
		const int result =
		    LibKernel::Tmpfs::Mount(target->second, 0755u, 16ull * 1024 * 1024, 512u);
		const int error = result == 0 ? 0 : LibKernel::KernelToPosix(result);
		LOGF("NATIVE_NMOUNT fstype=nullfs path=%s from=%s iovcnt=%" PRIu32
		     " flags=0 errno=%d backend=tmpfs_stand_in NON_AUTHENTIC=1\n",
		     target->second.c_str(), source.c_str(), count, error);
		return result == 0 ? Reply {0, 0} : Reply {-1, error};
	}
	if (type->second == "devfs") {
		// SceLncService passes only fstype and fspath for the sandbox /dev
		if (flags != 0 || options.size() != 2) return {-1, Libs::Posix::POSIX_EOPNOTSUPP};
		const int mounted = LibKernel::FileSystem::MountDevfs(target->second);
		const int error   = mounted == 0 ? 0 : LibKernel::KernelToPosix(mounted);
		LOGF("NATIVE_NMOUNT fstype=devfs path=%s iovcnt=%" PRIu32 " flags=0 errno=%d\n",
		     target->second.c_str(), count, error);
		return mounted == 0 ? Reply {0, 0} : Reply {-1, error};
	}
	if (type->second != "tmpfs") return {-1, Libs::Posix::POSIX_EOPNOTSUPP};
	if (flags != 0) return {-1, Libs::Posix::POSIX_EOPNOTSUPP};
	const bool with_mode    = options.size() == 5 && options.contains("mode");
	const bool without_mode = options.size() == 4 && !options.contains("mode");
	if ((!with_mode && !without_mode) || !options.contains("size") || !options.contains("inodes")) {
		return {-1, Libs::Posix::POSIX_EINVAL};
	}
	auto number = [](const std::string& value, unsigned base, uint64_t maximum, uint64_t* result) {
		if (value.empty()) return false;
		uint64_t parsed = 0;
		for (const unsigned char character: value) {
			if (character < '0' || character >= '0' + base) return false;
			const auto digit = static_cast<uint64_t>(character - '0');
			if (digit > maximum || parsed > (maximum - digit) / base) return false;
			parsed = parsed * base + digit;
		}
		*result = parsed;
		return true;
	};
	uint64_t mode = 0755, bytes = 0, inodes = 0;
	if ((with_mode && !number(options.at("mode"), 8, 07777, &mode)) ||
	    !number(options.at("size"), 10, INT64_MAX, &bytes) ||
	    !number(options.at("inodes"), 10, UINT32_MAX, &inodes) || bytes == 0 || inodes == 0) {
		return {-1, Libs::Posix::POSIX_EINVAL};
	}
	int  result   = LibKernel::FileSystem::MountTmpfs(target->second, static_cast<uint32_t>(mode),
	                                                  bytes, static_cast<uint32_t>(inodes));
	bool stand_in = false;
	if (result != 0 && std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_NMOUNT_TMPFS_PASS") != nullptr) {
		const uint64_t capped_bytes  = bytes > LibKernel::Tmpfs::MaximumMountBytes
		                                   ? LibKernel::Tmpfs::MaximumMountBytes
		                                   : bytes;
		const uint32_t capped_inodes = inodes > LibKernel::Tmpfs::MaximumInodes
		                                   ? LibKernel::Tmpfs::MaximumInodes
		                                   : static_cast<uint32_t>(inodes);
		result = LibKernel::Tmpfs::Mount(target->second, static_cast<uint32_t>(mode), capped_bytes,
		                                 capped_inodes);
		stand_in = (result == 0);
	}
	const int error = result == 0 ? 0 : LibKernel::KernelToPosix(result);
	LOGF("NATIVE_NMOUNT fstype=tmpfs path=%s iovcnt=%" PRIu32 " mode=%o size=%" PRIu64
	     " inodes=%" PRIu64 " flags=0 errno=%d%s\n",
	     target->second.c_str(), count, static_cast<unsigned>(mode), bytes, inodes, error,
	     stand_in ? " backend=tmpfs_stand_in NON_AUTHENTIC=1" : "");
	return result == 0 ? Reply {0, 0} : Reply {-1, error};
} catch (const std::bad_alloc&) {
	return {-1, Libs::Posix::POSIX_ENOMEM};
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
Reply MiniSyscoreOpen(const SyscallRequest& request) {
	const uint64_t address = request.args[0];
	std::string    path;
	const int      rc =
	    ReadExecveGuestString(address, 4096, LibKernel::KERNEL_ERROR_ENAMETOOLONG, &path);
	if (rc != 0) return {-1, LibKernel::KernelToPosix(rc)};
	const bool creates = (request.args[1] & 0x200) != 0;
	if (request.args[1] > INT32_MAX || (creates && request.args[2] > UINT16_MAX)) {
		return {-1, Libs::Posix::POSIX_EINVAL};
	}
	const int fd =
	    LibKernel::FileSystem::KernelOpen(path.c_str(), static_cast<int>(request.args[1]),
		                                  creates ? static_cast<uint16_t>(request.args[2]) : 0);
	const Reply reply = fd >= 0 ? Reply {fd, 0} : Reply {-1, LibKernel::KernelToPosix(fd)};
	LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_OPEN"
	     " path=%s guest_path=0x%016" PRIx64 " guest_flags=0x%016" PRIx64
	     " guest_mode=0x%016" PRIx64 " fd=%" PRId64 " errno=%d\n",
	     path.c_str(), address, request.args[1], request.args[2], reply.value, reply.posix_errno);
	return reply;
}
Reply MiniSyscoreSemaphore(const SyscallRequest& request) {
	using namespace LibKernel::Semaphore;
	const int owner = LibKernel::Process::GetPid();
	if (request.number == 0x225 || request.number == 0x227) {
		std::string name;
		const int   rc = ReadExecveGuestString(request.args[0], 256,
		                                       LibKernel::KERNEL_ERROR_ENAMETOOLONG, &name);
		if (rc != 0) return {-1, LibKernel::KernelToPosix(rc)};
		KernelSema sem = nullptr;
		int        result;
		if (request.number == 0x225) {
			if (request.args[1] > UINT32_MAX || request.args[2] > INT32_MAX ||
			    request.args[3] > INT32_MAX) {
				return {-1, Libs::Posix::POSIX_EINVAL};
			}
			result = KernelCreateSema(&sem, name.c_str(), static_cast<uint32_t>(request.args[1]),
			                          static_cast<int>(request.args[2]),
			                          static_cast<int>(request.args[3]), nullptr);
		} else {
			result = KernelOpenExistingSema(&sem, name.c_str());
		}
		if (result != 0) return {-1, LibKernel::KernelToPosix(result)};
		const auto handle = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(sem));
		LOGF("MINI_NATIVE_SEMA_OBJECT op=0x%llx pid=%d name=%s handle=%u\n",
		     static_cast<unsigned long long>(request.number), owner, name.c_str(), handle);
		return {handle, 0};
	}
	LibKernel::KernelUseconds  timeout = 0;
	LibKernel::KernelUseconds* output  = nullptr;
	if (request.number == 0x229) {
		if (request.args[1] == 0 || request.args[1] > INT32_MAX)
			return {-1, Libs::Posix::POSIX_EINVAL};
		output = reinterpret_cast<LibKernel::KernelUseconds*>(request.args[2]);
		if (output != nullptr &&
		    (!LibKernel::Memory::CanWriteGuest(output, sizeof(timeout)) ||
		     !ReadExecveGuestMemory(request.args[2], &timeout, sizeof(timeout)))) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
	}
	if (request.args[0] > INT32_MAX) return {-1, Libs::Posix::POSIX_ESRCH};
	const auto sem = reinterpret_cast<KernelSema>(static_cast<uintptr_t>(request.args[0]));
	if (request.number == 0x226 || request.number == 0x228) {
		const int rc = request.number == 0x226 ? KernelDeleteSema(sem) : KernelCloseSema(sem);
		return rc == 0 ? Reply {0, 0} : Reply {-1, LibKernel::KernelToPosix(rc)};
	}
	if (request.args[1] > INT32_MAX) return {-1, Libs::Posix::POSIX_EINVAL};
	int rc;
	if (request.number == 0x22b) {
		rc = KernelSignalSema(sem, static_cast<int>(request.args[1]));
	} else if (request.number == 0x229) {
		rc                = KernelWaitSema(sem, static_cast<int>(request.args[1]),
		                                   output != nullptr ? &timeout : nullptr);
		const bool waited = rc == 0 || rc == LibKernel::KERNEL_ERROR_ETIMEDOUT ||
		                    rc == LibKernel::KERNEL_ERROR_ECANCELED ||
		                    rc == LibKernel::KERNEL_ERROR_EACCES;
		if (waited && output != nullptr &&
		    !LibKernel::Memory::CopyToGuest(output, &timeout, sizeof(timeout))) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
	} else {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	return rc == 0 ? Reply {0, 0} : Reply {-1, LibKernel::KernelToPosix(rc)};
}
Reply MiniSyscoreKevent(const SyscallRequest& request) {
	if (request.args[0] > INT32_MAX || request.args[2] > 1 || request.args[4] > 1) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	int64_t queue = 0;
	if (!LibKernel::FileSystem::ResolveNativeKqueueDescriptor(static_cast<int>(request.args[0]),
	                                                          &queue)) {
		return {-1, Libs::Posix::POSIX_EBADF};
	}
	auto* output = reinterpret_cast<LibKernel::EventQueue::KernelEvent*>(request.args[3]);
	if (request.args[4] != 0 && !LibKernel::Memory::CanWriteGuest(output, sizeof(*output))) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	LibKernel::KernelUseconds timeout = 0;
	if (request.args[5] != 0) {
		LibKernel::KernelTimespec original;
		if (!ReadExecveGuestMemory(request.args[5], &original, sizeof(original))) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		if (original.tv_sec < 0 || original.tv_sec > UINT32_MAX / 1000000 || original.tv_nsec < 0 ||
		    original.tv_nsec >= 1000000000) {
			return {-1, Libs::Posix::POSIX_EINVAL};
		}
		const uint64_t micros = static_cast<uint64_t>(original.tv_sec) * 1000000 +
		                        (static_cast<uint64_t>(original.tv_nsec) + 999) / 1000;
		if (micros > UINT32_MAX) return {-1, Libs::Posix::POSIX_EINVAL};
		timeout = static_cast<LibKernel::KernelUseconds>(micros);
	}
	if (request.args[2] != 0) {
		LibKernel::EventQueue::KernelEvent change;
		if (!ReadExecveGuestMemory(request.args[1], &change, sizeof(change))) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		int rc;
		if (change.filter == LibKernel::EventQueue::KERNEL_EVFILT_PROC) {
			rc = LibKernel::EventQueue::KernelAddNativeProcEvent(queue, change);
		} else if (change.filter == LibKernel::EventQueue::KERNEL_EVFILT_VIDEO_OUT &&
		           change.flags == 1 && change.fflags == 0 && change.data == 0 &&
		           change.udata == nullptr) {
			rc = LibKernel::FileSystem::RegisterNativeDceFlipEvent(queue, change.ident);
		} else {
			return {-1, Libs::Posix::POSIX_ENOSYS};
		}
		if (rc != 0) return {-1, LibKernel::KernelToPosix(rc)};
	}
	if (request.args[4] == 0) return {0, 0};
	LibKernel::EventQueue::KernelEvent event;
	int                                received = 0;
	const int                          rc       = LibKernel::EventQueue::KernelWaitEqueue(
	    queue, &event, 1, &received, request.args[5] != 0 ? &timeout : nullptr);
	if (rc == LibKernel::KERNEL_ERROR_ETIMEDOUT) return {0, 0};
	if (rc != 0) return {-1, LibKernel::KernelToPosix(rc)};
	if (received != 0 && !LibKernel::Memory::CopyToGuest(output, &event, sizeof(event))) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	LOGF("MINI_NATIVE_KEVENT received=%d\n", received);
	return {received, 0};
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
	auto*          output    = reinterpret_cast<void*>(request.args[2]);
	auto*          length    = reinterpret_cast<void*>(request.args[3]);
	const auto*    input     = reinterpret_cast<const void*>(request.args[4]);
	const uint64_t input_len = request.args[5];
	uint64_t       capacity  = 0;
	if (length != nullptr && !ReadSysctlMemory(length, &capacity, sizeof(capacity))) {
		return {LibKernel::KERNEL_ERROR_EFAULT, 0};
	}
	const bool app_handler = count == 4 && mib[0] == 1 && mib[1] == 14 && mib[2] == 35;
	const bool app_object =
	    count == 4 && mib[0] == 1 && mib[1] == 14 && (mib[2] == 64 || mib[2] == 65);
	const auto valid_span = [&](const void* pointer, uint64_t size, bool writable) {
		return app_object ? ValidateAppSysctlSpan(pointer, size, writable)
		                  : ValidateSysctlSpan(pointer, size, writable);
	};
	if (!app_handler && ((output != nullptr && !valid_span(output, capacity, true)) ||
	                     (input != nullptr && !valid_span(input, input_len, false)))) {
		return {LibKernel::KERNEL_ERROR_EFAULT, 0};
	}
	std::string name;
	if (count == 2 && mib[0] == 0 && mib[1] == 3 && name == "kern.smp.cpus") {
		LOGF("FIRST_FRAME_AUDIT SYSAV_SYSCTL_NAME_MISSING"
		     " name=kern.smp.cpus result=ENOENT\n");
		return {-1, Libs::Posix::POSIX_ENOENT};
	}
	if (count == 2 && mib[0] == 0 && mib[1] == 3 && name == "kern.kern_type") {
		const uint32_t oid[2] = {1, 0x7ffffcb3};
		return PublishSysctlValue(output, length, capacity, oid, sizeof(oid));
	}
	if (count == 2 && mib[0] == 1 && static_cast<uint32_t>(mib[1]) == 0x7ffffcb3) {
		if (input != nullptr || input_len != 0) return {-1, Libs::Posix::POSIX_EPERM};
		const int32_t kernel_type = 1;
		const Reply   result =
		    PublishSysctlValue(output, length, capacity, &kernel_type, sizeof(kernel_type));
		if (result.value == 0) {
			LOGF("FIRST_FRAME_AUDIT NATIVE_KERN_TYPE value=1 width=4"
			     " source=kernel_13_60_captured_oid_readonly\n");
		}
		return result;
	}
	if (count == 2 && mib[0] == 0 && mib[1] == 3 && name == "hw.config.bd_drive") {
		const uint32_t oid[3] = {6, 0x7ffffe22u, 0x7ffffe1au};
		const Reply    result = PublishSysctlValue(output, length, capacity, oid, sizeof(oid));
		if (result.value == 0) {
			LOGF("FIRST_FRAME_AUDIT SYSCTL_BD_DRIVE_NAMETOMIB oid=6.2147483170.2147483162"
			     " source=live_13_60_sysctl\n");
		}
		return result;
	}
	if (count == 3 && mib[0] == 6 && static_cast<uint32_t>(mib[1]) == 0x7ffffe22u &&
	    static_cast<uint32_t>(mib[2]) == 0x7ffffe1au) {
		if (input != nullptr || input_len != 0) return {-1, Libs::Posix::POSIX_EPERM};
		const uint32_t bd_drive = 3;
		const Reply    result =
		    PublishSysctlValue(output, length, capacity, &bd_drive, sizeof(bd_drive));
		if (result.value == 0) {
			LOGF("FIRST_FRAME_AUDIT SYSCTL_BD_DRIVE value=%u width=4"
			     " source=live_13_60_sysctl\n",
			     bd_drive);
		}
		return result;
	}
	if (count == 2 && mib[0] == 0 && mib[1] == 3 && name == "kern.backup_restore_mode") {
		const uint32_t oid[2] = {1, 0x7ffffeb8};
		return PublishSysctlValue(output, length, capacity, oid, sizeof(oid));
	}
	if (count == 2 && mib[0] == 1 && static_cast<uint32_t>(mib[1]) == 0x7ffffeb8) {
		// RD|INT: only a new value is refused; the handler fetches the cache before it looks at
		// oldptr, so a size query fetches too.
		if (input != nullptr) return {-1, Libs::Posix::POSIX_EPERM};
		int32_t     mode   = 0;
		int32_t     status = 0;
		const char* reason = nullptr;
		if (LibKernel::RegMgr::BackupRestoreMode(&mode, &status, &reason) != 0) {
			LOGF("FIRST_FRAME_AUDIT NATIVE_BACKUP_RESTORE_MODE_UNMODELED reason=%s result=ENOSYS\n",
			     reason);
			return {-1, Libs::Posix::POSIX_ENOSYS};
		}
		if (status != 0) {
			LOGF("FIRST_FRAME_AUDIT NATIVE_BACKUP_RESTORE_MODE_REGMGR status=0x%08x\n",
			     static_cast<uint32_t>(status));
			return {-1, status};
		}
		const Reply result = PublishSysctlValue(output, length, capacity, &mode, sizeof(mode));
		if (result.value == 0) {
			LOGF("FIRST_FRAME_AUDIT NATIVE_BACKUP_RESTORE_MODE width=4 regmgr_key=0x20c0000"
			     " source=kernel_13_60_handler_cache\n");
		}
		return result;
	}
	if (count == 2 && mib[0] == 0 && mib[1] == 3 && name == "kern.init_safe_mode") {
		const uint32_t oid[2] = {1, 0x7ffffebb};
		const Reply    result = PublishSysctlValue(output, length, capacity, oid, sizeof(oid));
		if (result.value == 0) {
			LOGF("FIRST_FRAME_AUDIT MINI_SAFE_MODE_NAMETOMIB"
			     " name=kern.init_safe_mode oid=1.0x7ffffebb "
			     "kernel_13_60_object=0xffffffff9fec0720\n");
		}
		return result;
	}
	if (count == 2 && mib[0] == 1 && static_cast<uint32_t>(mib[1]) == 0x7ffffebb) {
		if (output != nullptr && length != nullptr && input == nullptr && input_len == 0) {
			const int fd = LibKernel::FileSystem::KernelOpen("/dev/iccnvs4", 0, 0);
			if (fd < 0) return {-1, LibKernel::KernelToPosix(fd)};
			uint8_t       stored = 0;
			const int64_t bytes  = LibKernel::FileSystem::KernelPread(fd, &stored, 1, 0x20);
			const int     closed = LibKernel::FileSystem::KernelClose(fd);
			if (bytes != 1) return {-1, LibKernel::KernelToPosix(static_cast<int>(bytes))};
			if (closed != 0) return {-1, LibKernel::KernelToPosix(closed)};
			const int32_t value = stored;
			const Reply   result =
			    PublishSysctlValue(output, length, capacity, &value, sizeof(value));
			if (result.value == 0) {
				LOGF("FIRST_FRAME_AUDIT MINI_SAFE_MODE_READ value=0x%02x"
				     " iccnvs_partition=4 offset=0x20 captured_backing=1\n",
				     stored);
			}
			return result;
		}
		if (output == nullptr && length == nullptr && input != nullptr &&
		    input_len == sizeof(int32_t)) {
			int32_t value = 0;
			if (!ReadSysctlMemory(input, &value, sizeof(value))) {
				return {-1, Libs::Posix::POSIX_EFAULT};
			}
			if (value < 0 || value > 0xff) return {-1, Libs::Posix::POSIX_EINVAL};
			const int fd = LibKernel::FileSystem::KernelOpen("/dev/iccnvs4", 0x10002, 0);
			if (fd < 0) return {-1, LibKernel::KernelToPosix(fd)};
			const uint8_t stored = static_cast<uint8_t>(value);
			const int64_t bytes  = LibKernel::FileSystem::KernelPwrite(fd, &stored, 1, 0x20);
			const int     closed = LibKernel::FileSystem::KernelClose(fd);
			if (bytes != 1) return {-1, LibKernel::KernelToPosix(static_cast<int>(bytes))};
			if (closed != 0) return {-1, LibKernel::KernelToPosix(closed)};
			LOGF("FIRST_FRAME_AUDIT MINI_SAFE_MODE_WRITE value=0x%02x"
			     " iccnvs_partition=4 offset=0x20\n",
			     stored);
			return {0, 0};
		}
		return {-1, Libs::Posix::POSIX_EINVAL};
	}
	if (count == 2 && mib[0] == 1 && mib[1] == 33 && input == nullptr && input_len == 0) {
		const uint64_t stack_top = LibKernel::PthreadGetMainGuestStackTop();
		if (stack_top == 0) {
			return {-1, Libs::Posix::POSIX_ENOENT};
		}
		const Reply result =
		    PublishSysctlValue(output, length, capacity, &stack_top, sizeof(stack_top));
		if (result.value == 0) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_KERN_USRSTACK"
			     " guest_stack_top=0x%016" PRIx64 "\n",
			     stack_top);
		}
		return result;
	}
	if (count == 2 && mib[0] == 1 && mib[1] == 37 && input == nullptr && input_len == 0 &&
	    output != nullptr && capacity > 0 && capacity <= 256) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		std::array<uint8_t, 256> bytes {};
		const auto               size = static_cast<ULONG>(capacity);
		const NTSTATUS           result =
		    BCryptGenRandom(nullptr, bytes.data(), size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		if (result < 0) {
			return {-1, Libs::Posix::POSIX_EAGAIN};
		}
		return PublishSysctlValue(output, length, capacity, bytes.data(), capacity);
#else
		return {-1, Libs::Posix::POSIX_ENOSYS};
#endif
	}
	if (count == 4 && mib[0] == 1 && mib[1] == 14 && mib[2] == 1) {
		const char* source   = "none";
		uint32_t    host_pid = 0;
		Reply       result {-1, Libs::Posix::POSIX_ENOSYS};
		// TODO: 13.60 handling of a new value (CTLFLAG_RD) not decoded
		if (input == nullptr) {
			const int exists =
			    LibKernel::Process::QueryGuestProcessExists(mib[3], &source, &host_pid);
			if (exists != 0) {
				result.posix_errno = LibKernel::KernelToPosix(exists);
			} else {
				// kinfo_proc is 0x448 bytes; only ki_structsize and ki_pid (+0x48) are set
				std::array<uint8_t, 0x448> record {};
				const int32_t              structsize = static_cast<int32_t>(record.size());
				std::memcpy(record.data(), &structsize, sizeof(structsize));
				std::memcpy(record.data() + 0x48, &mib[3], sizeof(mib[3]));
				result = PublishSysctlValue(output, length, capacity, record.data(), record.size());
			}
		}
		static std::atomic<uint32_t> logged {0};
		// always log failures - the watchdog acts on a live pid reading as gone
		if (logged.fetch_add(1) < 64 || result.value != 0) {
			LOGF("FIRST_FRAME_AUDIT KERN_PROC_PID caller_pid=%d caller_tid=%d pid=%d op=%s "
			     "out_capacity=%" PRIu64 " source=%s host_pid=%u result=%" PRId64
			     " errno=%d partial_record=%d fields=structsize,pid\n",
			     LibKernel::Process::GetPid(), LibKernel::PthreadGetthreadid(), mib[3],
			     input != nullptr    ? "write"
			     : output != nullptr ? "read"
			                         : "size",
			     capacity, source, host_pid, result.value, result.posix_errno,
			     result.value == 0 ? 1 : 0);
		}
		return result;
	}
	// userland_sysctl only takes newlen when new is non-null.
	const uint64_t new_len = input != nullptr ? input_len : 0;
	if (count == 4 && mib[0] == 1 && mib[1] == 14 && mib[2] == 0x51) {
		// K+0x5a9740 only moves 8 byte values. req->oldlen is *oldlenp even with a null old
		// pointer, and an untouched oldidx reports 0.
		bool published = false;
		int  result    = LibKernel::Budget::Builtin(
		    static_cast<uint32_t>(mib[3]), capacity, new_len,
		    [&](int64_t value) {
			    published = true;
			    return PublishSysctlValue(output, length, capacity, &value, sizeof(value)).value ==
				               0
			               ? 0
						   : Libs::Posix::POSIX_EFAULT;
		    },
		    [&](int64_t* value) {
			    return ReadSysctlMemory(input, value, sizeof(*value)) ? 0
				                                                      : Libs::Posix::POSIX_EFAULT;
		    });
		const uint64_t zero = 0;
		if (result == 0 && !published && length != nullptr &&
		    !WriteSysctlMemory(length, &zero, sizeof(zero)))
			result = Libs::Posix::POSIX_EFAULT;
		return result == 0 ? Reply {0, 0} : Reply {-1, result};
	}
	if (count == 4 && mib[0] == 1 && mib[1] == 14 && mib[2] == 35 && new_len == 0x98) {
		LibKernel::AppMount::Record kernel_record {};
		bool                        committed = false;
		const int                   access =
		    LibKernel::AppMount::GetAppInfo(mib[3], capacity, &kernel_record, &committed);
		if (access != 0) {
			return {-1, access};
		}
		// 0x9e930b50 copies the current record out before it copies the new one in.
		if (output != nullptr && capacity != 0 && !committed) {
			LOGF("APP_INFO_RECORD_UNKNOWN pid=%d caller=%d set_not_attempted\n", mib[3],
			     LibKernel::Process::GetPid());
			return {-1, Libs::Posix::POSIX_ENOSYS};
		}
		if (output != nullptr || length != nullptr) {
			const Reply result =
			    PublishSysctlValue(output, length, capacity, kernel_record.data(), capacity);
			if (result.value != 0) return result;
		}
		LibKernel::AppMount::Record record {};
		if (!ReadSysctlMemory(input, record.data(), record.size())) {
			return {LibKernel::KERNEL_ERROR_EFAULT, 0};
		}
		const int result = LibKernel::AppMount::SetAppInfo(mib[3], record);
		return result == 0 ? Reply {0, 0} : Reply {-1, result};
	}
	if (count == 4 && mib[0] == 1 && mib[1] == 14 && mib[2] == 35) {
		LibKernel::AppMount::Record kernel_record {};
		bool                        committed = false;
		const int                   access =
		    LibKernel::AppMount::GetAppInfo(mib[3], capacity, &kernel_record, &committed);
		if (access != 0) {
			return {-1, access};
		}
		if (committed) {
			return PublishSysctlValue(output, length, capacity, kernel_record.data(), capacity);
		}
		if (mib[3] != LibKernel::Process::GetPid()) {
			LOGF("APP_INFO_RECORD_UNKNOWN pid=%d caller=%d no_record_returned\n", mib[3],
			     LibKernel::Process::GetPid());
			return {-1, Libs::Posix::POSIX_ENOSYS};
		}
		if (output != nullptr && capacity > 0x58) {
			LOGF("APP_INFO_EXTENDED_UNIMPLEMENTED pid=%u requested=%" PRIu64
			     " no_partial_record_returned\n",
			     static_cast<uint32_t>(mib[3]), capacity);
			return {-1, Libs::Posix::POSIX_ENOSYS};
		}
		LibKernel::Process::PeerProcess peer {};
		if (!LibKernel::Process::FindPeerByPid(static_cast<int>(mib[3]), &peer)) {
			return {-1, Libs::Posix::POSIX_ESRCH};
		}
		if (!peer.has_category) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_APP_INFO_MISSING process"
			     " has no recovered category metadata\n");
			return {-1, Libs::Posix::POSIX_ENOENT};
		}
		std::array<uint8_t, 0x58> record {};
		std::memcpy(record.data() + 0x50, &peer.category, sizeof(peer.category));
		const Reply result =
		    PublishSysctlValue(output, length, capacity, record.data(), record.size());
		if (result.value == 0) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_APP_INFO_FROM_PROCESS"
			     " pid=%u category=0x%x size=0x%zx\n",
			     static_cast<uint32_t>(mib[3]), static_cast<unsigned>(peer.category),
			     record.size());
		}
		return result;
	}
	if (count == 4 && mib[0] == 1 && mib[1] == 14 && (mib[2] == 0x40 || mib[2] == 65)) {
		if (input != nullptr) {
			const auto facts = LibKernel::Process::GetCurrentAuthorizationFacts();
			if ((facts.known_capability0 & (1ull << 62)) == 0)
				return {-1, Libs::Posix::POSIX_ENOSYS};
			if ((facts.capability0 & (1ull << 62)) == 0) return {-1, Libs::Posix::POSIX_EPERM};
		}
		const uint64_t size     = mib[2] == 65 ? sizeof(LibKernel::AppMount::Record) : 8;
		const uint64_t copied   = output != nullptr ? std::min(capacity, size) : 0;
		const auto     transfer = [&](void* record, uint64_t write_size) {
			if (copied != 0 && !WriteSysctlMemory(output, record, copied))
				return Libs::Posix::POSIX_EFAULT;
			if (output != nullptr && capacity < size) return Libs::Posix::POSIX_ENOMEM;
			if (new_len == write_size && !ReadSysctlMemory(input, record, write_size))
				return Libs::Posix::POSIX_EFAULT;
			return 0;
		};
		int                     result   = 0;
		uint32_t                field_2c = 0;
		uint32_t                category = 0;
		std::array<char, 11>    title {};
		std::array<uint32_t, 2> observed_state {};
		if (mib[2] == 65) {
			result = LibKernel::AppMount::AppInfoById(
			    mib[3], capacity, new_len, [&](LibKernel::AppMount::Record& info) {
				    std::memcpy(&field_2c, info.data() + 0x2c, sizeof(field_2c));
				    std::memcpy(&category, info.data() + 0x50, sizeof(category));
				    std::memcpy(title.data(), info.data() + 0x10, 10);
				    return transfer(info.data(), info.size());
			    });
		} else {
			result = LibKernel::AppMount::AppState(
			    mib[3], capacity, new_len, [&](std::array<uint32_t, 2>& state) {
				    observed_state = state;
				    return transfer(state.data(), sizeof(uint32_t));
			    });
		}
		if ((result == 0 || result == Libs::Posix::POSIX_ENOMEM) && length != nullptr) {
			const uint64_t published = output != nullptr ? copied : size;
			if (!WriteSysctlMemory(length, &published, sizeof(published)))
				result = Libs::Posix::POSIX_EFAULT;
		}
		if (result == 0 && new_len == 0) {
			if (mib[2] == 65) {
				LOGF("APP_INFO_BY_ID caller=%d app_id=%d bytes=%" PRIu64
				     " field_2c=0x%x category=0x%x title=%.10s post_begin_eligible=%u "
				     "source=app_object_prefix\n",
				     LibKernel::Process::GetPid(), mib[3], copied, field_2c, category, title.data(),
				     field_2c != 0 && category < 0x20000 ? 1u : 0u);
			} else {
				LOGF("APP_STATE_QUERY caller=%d app_id=%d state=%u secondary=%u\n",
				     LibKernel::Process::GetPid(), mib[3], observed_state[0], observed_state[1]);
			}
		}
		return result == 0 ? Reply {0, 0} : Reply {-1, result};
	}
}
Reply SysAvNameStackGuard(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP") != nullptr) {
		static std::atomic<uint32_t> audio_name_trace_count {0};
		if (audio_name_trace_count.fetch_add(1) < 20) {
			LOGF("FIRST_FRAME_AUDIT AUDIOD_NATIVE_NAME_ABI"
			     " addr=0x%016" PRIx64 " len=0x%016" PRIx64 " name_ptr=0x%016" PRIx64 "\n",
			     request.args[0], request.args[1], request.args[2]);
		}
	}
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	if ((std::getenv("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP") != nullptr ||
	     LibKernel::Process::IsExecChild()) &&
	    request.args[0] >= 0x200000000ull && request.args[1] >= 0x4000 &&
	    (request.args[1] & 0x3fff) == 0 && request.args[2] >= 0x200000000ull &&
	    request.args[0] <= UINT64_MAX - request.args[1]) {
		const auto         addr          = request.args[0];
		const auto         size          = request.args[1];
		const auto         name_addr     = request.args[2];
		constexpr uint64_t name_capacity = LibKernel::Memory::KERNEL_MAXIMUM_NAME_LENGTH;
		LibKernel::Memory::VirtualQueryInfo target {};
		LibKernel::Memory::VirtualQueryInfo name_region {};
		if (name_addr > UINT64_MAX - name_capacity ||
		    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(addr), 0, &target,
		                                          sizeof(target)) != 0 ||
		    !target.is_committed || target.start > addr || target.end < addr + size ||
		    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(name_addr), 0,
		                                          &name_region, sizeof(name_region)) != 0 ||
		    !name_region.is_committed || !(name_region.protection & 1u) ||
		    name_region.start > name_addr || name_region.end < name_addr + name_capacity) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		const auto* name = reinterpret_cast<const char*>(name_addr);
		if (std::memchr(name, 0, name_capacity) == nullptr) {
			return {-1, Libs::Posix::POSIX_ENAMETOOLONG};
		}
		const int rc = LibKernel::Memory::KernelSetVirtualRangeName(
		    reinterpret_cast<const void*>(addr), size, name);
		if (rc != 0) return {-1, LibKernel::KernelToPosix(rc)};
		LOGF("FIRST_FRAME_AUDIT AUDIOD_NATIVE_FLEX_MAPPING_NAMED"
		     " addr=0x%016" PRIx64 " size=0x%016" PRIx64 " guest_name=%s committed_guest_range\n",
		     addr, size, name);
		return {0, 0};
	}
}
Reply SysAvNameScaninBuffer(const SyscallRequest& request) {
	constexpr char name[] = "SceSysAvControlScanInBuf";
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[1] != 0x6000000 || request.args[2] != 0x4c3c97 ||
	    request.args[0] < 0x200000000ull || request.args[0] > 0x300000000ull) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	LibKernel::Memory::VirtualQueryInfo target {};
	LibKernel::Memory::VirtualQueryInfo original_name {};
	const uint64_t                      end = request.args[0] + request.args[1];
	if (end < request.args[0] ||
	    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(request.args[0]), 0,
	                                          &target, sizeof(target)) != 0 ||
	    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(request.args[2]), 0,
	                                          &original_name, sizeof(original_name)) != 0 ||
	    !target.is_committed || target.start > request.args[0] || target.end < end ||
	    (target.protection & 1u) == 0 || !original_name.is_committed ||
	    original_name.start > request.args[2] ||
	    original_name.end < request.args[2] + sizeof(name) ||
	    (original_name.protection & 1u) == 0 ||
	    std::memcmp(reinterpret_cast<const void*>(request.args[2]), name, sizeof(name)) != 0) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	const int rc = LibKernel::Memory::KernelSetVirtualRangeName(
	    reinterpret_cast<const void*>(request.args[0]), request.args[1], name);
	if (rc != 0) {
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_SCANIN_BUFFER_NAMED"
	     " mapped_guest_address=0x%016" PRIx64 " length=0x%016" PRIx64 " guest_name=%s\n",
	     request.args[0], request.args[1], name);
	return {0, 0};
}
Reply SysAvControlShmClose(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[0] < 3 || request.args[0] > INT32_MAX) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const int fd = static_cast<int>(request.args[0]);
	if (LibKernel::FileSystem::IsNativeAvDescriptor(fd) ||
	    LibKernel::FileSystem::IsIccnvs4SnapshotDescriptor(fd) ||
	    LibKernel::FileSystem::PinNativeMbusReceiveQueue(fd) != nullptr) {
		const int rc = LibKernel::FileSystem::KernelClose(fd);
		return rc == 0 ? Reply {0, 0} : Reply {-1, LibKernel::KernelToPosix(rc)};
	}
	size_t size = 0;
	if (!LibKernel::FileSystem::GetSharedMemorySize(fd, &size) || size != 0x2000) {
		return {-1, Libs::Posix::POSIX_EBADF};
	}
	const int rc = LibKernel::FileSystem::KernelClose(fd);
	if (rc != 0) {
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_SHM_CLOSE"
	     " guest_fd=%d descriptor_released_through_FileSystem\n",
	     fd);
	return {0, 0};
}
struct SysAvIpmiServer {
	std::string service_name;
	uint64_t    original_guest_server  = 0;
	uint64_t    original_guest_config  = 0;
	uint32_t    owner_pid              = 0;
	int64_t     registered_event_queue = 0;
	uint32_t    notification_limit     = 0;
	// TODO: no client message producer yet
	std::deque<std::vector<uint8_t>> pending_requests;
};
static std::mutex                                    g_sysav_ipmi_lock;
static std::condition_variable                       g_sysav_ipmi_message_cv;
static std::unordered_map<uint32_t, SysAvIpmiServer> g_sysav_ipmi_servers;
Reply SysAvIpmiManagerCall(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_ORIGINAL_SYSCORE_APP_IPMI") != nullptr) {
		if (request.args[0] > UINT32_MAX ||
		    (request.args[1] != 0 && !OriginalNativeHandle32IsCanonical(request.args[1]))) {
			return {-1, Libs::Posix::POSIX_EINVAL};
		}
		int        status  = -1;
		const bool handled = LibKernel::IpmiManager::TryCall(
		    static_cast<uint32_t>(request.args[0]), static_cast<int32_t>(request.args[1]),
		    reinterpret_cast<int32_t*>(request.args[2]), reinterpret_cast<void*>(request.args[3]),
		    request.args[4], request.args[5], &status);
		if (!handled) return {-1, Libs::Posix::POSIX_ENOSYS};
		LOGF("NATIVE_IPMI_SHARED_ADAPTER command=0x%" PRIx64 " pid=%d handle=0x%" PRIx64
		     " transport=%d\n",
		     request.args[0], LibKernel::Process::GetPid(), request.args[1], status);
		return {status, status == -1 ? *Libs::Posix::GetErrorAddr() : 0};
	}
	const bool create_server =
	    request.args[0] == 0 && request.args[1] == 0 && request.args[4] == 0x18;
	const bool following_ipmi_call = request.args[0] == 0x10 && request.args[1] >= 0x1f00 &&
	                                 request.args[1] <= 0x1f05 && request.args[4] == 0x40;
	const bool create_client =
	    request.args[0] == 2 && request.args[1] == 0 && request.args[4] == 0x18;
	const bool client_control = request.args[0] == 0x400 && request.args[1] > 0 &&
	                            request.args[1] <= UINT32_MAX && request.args[4] == 0x20;
	const bool destroy_client = request.args[0] == 3 && request.args[1] > 0 &&
	                            request.args[1] <= UINT32_MAX && request.args[3] == 0 &&
	                            request.args[4] == 0;
	const bool original_client_followup =
	    request.args[0] == 0x46b && request.args[4] == sizeof(uint64_t);
	const bool failed_server_name = request.args[0] == 0x46a && request.args[1] == 0x8002004e &&
	                                request.args[4] == sizeof(uint64_t);
	const bool receive_packet_201 =
	    request.args[0] == 0x201 && request.args[1] != 0 && request.args[4] == 0x20;
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    (!create_server && !following_ipmi_call && !create_client && !client_control &&
	     !destroy_client && !original_client_followup && !failed_server_name &&
	     !receive_packet_201)) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	if (following_ipmi_call) {
		if (!ValidateSysctlSpan(reinterpret_cast<const void*>(request.args[3]), 0x40, false) ||
		    !ValidateSysctlSpan(reinterpret_cast<void*>(request.args[2]), sizeof(uint32_t), true)) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		const uint32_t operation_result = 0;
		if (!WriteSysctlMemory(reinterpret_cast<void*>(request.args[2]), &operation_result,
		                       sizeof(operation_result))) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_IPMI_TRACE"
		     " suboperation=0x%04" PRIx64 " record_bytes=0x40 result=0 nonblocking\n",
		     request.args[1]);
		return {0, 0};
	}
}
enum class ExecutableImageKind {
	Invalid,
	Self,
	Elf,
};
ExecutableImageKind ExecutableImageHeaderKind(const uint8_t* data, size_t size, uint64_t file_size,
                                              size_t* required_bytes = nullptr) {
	if (required_bytes != nullptr) *required_bytes = 0;
	if (data == nullptr || size < 4 || file_size < 4) return ExecutableImageKind::Invalid;
	const bool self = data[0] == 0x54 && data[1] == 0x14 && data[2] == 0xf5 && data[3] == 0xee;
	const bool elf  = data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F';
	if (self) {
		if (size < sizeof(Loader::SelfHeader) || file_size < sizeof(Loader::SelfHeader)) {
			return ExecutableImageKind::Invalid;
		}
		Loader::SelfHeader header {};
		std::memcpy(&header, data, sizeof(header));
		const uint64_t segment_bytes = uint64_t {header.segments_num} * sizeof(Loader::SelfSegment);
		const uint64_t elf_offset    = sizeof(header) + segment_bytes;
		if (header.file_size != file_size || header.size1 > file_size ||
		    header.size2 > file_size - header.size1 || elf_offset > header.size1 ||
		    sizeof(Loader::Elf64_Ehdr) > header.size1 - elf_offset) {
			return ExecutableImageKind::Invalid;
		}
		const size_t prefix_size = static_cast<size_t>(elf_offset + sizeof(Loader::Elf64_Ehdr));
		if (required_bytes != nullptr) *required_bytes = prefix_size;
		if (size < prefix_size) return ExecutableImageKind::Self;
		for (uint16_t i = 0; i != header.segments_num; ++i) {
			Loader::SelfSegment segment {};
			std::memcpy(&segment, data + sizeof(header) + uint64_t {i} * sizeof(segment),
			            sizeof(segment));
			if (segment.offset > file_size ||
			    segment.compressed_size > file_size - segment.offset) {
				return ExecutableImageKind::Invalid;
			}
		}
		const auto         elf_size = static_cast<size_t>(header.size1 - elf_offset);
		const auto*        elf_data = data + elf_offset;
		Loader::Elf64_Ehdr elf_header {};
		std::memcpy(&elf_header, elf_data, sizeof(elf_header));
		if (std::memcmp(elf_header.e_ident, "\177ELF", 4) != 0 ||
		    elf_header.e_ident[Loader::EI_CLASS] != Loader::ELFCLASS64 ||
		    elf_header.e_ident[Loader::EI_DATA] != Loader::ELFDATA2LSB ||
		    elf_header.e_ehsize != sizeof(elf_header) ||
		    elf_header.e_phentsize != sizeof(Loader::Elf64_Phdr) || elf_header.e_phnum == 0) {
			return ExecutableImageKind::Invalid;
		}
		const uint64_t table_size = uint64_t {elf_header.e_phnum} * sizeof(Loader::Elf64_Phdr);
		if (elf_header.e_phoff < sizeof(elf_header) || elf_header.e_phoff > elf_size ||
		    table_size > elf_size - elf_header.e_phoff) {
			return ExecutableImageKind::Invalid;
		}
		return ExecutableImageKind::Self;
	}
	if (elf) {
		if (size < sizeof(Loader::Elf64_Ehdr) || file_size < sizeof(Loader::Elf64_Ehdr)) {
			return ExecutableImageKind::Invalid;
		}
		Loader::Elf64_Ehdr header {};
		std::memcpy(&header, data, sizeof(header));
		if (header.e_ident[Loader::EI_CLASS] != Loader::ELFCLASS64 ||
		    header.e_ident[Loader::EI_DATA] != Loader::ELFDATA2LSB ||
		    header.e_ehsize != sizeof(header) || header.e_phentsize != sizeof(Loader::Elf64_Phdr) ||
		    header.e_phnum == 0) {
			return ExecutableImageKind::Invalid;
		}
		const uint64_t table_size = uint64_t {header.e_phnum} * sizeof(Loader::Elf64_Phdr);
		if (header.e_phoff < sizeof(header) || header.e_phoff > file_size ||
		    table_size > file_size - header.e_phoff) {
			return ExecutableImageKind::Invalid;
		}
		if (required_bytes != nullptr) *required_bytes = sizeof(header);
		return ExecutableImageKind::Elf;
	}
	return ExecutableImageKind::Invalid;
}
Reply SyscoreNativeRdup(const SyscallRequest& request) {
	if (request.number != 0x25b ||
	    (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD") == nullptr &&
	     std::getenv("KYTY_DIAGNOSTIC_MINI_SYSCORE_LIVE_RFORK") == nullptr)) {
		return {LibKernel::KERNEL_ERROR_ENOSYS, 0};
	}
	if (request.args[0] > INT32_MAX || request.args[1] > INT32_MAX) {
		return {-1, Libs::Posix::POSIX_EBADF};
	}
	const int fd = LibKernel::FileSystem::DuplicateParentSocketForRdup(
	    static_cast<int>(request.args[0]), static_cast<int>(request.args[1]));
	return fd >= 0 ? Reply {fd, 0} : Reply {-1, LibKernel::KernelToPosix(fd)};
}
Reply SysAvNativeKqueue(const SyscallRequest& request) {
	if (request.number != 0x16a ||
	    (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr &&
	     std::getenv("KYTY_DIAGNOSTIC_SYSCORE_NATIVE_KQUEUE_BACKEND") == nullptr)) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const int fd = LibKernel::FileSystem::CreateNativeKqueueDescriptor();
	if (fd < 0) {
		return {-1, LibKernel::KernelToPosix(fd)};
	}
	if (fd < 3) {
		return {-1, Libs::Posix::POSIX_EBADF};
	}
	return {fd, 0};
}
Reply NativeKeventChanges(const SyscallRequest& request) {
	using namespace LibKernel::EventQueue;
	int64_t queue = 0;
	if (request.args[0] > INT32_MAX || !LibKernel::FileSystem::ResolveNativeKqueueDescriptor(
	                                       static_cast<int>(request.args[0]), &queue)) {
		return {-1, Libs::Posix::POSIX_EBADF};
	}
	const auto count = request.args[2];
	if (count == 0 || count > 8) return {-1, Libs::Posix::POSIX_ENOSYS};
	std::array<KernelEvent, 64> changes {};
	if (!LibKernel::Memory::CopyFromGuest(changes.data(),
	                                      reinterpret_cast<const void*>(request.args[1]),
	                                      count * sizeof(KernelEvent))) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	for (size_t i = 0; i != count; ++i) {
		const auto& change  = changes[i];
		bool        modeled = false;
		if (change.filter == KERNEL_EVFILT_NOTIFY) {
			modeled =
			    change.flags == 1 && change.fflags == 0 && change.data >= 0 && change.data <= 255;
		} else if (change.filter == KERNEL_EVFILT_USER) {
			modeled = change.ident <= INT32_MAX && change.flags == 0x21 && change.fflags == 0;
		} else if (change.filter == KERNEL_EVFILT_READ && change.flags == 1 && change.fflags == 0 &&
		           change.data == 0 && change.ident <= INT32_MAX) {
			const int fd     = static_cast<int>(change.ident);
			int64_t   nested = 0;
			modeled          = LibKernel::FileSystem::GetDescriptorFlags(fd) < 0 ||
			                   LibKernel::FileSystem::PinGuestSocketReadSource(fd) != nullptr ||
			                   LibKernel::FileSystem::PinNativeMbusReceiveQueue(fd) != nullptr ||
			                   LibKernel::FileSystem::ResolveNativeKqueueDescriptor(fd, &nested);
		}
		if (!modeled) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_KEVENT5_UNMODELED_CHANGE queue=%" PRId64 " index=%zu"
			     " ident=%" PRIuPTR " filter=%d flags=0x%04x fflags=0x%08x data=%" PRIdPTR
			     " udata=0x%016" PRIxPTR " nothing_applied\n",
			     queue, i, change.ident, change.filter, change.flags, change.fflags, change.data,
			     reinterpret_cast<uintptr_t>(change.udata));
			return {-1, Libs::Posix::POSIX_ENOSYS};
		}
	}
	for (size_t i = 0; i != count; ++i) {
		const auto& change = changes[i];
		int         rc     = 0;
		LOGF("NATIVE_KEVENT_CHANGE guest_pid=%d queue=%" PRId64 " index=%zu ident=%" PRIuPTR
		     " filter=%d flags=0x%x fflags=0x%x data=%" PRIdPTR " udata=0x%" PRIxPTR "\n",
		     LibKernel::Process::GetPid(), queue, i, change.ident, change.filter, change.flags,
		     change.fflags, change.data, reinterpret_cast<uintptr_t>(change.udata));
		if (change.filter == KERNEL_EVFILT_NOTIFY) {
			rc = KernelAddNativeNotificationEvent(queue, change);
		} else if (change.filter == KERNEL_EVFILT_USER) {
			rc = KernelAddOriginalNativeUserEvent(queue, change);
		} else if (LibKernel::FileSystem::GetDescriptorFlags(static_cast<int>(change.ident)) < 0) {
			rc = LibKernel::KERNEL_ERROR_EBADF;
		} else {
			rc = KernelAddReadEvent(queue, static_cast<int>(change.ident), 0, change.udata);
		}
		if (rc != 0) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_KEVENT5_CHANGE_FAILED queue=%" PRId64 " index=%zu"
			     " ident=%" PRIuPTR " filter=%d error=0x%08x earlier_changes_kept=%zu\n",
			     queue, i, change.ident, change.filter, static_cast<uint32_t>(rc), i);
			return {-1, LibKernel::KernelToPosix(rc)};
		}
	}
	LOGF("NATIVE_KEVENT_CHANGES_REGISTERED guest_fd=%" PRIu64 " queue=%" PRId64 " count=%" PRIu64
	     " nothing_triggered\n",
	     request.args[0], queue, count);
	return {0, 0};
}
Reply NativeKeventWait(const SyscallRequest& request) {
	using namespace LibKernel::EventQueue;
	int64_t queue = 0;
	if (request.args[0] > INT32_MAX || !LibKernel::FileSystem::ResolveNativeKqueueDescriptor(
	                                       static_cast<int>(request.args[0]), &queue)) {
		return {-1, Libs::Posix::POSIX_EBADF};
	}
	const auto count = request.args[4];
	if (count == 0 || count > 64) return {-1, Libs::Posix::POSIX_ENOSYS};
	auto* output = reinterpret_cast<KernelEvent*>(request.args[3]);
	if (!LibKernel::Memory::CanWriteGuest(output, count * sizeof(KernelEvent))) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	LibKernel::KernelUseconds timeout = 0;
	if (request.args[5] != 0) {
		LibKernel::KernelTimespec ts {};
		if (!LibKernel::Memory::CopyFromGuest(&ts, reinterpret_cast<const void*>(request.args[5]),
		                                      sizeof(ts))) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000 ||
		    static_cast<uint64_t>(ts.tv_sec) > UINT32_MAX / 1000000ull) {
			return {-1, Libs::Posix::POSIX_EINVAL};
		}
		const auto micros = static_cast<uint64_t>(ts.tv_sec) * 1000000ull +
		                    (static_cast<uint64_t>(ts.tv_nsec) + 999) / 1000;
		if (micros > UINT32_MAX) return {-1, Libs::Posix::POSIX_EINVAL};
		timeout = static_cast<LibKernel::KernelUseconds>(micros);
	}
	std::array<KernelEvent, 64> events {};
	int                         received = 0;
	const int rc = KernelWaitEqueue(queue, events.data(), static_cast<int>(count), &received,
	                                request.args[5] != 0 ? &timeout : nullptr);
	if (rc == LibKernel::KERNEL_ERROR_ETIMEDOUT) return {0, 0};
	if (rc != 0) return {-1, LibKernel::KernelToPosix(rc)};
	for (int i = 0; i < received; ++i)
		events[i].flags &= 0xfef0u;
	if (received != 0 &&
	    !LibKernel::Memory::CopyToGuest(output, events.data(), received * sizeof(KernelEvent))) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	if (std::getenv("KYTY_DIAGNOSTIC_GUEST_SOCKET_IO")) {
		static std::atomic_uint32_t logged {0};
		for (int i = 0; i < received; ++i) {
			if (events[i].filter != KERNEL_EVFILT_READ || events[i].ident > INT32_MAX ||
			    !LibKernel::FileSystem::PinGuestSocketReadSource(static_cast<int>(events[i].ident)))
				continue;
			if (logged.fetch_add(1) >= 64) break;
			const auto& event = events[i];
			LOGF("NATIVE_KEVENT_OUTPUT guest_pid=%d guest_fd=%" PRIu64 " queue=%" PRId64
			     " index=%d ident=%" PRIuPTR " filter=%d flags=0x%x fflags=0x%x data=%" PRIdPTR
			     " udata=0x%" PRIxPTR " guest_output=1\n",
			     LibKernel::Process::GetPid(), request.args[0], queue, i, event.ident, event.filter,
			     event.flags, event.fflags, event.data, reinterpret_cast<uintptr_t>(event.udata));
		}
	}
	return {received, 0};
}
Reply RegMgrCall(const SyscallRequest& request) {
	// 0x214 (op, key, int* status, void* value, size); *status is the answer when the call returns
	// 0. Only what the guest stored this run reads back
	static const bool store = std::getenv("KYTY_DIAGNOSTIC_REGMGR_SESSION_STORE") != nullptr;
	static std::mutex mutex;
	static std::unordered_map<uint32_t, int32_t>              ints;
	static std::unordered_map<uint32_t, std::vector<uint8_t>> bins;
	const auto                                                op = request.args[0];
	const auto  key    = static_cast<uint32_t>(request.args[1]);
	auto*       status = reinterpret_cast<int32_t*>(request.args[2]);
	auto*       value  = reinterpret_cast<int32_t*>(request.args[3]);
	const auto  size   = request.args[4];
	Reply       reply {-1, Libs::Posix::POSIX_ENOSYS};
	const char* source   = "unanswered";
	int32_t     answered = 0;
	// one line per distinct (op, key, size, outcome) - op 7 polls constantly
	auto audit = [&] {
		static std::mutex                                log_mutex;
		static std::unordered_map<std::string, uint32_t> seen;
		const bool kernel = std::strcmp(source, "kernel_13.60_snapshot") == 0;
		// Ops 0 and 0x12 return the registry value itself (version dword, region id) as the status.
		char status_text[16] = "withheld";
		if (!kernel || (op != 0 && op != 0x12) || answered < 0)
			std::snprintf(status_text, sizeof(status_text), "0x%08x",
			              static_cast<uint32_t>(answered));
		char line[192];
		std::snprintf(line, sizeof(line),
		              "op=%" PRIu64 " key=0x%08x size=%" PRIu64 " rc=%" PRId64
		              " errno=%d status=%s source=%s store=%d%s",
		              op, key, size, reply.value, reply.posix_errno, status_text, source,
		              store ? 1 : 0, kernel ? "" : " NON_AUTHENTIC");
		std::lock_guard lock(log_mutex);
		if (seen[line]++ == 0)
			LOGF("FIRST_FRAME_AUDIT REGMGR %s pid=%d\n", line, LibKernel::Process::GetPid());
	};
}
Reply GuestChdir(const SyscallRequest& request) {
	LOGF("SYSCORE_APP_SPAWN chdir pid=%d path=0x%" PRIx64 " result=0\n",
	     LibKernel::Process::GetPid(), request.args[0]);
	return {0, 0};
}
Reply GuestChroot(const SyscallRequest& request) {
	std::string root;
	const int   rc =
	    ReadExecveGuestString(request.args[0], 1024, LibKernel::KERNEL_ERROR_ENAMETOOLONG, &root);
	LOGF("SYSCORE_APP_SPAWN chroot pid=%d path=0x%" PRIx64 " root=%s result=0x%x\n",
	     LibKernel::Process::GetPid(), request.args[0], rc == 0 ? root.c_str() : "", rc);
	if (rc != 0) return {-1, LibKernel::KernelToPosix(rc)};
	// the root becomes the child's / at execve; the child imports the sandbox mounts published
	// under it
	LibKernel::Process::RecordSpawnSandbox(LibKernel::Process::GetPid(), &root, nullptr);
	return {0, 0};
}
struct NativeEventFlag {
	LibKernel::EventFlag::KernelEventFlag flag;
	int                                   owner;
	bool                                  creator;
	std::string                           name;
};
std::mutex                                    g_native_event_lock;
std::unordered_map<uint32_t, NativeEventFlag> g_native_event_flags;
uint32_t                                      g_native_event_next = 0;
bool UseNativeEventFlags() {
	return std::getenv("KYTY_DIAGNOSTIC_MINI_SYSCORE_NATIVE_TRAPS") != nullptr ||
	       (LibKernel::Process::IsExecChild() &&
	        std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") != nullptr);
}
Reply NativeEventFlagOperation(const SyscallRequest& request) {
	using namespace LibKernel::EventFlag;
	std::unique_lock lock(g_native_event_lock);
	const int        owner = LibKernel::Process::GetPid();
	if (request.number == 0x21a || request.number == 0x21c) {
		std::string name;
		const int   error =
		    ReadExecveGuestString(request.args[0], 32, LibKernel::KERNEL_ERROR_ENAMETOOLONG, &name);
		if (error != 0) return {-1, LibKernel::KernelToPosix(error)};
		if (name.empty()) return {-1, Libs::Posix::POSIX_EINVAL};
		const bool create = request.number == 0x21a;
		if (create && (request.args[1] > UINT32_MAX || (request.args[1] & 0x100) == 0)) {
			return {-1, Libs::Posix::POSIX_ENOSYS};
		}
		if (g_native_event_next >= 0x3fffffffu) return {-1, Libs::Posix::POSIX_EAGAIN};
		KernelEventFlag flag = nullptr;
		const int       rc = create ? KernelCreateEventFlag(&flag, name.c_str(),
		                                                    static_cast<uint32_t>(request.args[1]),
		                                                    request.args[2], nullptr)
		                            : KernelOpenExistingEventFlag(&flag, name.c_str());
		if (rc != 0) return {-1, LibKernel::KernelToPosix(rc)};
		++g_native_event_next;
		g_native_event_flags.emplace(g_native_event_next,
		                             NativeEventFlag {flag, owner, create, name});
		LOGF("NATIVE_EVENTFLAG_HANDLE pid=%d id=%u name=%s create=%d initial=0x%llx attr=0x%llx\n",
		     owner, g_native_event_next, name.c_str(), create ? 1 : 0,
		     static_cast<unsigned long long>(create ? request.args[2] : 0),
		     static_cast<unsigned long long>(create ? request.args[1] : 0));
		return {g_native_event_next, 0};
	}
	if (request.args[0] > INT32_MAX) return {-1, Libs::Posix::POSIX_ESRCH};
	const auto found = g_native_event_flags.find(static_cast<uint32_t>(request.args[0]));
	if (found == g_native_event_flags.end() || found->second.owner != owner) {
		return {-1, Libs::Posix::POSIX_ESRCH};
	}
	const auto handle = found->second;
	int        rc     = LibKernel::KERNEL_ERROR_ENOSYS;
	if (request.number == 0x21b || request.number == 0x21d) {
		rc = request.number == 0x21b ? KernelDeleteEventFlag(handle.flag)
		                             : KernelCloseEventFlag(handle.flag);
		if (rc == 0) g_native_event_flags.erase(found);
		LOGF("NATIVE_EVENTFLAG_RELEASE pid=%d id=%llu name=%s delete=%d result=0x%08x\n", owner,
		     static_cast<unsigned long long>(request.args[0]), handle.name.c_str(),
		     handle.creator ? 1 : 0, static_cast<uint32_t>(rc));
	} else if (request.number == 0x220 || request.number == 0x221) {
		rc = request.number == 0x220 ? KernelSetEventFlag(handle.flag, request.args[1])
		                             : KernelClearEventFlag(handle.flag, request.args[1]);
		static std::atomic<uint32_t> changes {0};
		if (changes.fetch_add(1) < 256) {
			LOGF("NATIVE_EVENTFLAG_CHANGE pid=%d id=%llu name=%s operation=%s pattern=0x%llx "
			     "result=0x%08x\n",
			     owner, static_cast<unsigned long long>(request.args[0]), handle.name.c_str(),
			     request.number == 0x220 ? "set" : "clear",
			     static_cast<unsigned long long>(request.args[1]), static_cast<uint32_t>(rc));
		}
	} else if (request.number == 0x21e || request.number == 0x21f) {
		const uint64_t mode = request.args[2];
		if ((mode & ~uint64_t(0x3f)) != 0 || ((mode & 0xf) != 1 && (mode & 0xf) != 2) ||
		    (mode & 0x30) == 0x30 || request.args[1] == 0)
			return {-1, Libs::Posix::POSIX_EINVAL};
		uint64_t                  pattern = 0;
		LibKernel::KernelUseconds timeout = 0;
		if (request.args[3] != 0 &&
		    !LibKernel::Memory::CanWriteGuest(reinterpret_cast<void*>(request.args[3]),
		                                      sizeof(pattern))) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		const bool wait = request.number == 0x21e;
		if (wait && request.args[4] != 0 &&
		    (!LibKernel::Memory::CanWriteGuest(reinterpret_cast<void*>(request.args[4]),
		                                       sizeof(timeout)) ||
		     !ReadExecveGuestMemory(request.args[4], &timeout, sizeof(timeout))))
			return {-1, Libs::Posix::POSIX_EFAULT};
		if (wait) {
			std::string scope;
			if (!LibKernel::Process::GetScope(&scope)) return {-1, Libs::Posix::POSIX_ENOSYS};
			lock.unlock();
			rc = KernelWaitEventFlag(handle.flag, request.args[1], static_cast<uint32_t>(mode),
			                         &pattern, request.args[4] != 0 ? &timeout : nullptr);
		} else {
			rc = KernelPollEventFlag(handle.flag, request.args[1], static_cast<uint32_t>(mode),
			                         &pattern);
		}
		if (request.args[3] != 0 &&
		    !LibKernel::Memory::CopyToGuest(reinterpret_cast<void*>(request.args[3]), &pattern,
		                                    sizeof(pattern))) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		if (wait && request.args[4] != 0 &&
		    !LibKernel::Memory::CopyToGuest(reinterpret_cast<void*>(request.args[4]), &timeout,
		                                    sizeof(timeout))) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		LOGF("NATIVE_EVENTFLAG_WAIT_RESULT pid=%d id=%llu wait=%d requested=0x%llx actual=0x%llx "
		     "result=0x%08x\n",
		     owner, static_cast<unsigned long long>(request.args[0]), wait ? 1 : 0,
		     static_cast<unsigned long long>(request.args[1]),
		     static_cast<unsigned long long>(pattern), static_cast<uint32_t>(rc));
	}
	return rc == 0 ? Reply {0, 0} : Reply {-1, LibKernel::KernelToPosix(rc)};
}
struct NativeNamedObject {
	std::string name;
	uint64_t    object;
	uint32_t    type;
};
struct NativeNamedRegistry {
	uint32_t                                        next = 0;
	std::unordered_map<uint32_t, NativeNamedObject> objects;
};
std::mutex                                   g_native_named_lock;
std::unordered_map<int, NativeNamedRegistry> g_native_named_objects;
Reply NativeNamedObjectOperation(const SyscallRequest& request) {
	const uint32_t type = static_cast<uint16_t>(
	    (request.number == 0x22d ? request.args[2] : request.args[1]) | 0x1000u);
	const int       owner = LibKernel::Process::GetPid();
	std::lock_guard lock(g_native_named_lock);
	if (request.number == 0x22e) {
		if (request.args[0] > 0xfffe) return {-1, Libs::Posix::POSIX_ESRCH};
		const auto registry = g_native_named_objects.find(owner);
		if (registry == g_native_named_objects.end()) return {-1, Libs::Posix::POSIX_ESRCH};
		const auto found = registry->second.objects.find(static_cast<uint32_t>(request.args[0]));
		if (found == registry->second.objects.end() || found->second.type != type) {
			return {-1, Libs::Posix::POSIX_ESRCH};
		}
		registry->second.objects.erase(found);
		return {0, 0};
	}
	if (request.args[0] == 0) return {-1, Libs::Posix::POSIX_EINVAL};
	std::string name;
	const int   rc =
	    ReadExecveGuestString(request.args[0], 32, LibKernel::KERNEL_ERROR_ENAMETOOLONG, &name);
	if (rc != 0) return {-1, LibKernel::KernelToPosix(rc)};
	auto& registry = g_native_named_objects[owner];
	if (registry.objects.size() >= 0xfffe) return {-1, Libs::Posix::POSIX_EAGAIN};
	do {
		registry.next = registry.next % 0xfffe + 1;
	} while (registry.objects.contains(registry.next));
	registry.objects.emplace(registry.next, NativeNamedObject {name, request.args[1], type});
	LOGF("NATIVE_NAMED_OBJECT_REGISTERED pid=%d name=%s id=%u object=0x%llx type=0x%x "
	     "opaque_object_word=1\n",
	     owner, name.c_str(), registry.next, static_cast<unsigned long long>(request.args[1]),
	     type);
	return {registry.next, 0};
}
Reply NamedObject(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_MINI_SYSCORE_NATIVE_TRAPS") != nullptr ||
	    LibKernel::Process::IsExecChild()) {
		return NativeNamedObjectOperation(request);
	}
	// 0x22d (name, object, type) / 0x22e (id, type). The 16-bit id sits beside the type (mutex
	// +0x3c, semaphore +2) and comes back on destroy; sceKernelDeleteEqueue reads errno 3 as
	// already gone.
	static const bool table = std::getenv("KYTY_DIAGNOSTIC_NAMEDOBJ_ID_TABLE") != nullptr;
	static std::mutex mutex;
	static std::unordered_map<uint32_t, uint32_t> types;
	static std::unordered_map<uint32_t, int64_t>  named_live_equeues;
	static uint32_t                               last = 0;
	static std::atomic<uint32_t>                  count {0};
	static std::atomic<uint32_t>                  failures {0};
	if (!table) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const bool      trace = count.fetch_add(1) < 512;
	std::lock_guard lock(mutex);
	if (request.number == 0x22e) {
		const auto id    = static_cast<uint32_t>(request.args[0]);
		const auto found = types.find(id);
		if (found == types.end()) {
			if (failures.fetch_add(1) < 64) {
				LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_NAMEDOBJ delete id=%u type=0x%x is not in the "
				     "table, ESRCH NON_AUTHENTIC\n",
				     id, static_cast<uint32_t>(request.args[1]));
			}
			return {-1, Libs::Posix::POSIX_ESRCH};
		}
		if (trace) {
			LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_NAMEDOBJ delete id=%u type=0x%x created=0x%x "
			     "NON_AUTHENTIC\n",
			     id, static_cast<uint32_t>(request.args[1]), found->second);
		}
		types.erase(found);
		named_live_equeues.erase(id);
		return {0, 0};
	}
	const auto* name = reinterpret_cast<const char*>(request.args[0]);
	const auto  type = static_cast<uint32_t>(request.args[2]);
	if (name == nullptr) {
		if (failures.fetch_add(1) < 64) {
			LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_NAMEDOBJ create object=0x%" PRIx64
			     " type=0x%x has no name, EFAULT NON_AUTHENTIC\n",
			     request.args[1], type);
		}
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	int64_t real_backing_queue = 0;
	if (type == 0x107) {
		// splash 0x439610 names its kqueue; naming must not signal it
		if (request.args[1] > INT32_MAX || std::strcmp(name, "SceAvControlSplash") != 0 ||
		    !LibKernel::FileSystem::ResolveNativeKqueueDescriptor(static_cast<int>(request.args[1]),
		                                                          &real_backing_queue)) {
			return {-1, Libs::Posix::POSIX_EINVAL};
		}
	}
	if (types.size() >= 0xfffe) {
		if (failures.fetch_add(1) < 64) {
			LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_NAMEDOBJ create name=%s type=0x%x has no free "
			     "16-bit id, EAGAIN NON_AUTHENTIC\n",
			     name, type);
		}
		return {-1, Libs::Posix::POSIX_EAGAIN};
	}
	do {
		last = last % 0xfffe + 1;
	} while (types.count(last) != 0);
	types[last] = type;
	if (type == 0x107) {
		named_live_equeues[last] = real_backing_queue;
		LOGF("FIRST_FRAME_AUDIT SYSAV_SPLASH_NAMED_EQUEUE_BACKING"
		     " fd=%" PRIu64 " queue=%" PRId64 " process_local_name_id=%u\n",
		     request.args[1], real_backing_queue, last);
	}
	if (trace) {
		LOGF(
		    "FIRST_FRAME_AUDIT DIAGNOSTIC_NAMEDOBJ create name=%s object=0x%" PRIx64
		    " type=0x%x id=%u process-local id table, no kernel registry behind it NON_AUTHENTIC\n",
		    name, request.args[1], type, last);
	}
	return {last, 0};
}
} // namespace
bool ShouldLogMiniSyscallTrace(uint64_t ordinal) {
	return ordinal != 0 && (ordinal <= 64 || (ordinal & (ordinal - 1)) == 0);
}
Reply PreflightSyscoreExecve(const SyscallRequest& request) {
	return SyscoreExecvePreflight(request);
}
int WaitForImportedGuestIpmiServerRequest(uint32_t server_id, uint64_t capacity) {
	if (server_id == 0 || capacity == 0 || capacity > 0x10000) {
		return LibKernel::KERNEL_ERROR_EINVAL;
	}
	std::unique_lock lock(g_sysav_ipmi_lock);
	auto             it = g_sysav_ipmi_servers.find(server_id);
	if (it == g_sysav_ipmi_servers.end()) {
		return LibKernel::KERNEL_ERROR_ESRCH;
	}
	LOGF("FIRST_FRAME_AUDIT IMPORTED_IPMI_SERVER_RECEIVE_WAIT"
	     " server_id=%u service=%s requested_capacity=%" PRIu64 " pending=%zu\n",
	     server_id, it->second.service_name.c_str(), capacity, it->second.pending_requests.size());
	if (std::getenv("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_IPMI_TRACE_RESULT") != nullptr) {
		LOGF("FIRST_FRAME_AUDIT AUDIO_IPMI_TRACE_0X10_RESULT"
		     " server_id=%u name=%s registered_server=1"
		     " rpcsx_trace_0x10_contract\n",
		     server_id, it->second.service_name.c_str());
		return 0;
	}
	g_sysav_ipmi_message_cv.wait(lock, [server_id] {
		const auto server = g_sysav_ipmi_servers.find(server_id);
		return server == g_sysav_ipmi_servers.end() || !server->second.pending_requests.empty();
	});
	if (g_sysav_ipmi_servers.find(server_id) == g_sysav_ipmi_servers.end()) {
		return LibKernel::KERNEL_ERROR_ESRCH;
	}
	return LibKernel::KERNEL_ERROR_ENOSYS;
}
Reply Dispatch(const Request& request) {
	Reply       result {};
	const char* label = "unknown";
	switch (request.service) {
		case Service::FlexibleMapExport:
			label  = "dYK287SsmDs/native-map";
			result = MapNative(request);
			break;
		case Service::SysconfExport:
			label  = "mkawd0NA9ts/sysconf";
			result = SysconfNative(request);
			break;
		case Service::ReadlinkExport:
			label  = "pd02UI9TbOA/readlink";
			result = ReadlinkNative(request);
			break;
		default: result = {LibKernel::KERNEL_ERROR_ENOSYS, 0}; break;
	}
	Trace(label, request, result.value, result.posix_errno);
	return result;
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
bool InitializeOriginalMiniSyscoreBootEvents() {
	// stands in for mini-syscore 0x4022A0. Bit 0x2 (0x40E850) needs subsystem-board init and stays
	// clear
	static std::mutex                                           init_mutex;
	static bool                                                 initialized = false;
	static std::array<LibKernel::EventFlag::KernelEventFlag, 3> producer_handles {};
	std::lock_guard                                             lock(init_mutex);
	if (initialized) return true;

	struct OriginalSonyCreation {
		const char* name;
		uint32_t    attributes;
	};
	constexpr OriginalSonyCreation authentic_creations[] = {
	    {"SceSysCoreReboot", 0x121},
	    {"SceBootStatusFlags", 0x121},
	    {"SceSysCoreSuspend", 0x101},
	};

	for (size_t i = 0; i < std::size(authentic_creations); ++i) {
		auto*       handle = &producer_handles[i];
		const auto& spec   = authentic_creations[i];
		const int   rc = LibKernel::EventFlag::KernelCreateEventFlag(handle, spec.name,
		                                                             spec.attributes, 0, nullptr);
		if (rc != 0 || *handle == nullptr) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_MINI_SYSCORE_EVENT_CREATE_FAILED"
			     " name=%s attr=0x%x"
			     " result=0x%08x\n",
			     spec.name, spec.attributes, static_cast<uint32_t>(rc));
			for (size_t j = 0; j < i; ++j) {
				(void)LibKernel::EventFlag::KernelDeleteEventFlag(producer_handles[j]);
				producer_handles[j] = nullptr;
			}
			return false;
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_MINI_SYSCORE_EVENT_CREATED"
		     " creator_pc=0x4022A0 name=%s"
		     " attributes=0x%x initial_bits=0"
		     " backed_by_named_event_registry\n",
		     spec.name, spec.attributes);
	}
	initialized = true;
	return true;
}
bool RunSelfTests() {
	const Reply page     = Dispatch({Service::SysconfExport, {47}});
	const Reply bad_page = Dispatch({Service::SysconfExport, {123}});
	const Reply bad_map  = Dispatch({Service::FlexibleMapExport, {}});
	const Reply bad_link = Dispatch({Service::ReadlinkExport, {}});
	const Reply unknown  = Dispatch({static_cast<Service>(0xffffffffu), {}});
	int32_t     mib[]    = {9, 20};
	int32_t     output   = 0;
	size_t      length   = sizeof(output);
	const Reply size_query =
	    DispatchSyscall({0xca,
		                 {reinterpret_cast<uint64_t>(mib), 2, reinterpret_cast<uint64_t>(&output),
		                  reinterpret_cast<uint64_t>(&length), 0, 0}});
	const Reply               unknown_syscall = DispatchSyscall({0x123456u, {}});
	int32_t                   app_mib[4] {1, 14, 35, LibKernel::Process::GetPid()};
	std::array<uint8_t, 0x98> extended_info;
	extended_info.fill(0xa5);
	size_t      extended_size  = extended_info.size();
	const Reply extended_query = DispatchSyscall(
	    {0xca,
		 {reinterpret_cast<uint64_t>(app_mib), 4, reinterpret_cast<uint64_t>(extended_info.data()),
		  reinterpret_cast<uint64_t>(&extended_size), 0, 0}});
	const bool extended_app_passed = extended_query.value == -1 &&
	                                 extended_query.posix_errno == Libs::Posix::POSIX_ENOSYS &&
	                                 extended_size == extended_info.size() &&
	                                 std::all_of(extended_info.begin(), extended_info.end(),
	                                             [](uint8_t value) { return value == 0xa5; });
	const bool app_buffer_passed =
	    Libs::KernelGetAppInfo(LibKernel::Process::GetPid(), nullptr) ==
	        LibKernel::KERNEL_ERROR_EFAULT &&
	    Libs::KernelGetAppInfo(LibKernel::Process::GetPid(), reinterpret_cast<void*>(1)) ==
	        LibKernel::KERNEL_ERROR_EFAULT;
	LOGF("APP_INFO_EXTENDED_NEGATIVE_SELFTEST %s no_partial_record_returned=1\n",
	     extended_app_passed ? "PASS" : "FAIL");
	LOGF("APP_INFO_BUFFER_NEGATIVE_SELFTEST %s invalid_guest_outputs_rejected=1\n",
	     app_buffer_passed ? "PASS" : "FAIL");
	const Reply null_readlink            = DispatchSyscall({0x3a, {}});
	const Reply null_access              = DispatchSyscall({0x21, {}});
	const Reply null_mini_open           = MiniSyscoreOpen({0x05, {}});
	const Reply invalid_mini_open        = MiniSyscoreOpen({0x05, {UINT64_MAX}});
	const Reply null_socketpair          = MiniSyscoreSocketpair({0x87, {1, 1, 0, 0}});
	bool        sema_passed              = false;
	bool        named_mutex_passed       = false;
	bool        event_flag_passed        = false;
	bool        proc_event_passed        = false;
	bool        ignored_open_mode_passed = false;
	void*       socket_output            = nullptr;
	bool        socketpair_passed =
	    LibKernel::Memory::KernelMapNamedFlexibleMemory(&socket_output, kGuestPageSize, 3, 0,
		                                                "native-socket-fixture") == 0;
	if (socketpair_passed) {
		const Reply pair_reply =
		    MiniSyscoreSocketpair({0x87, {1, 1, 0, reinterpret_cast<uint64_t>(socket_output)}});
		auto*      pair     = static_cast<int*>(socket_output);
		const char sent     = 'Q';
		char       received = 0;
		socketpair_passed =
		    pair_reply.value == 0 && LibKernel::FileSystem::KernelWrite(pair[0], &sent, 1) == 1 &&
		    LibKernel::FileSystem::KernelRead(pair[1], &received, 1) == 1 && received == sent;
		if (pair_reply.value == 0) {
			socketpair_passed =
			    LibKernel::FileSystem::KernelClose(pair[0]) == 0 && socketpair_passed;
			socketpair_passed =
			    LibKernel::FileSystem::KernelClose(pair[1]) == 0 && socketpair_passed;
		}
		auto* sema_name    = static_cast<char*>(socket_output) + 128;
		auto* mutex_name   = static_cast<char*>(socket_output) + 256;
		auto* mutex_object = static_cast<char*>(socket_output) + 512;
		auto* missing_path = static_cast<char*>(socket_output) + 384;
		std::memcpy(missing_path, "/__kyty_native_open_missing_fixture__",
		            sizeof("/__kyty_native_open_missing_fixture__"));
		const int   expected_open = LibKernel::FileSystem::KernelOpen(missing_path, 2, 0);
		const Reply ignored_mode =
		    MiniSyscoreOpen({0x05, {reinterpret_cast<uint64_t>(missing_path), 2, UINT64_MAX}});
		ignored_open_mode_passed =
		    (expected_open == LibKernel::KERNEL_ERROR_ENOENT ||
			 expected_open == LibKernel::KERNEL_ERROR_EIO) &&
		    ignored_mode.value == -1 &&
		    ignored_mode.posix_errno == LibKernel::KernelToPosix(expected_open);
		std::memcpy(mutex_name, "NativeMiniMutexFixture", sizeof("NativeMiniMutexFixture"));
		const auto  event_name    = reinterpret_cast<uint64_t>(mutex_name);
		const auto  event_pattern = reinterpret_cast<uint64_t>(socket_output) + 1024;
		const Reply absent_event  = NativeEventFlagOperation({0x21c, {event_name}});
		const Reply created_event = NativeEventFlagOperation({0x21a, {event_name, 0x121, 0}});
		const Reply opened_event  = NativeEventFlagOperation({0x21c, {event_name}});
		std::memset(mutex_object, 0, 80);
		const Reply opaque_mutex = NativeNamedObjectOperation(
		    {0x22d, {reinterpret_cast<uint64_t>(mutex_name), UINT64_MAX, 0x101}});
		const Reply removed_opaque =
		    NativeNamedObjectOperation({0x22e, {static_cast<uint64_t>(opaque_mutex.value), 0x101}});
		const Reply registered_mutex =
		    NativeNamedObjectOperation({0x22d,
			                            {reinterpret_cast<uint64_t>(mutex_name),
			                             reinterpret_cast<uint64_t>(mutex_object), 0x101}});
		const Reply deleted_mutex = NativeNamedObjectOperation(
		    {0x22e, {static_cast<uint64_t>(registered_mutex.value), 0x101}});
		const Reply stale_mutex = NativeNamedObjectOperation(
		    {0x22e, {static_cast<uint64_t>(registered_mutex.value), 0x101}});
		const auto  cond_address = reinterpret_cast<uint64_t>(socket_output) + kGuestPageSize - 32;
		const Reply registered_cond = NativeNamedObjectOperation(
		    {0x22d, {reinterpret_cast<uint64_t>(mutex_name), cond_address, 0x102}});
		const Reply wrong_cond_type = NativeNamedObjectOperation(
		    {0x22e, {static_cast<uint64_t>(registered_cond.value), 0x101}});
		const Reply deleted_cond = NativeNamedObjectOperation(
		    {0x22e, {static_cast<uint64_t>(registered_cond.value), 0x102}});
		named_mutex_passed =
		    opaque_mutex.value > 0 && removed_opaque.value == 0 && registered_mutex.value > 0 &&
		    registered_mutex.value <= 0xfffe && deleted_mutex.value == 0 &&
		    stale_mutex.value == -1 && stale_mutex.posix_errno == Libs::Posix::POSIX_ESRCH &&
		    registered_cond.value > 0 && wrong_cond_type.value == -1 &&
		    wrong_cond_type.posix_errno == Libs::Posix::POSIX_ESRCH && deleted_cond.value == 0;
		std::memcpy(sema_name, "NativeMiniSemaFixture", sizeof("NativeMiniSemaFixture"));
		const auto  name_address = reinterpret_cast<uint64_t>(sema_name);
		const Reply absent_sema  = MiniSyscoreSemaphore({0x227, {name_address}});
		const Reply created_sema = MiniSyscoreSemaphore({0x225, {name_address, 0x101, 0, 1}});
		const Reply opened_sema  = MiniSyscoreSemaphore({0x227, {name_address}});
		sema_passed              = absent_sema.value == -1 &&
		                           absent_sema.posix_errno == Libs::Posix::POSIX_ESRCH &&
		                           created_sema.value > 0 && opened_sema.value > 0 &&
		                           created_sema.value != opened_sema.value;
		if (created_sema.value > 0 && opened_sema.value > 0) {
			auto* timeout = reinterpret_cast<LibKernel::KernelUseconds*>(
			    static_cast<char*>(socket_output) + 64);
			*timeout                    = 0;
			const uint64_t creator      = static_cast<uint64_t>(created_sema.value);
			const uint64_t alias        = static_cast<uint64_t>(opened_sema.value);
			const uint64_t time_address = reinterpret_cast<uint64_t>(timeout);
			const Reply    bad_need     = MiniSyscoreSemaphore({0x229, {UINT64_MAX, 0, 0}});
			const Reply    bad_timeout  = MiniSyscoreSemaphore({0x229, {UINT64_MAX, 1, 1}});
			*timeout                    = 17;
			const Reply bad_handle = MiniSyscoreSemaphore({0x229, {UINT64_MAX, 1, time_address}});
			sema_passed =
			    bad_need.value == -1 && bad_need.posix_errno == Libs::Posix::POSIX_EINVAL &&
			    bad_timeout.value == -1 && bad_timeout.posix_errno == Libs::Posix::POSIX_EFAULT &&
			    bad_handle.value == -1 && bad_handle.posix_errno == Libs::Posix::POSIX_ESRCH &&
			    *timeout == 17 && sema_passed;
			*timeout          = 0;
			const Reply empty = MiniSyscoreSemaphore({0x229, {alias, 1, time_address}});
			sema_passed = empty.value == -1 && empty.posix_errno == Libs::Posix::POSIX_ETIMEDOUT &&
			              sema_passed;
			const int owner = LibKernel::Process::GetPid();
			*timeout        = 250000;
			Reply       waited;
			std::thread waiter([&] {
				LibKernel::Process::ScopedGuestProcessPid scope(owner);
				waited = MiniSyscoreSemaphore({0x229, {alias, 1, time_address}});
			});
			std::this_thread::sleep_for(std::chrono::milliseconds(2));
			const Reply signalled = MiniSyscoreSemaphore({0x22b, {creator, 1}});
			waiter.join();
			sema_passed               = signalled.value == 0 && waited.value == 0 && sema_passed;
			const Reply queued_one    = MiniSyscoreSemaphore({0x22b, {creator, 1}});
			const Reply overflow      = MiniSyscoreSemaphore({0x22b, {creator, INT32_MAX}});
			*timeout                  = 0;
			const Reply retained_one  = MiniSyscoreSemaphore({0x229, {alias, 1, time_address}});
			sema_passed               = queued_one.value == 0 && overflow.value == -1 &&
			                            overflow.posix_errno == Libs::Posix::POSIX_EINVAL &&
			                            retained_one.value == 0 && sema_passed;
			const auto common_creator = reinterpret_cast<LibKernel::Semaphore::KernelSema>(creator);
			const int  imported_signal = LibKernel::Semaphore::KernelSignalSema(common_creator, 1);
			const Reply imported_count = MiniSyscoreSemaphore({0x229, {alias, 1, time_address}});
			sema_passed = imported_signal == 0 && imported_count.value == 0 && sema_passed;
			{
				LibKernel::Process::ScopedGuestProcessPid other(owner + 0x100000);
				const Reply rejected = MiniSyscoreSemaphore({0x22b, {creator, 1}});
				sema_passed = rejected.value == -1 &&
				              rejected.posix_errno == Libs::Posix::POSIX_ESRCH && sema_passed;
			}
			const Reply closed_alias    = MiniSyscoreSemaphore({0x228, {alias}});
			const Reply closed_creator  = MiniSyscoreSemaphore({0x228, {creator}});
			const Reply deleted_creator = MiniSyscoreSemaphore({0x226, {creator}});
			const Reply stale           = MiniSyscoreSemaphore({0x22b, {alias, 1}});
			sema_passed = closed_alias.value == 0 && closed_creator.value == -1 &&
			              closed_creator.posix_errno == Libs::Posix::POSIX_EPERM &&
			              deleted_creator.value == 0 && stale.value == -1 &&
			              stale.posix_errno == Libs::Posix::POSIX_ESRCH && sema_passed;
			LibKernel::Semaphore::KernelSema imported = nullptr;
			const int imported_create                 = LibKernel::Semaphore::KernelCreateSema(
			    &imported, "NativeMiniImportedSemFixture", 1, 1, 1, nullptr);
			if (imported_create == 0) {
				const auto  imported_handle = reinterpret_cast<uint64_t>(imported);
				const Reply native_wait =
				    MiniSyscoreSemaphore({0x229, {imported_handle, 1, time_address}});
				const Reply native_delete = MiniSyscoreSemaphore({0x226, {imported_handle}});
				sema_passed               = native_wait.value == 0 && native_delete.value == 0 &&
				                            LibKernel::Semaphore::KernelSignalSema(imported, 1) ==
				                                LibKernel::KERNEL_ERROR_ESRCH &&
				                            sema_passed;
			} else {
				sema_passed = false;
			}
		}
		const int queue_fd = LibKernel::FileSystem::CreateNativeKqueueDescriptor();
		if (queue_fd >= 3) {
			constexpr int fixture_pid = 0x60000400;
			LibKernel::Process::RegisterRforkChild(fixture_pid, LibKernel::Process::GetPid());
			auto* change = reinterpret_cast<LibKernel::EventQueue::KernelEvent*>(socket_output);
			*change = {fixture_pid, LibKernel::EventQueue::KERNEL_EVFILT_PROC, 1, 0xa0000000u, 0,
			           nullptr};
			auto* event = reinterpret_cast<LibKernel::EventQueue::KernelEvent*>(
			    static_cast<char*>(socket_output) + 32);
			auto* poll = reinterpret_cast<LibKernel::KernelTimespec*>(
			    static_cast<char*>(socket_output) + 96);
			*poll                      = {0, 0};
			const uint64_t descriptor  = static_cast<uint64_t>(queue_fd);
			const uint64_t change_addr = reinterpret_cast<uint64_t>(change);
			const uint64_t event_addr  = reinterpret_cast<uint64_t>(event);
			const Reply    registered =
			    MiniSyscoreKevent({0x16b, {descriptor, change_addr, 1, 0, 0, 0}});
			const Reply empty = MiniSyscoreKevent(
			    {0x16b, {descriptor, 0, 0, event_addr, 1, reinterpret_cast<uint64_t>(poll)}});
			LibKernel::Process::NotifyRforkChildExited(fixture_pid, 0x5500);
			const Reply exited = MiniSyscoreKevent({0x16b, {descriptor, 0, 0, event_addr, 1, 0}});
			proc_event_passed  = registered.value == 0 && empty.value == 0 && exited.value == 1 &&
			                     event->ident == fixture_pid && event->fflags == 0x80000000u &&
			                     event->data == 0x5500;
			uint32_t   status  = 0;
			const bool waited =
			    LibKernel::Process::WaitForChild(fixture_pid, &status, 0) == fixture_pid &&
			    status == 0x5500;
			const bool closed   = LibKernel::FileSystem::KernelClose(queue_fd) == 0;
			const bool released = LibKernel::Process::ReleaseReapedRforkChild(fixture_pid);
			proc_event_passed   = waited && closed && released &&
			                      !LibKernel::Process::IsTrackedRforkChild(fixture_pid) &&
			                      proc_event_passed;
		}
		socketpair_passed = LibKernel::Memory::KernelMunmap(
		                        reinterpret_cast<uint64_t>(socket_output), kGuestPageSize) == 0 &&
		                    socketpair_passed;
	}
}
} // namespace Libs::NativeKernelBridge
