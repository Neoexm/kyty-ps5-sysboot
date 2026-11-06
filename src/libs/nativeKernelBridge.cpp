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
static std::atomic<uint64_t> g_original_av_event_flag {0};

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

Reply MiniSyscoreStat(const SyscallRequest& request) {
	const uint64_t                      path_address   = request.args[0];
	const uint64_t                      output_address = request.args[1];
	LibKernel::Memory::VirtualQueryInfo path_region {};
	LibKernel::Memory::VirtualQueryInfo output_region {};
	if (path_address == 0 || output_address == 0 ||
	    output_address > UINT64_MAX - sizeof(LibKernel::FileSystem::FileStat) ||
	    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(path_address), 0,
	                                          &path_region, sizeof(path_region)) != 0 ||
	    !path_region.is_committed || path_region.start > path_address ||
	    path_region.end <= path_address || (path_region.protection & 1u) == 0 ||
	    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(output_address), 0,
	                                          &output_region, sizeof(output_region)) != 0 ||
	    !output_region.is_committed || output_region.start > output_address ||
	    output_region.end < output_address + sizeof(LibKernel::FileSystem::FileStat) ||
	    (output_region.protection & 2u) == 0) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	const size_t available =
	    static_cast<size_t>(std::min<uint64_t>(path_region.end - path_address, 4096));
	const char* path = reinterpret_cast<const char*>(path_address);
	if (std::memchr(path, '\0', available) == nullptr) {
		return {-1,
		        available == 4096 ? Libs::Posix::POSIX_ENAMETOOLONG : Libs::Posix::POSIX_EFAULT};
	}
	LibKernel::FileSystem::FileStat stat {};
	const int                       rc = LibKernel::FileSystem::KernelStat(path, &stat);
	if (rc == 0) {
		LibKernel::Memory::InvalidateMemory(output_address, sizeof(stat));
		std::memcpy(reinterpret_cast<void*>(output_address), &stat, sizeof(stat));
	}
	static std::atomic<uint32_t> traces {0};
	if (traces.fetch_add(1) < 8) {
		LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_NATIVE_STAT"
		     " path=%s output=0x%016" PRIx64 " result=%d errno=%d\n",
		     path, output_address, rc, rc == 0 ? 0 : LibKernel::KernelToPosix(rc));
	}
	return rc == 0 ? Reply {0, 0} : Reply {-1, LibKernel::KernelToPosix(rc)};
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

Reply BudgetSet(const SyscallRequest& request) {
	return BudgetReply(LibKernel::Budget::Set(static_cast<int32_t>(request.args[0])), 0);
}

Reply BudgetGet(const SyscallRequest&) {
	int64_t   id     = 0;
	const int result = LibKernel::Budget::Get(&id);
	return BudgetReply(result, id);
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
	if (count == 4 && mib[0] == 1 && mib[1] == 14 && mib[2] == 55 && mib[3] == UINT32_MAX &&
	    input == nullptr && input_len == 0 && output != nullptr && capacity == sizeof(uint32_t)) {
		LOGF("FIRST_FRAME_AUDIT SYSAV_IS_PS4_PROCESS_QUERY_UNAVAILABLE"
		     " no kernel state for process mode; ENOENT\n");
		return {-1, Libs::Posix::POSIX_ENOENT};
	}
	if (count == 4 && mib[0] == 1 && mib[1] == 14 && mib[2] == 36 &&
	    mib[3] == static_cast<uint32_t>(LibKernel::Process::GetPid()) && input == nullptr &&
	    input_len == 0) {
		auto*          rt        = Common::Singleton<Loader::RuntimeLinker>::Instance();
		const uint64_t proc_addr = rt->GetProcParam();
		if (proc_addr == 0) {
			return {-1, Libs::Posix::POSIX_ENOENT};
		}
		const auto* param = reinterpret_cast<const uint64_t*>(proc_addr);
		if (param[0] <= 0x17) {
			return {-1, Libs::Posix::POSIX_ENOENT};
		}
		const uint32_t original_compiled_sdk = static_cast<uint32_t>(param[2]);
		const Reply    result = PublishSysctlValue(output, length, capacity, &original_compiled_sdk,
		                                           sizeof(original_compiled_sdk));
		if (result.value == 0) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_COMPILED_SDK_FROM_PROCPARAM"
			     " value=0x%08x inferred_mib_mapping_from_native_libkernel\n",
			     original_compiled_sdk);
		}
		return result;
	}
	if (count == 4 && mib[0] == 1 && mib[1] == 14 && mib[2] == 68 &&
	    mib[3] == static_cast<uint32_t>(LibKernel::Process::GetPid()) && input == nullptr &&
	    input_len == 0) {
		auto*          rt        = Common::Singleton<Loader::RuntimeLinker>::Instance();
		const uint64_t proc_addr = rt->GetProcParam();
		if (proc_addr == 0) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_SDK_VERSION_MISSING"
			     " static ELF has no PT_OS_PROCPARAM; ENOENT\n");
			return {-1, Libs::Posix::POSIX_ENOENT};
		}
		const auto* param = reinterpret_cast<const uint64_t*>(proc_addr);
		if (param[0] <= 0x17) {
			return {-1, Libs::Posix::POSIX_ENOENT};
		}
		const uint64_t original_sdk = param[2];
		const Reply    result =
		    PublishSysctlValue(output, length, capacity, &original_sdk, sizeof(original_sdk));
		if (result.value == 0) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_SDK_VERSION_FROM_PROCPARAM"
			     " raw=0x%016" PRIx64 "\n",
			     original_sdk);
		}
		return result;
	}
}

Reply SysAvOriginalVirtualQuery(const SyscallRequest& request) {
	if (!std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") ||
	    request.args[0] < 0x200000000ull || request.args[0] > 0x300000000ull ||
	    request.args[1] != 0 || request.args[2] == 0 ||
	    request.args[3] != sizeof(LibKernel::Memory::VirtualQueryInfo) || request.args[4] != 0 ||
	    request.args[5] != 0) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	LibKernel::Memory::VirtualQueryInfo out_region {};
	if (LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(request.args[2]), 0,
	                                          &out_region, sizeof(out_region)) != 0 ||
	    !out_region.is_committed || (out_region.protection & 2u) == 0 ||
	    out_region.start > request.args[2] ||
	    out_region.end < request.args[2] + sizeof(out_region) ||
	    request.args[2] > UINT64_MAX - sizeof(out_region)) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	LibKernel::Memory::VirtualQueryInfo actual {};
	const int                           rc = LibKernel::Memory::KernelVirtualQuery(
	    reinterpret_cast<const void*>(request.args[0]), 0, &actual, sizeof(actual));
	if (rc != 0) return {-1, LibKernel::KernelToPosix(rc)};
	if (!actual.is_committed || !actual.is_direct || actual.start > request.args[0] ||
	    actual.end < request.args[0] + 0x7e9000ull) {
		return {-1, Libs::Posix::POSIX_EINVAL};
	}
	LibKernel::Memory::InvalidateMemory(request.args[2], sizeof(actual));
	std::memcpy(reinterpret_cast<void*>(request.args[2]), &actual, sizeof(actual));
	LOGF("FIRST_FRAME_AUDIT SYSAV_SPLASH_VIRTUAL_QUERY"
	     " guest_query_va=0x%016" PRIx64 " range=0x%016" PRIxPTR "..0x%016" PRIxPTR
	     " true_physical_offset=0x%016" PRIx64 " is_direct=%u is_committed=%u"
	     " guest_out=0x%016" PRIx64 " bytes=72\n",
	     request.args[0], actual.start, actual.end, actual.offset, actual.is_direct,
	     actual.is_committed, request.args[2]);
	Log::Flush();
	return {0, 0};
}

Reply NativeAnonymousMmap(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const auto addr   = request.args[0];
	const auto len    = request.args[1];
	const auto prot   = request.args[2];
	const auto flags  = request.args[3];
	const auto fd     = request.args[4];
	const auto offset = request.args[5];
	if (std::getenv("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP") != nullptr) {
		static std::atomic<uint32_t> audio_map_trace_count {0};
		if (audio_map_trace_count.fetch_add(1) < 20) {
			LOGF("FIRST_FRAME_AUDIT NATIVE_MMAP_ABI"
			     " pid=%d"
			     " hint=0x%016" PRIx64 " len=0x%016" PRIx64 " prot=0x%016" PRIx64
			     " flags=0x%016" PRIx64 " fd=0x%016" PRIx64 " offset=0x%016" PRIx64 "\n",
			     LibKernel::Process::GetPid(), addr, len, prot, flags, fd, offset);
		}
	}
	const uint64_t main_stack_top = LibKernel::PthreadGetMainGuestStackTop();
	if (addr == 0 && len == 0x2000 && prot == 3 && flags == 1 && fd >= 3 && fd <= INT32_MAX &&
	    offset == 0) {
		size_t shared_size = 0;
		if (!LibKernel::FileSystem::GetSharedMemorySize(static_cast<int>(fd), &shared_size) ||
		    shared_size != 0x2000) {
			return {-1, Libs::Posix::POSIX_EBADF};
		}
		void* mapped = LibKernel::FileSystem::MapSharedMemory(
		    static_cast<int>(fd), nullptr, len, static_cast<int>(prot), static_cast<int>(flags));
		if (mapped == reinterpret_cast<void*>(static_cast<intptr_t>(-1))) {
			return {-1, *Libs::Posix::GetErrorAddr()};
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_SHM_MAPPED"
		     " guest_fd=%" PRIu64 " guest_va=0x%016" PRIx64 " bytes=0x%016" PRIx64
		     " guest_shared_mapping\n",
		     fd, reinterpret_cast<uint64_t>(mapped), len);
		return {static_cast<int64_t>(reinterpret_cast<uint64_t>(mapped)), 0};
	}
	// /SceAo2TVCorP: MAP_SHARED rw, at whatever length the guest ftruncated it to
	if (addr == 0 && prot == 3 && flags == 1 && fd >= 3 && fd <= INT32_MAX && offset == 0 &&
	    LibKernel::FileSystem::IsSharedMemoryNamed(static_cast<int>(fd), "/SceAo2TVCorP")) {
		size_t shared_size = 0;
		if (!LibKernel::FileSystem::GetSharedMemorySize(static_cast<int>(fd), &shared_size) ||
		    shared_size == 0 || len != shared_size) {
			return {-1, Libs::Posix::POSIX_EBADF};
		}
		void* mapped = LibKernel::FileSystem::MapSharedMemory(
		    static_cast<int>(fd), nullptr, len, static_cast<int>(prot), static_cast<int>(flags));
		if (mapped == reinterpret_cast<void*>(static_cast<intptr_t>(-1))) {
			return {-1, *Libs::Posix::GetErrorAddr()};
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_AUDIO_SHM_MAPPED"
		     " guest_fd=%" PRIu64 " guest_va=0x%016" PRIx64 " bytes=0x%016" PRIx64
		     " scope_shared_audio_out_buffer_mapped\n",
		     fd, reinterpret_cast<uint64_t>(mapped), len);
		return {static_cast<int64_t>(reinterpret_cast<uint64_t>(mapped)), 0};
	}
	// 0x475408..0x475423: PROT_NONE over the first 16 KiB of the 48 KiB stack extension. Backing
	// stays.
	if (prot == 0 && flags == 0x110 && len == 0x4000 && main_stack_top > 0x21c000 &&
	    (addr == main_stack_top - 0x26c000 || addr == main_stack_top - 0x260000 ||
	     addr == main_stack_top - 0x210000 || addr == main_stack_top - 0x21c000 ||
	     (main_stack_top > 0x24c000 && addr == main_stack_top - 0x24c000) ||
	     (main_stack_top > 0x240000 && addr == main_stack_top - 0x240000)) &&
	    (fd == UINT64_MAX || fd == UINT32_MAX) && offset == 0) {
		LibKernel::Memory::VirtualQueryInfo range {};
		if (LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(addr), 0, &range,
		                                          sizeof(range)) != 0 ||
		    !range.is_committed || range.start > addr || range.end < addr + len ||
		    (range.protection & 7u) != 7u ||
		    !LibKernel::Memory::ProtectGuestMemory(addr, len,
		                                           Common::VirtualMemory::Mode::NoAccess)) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_STACK_GUARD_REMAP_FAILED"
			     " addr=0x%016" PRIx64 " size=0x%016" PRIx64 "\n",
			     addr, len);
			return {-1, Libs::Posix::POSIX_ENOMEM};
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_STACK_GUARD_REMAP_PROTECTED"
		     " addr=0x%016" PRIx64 " size=0x%016" PRIx64
		     " PROT_NONE existing_guest_stack_backing\n",
		     addr, len);
		return {static_cast<int64_t>(addr), 0};
	}
	// splash 0x43977C: 36 MiB of /dev/dmem0 at its allocated offset, 2 MiB aligned
	if (addr == 0x200000000ull && len == 0x6000000 && prot == 1 && flags == 0x15000001 && fd >= 3 &&
	    fd <= INT32_MAX && (offset & 0x1fffffull) == 0 && offset <= INT64_MAX &&
	    LibKernel::FileSystem::IsNativeDmemDescriptor(static_cast<int>(fd))) {
		void*     mapped = reinterpret_cast<void*>(addr);
		const int rc     = LibKernel::Memory::KernelMapDirectMemory(
		    &mapped, static_cast<size_t>(len), static_cast<int>(prot), 0,
		    static_cast<int64_t>(offset), 0x200000);
		if (rc != 0) {
			const int guest_errno = LibKernel::KernelToPosix(rc);
			LOGF("FIRST_FRAME_AUDIT SYSAV_96M_DMEM_MAP_FAILED"
			     " hint=0x%016" PRIx64 " bytes=0x%016" PRIx64 " guest_errno=%d\n",
			     addr, len, guest_errno);
			return {-1, guest_errno};
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_96M_DMEM_MAPPED"
		     " guest_va=0x%016" PRIx64 " hint=0x%016" PRIx64 " phys=0x%016" PRIx64
		     " bytes=0x%016" PRIx64 " backed_by_96MiB_physical_allocation\n",
		     reinterpret_cast<uint64_t>(mapped), addr, offset, len);
		return {static_cast<int64_t>(reinterpret_cast<uint64_t>(mapped)), 0};
	}
	if (len == 0x2400000 && flags == 0x15000001) {
		LOGF("FIRST_FRAME_AUDIT SYSAV_36M_MAP_BACKING_AUDIT"
		     " requested_va=0x%016" PRIx64 " len=0x%016" PRIx64 " prot=0x%016" PRIx64
		     " flags=0x%016" PRIx64 " fd=%" PRIu64 " physical_offset=0x%016" PRIx64
		     " dmem_descriptor=%u alignment_2MiB=%u"
		     " supports_nonfixed_hint=%u\n",
		     addr, len, prot, flags, fd, offset,
		     fd >= 3 && fd <= INT32_MAX &&
		             LibKernel::FileSystem::IsNativeDmemDescriptor(static_cast<int>(fd))
		         ? 1u
				 : 0u,
		     (offset & 0x1fffff) == 0 ? 1u : 0u, (addr == 0 || addr == 0x200000000ull) ? 1u : 0u);
		Log::Flush();
	}
	if ((addr == 0 || addr == 0x200000000ull) && len == 0x2400000 && prot == 0x33 &&
	    flags == 0x15000001 && fd >= 3 && fd <= INT32_MAX && (offset & 0x1fffff) == 0 &&
	    offset <= INT64_MAX &&
	    LibKernel::FileSystem::IsNativeDmemDescriptor(static_cast<int>(fd))) {
		// non-fixed hint 0x200000000 with 96 MiB already mapped nearby, so the result can differ
		// from it
		void*     mapped = reinterpret_cast<void*>(addr);
		const int rc     = LibKernel::Memory::KernelMapDirectMemory(
		    &mapped, static_cast<size_t>(len), static_cast<int>(prot), 0,
		    static_cast<int64_t>(offset), 0x200000);
		if (rc != 0) {
			const int guest_errno = LibKernel::KernelToPosix(rc);
			LOGF("FIRST_FRAME_AUDIT SYSAV_DMEM_MAP_FAILED"
			     " phys=0x%016" PRIx64 " bytes=0x%016" PRIx64 " guest_errno=%d\n",
			     offset, len, guest_errno);
			return {-1, guest_errno};
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_DMEM_MAPPED"
		     " direct_guest_va=0x%016" PRIx64 " hint=0x%016" PRIx64 " phys=0x%016" PRIx64
		     " bytes=0x%016" PRIx64 " cpu_gpu_writable_source_not_logo_evidence\n",
		     reinterpret_cast<uint64_t>(mapped), addr, offset, len);
		Log::Flush();
		return {static_cast<int64_t>(reinterpret_cast<uint64_t>(mapped)), 0};
	}
	if (prot == 0 && flags == 0x1100 && len == 0x4000 && main_stack_top > 0x204000 &&
	    addr == main_stack_top - 0x204000 && (fd == UINT64_MAX || fd == UINT32_MAX) &&
	    offset == 0) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		MEMORY_BASIC_INFORMATION guard_info {};
		const SIZE_T             queried =
		    VirtualQuery(reinterpret_cast<const void*>(addr), &guard_info, sizeof(guard_info));
		LOGF("FIRST_FRAME_AUDIT SYSAV_STACK_GUARD_EXISTING"
		     " address=0x%016" PRIx64 " query=%zu"
		     " state=0x%x protect=0x%x type=0x%x\n",
		     addr, static_cast<size_t>(queried), static_cast<unsigned>(guard_info.State),
		     static_cast<unsigned>(guard_info.Protect), static_cast<unsigned>(guard_info.Type));
		if (queried != 0 && guard_info.State == MEM_COMMIT &&
		    (guard_info.Protect & PAGE_NOACCESS) != 0 &&
		    reinterpret_cast<uint64_t>(guard_info.BaseAddress) <= addr &&
		    guard_info.RegionSize >= len &&
		    addr - reinterpret_cast<uint64_t>(guard_info.BaseAddress) <=
		        guard_info.RegionSize - len) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_STACK_GUARD_REUSED"
			     " address=0x%016" PRIx64 " preexisting pthread guard page"
			     " NON_AUTHENTIC\n",
			     addr);
			return {static_cast<int64_t>(addr), 0};
		}
#endif
		const uint64_t guard = LibKernel::Memory::AllocateRuntimeMemory(
		    addr, len, Common::VirtualMemory::Mode::NoAccess, "SceSysAvControlStackGuard", true);
		if (guard != addr) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_STACK_GUARD_MAP_FAILED"
			     " addr=0x%016" PRIx64 "\n",
			     addr);
			return {-1, Libs::Posix::POSIX_ENOMEM};
		}
		if (!LibKernel::Memory::ProtectGuestMemory(guard, len,
		                                           Common::VirtualMemory::Mode::NoAccess)) {
			LibKernel::Memory::FreeGuestMemory(guard, len);
			return {-1, Libs::Posix::POSIX_ENOMEM};
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_STACK_GUARD_MAPPED"
		     " addr=0x%016" PRIx64 " size=0x%016" PRIx64 " PROT_NONE guest_request_at_address\n",
		     guard, len);
		return {static_cast<int64_t>(guard), 0};
	}
	if (prot == 7 && flags == 0x400 && len == 0xc000 && main_stack_top > 0x26c000 &&
	    addr == main_stack_top - 0x26c000 && (fd == UINT64_MAX || fd == UINT32_MAX) &&
	    offset == 0) {
		const uint64_t mapped = LibKernel::Memory::AllocateRuntimeMemory(
		    addr, len, Common::VirtualMemory::Mode::ExecuteReadWrite, "SceSysAvIpmiNextThreadStack",
		    true);
		if (mapped != addr) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_IPMI_NEXT_NATIVE_STACK_FAILED"
			     " requested=0x%016" PRIx64 " len=0x%016" PRIx64 "\n",
			     addr, len);
			return {-1, Libs::Posix::POSIX_ENOMEM};
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_IPMI_NEXT_NATIVE_STACK_MAPPED"
		     " guest_address=0x%016" PRIx64 " bytes=0x%016" PRIx64 " RW_X_guest_stack_backing\n",
		     mapped, len);
		return {static_cast<int64_t>(mapped), 0};
	}
	// IPMI server: 80 KiB fixed RWX stack just below the thread-extension region
	if (prot == 7 && flags == 0x400 && len == 0x14000 && main_stack_top > 0x260000 &&
	    addr == main_stack_top - 0x260000 && (fd == UINT64_MAX || fd == UINT32_MAX) &&
	    offset == 0) {
		const uint64_t mapped = LibKernel::Memory::AllocateRuntimeMemory(
		    addr, len, Common::VirtualMemory::Mode::ExecuteReadWrite, "SceSysAvIpmiNativeStack",
		    true);
		if (mapped != addr) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_IPMI_NATIVE_STACK_MAP_FAILED"
			     " addr=0x%016" PRIx64 " len=0x%016" PRIx64 "\n",
			     addr, len);
			return {-1, Libs::Posix::POSIX_ENOMEM};
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_IPMI_NATIVE_STACK_MAPPED"
		     " guest_address=0x%016" PRIx64 " bytes=0x%016" PRIx64 " fixed_RW_X_mapping\n",
		     mapped, len);
		return {static_cast<int64_t>(mapped), 0};
	}
	if (prot == 7 && flags == 0x400 && len == 0x24000 && main_stack_top > 0x240000 &&
	    addr == main_stack_top - 0x240000 && (fd == UINT64_MAX || fd == UINT32_MAX) &&
	    offset == 0) {
		const uint64_t mapped = LibKernel::Memory::AllocateRuntimeMemory(
		    addr, len, Common::VirtualMemory::Mode::ExecuteReadWrite, "SceSysAvSplashNativeStack",
		    true);
		if (mapped != addr) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_SPLASH_NATIVE_STACK_MAP_FAILED"
			     " addr=0x%016" PRIx64 " size=0x%016" PRIx64 "\n",
			     addr, len);
			return {-1, Libs::Posix::POSIX_ENOMEM};
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_SPLASH_NATIVE_STACK_MAPPED"
		     " addr=0x%016" PRIx64 " size=0x%016" PRIx64 " fixed_stack_alloc_0x4753f5\n",
		     mapped, len);
		return {static_cast<int64_t>(mapped), 0};
	}
	if (prot == 7 && flags == 0x400 && len == 0xc000 && main_stack_top > 0x21c000 &&
	    (addr == main_stack_top - 0x210000 || addr == main_stack_top - 0x21c000 ||
	     (main_stack_top > 0x24c000 && addr == main_stack_top - 0x24c000)) &&
	    (fd == UINT64_MAX || fd == UINT32_MAX) && offset == 0) {
		const uint64_t mapped = LibKernel::Memory::AllocateRuntimeMemory(
		    addr, len, Common::VirtualMemory::Mode::ExecuteReadWrite, "SceSysAvNativeStackExt",
		    true);
		if (mapped != addr) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_STACK_EXTENSION_MAP_FAILED"
			     " addr=0x%016" PRIx64 " size=0x%016" PRIx64 "\n",
			     addr, len);
			return {-1, Libs::Posix::POSIX_ENOMEM};
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_STACK_EXTENSION_MAPPED"
		     " addr=0x%016" PRIx64 " size=0x%016" PRIx64 " prot=RWX fixed_guest_mapping\n",
		     mapped, len);
		return {static_cast<int64_t>(mapped), 0};
	}
	if (len == 0 || len > 0x1000000 || (len & 0x3fff) != 0 || (addr != 0 && (addr & 0x3fff) != 0) ||
	    prot != 3 || (flags != 0x9000 && !(flags == 0x1002 && addr == 0 && len == 0x4000)) ||
	    (fd != UINT64_MAX && fd != UINT32_MAX) || offset != 0) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	void*     mapped = reinterpret_cast<void*>(addr);
	const int rc     = LibKernel::Memory::KernelMapNamedFlexibleMemory(
	    &mapped, static_cast<size_t>(len), static_cast<int>(prot), flags == 0x9000 ? 0x8000 : 0,
	    "SceSysAvControl");
	if (rc != 0) {
		LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_MMAP_FAILED"
		     " hint=0x%016" PRIx64 " len=0x%016" PRIx64 " result=0x%08x\n",
		     addr, len, static_cast<uint32_t>(rc));
		return {-1, Libs::Posix::POSIX_ENOMEM};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_MMAP"
	     " hint=0x%016" PRIx64 " size=0x%016" PRIx64 " mapped=0x%016" PRIx64 " flags=0x%016" PRIx64
	     " guest_anonymous_mapping_allocated\n",
	     addr, len, reinterpret_cast<uint64_t>(mapped), flags);
	return {static_cast<int64_t>(reinterpret_cast<uint64_t>(mapped)), 0};
}

Reply AudiodExtendedMmap(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    (std::getenv("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP") == nullptr &&
	     !LibKernel::Process::IsExecChild())) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	if (!request.stack_arg7_valid) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	// 0x2d5 tail-jumps into the mmap body, mode at uap+0x20. With FMEM index 10 off the mode does
	// nothing for MAP_ANON, so modes 1/2 are plain anonymous mmap.
	if (request.args[0] != 0x200000000ull || request.args[1] == 0 ||
	    (request.args[1] & 0x3fff) != 0 || (request.args[2] != 2 && request.args[2] != 3) ||
	    request.args[3] != 0x1000 || (request.args[4] != 1 && request.args[4] != 2) ||
	    request.args[5] != UINT32_MAX || request.stack_arg7 != 0) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	void*     mapped = reinterpret_cast<void*>(request.args[0]);
	const int rc     = LibKernel::Memory::KernelMapNamedFlexibleMemory(
	    &mapped, static_cast<size_t>(request.args[1]), static_cast<int>(request.args[2]), 0,
	    request.args[2] == 3 ? "native_anonymous_rw" : "orbis_audiod");
	if (rc != 0) {
		const int guest_errno = LibKernel::KernelToPosix(rc);
		LOGF("FIRST_FRAME_AUDIT AUDIOD_EXTENDED_MMAP_FAILED"
		     " size=0x%016" PRIx64 " mode=%" PRIu64 " rc=0x%08x errno=%d\n",
		     request.args[1], request.args[4], static_cast<uint32_t>(rc), guest_errno);
		return {-1, guest_errno};
	}
	const uint64_t guest_addr = reinterpret_cast<uint64_t>(mapped);
	LOGF("FIRST_FRAME_AUDIT AUDIOD_EXTENDED_MMAP"
	     " hint=0x%016" PRIx64 " size=0x%016" PRIx64 " prot=0x%016" PRIx64 " flags=0x%016" PRIx64
	     " mode=%" PRIu64 " fd=0x%016" PRIx64 " offset=0x%016" PRIx64
	     " committed_guest_addr=0x%016" PRIx64 " anonymous_guest_visible_mapping\n",
	     request.args[0], request.args[1], request.args[2], request.args[3], request.args[4],
	     request.args[5], request.stack_arg7, guest_addr);
	return {static_cast<int64_t>(guest_addr), 0};
}

// 0x47543F names its first 16 KiB "stack guard" through 0x476E80 (syscall 0x24C)
Reply SysAvNativeNanosleep(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[0] == 0 || request.args[0] > UINT64_MAX - 16 ||
	    (request.args[1] != 0 && request.args[1] > UINT64_MAX - 16)) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	auto guest_span = [](uint64_t address, bool write) {
		LibKernel::Memory::VirtualQueryInfo guest {};
		return LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(address), 0,
		                                             &guest, sizeof(guest)) == 0 &&
		       guest.is_committed && guest.start <= address &&
		       guest.end >= address + sizeof(LibKernel::KernelTimespec) &&
		       (guest.protection & (write ? 2u : 1u)) != 0;
	};
	if (!guest_span(request.args[0], false) ||
	    (request.args[1] != 0 && !guest_span(request.args[1], true))) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	LibKernel::KernelTimespec original {};
	std::memcpy(&original, reinterpret_cast<const void*>(request.args[0]), sizeof(original));
	const auto rc = LibKernel::KernelNanosleep(
	    &original, request.args[1] != 0
	                   ? reinterpret_cast<LibKernel::KernelTimespec*>(request.args[1])
	                   : nullptr);
	if (rc != 0) {
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_NANOSLEEP"
	     " sec=%" PRId64 " nsec=%" PRId64 " sleep_completed\n",
	     original.tv_sec, original.tv_nsec);
	return {0, 0};
}

Reply SyscoreNativePoll(const SyscallRequest& request) {
	const bool infinite = request.args[2] == UINT32_MAX || request.args[2] == UINT64_MAX;
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_GUEST_THREAD_FS10") == nullptr ||
	    request.args[0] != 0 || request.args[1] != 0 || !infinite) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	LOGF("FIRST_FRAME_AUDIT SYSCORE_POLL_IDLE_BLOCK"
	     " nfds=0 timeout=-1\n");
	for (;;) {
		LibKernel::KernelSleep(1);
		LibKernel::PthreadTestcancel();
	}
}

Reply SysAvNativeClockGettime(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[0] != 15 || request.args[1] == 0) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const uint64_t                      addr = request.args[1];
	LibKernel::Memory::VirtualQueryInfo guest {};
	if (addr > UINT64_MAX - sizeof(LibKernel::KernelTimespec) ||
	    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(addr), 0, &guest,
	                                          sizeof(guest)) != 0 ||
	    !guest.is_committed || guest.start > addr ||
	    guest.end < addr + sizeof(LibKernel::KernelTimespec) || (guest.protection & 2u) == 0) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	LibKernel::KernelTimespec actual {};
	const int                 rc = LibKernel::KernelClockGettime(15, &actual);
	if (rc != 0) {
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	LibKernel::Memory::InvalidateMemory(addr, sizeof(actual));
	std::memcpy(reinterpret_cast<void*>(addr), &actual, sizeof(actual));
	LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_CLOCK_GETTIME"
	     " clock_id=15 from_process_clock"
	     " sec=%" PRId64 " nsec=%" PRId64 "\n",
	     actual.tv_sec, actual.tv_nsec);
	return {0, 0};
}

struct SysAvUmtxQueue {
	std::mutex              mutex;
	std::condition_variable cv;
	uint64_t                generation         = 0;
	unsigned                waiters            = 0;
	unsigned                rw_readers_waiting = 0;
	unsigned                rw_writers_waiting = 0;
};
static std::mutex                                                    g_sysav_umtx_lock;
static std::unordered_map<uint64_t, std::shared_ptr<SysAvUmtxQueue>> g_sysav_umtx_queues;

static std::shared_ptr<SysAvUmtxQueue> SysAvUmtxGetQueue(uint64_t address) {
	std::lock_guard lock(g_sysav_umtx_lock);
	auto&           entry = g_sysav_umtx_queues[address];
	if (!entry) {
		entry = std::make_shared<SysAvUmtxQueue>();
	}
	return entry;
}

// The 0x200000000 region base moves when exec-child TCBs take the low pages, so the page offset is
// the identity; args[5] ids disambiguate.
static bool SysAvGuestObjectAt(uint64_t addr, uint64_t observed_literal) {
	return addr >= 0x200000000ull && addr < 0x210000000ull &&
	       (addr & 0xfffull) == (observed_literal & 0xfffull);
}

Reply SysAvNativeUmtx(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	auto valid_guest_word = [](uint64_t addr, bool writable) {
		LibKernel::Memory::VirtualQueryInfo info {};
		return addr != 0 && addr <= UINT64_MAX - 4 && (addr & 3u) == 0 &&
		       LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(addr), 0, &info,
		                                             sizeof(info)) == 0 &&
		       info.is_committed && info.start <= addr && info.end >= addr + 4 &&
		       (info.protection & (writable ? 2u : 1u)) != 0;
	};
	// unlock loads the id from mutex+0x3c (0x47aaf8), 0x4703e0 passes it in r9
	auto mutex_id_matches = [&](uint64_t mutex, uint64_t id) {
		return id != 0 && valid_guest_word(mutex + 0x3c, false) &&
		       *reinterpret_cast<const uint32_t*>(mutex + 0x3c) == id;
	};
	const uint64_t addr = request.args[0];
	const uint64_t op   = request.args[1];
	if (op == 8 && SysAvGuestObjectAt(addr, 0x200003244) && request.args[4] != 0) {
		static std::atomic_uint32_t samples {0};
		if (samples.fetch_add(1) == 0) {
			const uint64_t                      input = request.args[4];
			LibKernel::Memory::VirtualQueryInfo region {};
			if (input <= UINT64_MAX - 32 &&
			    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(input), 0,
			                                          &region, sizeof(region)) == 0 &&
			    region.is_committed && region.start <= input && region.end >= input + 32 &&
			    (region.protection & 1u) != 0) {
				uint64_t words[4] {};
				std::memcpy(words, reinterpret_cast<const void*>(input), sizeof(words));
				LOGF("FIRST_FRAME_AUDIT SYSAV_TIMED_CV_INPUT"
				     " timeout_guest_ptr=0x%016" PRIx64 " words=%016" PRIx64 ",%016" PRIx64
				     ",%016" PRIx64 ",%016" PRIx64 " GUEST_BYTES_READ_ONLY\n",
				     input, words[0], words[1], words[2], words[3]);
			}
		}
	}
	// libc 0x470620..0x470771: ops 12/13/14 share one urwlock word. Bit 31 writer,
	// 0x40000000/0x20000000 waiters, low 29 bits readers
	if ((op == 12 || op == 13 || op == 14) &&
	    (SysAvGuestObjectAt(addr, 0x200002220) || SysAvGuestObjectAt(addr, 0x2000028c0)) &&
	    request.args[3] == 0 && request.args[4] == 0 &&
	    (op == 12 ? (request.args[2] == 0 || request.args[2] == 2) : request.args[2] == 0) &&
	    (request.args[5] == 0xff010300u || (op == 14 && request.args[5] == 0xffffffffu)) &&
	    valid_guest_word(addr, true) && valid_guest_word(addr + 4, false)) {
		constexpr uint32_t WriterHeld     = 0x80000000u;
		constexpr uint32_t ReadersWaiting = 0x40000000u;
		constexpr uint32_t WritersWaiting = 0x20000000u;
		constexpr uint32_t ReaderCount    = 0x1fffffffu;
		auto&              real_word      = *reinterpret_cast<uint32_t*>(addr);
		auto&              real_flags     = *reinterpret_cast<const uint32_t*>(addr + 4);
		if ((real_flags & 0x10cu) != 0) {
			return {-1, Libs::Posix::POSIX_ENOSYS};
		}
		std::atomic_ref<uint32_t> state(real_word);
		auto                      queue = SysAvUmtxGetQueue(addr);
		std::unique_lock          wait_lock(queue->mutex);
		if (op == 14) {
			uint32_t old = state.load(std::memory_order_acquire);
			while (true) {
				uint32_t next = old;
				if ((old & WriterHeld) != 0) {
					if ((old & ReaderCount) != 0) {
						return {-1, Libs::Posix::POSIX_EINVAL};
					}
					next &= ~WriterHeld;
				} else if ((old & ReaderCount) != 0) {
					next -= 1;
				} else {
					return {-1, Libs::Posix::POSIX_EPERM};
				}
				if (queue->rw_readers_waiting == 0) next &= ~ReadersWaiting;
				if (queue->rw_writers_waiting == 0) next &= ~WritersWaiting;
				if (state.compare_exchange_weak(old, next, std::memory_order_acq_rel)) {
					const auto wake = queue->rw_readers_waiting + queue->rw_writers_waiting;
					++queue->generation;
					wait_lock.unlock();
					if (wake != 0) queue->cv.notify_all();
					LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_RW_UNLOCK"
					     " guest_lock=0x%016" PRIx64 " prior=0x%08x new_state=0x%08x waiters=%u\n",
					     addr, old, next, wake);
					return {0, 0};
				}
			}
		}
		const bool     reader  = (op == 12);
		auto&          waiting = reader ? queue->rw_readers_waiting : queue->rw_writers_waiting;
		const uint32_t bit     = reader ? ReadersWaiting : WritersWaiting;
		++waiting;
		state.fetch_or(bit, std::memory_order_acq_rel);
		while (true) {
			uint32_t   old = state.load(std::memory_order_acquire);
			const bool available =
			    reader ? (old & WriterHeld) == 0 && (old & ReaderCount) != ReaderCount
				       : (old & (WriterHeld | ReaderCount)) == 0;
			if (available) {
				uint32_t next = reader ? old + 1u : (old | WriterHeld);
				if (waiting == 1) next &= ~bit;
				if (state.compare_exchange_weak(old, next, std::memory_order_acq_rel)) {
					--waiting;
					LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_RW_LOCK_ACQUIRED"
					     " op=%" PRIu64 " guest_lock=0x%016" PRIx64
					     " guest_state=0x%08x read_waiters=%u"
					     " write_waiters=%u\n",
					     op, addr, next, queue->rw_readers_waiting, queue->rw_writers_waiting);
					return {0, 0};
				}
				continue;
			}
			queue->cv.wait(wait_lock);
		}
	}
	if (op == 9 &&
	    (SysAvGuestObjectAt(addr, 0x200000ae4) || SysAvGuestObjectAt(addr, 0x200000ba4) ||
	     SysAvGuestObjectAt(addr, 0x2000034a4) || SysAvGuestObjectAt(addr, 0x200003244)) &&
	    request.args[2] == 8 && request.args[3] == 0 && request.args[4] == 0 &&
	    request.args[5] == ((addr & 0xfffull) == 0xae4   ? 0x1020003
	                        : (addr & 0xfffull) == 0xba4 ? 0x1020005
	                        : (addr & 0xfffull) == 0x4a4 ? 0x1020015
	                                                     : 0x102000e) &&
	    valid_guest_word(addr, true)) {
		auto     queue    = SysAvUmtxGetQueue(addr);
		unsigned awakened = 0;
		{
			std::lock_guard lock(queue->mutex);
			awakened = queue->waiters > 0 ? 1u : 0u;
			if (awakened != 0) {
				++queue->generation;
			}
		}
		if (awakened != 0) {
			queue->cv.notify_one();
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_UMTX_CV_SIGNAL"
		     " cv=0x%016" PRIx64 " pending_guest_waiter=%u"
		     " guest_signal_dispatched\n",
		     addr, awakened);
		return {0, 0};
	}
	if (op == 8 &&
	    ((SysAvGuestObjectAt(addr, 0x200000ae4) &&
	      SysAvGuestObjectAt(request.args[3], 0x200000a80) && request.args[5] == 0x1020003) ||
	     (SysAvGuestObjectAt(addr, 0x200000ba4) &&
	      SysAvGuestObjectAt(request.args[3], 0x200000b40) && request.args[5] == 0x1020005 &&
	      (request.args[2] & 0xffffu) == 0xeu) ||
	     (SysAvGuestObjectAt(addr, 0x2000034a4) &&
	      SysAvGuestObjectAt(request.args[3], 0x200003440) && request.args[5] == 0x1020015) ||
	     (SysAvGuestObjectAt(addr, 0x200003244) &&
	      SysAvGuestObjectAt(request.args[3], 0x200003140) && request.args[5] == 0x102000e &&
	      (((request.args[2] & 0xffffu) == 8u && request.args[4] != 0) ||
	       ((request.args[2] & 0xffffu) == 0xeu && request.args[4] == 0)))) &&
	    valid_guest_word(addr, true) && valid_guest_word(request.args[3], true)) {
		const bool timed = SysAvGuestObjectAt(addr, 0x200003244) && request.args[4] != 0;
		if (!SysAvGuestObjectAt(addr, 0x200003244) && request.args[4] != 0) {
			return {-1, Libs::Posix::POSIX_ENOSYS};
		}
		LibKernel::KernelTimespec timeout {};
		if (timed) {
			const uint64_t                      input = request.args[4];
			LibKernel::Memory::VirtualQueryInfo region {};
			if (input > UINT64_MAX - sizeof(timeout) ||
			    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(input), 0,
			                                          &region, sizeof(region)) != 0 ||
			    !region.is_committed || region.start > input ||
			    region.end < input + sizeof(timeout) || (region.protection & 1u) == 0) {
				return {-1, Libs::Posix::POSIX_EFAULT};
			}
			std::memcpy(&timeout, reinterpret_cast<const void*>(input), sizeof(timeout));
			if (timeout.tv_sec != 0 || timeout.tv_nsec != 10000000) {
				return {-1, Libs::Posix::POSIX_EINVAL};
			}
		}
		auto                      cond_queue  = SysAvUmtxGetQueue(addr);
		auto                      mutex_queue = SysAvUmtxGetQueue(request.args[3]);
		auto&                     cond_word   = *reinterpret_cast<uint32_t*>(addr);
		auto&                     owner_word  = *reinterpret_cast<uint32_t*>(request.args[3]);
		std::atomic_ref<uint32_t> owner(owner_word);
		std::atomic_ref<uint32_t> cond_waiters_word(cond_word);
		const uint32_t   guest_tid = static_cast<uint32_t>(LibKernel::PthreadGetthreadid());
		std::unique_lock wait_lock(cond_queue->mutex);
		const uint32_t   prior_owner = owner.load(std::memory_order_acquire);
		if ((prior_owner & 0x7fffffffu) != guest_tid) {
			return {-1, Libs::Posix::POSIX_EPERM};
		}
		const auto generation = cond_queue->generation;
		++cond_queue->waiters;
		cond_waiters_word.store(1u, std::memory_order_release);
		// release the guest mutex before blocking, like FreeBSD CV_WAIT
		// do_unlock_normal leaves CONTESTED behind while more than one contender is queued;
		// dropping it lets the next owner unlock on the fast path and strand them.
		uint32_t expected      = prior_owner;
		uint32_t released      = 0;
		unsigned mutex_waiters = 0;
		{
			std::lock_guard mutex_lock(mutex_queue->mutex);
			mutex_waiters = mutex_queue->waiters;
			released      = mutex_waiters > 1 ? 0x80000000u : 0u;
			while (!owner.compare_exchange_weak(expected, released, std::memory_order_acq_rel) &&
			       (expected & 0x7fffffffu) == guest_tid) {
			}
			if ((expected & 0x7fffffffu) == guest_tid) {
				++mutex_queue->generation;
			}
		}
		if ((expected & 0x7fffffffu) != guest_tid) {
			--cond_queue->waiters;
			if (cond_queue->waiters == 0) {
				cond_waiters_word.store(0u, std::memory_order_release);
			}
			return {-1, Libs::Posix::POSIX_EBUSY};
		}
		mutex_queue->cv.notify_all();
		LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_UMTX_CV_WAIT"
		     " cv=0x%016" PRIx64 " mutex=0x%016" PRIx64
		     " released_owner=%u mutex_waiters=%u released_word=0x%08x guest_wait\n",
		     addr, request.args[3], guest_tid, mutex_waiters, released);
		bool signaled = true;
		if (timed) {
			signaled =
			    cond_queue->cv.wait_for(wait_lock, std::chrono::nanoseconds(timeout.tv_nsec),
				                        [&] { return cond_queue->generation != generation; });
		} else {
			cond_queue->cv.wait(wait_lock, [&] { return cond_queue->generation != generation; });
		}
		--cond_queue->waiters;
		if (cond_queue->waiters == 0) {
			cond_waiters_word.store(0u, std::memory_order_release);
		}
		if (!signaled) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_UMTX_CV_TIMED_OUT"
			     " cv=0x%016" PRIx64 " guest_tid=%u"
			     " measured_wait_ns=%" PRId64 " guest_timeout_without_signal\n",
			     addr, guest_tid, timeout.tv_nsec);
			return {-1, Libs::Posix::POSIX_ETIMEDOUT};
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_UMTX_CV_WOKEN"
		     " cv=0x%016" PRIx64 " guest_tid=%u"
		     " signal_received\n",
		     addr, guest_tid);
		return {0, 0};
	}
	// 0x4703E0..0x470435: cmpxchg owner to 0, then _umtx_op(23) if CONTESTED was set
	// not stock FreeBSD numbering - 23 is the mutex wake and its wait (17) uses this same queue
	// 0x980: flags 0x400, id 0xff010100. Any mutex whose wake names its own flags and id is
	// accepted
	if (op == 23 &&
	    (((addr == 0x54a208 || addr == 0x550f20 || SysAvGuestObjectAt(addr, 0x200003140) ||
	       SysAvGuestObjectAt(addr, 0x200000a80) || SysAvGuestObjectAt(addr, 0x200000980)) &&
	      request.args[2] ==
	          (SysAvGuestObjectAt(addr, 0x200003140) || SysAvGuestObjectAt(addr, 0x200000a80) ||
	                   SysAvGuestObjectAt(addr, 0x200000980)
	               ? 0x400u
				   : 0u) &&
	      (!SysAvGuestObjectAt(addr, 0x200000a80) || request.args[5] == 0x1010002u) &&
	      (!SysAvGuestObjectAt(addr, 0x200000980) || request.args[5] == 0xff010100u) &&
	      (!SysAvGuestObjectAt(addr, 0x200003140) || request.args[5] == 0x101000bu) &&
	      (addr != 0x550f20 || request.args[5] == 0xffffffffu)) ||
	     (valid_guest_word(addr + 4, false) &&
	      request.args[2] == *reinterpret_cast<const uint32_t*>(addr + 4) &&
	      mutex_id_matches(addr, request.args[5]))) &&
	    request.args[3] == 0 && request.args[4] == 0 && valid_guest_word(addr, true) &&
	    valid_guest_word(addr + 4, false)) {
		auto& guest_owner_word = *reinterpret_cast<uint32_t*>(addr);
		auto& guest_flags      = *reinterpret_cast<const uint32_t*>(addr + 4);
		if ((guest_flags & 0x0cu) != 0 || (guest_flags & 0x100u) != 0) {
			return {-1, Libs::Posix::POSIX_ENOSYS};
		}
		std::atomic_ref<uint32_t> guest_owner(guest_owner_word);
		auto                      queue    = SysAvUmtxGetQueue(addr);
		bool                      wake_one = false;
		unsigned                  queued   = 0;
		{
			std::lock_guard lock(queue->mutex);
			queued            = queue->waiters;
			const auto before = guest_owner.load(std::memory_order_acquire);
			if ((before & 0x7fffffffu) == 0u) {
				wake_one = queued != 0;
				if (queued > 1) {
					// Keep contention for the remaining waiters.
					guest_owner.fetch_or(0x80000000u, std::memory_order_acq_rel);
				} else if (queued == 0) {
					// Do not erase an owner acquired by another thread.
					uint32_t expected = 0x80000000u;
					guest_owner.compare_exchange_strong(expected, 0u, std::memory_order_acq_rel);
				}
				if (wake_one) {
					++queue->generation;
				}
			} else if (queued != 0) {
				// relocked between the atomic unlock and the kernel call: contested, not free
				guest_owner.fetch_or(0x80000000u, std::memory_order_acq_rel);
			}
		}
		// notify_all: the RW ops share this cv for 0x28c0, and every woken mutex waiter re-checks
		// the word before returning.
		if (wake_one) {
			queue->cv.notify_all();
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_UMTX_MUTEX_WAKE"
		     " mutex=0x%016" PRIx64 " waiting_guest_threads=%u"
		     " one_waiter_notified=%u"
		     " current_guest_owner_word=0x%08x\n",
		     addr, queued, wake_one ? 1u : 0u, guest_owner.load(std::memory_order_acquire));
		return {0, 0};
	}
	// MUTEX_WAIT (17) doesn't grant the mutex, the caller cmpxchgs it afterwards
	if (op == 17 &&
	    (((SysAvGuestObjectAt(addr, 0x200000a80) || SysAvGuestObjectAt(addr, 0x200000980) ||
	       addr == 0x54a208 || addr == 0x550f20 || SysAvGuestObjectAt(addr, 0x2000028c0) ||
	       SysAvGuestObjectAt(addr, 0x200003440) || SysAvGuestObjectAt(addr, 0x200003140)) &&
	      (!SysAvGuestObjectAt(addr, 0x200000a80) || request.args[5] == 0x1010002) &&
	      (!SysAvGuestObjectAt(addr, 0x200000980) || request.args[5] == 0xff010100u) &&
	      (!SysAvGuestObjectAt(addr, 0x200003140) || request.args[5] == 0x101000b)) ||
	     (valid_guest_word(addr + 4, false) &&
	      (*reinterpret_cast<const uint32_t*>(addr + 4) & 0x0cu) == 0 &&
	      mutex_id_matches(addr, request.args[5]))) &&
	    request.args[2] == 0 && request.args[3] == 0 && request.args[4] == 0 &&
	    valid_guest_word(addr, true)) {
		auto                      queue = SysAvUmtxGetQueue(addr);
		std::unique_lock          lock(queue->mutex);
		auto&                     word = *reinterpret_cast<uint32_t*>(addr);
		std::atomic_ref<uint32_t> owner(word);
		// FreeBSD do_lock_normal(_UMUTEX_WAIT): CAS CONTESTED on, sleep for a wake, re-read. A
		// fast-path relock in between clears CONTESTED, so set it again before sleeping.
		uint32_t       current        = owner.load(std::memory_order_acquire);
		const uint32_t original_owner = current & 0x7fffffffu;
		unsigned       sleeps         = 0;
		while ((current & 0x7fffffffu) != 0u) {
			if (!owner.compare_exchange_strong(current, current | 0x80000000u,
			                                   std::memory_order_acq_rel)) {
				continue;
			}
			if (sleeps++ == 0) {
				LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_UMTX_MUTEX_WAIT"
				     " mutex=0x%016" PRIx64 " owner=%u guest_tid=%d"
				     " guest_wait\n",
				     addr, original_owner, LibKernel::PthreadGetthreadid());
			}
			++queue->waiters;
			const auto generation = queue->generation;
			queue->cv.wait(lock, [&] { return queue->generation != generation; });
			--queue->waiters;
			current = owner.load(std::memory_order_acquire);
		}
		if (sleeps != 0) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_UMTX_MUTEX_WAIT_RETURNED"
			     " mutex=0x%016" PRIx64 " guest_tid=%d sleeps=%u"
			     " current_guest_owner_word=0x%08x\n",
			     addr, LibKernel::PthreadGetthreadid(), sleeps, current);
		}
		return {0, 0};
	}
	return {-1, Libs::Posix::POSIX_ENOSYS};
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
	if (request.args[1] == 0x2400000 && request.args[2] == 0x4c22f2) {
		const uint64_t                      addr = request.args[0];
		LibKernel::Memory::VirtualQueryInfo region {};
		if (addr == 0 || addr > UINT64_MAX - request.args[1] ||
		    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(addr), 0, &region,
		                                          sizeof(region)) != 0 ||
		    !region.is_committed || region.start > addr || region.end < addr + request.args[1] ||
		    (region.protection & 3u) != 3u ||
		    std::memcmp(reinterpret_cast<const void*>(request.args[2]), "SceAvControlBootSplash",
		                sizeof("SceAvControlBootSplash")) != 0) {
			return {-1, Libs::Posix::POSIX_EINVAL};
		}
		const int rc = LibKernel::Memory::KernelSetVirtualRangeName(
		    reinterpret_cast<const void*>(addr), request.args[1], "SceAvControlBootSplash");
		if (rc != 0) return {-1, LibKernel::KernelToPosix(rc)};
		LOGF("FIRST_FRAME_AUDIT SYSAV_SPLASH_DIRECT_MAPPING_NAMED"
		     " guest_va=0x%016" PRIx64 " size=0x%016" PRIx64 " name=SceAvControlBootSplash"
		     " COMMITTED_DIRECT_MEMORY\n",
		     addr, request.args[1]);
		return {0, 0};
	}
	if (request.args[1] == 0x10000 && request.args[2] == 0x4cfa70) {
		const uint64_t                      top  = LibKernel::PthreadGetMainGuestStackTop();
		const uint64_t                      addr = request.args[0];
		LibKernel::Memory::VirtualQueryInfo target {};
		LibKernel::Memory::VirtualQueryInfo name_region {};
		const uint64_t capacity = LibKernel::Memory::KERNEL_MAXIMUM_NAME_LENGTH;
		if (top <= 0x25c000 || addr != top - 0x25c000 ||
		    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(addr), 0, &target,
		                                          sizeof(target)) != 0 ||
		    !target.is_committed || target.start > addr || target.end < addr + 0x10000 ||
		    target.protection != 7u ||
		    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(request.args[2]), 0,
		                                          &name_region, sizeof(name_region)) != 0 ||
		    !name_region.is_committed || (name_region.protection & 1u) == 0 ||
		    name_region.start > request.args[2] || name_region.end < request.args[2] + capacity ||
		    std::memchr(reinterpret_cast<const void*>(request.args[2]), 0, capacity) == nullptr) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		const auto* original_name = reinterpret_cast<const char*>(request.args[2]);
		const int   rc            = LibKernel::Memory::KernelSetVirtualRangeName(
		    reinterpret_cast<const void*>(addr), 0x10000, original_name);
		if (rc != 0) return {-1, LibKernel::KernelToPosix(rc)};
		LOGF("FIRST_FRAME_AUDIT SYSAV_IPMI_NATIVE_STACK_NAMED"
		     " usable_guest_va=0x%016" PRIx64 " guest_name=%s virtual_range_renamed\n",
		     addr, original_name);
		return {0, 0};
	}
	if ((request.args[2] == 0x4c1877 && request.args[1] == 0x20000) ||
	    (request.args[2] == 0x4c8c66 && request.args[1] == 0x8000) ||
	    (request.args[2] == 0x4bec14 && request.args[1] == 0x8000)) {
		const uint64_t                      top     = LibKernel::PthreadGetMainGuestStackTop();
		const uint64_t                      address = request.args[0];
		const uint64_t                      offset  = request.args[2] == 0x4c1877   ? 0x23c000
		                                              : request.args[2] == 0x4bec14 ? 0x268000
		                                                                            : 0x248000;
		const uint64_t                      span    = request.args[1];
		LibKernel::Memory::VirtualQueryInfo target {};
		LibKernel::Memory::VirtualQueryInfo name_region {};
		if (top <= offset || address != top - offset ||
		    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(address), 0,
		                                          &target, sizeof(target)) != 0 ||
		    !target.is_committed || target.start > address || target.end < address + span ||
		    target.protection != 7u ||
		    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(request.args[2]), 0,
		                                          &name_region, sizeof(name_region)) != 0 ||
		    !name_region.is_committed || (name_region.protection & 1u) == 0 ||
		    name_region.start > request.args[2] ||
		    name_region.end < request.args[2] + LibKernel::Memory::KERNEL_MAXIMUM_NAME_LENGTH ||
		    std::memchr(reinterpret_cast<const void*>(request.args[2]), 0,
		                LibKernel::Memory::KERNEL_MAXIMUM_NAME_LENGTH) == nullptr) {
			return {-1, Libs::Posix::POSIX_EINVAL};
		}
		const int rc = LibKernel::Memory::KernelSetVirtualRangeName(
		    reinterpret_cast<const void*>(address), static_cast<size_t>(span),
		    reinterpret_cast<const char*>(request.args[2]));
		if (rc != 0) {
			return {-1, LibKernel::KernelToPosix(rc)};
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_SPLASH_NATIVE_STACK_NAMED"
		     " guest_addr=0x%016" PRIx64 " size=0x%016" PRIx64 " guest_name_pointer=0x%016" PRIx64
		     " virtual_region_renamed\n",
		     address, span, request.args[2]);
		return {0, 0};
	}
	if (request.args[1] == 0x2000 && request.args[2] != 0) {
		LibKernel::Memory::VirtualQueryInfo guest_name_region {};
		const uint64_t                      text_address = request.args[2];
		const auto                          text_size    = sizeof("/SceAvControl");
		if (text_address > UINT64_MAX - text_size ||
		    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(text_address), 0,
		                                          &guest_name_region,
		                                          sizeof(guest_name_region)) != 0 ||
		    !guest_name_region.is_committed || (guest_name_region.protection & 1u) == 0 ||
		    guest_name_region.start > text_address ||
		    guest_name_region.end < text_address + text_size ||
		    std::memcmp(reinterpret_cast<const void*>(text_address), "/SceAvControl", text_size) !=
		        0) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		LibKernel::Memory::VirtualQueryInfo mapped {};
		const uint64_t                      address = request.args[0];
		if (address == 0 || address > UINT64_MAX - 0x2000 ||
		    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(address), 0,
		                                          &mapped, sizeof(mapped)) != 0 ||
		    !mapped.is_committed || !mapped.is_flexible || mapped.start > address ||
		    mapped.end < address + 0x2000 || (mapped.protection & 3u) != 3u) {
			return {-1, Libs::Posix::POSIX_EINVAL};
		}
		const int rc = LibKernel::Memory::KernelSetVirtualRangeName(
		    reinterpret_cast<const void*>(address), 0x2000, "/SceAvControl");
		if (rc != 0) {
			return {-1, LibKernel::KernelToPosix(rc)};
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_SHM_NAMED"
		     " guest_va=0x%016" PRIx64 " guest_range_name=/SceAvControl\n",
		     address);
		return {0, 0};
	}
	if ((request.args[2] != 0x4cd692 && request.args[2] != 0x4d14bc &&
	     request.args[2] != 0x4c0d73)) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const auto main_stack_top = LibKernel::PthreadGetMainGuestStackTop();
	const auto addr           = request.args[0];
	const bool guard          = request.args[2] == 0x4cd692;
	const auto expected_addr =
	    main_stack_top -
	    (guard ? ((main_stack_top > 0x240000 && addr == main_stack_top - 0x240000)
	                  ? 0x240000
	                  : ((main_stack_top > 0x24c000 && addr == main_stack_top - 0x24c000)
	                         ? 0x24c000
	                         : ((addr == main_stack_top - 0x21c000) ? 0x21c000 : 0x210000)))
	           : ((request.args[2] == 0x4c0d73) ? 0x218000 : 0x20c000));
	const auto  expected_size = guard ? 0x4000u : 0x8000u;
	const char* guest_name    = guard ? "stack guard"
	                                  : (request.args[2] == 0x4c0d73 ? "threadForPortControllerB"
	                                                                 : "threadForPortControllerA");
	if (main_stack_top <= 0x21c000 || addr != expected_addr || request.args[1] != expected_size) {
		return {-1, Libs::Posix::POSIX_EINVAL};
	}
	LibKernel::Memory::VirtualQueryInfo range {};
	if (LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(addr), 0, &range,
	                                          sizeof(range)) != 0 ||
	    !range.is_committed || range.start > addr || range.end < addr + request.args[1] ||
	    range.protection != (guard ? 0u : 7u)) {
		return {-1, Libs::Posix::POSIX_EINVAL};
	}
	const int rc = LibKernel::Memory::KernelSetVirtualRangeName(reinterpret_cast<const void*>(addr),
	                                                            request.args[1], guest_name);
	if (rc != 0) {
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_THREAD_STACK_NAMED"
	     " addr=0x%016" PRIx64 " size=0x%016" PRIx64 " guest_virtual_range_name=%s\n",
	     addr, request.args[1], guest_name);
	return {0, 0};
}

Reply SysAvNameOriginalSharedMemory(const SyscallRequest& request) {
	// 0x24C names the 0x2000-byte /SceAvControl mapping
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[1] != 0x2000 || request.args[0] == 0 || request.args[2] == 0 ||
	    request.args[0] > UINT64_MAX - request.args[1] ||
	    request.args[2] > UINT64_MAX - LibKernel::Memory::KERNEL_MAXIMUM_NAME_LENGTH) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	LibKernel::Memory::VirtualQueryInfo target {};
	LibKernel::Memory::VirtualQueryInfo name_range {};
	if (LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(request.args[0]), 0,
	                                          &target, sizeof(target)) != 0 ||
	    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(request.args[2]), 0,
	                                          &name_range, sizeof(name_range)) != 0 ||
	    !target.is_committed || target.start > request.args[0] ||
	    target.end < request.args[0] + request.args[1] || (target.protection & 2) == 0 ||
	    std::strcmp(target.name, "shared_mmap") != 0 || !name_range.is_committed ||
	    name_range.start > request.args[2] ||
	    name_range.end < request.args[2] + LibKernel::Memory::KERNEL_MAXIMUM_NAME_LENGTH ||
	    (name_range.protection & 1) == 0) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	char name[LibKernel::Memory::KERNEL_MAXIMUM_NAME_LENGTH] {};
	std::memcpy(name, reinterpret_cast<const void*>(request.args[2]), sizeof(name));
	if (std::memchr(name, 0, sizeof(name)) == nullptr) {
		return {-1, Libs::Posix::POSIX_ENAMETOOLONG};
	}
	const int rc = LibKernel::Memory::KernelSetVirtualRangeName(
	    reinterpret_cast<const void*>(request.args[0]), request.args[1], name);
	if (rc != 0) {
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_SHM_NAME_APPLIED"
	     " addr=0x%016" PRIx64 " size=0x%016" PRIx64 " guest_name=%s virtual_region_renamed\n",
	     request.args[0], request.args[1], name);
	return {0, 0};
}

bool SysAvGuestNameIs(uint64_t name_addr, const char* expected) {
	const uint64_t n = std::strlen(expected) + 1;
	if (name_addr == 0 || name_addr > UINT64_MAX - n) return false;
	LibKernel::Memory::VirtualQueryInfo region {};
	if (LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(name_addr), 0, &region,
	                                          sizeof(region)) != 0 ||
	    !region.is_committed || !(region.protection & 1u) || region.start > name_addr ||
	    region.end < name_addr + n) {
		return false;
	}
	return std::memcmp(reinterpret_cast<const void*>(name_addr), expected, n) == 0;
}

Reply SysAvNameAudioSharedMemory(const SyscallRequest& request) {
	// same for the 0x4000-byte /SceAo2TVCorP mapping. The router already matched the name.
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[1] != 0x4000 || request.args[0] == 0 || request.args[2] == 0 ||
	    request.args[0] > UINT64_MAX - request.args[1] ||
	    request.args[2] > UINT64_MAX - LibKernel::Memory::KERNEL_MAXIMUM_NAME_LENGTH) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	LibKernel::Memory::VirtualQueryInfo target {};
	LibKernel::Memory::VirtualQueryInfo name_range {};
	if (LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(request.args[0]), 0,
	                                          &target, sizeof(target)) != 0 ||
	    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(request.args[2]), 0,
	                                          &name_range, sizeof(name_range)) != 0 ||
	    !target.is_committed || target.start > request.args[0] ||
	    target.end < request.args[0] + request.args[1] || (target.protection & 2) == 0 ||
	    !name_range.is_committed || name_range.start > request.args[2] ||
	    name_range.end < request.args[2] + LibKernel::Memory::KERNEL_MAXIMUM_NAME_LENGTH ||
	    (name_range.protection & 1) == 0) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	// scope-shared, mapped by the scope direct mapper, so not tagged "shared_mmap"
	char name[LibKernel::Memory::KERNEL_MAXIMUM_NAME_LENGTH] {};
	std::memcpy(name, reinterpret_cast<const void*>(request.args[2]), sizeof(name));
	if (std::memchr(name, 0, sizeof(name)) == nullptr) {
		return {-1, Libs::Posix::POSIX_ENAMETOOLONG};
	}
	const int rc = LibKernel::Memory::KernelSetVirtualRangeName(
	    reinterpret_cast<const void*>(request.args[0]), request.args[1], name);
	if (rc != 0) {
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_AUDIO_SHM_NAME_APPLIED"
	     " addr=0x%016" PRIx64 " size=0x%016" PRIx64 " guest_name=%s virtual_region_renamed\n",
	     request.args[0], request.args[1], name);
	return {0, 0};
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

Reply SysAvCloseOriginalEventFlag(const SyscallRequest& request) {
	// 0x21D can follow a failed SceBootStatusFlags open with garbage in RDI; don't dereference it
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	auto actual = reinterpret_cast<LibKernel::EventFlag::KernelEventFlag>(request.args[0]);
	if (std::getenv("KYTY_DIAGNOSTIC_SYSAV_MINI_SYSCORE_BOOT_EVENTS") != nullptr &&
	    OriginalNativeHandle32IsCanonical(request.args[0])) {
		LibKernel::EventFlag::KernelEventFlag verified = nullptr;
		if (LibKernel::EventFlag::KernelResolveOriginalBootStatusHandle(
		        static_cast<uint32_t>(request.args[0]), &verified) == 0) {
			actual = verified;
		}
	}
	const int rc = LibKernel::EventFlag::KernelCloseEventFlag(actual);
	if (rc != 0) {
		const int err = LibKernel::KernelToPosix(rc);
		LOGF("FIRST_FRAME_AUDIT SYSAV_EVENTFLAG_CLOSE_LOOKUP"
		     " raw_guest_handle=0x%016" PRIx64 " registry_error=0x%08x\n",
		     request.args[0], static_cast<uint32_t>(rc));
		return {-1, err};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_EVENTFLAG_CLOSE"
	     " raw_guest_handle=0x%016" PRIx64 " handle_released\n",
	     request.args[0]);
	return {0, 0};
}

Reply SysAvOpenOriginalBootStatusFlag(const SyscallRequest& request) {
	constexpr char name[] = "SceBootStatusFlags";
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[0] != 0x4c4142 || request.args[0] > UINT64_MAX - sizeof(name)) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	LibKernel::Memory::VirtualQueryInfo region {};
	const int                           query_rc = LibKernel::Memory::KernelVirtualQuery(
	    reinterpret_cast<const void*>(request.args[0]), 0, &region, sizeof(region));
	if (query_rc != 0 || !region.is_committed || region.start > request.args[0] ||
	    region.end < request.args[0] + sizeof(name) || (region.protection & 1u) == 0 ||
	    std::memcmp(reinterpret_cast<const void*>(request.args[0]), name, sizeof(name)) != 0) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	LibKernel::EventFlag::KernelEventFlag actual_flag = nullptr;
	const int rc = LibKernel::EventFlag::KernelOpenExistingEventFlag(&actual_flag, name);
	if (rc != 0) {
		LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_BOOT_STATUS_OPEN_FAILED"
		     " guest_name=%s"
		     " registry_result=0x%08x\n",
		     name, static_cast<uint32_t>(rc));
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_EXISTING_EVENTFLAG_OPENED"
	     " name=%s flag=0x%016" PRIx64 " guest_32bit_handle=0x%08x"
	     " created_by_virtual_mini_syscore_service\n",
	     name, reinterpret_cast<uint64_t>(actual_flag),
	     static_cast<uint32_t>(reinterpret_cast<uintptr_t>(actual_flag)));
	return {reinterpret_cast<int64_t>(actual_flag), 0};
}

Reply SysAvCreateOriginalAvEventFlag(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[0] != 0x4d5da0 || request.args[1] != 0x121 ||
	    request.args[2] != 0x0000ffff00000000ull) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	LibKernel::Memory::VirtualQueryInfo name_region {};
	if (LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(request.args[0]), 0,
	                                          &name_region, sizeof(name_region)) != 0 ||
	    !name_region.is_committed || name_region.start > request.args[0] ||
	    name_region.end < request.args[0] + sizeof("SceAvControlEvf") ||
	    (name_region.protection & 1) == 0 ||
	    std::memcmp(reinterpret_cast<const void*>(request.args[0]), "SceAvControlEvf",
	                sizeof("SceAvControlEvf")) != 0) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	LibKernel::EventFlag::KernelEventFlag real_flag = nullptr;
	const int rc = LibKernel::EventFlag::KernelCreateEventFlag(&real_flag, "SceAvControlEvf", 0x121,
	                                                           0x0000ffff00000000ull, nullptr);
	if (rc != 0 || real_flag == nullptr) {
		LOGF("FIRST_FRAME_AUDIT SYSAV_AV_EVENTFLAG_CREATE_FAILED"
		     " kernel_error=0x%08x\n",
		     static_cast<uint32_t>(rc));
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_AV_EVENTFLAG_CREATED"
	     " name=SceAvControlEvf attr=0x121"
	     " initial_bits=0x0000ffff00000000"
	     " event_flag_handle=0x%016" PRIx64 "\n",
	     reinterpret_cast<uint64_t>(real_flag));
	g_original_av_event_flag.store(reinterpret_cast<uint64_t>(real_flag));
	return {static_cast<int64_t>(reinterpret_cast<uint64_t>(real_flag)), 0};
}

Reply SysAvWaitOriginalAvEventFlag(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	// splash 0x439610 waits on SceBootStatusFlags bit 0x2000, mode1
	if (std::getenv("KYTY_DIAGNOSTIC_SYSAV_MINI_SYSCORE_BOOT_EVENTS") &&
	    (request.args[1] == 0x2000ull || request.args[1] == 0x10ull) && request.args[2] == 1 &&
	    OriginalNativeHandle32IsCanonical(request.args[0]) && request.args[4] == 0) {
		LibKernel::EventFlag::KernelEventFlag actual = nullptr;
		const int resolved = LibKernel::EventFlag::KernelResolveOriginalBootStatusHandle(
		    static_cast<uint32_t>(request.args[0]), &actual);
		if (resolved != 0 || actual == nullptr) {
			return {-1, LibKernel::KernelToPosix(resolved)};
		}
		if (request.args[3] != 0) {
			LibKernel::Memory::VirtualQueryInfo region {};
			if (request.args[3] > UINT64_MAX - sizeof(uint64_t) ||
			    LibKernel::Memory::KernelVirtualQuery(
			        reinterpret_cast<const void*>(request.args[3]), 0, &region, sizeof(region)) !=
			        0 ||
			    !region.is_committed || region.start > request.args[3] ||
			    region.end < request.args[3] + sizeof(uint64_t) || (region.protection & 2u) == 0) {
				return {-1, Libs::Posix::POSIX_EFAULT};
			}
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_SPLASH_BOOT_FLAG_WAIT"
		     " splash_body=0x439610"
		     " matched_mini_syscore_event_handle=0x%016" PRIx64
		     " guest_requested_bits=0x%016" PRIx64 " wait_mode=1 timeout=NULL\n",
		     reinterpret_cast<uint64_t>(actual), request.args[1]);
		const int rc = LibKernel::EventFlag::KernelWaitEventFlag(
		    actual, request.args[1], 1, reinterpret_cast<uint64_t*>(request.args[3]), nullptr);
		if (rc != 0) return {-1, LibKernel::KernelToPosix(rc)};
		LOGF("FIRST_FRAME_AUDIT SYSAV_SPLASH_BOOT_READY_SIGNAL_RECEIVED"
		     " guest_producer_signalled_requested_bit=0x%016" PRIx64 "\n",
		     request.args[1]);
		return {0, 0};
	}
	if (request.args[1] != 0x0000ffff00000000ull || request.args[2] != 0x22 ||
	    request.args[3] == 0 || request.args[4] == 0) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const uint64_t actual_handle = g_original_av_event_flag.load();
	if (actual_handle == 0 || request.args[0] != static_cast<uint32_t>(actual_handle)) {
		return {-1, Libs::Posix::POSIX_ESRCH};
	}
	auto*     result_pattern = reinterpret_cast<uint64_t*>(request.args[3]);
	auto*     timeout        = reinterpret_cast<LibKernel::KernelUseconds*>(request.args[4]);
	const int rc             = LibKernel::EventFlag::KernelWaitEventFlag(
	    reinterpret_cast<LibKernel::EventFlag::KernelEventFlag>(actual_handle), request.args[1],
	    static_cast<uint32_t>(request.args[2]), result_pattern, timeout);
	if (rc != 0) {
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_AV_EVENTFLAG_WAIT"
	     " guest_handle=0x%08x host_handle=0x%016" PRIx64 " wait_bits=0x%016" PRIx64
	     " mode=0x22 guest_wait_completed\n",
	     static_cast<uint32_t>(request.args[0]), actual_handle, *result_pattern);
	return {0, 0};
}

Reply SysAvPollOriginalBootEventFlag(const SyscallRequest& request) {
	// 0x21F poll. Ready bits 0x2000/0x10, stop-splash 0x20000, mode1; nonblocking
	if (!std::getenv("KYTY_DIAGNOSTIC_SYSAV_MINI_SYSCORE_BOOT_EVENTS") ||
	    !std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") ||
	    !OriginalNativeHandle32IsCanonical(request.args[0]) ||
	    (request.args[1] != 0x2000 && request.args[1] != 0x10 && request.args[1] != 0x20000) ||
	    request.args[2] != 1) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	LibKernel::EventFlag::KernelEventFlag real = nullptr;
	const int resolved = LibKernel::EventFlag::KernelResolveOriginalBootStatusHandle(
	    static_cast<uint32_t>(request.args[0]), &real);
	if (resolved != 0 || real == nullptr) {
		return {-1, LibKernel::KernelToPosix(resolved)};
	}
	if (request.args[3] != 0) {
		LibKernel::Memory::VirtualQueryInfo region {};
		if (request.args[3] > UINT64_MAX - sizeof(uint64_t) ||
		    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(request.args[3]), 0,
		                                          &region, sizeof(region)) != 0 ||
		    !region.is_committed || region.start > request.args[3] ||
		    region.end < request.args[3] + sizeof(uint64_t) || (region.protection & 2u) == 0) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
	}
	auto*     observed = reinterpret_cast<uint64_t*>(request.args[3]);
	const int rc = LibKernel::EventFlag::KernelPollEventFlag(real, request.args[1], 1, observed);
	static std::atomic<uint32_t> checks {0};
	if (checks.fetch_add(1) < 24) {
		LOGF("FIRST_FRAME_AUDIT SYSAV_BOOT_FLAG_POLL"
		     " splash=0x439610 syscall=0x21f"
		     " requested_bits=0x%016" PRIx64 " registered_handle=0x%016" PRIx64
		     " observed_bits=0x%016" PRIx64 " kernel_result=0x%08x\n",
		     request.args[1], reinterpret_cast<uint64_t>(real), observed != nullptr ? *observed : 0,
		     static_cast<uint32_t>(rc));
	}
	if (rc != 0) return {-1, LibKernel::KernelToPosix(rc)};
	return {0, 0};
}

Reply SysAvSetRegisteredOriginalEventFlag(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[1] == 0) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	auto actual = reinterpret_cast<LibKernel::EventFlag::KernelEventFlag>(request.args[0]);
	if (std::getenv("KYTY_DIAGNOSTIC_SYSAV_MINI_SYSCORE_BOOT_EVENTS") != nullptr &&
	    OriginalNativeHandle32IsCanonical(request.args[0]) && request.args[1] != 0) {
		LibKernel::EventFlag::KernelEventFlag verified = nullptr;
		if (LibKernel::EventFlag::KernelResolveOriginalBootStatusHandle(
		        static_cast<uint32_t>(request.args[0]), &verified) == 0) {
			actual = verified;
			LOGF("FIRST_FRAME_AUDIT SYSAV_BOOT_EVENT_HANDLE_RESOLVED"
			     " guest_handle32=0x%08x"
			     " registered_handle=0x%016" PRIx64 " guest_authored_bits=0x%016" PRIx64
			     " matching_exact_named_eventflag\n",
			     static_cast<uint32_t>(request.args[0]), reinterpret_cast<uint64_t>(verified),
			     request.args[1]);
		}
	}
	const int rc = LibKernel::EventFlag::KernelSetRegisteredEventFlag(actual, request.args[1]);
	if (rc != 0) {
		LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_EVENTFLAG_SET_REGISTRY_LOOKUP"
		     " guest_handle=0x%016" PRIx64 " bits=0x%016" PRIx64 " registry_result=0x%08x\n",
		     request.args[0], request.args[1], static_cast<uint32_t>(rc));
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_EVENTFLAG_SET_REGISTERED_OBJECT"
	     " handle=0x%016" PRIx64 " bits=0x%016" PRIx64 " named_eventflag_set\n",
	     request.args[0], request.args[1]);
	return {0, 0};
}

Reply SysAvSetOriginalAvEventFlag(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	// The old AV flag keeps its 32-bit handle convention; other native sets must use a fully
	// registered handle.
	if (request.args[1] != 0x0000ffff00000000ull) {
		return SysAvSetRegisteredOriginalEventFlag(request);
	}
	const uint64_t actual_handle = g_original_av_event_flag.load();
	if (actual_handle == 0 || request.args[0] != static_cast<uint32_t>(actual_handle)) {
		return {-1, Libs::Posix::POSIX_ESRCH};
	}
	if (request.args[1] != 0x0000ffff00000000ull) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const int rc = LibKernel::EventFlag::KernelSetEventFlag(
	    reinterpret_cast<LibKernel::EventFlag::KernelEventFlag>(actual_handle), request.args[1]);
	if (rc != 0) {
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_AV_EVENTFLAG_SET"
	     " guest_handle=0x%08x host_handle=0x%016" PRIx64 " guest_set_bits=0x%016" PRIx64 "\n",
	     static_cast<uint32_t>(request.args[0]), actual_handle, request.args[1]);
	return {0, 0};
}

Reply SysAvDmemContainer(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[0] != UINT32_MAX) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const size_t physical_size = LibKernel::Memory::KernelGetDirectMemorySize();
	if (physical_size < 36ull * 1024 * 1024) {
		return {-1, Libs::Posix::POSIX_ENOMEM};
	}
	int64_t   available_start = 0;
	size_t    available_bytes = 0;
	const int rc              = LibKernel::Memory::KernelAvailableDirectMemorySize(
	    0, static_cast<int64_t>(physical_size), 2ull * 1024 * 1024, &available_start,
	    &available_bytes);
	if (rc != 0 || available_bytes < 36ull * 1024 * 1024) {
		return {-1, Libs::Posix::POSIX_ENOMEM};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_DMEM_CONTAINER"
	     " query=-1 virtual_container=0"
	     " backed_by_PhysicalMemory"
	     " size=0x%016" PRIx64 " contiguous_avail=0x%016" PRIx64 " guest_alloc_not_yet_performed\n",
	     static_cast<uint64_t>(physical_size), static_cast<uint64_t>(available_bytes));
	return {0, 0};
}

Reply SysAvBlockpoolOpen(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[0] != 0) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_BLOCKPOOL_OPEN"
	     " argument=0 result=ENOSYS\n");
	return {-1, Libs::Posix::POSIX_ENOSYS};
}

// 104-byte thr_new block from 0x474CF1..0x474D5B; start_func is the 0x475030 bootstrap
struct SysAvNativeThrParams {
	uint64_t start_func;
	uint64_t arg;
	uint64_t stack_base;
	uint64_t stack_size;
	uint64_t tls_base;
	uint64_t tls_size;
	uint64_t child_tid;
	uint64_t parent_tid;
	uint64_t flags;
	uint64_t rtprio;
	uint64_t spare0;
	uint64_t spare1;
	uint64_t spare2;
};
static_assert(sizeof(SysAvNativeThrParams) == 0x68);
static_assert(offsetof(SysAvNativeThrParams, tls_base) == 0x20);
static_assert(offsetof(SysAvNativeThrParams, child_tid) == 0x30);
static_assert(offsetof(SysAvNativeThrParams, flags) == 0x40);

struct SysAvThreadStartup {
	std::mutex              mutex;
	std::condition_variable ready_cv;
	uint64_t                original_entry   = 0;
	uint64_t                original_arg     = 0;
	uint64_t                original_tls     = 0;
	int                     native_guest_tid = 0;
	bool                    ready            = false;
	bool                    proceed          = false;
};

static thread_local uint64_t g_sysav_original_thread_state = 0;

static void* KYTY_SYSV_ABI SysAvThreadBootstrap(void* raw) {
	std::unique_ptr<SysAvThreadStartup> startup(static_cast<SysAvThreadStartup*>(raw));
	{
		std::unique_lock lock(startup->mutex);
		startup->native_guest_tid = LibKernel::PthreadGetthreadid();
		startup->ready            = true;
		startup->ready_cv.notify_one();
		startup->ready_cv.wait(lock, [&] { return startup->proceed; });
	}
	Loader::SetSysAvNativeThreadFsBase(startup->original_tls);
	g_sysav_original_thread_state = startup->original_arg;
	LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_THR_NEW_GUEST_ENTRY"
	     " entry=0x%016" PRIx64 " arg=0x%016" PRIx64 " tls_base=0x%016" PRIx64 " guest_tid=%d\n",
	     startup->original_entry, startup->original_arg, startup->original_tls,
	     startup->native_guest_tid);
	const auto entry = reinterpret_cast<LibKernel::pthread_entry_func_t>(startup->original_entry);
	return entry(reinterpret_cast<void*>(startup->original_arg));
}

// thr_exit (0x1AF) from libthr cleanup 0x46FA13..0x46FA28. Must not return to the guest.
Reply SysAvThrExit(const SyscallRequest& request) {
	const int  guest_tid       = LibKernel::PthreadGetthreadid();
	const bool original_worker = guest_tid > 1 && g_sysav_original_thread_state != 0 &&
	                             request.args[0] == g_sysav_original_thread_state;
	const bool original_main   = guest_tid == 1 && g_sysav_original_thread_state == 0 &&
	                             LibKernel::PthreadGetMainGuestStackTop() != 0 &&
	                             SysAvGuestObjectAt(request.args[0], 0x200000120) &&
	                             SysAvGuestObjectAt(request.args[1], 0x200000310) &&
	                             request.args[2] == 0 && request.args[3] == 0;
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    LibKernel::PthreadSelfOrNull() == nullptr || (!original_worker && !original_main)) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	// XXX: no robust-mutex handling, a waiter can still name the exiting thread as owner
	if (original_worker) {
		constexpr uint64_t                  lock_address = 0x550f20;
		LibKernel::Memory::VirtualQueryInfo lock_region {};
		if (LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(lock_address), 0,
		                                          &lock_region, sizeof(lock_region)) == 0 &&
		    lock_region.is_committed && lock_region.start <= lock_address &&
		    lock_region.end >= lock_address + 16 && (lock_region.protection & 1u) != 0) {
			uint32_t lock_words[4] {};
			std::memcpy(lock_words, reinterpret_cast<const void*>(lock_address),
			            sizeof(lock_words));
			LOGF("FIRST_FRAME_AUDIT SYSAV_THR_EXIT_MUTEX"
			     " exiting_guest_tid=%d mutex=0x%016" PRIx64 " guest_words=%08x,%08x,%08x,%08x"
			     " owner_low31=%u\n",
			     guest_tid, lock_address, lock_words[0], lock_words[1], lock_words[2],
			     lock_words[3], lock_words[0] & 0x7fffffffu);
		}
	}
	LOGF("FIRST_FRAME_AUDIT %s"
	     " thread_state=0x%016" PRIx64 " guest_tid=%d cleanup_reached"
	     " PthreadExit\n",
	     original_main ? "SYSAV_NATIVE_MAIN_THR_EXIT" : "SYSAV_NATIVE_THR_EXIT", request.args[0],
	     guest_tid);
	LibKernel::PthreadExit(nullptr);
	return {-1, Libs::Posix::POSIX_ENOSYS};
}

Reply SysAvThrNew(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[1] != sizeof(SysAvNativeThrParams) || request.args[0] == 0) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	auto guest_span = [](uint64_t addr, uint64_t size, bool write) {
		if (addr == 0 || size == 0 || size > UINT64_MAX - addr) {
			return false;
		}
		LibKernel::Memory::VirtualQueryInfo region {};
		const int rc = LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(addr), 0,
		                                                     &region, sizeof(region));
		return rc == 0 && region.is_committed && region.start <= addr &&
		       region.end >= addr + size && (region.protection & (write ? 2u : 1u)) != 0;
	};
	if (!guest_span(request.args[0], sizeof(SysAvNativeThrParams), false)) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	SysAvNativeThrParams params {};
	std::memcpy(&params, reinterpret_cast<const void*>(request.args[0]), sizeof(params));
	// trampoline 0x4750FA/0x475101 takes callback/arg from pthread +0x80/+0x88, not the 0x475030
	// bootstrap
	if (guest_span(params.arg, 0x90, false)) {
		uint64_t target[2] {};
		std::memcpy(target, reinterpret_cast<const void*>(params.arg + 0x80), sizeof(target));
		LOGF("FIRST_FRAME_AUDIT SYSAV_PTHREAD_CALLBACK"
		     " guest_thread_object=0x%016" PRIx64 " callback=0x%016" PRIx64
		     " callback_arg=0x%016" PRIx64 " libthr_callback_offsets=0x80,0x88"
		     " callback_is_logo_0x439610=%u\n",
		     params.arg, target[0], target[1], target[0] == 0x439610 ? 1u : 0u);
	}
	if (params.start_func != 0x475030 || params.flags != 2 || params.stack_size < 0x4000 ||
	    params.stack_size > 0x1000000 || (params.stack_base & 0x3fff) != 0 ||
	    params.tls_size != 0x40 || params.spare1 != 0 || params.spare2 != 0 ||
	    !guest_span(params.stack_base, params.stack_size, true) ||
	    !guest_span(params.tls_base, params.tls_size, true) ||
	    !guest_span(params.parent_tid, sizeof(uint64_t), true) ||
	    !guest_span(params.child_tid, sizeof(uint64_t), true)) {
		return {-1, Libs::Posix::POSIX_EINVAL};
	}
	LibKernel::PthreadAttr attr = nullptr;
	int                    rc   = LibKernel::PthreadAttrInit(&attr);
	if (rc == 0) {
		rc = LibKernel::PthreadAttrSetstack(&attr, reinterpret_cast<void*>(params.stack_base),
		                                    static_cast<size_t>(params.stack_size));
	}
	auto startup                     = std::make_unique<SysAvThreadStartup>();
	startup->original_entry          = params.start_func;
	startup->original_arg            = params.arg;
	startup->original_tls            = params.tls_base;
	LibKernel::Pthread actual_thread = nullptr;
	if (rc == 0) {
		rc = LibKernel::PthreadCreate(&actual_thread, &attr, SysAvThreadBootstrap, startup.get(),
		                              "SceSysAvControl Native");
	}
	if (attr != nullptr) {
		(void)LibKernel::PthreadAttrDestroy(&attr);
	}
	if (rc != 0) {
		LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_THR_NEW_FAILED"
		     " pthread_rc=0x%08x\n",
		     static_cast<uint32_t>(rc));
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	auto* live = startup.release();
	{
		std::unique_lock lock(live->mutex);
		live->ready_cv.wait(lock, [&] { return live->ready; });
		const uint64_t guest_tid = static_cast<uint64_t>(live->native_guest_tid);
		LibKernel::Memory::InvalidateMemory(params.parent_tid, sizeof(guest_tid));
		std::memcpy(reinterpret_cast<void*>(params.parent_tid), &guest_tid, sizeof(guest_tid));
		if (params.child_tid != params.parent_tid) {
			LibKernel::Memory::InvalidateMemory(params.child_tid, sizeof(guest_tid));
			std::memcpy(reinterpret_cast<void*>(params.child_tid), &guest_tid, sizeof(guest_tid));
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_THR_NEW_CREATED"
		     " entry=0x%016" PRIx64 " stack=0x%016" PRIx64 " stack_size=0x%016" PRIx64
		     " tls=0x%016" PRIx64 " guest_tid=%" PRIu64 "\n",
		     params.start_func, params.stack_base, params.stack_size, params.tls_base, guest_tid);
		live->proceed = true;
		live->ready_cv.notify_one();
	}
	return {0, 0};
}

// open(5) at 0x46f12a: /dev/dce, and /dev/dmem0..2 formatted by the initializer at 0x476670
Reply SysAvDceOpen(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[1] != 2 || (request.args[2] != 0 && request.args[0] != 0x4c8a25)) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const char* guest_path = request.args[0] == 0x4c8a25 ? "/dev/dipsw"
	                         : request.args[0] == 0x4c2a7d
	                             ? "/dev/av_control"
	                             : (request.args[0] == 0x4c3bf3 ? "/dev/hdmi" : "/dev/dce");
	char        native_dmem_path[sizeof("/dev/av_control")] {};
	if (request.args[0] != 0x4c04ac && request.args[0] != 0x4c8a25 && request.args[0] != 0x4c2a7d &&
	    request.args[0] != 0x4c3bf3) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		constexpr size_t path_bytes = sizeof(native_dmem_path);
		const auto       ptr        = request.args[0];
		if (ptr == 0 || ptr > UINT64_MAX - path_bytes) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		MEMORY_BASIC_INFORMATION mbi {};
		const auto length     = VirtualQuery(reinterpret_cast<const void*>(ptr), &mbi, sizeof(mbi));
		const auto protection = mbi.Protect & 0xff;
		if (length == 0 || mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) != 0 ||
		    (protection != PAGE_READONLY && protection != PAGE_READWRITE &&
		     protection != PAGE_EXECUTE_READ && protection != PAGE_EXECUTE_READWRITE) ||
		    reinterpret_cast<uint64_t>(mbi.BaseAddress) > ptr || mbi.RegionSize < path_bytes ||
		    ptr - reinterpret_cast<uint64_t>(mbi.BaseAddress) > mbi.RegionSize - path_bytes) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		LibKernel::Memory::VirtualQueryInfo guest {};
		if (LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(ptr), 0, &guest,
		                                          sizeof(guest)) != 0 ||
		    !guest.is_committed || (guest.protection & 1) == 0 || guest.start > ptr ||
		    guest.end < ptr + path_bytes) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		std::memcpy(native_dmem_path, reinterpret_cast<const void*>(ptr), path_bytes);
		if (std::memcmp(native_dmem_path, "/dev/mbus_av", sizeof("/dev/mbus_av")) == 0) {
			guest_path = "/dev/mbus_av";
		} else if (std::memcmp(native_dmem_path, "/dev/hdmi", sizeof("/dev/hdmi")) == 0) {
			guest_path = "/dev/hdmi";
		} else if (std::memcmp(native_dmem_path, "/dev/av_control", sizeof("/dev/av_control")) ==
		           0) {
			guest_path = "/dev/av_control";
		} else if (std::memcmp(native_dmem_path, "/dev/scanin", sizeof("/dev/scanin")) == 0) {
			guest_path = "/dev/scanin";
		} else if (std::memcmp(native_dmem_path, "/dev/hmd_cmd", sizeof("/dev/hmd_cmd")) == 0) {
			guest_path = "/dev/hmd_cmd";
		} else {
			if (std::memcmp(native_dmem_path, "/dev/dmem", 9) != 0 || native_dmem_path[9] < '0' ||
			    native_dmem_path[9] > '2' || native_dmem_path[10] != '\0') {
				return {-1, Libs::Posix::POSIX_ENOSYS};
			}
			guest_path = native_dmem_path;
		}
#else
		return {-1, Libs::Posix::POSIX_ENOSYS};
#endif
	}
	const int fd = LibKernel::FileSystem::KernelOpen(guest_path, 2, 0);
	if (fd < 0) {
		const int guest_errno = LibKernel::KernelToPosix(fd);
		LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_DEVICE_OPEN"
		     " path=%s result=error errno=%d\n",
		     guest_path, guest_errno);
		return {-1, guest_errno};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_DEVICE_OPEN"
	     " path=%s descriptor=%d\n",
	     guest_path, fd);
	return {fd, 0};
}


Reply SysAvControlShmTruncate(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[0] < 3 || request.args[0] > INT32_MAX || request.args[1] != 0x2000) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const int fd           = static_cast<int>(request.args[0]);
	size_t    current_size = 0;
	if (!LibKernel::FileSystem::GetSharedMemorySize(fd, &current_size) ||
	    (current_size != 0x1db0 && current_size != 0x2000)) {
		return {-1, Libs::Posix::POSIX_EBADF};
	}
	const int rc = LibKernel::FileSystem::KernelFtruncate(fd, 0x2000);
	if (rc != 0) {
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_SHM_FTRUNCATE"
	     " guest_fd=%d new_size=0x2000"
	     " shared_memory_backing\n",
	     fd);
	return {0, 0};
}

Reply SysAvControlShmFstat(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[0] < 3 || request.args[0] > INT32_MAX || request.args[1] == 0) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const int fd                  = static_cast<int>(request.args[0]);
	size_t    original_guest_size = 0;
	if (!LibKernel::FileSystem::GetSharedMemorySize(fd, &original_guest_size) ||
	    original_guest_size != 0x2000) {
		return {-1, Libs::Posix::POSIX_EBADF};
	}
	const int rc = LibKernel::FileSystem::KernelFstat(
	    fd, reinterpret_cast<LibKernel::FileSystem::FileStat*>(request.args[1]));
	if (rc != 0) {
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_SHM_FSTAT"
	     " guest_fd=%d st_size=0x%zx from_shared_descriptor\n",
	     fd, original_guest_size);
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

// /SceAo2TVCorP raw shm_open (0x1E2), shared by SysAv and Audiod. Matched by path, its flags differ
// from /SceAvControl's
Reply SysAvAudioShmOpen(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[0] == 0 || request.args[0] > UINT64_MAX - sizeof("/SceAo2TVCorP")) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	LibKernel::Memory::VirtualQueryInfo region {};
	if (LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(request.args[0]), 0,
	                                          &region, sizeof(region)) != 0 ||
	    !region.is_committed || region.start > request.args[0] ||
	    region.end < request.args[0] + sizeof("/SceAo2TVCorP") || (region.protection & 1u) == 0 ||
	    std::memcmp(reinterpret_cast<const void*>(request.args[0]), "/SceAo2TVCorP",
	                sizeof("/SceAo2TVCorP")) != 0) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const int fd = LibKernel::FileSystem::KernelShmOpen(
	    "/SceAo2TVCorP", static_cast<int>(request.args[1]), static_cast<uint16_t>(request.args[2]));
	if (fd < 0) {
		return {-1, *Libs::Posix::GetErrorAddr()};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_AUDIO_SHM_OPEN"
	     " name=/SceAo2TVCorP guest_fd=%d"
	     " scope_shared_audio_out_buffer"
	     " shared_memory_descriptor\n",
	     fd);
	return {fd, 0};
}

Reply SysAvAudioShmTruncate(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[0] < 3 || request.args[0] > INT32_MAX ||
	    !LibKernel::FileSystem::IsSharedMemoryNamed(static_cast<int>(request.args[0]),
	                                                "/SceAo2TVCorP")) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const int rc = LibKernel::FileSystem::KernelFtruncate(static_cast<int>(request.args[0]),
	                                                      static_cast<int64_t>(request.args[1]));
	if (rc != 0) {
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_AUDIO_SHM_FTRUNCATE"
	     " guest_fd=%d length=0x%" PRIx64 " scope_shared_audio_out_buffer_sized\n",
	     static_cast<int>(request.args[0]), request.args[1]);
	return {0, 0};
}

Reply SysAvAudioShmFstat(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[0] < 3 || request.args[0] > INT32_MAX || request.args[1] == 0 ||
	    !LibKernel::FileSystem::IsSharedMemoryNamed(static_cast<int>(request.args[0]),
	                                                "/SceAo2TVCorP")) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const int rc = LibKernel::FileSystem::KernelFstat(
	    static_cast<int>(request.args[0]),
	    reinterpret_cast<LibKernel::FileSystem::FileStat*>(request.args[1]));
	if (rc != 0) {
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	size_t sized = 0;
	LibKernel::FileSystem::GetSharedMemorySize(static_cast<int>(request.args[0]), &sized);
	LOGF("FIRST_FRAME_AUDIT SYSAV_AUDIO_SHM_FSTAT"
	     " guest_fd=%d st_size=0x%zx from_shared_descriptor\n",
	     static_cast<int>(request.args[0]), sized);
	return {0, 0};
}

Reply SysAvDceIoctl(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") != nullptr &&
	    (request.args[1] == 0x40046480u || request.args[1] == 0x40086481u ||
	     (request.args[0] >= 3 && request.args[0] <= INT32_MAX &&
	      (LibKernel::FileSystem::IsSectorPayloadDescriptor(static_cast<int>(request.args[0])) ||
	       LibKernel::FileSystem::IsNativeAvDescriptor(static_cast<int>(request.args[0])) ||
	       LibKernel::FileSystem::IsA53StorageDescriptor(static_cast<int>(request.args[0])))))) {
		if (request.args[0] > INT32_MAX) return {-1, Libs::Posix::POSIX_EBADF};
		const int rc =
		    LibKernel::FileSystem::KernelIoctl(static_cast<int>(request.args[0]), request.args[1],
			                                   reinterpret_cast<void*>(request.args[2]));
		return rc == 0 ? Reply {0, 0} : Reply {-1, LibKernel::KernelToPosix(rc)};
	}
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[0] < 3 || request.args[0] > INT32_MAX ||
	    (request.args[1] != 0x80208218 && request.args[1] != 0xc0588212 &&
	     request.args[1] != 0x80308217 && request.args[1] != 0x4008800a &&
	     request.args[1] != 0xc0288001 && request.args[1] != 0xc018800f &&
	     request.args[1] != 0x80108002) ||
	    request.args[2] == 0) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const int rc =
	    LibKernel::FileSystem::KernelIoctl(static_cast<int>(request.args[0]), request.args[1],
		                                   reinterpret_cast<void*>(request.args[2]));
	if (rc != 0) {
		const int guest_errno = LibKernel::KernelToPosix(rc);
		LOGF("FIRST_FRAME_AUDIT SYSAV_DCE_IOCTL"
		     " request=0x%08" PRIx64 " device_result=error errno=%d\n",
		     request.args[1], guest_errno);
		return {-1, guest_errno};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_DCE_IOCTL"
	     " request=0x%08" PRIx64 " forwarded_to_guest_device\n",
	     request.args[1]);
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
static uint32_t                                      g_sysav_next_ipmi_id = 1;

int RegisterSysAvIpmiServerFilterInternal(int64_t                                   queue,
                                          const LibKernel::EventQueue::KernelEvent& original) {
	if (std::getenv("KYTY_DIAGNOSTIC_SYSAV_IPMI_EVENT_MODEL") == nullptr ||
	    original.filter != -19 || original.flags != 1 || original.fflags != 0 ||
	    original.data != 16 || original.ident == 0 || original.ident > UINT32_MAX || queue == 0 ||
	    !LibKernel::EventQueue::KernelPinEqueue(queue)) {
		return LibKernel::KERNEL_ERROR_EINVAL;
	}
	const uint32_t  id = static_cast<uint32_t>(original.ident);
	std::lock_guard lock(g_sysav_ipmi_lock);
	const auto      it = g_sysav_ipmi_servers.find(id);
	if (it == g_sysav_ipmi_servers.end() || it->second.service_name != "SceSysAvControlIpc" ||
	    it->second.registered_event_queue != 0 || !it->second.pending_requests.empty()) {
		return LibKernel::KERNEL_ERROR_EINVAL;
	}
	LibKernel::EventQueue::KernelEqueueEvent item {};
	item.event      = original;
	item.event.data = 0; // pending request count
	const int rc    = LibKernel::EventQueue::KernelAddEvent(queue, item);
	if (rc != 0) return rc;
	it->second.registered_event_queue = queue;
	it->second.notification_limit     = 16;
	LOGF("FIRST_FRAME_AUDIT SYSAV_IPMI_SERVICE_EVENT_SOURCE_REGISTERED"
	     " existing_server_id=%u existing_queue=%" PRId64 " max_pending=16 pending=0"
	     " filter_minus19 backed_by_process_local_service\n",
	     id, queue);
	return 0;
}

void UnregisterSysAvIpmiServerFilterInternal(int64_t queue, uint32_t server_id) {
	std::lock_guard lock(g_sysav_ipmi_lock);
	auto            it = g_sysav_ipmi_servers.find(server_id);
	if (it != g_sysav_ipmi_servers.end() && it->second.registered_event_queue == queue) {
		(void)LibKernel::EventQueue::KernelDeleteEvent(queue, server_id, -19);
		it->second.registered_event_queue = 0;
		it->second.notification_limit     = 0;
	}
}

Reply SysAvNativeMdbgService(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[0] != 3 || request.args[1] != 0xffffffffa002031eull || request.args[2] != 0) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	// ENOSYS here runs the guest into the inline UD2 at 0x46b2fc
	if (std::getenv("KYTY_DIAGNOSTIC_SYSAV_MDBG_BENIGN_SUCCESS") != nullptr) {
		LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_MDBG_BENIGN_SUCCESS_NON_AUTHENTIC"
		     " operation=3 request=0xa002031e"
		     " returned_rax0_cf0_to_skip_guest_UD2_at_0x46b2fc\n");
		return {0, 0};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_MDBG_UNIMPLEMENTED"
	     " operation=3 request=0xa002031e"
	     " result=ENOSYS\n");
	return {-1, Libs::Posix::POSIX_ENOSYS};
}

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
	if (failed_server_name) {
		if (!ValidateSysctlSpan(reinterpret_cast<const void*>(request.args[3]), sizeof(uint64_t),
		                        false)) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_IPMI_FAILED_SERVER_NAME"
		     " operation=0x46a failed_create_handle=0x8002004e"
		     " transport_errno=EBADF\n");
		return {-1, Libs::Posix::POSIX_EBADF};
	}
	if (create_server && std::getenv("KYTY_DIAGNOSTIC_SYSAV_IPMI_SERVICE") != nullptr) {
		struct OriginalRegistration {
			uint64_t guest_server;
			uint64_t guest_service_name;
			uint64_t guest_config;
		};
		auto guest_span = [](uint64_t addr, uint64_t length, bool writable) {
			LibKernel::Memory::VirtualQueryInfo region {};
			return addr != 0 && length <= UINT64_MAX - addr &&
			       LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(addr), 0,
			                                             &region, sizeof(region)) == 0 &&
			       region.is_committed && region.start <= addr && region.end >= addr + length &&
			       (region.protection & (writable ? 2u : 1u)) != 0;
		};
		if (!guest_span(request.args[2], 4, true) ||
		    !guest_span(request.args[3], sizeof(OriginalRegistration), false)) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		OriginalRegistration original {};
		std::memcpy(&original, reinterpret_cast<const void*>(request.args[3]), sizeof(original));
		if (!guest_span(original.guest_server, 8, true) ||
		    !guest_span(original.guest_service_name, 1, false) ||
		    !guest_span(original.guest_config, 8, false)) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		std::string      service_name;
		constexpr size_t max_service_name = 128;
		for (size_t n = 0; n < max_service_name; ++n) {
			if (!guest_span(original.guest_service_name + n, 1, false)) {
				return {-1, Libs::Posix::POSIX_EFAULT};
			}
			char ch = 0;
			std::memcpy(&ch, reinterpret_cast<const void*>(original.guest_service_name + n), 1);
			if (ch == '\0') break;
			if (ch < 0x21 || ch > 0x7e) {
				return {-1, Libs::Posix::POSIX_EINVAL};
			}
			service_name.push_back(ch);
		}
		if (service_name.empty() || service_name.size() == max_service_name) {
			return {-1, Libs::Posix::POSIX_EINVAL};
		}
		std::lock_guard lock(g_sysav_ipmi_lock);
		for (const auto& pair: g_sysav_ipmi_servers) {
			if (pair.second.service_name == service_name) {
				return {-1, Libs::Posix::POSIX_EBUSY};
			}
		}
		if (g_sysav_next_ipmi_id == 0 || g_sysav_next_ipmi_id >= INT32_MAX) {
			return {-1, Libs::Posix::POSIX_ENOMEM};
		}
		const uint32_t owner_pid = static_cast<uint32_t>(LibKernel::Process::GetPid());
		uint32_t       id        = 0;
		if (LibKernel::IpmiScope::Enabled()) {
			if (!LibKernel::IpmiScope::Register(service_name, owner_pid, &id)) {
				LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_IPMI_SHARED_REGISTRATION_FAILED"
				     " service=%s\n",
				     service_name.c_str());
				return {-1, Libs::Posix::POSIX_EBUSY};
			}
			g_sysav_next_ipmi_id = std::max(g_sysav_next_ipmi_id, id + 1);
		} else {
			id = g_sysav_next_ipmi_id++;
		}
		g_sysav_ipmi_servers.emplace(id, SysAvIpmiServer {service_name, original.guest_server,
		                                                  original.guest_config, owner_pid});
		LibKernel::Memory::InvalidateMemory(request.args[2], sizeof(id));
		std::memcpy(reinterpret_cast<void*>(request.args[2]), &id, sizeof(id));
		LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_IPMI_SERVICE_REGISTERED"
		     " id=%u service=%s owner_pid=%u server=0x%016" PRIx64 " config=0x%016" PRIx64
		     " process_local\n",
		     id, service_name.c_str(), owner_pid, original.guest_server, original.guest_config);
		return {0, 0};
	}
	if (create_client && std::getenv("KYTY_DIAGNOSTIC_SYSAV_IPMI_CLIENT_DISCOVERY") != nullptr) {
		struct ClientRegistration {
			uint64_t guest_client;
			uint64_t guest_service_name;
			uint64_t guest_config;
		};
		auto valid = [](uint64_t address, uint64_t size, bool writable) {
			LibKernel::Memory::VirtualQueryInfo region {};
			return address != 0 && size <= UINT64_MAX - address &&
			       LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(address), 0,
			                                             &region, sizeof(region)) == 0 &&
			       region.is_committed && region.start <= address && region.end >= address + size &&
			       (region.protection & (writable ? 2u : 1u)) != 0;
		};
		if (!valid(request.args[2], 4, true) ||
		    !valid(request.args[3], sizeof(ClientRegistration), false)) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		ClientRegistration client {};
		std::memcpy(&client, reinterpret_cast<const void*>(request.args[3]), sizeof(client));
		if (!valid(client.guest_client, 8, true) || !valid(client.guest_config, 8, false)) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		std::string service_name;
		bool        terminated = false;
		for (size_t n = 0; n < 128; ++n) {
			if (!valid(client.guest_service_name + n, 1, false)) {
				return {-1, Libs::Posix::POSIX_EFAULT};
			}
			char ch = 0;
			std::memcpy(&ch, reinterpret_cast<const void*>(client.guest_service_name + n), 1);
			if (ch == '\0') {
				terminated = true;
				break;
			}
			if (ch < 0x21 || ch > 0x7e) {
				return {-1, Libs::Posix::POSIX_EINVAL};
			}
			service_name.push_back(ch);
		}
		if (!terminated || service_name.empty()) {
			return {-1, Libs::Posix::POSIX_EINVAL};
		}
		std::lock_guard lock(g_sysav_ipmi_lock);
		uint32_t        matching_server_id = 0;
		for (const auto& entry: g_sysav_ipmi_servers) {
			if (entry.second.service_name == service_name) {
				matching_server_id = entry.first;
				break;
			}
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_IPMI_CLIENT_DIRECTORY_LOOKUP"
		     " service=%s registered_server_id=%u"
		     " existing_server_count=%zu\n",
		     service_name.c_str(), matching_server_id, g_sysav_ipmi_servers.size());
		if (matching_server_id == 0 && LibKernel::IpmiScope::Enabled()) {
			uint32_t owner_pid      = 0;
			uint32_t owner_host_pid = 0;
			if (LibKernel::IpmiScope::Lookup(service_name, &matching_server_id, &owner_pid,
			                                 &owner_host_pid)) {
				LOGF("FIRST_FRAME_AUDIT SYSAV_CROSS_HOST_SERVICE_FOUND"
				     " service=%s owner_guest_pid=%u owner_host_pid=%u"
				     " service_id=%u"
				     " ENOSYS\n",
				     service_name.c_str(), owner_pid, owner_host_pid, matching_server_id);
			}
		}
		if (matching_server_id != 0 && LibKernel::IpmiScope::Enabled() &&
		    std::getenv("KYTY_DIAGNOSTIC_SYSAV_IPMI_REAL_CLIENT") != nullptr) {
			uint32_t actual_client = 0;
			uint32_t actual_server = 0;
			if (!LibKernel::IpmiScope::OpenClient(
			        service_name, static_cast<uint32_t>(LibKernel::Process::GetPid()),
			        &actual_client, &actual_server) ||
			    actual_client == 0 || actual_server != matching_server_id) {
				return {-1, Libs::Posix::POSIX_ENOSYS};
			}
			LibKernel::Memory::InvalidateMemory(request.args[2], sizeof(actual_client));
			std::memcpy(reinterpret_cast<void*>(request.args[2]), &actual_client,
			            sizeof(actual_client));
			LOGF("FIRST_FRAME_AUDIT SYSAV_CROSS_HOST_IPMI_CLIENT_CREATED"
			     " service=%s server_id=%u client_id=%u"
			     " guest_client=0x%016" PRIx64 " kernel_backed_live_owner\n",
			     service_name.c_str(), actual_server, actual_client, client.guest_client);
			return {0, 0};
		}
		return matching_server_id == 0 ? Reply {-1, Libs::Posix::POSIX_ENOENT}
		                               : Reply {-1, Libs::Posix::POSIX_ENOSYS};
	}
	if (client_control && std::getenv("KYTY_DIAGNOSTIC_SYSAV_IPMI_REAL_CLIENT") != nullptr) {
		LOGF("FIRST_FRAME_AUDIT SYSAV_IPMI_CLIENT_CONTROL_ENTER"
		     " operation=0x400 kernel_client=%" PRIu64 " result_ptr=0x%016" PRIx64
		     " argument_ptr=0x%016" PRIx64 " argument_size=%" PRIu64
		     " READ_ONLY_PENDING_ABI_VALIDATION\n",
		     request.args[1], request.args[2], request.args[3], request.args[4]);
		auto guest_span = [](uint64_t addr, uint64_t length, bool writable) {
			LibKernel::Memory::VirtualQueryInfo region {};
			return addr != 0 && length <= UINT64_MAX - addr &&
			       LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(addr), 0,
			                                             &region, sizeof(region)) == 0 &&
			       region.is_committed && region.start <= addr && region.end >= addr + length &&
			       (region.protection & (writable ? 2u : 1u)) != 0;
		};
		if (!guest_span(request.args[2], 4, true) || !guest_span(request.args[3], 0x20, false)) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_IPMI_CLIENT_CONTROL"
			     " result=EFAULT invalid_guest_argument_span\n");
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		uint64_t original[4] {};
		std::memcpy(original, reinterpret_cast<const void*>(request.args[3]), sizeof(original));
		uint32_t   server_id       = 0;
		uint32_t   owner_guest_pid = 0;
		const bool client_owned    = LibKernel::IpmiScope::InspectClient(
		    static_cast<uint32_t>(request.args[1]), &server_id, &owner_guest_pid);
		const bool nested_output_valid  = guest_span(original[2], sizeof(uint32_t), true);
		uint32_t   nested_output_before = 0;
		uint32_t   result_before        = 0;
		if (nested_output_valid) {
			std::memcpy(&nested_output_before, reinterpret_cast<const void*>(original[2]),
			            sizeof(uint32_t));
		}
		std::memcpy(&result_before, reinterpret_cast<const void*>(request.args[2]),
		            sizeof(uint32_t));
		static std::atomic<uint32_t> control_probe_count {0};
		if (control_probe_count.fetch_add(1) < 16) {
			LOGF("FIRST_FRAME_AUDIT SYSAV_IPMI_CLIENT_CONTROL_NESTED"
			     " client=%" PRIu64 " client_owned=%u server_id=%u"
			     " owner_guest_pid=%u caller_guest_pid=%" PRId64 " nested_ptr=0x%016" PRIx64
			     " nested_writable=%u"
			     " nested_dword_before=0x%08x result_dword_before=0x%08x\n",
			     request.args[1], client_owned ? 1u : 0u, server_id, owner_guest_pid,
			     static_cast<int64_t>(LibKernel::Process::GetPid()), original[2],
			     nested_output_valid ? 1u : 0u, nested_output_before, result_before);
		}
		const bool user_data_valid =
		    original[1] == 0 || (original[0] != 0 && guest_span(original[0], original[1], false));
		const bool fourth_output_valid =
		    original[3] == 0 || guest_span(original[3], sizeof(uint32_t), true);
		LOGF("FIRST_FRAME_AUDIT SYSAV_IPMI_CLIENT_CONNECT_ABI"
		     " op=0x400 kernel_client=%" PRIu64 " input_length=0x20 user_data=%016" PRIx64
		     " user_data_length=%" PRIu64 " status=%016" PRIx64 " optional_output=%016" PRIx64
		     " valid_user_data=%u valid_status=%u valid_optional=%u"
		     " live_client=%u owned_pid=%u current_guest_pid=%" PRId64
		     " server_id=%u client_connect_requires_server_ack\n",
		     request.args[1], original[0], original[1], original[2], original[3],
		     user_data_valid ? 1u : 0u, nested_output_valid ? 1u : 0u,
		     fourth_output_valid ? 1u : 0u, client_owned ? 1u : 0u, owner_guest_pid,
		     static_cast<int64_t>(LibKernel::Process::GetPid()), server_id);
		if (!client_owned ||
		    owner_guest_pid != static_cast<uint32_t>(LibKernel::Process::GetPid())) {
			return {-1, Libs::Posix::POSIX_EINVAL};
		}
		if (!user_data_valid || !nested_output_valid || !fourth_output_valid) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	if (destroy_client && std::getenv("KYTY_DIAGNOSTIC_SYSAV_IPMI_REAL_CLIENT") != nullptr) {
		auto guest_output = [](uint64_t addr) {
			LibKernel::Memory::VirtualQueryInfo region {};
			return addr != 0 &&
			       LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(addr), 0,
			                                             &region, sizeof(region)) == 0 &&
			       region.is_committed && region.start <= addr &&
			       region.end >= addr + sizeof(uint32_t) && (region.protection & 2u) != 0;
		};
		if (!guest_output(request.args[2])) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		if (!LibKernel::IpmiScope::CloseClient(static_cast<uint32_t>(request.args[1]))) {
			return {-1, Libs::Posix::POSIX_ESRCH};
		}
		const uint32_t prior_client = static_cast<uint32_t>(request.args[1]);
		// assert at 0x469d72 wants op 3's result word 0, not the removed id
		const uint32_t operation_result = 0;
		LibKernel::Memory::InvalidateMemory(request.args[2], sizeof(uint32_t));
		std::memcpy(reinterpret_cast<void*>(request.args[2]), &operation_result, sizeof(uint32_t));
		LOGF("FIRST_FRAME_AUDIT SYSAV_IPMI_CLIENT_DESTROYED"
		     " operation=3 client_id=%u"
		     " live_owned_handle_removed pending_packets_reclaimed\n",
		     prior_client);
		return {0, 0};
	}
	if (receive_packet_201 &&
	    std::getenv("KYTY_DIAGNOSTIC_SYSAV_IPMI_RECEIVE_PACKET_EAGAIN") != nullptr) {
		auto writable_u32 = [](uint64_t addr) {
			LibKernel::Memory::VirtualQueryInfo region {};
			return addr != 0 &&
			       LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(addr), 0,
			                                             &region, sizeof(region)) == 0 &&
			       region.is_committed && region.start <= addr &&
			       region.end >= addr + sizeof(uint32_t) && (region.protection & 2u) != 0;
		};
		if (!writable_u32(request.args[2])) {
			return {-1, Libs::Posix::POSIX_EFAULT};
		}
		// EAGAIN (0x80020023) is the only status 0x46b2c7 doesn't treat as fatal
		const uint32_t eagain_status = 0x80020023u;
		LibKernel::Memory::InvalidateMemory(request.args[2], sizeof(eagain_status));
		std::memcpy(reinterpret_cast<void*>(request.args[2]), &eagain_status,
		            sizeof(eagain_status));
		LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_IPMI_RECEIVE_PACKET_EAGAIN_NON_AUTHENTIC"
		     " service_id=0x201 handle=%" PRIu64 " status_out=0x%08x\n",
		     request.args[1], eagain_status);
		return {0, 0};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_IPMI_MANAGER_UNIMPLEMENTED"
	     " operation=%" PRIu64 " suboperation=%" PRIu64 " data_len=0x%" PRIx64 " result=ENOSYS\n",
	     request.args[0], request.args[1], request.args[4]);
	return {-1, Libs::Posix::POSIX_ENOSYS};
}

Reply SysAvGetAuthInfo(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	if (request.args[0] > static_cast<uint64_t>(INT32_MAX)) {
		return {-1, Libs::Posix::POSIX_ESRCH};
	}
	const int  requested_pid = static_cast<int32_t>(request.args[0]);
	const int  target_pid    = requested_pid == 0 ? LibKernel::Process::GetPid() : requested_pid;
	const bool remote        = target_pid != LibKernel::Process::GetPid();
	LibKernel::Process::PeerProcess peer {};
	if (remote ? !LibKernel::IpmiManager::FindCurrentRemotePeer(target_pid, &peer)
	           : !LibKernel::Process::FindPeerByPid(target_pid, &peer)) {
		return {-1, Libs::Posix::POSIX_ESRCH};
	}
	LibKernel::AuthInfo::Record filtered {};
	bool                        filtered_observation = false;
	if (peer.has_auth_info) {
		filtered = LibKernel::AuthInfo::Filter(peer.auth_info);
	} else if (peer.has_filtered_auth_info) {
		filtered             = peer.filtered_auth_info;
		filtered_observation = true;
	} else {
		LOGF("FIRST_FRAME_AUDIT SYSAV_AUTHINFO_MISSING"
		     " target_pid=%d verified capture unavailable"
		     " result=ENOENT\n",
		     target_pid);
		return {-1, Libs::Posix::POSIX_ENOENT};
	}
	if (!LibKernel::Memory::CopyToGuest(reinterpret_cast<void*>(request.args[1]), filtered.data(),
	                                    filtered.size())) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	if (filtered_observation) {
		LOGF("AUTHINFO_FILTERED_OBSERVATION pid=%d"
		     " source=%s\n",
		     target_pid, remote ? "scoped_peer_observation" : "native_587_observed_fields");
		return {0, 0};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_AUTHINFO_FILTERED_SOURCE_RECORD"
	     " pid=%d authority=0x%016" PRIx64 "\n",
	     target_pid, peer.auth_id);
	return {0, 0};
}

void WipeSensitiveBytes(void* data, size_t size) noexcept {
	auto* bytes = static_cast<volatile uint8_t*>(data);
	while (size != 0) {
		*bytes++ = 0;
		--size;
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

bool ExecutableImageStructureValid(const std::vector<uint8_t>& image, bool self) {
	size_t     required_bytes = 0;
	const auto kind =
	    ExecutableImageHeaderKind(image.data(), image.size(), image.size(), &required_bytes);
	return kind == (self ? ExecutableImageKind::Self : ExecutableImageKind::Elf) &&
	       required_bytes <= image.size();
}

Reply SysAvGetSelfAuthInfo(const SyscallRequest& request) try {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	std::string path;
	const int   path_rc =
	    ReadExecveGuestString(request.args[0], 0x400, LibKernel::KERNEL_ERROR_ENAMETOOLONG, &path);
	if (path_rc != 0) return {-1, LibKernel::KernelToPosix(path_rc)};
	if (path.empty()) return {-1, Libs::Posix::POSIX_ENOENT};

	LibKernel::FileSystem::FileStat named {};
	const int stat_rc = LibKernel::FileSystem::KernelStat(path.c_str(), &named);
	if (stat_rc != 0) return {-1, LibKernel::KernelToPosix(stat_rc)};
	if ((named.st_mode & 0170000u) != 0100000u) {
		return {-1, Libs::Posix::POSIX_EINVAL};
	}

	const int descriptor = LibKernel::FileSystem::KernelOpen(path.c_str(), 0, 0);
	if (descriptor < 0) return {-1, LibKernel::KernelToPosix(descriptor)};
	struct CloseOnExit {
		int descriptor;
		~CloseOnExit() { LibKernel::FileSystem::KernelClose(descriptor); }
	} close {descriptor};

	LibKernel::FileSystem::FileStat opened {};
	const int fstat_rc = LibKernel::FileSystem::KernelFstat(descriptor, &opened);
	if (fstat_rc != 0) return {-1, LibKernel::KernelToPosix(fstat_rc)};
	if ((opened.st_mode & 0170000u) != 0100000u || opened.st_dev != named.st_dev ||
	    opened.st_ino != named.st_ino || opened.st_size != named.st_size) {
		return {-1, Libs::Posix::POSIX_EIO};
	}
	if (opened.st_size < 4) return {-1, Libs::Posix::POSIX_ENOEXEC};
	constexpr size_t header_capacity = sizeof(Loader::SelfHeader) > sizeof(Loader::Elf64_Ehdr)
	                                       ? sizeof(Loader::SelfHeader)
	                                       : sizeof(Loader::Elf64_Ehdr);
	std::array<uint8_t, header_capacity> header_bytes {};
	const size_t                         header_size = static_cast<size_t>(
	    std::min<uint64_t>(static_cast<uint64_t>(opened.st_size), header_bytes.size()));
	size_t header_offset = 0;
	while (header_offset != header_size) {
		const int64_t read = LibKernel::FileSystem::KernelPread(
		    descriptor, header_bytes.data() + header_offset, header_size - header_offset,
		    static_cast<int64_t>(header_offset));
		if (read < 0) return {-1, LibKernel::KernelToPosix(static_cast<int>(read))};
		if (read == 0) return {-1, Libs::Posix::POSIX_EIO};
		header_offset += static_cast<size_t>(read);
	}
	size_t required_prefix = 0;
	auto   image_kind      = ExecutableImageHeaderKind(
	    header_bytes.data(), header_size, static_cast<uint64_t>(opened.st_size), &required_prefix);
	if (image_kind == ExecutableImageKind::Invalid) {
		return {-1, Libs::Posix::POSIX_ENOEXEC};
	}
	if (required_prefix > header_size) {
		std::vector<uint8_t> prefix(required_prefix);
		std::memcpy(prefix.data(), header_bytes.data(), header_size);
		size_t prefix_offset = header_size;
		while (prefix_offset != prefix.size()) {
			const int64_t read = LibKernel::FileSystem::KernelPread(
			    descriptor, prefix.data() + prefix_offset, prefix.size() - prefix_offset,
			    static_cast<int64_t>(prefix_offset));
			if (read < 0) return {-1, LibKernel::KernelToPosix(static_cast<int>(read))};
			if (read == 0) return {-1, Libs::Posix::POSIX_EIO};
			prefix_offset += static_cast<size_t>(read);
		}
		size_t     validated_prefix = 0;
		const auto validated_kind   = ExecutableImageHeaderKind(
		    prefix.data(), prefix.size(), static_cast<uint64_t>(opened.st_size), &validated_prefix);
		if (validated_kind != image_kind || validated_prefix != required_prefix) {
			return {-1, Libs::Posix::POSIX_ENOEXEC};
		}
		image_kind = validated_kind;
	}

	LibKernel::AuthInfo::ImageIdentity identity {};
	if (!LibKernel::Process::GetVerifiedOriginalSelfIdentity(&identity)) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const bool     is_self       = image_kind == ExecutableImageKind::Self;
	const uint64_t expected_size = is_self ? identity.self_size : identity.elf_size;
	if (expected_size != static_cast<uint64_t>(opened.st_size) ||
	    expected_size > std::numeric_limits<size_t>::max()) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}

	std::vector<uint8_t> image(static_cast<size_t>(expected_size));
	struct WipeVectorOnExit {
		std::vector<uint8_t>* bytes;
		~WipeVectorOnExit() {
			if (!bytes->empty()) WipeSensitiveBytes(bytes->data(), bytes->size());
		}
	} wipe_image {&image};
	size_t offset = 0;
	while (offset != image.size()) {
		const size_t  chunk = std::min<size_t>(image.size() - offset, 16u * 1024u * 1024u);
		const int64_t read  = LibKernel::FileSystem::KernelPread(
		    descriptor, image.data() + offset, chunk, static_cast<int64_t>(offset));
		if (read < 0) return {-1, LibKernel::KernelToPosix(static_cast<int>(read))};
		if (read == 0) return {-1, Libs::Posix::POSIX_EIO};
		offset += static_cast<size_t>(read);
	}
	LibKernel::FileSystem::FileStat stable {};
	const int stable_rc = LibKernel::FileSystem::KernelFstat(descriptor, &stable);
	if (stable_rc != 0) return {-1, LibKernel::KernelToPosix(stable_rc)};
	if (stable.st_dev != opened.st_dev || stable.st_ino != opened.st_ino ||
	    stable.st_size != opened.st_size || stable.st_mtim.tv_sec != opened.st_mtim.tv_sec ||
	    stable.st_mtim.tv_nsec != opened.st_mtim.tv_nsec) {
		return {-1, Libs::Posix::POSIX_EIO};
	}

	if (!ExecutableImageStructureValid(image, is_self)) {
		return {-1, Libs::Posix::POSIX_ENOEXEC};
	}

	const auto digest = LibKernel::AuthInfo::Sha256(image.data(), image.size());
	if ((is_self && digest != identity.self_sha256) ||
	    (!is_self && digest != identity.elf_sha256)) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}

	struct SensitiveOutput {
		LibKernel::AuthInfo::Capture capture {};
		LibKernel::AuthInfo::Record  filtered {};
		~SensitiveOutput() {
			WipeSensitiveBytes(&capture, sizeof(capture));
			WipeSensitiveBytes(&filtered, sizeof(filtered));
		}
	} sensitive;
	if (!LibKernel::Process::GetVerifiedAuthInfoForImage(identity, &sensitive.capture)) {
		LOGF("FIRST_FRAME_AUDIT SYSAV_GET_SELF_AUTHINFO_MISSING"
		     " image_kind=%s image_bytes=%" PRIu64 " result=ENOSYS\n",
		     is_self ? "self" : "elf", expected_size);
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	if (!LibKernel::AuthInfo::FilterSelfAuthInfo(sensitive.capture.record, sensitive.capture.record,
	                                             &sensitive.filtered)) {
		return {-1, Libs::Posix::POSIX_EPERM};
	}
	if (!LibKernel::Memory::CopyToGuest(reinterpret_cast<void*>(request.args[1]),
	                                    sensitive.filtered.data(), sensitive.filtered.size())) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_GET_SELF_AUTHINFO_FILTERED"
	     " image_kind=%s image_bytes=%" PRIu64 " bytes=0x%zx"
	     " source=image_bound_integrity_pinned_capture\n",
	     is_self ? "self" : "elf", expected_size, sensitive.filtered.size());
	return {0, 0};
} catch (const std::bad_alloc&) {
	return {-1, Libs::Posix::POSIX_ENOMEM};
}

Reply SysAvThrSelf(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	if (request.args[0] < 0x200000000ull || request.args[0] > 0x20003fff8ull) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	const int tid = LibKernel::PthreadGetthreadid();
	if (tid <= 0) {
		return {-1, Libs::Posix::POSIX_ESRCH};
	}
	const uint64_t guest_tid = static_cast<uint64_t>(tid);
	std::memcpy(reinterpret_cast<void*>(request.args[0]), &guest_tid, sizeof(guest_tid));
	LOGF("FIRST_FRAME_AUDIT SYSAV_THR_SELF guest_tid=%d"
	     " output=0x%016" PRIx64 "\n",
	     tid, request.args[0]);
	return {0, 0};
}

Reply SysAvThrGetName(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    request.args[0] == 0 || request.args[0] > INT32_MAX || request.args[1] == 0 ||
	    (request.args[2] != 0 && request.args[0] != 5)) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	constexpr uint64_t                  name_size = 32;
	const uint64_t                      target    = request.args[1];
	LibKernel::Memory::VirtualQueryInfo region {};
	if (target > UINT64_MAX - name_size ||
	    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(target), 0, &region,
	                                          sizeof(region)) != 0 ||
	    !region.is_committed || region.start > target || region.end < target + name_size ||
	    (region.protection & 2u) == 0) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	char      actual_name[name_size] {};
	const int rc =
	    LibKernel::PthreadGetNameByGuestThreadId(static_cast<int>(request.args[0]), actual_name);
	if (rc != 0) {
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	LibKernel::Memory::InvalidateMemory(target, name_size);
	std::memcpy(reinterpret_cast<void*>(target), actual_name, name_size);
	LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_THR_GET_NAME"
	     " tid=%" PRIu64 " pthread_name=%s"
	     " guest_buffer=0x%016" PRIx64 " bytes=32\n",
	     request.args[0], actual_name, target);
	return {0, 0};
}

Reply SysAvRtprioThread(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    (request.args[0] != 0 && request.args[0] != 1) ||
	    (request.args[1] != 0 &&
	     request.args[1] != static_cast<uint32_t>(LibKernel::PthreadGetthreadid())) ||
	    request.args[2] == 0) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	LibKernel::Memory::VirtualQueryInfo rtprio_region {};
	if (request.args[2] > UINT64_MAX - 4 ||
	    LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(request.args[2]), 0,
	                                          &rtprio_region, sizeof(rtprio_region)) != 0 ||
	    !rtprio_region.is_committed || rtprio_region.start > request.args[2] ||
	    rtprio_region.end < request.args[2] + 4 || (rtprio_region.protection & 3u) != 3u) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	int                         policy = 0;
	LibKernel::KernelSchedParam param {};
	if (Libs::Posix::pthread_getschedparam(LibKernel::PthreadSelfOrNull(), &policy, &param) != 0) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	if (request.args[0] == 1) {
		uint16_t rtprio[2] {};
		std::memcpy(rtprio, reinterpret_cast<const void*>(request.args[2]), sizeof(rtprio));
		const int guest_policy = rtprio[0] == 10 ? 1 : rtprio[0] == 2 ? 3 : rtprio[0] == 3 ? 2 : -1;
		LibKernel::KernelSchedParam set_param {};
		set_param.sched_priority = rtprio[1];
		if (guest_policy < 0 || Libs::Posix::pthread_setschedparam(LibKernel::PthreadSelfOrNull(),
		                                                           guest_policy, &set_param) != 0) {
			return {-1, Libs::Posix::POSIX_EINVAL};
		}
		LOGF("FIRST_FRAME_AUDIT SYSAV_RT_PRIO_THREAD_SET"
		     " guest_tid=%" PRIu64 " native_type=%u native_prio=%u"
		     " guest_policy=%d applied_to_existing_guest_pthread\n",
		     request.args[1], rtprio[0], rtprio[1], guest_policy);
		return {0, 0};
	}
	if (param.sched_priority < 0 || param.sched_priority > 0xffff) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const uint16_t raw_type  = policy == 1 ? 10u : policy == 3 ? 2u : 3u;
	const uint16_t raw_prio  = static_cast<uint16_t>(param.sched_priority);
	const uint16_t rtprio[2] = {raw_type, raw_prio};
	std::memcpy(reinterpret_cast<void*>(request.args[2]), rtprio, sizeof(rtprio));
	LOGF("FIRST_FRAME_AUDIT SYSAV_RT_PRIO_THREAD"
	     " guest_tid=%" PRIu64 " guest_policy=%d guest_priority=%d"
	     " native_type=%u from_existing_guest_pthread_state\n",
	     request.args[1], policy, param.sched_priority, raw_type);
	return {0, 0};
}

Reply SysAvSigaction(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    (request.args[0] != 32 && request.args[0] != 2) || request.args[1] == 0 ||
	    request.args[2] != 0) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	static std::array<std::array<uint8_t, 32>, 33> actions {};
	const auto                                     signum = static_cast<size_t>(request.args[0]);
	std::memcpy(actions[signum].data(), reinterpret_cast<const void*>(request.args[1]),
	            actions[signum].size());
	uint64_t guest_handler = 0;
	std::memcpy(&guest_handler, actions[signum].data(), sizeof(guest_handler));
	LOGF("FIRST_FRAME_AUDIT SYSAV_DIAGNOSTIC_NATIVE_SIGACTION"
	     " signal=%zu guest_handler=0x%016" PRIx64
	     " guest_action_bytes=32 REGISTERED_NO_SIGNAL_DELIVERY NON_AUTHENTIC\n",
	     signum, guest_handler);
	return {0, 0};
}

Reply SysAvSigprocmask(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr &&
	    std::getenv("KYTY_DIAGNOSTIC_MINI_SYSCORE_NATIVE_TRAPS") == nullptr) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const int result = LibKernel::KernelSigprocmask(static_cast<int32_t>(request.args[0]),
	                                                reinterpret_cast<const void*>(request.args[1]),
	                                                reinterpret_cast<void*>(request.args[2]));
	const int error  = result == 0 ? 0 : LibKernel::KernelToPosix(result);
	static std::atomic<uint32_t> logged {0};
	const uint32_t               idx = logged.fetch_add(1);
	if (idx < 8 || (idx < 1024 && (idx & 0x3f) == 0) || (idx & 0xfff) == 0) {
		const auto mask = LibKernel::PthreadGetSignalMask(LibKernel::PthreadSelfOrNull());
		LOGF("NATIVE_SIGPROCMASK idx=%u how=%d set=%d oset=%d errno=%d"
		     " mask0=0x%016" PRIx64 " mask1=0x%016" PRIx64 " shared_pthread_state=1\n",
		     idx, static_cast<int32_t>(request.args[0]), request.args[1] != 0, request.args[2] != 0,
		     error, mask.words[0], mask.words[1]);
	}
	return result == 0 ? Reply {0, 0} : Reply {-1, error};
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

// UMD reader 0x46ECE0: read set only, no timeout, before each recvfrom
Reply SysAvGuestSocketSelect(const SyscallRequest& request) {
	const auto nfds    = request.args[0];
	const auto readfds = request.args[1];
	if (nfds == 0 || nfds > 64 || readfds == 0 || request.args[2] != 0 || request.args[3] != 0 ||
	    request.args[4] != 0) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	uint64_t bits = 0;
	if (!LibKernel::Memory::CopyFromGuest(&bits, reinterpret_cast<const void*>(readfds),
	                                      sizeof(bits)) ||
	    !LibKernel::Memory::CanWriteGuest(reinterpret_cast<void*>(readfds), sizeof(bits))) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	if (nfds < 64) bits &= (uint64_t {1} << nfds) - 1;
	for (uint64_t fd = 0; fd < nfds; ++fd) {
		if ((bits >> fd & 1) != 0 &&
		    !LibKernel::FileSystem::PinGuestSocketReadSource(static_cast<int>(fd))) {
			return {-1, Libs::Posix::POSIX_ENOSYS};
		}
	}
	const uint64_t requested = bits;
	const int      ready =
	    Network::Net::Select(static_cast<int>(nfds), &bits, nullptr, nullptr, nullptr);
	if (ready < 0) return {-1, *Libs::Posix::GetErrorAddr()};
	if (!LibKernel::Memory::CopyToGuest(reinterpret_cast<void*>(readfds), &bits, sizeof(bits))) {
		return {-1, Libs::Posix::POSIX_EFAULT};
	}
	static std::atomic<uint32_t> logged {0};
	if (logged.fetch_add(1) < 32) {
		LOGF("FIRST_FRAME_AUDIT SYSAV_GUEST_SOCKET_SELECT nfds=%" PRIu64 " requested=0x%016" PRIx64
		     " ready=0x%016" PRIx64 " count=%d\n",
		     nfds, requested, bits, ready);
	}
	return {ready, 0};
}




Reply SysAvEmptyMprotect(const SyscallRequest& request) {
	if (request.number != 0x4a || request.args[0] != 0 || request.args[1] != 0 ||
	    request.args[2] != 0 ||
	    std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const int result = LibKernel::Memory::KernelMprotect(nullptr, 0, 0);
	if (result != 0) {
		return {-1, Libs::Posix::POSIX_EINVAL};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_EMPTY_MPROTECT"
	     " args=0,0,0 existing_guest_mprotect_model_result=0\n");
	return {0, 0};
}

Reply SysAvNativeMunmap(const SyscallRequest& request) {
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr) {
		return {-1, Libs::Posix::POSIX_ENOSYS};
	}
	const uint64_t addr   = request.args[0];
	const uint64_t length = request.args[1];
	if (addr == 0 || length == 0 || (addr & 0x3fffull) != 0 || (length & 0x3fffull) != 0 ||
	    length > UINT64_MAX - addr || length > static_cast<uint64_t>(SIZE_MAX)) {
		return {-1, Libs::Posix::POSIX_EINVAL};
	}
	LibKernel::Memory::VirtualQueryInfo range {};
	if (LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(addr), 0, &range,
	                                          sizeof(range)) != 0 ||
	    !range.is_committed || range.start > addr || range.end < addr + length) {
		return {-1, Libs::Posix::POSIX_EINVAL};
	}
	const int rc = LibKernel::Memory::KernelMunmap(addr, static_cast<size_t>(length));
	if (rc != 0) {
		return {-1, LibKernel::KernelToPosix(rc)};
	}
	LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_MUNMAP"
	     " guest_addr=0x%016" PRIx64 " bytes=0x%016" PRIx64 " virtual_mapping_released\n",
	     addr, length);
	return {0, 0};
}


Reply AccessGuestPath(const SyscallRequest& request) {
	// access (0x21). TODO: only F_OK, other modes need guest uid/gid
	const char* path = reinterpret_cast<const char*>(request.args[0]);
	const int   mode = static_cast<int>(request.args[1]);
	if (path == nullptr) {
		return {LibKernel::KERNEL_ERROR_EFAULT, 0};
	}
	if (mode != 0) {
		return {LibKernel::KERNEL_ERROR_ENOSYS, 0};
	}
	return {LibKernel::FileSystem::KernelCheckReachability(path), 0};
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
	if (LibKernel::RegMgr::Enabled()) {
		LibKernel::RegMgr::Guest guest;
		guest.status = request.args[2];
		guest.value  = request.args[3];
		guest.read   = [](uint64_t from, void* to, uint64_t n) {
			return ReadSysctlMemory(reinterpret_cast<const void*>(from), to, n);
		};
		guest.write = [](uint64_t to, const void* from, uint64_t n) {
			return WriteSysctlMemory(reinterpret_cast<void*>(to), from, n);
		};
		const char* reason = nullptr;
		const int   result = LibKernel::RegMgr::Call(static_cast<uint32_t>(op), key, size, guest,
		                                             &answered, &reason);
		if (result >= 0) {
			reply  = result == 0 ? Reply {0, 0} : Reply {-1, result};
			source = "kernel_13.60_snapshot";
			audit();
			return reply;
		}
		source = reason;
	}
	if (store && (op == 1 || op == 2) && size == sizeof(int32_t)) {
		if (status == nullptr || value == nullptr) {
			reply = {-1, Libs::Posix::POSIX_EFAULT};
		} else {
			std::lock_guard lock(mutex);
			if (op == 1) {
				ints[key] = *value;
				*status   = 0;
				reply     = {0, 0};
			} else if (const auto stored = ints.find(key); stored != ints.end()) {
				*value  = stored->second;
				*status = 0;
				reply   = {0, 0};
			}
		}
	} else if (store && (op == 5 || op == 6) && size > 0 && size <= 0x1000) {
		// ops 5/6 are SetBin/GetBin (raw ABI section 55). A width mismatch fails with ENOENT so the
		// caller uses its default
		auto* bytes = reinterpret_cast<uint8_t*>(request.args[3]);
		if (status == nullptr || bytes == nullptr) {
			reply = {-1, Libs::Posix::POSIX_EFAULT};
		} else {
			std::lock_guard lock(mutex);
			if (op == 5) {
				bins[key].assign(bytes, bytes + size);
				*status = 0;
				reply   = {0, 0};
			} else if (const auto stored = bins.find(key);
			           stored != bins.end() && stored->second.size() == size) {
				std::memcpy(bytes, stored->second.data(), size);
				*status = 0;
				reply   = {0, 0};
			}
		}
	} else if (store && op == 0x11 && key == 0 && value == nullptr && size == 0) {
		// sceRegMgrIsInitOK (+0x10e0). ShellUI's EvalRegMgrInitOK goes to safe mode on any negative
		if (status == nullptr) {
			reply = {-1, Libs::Posix::POSIX_EFAULT};
		} else {
			*status = 0;
			reply   = {0, 0};
			LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_REGMGR_INIT_OK status=0 describes the session "
			     "store, not a kernel registry NON_AUTHENTIC\n");
		}
	}
	static const bool sysav_defaults =
	    std::getenv("KYTY_DIAGNOSTIC_SYSAV_REGMGR_DEFAULTS") != nullptr;
	if (sysav_defaults && reply.posix_errno == Libs::Posix::POSIX_ENOSYS && op == 2 &&
	    size == sizeof(int32_t)) {
		// SceSysAvControl.elf defaults: Video at 0x4E4260 (40 x 16), Audio at 0x4E44E0 (12 x 24).
		// convertHistoryFromLayout0 never writes six of these and the 100 ms poll loops on ENOSYS
		// without them.
		static constexpr std::pair<uint32_t, int32_t> defaults[] = {
		    {0x0a030000, 0x13}, // v_mode
		    {0x0a210000, 0},    // v_4k_transfer_rate
		    {0x0a040000, 1},    // v_color_depth
		    {0x0a060000, 2},    // v_signal_range
		    {0x0a140000, 0},    // v_hdcp_version
		    {0x0a150000, 1},    // v_hdr
		    {0x0a290000, 0},    // v_vrr_mode
		    {0x0a2f0000, 0},    // v_enable_4320p
		    {0x0a2a0000, 0},    // v_display_1440p_confirmed
		    {0x0a2d0000, 2},    // v_allm_mode
		    {0x0a160000, 0},    // v_hdr_confirmed
		    {0x09010000, 0},    // invert_color
		    {0x0a0d0000, 0},    // v_display_area1
		    {0x0a1f0000, 0},    // v_display_area2
		    {0x0a2b0000, 0},    // v_display_area3
		    {0x0a200000, 0},    // v_display_area_type1
		    {0x0a2c0000, 0},    // v_display_area_type2
		    {0x0a180000, -1},   // v_hdr_max_ff_tml
		    {0x0a190000, -1},   // v_hdr_max_tml
		    {0x0a1a0000, -1},   // v_hdr_min_tml
		    {0x0a240000, 0},    // v_hfr
		    {0x0a270000, 0},    // v_vrr_boost
		    {0x0a280000, 0},    // v_vrr_capture_safe
		    {0x0a220000, 0},    // cec
		    {0x0a110000, 0},    // hdcp_off_mode
		    {0x0a130000, 0},    // reset_reso_flag
		    {0x0a250000, 0},    // hdr_arbitration_mode
		    {0x0a260000, 0},    // refreshrate_arbitration_mode
		    {0x0a2e0000, 0},    // display_1440_confirmed_version
		    {0x0a320000, 0},    // disable_hdcp
		    {0x0a700000, 0},    // dp_hdcp_mode
		    {0x0a710000, 0},    // fake_monitor_mode
		    {0x0a7a0000, 0},    // disable_hdmi
		    {0x0a720000, 0},    // v_vrr
		    {0x0a730000, 0},    // v_vrr_monitor_type
		    {0x0a740000, 0},    // v_limit_monitor_vrr_range
		    {0x0a760000, 0},    // v_vrr_debug_on_override
		    {0x0a770000, 0},    // v_vrr_mdelta_override
		    {0x0a790000, 0},    // v_hdmi_dsc_mode
		    {0x0a7b0000, 0},    // v_restrict_8k_output
		    {0x0b080000, 0},    // a_sound_format
		    {0x0b090000, 0},    // a_config_options
		    {0x0b070000, 0x18}, // a_codec
		    {0x0b030000, 1},    // a_headphone_out
		    {0x0b010000, 8},    // a_mode
		    {0x0b0a0000, 0},    // a_speaker_update
		    {0x0b0b0000, 0},    // a_speaker_setting
		    {0x0b0c0000, 0},    // a_speaker_layout
		    {0x0b0d0000, 1},    // a_speaker_type
		    {0x0b440101, 0},    // a_speaker_middle_flag_L
		    {0x0b440201, 0},    // a_speaker_middle_flag_R
		    {0x0b440301, 0},    // a_speaker_middle_flag_C
		};
		for (const auto& [k, v]: defaults) {
			if (k == key) {
				if (status == nullptr || value == nullptr) {
					reply = {-1, Libs::Posix::POSIX_EFAULT};
				} else {
					*value  = v;
					*status = 0;
					reply   = {0, 0};
					LOGF("FIRST_FRAME_AUDIT SYSAV_REGMGR_DEFAULT_SERVED op=0x2 key=0x%08x value=%d "
					     "source=SceSysAvControl_baked_defaults NON_AUTHENTIC\n",
					     key, v);
				}
				break;
			}
		}
	}
	if (std::getenv("KYTY_DIAGNOSTIC_REGMGR_KERNEL_TABLE") != nullptr &&
	    reply.posix_errno == Libs::Posix::POSIX_ENOSYS && op == 2 && size == sizeof(int32_t)) {
		// op 2 answers these from the kernel's in-memory table, no NVS read (SystemTtsArbitrator
		// keys)
		static constexpr std::pair<uint32_t, int32_t> captured[] = {
		    {0x09400100, 0},  // ACCESSIBILITY_TTS_enable
		    {0x02020000, 18}, // SYSTEM_language
		    {0x05020000, 1},  // DATE_date_format
		    {0x09400200, 3},  // TTS_speech_speed
		    {0x09400300, 12}, // TTS_volume
		};
		for (const auto& [k, v]: captured) {
			if (k == key) {
				if (!LibKernel::Memory::CanWriteGuest(status, sizeof(*status)) ||
				    !LibKernel::Memory::CanWriteGuest(value, sizeof(*value))) {
					reply = {-1, Libs::Posix::POSIX_EFAULT};
				} else {
					*value  = v;
					*status = 0;
					reply   = {0, 0};
					LOGF("FIRST_FRAME_AUDIT REGMGR_KERNEL_TABLE_SERVED op=0x2 key=0x%08x value=%d "
					     "source=kernel-13.60-live_registry_row\n",
					     key, v);
				}
				break;
			}
		}
	}
	audit();
	return reply;
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


// sys_budget_get_ptype. XXX: ptype not recoverable from the dump; 2 takes the cmp eax,2 edge to
// execve unless the budget block marks 0x2000100
Reply AppBudgetGetPtype(const SyscallRequest& request) {
	LOGF("SYSCORE_APP_SPAWN budget_get_ptype pid=%d id=0x%" PRIx64 " result=2 provisional=1\n",
	     LibKernel::Process::GetPid(), request.args[0]);
	return {2, 0};
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

int RegisterImportedGuestIpmiServer(const char* service_name, uint64_t guest_server,
                                    uint64_t guest_config, uint32_t owner_pid,
                                    uint32_t* server_id) {
	if (service_name == nullptr || service_name[0] == '\0' || guest_server == 0 ||
	    guest_config == 0 || owner_pid == 0 || server_id == nullptr) {
		return LibKernel::KERNEL_ERROR_EINVAL;
	}
	std::string name;
	for (size_t i = 0; i < 128; ++i) {
		const char ch = service_name[i];
		if (ch == '\0') break;
		if (ch < 0x21 || ch > 0x7e) {
			return LibKernel::KERNEL_ERROR_EINVAL;
		}
		name.push_back(ch);
	}
	if (name.empty() || name.size() >= 128) {
		return LibKernel::KERNEL_ERROR_EINVAL;
	}
	std::lock_guard lock(g_sysav_ipmi_lock);
	for (const auto& entry: g_sysav_ipmi_servers) {
		if (entry.second.service_name == name) {
			return LibKernel::KERNEL_ERROR_EBUSY;
		}
	}
	if (g_sysav_next_ipmi_id == 0 || g_sysav_next_ipmi_id >= INT32_MAX) {
		return LibKernel::KERNEL_ERROR_ENOMEM;
	}
	uint32_t id = 0;
	if (LibKernel::IpmiScope::Enabled()) {
		if (!LibKernel::IpmiScope::Register(name, owner_pid, &id)) {
			return LibKernel::KERNEL_ERROR_EBUSY;
		}
		g_sysav_next_ipmi_id = std::max(g_sysav_next_ipmi_id, id + 1);
	} else {
		id = g_sysav_next_ipmi_id++;
	}
	g_sysav_ipmi_servers.emplace(id, SysAvIpmiServer {name, guest_server, guest_config, owner_pid});
	*server_id = id;
	LOGF("FIRST_FRAME_AUDIT IMPORTED_IPMI_SERVER_REGISTERED"
	     " name=%s id=%u owner_pid=%u guest_server=0x%016" PRIx64 " guest_config=0x%016" PRIx64
	     " live_registry_entry_without_interprocess_transport\n",
	     name.c_str(), id, owner_pid, guest_server, guest_config);
	return 0;
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

int RegisterSysAvIpmiServerFilter(int64_t                                   queue,
                                  const LibKernel::EventQueue::KernelEvent& original) {
	return RegisterSysAvIpmiServerFilterInternal(queue, original);
}

void UnregisterSysAvIpmiServerFilter(int64_t queue, uint32_t server_id) {
	UnregisterSysAvIpmiServerFilterInternal(queue, server_id);
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
	static std::atomic<uint32_t> traces {0};
	if (traces.fetch_add(1) < 32) {
		LOGF("PS5_SYSCALL_BACKEND number=0x%016" PRIx64 " result=0x%016" PRIx64 " supported=%d\n",
		     request.number, static_cast<uint64_t>(result.value),
		     request.number == 0xca || request.number == 0x3a || request.number == 0x21 ||
		         request.number == 0x214 || request.number == 0x25a || request.number == 0x14 ||
		         request.number == 0x22d || request.number == 0x22e || request.number == 0x1db ||
		         request.number == 0x1dd || request.number == 0x24b || request.number == 0x25f ||
		         request.number == 0x1b0 || request.number == 0x1d2 || request.number == 0x1a0 ||
		         request.number == 0x154);
	}
	return result;
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

bool InitializeOriginalVirtualAudiodBootEvent() {
	// stands in for orbis_audiod.elf 0x32F..0x34D, which sets bit 0x10 before the daemon loop at
	// 0x360
	if (!std::getenv("KYTY_DIAGNOSTIC_SYSAV_MODEL_ORBIS_AUDIOD_BOOT_EVENT") ||
	    !std::getenv("KYTY_DIAGNOSTIC_SYSAV_MINI_SYSCORE_BOOT_EVENTS")) {
		return false;
	}
	static std::mutex service_mutex;
	static bool       service_started = false;
	std::lock_guard   lock(service_mutex);
	if (service_started) return true;
	if (!Libs::Audio::BackendInitialized()) {
		LOGF("FIRST_FRAME_AUDIT SYSAV_VIRTUAL_AUDIOD_NOT_STARTED"
		     " reason=audio_lifecycle_not_initialized"
		     " NO_BOOT_BIT_SET\n");
		return false;
	}
	LibKernel::EventFlag::KernelEventFlag event = nullptr;
	const int                             opened =
	    LibKernel::EventFlag::KernelOpenExistingEventFlag(&event, "SceBootStatusFlags");
	if (opened != 0 || event == nullptr) {
		LOGF("FIRST_FRAME_AUDIT SYSAV_VIRTUAL_AUDIOD_EVENT_OPEN_FAILED"
		     " error=0x%08x NO_BOOT_BIT_SET\n",
		     static_cast<uint32_t>(opened));
		return false;
	}
	const int set    = LibKernel::EventFlag::KernelSetRegisteredEventFlag(event, 0x10);
	const int closed = LibKernel::EventFlag::KernelCloseEventFlag(event);
	if (set != 0 || closed != 0) {
		LOGF("FIRST_FRAME_AUDIT SYSAV_VIRTUAL_AUDIOD_BOOT_EVENT_FAILED"
		     " set_error=0x%08x close_error=0x%08x\n",
		     static_cast<uint32_t>(set), static_cast<uint32_t>(closed));
		return false;
	}
	service_started = true;
	LOGF("FIRST_FRAME_AUDIT SYSAV_VIRTUAL_AUDIOD_BOOT_READY_SIGNALLED"
	     " source_orbis_audiod.elf_pc=0x32F_to_0x34D"
	     " guest_expected_boot_bit=0x10 named_event_set"
	     " audio_backend_lifecycle_initialized=1"
	     " VIRTUAL_SERVICE_MODEL\n");
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
