#include "common/abi.h"
#include "common/assert.h"
#include "common/common.h"
#include "common/logging/log.h"
#include "common/singleton.h"
#include "common/stringUtils.h"
#include "graphics/host_gpu/hostMemory.h"
#include "kernel/pthread.h"
#include "kernel/fileSystem.h"
#include "kernel/memory.h"
#include "kernel/process.h"
#include "kernel/execProcess.h"
#include "libs/errno.h"
#include "libs/guestPrintf.h"
#include "libs/libs.h"
#include "libs/vaContext.h"
#include "loader/runtimeLinker.h"
#include "loader/symbolDatabase.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fmt/format.h>
#include <list>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <unordered_map>
#include <vector>

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

extern "C" KYTY_SYSV_ABI int KytyGuestJumpSaveMask(void* buffer);
extern "C" KYTY_SYSV_ABI int KytyGuestJumpRestoreMask(void* buffer);

namespace Libs {

namespace LibKernel {
void KernelDispatchPendingSignalForCurrentThread();
bool CanAccessCurrentThreadStack(const void* pointer, uint64_t size, bool writable);
} // namespace LibKernel

namespace Jemspace {
bool ContainsAllocation(const void* pointer, uint64_t size);
}

namespace LibcInternalExt {
void RunThreadAtexitDestructors();
}

namespace LibC {

LIB_VERSION("libc", 1, "libc", 1, 1);

static uint32_t g_need_flag = 1;

using cxa_destructor_func_t = KYTY_SYSV_ABI void (*)(void*);
using atexit_func_t         = KYTY_SYSV_ABI void (*)();

struct ExitCallback {
	atexit_func_t         exit_func         = nullptr;
	cxa_destructor_func_t destructor_func   = nullptr;
	void*                 destructor_object = nullptr;
	void*                 module_id         = nullptr;
};

struct CContext {
	std::mutex              exit_mutex;
	std::list<ExitCallback> exit_callbacks;
};

static int RegisterExitCallback(const ExitCallback& callback) {
	auto* cc = Common::Singleton<CContext>::Instance();
	try {
		std::lock_guard lock(cc->exit_mutex);
		cc->exit_callbacks.push_front(callback);
	} catch (const std::bad_alloc&) {
		return -1;
	}
	return 0;
}

static void RunExitCallbacks(void* module_id) {
	auto* cc = Common::Singleton<CContext>::Instance();
	for (;;) {
		ExitCallback callback {};
		{
			std::lock_guard lock(cc->exit_mutex);
			auto            next =
			    std::find_if(cc->exit_callbacks.begin(), cc->exit_callbacks.end(),
				             [module_id](const ExitCallback& entry) {
				                 return module_id == nullptr || (entry.destructor_func != nullptr &&
								                                 entry.module_id == module_id);
			                 });
			if (next == cc->exit_callbacks.end()) {
				return;
			}
			callback = *next;
			cc->exit_callbacks.erase(next);
		}
		if (callback.exit_func != nullptr) {
			LOGF("GUEST_LIBC_EXIT_CALLBACK kind=atexit function=%p module=%p\n",
			     reinterpret_cast<void*>(callback.exit_func), callback.module_id);
			callback.exit_func();
		} else if (callback.destructor_func != nullptr) {
			LOGF("GUEST_LIBC_EXIT_CALLBACK kind=cxa function=%p module=%p\n",
			     reinterpret_cast<void*>(callback.destructor_func), callback.module_id);
			callback.destructor_func(callback.destructor_object);
		}
	}
}

struct InitEnvParams {
	int         argc;
	uint32_t    pad;
};

static_assert(sizeof(InitEnvParams) == 8);

static int                g_argc = 0;
static const char* const* g_argv = nullptr;
static const char* const* g_envp = nullptr;

int GetArgc() {
	return g_argc;
}

const char** GetArgv() {
	return const_cast<const char**>(g_argv);
}

static void dump_exit_context(uint64_t caller, int code) {
	auto* linker      = Common::Singleton<Loader::RuntimeLinker>::Instance();
	auto* program     = linker->FindProgramByAddr(caller);
	auto  module_name = (program == nullptr ? std::string("<unknown>")
	                                        : Common::PathToString(program->file_name.filename()));
	LOGF("GUEST_LIBC_EXIT caller=0x%016" PRIx64 " module=%s base=0x%016" PRIx64
	     " offset=0x%016" PRIx64 " code=%d\n",
	     caller, module_name.c_str(), program == nullptr ? 0 : program->base_vaddr,
	     program == nullptr ? 0 : caller - program->base_vaddr, code);
	uint64_t rsp = 0;
	asm volatile("movq %%rsp, %0" : "=r"(rsp));
	uint64_t readable = 0;
	Graphics::HostMemoryQueryReadable(rsp, 1024 * 8, readable);
	int logged = 0;
	for (int i = 0; static_cast<uint64_t>(i) * 8 + 8 <= readable && logged < 24; i++) {
		const auto value = *reinterpret_cast<uint64_t*>(rsp + static_cast<uint64_t>(i) * 8);
		auto*      p     = linker->FindProgramByAddr(value);
		if (p == nullptr || value == caller) continue;
		LOGF("  exit frame [rsp%+04x] 0x%016" PRIx64 " -> %s+0x%" PRIx64 "\n", i * 8, value,
		     Common::PathToString(p->file_name.filename()).c_str(), value - p->base_vaddr);
		logged++;
	}
}

static KYTY_SYSV_ABI void exit(int code) {
	PRINT_NAME();
	const int guest_pid = LibKernel::Process::GetPid();
	dump_exit_context(reinterpret_cast<uint64_t>(__builtin_return_address(0)), code);
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD") != nullptr &&
	    LibKernel::Process::IsTrackedRforkChild(guest_pid) &&
	    LibKernel::PthreadSelfOrNull() != nullptr) {
		LOGF("SYSCORE_GUEST_CHILD_LIBC_EXIT"
		     " guest_pid=%d exit_code=%d"
		     " terminating_only_child_thread"
		     " parent_and_other_guest_threads_preserved\n",
		     guest_pid, code);
		LibKernel::PthreadExit(
		    reinterpret_cast<void*>(static_cast<uintptr_t>(static_cast<uint32_t>(code))));
		EXIT("guest child libc exit unexpectedly returned\n");
	}
	LibcInternalExt::RunThreadAtexitDestructors();
	RunExitCallbacks(nullptr);
	const auto status = static_cast<uint32_t>(code) & 0xffu;
	if (LibKernel::Process::IsExecChild()) {
		LibKernel::Process::RecordExecChildExitStatus(status << 8u);
		LOGF("GUEST_EXEC_LIBC_EXIT guest_pid=%d guest_exit_status=%u "
		     "terminating_single_guest_host=1\n",
		     guest_pid, status);
	}
	std::fflush(nullptr);
	std::quick_exit(static_cast<int>(status));
}

static void PrintAbortStringCandidate(const char* name, uint64_t addr) {
	if (!Graphics::HostMemoryIsReadable(addr)) {
		return;
	}

	const auto* ptr = reinterpret_cast<const char*>(static_cast<uintptr_t>(addr));
	char        buf[257] {};
	size_t      len = 0;

	for (; len < sizeof(buf) - 1 && Graphics::HostMemoryIsReadable(addr + len); len++) {
		const auto c = static_cast<unsigned char>(ptr[len]);
		if (c == 0) {
			break;
		}
		if (!std::isprint(c) && c != '\n' && c != '\r' && c != '\t') {
			return;
		}
		buf[len] = static_cast<char>(c);
	}

	if (len >= 4) {
		LOGF("\t %s string = \"%s\"\n", name, buf);
	}
}

static void PrintAbortWideStringCandidate(const char* name, uint64_t addr) {
	if (!Graphics::HostMemoryIsReadable(addr)) {
		return;
	}

	const auto* ptr = reinterpret_cast<const uint16_t*>(static_cast<uintptr_t>(addr));
	char        buf[257] {};
	size_t      len = 0;

	for (;
	     len < sizeof(buf) - 1 && Graphics::HostMemoryIsReadable(addr + len * sizeof(uint16_t) + 1);
	     len++) {
		const auto c = ptr[len];
		if (c == 0) {
			break;
		}
		if (c > 0x7f ||
		    (!std::isprint(static_cast<unsigned char>(c)) && c != '\n' && c != '\r' && c != '\t')) {
			return;
		}
		buf[len] = static_cast<char>(c);
	}

	if (len >= 4) {
		LOGF("\t %s u16 = \"%s\"\n", name, buf);
	}
}

static void PrintAbortBytesCandidate(const char* name, uint64_t addr) {
	if (!Graphics::HostMemoryIsReadable(addr)) {
		return;
	}

	uint8_t bytes[64] {};
	size_t  len = 0;

	for (; len < sizeof(bytes) && Graphics::HostMemoryIsReadable(addr + len); len++) {
		bytes[len] = *reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(addr + len));
	}

	if (len == 0) {
		return;
	}

	LOGF("\t %s bytes =", name);
	for (size_t i = 0; i < len; i++) {
		LOGF(" %02" PRIx8, bytes[i]);
	}
	LOGF("\n");
}

static void PrintAbortPointerCandidate(const char* name, uint64_t addr) {
	PrintAbortStringCandidate(name, addr);
	PrintAbortWideStringCandidate(name, addr);
	PrintAbortBytesCandidate(name, addr);
}

static bool LooksLikeAbortPointer(uint64_t addr) {
	return Graphics::HostMemoryIsReadable(addr) && addr >= 0x10000;
}

static void PrintAbortPointerArrayCandidate(const char* name, uint64_t addr) {
	if (!LooksLikeAbortPointer(addr)) {
		return;
	}

	for (int i = 0; i < 8; i++) {
		const auto slot_addr = addr + static_cast<uint64_t>(i) * sizeof(uint64_t);
		if (!Graphics::HostMemoryIsReadable(slot_addr)) {
			break;
		}

		const auto value = *reinterpret_cast<const uint64_t*>(static_cast<uintptr_t>(slot_addr));
		if (!LooksLikeAbortPointer(value)) {
			continue;
		}

		LOGF("\t %s[%d] = 0x%016" PRIx64 "\n", name, i, value);
		const auto child_name = fmt::format("{}[{}]", name, i);
		PrintAbortPointerCandidate(child_name.c_str(), value);
	}
}

[[noreturn]] static KYTY_SYSV_ABI void abort(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                             uint64_t arg3, uint64_t arg4, uint64_t arg5) {
	PRINT_NAME();

	uint64_t rbp = 0;
	uint64_t rsp = 0;
	// This assembly is x86-64-specific, not Windows-specific.
#if defined(__x86_64__) || defined(_M_X64)
	asm volatile("movq %%rbp, %0" : "=r"(rbp));
	asm volatile("movq %%rsp, %0" : "=r"(rsp));
#endif

	const auto ret = reinterpret_cast<uint64_t>(__builtin_return_address(0));

	LOGF("Guest abort diagnostics:\n"
	     "\t return = 0x%016" PRIx64 "\n"
	     "\t rbp    = 0x%016" PRIx64 "\n"
	     "\t rsp    = 0x%016" PRIx64 "\n"
	     "\t arg0   = 0x%016" PRIx64 "\n"
	     "\t arg1   = 0x%016" PRIx64 "\n"
	     "\t arg2   = 0x%016" PRIx64 "\n"
	     "\t arg3   = 0x%016" PRIx64 "\n"
	     "\t arg4   = 0x%016" PRIx64 "\n"
	     "\t arg5   = 0x%016" PRIx64 "\n",
	     ret, rbp, rsp, arg0, arg1, arg2, arg3, arg4, arg5);

	PrintAbortPointerCandidate("arg0", arg0);
	PrintAbortPointerCandidate("arg1", arg1);
	PrintAbortPointerCandidate("arg2", arg2);
	PrintAbortPointerCandidate("arg3", arg3);
	PrintAbortPointerCandidate("arg4", arg4);
	PrintAbortPointerCandidate("arg5", arg5);
	PrintAbortPointerArrayCandidate("arg0", arg0);
	PrintAbortPointerArrayCandidate("arg1", arg1);
	PrintAbortPointerArrayCandidate("arg2", arg2);
	PrintAbortPointerArrayCandidate("arg3", arg3);
	PrintAbortPointerArrayCandidate("arg4", arg4);
	PrintAbortPointerArrayCandidate("arg5", arg5);

	if (rbp != 0) {
		Common::Singleton<Loader::RuntimeLinker>::Instance()->StackTrace(rbp, rsp);
	}

	if (rsp != 0) {
		LOGF("Guest abort stack words:\n");
		auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
		for (int i = 0; i < 16; i++) {
			const auto addr = rsp + static_cast<uint64_t>(i) * sizeof(uint64_t);
			if (!Graphics::HostMemoryIsReadable(addr)) {
				break;
			}
			const auto value   = *reinterpret_cast<const uint64_t*>(static_cast<uintptr_t>(addr));
			auto*      program = linker->FindProgramByAddr(value);
			if (program != nullptr) {
				auto module_name = Common::PathToString(program->file_name.filename());
				LOGF("\t [%02d] 0x%016" PRIx64 " %s+0x%016" PRIx64 "\n", i, value,
				     module_name.c_str(), value - program->base_vaddr);
			} else {
				LOGF("\t [%02d] 0x%016" PRIx64 "\n", i, value);
			}
			PrintAbortPointerCandidate(fmt::format("stack[{:02d}]", i).c_str(), value);
			PrintAbortPointerArrayCandidate(fmt::format("stack[{:02d}]", i).c_str(), value);
		}
	}

	EXIT("Guest abort()\n");
	std::abort();
}

static KYTY_SYSV_ABI int* libc_error() {
	PRINT_NAME();

	return Posix::GetErrorAddr();
}

static KYTY_SYSV_ABI void init_env(const InitEnvParams* params) {
	PRINT_NAME();

	if (params == nullptr) {
		g_argc = 0;
		g_argv = nullptr;
		g_envp = nullptr;
		return;
	}

	EXIT_NOT_IMPLEMENTED(!Graphics::HostMemoryRangeIsReadable(reinterpret_cast<uint64_t>(params),
	                                                          sizeof(InitEnvParams)));
	EXIT_NOT_IMPLEMENTED(params->argc < 0);
	const auto*    argv      = reinterpret_cast<const char* const*>(params + 1);
	const uint64_t argv_size = (static_cast<uint64_t>(params->argc) + 2u) * sizeof(*argv);
	EXIT_NOT_IMPLEMENTED(
	    !Graphics::HostMemoryRangeIsReadable(reinterpret_cast<uint64_t>(argv), argv_size));
	EXIT_NOT_IMPLEMENTED(argv[params->argc] != nullptr);

	g_argc = params->argc;
	g_argv = argv;
	g_envp = argv + params->argc + 1;

	LOGF("\t argc = %d\n"
	     "\t argv = 0x%016" PRIx64 "\n"
	     "\t envp = 0x%016" PRIx64 "\n",
	     g_argc, reinterpret_cast<uint64_t>(g_argv), reinterpret_cast<uint64_t>(g_envp));

	for (int i = 0; i < g_argc; i++) {
		LOGF("\t argv[%d] = %s\n", i, g_argv[i] != nullptr ? g_argv[i] : "<null>");
	}
}

static KYTY_SYSV_ABI int atexit(atexit_func_t func) {
	PRINT_NAME();

	if (func != nullptr) {
		return RegisterExitCallback({func, nullptr, nullptr, nullptr});
	}

	return 0;
}

static KYTY_SYSV_ABI int libc_printf(VA_ARGS) {
	VA_CONTEXT(ctx); // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
	const auto* format = reinterpret_cast<const char*>(rdi);
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LAUNCH_TRACE") != nullptr && format != nullptr &&
	    std::strstr(format, "[UMD MAIN] launching") != nullptr) {
		LOGF("SYSCORE_PRINTF_GUEST_CALLER return=%p format_ptr=0x%016" PRIx64
		     " ret_arg=0x%016" PRIx64 " format=%s\n",
		     __builtin_return_address(0), rdi, rsi, format);
	}

	PRINT_NAME();

	return GetGuestPrintfCtxFunc()(&ctx);
}

static KYTY_SYSV_ABI int puts(const char* s) {
	PRINT_NAME();

	return GetGuestPrintfStdFunc()("%s\n", s);
}

static KYTY_SYSV_ABI int setenv(const char* name, const char* value, int overwrite) {
	PRINT_NAME();

	LOGF("\t name      = %s\n"
	     "\t value     = %s\n"
	     "\t overwrite = %d\n",
	     (name != nullptr ? name : "<null>"), (value != nullptr ? value : "<null>"), overwrite);

	if (name == nullptr || value == nullptr || name[0] == '\0' ||
	    std::strchr(name, '=') != nullptr) {
		*Posix::GetErrorAddr() = Posix::POSIX_EINVAL;
		return -1;
	}

	// Guest environment changes must not leak into emulator host libraries.
	return 0;
}

static KYTY_SYSV_ABI int64_t libc_time(int64_t* timer) {
	const auto now = static_cast<int64_t>(std::time(nullptr));
	if (timer != nullptr) {
		*timer = now;
	}
	return now;
}

static KYTY_SYSV_ABI double libc_difftime(int64_t time1, int64_t time0) {
	return std::difftime(static_cast<std::time_t>(time1), static_cast<std::time_t>(time0));
}

struct GuestTm {
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
	int tm_wday;
	int tm_yday;
	int tm_isdst;
};

static_assert(sizeof(GuestTm) == 36);

static GuestTm ToGuestTm(const std::tm& time) {
	return {time.tm_sec,  time.tm_min,  time.tm_hour, time.tm_mday, time.tm_mon,
	        time.tm_year, time.tm_wday, time.tm_yday, time.tm_isdst};
}

static std::tm ToHostTm(const GuestTm& time) {
	std::tm result {};
	result.tm_sec   = time.tm_sec;
	result.tm_min   = time.tm_min;
	result.tm_hour  = time.tm_hour;
	result.tm_mday  = time.tm_mday;
	result.tm_mon   = time.tm_mon;
	result.tm_year  = time.tm_year;
	result.tm_wday  = time.tm_wday;
	result.tm_yday  = time.tm_yday;
	result.tm_isdst = time.tm_isdst;
	return result;
}

static KYTY_SYSV_ABI GuestTm* libc_gmtime(const int64_t* timer) {
	if (timer == nullptr) {
		return nullptr;
	}

	thread_local GuestTm result {};
	std::tm              host_result {};
	const auto           t = static_cast<std::time_t>(*timer);

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (_gmtime64_s(&host_result, &t) != 0) {
		return nullptr;
	}
#else
	if (gmtime_r(&t, &host_result) == nullptr) {
		return nullptr;
	}
#endif

	result = ToGuestTm(host_result);
	return &result;
}

static KYTY_SYSV_ABI GuestTm* libc_localtime(const int64_t* timer) {
	if (timer == nullptr) {
		return nullptr;
	}

	thread_local GuestTm result {};
	std::tm              host_result {};
	const auto           t = static_cast<std::time_t>(*timer);

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (_localtime64_s(&host_result, &t) != 0) {
		return nullptr;
	}
#else
	if (localtime_r(&t, &host_result) == nullptr) {
		return nullptr;
	}
#endif

	result = ToGuestTm(host_result);
	return &result;
}

static KYTY_SYSV_ABI int64_t libc_mktime(GuestTm* timeptr) {
	if (timeptr == nullptr) {
		return -1;
	}

	auto host_time = ToHostTm(*timeptr);

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	const auto result = static_cast<int64_t>(_mktime64(&host_time));
#else
	const auto result = static_cast<int64_t>(std::mktime(&host_time));
#endif

	*timeptr = ToGuestTm(host_time);
	return result;
}

static KYTY_SYSV_ABI size_t libc_strftime(char* str, size_t count, const char* format,
                                          const GuestTm* timeptr) {
	if (str == nullptr || format == nullptr || timeptr == nullptr) {
		return 0;
	}

	const auto host_time = ToHostTm(*timeptr);
	return std::strftime(str, count, format, &host_time);
}

static KYTY_SYSV_ABI void catchReturnFromMain(int status) {
	PRINT_NAME();

	uint64_t ret_addr = reinterpret_cast<uint64_t>(__builtin_return_address(0));
	uint64_t rsp      = 0;
	uint64_t rbp      = 0;
#if defined(__x86_64__) || defined(_M_X64)
	asm volatile("movq %%rsp, %0\n\t"
	             "movq %%rbp, %1\n\t"
	             : "=r"(rsp), "=r"(rbp));
#endif

	LOGF("\t status     = %d\n"
	     "\t ret_addr   = 0x%016" PRIx64 "\n"
	     "\t rsp        = 0x%016" PRIx64 "\n"
	     "\t rbp        = 0x%016" PRIx64 "\n",
	     status, ret_addr, rsp, rbp);
	if (rsp != 0) {
		auto* stack = reinterpret_cast<const uint64_t*>(rsp);
		for (uint32_t i = 0; i < 12; i++) {
			LOGF("\t stack[%02" PRIu32 "] = 0x%016" PRIx64 "\n", i, stack[i]);
		}
	}

	::printf("return from main = %d\n", status);
}

using execute_once_func_t = KYTY_SYSV_ABI int (*)(void*, void*, void**);

static std::mutex              g_execute_once_mutex;
static std::condition_variable g_execute_once_cv;

static KYTY_SYSV_ABI int std_execute_once(int* flag, execute_once_func_t func, void* arg) {
	PRINT_NAME();

	if (flag == nullptr || func == nullptr) {
		return 0;
	}

	constexpr int once_init    = 0;
	constexpr int once_done    = 1;
	constexpr int once_running = 2;

	{
		std::unique_lock lock(g_execute_once_mutex);
		while (*flag == once_running) {
			g_execute_once_cv.wait_for(lock, std::chrono::microseconds(10000));
			if (*flag == once_running) {
				lock.unlock();
				LibKernel::KernelDispatchPendingSignalForCurrentThread();
				lock.lock();
			}
		}
		if (*flag == once_done) {
			return 1;
		}
		*flag = once_running;
	}

	void* callback_context = nullptr;
	int   result           = func(nullptr, arg, &callback_context);

	{
		std::lock_guard lock(g_execute_once_mutex);
		*flag = (result != 0 ? once_done : once_init);
	}
	g_execute_once_cv.notify_all();

	return result;
}

static KYTY_SYSV_ABI int cxa_atexit(cxa_destructor_func_t func, void* arg, void* d) {
	PRINT_NAME();

	return func != nullptr ? RegisterExitCallback({nullptr, func, arg, d}) : 0;
}

void KYTY_SYSV_ABI cxa_finalize(void* d) {
	PRINT_NAME();

	RunExitCallbacks(d);
}

} // namespace LibC

namespace LibcInternalExt {

LIB_VERSION("LibcInternalExt", 1, "LibcInternal", 1, 1);

static uint64_t g_mspace_atomic_id_mask = 0;
static uint64_t g_mstate_table[64]      = {0};

using thread_atexit_destructor_t = KYTY_SYSV_ABI void (*)(void*);

struct ThreadAtexitDestructor {
	thread_atexit_destructor_t destructor;
	void*                      object;
	int32_t                    owner;
};

static thread_local std::vector<ThreadAtexitDestructor> g_thread_atexit_destructors;

static bool HostThreadAtexitCallback(thread_atexit_destructor_t destructor, void* dso) {
	if (!Graphics::HostMemoryRangeIsReadable(reinterpret_cast<uint64_t>(dso), sizeof(uint32_t)))
		return false;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	MEMORY_BASIC_INFORMATION region {};
	if (VirtualQuery(reinterpret_cast<const void*>(destructor), &region, sizeof(region)) !=
	        sizeof(region) ||
	    region.State != MEM_COMMIT || region.Type != MEM_IMAGE ||
	    (region.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
		return false;
	const auto protection = region.Protect & 0xffu;
	return protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ ||
	       protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
#else
	Dl_info image {};
	return Graphics::HostMemoryIsReadable(reinterpret_cast<uint64_t>(destructor)) &&
	       dladdr(reinterpret_cast<const void*>(destructor), &image) != 0 &&
	       image.dli_fbase != nullptr;
#endif
}

struct Info {
	uint64_t  size;
	uint32_t  unknown1;
	uint32_t  unknown2;
	uint64_t* mspace_atomic_id_mask;
	uint64_t* mstate_table;
};

void KYTY_SYSV_ABI LibcHeapGetTraceInfo(Info* info) {
	PRINT_NAME();

	EXIT_NOT_IMPLEMENTED(info->size != 32);

	info->mspace_atomic_id_mask = &g_mspace_atomic_id_mask;
	info->mstate_table          = g_mstate_table;
}

int KYTY_SYSV_ABI LibcInternalExtCxaThreadAtexit(thread_atexit_destructor_t destructor,
                                                 void* object, void* module_id) {
	PRINT_NAME();

	auto*      linker     = Common::Singleton<Loader::RuntimeLinker>::Instance();
	const auto dso        = reinterpret_cast<uint64_t>(module_id);
	bool       mapped_dso = false;
	const auto owner      = linker->AcquireThreadAtexit(dso, &mapped_dso);
	if (owner < 0 &&
	    (mapped_dso ||
	     linker->FindProgramByAddr(reinterpret_cast<uint64_t>(destructor)) != nullptr ||
	     !HostThreadAtexitCallback(destructor, module_id))) {
		return -1;
	}
	try {
		g_thread_atexit_destructors.push_back({destructor, object, owner});
	} catch (const std::bad_alloc&) {
		if (owner >= 0) linker->ReleaseThreadAtexit(owner);
		*Posix::GetErrorAddr() = Posix::POSIX_ENOMEM;
		return -1;
	}

	return 0;
}

void RunThreadAtexitDestructors() {
	while (!g_thread_atexit_destructors.empty()) {
		auto destructor = g_thread_atexit_destructors.back();
		g_thread_atexit_destructors.pop_back();

		if (destructor.destructor != nullptr) {
			destructor.destructor(destructor.object);
		}
		if (destructor.owner >= 0) {
			Common::Singleton<Loader::RuntimeLinker>::Instance()->ReleaseThreadAtexit(
			    destructor.owner);
		}
	}
}

LIB_DEFINE(InitLibcInternalExt_1) {
	LIB_FUNC("NWtTN10cJzE", LibcInternalExt::LibcHeapGetTraceInfo);
	LIB_FUNC("qBS714-Jr3g", LibcInternalExt::LibcInternalExtCxaThreadAtexit);
}

} // namespace LibcInternalExt

namespace LibcInternal {

LIB_VERSION("LibcInternal", 1, "LibcInternal", 1, 1);

static uint32_t g_need_flag = 1;

struct GuestReadStream {
	explicit GuestReadStream(int descriptor): fd(descriptor) {}
	int                  fd;
	std::recursive_mutex mutex;
	bool                 closed = false;
	bool                 eof    = false;
	bool                 error  = false;
};

static std::mutex                                                  g_read_stream_mutex;
static std::unordered_map<void*, std::shared_ptr<GuestReadStream>> g_read_streams;

static std::shared_ptr<GuestReadStream> FindReadStream(void* handle) {
	std::lock_guard lock(g_read_stream_mutex);
	const auto      found = g_read_streams.find(handle);
	return found == g_read_streams.end() ? nullptr : found->second;
}

static int ReadStreamError(int error) {
	*Posix::GetErrorAddr() = error;
	return -1;
}

// native libc FILE* (_Fiopen behind inlined ifstream) reach these too and go back to the native
// bodies
static uint64_t g_native_fopen  = 0;
static uint64_t g_native_fclose = 0;
static uint64_t g_native_fread  = 0;
static uint64_t g_native_fseek  = 0;
static uint64_t g_native_ftell  = 0;

void SetNativeStdioEntries(uint64_t fopen, uint64_t fclose, uint64_t fread, uint64_t fseek,
                           uint64_t ftell) {
	g_native_fopen  = fopen;
	g_native_fclose = fclose;
	g_native_fread  = fread;
	g_native_fseek  = fseek;
	g_native_ftell  = ftell;
	LOGF("LIBC_NATIVE_STDIO targets fopen=0x%016" PRIx64 " fclose=0x%016" PRIx64
	     " fread=0x%016" PRIx64 " fseek=0x%016" PRIx64 " ftell=0x%016" PRIx64 "\n",
	     fopen, fclose, fread, fseek, ftell);
}

void* KYTY_SYSV_ABI GuestFopen(const char* path, const char* mode) {
	if (path == nullptr) {
		ReadStreamError(Posix::POSIX_EFAULT);
		return nullptr;
	}
	if (mode == nullptr || *mode == '\0' || std::strchr("rwa", *mode) == nullptr) {
		ReadStreamError(Posix::POSIX_EINVAL);
		return nullptr;
	}
	bool binary = false;
	bool update = false;
	for (const char* part = mode + 1; *part != '\0'; ++part) {
		if (*part == 'b' && !binary) {
			binary = true;
		} else if (*part == '+' && !update) {
			update = true;
		} else {
			ReadStreamError(Posix::POSIX_EINVAL);
			return nullptr;
		}
	}
	if (*mode != 'r' || update) {
		if (g_native_fopen == 0) {
			ReadStreamError(Posix::POSIX_ENOSYS);
			return nullptr;
		}
		void* native = reinterpret_cast<KYTY_SYSV_ABI void* (*)(const char*, const char*)>(
		    g_native_fopen)(path, mode);
		LOGF("GUEST_NATIVE_STDIO_OPEN path=%s mode=%s file=%p errno=%d\n", path, mode, native,
		     native == nullptr ? *Posix::GetErrorAddr() : 0);
		return native;
	}
	const int descriptor = LibKernel::FileSystem::KernelOpen(path, 0, 0);
	LOGF("GUEST_READ_STDIO_OPEN path=%s mode=%s fd=%d\n", path, mode, descriptor);
	if (descriptor < 0) {
		ReadStreamError(LibKernel::KernelToPosix(descriptor));
		return nullptr;
	}
	try {
		auto            stream = std::make_shared<GuestReadStream>(descriptor);
		std::lock_guard lock(g_read_stream_mutex);
		g_read_streams.emplace(stream.get(), stream);
		return stream.get();
	} catch (const std::bad_alloc&) {
		LibKernel::FileSystem::KernelClose(descriptor);
		ReadStreamError(Posix::POSIX_ENOMEM);
		return nullptr;
	}
}

int KYTY_SYSV_ABI GuestFclose(void* handle) {
	auto stream = FindReadStream(handle);
	if (!stream && g_native_fclose != 0) {
		return reinterpret_cast<KYTY_SYSV_ABI int (*)(void*)>(g_native_fclose)(handle);
	}
	if (!stream) {
		return ReadStreamError(Posix::POSIX_EBADF);
	}
	std::lock_guard stream_lock(stream->mutex);
	if (stream->closed) {
		return ReadStreamError(Posix::POSIX_EBADF);
	}
	stream->closed = true;
	{
		std::lock_guard registry_lock(g_read_stream_mutex);
		g_read_streams.erase(handle);
	}
	const int result = LibKernel::FileSystem::KernelClose(stream->fd);
	return result < 0 ? ReadStreamError(LibKernel::KernelToPosix(result)) : 0;
}

size_t KYTY_SYSV_ABI GuestFread(void* destination, size_t size, size_t count, void* handle) {
	if (FindReadStream(handle) == nullptr && g_native_fread != 0) {
		using fread_t = KYTY_SYSV_ABI size_t (*)(void*, size_t, size_t, void*);
		return reinterpret_cast<fread_t>(g_native_fread)(destination, size, count, handle);
	}
	if (size == 0 || count == 0) {
		return 0;
	}
	if (count > std::numeric_limits<size_t>::max() / size) {
		ReadStreamError(Posix::POSIX_EINVAL);
		return 0;
	}
	auto stream = FindReadStream(handle);
	if (!stream) {
		ReadStreamError(Posix::POSIX_EBADF);
		return 0;
	}
	std::lock_guard lock(stream->mutex);
	if (stream->closed) {
		ReadStreamError(Posix::POSIX_EBADF);
		return 0;
	}
	if (stream->eof) {
		return 0;
	}
	const size_t requested = size * count;
	if (!LibKernel::Memory::CanWriteGuest(destination, requested) &&
	    !Jemspace::ContainsAllocation(destination, requested) &&
	    !LibKernel::CanAccessCurrentThreadStack(destination, requested, true)) {
		stream->error = true;
		ReadStreamError(Posix::POSIX_EFAULT);
		return 0;
	}
	size_t consumed = 0;
	while (consumed < requested) {
		const size_t chunk =
		    std::min(requested - consumed, static_cast<size_t>(std::numeric_limits<int>::max()));
		int           read_error = 0;
		const int64_t result     = LibKernel::FileSystem::ReadWithStatus(
		    stream->fd, static_cast<unsigned char*>(destination) + consumed, chunk, &read_error);
		if (result > 0) consumed += static_cast<size_t>(result);
		if (read_error != 0 || result < 0) {
			stream->error = true;
			ReadStreamError(
			    LibKernel::KernelToPosix(read_error != 0 ? read_error : static_cast<int>(result)));
			break;
		}
		if (result == 0) {
			stream->eof = true;
			break;
		}
	}
	return consumed / size;
}

int KYTY_SYSV_ABI GuestFseek(void* handle, int64_t offset, int whence) {
	auto stream = FindReadStream(handle);
	if (!stream && g_native_fseek != 0) {
		return reinterpret_cast<KYTY_SYSV_ABI int (*)(void*, int64_t, int)>(g_native_fseek)(
		    handle, offset, whence);
	}
	if (!stream) {
		return ReadStreamError(Posix::POSIX_EBADF);
	}
	std::lock_guard lock(stream->mutex);
	if (stream->closed) {
		return ReadStreamError(Posix::POSIX_EBADF);
	}
	const int64_t result = LibKernel::FileSystem::KernelLseek(stream->fd, offset, whence);
	if (result < 0) {
		return ReadStreamError(LibKernel::KernelToPosix(static_cast<int>(result)));
	}
	stream->eof = false;
	return 0;
}

int64_t KYTY_SYSV_ABI GuestFtell(void* handle) {
	auto stream = FindReadStream(handle);
	if (!stream && g_native_ftell != 0) {
		return reinterpret_cast<KYTY_SYSV_ABI int64_t (*)(void*)>(g_native_ftell)(handle);
	}
	if (!stream) {
		return ReadStreamError(Posix::POSIX_EBADF);
	}
	std::lock_guard lock(stream->mutex);
	if (stream->closed) {
		return ReadStreamError(Posix::POSIX_EBADF);
	}
	const int64_t result = LibKernel::FileSystem::KernelLseek(stream->fd, 0, 1);
	return result < 0 ? ReadStreamError(LibKernel::KernelToPosix(static_cast<int>(result)))
	                  : result;
}

[[gnu::naked, gnu::returns_twice]] KYTY_SYSV_ABI int GuestSetjmp(void* /*buffer*/) {
	asm volatile("pushq %rdi\n\t"
	             "callq KytyGuestJumpSaveMask\n\t"
	             "popq %rdi\n\t"
	             "movq (%rsp), %rax\n\t"
	             "movq %rax, 0(%rdi)\n\t"
	             "movq %rbx, 8(%rdi)\n\t"
	             "movq %rsp, 16(%rdi)\n\t"
	             "movq %rbp, 24(%rdi)\n\t"
	             "movq %r12, 32(%rdi)\n\t"
	             "movq %r13, 40(%rdi)\n\t"
	             "movq %r14, 48(%rdi)\n\t"
	             "movq %r15, 56(%rdi)\n\t"
	             "fnstcw 64(%rdi)\n\t"
	             "stmxcsr 68(%rdi)\n\t"
	             "xorl %eax, %eax\n\t"
	             "retq\n");
}

[[gnu::naked, gnu::noreturn]] KYTY_SYSV_ABI void GuestLongjmp(void* /*buffer*/, int /*value*/) {
	asm volatile("pushq %rdi\n\t"
	             "pushq %rsi\n\t"
	             "subq $8, %rsp\n\t"
	             "callq KytyGuestJumpRestoreMask\n\t"
	             "addq $8, %rsp\n\t"
	             "popq %rsi\n\t"
	             "popq %rdx\n\t"
	             "stmxcsr -4(%rsp)\n\t"
	             "movl 68(%rdx), %eax\n\t"
	             "andl $0xffffffc0, %eax\n\t"
	             "movl -4(%rsp), %edi\n\t"
	             "andl $0x3f, %edi\n\t"
	             "orl %eax, %edi\n\t"
	             "movl %edi, -4(%rsp)\n\t"
	             "ldmxcsr -4(%rsp)\n\t"
	             "movl %esi, %eax\n\t"
	             "movq 0(%rdx), %rcx\n\t"
	             "movq 8(%rdx), %rbx\n\t"
	             "movq 16(%rdx), %rsp\n\t"
	             "movq 24(%rdx), %rbp\n\t"
	             "movq 32(%rdx), %r12\n\t"
	             "movq 40(%rdx), %r13\n\t"
	             "movq 48(%rdx), %r14\n\t"
	             "movq 56(%rdx), %r15\n\t"
	             "fldcw 64(%rdx)\n\t"
	             "testl %eax, %eax\n\t"
	             "jnz 1f\n\t"
	             "incl %eax\n\t"
	             "1: movq %rcx, (%rsp)\n\t"
	             "retq\n");
}

int KYTY_SYSV_ABI vprintf(const char* str, VaList* c) {
	PRINT_NAME();

	if (c == nullptr) {
		return -1;
	}
	VaList    arguments = *c;
	const int result    = GetGuestVprintfFunc()(str, &arguments);
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_PRINTF_FAULT") != nullptr && str != nullptr &&
	    std::strstr(str, "SERIAL_PRINT_TIME_TICK") != nullptr) {
		LOGF("SYSCORE_VPRINTF_VA_LIST_PRESERVED"
		     " guest_gp_offset=%u formatted_gp_offset=%u"
		     " guest_fp_offset=%u formatted_fp_offset=%u"
		     " guest_overflow=%p formatted_overflow=%p\n",
		     c->gp_offset, arguments.gp_offset, c->fp_offset, arguments.fp_offset,
		     c->overflow_arg_area, arguments.overflow_arg_area);
	}
	return result;
}

static KYTY_SYSV_ABI int snprintf(VA_ARGS) {
	VA_CONTEXT(ctx); // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init)

	PRINT_NAME();

	return GetGuestSnprintfCtxFunc()(&ctx);
}

void* KYTY_SYSV_ABI memset(void* s, int c, size_t n) {
	PRINT_NAME();

	return ::memset(s, c, n);
}

void* KYTY_SYSV_ABI memcpy(void* dest, const void* src, size_t n) {
	return ::memcpy(dest, src, n);
}

void* KYTY_SYSV_ABI memmove(void* dest, const void* src, size_t n) {
	return ::memmove(dest, src, n);
}

int KYTY_SYSV_ABI memcmp(const void* s1, const void* s2, size_t n) {
	return ::memcmp(s1, s2, n);
}

int KYTY_SYSV_ABI strcmp(const char* s1, const char* s2) {
	return ::strcmp(s1, s2);
}

int KYTY_SYSV_ABI strncmp(const char* s1, const char* s2, size_t n) {
	return ::strncmp(s1, s2, n);
}

size_t KYTY_SYSV_ABI strlen(const char* s) {
	return ::strlen(s);
}

char* KYTY_SYSV_ABI strcpy(char* dest, const char* src) {
	return ::strcpy(dest, src);
}

int KYTY_SYSV_ABI strcpy_s(char* dest, size_t dest_size, const char* src) {
	if (dest == nullptr || dest_size == 0 || dest_size > 0x2000000000000000ull) {
		return 22;
	}
	if (src == nullptr) {
		dest[0] = '\0';
		return 22;
	}
	const size_t length = std::strlen(src);
	if (length >= dest_size) {
		dest[0] = '\0';
		return 34;
	}
	const auto dest_start = reinterpret_cast<uintptr_t>(dest);
	const auto src_start  = reinterpret_cast<uintptr_t>(src);
	if ((dest_start <= src_start && src_start - dest_start <= length) ||
	    (src_start < dest_start && dest_start - src_start <= length)) {
		dest[0] = '\0';
		return 22;
	}
	std::memcpy(dest, src, length + 1);
	return 0;
}

char* KYTY_SYSV_ABI strncpy(char* dest, const char* src, size_t count) {
	return ::strncpy(dest, src, count);
}

char* KYTY_SYSV_ABI strcat(char* dest, const char* src) {
	return ::strcat(dest, src);
}

const char* KYTY_SYSV_ABI strchr(const char* s, int c) {
	return ::strchr(s, c);
}

char* KYTY_SYSV_ABI strrchr(const char* s, int c) {
	return const_cast<char*>(::strrchr(s, c));
}

char* KYTY_SYSV_ABI strstr(const char* haystack, const char* needle) {
	static int log_count = 0;
	if (log_count++ < 8) {
		LOGF("LibcInternal::strstr(\"%s\", \"%s\")\n", (haystack != nullptr ? haystack : "<null>"),
		     (needle != nullptr ? needle : "<null>"));
	}
	return const_cast<char*>(::strstr(haystack, needle));
}

long KYTY_SYSV_ABI strtol(const char* str, char** endptr, int base) {
	static int log_count = 0;
	if (log_count++ < 16) {
		LOGF("LibcInternal::strtol(\"%s\", base=%d)\n", (str != nullptr ? str : "<null>"), base);
	}
	return ::strtol(str, endptr, base);
}

unsigned long KYTY_SYSV_ABI strtoul(const char* str, char** endptr, int base) {
	static int log_count = 0;
	if (log_count++ < 16) {
		LOGF("LibcInternal::strtoul(\"%s\", base=%d)\n", (str != nullptr ? str : "<null>"), base);
	}
	return ::strtoul(str, endptr, base);
}

int KYTY_SYSV_ABI atoi(const char* str) {
	return ::atoi(str);
}

float KYTY_SYSV_ABI sinf(float x) {
	return std::sin(x);
}

float KYTY_SYSV_ABI cosf(float x) {
	return std::cos(x);
}

void KYTY_SYSV_ABI sincosf(float x, float* sinp, float* cosp) {
	if (sinp != nullptr) {
		*sinp = std::sin(x);
	}
	if (cosp != nullptr) {
		*cosp = std::cos(x);
	}
}

double KYTY_SYSV_ABI sin(double x) {
	return std::sin(x);
}

double KYTY_SYSV_ABI cos(double x) {
	return std::cos(x);
}

void KYTY_SYSV_ABI sincos(double x, double* sinp, double* cosp) {
	if (sinp != nullptr) {
		*sinp = std::sin(x);
	}
	if (cosp != nullptr) {
		*cosp = std::cos(x);
	}
}

int KYTY_SYSV_ABI LibcHeapErrorReportForGame(uint64_t msp, uint64_t ptr, uint64_t error,
                                             uint64_t arg3, uint64_t arg4, uint64_t arg5) {
	PRINT_NAME();

	LOGF("\t temporary: heap error report ignored, msp=0x%016" PRIx64 ", ptr=0x%016" PRIx64
	     ", error=0x%016" PRIx64 ", args=(0x%016" PRIx64 ",0x%016" PRIx64 ",0x%016" PRIx64 ")\n",
	     msp, ptr, error, arg3, arg4, arg5);

	return 0;
}

LIB_DEFINE(InitLibcInternal_1) {
	LibcInternalExt::InitLibcInternalExt_1(s);
	LIB_FUNC("xeYO4u7uyJ0", LibcInternal::GuestFopen);
	LIB_FUNC("uodLYyUip20", LibcInternal::GuestFclose);
	LIB_FUNC("lbB+UlZqVG0", LibcInternal::GuestFread);
	LIB_FUNC("rQFVBXp-Cxg", LibcInternal::GuestFseek);
	LIB_FUNC("Qazy8LmXTvw", LibcInternal::GuestFtell);
	LIB_FUNC("gNQ1V2vfXDE", LibcInternal::GuestSetjmp);
	LIB_FUNC("lKEN2IebgJ0", LibcInternal::GuestLongjmp);

	LIB_OBJECT("ZT4ODD2Ts9o", &LibcInternal::g_need_flag);
	LIB_FUNC("GMpvxPFW924", LibcInternal::vprintf);
	LIB_FUNC("8zTFvBIAIN8", LibcInternal::memset);
	LIB_FUNC("Q3VBxCXhUHs", LibcInternal::memcpy);
	LIB_FUNC("+P6FRGH4LfA", LibcInternal::memmove);
	LIB_FUNC("DfivPArhucg", LibcInternal::memcmp);
	// aesyjrHVWy4 (+0x148a0) is 3-arg strncmp, Ovb2dSJOAuE (+0x42910) 2-arg strcmp. Swapped, Mono
	// rejects the BSJB signature.
	LIB_FUNC("aesyjrHVWy4", LibcInternal::strncmp);
	LIB_FUNC("Ovb2dSJOAuE", LibcInternal::strcmp);
	LIB_FUNC("j4ViWNHEgww", LibcInternal::strlen);
	LIB_FUNC("5Xa2ACNECdo", LibcInternal::strcpy_s);
	LIB_FUNC("6sJWiWSRuqk", LibcInternal::strncpy);
	LIB_FUNC("Ls4tzzhimqQ", LibcInternal::strcat);
	LIB_FUNC("ob5xAW4ln-0", LibcInternal::strchr);
	LIB_FUNC("9yDWMxEFdJU", LibcInternal::strrchr);
	LIB_FUNC("viiwFMaNamA", LibcInternal::strstr);
	LIB_FUNC("mXlxhmLNMPg", LibcInternal::strtol);
	LIB_FUNC("QxmSHBCuKTk", LibcInternal::strtoul);
	LIB_FUNC("zlfEH8FmyUA", LibcInternal::strtoul);
	LIB_FUNC("fPxypibz2MY", LibcInternal::atoi);
	LIB_FUNC("Q4rRL34CEeE", LibcInternal::sinf);
	LIB_FUNC("-P6FNMzk2Kc", LibcInternal::cosf);
	LIB_FUNC("pztV4AF18iI", LibcInternal::sincosf);
	LIB_FUNC("H8ya2H00jbI", LibcInternal::sin);
	LIB_FUNC("2WE3BTYVwKM", LibcInternal::cos);
	LIB_FUNC("jMB7EFyu30Y", LibcInternal::sincos);
	LIB_FUNC("eLdDw6l0-bU", LibcInternal::snprintf);

	LIB_FUNC("L1SBTkC+Cvw", LibC::abort);
	LIB_FUNC("tsvEmnenz48", LibC::cxa_atexit);
	LIB_FUNC("H2e8t5ScQGc", LibC::cxa_finalize);
	LIB_FUNC("DiGVep5yB5w", LibC::std_execute_once);

	LIB_FUNC("al3JzFI9MQ0", LibcInternal::LibcHeapErrorReportForGame);
}

} // namespace LibcInternal

namespace LibC {

LIB_DEFINE(InitLibC_1) {
	LibcInternal::InitLibcInternal_1(s);

	LIB_OBJECT("P330P3dFF68", &LibC::g_need_flag);

	LIB_FUNC("uMei1W9uyNo", LibC::exit);
	LIB_FUNC("L1SBTkC+Cvw", LibC::abort);
	LIB_FUNC("9BcDykPmo1I", LibC::libc_error);
	LIB_FUNC("bzQExy189ZI", LibC::init_env);
	LIB_FUNC("8G2LB+A3rzg", LibC::atexit);
	LIB_FUNC("hcuQgD53UxM", LibC::libc_printf);
	LIB_FUNC("YQ0navp+YIc", LibC::puts);
	LIB_FUNC("M4YYbSFfJ8g", LibC::setenv);
	LIB_FUNC("wLlFkwG9UcQ", LibC::libc_time);
	LIB_FUNC("-VVn74ZyhEs", LibC::libc_difftime);
	LIB_FUNC("1mecP7RgI2A", LibC::libc_gmtime);
	LIB_FUNC("efhK-YSUYYQ", LibC::libc_localtime);
	LIB_FUNC("n7AepwR0s34", LibC::libc_mktime);
	LIB_FUNC("Av3zjWi64Kw", LibC::libc_strftime);
	LIB_FUNC("XKRegsFpEpk", LibC::catchReturnFromMain);
	LIB_FUNC("tsvEmnenz48", LibC::cxa_atexit);
	LIB_FUNC("H2e8t5ScQGc", LibC::cxa_finalize);
	LIB_FUNC("DiGVep5yB5w", LibC::std_execute_once);
}

} // namespace LibC

} // namespace Libs
