#include "loader/runtimeLinker.h"

#include "common/assert.h"
#include "common/common.h"
#include "common/emulatorConfig.h"
#include "common/file.h"
#include "common/hostException.h"
#include "common/logging/log.h"
#include "common/platform/sysDbg.h"
#include "common/profiler.h"
#include "common/singleton.h"
#include "common/stringUtils.h"
#include "common/threads.h"
#include "common/virtualMemory.h"
#include "graphics/host_gpu/pageManager.h"
#include "kernel/directoryPassthrough.h"
#include "kernel/fileSystem.h"
#include "kernel/eventQueue.h"
#include "kernel/execProcess.h"
#include "kernel/memory.h"
#include "kernel/process.h"
#include "kernel/pthread.h"
#include "libs/errno.h"
#include "libs/libMbus.h"
#include "libs/nativeKernelBridge.h"
#include "loader/decryptedModuleOverlay.h"
#include "loader/elf.h"
#include "loader/gamePatch.h"
#include "loader/guestInstructionPatcher.h"
#include "loader/jit.h"
#include "loader/symbolDatabase.h"
#include "loader/x64InstructionEmulator.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <fmt/format.h>
#include <magic_enum.hpp>
#include <memory>
#include <mutex>
#include <unordered_set>
#include <utility>
#include <vector>

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#elif KYTY_PLATFORM == KYTY_PLATFORM_LINUX
#include <sys/uio.h>
#include <unistd.h>
#endif
#endif

namespace Libs::LibKernel {
void SetProgName(const std::string& name);
int KYTY_SYSV_ABI KernelSysctl(const uint32_t* mib, uint32_t mib_count, void* oldp, size_t* oldlenp,
                               const void* newp, size_t newlen);
int KYTY_SYSV_ABI KernelSysctlStub(const uint32_t* mib, uint32_t mib_count, void* oldp,
                                   size_t* oldlenp, const void* newp, size_t newlen);
int64_t KYTY_SYSV_ABI KernelRawSyscallStub(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                           uint64_t arg3, uint64_t arg4, uint64_t arg5,
                                           uint64_t number, uint64_t* error);
void KYTY_SYSV_ABI    KernelRawSyscallCensus(uint64_t number, uint64_t caller);
int KYTY_SYSV_ABI     KernelNativeOpen(const char* path, int flags, int mode);
int64_t KYTY_SYSV_ABI KernelNativeWrite(int d, const void* buf, size_t nbytes);
int KYTY_SYSV_ABI     KernelNativeClose(int d);
} // namespace Libs::LibKernel

namespace Libs::Posix {
int KYTY_SYSV_ABI getpagesize();
int KYTY_SYSV_ABI pthread_once(void* once_control, void(KYTY_SYSV_ABI* init_routine)());
} // namespace Libs::Posix

namespace Libs::NpCommon {
void SetDiagnosticNativeEntries(uint64_t create, uint64_t config, uint64_t start);
}
namespace Libs::LibcInternal {
}

namespace Loader {

Program::Program() = default;

Program::~Program() = default;

static void FreeTlsBlock(ThreadLocalStorage::Block* block, bool run_guest_free = true) {
	if (block == nullptr || block->ptr == nullptr) {
		return;
	}

	if (block->free_func != nullptr) {
		if (run_guest_free) {
			block->free_func(block->ptr);
		}
	} else if (block->vm_alloc) {
		EXIT_IF(!Libs::LibKernel::Memory::FreeGuestMemory(reinterpret_cast<uint64_t>(block->ptr),
		                                                  block->alloc_size));
	} else {
		delete[] block->ptr;
	}

	block->ptr        = nullptr;
	block->free_func  = nullptr;
	block->vm_alloc   = false;
	block->alloc_size = 0;
}

static uint64_t AlignUp(uint64_t value, uint64_t alignment) {
	return alignment != 0 ? (value + alignment - 1) & ~(alignment - 1) : value;
}

ThreadLocalStorage::~ThreadLocalStorage() {
	for (auto& [_, block]: tlss) {
		FreeTlsBlock(&block);
	}
}

#pragma pack(1)

struct EntryParams {
	int         argc;
	uint32_t    pad;
	const char* argv[3];
};

#pragma pack()

using atexit_func_t = KYTY_SYSV_ABI void (*)();
using entry_func_t  = KYTY_SYSV_ABI void (*)(EntryParams* params, atexit_func_t atexit_func);
using module_ini_fini_func_t = KYTY_SYSV_ABI int (*)(size_t args, const void* argp,
                                                     module_func_t func);

enum class BindType { Unknown, Local, Global, Weak };

struct RelocationInfo {
	bool        resolved   = false;
	BindType    bind       = BindType::Unknown;
	SymbolType  type       = SymbolType::Unknown;
	uint64_t    value      = 0;
	uint64_t    vaddr      = 0;
	uint64_t    base_vaddr = 0;
	std::string name;
	std::string dbg_name;
	bool        bind_self = false;
};

struct StubbedImportRecord {
	uint32_t    index       = 0;
	uint64_t    patch_vaddr = 0;
	uint64_t    thunk_vaddr = 0;
	uint32_t    host_exception_code_token = 0;
	std::string name;
	SymbolType  type = SymbolType::Unknown;
	BindType    bind = BindType::Unknown;
	std::string program;
};

static std::vector<StubbedImportRecord> g_stubbed_imports;
static std::atomic_uint32_t             g_unresolved_stub_call_log_count {0};
static std::vector<uint64_t>            g_unresolved_stub_thunk_pages;
static uint64_t                         g_unresolved_stub_thunk_offset = 0;
static constexpr uint64_t               UNRESOLVED_STUB_PAGE_SIZE      = 4096;

using agc_pool_malloc_func_t = KYTY_SYSV_ABI void* (*)(size_t);
static std::atomic<uint64_t> g_agc_pool_malloc_target {0};
static std::atomic<uint64_t> g_agc_pool_malloc_expected_return {0};
static std::atomic<uint32_t> g_agc_pool_malloc_outcome_count {0};
static std::atomic<uint32_t> g_agc_pool_malloc_install_count {0};
static std::mutex            g_agc_pool_malloc_install_mutex;
static std::atomic<uint32_t> g_mbus_guard_rejection_count {0};

static void* AgcPoolMallocOutcomeCall(size_t size, uint64_t caller) {
	const auto target = g_agc_pool_malloc_target.load(std::memory_order_acquire);
	if (target == 0) return nullptr;
	auto* result = reinterpret_cast<agc_pool_malloc_func_t>(target)(size);
	if (size == 0x22440u &&
	    caller == g_agc_pool_malloc_expected_return.load(std::memory_order_relaxed) &&
	    g_agc_pool_malloc_outcome_count.fetch_add(1, std::memory_order_relaxed) < 8) {
		LOGF("AGC_POOL_MALLOC_OUTCOME size=0x22440 caller_rva=0x58d2 success=%d"
		     "\n",
		     result != nullptr ? 1 : 0);
	}
	return result;
}

[[gnu::noinline]] static KYTY_SYSV_ABI void* AgcPoolMallocOutcome(size_t size) {
	return AgcPoolMallocOutcomeCall(size, reinterpret_cast<uint64_t>(__builtin_return_address(0)));
}



static bool IsExactMbusSetVolumeDownProvider(const Program& provider, const SymbolRecord& record) {
	static constexpr uint8_t client_load[]    = {0x48, 0x8b, 0x3d, 0x01, 0x9c, 0x00, 0x00};
	static constexpr uint8_t internal_error[] = {0x41, 0xbe, 0xff, 0x00, 0x9b, 0x80};
	return provider.base_vaddr != 0 && provider.mapped_size >= 0x10328u &&
	       record.vaddr == provider.base_vaddr + 0x66e0u &&
	       std::memcmp(reinterpret_cast<const void*>(provider.base_vaddr + 0x6718u), client_load,
	                   sizeof(client_load)) == 0 &&
	       std::memcmp(reinterpret_cast<const void*>(provider.base_vaddr + 0x3f2du), internal_error,
	                   sizeof(internal_error)) == 0;
}

static KYTY_SYSV_ABI uint64_t UnresolvedImportStub(uint64_t record_id, uint64_t rsi, uint64_t rdx,
                                                   uint64_t rcx, uint64_t r8, uint64_t r9,
                                                   uint64_t original_rdi,
                                                   uint64_t original_guest_return);

static bool PatchGuestMemory64(uint64_t vaddr, uint64_t value) {
	auto* ptr     = reinterpret_cast<uint64_t*>(vaddr);
	bool  changed = (*ptr != value);
	std::memcpy(ptr, &value, sizeof(value));
	return changed;
}

static uint64_t AllocateUnresolvedImportThunk(uint64_t record_id, uint64_t* allocated_size) {
	const bool     trace_caller = std::getenv("KYTY_DIAGNOSTIC_SYSCORE_CALLSITE_AUDIT") != nullptr;
	const uint64_t thunk_size   = trace_caller ? 48 : 38;
	if (allocated_size != nullptr) *allocated_size = thunk_size;

	if (g_unresolved_stub_thunk_pages.empty() ||
	    g_unresolved_stub_thunk_offset + thunk_size > UNRESOLVED_STUB_PAGE_SIZE) {
		auto page = Libs::LibKernel::Memory::AllocateRuntimeMemory(
		    0, UNRESOLVED_STUB_PAGE_SIZE, Common::VirtualMemory::Mode::ExecuteReadWrite,
		    "unresolved_import_thunk");
		EXIT_NOT_IMPLEMENTED(page == 0);
		g_unresolved_stub_thunk_pages.push_back(page);
		g_unresolved_stub_thunk_offset = 0;
	}

	auto* code = reinterpret_cast<uint8_t*>(g_unresolved_stub_thunk_pages.back() +
	                                        g_unresolved_stub_thunk_offset);
	g_unresolved_stub_thunk_offset += thunk_size;

	uint8_t bytes[38] = {
	    0x48, 0x83, 0xec, 0x18, 0x48, 0x89, 0x3c, 0x24, 0x48, 0xbf,
	    0,    0,    0,    0,    0,    0,    0,    0,             // mov rdi, record_id
	    0x48, 0xb8, 0,    0,    0,    0,    0,    0,    0,    0, // mov rax, UnresolvedImportStub
	    0xff, 0xd0,                                              // call rax
	    0x48, 0x83, 0xc4, 0x18, 0x0f, 0x57, 0xc0,                // xorps xmm0, xmm0
	    0xc3,                                                    // ret
	};
	const auto target = reinterpret_cast<uint64_t>(UnresolvedImportStub);
	if (trace_caller) {
		uint8_t traced[48] = {
		    0x48, 0x83, 0xec, 0x18, 0x48, 0x89, 0x3c, 0x24, 0x48, 0x8b, 0x44, 0x24,
		    0x18, 0x48, 0x89, 0x44, 0x24, 0x08, 0x48, 0xbf, 0,    0,    0,    0,
		    0,    0,    0,    0,    0x48, 0xb8, 0,    0,    0,    0,    0,    0,
		    0,    0,    0xff, 0xd0, 0x48, 0x83, 0xc4, 0x18, 0x0f, 0x57, 0xc0, 0xc3,
		};
		std::memcpy(traced + 20, &record_id, sizeof(record_id));
		std::memcpy(traced + 30, &target, sizeof(target));
		std::memcpy(code, traced, sizeof(traced));
	} else {
		std::memcpy(bytes + 10, &record_id, sizeof(record_id));
		std::memcpy(bytes + 20, &target, sizeof(target));
		std::memcpy(code, bytes, sizeof(bytes));
	}
	Common::VirtualMemory::FlushInstructionCache(reinterpret_cast<uint64_t>(code), thunk_size);
	return reinterpret_cast<uint64_t>(code);
}

static uint64_t RegisterStubbedImport(uint32_t index, const Program* program,
                                      const RelocationInfo& ri) {
	for (const auto& record: g_stubbed_imports) {
		if (record.patch_vaddr == ri.vaddr) {
			return record.thunk_vaddr;
		}
	}

	StubbedImportRecord record {};
	record.index       = index;
	record.patch_vaddr = ri.vaddr;
	record.name        = ri.name;
	record.type        = ri.type;
	record.bind        = ri.bind;
	record.program     = Common::PathToString(program->file_name);
	g_stubbed_imports.push_back(record);
	const auto record_id                     = g_stubbed_imports.size() - 1;
	uint64_t   thunk_size                    = 0;
	const auto thunk = AllocateUnresolvedImportThunk(record_id, &thunk_size);
	g_stubbed_imports[record_id].thunk_vaddr = thunk;
	const auto owner                         = Common::PathToString(program->file_name.filename());
	const auto detail                        = SymbolDatabase::GetNid(ri.name);
	g_stubbed_imports[record_id].host_exception_code_token =
	    Common::HostException::RegisterGuestCodeProvenance(
	        {thunk, thunk_size, ri.base_vaddr,
			 ri.vaddr >= ri.base_vaddr ? ri.vaddr - ri.base_vaddr : 0,
			 Common::HostException::FaultGuestCodeKind::UnresolvedImportThunk, owner.c_str(),
			 detail.c_str()});
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	EXIT_IF(g_stubbed_imports[record_id].host_exception_code_token == 0);
#endif
	return thunk;
}

static KYTY_SYSV_ABI uint64_t UnresolvedImportStub(uint64_t record_id, uint64_t rsi, uint64_t rdx,
                                                   uint64_t rcx, uint64_t r8, uint64_t r9,
                                                   uint64_t original_rdi,
                                                   uint64_t original_guest_return) {
	const auto log_index = g_unresolved_stub_call_log_count.fetch_add(1);
	if (log_index < 1024) {
		if (record_id < g_stubbed_imports.size()) {
			const auto& record = g_stubbed_imports[record_id];
			printf("Unresolved import stub called: %s\n", record.name.c_str());
			LOGF("Unresolved import stub called [%u]: patch_vaddr=0x%016" PRIx64
			     " jmprela_index=%" PRIu32 " symbol=%s type=%s bind=%s program=%s\n",
			     log_index, record.patch_vaddr, record.index, record.name.c_str(),
			     magic_enum::enum_name(record.type), magic_enum::enum_name(record.bind),
			     record.program.c_str());
		} else {
			printf("Unresolved import stub called: <bad-record>\n");
			LOGF("Unresolved import stub called [%u]: record_id=%" PRIu64 " symbol=<bad-record>\n",
			     log_index, record_id);
		}
	}
	return 0;
}

constexpr uint64_t SYSTEM_RESERVED  = 0x800000000u;
constexpr uint64_t CODE_BASE_INCR   = 0x010000000u;
constexpr uint64_t INVALID_OFFSET   = 0x040000000u;
constexpr uint64_t CODE_BASE_OFFSET = 0x100000000u;
constexpr uint64_t INVALID_MEMORY   = SYSTEM_RESERVED + INVALID_OFFSET;

static uint64_t g_desired_base_addr = SYSTEM_RESERVED + CODE_BASE_OFFSET;
static uint64_t g_invalid_memory    = 0;

static Program*              g_tls_main_program        = nullptr;
static thread_local Program* g_tls_cached_main_program = nullptr;
static thread_local uint8_t* g_tls_cached_main_tcb     = nullptr;
static thread_local uint64_t g_sysav_native_fsbase     = 0;
static thread_local uint64_t g_mini_native_fsbase      = 0;
static thread_local uint64_t g_exec_native_fsbase      = 0;


void SetMiniSyscoreNativeThreadFsBase(uint64_t guest_tls_base) {
	g_mini_native_fsbase = guest_tls_base;
}

void SetExecNativeThreadFsBase(uint64_t guest_tcb) {
	g_exec_native_fsbase = guest_tcb;
}

uint64_t ExecNativeThreadFsBase() {
	return g_exec_native_fsbase;
}

static KYTY_SYSV_ABI void RunEntry(uint64_t addr, EntryParams* params, atexit_func_t atexit_func,
                                   void* stack_top) {
#if defined(__x86_64__) || defined(_M_X64)
	auto* func = reinterpret_cast<entry_func_t>(addr);

	if (stack_top != nullptr) {
		const auto aligned_stack_top =
		    reinterpret_cast<uintptr_t>(stack_top) & ~static_cast<uintptr_t>(0x0f);
		const auto guest_rsp = aligned_stack_top - 2u * sizeof(uintptr_t);
		const auto guest_rbp = guest_rsp;

		auto* guest_root_frame = reinterpret_cast<uintptr_t*>(guest_rbp);
		guest_root_frame[0]    = 0;
		guest_root_frame[1]    = 0;

#if defined(__APPLE__)
		// Clang on macOS can allocate plain "r" inputs to r12/r13, which the template
		// clobbers before consuming them. Pin the inputs to registers the SysV guest
		// preserves without changing register allocation on Windows or Linux.
		register entry_func_t func_reg asm("rbx")      = func;
		register uintptr_t    guest_rsp_reg asm("r14") = guest_rsp;
		register uintptr_t    guest_rbp_reg asm("r15") = guest_rbp;
#endif

#if defined(__APPLE__)
		asm volatile(
		    "pushq %%r12\n\t"
		    "pushq %%r13\n\t"
		    "movq %%rsp, %%r12\n\t"
		    "movq %%rbp, %%r13\n\t"
		    "movq %[guest_rsp], %%rsp\n\t"
		    "movq %[guest_rbp], %%rbp\n\t"
		    "callq *%[func]\n\t"
		    "movq %%r13, %%rbp\n\t"
		    "movq %%r12, %%rsp\n\t"
		    "popq %%r13\n\t"
		    "popq %%r12\n\t"
		    :
		    : [func] "r"(func_reg), "D"(params),
		      "S"(atexit_func), [guest_rsp] "r"(guest_rsp_reg), [guest_rbp] "r"(guest_rbp_reg)
		    : "cc", "memory", "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "xmm0", "xmm1", "xmm2",
		      "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12",
		      "xmm13", "xmm14", "xmm15");
#elif KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		// Windows stack probes use the TEB stack limits during the guest stack switch.
		// bounds, which describe the host stack and are invalid while RSP is in guest memory.
		register entry_func_t func_reg asm("rbx")     = func;
		register uintptr_t    guest_rsp_reg asm("r8") = guest_rsp;
		register uintptr_t    guest_rbp_reg asm("r9") = guest_rbp;
		asm volatile("pushq %%r12\n\t"
		             "pushq %%r13\n\t"
		             "pushq %%r14\n\t"
		             "pushq %%r15\n\t"
		             "movq %%gs:0x08, %%r14\n\t"
		             "movq %%gs:0x10, %%r15\n\t"
		             "xorq %%rcx, %%rcx\n\t"
		             "movq %%rcx, %%gs:0x08\n\t"
		             "movq %%rcx, %%gs:0x10\n\t"
		             "movq %%rsp, %%r12\n\t"
		             "movq %%rbp, %%r13\n\t"
		             "movq %[guest_rsp], %%rsp\n\t"
		             "movq %[guest_rbp], %%rbp\n\t"
		             "callq *%[func]\n\t"
		             "movq %%r13, %%rbp\n\t"
		             "movq %%r12, %%rsp\n\t"
		             "movq %%r14, %%gs:0x08\n\t"
		             "movq %%r15, %%gs:0x10\n\t"
		             "popq %%r15\n\t"
		             "popq %%r14\n\t"
		             "popq %%r13\n\t"
		             "popq %%r12\n\t"
		             : [guest_rsp] "+r"(guest_rsp_reg), [guest_rbp] "+r"(guest_rbp_reg)
		             : [func] "r"(func_reg), "D"(params), "S"(atexit_func)
		             : "cc", "memory", "rax", "rcx", "rdx", "r10", "r11", "xmm0", "xmm1", "xmm2",
		               "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11",
		               "xmm12", "xmm13", "xmm14", "xmm15");
#else
		// Clobbers prevent inputs from being allocated to r12/r13.
		asm volatile("movq %%rsp, %%r12\n\t"
		             "movq %%rbp, %%r13\n\t"
		             "movq %[guest_rsp], %%rsp\n\t"
		             "movq %[guest_rbp], %%rbp\n\t"
		             "callq *%[func]\n\t"
		             "movq %%r13, %%rbp\n\t"
		             "movq %%r12, %%rsp\n\t"
		             :
		             : [func] "r"(func), "D"(params),
		               "S"(atexit_func), [guest_rsp] "r"(guest_rsp), [guest_rbp] "r"(guest_rbp)
		             : "cc", "memory", "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13",
		               "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8",
		               "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15");
#endif
		return;
	}

	uintptr_t guest_root_frame[2] = {};

#if defined(__APPLE__)
	register entry_func_t func_reg asm("rbx")      = func;
	register uintptr_t    guest_rbp_reg asm("r14") = reinterpret_cast<uintptr_t>(guest_root_frame);
#endif

#if defined(__APPLE__) || KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	asm volatile("pushq %%r12\n\t"
	             "pushq %%r13\n\t"
	             "movq %%rbp, %%r12\n\t"
	             "movq %[guest_rbp], %%rbp\n\t"
	             "callq *%[func]\n\t"
	             "movq %%r12, %%rbp\n\t"
	             "popq %%r13\n\t"
	             "popq %%r12\n\t"
	             :
#if defined(__APPLE__)
	             : [func] "r"(func_reg), "D"(params),
	               "S"(atexit_func), [guest_rbp] "r"(guest_rbp_reg)
#else
	             : [func] "r"(func), "D"(params),
	               "S"(atexit_func), [guest_rbp] "r"(guest_root_frame)
#endif
	             : "cc", "memory", "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "xmm0", "xmm1",
	               "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11",
	               "xmm12", "xmm13", "xmm14", "xmm15");
#else
	// Keep inputs out of r12.
	asm volatile("movq %%rbp, %%r12\n\t"
	             "movq %[guest_rbp], %%rbp\n\t"
	             "callq *%[func]\n\t"
	             "movq %%r12, %%rbp\n\t"
	             :
	             : [func] "r"(func), "D"(params),
	               "S"(atexit_func), [guest_rbp] "r"(guest_root_frame)
	             : "cc", "memory", "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "xmm0",
	               "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10",
	               "xmm11", "xmm12", "xmm13", "xmm14", "xmm15");
#endif
#else
	(void)stack_top;
	reinterpret_cast<entry_func_t>(addr)(params, atexit_func);
#endif
}

template <class F>
static KYTY_SYSV_ABI void RunInitializerStage(EntryParams* context, atexit_func_t /*atexit_func*/) {
	(*reinterpret_cast<F*>(context))();
}

#if defined(KYTY_VIRTUAL_MEMORY_ALLOCATION_TESTS)
static std::atomic<uint64_t> g_agc_pool_test_result {0};
static std::atomic<uint64_t> g_agc_pool_test_size {0};
static std::atomic<uint32_t> g_agc_pool_test_calls {0};

static KYTY_SYSV_ABI void* TestAgcPoolMalloc(size_t size) {
	g_agc_pool_test_size.store(size, std::memory_order_relaxed);
	g_agc_pool_test_calls.fetch_add(1, std::memory_order_relaxed);
	return reinterpret_cast<void*>(g_agc_pool_test_result.load(std::memory_order_relaxed));
}

bool TestAgcPoolMallocOutcomeDiagnostic() {
	static constexpr char    variable[]       = "KYTY_DIAGNOSTIC_AGC_POOL_MALLOC_OUTCOME";
	static constexpr uint8_t call_signature[] = {0x48, 0x89, 0xfb, 0xbf, 0x40, 0x24, 0x02,
	                                             0x00, 0xe8, 0x5e, 0x35, 0x12, 0x00};
	const auto*              current          = std::getenv(variable);
	const bool               present          = current != nullptr;
	const std::string        saved            = present ? current : "";
	auto                     set_environment  = [](const char* value) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		return _putenv_s(variable, value == nullptr ? "" : value) == 0;
#else
		return value == nullptr ? unsetenv(variable) == 0 : setenv(variable, value, 1) == 0;
#endif
	};
	{
		std::lock_guard lock(g_agc_pool_malloc_install_mutex);
		g_agc_pool_malloc_target.store(0, std::memory_order_release);
		g_agc_pool_malloc_expected_return.store(0, std::memory_order_relaxed);
		g_agc_pool_malloc_outcome_count.store(0, std::memory_order_relaxed);
		g_agc_pool_malloc_install_count.store(0, std::memory_order_relaxed);
	}
	std::vector<uint8_t> importer_image(0x6000);
	std::memcpy(importer_image.data() + 0x58c5, call_signature, sizeof(call_signature));
	Program importer;
	importer.file_name    = "AgcCompositor.elf";
	importer.base_vaddr   = reinterpret_cast<uint64_t>(importer_image.data());
	importer.mapped_size  = importer_image.size();
	importer.dynamic_info = std::make_unique<DynamicInfo>();
	const ModuleId  module {"N", 1, 1, "libSceLibcInternal"};
	const LibraryId library {"M", 1, "libSceLibcInternal"};
	importer.dynamic_info->import_modules.push_back(module);
	importer.dynamic_info->import_libs.push_back(library);
	char                     raw_import[] = "gQX+4GDQjpM#M#N";
	std::array<Elf64_Sym, 2> import_symbols {};
	import_symbols[1].st_info = static_cast<unsigned char>((STB_GLOBAL << 4u) | STT_FUNC);
	Elf64_Rela ordinary_relocation {};
	Elf64_Rela jump_relocation {0x100u, (uint64_t {1} << 32u) | R_X86_64_JUMP_SLOT, 0};
	importer.dynamic_info->str_table               = raw_import;
	importer.dynamic_info->str_table_size          = sizeof(raw_import);
	importer.dynamic_info->symbol_table            = import_symbols.data();
	importer.dynamic_info->symbol_table_total_size = sizeof(import_symbols);
	importer.dynamic_info->symbol_table_entry_size = sizeof(Elf64_Sym);
	importer.dynamic_info->rela_table              = &ordinary_relocation;
	importer.dynamic_info->rela_table_total_size   = 0;
	importer.dynamic_info->rela_table_entry_size   = sizeof(Elf64_Rela);
	importer.dynamic_info->jmprela_table           = &jump_relocation;
	importer.dynamic_info->jmprela_table_size      = sizeof(jump_relocation);
	importer.rela_bits.assign(1, 0);
	Program provider;
	provider.file_name    = "libSceLibcInternal.sprx";
	provider.base_vaddr   = reinterpret_cast<uint64_t>(TestAgcPoolMalloc) - 0x4e60u;
	provider.dynamic_info = std::make_unique<DynamicInfo>();
	provider.dynamic_info->export_modules.push_back(module);
	provider.dynamic_info->export_libs.push_back(library);
	char      raw_export[] = "gQX+4GDQjpM#C#A";
	Elf64_Sym symbol {};
	symbol.st_info                   = static_cast<unsigned char>((STB_GLOBAL << 4u) | STT_FUNC);
	symbol.st_value                  = 0x4e60u;
	provider.dynamic_info->str_table = raw_export;
	provider.dynamic_info->str_table_size          = sizeof(raw_export);
	provider.dynamic_info->symbol_table            = &symbol;
	provider.dynamic_info->symbol_table_total_size = sizeof(symbol);
	provider.dynamic_info->symbol_table_entry_size = sizeof(symbol);
	provider.export_symbols                        = std::make_unique<SymbolDatabase>();
	const SymbolResolve request {
	    "gQX+4GDQjpM", "libSceLibcInternal", 1, "libSceLibcInternal", 1, 1, SymbolType::Func};
	provider.export_symbols->Add(request, reinterpret_cast<uint64_t>(TestAgcPoolMalloc));
	const auto*   record = provider.export_symbols->Find(request);
	RuntimeLinker linker;
	importer.rt = &linker;
	linker.m_programs.push_back(&provider);
	auto relocate = [&] {
		importer.rela_bits.assign(1, 0);
		uint64_t empty = 0;
		std::memcpy(importer_image.data() + jump_relocation.r_offset, &empty, sizeof(empty));
		RuntimeLinker::Relocate(&importer);
		uint64_t output = 0;
		std::memcpy(&output, importer_image.data() + jump_relocation.r_offset, sizeof(output));
		return output;
	};
	const bool     absent_rejected = set_environment(nullptr) && record != nullptr &&
	                                 relocate() == record->vaddr && importer.rela_bits[0] == 1;
	const bool     configured      = set_environment("1");
	const uint64_t relocated       = configured ? relocate() : 0;
	const bool     installed =
	    relocated == reinterpret_cast<uint64_t>(AgcPoolMallocOutcome) && importer.rela_bits[0] == 1;
	static uint64_t token = 0;
	g_agc_pool_test_calls.store(0, std::memory_order_relaxed);
	g_agc_pool_test_result.store(reinterpret_cast<uint64_t>(&token), std::memory_order_relaxed);
	auto       diagnostic = reinterpret_cast<agc_pool_malloc_func_t>(relocated);
	const bool nonnull_passthrough =
	    installed && diagnostic(0x22440u) == &token &&
	    g_agc_pool_test_size.load(std::memory_order_relaxed) == 0x22440u;
	const bool exact_trace =
	    installed && AgcPoolMallocOutcomeCall(0x22440u, importer.base_vaddr + 0x58d2u) == &token &&
	    g_agc_pool_malloc_outcome_count.load(std::memory_order_relaxed) == 1;
	auto resolve = [&](const std::string& name = "gQX+4GDQjpM#M#N",
	                   SymbolType         type = SymbolType::Func) {
		SymbolRecord output {"unchanged", "unchanged", 0x55};
		bool         bind_self = true;
		linker.Resolve(name, type, &importer, &output, &bind_self);
		return std::pair {output, bind_self};
	};
	const auto [reinstalled_output, reinstalled_bind_self] = resolve();
	const bool reinstall_stable =
	    !reinstalled_bind_self &&
	    reinstalled_output.vaddr == reinterpret_cast<uint64_t>(AgcPoolMallocOutcome) &&
	    g_agc_pool_malloc_outcome_count.load(std::memory_order_relaxed) == 1;
	g_agc_pool_test_result.store(0, std::memory_order_relaxed);
	const bool null_passthrough =
	    installed && diagnostic(0x22440u) == nullptr &&
	    AgcPoolMallocOutcomeCall(0x22440u, importer.base_vaddr + 0x58d2u) == nullptr &&
	    g_agc_pool_malloc_outcome_count.load(std::memory_order_relaxed) == 2;
	g_agc_pool_test_result.store(reinterpret_cast<uint64_t>(&token), std::memory_order_relaxed);
	const auto before_other = g_agc_pool_malloc_outcome_count.load(std::memory_order_relaxed);
	const bool other_size_passthrough =
	    installed && diagnostic(7) == &token &&
	    g_agc_pool_malloc_outcome_count.load(std::memory_order_relaxed) == before_other;
	auto original_binding = [&] {
		const auto [output, bind_self] = resolve();
		return !bind_self && output.vaddr == record->vaddr;
	};
	const auto original_importer_name = importer.file_name;
	importer.file_name                = "Other.elf";
	const bool importer_name_rejected = original_binding();
	importer.file_name                = original_importer_name;
	const auto original_provider_name = provider.file_name;
	provider.file_name                = "Other.sprx";
	const bool provider_name_rejected = original_binding();
	provider.file_name                = original_provider_name;
	const auto [wrong_type_output, wrong_type_bind_self] =
	    resolve("gQX+4GDQjpM#M#N", SymbolType::Object);
	const bool type_rejected =
	    !wrong_type_bind_self &&
	    wrong_type_output.vaddr != reinterpret_cast<uint64_t>(AgcPoolMallocOutcome);
	const auto [wrong_name_output, wrong_name_bind_self] = resolve("wrong#M#N");
	const bool qualified_name_rejected =
	    !wrong_name_bind_self &&
	    wrong_name_output.vaddr != reinterpret_cast<uint64_t>(AgcPoolMallocOutcome);
	importer.dynamic_info->import_libs[0].version          = 2;
	const bool library_version_rejected                    = original_binding();
	importer.dynamic_info->import_libs[0].version          = 1;
	importer.dynamic_info->import_modules[0].version_minor = 2;
}

static std::atomic<uint32_t> g_test_mbus_set_volume_down_calls {0};


bool TestOriginalPadProviderDiagnosticRouting() {
	static constexpr char variable[]       = "KYTY_DIAGNOSTIC_HOST_INPUT_HID_PAD";
	static constexpr char guard_variable[] = "KYTY_DIAGNOSTIC_MBUS_UNINITIALIZED_GUARD";
	const auto*           current          = std::getenv(variable);
	const bool            present          = current != nullptr;
	const std::string     saved            = present ? current : "";
	const auto*           guard_current    = std::getenv(guard_variable);
	const bool            guard_present    = guard_current != nullptr;
	const std::string     guard_saved      = guard_present ? guard_current : "";
	auto                  set_environment  = [](const char* name, const char* value) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		return _putenv_s(name, value == nullptr ? "" : value) == 0;
#else
		return value == nullptr ? unsetenv(name) == 0 : setenv(name, value, 1) == 0;
#endif
	};

	const ModuleId      module {"M", 1, 1, "libScePad"};
	const LibraryId     library {"L", 1, "libScePad"};
	const SymbolResolve request {"xk0AcarP3V4",   "libScePad", 1, "libScePad", 1, 1,
	                             SymbolType::Func};
	const SymbolResolve device_request {"d7bXuEBycDI",   "libScePad", 1, "libScePad", 1, 1,
	                                    SymbolType::Func};
	const SymbolResolve ui_request {"FYqcaosYiIo",   "libScePad", 1, "libScePad", 1, 1,
	                                SymbolType::Func};

	Program importer;
	importer.file_name    = "libSceSysBridge.sprx";
	importer.dynamic_info = std::make_unique<DynamicInfo>();
	importer.dynamic_info->import_modules.push_back(module);
	importer.dynamic_info->import_libs.push_back(library);

	Program provider;
	provider.file_name    = "libScePad.sprx";
	provider.dynamic_info = std::make_unique<DynamicInfo>();
	provider.dynamic_info->export_modules.push_back(module);
	provider.dynamic_info->export_libs.push_back(library);
	provider.export_symbols = std::make_unique<SymbolDatabase>();
	provider.export_symbols->Add(request, 0x2222);
	provider.export_symbols->Add(device_request, 0x2223);
	provider.export_symbols->Add(ui_request, 0x2224);

	RuntimeLinker linker;
	linker.m_symbols->Add(request, 0x1111, "Controller::PadOpen");
	linker.m_symbols->Add(device_request, 0x1112, "PadDeviceOpen");
	linker.m_symbols->Add(ui_request, 0x1113, "PadUiReadState");
	linker.m_programs.push_back(&provider);

	auto resolve = [&](const char* nid) {
		SymbolRecord output {};
		bool         bind_self = true;
		linker.Resolve(std::string(nid) + "#L#M", SymbolType::Func, &importer, &output, &bind_self);
		return std::pair {output, bind_self};
	};

	const bool disabled                              = set_environment(variable, nullptr);
	const auto [disabled_output, disabled_bind_self] = resolve("xk0AcarP3V4");
	const bool hle_without_gate = !disabled_bind_self && disabled_output.vaddr == 0x1111;
	const bool configured       = set_environment(variable, "1");
	const auto [original_output, original_bind_self] = resolve("xk0AcarP3V4");
	const bool original_selected = !original_bind_self && original_output.vaddr == 0x2222;
	const auto [other_device_output, other_device_bind_self] = resolve("d7bXuEBycDI");
	const bool unrelated_device_original =
	    !other_device_bind_self && other_device_output.vaddr == 0x2223;
	importer.file_name                                   = "libScePsm.sprx";
	const auto [psm_device_output, psm_device_bind_self] = resolve("d7bXuEBycDI");
	const auto [psm_ui_output, psm_ui_bind_self]         = resolve("FYqcaosYiIo");
	const bool psm_bridge_selected = !psm_device_bind_self && psm_device_output.vaddr == 0x1112 &&
	                                 !psm_ui_bind_self && psm_ui_output.vaddr == 0x1113;
	importer.file_name             = "libReactNative.Modules.Vsh.sprx";
	const auto [react_device_output, react_device_bind_self] = resolve("d7bXuEBycDI");
	const auto [react_ui_output, react_ui_bind_self]         = resolve("FYqcaosYiIo");
	const bool react_bridge_selected = !react_device_bind_self &&
	                                   react_device_output.vaddr == 0x1112 && !react_ui_bind_self &&
	                                   react_ui_output.vaddr == 0x1113;
	importer.file_name               = "libSceSysBridge.sprx";
	provider.file_name               = "Other.sprx";
	const auto [wrong_provider_output, wrong_provider_bind_self] = resolve("xk0AcarP3V4");
	const bool provider_identity_required =
	    !wrong_provider_bind_self && wrong_provider_output.vaddr == 0x1111;
	provider.file_name = "libScePad.sprx";

	const ModuleId      mbus_module {"MM", 1, 1, "libSceMbus"};
	const LibraryId     mbus_library {"ML", 1, "libSceMbus"};
	const SymbolResolve mbus_request {"KRL-S9qBqXw",   "libSceMbus", 1, "libSceMbus", 1, 1,
	                                  SymbolType::Func};
	const SymbolResolve mbus_volume_request {"DOFWwhLN09E",   "libSceMbus", 1, "libSceMbus", 1, 1,
	                                         SymbolType::Func};
	Program             mbus_importer;
	mbus_importer.file_name    = "libScePsm.sprx";
	mbus_importer.dynamic_info = std::make_unique<DynamicInfo>();
	mbus_importer.dynamic_info->import_modules.push_back(mbus_module);
	mbus_importer.dynamic_info->import_libs.push_back(mbus_library);
	std::vector<uint8_t>     mbus_image(0x10400u, 0);
	static constexpr uint8_t client_load[]    = {0x48, 0x8b, 0x3d, 0x01, 0x9c, 0x00, 0x00};
	static constexpr uint8_t internal_error[] = {0x41, 0xbe, 0xff, 0x00, 0x9b, 0x80};
	std::memcpy(mbus_image.data() + 0x6718u, client_load, sizeof(client_load));
	std::memcpy(mbus_image.data() + 0x3f2du, internal_error, sizeof(internal_error));
	Program mbus_provider;
	mbus_provider.file_name    = "libSceMbus.sprx";
	mbus_provider.base_vaddr   = reinterpret_cast<uint64_t>(mbus_image.data());
	mbus_provider.mapped_size  = mbus_image.size();
	mbus_provider.dynamic_info = std::make_unique<DynamicInfo>();
	mbus_provider.dynamic_info->export_modules.push_back(mbus_module);
	mbus_provider.dynamic_info->export_libs.push_back(mbus_library);
	mbus_provider.export_symbols = std::make_unique<SymbolDatabase>();
	mbus_provider.export_symbols->Add(mbus_request, 0x3222);
	mbus_provider.export_symbols->Add(mbus_volume_request, mbus_provider.base_vaddr + 0x66e0u);
	linker.m_symbols->Add(mbus_request, 0x3111, "MbusGetDeviceInfoByCondition");
	linker.m_programs.push_back(&mbus_provider);
	auto resolve_mbus = [&] {
		SymbolRecord output {};
		bool         bind_self = true;
		linker.Resolve("KRL-S9qBqXw#ML#MM", SymbolType::Func, &mbus_importer, &output, &bind_self);
		return std::pair {output, bind_self};
	};
	const auto [psm_mbus_output, psm_mbus_bind_self]     = resolve_mbus();
	mbus_importer.file_name                              = "libSceSysBridge.sprx";
	const auto [other_mbus_output, other_mbus_bind_self] = resolve_mbus();
	const bool mbus_bridge_narrow = !psm_mbus_bind_self && psm_mbus_output.vaddr == 0x3111 &&
	                                !other_mbus_bind_self && other_mbus_output.vaddr == 0x3222;
	Libs::Mbus::SetOriginalGetDeviceInfoByCondition(0);

	const bool guard_environment_disabled = set_environment(guard_variable, nullptr);
	mbus_importer.file_name               = "libSceAudioOut.sprx";
	auto resolve_mbus_volume              = [&] {
		SymbolRecord output {};
		bool         bind_self = true;
		linker.Resolve("DOFWwhLN09E#ML#MM", SymbolType::Func, &mbus_importer, &output, &bind_self);
		return std::pair {output, bind_self};
	};
	const auto [disabled_volume_output, disabled_volume_bind_self] = resolve_mbus_volume();
	const bool guard_disabled = !disabled_volume_bind_self &&
	                            disabled_volume_output.vaddr == mbus_provider.base_vaddr + 0x66e0u;
	const bool guard_configured = set_environment(guard_variable, "1");
	Libs::Mbus::InitMbus_1(linker.m_symbols.get());
	const auto [guard_volume_output, guard_volume_bind_self] = resolve_mbus_volume();
	const bool guard_selected = !guard_volume_bind_self && guard_volume_output.vaddr != 0 &&
	                            guard_volume_output.vaddr != mbus_provider.base_vaddr + 0x66e0u;
	using TestSetVolumeDown   = KYTY_SYSV_ABI int (*)(int, int);
	const auto guard_call     = reinterpret_cast<TestSetVolumeDown>(guard_volume_output.vaddr);
	const bool mapped_null_client_rejected =
	    guard_selected && guard_call(1, 12) == static_cast<int32_t>(0x809b00ffu);

}

struct MainEntryStackTestState {
	bool      called = false;
	uintptr_t rsp    = 0;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	uintptr_t teb_stack_base  = UINTPTR_MAX;
	uintptr_t teb_stack_limit = UINTPTR_MAX;
#endif
};

static KYTY_SYSV_ABI void TestMainEntryStackCallback(EntryParams* params,
                                                     atexit_func_t /*atexit_func*/) {
	auto* state = reinterpret_cast<MainEntryStackTestState*>(const_cast<char*>(params->argv[0]));
	asm volatile("pushq %%r15\n\t"
	             "pushq %%r14\n\t"
	             "popq %%r14\n\t"
	             "popq %%r15\n\t"
	             :
	             :
	             : "memory");
	asm volatile("movq %%rsp, %0" : "=r"(state->rsp) : : "memory");
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	asm volatile("movq %%gs:0x08, %0\n\t"
	             "movq %%gs:0x10, %1\n\t"
	             : "=r"(state->teb_stack_base), "=r"(state->teb_stack_limit)
	             :
	             : "memory");
#endif
	state->called = true;
}

bool TestMainEntryUsesGuestStack() {
	constexpr uint64_t stack_size = 0x10000;
	const auto         stack_base = Libs::LibKernel::Memory::AllocateRuntimeMemory(
	    0, stack_size, Common::VirtualMemory::Mode::ReadWrite, "main_entry_stack_test");
	if (stack_base == 0) {
		return false;
	}

	MainEntryStackTestState state {};
	EntryParams             params {};
	params.argv[0] = reinterpret_cast<const char*>(&state);
	std::memset(reinterpret_cast<void*>(stack_base), 0xcd, stack_size);
	auto* root_frame = reinterpret_cast<const uintptr_t*>(stack_base + stack_size) - 2;

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	uintptr_t original_teb_stack_base  = 0;
	uintptr_t original_teb_stack_limit = 0;
	asm volatile("movq %%gs:0x08, %0\n\t"
	             "movq %%gs:0x10, %1\n\t"
	             : "=r"(original_teb_stack_base), "=r"(original_teb_stack_limit)
	             :
	             : "memory");
#endif

	RunEntry(reinterpret_cast<uint64_t>(TestMainEntryStackCallback), &params, nullptr,
	         reinterpret_cast<void*>(stack_base + stack_size));

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	uintptr_t restored_teb_stack_base  = 0;
	uintptr_t restored_teb_stack_limit = 0;
	asm volatile("movq %%gs:0x08, %0\n\t"
	             "movq %%gs:0x10, %1\n\t"
	             : "=r"(restored_teb_stack_base), "=r"(restored_teb_stack_limit)
	             :
	             : "memory");
	const bool teb_ok = state.teb_stack_base == 0 && state.teb_stack_limit == 0 &&
	                    restored_teb_stack_base == original_teb_stack_base &&
	                    restored_teb_stack_limit == original_teb_stack_limit;
#else
	constexpr bool teb_ok = true;
#endif

	const bool rsp_ok  = state.rsp >= stack_base && state.rsp < stack_base + stack_size;
	const bool root_ok = root_frame[0] == 0 && root_frame[1] == 0;
	const bool freed   = Libs::LibKernel::Memory::FreeGuestMemory(stack_base, stack_size);
	return state.called && rsp_ok && root_ok && teb_ok && freed;
}

struct InitializerStackTestState {
	uint64_t result_address = 0;
	bool     guest_output   = false;
	int      transport      = -1;
	int      posix_error    = 0;
	int      operation      = -1;
	int      returned       = -1;
	bool     closed         = false;
};



bool TestModuleRelocationUsesWritableHostMapping() {
	constexpr uint64_t page_size = 0x4000;
	constexpr uint64_t value     = 0x4b59545950415443;
	const auto         base      = Libs::LibKernel::Memory::AllocateProgramMemory(
	    0, page_size, Common::VirtualMemory::Mode::ReadWrite, "host_only_patch_test");
	if (base == 0) {
		return false;
	}
	Libs::LibKernel::Memory::SetProgramMemoryProtection(base, page_size,
	                                                    Common::VirtualMemory::Mode::Read);

	Libs::LibKernel::Memory::VirtualQueryInfo before {};
	Libs::LibKernel::Memory::VirtualQueryInfo after {};
	const bool                                before_ok =
	    Libs::LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(base), 0, &before,
	                                                sizeof(before)) == 0;
	const bool changed  = PatchGuestMemory64(base, value);
	const bool after_ok = Libs::LibKernel::Memory::KernelVirtualQuery(
	                          reinterpret_cast<const void*>(base), 0, &after, sizeof(after)) == 0;
	const bool value_ok = *reinterpret_cast<const uint64_t*>(base) == value;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	MEMORY_BASIC_INFORMATION mbi {};
	const bool               host_mode_ok =
	    VirtualQuery(reinterpret_cast<const void*>(base), &mbi, sizeof(mbi)) != 0 &&
	    mbi.Protect == PAGE_READWRITE;
#else
	constexpr bool host_mode_ok = true;
#endif
	const bool freed = Libs::LibKernel::Memory::FreeGuestMemory(base, page_size);

	return before_ok && after_ok && changed && value_ok && host_mode_ok && freed &&
	       before.protection == after.protection;
}
#endif

static uint64_t GetAlignedSize(const Elf64_Phdr* p) {
	return (p->p_align != 0 ? (p->p_memsz + (p->p_align - 1)) & ~(p->p_align - 1) : p->p_memsz);
}

static void DbgDumpSymbols(const std::string& folder, Elf64_Sym* symbols, uint64_t size,
                           const char* names) {
	auto folder_str = Common::FixDirectorySlash(folder);

	Common::File::CreateDirectories(folder_str);

	Common::File f;
	f.Create(folder_str + "symbols.txt");

	for (auto* sym = symbols;
	     reinterpret_cast<uint8_t*>(sym) < reinterpret_cast<uint8_t*>(symbols) + size; sym++) {
		f.Printf("----\n");
		f.Printf("st_name = %" PRIu32 ", %s\n", sym->st_name, names + sym->st_name);
		f.Printf("st_info = 0x%02" PRIx8 "\n", sym->st_info);
		f.Printf("st_other = 0x%02" PRIx8 "\n", sym->st_other);
		f.Printf("st_shndx = 0x%04" PRIx16 "\n", sym->st_shndx);
		f.Printf("st_value = 0x%016" PRIx64 "\n", sym->st_value);
		f.Printf("st_size = %" PRIu64 "\n", sym->st_size);
	}

	f.Close();
}

static void DbgDumpRela(const std::string& folder, Elf64_Rela* records, uint64_t size,
                        const char* /*names*/, const char* file_name) {
	auto folder_str = Common::FixDirectorySlash(folder);

	Common::File::CreateDirectories(folder_str);

	Common::File f;
	f.Create(folder_str + file_name);

	for (auto* r = records;
	     reinterpret_cast<uint8_t*>(r) < reinterpret_cast<uint8_t*>(records) + size; r++) {
		f.Printf("----\n"
		         "r_offset = 0x%016" PRIx64 "\n"
		         "r_info = 0x%016" PRIx64 "\n"
		         "r_addend = %" PRId64 "\n",
		         r->r_offset, r->r_info, r->r_addend);
	}

	f.Close();
}

static Common::VirtualMemory::Mode GetMode(Elf64_Word flags) {
	switch (flags) {
		case PF_R: return Common::VirtualMemory::Mode::Read;
		case PF_W: return Common::VirtualMemory::Mode::Write;
		case PF_R | PF_W: return Common::VirtualMemory::Mode::ReadWrite;
		case PF_X: return Common::VirtualMemory::Mode::Execute;
		case PF_X | PF_R: return Common::VirtualMemory::Mode::ExecuteRead;
		case PF_X | PF_W: return Common::VirtualMemory::Mode::ExecuteWrite;
		case PF_X | PF_W | PF_R: return Common::VirtualMemory::Mode::ExecuteReadWrite;

		default: return Common::VirtualMemory::Mode::NoAccess;
	}
}

struct GuestStackFrame {
	GuestStackFrame* next;
	uintptr_t        return_address;
};

static bool IsReadableRange(uint64_t addr, uint64_t size);
static std::atomic<bool>                    g_sysav_raw_traps_installed {false};
static std::atomic<uint64_t>                g_exec_child_native_mmap_site {0};
static std::atomic<uint64_t>                g_exec_child_native_name_site {0};
static std::atomic<uint64_t>                g_exec_child_native_extended_mmap_site {0};
static std::atomic<uint64_t>                g_syscore_native_execve_site {0};
static std::atomic<uint64_t>                g_syscore_native_rfork_site {0};
static std::atomic<uint64_t>                g_syscore_native_launch_entry_site {0};
static std::atomic<uint64_t>                g_syscore_native_rfork_child_entry_site {0};
static std::atomic<uint64_t>                g_syscore_native_child_setup_result_site {0};
static std::array<std::atomic<uint64_t>, 5> g_syscore_native_child_failure_sites {};
static std::atomic<uint64_t>                g_syscore_native_kqueue_result_site {0};
static std::atomic<uint64_t>                g_syscore_native_kqueue_syscall_site {0};
static std::atomic<uint64_t>                g_syscore_native_rdup_syscall_site {0};
static std::atomic<uint64_t>                g_agc_native_kevent_syscall_site {0};
static std::atomic<uint64_t>                g_syscore_original_vfprintf_probe {0};
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
static std::atomic<uint64_t>  g_exec_child_entry_site {0};
static std::array<uint8_t, 2> g_exec_child_entry_bytes {};
struct NativeLibkernelTrap {
	Program* owner;
	uint64_t site;
	uint32_t number;
};
struct NativeLibkernelWrapper {
	uint32_t number;
	uint32_t offset;
	uint8_t  signature[24];
};
static constexpr NativeLibkernelWrapper g_native_libkernel_wrappers[] = {
    {0xc4, 0xf20, {0x48, 0xc7, 0xc0, 0xc4, 0x00, 0x00, 0x00, 0x49, 0x89, 0xca, 0x0f, 0x05,
	               0x72, 0x01, 0xc3, 0x48, 0x8d, 0x0d, 0x9e, 0xf1, 0xff, 0xff, 0xff, 0xe1}},
    {0x214, 0x1a00, {0x48, 0xc7, 0xc0, 0x14, 0x02, 0x00, 0x00, 0x49, 0x89, 0xca, 0x0f, 0x05,
	                 0x72, 0x01, 0xc3, 0x48, 0x8d, 0x0d, 0xbe, 0xe6, 0xff, 0xff, 0xff, 0xe1}},
    {0xca, 0xf40, {0x48, 0xc7, 0xc0, 0xca, 0x00, 0x00, 0x00, 0x49, 0x89, 0xca, 0x0f, 0x05,
	               0x72, 0x01, 0xc3, 0x48, 0x8d, 0x0d, 0x7e, 0xf1, 0xff, 0xff, 0xff, 0xe1}},
    {0xd1, 0xfc0, {0x48, 0xc7, 0xc0, 0xd1, 0x00, 0x00, 0x00, 0x49, 0x89, 0xca, 0x0f, 0x05,
	               0x72, 0x01, 0xc3, 0x48, 0x8d, 0x0d, 0xfe, 0xf0, 0xff, 0xff, 0xff, 0xe1}},
    {0xf0, 0x10e0, {0x48, 0xc7, 0xc0, 0xf0, 0x00, 0x00, 0x00, 0x49, 0x89, 0xca, 0x0f, 0x05,
	                0x72, 0x01, 0xc3, 0x48, 0x8d, 0x0d, 0xde, 0xef, 0xff, 0xff, 0xff, 0xe1}},
    {0x1d2, 0x1800, {0x48, 0xc7, 0xc0, 0xd2, 0x01, 0x00, 0x00, 0x49, 0x89, 0xca, 0x0f, 0x05,
	                 0x72, 0x01, 0xc3, 0x48, 0x8d, 0x0d, 0xbe, 0xe8, 0xff, 0xff, 0xff, 0xe1}}};
static std::mutex                       g_native_libkernel_trap_mutex;
static std::vector<NativeLibkernelTrap> g_native_libkernel_traps;
static std::vector<NativeLibkernelTrap> g_sysav_raw_traps;
static std::vector<uint64_t>            g_sysav_original_ud2;
#endif
static constexpr std::array<uint32_t, 116> g_mini_native_syscall_offsets {{
    0x689EA, 0x68A33, 0x68A54, 0x68A7A, 0x68A9A, 0x68ABA, 0x68ADA, 0x68AFA, 0x68B1A, 0x68B3A,
    0x68B5A, 0x68B7A, 0x68B9A, 0x68BBA, 0x68BDA, 0x68BFA, 0x68C1A, 0x68C3A, 0x68C5A, 0x68C7A,
    0x68C9A, 0x68CBA, 0x68CDA, 0x68CFA, 0x68D1A, 0x68D3A, 0x68D5A, 0x68D7A, 0x68D9A, 0x68DBA,
    0x68DDA, 0x68DFA, 0x68E1A, 0x68E3A, 0x68E5A, 0x68E7A, 0x68E9A, 0x68EBA, 0x68EDA, 0x68EFA,
    0x68F1A, 0x68F3A, 0x68F5A, 0x68F7A, 0x68F9A, 0x68FBA, 0x68FDA, 0x68FFA, 0x6901A, 0x6903A,
    0x6905A, 0x6907A, 0x6A0DA, 0x6A0EA, 0x6A10A, 0x6A12A, 0x6A72A, 0x6A74A, 0x6A8EA, 0x6AA4A,
    0x6B35A, 0x6B37A, 0x6B74A, 0x6BB5A, 0x6C68A, 0x6C6AE, 0x6C6DA, 0x6C6FA, 0x6D29A, 0x6D2BA,
    0x6D2DA, 0x6D2FA, 0x6D39A, 0x6D3FA, 0x6DD8A, 0x6DDBA, 0x6DDEA, 0x6DE1A, 0x6E11A, 0x6E13A,
    0x6FE0A, 0x6FF8A, 0x700BA, 0x7066A, 0x7068A, 0x706AA, 0x7172A, 0x7192A, 0x7194A, 0x71CAA,
    0x71E8A, 0x71EAA, 0x71ECA, 0x71EEA, 0x71F0A, 0x71F2A, 0x71F4A, 0x720BA, 0x720DA, 0x720FA,
    0x7211A, 0x7213A, 0x7233A, 0x7235A, 0x7237A, 0x723BA, 0x7242A, 0x726FA, 0x7271A, 0x7273A,
    0x7275A, 0x7277A, 0x72C8A, 0x72CAA, 0x74D2A, 0x8B2FA,
}};
static std::atomic<bool>                   g_mini_native_syscall_traps_installed {false};
static std::atomic<uint64_t>               g_mini_updatemode_return_site {0};
static std::atomic<uint64_t>               g_mini_preinst_stat_return_site {0};
static std::atomic<uint64_t>               g_mini_preinst_mount_return_site {0};
static std::atomic<uint64_t>               g_mini_rescue_path_site {0};
static std::atomic<uint64_t>               g_mini_updatemode_spawn_passthru_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_hdd_rescue_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_ext_rescue_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_rescue_prologue_end_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_rescue_find_hdd_failed_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_rescue_eventlog_init_failed_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_r14d_jle_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_mount_result_jz_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_global_flag_jz_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_local_var_jz_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_dword_4d7520_addr {0};
static std::atomic<uint64_t>               g_mini_safe_mode_system_mount_jnz_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_system_ex_mount_jz_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_ssd0_open_jnz_site {0};
static std::atomic<uint64_t>               g_mini_sub426550_ioctl_ret_jz_site {0};
static std::atomic<uint64_t>               g_mini_sub426550_errno_translated_jz_site {0};
static std::atomic<uint64_t>               g_mini_sub426550_errno_sign_js_site {0};
static std::atomic<uint64_t>               g_mini_sub426550_open_ssd0_js_site {0};
static std::atomic<uint64_t>               g_mini_sub426550_case7_marker_site {0};
static std::atomic<uint64_t>               g_mini_sub426550_entry_site {0};
static std::atomic<uint64_t>               g_mini_sub428120_entry_site {0};
static std::atomic<uint64_t>               g_mini_dword4d7520_store_a_site {0};
static std::atomic<uint64_t>               g_mini_dword4d7520_store_b_site {0};
static std::atomic<uint64_t>               g_mini_dword4d7520_store_c_site {0};
static std::atomic<uint64_t>               g_mini_dword4d7520_target_vaddr {0};
static std::atomic<uint64_t>               g_mini_dword4d7520_helper_a_site {0};
static std::atomic<uint64_t>               g_mini_dword4d7520_helper_b_site {0};
static std::atomic<uint64_t>               g_mini_sub426190_entry_site {0};
static std::atomic<uint64_t>               g_mini_sub471250_entry_site {0};
static std::atomic<uint32_t>               g_mini_sub471250_v788_value {1u};
static std::atomic<uint64_t>               g_mini_sub419930_entry_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_sub402340_ssd0_user_jnz_site {0};
static std::atomic<uint64_t>               g_mini_cold_boot_progress_site {0};
static KYTY_MS_ABI uint8_t*                TlsMainGetAddr();

static int WalkGuestStack(uint64_t rbp, uint64_t rsp, void** stack, int capacity) {
	constexpr uintptr_t STACK_SIZE = 1024u * 1024u;
	const uintptr_t     code_start = SYSTEM_RESERVED + CODE_BASE_OFFSET;
	const uintptr_t     stack_end  = rsp + STACK_SIZE;
	if (stack == nullptr || capacity <= 0 || rsp == 0 || rbp < rsp || stack_end < rsp ||
	    g_desired_base_addr <= code_start) {
		return 0;
	}

	auto* frame = reinterpret_cast<GuestStackFrame*>(rbp);

	int depth = 0;
	while (depth < capacity) {
		const auto frame_addr = reinterpret_cast<uintptr_t>(frame);
		if (frame_addr < rsp || frame_addr > stack_end - sizeof(GuestStackFrame) ||
		    !IsReadableRange(frame_addr, sizeof(GuestStackFrame)) ||
		    frame->return_address < code_start || frame->return_address >= g_desired_base_addr) {
			break;
		}
		stack[depth++] = reinterpret_cast<void*>(frame->return_address);
		if (reinterpret_cast<uintptr_t>(frame->next) <= frame_addr) {
			break;
		}
		frame = frame->next;
	}
	return depth;
}

// Probe diagnostic ranges without raising another fault.
static bool IsReadableRange(uint64_t addr, uint64_t size) {
	if (addr == 0 || size == 0) {
		return false;
	}

	const uint64_t end = addr + size;
	if (end < addr) {
		return false;
	}

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	uint64_t current = addr;
	while (current < end) {
		MEMORY_BASIC_INFORMATION mbi {};
		if (VirtualQuery(reinterpret_cast<const void*>(current), &mbi, sizeof(mbi)) == 0 ||
		    mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
			return false;
		}
		const auto region_end = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
		if (region_end <= current) {
			return false;
		}
		current = std::min(region_end, end);
	}
#elif defined(__APPLE__)
	// Walk the Mach regions covering the range and require read permission. The fatal
	// report dumps memory behind raw register values, and a fault inside the reporter
	// re-enters the signal handler and wedges the reporting thread.
	uint64_t current = addr;
	while (current < end) {
		mach_vm_address_t              region_addr = current;
		mach_vm_size_t                 region_size = 0;
		vm_region_basic_info_data_64_t info {};
		mach_msg_type_number_t         count       = VM_REGION_BASIC_INFO_COUNT_64;
		mach_port_t                    object_name = MACH_PORT_NULL;
		if (mach_vm_region(mach_task_self(), &region_addr, &region_size, VM_REGION_BASIC_INFO_64,
		                   reinterpret_cast<vm_region_info_t>(&info), &count,
		                   &object_name) != KERN_SUCCESS ||
		    region_addr > current || (info.protection & VM_PROT_READ) == 0) {
			return false;
		}
		current = region_addr + region_size;
	}
#elif KYTY_PLATFORM == KYTY_PLATFORM_LINUX
	const auto page_size = static_cast<uint64_t>(sysconf(_SC_PAGESIZE));
	if (page_size == 0) {
		return false;
	}

	for (uint64_t current = addr; current < end;) {
		uint8_t probe = 0;

		iovec local {&probe, sizeof(probe)};
		iovec remote {reinterpret_cast<void*>(current), sizeof(probe)};

		if (process_vm_readv(getpid(), &local, 1, &remote, 1, 0) !=
		    static_cast<ssize_t>(sizeof(probe))) {
			return false;
		}

		const uint64_t next = (current & ~(page_size - 1)) + page_size;
		if (next <= current) { // wrapped at the top of the address space
			break;
		}
		current = next;
	}
#else
	(void)end;
#endif
	return true;
}

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
// DCE ioctls write results back into the argument buffer, so a committed read-only page isn't
// enough
static bool IsWritableRange(uint64_t addr, uint64_t size) {
	if (addr == 0 || size == 0 || addr > UINT64_MAX - size) {
		return false;
	}
	const uint64_t end = addr + size;
	for (uint64_t current = addr; current < end;) {
		MEMORY_BASIC_INFORMATION mbi {};
		if (VirtualQuery(reinterpret_cast<const void*>(current), &mbi, sizeof(mbi)) == 0 ||
		    mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) != 0) {
			return false;
		}
		const DWORD access = mbi.Protect & 0xff;
		if (access != PAGE_READWRITE && access != PAGE_WRITECOPY &&
		    access != PAGE_EXECUTE_READWRITE && access != PAGE_EXECUTE_WRITECOPY) {
			return false;
		}
		const uint64_t region_end = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
		if (region_end <= current) {
			return false;
		}
		current = std::min(region_end, end);
	}
	return true;
}


#endif

static bool
TerminateMappedExecChildOnUnhandledUd2(const Common::HostException::ExceptionInfo& info) {
	if (info.type != Common::HostException::ExceptionType::IllegalInstruction ||
	    !Libs::LibKernel::Process::IsExecChild() || !IsReadableRange(info.exception_address, 2)) {
		return false;
	}
	const auto* opcode = reinterpret_cast<const uint8_t*>(info.exception_address);
	if (opcode[0] != 0x0f || opcode[1] != 0x0b) {
		return false;
	}
	uint64_t              owner_base = 0;
	std::filesystem::path owner_path;
	if (!Common::Singleton<RuntimeLinker>::Instance()->GetOriginalUd2ProgramInfo(
	        info.exception_address, &owner_base, &owner_path)) {
		return false;
	}
	Libs::LibKernel::Process::RecordExecChildExitStatus(
	    Libs::LibKernel::Process::kGuestSigillCoreWaitStatus);
	LOGF("GUEST_EXEC_FATAL_SIGNAL guest_pid=%d guest_pc=0x%016" PRIx64 " guest_rva=0x%016" PRIx64
	     " owner=%s"
	     " signal=4 core=1 wait_status=0x%08x source=original_guest_ud2\n",
	     Libs::LibKernel::Process::GetPid(), info.exception_address,
	     info.exception_address - owner_base, Common::PathToString(owner_path).c_str(),
	     Libs::LibKernel::Process::kGuestSigillCoreWaitStatus);
	Log::Flush();
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	ExitProcess(static_cast<UINT>(EXCEPTION_ILLEGAL_INSTRUCTION));
#endif
	return true;
}

static bool KytyExceptionHandler(const Common::HostException::ExceptionInfo& exception_info) {
	const auto* info = &exception_info;

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->native_context != nullptr) {
		bool registered = false;
		{
			std::lock_guard lock(g_native_libkernel_trap_mutex);
			registered = std::any_of(
			    g_native_libkernel_traps.begin(), g_native_libkernel_traps.end(),
			    [&](const NativeLibkernelTrap& trap) {
				    return trap.site == info->exception_address && trap.number == info->rax;
			    });
		}
		if (registered && IsReadableRange(info->exception_address, 2)) {
			const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
			if (code[0] == 0x0f && code[1] == 0x0b) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				int posix_errno = reply.posix_errno;
				if (posix_errno == 0 && reply.value > Libs::LibKernel::KERNEL_ERROR_UNKNOWN &&
				    reply.value <= Libs::LibKernel::KERNEL_ERROR_UNKNOWN + 101) {
					posix_errno = Libs::LibKernel::KernelToPosix(static_cast<int>(reply.value));
				}
				auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
				if (posix_errno != 0) {
					*Libs::Posix::GetErrorAddr() = posix_errno;
					context->Rax                 = static_cast<uint64_t>(posix_errno);
					context->EFlags |= uint32_t {1};
				} else {
					context->Rax = static_cast<uint64_t>(reply.value);
					context->EFlags &= ~uint32_t {1};
				}
				context->Rip += 2;
				LOGF("NATIVE_LIBKERNEL_SYSCALL pc=0x%016" PRIx64 " number=0x%" PRIx64
				     " arg0=0x%" PRIx64 " value=%" PRId64 " errno=%d\n",
				     info->exception_address, info->rax, info->rdi, reply.value, posix_errno);
				return true;
			}
		}
	}
	const uint64_t exec_entry = g_exec_child_entry_site.load(std::memory_order_acquire);
	if (exec_entry != 0 && info->exception_address == exec_entry &&
	    info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    Libs::LibKernel::Process::IsExecChild()) {
		auto* code = reinterpret_cast<uint8_t*>(exec_entry);
		if (code[0] == 0x0f && code[1] == 0x0b) {
			DWORD protection = 0;
			if (!VirtualProtect(code, g_exec_child_entry_bytes.size(), PAGE_EXECUTE_READWRITE,
			                    &protection)) {
				return false;
			}
			std::memcpy(code, g_exec_child_entry_bytes.data(), g_exec_child_entry_bytes.size());
			DWORD      unused = 0;
			const bool restored =
			    VirtualProtect(code, g_exec_child_entry_bytes.size(), protection, &unused) != 0;
			if (!Common::VirtualMemory::FlushInstructionCache(exec_entry,
			                                                  g_exec_child_entry_bytes.size()) ||
			    !restored) {
				return false;
			}
			g_exec_child_entry_site.store(0, std::memory_order_release);
			LOGF("GUEST_EXECVE_ENTRY_OBSERVED guest_pid=%d pc=0x%016" PRIx64 " rsp=0x%016" PRIx64
			     " params=0x%016" PRIx64 " exit_handler=0x%016" PRIx64 " monotonic_ms=%llu"
			     " entry_bytes_restored=1\n",
			     Libs::LibKernel::Process::GetPid(), exec_entry, info->rsp, info->rdi, info->rsi,
			     static_cast<unsigned long long>(GetTickCount64()));
			Log::Flush();
			std::fflush(stdout);
			return true;
		}
	}
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_FS10_AUDIT") != nullptr &&
	    info->type == Common::HostException::ExceptionType::AccessViolation &&
	    info->exception_address == 0x92000dc4c && info->access_violation_vaddr == 0x10) {
		const uint64_t tcb      = reinterpret_cast<uint64_t>(TlsMainGetAddr());
		const bool     readable = tcb <= UINT64_MAX - 0x18 && IsReadableRange(tcb + 0x10, 8);
		uint64_t       guest_thread_word = 0;
		if (readable) {
			std::memcpy(&guest_thread_word, reinterpret_cast<const void*>(tcb + 0x10), 8);
		}
		LOGF("FIRST_FRAME_AUDIT SYSCORE_FS10_PROBE"
		     " fault_pc=0x%016" PRIx64 " tcb=0x%016" PRIx64
		     " readable=%u guest_thread_word=0x%016" PRIx64 " fault_preserved\n",
		     info->exception_address, tcb, readable ? 1u : 0u, guest_thread_word);
	}
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_GUEST_THREAD_FS10") != nullptr &&
	    info->type == Common::HostException::ExceptionType::AccessViolation &&
	    (info->exception_address == 0x92000dc4c || info->exception_address == 0x920008431 ||
	     info->exception_address == 0x92000e2ae || info->exception_address == 0x92000e669) &&
	    info->access_violation_vaddr == 0x10 && IsReadableRange(info->exception_address, 9)) {
		constexpr uint8_t expected_r15[] = {0x64, 0x4c, 0x8b, 0x3c, 0x25, 0x10, 0, 0, 0};
		constexpr uint8_t expected_r14[] = {0x64, 0x4c, 0x8b, 0x34, 0x25, 0x10, 0, 0, 0};
		constexpr uint8_t expected_r12[] = {0x64, 0x4c, 0x8b, 0x24, 0x25, 0x10, 0, 0, 0};
		const bool        reads_r15      = info->exception_address == 0x92000dc4c;
		const bool        reads_r12      = info->exception_address == 0x92000e2ae;
		const auto* expected = reads_r15 ? expected_r15 : reads_r12 ? expected_r12 : expected_r14;
		if (std::memcmp(reinterpret_cast<const void*>(info->exception_address), expected,
		                sizeof(expected_r15)) == 0) {
			const auto tcb = reinterpret_cast<uint64_t>(TlsMainGetAddr());
			if (tcb <= UINT64_MAX - 0x18 && IsReadableRange(tcb + 0x10, 8)) {
				uint64_t thread_pointer = 0;
				std::memcpy(&thread_pointer, reinterpret_cast<const void*>(tcb + 0x10), 8);
				if (thread_pointer != 0 && thread_pointer <= UINT64_MAX - 0xe0 &&
				    IsWritableRange(thread_pointer, 0xe0)) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					if (reads_r15) {
						context->R15 = thread_pointer;
					} else if (reads_r12) {
						context->R12 = thread_pointer;
					} else {
						context->R14 = thread_pointer;
					}
					context->Rip += sizeof(expected_r15);
					LOGF("FIRST_FRAME_AUDIT SYSCORE_LIBKERNEL_FS10"
					     " pc=0x%016" PRIx64 " destination=%s"
					     " tcb=0x%016" PRIx64 " model_thread=0x%016" PRIx64
					     " thread_read_emulated\n",
					     info->exception_address,
					     reads_r15   ? "r15"
					     : reads_r12 ? "r12"
					                 : "r14",
					     tcb, thread_pointer);
					return true;
				}
			}
		}
	}
	if (g_mini_native_syscall_traps_installed.load(std::memory_order_acquire) &&
	    g_mini_native_fsbase != 0 &&
	    info->type == Common::HostException::ExceptionType::AccessViolation &&
	    info->exception_address >= 0x400000 && info->exception_address < 0x510000 &&
	    IsReadableRange(info->exception_address, 9)) {
		const auto* ins = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (ins[0] == 0x64 && (ins[1] == 0x48 || ins[1] == 0x4c) && ins[2] == 0x8b &&
		    (ins[3] & 0xc7u) == 0x04 && ins[4] == 0x25) {
			uint32_t displacement = 0;
			std::memcpy(&displacement, ins + 5, sizeof(displacement));
			if (displacement <= 0x1000 && info->access_violation_vaddr == displacement &&
			    g_mini_native_fsbase <= UINT64_MAX - displacement - 8 &&
			    IsReadableRange(g_mini_native_fsbase + displacement, 8)) {
				uint64_t original_word = 0;
				std::memcpy(&original_word,
				            reinterpret_cast<const void*>(g_mini_native_fsbase + displacement), 8);
				auto*          context     = reinterpret_cast<CONTEXT*>(info->native_context);
				const unsigned destination = ((ins[3] >> 3) & 7u) | ((ins[1] & 4u) != 0 ? 8u : 0u);
				switch (destination) {
					case 0: context->Rax = original_word; break;
					case 1: context->Rcx = original_word; break;
					case 2: context->Rdx = original_word; break;
					case 3: context->Rbx = original_word; break;
					case 4: context->Rsp = original_word; break;
					case 5: context->Rbp = original_word; break;
					case 6: context->Rsi = original_word; break;
					case 7: context->Rdi = original_word; break;
					case 8: context->R8 = original_word; break;
					case 9: context->R9 = original_word; break;
					case 10: context->R10 = original_word; break;
					case 11: context->R11 = original_word; break;
					case 12: context->R12 = original_word; break;
					case 13: context->R13 = original_word; break;
					case 14: context->R14 = original_word; break;
					case 15: context->R15 = original_word; break;
				}
				context->Rip += 9;
				static std::atomic<uint32_t> mini_fs_reads {0};
				if (mini_fs_reads.fetch_add(1) < 32) {
					LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_NATIVE_GUEST_FS_LOAD"
					     " site=0x%016" PRIx64 " base=0x%016" PRIx64
					     " offset=0x%x destination=%u word=0x%016" PRIx64 "\n",
					     info->exception_address, g_mini_native_fsbase, displacement, destination,
					     original_word);
				}
				return true;
			}
		}
	}
	if (g_mini_native_syscall_traps_installed.load(std::memory_order_acquire) &&
	    info->type == Common::HostException::ExceptionType::AccessViolation &&
	    info->exception_address == 0x473a2d && info->access_violation_vaddr == 0x38 &&
	    IsReadableRange(info->exception_address, 9)) {
		const uint8_t expected[] = {0x64, 0x48, 0x8b, 0x04, 0x25, 0x38, 0, 0, 0};
		if (std::memcmp(reinterpret_cast<const void*>(info->exception_address), expected,
		                sizeof(expected)) == 0) {
			const auto tcb = reinterpret_cast<uint64_t>(TlsMainGetAddr());
			if (tcb <= UINT64_MAX - 0x40 && IsReadableRange(tcb + 0x38, sizeof(uint64_t))) {
				uint64_t original_guest_tls_word = 0;
				std::memcpy(&original_guest_tls_word, reinterpret_cast<const void*>(tcb + 0x38),
				            sizeof(original_guest_tls_word));
				auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
				context->Rax  = original_guest_tls_word;
				context->Rip += sizeof(expected);
				LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_TLS_FS38"
				     " guest_tcb=0x%016" PRIx64 " tls_word=0x%016" PRIx64 " fs_load_emulated\n",
				     tcb, original_guest_tls_word);
				return true;
			}
		}
	}
	if (g_mini_native_syscall_traps_installed.load(std::memory_order_acquire) &&
	    info->type == Common::HostException::ExceptionType::AccessViolation &&
	    info->exception_address == 0x46b247 && info->access_violation_vaddr == 0x10 &&
	    IsReadableRange(info->exception_address, 9)) {
		const uint8_t expected[] = {0x64, 0x48, 0x8b, 0x1c, 0x25, 0x10, 0, 0, 0};
		if (std::memcmp(reinterpret_cast<const void*>(info->exception_address), expected,
		                sizeof(expected)) == 0) {
			const auto tcb = reinterpret_cast<uint64_t>(TlsMainGetAddr());
			if (tcb <= UINT64_MAX - 0x18 && IsReadableRange(tcb + 0x10, sizeof(uint64_t))) {
				uint64_t original_guest_thread = 0;
				std::memcpy(&original_guest_thread, reinterpret_cast<const void*>(tcb + 0x10),
				            sizeof(original_guest_thread));
				auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
				context->Rbx  = original_guest_thread;
				context->Rip += sizeof(expected);
				LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_TLS_FS10"
				     " guest_tcb=0x%016" PRIx64 " guest_thread=0x%016" PRIx64 " fs_load_emulated\n",
				     tcb, original_guest_thread);
				return true;
			}
		}
	}
	const uint64_t mini_updatemode_return =
	    g_mini_updatemode_return_site.load(std::memory_order_acquire);
	if (mini_updatemode_return != 0 &&
	    info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address == mini_updatemode_return &&
	    IsReadableRange(mini_updatemode_return, 2)) {
		const auto* code = reinterpret_cast<const uint8_t*>(mini_updatemode_return);
		if (code[0] == 0x0f && code[1] == 0x0b) {
			const uint32_t value  = static_cast<uint32_t>(info->rax);
			uint32_t       parity = 0;
			for (uint32_t i = 0; i < 8; ++i) {
				parity += (value >> i) & 1u;
			}
			auto*              ctx     = reinterpret_cast<CONTEXT*>(info->native_context);
			constexpr uint32_t changed = 0x1u | 0x4u | 0x40u | 0x80u | 0x800u;
			const uint32_t status = ((parity & 1u) == 0 ? 0x4u : 0u) | (value == 0 ? 0x40u : 0u) |
			                        ((value & 0x80000000u) != 0 ? 0x80u : 0u);
			ctx->EFlags           = (ctx->EFlags & ~changed) | status;
			ctx->Rip += 2;
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_UPDATEMODE_RETURN"
			     " site=0x%016" PRIx64 " result=0x%08x signed=%d\n",
			     mini_updatemode_return, value, static_cast<int32_t>(value));
			Log::Flush();
			return true;
		}
	}
	const uint64_t mini_preinst_stat_return =
	    g_mini_preinst_stat_return_site.load(std::memory_order_acquire);
	const uint64_t mini_preinst_mount_return =
	    g_mini_preinst_mount_return_site.load(std::memory_order_acquire);
	if ((info->exception_address == mini_preinst_stat_return ||
	     info->exception_address == mini_preinst_mount_return) &&
	    info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    IsReadableRange(info->exception_address, 2)) {
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b) {
			const uint32_t value  = static_cast<uint32_t>(info->rax);
			uint32_t       parity = 0;
			for (uint32_t i = 0; i < 8; ++i) {
				parity += (value >> i) & 1u;
			}
			auto*              ctx     = reinterpret_cast<CONTEXT*>(info->native_context);
			constexpr uint32_t changed = 0x1u | 0x4u | 0x40u | 0x80u | 0x800u;
			const uint32_t status = ((parity & 1u) == 0 ? 0x4u : 0u) | (value == 0 ? 0x40u : 0u) |
			                        ((value & 0x80000000u) != 0 ? 0x80u : 0u);
			ctx->EFlags           = (ctx->EFlags & ~changed) | status;
			ctx->Rip += 2;
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_PREINST_%s_RETURN"
			     " site=0x%016" PRIx64 " result=0x%08x signed=%d\n",
			     info->exception_address == mini_preinst_stat_return ? "STAT" : "MOUNT",
			     info->exception_address, value, static_cast<int32_t>(value));
			Log::Flush();
			return true;
		}
	}
	const uint64_t mini_rescue_path = g_mini_rescue_path_site.load(std::memory_order_acquire);
	if (mini_rescue_path != 0 &&
	    info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address == mini_rescue_path && IsReadableRange(mini_rescue_path, 7)) {
		const auto* code = reinterpret_cast<const uint8_t*>(mini_rescue_path);
		if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x3d && code[3] == 0xa2 &&
		    code[4] == 0x28 && code[5] == 0x0a && code[6] == 0x00) {
			auto*   ctx          = reinterpret_cast<CONTEXT*>(info->native_context);
			int32_t initial_mode = 0;
			if (ctx->Rbp >= 0x30 && IsReadableRange(ctx->Rbp - 0x30, sizeof(initial_mode))) {
				std::memcpy(&initial_mode, reinterpret_cast<const void*>(ctx->Rbp - 0x30),
				            sizeof(initial_mode));
			}
			ctx->Rdi = 0x4a8597;
			ctx->Rip += 7;
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_RESCUE_PATH_ENTERED"
			     " site=0x%016" PRIx64 " initial_mode=%d\n",
			     mini_rescue_path, initial_mode);
			Log::Flush();
			return true;
		}
	}
	const uint64_t mini_updatemode_spawn_passthru =
	    g_mini_updatemode_spawn_passthru_site.load(std::memory_order_acquire);
	if (mini_updatemode_spawn_passthru != 0 &&
	    info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address == mini_updatemode_spawn_passthru &&
	    IsReadableRange(mini_updatemode_spawn_passthru, 5)) {
		const auto* code = reinterpret_cast<const uint8_t*>(mini_updatemode_spawn_passthru);
		if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x7c && code[3] == 0x00 &&
		    code[4] == 0x00) {
			auto* ctx = reinterpret_cast<CONTEXT*>(info->native_context);
			ctx->Rax  = 0;
			ctx->Rip += 5;
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_UPDATEMODE_SPAWN_PASSTHRU"
			     " site=0x%016" PRIx64 " rax=0 spawn_never_executed"
			     " guest_rip_advanced=5 NON_AUTHENTIC\n",
			     mini_updatemode_spawn_passthru);
			Log::Flush();
			return true;
		}
	}
	const uint64_t mini_hdd_rescue =
	    g_mini_safe_mode_hdd_rescue_site.load(std::memory_order_acquire);
	const uint64_t mini_ext_rescue =
	    g_mini_safe_mode_ext_rescue_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    (info->exception_address == mini_hdd_rescue ||
	     info->exception_address == mini_ext_rescue) &&
	    info->exception_address != 0 && IsReadableRange(info->exception_address, 5)) {
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x00 && code[3] == 0x00 &&
		    code[4] == 0x00) {
			auto* ctx = reinterpret_cast<CONTEXT*>(info->native_context);
			ctx->Rdi  = 0xf0;
			ctx->Rip += 5;
			const char* label = (info->exception_address == mini_hdd_rescue)
			                        ? "HDD_CHECK_RESCUE_HIT"
			                        : "EXT_MOUNT_RESCUE_HIT";
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_%s"
			     " site=0x%016" PRIx64 " rdi=0xf0 mov_edi_simulated"
			     " guest_rip_advanced=5 NON_AUTHENTIC\n",
			     label, info->exception_address);
			Log::Flush();
			return true;
		}
	}
	const uint64_t mini_rescue_prologue_end =
	    g_mini_safe_mode_rescue_prologue_end_site.load(std::memory_order_acquire);
	const uint64_t mini_rescue_find_hdd_failed =
	    g_mini_safe_mode_rescue_find_hdd_failed_site.load(std::memory_order_acquire);
	const uint64_t mini_rescue_eventlog_init_failed =
	    g_mini_safe_mode_rescue_eventlog_init_failed_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    (info->exception_address == mini_rescue_prologue_end ||
	     info->exception_address == mini_rescue_find_hdd_failed ||
	     info->exception_address == mini_rescue_eventlog_init_failed) &&
	    info->exception_address != 0 && IsReadableRange(info->exception_address, 5)) {
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x00 && code[3] == 0x00 &&
		    code[4] == 0x00) {
			auto*       ctx = reinterpret_cast<CONTEXT*>(info->native_context);
			const char* label;
			uint64_t    resume_rip;
			if (info->exception_address == mini_rescue_prologue_end) {
				label      = "RESCUE_UPSTREAM_PROLOGUE_END";
				resume_rip = info->exception_address + 5;
			} else if (info->exception_address == mini_rescue_find_hdd_failed) {
				label      = "RESCUE_UPSTREAM_FIND_HDD_FAILED";
				resume_rip = info->exception_address + (0x49ba - 0x478c);
			} else {
				label      = "RESCUE_UPSTREAM_EVENTLOG_INIT_FAILED";
				resume_rip = info->exception_address + (0x49ba - 0x4910);
			}
			ctx->Rip = resume_rip;
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_%s"
			     " site=0x%016" PRIx64 " resume_rip=0x%016" PRIx64
			     " jmp_to_4049ba_emulated NON_AUTHENTIC\n",
			     label, info->exception_address, resume_rip);
			Log::Flush();
			return true;
		}
	}
	const uint64_t r14d_jle = g_mini_safe_mode_r14d_jle_site.load(std::memory_order_acquire);
	const uint64_t mount_result_jz =
	    g_mini_safe_mode_mount_result_jz_site.load(std::memory_order_acquire);
	const uint64_t global_flag_jz =
	    g_mini_safe_mode_global_flag_jz_site.load(std::memory_order_acquire);
	const uint64_t local_var_jz =
	    g_mini_safe_mode_local_var_jz_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address != 0 &&
	    (info->exception_address == r14d_jle || info->exception_address == mount_result_jz ||
	     info->exception_address == global_flag_jz || info->exception_address == local_var_jz)) {
		auto* ctx = reinterpret_cast<CONTEXT*>(info->native_context);
		if (info->exception_address == r14d_jle && IsReadableRange(info->exception_address, 2)) {
			const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
			if (code[0] == 0x0f && code[1] == 0x0b) {
				const int32_t  r14d       = static_cast<int32_t>(ctx->R14 & 0xFFFFFFFFULL);
				const uint64_t taken      = info->exception_address + (0x4664 - 0x4636);
				const uint64_t fall       = info->exception_address + 2;
				const uint64_t resume_rip = (r14d <= 0) ? taken : fall;
				const char*    label =
				    (r14d <= 0) ? "jle_taken_mount_skipped" : "jle_not_taken_mount_attempted";
				ctx->Rip = resume_rip;
				LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_SAFE_MODE_R14D_PROBE"
				     " site=0x%016" PRIx64 " r14d=%d resume_rip=0x%016" PRIx64
				     " %s NON_AUTHENTIC\n",
				     info->exception_address, r14d, resume_rip, label);
				Log::Flush();
				return true;
			}
		}
		if (info->exception_address == mount_result_jz &&
		    IsReadableRange(info->exception_address, 6)) {
			const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
			if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x00 && code[3] == 0x00 &&
			    code[4] == 0x00 && code[5] == 0x00) {
				const int32_t  eax        = static_cast<int32_t>(ctx->Rax & 0xFFFFFFFFULL);
				const uint64_t taken      = info->exception_address + (0x4EFC - 0x465E);
				const uint64_t fall       = info->exception_address + 6;
				const uint64_t resume_rip = (eax == 0) ? taken : fall;
				const char*    label =
				    (eax == 0) ? "jz_taken_mount_SUCCESS_normal_boot" : "jz_not_taken_mount_FAILED";
				ctx->Rip = resume_rip;
				LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_SAFE_MODE_MOUNT_RESULT_PROBE"
				     " site=0x%016" PRIx64 " nmount_eax=0x%x nmount_eax_signed=%d"
				     " dev=/dev/ssd0.update target=/update fstype=exfatfs"
				     " resume_rip=0x%016" PRIx64 " %s NON_AUTHENTIC\n",
				     info->exception_address, static_cast<unsigned>(eax), eax, resume_rip, label);
				Log::Flush();
				return true;
			}
		}
		if (info->exception_address == global_flag_jz &&
		    IsReadableRange(info->exception_address, 2)) {
			const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
			if (code[0] == 0x0f && code[1] == 0x0b) {
				const uint64_t global_addr =
				    g_mini_safe_mode_dword_4d7520_addr.load(std::memory_order_acquire);
				uint32_t global_val = 0xDEADBEEF;
				if (global_addr != 0 && IsReadableRange(global_addr, 4)) {
					std::memcpy(&global_val, reinterpret_cast<const void*>(global_addr),
					            sizeof(global_val));
				}
				const uint64_t taken      = info->exception_address + (0x46BE - 0x4680);
				const uint64_t fall       = info->exception_address + 2;
				const uint64_t resume_rip = (global_val == 0) ? taken : fall;
				const char*    label =
				    (global_val == 0) ? "jz_taken_rescue_decision" : "jz_not_taken_fsck_path";
				ctx->Rip = resume_rip;
				LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_SAFE_MODE_GLOBAL_FLAG_PROBE"
				     " site=0x%016" PRIx64 " dword_4D7520_host=0x%016" PRIx64
				     " dword_4D7520_val=0x%x fsck_mode_flag_meaning=%s"
				     " resume_rip=0x%016" PRIx64 " %s NON_AUTHENTIC\n",
				     info->exception_address, global_addr, global_val,
				     (global_val == 0) ? "rescue" : "fsck_salvage", resume_rip, label);
				Log::Flush();
				return true;
			}
		}
		if (info->exception_address == local_var_jz &&
		    IsReadableRange(info->exception_address, 6)) {
			const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
			if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x00 && code[3] == 0x00 &&
			    code[4] == 0x00 && code[5] == 0x00) {
				const uint64_t var_addr = ctx->Rbp - 0x30;
				uint32_t       var_val  = 0xDEADBEEF;
				if (IsReadableRange(var_addr, 4)) {
					std::memcpy(&var_val, reinterpret_cast<const void*>(var_addr), sizeof(var_val));
				}
				const uint64_t taken      = info->exception_address + (0x4755 - 0x46C2);
				const uint64_t fall       = info->exception_address + 6;
				const uint64_t resume_rip = (var_val == 0) ? taken : fall;
				const char*    label      = (var_val == 0) ? "jz_taken_RESCUE_entered"
				                                           : "jz_not_taken_standby_shutdown_path";
				ctx->Rip                  = resume_rip;
				LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_SAFE_MODE_LOCAL_VAR_PROBE"
				     " site=0x%016" PRIx64 " rbp=0x%016" PRIx64
				     " v788_main_on_standby=0x%x resume_rip=0x%016" PRIx64 " %s NON_AUTHENTIC\n",
				     info->exception_address, ctx->Rbp, var_val, resume_rip, label);
				Log::Flush();
				return true;
			}
		}
	}
	const uint64_t ssd0_open_jnz =
	    g_mini_safe_mode_ssd0_open_jnz_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address != 0 && info->exception_address == ssd0_open_jnz &&
	    IsReadableRange(info->exception_address, 6)) {
		auto*       ctx  = reinterpret_cast<CONTEXT*>(info->native_context);
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x90 && code[3] == 0x90 &&
		    code[4] == 0x90 && code[5] == 0x90) {
			const int32_t  eax        = static_cast<int32_t>(ctx->Rax & 0xFFFFFFFFULL);
			const uint64_t taken      = info->exception_address + 6 + 0x99;
			const uint64_t fall       = info->exception_address + 6;
			const uint64_t resume_rip = (eax != 0) ? taken : fall;
			const char*    label      = (eax != 0) ? "jnz_taken_ssd0_open_FAILED_bypass_mount_block"
			                                       : "jnz_not_taken_ssd0_open_OK_enter_mount_block";
			ctx->Rip                  = resume_rip;
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_SAFE_MODE_SSD0_OPEN_RESULT_PROBE"
			     " site=0x%016" PRIx64 " open_eax=0x%x open_eax_signed=%d"
			     " dev=/dev/ssd0 flags=0x207"
			     " resume_rip=0x%016" PRIx64 " %s NON_AUTHENTIC\n",
			     info->exception_address, static_cast<unsigned>(eax), eax, resume_rip, label);
			Log::Flush();
			return true;
		}
	}
	const uint64_t sub426550_ioctl_ret_jz =
	    g_mini_sub426550_ioctl_ret_jz_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address != 0 && info->exception_address == sub426550_ioctl_ret_jz &&
	    IsReadableRange(info->exception_address, 2)) {
		auto*       ctx  = reinterpret_cast<CONTEXT*>(info->native_context);
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b) {
			const int32_t  eax        = static_cast<int32_t>(ctx->Rax & 0xFFFFFFFFULL);
			const uint64_t taken      = info->exception_address + 2 + 0x27;
			const uint64_t fall       = info->exception_address + 2;
			const uint64_t resume_rip = (eax == 0) ? taken : fall;
			const char* label = (eax == 0) ? "jz_taken_ioctl_40086481_SUCCESS_skip_errno_path"
			                               : "jz_not_taken_ioctl_40086481_FAILED_enter_errno_path";
			ctx->Rip          = resume_rip;
			LOGF("NON_AUTHENTIC_PROBE_SUB426550_IOCTL_40086481_RET"
			     " site=0x%016" PRIx64 " eax=0x%x eax_signed=%d"
			     " resume_rip=0x%016" PRIx64 " %s NON_AUTHENTIC\n",
			     info->exception_address, static_cast<unsigned>(eax), eax, resume_rip, label);
			Log::Flush();
			return true;
		}
	}
	const uint64_t sub426550_errno_translated_jz =
	    g_mini_sub426550_errno_translated_jz_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address != 0 && info->exception_address == sub426550_errno_translated_jz &&
	    IsReadableRange(info->exception_address, 2)) {
		auto*       ctx  = reinterpret_cast<CONTEXT*>(info->native_context);
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b) {
			const int32_t  eax        = static_cast<int32_t>(ctx->Rax & 0xFFFFFFFFULL);
			const uint64_t taken      = info->exception_address + 2 + 0x17;
			const uint64_t fall       = info->exception_address + 2;
			const uint64_t resume_rip = (eax == 0) ? taken : fall;
			const char*    label = (eax == 0)
			                           ? "jz_taken_sub_470030_returned_zero_leak_fd_continue"
			                           : "jz_not_taken_errno_mapped_to_SCE_error_close_and_bail";
			ctx->Rip             = resume_rip;
			LOGF("NON_AUTHENTIC_PROBE_SUB426550_IOCTL_ERRNO_TRANSLATED"
			     " site=0x%016" PRIx64 " eax=0x%x eax_signed=%d"
			     " resume_rip=0x%016" PRIx64 " %s NON_AUTHENTIC\n",
			     info->exception_address, static_cast<unsigned>(eax), eax, resume_rip, label);
			Log::Flush();
			return true;
		}
	}
	const uint64_t sub426550_errno_sign_js =
	    g_mini_sub426550_errno_sign_js_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address != 0 && info->exception_address == sub426550_errno_sign_js &&
	    IsReadableRange(info->exception_address, 6)) {
		auto*       ctx  = reinterpret_cast<CONTEXT*>(info->native_context);
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x90 && code[3] == 0x90 &&
		    code[4] == 0x90 && code[5] == 0x90) {
			const int32_t  r12d       = static_cast<int32_t>(ctx->R12 & 0xFFFFFFFFULL);
			const int32_t  r14d       = static_cast<int32_t>(ctx->R14 & 0xFFFFFFFFULL);
			const uint64_t taken      = info->exception_address + 6 - 0x2BB;
			const uint64_t fall       = info->exception_address + 6;
			const uint64_t resume_rip = (r12d < 0) ? taken : fall;
			const char*    label      = (r12d < 0) ? "js_taken_bail_return_sce_error_via_epilogue"
			                                       : "js_not_taken_continue_to_open_ssd0";
			ctx->Rip                  = resume_rip;
			LOGF("NON_AUTHENTIC_PROBE_SUB426550_ERRNO_SIGN_JS"
			     " site=0x%016" PRIx64 " r12d=0x%x r12d_signed=%d r14d=0x%x r14d_signed=%d"
			     " resume_rip=0x%016" PRIx64 " %s NON_AUTHENTIC\n",
			     info->exception_address, static_cast<unsigned>(r12d), r12d,
			     static_cast<unsigned>(r14d), r14d, resume_rip, label);
			Log::Flush();
			return true;
		}
	}
	const uint64_t sub426550_open_ssd0_js =
	    g_mini_sub426550_open_ssd0_js_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address != 0 && info->exception_address == sub426550_open_ssd0_js &&
	    IsReadableRange(info->exception_address, 6)) {
		auto*       ctx  = reinterpret_cast<CONTEXT*>(info->native_context);
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x90 && code[3] == 0x90 &&
		    code[4] == 0x90 && code[5] == 0x90) {
			const int32_t  eax        = static_cast<int32_t>(ctx->Rax & 0xFFFFFFFFULL);
			const int32_t  r14d       = static_cast<int32_t>(ctx->R14 & 0xFFFFFFFFULL);
			const uint64_t taken      = info->exception_address + 6 + 0x85;
			const uint64_t fall       = info->exception_address + 6;
			const uint64_t resume_rip = (eax < 0) ? taken : fall;
			const char*    label = (eax < 0)
			                           ? "js_taken_open_dev_ssd0_FAILED_get_is_nand_log_and_bail"
			                           : "js_not_taken_open_dev_ssd0_OK_continue_to_ioctl_40043105";
			ctx->Rip             = resume_rip;
			LOGF("NON_AUTHENTIC_PROBE_SUB426550_OPEN_SSD0_JS"
			     " site=0x%016" PRIx64 " eax=0x%x eax_signed=%d r14d=0x%x r14d_signed=%d"
			     " resume_rip=0x%016" PRIx64 " %s NON_AUTHENTIC\n",
			     info->exception_address, static_cast<unsigned>(eax), eax,
			     static_cast<unsigned>(r14d), r14d, resume_rip, label);
			Log::Flush();
			return true;
		}
	}
	const uint64_t sub426550_case7_marker =
	    g_mini_sub426550_case7_marker_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address != 0 && info->exception_address == sub426550_case7_marker &&
	    IsReadableRange(info->exception_address, 5)) {
		auto*       ctx  = reinterpret_cast<CONTEXT*>(info->native_context);
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x90 && code[3] == 0x90 &&
		    code[4] == 0x90) {
			const uint32_t edx        = static_cast<uint32_t>(ctx->Rdx & 0xFFFFFFFFULL);
			const uint64_t rsi        = ctx->Rsi;
			const int32_t  r12d       = static_cast<int32_t>(ctx->R12 & 0xFFFFFFFFULL);
			const uint64_t resume_rip = info->exception_address - (0x26ba4 - 0x2659e);
			ctx->Rip                  = resume_rip;
			LOGF("NON_AUTHENTIC_PROBE_SUB426550_CASE7_MARKER"
			     " site=0x%016" PRIx64 " edx=0x%x rsi=0x%016" PRIx64 " r12d=0x%x r12d_signed=%d"
			     " resume_rip=0x%016" PRIx64
			     " marker_sub_428120_bypassed_jmp_epilogue NON_AUTHENTIC\n",
			     info->exception_address, edx, rsi, static_cast<unsigned>(r12d), r12d, resume_rip);
			Log::Flush();
			return true;
		}
	}
	const uint64_t sub426550_entry = g_mini_sub426550_entry_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address != 0 && info->exception_address == sub426550_entry &&
	    IsReadableRange(info->exception_address, 7)) {
		auto*       ctx  = reinterpret_cast<CONTEXT*>(info->native_context);
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x90 && code[3] == 0x90 &&
		    code[4] == 0x90 && code[5] == 0x90 && code[6] == 0x90) {
			const uint64_t a1       = ctx->Rdi;
			const uint32_t a2       = static_cast<uint32_t>(ctx->Rsi & 0xFFFFFFFFULL);
			uint64_t       ret_addr = 0;
			if (ctx->Rbp != 0 && IsReadableRange(ctx->Rbp + 8, 8)) {
				ret_addr = *reinterpret_cast<const uint64_t*>(ctx->Rbp + 8);
			}
			char path_buf[33] = {0};
			if (a1 != 0 && IsReadableRange(a1, 32)) {
				const char* src = reinterpret_cast<const char*>(a1);
				for (int i = 0; i < 32; ++i) {
					const char c = src[i];
					if (c == 0) break;
					path_buf[i] = (c >= 0x20 && c < 0x7F) ? c : '?';
				}
			}
			const uint64_t rsp_before = ctx->Rsp;
			ctx->Rsp -= 0x3E8;
			ctx->Rip = sub426550_entry + 7;
			LOGF("NON_AUTHENTIC_PROBE_SUB426550_ENTRY"
			     " site=0x%016" PRIx64 " a1=0x%016" PRIx64 " a2=0x%x"
			     " ret_addr=0x%016" PRIx64 " rbp=0x%016" PRIx64 " rsp_before=0x%016" PRIx64
			     " rsp_after=0x%016" PRIx64 " path=\"%s\" resume_rip=0x%016" PRIx64
			     " entered_sub_426550 NON_AUTHENTIC\n",
			     info->exception_address, a1, a2, ret_addr, ctx->Rbp, rsp_before, ctx->Rsp,
			     path_buf, ctx->Rip);
			Log::Flush();
			return true;
		}
	}
	const uint64_t sub428120_entry = g_mini_sub428120_entry_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address != 0 && info->exception_address == sub428120_entry &&
	    IsReadableRange(info->exception_address, 4)) {
		auto*       ctx  = reinterpret_cast<CONTEXT*>(info->native_context);
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x90 && code[3] == 0x90) {
			const int32_t  a1_fd    = static_cast<int32_t>(ctx->Rdi & 0xFFFFFFFFULL);
			const uint64_t a2       = ctx->Rsi;
			uint64_t       ret_addr = 0;
			if (ctx->Rbp != 0 && IsReadableRange(ctx->Rbp + 8, 8)) {
				ret_addr = *reinterpret_cast<const uint64_t*>(ctx->Rbp + 8);
			}
			const uint64_t rsp_before = ctx->Rsp;
			ctx->Rsp -= 0x10;
			ctx->Rip = sub428120_entry + 4;
			LOGF("NON_AUTHENTIC_PROBE_SUB428120_ENTRY"
			     " site=0x%016" PRIx64 " a1_fd=%d a2=0x%016" PRIx64 " ret_addr=0x%016" PRIx64
			     " rbp=0x%016" PRIx64 " rsp_before=0x%016" PRIx64 " rsp_after=0x%016" PRIx64
			     " resume_rip=0x%016" PRIx64 " entered_verify_partition_table_100 NON_AUTHENTIC\n",
			     info->exception_address, a1_fd, a2, ret_addr, ctx->Rbp, rsp_before, ctx->Rsp,
			     ctx->Rip);
			Log::Flush();
			return true;
		}
	}
	const uint64_t dw4d_a = g_mini_dword4d7520_store_a_site.load(std::memory_order_acquire);
	const uint64_t dw4d_b = g_mini_dword4d7520_store_b_site.load(std::memory_order_acquire);
	const uint64_t dw4d_c = g_mini_dword4d7520_store_c_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address != 0 &&
	    (info->exception_address == dw4d_a || info->exception_address == dw4d_b ||
	     info->exception_address == dw4d_c) &&
	    IsReadableRange(info->exception_address, 10)) {
		auto*       ctx  = reinterpret_cast<CONTEXT*>(info->native_context);
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x90 && code[3] == 0x90 &&
		    code[4] == 0x90 && code[5] == 0x90 && code[6] == 0x90 && code[7] == 0x90 &&
		    code[8] == 0x90 && code[9] == 0x90) {
			const uint64_t target = g_mini_dword4d7520_target_vaddr.load(std::memory_order_acquire);
			if (target != 0 && IsReadableRange(target, 4)) {
				*reinterpret_cast<volatile uint32_t*>(target) = 1u;
			}
			uint64_t ret_addr = 0;
			if (ctx->Rbp != 0 && IsReadableRange(ctx->Rbp + 8, 8)) {
				ret_addr = *reinterpret_cast<const uint64_t*>(ctx->Rbp + 8);
			}
			uint64_t stack_top = 0;
			if (ctx->Rsp != 0 && IsReadableRange(ctx->Rsp, 8)) {
				stack_top = *reinterpret_cast<const uint64_t*>(ctx->Rsp);
			}
			const char* site_label =
			    (info->exception_address == dw4d_a) ? "site_a_0x402387_in_sub_402347_jne_zero_tail"
				: (info->exception_address == dw4d_b)
			        ? "site_b_0x40248C_in_sub_402347_error_tail"
			        : "site_c_0x404AE6_in_sub_402D30_sysctl_2470000_returned_zero";
			ctx->Rip = info->exception_address + 10;
			LOGF("NON_AUTHENTIC_PROBE_MINI_DWORD4D7520_SET"
			     " site=0x%016" PRIx64 " target=0x%016" PRIx64 " rax=0x%016" PRIx64
			     " rbp=0x%016" PRIx64 " rsp=0x%016" PRIx64 " ret_addr_rbp8=0x%016" PRIx64
			     " stack_top=0x%016" PRIx64 " resume_rip=0x%016" PRIx64 " %s NON_AUTHENTIC\n",
			     info->exception_address, target, ctx->Rax, ctx->Rbp, ctx->Rsp, ret_addr, stack_top,
			     ctx->Rip, site_label);
			Log::Flush();
			return true;
		}
	}
	const uint64_t dw4d_hA = g_mini_dword4d7520_helper_a_site.load(std::memory_order_acquire);
	const uint64_t dw4d_hB = g_mini_dword4d7520_helper_b_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address != 0 &&
	    (info->exception_address == dw4d_hA || info->exception_address == dw4d_hB) &&
	    IsReadableRange(info->exception_address, 7)) {
		auto*       ctx  = reinterpret_cast<CONTEXT*>(info->native_context);
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x90 && code[3] == 0x90 &&
		    code[4] == 0x90 && code[5] == 0x90 && code[6] == 0x90) {
			const uint64_t r15 = ctx->R15;
			if (r15 != 0 && IsReadableRange(r15, 4)) {
				*reinterpret_cast<volatile uint32_t*>(r15) = 1u;
			}
			uint64_t ret_addr = 0;
			if (ctx->Rbp != 0 && IsReadableRange(ctx->Rbp + 8, 8)) {
				ret_addr = *reinterpret_cast<const uint64_t*>(ctx->Rbp + 8);
			}
			const char* site_label   = (info->exception_address == dw4d_hA)
			                               ? "helper_a_0x40a42F_in_sub_40a320_nmount_failed"
			                               : "helper_b_0x40a47D_in_sub_40a320_sub426190_not_one";
			const char* caller_label = "unknown_outer_caller";
			switch (ret_addr) {
				case 0x402896: caller_label = "outer_call_0x402891_sub_402347_mnt_mount"; break;
				case 0x4044c6:
					caller_label = "outer_call_0x4044c1_sub_404280_system_data_mount";
					break;
				case 0x40497d:
					caller_label = "outer_call_0x404978_sub_402D30_rescue_system_data_mount";
					break;
				case 0x40903e: caller_label = "outer_call_0x409039_sub_408f10_mnt_mount"; break;
			}
			ctx->Rip = info->exception_address + 7;
			LOGF("NON_AUTHENTIC_PROBE_MINI_DWORD4D7520_HELPER_SET"
			     " site=0x%016" PRIx64 " r15_target=0x%016" PRIx64 " r14_rdi_path=0x%016" PRIx64
			     " rbx_rsi_mount=0x%016" PRIx64 " r13d_saved_eax=0x%x rax=0x%016" PRIx64
			     " rbp=0x%016" PRIx64 " rsp=0x%016" PRIx64 " ret_addr_rbp8=0x%016" PRIx64
			     " resume_rip=0x%016" PRIx64 " %s %s NON_AUTHENTIC\n",
			     info->exception_address, r15, ctx->R14, ctx->Rbx,
			     static_cast<unsigned>(ctx->R13 & 0xFFFFFFFFULL), ctx->Rax, ctx->Rbp, ctx->Rsp,
			     ret_addr, ctx->Rip, site_label, caller_label);
			Log::Flush();
			return true;
		}
	}
	const uint64_t sub426190_entry = g_mini_sub426190_entry_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address != 0 && info->exception_address == sub426190_entry &&
	    IsReadableRange(info->exception_address, 4)) {
		auto*       ctx  = reinterpret_cast<CONTEXT*>(info->native_context);
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x90 && code[3] == 0x90) {
			char path_buf[72]  = {0};
			bool path_readable = false;
			if (ctx->Rdi != 0 && IsReadableRange(ctx->Rdi, 1)) {
				const char* src = reinterpret_cast<const char*>(ctx->Rdi);
				size_t      n   = 0;
				while (n < sizeof(path_buf) - 1 && IsReadableRange(ctx->Rdi + n, 1) &&
				       src[n] != '\0') {
					path_buf[n] = src[n];
					++n;
				}
				path_buf[n]   = '\0';
				path_readable = true;
			}
			const bool ssd0_match = path_readable && std::strncmp(path_buf, "/dev/ssd0", 9) == 0;
			uint64_t   ret_addr   = 0;
			if (ctx->Rsp != 0 && IsReadableRange(ctx->Rsp, 8)) {
				ret_addr = *reinterpret_cast<const uint64_t*>(ctx->Rsp);
			}
			const char* action_label = nullptr;
			if (ssd0_match && ret_addr != 0) {
				ctx->Rax = 1;
				ctx->Rip = ret_addr;
				ctx->Rsp += 8;
				action_label = "shortcircuit_eax_1_passthrough_ok";
			} else {
				ctx->Rsp -= 8;
				if (IsReadableRange(ctx->Rsp, 8)) {
					*reinterpret_cast<uint64_t*>(ctx->Rsp) = ctx->Rbp;
				}
				ctx->Rbp = ctx->Rsp;
				ctx->Rip = info->exception_address + 4;
				action_label =
				    ssd0_match ? "fallthrough_ret_addr_unreadable" : "fallthrough_non_ssd0_path";
			}
			LOGF("NON_AUTHENTIC_PROBE_MINI_SUB426190_ENTRY"
			     " site=0x%016" PRIx64 " rdi=0x%016" PRIx64 " path=\"%s\""
			     " ret_addr_rsp0=0x%016" PRIx64 " rsp_before=0x%016" PRIx64 " rax=0x%016" PRIx64
			     " resume_rip=0x%016" PRIx64 " %s NON_AUTHENTIC\n",
			     info->exception_address, ctx->Rdi, path_buf, ret_addr,
			     ssd0_match ? ctx->Rsp - 8 : ctx->Rsp + 8, ctx->Rax, ctx->Rip, action_label);
			Log::Flush();
			return true;
		}
	}
	const uint64_t sub471250_entry = g_mini_sub471250_entry_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address != 0 && info->exception_address == sub471250_entry &&
	    IsReadableRange(info->exception_address, 4)) {
		auto*       ctx  = reinterpret_cast<CONTEXT*>(info->native_context);
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x90 && code[3] == 0x90) {
			uint64_t ret_addr = 0;
			if (ctx->Rsp != 0 && IsReadableRange(ctx->Rsp, 8)) {
				ret_addr = *reinterpret_cast<const uint64_t*>(ctx->Rsp);
			}
			const uint64_t out_ptr = ctx->Rdi;
			const uint32_t v788    = g_mini_sub471250_v788_value.load(std::memory_order_acquire);
			bool           wrote   = false;
			if (out_ptr != 0 && IsReadableRange(out_ptr, 4)) {
				*reinterpret_cast<uint32_t*>(out_ptr) = v788;
				wrote                                 = true;
			}
			const char* action_label = nullptr;
			if (wrote && ret_addr != 0) {
				ctx->Rax = 0;
				ctx->Rip = ret_addr;
				ctx->Rsp += 8;
				action_label = (v788 == 0u) ? "shortcircuit_v788_0_coldboot_ok"
				                            : "shortcircuit_v788_1_passthrough_ok";
			} else {
				ctx->Rsp -= 8;
				if (IsReadableRange(ctx->Rsp, 8)) {
					*reinterpret_cast<uint64_t*>(ctx->Rsp) = ctx->Rbp;
				}
				ctx->Rbp = ctx->Rsp;
				ctx->Rip = info->exception_address + 4;
				action_label =
				    wrote ? "fallthrough_ret_addr_unreadable" : "fallthrough_out_ptr_unwritable";
			}
			LOGF("NON_AUTHENTIC_PROBE_MINI_SUB471250_ENTRY"
			     " site=0x%016" PRIx64 " rdi_out=0x%016" PRIx64 " wrote_v788=%u"
			     " ret_addr_rsp0=0x%016" PRIx64 " rax=0x%016" PRIx64 " resume_rip=0x%016" PRIx64
			     " %s NON_AUTHENTIC\n",
			     info->exception_address, out_ptr, wrote ? v788 : 0u, ret_addr, ctx->Rax, ctx->Rip,
			     action_label);
			Log::Flush();
			return true;
		}
	}
	const uint64_t sub419930_entry = g_mini_sub419930_entry_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address != 0 && info->exception_address == sub419930_entry &&
	    IsReadableRange(info->exception_address, 4)) {
		auto*       ctx  = reinterpret_cast<CONTEXT*>(info->native_context);
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x90 && code[3] == 0x90) {
			uint64_t ret_addr = 0;
			if (ctx->Rsp != 0 && IsReadableRange(ctx->Rsp, 8)) {
				ret_addr = *reinterpret_cast<const uint64_t*>(ctx->Rsp);
			}
			const char* action_label = nullptr;
			if (ret_addr != 0) {
				ctx->Rax = 1;
				ctx->Rip = ret_addr;
				ctx->Rsp += 8;
				action_label = "shortcircuit_bfs_preflight_mountable_ok";
			} else {
				ctx->Rsp -= 8;
				if (IsReadableRange(ctx->Rsp, 8)) {
					*reinterpret_cast<uint64_t*>(ctx->Rsp) = ctx->Rbp;
				}
				ctx->Rbp     = ctx->Rsp;
				ctx->Rip     = info->exception_address + 4;
				action_label = "fallthrough_ret_addr_unreadable";
			}
			LOGF("NON_AUTHENTIC_PROBE_MINI_SUB419930_ENTRY"
			     " site=0x%016" PRIx64 " rdi=0x%016" PRIx64 " rsi=0x%016" PRIx64
			     " rdx=0x%016" PRIx64 " ret_addr_rsp0=0x%016" PRIx64 " rax=0x%016" PRIx64
			     " resume_rip=0x%016" PRIx64 " %s NON_AUTHENTIC\n",
			     info->exception_address, ctx->Rdi, ctx->Rsi, ctx->Rdx, ret_addr, ctx->Rax,
			     ctx->Rip, action_label);
			Log::Flush();
			return true;
		}
	}
	const uint64_t sys_mount_jnz =
	    g_mini_safe_mode_system_mount_jnz_site.load(std::memory_order_acquire);
	const uint64_t sys_ex_mount_jz =
	    g_mini_safe_mode_system_ex_mount_jz_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address != 0 &&
	    (info->exception_address == sys_mount_jnz || info->exception_address == sys_ex_mount_jz)) {
		auto* ctx = reinterpret_cast<CONTEXT*>(info->native_context);
		if (info->exception_address == sys_mount_jnz &&
		    IsReadableRange(info->exception_address, 2)) {
			const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
			if (code[0] == 0x0f && code[1] == 0x0b) {
				const int32_t  eax        = static_cast<int32_t>(ctx->Rax & 0xFFFFFFFFULL);
				const uint64_t taken      = info->exception_address + 2 + 0x3a;
				const uint64_t fall       = info->exception_address + 2;
				const uint64_t resume_rip = (eax != 0) ? taken : fall;
				const char*    label      = (eax != 0) ? "jnz_taken_system_mount_FAILED"
				                                       : "jnz_not_taken_system_mount_SUCCESS";
				ctx->Rip                  = resume_rip;
				LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_SAFE_MODE_SYSTEM_MOUNT_RESULT_PROBE"
				     " site=0x%016" PRIx64 " nmount_eax=0x%x nmount_eax_signed=%d"
				     " dev=/dev/ssd0.system target=/system fstype=exfatfs"
				     " resume_rip=0x%016" PRIx64 " %s NON_AUTHENTIC\n",
				     info->exception_address, static_cast<unsigned>(eax), eax, resume_rip, label);
				Log::Flush();
				return true;
			}
		}
		if (info->exception_address == sys_ex_mount_jz &&
		    IsReadableRange(info->exception_address, 6)) {
			const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
			if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x00 && code[3] == 0x00 &&
			    code[4] == 0x00 && code[5] == 0x00) {
				const int32_t  eax        = static_cast<int32_t>(ctx->Rax & 0xFFFFFFFFULL);
				const uint64_t taken      = info->exception_address + 6 + 0x3fc;
				const uint64_t fall       = info->exception_address + 6;
				const uint64_t resume_rip = (eax == 0) ? taken : fall;
				const char*    label = (eax == 0) ? "jz_taken_system_ex_mount_SUCCESS_normal_boot"
				                                  : "jz_not_taken_system_ex_mount_FAILED";
				ctx->Rip             = resume_rip;
				LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_SAFE_MODE_SYSTEM_EX_MOUNT_RESULT_PROBE"
				     " site=0x%016" PRIx64 " nmount_eax=0x%x nmount_eax_signed=%d"
				     " dev=/dev/ssd0.system_ex target=/system_ex fstype=exfatfs"
				     " resume_rip=0x%016" PRIx64 " %s NON_AUTHENTIC\n",
				     info->exception_address, static_cast<unsigned>(eax), eax, resume_rip, label);
				Log::Flush();
				return true;
			}
		}
	}
	const uint64_t sub402340_ssd0_user_jnz =
	    g_mini_safe_mode_sub402340_ssd0_user_jnz_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address != 0 && info->exception_address == sub402340_ssd0_user_jnz &&
	    IsReadableRange(info->exception_address, 2)) {
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b) {
			auto*          ctx               = reinterpret_cast<CONTEXT*>(info->native_context);
			const int32_t  eax               = static_cast<int32_t>(ctx->Rax & 0xFFFFFFFFULL);
			const uint64_t dword_4d7520_host = info->exception_address - 0x4ca6 + 0xd7520;
			uint32_t       dword_4d7520_val  = 0xffffffffu;
			if (IsReadableRange(dword_4d7520_host, 4)) {
				dword_4d7520_val = *reinterpret_cast<const uint32_t*>(dword_4d7520_host);
			}
			const uint64_t taken      = info->exception_address + 2 + 0x24;
			const uint64_t fall       = info->exception_address + 2;
			const uint64_t resume_rip = (eax != 0) ? taken : fall;
			const char*    label      = (eax != 0) ? "jnz_taken_sub402340_ssd0_user_FAILED"
			                                       : "jnz_not_taken_sub402340_ssd0_user_SUCCESS";
			ctx->Rip                  = resume_rip;
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_SAFE_MODE_SUB402340_SSD0_USER_RESULT_PROBE"
			     " site=0x%016" PRIx64 " sub402340_eax=0x%x sub402340_eax_signed=%d"
			     " dword_4D7520_host=0x%016" PRIx64 " dword_4D7520_val=0x%x"
			     " dev=ssd0.user target=/user fstype=bfs"
			     " resume_rip=0x%016" PRIx64 " %s NON_AUTHENTIC\n",
			     info->exception_address, static_cast<unsigned>(eax), eax, dword_4d7520_host,
			     dword_4d7520_val, resume_rip, label);
			Log::Flush();
			return true;
		}
	}
	const uint64_t cold_boot_progress_site =
	    g_mini_cold_boot_progress_site.load(std::memory_order_acquire);
	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address != 0 && info->exception_address == cold_boot_progress_site &&
	    IsReadableRange(info->exception_address, 5)) {
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x90 && code[3] == 0x90 &&
		    code[4] == 0x90) {
			auto* ctx = reinterpret_cast<CONTEXT*>(info->native_context);
			ctx->Rdi  = 1;
			ctx->Rip  = info->exception_address + 5;
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_COLD_BOOT_PROGRESS_HIT"
			     " site=0x%016" PRIx64 " rdi=1 mov_edi_simulated"
			     " guest_rip_advanced=5 NON_AUTHENTIC\n",
			     info->exception_address);
			Log::Flush();
			return true;
		}
	}
	if (g_mini_native_syscall_traps_installed.load(std::memory_order_acquire) &&
	    info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    !(info->rax == 0xfb && info->exception_address == 0x468a33 &&
	      std::getenv("KYTY_DIAGNOSTIC_MINI_SYSCORE_LIVE_RFORK") != nullptr) &&
	    info->exception_address >= 0x400000 && info->exception_address < 0x510000 &&
	    std::binary_search(g_mini_native_syscall_offsets.begin(),
	                       g_mini_native_syscall_offsets.end(),
	                       static_cast<uint32_t>(info->exception_address - 0x400000)) &&
	    IsReadableRange(info->exception_address, 2)) {
		const auto* bytes = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (bytes[0] == 0x0f && bytes[1] == 0x0b) {
			const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
			    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
			if (std::getenv("KYTY_DIAGNOSTIC_MINI_SYSCORE_LIVE_RFORK") != nullptr &&
			    Libs::LibKernel::Process::IsTrackedRforkChild(Libs::LibKernel::Process::GetPid())) {
				static thread_local uint32_t child_syscalls = 0;
				if (child_syscalls++ < 32) {
					LOGF("MINI_RFORK_CHILD_SYSCALL pid=%d nr=0x%llx args=%llx,%llx,%llx,%llx "
					     "result=%llx errno=%d\n",
					     Libs::LibKernel::Process::GetPid(),
					     static_cast<unsigned long long>(info->rax),
					     static_cast<unsigned long long>(info->rdi),
					     static_cast<unsigned long long>(info->rsi),
					     static_cast<unsigned long long>(info->rdx),
					     static_cast<unsigned long long>(info->r10),
					     static_cast<unsigned long long>(reply.value), reply.posix_errno);
				}
			}
			if (info->rax == 0x37) {
				auto*    context  = reinterpret_cast<CONTEXT*>(info->native_context);
				uint64_t stack[4] = {0, 0, 0, 0};
				for (int i = 0; i < 4; ++i) {
					const uint64_t slot = context->Rsp + static_cast<uint64_t>(i) * 8;
					if (IsReadableRange(slot, sizeof(uint64_t))) {
						std::memcpy(&stack[i], reinterpret_cast<const void*>(slot),
						            sizeof(uint64_t));
					}
				}
				const uint64_t options   = info->rdi;
				uint32_t       kind      = 3;
				uint32_t       exit_code = 1;
				Libs::LibKernel::Process::ClassifyMiniSyscoreRebootOptions(options, &kind,
				                                                           &exit_code);
				LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_REBOOT_SITE pid=%d options=0x%016" PRIx64
				     " rsp=0x%016" PRIx64 " ret=0x%016" PRIx64 " stack=0x%016" PRIx64
				     ",0x%016" PRIx64 ",0x%016" PRIx64 " updatemode_test_bytes=%02x%02x"
				     " reboot_syscall_return_address_identifies_call_site\n",
				     Libs::LibKernel::Process::GetPid(), options,
				     static_cast<uint64_t>(context->Rsp), stack[0], stack[1], stack[2], stack[3],
				     *reinterpret_cast<const uint8_t*>(0x405036),
				     *reinterpret_cast<const uint8_t*>(0x405037));
				LOGF("MINI_SYSCORE_REBOOT_CLASSIFY pid=%d options=0x%016" PRIx64
				     " kind=%u exit_code=%u is_exec_child=%u site=overlay\n",
				     Libs::LibKernel::Process::GetPid(), options, kind, exit_code,
				     Libs::LibKernel::Process::IsExecChild() ? 1u : 0u);
				Log::Flush();
				if (std::getenv("KYTY_DIAGNOSTIC_REBOOT_SESSION_EXIT") != nullptr) {
					LOGF("MINI_SYSCORE_REBOOT_SESSION_BOUNDARY options=0x%016" PRIx64
					     " kind=%u exit_code=%u noreturn"
					     " overlay_already_flushed=1 NON_AUTHENTIC=1\n",
					     options, kind, exit_code);
					Log::Flush();
					if (Libs::LibKernel::Process::IsExecChild()) {
						Libs::LibKernel::Process::RecordExecChildExitStatus(exit_code << 8);
						Libs::LibKernel::Process::RecordExecChildRebootOptions(options, kind,
						                                                       exit_code);
					}
					std::fflush(nullptr);
					std::quick_exit(static_cast<int>(exit_code));
				}
			}
			if (info->rax == 0xbc || info->rax == 0x144 || info->rax == 0x36 || info->rax == 0x05) {
				static std::atomic<uint32_t> dependency_probe_count {0};
				if (dependency_probe_count.fetch_add(1) < 36) {
					LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_NATIVE_DEPENDENCY_ARGS"
					     " site=0x%016" PRIx64 " nr=0x%016" PRIx64 " args=0x%016" PRIx64
					     ",0x%016" PRIx64 ",0x%016" PRIx64 ",0x%016" PRIx64 " result=0x%016" PRIx64
					     " posix_errno=%d\n",
					     info->exception_address, info->rax, info->rdi, info->rsi, info->rdx,
					     info->r10, static_cast<uint64_t>(reply.value), reply.posix_errno);
				}
			}
			const bool kernel_error = reply.posix_errno == 0 &&
			                          reply.value > Libs::LibKernel::KERNEL_ERROR_UNKNOWN &&
			                          reply.value <= Libs::LibKernel::KERNEL_ERROR_UNKNOWN + 101;
			const int  guest_errno =
			    kernel_error ? Libs::LibKernel::KernelToPosix(static_cast<int>(reply.value))
				             : reply.posix_errno;
			const bool failure = (reply.value == -1 && guest_errno > 0) || kernel_error;
			if ((reply.value >= 0 && guest_errno == 0) || failure) {
				auto* context   = reinterpret_cast<CONTEXT*>(info->native_context);
				context->Rax    = failure ? static_cast<uint64_t>(guest_errno)
				                          : static_cast<uint64_t>(reply.value);
				context->EFlags = (context->EFlags & ~uint32_t {1}) | (failure ? 1u : 0u);
				context->Rip += 2;
				if (info->rax == 0x07 && failure && guest_errno == Libs::Posix::POSIX_ECHILD &&
				    std::getenv("KYTY_DIAGNOSTIC_SYSCORE_SIGPROCMASK_LOOP_TRACE") != nullptr) {
					static std::atomic<bool> wait7_echild_return_logged {false};
					if (!wait7_echild_return_logged.exchange(true, std::memory_order_relaxed)) {
						LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_WAIT7_ECHILD_RETURN"
						     " parent_pid=%d requested_pid=%d options=0x%x"
						     " status_ptr=0x%016" PRIx64 " rax=%" PRIu64 " cf=%u"
						     " rip_before=0x%016" PRIx64 " rip_after=0x%016" PRIx64 "\n",
						     Libs::LibKernel::Process::GetPid(), static_cast<int32_t>(info->rdi),
						     static_cast<uint32_t>(info->rdx), info->rsi, context->Rax,
						     static_cast<unsigned>(context->EFlags & 1), info->exception_address,
						     context->Rip);
						Log::Flush();
					}
				}
				static std::atomic<uint32_t> native_probe_count {0};
				if (native_probe_count.fetch_add(1) < 64) {
					LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_NATIVE_SYSCALL"
					     " site=0x%016" PRIx64 " nr=0x%016" PRIx64 " result=0x%016" PRIx64
					     " errno=%d cf=%u\n",
					     info->exception_address, info->rax, context->Rax, guest_errno,
					     static_cast<unsigned>(context->EFlags & 1));
				}
				return true;
			}
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_NATIVE_REPLY_UNHANDLED"
			     " value=0x%016" PRIx64 " posix_errno=%d\n",
			     static_cast<uint64_t>(reply.value), reply.posix_errno);
		}
		LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_NATIVE_SYSCALL_UNHANDLED"
		     " site=0x%016" PRIx64 " nr=0x%016" PRIx64 " args=%016" PRIx64 ",%016" PRIx64
		     ",%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64 " fault_preserved\n",
		     info->exception_address, info->rax, info->rdi, info->rsi, info->rdx, info->r10,
		     info->r8, info->r9);
		Log::Flush();
		return false;
	}

	const uint64_t agc_native_kevent =
	    g_agc_native_kevent_syscall_site.load(std::memory_order_acquire);
	if (agc_native_kevent != 0 &&
	    std::getenv("KYTY_DIAGNOSTIC_AGC_NATIVE_KEVENT_AUDIT") != nullptr &&
	    info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address == agc_native_kevent && info->rax == 0x16b &&
	    IsReadableRange(agc_native_kevent, 2)) {
		const auto* opcode = reinterpret_cast<const uint8_t*>(agc_native_kevent);
		if (opcode[0] == 0x0f && opcode[1] == 0x0b) {
			Libs::LibKernel::EventQueue::KernelEvent entry {};
			const bool valid = info->rsi != 0 && info->rsi <= UINT64_MAX - sizeof(entry) &&
			                   IsReadableRange(info->rsi, sizeof(entry));
			if (valid) {
				std::memcpy(&entry, reinterpret_cast<const void*>(info->rsi), sizeof(entry));
			}
			const auto result = Libs::NativeKernelBridge::DispatchSyscall(
			    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
			const bool kernel_enosys =
			    result.value == Libs::LibKernel::KERNEL_ERROR_ENOSYS && result.posix_errno == 0;
			const int  err = kernel_enosys
			                     ? Libs::LibKernel::KernelToPosix(static_cast<int>(result.value))
			                     : result.posix_errno;
			const bool failure = kernel_enosys || (result.value == -1 && err > 0);
			if ((result.value >= 0 && err == 0) || failure) {
				auto* ctx = reinterpret_cast<CONTEXT*>(info->native_context);
				ctx->Rax =
				    failure ? static_cast<uint64_t>(err) : static_cast<uint64_t>(result.value);
				ctx->EFlags = (ctx->EFlags & ~uint32_t {1}) | (failure ? 1u : 0u);
				ctx->Rip += 2;
				static std::atomic_uint32_t observed {0};
				if (observed.fetch_add(1) < 24) {
					LOGF("AGC_NATIVE_KEVENT_AUDIT"
					     " fd=%" PRIu64 " change_ptr=%016" PRIx64 " nchanges=%" PRIu64
					     " event_ptr=%016" PRIx64 " nevents=%" PRIu64 " timeout=%016" PRIx64
					     " change_readable=%d ident=%" PRIuPTR
					     " filter=%d flags=0x%04x fflags=0x%08x"
					     " data=%" PRIdPTR " udata=%016" PRIx64 " backend_result=%" PRId64
					     " errno=%d cf=%u\n",
					     info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9, valid,
					     entry.ident, entry.filter, entry.flags, entry.fflags, entry.data,
					     reinterpret_cast<uint64_t>(entry.udata), result.value, err,
					     failure ? 1u : 0u);
				}
				return true;
			}
		}
	}
	const uint64_t rdup_native_site =
	    g_syscore_native_rdup_syscall_site.load(std::memory_order_acquire);
	if (rdup_native_site != 0 &&
	    std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD") != nullptr &&
	    info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address == rdup_native_site && info->rax == 0x25b &&
	    IsReadableRange(rdup_native_site, 2)) {
		const auto* bytes = reinterpret_cast<const uint8_t*>(rdup_native_site);
		if (bytes[0] == 0x0f && bytes[1] == 0x0b) {
			const auto answer = Libs::NativeKernelBridge::DispatchSyscall(
			    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
			const bool kernel_enosys =
			    answer.value == Libs::LibKernel::KERNEL_ERROR_ENOSYS && answer.posix_errno == 0;
			const int  err    = kernel_enosys
			                        ? Libs::LibKernel::KernelToPosix(static_cast<int>(answer.value))
			                        : answer.posix_errno;
			const bool failed = kernel_enosys || (answer.value == -1 && err != 0);
			if ((answer.value >= 0 && err == 0) || failed) {
				auto* ctx = reinterpret_cast<CONTEXT*>(info->native_context);
				ctx->Rax =
				    failed ? static_cast<uint64_t>(err) : static_cast<uint64_t>(answer.value);
				ctx->EFlags = (ctx->EFlags & ~uint32_t {1}) | (failed ? 1u : 0u);
				ctx->Rip += 2;
				static std::atomic_uint32_t observed {0};
				if (observed.fetch_add(1) < 20) {
					LOGF("SYSCORE_NATIVE_RDUP"
					     " guest_pid=%d parent_pid=%" PRIu64 " parent_fd=%" PRIu64
					     " result_fd=%" PRId64 " errno=%d cf=%u"
					     " native_syscall=0x25b\n",
					     Libs::LibKernel::Process::GetPid(), info->rdi, info->rsi, answer.value,
					     err, failed ? 1u : 0u);
				}
				return true;
			}
		}
	}
	const uint64_t kqueue_test =
	    g_syscore_native_kqueue_result_site.load(std::memory_order_acquire);
	if (kqueue_test != 0 && std::getenv("KYTY_DIAGNOSTIC_SYSCORE_KQUEUE_RESULT_AUDIT") != nullptr &&
	    info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address == kqueue_test && IsReadableRange(kqueue_test, 2)) {
		const auto* code = reinterpret_cast<const uint8_t*>(kqueue_test);
		if (code[0] == 0x0f && code[1] == 0x0b) {
			const uint32_t value       = static_cast<uint32_t>(info->rax);
			uint32_t       parity_bits = 0;
			for (uint32_t bit = 0; bit < 8; ++bit) {
				parity_bits += (value >> bit) & 1u;
			}
			auto*              ctx      = reinterpret_cast<CONTEXT*>(info->native_context);
			constexpr uint32_t tested   = 0x1u | 0x4u | 0x40u | 0x80u | 0x800u;
			const uint32_t     nz_flags = ((parity_bits & 1u) == 0 ? 0x4u : 0u) |
			                              (value == 0 ? 0x40u : 0u) |
			                              ((value & 0x80000000u) != 0 ? 0x80u : 0u);
			ctx->EFlags                 = (ctx->EFlags & ~tested) | nz_flags;
			ctx->Rip += 2;
			static std::atomic<uint32_t> observed {0};
			if (observed.fetch_add(1) < 16) {
				LOGF("SYSCORE_KQUEUE_RETURN"
				     " caller_site=%016" PRIx64 " eax=0x%08x signed=%d"
				     " emulated_test_eax_eax\n",
				     kqueue_test, value, static_cast<int32_t>(value));
			}
			return true;
		}
	}
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_CHILD_FAILURE_EDGES") != nullptr &&
	    info->type == Common::HostException::ExceptionType::IllegalInstruction) {
		for (uint32_t index = 0; index < g_syscore_native_child_failure_sites.size(); ++index) {
			const uint64_t site =
			    g_syscore_native_child_failure_sites[index].load(std::memory_order_acquire);
			if (site == 0 || info->exception_address != site || !IsReadableRange(site, 2)) {
				continue;
			}
			const auto* op = reinterpret_cast<const uint8_t*>(site);
			if (op[0] != 0x0f || op[1] != 0x0b) {
				continue;
			}
			const uint32_t result = static_cast<uint32_t>(info->rax);
			uint32_t       parity = 0;
			for (uint32_t i = 0; i < 8; ++i) {
				parity += (result >> i) & 1u;
			}
			auto*              ctx     = reinterpret_cast<CONTEXT*>(info->native_context);
			constexpr uint32_t changed = 0x1u | 0x4u | 0x40u | 0x80u | 0x800u;
			const uint32_t status = ((parity & 1u) == 0 ? 0x4u : 0u) | (result == 0 ? 0x40u : 0u) |
			                        ((result & 0x80000000u) != 0 ? 0x80u : 0u);
			ctx->EFlags           = (ctx->EFlags & ~changed) | status;
			ctx->Rip += 2;
			uint64_t pathptr = 0;
			uint64_t rootptr = 0;
			uint64_t fd      = UINT64_MAX;
			if (IsReadableRange(info->rbx, 0x38)) {
				const auto* descriptor = reinterpret_cast<const uint64_t*>(info->rbx);
				pathptr                = descriptor[1];
				rootptr                = descriptor[3];
				fd                     = descriptor[6];
			}
			LOGF("SYSCORE_CHILD_FAILURE_EDGE"
			     " site=%016" PRIx64 " index=%u child_guest_pid=%d"
			     " returned_eax=0x%08x signed=%d"
			     " child_descriptor=%016" PRIx64 " path_ptr=%016" PRIx64 " root_ptr=%016" PRIx64
			     " descriptor_fd_field=%016" PRIx64 " test_eax_eax_resumed\n",
			     site, index, Libs::LibKernel::Process::GetPid(), result,
			     static_cast<int32_t>(result), info->rbx, pathptr, rootptr, fd);
			if (index == 3 && IsReadableRange(info->rbx, 0x40)) {
				const auto* description  = reinterpret_cast<const uint8_t*>(info->rbx);
				uint64_t    source_array = 0;
				int32_t     source_fd    = -1;
				int32_t     source_count = 0;
				std::memcpy(&source_array, description + 0x20, sizeof(source_array));
				std::memcpy(&source_fd, description + 0x28, sizeof(source_fd));
				std::memcpy(&source_count, description + 0x38, sizeof(source_count));
				int32_t    originals[3] {-1, -1, -1};
				const bool readable =
				    source_array != 0 && IsReadableRange(source_array, sizeof(originals));
				if (readable) {
					std::memcpy(originals, reinterpret_cast<const void*>(source_array),
					            sizeof(originals));
				}
				LOGF("SYSCORE_CHILD_DESCRIPTOR_DUPLICATION"
				     " child_pid=%d source_array=%016" PRIx64
				     " source_fd=%d source_count=%d array_readable=%d"
				     " source_fds=%d,%d,%d"
				     "\n",
				     Libs::LibKernel::Process::GetPid(), source_array, source_fd, source_count,
				     readable, originals[0], originals[1], originals[2]);
			}
			return true;
		}
	}
	const uint64_t child_setup_site =
	    g_syscore_native_child_setup_result_site.load(std::memory_order_acquire);
	if (child_setup_site != 0 &&
	    std::getenv("KYTY_DIAGNOSTIC_SYSCORE_RFORK_CHILD_SETUP_AUDIT") != nullptr &&
	    info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address == child_setup_site && IsReadableRange(child_setup_site, 2)) {
		const auto* op = reinterpret_cast<const uint8_t*>(child_setup_site);
		if (op[0] == 0x0f && op[1] == 0x0b) {
			uint64_t saved_fd = UINT64_MAX;
			if (info->rbp >= 0x14 && IsReadableRange(info->rbp - 0x14, sizeof(uint32_t))) {
				const uint32_t value = *reinterpret_cast<const uint32_t*>(info->rbp - 0x14);
				saved_fd             = value;
			}
			const uint32_t result = static_cast<uint32_t>(info->rax);
			uint32_t       parity = 0;
			for (uint32_t i = 0; i < 8; ++i) {
				parity += (result >> i) & 1u;
			}
			auto*              ctx      = reinterpret_cast<CONTEXT*>(info->native_context);
			constexpr uint32_t affected = 0x1u | 0x4u | 0x40u | 0x80u | 0x800u;
			const uint32_t flags = ((parity & 1u) == 0 ? 0x4u : 0u) | (result == 0 ? 0x40u : 0u) |
			                       ((result & 0x80000000u) != 0 ? 0x80u : 0u);
			ctx->EFlags          = (ctx->EFlags & ~affected) | flags;
			ctx->Rip += 2;
			static std::atomic_uint32_t observed {0};
			if (observed.fetch_add(1) < 16) {
				LOGF("SYSCORE_CHILD_SETUP_SERVICE_RESULT"
				     " child_guest_pid=%d site=%016" PRIx64
				     " guest_eax=%08x signed=%d saved_fd=%016" PRIx64 " test_eax_eax_resumed\n",
				     Libs::LibKernel::Process::GetPid(), child_setup_site, result,
				     static_cast<int32_t>(result), saved_fd);
			}
			return true;
		}
	}
	const uint64_t guest_rfork_entry =
	    g_syscore_native_rfork_child_entry_site.load(std::memory_order_acquire);
	if (guest_rfork_entry != 0 &&
	    std::getenv("KYTY_DIAGNOSTIC_SYSCORE_RFORK_GUEST_ENTRY_AUDIT") != nullptr &&
	    info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address == guest_rfork_entry && IsReadableRange(guest_rfork_entry, 3)) {
		const auto* code = reinterpret_cast<const uint8_t*>(guest_rfork_entry);
		if (code[0] == 0x0f && code[1] == 0x0b && code[2] == 0x90) {
			const int actual_pid = Libs::LibKernel::Process::GetPid();
			LOGF("SYSCORE_RFORK_GUEST_ENTRY_CONFIRMED"
			     " guest_pid=%d pc=%016" PRIx64 " rsp=%016" PRIx64 " arg=%016" PRIx64
			     " push_rbp_executed=1"
			     " mov_rbp_rsp_resumed=1\n",
			     actual_pid, guest_rfork_entry - 1, info->rsp, info->rdi);
			auto* ctx = reinterpret_cast<CONTEXT*>(info->native_context);
			ctx->Rbp  = info->rsp;
			ctx->Rip += 3;
			return true;
		}
	}
	const uint64_t syscore_launch_entry =
	    g_syscore_native_launch_entry_site.load(std::memory_order_acquire);
	if (syscore_launch_entry != 0 &&
	    std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LAUNCH_ENTRY_AUDIT") != nullptr &&
	    info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address == syscore_launch_entry &&
	    IsReadableRange(syscore_launch_entry, 3)) {
		const auto* op = reinterpret_cast<const uint8_t*>(syscore_launch_entry);
		if (op[0] == 0x0f && op[1] == 0x0b && op[2] == 0x90) {
			uint64_t ret = 0;
			if (info->rsp <= UINT64_MAX - 16 && IsReadableRange(info->rsp + 8, sizeof(ret))) {
				std::memcpy(&ret, reinterpret_cast<const void*>(info->rsp + 8), sizeof(ret));
			}
			static std::atomic<uint32_t> launch_entry_calls {0};
			const auto                   nth = launch_entry_calls.fetch_add(1);
			if (nth < 12) {
				LOGF("SYSCORE_LOWER_LAUNCH_ENTRY"
				     " call=%u return=%016" PRIx64 " rdi=%016" PRIx64 " rsi=%016" PRIx64
				     " rdx=%016" PRIx64 " rcx=%016" PRIx64 " r8=%016" PRIx64 " r9=%016" PRIx64
				     " guest_stack=%016" PRIx64 " mov_rbp_rsp_resumed\n",
				     nth, ret, info->rdi, info->rsi, info->rdx, info->rcx, info->r8, info->r9,
				     info->rsp);
			}
			auto* ctx = reinterpret_cast<CONTEXT*>(info->native_context);
			ctx->Rbp  = info->rsp;
			ctx->Rip += 3;
			return true;
		}
	}
	const uint64_t original_vfprintf_site =
	    g_syscore_original_vfprintf_probe.load(std::memory_order_acquire);
	if (original_vfprintf_site != 0 &&
	    std::getenv("KYTY_DIAGNOSTIC_SYSCORE_VFPRINTF_AUDIT") != nullptr &&
	    info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address == original_vfprintf_site &&
	    IsReadableRange(original_vfprintf_site, 2)) {
		const auto* trap = reinterpret_cast<const uint8_t*>(original_vfprintf_site);
		if (trap[0] == 0x0f && trap[1] == 0x0b && info->rsp >= 8 &&
		    IsReadableRange(info->rsp - 8, 8) && IsReadableRange(info->rbp, 16)) {
			Libs::LibKernel::Memory::VirtualQueryInfo region {};
			const uint64_t                            new_rsp = info->rsp - 8;
			const bool                                writable =
			    Libs::LibKernel::Memory::KernelVirtualQuery(reinterpret_cast<const void*>(new_rsp),
				                                            0, &region, sizeof(region)) == 0 &&
			    region.is_committed && region.start <= new_rsp && region.end >= info->rsp &&
			    (region.protection & 2u) != 0;
			if (!writable) {
				return false;
			}
			const auto original_return = *reinterpret_cast<const uint64_t*>(info->rbp + 8);
			static std::atomic_uint32_t calls {0};
			const uint32_t              count = calls.fetch_add(1);
			if (count < 24) {
				LOGF("SYSCORE_VFPRINTF_ENTRY"
				     " call=%u caller_return=%016" PRIx64 " stream=%016" PRIx64
				     " format=%016" PRIx64 " va_list=%016" PRIx64 " r15=%016" PRIx64
				     " push_r15_resumed\n",
				     count, original_return, info->rdi, info->rsi, info->rdx, info->r15);
				uint64_t   list_words[4] {};
				const bool list_valid =
				    info->rdx != 0 && IsReadableRange(info->rdx, sizeof(list_words));
				if (list_valid) {
					std::memcpy(list_words, reinterpret_cast<const void*>(info->rdx),
					            sizeof(list_words));
				}
				const uint64_t overflow  = list_words[1];
				const uint64_t save_area = list_words[2];
				uint64_t       registers[8] {};
				uint64_t       spill[4] {};
				const bool     registers_valid =
				    list_valid && save_area != 0 && IsReadableRange(save_area, sizeof(registers));
				const bool overflow_valid =
				    list_valid && overflow != 0 && IsReadableRange(overflow, sizeof(spill));
				if (registers_valid) {
					std::memcpy(registers, reinterpret_cast<const void*>(save_area),
					            sizeof(registers));
				}
				if (overflow_valid) {
					std::memcpy(spill, reinterpret_cast<const void*>(overflow), sizeof(spill));
				}
				LOGF("SYSCORE_VFPRINTF_VA_LIST"
				     " call=%u list_valid=%d gp_offset=%u fp_offset=%u"
				     " overflow_ptr=%016" PRIx64 " save_ptr=%016" PRIx64
				     " regs_valid=%d regs=%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64
				     ",%016" PRIx64 ",%016" PRIx64 " spill_valid=%d"
				     " spill=%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64 "\n",
				     count, list_valid, static_cast<uint32_t>(list_words[0]),
				     static_cast<uint32_t>(list_words[0] >> 32), overflow, save_area,
				     registers_valid, registers[0], registers[1], registers[2], registers[3],
				     registers[4], registers[5], overflow_valid, spill[0], spill[1], spill[2],
				     spill[3]);
			}
			auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
			std::memcpy(reinterpret_cast<void*>(new_rsp), &info->r15, sizeof(uint64_t));
			context->Rsp = new_rsp;
			context->Rip += 2;
			return true;
		}
	}

	const uint64_t syscore_rfork = g_syscore_native_rfork_site.load(std::memory_order_acquire);
	const bool mini_rfork = g_mini_native_syscall_traps_installed.load(std::memory_order_acquire) &&
	                        std::getenv("KYTY_DIAGNOSTIC_MINI_SYSCORE_LIVE_RFORK") != nullptr &&
	                        info->exception_address == 0x468a33;
	if ((mini_rfork || (syscore_rfork != 0 &&
	                    (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_RFORK_AUDIT") != nullptr ||
	                     std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD") != nullptr))) &&
	    info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    (mini_rfork || info->exception_address == syscore_rfork) && info->rax == 0xfb &&
	    IsReadableRange(info->exception_address, 2)) {
		const auto* opcode = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (opcode[0] == 0x0f && opcode[1] == 0x0b) {
			const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
			    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
			if (reply.value != Libs::LibKernel::KERNEL_ERROR_ENOSYS) {
				return false;
			}
			if (((mini_rfork && (info->rdx == 0x40d0f0 || info->rdx == 0x40cf00)) ||
			     (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD") != nullptr &&
			      (info->rdx == 0x900003a30 || info->rdx == 0x900018880))) &&
			    info->rdi == 0x1030 && info->r14 != 0 && info->rsi > info->r14 + 0x100 &&
			    info->rsi <= info->r14 + 0x4000 && (info->rsi & 15u) == 0 && info->r10 != 0 &&
			    IsReadableRange(info->r10, 0x50)) {
				static std::mutex           child_launch_mutex;
				static int                  active_child_pid = 0;
				std::lock_guard<std::mutex> lock(child_launch_mutex);
				uint32_t                    previous_exit_status = 0;
				if (active_child_pid == 0 ||
				    Libs::LibKernel::Process::IsRforkChildContextRetired(active_child_pid) ||
				    Libs::LibKernel::Process::GetRforkChildExitStatus(active_child_pid,
				                                                      &previous_exit_status)) {
					Libs::LibKernel::Memory::VirtualQueryInfo region {};
					const bool mapped = info->r14 <= UINT64_MAX - 0x4000 &&
					                    Libs::LibKernel::Memory::KernelVirtualQuery(
					                        reinterpret_cast<const void*>(info->r14), 0, &region,
					                        sizeof(region)) == 0 &&
					                    region.is_committed && region.start <= info->r14 &&
					                    region.end >= info->r14 + 0x4000 &&
					                    (region.protection & 2u) != 0;
					if (mapped) {
						Libs::LibKernel::PthreadAttr attr = nullptr;
						auto                         err  = Libs::LibKernel::PthreadAttrInit(&attr);
						if (err == 0) {
							err = Libs::LibKernel::PthreadAttrSetstack(
							    &attr, reinterpret_cast<void*>(info->r14), 0x4000);
						}
						if (err == 0) {
							err = Libs::LibKernel::PthreadAttrSetdetachstate(&attr, 1);
						}
						Libs::LibKernel::Pthread child = nullptr;
						const int actual_pid = Libs::LibKernel::Process::AllocateRforkChildPid();
						if (err == 0 && actual_pid <= 0) err = actual_pid;
						if (err == 0) {
							err = Libs::LibKernel::PthreadCreateGuestRfork(
							    &child, &attr,
							    reinterpret_cast<Libs::LibKernel::pthread_entry_func_t>(info->rdx),
							    reinterpret_cast<void*>(info->r10), "rfork child", actual_pid,
							    info->rsi);
						}
						if (attr != nullptr) {
							Libs::LibKernel::PthreadAttrDestroy(&attr);
						}
						if (err == 0) {
							active_child_pid = actual_pid;
							auto* ctx        = reinterpret_cast<CONTEXT*>(info->native_context);
							ctx->Rax         = static_cast<uint64_t>(actual_pid);
							ctx->Rdx         = 0; // rfork_thread parent branch.
							ctx->EFlags &= ~uint32_t {1};
							ctx->Rip += 2;
							LOGF("SYSCORE_RFORK_THREAD_CREATED"
							     " child_guest_pid=%d entry=%016" PRIx64 " stack=%016" PRIx64
							     " malloc_base=%016" PRIx64 " arg=%016" PRIx64
							     " shares_guest_vm=1 new_child_guest_fd_table=1\n",
							     actual_pid, info->rdx, info->rsi, info->r14, info->r10);
							static std::atomic_uint32_t route_traces {0};
							if (route_traces.fetch_add(1) < 32) {
								const auto route = info->handler_route;
								const auto provenance =
								    Common::HostException::QueryActiveGuestCodeKind(
								        info->exception_address);
								LOGF("SYSCORE_RFORK_HANDLER_ROUTE"
								     " parent_guest_pid=%d child_guest_pid=%d entry_kind=%s "
								     "handler_route=%u"
								     " host_fiber=%u provenance_kind=%u site=%s\n",
								     Libs::LibKernel::Process::GetPid(), actual_pid,
								     info->rdx == 0x900018880 ? "app_spawn"
								     : mini_rfork             ? "mini_daemon_spawn"
								                              : "daemon_spawn",
								     static_cast<unsigned>(route),
								     route != Common::HostException::FaultHandlerRoute::Direct ? 1u
								                                                               : 0u,
								     static_cast<unsigned>(provenance),
								     mini_rfork ? "mini-syscore+0x68a33" : "libkernel+0x1b3");
							}
							if (mini_rfork) {
								LOGF("MINI_RFORK_THREAD_CREATED child_guest_pid=%d entry=%llx "
								     "stack=%llx\n",
								     actual_pid, static_cast<unsigned long long>(info->rdx),
								     static_cast<unsigned long long>(info->rsi));
							}
							return true;
						}
						LOGF("SYSCORE_RFORK_THREAD_FAILED"
						     " create_error=0x%08x"
						     " errno_path\n",
						     static_cast<unsigned>(err));
					} else {
						LOGF("SYSCORE_RFORK_THREAD_STACK_INVALID"
						     " alloc_base=%016" PRIx64 " stack_top=%016" PRIx64 "\n",
						     info->r14, info->rsi);
					}
				} else {
					LOGF("SYSCORE_RFORK_CHILD_STILL_ACTIVE"
					     " guest_pid=%d shared_guest_vm_requires_isolation\n",
					     active_child_pid);
				}
			}
			uint64_t original_guest_return = 0;
			if (info->rsp <= UINT64_MAX - 24 &&
			    IsReadableRange(info->rsp + 16, sizeof(original_guest_return))) {
				std::memcpy(&original_guest_return, reinterpret_cast<const void*>(info->rsp + 16),
				            sizeof(original_guest_return));
			}
			if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_RFORK_DESCRIPTOR_AUDIT") != nullptr) {
				static std::atomic<uint32_t> probes {0};
				const uint32_t               nth = probes.fetch_add(1);
				if (nth < 12) {
					uint64_t   work[10] {};
					const bool descriptor_readable = info->r10 != 0 &&
					                                 info->r10 <= UINT64_MAX - sizeof(work) &&
					                                 IsReadableRange(info->r10, sizeof(work));
					if (descriptor_readable) {
						std::memcpy(work, reinterpret_cast<const void*>(info->r10), sizeof(work));
					}
					char           program[193] {};
					uint32_t       program_length  = 0;
					bool           path_terminated = false;
					const uint64_t path            = work[1];
					while (descriptor_readable && path != 0 &&
					       program_length < sizeof(program) - 1 &&
					       path <= UINT64_MAX - program_length &&
					       IsReadableRange(path + program_length, 1)) {
						const uint8_t v = *reinterpret_cast<const uint8_t*>(path + program_length);
						if (!v) {
							path_terminated = true;
							break;
						}
						program[program_length++] =
						    (v >= 32 && v <= 126) ? static_cast<char>(v) : '.';
					}
					LOGF("SYSCORE_RFORK_CHILD_DESCRIPTOR"
					     " nth=%u descriptor=%016" PRIx64 " readable=%u fields=%016" PRIx64
					     ",%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64
					     " path_terminated=%u path=%s\n",
					     nth, info->r10, descriptor_readable ? 1u : 0u, work[0], work[1], work[2],
					     work[3], work[4], work[5], path_terminated ? 1u : 0u, program);
					if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_RFORK_PREFLIGHT") != nullptr) {
						const uint64_t child_stack_page = info->rsi > 0x100 ? info->rsi - 0x100 : 0;
						Libs::LibKernel::Memory::VirtualQueryInfo stack_mem {};
						Libs::LibKernel::Memory::VirtualQueryInfo entry_mem {};
						const bool                                stack_query =
						    child_stack_page != 0 &&
						    Libs::LibKernel::Memory::KernelVirtualQuery(
						        reinterpret_cast<const void*>(child_stack_page), 0, &stack_mem,
						        sizeof(stack_mem)) == 0;
						const bool entry_query = Libs::LibKernel::Memory::KernelVirtualQuery(
						                             reinterpret_cast<const void*>(info->rdx), 0,
						                             &entry_mem, sizeof(entry_mem)) == 0;
						uint64_t   argv[3] {};
						const bool argv_readable =
						    work[2] && IsReadableRange(work[2], sizeof(argv));
						if (argv_readable) {
							std::memcpy(argv, reinterpret_cast<const void*>(work[2]), sizeof(argv));
						}
						const auto host_file =
						    path_terminated ? Libs::LibKernel::FileSystem::GetRealFilename(program)
							                : std::filesystem::path {};
						const bool file_exists =
						    !host_file.empty() && Common::File::IsFileExisting(host_file);
						LOGF("SYSCORE_RFORK_RESOURCE_PREFLIGHT"
						     " nth=%u stack=%016" PRIx64 " stack_mapped=%u stack_committed=%u"
						     " stack_writeable=%u entry_mapped=%u"
						     " entry_executable=%u argv_readable=%u"
						     " argv=%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64
						     " target_file_exists=%u target=%s\n",
						     nth, child_stack_page, stack_query ? 1u : 0u,
						     stack_query && stack_mem.is_committed ? 1u : 0u,
						     stack_query && (stack_mem.protection & 2u) != 0 ? 1u : 0u,
						     entry_query ? 1u : 0u,
						     entry_query && (entry_mem.protection & 4u) != 0 ? 1u : 0u,
						     argv_readable ? 1u : 0u, argv[0], argv[1], argv[2],
						     file_exists ? 1u : 0u, Common::PathToString(host_file).c_str());
					}
				}
			}
			const int err     = Libs::LibKernel::KernelToPosix(static_cast<int>(reply.value));
			auto*     context = reinterpret_cast<CONTEXT*>(info->native_context);
			context->Rax      = static_cast<uint64_t>(err);
			context->EFlags   = (context->EFlags | uint32_t {1});
			context->Rip += 2;
			static std::atomic<uint32_t> observed {0};
			if (observed.fetch_add(1) < 16) {
				LOGF("SYSCORE_RFORK_NATIVE_OBSERVED"
				     " guest_return=%016" PRIx64 " flags=%016" PRIx64 " child_stack=%016" PRIx64
				     " child_entry=%016" PRIx64 " argument=%016" PRIx64 " r8=%016" PRIx64
				     " r9=%016" PRIx64 " unsupported_errno=%d cf=1"
				     " NO_PROCESS_CREATED\n",
				     original_guest_return, info->rdi, info->rsi, info->rdx, info->r10, info->r8,
				     info->r9, err);
			}
			return true;
		}
	}
	const uint64_t syscore_execve = g_syscore_native_execve_site.load(std::memory_order_acquire);
	if (syscore_execve != 0 && std::getenv("KYTY_DIAGNOSTIC_SYSCORE_EXECVE_AUDIT") != nullptr &&
	    info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address == syscore_execve && info->rax == 0x3b &&
	    IsReadableRange(syscore_execve, 2)) {
		const auto* opcode = reinterpret_cast<const uint8_t*>(syscore_execve);
		if (opcode[0] == 0x0f && opcode[1] == 0x0b) {
			const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
			    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
			if (reply.value == 0 && reply.posix_errno == 0) {
				return true;
			}
			if (reply.value >= 0) {
				return false;
			}
			char pathname[193] {};
			bool terminated = false;
			int  length     = 0;
			while (info->rdi != 0 && length < 192 &&
			       info->rdi <= UINT64_MAX - static_cast<uint64_t>(length) - 1 &&
			       IsReadableRange(info->rdi + static_cast<uint64_t>(length), 1)) {
				const uint8_t value =
				    *reinterpret_cast<const uint8_t*>(info->rdi + static_cast<uint64_t>(length));
				if (value == 0) {
					terminated = true;
					break;
				}
				pathname[length++] = value >= 32 && value <= 126 ? static_cast<char>(value) : '.';
			}
			if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_EXECVE_TARGET_PLAN") != nullptr) {
				std::array<std::string, 16> args {};
				unsigned int                count           = 0;
				bool                        argv_valid      = info->rsi != 0;
				bool                        argv_terminated = false;
				for (unsigned int i = 0; argv_valid && i < args.size(); ++i) {
					const uint64_t slot = info->rsi + uint64_t {8} * i;
					if (slot < info->rsi || !IsReadableRange(slot, sizeof(uint64_t))) {
						argv_valid = false;
						break;
					}
					uint64_t argument = 0;
					std::memcpy(&argument, reinterpret_cast<const void*>(slot), sizeof(argument));
					if (argument == 0) {
						argv_terminated = true;
						break;
					}
					if (argument > UINT64_MAX - 192) {
						argv_valid = false;
						break;
					}
					bool        argument_terminated = false;
					std::string value;
					for (unsigned int byte = 0; byte < 192; ++byte) {
						if (!IsReadableRange(argument + byte, 1)) {
							argv_valid = false;
							break;
						}
						const auto ch = *reinterpret_cast<const uint8_t*>(argument + byte);
						if (ch == 0) {
							argument_terminated = true;
							break;
						}
						value.push_back(ch >= 32 && ch <= 126 ? char(ch) : '.');
					}
					if (!argument_terminated) {
						argv_valid = false;
						break;
					}
					args[count++] = std::move(value);
				}
				const auto real_file = terminated
				                           ? Libs::LibKernel::FileSystem::GetRealFilename(pathname)
				                           : std::filesystem::path {};
				const bool exists = !real_file.empty() && Common::File::IsFileExisting(real_file);
				std::array<uint8_t, 64> header {};
				bool                    valid_elf = false;
				uint64_t                entry     = 0;
				uint16_t                elf_type  = 0;
				uint16_t                machine   = 0;
				if (exists) {
					std::ifstream input(real_file, std::ios::binary);
					input.read(reinterpret_cast<char*>(header.data()),
					           static_cast<std::streamsize>(header.size()));
					if (input.gcount() == static_cast<std::streamsize>(header.size())) {
						std::memcpy(&elf_type, header.data() + 16, sizeof(elf_type));
						std::memcpy(&machine, header.data() + 18, sizeof(machine));
						std::memcpy(&entry, header.data() + 24, sizeof(entry));
						valid_elf = header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' &&
						            header[3] == 'F' && header[4] == 2 && header[5] == 1 &&
						            elf_type == 0xfe10 && machine == 0x3e;
					}
				}
				LOGF("SYSCORE_EXECVE_TARGET_READ_ONLY_PREFLIGHT"
				     " guest_pid=%d path=%s"
				     " path_terminated=%d host_elf_exists=%d"
				     " elf_header_valid=%d type=%04x machine=%04x"
				     " entry=%016" PRIx64 " argv_pointer=%016" PRIx64
				     " argv_valid=%d argv_terminated=%d argc=%u"
				     " argv0=%s argv1=%s argv2=%s envp=%016" PRIx64 "\n",
				     Libs::LibKernel::Process::GetPid(), pathname, terminated, exists, valid_elf,
				     elf_type, machine, entry, info->rsi, argv_valid, argv_terminated, count,
				     count > 0 ? args[0].c_str() : "(none)", count > 1 ? args[1].c_str() : "(none)",
				     count > 2 ? args[2].c_str() : "(none)", info->rdx);
			}
			const int err     = Libs::LibKernel::KernelToPosix(static_cast<int>(reply.value));
			auto*     context = reinterpret_cast<CONTEXT*>(info->native_context);
			context->Rax      = static_cast<uint64_t>(err);
			context->EFlags   = context->EFlags | uint32_t {1};
			context->Rip += 2;
			LOGF("SYSCORE_EXECVE_NATIVE_OBSERVED"
			     " site=%016" PRIx64 " guest_path=%016" PRIx64 " argv=%016" PRIx64
			     " envp=%016" PRIx64 " path_terminated=%d path=%s guest_errno=%d cf=1"
			     "\n",
			     syscore_execve, info->rdi, info->rsi, info->rdx, terminated, pathname, err);
			return true;
		}
	}
	const auto audio_map_site  = g_exec_child_native_mmap_site.load(std::memory_order_acquire);
	const auto audio_name_site = g_exec_child_native_name_site.load(std::memory_order_acquire);
	const bool audio_map_call =
	    audio_map_site != 0 && info->exception_address == audio_map_site && info->rax == 0x1dd;
	const auto audio_extended_map_site =
	    g_exec_child_native_extended_mmap_site.load(std::memory_order_acquire);
	const bool audio_extended_map_call = audio_extended_map_site != 0 &&
	                                     info->exception_address == audio_extended_map_site &&
	                                     info->rax == 0x2d5;
	const bool audio_name_call =
	    audio_name_site != 0 && info->exception_address == audio_name_site && info->rax == 0x24c;
	if ((std::getenv("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP") != nullptr ||
	     Libs::LibKernel::Process::IsExecChild()) &&
	    info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    (audio_map_call || audio_name_call || audio_extended_map_call) &&
	    IsReadableRange(info->exception_address, 2)) {
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b) {
			Libs::NativeKernelBridge::SyscallRequest request {
			    info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}};
			if (audio_extended_map_call && info->rsp <= UINT64_MAX - 16 &&
			    IsReadableRange(info->rsp, 16)) {
				std::memcpy(&request.stack_arg7, reinterpret_cast<const void*>(info->rsp + 8), 8);
				request.stack_arg7_valid = true;
				LOGF("FIRST_FRAME_AUDIT AUDIOD_EXTENDED_MMAP_ABI"
				     " syscall=0x2d5"
				     " mode=%" PRIu64 " stack_arg7=0x%016" PRIx64 "\n",
				     info->r8, request.stack_arg7);
			}
			const auto reply = Libs::NativeKernelBridge::DispatchSyscall(request);
			const bool unsupported_extended_map =
			    audio_extended_map_call && reply.value == Libs::LibKernel::KERNEL_ERROR_ENOSYS &&
			    reply.posix_errno == 0;
			const int guest_errno =
			    unsupported_extended_map
			        ? Libs::LibKernel::KernelToPosix(static_cast<int>(reply.value))
			        : reply.posix_errno;
			const bool failed = (reply.value == -1 && guest_errno > 0) || unsupported_extended_map;
			if ((reply.value >= 0 && guest_errno == 0) || failed) {
				auto* context   = reinterpret_cast<CONTEXT*>(info->native_context);
				context->Rax    = failed ? static_cast<uint64_t>(guest_errno)
				                         : static_cast<uint64_t>(reply.value);
				context->EFlags = (context->EFlags & ~uint32_t {1}) | (failed ? 1u : 0u);
				context->Rip += 2;
				LOGF("FIRST_FRAME_AUDIT EXEC_CHILD_LIBKERNEL_SYSCALL"
				     " nr=0x%016" PRIx64 " site=0x%016" PRIx64 " result=0x%016" PRIx64
				     " guest_errno=%d"
				     " guest_cf=%u args=%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64
				     ",%016" PRIx64 ",%016" PRIx64 " native_guest_continues\n",
				     info->rax, info->exception_address, context->Rax, guest_errno,
				     static_cast<unsigned>(context->EFlags & 1), info->rdi, info->rsi, info->rdx,
				     info->r10, info->r8, info->r9);
				return true;
			}
		}
	}
	if (g_sysav_raw_traps_installed.load(std::memory_order_acquire) &&
	    info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    info->exception_address >= 0x400000 && info->exception_address < 0x4a4000 &&
	    IsReadableRange(info->exception_address, 2)) {
		const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address);
		if (code[0] == 0x0f && code[1] == 0x0b) {
			bool     installed_guard  = false;
			bool     original_ud2     = false;
			uint32_t installed_number = UINT32_MAX;
			{
				std::lock_guard lock(g_native_libkernel_trap_mutex);
				const auto trap = std::find_if(g_sysav_raw_traps.begin(), g_sysav_raw_traps.end(),
				                               [&](const NativeLibkernelTrap& entry) {
					                               return entry.site == info->exception_address;
				                               });
				installed_guard = trap != g_sysav_raw_traps.end();
				if (installed_guard) installed_number = trap->number;
				original_ud2 = std::find(g_sysav_original_ud2.begin(), g_sysav_original_ud2.end(),
				                         info->exception_address) != g_sysav_original_ud2.end();
			}
			if (info->rax == 0xca && info->rsi == 2 &&
			    IsReadableRange(info->rdi, 2 * sizeof(uint32_t))) {
				const auto* mib = reinterpret_cast<const uint32_t*>(info->rdi);
				LOGF("FIRST_FRAME_AUDIT SYSAV_RAW_SYSCTL_MIB first=%u second=%u"
				     " OBSERVED\n",
				     mib[0], mib[1]);
				if (mib[0] == 0 && mib[1] == 3 && info->r9 == 19 && IsReadableRange(info->r8, 19) &&
				    std::memcmp(reinterpret_cast<const void*>(info->r8), "kern.init_safe_mode",
				                19) == 0 &&
				    IsWritableRange(info->r10, sizeof(size_t))) {
					const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
					    {info->rax,
						 {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
					if ((reply.value == 0 && reply.posix_errno == 0) ||
					    (reply.value == -1 && reply.posix_errno > 0)) {
						auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
						context->Rax =
						    reply.value == 0 ? 0 : static_cast<uint64_t>(reply.posix_errno);
						context->EFlags =
						    (context->EFlags & ~uint32_t {1}) | (reply.value == -1 ? 1u : 0u);
						context->Rip += 2;
						return true;
					}
				}
			}
			if (info->rax == 0x28d && info->rdi == 0 && info->exception_address == 0x47731a) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if (reply.value == -1 && reply.posix_errno == Libs::Posix::POSIX_ENOSYS) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax  = static_cast<uint64_t>(reply.posix_errno);
					context->EFlags |= uint32_t {1};
					context->Rip += 2;
					return true;
				}
			}
			if (info->rax == 0x24a && info->rdi == UINT32_MAX &&
			    info->exception_address == 0x4772fa) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if ((reply.value == 0 && reply.posix_errno == 0) ||
				    (reply.value == -1 && reply.posix_errno > 0)) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax  = reply.value == 0 ? 0 : static_cast<uint64_t>(reply.posix_errno);
					context->EFlags =
					    (context->EFlags & ~uint32_t {1}) | (reply.value == 0 ? 0u : 1u);
					context->Rip += 2;
					return true;
				}
			}
			// boot-status flag gets closed after set/poll even with no ShellCore creator; the
			// handle registry checks the pointer without dereferencing it
			if (info->rax == 0x21d && info->exception_address == 0x478cca) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if ((reply.value == 0 && reply.posix_errno == 0) ||
				    (reply.value == -1 && reply.posix_errno > 0)) {
					auto* ctx   = reinterpret_cast<CONTEXT*>(info->native_context);
					ctx->Rax    = reply.value == -1 ? static_cast<uint64_t>(reply.posix_errno) : 0;
					ctx->EFlags = (ctx->EFlags & ~uint32_t {1}) | (reply.value == -1 ? 1u : 0u);
					ctx->Rip += 2;
					return true;
				}
			}
			// bit 0x8 can be set after a failed flag lookup (no ShellCore producer, no handle):
			// ESRCH
			if (info->rax == 0x220 && info->rsi != 0 && info->exception_address == 0x478c6a) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if ((reply.value == 0 && reply.posix_errno == 0) ||
				    (reply.value == -1 && reply.posix_errno > 0)) {
					auto* ctx   = reinterpret_cast<CONTEXT*>(info->native_context);
					ctx->Rax    = reply.value == -1 ? static_cast<uint64_t>(reply.posix_errno) : 0;
					ctx->EFlags = (ctx->EFlags & ~uint32_t {1}) | (reply.value == -1 ? 1u : 0u);
					ctx->Rip += 2;
					LOGF("FIRST_FRAME_AUDIT SYSAV_BOOT_FLAG_SET_LOOKUP"
					     " bits=0x%016" PRIx64 " guest_handle=0x%016" PRIx64 " posix_errno=%d\n",
					     info->rsi, info->rdi, reply.posix_errno);
					return true;
				}
			}
			if (info->rax == 0x220 &&
			    (info->rdi <= UINT32_MAX || (info->rdi >> 32) == UINT32_MAX) &&
			    info->rsi == 0x0000ffff00000000ull) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax,
					 {static_cast<uint32_t>(info->rdi), info->rsi, info->rdx, info->r10, info->r8,
					  info->r9}});
				if ((reply.value == 0 && reply.posix_errno == 0) ||
				    (reply.value == -1 && reply.posix_errno > 0)) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax  = reply.value == 0 ? 0 : static_cast<uint64_t>(reply.posix_errno);
					context->EFlags =
					    (context->EFlags & ~uint32_t {1}) | (reply.value == 0 ? 0u : 1u);
					context->Rip += 2;
					return true;
				}
			}
			if (info->rax == 0x21e && info->rdi <= UINT32_MAX &&
			    info->rsi == 0x0000ffff00000000ull && info->rdx == 0x22 &&
			    IsWritableRange(info->r10, sizeof(uint64_t)) &&
			    IsWritableRange(info->r8, sizeof(uint32_t))) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if ((reply.value == 0 && reply.posix_errno == 0) ||
				    (reply.value == -1 && reply.posix_errno > 0)) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax  = reply.value == 0 ? 0 : static_cast<uint64_t>(reply.posix_errno);
					context->EFlags =
					    (context->EFlags & ~uint32_t {1}) | (reply.value == 0 ? 0u : 1u);
					context->Rip += 2;
					return true;
				}
			}
			if (info->rax == 0x214 &&
			    (((info->rdi == 0x24 || info->rdi == 0x16) && info->rsi == 0 && info->r10 == 0 &&
			      info->r8 == 0) ||
			     ((info->rdi == 1 || info->rdi == 2 || info->rdi == 5 || info->rdi == 6) &&
			      info->rsi <= UINT32_MAX && info->r8 > 0 && info->r8 <= 0x1000 &&
			      IsWritableRange(info->r10, static_cast<size_t>(info->r8)))) &&
			    IsWritableRange(info->rdx, sizeof(uint32_t))) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if ((reply.value == 0 && reply.posix_errno == 0) ||
				    (reply.value == -1 && reply.posix_errno > 0)) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax  = reply.value == 0 ? 0 : static_cast<uint64_t>(reply.posix_errno);
					context->EFlags =
					    (context->EFlags & ~uint32_t {1}) | (reply.value == 0 ? 0u : 1u);
					context->Rip += 2;
					if (reply.value == -1) {
						LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_REGMGR_UNSUPPORTED"
						     " op=0x%" PRIx64 " errno=%d\n",
						     info->rdi, reply.posix_errno);
					}
					return true;
				}
			}
			if (info->rax == 0x1b0 && info->rdi >= 0x200000000ull && info->rdi < 0x210000000ull &&
			    IsReadableRange(info->rdi, sizeof(uint64_t))) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if (reply.value == 0 && reply.posix_errno == 0) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax  = 0;
					context->EFlags &= ~uint32_t {1};
					context->Rip += 2;
					LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_THR_SELF\n");
					return true;
				}
			}
			if (Libs::LibKernel::Process::IsExecChild() &&
			    ((info->rax == 0x22d && info->exception_address == 0x47321a) ||
			     (info->rax == 0x22e && info->exception_address == 0x4731fa))) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if (reply.value >= 0 || (reply.value == -1 && reply.posix_errno > 0)) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax  = reply.value == -1 ? static_cast<uint64_t>(reply.posix_errno)
					                                  : static_cast<uint64_t>(reply.value);
					context->EFlags =
					    (context->EFlags & ~uint32_t {1}) | (reply.value == -1 ? 1u : 0u);
					context->Rip += 2;
					return true;
				}
			}
			// 0x22e on AV-controller failure cleanup releases IDs from the process-local table
			if (info->rax == 0x22e && info->rdi > 0 && info->rdi <= 0xfffe &&
			    (info->rsi == 0x101 || info->rsi == 0x102 || info->rsi == 0x107) &&
			    std::getenv("KYTY_DIAGNOSTIC_NAMEDOBJ_ID_TABLE") != nullptr) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if ((reply.value == 0 && reply.posix_errno == 0) ||
				    (reply.value == -1 && reply.posix_errno > 0)) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax = reply.value == -1 ? static_cast<uint64_t>(reply.posix_errno) : 0;
					context->EFlags =
					    (context->EFlags & ~uint32_t {1}) | (reply.value == -1 ? 1u : 0u);
					context->Rip += 2;
					return true;
				}
			}
			if (info->rax == 4 && (info->rdi == 1 || info->rdi == 2) && info->rdx > 0 &&
			    info->rdx <= 1024 && IsReadableRange(info->rsi, info->rdx)) {
				std::string original_message(reinterpret_cast<const char*>(info->rsi),
				                             static_cast<size_t>(info->rdx));
				for (auto& c: original_message) {
					if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) {
						c = ' ';
					}
				}
				LOGF("FIRST_FRAME_AUDIT SYSAV_GUEST_STDOUT"
				     " fd=%" PRIu64 " bytes=%" PRIu64 " guest_message=%s\n",
				     info->rdi, info->rdx, original_message.c_str());
				auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
				context->Rax  = info->rdx;
				context->EFlags &= ~uint32_t {1};
				context->Rip += 2;
				return true;
			}
			if (info->rax == 0x16a) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall({info->rax, {}});
				if (reply.value >= 3 && reply.posix_errno == 0) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax  = static_cast<uint64_t>(reply.value);
					context->EFlags &= ~uint32_t {1};
					context->Rip += 2;
					LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_KQUEUE"
					     " guest_fd=%" PRId64 " event_queue_backing\n",
					     reply.value);
					return true;
				}
			}
			if (info->rax == 0x49 && info->rdi != 0 && info->rsi != 0 &&
			    (info->rdi & 0x3fffull) == 0 && (info->rsi & 0x3fffull) == 0) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if ((reply.value == 0 && reply.posix_errno == 0) ||
				    (reply.value == -1 && reply.posix_errno > 0)) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax = reply.value == -1 ? static_cast<uint64_t>(reply.posix_errno) : 0;
					context->EFlags =
					    (context->EFlags & ~uint32_t {1}) | (reply.value == -1 ? 1u : 0u);
					context->Rip += 2;
					return true;
				}
			}
			if (info->rax == 0x145 &&
			    std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") != nullptr) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall({info->rax, {}});
				if (reply.value == 0 && reply.posix_errno == 0) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax  = 0;
					context->EFlags &= ~uint32_t {1};
					context->Rip += 2;
					return true;
				}
			}
			if (info->rax == 0x4a && info->rdi == 0 && info->rsi == 0 && info->rdx == 0) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if (reply.value == 0 && reply.posix_errno == 0) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax  = 0;
					context->EFlags &= ~uint32_t {1};
					context->Rip += 2;
					LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_ZERO_LENGTH_MPROTECT\n");
					return true;
				}
			}
			if (info->rax == 0x259 && info->rdi == 3 && info->rsi == 0xffffffffa002031eull &&
			    info->rdx == 0) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if ((reply.value == 0 && reply.posix_errno == 0) ||
				    (reply.value == -1 && reply.posix_errno > 0)) {
					auto* ctx = reinterpret_cast<CONTEXT*>(info->native_context);
					ctx->Rax  = reply.value == 0 ? 0ull : static_cast<uint64_t>(reply.posix_errno);
					ctx->EFlags = (ctx->EFlags & ~uint32_t {1}) | (reply.value == 0 ? 0u : 1u);
					ctx->Rip += 2;
					return true;
				}
			}
			// RW_RDLOCK (12) and RW_WRLOCK (13) land here too
			if (info->rax == 0x1c6 && (info->rsi == 12 || info->rsi == 13) &&
			    IsReadableRange(info->rdi, 16)) {
				static std::atomic_uint32_t rw_samples {0};
				if (rw_samples.fetch_add(1) < 16) {
					uint32_t rw_words[4] {};
					std::memcpy(rw_words, reinterpret_cast<const void*>(info->rdi),
					            sizeof(rw_words));
					LOGF("FIRST_FRAME_AUDIT SYSAV_RWLOCK_CONTENTION"
					     " op=%" PRIu64 " guest_addr=0x%016" PRIx64 " state=0x%08x flags=0x%08x"
					     " blocked_readers=%u blocked_writers=%u"
					     " val=0x%016" PRIx64 " tid=%d\n",
					     info->rsi, info->rdi, rw_words[0], rw_words[1], rw_words[2], rw_words[3],
					     info->rdx, Libs::LibKernel::PthreadGetthreadid());
				}
			}
			// sys_thr_get_name at 0x47092A, answered from Kyty pthread state
			if (info->rax == 0x268 && info->rdi > 0 && info->rdi <= INT32_MAX &&
			    (info->rdx == 0 || info->rdi == 5) && IsWritableRange(info->rsi, 32)) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if ((reply.value == 0 && reply.posix_errno == 0) ||
				    (reply.value == -1 && reply.posix_errno > 0)) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax = reply.value == -1 ? static_cast<uint64_t>(reply.posix_errno) : 0;
					context->EFlags =
					    (context->EFlags & ~uint32_t {1}) | (reply.value == -1 ? 1u : 0u);
					context->Rip += 2;
					return true;
				}
			}
			// thr_exit at 0x47094A, doesn't return
			if (info->rax == 0x1af && IsReadableRange(info->rdi, sizeof(uint64_t))) {
				(void)Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
			}
			// sys_exit at 0x472B1A after both workers thr_exit; status becomes the Win32 exit code
			if (info->rax == 1 && info->exception_address == 0x472b1a && info->rdi <= 255) {
				if (Libs::LibKernel::Process::IsExecChild()) {
					Libs::LibKernel::Process::RecordExecChildExitStatus(
					    static_cast<uint32_t>((info->rdi & 255u) << 8u));
				}
				LOGF("FIRST_FRAME_AUDIT SYSAV_PROCESS_EXIT"
				     " syscall=1 guest_exit_status=%" PRIu64
				     " terminating_standalone_Kyty_guest_process\n",
				     info->rdi);
				std::fflush(nullptr);
				ExitProcess(static_cast<UINT>(info->rdi));
			}
			// failing _umtx_op (0x1C6): native atomics, not Kyty's HLE pthread format
			if (info->rax == 0x1c6 &&
			    (info->rsi == 8 || info->rsi == 9 || info->rsi == 17 || info->rsi == 23) &&
			    IsReadableRange(info->rdi, 16)) {
				static std::atomic_uint32_t samples {0};
				if (samples.fetch_add(1) < 12) {
					uint32_t original_words[4] {};
					std::memcpy(original_words, reinterpret_cast<const void*>(info->rdi),
					            sizeof(original_words));
					uint32_t original_mutex = 0;
					if (info->rsi == 8 && IsReadableRange(info->r10, 4)) {
						std::memcpy(&original_mutex, reinterpret_cast<const void*>(info->r10), 4);
					}
					LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_UMTX_STATE"
					     " op=%" PRIu64 " obj=0x%016" PRIx64 " words=%08x,%08x,%08x,%08x"
					     " mutex=0x%016" PRIx64 " mutex_owner=%08x"
					     " val=0x%016" PRIx64 " uaddr2=0x%016" PRIx64 " guest_tid=%d\n",
					     info->rsi, info->rdi, original_words[0], original_words[1],
					     original_words[2], original_words[3], info->r10, original_mutex, info->rdx,
					     info->r8, Libs::LibKernel::PthreadGetthreadid());
				}
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if ((reply.value == 0 && reply.posix_errno == 0) ||
				    (reply.value == -1 && reply.posix_errno > 0)) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax = reply.value == -1 ? static_cast<uint64_t>(reply.posix_errno) : 0;
					context->EFlags =
					    (context->EFlags & ~uint32_t {1}) | (reply.value == -1 ? 1u : 0u);
					context->Rip += 2;
					return true;
				}
			}
			if (info->rax == 0x1d2 && info->rdi == 0 &&
			    info->rsi == static_cast<uint32_t>(Libs::LibKernel::PthreadGetthreadid()) &&
			    IsReadableRange(info->rdx, sizeof(uint32_t))) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if (reply.value == 0 && reply.posix_errno == 0) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax  = 0;
					context->EFlags &= ~uint32_t {1};
					context->Rip += 2;
					LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_RT_PRIO\n");
					return true;
				}
			}
			if (info->rax == 0x1a0 && (info->rdi == 32 || info->rdi == 2) &&
			    IsReadableRange(info->rsi, 32) && info->rdx == 0) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if (reply.value == 0 && reply.posix_errno == 0) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax  = 0;
					context->EFlags &= ~uint32_t {1};
					context->Rip += 2;
					LOGF("FIRST_FRAME_AUDIT SYSAV_DIAGNOSTIC_NATIVE_SIGACTION_RETURN"
					     " signal=%" PRIu64 " WITHOUT_GUEST_SIGNAL_DELIVERY NON_AUTHENTIC\n",
					     info->rdi);
					return true;
				}
			}
			if (info->rax == 0x154 &&
			    ((info->rdi == 2 && info->rdx == 0) ||
			     (info->rdi == 3 && info->rdx == 0 && (info->rsi & 0xfffull) == 0x208 &&
			      info->rsi >= 0x200000000ull && info->rsi < 0x210000000ull) ||
			     (info->rdi == 1 && info->rsi == 0x4de5c8 && IsReadableRange(info->rdx, 16))) &&
			    IsReadableRange(info->rsi, 16)) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if (reply.value == 0 && reply.posix_errno == 0) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax  = 0;
					context->EFlags &= ~uint32_t {1};
					context->Rip += 2;
					LOGF("FIRST_FRAME_AUDIT SYSAV_DIAGNOSTIC_SIGPROCMASK_RETURN"
					     " WITHOUT_GUEST_SIGNAL_DELIVERY NON_AUTHENTIC\n");
					return true;
				}
			}
			if (info->rax == 0x1dd && info->rdi == 0 && info->rsi == 0x2000 && info->rdx == 3 &&
			    info->r10 == 1 && info->r8 >= 3 && info->r8 <= INT32_MAX && info->r9 == 0) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if ((reply.value > 0 && reply.posix_errno == 0) ||
				    (reply.value == -1 && reply.posix_errno > 0)) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax  = reply.value == -1 ? static_cast<uint64_t>(reply.posix_errno)
					                                  : static_cast<uint64_t>(reply.value);
					context->EFlags =
					    (context->EFlags & ~uint32_t {1}) | (reply.value == -1 ? 1u : 0u);
					context->Rip += 2;
					return true;
				}
			}
			// splash sys_virtual_query (0x23c), after mmap and rename
			if (info->rax == 0x23c && info->exception_address == 0x47739a &&
			    info->rdi >= 0x200000000ull && info->rdi < 0x300000000ull && info->rsi == 0 &&
			    IsWritableRange(info->rdx, sizeof(Libs::LibKernel::Memory::VirtualQueryInfo)) &&
			    info->r10 == sizeof(Libs::LibKernel::Memory::VirtualQueryInfo)) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if ((reply.value == 0 && reply.posix_errno == 0) ||
				    (reply.value == -1 && reply.posix_errno > 0)) {
					auto* ctx   = reinterpret_cast<CONTEXT*>(info->native_context);
					ctx->Rax    = reply.value == 0 ? 0 : static_cast<uint64_t>(reply.posix_errno);
					ctx->EFlags = (ctx->EFlags & ~uint32_t {1}) | (reply.value == 0 ? 0u : 1u);
					ctx->Rip += 2;
					LOGF("FIRST_FRAME_AUDIT SYSAV_VIRTUAL_QUERY_RETURN"
					     " site=0x47739A"
					     " guest_errno=%d success=%u\n",
					     reply.posix_errno, reply.value == 0 ? 1u : 0u);
					Log::Flush();
					return true;
				}
			}
			if (info->rax == 0x1dd && info->rsi != 0 && info->rsi <= 0x10000000 &&
			    (info->rsi & 0x3fffu) == 0 && (info->rdi & 0x3fffu) == 0) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if ((reply.value > 0 && reply.posix_errno == 0) ||
				    (reply.value == -1 && reply.posix_errno > 0)) {
					auto* ctx   = reinterpret_cast<CONTEXT*>(info->native_context);
					ctx->Rax    = reply.value == -1 ? static_cast<uint64_t>(reply.posix_errno)
					                                : static_cast<uint64_t>(reply.value);
					ctx->EFlags = (ctx->EFlags & ~uint32_t {1}) | (reply.value == -1 ? 1u : 0u);
					ctx->Rip += 2;
					LOGF("FIRST_FRAME_AUDIT SYSAV_MMAP_FALLBACK"
					     " addr=0x%016" PRIx64 " len=0x%016" PRIx64
					     " prot=0x%llx flags=0x%llx guest_errno=%d"
					     " backend_result=0x%016" PRIx64 "\n",
					     info->rdi, info->rsi, static_cast<unsigned long long>(info->rdx),
					     static_cast<unsigned long long>(info->r10), reply.posix_errno, ctx->Rax);
					return true;
				}
			}
			// 0x47543F stack builder names its PROT_NONE guard page via 0x24C ("stack guard"). 0xF0
			// is nanosleep (0x471DCA)
			if (info->rax == 0xf0 &&
			    IsReadableRange(info->rdi, sizeof(Libs::LibKernel::KernelTimespec)) &&
			    (info->rsi == 0 ||
			     IsWritableRange(info->rsi, sizeof(Libs::LibKernel::KernelTimespec)))) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if ((reply.value == 0 && reply.posix_errno == 0) ||
				    (reply.value == -1 && reply.posix_errno > 0)) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax = reply.value == -1 ? static_cast<uint64_t>(reply.posix_errno) : 0;
					context->EFlags =
					    (context->EFlags & ~uint32_t {1}) | (reply.value == -1 ? 1u : 0u);
					context->Rip += 2;
					return true;
				}
			}
			if (info->rax == 0xe8 && info->rdi == 15 &&
			    IsWritableRange(info->rsi, sizeof(Libs::LibKernel::KernelTimespec))) {
				const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
				    {info->rax, {info->rdi, info->rsi, info->rdx, info->r10, info->r8, info->r9}});
				if ((reply.value == 0 && reply.posix_errno == 0) ||
				    (reply.value == -1 && reply.posix_errno > 0)) {
					auto* context = reinterpret_cast<CONTEXT*>(info->native_context);
					context->Rax = reply.value == -1 ? static_cast<uint64_t>(reply.posix_errno) : 0;
					context->EFlags =
					    (context->EFlags & ~uint32_t {1}) | (reply.value == -1 ? 1u : 0u);
					context->Rip += 2;
					return true;
				}
			}
		}
	}
#endif

	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    Loader::X64InstructionEmulator::TryEmulate(info->native_context)) {
		return true;
	}

	if (info->type == Common::HostException::ExceptionType::AccessViolation) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		if (g_sysav_raw_traps_installed.load(std::memory_order_acquire) &&
		    g_sysav_native_fsbase >= 0x200000000ull && g_sysav_native_fsbase < 0x210000000ull &&
		    info->exception_address >= 0x400000 && info->exception_address < 0x4a4000 &&
		    IsReadableRange(info->exception_address, 9)) {
			const auto* ins = reinterpret_cast<const uint8_t*>(info->exception_address);
			if (ins[0] == 0x64 && (ins[1] & 0x0bu) == 0x08u && ins[2] == 0x8b &&
			    (ins[3] & 0xc7u) == 0x04u && ins[4] == 0x25) {
				uint32_t disp = 0;
				std::memcpy(&disp, ins + 5, sizeof(disp));
				const uint32_t reg = ((ins[3] >> 3u) & 7u) + ((ins[1] & 0x04u) != 0 ? 8u : 0u);
				if (disp <= 0x100 && reg != 4 && info->access_violation_vaddr == disp &&
				    IsReadableRange(g_sysav_native_fsbase + disp, 8)) {
					uint64_t value = 0;
					std::memcpy(&value, reinterpret_cast<const void*>(g_sysav_native_fsbase + disp),
					            sizeof(value));
					auto*     ctx    = reinterpret_cast<CONTEXT*>(info->native_context);
					uint64_t* output = nullptr;
					switch (reg) {
						case 0: output = &ctx->Rax; break;
						case 1: output = &ctx->Rcx; break;
						case 2: output = &ctx->Rdx; break;
						case 3: output = &ctx->Rbx; break;
						case 5: output = &ctx->Rbp; break;
						case 6: output = &ctx->Rsi; break;
						case 7: output = &ctx->Rdi; break;
						case 8: output = &ctx->R8; break;
						case 9: output = &ctx->R9; break;
						case 10: output = &ctx->R10; break;
						case 11: output = &ctx->R11; break;
						case 12: output = &ctx->R12; break;
						case 13: output = &ctx->R13; break;
						case 14: output = &ctx->R14; break;
						case 15: output = &ctx->R15; break;
						default: break;
					}
					if (output != nullptr) {
						*output = value;
						ctx->Rip += 9;
						// tens of thousands of TLS loads: log the first 256 and a sample
						static std::atomic<uint64_t> fs_read_count {0};
						const auto nth = fs_read_count.fetch_add(1, std::memory_order_relaxed);
						if (nth < 256 || ((nth & 0xffffu) == 0)) {
							LOGF("FIRST_FRAME_AUDIT SYSAV_NATIVE_GUEST_FS_READ"
							     " pc=0x%016" PRIx64 " offset=0x%x"
							     " reg=%u value=0x%016" PRIx64
							     " total_intercepts_before_sample=%" PRIu64 "\n",
							     info->exception_address, disp, reg, value, nth);
						}
						return true;
					}
				}
			}
		}
#endif
		if (g_exec_native_fsbase != 0 && info->access_violation_vaddr <= 0x1000 &&
		    IsReadableRange(info->exception_address, 12)) {
			// guest TCB: fs:[0x00] self, fs:[0x10] pthread, fs:[0x28] errno, fs:[0x38] secondary
			// TLS. libkernel derefs fs:[0x10], so those mov forms are emulated
			const auto* ins  = reinterpret_cast<const uint8_t*>(info->exception_address);
			uint32_t    disp = 0;
			if (ins[0] == 0x64 && (ins[1] & 0xf8u) == 0x48 && (ins[2] == 0x8b || ins[2] == 0x89) &&
			    (ins[3] & 0xc7u) == 0x04 && ins[4] == 0x25) {
				std::memcpy(&disp, ins + 5, sizeof(disp));
				const uint32_t reg  = ((ins[3] >> 3u) & 7u) + ((ins[1] & 0x04u) != 0 ? 8u : 0u);
				auto*          ctx  = reinterpret_cast<CONTEXT*>(info->native_context);
				uint64_t*      slot = nullptr;
				switch (reg) {
					case 0: slot = &ctx->Rax; break;
					case 1: slot = &ctx->Rcx; break;
					case 2: slot = &ctx->Rdx; break;
					case 3: slot = &ctx->Rbx; break;
					case 5: slot = &ctx->Rbp; break;
					case 6: slot = &ctx->Rsi; break;
					case 7: slot = &ctx->Rdi; break;
					case 8: slot = &ctx->R8; break;
					case 9: slot = &ctx->R9; break;
					case 10: slot = &ctx->R10; break;
					case 11: slot = &ctx->R11; break;
					case 12: slot = &ctx->R12; break;
					case 13: slot = &ctx->R13; break;
					case 14: slot = &ctx->R14; break;
					case 15: slot = &ctx->R15; break;
					default: break;
				}
				if (slot != nullptr && info->access_violation_vaddr == disp &&
				    IsReadableRange(g_exec_native_fsbase + disp, 8)) {
					static std::atomic<uint64_t> exec_fs_access_count {0};
					if (ins[2] == 0x8b) {
						std::memcpy(slot,
						            reinterpret_cast<const void*>(g_exec_native_fsbase + disp), 8);
					} else {
						std::memcpy(reinterpret_cast<void*>(g_exec_native_fsbase + disp), slot, 8);
					}
					ctx->Rip += 9;
					const auto nth = exec_fs_access_count.fetch_add(1, std::memory_order_relaxed);
					if (nth < 256 || ((nth & 0xffffu) == 0)) {
						LOGF("FIRST_FRAME_AUDIT EXEC_GUEST_FS_%s"
						     " pid=%d pc=0x%016" PRIx64 " offset=0x%x reg=%u"
						     " value=0x%016" PRIx64 " fsbase=0x%016" PRIx64 "\n",
						     ins[2] == 0x8b ? "READ" : "WRITE", Libs::LibKernel::Process::GetPid(),
						     info->exception_address, disp, reg, *slot, g_exec_native_fsbase);
					}
					return true;
				}
			} else if (ins[0] == 0x64 && ins[1] == 0xc7 && ins[2] == 0x04 && ins[3] == 0x25) {
				std::memcpy(&disp, ins + 4, sizeof(disp));
				if (info->access_violation_vaddr == disp &&
				    IsWritableRange(g_exec_native_fsbase + disp, 4)) {
					uint32_t imm = 0;
					std::memcpy(&imm, ins + 8, sizeof(imm));
					std::memcpy(reinterpret_cast<void*>(g_exec_native_fsbase + disp), &imm, 4);
					reinterpret_cast<CONTEXT*>(info->native_context)->Rip += 12;
					static std::atomic<uint64_t> exec_fs_errno_writes {0};
					if (exec_fs_errno_writes.fetch_add(1, std::memory_order_relaxed) < 256) {
						LOGF("FIRST_FRAME_AUDIT EXEC_GUEST_FS_WRITE"
						     " pid=%d pc=0x%016" PRIx64 " offset=0x%x"
						     " imm32=0x%08x fsbase=0x%016" PRIx64 "\n",
						     Libs::LibKernel::Process::GetPid(), info->exception_address, disp, imm,
						     g_exec_native_fsbase);
					}
					return true;
				}
			}
			if (ins[0] == 0x64) {
				static std::atomic<uint32_t> exec_fs_unresolved {0};
				if (exec_fs_unresolved.fetch_add(1) < 64) {
					LOGF("FIRST_FRAME_AUDIT EXEC_GUEST_FS_UNRESOLVED"
					     " pid=%d pc=0x%016" PRIx64 " vaddr=0x%016" PRIx64 " fsbase=0x%016" PRIx64
					     " instruction=%02x %02x %02x %02x %02x %02x"
					     " unhandled_fs_access\n",
					     Libs::LibKernel::Process::GetPid(), info->exception_address,
					     info->access_violation_vaddr, g_exec_native_fsbase, ins[0], ins[1], ins[2],
					     ins[3], ins[4], ins[5]);
				}
			}
		}
		using CoreAccess = Common::HostException::AccessViolationType;
		using GpuAccess  = Libs::Graphics::PageFaultAccess;
		GpuAccess access;
		switch (info->access_violation_type) {
			case CoreAccess::Read: access = GpuAccess::Read; break;
			case CoreAccess::Write: access = GpuAccess::Write; break;
			case CoreAccess::Execute: access = GpuAccess::Execute; break;
			case CoreAccess::Unknown: return false;
		}
		if (Libs::LibKernel::Memory::HandleGpuFault(access, info->access_violation_vaddr)) {
			return true;
		}
	}
	const bool provenance_prepared = Common::HostException::IsUnhandledFaultProvenancePrepared();
	const bool provenance_captured = Common::HostException::CaptureUnhandledFaultProvenance(*info);
	if (provenance_prepared) {
		Common::HostException::NoteHostExit(provenance_captured ? 1 : 2,
		                                    provenance_captured ? 321 : 322, info);
		Log::Flush();
		std::_Exit(provenance_captured ? 321 : 322);
	}
	if (info->exception_address == 0x91000478d &&
	    std::getenv("KYTY_DIAGNOSTIC_SYSCORE_PRINTF_FAULT") != nullptr) {
		uint64_t probe = info->rbp;
		for (int i = 0; i < 8 && probe != 0; i++) {
			if (!IsReadableRange(probe, sizeof(uint64_t) * 2)) {
				break;
			}
			const auto* values = reinterpret_cast<const uint64_t*>(probe);
			if (values[1] == 0x9000001fe && probe >= 24 && IsReadableRange(probe - 24, 24)) {
				const auto*    saved          = reinterpret_cast<const uint64_t*>(probe - 24);
				const uint64_t arguments      = saved[0];
				const uint64_t format_pointer = saved[1];
				const uint64_t stream         = saved[2];
				char           format[129] {};
				bool           readable = format_pointer != 0;
				int            length   = 0;
				while (readable && length < 128 &&
				       format_pointer <= UINT64_MAX - static_cast<uint64_t>(length) - 1) {
					const auto byte_address = format_pointer + static_cast<uint64_t>(length);
					if (!IsReadableRange(byte_address, 1)) {
						readable = false;
						break;
					}
					const auto byte = *reinterpret_cast<const unsigned char*>(byte_address);
					if (byte == 0) {
						break;
					}
					format[length++] = byte >= 32 && byte <= 126 ? static_cast<char>(byte) : '.';
				}
				std::printf("SYSCORE_GUEST_PRINTF_FAULT_SOURCE syscore_return=%016" PRIx64
				            " stream=%016" PRIx64 " format=%016" PRIx64 " arguments=%016" PRIx64
				            " format_readable=%d format_preview=%s\n",
				            values[1], stream, format_pointer, arguments, readable, format);
				char argument_preview[97] {};
				int  bytes = 0;
				while (arguments != 0 && bytes < 96 &&
				       arguments <= UINT64_MAX - static_cast<uint64_t>(bytes) - 1 &&
				       IsReadableRange(arguments + static_cast<uint64_t>(bytes), 1)) {
					const auto value =
					    *reinterpret_cast<const uint8_t*>(arguments + static_cast<uint64_t>(bytes));
					if (value == 0) {
						break;
					}
					argument_preview[bytes++] =
					    value >= 32 && value <= 126 ? static_cast<char>(value) : '.';
				}
				std::printf("SYSCORE_GUEST_PRINTF_FAULT_ARGUMENT_STRING"
				            " bytes=%d source=%016" PRIx64 " preview=%s\n",
				            bytes, arguments, argument_preview);
				break;
			}
			if (values[0] <= probe || values[0] - probe > 0x1000000) {
				break;
			}
			probe = values[0];
		}
		std::fflush(stdout);
	}
	if (info->exception_address == 0x90003921e &&
	    std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD") != nullptr) {
		Libs::LibKernel::Memory::VirtualQueryInfo guest {};
		const int                                 rc = Libs::LibKernel::Memory::KernelVirtualQuery(
		    reinterpret_cast<const void*>(info->exception_address), 0, &guest, sizeof(guest));
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		MEMORY_BASIC_INFORMATION native {};
		const SIZE_T queried = VirtualQuery(reinterpret_cast<LPCVOID>(info->exception_address),
		                                    &native, sizeof(native));
		std::printf("SYSCORE_SCE_DTL_EXECUTE_FAULT_AUDIT"
		            " guest_pc=%016" PRIx64 " kernel_query_rc=%d guest_start=%016" PRIx64
		            " guest_end=%016" PRIx64 " guest_prot=0x%08x"
		            " guest_committed=%d native_query=%zu"
		            " native_base=%p native_region=%zu"
		            " native_state=0x%08x native_protect=0x%08x"
		            " native_type=0x%08x\n",
		            info->exception_address, rc, guest.start, guest.end, guest.protection,
		            guest.is_committed, static_cast<size_t>(queried), native.BaseAddress,
		            static_cast<size_t>(native.RegionSize), static_cast<unsigned>(native.State),
		            static_cast<unsigned>(native.Protect), static_cast<unsigned>(native.Type));
		std::fflush(stdout);
#endif
	}
	EXIT("Unhandled host exception: type=%u code=%u pc=0x%016" PRIx64
	     " access=%u address=0x%016" PRIx64 "\n",
	     static_cast<unsigned>(info->type), info->native_code, info->exception_address,
	     static_cast<unsigned>(info->access_violation_type), info->access_violation_vaddr);
}

static void EncodeId64(uint16_t in_id, std::string* out_id) {
	static const char* str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";
	if (in_id < 0x40u) {
		*out_id += str[in_id];
	} else {
		if (in_id < 0x1000u) {
			*out_id += str[static_cast<uint16_t>(in_id >> 6u) & 0x3fu];
			*out_id += str[in_id & 0x3fu];
		} else {
			*out_id += str[static_cast<uint16_t>(in_id >> 12u) & 0x3fu];
			*out_id += str[static_cast<uint16_t>(in_id >> 6u) & 0x3fu];
			*out_id += str[in_id & 0x3fu];
		}
	}
}

template <class T>
static void GetDynDataOs(Elf64* elf, T* out, Elf64_Sxword tag) {
	if (const auto* dyn = elf->GetDynValue(tag); dyn != nullptr) {
		*out = elf->GetDynamicData<T>(dyn->d_un.d_ptr);
	}
}

template <class T>
static void GetDynData(Elf64* elf, uint64_t base_vaddr, T* out, Elf64_Sxword tag) {
	if (const auto* dyn = elf->GetDynValue(tag); dyn != nullptr) {
		*out = reinterpret_cast<T>(base_vaddr + dyn->d_un.d_ptr);
	}
}

template <class T>
static void GetDynValue(Elf64* elf, T* out, Elf64_Sxword tag) {
	if (const auto* dyn = elf->GetDynValue(tag); dyn != nullptr) {
		*out = dyn->d_un.d_val;
	}
}

template <class T>
static void GetDynValues(Elf64* elf, T* out, Elf64_Sxword tag) {
	for (const auto* dyn: elf->GetDynList(tag)) {
		out->push_back(dyn->d_un.d_val);
	}
}

template <class T>
static void GetDynPtr(Elf64* elf, T* out, Elf64_Sxword tag) {
	if (const auto* dyn = elf->GetDynValue(tag); dyn != nullptr) {
		*out = dyn->d_un.d_ptr;
	}
}

static void KYTY_SYSV_ABI ProgramExitHandler() {
	Common::Singleton<RuntimeLinker>::Instance()->StopAllModules();

	LOGF("exit!!!\n");
}

template <class T>
static void GetDynModules(Elf64* elf, T* out, const char* names, Elf64_Sxword tag) {
	std::vector<uint64_t> needed_modules;
	GetDynValues(elf, &needed_modules, tag);
	for (auto need: needed_modules) {
		ModuleId id {};
		// id.id            = static_cast<int>((need >> 48u) & 0xffffu);
		EncodeId64(static_cast<uint16_t>((need >> 48u) & 0xffffu), &id.id);
		id.version_major = static_cast<int>((need >> 40u) & 0xffu);
		id.version_minor = static_cast<int>((need >> 32u) & 0xffu);
		id.name          = names + (need & 0xffffffff);
		out->push_back(id);
	}
}

template <class T>
static void GetDynLibs(Elf64* elf, T* out, const char* names, Elf64_Sxword tag) {
	std::vector<uint64_t> needed_modules;
	GetDynValues(elf, &needed_modules, tag);
	for (auto need: needed_modules) {
		LibraryId id {};
		// id.id      = static_cast<int>((need >> 48u) & 0xffffu);
		EncodeId64(static_cast<uint16_t>((need >> 48u) & 0xffffu), &id.id);
		id.version = static_cast<int>((need >> 32u) & 0xffffu);
		id.name    = names + (need & 0xffffffff);
		out->push_back(id);
	}
}

static RelocationInfo GetRelocationInfo(Elf64_Rela* r, Program* program) {
	KYTY_PROFILER_FUNCTION();

	RelocationInfo ret;
	// SymbolRecord   sr {};

	auto         type    = r->GetType();
	auto         symbol  = r->GetSymbol();
	Elf64_Sxword addend  = r->r_addend;
	auto*        symbols = program->dynamic_info->symbol_table;
	auto*        names   = program->dynamic_info->str_table;
	ret.base_vaddr       = program->base_vaddr;
	ret.vaddr            = ret.base_vaddr + r->r_offset;
	ret.bind_self        = false;

	switch (type) {
		case R_X86_64_GLOB_DAT:
		case R_X86_64_JUMP_SLOT: addend = 0; [[fallthrough]];
		case R_X86_64_64: {
			auto         sym          = symbols[symbol];
			auto         bind         = sym.GetBind();
			auto         sym_type     = sym.GetType();
			uint64_t     symbol_vaddr = 0;
			SymbolRecord sr {};
			switch (sym_type) {
				case STT_NOTYPE: ret.type = SymbolType::NoType; break;
				case STT_FUNC: ret.type = SymbolType::Func; break;
				case STT_OBJECT: ret.type = SymbolType::Object; break;
				default: EXIT("unknown symbol type: %d\n", (int)sym_type);
			}
			switch (bind) {
				case STB_LOCAL:
					symbol_vaddr = ret.base_vaddr + sym.st_value;
					ret.bind     = BindType::Local;
					break;
				case STB_GLOBAL: ret.bind = BindType::Global; [[fallthrough]];
				case STB_WEAK: {
					ret.bind = (ret.bind == BindType::Unknown ? BindType::Weak : ret.bind);
					ret.name = names + sym.st_name;
					program->rt->Resolve(ret.name, ret.type, program, &sr, &ret.bind_self);
					if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_PRINTF_FAULT") != nullptr &&
					    Common::PathToString(program->file_name).find("SceSysCore.elf") !=
					        std::string::npos &&
					    (ret.name.rfind("pDBDcY6uLSA", 0) == 0 ||
					     ret.name.rfind("fffwELXNVFA", 0) == 0 ||
					     ret.name.rfind("hcuQgD53UxM", 0) == 0 ||
					     ret.name.rfind("qIjSKZfWk5I", 0) == 0 ||
					     ret.name.rfind("3Nr9caNHhyg", 0) == 0 ||
					     ret.name.rfind("IUfBO5UIZNc", 0) == 0 ||
					     ret.name.rfind("S-AQZoElaRM", 0) == 0 ||
					     ret.name.rfind("kdguLiAheLI", 0) == 0)) {
						LOGF("SYSCORE_FORMATTED_IO_IMPORT_RESOLVE requested=%s"
						     " target=%s address=%016" PRIx64 " bound_self=%d\n",
						     ret.name.c_str(), sr.name.c_str(), sr.vaddr, ret.bind_self);
					}
					symbol_vaddr = sr.vaddr;
				} break;
				default: EXIT("unknown bind: %d\n", (int)bind);
			}
			ret.resolved = (symbol_vaddr != 0 || ret.bind == BindType::Weak);
			ret.value    = (ret.resolved ? symbol_vaddr + addend : 0);
			ret.name     = sr.name;
			ret.dbg_name = sr.dbg_name;
		} break;
		case R_X86_64_RELATIVE:
			ret.value    = ret.base_vaddr + addend;
			ret.resolved = true;
			break;
		case R_X86_64_DTPMOD64:
			ret.value    = reinterpret_cast<uint64_t>(program);
			ret.resolved = true;
			ret.type     = SymbolType::TlsModule;
			ret.bind     = BindType::Local;
			ret.dbg_name = Common::PathToString(program->file_name);
			break;
		default: EXIT("unknown type: %d\n", (int)type);
	}

	return ret;
}

static bool RelocateRecord(uint32_t index, Elf64_Rela* r, Program* program, bool jmprela_table) {
	KYTY_PROFILER_FUNCTION();

	const auto ri      = GetRelocationInfo(r, program);
	auto       value   = ri.value;
	bool       stubbed = false;
	if (!ri.resolved) {
		const bool weak = ri.bind == BindType::Weak || !program->fail_if_global_not_resolved;
		if (!weak) {
			LOGF("Stubbed: %s\n",
			     fmt::format("[{:016x}] <- {:016x}, {}, {}, {}, {}", ri.vaddr, ri.value, ri.name,
			                 magic_enum::enum_name(ri.type), magic_enum::enum_name(ri.bind),
			                 ri.dbg_name).c_str());
		}
		if (ri.type == SymbolType::Object) {
			value = g_invalid_memory;
		} else {
			value   = RegisterStubbedImport(index, program, ri);
			stubbed = true;
		}
	}

	const bool patched = PatchGuestMemory64(ri.vaddr, value);
	if (patched && stubbed) {
		LOGF("Relocate: unresolved %s import patched to stub [%u] [%016" PRIx64 "] <- %016" PRIx64
		     ", %s, %s, %s, %s\n",
		     jmprela_table ? "PLT" : "non-PLT", index, ri.vaddr, value, ri.name.c_str(),
		     magic_enum::enum_name(ri.type), magic_enum::enum_name(ri.bind),
		     Common::PathToString(program->file_name).c_str());
	}

	if (program->dbg_print_reloc && patched && !ri.bind_self &&
	    (ri.bind == BindType::Global || ri.bind == BindType::Weak ||
	     ri.type == SymbolType::TlsModule)) {
		LOGF("Relocate: %s\n",
		     fmt::format("[{:016x}] <- {:016x}, {}, {}, {}, {}", ri.vaddr, ri.value, ri.name,
		                 magic_enum::enum_name(ri.type), magic_enum::enum_name(ri.bind),
		                 ri.dbg_name).c_str());
	}
	return ri.resolved;
}

static void ForEachRelocation(Program* program, auto&& func) {
	const auto& info = *program->dynamic_info;
	for (uint32_t i = 0; i < info.rela_table_total_size / sizeof(Elf64_Rela); ++i) {
		func(info.rela_table + i, i, false);
	}
	for (uint32_t i = 0; i < info.jmprela_table_size / sizeof(Elf64_Rela); ++i) {
		func(info.jmprela_table + i, i, true);
	}
}

static KYTY_MS_ABI uint8_t* TlsMainGetAddr() {
	EXIT_IF(g_tls_main_program == nullptr);

	if (g_tls_cached_main_program == g_tls_main_program && g_tls_cached_main_tcb != nullptr) {
		return g_tls_cached_main_tcb;
	}

	g_tls_cached_main_program = g_tls_main_program;
	g_tls_cached_main_tcb =
	    RuntimeLinker::TlsGetAddr(g_tls_main_program) + g_tls_main_program->tls.tcb_offset;
	return g_tls_cached_main_tcb;
}

static void PatchProgram(Program* program, uint64_t address, uint64_t size) {
	EXIT_IF(program == nullptr);
	EXIT_IF(program->elf == nullptr);

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (program->file_name.filename() == "libkernel.sprx" && address == program->base_vaddr) {
		for (const auto& descriptor: g_native_libkernel_wrappers) {
			if (size < descriptor.offset + 7) {
				LOGF("NATIVE_LIBKERNEL_TRAP_UNVERIFIED_LAYOUT path=%s syscall=0x%x"
				     " executable_size=0x%" PRIx64 "\n",
				     Common::PathToString(program->file_name).c_str(), descriptor.number, size);
				continue;
			}
			auto* const wrapper =
			    reinterpret_cast<uint8_t*>(program->base_vaddr + descriptor.offset);
			const bool known_prefix = std::memcmp(wrapper, descriptor.signature, 7) == 0;
			if (known_prefix &&
			    (size < descriptor.offset + sizeof(descriptor.signature) ||
			     std::memcmp(wrapper, descriptor.signature, sizeof(descriptor.signature)) != 0)) {
				EXIT("Unsupported libkernel native 0x%x wrapper at +0x%x: incomplete or mismatched "
				     "signature\n",
				     descriptor.number, descriptor.offset);
			}
			if (known_prefix) {
				const uint64_t  site = program->base_vaddr + descriptor.offset + 10;
				std::lock_guard lock(g_native_libkernel_trap_mutex);
				const auto      existing = std::find_if(
				    g_native_libkernel_traps.begin(), g_native_libkernel_traps.end(),
				    [&](const NativeLibkernelTrap& trap) { return trap.site == site; });
				EXIT_IF(existing != g_native_libkernel_traps.end() &&
				        (existing->owner != program || existing->number != descriptor.number));
				if (existing == g_native_libkernel_traps.end()) {
					g_native_libkernel_traps.push_back({program, site, descriptor.number});
				}
				wrapper[11] = 0x0b;
				EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(site, 2));
				LOGF("NATIVE_LIBKERNEL_TRAP_INSTALLED pc=0x%016" PRIx64
				     " syscall=0x%x signature_match=1\n",
				     site, descriptor.number);
			} else {
				LOGF("NATIVE_LIBKERNEL_TRAP_UNVERIFIED_LAYOUT path=%s syscall=0x%x"
				     "\n",
				     Common::PathToString(program->file_name).c_str(), descriptor.number);
			}
		}
	}
#endif

	if (program->file_name.filename() == "libkernel.sprx" && size >= 0x4700c &&
	    address == program->base_vaddr) {
		constexpr uint8_t expected_call[5] = {0xe8, 0x4d, 0x14, 0xfd, 0xff};
		auto* const       call_site  = reinterpret_cast<uint8_t*>(program->base_vaddr + 0x3ffee);
		auto* const       trampoline = reinterpret_cast<uint8_t*>(program->base_vaddr + 0x47000);
		constexpr uint8_t empty_trampoline[12] = {};
		if (std::memcmp(call_site, expected_call, sizeof(expected_call)) == 0 &&
		    std::memcmp(trampoline, empty_trampoline, sizeof(empty_trampoline)) == 0) {
			trampoline[0]         = 0x48;
			trampoline[1]         = 0xb8;
			const uint64_t target = reinterpret_cast<uint64_t>(Libs::LibKernel::KernelSysctl);
			std::memcpy(trampoline + 2, &target, sizeof(target));
			trampoline[10]             = 0xff;
			trampoline[11]             = 0xe0;
			const int32_t displacement = static_cast<int32_t>(
			    reinterpret_cast<intptr_t>(trampoline) - reinterpret_cast<intptr_t>(call_site + 5));
			std::memcpy(call_site + 1, &displacement, sizeof(displacement));
			LOGF("KERNEL_SYSCTL patched only thr_init.c kern.usrstack call at 0x%016" PRIx64 "\n",
			     reinterpret_cast<uint64_t>(call_site));
		} else {
			LOGF("KERNEL_SYSCTL thr_init.c signature mismatch; no patch applied\n");
		}
		if (size >= 0x4702c) {
			constexpr uint8_t expected_pagesize[5] = {0xe8, 0x79, 0xfe, 0xfc, 0xff};
			auto* const pagesize_call = reinterpret_cast<uint8_t*>(program->base_vaddr + 0x40032);
			auto* const pagesize_trampoline =
			    reinterpret_cast<uint8_t*>(program->base_vaddr + 0x47020);
			if (std::memcmp(pagesize_call, expected_pagesize, sizeof(expected_pagesize)) == 0 &&
			    std::memcmp(pagesize_trampoline, empty_trampoline, sizeof(empty_trampoline)) == 0) {
				pagesize_trampoline[0] = 0x48;
				pagesize_trampoline[1] = 0xb8;
				const uint64_t target  = reinterpret_cast<uint64_t>(Libs::Posix::getpagesize);
				std::memcpy(pagesize_trampoline + 2, &target, sizeof(target));
				pagesize_trampoline[10] = 0xff;
				pagesize_trampoline[11] = 0xe0;
				const int32_t displacement =
				    static_cast<int32_t>(reinterpret_cast<intptr_t>(pagesize_trampoline) -
					                     reinterpret_cast<intptr_t>(pagesize_call + 5));
				std::memcpy(pagesize_call + 1, &displacement, sizeof(displacement));
				LOGF("KERNEL_PAGESIZE patched native thr_init.c getpagesize at 0x%016" PRIx64 "\n",
				     reinterpret_cast<uint64_t>(pagesize_call));
			} else {
				LOGF("KERNEL_PAGESIZE native getpagesize signature mismatch; not patched\n");
			}
		}
		constexpr uint8_t expected_native_once[12] = {0x55, 0x48, 0x89, 0xe5, 0x41, 0x57,
		                                              0x41, 0x56, 0x41, 0x55, 0x41, 0x54};
		auto* const       native_once = reinterpret_cast<uint8_t*>(program->base_vaddr + 0x9780);
		if (std::memcmp(native_once, expected_native_once, sizeof(expected_native_once)) == 0) {
			native_once[0]        = 0x48;
			native_once[1]        = 0xb8;
			const uint64_t target = reinterpret_cast<uint64_t>(Libs::Posix::pthread_once);
			std::memcpy(native_once + 2, &target, sizeof(target));
			native_once[10] = 0xff;
			native_once[11] = 0xe0;
			LOGF("KERNEL_PTHREAD_ONCE redirected native implementation at 0x%016" PRIx64 "\n",
			     reinterpret_cast<uint64_t>(native_once));
		} else {
			LOGF("KERNEL_PTHREAD_ONCE native implementation signature mismatch; not patched\n");
		}
		constexpr uint8_t expected_native_open[12] = {0x55, 0x48, 0x89, 0xe5, 0x41, 0x57,
		                                              0x41, 0x56, 0x41, 0x55, 0x41, 0x54};
		auto* const       native_open = reinterpret_cast<uint8_t*>(program->base_vaddr + 0xe020);
		if (std::memcmp(native_open, expected_native_open, sizeof(expected_native_open)) == 0) {
			native_open[0]        = 0x48;
			native_open[1]        = 0xb8;
			const uint64_t target = reinterpret_cast<uint64_t>(Libs::LibKernel::KernelNativeOpen);
			std::memcpy(native_open + 2, &target, sizeof(target));
			native_open[10] = 0xff;
			native_open[11] = 0xe0;
			LOGF("KERNEL_NATIVE_OPEN redirected native implementation at 0x%016" PRIx64 "\n",
			     reinterpret_cast<uint64_t>(native_open));
		} else {
			LOGF("KERNEL_NATIVE_OPEN native implementation signature mismatch; not patched\n");
		}
		// write, close and __error start from %fs:0x10, which has no guest base here
		constexpr uint8_t expected_native_write[12] = {0x55, 0x48, 0x89, 0xe5, 0x41, 0x57,
		                                               0x41, 0x56, 0x41, 0x54, 0x53, 0x41};
		auto* const       native_write = reinterpret_cast<uint8_t*>(program->base_vaddr + 0xe8b0);
		if (std::memcmp(native_write, expected_native_write, sizeof(expected_native_write)) == 0) {
			native_write[0]       = 0x48;
			native_write[1]       = 0xb8;
			const uint64_t target = reinterpret_cast<uint64_t>(Libs::LibKernel::KernelNativeWrite);
			std::memcpy(native_write + 2, &target, sizeof(target));
			native_write[10] = 0xff;
			native_write[11] = 0xe0;
			LOGF("KERNEL_NATIVE_WRITE redirected native implementation at 0x%016" PRIx64 "\n",
			     reinterpret_cast<uint64_t>(native_write));
		} else {
			LOGF("KERNEL_NATIVE_WRITE native implementation signature mismatch; not patched\n");
		}
		constexpr uint8_t expected_native_close[12] = {0x55, 0x48, 0x89, 0xe5, 0x41, 0x57,
		                                               0x41, 0x56, 0x53, 0x50, 0x89, 0xfb};
		auto* const       native_close = reinterpret_cast<uint8_t*>(program->base_vaddr + 0xdc40);
		if (std::memcmp(native_close, expected_native_close, sizeof(expected_native_close)) == 0) {
			native_close[0]       = 0x48;
			native_close[1]       = 0xb8;
			const uint64_t target = reinterpret_cast<uint64_t>(Libs::LibKernel::KernelNativeClose);
			std::memcpy(native_close + 2, &target, sizeof(target));
			native_close[10] = 0xff;
			native_close[11] = 0xe0;
			LOGF("KERNEL_NATIVE_CLOSE redirected native implementation at 0x%016" PRIx64 "\n",
			     reinterpret_cast<uint64_t>(native_close));
		} else {
			LOGF("KERNEL_NATIVE_CLOSE native implementation signature mismatch; not patched\n");
		}
		constexpr uint8_t expected_native_error[12] = {0x55, 0x48, 0x89, 0xe5, 0x48, 0x8b,
		                                               0x0d, 0x35, 0x95, 0x06, 0x00, 0x48};
		auto* const       native_error = reinterpret_cast<uint8_t*>(program->base_vaddr + 0x2e00);
		if (std::memcmp(native_error, expected_native_error, sizeof(expected_native_error)) == 0) {
			native_error[0]       = 0x48;
			native_error[1]       = 0xb8;
			const uint64_t target = reinterpret_cast<uint64_t>(Libs::Posix::GetErrorAddr);
			std::memcpy(native_error + 2, &target, sizeof(target));
			native_error[10] = 0xff;
			native_error[11] = 0xe0;
			LOGF("KERNEL_NATIVE_ERROR redirected native implementation at 0x%016" PRIx64 "\n",
			     reinterpret_cast<uint64_t>(native_error));
		} else {
			LOGF("KERNEL_NATIVE_ERROR native implementation signature mismatch; not patched\n");
		}
		constexpr uint8_t expected_native_getpid[12] = {0x48, 0xc7, 0xc0, 0x14, 0x00, 0x00,
		                                                0x00, 0x49, 0x89, 0xca, 0x0f, 0x05};
		auto* const       native_getpid = reinterpret_cast<uint8_t*>(program->base_vaddr + 0x4e0);
		if (std::memcmp(native_getpid, expected_native_getpid, sizeof(expected_native_getpid)) ==
		    0) {
			// getpid can't fail, so the wrapper becomes mov eax, pid; ret. Its syscall would enter
			// the Windows service of the same number.
			const int32_t pid = Libs::LibKernel::Process::GetPid();
			native_getpid[0]  = 0xb8;
			std::memcpy(native_getpid + 1, &pid, sizeof(pid));
			native_getpid[5] = 0xc3;
			LOGF("KERNEL_NATIVE_GETPID native wrapper at 0x%016" PRIx64 " returns %d\n",
			     reinterpret_cast<uint64_t>(native_getpid), pid);
		} else {
			LOGF("KERNEL_NATIVE_GETPID native wrapper signature mismatch; not patched\n");
		}
		const bool redirect_raw_syscalls =
		    std::getenv("KYTY_DIAGNOSTIC_REDIRECT_LIBKERNEL_RAW_SYSCALLS") != nullptr;
		// unknown nodes give 0x80020002 instead of a positive NTSTATUS-derived value; importers
		// check the sign
		if (redirect_raw_syscalls ||
		    std::getenv("KYTY_DIAGNOSTIC_REDIRECT_LIBKERNEL_SYSCTL") != nullptr) {
			constexpr uint8_t expected_sysctl_stub[24] = {
			    0x48, 0xc7, 0xc0, 0xca, 0x00, 0x00, 0x00, 0x49, 0x89, 0xca, 0x0f, 0x05,
			    0x72, 0x01, 0xc3, 0x48, 0x8d, 0x0d, 0x7e, 0xf1, 0xff, 0xff, 0xff, 0xe1};
			auto* const sysctl_stub = reinterpret_cast<uint8_t*>(program->base_vaddr + 0xf40);
			if (std::memcmp(sysctl_stub, expected_sysctl_stub, sizeof(expected_sysctl_stub)) == 0) {
				// libkernel's own sysctls all end at this stub's syscall. Replacement keeps the
				// jump to cerror (+0xd4)
				constexpr uint8_t stub_tail[12] = {0xff, 0xd0, 0x59, 0x85, 0xc0, 0x0f,
				                                   0x85, 0x7e, 0xf1, 0xff, 0xff, 0xc3};
				sysctl_stub[0]                  = 0x51;
				sysctl_stub[1]                  = 0x48;
				sysctl_stub[2]                  = 0xb8;
				const uint64_t target =
				    reinterpret_cast<uint64_t>(Libs::LibKernel::KernelSysctlStub);
				std::memcpy(sysctl_stub + 3, &target, sizeof(target));
				std::memcpy(sysctl_stub + 11, stub_tail, sizeof(stub_tail));
				LOGF("KERNEL_SYSCTL redirected native __sysctl stub at 0x%016" PRIx64 "\n",
				     reinterpret_cast<uint64_t>(sysctl_stub));
			} else {
				LOGF("KERNEL_SYSCTL native __sysctl stub signature mismatch; not patched\n");
			}
		}
		// unhandled numbers fail with ENOSYS, not whatever the Windows service returns
		if (redirect_raw_syscalls) {
			constexpr uint8_t empty_stub[33] = {};
			auto* const       raw_stub = reinterpret_cast<uint8_t*>(program->base_vaddr + 0x47040);
			if (size >= 0x47061 && std::memcmp(raw_stub, empty_stub, sizeof(empty_stub)) == 0) {
				// push 0; push rsp; push rax; mov rax, target; call rax; add rsp, 16; pop rcx; test
				// ecx, ecx; jnz +1; ret; mov eax, ecx; jmp cerror. eax (the number) is the seventh
				// argument, the pushed zero is the errno slot the eighth points at.
				constexpr uint8_t stub_head[6]  = {0x6a, 0x00, 0x54, 0x50, 0x48, 0xb8};
				constexpr uint8_t stub_tail[15] = {0xff, 0xd0, 0x48, 0x83, 0xc4, 0x10, 0x59, 0x85,
				                                   0xc9, 0x75, 0x01, 0xc3, 0x89, 0xc8, 0xe9};
				std::memcpy(raw_stub, stub_head, sizeof(stub_head));
				const uint64_t target =
				    reinterpret_cast<uint64_t>(Libs::LibKernel::KernelRawSyscallStub);
				std::memcpy(raw_stub + 6, &target, sizeof(target));
				std::memcpy(raw_stub + 14, stub_tail, sizeof(stub_tail));
				const int32_t cerror = 0xd4 - (0x47040 + 33);
				std::memcpy(raw_stub + 29, &cerror, sizeof(cerror));
				constexpr uint8_t expected_tail[11] = {0x49, 0x89, 0xca, 0x0f, 0x05, 0x72,
				                                       0x01, 0xc3, 0x48, 0x8d, 0x0d};
				uint32_t          redirected        = 0;
				// only wrappers shaped mov rax, imm32; mov r10, rcx; syscall; jb; ret; lea rcx,
				// [cerror]; jmp rcx. The nine others (pipe, rfork, exit, execve, sigprocmask,
				// _umtx_op among them) keep their syscall
				for (uint32_t offset = 0x2a0; offset <= 0x2d20; offset++) {
					auto* const wrapper = reinterpret_cast<uint8_t*>(program->base_vaddr + offset);
					int32_t     lea     = 0;
					std::memcpy(&lea, wrapper + 18, sizeof(lea));
					if (wrapper[0] != 0x48 || wrapper[1] != 0xc7 || wrapper[2] != 0xc0 ||
					    std::memcmp(wrapper + 7, expected_tail, sizeof(expected_tail)) != 0 ||
					    wrapper[22] != 0xff || wrapper[23] != 0xe1 ||
					    static_cast<int32_t>(offset) + 22 + lea != 0xd4) {
						continue;
					}
					uint32_t number = 0;
					std::memcpy(&number, wrapper + 3, sizeof(number));
					const int32_t displacement = 0x47040 - static_cast<int32_t>(offset + 10);
					// mov eax, number; jmp raw_stub, and ud2 where the syscall instruction was.
					wrapper[0] = 0xb8;
					std::memcpy(wrapper + 1, &number, sizeof(number));
					wrapper[5] = 0xe9;
					std::memcpy(wrapper + 6, &displacement, sizeof(displacement));
					wrapper[11] = 0x0b;
					redirected++;
				}
				LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_REDIRECT_LIBKERNEL_RAW_SYSCALLS redirected %u "
				     "wrappers to the bridge; a number without a handler fails with ENOSYS "
				     "NON_AUTHENTIC\n",
				     redirected);
			} else {
				LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_REDIRECT_LIBKERNEL_RAW_SYSCALLS no empty stub "
				     "area at +0x47040; not patched\n");
			}
		}
		// log-only census of reached wrappers; the redirect wins if both are set
		if (std::getenv("KYTY_DIAGNOSTIC_CENSUS_LIBKERNEL_RAW_SYSCALLS") != nullptr) {
			constexpr uint8_t empty_stub[77] = {};
			auto* const census_stub = reinterpret_cast<uint8_t*>(program->base_vaddr + 0x47080);
			if (redirect_raw_syscalls) {
				LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_CENSUS_LIBKERNEL_RAW_SYSCALLS skipped; "
				     "KYTY_DIAGNOSTIC_REDIRECT_LIBKERNEL_RAW_SYSCALLS is set and its wrappers "
				     "execute no syscall instruction\n");
			} else if (size >= 0x470cd &&
			           std::memcmp(census_stub, empty_stub, sizeof(empty_stub)) == 0) {
				// pushfq; push rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11, rbp; mov rbp, rsp; cld;
				// mov edi, eax; mov rsi, [rbp + 0x60]; sub rsp, 0x200; and rsp, -16; fxsave64
				// [rsp]; mov rax, target; call rax; fxrstor64 [rsp]; mov rsp, rbp; the pops in
				// reverse; popfq; ret. The syscall and the jb after it read registers and CF that a
				// sysv call may clobber, so all of them come back as they were. [rbp + 0x60] is the
				// wrapper's return address.
				constexpr uint8_t stub_head[43] = {
				    0x9c, 0x50, 0x51, 0x52, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41,
				    0x52, 0x41, 0x53, 0x55, 0x48, 0x89, 0xe5, 0xfc, 0x89, 0xc7, 0x48,
				    0x8b, 0x75, 0x60, 0x48, 0x81, 0xec, 0x00, 0x02, 0x00, 0x00, 0x48,
				    0x83, 0xe4, 0xf0, 0x48, 0x0f, 0xae, 0x04, 0x24, 0x48, 0xb8};
				constexpr uint8_t stub_tail[26] = {
				    0xff, 0xd0, 0x48, 0x0f, 0xae, 0x0c, 0x24, 0x48, 0x89, 0xec, 0x5d, 0x41, 0x5b,
				    0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, 0x5f, 0x5e, 0x5a, 0x59, 0x58, 0x9d, 0xc3};
				std::memcpy(census_stub, stub_head, sizeof(stub_head));
				const uint64_t target =
				    reinterpret_cast<uint64_t>(Libs::LibKernel::KernelRawSyscallCensus);
				std::memcpy(census_stub + 43, &target, sizeof(target));
				std::memcpy(census_stub + 51, stub_tail, sizeof(stub_tail));
				uint32_t hooked = 0;
				// mov eax, number; jmp island over mov rax, number; the island (7 bytes of int3
				// padding) is call census_stub; jmp back. The syscall keeps its address since
				// libkernel checks post-syscall pcs by address (+0x27e60) and by the 5 bytes before
				// (+0x27ef0).
				const auto hook = [&](uint32_t entry, uint32_t island) {
					constexpr uint8_t expected_head[5]    = {0x49, 0x89, 0xca, 0x0f, 0x05};
					constexpr uint8_t expected_padding[7] = {0xcc, 0xcc, 0xcc, 0xcc,
					                                         0xcc, 0xcc, 0xcc};
					auto* const wrapper = reinterpret_cast<uint8_t*>(program->base_vaddr + entry);
					auto* const pad     = reinterpret_cast<uint8_t*>(program->base_vaddr + island);
					if (wrapper[0] != 0x48 || wrapper[1] != 0xc7 || wrapper[2] != 0xc0 ||
					    std::memcmp(wrapper + 7, expected_head, sizeof(expected_head)) != 0 ||
					    std::memcmp(pad, expected_padding, sizeof(expected_padding)) != 0) {
						return;
					}
					uint32_t number = 0;
					std::memcpy(&number, wrapper + 3, sizeof(number));
					const int32_t displacement = 0x47080 - static_cast<int32_t>(island + 5);
					wrapper[0]                 = 0xb8;
					std::memcpy(wrapper + 1, &number, sizeof(number));
					wrapper[5] = 0xeb;
					wrapper[6] = static_cast<uint8_t>(island - (entry + 7));
					pad[0]     = 0xe8;
					std::memcpy(pad + 1, &displacement, sizeof(displacement));
					pad[5] = 0xeb;
					pad[6] = static_cast<uint8_t>(entry - island);
					hooked++;
				};
				constexpr uint8_t expected_tail[6] = {0x72, 0x01, 0xc3, 0x48, 0x8d, 0x0d};
				for (uint32_t offset = 0x2a0; offset <= 0x2d20; offset++) {
					auto* const wrapper = reinterpret_cast<uint8_t*>(program->base_vaddr + offset);
					int32_t     lea     = 0;
					std::memcpy(&lea, wrapper + 18, sizeof(lea));
					if (std::memcmp(wrapper + 12, expected_tail, sizeof(expected_tail)) == 0 &&
					    wrapper[22] == 0xff && wrapper[23] == 0xe1 &&
					    static_cast<int32_t>(offset) + 22 + lea == 0xd4) {
						hook(offset, offset + 24);
					}
				}
				// pipe, setlogin, reboot and _umtx_op open with the same two instructions and have
				// int3 padding within a short jump. execve (+0x17d), rfork_thread (+0x1a9, +0x1ca),
				// getcontext (+0x2c4) and setcontext (+0x2ef) keep their bytes: trap flag just set,
				// no return address on top of the stack at the syscall, or only three bytes of
				// padding
				hook(0xf0, 0x114);
				hook(0x120, 0x145);
				hook(0x150, 0x169);
				hook(0x380, 0x392);
				LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_CENSUS_LIBKERNEL_RAW_SYSCALLS hooked %u "
				     "wrappers; each reports its number and caller and then executes its own "
				     "syscall instruction NON_AUTHENTIC\n",
				     hooked);
			} else {
				LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_CENSUS_LIBKERNEL_RAW_SYSCALLS no empty stub "
				     "area at +0x47080; not patched\n");
			}
		}
	}

	// Sce.Vsh.ShellUI.Ime is an encrypted SELF here, so TryLoadAndGetInterface<IImeSettings> throws
	// out of both boot-path callers. Both carry on when it returns false
	if (program->file_name.filename() == "Sce.Vsh.ShellUI.Legacy.dll.sprx" && size >= 0x1e5a2e &&
	    address == program->base_vaddr &&
	    std::getenv("KYTY_DIAGNOSTIC_SKIP_ABSENT_IME_INTERFACE") != nullptr) {
		constexpr uint8_t expected_onloaded_call[5] = {0xe8, 0xc0, 0x78, 0x0f, 0x00};
		constexpr uint8_t expected_focus_call[5]    = {0xe8, 0x5a, 0x71, 0x0f, 0x00};
		auto* const onloaded_call = reinterpret_cast<uint8_t*>(program->base_vaddr + 0x1e52c3);
		auto* const focus_call    = reinterpret_cast<uint8_t*>(program->base_vaddr + 0x1e5a29);
		if (std::memcmp(onloaded_call, expected_onloaded_call, sizeof(expected_onloaded_call)) ==
		        0 &&
		    std::memcmp(focus_call, expected_focus_call, sizeof(expected_focus_call)) == 0) {
			// xor eax,eax over the call; callers zero the out local in their prologue
			constexpr uint8_t answer_false[5] = {0x33, 0xc0, 0x90, 0x90, 0x90};
			std::memcpy(onloaded_call, answer_false, sizeof(answer_false));
			std::memcpy(focus_call, answer_false, sizeof(answer_false));
			LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_SKIP_ABSENT_IME_INTERFACE site=0x%016" PRIx64
			     " NON_AUTHENTIC\n",
			     reinterpret_cast<uint64_t>(onloaded_call));
			LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_SKIP_ABSENT_IME_INTERFACE site=0x%016" PRIx64
			     " NON_AUTHENTIC\n",
			     reinterpret_cast<uint64_t>(focus_call));
		} else {
			LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_SKIP_ABSENT_IME_INTERFACE call signature mismatch; "
			     "not patched\n");
		}
	}

	if (size >= 12) {
		// Replace guest stack-canary/errno stores through fs:[0x28] with nops.
		// Windows x64 cannot host guest FS directly, and an unpatched shared-library access faults
		// at address 0x28.
		const uint8_t fs_store_pattern[8] = {0x64, 0xc7, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00};
		auto*         start_ptr           = reinterpret_cast<uint8_t*>(address);
		auto*         end_ptr             = start_ptr + size - 12;

		for (auto* ptr = start_ptr; ptr <= end_ptr; ptr++) {
			if (memcmp(ptr, fs_store_pattern, sizeof(fs_store_pattern)) == 0) {
				LOGF("Patch fs:[0x28] store at addr: [%016" PRIx64 "]\n",
				     reinterpret_cast<uint64_t>(ptr));
				if (ptr + 16 < start_ptr + size && ptr[12] == 0xcd && ptr[13] == 0x45 &&
				    ptr[14] == 0x90 && ptr[15] == 0x0f && ptr[16] == 0x0b) {
					ptr[0] = 0x5d; // pop rbp
					ptr[1] = 0xc3; // ret
					std::memset(ptr + 2, 0x90, 15);
				} else {
					std::memset(ptr, 0x90, 12);
				}
			}
		}
	}

	if (!program->elf->IsShared() && program->tls.handler_vaddr != 0 &&
	    size >= Jit::Call9::GetSize()) {
		// Replace:
		//   66 66 66
		//   mov <reg>, qword ptr fs:[0x00]
		// with:
		//   call <handler>
		//   mov <reg>,rax
		//   nop ...
		const uint8_t tls_pattern[5]       = {0x64, 0x48, 0x8B, 0x00, 0x25};
		const uint8_t zero_displacement[4] = {};

		EXIT_IF(Jit::Call9::GetSize() != 9);

		auto* start_ptr = reinterpret_cast<uint8_t*>(address);
		auto* end_ptr   = start_ptr + size - Jit::Call9::GetSize();

		for (auto* ptr = start_ptr; ptr <= end_ptr; ptr++) {
			auto*  inst_ptr     = ptr;
			size_t prefix_count = 0;
			while (prefix_count < 3 && inst_ptr < start_ptr + size && *inst_ptr == 0x66) {
				inst_ptr++;
				prefix_count++;
			}

			if (inst_ptr + Jit::Call9::GetSize() > start_ptr + size) {
				break;
			}

			const uint8_t modrm = inst_ptr[3];
			if (memcmp(inst_ptr, tls_pattern, 3) == 0 && (modrm & 0xc7u) == 0x04u &&
			    inst_ptr[4] == tls_pattern[4] &&
			    memcmp(inst_ptr + 5, zero_displacement, sizeof(zero_displacement)) == 0) {
				LOGF("Patch tls at addr: [%016" PRIx64 "]\n", reinterpret_cast<uint64_t>(inst_ptr));

				const auto reg = (modrm >> 3u) & 7u;
				EXIT_NOT_IMPLEMENTED(reg == 4u);

				// A raw scan can encounter a 0x66 in the preceding instruction, so do not
				// overwrite it. Call9 starts with REX.W to neutralize genuine 0x66
				// prefixes on AMD processors (before it could turn E8 into callw 16bit).
				auto* code = new (inst_ptr) Jit::Call9;
				code->SetFunc(reg == 0
				                  ? program->tls.handler_vaddr
				                  : program->tls.handler_vaddr + Jit::TlsRegStub::GetOffset(reg));
				ptr += prefix_count + Jit::Call9::GetSize() - 1;
			}
		}
	}
}

#if defined(KYTY_VIRTUAL_MEMORY_ALLOCATION_TESTS)
bool TestNativeLibkernelGetdirentriesTrap() {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	static constexpr uint32_t wrapper_offset        = 0xf20;
	static constexpr uint8_t  wrapper_signature[24] = {
	    0x48, 0xc7, 0xc0, 0xc4, 0x00, 0x00, 0x00, 0x49, 0x89, 0xca, 0x0f, 0x05,
	    0x72, 0x01, 0xc3, 0x48, 0x8d, 0x0d, 0x9e, 0xf1, 0xff, 0xff, 0xff, 0xe1};
	size_t exact_descriptors       = 0;
	size_t conflicting_descriptors = 0;
	for (const auto& descriptor: g_native_libkernel_wrappers) {
		if (descriptor.number != 0xc4 && descriptor.offset != wrapper_offset) continue;
		if (descriptor.number == 0xc4 && descriptor.offset == wrapper_offset &&
		    std::memcmp(descriptor.signature, wrapper_signature, sizeof(wrapper_signature)) == 0) {
			++exact_descriptors;
		} else {
			++conflicting_descriptors;
		}
	}
	bool                 valid = exact_descriptors == 1 && conflicting_descriptors == 0;
	std::vector<uint8_t> positive_image(wrapper_offset + sizeof(wrapper_signature));
	std::vector<uint8_t> negative_image(wrapper_offset + sizeof(wrapper_signature));
	std::array<uint8_t, sizeof(wrapper_signature)> negative_signature {};
	std::memcpy(negative_signature.data(), wrapper_signature, sizeof(wrapper_signature));
	negative_signature[0] ^= 1;
	std::memcpy(positive_image.data() + wrapper_offset, wrapper_signature,
	            sizeof(wrapper_signature));
	std::memcpy(negative_image.data() + wrapper_offset, negative_signature.data(),
	            negative_signature.size());
	const auto make_elf = [] {
		Elf64_Ehdr header {};
		std::memcpy(header.e_ident, "\177ELF", 4);
		header.e_ident[EI_CLASS]   = ELFCLASS64;
		header.e_ident[EI_DATA]    = ELFDATA2LSB;
		header.e_ident[EI_VERSION] = EV_CURRENT;
		header.e_ident[EI_OSABI]   = ELFOSABI_FREEBSD;
		header.e_type              = ET_DYNAMIC;
		header.e_machine           = EM_X86_64;
		header.e_version           = EV_CURRENT;
		header.e_ehsize            = sizeof(header);
		header.e_phoff             = sizeof(header);
		header.e_phentsize         = sizeof(Elf64_Phdr);
		header.e_phnum             = 1;
		Elf64_Phdr segment {};
		segment.p_type   = PT_LOAD;
		segment.p_flags  = PF_R | PF_X;
		segment.p_filesz = sizeof(header) + sizeof(segment);
		segment.p_memsz  = segment.p_filesz;
		segment.p_align  = 0x10;
		std::vector<uint8_t> image(sizeof(header) + sizeof(segment));
		std::memcpy(image.data(), &header, sizeof(header));
		std::memcpy(image.data() + sizeof(header), &segment, sizeof(segment));
		auto elf = std::make_unique<Elf64>();
		elf->Open("native-libkernel-trap-fixture.elf", std::move(image));
		return elf;
	};
	Program positive;
	positive.file_name  = "libkernel.sprx";
	positive.base_vaddr = reinterpret_cast<uint64_t>(positive_image.data());
	positive.elf        = make_elf();
	Program negative;
	negative.file_name  = "libkernel.sprx";
	negative.base_vaddr = reinterpret_cast<uint64_t>(negative_image.data());
	negative.elf        = make_elf();
	if (valid) {
		PatchProgram(&positive, positive.base_vaddr, positive_image.size());
		PatchProgram(&negative, negative.base_vaddr, negative_image.size());
	}
	size_t positive_traps      = 0;
	size_t negative_traps      = 0;
	bool   positive_trap_exact = false;
	{
		std::lock_guard lock(g_native_libkernel_trap_mutex);
		for (const auto& trap: g_native_libkernel_traps) {
			if (trap.owner == &positive) {
				++positive_traps;
				positive_trap_exact =
				    trap.site == positive.base_vaddr + wrapper_offset + 10 && trap.number == 0xc4;
			}
			if (trap.owner == &negative) ++negative_traps;
		}
		g_native_libkernel_traps.erase(
		    std::remove_if(g_native_libkernel_traps.begin(), g_native_libkernel_traps.end(),
			               [&](const NativeLibkernelTrap& trap) {
			                   return trap.owner == &positive || trap.owner == &negative;
		                   }),
		    g_native_libkernel_traps.end());
	}
	valid = valid && positive_image[wrapper_offset + 10] == 0x0f &&
	        positive_image[wrapper_offset + 11] == 0x0b && positive_traps == 1 &&
	        positive_trap_exact && negative_traps == 0 &&
	        std::memcmp(negative_image.data() + wrapper_offset, negative_signature.data(),
	                    negative_signature.size()) == 0 &&
	        negative_image[wrapper_offset + 10] == 0x0f &&
	        negative_image[wrapper_offset + 11] == 0x05;
	return valid;
#else
	return true;
#endif
}
#endif

struct ExecLoadTiming {
	uint64_t open_us           = 0;
	uint64_t map_us            = 0;
	uint64_t patch_us          = 0;
	uint64_t dyninfo_us        = 0;
	uint64_t symdb_us          = 0;
	uint64_t needed_resolve_us = 0;
	uint64_t refresh_us        = 0;
	uint64_t relocate_us       = 0;
	uint64_t init_us           = 0;
	uint32_t programs          = 0;
};

ExecLoadTiming g_exec_load_timing;

uint64_t MicrosecondsSince(std::chrono::steady_clock::time_point start) {
	return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
	                                 std::chrono::steady_clock::now() - start)
	                                 .count());
}

uint64_t RuntimeLinker::GetEntry() {
	// EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());

	Common::LockGuard lock(m_mutex);

	for (const auto* p: m_programs) {
		if (p->elf != nullptr && !p->elf->IsShared()) {
			return p->elf->GetEntry() - p->elf->GetStaticImageBase() + p->base_vaddr;
		}
	}
	return 0;
}

uint64_t RuntimeLinker::GetProcParam() {
	// EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());

	Common::LockGuard lock(m_mutex);

	for (const auto* p: m_programs) {
		if (p->elf != nullptr && !p->elf->IsShared()) {
			return p->proc_param_vaddr;
		}
	}
	return 0;
}

void RuntimeLinker::DbgDump(const std::string& folder) {
	KYTY_PROFILER_FUNCTION();

	EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());

	Common::LockGuard lock(m_mutex);

	for (const auto* p: m_programs) {
		auto folder_str = Common::FixDirectorySlash(folder);
		folder_str += Common::FilenameWithoutDirectory(Common::PathToGenericString(p->file_name));

		EXIT_IF(p->elf == nullptr);

		p->elf->DbgDump(folder_str);

		if (p->dynamic_info != nullptr) {
			EXIT_NOT_IMPLEMENTED(p->dynamic_info->symbol_table_entry_size != 0 &&
			                     p->dynamic_info->symbol_table_entry_size != sizeof(Elf64_Sym));
			EXIT_NOT_IMPLEMENTED(p->dynamic_info->rela_table_entry_size != 0 &&
			                     p->dynamic_info->rela_table_entry_size != sizeof(Elf64_Rela));
			// EXIT_NOT_IMPLEMENTED(p->dynamic_info->jmprela_table == nullptr);
			// EXIT_NOT_IMPLEMENTED(p->dynamic_info->rela_table == nullptr);
			// EXIT_NOT_IMPLEMENTED(p->dynamic_info->symbol_table == nullptr);

			if (p->dynamic_info->symbol_table != nullptr) {
				DbgDumpSymbols(folder_str, p->dynamic_info->symbol_table,
				               p->dynamic_info->symbol_table_total_size,
				               p->dynamic_info->str_table);
			}
			if (p->dynamic_info->jmprela_table != nullptr) {
				DbgDumpRela(folder_str, p->dynamic_info->jmprela_table,
				            p->dynamic_info->jmprela_table_size, p->dynamic_info->str_table,
				            "jmprela_table.txt");
			}
			if (p->dynamic_info->rela_table != nullptr) {
				DbgDumpRela(folder_str, p->dynamic_info->rela_table,
				            p->dynamic_info->rela_table_total_size, p->dynamic_info->str_table,
				            "rela_table.txt");
			}
		}

		if (p->export_symbols != nullptr) {
			p->export_symbols->DbgDump(folder_str, "export_symbols.txt");
		}
		if (p->import_symbols != nullptr) {
			p->import_symbols->DbgDump(folder_str, "import_symbols.txt");
		}
	}
}

void RuntimeLinker::RelocateAll() {
	// EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());

	Common::LockGuard lock(m_mutex);

	const bool trace_pass = std::getenv("KYTY_DIAGNOSTIC_LOG_RELOC_PASS") != nullptr;
	const auto pass_start = std::chrono::steady_clock::now();
	auto       first_done = pass_start;
	auto       last_start = pass_start;

	for (auto* p: m_programs) {
		if (trace_pass && p == m_programs.back()) {
			last_start = std::chrono::steady_clock::now();
		}
		Relocate(p);
		if (trace_pass && p == m_programs.front()) {
			first_done = std::chrono::steady_clock::now();
		}
	}
	g_exec_load_timing.relocate_us += MicrosecondsSince(pass_start);

	if (trace_pass) {
		const auto pass_end = std::chrono::steady_clock::now();
		const auto us       = [](std::chrono::steady_clock::duration d) {
			return static_cast<uint64_t>(
			    std::chrono::duration_cast<std::chrono::microseconds>(d).count());
		};
		LOGF("FIRST_FRAME_AUDIT RELOC_PASS programs=%zu first_us=%" PRIu64 " last_us=%" PRIu64
		     " total_us=%" PRIu64 "\n",
		     m_programs.size(), us(first_done - pass_start), us(pass_end - last_start),
		     us(pass_end - pass_start));
	}
}

void RuntimeLinker::LogExecLoadPhases(const char* point) {
	LOGF("EXEC_LOAD_PHASES point=%s programs=%u open_us=%" PRIu64 " map_us=%" PRIu64
	     " patch_us=%" PRIu64 " dyninfo_us=%" PRIu64 " symdb_us=%" PRIu64
	     " needed_resolve_us=%" PRIu64 " refresh_us=%" PRIu64 " relocate_us=%" PRIu64
	     " init_us=%" PRIu64 "\n",
	     point, g_exec_load_timing.programs, g_exec_load_timing.open_us, g_exec_load_timing.map_us,
	     g_exec_load_timing.patch_us, g_exec_load_timing.dyninfo_us, g_exec_load_timing.symdb_us,
	     g_exec_load_timing.needed_resolve_us, g_exec_load_timing.refresh_us,
	     g_exec_load_timing.relocate_us, g_exec_load_timing.init_us);
}

void RuntimeLinker::RelocateProgram(Program* program) {
	Common::LockGuard lock(m_mutex);

	EXIT_IF(program == nullptr);
	EXIT_IF(std::find(m_programs.begin(), m_programs.end(), program) == m_programs.end());

	RelocateAll();
	if (!GamePatch::ApplyPending(program)) {
		EXIT("Failed to apply pending game cheat\n");
	}
}


static std::vector<std::string> NeededModuleNames(Program* program) {
	EXIT_IF(program == nullptr || program->elf == nullptr || program->dynamic_info == nullptr);
	std::vector<std::string> names;
	if (program->elf->IsStaticExec()) {
		return names;
	}
	for (const auto* needed: program->elf->GetDynList(DT_NEEDED)) {
		const auto offset = needed->d_un.d_val;
		if (offset >= program->dynamic_info->str_table_size ||
		    program->dynamic_info->str_table == nullptr) {
			LOGF("Invalid DT_NEEDED string offset in %s\n",
			     Common::PathToString(program->file_name).c_str());
			continue;
		}
		const auto* name = program->dynamic_info->str_table + offset;
		const auto  size = program->dynamic_info->str_table_size - offset;
		const auto* end  = static_cast<const char*>(std::memchr(name, '\0', size));
		if (end == nullptr || end == name) {
			LOGF("Invalid DT_NEEDED string in %s\n",
			     Common::PathToString(program->file_name).c_str());
			continue;
		}
		names.emplace_back(name, end);
	}
	return names;
}

static Program* FindNeededModule(Program* importer, const std::string& name) {
	const auto existing = std::find_if(
	    importer->needed_modules.begin(), importer->needed_modules.end(),
	    [&](const Program::NeededModule& dependency) { return dependency.name == name; });
	return existing == importer->needed_modules.end() ? nullptr : existing->provider;
}

static std::vector<std::string> NeededModuleCandidates(const std::string& name) {
	if (name.empty() || name == "." || name == ".." || name.find_first_of("/\\") != name.npos) {
		return {};
	}
	const std::vector<std::string> directories = {
	    "/app0/sce_module",      "/hostapp/sce_module",      "/system/common/lib",
	    "/system/priv/lib",      "/system_ex/common_ex/lib", "/system_ex/priv_ex/lib",
	    "/system/vsh/sce_module"};
	std::vector<std::string> names = {name};
	if (name.ends_with(".prx")) {
		names.push_back(name.substr(0, name.size() - 4) + ".sprx");
	} else if (!name.ends_with(".sprx")) {
		names.push_back(name + ".sprx");
	}
	std::vector<std::string> candidates;
	candidates.reserve(directories.size() * names.size());
	for (const auto& directory: directories) {
		for (const auto& file_name: names) {
			candidates.push_back(directory + "/" + file_name);
		}
	}
	return candidates;
}

static std::filesystem::path FindNeededModulePathUncached(const std::string& name) {
	for (const auto& guest_path: NeededModuleCandidates(name)) {
		auto path = Libs::LibKernel::FileSystem::GetRealFilename(guest_path);
		if (path.empty()) {
			Libs::LibKernel::DirectoryPassthrough::ResolveHostPath(guest_path, &path);
		}
		if (!path.empty() && Common::File::IsFileExisting(path)) {
			return path;
		}
	}
	return {};
}

static std::filesystem::path FindNeededModulePath(const std::string& name) {
	// candidate dirs are read-only mounts, so memoize; keeps RefreshNeededModules linear
	static std::unordered_map<std::string, std::filesystem::path> cache;
	if (const auto found = cache.find(name); found != cache.end()) {
		return found->second;
	}
	auto path = FindNeededModulePathUncached(name);
	cache.emplace(name, path);
	return path;
}

struct NeededModuleSource {
	std::filesystem::path                                          file_name;
	std::shared_ptr<Libs::LibKernel::DirectoryPassthrough::Handle> provider_handle;
	std::vector<uint8_t>                                           image;
	int result = Libs::LibKernel::KERNEL_ERROR_ENOENT;
};

static NeededModuleSource FindNeededModuleSource(const std::string& name) {
	NeededModuleSource source;
	for (const auto& guest_path: NeededModuleCandidates(name)) {
		auto path = Libs::LibKernel::FileSystem::GetRealFilename(guest_path);
		if (!path.empty()) {
			if (Common::File::IsFileExisting(path)) {
				source.file_name = std::move(path);
				source.result    = OK;
				return source;
			}
			continue;
		}
		Libs::LibKernel::DirectoryPassthrough::FileSnapshot snapshot;
		const int                                           result =
		    Libs::LibKernel::DirectoryPassthrough::OpenFileSnapshot(guest_path, &snapshot);
		if (result == Libs::LibKernel::KERNEL_ERROR_ENOENT) {
			continue;
		}
		source.result = result;
		if (result != OK) {
			return source;
		}
		if (snapshot.bytes.empty()) {
			source.result = Libs::LibKernel::KERNEL_ERROR_ENOEXEC;
			return source;
		}
		source.file_name       = std::move(snapshot.host_path);
		source.provider_handle = std::move(snapshot.handle);
		source.image           = std::move(snapshot.bytes);
		std::vector<uint8_t> decrypted;
		std::string          detail;
		switch (DecryptedModuleOverlay::ResolveDecryptedModuleImage(guest_path, source.image,
		                                                            &decrypted, &detail)) {
			case DecryptedModuleOverlay::Resolution::Substituted:
				LOGF("SYSTEM_EX_DECRYPTED_OVERLAY guest_path=%s result=substituted %s\n",
				     guest_path.c_str(), detail.c_str());
				source.image = std::move(decrypted);
				break;
			case DecryptedModuleOverlay::Resolution::RejectedMissing:
			case DecryptedModuleOverlay::Resolution::RejectedMismatch:
				LOGF("SYSTEM_EX_DECRYPTED_OVERLAY guest_path=%s result=rejected %s\n",
				     guest_path.c_str(), detail.c_str());
				break;
			case DecryptedModuleOverlay::Resolution::NotApplicable: break;
		}
		return source;
	}
	return source;
}


bool RuntimeLinker::IsProgramReferenced(Program* program) {
	std::vector<Program*>        pending;
	std::unordered_set<Program*> visited;
	for (auto* root: m_programs) {
		if (root->process_owned || root->load_count != 0 || root->active_module_calls != 0 ||
		    (root != program && root->pending_thread_atexit != 0)) {
			pending.push_back(root);
		}
	}
	while (!pending.empty()) {
		auto* current = pending.back();
		pending.pop_back();
		if (!visited.insert(current).second) {
			continue;
		}
		if (current == program) {
			return true;
		}
		for (const auto& dependency: current->needed_modules) {
			pending.push_back(dependency.provider);
		}
	}
	return false;
}

bool RuntimeLinker::IsThreadAtexitReferenced(Program* program) {
	std::vector<Program*>        pending;
	std::unordered_set<Program*> visited;
	for (auto* root: m_programs) {
		if (root->pending_thread_atexit != 0) pending.push_back(root);
	}
	while (!pending.empty()) {
		auto* current = pending.back();
		pending.pop_back();
		if (!visited.insert(current).second) continue;
		if (current == program) return true;
		for (const auto& dependency: current->needed_modules)
			pending.push_back(dependency.provider);
	}
	return false;
}


int RuntimeLinker::AcquireProgram(Program* program) {
	Common::LockGuard lock(m_mutex);
	if (std::find(m_programs.begin(), m_programs.end(), program) == m_programs.end()) {
		return Libs::LibKernel::KERNEL_ERROR_ESRCH;
	}
	if (program->module_state == Program::ModuleState::Stopping ||
	    program->module_state == Program::ModuleState::Stopped) {
		return Libs::LibKernel::KERNEL_ERROR_EBUSY;
	}
	if (program->load_count == std::numeric_limits<uint32_t>::max()) {
		return Libs::LibKernel::KERNEL_ERROR_EOVERFLOW;
	}
	++program->load_count;
	program->module_unload_pending = false;
	return OK;
}





int RuntimeLinker::UnloadProgram(Program* program) {
	// EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());

	Common::LockGuard lock(m_mutex);

	auto it = std::find(m_programs.begin(), m_programs.end(), program);
	EXIT_IF(it == m_programs.end());
	m_programs.erase(it);
	std::erase(m_needed_modules, program);
	std::erase(m_module_start_order, program->unique_id);
	for (auto* importer: m_programs) {
		std::erase_if(importer->needed_modules, [&](const Program::NeededModule& dependency) {
			return dependency.provider == program;
		});
	}

	for (auto* importer: m_programs) {
		const auto& info = *importer->dynamic_info;
		const auto rela_count =
		    static_cast<uint32_t>(info.rela_table_total_size / sizeof(Elf64_Rela));
		ForEachRelocation(importer, [&](Elf64_Rela* r, uint32_t index, bool jmprela) {
			const auto bit_index = (jmprela ? rela_count : 0) + index;
			auto&      bits      = importer->rela_bits[bit_index >> 3u];
			const auto mask      = 1u << (bit_index & 7u);
			const auto type      = r->GetType();
			if ((bits & mask) == 0 || (type != R_X86_64_64 && type != R_X86_64_GLOB_DAT &&
			                           type != R_X86_64_JUMP_SLOT)) {
				return;
			}
			const auto& symbol = info.symbol_table[r->GetSymbol()];
			if (symbol.GetBind() != STB_GLOBAL && symbol.GetBind() != STB_WEAK) {
				return;
			}
			const auto value =
			    *reinterpret_cast<const uint64_t*>(importer->base_vaddr + r->r_offset);
			const auto address = value - (type == R_X86_64_64 ? r->r_addend : 0);
			if (address < program->base_vaddr ||
			    address >= program->base_vaddr + program->mapped_size) {
				return;
			}
			SymbolType symbol_type;
			switch (symbol.GetType()) {
				case STT_NOTYPE: symbol_type = SymbolType::NoType; break;
				case STT_FUNC: symbol_type = SymbolType::Func; break;
				case STT_OBJECT: symbol_type = SymbolType::Object; break;
				default: return;
			}
			const std::string name = info.str_table + symbol.st_name;
			if (program->export_symbols->FindByNid(name.substr(0, name.find('#')), symbol_type,
			                                       address) != nullptr) {
				bits &= ~mask;
				if (RelocateRecord(index, r, importer, jmprela)) {
					bits |= mask;
				}
			}
		});
	}
	DeleteProgram(program);
	return OK;
}

RuntimeLinker::RuntimeLinker(): m_symbols(std::make_unique<SymbolDatabase>()) {
	EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());
}

RuntimeLinker::~RuntimeLinker() {
	Clear();
}

Program* RuntimeLinker::LoadProgram(const std::filesystem::path& elf_name) {
	return LoadProgramImpl(elf_name, nullptr);
}

Program* RuntimeLinker::LoadProgram(const std::filesystem::path& elf_name,
                                    std::vector<uint8_t>         image) {
	return LoadProgramImpl(elf_name, &image);
}

Program* RuntimeLinker::LoadProgramImpl(const std::filesystem::path& elf_name,
                                        std::vector<uint8_t>*        image) {
	KYTY_PROFILER_FUNCTION();

	Common::LockGuard lock(m_mutex);

	static int32_t id_seq = 0;

	LOGF("Loading: %s\n", Common::PathToString(elf_name).c_str());

	auto  program_owner = std::make_unique<Program>();
	auto* program       = program_owner.get();

	program->rt        = this;
	program->file_name = elf_name;
	program->unique_id = ++id_seq;

	program->elf = std::make_unique<Elf64>();
	const auto open_start = std::chrono::steady_clock::now();
	if (image == nullptr) {
		program->elf->Open(elf_name);
	} else {
		program->elf->Open(elf_name, std::move(*image));
	}
	g_exec_load_timing.open_us += MicrosecondsSince(open_start);

	if (program->elf->IsValid()) {
		auto phase_start = std::chrono::steady_clock::now();
		LoadProgramToMemory(program);
		g_exec_load_timing.map_us += MicrosecondsSince(phase_start);
		phase_start = std::chrono::steady_clock::now();
		ParseProgramDynamicInfo(program);
		g_exec_load_timing.dyninfo_us += MicrosecondsSince(phase_start);
		phase_start = std::chrono::steady_clock::now();
		CreateSymbolDatabase(program);
		g_exec_load_timing.symdb_us += MicrosecondsSince(phase_start);
	} else {
		EXIT("elf is not valid: %s\n", Common::PathToString(elf_name).c_str());
	}
	++g_exec_load_timing.programs;

	m_programs.push_back(program_owner.release());

	if (!program->elf->IsShared()) {
		program->process_owned               = true;
		program->fail_if_global_not_resolved = false;
		Libs::LibKernel::SetProgName(elf_name.filename().string());
		Libs::LibKernel::Process::SetName(elf_name.filename().string());
	}

	if (Common::ToLower(Common::DirectoryWithoutFilename(Common::PathToGenericString(elf_name)))
	        .ends_with("_module/")) {
		program->fail_if_global_not_resolved = false;
	}

	return program;
}


void RuntimeLinker::SaveMainProgram(const std::filesystem::path& elf_name) {
	EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());

	Common::LockGuard lock(m_mutex);

	for (const auto* p: m_programs) {
		EXIT_IF(p->elf == nullptr);

		if (!p->elf->IsShared()) {
			p->elf->Save(elf_name);
			break;
		}
	}
}

void RuntimeLinker::SaveProgram(Program* program, const std::filesystem::path& elf_name) {
	EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());

	Common::LockGuard lock(m_mutex);

	if (auto it = std::find(m_programs.begin(), m_programs.end(), program);
	    it != m_programs.end()) {
		EXIT_IF((*it)->elf == nullptr);

		(*it)->elf->Save(elf_name);
	} else {
		EXIT("program not found");
	}
}

static bool PrepareExecEntryParameters(void* stack_top, EntryParams** params,
                                       void** execution_stack) {
	const auto& arguments   = Libs::LibKernel::Process::GetExecChildArguments();
	const auto& environment = Libs::LibKernel::Process::GetExecChildEnvironment();
	uint64_t    stack_base  = 0;
	uint64_t    stack_size  = 0;
	const auto  top         = reinterpret_cast<uint64_t>(stack_top);
	if (!Libs::LibKernel::PthreadGetGuestStack(Libs::LibKernel::PthreadSelfOrNull(), &stack_base,
	                                           &stack_size) ||
	    stack_base > UINT64_MAX - stack_size || top <= stack_base ||
	    top > stack_base + stack_size || top - stack_base <= 0x12000u ||
	    arguments.size() > INT32_MAX) {
		return false;
	}
	const uint64_t available = top - stack_base - 0x12000u;
	const uint64_t max_words = available / sizeof(uint64_t);
	if (max_words < 5 || arguments.size() > max_words - 5 ||
	    environment.size() > max_words - 5 - arguments.size()) {
		return false;
	}
	const uint64_t table_size = (arguments.size() + environment.size() + 5u) * sizeof(uint64_t);
	uint64_t       total_size = table_size;
	for (const auto* values: {&arguments, &environment}) {
		for (const auto& value: *values) {
			if (value.size() >= available - total_size) {
				return false;
			}
			total_size += value.size() + 1u;
		}
	}
	const uint64_t start   = (top - total_size - 0x100u) & ~uint64_t {15};
	auto*          words   = reinterpret_cast<uint64_t*>(start);
	auto*          strings = reinterpret_cast<char*>(start + table_size);
	std::memset(words, 0, static_cast<size_t>(total_size));
	*words++ = arguments.size();
	for (const auto* values: {&arguments, &environment}) {
		for (const auto& value: *values) {
			*words++ = reinterpret_cast<uint64_t>(strings);
			std::memcpy(strings, value.c_str(), value.size() + 1u);
			strings += value.size() + 1u;
		}
		*words++ = 0;
	}
	words[0]         = 0;
	words[1]         = 0;
	*params          = reinterpret_cast<EntryParams*>(start);
	*execution_stack = reinterpret_cast<void*>(start - 0x1000u);
	LOGF("GUEST_EXECVE_STACK_PREPARED guest_pid=%d argc=%zu envc=%zu"
	     " params=0x%016" PRIx64 " bytes=%" PRIu64 "\n",
	     Libs::LibKernel::Process::GetPid(), arguments.size(), environment.size(), start,
	     total_size);
	return true;
}

static bool InstallExecEntryTrace(uint64_t entry) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (!IsReadableRange(entry, g_exec_child_entry_bytes.size())) {
		return false;
	}
	auto* code = reinterpret_cast<uint8_t*>(entry);
	if (code[0] == 0x0f && code[1] == 0x0b) {
		return false;
	}
	DWORD protection = 0;
	if (!VirtualProtect(code, g_exec_child_entry_bytes.size(), PAGE_EXECUTE_READWRITE,
	                    &protection)) {
		return false;
	}
	std::memcpy(g_exec_child_entry_bytes.data(), code, g_exec_child_entry_bytes.size());
	code[0]           = 0x0f;
	code[1]           = 0x0b;
	DWORD      unused = 0;
	const bool restored =
	    VirtualProtect(code, g_exec_child_entry_bytes.size(), protection, &unused) != 0;
	if (!Common::VirtualMemory::FlushInstructionCache(entry, g_exec_child_entry_bytes.size()) ||
	    !restored) {
		return false;
	}
	g_exec_child_entry_site.store(entry, std::memory_order_release);
	return true;
#else
	(void)entry;
	return false;
#endif
}

void RuntimeLinker::Execute(const std::filesystem::path& game_patch) {
	KYTY_PROFILER_THREAD("Thread_Main");

	Libs::LibKernel::PthreadInitSelfForMainThread();
	auto* main_stack_top = Libs::LibKernel::PthreadCreateMainGuestStack();

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	size_t expanded_size = 0;
	while (expanded_size < static_cast<size_t>(768) * 1024) {
		sys_dbg_stack_info_t stack {};
		SysStackUsage(stack);
		*reinterpret_cast<uint32_t*>(stack.guard_addr) = 0;
		expanded_size += stack.guard_size;
	}
#endif

	// The runtime automatically loads libc; other PRXs are requested by the application.
	const auto libc_path =
	    Libs::LibKernel::FileSystem::GetRealFilename("/app0/sce_module/libc.prx");
	auto* libc = Common::File::IsFileExisting(libc_path) ? LoadProgram(libc_path) : nullptr;
	if (libc != nullptr) {
		Common::LockGuard lock(m_mutex);
		libc->process_owned = true;
	}
	RelocateAll();
	Libs::LibKernel::Process::MarkExecChildStartupStage(9);
	Common::HostException::PrepareUnhandledFaultProvenance(Libs::LibKernel::Process::GetPid());
	if (std::getenv("KYTY_DIAGNOSTIC_NPCOMMON_NATIVE_TRACE") != nullptr) {
		for (const auto* module: m_needed_modules) {
			if (module->file_name.filename() == "libSceNpCommon.sprx") {
				Libs::NpCommon::SetDiagnosticNativeEntries(module->base_vaddr + 0x3b70u,
				                                           module->base_vaddr + 0x4080u,
				                                           module->base_vaddr + 0x3f60u);
				break;
			}
		}
	}
	if (!m_needed_modules.empty()) {
		WriteUnresolvedSymbols();
	}

	if (!game_patch.empty()) {
		if (!GamePatch::Apply(game_patch, m_programs.empty() ? nullptr : m_programs.front(),
		                      m_programs)) {
			EXIT("Failed to apply game cheat\n");
		}
	}
	EntryParams* exec_params = nullptr;
	void*        exec_stack  = nullptr;
	if (Libs::LibKernel::Process::IsExecChild()) {
		const auto entry = GetEntry();
		if (entry == 0 || !PrepareExecEntryParameters(main_stack_top, &exec_params, &exec_stack) ||
		    !InstallExecEntryTrace(entry)) {
			LOGF("GUEST_EXECVE_IMAGE_PREPARATION_FAILED guest_pid=%d\n",
			     Libs::LibKernel::Process::GetPid());
			std::fflush(stdout);
			std::quick_exit(1);
		}
		Libs::LibKernel::Process::MarkExecChildStartupStage(10);
		LogExecLoadPhases("commit_wait");
		if (!Libs::LibKernel::Process::AwaitExecChildCommit(
		        entry, reinterpret_cast<uint64_t>(exec_stack),
		        reinterpret_cast<uint64_t>(exec_params))) {
			std::quick_exit(1);
		}
		Libs::LibKernel::Process::MarkExecChildStartupStage(11);
		Libs::LibKernel::Process::PublishToScope();
	}
	if (const auto* proc_param = reinterpret_cast<const uint64_t*>(GetProcParam());
	    proc_param != nullptr && proc_param[0] > 0x3f && proc_param[3] != 0) {
		Libs::LibKernel::Process::SetName(reinterpret_cast<const char*>(proc_param[3]));
	}
	const bool shellui_npcommon_owner = [&] {
		if (g_tls_main_program == nullptr ||
		    g_tls_main_program->file_name.filename() != "NPXS40087_eboot_decrypted.elf") {
			return false;
		}
		const auto* proc_param = reinterpret_cast<const uint64_t*>(GetProcParam());
		return proc_param != nullptr && proc_param[0] > 0x1f && proc_param[3] != 0 &&
		       std::strcmp(reinterpret_cast<const char*>(proc_param[3]), "SceShellUI") == 0;
	}();
	auto initialize_modules = [this, libc, shellui_npcommon_owner] {
		if (libc != nullptr && libc->dynamic_info->init_vaddr != 0) {
			StartModule(libc, 0, nullptr, nullptr);
		}
	};
	const auto init_start = std::chrono::steady_clock::now();
	RunEntry(reinterpret_cast<uint64_t>(RunInitializerStage<decltype(initialize_modules)>),
	         reinterpret_cast<EntryParams*>(&initialize_modules), nullptr,
	         exec_stack != nullptr ? exec_stack : main_stack_top);
	g_exec_load_timing.init_us += MicrosecondsSince(init_start);
	Libs::LibKernel::Process::MarkExecChildStartupStage(12);
	if (Libs::LibKernel::Process::IsExecChild()) {
		LogExecLoadPhases("modules_started");
	}

	LOGF_COLOR(Log::Color::BrightYellow, "---\n--- Execute: %s\n---\n", "Main");

	if (auto entry = GetEntry(); entry != 0) {
		auto* params = exec_params;
		void* stack  = exec_stack;
		if (params == nullptr) {
			params = reinterpret_cast<EntryParams*>(
			    (reinterpret_cast<uintptr_t>(main_stack_top) - 0x100u) &
			    ~static_cast<uintptr_t>(0x0f));
			std::memset(params, 0, sizeof(EntryParams));
			params->argc    = 1;
			params->argv[0] = "KytyEmu";
			stack = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(params) - 0x1000u);
		}

		LOGF("stack_addr = %" PRIx64 "\n", reinterpret_cast<uint64_t>(params));

		RunEntry(entry, params, ProgramExitHandler, stack);
	}
	Common::HostException::ClearCurrentGuestStackBounds();
}

void RuntimeLinker::WriteUnresolvedSymbols() {
	std::filesystem::path report_path = "unresolved_symbols.log";
	if (Libs::LibKernel::Process::IsExecChild()) {
		report_path = Config::GetPrintfOutputFile();
		report_path += ".unresolved";
	}
	std::error_code error;
	const auto      report_absolute = std::filesystem::weakly_canonical(report_path, error);
	if (error) {
		LOGF("Cannot resolve unresolved-symbol report path: %s\n", error.message().c_str());
		return;
	}
	if (Config::GetPrintfDirection() == Config::LogDirection::File) {
		const auto log_absolute =
		    std::filesystem::weakly_canonical(Config::GetPrintfOutputFile(), error);
		if (!error && report_absolute == log_absolute) {
			LOGF("Cannot write unresolved-symbol report: path is also the active runtime log\n");
			return;
		}
	}
	std::vector<std::string> rows;
	for (auto* program: m_programs) {
		const auto& info       = *program->dynamic_info;
		const auto  rela_count = info.rela_table_total_size / sizeof(Elf64_Rela);
		ForEachRelocation(program, [&](Elf64_Rela* r, uint32_t index, bool jmprela) {
			const auto bit_index = (jmprela ? rela_count : 0) + index;
			if ((program->rela_bits[bit_index >> 3u] & (1u << (bit_index & 7u))) != 0) {
				return;
			}
			const auto ri = GetRelocationInfo(r, program);
			if (ri.resolved) {
				return;
			}
			const auto* original_name = info.str_table + info.symbol_table[r->GetSymbol()].st_name;
			rows.push_back(fmt::format(
			    "{}\t0x{:016x}\t{}\t{}\t{}\t{}\t{}\n", Common::PathToString(program->file_name),
			    ri.vaddr, original_name, magic_enum::enum_name(ri.type),
			    magic_enum::enum_name(ri.bind), jmprela ? "PLT" : "data", ri.name));
		});
	}
	std::sort(rows.begin(), rows.end());
	std::ofstream report(report_path, std::ios::trunc);
	if (!report) {
		LOGF("Cannot open unresolved-symbol report: %s\n",
		     Common::PathToString(report_path).c_str());
		return;
	}
	report << "module\taddress\timport\ttype\tbinding\ttable\tqualified_name\n";
	for (const auto& row: rows) {
		report << row;
	}
	report.close();
	if (!report) {
		LOGF("Failed to write unresolved-symbol report\n");
		return;
	}
	LOGF("Unresolved imports: %zu; report: %s\n", rows.size(),
	     Common::PathToString(report_absolute).c_str());
}

void RuntimeLinker::Clear() {
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD") != nullptr) {
		std::printf("SYSCORE_RUNTIME_LINKER_CLEAR_ENTER"
		            " children_may_be_active\n");
		std::fflush(stdout);
	}
	// EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());
	{
		Common::LockGuard lock(m_mutex);
		if (std::any_of(m_programs.begin(), m_programs.end(), [](const Program* program) {
			    return program->pending_thread_atexit != 0 || program->active_module_calls != 0;
		    })) {
			LOGF("RUNTIME_LINKER_CLEAR_DEFERRED active_module_or_thread_destructor_ownership=1\n");
			return;
		}
	}
	if (m_shellui_npcommon_pool_owned) {
		const int result = ReleaseShellUiNpCommonPool();
		LOGF("NPCOMMON_POOL_OWNER process=SceShellUI release_during_clear"
		     " result=0x%08x\n",
		     static_cast<uint32_t>(result));
	}
	Common::LockGuard lock(m_mutex);
	GamePatch::Clear();

	for (auto* p: m_programs) {
		DeleteProgram(p);
	}
	m_programs.clear();
	m_needed_modules.clear();
	m_module_start_order.clear();
	m_stopping_all_modules = false;
	for (auto& record: g_stubbed_imports) {
		Common::HostException::UnregisterGuestCodeProvenance(record.host_exception_code_token);
		record.host_exception_code_token = 0;
	}
	for (const auto page: g_unresolved_stub_thunk_pages) {
		EXIT_IF(!Libs::LibKernel::Memory::FreeGuestMemory(page, UNRESOLVED_STUB_PAGE_SIZE));
	}
	g_unresolved_stub_thunk_pages.clear();
	g_unresolved_stub_thunk_offset = 0;
	g_stubbed_imports.clear();
	g_unresolved_stub_call_log_count.store(0);
	g_agc_pool_malloc_target.store(0, std::memory_order_release);
	g_agc_pool_malloc_expected_return.store(0, std::memory_order_relaxed);
	g_agc_pool_malloc_outcome_count.store(0, std::memory_order_relaxed);
	g_agc_pool_malloc_install_count.store(0, std::memory_order_relaxed);
	if (g_invalid_memory != 0) {
		EXIT_IF(!Libs::LibKernel::Memory::FreeGuestMemory(g_invalid_memory, 4096));
		g_invalid_memory = 0;
	}
	g_tls_main_program        = nullptr;
	g_tls_cached_main_program = nullptr;
	g_tls_cached_main_tcb     = nullptr;
	g_desired_base_addr       = SYSTEM_RESERVED + CODE_BASE_OFFSET;
	m_symbols.reset();
}

void RuntimeLinker::Resolve(const std::string& name, SymbolType type, Program* program,
                            SymbolRecord* out_info, bool* bind_self) {
	KYTY_PROFILER_FUNCTION();

	Common::LockGuard lock(m_mutex);

	EXIT_IF(out_info == nullptr);

	auto ids = Common::Split(name, '#');

	if (bind_self != nullptr) {
		*bind_self = false;
	}

	if (ids.size() == 3) {
		const LibraryId* l = FindLibrary(*program, ids.at(1));
		const ModuleId*  m = FindModule(*program, ids.at(2));

		auto resolve_by_nid = [this, type](const std::string& nid, SymbolRecord* out) -> bool {
			EXIT_IF(out == nullptr);

			if (m_symbols != nullptr) {
				if (const auto* rec = m_symbols->FindByNid(nid, type); rec != nullptr) {
					*out = *rec;
					return true;
				}
			}

			for (auto* p: m_programs) {
				if (p != nullptr && p->export_symbols != nullptr) {
					if (const auto* rec = p->export_symbols->FindByNid(nid, type); rec != nullptr) {
						*out = *rec;
						return true;
					}
				}
			}

			return false;
		};

		if (l != nullptr && m != nullptr) {
			SymbolResolve sr {};
			sr.name                 = ids.at(0);
			sr.library              = l->name;
			sr.library_version      = l->version;
			sr.module               = m->name;
			sr.module_version_major = m->version_major;
			sr.module_version_minor = m->version_minor;
			sr.type                 = type;
			if ((sr.module == "libSceFont" && sr.library == "libSceFont") ||
			    (sr.module == "libSceFontFt" && sr.library == "libSceFontFt")) {
				for (auto* provider: m_programs) {
					if (!provider->original_font_provider ||
					    provider->module_state != Program::ModuleState::Started)
						continue;
					const auto file = provider->file_name.filename();
					if ((sr.module == "libSceFont" && file != "libSceFont.native.sprx") ||
					    (sr.module == "libSceFontFt" && file != "libSceFontFt.sprx"))
						continue;
					if (const auto* original = provider->export_symbols->Find(sr);
					    original != nullptr) {
						*out_info = *original;
						if (bind_self != nullptr) *bind_self = provider == program;
					} else {
						out_info->vaddr = 0;
						out_info->name  = SymbolDatabase::GenerateName(sr);
						out_info->dbg_name.clear();
					}
					return;
				}
			}
			const auto* mbus_guard = std::getenv("KYTY_DIAGNOSTIC_MBUS_UNINITIALIZED_GUARD");
			if (mbus_guard != nullptr && std::strcmp(mbus_guard, "1") == 0 &&
			    sr.module == "libSceMbus" && sr.library == "libSceMbus" &&
			    sr.name == "DOFWwhLN09E") {
				for (auto* provider: m_programs) {
					if (provider == nullptr || provider->export_symbols == nullptr ||
					    provider->file_name.filename() != "libSceMbus.sprx") {
						continue;
					}
					if (const auto* original = provider->export_symbols->Find(sr);
					    original != nullptr) {
						const bool known_provider =
						    IsExactMbusSetVolumeDownProvider(*provider, *original);
						if (program->file_name.filename() == "libSceAudioOut.sprx" &&
						    known_provider && m_symbols != nullptr) {
							if (const auto* hle = m_symbols->Find(sr); hle != nullptr) {
								Libs::Mbus::SetOriginalSetVolumeDown(
								    original->vaddr, provider->base_vaddr + 0x10320u);
								*out_info = *hle;
								LOGF("NON_AUTHENTIC_MBUS_GUARD route importer=%s"
								     " original=0x%016" PRIx64 " client_slot=0x%016" PRIx64
								     " hle=0x%016" PRIx64 "\n",
								     Common::PathToString(program->file_name).c_str(),
								     original->vaddr, provider->base_vaddr + 0x10320u, hle->vaddr);
								return;
							}
						}
						if (program->file_name.filename() == "libSceAudioOut.sprx" &&
						    !known_provider &&
						    g_mbus_guard_rejection_count.fetch_add(1, std::memory_order_relaxed) <
						        8) {
							LOGF_COLOR(Log::Color::Red,
							           "NON_AUTHENTIC_MBUS_GUARD rejected unknown provider layout"
							           " importer=%s target=0x%016" PRIx64 "\n",
							           Common::PathToString(program->file_name).c_str(),
							           original->vaddr);
						}
						*out_info = *original;
						if (bind_self != nullptr) *bind_self = provider == program;
						return;
					}
				}
			}

			const auto* original_pad = std::getenv("KYTY_DIAGNOSTIC_HOST_INPUT_HID_PAD");
			if (original_pad != nullptr && std::strcmp(original_pad, "1") == 0 &&
			    sr.module == "libSceMbus" && sr.library == "libSceMbus" &&
			    sr.name == "KRL-S9qBqXw") {
				for (auto* provider: m_programs) {
					if (provider == nullptr || provider->export_symbols == nullptr ||
					    provider->file_name.filename() != "libSceMbus.sprx") {
						continue;
					}
					if (const auto* original = provider->export_symbols->Find(sr);
					    original != nullptr) {
						if (program->file_name.filename() == "libScePsm.sprx" &&
						    m_symbols != nullptr) {
							if (const auto* hle = m_symbols->Find(sr); hle != nullptr) {
								Libs::Mbus::SetOriginalGetDeviceInfoByCondition(original->vaddr);
								*out_info = *hle;
								LOGF("NON_AUTHENTIC_INPUT_BRIDGE MBus controller query route"
								     " importer=%s original=0x%016" PRIx64 " hle=0x%016" PRIx64
								     "\n",
								     Common::PathToString(program->file_name).c_str(),
								     original->vaddr, hle->vaddr);
								return;
							}
						}
						*out_info = *original;
						if (bind_self != nullptr) *bind_self = provider == program;
						return;
					}
				}
			}
			if (original_pad != nullptr && std::strcmp(original_pad, "1") == 0 &&
			    sr.module == "libScePad" && sr.library == "libScePad") {
				const auto importer_file       = program->file_name.filename();
				const bool host_input_consumer = importer_file == "libScePsm.sprx" ||
				                                 importer_file == "libReactNative.Modules.Vsh.sprx";
				const bool host_input_call = sr.name == "d7bXuEBycDI" || sr.name == "FYqcaosYiIo";
				if (host_input_consumer && host_input_call && m_symbols != nullptr) {
					if (const auto* hle = m_symbols->Find(sr); hle != nullptr) {
						*out_info = *hle;
						LOGF("NON_AUTHENTIC_INPUT_BRIDGE Pad route importer=%s nid=%s"
						     " hle=0x%016" PRIx64 "\n",
						     Common::PathToString(program->file_name).c_str(), sr.name.c_str(),
						     hle->vaddr);
						return;
					}
				}
				for (auto* provider: m_programs) {
					if (provider == nullptr || provider->export_symbols == nullptr ||
					    provider->file_name.filename() != "libScePad.sprx") {
						continue;
					}
					if (const auto* original = provider->export_symbols->Find(sr);
					    original != nullptr) {
						*out_info = *original;
						if (bind_self != nullptr) *bind_self = provider == program;
						if (sr.name == "xk0AcarP3V4" || sr.name == "6ncge5+l5Qs") {
							LOGF("NATIVE_PAD_PROVIDER_BIND importer=%s nid=%s provider=%s"
							     " target=0x%016" PRIx64 " NON_AUTHENTIC_INPUT_BRIDGE\n",
							     Common::PathToString(program->file_name).c_str(), sr.name.c_str(),
							     Common::PathToString(provider->file_name).c_str(),
							     original->vaddr);
						}
						return;
					}
				}
			}

			const SymbolRecord* rec              = nullptr;
			const bool          trace_z7         = sr.name == "Z7NoR9m5SVo";
			const bool          trace_mutex      = sr.name == "9UK1vLZQft4";
			const bool          trace_pf         = sr.name == "39iV5E1HoCk";
			const bool          trace_userevt    = sr.name == "yH17Q6NWtVg";
			const bool          trace_net_config = sr.name == "6MojQ8uFHEI";
			const bool          trace_net_pool   = sr.name == "dgJBaeJnGpo";
			const bool          trace_app =
			    sr.name == "9PCBPZcDU7Q" || sr.name == "SfPuQO4vW9M" || sr.name == "yvbO67OvrFc";

			if (m_symbols != nullptr) {
				rec = m_symbols->Find(sr);
			}

			if (rec == nullptr && m_symbols != nullptr) {
				if (const auto* hle = m_symbols->FindByNid(sr.name, type); hle != nullptr) {
					*out_info = *hle;
					if (trace_app) {
						LOGF("AppMgr resolve HLE: nid=%s importer=%s target=%016" PRIx64 " %s\n",
						     sr.name.c_str(), Common::PathToString(program->file_name).c_str(),
						     out_info->vaddr, out_info->name.c_str());
					}
					LOGF("PS5 HLE NID override: %s -> %s\n", sr.name.c_str(),
					     out_info->name.c_str());
					return;
				}
			}

			if (rec == nullptr) {
				for (auto* p: m_programs) {
					const auto& libs = p->dynamic_info->export_libs;
					const auto& modules = p->dynamic_info->export_modules;
					if (p->export_symbols == nullptr ||
					    std::find(libs.begin(), libs.end(), *l) == libs.end() ||
					    std::find(modules.begin(), modules.end(), *m) == modules.end()) {
						continue;
					}
					rec = p->export_symbols->Find(sr);
					if (rec != nullptr) {
						if (bind_self != nullptr) {
							*bind_self = (p == program);
						}
						break;
					}
				}
			}

			if (rec == nullptr) {
				if (resolve_by_nid(sr.name, out_info)) {
					if (trace_app) {
						LOGF("AppMgr resolve NID fallback: nid=%s importer=%s target=%016" PRIx64
						     " %s\n",
						     sr.name.c_str(), Common::PathToString(program->file_name).c_str(),
						     out_info->vaddr, out_info->name.c_str());
					}
					LOGF("PS5 NID fallback: %s -> %s\n", sr.name.c_str(), out_info->name.c_str());
					return;
				}
			}

			if (rec != nullptr) {
				*out_info = *rec;
				if (trace_userevt) {
					LOGF("USEREVT resolve pick: importer=%s target=%016" PRIx64 " name=%s dbg=%s\n",
					     Common::PathToString(program->file_name).c_str(), out_info->vaddr,
					     out_info->name.c_str(), out_info->dbg_name.c_str());
				}
				if (sr.name == "Xru92wHJRmg") {
					LOGF("VIDEOOUT_VBLANK_TARGET importer=%s name=%s addr=0x%016" PRIx64 "\n",
					     Common::PathToString(program->file_name).c_str(), rec->name.c_str(),
					     rec->vaddr);
				}
				if (trace_net_config) {
					LOGF("NETCFG resolve native/exact: importer=%s target=%016" PRIx64 " %s\n",
					     Common::PathToString(program->file_name).c_str(), out_info->vaddr,
					     out_info->name.c_str());
				}
				if (trace_pf) {
					LOGF("PF resolve native/exact: importer=%s target=%016" PRIx64 " %s\n",
					     Common::PathToString(program->file_name).c_str(), out_info->vaddr,
					     out_info->name.c_str());
				}
				if (trace_app) {
					LOGF("AppMgr resolve native/exact: nid=%s importer=%s target=%016" PRIx64
					     " %s\n",
					     sr.name.c_str(), Common::PathToString(program->file_name).c_str(),
					     out_info->vaddr, out_info->name.c_str());
				}
			} else {
				out_info->vaddr    = 0;
				out_info->name     = SymbolDatabase::GenerateName(sr);
				out_info->dbg_name = "";
			}
		} else {
			if (resolve_by_nid(ids.at(0), out_info)) {
				LOGF("PS5 NID fallback: %s -> %s (missing lib/module metadata)\n",
				     ids.at(0).c_str(), out_info->name.c_str());
				return;
			}

			EXIT("l == nullptr || m == nullptr");
		}
	} else {
		out_info->vaddr    = 0;
		out_info->name     = name;
		out_info->dbg_name = "";
	}
}

uint64_t RuntimeLinker::ReadFromElf(Program* program, uint64_t vaddr) {
	EXIT_IF(program == nullptr);
	EXIT_IF(program->base_vaddr == 0 || program->base_size == 0);
	EXIT_IF(program->elf == nullptr);

	uint64_t ret = 0;

	const auto* ehdr = program->elf->GetEhdr();
	const auto* phdr = program->elf->GetPhdr();

	EXIT_IF(phdr == nullptr || ehdr == nullptr);

	for (Elf64_Half i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_memsz != 0 && (phdr[i].p_type == PT_LOAD || phdr[i].p_type == PT_OS_RELRO)) {
			uint64_t segment_addr      = phdr[i].p_vaddr + program->base_vaddr;
			uint64_t segment_file_size = phdr[i].p_filesz;

			if (vaddr >= segment_addr && vaddr < segment_addr + segment_file_size) {
				program->elf->LoadSegment(reinterpret_cast<uint64_t>(&ret),
				                          phdr[i].p_offset + vaddr - segment_addr, sizeof(ret));
				break;
			}
		}
	}

	return ret;
}

Program* RuntimeLinker::FindProgramById(int32_t id) {
	Common::LockGuard lock(m_mutex);

	// Id 0 is reserved for main program
	if (id == 0 && !m_programs.empty()) {
		return m_programs.front();
	}

	for (auto* p: m_programs) {
		if (p->unique_id == id) {
			return p;
		}
	}

	return nullptr;
}

Program* RuntimeLinker::FindProgramByFileName(const std::filesystem::path& elf_name) {
	Common::LockGuard lock(m_mutex);

	auto fixed_name = Common::FixFilenameSlash(Common::PathToGenericString(elf_name));
	for (auto* p: m_programs) {
		if (Common::EqualNoCase(Common::FixFilenameSlash(Common::PathToGenericString(p->file_name)),
		                        fixed_name)) {
			return p;
		}
	}

	return nullptr;
}

Program* RuntimeLinker::FindProgramByAddr(uint64_t vaddr) {
	Common::LockGuard lock(m_mutex);

	for (auto* p: m_programs) {
		const auto* ehdr = p->elf->GetEhdr();
		const auto* phdr = p->elf->GetPhdr();

		EXIT_IF(phdr == nullptr || ehdr == nullptr);

		for (Elf64_Half i = 0; i < ehdr->e_phnum; i++) {
			if (phdr[i].p_memsz != 0 &&
			    (phdr[i].p_type == PT_LOAD || phdr[i].p_type == PT_OS_RELRO)) {
				uint64_t segment_addr = phdr[i].p_vaddr + p->base_vaddr;
				uint64_t segment_size = GetAlignedSize(phdr + i);

				if (vaddr >= segment_addr && vaddr < segment_addr + segment_size) {
					return p;
				}
			}
		}
	}

	return nullptr;
}

bool RuntimeLinker::GetOriginalUd2ProgramInfo(uint64_t vaddr, uint64_t* base_vaddr,
                                              std::filesystem::path* file_name) {
	if (base_vaddr == nullptr || file_name == nullptr) {
		return false;
	}
	Common::LockGuard lock(m_mutex);
	for (auto* program: m_programs) {
		if (program == nullptr || program->elf == nullptr) {
			continue;
		}
		const auto* ehdr = program->elf->GetEhdr();
		const auto* phdr = program->elf->GetPhdr();
		if (phdr == nullptr || ehdr == nullptr) {
			continue;
		}
		const uint64_t image_base = program->elf->GetStaticImageBase();
		for (Elf64_Half index = 0; index < ehdr->e_phnum; ++index) {
			if (phdr[index].p_type != PT_LOAD || phdr[index].p_memsz == 0 ||
			    (phdr[index].p_flags & PF_X) == 0 || phdr[index].p_vaddr < image_base) {
				continue;
			}
			const uint64_t relative = phdr[index].p_vaddr - image_base;
			if (relative > UINT64_MAX - program->base_vaddr) {
				continue;
			}
			const uint64_t start = program->base_vaddr + relative;
			if (vaddr < start) {
				continue;
			}
			const uint64_t offset = vaddr - start;
			if (offset < phdr[index].p_filesz && phdr[index].p_filesz - offset >= 2 &&
			    std::find(program->original_ud2_sites.begin(), program->original_ud2_sites.end(),
			              vaddr) != program->original_ud2_sites.end()) {
				*base_vaddr = program->base_vaddr;
				*file_name  = program->file_name;
				return true;
			}
		}
	}
	return false;
}

void RuntimeLinker::StackTrace(uint64_t frame_ptr, uint64_t stack_ptr) {
	void* stack[20];
	int   depth = WalkGuestStack(frame_ptr, stack_ptr, stack, static_cast<int>(std::size(stack)));

	LOGF("Stack trace [thread = %d]:\n", Common::Thread::GetThreadIdUnique());

	for (int i = 0; i < depth; i++) {
		auto  vaddr = reinterpret_cast<uint64_t>(stack[i]);
		auto* p     = FindProgramByAddr(vaddr);
		LOGF("[%d] %016" PRIx64 ", off=%016" PRIx64 ", %s\n", i, vaddr,
		     (p == nullptr ? 0 : vaddr - p->base_vaddr),
		     (p == nullptr
		          ? "???"
		          : Common::FilenameWithoutDirectory(Common::PathToGenericString(p->file_name))
		                .c_str()));
	}
}

void RuntimeLinker::StopAllModules() {
	Common::LockGuard lock(m_mutex);

	for (auto* p: m_programs) {
		if (p->elf->IsShared() && p->dynamic_info->fini_vaddr != 0) {
			StopModule(p, 0, nullptr, nullptr);
		}
	}
}

int RuntimeLinker::AcquireShellUiNpCommonPool() {
	if (m_shellui_npcommon_pool_owned) {
		return Libs::LibKernel::KERNEL_ERROR_EBUSY;
	}
	Program* provider = nullptr;
	for (auto* module: m_needed_modules) {
		if (module != nullptr && module->dynamic_info != nullptr &&
		    std::strcmp(module->dynamic_info->so_name, "libSceNpCommon.prx") == 0) {
			provider = module;
			break;
		}
	}
	if (provider == nullptr || provider->module_state != Program::ModuleState::Started ||
	    provider->export_symbols == nullptr) {
		return Libs::LibKernel::KERNEL_ERROR_ENOENT;
	}
	const auto* acquire = provider->export_symbols->FindByNid("kgDwlmy78k0", SymbolType::Func);
	const auto* release = provider->export_symbols->FindByNid("CI2p6Viee9w", SymbolType::Func);
	if (acquire == nullptr || release == nullptr) {
		return Libs::LibKernel::KERNEL_ERROR_ENOSYS;
	}
	using pool_func_t = KYTY_SYSV_ABI int (*)();
	const int result  = reinterpret_cast<pool_func_t>(acquire->vaddr)();
	if (result == OK) {
		m_shellui_npcommon_pool_provider = provider;
		m_shellui_npcommon_pool_release  = release->vaddr;
		m_shellui_npcommon_pool_owned    = true;
	}
	return result;
}

int RuntimeLinker::ReleaseShellUiNpCommonPool() {
	if (!m_shellui_npcommon_pool_owned || m_shellui_npcommon_pool_release == 0) {
		return Libs::LibKernel::KERNEL_ERROR_ENOENT;
	}
	using pool_func_t                = KYTY_SYSV_ABI int (*)();
	const auto release               = m_shellui_npcommon_pool_release;
	m_shellui_npcommon_pool_provider = nullptr;
	m_shellui_npcommon_pool_release  = 0;
	m_shellui_npcommon_pool_owned    = false;
	return reinterpret_cast<pool_func_t>(release)();
}

int RuntimeLinker::StartModule(Program* program, size_t args, const void* argp,
                               module_func_t func) {
	{
		Common::LockGuard lock(m_mutex);
		if (std::find(m_programs.begin(), m_programs.end(), program) == m_programs.end()) {
			return Libs::LibKernel::KERNEL_ERROR_ESRCH;
		}
		EXIT_IF(program->dynamic_info == nullptr || program->elf == nullptr ||
		        !program->elf->IsShared());
		if (program->module_state == Program::ModuleState::Started) {
			return program->module_start_result;
		}
		if (program->module_state != Program::ModuleState::NotStarted) {
			return Libs::LibKernel::KERNEL_ERROR_EBUSY;
		}
		program->module_state          = Program::ModuleState::Starting;
		program->native_init_attempted = program->dynamic_info->init_vaddr != 0;
		++program->active_module_calls;
	}

	LOGF_COLOR(Log::Color::BrightYellow, "---\n--- Start module: %s\n---\n",
	           Common::PathToString(program->file_name).c_str());

	const int result =
	    program->dynamic_info->init_vaddr == 0
	        ? OK
	        : reinterpret_cast<module_ini_fini_func_t>(program->dynamic_info->init_vaddr +
	                                                   program->base_vaddr)(args, argp, func);
	{
		Common::LockGuard lock(m_mutex);
		--program->active_module_calls;
		program->module_start_result = result;
		program->module_state =
		    result < 0 ? Program::ModuleState::StartFailed : Program::ModuleState::Started;
		m_module_start_order.push_back(program->unique_id);
	}
	return result;
}

int RuntimeLinker::StopModule(Program* program, size_t args, const void* argp, module_func_t func) {
	{
		Common::LockGuard lock(m_mutex);
		if (std::find(m_programs.begin(), m_programs.end(), program) == m_programs.end()) {
			return Libs::LibKernel::KERNEL_ERROR_ESRCH;
		}
		EXIT_IF(program->dynamic_info == nullptr || program->elf == nullptr ||
		        !program->elf->IsShared());
		if (program->module_state == Program::ModuleState::Stopped) {
			return program->module_stop_result;
		}
		if (program->module_state == Program::ModuleState::NotStarted) {
			return OK;
		}
		if (program->module_state == Program::ModuleState::Starting ||
		    program->module_state == Program::ModuleState::Stopping ||
		    IsThreadAtexitReferenced(program)) {
			return Libs::LibKernel::KERNEL_ERROR_EBUSY;
		}
		program->module_state = Program::ModuleState::Stopping;
		++program->active_module_calls;
	}

	LOGF_COLOR(Log::Color::BrightYellow, "---\n--- Stop module: %s\n---\n",
	           Common::PathToString(program->file_name).c_str());

	const int result =
	    program->dynamic_info->fini_vaddr == 0
	        ? OK
	        : reinterpret_cast<module_ini_fini_func_t>(program->dynamic_info->fini_vaddr +
	                                                   program->base_vaddr)(args, argp, func);
	Libs::LibKernel::PthreadDeleteStaticObjects(program);
	{
		Common::LockGuard lock(m_mutex);
		--program->active_module_calls;
		program->module_stop_result = result;
		program->module_state       = Program::ModuleState::Stopped;
		std::erase(m_module_start_order, program->unique_id);
	}

	return result;
}

uint8_t* RuntimeLinker::TlsGetAddr(Program* program) {
	EXIT_IF(program == nullptr);

	Common::LockGuard lock(program->tls.mutex);

	auto& tls = program->tls.tlss[Common::Thread::GetThreadIdUnique()];

	if (tls.ptr == nullptr) {
		constexpr uint64_t TCB_SIZE  = 0x40;
		constexpr uint64_t TCB_ALIGN = 0x20;

		const auto tcb_offset =
		    program->tls.tcb_offset != 0 ? program->tls.tcb_offset : program->tls.image_size;
		const auto alloc_size = AlignUp(tcb_offset, TCB_ALIGN) + TCB_SIZE;
		tls.ptr        = reinterpret_cast<uint8_t*>(Libs::LibKernel::Memory::AllocateRuntimeMemory(
		    0, alloc_size, Common::VirtualMemory::Mode::ReadWrite, "thread_local_storage"));
		tls.free_func  = nullptr;
		tls.vm_alloc   = true;
		tls.alloc_size = alloc_size;

		EXIT_IF(tls.ptr == nullptr);

		std::memset(tls.ptr, 0, alloc_size);

		if (!program->tls.init_image.empty()) {
			std::memcpy(tls.ptr, program->tls.init_image.data(), program->tls.init_image.size());
		} else {
			std::memcpy(tls.ptr, reinterpret_cast<void*>(program->tls.image_vaddr),
			            program->tls.init_size);
		}

		auto* tcb = reinterpret_cast<uint64_t*>(tls.ptr + tcb_offset);
		tcb[0]    = reinterpret_cast<uint64_t>(tcb);
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		if (program->file_name.filename() == "SceSysCore.elf" &&
		    std::getenv("KYTY_DIAGNOSTIC_SYSCORE_GUEST_THREAD_FS10") != nullptr) {
			const auto guest_thread = Libs::LibKernel::PthreadSelfOrNull();
			if (guest_thread != nullptr) {
				tcb[2] = reinterpret_cast<uint64_t>(guest_thread);
				LOGF("FIRST_FRAME_AUDIT SYSCORE_GUEST_THREAD_TCB"
				     " tcb=0x%016" PRIx64 " model_thread=0x%016" PRIx64 "\n",
				     reinterpret_cast<uint64_t>(tcb), tcb[2]);
			}
		}
#endif
	}

	return tls.ptr;
}

void RuntimeLinker::DeleteTls(Program* program, int thread_id) {
	EXIT_IF(program == nullptr);

	if (thread_id == Common::Thread::GetThreadIdUnique() && g_tls_cached_main_program == program) {
		g_tls_cached_main_program = nullptr;
		g_tls_cached_main_tcb     = nullptr;
	}

	Common::LockGuard lock(program->tls.mutex);

	if (auto it = program->tls.tlss.find(thread_id); it != program->tls.tlss.end()) {
		FreeTlsBlock(&it->second);
		program->tls.tlss.erase(it);
	}
}

static uint64_t CalcBaseSize(const Elf64_Ehdr* ehdr, const Elf64_Phdr* phdr,
                             uint64_t image_offset) {
	uint64_t base_size = 0;
	for (Elf64_Half i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_memsz != 0 && (phdr[i].p_type == PT_LOAD || phdr[i].p_type == PT_OS_RELRO)) {
			uint64_t last_addr = phdr[i].p_vaddr - image_offset + GetAlignedSize(phdr + i);
			if (last_addr > base_size) {
				base_size = last_addr;
			}
		}
	}
	return base_size;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
void RuntimeLinker::LoadProgramToMemory(Program* program) {
	KYTY_PROFILER_FUNCTION();

	EXIT_IF(program == nullptr || program->base_vaddr != 0 || program->base_size != 0 ||
	        program->elf == nullptr);

	// static uint64_t desired_base_addr = DESIRED_BASE_ADDR;

	bool is_shared   = program->elf->IsShared();
	bool is_next_gen = program->elf->IsNextGen();
	const bool     static_exec  = program->elf->IsStaticExec();
	const uint64_t image_offset = program->elf->GetStaticImageBase();

	EXIT_NOT_IMPLEMENTED(!is_shared && !is_next_gen);
	EXIT_IF(static_exec && (image_offset == 0 || (image_offset & 0x3fffu) != 0));

	const auto* ehdr = program->elf->GetEhdr();
	const auto* phdr = program->elf->GetPhdr();

	EXIT_IF(phdr == nullptr || ehdr == nullptr);

	program->base_size                 = CalcBaseSize(ehdr, phdr, image_offset);
	constexpr uint64_t GUEST_PAGE_SIZE = 0x4000;
	EXIT_IF(program->base_size > UINT64_MAX - (GUEST_PAGE_SIZE - 1));
	program->base_size_aligned = AlignUp(program->base_size, GUEST_PAGE_SIZE);

	uint64_t tls_handler_size = is_shared ? 0 : Jit::SafeCall::GetSize();
	EXIT_IF(tls_handler_size > UINT64_MAX - program->base_size_aligned);
	program->mapped_size = program->base_size_aligned + tls_handler_size;
#if !defined(__APPLE__)
	const bool emulate_amd = Config::AmdCpuEnabled();
#else
	const bool emulate_amd = false;
#endif
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	const bool protect_memory_faults = Config::RedZoneProtectionEnabled();
#else
	const bool protect_memory_faults = false;
#endif
	const bool patch_guest_instructions = protect_memory_faults || emulate_amd;

	constexpr uint64_t INSTRUCTION_TRAMPOLINE_SIZE = 8u * 1024u * 1024u;
	if (patch_guest_instructions) {
		EXIT_IF(INSTRUCTION_TRAMPOLINE_SIZE > UINT64_MAX - program->mapped_size);
		program->mapped_size += INSTRUCTION_TRAMPOLINE_SIZE;
	}

	// libSceGnmDriver module start only accepts SceGnmDriver at 0xfe0000000 and hints /dev/gc,
	// SceGnmGpuInfo at 0xfe0200000, 0xfe0300000; tess factor ring at 0xff0000000. AgcCompositor
	// client shm is 0x1000000000 + (client << 33), mapped MAP_FIXED by the client over anything
	// loaded there.
	constexpr uint64_t GUEST_FIXED_BEGIN = 0xfe0000000u;
	constexpr uint64_t GUEST_FIXED_END   = 0x2000000000u;
	if (g_desired_base_addr < GUEST_FIXED_END &&
	    g_desired_base_addr + program->mapped_size > GUEST_FIXED_BEGIN) {
		g_desired_base_addr = GUEST_FIXED_END;
	}

	program->base_vaddr = Libs::LibKernel::Memory::AllocateProgramMemory(
	    static_exec ? image_offset : g_desired_base_addr, program->mapped_size,
	    Common::VirtualMemory::Mode::ExecuteReadWrite,
	    Common::PathToString(program->file_name.filename()).c_str(), static_exec);
	EXIT_IF(program->base_vaddr == 0);
	EXIT_IF(static_exec && program->base_vaddr != image_offset);

	if (patch_guest_instructions) {
		const auto trampoline_addr           = program->base_vaddr + program->base_size_aligned;
		program->instruction_trampoline_size = INSTRUCTION_TRAMPOLINE_SIZE;
		RegisterGuestInstructionPatchModule(
		    reinterpret_cast<void*>(program->base_vaddr), program->base_size_aligned,
		    reinterpret_cast<void*>(trampoline_addr), program->instruction_trampoline_size);
	}
	if (!is_shared) {
		program->tls.handler_vaddr =
		    program->base_vaddr + program->base_size_aligned + program->instruction_trampoline_size;
	}

	g_desired_base_addr += CODE_BASE_INCR * (1 + program->mapped_size / CODE_BASE_INCR);

	EXIT_IF(program->base_size_aligned < program->base_size);
	LOGF("base_vaddr             = 0x%016" PRIx64 "\n"
	     "base_size              = 0x%016" PRIx64 "\n"
	     "base_size_aligned      = 0x%016" PRIx64 "\n"
	     "mapped_size            = 0x%016" PRIx64 "\n",
	     program->base_vaddr, program->base_size, program->base_size_aligned, program->mapped_size);
	if (!is_shared) {
		LOGF("tls_handler_size       = 0x%016" PRIx64 "\n", tls_handler_size);
	}

	if (!Common::HostException::InstallHandler(KytyExceptionHandler)) {
		EXIT("Failed to install the required vectored exception handler\n");
	}

	std::vector<std::pair<uint64_t, uint64_t>> executable_segments;
	uint64_t                                   eh_frame_header_addr = 0;
	uint64_t                                   eh_frame_header_size = 0;

	for (Elf64_Half i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_memsz != 0 && (phdr[i].p_type == PT_LOAD || phdr[i].p_type == PT_OS_RELRO)) {
			uint64_t segment_addr        = phdr[i].p_vaddr - image_offset + program->base_vaddr;
			uint64_t segment_file_size   = phdr[i].p_filesz;
			uint64_t segment_memory_size = GetAlignedSize(phdr + i);
			auto     mode                = GetMode(phdr[i].p_flags);

			LOGF("[%d] addr        = 0x%016" PRIx64 "\n"
			     "[%d] file_size   = %" PRIu64 "\n"
			     "[%d] memory_size = %" PRIu64 "\n"
			     "[%d] mode        = %s\n",
			     i, segment_addr, i, segment_file_size, i, segment_memory_size, i,
			     magic_enum::enum_name(mode));

			program->elf->LoadSegment(segment_addr, phdr[i].p_offset, segment_file_size);

			bool skip_protect = (phdr[i].p_type == PT_LOAD && is_next_gen &&
			                     mode == Common::VirtualMemory::Mode::NoAccess);

			if (Common::VirtualMemory::IsExecute(mode)) {
				if (segment_file_size >= 2) {
					const auto* bytes = reinterpret_cast<const uint8_t*>(segment_addr);
					for (uint64_t offset = 0; offset < segment_file_size - 1; ++offset) {
						if (bytes[offset] == 0x0f && bytes[offset + 1] == 0x0b) {
							program->original_ud2_sites.push_back(segment_addr + offset);
						}
					}
				}
				const auto patch_start = std::chrono::steady_clock::now();
				PatchProgram(program, segment_addr, segment_memory_size);
				g_exec_load_timing.patch_us += MicrosecondsSince(patch_start);
				executable_segments.emplace_back(segment_addr, segment_file_size);
			}

			if (!skip_protect) {
				Libs::LibKernel::Memory::SetProgramMemoryProtection(segment_addr,
				                                                    segment_memory_size, mode);

				if (Common::VirtualMemory::IsExecute(mode)) {
					Common::VirtualMemory::FlushInstructionCache(segment_addr, segment_memory_size);
				}
			}
			if (Common::VirtualMemory::IsExecute(mode)) {
				const auto owner = Common::PathToString(program->file_name.filename());
				const auto detail =
				    fmt::format("{}#{}", phdr[i].p_type == PT_LOAD ? "PT_LOAD" : "PT_OS_RELRO", i);
				const auto token = Common::HostException::RegisterGuestCodeProvenance(
				    {segment_addr, segment_memory_size, program->base_vaddr,
					 phdr[i].p_vaddr - image_offset,
					 Common::HostException::FaultGuestCodeKind::ProgramExecutable, owner.c_str(),
					 detail.c_str()});
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
				EXIT_IF(token == 0);
#endif
				if (token != 0) program->host_exception_code_tokens.push_back(token);
			}
		}

		if (phdr[i].p_type == PT_TLS) {
			EXIT_IF(phdr[i].p_vaddr < image_offset ||
			        phdr[i].p_vaddr - image_offset >= program->base_size);

			program->tls.image_vaddr = phdr[i].p_vaddr - image_offset + program->base_vaddr;
			program->tls.init_size   = std::min(phdr[i].p_filesz, GetAlignedSize(phdr + i));
			program->tls.image_size  = GetAlignedSize(phdr + i);
			program->tls.tcb_offset  = program->tls.image_size;

			LOGF("tls addr = 0x%016" PRIx64 "\n"
			     "tls init   = %" PRIu64 "\n"
			     "tls size   = %" PRIu64 "\n"
			     "tls offset = %" PRIu64 "\n",
			     program->tls.image_vaddr, program->tls.init_size, program->tls.image_size,
			     program->tls.tcb_offset);
		}

		if (phdr[i].p_type == PT_OS_PROCPARAM) {
			EXIT_IF(program->proc_param_vaddr != 0);
			EXIT_IF(phdr[i].p_vaddr < image_offset ||
			        phdr[i].p_vaddr - image_offset >= program->base_size);

			program->proc_param_vaddr = phdr[i].p_vaddr - image_offset + program->base_vaddr;
		}

		if (patch_guest_instructions && phdr[i].p_type == PT_GNU_EH_FRAME) {
			eh_frame_header_addr = phdr[i].p_vaddr - image_offset + program->base_vaddr;
			eh_frame_header_size = phdr[i].p_memsz;
		}
	}

	if (program->file_name.filename() == "SceSysCore.elf" &&
	    std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD") != nullptr) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		const uint64_t           code = program->base_vaddr + 0x3921e;
		MEMORY_BASIC_INFORMATION host {};
		const SIZE_T queried = VirtualQuery(reinterpret_cast<LPCVOID>(code), &host, sizeof(host));
		Libs::LibKernel::Memory::VirtualQueryInfo guest {};
		const int query_rc = Libs::LibKernel::Memory::KernelVirtualQuery(
		    reinterpret_cast<const void*>(code), 0, &guest, sizeof(guest));
		LOGF("SYSCORE_INITIAL_DTL_CODEPAGE_STATE"
		     " guest_pc=%016" PRIx64 " native_queried=%zu"
		     " native_state=%08x native_protect=%08x"
		     " native_region=%zu guest_query_rc=%d"
		     " guest_committed=%d guest_protection=%08x\n",
		     code, static_cast<size_t>(queried), static_cast<unsigned>(host.State),
		     static_cast<unsigned>(host.Protect), static_cast<size_t>(host.RegionSize), query_rc,
		     guest.is_committed, guest.protection);
#endif
	}
	if (patch_guest_instructions) {
		std::vector<uintptr_t> function_starts;
		const bool             have_function_starts =
		    DecodeEhFrameFunctionStarts(eh_frame_header_addr, eh_frame_header_size,
		                                &function_starts) &&
		    !function_starts.empty();
		const auto module_name = Common::PathToString(program->file_name.filename());
		if (!have_function_starts) {
			Log::WriteToConsoleAndLog(
			    fmt::format("{}: {} not patched (function boundaries unavailable)\n",
			                emulate_amd ? "AMD CPU compatibility" : "Guest red-zone protection",
			                module_name));
		}
		GuestInstructionPatchResult totals {};
		for (const auto& [segment_addr, segment_size]: executable_segments) {
			const auto result = PatchGuestInstructions(segment_addr, segment_size, function_starts,
			                                           protect_memory_faults, emulate_amd);
			totals.reciprocal_sqrt += result.reciprocal_sqrt;
			totals.extrq += result.extrq;
			totals.insertq += result.insertq;
			totals.rdpid += result.rdpid;
			totals.clwb += result.clwb;
			if (protect_memory_faults) {
				LOGF("Windows guest red-zone patching: %s, functions=%" PRIu64 ", red_zone=%" PRIu64
				     ", memory=%" PRIu64 ", patched=%" PRIu64 ", short=%" PRIu64 ", stack=%" PRIu64
				     ", control=%" PRIu64 ", unrelocatable=%" PRIu64 "\n",
				     module_name.c_str(),
				     result.function_count, result.red_zone_function_count,
				     result.memory_instruction_count, result.patched_memory_instruction_count,
				     result.short_memory_instruction_count,
				     result.stack_dependent_memory_instruction_count,
				     result.control_flow_memory_instruction_count,
				     result.unrelocatable_memory_instruction_count);
			}
		}
		if (emulate_amd && have_function_starts) {
			InstructionPatchCounts combined {};
			std::string            details;
			for (const auto& [name, counts]: {std::pair {"VRSQRTPS", totals.reciprocal_sqrt},
			                                  {"EXTRQ", totals.extrq},
			                                  {"INSERTQ", totals.insertq},
			                                  {"RDPID", totals.rdpid},
			                                  {"CLWB", totals.clwb}}) {
				combined += counts;
				if (!details.empty()) details += "; ";
				details += fmt::format("{}: native={}, trapped={}, skipped={}", name, counts.native,
				                       counts.trapped, counts.Skipped());
			}
			const auto  found   = combined.found;
			const auto  skipped = combined.Skipped();
			const char* status  = found == 0         ? "no matching instructions"
			                      : skipped == found ? "not patched"
			                      : skipped != 0     ? "partially patched"
			                                         : "patched";
			Log::WriteToConsoleAndLog(
			    fmt::format("AMD CPU compatibility: {} {} ({})\n", module_name, status, details));
		}
	}

	if (!is_shared) {
		SetupTlsHandler(program);
	}

	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_KQUEUE_RESULT_AUDIT") != nullptr &&
	    program->file_name.filename() == "SceSysCore.elf") {
		constexpr uint64_t site = 0x326e;
		EXIT_IF(site + 2 > program->base_size_aligned);
		auto* code = reinterpret_cast<uint8_t*>(program->base_vaddr + site);
		EXIT_IF(code[0] != 0x85 || code[1] != 0xc0);
		code[0] = 0x0f;
		code[1] = 0x0b;
		EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(program->base_vaddr,
		                                                      program->base_size_aligned));
		g_syscore_native_kqueue_result_site.store(program->base_vaddr + site,
		                                          std::memory_order_release);
		LOGF("SYSCORE_KQUEUE_RETURN_PROBE_VALIDATED"
		     " site=%016" PRIx64 " test_eax_eax\n",
		     program->base_vaddr + site);
	}
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_RFORK_GUEST_ENTRY_AUDIT") != nullptr &&
	    program->file_name.filename() == "SceSysCore.elf") {
		constexpr uint64_t site = 0x3a31;
		EXIT_IF(site + 3 > program->base_size_aligned);
		auto* code = reinterpret_cast<uint8_t*>(program->base_vaddr + site);
		EXIT_IF(code[0] != 0x48 || code[1] != 0x89 || code[2] != 0xe5);
		code[0] = 0x0f;
		code[1] = 0x0b;
		code[2] = 0x90;
		EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(program->base_vaddr,
		                                                      program->base_size_aligned));
		g_syscore_native_rfork_child_entry_site.store(program->base_vaddr + site,
		                                              std::memory_order_release);
		LOGF("SYSCORE_RFORK_GUEST_ENTRY_PROBE_VALIDATED"
		     " entry=0x900003a30 prologue_match\n");
	}
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_CHILD_FAILURE_EDGES") != nullptr &&
	    program->file_name.filename() == "SceSysCore.elf") {
		constexpr std::array<uint64_t, 5> sites = {0x3a83, 0x3ad5, 0x3af0, 0x3b0b, 0x3b4b};
		for (const uint64_t site: sites) {
			EXIT_IF(site + 2 > program->base_size_aligned);
			const auto* op = reinterpret_cast<const uint8_t*>(program->base_vaddr + site);
			EXIT_IF(op[0] != 0x85 || op[1] != 0xc0);
		}
		for (uint32_t i = 0; i < sites.size(); ++i) {
			auto* op = reinterpret_cast<uint8_t*>(program->base_vaddr + sites[i]);
			op[0]    = 0x0f;
			op[1]    = 0x0b;
			g_syscore_native_child_failure_sites[i].store(program->base_vaddr + sites[i],
			                                              std::memory_order_release);
		}
		EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(program->base_vaddr,
		                                                      program->base_size_aligned));
		LOGF("SYSCORE_CHILD_FAILURE_EDGES_VALIDATED"
		     " test_sites=5 bytes_verified\n");
	}
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_RFORK_CHILD_SETUP_AUDIT") != nullptr &&
	    program->file_name.filename() == "SceSysCore.elf") {
		constexpr uint64_t site = 0x3b31;
		EXIT_IF(site + 2 > program->base_size_aligned);
		auto* op = reinterpret_cast<uint8_t*>(program->base_vaddr + site);
		EXIT_IF(op[0] != 0x85 || op[1] != 0xc0);
		op[0] = 0x0f;
		op[1] = 0x0b;
		EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(program->base_vaddr,
		                                                      program->base_size_aligned));
		g_syscore_native_child_setup_result_site.store(program->base_vaddr + site,
		                                               std::memory_order_release);
		LOGF("SYSCORE_CHILD_SETUP_RESULT_PROBE_VALIDATED"
		     " site=0x900003b31 test_match\n");
	}
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LAUNCH_ENTRY_AUDIT") != nullptr &&
	    program->file_name.filename() == "SceSysCore.elf") {
		constexpr uint64_t site = 0x31c1;
		EXIT_IF(site + 3 > program->base_size_aligned);
		auto* op = reinterpret_cast<uint8_t*>(program->base_vaddr + site);
		EXIT_IF(op[0] != 0x48 || op[1] != 0x89 || op[2] != 0xe5);
		op[0] = 0x0f;
		op[1] = 0x0b;
		op[2] = 0x90;
		EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(program->base_vaddr,
		                                                      program->base_size_aligned));
		g_syscore_native_launch_entry_site.store(program->base_vaddr + site,
		                                         std::memory_order_release);
		LOGF("SYSCORE_LOWER_LAUNCH_ENTRY_VALIDATED"
		     " site=%016" PRIx64 " mov_rbp_rsp\n",
		     program->base_vaddr + site);
	}
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_VFPRINTF_AUDIT") != nullptr &&
	    program->file_name.filename() == "libSceLibcInternal.sprx") {
		constexpr uint64_t vfprintf_push_r15_offset = 0x35224;
		EXIT_IF(vfprintf_push_r15_offset + 2 > program->base_size_aligned);
		auto* code = reinterpret_cast<uint8_t*>(program->base_vaddr + vfprintf_push_r15_offset);
		EXIT_IF(code[0] != 0x41 || code[1] != 0x57);
		code[0] = 0x0f;
		code[1] = 0x0b;
		EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(program->base_vaddr,
		                                                      program->base_size_aligned));
		g_syscore_original_vfprintf_probe.store(program->base_vaddr + vfprintf_push_r15_offset,
		                                        std::memory_order_release);
		LOGF("SYSCORE_VFPRINTF_VALIDATED_IN_MEMORY_PROBE"
		     " site=%016" PRIx64 " push_r15=4157\n",
		     program->base_vaddr + vfprintf_push_r15_offset);
	}

	if (std::getenv("KYTY_DIAGNOSTIC_AGC_NATIVE_KEVENT_AUDIT") != nullptr &&
	    program->file_name.filename() == "libkernel.sprx") {
		constexpr uint64_t syscall_offset = 0x144a;
		EXIT_IF(syscall_offset + 2 > program->base_size_aligned);
		auto* site = reinterpret_cast<uint8_t*>(program->base_vaddr + syscall_offset);
		EXIT_IF(site[0] != 0x0f || site[1] != 0x05);
		site[1] = 0x0b;
		EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(program->base_vaddr,
		                                                      program->base_size_aligned));
		g_agc_native_kevent_syscall_site.store(program->base_vaddr + syscall_offset,
		                                       std::memory_order_release);
		LOGF("AGC_NATIVE_KEVENT_TRAP_VALIDATED"
		     " site=%016" PRIx64 " number=0x16b\n",
		     program->base_vaddr + syscall_offset);
	}
	if ((std::getenv("KYTY_DIAGNOSTIC_SYSCORE_RFORK_AUDIT") != nullptr ||
	     std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD") != nullptr) &&
	    program->file_name.filename() == "libkernel.sprx") {
		constexpr uint64_t rfork_offset = 0x1b3;
		EXIT_IF(rfork_offset + 2 > program->base_size_aligned);
		auto* code = reinterpret_cast<uint8_t*>(program->base_vaddr + rfork_offset);
		EXIT_IF(code[0] != 0x0f || code[1] != 0x05);
		code[1] = 0x0b;
		EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(program->base_vaddr,
		                                                      program->base_size_aligned));
		g_syscore_native_rfork_site.store(program->base_vaddr + rfork_offset,
		                                  std::memory_order_release);
		const auto provenance =
		    Common::HostException::QueryActiveGuestCodeKind(program->base_vaddr + rfork_offset);
		LOGF("SYSCORE_RFORK_VALIDATED_NATIVE_TRAP"
		     " site=%016" PRIx64 " syscall=0xfb"
		     " provenance_kind=%u provenance_active=%u\n",
		     program->base_vaddr + rfork_offset, static_cast<unsigned>(provenance),
		     provenance != Common::HostException::FaultGuestCodeKind::Unavailable ? 1u : 0u);
	}
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_EXECVE_AUDIT") != nullptr &&
	    program->file_name.filename() == "libkernel.sprx") {
		constexpr uint64_t execve_offset = 0x7ea;
		EXIT_IF(execve_offset + 2 > program->base_size_aligned);
		auto* code = reinterpret_cast<uint8_t*>(program->base_vaddr + execve_offset);
		EXIT_IF(code[0] != 0x0f || code[1] != 0x05);
		code[1] = 0x0b;
		EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(program->base_vaddr,
		                                                      program->base_size_aligned));
		g_syscore_native_execve_site.store(program->base_vaddr + execve_offset,
		                                   std::memory_order_release);
		LOGF("SYSCORE_EXECVE_VALIDATED_NATIVE_TRAP"
		     " site=%016" PRIx64 " guest_syscall=0x3b\n",
		     program->base_vaddr + execve_offset);
	}
	if ((std::getenv("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP") != nullptr ||
	     Libs::LibKernel::Process::IsExecChild()) &&
	    std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") != nullptr &&
	    program->file_name.filename() == "libkernel.sprx") {
		constexpr uint32_t mmap_offset     = 0x186a;
		constexpr uint32_t name_offset     = 0x1eaa;
		constexpr uint32_t extended_offset = 0x2cea;
		EXIT_IF(extended_offset + 2 > program->base_size_aligned);
		auto* mmap_code     = reinterpret_cast<uint8_t*>(program->base_vaddr + mmap_offset);
		auto* name_code     = reinterpret_cast<uint8_t*>(program->base_vaddr + name_offset);
		auto* extended_code = reinterpret_cast<uint8_t*>(program->base_vaddr + extended_offset);
		EXIT_IF(mmap_code[0] != 0x0f || mmap_code[1] != 0x05 || name_code[0] != 0x0f ||
		        name_code[1] != 0x05 || extended_code[0] != 0x0f || extended_code[1] != 0x05);
		mmap_code[1]     = 0x0b;
		name_code[1]     = 0x0b;
		extended_code[1] = 0x0b;
		EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(program->base_vaddr,
		                                                      program->base_size_aligned));
		g_exec_child_native_mmap_site.store(program->base_vaddr + mmap_offset,
		                                    std::memory_order_release);
		g_exec_child_native_name_site.store(program->base_vaddr + name_offset,
		                                    std::memory_order_release);
		g_exec_child_native_extended_mmap_site.store(program->base_vaddr + extended_offset,
		                                             std::memory_order_release);
		LOGF("FIRST_FRAME_AUDIT EXEC_CHILD_NATIVE_LIBKERNEL_SYSCALL_TRAPS"
		     " mmap_site=0x%016" PRIx64 " name_site=0x%016" PRIx64
		     " extended_mmap_site=0x%016" PRIx64 "\n",
		     program->base_vaddr + mmap_offset, program->base_vaddr + name_offset,
		     program->base_vaddr + extended_offset);
	}

	if (std::getenv("KYTY_DIAGNOSTIC_MINI_SYSCORE_NATIVE_TRAPS") != nullptr &&
	    std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") != nullptr &&
	    program->file_name.filename() == "mini-syscore.elf") {
		EXIT_IF(program->base_vaddr != 0x400000);
		for (const auto offset: g_mini_native_syscall_offsets) {
			EXIT_IF(offset + 2 > program->base_size_aligned);
			const auto* site = reinterpret_cast<const uint8_t*>(program->base_vaddr + offset);
			EXIT_IF(site[0] != 0x0f || site[1] != 0x05);
		}
		for (const auto offset: g_mini_native_syscall_offsets) {
			auto* site = reinterpret_cast<uint8_t*>(program->base_vaddr + offset);
			site[1]    = 0x0b;
		}
		EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(program->base_vaddr,
		                                                      program->base_size_aligned));
		g_mini_native_syscall_traps_installed.store(true, std::memory_order_release);
		LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_NATIVE_TRAPS"
		     " count=%zu base=0x%016" PRIx64 " checked_elf_syscall_opcodes=1\n",
		     g_mini_native_syscall_offsets.size(), program->base_vaddr);
		if (std::getenv("KYTY_DIAGNOSTIC_MINI_UPDATEMODE_RETURN_AUDIT") != nullptr) {
			constexpr uint32_t offset = 0x5036;
			auto*              code   = reinterpret_cast<uint8_t*>(program->base_vaddr + offset);
			EXIT_IF(code[0] != 0x85 || code[1] != 0xc0);
			code[0] = 0x0f;
			code[1] = 0x0b;
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(program->base_vaddr + offset, 2));
			g_mini_updatemode_return_site.store(program->base_vaddr + offset,
			                                    std::memory_order_release);
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_UPDATEMODE_RETURN_PROBE"
			     " site=0x%016" PRIx64 " test_eax_eax=1\n",
			     program->base_vaddr + offset);
		}
		if (std::getenv("KYTY_DIAGNOSTIC_UPDATEMODE_SPAWN_PASSTHRU") != nullptr) {
			constexpr uint32_t offset = 0x5031;
			auto*              code   = reinterpret_cast<uint8_t*>(program->base_vaddr + offset);
			constexpr uint8_t  original_call[] = {0xe8, 0x9a, 0x7c, 0x00, 0x00};
			EXIT_IF(std::memcmp(code, original_call, sizeof(original_call)) != 0);
			code[0] = 0x0f;
			code[1] = 0x0b;
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(program->base_vaddr + offset,
			                                                      sizeof(original_call)));
			g_mini_updatemode_spawn_passthru_site.store(program->base_vaddr + offset,
			                                            std::memory_order_release);
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_UPDATEMODE_SPAWN_PASSTHRU_PROBE"
			     " site=0x%016" PRIx64 " call_rel32=e8_9a_7c_00_00"
			     " target_sub_40ccd0\n",
			     program->base_vaddr + offset);
		}
		if (std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_RESCUE_DISCRIMINATOR") != nullptr) {
			constexpr uint32_t hdd_offset   = 0x49ba;
			constexpr uint32_t ext_offset   = 0x5d06;
			constexpr uint8_t  mov_edi_f0[] = {0xbf, 0xf0, 0x00, 0x00, 0x00};
			auto*              hdd = reinterpret_cast<uint8_t*>(program->base_vaddr + hdd_offset);
			auto*              ext = reinterpret_cast<uint8_t*>(program->base_vaddr + ext_offset);
			EXIT_IF(std::memcmp(hdd, mov_edi_f0, sizeof(mov_edi_f0)) != 0);
			EXIT_IF(std::memcmp(ext, mov_edi_f0, sizeof(mov_edi_f0)) != 0);
			hdd[0] = 0x0f;
			hdd[1] = 0x0b;
			hdd[2] = 0x00;
			hdd[3] = 0x00;
			hdd[4] = 0x00;
			ext[0] = 0x0f;
			ext[1] = 0x0b;
			ext[2] = 0x00;
			ext[3] = 0x00;
			ext[4] = 0x00;
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(program->base_vaddr + hdd_offset,
			                                                      sizeof(mov_edi_f0)));
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(program->base_vaddr + ext_offset,
			                                                      sizeof(mov_edi_f0)));
			g_mini_safe_mode_hdd_rescue_site.store(program->base_vaddr + hdd_offset,
			                                       std::memory_order_release);
			g_mini_safe_mode_ext_rescue_site.store(program->base_vaddr + ext_offset,
			                                       std::memory_order_release);
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_SAFE_MODE_RESCUE_PROBES"
			     " hdd=0x%016" PRIx64 " ext=0x%016" PRIx64 " mov_edi_f0_signature\n",
			     program->base_vaddr + hdd_offset, program->base_vaddr + ext_offset);
		}
		if (std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_RESCUE_UPSTREAM_DISCRIMINATOR") != nullptr) {
			constexpr uint32_t prologue_end_offset         = 0x49b5;
			constexpr uint32_t find_hdd_failed_offset      = 0x478c;
			constexpr uint32_t eventlog_init_failed_offset = 0x4910;
			constexpr uint8_t  call_sub_471970[]           = {0xe8, 0xb6, 0xcf, 0x06, 0x00};
			constexpr uint8_t  jmp_40478c_to_4049ba[]      = {0xe9, 0x29, 0x02, 0x00, 0x00};
			constexpr uint8_t  jmp_404910_to_4049ba[]      = {0xe9, 0xa5, 0x00, 0x00, 0x00};
			auto* prologue = reinterpret_cast<uint8_t*>(program->base_vaddr + prologue_end_offset);
			auto* find_hdd =
			    reinterpret_cast<uint8_t*>(program->base_vaddr + find_hdd_failed_offset);
			auto* eventlog =
			    reinterpret_cast<uint8_t*>(program->base_vaddr + eventlog_init_failed_offset);
			EXIT_IF(std::memcmp(prologue, call_sub_471970, sizeof(call_sub_471970)) != 0);
			EXIT_IF(std::memcmp(find_hdd, jmp_40478c_to_4049ba, sizeof(jmp_40478c_to_4049ba)) != 0);
			EXIT_IF(std::memcmp(eventlog, jmp_404910_to_4049ba, sizeof(jmp_404910_to_4049ba)) != 0);
			prologue[0] = 0x0f;
			prologue[1] = 0x0b;
			prologue[2] = 0x00;
			prologue[3] = 0x00;
			prologue[4] = 0x00;
			find_hdd[0] = 0x0f;
			find_hdd[1] = 0x0b;
			find_hdd[2] = 0x00;
			find_hdd[3] = 0x00;
			find_hdd[4] = 0x00;
			eventlog[0] = 0x0f;
			eventlog[1] = 0x0b;
			eventlog[2] = 0x00;
			eventlog[3] = 0x00;
			eventlog[4] = 0x00;
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
			    program->base_vaddr + prologue_end_offset, sizeof(call_sub_471970)));
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
			    program->base_vaddr + find_hdd_failed_offset, sizeof(jmp_40478c_to_4049ba)));
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
			    program->base_vaddr + eventlog_init_failed_offset, sizeof(jmp_404910_to_4049ba)));
			g_mini_safe_mode_rescue_prologue_end_site.store(
			    program->base_vaddr + prologue_end_offset, std::memory_order_release);
			g_mini_safe_mode_rescue_find_hdd_failed_site.store(
			    program->base_vaddr + find_hdd_failed_offset, std::memory_order_release);
			g_mini_safe_mode_rescue_eventlog_init_failed_site.store(
			    program->base_vaddr + eventlog_init_failed_offset, std::memory_order_release);
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_SAFE_MODE_RESCUE_UPSTREAM_PROBES"
			     " prologue_end=0x%016" PRIx64 " find_hdd_failed=0x%016" PRIx64
			     " eventlog_init_failed=0x%016" PRIx64 " call_rel32_jmp_rel32_signatures\n",
			     program->base_vaddr + prologue_end_offset,
			     program->base_vaddr + find_hdd_failed_offset,
			     program->base_vaddr + eventlog_init_failed_offset);
		}
		if (std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_RESCUE_OPERAND_DISCRIMINATOR") != nullptr) {
			constexpr uint32_t r14d_jle_offset        = 0x4636;
			constexpr uint32_t mount_result_jz_offset = 0x465e;
			constexpr uint32_t global_flag_jz_offset  = 0x4680;
			constexpr uint32_t local_var_jz_offset    = 0x46c2;
			constexpr uint32_t dword_4d7520_offset    = 0xd7520;
			constexpr uint8_t  r14d_jle_sig[]         = {0x7e, 0x2c};
			constexpr uint8_t  mount_result_jz_sig[]  = {0x0f, 0x84, 0x98, 0x08, 0x00, 0x00};
			constexpr uint8_t  global_flag_jz_sig[]   = {0x74, 0x3c};
			constexpr uint8_t  local_var_jz_sig[]     = {0x0f, 0x84, 0x8d, 0x00, 0x00, 0x00};
			auto* r14d_site = reinterpret_cast<uint8_t*>(program->base_vaddr + r14d_jle_offset);
			auto* mount_site =
			    reinterpret_cast<uint8_t*>(program->base_vaddr + mount_result_jz_offset);
			auto* global_site =
			    reinterpret_cast<uint8_t*>(program->base_vaddr + global_flag_jz_offset);
			auto* local_site =
			    reinterpret_cast<uint8_t*>(program->base_vaddr + local_var_jz_offset);
			EXIT_IF(std::memcmp(r14d_site, r14d_jle_sig, sizeof(r14d_jle_sig)) != 0);
			EXIT_IF(std::memcmp(mount_site, mount_result_jz_sig, sizeof(mount_result_jz_sig)) != 0);
			EXIT_IF(std::memcmp(global_site, global_flag_jz_sig, sizeof(global_flag_jz_sig)) != 0);
			EXIT_IF(std::memcmp(local_site, local_var_jz_sig, sizeof(local_var_jz_sig)) != 0);
			r14d_site[0]   = 0x0f;
			r14d_site[1]   = 0x0b;
			mount_site[0]  = 0x0f;
			mount_site[1]  = 0x0b;
			mount_site[2]  = 0x00;
			mount_site[3]  = 0x00;
			mount_site[4]  = 0x00;
			mount_site[5]  = 0x00;
			global_site[0] = 0x0f;
			global_site[1] = 0x0b;
			local_site[0]  = 0x0f;
			local_site[1]  = 0x0b;
			local_site[2]  = 0x00;
			local_site[3]  = 0x00;
			local_site[4]  = 0x00;
			local_site[5]  = 0x00;
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
			    program->base_vaddr + r14d_jle_offset, sizeof(r14d_jle_sig)));
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
			    program->base_vaddr + mount_result_jz_offset, sizeof(mount_result_jz_sig)));
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
			    program->base_vaddr + global_flag_jz_offset, sizeof(global_flag_jz_sig)));
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
			    program->base_vaddr + local_var_jz_offset, sizeof(local_var_jz_sig)));
			g_mini_safe_mode_r14d_jle_site.store(program->base_vaddr + r14d_jle_offset,
			                                     std::memory_order_release);
			g_mini_safe_mode_mount_result_jz_site.store(
			    program->base_vaddr + mount_result_jz_offset, std::memory_order_release);
			g_mini_safe_mode_global_flag_jz_site.store(program->base_vaddr + global_flag_jz_offset,
			                                           std::memory_order_release);
			g_mini_safe_mode_local_var_jz_site.store(program->base_vaddr + local_var_jz_offset,
			                                         std::memory_order_release);
			g_mini_safe_mode_dword_4d7520_addr.store(program->base_vaddr + dword_4d7520_offset,
			                                         std::memory_order_release);
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_SAFE_MODE_RESCUE_OPERAND_PROBES"
			     " r14d_jle=0x%016" PRIx64 " mount_result_jz=0x%016" PRIx64
			     " global_flag_jz=0x%016" PRIx64 " local_var_jz=0x%016" PRIx64
			     " dword_4D7520=0x%016" PRIx64 " four_branch_signatures\n",
			     program->base_vaddr + r14d_jle_offset,
			     program->base_vaddr + mount_result_jz_offset,
			     program->base_vaddr + global_flag_jz_offset,
			     program->base_vaddr + local_var_jz_offset,
			     program->base_vaddr + dword_4d7520_offset);
		}
		if (std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_SYSTEM_MOUNT_RESULT_DISCRIMINATOR") != nullptr) {
			constexpr uint32_t system_mount_jnz_offset   = 0x43ed;
			constexpr uint32_t system_ex_mount_jz_offset = 0x4415;
			constexpr uint8_t  system_mount_jnz_sig[]    = {0x75, 0x3a};
			constexpr uint8_t  system_ex_mount_jz_sig[]  = {0x0f, 0x84, 0xfc, 0x03, 0x00, 0x00};
			auto*              sys_site =
			    reinterpret_cast<uint8_t*>(program->base_vaddr + system_mount_jnz_offset);
			auto* ex_site =
			    reinterpret_cast<uint8_t*>(program->base_vaddr + system_ex_mount_jz_offset);
			EXIT_IF(std::memcmp(sys_site, system_mount_jnz_sig, sizeof(system_mount_jnz_sig)) != 0);
			EXIT_IF(std::memcmp(ex_site, system_ex_mount_jz_sig, sizeof(system_ex_mount_jz_sig)) !=
			        0);
			sys_site[0] = 0x0f;
			sys_site[1] = 0x0b;
			ex_site[0]  = 0x0f;
			ex_site[1]  = 0x0b;
			ex_site[2]  = 0x00;
			ex_site[3]  = 0x00;
			ex_site[4]  = 0x00;
			ex_site[5]  = 0x00;
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
			    program->base_vaddr + system_mount_jnz_offset, sizeof(system_mount_jnz_sig)));
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
			    program->base_vaddr + system_ex_mount_jz_offset, sizeof(system_ex_mount_jz_sig)));
			g_mini_safe_mode_system_mount_jnz_site.store(
			    program->base_vaddr + system_mount_jnz_offset, std::memory_order_release);
			g_mini_safe_mode_system_ex_mount_jz_site.store(
			    program->base_vaddr + system_ex_mount_jz_offset, std::memory_order_release);
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_SAFE_MODE_SYSTEM_MOUNT_RESULT_PROBES"
			     " system_jnz=0x%016" PRIx64 " system_ex_jz=0x%016" PRIx64
			     " two_branch_signatures\n",
			     program->base_vaddr + system_mount_jnz_offset,
			     program->base_vaddr + system_ex_mount_jz_offset);
		}
		if (std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_SSD0_OPEN_RESULT_DISCRIMINATOR") != nullptr) {
			constexpr uint32_t ssd0_open_jnz_offset = 0x438a;
			constexpr uint8_t  ssd0_open_jnz_sig[]  = {0x0f, 0x85, 0x99, 0x00, 0x00, 0x00};
			auto* site = reinterpret_cast<uint8_t*>(program->base_vaddr + ssd0_open_jnz_offset);
			EXIT_IF(std::memcmp(site, ssd0_open_jnz_sig, sizeof(ssd0_open_jnz_sig)) != 0);
			site[0] = 0x0f;
			site[1] = 0x0b;
			site[2] = 0x90;
			site[3] = 0x90;
			site[4] = 0x90;
			site[5] = 0x90;
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
			    program->base_vaddr + ssd0_open_jnz_offset, sizeof(ssd0_open_jnz_sig)));
			g_mini_safe_mode_ssd0_open_jnz_site.store(program->base_vaddr + ssd0_open_jnz_offset,
			                                          std::memory_order_release);
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_SAFE_MODE_SSD0_OPEN_RESULT_PROBE_INSTALLED"
			     " jnz=0x%016" PRIx64 " branch_signature\n",
			     program->base_vaddr + ssd0_open_jnz_offset);
		}
		if (std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_SUB402340_SSD0_USER_RESULT_PROBE") != nullptr) {
			constexpr uint32_t sub402340_ssd0_user_jnz_offset = 0x4ca6;
			constexpr uint8_t  sub402340_ssd0_user_jnz_sig[]  = {0x75, 0x24};
			auto*              site =
			    reinterpret_cast<uint8_t*>(program->base_vaddr + sub402340_ssd0_user_jnz_offset);
			EXIT_IF(std::memcmp(site, sub402340_ssd0_user_jnz_sig,
			                    sizeof(sub402340_ssd0_user_jnz_sig)) != 0);
			site[0] = 0x0f;
			site[1] = 0x0b;
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
			    program->base_vaddr + sub402340_ssd0_user_jnz_offset,
			    sizeof(sub402340_ssd0_user_jnz_sig)));
			g_mini_safe_mode_sub402340_ssd0_user_jnz_site.store(
			    program->base_vaddr + sub402340_ssd0_user_jnz_offset, std::memory_order_release);
			LOGF("FIRST_FRAME_AUDIT "
			     "MINI_SYSCORE_SAFE_MODE_SUB402340_SSD0_USER_RESULT_PROBE_INSTALLED"
			     " jnz=0x%016" PRIx64 " dev=ssd0.user target=/user fstype=bfs"
			     " branch_signature\n",
			     program->base_vaddr + sub402340_ssd0_user_jnz_offset);
		}
		if (std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_COLD_BOOT_PROGRESS_PROBE") != nullptr) {
			// mov edi, 1 is at 0x5095, before call sub_471070 at 0x509a: 5 bytes off from the
			// dep-map
			constexpr uint32_t cold_boot_progress_offset = 0x5095;
			constexpr uint8_t  cold_boot_progress_sig[]  = {0xbf, 0x01, 0x00, 0x00, 0x00};
			auto*              site =
			    reinterpret_cast<uint8_t*>(program->base_vaddr + cold_boot_progress_offset);
			const uint64_t base       = program->base_vaddr;
			const uint64_t size       = program->base_size;
			const uint64_t target_off = static_cast<uint64_t>(cold_boot_progress_offset);
			if (size > 6 && base != 0) {
				const auto* bytes      = reinterpret_cast<const uint8_t*>(base);
				uint32_t    short_cond = 0, short_uncond = 0, near_cond = 0, near_uncond = 0,
				            near_call = 0;
				for (uint64_t off = 0; off + 2 <= size; ++off) {
					const uint8_t b0 = bytes[off];
					if ((b0 & 0xf0) == 0x70 || b0 == 0xeb) {
						const int32_t disp = static_cast<int8_t>(bytes[off + 1]);
						const int64_t tgt  = static_cast<int64_t>(off) + 2 + disp;
						if (tgt >= 0 && static_cast<uint64_t>(tgt) == target_off) {
							if (b0 == 0xeb) {
								++short_uncond;
								LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_COLD_BOOT_PROGRESS_XREF"
								     " kind=short_jmp site=0x%016" PRIx64
								     " disp=%d target=0x%016" PRIx64 "\n",
								     base + off, disp, base + target_off);
							} else {
								++short_cond;
								LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_COLD_BOOT_PROGRESS_XREF"
								     " kind=short_cc_%02x site=0x%016" PRIx64
								     " disp=%d target=0x%016" PRIx64 "\n",
								     b0, base + off, disp, base + target_off);
							}
						}
					}
					if (off + 5 <= size && (b0 == 0xe9 || b0 == 0xe8)) {
						const int32_t disp = *reinterpret_cast<const int32_t*>(bytes + off + 1);
						const int64_t tgt  = static_cast<int64_t>(off) + 5 + disp;
						if (tgt >= 0 && static_cast<uint64_t>(tgt) == target_off) {
							if (b0 == 0xe9) {
								++near_uncond;
								LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_COLD_BOOT_PROGRESS_XREF"
								     " kind=near_jmp site=0x%016" PRIx64
								     " disp=%d target=0x%016" PRIx64 "\n",
								     base + off, disp, base + target_off);
							} else {
								++near_call;
								LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_COLD_BOOT_PROGRESS_XREF"
								     " kind=near_call site=0x%016" PRIx64
								     " disp=%d target=0x%016" PRIx64 "\n",
								     base + off, disp, base + target_off);
							}
						}
					}
					if (off + 6 <= size && b0 == 0x0f && bytes[off + 1] >= 0x80 &&
					    bytes[off + 1] <= 0x8f) {
						const int32_t disp = *reinterpret_cast<const int32_t*>(bytes + off + 2);
						const int64_t tgt  = static_cast<int64_t>(off) + 6 + disp;
						if (tgt >= 0 && static_cast<uint64_t>(tgt) == target_off) {
							++near_cond;
							LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_COLD_BOOT_PROGRESS_XREF"
							     " kind=near_cc_%02x site=0x%016" PRIx64
							     " disp=%d target=0x%016" PRIx64 "\n",
							     bytes[off + 1], base + off, disp, base + target_off);
						}
					}
				}
				LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_COLD_BOOT_PROGRESS_XREF_SUMMARY"
				     " target=0x%016" PRIx64 " short_cc=%u short_jmp=%u near_cc=%u"
				     " near_jmp=%u near_call=%u scanned_bytes=%" PRIu64 "\n",
				     base + target_off, short_cond, short_uncond, near_cond, near_uncond, near_call,
				     size);
			}
			if (std::memcmp(site, cold_boot_progress_sig, sizeof(cold_boot_progress_sig)) != 0) {
				uint8_t pre[16] {};
				uint8_t post[16] {};
				std::memcpy(pre, site - 16, 16);
				std::memcpy(post, site, 16);
				LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_COLD_BOOT_PROGRESS_SIG_MISMATCH"
				     " offset=0x%016" PRIx64 " expected=bf_01_00_00_00"
				     " pre16=%02x_%02x_%02x_%02x_%02x_%02x_%02x_%02x"
				     "_%02x_%02x_%02x_%02x_%02x_%02x_%02x_%02x"
				     " post16=%02x_%02x_%02x_%02x_%02x_%02x_%02x_%02x"
				     "_%02x_%02x_%02x_%02x_%02x_%02x_%02x_%02x"
				     " ud2_not_installed NON_AUTHENTIC\n",
				     program->base_vaddr + cold_boot_progress_offset, pre[0], pre[1], pre[2],
				     pre[3], pre[4], pre[5], pre[6], pre[7], pre[8], pre[9], pre[10], pre[11],
				     pre[12], pre[13], pre[14], pre[15], post[0], post[1], post[2], post[3],
				     post[4], post[5], post[6], post[7], post[8], post[9], post[10], post[11],
				     post[12], post[13], post[14], post[15]);
				for (int32_t pre_off = -16; pre_off <= 0; ++pre_off) {
					if (std::memcmp(site + pre_off, cold_boot_progress_sig,
					                sizeof(cold_boot_progress_sig)) == 0) {
						LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_COLD_BOOT_PROGRESS_MOV_EDI_1_FOUND"
						     " at=0x%016" PRIx64 " relative_to_probe=%+d\n",
						     program->base_vaddr + cold_boot_progress_offset + pre_off, pre_off);
					}
				}
			} else {
				site[0] = 0x0f;
				site[1] = 0x0b;
				site[2] = 0x90;
				site[3] = 0x90;
				site[4] = 0x90;
				EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
				    program->base_vaddr + cold_boot_progress_offset,
				    sizeof(cold_boot_progress_sig)));
				g_mini_cold_boot_progress_site.store(
				    program->base_vaddr + cold_boot_progress_offset, std::memory_order_release);
				LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_COLD_BOOT_PROGRESS_PROBE_INSTALLED"
				     " cold_boot_progress=0x%016" PRIx64 " mov_edi_1_signature\n",
				     program->base_vaddr + cold_boot_progress_offset);
			}
		}
		if (std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_SUB426550_PROBE") != nullptr) {
			constexpr uint32_t ioctl_ret_jz_offset        = 0x26830;
			constexpr uint32_t errno_translated_jz_offset = 0x26840;
			constexpr uint32_t errno_sign_js_offset       = 0x26853;
			constexpr uint32_t open_ssd0_js_offset        = 0x2686e;
			constexpr uint32_t case7_marker_offset        = 0x26ba4;
			constexpr uint8_t  ioctl_ret_jz_sig[]         = {0x74, 0x27};
			constexpr uint8_t  errno_translated_jz_sig[]  = {0x74, 0x17};
			constexpr uint8_t  errno_sign_js_sig[]        = {0x0f, 0x88, 0x45, 0xfd, 0xff, 0xff};
			constexpr uint8_t  open_ssd0_js_sig[]         = {0x0f, 0x88, 0x85, 0x00, 0x00, 0x00};
			constexpr uint8_t  case7_marker_sig[]         = {0xe8, 0x77, 0x15, 0x00, 0x00};
			auto*              ioctl_ret_jz_site =
			    reinterpret_cast<uint8_t*>(program->base_vaddr + ioctl_ret_jz_offset);
			auto* errno_translated_jz_site =
			    reinterpret_cast<uint8_t*>(program->base_vaddr + errno_translated_jz_offset);
			auto* errno_sign_js_site =
			    reinterpret_cast<uint8_t*>(program->base_vaddr + errno_sign_js_offset);
			auto* open_ssd0_js_site =
			    reinterpret_cast<uint8_t*>(program->base_vaddr + open_ssd0_js_offset);
			auto* case7_marker_site =
			    reinterpret_cast<uint8_t*>(program->base_vaddr + case7_marker_offset);
			EXIT_IF(std::memcmp(ioctl_ret_jz_site, ioctl_ret_jz_sig, sizeof(ioctl_ret_jz_sig)) !=
			        0);
			EXIT_IF(std::memcmp(errno_translated_jz_site, errno_translated_jz_sig,
			                    sizeof(errno_translated_jz_sig)) != 0);
			EXIT_IF(std::memcmp(errno_sign_js_site, errno_sign_js_sig, sizeof(errno_sign_js_sig)) !=
			        0);
			EXIT_IF(std::memcmp(open_ssd0_js_site, open_ssd0_js_sig, sizeof(open_ssd0_js_sig)) !=
			        0);
			ioctl_ret_jz_site[0]        = 0x0f;
			ioctl_ret_jz_site[1]        = 0x0b;
			errno_translated_jz_site[0] = 0x0f;
			errno_translated_jz_site[1] = 0x0b;
			errno_sign_js_site[0]       = 0x0f;
			errno_sign_js_site[1]       = 0x0b;
			errno_sign_js_site[2]       = 0x90;
			errno_sign_js_site[3]       = 0x90;
			errno_sign_js_site[4]       = 0x90;
			errno_sign_js_site[5]       = 0x90;
			open_ssd0_js_site[0]        = 0x0f;
			open_ssd0_js_site[1]        = 0x0b;
			open_ssd0_js_site[2]        = 0x90;
			open_ssd0_js_site[3]        = 0x90;
			open_ssd0_js_site[4]        = 0x90;
			open_ssd0_js_site[5]        = 0x90;
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
			    program->base_vaddr + ioctl_ret_jz_offset, sizeof(ioctl_ret_jz_sig)));
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
			    program->base_vaddr + errno_translated_jz_offset, sizeof(errno_translated_jz_sig)));
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
			    program->base_vaddr + errno_sign_js_offset, sizeof(errno_sign_js_sig)));
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
			    program->base_vaddr + open_ssd0_js_offset, sizeof(open_ssd0_js_sig)));
			g_mini_sub426550_ioctl_ret_jz_site.store(program->base_vaddr + ioctl_ret_jz_offset,
			                                         std::memory_order_release);
			g_mini_sub426550_errno_translated_jz_site.store(
			    program->base_vaddr + errno_translated_jz_offset, std::memory_order_release);
			g_mini_sub426550_errno_sign_js_site.store(program->base_vaddr + errno_sign_js_offset,
			                                          std::memory_order_release);
			g_mini_sub426550_open_ssd0_js_site.store(program->base_vaddr + open_ssd0_js_offset,
			                                         std::memory_order_release);
			const bool install_case7 =
			    std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_SUB426550_CASE7_DESTRUCTIVE") != nullptr;
			if (install_case7) {
				EXIT_IF(std::memcmp(case7_marker_site, case7_marker_sig,
				                    sizeof(case7_marker_sig)) != 0);
				case7_marker_site[0] = 0x0f;
				case7_marker_site[1] = 0x0b;
				case7_marker_site[2] = 0x90;
				case7_marker_site[3] = 0x90;
				case7_marker_site[4] = 0x90;
				EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
				    program->base_vaddr + case7_marker_offset, sizeof(case7_marker_sig)));
				g_mini_sub426550_case7_marker_site.store(program->base_vaddr + case7_marker_offset,
				                                         std::memory_order_release);
			}
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_SUB426550_PROBES_INSTALLED"
			     " ioctl_ret_jz=0x%016" PRIx64 " errno_translated_jz=0x%016" PRIx64
			     " errno_sign_js=0x%016" PRIx64 " open_ssd0_js=0x%016" PRIx64 " case7_marker=%s"
			     " NON_AUTHENTIC\n",
			     program->base_vaddr + ioctl_ret_jz_offset,
			     program->base_vaddr + errno_translated_jz_offset,
			     program->base_vaddr + errno_sign_js_offset,
			     program->base_vaddr + open_ssd0_js_offset,
			     install_case7 ? "installed_destructive" : "skipped_nondestructive_run");
			if (std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_SUB426550_ENTRY_PROBE") != nullptr) {
				constexpr uint32_t sub426550_entry_offset = 0x2655d;
				constexpr uint32_t sub428120_entry_offset = 0x2812b;
				constexpr uint8_t  sub426550_entry_sig[]  = {0x48, 0x81, 0xec, 0xe8,
				                                             0x03, 0x00, 0x00};
				constexpr uint8_t  sub428120_entry_sig[]  = {0x48, 0x83, 0xec, 0x10};
				auto*              sub426550_entry_site =
				    reinterpret_cast<uint8_t*>(program->base_vaddr + sub426550_entry_offset);
				auto* sub428120_entry_site =
				    reinterpret_cast<uint8_t*>(program->base_vaddr + sub428120_entry_offset);
				EXIT_IF(std::memcmp(sub426550_entry_site, sub426550_entry_sig,
				                    sizeof(sub426550_entry_sig)) != 0);
				EXIT_IF(std::memcmp(sub428120_entry_site, sub428120_entry_sig,
				                    sizeof(sub428120_entry_sig)) != 0);
				sub426550_entry_site[0] = 0x0f;
				sub426550_entry_site[1] = 0x0b;
				sub426550_entry_site[2] = 0x90;
				sub426550_entry_site[3] = 0x90;
				sub426550_entry_site[4] = 0x90;
				sub426550_entry_site[5] = 0x90;
				sub426550_entry_site[6] = 0x90;
				sub428120_entry_site[0] = 0x0f;
				sub428120_entry_site[1] = 0x0b;
				sub428120_entry_site[2] = 0x90;
				sub428120_entry_site[3] = 0x90;
				EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
				    program->base_vaddr + sub426550_entry_offset, sizeof(sub426550_entry_sig)));
				EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
				    program->base_vaddr + sub428120_entry_offset, sizeof(sub428120_entry_sig)));
				g_mini_sub426550_entry_site.store(program->base_vaddr + sub426550_entry_offset,
				                                  std::memory_order_release);
				g_mini_sub428120_entry_site.store(program->base_vaddr + sub428120_entry_offset,
				                                  std::memory_order_release);
				LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_SUB426550_ENTRY_PROBES_INSTALLED"
				     " sub426550_entry=0x%016" PRIx64 " sub428120_entry=0x%016" PRIx64
				     " NON_AUTHENTIC\n",
				     program->base_vaddr + sub426550_entry_offset,
				     program->base_vaddr + sub428120_entry_offset);
			}
			if (std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_DWORD4D7520_PROBE") != nullptr) {
				constexpr uint32_t store_a_offset = 0x2387;
				constexpr uint32_t store_b_offset = 0x248c;
				constexpr uint32_t store_c_offset = 0x4ae6;
				constexpr uint32_t target_offset  = 0xd7520;
				constexpr uint8_t  store_a_sig[]  = {0xc7, 0x05, 0x8f, 0x51, 0x0d,
				                                     0x00, 0x01, 0x00, 0x00, 0x00};
				constexpr uint8_t  store_b_sig[]  = {0xc7, 0x05, 0x8a, 0x50, 0x0d,
				                                     0x00, 0x01, 0x00, 0x00, 0x00};
				constexpr uint8_t  store_c_sig[]  = {0xc7, 0x05, 0x30, 0x2a, 0x0d,
				                                     0x00, 0x01, 0x00, 0x00, 0x00};
				auto*              store_a_site =
				    reinterpret_cast<uint8_t*>(program->base_vaddr + store_a_offset);
				auto* store_b_site =
				    reinterpret_cast<uint8_t*>(program->base_vaddr + store_b_offset);
				auto* store_c_site =
				    reinterpret_cast<uint8_t*>(program->base_vaddr + store_c_offset);
				EXIT_IF(std::memcmp(store_a_site, store_a_sig, sizeof(store_a_sig)) != 0);
				EXIT_IF(std::memcmp(store_b_site, store_b_sig, sizeof(store_b_sig)) != 0);
				EXIT_IF(std::memcmp(store_c_site, store_c_sig, sizeof(store_c_sig)) != 0);
				auto overlay = [](uint8_t* site) {
					site[0] = 0x0f;
					site[1] = 0x0b;
					for (int i = 2; i < 10; ++i)
						site[i] = 0x90;
				};
				overlay(store_a_site);
				overlay(store_b_site);
				overlay(store_c_site);
				EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
				    program->base_vaddr + store_a_offset, sizeof(store_a_sig)));
				EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
				    program->base_vaddr + store_b_offset, sizeof(store_b_sig)));
				EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
				    program->base_vaddr + store_c_offset, sizeof(store_c_sig)));
				g_mini_dword4d7520_store_a_site.store(program->base_vaddr + store_a_offset,
				                                      std::memory_order_release);
				g_mini_dword4d7520_store_b_site.store(program->base_vaddr + store_b_offset,
				                                      std::memory_order_release);
				g_mini_dword4d7520_store_c_site.store(program->base_vaddr + store_c_offset,
				                                      std::memory_order_release);
				g_mini_dword4d7520_target_vaddr.store(program->base_vaddr + target_offset,
				                                      std::memory_order_release);
				LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_DWORD4D7520_STORE_PROBES_INSTALLED"
				     " store_a=0x%016" PRIx64 " store_b=0x%016" PRIx64 " store_c=0x%016" PRIx64
				     " target=0x%016" PRIx64 " NON_AUTHENTIC\n",
				     program->base_vaddr + store_a_offset, program->base_vaddr + store_b_offset,
				     program->base_vaddr + store_c_offset, program->base_vaddr + target_offset);
			}
			if (std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_DWORD4D7520_HELPER_PROBE") != nullptr) {
				constexpr uint32_t helper_a_offset = 0xa42f;
				constexpr uint32_t helper_b_offset = 0xa47d;
				constexpr uint8_t  helper_sig[]    = {0x41, 0xc7, 0x07, 0x01, 0x00, 0x00, 0x00};
				auto*              helper_a_site =
				    reinterpret_cast<uint8_t*>(program->base_vaddr + helper_a_offset);
				auto* helper_b_site =
				    reinterpret_cast<uint8_t*>(program->base_vaddr + helper_b_offset);
				EXIT_IF(std::memcmp(helper_a_site, helper_sig, sizeof(helper_sig)) != 0);
				EXIT_IF(std::memcmp(helper_b_site, helper_sig, sizeof(helper_sig)) != 0);
				auto overlay = [](uint8_t* site) {
					site[0] = 0x0f;
					site[1] = 0x0b;
					for (int i = 2; i < 7; ++i)
						site[i] = 0x90;
				};
				overlay(helper_a_site);
				overlay(helper_b_site);
				EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
				    program->base_vaddr + helper_a_offset, sizeof(helper_sig)));
				EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
				    program->base_vaddr + helper_b_offset, sizeof(helper_sig)));
				g_mini_dword4d7520_helper_a_site.store(program->base_vaddr + helper_a_offset,
				                                       std::memory_order_release);
				g_mini_dword4d7520_helper_b_site.store(program->base_vaddr + helper_b_offset,
				                                       std::memory_order_release);
				LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_DWORD4D7520_HELPER_PROBES_INSTALLED"
				     " helper_a=0x%016" PRIx64 " helper_b=0x%016" PRIx64
				     " inside_sub_40a320 NON_AUTHENTIC\n",
				     program->base_vaddr + helper_a_offset, program->base_vaddr + helper_b_offset);
			}
			if (std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_SUB426190_PASSTHROUGH_VERDICT") != nullptr) {
				constexpr uint32_t entry_offset = 0x26190;
				constexpr uint8_t  entry_sig[]  = {0x55, 0x48, 0x89, 0xe5};
				auto* entry_site = reinterpret_cast<uint8_t*>(program->base_vaddr + entry_offset);
				EXIT_IF(std::memcmp(entry_site, entry_sig, sizeof(entry_sig)) != 0);
				entry_site[0] = 0x0f;
				entry_site[1] = 0x0b;
				entry_site[2] = 0x90;
				entry_site[3] = 0x90;
				EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
				    program->base_vaddr + entry_offset, sizeof(entry_sig)));
				g_mini_sub426190_entry_site.store(program->base_vaddr + entry_offset,
				                                  std::memory_order_release);
				LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_SUB426190_ENTRY_PROBE_INSTALLED"
				     " entry=0x%016" PRIx64
				     " partition_magic_check_shortcircuit_for_ssd0 NON_AUTHENTIC\n",
				     program->base_vaddr + entry_offset);
			}
		}
		if (std::getenv("KYTY_DIAGNOSTIC_MINI_REBOOT_PATH_AUDIT") != nullptr) {
			constexpr std::array<uint32_t, 2> test_offsets = {0x91ea, 0x5b9f};
			for (const uint32_t offset: test_offsets) {
				auto* code = reinterpret_cast<uint8_t*>(program->base_vaddr + offset);
				EXIT_IF(code[0] != 0x85 || code[1] != 0xc0);
				code[0] = 0x0f;
				code[1] = 0x0b;
			}
			constexpr uint32_t rescue_offset = 0x5cee;
			auto* rescue = reinterpret_cast<uint8_t*>(program->base_vaddr + rescue_offset);
			constexpr uint8_t rescue_bytes[] = {0x48, 0x8d, 0x3d, 0xa2, 0x28, 0x0a, 0x00};
			EXIT_IF(std::memcmp(rescue, rescue_bytes, sizeof(rescue_bytes)) != 0);
			rescue[0] = 0x0f;
			rescue[1] = 0x0b;
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
			    program->base_vaddr + test_offsets[0], 2));
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
			    program->base_vaddr + test_offsets[1], 2));
			EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
			    program->base_vaddr + rescue_offset, sizeof(rescue_bytes)));
			g_mini_preinst_stat_return_site.store(program->base_vaddr + test_offsets[0],
			                                      std::memory_order_release);
			g_mini_preinst_mount_return_site.store(program->base_vaddr + test_offsets[1],
			                                       std::memory_order_release);
			g_mini_rescue_path_site.store(program->base_vaddr + rescue_offset,
			                              std::memory_order_release);
			const char* sub471250_env =
			    std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_SUB471250_PASSTHROUGH_VERDICT");
			if (sub471250_env != nullptr) {
				constexpr uint32_t entry_offset = 0x71250;
				constexpr uint8_t  entry_sig[]  = {0x55, 0x48, 0x89, 0xe5};
				auto* entry_site = reinterpret_cast<uint8_t*>(program->base_vaddr + entry_offset);
				EXIT_IF(std::memcmp(entry_site, entry_sig, sizeof(entry_sig)) != 0);
				entry_site[0] = 0x0f;
				entry_site[1] = 0x0b;
				entry_site[2] = 0x90;
				entry_site[3] = 0x90;
				EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
				    program->base_vaddr + entry_offset, sizeof(entry_sig)));
				const uint32_t v788_value = (sub471250_env[0] == '0') ? 0u : 1u;
				g_mini_sub471250_v788_value.store(v788_value, std::memory_order_release);
				g_mini_sub471250_entry_site.store(program->base_vaddr + entry_offset,
				                                  std::memory_order_release);
				LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_SUB471250_ENTRY_PROBE_INSTALLED"
				     " entry=0x%016" PRIx64 " v788_stand_in=%u"
				     " machdep_bootparams_is_main_on_standby_passthrough NON_AUTHENTIC\n",
				     program->base_vaddr + entry_offset, v788_value);
			}
			const char* sub419930_env =
			    std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_SUB419930_PASSTHROUGH_VERDICT");
			if (sub419930_env != nullptr) {
				constexpr uint32_t entry_offset = 0x19930;
				constexpr uint8_t  entry_sig[]  = {0x55, 0x48, 0x89, 0xe5};
				auto* entry_site = reinterpret_cast<uint8_t*>(program->base_vaddr + entry_offset);
				EXIT_IF(std::memcmp(entry_site, entry_sig, sizeof(entry_sig)) != 0);
				entry_site[0] = 0x0f;
				entry_site[1] = 0x0b;
				entry_site[2] = 0x90;
				entry_site[3] = 0x90;
				EXIT_IF(!Common::VirtualMemory::FlushInstructionCache(
				    program->base_vaddr + entry_offset, sizeof(entry_sig)));
				g_mini_sub419930_entry_site.store(program->base_vaddr + entry_offset,
				                                  std::memory_order_release);
				LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_SUB419930_ENTRY_PROBE_INSTALLED"
				     " entry=0x%016" PRIx64 " verdict=1 bfs_preflight_mountable_passthrough"
				     " NON_AUTHENTIC\n",
				     program->base_vaddr + entry_offset);
			}
			LOGF("FIRST_FRAME_AUDIT MINI_SYSCORE_REBOOT_PATH_PROBES"
			     " stat=0x%016" PRIx64 " mount=0x%016" PRIx64 " rescue=0x%016" PRIx64 "\n",
			     program->base_vaddr + test_offsets[0], program->base_vaddr + test_offsets[1],
			     program->base_vaddr + rescue_offset);
		}
	}

	LOGF("entry = 0x%016" PRIx64 "\n",
	     program->elf->GetEntry() - image_offset + program->base_vaddr);
}

void RuntimeLinker::DeleteProgram(Program* p) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	{
		std::lock_guard lock(g_native_libkernel_trap_mutex);
		std::erase_if(g_native_libkernel_traps,
		              [&](const NativeLibkernelTrap& trap) { return trap.owner == p; });
		std::erase_if(g_sysav_raw_traps,
		              [&](const NativeLibkernelTrap& trap) { return trap.owner == p; });
		if (p != nullptr)
			std::erase_if(g_sysav_original_ud2, [&](uint64_t pc) {
				return pc >= p->base_vaddr && pc - p->base_vaddr < p->base_size_aligned;
			});
	}
#endif
	if (p != nullptr && p->file_name.filename() == "SceSysCore.elf" &&
	    std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD") != nullptr) {
		std::printf("SYSCORE_EXECUTABLE_UNLOAD_BEGIN"
		            " base=0x%016" PRIx64 " mapped_size=0x%016" PRIx64 " code_will_be_released\n",
		            p->base_vaddr, p->mapped_size);
		std::fflush(stdout);
	}
	auto program = std::unique_ptr<Program>(p);
	if (g_tls_main_program == program.get()) {
		g_tls_main_program = nullptr;
	}
	if (g_tls_cached_main_program == program.get()) {
		g_tls_cached_main_program = nullptr;
		g_tls_cached_main_tcb     = nullptr;
	}
	for (auto& record: g_stubbed_imports) {
		if (record.patch_vaddr >= program->base_vaddr &&
		    record.patch_vaddr < program->base_vaddr + program->mapped_size) {
			Common::HostException::UnregisterGuestCodeProvenance(record.host_exception_code_token);
			record.host_exception_code_token = 0;
			record.patch_vaddr = 0;
		}
	}

	if (program->base_vaddr != 0 || program->mapped_size != 0) {
		EXIT_IF(program->base_vaddr == 0 || program->mapped_size == 0);
		if (program->instruction_trampoline_size != 0) {
			UnregisterGuestInstructionPatchModule(reinterpret_cast<void*>(program->base_vaddr));
		}
		EXIT_IF(
		    !Libs::LibKernel::Memory::FreeGuestMemory(program->base_vaddr, program->mapped_size));
	}
}

void RuntimeLinker::ParseProgramDynamicInfo(Program* program) {
	KYTY_PROFILER_FUNCTION();

	EXIT_IF(program == nullptr);
	EXIT_IF(program->elf == nullptr);
	EXIT_IF(program->dynamic_info != nullptr);

	program->dynamic_info = std::make_unique<DynamicInfo>();

	auto* elf = program->elf.get();
	if (elf->IsStaticExec()) {
		LOGF("FIRST_FRAME_AUDIT static_exec image_base=0x%016" PRIx64 " mapped_size=0x%016" PRIx64
		     " NO_DYNAMIC_IMPORTS\n",
		     elf->GetStaticImageBase(), program->mapped_size);
		return;
	}

	EXIT_NOT_IMPLEMENTED(elf->HasDynValue(DT_OS_HASH) && elf->HasDynValue(DT_HASH));
	GetDynDataOs(elf, &program->dynamic_info->hash_table, DT_OS_HASH);
	GetDynData(elf, program->base_vaddr, &program->dynamic_info->hash_table, DT_HASH);
	GetDynValue(elf, &program->dynamic_info->hash_table_size, DT_OS_HASHSZ);

	EXIT_NOT_IMPLEMENTED(elf->HasDynValue(DT_OS_STRTAB) && elf->HasDynValue(DT_STRTAB));
	EXIT_NOT_IMPLEMENTED(elf->HasDynValue(DT_OS_STRSZ) && elf->HasDynValue(DT_STRSZ));
	GetDynDataOs(elf, &program->dynamic_info->str_table, DT_OS_STRTAB);
	GetDynData(elf, program->base_vaddr, &program->dynamic_info->str_table, DT_STRTAB);
	GetDynValue(elf, &program->dynamic_info->str_table_size, DT_OS_STRSZ);
	GetDynValue(elf, &program->dynamic_info->str_table_size, DT_STRSZ);

	EXIT_NOT_IMPLEMENTED(elf->HasDynValue(DT_OS_SYMTAB) && elf->HasDynValue(DT_SYMTAB));
	EXIT_NOT_IMPLEMENTED(elf->HasDynValue(DT_OS_SYMENT) && elf->HasDynValue(DT_SYMENT));
	GetDynDataOs(elf, &program->dynamic_info->symbol_table, DT_OS_SYMTAB);
	GetDynData(elf, program->base_vaddr, &program->dynamic_info->symbol_table, DT_SYMTAB);
	GetDynValue(elf, &program->dynamic_info->symbol_table_total_size, DT_OS_SYMTABSZ);
	GetDynValue(elf, &program->dynamic_info->symbol_table_entry_size, DT_OS_SYMENT);
	GetDynValue(elf, &program->dynamic_info->symbol_table_entry_size, DT_SYMENT);

	GetDynPtr(elf, &program->dynamic_info->init_vaddr, DT_INIT);
	GetDynPtr(elf, &program->dynamic_info->fini_vaddr, DT_FINI);
	GetDynPtr(elf, &program->dynamic_info->init_array_vaddr, DT_INIT_ARRAY);
	GetDynPtr(elf, &program->dynamic_info->fini_array_vaddr, DT_FINI_ARRAY);
	GetDynPtr(elf, &program->dynamic_info->preinit_array_vaddr, DT_PREINIT_ARRAY);
	GetDynValue(elf, &program->dynamic_info->init_array_size, DT_INIT_ARRAYSZ);
	GetDynValue(elf, &program->dynamic_info->fini_array_size, DT_FINI_ARRAYSZ);
	GetDynValue(elf, &program->dynamic_info->preinit_array_size, DT_PREINIT_ARRAYSZ);

	Elf64_Sxword jmprel_type = 0;
	EXIT_NOT_IMPLEMENTED(elf->HasDynValue(DT_OS_PLTREL) && elf->HasDynValue(DT_PLTREL));
	GetDynValue(elf, &jmprel_type, DT_OS_PLTREL);
	GetDynValue(elf, &jmprel_type, DT_PLTREL);

	EXIT_NOT_IMPLEMENTED(jmprel_type != DT_RELA);
	if (jmprel_type == DT_RELA) {
		EXIT_NOT_IMPLEMENTED(elf->HasDynValue(DT_OS_JMPREL) && elf->HasDynValue(DT_JMPREL));
		EXIT_NOT_IMPLEMENTED(elf->HasDynValue(DT_OS_PLTRELSZ) && elf->HasDynValue(DT_PLTRELSZ));
		GetDynDataOs(elf, &program->dynamic_info->jmprela_table, DT_OS_JMPREL);
		GetDynData(elf, program->base_vaddr, &program->dynamic_info->jmprela_table, DT_JMPREL);
		GetDynValue(elf, &program->dynamic_info->jmprela_table_size, DT_OS_PLTRELSZ);
		GetDynValue(elf, &program->dynamic_info->jmprela_table_size, DT_PLTRELSZ);
	}

	EXIT_NOT_IMPLEMENTED(elf->HasDynValue(DT_OS_RELA) && elf->HasDynValue(DT_RELA));
	GetDynDataOs(elf, &program->dynamic_info->rela_table, DT_OS_RELA);
	GetDynData(elf, program->base_vaddr, &program->dynamic_info->rela_table, DT_RELA);
	GetDynValue(elf, &program->dynamic_info->rela_table_total_size, DT_OS_RELASZ);
	GetDynValue(elf, &program->dynamic_info->rela_table_total_size, DT_RELASZ);
	GetDynValue(elf, &program->dynamic_info->rela_table_entry_size, DT_OS_RELAENT);
	GetDynValue(elf, &program->dynamic_info->rela_table_entry_size, DT_RELAENT);
	EXIT_NOT_IMPLEMENTED(program->dynamic_info->rela_table_total_size % sizeof(Elf64_Rela) != 0 ||
	                     program->dynamic_info->jmprela_table_size % sizeof(Elf64_Rela) != 0);
	const auto rela_count = program->dynamic_info->rela_table_total_size / sizeof(Elf64_Rela);
	const auto jmprela_count = program->dynamic_info->jmprela_table_size / sizeof(Elf64_Rela);
	program->rela_bits.resize((rela_count + jmprela_count + 7u) / 8u);

	GetDynValue(elf, &program->dynamic_info->relative_count, DT_RELACOUNT);

	GetDynValue(elf, &program->dynamic_info->debug, DT_DEBUG);
	GetDynValue(elf, &program->dynamic_info->flags, DT_FLAGS);
	GetDynValue(elf, &program->dynamic_info->textrel, DT_TEXTREL);

	EXIT_NOT_IMPLEMENTED(program->dynamic_info->debug != 0);
	EXIT_NOT_IMPLEMENTED(program->dynamic_info->textrel != 0);

	uint64_t so_name = 0;
	GetDynValue(elf, &so_name, DT_SONAME);
	program->dynamic_info->so_name = program->dynamic_info->str_table + so_name;

	EXIT_NOT_IMPLEMENTED(elf->HasDynValue(DT_OS_NEEDED_MODULE) &&
	                     elf->HasDynValue(DT_OS_NEEDED_MODULE_1));
	EXIT_NOT_IMPLEMENTED(elf->HasDynValue(DT_OS_MODULE_INFO) &&
	                     elf->HasDynValue(DT_OS_MODULE_INFO_1));
	EXIT_NOT_IMPLEMENTED(elf->HasDynValue(DT_OS_IMPORT_LIB) &&
	                     elf->HasDynValue(DT_OS_IMPORT_LIB_1));
	EXIT_NOT_IMPLEMENTED(elf->HasDynValue(DT_OS_EXPORT_LIB) &&
	                     elf->HasDynValue(DT_OS_EXPORT_LIB_1));
	GetDynModules(elf, &program->dynamic_info->import_modules, program->dynamic_info->str_table,
	              DT_OS_NEEDED_MODULE);
	GetDynModules(elf, &program->dynamic_info->import_modules, program->dynamic_info->str_table,
	              DT_OS_NEEDED_MODULE_1);
	GetDynModules(elf, &program->dynamic_info->export_modules, program->dynamic_info->str_table,
	              DT_OS_MODULE_INFO);
	GetDynModules(elf, &program->dynamic_info->export_modules, program->dynamic_info->str_table,
	              DT_OS_MODULE_INFO_1);
	GetDynLibs(elf, &program->dynamic_info->import_libs, program->dynamic_info->str_table,
	           DT_OS_IMPORT_LIB);
	GetDynLibs(elf, &program->dynamic_info->import_libs, program->dynamic_info->str_table,
	           DT_OS_IMPORT_LIB_1);
	GetDynLibs(elf, &program->dynamic_info->export_libs, program->dynamic_info->str_table,
	           DT_OS_EXPORT_LIB);
	GetDynLibs(elf, &program->dynamic_info->export_libs, program->dynamic_info->str_table,
	           DT_OS_EXPORT_LIB_1);
}

void RuntimeLinker::Relocate(Program* program) {
	KYTY_PROFILER_FUNCTION();

	EXIT_IF(program == nullptr);
	if (program->elf != nullptr && program->elf->IsStaticExec()) {
		return;
	}

	if (g_invalid_memory == 0) {
		g_invalid_memory = Libs::LibKernel::Memory::AllocateRuntimeMemory(
		    INVALID_MEMORY, 4096, Common::VirtualMemory::Mode::NoAccess, "invalid_memory", true);
		EXIT_NOT_IMPLEMENTED(g_invalid_memory == 0);
	}

	LOGF_COLOR(Log::Color::White, "--- Relocate program: %s ---\n",
	           Common::PathToString(program->file_name).c_str());

	EXIT_NOT_IMPLEMENTED(program->dynamic_info->symbol_table_entry_size != sizeof(Elf64_Sym));
	EXIT_NOT_IMPLEMENTED(program->dynamic_info->rela_table_entry_size != sizeof(Elf64_Rela));
	EXIT_NOT_IMPLEMENTED(program->dynamic_info->jmprela_table == nullptr);
	EXIT_NOT_IMPLEMENTED(program->dynamic_info->rela_table == nullptr);
	EXIT_NOT_IMPLEMENTED(program->dynamic_info->symbol_table == nullptr);

	const auto rela_count = static_cast<uint32_t>(
	    program->dynamic_info->rela_table_total_size / sizeof(Elf64_Rela));

	ForEachRelocation(program, [&](Elf64_Rela* r, uint32_t index, bool jmprela) {
		const auto bit_index = (jmprela ? rela_count : 0) + index;
		if ((program->rela_bits[bit_index >> 3u] & (1u << (bit_index & 7u))) == 0 &&
		    RelocateRecord(index, r, program, jmprela)) {
			program->rela_bits[bit_index >> 3u] |= 1u << (bit_index & 7u);
		}
	});

	if (program->tls.image_vaddr != 0 && program->tls.init_size != 0 &&
	    program->tls.init_image.empty()) {
		const auto* src = reinterpret_cast<const uint8_t*>(program->tls.image_vaddr);
		program->tls.init_image.assign(src, src + program->tls.init_size);
	}
}

const ModuleId* RuntimeLinker::FindModule(const Program& program, const std::string& id) {
	const auto& import_modules = program.dynamic_info->import_modules;

	if (auto it = std::find_if(import_modules.begin(), import_modules.end(),
	                           [&id](const auto& module) { return module.id == id; });
	    it != import_modules.end()) {
		return &(*it);
	}

	const auto& export_modules = program.dynamic_info->export_modules;

	if (auto it = std::find_if(export_modules.begin(), export_modules.end(),
	                           [&id](const auto& module) { return module.id == id; });
	    it != export_modules.end()) {
		return &(*it);
	}

	return nullptr;
}

const LibraryId* RuntimeLinker::FindLibrary(const Program& program, const std::string& id) {
	const auto& import_libs = program.dynamic_info->import_libs;

	if (auto it = std::find_if(import_libs.begin(), import_libs.end(),
	                           [&id](const auto& lib) { return lib.id == id; });
	    it != import_libs.end()) {
		return &(*it);
	}

	const auto& export_libs = program.dynamic_info->export_libs;

	if (auto it = std::find_if(export_libs.begin(), export_libs.end(),
	                           [&id](const auto& lib) { return lib.id == id; });
	    it != export_libs.end()) {
		return &(*it);
	}

	return nullptr;
}

void RuntimeLinker::CreateSymbolDatabase(Program* program) {
	KYTY_PROFILER_FUNCTION();

	EXIT_IF(program == nullptr);
	EXIT_IF(program->export_symbols != nullptr);
	EXIT_IF(program->import_symbols != nullptr);

	program->export_symbols = std::make_unique<SymbolDatabase>();
	program->import_symbols = std::make_unique<SymbolDatabase>();

	auto syms = [](Program* program, SymbolDatabase* symbols, bool is_export) {
		if (program->dynamic_info->symbol_table == nullptr ||
		    program->dynamic_info->str_table == nullptr) {
			return;
		}

		for (auto* sym = program->dynamic_info->symbol_table;
		     reinterpret_cast<uint8_t*>(sym) <
		     reinterpret_cast<uint8_t*>(program->dynamic_info->symbol_table) +
		         program->dynamic_info->symbol_table_total_size;
		     sym++) {
			std::string id   = std::string(program->dynamic_info->str_table + sym->st_name);
			auto        bind = sym->GetBind();
			auto        type = sym->GetType();
			auto        ids  = Common::Split(id, '#');

			if (ids.size() == 3) {
				const auto* l = FindLibrary(*program, ids.at(1));
				const auto* m = FindModule(*program, ids.at(2));

				if (l != nullptr && m != nullptr && (bind == STB_GLOBAL || bind == STB_WEAK) &&
				    (type == STT_FUNC || type == STT_OBJECT || type == STT_NOTYPE) &&
				    is_export == (sym->st_value != 0)) {
					SymbolResolve sr {};
					sr.name                 = ids.at(0);
					sr.library              = l->name;
					sr.library_version      = l->version;
					sr.module               = m->name;
					sr.module_version_major = m->version_major;
					sr.module_version_minor = m->version_minor;
					switch (type) {
						case STT_NOTYPE: sr.type = SymbolType::NoType; break;
						case STT_FUNC: sr.type = SymbolType::Func; break;
						case STT_OBJECT: sr.type = SymbolType::Object; break;
						default: sr.type = SymbolType::Unknown; break;
					}
					symbols->Add(sr, (is_export ? sym->st_value + program->base_vaddr : 0));
				}
			}
		}
	};

	syms(program, program->export_symbols.get(), true);
	syms(program, program->import_symbols.get(), false);
}

void RuntimeLinker::SetupTlsHandler(Program* program) {
	EXIT_IF(program == nullptr);
	EXIT_IF(g_tls_main_program != nullptr);
	EXIT_IF(program->elf == nullptr);
	EXIT_IF(program->elf->IsShared());
	EXIT_IF(program->tls.handler_vaddr == 0);

	g_tls_main_program = program;

	auto* code = new (reinterpret_cast<void*>(program->tls.handler_vaddr)) Jit::SafeCall;

	code->SetFunc(TlsMainGetAddr);

	for (uint8_t reg = 1; reg < 8; reg++) {
		if (reg == 4) {
			continue;
		}

		auto* stub = new (reinterpret_cast<void*>(program->tls.handler_vaddr +
		                                          Jit::TlsRegStub::GetOffset(reg))) Jit::TlsRegStub;
		stub->SetFunc(program->tls.handler_vaddr);
		stub->SetOutputReg(reg);
	}

	EXIT_IF(!Libs::LibKernel::Memory::ProtectGuestMemory(program->tls.handler_vaddr,
	                                                     Jit::SafeCall::GetSize(),
	                                                     Common::VirtualMemory::Mode::Execute));
	Common::VirtualMemory::FlushInstructionCache(program->tls.handler_vaddr,
	                                             Jit::SafeCall::GetSize());
	const auto owner = Common::PathToString(program->file_name.filename());
	const auto token = Common::HostException::RegisterGuestCodeProvenance(
	    {program->tls.handler_vaddr, Jit::SafeCall::GetSize(), program->base_vaddr,
		 program->tls.handler_vaddr - program->base_vaddr,
		 Common::HostException::FaultGuestCodeKind::TlsHandler, owner.c_str(), "tls_safe_call"});
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	EXIT_IF(token == 0);
#endif
	if (token != 0) program->host_exception_code_tokens.push_back(token);
}

void RuntimeLinker::DeleteTlss(int thread_id) {
	Common::LockGuard lock(m_mutex);

	for (auto* p: m_programs) {
		DeleteTls(p, thread_id);
	}
}

void RuntimeLinker::DiscardTlssForExec(int thread_id) {
	Common::LockGuard lock(m_mutex);
	if (thread_id == Common::Thread::GetThreadIdUnique()) {
		g_tls_cached_main_program = nullptr;
		g_tls_cached_main_tcb     = nullptr;
	}
	for (auto* program: m_programs) {
		Common::LockGuard tls_lock(program->tls.mutex);
		if (auto it = program->tls.tlss.find(thread_id); it != program->tls.tlss.end()) {
			FreeTlsBlock(&it->second, false);
			program->tls.tlss.erase(it);
		}
	}
}

void RuntimeLinker::SetApplicationHeapApi(void* const api[10]) {
	Common::LockGuard lock(m_mutex);

	if (api == nullptr || api[0] == nullptr || api[1] == nullptr) {
		m_application_heap_malloc         = nullptr;
		m_application_heap_free           = nullptr;
		m_application_heap_posix_memalign = nullptr;
		return;
	}

	m_application_heap_malloc = reinterpret_cast<application_heap_malloc_func_t>(api[0]);
	m_application_heap_free   = reinterpret_cast<application_heap_free_func_t>(api[1]);
	m_application_heap_posix_memalign =
	    reinterpret_cast<application_heap_posix_memalign_func_t>(api[6]);
}

void* RuntimeLinker::ApplicationHeapMemalign(uint64_t alignment, uint64_t size) {
	Common::LockGuard lock(m_mutex);

	if (m_application_heap_posix_memalign != nullptr) {
		void* ptr = nullptr;
		return m_application_heap_posix_memalign(&ptr, alignment, size) == 0 ? ptr : nullptr;
	}

	return nullptr;
}

void* RuntimeLinker::ApplicationHeapMalloc(uint64_t size) {
	Common::LockGuard lock(m_mutex);

	return m_application_heap_malloc != nullptr ? m_application_heap_malloc(size) : nullptr;
}

} // namespace Loader
