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
} // namespace Libs::LibKernel



namespace Loader {

Program::Program() = default;

Program::~Program() = default;

static void FreeTlsBlock(ThreadLocalStorage::Block* block) {
	if (block == nullptr || block->ptr == nullptr) {
		return;
	}

	if (block->free_func != nullptr) {
		block->free_func(block->ptr);
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

static KYTY_SYSV_ABI uint64_t UnresolvedImportStub(uint64_t record_id);

static bool PatchGuestMemory64(uint64_t vaddr, uint64_t value) {
	auto* ptr     = reinterpret_cast<uint64_t*>(vaddr);
	bool  changed = (*ptr != value);
	std::memcpy(ptr, &value, sizeof(value));
	return changed;
}

static uint64_t AllocateUnresolvedImportThunk(uint64_t record_id) {
	constexpr uint64_t thunk_size = 34;

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

	uint8_t bytes[thunk_size] = {
	    0x48, 0x83, 0xec, 0x08,               // sub rsp, 8
	    0x48, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0, // mov rdi, record_id
	    0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, UnresolvedImportStub
	    0xff, 0xd0,                           // call rax
	    0x48, 0x83, 0xc4, 0x08,               // add rsp, 8
	    0x0f, 0x57, 0xc0,                     // xorps xmm0, xmm0
	    0xc3,                                 // ret
	};
	const auto target = reinterpret_cast<uint64_t>(UnresolvedImportStub);
	std::memcpy(bytes + 6, &record_id, sizeof(record_id));
	std::memcpy(bytes + 16, &target, sizeof(target));
	std::memcpy(code, bytes, sizeof(bytes));
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
	const auto thunk                         = AllocateUnresolvedImportThunk(record_id);
	g_stubbed_imports[record_id].thunk_vaddr = thunk;
	return thunk;
}

static KYTY_SYSV_ABI uint64_t UnresolvedImportStub(uint64_t record_id) {
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

#if defined(KYTY_VIRTUAL_MEMORY_ALLOCATION_TESTS)
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
static std::atomic<uint64_t>                g_syscore_native_launch_entry_site {0};
static std::atomic<uint64_t>                g_syscore_native_rfork_child_entry_site {0};
static std::atomic<uint64_t>                g_syscore_native_child_setup_result_site {0};
static std::atomic<uint64_t>                g_syscore_native_kqueue_result_site {0};
static std::atomic<uint64_t>                g_agc_native_kevent_syscall_site {0};
static std::atomic<uint64_t>                g_syscore_original_vfprintf_probe {0};
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
struct NativeLibkernelTrap {
	Program* owner;
	uint64_t site;
	uint32_t number;
};
static std::mutex                       g_native_libkernel_trap_mutex;
static std::vector<NativeLibkernelTrap> g_native_libkernel_traps;
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
static std::atomic<uint64_t>               g_mini_safe_mode_r14d_jle_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_mount_result_jz_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_global_flag_jz_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_local_var_jz_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_dword_4d7520_addr {0};
static std::atomic<uint64_t>               g_mini_safe_mode_system_mount_jnz_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_system_ex_mount_jz_site {0};
static std::atomic<uint64_t>               g_mini_safe_mode_ssd0_open_jnz_site {0};
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
#endif

	if (info->type == Common::HostException::ExceptionType::IllegalInstruction &&
	    Loader::X64InstructionEmulator::TryEmulate(info->native_context)) {
		return true;
	}

	if (info->type == Common::HostException::ExceptionType::AccessViolation) {
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
	// Report whatever guest context can be read safely before terminating: which guest thread
	// faulted, the register file, the faulting code bytes and the top of its stack.
	{
		char thread_name[64] = "(host thread)";
		if (auto self = Libs::LibKernel::PthreadSelfOrNull(); self != nullptr) {
			if (Libs::LibKernel::PthreadGetname(self, thread_name) != 0) {
				std::snprintf(thread_name, sizeof(thread_name), "(unnamed guest thread)");
			}
		}
		std::printf("--- Guest fault context ---\n");
		std::printf("thread: %s\n", thread_name);
		std::printf("rax=%016" PRIx64 " rbx=%016" PRIx64 " rcx=%016" PRIx64 " rdx=%016" PRIx64 "\n"
		            "rsi=%016" PRIx64 " rdi=%016" PRIx64 " rbp=%016" PRIx64 " rsp=%016" PRIx64 "\n"
		            "r8 =%016" PRIx64 " r9 =%016" PRIx64 " r10=%016" PRIx64 " r11=%016" PRIx64 "\n"
		            "r12=%016" PRIx64 " r13=%016" PRIx64 " r14=%016" PRIx64 " r15=%016" PRIx64 "\n",
		            info->rax, info->rbx, info->rcx, info->rdx, info->rsi, info->rdi, info->rbp,
		            info->rsp, info->r8, info->r9, info->r10, info->r11, info->r12, info->r13,
		            info->r14, info->r15);
		if (IsReadableRange(info->exception_address - 48, 96)) {
			const auto* code = reinterpret_cast<const uint8_t*>(info->exception_address - 48);
			std::printf("code (pc-48 .. pc+48, fault at byte 48):");
			for (int i = 0; i < 96; i++) {
				std::printf("%s%02x", (i % 16 == 0) ? "\n " : " ", code[i]);
			}
			std::printf("\n");
		}
		if (IsReadableRange(info->rsp, 32 * sizeof(uint64_t))) {
			const auto* stack = reinterpret_cast<const uint64_t*>(info->rsp);
			std::printf("stack:");
			for (int i = 0; i < 32; i++) {
				std::printf("%s %016" PRIx64, (i % 4 == 0) ? "\n " : "", stack[i]);
			}
			std::printf("\n");
		}
		std::fflush(stdout);
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
					symbol_vaddr = sr.vaddr;
				} break;
				default: EXIT("unknown bind: %d\n", (int)bind);
			}
			ret.resolved = (symbol_vaddr != 0);
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

uint64_t RuntimeLinker::GetEntry() {
	// EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());

	Common::LockGuard lock(m_mutex);

	for (const auto* p: m_programs) {
		if (p->elf != nullptr && !p->elf->IsShared()) {
			return p->elf->GetEntry() + p->base_vaddr;
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

	for (auto* p: m_programs) {
		Relocate(p);
	}
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
void RuntimeLinker::UnloadProgram(Program* program) {
	// EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());

	Common::LockGuard lock(m_mutex);

	auto it = std::find(m_programs.begin(), m_programs.end(), program);
	EXIT_IF(it == m_programs.end());
	m_programs.erase(it);

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
}

RuntimeLinker::RuntimeLinker(): m_symbols(std::make_unique<SymbolDatabase>()) {
	EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());
}

RuntimeLinker::~RuntimeLinker() {
	Clear();
}

Program* RuntimeLinker::LoadProgram(const std::filesystem::path& elf_name) {
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
	program->elf->Open(elf_name);

	if (program->elf->IsValid()) {
		LoadProgramToMemory(program);
		ParseProgramDynamicInfo(program);
		CreateSymbolDatabase(program);
	} else {
		EXIT("elf is not valid: %s\n", Common::PathToString(elf_name).c_str());
	}

	m_programs.push_back(program_owner.release());

	if (!program->elf->IsShared()) {
		program->fail_if_global_not_resolved = false;
		Libs::LibKernel::SetProgName(elf_name.filename().string());
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

void RuntimeLinker::Execute(const std::filesystem::path& game_patch) {
	KYTY_PROFILER_THREAD("Thread_Main");

	Libs::LibKernel::PthreadInitSelfForMainThread();
	auto* main_stack_top = Libs::LibKernel::PthreadCreateMainGuestStack();

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	// Guest code has no Windows stack probes and may jump over the guard page. Module
	// initializers execute on the host stack too, so grow it before calling any guest code.
	size_t expanded_size = 0;
	while (expanded_size < static_cast<size_t>(768) * 1024) {
		sys_dbg_stack_info_t stack {};
		SysStackUsage(stack);
		*reinterpret_cast<uint32_t*>(stack.guard_addr) = 0;
		expanded_size += stack.guard_size;
	}
#endif

	// The runtime automatically loads libc; other PRXs are requested by the application.
	const auto libc_path = Libs::LibKernel::FileSystem::GetRealFilename("/app0/sce_module/libc.prx");
	auto* libc = Common::File::IsFileExisting(libc_path) ? LoadProgram(libc_path) : nullptr;
	RelocateAll();

	if (!game_patch.empty()) {
		if (!GamePatch::Apply(game_patch, m_programs.empty() ? nullptr : m_programs.front(),
		                      m_programs)) {
			EXIT("Failed to apply game cheat\n");
		}
	}
	if (libc != nullptr && libc->dynamic_info->init_vaddr != 0) {
		StartModule(libc, 0, nullptr, nullptr);
	}

	LOGF_COLOR(Log::Color::BrightYellow, "---\n--- Execute: %s\n---\n", "Main");

	if (auto entry = GetEntry(); entry != 0) {
		auto* params = reinterpret_cast<EntryParams*>(
		    (reinterpret_cast<uintptr_t>(main_stack_top) - 0x100u) & ~static_cast<uintptr_t>(0x0f));
		std::memset(params, 0, sizeof(EntryParams));
		params->argc    = 1;
		params->argv[0] = "KytyEmu";

		LOGF("stack_addr = %" PRIx64 "\n", reinterpret_cast<uint64_t>(params));

		RunEntry(entry, params, ProgramExitHandler,
		         reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(params) - 0x1000u));
	}
}

void RuntimeLinker::Clear() {
	// EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());

	Common::LockGuard lock(m_mutex);
	GamePatch::Clear();

	for (auto* p: m_programs) {
		DeleteProgram(p);
	}
	m_programs.clear();
	for (const auto page: g_unresolved_stub_thunk_pages) {
		EXIT_IF(!Libs::LibKernel::Memory::FreeGuestMemory(page, UNRESOLVED_STUB_PAGE_SIZE));
	}
	g_unresolved_stub_thunk_pages.clear();
	g_unresolved_stub_thunk_offset = 0;
	g_stubbed_imports.clear();
	g_unresolved_stub_call_log_count.store(0);
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

			const SymbolRecord* rec = nullptr;

			if (m_symbols != nullptr) {
				rec = m_symbols->Find(sr);
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
					LOGF("PS5 NID fallback: %s -> %s\n", sr.name.c_str(), out_info->name.c_str());
					return;
				}
			}

			if (rec != nullptr) {
				*out_info = *rec;
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

int RuntimeLinker::StartModule(Program* program, size_t args, const void* argp,
                               module_func_t func) {
	EXIT_IF(program == nullptr);
	EXIT_IF(program->dynamic_info == nullptr);
	EXIT_IF(program->elf == nullptr);
	EXIT_IF(!program->elf->IsShared());

	EXIT_IF(std::find(m_programs.begin(), m_programs.end(), program) == m_programs.end());

	LOGF_COLOR(Log::Color::BrightYellow, "---\n--- Start module: %s\n---\n",
	           Common::PathToString(program->file_name).c_str());

	return reinterpret_cast<module_ini_fini_func_t>(program->dynamic_info->init_vaddr +
	                                                program->base_vaddr)(args, argp, func);
}

int RuntimeLinker::StopModule(Program* program, size_t args, const void* argp, module_func_t func) {
	EXIT_IF(program == nullptr);
	EXIT_IF(program->dynamic_info == nullptr);
	EXIT_IF(program->elf == nullptr);
	EXIT_IF(!program->elf->IsShared());

	EXIT_IF(std::find(m_programs.begin(), m_programs.end(), program) == m_programs.end());

	LOGF_COLOR(Log::Color::BrightYellow, "---\n--- Stop module: %s\n---\n",
	           Common::PathToString(program->file_name).c_str());

	int result = reinterpret_cast<module_ini_fini_func_t>(program->dynamic_info->fini_vaddr +
	                                                      program->base_vaddr)(args, argp, func);

	Libs::LibKernel::PthreadDeleteStaticObjects(program);

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

static uint64_t CalcBaseSize(const Elf64_Ehdr* ehdr, const Elf64_Phdr* phdr) {
	uint64_t base_size = 0;
	for (Elf64_Half i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_memsz != 0 && (phdr[i].p_type == PT_LOAD || phdr[i].p_type == PT_OS_RELRO)) {
			uint64_t last_addr = phdr[i].p_vaddr + GetAlignedSize(phdr + i);
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

	EXIT_NOT_IMPLEMENTED(!is_shared && !is_next_gen);

	const auto* ehdr = program->elf->GetEhdr();
	const auto* phdr = program->elf->GetPhdr();

	EXIT_IF(phdr == nullptr || ehdr == nullptr);

	program->base_size                 = CalcBaseSize(ehdr, phdr);
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

	program->base_vaddr = Libs::LibKernel::Memory::AllocateProgramMemory(
	    g_desired_base_addr, program->mapped_size, Common::VirtualMemory::Mode::ExecuteReadWrite,
	    Common::PathToString(program->file_name.filename()).c_str());
	EXIT_IF(program->base_vaddr == 0);

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
			uint64_t segment_addr        = phdr[i].p_vaddr + program->base_vaddr;
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
				PatchProgram(program, segment_addr, segment_memory_size);
				executable_segments.emplace_back(segment_addr, segment_file_size);
			}

			if (!skip_protect) {
				Libs::LibKernel::Memory::SetProgramMemoryProtection(segment_addr,
				                                                    segment_memory_size, mode);

				if (Common::VirtualMemory::IsExecute(mode)) {
					Common::VirtualMemory::FlushInstructionCache(segment_addr, segment_memory_size);
				}
			}
		}

		if (phdr[i].p_type == PT_TLS) {
			EXIT_IF(phdr[i].p_vaddr >= program->base_size);

			program->tls.image_vaddr = phdr[i].p_vaddr + program->base_vaddr;
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
			EXIT_IF(phdr[i].p_vaddr >= program->base_size);

			program->proc_param_vaddr = phdr[i].p_vaddr + program->base_vaddr;
		}

		if (patch_guest_instructions && phdr[i].p_type == PT_GNU_EH_FRAME) {
			eh_frame_header_addr = phdr[i].p_vaddr + program->base_vaddr;
			eh_frame_header_size = phdr[i].p_memsz;
		}
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
	LOGF("entry = 0x%016" PRIx64 "\n", program->elf->GetEntry() + program->base_vaddr);
}

void RuntimeLinker::DeleteProgram(Program* p) {
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
}

void RuntimeLinker::DeleteTlss(int thread_id) {
	Common::LockGuard lock(m_mutex);

	for (auto* p: m_programs) {
		DeleteTls(p, thread_id);
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
