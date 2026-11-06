#include "common/abi.h"
#include "common/assert.h"
#include "common/common.h"
#include "common/emulatorConfig.h"
#include "common/file.h"
#include "common/logging/log.h"
#include "common/singleton.h"
#include "common/stringUtils.h"
#include "common/threads.h"
#include "kernel/eventFlag.h"
#include "kernel/eventQueue.h"
#include "kernel/fileSystem.h"
#include "kernel/ipmiManager.h"
#include "kernel/memory.h"
#include "kernel/process.h"
#include "kernel/pthread.h"
#include "kernel/semaphore.h"
#include "kernel/syncOnAddress.h"
#include "libs/errno.h"
#include "libs/libs.h"
#include "libs/network.h"
#include "loader/elf.h"
#include "loader/runtimeLinker.h"
#include "loader/symbolDatabase.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#elif defined(__APPLE__)
#include <csignal>
#include <pthread.h>
#include <sys/ucontext.h>
#else
#include <csignal>
#include <pthread.h>
#include <ucontext.h>
#endif

namespace Libs {

namespace LibC {
int          GetArgc();
const char** GetArgv();
} // namespace LibC

static std::filesystem::path ResolveNativeModulePath(const std::string& guest_path) {
	auto host_path = LibKernel::FileSystem::GetRealFilename(guest_path);
	if (host_path.empty()) {
		LibKernel::DirectoryPassthrough::ResolveHostPath(guest_path, &host_path);
	}
	return host_path;
}
struct NativeModuleSource {
	std::filesystem::path                                    file_name;
	std::shared_ptr<LibKernel::DirectoryPassthrough::Handle> provider_handle;
	std::vector<uint8_t>                                     image;
	int result = LibKernel::KERNEL_ERROR_ENOENT;
};
static void ApplyNativeModuleOverlay(const std::string& guest_path, NativeModuleSource* source) {
	if (source == nullptr || source->result != OK || source->image.empty()) return;

	std::vector<uint8_t> decrypted;
	std::string          detail;
	switch (Loader::DecryptedModuleOverlay::ResolveDecryptedModuleImage(guest_path, source->image,
	                                                                    &decrypted, &detail)) {
		case Loader::DecryptedModuleOverlay::Resolution::Substituted:
			LOGF("SYSTEM_EX_DECRYPTED_OVERLAY guest_path=%s route=native_module result=substituted "
			     "%s\n",
			     guest_path.c_str(), detail.c_str());
			source->image = std::move(decrypted);
			break;
		case Loader::DecryptedModuleOverlay::Resolution::RejectedMissing:
		case Loader::DecryptedModuleOverlay::Resolution::RejectedMismatch:
			LOGF("SYSTEM_EX_DECRYPTED_OVERLAY guest_path=%s route=native_module result=rejected "
			     "%s\n",
			     guest_path.c_str(), detail.c_str());
			source->result = LibKernel::KERNEL_ERROR_ENOEXEC;
			break;
		case Loader::DecryptedModuleOverlay::Resolution::NotApplicable: break;
	}
}
static int ReadNativeModuleSnapshot(const std::string&           guest_path,
                                    const std::filesystem::path& file_name,
                                    std::vector<uint8_t>*        image) {
	if (LibKernel::FileSystem::ReadPsmShellUiApplicationSnapshot(guest_path, image)) {
		return image->empty() ? LibKernel::KERNEL_ERROR_ENOEXEC : OK;
	}
	Common::File file;
	if (!file.Open(file_name, Common::File::Mode::Read)) return LibKernel::KERNEL_ERROR_ENOENT;
	const auto size = file.Size();
	if (size == 0) return LibKernel::KERNEL_ERROR_ENOEXEC;
	if (size > UINT32_MAX) return LibKernel::KERNEL_ERROR_EFBIG;
	std::vector<uint8_t> bytes(static_cast<size_t>(size));
	uint32_t             actual = 0;
	std::error_code      error;
	file.Read(bytes.data(), static_cast<uint32_t>(bytes.size()), &actual, &error);
	if (error || actual != bytes.size() || file.Size() != size) return LibKernel::KERNEL_ERROR_EIO;
	*image = std::move(bytes);
	return OK;
}
LIB_VERSION("libkernel", 1, "libkernel", 1, 1);

namespace LibKernelApr {
LIB_DEFINE(InitLibKernel_1_Apr);
} // namespace LibKernelApr

namespace LibKernel {

using KernelModule                   = int32_t;
using get_thread_atexit_count_func_t = KYTY_SYSV_ABI int (*)(KernelModule);
using thread_atexit_report_func_t    = KYTY_SYSV_ABI void (*)(KernelModule);

static std::array<uint8_t, 20> sha1_digest(const uint8_t* data, size_t size) {
	uint32_t h0 = 0x67452301u;
	uint32_t h1 = 0xefcdab89u;
	uint32_t h2 = 0x98badcfeu;
	uint32_t h3 = 0x10325476u;
	uint32_t h4 = 0xc3d2e1f0u;

	std::vector<uint8_t> msg(data, data + size);
	const uint64_t       bit_len = static_cast<uint64_t>(size) * 8u;

	msg.push_back(0x80u);
	while ((msg.size() % 64u) != 56u) {
		msg.push_back(0u);
	}
	for (int i = 7; i >= 0; i--) {
		msg.push_back(static_cast<uint8_t>((bit_len >> (i * 8)) & 0xffu));
	}

	for (size_t offset = 0; offset < msg.size(); offset += 64u) {
		uint32_t w[80] = {};
		for (int i = 0; i < 16; i++) {
			const auto j = offset + static_cast<size_t>(i) * 4u;
			w[i] = (static_cast<uint32_t>(msg[j + 0]) << 24u) |
			       (static_cast<uint32_t>(msg[j + 1]) << 16u) |
			       (static_cast<uint32_t>(msg[j + 2]) << 8u) | static_cast<uint32_t>(msg[j + 3]);
		}
		for (int i = 16; i < 80; i++) {
			w[i] = std::rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
		}

		uint32_t a = h0;
		uint32_t b = h1;
		uint32_t c = h2;
		uint32_t d = h3;
		uint32_t e = h4;

		for (int i = 0; i < 80; i++) {
			uint32_t f = 0;
			uint32_t k = 0;
			if (i < 20) {
				f = (b & c) | ((~b) & d);
				k = 0x5a827999u;
			} else if (i < 40) {
				f = b ^ c ^ d;
				k = 0x6ed9eba1u;
			} else if (i < 60) {
				f = (b & c) | (b & d) | (c & d);
				k = 0x8f1bbcdcu;
			} else {
				f = b ^ c ^ d;
				k = 0xca62c1d6u;
			}

			const auto temp = std::rotl(a, 5) + f + e + k + w[i];
			e               = d;
			d               = c;
			c               = std::rotl(b, 30);
			b               = a;
			a               = temp;
		}

		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
	}

	std::array<uint8_t, 20> digest = {};
	const uint32_t          h[5]   = {h0, h1, h2, h3, h4};
	for (int i = 0; i < 5; i++) {
		digest[static_cast<size_t>(i) * 4u + 0u] = static_cast<uint8_t>((h[i] >> 24u) & 0xffu);
		digest[static_cast<size_t>(i) * 4u + 1u] = static_cast<uint8_t>((h[i] >> 16u) & 0xffu);
		digest[static_cast<size_t>(i) * 4u + 2u] = static_cast<uint8_t>((h[i] >> 8u) & 0xffu);
		digest[static_cast<size_t>(i) * 4u + 3u] = static_cast<uint8_t>(h[i] & 0xffu);
	}
	return digest;
}

static std::string kernel_symbol_to_nid(const char* symbol) {
	static constexpr std::array<uint8_t, 16> salt = {0x51, 0x8d, 0x64, 0xa6, 0x35, 0xde,
	                                                 0xd8, 0xc1, 0xe6, 0xb0, 0x39, 0xb1,
	                                                 0xc3, 0xe5, 0x52, 0x30};
	static constexpr char                    codes[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";

	const auto           symbol_size = std::strlen(symbol);
	std::vector<uint8_t> input(symbol_size + salt.size());
	std::memcpy(input.data(), symbol, symbol_size);
	std::memcpy(input.data() + symbol_size, salt.data(), salt.size());

	const auto hash = sha1_digest(input.data(), input.size());

	uint64_t digest = 0;
	std::memcpy(&digest, hash.data(), sizeof(digest));

	char nid[12] = {};
	for (int i = 0; i < 10; i++) {
		nid[i] = codes[(digest >> (58 - i * 6)) & 0x3fu];
	}
	nid[10] = codes[(digest & 0xfu) * 4u];
	return std::string(nid);
}

static const Loader::SymbolRecord* kernel_find_export_symbol(const Loader::SymbolDatabase* symbols,
                                                             const char*                   symbol) {
	EXIT_IF(symbols == nullptr);
	EXIT_IF(symbol == nullptr);

	const auto nid = kernel_symbol_to_nid(symbol);

	if (const auto* record = symbols->FindByNid(nid, Loader::SymbolType::Func); record != nullptr) {
		return record;
	}
	if (const auto* record = symbols->FindByNid(nid, Loader::SymbolType::Object);
	    record != nullptr) {
		return record;
	}
	if (const auto* record = symbols->FindByNid(nid, Loader::SymbolType::NoType);
	    record != nullptr) {
		return record;
	}

	const auto symbol_name = std::string(symbol);
	if (const auto* record = symbols->FindByName(symbol_name, Loader::SymbolType::Func);
	    record != nullptr) {
		return record;
	}
	if (const auto* record = symbols->FindByName(symbol_name, Loader::SymbolType::Object);
	    record != nullptr) {
		return record;
	}
	return symbols->FindByName(symbol_name, Loader::SymbolType::NoType);
}

static void* KYTY_SYSV_ABI KernelApplicationHeapGetMem(uint64_t alignment, uint64_t size) {
	static std::atomic_uint32_t log_count = 0;

	if (alignment < 0x10u) {
		alignment = 0x10u;
	}
	if ((alignment & (alignment - 1u)) != 0u) {
		return nullptr;
	}

	auto* rt  = Common::Singleton<Loader::RuntimeLinker>::Instance();
	void* ptr = rt->ApplicationHeapMemalign(alignment, size);

	const auto index = log_count.fetch_add(1, std::memory_order_relaxed);
	if (index < 8 || (index % 600) == 0) {
		LOGF("\t KernelApplicationHeapGetMem alignment = 0x%016" PRIx64 ", size = 0x%016" PRIx64
		     ", ptr = 0x%016" PRIx64 "\n",
		     alignment, size, reinterpret_cast<uint64_t>(ptr));
	}

	return ptr;
}

int KYTY_SYSV_ABI KernelDlsym(KernelModule handle, const char* symbol, void** addr) {
	static std::atomic_uint32_t log_count = 0;
	const auto                  index     = log_count.fetch_add(1, std::memory_order_relaxed);
	if (index < 32 || (index % 600) == 0) {
		PRINT_NAME();
		LOGF("\t call_count = %" PRIu32 ", handle = %" PRId32 ", symbol = %s\n", index + 1, handle,
		     symbol != nullptr ? symbol : "(null)");
	}

	if (addr == nullptr) {
		return KERNEL_ERROR_EFAULT;
	}

	if (symbol == nullptr) {
		*addr = nullptr;
		return KERNEL_ERROR_EFAULT;
	}

	auto* rt      = Common::Singleton<Loader::RuntimeLinker>::Instance();
	auto* program = rt->FindProgramById(handle);
	if (program == nullptr || program->export_symbols == nullptr) {
		*addr = nullptr;
		LOGF("\t unresolved dlsym: handle = %" PRId32 ", symbol = %s, reason = module not found\n",
		     handle, symbol);
		return KERNEL_ERROR_ESRCH;
	}

	const auto* record = kernel_find_export_symbol(program->export_symbols.get(), symbol);
	if (record != nullptr) {
		*addr = reinterpret_cast<void*>(record->vaddr);
		if (index < 32 || (index % 600) == 0) {
			LOGF("\t resolved = 0x%016" PRIx64 " (%s)\n", record->vaddr, record->name.c_str());
		}
		return OK;
	}

	if (handle == 0 && std::strcmp(symbol, "scriptingGetMem") == 0) {
		*addr = reinterpret_cast<void*>(&KernelApplicationHeapGetMem);
		if (index < 32 || (index % 600) == 0) {
			LOGF("\t resolved = 0x%016" PRIx64 " (application heap scriptingGetMem)\n",
			     reinterpret_cast<uint64_t>(*addr));
		}
		return OK;
	}

	*addr = nullptr;
	LOGF("\t unresolved dlsym: handle = %" PRId32 ", module = %s, symbol = %s\n", handle,
	     Common::PathToString(program->file_name).c_str(), symbol);
	return KERNEL_ERROR_ESRCH;
}

#pragma pack(1)

struct KernelLoadModuleOpt {
	size_t size;
};

struct KernelUnloadModuleOpt {
	size_t size;
};

struct TlsInfo {
	Loader::Program* program;
	uint64_t         offset;
};

struct MallocReplace {
	uint64_t size               = sizeof(MallocReplace);
	void*    malloc_initialize  = nullptr;
	void*    malloc_finalize    = nullptr;
	void*    malloc             = nullptr;
	void*    free               = nullptr;
	void*    calloc             = nullptr;
	void*    realloc            = nullptr;
	void*    memalign           = nullptr;
	void*    reallocalign       = nullptr;
	void*    posix_memalign     = nullptr;
	void*    malloc_stats       = nullptr;
	void*    malloc_stats_fast  = nullptr;
	void*    malloc_usable_size = nullptr;
	void*    aligned_alloc      = nullptr;
};

struct NewReplace {
	uint64_t size                           = sizeof(NewReplace);
	void*    new_p                          = nullptr;
	void*    new_nothrow                    = nullptr;
	void*    new_array                      = nullptr;
	void*    new_array_nothrow              = nullptr;
	void*    delete_p                       = nullptr;
	void*    delete_nothrow                 = nullptr;
	void*    delete_array                   = nullptr;
	void*    delete_array_nothrow           = nullptr;
	void*    delete_with_size               = nullptr;
	void*    delete_with_size_nothrow       = nullptr;
	void*    delete_array_with_size         = nullptr;
	void*    delete_array_with_size_nothrow = nullptr;
};

struct ModuleInfo {
	uint64_t     size;
	uint64_t     info[32];
	KernelModule handle;
	uint8_t      pad[156];
};

struct ModuleInfoForUnwind {
	uint64_t st_size;
	char     name[256];
	uint64_t eh_frame_hdr_addr;
	uint64_t eh_frame_addr;
	uint64_t eh_frame_size;
	uint64_t seg0_addr;
	uint64_t seg0_size;
};

static_assert(sizeof(ModuleInfoForUnwind) == 304);

#pragma pack()

constexpr size_t PROGNAME_MAX_SIZE = 511;

static uint64_t             g_stack_chk_guard                     = 0xDeadBeef00000007;
static char                 g_progname_buf[PROGNAME_MAX_SIZE + 1] = {0};
static const char*          g_progname                            = g_progname_buf;
static std::atomic_uint64_t g_gpo_state_bits {0};

static get_thread_atexit_count_func_t g_get_thread_atexit_count_func = nullptr;
static thread_atexit_report_func_t    g_thread_atexit_report_func    = nullptr;

void SetProgName(const std::string& name) {
	strncpy(g_progname_buf, name.c_str(), PROGNAME_MAX_SIZE);
}

static KYTY_SYSV_ABI int* get_error_addr() {
	return Posix::GetErrorAddr();
}

static KYTY_SYSV_ABI int getargc() {
	PRINT_NAME();

	return LibC::GetArgc();
}

static KYTY_SYSV_ABI const char** getargv() {
	PRINT_NAME();

	return LibC::GetArgv();
}

static void dump_stack_chk_fail_context(uint64_t caller, uint64_t rsp) {
	LOGF("stack_chk_fail caller = 0x%016" PRIx64 "\n", caller);
	LOGF("stack_chk_fail guard  = 0x%016" PRIx64 " @ 0x%016" PRIx64 "\n", g_stack_chk_guard,
	     reinterpret_cast<uint64_t>(&g_stack_chk_guard));

	auto* linker  = Common::Singleton<Loader::RuntimeLinker>::Instance();
	auto* program = linker->FindProgramByAddr(caller);

	LOGF("stack_chk_fail rsp    = 0x%016" PRIx64 "\n"
	     "stack_chk_fail caller/saved-guard scan:\n",
	     rsp);
	for (int i = -32; i < 512; i++) {
		auto addr  = rsp + static_cast<int64_t>(i) * 8;
		auto value = *reinterpret_cast<uint64_t*>(addr);

		if (value == caller) {
			auto saved_guard_addr = addr + 0x4a8;
			auto saved_guard      = *reinterpret_cast<uint64_t*>(saved_guard_addr);
			LOGF("  return addr at 0x%016" PRIx64
			     "; saved guard candidate [ret+0x4a8] = 0x%016" PRIx64 " -> 0x%016" PRIx64 "\n",
			     addr, saved_guard_addr, saved_guard);
		}

		if (value == g_stack_chk_guard) {
			LOGF("  guard value found at stack 0x%016" PRIx64 "\n", addr);
		}
	}

	LOGF("stack_chk_fail stack qwords:\n");
	for (int i = -4; i < 20; i++) {
		auto  addr  = rsp + static_cast<int64_t>(i) * 8;
		auto  value = *reinterpret_cast<uint64_t*>(addr);
		auto* p     = linker->FindProgramByAddr(value);
		auto  module_name =
		    (p == nullptr ? std::string() : Common::PathToString(p->file_name.filename()));
		LOGF("  [%+03d] 0x%016" PRIx64 " : 0x%016" PRIx64 " %s\n", i, addr, value,
		     module_name.c_str());
	}

	if (program == nullptr) {
		LOGF("stack_chk_fail caller module = <unknown>\n");
		return;
	}

	auto caller_module_name = Common::PathToString(program->file_name.filename());
	LOGF("stack_chk_fail caller module = %s, base = 0x%016" PRIx64 ", offset = 0x%016" PRIx64 "\n",
	     caller_module_name.c_str(), program->base_vaddr, caller - program->base_vaddr);

	auto read_byte = [program](uint64_t vaddr) {
		auto     aligned = vaddr & ~0x07ull;
		uint64_t value   = Loader::RuntimeLinker::ReadFromElf(program, aligned);
		return static_cast<uint8_t>((value >> ((vaddr - aligned) * 8u)) & 0xffu);
	};

	if (caller >= 5 && read_byte(caller - 5) == 0xe8) {
		uint32_t rel = 0;
		for (uint32_t i = 0; i < 4; i++) {
			rel |= static_cast<uint32_t>(read_byte(caller - 4 + i)) << (i * 8u);
		}
		auto target = caller + static_cast<int32_t>(rel);
		LOGF("stack_chk_fail preceding call = rel32 at 0x%016" PRIx64 ", target = 0x%016" PRIx64
		     "\n",
		     caller - 5, target);
	} else if (caller >= 6 && read_byte(caller - 6) == 0xff &&
	           (read_byte(caller - 5) & 0x38u) == 0x10) {
		LOGF("stack_chk_fail preceding call = indirect at 0x%016" PRIx64 "\n", caller - 6);
	}

	auto dump_start = (caller >= 64 ? caller - 64 : 0);
	auto dump_end   = caller + 32;

	LOGF("stack_chk_fail caller bytes from ELF:\n");
	for (auto addr = dump_start; addr < dump_end; addr += 16) {
		LOGF("  0x%016" PRIx64 ":", addr);
		for (uint32_t i = 0; i < 16; i++) {
			LOGF("%c%02" PRIx8, (addr + i == caller ? '>' : ' '), read_byte(addr + i));
		}
		LOGF("\n");
	}
}

static KYTY_SYSV_ABI void stack_chk_fail() {
	PRINT_NAME();

	uint64_t rsp = 0;
	asm volatile("movq %%rsp, %0" : "=r"(rsp));
	dump_stack_chk_fail_context(reinterpret_cast<uint64_t>(__builtin_return_address(0)), rsp);

	EXIT("stack fail!!!");
}

bool CanAccessCurrentThreadStack(const void* pointer, uint64_t size, bool writable) {
	const auto address = reinterpret_cast<uint64_t>(pointer);
	if (size == 0) {
		return true;
	}
	if (pointer == nullptr || size > UINT64_MAX - address) {
		return false;
	}
	Memory::VirtualQueryInfo guest {};
	if (Memory::KernelVirtualQuery(pointer, 1, &guest, sizeof(guest)) == 0 &&
	    guest.start < address + size && address < guest.end) {
		return false;
	}
	uint64_t low  = 0;
	uint64_t high = 0;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	ULONG_PTR stack_low  = 0;
	ULONG_PTR stack_high = 0;
	GetCurrentThreadStackLimits(&stack_low, &stack_high);
	low  = stack_low;
	high = stack_high;
#elif defined(__APPLE__)
	high = reinterpret_cast<uint64_t>(pthread_get_stackaddr_np(pthread_self()));
	low  = high - pthread_get_stacksize_np(pthread_self());
#else
	pthread_attr_t attr {};
	if (pthread_getattr_np(pthread_self(), &attr) != 0) {
		return false;
	}
	void*      base       = nullptr;
	size_t     stack_size = 0;
	const auto result     = pthread_attr_getstack(&attr, &base, &stack_size);
	pthread_attr_destroy(&attr);
	if (result != 0) {
		return false;
	}
	low = reinterpret_cast<uint64_t>(base);
	if (stack_size > UINT64_MAX - low) {
		return false;
	}
	high = low + stack_size;
#endif
	const auto end = address + size;
	if (address < low || end > high) {
		return false;
	}
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	for (auto cursor = address; cursor < end;) {
		MEMORY_BASIC_INFORMATION region {};
		if (VirtualQuery(reinterpret_cast<const void*>(cursor), &region, sizeof(region)) !=
		        sizeof(region) ||
		    region.State != MEM_COMMIT || (region.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
			return false;
		}
		const auto protection = region.Protect & 0xffu;
		const bool can_write  = protection == PAGE_READWRITE || protection == PAGE_WRITECOPY ||
		                        protection == PAGE_EXECUTE_READWRITE ||
		                        protection == PAGE_EXECUTE_WRITECOPY;
		const bool can_read =
		    can_write || protection == PAGE_READONLY || protection == PAGE_EXECUTE_READ;
		if (writable ? !can_write : !can_read) {
			return false;
		}
		const auto base = reinterpret_cast<uint64_t>(region.BaseAddress);
		if (base > cursor || region.RegionSize > UINT64_MAX - base) {
			return false;
		}
		const auto next = std::min<uint64_t>(end, base + region.RegionSize);
		if (next <= cursor) {
			return false;
		}
		cursor = next;
	}
#else
	(void)writable;
#endif
	return true;
}

static bool ReadSignalMask(const void* source, PthreadSignalMask* mask) {
	if (Memory::CopyFromGuest(mask, source, sizeof(*mask))) {
		return true;
	}
	if (!CanAccessCurrentThreadStack(source, sizeof(*mask), false)) {
		return false;
	}
	std::memcpy(mask, source, sizeof(*mask));
	return true;
}

static bool WriteSignalMask(void* destination, const PthreadSignalMask& mask) {
	if (Memory::CopyToGuest(destination, &mask, sizeof(mask))) {
		return true;
	}
	if (!CanAccessCurrentThreadStack(destination, sizeof(mask), true)) {
		return false;
	}
	std::memcpy(destination, &mask, sizeof(mask));
	return true;
}

void KernelDispatchPendingSignalForCurrentThread();
int KernelSigprocmask(int how, const void* set, void* oset) {
	static_assert(sizeof(PthreadSignalMask) == 16);
	PthreadSignalMask requested {};
	if (set != nullptr && !ReadSignalMask(set, &requested)) {
		return KERNEL_ERROR_EFAULT;
	}
	if (set != nullptr && (how < 1 || how > 3)) {
		return KERNEL_ERROR_EINVAL;
	}
	auto*      thread   = PthreadSelfOrNull();
	const auto previous = PthreadGetSignalMask(thread);
	if (set != nullptr) {
		for (size_t i = 0; i < 2; ++i) {
			if (how == 1) {
				requested.words[i] |= previous.words[i];
			}
			if (how == 2) {
				requested.words[i] = previous.words[i] & ~requested.words[i];
			}
		}
		PthreadSetSignalMask(thread, requested);
	}
	if (oset != nullptr && !WriteSignalMask(oset, previous)) {
		return KERNEL_ERROR_EFAULT;
	}
	if (set != nullptr && how != 1) {
		KernelDispatchPendingSignalForCurrentThread();
	}
	return 0;
}

static KYTY_SYSV_ABI int sigprocmask(int how, const void* set, void* oset) {
	return POSIX_CALL(KernelSigprocmask(how, set, oset));
}
struct GuestSigaction {
	uint64_t handler = 0;
	uint32_t flags   = 0;
	uint32_t mask[4] {};
	uint32_t padding = 0;
};
static std::mutex                      g_guest_sigaction_mutex;
static std::array<GuestSigaction, 129> g_guest_sigactions;
static std::atomic_uint32_t            g_guest_sigaction_calls {0};
static bool ReadGuestSigaction(const GuestSigaction* source, GuestSigaction* action) {
	if (Memory::CopyFromGuest(action, source, sizeof(*action))) {
		return true;
	}
	if (!CanAccessCurrentThreadStack(source, sizeof(*action), false)) {
		return false;
	}
	std::memcpy(action, source, sizeof(*action));
	return true;
}
static bool WriteGuestSigaction(GuestSigaction* destination, const GuestSigaction& action) {
	if (Memory::CopyToGuest(destination, &action, sizeof(action))) {
		return true;
	}
	if (!CanAccessCurrentThreadStack(destination, sizeof(action), true)) {
		return false;
	}
	std::memcpy(destination, &action, sizeof(action));
	return true;
}
static int GuestSigactionError(int error) {
	*Posix::GetErrorAddr() = error;
	return -1;
}
static bool IsValidGuestSigaction(int signum, const GuestSigaction& action) {
	constexpr uint32_t allowed_flags = 0x7f;
	if (action.handler != 0 && action.handler != 1 && (action.flags & ~allowed_flags) != 0) {
		return false;
	}
	if ((signum == 9 || signum == 17) && action.handler != 0) {
		return false;
	}
	return true;
}
static int KYTY_SYSV_ABI GuestSigactionCall(int signum, const GuestSigaction* requested,
                                            GuestSigaction* previous) {
	if (signum < 1 || signum > 128 || signum == 32) {
		return GuestSigactionError(Posix::POSIX_EINVAL);
	}

	GuestSigaction requested_copy {};
	if (requested != nullptr && !ReadGuestSigaction(requested, &requested_copy)) {
		return GuestSigactionError(Posix::POSIX_EFAULT);
	}
	if (requested != nullptr && !IsValidGuestSigaction(signum, requested_copy)) {
		return GuestSigactionError(Posix::POSIX_EINVAL);
	}

	GuestSigaction previous_copy {};
	{
		std::lock_guard lock(g_guest_sigaction_mutex);
		previous_copy = g_guest_sigactions[signum];
		if (requested != nullptr) {
			g_guest_sigactions[signum] = requested_copy;
		}
	}

	if (previous != nullptr && !WriteGuestSigaction(previous, previous_copy)) {
		return GuestSigactionError(Posix::POSIX_EFAULT);
	}

	const auto call = g_guest_sigaction_calls.fetch_add(1, std::memory_order_relaxed);
	if (call < 18 || (call % 256) == 0) {
		LOGF("FIRST_FRAME_AUDIT GUEST_SIGACTION_STATE signal=%d set=%d query=%d"
		     " delivery=unmodeled\n",
		     signum, requested != nullptr, previous != nullptr);
	}
	return 0;
}
static bool IsAllowedExceptionSignal(int signum) {
	constexpr int POSIX_SIGHUP  = 1;
	constexpr int POSIX_SIGILL  = 4;
	constexpr int POSIX_SIGFPE  = 8;
	constexpr int POSIX_SIGBUS  = 10;
	constexpr int POSIX_SIGSEGV = 11;
	constexpr int POSIX_SIGUSR1 = 30;

	return signum == POSIX_SIGHUP || signum == POSIX_SIGILL || signum == POSIX_SIGFPE ||
	       signum == POSIX_SIGBUS || signum == POSIX_SIGSEGV || signum == POSIX_SIGUSR1;
}

static void* g_exception_handlers[130] = {};

using exception_handler_func_t = KYTY_SYSV_ABI void (*)(int, void*);

static thread_local bool g_dispatching_signal_handler = false;

struct SignalDispatchScope {
	SignalDispatchScope(): previous(g_dispatching_signal_handler) {
		g_dispatching_signal_handler = true;
	}
	~SignalDispatchScope() { g_dispatching_signal_handler = previous; }

	bool previous;
};

bool KernelIsDispatchingSignalOnCurrentThread() {
	return g_dispatching_signal_handler;
}

#if KYTY_PLATFORM != KYTY_PLATFORM_WINDOWS
static void WaitForSignalDispatch(Pthread thread, int signum) {
	constexpr auto DISPATCH_WAIT_STEP = std::chrono::microseconds(1000);
	constexpr auto DISPATCH_WAIT_MAX  = std::chrono::milliseconds(2);

	auto waited = std::chrono::microseconds(0);
	while (PthreadHasPendingSignal(thread, signum) && waited < DISPATCH_WAIT_MAX) {
		Common::Thread::SleepMicro(DISPATCH_WAIT_STEP.count());
		waited += DISPATCH_WAIT_STEP;
	}
}
#endif

struct SignalMcontext {
	uint64_t mc_onstack;
	uint64_t mc_rdi;
	uint64_t mc_rsi;
	uint64_t mc_rdx;
	uint64_t mc_rcx;
	uint64_t mc_r8;
	uint64_t mc_r9;
	uint64_t mc_rax;
	uint64_t mc_rbx;
	uint64_t mc_rbp;
	uint64_t mc_r10;
	uint64_t mc_r11;
	uint64_t mc_r12;
	uint64_t mc_r13;
	uint64_t mc_r14;
	uint64_t mc_r15;
	int      mc_trapno;
	uint16_t mc_fs;
	uint16_t mc_gs;
	uint64_t mc_addr;
	int      mc_flags;
	uint16_t mc_es;
	uint16_t mc_ds;
	uint64_t mc_err;
	uint64_t mc_rip;
	uint64_t mc_cs;
	uint64_t mc_rflags;
	uint64_t mc_reserved_0xb8[8];
	uint64_t mc_rsp;
	uint64_t mc_ss;
	uint64_t mc_len;
	uint64_t mc_fpformat;
	uint64_t mc_ownedfp;
	uint64_t mc_lbrfrom;
	uint64_t mc_lbrto;
	uint64_t mc_aux1;
	uint64_t mc_aux2;
	uint64_t mc_fpstate[104];
	uint64_t mc_fsbase;
	uint64_t mc_gsbase;
	uint64_t mc_spare[6];
};

struct SignalStack {
	void*    ss_sp;
	uint64_t ss_size;
	int      ss_flags;
	int      _align;
};

struct SignalUcontext {
	SignalMcontext uc_mcontext;
};

static_assert(offsetof(SignalUcontext, uc_mcontext) == 0x00);
static_assert(offsetof(SignalMcontext, mc_rip) == 0xa0);
static_assert(offsetof(SignalUcontext, uc_mcontext) + offsetof(SignalMcontext, mc_rsp) == 0xf8);

static SignalUcontext CreateSignalUcontext(
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
    const CONTEXT* source_ctx = nullptr
#endif
) {
	SignalUcontext ctx = {};

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	CONTEXT host_ctx = {};
	if (source_ctx != nullptr) {
		host_ctx = *source_ctx;
	} else {
		host_ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
		RtlCaptureContext(&host_ctx);
	}

	ctx.uc_mcontext.mc_r8     = host_ctx.R8;
	ctx.uc_mcontext.mc_r9     = host_ctx.R9;
	ctx.uc_mcontext.mc_r10    = host_ctx.R10;
	ctx.uc_mcontext.mc_r11    = host_ctx.R11;
	ctx.uc_mcontext.mc_r12    = host_ctx.R12;
	ctx.uc_mcontext.mc_r13    = host_ctx.R13;
	ctx.uc_mcontext.mc_r14    = host_ctx.R14;
	ctx.uc_mcontext.mc_r15    = host_ctx.R15;
	ctx.uc_mcontext.mc_rdi    = host_ctx.Rdi;
	ctx.uc_mcontext.mc_rsi    = host_ctx.Rsi;
	ctx.uc_mcontext.mc_rbp    = host_ctx.Rbp;
	ctx.uc_mcontext.mc_rbx    = host_ctx.Rbx;
	ctx.uc_mcontext.mc_rdx    = host_ctx.Rdx;
	ctx.uc_mcontext.mc_rax    = host_ctx.Rax;
	ctx.uc_mcontext.mc_rcx    = host_ctx.Rcx;
	ctx.uc_mcontext.mc_rsp    = host_ctx.Rsp;
	ctx.uc_mcontext.mc_rip    = host_ctx.Rip;
	ctx.uc_mcontext.mc_cs     = host_ctx.SegCs;
	ctx.uc_mcontext.mc_fs     = host_ctx.SegFs;
	ctx.uc_mcontext.mc_gs     = host_ctx.SegGs;
	ctx.uc_mcontext.mc_ss     = host_ctx.SegSs;
	ctx.uc_mcontext.mc_ds     = host_ctx.SegDs;
	ctx.uc_mcontext.mc_es     = host_ctx.SegEs;
	ctx.uc_mcontext.mc_rflags = host_ctx.EFlags;
	ctx.uc_mcontext.mc_len    = sizeof(SignalMcontext);
#else
	ctx.uc_mcontext.mc_len = sizeof(SignalMcontext);
	uint64_t stack_marker  = 0;
	ctx.uc_mcontext.mc_rsp = reinterpret_cast<uint64_t>(&stack_marker);
	ctx.uc_mcontext.mc_rbp = reinterpret_cast<uint64_t>(__builtin_frame_address(0));
	ctx.uc_mcontext.mc_rip = reinterpret_cast<uint64_t>(__builtin_return_address(0));

#if defined(__x86_64__)
	// Capture the remaining guest-visible registers.
	uint64_t rax = 0;
	uint64_t rbx = 0;
	uint64_t rcx = 0;
	uint64_t rdx = 0;
	uint64_t rsi = 0;
	uint64_t rdi = 0;
	asm volatile("movq %%rax, %0\n\t"
	             "movq %%rbx, %1\n\t"
	             "movq %%rcx, %2\n\t"
	             "movq %%rdx, %3\n\t"
	             "movq %%rsi, %4\n\t"
	             "movq %%rdi, %5\n\t"
	             : "=m"(rax), "=m"(rbx), "=m"(rcx), "=m"(rdx), "=m"(rsi), "=m"(rdi)
	             :
	             : "memory");

	uint64_t r8  = 0;
	uint64_t r9  = 0;
	uint64_t r10 = 0;
	uint64_t r11 = 0;
	uint64_t r12 = 0;
	uint64_t r13 = 0;
	uint64_t r14 = 0;
	uint64_t r15 = 0;
	asm volatile("movq %%r8,  %0\n\t"
	             "movq %%r9,  %1\n\t"
	             "movq %%r10, %2\n\t"
	             "movq %%r11, %3\n\t"
	             "movq %%r12, %4\n\t"
	             "movq %%r13, %5\n\t"
	             "movq %%r14, %6\n\t"
	             "movq %%r15, %7\n\t"
	             : "=m"(r8), "=m"(r9), "=m"(r10), "=m"(r11), "=m"(r12), "=m"(r13), "=m"(r14),
	               "=m"(r15)
	             :
	             : "memory");

	uint64_t rflags = 0;
	uint64_t cs     = 0;
	uint64_t ss     = 0;
	asm volatile("pushfq\n\t"
	             "popq %0\n\t"
	             "movq %%cs, %1\n\t"
	             "movq %%ss, %2\n\t"
	             : "=r"(rflags), "=r"(cs), "=r"(ss)
	             :
	             : "memory");

	ctx.uc_mcontext.mc_rax    = rax;
	ctx.uc_mcontext.mc_rbx    = rbx;
	ctx.uc_mcontext.mc_rcx    = rcx;
	ctx.uc_mcontext.mc_rdx    = rdx;
	ctx.uc_mcontext.mc_rsi    = rsi;
	ctx.uc_mcontext.mc_rdi    = rdi;
	ctx.uc_mcontext.mc_r8     = r8;
	ctx.uc_mcontext.mc_r9     = r9;
	ctx.uc_mcontext.mc_r10    = r10;
	ctx.uc_mcontext.mc_r11    = r11;
	ctx.uc_mcontext.mc_r12    = r12;
	ctx.uc_mcontext.mc_r13    = r13;
	ctx.uc_mcontext.mc_r14    = r14;
	ctx.uc_mcontext.mc_r15    = r15;
	ctx.uc_mcontext.mc_rflags = rflags;
	ctx.uc_mcontext.mc_cs     = cs;
	ctx.uc_mcontext.mc_ss     = ss;
#endif
#endif

	return ctx;
}

static SignalUcontext CreateCurrentGuestCallSignalUcontext(uint64_t rip) {
	auto ctx = CreateSignalUcontext();

	uint64_t rsp = 0;
	uint64_t rbp = 0;
	uint64_t rbx = 0;
	uint64_t r12 = 0;
	uint64_t r13 = 0;
	uint64_t r14 = 0;
	uint64_t r15 = 0;
	asm volatile("movq %%rsp, %0\n\t"
	             "movq %%rbp, %1\n\t"
	             "movq %%rbx, %2\n\t"
	             "movq %%r12, %3\n\t"
	             "movq %%r13, %4\n\t"
	             "movq %%r14, %5\n\t"
	             "movq %%r15, %6\n\t"
	             : "=r"(rsp), "=r"(rbp), "=r"(rbx), "=r"(r12), "=r"(r13), "=r"(r14), "=r"(r15)
	             :
	             : "memory");

	ctx.uc_mcontext.mc_rax = 0;
	ctx.uc_mcontext.mc_rcx = 0;
	ctx.uc_mcontext.mc_rdx = 0;
	ctx.uc_mcontext.mc_rsi = 0;
	ctx.uc_mcontext.mc_rdi = 0;
	ctx.uc_mcontext.mc_r8  = 0;
	ctx.uc_mcontext.mc_r9  = 0;
	ctx.uc_mcontext.mc_r10 = 0;
	ctx.uc_mcontext.mc_r11 = 0;
	ctx.uc_mcontext.mc_rbx = rbx;
	ctx.uc_mcontext.mc_rbp = rbp;
	ctx.uc_mcontext.mc_rsp = rsp;
	ctx.uc_mcontext.mc_r12 = r12;
	ctx.uc_mcontext.mc_r13 = r13;
	ctx.uc_mcontext.mc_r14 = r14;
	ctx.uc_mcontext.mc_r15 = r15;
	ctx.uc_mcontext.mc_rip = rip;

	return ctx;
}

static bool IsGuestCodeAddress(uint64_t addr) {
	return addr >= 0x0000000900000000ull && addr < 0x0000000980000000ull;
}

static bool IsAddressInRange(uint64_t addr, uint64_t base, uint64_t size) {
	return size != 0 && addr >= base && addr < base + size;
}

static uint64_t GetFallbackStackPointer(Pthread thread) {
	uint64_t stack_addr = 0;
	uint64_t stack_size = 0;
	if (!PthreadGetGuestStack(thread, &stack_addr, &stack_size)) {
		return 0;
	}

	const auto stack_top = (stack_addr + stack_size) & ~0xfull;
	if (stack_top <= stack_addr + 0x100) {
		return stack_top;
	}
	return stack_top - 0x100;
}

static void SanitizeNonGuestSignalUcontext(SignalUcontext* ctx, Pthread thread) {
	if (ctx == nullptr || IsGuestCodeAddress(ctx->uc_mcontext.mc_rip)) {
		return;
	}

	uint64_t   stack_addr = 0;
	uint64_t   stack_size = 0;
	const bool has_stack  = PthreadGetGuestStack(thread, &stack_addr, &stack_size);
	const bool rsp_valid =
	    has_stack && IsAddressInRange(ctx->uc_mcontext.mc_rsp, stack_addr, stack_size);
	const bool rbp_valid =
	    has_stack && IsAddressInRange(ctx->uc_mcontext.mc_rbp, stack_addr, stack_size);
	const auto fallback_sp = GetFallbackStackPointer(thread);

	ctx->uc_mcontext.mc_rax = 0;
	ctx->uc_mcontext.mc_rbx = 0;
	ctx->uc_mcontext.mc_rcx = 0;
	ctx->uc_mcontext.mc_rdx = 0;
	ctx->uc_mcontext.mc_rsi = 0;
	ctx->uc_mcontext.mc_rdi = 0;
	ctx->uc_mcontext.mc_rbp = (rbp_valid ? ctx->uc_mcontext.mc_rbp : fallback_sp);
	ctx->uc_mcontext.mc_rsp = (rsp_valid ? ctx->uc_mcontext.mc_rsp : fallback_sp);
	ctx->uc_mcontext.mc_r8  = 0;
	ctx->uc_mcontext.mc_r9  = 0;
	ctx->uc_mcontext.mc_r10 = 0;
	ctx->uc_mcontext.mc_r11 = 0;
	ctx->uc_mcontext.mc_r12 = 0;
	ctx->uc_mcontext.mc_r13 = 0;
	ctx->uc_mcontext.mc_r14 = 0;
	ctx->uc_mcontext.mc_r15 = 0;
	ctx->uc_mcontext.mc_rip = 0;
}

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
static void ApplySignalUcontext(CONTEXT* dst_ctx, const SignalUcontext& src_ctx) {
	if (dst_ctx == nullptr) {
		return;
	}

	dst_ctx->R8     = src_ctx.uc_mcontext.mc_r8;
	dst_ctx->R9     = src_ctx.uc_mcontext.mc_r9;
	dst_ctx->R10    = src_ctx.uc_mcontext.mc_r10;
	dst_ctx->R11    = src_ctx.uc_mcontext.mc_r11;
	dst_ctx->R12    = src_ctx.uc_mcontext.mc_r12;
	dst_ctx->R13    = src_ctx.uc_mcontext.mc_r13;
	dst_ctx->R14    = src_ctx.uc_mcontext.mc_r14;
	dst_ctx->R15    = src_ctx.uc_mcontext.mc_r15;
	dst_ctx->Rdi    = src_ctx.uc_mcontext.mc_rdi;
	dst_ctx->Rsi    = src_ctx.uc_mcontext.mc_rsi;
	dst_ctx->Rbp    = src_ctx.uc_mcontext.mc_rbp;
	dst_ctx->Rbx    = src_ctx.uc_mcontext.mc_rbx;
	dst_ctx->Rdx    = src_ctx.uc_mcontext.mc_rdx;
	dst_ctx->Rax    = src_ctx.uc_mcontext.mc_rax;
	dst_ctx->Rcx    = src_ctx.uc_mcontext.mc_rcx;
	dst_ctx->Rsp    = src_ctx.uc_mcontext.mc_rsp;
	dst_ctx->Rip    = src_ctx.uc_mcontext.mc_rip;
	dst_ctx->SegCs  = static_cast<DWORD>(src_ctx.uc_mcontext.mc_cs);
	dst_ctx->SegFs  = src_ctx.uc_mcontext.mc_fs;
	dst_ctx->SegGs  = src_ctx.uc_mcontext.mc_gs;
	dst_ctx->SegSs  = static_cast<DWORD>(src_ctx.uc_mcontext.mc_ss);
	dst_ctx->SegDs  = src_ctx.uc_mcontext.mc_ds;
	dst_ctx->SegEs  = src_ctx.uc_mcontext.mc_es;
	dst_ctx->EFlags = static_cast<DWORD>(src_ctx.uc_mcontext.mc_rflags);
}
#endif

#if KYTY_PLATFORM != KYTY_PLATFORM_WINDOWS && defined(__x86_64__)

static SignalUcontext CreateSignalUcontextFromHost(const ucontext_t* host_ctx) {
	SignalUcontext ctx = {};
	if (host_ctx == nullptr) {
		return ctx;
	}

#if defined(__APPLE__)
	const auto& ss = host_ctx->uc_mcontext->__ss;

	ctx.uc_mcontext.mc_rdi    = ss.__rdi;
	ctx.uc_mcontext.mc_rsi    = ss.__rsi;
	ctx.uc_mcontext.mc_rdx    = ss.__rdx;
	ctx.uc_mcontext.mc_rcx    = ss.__rcx;
	ctx.uc_mcontext.mc_r8     = ss.__r8;
	ctx.uc_mcontext.mc_r9     = ss.__r9;
	ctx.uc_mcontext.mc_rax    = ss.__rax;
	ctx.uc_mcontext.mc_rbx    = ss.__rbx;
	ctx.uc_mcontext.mc_rbp    = ss.__rbp;
	ctx.uc_mcontext.mc_r10    = ss.__r10;
	ctx.uc_mcontext.mc_r11    = ss.__r11;
	ctx.uc_mcontext.mc_r12    = ss.__r12;
	ctx.uc_mcontext.mc_r13    = ss.__r13;
	ctx.uc_mcontext.mc_r14    = ss.__r14;
	ctx.uc_mcontext.mc_r15    = ss.__r15;
	ctx.uc_mcontext.mc_rip    = ss.__rip;
	ctx.uc_mcontext.mc_rsp    = ss.__rsp;
	ctx.uc_mcontext.mc_rflags = ss.__rflags;
	ctx.uc_mcontext.mc_cs     = ss.__cs & 0xffffu;
	ctx.uc_mcontext.mc_gs     = static_cast<uint16_t>(ss.__gs & 0xffffu);
	ctx.uc_mcontext.mc_fs     = static_cast<uint16_t>(ss.__fs & 0xffffu);
	ctx.uc_mcontext.mc_len    = sizeof(SignalMcontext);

	return ctx;
#else
	const auto* gregs = host_ctx->uc_mcontext.gregs;

	ctx.uc_mcontext.mc_rdi    = static_cast<uint64_t>(gregs[REG_RDI]);
	ctx.uc_mcontext.mc_rsi    = static_cast<uint64_t>(gregs[REG_RSI]);
	ctx.uc_mcontext.mc_rdx    = static_cast<uint64_t>(gregs[REG_RDX]);
	ctx.uc_mcontext.mc_rcx    = static_cast<uint64_t>(gregs[REG_RCX]);
	ctx.uc_mcontext.mc_r8     = static_cast<uint64_t>(gregs[REG_R8]);
	ctx.uc_mcontext.mc_r9     = static_cast<uint64_t>(gregs[REG_R9]);
	ctx.uc_mcontext.mc_rax    = static_cast<uint64_t>(gregs[REG_RAX]);
	ctx.uc_mcontext.mc_rbx    = static_cast<uint64_t>(gregs[REG_RBX]);
	ctx.uc_mcontext.mc_rbp    = static_cast<uint64_t>(gregs[REG_RBP]);
	ctx.uc_mcontext.mc_r10    = static_cast<uint64_t>(gregs[REG_R10]);
	ctx.uc_mcontext.mc_r11    = static_cast<uint64_t>(gregs[REG_R11]);
	ctx.uc_mcontext.mc_r12    = static_cast<uint64_t>(gregs[REG_R12]);
	ctx.uc_mcontext.mc_r13    = static_cast<uint64_t>(gregs[REG_R13]);
	ctx.uc_mcontext.mc_r14    = static_cast<uint64_t>(gregs[REG_R14]);
	ctx.uc_mcontext.mc_r15    = static_cast<uint64_t>(gregs[REG_R15]);
	ctx.uc_mcontext.mc_rip    = static_cast<uint64_t>(gregs[REG_RIP]);
	ctx.uc_mcontext.mc_rsp    = static_cast<uint64_t>(gregs[REG_RSP]);
	ctx.uc_mcontext.mc_rflags = static_cast<uint64_t>(gregs[REG_EFL]);

	// Linux packs cs/gs/fs into one greg.
	const auto csgsfs      = static_cast<uint64_t>(gregs[REG_CSGSFS]);
	ctx.uc_mcontext.mc_cs  = csgsfs & 0xffffu;
	ctx.uc_mcontext.mc_gs  = static_cast<uint16_t>((csgsfs >> 16u) & 0xffffu);
	ctx.uc_mcontext.mc_fs  = static_cast<uint16_t>((csgsfs >> 32u) & 0xffffu);
	ctx.uc_mcontext.mc_len = sizeof(SignalMcontext);

	return ctx;
#endif
}

static void ApplySignalUcontextToHost(ucontext_t* dst_ctx, const SignalUcontext& src_ctx) {
	if (dst_ctx == nullptr) {
		return;
	}

#if defined(__APPLE__)
	auto& ss = dst_ctx->uc_mcontext->__ss;

	ss.__rdi    = src_ctx.uc_mcontext.mc_rdi;
	ss.__rsi    = src_ctx.uc_mcontext.mc_rsi;
	ss.__rdx    = src_ctx.uc_mcontext.mc_rdx;
	ss.__rcx    = src_ctx.uc_mcontext.mc_rcx;
	ss.__r8     = src_ctx.uc_mcontext.mc_r8;
	ss.__r9     = src_ctx.uc_mcontext.mc_r9;
	ss.__rax    = src_ctx.uc_mcontext.mc_rax;
	ss.__rbx    = src_ctx.uc_mcontext.mc_rbx;
	ss.__rbp    = src_ctx.uc_mcontext.mc_rbp;
	ss.__r10    = src_ctx.uc_mcontext.mc_r10;
	ss.__r11    = src_ctx.uc_mcontext.mc_r11;
	ss.__r12    = src_ctx.uc_mcontext.mc_r12;
	ss.__r13    = src_ctx.uc_mcontext.mc_r13;
	ss.__r14    = src_ctx.uc_mcontext.mc_r14;
	ss.__r15    = src_ctx.uc_mcontext.mc_r15;
	ss.__rip    = src_ctx.uc_mcontext.mc_rip;
	ss.__rsp    = src_ctx.uc_mcontext.mc_rsp;
	ss.__rflags = src_ctx.uc_mcontext.mc_rflags;
	// Segment selectors are left untouched; XNU validates them on sigreturn.
#else
	auto* gregs = dst_ctx->uc_mcontext.gregs;

	gregs[REG_RDI] = static_cast<greg_t>(src_ctx.uc_mcontext.mc_rdi);
	gregs[REG_RSI] = static_cast<greg_t>(src_ctx.uc_mcontext.mc_rsi);
	gregs[REG_RDX] = static_cast<greg_t>(src_ctx.uc_mcontext.mc_rdx);
	gregs[REG_RCX] = static_cast<greg_t>(src_ctx.uc_mcontext.mc_rcx);
	gregs[REG_R8]  = static_cast<greg_t>(src_ctx.uc_mcontext.mc_r8);
	gregs[REG_R9]  = static_cast<greg_t>(src_ctx.uc_mcontext.mc_r9);
	gregs[REG_RAX] = static_cast<greg_t>(src_ctx.uc_mcontext.mc_rax);
	gregs[REG_RBX] = static_cast<greg_t>(src_ctx.uc_mcontext.mc_rbx);
	gregs[REG_RBP] = static_cast<greg_t>(src_ctx.uc_mcontext.mc_rbp);
	gregs[REG_R10] = static_cast<greg_t>(src_ctx.uc_mcontext.mc_r10);
	gregs[REG_R11] = static_cast<greg_t>(src_ctx.uc_mcontext.mc_r11);
	gregs[REG_R12] = static_cast<greg_t>(src_ctx.uc_mcontext.mc_r12);
	gregs[REG_R13] = static_cast<greg_t>(src_ctx.uc_mcontext.mc_r13);
	gregs[REG_R14] = static_cast<greg_t>(src_ctx.uc_mcontext.mc_r14);
	gregs[REG_R15] = static_cast<greg_t>(src_ctx.uc_mcontext.mc_r15);
	gregs[REG_RIP] = static_cast<greg_t>(src_ctx.uc_mcontext.mc_rip);
	gregs[REG_RSP] = static_cast<greg_t>(src_ctx.uc_mcontext.mc_rsp);
	gregs[REG_EFL] = static_cast<greg_t>(src_ctx.uc_mcontext.mc_rflags);

	// The kernel validates packed segment selectors on sigreturn.
#endif
}

static int SignalDispatchHostSignal() {
#if defined(__APPLE__)
	// macOS has no realtime signals; SIGUSR1 is otherwise unused on the host side (the
	// guest's SIGUSR1 is an emulated signal number, not a host registration).
	static const int host_signal = SIGUSR1;
#else
	static const int host_signal = SIGRTMIN + 3;
#endif
	return host_signal;
}

static void HostSignalDispatchHandler(int /*host_signal*/, siginfo_t* /*info*/,
                                      void* native_context) {
	Pthread current = PthreadSelfOrNull();
	if (current == nullptr) {
		return;
	}

	auto* host_ctx = static_cast<ucontext_t*>(native_context);

	for (int signum = 0; signum < static_cast<int>(std::size(g_exception_handlers)); signum++) {
		if (PthreadIsSignalBlocked(current, signum) || !PthreadTakePendingSignal(current, signum)) {
			continue;
		}

		auto* handler = reinterpret_cast<exception_handler_func_t>(g_exception_handlers[signum]);
		if (handler != nullptr) {
			SignalDispatchScope scope;
			auto                ctx = CreateSignalUcontextFromHost(host_ctx);
			if (IsGuestCodeAddress(ctx.uc_mcontext.mc_rip)) {
				handler(signum, &ctx);
				ApplySignalUcontextToHost(host_ctx, ctx);
			} else {
				// Do not expose or restore a host frame.
				SanitizeNonGuestSignalUcontext(&ctx, current);
				handler(signum, &ctx);
			}
		}
		return;
	}
}

static bool EnsureHostSignalDispatchInstalled() {
	static const bool installed = [] {
		struct sigaction action {};
		action.sa_sigaction = HostSignalDispatchHandler;
		sigemptyset(&action.sa_mask);
		action.sa_flags = SA_SIGINFO | SA_RESTART;
		return ::sigaction(SignalDispatchHostSignal(), &action, nullptr) == 0;
	}();
	return installed;
}

#endif

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
enum KytyQueueUserApcFlags : ULONG_PTR {
	KytyQueueUserApcFlagsNone            = 0,
	KytyQueueUserApcFlagsSpecialUserApc  = 1,
	KytyQueueUserApcFlagsCallbackContext = 0x00010000,
	KytyQueueUserApcFlagsMaxValue        = 2,
};

union KytyUserApcOption {
	ULONG_PTR UserApcFlags;
	HANDLE    MemoryReserveHandle;
};

using KytyPsApcRoutine = void (*)(void* apc_arg1, void* apc_arg2, void* apc_arg3, PCONTEXT context);
using NtQueueApcThreadExFunc = uint64_t(WINAPI*)(HANDLE thread, KytyUserApcOption option,
                                                 KytyPsApcRoutine routine, void* arg1, void* arg2,
                                                 void* arg3);

static NtQueueApcThreadExFunc GetNtQueueApcThreadEx() {
	static auto* nt_queue_apc_thread_ex = reinterpret_cast<NtQueueApcThreadExFunc>(
	    GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueueApcThreadEx"));
	return nt_queue_apc_thread_ex;
}

static void SignalApcHandler(void* arg1, void* arg2, void* /*arg3*/, PCONTEXT context) {
	auto*      thread = static_cast<Pthread>(arg1);
	const auto signum = static_cast<int>(reinterpret_cast<intptr_t>(arg2));
	if (PthreadIsSignalBlocked(thread, signum) || !PthreadTakePendingSignal(thread, signum)) {
		return;
	}

	auto* handler = reinterpret_cast<exception_handler_func_t>(g_exception_handlers[signum]);
	if (handler != nullptr) {
		SignalDispatchScope scope;
		auto                ctx           = CreateSignalUcontext(context);
		auto                guest_context = IsGuestCodeAddress(ctx.uc_mcontext.mc_rip);
		if (!guest_context) {
			SanitizeNonGuestSignalUcontext(&ctx, thread);
			std::thread([thread, signum, handler, ctx]() mutable {
				SignalDispatchScope helper_scope;
				auto*               previous_self = PthreadSwapSelfForSignal(thread);
				handler(signum, &ctx);
				PthreadSwapSelfForSignal(previous_self);
			}).detach();
			return;
		}
		handler(signum, &ctx);
		if (guest_context) {
			ApplySignalUcontext(context, ctx);
		}
	}
}

#endif

void KernelDispatchPendingSignalForCurrentThread() {
	Pthread current = PthreadSelfOrNull();
	if (current == nullptr) {
		return;
	}

	for (int signum = 0; signum < static_cast<int>(std::size(g_exception_handlers)); signum++) {
		if (PthreadIsSignalBlocked(current, signum) || !PthreadTakePendingSignal(current, signum)) {
			continue;
		}

		auto* handler = reinterpret_cast<exception_handler_func_t>(g_exception_handlers[signum]);
		if (handler != nullptr) {
			SignalDispatchScope scope;
			auto                ctx = CreateSignalUcontext();
			SanitizeNonGuestSignalUcontext(&ctx, current);
			handler(signum, &ctx);
		}
		return;
	}
}

static int KYTY_SYSV_ABI KernelInstallExceptionHandler(int signum, void* handler) {
	PRINT_NAME();

	LOGF("\t signum  = %d\n"
	     "\t handler = 0x%016" PRIx64 "\n",
	     signum, reinterpret_cast<uint64_t>(handler));

	if (!IsAllowedExceptionSignal(signum)) {
		return KERNEL_ERROR_EINVAL;
	}
	if (g_exception_handlers[signum] != nullptr) {
		return KERNEL_ERROR_EAGAIN;
	}

	g_exception_handlers[signum] = handler;
	return OK;
}

static int KYTY_SYSV_ABI KernelRemoveExceptionHandler(int signum) {
	PRINT_NAME();

	LOGF("\t signum = %d\n", signum);

	if (!IsAllowedExceptionSignal(signum)) {
		return KERNEL_ERROR_EINVAL;
	}

	g_exception_handlers[signum] = nullptr;
	return OK;
}

static int KYTY_SYSV_ABI KernelRaiseException(Pthread thread, int signum) {
	constexpr int POSIX_SIGUSR1 = 30;

	if (signum != POSIX_SIGUSR1 || thread == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	auto* handler = reinterpret_cast<exception_handler_func_t>(g_exception_handlers[signum]);
	if (handler != nullptr) {
		if (PthreadIsSignalBlocked(thread, signum)) {
			PthreadQueuePendingSignal(thread, signum);
			return OK;
		}
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		const auto target_thread_id       = PthreadGetHostThreadId(thread);
		auto*      nt_queue_apc_thread_ex = GetNtQueueApcThreadEx();
		if (target_thread_id == 0) {
			return KERNEL_ERROR_EINVAL;
		}
		if (target_thread_id == static_cast<uint64_t>(GetCurrentThreadId())) {
			SignalDispatchScope scope;
			auto                ctx = CreateCurrentGuestCallSignalUcontext(
			    reinterpret_cast<uint64_t>(__builtin_return_address(0)));
			handler(signum, &ctx);
			return OK;
		}
		if (nt_queue_apc_thread_ex == nullptr) {
			return KERNEL_ERROR_EINVAL;
		}

		HANDLE target_thread =
		    OpenThread(THREAD_SET_CONTEXT, FALSE, static_cast<DWORD>(target_thread_id));
		if (target_thread == nullptr) {
			return KERNEL_ERROR_EINVAL;
		}

		PthreadQueuePendingSignal(thread, signum);
		KytyUserApcOption option {};
		option.UserApcFlags = KytyQueueUserApcFlagsSpecialUserApc;

		const auto status =
		    nt_queue_apc_thread_ex(target_thread, option, SignalApcHandler, thread,
		                           reinterpret_cast<void*>(static_cast<intptr_t>(signum)), nullptr);

		if (status != 0) {
			PthreadTakePendingSignal(thread, signum);
			CloseHandle(target_thread);
			LOGF("\t NtQueueApcThreadEx failed: target_os_thread=%" PRIu64 ", status=0x%016" PRIx64
			     "\n",
			     target_thread_id, status);
			return KERNEL_ERROR_EINVAL;
		}

		PthreadWakeForSignal(thread);
		CloseHandle(target_thread);
		return OK;
#elif defined(__x86_64__)
		// Deliver on the target thread.
		if (thread == PthreadSelfOrNull()) {
			SignalDispatchScope scope;
			auto                ctx = CreateCurrentGuestCallSignalUcontext(
			    reinterpret_cast<uint64_t>(__builtin_return_address(0)));
			handler(signum, &ctx);
			return OK;
		}

		if (!EnsureHostSignalDispatchInstalled()) {
			return KERNEL_ERROR_EINVAL;
		}

		PthreadQueuePendingSignal(thread, signum);
		if (!PthreadKillHost(thread, SignalDispatchHostSignal())) {
			PthreadTakePendingSignal(thread, signum);
			LOGF("\t pthread_kill failed for target thread\n");
			return KERNEL_ERROR_EINVAL;
		}

		PthreadWakeForSignal(thread);
		WaitForSignalDispatch(thread, signum);
		return OK;
#else
		auto ctx = CreateSignalUcontext();
		handler(signum, &ctx);
#endif
	}

	return OK;
}

static KYTY_SYSV_ABI KernelModule KernelLoadStartModule(const char* module_file_name, size_t args,
                                                        const void* argp, uint32_t flags,
                                                        const KernelLoadModuleOpt* opt, int* res) {
	PRINT_NAME();

	// EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());

	LOGF("\tmodule_file_name = %s\n", module_file_name);

	EXIT_NOT_IMPLEMENTED(flags != 0);
	EXIT_NOT_IMPLEMENTED(opt != nullptr);

	auto* rt = Common::Singleton<Loader::RuntimeLinker>::Instance();

	auto module_path = FileSystem::GetRealFilename(std::string(module_file_name));
	if (!Common::File::IsFileExisting(module_path)) {
		LOGF("\tmodule real path missing = %s\n", Common::PathToString(module_path).c_str());
		if (res != nullptr) {
			*res = KERNEL_ERROR_ENOENT;
		}
		return KERNEL_ERROR_ENOENT;
	}

	auto* program = rt->FindProgramByFileName(module_path);
	if (program != nullptr) {
		++program->load_count;
		if (res != nullptr) {
			*res = OK;
		}
		return static_cast<KernelModule>(program->unique_id);
	}

	program = rt->LoadProgram(module_path);

	auto handle = program->unique_id;

	program->dbg_print_reloc = true;

	rt->RelocateProgram(program);

	program->load_count = 1;
	int result = rt->StartModule(program, args, argp, nullptr);

	LOGF("\tmodule_start() result = %d\n", result);

	EXIT_NOT_IMPLEMENTED(result < 0);

	if (res != nullptr) {
		*res = result;
	}

	return static_cast<KernelModule>(handle);
}

static int KYTY_SYSV_ABI KernelStopUnloadModule(KernelModule handle, size_t args, const void* argp,
                                                uint32_t flags, const KernelUnloadModuleOpt* opt,
                                                int* res) {
	PRINT_NAME();

	// EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());

	auto* rt = Common::Singleton<Loader::RuntimeLinker>::Instance();

	EXIT_NOT_IMPLEMENTED(flags != 0);
	EXIT_NOT_IMPLEMENTED(opt != nullptr);

	auto* program = rt->FindProgramById(handle);

	if (program == nullptr) {
		LOGF("\tinvalid module handle = %" PRId32 "\n", handle);
		return KERNEL_ERROR_ESRCH;
	}

	if (program->load_count > 1) {
		--program->load_count;
		return OK;
	}

	if (g_get_thread_atexit_count_func != nullptr &&
	    g_get_thread_atexit_count_func(program->unique_id) > 0) {
		LOGF("KernelStopUnloadModule: cannot unload %s\n",
		     Common::PathToString(program->file_name).c_str());
		if (g_thread_atexit_report_func != nullptr) {
			g_thread_atexit_report_func(program->unique_id);
		}
		return KERNEL_ERROR_EBUSY;
	}

	int result = rt->StopModule(program, args, argp, nullptr);

	LOGF("\tmodule_stop() result = %d\n", result);

	EXIT_NOT_IMPLEMENTED(result < 0);

	if (res != nullptr) {
		*res = result;
	}

	rt->UnloadProgram(program);

	return OK;
}

static void* KYTY_SYSV_ABI tls_get_addr(TlsInfo* info) {
	PRINT_NAME();

	// EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread());

	return Loader::RuntimeLinker::TlsGetAddr(info->program) + info->offset;
}

static void* KYTY_SYSV_ABI KernelGetProcParam() {
	PRINT_NAME();

	auto* rt = Common::Singleton<Loader::RuntimeLinker>::Instance(); // NOLINT

	return reinterpret_cast<void*>(rt->GetProcParam());
}

static int KYTY_SYSV_ABI KernelIsTrinityMode() {
	static std::atomic_uint32_t call_count {0};

	auto count = call_count.fetch_add(1, std::memory_order_relaxed);
	if (count < 8 || (count % 1024) == 0) {
		PRINT_NAME();
		LOGF("\tcall = %u, return = 0 (base PS5 mode)\n", count + 1);
	}

	return 0;
}

static int KYTY_SYSV_ABI KernelGetOperationMode(int* mode, int* submode) {
	PRINT_NAME();

	*mode    = 2; // PS5 Base
	*submode = 0; // None
	LOGF("\t mode = %d, submode = %d\n", *mode, *submode);
	return OK;
}

static int KYTY_SYSV_ABI KernelFsync(int fd) {
	PRINT_NAME();

	LOGF("\t fd = %d\n", fd);

	return OK;
}

static void KYTY_SYSV_ABI KernelSync() {
	PRINT_NAME();
}

static int KYTY_SYSV_ABI getpid() {
	PRINT_NAME();

	return 100;
}

static void KYTY_SYSV_ABI KernelRtldSetApplicationHeapAPI(void* api[]) {
	PRINT_NAME();

	auto* rt = Common::Singleton<Loader::RuntimeLinker>::Instance();
	rt->SetApplicationHeapApi(api);

	if (api == nullptr) {
		return;
	}

	for (int i = 0; i < 10; i++) {
		LOGF("\tapi[%d] = 0x%016" PRIx64 "\n", i, reinterpret_cast<uint64_t>(api[i]));
	}

	[[maybe_unused]] auto* heap_malloc         = api[0];
	[[maybe_unused]] auto* heap_free           = api[1];
	[[maybe_unused]] auto* heap_posix_memalign = api[6];
}

static int64_t KYTY_SYSV_ABI write(int d, const char* str, int64_t size) {
	// PRINT_NAME();

	EXIT_NOT_IMPLEMENTED(d < 0);

	if (Network::Net::IsSocket(d)) {
		return Network::Net::Send(d, str, static_cast<uint64_t>(size), 0);
	}

	if (d > 2) {
		return POSIX_N_CALL(FileSystem::KernelWrite(d, str, size));
	}

	int size_int = static_cast<int>(size);

	return size_int;
}

static int KYTY_SYSV_ABI open(const char* path, int flags, int mode) {
	return POSIX_N_CALL(FileSystem::KernelOpen(path, flags, (flags & 0x200) != 0 ? mode : 0));
}

static int KYTY_SYSV_ABI umask(int mask) {
	return FileSystem::KernelUmask(mask);
}

static int KYTY_SYSV_ABI fsync(int d) {
	return POSIX_CALL(KernelFsync(d));
}

static int KYTY_SYSV_ABI close(int d) {
	if (d < 0) {
		*Posix::GetErrorAddr() = Posix::POSIX_EBADF;
		return -1;
	}

	if (d <= 2) {
		return 0;
	}

	if (Network::Net::IsSocket(d)) {
		return POSIX_NET_CALL(Network::Net::SocketClose(d));
	}

	return POSIX_CALL(FileSystem::KernelClose(d));
}

static int KYTY_SYSV_ABI ioctl(int d, uint64_t request, void* arg) {
	if (Network::Net::IsSocket(d)) {
		return Network::Net::Ioctl(d, request, arg);
	}
	return POSIX_N_CALL(FileSystem::KernelIoctl(d, request, arg));
}
static int KYTY_SYSV_ABI sysctlbyname(const char* name, void* oldp, size_t* oldlenp,
                                      const void* newp, size_t newlen) {
	if (name == nullptr || oldlenp == nullptr) {
		*Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
		return -1;
	}

	LOGF("\t sysctlbyname = %s\n", name);

	if (std::strcmp(name, "kern.rng_pseudo") == 0) {
		if (newp != nullptr || newlen != 0) {
			*Posix::GetErrorAddr() = Posix::POSIX_EINVAL;
			return -1;
		}

		if (oldp == nullptr) {
			*oldlenp = 64;
			return 0;
		}

		const auto size = *oldlenp;
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(oldp), size);
		auto*              out = static_cast<uint8_t*>(oldp);
		std::random_device random;
		for (size_t i = 0; i < size; i++) {
			out[i] = static_cast<uint8_t>(random());
		}
		return 0;
	}

	*Posix::GetErrorAddr() = Posix::POSIX_ENOENT;
	return -1;
}
int KYTY_SYSV_ABI KernelSysctl(const uint32_t* mib, uint32_t mib_count, void* oldp, size_t* oldlenp,
                               const void* newp, size_t newlen) {
	if (mib == nullptr) {
		*Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
		return -1;
	}
	// The kernel takes a missing oldlenp as a length of 0, which is how libkernel sets a value or
	// pokes a node.
	size_t no_oldlen = 0;
	if (oldlenp == nullptr) {
		oldlenp = &no_oldlen;
	}
	if (mib_count == 2 && mib[0] == 1 && mib[1] == 33) {
		if (newp != nullptr || newlen != 0) {
			*Posix::GetErrorAddr() = Posix::POSIX_EINVAL;
			return -1;
		}
		const auto stack_top = PthreadGetMainGuestStackTop();
		if (stack_top == 0) {
			*Posix::GetErrorAddr() = Posix::POSIX_ENOENT;
			return -1;
		}
		const size_t output_size    = sizeof(stack_top);
		const auto   requested_size = *oldlenp;
		*oldlenp                    = output_size;
		if (oldp == nullptr) {
			return 0;
		}
		if (requested_size < output_size) {
			*Posix::GetErrorAddr() = Posix::POSIX_ENOMEM;
			return -1;
		}
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(oldp), output_size);
		std::memcpy(oldp, &stack_top, output_size);
		LOGF("KERNEL_SYSCTL kern.usrstack=0x%016" PRIx64 "\n", stack_top);
		return 0;
	}
	// sysctlnametomib (+0x115f0): name as the new value of {0, 3}. Kernel oids start at 0x100,
	// clear of libkernel's MIBs
	uint32_t    oid[2]      = {0, 0x100};
	uint64_t    value       = 0;
	const void* output      = &value;
	size_t      output_size = 0;
	std::string unknown;
	if (mib_count == 2 && mib[0] == 0 && mib[1] == 3 && newp != nullptr) {
		const std::string name(static_cast<const char*>(newp), newlen);
		if (name == "kern.rng_pseudo") {
			oid[0] = 1;
		} else if (name == "machdep.tsc_freq") {
			oid[0] = 7;
		}
		if (oid[0] != 0) {
			output      = oid;
			output_size = sizeof(oid);
		} else {
			unknown = "name=" + name;
		}
	} else if (mib_count == 2 && mib[0] == 1 && mib[1] == 0x100) {
		return sysctlbyname("kern.rng_pseudo", oldp, oldlenp, newp, newlen);
	} else if (mib_count == 4 && mib[0] == 1 && mib[1] == 14 && (mib[2] == 36 || mib[2] == 68) &&
	           newp == nullptr) {
		// 36: compiled SDK version (+0x1c860); 68 high half: Prospero SDK (+0x1c9c0). mib[3] is a
		// pid, not compared
		auto*       rt         = Common::Singleton<Loader::RuntimeLinker>::Instance(); // NOLINT
		const auto* proc_param = reinterpret_cast<const uint64_t*>(rt->GetProcParam());
		if (proc_param != nullptr && proc_param[0] > 0x17) {
			value       = proc_param[2];
			output_size = mib[2] == 68 ? sizeof(value) : sizeof(uint32_t);
		}
	} else if (mib_count == 2 && newp == nullptr) {
		if (mib[0] == 7 && mib[1] == 0x100) {
			value       = KernelGetTscFrequency();
			output_size = sizeof(value);
		} else if ((mib[0] == 6 && mib[1] == 7) || (mib[0] == 9 && mib[1] == 20)) {
			// hw.pagesize and p1003_1b.pagesize are ints; sysconf(_SC_PAGESIZE) prefers a non-zero
			// second over getpagesize
			value       = 0x4000;
			output_size = sizeof(int32_t);
		}
	}
	if (output_size != 0) {
		const auto requested_size = *oldlenp;
		*oldlenp                  = output_size;
		if (oldp == nullptr) {
			return 0;
		}
		if (requested_size < output_size) {
			*Posix::GetErrorAddr() = Posix::POSIX_ENOMEM;
			return -1;
		}
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(oldp), output_size);
		std::memcpy(oldp, output, output_size);
		return 0;
	}
	if (unknown.empty()) {
		char text[64];
		std::snprintf(text, sizeof(text), "mib=%u.%u.%u count=%u%s", mib_count > 0 ? mib[0] : 0,
		              mib_count > 1 ? mib[1] : 0, mib_count > 2 ? mib[2] : 0, mib_count,
		              newp != nullptr ? " set" : "");
		unknown = text;
	}
	static std::mutex               unknown_mutex;
	static std::vector<std::string> unknown_logged;
	{
		std::lock_guard lock(unknown_mutex);
		if (std::find(unknown_logged.begin(), unknown_logged.end(), unknown) ==
		    unknown_logged.end()) {
			unknown_logged.push_back(unknown);
			LOGF("KERNEL_SYSCTL unsupported %s\n", unknown.c_str());
		}
	}
	*Posix::GetErrorAddr() = Posix::POSIX_ENOENT;
	return -1;
}
int KYTY_SYSV_ABI KernelSysctlStub(const uint32_t* mib, uint32_t mib_count, void* oldp,
                                   size_t* oldlenp, const void* newp, size_t newlen) {
	return KernelSysctl(mib, mib_count, oldp, oldlenp, newp, newlen) == 0 ? 0
	                                                                      : *Posix::GetErrorAddr();
}
int KYTY_SYSV_ABI KernelNativeOpen(const char* path, int flags, int mode) {
	return POSIX_N_CALL(FileSystem::KernelOpen(path, flags, (flags & 0x200) != 0 ? mode : 0));
}
int64_t KYTY_SYSV_ABI KernelNativeWrite(int d, const void* buf, size_t nbytes) {
	return POSIX_N_CALL(FileSystem::KernelWrite(d, buf, nbytes));
}
int KYTY_SYSV_ABI KernelNativeClose(int d) {
	return POSIX_CALL(FileSystem::KernelClose(d));
}
// non-zero *error goes to libkernel's cerror (+0xd4), which sets errno and returns -1
int64_t KYTY_SYSV_ABI KernelRawSyscallStub(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                           uint64_t arg3, uint64_t arg4, uint64_t arg5,
                                           uint64_t number, uint64_t* error) {
	const auto reply =
	    NativeKernelBridge::DispatchSyscall({number, {arg0, arg1, arg2, arg3, arg4, arg5}});
	int posix_errno = reply.posix_errno;
	if (posix_errno == 0 && reply.value > KERNEL_ERROR_UNKNOWN &&
	    reply.value <= KERNEL_ERROR_UNKNOWN + 101) {
		posix_errno = KernelToPosix(static_cast<int>(reply.value));
	}
	static std::atomic_uint32_t seen[0x300];
	if (number < 0x300 && seen[number].fetch_add(1) == 0) {
		// error is the slot the +0x47040 stub pushed right under the wrapper's return address.
		LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_REDIRECT_LIBKERNEL_RAW_SYSCALLS first call "
		     "number=0x%" PRIx64 " caller=0x%" PRIx64 " args=0x%" PRIx64 ",0x%" PRIx64 ",0x%" PRIx64
		     ",0x%" PRIx64 ",0x%" PRIx64 ",0x%" PRIx64 " value=0x%" PRIx64
		     " errno=%d NON_AUTHENTIC\n",
		     number, error[1], arg0, arg1, arg2, arg3, arg4, arg5,
		     static_cast<uint64_t>(reply.value), posix_errno);
	}
	*error = static_cast<uint64_t>(posix_errno);
	return reply.value;
}
// called mid-wrapper by the census stub (+0x47080) on any thread, so the line is built on the stack
void KYTY_SYSV_ABI KernelRawSyscallCensus(uint64_t number, uint64_t caller) {
	static std::atomic_uint64_t calls[0x300];
	if (number >= 0x300) {
		return;
	}
	const uint64_t count = calls[number].fetch_add(1) + 1;
	if ((count & (count - 1)) == 0) {
		char      line[160];
		const int length = std::snprintf(
		    line, sizeof(line),
		    "FIRST_FRAME_AUDIT DIAGNOSTIC_CENSUS_LIBKERNEL_RAW_SYSCALLS number=0x%" PRIx64
		    " caller=0x%016" PRIx64 " count=%" PRIu64 "\n",
		    number, caller, count);
		::Log::Write(std::string_view(line, static_cast<size_t>(length)));
	}
}
static int64_t KYTY_SYSV_ABI read(int d, void* buf, uint64_t nbytes) {
	// PRINT_NAME();

	if (buf == nullptr) {
		*Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
		return -1;
	}

	if (d < 0 || d == 1 || d == 2) {
		*Posix::GetErrorAddr() = Posix::POSIX_EBADF;
		return -1;
	}

	if (Network::Net::IsSocket(d)) {
		return Network::Net::Recv(d, buf, nbytes, 0);
	}

	if (d > 2) {
		return POSIX_N_CALL(FileSystem::KernelRead(d, buf, nbytes));
	}

	if (nbytes == 0) {
		return 0;
	}

	auto* str = std::fgets(static_cast<char*>(buf), static_cast<int>(nbytes), stdin);

	return (str != nullptr ? static_cast<int64_t>(strlen(str)) : 0);
}

static bool DecodeEhFramePointer(const uint8_t* data, const uint8_t* end, uint8_t encoding,
                                 uint64_t field_addr, uint64_t* value) {
	EXIT_IF(value == nullptr);

	if (encoding == 0xff) {
		return false;
	}

	uint64_t out       = 0;
	auto     format    = encoding & 0x0f;
	auto     app       = encoding & 0x70;
	bool     is_signed = false;

	switch (format) {
		case 0x00:
			if (data + sizeof(uint64_t) > end) {
				return false;
			}
			std::memcpy(&out, data, sizeof(uint64_t));
			break;
		case 0x03:
			if (data + sizeof(uint32_t) > end) {
				return false;
			}
			{
				uint32_t tmp = 0;
				std::memcpy(&tmp, data, sizeof(tmp));
				out = tmp;
			}
			break;
		case 0x04:
			if (data + sizeof(uint64_t) > end) {
				return false;
			}
			std::memcpy(&out, data, sizeof(uint64_t));
			break;
		case 0x0b:
			if (data + sizeof(int32_t) > end) {
				return false;
			}
			{
				int32_t tmp = 0;
				std::memcpy(&tmp, data, sizeof(tmp));
				out       = static_cast<uint64_t>(static_cast<int64_t>(tmp));
				is_signed = true;
			}
			break;
		case 0x0c:
			if (data + sizeof(int64_t) > end) {
				return false;
			}
			std::memcpy(&out, data, sizeof(int64_t));
			is_signed = true;
			break;
		default: return false;
	}

	if (app == 0x10) {
		out = (is_signed ? static_cast<uint64_t>(static_cast<int64_t>(field_addr) +
		                                         static_cast<int64_t>(out))
		                 : field_addr + out);
	} else if (app != 0) {
		return false;
	}

	*value = out;
	return true;
}

// Kyty does not create guest signal-return trampoline frames.
int KYTY_SYSV_ABI KernelIsSignalReturn(uint64_t /*pc*/) {
	return 0;
}

int KYTY_SYSV_ABI KernelGetModuleInfoForUnwind(uint64_t addr, int flags,
                                               ModuleInfoForUnwind* info) {
	if (flags >= 3) {
		if (info != nullptr) {
			std::memset(info, 0, sizeof(ModuleInfoForUnwind));
		}
		return KERNEL_ERROR_EINVAL;
	}

	if (info == nullptr) {
		return KERNEL_ERROR_EFAULT;
	}

	if (info->st_size < sizeof(ModuleInfoForUnwind)) {
		return KERNEL_ERROR_EINVAL;
	}

	auto* rt      = Common::Singleton<Loader::RuntimeLinker>::Instance();
	auto* program = rt->FindProgramByAddr(addr);
	if (program == nullptr || program->elf == nullptr) {
		if (addr < 0x800000000ull) {
			// TODO(unwind): guest unwinding can reach a Kyty host return address below the guest VA
			// range. Report a synthetic boundary with no unwind tables so libc stops cleanly
			// instead of raising.
			std::memset(info, 0, sizeof(ModuleInfoForUnwind));
			info->st_size = sizeof(ModuleInfoForUnwind);
			std::snprintf(info->name, sizeof(info->name), "%s", "KytyHostBoundary");
			info->seg0_addr = addr & ~0xfffffull;
			info->seg0_size = 0x100000;
			return OK;
		}

		return KERNEL_ERROR_ESRCH;
	}

	const auto* ehdr = program->elf->GetEhdr();
	const auto* phdr = program->elf->GetPhdr();
	if (ehdr == nullptr || phdr == nullptr) {
		return KERNEL_ERROR_ESRCH;
	}

	constexpr Loader::Elf64_Word PT_GNU_EH_FRAME = 0x6474e550;

	uint64_t eh_frame_hdr_size = 0;

	std::memset(info, 0, sizeof(ModuleInfoForUnwind));
	info->st_size = sizeof(ModuleInfoForUnwind);

	if (program->dynamic_info != nullptr && program->dynamic_info->so_name != nullptr &&
	    program->dynamic_info->so_name[0] != '\0') {
		std::snprintf(info->name, sizeof(info->name), "%s", program->dynamic_info->so_name);
	} else {
		auto fallback_name = Common::PathToString(program->file_name.filename());
		std::snprintf(info->name, sizeof(info->name), "%s", fallback_name.c_str());
	}

	uint64_t image_start = UINT64_MAX;
	uint64_t image_end   = 0;

	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_memsz == 0) {
			continue;
		}

		if (phdr[i].p_type == Loader::PT_LOAD || phdr[i].p_type == Loader::PT_OS_RELRO) {
			const auto start = program->base_vaddr + phdr[i].p_vaddr;
			const auto end   = start + phdr[i].p_memsz;
			image_start      = std::min(image_start, start);
			image_end        = std::max(image_end, end);
		}

		if (phdr[i].p_type == PT_GNU_EH_FRAME) {
			info->eh_frame_hdr_addr = program->base_vaddr + phdr[i].p_vaddr;
			eh_frame_hdr_size       = phdr[i].p_memsz;
		}
	}

	const auto* shdr = program->elf->GetShdr();
	if (shdr != nullptr) {
		for (int i = 0; i < ehdr->e_shnum; i++) {
			const char* section_name = program->elf->GetSectionName(i);
			if (section_name != nullptr && std::strcmp(section_name, ".eh_frame") == 0) {
				info->eh_frame_addr = program->base_vaddr + shdr[i].sh_addr;
				info->eh_frame_size = shdr[i].sh_size;
				break;
			}
		}
	}

	if (info->eh_frame_hdr_addr != 0 && eh_frame_hdr_size >= 4) {
		const auto* hdr = reinterpret_cast<const uint8_t*>(info->eh_frame_hdr_addr);
		const auto* end = hdr + eh_frame_hdr_size;
		if (hdr[0] == 1) {
			uint64_t eh_frame_addr = 0;
			if (DecodeEhFramePointer(hdr + 4, end, hdr[1], info->eh_frame_hdr_addr + 4,
			                         &eh_frame_addr)) {
				info->eh_frame_addr = eh_frame_addr;
				if (info->eh_frame_size == 0 && info->eh_frame_hdr_addr > eh_frame_addr) {
					info->eh_frame_size = info->eh_frame_hdr_addr - eh_frame_addr;
				} else if (info->eh_frame_size == 0 &&
				           program->base_size_aligned >
				               info->eh_frame_hdr_addr - program->base_vaddr) {
					info->eh_frame_size = program->base_size_aligned -
					                      (info->eh_frame_hdr_addr - program->base_vaddr);
				}
			}
		}
	}

	if (image_start != UINT64_MAX && image_end > image_start) {
		info->seg0_addr = image_start;
		info->seg0_size = image_end - image_start;
	}

	if (info->eh_frame_addr != 0 && info->eh_frame_size == 0) {
		for (int i = 0; i < ehdr->e_phnum; i++) {
			if (phdr[i].p_memsz == 0 ||
			    (phdr[i].p_type != Loader::PT_LOAD && phdr[i].p_type != Loader::PT_OS_RELRO)) {
				continue;
			}

			const auto start = program->base_vaddr + phdr[i].p_vaddr;
			const auto end   = start + phdr[i].p_memsz;
			if (info->eh_frame_addr >= start && info->eh_frame_addr < end) {
				info->eh_frame_size = end - info->eh_frame_addr;
				break;
			}
		}
	}

	return OK;
}

static int KYTY_SYSV_ABI KernelGetModuleInfoFromAddr(uint64_t addr, int n, ModuleInfo* r) {
	PRINT_NAME();

	LOGF("\taddr = %016" PRIx64 "\n"
	     "\tn = %d\n",
	     addr, n);

	EXIT_NOT_IMPLEMENTED(n != 2);
	EXIT_NOT_IMPLEMENTED(r == nullptr);

	auto* rt = Common::Singleton<Loader::RuntimeLinker>::Instance();

	auto* p = rt->FindProgramByAddr(addr);

	if (p == nullptr) {
		LOGF("\thandle: not found\n");
		r->handle = 0;
		return -1;
	}

	r->handle = p->unique_id;

	LOGF("\thandle: %d\n", r->handle);

	return 0;
}

static void KYTY_SYSV_ABI KernelDebugRaiseExceptionOnReleaseMode(int /*c1*/, int /*c2*/) {
	PRINT_NAME();
}

static int KYTY_SYSV_ABI KernelIpmiManagerCall(uint32_t command, int32_t client_id, int32_t* result,
                                               void* args, size_t args_size, uint64_t magic) {
	PRINT_NAME();
	int transport_status = 0;
	if (IpmiManager::TryCall(command, client_id, result, args, args_size, magic, &transport_status))
		return transport_status;

	if (!Memory::CanWriteGuest(result, sizeof(*result))) {
		*Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
		return -1;
	}

	if (command == 0x201 &&
	    std::getenv("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_IPMI_RECEIVE_ABI2") != nullptr) {
		Memory::VirtualQueryInfo region {};
		const uint64_t           address = reinterpret_cast<uint64_t>(args);
		const bool readable = args_size == 0x20 && address != 0 &&
		                      Memory::KernelVirtualQuery(args, 0, &region, sizeof(region)) == 0 &&
		                      region.is_committed && region.start <= address &&
		                      region.end >= address + 0x20 && (region.protection & 1u) != 0;
		uint64_t   descriptor[4] {};
		if (readable) {
			std::memcpy(descriptor, args, sizeof(descriptor));
		}
		LOGF("AUDIO_IPMI_RECEIVE_PACKET_ABI"
		     " command=0x201 server_id=%d argument_size=%zu"
		     " descriptor_readable=%d result_ptr=%p"
		     " descriptor=%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64 "\n",
		     client_id, args_size, readable, static_cast<void*>(result), descriptor[0],
		     descriptor[1], descriptor[2], descriptor[3]);
	}
	const bool register_imported_server =
	    command == 0 && std::getenv("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_IPMI_REGISTRY") != nullptr;
	if (command == 0 && (register_imported_server ||
	                     std::getenv("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_IPMI_AUDIT") != nullptr)) {
		auto readable = [](uint64_t address, size_t bytes) {
			Memory::VirtualQueryInfo region {};
			return address != 0 && bytes <= UINT64_MAX - address &&
			       Memory::KernelVirtualQuery(reinterpret_cast<const void*>(address), 0, &region,
			                                  sizeof(region)) == 0 &&
			       region.is_committed && region.start <= address &&
			       region.end >= address + bytes && (region.protection & 1u) != 0;
		};
		if (args_size == sizeof(uint64_t) * 3 &&
		    readable(reinterpret_cast<uint64_t>(args), args_size)) {
			uint64_t descriptor[3] {};
			std::memcpy(descriptor, args, sizeof(descriptor));
			std::string original_name;
			bool        terminated = false;
			for (size_t i = 0; i < 128; ++i) {
				if (!readable(descriptor[1] + i, 1)) break;
				char value = 0;
				std::memcpy(&value, reinterpret_cast<const void*>(descriptor[1] + i), 1);
				if (value == '\0') {
					terminated = true;
					break;
				}
				if (value < 0x21 || value > 0x7e) break;
				original_name.push_back(value);
			}
			LOGF("FIRST_FRAME_AUDIT AUDIO_IPMI_SERVER_REGISTRATION_ABI"
			     " command=%u requested_client=%d output=0x%016" PRIx64 " descriptor=%016" PRIx64
			     ",%016" PRIx64 ",%016" PRIx64 " name=%s terminated=%u owner_pid=%d\n",
			     command, client_id, reinterpret_cast<uint64_t>(result), descriptor[0],
			     descriptor[1], descriptor[2], original_name.c_str(),
			     static_cast<unsigned>(terminated), Process::GetPid());
			if (register_imported_server) {
				if (!terminated || original_name.empty() ||
				    !readable(descriptor[0], sizeof(uint64_t)) ||
				    !readable(descriptor[2], sizeof(uint64_t))) {
					return -22;
				}
				uint32_t  id = 0;
				const int rc = NativeKernelBridge::RegisterImportedGuestIpmiServer(
				    original_name.c_str(), descriptor[0], descriptor[2],
				    static_cast<uint32_t>(Process::GetPid()), &id);
				if (rc != 0) {
					return rc;
				}
				*result = static_cast<int32_t>(id);
				return 0;
			}
		}
		if (register_imported_server) return -22;
	}

	if (command == 0x10 && std::getenv("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_IPMI_AUDIT") != nullptr) {
		Memory::VirtualQueryInfo region {};
		const auto               address = reinterpret_cast<uint64_t>(args);
		if (address != 0 && args_size >= sizeof(uint64_t) * 3 &&
		    args_size <= sizeof(uint64_t) * 8 &&
		    Memory::KernelVirtualQuery(args, 0, &region, sizeof(region)) == 0 &&
		    region.is_committed && region.start <= address && region.end >= address + args_size &&
		    (region.protection & 1u) != 0) {
			uint64_t original[8] {};
			std::memcpy(original, args, args_size);
			LOGF("FIRST_FRAME_AUDIT AUDIO_IPMI_RECEIVE_ABI"
			     " op=0x10 subop=0x%08x size=%zu"
			     " descriptor=%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64
			     ",%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64 ",%016" PRIx64 "\n",
			     static_cast<uint32_t>(client_id), args_size, original[0], original[1], original[2],
			     original[3], original[4], original[5], original[6], original[7]);
		}
	}

	if (command == 0x10 && client_id == 0x1f00 &&
	    std::getenv("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_IPMI_REGISTRY") != nullptr &&
	    std::getenv("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_IPMI_RECEIVE_WAIT") != nullptr) {
		Memory::VirtualQueryInfo region {};
		const auto               address = reinterpret_cast<uint64_t>(args);
		if (address == 0 || args_size != 0x40 ||
		    Memory::KernelVirtualQuery(args, 0, &region, sizeof(region)) != 0 ||
		    !region.is_committed || region.start > address || region.end < address + args_size ||
		    (region.protection & 1u) == 0) {
			return -22;
		}
		uint64_t receive[8] {};
		std::memcpy(receive, args, sizeof(receive));
		if (receive[0] == 0 || receive[0] > UINT32_MAX || receive[2] == 0 || receive[2] > 0x10000) {
			return -22;
		}
		for (int i = 3; i < 8; ++i) {
			if (receive[i] != 0) return -22;
		}
		Memory::VirtualQueryInfo buffer {};
		if (receive[1] == 0 || receive[2] > UINT64_MAX - receive[1] ||
		    Memory::KernelVirtualQuery(reinterpret_cast<const void*>(receive[1]), 0, &buffer,
		                               sizeof(buffer)) != 0 ||
		    !buffer.is_committed || buffer.start > receive[1] ||
		    buffer.end < receive[1] + receive[2] || (buffer.protection & 2u) == 0) {
			return -22;
		}
		const int kernel_result = NativeKernelBridge::WaitForImportedGuestIpmiServerRequest(
		    static_cast<uint32_t>(receive[0]), receive[2]);
		if (kernel_result == 0 &&
		    std::getenv("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_IPMI_TRACE_RESULT") != nullptr) {
			Memory::VirtualQueryInfo output {};
			const uint64_t           address = reinterpret_cast<uint64_t>(result);
			if (Memory::KernelVirtualQuery(result, 0, &output, sizeof(output)) != 0 ||
			    !output.is_committed || output.start > address ||
			    output.end < address + sizeof(*result) || (output.protection & 2u) == 0) {
				return -14;
			}
			Memory::InvalidateMemory(address, sizeof(*result));
			*result = 0;
		}
		return kernel_result;
	}
}
static int32_t KYTY_SYSV_ABI KernelDebugRaiseException(int32_t code, const void* context) {
	PRINT_NAME();
	if (std::getenv("KYTY_DIAGNOSTIC_SHELLUI_EXCEPTION_ORIGIN") != nullptr) {
		const auto caller  = reinterpret_cast<uint64_t>(__builtin_return_address(0));
		auto*      linker  = Common::Singleton<Loader::RuntimeLinker>::Instance();
		auto*      program = linker->FindProgramByAddr(caller);
		const auto module  = program == nullptr
		                         ? std::string("unknown")
		                         : Common::PathToString(program->file_name.filename());
		const auto rva     = program == nullptr ? 0 : caller - program->base_vaddr;
		LOGF("SHELLUI_DEBUG_RAISE guest_pid=%d guest_tid=%d code=0x%08x context_null=%u"
		     " caller_module=%s caller_rva=0x%016" PRIx64 " provider=hle_libkernel result=%s\n",
		     Process::GetPid(), PthreadGetthreadid(), static_cast<uint32_t>(code),
		     context == nullptr ? 1u : 0u, module.c_str(), rva,
		     context == nullptr ? "operation3_unsupported" : "invalid_context");
	}
	return context == nullptr ? KERNEL_ERROR_ENOSYS : KERNEL_ERROR_EINVAL;
}

static void KYTY_SYSV_ABI exit(int code) {
	PRINT_NAME();
	const int guest_pid = Process::GetPid();
	if (std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD") != nullptr &&
	    Process::IsTrackedRforkChild(guest_pid) && PthreadSelfOrNull() != nullptr) {
		LOGF("SYSCORE_GUEST_CHILD_KERNEL_EXIT"
		     " guest_pid=%d exit_code=%d"
		     " terminating_only_child_thread"
		     " parent_and_other_guest_threads_preserved\n",
		     guest_pid, code);
		PthreadExit(reinterpret_cast<void*>(static_cast<uintptr_t>(static_cast<uint32_t>(code))));
		EXIT("guest child kernel exit unexpectedly returned\n");
	}
	if (Process::IsExecChild()) {
		Process::RecordExecChildExitStatus((static_cast<uint32_t>(code) & 0xffu) << 8u);
	}
	::exit(code);
}

static KYTY_SYSV_ABI MallocReplace* KernelGetSanitizerMallocReplaceExternal() {
	PRINT_NAME();

	static MallocReplace ret;

	return &ret;
}

static KYTY_SYSV_ABI NewReplace* KernelGetSanitizerNewReplaceExternal() {
	PRINT_NAME();

	static NewReplace ret;

	return &ret;
}

static KYTY_SYSV_ABI int elf_phdr_match_addr(ModuleInfo* m, uint64_t dtor_vaddr) {
	PRINT_NAME();

	EXIT_NOT_IMPLEMENTED(m == nullptr);

	auto* rt     = Common::Singleton<Loader::RuntimeLinker>::Instance();
	auto* p      = rt->FindProgramByAddr(dtor_vaddr);
	int   result = (p != nullptr && p->unique_id == m->handle) ? 1 : 0;

	LOGF("\thandle     = %" PRId32 "\n"
	     "\tdtor_vaddr = %016" PRIx64 "\n"
	     "\tmatch      = %s\n",
	     m->handle, dtor_vaddr, result == 1 ? "true" : "false");

	return result;
}

int KYTY_SYSV_ABI KernelUuidCreate(uint32_t* uuid) {
	PRINT_NAME();

	if (uuid == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	static thread_local std::mt19937 rng(std::random_device {}());
	uuid[0] = rng();
	uuid[1] = rng();
	uuid[2] = rng();
	uuid[3] = rng();

	return OK;
}

static KYTY_SYSV_ABI int KernelGetOpenPsId(void* open_ps_id) {
	PRINT_NAME();

	if (open_ps_id == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}

	static constexpr uint8_t id[16] = {
	    0x4b, 0x79, 0x74, 0x79, 0x4f, 0x70, 0x65, 0x6e,
	    0x50, 0x73, 0x49, 0x64, 0x00, 0x00, 0x00, 0x01,
	};

	std::memcpy(open_ps_id, id, sizeof(id));

	return OK;
}

// libkernel reads machdep.openpsid_for_sys with a raw sysctl and hands back its result unconverted,
// so the null case is the plain errno
static KYTY_SYSV_ABI int KernelGetOpenPsIdForSystem(void* open_ps_id) {
	PRINT_NAME();

	if (open_ps_id == nullptr) {
		return Posix::POSIX_EINVAL;
	}

	static constexpr uint8_t id[16] = {
	    0x4b, 0x79, 0x74, 0x79, 0x4f, 0x70, 0x65, 0x6e,
	    0x50, 0x73, 0x49, 0x64, 0x00, 0x00, 0x00, 0x02,
	};

	std::memcpy(open_ps_id, id, sizeof(id));

	return OK;
}
static KYTY_SYSV_ABI void pthread_cxa_finalize(void* /*p*/) {
	PRINT_NAME();
}

void KYTY_SYSV_ABI KernelSetThreadAtexitCount(get_thread_atexit_count_func_t func) {
	PRINT_NAME();

	EXIT_NOT_IMPLEMENTED(g_get_thread_atexit_count_func != nullptr);

	g_get_thread_atexit_count_func = func;
}

void KYTY_SYSV_ABI KernelSetThreadAtexitReport(thread_atexit_report_func_t func) {
	PRINT_NAME();

	EXIT_NOT_IMPLEMENTED(g_thread_atexit_report_func != nullptr);

	g_thread_atexit_report_func = func;
}

int KYTY_SYSV_ABI KernelRtldThreadAtexitIncrement(uint64_t* /*c*/) {
	PRINT_NAME();

	//__sync_fetch_and_add(c, 1);

	return 0;
}

int KYTY_SYSV_ABI KernelRtldThreadAtexitDecrement(uint64_t* /*c*/) {
	PRINT_NAME();

	//__sync_fetch_and_sub(c, 1);

	return 0;
}

static uint64_t KYTY_SYSV_ABI KernelGetAvailableCpumask() {
	PRINT_NAME();

	return 0x1fff;
}

static KYTY_SYSV_ABI int KernelGetCurrentCpu() {
	PRINT_NAME();

	return 0;
}

int KYTY_SYSV_ABI clock_gettime(int clock_id, LibKernel::KernelTimespec* time) {
	PRINT_NAME();

	return POSIX_CALL(LibKernel::KernelClockGettime(clock_id, time));
}

int KYTY_SYSV_ABI clock_getres(int clock_id, LibKernel::KernelTimespec* res) {
	PRINT_NAME();

	return POSIX_CALL(LibKernel::KernelClockGetres(clock_id, res));
}

void KYTY_SYSV_ABI KernelSetGPO(uint32_t bits) {
	g_gpo_state_bits.store(bits, std::memory_order_relaxed);

	static std::atomic_uint32_t call_count {0};
	auto                        count = call_count.fetch_add(1, std::memory_order_relaxed);
	if (count < 16 || (count % 1024) == 0) {
		PRINT_NAME();
		LOGF("\tcall = %u, bits = 0x%08" PRIx32 "\n", count + 1, bits);
	}
}

uint64_t KYTY_SYSV_ABI KernelGetGPI() {
	auto bits = g_gpo_state_bits.load(std::memory_order_relaxed);

	static std::atomic_uint32_t call_count {0};
	auto                        count = call_count.fetch_add(1, std::memory_order_relaxed);
	if (count < 16 || (count % 1024) == 0) {
		PRINT_NAME();
		LOGF("\tcall = %u, return = 0x%016" PRIx64 "\n", count + 1, bits);
	}

	return bits;
}

} // namespace LibKernel

namespace LibKernelWriteThrottling {

LIB_VERSION("libkernel_write_throttling", 1, "libkernel", 1, 1);

static uint64_t KYTY_SYSV_ABI WriteThrottlingStub() {
	return 0;
}

LIB_DEFINE(InitLibKernelWriteThrottling) {
	LIB_FUNC("YFC3dBBipj8", WriteThrottlingStub);
}

} // namespace LibKernelWriteThrottling

namespace Posix {

LIB_VERSION("Posix", 1, "libkernel", 1, 1);

int KYTY_SYSV_ABI getpagesize() {
	PRINT_NAME();

	return 0x4000;
}

int KYTY_SYSV_ABI clock_gettime(int clock_id, LibKernel::KernelTimespec* time) {
	PRINT_NAME();

	return POSIX_CALL(LibKernel::KernelClockGettime(clock_id, time));
}

int KYTY_SYSV_ABI clock_getres(int clock_id, LibKernel::KernelTimespec* res) {
	PRINT_NAME();

	return POSIX_CALL(LibKernel::KernelClockGetres(clock_id, res));
}

struct KernelTimezone {
	int32_t tz_minuteswest;
	int32_t tz_dsttime;
};

int KYTY_SYSV_ABI gettimeofday(LibKernel::KernelTimeval* time, KernelTimezone* timezone) {
	PRINT_NAME();

	if (time != nullptr) {
		int result = LibKernel::KernelGettimeofday(time);
		if (result != OK) {
			*GetErrorAddr() = LibKernel::KernelToPosix(result);
			return -1;
		}
	}

	if (timezone != nullptr) {
		timezone->tz_minuteswest = 0;
		timezone->tz_dsttime     = 0;
	}

	return 0;
}

struct KernelRusage {
	LibKernel::KernelTimeval ru_utime;
	LibKernel::KernelTimeval ru_stime;
	int64_t                  ru_counters[14];
};
int KYTY_SYSV_ABI wait4(int pid, int32_t* status, int options, KernelRusage* usage) {
	if (usage != nullptr) {
		*GetErrorAddr() = POSIX_ENOSYS;
		return -1;
	}
	if (status != nullptr && !LibKernel::Memory::CanWriteGuest(status, sizeof(*status))) {
		*GetErrorAddr() = POSIX_EFAULT;
		return -1;
	}
	const int child =
	    LibKernel::Process::WaitForChild(pid, reinterpret_cast<uint32_t*>(status), options, true);
	if (child < 0) {
		*GetErrorAddr() = LibKernel::KernelToPosix(child);
		return -1;
	}
	return child;
}
int KYTY_SYSV_ABI nanosleep(const LibKernel::KernelTimespec* rqtp,
                            LibKernel::KernelTimespec*       rmtp) {
	PRINT_NAME();

	return POSIX_CALL(LibKernel::KernelNanosleep(rqtp, rmtp));
}

int KYTY_SYSV_ABI stat(const char* path, LibKernel::FileSystem::FileStat* sb) {
	PRINT_NAME();

	return POSIX_CALL(LibKernel::FileSystem::KernelStat(path, sb));
}

int KYTY_SYSV_ABI mkdir(const char* path, uint16_t mode) {
	PRINT_NAME();

	return POSIX_CALL(LibKernel::FileSystem::KernelMkdir(path, mode));
}

int KYTY_SYSV_ABI rmdir(const char* path) {
	PRINT_NAME();

	return POSIX_CALL(LibKernel::FileSystem::KernelRmdir(path));
}
int KYTY_SYSV_ABI unlink(const char* path) {
	PRINT_NAME();

	return POSIX_CALL(LibKernel::FileSystem::KernelUnlink(path));
}
int64_t KYTY_SYSV_ABI lseek(int d, int64_t offset, int whence) {
	PRINT_NAME();

	return POSIX_N_CALL(LibKernel::FileSystem::KernelLseek(d, offset, whence));
}

int64_t KYTY_SYSV_ABI pread(int d, void* buf, size_t nbytes, int64_t offset) {
	PRINT_NAME();

	return POSIX_N_CALL(LibKernel::FileSystem::KernelPread(d, buf, nbytes, offset));
}

int64_t KYTY_SYSV_ABI pwrite(int d, const void* buf, size_t nbytes, int64_t offset) {
	PRINT_NAME();

	return POSIX_N_CALL(LibKernel::FileSystem::KernelPwrite(d, buf, nbytes, offset));
}

int KYTY_SYSV_ABI flock(int d, int operation) {
	PRINT_NAME();

	constexpr int lock_sh = 0x01;
	constexpr int lock_ex = 0x02;
	constexpr int lock_nb = 0x04;
	constexpr int lock_un = 0x08;

	auto lock_mode = operation & ~(lock_nb);
	if (lock_mode != lock_sh && lock_mode != lock_ex && lock_mode != lock_un) {
		*GetErrorAddr() = POSIX_EINVAL;
		return -1;
	}

	LibKernel::FileSystem::FileStat sb {};
	auto                            result = LibKernel::FileSystem::KernelFstat(d, &sb);
	if (result != OK) {
		*GetErrorAddr() = LibKernel::KernelToPosix(result);
		return -1;
	}

	return 0;
}

int64_t KYTY_SYSV_ABI fstat(int d, LibKernel::FileSystem::FileStat* sb) {
	PRINT_NAME();

	return POSIX_N_CALL(LibKernel::FileSystem::KernelFstat(d, sb));
}

int KYTY_SYSV_ABI ftruncate(int d, int64_t length) {
	PRINT_NAME();

	return POSIX_CALL(LibKernel::FileSystem::KernelFtruncate(d, length));
}

int KYTY_SYSV_ABI socket(int family, int type, int protocol) {
	PRINT_NAME();
	return Network::Net::Socket(family, type, protocol);
}

int KYTY_SYSV_ABI bind(int s, const void* addr, uint32_t addrlen) {
	PRINT_NAME();
	return Network::Net::Bind(s, addr, addrlen);
}

int KYTY_SYSV_ABI connect(int s, const void* addr, uint32_t addrlen) {
	PRINT_NAME();
	return Network::Net::Connect(s, addr, addrlen);
}

int KYTY_SYSV_ABI listen(int s, int backlog) {
	PRINT_NAME();
	return Network::Net::Listen(s, backlog);
}

int KYTY_SYSV_ABI accept(int s, void* addr, uint32_t* addrlen) {
	PRINT_NAME();
	return Network::Net::Accept(s, addr, addrlen);
}

int KYTY_SYSV_ABI getsockname(int s, void* addr, uint32_t* addrlen) {
	PRINT_NAME();
	return Network::Net::Getsockname(s, addr, addrlen);
}

int KYTY_SYSV_ABI getsockopt(int s, int level, int optname, void* optval, uint32_t* optlen) {
	PRINT_NAME();
	return Network::Net::Getsockopt(s, level, optname, optval, optlen);
}

int KYTY_SYSV_ABI setsockopt(int s, int level, int optname, const void* optval, uint32_t optlen) {
	PRINT_NAME();
	return Network::Net::Setsockopt(s, level, optname, optval, optlen);
}

int KYTY_SYSV_ABI select(int nfds, void* readfds, void* writefds, void* exceptfds,
                         const void* timeout) {
	PRINT_NAME();
	return Network::Net::Select(nfds, readfds, writefds, exceptfds, timeout);
}

int64_t KYTY_SYSV_ABI send(int s, const void* buf, uint64_t len, int flags) {
	PRINT_NAME();
	return Network::Net::Send(s, buf, len, flags);
}

int64_t KYTY_SYSV_ABI sendto(int s, const void* buf, uint64_t len, int flags, const void* addr,
                             uint32_t addrlen) {
	PRINT_NAME();
	return Network::Net::Sendto(s, buf, len, flags, addr, addrlen);
}

int64_t KYTY_SYSV_ABI recv(int s, void* buf, uint64_t len, int flags) {
	PRINT_NAME();
	return Network::Net::Recv(s, buf, len, flags);
}

int64_t KYTY_SYSV_ABI recvfrom(int s, void* buf, uint64_t len, int flags, void* addr,
                               uint32_t* addrlen) {
	PRINT_NAME();
	return Network::Net::Recvfrom(s, buf, len, flags, addr, addrlen);
}

int KYTY_SYSV_ABI inet_pton(int af, const char* src, void* dst) {
	PRINT_NAME();

	const int result = Network::Net::NetInetPton(af, src, dst);
	if (result < 0) {
		*GetErrorAddr() = Network::NetToPosix(result);
		return -1;
	}
	return result;
}

const char* KYTY_SYSV_ABI inet_ntop(int af, const void* src, char* dst, uint32_t size) {
	PRINT_NAME();

	const char* result = Network::Net::NetInetNtop(af, src, dst, size);
	if (result == nullptr) {
		*GetErrorAddr() = (af == 2 ? POSIX_ENOSPC : POSIX_EAFNOSUPPORT);
	}

	return result;
}

uint64_t KYTY_SYSV_ABI cfwBSQyr5Ys(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5,
                                   uint64_t a6) {
	PRINT_NAME();

	LOGF("\t return = 0x%016" PRIx64 "\n"
	     "\t a1     = 0x%016" PRIx64 "\n"
	     "\t a2     = 0x%016" PRIx64 "\n"
	     "\t a3     = 0x%016" PRIx64 "\n"
	     "\t a4     = 0x%016" PRIx64 "\n"
	     "\t a5     = 0x%016" PRIx64 "\n"
	     "\t a6     = 0x%016" PRIx64 "\n"
	     "\t result = 0\n",
	     reinterpret_cast<uint64_t>(__builtin_return_address(0)), a1, a2, a3, a4, a5, a6);

	return 0;
}

static void LogExperimentalSyncOnAddress(std::atomic_bool& logged, const char* function_name) {
	if (!logged.exchange(true, std::memory_order_relaxed)) {
		::printf("WARNING: %s is experimental\n", function_name);
		LOGF("WARNING: %s is experimental\n", function_name);
	}
}

int KYTY_SYSV_ABI KernelSyncOnAddressWait(volatile uint32_t* address, uint32_t expected,
                                          const uint32_t* timeout_micros) {
	return LibKernel::SyncOnAddress::Wait32(address, expected, timeout_micros,
	                                        LibKernel::KernelDispatchPendingSignalForCurrentThread);
}

int KYTY_SYSV_ABI KernelSyncOnAddressWait32(volatile uint32_t* address, uint32_t expected,
                                            const uint32_t* timeout_micros) {
	static std::atomic_bool logged {false};
	LogExperimentalSyncOnAddress(logged, "sceKernelSyncOnAddressWait32");
	return LibKernel::SyncOnAddress::Wait32(address, expected, timeout_micros,
	                                        LibKernel::KernelDispatchPendingSignalForCurrentThread);
}

int KYTY_SYSV_ABI KernelSyncOnAddressWait64(volatile uint64_t* address, uint64_t expected,
                                            const uint32_t* timeout_micros) {
	static std::atomic_bool logged {false};
	LogExperimentalSyncOnAddress(logged, "sceKernelSyncOnAddressWait64");
	return LibKernel::SyncOnAddress::Wait64(address, expected, timeout_micros,
	                                        LibKernel::KernelDispatchPendingSignalForCurrentThread);
}

int KYTY_SYSV_ABI KernelSyncOnAddressWake(volatile void* address, int32_t count) {
	return LibKernel::SyncOnAddress::Wake(address, count);
}

int KYTY_SYSV_ABI UmtxOp(volatile void* address, int operation, uint64_t value,
                           void* uaddr, const void* timeout) {
	constexpr int UMTX_OP_WAIT = 2;
	constexpr int UMTX_OP_WAKE = 3;

	EXIT_NOT_IMPLEMENTED(uaddr != nullptr);

	switch (operation) {
		case UMTX_OP_WAIT:
			if (timeout != nullptr) {
				LibKernel::KernelTimespec duration {};
				std::memcpy(&duration, timeout, sizeof(duration));
				if (duration.tv_sec < 0 || duration.tv_nsec < 0 || duration.tv_nsec >= 1000000000) {
					*GetErrorAddr() = POSIX_EINVAL;
					return -1;
				}
				const auto max_ns = std::chrono::nanoseconds::max().count();
				const auto timeout_ns = duration.tv_sec > (max_ns - duration.tv_nsec) / 1000000000
				                            ? max_ns
				                            : duration.tv_sec * 1000000000 + duration.tv_nsec;
				return POSIX_CALL(LibKernel::SyncOnAddress::Wait64(
				    static_cast<volatile uint64_t*>(address), value, std::chrono::nanoseconds(timeout_ns),
				    LibKernel::KernelDispatchPendingSignalForCurrentThread));
			}
			return POSIX_CALL(LibKernel::SyncOnAddress::Wait64(
			    static_cast<volatile uint64_t*>(address), value, nullptr,
			    LibKernel::KernelDispatchPendingSignalForCurrentThread));
		case UMTX_OP_WAKE:
			return POSIX_CALL(LibKernel::SyncOnAddress::Wake(address, static_cast<int32_t>(value)));
		default: EXIT("Unsupported _umtx_op operation: %d\n", operation);
	}
}

LIB_DEFINE(InitLibKernel_1_Posix) {
	LIB_FUNC("k+AXqu2-eBc", getpagesize);
	LIB_FUNC("lLMT9vJAck0", clock_gettime);
	LIB_FUNC("smIj7eqzZE8", clock_getres);
	LIB_FUNC("n88vx3C5nW8", gettimeofday);
	LIB_FUNC("NhpspxdjEKU", nanosleep);
	LIB_FUNC("yS8U2TGCe1A", nanosleep);
	LIB_FUNC("E6ao34wPw+U", stat);
	LIB_FUNC("JGMio+21L4c", mkdir);
	LIB_FUNC("ih4CD9-gghM", Posix::ftruncate);
	LIB_FUNC("pDuPEf3m4fI", Posix::sem_init);
	LIB_FUNC("cDW233RAwWo", Posix::sem_destroy);
	LIB_FUNC("YCV5dGGBcCo", Posix::sem_wait);
	LIB_FUNC("WBWzsRifCEA", Posix::sem_trywait);
	LIB_FUNC("4SbrhCozqQU", Posix::sem_reltimedwait_np);
	LIB_FUNC("w5IHyvahg-o", Posix::sem_timedwait);
	LIB_FUNC("IKP8typ0QUk", Posix::sem_post);
	LIB_FUNC("Bq+LRV-N6Hk", Posix::sem_getvalue);

	LIB_FUNC("OxhIB8LB-PQ", Posix::pthread_create);
	LIB_FUNC("Jmi+9w9u0E4", Posix::pthread_create_name_np);
	LIB_FUNC("+U1R4WtXvoc", Posix::pthread_detach);
	LIB_FUNC("FJrT5LuUBAU", Posix::pthread_exit);
	LIB_FUNC("EotR8a3ASf4", Posix::pthread_self);
	LIB_FUNC("9vyP6Z7bqzc", Posix::pthread_rename_np);
	LIB_FUNC("lZzFeSxPl08", Posix::pthread_setcancelstate);
	LIB_FUNC("a2P9wYGeZvc", Posix::pthread_setprio);
	LIB_FUNC("FIs3-UQT9sg", Posix::pthread_getschedparam);
	LIB_FUNC("P41kTWUS3EI", Posix::pthread_getschedparam);
	LIB_FUNC("Xs9hdiD7sAA", Posix::pthread_setschedparam);
	LIB_FUNC("oIRFTjoILbg", Posix::pthread_setschedparam);
	LIB_FUNC("B5GmVDKwpn0", Posix::pthread_yield);
	LIB_FUNC("h9CcP3J0oVM", Posix::pthread_join);
	LIB_FUNC("wtkt-teR1so", Posix::pthread_attr_init);
	LIB_FUNC("zHchY8ft5pk", Posix::pthread_attr_destroy);
	LIB_FUNC("vQm4fDEsWi8", Posix::pthread_attr_getstack);
	LIB_FUNC("-SrbXpGR1f0", Posix::pthread_attr_setstack);
	LIB_FUNC("2Q0z6rnBrTE", Posix::pthread_attr_setstacksize);
	LIB_FUNC("Ucsu-OK+els", Posix::pthread_attr_get_np);
	LIB_FUNC("RtLRV-pBTTY", Posix::pthread_attr_getschedpolicy);
	LIB_FUNC("JarMIy8kKEY", Posix::pthread_attr_setschedpolicy);
	LIB_FUNC("E+tyo3lp5Lw", Posix::pthread_attr_setdetachstate);
	LIB_FUNC("euKRgm0Vn2M", Posix::pthread_attr_setschedparam);
	LIB_FUNC("7ZlAakEf0Qg", Posix::pthread_attr_setinheritsched);
	LIB_FUNC("0qOtCR-ZHck", Posix::pthread_attr_getstacksize);
	LIB_FUNC("VUT1ZSrHT0I", Posix::pthread_attr_getdetachstate);
	LIB_FUNC("JKyG3SWyA10", Posix::pthread_attr_setguardsize);
	LIB_FUNC("JNkVVsVDmOk", Posix::pthread_attr_getguardsize);
	LIB_FUNC("qlk9pSLsUmM", Posix::pthread_attr_getschedparam);
	LIB_FUNC("FXPWHNk8Of0", Posix::pthread_attr_getschedparam);
	LIB_FUNC("7Xl257M4VNI", LibKernel::PthreadEqual);
	LIB_FUNC("7H0iTOciTLo", Posix::pthread_mutex_lock);
	LIB_FUNC("K-jXhbt2gn4", Posix::pthread_mutex_trylock);
	LIB_FUNC("2Z+PpY6CaJg", Posix::pthread_mutex_unlock);
	LIB_FUNC("ttHNfU+qDBU", Posix::pthread_mutex_init);
	LIB_FUNC("dQHWEsJtoE4", Posix::pthread_mutexattr_init);
	LIB_FUNC("mDmgMOGVUqg", Posix::pthread_mutexattr_settype);
	LIB_FUNC("5txKfcMUAok", Posix::pthread_mutexattr_setprotocol);
	LIB_FUNC("HF7lK46xzjY", Posix::pthread_mutexattr_destroy);
	LIB_FUNC("ltCfaGr2JGE", Posix::pthread_mutex_destroy);
	LIB_FUNC("mkx2fVhNMsg", Posix::pthread_cond_broadcast);
	LIB_FUNC("2MOy+rUfuhQ", Posix::pthread_cond_signal);
	LIB_FUNC("0TyVk4MSLt0", Posix::pthread_cond_init);
	LIB_FUNC("Op8TBGY5KHg", Posix::pthread_cond_wait);
	LIB_FUNC("Z4QosVuAsA0", Posix::pthread_once);
	LIB_FUNC("1471ajPzxh0", Posix::pthread_rwlock_destroy);
	LIB_FUNC("ytQULN-nhL4", Posix::pthread_rwlock_init);
	LIB_FUNC("sIlRvQqsN2Y", Posix::pthread_rwlock_wrlock);
	LIB_FUNC("SFxTMOfuCkE", LibKernel::PthreadRwlockTryrdlock);
	LIB_FUNC("XhWHn6P5R7U", LibKernel::PthreadRwlockTrywrlock);
	LIB_FUNC("mqULNdimTn0", Posix::pthread_key_create);
	LIB_FUNC("6BpEZuDT7YI", Posix::pthread_key_delete);
	LIB_FUNC("WrOLvHU0yQM", Posix::pthread_setspecific);
	LIB_FUNC("0-KXaS70xy4", Posix::pthread_getspecific);
	LIB_FUNC("-quPa4SEJUw", Posix::pthread_getstack);
	LIB_FUNC("YQOfxL4QfeU", LibKernel::Memory::KernelMprotect);
	LIB_FUNC("UqDGjXA5yUM", LibKernel::Memory::KernelMunmap);
	LIB_FUNC("AqBioC2vF3I", LibKernel::read);
	LIB_FUNC("TU-d9PfIHPM", Posix::socket);
	LIB_FUNC("KuOmgKoqCdY", Posix::bind);
	LIB_FUNC("XVL8So3QJUk", Posix::connect);
	LIB_FUNC("pxnCmagrtao", Posix::listen);
	LIB_FUNC("3e+4Iv7IJ8U", Posix::accept);
	LIB_FUNC("RenI1lL1WFk", Posix::getsockname);
	LIB_FUNC("6O8EwYOgH9Y", Posix::getsockopt);
	LIB_FUNC("fFxGkxF2bVo", Posix::setsockopt);
	LIB_FUNC("T8fER+tIGgk", Posix::select);
	LIB_FUNC("fZOeZIOEmLw", Posix::send);
	LIB_FUNC("oBr313PppNE", Posix::sendto);
	LIB_FUNC("Ez8xjo9UF4E", Posix::recv);
	LIB_FUNC("lUk6wrGXyMw", Posix::recvfrom);
	LIB_FUNC("4n51s0zEf0c", Posix::inet_pton);
	LIB_FUNC("5jRCs2axtr4", Posix::inet_ntop);
	LIB_FUNC("cfwBSQyr5Ys", cfwBSQyr5Ys);
}

} // namespace Posix

namespace Coredump {

LIB_VERSION("Coredump", 1, "Coredump", 1, 1);

static uint64_t g_coredump_handler         = 0;
static uint64_t g_coredump_handler_context = 0;

int KYTY_SYSV_ABI sceCoredumpRegisterCoredumpHandler(uint64_t handler, size_t stack_size,
                                                     uint64_t context) {
	PRINT_NAME();

	g_coredump_handler         = handler;
	g_coredump_handler_context = context;

	LOGF("\t handler = 0x%016" PRIx64 "\n"
	     "\t stack   = 0x%016" PRIx64 "\n"
	     "\t context = 0x%016" PRIx64 "\n",
	     handler, static_cast<uint64_t>(stack_size), context);

	return OK;
}

int KYTY_SYSV_ABI sceCoredumpUnregisterCoredumpHandler() {
	PRINT_NAME();

	g_coredump_handler         = 0;
	g_coredump_handler_context = 0;

	return OK;
}

} // namespace Coredump

namespace Fiber {

LIB_VERSION("Fiber", 1, "Fiber", 1, 1);

constexpr int32_t FIBER_ERROR_NULL       = -2141650943; /* 0x80590001 */
constexpr int32_t FIBER_ERROR_ALIGNMENT  = -2141650942; /* 0x80590002 */
constexpr int32_t FIBER_ERROR_RANGE      = -2141650941; /* 0x80590003 */
constexpr int32_t FIBER_ERROR_INVALID    = -2141650940; /* 0x80590004 */
constexpr int32_t FIBER_ERROR_PERMISSION = -2141650939; /* 0x80590005 */
constexpr int32_t FIBER_ERROR_STATE      = -2141650938; /* 0x80590006 */

constexpr uint32_t FIBER_MAGIC_START       = 0xdef1649c;
constexpr uint32_t FIBER_MAGIC_END         = 0xb37592a0;
constexpr uint32_t FIBER_OPT_MAGIC         = 0xbb40e64d;
constexpr uint64_t FIBER_STACK_MAGIC       = 0x7149f2ca7149f2ca;
constexpr uint64_t FIBER_CONTEXT_MIN_SIZE  = 512;
constexpr size_t   FIBER_MAX_NAME_LENGTH   = 31;
constexpr uint32_t FIBER_STATE_RUNNING     = 1;
constexpr uint32_t FIBER_STATE_IDLE        = 2;
constexpr uint32_t FIBER_STATE_TERMINATED  = 3;
constexpr uint32_t FIBER_FLAG_SET_FPU_REGS = 0x100;

using FiberEntry = KYTY_SYSV_ABI void (*)(uint64_t arg_on_initialize, uint64_t arg_on_run);

struct FiberOptParam {
	uint32_t magic;
};

struct FiberCpuContext {
	uint64_t rbx;
	uint64_t rbp;
	uint64_t rdi;
	uint64_t rsi;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;
	uint64_t rsp;
	uint64_t rip;
};

static_assert(sizeof(FiberCpuContext) == 80);

struct FiberObject {
	uint32_t        magic_start;
	uint32_t        state;
	FiberEntry      entry;
	uint64_t        arg_on_initialize;
	void*           addr_context;
	uint64_t        size_context;
	char            name[FIBER_MAX_NAME_LENGTH + 1];
	void*           context;
	uint32_t        flags;
	uint32_t        padding;
	void*           context_start;
	void*           context_end;
	FiberCpuContext saved_context;
	uint64_t        arg_on_run;
	uint64_t        arg_on_return;
	bool            context_valid;
	uint32_t        magic_end;
};

static_assert(sizeof(FiberObject) <= 256);

struct FiberInfo {
	uint64_t   size;
	FiberEntry entry;
	uint64_t   arg_on_initialize;
	void*      addr_context;
	uint64_t   size_context;
	char       name[FIBER_MAX_NAME_LENGTH + 1];
	uint64_t   size_context_margin;
	uint8_t    padding[48];
};

static_assert(sizeof(FiberInfo) == 128);

static bool FiberIsValid(const FiberObject* fiber) {
	return fiber != nullptr && fiber->magic_start == FIBER_MAGIC_START &&
	       fiber->magic_end == FIBER_MAGIC_END;
}

struct FiberThreadContext {
	FiberObject*    current_fiber;
	FiberObject*    returned_fiber;
	FiberObject*    pending_idle_fiber;
	FiberCpuContext cpu_context;
};

static const auto g_fiber_context_key = [] {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	const auto key = TlsAlloc();
	if (key == TLS_OUT_OF_INDEXES) {
		std::abort();
	}
#else
	pthread_key_t key;
	if (pthread_key_create(&key, nullptr) != 0) {
		std::abort();
	}
#endif
	return key;
}();

// Native lookup must stay fresh when a fiber resumes on another host thread.
static FiberThreadContext* FiberGetThreadContext() {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	return static_cast<FiberThreadContext*>(TlsGetValue(g_fiber_context_key));
#else
	return static_cast<FiberThreadContext*>(pthread_getspecific(g_fiber_context_key));
#endif
}

static void FiberSetThreadContext(FiberThreadContext* context) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (TlsSetValue(g_fiber_context_key, context) == 0) {
#else
	if (pthread_setspecific(g_fiber_context_key, context) != 0) {
#endif
		std::abort();
	}
}

static uint32_t FiberLoadState(const FiberObject* fiber) {
	auto& state = const_cast<uint32_t&>(fiber->state);
	return std::atomic_ref<uint32_t>(state).load(std::memory_order_acquire);
}

static void FiberStoreState(FiberObject* fiber, uint32_t state) {
	std::atomic_ref<uint32_t>(fiber->state).store(state, std::memory_order_release);
}

static void FiberCompleteSwitch(FiberObject* current) {
	auto* context = FiberGetThreadContext();
	context->current_fiber = current;
	// Only publish IDLE after switching away from the departing fiber's stack.
	auto* fiber = context->pending_idle_fiber;
	context->pending_idle_fiber = nullptr;
	if (fiber != nullptr) {
		FiberStoreState(fiber, FIBER_STATE_IDLE);
	}
}

static bool FiberCompareExchangeState(FiberObject* fiber, uint32_t expected, uint32_t desired) {
	return std::atomic_ref<uint32_t>(fiber->state)
	    .compare_exchange_strong(expected, desired, std::memory_order_acq_rel,
	                             std::memory_order_acquire);
}

static void FiberSetContextValid(FiberObject* fiber, bool valid) {
	fiber->context_valid = valid;
	fiber->context       = valid ? &fiber->saved_context : nullptr;
}

#if defined(__x86_64__) || defined(_M_X64)
[[gnu::naked,
  gnu::returns_twice]] static KYTY_SYSV_ABI int FiberSaveContext(FiberCpuContext* /*ctx*/) {
	asm volatile("movq %rdi, %r10\n\t"
	             "movq %rbx, 0(%r10)\n\t"
	             "movq %rbp, 8(%r10)\n\t"
	             "movq %rdi, 16(%r10)\n\t"
	             "movq %rsi, 24(%r10)\n\t"
	             "movq %r12, 32(%r10)\n\t"
	             "movq %r13, 40(%r10)\n\t"
	             "movq %r14, 48(%r10)\n\t"
	             "movq %r15, 56(%r10)\n\t"
	             "leaq 8(%rsp), %r11\n\t"
	             "movq %r11, 64(%r10)\n\t"
	             "movq (%rsp), %r11\n\t"
	             "movq %r11, 72(%r10)\n\t"
	             "xorl %eax, %eax\n\t"
	             "retq\n");
}

[[gnu::naked, gnu::noreturn]] static KYTY_SYSV_ABI void
FiberRestoreContext(FiberCpuContext* /*ctx*/, uint64_t /*ret*/) {
	asm volatile("movq %rdi, %r10\n\t"
	             "movq %rsi, %rax\n\t"
	             "movq 72(%r10), %r11\n\t"
	             "movq 0(%r10), %rbx\n\t"
	             "movq 8(%r10), %rbp\n\t"
	             "movq 16(%r10), %rdi\n\t"
	             "movq 24(%r10), %rsi\n\t"
	             "movq 32(%r10), %r12\n\t"
	             "movq 40(%r10), %r13\n\t"
	             "movq 48(%r10), %r14\n\t"
	             "movq 56(%r10), %r15\n\t"
	             "movq 64(%r10), %rsp\n\t"
	             "jmp *%r11\n");
}
#else
static int FiberSaveContext(FiberCpuContext* ctx) {
	(void)ctx;
	return 0;
}

static void FiberRestoreContext(FiberCpuContext* ctx, uint64_t ret) {
	(void)ctx;
	(void)ret;
	EXIT("Fiber context switching is only implemented on x86_64\n");
}
#endif

[[noreturn]] static KYTY_SYSV_ABI void FiberStartTrampoline(FiberObject* fiber);

[[noreturn]] static KYTY_SYSV_ABI void FiberStartOnGuestStack(FiberObject* fiber) {
	FiberCpuContext ctx {};
	const auto      stack_top = reinterpret_cast<uintptr_t>(fiber->addr_context) +
	                            static_cast<uintptr_t>(fiber->size_context);
	auto            rsp       = (stack_top & ~static_cast<uintptr_t>(0x0f));
	rsp -= sizeof(uint64_t);
	*reinterpret_cast<uint64_t*>(rsp) = 0;

	ctx.rsp = rsp;
	ctx.rip = reinterpret_cast<uint64_t>(&FiberStartTrampoline);
	ctx.rdi = reinterpret_cast<uint64_t>(fiber);

	FiberRestoreContext(&ctx, 1);
}

[[noreturn]] static KYTY_SYSV_ABI void FiberStartTrampoline(FiberObject* fiber) {
	FiberCompleteSwitch(fiber);

	fiber->entry(fiber->arg_on_initialize, fiber->arg_on_run);

	FiberStoreState(fiber, FIBER_STATE_TERMINATED);
	FiberSetContextValid(fiber, false);
	fiber->arg_on_return  = 0;
	auto* context = FiberGetThreadContext();
	context->returned_fiber = fiber;
	context->current_fiber = nullptr;

	FiberRestoreContext(&context->cpu_context, 1);
}

int32_t KYTY_SYSV_ABI FiberInitialize(FiberObject* fiber, const char* name, FiberEntry entry,
                                      uint64_t arg_on_initialize, void* addr_context,
                                      uint64_t size_context, const FiberOptParam* opt_param,
                                      uint32_t build_version) {
	PRINT_NAME();

	if (fiber == nullptr || name == nullptr || entry == nullptr) {
		return FIBER_ERROR_NULL;
	}

	if ((reinterpret_cast<uint64_t>(fiber) & 7u) != 0 ||
	    (reinterpret_cast<uint64_t>(addr_context) & 15u) != 0 ||
	    (opt_param != nullptr && (reinterpret_cast<uint64_t>(opt_param) & 7u) != 0)) {
		return FIBER_ERROR_ALIGNMENT;
	}

	if (size_context != 0 && size_context < FIBER_CONTEXT_MIN_SIZE) {
		return FIBER_ERROR_RANGE;
	}

	if ((size_context & 15u) != 0 || (addr_context == nullptr && size_context != 0) ||
	    (addr_context != nullptr && size_context == 0) ||
	    (opt_param != nullptr && opt_param->magic != FIBER_OPT_MAGIC)) {
		return FIBER_ERROR_INVALID;
	}

	std::memset(fiber, 0, sizeof(*fiber));
	std::strncpy(fiber->name, name, FIBER_MAX_NAME_LENGTH);
	fiber->name[FIBER_MAX_NAME_LENGTH] = '\0';

	fiber->magic_start       = FIBER_MAGIC_START;
	fiber->state             = FIBER_STATE_IDLE;
	fiber->entry             = entry;
	fiber->arg_on_initialize = arg_on_initialize;
	fiber->addr_context      = addr_context;
	fiber->size_context      = size_context;
	fiber->flags             = (build_version >= 0x03500000 ? FIBER_FLAG_SET_FPU_REGS : 0);
	fiber->context_start     = addr_context;
	fiber->context_end =
	    (addr_context != nullptr ? static_cast<uint8_t*>(addr_context) + size_context : nullptr);
	std::memset(&fiber->saved_context, 0, sizeof(fiber->saved_context));
	FiberSetContextValid(fiber, false);
	fiber->magic_end = FIBER_MAGIC_END;

	if (addr_context != nullptr) {
		*static_cast<uint64_t*>(addr_context) = FIBER_STACK_MAGIC;
	}

	LOGF("\t fiber init: %s, entry = 0x%016" PRIx64 ", context = 0x%016" PRIx64 ", size = %" PRIu64
	     "\n",
	     fiber->name, reinterpret_cast<uint64_t>(entry), reinterpret_cast<uint64_t>(addr_context),
	     size_context);

	return OK;
}

int32_t KYTY_SYSV_ABI FiberInitializeInternal(FiberObject* fiber, const char* name,
                                              FiberEntry entry, uint64_t arg_on_initialize,
                                              void* addr_context, uint64_t size_context,
                                              const FiberOptParam* opt_param, uint32_t flags,
                                              uint32_t build_version) {
	auto ret = FiberInitialize(fiber, name, entry, arg_on_initialize, addr_context, size_context,
	                           opt_param, build_version);
	if (ret == OK && fiber != nullptr) {
		fiber->flags |= flags;
	}
	return ret;
}

int32_t KYTY_SYSV_ABI FiberOptParamInitialize(FiberOptParam* opt_param) {
	PRINT_NAME();

	if (opt_param == nullptr) {
		return FIBER_ERROR_NULL;
	}
	if ((reinterpret_cast<uint64_t>(opt_param) & 7u) != 0) {
		return FIBER_ERROR_ALIGNMENT;
	}

	std::memset(opt_param, 0, 128);
	opt_param->magic = FIBER_OPT_MAGIC;

	return OK;
}

int32_t KYTY_SYSV_ABI FiberFinalize(FiberObject* fiber) {
	PRINT_NAME();

	if (fiber == nullptr) {
		return FIBER_ERROR_NULL;
	}
	if (!FiberIsValid(fiber)) {
		return FIBER_ERROR_INVALID;
	}
	if (!FiberCompareExchangeState(fiber, FIBER_STATE_IDLE, FIBER_STATE_TERMINATED)) {
		return FIBER_ERROR_STATE;
	}

	return OK;
}

int32_t KYTY_SYSV_ABI FiberRun(FiberObject* fiber, uint64_t arg_on_run, uint64_t* arg_on_return) {
	PRINT_NAME();

	if (!FiberIsValid(fiber)) {
		return FIBER_ERROR_INVALID;
	}
	if (FiberGetThreadContext() != nullptr) {
		return FIBER_ERROR_PERMISSION;
	}
	if (!FiberCompareExchangeState(fiber, FIBER_STATE_IDLE, FIBER_STATE_RUNNING)) {
		return FIBER_ERROR_STATE;
	}

	fiber->arg_on_run    = arg_on_run;
	fiber->arg_on_return = 0;
	// Register on the host stack; switching fibers only reads the native TLS slot.
	FiberThreadContext context {};
	FiberSetThreadContext(&context);

	if (FiberSaveContext(&context.cpu_context) == 0) {
		if (fiber->context_valid) {
			FiberRestoreContext(&fiber->saved_context, 1);
		}
		FiberStartOnGuestStack(fiber);
	}

	auto* returned_fiber  = (context.returned_fiber != nullptr ? context.returned_fiber : fiber);
	const auto return_value = returned_fiber->arg_on_return;
	const auto return_code =
	    FiberLoadState(returned_fiber) == FIBER_STATE_TERMINATED ? FIBER_ERROR_STATE : OK;
	// Copy results before another thread can acquire and resume the fiber.
	FiberCompleteSwitch(nullptr);
	FiberSetThreadContext(nullptr);

	if (arg_on_return != nullptr) {
		*arg_on_return = return_value;
	}

	return return_code;
}

int32_t KYTY_SYSV_ABI FiberSwitch(FiberObject* fiber, uint64_t arg_on_run,
                                  uint64_t* arg_on_return) {
	PRINT_NAME();

	if (!FiberIsValid(fiber)) {
		return FIBER_ERROR_INVALID;
	}
	auto* context = FiberGetThreadContext();
	if (context == nullptr) {
		return FIBER_ERROR_PERMISSION;
	}

	if (!FiberCompareExchangeState(fiber, FIBER_STATE_IDLE, FIBER_STATE_RUNNING)) {
		return FIBER_ERROR_STATE;
	}

	auto* caller = context->current_fiber;

	fiber->arg_on_run    = arg_on_run;
	fiber->arg_on_return = 0;

	if (FiberSaveContext(&caller->saved_context) == 0) {
		FiberSetContextValid(caller, true);
		context->pending_idle_fiber = caller;
		if (fiber->context_valid) {
			FiberRestoreContext(&fiber->saved_context, 1);
		}
		FiberStartOnGuestStack(fiber);
	}

	FiberCompleteSwitch(caller);

	if (arg_on_return != nullptr) {
		*arg_on_return = caller->arg_on_run;
	}

	return OK;
}

int32_t KYTY_SYSV_ABI FiberGetSelf(FiberObject** fiber) {
	PRINT_NAME();

	if (fiber == nullptr) {
		return FIBER_ERROR_NULL;
	}

	const auto* context = FiberGetThreadContext();
	*fiber = context != nullptr ? context->current_fiber : nullptr;

	return OK;
}

int32_t KYTY_SYSV_ABI FiberReturnToThread(uint64_t arg_on_return, uint64_t* arg_on_run) {
	PRINT_NAME();

	auto* context = FiberGetThreadContext();
	if (context == nullptr) {
		return FIBER_ERROR_PERMISSION;
	}

	auto* fiber          = context->current_fiber;
	fiber->arg_on_return = arg_on_return;

	if (FiberSaveContext(&fiber->saved_context) == 0) {
		FiberSetContextValid(fiber, true);
		context->returned_fiber = fiber;
		context->pending_idle_fiber = fiber;
		FiberRestoreContext(&context->cpu_context, 1);
	}

	FiberCompleteSwitch(fiber);
	if (arg_on_run != nullptr) {
		*arg_on_run = fiber->arg_on_run;
	}

	return OK;
}

int32_t KYTY_SYSV_ABI FiberGetInfo(FiberObject* fiber, FiberInfo* fiber_info) {
	PRINT_NAME();

	if (fiber == nullptr || fiber_info == nullptr) {
		return FIBER_ERROR_NULL;
	}
	if (!FiberIsValid(fiber)) {
		return FIBER_ERROR_INVALID;
	}

	std::memset(fiber_info, 0, sizeof(*fiber_info));
	fiber_info->size              = sizeof(*fiber_info);
	fiber_info->entry             = fiber->entry;
	fiber_info->arg_on_initialize = fiber->arg_on_initialize;
	fiber_info->addr_context      = fiber->addr_context;
	fiber_info->size_context      = fiber->size_context;
	std::strncpy(fiber_info->name, fiber->name, FIBER_MAX_NAME_LENGTH);

	return OK;
}

int32_t KYTY_SYSV_ABI FiberStartContextSizeCheck(uint32_t flags) {
	PRINT_NAME();
	LOGF("\t flags = 0x%08" PRIx32 "\n", flags);
	return OK;
}

int32_t KYTY_SYSV_ABI FiberStopContextSizeCheck() {
	PRINT_NAME();
	return OK;
}

int32_t KYTY_SYSV_ABI FiberRename(FiberObject* fiber, const char* name) {
	PRINT_NAME();

	if (fiber == nullptr || name == nullptr) {
		return FIBER_ERROR_NULL;
	}
	if (!FiberIsValid(fiber)) {
		return FIBER_ERROR_INVALID;
	}

	std::strncpy(fiber->name, name, FIBER_MAX_NAME_LENGTH);
	fiber->name[FIBER_MAX_NAME_LENGTH] = '\0';

	return OK;
}

int32_t KYTY_SYSV_ABI FiberGetThreadFramePointerAddress(uint64_t* addr_frame_pointer) {
	PRINT_NAME();

	if (addr_frame_pointer == nullptr) {
		return FIBER_ERROR_NULL;
	}

	*addr_frame_pointer = 0;

	return OK;
}

} // namespace Fiber

int chmod(const char* path, int mode) {
	PRINT_NAME();

	return OK;
}

int KYTY_SYSV_ABI KernelGetSpecialModelFlag(uint16_t* flag) {
	PRINT_NAME();

	if (flag == nullptr) {
		return LibKernel::KERNEL_ERROR_EINVAL;
	}

	*flag = 0;
	return OK;
}
int KYTY_SYSV_ABI KernelIsEcoChargeAvailable() {
	PRINT_NAME();

	return 0;
}
int KYTY_SYSV_ABI KernelIsAuthenticTrinity() {
	PRINT_NAME();

	return 0;
}
int KYTY_SYSV_ABI KernelGetCurrentFanDuty(uint16_t* duty, uint64_t* chassis_info) {
	PRINT_NAME();

	if (duty == nullptr || chassis_info == nullptr) {
		return LibKernel::KERNEL_ERROR_EINVAL;
	}

	*duty         = 0;
	*chassis_info = 0;
	return OK;
}
int KYTY_SYSV_ABI KernelGetSocPowerConsumption(void* info) {
	PRINT_NAME();

	if (info == nullptr) {
		return LibKernel::KERNEL_ERROR_EINVAL;
	}

	std::memset(info, 0, 0x70);
	return OK;
}
// diagnostic: selected peers get the 0x4800000000000015 SceAvCapture authority
static bool DiagnosticCompositorClientAuthorityMatches(uint64_t authority_id) {
	const char* value = std::getenv("KYTY_DIAGNOSTIC_AUTHINFO_COMPOSITOR_CLIENT");
	if (value == nullptr || *value == '\0') return false;
	const char* p = value;
	while (*p != '\0') {
		while (*p == ',' || *p == ';' || *p == ' ' || *p == '\t')
			++p;
		if (*p == '\0') break;
		char*          end    = nullptr;
		const uint64_t parsed = std::strtoull(p, &end, 0);
		if (end == p) break;
		if (parsed == authority_id) return true;
		p = end;
	}
	return false;
}
int KYTY_SYSV_ABI KernelGetAuthinfo(int pid, void* info) {
	PRINT_NAME();

	if (info == nullptr) {
		*Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
		return -1;
	}

	LibKernel::Process::PeerProcess process;
	if (!LibKernel::Process::FindPeerByPid(pid != 0 ? pid : LibKernel::Process::GetPid(),
	                                       &process)) {
		*Posix::GetErrorAddr() = Posix::POSIX_ESRCH;
		return -1;
	}

	LibKernel::AuthInfo::Record response {};
	const int                   target_pid = pid != 0 ? pid : LibKernel::Process::GetPid();
	const bool                  remote     = target_pid != LibKernel::Process::GetPid();
	const bool observed = !process.has_auth_info &&
	                      (remote ? process.has_filtered_auth_info
	                              : LibKernel::Process::GetCurrentFilteredAuthInfo(&response));
	if (!process.has_auth_info && !observed &&
	    DiagnosticCompositorClientAuthorityMatches(process.auth_id)) {
		LibKernel::AuthInfo::Record standin {};
		constexpr uint64_t          compositor_client_authority = 0x4800000000000015ull;
		std::memcpy(standin.data(), &compositor_client_authority,
		            sizeof(compositor_client_authority));
		if (!LibKernel::Memory::CopyToGuest(info, standin.data(), standin.size())) {
			*Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
			return -1;
		}
		LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_AUTHINFO_COMPOSITOR_CLIENT pid=%d "
		     "peer_authority=0x%016" PRIx64 " synthesized_authority=0x%016" PRIx64
		     " NON_AUTHENTIC\n",
		     pid, process.auth_id, compositor_client_authority);
		return OK;
	}
	if (!process.has_auth_info && !observed) {
		*Posix::GetErrorAddr() = Posix::POSIX_ENOENT;
		LOGF("AUTHINFO_MISSING pid=%d authority=0x%016" PRIx64 " result=ENOENT\n", pid,
		     process.auth_id);
		return -1;
	}
	const auto         caller               = LibKernel::Process::GetCurrentAuthorizationFacts();
	constexpr uint64_t privilege_bit        = uint64_t {1} << 62;
	const bool         privileged           = caller.root_prison_known && caller.root_prison &&
	                                          (caller.known_capability0 & privilege_bit) != 0 &&
	                                          (caller.capability0 & privilege_bit) != 0;
	bool               full_authinfo_record = false;
	if (privileged && process.has_auth_info) {
		response             = process.auth_info;
		full_authinfo_record = true;
	} else {
		if (process.has_auth_info)
			response = LibKernel::AuthInfo::Filter(process.auth_info);
		else if (remote)
			response = process.filtered_auth_info;
		if (privileged) {
			std::memcpy(response.data(), &process.auth_id, sizeof(process.auth_id));
		}
	}
	constexpr uint64_t diagnostic_caps = 0x4000000000000000ull;
	const bool         diagnostic_shellui_cap =
	    !privileged && !observed && process.auth_id == 0x480000000000000Full &&
	    std::getenv("KYTY_DIAGNOSTIC_AUTHINFO_SHELLUI_SYSTEM_CAP") != nullptr;
	if (diagnostic_shellui_cap) {
		std::memcpy(response.data() + 8, &diagnostic_caps, sizeof(diagnostic_caps));
	}
	if (!LibKernel::Memory::CopyToGuest(info, response.data(), response.size())) {
		*Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
		return -1;
	}
	if (privileged) {
		LOGF("AUTHINFO_PRIVILEGE_0X2AE pid=%d root_prison=verified bit62=verified source=%s"
		     " full_authinfo_record=%d remote_visibility=existing_peer_scope\n",
		     target_pid, full_authinfo_record ? "exact_capture" : "partial_observation",
		     full_authinfo_record ? 1 : 0);
		return OK;
	}
	if (observed) {
		LOGF("AUTHINFO_FILTERED_OBSERVATION pid=%d source=%s full_authinfo_record=0\n", target_pid,
		     remote ? "scoped_peer_observation" : "native_587_observed_fields");
		return OK;
	}
	LOGF("AUTHINFO_FILTERED_SOURCE_RECORD pid=%d authority=0x%016" PRIx64
	     " privilege_0x2ae=filtered caller_root_prison_known=%d caller_root_prison=%d"
	     " caller_bit62_known=%d caller_bit62=%d\n",
	     pid, process.auth_id, caller.root_prison_known ? 1 : 0, caller.root_prison ? 1 : 0,
	     (caller.known_capability0 & privilege_bit) != 0 ? 1 : 0,
	     (caller.capability0 & privilege_bit) != 0 ? 1 : 0);
	if (diagnostic_shellui_cap) {
		LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_AUTHINFO_CAPS pid=%d caps0=0x%016" PRIx64
		     " NON_AUTHENTIC\n",
		     pid, diagnostic_caps);
	}
	LOGF("\t pid = %d, authority id = 0x%016" PRIx64 "\n", pid, process.auth_id);
	return OK;
}
int KYTY_SYSV_ABI KernelGetAppInfo2(int pid, void* info, size_t size) {
	PRINT_NAME();
	LibKernel::AppMount::Record record {};
	bool                        committed = false;
	const int result = LibKernel::AppMount::GetAppInfo(pid, size, &record, &committed);
	if (result != 0) {
		*Posix::GetErrorAddr() = result;
		return LibKernel::KERNEL_ERROR_UNKNOWN + result;
	}
	if (!committed) {
		LOGF("APP_INFO2_UNAVAILABLE pid=%d info=%p size=%" PRIu64
		     " no_committed_record output_unchanged=1\n",
		     pid, info, static_cast<uint64_t>(size));
		*Posix::GetErrorAddr() = Posix::POSIX_ENOSYS;
		return LibKernel::KERNEL_ERROR_ENOSYS;
	}
	if (size != 0 && !LibKernel::Memory::CopyToGuest(info, record.data(), size))
		return LibKernel::KERNEL_ERROR_EFAULT;
	int32_t app_id = 0;
	std::memcpy(&app_id, record.data(), sizeof(app_id));
	LOGF("APP_INFO2 pid=%d size=%" PRIu64 " app_id=%d title=%.10s\n", pid,
	     static_cast<uint64_t>(size), app_id, reinterpret_cast<const char*>(record.data() + 0x10));
	return OK;
}
// Without this export the unresolved-import stub returns 0, which SysCore addShellCoreApp takes as
// a mounted appid 0.
static uint32_t AppMountRead32(const std::array<uint8_t, 0x18b0>& info, size_t offset) {
	uint32_t value = 0;
	std::memcpy(&value, info.data() + offset, sizeof(value));
	return value;
}
// The kind byte the wrapper stores at +0x1a of the syscall block; -1 is its EINVAL.
static int AppMountKind(uint32_t category, uint32_t mode) {
	switch (category) {
		case 0:
		case 0xf000:
		case 0xf100:
		case 0x10000:
		case 0x10100:
		case 0x10200:
		case 0x10300:
		case 0x1f000:
		case 0x1f300:
		case 0x20000:
		case 0x20100:
		case 0x2f000: return 0;
		case 0x1f100:
		case 0x1f200:
		case 0x1f400:
		case 0x1f500:
		case 0x2f100: return 1;
		case 0x20200:
		case 0x02000000:
		case 0x02000100:
		case 0x0200f000:
		case 0x0200f100:
		case 0x0200f200: return 2;
		case 0x05000000: return 3;
		case 0x03000000: return mode == 1 ? 6 : (mode == 2 ? 7 : 4);
		case 0x01000000: return 5;
		default: return -1;
	}
}
int KYTY_SYSV_ABI KernelSetAppState(int32_t app_id, uint32_t state) {
	PRINT_NAME();
	const int32_t mib[4] {1, 14, 0x40, app_id};
	const auto    reply =
	    NativeKernelBridge::DispatchSyscall({0xca,
		                                     {reinterpret_cast<uint64_t>(mib), 4, 0, 0,
		                                      reinterpret_cast<uint64_t>(&state), sizeof(state)}});
	int error = reply.posix_errno;
	if (error == 0 && reply.value != 0)
		error = LibKernel::KernelToPosix(static_cast<int>(reply.value));
	if (error != 0) *Posix::GetErrorAddr() = error;
	const int result = error == 0 ? 0 : LibKernel::KERNEL_ERROR_UNKNOWN + error;
	LOGF("APP_STATE_EXPORT app_id=%d state=%u result=0x%x nid=QU57kCwF81U\n", app_id, state,
	     result);
	return result;
}
// libkernel_sys +0x42f10: an 8-byte read of the same oid; the outputs are only written once the
// sysctl succeeds.
int KYTY_SYSV_ABI KernelGetAppState(int32_t app_id, int32_t* state, int32_t* secondary) {
	PRINT_NAME();
	const int32_t mib[4] {1, 14, 0x40, app_id};
	int32_t       buf[2] {};
	uint64_t      len   = sizeof(buf);
	const auto    reply = NativeKernelBridge::DispatchSyscall(
	    {0xca,
		 {reinterpret_cast<uint64_t>(mib), 4, reinterpret_cast<uint64_t>(buf),
		  reinterpret_cast<uint64_t>(&len), 0, 0}});
	int error = reply.posix_errno;
	if (error == 0 && reply.value != 0)
		error = LibKernel::KernelToPosix(static_cast<int>(reply.value));
	LOGF("APP_STATE_GET_EXPORT app_id=%d errno=%d state=%d secondary=%d nid=WYCNbP+Q9kc\n", app_id,
	     error, buf[0], buf[1]);
	if (error != 0) {
		*Posix::GetErrorAddr() = error;
		return LibKernel::KERNEL_ERROR_UNKNOWN + error;
	}
	if (state != nullptr) *state = buf[0];
	if (secondary != nullptr) *secondary = buf[1];
	return OK;
}
// libkernel_sys +0x43040 passes the caller's buffer straight through as oldp with oldlen 0x98.
int KYTY_SYSV_ABI KernelGetAppInfoByAppId(int32_t app_id, void* info) {
	PRINT_NAME();
	const int32_t mib[4] {1, 14, 65, app_id};
	uint64_t      len   = sizeof(LibKernel::AppMount::Record);
	const auto    reply = NativeKernelBridge::DispatchSyscall(
	    {0xca,
		 {reinterpret_cast<uint64_t>(mib), 4, reinterpret_cast<uint64_t>(info),
		  reinterpret_cast<uint64_t>(&len), 0, 0}});
	int error = reply.posix_errno;
	if (error == 0 && reply.value != 0)
		error = LibKernel::KernelToPosix(static_cast<int>(reply.value));
	if (error != 0) *Posix::GetErrorAddr() = error;
	const int result = error == 0 ? 0 : LibKernel::KERNEL_ERROR_UNKNOWN + error;
	LOGF("APP_INFO_BY_ID_EXPORT app_id=%d result=0x%x nid=zsMzX135ofU\n", app_id, result);
	return result;
}
// processSpawn gate: Prospero SDK word from PT_OS_PROCPARAM, taken from the decrypted overlay
static int SdkVersionByPath(const char* path, uint64_t shift, uint32_t* out, const char* tag) {
	if (path == nullptr || out == nullptr) {
		LOGF("%s path=%s out=%s result=0x%x reason=null_arg\n", tag,
		     path != nullptr ? path : "(null)", out != nullptr ? "set" : "(null)",
		     LibKernel::KERNEL_ERROR_EINVAL);
		return LibKernel::KERNEL_ERROR_EINVAL;
	}
	LibKernel::DirectoryPassthrough::FileSnapshot snapshot;
	const int result = LibKernel::DirectoryPassthrough::OpenFileSnapshot(path, &snapshot);
	if (result != OK || snapshot.bytes.empty()) {
		LOGF("%s path=%s result=0x%x reason=open\n", tag, path, result);
		return result != OK ? result : LibKernel::KERNEL_ERROR_ENOENT;
	}
	std::vector<uint8_t> decrypted;
	std::string          detail;
	if (Loader::DecryptedModuleOverlay::ResolveDecryptedModuleImage(path, snapshot.bytes,
	                                                                &decrypted, &detail) !=
	        Loader::DecryptedModuleOverlay::Resolution::Substituted ||
	    decrypted.size() < 0x1000) {
		LOGF("%s path=%s result=0x%x reason=no_decrypted_image %s\n", tag, path,
		     LibKernel::KERNEL_ERROR_ENOENT, detail.c_str());
		return LibKernel::KERNEL_ERROR_ENOENT;
	}
	const auto*    phdr  = reinterpret_cast<const Loader::Elf64_Phdr*>(decrypted.data() + 0x40);
	const uint16_t phnum = *reinterpret_cast<const uint16_t*>(decrypted.data() + 0x38);
	for (uint16_t i = 0; i < phnum; i++) {
		const uint64_t off = phdr[i].p_offset;
		if (phdr[i].p_type != Loader::PT_OS_PROCPARAM || phdr[i].p_filesz < 0x18 ||
		    off + phdr[i].p_filesz > decrypted.size()) {
			continue;
		}
		*out = static_cast<uint32_t>(
		    *reinterpret_cast<const uint64_t*>(decrypted.data() + off + 0x10) >> shift);
		LOGF("%s path=%s value=0x%08x result=0\n", tag, path, *out);
		return 0;
	}
	LOGF("%s path=%s result=0x%x reason=no_procparam\n", tag, path, LibKernel::KERNEL_ERROR_ENOENT);
	return LibKernel::KERNEL_ERROR_ENOENT;
}
// 4P1e01mbenA is sceKernelGetProcessTypeOfBudget (SysCore stub slot 246, called twice from
// createApp with rdi=[r15+8]). SysCore only takes the NotifyAppStateChanged(1) branch when the
// result is 0.
int KYTY_SYSV_ABI KernelGetProcessTypeOfBudget(int32_t pid) {
	PRINT_NAME();
	int32_t ptype = 0;
	if (!LibKernel::Budget::Ptype(pid, &ptype)) {
		LOGF("PROCESS_TYPE_OF_BUDGET pid=%d result=0x%x\n", pid, LibKernel::KERNEL_ERROR_ESRCH);
		return LibKernel::KERNEL_ERROR_ESRCH;
	}
	LOGF("PROCESS_TYPE_OF_BUDGET pid=%d ptype=%d result=0\n", pid, ptype);
	return ptype;
}
// The budget wrappers below sit on raw 0x238-0x23a, whose handlers put an sce error in the value
// rather than an errno.
static int BudgetErrno(const NativeKernelBridge::Reply& reply) {
	if (reply.posix_errno == 0 && reply.value > LibKernel::KERNEL_ERROR_UNKNOWN &&
	    reply.value <= LibKernel::KERNEL_ERROR_UNKNOWN + 101) {
		return LibKernel::KernelToPosix(static_cast<int>(reply.value));
	}
	return reply.posix_errno;
}
int KYTY_SYSV_ABI KernelCreateBudget(int64_t* id, const char* name, uint32_t ptype,
                                     const void* entries, uint32_t count, void* out_entries) {
	PRINT_NAME();
	int error = 0;
	for (int attempt = 0;; attempt++) {
		const auto reply = NativeKernelBridge::DispatchSyscall(
		    {0x238,
			 {reinterpret_cast<uint64_t>(name), ptype, reinterpret_cast<uint64_t>(entries), count,
			  reinterpret_cast<uint64_t>(out_entries)}});
		error = BudgetErrno(reply);
		if (error == 0) {
			*id = reply.value;
			break;
		}
		*Posix::GetErrorAddr() = error;
		if (error != Posix::POSIX_EPERM) break;
		Common::Thread::SleepMicro(100000);
		if (attempt == 9) break;
		LOGF("libkernel: FIXME: Retrying memory space creation.\n");
	}
	const int result = error == 0 ? 0 : LibKernel::KERNEL_ERROR_UNKNOWN + error;
	LOGF("BUDGET_CREATE_EXPORT ptype=%u count=%u result=0x%x id=%" PRId64 " nid=BVafm-M0GNw\n",
	     ptype, count, result, error == 0 ? *id : -1);
	return result;
}
int KYTY_SYSV_ABI KernelDeleteBudget(int32_t budget) {
	PRINT_NAME();
	const int error = BudgetErrno(NativeKernelBridge::DispatchSyscall(
	    {0x239, {static_cast<uint64_t>(static_cast<int64_t>(budget))}}));
	if (error != 0) *Posix::GetErrorAddr() = error;
	const int result = error == 0 ? 0 : LibKernel::KERNEL_ERROR_UNKNOWN + error;
	LOGF("BUDGET_DELETE_EXPORT id=%d result=0x%x nid=vs+KPSoE7AM\n", budget, result);
	return result;
}
// libkernel_sys +0x46b00: the builtin budget of process type n is id -2-n.
int KYTY_SYSV_ABI KernelGetResourceLimit(uint32_t ptype, void* entries, int32_t* count) {
	PRINT_NAME();
	if (ptype > 4) return LibKernel::KERNEL_ERROR_EINVAL;
	const int32_t budget = -2 - static_cast<int32_t>(ptype);
	const int     error  = BudgetErrno(NativeKernelBridge::DispatchSyscall(
	    {0x23a,
		 {static_cast<uint64_t>(static_cast<int64_t>(budget)), reinterpret_cast<uint64_t>(entries),
		  reinterpret_cast<uint64_t>(count)}}));
	if (error != 0) *Posix::GetErrorAddr() = error;
	const int result = error == 0 ? 0 : LibKernel::KERNEL_ERROR_UNKNOWN + error;
	LOGF("BUDGET_RESOURCE_LIMIT_EXPORT ptype=%u result=0x%x nid=S2-4Sh3qnm8\n", ptype, result);
	return result;
}
// libkernel_sys +0x46b40 reads up to 14 entries of the given budget and copies out the first of
// that kind; none is ENOENT.
int KYTY_SYSV_ABI KernelGetResourceOne(int32_t budget, uint32_t kind, void* entry) {
	PRINT_NAME();
	std::array<uint8_t, 0x18 * 14> entries {};
	int32_t                        count = 14;
	const int                      error = BudgetErrno(NativeKernelBridge::DispatchSyscall(
	    {0x23a,
		 {static_cast<uint64_t>(static_cast<int64_t>(budget)),
		  reinterpret_cast<uint64_t>(entries.data()), reinterpret_cast<uint64_t>(&count)}}));
	if (error != 0) {
		*Posix::GetErrorAddr() = error;
		return LibKernel::KERNEL_ERROR_UNKNOWN + error;
	}
	for (int32_t i = 0; i < count; i++) {
		uint32_t found = 0;
		std::memcpy(&found, entries.data() + 0x18 * i, sizeof(found));
		if (found == kind) {
			std::memcpy(entry, entries.data() + 0x18 * i, 0x18);
			return OK;
		}
	}
	return LibKernel::KERNEL_ERROR_ENOENT;
}
// libkernel_sys +0x42820 hands the caller's own 0x178-byte block to raw 0x2c2, so the id goes
// wherever its +0xb0 points
int KYTY_SYSV_ABI KernelBeginAppMount(void* request) {
	PRINT_NAME();
	const auto reply =
	    NativeKernelBridge::DispatchSyscall({0x2c2, {reinterpret_cast<uint64_t>(request)}});
	int error = reply.posix_errno;
	if (error == 0 && reply.value != 0)
		error = LibKernel::KernelToPosix(static_cast<int>(reply.value));
	if (error != 0) *Posix::GetErrorAddr() = error;
	const int result = error == 0 ? 0 : LibKernel::KERNEL_ERROR_UNKNOWN + error;
	LOGF("APP_MOUNT_EXPORT result=0x%x nid=H69MYqpNjCc\n", result);
	return result;
}
int KYTY_SYSV_ABI KernelEndAppMount2(int32_t app_id) {
	PRINT_NAME();
	const auto reply =
	    NativeKernelBridge::DispatchSyscall({0x2c3, {reinterpret_cast<uint64_t>(&app_id)}});
	int error = reply.posix_errno;
	if (error == 0 && reply.value != 0)
		error = LibKernel::KernelToPosix(static_cast<int>(reply.value));
	if (error != 0) *Posix::GetErrorAddr() = error;
	const int result = error == 0 ? 0 : LibKernel::KERNEL_ERROR_UNKNOWN + error;
	LOGF("APP_MOUNT_END_EXPORT app_id=%d result=0x%x nid=CYIzY6OXyAs\n", app_id, result);
	return result;
}
int KYTY_SYSV_ABI KernelBeginAppMount2(void* info, uint64_t arg1, uint64_t arg2) {
	PRINT_NAME();
	if (info == nullptr) return LibKernel::KERNEL_ERROR_EINVAL;

	std::array<uint8_t, 0x18b0> public_info {};
	if (!LibKernel::Memory::CopyFromGuest(public_info.data(), info, public_info.size())) {
		return LibKernel::KERNEL_ERROR_EFAULT;
	}

	const uint32_t category   = AppMountRead32(public_info, 0);
	const uint8_t  hw_mode    = public_info[0x49];
	const uint8_t  sub_mode   = public_info[0x4b];
	const uint32_t settings   = AppMountRead32(public_info, 0x10a0);
	const bool     low_energy = (AppMountRead32(public_info, 0x18a8) & 1) != 0 ||
	                            (AppMountRead32(public_info, 0x18ac) & 1) != 0;
	const int      kind       = AppMountKind(category, AppMountRead32(public_info, 0x1870));
	if (kind < 0 || !((hw_mode <= 3) || hw_mode == 0xff) ||
	    !((sub_mode <= 1) || sub_mode == 0xff) ||
	    (sub_mode == 1 && (hw_mode != 0 || !low_energy)) || settings > 16) {
		return LibKernel::KERNEL_ERROR_EINVAL;
	}

	LibKernel::AppMount::Request request {};
	auto                         put = [&](size_t to, size_t from, size_t size) {
		std::memcpy(request.data() + to, public_info.data() + from, size);
	};
	const uint64_t header = 8;
	std::memcpy(request.data(), &header, sizeof(header));
	put(0x08, 0x24, 4);
	put(0x0c, 0x2c, 4);
	// strlcpy(+0x10, info+4, 10)
	for (size_t i = 0; i < 9 && public_info[4 + i] != 0; i++) {
		request[0x10 + i] = public_info[4 + i];
	}
	request[0x1a] = static_cast<uint8_t>(kind);
	request[0x1b] = public_info[0x888];
	request[0x1c] = public_info[0x68];
	request[0x1d] = 0xff;
	request[0x1f] = public_info[0x48];
	put(0x20, 0x38, 8);
	put(0x28, 0x28, 4);
	put(0x2c, 0x30, 4);
	put(0x30, 0x50, 16);
	put(0x40, 0x60, 8);
	request[0x48] = hw_mode;
	request[0x49] = 0xff;
	request[0x4a] = public_info[0x4a];
	request[0x4b] = sub_mode;
	put(0x4c, 0x1874, 4);
	put(0x50, 0, 4);
	put(0x54, 0x18a8, 4);
	put(0x58, 0x1880, 32);
	put(0x78, 0x18a0, 8);
	put(0x94, 0x18ac, 4);
	put(0x98, 0x40, 8);
	std::memcpy(request.data() + 0xa0, &arg1, sizeof(arg1));
	std::memcpy(request.data() + 0xa8, &arg2, sizeof(arg2));
	int32_t    app_id         = -1;
	const auto app_id_address = reinterpret_cast<uint64_t>(&app_id);
	std::memcpy(request.data() + 0xb0, &app_id_address, sizeof(app_id_address));
	put(0xb8, 0x1878, 8);
	put(0xc0, 0x1090, 16);
	put(0xd0, 0x10a0, 4);
	for (uint32_t i = 0; i < settings; i++) {
		put(0xd4 + 2 * i, 0x10a4 + 4 * i, 2);
		const uint64_t entry = reinterpret_cast<uint64_t>(info) + 0x10e4 + 0x25 * i;
		std::memcpy(request.data() + 0xf8 + 8 * i, &entry, sizeof(entry));
	}

	// libkernel_sys +0x42850 only picks the kind byte from the category; every accepted category
	// takes the same marshalling to raw 0x2c2.
	const int result = LibKernel::AppMount::Begin(
	    [&](LibKernel::AppMount::Request& block) {
		    block = request;
		    return 0;
	    },
	    [&](uint64_t, int32_t id) {
		    app_id = id;
		    return 0;
	    },
	    [](uint64_t address, void* buffer, uint64_t size) {
		    return LibKernel::Memory::CopyFromGuest(buffer, reinterpret_cast<const void*>(address),
			                                        size)
		               ? 0
					   : Posix::POSIX_EFAULT;
	    });
	if (result != 0) {
		LOGF("APP_MOUNT2_FAILED info=%p category=0x%x errno=%d no_app_returned=1\n", info, category,
		     result);
		*Posix::GetErrorAddr() = result;
		return LibKernel::KERNEL_ERROR_UNKNOWN + result;
	}
	return app_id;
}
static int KYTY_SYSV_ABI KernelGetAppInfoBit(const void* record, size_t size, uint32_t bit,
                                             int* output) {
	PRINT_NAME();
	if (record == nullptr || output == nullptr) return LibKernel::KERNEL_ERROR_EFAULT;
	if (size >= 0x29 || bit > 127) return LibKernel::KERNEL_ERROR_EINVAL;
	const auto address = reinterpret_cast<uint64_t>(record);
	const auto offset  = 8 + 8 * (bit >> 6);
	if (address > UINT64_MAX - offset) return LibKernel::KERNEL_ERROR_EFAULT;
	uint64_t word = 0;
	if (!LibKernel::Memory::CopyFromGuest(&word, reinterpret_cast<void*>(address + offset),
	                                      sizeof(word))) {
		return LibKernel::KERNEL_ERROR_EFAULT;
	}
	const int value = static_cast<int>((word >> (bit & 63)) & 1);
	return LibKernel::Memory::CopyToGuest(output, &value, sizeof(value))
	           ? OK
			   : LibKernel::KERNEL_ERROR_EFAULT;
}
static int KYTY_SYSV_ABI KernelQueryAppClassification(int* output) {
	PRINT_NAME();
	if (output == nullptr) return LibKernel::KERNEL_ERROR_EINVAL;
	auto*       rt         = Common::Singleton<Loader::RuntimeLinker>::Instance();
	const auto* proc_param = reinterpret_cast<const uint64_t*>(rt->GetProcParam());
	if (proc_param == nullptr || proc_param[0] <= 0x17) {
		LOGF("APP_CLASSIFICATION_UNAVAILABLE mib=1,14,68,self no_process_param "
		     "output_unchanged=1\n");
		*Posix::GetErrorAddr() = Posix::POSIX_ENOENT;
		return LibKernel::KERNEL_ERROR_ENOENT;
	}
	const uint32_t classification = static_cast<uint32_t>(proc_param[2] >> 32);
	if (!LibKernel::Memory::CopyToGuest(output, &classification, sizeof(classification))) {
		return LibKernel::KERNEL_ERROR_EFAULT;
	}
	LOGF("APP_CLASSIFICATION_FROM_PROCPARAM value=0x%08x mib=1,14,68,self\n", classification);
	return OK;
}
int KYTY_SYSV_ABI KernelGetAppInfo(int pid, void* info) {
	PRINT_NAME();
	// A record set through {1,14,35} is the kernel's own; the SFO category below only covers
	// processes that never set one.
	LibKernel::AppMount::Record committed_record {};
	bool                        committed = false;
	const int access = LibKernel::AppMount::GetAppInfo(pid, 0x58, &committed_record, &committed);
	if (access != 0) {
		*Posix::GetErrorAddr() = access;
		return LibKernel::KERNEL_ERROR_UNKNOWN + access;
	}
	if (!LibKernel::Memory::CanWriteGuest(info, 0x58)) return LibKernel::KERNEL_ERROR_EFAULT;
	if (committed) {
		if (!LibKernel::Memory::CopyToGuest(info, committed_record.data(), 0x58))
			return LibKernel::KERNEL_ERROR_EFAULT;
		return OK;
	}

	LibKernel::Process::PeerProcess process;
	if (!LibKernel::Process::FindPeerByPid(pid, &process)) {
		// pfind found the pid so not ESRCH, there's just no metadata
		LOGF("APP_INFO_RECORD_UNKNOWN pid=%d no_peer_metadata\n", pid);
		*Posix::GetErrorAddr() = Posix::POSIX_ENOSYS;
		return LibKernel::KERNEL_ERROR_ENOSYS;
	}

	if (!process.has_category) {
		LOGF("APP_INFO_CATEGORY_UNAVAILABLE pid=%d no_record_returned=1\n", pid);
		return LibKernel::KERNEL_ERROR_ENOENT;
	}

	// Native callers only show the category at +0x50 of the 0x58-byte record. The rest, including
	// the id at +0, stays zero.
	std::array<uint8_t, 0x58> record {};
	std::memcpy(record.data() + 0x50, &process.category, sizeof(process.category));
	if (!LibKernel::Memory::CopyToGuest(info, record.data(), record.size()))
		return LibKernel::KERNEL_ERROR_EFAULT;
	LOGF("\t pid = %d, category = 0x%x\n", pid, process.category);
	return OK;
}
int KYTY_SYSV_ABI KernelGetProcessName(int pid, char* name) {
	PRINT_NAME();

	// Ids above 99999 are thread ids, which the native wrapper (+0x15860) turns away before its
	// thr_get_name syscall.
	std::string process_name;
	if (pid > 99999 || !LibKernel::Process::FindNameByPid(pid, &process_name)) {
		return LibKernel::KERNEL_ERROR_ESRCH;
	}

	strncpy(name, process_name.c_str(), 32);
	name[31] = '\0';
	LOGF("\t pid = %d, name = %s\n", pid, name);
	return OK;
}
int KYTY_SYSV_ABI KernelGetAppCategoryType(int pid, int* category) {
	PRINT_NAME();

	if (category == nullptr) {
		return LibKernel::KERNEL_ERROR_EINVAL;
	}

	LibKernel::AppMount::Record record {};
	bool                        committed = false;
	const int access = LibKernel::AppMount::GetAppInfo(pid, 0x58, &record, &committed);
	if (access != 0) {
		*Posix::GetErrorAddr() = access;
		return LibKernel::KERNEL_ERROR_UNKNOWN + access;
	}
	if (committed) {
		return LibKernel::Memory::CopyToGuest(category, record.data() + 0x50, sizeof(*category))
		           ? OK
				   : LibKernel::KERNEL_ERROR_EFAULT;
	}

	LibKernel::Process::PeerProcess process;
	if (!LibKernel::Process::FindPeerByPid(pid, &process)) {
		// pfind found the pid so not ESRCH, there's just no metadata
		LOGF("APP_INFO_RECORD_UNKNOWN pid=%d no_peer_metadata\n", pid);
		*Posix::GetErrorAddr() = Posix::POSIX_ENOSYS;
		return LibKernel::KERNEL_ERROR_ENOSYS;
	}

	if (!process.has_category) {
		return LibKernel::KERNEL_ERROR_ENOENT;
	}

	if (!LibKernel::Memory::CopyToGuest(category, &process.category, sizeof(process.category))) {
		return LibKernel::KERNEL_ERROR_EFAULT;
	}
	LOGF("\t pid = %d, category = 0x%x\n", pid, process.category);
	return OK;
}
// fh-Bb3wl0Vs: AgcCompositor reads the app record category by app id rather than by pid.
int KYTY_SYSV_ABI KernelGetAppCategoryTypeByAppId(int32_t app_id, int* category) {
	PRINT_NAME();
	if (category == nullptr) {
		return LibKernel::KERNEL_ERROR_EINVAL;
	}
	uint32_t  value  = 0;
	const int access = LibKernel::AppMount::AppInfoById(
	    app_id, sizeof(LibKernel::AppMount::Record), 0,
	    [&value](LibKernel::AppMount::Record& record) {
		    std::memcpy(&value, record.data() + 0x50, sizeof(value));
		    return 0;
	    });
	if (access != 0) {
		*Posix::GetErrorAddr() = access;
		return LibKernel::KERNEL_ERROR_UNKNOWN + access;
	}
	if (!LibKernel::Memory::CopyToGuest(category, &value, sizeof(value))) {
		return LibKernel::KERNEL_ERROR_EFAULT;
	}
	LOGF("\t app_id = %d, category = 0x%x\n", app_id, value);
	return OK;
}
int KYTY_SYSV_ABI TraceSysCoreGetShellCoreAppId(int32_t* app_id) {
	auto* rt          = Common::Singleton<Loader::RuntimeLinker>::Instance();
	auto  module_path = ResolveNativeModulePath("/system/common/lib/libSceSysCore.sprx");
	auto* program     = rt->FindProgramByFileName(module_path);
	EXIT_IF(program == nullptr);
	auto* initialized = reinterpret_cast<uint8_t*>(program->base_vaddr + 0x10048);
	auto* connected   = reinterpret_cast<uint8_t*>(program->base_vaddr + 0x10049);
	LOGF("SysCore get app id before: initialized=%u connected=%u\n",
	     static_cast<unsigned>(*initialized), static_cast<unsigned>(*connected));
	using get_func_t  = KYTY_SYSV_ABI int (*)(int32_t*);
	const auto result = reinterpret_cast<get_func_t>(program->base_vaddr + 0xaf0)(app_id);
	LOGF("SysCore get app id after: initialized=%u connected=%u result=0x%08x app_id=0x%08x\n",
	     static_cast<unsigned>(*initialized), static_cast<unsigned>(*connected),
	     static_cast<unsigned>(result),
	     app_id != nullptr ? static_cast<unsigned>(*app_id) : 0xffffffffu);
	return result;
}
int KYTY_SYSV_ABI TraceIpmiCreateClient(void** out_client, void* config, void* arg, void* storage) {
	auto* rt          = Common::Singleton<Loader::RuntimeLinker>::Instance();
	auto  module_path = ResolveNativeModulePath("/system/common/lib/libSceIpmi.sprx");
	auto* program     = rt->FindProgramByFileName(module_path);
	EXIT_IF(program == nullptr);

	const auto before = storage != nullptr ? *reinterpret_cast<uint64_t*>(storage) : 0;
	LOGF("IPMI create before: out=%016" PRIx64 " storage=%016" PRIx64 " first=%016" PRIx64 "\n",
	     reinterpret_cast<uint64_t>(out_client), reinterpret_cast<uint64_t>(storage), before);

	using create_func_t = KYTY_SYSV_ABI int (*)(void**, void*, void*, void*);
	const auto result   = reinterpret_cast<create_func_t>(program->base_vaddr +
	                                                      0x10a0)(out_client, config, arg, storage);

	const auto client = out_client != nullptr ? reinterpret_cast<uint64_t>(*out_client) : 0;
	const auto vtable = client != 0 ? *reinterpret_cast<const uint64_t*>(client) : 0;
	const auto slot58 = vtable != 0 ? *reinterpret_cast<const uint64_t*>(vtable + 0x58) : 0;
	LOGF("IPMI create after: result=0x%08x client=%016" PRIx64 " vtable=%016" PRIx64
	     " slot58=%016" PRIx64 " expected_vtable=%016" PRIx64 "\n",
	     static_cast<unsigned>(result), client, vtable, slot58, program->base_vaddr + 0xc010);
	return result;
}
int KYTY_SYSV_ABI KernelAioInitializeImpl(void* param, int32_t size) {
	PRINT_NAME();

	LOGF("\t param = 0x%016" PRIx64 "\n"
	     "\t size  = 0x%08" PRIx32 "\n",
	     reinterpret_cast<uint64_t>(param), static_cast<uint32_t>(size));

	return OK;
}

void KYTY_SYSV_ABI KernelAioInitializeParam(void* param) {
	PRINT_NAME();

	LOGF("\t param = 0x%016" PRIx64 "\n", reinterpret_cast<uint64_t>(param));
}

constexpr int32_t KERNEL_AIO_STATE_SUBMITTED  = 1;
constexpr int32_t KERNEL_AIO_STATE_PROCESSING = 2;
constexpr int32_t KERNEL_AIO_STATE_COMPLETED  = 3;
constexpr int32_t KERNEL_AIO_STATE_ABORTED    = 4;
constexpr int32_t KERNEL_AIO_STATE_NOTIFIED   = 0x10000;
constexpr int32_t KERNEL_AIO_MAX_QUEUE        = 512;
constexpr int32_t KERNEL_AIO_MAX_REQUESTS     = 128;

struct KernelAioResult {
	int64_t  return_value;
	uint32_t state;
};

struct KernelAioRwRequest {
	int64_t          offset;
	size_t           nbyte;
	void*            buf;
	KernelAioResult* result;
	int32_t          fd;
};

static std::array<std::atomic_int32_t, KERNEL_AIO_MAX_QUEUE> g_kernel_aio_state = {};
static std::atomic_int32_t                                   g_kernel_aio_next_id {1};

static int32_t kernel_aio_next_id() {
	const auto sequence = g_kernel_aio_next_id.fetch_add(1, std::memory_order_relaxed);
	return ((sequence - 1) % (KERNEL_AIO_MAX_QUEUE - 1)) + 1;
}

static bool kernel_aio_is_valid_id(int32_t id) {
	return id > 0 && id < KERNEL_AIO_MAX_QUEUE;
}

int KYTY_SYSV_ABI KernelAioSubmitReadCommands(KernelAioRwRequest* req, int32_t size, int32_t prio,
                                              int32_t* id) {
	PRINT_NAME();

	if (req == nullptr || id == nullptr) {
		return LibKernel::KERNEL_ERROR_EFAULT;
	}

	if (size <= 0 || size > KERNEL_AIO_MAX_REQUESTS) {
		return LibKernel::KERNEL_ERROR_EINVAL;
	}

	const auto submit_id = kernel_aio_next_id();
	g_kernel_aio_state[submit_id].store(KERNEL_AIO_STATE_PROCESSING, std::memory_order_release);

	for (int32_t i = 0; i < size; i++) {
		if (req[i].result == nullptr) {
			g_kernel_aio_state[submit_id].store(KERNEL_AIO_STATE_ABORTED,
			                                    std::memory_order_release);
			return LibKernel::KERNEL_ERROR_EFAULT;
		}

		req[i].result->state = KERNEL_AIO_STATE_SUBMITTED;

		const auto result =
		    LibKernel::FileSystem::KernelPread(req[i].fd, req[i].buf, req[i].nbyte, req[i].offset);

		req[i].result->return_value = result;
		req[i].result->state = (result < 0 ? KERNEL_AIO_STATE_ABORTED : KERNEL_AIO_STATE_COMPLETED);
	}

	g_kernel_aio_state[submit_id].store(KERNEL_AIO_STATE_COMPLETED, std::memory_order_release);
	*id = submit_id;

	(void)prio;
	return OK;
}

int KYTY_SYSV_ABI KernelAioSubmitWriteCommands(KernelAioRwRequest* req, int32_t size, int32_t prio,
                                               int32_t* id) {
	PRINT_NAME();

	if (req == nullptr || id == nullptr) {
		return LibKernel::KERNEL_ERROR_EFAULT;
	}

	if (size <= 0 || size > KERNEL_AIO_MAX_REQUESTS) {
		return LibKernel::KERNEL_ERROR_EINVAL;
	}

	const auto submit_id = kernel_aio_next_id();
	g_kernel_aio_state[submit_id].store(KERNEL_AIO_STATE_PROCESSING, std::memory_order_release);

	for (int32_t i = 0; i < size; i++) {
		if (req[i].result == nullptr) {
			g_kernel_aio_state[submit_id].store(KERNEL_AIO_STATE_ABORTED,
			                                    std::memory_order_release);
			return LibKernel::KERNEL_ERROR_EFAULT;
		}

		req[i].result->state = KERNEL_AIO_STATE_SUBMITTED;

		const auto result =
		    LibKernel::FileSystem::KernelPwrite(req[i].fd, req[i].buf, req[i].nbyte, req[i].offset);

		req[i].result->return_value = result;
		req[i].result->state = (result < 0 ? KERNEL_AIO_STATE_ABORTED : KERNEL_AIO_STATE_COMPLETED);
	}

	g_kernel_aio_state[submit_id].store(KERNEL_AIO_STATE_COMPLETED, std::memory_order_release);
	*id = submit_id;

	(void)prio;
	return OK;
}

int KYTY_SYSV_ABI KernelAioPollRequest(int32_t id, int32_t* state) {
	PRINT_NAME();

	if (state == nullptr) {
		return LibKernel::KERNEL_ERROR_EFAULT;
	}

	if (!kernel_aio_is_valid_id(id)) {
		*state = LibKernel::KERNEL_ERROR_ESRCH;
		return OK;
	}

	auto current = g_kernel_aio_state[id].load(std::memory_order_acquire);
	while (current == KERNEL_AIO_STATE_COMPLETED || current == KERNEL_AIO_STATE_ABORTED) {
		if (g_kernel_aio_state[id].compare_exchange_weak(current, current | KERNEL_AIO_STATE_NOTIFIED,
		                                                std::memory_order_acq_rel)) {
			break;
		}
	}
	*state = current == 0 ? LibKernel::KERNEL_ERROR_ESRCH : current;
	return OK;
}

int KYTY_SYSV_ABI KernelAioPollRequests(int32_t* ids, int32_t num, int32_t* states) {
	if (ids == nullptr || states == nullptr) {
		return LibKernel::KERNEL_ERROR_EFAULT;
	}
	if (num <= 0 || num > KERNEL_AIO_MAX_REQUESTS) {
		return LibKernel::KERNEL_ERROR_EINVAL;
	}
	for (int32_t i = 0; i < num; i++) {
		KernelAioPollRequest(ids[i], &states[i]);
	}
	return OK;
}

int KYTY_SYSV_ABI KernelAioWaitRequest(int32_t id, int32_t* state, uint32_t* usec) {
	PRINT_NAME();

	if (state == nullptr) {
		return LibKernel::KERNEL_ERROR_EFAULT;
	}

	if (!kernel_aio_is_valid_id(id)) {
		return KernelAioPollRequest(id, state);
	}

	uint32_t waited  = 0;
	auto     current = g_kernel_aio_state[id].load(std::memory_order_acquire);
	while (current == KERNEL_AIO_STATE_PROCESSING) {
		if (usec != nullptr && *usec != 0 && waited >= *usec) {
			*state = current;
			return LibKernel::KERNEL_ERROR_ETIMEDOUT;
		}

		Common::Thread::SleepMicro(10);
		waited += 10;
		current = g_kernel_aio_state[id].load(std::memory_order_acquire);
	}

	return KernelAioPollRequest(id, state);
}

int KYTY_SYSV_ABI KernelAioDeleteRequest(int32_t id, int32_t* ret) {
	PRINT_NAME();

	if (ret == nullptr) {
		return LibKernel::KERNEL_ERROR_EFAULT;
	}

	if (!kernel_aio_is_valid_id(id)) {
		*ret = LibKernel::KERNEL_ERROR_ESRCH;
		return OK;
	}

	auto current = g_kernel_aio_state[id].load(std::memory_order_acquire);
	for (;;) {
		const auto state = current & ~KERNEL_AIO_STATE_NOTIFIED;
		if (state != KERNEL_AIO_STATE_COMPLETED && state != KERNEL_AIO_STATE_ABORTED) {
			*ret = current == 0 ? LibKernel::KERNEL_ERROR_ESRCH : LibKernel::KERNEL_ERROR_EBUSY;
			break;
		}
		if (g_kernel_aio_state[id].compare_exchange_weak(current, 0, std::memory_order_acq_rel)) {
			*ret = OK;
			break;
		}
	}
	return OK;
}

int KYTY_SYSV_ABI KernelAioDeleteRequests(int32_t* ids, int32_t num, int32_t* rets) {
	if (ids == nullptr || rets == nullptr) {
		return LibKernel::KERNEL_ERROR_EFAULT;
	}
	if (num <= 0 || num > KERNEL_AIO_MAX_REQUESTS) {
		return LibKernel::KERNEL_ERROR_EINVAL;
	}
	for (int32_t i = 0; i < num; i++) {
		KernelAioDeleteRequest(ids[i], &rets[i]);
	}
	return OK;
}

namespace FileSystem = LibKernel::FileSystem;
namespace Memory     = LibKernel::Memory;
namespace EventQueue = LibKernel::EventQueue;
namespace EventFlag  = LibKernel::EventFlag;
namespace Semaphore  = LibKernel::Semaphore;

namespace Fiber {

LIB_DEFINE(InitFiber_1) {
	LIB_FUNC("hVYD7Ou2pCQ", Fiber::FiberInitialize);
	LIB_FUNC("7+OJIpko9RY", Fiber::FiberInitializeInternal);
	LIB_FUNC("asjUJJ+aa8s", Fiber::FiberOptParamInitialize);
	LIB_FUNC("JeNX5F-NzQU", Fiber::FiberFinalize);
	LIB_FUNC("a0LLrZWac0M", Fiber::FiberRun);
	LIB_FUNC("PFT2S-tJ7Uk", Fiber::FiberSwitch);
	LIB_FUNC("p+zLIOg27zU", Fiber::FiberGetSelf);
	LIB_FUNC("B0ZX2hx9DMw", Fiber::FiberReturnToThread);
	LIB_FUNC("avfGJ94g36Q", Fiber::FiberRun);
	LIB_FUNC("ZqhZFuzKT6U", Fiber::FiberSwitch);
	LIB_FUNC("uq2Y5BFz0PE", Fiber::FiberGetInfo);
	LIB_FUNC("Lcqty+QNWFc", Fiber::FiberStartContextSizeCheck);
	LIB_FUNC("Kj4nXMpnM8Y", Fiber::FiberStopContextSizeCheck);
	LIB_FUNC("JzyT91ucGDc", Fiber::FiberRename);
	LIB_FUNC("0dy4JtMUcMQ", Fiber::FiberGetThreadFramePointerAddress);
}

} // namespace Fiber

namespace Coredump {

LIB_DEFINE(InitCoredump_1) {
	LIB_FUNC("8zLSfEfW5AU", Coredump::sceCoredumpRegisterCoredumpHandler);
	LIB_FUNC("fFkhOgztiCA", Coredump::sceCoredumpUnregisterCoredumpHandler);
}

} // namespace Coredump

LIB_DEFINE(InitLibKernel_1_FS) {
	LIB_FUNC("1G3lF1Gg1k8", FileSystem::KernelOpen);
	LIB_FUNC("UK2Tl2DWUns", FileSystem::KernelClose);
	LIB_FUNC("Cg4srZ6TKbU", FileSystem::KernelRead);
	LIB_FUNC("4wSze92BhLI", FileSystem::KernelWrite);
	LIB_FUNC("+r3rMFwItV4", FileSystem::KernelPread);
	LIB_FUNC("yTj62I7kw4s", FileSystem::KernelPreadv);
	LIB_FUNC("nKWi-N2HBV4", FileSystem::KernelPwrite);
	LIB_FUNC("mBd4AfLP+u8", FileSystem::KernelPwritev);
	LIB_FUNC("eV9wAD2riIA", FileSystem::KernelStat);
	LIB_FUNC("kBwCPsYX-m4", FileSystem::KernelFstat);
	LIB_FUNC("AUXVxWeJU-A", FileSystem::KernelUnlink);
	LIB_FUNC("52NcYU9+lEo", FileSystem::KernelRename);
	LIB_FUNC("taRWhTJFTgE", FileSystem::KernelGetdirentries);
	LIB_FUNC("oib76F-12fk", FileSystem::KernelLseek);
	LIB_FUNC("j2AIqSqJP0w", FileSystem::KernelGetdents);
	LIB_FUNC("1-LFLmRFxxM", FileSystem::KernelMkdir);
	LIB_FUNC("naInUjYt3so", FileSystem::KernelRmdir);
	LIB_FUNC("uWyW3v98sU4", FileSystem::KernelCheckReachability);
}

// unmount(2), syscall 22
static int KYTY_SYSV_ABI KernelUnmount(const char* path, int flags) {
	const int result = LibKernel::FileSystem::KernelUnmount(path, flags);
	if (result != OK) {
		*Posix::GetErrorAddr() = LibKernel::KernelToPosix(result);
		return -1;
	}
	return 0;
}
// 7NwggrWJ5cA (+0x1a00) is the raw 0x214 wrapper under libSceRegMgr, which reads errno after any
// nonzero return
static int KYTY_SYSV_ABI DiagnosticRegMgrCall(uint64_t op, uint64_t reg_id, int32_t* status,
                                              void* value, size_t size) {
	const auto reply = NativeKernelBridge::DispatchSyscall(
	    {0x214,
		 {op, reg_id, reinterpret_cast<uint64_t>(status), reinterpret_cast<uint64_t>(value),
		  static_cast<uint64_t>(size)}});
	if (reply.posix_errno != 0) {
		*Posix::GetErrorAddr() = reply.posix_errno;
	}
	return static_cast<int>(reply.value);
}
LIB_DEFINE(InitLibKernel_1_Mem) {
	LIB_FUNC("mL8NDH86iQI", Memory::KernelMapNamedFlexibleMemory);
	LIB_FUNC("IWIBBdTHit4", Memory::KernelMapFlexibleMemory);
	LIB_FUNC("DGMG3JshrZU", Memory::KernelSetVirtualRangeName);
	LIB_FUNC("mkgXxsoxWHg", Memory::KernelClearVirtualRangeName);
	// 6xx
	LIB_FUNC("4h6F1LLbTiw", Memory::KernelMapFlexibleMemory);
	LIB_FUNC("cQke9UuBQOk", Memory::KernelMunmap);
	LIB_FUNC("pO96TwzOm5E", Memory::KernelGetDirectMemorySize);
	LIB_FUNC("C0f7TJcbfac", Memory::KernelAvailableDirectMemorySize);
	LIB_FUNC("tZ2yplY8MBY", Memory::KernelGetPageTableStats);
	LIB_FUNC("rTXw65xmLIA", Memory::KernelAllocateDirectMemory);
	LIB_FUNC("B+vc2AO2Zrc", Memory::KernelAllocateMainDirectMemory);
	LIB_FUNC("rVjRvHJ0X6c", Memory::KernelVirtualQuery);
	LIB_FUNC("yDBwVAolDgg", Memory::KernelIsStack);
	LIB_FUNC("7oxv3PPCumo", Memory::KernelReserveVirtualRange);
	LIB_FUNC("L-Q3LEjIbgA", Memory::KernelMapDirectMemory);
	LIB_FUNC("BQQniolj9tQ", Memory::KernelMapDirectMemory2);
	LIB_FUNC("NcaWUxfMNIQ", Memory::KernelMapNamedDirectMemory);
	LIB_FUNC("BohYr-F7-is", Memory::KernelSetPrtAperture);
	LIB_FUNC("L0v2Go5jOuM", Memory::KernelGetPrtAperture);
	LIB_FUNC("hwVSPCmp5tM", Memory::KernelCheckedReleaseDirectMemory);
	LIB_FUNC("MBuItvba6z8", Memory::KernelReleaseDirectMemory);
	LIB_FUNC("jh+8XiK4LeE", Memory::KernelIsAddressSanitizerEnabled);
	LIB_FUNC("WFcfL2lzido", Memory::KernelQueryMemoryProtection);
	LIB_FUNC("BHouLQzh0X0", Memory::KernelDirectMemoryQuery);
	LIB_FUNC("aNz11fnnzi4", Memory::KernelAvailableFlexibleMemorySize);
	LIB_FUNC("n1-v6FgU7MQ", Memory::KernelConfiguredFlexibleMemorySize);
	LIB_FUNC("vSMAm3cxYTY", Memory::KernelMprotect);
	LIB_FUNC("9bfdLIyuwCY", Memory::KernelMtypeprotect);
	LIB_FUNC("2SKEx6bSq-4", Memory::KernelBatchMap);
	LIB_FUNC("kBJzF8x4SyE", Memory::KernelBatchMap2);
	LIB_FUNC("pU-QydtGcGY", Memory::KernelMemoryPoolReserve);
	LIB_FUNC("qCSfqDILlns", Memory::KernelMemoryPoolExpand);
	LIB_FUNC("Vzl66WmfLvk", Memory::KernelMemoryPoolCommit);
	LIB_FUNC("LXo1tpFqJGs", Memory::KernelMemoryPoolDecommit);
	LIB_FUNC("YN878uKRBbE", Memory::KernelMemoryPoolBatch);
	LIB_FUNC("bvD+95Q6asU", Memory::KernelMemoryPoolGetBlockStats);
}

LIB_DEFINE(InitLibKernel_1_Equeue) {
	LIB_FUNC("D0OdFMjp46I", EventQueue::KernelCreateEqueue);
	LIB_FUNC("jpFjmgAC5AE", EventQueue::KernelDeleteEqueue);
	LIB_FUNC("fzyMKs9kim0", EventQueue::KernelWaitEqueue);
	LIB_FUNC("vz+pg2zdopI", EventQueue::KernelGetEventUserData);
	LIB_FUNC("mJ7aghmgvfc", EventQueue::KernelGetEventId);
	LIB_FUNC("23CPPI1tyBY", EventQueue::KernelGetEventFilter);
	LIB_FUNC("kwGyyjohI50", EventQueue::KernelGetEventData);
	LIB_FUNC("Q0qr9AyqJSk", EventQueue::KernelGetEventFflags);
	LIB_FUNC("Uu-iDFC9aUc", EventQueue::KernelGetEventError);
	LIB_FUNC("4R6-OvI2cEA", EventQueue::KernelAddUserEvent);
	LIB_FUNC("WDszmSbWuDk", EventQueue::KernelAddUserEventEdge);
	LIB_FUNC("F6e0kwo4cnk", EventQueue::KernelTriggerUserEvent);
	LIB_FUNC("LJDwdSNTnDg", EventQueue::KernelDeleteUserEvent);
	LIB_FUNC("57ZK+ODEXWY", EventQueue::KernelAddTimerEvent);
	LIB_FUNC("R74tt43xP6k", EventQueue::KernelAddHRTimerEvent);
	LIB_FUNC("J+LF6LwObXU", EventQueue::KernelDeleteHRTimerEvent);
	LIB_FUNC("bBfz7kMF2Ho", EventQueue::KernelAddAmprEvent);
	LIB_FUNC("vuae5JPNt9A", EventQueue::KernelAddAmprSystemEvent);
	LIB_FUNC("bMmid3pfyjo", EventQueue::KernelDeleteAmprEvent);
	LIB_FUNC("Ij+ryuEClXQ", EventQueue::KernelDeleteAmprSystemEvent);
}

LIB_DEFINE(InitLibKernel_1_EventFlag) {
	LIB_FUNC("PZku4ZrXJqg", EventFlag::KernelCancelEventFlag);
	LIB_FUNC("7uhBFWRAS60", EventFlag::KernelClearEventFlag);
	LIB_FUNC("BpFoboUJoZU", EventFlag::KernelCreateEventFlag);
	LIB_FUNC("8mql9OcQnd4", EventFlag::KernelDeleteEventFlag);
	LIB_FUNC("1vDaenmJtyA", EventFlag::KernelOpenEventFlag);
	LIB_FUNC("s9-RaxukuzQ", EventFlag::KernelCloseEventFlag);
	LIB_FUNC("9lvj5DjHZiA", EventFlag::KernelPollEventFlag);
	LIB_FUNC("JTvBflhYazQ", EventFlag::KernelWaitEventFlag);
	LIB_FUNC("IOnSvHzqu6A", EventFlag::KernelSetEventFlag);
}

LIB_DEFINE(InitLibKernel_1_Semaphore) {
	LIB_FUNC("188x57JYp0g", Semaphore::KernelCreateSema);
	LIB_FUNC("MwhHNKdBXq8", Semaphore::KernelOpenSema);
	LIB_FUNC("HBkUky2PZPA", Semaphore::KernelCloseSema);
	LIB_FUNC("R1Jvn8bSCW8", Semaphore::KernelDeleteSema);
	LIB_FUNC("Zxa0VhQVTsk", Semaphore::KernelWaitSema);
	LIB_FUNC("12wOHk8ywb0", Semaphore::KernelPollSema);
	LIB_FUNC("4czppHBiriw", Semaphore::KernelSignalSema);
	LIB_FUNC("4DM06U2BNEY", Semaphore::KernelCancelSema);
	LIB_FUNC("GEnUkDZoUwY", Semaphore::PthreadSemInit);
	LIB_FUNC("Vwc+L05e6oE", Semaphore::PthreadSemDestroy);
	LIB_FUNC("C36iRE0F5sE", Semaphore::PthreadSemWait);
	LIB_FUNC("H2a+IN9TP0E", Semaphore::PthreadSemTrywait);
	LIB_FUNC("fjN6NQHhK8k", Semaphore::PthreadSemTimedwait);
	LIB_FUNC("aishVAiFaYM", Semaphore::PthreadSemPost);
	LIB_FUNC("DjpBvGlaWbQ", Semaphore::PthreadSemGetvalue);
}

static int KYTY_SYSV_ABI DiagnosticPsmThreadRename(LibKernel::Pthread thread, const char* name) {
	thread                 = LibKernel::PthreadHostObjectFor(thread);
	const bool target_self = thread != nullptr && thread == LibKernel::PthreadSelfOrNull();
	const int  result      = LibKernel::PthreadRename(thread, name);
	LOGF(
	    "FIRST_FRAME_AUDIT PSM_NATIVE_THREAD_RENAME target_self=%u name_present=%u result=0x%08x\n",
	    target_self ? 1u : 0u, name != nullptr ? 1u : 0u, static_cast<uint32_t>(result));
	return result;
}
LIB_DEFINE(InitLibKernel_1_Pthread) {
	LIB_FUNC("9UK1vLZQft4", LibKernel::PthreadMutexLock);
	LIB_FUNC("tn3VlD0hG60", LibKernel::PthreadMutexUnlock);
	LIB_FUNC("2Of0f+3mhhE", LibKernel::PthreadMutexDestroy);
	LIB_FUNC("cmo1RIYva9o", LibKernel::PthreadMutexInit);
	LIB_FUNC("upoVrzMHFeE", LibKernel::PthreadMutexTrylock);
	LIB_FUNC("smWEktiyyG0", LibKernel::PthreadMutexattrDestroy);
	LIB_FUNC("F8bUHwAG284", LibKernel::PthreadMutexattrInit);
	LIB_FUNC("iMp8QpE+XO4", LibKernel::PthreadMutexattrSettype);
	LIB_FUNC("1FGvU0i9saQ", LibKernel::PthreadMutexattrSetprotocol);

	LIB_FUNC("aI+OeCz8xrQ", LibKernel::PthreadSelf);
	LIB_FUNC("EotR8a3ASf4", LibKernel::PthreadSelf);
	LIB_FUNC("6UgtwV+0zb4", LibKernel::PthreadCreate);
	LIB_FUNC("3PtV6p3QNX4", LibKernel::PthreadEqual);
	LIB_FUNC("onNY9Byn-W8", LibKernel::PthreadJoin);
	LIB_FUNC("4qGrR6eoP9Y", LibKernel::PthreadDetach);
	LIB_FUNC("3kg7rT0NQIs", LibKernel::PthreadExit);
	LIB_FUNC("qBDmpCyGssE", LibKernel::PthreadCancel);
	LIB_FUNC("OAmWq+OHSjw", LibKernel::PthreadSetcancelstate);
	LIB_FUNC("sCJd99Phct0", LibKernel::PthreadSetcanceltype);
	LIB_FUNC("How7B8Oet6k", LibKernel::PthreadGetname);
	LIB_FUNC("GBUY7ywdULE", LibKernel::PthreadRename);
	LIB_FUNC("bt3CTBKmGyI", LibKernel::PthreadSetaffinity);
	LIB_FUNC("rcrVFJsQWRY", LibKernel::PthreadGetaffinity);
	LIB_FUNC("1tKyG7RlMJo", LibKernel::PthreadGetprio);
	LIB_FUNC("W0Hpm2X0uPE", LibKernel::PthreadSetprio);
	LIB_FUNC("T72hz6ffq08", LibKernel::PthreadYield);
	LIB_FUNC("6XG4B33N09g", LibKernel::PthreadYield);
	LIB_FUNC("CBNtXOoef-E", Posix::sched_get_priority_max);
	LIB_FUNC("m0iS6jNsXds", Posix::sched_get_priority_min);
	LIB_FUNC("EI-5-jlq2dE", LibKernel::PthreadGetthreadid);
	LIB_FUNC("geDaqgH9lTg", LibKernel::PthreadKeyCreate);
	LIB_FUNC("PrdHuuDekhY", LibKernel::PthreadKeyDelete);
	LIB_FUNC("+BzXYkqYeLE", LibKernel::PthreadSetspecific);
	LIB_FUNC("eoht7mQOCmo", LibKernel::PthreadGetspecific);

	LIB_FUNC("62KCwEMmzcM", LibKernel::PthreadAttrDestroy);
	LIB_FUNC("x1X76arYMxU", LibKernel::PthreadAttrGet);
	LIB_FUNC("8+s5BzZjxSg", LibKernel::PthreadAttrGetaffinity);
	LIB_FUNC("nsYoNRywwNg", LibKernel::PthreadAttrInit);
	LIB_FUNC("JaRMy+QcpeU", LibKernel::PthreadAttrGetdetachstate);
	LIB_FUNC("-quPa4SEJUw", LibKernel::PthreadAttrGetstack);
	LIB_FUNC("Ru36fiTtJzA", LibKernel::PthreadAttrGetstackaddr);
	LIB_FUNC("-fA+7ZlGDQs", LibKernel::PthreadAttrGetstacksize);
	LIB_FUNC("txHtngJ+eyc", LibKernel::PthreadAttrGetguardsize);
	LIB_FUNC("9RnL-m0+diQ", LibKernel::PthreadAttrGetsolosched);
	LIB_FUNC("Bvn74vj6oLo", LibKernel::PthreadAttrSetstack);
	LIB_FUNC("F+yfmduIBB8", LibKernel::PthreadAttrSetstackaddr);
	LIB_FUNC("UTXzJbWhhTE", LibKernel::PthreadAttrSetstacksize);
	LIB_FUNC("2Q0z6rnBrTE", LibKernel::PthreadAttrSetstacksize);
	LIB_FUNC("-Wreprtu0Qs", LibKernel::PthreadAttrSetdetachstate);
	LIB_FUNC("El+cQ20DynU", LibKernel::PthreadAttrSetguardsize);
	LIB_FUNC("eXbUSpEaTsA", LibKernel::PthreadAttrSetinheritsched);
	LIB_FUNC("DzES9hQF4f4", LibKernel::PthreadAttrSetschedparam);
	LIB_FUNC("4+h9EzwKF4I", LibKernel::PthreadAttrSetschedpolicy);
	LIB_FUNC("Dk6FC-TI+7Q", LibKernel::PthreadAttrSetsolosched);
	LIB_FUNC("3qxgM4ezETA", LibKernel::PthreadAttrSetaffinity);
	LIB_FUNC("FXPWHNk8Of0", LibKernel::PthreadAttrGetschedparam);

	LIB_FUNC("6ULAa0fq4jA", LibKernel::PthreadRwlockInit);
	LIB_FUNC("BB+kb08Tl9A", LibKernel::PthreadRwlockDestroy);
	LIB_FUNC("Ox9i0c7L5w0", LibKernel::PthreadRwlockRdlock);
	LIB_FUNC("iGjsr1WAtI0", LibKernel::PthreadRwlockRdlock);
	LIB_FUNC("+L98PIbGttk", LibKernel::PthreadRwlockUnlock);
	LIB_FUNC("EgmLo6EWgso", LibKernel::PthreadRwlockUnlock);
	LIB_FUNC("mqdNorrB+gI", LibKernel::PthreadRwlockWrlock);
	LIB_FUNC("sIlRvQqsN2Y", LibKernel::PthreadRwlockWrlock);
	LIB_FUNC("bIHoZCTomsI", LibKernel::PthreadRwlockTrywrlock);
	LIB_FUNC("XD3mDeybCnk", LibKernel::PthreadRwlockTryrdlock);
	LIB_FUNC("iPtZRWICjrM", LibKernel::PthreadRwlockTimedrdlock);
	LIB_FUNC("adh--6nIqTk", LibKernel::PthreadRwlockTimedwrlock);
	LIB_FUNC("i2ifZ3fS2fo", LibKernel::PthreadRwlockattrDestroy);
	LIB_FUNC("yOfGg-I1ZII", LibKernel::PthreadRwlockattrInit);
	LIB_FUNC("qsdmgXjqSgk", LibKernel::PthreadRwlockattrDestroy);
	LIB_FUNC("xFebsA4YsFI", LibKernel::PthreadRwlockattrInit);
	LIB_FUNC("h-OifiouBd8", LibKernel::PthreadRwlockattrSettype);

	LIB_FUNC("2Tb92quprl0", LibKernel::PthreadCondInit);
	LIB_FUNC("g+PZd2hiacg", LibKernel::PthreadCondDestroy);
	LIB_FUNC("RXXqi4CtF8w", LibKernel::PthreadCondDestroy);
	LIB_FUNC("WKAXJ4XBPQ4", LibKernel::PthreadCondWait);
	LIB_FUNC("JGgj7Uvrl+A", LibKernel::PthreadCondBroadcast);
	LIB_FUNC("kDh-NfxgMtE", LibKernel::PthreadCondSignal);
	LIB_FUNC("2MOy+rUfuhQ", LibKernel::PthreadCondSignal);
	LIB_FUNC("o69RpYO-Mu0", LibKernel::PthreadCondSignalto);
	LIB_FUNC("BmMjYxmew1w", LibKernel::PthreadCondTimedwait);
	LIB_FUNC("27bAgiJmOh0", Posix::pthread_cond_timedwait);
	LIB_FUNC("m5-2bsNfv7s", LibKernel::PthreadCondattrInit);
	LIB_FUNC("mKoTx03HRWA", Posix::pthread_condattr_init);
	LIB_FUNC("waPcxYiR3WA", LibKernel::PthreadCondattrDestroy);
	LIB_FUNC("dJcuQVn6-Iw", Posix::pthread_condattr_destroy);
	LIB_FUNC("EjllaAqAPZo", Posix::pthread_condattr_setclock);

	LIB_FUNC("wRYVA5Zolso", LibKernel::KernelClockGetres);
	LIB_FUNC("QBi7HCK03hw", LibKernel::KernelClockGettime);
	LIB_FUNC("ejekcaNQNq0", LibKernel::KernelGettimeofday);
	LIB_FUNC("kOcnerypnQA", LibKernel::KernelGettimezone);
	LIB_FUNC("0NTHN1NKONI", LibKernel::KernelConvertLocaltimeToUtc);
	LIB_FUNC("-o5uEDpN+oY", LibKernel::KernelConvertUtcToLocaltime);
	LIB_FUNC("n88vx3C5nW8", Posix::gettimeofday);
	LIB_FUNC("-2IRUCO--PM", LibKernel::KernelReadTsc);
	LIB_FUNC("1j3S3n-tTW4", LibKernel::KernelGetTscFrequency);
	LIB_FUNC("4J2sUJmuHZQ", LibKernel::KernelGetProcessTime);
	LIB_FUNC("BNowx2l588E", LibKernel::KernelGetProcessTimeCounterFrequency);
	LIB_FUNC("fgxnMeTNUtY", LibKernel::KernelGetProcessTimeCounter);

	LIB_FUNC("7H0iTOciTLo", Posix::pthread_mutex_lock);
	LIB_FUNC("2Z+PpY6CaJg", Posix::pthread_mutex_unlock);
	LIB_FUNC("IafI2PxcPnQ", LibKernel::PthreadMutexTimedlock);
	LIB_FUNC("Io9+nTKXZtA", Posix::pthread_mutex_timedlock);
	LIB_FUNC("mkx2fVhNMsg", Posix::pthread_cond_broadcast);
	LIB_FUNC("Op8TBGY5KHg", Posix::pthread_cond_wait);
	LIB_FUNC("14bOACANTBo", Posix::pthread_once);
	LIB_FUNC("Z4QosVuAsA0", Posix::pthread_once);
	LIB_FUNC("Oy6IpwgtYOk", Posix::lseek);
	LIB_FUNC("ezv-RSBNKqI", Posix::pread);
	LIB_FUNC("C2kJ-byS5rM", Posix::pwrite);
	LIB_FUNC("9eMlfusH4sU", Posix::flock);
	LIB_FUNC("mqQMh1zPPT8", Posix::fstat);

	LIB_FUNC("z0dtnPxYgtg", chmod);
	LIB_FUNC("W8f1adVl+48", chmod);
	LIB_FUNC("Xj9nET9tctI", KernelGetSpecialModelFlag);
	LIB_FUNC("a9683+DNj84", KernelIsEcoChargeAvailable);
	LIB_FUNC("X0HkB92+NRE", KernelIsAuthenticTrinity);
	LIB_FUNC("7siOfIbbg8I", KernelGetCurrentFanDuty);
	LIB_FUNC("CA5jcDb2vYI", KernelGetSocPowerConsumption);
	LIB_FUNC("igMefp4SAv0", KernelGetAuthinfo);
	LIB_FUNC("G-MYv5erXaU", KernelGetAppInfo);
	LIB_FUNC("d7xu4QDJw8Q", KernelGetAppInfo2);
	LIB_FUNC("HRDq-RDIGmI", KernelBeginAppMount2);
	LIB_FUNC("H69MYqpNjCc", KernelBeginAppMount);
	LIB_FUNC("CYIzY6OXyAs", KernelEndAppMount2);
	LIB_FUNC("QU57kCwF81U", KernelSetAppState);
	LIB_FUNC("WYCNbP+Q9kc", KernelGetAppState);
	LIB_FUNC("zsMzX135ofU", KernelGetAppInfoByAppId);
	LIB_FUNC("4P1e01mbenA", KernelGetProcessTypeOfBudget);
	LIB_FUNC("fh-Bb3wl0Vs", KernelGetAppCategoryTypeByAppId);
	LIB_FUNC("BVafm-M0GNw", KernelCreateBudget);
	LIB_FUNC("vs+KPSoE7AM", KernelDeleteBudget);
	LIB_FUNC("S2-4Sh3qnm8", KernelGetResourceLimit);
	LIB_FUNC("TQxbrxPdIxU", KernelGetResourceOne);
	LIB_FUNC("TUZlvaB9rlg", KernelGetAppInfoBit);
	LIB_FUNC("GGeRJk1XdWc", KernelQueryAppClassification);
	LIB_FUNC("+xy9ORMbd8U", KernelGetAppCategoryType);
	LIB_FUNC("fUJRLEbJOuQ", KernelGetProcessName);
	LIB_FUNC("VAzswvTOCzI", Posix::unlink);
	LIB_FUNC("c7ZnT7V1B98", Posix::rmdir);
	LIB_FUNC("JGMio+21L4c", Posix::mkdir);
	LIB_FUNC("wuCroIGjt2g", FileSystem::KernelOpen);
	LIB_FUNC("bY-PO6JhzhQ", FileSystem::KernelClose);
	LIB_FUNC("FN4gaPmuFV8", FileSystem::KernelWrite);
}

static void AddLibkernelUnityFunc(Loader::SymbolDatabase* s, const char* nid, uint64_t func,
                                  const std::string& dbg_name) {
	Loader::SymbolResolve sr {};
	sr.name                 = nid;
	sr.library              = "libkernel_unity";
	sr.library_version      = 1;
	sr.module               = "libkernel";
	sr.module_version_major = 1;
	sr.module_version_minor = 1;
	sr.type                 = Loader::SymbolType::Func;
	s->Add(sr, func, dbg_name);
}

LIB_DEFINE(InitLibKernel_1) {
	LIB_FUNC("04AjkP0jO9U", Posix::UmtxOp);
	InitLibKernel_1_FS(s);
	InitLibKernel_1_Mem(s);
	InitLibKernel_1_Equeue(s);
	InitLibKernel_1_EventFlag(s);
	InitLibKernel_1_Semaphore(s);
	InitLibKernel_1_Pthread(s);
	LibKernelApr::InitLibKernel_1_Apr(s);
	Posix::InitLibKernel_1_Posix(s);
	LibKernelWriteThrottling::InitLibKernelWriteThrottling(s);

	LIB_OBJECT("f7uOxY9mM1U", &LibKernel::g_stack_chk_guard);
	LIB_OBJECT("djxxOmW6-aw", &LibKernel::g_progname);

	LIB_FUNC("1jfXLRVzisc", LibKernel::KernelUsleep);
	LIB_FUNC("QcteRwbsnV0", LibKernel::KernelUsleep);
	LIB_FUNC("QvsZxomvUHs", LibKernel::KernelNanosleep);
	LIB_FUNC("LwG8g3niqwA", LibKernel::KernelDlsym);
	LIB_FUNC("-ZR+hG7aDHw", LibKernel::KernelSleep);
	LIB_FUNC("6c3rCVE-fTU", LibKernel::open);
	LIB_FUNC("6xVpy0Fdq+I", LibKernel::sigprocmask);
	LIB_FUNC("6Z83sYWFlA8", LibKernel::exit);
	LIB_FUNC("8OnWXlgQlvo", LibKernel::KernelRtldThreadAtexitDecrement);
	LIB_FUNC("959qrazPIrg", LibKernel::KernelGetProcParam);
	LIB_FUNC("tU5e3f9gSiU", LibKernel::KernelIsTrinityMode);
	LIB_FUNC("NH6xARDOVv8", LibKernel::KernelGetOperationMode);
	LIB_FUNC("fTx66l5iWIA", LibKernel::KernelFsync);
	LIB_FUNC("uvT2iYBBnkY", LibKernel::KernelSync);
	LIB_FUNC("HoLVWNanBBc", LibKernel::getpid);
	LIB_FUNC("9BcDykPmo1I", LibKernel::get_error_addr);
	LIB_FUNC("k+AXqu2-eBc", Posix::getpagesize);
	LIB_FUNC("bnZxYgAFeA0", LibKernel::KernelGetSanitizerNewReplaceExternal);
	LIB_FUNC("ca7v6Cxulzs", LibKernel::KernelSetGPO);
	LIB_FUNC("4oXYe9Xmk0Q", LibKernel::KernelGetGPI);
	LIB_FUNC("DRuBt2pvICk", LibKernel::read);
	LIB_FUNC("AqBioC2vF3I", LibKernel::read);
	LIB_FUNC("f7KBOafysXo", LibKernel::KernelGetModuleInfoFromAddr);
	LIB_FUNC("RpQJJVKTiFM", LibKernel::KernelGetModuleInfoForUnwind);
	LIB_FUNC("crb5j7mkk1c", LibKernel::KernelIsSignalReturn); // _is_signal_return
	LIB_FUNC("Fjc4-n1+y2g", LibKernel::elf_phdr_match_addr);
	LIB_FUNC("FxVZqBAA7ks", LibKernel::write);
	LIB_FUNC("FJmglmTMdr4", LibKernel::getargv);
	LIB_FUNC("kbw4UHHSYy0", LibKernel::pthread_cxa_finalize);
	LIB_FUNC("lLMT9vJAck0", LibKernel::clock_gettime);
	LIB_FUNC("5TgME6AYty4", KernelAioDeleteRequest);
	LIB_FUNC("Ft3EtsZzAoY", KernelAioDeleteRequests);
	LIB_FUNC("HgX7+AORI58", KernelAioSubmitReadCommands);
	LIB_FUNC("2pOuoWoCxdk", KernelAioPollRequest);
	LIB_FUNC("o7O4z3jwKzo", KernelAioPollRequests);
	LIB_FUNC("KOF-oJbQVvc", KernelAioWaitRequest);
	LIB_FUNC("XQ8C8y+de+E", KernelAioSubmitWriteCommands);
	LIB_FUNC("nu4a0-arQis", KernelAioInitializeParam);
	LIB_FUNC("il03nluKfMk", LibKernel::KernelRaiseException);
	LIB_FUNC("iKJMWrAumPE", LibKernel::getargc);
	LIB_FUNC("NNtFaKJbPt0", LibKernel::close);
	LIB_FUNC("OMDRKKAZ8I4", LibKernel::KernelDebugRaiseException);
	LIB_FUNC("Ou3iL1abvng", LibKernel::stack_chk_fail);
	LIB_FUNC("p5EcQeEeJAE", LibKernel::KernelRtldSetApplicationHeapAPI);
	LIB_FUNC("pB-yGZ2nQ9o", LibKernel::KernelSetThreadAtexitCount);
	LIB_FUNC("py6L8jiVAN8", LibKernel::KernelGetSanitizerMallocReplaceExternal);
	LIB_FUNC("Qhv5ARAoOEc", LibKernel::KernelRemoveExceptionHandler);
	LIB_FUNC("QKd0qM58Qes", LibKernel::KernelStopUnloadModule);
	LIB_FUNC("rNhWz+lvOMU", LibKernel::KernelSetThreadDtors);
	LIB_FUNC("Tz4RNUCBbGI", LibKernel::KernelRtldThreadAtexitIncrement);
	LIB_FUNC("vNe1w4diLCs", LibKernel::tls_get_addr);
	LIB_FUNC("vYU8P9Td2Zo", KernelAioInitializeImpl);
	LIB_FUNC("WhCc1w3EhSI", LibKernel::KernelSetThreadAtexitReport);
	LIB_FUNC("WkwEd3N7w0Y", LibKernel::KernelInstallExceptionHandler);
	LIB_FUNC("La9uyZv4Kvw", LibKernel::KernelGetAvailableCpumask);
	LIB_FUNC("g0VTBxfJyu0", LibKernel::KernelGetCurrentCpu);
	LIB_FUNC("wzvqT4UqKX8", LibKernel::KernelLoadStartModule);
	LIB_FUNC("Xjoosiw+XPI", LibKernel::KernelUuidCreate);
	LIB_FUNC("DLORcroUqbc", LibKernel::KernelGetOpenPsId);
	LIB_FUNC("zE-wXIZjLoM", LibKernel::KernelDebugRaiseExceptionOnReleaseMode);
	LIB_FUNC("Hc4CaR6JBL0", Posix::KernelSyncOnAddressWait);
	LIB_FUNC("B2n8aDorSH4", Posix::KernelSyncOnAddressWait32);
	LIB_FUNC("PZQhiiLXRFs", Posix::KernelSyncOnAddressWait64);
	LIB_FUNC("q2y-wDIVWZA", Posix::KernelSyncOnAddressWake);

	AddLibkernelUnityFunc(s, "Qhv5ARAoOEc",
	                      reinterpret_cast<uint64_t>(LibKernel::KernelRemoveExceptionHandler),
	                      "LibKernel::KernelRemoveExceptionHandler");
	AddLibkernelUnityFunc(s, "il03nluKfMk",
	                      reinterpret_cast<uint64_t>(LibKernel::KernelRaiseException),
	                      "LibKernel::KernelRaiseException");
	AddLibkernelUnityFunc(s, "WkwEd3N7w0Y",
	                      reinterpret_cast<uint64_t>(LibKernel::KernelInstallExceptionHandler),
	                      "LibKernel::KernelInstallExceptionHandler");
}

} // namespace Libs
