#include "common/logging/log.h"
#include "libs/libs.h"
#include "loader/symbolDatabase.h"

#include <atomic>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <new>

namespace Libs {

namespace Jemspace {

struct Context {
	uint32_t              flags;
	uint64_t              limit;
	std::atomic<uint64_t> used {0};
	std::atomic<uint64_t> peak {0};
};

// just below each guest pointer, so aligned blocks free and size without a lookup
struct Block {
	void*    base;
	size_t   size;
	Context* context;
};

static std::mutex                  g_allocation_mutex;
static std::map<uintptr_t, size_t> g_allocations;

static auto FindAllocationLocked(uintptr_t address, uint64_t size) {
	auto allocation = g_allocations.upper_bound(address);
	if (allocation == g_allocations.begin()) return g_allocations.end();
	--allocation;
	const auto offset = address - allocation->first;
	if (offset > allocation->second || size > allocation->second - offset) {
		return g_allocations.end();
	}
	return allocation;
}

bool QueryAllocation(const void* ptr, uint64_t size, uint64_t* offset_out,
                     uint64_t* allocation_size_out) {
	if (offset_out != nullptr) *offset_out = 0;
	if (allocation_size_out != nullptr) *allocation_size_out = 0;
	if (ptr == nullptr) return false;
	const auto address = reinterpret_cast<uintptr_t>(ptr);
	if (size > std::numeric_limits<uintptr_t>::max() - address) return false;
	std::lock_guard lock(g_allocation_mutex);
	const auto      allocation = FindAllocationLocked(address, size);
	if (allocation == g_allocations.end()) return false;
	const auto offset = address - allocation->first;
	if (offset_out != nullptr) *offset_out = offset;
	if (allocation_size_out != nullptr) *allocation_size_out = allocation->second;
	return true;
}

bool ContainsAllocation(const void* ptr, uint64_t size) {
	return QueryAllocation(ptr, size, nullptr, nullptr);
}

bool CopyToAllocation(void* destination, const void* source, uint64_t size) {
	if (destination == nullptr || (source == nullptr && size != 0)) return false;
	const auto address = reinterpret_cast<uintptr_t>(destination);
	if (size > std::numeric_limits<uintptr_t>::max() - address) return false;
	std::lock_guard lock(g_allocation_mutex);
	if (FindAllocationLocked(address, size) == g_allocations.end()) return false;
	if (size != 0) std::memcpy(destination, source, size);
	return true;
}

bool CopyFromAllocation(void* destination, const void* source, uint64_t size) {
	if (source == nullptr || (destination == nullptr && size != 0)) return false;
	const auto address = reinterpret_cast<uintptr_t>(source);
	if (size > std::numeric_limits<uintptr_t>::max() - address) return false;
	std::lock_guard lock(g_allocation_mutex);
	if (FindAllocationLocked(address, size) == g_allocations.end()) return false;
	if (size != 0) std::memcpy(destination, source, size);
	return true;
}

static bool RegisterAllocation(uintptr_t address, size_t size) {
	try {
		std::lock_guard lock(g_allocation_mutex);
		return g_allocations.emplace(address, size).second;
	} catch (const std::bad_alloc&) {
		return false;
	}
}

static void RemoveAllocation(const void* ptr) {
	std::lock_guard lock(g_allocation_mutex);
	g_allocations.erase(reinterpret_cast<uintptr_t>(ptr));
}

static void* Allocate(Context* context, size_t align, size_t size) {
	const size_t requested_size = size;
	if (align < 16 || (align & (align - 1)) != 0) {
		align = 16;
	}
	if (size == 0) {
		size = 1;
	}
	if (size > std::numeric_limits<size_t>::max() - align - sizeof(Block)) {
		return nullptr;
	}
	if (context != nullptr) {
		auto used = context->used.fetch_add(size) + size;
		if (context->limit != 0 && used > context->limit) {
			context->used -= size;
			LOGF("Jemspace HLE limit: context=%p, limit=0x%" PRIx64 ", used=0x%" PRIx64
			     ", size=0x%" PRIx64 "\n",
			     static_cast<void*>(context), context->limit, used - size,
			     static_cast<uint64_t>(size));
			return nullptr;
		}
		auto peak = context->peak.load();
		while (used > peak && !context->peak.compare_exchange_weak(peak, used)) {
		}
	}
	void* base = std::malloc(size + align + sizeof(Block));
	if (base == nullptr) {
		if (context != nullptr) {
			context->used -= size;
		}
		return nullptr;
	}
	auto  addr     = (reinterpret_cast<uintptr_t>(base) + sizeof(Block) + align - 1) &
	                 ~(static_cast<uintptr_t>(align) - 1);
	auto* block    = reinterpret_cast<Block*>(addr) - 1;
	block->base    = base;
	block->size    = size;
	block->context = context;
	if (!RegisterAllocation(addr, requested_size)) {
		std::free(base);
		if (context != nullptr) {
			context->used -= size;
		}
		return nullptr;
	}
	return reinterpret_cast<void*>(addr);
}

static void* KYTY_SYSV_ABI Create(const char* name, uint64_t limit, uint32_t flags) {
	if (flags > 2 || name == nullptr) {
		return nullptr;
	}
	auto* context  = new Context;
	context->flags = flags;
	context->limit = limit;
	LOGF("Jemspace HLE create: %s, flags=0x%08x, limit=0x%" PRIx64 ", context=%p\n", name, flags,
	     limit, static_cast<void*>(context));
	return context;
}

static int KYTY_SYSV_ABI Destroy(Context* context) {
	if (context == nullptr) {
		return 22;
	}
	LOGF("Jemspace HLE destroy: context=%p, used=0x%" PRIx64 "\n", static_cast<void*>(context),
	     context->used.load());
	delete context;
	return 0;
}

static void* KYTY_SYSV_ABI Malloc(Context* context, size_t size) {
	return Allocate(context, 16, size);
}

static int KYTY_SYSV_ABI Free(void* context, void* ptr) {
	(void)context;
	if (ptr != nullptr) {
		RemoveAllocation(ptr);
		auto* block = static_cast<Block*>(ptr) - 1;
		if (block->context != nullptr) {
			block->context->used -= block->size;
		}
		std::free(block->base);
	}
	return 0;
}

static void* KYTY_SYSV_ABI Calloc(Context* context, size_t count, size_t size) {
	if (count != 0 && size > std::numeric_limits<size_t>::max() / count) {
		return nullptr;
	}
	void* ptr = Allocate(context, 16, count * size);
	if (ptr != nullptr) {
		std::memset(ptr, 0, count * size);
	}
	return ptr;
}

static void* KYTY_SYSV_ABI Memalign(Context* context, size_t align, size_t size) {
	return Allocate(context, align, size);
}

static void* KYTY_SYSV_ABI Realloc(Context* context, void* ptr, size_t size) {
	if (ptr == nullptr) {
		return Allocate(context, 16, size);
	}
	auto* old = static_cast<Block*>(ptr) - 1;
	// rallocx can grow in place; don't charge the old size alongside the new
	if (old->context != nullptr) {
		old->context->used -= old->size;
	}
	void* moved = Allocate(context, 16, size);
	if (moved == nullptr) {
		if (old->context != nullptr) {
			old->context->used += old->size;
		}
		return nullptr;
	}
	std::memcpy(moved, ptr, old->size < size ? old->size : size);
	RemoveAllocation(ptr);
	std::free(old->base);
	return moved;
}

static void KYTY_SYSV_ABI GetStats(Context* context, uint64_t* stats) {
	if (context == nullptr || stats == nullptr) {
		return;
	}
	// limit, committed, reserved, peak committed, peak reserved
	stats[0] = context->limit;
	stats[1] = context->used;
	stats[2] = context->used;
	stats[3] = context->peak;
	stats[4] = context->peak;
}

// usable size; natively je_malloc_usable_size. NULL gives 0.
static uint64_t KYTY_SYSV_ABI UsableSize(void* ptr) {
	if (ptr == nullptr) {
		return 0;
	}
	return (static_cast<Block*>(ptr) - 1)->size;
}

// allocates when ptr is null, else rallocx. ctx+0x94 (MALLOCX_ARENA) is ignored.
static void* KYTY_SYSV_ABI RallocAligned(Context* context, void* ptr, size_t align, size_t size) {
	if (ptr == nullptr) {
		return Allocate(context, align, size);
	}
	auto* old = static_cast<Block*>(ptr) - 1;
	if (old->context != nullptr) {
		old->context->used -= old->size;
	}
	void* moved = Allocate(context, align, size);
	if (moved == nullptr) {
		if (old->context != nullptr) {
			old->context->used += old->size;
		}
		return nullptr;
	}
	std::memcpy(moved, ptr, old->size < size ? old->size : size);
	RemoveAllocation(ptr);
	std::free(old->base);
	return moved;
}

// posix_memalign equivalent: 0x16 for a non power of two alignment, 0xc on allocation failure.
static int KYTY_SYSV_ABI PosixMemalign(Context* context, void** out, size_t align, size_t size) {
	(void)context;
	if (align == 0 || (align & (align - 1)) != 0) {
		return 0x16;
	}
	void* ptr = Allocate(context, align, size);
	if (ptr == nullptr) {
		return 0xc;
	}
	*out = ptr;
	return 0;
}

} // namespace Jemspace

namespace LibSceJemspace {

LIB_VERSION("SceJemspace", 1, "SceJemspace", 1, 1);

LIB_DEFINE(InitJemspace_1) {
	LIB_FUNC("PudtK6jPkKk", Jemspace::Create);
	LIB_FUNC("xi1kSeeeHko", Jemspace::Destroy);
	LIB_FUNC("IUMgip-Glc4", Jemspace::Malloc);
	LIB_FUNC("KMxjh6mb1yk", Jemspace::Free);
	LIB_FUNC("Ua4eXAn2rec", Jemspace::Calloc);
	LIB_FUNC("jwK0WHNUz+c", Jemspace::Memalign);
	LIB_FUNC("bmstosXtyt8", Jemspace::Realloc);
	LIB_FUNC("uuRDRq3yqII", Jemspace::GetStats);
}

} // namespace LibSceJemspace

namespace LibJemspaceV1 {

LIB_VERSION("Jemspace", 1, "Jemspace", 1, 0);

LIB_DEFINE(InitJemspace_1) {
	LIB_FUNC("HbsjU8cbCqQ", Jemspace::RallocAligned);
	LIB_FUNC("-aMNYbF70Ag", Jemspace::PosixMemalign);
	LIB_FUNC("qyDRGMvYK7U", Jemspace::UsableSize);
}

} // namespace LibJemspaceV1

LIB_DEFINE(InitJemspace_1) {
	LibSceJemspace::InitJemspace_1(s);
	LibJemspaceV1::InitJemspace_1(s);
}

} // namespace Libs
