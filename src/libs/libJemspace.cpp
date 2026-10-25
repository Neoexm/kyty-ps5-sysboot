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
} // namespace Jemspace
} // namespace Libs
