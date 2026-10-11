#include "kernel/nullfsMount.h"

#include "kernel/tmpfs.h"
#include "libs/errno.h"

#include <algorithm>
#include <array>
#include <limits>
#include <mutex>
#include <new>
#include <utility>
#include <vector>

namespace Libs::LibKernel::NullfsMount {
namespace {

// console /mnt/sandbox: 16 sandboxes, ~26 mount dirs each
constexpr size_t MaximumMounts = 1024;
constexpr size_t MaximumChain  = 16;

struct MountRecord {
	std::string point;
	std::string source;
	uint64_t    generation = 0;
	uint64_t    flags      = 0;
};

std::mutex               mounts_mutex;
std::vector<MountRecord> mounts;
uint64_t                 next_generation = 1;

bool Matches(const std::string& point, const std::string& path) {
	return path.size() >= point.size() && path.compare(0, point.size(), point) == 0 &&
	       (path.size() == point.size() || path[point.size()] == '/');
}

bool Overlap(const std::string& left, const std::string& right) {
	return Matches(left, right) || Matches(right, left);
}

const MountRecord* FindMount(const std::vector<MountRecord>& records, const std::string& path) {
	const MountRecord* found = nullptr;
	for (const auto& mount: records) {
		if (!Matches(mount.point, path)) continue;
		if (found == nullptr || mount.point.size() > found->point.size()) found = &mount;
	}
	return found;
}

int ResolveLocked(const std::vector<MountRecord>& records, const std::string& path,
                  Resolution* resolution) {
	if (resolution == nullptr) return KERNEL_ERROR_EFAULT;
	std::string current;
	int         result = Tmpfs::NormalizePath(path, &current);
	if (result != OK) return result;
	std::array<uint64_t, MaximumChain> visited {};
	size_t                             visited_count    = 0;
	uint64_t                           first_generation = 0;
	bool                               read_only        = false;
	bool                               no_exec          = false;
	for (size_t depth = 0; depth <= MaximumChain; ++depth) {
		const auto* mount = FindMount(records, current);
		if (mount == nullptr) {
			*resolution = {std::move(current), first_generation, first_generation != 0, read_only,
			               no_exec};
			return OK;
		}
		if (std::find(visited.begin(), visited.begin() + visited_count, mount->generation) !=
		    visited.begin() + visited_count) {
			return KERNEL_ERROR_ELOOP;
		}
		if (visited_count == visited.size()) return KERNEL_ERROR_ELOOP;
		visited[visited_count++] = mount->generation;
		if (first_generation == 0) {
			first_generation = mount->generation;
			no_exec          = (mount->flags & FlagNoExec) != 0;
		}
		read_only |= (mount->flags & FlagReadOnly) != 0;
		std::string next = mount->source;
		next.append(current, mount->point.size(), std::string::npos);
		result = Tmpfs::NormalizePath(next, &current);
		if (result != OK) return result;
	}
	return KERNEL_ERROR_ELOOP;
}

int StageMount(std::vector<MountRecord>* records, uint64_t* generation, const std::string& point,
               const std::string& source, uint64_t flags) {
	if ((flags & ~(FlagReadOnly | FlagNoExec)) != 0) return KERNEL_ERROR_EOPNOTSUPP;
	std::string normalized_point;
	std::string normalized_source;
	int         result = Tmpfs::NormalizePath(point, &normalized_point);
	if (result != OK) return result;
	result = Tmpfs::NormalizePath(source, &normalized_source);
	if (result != OK) return result;
	if (normalized_point == "/") return KERNEL_ERROR_EINVAL;
	Resolution lower;
	result = ResolveLocked(*records, normalized_source, &lower);
	if (result != OK) return result;
	normalized_source = std::move(lower.path);
	// source is flattened past its aliases, so a read-only layer on the way still applies
	if (lower.read_only) flags |= FlagReadOnly;
	if (Overlap(normalized_point, normalized_source)) return KERNEL_ERROR_ELOOP;
	for (const auto& mount: *records) {
		if (Overlap(mount.point, normalized_point) || Overlap(mount.source, normalized_point))
			return KERNEL_ERROR_EBUSY;
	}
	if (records->size() >= MaximumMounts || *generation == 0 ||
	    *generation == std::numeric_limits<uint64_t>::max())
		return KERNEL_ERROR_ENOSPC;
	records->push_back({normalized_point, normalized_source, *generation, flags});
	Resolution verified;
	result = ResolveLocked(*records, normalized_point, &verified);
	if (result != OK) return result;
	++*generation;
	return OK;
}

} // namespace

int Mount(const std::string& point, const std::string& source, uint64_t flags) try {
	std::lock_guard lock(mounts_mutex);
	auto            staged     = mounts;
	auto            generation = next_generation;
	const int       result     = StageMount(&staged, &generation, point, source, flags);
	if (result != OK) return result;
	mounts.swap(staged);
	next_generation = generation;
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int SnapshotMounts(std::vector<MountInfo>* infos) try {
	if (infos == nullptr) return KERNEL_ERROR_EFAULT;
	std::lock_guard        lock(mounts_mutex);
	std::vector<MountInfo> snapshot;
	snapshot.reserve(mounts.size());
	for (const auto& mount: mounts)
		snapshot.push_back({mount.point, mount.source, mount.flags});
	infos->swap(snapshot);
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int ImportMounts(const std::vector<MountInfo>& infos) try {
	std::lock_guard lock(mounts_mutex);
	auto            staged     = mounts;
	auto            generation = next_generation;
	for (const auto& info: infos) {
		const int result = StageMount(&staged, &generation, info.point, info.source, info.flags);
		if (result != OK) return result;
		if (staged.back().point != info.point || staged.back().source != info.source)
			return KERNEL_ERROR_EINVAL;
	}
	mounts.swap(staged);
	next_generation = generation;
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int Unmount(const std::string& point) try {
	std::string normalized;
	const int   result = Tmpfs::NormalizePath(point, &normalized);
	if (result != OK) return result;
	std::lock_guard lock(mounts_mutex);
	const auto found = std::find_if(mounts.begin(), mounts.end(),
	                                [&](const auto& mount) { return mount.point == normalized; });
	if (found == mounts.end()) return KERNEL_ERROR_EINVAL;
	mounts.erase(found);
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

void Shutdown() {
	std::lock_guard lock(mounts_mutex);
	mounts.clear();
	next_generation = 1;
}

bool Contains(const std::string& path) try {
	std::string normalized;
	if (Tmpfs::NormalizePath(path, &normalized) != OK) return false;
	std::lock_guard lock(mounts_mutex);
	return FindMount(mounts, normalized) != nullptr;
} catch (const std::bad_alloc&) {
	return false;
}

bool IsMountPoint(const std::string& path) try {
	std::string normalized;
	if (Tmpfs::NormalizePath(path, &normalized) != OK) return false;
	std::lock_guard lock(mounts_mutex);
	return std::any_of(mounts.begin(), mounts.end(),
	                   [&](const auto& mount) { return mount.point == normalized; });
} catch (const std::bad_alloc&) {
	return true;
}

bool Overlaps(const std::string& path) try {
	std::string normalized;
	if (Tmpfs::NormalizePath(path, &normalized) != OK) return false;
	std::lock_guard lock(mounts_mutex);
	return std::any_of(mounts.begin(), mounts.end(),
	                   [&](const auto& mount) { return Overlap(mount.point, normalized); });
} catch (const std::bad_alloc&) {
	return true;
}

int Resolve(const std::string& path, Resolution* resolution) try {
	std::lock_guard lock(mounts_mutex);
	return ResolveLocked(mounts, path, resolution);
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

} // namespace Libs::LibKernel::NullfsMount
