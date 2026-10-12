#include "kernel/bfsMount.h"

#include "libs/errno.h"

#include <algorithm>
#include <limits>
#include <mutex>
#include <new>
#include <utility>

namespace Libs::LibKernel::BfsMount {
namespace {

struct MountRecord {
	std::string                point;
	std::shared_ptr<BfsVolume> volume;
	uint32_t                   device = 0;
};

std::mutex                                mounts_mutex;
std::vector<std::shared_ptr<MountRecord>> mounts;
uint32_t                                  next_device = 0xbf000000u;

int Error(BfsVolume::Result result) {
	switch (result) {
		case BfsVolume::Result::Ok: return OK;
		case BfsVolume::Result::Invalid: return KERNEL_ERROR_EINVAL;
		case BfsVolume::Result::NotFound: return KERNEL_ERROR_ENOENT;
		case BfsVolume::Result::NotDirectory: return KERNEL_ERROR_ENOTDIR;
		case BfsVolume::Result::IsDirectory: return KERNEL_ERROR_EISDIR;
		case BfsVolume::Result::Unsupported: return KERNEL_ERROR_ENOTSUP;
		case BfsVolume::Result::MissingData: return KERNEL_ERROR_EIO;
		default: return KERNEL_ERROR_EIO;
	}
}

bool Matches(const std::string& point, const std::string& path) {
	const bool prefix =
	    path.size() >= point.size() && std::equal(point.begin(), point.end(), path.begin());
	return point == "/" || (prefix && (path.size() == point.size() || path[point.size()] == '/'));
}

std::shared_ptr<MountRecord> FindMount(const std::string& path) {
	std::shared_ptr<MountRecord> found;
	for (const auto& mount: mounts) {
		if (Matches(mount->point, path) && (!found || mount->point.size() > found->point.size()))
			found = mount;
	}
	return found;
}

int Lookup(const std::shared_ptr<MountRecord>& mount, const std::string& path,
           BfsVolume::Entry* entry) {
	const auto relative = mount->point == "/"                  ? path
	                      : path.size() == mount->point.size() ? std::string {"/"}
	                                                           : path.substr(mount->point.size());
	return Error(mount->volume->Stat(relative, entry));
}

int Normalize(const std::string& path, std::string* normalized) {
	if (path.empty() || path.front() != '/' || path.find('\0') != path.npos ||
	    path.find('\\') != path.npos)
		return KERNEL_ERROR_EINVAL;
	if (path.size() >= 1024) return KERNEL_ERROR_ENAMETOOLONG;
	std::string walked = "/";
	for (size_t start = 1; start <= path.size();) {
		const auto end  = path.find('/', start);
		const auto part = path.substr(start, end == path.npos ? path.npos : end - start);
		if (!part.empty()) {
			if (part.size() > 255) return KERNEL_ERROR_ENAMETOOLONG;
			if (const auto mount = FindMount(walked)) {
				BfsVolume::Entry entry;
				const int        result = Lookup(mount, walked, &entry);
				if (result != OK) return result;
				if (!entry.directory) return KERNEL_ERROR_ENOTDIR;
			}
			if (part == "..") {
				const auto slash = walked.rfind('/');
				walked.resize(slash == 0 ? 1 : slash);
			} else if (part != ".") {
				if (walked.size() > 1) walked += '/';
				walked += part;
			}
		}
		if (end == path.npos) break;
		start = end + 1;
	}
	if (path.back() == '/' || path.ends_with("/.") || path.ends_with("/..")) {
		if (const auto mount = FindMount(walked)) {
			BfsVolume::Entry entry;
			const int        result = Lookup(mount, walked, &entry);
			if (result != OK) return result;
			if (!entry.directory) return KERNEL_ERROR_ENOTDIR;
		}
	}
	*normalized = std::move(walked);
	return OK;
}

NodeStat Metadata(const MountRecord& mount, const BfsVolume::Entry& entry) {
	const uint32_t mode = entry.mode != 0 ? entry.mode : (entry.directory ? 0040555u : 0100444u);
	return {mount.device, entry.inode, mode, entry.size, entry.size};
}

} // namespace

class Handle {
public:
	std::shared_ptr<MountRecord> mount;
	BfsVolume::Entry             entry;
	std::mutex                   mutex;
	uint64_t                     offset = 0;
};

int Mount(const std::string& point, std::shared_ptr<BfsVolume> volume) try {
	if (!volume) return KERNEL_ERROR_EINVAL;
	std::lock_guard lock(mounts_mutex);
	std::string     normalized;
	const int       result = Normalize(point, &normalized);
	if (result != OK) return result;
	for (const auto& mount: mounts) {
		if (Matches(mount->point, normalized) || Matches(normalized, mount->point))
			return KERNEL_ERROR_EBUSY;
	}
	auto mount    = std::make_shared<MountRecord>();
	mount->point  = normalized;
	mount->volume = std::move(volume);
	if (mounts.size() >= 16 || next_device == UINT32_MAX) return KERNEL_ERROR_ENOSPC;
	mount->device = next_device++;
	mounts.push_back(std::move(mount));
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int Unmount(const std::string& point) try {
	std::lock_guard lock(mounts_mutex);
	std::string     normalized;
	const int       result = Normalize(point, &normalized);
	if (result != OK) return result;
	const auto found = std::find_if(mounts.begin(), mounts.end(), [&](const auto& mount) {
		return mount->point.size() == normalized.size() && Matches(mount->point, normalized);
	});
	if (found == mounts.end()) return KERNEL_ERROR_EINVAL;
	mounts.erase(found);
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

void Shutdown() {
	std::lock_guard lock(mounts_mutex);
	mounts.clear();
}

bool Contains(const std::string& path) try {
	std::lock_guard lock(mounts_mutex);
	std::string     normalized;
	if (Normalize(path, &normalized) != OK) return FindMount(path) != nullptr;
	return FindMount(normalized) != nullptr;
} catch (const std::bad_alloc&) {
	return false;
}

bool Overlaps(const std::string& path) try {
	std::lock_guard lock(mounts_mutex);
	std::string     normalized;
	if (Normalize(path, &normalized) != OK) return FindMount(path) != nullptr;
	return std::any_of(mounts.begin(), mounts.end(), [&](const auto& mount) {
		return Matches(mount->point, normalized) || Matches(normalized, mount->point);
	});
} catch (const std::bad_alloc&) {
	return true;
}

int ValidateTraversal(const std::string& path) try {
	std::lock_guard lock(mounts_mutex);
	std::string     normalized;
	return Normalize(path, &normalized);
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int Open(const std::string& path, int flags, std::shared_ptr<Handle>* handle) try {
	if (!handle) return KERNEL_ERROR_EFAULT;
	if ((flags & 3) == 3) return KERNEL_ERROR_EINVAL;
	std::lock_guard lock(mounts_mutex);
	std::string     normalized;
	const int       result = Normalize(path, &normalized);
	if (result != OK) return result;
	const auto mount = FindMount(normalized);
	if (!mount) return KERNEL_ERROR_ENOENT;
	if ((flags & 3) != 0 || (flags & (0x8 | 0x200 | 0x400 | 0x800))) return KERNEL_ERROR_EROFS;
	auto      opened = std::make_shared<Handle>();
	const int found  = Lookup(mount, normalized, &opened->entry);
	if (found != OK) return found;
	if ((flags & 0x20000) && !opened->entry.directory) return KERNEL_ERROR_ENOTDIR;
	opened->mount = mount;
	*handle       = std::move(opened);
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int Close(std::shared_ptr<Handle>& handle) {
	if (!handle) return KERNEL_ERROR_EBADF;
	handle.reset();
	return OK;
}

int Stat(const std::string& path, NodeStat* stat) try {
	if (!stat) return KERNEL_ERROR_EFAULT;
	std::lock_guard lock(mounts_mutex);
	std::string     normalized;
	const int       result = Normalize(path, &normalized);
	if (result != OK) return result;
	const auto mount = FindMount(normalized);
	if (!mount) return KERNEL_ERROR_ENOENT;
	BfsVolume::Entry entry;
	const int        found = Lookup(mount, normalized, &entry);
	if (found != OK) return found;
	*stat = Metadata(*mount, entry);
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int Fstat(const std::shared_ptr<Handle>& handle, NodeStat* stat) {
	if (!stat) return KERNEL_ERROR_EFAULT;
	if (!handle) return KERNEL_ERROR_EBADF;
	*stat = Metadata(*handle->mount, handle->entry);
	return OK;
}

int Entries(const std::shared_ptr<Handle>& handle, std::vector<DirectoryEntry>* entries) try {
	if (!entries) return KERNEL_ERROR_EFAULT;
	if (!handle) return KERNEL_ERROR_EBADF;
	std::vector<BfsVolume::Entry> children;
	const int result = Error(handle->mount->volume->List(handle->entry.path, &children));
	if (result != OK) return result;
	std::vector<DirectoryEntry> output;
	for (const auto& child: children) {
		if (child.path.size() > 255) return KERNEL_ERROR_ENAMETOOLONG;
		output.push_back({child.inode, child.directory, child.path});
	}
	*entries = std::move(output);
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int64_t Pread(const std::shared_ptr<Handle>& handle, void* data, size_t length, uint64_t offset) {
	if (!handle) return KERNEL_ERROR_EBADF;
	size_t    actual = 0;
	const int result =
	    Error(handle->mount->volume->Read(handle->entry.path, offset, data, length, &actual));
	return result == OK ? static_cast<int64_t>(actual) : result;
}

int64_t Read(const std::shared_ptr<Handle>& handle, void* data, size_t length) {
	if (!handle) return KERNEL_ERROR_EBADF;
	std::lock_guard lock(handle->mutex);
	const auto      actual = Pread(handle, data, length, handle->offset);
	if (actual > 0) handle->offset += static_cast<uint64_t>(actual);
	return actual;
}

int64_t Seek(const std::shared_ptr<Handle>& handle, int64_t offset, int whence) {
	if (!handle) return KERNEL_ERROR_EBADF;
	if (handle->entry.directory) return KERNEL_ERROR_EISDIR;
	if (whence < 0 || whence > 2) return KERNEL_ERROR_EINVAL;
	std::lock_guard lock(handle->mutex);
	const uint64_t  base = whence == 0 ? 0 : whence == 1 ? handle->offset : handle->entry.size;
	if (offset >= 0) {
		if (base > static_cast<uint64_t>(INT64_MAX - offset)) return KERNEL_ERROR_EOVERFLOW;
		handle->offset = base + static_cast<uint64_t>(offset);
	} else {
		const auto distance = uint64_t {0} - static_cast<uint64_t>(offset);
		if (distance > base) return KERNEL_ERROR_EINVAL;
		handle->offset = base - distance;
	}
	return static_cast<int64_t>(handle->offset);
}

} // namespace Libs::LibKernel::BfsMount
