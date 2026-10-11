#include "kernel/directoryPassthrough.h"

#include "common/logging/log.h"
#include "common/stringUtils.h"
#include "kernel/capturedDirectory.h"
#include "kernel/authInfo.h"
#include "loader/decryptedModuleOverlay.h"
#include "libs/errno.h"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#include <io.h>
#include <share.h>
#include <windows.h>
#include <bcrypt.h>
#undef DeleteFile
#undef CreateDirectory
#endif
namespace Libs::LibKernel::DirectoryPassthrough {
namespace {
struct UpperShared {
	uint64_t magic;
	uint64_t generation;
};
// kind: 'd' directory, 'f' file, 'w' whiteout. A file with no object was renamed or touched, not
// written. origin: captured path to read or merge with, empty = opaque.
struct UpperNode {
	char        kind   = 0;
	uint32_t    mode   = 0;
	uint32_t    uid    = 0;
	uint32_t    gid    = 0;
	int64_t     mtime  = 0;
	uint32_t    inode  = 0;
	uint64_t    object = 0;
	std::string origin;
};
struct UpperStore {
	std::filesystem::path            directory;
	void*                            mutex   = nullptr;
	void*                            mapping = nullptr;
	UpperShared*                     shared  = nullptr;
	uint64_t                         loaded  = UINT64_MAX;
	uint64_t                         serial  = 1;
	std::map<std::string, UpperNode> nodes;

	~UpperStore() {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		if (shared != nullptr) UnmapViewOfFile(shared);
		if (mapping != nullptr) CloseHandle(mapping);
		if (mutex != nullptr) CloseHandle(mutex);
#endif
	}
};
struct MountRecord {
	std::string                                        point;
	std::filesystem::path                              host_root;
	std::filesystem::path                              canonical_root;
	uint32_t                                           device = 0;
	std::shared_ptr<const CapturedDirectory::Snapshot> snapshot;
	std::shared_ptr<const CapturedDirectory::Snapshot> fallback;
	std::vector<std::string>                           fallback_prefixes;
	std::shared_ptr<UpperStore>                        upper;
	bool                                               factory_storage_view = false;
	std::string                                        guest_fstype;
	std::string                                        guest_source;
	uint64_t                                           guest_flags = 0;
};
std::mutex                                mounts_mutex;
std::vector<std::shared_ptr<MountRecord>> mounts;
bool LowercaseEqual(std::string_view left, std::string_view right) {
	if (left.size() != right.size()) return false;
	for (size_t i = 0; i < left.size(); ++i) {
		auto l = left[i], r = right[i];
		if (l >= 'A' && l <= 'Z') l += 'a' - 'A';
		if (r >= 'A' && r <= 'Z') r += 'a' - 'A';
		if (l != r) return false;
	}
	return true;
}
bool Matches(const std::string& point, const std::string& path) {
	const bool prefix =
	    path.size() >= point.size() &&
	    LowercaseEqual(std::string_view {point}, std::string_view {path}.substr(0, point.size()));
	return point == "/" || (prefix && (path.size() == point.size() || path[point.size()] == '/'));
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
	*normalized = std::move(walked);
	return OK;
}
// A prefix is either a fully listed captured directory or one captured regular file with stored
// bytes.
int AdmitFallbackPrefix(const CapturedDirectory::Snapshot& snapshot, const std::string& prefix,
                        const std::vector<std::string>& admitted) {
	if (prefix == "/") return KERNEL_ERROR_EINVAL;
	for (const auto& existing: admitted) {
		if (Matches(existing, prefix) || Matches(prefix, existing)) return KERNEL_ERROR_EBUSY;
	}
	const CapturedDirectory::Entry* entry = nullptr;
	int present = CapturedDirectory::FindDirectory(snapshot, prefix, &entry);
	if (present == KERNEL_ERROR_ENOTDIR)
		present = CapturedDirectory::Find(snapshot, prefix, &entry);
	if (present != OK) return present;
	if (entry->type == 4) return entry->complete ? OK : KERNEL_ERROR_EINVAL;
	return entry->type == 8 && entry->metadata && !entry->file.empty() ? OK : KERNEL_ERROR_EINVAL;
}
} // namespace
int AttachCapturedFallback(const std::string& point, const std::string& prefix,
                           const std::string& manifest_sha256) try {
	std::lock_guard lock(mounts_mutex);
	std::string     normalized_point, normalized_prefix;
	const int       point_result  = Normalize(point, &normalized_point);
	const int       prefix_result = Normalize(prefix, &normalized_prefix);
	if (point_result != OK) return point_result;
	if (prefix_result != OK) return prefix_result;
	if (normalized_point != point || normalized_prefix != prefix || normalized_prefix == "/")
		return KERNEL_ERROR_EINVAL;
	const auto found = std::find_if(mounts.begin(), mounts.end(), [&](const auto& mount) {
		return LowercaseEqual(mount->point, normalized_point);
	});
	if (found == mounts.end()) return KERNEL_ERROR_ENOENT;
	if ((*found)->snapshot) return KERNEL_ERROR_EBUSY;
	const auto snapshot = CapturedDirectory::ForPoint(normalized_point);
	if (!snapshot || snapshot->manifest_sha256 != manifest_sha256) return KERNEL_ERROR_EINVAL;
	if ((*found)->fallback && (*found)->fallback != snapshot) return KERNEL_ERROR_EBUSY;
	const int admitted =
	    AdmitFallbackPrefix(*snapshot, normalized_prefix, (*found)->fallback_prefixes);
	if (admitted != OK) return admitted;
	(*found)->fallback_prefixes.push_back(normalized_prefix);
	(*found)->fallback = snapshot;
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}
int DescribeMount(const std::string& point, MountInfo* info) try {
	if (!info) return KERNEL_ERROR_EFAULT;
	std::lock_guard lock(mounts_mutex);
	const auto      found = std::find_if(mounts.begin(), mounts.end(), [&](const auto& mount) {
		return LowercaseEqual(mount->point, point);
	});
	if (found == mounts.end()) return KERNEL_ERROR_ENOENT;
	*info = {(*found)->point,
	         (*found)->host_root,
	         (*found)->device,
	         (*found)->snapshot ? (*found)->snapshot->manifest_sha256 : "",
	         (*found)->fallback_prefixes,
	         (*found)->fallback ? (*found)->fallback->manifest_sha256 : "",
	         (*found)->upper != nullptr,
	         (*found)->guest_fstype,
	         (*found)->guest_source,
	         (*found)->guest_flags};
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}
} // namespace Libs::LibKernel::DirectoryPassthrough
