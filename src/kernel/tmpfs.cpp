#include "kernel/tmpfs.h"

#include "kernel/process.h"
#include "libs/errno.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <string_view>

#if defined(_WIN32)
#include <windows.h>
#endif
namespace Libs::LibKernel::Tmpfs {
namespace {
constexpr uint32_t DirectoryMode    = 0040000;
constexpr uint32_t TypeMask         = 0170000;
constexpr uint32_t SearchPermission = 1;
constexpr size_t   PathCapacity     = 1024;
constexpr size_t   NameCapacity     = 256;
struct Credentials {
	uint32_t uid  = 0;
	uint32_t gid  = 0;
	uint32_t mask = 0;
};

thread_local Credentials credentials;
} // namespace
#if defined(_WIN32)
namespace {
constexpr uint32_t MaximumPages            = MaximumMountBytes / PageSize;
constexpr uint32_t InvalidSlot             = std::numeric_limits<uint32_t>::max();
struct NodeRecord {
	uint64_t inode;
	uint64_t size;
	uint64_t data_pages;
	int64_t  accessed;
	int64_t  modified;
	int64_t  changed;
	int64_t  created;
	uint32_t mode;
	uint32_t uid;
	uint32_t gid;
	uint32_t links;
	uint32_t references;
	uint32_t reserved;
};
struct DirectoryRecord {
	uint64_t parent;
	uint32_t linked;
	uint32_t reserved;
	char     name[NameCapacity];
};
struct PageRecord {
	uint64_t inode;
	uint32_t logical;
	uint32_t reserved;
};
struct MountRecord {
	uint64_t        generation;
	uint64_t        byte_limit;
	uint64_t        metadata_bytes;
	uint64_t        data_pages;
	uint64_t        next_inode;
	uint32_t        inode_limit;
	uint32_t        inode_count;
	char            path[PathCapacity];
	NodeRecord      nodes[MaximumInodes];
	DirectoryRecord entries[MaximumInodes];
	PageRecord      pages[MaximumPages];
	uint8_t         data[MaximumMountBytes];
};
bool IsDirectory(const NodeRecord& node) {
	return (node.mode & TypeMask) == DirectoryMode;
}
bool Allowed(const NodeRecord& node, uint32_t requested) {
	if (credentials.uid == 0) return true;
	const uint32_t shift = credentials.uid == node.uid ? 6 : credentials.gid == node.gid ? 3 : 0;
	return ((node.mode >> shift) & requested) == requested;
}
bool Matches(const char* mount, const std::string& path) {
	const size_t length = std::strlen(mount);
	return (length == 1 && mount[0] == '/') ||
	       (path.size() >= length && path.compare(0, length, mount) == 0 &&
	        (path.size() == length || path[length] == '/'));
}
uint32_t FindChild(const MountRecord& mount, uint64_t parent, std::string_view name) {
	for (uint32_t index = 1; index < mount.inode_limit; ++index) {
		const auto& entry = mount.entries[index];
		if (mount.nodes[index].inode != 0 && entry.linked != 0 && entry.parent == parent &&
		    std::string_view(entry.name) == name)
			return index;
	}
	return InvalidSlot;
}
int Lookup(const MountRecord& mount, const std::string& path, uint32_t* result) {
	if (!Matches(mount.path, path)) return KERNEL_ERROR_ENOENT;
	size_t   cursor  = std::strlen(mount.path);
	uint32_t current = 0;
	while (cursor < path.size()) {
		while (cursor < path.size() && path[cursor] == '/')
			++cursor;
		if (cursor == path.size()) break;
		const auto& parent = mount.nodes[current];
		if (!IsDirectory(parent)) return KERNEL_ERROR_ENOTDIR;
		if (!Allowed(parent, SearchPermission)) return KERNEL_ERROR_EACCES;
		const size_t start = cursor;
		while (cursor < path.size() && path[cursor] != '/')
			++cursor;
		current =
		    FindChild(mount, parent.inode, std::string_view(path.data() + start, cursor - start));
		if (current == InvalidSlot) return KERNEL_ERROR_ENOENT;
	}
	*result = current;
	return OK;
}
} // namespace
#else
#endif
} // namespace Libs::LibKernel::Tmpfs
