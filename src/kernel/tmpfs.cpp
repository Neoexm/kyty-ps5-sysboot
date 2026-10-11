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
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace Libs::LibKernel::Tmpfs {
namespace {

constexpr uint32_t DirectoryMode    = 0040000;
constexpr uint32_t RegularMode      = 0100000;
constexpr uint32_t TypeMask         = 0170000;
constexpr uint32_t ReadPermission   = 4;
constexpr uint32_t WritePermission  = 2;
constexpr uint32_t SearchPermission = 1;
constexpr size_t   PathCapacity     = 1024;
constexpr size_t   NameCapacity     = 256;

struct Credentials {
	uint32_t uid  = 0;
	uint32_t gid  = 0;
	uint32_t mask = 0;
};

thread_local Credentials credentials;

int64_t Now() {
	return std::chrono::duration_cast<std::chrono::seconds>(
	           std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

bool TrailingDirectory(const std::string& path) {
	return !path.empty() && (path.back() == '/' || path.ends_with("/.") || path.ends_with("/.."));
}

bool SpecialFinalComponent(const std::string& path) {
	std::string_view value(path);
	while (!value.empty() && value.back() == '/')
		value.remove_suffix(1);
	const auto slash = value.rfind('/');
	if (slash != std::string_view::npos) value.remove_prefix(slash + 1);
	return value == "." || value == "..";
}

} // namespace

void SetCredentials(uint32_t uid, uint32_t gid, uint32_t mask) {
	credentials = {uid, gid, mask & 0777};
}

int NormalizePath(const std::string& path, std::string* normalized) {
	if (normalized == nullptr) return KERNEL_ERROR_EFAULT;
	if (path.empty() || path.front() != '/' || path.find('\0') != std::string::npos ||
	    path.find('\\') != std::string::npos)
		return KERNEL_ERROR_EINVAL;
	if (path.size() >= PathCapacity) return KERNEL_ERROR_ENAMETOOLONG;
	try {
		std::string result;
		result.reserve(path.size());
		size_t cursor = 0;
		while (cursor < path.size()) {
			while (cursor < path.size() && path[cursor] == '/')
				++cursor;
			const size_t start = cursor;
			while (cursor < path.size() && path[cursor] != '/')
				++cursor;
			const std::string_view part(path.data() + start, cursor - start);
			if (part.size() >= NameCapacity) return KERNEL_ERROR_ENAMETOOLONG;
			if (part.empty() || part == ".") continue;
			if (part == "..") {
				const auto slash = result.rfind('/');
				if (slash != std::string::npos) result.resize(slash);
				continue;
			}
			result.push_back('/');
			result.append(part);
		}
		if (result.empty()) result = "/";
		*normalized = std::move(result);
		return OK;
	} catch (const std::bad_alloc&) {
		return KERNEL_ERROR_ENOMEM;
	}
}

#if defined(_WIN32)
namespace {

constexpr uint64_t NamespaceMagic          = 0x315346504d54594bull;
constexpr uint32_t NamespaceVersion        = 1;
constexpr uint32_t MaximumPages            = MaximumMountBytes / PageSize;
constexpr uint32_t MaximumOpenDescriptions = 1024;
constexpr uint32_t InvalidSlot             = std::numeric_limits<uint32_t>::max();
constexpr int      AccessMask              = 3;
constexpr int      AppendFlag              = 0x8;
constexpr int      SyncFlag                = 0x80;
constexpr int      CreateFlag              = 0x200;
constexpr int      TruncateFlag            = 0x400;
constexpr int      ExclusiveFlag           = 0x800;
constexpr int      DirectoryFlag           = 0x20000;
constexpr int      CloseOnExecFlag         = 0x100000;
constexpr int SupportedOpenFlags = AccessMask | AppendFlag | SyncFlag | CreateFlag | TruncateFlag |
                                   ExclusiveFlag | DirectoryFlag | CloseOnExecFlag;

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

struct OpenRecord {
	uint64_t token;
	uint64_t mount_generation;
	uint64_t inode;
	uint64_t offset;
	uint64_t owner_birth;
	uint32_t owner_pid;
	uint32_t mount;
	uint32_t node;
	uint32_t access;
	uint32_t append;
	uint32_t reserved;
};

struct SharedNamespace {
	uint64_t    magic;
	uint64_t    layout_bytes;
	uint64_t    next_mount;
	uint64_t    next_open;
	uint32_t    version;
	uint32_t    poisoned;
	OpenRecord  open[MaximumOpenDescriptions];
	MountRecord mounts[MaximumMounts];
};

constexpr uint32_t ModelNodeBytes           = sizeof(NodeRecord);
constexpr uint32_t ModelDirectoryEntryBytes = sizeof(DirectoryRecord);

struct NamespaceState {
	HANDLE           mapping = nullptr;
	HANDLE           mutex   = nullptr;
	SharedNamespace* shared  = nullptr;
	std::string      scope;
	uint32_t         host_pid   = 0;
	uint64_t         host_birth = 0;

	~NamespaceState() {
		if (shared) UnmapViewOfFile(shared);
		if (mapping) CloseHandle(mapping);
		if (mutex) CloseHandle(mutex);
	}
};

std::mutex                      state_mutex;
std::shared_ptr<NamespaceState> current_state;

uint64_t ProcessBirth(HANDLE process) {
	FILETIME created {}, exited {}, kernel {}, user {};
	if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return 0;
	return (static_cast<uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
}

bool ScopeValid(const std::string& scope) {
	return !scope.empty() && scope.size() <= 64 &&
	       std::all_of(scope.begin(), scope.end(), [](unsigned char ch) {
		       return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			          (ch >= '0' && ch <= '9') || ch == '_';
	       });
}

struct SharedLock {
	std::shared_ptr<NamespaceState> state;
	bool                            acquired = false;
	int                             error    = KERNEL_ERROR_EIO;

	explicit SharedLock(std::shared_ptr<NamespaceState> value): state(std::move(value)) {
		if (!state || !state->mutex || !state->shared) return;
		const auto result = WaitForSingleObject(state->mutex, 5000);
		acquired          = result == WAIT_OBJECT_0 || result == WAIT_ABANDONED;
		if (!acquired) return;
		auto* shared = state->shared;
		if (result == WAIT_ABANDONED) shared->poisoned = 1;
		if (shared->magic != NamespaceMagic || shared->version != NamespaceVersion ||
		    shared->layout_bytes != sizeof(SharedNamespace) || shared->poisoned != 0)
			return;
		error = OK;
	}

	~SharedLock() {
		if (acquired) ReleaseMutex(state->mutex);
	}
};

int Current(std::shared_ptr<NamespaceState>* state) {
	{
		std::lock_guard lock(state_mutex);
		if (current_state) {
			*state = current_state;
			return OK;
		}
	}
	std::string scope;
	if (!Process::GetScope(&scope)) return KERNEL_ERROR_ENOENT;
	const int result = Initialize(scope);
	if (result != OK) return result;
	std::lock_guard lock(state_mutex);
	if (!current_state) return KERNEL_ERROR_EIO;
	*state = current_state;
	return OK;
}

bool IsDirectory(const NodeRecord& node) {
	return (node.mode & TypeMask) == DirectoryMode;
}

bool Allowed(const NodeRecord& node, uint32_t requested) {
	if (credentials.uid == 0) return true;
	const uint32_t shift = credentials.uid == node.uid ? 6 : credentials.gid == node.gid ? 3 : 0;
	return ((node.mode >> shift) & requested) == requested;
}

uint64_t Charged(const MountRecord& mount) {
	return mount.metadata_bytes + mount.data_pages * PageSize;
}

bool CanCharge(const MountRecord& mount, uint64_t bytes) {
	const auto charged = Charged(mount);
	return charged <= mount.byte_limit && bytes <= mount.byte_limit - charged;
}

bool Matches(const char* mount, const std::string& path) {
	const size_t length = std::strlen(mount);
	return (length == 1 && mount[0] == '/') ||
	       (path.size() >= length && path.compare(0, length, mount) == 0 &&
	        (path.size() == length || path[length] == '/'));
}

uint32_t FindMount(SharedNamespace* shared, const std::string& path) {
	uint32_t found   = InvalidSlot;
	size_t   longest = 0;
	for (uint32_t index = 0; index < MaximumMounts; ++index) {
		const auto& mount = shared->mounts[index];
		if (mount.generation == 0 || !Matches(mount.path, path)) continue;
		const size_t length = std::strlen(mount.path);
		if (found == InvalidSlot || length > longest) {
			longest = length;
			found   = index;
		}
	}
	return found;
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

int Traverse(SharedNamespace* shared, const std::string& path) {
	try {
		std::string current = "/";
		current.reserve(path.size());
		size_t cursor = 0;
		while (cursor < path.size()) {
			while (cursor < path.size() && path[cursor] == '/')
				++cursor;
			if (cursor == path.size()) break;
			const size_t start = cursor;
			while (cursor < path.size() && path[cursor] != '/')
				++cursor;
			const std::string_view part(path.data() + start, cursor - start);
			const auto             mount_index = FindMount(shared, current);
			if (mount_index != InvalidSlot) {
				const auto& mount  = shared->mounts[mount_index];
				uint32_t    index  = InvalidSlot;
				const int   result = Lookup(mount, current, &index);
				if (result != OK) return result;
				if (!IsDirectory(mount.nodes[index])) return KERNEL_ERROR_ENOTDIR;
				if (!Allowed(mount.nodes[index], SearchPermission)) return KERNEL_ERROR_EACCES;
			}
			if (part == ".") continue;
			if (part == "..") {
				const auto slash = current.rfind('/');
				current.resize(slash == 0 ? 1 : slash);
				continue;
			}
			if (current != "/") current.push_back('/');
			current.append(part);
		}
		return OK;
	} catch (const std::bad_alloc&) {
		return KERNEL_ERROR_ENOMEM;
	}
}

int Parent(const MountRecord& mount, const std::string& path, uint32_t* parent,
           std::string_view* name) {
	if (path == mount.path) return KERNEL_ERROR_EBUSY;
	const auto slash = path.rfind('/');
	if (slash == std::string::npos || slash + 1 >= path.size()) return KERNEL_ERROR_EINVAL;
	std::string parent_path;
	try {
		parent_path = slash == 0 ? "/" : path.substr(0, slash);
	} catch (const std::bad_alloc&) {
		return KERNEL_ERROR_ENOMEM;
	}
	int result = Lookup(mount, parent_path, parent);
	if (result != OK) return result;
	const auto& node = mount.nodes[*parent];
	if (!IsDirectory(node)) return KERNEL_ERROR_ENOTDIR;
	if (!Allowed(node, SearchPermission)) return KERNEL_ERROR_EACCES;
	*name = std::string_view(path.data() + slash + 1, path.size() - slash - 1);
	return OK;
}

uint32_t FreeNode(const MountRecord& mount) {
	for (uint32_t index = 1; index < mount.inode_limit; ++index) {
		if (mount.nodes[index].inode == 0) return index;
	}
	return InvalidSlot;
}

uint32_t FreeOpen(const SharedNamespace* shared) {
	for (uint32_t index = 0; index < MaximumOpenDescriptions; ++index) {
		if (shared->open[index].token == 0) return index;
	}
	return InvalidSlot;
}

void FreePages(MountRecord& mount, uint32_t node_index, uint64_t first_logical = 0) {
	auto& node = mount.nodes[node_index];
	for (uint32_t index = 0; index < MaximumPages; ++index) {
		auto& page = mount.pages[index];
		if (page.inode == node.inode && page.logical >= first_logical) {
			page = {};
			--mount.data_pages;
			--node.data_pages;
		}
	}
}

void Reclaim(MountRecord& mount, uint32_t index) {
	auto& node = mount.nodes[index];
	if (index == 0 || node.inode == 0 || node.links != 0 || node.references != 0) return;
	FreePages(mount, index);
	mount.metadata_bytes -= ModelNodeBytes;
	--mount.inode_count;
	node                 = {};
	mount.entries[index] = {};
}

void ReleaseOpen(SharedNamespace* shared, uint32_t index) {
	auto& open = shared->open[index];
	if (open.token == 0) return;
	if (open.mount < MaximumMounts && open.node < MaximumInodes) {
		auto& mount = shared->mounts[open.mount];
		auto& node  = mount.nodes[open.node];
		if (mount.generation == open.mount_generation && node.inode == open.inode &&
		    node.references != 0) {
			--node.references;
			Reclaim(mount, open.node);
		}
	}
	open = {};
}

bool OwnerAlive(const OpenRecord& open) {
	HANDLE process =
	    OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, open.owner_pid);
	if (!process) return GetLastError() != ERROR_INVALID_PARAMETER;
	const auto     wait  = WaitForSingleObject(process, 0);
	const uint64_t birth = ProcessBirth(process);
	CloseHandle(process);
	return wait != WAIT_OBJECT_0 &&
	       (open.owner_birth == 0 || birth == 0 || open.owner_birth == birth);
}

void ReapDeadOwners(const NamespaceState& state) {
	auto*                                         shared = state.shared;
	std::array<uint32_t, MaximumOpenDescriptions> examined {};
	std::array<uint64_t, MaximumOpenDescriptions> examined_birth {};
	std::array<bool, MaximumOpenDescriptions>     alive {};
	size_t                                        examined_count = 0;
	for (uint32_t index = 0; index < MaximumOpenDescriptions; ++index) {
		const auto& open = shared->open[index];
		if (open.token == 0 ||
		    (open.owner_pid == state.host_pid && open.owner_birth == state.host_birth))
			continue;
		size_t cached = 0;
		while (cached < examined_count &&
		       (examined[cached] != open.owner_pid || examined_birth[cached] != open.owner_birth))
			++cached;
		if (cached == examined_count) {
			examined[cached]       = open.owner_pid;
			examined_birth[cached] = open.owner_birth;
			alive[cached]          = OwnerAlive(open);
			++examined_count;
		}
		if (!alive[cached]) ReleaseOpen(shared, index);
	}
}

void FillStat(const MountRecord& mount, const NodeRecord& node, NodeStat* stat) {
	*stat = {node.inode,    static_cast<uint32_t>(mount.generation),
	         node.size,     IsDirectory(node) ? node.size : node.data_pages * PageSize,
	         node.mode,     node.uid,
	         node.gid,      node.links,
	         node.accessed, node.modified,
	         node.changed,  node.created};
}

void CreateNode(MountRecord& mount, uint32_t index, uint32_t parent, std::string_view name,
                uint32_t mode) {
	const int64_t time  = Now();
	auto&         node  = mount.nodes[index];
	auto&         entry = mount.entries[index];
	node                = {};
	node.inode          = mount.next_inode++;
	node.mode           = mode;
	node.uid            = credentials.uid;
	node.gid = (mount.nodes[parent].mode & 02000) != 0 ? mount.nodes[parent].gid : credentials.gid;
	if (IsDirectory(node) && (mount.nodes[parent].mode & 02000) != 0) node.mode |= 02000;
	node.links    = IsDirectory(node) ? 2 : 1;
	node.accessed = node.modified = node.changed = node.created = time;
	entry                                                       = {};
	entry.parent                                                = mount.nodes[parent].inode;
	std::memcpy(entry.name, name.data(), name.size());
	entry.linked = 1;
	++mount.inode_count;
	mount.metadata_bytes += ModelNodeBytes + ModelDirectoryEntryBytes;
	mount.nodes[parent].size += ModelDirectoryEntryBytes;
	if (IsDirectory(node)) ++mount.nodes[parent].links;
	mount.nodes[parent].modified = mount.nodes[parent].changed = time;
}

uint32_t FindInode(const MountRecord& mount, uint64_t inode) {
	for (uint32_t index = 0; index < mount.inode_limit; ++index) {
		if (mount.nodes[index].inode == inode) return index;
	}
	return InvalidSlot;
}

void RemoveEntry(MountRecord& mount, uint32_t index) {
	auto&          node   = mount.nodes[index];
	auto&          entry  = mount.entries[index];
	const uint32_t parent = FindInode(mount, entry.parent);
	if (parent != InvalidSlot) {
		mount.nodes[parent].size -= ModelDirectoryEntryBytes;
		if (IsDirectory(node)) --mount.nodes[parent].links;
		mount.nodes[parent].modified = mount.nodes[parent].changed = Now();
	}
	entry.linked = 0;
	mount.metadata_bytes -= ModelDirectoryEntryBytes;
	node.links   = 0;
	node.changed = Now();
	Reclaim(mount, index);
}

bool DirectoryEmpty(const MountRecord& mount, uint32_t index) {
	const uint64_t inode = mount.nodes[index].inode;
	for (uint32_t child = 1; child < mount.inode_limit; ++child) {
		if (mount.entries[child].linked != 0 && mount.entries[child].parent == inode) return false;
	}
	return true;
}

bool StickyAllowed(const NodeRecord& parent, const NodeRecord& node) {
	return (parent.mode & 01000) == 0 || credentials.uid == 0 || credentials.uid == parent.uid ||
	       credentials.uid == node.uid;
}

uint32_t PageIndex(const MountRecord& mount, uint64_t inode, uint32_t logical) {
	for (uint32_t index = 0; index < MaximumPages; ++index) {
		if (mount.pages[index].inode == inode && mount.pages[index].logical == logical)
			return index;
	}
	return InvalidSlot;
}

int ReservePages(MountRecord& mount, uint32_t node_index, uint64_t offset, uint64_t size) {
	if (size == 0) return OK;
	if (offset > MaximumMountBytes || size > MaximumMountBytes - offset) return KERNEL_ERROR_EFBIG;
	auto&                              node  = mount.nodes[node_index];
	const uint32_t                     first = static_cast<uint32_t>(offset / PageSize);
	const uint32_t                     last = static_cast<uint32_t>((offset + size - 1) / PageSize);
	std::array<uint32_t, MaximumPages> missing {};
	uint32_t                           needed = 0;
	for (uint32_t logical = first; logical <= last; ++logical) {
		if (PageIndex(mount, node.inode, logical) == InvalidSlot) missing[needed++] = logical;
	}
	if (needed > MaximumPages - mount.data_pages ||
	    !CanCharge(mount, static_cast<uint64_t>(needed) * PageSize))
		return KERNEL_ERROR_ENOSPC;
	uint32_t assigned = 0;
	for (uint32_t index = 0; index < MaximumPages && assigned < needed; ++index) {
		if (mount.pages[index].inode != 0) continue;
		std::memset(mount.data + static_cast<uint64_t>(index) * PageSize, 0, PageSize);
		mount.pages[index] = {node.inode, missing[assigned++], 0};
	}
	mount.data_pages += needed;
	node.data_pages += needed;
	return OK;
}

void Resize(MountRecord& mount, uint32_t index, uint64_t size) {
	auto& node = mount.nodes[index];
	if (size < node.size) {
		FreePages(mount, index, (size + PageSize - 1) / PageSize);
		if (size % PageSize != 0) {
			const auto page = PageIndex(mount, node.inode, static_cast<uint32_t>(size / PageSize));
			if (page != InvalidSlot) {
				std::memset(mount.data + static_cast<uint64_t>(page) * PageSize + size % PageSize,
				            0, PageSize - size % PageSize);
			}
		}
	}
	node.size     = size;
	node.modified = node.changed = Now();
}

} // namespace

class Handle {
public:
	std::shared_ptr<NamespaceState> state;
	uint32_t                        index = InvalidSlot;
	uint64_t                        token = 0;

	~Handle() {
		if (index == InvalidSlot || !state || token == 0) return;
		SharedLock lock(state);
		if (lock.error != OK) return;
		if (state->shared->open[index].token == token) ReleaseOpen(state->shared, index);
	}
};

namespace {

int ResolveHandle(const std::shared_ptr<Handle>& handle, OpenRecord** open, MountRecord** mount,
                  NodeRecord** node) {
	if (!handle || handle->index >= MaximumOpenDescriptions || handle->token == 0)
		return KERNEL_ERROR_EBADF;
	auto& record = handle->state->shared->open[handle->index];
	if (record.token != handle->token || record.mount >= MaximumMounts ||
	    record.node >= MaximumInodes || record.owner_pid != handle->state->host_pid ||
	    record.owner_birth != handle->state->host_birth)
		return KERNEL_ERROR_EBADF;
	auto& filesystem = handle->state->shared->mounts[record.mount];
	auto& inode      = filesystem.nodes[record.node];
	if (filesystem.generation != record.mount_generation || inode.inode != record.inode ||
	    inode.references == 0)
		return KERNEL_ERROR_EBADF;
	*open  = &record;
	*mount = &filesystem;
	*node  = &inode;
	return OK;
}

int64_t Transfer(const std::shared_ptr<Handle>& handle, void* data, uint64_t size, uint64_t offset,
                 bool sequential, bool write) {
	if (!handle) return KERNEL_ERROR_EBADF;
	if (size != 0 && data == nullptr) return KERNEL_ERROR_EFAULT;
	if (size > static_cast<uint64_t>(INT64_MAX)) return KERNEL_ERROR_EINVAL;
	SharedLock lock(handle->state);
	if (lock.error != OK) return lock.error;
	OpenRecord*  open  = nullptr;
	MountRecord* mount = nullptr;
	NodeRecord*  node  = nullptr;
	const int    error = ResolveHandle(handle, &open, &mount, &node);
	if (error != OK) return error;
	if (IsDirectory(*node)) return KERNEL_ERROR_EISDIR;
	if ((write && open->access == 0) || (!write && open->access == 1)) return KERNEL_ERROR_EBADF;
	if (size == 0) return 0;
	if (sequential) offset = write && open->append != 0 ? node->size : open->offset;
	if (offset > static_cast<uint64_t>(INT64_MAX)) return KERNEL_ERROR_EINVAL;
	uint64_t actual = size;
	if (write) {
		if (offset > MaximumMountBytes || size > MaximumMountBytes - offset)
			return KERNEL_ERROR_EFBIG;
		const int allocated =
		    ReservePages(*mount, open->node, 0, std::max(node->size, offset + size));
		if (allocated != OK) return allocated;
	} else {
		actual = offset >= node->size ? 0 : std::min(size, node->size - offset);
	}
	uint64_t copied = 0;
	while (copied < actual) {
		const uint64_t position = offset + copied;
		const uint64_t length   = std::min(actual - copied, PageSize - position % PageSize);
		const uint32_t index =
		    PageIndex(*mount, node->inode, static_cast<uint32_t>(position / PageSize));
		auto* buffer = static_cast<uint8_t*>(data) + copied;
		if (index == InvalidSlot) {
			if (write) {
				handle->state->shared->poisoned = 1;
				return KERNEL_ERROR_EIO;
			}
			std::memset(buffer, 0, static_cast<size_t>(length));
		} else {
			auto* memory =
			    mount->data + static_cast<uint64_t>(index) * PageSize + position % PageSize;
			if (write)
				std::memcpy(memory, buffer, static_cast<size_t>(length));
			else
				std::memcpy(buffer, memory, static_cast<size_t>(length));
		}
		copied += length;
	}
	if (write) {
		node->size     = std::max(node->size, offset + actual);
		node->modified = node->changed = Now();
		if (credentials.uid != 0) node->mode &= ~06000u;
	} else if (actual != 0) {
		node->accessed = Now();
	}
	if (sequential) open->offset = offset + actual;
	return static_cast<int64_t>(actual);
}

} // namespace

int Initialize(const std::string& scope) {
	if (!ScopeValid(scope)) return KERNEL_ERROR_EINVAL;
	std::lock_guard local(state_mutex);
	if (current_state) return current_state->scope == scope ? OK : KERNEL_ERROR_EBUSY;
	try {
		auto state             = std::make_shared<NamespaceState>();
		state->scope           = scope;
		state->host_pid        = GetCurrentProcessId();
		state->host_birth      = ProcessBirth(GetCurrentProcess());
		const std::string base = "Local\\KytyPS5_Tmpfs_v1_" + scope;
		state->mutex           = CreateMutexA(nullptr, FALSE, (base + "_mutex").c_str());
		if (!state->mutex) return KERNEL_ERROR_EIO;
		state->mapping = CreateFileMappingA(
		    INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
		    static_cast<DWORD>(sizeof(SharedNamespace) >> 32),
		    static_cast<DWORD>(sizeof(SharedNamespace) & 0xffffffffu), (base + "_memory").c_str());
		if (!state->mapping) return KERNEL_ERROR_ENOMEM;
		state->shared = static_cast<SharedNamespace*>(
		    MapViewOfFile(state->mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedNamespace)));
		if (!state->shared) return KERNEL_ERROR_ENOMEM;
		const auto waited = WaitForSingleObject(state->mutex, 5000);
		if (waited != WAIT_OBJECT_0 && waited != WAIT_ABANDONED) return KERNEL_ERROR_EIO;
		auto* shared = state->shared;
		if (waited == WAIT_ABANDONED) shared->poisoned = 1;
		if (shared->magic == 0 && shared->version == 0 && shared->poisoned == 0) {
			shared->layout_bytes = sizeof(SharedNamespace);
			shared->next_mount   = 1;
			shared->next_open    = 1;
			shared->version      = NamespaceVersion;
			shared->magic        = NamespaceMagic;
		}
		const bool valid = shared->magic == NamespaceMagic && shared->version == NamespaceVersion &&
		                   shared->layout_bytes == sizeof(SharedNamespace) && shared->poisoned == 0;
		if (valid) ReapDeadOwners(*state);
		ReleaseMutex(state->mutex);
		if (!valid) return KERNEL_ERROR_EIO;
		current_state = std::move(state);
		return OK;
	} catch (const std::bad_alloc&) {
		return KERNEL_ERROR_ENOMEM;
	}
}

void Shutdown() {
	std::lock_guard lock(state_mutex);
	current_state.reset();
	credentials = {};
}

int ValidateTraversal(const std::string& path) {
	std::string normalized;
	const int   parsed = NormalizePath(path, &normalized);
	if (parsed != OK) return parsed;
	std::shared_ptr<NamespaceState> state;
	const int                       ready = Current(&state);
	if (ready != OK) return ready == KERNEL_ERROR_ENOENT ? OK : ready;
	SharedLock lock(state);
	if (lock.error != OK) return lock.error;
	return Traverse(state->shared, path);
}

bool Contains(const std::string& path) {
	std::string normalized;
	if (NormalizePath(path, &normalized) != OK) return false;
	std::shared_ptr<NamespaceState> state;
	const int                       ready = Current(&state);
	if (ready != OK) return ready != KERNEL_ERROR_ENOENT;
	SharedLock lock(state);
	if (lock.error != OK) return true;
	return FindMount(state->shared, normalized) != InvalidSlot;
}

bool Overlaps(const std::string& path) {
	std::string normalized;
	if (NormalizePath(path, &normalized) != OK) return false;
	std::shared_ptr<NamespaceState> state;
	const int                       ready = Current(&state);
	if (ready != OK) return ready != KERNEL_ERROR_ENOENT;
	SharedLock lock(state);
	if (lock.error != OK) return true;
	for (const auto& mount: state->shared->mounts) {
		if (mount.generation == 0) continue;
		const std::string_view existing(mount.path);
		const auto             size   = std::min(existing.size(), normalized.size());
		const bool             prefix = std::equal(existing.begin(), existing.begin() + size,
		                                           normalized.begin(), [](char left, char right) {
			                               if (left >= 'A' && left <= 'Z') left += 'a' - 'A';
			                               if (right >= 'A' && right <= 'Z') right += 'a' - 'A';
			                               return left == right;
		                                           });
		if (prefix && (existing.size() == normalized.size() || normalized == "/" ||
		               (existing.size() > size ? existing[size] == '/' : normalized[size] == '/')))
			return true;
	}
	return false;
}

int Mount(const std::string& path, uint32_t mode, uint64_t byte_limit, uint32_t inode_limit,
          uint32_t uid, uint32_t gid) {
	std::string normalized;
	int         result = NormalizePath(path, &normalized);
	if (result != OK) return result;
	if (normalized == "/" || (mode & ~07777u) != 0 || byte_limit == 0 || inode_limit == 0)
		return KERNEL_ERROR_EINVAL;
	if (byte_limit > MaximumMountBytes || inode_limit > MaximumInodes) return KERNEL_ERROR_ENOTSUP;
	if (byte_limit < ModelNodeBytes) return KERNEL_ERROR_ENOSPC;
	if (credentials.uid != 0) return KERNEL_ERROR_EPERM;
	std::shared_ptr<NamespaceState> state;
	result = Current(&state);
	if (result != OK) return result;
	SharedLock lock(state);
	if (lock.error != OK) return lock.error;
	result = Traverse(state->shared, path);
	if (result != OK) return result;
	ReapDeadOwners(*state);
	auto*    shared = state->shared;
	uint32_t slot   = InvalidSlot;
	for (uint32_t index = 0; index < MaximumMounts; ++index) {
		auto& mount = shared->mounts[index];
		if (mount.generation == 0) {
			if (slot == InvalidSlot) slot = index;
			continue;
		}
		if (normalized == mount.path) return KERNEL_ERROR_ENOTSUP;
		if (Matches(mount.path, normalized) ||
		    (std::string_view(mount.path).starts_with(normalized) &&
		     mount.path[normalized.size()] == '/'))
			return KERNEL_ERROR_ENOTSUP;
	}
	if (slot == InvalidSlot) return KERNEL_ERROR_ENOSPC;
	if (shared->next_mount == 0 || shared->next_mount > UINT32_MAX) return KERNEL_ERROR_ENOSPC;
	auto& mount = shared->mounts[slot];
	std::memset(&mount, 0, offsetof(MountRecord, data));
	mount.byte_limit     = byte_limit;
	mount.inode_limit    = inode_limit;
	mount.inode_count    = 1;
	mount.metadata_bytes = ModelNodeBytes;
	mount.next_inode     = 2;
	std::memcpy(mount.path, normalized.c_str(), normalized.size() + 1);
	auto& root    = mount.nodes[0];
	root.inode    = 1;
	root.mode     = DirectoryMode | mode;
	root.uid      = uid;
	root.gid      = gid;
	root.links    = 2;
	root.accessed = root.modified = root.changed = root.created = Now();
	mount.entries[0].linked                                     = 1;
	mount.entries[0].parent                                     = root.inode;
	mount.generation                                            = shared->next_mount++;
	return OK;
}

int Unmount(const std::string& path) {
	std::string normalized;
	int         result = NormalizePath(path, &normalized);
	if (result != OK) return result;
	if (credentials.uid != 0) return KERNEL_ERROR_EPERM;
	std::shared_ptr<NamespaceState> state;
	result = Current(&state);
	if (result != OK) return result;
	SharedLock lock(state);
	if (lock.error != OK) return lock.error;
	result = Traverse(state->shared, path);
	if (result != OK) return result;
	ReapDeadOwners(*state);
	const auto index = FindMount(state->shared, normalized);
	if (index == InvalidSlot || normalized != state->shared->mounts[index].path)
		return KERNEL_ERROR_EINVAL;
	const auto& mount = state->shared->mounts[index];
	for (const auto& open: state->shared->open) {
		if (open.token != 0 && open.mount == index && open.mount_generation == mount.generation)
			return KERNEL_ERROR_EBUSY;
	}
	state->shared->mounts[index].generation = 0;
	return OK;
}

int QueryUsage(const std::string& path, Usage* usage) {
	if (usage == nullptr) return KERNEL_ERROR_EFAULT;
	std::string normalized;
	int         result = NormalizePath(path, &normalized);
	if (result != OK) return result;
	std::shared_ptr<NamespaceState> state;
	result = Current(&state);
	if (result != OK) return result;
	SharedLock lock(state);
	if (lock.error != OK) return lock.error;
	result = Traverse(state->shared, path);
	if (result != OK) return result;
	ReapDeadOwners(*state);
	const auto index = FindMount(state->shared, normalized);
	if (index == InvalidSlot) return KERNEL_ERROR_ENOENT;
	const auto& mount = state->shared->mounts[index];
	*usage            = {mount.byte_limit,     Charged(mount), mount.data_pages * PageSize,
	                     mount.metadata_bytes, PageSize,       mount.inode_limit,
	                     mount.inode_count,    ModelNodeBytes, ModelDirectoryEntryBytes};
	return OK;
}

int Open(const std::string& path, int flags, uint32_t mode, std::shared_ptr<Handle>* handle) {
	if (handle == nullptr) return KERNEL_ERROR_EFAULT;
	if (*handle) return KERNEL_ERROR_EBUSY;
	if ((flags & ~SupportedOpenFlags) != 0) return KERNEL_ERROR_ENOTSUP;
	if ((flags & AccessMask) == AccessMask || (mode & ~07777u) != 0) return KERNEL_ERROR_EINVAL;
	const uint32_t access = flags & AccessMask;
	if ((flags & TruncateFlag) != 0 && access == 0) return KERNEL_ERROR_EACCES;
	std::string normalized;
	int         result = NormalizePath(path, &normalized);
	if (result != OK) return result;
	std::shared_ptr<NamespaceState> state;
	result = Current(&state);
	if (result != OK) return result;
	std::shared_ptr<Handle> staged;
	try {
		staged        = std::make_shared<Handle>();
		staged->state = state;
	} catch (const std::bad_alloc&) {
		return KERNEL_ERROR_ENOMEM;
	}
	SharedLock lock(state);
	if (lock.error != OK) return lock.error;
	result = Traverse(state->shared, path);
	if (result != OK) return result;
	ReapDeadOwners(*state);
	auto*          shared      = state->shared;
	const uint32_t mount_index = FindMount(shared, normalized);
	if (mount_index == InvalidSlot) return KERNEL_ERROR_ENOENT;
	auto&    mount          = shared->mounts[mount_index];
	uint32_t node_index     = InvalidSlot;
	result                  = Lookup(mount, normalized, &node_index);
	bool             create = false;
	uint32_t         parent = InvalidSlot;
	std::string_view name;
	if (result != OK) {
		if (result != KERNEL_ERROR_ENOENT || (flags & CreateFlag) == 0) return result;
		if ((flags & DirectoryFlag) != 0 || TrailingDirectory(path)) return KERNEL_ERROR_ENOENT;
		result = Parent(mount, normalized, &parent, &name);
		if (result != OK) return result;
		if (!Allowed(mount.nodes[parent], WritePermission | SearchPermission))
			return KERNEL_ERROR_EACCES;
		if (mount.inode_count >= mount.inode_limit ||
		    !CanCharge(mount, ModelNodeBytes + ModelDirectoryEntryBytes))
			return KERNEL_ERROR_ENOSPC;
		node_index = FreeNode(mount);
		if (node_index == InvalidSlot || mount.next_inode == 0 || mount.next_inode > UINT32_MAX)
			return KERNEL_ERROR_ENOSPC;
		create = true;
	} else {
		auto& node = mount.nodes[node_index];
		if ((flags & (CreateFlag | ExclusiveFlag)) == (CreateFlag | ExclusiveFlag))
			return KERNEL_ERROR_EEXIST;
		if (((flags & DirectoryFlag) != 0 || TrailingDirectory(path)) && !IsDirectory(node))
			return KERNEL_ERROR_ENOTDIR;
		if (IsDirectory(node) && (access != 0 || (flags & (CreateFlag | TruncateFlag)) != 0))
			return KERNEL_ERROR_EISDIR;
		const uint32_t requested = access == 0   ? ReadPermission
		                           : access == 1 ? WritePermission
		                                         : ReadPermission | WritePermission;
		if (!Allowed(node, requested)) return KERNEL_ERROR_EACCES;
	}
	const uint32_t open_index = FreeOpen(shared);
	if (open_index == InvalidSlot) return KERNEL_ERROR_ENFILE;
	if (shared->next_open == 0 || shared->next_open == UINT64_MAX) return KERNEL_ERROR_ENFILE;
	if (create)
		CreateNode(mount, node_index, parent, name, RegularMode | (mode & ~credentials.mask));
	auto& node = mount.nodes[node_index];
	if ((flags & TruncateFlag) != 0) Resize(mount, node_index, 0);
	auto& open            = shared->open[open_index];
	open                  = {};
	open.token            = shared->next_open++;
	open.mount_generation = mount.generation;
	open.inode            = node.inode;
	open.owner_pid        = state->host_pid;
	open.owner_birth      = state->host_birth;
	open.mount            = mount_index;
	open.node             = node_index;
	open.access           = access;
	open.append           = (flags & AppendFlag) != 0;
	++node.references;
	staged->index = open_index;
	staged->token = open.token;
	*handle       = std::move(staged);
	return OK;
}

int Close(std::shared_ptr<Handle>& handle) {
	if (!handle) return KERNEL_ERROR_EBADF;
	SharedLock lock(handle->state);
	if (lock.error != OK) return lock.error;
	OpenRecord*  open   = nullptr;
	MountRecord* mount  = nullptr;
	NodeRecord*  node   = nullptr;
	const int    result = ResolveHandle(handle, &open, &mount, &node);
	if (result != OK) return result;
	if (handle.use_count() == 1) {
		ReleaseOpen(handle->state->shared, handle->index);
		handle->index = InvalidSlot;
		handle->token = 0;
	}
	handle.reset();
	return OK;
}

int64_t Read(const std::shared_ptr<Handle>& handle, void* data, uint64_t size) {
	return Transfer(handle, data, size, 0, true, false);
}

int64_t Pread(const std::shared_ptr<Handle>& handle, void* data, uint64_t size, uint64_t offset) {
	return Transfer(handle, data, size, offset, false, false);
}

int64_t Write(const std::shared_ptr<Handle>& handle, const void* data, uint64_t size) {
	return Transfer(handle, const_cast<void*>(data), size, 0, true, true);
}

int64_t Pwrite(const std::shared_ptr<Handle>& handle, const void* data, uint64_t size,
               uint64_t offset) {
	return Transfer(handle, const_cast<void*>(data), size, offset, false, true);
}

int64_t Seek(const std::shared_ptr<Handle>& handle, int64_t offset, int whence) {
	if (!handle) return KERNEL_ERROR_EBADF;
	SharedLock lock(handle->state);
	if (lock.error != OK) return lock.error;
	OpenRecord*  open   = nullptr;
	MountRecord* mount  = nullptr;
	NodeRecord*  node   = nullptr;
	const int    result = ResolveHandle(handle, &open, &mount, &node);
	if (result != OK) return result;
	if (IsDirectory(*node)) return KERNEL_ERROR_ENOTSUP;
	if (whence < 0 || whence > 2) return KERNEL_ERROR_EINVAL;
	const uint64_t base   = whence == 0 ? 0 : whence == 1 ? open->offset : node->size;
	uint64_t       target = 0;
	if (offset < 0) {
		const uint64_t distance = static_cast<uint64_t>(-(offset + 1)) + 1;
		if (distance > base) return KERNEL_ERROR_EINVAL;
		target = base - distance;
	} else {
		if (static_cast<uint64_t>(offset) > static_cast<uint64_t>(INT64_MAX) - base)
			return KERNEL_ERROR_EINVAL;
		target = base + static_cast<uint64_t>(offset);
	}
	open->offset = target;
	return static_cast<int64_t>(target);
}

int Truncate(const std::shared_ptr<Handle>& handle, uint64_t size) {
	if (!handle) return KERNEL_ERROR_EBADF;
	if (size > MaximumMountBytes) return KERNEL_ERROR_EFBIG;
	SharedLock lock(handle->state);
	if (lock.error != OK) return lock.error;
	OpenRecord*  open   = nullptr;
	MountRecord* mount  = nullptr;
	NodeRecord*  node   = nullptr;
	const int    result = ResolveHandle(handle, &open, &mount, &node);
	if (result != OK) return result;
	if (IsDirectory(*node)) return KERNEL_ERROR_EISDIR;
	if (open->access == 0) return KERNEL_ERROR_EBADF;
	if (size > node->size) {
		const int allocated = ReservePages(*mount, open->node, 0, size);
		if (allocated != OK) return allocated;
	}
	Resize(*mount, open->node, size);
	if (credentials.uid != 0) node->mode &= ~06000u;
	return OK;
}

int Stat(const std::string& path, NodeStat* stat) {
	if (stat == nullptr) return KERNEL_ERROR_EFAULT;
	std::string normalized;
	int         result = NormalizePath(path, &normalized);
	if (result != OK) return result;
	std::shared_ptr<NamespaceState> state;
	result = Current(&state);
	if (result != OK) return result;
	SharedLock lock(state);
	if (lock.error != OK) return lock.error;
	result = Traverse(state->shared, path);
	if (result != OK) return result;
	const uint32_t mount_index = FindMount(state->shared, normalized);
	if (mount_index == InvalidSlot) return KERNEL_ERROR_ENOENT;
	const auto& mount = state->shared->mounts[mount_index];
	uint32_t    index = InvalidSlot;
	result            = Lookup(mount, normalized, &index);
	if (result != OK) return result;
	if (TrailingDirectory(path) && !IsDirectory(mount.nodes[index])) return KERNEL_ERROR_ENOTDIR;
	FillStat(mount, mount.nodes[index], stat);
	return OK;
}

int Fstat(const std::shared_ptr<Handle>& handle, NodeStat* stat) {
	if (stat == nullptr) return KERNEL_ERROR_EFAULT;
	if (!handle) return KERNEL_ERROR_EBADF;
	SharedLock lock(handle->state);
	if (lock.error != OK) return lock.error;
	OpenRecord*  open   = nullptr;
	MountRecord* mount  = nullptr;
	NodeRecord*  node   = nullptr;
	const int    result = ResolveHandle(handle, &open, &mount, &node);
	if (result != OK) return result;
	FillStat(*mount, *node, stat);
	return OK;
}

int Entries(const std::shared_ptr<Handle>& handle, std::vector<DirectoryEntry>* entries) {
	if (entries == nullptr) return KERNEL_ERROR_EFAULT;
	if (!handle) return KERNEL_ERROR_EBADF;
	SharedLock lock(handle->state);
	if (lock.error != OK) return lock.error;
	OpenRecord*  open   = nullptr;
	MountRecord* mount  = nullptr;
	NodeRecord*  node   = nullptr;
	const int    result = ResolveHandle(handle, &open, &mount, &node);
	if (result != OK) return result;
	if (!IsDirectory(*node)) return KERNEL_ERROR_ENOTDIR;
	if (open->access == 1) return KERNEL_ERROR_EBADF;
	try {
		std::vector<DirectoryEntry> staged;
		staged.reserve(mount->inode_count + 2);
		staged.push_back({node->inode, 4, "."});
		staged.push_back({mount->entries[open->node].parent, 4, ".."});
		for (uint32_t index = 1; index < mount->inode_limit; ++index) {
			const auto& entry = mount->entries[index];
			const auto& child = mount->nodes[index];
			if (entry.linked != 0 && entry.parent == node->inode && child.inode != 0) {
				staged.push_back({child.inode, static_cast<uint8_t>(IsDirectory(child) ? 4 : 8),
				                  std::string(entry.name)});
			}
		}
		std::sort(staged.begin() + 2, staged.end(),
		          [](const auto& left, const auto& right) { return left.name < right.name; });
		node->accessed = Now();
		*entries       = std::move(staged);
		return OK;
	} catch (const std::bad_alloc&) {
		return KERNEL_ERROR_ENOMEM;
	}
}

int Mkdir(const std::string& path, uint32_t mode) {
	if ((mode & ~07777u) != 0) return KERNEL_ERROR_EINVAL;
	std::string normalized;
	int         result = NormalizePath(path, &normalized);
	if (result != OK) return result;
	std::shared_ptr<NamespaceState> state;
	result = Current(&state);
	if (result != OK) return result;
	SharedLock lock(state);
	if (lock.error != OK) return lock.error;
	result = Traverse(state->shared, path);
	if (result != OK) return result;
	ReapDeadOwners(*state);
	const uint32_t mount_index = FindMount(state->shared, normalized);
	if (mount_index == InvalidSlot) return KERNEL_ERROR_ENOENT;
	auto&            mount  = state->shared->mounts[mount_index];
	uint32_t         parent = InvalidSlot;
	std::string_view name;
	result = Parent(mount, normalized, &parent, &name);
	if (result != OK) return normalized == mount.path ? KERNEL_ERROR_EEXIST : result;
	if (!Allowed(mount.nodes[parent], WritePermission | SearchPermission))
		return KERNEL_ERROR_EACCES;
	if (FindChild(mount, mount.nodes[parent].inode, name) != InvalidSlot)
		return KERNEL_ERROR_EEXIST;
	if (mount.inode_count >= mount.inode_limit ||
	    !CanCharge(mount, ModelNodeBytes + ModelDirectoryEntryBytes))
		return KERNEL_ERROR_ENOSPC;
	const uint32_t index = FreeNode(mount);
	if (index == InvalidSlot || mount.next_inode == 0 || mount.next_inode > UINT32_MAX)
		return KERNEL_ERROR_ENOSPC;
	CreateNode(mount, index, parent, name, DirectoryMode | (mode & ~credentials.mask));
	return OK;
}

namespace {

int Remove(const std::string& path, bool directory) {
	if (directory && SpecialFinalComponent(path)) return KERNEL_ERROR_EINVAL;
	std::string normalized;
	int         result = NormalizePath(path, &normalized);
	if (result != OK) return result;
	std::shared_ptr<NamespaceState> state;
	result = Current(&state);
	if (result != OK) return result;
	SharedLock lock(state);
	if (lock.error != OK) return lock.error;
	result = Traverse(state->shared, path);
	if (result != OK) return result;
	ReapDeadOwners(*state);
	const uint32_t mount_index = FindMount(state->shared, normalized);
	if (mount_index == InvalidSlot) return KERNEL_ERROR_ENOENT;
	auto&            mount  = state->shared->mounts[mount_index];
	uint32_t         parent = InvalidSlot;
	std::string_view name;
	result = Parent(mount, normalized, &parent, &name);
	if (result != OK) return result;
	auto& parent_node = mount.nodes[parent];
	if (!Allowed(parent_node, WritePermission | SearchPermission)) return KERNEL_ERROR_EACCES;
	const uint32_t index = FindChild(mount, parent_node.inode, name);
	if (index == InvalidSlot) return KERNEL_ERROR_ENOENT;
	const auto& node = mount.nodes[index];
	if ((directory || TrailingDirectory(path)) && !IsDirectory(node)) return KERNEL_ERROR_ENOTDIR;
	if (!directory && IsDirectory(node)) return KERNEL_ERROR_EPERM;
	if (!StickyAllowed(parent_node, node)) return KERNEL_ERROR_EPERM;
	if (directory && !DirectoryEmpty(mount, index)) return KERNEL_ERROR_ENOTEMPTY;
	RemoveEntry(mount, index);
	return OK;
}

} // namespace

int Unlink(const std::string& path) {
	return Remove(path, false);
}

int Rmdir(const std::string& path) {
	return Remove(path, true);
}

int Rename(const std::string& from, const std::string& to) {
	if (SpecialFinalComponent(from) || SpecialFinalComponent(to)) return KERNEL_ERROR_EINVAL;
	std::string source;
	std::string target;
	int         result = NormalizePath(from, &source);
	if (result != OK) return result;
	result = NormalizePath(to, &target);
	if (result != OK) return result;
	std::shared_ptr<NamespaceState> state;
	result = Current(&state);
	if (result != OK) return result;
	SharedLock lock(state);
	if (lock.error != OK) return lock.error;
	result = Traverse(state->shared, from);
	if (result != OK) return result;
	result = Traverse(state->shared, to);
	if (result != OK) return result;
	ReapDeadOwners(*state);
	auto*          shared       = state->shared;
	const uint32_t source_mount = FindMount(shared, source);
	const uint32_t target_mount = FindMount(shared, target);
	if (source_mount == InvalidSlot || target_mount == InvalidSlot || source_mount != target_mount)
		return KERNEL_ERROR_EXDEV;
	auto&            mount         = shared->mounts[source_mount];
	uint32_t         source_parent = InvalidSlot;
	uint32_t         target_parent = InvalidSlot;
	std::string_view source_name, target_name;
	result = Parent(mount, source, &source_parent, &source_name);
	if (result != OK) return result;
	result = Parent(mount, target, &target_parent, &target_name);
	if (result != OK) return result;
	if (!Allowed(mount.nodes[source_parent], WritePermission | SearchPermission) ||
	    !Allowed(mount.nodes[target_parent], WritePermission | SearchPermission))
		return KERNEL_ERROR_EACCES;
	const uint32_t index = FindChild(mount, mount.nodes[source_parent].inode, source_name);
	if (index == InvalidSlot) return KERNEL_ERROR_ENOENT;
	const auto& node = mount.nodes[index];
	if (TrailingDirectory(from) && !IsDirectory(node)) return KERNEL_ERROR_ENOTDIR;
	if (!StickyAllowed(mount.nodes[source_parent], node)) return KERNEL_ERROR_EPERM;
	const uint32_t destination = FindChild(mount, mount.nodes[target_parent].inode, target_name);
	if (destination == index) return OK;
	if (TrailingDirectory(to) && destination == InvalidSlot) return KERNEL_ERROR_ENOENT;
	if (IsDirectory(node)) {
		uint32_t ancestor = target_parent;
		for (uint32_t depth = 0; depth < MaximumInodes; ++depth) {
			if (ancestor == index) return KERNEL_ERROR_EINVAL;
			if (ancestor == 0) break;
			ancestor = FindInode(mount, mount.entries[ancestor].parent);
			if (ancestor == InvalidSlot) return KERNEL_ERROR_EIO;
		}
	}
	if (destination != InvalidSlot) {
		const auto& existing = mount.nodes[destination];
		if (IsDirectory(node) && !IsDirectory(existing)) return KERNEL_ERROR_ENOTDIR;
		if (!IsDirectory(node) && IsDirectory(existing)) return KERNEL_ERROR_EISDIR;
		if (TrailingDirectory(to) && !IsDirectory(existing)) return KERNEL_ERROR_ENOTDIR;
		if (!StickyAllowed(mount.nodes[target_parent], existing)) return KERNEL_ERROR_EPERM;
		if (IsDirectory(existing) && !DirectoryEmpty(mount, destination))
			return KERNEL_ERROR_ENOTEMPTY;
		RemoveEntry(mount, destination);
	}
	auto& entry = mount.entries[index];
	mount.nodes[source_parent].size -= ModelDirectoryEntryBytes;
	mount.nodes[target_parent].size += ModelDirectoryEntryBytes;
	if (IsDirectory(node) && source_parent != target_parent) {
		--mount.nodes[source_parent].links;
		++mount.nodes[target_parent].links;
	}
	entry.parent = mount.nodes[target_parent].inode;
	std::memset(entry.name, 0, sizeof(entry.name));
	std::memcpy(entry.name, target_name.data(), target_name.size());
	const int64_t time                  = Now();
	mount.nodes[index].changed          = time;
	mount.nodes[source_parent].modified = mount.nodes[source_parent].changed = time;
	mount.nodes[target_parent].modified = mount.nodes[target_parent].changed = time;
	return OK;
}

#else

class Handle {};

int Initialize(const std::string&) {
	return KERNEL_ERROR_ENOTSUP;
}
void Shutdown() {
	credentials = {};
}
int ValidateTraversal(const std::string& path) {
	std::string normalized;
	return NormalizePath(path, &normalized);
}
bool Contains(const std::string&) {
	return false;
}
bool Overlaps(const std::string&) {
	return false;
}
int Mount(const std::string&, uint32_t, uint64_t, uint32_t, uint32_t, uint32_t) {
	return KERNEL_ERROR_ENOTSUP;
}
int Unmount(const std::string&) {
	return KERNEL_ERROR_ENOTSUP;
}
int QueryUsage(const std::string&, Usage*) {
	return KERNEL_ERROR_ENOTSUP;
}
int Open(const std::string&, int, uint32_t, std::shared_ptr<Handle>*) {
	return KERNEL_ERROR_ENOTSUP;
}
int Close(std::shared_ptr<Handle>& handle) {
	if (!handle) return KERNEL_ERROR_EBADF;
	handle.reset();
	return OK;
}
int64_t Read(const std::shared_ptr<Handle>&, void*, uint64_t) {
	return KERNEL_ERROR_ENOTSUP;
}
int64_t Pread(const std::shared_ptr<Handle>&, void*, uint64_t, uint64_t) {
	return KERNEL_ERROR_ENOTSUP;
}
int64_t Write(const std::shared_ptr<Handle>&, const void*, uint64_t) {
	return KERNEL_ERROR_ENOTSUP;
}
int64_t Pwrite(const std::shared_ptr<Handle>&, const void*, uint64_t, uint64_t) {
	return KERNEL_ERROR_ENOTSUP;
}
int64_t Seek(const std::shared_ptr<Handle>&, int64_t, int) {
	return KERNEL_ERROR_ENOTSUP;
}
int Truncate(const std::shared_ptr<Handle>&, uint64_t) {
	return KERNEL_ERROR_ENOTSUP;
}
int Stat(const std::string&, NodeStat*) {
	return KERNEL_ERROR_ENOTSUP;
}
int Fstat(const std::shared_ptr<Handle>&, NodeStat*) {
	return KERNEL_ERROR_ENOTSUP;
}
int Entries(const std::shared_ptr<Handle>&, std::vector<DirectoryEntry>*) {
	return KERNEL_ERROR_ENOTSUP;
}
int Mkdir(const std::string&, uint32_t) {
	return KERNEL_ERROR_ENOTSUP;
}
int Unlink(const std::string&) {
	return KERNEL_ERROR_ENOTSUP;
}
int Rmdir(const std::string&) {
	return KERNEL_ERROR_ENOTSUP;
}
int Rename(const std::string&, const std::string&) {
	return KERNEL_ERROR_ENOTSUP;
}

#endif

int ExportHandle(const std::shared_ptr<Handle>& handle, std::string* token) {
	if (token == nullptr) return KERNEL_ERROR_EFAULT;
	if (!handle) return KERNEL_ERROR_EBADF;
	return KERNEL_ERROR_ENOSYS;
}

int ImportHandle(const std::string&, std::shared_ptr<Handle>* handle) {
	if (handle == nullptr) return KERNEL_ERROR_EFAULT;
	return KERNEL_ERROR_ENOSYS;
}

} // namespace Libs::LibKernel::Tmpfs
