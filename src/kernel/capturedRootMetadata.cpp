#include "kernel/capturedRootMetadata.h"

#include "kernel/capturedMetadataCache.h"
#include "kernel/authInfo.h"
#include "kernel/fileSystem.h"
#include "libs/errno.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <unordered_map>
#include <unordered_set>

namespace Libs::LibKernel::CapturedRootMetadata {
namespace {

constexpr size_t NodeSize    = 0x2f0;
constexpr size_t ImageSize   = 103546880;
constexpr char   ImageHash[] = "201bbbebe7d347b53148e88b3c2d7dec3e844aa36f1075e73d1b34c1101d6176";
constexpr Layout CapturedLayout {0xffffffff9e3f0000ull, 0x2e692c0, 0x2e6a4f8, 871};

struct InvalidImage {};

class Reader {
public:
	Reader(std::span<const uint8_t> bytes, uint64_t base): bytes(bytes), base(base) {}

	void Span(size_t offset, size_t size) const {
		if (offset > bytes.size() || size > bytes.size() - offset) throw InvalidImage {};
	}

	uint64_t Number(size_t offset, size_t size) const {
		Span(offset, size);
		uint64_t value = 0;
		for (size_t n = 0; n < size; ++n)
			value |= static_cast<uint64_t>(bytes[offset + n]) << (8 * n);
		return value;
	}

	size_t Offset(uint64_t pointer, size_t size) const {
		if (pointer < base || pointer - base > std::numeric_limits<size_t>::max())
			throw InvalidImage {};
		const auto offset = static_cast<size_t>(pointer - base);
		Span(offset, size);
		return offset;
	}

	uint64_t Pointer(size_t offset) const {
		if (offset > UINT64_MAX - base) throw InvalidImage {};
		return base + offset;
	}

	bool Equals(size_t offset, const char* text, size_t size) const {
		Span(offset, size);
		return std::memcmp(bytes.data() + offset, text, size) == 0;
	}

	std::string Name(size_t offset) const {
		std::string name;
		for (size_t n = 0; n < 0x104; ++n) {
			const auto character = Number(offset + n * 2, 2);
			if (character == 0) return name;
			if (name.size() == 255) throw InvalidImage {};
			if (character < 0x20 || character > 0x7e || character == '/' || character == '\\')
				throw InvalidImage {};
			name.push_back(static_cast<char>(character));
		}
		throw InvalidImage {};
	}

private:
	std::span<const uint8_t> bytes;
	uint64_t                 base;
};

struct Node {
	std::string name;
	uint64_t    vnode = 0, parent_vnode = 0, size = 0;
	uint32_t    cluster = 0, parent_cluster = 0;
	uint8_t     attributes = 0;
	bool        directory = false, root = false;
};

std::mutex                      snapshot_mutex;
std::shared_ptr<const Snapshot> published;
bool                            last_load_cache_hit = false;

constexpr uint64_t RootCachePayloadLimit = 1024 * 1024;

bool ValidCachedPath(const std::string& path) {
	return !path.empty() && path[0] == '/' && path.size() < 4096 && path.find('\0') == path.npos &&
	       path.find('\\') == path.npos && path.find("//") == path.npos &&
	       (path.size() == 1 || path.back() != '/');
}

std::vector<uint8_t> EncodeSnapshot(const Snapshot& snapshot) {
	CapturedMetadataCache::Writer writer;
	writer.U64(snapshot.root_node_count);
	writer.U32(static_cast<uint32_t>(snapshot.directories.size()));
	for (const auto& directory: snapshot.directories) {
		writer.String(directory.path);
		writer.U32(directory.inode);
		writer.U32(directory.mode);
		writer.U32(directory.uid);
		writer.U32(directory.gid);
		writer.U32(directory.block_size);
		writer.U64(directory.size);
		writer.U32(directory.flags);
	}
	return writer.Bytes();
}

bool DecodeSnapshot(std::span<const uint8_t> payload, Snapshot* snapshot) {
	if (snapshot == nullptr) return false;
	CapturedMetadataCache::Reader reader(payload);
	uint64_t                      root_node_count = 0;
	uint32_t                      directory_count = 0;
	if (!reader.U64(&root_node_count) || !reader.U32(&directory_count) || root_node_count != 24 ||
	    directory_count != 17)
		return false;
	Snapshot decoded;
	decoded.root_node_count = static_cast<size_t>(root_node_count);
	decoded.directories.reserve(directory_count);
	for (uint32_t n = 0; n < directory_count; ++n) {
		Directory directory;
		if (!reader.String(&directory.path, 4095) || !reader.U32(&directory.inode) ||
		    !reader.U32(&directory.mode) || !reader.U32(&directory.uid) ||
		    !reader.U32(&directory.gid) || !reader.U32(&directory.block_size) ||
		    !reader.U64(&directory.size) || !reader.U32(&directory.flags) ||
		    !ValidCachedPath(directory.path) || (directory.mode & 0170000u) != 0040000u ||
		    directory.block_size != 4096 || directory.size > INT64_MAX ||
		    (!decoded.directories.empty() && decoded.directories.back().path >= directory.path))
			return false;
		decoded.directories.push_back(std::move(directory));
	}
	if (!reader.Done() || decoded.directories.front().path != "/") return false;
	*snapshot = std::move(decoded);
	return true;
}

CapturedMetadataCache::Key RootCacheKey(const std::filesystem::path& path) {
	const std::string discriminator = std::string("root_snapshot_v1:") + ImageHash + ":" +
	                                  std::to_string(ImageSize) + ":" +
	                                  std::to_string(CapturedLayout.virtual_base) + ":" +
	                                  std::to_string(CapturedLayout.filesystem_offset) + ":" +
	                                  std::to_string(CapturedLayout.nodes_offset) + ":" +
	                                  std::to_string(CapturedLayout.node_count);
	const std::array<std::filesystem::path, 1> sources {path};
	return CapturedMetadataCache::Prepare("captured_root", discriminator, sources,
	                                      RootCachePayloadLimit);
}

} // namespace

int Decode(std::span<const uint8_t> image, const Layout& layout, Snapshot* snapshot) try {
	if (snapshot == nullptr) return KERNEL_ERROR_EFAULT;
	if (layout.node_count == 0 || layout.node_count > 4096 ||
	    layout.node_count > (SIZE_MAX - layout.nodes_offset) / NodeSize)
		return KERNEL_ERROR_EINVAL;
	Reader reader(image, layout.virtual_base);
	reader.Span(layout.filesystem_offset, 0x100);
	reader.Span(layout.nodes_offset, layout.node_count * NodeSize);
	const auto fs   = layout.filesystem_offset;
	const auto boot = reader.Offset(reader.Number(fs + 0x18, 8), 512);
	if (fs + 0x100 > boot || boot + 512 > layout.nodes_offset ||
	    !reader.Equals(boot + 3, "SCEI    ", 8) || !reader.Equals(boot + 43, "ORBIS ROOT ", 11) ||
	    !reader.Equals(boot + 54, "FAT12   ", 8) || reader.Number(boot + 510, 2) != 0xaa55 ||
	    reader.Number(boot + 11, 2) != 512 || reader.Number(boot + 13, 1) != 8 ||
	    reader.Number(boot + 14, 2) != 1 || reader.Number(boot + 16, 1) != 2 ||
	    reader.Number(boot + 17, 2) != 512 || reader.Number(boot + 19, 2) != 14336 ||
	    reader.Number(boot + 22, 2) != 6 || reader.Number(fs + 0x2c, 4) != 12 ||
	    reader.Number(fs + 0x40, 4) != 0x1d01 || reader.Number(fs + 0x44, 4) != 1 ||
	    reader.Number(fs + 0x4c, 4) != 512 || reader.Number(fs + 0x50, 4) != 8)
		return KERNEL_ERROR_EINVAL;
	std::vector<Node>                    nodes;
	std::unordered_map<uint64_t, size_t> by_vnode;
	std::unordered_map<uint32_t, size_t> by_cluster;
	size_t                               root = SIZE_MAX;
	for (size_t n = 0; n < layout.node_count; ++n) {
		const auto offset = layout.nodes_offset + n * NodeSize;
		if (reader.Number(offset + 0x210, 8) != reader.Pointer(fs)) continue;
		Node       node;
		const auto component = reader.Number(offset + 0x208, 8);
		node.root = reader.Number(offset, 2) == '/' && reader.Number(offset + 2, 2) == 0 &&
		            component == reader.Pointer(offset + 2);
		if (!node.root && component != reader.Pointer(offset)) return KERNEL_ERROR_EINVAL;
		if (!node.root) node.name = reader.Name(offset);
		if ((!node.root && (node.name.empty() || node.name == "." || node.name == "..")) ||
		    (node.root && root != SIZE_MAX))
			return KERNEL_ERROR_EINVAL;
		node.directory  = reader.Number(offset + 0x21a, 2) == 6;
		node.size       = reader.Number(offset + 0x220, 8);
		node.attributes = static_cast<uint8_t>(reader.Number(offset + 0x265, 1));
		if (node.directory != ((node.attributes & 0x10u) != 0)) return KERNEL_ERROR_EINVAL;
		node.cluster        = static_cast<uint32_t>(reader.Number(offset + 0x260, 4));
		node.parent_cluster = static_cast<uint32_t>(reader.Number(offset + 0x278, 4));
		node.vnode          = reader.Number(offset + 0x2e0, 8);
		node.parent_vnode   = reader.Number(offset + 0x2e8, 8);
		if (node.vnode == 0 || !by_vnode.emplace(node.vnode, nodes.size()).second ||
		    (node.directory && !by_cluster.emplace(node.cluster, nodes.size()).second))
			return KERNEL_ERROR_EINVAL;
		if (node.directory && (node.size == 0 || node.size > INT64_MAX || node.size % 4096 != 0))
			return KERNEL_ERROR_EINVAL;
		if (node.root) {
			if (!node.directory || node.cluster != 0 || node.parent_cluster != 0xfffffffeu ||
			    node.parent_vnode != 0)
				return KERNEL_ERROR_EINVAL;
			root = nodes.size();
		} else if (node.directory && (node.cluster < 2 || node.cluster >= 0xff7)) {
			return KERNEL_ERROR_EINVAL;
		}
		nodes.push_back(std::move(node));
	}
	if (root == SIZE_MAX) return KERNEL_ERROR_EINVAL;
	std::vector<size_t> parents(nodes.size(), SIZE_MAX);
	for (size_t n = 0; n < nodes.size(); ++n) {
		if (n == root) continue;
		const auto vnode   = by_vnode.find(nodes[n].parent_vnode);
		const auto cluster = by_cluster.find(nodes[n].parent_cluster);
		if (vnode == by_vnode.end() || cluster == by_cluster.end() ||
		    vnode->second != cluster->second || vnode->second == n ||
		    !nodes[vnode->second].directory)
			return KERNEL_ERROR_EINVAL;
		parents[n] = vnode->second;
	}
	Snapshot decoded;
	decoded.root_node_count = nodes.size();
	std::unordered_set<std::string> paths;
	for (size_t n = 0; n < nodes.size(); ++n) {
		std::vector<size_t> ancestry;
		size_t              current = n;
		while (current != root) {
			if (ancestry.size() >= nodes.size() ||
			    std::find(ancestry.begin(), ancestry.end(), current) != ancestry.end())
				return KERNEL_ERROR_EINVAL;
			ancestry.push_back(current);
			current = parents[current];
		}
		std::string path = "/";
		for (auto entry = ancestry.rbegin(); entry != ancestry.rend(); ++entry) {
			if (path.size() > 1) path += '/';
			path += nodes[*entry].name;
		}
		if (path.size() >= 4096) return KERNEL_ERROR_EINVAL;
		if (!paths.insert(path).second) return KERNEL_ERROR_EINVAL;
		if (!nodes[n].directory) continue;
		const auto attributes = nodes[n].attributes;
		decoded.directories.push_back({std::move(path), n == root ? 1u : nodes[n].cluster,
		                               0040000u | ((attributes & 1u) != 0 ? 0555u : 0777u),
		                               static_cast<uint32_t>(reader.Number(fs + 0xf0, 4)),
		                               static_cast<uint32_t>(reader.Number(fs + 0xf4, 4)), 4096,
		                               nodes[n].size, (attributes & 0x20u) == 0 ? 0x10000u : 0u});
	}
	std::sort(decoded.directories.begin(), decoded.directories.end(),
	          [](const auto& left, const auto& right) { return left.path < right.path; });
	*snapshot = std::move(decoded);
	return OK;
} catch (const InvalidImage&) {
	return KERNEL_ERROR_EINVAL;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int Lookup(const Snapshot& snapshot, const std::string& path, FileSystem::FileStat* stat) try {
	if (stat == nullptr) return KERNEL_ERROR_EFAULT;
	if (path.empty() || path.size() >= 4096 || path[0] != '/' || path.find('\0') != path.npos ||
	    path.find('\\') != path.npos)
		return KERNEL_ERROR_EINVAL;
	std::string canonical = "/";
	const auto  find      = [&]() {
		return std::find_if(snapshot.directories.begin(), snapshot.directories.end(),
		                    [&](const auto& directory) { return directory.path == canonical; });
	};
	if (find() == snapshot.directories.end()) return KERNEL_ERROR_EIO;
	for (size_t start = 1; start <= path.size();) {
		const auto end  = path.find('/', start);
		const auto part = path.substr(start, end == path.npos ? path.npos : end - start);
		if (part.size() > 255) return KERNEL_ERROR_ENAMETOOLONG;
		if (part == "..") {
			const auto slash = canonical.rfind('/');
			canonical.resize(slash == 0 ? 1 : slash);
		} else if (!part.empty() && part != ".") {
			if (canonical.size() > 1) canonical += '/';
			canonical += part;
		}
		if (find() == snapshot.directories.end()) return KERNEL_ERROR_ENOENT;
		if (end == path.npos) break;
		start = end + 1;
	}
	const auto found = find();
	if (found == snapshot.directories.end()) return KERNEL_ERROR_ENOENT;
	FileSystem::FileStat result {};
	result.st_dev     = UINT32_MAX;
	result.st_ino     = found->inode;
	result.st_mode    = static_cast<uint16_t>(found->mode);
	result.st_nlink   = 1;
	result.st_uid     = found->uid;
	result.st_gid     = found->gid;
	result.st_rdev    = UINT32_MAX;
	result.st_size    = static_cast<int64_t>(found->size);
	result.st_blocks  = static_cast<int64_t>(found->size / 512);
	result.st_blksize = found->block_size;
	result.st_flags   = found->flags;
	result.st_gen     = UINT32_MAX;
	result.st_atim = result.st_mtim = result.st_ctim = result.st_birthtim = {-1, -1};
	*stat                                                                 = result;
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int Load(const std::filesystem::path& path) try {
	const auto           cache_key = RootCacheKey(path);
	std::vector<uint8_t> cached;
	Snapshot             decoded;
	if (CapturedMetadataCache::Read(cache_key, &cached) == CapturedMetadataCache::ReadResult::Hit &&
	    DecodeSnapshot(cached, &decoded)) {
		std::shared_ptr<const Snapshot> ready = std::make_shared<Snapshot>(std::move(decoded));
		std::lock_guard                 lock(snapshot_mutex);
		published.swap(ready);
		last_load_cache_hit = true;
		return OK;
	}
	std::error_code error;
	const auto      status = std::filesystem::status(path, error);
	if (error == std::errc::no_such_file_or_directory) return KERNEL_ERROR_ENOENT;
	if (error == std::errc::permission_denied) return KERNEL_ERROR_EACCES;
	if (error) return KERNEL_ERROR_EIO;
	if (!std::filesystem::exists(status)) return KERNEL_ERROR_ENOENT;
	if (!std::filesystem::is_regular_file(status)) return KERNEL_ERROR_EINVAL;
	std::ifstream input(path, std::ios::binary | std::ios::ate);
	if (!input) return KERNEL_ERROR_EACCES;
	if (input.tellg() != static_cast<std::streamoff>(ImageSize)) return KERNEL_ERROR_EINVAL;
	std::vector<uint8_t> bytes(ImageSize);
	input.seekg(0);
	if (!input.read(reinterpret_cast<char*>(bytes.data()),
	                static_cast<std::streamsize>(bytes.size())))
		return KERNEL_ERROR_EIO;
	if (input.peek() != std::ifstream::traits_type::eof()) return KERNEL_ERROR_EINVAL;
	if (AuthInfo::DigestHex(AuthInfo::Sha256(bytes.data(), bytes.size())) != ImageHash)
		return KERNEL_ERROR_EINVAL;
	const int result = Decode(bytes, CapturedLayout, &decoded);
	if (result != OK) return result;
	if (decoded.root_node_count != 24 || decoded.directories.size() != 17)
		return KERNEL_ERROR_EINVAL;
	const auto encoded = EncodeSnapshot(decoded);
	CapturedMetadataCache::Write(cache_key, encoded);
	std::shared_ptr<const Snapshot> ready = std::make_shared<Snapshot>(std::move(decoded));
	std::lock_guard                 lock(snapshot_mutex);
	published.swap(ready);
	last_load_cache_hit = false;
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
} catch (const std::filesystem::filesystem_error&) {
	return KERNEL_ERROR_EIO;
}

void Shutdown() {
	std::lock_guard lock(snapshot_mutex);
	published.reset();
	last_load_cache_hit = false;
}

bool Enabled() {
	std::lock_guard lock(snapshot_mutex);
	return published != nullptr;
}

bool LastLoadUsedStartupCache() {
	std::lock_guard lock(snapshot_mutex);
	return published != nullptr && last_load_cache_hit;
}

int Stat(const std::string& path, FileSystem::FileStat* stat) {
	std::shared_ptr<const Snapshot> snapshot;
	{
		std::lock_guard lock(snapshot_mutex);
		snapshot = published;
	}
	return snapshot ? Lookup(*snapshot, path, stat) : KERNEL_ERROR_ENOENT;
}

} // namespace Libs::LibKernel::CapturedRootMetadata
