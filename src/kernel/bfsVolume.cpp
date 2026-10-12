#include "kernel/bfsVolume.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <utility>

namespace Libs::LibKernel {
namespace {

using Result = BfsVolume::Result;

constexpr uint32_t BlockBytes     = 0x10000;
constexpr uint32_t InodeBytes     = 0x100;
constexpr uint32_t InodesPerBlock = BlockBytes / InodeBytes;

constexpr uint64_t MetadataMagic          = 0x10F50BF520180705ULL;
constexpr uint64_t SuperblockMagicCurrent = 0x20F50BF520190705ULL;
constexpr uint64_t SuperblockMagicLegacy  = 0x20F50BF520180713ULL;
constexpr uint32_t InodeMagic             = 0xBF10u;

constexpr uint16_t TagTerminator         = 0x0000;
constexpr uint16_t TagSuperblockLbnArray = 0x0001;
constexpr uint16_t TagDivisionRecords    = 0x0100;
constexpr uint16_t TagFreeBitmapLbn      = 0x1000;

constexpr uint32_t RootInode = 2;

constexpr uint32_t InodeOffsetMagic       = 0;
constexpr uint32_t InodeOffsetMode        = 16;
constexpr uint32_t InodeOffsetSize        = 40;
constexpr uint32_t InodeOffsetNblocks     = 48;
constexpr uint32_t InodeOffsetNlink       = 56;
constexpr uint32_t InodeOffsetFirstDirect = 128;

constexpr uint32_t DirentHeaderBytes = 16;

constexpr uint8_t DirentTypeDir = 4;
constexpr uint8_t DirentTypeReg = 8;

uint16_t U16(const uint8_t* p) {
	return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
}
uint32_t U32(const uint8_t* p) {
	return uint32_t(U16(p)) | (uint32_t(U16(p + 2)) << 16);
}
uint64_t U64(const uint8_t* p) {
	return uint64_t(U32(p)) | (uint64_t(U32(p + 4)) << 32);
}

Result MediaResult(SectorBacking::Result result) {
	switch (result) {
		case SectorBacking::Result::Ok: return Result::Ok;
		case SectorBacking::Result::MissingData: return Result::MissingData;
		case SectorBacking::Result::Io: return Result::Io;
		case SectorBacking::Result::Unsupported: return Result::Unsupported;
		default: return Result::Corrupt;
	}
}

struct DivisionRecord {
	uint32_t start_lbn   = 0;
	uint32_t block_count = 0;
	// fsck only reads +0 and +4 of the 32-byte record
};

struct Dinode {
	uint32_t inum             = 0;
	uint32_t mode             = 0;
	uint64_t size             = 0;
	uint32_t nblocks          = 0;
	uint32_t nlink            = 0;
	uint32_t first_direct_lbn = 0;
	bool     directory        = false;
};

bool IsPrintableName(const char* name, size_t length) {
	if (length == 0) return false;
	for (size_t i = 0; i < length; ++i) {
		const auto c = static_cast<uint8_t>(name[i]);
		if (c == 0 || c == '/') return false;
	}
	return true;
}

} // namespace

struct BfsVolume::State {
	std::mutex                     mutex;
	std::shared_ptr<SectorBacking> backing;
	uint64_t                       capacity = 0;
	bool                           clean    = false;
	std::string                    partition_name;

	std::vector<DivisionRecord> divisions;
	uint32_t                    free_bitmap_lbn  = 0;
	bool                        have_free_bitmap = false;

	// TODO: division[0] only, the inum->division mapping isn't RE'd
	std::map<uint32_t, Dinode>             inodes;
	std::map<uint32_t, std::vector<Entry>> directory_cache;

	Result ReadBlock(uint32_t lbn, void* bytes) const {
		const uint64_t offset = uint64_t(lbn) * BlockBytes;
		if (offset > capacity || BlockBytes > capacity - offset) return Result::Corrupt;
		return MediaResult(backing->Read(offset, bytes, BlockBytes));
	}

	Result ReadRange(uint64_t offset, void* bytes, size_t length) const {
		if (offset > capacity || length > capacity - offset) return Result::Corrupt;
		return MediaResult(backing->Read(offset, bytes, length));
	}

	Result LoadInode(uint32_t inum, Dinode* out) {
		if (auto it = inodes.find(inum); it != inodes.end()) {
			*out = it->second;
			return Result::Ok;
		}
		if (divisions.empty()) return Result::Corrupt;
		const uint32_t block_offset = inum / InodesPerBlock;
		if (block_offset >= divisions[0].block_count) return Result::NotFound;
		const uint32_t                  lbn = divisions[0].start_lbn + block_offset;
		std::array<uint8_t, BlockBytes> block {};
		const Result                    media = ReadBlock(lbn, block.data());
		if (media != Result::Ok) return media;
		const uint8_t* dinode = block.data() + uint32_t(inum % InodesPerBlock) * InodeBytes;
		if (U32(dinode + InodeOffsetMagic) != InodeMagic) return Result::Corrupt;
		Dinode node {};
		node.inum             = inum;
		node.mode             = U32(dinode + InodeOffsetMode);
		node.size             = U64(dinode + InodeOffsetSize);
		node.nblocks          = U32(dinode + InodeOffsetNblocks);
		node.nlink            = U32(dinode + InodeOffsetNlink);
		node.first_direct_lbn = U32(dinode + InodeOffsetFirstDirect);
		if ((node.mode & 0170000u) != 0040000u && (node.mode & 0170000u) != 0100000u)
			return Result::Unsupported;
		node.directory = (node.mode & 0170000u) == 0040000u;
		inodes[inum]   = node;
		*out           = node;
		return Result::Ok;
	}

	Result ListDirectory(uint32_t inum, std::vector<Entry>* out) {
		if (auto it = directory_cache.find(inum); it != directory_cache.end()) {
			*out = it->second;
			return Result::Ok;
		}
		Dinode       node {};
		const Result load = LoadInode(inum, &node);
		if (load != Result::Ok) return load;
		if (!node.directory) return Result::NotDirectory;
		// mkfs gives the root di_size 0x10000; first direct block only until indirect pointers are
		// RE'd
		if (node.size > BlockBytes) return Result::Unsupported;
		if (node.first_direct_lbn == 0) return Result::Corrupt;
		std::array<uint8_t, BlockBytes> block {};
		const Result                    media = ReadBlock(node.first_direct_lbn, block.data());
		if (media != Result::Ok) return media;
		std::vector<Entry> entries;
		const uint32_t end = node.size == 0
		                         ? BlockBytes
		                         : static_cast<uint32_t>(std::min<uint64_t>(node.size, BlockBytes));
		for (uint32_t offset = 0; offset + DirentHeaderBytes <= end;) {
			const uint8_t* header  = block.data() + offset;
			const uint32_t d_ino   = U32(header + 0);
			const uint32_t reclen  = U32(header + 8);
			const uint8_t  namelen = header[12];
			const uint8_t  type    = header[14];
			if (reclen < DirentHeaderBytes || reclen > end - offset) return Result::Corrupt;
			if (uint32_t(namelen) + DirentHeaderBytes > reclen) return Result::Corrupt;
			const auto* name = reinterpret_cast<const char*>(header + DirentHeaderBytes);
			if (d_ino != 0 && IsPrintableName(name, namelen)) {
				std::string text(name, name + namelen);
				if (text != "." && text != "..") {
					Entry entry {};
					entry.path      = std::move(text);
					entry.inode     = d_ino;
					entry.directory = type == DirentTypeDir;
					if (type != DirentTypeDir && type != DirentTypeReg) {
						// only 0/4/8 seen so far
						return Result::Unsupported;
					}
					Dinode       child {};
					const Result loaded = LoadInode(d_ino, &child);
					if (loaded != Result::Ok) return loaded;
					if (entry.directory != child.directory) return Result::Corrupt;
					entry.mode = child.mode;
					entry.size = child.size;
					entries.push_back(std::move(entry));
				}
			}
			offset += reclen;
		}
		directory_cache[inum] = entries;
		*out                  = std::move(entries);
		return Result::Ok;
	}

	Result Resolve(const std::string& path, Entry* out) {
		if (path.empty() || path.front() != '/') return Result::Invalid;
		Dinode       root {};
		const Result load = LoadInode(RootInode, &root);
		if (load != Result::Ok) return load;
		if (path == "/") {
			out->path      = "/";
			out->inode     = RootInode;
			out->directory = true;
			out->mode      = root.mode;
			out->size      = root.size;
			return Result::Ok;
		}
		uint32_t current        = RootInode;
		bool     current_is_dir = true;
		uint64_t current_size   = root.size;
		uint32_t current_mode   = root.mode;
		size_t   index          = 1;
		while (index < path.size()) {
			const auto slash = path.find('/', index);
			const auto next  = slash == std::string::npos ? path.size() : slash;
			if (next == index) return Result::Invalid;
			const std::string component = path.substr(index, next - index);
			if (!current_is_dir) return Result::NotDirectory;
			std::vector<Entry> entries;
			const Result       listed = ListDirectory(current, &entries);
			if (listed != Result::Ok) return listed;
			const auto hit = std::find_if(entries.begin(), entries.end(),
			                              [&](const Entry& e) { return e.path == component; });
			if (hit == entries.end()) return Result::NotFound;
			current        = hit->inode;
			current_is_dir = hit->directory;
			Dinode       child {};
			const Result loaded = LoadInode(current, &child);
			if (loaded != Result::Ok) return loaded;
			current_size = child.size;
			current_mode = child.mode;
			if (next == path.size()) {
				out->path      = path;
				out->inode     = current;
				out->directory = current_is_dir;
				out->mode      = current_mode;
				out->size      = current_size;
				return Result::Ok;
			}
			if (next + 1 == path.size()) {
				if (!current_is_dir) return Result::NotDirectory;
				out->path      = path.substr(0, path.size() - 1);
				out->inode     = current;
				out->directory = true;
				out->mode      = current_mode;
				out->size      = current_size;
				return Result::Ok;
			}
			index = next + 1;
		}
		return Result::Invalid;
	}
};

std::unique_ptr<BfsVolume> BfsVolume::Open(std::shared_ptr<SectorBacking> backing,
                                           const Options& options, Result* result) {
	const auto fail = [&](Result value) {
		if (result) *result = value;
		return std::unique_ptr<BfsVolume> {};
	};
	if (!backing) return fail(Result::Invalid);
	if (backing->Capacity() < BlockBytes) return fail(Result::Invalid);

	auto state      = std::make_unique<State>();
	state->backing  = backing;
	state->capacity = backing->Capacity();

	std::array<uint8_t, BlockBytes> metadata {};
	const Result                    media = state->ReadBlock(0, metadata.data());
	if (media != Result::Ok) return fail(media);
	if (U64(metadata.data() + 0) != MetadataMagic) return fail(Result::Invalid);

	std::vector<uint32_t> superblock_lbns;
	uint32_t              cursor = 64;
	for (;;) {
		if (cursor + 8 > BlockBytes) return fail(Result::Corrupt);
		const uint16_t tag           = U16(metadata.data() + cursor + 0);
		const uint16_t length        = U16(metadata.data() + cursor + 2);
		const uint32_t payload_start = cursor + 8;
		if (length > BlockBytes - payload_start) return fail(Result::Corrupt);
		if (tag == TagTerminator) break;
		const uint8_t* payload = metadata.data() + payload_start;
		if (tag == TagSuperblockLbnArray) {
			if (length % 4 != 0) return fail(Result::Corrupt);
			for (uint32_t i = 0; i < length; i += 4)
				superblock_lbns.push_back(U32(payload + i));
		} else if (tag == TagDivisionRecords) {
			if (length % 32 != 0) return fail(Result::Corrupt);
			for (uint32_t i = 0; i < length; i += 32) {
				DivisionRecord record {};
				record.start_lbn   = U32(payload + i + 0);
				record.block_count = U32(payload + i + 4);
				state->divisions.push_back(record);
			}
		} else if (tag == TagFreeBitmapLbn) {
			if (length != 4) return fail(Result::Corrupt);
			state->free_bitmap_lbn  = U32(payload);
			state->have_free_bitmap = true;
		}
		cursor = payload_start + length;
	}

	if (superblock_lbns.empty() || state->divisions.empty()) return fail(Result::Invalid);
	const auto&    division     = state->divisions[0];
	const uint64_t division_end = uint64_t(division.start_lbn) + division.block_count;
	if (division.block_count == 0 || division_end > state->capacity / BlockBytes ||
	    division_end > uint64_t(UINT32_MAX) + 1)
		return fail(Result::Corrupt);

	bool found_superblock = false;
	for (uint32_t sb_lbn: superblock_lbns) {
		std::array<uint8_t, BlockBytes> sb {};
		const Result                    media_sb = state->ReadBlock(sb_lbn, sb.data());
		if (media_sb != Result::Ok) return fail(media_sb);
		const uint64_t magic = U64(sb.data() + 0);
		if (magic != SuperblockMagicCurrent && magic != SuperblockMagicLegacy) continue;
		const uint8_t flags       = sb[16];
		const char*   name_start  = reinterpret_cast<const char*>(sb.data() + 32);
		const size_t  name_max    = 256;
		size_t        name_length = 0;
		while (name_length < name_max && name_start[name_length] != 0)
			++name_length;
		std::string name(name_start, name_start + name_length);
		if (!options.partition_name.empty() && name != options.partition_name) continue;
		state->partition_name = std::move(name);
		state->clean          = (flags & 0x40) != 0;
		found_superblock      = true;
		break;
	}
	if (!found_superblock)
		return fail(options.partition_name.empty() ? Result::Invalid : Result::NotFound);

	Dinode       root {};
	const Result loaded_root = state->LoadInode(RootInode, &root);
	if (loaded_root != Result::Ok) return fail(loaded_root);
	if (!root.directory) return fail(Result::Corrupt);

	if (result) *result = Result::Ok;
	return std::unique_ptr<BfsVolume>(new BfsVolume(std::move(state)));
}

BfsVolume::BfsVolume(std::unique_ptr<State> state): m_state(std::move(state)) {}
BfsVolume::~BfsVolume() = default;

BfsVolume::Result BfsVolume::Stat(const std::string& path, Entry* entry) const {
	if (!entry) return Result::Invalid;
	std::lock_guard lock(m_state->mutex);
	return const_cast<State&>(*m_state).Resolve(path, entry);
}

BfsVolume::Result BfsVolume::List(const std::string& path, std::vector<Entry>* entries) const {
	if (!entries) return Result::Invalid;
	std::lock_guard lock(m_state->mutex);
	Entry           resolved {};
	auto&           state = const_cast<State&>(*m_state);
	const Result    found = state.Resolve(path, &resolved);
	if (found != Result::Ok) return found;
	if (!resolved.directory) return Result::NotDirectory;
	return state.ListDirectory(resolved.inode, entries);
}

BfsVolume::Result BfsVolume::Read(const std::string& path, uint64_t offset, void* bytes,
                                  size_t length, size_t* actual) const {
	if (actual) *actual = 0;
	if (!bytes && length) return Result::Invalid;
	std::lock_guard lock(m_state->mutex);
	Entry           resolved {};
	auto&           state = const_cast<State&>(*m_state);
	const Result    found = state.Resolve(path, &resolved);
	if (found != Result::Ok) return found;
	if (resolved.directory) return Result::IsDirectory;
	if (length == 0) return Result::Ok;
	Dinode       node {};
	const Result loaded = state.LoadInode(resolved.inode, &node);
	if (loaded != Result::Ok) return loaded;
	if (offset >= node.size) {
		if (actual) *actual = 0;
		return Result::Ok;
	}
	const uint64_t available = node.size - offset;
	const uint64_t capped    = std::min<uint64_t>(length, available);
	// TODO: first direct block only. Second direct, indirect blocks and inode+128 onward not RE'd.
	if (offset + capped > BlockBytes) return Result::Unsupported;
	if (node.first_direct_lbn == 0) return Result::Corrupt;
	const uint64_t disk_offset = uint64_t(node.first_direct_lbn) * BlockBytes + offset;
	const Result   media       = state.ReadRange(disk_offset, bytes, static_cast<size_t>(capped));
	if (media != Result::Ok) return media;
	if (actual) *actual = static_cast<size_t>(capped);
	return Result::Ok;
}

uint64_t BfsVolume::Capacity() const {
	return m_state ? m_state->capacity : 0;
}
uint64_t BfsVolume::SourceBytes() const {
	return m_state && m_state->backing ? m_state->backing->SourceBytes() : 0;
}
bool BfsVolume::CleanFlagSet() const {
	return m_state && m_state->clean;
}
const std::string& BfsVolume::SelectedPartitionName() const {
	static const std::string empty;
	return m_state ? m_state->partition_name : empty;
}

} // namespace Libs::LibKernel
