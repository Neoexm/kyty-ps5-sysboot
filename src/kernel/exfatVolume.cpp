#include "kernel/exfatVolume.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <map>
#include <new>
#include <set>
#include <utility>

namespace Libs::LibKernel {
namespace {

using Result                  = ExfatVolume::Result;
constexpr size_t MaxTransfer  = 16 * 1024 * 1024;
constexpr size_t MaxDirectory = 256 * 1024 * 1024;

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

bool ValidName(const std::u16string& name) {
	if (name.empty() || name == u"." || name == u"..") return false;
	for (size_t i = 0; i < name.size(); ++i) {
		const auto c = name[i];
		if (c < 0x20 || c == u'"' || c == u'*' || c == u'/' || c == u':' || c == u'<' ||
		    c == u'>' || c == u'?' || c == u'\\' || c == u'|')
			return false;
		if (c >= 0xd800 && c <= 0xdbff) {
			if (++i == name.size() || name[i] < 0xdc00 || name[i] > 0xdfff) return false;
		} else if (c >= 0xdc00 && c <= 0xdfff)
			return false;
	}
	return true;
}

bool SetValid(const uint8_t* entry, size_t count) {
	uint16_t checksum = 0;
	for (size_t i = 0; i < count * 32; ++i) {
		if (i != 2 && i != 3)
			checksum = static_cast<uint16_t>((checksum >> 1) | (checksum << 15)) + entry[i];
	}
	return checksum == U16(entry + 2);
}

bool GuidValid(const uint8_t* bytes) {
	return std::any_of(bytes, bytes + 16, [](auto c) { return c != 0; });
}

} // namespace

struct ExfatVolume::State {
	struct Node {
		Entry                 entry;
		std::vector<uint32_t> clusters;
	};
	std::shared_ptr<SectorBacking> backing;
	uint64_t                       capacity      = 0;
	uint64_t                       heap          = 0;
	uint32_t                       cluster_bytes = 0;
	uint32_t                       cluster_count = 0;
	std::vector<uint8_t>           fat;
	std::vector<uint8_t>           bitmap;
	std::array<uint16_t, 65536>    upcase {};
	std::map<std::u16string, Node> nodes;
	std::set<uint32_t>             owned;

	Result ReadMedia(uint64_t offset, void* bytes, size_t length) const {
		if (offset > capacity || length > capacity - offset) return Result::Corrupt;
		return MediaResult(backing->Read(offset, bytes, length));
	}

	bool ClusterValid(uint32_t cluster) const {
		return cluster >= 2 && cluster - 2 < cluster_count;
	}

	Result Chain(uint32_t first, uint64_t length, bool contiguous, bool root,
	             std::vector<uint32_t>* clusters) const {
		clusters->clear();
		if (!root && length == 0) return first == 0 && !contiguous ? Result::Ok : Result::Corrupt;
		if (!ClusterValid(first) || length > capacity) return Result::Corrupt;
		const uint64_t count = root ? cluster_count : (length + cluster_bytes - 1) / cluster_bytes;
		if (count > cluster_count || (root && contiguous)) return Result::Corrupt;
		std::set<uint32_t> seen;
		uint32_t           cluster = first;
		for (uint64_t i = 0; i < count; ++i) {
			if (!ClusterValid(cluster) || !seen.insert(cluster).second) return Result::Corrupt;
			clusters->push_back(cluster);
			if (root && clusters->size() > MaxDirectory / cluster_bytes) return Result::Unsupported;
			const uint32_t next =
			    contiguous ? cluster + 1 : U32(fat.data() + uint64_t(cluster) * 4);
			if (root && next == 0xffffffff) return Result::Ok;
			if (!root && i + 1 == count)
				return contiguous || next == 0xffffffff ? Result::Ok : Result::Corrupt;
			cluster = next;
		}
		return Result::Corrupt;
	}

	Result ReadChain(const std::vector<uint32_t>& clusters, uint64_t offset, void* bytes,
	                 size_t length) const {
		auto* out = static_cast<uint8_t*>(bytes);
		while (length) {
			const uint64_t index  = offset / cluster_bytes;
			const size_t   inside = offset % cluster_bytes;
			if (index >= clusters.size()) return Result::Corrupt;
			const size_t count  = std::min<size_t>({length, cluster_bytes - inside, MaxTransfer});
			const auto   result = ReadMedia(
			    heap + uint64_t(clusters[index] - 2) * cluster_bytes + inside, out, count);
			if (result != Result::Ok) return result;
			offset += count;
			out += count;
			length -= count;
		}
		return Result::Ok;
	}

	Result Claim(const std::vector<uint32_t>& clusters) {
		for (const auto cluster: clusters) {
			const auto bit = cluster - 2;
			if (!(bitmap[bit / 8] & (1u << (bit % 8))) || !owned.insert(cluster).second)
				return Result::Corrupt;
		}
		return Result::Ok;
	}

	Result BenignAllocation(const uint8_t* entry, uint16_t flags) {
		if (!(flags & 1u)) return flags & 2u ? Result::Corrupt : Result::Ok;
		std::vector<uint32_t> clusters;
		auto result = Chain(U32(entry + 20), U64(entry + 24), (flags & 2u) != 0, false, &clusters);
		return result == Result::Ok ? Claim(clusters) : result;
	}

	Result BenignSecondary(const uint8_t* entry) {
		if ((entry[0] & 0xe0u) != 0xe0u) return Result::Unsupported;
		if (entry[0] == 0xe0 && (entry[1] != 0 || !GuidValid(entry + 2))) return Result::Corrupt;
		if (entry[0] == 0xe1 && ((entry[1] & ~3u) || !(entry[1] & 1u) || !GuidValid(entry + 2)))
			return Result::Corrupt;
		return BenignAllocation(entry, entry[1]);
	}

	std::u16string Fold(const std::u16string& path) const {
		std::u16string key = path;
		for (auto& c: key)
			c = static_cast<char16_t>(upcase[c]);
		return key;
	}

	Result Key(const std::u16string& path, std::u16string* key) const {
		if (path.empty() || path.front() != u'/' || path.size() > 32767) return Result::Invalid;
		if (path == u"/") {
			*key = path;
			return Result::Ok;
		}
		size_t begin = 1;
		while (begin < path.size()) {
			const auto end  = path.find(u'/', begin);
			const auto name = path.substr(begin, end == path.npos ? path.npos : end - begin);
			if (!ValidName(name) || name.size() > 255) return Result::Invalid;
			if (end == path.npos) break;
			begin = end + 1;
			if (begin == path.size()) return Result::Invalid;
		}
		*key = Fold(path);
		return Result::Ok;
	}

	Result Lookup(const std::u16string& path, const Node** node) const {
		std::u16string key;
		const auto     result = Key(path, &key);
		if (result != Result::Ok) return result;
		const auto found = nodes.find(key);
		if (found != nodes.end()) {
			*node = &found->second;
			return Result::Ok;
		}
		for (size_t end = key.find(u'/', 1); end != key.npos; end = key.find(u'/', end + 1)) {
			const auto parent = nodes.find(key.substr(0, end));
			if (parent == nodes.end()) return Result::NotFound;
			if (!parent->second.entry.Directory()) return Result::NotDirectory;
		}
		return Result::NotFound;
	}

	Result IndexDirectory(const std::u16string& path, const std::vector<uint32_t>& clusters,
	                      uint64_t length, unsigned depth) {
		if (depth > 64 || length > MaxDirectory || nodes.size() > 100000)
			return Result::Unsupported;
		std::vector<uint8_t> bytes(static_cast<size_t>(length));
		auto                 result = ReadChain(clusters, 0, bytes.data(), bytes.size());
		if (result != Result::Ok) return result;
		std::vector<std::u16string> children;
		bool                        have_guid = false;
		for (size_t offset = 0; offset + 32 <= bytes.size();) {
			const auto* entry = bytes.data() + offset;
			if (entry[0] == 0) break;
			if (!(entry[0] & 0x80)) {
				offset += 32;
				continue;
			}
			if (path == u"/" && (entry[0] == 0x81 || entry[0] == 0x82 || entry[0] == 0x83)) {
				offset += 32;
				continue;
			}
			if (entry[0] != 0x85 && (entry[0] & 0xe0u) != 0xa0u) return Result::Unsupported;
			const size_t count = size_t(entry[1]) + 1;
			if (count > (bytes.size() - offset) / 32 || !SetValid(entry, count))
				return Result::Corrupt;
			if (entry[0] != 0x85) {
				if (entry[0] == 0xa0) {
					if (path != u"/" || count != 1 || U16(entry + 4) != 0 ||
					    !GuidValid(entry + 6) || have_guid)
						return Result::Corrupt;
					have_guid = true;
				}
				result = BenignAllocation(entry, U16(entry + 4));
				if (result != Result::Ok) return result;
				for (size_t i = 1; i < count; ++i) {
					result = BenignSecondary(entry + i * 32);
					if (result != Result::Ok) return result;
				}
				offset += count * 32;
				continue;
			}
			if (count < 3) return Result::Corrupt;
			const auto*  stream      = entry + 32;
			const size_t name_length = stream[3];
			if (stream[0] != 0xc0 || !name_length || count < 2 + (name_length + 14) / 15)
				return Result::Corrupt;
			if ((stream[1] & ~3u) || !(stream[1] & 1u)) return Result::Unsupported;
			std::u16string name;
			for (size_t i = 0; i < (name_length + 14) / 15; ++i) {
				const auto* part = entry + 64 + i * 32;
				if (part[0] != 0xc1) return Result::Corrupt;
				if (part[1] != 0) return Result::Unsupported;
				for (size_t j = 0; j < 15 && name.size() < name_length; ++j)
					name += static_cast<char16_t>(U16(part + 2 + j * 2));
			}
			if (!ValidName(name)) return Result::Corrupt;
			for (size_t i = 2 + (name_length + 14) / 15; i < count; ++i) {
				result = BenignSecondary(entry + i * 32);
				if (result != Result::Ok) return result;
			}
			uint16_t hash = 0;
			for (const auto c: name) {
				const auto upper = upcase[c];
				hash = static_cast<uint16_t>((hash >> 1) | (hash << 15)) + (upper & 0xff);
				hash = static_cast<uint16_t>((hash >> 1) | (hash << 15)) + (upper >> 8);
			}
			if (hash != U16(stream + 4)) return Result::Corrupt;
			Node node;
			node.entry = {path == u"/" ? path + name : path + u"/" + name, U64(stream + 24),
			              U64(stream + 8), U16(entry + 4)};
			if (node.entry.valid_size > node.entry.size || node.entry.size > capacity ||
			    (node.entry.Directory() &&
			     (node.entry.valid_size != node.entry.size || node.entry.size % cluster_bytes)))
				return Result::Corrupt;
			result = Chain(U32(stream + 20), node.entry.size, (stream[1] & 2u) != 0, false,
			               &node.clusters);
			if (result != Result::Ok) return result;
			node.entry.allocated_size = uint64_t(node.clusters.size()) * cluster_bytes;
			result                    = Claim(node.clusters);
			if (result != Result::Ok) return result;
			const auto key = Fold(node.entry.path);
			if (node.entry.Directory()) children.push_back(key);
			if (nodes.size() >= 100000) return Result::Unsupported;
			if (!nodes.emplace(key, std::move(node)).second) return Result::Corrupt;
			offset += count * 32;
		}
		std::vector<uint8_t>().swap(bytes);
		for (const auto& key: children) {
			const auto& child = nodes.at(key);
			result = IndexDirectory(child.entry.path, child.clusters, child.entry.size, depth + 1);
			if (result != Result::Ok) return result;
		}
		return Result::Ok;
	}

	Result Initialize() {
		std::array<uint8_t, 512> sector {};
		auto result = MediaResult(backing->Read(0, sector.data(), sector.size()));
		if (result != Result::Ok) return result;
		if (std::memcmp(sector.data() + 3, "EXFAT   ", 8) || sector[510] != 0x55 ||
		    sector[511] != 0xaa ||
		    !std::all_of(sector.begin() + 11, sector.begin() + 64, [](auto c) { return c == 0; }))
			return Result::Corrupt;
		if (sector[105] != 1 || sector[104] > 99 || sector[108] < 9 || sector[108] > 12 ||
		    sector[109] > 25 - sector[108] || (sector[110] != 1 && sector[110] != 2))
			return Result::Unsupported;
		const uint64_t bps     = uint64_t {1} << sector[108];
		const uint64_t sectors = U64(sector.data() + 72);
		if (sectors < 24 || sectors > UINT64_MAX / bps) return Result::Corrupt;
		capacity = sectors * bps;
		if (capacity < 1024 * 1024) return Result::Corrupt;
		if (capacity != backing->Capacity() || bps != backing->SectorSize()) return Result::Invalid;
		std::vector<uint8_t> boot(static_cast<size_t>(24 * bps));
		result = ReadMedia(0, boot.data(), boot.size());
		if (result != Result::Ok) return result;
		for (size_t block: {size_t {0}, size_t {12}}) {
			const auto* bytes = boot.data() + block * bps;
			if (bytes[0] != 0xeb || bytes[1] != 0x76 || bytes[2] != 0x90 || bytes[510] != 0x55 ||
			    bytes[511] != 0xaa || (bytes[112] > 100 && bytes[112] != 0xff))
				return Result::Corrupt;
			uint32_t sum = 0;
			for (size_t i = 0; i < 11 * bps; ++i) {
				if (i != 106 && i != 107 && i != 112) sum = ((sum >> 1) | (sum << 31)) + bytes[i];
			}
			for (size_t i = 11 * bps; i < 12 * bps; i += 4)
				if (U32(bytes + i) != sum) return Result::Corrupt;
			for (size_t i = 1; i <= 8; ++i)
				if (U32(bytes + (i + 1) * bps - 4) != 0xaa550000) return Result::Corrupt;
		}
		for (size_t i = 0; i < 113; ++i) {
			if (i != 106 && i != 107 && i != 112 && boot[i] != boot[12 * bps + i])
				return Result::Corrupt;
		}
		const auto flags = U16(sector.data() + 106);
		if ((flags & 0xfff0) || (flags & 1u) >= sector[110]) return Result::Corrupt;
		if (flags & 6u) return Result::Unsupported;
		const uint32_t fat_offset = U32(sector.data() + 80), fat_sectors = U32(sector.data() + 84);
		const uint32_t heap_sector = U32(sector.data() + 88);
		cluster_count              = U32(sector.data() + 92);
		cluster_bytes              = static_cast<uint32_t>(bps << sector[109]);
		heap                       = uint64_t(heap_sector) * bps;
		if (!cluster_count || cluster_count > 0xfffffff5u || fat_offset < 24 ||
		    uint64_t(fat_offset) + uint64_t(fat_sectors) * sector[110] > heap_sector ||
		    uint64_t(cluster_count + 2) * 4 > uint64_t(fat_sectors) * bps || heap > capacity ||
		    cluster_count != (capacity - heap) / cluster_bytes)
			return Result::Corrupt;
		if (uint64_t(cluster_count + 2) * 4 > MaxTransfer) return Result::Unsupported;
		fat.resize(size_t(cluster_count + 2) * 4);
		result = ReadMedia((uint64_t(fat_offset) + (flags & 1u) * uint64_t(fat_sectors)) * bps,
		                   fat.data(), fat.size());
		if (result != Result::Ok) return result;
		Node root;
		result = Chain(U32(sector.data() + 96), 0, false, true, &root.clusters);
		if (result != Result::Ok) return result;
		root.entry                = {u"/", uint64_t(root.clusters.size()) * cluster_bytes,
		                             uint64_t(root.clusters.size()) * cluster_bytes, 0x10};
		root.entry.allocated_size = root.entry.size;
		std::vector<uint8_t> directory(static_cast<size_t>(root.entry.size));
		result = ReadChain(root.clusters, 0, directory.data(), directory.size());
		if (result != Result::Ok) return result;
		struct Metadata {
			uint32_t first;
			uint64_t size;
			uint32_t checksum;
		};
		std::array<Metadata, 2> maps {};
		Metadata                table {};
		bool                    have_table = false;
		std::array<bool, 2>     have_map {};
		for (size_t i = 0; i + 32 <= directory.size();) {
			const auto* e = directory.data() + i;
			if (!e[0]) break;
			if (e[0] == 0x81) {
				const unsigned index = e[1] & 1u;
				if ((e[1] & ~1u) || index >= sector[110] || have_map[index]) return Result::Corrupt;
				have_map[index] = true;
				maps[index]     = {U32(e + 20), U64(e + 24), 0};
			} else if (e[0] == 0x82) {
				if (have_table) return Result::Corrupt;
				have_table = true;
				table      = {U32(e + 20), U64(e + 24), U32(e + 4)};
			}
			if (e[0] == 0x85 || (e[0] & 0xe0u) == 0xa0u) {
				const size_t count = size_t(e[1]) + 1;
				if (count > (directory.size() - i) / 32) return Result::Corrupt;
				i += count * 32;
			} else
				i += 32;
		}
		if (!have_table || !have_map[0] || (sector[110] == 2 && !have_map[1]) || table.size < 2 ||
		    table.size > 131072 || (table.size & 1u))
			return Result::Corrupt;
		const auto& active_map = maps[flags & 1u];
		if (active_map.size != (uint64_t(cluster_count) + 7) / 8) return Result::Corrupt;
		std::vector<uint32_t> map_chain, table_chain;
		result = Chain(active_map.first, active_map.size, false, false, &map_chain);
		if (result != Result::Ok) return result;
		bitmap.resize(static_cast<size_t>(active_map.size));
		result = ReadChain(map_chain, 0, bitmap.data(), bitmap.size());
		if (result != Result::Ok) return result;
		result = Chain(table.first, table.size, false, false, &table_chain);
		if (result != Result::Ok) return result;
		std::vector<uint8_t> upper(static_cast<size_t>(table.size));
		result = ReadChain(table_chain, 0, upper.data(), upper.size());
		if (result != Result::Ok) return result;
		uint32_t checksum = 0;
		for (const auto c: upper)
			checksum = ((checksum >> 1) | (checksum << 31)) + c;
		if (checksum != table.checksum) return Result::Corrupt;
		size_t character = 0;
		for (size_t i = 0; i < upper.size();) {
			if (character >= upcase.size()) return Result::Corrupt;
			const auto value = U16(upper.data() + i);
			i += 2;
			if (value == 0xffff && character != 0xffff) {
				if (i == upper.size()) return Result::Corrupt;
				const auto count = U16(upper.data() + i);
				i += 2;
				if (!count || count > upcase.size() - character) return Result::Corrupt;
				for (size_t j = 0; j < count; ++j) {
					upcase[character] = static_cast<uint16_t>(character);
					++character;
				}
			} else
				upcase[character++] = value;
		}
		if (character != upcase.size()) return Result::Corrupt;
		for (size_t i = 0; i < 128; ++i) {
			if (upcase[i] != (i >= 'a' && i <= 'z' ? i - 32 : i)) return Result::Corrupt;
		}
		for (const auto* chain: {&root.clusters, &map_chain, &table_chain}) {
			result = Claim(*chain);
			if (result != Result::Ok) return result;
		}
		if (sector[110] == 2) {
			const auto& inactive = maps[1 - (flags & 1u)];
			if (inactive.size != active_map.size) return Result::Corrupt;
			std::vector<uint32_t> inactive_chain;
			result = Chain(inactive.first, inactive.size, false, false, &inactive_chain);
			if (result != Result::Ok) return result;
			result = Claim(inactive_chain);
			if (result != Result::Ok) return result;
		}
		nodes.emplace(u"/", root);
		std::vector<uint8_t>().swap(directory);
		return IndexDirectory(u"/", root.clusters, root.entry.size, 0);
	}
};

ExfatVolume::ExfatVolume(std::unique_ptr<State> state): m_state(std::move(state)) {}
ExfatVolume::~ExfatVolume() = default;

std::unique_ptr<ExfatVolume> ExfatVolume::Open(std::shared_ptr<SectorBacking> backing,
                                               Result*                        result) try {
	if (!result) return {};
	*result = Result::Invalid;
	if (!backing) return {};
	if (!backing->ReadOnly()) {
		*result = Result::Unsupported;
		return {};
	}
	auto state     = std::make_unique<State>();
	state->backing = std::move(backing);
	*result        = state->Initialize();
	if (*result != Result::Ok) return {};
	return std::unique_ptr<ExfatVolume>(new ExfatVolume(std::move(state)));
} catch (const std::bad_alloc&) {
	if (result) *result = Result::Io;
	return {};
}

ExfatVolume::Result ExfatVolume::Stat(const std::u16string& path, Entry* entry) const {
	if (!entry) return Result::Invalid;
	const State::Node* node   = nullptr;
	const auto         result = m_state->Lookup(path, &node);
	if (result != Result::Ok) return result;
	*entry = node->entry;
	return Result::Ok;
}

ExfatVolume::Result ExfatVolume::List(const std::u16string& path,
                                      std::vector<Entry>*   entries) const {
	if (!entries) return Result::Invalid;
	Entry      directory;
	const auto result = Stat(path, &directory);
	if (result != Result::Ok) return result;
	if (!directory.Directory()) return Result::NotDirectory;
	const auto prefix = m_state->Fold(directory.path == u"/" ? u"/" : directory.path + u"/");
	std::vector<Entry> output;
	for (auto i = m_state->nodes.lower_bound(prefix);
	     i != m_state->nodes.end() && i->first.starts_with(prefix); ++i) {
		if (i->first.size() > prefix.size() && i->first.find(u'/', prefix.size()) == i->first.npos)
			output.push_back(i->second.entry);
	}
	*entries = std::move(output);
	return Result::Ok;
}

ExfatVolume::Result ExfatVolume::Read(const std::u16string& path, uint64_t offset, void* bytes,
                                      size_t length, size_t* actual) const try {
	if (!actual || (length && !bytes) || length > MaxTransfer) return Result::Invalid;
	const State::Node* found = nullptr;
	const auto         keyed = m_state->Lookup(path, &found);
	if (keyed != Result::Ok) return keyed;
	const auto& node = *found;
	if (node.entry.Directory()) return Result::IsDirectory;
	const size_t size = static_cast<size_t>(
	    offset >= node.entry.size ? 0 : std::min<uint64_t>(length, node.entry.size - offset));
	std::vector<uint8_t> output(size, 0);
	if (size && offset < node.entry.valid_size) {
		const auto valid =
		    static_cast<size_t>(std::min<uint64_t>(size, node.entry.valid_size - offset));
		const auto result = m_state->ReadChain(node.clusters, offset, output.data(), valid);
		if (result != Result::Ok) return result;
	}
	if (size) std::memcpy(bytes, output.data(), size);
	*actual = size;
	return Result::Ok;
} catch (const std::bad_alloc&) {
	return Result::Io;
}

uint64_t ExfatVolume::Capacity() const {
	return m_state->capacity;
}
uint64_t ExfatVolume::SourceBytes() const {
	return m_state->backing->SourceBytes();
}

} // namespace Libs::LibKernel
