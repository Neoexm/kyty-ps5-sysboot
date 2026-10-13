#include "kernel/capturedDirectory.h"
#include "kernel/authInfo.h"
#include "kernel/capturedMetadataCache.h"
#include "libs/errno.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>

namespace Libs::LibKernel::CapturedDirectory {
namespace {
std::mutex                                   mutex;
std::vector<std::shared_ptr<const Snapshot>> snapshots;
bool                                         last_load_cache_hit = false;

constexpr uint64_t DirectoryCachePayloadLimit = 64 * 1024 * 1024;

std::string Key(std::string_view path, bool sensitive) {
	std::string key(path);
	if (!sensitive)
		for (auto& ch: key)
			if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
	return key;
}

bool ValidPath(const std::string& path) {
	if (path.empty() || path[0] != '/' || path.size() >= 1024 || path.find('\0') != path.npos ||
	    path.find('\\') != path.npos || path.find("//") != path.npos ||
	    (path.size() > 1 && path.back() == '/'))
		return false;
	for (size_t start = 1; start < path.size();) {
		const auto end  = path.find('/', start);
		const auto part = path.substr(start, end == path.npos ? path.npos : end - start);
		if (part == "." || part == ".." || part.size() > 255) return false;
		start = end == path.npos ? path.size() : end + 1;
	}
	return true;
}

bool Within(const std::filesystem::path& root, const std::filesystem::path& path) {
	const auto relative = path.lexically_relative(root);
	return !relative.empty() && !relative.is_absolute() &&
	       std::none_of(relative.begin(), relative.end(),
	                    [](const auto& part) { return part == ".."; });
}

int ReadPinned(const std::filesystem::path& file, const std::string& sha256,
               AuthInfo::Digest* expected, std::string* bytes) {
	if (!AuthInfo::ParseDigestHex(sha256, expected)) return KERNEL_ERROR_EINVAL;
	std::error_code error;
	const auto      size = std::filesystem::file_size(file, error);
	if (error) return KERNEL_ERROR_ENOENT;
	if (size == 0 || size > 16 * 1024 * 1024) return KERNEL_ERROR_EINVAL;
	std::ifstream input(file, std::ios::binary);
	bytes->assign(static_cast<size_t>(size), '\0');
	if (!input.read(bytes->data(), bytes->size()) || input.peek() != EOF) return KERNEL_ERROR_EIO;
	if (AuthInfo::Sha256(bytes->data(), bytes->size()) != *expected) return KERNEL_ERROR_EINVAL;
	return OK;
}

bool ReadMetadata(const nlohmann::json& row, Entry* entry) {
	for (const char* key: {"inode", "mode", "uid", "gid"})
		if (!row.at(key).is_number_unsigned() || row.at(key).get<uint64_t>() > UINT32_MAX)
			return false;
	if (!row.at("size").is_number_unsigned() || row.at("size").get<uint64_t>() > INT64_MAX ||
	    !row.at("mtime").is_number_integer() ||
	    (row.at("mtime").is_number_unsigned() && row.at("mtime").get<uint64_t>() > INT64_MAX))
		return false;
	entry->stat.inode = row.at("inode").get<uint32_t>();
	entry->stat.mode  = row.at("mode").get<uint32_t>();
	entry->stat.size  = row.at("size").get<uint64_t>();
	entry->stat.uid   = row.at("uid").get<uint32_t>();
	entry->stat.gid   = row.at("gid").get<uint32_t>();
	entry->stat.mtime = row.at("mtime").get<int64_t>();
	if ((entry->stat.mode & 0170000u) >> 12 != entry->type || entry->stat.size > INT64_MAX)
		return false;
	entry->stat.allocated_size = 0;
	entry->stat.captured       = true;
	return true;
}

CapturedMetadataCache::Key DirectoryCacheKey(const std::filesystem::path& manifest,
                                             const AuthInfo::Digest& expected, bool lazy_files,
                                             const std::filesystem::path& relocated) {
	const auto root = relocated.u8string();
	const auto discriminator =
	    std::string("directory_snapshot_v1:") + AuthInfo::DigestHex(expected) +
	    ":lazy=" + (lazy_files ? "1" : "0") +
	    ":root=" + std::string(reinterpret_cast<const char*>(root.c_str()), root.size());
	const std::array<std::filesystem::path, 1> sources {manifest};
	return CapturedMetadataCache::Prepare("captured_directory", discriminator, sources,
	                                      DirectoryCachePayloadLimit);
}

std::vector<uint8_t> EncodeSnapshots(const std::vector<std::shared_ptr<const Snapshot>>& source) {
	CapturedMetadataCache::Writer writer;
	writer.U32(static_cast<uint32_t>(source.size()));
	for (const auto& snapshot: source) {
		writer.String(snapshot->point);
		writer.String(snapshot->manifest_sha256);
		writer.String(snapshot->supplement_sha256);
		writer.Path(snapshot->root);
		writer.Path(snapshot->storage);
		writer.U8(snapshot->case_sensitive ? 1 : 0);
		writer.U32(static_cast<uint32_t>(snapshot->entries.size()));
		for (const auto& [path, entry]: snapshot->entries) {
			writer.String(path);
			writer.U32(entry.stat.device);
			writer.U32(entry.stat.inode);
			writer.U32(entry.stat.mode);
			writer.U64(entry.stat.size);
			writer.U64(entry.stat.allocated_size);
			writer.U32(entry.stat.uid);
			writer.U32(entry.stat.gid);
			writer.I64(entry.stat.mtime);
			writer.U8(entry.stat.captured ? 1 : 0);
			writer.Path(entry.file);
			writer.String(entry.sha256);
			writer.String(entry.name);
			writer.U8(entry.metadata ? 1 : 0);
			writer.U8(entry.complete ? 1 : 0);
			writer.U8(entry.type);
		}
	}
	return writer.Bytes();
}

bool DecodeSnapshots(std::span<const uint8_t> payload, const AuthInfo::Digest& expected,
                     bool lazy_files, std::vector<std::shared_ptr<const Snapshot>>* output) try {
	if (output == nullptr) return false;
	CapturedMetadataCache::Reader reader(payload);
	uint32_t                      snapshot_count = 0;
	if (!reader.U32(&snapshot_count) || snapshot_count > 8) return false;
	const auto                                   expected_hex = AuthInfo::DigestHex(expected);
	std::vector<std::shared_ptr<const Snapshot>> decoded;
	for (uint32_t volume = 0; volume < snapshot_count; ++volume) {
		auto     snapshot       = std::make_shared<Snapshot>();
		uint8_t  case_sensitive = 0;
		uint32_t entry_count    = 0;
		if (!reader.String(&snapshot->point, 1023) ||
		    !reader.String(&snapshot->manifest_sha256, 64) ||
		    !reader.String(&snapshot->supplement_sha256, 64) ||
		    !reader.Path(&snapshot->root, 32767) || !reader.Path(&snapshot->storage, 32767) ||
		    !reader.U8(&case_sensitive) || case_sensitive > 1 || !reader.U32(&entry_count) ||
		    entry_count > 100000 || snapshot->manifest_sha256 != expected_hex ||
		    !snapshot->supplement_sha256.empty() || !ValidPath(snapshot->point) ||
		    snapshot->point == "/")
			return false;
		snapshot->case_sensitive = case_sensitive != 0;
		std::error_code error;
		const auto      storage = std::filesystem::canonical(snapshot->storage, error);
		if (error || storage != snapshot->storage || !std::filesystem::is_directory(storage))
			return false;
		const auto root = std::filesystem::canonical(snapshot->root, error);
		if (error || root != snapshot->root || !std::filesystem::is_directory(root) ||
		    !Within(storage, root))
			return false;
		for (const auto& prior: decoded)
			if (prior->root == root || prior->point == snapshot->point) return false;
		for (uint32_t n = 0; n < entry_count; ++n) {
			std::string path;
			Entry       entry;
			uint8_t     captured = 0;
			uint8_t     metadata = 0;
			uint8_t     complete = 0;
			if (!reader.String(&path, 1023) || !reader.U32(&entry.stat.device) ||
			    !reader.U32(&entry.stat.inode) || !reader.U32(&entry.stat.mode) ||
			    !reader.U64(&entry.stat.size) || !reader.U64(&entry.stat.allocated_size) ||
			    !reader.U32(&entry.stat.uid) || !reader.U32(&entry.stat.gid) ||
			    !reader.I64(&entry.stat.mtime) || !reader.U8(&captured) || captured > 1 ||
			    !reader.Path(&entry.file, 32767) || !reader.String(&entry.sha256, 64) ||
			    !reader.String(&entry.name, 255) || !reader.U8(&metadata) || metadata > 1 ||
			    !reader.U8(&complete) || complete > 1 || !reader.U8(&entry.type) ||
			    entry.type > 15 || !ValidPath(path) ||
			    (!snapshot->case_sensitive && Key(path, false) != path))
				return false;
			entry.stat.captured  = captured != 0;
			entry.metadata       = metadata != 0;
			entry.complete       = complete != 0;
			const auto slash     = path.rfind('/');
			const auto path_name = path.substr(slash + 1);
			if (entry.name.empty() != (path == "/") ||
			    entry.name.find_first_of("/\\") != entry.name.npos ||
			    (snapshot->case_sensitive ? entry.name != path_name
			                              : Key(entry.name, false) != path_name) ||
			    entry.stat.allocated_size != 0 || entry.stat.captured != entry.metadata ||
			    (entry.complete && entry.type != 4) ||
			    (entry.metadata && (((entry.stat.mode & 0170000u) >> 12) != entry.type ||
			                        entry.stat.size > INT64_MAX)))
				return false;
			if (!entry.file.empty()) {
				AuthInfo::Digest digest;
				if (!entry.metadata || entry.type != 8 ||
				    !AuthInfo::ParseDigestHex(entry.sha256, &digest) ||
				    AuthInfo::DigestHex(digest) != entry.sha256 || !Within(storage, entry.file))
					return false;
				if (!lazy_files) {
					const auto file = std::filesystem::canonical(entry.file, error);
					if (error || file != entry.file || !std::filesystem::is_regular_file(file) ||
					    std::filesystem::file_size(file, error) != entry.stat.size || error)
						return false;
				}
			} else if (!entry.sha256.empty()) {
				return false;
			}
			if (!snapshot->entries.emplace(path, std::move(entry)).second) return false;
		}
		const auto root_entry = snapshot->entries.find("/");
		if (root_entry == snapshot->entries.end() || !root_entry->second.metadata ||
		    root_entry->second.type != 4)
			return false;
		for (const auto& [path, entry]: snapshot->entries) {
			if (path == "/") continue;
			const auto slash  = path.rfind('/');
			const auto parent = snapshot->entries.find(slash == 0 ? "/" : path.substr(0, slash));
			if (parent == snapshot->entries.end() || parent->second.type != 4) return false;
		}
		decoded.push_back(std::move(snapshot));
	}
	if (!reader.Done()) return false;
	*output = std::move(decoded);
	return true;
} catch (const std::filesystem::filesystem_error&) {
	return false;
} catch (const std::bad_alloc&) {
	return false;
}
} // namespace

int Load(const std::filesystem::path& manifest, const std::string& sha256) try {
	AuthInfo::Digest expected;
	if (!AuthInfo::ParseDigestHex(sha256, &expected)) return KERNEL_ERROR_EINVAL;
	std::error_code error;
	const char*     lazy_value = std::getenv("KYTY_PS5_CAPTURED_STORAGE_LAZY_FILES");
	const bool      lazy_files = lazy_value != nullptr && std::string_view(lazy_value) == "1";
	// manifest holds its absolute host dir; a moved copy is named here and host_roots are rebased
	const char*          relocated_value = std::getenv("KYTY_PS5_CAPTURED_STORAGE_ROOT");
	const auto           relocated       = relocated_value != nullptr && relocated_value[0] != '\0'
	                                           ? std::filesystem::u8path(relocated_value)
	                                           : std::filesystem::path();
	const auto           cache_key = DirectoryCacheKey(manifest, expected, lazy_files, relocated);
	std::vector<uint8_t> cached;
	std::vector<std::shared_ptr<const Snapshot>> cached_snapshots;
	if (CapturedMetadataCache::Read(cache_key, &cached) == CapturedMetadataCache::ReadResult::Hit &&
	    DecodeSnapshots(cached, expected, lazy_files, &cached_snapshots)) {
		std::lock_guard lock(mutex);
		if (!snapshots.empty()) return KERNEL_ERROR_EBUSY;
		snapshots.swap(cached_snapshots);
		last_load_cache_hit = true;
		return OK;
	}
	std::string bytes;
	if (const int read = ReadPinned(manifest, sha256, &expected, &bytes); read != OK) return read;
	const auto json = nlohmann::json::parse(bytes);
	if (json.at("version") != 1 || !json.at("volumes").is_array() || json.at("volumes").size() > 8)
		return KERNEL_ERROR_EINVAL;
	const auto recorded =
	    std::filesystem::u8path(json.at("storage").get<std::string>()).lexically_normal();
	const auto storage =
	    std::filesystem::canonical(relocated.empty() ? recorded : relocated, error);
	if (error || !std::filesystem::is_directory(storage)) return KERNEL_ERROR_ENOENT;
	std::vector<std::shared_ptr<const Snapshot>> staged;
	for (const auto& volume: json.at("volumes")) {
		auto snapshot             = std::make_shared<Snapshot>();
		snapshot->manifest_sha256 = AuthInfo::DigestHex(expected);
		snapshot->point           = volume.at("point").get<std::string>();
		if (!ValidPath(snapshot->point) || snapshot->point == "/") return KERNEL_ERROR_EINVAL;
		snapshot->storage = storage;
		auto host_root =
		    std::filesystem::u8path(volume.at("host_root").get<std::string>()).lexically_normal();
		if (!relocated.empty()) {
			if (!Within(recorded, host_root)) return KERNEL_ERROR_EINVAL;
			host_root = storage / host_root.lexically_relative(recorded);
		}
		snapshot->root = std::filesystem::canonical(host_root, error);
		if (error || !std::filesystem::is_directory(snapshot->root) ||
		    !Within(storage, snapshot->root))
			return KERNEL_ERROR_EINVAL;
		for (const auto& prior: staged)
			if (prior->root == snapshot->root || prior->point == snapshot->point)
				return KERNEL_ERROR_EINVAL;
		snapshot->case_sensitive = volume.at("case_sensitive").get<bool>();
		if (!volume.at("entries").is_array() || volume.at("entries").size() > 100000)
			return KERNEL_ERROR_EINVAL;
		for (const auto& row: volume.at("entries")) {
			const auto path = row.at("path").get<std::string>();
			if (!ValidPath(path)) return KERNEL_ERROR_EINVAL;
			Entry entry;
			entry.name     = path.substr(path.rfind('/') + 1);
			entry.metadata = row.at("metadata").get<bool>();
			entry.complete = row.at("complete").get<bool>();
			if (!row.at("type").is_number_unsigned() || row.at("type").get<uint64_t>() > 15)
				return KERNEL_ERROR_EINVAL;
			entry.type = row.at("type").get<uint8_t>();
			if (entry.metadata && !ReadMetadata(row, &entry)) return KERNEL_ERROR_EINVAL;
			if (row.contains("file")) {
				if (!entry.metadata || entry.type != 8) return KERNEL_ERROR_EINVAL;
				const auto relative = std::filesystem::u8path(row.at("file").get<std::string>());
				if (relative.is_absolute() || relative.empty()) return KERNEL_ERROR_EINVAL;
				entry.sha256 = row.at("sha256").get<std::string>();
				AuthInfo::Digest digest;
				if (!AuthInfo::ParseDigestHex(entry.sha256, &digest)) return KERNEL_ERROR_EINVAL;
				entry.sha256 = AuthInfo::DigestHex(digest);
				if (lazy_files) {
					// Checked on open by TransferCaptured (size, SHA-256). A missing payload fails
					// only that open, with EIO.
					entry.file = (storage / relative).lexically_normal();
					if (!Within(storage, entry.file)) return KERNEL_ERROR_EINVAL;
				} else {
					entry.file = std::filesystem::canonical(storage / relative, error);
					if (error || !Within(storage, entry.file) ||
					    !std::filesystem::is_regular_file(entry.file) ||
					    std::filesystem::file_size(entry.file) != entry.stat.size)
						return KERNEL_ERROR_EINVAL;
				}
			}
			if (entry.complete && entry.type != 4) return KERNEL_ERROR_EINVAL;
			if (!snapshot->entries.emplace(Key(path, snapshot->case_sensitive), std::move(entry))
			         .second)
				return KERNEL_ERROR_EINVAL;
		}
		const auto root = snapshot->entries.find("/");
		if (root == snapshot->entries.end() || !root->second.metadata || root->second.type != 4)
			return KERNEL_ERROR_EINVAL;
		for (const auto& [path, entry]: snapshot->entries) {
			if (path == "/") continue;
			const auto slash  = path.rfind('/');
			const auto parent = snapshot->entries.find(slash == 0 ? "/" : path.substr(0, slash));
			if (parent == snapshot->entries.end() || parent->second.type != 4)
				return KERNEL_ERROR_EINVAL;
		}
		staged.push_back(std::move(snapshot));
	}
	const auto encoded = EncodeSnapshots(staged);
	CapturedMetadataCache::Write(cache_key, encoded);
	std::lock_guard lock(mutex);
	if (!snapshots.empty()) return KERNEL_ERROR_EBUSY;
	snapshots.swap(staged);
	last_load_cache_hit = false;
	return OK;
} catch (const nlohmann::json::exception&) {
	return KERNEL_ERROR_EINVAL;
} catch (const std::filesystem::filesystem_error&) {
	return KERNEL_ERROR_EIO;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int Supplement(const std::filesystem::path& file, const std::string& sha256) try {
	AuthInfo::Digest expected;
	std::string      bytes;
	if (const int read = ReadPinned(file, sha256, &expected, &bytes); read != OK) return read;
	const auto       json = nlohmann::json::parse(bytes);
	AuthInfo::Digest base;
	if (json.at("version") != 1 || !json.at("volumes").is_array() ||
	    !AuthInfo::ParseDigestHex(json.at("base_manifest_sha256").get<std::string>(), &base))
		return KERNEL_ERROR_EINVAL;
	std::lock_guard lock(mutex);
	auto            staged = snapshots;
	for (const auto& volume: json.at("volumes")) {
		const auto point = volume.at("point").get<std::string>();
		const auto found = std::find_if(staged.begin(), staged.end(), [&](const auto& snapshot) {
			return snapshot->point == point;
		});
		// one supplement per point
		if (found == staged.end() || (*found)->manifest_sha256 != AuthInfo::DigestHex(base) ||
		    !(*found)->supplement_sha256.empty() || !volume.at("entries").is_array())
			return KERNEL_ERROR_EINVAL;
		auto snapshot               = std::make_shared<Snapshot>(**found);
		snapshot->supplement_sha256 = AuthInfo::DigestHex(expected);
		for (const auto& row: volume.at("entries")) {
			const auto path = row.at("path").get<std::string>();
			if (!ValidPath(path)) return KERNEL_ERROR_EINVAL;
			const auto entry = snapshot->entries.find(Key(path, snapshot->case_sensitive));
			if (entry == snapshot->entries.end() || entry->second.metadata ||
			    !ReadMetadata(row, &entry->second))
				return KERNEL_ERROR_EINVAL;
			entry->second.metadata = true;
		}
		*found = std::move(snapshot);
	}
	snapshots.swap(staged);
	return OK;
} catch (const nlohmann::json::exception&) {
	return KERNEL_ERROR_EINVAL;
} catch (const std::filesystem::filesystem_error&) {
	return KERNEL_ERROR_EIO;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

void Clear() {
	std::lock_guard lock(mutex);
	snapshots.clear();
	last_load_cache_hit = false;
}

bool LastLoadUsedStartupCache() {
	std::lock_guard lock(mutex);
	return !snapshots.empty() && last_load_cache_hit;
}

std::shared_ptr<const Snapshot> ForRoot(const std::filesystem::path& root) {
	std::lock_guard lock(mutex);
	for (const auto& snapshot: snapshots)
		if (snapshot->root == root) return snapshot;
	return {};
}

std::shared_ptr<const Snapshot> ForPoint(std::string_view point) {
	std::lock_guard lock(mutex);
	for (const auto& snapshot: snapshots)
		if (snapshot->point == point) return snapshot;
	return {};
}

int RootMetadata(const std::string& point, DirectoryPassthrough::NodeStat* stat) {
	std::lock_guard lock(mutex);
	for (const auto& snapshot: snapshots) {
		if (snapshot->point == point) {
			*stat = snapshot->entries.at("/").stat;
			return OK;
		}
	}
	return KERNEL_ERROR_ENOENT;
}

int Find(const Snapshot& snapshot, std::string_view path, const Entry** entry) {
	const auto key    = Key(path.empty() ? "/" : path, snapshot.case_sensitive);
	auto       parent = snapshot.entries.find("/");
	if (key == "/") {
		*entry = &parent->second;
		return parent->second.metadata ? OK : KERNEL_ERROR_EIO;
	}
	for (size_t start = 1; start <= key.size();) {
		const auto end     = key.find('/', start);
		const auto current = snapshot.entries.find(key.substr(0, end));
		if (current == snapshot.entries.end())
			return parent->second.complete ? KERNEL_ERROR_ENOENT : KERNEL_ERROR_EIO;
		if (current->second.type == 10 ||
		    (!current->second.metadata && (end == key.npos || current->second.type != 4)))
			return KERNEL_ERROR_EIO;
		if (end != key.npos && current->second.type != 4) return KERNEL_ERROR_ENOTDIR;
		if (end == key.npos) {
			*entry = &current->second;
			return OK;
		}
		parent = current;
		start  = end + 1;
	}
	return KERNEL_ERROR_EIO;
}

int FindDirectory(const Snapshot& snapshot, std::string_view path, const Entry** entry) {
	const auto found =
	    snapshot.entries.find(Key(path.empty() ? "/" : path, snapshot.case_sensitive));
	if (found == snapshot.entries.end()) return KERNEL_ERROR_ENOENT;
	if (found->second.type != 4) return KERNEL_ERROR_ENOTDIR;
	*entry = &found->second;
	return OK;
}

int List(const Snapshot& snapshot, std::string_view path,
         std::vector<DirectoryPassthrough::DirectoryEntry>* entries) {
	const Entry* directory = nullptr;
	const int    found     = Find(snapshot, path, &directory);
	if (found != OK) return found;
	if (directory->type != 4) return KERNEL_ERROR_ENOTDIR;
	if (!directory->complete) return KERNEL_ERROR_EIO;
	const auto key    = Key(path.empty() ? "/" : path, snapshot.case_sensitive);
	const auto prefix = key == "/" ? key : key + "/";
	std::vector<DirectoryPassthrough::DirectoryEntry> output;
	for (auto item = snapshot.entries.lower_bound(prefix);
	     item != snapshot.entries.end() && item->first.starts_with(prefix); ++item) {
		const auto name = item->first.substr(prefix.size());
		if (name.empty() || name.find('/') != name.npos) continue;
		const auto& node = item->second;
		output.push_back({node.stat.inode, node.type == 4, node.name, node.type});
	}
	*entries = std::move(output);
	return OK;
}

} // namespace Libs::LibKernel::CapturedDirectory
