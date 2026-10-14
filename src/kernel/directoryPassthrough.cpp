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
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <io.h>
#include <share.h>
#include <windows.h>
#include <bcrypt.h>
#undef DeleteFile
#undef CreateDirectory
#endif

// Diagnostic VFS backend over a host directory, same surface as ExfatMount. Writes return EROFS;
// fsck mode-2 only reads. Except a captured mount nmounted without MNT_RDONLY with
// KYTY_DIAGNOSTIC_PASSTHROUGH_UPPER set: writes go to a copy-on-write upper store there, shared by
// all exec children.

namespace Libs::LibKernel::DirectoryPassthrough {
namespace {

constexpr uint64_t UpperMagic = 0x3150555450595448ull;
// Seconds between 1601-01-01 (the Windows file clock epoch) and 1970-01-01.
constexpr int64_t FileClockEpochSkew = 11644473600;

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
uint32_t                                  next_device = 0xef100000u;

uint32_t FnvInode(uint32_t device, std::string_view key) {
	uint64_t hash = 0xcbf29ce484222325ull ^ static_cast<uint64_t>(device);
	for (unsigned char c: key) {
		if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
		hash ^= c;
		hash *= 0x100000001b3ull;
	}
	const auto folded = static_cast<uint32_t>(hash ^ (hash >> 32));
	return folded == 0 ? 1u : folded;
}

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

bool LowercaseStartsWith(std::string_view text, std::string_view prefix) {
	return text.size() >= prefix.size() && LowercaseEqual(text.substr(0, prefix.size()), prefix);
}

bool IsHexUserDirectory(std::string_view name) {
	if (name.size() != 8 || LowercaseEqual(name, "000000fe") || LowercaseEqual(name, "000000ff"))
		return false;
	return std::all_of(name.begin(), name.end(), [](char c) {
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
	});
}

bool HasUserDirectory(std::string_view origin, std::string_view root) {
	if (!LowercaseStartsWith(origin, root)) return false;
	const auto rest  = origin.substr(root.size());
	const auto slash = rest.find('/');
	return IsHexUserDirectory(rest.substr(0, slash));
}

bool FactoryStorageHides(const MountRecord& mount, std::string_view origin) {
	if (!mount.factory_storage_view) return false;
	constexpr std::string_view home = "/priv/home/";
	if (LowercaseStartsWith(origin, home)) {
		const auto rest  = origin.substr(home.size());
		const auto slash = rest.find('/');
		const auto name  = rest.substr(0, slash);
		if (LowercaseEqual(name, "user_list.dat") || LowercaseEqual(name, "user_list.dat.0") ||
		    IsHexUserDirectory(name))
			return true;
	}
	if (LowercaseStartsWith(origin, "/priv/cache/profile/") ||
	    HasUserDirectory(origin, "/priv/messages/") || HasUserDirectory(origin, "/priv/sticker/") ||
	    HasUserDirectory(origin, "/eap/rodata/home/"))
		return true;
	for (const std::string_view database: {"/priv/mms/notification2.db"}) {
		if (LowercaseEqual(origin, database) ||
		    (origin.size() > database.size() && origin[database.size()] == '-' &&
		     LowercaseEqual(origin.substr(0, database.size()), database)))
			return true;
	}
	return false;
}

bool Matches(const std::string& point, const std::string& path) {
	const bool prefix =
	    path.size() >= point.size() &&
	    LowercaseEqual(std::string_view {point}, std::string_view {path}.substr(0, point.size()));
	return point == "/" || (prefix && (path.size() == point.size() || path[point.size()] == '/'));
}

bool ValidGuestMountIdentity(const std::string& point, const std::string& fstype,
                             const std::string& source, uint64_t flags) {
	const bool empty = fstype.empty() && source.empty() && flags == 0;
	if (empty) return true;
	if (fstype.empty() || source.empty() || fstype.size() >= 16 || source.size() >= 88 ||
	    point.size() >= 88 || fstype.find('\0') != fstype.npos ||
	    source.find('\0') != source.npos || fstype.find_first_of("\r\n") != fstype.npos ||
	    source.find_first_of("\r\n") != source.npos || (flags & ~1ull) != 0)
		return false;
	return true;
}

bool IsWithinRoot(const std::filesystem::path& root, const std::filesystem::path& candidate);

std::shared_ptr<MountRecord> FindMount(const std::string& path) {
	std::shared_ptr<MountRecord> found;
	for (const auto& mount: mounts) {
		if (mount->snapshot && mount->snapshot->case_sensitive &&
		    path.compare(0, mount->point.size(), mount->point) != 0)
			continue;
		if (Matches(mount->point, path) && (!found || mount->point.size() > found->point.size()))
			found = mount;
	}
	return found;
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

// Case-insensitive like exfatfs. An NTFS copy of the dump keeps its casing, so try a direct hit
// before scanning.
int ResolveHost(const std::filesystem::path& host_root, const std::string& relative,
                std::filesystem::path* resolved, bool* exists) {
	*resolved = host_root;
	*exists   = false;
	if (relative == "/" || relative.empty()) {
		std::error_code ec;
		const auto      canonical_root = std::filesystem::weakly_canonical(host_root, ec);
		if (ec || !std::filesystem::is_directory(canonical_root, ec) || ec)
			return KERNEL_ERROR_ENOENT;
		*resolved = canonical_root;
		*exists   = true;
		return OK;
	}
	size_t start = 0;
	if (!relative.empty() && relative.front() == '/') start = 1;
	while (start < relative.size()) {
		auto end = relative.find('/', start);
		if (end == relative.npos) end = relative.size();
		std::string component = relative.substr(start, end - start);
		start                 = end + 1;
		if (component.empty()) continue;
		std::error_code ec;
		auto            direct        = *resolved / std::filesystem::u8path(component);
		const bool      direct_exists = std::filesystem::exists(direct, ec);
		if (ec) return KERNEL_ERROR_EIO;
		if (direct_exists) {
			*resolved = std::move(direct);
			continue;
		}
		const bool directory = std::filesystem::is_directory(*resolved, ec);
		if (ec) return KERNEL_ERROR_EIO;
		if (!directory) return KERNEL_ERROR_ENOTDIR;
		bool found = false;
		for (const auto& entry: std::filesystem::directory_iterator(*resolved, ec)) {
			const auto       name_u8 = entry.path().filename().u8string();
			std::string_view name_view(reinterpret_cast<const char*>(name_u8.data()),
			                           name_u8.size());
			if (LowercaseEqual(name_view, std::string_view {component})) {
				*resolved = entry.path();
				found     = true;
				break;
			}
		}
		if (ec) return KERNEL_ERROR_EIO;
		if (!found) {
			const auto canonical_candidate = std::filesystem::weakly_canonical(direct, ec);
			if (ec) return KERNEL_ERROR_EIO;
			const auto canonical_root = std::filesystem::weakly_canonical(host_root, ec);
			if (ec) return KERNEL_ERROR_EIO;
			if (!IsWithinRoot(canonical_root, canonical_candidate)) return KERNEL_ERROR_ENOENT;
			*resolved = canonical_candidate;
			return OK;
		}
	}
	std::error_code ec;
	const auto      canon_resolved = std::filesystem::weakly_canonical(*resolved, ec);
	if (ec) return KERNEL_ERROR_ENOENT;
	const auto canon_root = std::filesystem::weakly_canonical(host_root, ec);
	if (ec) return KERNEL_ERROR_ENOENT;
	if (!IsWithinRoot(canon_root, canon_resolved)) return KERNEL_ERROR_ENOENT;
	const bool present = std::filesystem::exists(canon_resolved, ec);
	if (ec) return KERNEL_ERROR_ENOENT;
	*resolved = canon_resolved;
	*exists   = present;
	return OK;
}

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
std::filesystem::path NormalizeFinalPath(std::wstring path) {
	constexpr std::wstring_view unc_prefix = LR"(\\?\UNC\)";
	constexpr std::wstring_view dos_prefix = LR"(\\?\)";
	if (path.starts_with(unc_prefix)) {
		path = L"\\\\" + path.substr(unc_prefix.size());
	} else if (path.starts_with(dos_prefix)) {
		path.erase(0, dos_prefix.size());
	}
	return std::filesystem::path(std::move(path)).lexically_normal();
}

bool EqualPathComponent(const std::filesystem::path& left, const std::filesystem::path& right) {
	const auto& l = left.native();
	const auto& r = right.native();
	if (l.size() > static_cast<size_t>(INT_MAX) || r.size() > static_cast<size_t>(INT_MAX)) {
		return false;
	}
	return CompareStringOrdinal(l.data(), static_cast<int>(l.size()), r.data(),
	                            static_cast<int>(r.size()), TRUE) == CSTR_EQUAL;
}

bool IsWithinRoot(const std::filesystem::path& root, const std::filesystem::path& candidate) {
	auto root_it      = root.begin();
	auto candidate_it = candidate.begin();
	for (; root_it != root.end(); ++root_it, ++candidate_it) {
		if (candidate_it == candidate.end() || !EqualPathComponent(*root_it, *candidate_it)) {
			return false;
		}
	}
	return true;
}

int FinalOpenedPath(std::FILE* file, const std::filesystem::path& canonical_root,
                    std::filesystem::path* host) {
	const int descriptor = _fileno(file);
	if (descriptor < 0) return KERNEL_ERROR_EIO;
	const intptr_t native = _get_osfhandle(descriptor);
	if (native == -1) return KERNEL_ERROR_EIO;
	const auto  handle = reinterpret_cast<HANDLE>(native);
	const DWORD length =
	    GetFinalPathNameByHandleW(handle, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
	if (length == 0) return KERNEL_ERROR_EIO;
	std::wstring final_name(length, L'\0');
	const DWORD  written = GetFinalPathNameByHandleW(handle, final_name.data(), length,
	                                                 FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
	if (written == 0 || written >= length) return KERNEL_ERROR_EIO;
	final_name.resize(written);
	auto final_path = NormalizeFinalPath(std::move(final_name));
	if (!IsWithinRoot(canonical_root, final_path)) return KERNEL_ERROR_ENOENT;
	*host = std::move(final_path);
	return OK;
}
#else
bool IsWithinRoot(const std::filesystem::path& root, const std::filesystem::path& candidate) {
	auto root_it      = root.begin();
	auto candidate_it = candidate.begin();
	for (; root_it != root.end(); ++root_it, ++candidate_it) {
		if (candidate_it == candidate.end() || *root_it != *candidate_it) return false;
	}
	return true;
}
#endif

std::string Relative(const MountRecord& mount, const std::string& path) {
	if (mount.point == "/") return path;
	if (path.size() == mount.point.size()) return "/";
	return path.substr(mount.point.size());
}

int ResolveCaptured(const MountRecord&                                        mount,
                    const std::shared_ptr<const CapturedDirectory::Snapshot>& snapshot,
                    const std::string& path, std::filesystem::path* host, bool* exists) {
	const CapturedDirectory::Entry* entry = nullptr;
	const int found = CapturedDirectory::Find(*snapshot, Relative(mount, path), &entry);
	if (found != OK) return found;
	if (entry->type != 4 && entry->file.empty()) return KERNEL_ERROR_EIO;
	*host   = entry->type == 4 ? snapshot->root : entry->file;
	*exists = true;
	return OK;
}

int Resolve(const MountRecord& mount, const std::string& path, std::filesystem::path* host,
            bool* exists, std::shared_ptr<const CapturedDirectory::Snapshot>* source) {
	source->reset();
	if (mount.snapshot) {
		const int result = ResolveCaptured(mount, mount.snapshot, path, host, exists);
		if (result == OK) *source = mount.snapshot;
		return result;
	}
	const auto relative = Relative(mount, path);
	// manifest ELFs get the encrypted SELF; the exec-time substitution keys on its bytes
	if (mount.fallback && Loader::DecryptedModuleOverlay::ManifestCoversPath(path)) {
		const int captured = ResolveCaptured(mount, mount.fallback, path, host, exists);
		if (captured == OK && *exists) {
			*source = mount.fallback;
			return OK;
		}
	}
	const int primary = ResolveHost(mount.canonical_root, relative, host, exists);
	if (primary == OK && *exists) return OK;
	// ENOENT includes host symlinks leading outside the root
	if ((primary != OK && primary != KERNEL_ERROR_ENOENT) || !mount.fallback ||
	    std::none_of(mount.fallback_prefixes.begin(), mount.fallback_prefixes.end(),
	                 [&](const auto& prefix) { return Matches(prefix, relative); }))
		return primary;
	const int result = ResolveCaptured(mount, mount.fallback, path, host, exists);
	if (result == OK) *source = mount.fallback;
	return result;
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

NodeStat Metadata(const MountRecord& mount, const std::string& normalized,
                  const std::filesystem::path& host, bool is_directory,
                  const std::shared_ptr<const CapturedDirectory::Snapshot>& source = {}) {
	if (source) {
		const CapturedDirectory::Entry* entry = nullptr;
		if (CapturedDirectory::Find(*source, Relative(mount, normalized), &entry) != OK) return {};
		auto stat   = entry->stat;
		stat.device = mount.device;
		return stat;
	}
	NodeStat stat {};
	stat.device = mount.device;
	stat.inode  = FnvInode(mount.device, normalized);
	stat.mode   = (is_directory ? 0040000u : 0100000u) | 0555u;
	if (!is_directory) {
		std::error_code ec;
		const auto      size = std::filesystem::file_size(host, ec);
		if (!ec) {
			stat.size           = size;
			stat.allocated_size = (size + 4095) & ~uint64_t {4095};
		}
	}
	return stat;
}

std::string Escape(std::string_view text) {
	std::string out;
	out.reserve(text.size());
	for (const char c: text) {
		if (c == '%' || c == '\t' || c == '\r' || c == '\n') {
			char hex[4];
			std::snprintf(hex, sizeof(hex), "%%%02X", static_cast<unsigned char>(c));
			out += hex;
		} else {
			out += c;
		}
	}
	return out;
}

bool Unescape(std::string_view text, std::string* out) {
	out->clear();
	for (size_t i = 0; i < text.size(); ++i) {
		if (text[i] != '%') {
			*out += text[i];
			continue;
		}
		unsigned value = 0;
		if (i + 2 >= text.size()) return false;
		const auto [end, error] =
		    std::from_chars(text.data() + i + 1, text.data() + i + 3, value, 16);
		if (error != std::errc {} || end != text.data() + i + 3) return false;
		*out += static_cast<char>(value);
		i += 2;
	}
	return true;
}

template <typename T>
bool Parse(std::string_view text, int base, T* value) {
	const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), *value, base);
	return !text.empty() && error == std::errc {} && end == text.data() + text.size();
}

int LoadIndex(UpperStore* upper) {
	upper->nodes.clear();
	upper->serial         = 1;
	const auto      index = upper->directory / "index.txt";
	std::error_code ec;
	if (!std::filesystem::exists(index, ec)) return ec ? KERNEL_ERROR_EIO : OK;
	std::ifstream input(index, std::ios::binary);
	std::string   line;
	if (!input || !std::getline(input, line) || !line.starts_with("KYTY_PT_UPPER 1 ") ||
	    !Parse(std::string_view {line}.substr(16), 10, &upper->serial))
		return KERNEL_ERROR_EIO;
	while (std::getline(input, line)) {
		std::vector<std::string_view> parts;
		for (size_t start = 0;;) {
			const auto end = line.find('\t', start);
			parts.push_back(
			    std::string_view {line}.substr(start, end == line.npos ? line.npos : end - start));
			if (end == line.npos) break;
			start = end + 1;
		}
		UpperNode   node;
		std::string path;
		if (parts.size() != 9 || parts[0].size() != 1 ||
		    std::string_view {"dfw"}.find(parts[0][0]) == std::string_view::npos ||
		    !Parse(parts[1], 8, &node.mode) || !Parse(parts[2], 10, &node.uid) ||
		    !Parse(parts[3], 10, &node.gid) || !Parse(parts[4], 10, &node.mtime) ||
		    !Parse(parts[5], 16, &node.inode) || !Parse(parts[6], 10, &node.object) ||
		    !Unescape(parts[7], &node.origin) || !Unescape(parts[8], &path) || path.empty() ||
		    path.front() != '/')
			return KERNEL_ERROR_EIO;
		node.kind                     = parts[0][0];
		upper->nodes[std::move(path)] = std::move(node);
	}
	return input.bad() ? KERNEL_ERROR_EIO : OK;
}

int SaveIndex(UpperStore* upper) {
	const auto temporary = upper->directory / "index.tmp";
	{
		std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
		output << "KYTY_PT_UPPER 1 " << upper->serial << '\n';
		for (const auto& [path, node]: upper->nodes) {
			char fields[128];
			std::snprintf(fields, sizeof(fields), "%c\t%o\t%u\t%u\t%lld\t%x\t%llu\t", node.kind,
			              node.mode, node.uid, node.gid, static_cast<long long>(node.mtime),
			              node.inode, static_cast<unsigned long long>(node.object));
			output << fields << Escape(node.origin) << '\t' << Escape(path) << '\n';
		}
		output.flush();
		if (!output) {
			upper->loaded = UINT64_MAX;
			return KERNEL_ERROR_EIO;
		}
	}
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (!MoveFileExW(temporary.c_str(), (upper->directory / "index.txt").c_str(),
	                 MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
		upper->loaded = UINT64_MAX;
		return KERNEL_ERROR_EIO;
	}
	upper->loaded = ++upper->shared->generation;
	return OK;
#else
	return KERNEL_ERROR_ENOSYS;
#endif
}

// Orders index writes across exec children; the generation marks cached nodes stale.
class UpperLock {
public:
	explicit UpperLock(UpperStore* upper): upper(upper) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		const DWORD waited = WaitForSingleObject(upper->mutex, 5000);
		if (waited != WAIT_OBJECT_0 && waited != WAIT_ABANDONED) {
			result = KERNEL_ERROR_EIO;
			return;
		}
		held = true;
		if (waited == WAIT_ABANDONED) ++upper->shared->generation;
		if (upper->shared->magic == 0) upper->shared->magic = UpperMagic;
		if (upper->shared->magic != UpperMagic) {
			result = KERNEL_ERROR_EIO;
			return;
		}
		if (upper->loaded != upper->shared->generation) {
			result        = LoadIndex(upper);
			upper->loaded = result == OK ? upper->shared->generation : UINT64_MAX;
		}
#else
		result = KERNEL_ERROR_ENOSYS;
#endif
	}
	~UpperLock() {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		if (held) ReleaseMutex(upper->mutex);
#endif
	}
	UpperLock(const UpperLock&)            = delete;
	UpperLock& operator=(const UpperLock&) = delete;

	int result = OK;

private:
	UpperStore* upper;
	bool        held = false;
};

int AttachUpper(MountRecord* mount) {
	const char* root = std::getenv("KYTY_DIAGNOSTIC_PASSTHROUGH_UPPER");
	if (root == nullptr || *root == '\0' || !mount->snapshot || !mount->snapshot->case_sensitive)
		return KERNEL_ERROR_EROFS;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	auto name = mount->point;
	std::replace(name.begin(), name.end(), '/', '_');
	auto            upper = std::make_shared<UpperStore>();
	std::error_code ec;
	std::filesystem::create_directories(std::filesystem::u8path(root) / name / "objects", ec);
	if (ec) return KERNEL_ERROR_EIO;
	upper->directory = std::filesystem::canonical(std::filesystem::u8path(root) / name, ec);
	if (ec) return KERNEL_ERROR_EIO;
	uint64_t hash = 0xcbf29ce484222325ull;
	for (unsigned char c: Common::PathToString(upper->directory)) {
		if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
		hash ^= c;
		hash *= 0x100000001b3ull;
	}
	char object_name[96];
	std::snprintf(object_name, sizeof(object_name),
	              "Local\\KytyPS5_PassthroughUpper_v1_%016llx_mutex",
	              static_cast<unsigned long long>(hash));
	upper->mutex = CreateMutexA(nullptr, FALSE, object_name);
	if (upper->mutex == nullptr) return KERNEL_ERROR_EIO;
	std::snprintf(object_name, sizeof(object_name),
	              "Local\\KytyPS5_PassthroughUpper_v1_%016llx_memory",
	              static_cast<unsigned long long>(hash));
	upper->mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
	                                    sizeof(UpperShared), object_name);
	if (upper->mapping == nullptr) return KERNEL_ERROR_EIO;
	upper->shared = static_cast<UpperShared*>(
	    MapViewOfFile(upper->mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(UpperShared)));
	if (upper->shared == nullptr) return KERNEL_ERROR_EIO;
	size_t nodes = 0;
	{
		UpperLock lock(upper.get());
		if (lock.result != OK) return lock.result;
		nodes = upper->nodes.size();
	}
	LOGF("PASSTHROUGH_UPPER_ATTACHED point=%s store=%s nodes=%zu NON_AUTHENTIC=1\n",
	     Log::EscapeField(mount->point).c_str(),
	     Log::EscapeField(Common::PathToString(upper->directory)).c_str(), nodes);
	const char* factory  = std::getenv("KYTY_DIAGNOSTIC_FACTORY_STORAGE_VIEW");
	const char* registry = std::getenv("KYTY_DIAGNOSTIC_REGMGR_SESSION_STORE");
	const bool  factory_requested =
	    LowercaseEqual(mount->point, "/system_data") && factory != nullptr && *factory != '\0';
	mount->factory_storage_view = factory_requested && registry != nullptr && *registry != '\0';
	if (mount->factory_storage_view) {
		LOGF("FACTORY_STORAGE_VIEW_ATTACHED point=%s lower_accounts=hidden "
		     "lower_notification_database=hidden upper_writes=visible NON_AUTHENTIC=1\n",
		     Log::EscapeField(mount->point).c_str());
	} else if (factory_requested) {
		LOGF("FACTORY_STORAGE_VIEW_REJECTED point=%s reason=regmgr_session_store_disabled "
		     "NON_AUTHENTIC=1\n",
		     Log::EscapeField(mount->point).c_str());
	}
	mount->upper = std::move(upper);
	return OK;
#else
	return KERNEL_ERROR_EROFS;
#endif
}

std::string ParentOf(const std::string& relative) {
	const auto slash = relative.rfind('/');
	return slash == 0 ? std::string {"/"} : relative.substr(0, slash);
}

std::string Name(const std::string& relative) {
	return relative.substr(relative.rfind('/') + 1);
}

std::string Join(const std::string& directory, std::string_view name) {
	return (directory == "/" ? directory : directory + "/") + std::string {name};
}

int64_t Now() {
	return std::chrono::duration_cast<std::chrono::seconds>(
	           std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

std::filesystem::path ObjectPath(const UpperStore& upper, uint64_t object) {
	return upper.directory / "objects" / std::to_string(object);
}

void EraseTree(UpperStore* upper, const std::string& relative) {
	upper->nodes.erase(relative);
	const auto prefix = relative + "/";
	for (auto item = upper->nodes.lower_bound(prefix);
	     item != upper->nodes.end() && item->first.starts_with(prefix);)
		item = upper->nodes.erase(item);
}

struct View {
	char                            kind  = 0;
	const UpperNode*                node  = nullptr;
	const CapturedDirectory::Entry* entry = nullptr;
	std::string                     origin;
};

int Lookup(const MountRecord& mount, const std::string& relative, View* view) {
	const auto& nodes = mount.upper->nodes;
	*view             = {};
	view->origin      = "/";
	const auto root   = nodes.find("/");
	if (root != nodes.end()) {
		view->node   = &root->second;
		view->origin = root->second.origin;
	}
	std::string walked;
	for (size_t start = 1; start < relative.size();) {
		if (view->node && view->node->kind == 'f') return KERNEL_ERROR_ENOTDIR;
		auto end = relative.find('/', start);
		if (end == relative.npos) end = relative.size();
		const auto part = std::string_view {relative}.substr(start, end - start);
		start           = end + 1;
		walked += '/';
		walked += part;
		const auto found = nodes.find(walked);
		if (found != nodes.end() && found->second.kind == 'w') return KERNEL_ERROR_ENOENT;
		if (found != nodes.end()) {
			view->node   = &found->second;
			view->origin = found->second.origin;
		} else {
			view->node = nullptr;
			if (view->origin.empty()) return KERNEL_ERROR_ENOENT;
			view->origin = Join(view->origin, part);
		}
	}
	if (view->node && (view->node->kind == 'd' || view->node->object != 0)) {
		view->kind = view->node->kind;
		return OK;
	}
	const int found = CapturedDirectory::Find(*mount.snapshot, view->origin, &view->entry);
	if (found != OK) return found;
	if (!view->node && FactoryStorageHides(mount, view->origin)) return KERNEL_ERROR_ENOENT;
	view->kind = view->node ? view->node->kind : (view->entry->type == 4 ? 'd' : 'f');
	return OK;
}

int ViewStat(const MountRecord& mount, const View& view, NodeStat* stat) {
	*stat        = view.entry ? view.entry->stat : NodeStat {};
	stat->device = mount.device;
	if (!view.node) return OK;
	stat->mode     = view.node->mode;
	stat->uid      = view.node->uid;
	stat->gid      = view.node->gid;
	stat->mtime    = view.node->mtime;
	stat->inode    = view.node->inode;
	stat->captured = true;
	if (view.node->kind == 'd') stat->size = 512;
	if (view.node->kind == 'f' && view.node->object != 0) {
		const auto      object = ObjectPath(*mount.upper, view.node->object);
		std::error_code ec;
		stat->size = std::filesystem::file_size(object, ec);
		if (ec) return KERNEL_ERROR_EIO;
		const auto written = std::filesystem::last_write_time(object, ec);
		if (ec) return KERNEL_ERROR_EIO;
		stat->mtime =
		    std::chrono::duration_cast<std::chrono::seconds>(written.time_since_epoch()).count() -
		    FileClockEpochSkew;
	}
	return OK;
}

int MergedList(const MountRecord& mount, const std::string& relative, const View& view,
               std::vector<DirectoryEntry>* entries) {
	const auto&                 nodes  = mount.upper->nodes;
	const auto                  prefix = relative == "/" ? relative : relative + "/";
	std::vector<DirectoryEntry> output;
	std::set<std::string>       shadowed;
	for (auto item = nodes.lower_bound(prefix);
	     item != nodes.end() && item->first.starts_with(prefix); ++item) {
		auto name = item->first.substr(prefix.size());
		if (name.empty() || name.find('/') != name.npos) continue;
		shadowed.insert(name);
		if (item->second.kind == 'w') continue;
		const uint8_t type = item->second.kind == 'd' ? 4 : 8;
		output.push_back({item->second.inode, type == 4, std::move(name), type});
	}
	if (!view.origin.empty()) {
		std::vector<DirectoryEntry> lower;
		const int listed = CapturedDirectory::List(*mount.snapshot, view.origin, &lower);
		if (listed != OK) return listed;
		for (auto& child: lower) {
			if (!shadowed.contains(child.name) &&
			    !FactoryStorageHides(mount, Join(view.origin, child.name)))
				output.push_back(std::move(child));
		}
	}
	*entries = std::move(output);
	return OK;
}

// first change inside a directory gives it a merged upper node, so its mtime can move
int Touch(const MountRecord& mount, const std::string& relative, int64_t now) {
	auto&      nodes = mount.upper->nodes;
	const auto found = nodes.find(relative);
	if (found != nodes.end()) {
		found->second.mtime = now;
		return OK;
	}
	View      view;
	const int looked = Lookup(mount, relative, &view);
	if (looked != OK) return looked;
	if (!view.entry || !view.entry->metadata) return KERNEL_ERROR_EIO;
	UpperNode node;
	node.kind       = 'd';
	node.mode       = view.entry->stat.mode;
	node.uid        = view.entry->stat.uid;
	node.gid        = view.entry->stat.gid;
	node.inode      = view.entry->stat.inode;
	node.mtime      = now;
	node.origin     = view.origin;
	nodes[relative] = std::move(node);
	return OK;
}

// Would removing parent/name expose a captured entry? Unknown counts as yes.
bool LowerVisible(const MountRecord& mount, const std::string& parent, const std::string& name) {
	View view;
	if (Lookup(mount, parent, &view) != OK || view.kind != 'd' || view.origin.empty()) return false;
	const CapturedDirectory::Entry* entry = nullptr;
	return CapturedDirectory::Find(*mount.snapshot, Join(view.origin, name), &entry) !=
	       KERNEL_ERROR_ENOENT;
}

int TransferCaptured(std::FILE* source, const CapturedDirectory::Entry& entry,
                     std::FILE* destination) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	BCRYPT_ALG_HANDLE  algorithm = nullptr;
	BCRYPT_HASH_HANDLE hash      = nullptr;
	AuthInfo::Digest   expected {}, actual {};
	bool ok = AuthInfo::ParseDigestHex(entry.sha256, &expected) &&
	          BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0 &&
	          BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0;
	std::vector<uint8_t> bytes(1024 * 1024);
	uint64_t             transferred = 0;
	while (ok && transferred < entry.stat.size) {
		const auto size =
		    static_cast<size_t>(std::min<uint64_t>(bytes.size(), entry.stat.size - transferred));
		ok = std::fread(bytes.data(), 1, size, source) == size && !std::ferror(source) &&
		     BCryptHashData(hash, bytes.data(), static_cast<ULONG>(size), 0) >= 0 &&
		     (destination == nullptr || std::fwrite(bytes.data(), 1, size, destination) == size);
		transferred += size;
	}
	ok = ok && std::fgetc(source) == EOF && !std::ferror(source) &&
	     BCryptFinishHash(hash, actual.data(), static_cast<ULONG>(actual.size()), 0) >= 0 &&
	     actual == expected && std::fseek(source, 0, SEEK_SET) == 0 &&
	     (destination == nullptr || std::fflush(destination) == 0);
	if (hash != nullptr) BCryptDestroyHash(hash);
	if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
	return ok ? OK : KERNEL_ERROR_EIO;
#else
	if (entry.stat.size > SIZE_MAX) return KERNEL_ERROR_EFBIG;
	std::vector<uint8_t> bytes(static_cast<size_t>(entry.stat.size));
	const bool           ok =
	    std::fread(bytes.data(), 1, bytes.size(), source) == bytes.size() &&
	    std::fgetc(source) == EOF && !std::ferror(source) &&
	    AuthInfo::DigestHex(AuthInfo::Sha256(bytes.data(), bytes.size())) == entry.sha256 &&
	    std::fseek(source, 0, SEEK_SET) == 0 &&
	    (destination == nullptr ||
		 (std::fwrite(bytes.data(), 1, bytes.size(), destination) == bytes.size() &&
		  std::fflush(destination) == 0));
	return ok ? OK : KERNEL_ERROR_EIO;
#endif
}

int OpenCaptured(const CapturedDirectory::Snapshot& snapshot, const CapturedDirectory::Entry& entry,
                 std::FILE** file, std::filesystem::path* host) {
	if (entry.file.empty()) return KERNEL_ERROR_EIO;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	std::FILE* opened = _wfsopen(entry.file.c_str(), L"rb", _SH_DENYWR);
	if (opened == nullptr) return KERNEL_ERROR_EIO;
	int result = FinalOpenedPath(opened, snapshot.storage, host);
#else
	std::FILE* opened = std::fopen(entry.file.c_str(), "rb");
	if (opened == nullptr) return KERNEL_ERROR_EIO;
	*host      = entry.file;
	int result = OK;
#endif
	if (result == OK) result = TransferCaptured(opened, entry, nullptr);
	if (result != OK || file == nullptr) std::fclose(opened);
	if (result != OK) return result;
	if (file) *file = opened;
	return OK;
}

int CopyCaptured(const CapturedDirectory::Snapshot& snapshot, const CapturedDirectory::Entry& entry,
                 const std::filesystem::path& destination) {
	std::FILE*            source = nullptr;
	std::filesystem::path host;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	source = _wfsopen(entry.file.c_str(), L"rb", _SH_DENYWR);
	if (source == nullptr) return KERNEL_ERROR_EIO;
	int        result = FinalOpenedPath(source, snapshot.storage, &host);
	std::FILE* output = result == OK ? _wfsopen(destination.c_str(), L"w+b", _SH_DENYRW) : nullptr;
#else
	source = std::fopen(entry.file.c_str(), "rb");
	if (source == nullptr) return KERNEL_ERROR_EIO;
	host              = entry.file;
	int        result = OK;
	std::FILE* output = std::fopen(destination.c_str(), "w+b");
#endif
	if (result == OK && output == nullptr) result = KERNEL_ERROR_EIO;
	if (result == OK) result = TransferCaptured(source, entry, output);
	if (output != nullptr && std::fclose(output) != 0 && result == OK) result = KERNEL_ERROR_EIO;
	std::fclose(source);
	if (result != OK) {
		std::error_code ignored;
		std::filesystem::remove(destination, ignored);
	}
	return result;
}

} // namespace

class Handle {
public:
	std::shared_ptr<MountRecord>                       mount;
	std::shared_ptr<const CapturedDirectory::Snapshot> snapshot;
	std::string                                        normalized;
	std::filesystem::path                              host;
	bool                                               directory = false;
	std::mutex                                         mutex;
	uint64_t                                           offset   = 0;
	std::FILE*                                         file     = nullptr;
	bool                                               overlay  = false;
	bool                                               object   = false;
	bool                                               writable = false;
	bool                                               append   = false;
	NodeStat                                           stat;

	~Handle() {
		if (file != nullptr) std::fclose(file);
	}
};

static int OpenOverlay(const std::shared_ptr<MountRecord>& mount, std::string normalized, int flags,
                       uint32_t mode, std::shared_ptr<Handle>* handle) {
	auto&     upper = *mount->upper;
	UpperLock lock(&upper);
	if (lock.result != OK) return lock.result;
	const bool write    = (flags & 3) != 0;
	const bool truncate = (flags & 0x400) != 0;
	const auto relative = Relative(*mount, normalized);
	View       view;
	int        looked = Lookup(*mount, relative, &view);
	if (looked == KERNEL_ERROR_ENOENT && (flags & 0x200)) {
		View      parent;
		const int found = Lookup(*mount, ParentOf(relative), &parent);
		if (found != OK) return found;
		if (parent.kind != 'd') return KERNEL_ERROR_ENOTDIR;
		NodeStat  parent_stat;
		const int stated = ViewStat(*mount, parent, &parent_stat);
		if (stated != OK) return stated;
		UpperNode node;
		node.kind   = 'f';
		node.mode   = 0100000u | (mode & 07777u & ~01000u);
		node.gid    = parent_stat.gid;
		node.mtime  = Now();
		node.object = upper.serial++;
		node.inode  = FnvInode(mount->device, "upper/" + std::to_string(node.object));
		{
			std::ofstream created(ObjectPath(upper, node.object),
			                      std::ios::binary | std::ios::trunc);
			if (!created) return KERNEL_ERROR_EIO;
		}
		const int touched = Touch(*mount, ParentOf(relative), node.mtime);
		if (touched != OK) {
			upper.loaded = UINT64_MAX;
			return touched;
		}
		upper.nodes[relative] = std::move(node);
		const int saved       = SaveIndex(&upper);
		if (saved != OK) return saved;
		looked = Lookup(*mount, relative, &view);
	} else if (looked == OK && (flags & 0xa00) == 0xa00) {
		return KERNEL_ERROR_EEXIST;
	}
	if (looked != OK) return looked;
	if ((flags & 0x20000) && view.kind != 'd') return KERNEL_ERROR_ENOTDIR;
	if (view.kind == 'd' && (write || truncate)) return KERNEL_ERROR_EISDIR;
	if (view.kind == 'f' && (!view.node || view.node->object == 0) && (write || truncate)) {
		UpperNode node;
		if (view.node) {
			node = *view.node;
		} else {
			node.kind   = 'f';
			node.mode   = view.entry->stat.mode;
			node.uid    = view.entry->stat.uid;
			node.gid    = view.entry->stat.gid;
			node.mtime  = view.entry->stat.mtime;
			node.inode  = view.entry->stat.inode;
			node.origin = view.origin;
		}
		node.object       = upper.serial++;
		const auto object = ObjectPath(upper, node.object);
		if (!truncate) {
			const int copied = CopyCaptured(*mount->snapshot, *view.entry, object);
			if (copied != OK) return copied;
		} else {
			std::ofstream output(object, std::ios::binary | std::ios::trunc);
			if (!output) return KERNEL_ERROR_EIO;
		}
		if (!truncate) {
			std::error_code ec;
			std::filesystem::last_write_time(object,
			                                 std::filesystem::file_time_type(std::chrono::seconds(
			                                     node.mtime + FileClockEpochSkew)),
			                                 ec);
			if (ec) return KERNEL_ERROR_EIO;
		}
		upper.nodes[relative] = std::move(node);
		const int saved       = SaveIndex(&upper);
		if (saved != OK) return saved;
		looked = Lookup(*mount, relative, &view);
		if (looked != OK) return looked;
	}
	auto      opened = std::make_shared<Handle>();
	const int stated = ViewStat(*mount, view, &opened->stat);
	if (stated != OK) return stated;
	opened->mount      = mount;
	opened->normalized = std::move(normalized);
	opened->directory  = view.kind == 'd';
	opened->overlay    = true;
	opened->writable   = write;
	opened->append     = (flags & 0x8) != 0;
	if (view.kind == 'f' && view.node && view.node->object != 0) {
		opened->object = true;
		opened->host   = ObjectPath(upper, view.node->object);
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		opened->file =
		    _wfsopen(opened->host.c_str(), write || truncate ? L"r+b" : L"rb", _SH_DENYNO);
		if (opened->file == nullptr) return KERNEL_ERROR_EIO;
		if (truncate && _chsize_s(_fileno(opened->file), 0) != 0) return KERNEL_ERROR_EIO;
#else
		return KERNEL_ERROR_ENOSYS;
#endif
	} else if (view.kind == 'f') {
		const int read = OpenCaptured(*mount->snapshot, *view.entry, &opened->file, &opened->host);
		if (read != OK) return read;
	}
	*handle = std::move(opened);
	return OK;
}

int Mount(const std::string& point, const std::filesystem::path& host_root, bool writable,
          const std::string& guest_fstype, const std::string& guest_source,
          uint64_t guest_flags) try {
	std::lock_guard lock(mounts_mutex);
	std::string     normalized;
	const int       result = Normalize(point, &normalized);
	if (result != OK) return result;
	if (!ValidGuestMountIdentity(normalized, guest_fstype, guest_source, guest_flags) ||
	    (writable && (guest_flags & 1u) != 0) ||
	    (!writable && !guest_fstype.empty() && (guest_flags & 1u) == 0))
		return KERNEL_ERROR_EINVAL;
	std::error_code ec;
	const auto      canonical_root = std::filesystem::canonical(host_root, ec);
	if (ec || !std::filesystem::is_directory(canonical_root, ec) || ec) return KERNEL_ERROR_ENOENT;
	for (const auto& mount: mounts) {
		if (Matches(mount->point, normalized) || Matches(normalized, mount->point))
			return KERNEL_ERROR_EBUSY;
	}
	uint32_t device = next_device;
	while (device != UINT32_MAX &&
	       std::any_of(mounts.begin(), mounts.end(),
	                   [&](const auto& mount) { return mount->device == device; }))
		++device;
	if (mounts.size() >= 16 || device == UINT32_MAX) return KERNEL_ERROR_ENOSPC;
	auto mount            = std::make_shared<MountRecord>();
	mount->point          = normalized;
	mount->host_root      = host_root;
	mount->canonical_root = canonical_root;
	mount->device         = device;
	mount->snapshot       = CapturedDirectory::ForRoot(canonical_root);
	mount->guest_fstype   = guest_fstype;
	mount->guest_source   = guest_source;
	mount->guest_flags    = guest_flags;
	if (writable) {
		const int attached = AttachUpper(mount.get());
		if (attached != OK && attached != KERNEL_ERROR_EROFS) return attached;
	}
	if (!mount->guest_fstype.empty()) {
		if (mount->upper)
			mount->guest_flags &= ~1ull;
		else
			mount->guest_flags |= 1ull;
	}
	mounts.push_back(std::move(mount));
	next_device = device + 1;
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

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

int ImportReadOnlyMounts(const std::vector<MountInfo>& infos) try {
	std::lock_guard lock(mounts_mutex);
	if (mounts.size() > 16 || infos.size() > 16 || infos.size() > 16 - mounts.size())
		return KERNEL_ERROR_ENOSPC;
	std::vector<std::shared_ptr<MountRecord>> staged;
	staged.reserve(infos.size());
	for (const auto& info: infos) {
		std::string point;
		const int   parsed = Normalize(info.point, &point);
		if (parsed != OK) return parsed;
		if (point != info.point || point == "/" || !info.host_root.is_absolute() ||
		    info.device < 0xef100000u || info.device == UINT32_MAX)
			return KERNEL_ERROR_EINVAL;
		if (!ValidGuestMountIdentity(point, info.guest_fstype, info.guest_source,
		                             info.guest_flags) ||
		    (info.writable && (info.guest_flags & 1u) != 0) ||
		    (!info.writable && !info.guest_fstype.empty() && (info.guest_flags & 1u) == 0))
			return KERNEL_ERROR_EINVAL;
		std::error_code error;
		const auto      canonical_root = std::filesystem::canonical(info.host_root, error);
		if (error || !std::filesystem::is_directory(canonical_root, error) || error)
			return KERNEL_ERROR_ENOENT;
		for (const auto& mount: mounts) {
			if (mount->device == info.device || Matches(mount->point, point) ||
			    Matches(point, mount->point))
				return KERNEL_ERROR_EBUSY;
		}
		for (const auto& mount: staged) {
			if (mount->device == info.device || Matches(mount->point, point) ||
			    Matches(point, mount->point))
				return KERNEL_ERROR_EBUSY;
		}
		auto mount            = std::make_shared<MountRecord>();
		mount->point          = point;
		mount->host_root      = info.host_root;
		mount->canonical_root = canonical_root;
		mount->device         = info.device;
		mount->guest_fstype   = info.guest_fstype;
		mount->guest_source   = info.guest_source;
		mount->guest_flags    = info.guest_flags;
		mount->snapshot       = CapturedDirectory::ForRoot(canonical_root);
		if ((mount->snapshot ? mount->snapshot->manifest_sha256 : "") != info.manifest_sha256)
			return KERNEL_ERROR_EINVAL;
		if (info.fallback_prefixes.empty() != info.fallback_manifest_sha256.empty())
			return KERNEL_ERROR_EINVAL;
		if (!info.fallback_prefixes.empty()) {
			mount->fallback = CapturedDirectory::ForPoint(point);
			if (!mount->fallback ||
			    mount->fallback->manifest_sha256 != info.fallback_manifest_sha256)
				return KERNEL_ERROR_EINVAL;
		}
		for (const auto& prefix: info.fallback_prefixes) {
			std::string fallback_prefix;
			const int   normalized_fallback = Normalize(prefix, &fallback_prefix);
			if (normalized_fallback != OK || fallback_prefix != prefix) return KERNEL_ERROR_EINVAL;
			const int admitted =
			    AdmitFallbackPrefix(*mount->fallback, fallback_prefix, mount->fallback_prefixes);
			if (admitted != OK) return admitted;
			mount->fallback_prefixes.push_back(std::move(fallback_prefix));
		}
		if (info.writable) {
			const int attached = AttachUpper(mount.get());
			if (attached != OK)
				return attached == KERNEL_ERROR_EROFS ? KERNEL_ERROR_EINVAL : attached;
		}
		staged.push_back(std::move(mount));
	}
	mounts.reserve(mounts.size() + staged.size());
	for (auto& mount: staged)
		mounts.push_back(std::move(mount));
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

void Shutdown() {
	std::lock_guard lock(mounts_mutex);
	mounts.clear();
	CapturedDirectory::Clear();
}

bool Contains(const std::string& path, bool captured_only) try {
	std::lock_guard lock(mounts_mutex);
	std::string     normalized;
	auto            mount = FindMount(Normalize(path, &normalized) == OK ? normalized : path);
	if (captured_only && (!mount || !mount->snapshot)) mount = FindMount(path);
	return mount && (!captured_only || mount->snapshot);
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

int Open(const std::string& path, int flags, std::shared_ptr<Handle>* handle, uint32_t mode) try {
	if (!handle) return KERNEL_ERROR_EFAULT;
	if ((flags & 3) == 3) return KERNEL_ERROR_EINVAL;
	const bool      mutating = (flags & 3) != 0 || (flags & (0x8 | 0x200 | 0x400 | 0x800));
	std::lock_guard lock(mounts_mutex);
	std::string     normalized;
	const int       result = Normalize(path, &normalized);
	const auto      mount  = result == OK ? FindMount(normalized) : nullptr;
	if (mutating && (!mount || !mount->upper)) return KERNEL_ERROR_EROFS;
	if (result != OK) return result;
	if (!mount) return KERNEL_ERROR_ENOENT;
	if (mount->upper) {
		const int opened = OpenOverlay(mount, normalized, flags, mode, handle);
		if (std::getenv("KYTY_DIAGNOSTIC_READ_ONLY_PROVIDER_IO_AUDIT") != nullptr) {
			LOGF("PASSTHROUGH_UPPER_IO operation=open path=%s flags=0x%x mode=0%o result=0x%08x\n",
			     Log::EscapeField(normalized).c_str(), flags, mode, static_cast<unsigned>(opened));
		}
		return opened;
	}
	std::filesystem::path                              host;
	bool                                               exists = false;
	std::shared_ptr<const CapturedDirectory::Snapshot> source;
	const int  resolved = Resolve(*mount, normalized, &host, &exists, &source);
	const bool audit    = std::getenv("KYTY_DIAGNOSTIC_READ_ONLY_PROVIDER_IO_AUDIT") != nullptr;
	if (resolved != OK) {
		if (audit) {
			LOGF("READ_ONLY_PROVIDER_IO operation=open path=%s flags=0x%x result=0x%08x point=%s "
			     "root=%s candidate=%s\n",
			     Log::EscapeField(normalized).c_str(), flags, static_cast<unsigned>(resolved),
			     Log::EscapeField(mount->point).c_str(),
			     Log::EscapeField(Common::PathToString(mount->host_root)).c_str(),
			     Log::EscapeField(Common::PathToString(host)).c_str());
		}
		return resolved;
	}
	if (!exists) {
		if (audit) {
			LOGF("READ_ONLY_PROVIDER_IO operation=open path=%s flags=0x%x result=0x%08x point=%s "
			     "root=%s candidate=%s\n",
			     Log::EscapeField(normalized).c_str(), flags,
			     static_cast<unsigned>(KERNEL_ERROR_ENOENT), Log::EscapeField(mount->point).c_str(),
			     Log::EscapeField(Common::PathToString(mount->host_root)).c_str(),
			     Log::EscapeField(Common::PathToString(host)).c_str());
		}
		return KERNEL_ERROR_ENOENT;
	}
	std::error_code ec;
	const auto      metadata = Metadata(*mount, normalized, host, false, source);
	const bool      is_directory =
	    source ? (metadata.mode & 0170000u) == 0040000u : std::filesystem::is_directory(host, ec);
	if ((flags & 0x20000) && !is_directory) return KERNEL_ERROR_ENOTDIR;
	auto opened        = std::make_shared<Handle>();
	opened->mount      = mount;
	opened->snapshot   = source;
	opened->normalized = std::move(normalized);
	opened->host       = std::move(host);
	opened->directory  = is_directory;
	if (!is_directory) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		opened->file = _wfsopen(opened->host.c_str(), L"rb", _SH_DENYWR);
#else
		opened->file = std::fopen(opened->host.c_str(), "rb");
#endif
		if (opened->file == nullptr) return KERNEL_ERROR_EIO;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		const int verified = FinalOpenedPath(
		    opened->file, source ? source->storage : mount->canonical_root, &opened->host);
		if (verified != OK) return verified;
#endif
		if (source) {
			const CapturedDirectory::Entry* entry = nullptr;
			if (CapturedDirectory::Find(*source, Relative(*mount, opened->normalized), &entry) !=
			    OK)
				return KERNEL_ERROR_EIO;
			std::vector<uint8_t> bytes(static_cast<size_t>(metadata.size));
			if (std::fread(bytes.data(), 1, bytes.size(), opened->file) != bytes.size() ||
			    std::fgetc(opened->file) != EOF || std::ferror(opened->file) ||
			    AuthInfo::DigestHex(AuthInfo::Sha256(bytes.data(), bytes.size())) != entry->sha256)
				return KERNEL_ERROR_EIO;
			if (std::fseek(opened->file, 0, SEEK_SET) != 0) return KERNEL_ERROR_EIO;
		}
	}
	if (audit) {
		const auto stat = Metadata(*mount, opened->normalized, opened->host, is_directory, source);
		LOGF("READ_ONLY_PROVIDER_IO operation=open path=%s flags=0x%x result=0 directory=%u "
		     "size=%llu device=0x%08x inode=0x%08x captured=%u fallback=%u point=%s root=%s "
		     "host=%s\n",
		     Log::EscapeField(opened->normalized).c_str(), flags, is_directory ? 1u : 0u,
		     static_cast<unsigned long long>(stat.size), stat.device, stat.inode, source ? 1u : 0u,
		     source && source == mount->fallback ? 1u : 0u, Log::EscapeField(mount->point).c_str(),
		     Log::EscapeField(Common::PathToString(mount->host_root)).c_str(),
		     Log::EscapeField(Common::PathToString(opened->host)).c_str());
	}
	*handle = std::move(opened);
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int OpenFileSnapshot(const std::string& path, FileSnapshot* snapshot) try {
	if (!snapshot) return KERNEL_ERROR_EFAULT;
	FileSnapshot opened;
	const int    result = Open(path, 0, &opened.handle);
	if (result != OK) return result;
	if (opened.handle->directory) return KERNEL_ERROR_EISDIR;

	std::lock_guard lock(opened.handle->mutex);
	if (opened.handle->file == nullptr) return KERNEL_ERROR_EIO;
	std::clearerr(opened.handle->file);
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (_fseeki64(opened.handle->file, 0, SEEK_END) != 0) return KERNEL_ERROR_EIO;
	const auto size = _ftelli64(opened.handle->file);
#else
	if (std::fseek(opened.handle->file, 0, SEEK_END) != 0) return KERNEL_ERROR_EIO;
	const auto size = std::ftell(opened.handle->file);
#endif
	if (size < 0) return KERNEL_ERROR_EIO;
	if (static_cast<uint64_t>(size) > UINT32_MAX) return KERNEL_ERROR_EFBIG;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (_fseeki64(opened.handle->file, 0, SEEK_SET) != 0) return KERNEL_ERROR_EIO;
#else
	if (std::fseek(opened.handle->file, 0, SEEK_SET) != 0) return KERNEL_ERROR_EIO;
#endif
	opened.bytes.resize(static_cast<size_t>(size));
	const auto actual =
	    std::fread(opened.bytes.data(), 1, opened.bytes.size(), opened.handle->file);
	const auto trailing = std::fgetc(opened.handle->file);
	if (actual != opened.bytes.size() || trailing != EOF || std::ferror(opened.handle->file)) {
		return KERNEL_ERROR_EIO;
	}
	opened.host_path = opened.handle->host;
	*snapshot        = std::move(opened);
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int Close(std::shared_ptr<Handle>& handle) {
	if (!handle) return KERNEL_ERROR_EBADF;
	handle.reset();
	return OK;
}

// For SyscoreExecvePreflight: FileSystem ResolvePath returns {} under passthrough mounts.
int ResolveHostPath(const std::string& path, std::filesystem::path* host) try {
	if (!host) return KERNEL_ERROR_EFAULT;
	std::lock_guard lock(mounts_mutex);
	std::string     normalized;
	const int       result = Normalize(path, &normalized);
	if (result != OK) return result;
	const auto mount = FindMount(normalized);
	if (!mount) return KERNEL_ERROR_ENOENT;
	std::filesystem::path                              resolved;
	bool                                               exists = false;
	std::shared_ptr<const CapturedDirectory::Snapshot> source;
	const int rc = Resolve(*mount, normalized, &resolved, &exists, &source);
	if (rc != OK) return rc;
	if (!exists) return KERNEL_ERROR_ENOENT;
	*host = std::move(resolved);
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int Stat(const std::string& path, NodeStat* stat) try {
	if (!stat) return KERNEL_ERROR_EFAULT;
	std::lock_guard lock(mounts_mutex);
	std::string     normalized;
	const int       result = Normalize(path, &normalized);
	if (result != OK) return result;
	const auto mount = FindMount(normalized);
	if (!mount) return KERNEL_ERROR_ENOENT;
	if (mount->upper) {
		UpperLock upper_lock(mount->upper.get());
		if (upper_lock.result != OK) return upper_lock.result;
		View      view;
		const int looked = Lookup(*mount, Relative(*mount, normalized), &view);
		if (looked != OK) return looked;
		return ViewStat(*mount, view, stat);
	}
	std::filesystem::path                              host;
	bool                                               exists = false;
	std::shared_ptr<const CapturedDirectory::Snapshot> source;
	const int resolved = Resolve(*mount, normalized, &host, &exists, &source);
	if (resolved != OK) return resolved;
	if (!exists) return KERNEL_ERROR_ENOENT;
	std::error_code ec;
	const bool      is_directory = source ? false : std::filesystem::is_directory(host, ec);
	*stat                        = Metadata(*mount, normalized, host, is_directory, source);
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int Fstat(const std::shared_ptr<Handle>& handle, NodeStat* stat) {
	if (!stat) return KERNEL_ERROR_EFAULT;
	if (!handle) return KERNEL_ERROR_EBADF;
	if (handle->overlay) {
		*stat = handle->stat;
		if (!handle->object) return OK;
		std::error_code ec;
		stat->size = std::filesystem::file_size(handle->host, ec);
		if (ec) return KERNEL_ERROR_EIO;
		const auto written = std::filesystem::last_write_time(handle->host, ec);
		if (ec) return KERNEL_ERROR_EIO;
		stat->mtime =
		    std::chrono::duration_cast<std::chrono::seconds>(written.time_since_epoch()).count() -
		    FileClockEpochSkew;
		return OK;
	}
	*stat = Metadata(*handle->mount, handle->normalized, handle->host, handle->directory,
	                 handle->snapshot);
	return OK;
}

int Fstatfs(const std::shared_ptr<Handle>& handle, MountInfo* info) {
	if (!info) return KERNEL_ERROR_EFAULT;
	if (!handle || !handle->mount) return KERNEL_ERROR_EBADF;
	const auto& mount = handle->mount;
	if (!ValidGuestMountIdentity(mount->point, mount->guest_fstype, mount->guest_source,
	                             mount->guest_flags) ||
	    mount->guest_fstype.empty())
		return KERNEL_ERROR_ENOSYS;
	*info = {mount->point,
	         {},
	         mount->device,
	         {},
	         {},
	         {},
	         mount->upper != nullptr,
	         mount->guest_fstype,
	         mount->guest_source,
	         mount->guest_flags};
	return OK;
}

int Entries(const std::shared_ptr<Handle>& handle, std::vector<DirectoryEntry>* entries) try {
	if (!entries) return KERNEL_ERROR_EFAULT;
	if (!handle) return KERNEL_ERROR_EBADF;
	if (!handle->directory) return KERNEL_ERROR_ENOTDIR;
	// Listed by path: a directory renamed or removed while open reads as its current namesake or as
	// empty.
	if (handle->overlay) {
		std::lock_guard lock(mounts_mutex);
		UpperLock       upper_lock(handle->mount->upper.get());
		if (upper_lock.result != OK) return upper_lock.result;
		const auto relative = Relative(*handle->mount, handle->normalized);
		View       view;
		const int  looked = Lookup(*handle->mount, relative, &view);
		if (looked == KERNEL_ERROR_ENOENT || (looked == OK && view.kind != 'd')) {
			entries->clear();
			return OK;
		}
		if (looked != OK) return looked;
		return MergedList(*handle->mount, relative, view, entries);
	}
	if (handle->snapshot)
		return CapturedDirectory::List(*handle->snapshot,
		                               Relative(*handle->mount, handle->normalized), entries);
	std::vector<DirectoryEntry> output;
	std::error_code             ec;
	for (const auto& entry: std::filesystem::directory_iterator(handle->host, ec)) {
		const auto  name_u8 = entry.path().filename().u8string();
		std::string name(reinterpret_cast<const char*>(name_u8.data()), name_u8.size());
		if (name.size() > 255) return KERNEL_ERROR_ENAMETOOLONG;
		const bool is_directory = entry.is_directory(ec);
		auto       child_normalized =
		    handle->normalized == "/" ? std::string {"/"} + name : handle->normalized + "/" + name;
		output.push_back(
		    {FnvInode(handle->mount->device, child_normalized), is_directory, std::move(name)});
	}
	const auto&                 mount = *handle->mount;
	std::vector<DirectoryEntry> captured;
	const auto                  relative = Relative(mount, handle->normalized);
	if (mount.fallback && CapturedDirectory::List(*mount.fallback, relative, &captured) == OK) {
		const size_t primary_count = output.size();
		for (auto& child: captured) {
			const auto child_relative =
			    relative == "/" ? "/" + child.name : relative + "/" + child.name;
			const bool admitted =
			    std::any_of(mount.fallback_prefixes.begin(), mount.fallback_prefixes.end(),
				            [&](const auto& prefix) { return Matches(prefix, child_relative); });
			const bool shadowed = std::any_of(
			    output.begin(), output.begin() + primary_count,
			    [&](const auto& present) { return LowercaseEqual(present.name, child.name); });
			if (admitted && !shadowed) output.push_back(std::move(child));
		}
	}
	*entries = std::move(output);
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int64_t Pread(const std::shared_ptr<Handle>& handle, void* data, size_t length, uint64_t offset) {
	if (!handle) return KERNEL_ERROR_EBADF;
	if (handle->directory) return KERNEL_ERROR_EISDIR;
	if (length == 0) return 0;
	std::lock_guard lock(handle->mutex);
	if (handle->file == nullptr) return KERNEL_ERROR_EIO;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (_fseeki64(handle->file, static_cast<long long>(offset), SEEK_SET) != 0)
		return KERNEL_ERROR_EIO;
#else
	if (std::fseek(handle->file, static_cast<long>(offset), SEEK_SET) != 0) return KERNEL_ERROR_EIO;
#endif
	const auto actual = std::fread(data, 1, length, handle->file);
	if (actual == 0 && std::ferror(handle->file)) return KERNEL_ERROR_EIO;
	if (std::getenv("KYTY_DIAGNOSTIC_READ_ONLY_PROVIDER_IO_AUDIT") != nullptr) {
		LOGF("READ_ONLY_PROVIDER_IO operation=pread path=%s offset=%llu requested=%zu result=%zu\n",
		     Log::EscapeField(handle->normalized).c_str(), static_cast<unsigned long long>(offset),
		     length, actual);
	}
	return static_cast<int64_t>(actual);
}

int64_t Read(const std::shared_ptr<Handle>& handle, void* data, size_t length) {
	if (!handle) return KERNEL_ERROR_EBADF;
	if (handle->directory) return KERNEL_ERROR_EISDIR;
	const auto actual = Pread(handle, data, length, handle->offset);
	if (actual > 0) handle->offset += static_cast<uint64_t>(actual);
	return actual;
}

int64_t Seek(const std::shared_ptr<Handle>& handle, int64_t offset, int whence) {
	if (!handle) return KERNEL_ERROR_EBADF;
	if (handle->directory) return KERNEL_ERROR_EISDIR;
	if (whence < 0 || whence > 2) return KERNEL_ERROR_EINVAL;
	std::lock_guard lock(handle->mutex);
	uint64_t        base = 0;
	if (whence == 1)
		base = handle->offset;
	else if (whence == 2) {
		std::error_code ec;
		base = std::filesystem::file_size(handle->host, ec);
		if (ec) return KERNEL_ERROR_EIO;
	}
	if (offset >= 0) {
		if (base > static_cast<uint64_t>(INT64_MAX) - static_cast<uint64_t>(offset))
			return KERNEL_ERROR_EOVERFLOW;
		handle->offset = base + static_cast<uint64_t>(offset);
	} else {
		const auto distance = uint64_t {0} - static_cast<uint64_t>(offset);
		if (distance > base) return KERNEL_ERROR_EINVAL;
		handle->offset = base - distance;
	}
	return static_cast<int64_t>(handle->offset);
}

// O_APPEND also governs pwrite, as in FreeBSD's ffs_write. Callers hold handle.mutex.
static int64_t WriteLocked(Handle& handle, const void* data, size_t length, uint64_t* offset) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	const int positioned = handle.append
	                           ? _fseeki64(handle.file, 0, SEEK_END)
	                           : _fseeki64(handle.file, static_cast<long long>(*offset), SEEK_SET);
	if (positioned != 0 || std::fwrite(data, 1, length, handle.file) != length ||
	    std::fflush(handle.file) != 0)
		return KERNEL_ERROR_EIO;
	const auto end = _ftelli64(handle.file);
	if (end < 0) return KERNEL_ERROR_EIO;
	*offset = static_cast<uint64_t>(end);
	return static_cast<int64_t>(length);
#else
	return KERNEL_ERROR_ENOSYS;
#endif
}

int64_t Write(const std::shared_ptr<Handle>& handle, const void* data, size_t length) {
	if (!handle || !handle->writable || handle->file == nullptr) return KERNEL_ERROR_EBADF;
	if (length == 0) return 0;
	std::lock_guard lock(handle->mutex);
	return WriteLocked(*handle, data, length, &handle->offset);
}

int64_t Pwrite(const std::shared_ptr<Handle>& handle, const void* data, size_t length,
               uint64_t offset) {
	if (!handle || !handle->writable || handle->file == nullptr) return KERNEL_ERROR_EBADF;
	if (length == 0) return 0;
	std::lock_guard lock(handle->mutex);
	return WriteLocked(*handle, data, length, &offset);
}

int Truncate(const std::shared_ptr<Handle>& handle, uint64_t length) {
	if (!handle) return KERNEL_ERROR_EBADF;
	if (handle->directory || !handle->writable || handle->file == nullptr ||
	    length > static_cast<uint64_t>(INT64_MAX))
		return KERNEL_ERROR_EINVAL;
	std::lock_guard lock(handle->mutex);
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (std::fflush(handle->file) != 0 ||
	    _chsize_s(_fileno(handle->file), static_cast<long long>(length)) != 0)
		return KERNEL_ERROR_EIO;
	return OK;
#else
	return KERNEL_ERROR_ENOSYS;
#endif
}

int Fsync(const std::shared_ptr<Handle>& handle) {
	if (!handle) return KERNEL_ERROR_EBADF;
	if (handle->directory || handle->file == nullptr) return KERNEL_ERROR_EBADF;
	std::lock_guard lock(handle->mutex);
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	const int descriptor = _fileno(handle->file);
	if (descriptor < 0) return KERNEL_ERROR_EIO;
	const intptr_t native = _get_osfhandle(descriptor);
	if (native == -1) return KERNEL_ERROR_EIO;
	if (handle->writable && std::fflush(handle->file) != 0) return KERNEL_ERROR_EIO;
	if (FlushFileBuffers(reinterpret_cast<HANDLE>(native)) != 0) return OK;
	return !handle->writable && GetLastError() == ERROR_ACCESS_DENIED ? OK : KERNEL_ERROR_EIO;
#else
	return KERNEL_ERROR_ENOSYS;
#endif
}

static void AuditUpper(const char* operation, const std::string& path, int result) {
	if (std::getenv("KYTY_DIAGNOSTIC_READ_ONLY_PROVIDER_IO_AUDIT") == nullptr) return;
	LOGF("PASSTHROUGH_UPPER_IO operation=%s path=%s result=0x%08x\n", operation,
	     Log::EscapeField(path).c_str(), static_cast<unsigned>(result));
}

int Mkdir(const std::string& path, uint32_t mode) try {
	std::lock_guard lock(mounts_mutex);
	std::string     normalized;
	const auto      mount = Normalize(path, &normalized) == OK ? FindMount(normalized) : nullptr;
	if (!mount || !mount->upper) return KERNEL_ERROR_EROFS;
	auto&      upper    = *mount->upper;
	const auto relative = Relative(*mount, normalized);
	const int  result   = [&] {
		UpperLock upper_lock(&upper);
		if (upper_lock.result != OK) return upper_lock.result;
		if (relative == "/") return KERNEL_ERROR_EEXIST;
		View      view;
		const int looked = Lookup(*mount, relative, &view);
		if (looked == OK) return KERNEL_ERROR_EEXIST;
		if (looked != KERNEL_ERROR_ENOENT) return looked;
		View      parent;
		const int found = Lookup(*mount, ParentOf(relative), &parent);
		if (found != OK) return found;
		if (parent.kind != 'd') return KERNEL_ERROR_ENOTDIR;
		NodeStat  parent_stat;
		const int stated = ViewStat(*mount, parent, &parent_stat);
		if (stated != OK) return stated;
		UpperNode node;
		node.kind         = 'd';
		node.mode         = 0040000u | (mode & 0777u);
		node.gid          = parent_stat.gid;
		node.mtime        = Now();
		node.inode        = FnvInode(mount->device, "upper/" + std::to_string(upper.serial++));
		const int touched = Touch(*mount, ParentOf(relative), node.mtime);
		if (touched != OK) {
			upper.loaded = UINT64_MAX;
			return touched;
		}
		upper.nodes[relative] = std::move(node);
		return SaveIndex(&upper);
	}();
	AuditUpper("mkdir", normalized, result);
	return result;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int Rmdir(const std::string& path) try {
	std::lock_guard lock(mounts_mutex);
	std::string     normalized;
	const auto      mount = Normalize(path, &normalized) == OK ? FindMount(normalized) : nullptr;
	if (!mount || !mount->upper) return KERNEL_ERROR_EROFS;
	auto&      upper    = *mount->upper;
	const auto relative = Relative(*mount, normalized);
	const int  result   = [&] {
		UpperLock upper_lock(&upper);
		if (upper_lock.result != OK) return upper_lock.result;
		if (relative == "/") return KERNEL_ERROR_EBUSY;
		View      view;
		const int looked = Lookup(*mount, relative, &view);
		if (looked != OK) return looked;
		if (view.kind != 'd') return KERNEL_ERROR_ENOTDIR;
		std::vector<DirectoryEntry> children;
		const int                   listed = MergedList(*mount, relative, view, &children);
		if (listed != OK) return listed;
		if (!children.empty()) return KERNEL_ERROR_ENOTEMPTY;
		const auto parent  = ParentOf(relative);
		const bool visible = LowerVisible(*mount, parent, Name(relative));
		const int  touched = Touch(*mount, parent, Now());
		if (touched != OK) {
			upper.loaded = UINT64_MAX;
			return touched;
		}
		EraseTree(&upper, relative);
		if (visible) upper.nodes[relative].kind = 'w';
		return SaveIndex(&upper);
	}();
	AuditUpper("rmdir", normalized, result);
	return result;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int Unlink(const std::string& path) try {
	std::lock_guard lock(mounts_mutex);
	std::string     normalized;
	const auto      mount = Normalize(path, &normalized) == OK ? FindMount(normalized) : nullptr;
	if (!mount || !mount->upper) return KERNEL_ERROR_EROFS;
	auto&      upper    = *mount->upper;
	const auto relative = Relative(*mount, normalized);
	const int  result   = [&] {
		UpperLock upper_lock(&upper);
		if (upper_lock.result != OK) return upper_lock.result;
		if (relative == "/") return KERNEL_ERROR_EPERM;
		View      view;
		const int looked = Lookup(*mount, relative, &view);
		if (looked != OK) return looked;
		if (view.kind == 'd') return KERNEL_ERROR_EPERM;
		const uint64_t object  = view.node ? view.node->object : 0;
		const auto     parent  = ParentOf(relative);
		const bool     visible = LowerVisible(*mount, parent, Name(relative));
		const int      touched = Touch(*mount, parent, Now());
		if (touched != OK) {
			upper.loaded = UINT64_MAX;
			return touched;
		}
		upper.nodes.erase(relative);
		if (visible) upper.nodes[relative].kind = 'w';
		const int saved = SaveIndex(&upper);
		// An object another descriptor still holds open stays behind, like an unlinked inode with a
		// live reference.
		if (saved == OK && object != 0) {
			std::error_code ec;
			std::filesystem::remove(ObjectPath(upper, object), ec);
		}
		return saved;
	}();
	AuditUpper("unlink", normalized, result);
	return result;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int Rename(const std::string& from, const std::string& to) try {
	std::lock_guard lock(mounts_mutex);
	std::string     source, target;
	const int       from_normalized = Normalize(from, &source);
	const int       to_normalized   = Normalize(to, &target);
	if (from_normalized != OK) return from_normalized;
	if (to_normalized != OK) return to_normalized;
	const auto mount = FindMount(source);
	if (!mount || FindMount(target) != mount) return KERNEL_ERROR_EXDEV;
	if (!mount->upper) return KERNEL_ERROR_EROFS;
	auto&      upper         = *mount->upper;
	const auto from_relative = Relative(*mount, source);
	const auto to_relative   = Relative(*mount, target);
	const int  result        = [&] {
		UpperLock upper_lock(&upper);
		if (upper_lock.result != OK) return upper_lock.result;
		if (from_relative == "/" || to_relative == "/") return KERNEL_ERROR_EBUSY;
		View      from_view;
		const int looked = Lookup(*mount, from_relative, &from_view);
		if (looked != OK) return looked;
		if (from_relative == to_relative) return OK;
		if (to_relative.starts_with(from_relative + "/")) return KERNEL_ERROR_EINVAL;
		const auto from_parent = ParentOf(from_relative);
		const auto to_parent   = ParentOf(to_relative);
		View       parent;
		const int  found = Lookup(*mount, to_parent, &parent);
		if (found != OK) return found;
		if (parent.kind != 'd') return KERNEL_ERROR_ENOTDIR;
		View      to_view;
		const int existing = Lookup(*mount, to_relative, &to_view);
		if (existing != OK && existing != KERNEL_ERROR_ENOENT) return existing;
		uint64_t replaced = 0;
		if (existing == OK) {
			if (from_view.kind == 'd' && to_view.kind != 'd') return KERNEL_ERROR_ENOTDIR;
			if (from_view.kind != 'd' && to_view.kind == 'd') return KERNEL_ERROR_EISDIR;
			if (to_view.kind == 'd') {
				std::vector<DirectoryEntry> children;
				const int listed = MergedList(*mount, to_relative, to_view, &children);
				if (listed != OK) return listed;
				if (!children.empty()) return KERNEL_ERROR_ENOTEMPTY;
			}
			if (to_view.node) replaced = to_view.node->object;
		}
		UpperNode moved;
		if (from_view.node) {
			moved = *from_view.node;
		} else {
			if (!from_view.entry || !from_view.entry->metadata) return KERNEL_ERROR_EIO;
			moved.kind   = from_view.kind;
			moved.mode   = from_view.entry->stat.mode;
			moved.uid    = from_view.entry->stat.uid;
			moved.gid    = from_view.entry->stat.gid;
			moved.mtime  = from_view.entry->stat.mtime;
			moved.inode  = from_view.entry->stat.inode;
			moved.origin = from_view.origin;
		}
		const bool visible = LowerVisible(*mount, from_parent, Name(from_relative));
		const auto now     = Now();
		int        touched = Touch(*mount, from_parent, now);
		if (touched == OK) touched = Touch(*mount, to_parent, now);
		if (touched != OK) {
			upper.loaded = UINT64_MAX;
			return touched;
		}
		std::vector<std::pair<std::string, UpperNode>> descendants;
		const auto                                     prefix = from_relative + "/";
		for (auto item = upper.nodes.lower_bound(prefix);
		     item != upper.nodes.end() && item->first.starts_with(prefix);) {
			descendants.emplace_back(to_relative + item->first.substr(from_relative.size()),
			                         std::move(item->second));
			item = upper.nodes.erase(item);
		}
		upper.nodes.erase(from_relative);
		EraseTree(&upper, to_relative);
		upper.nodes[to_relative] = std::move(moved);
		for (auto& [moved_path, node]: descendants)
			upper.nodes[moved_path] = std::move(node);
		if (visible) upper.nodes[from_relative].kind = 'w';
		const int saved = SaveIndex(&upper);
		if (saved == OK && replaced != 0) {
			std::error_code ec;
			std::filesystem::remove(ObjectPath(upper, replaced), ec);
		}
		return saved;
	}();
	AuditUpper("rename", source + " -> " + target, result);
	return result;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

} // namespace Libs::LibKernel::DirectoryPassthrough
