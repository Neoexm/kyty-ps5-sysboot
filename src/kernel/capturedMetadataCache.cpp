#include "kernel/capturedMetadataCache.h"

#include "common/file.h"
#include "common/stringUtils.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <limits>
#include <system_error>

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#include <windows.h>
#ifdef DeleteFile
#undef DeleteFile
#endif
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace Libs::LibKernel::CapturedMetadataCache {
namespace {

constexpr std::array<uint8_t, 8> Magic {'K', 'Y', 'T', 'Y', 'I', 'M', 'C', '1'};
constexpr uint32_t               FormatVersion = 1;
constexpr uint64_t               HeaderSize    = Magic.size() + 4 + 8 + AuthInfo::kDigestSize * 2;
std::atomic<uint64_t>            temporary_sequence {0};

bool Hex64(std::string_view value) {
	return value.size() == AuthInfo::kDigestSize * 2 &&
	       std::ranges::all_of(value, [](unsigned char ch) { return std::isxdigit(ch) != 0; });
}

bool KindValid(std::string_view value) {
	return !value.empty() && value.size() <= 32 && std::ranges::all_of(value, [](unsigned char ch) {
		return std::islower(ch) != 0 || std::isdigit(ch) != 0 || ch == '_';
	});
}

void AppendU32(std::vector<uint8_t>* bytes, uint32_t value) {
	for (size_t n = 0; n < 4; ++n)
		bytes->push_back(static_cast<uint8_t>(value >> (n * 8)));
}

void AppendU64(std::vector<uint8_t>* bytes, uint64_t value) {
	for (size_t n = 0; n < 8; ++n)
		bytes->push_back(static_cast<uint8_t>(value >> (n * 8)));
}

bool ReadSourceStamp(const std::filesystem::path& path, SourceStamp* source) {
	if (source == nullptr) return false;
	std::error_code error;
	const auto      status = std::filesystem::status(path, error);
	if (error || !std::filesystem::is_regular_file(status)) return false;
	source->path = path;
	source->size = std::filesystem::file_size(path, error);
	if (error) return false;
	const auto write = std::filesystem::last_write_time(path, error);
	if (error) return false;
	source->write_time = static_cast<int64_t>(write.time_since_epoch().count());
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	const auto handle = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
	                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
	                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (handle == INVALID_HANDLE_VALUE) return false;
	BY_HANDLE_FILE_INFORMATION identity {};
	FILE_BASIC_INFO            basic {};
	const bool                 valid =
	    GetFileInformationByHandle(handle, &identity) != 0 &&
	    GetFileInformationByHandleEx(handle, FileBasicInfo, &basic, sizeof(basic)) != 0;
	CloseHandle(handle);
	if (!valid) return false;
	source->change_time = basic.ChangeTime.QuadPart;
	source->volume_id   = identity.dwVolumeSerialNumber;
	source->file_id =
	    (static_cast<uint64_t>(identity.nFileIndexHigh) << 32u) | identity.nFileIndexLow;
#else
	struct stat info {};
	if (stat(path.c_str(), &info) != 0) return false;
#if defined(__APPLE__)
	source->change_time =
	    static_cast<int64_t>(info.st_ctimespec.tv_sec) * 1000000000ll + info.st_ctimespec.tv_nsec;
#else
	source->change_time =
	    static_cast<int64_t>(info.st_ctim.tv_sec) * 1000000000ll + info.st_ctim.tv_nsec;
#endif
	source->volume_id = static_cast<uint64_t>(info.st_dev);
	source->file_id   = static_cast<uint64_t>(info.st_ino);
#endif
	return true;
}

bool SourceStillMatches(const SourceStamp& source) {
	SourceStamp current;
	return ReadSourceStamp(source.path, &current) && current.size == source.size &&
	       current.write_time == source.write_time && current.change_time == source.change_time &&
	       current.volume_id == source.volume_id && current.file_id == source.file_id;
}

std::filesystem::path TemporaryPath(const std::filesystem::path& file) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	const auto process = static_cast<uint64_t>(GetCurrentProcessId());
#else
	const auto process = static_cast<uint64_t>(getpid());
#endif
	auto path = file;
	path += ".tmp." + std::to_string(process) + "." + std::to_string(++temporary_sequence);
	return path;
}

bool Replace(const std::filesystem::path& from, const std::filesystem::path& to) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	return MoveFileExW(from.c_str(), to.c_str(),
	                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
	std::error_code error;
	std::filesystem::rename(from, to, error);
	return !error;
#endif
}

} // namespace

Key Prepare(std::string kind, std::string discriminator,
            std::span<const std::filesystem::path> sources, uint64_t payload_limit) try {
	Key key;
	key.kind                = std::move(kind);
	key.discriminator       = std::move(discriminator);
	key.payload_limit       = payload_limit;
	const char* root_value  = std::getenv("KYTY_PS5_STARTUP_CACHE_DIR");
	const char* build_value = std::getenv("KYTY_PS5_STARTUP_CACHE_BUILD_ID");
	if (root_value == nullptr || build_value == nullptr || !KindValid(key.kind) ||
	    !Hex64(build_value) || payload_limit == 0 || payload_limit > UINT32_MAX)
		return key;
	const auto root = Common::PathFromUtf8(root_value);
	if (!root.is_absolute()) return key;
	key.build_id         = build_value;
	std::string material = "KytyImmutableMetadata1\nkind=" + key.kind + "\nbuild=" + key.build_id +
	                       "\ndiscriminator=" + key.discriminator + "\n";
	for (const auto& source_path: sources) {
		std::error_code error;
		auto            path = std::filesystem::absolute(source_path, error).lexically_normal();
		if (error) return key;
		SourceStamp source;
		if (!ReadSourceStamp(path, &source)) return key;
		material += "source=" + Common::PathToGenericString(source.path) + ":" +
		            std::to_string(source.size) + ":" + std::to_string(source.write_time) + "\n";
		material += "identity=" + std::to_string(source.volume_id) + ":" +
		            std::to_string(source.file_id) + ":" + std::to_string(source.change_time) +
		            "\n";
		key.sources.push_back(std::move(source));
	}
	key.digest  = AuthInfo::Sha256(material.data(), material.size());
	key.file    = root / key.build_id.substr(0, 16) /
	              (key.kind + "-" + AuthInfo::DigestHex(key.digest) + ".bin");
	key.enabled = true;
	return key;
} catch (const std::filesystem::filesystem_error&) {
	return {};
} catch (const std::bad_alloc&) {
	return {};
}

ReadResult Read(const Key& key, std::vector<uint8_t>* payload) try {
	if (!key.enabled || payload == nullptr) return ReadResult::Disabled;
	for (const auto& source: key.sources)
		if (!SourceStillMatches(source)) return ReadResult::Miss;
	Common::File file(key.file, Common::File::Mode::Read);
	if (file.IsInvalid()) return ReadResult::Miss;
	const auto size = file.Size();
	if (size < HeaderSize || size - HeaderSize > key.payload_limit || size > UINT32_MAX)
		return ReadResult::Miss;
	std::vector<uint8_t> bytes(static_cast<size_t>(size));
	uint32_t             read = 0;
	file.Read(bytes.data(), static_cast<uint32_t>(bytes.size()), &read);
	file.Close();
	if (read != bytes.size() || !std::equal(Magic.begin(), Magic.end(), bytes.begin()))
		return ReadResult::Miss;
	Reader   header(std::span<const uint8_t>(bytes).subspan(Magic.size()));
	uint32_t version      = 0;
	uint64_t payload_size = 0;
	if (!header.U32(&version) || !header.U64(&payload_size) || version != FormatVersion ||
	    payload_size != size - HeaderSize)
		return ReadResult::Miss;
	AuthInfo::Digest key_digest {};
	AuthInfo::Digest payload_digest {};
	for (auto& byte: key_digest)
		if (!header.U8(&byte)) return ReadResult::Miss;
	for (auto& byte: payload_digest)
		if (!header.U8(&byte)) return ReadResult::Miss;
	if (key_digest != key.digest) return ReadResult::Miss;
	auto body = std::span<const uint8_t>(bytes).subspan(HeaderSize);
	if (AuthInfo::Sha256(body.data(), body.size()) != payload_digest) return ReadResult::Miss;
	payload->assign(body.begin(), body.end());
	return ReadResult::Hit;
} catch (const std::bad_alloc&) {
	return ReadResult::Miss;
}

bool Write(const Key& key, std::span<const uint8_t> payload) try {
	if (!key.enabled || payload.empty() || payload.size() > key.payload_limit ||
	    payload.size() > UINT32_MAX)
		return false;
	for (const auto& source: key.sources)
		if (!SourceStillMatches(source)) return false;
	if (!Common::File::CreateDirectories(key.file.parent_path())) return false;
	std::vector<uint8_t> header;
	header.insert(header.end(), Magic.begin(), Magic.end());
	AppendU32(&header, FormatVersion);
	AppendU64(&header, payload.size());
	header.insert(header.end(), key.digest.begin(), key.digest.end());
	const auto payload_digest = AuthInfo::Sha256(payload.data(), payload.size());
	header.insert(header.end(), payload_digest.begin(), payload_digest.end());
	const auto   temporary = TemporaryPath(key.file);
	Common::File file;
	uint32_t     header_written  = 0;
	uint32_t     payload_written = 0;
	if (file.Create(temporary)) {
		file.Write(header.data(), static_cast<uint32_t>(header.size()), &header_written);
		file.Write(payload.data(), static_cast<uint32_t>(payload.size()), &payload_written);
	}
	const bool flushed = !file.IsInvalid() && file.Flush();
	file.Close();
	if (header_written != header.size() || payload_written != payload.size() || !flushed ||
	    !Replace(temporary, key.file)) {
		Common::File::DeleteFile(temporary);
		return false;
	}
	return true;
} catch (const std::bad_alloc&) {
	return false;
}

void Writer::U8(uint8_t value) {
	bytes.push_back(value);
}

void Writer::U32(uint32_t value) {
	AppendU32(&bytes, value);
}

void Writer::U64(uint64_t value) {
	AppendU64(&bytes, value);
}

void Writer::I64(int64_t value) {
	U64(static_cast<uint64_t>(value));
}

void Writer::String(std::string_view value) {
	if (value.size() > UINT32_MAX) return;
	U32(static_cast<uint32_t>(value.size()));
	bytes.insert(bytes.end(), value.begin(), value.end());
}

void Writer::Path(const std::filesystem::path& value) {
	String(Common::PathToString(value));
}

bool Reader::U8(uint8_t* value) {
	if (value == nullptr || offset == bytes.size()) return false;
	*value = bytes[offset++];
	return true;
}

bool Reader::U32(uint32_t* value) {
	if (value == nullptr || offset > bytes.size() || bytes.size() - offset < 4) return false;
	*value = 0;
	for (size_t n = 0; n < 4; ++n)
		*value |= static_cast<uint32_t>(bytes[offset++]) << (n * 8);
	return true;
}

bool Reader::U64(uint64_t* value) {
	if (value == nullptr || offset > bytes.size() || bytes.size() - offset < 8) return false;
	*value = 0;
	for (size_t n = 0; n < 8; ++n)
		*value |= static_cast<uint64_t>(bytes[offset++]) << (n * 8);
	return true;
}

bool Reader::I64(int64_t* value) {
	uint64_t encoded = 0;
	if (value == nullptr || !U64(&encoded)) return false;
	*value = static_cast<int64_t>(encoded);
	return true;
}

bool Reader::String(std::string* value, uint32_t limit) {
	uint32_t size = 0;
	if (value == nullptr || !U32(&size) || size > limit || offset > bytes.size() ||
	    bytes.size() - offset < size)
		return false;
	value->assign(reinterpret_cast<const char*>(bytes.data() + offset), size);
	offset += size;
	return true;
}

bool Reader::Path(std::filesystem::path* value, uint32_t limit) {
	std::string encoded;
	if (value == nullptr || !String(&encoded, limit) || encoded.find('\0') != encoded.npos)
		return false;
	*value = Common::PathFromUtf8(encoded);
	return true;
}

} // namespace Libs::LibKernel::CapturedMetadataCache
