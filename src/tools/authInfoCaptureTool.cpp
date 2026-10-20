#include "kernel/authInfo.h"

#include "loader/elf.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <limits>
#include <map>
#include <optional>
#include <random>
#include <string>
#include <type_traits>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {
using namespace Libs::LibKernel::AuthInfo;

void SecureWipe(void* data, size_t size) noexcept {
	auto* bytes = static_cast<volatile uint8_t*>(data);
	while (bytes != nullptr && size-- != 0)
		*bytes++ = 0;
}

template <typename T>
class WipeOnExit final {
public:
	explicit WipeOnExit(T* value): m_value(value) {
		static_assert(std::is_trivially_copyable_v<T>);
	}
	~WipeOnExit() { SecureWipe(m_value, sizeof(T)); }
	WipeOnExit(const WipeOnExit&)            = delete;
	WipeOnExit& operator=(const WipeOnExit&) = delete;

private:
	T* m_value;
};

struct Snapshot {
	std::vector<uint8_t> bytes;
#if defined(_WIN32)
	HANDLE handle = INVALID_HANDLE_VALUE;
#else
	int handle = -1;
#endif
	Snapshot() = default;
	~Snapshot() {
		if (!bytes.empty()) SecureWipe(bytes.data(), bytes.size());
		Close();
	}
	Snapshot(const Snapshot&)            = delete;
	Snapshot& operator=(const Snapshot&) = delete;
	void      Close() {
#if defined(_WIN32)
		if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
		handle = INVALID_HANDLE_VALUE;
#else
		if (handle >= 0) close(handle);
		handle = -1;
#endif
	}
};

bool ReadSnapshot(const std::filesystem::path& path, std::optional<size_t> exact_size,
                  Snapshot* snapshot) {
	if (snapshot == nullptr || path.empty()) return false;
#if defined(_WIN32)
	snapshot->handle = CreateFileW(
	    path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
	    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
	if (snapshot->handle == INVALID_HANDLE_VALUE) return false;
	FILE_ATTRIBUTE_TAG_INFO attributes {};
	if (!GetFileInformationByHandleEx(snapshot->handle, FileAttributeTagInfo, &attributes,
	                                  sizeof(attributes)) ||
	    (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
	        0) {
		return false;
	}
	LARGE_INTEGER length {};
	if (!GetFileSizeEx(snapshot->handle, &length) || length.QuadPart < 0 ||
	    static_cast<uint64_t>(length.QuadPart) > std::numeric_limits<size_t>::max()) {
		return false;
	}
	const auto size = static_cast<size_t>(length.QuadPart);
	if (exact_size.has_value() && size != *exact_size) return false;
	try {
		snapshot->bytes.resize(size);
	} catch (...) {
		return false;
	}
	size_t offset = 0;
	while (offset != size) {
		const auto  remaining = size - offset;
		const DWORD requested =
		    static_cast<DWORD>(std::min<size_t>(remaining, std::numeric_limits<DWORD>::max()));
		DWORD count = 0;
		if (!ReadFile(snapshot->handle, snapshot->bytes.data() + offset, requested, &count,
		              nullptr) ||
		    count != requested) {
			return false;
		}
		offset += count;
	}
	LARGE_INTEGER retained_length {};
	return GetFileSizeEx(snapshot->handle, &retained_length) &&
	       retained_length.QuadPart == length.QuadPart;
#else
	snapshot->handle = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (snapshot->handle < 0) return false;
	struct stat info {};
	if (fstat(snapshot->handle, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 0 ||
	    static_cast<uint64_t>(info.st_size) > std::numeric_limits<size_t>::max()) {
		return false;
	}
	const auto size = static_cast<size_t>(info.st_size);
	if (exact_size.has_value() && size != *exact_size) return false;
	try {
		snapshot->bytes.resize(size);
	} catch (...) {
		return false;
	}
	size_t offset = 0;
	while (offset != size) {
		const auto count = read(snapshot->handle, snapshot->bytes.data() + offset, size - offset);
		if (count <= 0) return false;
		offset += static_cast<size_t>(count);
	}
	struct stat retained_info {};
	return fstat(snapshot->handle, &retained_info) == 0 && retained_info.st_size == info.st_size;
#endif
}

#if defined(_WIN32)
std::wstring TemporaryName(const std::filesystem::path& output) {
	std::array<uint8_t, 16> random {};
	if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()),
	                    BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
		return {};
	}
	constexpr wchar_t digits[] = L"0123456789abcdef";
	std::wstring      suffix   = L".tmp.";
	for (const auto byte: random) {
		suffix.push_back(digits[byte >> 4]);
		suffix.push_back(digits[byte & 15]);
	}
	return output.filename().wstring() + suffix;
}
#else
std::string TemporaryName(const std::filesystem::path& output) {
	std::random_device random_device;
	constexpr char     digits[] = "0123456789abcdef";
	std::string        suffix   = ".tmp.";
	for (size_t i = 0; i != 16; ++i) {
		const auto byte = static_cast<uint8_t>(random_device());
		suffix.push_back(digits[byte >> 4]);
		suffix.push_back(digits[byte & 15]);
	}
	return output.filename().string() + suffix;
}
#endif

bool ParentIsDirectDirectory(const std::filesystem::path& output, std::filesystem::path* parent) {
	if (output.empty() || output.filename().empty() || parent == nullptr) return false;
	*parent = output.parent_path();
	if (parent->empty()) *parent = std::filesystem::current_path();
#if defined(_WIN32)
	HANDLE handle =
	    CreateFileW(parent->c_str(), FILE_READ_ATTRIBUTES,
		            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
		            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
	if (handle == INVALID_HANDLE_VALUE) return false;
	FILE_ATTRIBUTE_TAG_INFO attributes {};
	const bool result = GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes,
	                                                 sizeof(attributes)) &&
	                    (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
	                    (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
	CloseHandle(handle);
	return result;
#else
	std::error_code error;
	const auto      status = std::filesystem::symlink_status(*parent, error);
	return !error && status.type() == std::filesystem::file_type::directory;
#endif
}

bool OutputDoesNotExist(const std::filesystem::path& output) {
#if defined(_WIN32)
	const DWORD attributes = GetFileAttributesW(output.c_str());
	if (attributes != INVALID_FILE_ATTRIBUTES) return false;
	const DWORD error = GetLastError();
	return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
#else
	struct stat info {};
	if (lstat(output.c_str(), &info) == 0) return false;
	return errno == ENOENT;
#endif
}

bool Publish(const std::filesystem::path& output, const uint8_t* data, size_t size) {
	std::filesystem::path parent;
	if (!ParentIsDirectDirectory(output, &parent) || !OutputDoesNotExist(output)) return false;
#if defined(_WIN32)
	PSECURITY_DESCRIPTOR security_descriptor = nullptr;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;OW)", SDDL_REVISION_1,
	                                                          &security_descriptor, nullptr)) {
		return false;
	}
	SECURITY_ATTRIBUTES security_attributes {};
	security_attributes.nLength              = sizeof(security_attributes);
	security_attributes.lpSecurityDescriptor = security_descriptor;
	security_attributes.bInheritHandle       = FALSE;
	const auto temporary_name                = TemporaryName(output);
	if (temporary_name.empty()) {
		LocalFree(security_descriptor);
		return false;
	}
	const auto temporary = parent / temporary_name;
	HANDLE     file = CreateFileW(temporary.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
	                              &security_attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
	LocalFree(security_descriptor);
	if (file == INVALID_HANDLE_VALUE) return false;
	bool   result = true;
	size_t offset = 0;
	while (result && offset != size) {
		const auto  remaining = size - offset;
		const DWORD requested =
		    static_cast<DWORD>(std::min<size_t>(remaining, std::numeric_limits<DWORD>::max()));
		DWORD count = 0;
		result = WriteFile(file, data + offset, requested, &count, nullptr) && count == requested;
		offset += count;
	}
	if (result) result = FlushFileBuffers(file) != FALSE;
	LARGE_INTEGER beginning {};
	if (result) result = SetFilePointerEx(file, beginning, nullptr, FILE_BEGIN) != FALSE;
	std::array<uint8_t, 4096> verify_buffer {};
	WipeOnExit                wipe_verify_buffer(&verify_buffer);
	offset = 0;
	while (result && offset != size) {
		const DWORD requested =
		    static_cast<DWORD>(std::min<size_t>(verify_buffer.size(), size - offset));
		DWORD count = 0;
		result = ReadFile(file, verify_buffer.data(), requested, &count, nullptr) &&
		         count == requested && std::memcmp(verify_buffer.data(), data + offset, count) == 0;
		offset += count;
	}
	CloseHandle(file);
	if (result)
		result = MoveFileExW(temporary.c_str(), output.c_str(), MOVEFILE_WRITE_THROUGH) != FALSE;
	if (!result) DeleteFileW(temporary.c_str());
	return result;
#else
	std::filesystem::path temporary;
	int                   file = -1;
	for (uint32_t attempt = 0; attempt != 16 && file < 0; ++attempt) {
		temporary = parent / TemporaryName(output);
		file      = open(temporary.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
		if (file < 0 && errno != EEXIST) return false;
	}
	if (file < 0) return false;
	bool   result = true;
	size_t offset = 0;
	while (result && offset != size) {
		const auto count = write(file, data + offset, size - offset);
		if (count <= 0) {
			result = false;
		} else {
			offset += static_cast<size_t>(count);
		}
	}
	if (result) result = fsync(file) == 0;
	if (result) result = lseek(file, 0, SEEK_SET) == 0;
	std::array<uint8_t, 4096> verify_buffer {};
	WipeOnExit                wipe_verify_buffer(&verify_buffer);
	offset = 0;
	while (result && offset != size) {
		const auto requested = std::min(verify_buffer.size(), size - offset);
		const auto count     = read(file, verify_buffer.data(), requested);
		result               = count == static_cast<decltype(count)>(requested) &&
		                       std::memcmp(verify_buffer.data(), data + offset, requested) == 0;
		if (result) offset += requested;
	}
	close(file);
	if (result) result = link(temporary.c_str(), output.c_str()) == 0;
	unlink(temporary.c_str());
	return result;
#endif
}

bool SameCapture(const Capture& left, const Capture& right) {
	return left.version == right.version && left.authority_id == right.authority_id &&
	       left.self_sha256 == right.self_sha256 && left.elf_sha256 == right.elf_sha256 &&
	       left.record_sha256 == right.record_sha256 &&
	       left.envelope_sha256 == right.envelope_sha256 && left.record == right.record &&
	       left.envelope == right.envelope;
}

void PrintSuccess(const char* status, const Capture& capture) {
	std::printf("status=%s\n", status);
	std::printf("authority_id=0x%016" PRIx64 "\n", capture.authority_id);
	std::printf("self_sha256=%s\n", DigestHex(capture.self_sha256).c_str());
	std::printf("elf_sha256=%s\n", DigestHex(capture.elf_sha256).c_str());
	std::printf("envelope_sha256=%s\n", DigestHex(capture.envelope_sha256).c_str());
	std::printf("hardware_provenance_authenticated=false\n");
}

int Reject(int result) {
	std::fprintf(stderr, "status=rejected\n");
	std::fprintf(stderr, "hardware_provenance_authenticated=false\n");
	return result;
}

template <size_t N>
bool ParseOptions(int argc, char** argv, const std::array<const char*, N>& expected,
                  std::map<std::string, std::filesystem::path>* options) {
	if (argc != static_cast<int>(2 + N * 2) || options == nullptr) return false;
	for (int i = 2; i < argc; i += 2) {
		const std::string key = argv[i];
		if (argv[i + 1][0] == 0 || options->contains(key)) return false;
		if (std::find_if(expected.begin(), expected.end(),
		                 [&](const char* item) { return key == item; }) == expected.end()) {
			return false;
		}
		options->emplace(key, std::filesystem::u8path(argv[i + 1]));
	}
	return options->size() == expected.size();
}

int Inspect(int argc, char** argv) {
	std::map<std::string, std::filesystem::path> options;
	if (!ParseOptions(argc, argv, std::array<const char*, 2> {"--self", "--elf"}, &options))
		return Reject(2);
	Snapshot self_snapshot;
	Snapshot elf_snapshot;
	if (!ReadSnapshot(options.at("--self"), std::nullopt, &self_snapshot) ||
	    !ReadSnapshot(options.at("--elf"), std::nullopt, &elf_snapshot)) {
		return Reject(1);
	}
	ImageIdentity identity;
	std::string   reason;
	if (!ValidateImageIdentity(self_snapshot.bytes.data(), self_snapshot.bytes.size(),
	                           elf_snapshot.bytes.data(), elf_snapshot.bytes.size(), &identity,
	                           &reason)) {
		return Reject(1);
	}
	Loader::SelfHeader header {};
	std::memcpy(&header, self_snapshot.bytes.data(), sizeof(header));
	const uint64_t elf_offset =
	    sizeof(header) + uint64_t {header.segments_num} * sizeof(Loader::SelfSegment);
	Loader::Elf64_Ehdr embedded {};
	std::memcpy(&embedded, self_snapshot.bytes.data() + elf_offset, sizeof(embedded));
	const uint64_t authority_offset =
	    (elf_offset + embedded.e_phoff + uint64_t {embedded.e_phnum} * sizeof(Loader::Elf64_Phdr) +
		 15) &
	    ~uint64_t {15};
	uint32_t encrypted_segments = 0;
	uint32_t signed_segments    = 0;
	for (uint16_t i = 0; i != header.segments_num; ++i) {
		Loader::SelfSegment segment {};
		std::memcpy(&segment,
		            self_snapshot.bytes.data() + sizeof(header) + uint64_t {i} * sizeof(segment),
		            sizeof(segment));
		if ((segment.type & 2) != 0) ++encrypted_segments;
		if ((segment.type & 4) != 0) ++signed_segments;
	}
	const uint64_t metadata_offset      = header.size1;
	const uint64_t payload_offset       = uint64_t {header.size1} + header.size2;
	const auto     public_header_sha256 = Sha256(self_snapshot.bytes.data(), header.size1);
	const auto metadata_sha256 = Sha256(self_snapshot.bytes.data() + metadata_offset, header.size2);
	std::printf("status=image_identity_consistent\n");
	std::printf("authority_id=0x%016" PRIx64 "\n", identity.authority_id);
	std::printf("self_sha256=%s\n", DigestHex(identity.self_sha256).c_str());
	std::printf("elf_sha256=%s\n", DigestHex(identity.elf_sha256).c_str());
	std::printf("self_header_size=0x%04x\n", static_cast<unsigned>(header.size1));
	std::printf("self_metadata_size=0x%04x\n", static_cast<unsigned>(header.size2));
	std::printf("self_payload_offset=0x%" PRIx64 "\n", payload_offset);
	std::printf("elf_header_offset=0x%" PRIx64 "\n", elf_offset);
	std::printf("public_authority_offset=0x%" PRIx64 "\n", authority_offset);
	std::printf("segment_count=%u\n", static_cast<unsigned>(header.segments_num));
	std::printf("encrypted_segment_count=%u\n", encrypted_segments);
	std::printf("signed_segment_count=%u\n", signed_segments);
	std::printf("public_header_sha256=%s\n", DigestHex(public_header_sha256).c_str());
	std::printf("metadata_sha256=%s\n", DigestHex(metadata_sha256).c_str());
	std::printf("authority_public_bytes=8\n");
	std::printf("authinfo_record_source=external_integrity_pinned_capture_required\n");
	std::printf("hardware_provenance_authenticated=false\n");
	return 0;
}

int Pack(int argc, char** argv) {
	std::map<std::string, std::filesystem::path> options;
	if (!ParseOptions(argc, argv,
	                  std::array<const char*, 4> {"--record", "--self", "--elf", "--out"},
	                  &options))
		return Reject(2);
	Snapshot record_snapshot;
	Snapshot self_snapshot;
	Snapshot elf_snapshot;
	if (!ReadSnapshot(options.at("--record"), kSize, &record_snapshot) ||
	    !ReadSnapshot(options.at("--self"), std::nullopt, &self_snapshot) ||
	    !ReadSnapshot(options.at("--elf"), std::nullopt, &elf_snapshot)) {
		return Reject(1);
	}
	ImageIdentity identity;
	std::string   reason;
	if (!ValidateImageIdentity(self_snapshot.bytes.data(), self_snapshot.bytes.size(),
	                           elf_snapshot.bytes.data(), elf_snapshot.bytes.size(), &identity,
	                           &reason)) {
		return Reject(1);
	}
	Record     record {};
	WipeOnExit wipe_record(&record);
	std::memcpy(record.data(), record_snapshot.bytes.data(), record.size());
	Capture capture {};
	if (!BuildCaptureEnvelope(record, identity, &capture, &reason)) return Reject(1);
	const auto& output = options.at("--out");
	if (!Publish(output, capture.envelope.data(), capture.envelope.size())) return Reject(1);
	Snapshot published;
	Capture  verified {};
	if (!ReadSnapshot(output, kCaptureEnvelopeSize, &published) ||
	    !ParseCaptureEnvelope(published.bytes.data(), published.bytes.size(),
	                          capture.envelope_sha256, identity.self_sha256, identity.elf_sha256,
	                          identity.authority_id, &verified, &reason) ||
	    !SameCapture(capture, verified)) {
		published.Close();
		std::error_code error;
		std::filesystem::remove(output, error);
		return Reject(1);
	}
	PrintSuccess("integrity_bound", verified);
	return 0;
}

int Verify(int argc, char** argv) {
	std::map<std::string, std::filesystem::path> options;
	if (!ParseOptions(argc, argv,
	                  std::array<const char*, 4> {"--capture", "--self", "--elf", "--sha256"},
	                  &options))
		return Reject(2);
	const auto pin_text = options.at("--sha256").string();
	Digest     pin {};
	if (!ParseDigestHex(pin_text, &pin)) {
		return Reject(2);
	}
	Snapshot capture_snapshot;
	Snapshot self_snapshot;
	Snapshot elf_snapshot;
	if (!ReadSnapshot(options.at("--capture"), kCaptureEnvelopeSize, &capture_snapshot) ||
	    !ReadSnapshot(options.at("--self"), std::nullopt, &self_snapshot) ||
	    !ReadSnapshot(options.at("--elf"), std::nullopt, &elf_snapshot)) {
		return Reject(1);
	}
	ImageIdentity identity;
	std::string   reason;
	if (!ValidateImageIdentity(self_snapshot.bytes.data(), self_snapshot.bytes.size(),
	                           elf_snapshot.bytes.data(), elf_snapshot.bytes.size(), &identity,
	                           &reason)) {
		return Reject(1);
	}
	Capture capture {};
	if (!ParseCaptureEnvelope(capture_snapshot.bytes.data(), capture_snapshot.bytes.size(), pin,
	                          identity.self_sha256, identity.elf_sha256, identity.authority_id,
	                          &capture, &reason)) {
		return Reject(1);
	}
	PrintSuccess("integrity_verified", capture);
	return 0;
}
} // namespace

int main(int argc, char** argv) {
	try {
		if (argc < 2) return Reject(2);
		if (std::strcmp(argv[1], "inspect") == 0) return Inspect(argc, argv);
		if (std::strcmp(argv[1], "pack") == 0) return Pack(argc, argv);
		if (std::strcmp(argv[1], "verify") == 0) return Verify(argc, argv);
		return Reject(2);
	} catch (...) {
		return Reject(1);
	}
}
