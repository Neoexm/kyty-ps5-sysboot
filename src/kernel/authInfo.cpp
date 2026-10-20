#include "kernel/authInfo.h"

#include "loader/elf.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <limits>
#include <type_traits>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace Libs::LibKernel::AuthInfo {
namespace {
constexpr std::array<uint8_t, 8> kCaptureMagic {'K', 'y', 't', 'y', 'A', 'I', '0', '2'};
constexpr std::array<uint8_t, 8> kScopedMagic {'K', 'y', 't', 'y', 'A', 'P', '0', '2'};
constexpr std::array<uint8_t, 8> kScopedObservationMagic {'K', 'y', 't', 'y', 'A', 'S', '0', '1'};
constexpr uint32_t               kCaptureHeaderSize           = 0x80;
constexpr uint32_t               kScopedHeaderSize            = 0x48;
constexpr uint32_t               kScopedObservationHeaderSize = 0x50;

constexpr std::array<uint32_t, 64> kSha256Constants {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

struct Sha256State {
	std::array<uint32_t, 8> state {
	    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	};
	std::array<uint8_t, 64> block {};
	uint64_t                bytes = 0;
	size_t                  used  = 0;
};

void SecureWipe(void* data, size_t size) noexcept {
	auto* bytes = static_cast<volatile unsigned char*>(data);
	while (size != 0) {
		*bytes++ = 0;
		--size;
	}
}

template <typename T>
class WipeObjectOnExit final {
public:
	explicit WipeObjectOnExit(T* value): m_value(value) {
		static_assert(std::is_trivially_copyable_v<T>);
	}
	~WipeObjectOnExit() { SecureWipe(m_value, sizeof(T)); }

	WipeObjectOnExit(const WipeObjectOnExit&)            = delete;
	WipeObjectOnExit& operator=(const WipeObjectOnExit&) = delete;

private:
	T* m_value;
};

template <typename Buffer>
class WipeBufferOnExit final {
public:
	explicit WipeBufferOnExit(Buffer* buffer): m_buffer(buffer) {}
	~WipeBufferOnExit() {
		using Value = typename Buffer::value_type;
		static_assert(std::is_trivially_copyable_v<Value>);
		if (!m_buffer->empty()) SecureWipe(m_buffer->data(), m_buffer->size() * sizeof(Value));
	}

	WipeBufferOnExit(const WipeBufferOnExit&)            = delete;
	WipeBufferOnExit& operator=(const WipeBufferOnExit&) = delete;

private:
	Buffer* m_buffer;
};

uint32_t RotateRight(uint32_t value, uint32_t count) {
	return (value >> count) | (value << (32 - count));
}

uint32_t Load32Big(const uint8_t* data) {
	return (uint32_t {data[0]} << 24) | (uint32_t {data[1]} << 16) | (uint32_t {data[2]} << 8) |
	       uint32_t {data[3]};
}

uint32_t Load32Little(const uint8_t* data) {
	return uint32_t {data[0]} | (uint32_t {data[1]} << 8) | (uint32_t {data[2]} << 16) |
	       (uint32_t {data[3]} << 24);
}

uint64_t Load64Little(const uint8_t* data) {
	uint64_t value = 0;
	for (uint32_t i = 0; i != 8; ++i)
		value |= uint64_t {data[i]} << (i * 8);
	return value;
}

void Store32Little(uint8_t* data, uint32_t value) {
	for (uint32_t i = 0; i != 4; ++i)
		data[i] = static_cast<uint8_t>(value >> (i * 8));
}

void Store64Little(uint8_t* data, uint64_t value) {
	for (uint32_t i = 0; i != 8; ++i)
		data[i] = static_cast<uint8_t>(value >> (i * 8));
}

void Transform(Sha256State* state, const uint8_t* block) {
	std::array<uint32_t, 64> words {};
	WipeObjectOnExit         wipe_words(&words);
	for (uint32_t i = 0; i != 16; ++i)
		words[i] = Load32Big(block + i * 4);
	for (uint32_t i = 16; i != 64; ++i) {
		const uint32_t s0 =
		    RotateRight(words[i - 15], 7) ^ RotateRight(words[i - 15], 18) ^ (words[i - 15] >> 3);
		const uint32_t s1 =
		    RotateRight(words[i - 2], 17) ^ RotateRight(words[i - 2], 19) ^ (words[i - 2] >> 10);
		words[i] = words[i - 16] + s0 + words[i - 7] + s1;
	}
	auto a = state->state[0];
	auto b = state->state[1];
	auto c = state->state[2];
	auto d = state->state[3];
	auto e = state->state[4];
	auto f = state->state[5];
	auto g = state->state[6];
	auto h = state->state[7];
	for (uint32_t i = 0; i != 64; ++i) {
		const uint32_t s1       = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
		const uint32_t choice   = (e & f) ^ (~e & g);
		const uint32_t first    = h + s1 + choice + kSha256Constants[i] + words[i];
		const uint32_t s0       = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
		const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
		const uint32_t second   = s0 + majority;
		h                       = g;
		g                       = f;
		f                       = e;
		e                       = d + first;
		d                       = c;
		c                       = b;
		b                       = a;
		a                       = first + second;
	}
	state->state[0] += a;
	state->state[1] += b;
	state->state[2] += c;
	state->state[3] += d;
	state->state[4] += e;
	state->state[5] += f;
	state->state[6] += g;
	state->state[7] += h;
}

void Update(Sha256State* state, const uint8_t* data, size_t size) {
	state->bytes += size;
	while (size != 0) {
		const size_t count = std::min(size, state->block.size() - state->used);
		std::memcpy(state->block.data() + state->used, data, count);
		state->used += count;
		data += count;
		size -= count;
		if (state->used == state->block.size()) {
			Transform(state, state->block.data());
			state->used = 0;
		}
	}
}

Digest Finish(Sha256State* state) {
	const uint64_t bits         = state->bytes * 8;
	state->block[state->used++] = 0x80;
	if (state->used > 56) {
		std::fill(state->block.begin() + static_cast<ptrdiff_t>(state->used), state->block.end(),
		          0);
		Transform(state, state->block.data());
		state->used = 0;
	}
	std::fill(state->block.begin() + static_cast<ptrdiff_t>(state->used), state->block.begin() + 56,
	          0);
	for (uint32_t i = 0; i != 8; ++i)
		state->block[56 + i] = static_cast<uint8_t>(bits >> ((7 - i) * 8));
	Transform(state, state->block.data());
	Digest digest {};
	for (uint32_t i = 0; i != 8; ++i) {
		digest[i * 4]     = static_cast<uint8_t>(state->state[i] >> 24);
		digest[i * 4 + 1] = static_cast<uint8_t>(state->state[i] >> 16);
		digest[i * 4 + 2] = static_cast<uint8_t>(state->state[i] >> 8);
		digest[i * 4 + 3] = static_cast<uint8_t>(state->state[i]);
	}
	return digest;
}

bool Fail(std::string* reason, const char* text) {
	if (reason != nullptr) *reason = text;
	return false;
}

bool ParseCaptureInternal(const uint8_t* data, size_t size, const Digest* expected_envelope_sha256,
                          const Digest* expected_self_sha256, const Digest* expected_elf_sha256,
                          const uint64_t* expected_authority_id, Capture* capture,
                          std::string* reason) {
	if (capture == nullptr) return Fail(reason, "capture arguments invalid");
	*capture = {};
	if (data == nullptr) return Fail(reason, "capture arguments invalid");
	if (size != kCaptureEnvelopeSize) return Fail(reason, "capture wrong size");
	const auto envelope_sha256 = Sha256(data, size);
	if (expected_envelope_sha256 != nullptr && envelope_sha256 != *expected_envelope_sha256) {
		return Fail(reason, "capture hash mismatch");
	}
	if (!std::equal(kCaptureMagic.begin(), kCaptureMagic.end(), data))
		return Fail(reason, "capture magic mismatch");
	if (Load32Little(data + 8) != kCaptureEnvelopeVersion)
		return Fail(reason, "capture version mismatch");
	if (Load32Little(data + 12) != kCaptureHeaderSize ||
	    Load32Little(data + 16) != kCaptureEnvelopeSize || Load32Little(data + 20) != kSize)
		return Fail(reason, "capture header malformed");
	const uint64_t   authority_id = Load64Little(data + 24);
	Digest           self_sha256 {};
	Digest           elf_sha256 {};
	Digest           record_sha256 {};
	Record           record {};
	WipeObjectOnExit wipe_record(&record);
	std::memcpy(self_sha256.data(), data + 32, self_sha256.size());
	std::memcpy(elf_sha256.data(), data + 64, elf_sha256.size());
	std::memcpy(record_sha256.data(), data + 96, record_sha256.size());
	std::memcpy(record.data(), data + kCaptureHeaderSize, record.size());
	if (Sha256(record.data(), record.size()) != record_sha256)
		return Fail(reason, "capture record hash mismatch");
	if (AuthorityId(record) != authority_id)
		return Fail(reason, "capture record authority mismatch");
	if (expected_self_sha256 != nullptr && self_sha256 != *expected_self_sha256) {
		return Fail(reason, "capture SELF hash mismatch");
	}
	if (expected_elf_sha256 != nullptr && elf_sha256 != *expected_elf_sha256) {
		return Fail(reason, "capture ELF hash mismatch");
	}
	if (expected_authority_id != nullptr && authority_id != *expected_authority_id) {
		return Fail(reason, "capture authority mismatch");
	}
	capture->version         = kCaptureEnvelopeVersion;
	capture->authority_id    = authority_id;
	capture->self_sha256     = self_sha256;
	capture->elf_sha256      = elf_sha256;
	capture->record_sha256   = record_sha256;
	capture->envelope_sha256 = envelope_sha256;
	capture->record          = record;
	std::memcpy(capture->envelope.data(), data, size);
	if (reason != nullptr) *reason = "verified";
	return true;
}

bool SameCapture(const Capture& left, const Capture& right) {
	return left.version == right.version && left.authority_id == right.authority_id &&
	       left.self_sha256 == right.self_sha256 && left.elf_sha256 == right.elf_sha256 &&
	       left.record_sha256 == right.record_sha256 &&
	       left.envelope_sha256 == right.envelope_sha256 && left.record == right.record &&
	       left.envelope == right.envelope;
}

std::string HexBytes(const uint8_t* data, size_t size) {
	constexpr char digits[] = "0123456789abcdef";
	std::string    text(size * 2, '0');
	for (size_t i = 0; i != size; ++i) {
		text[i * 2]     = digits[data[i] >> 4];
		text[i * 2 + 1] = digits[data[i] & 15];
	}
	return text;
}

int HexDigit(char value) {
	if (value >= '0' && value <= '9') return value - '0';
	if (value >= 'a' && value <= 'f') return value - 'a' + 10;
	if (value >= 'A' && value <= 'F') return value - 'A' + 10;
	return -1;
}

bool DecodeHex(std::string_view text, uint8_t* data, size_t size) {
	if (data == nullptr || text.size() != size * 2) return false;
	for (size_t i = 0; i != size; ++i) {
		const int high = HexDigit(text[i * 2]);
		const int low  = HexDigit(text[i * 2 + 1]);
		if (high < 0 || low < 0) return false;
		data[i] = static_cast<uint8_t>((high << 4) | low);
	}
	return true;
}

enum class CaptureSnapshotResult {
	Read,
	Unavailable,
	WrongSize,
	Changed,
};

template <size_t Size>
CaptureSnapshotResult ReadCaptureSnapshot(const std::filesystem::path& path,
                                          std::array<uint8_t, Size>*   encoded) {
	if (encoded == nullptr) return CaptureSnapshotResult::Unavailable;
#if defined(_WIN32)
	HANDLE file = CreateFileW(
	    path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
	    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
	if (file == INVALID_HANDLE_VALUE) return CaptureSnapshotResult::Unavailable;
	FILE_ATTRIBUTE_TAG_INFO attributes {};
	LARGE_INTEGER           before {};
	CaptureSnapshotResult   result = CaptureSnapshotResult::Unavailable;
	if (GetFileInformationByHandleEx(file, FileAttributeTagInfo, &attributes, sizeof(attributes)) &&
	    (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ==
	        0 &&
	    GetFileSizeEx(file, &before)) {
		if (before.QuadPart != static_cast<LONGLONG>(encoded->size())) {
			result = CaptureSnapshotResult::WrongSize;
		} else {
			result        = CaptureSnapshotResult::Read;
			size_t offset = 0;
			while (result == CaptureSnapshotResult::Read && offset != encoded->size()) {
				const DWORD requested = static_cast<DWORD>(
				    std::min<size_t>(encoded->size() - offset, std::numeric_limits<DWORD>::max()));
				DWORD count = 0;
				if (!ReadFile(file, encoded->data() + offset, requested, &count, nullptr) ||
				    count != requested) {
					result = CaptureSnapshotResult::Changed;
				} else {
					offset += count;
				}
			}
			LARGE_INTEGER after {};
			if (result == CaptureSnapshotResult::Read &&
			    (!GetFileSizeEx(file, &after) || after.QuadPart != before.QuadPart)) {
				result = CaptureSnapshotResult::Changed;
			}
		}
	}
	CloseHandle(file);
	return result;
#else
	int flags = O_RDONLY;
#if defined(O_CLOEXEC)
	flags |= O_CLOEXEC;
#endif
#if defined(O_NOFOLLOW)
	flags |= O_NOFOLLOW;
#endif
	const int file = open(path.c_str(), flags);
	if (file < 0) return CaptureSnapshotResult::Unavailable;
	struct stat           before {};
	CaptureSnapshotResult result = CaptureSnapshotResult::Unavailable;
	if (fstat(file, &before) == 0 && S_ISREG(before.st_mode) && before.st_size >= 0) {
		if (static_cast<uint64_t>(before.st_size) != encoded->size()) {
			result = CaptureSnapshotResult::WrongSize;
		} else {
			result        = CaptureSnapshotResult::Read;
			size_t offset = 0;
			while (result == CaptureSnapshotResult::Read && offset != encoded->size()) {
				const auto count = read(file, encoded->data() + offset, encoded->size() - offset);
				if (count < 0 && errno == EINTR) continue;
				if (count <= 0) {
					result = CaptureSnapshotResult::Changed;
				} else {
					offset += static_cast<size_t>(count);
				}
			}
			struct stat after {};
			if (result == CaptureSnapshotResult::Read &&
			    (fstat(file, &after) != 0 || after.st_size != before.st_size ||
			     after.st_dev != before.st_dev || after.st_ino != before.st_ino)) {
				result = CaptureSnapshotResult::Changed;
			}
		}
	}
	close(file);
	return result;
#endif
}
} // namespace

uint64_t AuthorityId(const Record& record) {
	uint64_t value = 0;
	std::memcpy(&value, record.data(), sizeof(value));
	return value;
}

uint64_t Capability0(const Record& record) {
	uint64_t value = 0;
	std::memcpy(&value, record.data() + 8, sizeof(value));
	return value;
}

bool IsFilteredAuthorityVisible(uint64_t authority_id) {
	if (authority_id == 0x4800000000001010ull) return true;
	const uint64_t index = authority_id - 0x4800000010000004ull;
	return index <= 15 && ((0xe001ull >> index) & 1) != 0;
}

Record Filter(const Record& record) {
	Record         filtered {};
	const uint64_t authority_id = AuthorityId(record);
	const uint64_t capability   = Capability0(record) & kFilteredCapabilityMask;
	if (IsFilteredAuthorityVisible(authority_id)) {
		std::memcpy(filtered.data(), &authority_id, sizeof(authority_id));
	}
	std::memcpy(filtered.data() + 8, &capability, sizeof(capability));
	return filtered;
}

bool BuildFilteredRecord(const AuthorizationFacts& facts, Record* output) {
	if (output == nullptr || !facts.has_authority ||
	    facts.known_capability0 != kFilteredCapabilityMask ||
	    (facts.capability0 & ~facts.known_capability0) != 0)
		return false;
	Record filtered {};
	if (IsFilteredAuthorityVisible(facts.authority_id)) {
		std::memcpy(filtered.data(), &facts.authority_id, sizeof(facts.authority_id));
	}
	const uint64_t capability = facts.capability0 & kFilteredCapabilityMask;
	std::memcpy(filtered.data() + 8, &capability, sizeof(capability));
	*output = filtered;
	return true;
}

bool FilterSelfAuthInfo(const Record& caller, const Record& target, Record* output) {
	if (output == nullptr) return false;
	const uint64_t   caller_authority = AuthorityId(caller);
	const bool       restricted       = (caller[0x17] & 1u) != 0;
	Record           filtered         = target;
	WipeObjectOnExit wipe_filtered(&filtered);
	*output = {};
	std::fill(filtered.begin() + 0x08, filtered.begin() + 0x28, 0);
	std::fill(filtered.begin() + 0x48, filtered.end(), 0);
	if (caller_authority != 0x4800000000000010ull) {
		std::fill(filtered.begin(), filtered.begin() + sizeof(uint64_t), 0);
	}
	if (restricted) {
		Store64Little(filtered.data() + 0x28, Load64Little(filtered.data() + 0x28) & 0x04000000ull);
		std::fill(filtered.begin() + 0x30, filtered.begin() + 0x48, 0);
	} else {
		if (caller_authority != 0x4800000000000010ull &&
		    caller_authority != 0x4800000000000007ull) {
			return false;
		}
		std::fill(filtered.begin() + 0x28, filtered.begin() + 0x38, 0);
		Store64Little(filtered.data() + 0x38, Load64Little(filtered.data() + 0x38) & 0xffull);
		std::fill(filtered.begin() + 0x40, filtered.begin() + 0x48, 0);
	}
	*output = filtered;
	return true;
}

Digest Sha256(const void* data, size_t size) {
	Sha256State      state;
	WipeObjectOnExit wipe_state(&state);
	if (size != 0) Update(&state, static_cast<const uint8_t*>(data), size);
	return Finish(&state);
}

std::string DigestHex(const Digest& digest) {
	return HexBytes(digest.data(), digest.size());
}

bool ParseDigestHex(std::string_view text, Digest* digest) {
	if (digest == nullptr) return false;
	Digest parsed {};
	if (!DecodeHex(text, parsed.data(), parsed.size())) return false;
	*digest = parsed;
	return true;
}

std::string CapturePathEnvironmentName(const Digest& self_sha256) {
	return std::string(kCapturePathEnvironment) + '_' + DigestHex(self_sha256);
}

std::string CaptureSha256EnvironmentName(const Digest& self_sha256) {
	return std::string(kCaptureSha256Environment) + '_' + DigestHex(self_sha256);
}

bool ValidateImageIdentity(const uint8_t* self_data, size_t self_size, const uint8_t* elf_data,
                           size_t elf_size, ImageIdentity* identity, std::string* reason) {
	if (identity == nullptr) return Fail(reason, "image identity arguments invalid");
	*identity = {};
	if ((self_data == nullptr && self_size != 0) || (elf_data == nullptr && elf_size != 0))
		return Fail(reason, "image identity arguments invalid");
	auto read_self = [&](uint64_t offset, void* data, size_t bytes) {
		if (offset > self_size || bytes > self_size - offset) return false;
		std::memcpy(data, self_data + offset, bytes);
		return true;
	};
	auto read_elf = [&](uint64_t offset, void* data, size_t bytes) {
		if (offset > elf_size || bytes > elf_size - offset) return false;
		std::memcpy(data, elf_data + offset, bytes);
		return true;
	};
	Loader::SelfHeader header {};
	if (!read_self(0, &header, sizeof(header))) return Fail(reason, "truncated SELF header");
	if (std::memcmp(header.ident, "\x54\x14\xf5\xee", 4) != 0)
		return Fail(reason, "invalid SELF magic");
	const uint64_t elf_offset =
	    sizeof(header) + uint64_t {header.segments_num} * sizeof(Loader::SelfSegment);
	if (header.file_size != self_size || header.size1 > self_size ||
	    header.size2 > self_size - header.size1 || elf_offset > header.size1 ||
	    sizeof(Loader::Elf64_Ehdr) > header.size1 - elf_offset)
		return Fail(reason, "invalid SELF header bounds");
	for (uint16_t i = 0; i < header.segments_num; ++i) {
		Loader::SelfSegment segment {};
		if (!read_self(sizeof(header) + uint64_t {i} * sizeof(segment), &segment,
		               sizeof(segment)) ||
		    segment.offset > self_size || segment.compressed_size > self_size - segment.offset) {
			return Fail(reason, "invalid SELF segment bounds");
		}
	}
	Loader::Elf64_Ehdr embedded {};
	Loader::Elf64_Ehdr actual {};
	if (!read_self(elf_offset, &embedded, sizeof(embedded)) ||
	    !read_elf(0, &actual, sizeof(actual)))
		return Fail(reason, "truncated ELF header");
	if (std::memcmp(embedded.e_ident, "\177ELF", 4) != 0 ||
	    embedded.e_ident[Loader::EI_CLASS] != Loader::ELFCLASS64 ||
	    embedded.e_ident[Loader::EI_DATA] != Loader::ELFDATA2LSB ||
	    embedded.e_ehsize != sizeof(embedded) ||
	    embedded.e_phentsize != sizeof(Loader::Elf64_Phdr) || embedded.e_phnum == 0) {
		return Fail(reason, "invalid embedded ELF header");
	}
	if (std::memcmp(&embedded, &actual, sizeof(actual)) != 0)
		return Fail(reason, "ELF header mismatch");
	const uint64_t table_bytes = uint64_t {embedded.e_phnum} * sizeof(Loader::Elf64_Phdr);
	if (embedded.e_phoff < sizeof(embedded) || embedded.e_phoff > header.size1 - elf_offset ||
	    table_bytes > header.size1 - elf_offset - embedded.e_phoff || embedded.e_phoff > elf_size ||
	    table_bytes > elf_size - embedded.e_phoff)
		return Fail(reason, "invalid ELF program header bounds");
	const uint64_t extended = (elf_offset + embedded.e_phoff + table_bytes + 15) & ~uint64_t {15};
	if (extended > header.size1 || sizeof(uint64_t) > header.size1 - extended)
		return Fail(reason, "missing SELF authority field");
	for (uint16_t i = 0; i < embedded.e_phnum; ++i) {
		Loader::Elf64_Phdr original_phdr {};
		Loader::Elf64_Phdr actual_phdr {};
		const auto         offset = embedded.e_phoff + uint64_t {i} * sizeof(original_phdr);
		if (!read_self(elf_offset + offset, &original_phdr, sizeof(original_phdr)) ||
		    !read_elf(offset, &actual_phdr, sizeof(actual_phdr)))
			return Fail(reason, "truncated ELF program headers");
		if (std::memcmp(&original_phdr, &actual_phdr, sizeof(actual_phdr)) != 0)
			return Fail(reason, "ELF program header mismatch");
	}
	std::memcpy(&identity->authority_id, self_data + extended, sizeof(identity->authority_id));
	identity->self_size   = self_size;
	identity->elf_size    = elf_size;
	identity->self_sha256 = Sha256(self_data, self_size);
	identity->elf_sha256  = Sha256(elf_data, elf_size);
	if (reason != nullptr) *reason = "verified";
	return true;
}

bool BuildCaptureEnvelope(const Record& record, const ImageIdentity& identity, Capture* capture,
                          std::string* reason) {
	if (capture == nullptr) return Fail(reason, "capture builder arguments invalid");
	Record           canonical_record = record;
	WipeObjectOnExit wipe_record(&canonical_record);
	*capture                    = {};
	const uint64_t authority_id = AuthorityId(canonical_record);
	if (authority_id != identity.authority_id) return Fail(reason, "capture authority mismatch");
	std::array<uint8_t, kCaptureEnvelopeSize> envelope {};
	WipeObjectOnExit                          wipe_envelope(&envelope);
	std::copy(kCaptureMagic.begin(), kCaptureMagic.end(), envelope.begin());
	Store32Little(envelope.data() + 8, kCaptureEnvelopeVersion);
	Store32Little(envelope.data() + 12, kCaptureHeaderSize);
	Store32Little(envelope.data() + 16, kCaptureEnvelopeSize);
	Store32Little(envelope.data() + 20, kSize);
	Store64Little(envelope.data() + 24, authority_id);
	std::memcpy(envelope.data() + 32, identity.self_sha256.data(), identity.self_sha256.size());
	std::memcpy(envelope.data() + 64, identity.elf_sha256.data(), identity.elf_sha256.size());
	const auto record_sha256 = Sha256(canonical_record.data(), canonical_record.size());
	std::memcpy(envelope.data() + 96, record_sha256.data(), record_sha256.size());
	std::memcpy(envelope.data() + kCaptureHeaderSize, canonical_record.data(),
	            canonical_record.size());
	const auto envelope_sha256 = Sha256(envelope.data(), envelope.size());
	Capture    parsed {};
	if (!ParseCaptureInternal(envelope.data(), envelope.size(), &envelope_sha256,
	                          &identity.self_sha256, &identity.elf_sha256, &authority_id, &parsed,
	                          reason))
		return false;
	*capture = parsed;
	if (reason != nullptr) *reason = "built";
	return true;
}

bool ParseCaptureEnvelope(const uint8_t* data, size_t size, const Digest& expected_envelope_sha256,
                          const Digest& expected_self_sha256, const Digest& expected_elf_sha256,
                          uint64_t expected_authority_id, Capture* capture, std::string* reason) {
	return ParseCaptureInternal(data, size, &expected_envelope_sha256, &expected_self_sha256,
	                            &expected_elf_sha256, &expected_authority_id, capture, reason);
}

CaptureLoadResult LoadCaptureFromEnvironment(const Digest& expected_self_sha256,
                                             const Digest& expected_elf_sha256,
                                             uint64_t expected_authority_id, Capture* capture,
                                             std::string* reason) {
	if (capture == nullptr) {
		if (reason != nullptr) *reason = "capture output unavailable";
		return CaptureLoadResult::Rejected;
	}
	*capture              = {};
	const auto  path_name = CapturePathEnvironmentName(expected_self_sha256);
	const auto  hash_name = CaptureSha256EnvironmentName(expected_self_sha256);
	const char* path_text = std::getenv(path_name.c_str());
	const char* hash_text = std::getenv(hash_name.c_str());
	const bool  has_path  = path_text != nullptr && path_text[0] != 0;
	const bool  has_hash  = hash_text != nullptr && hash_text[0] != 0;
	if (!has_path && !has_hash) {
		if (reason != nullptr) *reason = "absent";
		return CaptureLoadResult::Absent;
	}
	if (!has_path || !has_hash) {
		if (reason != nullptr) *reason = "capture path/hash pair incomplete";
		return CaptureLoadResult::Rejected;
	}
	Digest expected_envelope_sha256 {};
	if (!ParseDigestHex(hash_text, &expected_envelope_sha256)) {
		if (reason != nullptr) *reason = "capture hash malformed";
		return CaptureLoadResult::Rejected;
	}
	try {
		const auto path = std::filesystem::u8path(path_text);
		if (!path.is_absolute()) {
			if (reason != nullptr) *reason = "capture path is not absolute";
			return CaptureLoadResult::Rejected;
		}
		std::array<uint8_t, kCaptureEnvelopeSize> encoded {};
		WipeBufferOnExit                          wipe_encoded(&encoded);
		const auto                                snapshot = ReadCaptureSnapshot(path, &encoded);
		if (snapshot != CaptureSnapshotResult::Read) {
			if (reason != nullptr) {
				*reason = snapshot == CaptureSnapshotResult::WrongSize ? "capture wrong size"
				          : snapshot == CaptureSnapshotResult::Changed
				              ? "capture size changed while reading"
				              : "capture file unavailable";
			}
			return CaptureLoadResult::Rejected;
		}
		if (!ParseCaptureEnvelope(encoded.data(), encoded.size(), expected_envelope_sha256,
		                          expected_self_sha256, expected_elf_sha256, expected_authority_id,
		                          capture, reason)) {
			return CaptureLoadResult::Rejected;
		}
		return CaptureLoadResult::Verified;
	} catch (...) {
		if (reason != nullptr) *reason = "capture path invalid";
		return CaptureLoadResult::Rejected;
	}
}

bool ParseObservation(const uint8_t* data, size_t size, const Digest& envelope_sha256,
                      const ImageIdentity& image, Observation* observation, std::string* reason) {
	if (observation == nullptr) return Fail(reason, "observation output unavailable");
	*observation = {};
	if (data == nullptr || size != kObservationSize) return Fail(reason, "observation wrong size");
	if (Sha256(data, size) != envelope_sha256) return Fail(reason, "observation hash mismatch");
	const uint32_t version = Load32Little(data + 8);
	const bool     v1      = std::memcmp(data, "KytyAO01", 8) == 0 && version == 1;
	const bool     v2      = std::memcmp(data, "KytyAO02", 8) == 0 && version == 2;
	if ((!v1 && !v2) || Load32Little(data + 12) != kObservationSize)
		return Fail(reason, "observation header malformed");
	if (Load64Little(data + 16) != image.authority_id ||
	    !std::equal(image.self_sha256.begin(), image.self_sha256.end(), data + 40) ||
	    !std::equal(image.elf_sha256.begin(), image.elf_sha256.end(), data + 72))
		return Fail(reason, "observation image mismatch");
	const uint64_t capability = Load64Little(data + 24);
	const uint64_t known      = Load64Little(data + 32);
	if (known == 0 || (known & ~kFilteredCapabilityMask) != 0 || (capability & ~known) != 0)
		return Fail(reason, "observation exceeds native filtered fields");
	const uint32_t authorization_flags = Load32Little(data + 156);
	if ((v1 && authorization_flags != 0) ||
	    (v2 && ((authorization_flags & ~3u) != 0 ||
	            ((authorization_flags & 2u) != 0 && (authorization_flags & 1u) == 0))))
		return Fail(reason, "observation authorization flags malformed");
	if (Load32Little(data + 136) != 0x13600007u || Load32Little(data + 140) == 0 ||
	    Load32Little(data + 140) > INT32_MAX || Load64Little(data + 144) == 0 ||
	    Load32Little(data + 152) >= 1000000 || Load64Little(data + 160) < Load64Little(data + 144))
		return Fail(reason, "observation native identity malformed");
	if (std::all_of(data + 104, data + 136, [](uint8_t byte) { return byte == 0; }) ||
	    std::all_of(data + 168, data + 200, [](uint8_t byte) { return byte == 0; }))
		return Fail(reason, "observation evidence binding absent");
	observation->image = image;
	observation->facts = {true,
	                      image.authority_id,
	                      capability,
	                      known,
	                      v2 && (authorization_flags & 1u) != 0,
	                      v2 && (authorization_flags & 2u) != 0};
	std::copy(data + 104, data + 136, observation->evidence_sha256.begin());
	observation->envelope_sha256 = envelope_sha256;
	std::copy(data, data + size, observation->encoded.begin());
	if (reason != nullptr) *reason = "verified";
	return true;
}

CaptureLoadResult LoadObservationFromEnvironment(const ImageIdentity& image,
                                                 Observation* observation, std::string* reason) {
	if (observation == nullptr) {
		Fail(reason, "observation output unavailable");
		return CaptureLoadResult::Rejected;
	}
	*observation          = {};
	const auto  suffix    = DigestHex(image.self_sha256);
	const auto  path_name = "KYTY_PS5_AUTHORIZATION_OBSERVATION_" + suffix;
	const auto  hash_name = "KYTY_PS5_AUTHORIZATION_OBSERVATION_SHA256_" + suffix;
	const char* path      = std::getenv(path_name.c_str());
	const char* hash      = std::getenv(hash_name.c_str());
	if ((!path || !*path) && (!hash || !*hash)) {
		if (reason != nullptr) *reason = "absent";
		return CaptureLoadResult::Absent;
	}
	Digest expected {};
	if (!path || !*path || !hash || !ParseDigestHex(hash, &expected)) {
		Fail(reason, "observation path/hash pair incomplete or malformed");
		return CaptureLoadResult::Rejected;
	}
	try {
		const auto                            file = std::filesystem::u8path(path);
		std::array<uint8_t, kObservationSize> bytes {};
		if (!file.is_absolute() ||
		    ReadCaptureSnapshot(file, &bytes) != CaptureSnapshotResult::Read) {
			Fail(reason, "observation file unavailable or wrong size");
			return CaptureLoadResult::Rejected;
		}
		return ParseObservation(bytes.data(), bytes.size(), expected, image, observation, reason)
		           ? CaptureLoadResult::Verified
				   : CaptureLoadResult::Rejected;
	} catch (const std::filesystem::filesystem_error&) {
		Fail(reason, "observation path invalid");
		return CaptureLoadResult::Rejected;
	}
}

bool EncodeScopedCapture(const Capture& capture, int guest_pid, uint32_t host_pid,
                         std::array<uint8_t, kScopedCaptureSize>* encoded) {
	if (encoded == nullptr || guest_pid <= 0 || host_pid == 0) return false;
	Capture verified {};
	if (!ParseCaptureInternal(capture.envelope.data(), capture.envelope.size(),
	                          &capture.envelope_sha256, &capture.self_sha256, &capture.elf_sha256,
	                          &capture.authority_id, &verified, nullptr))
		return false;
	if (!SameCapture(capture, verified)) return false;
	encoded->fill(0);
	std::copy(kScopedMagic.begin(), kScopedMagic.end(), encoded->begin());
	Store32Little(encoded->data() + 8, kCaptureEnvelopeVersion);
	Store32Little(encoded->data() + 12, kScopedHeaderSize);
	Store32Little(encoded->data() + 16, kScopedCaptureSize);
	Store32Little(encoded->data() + 20, kCaptureEnvelopeSize);
	Store32Little(encoded->data() + 24, static_cast<uint32_t>(guest_pid));
	Store32Little(encoded->data() + 28, host_pid);
	Store64Little(encoded->data() + 32, verified.authority_id);
	std::memcpy(encoded->data() + 40, verified.envelope_sha256.data(),
	            verified.envelope_sha256.size());
	std::memcpy(encoded->data() + kScopedHeaderSize, verified.envelope.data(),
	            verified.envelope.size());
	return true;
}

bool DecodeScopedCapture(const uint8_t* data, size_t size, int expected_guest_pid,
                         uint32_t expected_host_pid, uint64_t expected_authority_id,
                         const Digest& expected_self_sha256, const Digest& expected_elf_sha256,
                         Capture* capture, std::string* reason) {
	if (capture == nullptr) {
		return Fail(reason, "scoped capture arguments invalid");
	}
	*capture = {};
	if (data == nullptr || expected_guest_pid <= 0 || expected_host_pid == 0) {
		return Fail(reason, "scoped capture arguments invalid");
	}
	if (size != kScopedCaptureSize) return Fail(reason, "scoped capture wrong size");
	if (!std::equal(kScopedMagic.begin(), kScopedMagic.end(), data))
		return Fail(reason, "scoped capture magic mismatch");
	if (Load32Little(data + 8) != kCaptureEnvelopeVersion ||
	    Load32Little(data + 12) != kScopedHeaderSize ||
	    Load32Little(data + 16) != kScopedCaptureSize ||
	    Load32Little(data + 20) != kCaptureEnvelopeSize) {
		return Fail(reason, "scoped capture header malformed");
	}
	if (Load32Little(data + 24) != static_cast<uint32_t>(expected_guest_pid) ||
	    Load32Little(data + 28) != expected_host_pid ||
	    Load64Little(data + 32) != expected_authority_id) {
		return Fail(reason, "scoped capture owner mismatch");
	}
	Digest           envelope_sha256 {};
	WipeObjectOnExit wipe_envelope_sha256(&envelope_sha256);
	std::memcpy(envelope_sha256.data(), data + 40, envelope_sha256.size());
	return ParseCaptureInternal(data + kScopedHeaderSize, kCaptureEnvelopeSize, &envelope_sha256,
	                            &expected_self_sha256, &expected_elf_sha256, &expected_authority_id,
	                            capture, reason);
}

bool EncodeScopedObservation(const Observation& observation, int guest_pid, uint32_t host_pid,
                             uint64_t                                     host_birth,
                             std::array<uint8_t, kScopedObservationSize>* encoded) {
	if (encoded == nullptr || guest_pid <= 0 || host_pid == 0 || host_birth == 0) return false;
	Observation verified {};
	if (!ParseObservation(observation.encoded.data(), observation.encoded.size(),
	                      observation.envelope_sha256, observation.image, &verified, nullptr) ||
	    verified.encoded != observation.encoded ||
	    verified.envelope_sha256 != observation.envelope_sha256)
		return false;
	encoded->fill(0);
	std::copy(kScopedObservationMagic.begin(), kScopedObservationMagic.end(), encoded->begin());
	Store32Little(encoded->data() + 8, 1);
	Store32Little(encoded->data() + 12, kScopedObservationHeaderSize);
	Store32Little(encoded->data() + 16, kScopedObservationSize);
	Store32Little(encoded->data() + 20, kObservationSize);
	Store32Little(encoded->data() + 24, static_cast<uint32_t>(guest_pid));
	Store32Little(encoded->data() + 28, host_pid);
	Store64Little(encoded->data() + 32, verified.image.authority_id);
	std::memcpy(encoded->data() + 40, verified.envelope_sha256.data(),
	            verified.envelope_sha256.size());
	Store64Little(encoded->data() + 72, host_birth);
	std::copy(verified.encoded.begin(), verified.encoded.end(),
	          encoded->begin() + kScopedObservationHeaderSize);
	return true;
}

bool DecodeScopedObservation(const uint8_t* data, size_t size, int expected_guest_pid,
                             uint32_t expected_host_pid, uint64_t expected_host_birth,
                             uint64_t expected_authority_id, const Digest& expected_self_sha256,
                             const Digest& expected_elf_sha256,
                             const Digest& expected_envelope_sha256, Observation* observation,
                             std::string* reason) {
	if (observation == nullptr) return Fail(reason, "scoped observation output unavailable");
	*observation = {};
	if (data == nullptr || expected_guest_pid <= 0 || expected_host_pid == 0 ||
	    expected_host_birth == 0)
		return Fail(reason, "scoped observation arguments invalid");
	if (size != kScopedObservationSize) return Fail(reason, "scoped observation wrong size");
	if (!std::equal(kScopedObservationMagic.begin(), kScopedObservationMagic.end(), data) ||
	    Load32Little(data + 8) != 1 || Load32Little(data + 12) != kScopedObservationHeaderSize ||
	    Load32Little(data + 16) != kScopedObservationSize ||
	    Load32Little(data + 20) != kObservationSize) {
		return Fail(reason, "scoped observation header malformed");
	}
	if (Load32Little(data + 24) != static_cast<uint32_t>(expected_guest_pid) ||
	    Load32Little(data + 28) != expected_host_pid ||
	    Load64Little(data + 32) != expected_authority_id ||
	    Load64Little(data + 72) != expected_host_birth ||
	    !std::equal(expected_envelope_sha256.begin(), expected_envelope_sha256.end(), data + 40)) {
		return Fail(reason, "scoped observation owner mismatch");
	}
	ImageIdentity image {};
	image.authority_id = expected_authority_id;
	image.self_sha256  = expected_self_sha256;
	image.elf_sha256   = expected_elf_sha256;
	return ParseObservation(data + kScopedObservationHeaderSize, kObservationSize,
	                        expected_envelope_sha256, image, observation, reason);
}

} // namespace Libs::LibKernel::AuthInfo
