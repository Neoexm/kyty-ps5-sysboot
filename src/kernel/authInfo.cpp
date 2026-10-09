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
constexpr uint32_t               kCaptureHeaderSize           = 0x80;
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
} // namespace Libs::LibKernel::AuthInfo
