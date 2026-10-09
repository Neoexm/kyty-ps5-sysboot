#ifndef KYTY_PS5_KERNEL_AUTH_INFO_H_
#define KYTY_PS5_KERNEL_AUTH_INFO_H_

#include "common/common.h"

#include <array>
#include <string>
#include <string_view>

namespace Libs::LibKernel::AuthInfo {
constexpr size_t   kSize                   = 0x88;
constexpr size_t   kDigestSize             = 32;
constexpr uint32_t kCaptureEnvelopeVersion = 2;
constexpr size_t   kCaptureEnvelopeSize    = 0x108;
constexpr size_t   kObservationSize        = 200;
constexpr uint64_t kFilteredCapabilityMask = 0x7000000000000000ull;

using Record = std::array<uint8_t, kSize>;
using Digest = std::array<uint8_t, kDigestSize>;
struct AuthorizationFacts {
	bool     has_authority     = false;
	uint64_t authority_id      = 0;
	uint64_t capability0       = 0;
	uint64_t known_capability0 = 0;
	bool     root_prison_known = false;
	bool     root_prison       = false;
};
struct Capture {
	uint32_t                                  version      = 0;
	uint64_t                                  authority_id = 0;
	Digest                                    self_sha256 {};
	Digest                                    elf_sha256 {};
	Digest                                    record_sha256 {};
	Digest                                    envelope_sha256 {};
	Record                                    record {};
	std::array<uint8_t, kCaptureEnvelopeSize> envelope {};

	~Capture() noexcept {
		auto* bytes = reinterpret_cast<volatile uint8_t*>(this);
		for (size_t i = 0; i != sizeof(*this); ++i)
			bytes[i] = 0;
	}
};
struct ImageIdentity {
	uint64_t authority_id = 0;
	uint64_t self_size    = 0;
	uint64_t elf_size     = 0;
	Digest   self_sha256 {};
	Digest   elf_sha256 {};
};
struct Observation {
	ImageIdentity                         image;
	AuthorizationFacts                    facts;
	Digest                                evidence_sha256 {};
	Digest                                envelope_sha256 {};
	std::array<uint8_t, kObservationSize> encoded {};
};
uint64_t    AuthorityId(const Record& record);
uint64_t    Capability0(const Record& record);
Record      Filter(const Record& record);
bool        BuildFilteredRecord(const AuthorizationFacts& facts, Record* output);
Digest      Sha256(const void* data, size_t size);
std::string DigestHex(const Digest& digest);
bool        ParseDigestHex(std::string_view text, Digest* digest);
bool ParseCaptureEnvelope(const uint8_t* data, size_t size, const Digest& expected_envelope_sha256,
                          const Digest& expected_self_sha256, const Digest& expected_elf_sha256,
                          uint64_t expected_authority_id, Capture* capture, std::string* reason);
} // namespace Libs::LibKernel::AuthInfo
#endif
