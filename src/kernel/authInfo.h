#ifndef KYTY_PS5_KERNEL_AUTH_INFO_H_
#define KYTY_PS5_KERNEL_AUTH_INFO_H_

#include "common/common.h"

#include <array>
#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <utility>

namespace Libs::LibKernel::AuthInfo {

constexpr size_t   kSize                   = 0x88;
constexpr size_t   kDigestSize             = 32;
constexpr uint32_t kCaptureEnvelopeVersion = 2;
constexpr size_t   kCaptureEnvelopeSize    = 0x108;
constexpr size_t   kScopedCaptureSize      = 0x150;
constexpr size_t   kObservationSize        = 200;
constexpr size_t   kScopedObservationSize  = 0x118;
constexpr size_t   kCaptureCatalogueCapacity = 256 * 1024;
constexpr uint64_t kFilteredCapabilityMask = 0x7000000000000000ull;

inline constexpr char kCapturePathEnvironment[]   = "KYTY_PS5_CAPTURED_AUTHINFO";
inline constexpr char kCaptureSha256Environment[] = "KYTY_PS5_CAPTURED_AUTHINFO_SHA256";

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

enum class CaptureLoadResult {
	Absent,
	Verified,
	Rejected,
};

class CaptureCatalogue {
public:
	bool Add(const Digest& self_sha256, const Digest& envelope_sha256,
	         const std::filesystem::path& path, std::string* reason);
	CaptureLoadResult Load(const ImageIdentity& image, Capture* capture, std::string* reason) const;
	bool Encode(uint8_t* output, size_t capacity, size_t* written, std::string* reason) const;
	bool Decode(const uint8_t* data, size_t size, std::string* reason);
	size_t Size() const { return m_entries.size(); }
	void Clear() { m_entries.clear(); }

private:
	std::map<Digest, std::pair<Digest, std::filesystem::path>> m_entries;
};

uint64_t    AuthorityId(const Record& record);
uint64_t    Capability0(const Record& record);
bool        IsFilteredAuthorityVisible(uint64_t authority_id);
Record      Filter(const Record& record);
bool        FilterSelfAuthInfo(const Record& caller, const Record& target, Record* output);
bool        BuildFilteredRecord(const AuthorizationFacts& facts, Record* output);
Digest      Sha256(const void* data, size_t size);
std::string DigestHex(const Digest& digest);
bool        ParseDigestHex(std::string_view text, Digest* digest);
std::string CapturePathEnvironmentName(const Digest& self_sha256);
std::string CaptureSha256EnvironmentName(const Digest& self_sha256);
bool ParseObservation(const uint8_t* data, size_t size, const Digest& envelope_sha256,
                      const ImageIdentity& image, Observation* observation, std::string* reason);
CaptureLoadResult LoadObservationFromEnvironment(const ImageIdentity& image,
                                                 Observation* observation, std::string* reason);
bool ValidateImageIdentity(const uint8_t* self_data, size_t self_size, const uint8_t* elf_data,
                           size_t elf_size, ImageIdentity* identity, std::string* reason);
bool BuildCaptureEnvelope(const Record& record, const ImageIdentity& identity, Capture* capture,
                          std::string* reason);
bool ParseCaptureEnvelope(const uint8_t* data, size_t size, const Digest& expected_envelope_sha256,
                          const Digest& expected_self_sha256, const Digest& expected_elf_sha256,
                          uint64_t expected_authority_id, Capture* capture, std::string* reason);
CaptureLoadResult LoadCaptureFromEnvironment(const Digest& expected_self_sha256,
                                             const Digest& expected_elf_sha256,
                                             uint64_t expected_authority_id, Capture* capture,
                                             std::string* reason);
bool              EncodeScopedCapture(const Capture& capture, int guest_pid, uint32_t host_pid,
                                      std::array<uint8_t, kScopedCaptureSize>* encoded);
bool DecodeScopedCapture(const uint8_t* data, size_t size, int expected_guest_pid,
                         uint32_t expected_host_pid, uint64_t expected_authority_id,
                         const Digest& expected_self_sha256, const Digest& expected_elf_sha256,
                         Capture* capture, std::string* reason);
bool EncodeScopedObservation(const Observation& observation, int guest_pid, uint32_t host_pid,
                             uint64_t                                     host_birth,
                             std::array<uint8_t, kScopedObservationSize>* encoded);
bool DecodeScopedObservation(const uint8_t* data, size_t size, int expected_guest_pid,
                             uint32_t expected_host_pid, uint64_t expected_host_birth,
                             uint64_t expected_authority_id, const Digest& expected_self_sha256,
                             const Digest& expected_elf_sha256,
                             const Digest& expected_envelope_sha256, Observation* observation,
                             std::string* reason);

} // namespace Libs::LibKernel::AuthInfo

#endif
