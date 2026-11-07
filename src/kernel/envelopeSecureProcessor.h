#ifndef KYTY_KERNEL_ENVELOPE_SECURE_PROCESSOR_H_
#define KYTY_KERNEL_ENVELOPE_SECURE_PROCESSOR_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>

namespace Libs::LibKernel::EnvelopeSecureProcessor {

constexpr uint32_t derive_command     = 0x401;
constexpr uint32_t crypt_command      = 0x281000;
constexpr uint32_t residual_command   = 0x80800;
constexpr size_t   crypt_chunk_size   = 0x10000;
constexpr uint32_t unavailable_result = 0xffffffed;

struct Context {
	uint32_t                  cid = 0;
	uint32_t                  mkv = 0;
	std::array<uint8_t, 0x20> salt {};
};

enum class Status {
	Success,
	NotConfigured,
	Unavailable,
	OperationError,
	ProtocolError,
	TransportError,
};

enum class Provider {
	None,
	Command,
	Console,
	Local,
};

struct CommandResult {
	Status   status           = Status::ProtocolError;
	uint32_t operation_result = unavailable_result;
};

class Backend {
public:
	virtual ~Backend() = default;
	virtual Provider      Kind() const noexcept { return Provider::Command; }
	virtual CommandResult DeriveKey(const Context& context, uint16_t* slot) noexcept         = 0;
	virtual CommandResult DecryptBlocks(uint16_t slot, std::span<uint8_t, 16> state,
	                                    std::span<const uint8_t> input,
	                                    std::span<uint8_t>       output) noexcept            = 0;
	virtual CommandResult EncryptBlock(uint16_t slot, std::span<uint8_t, 16> state) noexcept = 0;
	virtual void          ReleaseKey(uint16_t slot) noexcept                                 = 0;
};

struct EnvelopeRequest {
	Context                         context;
	std::span<const uint8_t, 0x300> verification_key;
	std::span<const uint8_t>        envelope;
	size_t                          output_capacity = 0;
};

struct Result;

class EnvelopeBackend {
public:
	virtual ~EnvelopeBackend() = default;
	virtual Result Process(const EnvelopeRequest& request, std::span<uint8_t> output) noexcept = 0;
};

struct Result {
	Status   status             = Status::ProtocolError;
	uint32_t operation_result   = unavailable_result;
	size_t   written            = 0;
	Provider provider           = Provider::None;
	int32_t  transport_result   = 0;
	int32_t  native_open_errno  = 0;
	int32_t  native_ioctl_errno = 0;
	int32_t  native_close_errno = 0;
	int32_t  cleanup_result     = 0;
	uint32_t dispatch_state     = 0;
	uint64_t request_id         = 0;
};

class RnpsBackend {
public:
	virtual ~RnpsBackend()                                   = default;
	virtual bool   Probe() noexcept                          = 0;
	virtual Result Decrypt(std::span<uint8_t> data) noexcept = 0;
};

enum class ConfigurationStatus {
	NotRequested,
	Configured,
	Invalid,
};

Result Process(const Context& context, std::span<const uint8_t, 16> iv,
               std::span<const uint8_t> ciphertext, std::span<uint8_t> plaintext) noexcept;
Result ProcessEnvelope(const EnvelopeRequest& request, std::span<const uint8_t, 16> iv,
                       std::span<const uint8_t> ciphertext, std::span<uint8_t> plaintext) noexcept;
Result ProcessRnps(std::span<uint8_t> data) noexcept;
bool   RnpsProviderReachable() noexcept;
ConfigurationStatus ConfigureProductionBackendFromEnvironment(std::string* error,
                                                              Provider*    provider = nullptr);
const char*         StatusName(Status status) noexcept;
const char*         ProviderName(Provider provider) noexcept;
void                Wipe(std::span<uint8_t> bytes) noexcept;

#if defined(KYTY_ENVELOPE_SECURE_PROCESSOR_TESTS)
void SetBackendForTesting(std::shared_ptr<Backend> backend);
void SetEnvelopeBackendForTesting(std::shared_ptr<EnvelopeBackend> backend);
void SetRnpsBackendForTesting(std::shared_ptr<RnpsBackend> backend);
#endif

} // namespace Libs::LibKernel::EnvelopeSecureProcessor

#endif
