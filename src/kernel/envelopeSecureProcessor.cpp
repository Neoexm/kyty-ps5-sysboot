#include "kernel/envelopeSecureProcessor.h"
#include "kernel/envelopeConsoleProvider.h"
#include "kernel/envelopeLocalBackend.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <mutex>

namespace Libs::LibKernel::EnvelopeSecureProcessor {

namespace {

std::mutex                       g_backend_mutex;
std::shared_ptr<EnvelopeBackend> g_envelope_backend;
std::shared_ptr<RnpsBackend>     g_rnps_backend;
std::shared_ptr<Backend>         g_backend;

std::shared_ptr<Backend> CurrentBackend() {
	std::lock_guard lock(g_backend_mutex);
	return g_backend;
}

std::shared_ptr<EnvelopeBackend> CurrentEnvelopeBackend() {
	std::lock_guard lock(g_backend_mutex);
	return g_envelope_backend;
}

std::shared_ptr<RnpsBackend> CurrentRnpsBackend() {
	std::lock_guard lock(g_backend_mutex);
	return g_rnps_backend;
}

Result Fail(Status status, uint32_t operation_result, std::span<uint8_t> output,
            Provider provider = Provider::None) {
	Wipe(output);
	if (operation_result == 0) operation_result = unavailable_result;
	return {status, operation_result, 0, provider};
}

Status SelectedBackendStatus(Status status) {
	return status == Status::NotConfigured ? Status::ProtocolError : status;
}

} // namespace

void Wipe(std::span<uint8_t> bytes) noexcept {
	volatile uint8_t* cursor = bytes.data();
	for (size_t i = 0; i < bytes.size(); i++)
		cursor[i] = 0;
}

const char* StatusName(Status status) noexcept {
	switch (status) {
		case Status::Success: return "success";
		case Status::NotConfigured: return "not_configured";
		case Status::Unavailable: return "unavailable";
		case Status::OperationError: return "operation_error";
		case Status::ProtocolError: return "protocol_error";
		case Status::TransportError: return "transport_error";
	}
	return "invalid";
}

const char* ProviderName(Provider provider) noexcept {
	switch (provider) {
		case Provider::None: return "none";
		case Provider::Command: return "command";
		case Provider::Console: return "console";
		case Provider::Local: return "local";
	}
	return "invalid";
}

Result Process(const Context& context, std::span<const uint8_t, 16> iv,
               std::span<const uint8_t> ciphertext, std::span<uint8_t> plaintext) noexcept {
	if (ciphertext.empty() || ciphertext.size() != plaintext.size()) {
		return Fail(Status::ProtocolError, unavailable_result, plaintext);
	}
	const auto backend = CurrentBackend();
	if (backend == nullptr) return Fail(Status::NotConfigured, unavailable_result, plaintext);

	const auto provider = backend->Kind();
	uint16_t   slot     = 0;
	const auto derived  = backend->DeriveKey(context, &slot);
	if (derived.status != Status::Success || derived.operation_result != 0) {
		return Fail(derived.status == Status::Success ? Status::ProtocolError
		                                              : SelectedBackendStatus(derived.status),
		            derived.operation_result, plaintext, provider);
	}
	struct Slot {
		std::shared_ptr<Backend> backend;
		uint16_t                 value;
		~Slot() { backend->ReleaseKey(value); }
	} lease {backend, slot};

	std::array<uint8_t, 16> chain {};
	std::memcpy(chain.data(), iv.data(), chain.size());
	const size_t aligned = ciphertext.size() & ~size_t {15};
	for (size_t offset = 0; offset < aligned;) {
		const size_t count  = std::min(crypt_chunk_size, aligned - offset);
		const auto   result = backend->DecryptBlocks(slot, chain, ciphertext.subspan(offset, count),
		                                             plaintext.subspan(offset, count));
		if (result.status != Status::Success || result.operation_result != 0) {
			Wipe(chain);
			return Fail(result.status == Status::Success ? Status::ProtocolError
			                                             : SelectedBackendStatus(result.status),
			            result.operation_result, plaintext, provider);
		}
		offset += count;
	}

	const size_t tail = ciphertext.size() - aligned;
	if (tail != 0) {
		const auto result = backend->EncryptBlock(slot, chain);
		if (result.status != Status::Success || result.operation_result != 0) {
			Wipe(chain);
			return Fail(result.status == Status::Success ? Status::ProtocolError
			                                             : SelectedBackendStatus(result.status),
			            result.operation_result, plaintext, provider);
		}
		for (size_t i = 0; i < tail; i++)
			plaintext[aligned + i] = ciphertext[aligned + i] ^ chain[i];
	}
	Wipe(chain);
	return {Status::Success, 0, plaintext.size(), provider};
}

Result ProcessEnvelope(const EnvelopeRequest& request, std::span<const uint8_t, 16> iv,
                       std::span<const uint8_t> ciphertext, std::span<uint8_t> plaintext) noexcept {
	if (request.output_capacity != plaintext.size() || request.envelope.empty() ||
	    ciphertext.empty() || ciphertext.size() != plaintext.size()) {
		return Fail(Status::ProtocolError, unavailable_result, plaintext);
	}
	const auto backend = CurrentEnvelopeBackend();
	if (backend == nullptr) return Process(request.context, iv, ciphertext, plaintext);
	auto result     = backend->Process(request, plaintext);
	result.provider = Provider::Console;
	if (result.status == Status::NotConfigured) result.status = Status::ProtocolError;
	if (result.status != Status::Success || result.operation_result != 0 ||
	    result.written != plaintext.size()) {
		Wipe(plaintext);
		result.written = 0;
		if (result.status == Status::Success) result.status = Status::ProtocolError;
		if (result.operation_result == 0) result.operation_result = unavailable_result;
	}
	return result;
}

Result ProcessRnps(std::span<uint8_t> data) noexcept {
	if (data.empty()) return Fail(Status::ProtocolError, unavailable_result, data);
	const auto backend = CurrentRnpsBackend();
	if (backend == nullptr) return Fail(Status::NotConfigured, unavailable_result, data);
	auto result     = backend->Decrypt(data);
	result.provider = Provider::Console;
	if (result.status == Status::NotConfigured) result.status = Status::ProtocolError;
	if (result.status != Status::Success || result.operation_result != 0 ||
	    result.written != data.size()) {
		Wipe(data);
		result.written = 0;
		if (result.status == Status::Success) result.status = Status::ProtocolError;
		if (result.operation_result == 0) result.operation_result = unavailable_result;
	}
	return result;
}

bool RnpsProviderReachable() noexcept {
	const auto backend = CurrentRnpsBackend();
	return backend != nullptr && backend->Probe();
}

ConfigurationStatus ConfigureProductionBackendFromEnvironment(std::string* error,
                                                              Provider*    provider) {
	const char* selection = std::getenv("KYTY_PS5_ENVELOPE_BACKEND");
	if (selection != nullptr && std::strcmp(selection, "local") == 0) {
		std::shared_ptr<Backend> local;
		const auto               status = CreateLocalBackendFromEnvironment(&local, error);
		if (status != ConfigurationStatus::Configured) return status;
		{
			std::lock_guard lock(g_backend_mutex);
			g_backend = std::move(local);
		}
		if (provider != nullptr) *provider = Provider::Local;
		return ConfigurationStatus::Configured;
	}
	if (selection != nullptr && selection[0] != '\0' && std::strcmp(selection, "console") != 0) {
		if (error != nullptr) *error = "unknown KYTY_PS5_ENVELOPE_BACKEND value";
		return ConfigurationStatus::Invalid;
	}
	std::shared_ptr<EnvelopeBackend> console;
	const auto                       status = CreateConsoleProviderFromEnvironment(&console, error);
	if (status != ConfigurationStatus::Configured) return status;
	std::shared_ptr<RnpsBackend> rnps;
	if (CreateConsoleRnpsProviderFromEnvironment(&rnps, error) != ConfigurationStatus::Configured) {
		if (error != nullptr) *error = "rnps provider configuration failed";
		return ConfigurationStatus::Invalid;
	}
	{
		std::lock_guard lock(g_backend_mutex);
		g_envelope_backend = std::move(console);
		g_rnps_backend     = std::move(rnps);
	}
	if (provider != nullptr) *provider = Provider::Console;
	return ConfigurationStatus::Configured;
}

#if defined(KYTY_ENVELOPE_SECURE_PROCESSOR_TESTS)
void SetBackendForTesting(std::shared_ptr<Backend> backend) {
	std::lock_guard lock(g_backend_mutex);
	g_backend = std::move(backend);
}

void SetEnvelopeBackendForTesting(std::shared_ptr<EnvelopeBackend> backend) {
	std::lock_guard lock(g_backend_mutex);
	g_envelope_backend = std::move(backend);
}

void SetRnpsBackendForTesting(std::shared_ptr<RnpsBackend> backend) {
	std::lock_guard lock(g_backend_mutex);
	g_rnps_backend = std::move(backend);
}
#endif

} // namespace Libs::LibKernel::EnvelopeSecureProcessor
