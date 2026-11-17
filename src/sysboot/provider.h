#ifndef KYTY_SYSBOOT_PROVIDER_H_
#define KYTY_SYSBOOT_PROVIDER_H_

#include <nlohmann/json.hpp>

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

namespace Sysboot {

struct NativeTarget {
	std::string host;
	uint16_t    port = 9035;
	std::string token;
};

// error gets the same payload the PS5 bridge's OperationError carries: code, message, and dispatched/native when known
bool NativeCall(const NativeTarget& target, const char* op, const nlohmann::json& args,
                uint32_t timeout_ms, const std::atomic<bool>* cancel, nlohmann::json* result,
                nlohmann::json* error);

struct ProviderState;

// Loopback end of KYTY_PS5_ENVELOPE_PROVIDER_*: same wire format and outcome mapping as the bridge's envelope_provider.py, relayed to the payload directly.
class EnvelopeProvider {
public:
	EnvelopeProvider();
	~EnvelopeProvider();
	EnvelopeProvider(const EnvelopeProvider&)            = delete;
	EnvelopeProvider& operator=(const EnvelopeProvider&) = delete;

	bool Start(const NativeTarget& target, const std::string& expected_build_id,
	           uint32_t native_timeout_ms, const std::array<uint8_t, 32>& key,
	           std::wstring* error);
	void Stop();

	[[nodiscard]] uint16_t Port() const;
	[[nodiscard]] uint32_t Completed() const;
	[[nodiscard]] uint32_t Rejected() const;

private:
	std::unique_ptr<ProviderState> m_state;
};

} // namespace Sysboot

#endif
