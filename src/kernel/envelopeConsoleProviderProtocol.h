#ifndef KYTY_KERNEL_ENVELOPE_CONSOLE_PROVIDER_PROTOCOL_H_
#define KYTY_KERNEL_ENVELOPE_CONSOLE_PROVIDER_PROTOCOL_H_

#include <array>
#include <cstddef>
#include <cstdint>

namespace Libs::LibKernel::EnvelopeConsoleProtocol {
constexpr uint32_t version        = 1;
constexpr uint32_t opcode         = 1;
constexpr uint32_t header_size    = 0x60;
struct RequestHeader {
	std::array<char, 8>     magic;
	uint32_t                version;
	uint32_t                header_size;
	uint32_t                total_size;
	uint32_t                opcode;
	uint64_t                request_id;
	uint32_t                cid;
	uint32_t                mkv;
	uint32_t                key_size;
	uint32_t                salt_size;
	uint32_t                input_size;
	uint32_t                output_capacity;
	uint32_t                reserved0;
	uint32_t                reserved1;
	std::array<uint8_t, 32> hmac;
};
struct ResponseHeader {
	std::array<char, 8>     magic;
	uint32_t                version;
	uint32_t                header_size;
	uint32_t                total_size;
	uint32_t                opcode;
	uint64_t                request_id;
	int32_t                 transport_status;
	int32_t                 native_open_errno;
	int32_t                 native_ioctl_errno;
	int32_t                 native_close_errno;
	uint32_t                operation_result;
	uint32_t                output_size;
	int32_t                 cleanup_status;
	uint32_t                dispatch_state;
	std::array<uint8_t, 32> hmac;
};
} // namespace Libs::LibKernel::EnvelopeConsoleProtocol
#endif
