#ifndef KYTY_KERNEL_ENVELOPE_CONSOLE_PROVIDER_PROTOCOL_H_
#define KYTY_KERNEL_ENVELOPE_CONSOLE_PROVIDER_PROTOCOL_H_

#include <array>
#include <cstddef>
#include <cstdint>

namespace Libs::LibKernel::EnvelopeConsoleProtocol {

constexpr uint32_t version        = 1;
constexpr uint32_t opcode         = 1;
constexpr uint32_t rnps_opcode    = 2;
constexpr uint32_t header_size    = 0x60;
constexpr uint32_t max_input_size = 0x10000;
constexpr uint32_t rnps_max_input_size =
    0x7fffffff; // rnps ioctl size is i32; shipped .ps.bundle files exceed 4 MiB
constexpr uint32_t            dispatch_pre             = 0;
constexpr uint32_t            dispatch_complete        = 1;
constexpr uint32_t            dispatch_unknown         = 2;
constexpr int32_t             maximum_transport_status = 5;
constexpr std::array<char, 8> request_magic {'K', 'Y', 'E', 'N', 'V', '0', '0', '1'};
constexpr std::array<char, 8> response_magic {'K', 'Y', 'E', 'N', 'R', '0', '0', '1'};

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

static_assert(sizeof(RequestHeader) == header_size);
static_assert(sizeof(ResponseHeader) == header_size);
static_assert(offsetof(RequestHeader, magic) == 0x00);
static_assert(offsetof(RequestHeader, version) == 0x08);
static_assert(offsetof(RequestHeader, header_size) == 0x0c);
static_assert(offsetof(RequestHeader, total_size) == 0x10);
static_assert(offsetof(RequestHeader, opcode) == 0x14);
static_assert(offsetof(RequestHeader, request_id) == 0x18);
static_assert(offsetof(RequestHeader, cid) == 0x20);
static_assert(offsetof(RequestHeader, mkv) == 0x24);
static_assert(offsetof(RequestHeader, key_size) == 0x28);
static_assert(offsetof(RequestHeader, salt_size) == 0x2c);
static_assert(offsetof(RequestHeader, input_size) == 0x30);
static_assert(offsetof(RequestHeader, output_capacity) == 0x34);
static_assert(offsetof(RequestHeader, reserved0) == 0x38);
static_assert(offsetof(RequestHeader, reserved1) == 0x3c);
static_assert(offsetof(RequestHeader, hmac) == 0x40);
static_assert(offsetof(ResponseHeader, magic) == 0x00);
static_assert(offsetof(ResponseHeader, version) == 0x08);
static_assert(offsetof(ResponseHeader, header_size) == 0x0c);
static_assert(offsetof(ResponseHeader, total_size) == 0x10);
static_assert(offsetof(ResponseHeader, opcode) == 0x14);
static_assert(offsetof(ResponseHeader, request_id) == 0x18);
static_assert(offsetof(ResponseHeader, transport_status) == 0x20);
static_assert(offsetof(ResponseHeader, native_open_errno) == 0x24);
static_assert(offsetof(ResponseHeader, native_ioctl_errno) == 0x28);
static_assert(offsetof(ResponseHeader, native_close_errno) == 0x2c);
static_assert(offsetof(ResponseHeader, operation_result) == 0x30);
static_assert(offsetof(ResponseHeader, output_size) == 0x34);
static_assert(offsetof(ResponseHeader, cleanup_status) == 0x38);
static_assert(offsetof(ResponseHeader, dispatch_state) == 0x3c);
static_assert(offsetof(ResponseHeader, hmac) == 0x40);

} // namespace Libs::LibKernel::EnvelopeConsoleProtocol

#endif
