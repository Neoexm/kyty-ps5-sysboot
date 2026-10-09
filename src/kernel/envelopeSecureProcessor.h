#ifndef KYTY_KERNEL_ENVELOPE_SECURE_PROCESSOR_H_
#define KYTY_KERNEL_ENVELOPE_SECURE_PROCESSOR_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>

namespace Libs::LibKernel::EnvelopeSecureProcessor {
constexpr uint32_t unavailable_result = 0xffffffed;
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

struct Result;
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
} // namespace Libs::LibKernel::EnvelopeSecureProcessor
#endif
