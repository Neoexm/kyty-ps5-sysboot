#ifndef KYTY_PS5_KERNEL_SOCKET_POLICY_H_
#define KYTY_PS5_KERNEL_SOCKET_POLICY_H_

#include <cstdint>

namespace Libs::LibKernel::SocketPolicy {

enum class Fact : uint8_t { Unknown, Clear, Set };
struct Credentials {
	Fact capability62 = Fact::Unknown;
	Fact word68_bit57 = Fact::Unknown;
};
} // namespace Libs::LibKernel::SocketPolicy
#endif
