#ifndef KYTY_PS5_KERNEL_SOCKET_POLICY_H_
#define KYTY_PS5_KERNEL_SOCKET_POLICY_H_

#include <cstdint>

namespace Libs::LibKernel::SocketPolicy {

enum class Fact : uint8_t { Unknown, Clear, Set };

struct Credentials {
	Fact capability62 = Fact::Unknown;
	Fact word68_bit57 = Fact::Unknown;
};

enum class Admission { Allow, Deny, Unknown };

Admission Check(uint32_t flags, const Credentials& target, const Credentials& caller);

} // namespace Libs::LibKernel::SocketPolicy

#endif
