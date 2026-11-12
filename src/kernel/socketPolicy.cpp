#include "kernel/socketPolicy.h"

namespace Libs::LibKernel::SocketPolicy {

Admission Check(uint32_t flags, const Credentials& target, const Credentials& caller) {
	if ((flags & 0x10u) != 0 || target.capability62 == Fact::Clear ||
	    caller.capability62 == Fact::Set ||
	    ((flags & 0x20u) != 0 && caller.word68_bit57 == Fact::Set))
		return Admission::Allow;
	if (target.capability62 == Fact::Unknown || caller.capability62 == Fact::Unknown ||
	    ((flags & 0x20u) != 0 && caller.word68_bit57 == Fact::Unknown))
		return Admission::Unknown;
	return Admission::Deny;
}

} // namespace Libs::LibKernel::SocketPolicy
