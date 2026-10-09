#ifndef KYTY_KERNEL_NULLFS_MOUNT_H_
#define KYTY_KERNEL_NULLFS_MOUNT_H_

#include <cstdint>
#include <string>
#include <vector>

namespace Libs::LibKernel::NullfsMount {
struct Resolution {
	std::string path;
	uint64_t    generation = 0;
	bool        mounted    = false;
	// MNT_RDONLY from any layer, since writes bypass to every lower mount; MNT_NOEXEC only from the
	// layer the path entered, as exec checks the vnode's own mount.
	bool read_only = false;
	bool no_exec   = false;
};
} // namespace Libs::LibKernel::NullfsMount
#endif
