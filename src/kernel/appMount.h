#ifndef EMULATOR_INCLUDE_EMULATOR_KERNEL_APP_MOUNT_H_
#define EMULATOR_INCLUDE_EMULATOR_KERNEL_APP_MOUNT_H_

#include "common/common.h"

#include <array>
#include <functional>

namespace Libs::LibKernel::AppMount {
// Raw syscall 0x2c2 block as libkernel HRDq-RDIGmI marshals it; +0xb0 points at the wrapper-local
// id.
using Request = std::array<uint8_t, 0x178>;
// The proc+0x460 record behind {1,14,35,pid}.
using Record = std::array<uint8_t, 0x98>;
// return 0 or a POSIX errno
// copyin fills the block, copyout writes the id to +0xb0, read fetches param.json behind +0xa0
int Begin(const std::function<int(Request&)>&                  copyin,
          const std::function<int(uint64_t, int32_t)>&         copyout,
          const std::function<int(uint64_t, void*, uint64_t)>& read);
// Raw syscall 0x2c3; copyin reads the int the argument points at.
int         End(const std::function<int(int32_t*)>& copyin);
} // namespace Libs::LibKernel::AppMount
#endif /* EMULATOR_INCLUDE_EMULATOR_KERNEL_APP_MOUNT_H_ */
