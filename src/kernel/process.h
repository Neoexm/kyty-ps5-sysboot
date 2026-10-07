#ifndef EMULATOR_INCLUDE_EMULATOR_KERNEL_PROCESS_H_
#define EMULATOR_INCLUDE_EMULATOR_KERNEL_PROCESS_H_

#include "common/common.h"
#include "kernel/authInfo.h"

#include <string>

namespace Libs::LibKernel::Process {
int GetPid();
} // namespace Libs::LibKernel::Process
#endif /* EMULATOR_INCLUDE_EMULATOR_KERNEL_PROCESS_H_ */
