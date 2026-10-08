#ifndef EMULATOR_INCLUDE_EMULATOR_KERNEL_PROCESS_H_
#define EMULATOR_INCLUDE_EMULATOR_KERNEL_PROCESS_H_

#include "common/common.h"
#include "kernel/authInfo.h"

#include <string>

namespace Libs::LibKernel::Process {
struct PeerProcess {
	int              pid           = 0;
	uint32_t         host_pid      = 0;
	uint64_t         host_birth    = 0;
	bool             has_category  = false;
	int32_t          category      = 0;
	uint64_t         auth_id       = 0;
	bool             has_auth_info = false;
	AuthInfo::Record auth_info {};
	bool             has_filtered_auth_info = false;
	AuthInfo::Record filtered_auth_info {};
	~PeerProcess() {
		auto* bytes = static_cast<volatile uint8_t*>(auth_info.data());
		for (size_t i = 0; i != auth_info.size(); ++i)
			bytes[i] = 0;
		bytes = static_cast<volatile uint8_t*>(filtered_auth_info.data());
		for (size_t i = 0; i != filtered_auth_info.size(); ++i)
			bytes[i] = 0;
		has_auth_info          = false;
		has_filtered_auth_info = false;
	}
};
int GetPid();
} // namespace Libs::LibKernel::Process
#endif /* EMULATOR_INCLUDE_EMULATOR_KERNEL_PROCESS_H_ */
