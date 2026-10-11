#ifndef KYTY_KERNEL_EXEC_PROCESS_H_
#define KYTY_KERNEL_EXEC_PROCESS_H_

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace Libs::LibKernel::Process {
bool     IsExecChildImagePath(const std::filesystem::path& host_path);
std::string GetExecChildSandboxWord();
inline void ClassifyMiniSyscoreRebootOptions(uint64_t options, uint32_t* kind,
                                             uint32_t* exit_code) {
	uint32_t k  = 3;
	uint32_t ec = 1;
	if (options == 0x4000) { // RB_POWEROFF
		k  = 0;
		ec = 0;
	} else if (options == 0x50000000) { // safe-mode / updatemode reboot bit
		k  = 1;
		ec = 1;
	} else if (options == 0) { // RB_AUTOBOOT
		k  = 2;
		ec = 2;
	}
	if (kind != nullptr) *kind = k;
	if (exit_code != nullptr) *exit_code = ec;
}
} // namespace Libs::LibKernel::Process
#endif
