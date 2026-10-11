#ifndef KYTY_KERNEL_EXEC_PROCESS_H_
#define KYTY_KERNEL_EXEC_PROCESS_H_

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace Libs::LibKernel::Process {
bool     IsExecChildImagePath(const std::filesystem::path& host_path);
std::string GetExecChildSandboxWord();
} // namespace Libs::LibKernel::Process
#endif
