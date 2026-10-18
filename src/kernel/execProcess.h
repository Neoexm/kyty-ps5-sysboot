#ifndef KYTY_KERNEL_EXEC_PROCESS_H_
#define KYTY_KERNEL_EXEC_PROCESS_H_

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace Emulator {
struct RunOptions;
}

namespace Libs::LibKernel::Process {

inline constexpr uint32_t kGuestSigillCoreWaitStatus = 0x84u;

void ConfigureExecRuntime(const Emulator::RunOptions& options);
void InstallRootOriginalSelf(const Emulator::RunOptions& options);
bool RootOriginalSelfIsLoadedFile(const std::filesystem::path& host_path);
// Production keeps the lock for the life of the process.
void     ReleaseValidatedElfForTests();
uint32_t ExecPrepareTimeoutForTests();
bool     InitializeExecChild(const std::string& endpoint);
void     MarkExecChildStartupStage(uint32_t stage);
void     ApplyExecChildOptions(Emulator::RunOptions* options);
bool     InstallExecChildDescriptors();
bool     InstallExecChildReadOnlyProviders();
bool     IsExecChild();
bool     ResolveExecChildImagePath(const std::string& guest_path, std::filesystem::path* host_path);
bool     IsExecChildImagePath(const std::filesystem::path& host_path);
bool     ResolveExecChildApp0PackageTarget(const std::string&     package_name,
                                           std::filesystem::path* app0_dir);
bool ResolveExecChildApp0Package(const std::string& package_name, std::filesystem::path* app0_dir);
bool IsExecChildApp0Package(const std::string& package_name);
const std::vector<std::string>& GetExecChildArguments();
const std::vector<std::string>& GetExecChildEnvironment();
void        RecordSpawnSandbox(int pid, const std::string* root, const std::string* word);
std::string GetExecChildSandboxWord();
void        SignalExecChildImageCommitted(uint64_t entry);
bool        AwaitExecChildCommit(uint64_t entry, uint64_t stack, uint64_t params);
void        ReleaseCommittedExecChild(int pid);
void        RecordExecChildExitStatus(uint32_t wait_status);
void        RecordExecChildRebootOptions(uint64_t options, uint32_t kind, uint32_t exit_code);
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
int ExecImage(const std::string& guest_path, const std::filesystem::path& host_path,
              const std::vector<std::string>& argv, const std::vector<std::string>& envp,
              const std::filesystem::path& app0_dir = {}, const std::string& app0_elf = {});

} // namespace Libs::LibKernel::Process

#endif
