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

// RFPROC child pid while RF_MEM shares the parent's VM. Thread-local, nests.
class ScopedGuestProcessPid {
public:
	explicit ScopedGuestProcessPid(int pid);
	~ScopedGuestProcessPid();
	ScopedGuestProcessPid(const ScopedGuestProcessPid&)            = delete;
	ScopedGuestProcessPid& operator=(const ScopedGuestProcessPid&) = delete;

private:
	int previous_pid = 0;
};

int GetPid();
// Pid for an in-process RFPROC child; kernel error if the scope allocator is unavailable or full.
int  AllocateRforkChildPid();
void RegisterRforkChild(int pid, int parent_pid);
// an app child's sc_spawn carries its /app0 sandbox alias (a[0]) and package path (a[1])
void SetRforkChildAppExec(int pid, const std::string& alias, const std::string& real);
bool ResolveAppExecPath(const std::string& path, std::string* out);
bool IsTrackedRforkChild(int pid);
// True on the guest thread of a live, not yet exec'd RFPROC child, which is that process's only
// thread.
bool IsRforkChildThread();
bool MarkRforkChildExecCommitted(int pid, uint32_t host_pid, const std::string& path);
bool IsRforkChildExecCommitted(int pid);
bool IsRforkChildContextRetired(int pid);
void NotifyRforkChildContextRetired(int pid);
bool GetRforkChildExitStatus(int pid, uint32_t* status);
int  WaitForChild(int pid, uint32_t* status, int options, bool guest_status = false);
bool ReleaseReapedRforkChild(int pid);
void NotifyRforkChildExited(int pid, uint32_t exit_status);
bool GetScope(std::string* scope);
void InstallVerifiedOriginalSelf(const AuthInfo::ImageIdentity& identity);
void ClearVerifiedOriginalSelf();
bool GetVerifiedOriginalSelfIdentity(AuthInfo::ImageIdentity* identity);
AuthInfo::AuthorizationFacts GetCurrentAuthorizationFacts();
bool InstallVerifiedAuthorizationObservation(const AuthInfo::Observation& observation);
bool GetCurrentFilteredAuthInfo(AuthInfo::Record* record);
bool InstallVerifiedAuthInfo(const AuthInfo::Capture& capture);
bool GetVerifiedAuthInfoForImage(const AuthInfo::ImageIdentity& identity,
                                 AuthInfo::Capture*             capture);
void ClearVerifiedAuthInfo();
void PublishToScope();
bool FindPeerByPid(int pid, PeerProcess* peer);
bool FindPeerByHostPid(uint32_t host_pid, PeerProcess* peer);
// kern.proc.pid existence: 0, KERNEL_ERROR_ESRCH, or KERNEL_ERROR_ENOSYS when unknown
int  QueryGuestProcessExists(int pid, const char** source, uint32_t* host_pid);
void SetName(const std::string& name);
bool FindNameByPid(int pid, std::string* name);

} // namespace Libs::LibKernel::Process

#endif /* EMULATOR_INCLUDE_EMULATOR_KERNEL_PROCESS_H_ */
