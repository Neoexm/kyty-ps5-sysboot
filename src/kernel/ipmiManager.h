#ifndef KYTY_PS5_KERNEL_IPMI_MANAGER_H_
#define KYTY_PS5_KERNEL_IPMI_MANAGER_H_

#include "kernel/authInfo.h"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace Libs::LibKernel::Process {
struct PeerProcess;
}

namespace Libs::LibKernel::IpmiManager {
int  ValidateServerConfig(const void* config);
int  ValidateServerAuthorization(std::string_view name, const AuthInfo::Record& auth_info);
int  ValidateServerAuthorization(std::string_view name, const AuthInfo::AuthorizationFacts& facts);
bool TryCall(uint32_t command, int32_t handle, int32_t* result, void* args, size_t size,
             uint64_t magic, int* status);
bool ValidateCurrentAuthorizationPeer(int target_pid, uint32_t* host_pid = nullptr,
                                      uint64_t* host_birth = nullptr);
bool ValidateCurrentRequestPeer(int target_pid, uint32_t* host_pid = nullptr,
                                uint64_t* host_birth = nullptr);
bool ValidateCurrentRemotePeer(int target_pid, uint32_t* host_pid = nullptr,
                               uint64_t* host_birth = nullptr);
bool FindCurrentRemotePeer(int target_pid, Process::PeerProcess* peer);
} // namespace Libs::LibKernel::IpmiManager

#endif
