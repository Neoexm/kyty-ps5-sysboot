#ifndef KYTY_EMULATOR_LIBS_NATIVE_KERNEL_BRIDGE_H_
#define KYTY_EMULATOR_LIBS_NATIVE_KERNEL_BRIDGE_H_

#include <array>
#include <cstdint>

namespace Libs::LibKernel::EventQueue {
struct KernelEvent;
}

namespace Libs::NativeKernelBridge {

// Native libkernel export contracts, not a SYSCALL trap. NIDs dYK287SsmDs, mkawd0NA9ts, pd02UI9TbOA
// (13.60).
enum class Service : uint32_t {
	FlexibleMapExport = 1, // native helper, reaches guest syscall 0x2D5
	SysconfExport     = 2, // sysconf(47), native query uses MIB {9, 20}
	ReadlinkExport    = 3, // native libkernel_sys reaches syscall 0x3A
};

struct Request {
	Service                 service;
	std::array<uint64_t, 6> args {};
};

struct Reply {
	int64_t value       = -1; // native export's return register (RAX)
	int     posix_errno = 0;  // set by the export adapter if value == -1
};

// For a future guest-instruction trap. Wrapper arg order RDI, RSI, RDX, R10, R8, R9 (SYSCALL
// clobbers RCX); a 7th comes off the guest stack only for a recovered ABI.
struct SyscallRequest {
	uint64_t                number = 0;
	std::array<uint64_t, 6> args {};
	uint64_t                stack_arg7       = 0;
	bool                    stack_arg7_valid = false;
};

// the caller translates this reply to its export ABI
Reply Dispatch(const Request& request);
Reply DispatchSyscall(const SyscallRequest& request);
Reply PreflightSyscoreExecve(const SyscallRequest& request);
bool  ShouldLogMiniSyscallTrace(uint64_t ordinal);
int RegisterImportedGuestIpmiServer(const char* service_name, uint64_t guest_server,
                                    uint64_t guest_config, uint32_t owner_pid, uint32_t* server_id);
int WaitForImportedGuestIpmiServerRequest(uint32_t server_id, uint64_t capacity);
// mini-syscore cold-boot event creation, mini-syscore.elf 0x4022A0
bool InitializeOriginalMiniSyscoreBootEvents();
// optional orbis_audiod startup model (event-setter at 0x32F..0x34D); Kyty's audio lifecycle backs
// the event
bool InitializeOriginalVirtualAudiodBootEvent();
// Opt-in, process-local IPC notification registration on an empty service queue. Caller rolls back
// if other kevents fail.
int  RegisterSysAvIpmiServerFilter(int64_t                                   queue,
                                   const LibKernel::EventQueue::KernelEvent& original);
void UnregisterSysAvIpmiServerFilter(int64_t queue, uint32_t server_id);
bool RunSelfTests();

} // namespace Libs::NativeKernelBridge

#endif // KYTY_EMULATOR_LIBS_NATIVE_KERNEL_BRIDGE_H_
