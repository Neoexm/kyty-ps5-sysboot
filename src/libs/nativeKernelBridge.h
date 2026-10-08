#ifndef KYTY_EMULATOR_LIBS_NATIVE_KERNEL_BRIDGE_H_
#define KYTY_EMULATOR_LIBS_NATIVE_KERNEL_BRIDGE_H_

#include <array>
#include <cstdint>

namespace Libs::LibKernel::EventQueue {
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
Reply DispatchSyscall(const SyscallRequest& request);
} // namespace Libs::NativeKernelBridge

#endif // KYTY_EMULATOR_LIBS_NATIVE_KERNEL_BRIDGE_H_
