#ifndef EMULATOR_INCLUDE_EMULATOR_KERNEL_REG_MGR_H_
#define EMULATOR_INCLUDE_EMULATOR_KERNEL_REG_MGR_H_

#include "common/common.h"

#include <functional>

namespace Libs::LibKernel::RegMgr {

// dir of 13.60 live_regmgr_*.bin files + sha256 of its regmgr_snapshot.sha256
inline constexpr char kSnapshotEnvironment[]       = "KYTY_REGMGR_LIVE_SNAPSHOT";
inline constexpr char kSnapshotSha256Environment[] = "KYTY_REGMGR_LIVE_SNAPSHOT_SHA256";

struct Guest {
	uint64_t                                             status = 0;
	uint64_t                                             value  = 0;
	std::function<bool(uint64_t, void*, uint64_t)>       read;
	std::function<bool(uint64_t, const void*, uint64_t)> write;
};

// Raw syscall 0x214 {op, key, &status, value, size}. 0 or a POSIX errno; -1 and *reason when
// unmodelled.
int Call(uint32_t op, uint32_t key, uint64_t size, const Guest& guest, int32_t* status,
         const char** reason);

// kern.backup_restore_mode: 0 with *value, 0 with a nonzero *status when the registry read failed,
// -1 with *reason when unmodelled.
int BackupRestoreMode(int32_t* value, int32_t* status, const char** reason);

} // namespace Libs::LibKernel::RegMgr

#endif /* EMULATOR_INCLUDE_EMULATOR_KERNEL_REG_MGR_H_ */
