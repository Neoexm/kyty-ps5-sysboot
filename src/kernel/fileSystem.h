#ifndef EMULATOR_INCLUDE_EMULATOR_KERNEL_FILESYSTEM_H_
#define EMULATOR_INCLUDE_EMULATOR_KERNEL_FILESYSTEM_H_

#include "common/abi.h"
#include "common/common.h"
#include "common/stringUtils.h"
#include "kernel/pthread.h"

#include <cstddef>
#include <condition_variable>
#include <filesystem>
#include <deque>
#include <memory>
#include <mutex>
#include <vector>

namespace Libs::LibKernel {
class SectorBacking;
class ExfatVolume;
class BfsVolume;
} // namespace Libs::LibKernel
namespace Common {
class File;
}
namespace Libs::LibKernel::FileSystem {

struct FileStat {
	uint32_t       st_dev;
	uint32_t       st_ino;
	uint16_t       st_mode;
	uint16_t       st_nlink;
	uint32_t       st_uid;
	uint32_t       st_gid;
	uint32_t       st_rdev;
	KernelTimespec st_atim;
	KernelTimespec st_mtim;
	KernelTimespec st_ctim;
	int64_t        st_size;
	int64_t        st_blocks;
	uint32_t       st_blksize;
	uint32_t       st_flags;
	uint32_t       st_gen;
	int32_t        st_lspare;
	KernelTimespec st_birthtim;
	unsigned int: (8 / 2) * (16 - static_cast<int>(sizeof(KernelTimespec)));
	unsigned int: (8 / 2) * (16 - static_cast<int>(sizeof(KernelTimespec)));
};

struct KernelFsid {
	int32_t val[2];
};

struct KernelStatfs {
	uint32_t   f_version;
	uint32_t   f_type;
	uint64_t   f_flags;
	uint64_t   f_bsize;
	uint64_t   f_iosize;
	uint64_t   f_blocks;
	uint64_t   f_bfree;
	int64_t    f_bavail;
	uint64_t   f_files;
	int64_t    f_ffree;
	uint64_t   f_syncwrites;
	uint64_t   f_asyncwrites;
	uint64_t   f_syncreads;
	uint64_t   f_asyncreads;
	uint64_t   f_spare[10];
	uint32_t   f_namemax;
	uint32_t   f_owner;
	KernelFsid f_fsid;
	char       f_charspare[80];
	char       f_fstypename[16];
	char       f_mntfromname[88];
	char       f_mntonname[88];
};

static_assert(sizeof(KernelStatfs) == 0x1d8);
static_assert(offsetof(KernelStatfs, f_flags) == 0x08);
static_assert(offsetof(KernelStatfs, f_namemax) == 0xb8);
static_assert(offsetof(KernelStatfs, f_fsid) == 0xc0);
static_assert(offsetof(KernelStatfs, f_fstypename) == 0x118);
static_assert(offsetof(KernelStatfs, f_mntfromname) == 0x128);
static_assert(offsetof(KernelStatfs, f_mntonname) == 0x180);

struct KernelIovec {
	void*  iov_base;
	size_t iov_len;
};

static_assert(sizeof(KernelIovec) == 16);
static_assert(offsetof(KernelIovec, iov_len) == 8);

// Per-guest fd table: RFCFDG starts with no inherited fds even with a shared VM. Owns only the
// table.
class FileDescriptors;
class ScopedGuestDescriptorTable {
public:
	ScopedGuestDescriptorTable();
	~ScopedGuestDescriptorTable();
	ScopedGuestDescriptorTable(const ScopedGuestDescriptorTable&)            = delete;
	ScopedGuestDescriptorTable& operator=(const ScopedGuestDescriptorTable&) = delete;

private:
	FileDescriptors* previous = nullptr;
	FileDescriptors* owned    = nullptr;
};

int  ExportExecDescriptors(std::string* manifest);
int  ImportExecDescriptors(const std::string& manifest);
int  ExportExecReadOnlyProviders(std::string* manifest);
int  ImportExecReadOnlyProviders(const std::string& manifest);
int  ExportExecNullfsMounts(std::string* manifest);
int  ImportExecNullfsMounts(const std::string& manifest);
int  ImportExecSandboxMounts(const std::string& root, const std::string& word);
int  GetDescriptorFlags(int fd);
int  SetDescriptorFlags(int fd, int flags);
struct GuestSocketReadSource;
void Initialize();
void Shutdown();
void EmergencyShutdown();
bool IsDiagnosticGcDeviceReady() noexcept;

struct Lifecycle {
	static constexpr const char* name        = "FileSystem";
	static constexpr auto        initialize  = Libs::LibKernel::FileSystem::Initialize;
	static constexpr auto        shutdown    = Libs::LibKernel::FileSystem::Shutdown;
	static constexpr auto emergency_shutdown = Libs::LibKernel::FileSystem::EmergencyShutdown;
};

void                  Mount(const std::filesystem::path& folder, const std::string& point);
void                  MountReadOnly(const std::filesystem::path& folder, const std::string& point);
int                   MountInitialSystemTmpDirectory(const std::filesystem::path& sysroot,
                                                     const std::filesystem::path& directory);
int KYTY_SYSV_ABI     KernelUmask(int mask);
uint16_t              GetUmask();
bool                  IsTmpfsDescriptor(int descriptor);
int  MountTmpfs(const std::string& point, uint32_t mode, uint64_t byte_limit, uint32_t inode_limit);
int  MountExfatReadOnly(const std::string& point, std::shared_ptr<ExfatVolume> volume);
int  MountRegisteredExfatReadOnly(const std::string& device, const std::string& point);
int  MountBfsReadOnly(const std::string& point, std::shared_ptr<BfsVolume> volume);
int  MountRegisteredBfs(const std::string& device, const std::string& point);
int  MountNullfs(const std::string& source, const std::string& point, uint64_t flags = 0);
int  MountDevfs(const std::string& point);
int  RegisterDiagnosticSectorPayload(const std::string&             device,
                                     std::shared_ptr<SectorBacking> backing);
int  RegisterDiagnosticPartitionPassthrough(const std::string&           device,
                                            const std::filesystem::path& host_root);
bool HasCapturedPartitionPassthrough(const std::string& device);
int  MountRegisteredPartitionPassthrough(const std::string& device, const std::string& point,
                                         bool writable = false);
void                  Umount(const std::string& folder_or_point);
// Returns an empty path when the guest path has no mounted filesystem.
std::filesystem::path GetRealFilename(const std::string& mounted_file_name);
bool IsNullfsNoExec(const std::string& mounted_file_name);

int KYTY_SYSV_ABI     KernelOpen(const char* path, int flags, uint16_t mode);
int                   CreateEqueueDescriptor(int64_t handle);
bool                  IsNativeDmemDescriptor(int fd);
bool                  IsSectorPayloadDescriptor(int fd);
bool                  IsNativeAvProbeDescriptor(int fd);
bool                  IsNativeAvDescriptor(int fd);
bool                  IsA53StorageDescriptor(int fd);
bool                  IsIccnvs4SnapshotDescriptor(int fd);
struct NativeSystemMbusState {
	std::mutex              mutex;
	std::condition_variable cv;
	std::deque<uint8_t>     received;
	std::deque<uint8_t>     priority;
	bool                    shutting_down = false;
};
bool                                    IsNativeDipswDescriptor(int fd);
int KYTY_SYSV_ABI     KernelShmUnlink(const char* path);
int KYTY_SYSV_ABI     KernelClose(int d);
int KYTY_SYSV_ABI     KernelPipe(int* fds);
int                   CreateGuestSocketPair(int* fds);
int KYTY_SYSV_ABI     KernelIoctl(int d, uint64_t request, void* arg);
int64_t KYTY_SYSV_ABI KernelRead(int d, void* buf, size_t nbytes);
int64_t KYTY_SYSV_ABI KernelPread(int d, void* buf, size_t nbytes, int64_t offset);
int64_t KYTY_SYSV_ABI KernelPreadv(int d, const KernelIovec* iov, int iovcnt, int64_t offset);
int64_t KYTY_SYSV_ABI KernelWrite(int d, const void* buf, size_t nbytes);
int64_t KYTY_SYSV_ABI KernelPwrite(int d, const void* buf, size_t nbytes, int64_t offset);
int64_t KYTY_SYSV_ABI KernelPwritev(int d, const KernelIovec* iov, int iovcnt, int64_t offset);
int64_t KYTY_SYSV_ABI KernelLseek(int d, int64_t offset, int whence);
int KYTY_SYSV_ABI     KernelStat(const char* path, FileStat* sb);
int KYTY_SYSV_ABI     KernelFstat(int d, FileStat* sb);
int KYTY_SYSV_ABI     KernelFstatfs(int d, KernelStatfs* sb);
int KYTY_SYSV_ABI     KernelFtruncate(int d, int64_t length);
int KYTY_SYSV_ABI     KernelFsync(int d);
int KYTY_SYSV_ABI     KernelUnlink(const char* path);
int KYTY_SYSV_ABI     KernelRename(const char* from, const char* to);
int KYTY_SYSV_ABI     KernelGetdirentries(int fd, char* buf, int nbytes, int64_t* basep);
int KYTY_SYSV_ABI     KernelGetdents(int fd, char* buf, int nbytes);
int KYTY_SYSV_ABI     KernelMkdir(const char* path, uint16_t mode);
int KYTY_SYSV_ABI     KernelRmdir(const char* path);
int KYTY_SYSV_ABI     KernelUnmount(const char* path, int flags);
int KYTY_SYSV_ABI     KernelCheckReachability(const char* path);
bool                  GetSharedMemorySize(int d, size_t* size);
bool                  IsSharedMemoryNamed(int d, const char* name);

} // namespace Libs::LibKernel::FileSystem

#endif /* EMULATOR_INCLUDE_EMULATOR_KERNEL_FILESYSTEM_H_ */
