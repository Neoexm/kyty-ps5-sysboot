#ifndef EMULATOR_INCLUDE_EMULATOR_KERNEL_TMPFS_H_
#define EMULATOR_INCLUDE_EMULATOR_KERNEL_TMPFS_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Libs::LibKernel::Tmpfs {

inline constexpr uint64_t PageSize          = 16384;
inline constexpr uint64_t MaximumMountBytes = 16 * 1024 * 1024;
inline constexpr uint32_t MaximumMounts     = 32;
inline constexpr uint32_t MaximumInodes     = 8192;

struct NodeStat {
	uint64_t inode           = 0;
	uint32_t device          = 0;
	uint64_t size            = 0;
	uint64_t allocated_bytes = 0;
	uint32_t mode            = 0;
	uint32_t uid             = 0;
	uint32_t gid             = 0;
	uint32_t links           = 0;
	int64_t  accessed        = 0;
	int64_t  modified        = 0;
	int64_t  changed         = 0;
	int64_t  created         = 0;
};

struct DirectoryEntry {
	uint64_t    inode = 0;
	uint8_t     type  = 0;
	std::string name;
};

struct Usage {
	uint64_t byte_limit                  = 0;
	uint64_t charged_bytes               = 0;
	uint64_t data_bytes                  = 0;
	uint64_t metadata_bytes              = 0;
	uint64_t page_size                   = PageSize;
	uint32_t inode_limit                 = 0;
	uint32_t inodes                      = 0;
	uint32_t model_node_bytes            = 0;
	uint32_t model_directory_entry_bytes = 0;
};

class Handle;

void SetCredentials(uint32_t uid, uint32_t gid, uint32_t mask = 0);
int  Initialize(const std::string& scope);
void Shutdown();
int  NormalizePath(const std::string& path, std::string* normalized);
int  ValidateTraversal(const std::string& path);
bool Contains(const std::string& path);
bool Overlaps(const std::string& path);
int  Mount(const std::string& path, uint32_t mode, uint64_t byte_limit, uint32_t inode_limit,
           uint32_t uid = 0, uint32_t gid = 0);
int  QueryUsage(const std::string& path, Usage* usage);

int     Open(const std::string& path, int flags, uint32_t mode, std::shared_ptr<Handle>* handle);
int     Close(std::shared_ptr<Handle>& handle);
int64_t Read(const std::shared_ptr<Handle>& handle, void* data, uint64_t size);
int64_t Pread(const std::shared_ptr<Handle>& handle, void* data, uint64_t size, uint64_t offset);
int64_t Write(const std::shared_ptr<Handle>& handle, const void* data, uint64_t size);
int64_t Pwrite(const std::shared_ptr<Handle>& handle, const void* data, uint64_t size,
               uint64_t offset);
int64_t Seek(const std::shared_ptr<Handle>& handle, int64_t offset, int whence);
int     Truncate(const std::shared_ptr<Handle>& handle, uint64_t size);
int     Fstat(const std::shared_ptr<Handle>& handle, NodeStat* stat);
int     Entries(const std::shared_ptr<Handle>& handle, std::vector<DirectoryEntry>* entries);
int     Mkdir(const std::string& path, uint32_t mode);
int     Unlink(const std::string& path);
int     Rmdir(const std::string& path);
int     Rename(const std::string& from, const std::string& to);
int     ExportHandle(const std::shared_ptr<Handle>& handle, std::string* token);
int     ImportHandle(const std::string& token, std::shared_ptr<Handle>* handle);

} // namespace Libs::LibKernel::Tmpfs
#endif
