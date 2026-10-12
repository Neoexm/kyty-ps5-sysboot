#ifndef KYTY_KERNEL_BFS_MOUNT_H_
#define KYTY_KERNEL_BFS_MOUNT_H_

#include "kernel/bfsVolume.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Libs::LibKernel::BfsMount {

struct NodeStat {
	uint32_t device         = 0;
	uint32_t inode          = 0;
	uint32_t mode           = 0;
	uint64_t size           = 0;
	uint64_t allocated_size = 0;
};

struct DirectoryEntry {
	uint32_t    inode     = 0;
	bool        directory = false;
	std::string name;
};

class Handle;

int     Mount(const std::string& point, std::shared_ptr<BfsVolume> volume);
int     Unmount(const std::string& point);
void    Shutdown();
bool    Contains(const std::string& path);
bool    Overlaps(const std::string& path);
int     ValidateTraversal(const std::string& path);
int     Open(const std::string& path, int flags, std::shared_ptr<Handle>* handle);
int     Close(std::shared_ptr<Handle>& handle);
int     Stat(const std::string& path, NodeStat* stat);
int     Fstat(const std::shared_ptr<Handle>& handle, NodeStat* stat);
int     Entries(const std::shared_ptr<Handle>& handle, std::vector<DirectoryEntry>* entries);
int64_t Read(const std::shared_ptr<Handle>& handle, void* data, size_t length);
int64_t Pread(const std::shared_ptr<Handle>& handle, void* data, size_t length, uint64_t offset);
int64_t Seek(const std::shared_ptr<Handle>& handle, int64_t offset, int whence);

} // namespace Libs::LibKernel::BfsMount
#endif
