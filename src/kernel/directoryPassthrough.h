#ifndef KYTY_KERNEL_DIRECTORY_PASSTHROUGH_H_
#define KYTY_KERNEL_DIRECTORY_PASSTHROUGH_H_

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace Libs::LibKernel::DirectoryPassthrough {
struct NodeStat {
	uint32_t device         = 0;
	uint32_t inode          = 0;
	uint32_t mode           = 0;
	uint64_t size           = 0;
	uint64_t allocated_size = 0;
	uint32_t uid            = 0;
	uint32_t gid            = 0;
	int64_t  mtime          = 0;
	bool     captured       = false;
};
struct DirectoryEntry {
	uint32_t    inode     = 0;
	bool        directory = false;
	std::string name;
	uint8_t     type = 0;
};

class Handle;
struct FileSnapshot {
	std::filesystem::path   host_path;
	std::shared_ptr<Handle> handle;
	std::vector<uint8_t>    bytes;
};
struct MountInfo {
	std::string              point;
	std::filesystem::path    host_root;
	uint32_t                 device = 0;
	std::string              manifest_sha256;
	std::vector<std::string> fallback_prefixes;
	std::string              fallback_manifest_sha256;
	bool                     writable = false;
	std::string              guest_fstype;
	std::string              guest_source;
	uint64_t                 guest_flags = 0;
};
int  Mount(const std::string& point, const std::filesystem::path& host_root, bool writable = false,
           const std::string& guest_fstype = {}, const std::string& guest_source = {},
           uint64_t guest_flags = 0);
int  AttachCapturedFallback(const std::string& point, const std::string& prefix,
                            const std::string& manifest_sha256);
int  DescribeMount(const std::string& point, MountInfo* info);
int  Unmount(const std::string& point);
bool Contains(const std::string& path, bool captured_only = false);
bool Overlaps(const std::string& path);
int  ValidateTraversal(const std::string& path);
int  Close(std::shared_ptr<Handle>& handle);
int  Stat(const std::string& path, NodeStat* stat);
int64_t Pread(const std::shared_ptr<Handle>& handle, void* data, size_t length, uint64_t offset);
int64_t Seek(const std::shared_ptr<Handle>& handle, int64_t offset, int whence);
int     Truncate(const std::shared_ptr<Handle>& handle, uint64_t length);
int     Mkdir(const std::string& path, uint32_t mode);
int     Rmdir(const std::string& path);
int     Unlink(const std::string& path);
int     Rename(const std::string& from, const std::string& to);
} // namespace Libs::LibKernel::DirectoryPassthrough
#endif
