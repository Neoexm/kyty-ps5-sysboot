#ifndef EMULATOR_INCLUDE_EMULATOR_KERNEL_TMPFS_H_
#define EMULATOR_INCLUDE_EMULATOR_KERNEL_TMPFS_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Libs::LibKernel::Tmpfs {
inline constexpr uint64_t PageSize          = 16384;
inline constexpr uint64_t MaximumMountBytes = 16 * 1024 * 1024;
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
} // namespace Libs::LibKernel::Tmpfs
#endif
