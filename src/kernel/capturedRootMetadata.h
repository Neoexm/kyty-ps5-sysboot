#ifndef KYTY_KERNEL_CAPTURED_ROOT_METADATA_H_
#define KYTY_KERNEL_CAPTURED_ROOT_METADATA_H_

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace Libs::LibKernel::FileSystem {
struct FileStat;
}
namespace Libs::LibKernel::CapturedRootMetadata {
struct Directory {
	std::string path;
	uint32_t    inode      = 0;
	uint32_t    mode       = 0;
	uint32_t    uid        = 0;
	uint32_t    gid        = 0;
	uint32_t    block_size = 0;
	uint64_t    size       = 0;
	uint32_t    flags      = 0;
};
bool Enabled();
int  Stat(const std::string& path, FileSystem::FileStat* stat);
} // namespace Libs::LibKernel::CapturedRootMetadata
#endif
