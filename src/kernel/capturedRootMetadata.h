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

struct Layout {
	uint64_t virtual_base      = 0;
	size_t   filesystem_offset = 0;
	size_t   nodes_offset      = 0;
	size_t   node_count        = 0;
};

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

struct Snapshot {
	std::vector<Directory> directories;
	size_t                 root_node_count = 0;
};

int  Decode(std::span<const uint8_t> image, const Layout& layout, Snapshot* snapshot);
int  Lookup(const Snapshot& snapshot, const std::string& path, FileSystem::FileStat* stat);
int  Load(const std::filesystem::path& image);
void Shutdown();
bool Enabled();
bool LastLoadUsedStartupCache();
int  Stat(const std::string& path, FileSystem::FileStat* stat);

} // namespace Libs::LibKernel::CapturedRootMetadata
#endif
