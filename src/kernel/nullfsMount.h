#ifndef KYTY_KERNEL_NULLFS_MOUNT_H_
#define KYTY_KERNEL_NULLFS_MOUNT_H_

#include <cstdint>
#include <string>
#include <vector>

namespace Libs::LibKernel::NullfsMount {

struct Resolution {
	std::string path;
	uint64_t    generation = 0;
	bool        mounted    = false;
	// MNT_RDONLY from any layer, since writes bypass to every lower mount; MNT_NOEXEC only from the
	// layer the path entered, as exec checks the vnode's own mount.
	bool read_only = false;
	bool no_exec   = false;
};

struct MountInfo {
	std::string point;
	std::string source;
	uint64_t    flags = 0;
};

constexpr uint64_t FlagReadOnly = 0x1;
constexpr uint64_t FlagNoExec   = 0x4;

int  Mount(const std::string& point, const std::string& source, uint64_t flags = 0);
int  SnapshotMounts(std::vector<MountInfo>* infos);
int  ImportMounts(const std::vector<MountInfo>& infos);
int  Unmount(const std::string& point);
void Shutdown();
bool Contains(const std::string& path);
bool IsMountPoint(const std::string& path);
bool Overlaps(const std::string& path);
int  Resolve(const std::string& path, Resolution* resolution);

} // namespace Libs::LibKernel::NullfsMount

#endif
