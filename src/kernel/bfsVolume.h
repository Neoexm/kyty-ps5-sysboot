#ifndef KYTY_KERNEL_BFS_VOLUME_H_
#define KYTY_KERNEL_BFS_VOLUME_H_

#include "kernel/sectorBacking.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Libs::LibKernel {
class BfsVolume {
public:
	enum class Result {
		Ok,
		Invalid,
		Corrupt,
		MissingData,
		Io,
		NotFound,
		NotDirectory,
		IsDirectory,
		Unsupported
	};

	struct Entry {
		std::string path;
		uint64_t    size      = 0;
		uint32_t    mode      = 0;
		uint32_t    inode     = 0;
		bool        directory = false;
	};

	struct Options {
		// Named partition selector. Empty = first superblock found.
		std::string partition_name;
	};

	static std::unique_ptr<BfsVolume> Open(std::shared_ptr<SectorBacking> backing,
	                                       const Options& options, Result* result);

	~BfsVolume();

	Result Stat(const std::string& path, Entry* entry) const;
	Result List(const std::string& path, std::vector<Entry>* entries) const;
	Result Read(const std::string& path, uint64_t offset, void* bytes, size_t length,
	            size_t* actual) const;

	uint64_t Capacity() const;
	uint64_t SourceBytes() const;

	// Superblock bit sceFsBfsCheckCleanFlag tests. False = not shut down cleanly; sub_402340 then
	// sets dword_4D7520=1 and returns -1.
	bool CleanFlagSet() const;

	const std::string& SelectedPartitionName() const;

	BfsVolume(const BfsVolume&)            = delete;
	BfsVolume& operator=(const BfsVolume&) = delete;

private:
	struct State;
	explicit BfsVolume(std::unique_ptr<State> state);
	std::unique_ptr<State> m_state;
};
} // namespace Libs::LibKernel
#endif
