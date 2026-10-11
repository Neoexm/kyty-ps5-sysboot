#ifndef KYTY_KERNEL_EXFAT_VOLUME_H_
#define KYTY_KERNEL_EXFAT_VOLUME_H_

#include "kernel/sectorBacking.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Libs::LibKernel {
class ExfatVolume {
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
		std::u16string path;
		uint64_t       size           = 0;
		uint64_t       valid_size     = 0;
		uint16_t       attributes     = 0;
		uint64_t       allocated_size = 0;
		bool           Directory() const { return (attributes & 0x10) != 0; }
	};

	static std::unique_ptr<ExfatVolume> Open(std::shared_ptr<SectorBacking> backing,
	                                         Result*                        result);
	~ExfatVolume();
	Result   Stat(const std::u16string& path, Entry* entry) const;
	Result   List(const std::u16string& path, std::vector<Entry>* entries) const;
	Result   Read(const std::u16string& path, uint64_t offset, void* bytes, size_t length,
	              size_t* actual) const;
	uint64_t Capacity() const;
	uint64_t SourceBytes() const;
	ExfatVolume(const ExfatVolume&)            = delete;
	ExfatVolume& operator=(const ExfatVolume&) = delete;

private:
	struct State;
	explicit ExfatVolume(std::unique_ptr<State> state);
	std::unique_ptr<State> m_state;
};
} // namespace Libs::LibKernel
#endif
