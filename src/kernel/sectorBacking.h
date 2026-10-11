#ifndef KYTY_KERNEL_SECTOR_BACKING_H_
#define KYTY_KERNEL_SECTOR_BACKING_H_

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>

namespace Libs::LibKernel {

class SectorBacking {
public:
	enum class Result { Ok, Invalid, Io, MissingData, ReadOnly, NoSpace, Unsupported };
	static std::unique_ptr<SectorBacking> Open(const std::filesystem::path& source,
	                                           const std::filesystem::path& overlay,
	                                           uint32_t sector_size, uint64_t capacity,
	                                           const std::string& sha256, Result* result);
	static std::unique_ptr<SectorBacking> OpenCapturedPrefix(const std::filesystem::path& source,
	                                                         const std::filesystem::path& overlay,
	                                                         const std::string&           sha256,
	                                                         Result*                      result);
	~SectorBacking();
	Result Read(uint64_t offset, void* bytes, size_t length);
	// Io can leave an indeterminate write if both persistence and rollback fail.
	Result   Write(uint64_t offset, const void* bytes, size_t length);
	uint64_t Capacity() const;
	uint64_t SourceBytes() const;
	uint32_t SectorSize() const;
	bool     ReadOnly() const;
#if defined(KYTY_SECTOR_BACKING_TESTING)
	void FailNextCommit(bool flush, bool rollback);
#endif
	SectorBacking(const SectorBacking&)            = delete;
	SectorBacking& operator=(const SectorBacking&) = delete;

private:
	struct State;
	static std::unique_ptr<SectorBacking> OpenInternal(const std::filesystem::path& source,
	                                                   const std::filesystem::path& overlay,
	                                                   uint32_t sector_size, uint64_t capacity,
	                                                   const std::string& sha256, Result* result,
	                                                   bool captured_prefix);
	explicit SectorBacking(std::unique_ptr<State> state);
	std::unique_ptr<State> m_state;
};

} // namespace Libs::LibKernel
#endif
