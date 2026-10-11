#ifndef KYTY_KERNEL_CAPTURED_METADATA_CACHE_H_
#define KYTY_KERNEL_CAPTURED_METADATA_CACHE_H_

#include "kernel/authInfo.h"

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Libs::LibKernel::CapturedMetadataCache {
struct SourceStamp {
	std::filesystem::path path;
	uint64_t              size        = 0;
	int64_t               write_time  = 0;
	int64_t               change_time = 0;
	uint64_t              volume_id   = 0;
	uint64_t              file_id     = 0;
};
struct Key {
	std::filesystem::path    file;
	std::string              kind;
	std::string              discriminator;
	std::string              build_id;
	std::vector<SourceStamp> sources;
	AuthInfo::Digest         digest {};
	uint64_t                 payload_limit = 0;
	bool                     enabled       = false;
};
class Writer {
public:
	void                        U8(uint8_t value);
	void                        U32(uint32_t value);
	void                        U64(uint64_t value);
	void                        I64(int64_t value);
	void                        String(std::string_view value);
	void                        Path(const std::filesystem::path& value);
	const std::vector<uint8_t>& Bytes() const { return bytes; }

private:
	std::vector<uint8_t> bytes;
};
} // namespace Libs::LibKernel::CapturedMetadataCache
#endif
