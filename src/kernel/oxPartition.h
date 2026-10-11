#ifndef KYTY_PS5_KERNEL_OX_PARTITION_H_
#define KYTY_PS5_KERNEL_OX_PARTITION_H_

#include "common/common.h"

#include <array>

namespace Libs::LibKernel::OxPartition {

struct Header {
	uint8_t  bank             = 0;
	uint32_t selected_mbr_lba = 0;
	uint32_t status_lba       = 0;
};

struct Entry {
	uint8_t  raw_type     = 0;
	bool     alternate    = false;
	uint64_t start_lba    = 0;
	uint32_t sector_count = 0;
};

bool        ReadHeader(const void* sector0, size_t sector0_size, const void* status_sector,
                       size_t status_size, Header* header);
bool        ReadEntries(const void* mbr, size_t mbr_size, uint32_t selected_mbr_lba,
                        std::array<Entry, 16>* entries, size_t* count);
const char* SystemName(const Entry& entry);

} // namespace Libs::LibKernel::OxPartition

#endif
