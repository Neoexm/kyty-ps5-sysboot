#include "kernel/oxPartition.h"

#include <cstring>

namespace Libs::LibKernel::OxPartition {
namespace {
uint32_t Dword(const uint8_t* data) {
	uint32_t value = 0;
	std::memcpy(&value, data, sizeof(value));
	return value;
}
} // namespace

bool ReadHeader(const void* sector0, size_t sector0_size, const void* status_sector,
                size_t status_size, Header* header) {
	static constexpr char signature[] = "SONY COMPUTER ENTERTAINMENT INC.";
	if (sector0 == nullptr || status_sector == nullptr || header == nullptr ||
	    sector0_size < 0x3c || status_size == 0)
		return false;
	const auto* bytes = static_cast<const uint8_t*>(sector0);
	if (std::memcmp(bytes, signature, sizeof(signature) - 1) != 0 || Dword(bytes + 0x2c) != 1 ||
	    Dword(bytes + 0x30) != 1 || Dword(bytes + 0x38) != 1)
		return false;
	const uint8_t bank       = static_cast<const uint8_t*>(status_sector)[0] >> 7;
	header->bank             = bank;
	header->selected_mbr_lba = Dword(bytes + 0x24 + bank * 4);
	header->status_lba       = Dword(bytes + 0x34);
	return header->selected_mbr_lba != 0 && header->status_lba != 0;
}

bool ReadEntries(const void* mbr, size_t mbr_size, uint32_t selected_mbr_lba,
                 std::array<Entry, 16>* entries, size_t* count) {
	static constexpr char signature[] = "Sony Computer Entertainment Inc.";
	if (mbr == nullptr || entries == nullptr || count == nullptr || mbr_size < 0x180 ||
	    selected_mbr_lba == 0)
		return false;
	const auto* bytes = static_cast<const uint8_t*>(mbr);
	if (std::memcmp(bytes, signature, sizeof(signature) - 1) != 0) return false;
	*entries = {};
	*count   = 0;
	for (size_t i = 0; i < entries->size(); ++i) {
		const auto*    source   = bytes + 0x40 + i * 0x14;
		const uint32_t relative = Dword(source);
		const uint32_t sectors  = Dword(source + 4);
		if (relative == 0 || sectors == 0) continue;
		const uint64_t start = static_cast<uint64_t>(selected_mbr_lba) + relative;
		if (start + sectors - 1 < start) return false;
		auto& entry        = (*entries)[(*count)++];
		entry.raw_type     = source[8];
		entry.alternate    = (source[9] & 1) == 0;
		entry.start_lba    = start;
		entry.sector_count = sectors;
	}
	return true;
}

const char* SystemName(const Entry& entry) {
	if (entry.raw_type == 4) return entry.alternate ? "system_b" : "system";
	if (entry.raw_type == 5) return entry.alternate ? "system_ex_b" : "system_ex";
	return nullptr;
}

} // namespace Libs::LibKernel::OxPartition
