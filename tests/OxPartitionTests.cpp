#include "kernel/oxPartition.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {
void Check(bool value, const char* text) {
	if (!value) { std::fprintf(stderr, "OxPartitionTests: %s\n", text); std::abort(); }
}

void Store32(uint8_t* data, size_t offset, uint32_t value) {
	std::memcpy(data + offset, &value, sizeof(value));
}
}

int main() {
	using namespace Libs::LibKernel::OxPartition;
	std::array<uint8_t, 512> sector0 {};
	std::array<uint8_t, 512> status {};
	std::memcpy(sector0.data(), "SONY COMPUTER ENTERTAINMENT INC.", 32);
	Store32(sector0.data(), 0x24, 0x100);
	Store32(sector0.data(), 0x28, 0x200);
	Store32(sector0.data(), 0x2c, 1);
	Store32(sector0.data(), 0x30, 1);
	Store32(sector0.data(), 0x34, 0x80);
	Store32(sector0.data(), 0x38, 1);
	Header header;
	Check(ReadHeader(sector0.data(), sector0.size(), status.data(), status.size(), &header) &&
	      header.bank == 0 && header.selected_mbr_lba == 0x100 && header.status_lba == 0x80, "bank zero header");
	status[0] = 0x80;
	Check(ReadHeader(sector0.data(), sector0.size(), status.data(), status.size(), &header) &&
	      header.bank == 1 && header.selected_mbr_lba == 0x200, "bank one header");
	sector0[0] = 0;
	Check(!ReadHeader(sector0.data(), sector0.size(), status.data(), status.size(), &header), "header signature");
	sector0[0] = 'S';

	std::array<uint8_t, 512> mbr {};
	std::memcpy(mbr.data(), "Sony Computer Entertainment Inc.", 32);
	Store32(mbr.data(), 0x40, 0x20);
	Store32(mbr.data(), 0x44, 0x300);
	mbr[0x48] = 4;
	mbr[0x49] = 1;
	Store32(mbr.data(), 0x54, 0x400);
	Store32(mbr.data(), 0x58, 0x500);
	mbr[0x5c] = 5;
	mbr[0x5d] = 0;
	std::array<Entry, 16> entries {};
	size_t count = 0;
	Check(ReadEntries(mbr.data(), mbr.size(), 0x200, &entries, &count) && count == 2, "entry table");
	Check(entries[0].start_lba == 0x220 && entries[0].sector_count == 0x300 &&
	      std::strcmp(SystemName(entries[0]), "system") == 0, "unsuffixed system entry");
	Check(entries[1].start_lba == 0x600 && entries[1].sector_count == 0x500 &&
	      std::strcmp(SystemName(entries[1]), "system_ex_b") == 0, "alternate system_ex entry");
	mbr[0] = 0;
	Check(!ReadEntries(mbr.data(), mbr.size(), 0x200, &entries, &count), "mbr signature");
	return 0;
}
