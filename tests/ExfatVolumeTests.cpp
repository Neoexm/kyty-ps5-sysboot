#include "kernel/exfatVolume.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#endif

using Volume = Libs::LibKernel::ExfatVolume;
using Backing = Libs::LibKernel::SectorBacking;
using Result = Volume::Result;

static void Check(bool value, const char* text) {
    if (!value) { std::fprintf(stderr, "ExfatVolumeTests: failed: %s\n", text); std::exit(1); }
}

static void Put16(std::vector<uint8_t>& bytes, size_t offset, uint16_t value) {
    bytes.at(offset) = static_cast<uint8_t>(value);
    bytes.at(offset + 1) = static_cast<uint8_t>(value >> 8);
}

static void Put32(std::vector<uint8_t>& bytes, size_t offset, uint32_t value) {
    Put16(bytes, offset, static_cast<uint16_t>(value));
    Put16(bytes, offset + 2, static_cast<uint16_t>(value >> 16));
}

static void Put64(std::vector<uint8_t>& bytes, size_t offset, uint64_t value) {
    Put32(bytes, offset, static_cast<uint32_t>(value));
    Put32(bytes, offset + 4, static_cast<uint32_t>(value >> 32));
}

static void BootChecksum(std::vector<uint8_t>& bytes) {
    for (size_t block: {size_t {0}, size_t {12 * 512}}) {
        uint32_t sum = 0;
        for (size_t i = 0; i < 11 * 512; ++i) {
            if (i != 106 && i != 107 && i != 112) sum = ((sum >> 1) | (sum << 31)) + bytes[block + i];
        }
        for (size_t i = 11 * 512; i < 12 * 512; i += 4) Put32(bytes, block + i, sum);
    }
}

static void SetChecksum(std::vector<uint8_t>& bytes, size_t offset) {
    const size_t size = (size_t(bytes.at(offset + 1)) + 1) * 32;
    uint16_t sum = 0;
    for (size_t i = 0; i < size; ++i) {
        if (i != 2 && i != 3) sum = static_cast<uint16_t>((sum >> 1) | (sum << 15)) + bytes.at(offset + i);
    }
    Put16(bytes, offset + 2, sum);
}

static std::vector<uint8_t> Fixture() {
    std::vector<uint8_t> bytes(2048 * 512);
    bytes[0] = 0xeb; bytes[1] = 0x76; bytes[2] = 0x90;
    std::memcpy(bytes.data() + 3, "EXFAT   ", 8);
    Put64(bytes, 72, 2048);
    Put32(bytes, 80, 24);
    Put32(bytes, 84, 16);
    Put32(bytes, 88, 40);
    Put32(bytes, 92, 2008);
    Put32(bytes, 96, 2);
    Put16(bytes, 104, 0x100);
    bytes[108] = 9; bytes[109] = 0; bytes[110] = 1;
    bytes[510] = 0x55; bytes[511] = 0xaa;
    for (size_t i = 1; i <= 8; ++i) Put32(bytes, (i + 1) * 512 - 4, 0xaa550000);
    std::copy_n(bytes.begin(), 12 * 512, bytes.begin() + 12 * 512);
    BootChecksum(bytes);
    Put32(bytes, 24 * 512, 0xfffffff8);
    Put32(bytes, 24 * 512 + 4, 0xffffffff);
    for (size_t cluster = 2; cluster <= 8; ++cluster) Put32(bytes, 24 * 512 + cluster * 4, 0xffffffff);
    Put32(bytes, 24 * 512 + 6 * 4, 8);
    bytes[41 * 512] = 0x7f;
    const std::array<uint16_t, 34> table = [] {
        std::array<uint16_t, 34> values {};
        values[0] = 0xffff; values[1] = 97;
        for (size_t i = 0; i < 26; ++i) values[i + 2] = static_cast<uint16_t>('A' + i);
        values[28] = 0xffff; values[29] = 65412;
        values[30] = 0xffff;
        return values;
    }();
    for (size_t i = 0; i < 31; ++i) Put16(bytes, 42 * 512 + i * 2, table[i]);
    uint32_t upper_sum = 0;
    for (size_t i = 0; i < 62; ++i) upper_sum = ((upper_sum >> 1) | (upper_sum << 31)) + bytes[42 * 512 + i];
    const size_t root = 40 * 512;
    bytes[root] = 0x81;
    Put32(bytes, root + 20, 3); Put64(bytes, root + 24, 251);
    bytes[root + 32] = 0x82;
    Put32(bytes, root + 36, upper_sum); Put32(bytes, root + 52, 4); Put64(bytes, root + 56, 62);
    const auto file = [&](size_t offset, const std::u16string& name, uint32_t first, uint64_t size, uint64_t valid, uint8_t flags, uint16_t attributes) {
        bytes[offset] = 0x85; bytes[offset + 1] = 2;
        Put16(bytes, offset + 4, attributes);
        bytes[offset + 32] = 0xc0; bytes[offset + 33] = flags; bytes[offset + 35] = static_cast<uint8_t>(name.size());
        uint16_t hash = 0;
        for (auto c: name) {
            if (c >= u'a' && c <= u'z') c -= 32;
            hash = static_cast<uint16_t>((hash >> 1) | (hash << 15)) + (c & 0xff);
            hash = static_cast<uint16_t>((hash >> 1) | (hash << 15)) + (c >> 8);
        }
        Put16(bytes, offset + 36, hash); Put64(bytes, offset + 40, valid);
        Put32(bytes, offset + 52, first); Put64(bytes, offset + 56, size);
        bytes[offset + 64] = 0xc1;
        for (size_t i = 0; i < name.size(); ++i) Put16(bytes, offset + 66 + i * 2, name[i]);
        SetChecksum(bytes, offset);
    };
    file(root + 64, u"hello.bin", 5, 5, 5, 3, 0x20);
    file(root + 160, u"chain.bin", 6, 700, 600, 1, 0x20);
    file(root + 256, u"sub", 7, 512, 512, 3, 0x10);
    file(45 * 512, u"empty", 0, 0, 0, 1, 0x20);
    std::memcpy(bytes.data() + 43 * 512, "HELLO", 5);
    std::fill_n(bytes.begin() + 44 * 512, 512, 0x61);
    std::fill_n(bytes.begin() + 46 * 512, 512, 0x62);
    return bytes;
}

#if defined(_WIN32)
static std::string Hash(const std::vector<uint8_t>& bytes) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::array<uint8_t, 32> value {};
    Check(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0 &&
          BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0 &&
          BCryptHashData(hash, const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0) >= 0 &&
          BCryptFinishHash(hash, value.data(), value.size(), 0) >= 0, "hash fixture");
    BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
    std::string text;
    for (const auto c: value) { text += "0123456789abcdef"[c >> 4]; text += "0123456789abcdef"[c & 15]; }
    return text;
}

static std::string Path8(const std::u16string& text) {
    const auto utf8 = std::filesystem::path(text).generic_u8string();
    return {reinterpret_cast<const char*>(utf8.data()), utf8.size()};
}

static void Audit(Volume& volume, const std::u16string& path, const std::filesystem::path& extracted, size_t* files, size_t* dirs, uint64_t* bytes) {
    std::vector<Volume::Entry> entries;
    Check(volume.List(path, &entries) == Result::Ok, "list directory");
    for (const auto& entry: entries) {
        if (entry.Directory()) { ++*dirs; Audit(volume, entry.path, extracted, files, dirs, bytes); continue; }
        ++*files;
        std::vector<uint8_t> chunk(1024 * 1024);
        std::vector<uint8_t> expected(chunk.size());
        std::ifstream source;
        if (!extracted.empty()) {
            const auto original = std::filesystem::path(L"\\\\?\\" + std::filesystem::absolute(extracted / std::filesystem::path(entry.path.substr(1))).wstring());
            std::error_code error;
            const auto size = std::filesystem::file_size(original, error);
            if (error || size != entry.size) std::fprintf(stderr, "EXFAT_COMPARE_FAILED path=%s error=%d\n", Path8(entry.path).c_str(), error.value());
            Check(!error && size == entry.size, "extracted original size matches stream");
            source.open(original, std::ios::binary);
            Check(source.is_open(), "open independently extracted original");
        }
        uint64_t read = 0;
        uint64_t fnv = 14695981039346656037ull;
        while (read < entry.size) {
            size_t actual = 0;
            Check(volume.Read(entry.path, read, chunk.data(), chunk.size(), &actual) == Result::Ok && actual, "read file data from sectors");
            if (source.is_open()) {
                source.read(reinterpret_cast<char*>(expected.data()), actual);
                Check(source.gcount() == static_cast<std::streamsize>(actual) && std::memcmp(chunk.data(), expected.data(), actual) == 0,
                      "every file byte matches independent extraction");
            }
            for (size_t i = 0; i < actual; ++i) { fnv ^= chunk[i]; fnv *= 1099511628211ull; }
            read += actual;
        }
        *bytes += read;
        std::printf("EXFAT_FILE %llu %016llx %s\n", static_cast<unsigned long long>(read), static_cast<unsigned long long>(fnv), Path8(entry.path).c_str());
    }
}
#endif

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IOLBF, 4096);
    std::setvbuf(stderr, nullptr, _IONBF, 0);
#if defined(_WIN32)
    if ((argc == 5 || argc == 6) && std::string(argv[1]) == "--image") {
        Backing::Result media_result;
        auto backing = Backing::Open(std::filesystem::u8path(argv[2]), {}, 4096, std::stoull(argv[3]), argv[4], &media_result);
        Check(backing && media_result == Backing::Result::Ok, "open SHA-bound image");
        Result result;
        auto volume = Volume::Open(std::move(backing), &result);
        std::printf("EXFAT_OPEN result=%u\n", static_cast<unsigned>(result));
        Check(volume && result == Result::Ok, "validate image filesystem");
        size_t files = 0, dirs = 0;
        uint64_t bytes = 0;
        Audit(*volume, u"/", argc == 6 ? std::filesystem::u8path(argv[5]) : std::filesystem::path {}, &files, &dirs, &bytes);
        std::printf("EXFAT_IMAGE files=%zu directories=%zu file_bytes=%llu source_bytes=%llu volume_bytes=%llu controller_activation=0 normal_boot=0\n", files, dirs,
            static_cast<unsigned long long>(bytes), static_cast<unsigned long long>(volume->SourceBytes()), static_cast<unsigned long long>(volume->Capacity()));
        return 0;
    }
    const auto root = std::filesystem::temp_directory_path() / ("kyty_exfat_test_" + std::to_string(GetCurrentProcessId()) + "_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    Check(std::filesystem::create_directory(root), "create fixture directory");
    unsigned sequence = 0;
    const auto open = [&](const std::vector<uint8_t>& bytes, Result* result, bool writable = false) {
        const auto path = root / (std::to_string(sequence++) + ".bin");
        { std::ofstream output(path, std::ios::binary); output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); Check(output.good(), "write fixture"); }
        Backing::Result media;
        auto backing = Backing::Open(path, writable ? root / (path.stem().string() + ".kytycow") : std::filesystem::path {}, 512, 2048 * 512, Hash(bytes), &media);
        Check(backing && media == Backing::Result::Ok, "open fixture backing");
        return Volume::Open(std::move(backing), result);
    };
    auto bytes = Fixture();
    Result result;
    auto volume = open(bytes, &result);
    Check(volume && result == Result::Ok, "validate fixture volume");
    std::array<uint8_t, 800> output;
    output.fill(0xa5);
    size_t actual = 91;
    Check(volume->Read(u"/HELLO.BIN", 0, output.data(), output.size(), &actual) == Result::Ok && actual == 5 &&
          std::memcmp(output.data(), "HELLO", 5) == 0 && output[5] == 0xa5, "case folding and EOF");
    Check(volume->Read(u"/chain.bin", 500, output.data(), output.size(), &actual) == Result::Ok && actual == 200 &&
          output[0] == 0x61 && output[11] == 0x61 && output[12] == 0x62 && output[99] == 0x62 &&
          std::all_of(output.begin() + 100, output.begin() + 200, [](auto c) { return c == 0; }), "fragmented file and exFAT valid-data zero range");
    std::vector<Volume::Entry> entries;
    Check(volume->List(u"/", &entries) == Result::Ok && entries.size() == 3 &&
          volume->List(u"/SUB", &entries) == Result::Ok && entries.size() == 1, "indexed nested directories");
    Check(volume->Read(u"/sub/empty", UINT64_MAX, nullptr, 0, &actual) == Result::Ok && actual == 0, "empty file and beyond EOF");
    Check(volume->Read(u"/", 0, output.data(), 1, &actual) == Result::IsDirectory &&
          volume->List(u"/hello.bin", &entries) == Result::NotDirectory &&
          volume->Read(u"/missing", 0, output.data(), 1, &actual) == Result::NotFound &&
          volume->Read(u"/sub/../hello.bin", 0, output.data(), 1, &actual) == Result::Invalid &&
          volume->Read(u"/hello.bin", 0, nullptr, 1, &actual) == Result::Invalid &&
          volume->Read(u"/hello.bin", 0, output.data(), 17 * 1024 * 1024, &actual) == Result::Invalid, "invalid operations");
    Volume::Entry unchanged {u"sentinel", 91, 17, 3};
    output.fill(0xa5); actual = 91;
    entries = {unchanged};
    Check(volume->Stat(u"/HELLO.BIN/child", &unchanged) == Result::NotDirectory && unchanged.path == u"sentinel" && unchanged.size == 91 &&
          volume->Read(u"/hello.bin/child", 0, output.data(), 1, &actual) == Result::NotDirectory && actual == 91 && output[0] == 0xa5 &&
          volume->List(u"/hello.bin/child", &entries) == Result::NotDirectory && entries.size() == 1 && entries[0].path == u"sentinel",
          "non-directory ancestor returns precise error without changing outputs");
    Check(!open(bytes, &result, true) && result == Result::Unsupported, "reject mutable backing for cached metadata");
    const auto corrupt = [&](const std::vector<uint8_t>& changed, Result expected, const char* label) {
        Check(!open(changed, &result) && result == expected, label);
    };
    auto extended = bytes;
    extended[40 * 512 + 352] = 0xa0;
    extended[40 * 512 + 358] = 1;
    SetChecksum(extended, 40 * 512 + 352);
    auto guid = open(extended, &result);
    Check(guid && result == Result::Ok && guid->Read(u"/hello.bin", 0, output.data(), output.size(), &actual) == Result::Ok && actual == 5,
          "optional Volume GUID preserves access to file data");
    guid.reset();
    auto malformed = extended;
    malformed[40 * 512 + 360] ^= 1;
    corrupt(malformed, Result::Corrupt, "Volume GUID set checksum corruption");
    malformed = extended;
    malformed[40 * 512 + 358] = 0; SetChecksum(malformed, 40 * 512 + 352);
    corrupt(malformed, Result::Corrupt, "null Volume GUID");
    malformed = extended;
    std::copy_n(malformed.begin() + 40 * 512 + 352, 32, malformed.begin() + 40 * 512 + 384);
    corrupt(malformed, Result::Corrupt, "duplicate Volume GUID");
    extended = bytes;
    std::copy_n(bytes.begin() + 40 * 512 + 160, 192, extended.begin() + 40 * 512 + 192);
    const size_t primary = 40 * 512 + 64, extra = primary + 96;
    std::fill_n(extended.begin() + extra, 32, 0);
    extended[primary + 1] = 3; extended[extra] = 0xe0; extended[extra + 2] = 1;
    SetChecksum(extended, primary);
    auto vendor = open(extended, &result);
    Check(vendor && result == Result::Ok && vendor->Read(u"/hello.bin", 0, output.data(), output.size(), &actual) == Result::Ok && actual == 5 &&
          vendor->List(u"/", &entries) == Result::Ok && entries.size() == 3, "vendor extension preserves file and neighboring entry sets");
    vendor.reset();
    malformed = extended; malformed[extra + 2] = 0; SetChecksum(malformed, primary);
    corrupt(malformed, Result::Corrupt, "null vendor GUID");
    malformed = extended; malformed[extra] = 0xc2; SetChecksum(malformed, primary);
    corrupt(malformed, Result::Unsupported, "unrecognized critical secondary cannot be ignored");
    malformed = extended; malformed[extra] = 0x60; SetChecksum(malformed, primary);
    corrupt(malformed, Result::Unsupported, "unused secondary cannot be ignored in live entry set");
    malformed = extended; malformed[extra] = 0xe1; malformed[extra + 1] = 3;
    Put32(malformed, extra + 20, 9); Put64(malformed, extra + 24, 5); SetChecksum(malformed, primary);
    malformed[41 * 512] = 0xff;
    auto allocation = open(malformed, &result);
    Check(allocation && result == Result::Ok, "benign vendor allocation claims independent contiguous extent");
    allocation.reset();
    auto bad_allocation = malformed; Put32(bad_allocation, extra + 20, 5); SetChecksum(bad_allocation, primary);
    corrupt(bad_allocation, Result::Corrupt, "vendor allocation cannot cross-link normal stream");
    bad_allocation = malformed; Put32(bad_allocation, extra + 20, 3); SetChecksum(bad_allocation, primary);
    corrupt(bad_allocation, Result::Corrupt, "vendor allocation cannot cross-link filesystem bitmap");
    bad_allocation = malformed; bad_allocation[41 * 512] = 0x7f;
    corrupt(bad_allocation, Result::Corrupt, "vendor allocation must reference allocated clusters");
    bad_allocation = malformed; Put64(bad_allocation, extra + 24, 0); SetChecksum(bad_allocation, primary);
    corrupt(bad_allocation, Result::Corrupt, "empty contiguous vendor allocation is invalid");
    extended = bytes;
    const size_t benign = 40 * 512 + 352;
    extended[benign] = 0xa2; Put16(extended, benign + 4, 3);
    Put32(extended, benign + 20, 9); Put64(extended, benign + 24, 5);
    extended[41 * 512] = 0xff; SetChecksum(extended, benign);
    auto unknown = open(extended, &result);
    Check(unknown && result == Result::Ok && unknown->List(u"/", &entries) == Result::Ok && entries.size() == 3,
          "unknown benign primary retains namespace and claims its allocation");
    unknown.reset();
    malformed = extended; Put32(malformed, benign + 20, 5); SetChecksum(malformed, benign);
    corrupt(malformed, Result::Corrupt, "benign primary allocation cannot cross-link file");
    malformed = extended; malformed[benign + 1] = 1; malformed[benign + 32] = 0x81;
    SetChecksum(malformed, benign);
    corrupt(malformed, Result::Unsupported, "metadata-looking secondary is not an independent root bitmap");
    malformed = extended; malformed[benign + 1] = 5; SetChecksum(malformed, benign);
    corrupt(malformed, Result::Corrupt, "benign primary set cannot overrun directory");
    extended = bytes;
    for (size_t boot: {size_t {0}, size_t {12 * 512}}) Put16(extended, boot + 104, 0x101);
    BootChecksum(extended);
    auto revision = open(extended, &result);
    Check(revision && result == Result::Ok, "compatible minor exFAT revision");
    revision.reset();
    for (size_t boot: {size_t {0}, size_t {12 * 512}}) Put16(extended, boot + 104, 0x200);
    BootChecksum(extended);
    corrupt(extended, Result::Unsupported, "unsupported major exFAT revision");
    auto changed = bytes; changed[120] ^= 1;
    corrupt(changed, Result::Corrupt, "boot checksum corruption");
    changed = bytes; changed[12 * 512 + 120] ^= 1;
    corrupt(changed, Result::Corrupt, "backup checksum corruption");
    changed = bytes; changed[12 * 512 + 510] = 0; BootChecksum(changed);
    corrupt(changed, Result::Corrupt, "backup signature with repaired checksum");
    changed = bytes; Put32(changed, 92, 3000); Put32(changed, 12 * 512 + 92, 3000); BootChecksum(changed);
    corrupt(changed, Result::Corrupt, "cluster heap capacity overflow");
    changed = bytes; changed[40 * 512 + 64 + 4] ^= 1;
    corrupt(changed, Result::Corrupt, "directory set checksum");
    changed = bytes; changed[40 * 512 + 64 + 36] ^= 1; SetChecksum(changed, 40 * 512 + 64);
    corrupt(changed, Result::Corrupt, "name hash with valid entry checksum");
    changed = bytes; changed[41 * 512] &= ~(1u << 3);
    corrupt(changed, Result::Corrupt, "stream references unallocated cluster");
    changed = bytes; Put32(changed, 24 * 512 + 6 * 4, 6);
    corrupt(changed, Result::Corrupt, "cycle in file FAT chain");
    changed = bytes; Put32(changed, 24 * 512 + 6 * 4, 0xffffffff);
    corrupt(changed, Result::Corrupt, "premature file EOC");
    changed = bytes; Put32(changed, 24 * 512 + 2 * 4, 2);
    corrupt(changed, Result::Corrupt, "cycle in root chain");
    changed = bytes; Put64(changed, 40 * 512 + 64 + 40, 6); SetChecksum(changed, 40 * 512 + 64);
    corrupt(changed, Result::Corrupt, "valid data exceeds file size");
    changed = bytes; changed[42 * 512] ^= 1;
    corrupt(changed, Result::Corrupt, "upcase checksum");
    changed = bytes; Put16(changed, 42 * 512 + 4, 'B');
    uint32_t repaired_upper = 0;
    for (size_t i = 0; i < 62; ++i) repaired_upper = ((repaired_upper >> 1) | (repaired_upper << 31)) + changed[42 * 512 + i];
    Put32(changed, 40 * 512 + 36, repaired_upper);
    corrupt(changed, Result::Corrupt, "invalid mandatory ASCII mapping with repaired checksum");
    changed = bytes; Put32(changed, 40 * 512 + 64 + 52, 3); SetChecksum(changed, 40 * 512 + 64);
    corrupt(changed, Result::Corrupt, "file cross-link into bitmap metadata");
    changed = bytes; changed[40 * 512 + 352] = 0x84;
    corrupt(changed, Result::Unsupported, "unknown critical entry");
    changed = bytes; changed[45 * 512 + 33] = 3; SetChecksum(changed, 45 * 512);
    corrupt(changed, Result::Corrupt, "empty stream cannot claim contiguous allocation");
    changed = bytes; changed.resize(46 * 512);
    auto partial = open(changed, &result);
    Check(partial && result == Result::Ok, "known metadata with missing file tail remains inspectable");
    output.fill(0xa5); actual = 91;
    Check(partial->Read(u"/chain.bin", 500, output.data(), 150, &actual) == Result::MissingData && actual == 91 &&
          std::all_of(output.begin(), output.end(), [](auto c) { return c == 0xa5; }), "missing second extent leaves entire caller output unchanged");
    Check(partial->Read(u"/chain.bin", 600, output.data(), 100, &actual) == Result::Ok && actual == 100 && output[0] == 0,
          "logical VDL zeroes do not read unknown physical tail");
    changed = bytes;
    std::copy(bytes.begin() + 40 * 512, bytes.end() - 16 * 512, changed.begin() + 56 * 512);
    std::copy_n(bytes.begin() + 24 * 512, 16 * 512, changed.begin() + 40 * 512);
    for (size_t boot: {size_t {0}, size_t {12 * 512}}) {
        Put32(changed, boot + 88, 56); Put32(changed, boot + 92, 1992);
        Put16(changed, boot + 106, 1); changed[boot + 110] = 2;
    }
    BootChecksum(changed);
    Put64(changed, 56 * 512 + 24, 249);
    changed[56 * 512 + 352] = 0x81; changed[56 * 512 + 353] = 1;
    Put32(changed, 56 * 512 + 372, 9); Put64(changed, 56 * 512 + 376, 249);
    changed[57 * 512] = 0xff; changed[63 * 512] = 0xff;
    Put32(changed, 40 * 512 + 9 * 4, 0xffffffff);
    Put32(changed, 24 * 512 + 6 * 4, 6);
    auto dual = open(changed, &result);
    Check(dual && result == Result::Ok && dual->Read(u"/chain.bin", 500, output.data(), 100, &actual) == Result::Ok && output[12] == 0x62,
          "active FAT and bitmap one selected despite invalid inactive FAT file chain");
    dual.reset();
    Put32(changed, 56 * 512 + 64 + 52, 3); SetChecksum(changed, 56 * 512 + 64);
    corrupt(changed, Result::Corrupt, "file cannot overlap inactive allocation bitmap");
    volume.reset(); partial.reset();
    std::error_code error;
    Check(std::filesystem::canonical(root).parent_path() == std::filesystem::canonical(std::filesystem::temp_directory_path()) &&
          root.filename().string().starts_with("kyty_exfat_test_"), "fixture cleanup stays within generated temporary directory");
    std::filesystem::remove_all(root, error);
    Check(!error, "release fixture handles");
    std::printf("ExfatVolumeTests: all cases passed controller_activation=0 normal_boot=0\n");
#else
    std::printf("ExfatVolumeTests: Windows sector backing unavailable\n");
#endif
    return 0;
}
