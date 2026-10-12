// Synthetic BFS image: block=0x10000, inode=0x100, metadata TLV at +64 of block 0 (tags 1/0x100/0x1000/0), SB magic 0x20F50BF520190705, clean bit 0x40 at SB+16, 256-byte partition name at SB+32, dinode magic 0xBF10 at inode+0 (mode +16, size +40, first direct LBN +128), dirent 16-byte header + 8-byte-padded name. NON_AUTHENTIC parser fixture.
#include "kernel/bfsVolume.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#endif

using Volume = Libs::LibKernel::BfsVolume;
using Backing = Libs::LibKernel::SectorBacking;
using Result = Volume::Result;

static void Check(bool value, const char* text) {
    if (!value) { std::fprintf(stderr, "BfsVolumeTests: failed: %s\n", text); std::exit(1); }
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

static constexpr size_t Block = 0x10000;
static constexpr size_t InodeSize = 0x100;
static constexpr uint64_t MetadataMagic = 0x10F50BF520180705ULL;
static constexpr uint64_t SbMagicCurrent = 0x20F50BF520190705ULL;
static constexpr uint64_t SbMagicLegacy  = 0x20F50BF520180713ULL;

static void WriteInode(std::vector<uint8_t>& bytes, size_t offset, uint32_t mode, uint64_t size, uint32_t nblocks, uint32_t nlink, uint32_t first_direct) {
    Put32(bytes, offset + 0, 0xBF10);
    Put32(bytes, offset + 16, mode);
    Put64(bytes, offset + 40, size);
    Put32(bytes, offset + 48, nblocks);
    Put32(bytes, offset + 56, nlink);
    Put32(bytes, offset + 128, first_direct);
}

static size_t EmitDirent(std::vector<uint8_t>& bytes, size_t offset, uint32_t ino, uint32_t reclen, uint8_t type, const std::string& name) {
    Put32(bytes, offset + 0, ino);
    Put32(bytes, offset + 8, reclen);
    bytes.at(offset + 12) = static_cast<uint8_t>(name.size());
    bytes.at(offset + 14) = type;
    std::copy(name.begin(), name.end(), bytes.begin() + offset + 16);
    return offset + reclen;
}

static std::vector<uint8_t> Fixture(uint64_t sb_magic = SbMagicCurrent, const std::string& partition = "ssd0.user", uint8_t sb_flags = 0x40) {
    std::vector<uint8_t> bytes(32 * Block);

    Put64(bytes, 0, MetadataMagic);

    size_t cursor = 64;
    Put16(bytes, cursor + 0, 1); Put16(bytes, cursor + 2, 4);
    Put32(bytes, cursor + 8, 1);
    cursor += 8 + 4;

    Put16(bytes, cursor + 0, 0x100); Put16(bytes, cursor + 2, 32);
    Put32(bytes, cursor + 8 + 0, 2);
    Put32(bytes, cursor + 8 + 4, 1);
    cursor += 8 + 32;

    Put16(bytes, cursor + 0, 0x1000); Put16(bytes, cursor + 2, 4);
    Put32(bytes, cursor + 8, 16);
    cursor += 8 + 4;

    // tag 0 terminator written implicitly by the zero-initialised buffer

    Put64(bytes, 1 * Block + 0, sb_magic);
    bytes.at(1 * Block + 16) = sb_flags;
    std::copy(partition.begin(), partition.end(), bytes.begin() + 1 * Block + 32);

    const size_t inode_base = 2 * Block;
    WriteInode(bytes, inode_base + 2 * InodeSize, 0040755, 0x10000, 1, 2, 3);
    WriteInode(bytes, inode_base + 3 * InodeSize, 0100644, 5,       1, 1, 4);
    WriteInode(bytes, inode_base + 4 * InodeSize, 0040755, 0x10000, 1, 2, 5);

    const size_t root_dir = 3 * Block;
    size_t pos = root_dir;
    pos = EmitDirent(bytes, pos, 2, 24, 4, ".");
    pos = EmitDirent(bytes, pos, 2, 24, 4, "..");
    pos = EmitDirent(bytes, pos, 3, 32, 8, "greet.txt");
    EmitDirent(bytes, pos, 4, static_cast<uint32_t>(root_dir + Block - pos), 4, "lost+found");

    std::memcpy(bytes.data() + 4 * Block, "HELLO", 5);

    const size_t lost_dir = 5 * Block;
    EmitDirent(bytes, lost_dir, 4, static_cast<uint32_t>(Block), 4, ".");

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
#endif

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IOLBF, 4096);
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    if (argc == 3 && std::strcmp(argv[1], "--write") == 0) {
        const auto bytes = Fixture();
        std::ofstream output(argv[2], std::ios::binary);
        output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        if (!output.good()) { std::fprintf(stderr, "BfsVolumeTests: write failed: %s\n", argv[2]); return 1; }
        std::printf("BfsVolumeTests: wrote NON_AUTHENTIC fixture %zu bytes -> %s\n", bytes.size(), argv[2]);
        return 0;
    }
#if defined(_WIN32)
    const auto root = std::filesystem::temp_directory_path() / ("kyty_bfs_test_" + std::to_string(GetCurrentProcessId()) + "_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    Check(std::filesystem::create_directory(root), "create fixture directory");
    unsigned sequence = 0;
    const auto open = [&](const std::vector<uint8_t>& bytes, const Volume::Options& options, Result* result) {
        const auto path = root / (std::to_string(sequence++) + ".bin");
        { std::ofstream output(path, std::ios::binary); output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); Check(output.good(), "write fixture"); }
        Backing::Result media;
        auto backing = Backing::Open(path, {}, 512, bytes.size(), Hash(bytes), &media);
        Check(backing && media == Backing::Result::Ok, "open fixture backing");
        return Volume::Open(std::move(backing), options, result);
    };

    auto bytes = Fixture();
    Result result;
    Volume::Options options {};
    auto volume = open(bytes, options, &result);
    Check(volume && result == Result::Ok, "open current-magic fixture");
    Check(volume->CleanFlagSet(), "clean bit observed from SB flags");
    Check(volume->SelectedPartitionName() == "ssd0.user", "partition name decoded from SB");

    std::vector<Volume::Entry> entries;
    Check(volume->List("/", &entries) == Result::Ok, "list root");
    Check(entries.size() == 2, "root entry count after . and .. filtered");
    const auto find = [&](const std::string& name) {
        return std::find_if(entries.begin(), entries.end(), [&](const Volume::Entry& e) { return e.path == name; });
    };
    Check(find("greet.txt") != entries.end() && !find("greet.txt")->directory, "greet.txt is a regular file");
    Check(find("lost+found") != entries.end() && find("lost+found")->directory, "lost+found is a directory");

    Volume::Entry stat {};
    Check(volume->Stat("/lost+found", &stat) == Result::Ok && stat.directory && stat.inode == 4, "stat subdirectory");
    Check(volume->Stat("/greet.txt", &stat) == Result::Ok && !stat.directory && stat.size == 5 && stat.inode == 3, "stat regular file");

    std::array<uint8_t, 16> buffer {};
    buffer.fill(0xa5);
    size_t actual = 91;
    Check(volume->Read("/greet.txt", 0, buffer.data(), buffer.size(), &actual) == Result::Ok && actual == 5 &&
          std::memcmp(buffer.data(), "HELLO", 5) == 0 && buffer[5] == 0xa5, "read short file and stop at EOF");

    Check(volume->Read("/greet.txt", 10, buffer.data(), buffer.size(), &actual) == Result::Ok && actual == 0, "read past EOF returns zero bytes");
    Check(volume->Read("/missing", 0, buffer.data(), 1, &actual) == Result::NotFound, "lookup miss");
    Check(volume->Read("/", 0, buffer.data(), 1, &actual) == Result::IsDirectory, "cannot read root directory");
    Check(volume->List("/greet.txt", &entries) == Result::NotDirectory, "cannot list a file");

    volume.reset();

    auto legacy_bytes = Fixture(SbMagicLegacy);
    auto legacy = open(legacy_bytes, options, &result);
    Check(legacy && result == Result::Ok, "legacy SB magic still accepted");
    Check(legacy->SelectedPartitionName() == "ssd0.user", "legacy SB name decoded");
    legacy.reset();

    auto dirty_bytes = Fixture(SbMagicCurrent, "ssd0.user", 0x00);
    auto dirty = open(dirty_bytes, options, &result);
    Check(dirty && result == Result::Ok && !dirty->CleanFlagSet(), "dirty flag observed, mount still returns the volume");
    dirty.reset();

    Volume::Options named {}; named.partition_name = "ssd0.user";
    auto named_volume = open(bytes, named, &result);
    Check(named_volume && result == Result::Ok, "named partition selector matches");
    named_volume.reset();

    Volume::Options missing {}; missing.partition_name = "ssd0.update";
    Check(!open(bytes, missing, &result) && result == Result::NotFound, "named partition selector fails loudly on mismatch");

    auto corrupt_metadata = bytes;
    corrupt_metadata[0] ^= 0xff;
    Check(!open(corrupt_metadata, options, &result) && result == Result::Invalid, "metadata magic mismatch rejected");

    auto bad_sb = bytes;
    Put64(bad_sb, 1 * Block + 0, 0xdeadbeefdeadbeefULL);
    Check(!open(bad_sb, options, &result) && result == Result::Invalid, "no superblock with recognised magic");

    auto bad_root = bytes;
    Put32(bad_root, 2 * Block + 2 * InodeSize + 0, 0);
    Check(!open(bad_root, options, &result) && result == Result::Corrupt, "root inode missing dinode magic");

    auto not_a_dir = bytes;
    Put32(not_a_dir, 2 * Block + 2 * InodeSize + 16, 0100644);
    Check(!open(not_a_dir, options, &result) && result == Result::Corrupt, "root inode must be a directory");

    auto oversized_division = bytes;
    Put32(oversized_division, 88, UINT32_MAX);
    Check(!open(oversized_division, options, &result) && result == Result::Corrupt, "inode division cannot exceed backing");

    auto empty_division = bytes;
    Put32(empty_division, 88, 0);
    Check(!open(empty_division, options, &result) && result == Result::Corrupt, "empty inode division rejected");

    auto mismatched_type = bytes;
    mismatched_type[3 * Block + 48 + 14] = 4;
    auto mismatched = open(mismatched_type, options, &result);
    Check(mismatched && mismatched->Stat("/greet.txt", &stat) == Result::Corrupt, "directory type must match inode mode");
    mismatched.reset();

    auto hidden_directory = bytes;
    hidden_directory[3 * Block + 80 + 14] = 8;
    auto hidden = open(hidden_directory, options, &result);
    Check(hidden && hidden->Read("/lost+found", 0, buffer.data(), 1, &actual) == Result::Corrupt && actual == 0, "directory data cannot be exposed as a regular file");
    hidden.reset();

    auto unsupported_mode = bytes;
    Put32(unsupported_mode, 2 * Block + 3 * InodeSize + 16, 0120777);
    auto unsupported = open(unsupported_mode, options, &result);
    Check(unsupported && unsupported->Read("/greet.txt", 0, buffer.data(), 1, &actual) == Result::Unsupported && actual == 0, "unsupported inode type is not read as a regular file");
    unsupported.reset();

    auto large_file = bytes;
    Put64(large_file, 2 * Block + 3 * InodeSize + 40, 2 * Block);
    auto large = open(large_file, options, &result);
    Check(large && large->Read("/greet.txt", Block + 1, nullptr, 0, &actual) == Result::Ok && actual == 0, "empty read does not require a supported extent");
    Check(large->Read("/greet.txt", Block, buffer.data(), 1, &actual) == Result::Unsupported && actual == 0, "unrecovered second extent fails explicitly");
    large.reset();

    auto concurrent = open(bytes, options, &result);
    Check(concurrent != nullptr, "open concurrent volume");
    std::atomic<bool> start {false};
    std::array<std::thread, 6> workers;
    for (auto& worker: workers) {
        worker = std::thread([&] {
            while (!start.load()) std::this_thread::yield();
            for (unsigned i = 0; i < 128; ++i) {
                Volume::Entry node {};
                std::vector<Volume::Entry> children;
                std::array<uint8_t, 5> data {};
                size_t count = 0;
                Check(concurrent->Stat("/greet.txt", &node) == Result::Ok && node.size == 5, "concurrent stat");
                Check(concurrent->List("/", &children) == Result::Ok && children.size() == 2, "concurrent directory cache");
                Check(concurrent->Read("/greet.txt", 0, data.data(), data.size(), &count) == Result::Ok && count == 5 && std::memcmp(data.data(), "HELLO", 5) == 0, "concurrent file read");
            }
        });
    }
    start.store(true);
    for (auto& worker: workers) worker.join();
    concurrent.reset();

    std::printf("BfsVolumeTests: ok\n");
#endif
    return 0;
}
