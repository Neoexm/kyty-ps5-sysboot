#include "kernel/sectorBacking.h"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>
#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#endif

using Backing = Libs::LibKernel::SectorBacking;
using Result = Backing::Result;
constexpr const char* FixtureHash = "785b0751fc2c53dc14a4ce3d800e69ef9ce1009eb327ccf458afe09c242c26c9";

static void Check(bool value, const char* text) {
    if (!value) { std::fprintf(stderr, "SectorBackingTests: failed: %s\n", text); std::abort(); }
}

int main(int argc, char** argv) {
#if defined(_WIN32)
    if (argc == 6 && std::string(argv[1]) == "--image") {
        Result result;
        const auto image = Backing::Open(std::filesystem::u8path(argv[2]), {}, 4096, std::stoull(argv[3]), argv[4], &result);
        Check(image && result == Result::Ok, "verified image opens read-only");
        std::array<uint8_t, 4096> first {}, end {};
        Check(image->Read(0, first.data(), first.size()) == Result::Ok &&
              image->Read(image->SourceBytes() - end.size(), end.data(), end.size()) == Result::Ok,
              "read first and final supplied sectors");
        end.fill(0xa5);
        Check(image->Read(image->SourceBytes(), end.data(), end.size()) == Result::MissingData && end.front() == 0xa5,
              "omitted original tail remains unavailable");
        Check(image->Write(0, first.data(), first.size()) == Result::ReadOnly, "source cannot be modified");
        std::printf("SectorBackingTests: image_verified source_bytes=%llu capacity=%llu unknown_tail_rejected=1 label=%s\n",
                    image->SourceBytes(), image->Capacity(), argv[5]);
        return 0;
    }
    if (argc == 4 && std::string(argv[1]) == "--peer") {
        Result result;
        auto peer = Backing::Open(std::filesystem::u8path(argv[2]), std::filesystem::u8path(argv[3]), 512, 2048, FixtureHash, &result);
        std::array<uint8_t, 512> data;
        data.fill(0x3b);
        Check(peer && peer->Write(1536, data.data(), data.size()) == Result::Ok, "peer persists a complete sector");
        return 0;
    }
    const auto root = std::filesystem::temp_directory_path() /
        ("kyty_sector_test_" + std::to_string(GetCurrentProcessId()) + "_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    Check(std::filesystem::create_directory(root), "create disposable virtual media directory");
    const auto source = root / "source.bin", overlay = root / "state.kytycow";
    std::vector<uint8_t> original(1024);
    for (size_t i = 0; i < original.size(); ++i) original[i] = static_cast<uint8_t>(i);
    { std::ofstream output(source, std::ios::binary); output.write(reinterpret_cast<const char*>(original.data()), original.size()); Check(output.good(), "write disposable source"); }
    Result result;
    const auto partial_source = root / "partial-prefix.bin";
    { std::ofstream output(partial_source, std::ios::binary); output.write(reinterpret_cast<const char*>(original.data()), 17); }
    auto captured = Backing::OpenCapturedPrefix(partial_source, {}, "", &result);
    std::array<uint8_t, 4> fragment {0xa5, 0xa5, 0xa5, 0xa5};
    Check(captured && captured->SourceBytes() == 17 && captured->Read(13, fragment.data(), fragment.size()) == Result::Ok && fragment[3] == 16,
          "opened partial prefix supplies exact known fragment");
    fragment.fill(0xa5);
    Check(captured->Read(16, fragment.data(), 2) == Result::MissingData && fragment[0] == 0xa5 &&
          captured->Write(0, fragment.data(), 1) == Result::ReadOnly,
          "uncaptured partial-sector bytes remain unavailable");
    HANDLE prefix_writer = CreateFileW(partial_source.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    Check(prefix_writer == INVALID_HANDLE_VALUE, "captured prefix excludes concurrent writers");
    std::error_code rename_error;
    std::filesystem::rename(partial_source, root / "renamed-prefix.bin", rename_error);
    Check(rename_error && std::filesystem::exists(partial_source), "captured prefix excludes pathname replacement");
    Check(!Backing::OpenCapturedPrefix(partial_source, root / "unbound.kytycow", "", &result) && result == Result::Invalid &&
          !std::filesystem::exists(root / "unbound.kytycow"), "writable prefix requires explicit source hash");
    captured.reset();
    const auto partial_overlay = root / "partial-state.kytycow";
    const char* partial_hash = "3e5718fea51a8f3f5baca61c77afab473c1810f8b9db330273b4011ce92c787e";
    captured = Backing::OpenCapturedPrefix(partial_source, partial_overlay, partial_hash, &result);
    const uint8_t tail_value = 0x91;
    Check(captured && captured->Write(16, &tail_value, 1) == Result::Ok &&
          captured->Read(13, fragment.data(), fragment.size()) == Result::Ok && fragment[0] == 13 && fragment[3] == tail_value,
          "SHA-bound partial prefix preserves and writes only captured bytes");
    fragment.fill(0xa5);
    Check(captured->Read(16, fragment.data(), 2) == Result::MissingData && fragment[0] == 0xa5 &&
          captured->Write(16, fragment.data(), 2) == Result::MissingData &&
          captured->Write(17, &tail_value, 1) == Result::MissingData,
          "partial journal does not promote padding to captured data");
    captured.reset();
    captured = Backing::OpenCapturedPrefix(partial_source, partial_overlay, partial_hash, &result);
    Check(captured && captured->Read(16, fragment.data(), 1) == Result::Ok && fragment[0] == tail_value &&
          captured->Read(17, fragment.data(), 1) == Result::MissingData,
          "partial prefix validity and writes survive reopen");
    captured.reset();
    { std::ifstream input(partial_source, std::ios::binary); std::array<uint8_t, 17> unchanged {};
      input.read(reinterpret_cast<char*>(unchanged.data()), unchanged.size());
      Check(input.good() && std::equal(unchanged.begin(), unchanged.end(), original.begin()), "partial prefix source remains unchanged"); }
    auto first = Backing::Open(source, overlay, 512, 2048, FixtureHash, &result);
    Check(first && result == Result::Ok && first->Capacity() == 2048 && first->SourceBytes() == 1024, "bind journal to source geometry and hash");
    auto second = Backing::Open(source, overlay, 512, 2048, FixtureHash, &result);
    Check(second && result == Result::Ok, "second handle shares journal");
    std::array<uint8_t, 512> bytes;
    bytes.fill(0xa5);
    Check(first->Read(UINT64_MAX, bytes.data(), 1) == Result::Invalid &&
          first->Read(2048, bytes.data(), 1) == Result::Invalid &&
          first->Write(2000, bytes.data(), 100) == Result::Invalid &&
          first->Read(0, nullptr, 1) == Result::Invalid &&
          first->Write(0, nullptr, 1) == Result::Invalid, "bounds and host buffer arguments are rejected");
    Check(first->Read(1024, bytes.data(), bytes.size()) == Result::MissingData && bytes.front() == 0xa5,
          "unknown tail adds no source bytes and leaves output unchanged");
    Check(first->Read(1000, bytes.data(), 32) == Result::MissingData && bytes.front() == 0xa5,
          "mixed available and unavailable read is atomic");
    Check(first->Write(1000, bytes.data(), 32) == Result::MissingData &&
          first->Write(1025, bytes.data(), 1) == Result::MissingData, "partial unknown sector write is rejected before mutation");
    Check(first->Read(512, bytes.data(), bytes.size()) == Result::Ok && bytes.front() == 0 && bytes.back() == 255,
          "failed mixed write leaves known sector unchanged");
    const uint8_t replacement = 0x5a;
    Check(first->Write(513, &replacement, 1) == Result::Ok &&
          second->Read(512, bytes.data(), bytes.size()) == Result::Ok && bytes[0] == 0 && bytes[1] == replacement && bytes[2] == 2,
          "partial known sector preserves its neighbors across handles");
    bytes.fill(0x7c);
    Check(second->Write(1024, bytes.data(), bytes.size()) == Result::Ok &&
          first->Read(1024, bytes.data(), bytes.size()) == Result::Ok && bytes.back() == 0x7c,
          "explicit full-sector write supplies previously unavailable contents");
    first->FailNextCommit(false, false);
    Check(first->Write(1536, bytes.data(), bytes.size()) == Result::Io &&
          second->Read(1536, bytes.data(), bytes.size()) == Result::MissingData,
          "partial append failure rolls back before another process can read it");
    first->FailNextCommit(true, false);
    Check(first->Write(1536, bytes.data(), bytes.size()) == Result::Io &&
          second->Read(1536, bytes.data(), bytes.size()) == Result::MissingData,
          "flush failure rolls back even a complete appended transaction");
    first->FailNextCommit(true, true);
    Check(first->Write(1536, bytes.data(), bytes.size()) == Result::Io &&
          second->Read(1536, bytes.data(), bytes.size()) == Result::Ok && bytes.front() == 0x7c,
          "persistence and rollback failure is an explicit indeterminate Io outcome");
    std::array<wchar_t, 32768> executable;
    Check(GetModuleFileNameW(nullptr, executable.data(), executable.size()) != 0, "locate peer executable");
    std::wstring command = L"\"" + std::wstring(executable.data()) + L"\" --peer \"" + source.wstring() + L"\" \"" + overlay.wstring() + L"\"";
    STARTUPINFOW startup {}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process {};
    Check(CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, root.c_str(), &startup, &process), "start isolated journal peer");
    Check(WaitForSingleObject(process.hProcess, 10000) == WAIT_OBJECT_0, "journal peer finishes within bound");
    DWORD exit = 1; GetExitCodeProcess(process.hProcess, &exit);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    Check(exit == 0 && first->Read(1536, bytes.data(), bytes.size()) == Result::Ok && bytes.front() == 0x3b,
          "parent refresh sees cross-process committed sector");
    auto writer = [&](Backing* image, uint64_t offset, uint8_t value) {
        std::array<uint8_t, 512> data; data.fill(value);
        for (int i = 0; i < 20; ++i) Check(image->Write(offset, data.data(), data.size()) == Result::Ok, "concurrent sector commit");
    };
    std::thread left(writer, first.get(), 0, 0x11), right(writer, second.get(), 512, 0x22);
    left.join(); right.join();
    Check(first->Read(0, bytes.data(), bytes.size()) == Result::Ok && bytes.front() == 0x11 &&
          first->Read(512, bytes.data(), bytes.size()) == Result::Ok && bytes.front() == 0x22, "serialized writers retain both sector updates");
    first.reset(); second.reset();
    auto reopened = Backing::Open(source, overlay, 512, 2048, FixtureHash, &result);
    Check(reopened && reopened->Read(1536, bytes.data(), bytes.size()) == Result::Ok && bytes.front() == 0x3b,
          "journal survives every owner closing");
    reopened.reset();
    Check(!Backing::Open(source, overlay, 512, 2560, FixtureHash, &result) && result == Result::Io, "journal rejects changed capacity");
    Check(!Backing::Open(source, {}, 512, 2048, std::string(64, '0'), &result) && result == Result::Io,
          "source identity mismatch is rejected");
    const auto torn = root / "torn.kytycow";
    Check(std::filesystem::copy_file(overlay, torn), "copy journal into corruption fixture");
    { std::ofstream append(torn, std::ios::binary | std::ios::app); append.put('x'); }
    const auto torn_size = std::filesystem::file_size(torn);
    Check(!Backing::Open(source, torn, 512, 2048, FixtureHash, &result) && result == Result::Io &&
          std::filesystem::file_size(torn) == torn_size, "torn transaction fails without destructive repair");
    const auto corrupt = root / "corrupt.kytycow";
    Check(std::filesystem::copy_file(overlay, corrupt), "copy journal for integrity test");
    { std::fstream file(corrupt, std::ios::binary | std::ios::in | std::ios::out); file.seekp(64 + 56 + 8); file.put('x'); }
    Check(!Backing::Open(source, corrupt, 512, 2048, FixtureHash, &result) && result == Result::Io, "transaction checksum rejects altered payload");
    std::ifstream input(source, std::ios::binary);
    std::vector<uint8_t> final(original.size()); input.read(reinterpret_cast<char*>(final.data()), final.size()); input.close();
    Check(final == original, "source fixture remains byte-for-byte unchanged");
    const auto resolved = std::filesystem::canonical(root);
    Check(resolved.parent_path() == std::filesystem::canonical(std::filesystem::temp_directory_path()) &&
          resolved.filename().wstring().starts_with(L"kyty_sector_test_"), "cleanup targets owned disposable media");
    std::filesystem::remove_all(resolved);
    std::printf("SectorBackingTests: all cases passed host_fixture_only=1\n");
#else
    std::printf("SectorBackingTests: Windows backing implementation unavailable\n");
#endif
    return 0;
}
