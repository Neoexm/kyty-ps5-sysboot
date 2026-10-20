#include "kernel/authInfo.h"

#include "loader/elf.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <new>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace {
using namespace Libs::LibKernel::AuthInfo;

void Check(bool value, const char *text) {
  if (!value) {
    std::fprintf(stderr, "AuthInfoTests: %s\n", text);
    std::abort();
  }
}

void Store32(uint8_t *data, uint32_t value) {
  for (uint32_t i = 0; i != 4; ++i)
    data[i] = static_cast<uint8_t>(value >> (i * 8));
}

void Store64(uint8_t *data, uint64_t value) {
  for (uint32_t i = 0; i != 8; ++i)
    data[i] = static_cast<uint8_t>(value >> (i * 8));
}

uint64_t Load64(const uint8_t *data) {
  uint64_t value = 0;
  for (uint32_t i = 0; i != 8; ++i)
    value |= uint64_t{data[i]} << (i * 8);
  return value;
}

void SetEnvironment(const std::string &name, const char *value) {
#if defined(_WIN32)
  Check(_putenv_s(name.c_str(), value == nullptr ? "" : value) == 0,
        "set environment");
#else
  Check(value == nullptr ? unsetenv(name.c_str()) == 0
                         : setenv(name.c_str(), value, 1) == 0,
        "set environment");
#endif
}

struct SavedEnvironment {
  std::string name;
  bool present = false;
  std::string value;
  explicit SavedEnvironment(std::string variable) : name(std::move(variable)) {
#if defined(_WIN32)
    char *current = nullptr;
    size_t size = 0;
    Check(_dupenv_s(&current, &size, name.c_str()) == 0, "read environment");
    if (current != nullptr) {
      present = true;
      value = current;
      std::free(current);
    }
#else
    if (const char *current = std::getenv(name.c_str())) {
      present = true;
      value = current;
    }
#endif
  }
  ~SavedEnvironment() {
    SetEnvironment(name, present ? value.c_str() : nullptr);
  }
};

struct Fixture {
  uint64_t authority_id = 0;
  Digest self_sha256{};
  Digest elf_sha256{};
  Digest envelope_sha256{};
  Record record{};
  std::array<uint8_t, kCaptureEnvelopeSize> envelope{};
  Capture capture{};
};

Fixture MakeFixture(uint8_t seed, uint64_t authority_id) {
  Fixture fixture;
  fixture.authority_id = authority_id;
  std::array<uint8_t, 193> self_bytes{};
  std::array<uint8_t, 521> elf_bytes{};
  for (size_t i = 0; i != self_bytes.size(); ++i) {
    self_bytes[i] = static_cast<uint8_t>(seed + i * 17 + 3);
  }
  for (size_t i = 0; i != elf_bytes.size(); ++i) {
    elf_bytes[i] = static_cast<uint8_t>(seed * 3 + i * 29 + 7);
  }
  fixture.self_sha256 = Sha256(self_bytes.data(), self_bytes.size());
  fixture.elf_sha256 = Sha256(elf_bytes.data(), elf_bytes.size());
  for (size_t i = 0; i != fixture.record.size(); ++i) {
    fixture.record[i] = static_cast<uint8_t>(seed + i * 3 + 1);
  }
  Store64(fixture.record.data(), fixture.authority_id);
  Store64(fixture.record.data() + 8, 1ull << 62);
  std::memcpy(fixture.envelope.data(), "KytyAI02", 8);
  Store32(fixture.envelope.data() + 8, kCaptureEnvelopeVersion);
  Store32(fixture.envelope.data() + 12, 0x80);
  Store32(fixture.envelope.data() + 16,
          static_cast<uint32_t>(kCaptureEnvelopeSize));
  Store32(fixture.envelope.data() + 20, static_cast<uint32_t>(kSize));
  Store64(fixture.envelope.data() + 24, fixture.authority_id);
  std::memcpy(fixture.envelope.data() + 32, fixture.self_sha256.data(),
              fixture.self_sha256.size());
  std::memcpy(fixture.envelope.data() + 64, fixture.elf_sha256.data(),
              fixture.elf_sha256.size());
  const auto record_sha256 =
      Sha256(fixture.record.data(), fixture.record.size());
  std::memcpy(fixture.envelope.data() + 96, record_sha256.data(),
              record_sha256.size());
  std::memcpy(fixture.envelope.data() + 0x80, fixture.record.data(),
              fixture.record.size());
  fixture.envelope_sha256 =
      Sha256(fixture.envelope.data(), fixture.envelope.size());
  std::string reason;
  Check(ParseCaptureEnvelope(fixture.envelope.data(), fixture.envelope.size(),
                             fixture.envelope_sha256, fixture.self_sha256,
                             fixture.elf_sha256, fixture.authority_id,
                             &fixture.capture, &reason),
        "construct verified fixture");
  return fixture;
}

Digest Changed(Digest digest) {
  digest[0] ^= 0x80;
  return digest;
}

void WriteFile(const std::filesystem::path &path, const void *data,
               size_t size) {
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  file.write(static_cast<const char *>(data),
             static_cast<std::streamsize>(size));
  file.close();
  Check(static_cast<bool>(file), "write capture fixture");
}

struct ImageFixture {
  std::vector<uint8_t> self;
  std::vector<uint8_t> elf;
  ImageIdentity identity{};
};

ImageFixture MakeImageFixture(uint64_t authority_id) {
  ImageFixture fixture;
  Loader::Elf64_Ehdr elf_header{};
  std::memcpy(elf_header.e_ident, "\177ELF", 4);
  elf_header.e_ident[Loader::EI_CLASS] = Loader::ELFCLASS64;
  elf_header.e_ident[Loader::EI_DATA] = Loader::ELFDATA2LSB;
  elf_header.e_ehsize = sizeof(elf_header);
  elf_header.e_phoff = sizeof(elf_header);
  elf_header.e_phentsize = sizeof(Loader::Elf64_Phdr);
  elf_header.e_phnum = 1;
  Loader::Elf64_Phdr program_header{};
  program_header.p_type = Loader::PT_LOAD;
  program_header.p_flags = Loader::PF_R | Loader::PF_X;
  program_header.p_offset = 0;
  program_header.p_filesz = sizeof(elf_header) + sizeof(program_header);
  program_header.p_memsz = program_header.p_filesz;
  program_header.p_align = 0x10;
  fixture.elf.resize(sizeof(elf_header) + sizeof(program_header) + 19);
  std::memcpy(fixture.elf.data(), &elf_header, sizeof(elf_header));
  std::memcpy(fixture.elf.data() + elf_header.e_phoff, &program_header,
              sizeof(program_header));
  for (size_t i = sizeof(elf_header) + sizeof(program_header);
       i != fixture.elf.size(); ++i) {
    fixture.elf[i] = static_cast<uint8_t>(i * 11 + 9);
  }
  const uint64_t elf_offset =
      sizeof(Loader::SelfHeader) + sizeof(Loader::SelfSegment);
  const uint64_t authority_offset =
      (elf_offset + elf_header.e_phoff + sizeof(program_header) + 15) &
      ~uint64_t{15};
  const size_t authenticated_size = authority_offset + sizeof(authority_id);
  fixture.self.resize(authenticated_size + 13);
  Loader::SelfHeader self_header{};
  std::memcpy(self_header.ident, "\x54\x14\xf5\xee", 4);
  self_header.size1 = static_cast<uint16_t>(authenticated_size);
  self_header.size2 = static_cast<uint16_t>(fixture.self.size() - authenticated_size);
  self_header.file_size = fixture.self.size();
  self_header.segments_num = 1;
  std::memcpy(fixture.self.data(), &self_header, sizeof(self_header));
  Loader::SelfSegment self_segment{};
  self_segment.type = 6;
  std::memcpy(fixture.self.data() + sizeof(self_header), &self_segment,
              sizeof(self_segment));
  std::memcpy(fixture.self.data() + elf_offset, &elf_header, sizeof(elf_header));
  std::memcpy(fixture.self.data() + elf_offset + elf_header.e_phoff,
              &program_header, sizeof(program_header));
  std::memcpy(fixture.self.data() + authority_offset, &authority_id,
              sizeof(authority_id));
  for (size_t i = authenticated_size; i != fixture.self.size(); ++i) {
    fixture.self[i] = static_cast<uint8_t>(i * 7 + 5);
  }
  std::string reason;
  Check(ValidateImageIdentity(fixture.self.data(), fixture.self.size(),
                              fixture.elf.data(), fixture.elf.size(),
                              &fixture.identity, &reason),
        "construct matching SELF and ELF fixture");
  return fixture;
}

std::string ShellQuote(const std::string &text) {
  std::string quoted = "\"";
  for (const auto character : text) {
    if (character == '"') quoted += '\\';
    quoted += character;
  }
  quoted += '"';
  return quoted;
}

std::string ReadText(const std::filesystem::path &path) {
  std::ifstream file(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(file),
          std::istreambuf_iterator<char>()};
}

struct CommandResult {
  int exit_code = -1;
  std::string output;
  std::string error;
};

CommandResult RunTool(const std::filesystem::path &tool,
                      const std::vector<std::string> &arguments,
                      const std::filesystem::path &directory,
                      const std::string &name) {
  const auto output_path = directory / (name + ".stdout");
  const auto error_path = directory / (name + ".stderr");
#if defined(_WIN32)
  std::string command = "call " + ShellQuote(tool.string());
#else
  std::string command = ShellQuote(tool.string());
#endif
  for (const auto &argument : arguments) {
    command += ' ';
    command += ShellQuote(argument);
  }
  command += " >" + ShellQuote(output_path.string());
  command += " 2>" + ShellQuote(error_path.string());
  CommandResult result;
  result.exit_code = std::system(command.c_str());
  result.output = ReadText(output_path);
  result.error = ReadText(error_path);
  return result;
}

void CheckNoTemporaryFiles(const std::filesystem::path &directory) {
  for (const auto &entry : std::filesystem::directory_iterator(directory)) {
    Check(entry.path().filename().string().find(".tmp.") == std::string::npos,
          "CLI failure cleans temporary output");
  }
}

void RunCliTests(const std::filesystem::path &tool,
                 const ImageFixture &image, Record record) {
  const std::string sentinel = "AUTHINFO_RECORD_SENTINEL_DO_NOT_PRINT";
  std::memcpy(record.data() + 32, sentinel.data(), sentinel.size());
  const auto suffix = std::to_string(
      std::chrono::steady_clock::now().time_since_epoch().count());
  const auto directory = std::filesystem::absolute(
      std::filesystem::temp_directory_path() /
      ("kyty_auth_info_cli_" + suffix));
  Check(std::filesystem::create_directory(directory),
        "create CLI integration directory");
  const auto record_path = directory / "record.bin";
  const auto self_path = directory / "image.self";
  const auto elf_path = directory / "image.elf";
  const auto capture_path = directory / "capture.bin";
  WriteFile(record_path, record.data(), record.size());
  WriteFile(self_path, image.self.data(), image.self.size());
  WriteFile(elf_path, image.elf.data(), image.elf.size());
  std::string transcript;
  auto Run = [&](const std::vector<std::string> &arguments,
                 const std::string &name) {
    const auto result = RunTool(tool, arguments, directory, name);
    transcript += result.output;
    transcript += result.error;
    return result;
  };
  const auto inspect = Run(
      {"inspect", "--self", self_path.string(), "--elf", elf_path.string()},
      "inspect");
  Check(inspect.exit_code == 0 && inspect.error.empty(),
        "CLI SELF inspection reports bounded public provenance");
  for (const char *field : {
           "status=image_identity_consistent",
           "authority_id=0x3800000000000034",
           "self_sha256=dbd067e8fe706a1f79c17f35c791ed1e28a20c44ca5ec6a16840881e22ffd675",
           "elf_sha256=98b541da48e10637cc57c41f4440c8d8eb51206c86483e670c522fb53de8aa3d",
           "self_header_size=0x00c8", "self_metadata_size=0x000d",
           "self_payload_offset=0xd5", "elf_header_offset=0x40",
           "public_authority_offset=0xc0", "segment_count=1",
           "encrypted_segment_count=1", "signed_segment_count=1",
           "public_header_sha256=0d8d24994ac3608438e8c67d4a8ac90453619a95c910cb4654ebb6c38dff18bd",
           "metadata_sha256=d70b02ca17d9b0c7b53aa27ae3ee5eb249a48806e7f0ad103df94ba0d54db964",
           "authority_public_bytes=8",
           "authinfo_record_source=external_integrity_pinned_capture_required",
           "hardware_provenance_authenticated=false"}) {
    Check(inspect.output.find(field) != std::string::npos,
          "CLI SELF inspection field matches fixture");
  }
  const auto pack = Run(
      {"pack", "--record", record_path.string(), "--self", self_path.string(),
       "--elf", elf_path.string(), "--out", capture_path.string()},
      "pack");
  Check(pack.exit_code == 0 &&
            pack.output.find("status=integrity_bound") == 0 &&
            pack.output.find("hardware_provenance_authenticated=false") !=
                std::string::npos &&
            pack.error.empty(),
        "CLI canonical pack succeeds with bounded status");
  const auto capture_bytes = [&] {
    std::ifstream file(capture_path, std::ios::binary);
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(file),
                                std::istreambuf_iterator<char>());
  }();
  Check(capture_bytes.size() == kCaptureEnvelopeSize,
        "CLI pack writes exact envelope size");
  const auto envelope_sha256 = Sha256(capture_bytes.data(), capture_bytes.size());
  const auto verify = Run(
      {"verify", "--capture", capture_path.string(), "--self", self_path.string(),
       "--elf", elf_path.string(), "--sha256", DigestHex(envelope_sha256)},
      "verify");
  Check(verify.exit_code == 0 &&
            verify.output.find("status=integrity_verified") == 0 &&
            verify.error.empty(),
        "CLI pinned verification succeeds");
  const auto existing = Run(
      {"pack", "--record", record_path.string(), "--self", self_path.string(),
       "--elf", elf_path.string(), "--out", capture_path.string()},
      "existing");
  Check(existing.exit_code != 0 &&
            ReadText(capture_path) ==
                std::string(reinterpret_cast<const char *>(capture_bytes.data()),
                            capture_bytes.size()),
        "CLI refuses existing output without changing it");
  for (const size_t size : {kSize - 1, kSize + 1}) {
    const auto malformed_record =
        directory / ("record_" + std::to_string(size) + ".bin");
    WriteFile(malformed_record, record.data(), size < record.size() ? size : record.size());
    if (size > record.size()) {
      std::ofstream file(malformed_record, std::ios::binary | std::ios::app);
      file.put('\0');
    }
    const auto output = directory / ("record_" + std::to_string(size) + ".capture");
    const auto result = Run(
        {"pack", "--record", malformed_record.string(), "--self",
         self_path.string(), "--elf", elf_path.string(), "--out", output.string()},
        "bad_record_" + std::to_string(size));
    Check(result.exit_code != 0 && !std::filesystem::exists(output),
          "CLI rejects wrong raw record size");
  }
  for (const size_t size : {kCaptureEnvelopeSize - 1,
                            kCaptureEnvelopeSize + 1}) {
    const auto malformed_capture =
        directory / ("capture_" + std::to_string(size) + ".bin");
    WriteFile(malformed_capture, capture_bytes.data(),
              std::min(size, capture_bytes.size()));
    if (size > capture_bytes.size()) {
      std::ofstream file(malformed_capture, std::ios::binary | std::ios::app);
      file.put('\0');
    }
    const auto result = Run(
        {"verify", "--capture", malformed_capture.string(), "--self",
         self_path.string(), "--elf", elf_path.string(), "--sha256",
         DigestHex(envelope_sha256)},
        "bad_capture_" + std::to_string(size));
    Check(result.exit_code != 0, "CLI rejects wrong envelope size");
  }
  const auto duplicate = Run(
      {"pack", "--record", record_path.string(), "--record", record_path.string(),
       "--elf", elf_path.string(), "--out", (directory / "duplicate.bin").string()},
      "duplicate");
  Check(duplicate.exit_code != 0, "CLI rejects duplicate options");
  const auto unknown = Run(
      {"pack", "--record", record_path.string(), "--self", self_path.string(),
       "--unknown", elf_path.string(), "--out", (directory / "unknown.bin").string()},
      "unknown");
  Check(unknown.exit_code != 0, "CLI rejects unknown options");
  const auto missing =
      Run({"pack", "--record", record_path.string(), "--self", self_path.string(),
           "--elf", elf_path.string()},
          "missing");
  Check(missing.exit_code != 0, "CLI rejects missing options");
  const auto bad_pin = Run(
      {"verify", "--capture", capture_path.string(), "--self", self_path.string(),
       "--elf", elf_path.string(), "--sha256", std::string(64, '0')},
      "bad_pin");
  Check(bad_pin.exit_code != 0, "CLI rejects incorrect envelope pin");
  Check(transcript.find(sentinel) == std::string::npos &&
            transcript.find(DigestHex(Sha256(record.data(), record.size()))) ==
                std::string::npos,
        "CLI never prints record bytes or record digest");
  CheckNoTemporaryFiles(directory);
  std::error_code ignored;
  std::filesystem::remove_all(directory, ignored);
  Check(!std::filesystem::exists(directory),
        "remove CLI integration directory");
}
}

void CheckObservations() {
  const auto image = MakeImageFixture(0x4800000000000007ull).identity;
  std::array<uint8_t, kObservationSize> bytes {};
  std::memcpy(bytes.data(), "KytyAO01", 8);
  Store32(bytes.data() + 8, 1);
  Store32(bytes.data() + 12, bytes.size());
  Store64(bytes.data() + 16, image.authority_id);
  Store64(bytes.data() + 24, 1ull << 62);
  Store64(bytes.data() + 32, kFilteredCapabilityMask);
  std::copy(image.self_sha256.begin(), image.self_sha256.end(), bytes.begin() + 40);
  std::copy(image.elf_sha256.begin(), image.elf_sha256.end(), bytes.begin() + 72);
  bytes[104] = 1;
  Store32(bytes.data() + 136, 0x13600007);
  Store32(bytes.data() + 140, 52);
  Store64(bytes.data() + 144, 100);
  Store32(bytes.data() + 152, 123456);
  Store64(bytes.data() + 160, 200);
  bytes[168] = 2;
  const auto digest = Sha256(bytes.data(), bytes.size());
  Observation observation;
  std::string reason;
  Check(ParseObservation(bytes.data(), bytes.size(), digest, image, &observation, &reason) &&
        observation.facts.has_authority && observation.facts.authority_id == image.authority_id &&
        observation.facts.capability0 == (1ull << 62) &&
        observation.facts.known_capability0 == kFilteredCapabilityMask &&
        !observation.facts.root_prison_known && !observation.facts.root_prison,
        "partial observation retains exactly the native filtered capability knowledge");
  const auto canonical_observation = observation;
  auto privilege_bytes = bytes;
  std::memcpy(privilege_bytes.data(), "KytyAO02", 8);
  Store32(privilege_bytes.data() + 8, 2);
  Store32(privilege_bytes.data() + 156, 3);
  Check(ParseObservation(privilege_bytes.data(), privilege_bytes.size(),
                         Sha256(privilege_bytes.data(), privilege_bytes.size()), image,
                         &observation, &reason) && observation.facts.root_prison_known &&
        observation.facts.root_prison,
        "version-two observation carries an explicit verified root-prison fact");
  const auto root_observation = observation;
  Store32(privilege_bytes.data() + 156, 1);
  Check(ParseObservation(privilege_bytes.data(), privilege_bytes.size(),
                         Sha256(privilege_bytes.data(), privilege_bytes.size()), image,
                         &observation, &reason) && observation.facts.root_prison_known &&
        !observation.facts.root_prison,
        "version-two observation distinguishes verified non-root prison");
  for (const uint32_t flags : {2u, 4u}) {
    Store32(privilege_bytes.data() + 156, flags);
    Check(!ParseObservation(privilege_bytes.data(), privilege_bytes.size(),
                            Sha256(privilege_bytes.data(), privilege_bytes.size()), image,
                            &observation, &reason),
          "version-two observation rejects inconsistent or unknown authorization flags");
  }
  auto invalid_v1_flags = bytes;
  Store32(invalid_v1_flags.data() + 156, 1);
  Check(!ParseObservation(invalid_v1_flags.data(), invalid_v1_flags.size(),
                          Sha256(invalid_v1_flags.data(), invalid_v1_flags.size()), image,
                          &observation, &reason),
        "version-one observation cannot smuggle a root-prison fact");
  observation = canonical_observation;
  Record filtered;
  filtered.fill(0xa5);
  const auto untouched = filtered;
  auto incomplete = canonical_observation.facts;
  incomplete.known_capability0 = 1ull << 62;
  Check(!BuildFilteredRecord(incomplete, &filtered) && filtered == untouched,
        "filtered record builder refuses unknown public bits without touching output");
  auto invalid = canonical_observation.facts;
  invalid.capability0 |= 1ull << 59;
  Check(!BuildFilteredRecord(invalid, &filtered) && filtered == untouched,
        "filtered record builder refuses values outside verified knowledge");
  invalid = canonical_observation.facts;
  invalid.known_capability0 |= 1;
  Check(!BuildFilteredRecord(invalid, &filtered) && filtered == untouched,
        "filtered record builder refuses non-public knowledge bits");
  auto absent = canonical_observation.facts;
  absent.has_authority = false;
  Check(!BuildFilteredRecord(absent, &filtered) && filtered == untouched &&
        !BuildFilteredRecord(canonical_observation.facts, nullptr),
        "filtered record builder requires verified authority and output");
  Check(BuildFilteredRecord(canonical_observation.facts, &filtered) &&
        AuthorityId(filtered) == 0 && Capability0(filtered) == (1ull << 62) &&
        std::all_of(filtered.begin() + 16, filtered.end(),
                    [](uint8_t value) { return value == 0; }),
        "complete observation builds only the exact native filtered record");
  auto visible = canonical_observation.facts;
  visible.authority_id = 0x4800000010000004ull;
  Check(BuildFilteredRecord(visible, &filtered) &&
        AuthorityId(filtered) == visible.authority_id &&
        Capability0(filtered) == (1ull << 62),
        "filtered record builder retains only a natively visible authority");

  constexpr uint64_t host_birth = 0x01dc6e5b93843210ull;
  std::array<uint8_t, kScopedObservationSize> scoped_observation {};
  Check(EncodeScopedObservation(canonical_observation, 1002, 4321, host_birth,
                                &scoped_observation),
        "encode lifecycle-bound scoped observation");
  Observation decoded_observation;
  Check(DecodeScopedObservation(
            scoped_observation.data(), scoped_observation.size(), 1002, 4321, host_birth,
            image.authority_id, image.self_sha256, image.elf_sha256, digest,
            &decoded_observation, &reason) &&
        decoded_observation.encoded == canonical_observation.encoded &&
        decoded_observation.facts.capability0 == canonical_observation.facts.capability0 &&
        decoded_observation.facts.known_capability0 ==
            canonical_observation.facts.known_capability0,
        "scoped observation round trip preserves canonical facts");
  std::array<uint8_t, kScopedObservationSize> root_scoped_observation {};
  Check(EncodeScopedObservation(root_observation, 1002, 4321, host_birth,
                                &root_scoped_observation) &&
        DecodeScopedObservation(
            root_scoped_observation.data(), root_scoped_observation.size(), 1002, 4321,
            host_birth, image.authority_id, image.self_sha256, image.elf_sha256,
            root_observation.envelope_sha256, &decoded_observation, &reason) &&
        decoded_observation.facts.root_prison_known &&
        decoded_observation.facts.root_prison,
        "scoped version-two round trip preserves verified prison knowledge");
  auto tampered_root_scoped = root_scoped_observation;
  tampered_root_scoped[kScopedObservationSize - kObservationSize + 156] ^= 2;
  Check(!DecodeScopedObservation(
            tampered_root_scoped.data(), tampered_root_scoped.size(), 1002, 4321,
            host_birth, image.authority_id, image.self_sha256, image.elf_sha256,
            root_observation.envelope_sha256, &decoded_observation, &reason) &&
        !decoded_observation.facts.has_authority,
        "scoped version-two prison tamper fails closed");
  auto RejectScopedObservation = [&](const std::array<uint8_t, kScopedObservationSize>& encoded,
                                     int guest_pid, uint32_t host_pid, uint64_t birth,
                                     uint64_t authority_id, const Digest& self_sha256,
                                     const Digest& elf_sha256, const Digest& envelope_sha256,
                                     const char* text) {
    decoded_observation = canonical_observation;
    Check(!DecodeScopedObservation(encoded.data(), encoded.size(), guest_pid, host_pid, birth,
              authority_id, self_sha256, elf_sha256, envelope_sha256,
              &decoded_observation, &reason) && !decoded_observation.facts.has_authority,
          text);
  };
  RejectScopedObservation(scoped_observation, 1003, 4321, host_birth, image.authority_id,
                          image.self_sha256, image.elf_sha256, digest,
                          "scoped observation rejects wrong guest owner");
  RejectScopedObservation(scoped_observation, 1002, 4322, host_birth, image.authority_id,
                          image.self_sha256, image.elf_sha256, digest,
                          "scoped observation rejects wrong host owner");
  RejectScopedObservation(scoped_observation, 1002, 4321, host_birth + 1, image.authority_id,
                          image.self_sha256, image.elf_sha256, digest,
                          "scoped observation rejects recycled host birth");
  RejectScopedObservation(scoped_observation, 1002, 4321, host_birth,
                          image.authority_id + 1, image.self_sha256, image.elf_sha256, digest,
                          "scoped observation rejects wrong authority");
  RejectScopedObservation(scoped_observation, 1002, 4321, host_birth, image.authority_id,
                          Changed(image.self_sha256), image.elf_sha256, digest,
                          "scoped observation rejects wrong SELF hash");
  RejectScopedObservation(scoped_observation, 1002, 4321, host_birth, image.authority_id,
                          image.self_sha256, Changed(image.elf_sha256), digest,
                          "scoped observation rejects wrong ELF hash");
  RejectScopedObservation(scoped_observation, 1002, 4321, host_birth, image.authority_id,
                          image.self_sha256, image.elf_sha256, Changed(digest),
                          "scoped observation rejects wrong envelope marker");
  auto malformed_scoped_observation = scoped_observation;
  malformed_scoped_observation[0] ^= 1;
  RejectScopedObservation(malformed_scoped_observation, 1002, 4321, host_birth,
                          image.authority_id, image.self_sha256, image.elf_sha256, digest,
                          "scoped observation rejects malformed header");
  malformed_scoped_observation = scoped_observation;
  malformed_scoped_observation.back() ^= 1;
  RejectScopedObservation(malformed_scoped_observation, 1002, 4321, host_birth,
                          image.authority_id, image.self_sha256, image.elf_sha256, digest,
                          "scoped observation rejects tampered payload");
  decoded_observation = canonical_observation;
  Check(!DecodeScopedObservation(
            scoped_observation.data(), scoped_observation.size() - 1, 1002, 4321, host_birth,
            image.authority_id, image.self_sha256, image.elf_sha256, digest,
            &decoded_observation, &reason) && !decoded_observation.facts.has_authority &&
        !DecodeScopedObservation(nullptr, scoped_observation.size(), 1002, 4321, host_birth,
            image.authority_id, image.self_sha256, image.elf_sha256, digest,
            &decoded_observation, &reason) &&
        !DecodeScopedObservation(scoped_observation.data(), scoped_observation.size(),
            1002, 4321, host_birth, image.authority_id, image.self_sha256,
            image.elf_sha256, digest, nullptr, &reason),
        "scoped observation rejects partial, null input and null output");
  Check(!EncodeScopedObservation(canonical_observation, 0, 4321, host_birth,
                                 &scoped_observation) &&
        !EncodeScopedObservation(canonical_observation, 1002, 0, host_birth,
                                 &scoped_observation) &&
        !EncodeScopedObservation(canonical_observation, 1002, 4321, 0,
                                 &scoped_observation) &&
        !EncodeScopedObservation(canonical_observation, 1002, 4321, host_birth, nullptr),
        "scoped observation encoder requires complete lifecycle ownership");
  for (const size_t offset : {0, 8, 12, 16, 40, 72, 136, 156}) {
    auto changed = bytes;
    changed[offset] ^= 1;
    Check(!ParseObservation(changed.data(), changed.size(), Sha256(changed.data(), changed.size()),
                            image, &observation, &reason) && !observation.facts.has_authority,
          "malformed or differently bound observation clears authorization knowledge");
  }
  auto changed = bytes;
  changed[24] = 1;
  Check(!ParseObservation(changed.data(), changed.size(), Sha256(changed.data(), changed.size()),
                          image, &observation, &reason), "observation cannot supply undisclosed capability bits");
  for (uint64_t subset = 1; subset != 8; ++subset) {
    for (const uint64_t capability : {uint64_t{0}, subset << 60}) {
      changed = bytes;
      Store64(changed.data() + 24, capability);
      Store64(changed.data() + 32, subset << 60);
      Check(ParseObservation(changed.data(), changed.size(), Sha256(changed.data(), changed.size()),
                             image, &observation, &reason) &&
            observation.facts.capability0 == capability &&
            observation.facts.known_capability0 == (subset << 60),
            "observation preserves exactly a nonempty subset of native disclosed bits");
    }
  }
  for (const uint64_t mask : {uint64_t{0}, uint64_t{1} << 59, uint64_t{1} << 63,
                              kFilteredCapabilityMask | uint64_t{1}}) {
    changed = bytes;
    Store64(changed.data() + 24, 0);
    Store64(changed.data() + 32, mask);
    Check(!ParseObservation(changed.data(), changed.size(), Sha256(changed.data(), changed.size()),
                            image, &observation, &reason) && !observation.facts.has_authority,
          "observation rejects empty and undisclosed known masks");
  }
  changed = bytes;
  Store64(changed.data() + 24, uint64_t{1} << 60);
  Store64(changed.data() + 32, uint64_t{1} << 62);
  Check(!ParseObservation(changed.data(), changed.size(), Sha256(changed.data(), changed.size()),
                          image, &observation, &reason),
        "observation rejects set values outside its narrower known mask");
  Check(!ParseObservation(bytes.data(), bytes.size(), Changed(digest), image, &observation, &reason),
        "observation pin mismatch rejected");
  const auto path = std::filesystem::absolute(std::filesystem::temp_directory_path() /
      ("kyty_auth_observation_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())));
  const auto path_name = "KYTY_PS5_AUTHORIZATION_OBSERVATION_" + DigestHex(image.self_sha256);
  const auto hash_name = "KYTY_PS5_AUTHORIZATION_OBSERVATION_SHA256_" + DigestHex(image.self_sha256);
  SavedEnvironment saved_path(path_name), saved_hash(hash_name);
  SetEnvironment(path_name, nullptr);
  SetEnvironment(hash_name, nullptr);
  Check(LoadObservationFromEnvironment(image, &observation, &reason) == CaptureLoadResult::Absent,
        "missing observation does not create known bits");
  WriteFile(path, bytes.data(), bytes.size());
  SetEnvironment(path_name, path.string().c_str());
  Check(LoadObservationFromEnvironment(image, &observation, &reason) == CaptureLoadResult::Rejected,
        "observation requires an external integrity pin");
  SetEnvironment(hash_name, DigestHex(digest).c_str());
  Check(LoadObservationFromEnvironment(image, &observation, &reason) == CaptureLoadResult::Verified,
        "image-keyed pinned observation loads");
  WriteFile(path, bytes.data(), bytes.size() - 1);
  Check(LoadObservationFromEnvironment(image, &observation, &reason) == CaptureLoadResult::Rejected,
        "truncated observation rejected");
  std::filesystem::remove(path);
}

int main(int argc, char **argv) {
  CheckObservations();
  static_assert(sizeof(Capture) == 0x220);
  static_assert(!std::is_trivially_destructible_v<Capture>);
  static_assert(std::is_copy_constructible_v<Capture>);
  static_assert(std::is_copy_assignable_v<Capture>);
  alignas(Capture) std::array<uint8_t, sizeof(Capture)> capture_storage {};
  auto *destroyed_capture = ::new (capture_storage.data()) Capture;
  auto *capture_bytes = reinterpret_cast<volatile uint8_t *>(destroyed_capture);
  for (size_t i = 0; i != sizeof(Capture); ++i) capture_bytes[i] = 0xa5;
  destroyed_capture->~Capture();
  Check(std::all_of(capture_storage.begin(), capture_storage.end(),
                    [](uint8_t byte) { return byte == 0; }),
        "capture destructor wipes the complete object storage");

  const auto empty_sha256 = Sha256(nullptr, 0);
  Check(DigestHex(empty_sha256) ==
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "SHA-256 empty vector");
  const char abc[] = "abc";
  Check(DigestHex(Sha256(abc, 3)) ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "SHA-256 abc vector");
  Digest parsed_digest{};
  Check(ParseDigestHex(DigestHex(empty_sha256), &parsed_digest) &&
            parsed_digest == empty_sha256,
        "SHA-256 hex round trip");
  Check(!ParseDigestHex("bad", &parsed_digest), "malformed SHA-256 rejected");
  Check(!ParseDigestHex(DigestHex(empty_sha256), nullptr),
        "null SHA-256 output rejected");

  const uint64_t image_authority = 0x3800000000000034ull;
  const auto image = MakeImageFixture(image_authority);
  Check(image.identity.authority_id == image_authority &&
            image.identity.self_size == image.self.size() &&
            image.identity.elf_size == image.elf.size() &&
            image.identity.self_sha256 ==
                Sha256(image.self.data(), image.self.size()) &&
            image.identity.elf_sha256 ==
                Sha256(image.elf.data(), image.elf.size()),
        "matching SELF and ELF identity uses full-byte hashes");
  ImageIdentity image_identity = image.identity;
  std::string image_reason;
  Check(!ValidateImageIdentity(nullptr, image.self.size(), image.elf.data(),
                               image.elf.size(), &image_identity,
                               &image_reason) &&
            image_identity.authority_id == 0,
        "null SELF bytes rejected and identity cleared");
  Check(!ValidateImageIdentity(image.self.data(), image.self.size(),
                               image.elf.data(), image.elf.size(), nullptr,
                               &image_reason),
        "null image identity output rejected");
  std::vector<uint8_t> malformed_self(sizeof(Loader::SelfHeader) - 1);
  Check(!ValidateImageIdentity(malformed_self.data(), malformed_self.size(),
                               image.elf.data(), image.elf.size(),
                               &image_identity, &image_reason) &&
            image_reason == "truncated SELF header",
        "truncated SELF rejected in canonical order");
  malformed_self = image.self;
  malformed_self[0] ^= 1;
  Check(!ValidateImageIdentity(malformed_self.data(), malformed_self.size(),
                               image.elf.data(), image.elf.size(),
                               &image_identity, &image_reason) &&
            image_reason == "invalid SELF magic",
        "invalid SELF magic rejected");
  std::vector<uint8_t> malformed_elf(sizeof(Loader::Elf64_Ehdr) - 1);
  Check(!ValidateImageIdentity(image.self.data(), image.self.size(),
                               malformed_elf.data(), malformed_elf.size(),
                               &image_identity, &image_reason) &&
            image_reason == "truncated ELF header",
        "truncated ELF rejected");
  malformed_elf = image.elf;
  malformed_elf[Loader::EI_ABIVERSION] ^= 1;
  Check(!ValidateImageIdentity(image.self.data(), image.self.size(),
                               malformed_elf.data(), malformed_elf.size(),
                               &image_identity, &image_reason) &&
            image_reason == "ELF header mismatch",
        "mismatched ELF header rejected");
  auto changed_self_tail = image.self;
  changed_self_tail.back() ^= 1;
  Check(ValidateImageIdentity(changed_self_tail.data(), changed_self_tail.size(),
                              image.elf.data(), image.elf.size(),
                              &image_identity, &image_reason) &&
            image_identity.self_sha256 != image.identity.self_sha256,
        "SELF tail participates in identity hash");
  auto changed_elf_tail = image.elf;
  changed_elf_tail.back() ^= 1;
  Check(ValidateImageIdentity(image.self.data(), image.self.size(),
                              changed_elf_tail.data(), changed_elf_tail.size(),
                              &image_identity, &image_reason) &&
            image_identity.elf_sha256 != image.identity.elf_sha256,
        "ELF tail participates in identity hash");

  Record built_record{};
  for (size_t i = 0; i != built_record.size(); ++i)
    built_record[i] = static_cast<uint8_t>(i * 13 + 17);
  Store64(built_record.data(), image_authority);
  Capture built;
  Check(BuildCaptureEnvelope(built_record, image.identity, &built,
                             &image_reason) &&
            built.version == kCaptureEnvelopeVersion &&
            built.authority_id == image_authority &&
            built.record == built_record,
        "canonical builder preserves every record byte");
  Capture built_again;
  Check(BuildCaptureEnvelope(built_record, image.identity, &built_again,
                             &image_reason) &&
            built_again.envelope == built.envelope &&
            built_again.envelope_sha256 == built.envelope_sha256,
        "canonical builder is deterministic");
  Capture aliased_build = built;
  Check(BuildCaptureEnvelope(aliased_build.record, image.identity,
                             &aliased_build, &image_reason) &&
            aliased_build.record == built_record,
        "canonical builder tolerates record output aliasing");
  Capture built_parsed;
  Check(ParseCaptureEnvelope(
            built.envelope.data(), built.envelope.size(),
            built.envelope_sha256, image.identity.self_sha256,
            image.identity.elf_sha256, image.identity.authority_id,
            &built_parsed, &image_reason) &&
            built_parsed.record == built_record,
        "canonical builder round trip");
  ImageIdentity wrong_authority = image.identity;
  ++wrong_authority.authority_id;
  built_again = built;
  Check(!BuildCaptureEnvelope(built_record, wrong_authority, &built_again,
                              &image_reason) &&
            built_again.version == 0 &&
            image_reason == "capture authority mismatch",
        "builder rejects authority mismatch and clears output");
  Check(!BuildCaptureEnvelope(built_record, image.identity, nullptr,
                              &image_reason),
        "builder rejects null output");
  if (argc == 2) RunCliTests(std::filesystem::absolute(argv[1]), image,
                             built_record);

  const uint64_t visible[]{
      0x4800000010000004ull, 0x4800000010000011ull, 0x4800000010000012ull,
      0x4800000010000013ull, 0x4800000000001010ull,
  };
  for (auto authority_id : visible)
    Check(IsFilteredAuthorityVisible(authority_id), "visible authority");
  Check(!IsFilteredAuthorityVisible(0x4800000010000003ull),
        "authority below range");
  Check(!IsFilteredAuthorityVisible(0x4800000010000005ull),
        "authority masked out");
  Check(!IsFilteredAuthorityVisible(0x4800000010000014ull),
        "authority above range");
  Check(!IsFilteredAuthorityVisible(0), "zero authority");

  Record source{};
  for (size_t i = 0; i < source.size(); ++i)
    source[i] = static_cast<uint8_t>(i + 1);
  Store64(source.data(), visible[1]);
  Store64(source.data() + 8, 0xf123456789abcdefull);
  const auto filtered = Filter(source);
  Check(AuthorityId(filtered) == visible[1], "whitelisted authority retained");
  Check(Capability0(filtered) == 0x7000000000000000ull, "capability mask");
  for (size_t i = 16; i < filtered.size(); ++i)
    Check(filtered[i] == 0, "tail zeroed");
  Store64(source.data(), 0x480000000000000full);
  const auto hidden = Filter(source);
  Check(AuthorityId(hidden) == 0, "unlisted authority hidden");
  Check(Capability0(hidden) == 0x7000000000000000ull,
        "capability survives hidden authority");

  Record caller{};
  Record target{};
  for (size_t i = 0; i != target.size(); ++i)
    target[i] = static_cast<uint8_t>(i + 1);
  Store64(caller.data(), 0x4800000000000010ull);
  Store64(target.data(), 0x4800000000000007ull);
  Store64(target.data() + 0x28, 0xffffffffffffffffull);
  Store64(target.data() + 0x30, 0xfedcba9876543210ull);
  Store64(target.data() + 0x38, 0x1122334455667788ull);
  Store64(target.data() + 0x40, 0x8877665544332211ull);
  Record self_filtered{};
  Check(FilterSelfAuthInfo(caller, target, &self_filtered),
        "self auth info privileged caller accepted");
  Check(Load64(self_filtered.data()) == 0x4800000000000007ull &&
            Load64(self_filtered.data() + 0x28) == 0 &&
            Load64(self_filtered.data() + 0x30) == 0 &&
            Load64(self_filtered.data() + 0x38) == 0x88 &&
            Load64(self_filtered.data() + 0x40) == 0,
        "self auth info normal branch filters privileged fields");
  Check(std::all_of(self_filtered.begin() + 0x08,
                    self_filtered.begin() + 0x28,
                    [](uint8_t value) { return value == 0; }) &&
            std::all_of(self_filtered.begin() + 0x48, self_filtered.end(),
                        [](uint8_t value) { return value == 0; }),
        "self auth info clears fixed private ranges");

  Store64(caller.data(), 0x4800000000000007ull);
  Check(FilterSelfAuthInfo(caller, target, &self_filtered) &&
            Load64(self_filtered.data()) == 0 &&
            Load64(self_filtered.data() + 0x38) == 0x88,
        "self auth info public caller hides target authority");

  Store64(caller.data(), 0x1111222233334444ull);
  caller[0x17] |= 1;
  Check(FilterSelfAuthInfo(caller, target, &self_filtered) &&
            Load64(self_filtered.data()) == 0 &&
            Load64(self_filtered.data() + 0x28) == 0x04000000ull &&
            std::all_of(self_filtered.begin() + 0x30,
                        self_filtered.begin() + 0x48,
                        [](uint8_t value) { return value == 0; }),
        "self auth info restricted caller receives masked capability");

  caller[0x17] &= static_cast<uint8_t>(~1u);
  self_filtered.fill(0xa5);
  Check(!FilterSelfAuthInfo(caller, target, &self_filtered) &&
            std::all_of(self_filtered.begin(), self_filtered.end(),
                        [](uint8_t value) { return value == 0; }),
        "self auth info rejects unprivileged caller without output");
  Check(!FilterSelfAuthInfo(caller, target, nullptr),
        "self auth info rejects null output");

  const auto fixture = MakeFixture(0x21, 0x3800000000000011ull);
  const auto second = MakeFixture(0x62, 0x3800000000000012ull);
  Capture parsed;
  std::string reason;
  Check(ParseCaptureEnvelope(fixture.envelope.data(), fixture.envelope.size(),
                             fixture.envelope_sha256, fixture.self_sha256,
                             fixture.elf_sha256, fixture.authority_id, &parsed,
                             &reason) &&
            parsed.record == fixture.record &&
            parsed.elf_sha256 == fixture.elf_sha256,
        "strict SELF and ELF envelope binding");
  parsed = fixture.capture;
  Check(!ParseCaptureEnvelope(
            fixture.envelope.data(), fixture.envelope.size() - 1,
            fixture.envelope_sha256, fixture.self_sha256, fixture.elf_sha256,
            fixture.authority_id, &parsed, &reason) &&
            parsed.version == 0,
        "partial envelope rejected and output cleared");
  Check(!ParseCaptureEnvelope(nullptr, fixture.envelope.size(),
                              fixture.envelope_sha256, fixture.self_sha256,
                              fixture.elf_sha256, fixture.authority_id, &parsed,
                              &reason) &&
            parsed.version == 0,
        "null envelope clears output");
  Check(!ParseCaptureEnvelope(fixture.envelope.data(), fixture.envelope.size(),
                              fixture.envelope_sha256, fixture.self_sha256,
                              fixture.elf_sha256, fixture.authority_id, nullptr,
                              &reason),
        "null envelope output rejected");
  Check(!ParseCaptureEnvelope(fixture.envelope.data(), fixture.envelope.size(),
                              Changed(fixture.envelope_sha256),
                              fixture.self_sha256, fixture.elf_sha256,
                              fixture.authority_id, &parsed, &reason),
        "envelope hash mismatch");
  Check(!ParseCaptureEnvelope(fixture.envelope.data(), fixture.envelope.size(),
                              fixture.envelope_sha256,
                              Changed(fixture.self_sha256), fixture.elf_sha256,
                              fixture.authority_id, &parsed, &reason),
        "SELF hash mismatch");
  Check(!ParseCaptureEnvelope(fixture.envelope.data(), fixture.envelope.size(),
                              fixture.envelope_sha256, fixture.self_sha256,
                              Changed(fixture.elf_sha256), fixture.authority_id,
                              &parsed, &reason),
        "full ELF hash mismatch");
  Check(!ParseCaptureEnvelope(fixture.envelope.data(), fixture.envelope.size(),
                              fixture.envelope_sha256, fixture.self_sha256,
                              fixture.elf_sha256, fixture.authority_id + 1,
                              &parsed, &reason),
        "public authority mismatch");

  auto RejectEnvelope = [&](std::array<uint8_t, kCaptureEnvelopeSize> envelope,
                            uint64_t authority_id, const char *text) {
    const auto hash = Sha256(envelope.data(), envelope.size());
    parsed = fixture.capture;
    Check(!ParseCaptureEnvelope(envelope.data(), envelope.size(), hash,
                                fixture.self_sha256, fixture.elf_sha256,
                                authority_id, &parsed, &reason) &&
              parsed.version == 0,
          text);
  };
  auto malformed = fixture.envelope;
  malformed[0] ^= 1;
  RejectEnvelope(malformed, fixture.authority_id, "capture magic mismatch");
  malformed = fixture.envelope;
  Store32(malformed.data() + 8, kCaptureEnvelopeVersion + 1);
  RejectEnvelope(malformed, fixture.authority_id, "capture version mismatch");
  for (const auto offset : {12u, 16u, 20u}) {
    malformed = fixture.envelope;
    Store32(malformed.data() + offset, 1);
    RejectEnvelope(malformed, fixture.authority_id,
                   "capture size field mismatch");
  }
  malformed = fixture.envelope;
  malformed[0x80 + 17] ^= 0x40;
  RejectEnvelope(malformed, fixture.authority_id,
                 "capture record tamper rejected");
  malformed = fixture.envelope;
  Store64(malformed.data() + 24, fixture.authority_id + 1);
  RejectEnvelope(malformed, fixture.authority_id + 1,
                 "record and header authority mismatch");

  std::array<uint8_t, kScopedCaptureSize> scoped{};
  Check(EncodeScopedCapture(fixture.capture, 1002, 4321, &scoped),
        "encode scoped capture");
  Check(DecodeScopedCapture(scoped.data(), scoped.size(), 1002, 4321,
                            fixture.authority_id, fixture.self_sha256,
                            fixture.elf_sha256, &parsed, &reason) &&
            parsed.record == fixture.record,
        "scoped publication round trip");
  Check(!DecodeScopedCapture(scoped.data(), scoped.size(), 1003, 4321,
                             fixture.authority_id, fixture.self_sha256,
                             fixture.elf_sha256, &parsed, &reason),
        "scoped guest owner mismatch");
  Check(!DecodeScopedCapture(scoped.data(), scoped.size(), 1002, 4322,
                             fixture.authority_id, fixture.self_sha256,
                             fixture.elf_sha256, &parsed, &reason),
        "scoped host owner mismatch");
  Check(!DecodeScopedCapture(scoped.data(), scoped.size(), 1002, 4321,
                             fixture.authority_id + 1, fixture.self_sha256,
                             fixture.elf_sha256, &parsed, &reason),
        "scoped authority mismatch");
  Check(!DecodeScopedCapture(scoped.data(), scoped.size(), 1002, 4321,
                             fixture.authority_id, Changed(fixture.self_sha256),
                             fixture.elf_sha256, &parsed, &reason),
        "scoped SELF mismatch");
  Check(!DecodeScopedCapture(scoped.data(), scoped.size(), 1002, 4321,
                             fixture.authority_id, fixture.self_sha256,
                             Changed(fixture.elf_sha256), &parsed, &reason),
        "scoped ELF mismatch");
  parsed = fixture.capture;
  Check(!DecodeScopedCapture(scoped.data(), scoped.size() - 1, 1002, 4321,
                             fixture.authority_id, fixture.self_sha256,
                             fixture.elf_sha256, &parsed, &reason) &&
            parsed.version == 0,
        "partial scoped publication rejected and output cleared");
  parsed = fixture.capture;
  Check(!DecodeScopedCapture(nullptr, scoped.size(), 1002, 4321,
                             fixture.authority_id, fixture.self_sha256,
                             fixture.elf_sha256, &parsed, &reason) &&
            parsed.version == 0,
        "null scoped input clears output");
  Check(!DecodeScopedCapture(scoped.data(), scoped.size(), 1002, 4321,
                             fixture.authority_id, fixture.self_sha256,
                             fixture.elf_sha256, nullptr, &reason),
        "null scoped output rejected");
  Check(!EncodeScopedCapture(fixture.capture, 1002, 4321, nullptr),
        "null scoped encode output rejected");
  auto RejectScoped = [&](std::array<uint8_t, kScopedCaptureSize> encoded,
                          const char *text) {
    parsed = fixture.capture;
    Check(!DecodeScopedCapture(encoded.data(), encoded.size(), 1002, 4321,
                               fixture.authority_id, fixture.self_sha256,
                               fixture.elf_sha256, &parsed, &reason) &&
              parsed.version == 0,
          text);
  };
  auto malformed_scoped = scoped;
  malformed_scoped[0] ^= 1;
  RejectScoped(malformed_scoped, "scoped magic mismatch");
  for (const auto offset : {8u, 12u, 16u, 20u}) {
    malformed_scoped = scoped;
    Store32(malformed_scoped.data() + offset, 1);
    RejectScoped(malformed_scoped, "scoped version or size field mismatch");
  }
  malformed_scoped = scoped;
  malformed_scoped[40] ^= 1;
  RejectScoped(malformed_scoped, "scoped envelope digest mismatch");
  malformed_scoped = scoped;
  malformed_scoped.back() ^= 1;
  RejectScoped(malformed_scoped, "scoped envelope body tamper rejected");

  for (uint32_t field = 0; field != 4; ++field) {
    auto inconsistent = fixture.capture;
    if (field == 0)
      inconsistent.record[0] ^= 1;
    if (field == 1)
      inconsistent.record_sha256[0] ^= 1;
    if (field == 2)
      ++inconsistent.version;
    if (field == 3)
      inconsistent.elf_sha256[0] ^= 1;
    std::array<uint8_t, kScopedCaptureSize> rejected{};
    Check(!EncodeScopedCapture(inconsistent, 1002, 4321, &rejected),
          "inconsistent scoped capture rejected");
  }

  const auto suffix = std::to_string(
      std::chrono::steady_clock::now().time_since_epoch().count());
  const auto path =
      std::filesystem::absolute(std::filesystem::temp_directory_path() /
                                ("kyty_auth_info_test_" + suffix + ".bin"));
  const auto second_path = std::filesystem::absolute(
      std::filesystem::temp_directory_path() /
      ("kyty_auth_info_test_second_" + suffix + ".bin"));
  WriteFile(path, fixture.envelope.data(), fixture.envelope.size());
  WriteFile(second_path, second.envelope.data(), second.envelope.size());
  const auto path_text = path.string();
  const auto second_path_text = second_path.string();
  const auto path_name = CapturePathEnvironmentName(fixture.self_sha256);
  const auto hash_name = CaptureSha256EnvironmentName(fixture.self_sha256);
  const auto second_path_name = CapturePathEnvironmentName(second.self_sha256);
  const auto second_hash_name =
      CaptureSha256EnvironmentName(second.self_sha256);
  Check(path_name == std::string(kCapturePathEnvironment) + '_' +
                         DigestHex(fixture.self_sha256),
        "identity-keyed path name");
  Check(hash_name == std::string(kCaptureSha256Environment) + '_' +
                         DigestHex(fixture.self_sha256),
        "identity-keyed hash name");
  SavedEnvironment saved_path(path_name);
  SavedEnvironment saved_hash(hash_name);
  SavedEnvironment saved_second_path(second_path_name);
  SavedEnvironment saved_second_hash(second_hash_name);
  SetEnvironment(path_name, nullptr);
  SetEnvironment(hash_name, nullptr);
  SetEnvironment(second_path_name, "unrelated-relative-path");
  SetEnvironment(second_hash_name, "unrelated-malformed-hash");
  parsed = fixture.capture;
  Check(LoadCaptureFromEnvironment(fixture.self_sha256, fixture.elf_sha256,
                                   fixture.authority_id, &parsed,
                                   &reason) == CaptureLoadResult::Absent &&
            parsed.version == 0,
        "unrelated identity entries leave current identity absent");
  Check(LoadCaptureFromEnvironment(fixture.self_sha256, fixture.elf_sha256,
                                   fixture.authority_id, nullptr,
                                   &reason) == CaptureLoadResult::Rejected,
        "null environment output rejected");
  SetEnvironment(path_name, path_text.c_str());
  Check(LoadCaptureFromEnvironment(fixture.self_sha256, fixture.elf_sha256,
                                   fixture.authority_id, &parsed,
                                   &reason) == CaptureLoadResult::Rejected,
        "matching path without pinned hash rejected");
  SetEnvironment(path_name, nullptr);
  const auto envelope_hex = DigestHex(fixture.envelope_sha256);
  SetEnvironment(hash_name, envelope_hex.c_str());
  Check(LoadCaptureFromEnvironment(fixture.self_sha256, fixture.elf_sha256,
                                   fixture.authority_id, &parsed,
                                   &reason) == CaptureLoadResult::Rejected,
        "matching hash without path rejected");
  SetEnvironment(path_name, path_text.c_str());
  Check(LoadCaptureFromEnvironment(fixture.self_sha256, fixture.elf_sha256,
                                   fixture.authority_id, &parsed,
                                   &reason) == CaptureLoadResult::Verified &&
            parsed.record == fixture.record,
        "matching pinned capture verified despite unrelated bad entry");
  Check(LoadCaptureFromEnvironment(Changed(fixture.self_sha256),
                                   fixture.elf_sha256, fixture.authority_id,
                                   &parsed,
                                   &reason) == CaptureLoadResult::Absent,
        "unconfigured identity remains absent");
  Check(LoadCaptureFromEnvironment(fixture.self_sha256,
                                   Changed(fixture.elf_sha256),
                                   fixture.authority_id, &parsed,
                                   &reason) == CaptureLoadResult::Rejected,
        "path input full ELF mismatch rejected");
  Check(LoadCaptureFromEnvironment(fixture.self_sha256, fixture.elf_sha256,
                                   fixture.authority_id + 1, &parsed,
                                   &reason) == CaptureLoadResult::Rejected,
        "path input authority mismatch rejected");
  SetEnvironment(hash_name, "not-a-sha256");
  Check(LoadCaptureFromEnvironment(fixture.self_sha256, fixture.elf_sha256,
                                   fixture.authority_id, &parsed,
                                   &reason) == CaptureLoadResult::Rejected,
        "malformed matching pinned hash rejected");
  SetEnvironment(hash_name, envelope_hex.c_str());
  SetEnvironment(path_name, "relative-capture.bin");
  Check(LoadCaptureFromEnvironment(fixture.self_sha256, fixture.elf_sha256,
                                   fixture.authority_id, &parsed,
                                   &reason) == CaptureLoadResult::Rejected,
        "relative matching path rejected");
  SetEnvironment(path_name, path_text.c_str());
  malformed = fixture.envelope;
  malformed.back() ^= 1;
  WriteFile(path, malformed.data(), malformed.size());
  Check(LoadCaptureFromEnvironment(fixture.self_sha256, fixture.elf_sha256,
                                   fixture.authority_id, &parsed,
                                   &reason) == CaptureLoadResult::Rejected,
        "changed matching input rejected by pinned hash");
  WriteFile(path, fixture.envelope.data(), fixture.envelope.size() - 1);
  Check(LoadCaptureFromEnvironment(fixture.self_sha256, fixture.elf_sha256,
                                   fixture.authority_id, &parsed,
                                   &reason) == CaptureLoadResult::Rejected,
        "wrong-size matching input rejected");
  WriteFile(path, fixture.envelope.data(), fixture.envelope.size());
  const auto second_hex = DigestHex(second.envelope_sha256);
  SetEnvironment(second_path_name, second_path_text.c_str());
  SetEnvironment(second_hash_name, second_hex.c_str());
  Check(LoadCaptureFromEnvironment(second.self_sha256, second.elf_sha256,
                                   second.authority_id, &parsed,
                                   &reason) == CaptureLoadResult::Verified &&
            parsed.record == second.record,
        "second identity selects its own capture");
  Check(LoadCaptureFromEnvironment(fixture.self_sha256, fixture.elf_sha256,
                                   fixture.authority_id, &parsed,
                                   &reason) == CaptureLoadResult::Verified &&
            parsed.record == fixture.record,
        "first identity remains independently selectable");
  SetEnvironment(second_hash_name, nullptr);
  Check(LoadCaptureFromEnvironment(second.self_sha256, second.elf_sha256,
                                   second.authority_id, &parsed,
                                   &reason) == CaptureLoadResult::Rejected,
        "incomplete matching second entry rejected");
  Check(LoadCaptureFromEnvironment(fixture.self_sha256, fixture.elf_sha256,
                                   fixture.authority_id, &parsed,
                                   &reason) == CaptureLoadResult::Verified,
        "broken second entry does not reject first identity");

  std::error_code ignored;
  std::filesystem::remove(path, ignored);
  std::filesystem::remove(second_path, ignored);
  std::puts("AuthInfoTests: SELF/ELF binding, canonical envelope, scoped "
            "ownership, keyed selection, tamper, and absence passed");
  return 0;
}
