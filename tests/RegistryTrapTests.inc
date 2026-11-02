#if defined(_WIN32)

constexpr uint64_t RegistryTrapOffset = 0x1a00;
constexpr uint64_t SysctlTrapOffset = 0xf40;
constexpr uint64_t PollTrapOffset = 0xfc0;
constexpr uint64_t NanosleepTrapOffset = 0x10e0;
constexpr uint64_t RegistryTrapCerrorOffset = 0xd4;
constexpr uint64_t RegistryTrapErrnoOffset = 0x5000;
constexpr uint64_t RegistryTrapReadOnlyOffset = 0x3000;

constexpr std::array<uint8_t, 24> RegistryTrapSignature {
    0x48, 0xc7, 0xc0, 0x14, 0x02, 0x00, 0x00, 0x49,
    0x89, 0xca, 0x0f, 0x05, 0x72, 0x01, 0xc3, 0x48,
    0x8d, 0x0d, 0xbe, 0xe6, 0xff, 0xff, 0xff, 0xe1};
constexpr std::array<uint8_t, 24> SysctlTrapSignature {
    0x48, 0xc7, 0xc0, 0xca, 0x00, 0x00, 0x00, 0x49,
    0x89, 0xca, 0x0f, 0x05, 0x72, 0x01, 0xc3, 0x48,
    0x8d, 0x0d, 0x7e, 0xf1, 0xff, 0xff, 0xff, 0xe1};
constexpr std::array<uint8_t, 24> PollTrapSignature {
    0x48, 0xc7, 0xc0, 0xd1, 0x00, 0x00, 0x00, 0x49,
    0x89, 0xca, 0x0f, 0x05, 0x72, 0x01, 0xc3, 0x48,
    0x8d, 0x0d, 0xfe, 0xf0, 0xff, 0xff, 0xff, 0xe1};
constexpr std::array<uint8_t, 24> NanosleepTrapSignature {
    0x48, 0xc7, 0xc0, 0xf0, 0x00, 0x00, 0x00, 0x49,
    0x89, 0xca, 0x0f, 0x05, 0x72, 0x01, 0xc3, 0x48,
    0x8d, 0x0d, 0xde, 0xef, 0xff, 0xff, 0xff, 0xe1};
constexpr std::array<int32_t, 2> RegistryTrapSentinels {0x13579bdf, 0x2468ace1};

class RegistryTrapEnvironment {
public:
  RegistryTrapEnvironment() {
    constexpr const char* names[] = {
        "KYTY_DIAGNOSTIC_REGMGR_SESSION_STORE",
        "KYTY_DIAGNOSTIC_REGMGR_KERNEL_TABLE",
        "KYTY_REGMGR_LIVE_SNAPSHOT",
        "KYTY_REGMGR_LIVE_SNAPSHOT_SHA256",
        "KYTY_DIAGNOSTIC_REDIRECT_LIBKERNEL_RAW_SYSCALLS",
        "KYTY_DIAGNOSTIC_REDIRECT_LIBKERNEL_SYSCTL",
        "KYTY_DIAGNOSTIC_CENSUS_LIBKERNEL_RAW_SYSCALLS",
        "KYTY_DIAGNOSTIC_AGC_NATIVE_KEVENT_AUDIT",
        "KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD",
        "KYTY_DIAGNOSTIC_SYSCORE_NATIVE_KQUEUE_BACKEND",
        "KYTY_DIAGNOSTIC_SYSCORE_RFORK_AUDIT",
        "KYTY_DIAGNOSTIC_SYSCORE_EXECVE_AUDIT",
        "KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP",
        "KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS",
        "KYTY_DIAGNOSTIC_SYSCORE_GUEST_THREAD_FS10",
        "KYTY_DIAGNOSTIC_NATIVE_SYSCALL_HOST_STACK",
        "KYTY_DIAGNOSTIC_MINI_SYSCORE_NATIVE_TRAPS",
        "KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE",
        "KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY",
        "KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SOCKET"};
    for (const auto* name: names) {
      const auto* value = std::getenv(name);
      saved.push_back({name, value != nullptr, value == nullptr ? "" : value});
      Check(_putenv_s(name, "") == 0, "clear inherited wrapper diagnostic setting");
    }
  }

  ~RegistryTrapEnvironment() {
    for (const auto& entry: saved) {
      Check(_putenv_s(entry.name, entry.present ? entry.value.c_str() : "") == 0,
            "restore wrapper diagnostic setting");
    }
  }

  KYTY_CLASS_NO_COPY(RegistryTrapEnvironment);

private:
  struct Saved {
    const char* name;
    bool present;
    std::string value;
  };
  std::vector<Saved> saved;
};

enum class RegistryTrapFixture {
  Valid,
  RegmgrMismatch,
  RegmgrTruncated,
  SysctlMismatch,
  SysctlTruncated
};

void WriteRegistryTrapElf(const std::filesystem::path& path,
                          RegistryTrapFixture fixture) {
  WriteModuleLifetimeElf(path, 1);
  Common::File input(path, Common::File::Mode::Read);
  Check(!input.IsInvalid(), "open synthetic wrapper ELF for layout adaptation");
  auto image = input.ReadWholeBuffer();
  input.Close();
  Check(image.size() == 0x8000, "synthetic wrapper ELF has two guest pages");

  Loader::Elf64_Ehdr header {};
  std::array<Loader::Elf64_Phdr, 3> segments {};
  std::memcpy(&header, image.data(), sizeof(header));
  Check(header.e_phnum == segments.size() &&
            header.e_phoff + sizeof(segments) <= image.size(),
        "synthetic wrapper ELF program headers fit");
  std::memcpy(segments.data(), image.data() + header.e_phoff, sizeof(segments));
  std::fill(image.begin() + header.e_phoff,
            image.begin() + header.e_phoff + sizeof(segments), std::byte {0});
  header.e_entry = 0;
  header.e_phoff = 0x200;
  segments[0].p_flags = Loader::PF_R | Loader::PF_X;
  segments[1].p_flags = Loader::PF_R | Loader::PF_W;

  if (fixture == RegistryTrapFixture::RegmgrTruncated ||
      fixture == RegistryTrapFixture::SysctlTruncated) {
    const auto offset = fixture == RegistryTrapFixture::RegmgrTruncated
                            ? RegistryTrapOffset : SysctlTrapOffset;
    segments[0].p_filesz = offset + 15;
    segments[0].p_memsz = segments[0].p_filesz;
    segments[0].p_align = 1;
  }
  std::memcpy(image.data(), &header, sizeof(header));
  std::memcpy(image.data() + header.e_phoff, segments.data(), sizeof(segments));
  for (size_t offset = 0x400; offset < 0x800; offset += sizeof(Loader::Elf64_Dyn)) {
    Loader::Elf64_Dyn item {};
    std::memcpy(&item, image.data() + offset, sizeof(item));
    if (item.d_tag == 0) break;
    if (item.d_tag == Loader::DT_INIT || item.d_tag == Loader::DT_FINI) {
      item.d_un.d_val = 0;
      std::memcpy(image.data() + offset, &item, sizeof(item));
    }
  }
  std::fill(image.begin() + 0x4000, image.end(), std::byte {0});

  std::array<uint8_t, 27> cerror {
      0x48, 0x8d, 0x15, 0, 0, 0, 0, 0x89, 0x02, 0xff, 0x42, 0x04,
      0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff,
      0x48, 0xc7, 0xc2, 0xff, 0xff, 0xff, 0xff, 0xc3};
  const int32_t displacement = static_cast<int32_t>(
      RegistryTrapErrnoOffset - (RegistryTrapCerrorOffset + 7));
  std::memcpy(cerror.data() + 3, &displacement, sizeof(displacement));
  std::memcpy(image.data() + RegistryTrapCerrorOffset, cerror.data(), cerror.size());
  std::memcpy(image.data() + RegistryTrapOffset,
              RegistryTrapSignature.data(), RegistryTrapSignature.size());
  std::memcpy(image.data() + SysctlTrapOffset,
              SysctlTrapSignature.data(), SysctlTrapSignature.size());
  std::memcpy(image.data() + PollTrapOffset,
              PollTrapSignature.data(), PollTrapSignature.size());
  std::memcpy(image.data() + NanosleepTrapOffset,
              NanosleepTrapSignature.data(), NanosleepTrapSignature.size());
  std::memcpy(image.data() + RegistryTrapReadOnlyOffset,
              RegistryTrapSentinels.data(), sizeof(RegistryTrapSentinels));
  if (fixture == RegistryTrapFixture::RegmgrMismatch) {
    image[RegistryTrapOffset + 23] = std::byte {0xe0};
  } else if (fixture == RegistryTrapFixture::SysctlMismatch) {
    image[SysctlTrapOffset + 23] = std::byte {0xe0};
  }

  Common::File output;
  Check(output.Create(path), "rewrite synthetic wrapper ELF layout");
  uint32_t written = 0;
  output.Write(image.data(), static_cast<uint32_t>(image.size()), &written);
  Check(written == image.size() && output.Flush(), "save synthetic wrapper ELF");
  output.Close();
}

void CheckRegistryTrapInstalled(const Loader::Program* program) {
  Check(program != nullptr && program->base_size >= 0x8000,
        "synthetic wrapper ELF is loaded");
  const auto verify = [&](uint64_t offset, std::array<uint8_t, 24> expected) {
    expected[11] = 0x0b;
    Check(std::memcmp(reinterpret_cast<const void*>(program->base_vaddr + offset),
                      expected.data(), expected.size()) == 0,
          "verify exact native wrapper and UD2 before any machine-code execution");
  };
  verify(RegistryTrapOffset, RegistryTrapSignature);
  verify(SysctlTrapOffset, SysctlTrapSignature);
  verify(PollTrapOffset, PollTrapSignature);
  verify(NanosleepTrapOffset, NanosleepTrapSignature);
}

struct RegistryTrapResult {
  int64_t value;
  int64_t secondary;
};

using RegistryTrapCall = RegistryTrapResult (KYTY_SYSV_ABI *)(
    uint32_t, uint32_t, int32_t*, void*, size_t);
using SysctlTrapCall = RegistryTrapResult (KYTY_SYSV_ABI *)(
    const uint32_t*, uint32_t, void*, size_t*, const void*, size_t);
using PollTrapCall = RegistryTrapResult (KYTY_SYSV_ABI *)(void*, uint64_t, int32_t);
using NanosleepTrapCall = RegistryTrapResult (KYTY_SYSV_ABI *)(
    const Libs::LibKernel::KernelTimespec*, Libs::LibKernel::KernelTimespec*);

void CheckRegistryTrapCalls(Loader::Program* program) {
  using namespace Libs::LibKernel;
  CheckRegistryTrapInstalled(program);
  const auto base = program->base_vaddr;
  Check(Memory::ProtectGuestMemory(base, 0x4000,
                                   Common::VirtualMemory::Mode::ExecuteRead),
        "protect synthetic native code and read-only output sentinels");
  MEMORY_BASIC_INFORMATION protection {};
  Check(VirtualQuery(reinterpret_cast<const void*>(base + RegistryTrapReadOnlyOffset),
                      &protection, sizeof(protection)) == sizeof(protection) &&
            protection.Protect == PAGE_EXECUTE_READ,
        "read-only output fixture has host write protection");

  auto regmgr = reinterpret_cast<RegistryTrapCall>(base + RegistryTrapOffset);
  auto sysctl = reinterpret_cast<SysctlTrapCall>(base + SysctlTrapOffset);
  auto poll = reinterpret_cast<PollTrapCall>(base + PollTrapOffset);
  auto nanosleep = reinterpret_cast<NanosleepTrapCall>(base + NanosleepTrapOffset);
  auto* native_errno = reinterpret_cast<int32_t*>(base + RegistryTrapErrnoOffset);
  auto* cerror_calls = reinterpret_cast<uint32_t*>(base + RegistryTrapErrnoOffset + 4);
  auto* hle_errno = Libs::Posix::GetErrorAddr();
  const int saved_errno = *hle_errno;
  *cerror_calls = 0;
  const auto prepare_error = [&]() {
    *native_errno = -101;
    *hle_errno = Libs::Posix::POSIX_EINVAL;
    return *cerror_calls + 1;
  };
  const auto failure = [&](RegistryTrapResult result, int expected, uint32_t calls) {
    Check(result.value == -1 && result.secondary == -1,
          "unchanged native carry branch reaches cerror and returns minus one");
    Check(*native_errno == expected && *hle_errno == expected,
          "native cerror storage and imported HLE errno agree");
    Check(*cerror_calls == calls, "one native cerror branch executes per failed wrapper call");
  };

  auto* outputs = reinterpret_cast<int32_t*>(base + 0x5100);
  std::memcpy(outputs, RegistryTrapSentinels.data(), sizeof(RegistryTrapSentinels));
  auto expected_calls = prepare_error();
  failure(regmgr(2, 0x70020000, outputs, outputs + 1, sizeof(int32_t)),
          Libs::Posix::POSIX_ENOSYS, expected_calls);
  Check(std::memcmp(outputs, RegistryTrapSentinels.data(), sizeof(RegistryTrapSentinels)) == 0,
        "unsupported registry read leaves guest status and value unchanged");

  auto* read_only = reinterpret_cast<int32_t*>(base + RegistryTrapReadOnlyOffset);
  expected_calls = prepare_error();
  failure(regmgr(2, 0x70020000, read_only, read_only + 1, sizeof(int32_t)),
          Libs::Posix::POSIX_ENOSYS, expected_calls);
  Check(std::memcmp(read_only, RegistryTrapSentinels.data(), sizeof(RegistryTrapSentinels)) == 0,
        "unsupported registry read never writes read-only guest outputs");

  expected_calls = prepare_error();
  failure(regmgr(2, 0x70020000, reinterpret_cast<int32_t*>(uintptr_t {1}),
                 reinterpret_cast<void*>(uintptr_t {2}), sizeof(int32_t)),
          Libs::Posix::POSIX_ENOSYS, expected_calls);
  expected_calls = prepare_error();
  failure(regmgr(0x11, 0, outputs, nullptr, 0),
          Libs::Posix::POSIX_ENOSYS, expected_calls);
  Check(std::memcmp(outputs, RegistryTrapSentinels.data(), sizeof(RegistryTrapSentinels)) == 0,
        "unsupported registry initialization query does not manufacture ready status");

  Check(_putenv_s("KYTY_DIAGNOSTIC_REGMGR_KERNEL_TABLE", "1") == 0, "enable captured kernel registry rows");
  for (const auto& [key, expected]: {std::pair<uint32_t, int32_t> {0x09400100, 0}, {0x02020000, 18}, {0x05020000, 1}, {0x09400200, 3}, {0x09400300, 12}}) {
    std::memcpy(outputs, RegistryTrapSentinels.data(), sizeof(RegistryTrapSentinels));
    const auto before = *cerror_calls;
    const auto served = regmgr(2, key, outputs, outputs + 1, sizeof(int32_t));
    Check(served.value == 0 && *cerror_calls == before && outputs[0] == 0 && outputs[1] == expected,
          "captured kernel row answers GetInt with status 0 and the row's value");
  }
  for (const uint32_t key: {0x09400600u, 0x09c00100u, 0x70020000u}) {
    std::memcpy(outputs, RegistryTrapSentinels.data(), sizeof(RegistryTrapSentinels));
    expected_calls = prepare_error();
    failure(regmgr(2, key, outputs, outputs + 1, sizeof(int32_t)), Libs::Posix::POSIX_ENOSYS, expected_calls);
    Check(std::memcmp(outputs, RegistryTrapSentinels.data(), sizeof(RegistryTrapSentinels)) == 0,
          "instance-restricted, absent and unrelated keys stay unanswered");
  }
  expected_calls = prepare_error();
  failure(regmgr(2, 0x09400100, outputs, outputs + 1, sizeof(int64_t)), Libs::Posix::POSIX_ENOSYS, expected_calls);
  expected_calls = prepare_error();
  failure(regmgr(1, 0x09400100, outputs, outputs + 1, sizeof(int32_t)), Libs::Posix::POSIX_ENOSYS, expected_calls);
  Check(std::memcmp(outputs, RegistryTrapSentinels.data(), sizeof(RegistryTrapSentinels)) == 0,
        "wrong size and SetInt are not served from the captured rows");
  expected_calls = prepare_error();
  failure(regmgr(2, 0x09400100, read_only, read_only + 1, sizeof(int32_t)), Libs::Posix::POSIX_EFAULT, expected_calls);
  Check(std::memcmp(read_only, RegistryTrapSentinels.data(), sizeof(RegistryTrapSentinels)) == 0,
        "captured row read never writes read-only guest outputs");
  Check(_putenv_s("KYTY_DIAGNOSTIC_REGMGR_KERNEL_TABLE", "") == 0, "clear captured kernel registry rows");
  std::memcpy(outputs, RegistryTrapSentinels.data(), sizeof(RegistryTrapSentinels));
  expected_calls = prepare_error();
  failure(regmgr(2, 0x09400100, outputs, outputs + 1, sizeof(int32_t)), Libs::Posix::POSIX_ENOSYS, expected_calls);
  Check(std::memcmp(outputs, RegistryTrapSentinels.data(), sizeof(RegistryTrapSentinels)) == 0,
        "without the gate the TTS key keeps failing");

  Check(_putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_SYSCORE_GUEST_THREAD_FS10", "1") == 0,
        "enable exact sleep and idle-poll wrapper fixtures");
  auto* requested = reinterpret_cast<Libs::LibKernel::KernelTimespec*>(base + 0x5500);
  auto* remaining = reinterpret_cast<Libs::LibKernel::KernelTimespec*>(base + 0x5520);
  *requested = {0, 1000000};
  *remaining = {-1, -1};
  const auto sleep_result = nanosleep(requested, remaining);
  Check(sleep_result.value == 0 && remaining->tv_sec == 0 && remaining->tv_nsec == 0,
        "exact nanosleep wrapper resumes after a bounded Kyty sleep");
  expected_calls = prepare_error();
  failure(poll(nullptr, 0, 0), Libs::Posix::POSIX_ENOSYS, expected_calls);
  Check(_putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_SYSCORE_GUEST_THREAD_FS10", "") == 0,
        "clear exact sleep and idle-poll wrapper fixtures");

  auto* mib = reinterpret_cast<uint32_t*>(base + 0x5200);
  auto* length = reinterpret_cast<size_t*>(base + 0x5300);
  auto* values = reinterpret_cast<uint32_t*>(base + 0x5400);
  mib[0] = 9;
  mib[1] = 20;
  values[0] = 0x11223344;
  values[1] = 0x55667788;
  *length = sizeof(uint32_t);
  *native_errno = -101;
  *hle_errno = Libs::Posix::POSIX_EINVAL;
  const auto before_success = *cerror_calls;
  const auto page_size = sysctl(mib, 2, values, length, nullptr, 0);
  Check(page_size.value == 0 && values[0] == 0x4000 &&
            values[1] == 0x55667788 && *length == sizeof(uint32_t),
        "unchanged native sysctl returns the existing guest page size and exact width");
  Check(*cerror_calls == before_success && *native_errno == -101 &&
            *hle_errno == Libs::Posix::POSIX_EINVAL,
        "successful native sysctl clears carry and preserves errno");

  mib[0] = 0;
  mib[1] = 3;
  std::array<uint32_t, 26> oid_sentinels {};
  oid_sentinels.fill(0x5aa55aa5);
  std::memcpy(values, oid_sentinels.data(), sizeof(oid_sentinels));
  *length = sizeof(oid_sentinels);
  constexpr char unknown_name[] = "machdep.idps";
  auto* name = reinterpret_cast<char*>(base + 0x5800);
  std::memcpy(name, unknown_name, sizeof(unknown_name));
  expected_calls = prepare_error();
  failure(sysctl(mib, 2, values, length, name, sizeof(unknown_name) - 1),
          Libs::Posix::POSIX_ENOENT, expected_calls);
  Check(*length == sizeof(oid_sentinels) &&
            std::memcmp(values, oid_sentinels.data(), sizeof(oid_sentinels)) == 0,
        "unknown sysctl name leaves OID output and 64-bit length unchanged");

  expected_calls = prepare_error();
  failure(sysctl(nullptr, 2, values, length, nullptr, 0),
          Libs::Posix::POSIX_EFAULT, expected_calls);
  Check(*length == sizeof(oid_sentinels) &&
            std::memcmp(values, oid_sentinels.data(), sizeof(oid_sentinels)) == 0,
        "encoded sysctl bridge error becomes native EFAULT without output writes");
  *hle_errno = saved_errno;
}

void CheckSysctlSpanCalls(Loader::Program* program, const std::filesystem::path& directory) {
  using namespace Libs::LibKernel;
  static_assert(sizeof(size_t) == sizeof(uint64_t));
  CheckRegistryTrapInstalled(program);
  const auto base = program->base_vaddr;
  using RawCountCall = RegistryTrapResult (KYTY_SYSV_ABI *)(
      const uint32_t*, uint64_t, void*, size_t*, const void*, size_t);
  const auto sysctl = reinterpret_cast<RawCountCall>(base + SysctlTrapOffset);
  auto* native_errno = reinterpret_cast<int32_t*>(base + RegistryTrapErrnoOffset);
  auto* cerror_calls = reinterpret_cast<uint32_t*>(base + RegistryTrapErrnoOffset + 4);
  auto* hle_errno = Libs::Posix::GetErrorAddr();
  const int saved_errno = *hle_errno;
  auto* mib = reinterpret_cast<uint32_t*>(base + 0x6000);
  auto* length = reinterpret_cast<size_t*>(base + 0x6100);
  auto* output = reinterpret_cast<uint8_t*>(base + 0x6200);
  auto* input = reinterpret_cast<uint8_t*>(base + 0x6400);
  constexpr size_t output_bytes = 0x100;
  constexpr uint8_t sentinel = 0xa5;
  const auto unchanged = [](const void* address, size_t size) {
    const auto* bytes = static_cast<const uint8_t*>(address);
    return std::all_of(bytes, bytes + size, [](uint8_t value) { return value == sentinel; });
  };
  const auto reset = [&] {
    mib[0] = 9;
    mib[1] = 20;
    mib[2] = mib[3] = 0;
    *length = sizeof(uint32_t);
    std::memset(output, sentinel, output_bytes);
    std::memset(input, sentinel, output_bytes);
  };
  const auto invoke = [&](const uint32_t* name, uint64_t count, void* oldp,
                          size_t* oldlenp, const void* newp, size_t newlen,
                          int expected, const char* label) {
    const auto before = *cerror_calls;
    *native_errno = -1100;
    *hle_errno = Libs::Posix::POSIX_EBUSY;
    const auto result = sysctl(name, count, oldp, oldlenp, newp, newlen);
    if (expected == 0) {
      Check(result.value == 0 && *cerror_calls == before && *native_errno == -1100 &&
                *hle_errno == Libs::Posix::POSIX_EBUSY, label);
    } else {
      Check(result.value == -1 && result.secondary == -1 &&
                *cerror_calls == before + 1 && *native_errno == expected &&
                *hle_errno == expected, label);
    }
  };

  reset();
  invoke(mib, 0xfeedface00000002ull, output, length, nullptr, 0, 0,
         "native sysctl consumes only the uint32 MIB count");
  Check(*length == 4 && *reinterpret_cast<uint32_t*>(output) == 0x4000 &&
            unchanged(output + 4, output_bytes - 4), "native sysctl preserves exact value width");
  for (const uint64_t count: {0ull, 1ull, 5ull, 0xffffffffull}) {
    reset();
    invoke(reinterpret_cast<const uint32_t*>(uintptr_t {1}), count, output, length,
           nullptr, 0, Libs::Posix::POSIX_EINVAL,
           "unsupported native sysctl MIB count is rejected before pointer access");
    Check(*length == 4 && unchanged(output, output_bytes),
          "unsupported native sysctl count publishes no output");
  }

  reset();
  *length = UINT64_MAX;
  invoke(mib, 2, nullptr, length, nullptr, 0, 0, "native sysctl null output measures required size");
  Check(*length == 4 && unchanged(output, output_bytes),
        "native sysctl publishes the full uint64 required length");
  invoke(mib, 2, nullptr, nullptr, nullptr, 0, 0,
         "native sysctl known read may discard both value and length");
  invoke(mib, 2, output, nullptr, nullptr, 0, Libs::Posix::POSIX_ENOMEM,
         "native sysctl null oldlenp gives a nonnull output zero capacity");
  Check(unchanged(output, output_bytes), "native sysctl zero implicit capacity writes no value");
  for (size_t capacity: {size_t {0}, size_t {1}, size_t {3}}) {
    reset();
    *length = capacity;
    invoke(mib, 2, output, length, nullptr, 0, Libs::Posix::POSIX_ENOMEM,
           "native sysctl short output copies its prefix and returns ENOMEM");
    const uint32_t expected = 0x4000;
    Check(*length == capacity && std::memcmp(output, &expected, capacity) == 0 &&
              unchanged(output + capacity, output_bytes - capacity),
          "native sysctl short result reports copied bytes and preserves the tail");
  }
  reset();
  *length = 0x100000004ull;
  invoke(mib, 2, output, length, nullptr, 0, Libs::Posix::POSIX_EFAULT,
         "native sysctl validates the full uint64 advertised output span");
  Check(*length == 0x100000004ull && unchanged(output, output_bytes),
        "native sysctl cannot truncate a large size_t capacity to uint32");

  uint32_t host_mib[2] {9, 20};
  uint32_t host_output[2] {0xa5a5a5a5u, 0xa5a5a5a5u};
  size_t host_length = sizeof(uint32_t);
  ULONG_PTR stack_low = 0, stack_high = 0;
  GetCurrentThreadStackLimits(&stack_low, &stack_high);
  const auto in_stack = [&](const void* pointer, size_t size) {
    const auto address = reinterpret_cast<uintptr_t>(pointer);
    return address >= stack_low && address < stack_high && size <= stack_high - address;
  };
  Check(in_stack(host_mib, sizeof(host_mib)) && in_stack(host_output, sizeof(host_output)) &&
            in_stack(&host_length, sizeof(host_length)),
        "native sysctl host-local fixture belongs to this current stack");
  invoke(host_mib, 2, host_output, &host_length, nullptr, 0, 0,
         "mapped native sysctl wrapper supports original initializer current-stack locals");
  Check(host_output[0] == 0x4000 && host_output[1] == 0xa5a5a5a5u && host_length == 4,
        "native sysctl current-stack copyout is exact");
  auto* unrelated = static_cast<uint8_t*>(
      VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  Check(unrelated != nullptr && !in_stack(unrelated, 0x1000),
        "native sysctl unrelated host allocation is outside the current stack");
  std::memset(unrelated, sentinel, 0x1000);
  Memory::VirtualQueryInfo unrelated_region {};
  Check(Memory::KernelVirtualQuery(unrelated, 0, &unrelated_region, sizeof(unrelated_region)) != 0,
        "native sysctl unrelated host allocation is not registered guest memory");
  reset();
  invoke(mib, 2, unrelated, length, nullptr, 0, Libs::Posix::POSIX_EFAULT,
         "native sysctl does not admit arbitrary committed writable host memory");
  Check(*length == 4 && unchanged(unrelated, 0x1000),
        "native sysctl rejected host allocation remains unchanged");
  Check(VirtualFree(unrelated, 0, MEM_RELEASE), "release owned sysctl host-allocation control");

  constexpr uint64_t page = 0x4000;
  const uint64_t pages = Memory::AllocateRuntimeMemory(
      0, 3 * page, Common::VirtualMemory::Mode::ReadWrite, "sysctl_span_tests");
  Check(pages != 0, "allocate mapped native sysctl span fixture");
  auto* edge = reinterpret_cast<uint8_t*>(pages + page);
  auto* read_only = reinterpret_cast<uint8_t*>(pages + 2 * page);
  std::memset(reinterpret_cast<void*>(pages), sentinel, 3 * page);
  const size_t read_only_capacity = 4;
  std::memcpy(read_only + 0x20, &read_only_capacity, sizeof(read_only_capacity));
  Check(Memory::KernelMprotect(edge, page, 0) == 0 &&
            Memory::KernelMprotect(read_only, page, 1) == 0,
        "native sysctl span fixture has a guard and read-only page");

  reset();
  const uint32_t first_mib = 9;
  std::memcpy(edge - 4, &first_mib, sizeof(first_mib));
  invoke(reinterpret_cast<const uint32_t*>(edge - 4), 2, output, length,
         nullptr, 0, Libs::Posix::POSIX_EFAULT,
         "native sysctl validates the entire MIB before its second word");
  Check(*length == 4 && unchanged(output, output_bytes),
        "native sysctl invalid MIB leaves output and length unchanged");
  reset();
  const uint32_t short_length = 4;
  std::memcpy(edge - 4, &short_length, sizeof(short_length));
  invoke(mib, 2, output, reinterpret_cast<size_t*>(edge - 4), nullptr, 0,
         Libs::Posix::POSIX_EFAULT, "native sysctl reads all eight oldlenp bytes safely");
  Check(unchanged(output, output_bytes) &&
            std::memcmp(edge - 4, &short_length, sizeof(short_length)) == 0,
        "native sysctl partial length pointer produces no output");
  reset();
  std::memset(edge - 4, sentinel, 4);
  *length = 8;
  invoke(mib, 2, edge - 4, length, nullptr, 0, Libs::Posix::POSIX_EFAULT,
         "native sysctl checks the advertised output tail beyond a four-byte value");
  Check(*length == 8 && unchanged(edge - 4, 4),
        "native sysctl full-capacity failure leaves its writable prefix unchanged");
  reset();
  invoke(mib, 2, edge - 2, length, nullptr, 0, Libs::Posix::POSIX_EFAULT,
         "native sysctl rejects a value crossing the guard without a partial store");
  Check(*length == 4 && unchanged(edge - 2, 2),
        "native sysctl guarded value failure preserves prefix and length");
  reset();
  invoke(mib, 2, read_only, length, nullptr, 0, Libs::Posix::POSIX_EFAULT,
         "native sysctl rejects a read-only output");
  Check(*length == 4 && unchanged(read_only, 4), "native sysctl read-only output remains intact");
  reset();
  invoke(mib, 2, output, reinterpret_cast<size_t*>(read_only + 0x20), nullptr, 0,
         Libs::Posix::POSIX_EFAULT,
         "native sysctl preflights returned length before publishing a valid output");
  Check(unchanged(output, output_bytes) &&
            std::memcmp(read_only + 0x20, &read_only_capacity, sizeof(read_only_capacity)) == 0,
        "native sysctl invalid length publication preserves both outputs");
  Check(Memory::ProtectGuestHostMemory(
            reinterpret_cast<uint64_t>(read_only), page, Common::VirtualMemory::Mode::ReadWrite),
        "native sysctl fixture independently widens only host page access");
  reset();
  invoke(mib, 2, read_only, length, nullptr, 0, Libs::Posix::POSIX_EFAULT,
         "native sysctl registered guest read-only rights cannot use the host fallback");
  Check(*length == 4 && unchanged(read_only, 4),
        "native sysctl semantic permission failure publishes nothing");

  reset();
  mib[0] = 0;
  mib[1] = 3;
  constexpr char kernel_type_name[] = "kern.kern_type";
  std::memcpy(input, kernel_type_name, sizeof(kernel_type_name) - 1);
  *length = 8;
  invoke(mib, 2, output, length, input, sizeof(kernel_type_name) - 1, 0,
         "native sysctl resolves the original firmware kernel-type OID");
  Check(*length == 8 && reinterpret_cast<uint32_t*>(output)[0] == 1 &&
            reinterpret_cast<uint32_t*>(output)[1] == 0x7ffffcb3 && unchanged(output + 8, output_bytes - 8),
        "kernel-type name resolution preserves exact OID width and output tail");
  reset();
  mib[0] = 1;
  mib[1] = 0x7ffffcb3;
  *length = 8;
  invoke(mib, 2, output, length, nullptr, 0, 0,
         "native sysctl reads the captured retail kernel-type value");
  Check(*length == 4 && *reinterpret_cast<int32_t*>(output) == 1 && unchanged(output + 4, output_bytes - 4),
        "kernel-type read publishes only the four-byte integer");
  *length = 0;
  invoke(mib, 2, nullptr, length, nullptr, 0, 0,
         "kernel-type size query works without a destination buffer");
  Check(*length == 4, "kernel-type size query reports four bytes");
  *length = 3;
  std::memset(output, sentinel, output_bytes);
  invoke(mib, 2, output, length, nullptr, 0, Libs::Posix::POSIX_ENOMEM,
         "short kernel-type destination returns native ENOMEM");
  const int32_t kernel_type = 1;
  Check(*length == 3 && std::memcmp(output, &kernel_type, 3) == 0 && unchanged(output + 3, output_bytes - 3),
        "short kernel-type result preserves the uncopied tail");
  *length = 8;
  std::memset(output, sentinel, output_bytes);
  invoke(mib, 2, output, length, input, 4, Libs::Posix::POSIX_EPERM,
         "read-only kernel-type OID rejects writes");
  Check(*length == 8 && unchanged(output, output_bytes), "kernel-type write failure preserves both outputs");

  reset();
  mib[0] = 0;
  mib[1] = 3;
  constexpr char bd_drive_name[] = "hw.config.bd_drive";
  std::memcpy(input, bd_drive_name, sizeof(bd_drive_name) - 1);
  *length = 12;
  invoke(mib, 2, output, length, input, sizeof(bd_drive_name) - 1, 0,
         "native sysctl resolves the captured BD-drive OID");
  const std::array<uint32_t, 3> bd_drive_oid {6, 0x7ffffe22u, 0x7ffffe1au};
  Check(*length == sizeof(bd_drive_oid) && std::memcmp(output, bd_drive_oid.data(), sizeof(bd_drive_oid)) == 0 &&
            unchanged(output + sizeof(bd_drive_oid), output_bytes - sizeof(bd_drive_oid)),
        "BD-drive name resolution preserves the measured three-word OID width");
  reset();
  std::copy(bd_drive_oid.begin(), bd_drive_oid.end(), mib);
  *length = 8;
  invoke(mib, 3, output, length, nullptr, 0, 0,
         "native sysctl reads the captured BD-drive configuration");
  Check(*length == 4 && *reinterpret_cast<uint32_t*>(output) == 3 && unchanged(output + 4, output_bytes - 4),
        "BD-drive read publishes only the measured four-byte value");
  *length = 0;
  invoke(mib, 3, nullptr, length, nullptr, 0, 0,
         "BD-drive size query works without a destination buffer");
  Check(*length == 4, "BD-drive size query reports four bytes");
  *length = 3;
  std::memset(output, sentinel, output_bytes);
  invoke(mib, 3, output, length, nullptr, 0, Libs::Posix::POSIX_ENOMEM,
         "short BD-drive destination returns native ENOMEM");
  const uint32_t bd_drive = 3;
  Check(*length == 3 && std::memcmp(output, &bd_drive, 3) == 0 && unchanged(output + 3, output_bytes - 3),
        "short BD-drive result preserves the uncopied tail");
  *length = 8;
  std::memset(output, sentinel, output_bytes);
  invoke(mib, 3, output, length, input, 4, Libs::Posix::POSIX_EPERM,
         "read-only BD-drive OID rejects writes");
  Check(*length == 8 && unchanged(output, output_bytes), "BD-drive write failure preserves both outputs");

  for (const char* name: {"machdep.idps", "kern.kern_type.unavailable"}) {
    reset();
    mib[0] = 0;
    mib[1] = 3;
    const size_t size = std::strlen(name);
    std::memcpy(edge - size, name, size);
    *length = 104;
    invoke(mib, 2, output, length, edge - size, size, Libs::Posix::POSIX_ENOENT,
           "native sysctl counted missing name needs no readable trailing NUL");
    Check(*length == 104 && unchanged(output, output_bytes),
          "native sysctl missing name cannot manufacture OID data or length");
    invoke(mib, 2, output, length, edge - size, size + 1, Libs::Posix::POSIX_EFAULT,
           "native sysctl validates the whole advertised input including its last byte");
    Check(*length == 104 && unchanged(output, output_bytes),
          "native sysctl invalid input leaves OID and length unchanged");
    invoke(mib, 2, output, length, edge - size, (size_t {1} << 32) + size,
           Libs::Posix::POSIX_EFAULT, "native sysctl preserves all size_t input-length bits");
    Check(*length == 104 && unchanged(output, output_bytes),
          "native sysctl oversized input cannot be truncated to a valid name");
  }

  reset();
  invoke(mib, 2, mib, length, nullptr, 0, 0, "native sysctl snapshots MIB before aliased copyout");
  Check(mib[0] == 0x4000 && mib[1] == 20 && *length == 4,
        "native sysctl aliased selector result preserves unconsumed words");
  reset();
  *length = 8;
  invoke(mib, 2, length, length, nullptr, 0, 0,
         "native sysctl snapshots aliased capacity and publishes length after value");
  Check(*length == 4, "native sysctl output/length alias ends with the uint64 returned length");
  reset();
  mib[0] = 0;
  mib[1] = 3;
  constexpr char tsc_name[] = "machdep.tsc_freq";
  std::memcpy(input, tsc_name, sizeof(tsc_name) - 1);
  *length = sizeof(tsc_name) - 1;
  invoke(mib, 2, input, length, input, sizeof(tsc_name) - 1, 0,
         "native sysctl snapshots counted input before an aliased name-to-MIB output");
  const std::array<uint32_t, 2> tsc_oid {7, 0x100};
  Check(*length == sizeof(tsc_oid) && std::memcmp(input, tsc_oid.data(), sizeof(tsc_oid)) == 0 &&
            std::memcmp(input + sizeof(tsc_oid), tsc_name + sizeof(tsc_oid),
                        sizeof(tsc_name) - 1 - sizeof(tsc_oid)) == 0,
        "native sysctl aliased name resolution changes only its existing modeled OID bytes");

  reset();
  const auto pid = Libs::NativeKernelBridge::DispatchSyscall({0x14, {}});
  Check(pid.value > 0 && pid.posix_errno == 0, "native sysctl fixture uses the guest pid");
  mib[0] = 1;
  mib[1] = 14;
  mib[2] = 35;
  mib[3] = static_cast<uint32_t>(pid.value);
  *length = 0x98;
  invoke(mib, 4, output, length, nullptr, 0, Libs::Posix::POSIX_ENOSYS,
         "native sysctl extended 152-byte app-info read remains unsupported");
  Check(*length == 0x98 && unchanged(output, output_bytes),
        "native sysctl extended read returns no partial record");
  // a committed self record would replace the legacy category answers below, hence the throwaway scope
  char app_scope[21] {};
  std::snprintf(app_scope, sizeof(app_scope), "r%08lx%08lx", GetCurrentProcessId(),
                static_cast<unsigned long>(GetTickCount()));
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", app_scope) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1") == 0,
        "scope the app-info setter");
  invoke(mib, 4, nullptr, nullptr, edge - 0x97, 0x98, Libs::Posix::POSIX_EFAULT,
         "native sysctl app-info setter validates its complete input span");
  Check(unchanged(input, output_bytes) && *length == 0x98 && unchanged(output, output_bytes),
        "native sysctl invalid app-info setter stores no record");
  invoke(mib, 4, output, length, nullptr, 0, Libs::Posix::POSIX_ENOSYS,
         "native sysctl extended read still has no record after a faulting set");
  invoke(mib, 4, nullptr, nullptr, input, 0x98, 0,
         "native sysctl commits the write-only 152-byte app-info setter");
  Check(unchanged(input, output_bytes) && *length == 0x98 && unchanged(output, output_bytes),
        "native sysctl app-info setter changes no caller buffer");
  invoke(mib, 4, output, length, nullptr, 0, 0, "native sysctl extended read returns the committed record");
  Check(*length == 0x98 && std::memcmp(output, input, 0x98) == 0, "the committed record is the caller's 152 bytes");
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", "") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "") == 0,
        "leave the app-info setter scope");

  Process::PeerProcess app_peer {};
  Check(Process::FindPeerByPid(static_cast<int>(pid.value), &app_peer) && !app_peer.has_category,
        "app-info fixture begins with absent process category metadata");
  const auto missing_category = [&] {
    reset();
    mib[0] = 1;
    mib[1] = 14;
    mib[2] = 35;
    mib[3] = static_cast<uint32_t>(pid.value);
    *length = 0x58;
    *hle_errno = Libs::Posix::POSIX_EBUSY;
    Check(Libs::KernelGetAppInfo(static_cast<int>(pid.value), output) == KERNEL_ERROR_ENOENT &&
              unchanged(output, output_bytes) && *hle_errno == Libs::Posix::POSIX_EBUSY,
          "HLE app-info missing category returns ENOENT without a zero record");
    Check(Libs::KernelGetAppCategoryType(static_cast<int>(pid.value), reinterpret_cast<int*>(output)) ==
              KERNEL_ERROR_ENOENT && unchanged(output, output_bytes) &&
              *hle_errno == Libs::Posix::POSIX_EBUSY,
          "category getter preserves missing metadata instead of returning zero");
    Check(Libs::KernelGetAppCategoryType(static_cast<int>(pid.value),
              reinterpret_cast<int*>(uintptr_t {1})) == KERNEL_ERROR_ENOENT &&
              Libs::KernelGetAppCategoryType(-1, reinterpret_cast<int*>(output)) == KERNEL_ERROR_ESRCH &&
              unchanged(output, output_bytes),
          "category metadata lookup fails before publishing caller output");
    invoke(mib, 4, output, length, nullptr, 0, Libs::Posix::POSIX_ENOENT,
           "native app-info and HLE agree when process category is absent");
    Check(*length == 0x58 && unchanged(output, output_bytes),
          "missing category preserves native output and returned length");
  };
  missing_category();
  Check(Libs::KernelGetAppCategoryType(static_cast<int>(pid.value), nullptr) == KERNEL_ERROR_EINVAL &&
            Libs::KernelGetAppCategoryType(-1, nullptr) == KERNEL_ERROR_EINVAL,
        "original category getter rejects null before process lookup");
  Check(Libs::KernelGetAppInfo(static_cast<int>(pid.value), nullptr) == KERNEL_ERROR_EFAULT &&
            Libs::KernelGetAppInfo(static_cast<int>(pid.value), reinterpret_cast<void*>(uintptr_t {1})) ==
                KERNEL_ERROR_EFAULT &&
            Libs::KernelGetAppInfo(static_cast<int>(pid.value),
                reinterpret_cast<void*>(base + RegistryTrapReadOnlyOffset)) == KERNEL_ERROR_EFAULT &&
            Libs::KernelGetAppInfo(static_cast<int>(pid.value), edge - 0x57) == KERNEL_ERROR_EFAULT,
        "HLE app-info validates full output before missing-category handling");
  Check(Libs::KernelGetAppInfo(-1, output) == KERNEL_ERROR_ESRCH && unchanged(output, output_bytes),
        "HLE app-info preserves unknown-pid errors and caller output");
  const auto load_metadata = [&](const char* filename, const std::string& json) {
    const auto path = directory / filename;
    Common::File metadata;
    Check(metadata.Create(path), "create disposable app-info metadata fixture");
    uint32_t written = 0;
    metadata.Write(json.data(), static_cast<uint32_t>(json.size()), &written);
    Check(written == json.size() && metadata.Flush(), "write app-info metadata fixture");
    metadata.Close();
    Loader::SystemContentLoadParamSfo(path);
  };
  for (const int32_t category: {0, 0x1234}) {
    load_metadata(category == 0 ? "category_zero.json" : "category_nonzero.json",
                  "{\"applicationCategoryType\":" + std::to_string(category) + "}");
    app_peer = {};
    Check(Process::FindPeerByPid(static_cast<int>(pid.value), &app_peer) &&
              app_peer.has_category && app_peer.category == category,
          "app-info fixture category comes from explicit metadata including zero");
    reset();
    auto* category_output = reinterpret_cast<int*>(output);
    *hle_errno = Libs::Posix::POSIX_EBUSY;
    Check(Libs::KernelGetAppCategoryType(static_cast<int>(pid.value), category_output) == 0 &&
              *category_output == category && unchanged(output + sizeof(int), output_bytes - sizeof(int)) &&
              *hle_errno == Libs::Posix::POSIX_EBUSY,
          "category getter copies exactly four metadata-derived bytes including explicit zero");
    Check(Libs::KernelGetAppCategoryType(static_cast<int>(pid.value),
              reinterpret_cast<int*>(uintptr_t {1})) == KERNEL_ERROR_EFAULT &&
              Libs::KernelGetAppCategoryType(static_cast<int>(pid.value),
                  reinterpret_cast<int*>(base + RegistryTrapReadOnlyOffset)) == KERNEL_ERROR_EFAULT &&
              Libs::KernelGetAppCategoryType(static_cast<int>(pid.value),
                  reinterpret_cast<int*>(edge - 3)) == KERNEL_ERROR_EFAULT,
          "category copyout rejects inaccessible readonly and guard-crossing destinations");
    auto* guarded_category = reinterpret_cast<int*>(edge - sizeof(int));
    Check(Libs::KernelGetAppCategoryType(static_cast<int>(pid.value), guarded_category) == 0 &&
              *guarded_category == category,
          "category copyout accepts exactly four bytes ending at a guard page");
    reset();
    std::array<uint8_t, 0x58> expected {};
    std::memcpy(expected.data() + 0x50, &category, sizeof(category));
    Check(Libs::KernelGetAppInfo(static_cast<int>(pid.value), output) == 0 &&
              std::memcmp(output, expected.data(), expected.size()) == 0 &&
              unchanged(output + expected.size(), output_bytes - expected.size()),
          "HLE app-info retains the bounded legacy category compatibility view");
    reset();
    mib[0] = 1;
    mib[1] = 14;
    mib[2] = 35;
    mib[3] = static_cast<uint32_t>(pid.value);
    *length = expected.size();
    invoke(mib, 4, output, length, nullptr, 0, 0,
           "native app-info preserves explicitly supplied category zero and nonzero");
    Check(*length == expected.size() && std::memcmp(output, expected.data(), expected.size()) == 0 &&
              unchanged(output + expected.size(), output_bytes - expected.size()),
          "native and HLE legacy app-info views agree without widening output");
    std::memset(output, sentinel, output_bytes);
    *length = 0x52;
    invoke(mib, 4, output, length, nullptr, 0, Libs::Posix::POSIX_ENOMEM,
           "native short app-info query retains partial-copy semantics");
    Check(*length == 0x52 && std::memcmp(output, expected.data(), 0x52) == 0 &&
              unchanged(output + 0x52, output_bytes - 0x52),
          "native short app-info writes only the supplied capacity");
  }
  load_metadata("category_absent.json", "{}");
  missing_category();
  std::printf("RegistryTrapTests: category_getter_availability=pass copyout4=pass "
              "null_order=pass explicit_zero=pass\n");
  std::printf("RegistryTrapTests: app_info_missing_category=pass explicit_zero=pass "
              "legacy_bounds=pass metadata_reset=pass\n");

  Check(Memory::ProtectGuestMemory(pages, 3 * page, Common::VirtualMemory::Mode::ReadWrite) &&
            Memory::FreeGuestMemory(pages, 3 * page), "release owned native sysctl guarded pages");
  *hle_errno = saved_errno;
  std::printf("RegistryTrapTests: native_sysctl_spans=pass count32_size64=pass "
              "short_copy=pass aliases=pass current_stack_only=pass missing_records_unchanged=1\n");
}


void CheckRegistryTrapRejection(const std::filesystem::path& directory,
                                RegistryTrapFixture fixture, const char* label,
                                const char* expected_error) {
  const auto folder = directory / label;
  Check(std::filesystem::create_directory(folder), "create unsupported-wrapper fixture directory");
  const auto elf = folder / "libkernel.sprx";
  const auto evidence = folder / "load_rejection.log";
  WriteRegistryTrapElf(elf, fixture);
  std::wstring executable(32768, L'\0');
  const auto length = GetModuleFileNameW(nullptr, executable.data(),
                                       static_cast<DWORD>(executable.size()));
  Check(length > 0 && length < executable.size(), "locate wrapper rejection child executable");
  executable.resize(length);
  auto command = L"\"" + executable + L"\" --registry-trap-reject \"" +
                 elf.native() + L"\" \"" + evidence.native() + L"\"";
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process {};
  Check(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process),
        "start isolated unsupported-wrapper load test");
  const auto wait = WaitForSingleObject(process.hProcess, 10000);
  if (wait != WAIT_OBJECT_0) {
    TerminateProcess(process.hProcess, 126);
    WaitForSingleObject(process.hProcess, 1000);
  }
  DWORD exit_code = 0xffffffffu;
  const bool status_read = GetExitCodeProcess(process.hProcess, &exit_code) != FALSE;
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  Common::File log(evidence, Common::File::Mode::Read);
  Check(!log.IsInvalid(), "open unsupported-wrapper load evidence");
  const auto bytes = log.ReadWholeBuffer();
  log.Close();
  const std::string text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  Check(wait == WAIT_OBJECT_0 && status_read && exit_code == 321 &&
            text.find("REGISTRY_TRAP_REJECT_LOAD_BEGIN") != std::string::npos &&
            text.find(expected_error) != std::string::npos &&
            text.find("REGISTRY_TRAP_REJECT_LOAD_RETURNED") == std::string::npos,
        "recognized unsupported wrapper is rejected by the exact loader guard");
  std::printf("RegistryTrapTests: %s load rejected before wrapper invocation\n", label);
}

#endif

int RunRegistryTrapChild(int argc, char** argv) {
#if defined(_WIN32)
  if (argc < 2 || std::strcmp(argv[1], "--registry-trap-reject") != 0) return -1;
  if (argc != 4) return 2;
  const auto evidence = Common::PathFromUtf8(argv[3]);
  if (_wfreopen(evidence.c_str(), L"wb", stdout) == nullptr) return 3;
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
  RegistryTrapEnvironment environment;
  Common::InitializeThreads();
  Common::Subsystems subsystems;
  subsystems.Initialize<Config::Lifecycle>();
  Config::ConfigOptions options;
  options.printf_direction = Config::LogDirection::Silent;
  Config::Load(options);
  subsystems.Initialize<Log::Lifecycle>();
  subsystems.Initialize<Libs::LibKernel::Memory::Lifecycle>();
  std::printf("REGISTRY_TRAP_REJECT_LOAD_BEGIN\n");
  std::fflush(stdout);
  auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
  linker->LoadProgram(Common::PathFromUtf8(argv[2]));
  std::printf("REGISTRY_TRAP_REJECT_LOAD_RETURNED\n");
  std::fflush(stdout);
  linker->Clear();
  subsystems.Destroy();
  return 126;
#else
  return -1;
#endif
}

void CheckRforkTrapWithoutAudit(const std::filesystem::path& root) {
#if defined(_WIN32)
  RegistryTrapEnvironment environment;
  const auto directory = root / "rfork_without_audit";
  Check(std::filesystem::create_directory(directory), "create rfork trap fixture directory");
  const auto path = directory / "libkernel.sprx";
  WriteRegistryTrapElf(path, RegistryTrapFixture::Valid);
  Common::File input(path, Common::File::Mode::Read);
  auto image = input.ReadWholeBuffer();
  input.Close();
  constexpr std::array<uint8_t, 66> wrapper {
      0x53, 0x41, 0x54, 0x48, 0x89, 0xd3, 0x49, 0x89, 0xcc, 0x48, 0xc7, 0xc0, 0xfb, 0x00, 0x00, 0x00,
      0x49, 0x89, 0xca, 0x0f, 0x05, 0x72, 0x1f, 0x83, 0xfa, 0x00, 0x75, 0x04, 0x41, 0x5c, 0x5b, 0xc3,
      0x48, 0x89, 0xf4, 0x4c, 0x89, 0xe7, 0xff, 0xd3, 0x89, 0xc7, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00,
      0x00, 0x49, 0x89, 0xca, 0x0f, 0x05, 0x41, 0x5c, 0x5b, 0x48, 0x8d, 0x15, 0xf4, 0xfe, 0xff, 0xff,
      0xff, 0xe2};
  std::memcpy(image.data() + 0x1a0, wrapper.data(), wrapper.size());
  image[0x204a] = std::byte {0x0f};
  image[0x204b] = std::byte {0x05};
  Common::File output;
  Check(output.Create(path), "create native rfork wrapper fixture");
  uint32_t written = 0;
  output.Write(image.data(), static_cast<uint32_t>(image.size()), &written);
  Check(written == image.size() && output.Flush(), "write native rfork wrapper fixture");
  output.Close();
  Check(_putenv_s("KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD", "1") == 0 &&
            std::getenv("KYTY_DIAGNOSTIC_SYSCORE_RFORK_AUDIT") == nullptr,
        "enable live rfork without an audit flag");
  auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
  auto* program = linker->LoadProgram(path);
  linker->RelocateAll();
  const auto base = program->base_vaddr;
  const auto* mapped = reinterpret_cast<const uint8_t*>(base + 0x1a0);
  Check(mapped[0x13] == 0x0f && mapped[0x14] == 0x0b,
        "live rfork traps syscall 0xfb without audit diagnostics");
  using Rfork = int64_t (KYTY_SYSV_ABI *)(uint64_t, uint64_t, uint64_t, uint64_t);
  const auto invoke = reinterpret_cast<Rfork>(base + 0x1a0);
  auto* native_errno = reinterpret_cast<int32_t*>(base + RegistryTrapErrnoOffset);
  auto* cerror_calls = reinterpret_cast<uint32_t*>(base + RegistryTrapErrnoOffset + 4);
  *native_errno = 0;
  *cerror_calls = 0;
  Check(invoke(0, 0, 0, 0) == -1 && *native_errno == Libs::Posix::POSIX_ENOSYS && *cerror_calls == 1,
        "unsupported rfork returns guest errno through its original cerror branch");
  linker->Clear();
  Common::File unchanged(path, Common::File::Mode::Read);
  const auto source = unchanged.ReadWholeBuffer();
  Check(std::memcmp(source.data() + 0x1a0, wrapper.data(), wrapper.size()) == 0,
        "rfork trap preserves source syscall bytes");
  std::printf("RegistryTrapTests: live rfork without audit traps 0xfb and rejects unsupported calls\n");
#endif
}

void CheckRegistryTraps(const std::filesystem::path& root) {
#if defined(_WIN32)
  RegistryTrapEnvironment environment;
  const auto directory = root / "native_wrapper_traps";
  Check(std::filesystem::create_directory(directory), "create native wrapper fixture directory");
  const auto path = directory / "libkernel.sprx";
  WriteRegistryTrapElf(path, RegistryTrapFixture::Valid);
  auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
  Check(linker->FindProgramByFileName(path) == nullptr,
        "native wrapper fixture is not already loaded");
  auto* program = linker->LoadProgram(path);
  CheckRegistryTrapInstalled(program);
  linker->RelocateAll();
  CheckRegistryTrapCalls(program);
  CheckSysctlSpanCalls(program, directory);
  const auto handle = program->unique_id;
  const auto base = program->base_vaddr;
  Check(linker->UnloadProgram(program) == 0, "unload synthetic native wrapper owner");
  CheckModuleLifetimeUnmapped(handle, base);

  Common::File unchanged(path, Common::File::Mode::Read);
  Check(!unchanged.IsInvalid(), "reopen immutable synthetic wrapper source");
  const auto image = unchanged.ReadWholeBuffer();
  unchanged.Close();
  Check(image.size() == 0x8000 &&
            std::memcmp(image.data() + RegistryTrapOffset,
                        RegistryTrapSignature.data(), RegistryTrapSignature.size()) == 0 &&
            std::memcmp(image.data() + SysctlTrapOffset,
                        SysctlTrapSignature.data(), SysctlTrapSignature.size()) == 0 &&
            std::memcmp(image.data() + PollTrapOffset,
                        PollTrapSignature.data(), PollTrapSignature.size()) == 0 &&
            std::memcmp(image.data() + NanosleepTrapOffset,
                        NanosleepTrapSignature.data(), NanosleepTrapSignature.size()) == 0,
        "loader traps change only mapped code and preserve source syscall bytes");

  program = linker->LoadProgram(path);
  CheckRegistryTrapInstalled(program);
  const auto second_handle = program->unique_id;
  const auto second_base = program->base_vaddr;
  auto call = reinterpret_cast<RegistryTrapCall>(second_base + RegistryTrapOffset);
  auto* native_errno = reinterpret_cast<int32_t*>(second_base + RegistryTrapErrnoOffset);
  auto* calls = reinterpret_cast<uint32_t*>(second_base + RegistryTrapErrnoOffset + 4);
  const auto saved_errno = *Libs::Posix::GetErrorAddr();
  const auto result = call(2, 0x70020000, reinterpret_cast<int32_t*>(uintptr_t {1}),
                           reinterpret_cast<void*>(uintptr_t {2}), sizeof(int32_t));
  Check(result.value == -1 && result.secondary == -1 && *calls == 1 &&
            *native_errno == Libs::Posix::POSIX_ENOSYS &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOSYS,
        "reloaded wrapper owner obtains a working registered trap");
  *Libs::Posix::GetErrorAddr() = saved_errno;
  linker->Clear();
  CheckModuleLifetimeUnmapped(second_handle, second_base);

  constexpr const char* regmgr_error =
      "Unsupported libkernel native 0x214 wrapper at +0x1a00: incomplete or mismatched signature";
  constexpr const char* sysctl_error =
      "Unsupported libkernel native 0xca wrapper at +0xf40: incomplete or mismatched signature";
  CheckRegistryTrapRejection(directory, RegistryTrapFixture::RegmgrMismatch,
                             "regmgr_mismatch", regmgr_error);
  CheckRegistryTrapRejection(directory, RegistryTrapFixture::RegmgrTruncated,
                             "regmgr_truncated", regmgr_error);
  CheckRegistryTrapRejection(directory, RegistryTrapFixture::SysctlMismatch,
                             "sysctl_mismatch", sysctl_error);
  CheckRegistryTrapRejection(directory, RegistryTrapFixture::SysctlTruncated,
                             "sysctl_truncated", sysctl_error);
  CheckRforkTrapWithoutAudit(root);
  std::printf("RegistryTrapTests: actual loader traps, native carry/errno and sysctl cases passed\n");
#endif
}
