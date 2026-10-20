#if defined(_WIN32)
// Syscall 0x214 against a small registry laid out the way the 13.60 kernel keeps it: 40-byte rows, a value pool, a defaults pool, two NVS halves, the readiness globals and the SetInt validator table.
void CheckRegMgrSnapshot(const std::filesystem::path& root) {
  using namespace Libs;
  using namespace Libs::LibKernel;
  RegistryTrapEnvironment clean;

  std::vector<uint8_t> table(40 * 15);
  const auto row = [&](size_t i, uint32_t key, uint16_t type, uint16_t size, uint8_t a, int32_t live, uint16_t nvs, uint8_t perm, uint16_t sel,
                       int32_t dflt) {
    auto* r = table.data() + i * 40;
    std::memcpy(r, &key, 4);
    std::memcpy(r + 4, &type, 2);
    std::memcpy(r + 6, &size, 2);
    r[0xa] = a;
    r[0xb] = 2;
    std::memcpy(r + 0xc, &live, 4);
    std::memcpy(r + 0x10, &nvs, 2);
    r[0x18] = perm;
    std::memcpy(r + 0x20, &sel, 2);
    std::memcpy(r + 0x24, &dflt, 4);
    return r;
  };
  row(0, 0x7a010000, 0, 4, 1, 5, 0x40, 1, 1, 9)[0x1d] = 1;
  row(1, 0x7a020000, 0, 4, 0, 0, 0x648, 1, 1, 3);
  row(2, 0x7a030000, 0, 4, 1, 77, 0x44, 0, 1, 1234);
  row(3, 0x7a040000, 1, 16, 2, 0, 0x50, 1, 0, 'A');
  row(4, 0x7a050000, 2, 8, 16, 0x20, 0x60, 1, 1, 0);
  auto* array = row(5, 0x7a060000, 0, 4, 16, 0x40, 0x68, 1, 1, 0);
  array[0x15] = 3;
  array[0x16] = 8;
  row(6, 0x0b060000, 0, 4, 1, 0, 0x78, 1, 1, 0);
  row(7, 0x01400000, 0, 4, 1, 2, 0x7c, 1, 1, 0);
  row(8, 0x7a080000, 2, 8, 2, 0x60, 0, 1, 1, 0)[0x13] = 1;
  row(9, 0x7a090000, 0, 4, 0, 0, 0x600, 1, 1, 0);
  row(10, 0x02010000, 0, 4, 0, 0, 0x84, 1, 1, 0);
  row(11, 0x02130000, 0, 4, 0, 0, 0x88, 1, 1, 0);
  row(12, 0x02860100, 0, 4, 0, 0, 0x8c, 1, 1, 0);
  row(13, 0x020c0000, 0, 4, 1, 1, 0x90, 1, 1, 0);
  row(14, 0x7a0a0000, 1, 16, 16, 0x80, 0, 1, 0, 0);

  std::vector<uint8_t> head(16), pool(0x1000), pool2(0x10), nvs_a(0x590), nvs_b(0x590), globals(0x60), mode_mask(4), rodata(0x400);
  std::vector<uint8_t> hw(0x80), region(0x7c), version(0x28);
  const uint16_t count = 15;
  std::memcpy(head.data(), &count, 2);
  std::memcpy(pool.data(), "hello", 6);
  for (int i = 0; i < 8; i++) {
    pool[0x20 + i] = static_cast<uint8_t>(0xa0 + i);
    pool2[i] = static_cast<uint8_t>(1 + i);
  }
  for (int i = 0; i < 3; i++) {
    const int32_t element = 100 + i;
    std::memcpy(pool.data() + 0x40 + 4 * i, &element, 4);
  }
  std::memcpy(pool.data() + 0x60, "abcdefg", 8);
  std::memcpy(pool.data() + 0x80, "captured", 9);
  const uint32_t stored = 0x11223344;
  std::memcpy(nvs_b.data() + 8, &stored, 4);
  const auto put32 = [](std::vector<uint8_t>& bytes, size_t offset, uint32_t v) { std::memcpy(bytes.data() + offset, &v, 4); };
  put32(globals, 0, 4);
  put32(globals, 8, 1);
  put32(globals, 0x50, 7);
  put32(mode_mask, 0, 4);
  put32(rodata, 8, 4);
  put32(rodata, 0x30, 0x7a010000);
  rodata[0x35] = 1;
  rodata[0x36] = 1;
  put32(rodata, 0x38, 0);
  put32(rodata, 0x3c, 10);
  hw[0] = 0xfe;
  hw[1] = 0xff;
  put32(hw, 0xc, 0xffffffff);
  put32(region, 0, 1);
  std::memcpy(region.data() + 4, "JP", 3);
  put32(region, 8, 4);
  std::memcpy(region.data() + 12, "US", 3);
  std::memcpy(region.data() + 0x78, "XX", 3);
  put32(version, 0, 0x01020304);
  put32(version, 0x24, 0x05060708);

  const auto write_snapshot = [&](const std::filesystem::path& at) {
    std::filesystem::create_directories(at);
    const std::pair<const char*, const std::vector<uint8_t>*> files[] = {
        {"live_regmgr_head.bin", &head},       {"live_regmgr_table.bin", &table},     {"live_regmgr_pool.bin", &pool},
        {"live_regmgr_pool2.bin", &pool2},     {"live_regmgr_nvs_a.bin", &nvs_a},     {"live_regmgr_nvs_b.bin", &nvs_b},
        {"live_regmgr_globals.bin", &globals}, {"live_regmgr_modemask.bin", &mode_mask}, {"live_regmgr_rodata.bin", &rodata},
        {"live_regmgr_hw.bin", &hw},           {"live_regmgr_region.bin", &region},   {"live_regmgr_version.bin", &version}};
    std::string manifest;
    for (const auto& [name, bytes]: files) {
      std::ofstream(at / name, std::ios::binary).write(reinterpret_cast<const char*>(bytes->data()), static_cast<std::streamsize>(bytes->size()));
      manifest += AuthInfo::DigestHex(AuthInfo::Sha256(bytes->data(), bytes->size())) + " *" + name + "\n";
    }
    std::ofstream(at / "regmgr_snapshot.sha256", std::ios::binary) << manifest;
    return AuthInfo::DigestHex(AuthInfo::Sha256(manifest.data(), manifest.size()));
  };
  const auto use = [](const std::filesystem::path& at, const std::string& sha) {
    Check(_putenv_s(RegMgr::kSnapshotEnvironment, at.string().c_str()) == 0 && _putenv_s(RegMgr::kSnapshotSha256Environment, sha.c_str()) == 0,
          "point at the registry snapshot");
  };

  const auto become = [](int pid, uint64_t authority, bool capture, bool bit62) {
    auto fixture = MakeAuthInfoScopeLifecycleFixture(pid);
    fixture.identity.authority_id = authority;
    AuthInfoScopeStore64(fixture.record.data(), authority);
    AuthInfoScopeStore64(fixture.record.data() + 8, bit62 ? 1ull << 62 : 0);
    Check(AuthInfo::BuildCaptureEnvelope(fixture.record, fixture.identity, &fixture.capture, nullptr), "build registry caller identity");
    Process::ClearVerifiedOriginalSelf();
    Process::InstallVerifiedOriginalSelf(fixture.identity);
    if (capture) Check(Process::InstallVerifiedAuthInfo(fixture.capture), "install registry caller capability");
  };

  void* memory = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&memory, 0x4000, 3, 0, "regmgr-snapshot") == OK, "map registry guest buffers");
  auto* status = static_cast<int32_t*>(memory);
  auto* value = static_cast<uint8_t*>(memory) + 0x100;
  const auto call = [&](uint32_t op, uint32_t key, uint64_t size, bool null_value = false, bool null_status = false) {
    *status = RegistryTrapSentinels[0];
    return NativeKernelBridge::DispatchSyscall({0x214, {op, key, null_status ? 0 : reinterpret_cast<uint64_t>(status),
                                                        null_value ? 0 : reinterpret_cast<uint64_t>(value), size}});
  };
  const auto answers = [&](uint32_t op, uint32_t key, uint64_t size, uint32_t expected) {
    const auto reply = call(op, key, size);
    return reply.value == 0 && static_cast<uint32_t>(*status) == expected;
  };
  const auto unanswered = [&](uint32_t op, uint32_t key, uint64_t size) {
    const auto reply = call(op, key, size);
    return reply.value == -1 && reply.posix_errno == Posix::POSIX_ENOSYS && *status == RegistryTrapSentinels[0];
  };
  const auto get_int = [&](uint32_t key) {
    std::memset(value, 0xcc, 4);
    int32_t result = 0x5a5a5a5a;
    if (answers(2, key, 4, 0)) std::memcpy(&result, value, 4);
    return result;
  };
  const auto set_int = [&](uint32_t key, int32_t v, uint32_t expected) {
    std::memcpy(value, &v, 4);
    return answers(1, key, 4, expected);
  };

  const auto captured = write_snapshot(root / "main");
  use(root / "main", captured);
  Process::ScopedGuestProcessPid as_caller(7300);
  become(7300, 0x4800000000000007ull, true, true);

  Check(get_int(0x7a010000) == 5, "GetInt reads a live in-row value");
  std::memset(value, 0xcc, 4);
  Check(answers(7, 0x7a010000, 4, 0) && std::memcmp(value, "\x09\x00\x00\x00", 4) == 0, "op 7 reads the row default");
  Check(set_int(0x7a010000, 11, 0x800d0225) && set_int(0x7a010000, -1, 0x800d0224), "the validator table bounds SetInt");
  Check(set_int(0x7a010000, 5, 0) && set_int(0x7a010000, 7, 0) && get_int(0x7a010000) == 7, "SetInt stores and reads back");

  Check(get_int(0x7a020000) == 0x11223344, "a row without memory storage reads NVS");
  Check(set_int(0x7a020000, 42, 0) && get_int(0x7a020000) == 42, "an NVS row keeps what was written");
  Check(get_int(0x7a090000) == static_cast<int32_t>(0x5a5a5a5a) && static_cast<uint32_t>(*status) == 0x800d0002, "an NVS offset between the halves is refused");

  Check(get_int(0x7a030000) == 1234, "a caller without row permission gets the default");
  Check(set_int(0x7a030000, 5, 0) && get_int(0x7a030000) == 1234, "a defaulted SetInt succeeds without storing");

  std::memset(value, 0xcc, 32);
  Check(answers(4, 0x7a040000, 16, 0) && std::strcmp(reinterpret_cast<char*>(value), "hello") == 0, "GetStr copies the string");
  Check(answers(4, 0x7a040000, 8, 0x800d0208), "GetStr wants the whole row");
  std::memset(value, 0, 32);
  std::memcpy(value, "world", 6);
  Check(answers(3, 0x7a040000, 16, 0), "SetStr stores");
  std::memset(value, 0xcc, 32);
  Check(answers(4, 0x7a040000, 16, 0) && std::strcmp(reinterpret_cast<char*>(value), "world") == 0, "GetStr reads the new string");
  std::memset(value, 0xcc, 32);
  Check(answers(8, 0x7a040000, 16, 0) && std::strcmp(reinterpret_cast<char*>(value), "AAAAAAAAAAAAAAA") == 0, "op 8 fills from the default byte");
  Check(unanswered(8, 0x7a040000, 20), "op 8 past an unterminated default is left to the caller");

  std::memset(value, 0xcc, 16);
  Check(answers(9, 0x7a050000, 8, 0) && std::memcmp(value, "\x01\x02\x03\x04\x05\x06\x07\x08", 8) == 0, "op 9 copies the pooled default");
  std::memset(value, 0xcc, 16);
  Check(answers(6, 0x7a050000, 8, 0) && std::memcmp(value, "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7", 8) == 0, "GetBin reads the value pool");
  std::memset(value, 0xff, 8);
  Check(answers(5, 0x7a050000, 8, 0), "SetBin stores");
  std::memset(value, 0xcc, 16);
  Check(answers(6, 0x7a050000, 8, 0) && std::memcmp(value, "\xff\xff\xff\xff\xff\xff\xff\xff", 8) == 0, "GetBin reads the stored bytes");

  Check(get_int(0x7a060100) == 101 && get_int(0x7a060200) == 102, "array keys index the pool");
  Check(answers(2, 0x7a060300, 4, 0x800d0203), "array keys stop at the row's count");

  Check(set_int(0x0b060000, 3, 0) && get_int(0x0b060000) == 0, "a masked audio-mode key ignores the write");
  std::memcpy(value, "\x09\x00\x00\x00", 4);
  Check(unanswered(1, 0x01400000, 4) && get_int(0x01400000) == 2, "a key with a kernel side effect is left untouched");
  Check(get_int(0x02860100) == -2, "a hardware byte key reads sign-extended from the captured image");
  Check(get_int(0x02010000) == 0 && get_int(0x02130000) == 0, "the 0xff byte and -1 dword sentinels read as 0");
  Check(unanswered(1, 0x02010000, 4), "a hardware key write is left to the caller");

  std::memset(value, 0, 16);
  std::memcpy(value, "blocked", 8);
  Check(unanswered(3, 0x7a0a0000, 16), "an NVS-less memory row refuses session storage while the diagnostic gate is off");
  std::memset(value, 0xcc, 16);
  Check(answers(4, 0x7a0a0000, 16, 0) && std::strcmp(reinterpret_cast<char*>(value), "captured") == 0,
        "a refused session write leaves shared memory unchanged");

  auto* mib = reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(memory) + 0x1000);
  auto* oid = mib + 4;
  auto* length = reinterpret_cast<size_t*>(static_cast<uint8_t*>(memory) + 0x1040);
  auto* name = static_cast<char*>(memory) + 0x1060;
  auto* mode = reinterpret_cast<int32_t*>(static_cast<uint8_t*>(memory) + 0x10a0);
  const auto sysctl = [&](uint32_t* at, void* out, void* in, uint64_t in_len) {
    return NativeKernelBridge::DispatchSyscall({0xca, {reinterpret_cast<uint64_t>(at), 2, reinterpret_cast<uint64_t>(out),
                                                       out != nullptr ? reinterpret_cast<uint64_t>(length) : 0, reinterpret_cast<uint64_t>(in), in_len}});
  };
  mib[0] = 0;
  mib[1] = 3;
  *length = 8;
  std::memcpy(name, "kern.backup_restore_mode", 24);
  Check(sysctl(mib, oid, name, 24).value == 0 && *length == 8 && oid[0] == 1 && oid[1] == 0x7ffffeb8, "kern.backup_restore_mode has its 13.60 OID");
  *length = 4;
  *mode = -1;
  Check(sysctl(oid, mode, nullptr, 0).value == 0 && *length == 4 && *mode == 1, "kern.backup_restore_mode reads 0x020c0000");
  Check(set_int(0x020c0000, 0, 0) && get_int(0x020c0000) == 0, "0x020c0000 takes a write");
  *length = 4;
  *mode = -1;
  Check(sysctl(oid, mode, nullptr, 0).value == 0 && *mode == 1, "the handler keeps its first fetch");
  const auto refused = sysctl(oid, nullptr, mode, 4);
  Check(refused.value == -1 && refused.posix_errno == Posix::POSIX_EPERM, "kern.backup_restore_mode takes no new value");

  std::memset(value, 0xcc, 16);
  Check(answers(4, 0x7a080000, 4, 0) && std::strcmp(reinterpret_cast<char*>(value), "abc") == 0, "a short GetStr on a 0x100 row terminates");
  std::memset(value, 0xcc, 16);
  Check(answers(6, 0x7a080000, 4, 0) && std::memcmp(value, "abcd", 4) == 0 && value[4] == 0xcc, "a short GetBin on a 0x100 row copies only what fits");
  Check(answers(6, 0x7a080000, 9, 0x800d0208), "a 0x100 row refuses a larger buffer");

  Check(answers(2, 0x7a0f0000, 4, 0x800d0203), "a missing key");
  Check(call(2, 0x7a010000, 4, true).value == 0 && static_cast<uint32_t>(*status) == 0x800d0202, "no value buffer");
  Check(answers(6, 0x7a050000, 0x801, 0x800d0208), "an oversized request");
  const auto no_status = call(2, 0x7a010000, 4, false, true);
  Check(no_status.value == -1 && no_status.posix_errno == Posix::POSIX_EFAULT, "no status pointer");
  Check(call(0x11, 0, 0, true).value == 0 && *status == 0, "op 0x11 reports a ready registry");
  Check(call(0, 1, 0, true).value == 0 && static_cast<uint32_t>(*status) == 0x05060708 && call(0, 2, 0, true).value == 0 &&
            static_cast<uint32_t>(*status) == 0x01020304,
        "op 0 reads the captured version block");
  Check(call(0x12, 0, 0, true).value == 0 && *status == 4, "op 0x12 reports the region id");
  std::memset(value, 0xcc, 8);
  Check(answers(0x13, 0, 4, 0) && std::strcmp(reinterpret_cast<char*>(value), "US") == 0, "op 0x13 copies the code for the region id");
  Check(answers(0x13, 0, 2, 0x800d0202), "op 0x13 wants room for the code");
  Check(unanswered(0x16, 0x7a010000, 4), "undecoded ops are left to the caller");

  become(7300, 0x4800000000000007ull, true, false);
  const auto denied = call(2, 0x7a010000, 4);
  Check(denied.value == -1 && denied.posix_errno == Posix::POSIX_EPERM && *status == RegistryTrapSentinels[0], "a measured clear bit 62 is EPERM");
  become(7300, 0x4800000000000007ull, false, false);
  Check(unanswered(2, 0x7a010000, 4), "an unmeasured bit 62 is left to the caller");
  become(7300, 0x4800000000010003ull, true, true);
  Check(get_int(0x7a010000) == 7, "the restricted authority reads a row it may read");
  Check(answers(2, 0x7a020000, 4, 0x800d0218) && answers(2, 0x7a0f0000, 4, 0x800d0203), "the restricted authority is refused other rows");
  Check(set_int(0x7a010000, 8, 0x800d0218) && answers(0x11, 0, 0, 0x800d0218), "the restricted authority cannot write or ask readiness");

  become(7300, 0x4800000000000007ull, true, true);
  const auto scope = [](const char* name) {
    Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", name) == 0 && _putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1") == 0,
          "scope the registry");
  };
  char first[21] {};
  char second[21] {};
  std::snprintf(first, sizeof(first), "r%08lx%08lx", GetCurrentProcessId(), static_cast<unsigned long>(GetTickCount()));
  std::snprintf(second, sizeof(second), "s%08lx%08lx", GetCurrentProcessId(), static_cast<unsigned long>(GetTickCount()));
  Check(_putenv_s("KYTY_DIAGNOSTIC_REGMGR_SESSION_STORE", "1") == 0, "enable diagnostic registry session storage");
  scope(first);
  Check(get_int(0x7a020000) == 0x11223344 && set_int(0x7a020000, 77, 0), "a scope starts from the capture");
  std::memset(value, 0, 16);
  std::memcpy(value, "recovered", 10);
  Check(answers(3, 0x7a0a0000, 16, 0), "the diagnostic gate stores an NVS-less row in scope-shared memory");
  {
    Process::ScopedGuestProcessPid peer(7301);
    become(7301, 0x4800000000000007ull, true, true);
    std::memset(value, 0xcc, 16);
    Check(answers(4, 0x7a0a0000, 16, 0) && std::strcmp(reinterpret_cast<char*>(value), "recovered") == 0,
          "a peer guest process in the same scope reads the session write");
  }
  become(7300, 0x4800000000000007ull, true, true);
  scope(second);
  std::memset(value, 0xcc, 16);
  Check(get_int(0x7a020000) == 0x11223344 && answers(4, 0x7a0a0000, 16, 0) &&
            std::strcmp(reinterpret_cast<char*>(value), "captured") == 0,
        "another scope does not see session writes");
  scope(first);
  std::memset(value, 0xcc, 16);
  Check(get_int(0x7a020000) == 77 && answers(4, 0x7a0a0000, 16, 0) &&
            std::strcmp(reinterpret_cast<char*>(value), "recovered") == 0,
        "the scope keeps its own persistent and session writes");
  scope("");
  Check(_putenv_s("KYTY_DIAGNOSTIC_REGMGR_SESSION_STORE", "") == 0, "disable diagnostic registry session storage");

  use(root / "main", std::string(64, '0'));
  Check(unanswered(2, 0x7a010000, 4), "a capture whose manifest does not match is not used");
  hw[1] = 3;
  put32(hw, 0xc, 0x12345);
  const auto fresh = write_snapshot(root / "fresh");
  use(root / "fresh", fresh);
  Check(get_int(0x7a020000) == 0x11223344, "pointing at another capture directory starts over");
  Check(get_int(0x02010000) == 3 && get_int(0x02130000) == 0x12345, "0x02130000 is a whole dword");
  Check(_putenv_s(RegMgr::kSnapshotEnvironment, "") == 0 && _putenv_s(RegMgr::kSnapshotSha256Environment, "") == 0, "clear the registry snapshot");
  Process::ClearVerifiedOriginalSelf();
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), 0x4000) == OK, "release registry guest buffers");
}
#endif
