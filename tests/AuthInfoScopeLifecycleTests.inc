#if defined(_WIN32)
struct AuthInfoScopeLifecycleFixture {
  Libs::LibKernel::AuthInfo::ImageIdentity identity {};
  Libs::LibKernel::AuthInfo::Record record {};
  Libs::LibKernel::AuthInfo::Capture capture {};
};
void AuthInfoScopeStore64(uint8_t* data, uint64_t value) {
  for (uint32_t i = 0; i != 8; ++i) data[i] = static_cast<uint8_t>(value >> (i * 8));
}
AuthInfoScopeLifecycleFixture MakeAuthInfoScopeLifecycleFixture(int guest_pid) {
  using namespace Libs::LibKernel::AuthInfo;
  AuthInfoScopeLifecycleFixture fixture;
  std::array<uint8_t, 193> self {};
  std::array<uint8_t, 521> elf {};
  const auto seed = static_cast<uint8_t>(guest_pid);
  for (size_t i = 0; i != self.size(); ++i) self[i] = static_cast<uint8_t>(seed + i * 17 + 3);
  for (size_t i = 0; i != elf.size(); ++i) elf[i] = static_cast<uint8_t>(seed * 3 + i * 29 + 7);
  fixture.identity.authority_id = 0x4800000010000004ull;
  fixture.identity.self_size = self.size();
  fixture.identity.elf_size = elf.size();
  fixture.identity.self_sha256 = Sha256(self.data(), self.size());
  fixture.identity.elf_sha256 = Sha256(elf.data(), elf.size());
  for (size_t i = 0; i != fixture.record.size(); ++i) {
    fixture.record[i] = static_cast<uint8_t>(seed + i * 5 + 11);
  }
  AuthInfoScopeStore64(fixture.record.data(), fixture.identity.authority_id);
  AuthInfoScopeStore64(fixture.record.data() + 8, 1ull << 62);
  Check(BuildCaptureEnvelope(fixture.record, fixture.identity, &fixture.capture, nullptr),
        "build scoped AuthInfo lifecycle fixture");
  return fixture;
}
#endif
