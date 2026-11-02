#if defined(_WIN32)
struct LocalSocketPolicySavedIdentity {
  Libs::LibKernel::AuthInfo::ImageIdentity identity {};
  Libs::LibKernel::AuthInfo::Capture capture {};
  bool has_identity = false, has_capture = false;

  LocalSocketPolicySavedIdentity() {
    namespace Process = Libs::LibKernel::Process;
    has_identity = Process::GetVerifiedOriginalSelfIdentity(&identity);
    has_capture = has_identity && Process::GetVerifiedAuthInfoForImage(identity, &capture);
  }

  ~LocalSocketPolicySavedIdentity() {
    namespace Process = Libs::LibKernel::Process;
    Process::ClearVerifiedOriginalSelf();
    if (has_identity) Process::InstallVerifiedOriginalSelf(identity);
    if (has_capture) Check(Process::InstallVerifiedAuthInfo(capture), "restore prior socket fixture authorization");
  }
};
Libs::LibKernel::AuthInfo::ImageIdentity LocalSocketPolicyIdentity() {
  using namespace Libs::LibKernel;
  AuthInfo::ImageIdentity identity {};
  identity.authority_id = 0x3800000000000011ull;
  constexpr char self[] = "socket-policy-fixture-self";
  constexpr char elf[] = "socket-policy-fixture-elf";
  identity.self_size = sizeof(self);
  identity.elf_size = sizeof(elf);
  identity.self_sha256 = AuthInfo::Sha256(self, sizeof(self));
  identity.elf_sha256 = AuthInfo::Sha256(elf, sizeof(elf));
  return identity;
}
void LocalSocketPolicyCredential(int state) {
  using namespace Libs::LibKernel;
  Process::ClearVerifiedOriginalSelf();
  if (state < 0) return;
  const auto identity = LocalSocketPolicyIdentity();
  AuthInfo::Record record {};
  std::memcpy(record.data(), &identity.authority_id, sizeof(identity.authority_id));
  const uint64_t capabilities = state == 0 ? 0 : uint64_t {1} << 62;
  std::memcpy(record.data() + 8, &capabilities, sizeof(capabilities));
  AuthInfo::Capture capture {};
  Check(AuthInfo::BuildCaptureEnvelope(record, identity, &capture, nullptr),
        "build explicit synthetic socket authorization fixture without production capture input");
  Process::InstallVerifiedOriginalSelf(identity);
  Check(Process::InstallVerifiedAuthInfo(capture), "install only test-created socket authorization facts");
}
#endif
