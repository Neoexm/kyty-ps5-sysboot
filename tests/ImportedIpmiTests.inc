void CheckImportedIpmiErrors() {
#if defined(_WIN32)
  using namespace Libs::LibKernel;
  const std::array<const char*, 9> names {
      "KYTY_DIAGNOSTIC_ORIGINAL_SYSCORE_APP_IPMI",
      "KYTY_DIAGNOSTIC_IPMI_SHARED_SCOPE",
      "KYTY_DIAGNOSTIC_ORBIS_AUDIOD_IPMI_REGISTRY",
      "KYTY_DIAGNOSTIC_ORBIS_AUDIOD_IPMI_RECEIVE_WAIT",
      "KYTY_DIAGNOSTIC_ORBIS_AUDIOD_IPMI_TRACE_RESULT",
      "KYTY_DIAGNOSTIC_ORBIS_AUDIOD_IPMI_AUDIT",
      "KYTY_DIAGNOSTIC_ORBIS_AUDIOD_IPMI_RECEIVE_ABI2",
      "KYTY_DIAGNOSTIC_PSM_SHARED_DMEM_RESPONDER",
      "KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS"};
  std::array<std::string, names.size()> saved;
  for (size_t i = 0; i < names.size(); ++i) {
    const char* value = std::getenv(names[i]);
    saved[i] = value ? value : "";
    Check(_putenv_s(names[i], "") == 0, "disable imported IPMI diagnostic responders");
  }
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* symbol = symbols.FindByNid("Hk7iHmGxB18", Loader::SymbolType::Func);
  Check(symbol != nullptr, "resolve IPMI syscall export");
  using Call = int (KYTY_SYSV_ABI *)(uint32_t, int32_t, int32_t*, void*, size_t, uint64_t);
  const auto call = reinterpret_cast<Call>(symbol->vaddr);
  void* storage = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&storage, 0x4000, 3, 0, "imported-ipmi-test") == OK,
        "allocate imported IPMI guest buffers");
  auto* bytes = static_cast<uint8_t*>(storage);
  std::memset(bytes, 0, 0x4000);
  const auto* auth_symbol = symbols.FindByNid("igMefp4SAv0", Loader::SymbolType::Func);
  Check(auth_symbol != nullptr, "resolve process auth info export");
  using GetAuthInfo = int (KYTY_SYSV_ABI *)(int, void*);
  const auto get_auth_info = reinterpret_cast<GetAuthInfo>(auth_symbol->vaddr);
  AuthInfo::Digest self_digest {};
  AuthInfo::Digest elf_digest {};
  self_digest[0] = 1;
  elf_digest[0] = 2;
  constexpr uint64_t authority_id = 0x3800000000000011ull;
  Process::ClearVerifiedOriginalSelf();
  AuthInfo::ImageIdentity image_identity {};
  image_identity.authority_id = authority_id;
  image_identity.self_size = 1;
  image_identity.elf_size = 1;
  image_identity.self_sha256 = self_digest;
  image_identity.elf_sha256 = elf_digest;
  Process::InstallVerifiedOriginalSelf(image_identity);
  Process::PeerProcess peer;
  Check(Process::FindPeerByPid(Process::GetPid(), &peer) && peer.auth_id == authority_id &&
            !peer.has_auth_info,
        "establish SELF identity without captured auth info");
  auto* auth_output = bytes + 0x900;
  std::memset(auth_output, 0xa5, AuthInfo::kSize);
  *Libs::Posix::GetErrorAddr() = 0;
  Check(get_auth_info(0, auth_output) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOENT &&
            std::all_of(auth_output, auth_output + AuthInfo::kSize,
                        [](uint8_t value) { return value == 0xa5; }),
        "missing captured auth info fails without changing imported output");
  Check(_putenv_s(names.back(), "1") == 0, "enable native auth info syscall fixture");
  std::memset(auth_output, 0xa5, AuthInfo::kSize);
  const auto native_auth = Libs::NativeKernelBridge::DispatchSyscall(
      {0x24b, {0, reinterpret_cast<uint64_t>(auth_output)}});
  Check(native_auth.value == -1 && native_auth.posix_errno == Libs::Posix::POSIX_ENOENT &&
            std::all_of(auth_output, auth_output + AuthInfo::kSize,
                        [](uint8_t value) { return value == 0xa5; }),
        "missing captured auth info fails without changing native output");
  std::array<uint8_t, AuthInfo::kObservationSize> observed {};
  auto store32 = [](uint8_t* out, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) out[i] = static_cast<uint8_t>(value >> (8 * i));
  };
  auto store64 = [](uint8_t* out, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) out[i] = static_cast<uint8_t>(value >> (8 * i));
  };
  std::memcpy(observed.data(), "KytyAO01", 8);
  store32(observed.data() + 8, 1);
  store32(observed.data() + 12, observed.size());
  store64(observed.data() + 16, authority_id);
  store64(observed.data() + 24, 1ull << 62);
  store64(observed.data() + 32, AuthInfo::kFilteredCapabilityMask);
  std::copy(self_digest.begin(), self_digest.end(), observed.begin() + 40);
  std::copy(elf_digest.begin(), elf_digest.end(), observed.begin() + 72);
  observed[104] = observed[168] = 1;
  store32(observed.data() + 136, 0x13600007);
  store32(observed.data() + 140, 52);
  store64(observed.data() + 144, 100);
  store64(observed.data() + 160, 200);
  AuthInfo::Observation observation;
  Check(AuthInfo::ParseObservation(observed.data(), observed.size(),
        AuthInfo::Sha256(observed.data(), observed.size()), image_identity, &observation, nullptr) &&
        Process::InstallVerifiedAuthorizationObservation(observation),
        "install synthetic image-bound partial authorization fixture");
  const auto facts = Process::GetCurrentAuthorizationFacts();
  Check(facts.has_authority && facts.authority_id == authority_id &&
        facts.capability0 == (1ull << 62) && facts.known_capability0 == AuthInfo::kFilteredCapabilityMask &&
        Process::FindPeerByPid(Process::GetPid(), &peer) && !peer.has_auth_info,
        "observed fields do not manufacture a complete process credential");
  AuthInfo::Record expected_auth {};
  store64(expected_auth.data() + 8, 1ull << 62);
  Check(get_auth_info(0, auth_output) == 0 &&
        std::memcmp(auth_output, expected_auth.data(), expected_auth.size()) == 0,
        "imported authinfo reproduces the exact native filtered output from disclosed fields");
  std::memset(auth_output, 0xa5, AuthInfo::kSize);
  const auto observed_native = Libs::NativeKernelBridge::DispatchSyscall(
      {0x24b, {0, reinterpret_cast<uint64_t>(auth_output)}});
  Check(observed_native.value == 0 && observed_native.posix_errno == 0 &&
        std::memcmp(auth_output, expected_auth.data(), expected_auth.size()) == 0,
        "native authinfo agrees with the imported filtered output");
  const auto invalid_observed_output = Libs::NativeKernelBridge::DispatchSyscall({0x24b, {0, 1}});
  Check(invalid_observed_output.value == -1 &&
        invalid_observed_output.posix_errno == Libs::Posix::POSIX_EFAULT,
        "partial authinfo still validates the guest output mapping");
  AuthInfo::Record conflicting_record {};
  store64(conflicting_record.data(), authority_id);
  AuthInfo::Capture conflicting_capture;
  Check(AuthInfo::BuildCaptureEnvelope(conflicting_record, image_identity, &conflicting_capture, nullptr) &&
        !Process::InstallVerifiedAuthInfo(conflicting_capture),
        "complete capture cannot silently replace contradictory observed fields");
  Process::ClearVerifiedAuthInfo();
  Check((Process::GetCurrentAuthorizationFacts().capability0 & (1ull << 62)) != 0,
        "clearing an absent full capture preserves independent observed knowledge");
  Process::ClearVerifiedOriginalSelf();
  Check(!Process::GetCurrentAuthorizationFacts().has_authority &&
        !Process::GetCurrentFilteredAuthInfo(&expected_auth),
        "clearing the image revokes its partial authorization");
  auto* result = reinterpret_cast<int32_t*>(bytes);
  auto* nested = reinterpret_cast<int32_t*>(bytes + 8);
  auto* args = reinterpret_cast<uint64_t*>(bytes + 0x40);
  args[0] = args[2] = reinterpret_cast<uint64_t>(nested);
  args[1] = reinterpret_cast<uint64_t>(bytes + 0x100);
  for (const uint32_t command: {0u, 2u, 0x10u, 0x201u, 0x252u, 0x310u, 0x400u,
                                0x490u, 0x320u, 0x241u, 0x7fffffffu}) {
    *result = 0x5a123456;
    *nested = 0x2b654321;
    *Libs::Posix::GetErrorAddr() = 0;
    Check(call(command, 1, result, args, 48, 0xdeadbadecafebeafull) == -1 &&
              *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOSYS &&
              *result == 0x5a123456 && *nested == 0x2b654321,
          "unsupported IPMI does not create IDs, ACK, dequeue or alter outputs");
  }
  Check(call(0x320, 1, result, reinterpret_cast<void*>(1), 48, 0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOSYS,
        "unsupported invoke does not dereference its payload");
  Check(call(0, 0, nullptr, args, 24, 0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT,
        "imported IPMI validates syscall result storage");
  Check(_putenv_s(names[0], "1") == 0 &&
            _putenv_s(names[1], ("hk7i_" + std::to_string(GetCurrentProcessId())).c_str()) == 0,
        "enable IPMI adapter for strict error checks");
  auto* creation = reinterpret_cast<uint64_t*>(bytes + 0x80);
  creation[0] = reinterpret_cast<uint64_t>(bytes + 0x380);
  creation[1] = reinterpret_cast<uint64_t>(bytes + 0x100);
  creation[2] = reinterpret_cast<uint64_t>(bytes + 0x200);
  std::strcpy(reinterpret_cast<char*>(bytes + 0x100), "SceAudioSystemIpcServer");
  *reinterpret_cast<uint64_t*>(bytes + 0x200) = 56;
  *result = 0x5a123456;
  Check(call(0, 0, result, creation, 24, 0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOSYS && *result == 0x5a123456,
        "missing auth info returns transport failure without altering the result or admitting a server");
  creation[2] = 1;
  Check(call(0, 0, result, creation, 24, 0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOSYS && *result == 0x5a123456,
        "missing auth info is checked before server configuration memory");
  auto* trace = bytes + 0x800;
  *reinterpret_cast<int32_t*>(trace) = -1;
  std::memcpy(trace + 8, "SceAudioSystemIpcServer", 23);
  *reinterpret_cast<int32_t*>(trace + 0x24) = KERNEL_ERROR_ENOSYS;
  std::array<uint8_t, 64> trace_before {};
  std::memcpy(trace_before.data(), trace, trace_before.size());
  Check(call(0x10, 0x1f02, result, trace, 64, 0xdeadbadecafebeafull) == OK && *result == OK &&
            std::memcmp(trace, trace_before.data(), 64) == 0,
        "failed-create trace reports its error without changing record or server state");
  uint32_t trace_server = 0, trace_owner = 0, trace_host = 0;
  *result = 0x5a123456;
  Check(!IpmiScope::Lookup("SceAudioSystemIpcServer", &trace_server, &trace_owner, &trace_host) &&
            call(0, 0, result, creation, 24, 0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOSYS && *result == 0x5a123456,
        "diagnostic report neither registers nor authorizes the failed server");
  Check(call(0x10, 0x1f06, result, trace, 64, 0) == OK && *result == OK,
        "captured unknown trace subtype completes its diagnostic processing");
  for (const size_t size: {size_t {0}, size_t {48}, size_t {63}}) {
    *result = 0x5a123456;
    Check(call(0x10, 0x1f02, result, trace, size, 0) == -1 &&
              *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL && *result == 0x5a123456,
          "malformed imported trace size preserves logical output");
  }
  Check(call(0x10, 0x1f02, result, nullptr, 64, 0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL && *result == 0x5a123456,
        "null imported trace record is a transport shape error");
  Check(call(0x10, 0x1f02, result, reinterpret_cast<void*>(1), 64, 0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT && *result == 0x5a123456,
        "unreadable imported trace record preserves logical output");
  Check(call(0x10, 0x1f02, result, nullptr, 65, 0) == OK &&
            *result == static_cast<int32_t>(0x800e0001u),
        "outer imported trace limit returns captured logical status before record access");
  int32_t host_trace_result = 0x5a123456;
  Check(call(0x10, 0x1f02, &host_trace_result, trace, 64, 0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT && host_trace_result == 0x5a123456,
        "imported diagnostic trace cannot overwrite output outside guest mappings");
  creation[2] = reinterpret_cast<uint64_t>(bytes + 0x200);
  *reinterpret_cast<uint64_t*>(bytes + 0x200) = 336;
  Check(call(2, 0, result, creation, 24, 0) == OK && *result > 0,
        "client allocation owns a disconnected KID before service registration");
  const int32_t client = *result;
  args[0] = reinterpret_cast<uint64_t>(bytes + 0x500);
  Check(call(0x46a, client, result, args, 8, 0) == OK && *result == OK &&
            std::strcmp(reinterpret_cast<char*>(bytes + 0x500), "SceAudioSystemIpcServer") == 0,
        "disconnected imported client exposes its service name");
  args[0] = args[1] = 0;
  args[2] = reinterpret_cast<uint64_t>(nested);
  args[3] = reinterpret_cast<uint64_t>(bytes + 0x3c0);
  Check(call(0x400, client, result, args, 32, 0) == OK &&
            *result == KERNEL_ERROR_ESRCH && *nested == 0x2b654321,
        "explicit zero-timeout absent-service connect preserves completion");
  Check(call(3, client, result, nullptr, 0, 0) == OK && *result == OK,
        "disconnected imported client closes without a server or shared endpoint");
  Check(call(0x400, 0x2000ffff, result, args, 32, 0) == OK &&
            *result == KERNEL_ERROR_EBADF && *nested == 0x2b654321,
        "managed handle errors preserve adapter precedence and completion output");
  Check(call(0x46a, static_cast<int32_t>(0x8002004e), result, args, 8, 0) == OK &&
            *result == KERNEL_ERROR_EBADF && *nested == 0x2b654321,
        "failed server name query is handled without changing its name output");
  for (size_t i = 0; i < names.size(); ++i) {
    Check(_putenv_s(names[i], saved[i].c_str()) == 0, "restore imported IPMI settings");
  }
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(storage), 0x4000) == OK,
        "release imported IPMI guest buffers");
#endif
}
