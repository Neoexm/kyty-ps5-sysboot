#if defined(_WIN32)

static bool EnvelopeConsoleHmac(const std::array<uint8_t, 32>& token, const void* header,
                                size_t header_size, std::span<const uint8_t> body,
                                std::array<uint8_t, 32>* digest) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  DWORD object_size = 0;
  DWORD copied = 0;
  std::vector<uint8_t> object;
  bool ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                                        BCRYPT_ALG_HANDLE_HMAC_FLAG) >= 0;
  if (ok) {
    ok = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                           reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
                           &copied, 0) >= 0 && copied == sizeof(object_size);
  }
  if (ok) {
    object.resize(object_size);
    ok = BCryptCreateHash(algorithm, &hash, object.data(), static_cast<ULONG>(object.size()),
                          const_cast<PUCHAR>(token.data()), static_cast<ULONG>(token.size()), 0) >= 0;
  }
  if (ok) {
    ok = BCryptHashData(hash, static_cast<PUCHAR>(const_cast<void*>(header)),
                        static_cast<ULONG>(header_size), 0) >= 0;
  }
  if (ok && !body.empty()) {
    ok = BCryptHashData(hash, const_cast<PUCHAR>(body.data()),
                        static_cast<ULONG>(body.size()), 0) >= 0;
  }
  if (ok) ok = BCryptFinishHash(hash, digest->data(), static_cast<ULONG>(digest->size()), 0) >= 0;
  if (hash != nullptr) BCryptDestroyHash(hash);
  if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
  if (!object.empty()) SecureZeroMemory(object.data(), object.size());
  return ok;
}

static bool EnvelopeConsoleEqual(const std::array<uint8_t, 32>& left,
                                 const std::array<uint8_t, 32>& right) {
  uint8_t different = 0;
  for (size_t i = 0; i < left.size(); i++) different |= left[i] ^ right[i];
  return different == 0;
}

static bool EnvelopeConsoleReceive(SOCKET socket, void* bytes, size_t size) {
  auto* cursor = static_cast<uint8_t*>(bytes);
  while (size != 0) {
    const int count = recv(socket, reinterpret_cast<char*>(cursor), static_cast<int>(size), 0);
    if (count <= 0) return false;
    cursor += count;
    size -= count;
  }
  return true;
}

static bool EnvelopeConsoleSend(SOCKET socket, const void* bytes, size_t size) {
  const auto* cursor = static_cast<const uint8_t*>(bytes);
  while (size != 0) {
    const int count = send(socket, reinterpret_cast<const char*>(cursor), static_cast<int>(size), 0);
    if (count <= 0) return false;
    cursor += count;
    size -= count;
  }
  return true;
}

class EnvelopeConsoleTestServer {
public:
  enum class Mode { Success, DigestMismatch, NativeFailure, Malformed, BadHmac, Trailing, Disconnect, Timeout, SlowDrip, BadTransport, NegativeStatus, SentinelResult };

  EnvelopeConsoleTestServer(Mode mode, const std::array<uint8_t, 32>& token,
                            std::span<const uint8_t, 0x300> expected_key,
                            std::span<const uint8_t, 0x20> expected_salt,
                            std::span<const uint8_t> expected_envelope,
                            std::span<const uint8_t> response): mode(mode), token(token),
      expected_envelope(expected_envelope.begin(), expected_envelope.end()),
      response(response.begin(), response.end()) {
    std::copy(expected_key.begin(), expected_key.end(), this->expected_key.begin());
    std::copy(expected_salt.begin(), expected_salt.end(), this->expected_salt.begin());
    static const bool sockets_ready = [] {
      WSADATA data {};
      return WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }();
    Check(sockets_ready, "initialize envelope loopback test sockets");
    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Check(listener != INVALID_SOCKET, "create envelope loopback test listener");
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    Check(bind(listener, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0 &&
          listen(listener, 1) == 0, "bind envelope loopback test listener");
    int length = sizeof(address);
    Check(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) == 0,
          "read envelope loopback test port");
    port = ntohs(address.sin_port);
    worker = std::thread([this] { Run(); });
  }

  ~EnvelopeConsoleTestServer() {
    Join();
    if (listener != INVALID_SOCKET) closesocket(listener);
    SecureZeroMemory(token.data(), token.size());
  }

  EnvelopeConsoleTestServer(const EnvelopeConsoleTestServer&) = delete;
  EnvelopeConsoleTestServer& operator=(const EnvelopeConsoleTestServer&) = delete;

  uint16_t Port() const { return port; }

  void Join() {
    if (worker.joinable()) worker.join();
  }

  bool RequestValid() const { return request_valid; }
  uint64_t RequestId() const { return request_id; }

private:
  void Run() {
    const SOCKET client = accept(listener, nullptr, nullptr);
    closesocket(listener);
    listener = INVALID_SOCKET;
    if (client == INVALID_SOCKET) return;
    const DWORD timeout = 5000;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    using namespace Libs::LibKernel::EnvelopeConsoleProtocol;
    RequestHeader request {};
    if (!EnvelopeConsoleReceive(client, &request, sizeof(request)) ||
        request.total_size < header_size || request.total_size > header_size + 0x320 + max_input_size) {
      closesocket(client);
      return;
    }
    std::vector<uint8_t> body(request.total_size - header_size);
    if (!EnvelopeConsoleReceive(client, body.data(), body.size())) {
      closesocket(client);
      return;
    }
    const auto received_hmac = request.hmac;
    request.hmac.fill(0);
    std::array<uint8_t, 32> expected_hmac {};
    const bool authenticated = EnvelopeConsoleHmac(token, &request, sizeof(request), body, &expected_hmac) &&
                               EnvelopeConsoleEqual(received_hmac, expected_hmac);
    SecureZeroMemory(expected_hmac.data(), expected_hmac.size());
    request_id = request.request_id;
    request_valid = authenticated && request.magic == request_magic && request.version == version &&
        request.header_size == header_size && request.opcode == opcode && request.request_id != 0 &&
        request.cid == 0x15 && request.mkv == 3 && request.key_size == 0x300 &&
        request.salt_size == 0x20 && request.input_size == expected_envelope.size() &&
        request.output_capacity == response.size() && request.reserved0 == 0 && request.reserved1 == 0 &&
        request.total_size == header_size + body.size() && body.size() == 0x320 + expected_envelope.size() &&
        std::equal(expected_key.begin(), expected_key.end(), body.begin()) &&
        std::equal(expected_salt.begin(), expected_salt.end(), body.begin() + 0x300) &&
        std::equal(expected_envelope.begin(), expected_envelope.end(), body.begin() + 0x320);
    SecureZeroMemory(body.data(), body.size());
    if (!request_valid || mode == Mode::Disconnect) {
      closesocket(client);
      return;
    }
    if (mode == Mode::Timeout) {
      std::this_thread::sleep_for(std::chrono::milliseconds(250));
      closesocket(client);
      return;
    }

    std::vector<uint8_t> output;
    if (mode != Mode::NativeFailure && mode != Mode::Malformed) output = response;
    if (mode == Mode::DigestMismatch && !output.empty()) output[0] ^= 0x80;
    ResponseHeader reply {};
    reply.magic = mode == Mode::Malformed ? request_magic : response_magic;
    reply.version = version;
    reply.header_size = header_size;
    reply.total_size = header_size + static_cast<uint32_t>(output.size());
    reply.opcode = opcode;
    reply.request_id = request.request_id;
    reply.transport_status = mode == Mode::BadTransport ? maximum_transport_status + 1 : 0;
    reply.native_open_errno = mode == Mode::NegativeStatus ? -1 : 0;
    reply.native_ioctl_errno = mode == Mode::NativeFailure ? 5 : 0;
    reply.operation_result = mode == Mode::SentinelResult ? UINT32_MAX : 0;
    reply.output_size = static_cast<uint32_t>(output.size());
    reply.dispatch_state = dispatch_complete;
    EnvelopeConsoleHmac(token, &reply, sizeof(reply), output, &reply.hmac);
    if (mode == Mode::BadHmac) reply.hmac[0] ^= 1;
    if (mode == Mode::SlowDrip) {
      const auto* bytes = reinterpret_cast<const uint8_t*>(&reply);
      for (size_t i = 0; i < sizeof(reply); i++) {
        if (!EnvelopeConsoleSend(client, bytes + i, 1)) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
      }
      shutdown(client, SD_SEND);
      closesocket(client);
      if (!output.empty()) SecureZeroMemory(output.data(), output.size());
      return;
    }
    EnvelopeConsoleSend(client, &reply, sizeof(reply));
    if (!output.empty()) EnvelopeConsoleSend(client, output.data(), output.size());
    if (mode == Mode::Trailing) {
      const uint8_t trailing = 0xa5;
      EnvelopeConsoleSend(client, &trailing, sizeof(trailing));
    }
    shutdown(client, SD_SEND);
    closesocket(client);
    if (!output.empty()) SecureZeroMemory(output.data(), output.size());
  }

  Mode mode;
  std::array<uint8_t, 32> token {};
  std::array<uint8_t, 0x300> expected_key {};
  std::array<uint8_t, 0x20> expected_salt {};
  std::vector<uint8_t> expected_envelope;
  std::vector<uint8_t> response;
  SOCKET listener = INVALID_SOCKET;
  uint16_t port = 0;
  std::thread worker;
  bool request_valid = false;
  uint64_t request_id = 0;
};

class EnvelopeRecordingBackend final: public Libs::LibKernel::EnvelopeSecureProcessor::EnvelopeBackend {
public:
  using EnvelopeBackend = Libs::LibKernel::EnvelopeSecureProcessor::EnvelopeBackend;
  using EnvelopeRequest = Libs::LibKernel::EnvelopeSecureProcessor::EnvelopeRequest;
  using Result = Libs::LibKernel::EnvelopeSecureProcessor::Result;

  explicit EnvelopeRecordingBackend(std::shared_ptr<EnvelopeBackend> backend): backend(std::move(backend)) {}

  Result Process(const EnvelopeRequest& request, std::span<uint8_t> output) noexcept override {
    calls++;
    result = backend->Process(request, output);
    return result;
  }

  std::shared_ptr<EnvelopeBackend> backend;
  Result result;
  size_t calls = 0;
};

class EnvelopeCountingBackend final: public Libs::LibKernel::EnvelopeSecureProcessor::EnvelopeBackend {
public:
  using EnvelopeRequest = Libs::LibKernel::EnvelopeSecureProcessor::EnvelopeRequest;
  using Result = Libs::LibKernel::EnvelopeSecureProcessor::Result;

  Result Process(const EnvelopeRequest&, std::span<uint8_t> output) noexcept override {
    calls++;
    Libs::LibKernel::EnvelopeSecureProcessor::Wipe(output);
    return {};
  }

  size_t calls = 0;
};

static bool EnvelopeAes(const std::array<uint8_t, 16>& secret, bool decrypt, bool cbc,
                        std::span<const uint8_t> input, std::span<uint8_t> output,
                        std::span<const uint8_t> iv = {}) {
  if (input.empty() || input.size() != output.size() || input.size() > ULONG_MAX ||
      (cbc && iv.size() != 16) || (!cbc && !iv.empty())) return false;
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_KEY_HANDLE key = nullptr;
  DWORD object_size = 0;
  DWORD property_size = 0;
  const wchar_t* mode = cbc ? BCRYPT_CHAIN_MODE_CBC : BCRYPT_CHAIN_MODE_ECB;
  const ULONG mode_size = cbc ? sizeof(BCRYPT_CHAIN_MODE_CBC) : sizeof(BCRYPT_CHAIN_MODE_ECB);
  bool ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0) >= 0 &&
            BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
                              reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(mode)), mode_size, 0) >= 0 &&
            BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size),
                              sizeof(object_size), &property_size, 0) >= 0 &&
            property_size == sizeof(object_size) && object_size != 0;
  std::vector<uint8_t> object(ok ? object_size : 0);
  if (ok) ok = BCryptGenerateSymmetricKey(algorithm, &key, object.data(), object_size,
                                         const_cast<PUCHAR>(secret.data()), secret.size(), 0) >= 0;
  std::array<uint8_t, 16> local_iv {};
  if (cbc) std::memcpy(local_iv.data(), iv.data(), local_iv.size());
  ULONG written = 0;
  if (ok) {
    const auto status = decrypt
        ? BCryptDecrypt(key, const_cast<PUCHAR>(input.data()), static_cast<ULONG>(input.size()), nullptr,
                        cbc ? local_iv.data() : nullptr, cbc ? local_iv.size() : 0,
                        output.data(), static_cast<ULONG>(output.size()), &written, 0)
        : BCryptEncrypt(key, const_cast<PUCHAR>(input.data()), static_cast<ULONG>(input.size()), nullptr,
                        cbc ? local_iv.data() : nullptr, cbc ? local_iv.size() : 0,
                        output.data(), static_cast<ULONG>(output.size()), &written, 0);
    ok = status >= 0 && written == output.size();
  }
  if (key != nullptr) BCryptDestroyKey(key);
  if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
  if (!object.empty()) SecureZeroMemory(object.data(), object.size());
  SecureZeroMemory(local_iv.data(), local_iv.size());
  return ok;
}

static std::vector<uint8_t> EncryptEnvelopeFixture(const std::array<uint8_t, 16>& key,
                                                   std::span<const uint8_t, 16> iv,
                                                   std::span<const uint8_t> plaintext) {
  using namespace Libs::LibKernel::EnvelopeSecureProcessor;
  std::vector<uint8_t> ciphertext(plaintext.size());
  std::array<uint8_t, 16> chain {};
  std::memcpy(chain.data(), iv.data(), chain.size());
  const size_t aligned = plaintext.size() & ~size_t {15};
  for (size_t offset = 0; offset < aligned;) {
    const size_t count = std::min(crypt_chunk_size, aligned - offset);
    Check(EnvelopeAes(key, false, true, plaintext.subspan(offset, count),
                      std::span<uint8_t>(ciphertext).subspan(offset, count), chain),
          "encrypt an aligned envelope fixture chunk");
    std::memcpy(chain.data(), ciphertext.data() + offset + count - chain.size(), chain.size());
    offset += count;
  }
  const size_t tail = plaintext.size() - aligned;
  if (tail != 0) {
    std::array<uint8_t, 16> stream {};
    Check(EnvelopeAes(key, false, false, chain, stream), "encrypt the envelope residual IV");
    for (size_t i = 0; i < tail; i++) ciphertext[aligned + i] = plaintext[aligned + i] ^ stream[i];
    SecureZeroMemory(stream.data(), stream.size());
  }
  SecureZeroMemory(chain.data(), chain.size());
  return ciphertext;
}

class EnvelopeKatBackend final: public Libs::LibKernel::EnvelopeSecureProcessor::Backend {
public:
  using CommandResult = Libs::LibKernel::EnvelopeSecureProcessor::CommandResult;
  using Context = Libs::LibKernel::EnvelopeSecureProcessor::Context;
  using Status = Libs::LibKernel::EnvelopeSecureProcessor::Status;

  enum class Failure { None, NotConfigured, Derive, Crypt, Residual };

  EnvelopeKatBackend(Context expected, std::array<uint8_t, 16> key): expected(expected), key(key) {}
  ~EnvelopeKatBackend() override { SecureZeroMemory(key.data(), key.size()); }

  CommandResult DeriveKey(const Context& context, uint16_t* slot) noexcept override {
    derive_calls++;
    if (failure == Failure::NotConfigured) {
      return {Status::NotConfigured, Libs::LibKernel::EnvelopeSecureProcessor::unavailable_result};
    }
    if (failure == Failure::Derive) return {Status::OperationError, failure_result};
    if (context.cid != expected.cid || context.mkv != expected.mkv || context.salt != expected.salt) {
      return {Status::Unavailable, Libs::LibKernel::EnvelopeSecureProcessor::unavailable_result};
    }
    *slot = slot_value;
    return {Status::Success, 0};
  }

  CommandResult DecryptBlocks(uint16_t slot, std::span<uint8_t, 16> state,
                              std::span<const uint8_t> input, std::span<uint8_t> output) noexcept override {
    crypt_calls++;
    if (failure == Failure::Crypt) return {Status::OperationError, failure_result};
    if (slot != slot_value || input.empty() || input.size() != output.size() ||
        input.size() % 16 != 0 || input.size() > Libs::LibKernel::EnvelopeSecureProcessor::crypt_chunk_size) {
      return {Status::ProtocolError, Libs::LibKernel::EnvelopeSecureProcessor::unavailable_result};
    }
    if (!EnvelopeAes(key, true, true, input, output, state)) {
      return {Status::OperationError, failure_result};
    }
    std::memcpy(state.data(), input.data() + input.size() - state.size(), state.size());
    return {Status::Success, 0};
  }

  CommandResult EncryptBlock(uint16_t slot, std::span<uint8_t, 16> state) noexcept override {
    residual_calls++;
    if (failure == Failure::Residual) return {Status::OperationError, failure_result};
    if (slot != slot_value) return {Status::ProtocolError, Libs::LibKernel::EnvelopeSecureProcessor::unavailable_result};
    std::array<uint8_t, 16> encrypted {};
    const bool ok = EnvelopeAes(key, false, false, state, encrypted);
    if (ok) std::memcpy(state.data(), encrypted.data(), encrypted.size());
    SecureZeroMemory(encrypted.data(), encrypted.size());
    return ok ? CommandResult {Status::Success, 0}
              : CommandResult {Status::OperationError, failure_result};
  }

  void ReleaseKey(uint16_t slot) noexcept override {
    if (slot == slot_value) release_calls++;
  }

  Context expected;
  std::array<uint8_t, 16> key;
  Failure failure = Failure::None;
  size_t derive_calls = 0;
  size_t crypt_calls = 0;
  size_t residual_calls = 0;
  size_t release_calls = 0;
  static constexpr uint32_t failure_result = 0x81234567;
  static constexpr uint16_t slot_value = 7;
};

class EnvelopeOpaqueStateBackend final: public Libs::LibKernel::EnvelopeSecureProcessor::Backend {
public:
  using CommandResult = Libs::LibKernel::EnvelopeSecureProcessor::CommandResult;
  using Context = Libs::LibKernel::EnvelopeSecureProcessor::Context;
  using Status = Libs::LibKernel::EnvelopeSecureProcessor::Status;

  CommandResult DeriveKey(const Context&, uint16_t* slot) noexcept override {
    *slot = slot_value;
    return {Status::Success, 0};
  }

  CommandResult DecryptBlocks(uint16_t slot, std::span<uint8_t, 16> state,
                              std::span<const uint8_t> input, std::span<uint8_t> output) noexcept override {
    if (slot != slot_value || input.size() != 16 || output.size() != 16) {
      return {Status::ProtocolError, Libs::LibKernel::EnvelopeSecureProcessor::unavailable_result};
    }
    std::memcpy(output.data(), input.data(), input.size());
    std::copy(opaque_state.begin(), opaque_state.end(), state.begin());
    return {Status::Success, 0};
  }

  CommandResult EncryptBlock(uint16_t slot, std::span<uint8_t, 16> state) noexcept override {
    if (slot != slot_value || !std::equal(state.begin(), state.end(), opaque_state.begin())) {
      return {Status::ProtocolError, Libs::LibKernel::EnvelopeSecureProcessor::unavailable_result};
    }
    std::copy(residual_stream.begin(), residual_stream.end(), state.begin());
    saw_opaque_state = true;
    return {Status::Success, 0};
  }

  void ReleaseKey(uint16_t slot) noexcept override {
    if (slot == slot_value) release_calls++;
  }

  bool saw_opaque_state = false;
  size_t release_calls = 0;
  static constexpr uint16_t slot_value = 11;
  static constexpr std::array<uint8_t, 16> opaque_state {
      0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
      0x19, 0x0a, 0xfb, 0xec, 0xdd, 0xce, 0xbf, 0xa0};
  static constexpr std::array<uint8_t, 16> residual_stream {
      0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88,
      0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x00};
};

void CheckEnvelope(const std::filesystem::path &root) {
  using namespace Libs::LibKernel;
  using namespace Libs::LibKernel::EnvelopeSecureProcessor;
  static_assert(derive_command == 0x401 && crypt_command == 0x281000 && residual_command == 0x80800);
  SetEnvelopeBackendForTesting(nullptr);
  LocalSocketPolicySavedIdentity saved_identity;
  LocalSocketPolicyCredential(-1);
  Check(FileSystem::KernelOpen("/dev/envelope", 2, 0) == KERNEL_ERROR_EPERM, "envelope refuses unknown capabilities");
  LocalSocketPolicyCredential(0);
  Check(FileSystem::KernelOpen("/dev/envelope", 2, 0) == KERNEL_ERROR_EPERM, "envelope d_open requires capability bit 62");
  LocalSocketPolicyCredential(1);
  const int fd = FileSystem::KernelOpen("/dev/envelope", 2, 0);
  Check(fd >= 3, "envelope opens for a bit-62 credential");
  const int second = FileSystem::KernelOpen("/dev/envelope", 2, 0);
  Check(second >= 3 && FileSystem::KernelClose(second) == OK, "envelope has no exclusive opener");

  void* memory = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&memory, 0x4000, 3, 0, "envelope-fixture") == OK, "map envelope request memory");
  auto* base = static_cast<uint8_t*>(memory);
  auto* stat = reinterpret_cast<FileSystem::FileStat*>(base + 0x3800);
  Check(FileSystem::KernelStat("/dev/envelope", stat) == OK && stat->st_mode == 0020600u &&
        FileSystem::KernelFstat(fd, stat) == OK && stat->st_mode == 0020600u,
        "envelope is a root-only character device");

  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_KEY_HANDLE signer = nullptr;
  Check(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0) >= 0 &&
        BCryptGenerateKeyPair(algorithm, &signer, 3072, 0) >= 0 && BCryptFinalizeKeyPair(signer, 0) >= 0,
        "generate an RSA-3072 envelope signer");
  std::vector<uint8_t> blob(sizeof(BCRYPT_RSAKEY_BLOB) + 0x400);
  ULONG exported = 0;
  Check(BCryptExportKey(signer, nullptr, BCRYPT_RSAPUBLIC_BLOB, blob.data(), static_cast<ULONG>(blob.size()), &exported, 0) >= 0,
        "export the signer public key");
  BCRYPT_RSAKEY_BLOB public_key {};
  std::memcpy(&public_key, blob.data(), sizeof(public_key));
  Check(public_key.cbModulus == 0x180 && public_key.cbPublicExp <= 0x180, "signer modulus is 0x180 bytes");
  std::array<uint8_t, 0x300> key {};
  std::memcpy(key.data(), blob.data() + sizeof(public_key) + public_key.cbPublicExp, 0x180);
  std::memcpy(key.data() + 0x300 - public_key.cbPublicExp, blob.data() + sizeof(public_key), public_key.cbPublicExp);
  std::array<uint8_t, 0x20> salt {};
  for (size_t i = 0; i < salt.size(); i++) salt[i] = static_cast<uint8_t>(0x40 + i);
  std::array<uint8_t, 16> iv {};
  std::array<uint8_t, 16> kat_key {};
  for (size_t i = 0; i < iv.size(); i++) {
    iv[i] = static_cast<uint8_t>(0x20 + i);
    kat_key[i] = static_cast<uint8_t>(0x90 + i);
  }

  const std::string text = "{\"userfeedback\":{\"timeX\":123,\"timeY\":456},\"fixture\":\"public-vector\"}  ";
  const std::vector<uint8_t> plaintext(text.begin(), text.end());
  Check(plaintext.size() == 70, "the nonprotected fixture matches the 70-byte payload length");
  const auto ciphertext = EncryptEnvelopeFixture(kat_key, iv, plaintext);
  auto seal = [&](uint32_t cid, const AuthInfo::Digest& signed_hash) {
    std::vector<uint8_t> in(0x1d0 + plaintext.size());
    const uint32_t magic = 0x5173cbcc, version = 1;
    const uint64_t payload = plaintext.size();
    std::memcpy(in.data(), &magic, 4);
    std::memcpy(in.data() + 4, &version, 4);
    std::memcpy(in.data() + 8, &cid, 4);
    std::memcpy(in.data() + 0x10, &payload, 8);
    std::memcpy(in.data() + 0x20, iv.data(), iv.size());
    std::memcpy(in.data() + 0x30, signed_hash.data(), 32);
    std::memcpy(in.data() + 0x1d0, ciphertext.data(), ciphertext.size());
    auto hash = AuthInfo::Sha256(in.data(), in.size());
    BCRYPT_PSS_PADDING_INFO pss {BCRYPT_SHA256_ALGORITHM, 32};
    ULONG written = 0;
    Check(BCryptSignHash(signer, &pss, hash.data(), 32, in.data() + 0x50, 0x180, &written, BCRYPT_PAD_PSS) >= 0 && written == 0x180,
          "sign the envelope fixture");
    return in;
  };
  const auto plaintext_sha256 = AuthInfo::Sha256(plaintext.data(), plaintext.size());
  const auto sealed = seal(0x15, plaintext_sha256);
  const auto unrelated = seal(0x15, AuthInfo::Sha256(text.data(), 4));

  auto* in_area = base + 0x400;
  auto* out_area = base + 0x2000;
  auto request = [&](const std::vector<uint8_t>& in, uint32_t cid, uint32_t mkv, uint64_t size, uint64_t out) {
    std::memset(base, 0, 0x400);
    std::memcpy(base, &cid, 4);
    std::memcpy(base + 4, key.data(), key.size());
    std::memcpy(base + 0x304, &mkv, 4);
    std::memcpy(base + 0x308, salt.data(), salt.size());
    const auto in_ptr = reinterpret_cast<uint64_t>(in_area);
    std::memcpy(base + 0x328, &size, 8);
    std::memcpy(base + 0x330, &in_ptr, 8);
    std::memcpy(base + 0x338, &out, 8);
    const uint32_t untouched = 0xa5a5a5a5;
    std::memcpy(base + 0x340, &untouched, 4);
    std::memcpy(in_area, in.data(), in.size());
    std::memset(out_area, 0xcd, 0x1000);
    Check(FileSystem::KernelIoctl(fd, 0xc3483101, base) == OK, "envelope ioctl reports through +0x340 only");
    uint32_t result = 0;
    std::memcpy(&result, base + 0x340, 4);
    return result;
  };
  const auto out = reinterpret_cast<uint64_t>(out_area);
  auto out_untouched = [&] { return std::all_of(out_area, out_area + 0x1000, [](uint8_t byte) { return byte == 0xcd; }); };

  Check(FileSystem::KernelIoctl(fd, 0xc3483102, base) == KERNEL_ERROR_ENOTTY, "other envelope commands are ENOTTY");
  Check(FileSystem::KernelIoctl(fd, 0xc3483101, reinterpret_cast<void*>(uint64_t {0x10})) == KERNEL_ERROR_EFAULT,
        "the 0x348-byte argument copyin can fault");
  Check(request(sealed, 0x15, 3, sealed.size(), 0) == 0, "verify-only accepts a valid PSS signature");
  Check(request(sealed, 0x15, 3, 0x1d0, out) == 0x800f0f16 && request(sealed, 0x15, 3, 0x40001, out) == 0x800f0f16,
        "in_size outside [0x1d1, 0x40000] is rejected before copyin");
  auto bad = sealed;
  bad[0] ^= 1;
  Check(request(bad, 0x15, 3, bad.size(), out) == 0x800f0f23, "bad magic");
  Check(request(sealed, 0x15, 3, sealed.size() + 1, out) == 0x800f0f23, "payload size must match in_size");
  bad = sealed;
  bad[4] = 2;
  Check(request(bad, 0x15, 3, bad.size(), out) == 0x800f0f2e, "bad version");
  Check(request(sealed, 0x16, 3, sealed.size(), out) == 0x800f0f26, "content id must match the caller");
  bad = sealed;
  bad[0x1d0] ^= 1;
  Check(request(bad, 0x15, 3, bad.size(), out) == 0x800f0f24 && out_untouched(), "the signature covers the ciphertext");
  bad = sealed;
  bad[0x30] ^= 1;
  Check(request(bad, 0x15, 3, bad.size(), 0) == 0x800f0f24, "the signature covers the plaintext digest");
  bad = sealed;
  bad[0x60] ^= 1;
  Check(request(bad, 0x15, 3, bad.size(), 0) == 0x800f0f24, "a damaged signature fails");

  Context context;
  context.cid = 0x15;
  context.mkv = 3;
  context.salt = salt;
  auto kat = std::make_shared<EnvelopeKatBackend>(context, kat_key);
  SetBackendForTesting(kat);
  const auto derive_before_verify = kat->derive_calls;
  Check(request(sealed, 0x15, 3, sealed.size(), 0) == 0 && kat->derive_calls == derive_before_verify,
        "verify-only never invokes the secure backend");
  Check(request(sealed, 0x15, 3, sealed.size(), out) == 0 &&
            std::memcmp(out_area, plaintext.data(), plaintext.size()) == 0 &&
            std::all_of(out_area + plaintext.size(), out_area + 0x1000, [](uint8_t byte) { return byte == 0xcd; }),
        "the ioctl path returns a digest-verified 70-byte KAT plaintext");
  const auto parsed = nlohmann::json::parse(out_area, out_area + plaintext.size(), nullptr, false);
  Check(!parsed.is_discarded() && parsed["userfeedback"]["timeX"] == 123 && parsed["userfeedback"]["timeY"] == 456,
        "the nonprotected result has the configuration consumer shape");
  Check(kat->derive_calls == 1 && kat->crypt_calls == 1 && kat->residual_calls == 1 && kat->release_calls == 1,
        "the 70-byte request uses one derive, aligned crypt, residual crypt and release");
  Check(request(sealed, 0x15, 3, sealed.size(), 0x1000) == 0x800f0f0e,
        "secure processing reports a guest copyout fault only after digest verification");
  Check(request(unrelated, 0x15, 3, unrelated.size(), out) == 0x800f0f36 && out_untouched(),
        "a valid signature with the wrong plaintext digest never copies output");
  Check(request(sealed, 0x15, 4, sealed.size(), out) == unavailable_result && out_untouched(),
        "a different master key version cannot reuse the configured test slot");
  auto other_salt = salt;
  other_salt[0] ^= 0xff;
  salt = other_salt;
  Check(request(sealed, 0x15, 3, sealed.size(), out) == unavailable_result && out_untouched(),
        "a different salt cannot reuse the configured test slot");
  salt[0] ^= 0xff;

  std::vector<uint8_t> long_plaintext(crypt_chunk_size + 0x13);
  for (size_t i = 0; i < long_plaintext.size(); i++) long_plaintext[i] = static_cast<uint8_t>(i * 13 + 7);
  const auto long_ciphertext = EncryptEnvelopeFixture(kat_key, iv, long_plaintext);
  std::vector<uint8_t> long_output(long_plaintext.size(), 0xcd);
  const auto crypt_before = kat->crypt_calls;
  const auto residual_before = kat->residual_calls;
  const auto long_result = EnvelopeSecureProcessor::Process(context, iv, long_ciphertext, long_output);
  Check(long_result.status == Status::Success && long_result.operation_result == 0 &&
        long_result.written == long_plaintext.size() && long_output == long_plaintext &&
        kat->crypt_calls == crypt_before + 2 && kat->residual_calls == residual_before + 1,
        "secure processing preserves the 0x10000-byte chunk and residual boundaries");

  auto check_boundary = [&](size_t size, size_t expected_crypt, size_t expected_residual) {
    std::vector<uint8_t> input(size);
    for (size_t i = 0; i < size; i++) input[i] = static_cast<uint8_t>(i * 29 + 3);
    const auto encrypted = EncryptEnvelopeFixture(kat_key, iv, input);
    std::vector<uint8_t> output(size, 0xcd);
    const auto derive_before = kat->derive_calls;
    const auto crypt_before_boundary = kat->crypt_calls;
    const auto residual_before_boundary = kat->residual_calls;
    const auto release_before = kat->release_calls;
    const auto result = EnvelopeSecureProcessor::Process(context, iv, encrypted, output);
    Check(result.status == Status::Success && result.written == size && output == input &&
          kat->derive_calls == derive_before + 1 && kat->crypt_calls == crypt_before_boundary + expected_crypt &&
          kat->residual_calls == residual_before_boundary + expected_residual && kat->release_calls == release_before + 1,
          "secure processing selects the exact sub-block or aligned command path");
  };
  check_boundary(1, 0, 1);
  check_boundary(16, 1, 0);
  check_boundary(crypt_chunk_size, 1, 0);

  auto opaque = std::make_shared<EnvelopeOpaqueStateBackend>();
  SetBackendForTesting(opaque);
  std::array<uint8_t, 17> opaque_input {};
  for (size_t i = 0; i < opaque_input.size(); i++) opaque_input[i] = static_cast<uint8_t>(0x30 + i);
  std::array<uint8_t, 17> opaque_output {};
  const auto opaque_result = EnvelopeSecureProcessor::Process(context, iv, opaque_input, opaque_output);
  Check(opaque_result.status == Status::Success && opaque_result.written == opaque_output.size() &&
        std::equal(opaque_output.begin(), opaque_output.begin() + 16, opaque_input.begin()) &&
        opaque_output[16] == static_cast<uint8_t>(opaque_input[16] ^ EnvelopeOpaqueStateBackend::residual_stream[0]) &&
        opaque->saw_opaque_state && opaque->release_calls == 1,
        "secure processing passes the backend-returned opaque state into residual processing");
  SetBackendForTesting(kat);

  kat->failure = EnvelopeKatBackend::Failure::Residual;
  std::vector<uint8_t> failed_output(17, 0xcd);
  std::vector<uint8_t> failed_plaintext(17, 0x42);
  const auto failed_ciphertext = EncryptEnvelopeFixture(kat_key, iv, failed_plaintext);
  const auto failed = EnvelopeSecureProcessor::Process(context, iv, failed_ciphertext, failed_output);
  Check(failed.status == Status::OperationError && failed.operation_result == EnvelopeKatBackend::failure_result &&
        failed.written == 0 && std::all_of(failed_output.begin(), failed_output.end(), [](uint8_t byte) { return byte == 0; }),
        "a backend failure wipes partial plaintext and preserves the operation result");
  kat->failure = EnvelopeKatBackend::Failure::None;
  SetBackendForTesting(nullptr);

  {
    // host AES behind the production command path; the derivation is a stand-in gated by KYTY_DIAGNOSTIC_ENVELOPE_LOCAL
    auto local = std::make_shared<LocalSecureBackend>();
    const auto table_path = root / "envelope-local-keys.tbl";
    {
      Common::File table;
      Check(table.Create(table_path), "create local envelope key table");
      const char magic[8] = {'K','Y','T','Y','M','K','V','1'};
      table.Write(magic, sizeof(magic));
      const uint32_t count = 1;
      table.Write(&count, sizeof(count));
      const uint32_t cid = context.cid, mkv = context.mkv;
      const uint32_t derivation = derivation_diagnostic_ecb_salt, material_size = 16;
      std::array<uint8_t, 32> material {};
      for (size_t i = 0; i < material.size(); i++) material[i] = static_cast<uint8_t>(0x55 + i * 3);
      table.Write(&cid, sizeof(cid));
      table.Write(&mkv, sizeof(mkv));
      table.Write(&derivation, sizeof(derivation));
      table.Write(&material_size, sizeof(material_size));
      table.Write(material.data(), material.size());
      table.Close();
      std::string table_error;
      Check(local->LoadKeyTable(Common::PathToString(table_path).c_str(), &table_error),
            "load the local envelope key table");
      _putenv_s("KYTY_DIAGNOSTIC_ENVELOPE_LOCAL", "1");
      uint16_t slot = 0;
      Check(local->DeriveKey(context, &slot).status == Status::Success && slot != 0,
            "local backend derives a provisioned domain");
      local->ReleaseKey(slot);
      Context denied = context;
      denied.mkv = context.mkv + 1;
      Check(local->DeriveKey(denied, &slot).status == Status::Unavailable,
            "local backend fails closed on an unprovisioned domain");
      _putenv_s("KYTY_DIAGNOSTIC_ENVELOPE_LOCAL", "0");
      Check(local->DeriveKey(context, &slot).status == Status::Unavailable,
            "diagnostic derivations require the diagnostic gate");
      _putenv_s("KYTY_DIAGNOSTIC_ENVELOPE_LOCAL", "1");

      std::array<uint8_t, 16> m16 {};
      std::memcpy(m16.data(), material.data(), m16.size());
      std::array<uint8_t, 16> derived_key {};
      Check(EnvelopeAes(m16, false, false,
                        std::span<const uint8_t>(context.salt.data(), m16.size()), derived_key),
            "compute the expected diagnostic slot key");
      const auto local_ciphertext = EncryptEnvelopeFixture(derived_key, iv, plaintext);
      std::vector<uint8_t> local_output(plaintext.size(), 0xcd);
      SetBackendForTesting(local);
      const auto local_result = EnvelopeSecureProcessor::Process(context, iv, local_ciphertext, local_output);
      Check(local_result.status == Status::Success && local_result.provider == Provider::Local &&
            local_result.written == plaintext.size() && local_output == plaintext,
            "the local backend round-trips plaintext through host AES with local provenance");
      SetBackendForTesting(nullptr);
      SecureZeroMemory(m16.data(), m16.size());
      SecureZeroMemory(derived_key.data(), derived_key.size());
      SecureZeroMemory(material.data(), material.size());
    }
  }

  auto hex = [](const uint8_t* bytes, size_t size) {
    std::string value;
    for (size_t i = 0; i < size; i++) {
      char pair[3];
      std::snprintf(pair, sizeof(pair), "%02x", bytes[i]);
      value += pair;
    }
    return value;
  };
  auto line = [&](const std::vector<uint8_t>& in, const std::array<uint8_t, 0x20>& record_salt, const AuthInfo::Digest& digest) {
    std::ostringstream stream;
    stream << in.size() << " 0x15 3 0 " << AuthInfo::DigestHex(AuthInfo::Sha256(in.data(), in.size())) << ' '
           << AuthInfo::DigestHex(AuthInfo::Sha256(key.data(), key.size())) << ' '
           << AuthInfo::DigestHex(AuthInfo::Sha256(record_salt.data(), record_salt.size())) << ' ' << AuthInfo::DigestHex(digest) << ' '
           << hex(plaintext.data(), plaintext.size()) << '\n';
    return stream.str();
  };
  const std::string observations = "# fixture\n" + line(sealed, salt, plaintext_sha256) + line(unrelated, salt, plaintext_sha256) +
                                   line(sealed, other_salt, AuthInfo::Sha256(text.data(), 4));
  const auto observation_path = root / "envelope-observations.txt";
  Common::File file;
  Check(file.Create(observation_path), "create envelope observation fixture");
  file.Write(observations.data(), observations.size());
  file.Close();
  const auto observation_pin = AuthInfo::DigestHex(AuthInfo::Sha256(observations.data(), observations.size()));
  _putenv_s("KYTY_PS5_ENVELOPE_OBSERVATIONS", Common::PathToString(observation_path).c_str());
  _putenv_s("KYTY_PS5_ENVELOPE_OBSERVATIONS_SHA256", observation_pin.c_str());

  Check(request(sealed, 0x15, 3, sealed.size(), out) == 0 && std::memcmp(out_area, plaintext.data(), plaintext.size()) == 0 &&
            std::all_of(out_area + plaintext.size(), out_area + 0x1000, [](uint8_t byte) { return byte == 0xcd; }),
        "the exact pinned observation remains a separate supported provider");
  kat->failure = EnvelopeKatBackend::Failure::Derive;
  SetBackendForTesting(kat);
  Check(request(sealed, 0x15, 3, sealed.size(), out) == EnvelopeKatBackend::failure_result && out_untouched(),
        "a configured backend failure never falls through to an observation");
  kat->failure = EnvelopeKatBackend::Failure::NotConfigured;
  Check(request(sealed, 0x15, 3, sealed.size(), out) == unavailable_result && out_untouched(),
        "a selected backend cannot return NotConfigured to fall through to an observation");
  SetBackendForTesting(nullptr);
  kat->failure = EnvelopeKatBackend::Failure::None;
  Check(request(sealed, 0x15, 4, sealed.size(), out) == unavailable_result && out_untouched(), "a different master key version has no observation");
  Check(request(unrelated, 0x15, 3, unrelated.size(), out) == unavailable_result && out_untouched(),
        "an observation whose plaintext is not the signed digest is never served");
  salt = other_salt;
  Check(request(sealed, 0x15, 3, sealed.size(), out) == unavailable_result && out_untouched(), "a record with a false plaintext digest is not loaded");
  salt[0] ^= 0xff;
  Check(request(sealed, 0x15, 3, sealed.size(), 0x1000) == 0x800f0f0e, "a faulting copyout reports 0x800f0f0e");

  auto counting = std::make_shared<EnvelopeCountingBackend>();
  SetEnvelopeBackendForTesting(counting);
  Check(request(sealed, 0x15, 3, sealed.size(), 0) == 0 && counting->calls == 0,
        "verify-only does not invoke a configured whole-envelope provider");
  SetEnvelopeBackendForTesting(nullptr);

  struct SavedEnvelopeEnvironment {
    bool present;
    std::string value;
  };
  auto save_environment = [](const char* name) {
    const char* value = std::getenv(name);
    return SavedEnvelopeEnvironment {value != nullptr, value == nullptr ? "" : value};
  };
  const auto saved_port = save_environment("KYTY_PS5_ENVELOPE_PROVIDER_PORT");
  const auto saved_token = save_environment("KYTY_PS5_ENVELOPE_PROVIDER_TOKEN_FILE");
  const auto saved_timeout = save_environment("KYTY_PS5_ENVELOPE_PROVIDER_TIMEOUT_MS");
  const auto saved_replay = save_environment("KYTY_PS5_OFFLINE_REPLAY_HMAC_KEY_HEX");
  std::array<uint8_t, 32> provider_token {};
  for (size_t i = 0; i < provider_token.size(); i++) provider_token[i] = static_cast<uint8_t>(0x31 + i * 7);
  auto write_token = [&](const std::filesystem::path& path, const std::array<uint8_t, 32>& token, const char* suffix) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << std::hex << std::setfill('0');
    for (const auto byte: token) output << std::setw(2) << static_cast<unsigned>(byte);
    output << suffix;
    output.close();
    Check(output.good(), "write envelope provider test token file");
  };
  const auto provider_token_path = root / "envelope-provider-token.txt";
  write_token(provider_token_path, provider_token, "\n");
  const auto zero_token_path = root / "envelope-provider-zero-token.txt";
  std::array<uint8_t, 32> zero_token {};
  write_token(zero_token_path, zero_token, "\n");
  const auto whitespace_token_path = root / "envelope-provider-whitespace-token.txt";
  write_token(whitespace_token_path, provider_token, "\n\n");
  Check(_putenv_s("KYTY_PS5_ENVELOPE_PROVIDER_PORT", "1") == 0 &&
        _putenv_s("KYTY_PS5_ENVELOPE_PROVIDER_TIMEOUT_MS", "100") == 0 &&
        _putenv_s("KYTY_PS5_OFFLINE_REPLAY_HMAC_KEY_HEX", "") == 0 &&
        _putenv_s("KYTY_PS5_ENVELOPE_PROVIDER_TOKEN_FILE", Common::PathToString(zero_token_path).c_str()) == 0,
        "set invalid envelope provider token configuration");
  std::shared_ptr<EnvelopeBackend> rejected_provider;
  std::string provider_error;
  Check(CreateConsoleProviderFromEnvironment(&rejected_provider, &provider_error) == ConfigurationStatus::Invalid &&
        rejected_provider == nullptr && !provider_error.empty(),
        "the console provider rejects an all-zero authentication token");
  provider_error.clear();
  Check(_putenv_s("KYTY_PS5_ENVELOPE_PROVIDER_TOKEN_FILE", Common::PathToString(whitespace_token_path).c_str()) == 0 &&
        CreateConsoleProviderFromEnvironment(&rejected_provider, &provider_error) == ConfigurationStatus::Invalid &&
        rejected_provider == nullptr && !provider_error.empty(),
        "the console provider rejects noncanonical token-file whitespace");

  std::string replay_key;
  const char* digits = "0123456789abcdef";
  for (const auto byte: provider_token) {
    replay_key += digits[byte >> 4];
    replay_key += digits[byte & 15];
  }
  std::shared_ptr<EnvelopeBackend> replay_provider;
  std::shared_ptr<RnpsBackend> replay_rnps;
  Check(_putenv_s("KYTY_PS5_ENVELOPE_PROVIDER_TOKEN_FILE", "") == 0 &&
        _putenv_s("KYTY_PS5_OFFLINE_REPLAY_HMAC_KEY_HEX", replay_key.c_str()) == 0 &&
        CreateConsoleProviderFromEnvironment(&replay_provider, &provider_error) == ConfigurationStatus::Configured &&
        CreateConsoleRnpsProviderFromEnvironment(&replay_rnps, &provider_error) == ConfigurationStatus::Configured &&
        replay_provider != nullptr && replay_rnps != nullptr,
        "configure both loopback providers without a token file");
  replay_provider.reset();
  replay_rnps.reset();
  Check(_putenv_s("KYTY_PS5_ENVELOPE_PROVIDER_TOKEN_FILE", Common::PathToString(provider_token_path).c_str()) == 0 &&
        CreateConsoleProviderFromEnvironment(&rejected_provider, &provider_error) == ConfigurationStatus::Invalid,
        "reject a replay key combined with a provider token file");
  Check(_putenv_s("KYTY_PS5_ENVELOPE_PROVIDER_TOKEN_FILE", "") == 0 &&
        _putenv_s("KYTY_PS5_OFFLINE_REPLAY_HMAC_KEY_HEX", "invalid") == 0 &&
        CreateConsoleProviderFromEnvironment(&rejected_provider, &provider_error) == ConfigurationStatus::Invalid,
        "reject a malformed replay key");
  Check(_putenv_s("KYTY_PS5_OFFLINE_REPLAY_HMAC_KEY_HEX", std::string(64, '0').c_str()) == 0 &&
        CreateConsoleProviderFromEnvironment(&rejected_provider, &provider_error) == ConfigurationStatus::Invalid,
        "reject an all-zero replay key");
  Check(_putenv_s("KYTY_PS5_OFFLINE_REPLAY_HMAC_KEY_HEX", "") == 0,
        "clear replay key before live provider cases");

  auto configure_console = [&](uint16_t port, uint32_t timeout_ms) {
    const auto port_text = std::to_string(port);
    const auto timeout_text = std::to_string(timeout_ms);
    Check(_putenv_s("KYTY_PS5_ENVELOPE_PROVIDER_PORT", port_text.c_str()) == 0 &&
          _putenv_s("KYTY_PS5_ENVELOPE_PROVIDER_TOKEN_FILE", Common::PathToString(provider_token_path).c_str()) == 0 &&
          _putenv_s("KYTY_PS5_ENVELOPE_PROVIDER_TIMEOUT_MS", timeout_text.c_str()) == 0,
          "set envelope provider loopback configuration");
    std::shared_ptr<EnvelopeBackend> provider;
    std::string error;
    Check(CreateConsoleProviderFromEnvironment(&provider, &error) == ConfigurationStatus::Configured &&
          provider != nullptr && error.empty(), "configure the authenticated envelope loopback provider");
    auto recording = std::make_shared<EnvelopeRecordingBackend>(std::move(provider));
    SetEnvelopeBackendForTesting(recording);
    return recording;
  };

  auto run_console = [&](EnvelopeConsoleTestServer::Mode mode, uint32_t timeout_ms) {
    EnvelopeConsoleTestServer server(mode, provider_token, key, salt, sealed, plaintext);
    auto recording = configure_console(server.Port(), timeout_ms);
    const uint32_t result = request(sealed, 0x15, 3, sealed.size(), out);
    server.Join();
    Check(server.RequestValid() && server.RequestId() != 0 && recording->calls == 1,
          "the ioctl sent one authenticated pointer-free envelope request");
    SetEnvelopeBackendForTesting(nullptr);
    return std::pair {result, recording->result};
  };

  const auto console_success = run_console(EnvelopeConsoleTestServer::Mode::Success, 1000);
  Check(console_success.first == 0 && console_success.second.status == Status::Success &&
        console_success.second.provider == Provider::Console && console_success.second.operation_result == 0 &&
        console_success.second.written == plaintext.size() && console_success.second.dispatch_state == 1 &&
        std::memcmp(out_area, plaintext.data(), plaintext.size()) == 0,
        "the ioctl accepts authenticated output and copies it only after the local digest check");

  const auto console_digest = run_console(EnvelopeConsoleTestServer::Mode::DigestMismatch, 1000);
  Check(console_digest.first == 0x800f0f36 && console_digest.second.status == Status::Success &&
        console_digest.second.dispatch_state == 1 && out_untouched(),
        "a provider success with the wrong plaintext digest leaves guest output untouched");

  const auto derive_before_console_failure = kat->derive_calls;
  SetBackendForTesting(kat);
  EnvelopeConsoleTestServer native_failure_server(EnvelopeConsoleTestServer::Mode::NativeFailure,
      provider_token, key, salt, sealed, plaintext);
  auto native_failure_recording = configure_console(native_failure_server.Port(), 1000);
  const uint32_t native_failure = request(sealed, 0x15, 3, sealed.size(), out);
  native_failure_server.Join();
  Check(native_failure_server.RequestValid() && native_failure == unavailable_result && out_untouched() &&
        native_failure_recording->calls == 1 && native_failure_recording->result.status == Status::OperationError &&
        native_failure_recording->result.native_ioctl_errno == 5 &&
        native_failure_recording->result.dispatch_state == 1 &&
        kat->derive_calls == derive_before_console_failure,
        "a selected native-provider failure is terminal without command or observation fallback");
  SetEnvelopeBackendForTesting(nullptr);
  SetBackendForTesting(nullptr);

  const auto console_malformed = run_console(EnvelopeConsoleTestServer::Mode::Malformed, 1000);
  Check(console_malformed.first == unavailable_result && console_malformed.second.status == Status::ProtocolError &&
        console_malformed.second.dispatch_state == 2 && out_untouched(),
        "a malformed post-dispatch response is outcome-unknown and leaves guest output untouched");
  const auto console_hmac = run_console(EnvelopeConsoleTestServer::Mode::BadHmac, 1000);
  Check(console_hmac.first == unavailable_result && console_hmac.second.status == Status::ProtocolError &&
        console_hmac.second.dispatch_state == 2 && out_untouched(),
        "an unauthenticated post-dispatch response is outcome-unknown and terminal");
  const auto console_trailing = run_console(EnvelopeConsoleTestServer::Mode::Trailing, 1000);
  Check(console_trailing.first == unavailable_result && console_trailing.second.status == Status::ProtocolError &&
        console_trailing.second.dispatch_state == 2 && out_untouched(),
        "a response with trailing bytes is rejected as outcome-unknown");
  const auto console_disconnect = run_console(EnvelopeConsoleTestServer::Mode::Disconnect, 1000);
  Check(console_disconnect.first == unavailable_result && console_disconnect.second.status == Status::TransportError &&
        console_disconnect.second.transport_result != 0 && console_disconnect.second.dispatch_state == 2 && out_untouched(),
        "a disconnect after request commit is transport-failed with unknown outcome");
  const auto console_timeout = run_console(EnvelopeConsoleTestServer::Mode::Timeout, 100);
  Check(console_timeout.first == unavailable_result && console_timeout.second.status == Status::TransportError &&
        console_timeout.second.transport_result != 0 && console_timeout.second.dispatch_state == 2 && out_untouched(),
        "a timeout after request commit is terminal with unknown outcome");
  const auto slow_drip_started = std::chrono::steady_clock::now();
  const auto console_slow_drip = run_console(EnvelopeConsoleTestServer::Mode::SlowDrip, 100);
  const auto slow_drip_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - slow_drip_started).count();
  Check(console_slow_drip.first == unavailable_result &&
        console_slow_drip.second.status == Status::TransportError &&
        console_slow_drip.second.transport_result != 0 && console_slow_drip.second.dispatch_state == 2 &&
        slow_drip_ms < 1000 && out_untouched(),
        "a slow-drip response cannot reset the absolute transaction deadline");
  const auto console_bad_transport = run_console(EnvelopeConsoleTestServer::Mode::BadTransport, 1000);
  Check(console_bad_transport.first == unavailable_result &&
        console_bad_transport.second.status == Status::ProtocolError &&
        console_bad_transport.second.dispatch_state == 2 && out_untouched(),
        "an authenticated out-of-range transport enum is rejected as post-dispatch malformed");
  const auto console_negative_status = run_console(EnvelopeConsoleTestServer::Mode::NegativeStatus, 1000);
  Check(console_negative_status.first == unavailable_result &&
        console_negative_status.second.status == Status::ProtocolError &&
        console_negative_status.second.dispatch_state == 2 && out_untouched(),
        "an authenticated negative native status is rejected as post-dispatch malformed");
  const auto console_sentinel_result = run_console(EnvelopeConsoleTestServer::Mode::SentinelResult, 1000);
  Check(console_sentinel_result.first == unavailable_result &&
        console_sentinel_result.second.status == Status::ProtocolError &&
        console_sentinel_result.second.dispatch_state == 2 && out_untouched(),
        "an uninitialized native-result sentinel is never propagated as an operation result");

  SetEnvelopeBackendForTesting(nullptr);
  Check(_putenv_s("KYTY_PS5_ENVELOPE_PROVIDER_PORT", saved_port.present ? saved_port.value.c_str() : "") == 0 &&
        _putenv_s("KYTY_PS5_ENVELOPE_PROVIDER_TOKEN_FILE", saved_token.present ? saved_token.value.c_str() : "") == 0 &&
        _putenv_s("KYTY_PS5_ENVELOPE_PROVIDER_TIMEOUT_MS", saved_timeout.present ? saved_timeout.value.c_str() : "") == 0 &&
        _putenv_s("KYTY_PS5_OFFLINE_REPLAY_HMAC_KEY_HEX", saved_replay.present ? saved_replay.value.c_str() : "") == 0,
        "restore envelope provider environment");
  SecureZeroMemory(provider_token.data(), provider_token.size());

  if (const char* vector = std::getenv("KYTY_TEST_ENVELOPE_VECTOR"); vector != nullptr && vector[0] != '\0') {
    std::ifstream input(Common::PathFromUtf8(vector), std::ios::binary);
    const std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    Check(bytes.size() > 0x320 + 0x1d0 && bytes.size() - 0x320 <= 0x2000 - 0x400, "read console envelope vector");
    std::memcpy(key.data(), bytes.data(), 0x300);
    std::memcpy(salt.data(), bytes.data() + 0x300, 0x20);
    const std::vector<uint8_t> console(bytes.begin() + 0x320, bytes.end());
    uint32_t cid = 0;
    std::memcpy(&cid, console.data() + 8, 4);
    Check(request(console, cid, 3, console.size(), 0) == 0, "PSS signature verifies on the console envelope");
    Check(request(console, cid, 3, console.size(), out) == unavailable_result && out_untouched(), "the console envelope has no configured secure backend here");
    std::printf("KernelFileSystemTests: console envelope vector verified size=%zu cid=0x%x\n", console.size(), cid);
  }

  SetBackendForTesting(nullptr);
  SetEnvelopeBackendForTesting(nullptr);
  _putenv_s("KYTY_PS5_ENVELOPE_OBSERVATIONS", "");
  _putenv_s("KYTY_PS5_ENVELOPE_OBSERVATIONS_SHA256", "");
  SecureZeroMemory(kat_key.data(), kat_key.size());
  BCryptDestroyKey(signer);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  Check(FileSystem::KernelClose(fd) == OK, "close envelope");
}
#endif
