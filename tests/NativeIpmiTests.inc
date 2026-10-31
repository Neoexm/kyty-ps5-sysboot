void CheckNativeStrictIpmi() {
#if defined(_WIN32)
  namespace Kernel = Libs::LibKernel;
  namespace Bridge = Libs::NativeKernelBridge;
  const char* keys[] = {"KYTY_DIAGNOSTIC_ORIGINAL_SYSCORE_APP_IPMI",
      "KYTY_DIAGNOSTIC_IPMI_SHARED_SCOPE", "KYTY_DIAGNOSTIC_SYSAV_IPMI_SERVICE"};
  std::array<std::string, 3> saved;
  for (size_t i = 0; i < saved.size(); ++i) {
    const auto* value = std::getenv(keys[i]);
    saved[i] = value == nullptr ? "" : value;
  }
  char scope[21] {};
  std::snprintf(scope, sizeof(scope), "i%08lx%08lx", GetCurrentProcessId(),
                static_cast<unsigned long>(GetTickCount()));
  Check(_putenv_s(keys[0], "1") == 0 && _putenv_s(keys[1], scope) == 0 &&
        _putenv_s(keys[2], "1") == 0, "select strict native IPMI with legacy bypass also configured");
  void* storage = nullptr;
  Check(Kernel::Memory::KernelMapNamedFlexibleMemory(&storage, 0x4000, 3, 0, "native-ipmi-test") == OK,
        "allocate guest IPMI argument records");
  auto* bytes = static_cast<uint8_t*>(storage);
  std::memset(bytes, 0, 0x4000);
  const auto base = reinterpret_cast<uint64_t>(bytes);
  auto* result = reinterpret_cast<int32_t*>(bytes);
  auto* creation = reinterpret_cast<uint64_t*>(bytes + 0x40);
  creation[0] = base + 0x100;
  creation[1] = base + 0x200;
  creation[2] = base + 0x300;
  std::strcpy(reinterpret_cast<char*>(bytes + 0x200), "SceNativeIpmiFixture");
  auto* config = reinterpret_cast<uint64_t*>(bytes + 0x300);
  config[0] = 0x38;
  config[1] = 1;
  config[2] = 0x100;
  config[3] = 0x100;
  *result = 0x12345678;
  const auto server = Bridge::DispatchSyscall({0x26e, {0, 0, base, base + 0x40, 24, 0}});
  Check(server.value == -1 && server.posix_errno == Libs::Posix::POSIX_ENOSYS && *result == 0x12345678,
        "missing authinfo returns transport failure with unchanged result and no legacy server creation");
  uint32_t id = 0, guest_pid = 0, host_pid = 0;
  Check(!Kernel::IpmiScope::Lookup("SceNativeIpmiFixture", &id, &guest_pid, &host_pid),
        "failed authorization does not register any service");
  config[0] = 336;
  *result = 0x12345678;
  const auto client = Bridge::DispatchSyscall({0x26e, {2, 0, base, base + 0x40, 24, 0}});
  Check(client.value == 0 && client.posix_errno == 0 && *result > 0,
        "native client creation allocates a disconnected object without a server");
  const auto client_id = static_cast<uint32_t>(*result);
  Check(!Kernel::IpmiScope::Lookup("SceNativeIpmiFixture", &id, &guest_pid, &host_pid),
        "disconnected client creation does not register a service");
  auto* completion = reinterpret_cast<int32_t*>(bytes + 0x700);
  auto* timeout = reinterpret_cast<uint32_t*>(bytes + 0x710);
  auto* connect = reinterpret_cast<uint64_t*>(bytes + 0x720);
  *completion = 0x12345678;
  *timeout = 0;
  connect[0] = 0;
  connect[1] = 0;
  connect[2] = base + 0x700;
  connect[3] = base + 0x710;
  const auto missing = Bridge::DispatchSyscall({0x26e, {0x400, client_id, base, base + 0x720, 32, 0}});
  Check(missing.value == 0 && missing.posix_errno == 0 && *result == Kernel::KERNEL_ERROR_ESRCH &&
        *completion == 0x12345678, "zero-timeout connect preserves the missing-server error");
  const auto closed = Bridge::DispatchSyscall({0x26e, {3, client_id, base, 0, 0, 0}});
  Check(closed.value == 0 && closed.posix_errno == 0 && *result == OK,
        "close disconnected native client");
  *result = 0x12345678;
  std::memset(bytes + 0x400, 0xa5, 0x20);
  const auto unsupported = Bridge::DispatchSyscall({0x26e, {0x400, 1, base, base + 0x400, 32, 0}});
  Check(unsupported.value == -1 && unsupported.posix_errno == Libs::Posix::POSIX_ENOSYS &&
        *result == 0x12345678 && bytes[0x400] == 0xa5,
        "unsupported native IPMI does not acknowledge a nonexistent connection");
  *reinterpret_cast<uint64_t*>(bytes + 0x500) = base + 0x600;
  std::memset(bytes + 0x600, 0x5a, 32);
  const auto failed_name = Bridge::DispatchSyscall({0x26e,
      {0x46a, 0x8002004e, base, base + 0x500, 8, 0}});
  Check(failed_name.value == 0 && failed_name.posix_errno == 0 &&
        *result == Kernel::KERNEL_ERROR_EBADF && bytes[0x600] == 0x5a && bytes[0x61f] == 0x5a,
        "failed native server name query preserves operation status and leaves the name untouched");
  int32_t host_result = 0x12345678;
  const auto bad_result = Bridge::DispatchSyscall({0x26e, {2, 0,
      reinterpret_cast<uint64_t>(&host_result), base + 0x40, 24, 0}});
  Check(bad_result.value == -1 && bad_result.posix_errno == Libs::Posix::POSIX_EFAULT &&
        host_result == 0x12345678, "native IPMI rejects output outside guest mappings");
  const auto bad_handle = Bridge::DispatchSyscall({0x26e, {2, 0x100000000, base, base + 0x40, 24, 0}});
  Check(bad_handle.value == -1 && bad_handle.posix_errno == Libs::Posix::POSIX_EINVAL,
        "native IPMI rejects noncanonical handle words");
  Check(Kernel::Memory::KernelMunmap(base, 0x4000) == OK, "release native IPMI argument storage");
  for (size_t i = 0; i < saved.size(); ++i) Check(_putenv_s(keys[i], saved[i].c_str()) == 0,
        "restore native IPMI test settings");
  std::printf("NativeIpmiTests: strict routing, authorization, absent server and output preservation passed\n");
#endif
}
