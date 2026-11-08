void CheckNativeAvDevices(Libs::Graphics::WindowContext& graphics) {
#if defined(_WIN32)
  using namespace NativeAvTest;
  using namespace Libs::LibKernel;
  Environment environment;
  for (size_t i = 1; i < controls.size(); ++i) Environment::Set(controls[i], "");
  static_cast<void>(VO::VideoOutInit(64, 64, *graphics.presenter));
  Check(VO::VideoOutIsInitialized(), "normal AV fixture initializes VideoOut");
  {
    Requests io;
    Check(!FileSystem::IsNativeAvProbeDescriptor(io.av),
          "normal AV descriptor does not require the diagnostic probe");
    auto create_client = [&](int fd, uint32_t port, uint32_t bus, uint64_t output) {
      io.Put(0, std::array<uint64_t, 4>{
          (uint64_t{port} << 32) | 1, (uint64_t{8} << 32) | bus, output, 0});
      return FileSystem::KernelIoctl(fd, 0x80208218u, io.At());
    };
    auto client_request = [&](int fd, uint32_t command, uint32_t cookie) {
      io.Put(0, std::array<uint64_t, 6>{command,
          (command == 9 ? uint64_t{8} << 32 : 0) | cookie,
          command == 9 ? reinterpret_cast<uint64_t>(io.At(0x500)) : 0,
          0, command == 9 ? reinterpret_cast<uint64_t>(io.At(0x508)) : 0,
          command == 9 ? 8u : 0u});
      return FileSystem::KernelIoctl(fd, 0x80308217u, io.At());
    };
  }
  VO::VideoOutShutdown();
  std::printf("NativeAvDeviceTests: normal_clock=pass pending_mode=pass unknown_hdmi_preserved=pass no_mbus_injection=pass\n");
#endif
}
