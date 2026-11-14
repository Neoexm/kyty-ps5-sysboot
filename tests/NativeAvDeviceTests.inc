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
    const auto client_output = reinterpret_cast<uint64_t>(io.At(0x500));
    const auto before_client = Both();
    io.Put(0x500, uint64_t{0x9876543210abcdefu});
    Check(create_client(io.main, 7, 0, client_output) == KERNEL_ERROR_EINVAL &&
          io.Read<uint64_t>(0x500) == 0x9876543210abcdefu,
          "DCE rejects an invalid port without writing a cookie");
    Check(create_client(io.main, 1, 0, 1) == KERNEL_ERROR_EFAULT,
          "DCE validates client copyout before reserving the port");
    uint64_t host_output = 0xabcdef1234567890u;
    Check(create_client(io.main, 1, 0, reinterpret_cast<uint64_t>(&host_output)) == KERNEL_ERROR_EFAULT &&
          host_output == 0xabcdef1234567890u,
          "DCE client copyout cannot target a writable host stack buffer");
    Check(create_client(io.main, 1, 0, client_output) == OK,
          "DCE creates the recovered MAIN client independently of display mode readiness");
    const uint64_t cookie = io.Read<uint64_t>(0x500);
    Check(cookie != 0 && cookie <= UINT32_MAX && Both() == before_client,
          "DCE returns an opaque client identity without programming display state");
    Check(create_client(io.typec, 1, 0, client_output) == KERNEL_ERROR_EBUSY &&
          io.Read<uint64_t>(0x500) == cookie,
          "DCE preserves an occupied MAIN port and the caller output");
    Check(client_request(io.typec, 9, static_cast<uint32_t>(cookie)) == KERNEL_ERROR_EINVAL,
          "DCE client cookie is bound to its descriptor");
    {
      Process::ScopedGuestProcessPid other(8765);
      Check(client_request(io.main, 9, static_cast<uint32_t>(cookie)) == KERNEL_ERROR_EINVAL &&
            client_request(io.main, 1, static_cast<uint32_t>(cookie)) == KERNEL_ERROR_EINVAL,
            "DCE does not disclose or destroy another guest process client");
    }
    Check(client_request(io.main, 9, static_cast<uint32_t>(cookie)) == OK &&
          io.Read<uint64_t>(0x508) == 0x170,
          "DCE command nine returns the recovered shared area size");
    const uint64_t shared = io.Read<uint64_t>(0x500);
    Memory::VirtualQueryInfo shared_info {};
    Check(shared != 0 && Memory::KernelVirtualQuery(reinterpret_cast<void*>(shared),
          0, &shared_info, sizeof(shared_info)) == OK && shared_info.is_committed,
          "DCE shared area has guest memory backing");
    const auto* shared_bytes = reinterpret_cast<const uint8_t*>(shared);
    Check(std::all_of(shared_bytes, shared_bytes + 0x170, [](uint8_t byte) { return byte == 0; }),
          "DCE initializes its shared slot without injecting readiness or pixels");
    Check(client_request(io.main, 9, static_cast<uint32_t>(cookie)) == OK &&
          io.Read<uint64_t>(0x500) == shared,
          "repeated DCE mapping queries retain the same allocation");
    io.Put(0, std::array<uint64_t, 6>{9, (uint64_t{8} << 32) | cookie,
        reinterpret_cast<uint64_t>(&host_output), 0,
        reinterpret_cast<uint64_t>(io.At(0x508)), 8});
    Check(FileSystem::KernelIoctl(io.main, 0x80308217u, io.At()) == KERNEL_ERROR_EFAULT &&
          host_output == 0xabcdef1234567890u,
          "DCE shared mapping copyout requires guest memory");
    Check(client_request(io.main, 1, static_cast<uint32_t>(cookie)) == OK &&
          client_request(io.main, 9, static_cast<uint32_t>(cookie)) == KERNEL_ERROR_EINVAL,
          "DCE close invalidates the client cookie");
    Check(Memory::KernelVirtualQuery(reinterpret_cast<void*>(shared),
          0, &shared_info, sizeof(shared_info)) != OK || !shared_info.is_committed,
          "DCE client close releases its guest shared allocation");
    Check(create_client(io.typec, 1, 0, client_output) == OK &&
          io.Read<uint64_t>(0x500) != cookie,
          "DCE reopens a released port with a new client generation");
    const uint32_t next_cookie = static_cast<uint32_t>(io.Read<uint64_t>(0x500));
    Check(client_request(io.typec, 1, next_cookie) == OK && Both() == before_client,
          "DCE client lifecycle leaves controller timing and readiness intact");
    const int client_fd = FileSystem::KernelOpen("/dev/dce", 2, 0);
    Check(client_fd >= 3 && create_client(client_fd, 1, 0, client_output) == OK,
          "DCE opens a separate descriptor with an owned client");
    const uint32_t closing_cookie = static_cast<uint32_t>(io.Read<uint64_t>(0x500));
    Check(client_request(client_fd, 9, closing_cookie) == OK,
          "DCE descriptor owns its shared allocation");
    const uint64_t closing_shared = io.Read<uint64_t>(0x500);
    Check(FileSystem::KernelClose(client_fd) == OK &&
          (Memory::KernelVirtualQuery(reinterpret_cast<void*>(closing_shared),
           0, &shared_info, sizeof(shared_info)) != OK || !shared_info.is_committed),
          "closing the DCE descriptor also releases an unclosed client");
    Check(create_client(io.main, 1, 0, client_output) == OK &&
          client_request(io.main, 1, static_cast<uint32_t>(io.Read<uint64_t>(0x500))) == OK,
          "descriptor cleanup releases the port lease");
    Check(create_client(io.main, 1, 0, client_output) == OK,
          "DCE creates a client for mapping replacement ownership checks");
    const uint32_t replaced_cookie = static_cast<uint32_t>(io.Read<uint64_t>(0x500));
    Check(client_request(io.main, 9, replaced_cookie) == OK,
          "DCE exposes the owned allocation before replacement");
    void* replacement = reinterpret_cast<void*>(io.Read<uint64_t>(0x500));
    const uint64_t replaced_address = reinterpret_cast<uint64_t>(replacement);
    Check(Memory::KernelMapNamedFlexibleMemory(&replacement, 0x4000, 3, 0x10, "dce_replacement") == OK &&
          reinterpret_cast<uint64_t>(replacement) == replaced_address,
          "guest MAP_FIXED replaces the DCE allocation at the same address");
    *static_cast<uint64_t*>(replacement) = 0x1020304050607080u;
    Check(client_request(io.main, 9, replaced_cookie) == KERNEL_ERROR_EFAULT,
          "DCE does not redisclose an unrelated replacement as its shared area");
    Check(client_request(io.main, 1, replaced_cookie) == OK &&
          Memory::KernelVirtualQuery(replacement, 0, &shared_info, sizeof(shared_info)) == OK &&
          shared_info.is_committed && *static_cast<uint64_t*>(replacement) == 0x1020304050607080u,
          "DCE close preserves guest memory that replaced its allocation");
    Check(Memory::KernelMunmap(replaced_address, 0x4000) == OK,
          "guest explicitly releases the preserved replacement allocation");
    Check(io.DisplayClock(120000, io.At(0x300)) == OK &&
          io.Read<uint32_t>(0x300) == 120000,
          "normal AV ioctl programs the display clock without diagnostic switches");
    Check(Get(0).display_clock_10khz == 120000 &&
          Get(1).display_clock_10khz == 120000 &&
          !Get(0).committed && !Get(1).committed,
          "normal clock programming alone does not establish a display mode");
    const auto programmed = Both();
    Check(io.DisplayClock(120001, io.At(0x300)) == KERNEL_ERROR_EINVAL && Both() == programmed,
          "unsupported display clock leaves controller state unchanged");
    Check(io.DisplayClock(120000, reinterpret_cast<void*>(1)) == KERNEL_ERROR_EFAULT &&
          Both() == programmed,
          "normal AV rejects an invalid nested output before modifying state");
    Check(FileSystem::KernelIoctl(io.av, 0xc0109a0eu, reinterpret_cast<void*>(1)) == KERNEL_ERROR_EFAULT,
          "normal AV validates its ioctl envelope");
    Check(io.Pair(0xc0089a0du, 0, 5934066) == KERNEL_ERROR_EINVAL && Both() == programmed,
          "pixel clock still requires a pending locked transaction");
    Check(io.Start(0) == OK, "normal AV begins a DCE mode transaction");
    io.Program(0);
    Check(Get(0).pending && !Get(0).committed &&
          Get(0).pending_timing.timing_programmed &&
          Get(0).pending_timing.pixel_encoding_programmed,
          "normal AV stages firmware timing and format without auto-completing the transaction");
    Check(io.Finish(0) == OK && Get(0).committed,
          "normal AV finishes only the fully programmed transaction");
    Check(create_client(io.main, 1, 0, client_output) == OK,
          "DCE creates a client over the programmed MAIN controller");
    const uint32_t graphics_cookie = static_cast<uint32_t>(io.Read<uint64_t>(0x500));
    EQ::KernelEqueue flip_queue = EQ::KERNEL_EQUEUE_INVALID;
    Check(EQ::KernelCreateEqueue(&flip_queue, "native-dce-client") == OK,
          "DCE client uses an event queue");
    constexpr uint64_t flip_ident = 0x0006010000000000ull;
    Check(FileSystem::RegisterNativeDceFlipEvent(flip_queue, flip_ident | 1) == KERNEL_ERROR_EINVAL,
          "DCE rejects an unsupported event encoding");
    {
      Process::ScopedGuestProcessPid other(8765);
      Check(FileSystem::RegisterNativeDceFlipEvent(flip_queue, flip_ident) == KERNEL_ERROR_EINVAL,
            "DCE flip events cannot bind another process client");
    }
    const auto before_graphics = Both();
    Check(FileSystem::RegisterNativeDceFlipEvent(flip_queue, flip_ident) == OK &&
          Both() == before_graphics,
          "DCE binds the flip event without reprogramming mode state");
    EQ::KernelEvent event;
    int event_count = -1;
    KernelUseconds poll = 0;
    Check(EQ::KernelWaitEqueue(flip_queue, &event, 1, &event_count, &poll) == KERNEL_ERROR_ETIMEDOUT &&
          event_count == 0,
          "DCE event registration does not synthesize a completed flip");
    auto graphics_request = [&](uint32_t command, uint32_t bytes, uint64_t index) {
      io.Put(0, std::array<uint64_t, 6>{command,
          (uint64_t{bytes} << 32) | graphics_cookie,
          reinterpret_cast<uint64_t>(io.At(0x100)), index, 0, 0});
      return FileSystem::KernelIoctl(io.main, 0x80308217u, io.At());
    };
    const std::array<uint64_t, 12> splash_attributes {
        0, 0x8000000000000000ull, 0x0000078000000000ull, 0x0000043800000780ull,
        0xffffffff00000000ull, 0x00000000ffffffffull, 0x8000000000000000ull, 0, 0, 0, 0, 0};
    io.Put(0, std::array<uint64_t, 6>{0x38, (uint64_t{0x60} << 32) | graphics_cookie,
        reinterpret_cast<uint64_t>(splash_attributes.data()), 0, 0, 0});
    Check(FileSystem::KernelIoctl(io.main, 0x80308217u, io.At()) == KERNEL_ERROR_EFAULT,
          "DCE attributes must come from guest memory rather than a readable host record");
    io.Put(0x100, splash_attributes);
    io.Put(0x118, uint64_t{0});
    Check(graphics_request(0x38, 0x60, 0) == KERNEL_ERROR_EINVAL,
          "DCE rejects an unrecovered surface layout");
    io.Put(0x100, splash_attributes);
    Check(graphics_request(0x38, 0x60, 0) == OK &&
          graphics_request(0x38, 0x60, 0) == KERNEL_ERROR_EBUSY,
          "DCE registers the recovered attribute group once per client");
    io.Put(0x100, std::array<uint64_t, 6>{0, 0, reinterpret_cast<uint64_t>(&host_output), 0, 0, 0});
    Check(graphics_request(0x37, 0x30, 0) == KERNEL_ERROR_EFAULT,
          "DCE cannot register host memory as a guest framebuffer");
    void* guest_surface = nullptr;
    Check(Memory::KernelMapNamedFlexibleMemory(&guest_surface, 0x7ec000, 3, 0, "native_dce_surface") == OK,
          "DCE registration fixture allocates guest surface memory");
    io.Put(0x100, std::array<uint64_t, 6>{0, 0, reinterpret_cast<uint64_t>(guest_surface), 0, 0, 0});
    const std::array<uint64_t, 6> host_registration {0, 0, reinterpret_cast<uint64_t>(guest_surface), 0, 0, 0};
    io.Put(0, std::array<uint64_t, 6>{0x37, (uint64_t{0x30} << 32) | graphics_cookie,
        reinterpret_cast<uint64_t>(host_registration.data()), 0, 0, 0});
    Check(FileSystem::KernelIoctl(io.main, 0x80308217u, io.At()) == KERNEL_ERROR_EFAULT,
          "DCE registration records must be owned guest input");
    Check(graphics_request(0x37, 0x30, 0) == OK &&
          graphics_request(0x37, 0x30, 0) == KERNEL_ERROR_EBUSY &&
          graphics_request(0x37, 0x30, 4) == KERNEL_ERROR_EINVAL,
          "DCE registers only guest backing in a supported free buffer slot");
    const std::array<uint64_t, 9> host_flip {};
    io.Put(0x500, uint64_t{0xa1b2c3d4e5f60718u});
    io.Put(0, std::array<uint64_t, 6>{0x36, (uint64_t{0x48} << 32) | graphics_cookie,
        reinterpret_cast<uint64_t>(host_flip.data()), 0,
        reinterpret_cast<uint64_t>(io.At(0x500)), 8});
    Check(FileSystem::KernelIoctl(io.main, 0x80308217u, io.At()) == KERNEL_ERROR_EFAULT &&
          io.Read<uint64_t>(0x500) == 0xa1b2c3d4e5f60718u,
          "DCE rejects a host flip record without acknowledging or submitting it");
    Check(client_request(io.main, 1, graphics_cookie) == OK && Both() == before_graphics,
          "DCE client close releases buffers while preserving the controller owner");
    Check(EQ::KernelDeleteEvent(flip_queue, flip_ident, EQ::KERNEL_EVFILT_VIDEO_OUT) == KERNEL_ERROR_ENOENT,
          "DCE client close removes its flip event registration");
    Check(EQ::KernelDeleteEqueue(flip_queue) == OK &&
          Memory::KernelMunmap(reinterpret_cast<uint64_t>(guest_surface), 0x7ec000) == OK,
          "DCE client does not take ownership of caller queue or pixel allocation");
    const int hdmi = FileSystem::KernelOpen("/dev/hdmi", 2, 0);
    const int scanin = FileSystem::KernelOpen("/dev/scanin", 2, 0);
    const int hmd = FileSystem::KernelOpen("/dev/hmd_cmd", 2, 0);
    Check(hdmi >= 3 && scanin >= 3 && !FileSystem::IsNativeAvProbeDescriptor(hdmi),
          "normal device resources are separate from legacy discovery");
    Check(hmd >= 3 && FileSystem::IsNativeAvDescriptor(hmd) &&
          !FileSystem::IsNativeAvProbeDescriptor(hmd),
          "HmdControl creates a normal device resource");
    Check(FileSystem::KernelOpen("/dev/hmd_cmd", 0, 0) == KERNEL_ERROR_EINVAL,
          "HmdControl resource rejects unsupported open access");
    const auto before_hmd = Both();
    io.Put(0, std::array<uint64_t, 2>{120000, reinterpret_cast<uint64_t>(io.At(0x300))});
    io.Put(0x300, uint32_t{0xa5a5a5a5u});
    Check(FileSystem::KernelIoctl(hmd, 0xc0109a0eu, io.At()) == KERNEL_ERROR_ENOTTY &&
          io.Read<uint32_t>(0x300) == 0xa5a5a5a5u && Both() == before_hmd,
          "HMD requests cannot program the AV clock or produce output");
    Check(FileSystem::KernelRead(hmd, io.At(), 80) == KERNEL_ERROR_ENODEV &&
          FileSystem::KernelPread(hmd, io.At(), 4, 0) == KERNEL_ERROR_ESPIPE &&
          FileSystem::KernelWrite(hmd, io.At(), 4) == KERNEL_ERROR_ENOSYS,
          "HMD descriptor generates no hardware traffic and reaches no host files");
    const auto hmd_closed = Libs::NativeKernelBridge::DispatchSyscall({0x06, {static_cast<uint64_t>(hmd)}});
    Check(hmd_closed.value == 0 && hmd_closed.posix_errno == 0 &&
          FileSystem::KernelIoctl(hmd, 0xc0109a0eu, io.At()) == KERNEL_ERROR_EBADF,
          "native HMD close releases only its own resource");
    std::memset(io.At(0x300), 0xa5, 32);
    io.Put(0, std::array<uint64_t, 3>{
        reinterpret_cast<uint64_t>(io.At(0x300)),
        reinterpret_cast<uint64_t>(io.At(0x301)),
        reinterpret_cast<uint64_t>(io.At(0x302))});
    Check(FileSystem::KernelIoctl(hdmi, 0xc0188d10u, io.At()) == KERNEL_ERROR_ENOTTY &&
          io.Read<uint32_t>(0x300) == 0xa5a5a5a5u,
          "unrecovered HDMI configuration is not replaced with placeholder device bytes");
    Check(FileSystem::KernelIoctl(hdmi, 0x20008d01u, nullptr) == KERNEL_ERROR_ENOTTY,
          "unimplemented HDMI initialization does not report success");
    Check(FileSystem::KernelIoctl(hdmi, 0xc0188d10u, reinterpret_cast<void*>(1)) == KERNEL_ERROR_EFAULT,
          "normal unknown ioctl tracing does not dereference invalid guest storage");
    Check(FileSystem::KernelRead(hdmi, io.At(), 80) == KERNEL_ERROR_ENODEV,
          "normal HDMI resource returns no receive data");
    Check(FileSystem::KernelPread(hdmi, io.At(), 4, 0) == KERNEL_ERROR_ESPIPE,
          "normal AV device is not a positioned host file");
    Check(FileSystem::KernelWrite(hdmi, io.At(), 4) == KERNEL_ERROR_ENOSYS,
          "unsupported normal device write cannot reach a host file");
    const int mbus = FileSystem::KernelOpen("/dev/mbus_av", 6, 0);
    Check(mbus >= 3 && FileSystem::KernelRead(mbus, io.At(), 80) == KERNEL_ERROR_EWOULDBLOCK,
          "AV programming does not inject an unrecovered MBus activation packet");
    Check(FileSystem::KernelClose(mbus) == OK && FileSystem::KernelClose(scanin) == OK,
          "normal AV fixture closes only its own resources");
    const auto closed = Libs::NativeKernelBridge::DispatchSyscall({0x06, {static_cast<uint64_t>(hdmi)}});
    Check(closed.value == 0 && closed.posix_errno == 0 &&
          FileSystem::KernelIoctl(hdmi, 0x20008d01u, nullptr) == KERNEL_ERROR_EBADF,
          "native close adapter releases the normal HDMI descriptor");
  }
  VO::VideoOutShutdown();
  std::printf("NativeAvDeviceTests: normal_clock=pass pending_mode=pass unknown_hdmi_preserved=pass no_mbus_injection=pass\n");
#endif
}
