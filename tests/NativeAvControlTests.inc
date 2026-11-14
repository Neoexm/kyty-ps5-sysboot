#if defined(_WIN32)
extern "C" size_t KytyVideoOutSysSetModeRegistrationCountForTest(uint32_t head);
extern "C" size_t KytyVideoOutSysVblankRegistrationCountForTest(uint32_t head);

namespace NativeAvTest {

namespace VO = Libs::VideoOut;
namespace Memory = Libs::LibKernel::Memory;
namespace EQ = Libs::LibKernel::EventQueue;
using Snapshot = VO::VideoOutNativeControllerSnapshot;
using Clock = std::chrono::steady_clock;

constexpr std::array<const char*, 8> controls {
    "KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS",
    "KYTY_DIAGNOSTIC_SYSAV_AV_DEVICE_PROBE",
    "KYTY_DIAGNOSTIC_SYSAV_VIRTUAL_DISPCLK",
    "KYTY_DIAGNOSTIC_SYSAV_VIRTUAL_PIXEL_PLL",
    "KYTY_DIAGNOSTIC_SYSAV_VIRTUAL_OTG_TIMING",
    "KYTY_DIAGNOSTIC_SYSAV_VIRTUAL_OTG_CONTROL",
    "KYTY_DIAGNOSTIC_SYSAV_VIRTUAL_FORMAT_REGISTERS",
    "KYTY_DIAGNOSTIC_SYSAV_SPLASH_SHARE_DCE_HEAD",
};
constexpr std::array<uint32_t, 21> hdmi_start {
    0, 0, 0, 47, 59341, 4399, 2249, 3840, 2160, 0, 1, 1, 0, 0,
    0x426fc28f, 0, 24, 0x0bb50052, 0x200, 0, 0,
};
constexpr std::array<uint32_t, 21> hdmi_480_start {
    0, 0, 0, 0, 2700, 857, 524, 720, 480, 0, 0, 1, 0, 0,
    0x426fc28f, 0, 24, 0x0bb50024, 0x200, 0, 0,
};
constexpr std::array<uint32_t, 21> typec_start {
    1, 1, 0, 8, 14836, 2199, 1124, 1920, 1080, 0, 1, 14, 0, 0,
    0x426fc28f, 0, 30, 0x0bb50029, 32, 0, 0,
};
constexpr std::array<uint32_t, 16> hdmi_timing {
    59341, 4399, 4224, 384, 0, 88, 2249, 2242, 82, 0, 10,
    0x426fc28f, 0, 0, 0, 0,
};
constexpr std::array<uint32_t, 16> hdmi_480_timing {
    2700, 857, 842, 122, 0, 62, 524, 516, 36, 0, 6,
    0x426fc28f, 0, 0, 0, 0,
};
constexpr std::array<uint32_t, 16> typec_timing {
    14836, 2199, 2112, 192, 0, 44, 1124, 1121, 41, 0, 5,
    0x426fc28f, 0, 0, 0, 0,
};

class Environment {
public:
  Environment() {
    for (const char* key : controls) {
      Save(key);
      Set(key, key == controls.back() ? "" : "1");
    }
    for (const char* key : {
        "KYTY_DIAGNOSTIC_HOLD_FIRST_PRESENT",
        "KYTY_DIAGNOSTIC_SYSAV_FRAME_READBACK",
        "KYTY_DIAGNOSTIC_PRESENT_READBACK",
        "KYTY_DIAGNOSTIC_SYSTEM_BUS_TO_MAIN_LAYER"}) {
      Save(key);
      Set(key, "");
    }
  }
  ~Environment() {
    for (const auto& entry : saved) Set(entry.first.c_str(), entry.second.c_str());
  }
  static void Set(const char* key, const char* value) {
    Check(_putenv_s(key, value) == 0, "native AV fixture controls environment");
  }
private:
  void Save(const char* key) {
    const char* value = std::getenv(key);
    saved.emplace_back(key, value ? value : "");
  }
  std::vector<std::pair<std::string, std::string>> saved;
};

Snapshot Get(uint32_t selector) {
  Snapshot result;
  Check(VO::VideoOutNativeGetControllerSnapshot(selector, &result) == OK,
        "native AV reads selected controller snapshot");
  return result;
}

std::array<Snapshot, 2> Both() { return {Get(0), Get(1)}; }

class Requests {
public:
  Requests() {
    Check(Memory::KernelMapNamedFlexibleMemory(
        &memory, 0x8000, 3, 0, "native_av_fixture") == OK,
        "native AV maps guest request pages");
    av = FileSystem::KernelOpen("/dev/av_control", 2, 0);
    main = FileSystem::KernelOpen("/dev/dce", 2, 0);
    typec = FileSystem::KernelOpen("/dev/dce", 2, 0);
    finisher = FileSystem::KernelOpen("/dev/dce", 2, 0);
    Check(av >= 0 && main >= 0 && typec >= 0 && finisher >= 0,
          "native AV opens existing diagnostic device adapters");
  }
  ~Requests() {
    CloseDevices();
    Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), 0x8000) == OK,
          "native AV releases guest request pages");
  }
  uint8_t* At(size_t offset = 0) {
    return static_cast<uint8_t*>(memory) + offset;
  }
  template<class T> void Put(size_t offset, const T& value) {
    std::memcpy(At(offset), &value, sizeof(value));
  }
  template<class T> T Read(size_t offset) {
    T value;
    std::memcpy(&value, At(offset), sizeof(value));
    return value;
  }
  int Boolean(uint32_t ioctl, uint32_t selector, uint8_t enabled) {
    const std::array<uint32_t, 2> words {
        selector, 0xf0c3a500u | enabled};
    Put(0, words);
    return FileSystem::KernelIoctl(av, ioctl, At());
  }
  int Pair(uint32_t ioctl, uint32_t selector, uint32_t value) {
    Put(0, std::array<uint32_t, 2>{selector, value});
    return FileSystem::KernelIoctl(av, ioctl, At());
  }
  int DisplayClock(uint32_t value, void* output) {
    Put(0, std::array<uint64_t, 2>{
        (uint64_t{0xa5c3f00d} << 32) | value,
        reinterpret_cast<uint64_t>(output)});
    return FileSystem::KernelIoctl(av, 0xc0109a0eu, At());
  }
  int StartRecord(int fd, const std::array<uint32_t, 21>& record) {
    Put(0x100, record);
    Put(0, std::array<uint64_t, 4>{
        10, uint64_t{84} << 32, reinterpret_cast<uint64_t>(At(0x100)), 0});
    return FileSystem::KernelIoctl(fd, 0x80208218u, At());
  }
  int Start(uint32_t selector) {
    return StartRecord(selector == 0 ? main : typec,
                       selector == 0 ? hdmi_start : typec_start);
  }
  int FinishOn(int fd, uint32_t selector) {
    Put(0, std::array<uint32_t, 8>{11, selector, 0, 0, 0, 0, 0, 0});
    return FileSystem::KernelIoctl(fd, 0x80208218u, At());
  }
  int Finish(uint32_t selector) { return FinishOn(finisher, selector); }
  void MakeTiming(uint32_t selector) {
    Put(0x200, selector == 0 ? hdmi_timing : typec_timing);
    Put(0, std::array<uint64_t, 4>{
        (uint64_t{0xa5c3f00d} << 32) | selector,
        reinterpret_cast<uint64_t>(At(0x200)),
        selector == 0 ? 0x0000000100000001ull : 0x000000010000000eull, 0});
  }
  int Timing(uint32_t selector) {
    MakeTiming(selector);
    return FileSystem::KernelIoctl(av, 0xc0209a07u, At());
  }
  void Program(uint32_t selector) {
    Check(Boolean(0xc0089a04u, selector, 1) == OK,
          "native AV enables selected pending double buffer");
    Check(Boolean(0xc0089a05u, selector, 1) == OK,
          "native AV locks selected master update");
    Check(Pair(0xc0089a0du, selector, selector == 0 ? 5934066 : 1483516) == OK,
          "native AV programs full-width PPLL rate");
    Check(Timing(selector) == OK, "native AV supplies progressive OTG words");
    Check(Boolean(0xc0089a01u, selector, 1) == OK,
          "native AV enables selected pending OTG");
    Check(Boolean(0xc0089a05u, selector, 0) == OK,
          "native AV unlocks selected master update");
    Check(Pair(0xc0089a13u, selector, 0) == OK &&
          Pair(0xc0089a14u, selector, 0) == OK,
          "native AV supplies both selected format registers");
  }
  void ProtectSecondPage(int prot, DWORD expected) {
    Check(Memory::KernelMprotect(At(0x4000), 0x4000, prot) == OK,
          "native AV sets guest page protection");
    MEMORY_BASIC_INFORMATION info {};
    Check(VirtualQuery(At(0x4000), &info, sizeof(info)) == sizeof(info) &&
          (info.Protect & 0xff) == expected,
          "native AV verifies host page protection before invalid-span call");
  }
  void ReopenMain() {
    Check(main == -1, "native AV reopens only after owner close");
    main = FileSystem::KernelOpen("/dev/dce", 2, 0);
    Check(main >= 0, "native AV opens a fresh DCE owner");
  }
  void CloseDevices() {
    for (int* fd : {&main, &typec, &finisher, &av}) {
      if (*fd >= 0) {
        Check(FileSystem::KernelClose(*fd) == OK, "native AV closes fixture descriptor");
        *fd = -1;
      }
    }
  }
  int av = -1, main = -1, typec = -1, finisher = -1;
private:
  void* memory = nullptr;
};

uint64_t Count(int handle, bool system = false) {
  alignas(8) std::array<uint8_t, 40> storage {};
  auto* status = reinterpret_cast<VO::VideoOutVblankStatus*>(storage.data());
  Check((system ? VO::VideoOutSysGetVblankStatus2(handle, status) :
                  VO::VideoOutGetVblankStatus(handle, status)) == OK,
        "native AV reads scheduler vblank status");
  uint64_t count;
  std::memcpy(&count, storage.data(), sizeof(count));
  return count;
}

struct FlipStatus {
  uint64_t count;
  int64_t argument;
  int32_t pending;
};

FlipStatus Flip(int handle) {
  alignas(8) std::array<uint8_t, 0x80> storage {};
  Check(VO::VideoOutGetFlipStatus(
      handle, reinterpret_cast<VO::VideoOutFlipStatus*>(storage.data())) == OK,
      "native AV reads presentation completion status");
  FlipStatus result {};
  std::memcpy(&result.count, storage.data(), 8);
  std::memcpy(&result.argument, storage.data() + 24, 8);
  std::memcpy(&result.pending, storage.data() + 52, 4);
  return result;
}

class Events {
public:
  Events(int id, bool system, const char* name) : id(id), system(system) {
    Check(EQ::KernelCreateEqueue(&queue, name) == OK, "native AV creates event queue");
    if (system) {
      Check(VO::VideoOutSysAddVblankEvent2(queue, id, this) == OK &&
            VO::VideoOutSysAddSetModeEvent2(queue, id, this) == OK,
            "native AV registers system-head vblank and set-mode events");
    } else {
      Check(VO::VideoOutAddFlipEvent(queue, id, this) == OK &&
            VO::VideoOutAddVblankEvent(queue, id, this) == OK &&
            VO::VideoOutAddPreVblankStartEvent(queue, id, this) == OK &&
            VO::VideoOutAddSetModeEvent(queue, id, this) == OK,
            "native AV registers logical-output events");
    }
  }
  ~Events() { Close(); }
  void Close() {
    if (queue != 0) {
      Check(EQ::KernelDeleteEqueue(queue) == OK, "native AV deletes owned event queue");
      queue = 0;
    }
  }
  void Pump() {
    for (unsigned batch = 0; batch != 64; ++batch) {
      std::array<EQ::KernelEvent, 32> events {};
      int received = -1;
      const Libs::LibKernel::KernelUseconds zero = 0;
      const int rc = EQ::KernelWaitEqueue(
          queue, events.data(), static_cast<int>(events.size()), &received, &zero);
      if (rc == Libs::LibKernel::KERNEL_ERROR_ETIMEDOUT) {
        Check(received == 0, "native AV empty event poll returns zero records");
        return;
      }
      Check(rc == OK && received > 0 && received <= static_cast<int>(events.size()),
            "native AV event poll has valid bounded results");
      for (int i = 0; i != received; ++i) {
        const auto& event = events[i];
        Check(event.filter == EQ::KERNEL_EVFILT_VIDEO_OUT && event.udata == this,
              "native AV events retain exact filter and user data");
        if (system) {
          const uint64_t expected_vblank = (uint64_t{0x70} << 48) |
              (static_cast<uint64_t>(id) << 40) | 0x100000000ull;
          const uint64_t expected_set_mode = (uint64_t{0x73} << 48) |
              (static_cast<uint64_t>(id) << 40) | 0x100000000ull;
          Check(event.ident == expected_vblank || event.ident == expected_set_mode,
                "native AV system event retains exact type and head identity");
          if (event.ident == expected_vblank) {
            ++vblank;
          } else {
            ++set_mode;
          }
        } else if (event.ident == 0) {
          int64_t argument = 0;
          Check(VO::VideoOutGetEventData(&event, &argument) == OK,
                "native AV decodes flip completion payload");
          arguments.push_back(argument);
          ++flip;
        } else if (event.ident == 1) {
          ++vblank;
        } else if (event.ident == 2) {
          ++pre_vblank;
        } else {
          Check(event.ident == 0x10008, "native AV logical event retains exact SetMode identity");
          ++set_mode;
        }
      }
    }
    Check(false, "native AV event drain remains bounded");
  }
  bool Saw(int64_t argument) const {
    return std::find(arguments.begin(), arguments.end(), argument) != arguments.end();
  }
  uint64_t flip = 0, vblank = 0, pre_vblank = 0, set_mode = 0;
private:
  EQ::KernelEqueue queue = 0;
  int id;
  bool system;
  std::vector<int64_t> arguments;
};

void CheckSysSetModeEvents() {
  constexpr uintptr_t head0_ident = 0x0073000100000000ull;
  constexpr uintptr_t head1_ident = 0x0073010100000000ull;
  EQ::KernelEqueue head0_queue = EQ::KERNEL_EQUEUE_INVALID;
  EQ::KernelEqueue head1_queue = EQ::KERNEL_EQUEUE_INVALID;
  int head0_udata = 0;
  int head0_updated_udata = 0;
  int head1_udata = 0;

  Check(EQ::KernelCreateEqueue(&head0_queue, "native_av_setmode_head0") == OK &&
        EQ::KernelCreateEqueue(&head1_queue, "native_av_setmode_head1") == OK,
        "native AV creates dedicated system set-mode queues");
  Check(VO::VideoOutSysAddSetModeEvent2(head0_queue, 0, &head0_udata) == OK &&
        VO::VideoOutSysAddSetModeEvent2(head1_queue, 1, &head1_udata) == OK &&
        KytyVideoOutSysSetModeRegistrationCountForTest(0) == 1 &&
        KytyVideoOutSysSetModeRegistrationCountForTest(1) == 1,
        "native AV registers exact system set-mode heads");
  Check(VO::VideoOutSysAddSetModeEvent2(head0_queue, 2, nullptr) ==
            VO::VIDEO_OUT_ERROR_INVALID_VALUE,
        "native AV rejects system set-mode head two");

  auto expect_empty = [](EQ::KernelEqueue queue, const char* label) {
    EQ::KernelEvent event {};
    int received = -1;
    const Libs::LibKernel::KernelUseconds zero = 0;
    Check(EQ::KernelWaitEqueue(queue, &event, 1, &received, &zero) ==
              Libs::LibKernel::KERNEL_ERROR_ETIMEDOUT && received == 0,
          label);
  };
  expect_empty(head0_queue, "native AV system set-mode head zero starts silent");
  expect_empty(head1_queue, "native AV system set-mode head one starts silent");

  Check(VO::VideoOutSysAddSetModeEvent2(head0_queue, 0, &head0_updated_udata) == OK,
        "native AV updates duplicate system set-mode registration");
  Check(KytyVideoOutSysSetModeRegistrationCountForTest(0) == 1,
        "native AV duplicate system set-mode registration reuses tracked ownership");
  expect_empty(head0_queue, "native AV duplicate system set-mode registration stays silent");
  Check(EQ::KernelTriggerEvent(head0_queue, head0_ident, EQ::KERNEL_EVFILT_VIDEO_OUT,
                               nullptr) == OK &&
        EQ::KernelTriggerEvent(head1_queue, head0_ident, EQ::KERNEL_EVFILT_VIDEO_OUT,
                               nullptr) == Libs::LibKernel::KERNEL_ERROR_ENOENT,
        "native AV system set-mode identities remain isolated by head");

  auto expect_event = [](EQ::KernelEqueue queue, uintptr_t ident, void* udata,
                         const char* label) {
    EQ::KernelEvent event {};
    int received = -1;
    const Libs::LibKernel::KernelUseconds zero = 0;
    Check(EQ::KernelWaitEqueue(queue, &event, 1, &received, &zero) == OK && received == 1 &&
              event.ident == ident && event.filter == EQ::KERNEL_EVFILT_VIDEO_OUT &&
              event.flags == 0 && event.fflags == 0 && event.data == 0 && event.udata == udata,
          label);
  };
  expect_event(head0_queue, head0_ident, &head0_updated_udata,
               "native AV returns exact head-zero set-mode registration");
  expect_empty(head0_queue, "native AV consumes a system set-mode edge once");

  Check(EQ::KernelTriggerEvent(head1_queue, head1_ident, EQ::KERNEL_EVFILT_VIDEO_OUT,
                               nullptr) == OK,
        "native AV triggers the exact head-one system set-mode identity");
  expect_event(head1_queue, head1_ident, &head1_udata,
               "native AV returns exact head-one set-mode registration");
  expect_empty(head1_queue, "native AV consumes the head-one system set-mode edge once");

  auto retained_queue = EQ::KernelPinEqueue(head1_queue);
  Check(retained_queue != nullptr &&
        EQ::KernelTriggerEvent(head1_queue, head1_ident, EQ::KERNEL_EVFILT_VIDEO_OUT,
                               nullptr) == OK &&
        EQ::KernelDeleteEqueue(head1_queue) == OK,
        "native AV closes a pinned queue with a pending system set-mode edge");
  EQ::KernelEvent stale_event {};
  int stale_received = -1;
  const Libs::LibKernel::KernelUseconds zero = 0;
  Check(!EQ::KernelPinEqueue(head1_queue) &&
        KytyVideoOutSysSetModeRegistrationCountForTest(1) == 0 &&
        EQ::KernelTriggerEvent(head1_queue, head1_ident, EQ::KERNEL_EVFILT_VIDEO_OUT,
                               nullptr) == Libs::LibKernel::KERNEL_ERROR_EBADF &&
        EQ::KernelWaitEqueue(head1_queue, &stale_event, 1, &stale_received, &zero) ==
            Libs::LibKernel::KERNEL_ERROR_EBADF && stale_received == 0 &&
        VO::VideoOutSysAddSetModeEvent2(head1_queue, 1, &head1_udata) ==
            VO::VIDEO_OUT_ERROR_INVALID_EVENT_QUEUE,
        "native AV removes closed system set-mode queue registrations");
  retained_queue.reset();
  Check(EQ::KernelDeleteEqueue(head0_queue) == OK &&
        KytyVideoOutSysSetModeRegistrationCountForTest(0) == 0,
        "native AV deletes the remaining system set-mode queue");
}

template<class Predicate, class Pump>
void Wait(Predicate&& predicate, Pump&& pump, const char* label) {
  const auto deadline = Clock::now() + std::chrono::seconds(5);
  while (true) {
    pump();
    if (predicate()) return;
    Check(Clock::now() < deadline, label);
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
}

void DrainGpu(Libs::Graphics::RenderContext& renderer) {
  auto completion = std::async(std::launch::async, [&renderer] {
    renderer.GetGpu().WaitForIdle();
    renderer.GetGpu().SendCommandSync([&renderer] {
      auto& scheduler = renderer.GetCommandScheduler();
      Check(scheduler.Active(), "native AV preparation established an active GPU command context");
      scheduler.Finish();
    });
    renderer.GetCommandScheduler().DrainPriorityOperations();
  });
  Check(completion.wait_for(std::chrono::seconds(5)) == std::future_status::ready,
        "native AV guest/GPU preparation and completion drain is bounded");
  completion.get();
}

void Register(int handle, void* address, uint32_t width, uint32_t height) {
  alignas(8) std::array<uint8_t, 0x50> attribute {};
  alignas(8) std::array<const void*, 4> buffers {address, nullptr, nullptr, nullptr};
  auto* attr = reinterpret_cast<VO::VideoOutBufferAttribute2*>(attribute.data());
  VO::VideoOutSetBufferAttribute2(attr, 0x8000000000000000ull, 1, width, height, 0, 0, 0);
  Check(VO::VideoOutRegisterBuffers2(handle, 0, 0,
      reinterpret_cast<const VO::VideoOutBuffers*>(buffers.data()), 1, attr, 0, nullptr) == OK,
      "native AV registers a mapped linear framebuffer");
}

}

void CheckNativeAvControls(Libs::Graphics::WindowContext& graphics,
                           const Config::ConfigOptions& original_options) {
  using namespace NativeAvTest;
  using namespace Libs::LibKernel;
  Environment environment;
  auto options = original_options;
  options.vblank_frequency = 30;
  Config::Load(options);
  auto& driver = VO::VideoOutInit(64, 64, *graphics.presenter);
  auto& renderer = *graphics.render_context;
  renderer.InitializeGpu(&driver);
  CheckSysSetModeEvents();
  Requests io;
  const int sub = VO::VideoOutOpen(0, 2, 0, nullptr);
  Check(sub > 0, "native AV opens independent fallback SUB");
  const int overlay = VO::VideoOutOpen(0, 1, 0, nullptr);
  Check(overlay > 0 && overlay != sub, "native AV opens the supported OVERLAY presentation bus");
  Events sub_events(sub, false, "native_av_sub");
  Events overlay_events(overlay, false, "native_av_overlay");
  Events system0_events(0, true, "native_av_system0");
  Events system1_events(1, true, "native_av_system1");
  std::unique_ptr<Events> main_events;
  std::unique_ptr<Events> reopened_events;
  auto pump = [&] {
    sub_events.Pump();
    overlay_events.Pump();
    system0_events.Pump();
    system1_events.Pump();
    if (main_events) main_events->Pump();
    if (reopened_events) reopened_events->Pump();
  };
  auto sub_ticks = [&](uint64_t ticks) {
    const auto target = Count(sub) + ticks;
    Wait([&] { return Count(sub) >= target; }, pump,
         "native AV independent SUB clock continues within bound");
  };
  sub_ticks(3);
  const auto fallback_start = Clock::now();
  const auto fallback_count = Count(sub);
  const auto fallback_overlay_count = Count(overlay);
  sub_ticks(20);
  const double fallback_seconds =
      std::chrono::duration<double>(Clock::now() - fallback_start).count();
  const double fallback_rate = (Count(sub) - fallback_count) / fallback_seconds;
  const auto fallback_delta = Count(sub) - fallback_count;
  const auto fallback_overlay_delta = Count(overlay) - fallback_overlay_count;
  Check(fallback_rate > 18.0 && fallback_rate < 42.0 &&
        sub_events.vblank > 0 && sub_events.pre_vblank > 0 &&
        overlay_events.vblank > 0 && overlay_events.pre_vblank > 0 &&
        fallback_overlay_delta + 1 >= fallback_delta &&
        fallback_overlay_delta <= fallback_delta + 1 &&
        system0_events.vblank > 0 && system1_events.vblank > 0 &&
        system0_events.set_mode == 0 && system1_events.set_mode == 0,
        "native AV observes 30Hz fallback counters and correctly identified events");
  std::printf("NativeAvControlTests: fallback_sub_hz=%.3f overlay_ticks=%llu seconds=%.3f\n",
              fallback_rate, static_cast<unsigned long long>(fallback_overlay_delta),
              fallback_seconds);
  Check(VO::VideoOutConfigureOutput(sub, 1, nullptr, nullptr, 0) == OK,
        "native AV configures a logical SUB output mode");
  pump();
  Check(sub_events.set_mode == 1 && system0_events.set_mode == 0 &&
        system1_events.set_mode == 0,
        "native AV ConfigureOutput issues no system-head set-mode transition");

  Check(!Get(0).pending && !Get(0).committed && Get(0).bound_handle == -1 &&
        !Get(1).pending && !Get(1).committed && Get(1).bound_handle == -1,
        "native AV starts with two unbound unprogrammed controller records");
  auto before = Both();
  Check(FileSystem::KernelIoctl(io.av, 0xc0089a05u, nullptr) == KERNEL_ERROR_EFAULT &&
        Both() == before, "native AV rejects null envelope without register changes");
  io.Put(0x3ffc, std::array<uint32_t, 2>{0, 1});
  io.ProtectSecondPage(0, PAGE_NOACCESS);
  Check(FileSystem::KernelIoctl(io.av, 0xc0089a05u, io.At(0x3ffc)) ==
        KERNEL_ERROR_EFAULT && Both() == before,
        "native AV rejects an envelope crossing an inaccessible page atomically");
  io.ProtectSecondPage(3, PAGE_READWRITE);
  Check(io.Boolean(0xc0089a01u, 2, 0) == KERNEL_ERROR_EINVAL &&
        io.Boolean(0xc0089a01u, 0, 2) == KERNEL_ERROR_EINVAL &&
        io.Pair(0xc0089a0du, 0, 1) == KERNEL_ERROR_EINVAL &&
        Both() == before, "native AV rejects invalid selector Boolean and PPLL inputs");
  io.Put(0x4000, uint64_t{0x13579bdf2468ace0});
  io.ProtectSecondPage(1, PAGE_READONLY);
  Check(io.DisplayClock(120000, io.At(0x4000)) == KERNEL_ERROR_EFAULT &&
        Both() == before && io.Read<uint64_t>(0x4000) == 0x13579bdf2468ace0ull,
        "native AV validates the entire writable DISPCLK output before mutation");
  io.ProtectSecondPage(3, PAGE_READWRITE);
  io.Put(0x300, uint64_t{0x13579bdf2468ace0});
  Check(io.DisplayClock(120001, io.At(0x300)) == KERNEL_ERROR_EINVAL &&
        Both() == before && io.Read<uint64_t>(0x300) == 0x13579bdf2468ace0ull,
        "native AV unsupported DISPCLK leaves register state and output intact");
  Check(io.DisplayClock(120000, io.At(0x300)) == OK &&
        io.Read<uint32_t>(0x300) == 120000 &&
        io.Read<uint32_t>(0x304) == 0x13579bdf &&
        Get(0).display_clock_10khz == 120000 &&
        !Get(0).pending_timing.ppll_programmed && !Get(0).scanout_enabled,
        "native AV ignores DISPCLK ABI padding and writes exactly four output bytes");

  Check(io.Boolean(0xc0089a01u, 0, 0) == OK,
        "native AV accepts pre-START OTG disable with nonzero padding");
  before = Both();
  auto invalid_start = hdmi_start;
  invalid_start[0] = 2;
  Check(io.StartRecord(io.main, invalid_start) == KERNEL_ERROR_EINVAL && Both() == before,
        "native AV malformed DCE selector does not acquire or program MAIN");
  Check(io.StartRecord(io.main, hdmi_480_start) == OK &&
        Get(0).pending_timing.width == 720 && Get(0).pending_timing.height == 480 &&
        Get(0).pending_timing.h_total == 858 && Get(0).pending_timing.v_total == 525 &&
        Get(0).pending_timing.pixel_clock_10khz == 2700,
        "native AV stages the exact 480p DCE timing record");
  before = Both();
  auto invalid_480 = hdmi_480_start;
  invalid_480[10] = 1;
  Check(io.StartRecord(io.main, invalid_480) == KERNEL_ERROR_EINVAL && Both() == before,
        "native AV rejects a modified 480p DCE timing record atomically");
  Check(io.Boolean(0xc0089a05u, 0, 1) == OK &&
        io.Pair(0xc0089a0du, 0, 5934066) == KERNEL_ERROR_EINVAL &&
        io.Pair(0xc0089a0du, 0, 270000) == OK,
        "native AV binds the 480p PPLL rate to its pending mode");
  io.Put(0x200, hdmi_480_timing);
  io.Put(0, std::array<uint64_t, 4>{
      uint64_t{0xa5c3f00d} << 32, reinterpret_cast<uint64_t>(io.At(0x200)),
	  1, 0});
  Check(FileSystem::KernelIoctl(io.av, 0xc0209a07u, io.At()) == OK &&
        Get(0).pending_timing.otg_timing == hdmi_480_timing &&
        io.Boolean(0xc0089a05u, 0, 0) == OK,
        "native AV programs the firmware 480p OTG table before replacing the pending mode");
  Check(io.Start(0) == OK, "native AV unchanged HDMI START acquires MAIN");
  const int main = Get(0).bound_handle;
  const auto first_generation = Get(0).bound_generation;
  Check(main > 0 && main != sub && main != overlay &&
        first_generation != 0 && Get(0).pending &&
        !Get(0).committed && !Get(0).scanout_enabled && Count(main) == 0,
        "native AV pending HDMI owns a distinct generation with scanout suppressed");
  main_events = std::make_unique<Events>(main, false, "native_av_main");
  sub_ticks(2);
  pump();
  const auto pending_main_count = Count(main);
  const auto pending_system0_count = Count(0, true);
  const auto pending_main_events = main_events->vblank;
  const auto pending_system0_events = system0_events.vblank;
  const auto pending_system1_count = Count(1, true);
  sub_ticks(6);
  Check(Count(main) == pending_main_count && Count(0, true) == pending_system0_count &&
        main_events->vblank == pending_main_events &&
        system0_events.vblank == pending_system0_events &&
        Count(1, true) > pending_system1_count && main_events->set_mode == 0,
        "native AV pending MAIN and system head0 stay silent while SUB and head1 run");

  const auto hdmi_pending = Get(0);
  Check(io.Start(1) == OK, "native AV TYPE_C START creates an independent pending record");
  io.Program(1);
  Check(Get(0) == hdmi_pending && Get(1).bound_handle == -1 &&
        Get(1).pending_timing.ppll_rate_100hz == 1483516 &&
        Get(1).pending_timing.otg_timing == typec_timing,
        "native AV TYPE_C full-width registers do not replace HDMI timing or binding");
  before = Both();
  Check(io.Finish(1) == KERNEL_ERROR_EOPNOTSUPP && Both() == before,
        "native AV unbound TYPE_C FINISH explicitly remains unsupported");
  pump();
  Check(main_events->set_mode == 0 && Count(main) == pending_main_count,
        "native AV TYPE_C FINISH emits no HDMI completion or fallback tick");

  Check(io.Boolean(0xc0089a04u, 0, 1) == OK &&
        io.Boolean(0xc0089a05u, 0, 1) == OK &&
        Get(0).master_locked && !Get(0).pending_timing.ppll_programmed,
        "native AV 9A05 changes master lock and never masquerades as PPLL");
  before = Both();
  Check(io.Boolean(0xc0089a05u, 0, 1) == OK && Both() == before,
        "native AV repeated master-lock register write is idempotent");
  io.Put(0x4000, std::array<uint32_t, 2>{0, 0xe2d4c601});
  io.ProtectSecondPage(1, PAGE_READONLY);
  Check(FileSystem::KernelIoctl(io.av, 0xc0089a05u, io.At(0x4000)) == OK &&
        Both() == before && io.Read<uint32_t>(0x4004) == 0xe2d4c601,
        "native AV master lock accepts read-only input and ignores three padding bytes");
  io.ProtectSecondPage(3, PAGE_READWRITE);
  Check(io.Finish(0) == KERNEL_ERROR_EINVAL && Both() == before,
        "native AV incomplete locked HDMI FINISH is atomic");
  for (size_t i = 2; i != 7; ++i) Environment::Set(controls[i], "");
  Check(io.Finish(0) == KERNEL_ERROR_EINVAL && Both() == before,
        "native AV missing diagnostic flags cannot waive pending timing prerequisites");
  for (size_t i = 2; i != 7; ++i) Environment::Set(controls[i], "1");
  Check(io.Pair(0xc0089a0du, 0, 5934066) == OK &&
        Get(0).pending_timing.ppll_rate_100hz == 5934066 &&
        Get(0).pending_timing.ppll_programmed,
        "native AV 9A0D consumes the full 32-bit PPLL rate");
  before = Both();
  Check(io.Pair(0xc0089a0du, 0, 0xffffffffu) == KERNEL_ERROR_EINVAL &&
        Both() == before, "native AV unsupported PPLL preserves previously staged timing");
  io.MakeTiming(0);
  io.Put(8, reinterpret_cast<uint64_t>(io.At(0x4000)));
  io.ProtectSecondPage(0, PAGE_NOACCESS);
  Check(FileSystem::KernelIoctl(io.av, 0xc0209a07u, io.At()) == KERNEL_ERROR_EFAULT &&
        Both() == before, "native AV rejects inaccessible nested timing before state changes");
  io.ProtectSecondPage(3, PAGE_READWRITE);
  io.MakeTiming(0);
  io.Put(16, uint32_t{2});
  Check(FileSystem::KernelIoctl(io.av, 0xc0209a07u, io.At()) == KERNEL_ERROR_EINVAL &&
        Both() == before, "native AV rejects unmatched OTG control fields atomically");
  io.MakeTiming(0);
  io.Put(0x200 + 4, uint32_t{4398});
  Check(FileSystem::KernelIoctl(io.av, 0xc0209a07u, io.At()) == KERNEL_ERROR_EINVAL &&
        Both() == before, "native AV rejects OTG totals inconsistent with pending START");
  Check(io.Timing(0) == OK && Get(0).pending_timing.otg_timing == hdmi_timing &&
        io.Boolean(0xc0089a01u, 0, 1) == OK &&
        io.Boolean(0xc0089a05u, 0, 0) == OK,
        "native AV stages padded OTG request and unlocks master update");
  before = Both();
  Check(io.Finish(0) == KERNEL_ERROR_EINVAL && Both() == before,
        "native AV missing format registers prevent completion");
  Check(io.Pair(0xc0089a13u, 0, 0) == OK, "native AV writes current pixel encoding");
  before = Both();
  Check(io.Finish(0) == KERNEL_ERROR_EINVAL && Both() == before &&
        io.Pair(0xc0089a14u, 0, 0x100) == KERNEL_ERROR_EINVAL && Both() == before,
        "native AV requires subsampling and rejects nonzero full-width format value");
  Check(io.Pair(0xc0089a14u, 0, 0) == OK &&
        io.Boolean(0xc0089a05u, 0, 1) == OK,
        "native AV completes format fields and explicitly relocks");
  before = Both();
  Check(io.Finish(0) == KERNEL_ERROR_EINVAL && Both() == before,
        "native AV fully programmed but master-locked FINISH does not commit");
  Check(io.Boolean(0xc0089a05u, 0, 0) == OK, "native AV releases final update lock");
  before = Both();
  io.Put(0, std::array<uint32_t, 8>{11, 0, 0, 0, 0, 0, 0, 1});
  Check(FileSystem::KernelIoctl(io.finisher, 0x80208218u, io.At()) ==
        KERNEL_ERROR_EINVAL && Both() == before,
        "native AV malformed FINISH tail preserves ready pending transaction");
  Check(io.Finish(0) == OK, "native AV separate descriptor FINISH commits HDMI timing");
  const auto committed = Get(0);
  Check(committed.committed && !committed.pending && committed.scanout_enabled &&
        committed.bound_handle == main && committed.bound_generation == first_generation &&
        committed.committed_timing.width == 3840 && committed.committed_timing.height == 2160 &&
        committed.committed_timing.h_total == 4400 && committed.committed_timing.v_total == 2250 &&
        committed.committed_timing.ppll_rate_100hz == 5934066 &&
        committed.committed_timing.refresh_hz > 59.93f &&
        committed.committed_timing.refresh_hz < 59.95f,
        "native AV commits verified progressive PPLL timing to its live HDMI binding");
  Wait([&] { return main_events->set_mode == 1; }, pump,
       "native AV successful HDMI FINISH emits one SetMode event");
  Check(system0_events.set_mode == 0 && system1_events.set_mode == 0,
        "native AV HDMI programming issues no system-head set-mode transition");
  before = Both();
  Check(io.Finish(0) == KERNEL_ERROR_EINVAL && Both() == before,
        "native AV duplicate FINISH cannot recommit a consumed transaction");

  sub_ticks(2);
  const auto native_start_time = Clock::now();
  const auto native_main_start = Count(main);
  const auto native_sub_start = Count(sub);
  const auto native_overlay_start = Count(overlay);
  const auto native_system0_start = Count(0, true);
  const auto native_system1_start = Count(1, true);
  Wait([&] { return Count(main) >= native_main_start + 24; }, pump,
       "native AV committed native scanout produces vblanks");
  const double native_seconds =
      std::chrono::duration<double>(Clock::now() - native_start_time).count();
  const auto main_delta = Count(main) - native_main_start;
  const auto sub_delta = Count(sub) - native_sub_start;
  const auto overlay_delta = Count(overlay) - native_overlay_start;
  const auto system0_delta = Count(0, true) - native_system0_start;
  const auto system1_delta = Count(1, true) - native_system1_start;
  const double native_rate = main_delta / native_seconds;
  Check(native_rate > 45.0 && native_rate < 80.0 && sub_delta > 0 &&
        main_delta > sub_delta * 1.5 && main_delta < sub_delta * 2.5 &&
        overlay_delta + 1 >= sub_delta && overlay_delta <= sub_delta + 1 &&
        system0_delta + 1 >= main_delta && system0_delta <= main_delta + 1 &&
        system1_delta + 1 >= sub_delta && system1_delta <= sub_delta + 1 &&
        main_events->vblank > 0 && main_events->pre_vblank > 0 &&
        main_events->set_mode == 1,
        "native AV HDMI/head0 cadence follows PPLL while SUB/OVERLAY/head1 retain fallback");
  std::printf("NativeAvControlTests: native_main_hz=%.3f main=%llu sub=%llu overlay=%llu "
              "system0=%llu system1=%llu seconds=%.3f\n", native_rate,
              static_cast<unsigned long long>(main_delta),
              static_cast<unsigned long long>(sub_delta),
              static_cast<unsigned long long>(overlay_delta),
              static_cast<unsigned long long>(system0_delta),
              static_cast<unsigned long long>(system1_delta), native_seconds);
  const auto hdmi_live = Get(0);
  Check(io.Start(1) == OK, "native AV restages independent TYPE_C while HDMI scans out");
  io.Program(1);
  before = Both();
  Check(io.Finish(1) == KERNEL_ERROR_EOPNOTSUPP && Both() == before &&
        Get(0) == hdmi_live, "native AV TYPE_C programming cannot overwrite active HDMI");
  sub_ticks(3);
  Check(main_events->set_mode == 1 && system0_events.set_mode == 0 &&
        system1_events.set_mode == 0,
        "native AV TYPE_C produces no unrelated SetMode event");

  Check(io.Boolean(0xc0089a01u, 0, 0) == OK && !Get(0).scanout_enabled,
        "native AV committed OTG disable has a scanout effect");
  sub_ticks(2);
  pump();
  auto stopped_main = Count(main);
  auto stopped_system0 = Count(0, true);
  auto stopped_events = main_events->vblank;
  auto stopped_system_events = system0_events.vblank;
  auto continued_system1 = Count(1, true);
  sub_ticks(6);
  Check(Count(main) == stopped_main && Count(0, true) == stopped_system0 &&
        main_events->vblank == stopped_events &&
        system0_events.vblank == stopped_system_events &&
        Count(1, true) > continued_system1,
        "native AV disabled MAIN/head0 suppress counts and events while other clocks progress");
  const auto disabled = Get(0);
  Check(io.Boolean(0xc0089a01u, 0, 1) == OK && Get(0).scanout_enabled &&
        Get(0).committed_timing == committed.committed_timing &&
        Get(0).timing_generation == disabled.timing_generation + 1,
        "native AV direct OTG re-enable resumes only its valid committed mode");
  before = Both();
  Check(io.Boolean(0xc0089a01u, 0, 1) == OK && Both() == before,
        "native AV repeated OTG enable does not create another timing generation");
  sub_ticks(4);
  Check(Count(main) > stopped_main && main_events->set_mode == 1,
        "native AV direct resume advances scanout without a SetMode event");

  constexpr std::array<uint64_t, 12> splash_attributes {
      0, 0x8000000000000000ull, 0x0000078000000000ull, 0x0000043800000780ull,
      0xffffffff00000000ull, 0x00000000ffffffffull, 0x8000000000000000ull, 0, 0, 0, 0, 0};
  Check(VO::VideoOutNativeConfigureSplashAttributes(
      splash_attributes.data(), splash_attributes.size()) == OK,
      "native AV 1080 buffer layout remains independent of the committed 4K signal");
  constexpr size_t allocation_size = 0x804000;
  int64_t direct_offset = -1;
  Check(Memory::KernelAllocateDirectMemory(0, Memory::KernelGetDirectMemorySize(),
      allocation_size, 0x4000, 0, &direct_offset) == OK,
      "native AV allocates framebuffer backing");
  void* pixels = nullptr;
  Check(Memory::KernelMapDirectMemory(
      &pixels, allocation_size, 3, 0, direct_offset, 0x4000) == OK,
      "native AV maps framebuffer backing");
  std::memset(pixels, 0x39, 0x800000);
  auto* overlay_pixels = static_cast<uint8_t*>(pixels) + 0x800000;
  std::fill_n(reinterpret_cast<uint32_t*>(overlay_pixels), 64 * 64, 0xffc7a539u);
  renderer.MapMemory(reinterpret_cast<uint64_t>(pixels), allocation_size);
  Register(main, pixels, 1920, 1080);
  Register(overlay, overlay_pixels, 64, 64);
  Check(io.Boolean(0xc0089a01u, 0, 0) == OK,
        "native AV disables MAIN before a two-owner queue test");
  sub_ticks(2);
  pump();
  stopped_main = Count(main);
  stopped_system0 = Count(0, true);
  stopped_events = main_events->vblank;
  stopped_system_events = system0_events.vblank;
  Check(VO::VideoOutSubmitFlip(main, 0, 1, 0x1101) == OK,
        "native AV queues a MAIN surface while its scanout is disabled");
  DrainGpu(renderer);
  Check(Flip(main).pending == 1 && Flip(main).count == 0,
        "native AV disabled MAIN retains its prepared GPU-backed flip");
  Check(VO::VideoOutSubmitFlip(overlay, 0, 1, 0x2201) == OK,
        "native AV queues an independent OVERLAY behind the prepared disabled MAIN");
  DrainGpu(renderer);
  Wait([&] { return Flip(overlay).count == 1 && overlay_events.Saw(0x2201); }, pump,
       "native AV independent ready OVERLAY passes a disabled ready MAIN in the queue");
  Check(Flip(overlay).argument == 0x2201 && Flip(overlay).pending == 0 &&
        Flip(main).count == 0 && Flip(main).pending == 1 &&
        Count(main) == stopped_main && Count(0, true) == stopped_system0 &&
        main_events->vblank == stopped_events &&
        system0_events.vblank == stopped_system_events && main_events->flip == 0,
        "native AV OVERLAY presentation progresses without consuming paused MAIN");

  const auto previous_transaction = Get(0).transaction_id;
  const auto previous_committed = Get(0).committed_timing;
  Check(io.Start(0) == OK && Get(0).pending && !Get(0).scanout_enabled &&
        Get(0).transaction_id != previous_transaction &&
        !Get(0).pending_timing.ppll_programmed &&
        !Get(0).pending_timing.timing_programmed &&
        !Get(0).pending_timing.pixel_encoding_programmed &&
        !Get(0).pending_timing.subsampling_programmed &&
        Get(0).committed_timing == previous_committed,
        "native AV fresh START retains historical commit but requires new register inputs");
  before = Both();
  Check(io.Finish(0) == KERNEL_ERROR_EINVAL && Both() == before,
        "native AV fresh FINISH cannot reuse previous transaction prerequisites");
  Check(VO::VideoOutSubmitFlip(overlay, 0, 1, 0x2202) == OK,
        "native AV queues another independent OVERLAY during pending MAIN programming");
  DrainGpu(renderer);
  Wait([&] { return Flip(overlay).count == 2 && overlay_events.Saw(0x2202); }, pump,
       "native AV pending MAIN does not starve an independent OVERLAY");
  Check(Count(main) == stopped_main && Count(0, true) == stopped_system0 &&
        Flip(main).pending == 1 && Flip(main).count == 0,
        "native AV pending transaction cannot fall back to default ticks or present");
  io.Program(0);
  const auto resume_time = Clock::now();
  const auto resume_count = Count(main);
  Check(io.Finish(0) == OK, "native AV fresh fully programmed transaction resumes HDMI");
  Wait([&] { return Flip(main).count == 1 && main_events->Saw(0x1101); }, pump,
       "native AV resumed MAIN presents its retained framebuffer");
  sub_ticks(6);
  const double resumed_seconds =
      std::chrono::duration<double>(Clock::now() - resume_time).count();
  Check(Flip(main).argument == 0x1101 && Flip(main).pending == 0 &&
        main_events->set_mode == 2 &&
        Count(main) - resume_count <= static_cast<uint64_t>(resumed_seconds * 90.0) + 4,
        "native AV resume has one completion and no accumulated paused-tick burst");
  std::printf("NativeAvControlTests: independent_owner_progress main_arg=0x1101 "
              "overlay_args=0x2201,0x2202 paused_main_events=0\n");

  Check(io.Boolean(0xc0089a01u, 0, 0) == OK &&
        VO::VideoOutSubmitFlip(main, 0, 1, 0x1102) == OK,
        "native AV prepares a pending frame for generation-close cancellation");
  DrainGpu(renderer);
  Check(Flip(main).pending == 1, "native AV old generation owns the pending frame");
  const int stale_fd = io.main;
  Check(VO::VideoOutClose(main) == OK,
        "native AV closes MAIN while retaining the old native descriptor");
  io.main = -1;
  Check(Get(0).bound_handle == -1 && !Get(0).pending && !Get(0).scanout_enabled,
        "native AV MAIN close invalidates controller binding and pending scanout");
  sub_ticks(2);
  pump();
  const auto old_event_vblank = main_events->vblank;
  const auto old_event_flip = main_events->flip;
  const auto old_event_mode = main_events->set_mode;
  const auto restored_head0 = Count(0, true);
  sub_ticks(4);
  Check(Count(0, true) > restored_head0 && !main_events->Saw(0x1102),
        "native AV closing MAIN restores system-head0 fallback and cancels its old frame");
  io.ReopenMain();
  Check(io.Start(0) == OK, "native AV fresh owner acquires a new MAIN generation");
  const int reopened_main = Get(0).bound_handle;
  Check(reopened_main > 0 && Get(0).bound_generation != first_generation &&
        Flip(reopened_main).count == 0 && Flip(reopened_main).pending == 0,
        "native AV reopened MAIN inherits no prior generation flip completion or request");
  reopened_events = std::make_unique<Events>(reopened_main, false, "native_av_reopened");
  before = Both();
  Check(io.StartRecord(stale_fd, hdmi_start) == KERNEL_ERROR_EINVAL && Both() == before,
        "native AV stale DCE START cannot mutate another MAIN generation");
  io.Program(0);
  before = Both();
  Check(io.FinishOn(stale_fd, 0) == KERNEL_ERROR_EINVAL && Both() == before,
        "native AV stale DCE FINISH cannot publish a fully prepared new transaction");
  Check(FileSystem::KernelClose(stale_fd) == OK && Both() == before &&
        Count(reopened_main) == 0,
        "native AV stale descriptor close leaves the new MAIN generation alive");
  Check(io.Finish(0) == OK, "native AV unbound finisher commits the current live generation");
  sub_ticks(4);
  Check(reopened_events->set_mode == 1 && Count(reopened_main) > 0 &&
        Flip(reopened_main).count == 0 && Flip(reopened_main).pending == 0 &&
        main_events->vblank == old_event_vblank &&
        main_events->flip == old_event_flip && main_events->set_mode == old_event_mode,
        "native AV old-generation registrations receive no new-generation events");
  Register(reopened_main, pixels, 1920, 1080);
  Check(io.Boolean(0xc0089a01u, 0, 0) == OK,
        "native AV pauses the replacement generation for stale-client cancellation checks");
  Check(VO::VideoOutSubmitFlip(reopened_main, 0, 1, 0x3301) == OK,
        "native AV new generation accepts its own framebuffer");
  DrainGpu(renderer);
  before = Both();
  int stale_client_handle = reopened_main;
  VO::VideoOutNativeReleaseClientHandle(&stale_client_handle, first_generation);
  Check(stale_client_handle == -1 && Both() == before &&
        Flip(reopened_main).pending == 1 && Flip(reopened_main).count == 0,
        "native AV stale client release preserves replacement-generation requests and counters");
  EQ::KernelEqueue stale_client_queue = EQ::KERNEL_EQUEUE_INVALID;
  constexpr uint64_t native_flip_ident = 0x0006010000000000ull;
  Check(EQ::KernelCreateEqueue(&stale_client_queue, "native_av_stale_client") == OK &&
        VO::VideoOutNativeRegisterOriginalSplashFlipEvent(stale_client_queue, native_flip_ident,
            reopened_main, first_generation) != OK &&
        EQ::KernelDeleteEvent(stale_client_queue, native_flip_ident, EQ::KERNEL_EVFILT_VIDEO_OUT) ==
            KERNEL_ERROR_ENOENT &&
        EQ::KernelDeleteEqueue(stale_client_queue) == OK && Both() == before &&
        Flip(reopened_main).pending == 1,
        "native AV stale event attachment cannot bind a replacement head or cancel its work");
  Check(io.Boolean(0xc0089a01u, 0, 1) == OK,
        "native AV resumes the preserved replacement-generation request");
  Wait([&] { return Flip(reopened_main).count == 1 && reopened_events->Saw(0x3301); }, pump,
       "native AV reopened generation completes its own GPU-backed presentation");
  Check(VO::VideoOutSetFlipMaster(overlay, reopened_main) == OK,
        "native AV binds fallback OVERLAY as a slave of native MAIN");
  const auto group_main_start = Flip(reopened_main).count;
  const auto group_overlay_start = Flip(overlay).count;
  Check(VO::VideoOutSubmitFlip(overlay, 0, 8, 0x4402) == OK,
        "native AV queues the OVERLAY slave surface before its owner");
  DrainGpu(renderer);
  Check(Flip(overlay).count == group_overlay_start && Flip(overlay).pending == 1,
        "native AV an unclaimed slave surface does not present independently");
  Check(VO::VideoOutSubmitFlip(reopened_main, 0, 9, 0x4401) == OK,
        "native AV queues the MAIN owner to capture the prepared OVERLAY surface");
  DrainGpu(renderer);
  Wait([&] {
    const auto primary = Flip(reopened_main);
    if (primary.count == group_main_start) return false;
    const auto secondary = Flip(overlay);
    Check(primary.count == group_main_start + 1 && secondary.count == group_overlay_start + 1 &&
          primary.argument == 0x4401 && secondary.argument == 0x4402 &&
          primary.pending == 0 && secondary.pending == 0,
          "native AV group publishes both completions atomically across unequal head rates");
    return reopened_events->Saw(0x4401) && overlay_events.Saw(0x4402);
  }, pump, "native AV MAIN-owned group progresses without slave timer phase coupling");
  Check(!main_events->Saw(0x1102) && main_events->flip == old_event_flip,
        "native AV cancelled old generation never emits a late flip completion");
  std::printf("NativeAvControlTests: generation_isolation=pass stale_dce=pass "
              "group_main_arg=0x4401 group_overlay_arg=0x4402\n");

  DrainGpu(renderer);
  Check(VO::VideoOutClose(overlay) == OK, "native AV closes drained OVERLAY group slave");
  Environment::Set(controls.back(), "1");
  const auto leased_controller = Get(0);
  const auto lease_mode_events = reopened_events->set_mode;
  const int shared_main = VO::VideoOutOpen(0, 0, 0, nullptr);
  Check(shared_main == reopened_main && Get(0) == leased_controller,
        "native AV existing DCE-to-splash sharing acquires the live MAIN lease");
  Check(FileSystem::KernelClose(io.main) == OK,
        "native AV closes the native owner after acquiring a user lease");
  io.main = -1;
  Check(Get(0) == leased_controller,
        "native AV DCE-to-splash transfer retains binding generation and committed timing");
  const auto lease_count = Count(shared_main);
  Wait([&] { return Count(shared_main) >= lease_count + 2; }, pump,
       "native AV transferred MAIN lease keeps its scanout running");
  Check(reopened_events->set_mode == lease_mode_events &&
        Get(0) == leased_controller,
        "native AV lease transfer produces no SetMode or timing generation");
  Check(VO::VideoOutClose(shared_main) == OK && Get(0).bound_handle == -1 &&
        !Get(0).scanout_enabled,
        "native AV last user lease close invalidates the live controller binding");
  pump();
  Check(system0_events.set_mode == 0 && system1_events.set_mode == 0,
        "native AV keeps both system set-mode heads silent through the full controller flow");
  reopened_events->Close();
  main_events->Close();
  sub_events.Close();
  overlay_events.Close();
  system0_events.Close();
  system1_events.Close();
  Check(KytyVideoOutSysSetModeRegistrationCountForTest(0) == 0 &&
        KytyVideoOutSysSetModeRegistrationCountForTest(1) == 0 &&
        KytyVideoOutSysVblankRegistrationCountForTest(0) == 0 &&
        KytyVideoOutSysVblankRegistrationCountForTest(1) == 0,
        "native AV queue close drains both system event kinds from both heads");
  Check(VO::VideoOutClose(sub) == OK, "native AV closes the SUB cadence observer");
  io.CloseDevices();
  renderer.UnmapMemory(reinterpret_cast<uint64_t>(pixels), allocation_size);
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(pixels), allocation_size) == OK &&
        Memory::KernelReleaseDirectMemory(direct_offset, allocation_size) == OK,
        "native AV releases framebuffer mappings and backing");
  EQ::KernelEqueue reinit_queue = EQ::KERNEL_EQUEUE_INVALID;
  int old_reinit_udata = 0;
  Check(EQ::KernelCreateEqueue(&reinit_queue, "native_av_system_reinit") == OK &&
        VO::VideoOutSysAddVblankEvent2(reinit_queue, 0, &old_reinit_udata) == OK &&
        VO::VideoOutSysAddSetModeEvent2(reinit_queue, 0, &old_reinit_udata) == OK &&
        KytyVideoOutSysVblankRegistrationCountForTest(0) == 1 &&
        KytyVideoOutSysSetModeRegistrationCountForTest(0) == 1,
        "native AV keeps both system event kinds live for shutdown ownership testing");
  renderer.ShutdownGpu();
  VO::VideoOutShutdown();
  constexpr uintptr_t sys_vblank_head0 = 0x0070000100000000ull;
  constexpr uintptr_t sys_set_mode_head0 = 0x0073000100000000ull;
  EQ::KernelEvent detached_event {};
  int detached_received = -1;
  const Libs::LibKernel::KernelUseconds zero = 0;
  Check(EQ::KernelTriggerEvent(reinit_queue, sys_vblank_head0,
                               EQ::KERNEL_EVFILT_VIDEO_OUT, nullptr) ==
            Libs::LibKernel::KERNEL_ERROR_ENOENT &&
        EQ::KernelTriggerEvent(reinit_queue, sys_set_mode_head0,
                               EQ::KERNEL_EVFILT_VIDEO_OUT, nullptr) ==
            Libs::LibKernel::KERNEL_ERROR_ENOENT &&
        VO::VideoOutSysAddSetModeEvent2(reinit_queue, 0, nullptr) ==
            VO::VIDEO_OUT_ERROR_FATAL &&
        EQ::KernelWaitEqueue(reinit_queue, &detached_event, 1, &detached_received, &zero) ==
            Libs::LibKernel::KERNEL_ERROR_ETIMEDOUT && detached_received == 0,
        "native AV shutdown detaches both system event kinds and registration fails closed");
  static_cast<void>(VO::VideoOutInit(64, 64, *graphics.presenter));
  int new_reinit_udata = 0;
  Check(VO::VideoOutSysAddVblankEvent2(reinit_queue, 0, &new_reinit_udata) == OK &&
        VO::VideoOutSysAddSetModeEvent2(reinit_queue, 0, &new_reinit_udata) == OK &&
        KytyVideoOutSysVblankRegistrationCountForTest(0) == 1 &&
        KytyVideoOutSysSetModeRegistrationCountForTest(0) == 1,
        "native AV reinitialization owns same-head registrations on the live queue");
  Check(EQ::KernelDeleteEqueue(reinit_queue) == OK &&
        KytyVideoOutSysVblankRegistrationCountForTest(0) == 0 &&
        KytyVideoOutSysSetModeRegistrationCountForTest(0) == 0,
        "native AV close drains reinitialized system registration ownership");
  VO::VideoOutShutdown();
  Config::Load(original_options);
  std::printf("NativeAvControlTests: mapped_ioctl_rollback=pass controller_isolation=pass "
              "scheduler=pass gpu_flips=pass diagnostic_HDMI_binding_only=1\n");
}
#else
void CheckNativeAvControls(Libs::Graphics::WindowContext&,
                           const Config::ConfigOptions&) {}
#endif
