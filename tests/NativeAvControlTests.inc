#if defined(_WIN32)
namespace NativeAvTest {
namespace Memory = Libs::LibKernel::Memory;
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
}
#else
#endif
