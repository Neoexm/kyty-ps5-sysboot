void CheckSysmoduleDependencies(const std::filesystem::path& root) {
  using namespace Libs::LibKernel;
  const auto directory = root / "sysmodule_dependencies";
  Check(std::filesystem::create_directory(directory), "create sysmodule dependency fixture");
  Check(FileSystem::GetRealFilename("/system/common/lib").empty(),
        "dependency fixture does not shadow original libraries");
  FileSystem::MountReadOnly(directory, "/system/common/lib");

  Loader::SymbolDatabase symbols;
  Libs::InitSysmodule_1(&symbols);
  const auto* load_symbol = symbols.FindByNid("39iV5E1HoCk", Loader::SymbolType::Func);
  const auto* find_symbol = symbols.FindByNid("D8cuU4d72xM", Loader::SymbolType::Func);
  const auto* loaded_symbol = symbols.FindByNid("ynFKQ5bfGks", Loader::SymbolType::Func);
  Check(load_symbol && find_symbol && loaded_symbol, "resolve original internal sysmodule APIs");
  const auto load = reinterpret_cast<int (KYTY_SYSV_ABI *)(uint32_t)>(load_symbol->vaddr);
  const auto find = reinterpret_cast<int (KYTY_SYSV_ABI *)(uint32_t, int*)>(find_symbol->vaddr);
  const auto loaded = reinterpret_cast<int (KYTY_SYSV_ABI *)(uint32_t)>(loaded_symbol->vaddr);
  constexpr int not_loaded = static_cast<int32_t>(0x805a1001u);
  auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
  const std::array<const char*, 6> names {{
      "libSceIpmi.sprx", "libSceMbus.sprx", "libSceAvSetting.sprx",
      "libSceVideoOut.sprx", "libSceAgcDriver.sprx", "libSceRegMgr.sprx"}};
  const auto program = [&](size_t index) {
    return linker->FindProgramByFileName(directory / names[index]);
  };

  WriteModuleLifetimeElf(directory / names[0], 1);
  g_module_lifetime = {};
  int handle = -29;
  Check(load(0x80000022) == KERNEL_ERROR_ENOENT &&
            g_module_lifetime.order == std::vector<int>({1}) &&
            program(0) && program(0)->load_count == 1 && program(3) == nullptr &&
            find(0x80000022, &handle) == not_loaded && handle == -29,
        "missing native Mbus stops the VideoOut row without creating its root");
  linker->Clear();

  for (size_t i = 1; i < names.size(); ++i) {
    WriteModuleLifetimeElf(directory / names[i], static_cast<uint32_t>(i + 1));
  }
  g_module_lifetime = {};
  g_module_lifetime.fail_start_id = 5;
  g_module_lifetime.failed_path = directory / names[4];
  handle = -47;
  Check(load(0x80000080) == KERNEL_ERROR_ESTART &&
            g_module_lifetime.order == std::vector<int>({1, 2, 3, 4, 5, -5}) &&
            g_module_lifetime.starts[5] == 1 && g_module_lifetime.stops[5] == 1 &&
            program(4) == nullptr && find(0x80000080, &handle) == not_loaded &&
            handle == -47 && loaded(0x80000080) == not_loaded,
        "native driver initializer failure is cleaned up and remains a failed row");
  Check(program(0)->load_count == 3 && program(1)->load_count == 2 &&
            program(2)->load_count == 1 && program(3)->load_count == 1 &&
            program(5) == nullptr,
        "failure preserves only the completed dependency acquisitions");
  linker->Clear();

  g_module_lifetime = {};
  Check(load(0x80000022) == 0 &&
            g_module_lifetime.order == std::vector<int>({1, 2, 3, 4}) &&
            program(0)->load_count == 3 && program(1)->load_count == 2 &&
            program(2)->load_count == 1 && program(3)->load_count == 1 &&
            program(4) == nullptr && program(5) == nullptr,
        "VideoOut row initializes dependencies in native order with repeated acquisitions");
  handle = -1;
  Check(find(0x80000022, &handle) == 0 && handle == program(3)->unique_id &&
            loaded(0x80000022) == 0,
        "VideoOut numeric row exposes its initialized root handle");
  Check(load(0x8000001f) == 0 &&
            g_module_lifetime.order == std::vector<int>({1, 2, 3, 4, 6}) &&
            program(5)->load_count == 1 && find(0x8000001f, &handle) == 0 &&
            handle == program(5)->unique_id,
        "original registry row runs and identifies its own provider");
  Check(load(0x80000080) == 0 &&
            g_module_lifetime.order == std::vector<int>({1, 2, 3, 4, 6, 5}) &&
            program(0)->load_count == 6 && program(1)->load_count == 4 &&
            program(2)->load_count == 2 && program(3)->load_count == 2 &&
            program(4)->load_count == 1 && find(0x80000080, &handle) == 0 &&
            handle == program(4)->unique_id,
        "original graphics row retains common providers before starting its driver");
  Check(load(0x80000080) == 0 &&
            g_module_lifetime.order == std::vector<int>({1, 2, 3, 4, 6, 5}) &&
            program(0)->load_count == 9 && program(1)->load_count == 6 &&
            program(2)->load_count == 3 && program(3)->load_count == 3 &&
            program(4)->load_count == 2,
        "repeated numeric loading acquires live providers without repeating their initializers");
  linker->StopAllModules();
  for (size_t i = 0; i < names.size(); ++i) {
    Check(g_module_lifetime.starts[i + 1] == 1 && g_module_lifetime.stops[i + 1] == 1,
          "native numeric dependencies finalize their providers once");
  }
  linker->Clear();
  handle = -53;
  Check(find(0x80000080, &handle) == not_loaded && handle == -53 &&
            loaded(0x80000022) == not_loaded && loaded(0x8000001f) == not_loaded,
        "process cleanup cannot leave numeric rows reporting live providers");

  const std::array<std::pair<uint32_t, const char*>, 6> remaining {{
      {0x80000086, "libSceAgcVsh.sprx"}, {0x8000001a, "libSceCamera.sprx"},
      {0x8000008a, "libSceComposite.sprx"}, {0x80000029, "libSceDipsw.sprx"},
      {0x80000021, "libSceAvSetting.sprx"}, {0x800000d4, "libSceSisrSys.sprx"}}};
  for (const auto& [id, name]: remaining) {
    const bool camera = id == 0x8000001a;
    const bool av = id == 0x80000021;
    const uint32_t root_id = av ? 3 : 4;
    WriteModuleLifetimeElf(directory / name, root_id);
    g_module_lifetime = {};
    const std::vector<int> expected = camera ? std::vector<int>({1, 2, 4}) :
        av ? std::vector<int>({1, 2, 3}) : std::vector<int>({4});
    handle = -71;
    Check(load(id) == 0 && g_module_lifetime.order == expected,
          "remaining original compositor numeric row initializes its ordered providers");
    auto* provider = linker->FindProgramByFileName(directory / name);
    Check(provider && provider->native_init_attempted && provider->load_count == 1 &&
              find(id, &handle) == 0 && handle == provider->unique_id && loaded(id) == 0,
          "remaining numeric row identifies the executed native root provider");
    Check(load(id) == 0 && provider->load_count == 2 &&
              g_module_lifetime.order == expected && g_module_lifetime.starts[root_id] == 1,
          "remaining numeric rows retain live roots without duplicate initialization");
    if (camera || av) {
      Check(program(0)->load_count == (av ? 4 : 2) && program(1)->load_count == 2 &&
                g_module_lifetime.starts[1] == 1 && g_module_lifetime.starts[2] == 1,
            "Camera and AvSetting rows preserve their repeated shared acquisitions");
    }
    linker->StopAllModules();
    for (const int initialized: expected) {
      Check(g_module_lifetime.stops[initialized] == 1,
            "remaining native numeric providers finalize once after repeated acquisition");
    }
    linker->Clear();
    handle = -73;
    Check(find(id, &handle) == not_loaded && handle == -73 && loaded(id) == not_loaded,
          "remaining numeric rows do not retain handles after process cleanup");
  }
  const auto* public_load_symbol = symbols.FindByNid("g8cM39EUZ6o", Loader::SymbolType::Func);
  Check(public_load_symbol != nullptr, "resolve public sysmodule loader");
  const auto public_load = reinterpret_cast<int (KYTY_SYSV_ABI *)(uint16_t)>(public_load_symbol->vaddr);
  const std::array<std::pair<uint32_t, const char*>, 4> early {{
      {0x80000017, "libSceHidControl.sprx"}, {0xd4, "libSceHmd.sprx"},
      {0x12a, "libSceHmd2.sprx"}, {0xfb, "libSceBluetoothHid.sprx"}}};
  for (const auto& [id, name]: early) {
    const auto acquire = [&] { return (id & 0x80000000) ? load(id) : public_load(static_cast<uint16_t>(id)); };
    handle = -83;
    Check(acquire() == KERNEL_ERROR_ENOENT && find(id, &handle) == not_loaded && handle == -83,
          "early SysCore module request cannot succeed without its provider");
    WriteModuleLifetimeElf(directory / name, 4);
    g_module_lifetime = {};
    g_module_lifetime.fail_start_id = 4;
    g_module_lifetime.failed_path = directory / name;
    Check(acquire() == KERNEL_ERROR_ESTART && linker->FindProgramByFileName(directory / name) == nullptr &&
              g_module_lifetime.order == std::vector<int>({4, -4}) && find(id, &handle) == not_loaded,
          "early system module initializer failure remains a failed acquisition");
    g_module_lifetime = {};
    Check(acquire() == 0 && g_module_lifetime.order == std::vector<int>({4}),
          "early system row executes the provider initializer");
    auto* provider = linker->FindProgramByFileName(directory / name);
    Check(provider && provider->native_init_attempted && provider->load_count == 1 &&
              find(id, &handle) == 0 && handle == provider->unique_id && loaded(id) == 0,
          "early system module exposes only its live provider handle");
    Check(acquire() == 0 && provider->load_count == 2 && g_module_lifetime.starts[4] == 1,
          "early system module reacquisition does not repeat initialization");
    linker->StopAllModules();
    Check(g_module_lifetime.stops[4] == 1, "early system provider finalizes once");
    linker->Clear();
    handle = -89;
    Check(find(id, &handle) == not_loaded && handle == -89,
          "early system module cannot retain a live handle after teardown");
  }
  FileSystem::Umount("/system/common/lib");
  g_module_lifetime = {};
  std::printf("SysmoduleDependencyTests: native_order=pass handles=pass missing_dependency=pass initializer_failure=pass host_fixture_only=1\n");
}
