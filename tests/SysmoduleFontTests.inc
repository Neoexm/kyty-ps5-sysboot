int32_t g_sysmodule_blocked_handle = -1;
bool g_sysmodule_atexit_count_installed = false;

int KYTY_SYSV_ABI SysmoduleThreadAtexitCount(int32_t handle) {
  return handle == g_sysmodule_blocked_handle ? 1 : 0;
}

void CheckMemoryResidency() {
  using namespace Libs::LibKernel;
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* lock_symbol = symbols.FindByNid("3k6kx-zOOSQ", Loader::SymbolType::Func);
  const auto* unlock_symbol = symbols.FindByNid("xQIIfJ860sk", Loader::SymbolType::Func);
  Check(lock_symbol && unlock_symbol, "resolve original memory residency exports");
  using Residency = int (KYTY_SYSV_ABI *)(const void*, size_t);
  const auto lock = reinterpret_cast<Residency>(lock_symbol->vaddr);
  const auto unlock = reinterpret_cast<Residency>(unlock_symbol->vaddr);
  const uint64_t address = Memory::AllocateProgramMemory(0, 0x8000,
      Common::VirtualMemory::Mode::ReadWrite, "residency_test");
  Check(address != 0, "allocate residency fixture in the guest address space");
  auto* page = reinterpret_cast<uint8_t*>(address);
  std::memset(page, 0x39, 0x8000);
  auto* error = Libs::Posix::GetErrorAddr();
  *error = Libs::Posix::POSIX_EIO;
  Check(lock(page, 1) == 0 && lock(page + 1, 0) == 0 && *error == Libs::Posix::POSIX_EIO,
        "round residency spans to guest pages and preserve errno on success");
#if defined(_WIN32)
  using QueryWorkingSet = BOOL (WINAPI *)(HANDLE, PVOID, DWORD);
  const auto query = reinterpret_cast<QueryWorkingSet>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "K32QueryWorkingSetEx"));
  Check(query != nullptr, "resolve host residency observation");
  std::array<PSAPI_WORKING_SET_EX_INFORMATION, 8> resident {};
  auto check_locked = [&](bool expected, bool second = false) {
    for (size_t i = 0; i < resident.size(); ++i) resident[i].VirtualAddress = page + i * 0x1000;
    Check(query(GetCurrentProcess(), resident.data(), sizeof(resident)) != 0,
          "observe host residency");
    for (size_t i = 0; i < resident.size(); ++i) {
      const auto& item = resident[i];
      Check(item.VirtualAttributes.Valid && bool(item.VirtualAttributes.Locked) == (i < 4 ? expected : second),
            "all host pages reflect the guest residency operation");
    }
  };
  check_locked(true);
#endif
  Check(lock(page, 0xc000) == KERNEL_ERROR_ENOMEM && *error == Libs::Posix::POSIX_ENOMEM,
        "reject a partly unmapped residency range");
#if defined(_WIN32)
  check_locked(true);
#endif
  Check(lock(reinterpret_cast<void*>(UINT64_MAX - 3), 8) == KERNEL_ERROR_EINVAL &&
        *error == Libs::Posix::POSIX_EINVAL, "reject a residency range wrapping around zero");
  Check(unlock(page, 0x8000) == 0 && unlock(page, 0x4000) == 0,
        "one unlock releases repeated locks and mixed locked and unlocked guest pages");
#if defined(_WIN32)
  for (size_t i = 0; i < resident.size(); ++i) {
    volatile auto value = page[i * 0x1000];
    Check(value == 0x39, "residency changes preserve guest contents");
  }
  check_locked(false);
#endif
  Check(lock(page + 0x10, 0x4000) == 0, "font spans lock both intersected guest pages");
#if defined(_WIN32)
  check_locked(true, true);
#endif
  Check(Memory::KernelMunlockAll() == 0, "unlockall releases the guest residency set");
#if defined(_WIN32)
  check_locked(false);
#endif
  Check(lock(page, 0x4000) == 0 && Memory::FreeGuestMemory(address, 0x8000) &&
        Memory::KernelMunlockAll() == 0, "unmap removes residency without stale unlockall failures");
  Check(lock(page, 0x4000) == KERNEL_ERROR_ENOMEM && unlock(page, 0x4000) == KERNEL_ERROR_ENOMEM,
        "unmapped pages cannot acquire or release residency");
  std::printf("MemoryResidencyTests: host_lock=pass host_unlock=pass invalid_spans=pass\n");
}

void CheckFontAppMetadata() {
  using namespace Libs::LibKernel;
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* info_symbol = symbols.FindByNid("d7xu4QDJw8Q", Loader::SymbolType::Func);
  const auto* bit_symbol = symbols.FindByNid("TUZlvaB9rlg", Loader::SymbolType::Func);
  const auto* classification_symbol = symbols.FindByNid("GGeRJk1XdWc", Loader::SymbolType::Func);
  Check(info_symbol && bit_symbol && classification_symbol, "resolve font metadata APIs");
  const auto info = reinterpret_cast<int (KYTY_SYSV_ABI *)(int, void*, size_t)>(info_symbol->vaddr);
  const auto bit = reinterpret_cast<int (KYTY_SYSV_ABI *)(const void*, size_t, uint32_t, int*)>(bit_symbol->vaddr);
  const auto classification = reinterpret_cast<int (KYTY_SYSV_ABI *)(int*)>(classification_symbol->vaddr);
  const uint64_t address = Memory::AllocateProgramMemory(0, 0x4000,
      Common::VirtualMemory::Mode::ReadWrite, "font_metadata_test");
  Check(address != 0, "allocate font metadata fixture");
  auto* page = reinterpret_cast<uint8_t*>(address);
  std::memset(page, 0x6b, 0x4000);
  std::array<uint8_t, 0x98> sentinel {};
  std::memcpy(sentinel.data(), page, sentinel.size());
  Check(info(Process::GetPid(), page, 0x98) == KERNEL_ERROR_ENOSYS &&
        *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOSYS &&
        std::memcmp(page, sentinel.data(), sentinel.size()) == 0,
        "unknown extended application metadata fails without manufacturing a record");
  Check(info(1003, page, 0x98) == KERNEL_ERROR_ESRCH && *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ESRCH &&
        std::memcmp(page, sentinel.data(), sentinel.size()) == 0,
        "a pid no process holds is ESRCH, as pfind in 0x9e930b50");
  auto* output = reinterpret_cast<int*>(page + 0x100);
  *output = -27;
  Check(classification(output) == KERNEL_ERROR_ENOENT &&
        *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOENT && *output == -27 &&
        classification(nullptr) == KERNEL_ERROR_EINVAL,
        "missing original process parameter preserves caller output");
  std::array<uint64_t, 5> record {0xabcdef, uint64_t{1} << 63, uint64_t{1} << 47, 0, 0};
  std::memcpy(page, record.data(), sizeof(record));
  Check(bit(page, 0x28, 111, output) == 0 && *output == 1 &&
        bit(page, 0x28, 110, output) == 0 && *output == 0 &&
        bit(page, 0x28, 63, output) == 0 && *output == 1 &&
        bit(page, 0x28, 64, output) == 0 && *output == 0,
        "original bit accessor consumes only the caller supplied metadata words");
  *output = -27;
  Check(bit(page, 0x29, 111, output) == KERNEL_ERROR_EINVAL &&
        bit(page, 0x28, 128, output) == KERNEL_ERROR_EINVAL &&
        bit(nullptr, 0x28, 111, output) == KERNEL_ERROR_EFAULT &&
        bit(page, 0x28, 111, nullptr) == KERNEL_ERROR_EFAULT && *output == -27,
        "invalid metadata accessor arguments leave output unchanged");
  Check(Memory::FreeGuestMemory(address, 0x4000), "release font metadata fixture");
  std::printf("FontAppMetadataTests: unavailable_records=pass original_bit_accessor=pass\n");
}

void CheckOriginalAppClassification(const std::filesystem::path& executable) {
  using namespace Libs::LibKernel;
  auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
  Check(linker->GetProcParam() == 0, "classification fixture starts without a main executable");

  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* symbol = symbols.FindByNid("GGeRJk1XdWc", Loader::SymbolType::Func);
  Check(symbol != nullptr, "resolve original classification export");
  const auto classification = reinterpret_cast<int (KYTY_SYSV_ABI *)(int*)>(symbol->vaddr);
  const uint64_t address = Memory::AllocateProgramMemory(0, 0x4000,
      Common::VirtualMemory::Mode::ReadWrite, "app_classification_test");
  Check(address != 0, "allocate classification output");
  auto* output = reinterpret_cast<int*>(address);

  *output = -27;
  Check(classification(output) == KERNEL_ERROR_ENOENT && *output == -27,
        "no main executable has no manufactured classification");
  Check(linker->LoadProgram(executable) != nullptr, "load the ShellUI executable");
  const auto* proc_param = reinterpret_cast<const uint64_t*>(linker->GetProcParam());
  Check(proc_param != nullptr && proc_param[0] == 0x60 && proc_param[2] == 0x1360000713590001ull,
        "use the pinned ShellUI process parameter");
  Check(classification(output) == 0 && static_cast<uint32_t>(*output) == 0x13600007u,
        "publish the high dword selected by the original libkernel wrapper");
  Check(classification(nullptr) == KERNEL_ERROR_EINVAL &&
        classification(reinterpret_cast<int*>(0x1234)) == KERNEL_ERROR_EFAULT,
        "reject null and unmapped outputs without changing the successful value");
  Check(static_cast<uint32_t>(*output) == 0x13600007u,
        "invalid output arguments preserve the prior result");

  linker->Clear();
  *output = -27;
  Check(classification(output) == KERNEL_ERROR_ENOENT && *output == -27,
        "unloading the main executable removes the process-parameter source");
  Check(Memory::FreeGuestMemory(address, 0x4000), "release classification output");
  std::printf("AppClassificationTests: original_procparam=pass output=0x13600007 negatives=pass\n");
}

int AuditNativeFontProviders(const std::filesystem::path& root) {
  Check(std::filesystem::is_directory(root), "native font audit requires an existing sysroot");
  FileSystem::MountReadOnly(root, "/");
  auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
  Libs::InitAll(linker->Symbols());
  const auto* symbol = linker->Symbols()->FindByNid("g8cM39EUZ6o", Loader::SymbolType::Func);
  Check(symbol != nullptr, "resolve font sysmodule load API");
  const auto load = reinterpret_cast<int (KYTY_SYSV_ABI *)(uint16_t)>(symbol->vaddr);
  int result = 0;
  for (uint16_t id: {0x84, 0x98, 0x99}) {
    std::printf("NATIVE_FONT_AUDIT before id=0x%02x original_module_start=1 normal_boot=0\n", id);
    std::fflush(stdout);
    Log::Flush();
    const int loaded = load(id);
    std::printf("NATIVE_FONT_AUDIT after id=0x%02x result=0x%08x\n", id,
                static_cast<uint32_t>(loaded));
    std::fflush(stdout);
    Log::Flush();
    if (loaded == 0 && id != 0x99) {
      const auto name = id == 0x84 ? "libSceFont.native.sprx" : "libSceFontFt.sprx";
      const auto* provider = linker->FindProgramByFileName(root / "system/common/lib" / name);
      Check(provider != nullptr, "audit font module state");
      std::printf("NATIVE_FONT_AUDIT id=0x%02x state=%d native_init=%d original_provider=%d\n",
                  id, static_cast<int>(provider->module_state), provider->native_init_attempted,
                  provider->original_font_provider);
      for (const auto& module: provider->dynamic_info->export_modules) {
        std::printf("NATIVE_FONT_AUDIT export_module=%s version=%d.%d\n", module.name.c_str(),
                    module.version_major, module.version_minor);
      }
      for (const auto& library: provider->dynamic_info->export_libs) {
        std::printf("NATIVE_FONT_AUDIT export_library=%s version=%d\n", library.name.c_str(), library.version);
      }
    }
    if (loaded != 0) {
      result = 1;
      break;
    }
  }
  if (result == 0) {
    auto* ft = linker->FindProgramByFileName(root / "system/common/lib/libSceFontFt.sprx");
    Check(ft && ft->export_symbols, "locate FontFt exports");
    for (const auto& [nid, rva]: std::array<std::pair<const char*, uint64_t>, 2>{{
         {"oM+XCzVG3oM", 0x1c000}, {"Xx974EW-QFY", 0x1c740}}}) {
      const auto* selector_symbol = ft->export_symbols->FindByNid(nid, Loader::SymbolType::Func);
      Check(selector_symbol != nullptr, "resolve selector from the native FontFt provider");
      const auto selector = reinterpret_cast<void* (KYTY_SYSV_ABI *)(uint32_t)>(selector_symbol->vaddr);
      Check(reinterpret_cast<uint64_t>(selector(0)) == ft->base_vaddr + rva && selector(1) == nullptr,
            "FontFt selects its own descriptor and rejects unsupported selection");
      std::printf("NATIVE_FONT_AUDIT selector=%s original_provider=1 descriptor_rva=0x%llx passed=1\n",
                  nid, static_cast<unsigned long long>(rva));
    }
  }
  linker->Clear();
  FileSystem::Umount("/");
  return result;
}

void CheckSysmoduleFontProviders(const std::filesystem::path& root) {
  CheckMemoryResidency();
  CheckFontAppMetadata();
  using namespace Libs::LibKernel;
  const auto directory = root / "sysmodule_fonts";
  Check(std::filesystem::create_directory(directory), "create font module fixture");
  Check(FileSystem::GetRealFilename("/system/common/lib").empty(),
        "font fixture does not shadow system libraries");
  FileSystem::MountReadOnly(directory, "/system/common/lib");
  WriteModuleLifetimeElf(directory / "libSceFont.native.sprx", 1);
  WriteModuleLifetimeElf(directory / "libSceFontFt.sprx", 2);
  WriteModuleLifetimeElf(directory / "libSceFreeTypeOl.sprx", 4);

  Loader::SymbolDatabase symbols;
  Libs::InitSysmodule_1(&symbols);
  Libs::InitLibKernel_1(&symbols);
  const auto* load_symbol = symbols.FindByNid("g8cM39EUZ6o", Loader::SymbolType::Func);
  const auto* unload_symbol = symbols.FindByNid("eR2bZFAAU0Q", Loader::SymbolType::Func);
  const auto* find_symbol = symbols.FindByNid("D8cuU4d72xM", Loader::SymbolType::Func);
  const auto* loaded_symbol = symbols.FindByNid("fMP5NHUOaMk", Loader::SymbolType::Func);
  Check(load_symbol && unload_symbol && find_symbol && loaded_symbol, "resolve font sysmodule APIs");
  const auto load = reinterpret_cast<int (KYTY_SYSV_ABI *)(uint16_t)>(load_symbol->vaddr);
  const auto unload = reinterpret_cast<int (KYTY_SYSV_ABI *)(uint16_t)>(unload_symbol->vaddr);
  const auto find = reinterpret_cast<int (KYTY_SYSV_ABI *)(uint32_t, int*)>(find_symbol->vaddr);
  const auto loaded = reinterpret_cast<int (KYTY_SYSV_ABI *)(uint16_t)>(loaded_symbol->vaddr);
  constexpr int not_loaded = static_cast<int32_t>(0x805a1001u);
  auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
  g_module_lifetime = {};
  int missing_handle = -29;
  Check(find(0x99, &missing_handle) == not_loaded && missing_handle == -29,
        "unloaded Ot has no manufactured module handle");
  Check(load(0x99) == KERNEL_ERROR_ENOENT &&
        linker->FindProgramByFileName(directory / "libSceFreeTypeOl.sprx") == nullptr,
        "missing selected Ot fails instead of claiming success or substituting Ol");
  Check(loaded(0x99) == not_loaded,
        "public is-loaded reports the absent provider");
  WriteModuleLifetimeElf(directory / "libSceFreeTypeOt.sprx", 3);
  Check(load(0x84) == 0 && load(0x98) == 0 && load(0x99) == 0,
        "font IDs load their providers in caller order");
  Check(g_module_lifetime.order == std::vector<int>({1, 2, 3}) &&
        g_module_lifetime.starts[4] == 0,
        "font sequence initializes native Font, FontFt and selected Ot without Ol");
  const std::array<std::pair<uint32_t, const char*>, 3> rows {{
      {0x84, "libSceFont.native.sprx"}, {0x98, "libSceFontFt.sprx"},
      {0x99, "libSceFreeTypeOt.sprx"}}};
  int ot_handle = -1;
  for (const auto& [id, name]: rows) {
    int handle = -1;
    auto* program = linker->FindProgramByFileName(directory / name);
    Check(program && find(id, &handle) == 0 && handle == program->unique_id && loaded(id) == 0,
          "font handles and public load status reflect live original-ID providers");
    if (id == 0x99) ot_handle = handle;
  }
  Check(load(0x99) == 0 && g_module_lifetime.starts[3] == 1,
        "repeated Ot loading reuses its live initializer");
  int repeated_handle = -1;
  Check(find(0x99, &repeated_handle) == 0 && repeated_handle == ot_handle,
        "repeated ID returns the same provider");
  auto* ot = linker->FindProgramById(ot_handle);
  const auto ot_address = ot->base_vaddr;
  Check(ot->load_count == 2 && unload(0x99) == 0 && ot->load_count == 1 &&
            loaded(0x99) == 0 && g_module_lifetime.stops[3] == 0,
        "first balanced font sysmodule unload releases one acquisition");
  Check(unload(0x99) == 0 && g_module_lifetime.stops[3] == 1 && loaded(0x99) == not_loaded,
        "last font sysmodule unload runs the finalizer and clears row status");
  CheckModuleLifetimeUnmapped(ot_handle, ot_address);
  repeated_handle = -47;
  Check(find(0x99, &repeated_handle) == not_loaded && repeated_handle == -47 &&
            unload(0x99) == not_loaded && unload(0) == static_cast<int32_t>(0x805a1000u),
        "unloaded and zero font sysmodule IDs fail without a manufactured handle");
  auto* font = linker->FindProgramByFileName(directory / "libSceFont.native.sprx");
  const auto font_handle = font->unique_id;
  const auto font_address = font->base_vaddr;
  linker->LoadNeededModules(font);
  Check(font->process_owned && font->load_count == 1 && unload(0x84) == 0 &&
            font->load_count == 0 && loaded(0x84) == not_loaded &&
            linker->FindProgramById(font_handle) == font && g_module_lifetime.stops[1] == 0,
        "font row unload releases its own reference while retaining the startup owner");
  Check(load(0x84) == 0 && font->load_count == 1 && loaded(0x84) == 0 &&
            g_module_lifetime.starts[1] == 1 && unload(0x84) == 0 &&
            loaded(0x84) == not_loaded && font->load_count == 0,
        "retained font provider can be acquired and released again without reinitialization");
  Check(unload(0x98) == 0 && loaded(0x98) == not_loaded && g_module_lifetime.stops[2] == 1,
        "independent font provider unloads its single acquisition");
  Check(unload(0x85) == KERNEL_ERROR_ENOSYS,
        "unsupported complex sysmodule unload does not report successful release");
  const auto* count_symbol = symbols.FindByNid("pB-yGZ2nQ9o", Loader::SymbolType::Func);
  const auto* raw_unload_symbol = symbols.FindByNid("QKd0qM58Qes", Loader::SymbolType::Func);
  Check(count_symbol && raw_unload_symbol, "resolve thread finalizer lifetime gate and raw unload");
  using Count = int (KYTY_SYSV_ABI *)(int32_t);
  const auto set_count = reinterpret_cast<void (KYTY_SYSV_ABI *)(Count)>(count_symbol->vaddr);
  const auto raw_unload = reinterpret_cast<ModuleLifetimeUnload>(raw_unload_symbol->vaddr);
  if (!g_sysmodule_atexit_count_installed) {
    set_count(&SysmoduleThreadAtexitCount);
    g_sysmodule_atexit_count_installed = true;
  }
  Check(load(0x99) == 0 && find(0x99, &g_sysmodule_blocked_handle) == 0,
        "acquire a font provider for the registered thread lifetime gate");
  const auto blocked_handle = g_sysmodule_blocked_handle;
  auto* blocked = linker->FindProgramById(blocked_handle);
  const auto blocked_address = blocked->base_vaddr;
  Check(blocked->load_count == 1 && unload(0x99) == KERNEL_ERROR_EBUSY &&
            loaded(0x99) == not_loaded && blocked->load_count == 1 &&
            linker->FindProgramById(blocked_handle) == blocked && g_module_lifetime.stops[3] == 1,
        "failed native unload consumes only the Sysmodule row while thread ownership retains mapping");
  Check(unload(0x99) == not_loaded,
        "failed final row release is not advertised as another successful acquisition");
  g_sysmodule_blocked_handle = -1;
  int raw_result = -1;
  Check(raw_unload(blocked_handle, 0, nullptr, 0, nullptr, &raw_result) == 0 && raw_result == 0 &&
            g_module_lifetime.stops[3] == 2,
        "raw loader can release the retained provider after thread lifetime gate clears");
  CheckModuleLifetimeUnmapped(blocked_handle, blocked_address);
  linker->StopAllModules();
  Check(g_module_lifetime.stops[1] == 1,
        "retained startup font receives its process finalizer once");
  linker->Clear();
  CheckModuleLifetimeUnmapped(font_handle, font_address);
  Check(loaded(0x99) == not_loaded,
        "released module mappings cannot leave a false font-ready record");

  g_module_lifetime = {};
  g_module_lifetime.fail_start_id = 7;
  g_module_lifetime.failed_path = directory / "libSceFreeTypeOt.sprx";
  WriteModuleLifetimeElf(g_module_lifetime.failed_path, 7);
  Check(load(0x99) == KERNEL_ERROR_ESTART &&
        g_module_lifetime.order == std::vector<int>({7, -7}) && loaded(0x99) == not_loaded,
        "selected font initializer failure propagates and consumes its cleanup");
  linker->Clear();
  FileSystem::Umount("/system/common/lib");

  const auto passthrough = root / "sysmodule_passthrough";
  const auto passthrough_lib = passthrough / "common" / "lib";
  Check(std::filesystem::create_directories(passthrough_lib),
        "create provider-backed sysmodule fixture");
  Check(DirectoryPassthrough::Mount("/system", passthrough) == OK &&
            FileSystem::KernelCheckReachability("/system/common/lib") == OK &&
            FileSystem::GetRealFilename("/system/common/lib").empty(),
        "publish the system library root without exposing an opaque host path");
  missing_handle = -61;
  Check(load(0x99) == KERNEL_ERROR_ENOENT &&
            find(0x99, &missing_handle) == not_loaded && missing_handle == -61 &&
            loaded(0x99) == not_loaded,
        "provider-backed sysmodule lookup reports a missing module");
  const auto passthrough_ot = passthrough_lib / "libSceFreeTypeOt.sprx";
  g_module_lifetime = {};
  WriteModuleLifetimeElf(passthrough_ot, 6);
  Check(load(0x99) == 0 && g_module_lifetime.order == std::vector<int>({6}) &&
            FileSystem::GetRealFilename("/system/common/lib/libSceFreeTypeOt.sprx").empty(),
        "provider-backed sysmodule load runs the module initializer");
  auto* passthrough_program = linker->FindProgramByFileName(passthrough_ot);
  int passthrough_handle = -1;
  Check(passthrough_program != nullptr && find(0x99, &passthrough_handle) == 0 &&
            passthrough_handle == passthrough_program->unique_id && loaded(0x99) == 0 &&
            passthrough_program->load_count == 1,
        "provider-backed sysmodule exposes its live loader handle and status");
  const auto passthrough_address = passthrough_program->base_vaddr;
  Check(unload(0x99) == 0 && g_module_lifetime.stops[6] == 1 &&
            loaded(0x99) == not_loaded,
        "provider-backed sysmodule balances its loader acquisition");
  CheckModuleLifetimeUnmapped(passthrough_handle, passthrough_address);
  Check(DirectoryPassthrough::Unmount("/system") == OK,
        "remove provider-backed sysmodule fixture");
  linker->Clear();
  std::printf("SysmoduleFontTests: original_ids=pass handles=pass missing_ot=pass initializer_failure=pass provider_passthrough=pass host_fixture_only=1\n");
}
