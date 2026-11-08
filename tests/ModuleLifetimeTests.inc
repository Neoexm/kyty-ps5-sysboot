using ModuleLifetimeLoad = int32_t (KYTY_SYSV_ABI *)(
    const char*, size_t, const void*, uint32_t, const void*, int*);
using ModuleLifetimeLoadByName = int (KYTY_SYSV_ABI *)(
    const char*, size_t, const void*, uint32_t, int*);
using ModuleLifetimeUnload = int (KYTY_SYSV_ABI *)(
    int32_t, size_t, const void*, uint32_t, const void*, int*);

constexpr uint64_t ModuleLifetimeInitOffset = 0x4000;
constexpr uint64_t ModuleLifetimeFiniOffset = 0x4040;
constexpr uint64_t ModuleLifetimeCallOffset = 0x4100;
constexpr uint64_t ModuleLifetimeDataOffset = 0x1800;
constexpr uint64_t ModuleLifetimeStaticBase = 0x400000;
constexpr uint64_t ModuleLifetimeData = 0x4b5954594c494645;
constexpr uint32_t ModuleLifetimeValue = 0x13572468;

struct ModuleLifetimeState {
  std::vector<int> order;
  std::array<unsigned, 8> starts {};
  std::array<unsigned, 8> stops {};
  int32_t provider_handle = -1;
  uint64_t provider_base = 0;
  bool check_provider_on_owner_stop = false;
  int32_t release_during_stop = -1;
  bool released_during_stop = false;
  uint32_t fail_start_id = 0;
  uint32_t negative_stop_id = 0;
  std::filesystem::path failed_path;
  int32_t failed_handle = -1;
  uint64_t failed_address = 0;
  uint32_t recursive_start_id = 0;
  std::string recursive_path;
  int32_t recursive_handle = 0;
  int recursive_result = 0;
  uint32_t recursive_stop_id = 0;
  std::string recursive_stop_path;
  int32_t recursive_stop_handle = 0;
  int recursive_stop_result = 0;
};

struct ModuleLifetimeStartGate {
  std::mutex mutex;
  std::condition_variable entered_condition;
  std::condition_variable release_condition;
  uint32_t id = 0;
  bool entered = false;
  bool released = false;
};

struct ModuleLifetimeCycleGate {
  std::mutex mutex;
  std::condition_variable condition;
  uint32_t participants = 0;
  uint32_t entered = 0;
  uint32_t completed = 0;
  std::array<std::string, 8> paths;
  std::array<int32_t, 8> handles {};
  std::array<int, 8> results {};
};

ModuleLifetimeLoad g_module_lifetime_load = nullptr;
ModuleLifetimeUnload g_module_lifetime_unload = nullptr;
ModuleLifetimeState g_module_lifetime;
ModuleLifetimeStartGate g_module_lifetime_start_gate;
ModuleLifetimeCycleGate g_module_lifetime_cycle_gate;

void ArmModuleLifetimeCycleGate(uint32_t first_id, const char* first_path,
                                uint32_t second_id, const char* second_path) {
  std::lock_guard lock(g_module_lifetime_cycle_gate.mutex);
  g_module_lifetime_cycle_gate.participants =
      (uint32_t {1} << first_id) | (uint32_t {1} << second_id);
  g_module_lifetime_cycle_gate.entered = 0;
  g_module_lifetime_cycle_gate.completed = 0;
  g_module_lifetime_cycle_gate.paths = {};
  g_module_lifetime_cycle_gate.paths[first_id] = first_path;
  g_module_lifetime_cycle_gate.paths[second_id] = second_path;
  g_module_lifetime_cycle_gate.handles.fill(0);
  g_module_lifetime_cycle_gate.results.fill(0);
}

void ResetModuleLifetimeCycleGate() {
  std::lock_guard lock(g_module_lifetime_cycle_gate.mutex);
  g_module_lifetime_cycle_gate.participants = 0;
  g_module_lifetime_cycle_gate.entered = 0;
  g_module_lifetime_cycle_gate.completed = 0;
  g_module_lifetime_cycle_gate.paths = {};
}

void ArmModuleLifetimeStartGate(uint32_t id) {
  std::lock_guard lock(g_module_lifetime_start_gate.mutex);
  g_module_lifetime_start_gate.id = id;
  g_module_lifetime_start_gate.entered = false;
  g_module_lifetime_start_gate.released = false;
}

void WaitForModuleLifetimeStartGate() {
  std::unique_lock lock(g_module_lifetime_start_gate.mutex);
  Check(g_module_lifetime_start_gate.entered_condition.wait_for(
            lock, std::chrono::seconds(5), [] {
              return g_module_lifetime_start_gate.entered;
            }),
        "module initializer reaches the deterministic concurrency gate");
}

void ReleaseModuleLifetimeStartGate() {
  std::lock_guard lock(g_module_lifetime_start_gate.mutex);
  g_module_lifetime_start_gate.released = true;
  g_module_lifetime_start_gate.release_condition.notify_all();
}

void CheckModuleLifetimeProvider() {
  auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
  auto* provider = linker->FindProgramById(g_module_lifetime.provider_handle);
  Check(provider != nullptr &&
            provider->base_vaddr == g_module_lifetime.provider_base,
        "DT_NEEDED provider identity and mapping remain live");
  Check(g_module_lifetime.stops[1] == 0,
        "DT_NEEDED provider has not finalized before its owner");
  uint64_t value = 0;
  std::memcpy(&value,
              reinterpret_cast<const void*>(provider->base_vaddr +
                                             ModuleLifetimeDataOffset),
              sizeof(value));
  Check(value == ModuleLifetimeData, "retained provider data remains intact");
  using Call = uint32_t (KYTY_SYSV_ABI *)();
  auto call = reinterpret_cast<Call>(provider->base_vaddr +
                                     ModuleLifetimeCallOffset);
  Check(call() == ModuleLifetimeValue, "retained provider machine code executes");
}

int KYTY_SYSV_ABI RecordModuleLifetime(uint32_t id, uint32_t stopping) {
  Check(id > 0 && id < g_module_lifetime.starts.size() && stopping <= 1,
        "synthetic ELF callback arguments");
  if (stopping == 0) {
    const auto bit = uint32_t {1} << id;
    bool cycle_member = false;
    std::string cycle_path;
    {
      std::unique_lock lock(g_module_lifetime_cycle_gate.mutex);
      cycle_member = (g_module_lifetime_cycle_gate.participants & bit) != 0;
      if (cycle_member) {
        ++g_module_lifetime.starts[id];
        g_module_lifetime.order.push_back(static_cast<int>(id));
        cycle_path = g_module_lifetime_cycle_gate.paths[id];
        g_module_lifetime_cycle_gate.entered |= bit;
        g_module_lifetime_cycle_gate.condition.notify_all();
        Check(g_module_lifetime_cycle_gate.condition.wait_for(
                  lock, std::chrono::seconds(5), [&] {
                    return g_module_lifetime_cycle_gate.entered ==
                           g_module_lifetime_cycle_gate.participants;
                  }),
              "both concurrent cycle initializers reach the call barrier");
      }
    }
    if (cycle_member) {
      int nested_result = 117;
      const auto nested_handle = g_module_lifetime_load(
          cycle_path.c_str(), 0, nullptr, 0, nullptr, &nested_result);
      std::unique_lock lock(g_module_lifetime_cycle_gate.mutex);
      g_module_lifetime_cycle_gate.handles[id] = nested_handle;
      g_module_lifetime_cycle_gate.results[id] = nested_result;
      g_module_lifetime_cycle_gate.completed |= bit;
      g_module_lifetime_cycle_gate.condition.notify_all();
      Check(g_module_lifetime_cycle_gate.condition.wait_for(
                lock, std::chrono::seconds(5), [&] {
                  return g_module_lifetime_cycle_gate.completed ==
                         g_module_lifetime_cycle_gate.participants;
                }),
            "both concurrent cycle initializers reject their nested wait");
    } else {
      ++g_module_lifetime.starts[id];
      g_module_lifetime.order.push_back(static_cast<int>(id));
    }
    if (!cycle_member && id == g_module_lifetime.recursive_start_id) {
      int nested_result = 0;
      const auto nested_handle = g_module_lifetime_load(
          g_module_lifetime.recursive_path.c_str(), 0, nullptr, 0, nullptr,
          &nested_result);
      g_module_lifetime.recursive_handle = nested_handle;
      g_module_lifetime.recursive_result = nested_result;
    }
    {
      std::unique_lock lock(g_module_lifetime_start_gate.mutex);
      if (id == g_module_lifetime_start_gate.id) {
        g_module_lifetime_start_gate.entered = true;
        g_module_lifetime_start_gate.entered_condition.notify_all();
        g_module_lifetime_start_gate.release_condition.wait(lock, [] {
          return g_module_lifetime_start_gate.released;
        });
      }
    }
    if (id == g_module_lifetime.fail_start_id) {
      auto* program = Common::Singleton<Loader::RuntimeLinker>::Instance()
                          ->FindProgramByFileName(g_module_lifetime.failed_path);
      Check(program != nullptr, "failed initializer runs in a loaded ELF");
      g_module_lifetime.failed_handle = program->unique_id;
      g_module_lifetime.failed_address = program->base_vaddr;
      return -37;
    }
    return 0;
  }
  ++g_module_lifetime.stops[id];
  g_module_lifetime.order.push_back(-static_cast<int>(id));
  if (id == g_module_lifetime.negative_stop_id) {
    return -53;
  }
  if (id == 2 && g_module_lifetime.check_provider_on_owner_stop) {
    CheckModuleLifetimeProvider();
  }
  if (id == 5 && g_module_lifetime.release_during_stop >= 0) {
    const auto handle = g_module_lifetime.release_during_stop;
    g_module_lifetime.release_during_stop = -1;
    int result = -1;
    Check(g_module_lifetime_unload(handle, 0, nullptr, 0, nullptr, &result) == 0,
          "module finalizer releases a dynamically acquired peer");
    Check(result == 0, "peer finalizer result propagates during shutdown");
    Check(Common::Singleton<Loader::RuntimeLinker>::Instance()
                  ->FindProgramById(handle) == nullptr,
          "peer released by finalizer is unmapped");
    g_module_lifetime.released_during_stop = true;
  }
  if (id == g_module_lifetime.recursive_stop_id) {
    int nested_result = 117;
    const auto nested_handle = g_module_lifetime_load(
        g_module_lifetime.recursive_stop_path.c_str(), 0, nullptr, 0, nullptr,
        &nested_result);
    g_module_lifetime.recursive_stop_handle = nested_handle;
    g_module_lifetime.recursive_stop_result = nested_result;
  }
  return 0;
}

void WriteModuleLifetimeElf(const std::filesystem::path& path, uint32_t id,
                            const char* needed = nullptr, bool static_exec = false,
                            bool omit_soname = false) {
  using namespace Loader;
  std::vector<uint8_t> image(0x8000);
  std::fill(image.begin() + 0x4000, image.end(), 0x90);
  const auto put = [&](uint64_t offset, const void* data, size_t size) {
    Check(offset <= image.size() && size <= image.size() - offset,
          "synthetic ELF field fits fixture");
    std::memcpy(image.data() + offset, data, size);
  };

  std::string strings(1, '\0');
  const auto name_offset = strings.size();
  strings += path.filename().string();
  strings.push_back('\0');
  const auto needed_offset = strings.size();
  if (needed != nullptr) {
    strings += needed;
    strings.push_back('\0');
  }
  put(0x1000, strings.data(), strings.size());

  std::vector<Elf64_Dyn> dynamic;
  const auto tag = [&](Elf64_Sxword key, uint64_t value) {
    Elf64_Dyn item {};
    item.d_tag = key;
    item.d_un.d_val = value;
    dynamic.push_back(item);
  };
  tag(DT_STRTAB, 0x1000);
  tag(DT_STRSZ, strings.size());
  tag(DT_SYMTAB, 0x1200);
  tag(DT_SYMENT, sizeof(Elf64_Sym));
  tag(DT_OS_SYMTABSZ, 0);
  tag(DT_JMPREL, 0x1240);
  tag(DT_PLTRELSZ, 0);
  tag(DT_PLTREL, DT_RELA);
  tag(DT_RELA, 0x1280);
  tag(DT_RELASZ, 0);
  tag(DT_RELAENT, sizeof(Elf64_Rela));
  if (!omit_soname) tag(DT_SONAME, name_offset);
  tag(DT_INIT, ModuleLifetimeInitOffset);
  tag(DT_FINI, ModuleLifetimeFiniOffset);
  if (needed != nullptr) {
    tag(DT_NEEDED, needed_offset);
  }
  tag(0, 0);
  put(0x400, dynamic.data(), dynamic.size() * sizeof(Elf64_Dyn));

  Elf64_Ehdr header {};
  const uint8_t ident[] = {0x7f, 'E', 'L', 'F', ELFCLASS64,
                           ELFDATA2LSB, EV_CURRENT, ELFOSABI_FREEBSD, 2};
  std::memcpy(header.e_ident, ident, sizeof(ident));
  header.e_type = static_exec ? ET_EXEC : ET_DYNAMIC;
  header.e_machine = EM_X86_64;
  header.e_version = EV_CURRENT;
  header.e_entry = (static_exec ? ModuleLifetimeStaticBase : 0) + ModuleLifetimeInitOffset;
  header.e_phoff = sizeof(Elf64_Ehdr);
  header.e_ehsize = sizeof(Elf64_Ehdr);
  header.e_phentsize = sizeof(Elf64_Phdr);
  header.e_phnum = static_exec ? 2 : 3;
  put(0, &header, sizeof(header));

  std::array<Elf64_Phdr, 3> segments {};
  segments[0].p_type = PT_LOAD;
  segments[0].p_flags = PF_R | PF_W;
  segments[0].p_vaddr = static_exec ? ModuleLifetimeStaticBase : 0;
  segments[0].p_filesz = 0x4000;
  segments[0].p_memsz = 0x4000;
  segments[0].p_align = 0x4000;
  segments[1].p_type = PT_LOAD;
  segments[1].p_flags = PF_R | PF_X;
  segments[1].p_offset = 0x4000;
  segments[1].p_vaddr = segments[0].p_vaddr + 0x4000;
  segments[1].p_filesz = 0x4000;
  segments[1].p_memsz = 0x4000;
  segments[1].p_align = 0x4000;
  segments[2].p_type = PT_DYNAMIC;
  segments[2].p_flags = PF_R;
  segments[2].p_offset = 0x400;
  segments[2].p_vaddr = 0x400;
  segments[2].p_filesz = dynamic.size() * sizeof(Elf64_Dyn);
  segments[2].p_memsz = segments[2].p_filesz;
  segments[2].p_align = 8;
  if (static_exec) {
    segments[2] = {};
    std::fill(image.begin() + 0x400, image.begin() + 0x1000, uint8_t {0});
  }
  put(header.e_phoff, segments.data(), sizeof(segments));

  const auto entry = [&](uint64_t offset, uint32_t stopping) {
    std::array<uint8_t, 22> code {
        0xbf, 0, 0, 0, 0, 0xbe, 0, 0, 0, 0, 0x48, 0xb8,
        0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xe0};
    const auto target = reinterpret_cast<uint64_t>(&RecordModuleLifetime);
    std::memcpy(code.data() + 1, &id, sizeof(id));
    std::memcpy(code.data() + 6, &stopping, sizeof(stopping));
    std::memcpy(code.data() + 12, &target, sizeof(target));
    put(offset, code.data(), code.size());
  };
  entry(ModuleLifetimeInitOffset, 0);
  entry(ModuleLifetimeFiniOffset, 1);
  std::array<uint8_t, 6> call {0xb8, 0, 0, 0, 0, 0xc3};
  std::memcpy(call.data() + 1, &ModuleLifetimeValue, sizeof(ModuleLifetimeValue));
  put(ModuleLifetimeCallOffset, call.data(), call.size());
  put(ModuleLifetimeDataOffset, &ModuleLifetimeData, sizeof(ModuleLifetimeData));

  Common::File file;
  Check(file.Create(path), "create synthetic module ELF");
  uint32_t written = 0;
  file.Write(image.data(), static_cast<uint32_t>(image.size()), &written);
  Check(written == image.size() && file.Flush(), "write synthetic module ELF");
  file.Close();
}

void CheckModuleLifetimeUnmapped(int32_t handle, uint64_t address);

void CheckPsmMscorlibAotLoaderIdentity() {
  using namespace Libs::LibKernel;
  TempDirectory provider;
  const auto native = provider.Path() / "common_ex" / "lib" / "mscorlib.dll.sprx";
  const auto reactive = provider.Path() / "common_ex" / "lib" / "System.Reactive.Core.dll.sprx";
  const auto yoga = provider.Path() / "common_ex" / "lib" / "libSceFacebook.Yoga.sprx";
  const auto unrelated = provider.Path() / "common_ex" / "lib" / "libOther.sprx";
  const auto folly = provider.Path() / "common_ex" / "lib" / "libSceFollyShared.sprx";
  const auto lib_dir = provider.Path() / "common_ex" / "lib";
  Check(std::filesystem::create_directories(native.parent_path()),
        "create exact mscorlib provider fixture");
  WriteModuleLifetimeElf(native, 5);
  WriteModuleLifetimeElf(reactive, 6);
  WriteModuleLifetimeElf(yoga, 7);
  WriteModuleLifetimeElf(folly, 4);
  WriteModuleLifetimeElf(lib_dir / "libSceJsi-0.70.sprx", 3);
  WriteModuleLifetimeElf(lib_dir / "libhermes-0.11.sprx", 2);
  WriteModuleLifetimeElf(lib_dir / "libhermesRemoteInspector.sprx", 1);
  {
    std::ofstream output(unrelated, std::ios::binary);
    output.write("SELF", 4);
    output.flush();
    Check(output.good(), "write provider-present unrelated native module fixture");
  }
  Check(std::filesystem::file_size(unrelated) == 4,
        "verify provider-present unrelated native module fixture");
  Check(DirectoryPassthrough::Mount("/system_ex", provider.Path()) == OK,
        "publish exact mscorlib through the read-only provider");

  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* exact_symbol = symbols.FindByNid("Y1nEpkCieOY", Loader::SymbolType::Func);
  const auto* ordinary_symbol = symbols.FindByNid("wzvqT4UqKX8", Loader::SymbolType::Func);
  const auto* unload_symbol = symbols.FindByNid("QKd0qM58Qes", Loader::SymbolType::Func);
  const auto* debug_raise_symbol = symbols.FindByNid("OMDRKKAZ8I4", Loader::SymbolType::Func);
  Check(exact_symbol != nullptr && ordinary_symbol != nullptr && unload_symbol != nullptr &&
            debug_raise_symbol != nullptr,
        "resolve exact, ordinary, unload, and debug-exception exports");
  const auto exact = reinterpret_cast<ModuleLifetimeLoad>(exact_symbol->vaddr);
  const auto ordinary = reinterpret_cast<ModuleLifetimeLoad>(ordinary_symbol->vaddr);
  const auto unload = reinterpret_cast<ModuleLifetimeUnload>(unload_symbol->vaddr);
  using DebugRaise = int32_t (KYTY_SYSV_ABI *)(int32_t, const void*);
  const auto debug_raise = reinterpret_cast<DebugRaise>(debug_raise_symbol->vaddr);
  Check(debug_raise(static_cast<int32_t>(0xa0020087u), reinterpret_cast<const void*>(1)) ==
            KERNEL_ERROR_EINVAL &&
            debug_raise(static_cast<int32_t>(0xa0020087u), nullptr) == KERNEL_ERROR_ENOSYS,
        "debug-exception ABI rejects a non-null context and reports unsupported delivery");

  g_module_lifetime = {};
  int result = 0x12345678;
  const auto first = exact("//common_ex/lib/mono/2.1/mscorlib.dll.sprx", 0, nullptr,
                           0x20000, nullptr, &result);
  Check(first > 0 && result == OK && g_module_lifetime.starts[5] == 1,
        "exact Y1 path starts the provider-backed mscorlib fixture");
  result = 0x12345678;
  const auto second = ordinary("/common_ex/lib/mono/2.1/mscorlib.dll.sprx", 0,
                               nullptr, 0, nullptr, &result);
  auto* loaded = Common::Singleton<Loader::RuntimeLinker>::Instance()
                     ->FindProgramByFileName(std::filesystem::canonical(native));
  Check(second == first && result == OK && loaded != nullptr &&
            loaded->unique_id == first && g_module_lifetime.starts[5] == 1,
        "ordinary observed path reuses the exact provider identity without a second start");
  result = 0x12345678;
  Check(ordinary("//common_ex/lib/mono/2.1/mscorlib.dll.sprx", 0, nullptr, 0,
                 nullptr, &result) == KERNEL_ERROR_ENOENT &&
            result == KERNEL_ERROR_ENOENT && g_module_lifetime.starts[5] == 1,
        "unobserved double-slash ordinary path remains rejected without changing ownership");
  Check(unload(first, 0, nullptr, 0, nullptr, &result) == OK &&
            unload(second, 0, nullptr, 0, nullptr, &result) == OK &&
            g_module_lifetime.stops[5] == 1,
        "both acquisitions release the provider-backed module exactly once");

  result = 0x12345678;
  const auto reactive_first = exact("//common_ex/lib/System.Reactive.Core.dll.sprx", 0,
                                    nullptr, 0x20000, nullptr, &result);
  Check(reactive_first > 0 && result == OK && g_module_lifetime.starts[6] == 1,
        "exact Y1 path starts the provider-backed shared AOT fixture");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_NATIVE_AOT_LOAD", "") == 0,
        "disable the shared-AOT loader alias");
#else
  Check(unsetenv("KYTY_DIAGNOSTIC_PSM_NATIVE_AOT_LOAD") == 0,
        "disable the shared-AOT loader alias");
#endif
  result = 0x12345678;
  Check(ordinary("/common_ex/lib/System.Reactive.Core.dll.sprx", 0, nullptr, 0,
                 nullptr, &result) == KERNEL_ERROR_ENOENT &&
            result == KERNEL_ERROR_ENOENT && g_module_lifetime.starts[6] == 1,
        "ordinary shared-AOT alias remains inert without its production gate");
  result = 0x12345678;
  Check(ordinary("/common_ex/lib/libSceFacebook.Yoga.sprx", 0, nullptr, 0,
                 nullptr, &result) == KERNEL_ERROR_ENOENT &&
            result == KERNEL_ERROR_ENOENT && g_module_lifetime.starts[7] == 0,
        "native dependency alias remains inert without its production gate");
  result = 0x12345678;
  Check(ordinary("/common_ex/lib/libSceFollyShared.sprx", 0, nullptr, 0,
                 nullptr, &result) == KERNEL_ERROR_ENOENT &&
            result == KERNEL_ERROR_ENOENT && g_module_lifetime.starts[4] == 0,
        "RNPS dependency alias remains inert without its production gate");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_NATIVE_AOT_LOAD", "1") == 0,
        "restore the shared-AOT loader alias");
#else
  Check(setenv("KYTY_DIAGNOSTIC_PSM_NATIVE_AOT_LOAD", "1", 1) == 0,
        "restore the shared-AOT loader alias");
#endif
  result = 0x12345678;
  Check(ordinary("/common_ex/lib/Missing.Native.dll.sprx", 0, nullptr, 0,
                 nullptr, &result) == KERNEL_ERROR_ENOENT &&
            result == KERNEL_ERROR_ENOENT && g_module_lifetime.starts[6] == 1,
        "admitted shared-AOT alias preserves ENOENT for an absent provider object");

  result = 0x12345678;
  const auto yoga_first = ordinary("/common_ex/lib/libSceFacebook.Yoga.sprx", 0,
                                   nullptr, 0, nullptr, &result);
  auto* yoga_loaded = Common::Singleton<Loader::RuntimeLinker>::Instance()
                          ->FindProgramByFileName(std::filesystem::canonical(yoga));
  Check(yoga_first > 0 && result == OK && yoga_loaded != nullptr &&
            yoga_loaded->unique_id == yoga_first && g_module_lifetime.starts[7] == 1,
        "ordinary PSM DllImport loads the provider-backed native dependency");
  result = 0x12345678;
  Check(ordinary("//common_ex/lib/libSceFacebook.Yoga.sprx", 0, nullptr, 0,
                 nullptr, &result) == KERNEL_ERROR_ENOENT &&
            result == KERNEL_ERROR_ENOENT &&
            ordinary("/common_ex/lib/nested/libSceFacebook.Yoga.sprx", 0, nullptr, 0,
                     nullptr, &result) == KERNEL_ERROR_ENOENT &&
            result == KERNEL_ERROR_ENOENT &&
            ordinary("/common_ex/lib/SceFacebook.Yoga.sprx", 0, nullptr, 0,
                     nullptr, &result) == KERNEL_ERROR_ENOENT &&
            result == KERNEL_ERROR_ENOENT &&
            ordinary("/common_ex/lib/libOther.sprx", 0, nullptr, 0,
                     nullptr, &result) == KERNEL_ERROR_ENOENT &&
            result == KERNEL_ERROR_ENOENT &&
            ordinary("/common_ex/lib/mono/2.1/libSceFacebook.Yoga.sprx", 0,
                     nullptr, 0, nullptr, &result) == KERNEL_ERROR_ENOENT &&
            result == KERNEL_ERROR_ENOENT && g_module_lifetime.starts[7] == 1,
        "native dependency alias rejects slash, nesting, basename, and unrelated modules");
  Check(unload(yoga_first, 0, nullptr, 0, nullptr, &result) == OK &&
            g_module_lifetime.stops[7] == 1,
        "native PSM dependency releases its provider-backed lifecycle once");

  // ShellUI has Folly as a DT_NEEDED of libNativeExtensions before RNPS asks for it again.
  result = 0x12345678;
  const auto folly_needed = ordinary("/system_ex/common_ex/lib/libSceFollyShared.sprx", 0,
                                     nullptr, 0, nullptr, &result);
  Check(folly_needed > 0 && result == OK && g_module_lifetime.starts[4] == 1,
        "system_ex path loads the provider-backed Folly fixture");
  result = 0x12345678;
  const auto folly_rnps = ordinary("/common_ex/lib/libSceFollyShared.sprx", 0, nullptr, 0,
                                   nullptr, &result);
  auto* folly_loaded = Common::Singleton<Loader::RuntimeLinker>::Instance()
                           ->FindProgramByFileName(std::filesystem::canonical(folly));
  Check(folly_rnps == folly_needed && result == OK && folly_loaded != nullptr &&
            folly_loaded->unique_id == folly_needed && g_module_lifetime.starts[4] == 1,
        "RNPS sandbox path reuses the loaded Folly identity without a second start");
  result = 0x12345678;
  const auto jsi = ordinary("/common_ex/lib/libSceJsi-0.70.sprx", 0, nullptr, 0, nullptr,
                            &result);
  Check(jsi > 0 && result == OK && g_module_lifetime.starts[3] == 1,
        "RNPS sandbox path loads Jsi");
  result = 0x12345678;
  const auto hermes = ordinary("/common_ex/lib/libhermes-0.11.sprx", 0, nullptr, 0, nullptr,
                               &result);
  Check(hermes > 0 && result == OK && g_module_lifetime.starts[2] == 1,
        "RNPS sandbox path loads Hermes");
  result = 0x12345678;
  Check(ordinary("/common_ex/lib/libhermesRemoteInspector.sprx", 0, nullptr, 0,
                 nullptr, &result) == KERNEL_ERROR_ENOENT &&
            result == KERNEL_ERROR_ENOENT &&
            ordinary("//common_ex/lib/libSceFollyShared.sprx", 0, nullptr, 0,
                     nullptr, &result) == KERNEL_ERROR_ENOENT &&
            result == KERNEL_ERROR_ENOENT &&
            ordinary("/common_ex/lib/mono/2.1/libSceJsi-0.70.sprx", 0, nullptr, 0,
                     nullptr, &result) == KERNEL_ERROR_ENOENT &&
            result == KERNEL_ERROR_ENOENT && g_module_lifetime.starts[1] == 0 &&
            g_module_lifetime.starts[3] == 1,
        "RNPS alias leaves the debugger-only inspector, slash and mono variants unadmitted");
  Check(unload(folly_rnps, 0, nullptr, 0, nullptr, &result) == OK &&
            g_module_lifetime.stops[4] == 0 &&
            unload(folly_needed, 0, nullptr, 0, nullptr, &result) == OK &&
            g_module_lifetime.stops[4] == 1 &&
            unload(jsi, 0, nullptr, 0, nullptr, &result) == OK &&
            unload(hermes, 0, nullptr, 0, nullptr, &result) == OK &&
            g_module_lifetime.stops[3] == 1 && g_module_lifetime.stops[2] == 1,
        "RNPS dependencies release once per module after every acquisition");
  result = 0x12345678;
  const auto reactive_second = ordinary("/common_ex/lib/System.Reactive.Core.dll.sprx", 0,
                                        nullptr, 0, nullptr, &result);
  auto* reactive_loaded = Common::Singleton<Loader::RuntimeLinker>::Instance()
                              ->FindProgramByFileName(std::filesystem::canonical(reactive));
  Check(reactive_second == reactive_first && result == OK && reactive_loaded != nullptr &&
            reactive_loaded->unique_id == reactive_first && g_module_lifetime.starts[6] == 1,
        "ordinary observed shared-AOT path reuses the exact provider identity without a second start");
  const auto reactive_address = reactive_loaded->base_vaddr;
  result = 0x12345678;
  Check(ordinary("//common_ex/lib/System.Reactive.Core.dll.sprx", 0, nullptr, 0,
                 nullptr, &result) == KERNEL_ERROR_ENOENT &&
            result == KERNEL_ERROR_ENOENT && g_module_lifetime.starts[6] == 1,
        "unobserved shared-AOT slash variant remains rejected without changing ownership");
  result = 0x12345678;
  Check(ordinary("/common_ex/lib/nested/System.Reactive.Core.dll.sprx", 0, nullptr, 0,
                 nullptr, &result) == KERNEL_ERROR_ENOENT &&
            result == KERNEL_ERROR_ENOENT && g_module_lifetime.starts[6] == 1,
        "nested shared-AOT path remains outside the loader alias");
  result = 0x12345678;
  Check(ordinary("/common_ex/lib/System.Reactive.Core.dll.sprx.extra", 0, nullptr, 0,
                 nullptr, &result) == KERNEL_ERROR_ENOENT &&
            result == KERNEL_ERROR_ENOENT && g_module_lifetime.starts[6] == 1,
        "shared-AOT alias rejects a non-sprx suffix");
  Check(unload(reactive_first, 0, nullptr, 0, nullptr, &result) == OK &&
            unload(reactive_second, 0, nullptr, 0, nullptr, &result) == OK &&
            g_module_lifetime.stops[6] == 1 &&
            Common::Singleton<Loader::RuntimeLinker>::Instance()
                    ->FindProgramByFileName(std::filesystem::canonical(reactive)) == nullptr,
        "shared-AOT acquisitions release the provider-backed module exactly once");
  CheckModuleLifetimeUnmapped(reactive_first, reactive_address);
  Check(DirectoryPassthrough::Unmount("/system_ex") == OK,
        "remove exact mscorlib provider fixture");
}

void CheckModuleLifetimeUnmapped(int32_t handle, uint64_t address) {
  auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
  Check(linker->FindProgramById(handle) == nullptr &&
            linker->FindProgramByAddr(address) == nullptr,
        "released module is absent from loader identities and mappings");
  Libs::LibKernel::Memory::VirtualQueryInfo query {};
  const auto result = Libs::LibKernel::Memory::KernelVirtualQuery(
      reinterpret_cast<const void*>(address), 0, &query, sizeof(query));
  Check(result != 0 || !query.is_committed ||
            query.start > address || query.end <= address,
        "released module no longer owns committed guest memory");
}

void CheckModuleLifetimes(const std::filesystem::path& root) {
  using namespace Libs::LibKernel;
  const auto directory = root / "module_lifetime";
  Check(std::filesystem::create_directory(directory),
        "create module lifetime fixture directory");
  WriteModuleLifetimeElf(directory / "lifetime_provider.sprx", 1);
  WriteModuleLifetimeElf(directory / "lifetime_owner.sprx", 2,
                         "lifetime_provider.sprx");
  WriteModuleLifetimeElf(directory / "lifetime_dynamic.sprx", 3);
  WriteModuleLifetimeElf(directory / "lifetime_first.sprx", 3);
  WriteModuleLifetimeElf(directory / "lifetime_peer.sprx", 4);
  WriteModuleLifetimeElf(directory / "lifetime_mutator.sprx", 5);
  WriteModuleLifetimeElf(directory / "lifetime_unstarted.sprx", 6);
  WriteModuleLifetimeElf(directory / "lifetime_failed.sprx", 7);
  WriteModuleLifetimeElf(directory / "lifetime_concurrent.sprx", 4);
  WriteModuleLifetimeElf(directory / "lifetime_concurrent_failed.sprx", 7);
  WriteModuleLifetimeElf(directory / "lifetime_cycle_a.sprx", 4);
  WriteModuleLifetimeElf(directory / "lifetime_cycle_b.sprx", 6);
  Check(FileSystem::GetRealFilename("/app0/sce_module").empty(),
        "module fixture mount does not shadow another mapping");
  FileSystem::MountReadOnly(directory, "/app0/sce_module");

  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* load_symbol =
      symbols.FindByNid("wzvqT4UqKX8", Loader::SymbolType::Func);
  const auto* unload_symbol =
      symbols.FindByNid("QKd0qM58Qes", Loader::SymbolType::Func);
  Check(load_symbol != nullptr && unload_symbol != nullptr,
        "module lifetime exports resolve");
  g_module_lifetime_load =
      reinterpret_cast<ModuleLifetimeLoad>(load_symbol->vaddr);
  g_module_lifetime_unload =
      reinterpret_cast<ModuleLifetimeUnload>(unload_symbol->vaddr);
  auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();

  g_module_lifetime = {};
  auto* owner = linker->LoadProgram(directory / "lifetime_owner.sprx");
  linker->LoadNeededModules(owner);
  auto* provider =
      linker->FindProgramByFileName(directory / "lifetime_provider.sprx");
  Check(provider != nullptr, "DT_NEEDED loads the provider ELF");
  const auto owner_handle = owner->unique_id;
  const auto owner_address = owner->base_vaddr;
  g_module_lifetime.provider_handle = provider->unique_id;
  g_module_lifetime.provider_base = provider->base_vaddr;
  g_module_lifetime.check_provider_on_owner_stop = true;
  linker->LoadNeededModules(owner);
  Check(linker->FindProgramByFileName(directory / "lifetime_provider.sprx") ==
            provider,
        "repeated dependency discovery reuses the provider");
  linker->RelocateAll();
  Check(linker->StartModule(provider, 0, nullptr, nullptr) == 0 &&
            linker->StartModule(owner, 0, nullptr, nullptr) == 0,
        "native provider and owner initializers execute");
  CheckModuleLifetimeProvider();

  int result = -1;
  const auto first = g_module_lifetime_load(
      "/app0/sce_module/lifetime_provider.sprx", 0, nullptr, 0, nullptr, &result);
  Check(first == g_module_lifetime.provider_handle && result == 0,
        "dynamic acquisition returns the existing DT_NEEDED provider");
  const auto second = g_module_lifetime_load(
      "/app0/sce_module/lifetime_provider.sprx", 0, nullptr, 0, nullptr, &result);
  Check(second == first && g_module_lifetime.starts[1] == 1,
        "repeated dynamic acquisition does not rerun provider initialization");
  Check(g_module_lifetime_unload(first, 0, nullptr, 0, nullptr, &result) == 0,
        "first balanced provider release succeeds");
  CheckModuleLifetimeProvider();
  Check(g_module_lifetime_unload(second, 0, nullptr, 0, nullptr, &result) == 0,
        "last balanced dynamic release retains the startup dependency");
  CheckModuleLifetimeProvider();
  Check(g_module_lifetime_unload(second, 0, nullptr, 0, nullptr, &result) ==
            KERNEL_ERROR_EBUSY,
        "unbalanced release cannot unload a still-needed provider");
  CheckModuleLifetimeProvider();

  linker->StopAllModules();
  Check(g_module_lifetime.order == std::vector<int>({1, 2, -2, -1}),
        "owner finalizes with its provider alive in reverse start order");
  linker->StopAllModules();
  Check(g_module_lifetime.stops[1] == 1 && g_module_lifetime.stops[2] == 1,
        "process module finalization runs each initializer's fini once");
  const auto provider_handle = g_module_lifetime.provider_handle;
  const auto provider_address = g_module_lifetime.provider_base;
  linker->Clear();
  CheckModuleLifetimeUnmapped(owner_handle, owner_address);
  CheckModuleLifetimeUnmapped(provider_handle, provider_address);

  g_module_lifetime = {};
  const auto dynamic = g_module_lifetime_load(
      "/app0/sce_module/lifetime_dynamic.sprx", 0, nullptr, 0, nullptr, &result);
  Check(dynamic > 0 && result == 0 && g_module_lifetime.starts[3] == 1,
        "dynamic-only ELF initializes through the public load export");
  auto* dynamic_program = linker->FindProgramById(dynamic);
  Check(dynamic_program != nullptr, "dynamic-only module has a mapping");
  const auto dynamic_address = dynamic_program->base_vaddr;
  Check(g_module_lifetime_load("/app0/sce_module/lifetime_dynamic.sprx", 0,
                               nullptr, 0, nullptr, &result) == dynamic &&
            g_module_lifetime.starts[3] == 1,
        "dynamic-only module shares repeated acquisitions");
  Check(g_module_lifetime_unload(dynamic, 0, nullptr, 0, nullptr, &result) == 0 &&
            linker->FindProgramById(dynamic) != nullptr &&
            g_module_lifetime.stops[3] == 0,
        "nonfinal acquisition release preserves the dynamic module");
  Check(g_module_lifetime_unload(dynamic, 0, nullptr, 0, nullptr, &result) == 0 &&
            result == 0 && g_module_lifetime.stops[3] == 1,
        "final acquisition release runs the module finalizer");
  CheckModuleLifetimeUnmapped(dynamic, dynamic_address);
  Check(g_module_lifetime_unload(dynamic, 0, nullptr, 0, nullptr, &result) ==
            KERNEL_ERROR_ESRCH,
        "stale module handle reports ESRCH");
  Check(g_module_lifetime_load("/app0/sce_module/lifetime_missing.sprx", 0,
                               nullptr, 0, nullptr, &result) ==
            KERNEL_ERROR_ENOENT && result == KERNEL_ERROR_ENOENT,
        "missing dynamic module has no successful handle");
  linker->StopAllModules();
  Check(g_module_lifetime.order == std::vector<int>({3, -3}),
        "unloaded dynamic module is not finalized again");
  linker->Clear();

  g_module_lifetime = {};
  g_module_lifetime.negative_stop_id = 3;
  const auto negative_stop = g_module_lifetime_load(
      "/app0/sce_module/lifetime_dynamic.sprx", 0, nullptr, 0, nullptr, &result);
  Check(negative_stop > 0 && result == 0,
        "negative finalizer fixture loads through the public export");
  const auto negative_address = linker->FindProgramById(negative_stop)->base_vaddr;
  result = 117;
  Check(g_module_lifetime_unload(negative_stop, 0, nullptr, 0, nullptr, &result) == 0 &&
            result == -53 && g_module_lifetime.stops[3] == 1,
        "negative finalizer result propagates while successful unload completes");
  CheckModuleLifetimeUnmapped(negative_stop, negative_address);
  linker->StopAllModules();
  Check(g_module_lifetime.stops[3] == 1,
        "negative finalizer is consumed once before process shutdown");
  Check(g_module_lifetime_unload(negative_stop, 0, nullptr, 0, nullptr, &result) ==
            KERNEL_ERROR_ESRCH && result == -53,
        "stale unload preserves the caller result after negative finalization");
  linker->Clear();

  const auto negative_repeat = g_module_lifetime_load(
      "/app0/sce_module/lifetime_dynamic.sprx", 0, nullptr, 0, nullptr, &result);
  Check(negative_repeat > 0 && result == 0,
        "negative finalizer fixture can be loaded again after unload");
  const auto repeated_address = linker->FindProgramById(negative_repeat)->base_vaddr;
  Check(g_module_lifetime_unload(0, 0, nullptr, 0, nullptr, &result) ==
            KERNEL_ERROR_EINVAL && result == 0 &&
            linker->FindProgramById(negative_repeat)->load_count == 1,
        "zero module handle fails before lookup without releasing another module");
  Check(g_module_lifetime_unload(negative_repeat, 0, nullptr, 1, nullptr, &result) ==
            KERNEL_ERROR_EINVAL && result == 0 &&
            linker->FindProgramById(negative_repeat)->load_count == 1 &&
            g_module_lifetime.stops[3] == 1,
        "unsupported unload flags fail without releasing or finalizing");
  const uint64_t unused_option = 0;
  Check(g_module_lifetime_unload(negative_repeat, 0, nullptr, 0, &unused_option, &result) ==
            KERNEL_ERROR_EINVAL && result == 0 &&
            linker->FindProgramById(negative_repeat)->load_count == 1 &&
            g_module_lifetime.stops[3] == 1,
        "unsupported unload options fail without dereference or mutation");
  Check(g_module_lifetime_unload(negative_repeat, 0, nullptr, 0, nullptr, nullptr) == 0 &&
            g_module_lifetime.stops[3] == 2,
        "negative finalization unloads normally with a null result pointer");
  CheckModuleLifetimeUnmapped(negative_repeat, repeated_address);
  linker->Clear();
  std::printf("ModuleLifetimeTests: negative native finalizer result and successful unload passed\n");

  g_module_lifetime = {};
  g_module_lifetime.fail_start_id = 7;
  g_module_lifetime.failed_path = directory / "lifetime_failed.sprx";
  Check(g_module_lifetime_load("/app0/sce_module/lifetime_failed.sprx", 0,
                               nullptr, 0, nullptr, &result) ==
            KERNEL_ERROR_ESTART && result == -37,
        "failed native initializer returns ESTART and its exact result");
  Check(g_module_lifetime.order == std::vector<int>({7, -7}) &&
            g_module_lifetime.failed_handle > 0,
        "failed native initializer receives its required cleanup finalizer");
  CheckModuleLifetimeUnmapped(g_module_lifetime.failed_handle,
                              g_module_lifetime.failed_address);
  linker->StopAllModules();
  Check(g_module_lifetime.stops[7] == 1,
        "failed-start finalizer is consumed once before process shutdown");
  linker->Clear();

  g_module_lifetime = {};
  g_module_lifetime.recursive_start_id = 4;
  g_module_lifetime.recursive_path =
      "/app0/sce_module/lifetime_concurrent.sprx";
  ArmModuleLifetimeStartGate(4);
  auto successful_first = std::async(std::launch::async, [&] {
    int start_result = 117;
    const auto handle = g_module_lifetime_load(
        "/app0/sce_module/lifetime_concurrent.sprx", 0, nullptr, 0, nullptr,
        &start_result);
    return std::pair<int32_t, int> {handle, start_result};
  });
  WaitForModuleLifetimeStartGate();
  std::promise<void> successful_second_called;
  auto successful_second_called_future = successful_second_called.get_future();
  auto successful_second = std::async(std::launch::async, [&] {
    successful_second_called.set_value();
    int start_result = 117;
    const auto handle = g_module_lifetime_load(
        "/app0/sce_module/lifetime_concurrent.sprx", 0, nullptr, 0, nullptr,
        &start_result);
    return std::pair<int32_t, int> {handle, start_result};
  });
  successful_second_called_future.wait();
  Check(successful_second.wait_for(std::chrono::milliseconds(250)) ==
            std::future_status::timeout,
        "parallel acquisition waits for the initializer result");
  ReleaseModuleLifetimeStartGate();
  const auto successful_first_result = successful_first.get();
  auto* concurrent_program =
      linker->FindProgramById(successful_first_result.first);
  Check(successful_first_result.first > 0 &&
            successful_first_result.second == 0 &&
            concurrent_program != nullptr && concurrent_program->load_count == 2 &&
            g_module_lifetime.starts[4] == 1 &&
            g_module_lifetime.recursive_handle == KERNEL_ERROR_EBUSY &&
            g_module_lifetime.recursive_result == KERNEL_ERROR_EBUSY,
        "successful initialization reserves the waiting acquisition and rejects same-thread recursion");
  const auto concurrent_address = concurrent_program->base_vaddr;
  Check(g_module_lifetime_unload(successful_first_result.first, 0, nullptr, 0,
                                 nullptr, &result) == 0 &&
            linker->FindProgramById(successful_first_result.first) != nullptr &&
            concurrent_program->load_count == 1 && g_module_lifetime.stops[4] == 0,
        "initializer caller can release immediately without invalidating the waiting acquisition");
  const auto successful_second_result = successful_second.get();
  Check(successful_second_result.first == successful_first_result.first &&
            successful_second_result.second == 0 &&
            linker->FindProgramById(successful_second_result.first) == concurrent_program,
        "waiting acquisition consumes its reserved live handle after initialization");
  Check(g_module_lifetime_unload(successful_second_result.first, 0, nullptr, 0,
                                 nullptr, &result) == 0 &&
            g_module_lifetime.stops[4] == 1 &&
            g_module_lifetime.order == std::vector<int>({4, -4}),
        "last concurrent acquisition finalizes the module once");
  CheckModuleLifetimeUnmapped(successful_first_result.first,
                              concurrent_address);
  linker->Clear();

  g_module_lifetime = {};
  g_module_lifetime.fail_start_id = 7;
  g_module_lifetime.failed_path =
      directory / "lifetime_concurrent_failed.sprx";
  ArmModuleLifetimeStartGate(7);
  auto failed_first = std::async(std::launch::async, [&] {
    int start_result = 117;
    const auto handle = g_module_lifetime_load(
        "/app0/sce_module/lifetime_concurrent_failed.sprx", 0, nullptr, 0,
        nullptr, &start_result);
    return std::pair<int32_t, int> {handle, start_result};
  });
  WaitForModuleLifetimeStartGate();
  std::promise<void> failed_second_called;
  auto failed_second_called_future = failed_second_called.get_future();
  auto failed_second = std::async(std::launch::async, [&] {
    failed_second_called.set_value();
    int start_result = 117;
    const auto handle = g_module_lifetime_load(
        "/app0/sce_module/lifetime_concurrent_failed.sprx", 0, nullptr, 0,
        nullptr, &start_result);
    return std::pair<int32_t, int> {handle, start_result};
  });
  failed_second_called_future.wait();
  Check(failed_second.wait_for(std::chrono::milliseconds(250)) ==
            std::future_status::timeout,
        "parallel acquisition waits while the initializer can still fail");
  ReleaseModuleLifetimeStartGate();
  const auto failed_first_result = failed_first.get();
  const auto failed_second_result = failed_second.get();
  Check(failed_first_result.first == KERNEL_ERROR_ESTART &&
            failed_second_result.first == KERNEL_ERROR_ESTART &&
            failed_first_result.second == -37 &&
            failed_second_result.second == -37 &&
            g_module_lifetime.starts[7] == 1 &&
            g_module_lifetime.stops[7] == 1 &&
            g_module_lifetime.order == std::vector<int>({7, -7}) &&
            g_module_lifetime.failed_handle > 0,
        "failed initialization publishes ESTART only after one cleanup and preserves its result");
  CheckModuleLifetimeUnmapped(g_module_lifetime.failed_handle,
                              g_module_lifetime.failed_address);
  linker->StopAllModules();
  Check(g_module_lifetime.stops[7] == 1,
        "failed concurrent initialization leaves no dangling process module");
  linker->Clear();
  ArmModuleLifetimeStartGate(0);

  g_module_lifetime = {};
  ArmModuleLifetimeCycleGate(
      4, "/app0/sce_module/lifetime_cycle_b.sprx", 6,
      "/app0/sce_module/lifetime_cycle_a.sprx");
  auto cycle_a = std::async(std::launch::async, [&] {
    int start_result = 117;
    const auto handle = g_module_lifetime_load(
        "/app0/sce_module/lifetime_cycle_a.sprx", 0, nullptr, 0, nullptr,
        &start_result);
    return std::pair<int32_t, int> {handle, start_result};
  });
  auto cycle_b = std::async(std::launch::async, [&] {
    int start_result = 117;
    const auto handle = g_module_lifetime_load(
        "/app0/sce_module/lifetime_cycle_b.sprx", 0, nullptr, 0, nullptr,
        &start_result);
    return std::pair<int32_t, int> {handle, start_result};
  });
  Check(cycle_a.wait_for(std::chrono::seconds(5)) == std::future_status::ready &&
            cycle_b.wait_for(std::chrono::seconds(5)) == std::future_status::ready,
        "cross-module initializer cycle completes without a deadlock");
  const auto cycle_a_result = cycle_a.get();
  const auto cycle_b_result = cycle_b.get();
  {
    std::lock_guard lock(g_module_lifetime_cycle_gate.mutex);
    Check(cycle_a_result.first > 0 && cycle_a_result.second == 0 &&
              cycle_b_result.first > 0 && cycle_b_result.second == 0 &&
              g_module_lifetime_cycle_gate.handles[4] == KERNEL_ERROR_EBUSY &&
              g_module_lifetime_cycle_gate.results[4] == KERNEL_ERROR_EBUSY &&
              g_module_lifetime_cycle_gate.handles[6] == KERNEL_ERROR_EBUSY &&
              g_module_lifetime_cycle_gate.results[6] == KERNEL_ERROR_EBUSY,
          "cross-module concurrent initializer cycle fails closed without waiting");
  }
  ResetModuleLifetimeCycleGate();
  Check(g_module_lifetime_unload(cycle_a_result.first, 0, nullptr, 0, nullptr,
                                 &result) == 0 &&
            g_module_lifetime_unload(cycle_b_result.first, 0, nullptr, 0, nullptr,
                                     &result) == 0,
        "cycle fixtures retain balanced top-level acquisitions");
  linker->Clear();

  g_module_lifetime = {};
  const auto fini_owner = g_module_lifetime_load(
      "/app0/sce_module/lifetime_cycle_a.sprx", 0, nullptr, 0, nullptr,
      &result);
  Check(fini_owner > 0 && result == 0,
        "finalizer recursion owner initializes before the target");
  const auto fini_owner_address = linker->FindProgramById(fini_owner)->base_vaddr;
  g_module_lifetime.recursive_stop_id = 4;
  g_module_lifetime.recursive_stop_path =
      "/app0/sce_module/lifetime_cycle_b.sprx";
  ArmModuleLifetimeStartGate(6);
  auto fini_target = std::async(std::launch::async, [&] {
    int start_result = 117;
    const auto handle = g_module_lifetime_load(
        "/app0/sce_module/lifetime_cycle_b.sprx", 0, nullptr, 0, nullptr,
        &start_result);
    return std::pair<int32_t, int> {handle, start_result};
  });
  WaitForModuleLifetimeStartGate();
  Check(g_module_lifetime_unload(fini_owner, 0, nullptr, 0, nullptr, &result) == 0 &&
            result == 0 &&
            g_module_lifetime.recursive_stop_handle == KERNEL_ERROR_EBUSY &&
            g_module_lifetime.recursive_stop_result == KERNEL_ERROR_EBUSY,
        "finalizer recursive load cannot wait while the outer lifecycle lock is held");
  CheckModuleLifetimeUnmapped(fini_owner, fini_owner_address);
  ReleaseModuleLifetimeStartGate();
  Check(fini_target.wait_for(std::chrono::seconds(5)) == std::future_status::ready,
        "finalizer recursion target completes without a recursive-lock deadlock");
  const auto fini_target_result = fini_target.get();
  Check(fini_target_result.first > 0 && fini_target_result.second == 0,
        "finalizer recursion target completes after the outer unload");
  const auto fini_target_address =
      linker->FindProgramById(fini_target_result.first)->base_vaddr;
  Check(g_module_lifetime_unload(fini_target_result.first, 0, nullptr, 0,
                                 nullptr, &result) == 0,
        "finalizer recursion target keeps its top-level acquisition");
  CheckModuleLifetimeUnmapped(fini_target_result.first, fini_target_address);
  linker->Clear();
  ArmModuleLifetimeStartGate(0);
  std::printf("ModuleLifetimeTests: concurrent_start_success=pass concurrent_start_failure=pass recursive_start_busy=pass cross_module_cycle_busy=pass finalizer_recursive_wait_busy=pass\n");

  g_module_lifetime = {};
  auto* first_program = linker->LoadProgram(directory / "lifetime_first.sprx");
  auto* peer = linker->LoadProgram(directory / "lifetime_peer.sprx");
  auto* mutator = linker->LoadProgram(directory / "lifetime_mutator.sprx");
  auto* unstarted =
      linker->LoadProgram(directory / "lifetime_unstarted.sprx");
  const auto first_handle = first_program->unique_id;
  const auto first_address = first_program->base_vaddr;
  const auto peer_handle = peer->unique_id;
  const auto peer_address = peer->base_vaddr;
  const auto mutator_handle = mutator->unique_id;
  const auto mutator_address = mutator->base_vaddr;
  const auto unstarted_handle = unstarted->unique_id;
  const auto unstarted_address = unstarted->base_vaddr;
  linker->RelocateAll();
  Check(linker->StartModule(peer, 0, nullptr, nullptr) == 0 &&
            linker->StartModule(first_program, 0, nullptr, nullptr) == 0 &&
            linker->StartModule(mutator, 0, nullptr, nullptr) == 0,
        "fixture initialization order differs from ELF load order");
  Check(g_module_lifetime_load("/app0/sce_module/lifetime_peer.sprx", 0,
                               nullptr, 0, nullptr, &result) == peer_handle,
        "shutdown peer owns a balanced dynamic acquisition");
  g_module_lifetime.release_during_stop = peer_handle;
  linker->StopAllModules();
  Check(g_module_lifetime.released_during_stop &&
            g_module_lifetime.order == std::vector<int>({4, 3, 5, -5, -4, -3}),
        "shutdown snapshots start order across finalizer-driven unload");
  CheckModuleLifetimeUnmapped(peer_handle, peer_address);
  linker->StopAllModules();
  Check(g_module_lifetime.stops[3] == 1 &&
            g_module_lifetime.stops[4] == 1 &&
            g_module_lifetime.stops[5] == 1 &&
            g_module_lifetime.stops[6] == 0,
        "shutdown skips an unstarted module and already finalized peers");
  linker->Clear();
  CheckModuleLifetimeUnmapped(first_handle, first_address);
  CheckModuleLifetimeUnmapped(mutator_handle, mutator_address);
  CheckModuleLifetimeUnmapped(unstarted_handle, unstarted_address);

  const auto alias_lower_directory = directory / "alias_lower";
  Check(std::filesystem::create_directory(alias_lower_directory),
        "create lower-priority dependency fixture directory");
  Check(FileSystem::GetRealFilename("/system/common/lib").empty(),
        "dependency fixture does not shadow a system library mapping");
  const auto alias_lower_path = alias_lower_directory / "lifetime_alias.sprx";
  const auto alias_higher_path = directory / "lifetime_alias.sprx";
  WriteModuleLifetimeElf(alias_lower_path, 1, nullptr, false, true);
  WriteModuleLifetimeElf(directory / "lifetime_alias_owner.sprx", 2,
                         "lifetime_alias.prx");
  FileSystem::MountReadOnly(alias_lower_directory, "/system/common/lib");
  auto* alias_owner = linker->LoadProgram(directory / "lifetime_alias_owner.sprx");
  linker->LoadNeededModules(alias_owner);
  auto* alias_lower = linker->FindProgramByFileName(alias_lower_path);
  Check(alias_lower != nullptr &&
            alias_lower->elf->GetDynValue(Loader::DT_SONAME) == nullptr &&
            alias_lower->dynamic_info->so_name != nullptr &&
            alias_lower->dynamic_info->so_name[0] == '\0' &&
            alias_owner->needed_modules.size() == 1 &&
            alias_owner->needed_modules[0].name == "lifetime_alias.prx" &&
            alias_owner->needed_modules[0].provider == alias_lower,
        "DT_NEEDED name binds through .prx alias to an absent-SONAME provider");
  WriteModuleLifetimeElf(alias_higher_path, 4, nullptr, false, true);
  auto* alias_higher = linker->LoadProgram(alias_higher_path);
  Check(alias_higher != nullptr && alias_higher != alias_lower &&
            alias_higher->elf->GetDynValue(Loader::DT_SONAME) == nullptr &&
            alias_higher->dynamic_info->so_name != nullptr &&
            alias_higher->dynamic_info->so_name[0] == '\0' &&
            FileSystem::GetRealFilename("/app0/sce_module/lifetime_alias.sprx") ==
                alias_higher_path,
        "later same-basename provider is loaded at a higher-priority resolver path");
  Check(alias_owner->needed_modules.size() == 1 &&
            alias_owner->needed_modules[0].name == "lifetime_alias.prx" &&
            alias_owner->needed_modules[0].provider == alias_lower,
        "incremental refresh preserves the first exact-name provider binding");
  linker->LoadNeededModules(alias_owner);
  Check(alias_owner->needed_modules.size() == 1 &&
            alias_owner->needed_modules[0].name == "lifetime_alias.prx" &&
            alias_owner->needed_modules[0].provider == alias_lower &&
            linker->FindProgramById(alias_lower->unique_id) == alias_lower &&
            linker->FindProgramById(alias_higher->unique_id) == alias_higher,
        "repeated dependency discovery neither duplicates nor redirects a selected provider");
  const std::array<std::pair<int32_t, uint64_t>, 3> alias_mappings {{
      {alias_owner->unique_id, alias_owner->base_vaddr},
      {alias_lower->unique_id, alias_lower->base_vaddr},
      {alias_higher->unique_id, alias_higher->base_vaddr}}};
  linker->Clear();
  for (const auto& [handle, address]: alias_mappings) {
    CheckModuleLifetimeUnmapped(handle, address);
  }
  FileSystem::Umount("/system/common/lib");
  std::printf("ModuleLifetimeTests: absent-SONAME .prx alias preserves selected provider passed\n");

  const auto passthrough_directory = directory / "passthrough";
  const auto passthrough_lib = passthrough_directory / "common" / "lib";
  Check(std::filesystem::create_directories(passthrough_lib),
        "create read-only passthrough dependency directory");
  const auto passthrough_path = passthrough_lib / "lifetime_passthrough.sprx";
  const auto passthrough_owner_path = directory / "lifetime_passthrough_owner.sprx";
  const auto escape_path = passthrough_directory / "common" / "lifetime_escape.sprx";
  const auto escape_owner_path = directory / "lifetime_escape_owner.sprx";
  WriteModuleLifetimeElf(passthrough_path, 8);
  WriteModuleLifetimeElf(passthrough_owner_path, 9, "lifetime_passthrough.prx");
  WriteModuleLifetimeElf(escape_path, 10);
  WriteModuleLifetimeElf(escape_owner_path, 11, "../lifetime_escape.prx");
  Check(DirectoryPassthrough::Mount("/system", passthrough_directory) == OK &&
            FileSystem::GetRealFilename("/system/common/lib/lifetime_passthrough.sprx").empty(),
        "publish a read-only dependency provider without exposing its host path through the VFS");
  auto* passthrough_owner = linker->LoadProgram(passthrough_owner_path);
  linker->LoadNeededModules(passthrough_owner);
  auto* passthrough_provider = linker->FindProgramByFileName(passthrough_path);
  Check(passthrough_provider != nullptr && passthrough_owner->needed_modules.size() == 1 &&
            passthrough_owner->needed_modules[0].name == "lifetime_passthrough.prx" &&
            passthrough_owner->needed_modules[0].provider == passthrough_provider,
        "DT_NEEDED resolves a module through the contained read-only provider");
  auto* escape_owner = linker->LoadProgram(escape_owner_path);
  linker->LoadNeededModules(escape_owner);
  Check(escape_owner->needed_modules.empty() && linker->FindProgramByFileName(escape_path) == nullptr,
        "DT_NEEDED cannot traverse outside the fixed library search directory");
  const auto passthrough_owner_handle = passthrough_owner->unique_id;
  const auto passthrough_owner_address = passthrough_owner->base_vaddr;
  const auto passthrough_provider_handle = passthrough_provider->unique_id;
  const auto passthrough_provider_address = passthrough_provider->base_vaddr;
  const auto escape_owner_handle = escape_owner->unique_id;
  const auto escape_owner_address = escape_owner->base_vaddr;
  linker->Clear();
  CheckModuleLifetimeUnmapped(passthrough_owner_handle, passthrough_owner_address);
  CheckModuleLifetimeUnmapped(passthrough_provider_handle, passthrough_provider_address);
  CheckModuleLifetimeUnmapped(escape_owner_handle, escape_owner_address);
  Check(DirectoryPassthrough::Unmount("/system") == OK,
        "remove the read-only dependency provider");
  std::printf("ModuleLifetimeTests: read-only provider DT_NEEDED resolution passed\n");

  const auto snapshot_a_directory = directory / "snapshot_provider_a";
  const auto snapshot_b_directory = directory / "snapshot_provider_b";
  const auto snapshot_relative = std::filesystem::path("common_ex") / "lib" /
                                 "lifetime_snapshot_provider.sprx";
  Check(std::filesystem::create_directories(snapshot_a_directory / "common_ex" / "lib") &&
            std::filesystem::create_directories(snapshot_b_directory / "common_ex" / "lib"),
        "create isolated snapshot provider roots");
  const auto snapshot_a_path = snapshot_a_directory / snapshot_relative;
  const auto snapshot_b_path = snapshot_b_directory / snapshot_relative;
  const auto snapshot_owner_path = directory / "lifetime_snapshot_owner.sprx";
  WriteModuleLifetimeElf(snapshot_a_path, 5);
  WriteModuleLifetimeElf(snapshot_b_path, 6);
  WriteModuleLifetimeElf(snapshot_owner_path, 7, "lifetime_snapshot_provider.sprx");
  Check(DirectoryPassthrough::Mount("/snapshot-provider", snapshot_a_directory) == OK,
        "mount provider A for a pinned module snapshot");
  DirectoryPassthrough::FileSnapshot pinned_snapshot;
  Check(DirectoryPassthrough::OpenFileSnapshot(
            "/snapshot-provider/common_ex/lib/lifetime_snapshot_provider.sprx",
            &pinned_snapshot) == OK && pinned_snapshot.handle != nullptr &&
            pinned_snapshot.host_path == std::filesystem::canonical(snapshot_a_path),
        "capture provider A with its canonical identity and live mount generation");
  Check(DirectoryPassthrough::Unmount("/snapshot-provider") == OK &&
            DirectoryPassthrough::Mount("/snapshot-provider", snapshot_b_directory) == OK,
        "replace the guest provider namespace with provider B");
  DirectoryPassthrough::FileSnapshot remounted_snapshot;
  Check(DirectoryPassthrough::OpenFileSnapshot(
            "/snapshot-provider/common_ex/lib/lifetime_snapshot_provider.sprx",
            &remounted_snapshot) == OK && remounted_snapshot.handle != nullptr &&
            remounted_snapshot.host_path == std::filesystem::canonical(snapshot_b_path) &&
            remounted_snapshot.bytes != pinned_snapshot.bytes,
        "remounted guest pathname resolves distinct provider B bytes");
  pinned_snapshot.handle.reset();
  WriteModuleLifetimeElf(snapshot_a_path, 6);
  g_module_lifetime = {};
  auto* snapshot_program = linker->LoadProgram(
      pinned_snapshot.host_path, std::move(pinned_snapshot.bytes));
  Check(snapshot_program != nullptr &&
            snapshot_program->file_name == std::filesystem::canonical(snapshot_a_path),
        "memory-backed loader preserves provider A canonical identity");
  linker->RelocateProgram(snapshot_program);
  const auto snapshot_handle = snapshot_program->unique_id;
  const auto snapshot_address = snapshot_program->base_vaddr;
  Check(linker->AcquireProgram(snapshot_program) == OK &&
            linker->StartModule(snapshot_program, 0, nullptr, nullptr) == OK &&
            g_module_lifetime.starts[5] == 1 && g_module_lifetime.starts[6] == 0,
        "module load consumes captured provider A bytes after its disk path and guest mount select B");
  Check(g_module_lifetime_unload(snapshot_handle, 0, nullptr, 0, nullptr, &result) == OK &&
            g_module_lifetime.stops[5] == 1 &&
            g_module_lifetime.order == std::vector<int>({5, -5}),
        "captured provider module has balanced finalization");
  CheckModuleLifetimeUnmapped(snapshot_handle, snapshot_address);
  remounted_snapshot.handle.reset();
  Check(DirectoryPassthrough::Unmount("/snapshot-provider") == OK,
        "remove the remounted snapshot provider");
  Check(DirectoryPassthrough::Mount("/system_ex", snapshot_b_directory) == OK,
        "publish provider B through the DT_NEEDED search namespace");
  g_module_lifetime = {};
  auto* snapshot_owner = linker->LoadProgram(snapshot_owner_path);
  linker->LoadNeededModules(snapshot_owner);
  const auto snapshot_b_identity = std::filesystem::canonical(snapshot_b_path);
  auto* snapshot_dependency = linker->FindProgramByFileName(snapshot_b_identity);
  Check(snapshot_dependency != nullptr && snapshot_owner->needed_modules.size() == 1 &&
            snapshot_owner->needed_modules[0].name == "lifetime_snapshot_provider.sprx" &&
            snapshot_owner->needed_modules[0].provider == snapshot_dependency &&
            snapshot_dependency->file_name == snapshot_b_identity,
        "DT_NEEDED loads the provider snapshot under its exact canonical identity");
  linker->RelocateProgram(snapshot_dependency);
  Check(linker->StartModule(snapshot_dependency, 0, nullptr, nullptr) == OK &&
            g_module_lifetime.starts[6] == 1 && g_module_lifetime.starts[5] == 0,
        "DT_NEEDED provider executes the selected provider B snapshot");
  const auto snapshot_owner_handle = snapshot_owner->unique_id;
  const auto snapshot_owner_address = snapshot_owner->base_vaddr;
  const auto snapshot_dependency_handle = snapshot_dependency->unique_id;
  const auto snapshot_dependency_address = snapshot_dependency->base_vaddr;
  linker->StopAllModules();
  Check(g_module_lifetime.stops[6] == 1,
        "DT_NEEDED provider snapshot finalizes once");
  linker->Clear();
  CheckModuleLifetimeUnmapped(snapshot_owner_handle, snapshot_owner_address);
  CheckModuleLifetimeUnmapped(snapshot_dependency_handle, snapshot_dependency_address);
  Check(DirectoryPassthrough::Unmount("/system_ex") == OK,
        "remove the DT_NEEDED snapshot provider");
  std::printf("ModuleLifetimeTests: pinned provider snapshot and DT_NEEDED loading passed\n");

  const auto public_provider_directory = directory / "public_provider";
  const auto public_provider_lib = public_provider_directory / "common_ex" / "lib";
  Check(std::filesystem::create_directories(public_provider_lib),
        "create public dynamic-loader provider directory");
#if defined(_WIN32)
  const auto public_provider_alias_parent = public_provider_directory / "priv_ex";
  const auto public_provider_alias = public_provider_alias_parent / "lib";
  Check(std::filesystem::create_directory(public_provider_alias_parent),
        "create provider alias parent");
  CreateInitialDirectoryJunction(public_provider_alias, public_provider_lib);
#endif
  const auto public_provider_path =
      public_provider_lib / "lifetime_public_provider.sprx";
  const auto public_escape_path = directory / "lifetime_public_escape.sprx";
  WriteModuleLifetimeElf(public_provider_path, 3);
  WriteModuleLifetimeElf(public_escape_path, 4);
  Check(DirectoryPassthrough::Mount("/system_ex", public_provider_directory) == OK &&
            FileSystem::GetRealFilename(
                "/system_ex/common_ex/lib/lifetime_public_provider.sprx").empty(),
        "publish a dynamic-loader provider without exposing its host path");

  g_module_lifetime = {};
  result = -1;
  const auto public_handle = g_module_lifetime_load(
      "/system_ex/common_ex/lib/lifetime_public_provider.sprx", 0,
      nullptr, 0, nullptr, &result);
  auto* public_program = linker->FindProgramById(public_handle);
  Check(public_handle > 0 && result == 0 && public_program != nullptr &&
            public_program->file_name == std::filesystem::canonical(public_provider_path) &&
            g_module_lifetime.starts[3] == 1,
        "public load NID resolves the exact contained provider ELF");
  const auto public_address = public_program->base_vaddr;
  uint32_t public_acquisitions = 1;

#if defined(_WIN32)
  const auto alias_handle = g_module_lifetime_load(
      "/system_ex/priv_ex/lib/lifetime_public_provider.sprx", 0,
      nullptr, 0, nullptr, &result);
  ++public_acquisitions;
  Check(alias_handle == public_handle && result == 0 &&
            public_program->load_count == public_acquisitions &&
            public_program->file_name == std::filesystem::canonical(public_provider_path) &&
            g_module_lifetime.starts[3] == 1,
        "contained junction alias reuses the canonical provider identity");
#endif

  const auto basename_handle = g_module_lifetime_load(
      "lifetime_public_provider.sprx", 0, nullptr, 0, nullptr, &result);
  ++public_acquisitions;
  Check(basename_handle == public_handle && result == 0 &&
            public_program->load_count == public_acquisitions &&
            g_module_lifetime.starts[3] == 1,
        "basename acquisition reuses the provider-backed loader identity");

  Loader::SymbolDatabase sysmodule_symbols;
  Libs::InitSysmodule_1(&sysmodule_symbols);
  const auto* load_by_name_symbol =
      sysmodule_symbols.FindByNid("CU8m+Qs+HN4", Loader::SymbolType::Func);
  Check(load_by_name_symbol != nullptr,
        "load-module-by-name export resolves");
  const auto load_by_name =
      reinterpret_cast<ModuleLifetimeLoadByName>(load_by_name_symbol->vaddr);
  const auto named_handle = load_by_name(
      "lifetime_public_provider", 0, nullptr, 0, &result);
  ++public_acquisitions;
  Check(named_handle == public_handle && result == 0 &&
            public_program->load_count == public_acquisitions &&
            g_module_lifetime.starts[3] == 1,
        "load-module-by-name reuses the provider-backed loader identity");

  result = 117;
  Check(g_module_lifetime_load(
            "/system_ex/common_ex/lib/lifetime_public_missing.sprx", 0,
            nullptr, 0, nullptr, &result) == KERNEL_ERROR_ENOENT &&
            result == KERNEL_ERROR_ENOENT,
        "missing provider-backed dynamic module reports ENOENT");
  result = 117;
  Check(g_module_lifetime_load(
            "/system_ex/common_ex/lib/../../../../lifetime_public_escape.sprx", 0,
            nullptr, 0, nullptr, &result) == KERNEL_ERROR_ENOENT &&
            result == KERNEL_ERROR_ENOENT &&
            linker->FindProgramByFileName(public_escape_path) == nullptr,
        "dynamic module path traversal cannot escape the provider root");
  Check(FileSystem::GetRealFilename(
            "/system_ex/common_ex/lib/lifetime_public_provider.sprx").empty(),
        "dynamic loading preserves provider host-path opacity");

  --public_acquisitions;
  Check(g_module_lifetime_unload(public_handle, 0, nullptr, 0, nullptr, &result) == 0 &&
            linker->FindProgramById(public_handle) == public_program &&
            public_program->load_count == public_acquisitions &&
            g_module_lifetime.stops[3] == 0,
        "first provider-backed acquisition releases without finalization");
#if defined(_WIN32)
  --public_acquisitions;
  Check(g_module_lifetime_unload(alias_handle, 0, nullptr, 0, nullptr, &result) == 0 &&
            linker->FindProgramById(public_handle) == public_program &&
            public_program->load_count == public_acquisitions &&
            g_module_lifetime.stops[3] == 0,
        "junction-alias acquisition releases without changing loader identity");
#endif
  --public_acquisitions;
  Check(g_module_lifetime_unload(basename_handle, 0, nullptr, 0, nullptr, &result) == 0 &&
            linker->FindProgramById(public_handle) == public_program &&
            public_program->load_count == public_acquisitions &&
            g_module_lifetime.stops[3] == 0,
        "basename acquisition releases without changing loader identity");
  Check(g_module_lifetime_unload(named_handle, 0, nullptr, 0, nullptr, &result) == 0 &&
            result == 0 && g_module_lifetime.stops[3] == 1,
        "final provider-backed release runs the module finalizer");
  CheckModuleLifetimeUnmapped(public_handle, public_address);
  Check(g_module_lifetime.order == std::vector<int>({3, -3}),
        "provider-backed dynamic module initializes and finalizes once");
  Check(DirectoryPassthrough::Unmount("/system_ex") == OK,
        "remove the public dynamic-loader provider");
#if defined(_WIN32)
  Check(RemoveDirectoryW(public_provider_alias.c_str()) != FALSE,
        "remove the disposable public loader junction");
#endif
  std::printf("ModuleLifetimeTests: read-only provider public dynamic loading passed\n");

  const auto static_path = directory / "lifetime_static.elf";
  WriteModuleLifetimeElf(static_path, 6, nullptr, true);
  auto* static_root = linker->LoadProgram(static_path);
  Check(static_root != nullptr && static_root->elf->IsStaticExec() &&
            static_root->elf->GetDynamic() == nullptr &&
            static_root->base_vaddr == ModuleLifetimeStaticBase &&
            static_root->process_owned && static_root->needed_modules.empty(),
        "static ELF loads and refreshes dependencies without a dynamic section");
  const auto static_handle = static_root->unique_id;
  auto* later_dynamic = linker->LoadProgram(directory / "lifetime_provider.sprx");
  Check(later_dynamic != nullptr && later_dynamic->elf->IsShared() &&
            linker->FindProgramById(static_handle) == static_root &&
            static_root->needed_modules.empty() && later_dynamic->needed_modules.empty(),
        "later dynamic load safely refreshes a still-resident static ELF");
  uint64_t static_value = 0;
  std::memcpy(&static_value,
              reinterpret_cast<const void*>(ModuleLifetimeStaticBase + ModuleLifetimeDataOffset),
              sizeof(static_value));
  Check(static_value == ModuleLifetimeData,
        "static ELF backing remains intact after dynamic dependency refresh");
  const auto later_handle = later_dynamic->unique_id;
  const auto later_address = later_dynamic->base_vaddr;
  linker->Clear();
  CheckModuleLifetimeUnmapped(static_handle, ModuleLifetimeStaticBase);
  CheckModuleLifetimeUnmapped(later_handle, later_address);
  std::printf("ModuleLifetimeTests: static ELF and later dynamic refresh passed\n");
  FileSystem::Umount("/app0/sce_module");
  std::printf("ModuleLifetimeTests: synthetic ELF dependency and shutdown cases passed\n");
}
