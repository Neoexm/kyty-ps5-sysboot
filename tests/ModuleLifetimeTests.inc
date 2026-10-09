using ModuleLifetimeLoad = int32_t (KYTY_SYSV_ABI *)(
    const char*, size_t, const void*, uint32_t, const void*, int*);
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
