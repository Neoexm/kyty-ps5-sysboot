struct NativeFontAllocation {
  uint64_t address;
  uint64_t requested;
  uint64_t mapped;
  bool live;
};

struct NativeFontHeap {
  std::vector<NativeFontAllocation> allocations;
  uint32_t frees = 0;
  uint32_t invalid_frees = 0;
  uint32_t failed_allocations = 0;
};

void NativeFontCreateFlush() {
  std::fflush(stdout);
  Log::Flush();
}

void* KYTY_SYSV_ABI NativeFontAllocate(void* context, size_t requested) {
  auto* heap = static_cast<NativeFontHeap*>(context);
  Check(heap != nullptr, "native font allocator receives its callback context");
  uint64_t address = 0;
  uint64_t mapped = 0;
  if (requested > 0 && requested <= UINT64_MAX - 0x3fff) {
    mapped = (static_cast<uint64_t>(requested) + 0x3fff) & ~uint64_t{0x3fff};
    address = Libs::LibKernel::Memory::AllocateProgramMemory(0, mapped,
        Common::VirtualMemory::Mode::ReadWrite, "native_font_heap");
    if (address != 0) {
      std::memset(reinterpret_cast<void*>(address), 0xa5, static_cast<size_t>(mapped));
      heap->allocations.push_back({address, requested, mapped, true});
    }
  }
  if (address == 0) ++heap->failed_allocations;
  std::printf("NATIVE_FONT_CREATE alloc request=0x%llx mapped=0x%llx result=0x%llx live_record=%d\n",
      static_cast<unsigned long long>(requested), static_cast<unsigned long long>(mapped),
      static_cast<unsigned long long>(address), address != 0);
  NativeFontCreateFlush();
  return reinterpret_cast<void*>(address);
}

void KYTY_SYSV_ABI NativeFontFree(void* context, void* pointer) {
  auto* heap = static_cast<NativeFontHeap*>(context);
  Check(heap != nullptr, "native font free receives its callback context");
  if (pointer == nullptr) return;
  const auto address = reinterpret_cast<uint64_t>(pointer);
  auto allocation = std::find_if(heap->allocations.rbegin(), heap->allocations.rend(),
      [&](const auto& item) { return item.live && item.address == address; });
  if (allocation == heap->allocations.rend()) {
    ++heap->invalid_frees;
    std::printf("NATIVE_FONT_CREATE free address=0x%llx unknown_live_allocation=1\n",
        static_cast<unsigned long long>(address));
    NativeFontCreateFlush();
    return;
  }
  const bool freed = Libs::LibKernel::Memory::FreeGuestMemory(address, allocation->mapped);
  if (freed) {
    allocation->live = false;
    ++heap->frees;
  } else {
    ++heap->invalid_frees;
  }
  std::printf("NATIVE_FONT_CREATE free address=0x%llx requested=0x%llx mapped=0x%llx result=%d\n",
      static_cast<unsigned long long>(address), static_cast<unsigned long long>(allocation->requested),
      static_cast<unsigned long long>(allocation->mapped), freed);
  NativeFontCreateFlush();
}

struct NativeFontCallbacks {
  void* (KYTY_SYSV_ABI *allocate)(void*, size_t);
  void (KYTY_SYSV_ABI *free)(void*, void*);
  void* (KYTY_SYSV_ABI *reallocate)(void*, void*, size_t);
  void* reserved;
};

struct NativeFontMemory {
  uint16_t type;
  uint16_t attr;
  uint32_t size;
  void* address;
  void* context;
  const NativeFontCallbacks* callbacks;
  void* destroy;
  void* destroy_object;
  void* user;
  void* parent;
};

struct NativeFontControl {
  NativeFontMemory memory;
  NativeFontCallbacks callbacks;
  void* library;
  void* renderer;
};

static_assert(sizeof(NativeFontCallbacks) == 32);
static_assert(sizeof(NativeFontMemory) == 64);
static_assert(offsetof(NativeFontMemory, callbacks) == 0x18);
using NativeFontMemoryInit = int (KYTY_SYSV_ABI *)(NativeFontMemory*, void*, uint32_t,
    const NativeFontCallbacks*, void*, void*, void*);
using NativeFontLibraryCreate = int (KYTY_SYSV_ABI *)(const NativeFontMemory*, void*, uint64_t, void**);
using NativeFontLibraryDestroy = int (KYTY_SYSV_ABI *)(void**);
using NativeFontMemoryTerm = int (KYTY_SYSV_ABI *)(NativeFontMemory*);
using NativeFontSelector = void* (KYTY_SYSV_ABI *)(uint32_t);

bool NativeFontVerifyBindings(Loader::RuntimeLinker* linker, Loader::Program* font,
                              Loader::Program* ft, Loader::Program* ot) {
  uint32_t freetype_imports = 0;
  uint32_t freetype_bound = 0;
  bool classification_bound = false;
  bool memset_bound = false;
  const auto visit = [&](Loader::Program* program, auto&& inspect) {
    const auto& info = *program->dynamic_info;
    for (const auto& [table, bytes]:
         std::array<std::pair<Loader::Elf64_Rela*, uint64_t>, 2>{{
             {info.rela_table, info.rela_table_total_size},
             {info.jmprela_table, info.jmprela_table_size}}}) {
      for (size_t i = 0; i < bytes / sizeof(Loader::Elf64_Rela); ++i) {
        const auto& relocation = table[i];
        const auto type = relocation.GetType();
        if (type != Loader::R_X86_64_64 && type != Loader::R_X86_64_GLOB_DAT &&
            type != Loader::R_X86_64_JUMP_SLOT) continue;
        const auto& symbol = info.symbol_table[relocation.GetSymbol()];
        if (symbol.st_shndx != 0 || symbol.GetType() != Loader::STT_FUNC) continue;
        const auto ids = Common::Split(std::string(info.str_table + symbol.st_name), '#');
        if (ids.size() != 3) continue;
        uint64_t value = 0;
        std::memcpy(&value, reinterpret_cast<const void*>(program->base_vaddr + relocation.r_offset), 8);
        if (type == Loader::R_X86_64_64) value -= relocation.r_addend;
        inspect(ids, value, info);
      }
    }
  };
  visit(ft, [&](const auto& ids, uint64_t target, const auto& info) {
    const auto library = std::find_if(info.import_libs.begin(), info.import_libs.end(),
        [&](const auto& item) { return item.id == ids[1]; });
    const auto module = std::find_if(info.import_modules.begin(), info.import_modules.end(),
        [&](const auto& item) { return item.id == ids[2]; });
    if (library == info.import_libs.end() || module == info.import_modules.end() ||
        library->name != "libSceFreeType" || module->name != "libSceFreeType") return;
    ++freetype_imports;
    const Loader::SymbolResolve request {ids[0], library->name, library->version,
        module->name, module->version_major, module->version_minor, Loader::SymbolType::Func};
    const auto* original = ot->export_symbols->Find(request);
    const bool bound = original != nullptr && target == original->vaddr;
    if (bound) ++freetype_bound;
    else std::printf("NATIVE_FONT_CREATE missing_original_ot nid=%s target=0x%llx\n",
        ids[0].c_str(), static_cast<unsigned long long>(target));
  });
  visit(font, [&](const auto& ids, uint64_t target, const auto&) {
    if (ids[0] != "GGeRJk1XdWc") return;
    const auto* symbol = linker->Symbols()->FindByNid(ids[0], Loader::SymbolType::Func);
    classification_bound = symbol != nullptr && target == symbol->vaddr;
  });
  visit(ot, [&](const auto& ids, uint64_t target, const auto&) {
    if (ids[0] != "8zTFvBIAIN8") return;
    const auto* symbol = linker->Symbols()->FindByNid(ids[0], Loader::SymbolType::Func);
    memset_bound = symbol != nullptr && target == symbol->vaddr;
  });
  std::printf("NATIVE_FONT_CREATE upstream fontft_ot=%u/%u classification_hle=%d memset_hle=%d\n",
      freetype_bound, freetype_imports, classification_bound, memset_bound);
  NativeFontCreateFlush();
  return freetype_imports == 36 && freetype_bound == freetype_imports &&
      classification_bound && memset_bound;
}

int AuditNativeFontCreate(const std::filesystem::path& root) {
  Check(std::filesystem::is_directory(root), "native creation audit requires the firmware sysroot");
  auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
  Check(linker->FindProgramByFileName(root / "system/common/lib/libSceFont.native.sprx") == nullptr,
        "native creation audit does not preload providers");
  FileSystem::MountReadOnly(root, "/");
  Libs::InitAll(linker->Symbols());
  const auto finish = [&](int result) {
    linker->Clear();
    FileSystem::Umount("/");
    return result;
  };
  const auto* load_symbol = linker->Symbols()->FindByNid("g8cM39EUZ6o", Loader::SymbolType::Func);
  Check(load_symbol != nullptr, "resolve public sysmodule load API");
  const auto load = reinterpret_cast<int (KYTY_SYSV_ABI *)(uint16_t)>(load_symbol->vaddr);
  for (uint16_t id: {0x84, 0x98, 0x99}) {
    std::printf("NATIVE_FONT_CREATE before_load id=0x%02x normal_boot=0\n", id);
    NativeFontCreateFlush();
    const int result = load(id);
    std::printf("NATIVE_FONT_CREATE after_load id=0x%02x result=0x%08x\n", id,
        static_cast<uint32_t>(result));
    NativeFontCreateFlush();
    if (result != 0) return finish(2);
  }
  auto* font = linker->FindProgramByFileName(root / "system/common/lib/libSceFont.native.sprx");
  auto* ft = linker->FindProgramByFileName(root / "system/common/lib/libSceFontFt.sprx");
  auto* ot = linker->FindProgramByFileName(root / "system/common/lib/libSceFreeTypeOt.sprx");
  for (auto* program: {font, ft, ot}) {
    if (program == nullptr || program->module_state != Loader::Program::ModuleState::Started ||
        !program->native_init_attempted || program->module_start_result < 0) return finish(2);
    std::printf("NATIVE_FONT_CREATE original_module=%s handle=%d start_result=%d active_font=%d\n",
        Common::PathToString(program->file_name).c_str(), program->unique_id,
        program->module_start_result, program->original_font_provider);
  }
  if (!font->original_font_provider || !ft->original_font_provider ||
      !NativeFontVerifyBindings(linker, font, ft, ot)) return finish(2);
  const auto* init_record = font->export_symbols->FindByNid("whrS4oksXc4", Loader::SymbolType::Func);
  const auto* create_record = font->export_symbols->FindByNid("n590hj5Oe-k", Loader::SymbolType::Func);
  const auto* destroy_record = font->export_symbols->FindByNid("FXP359ygujs", Loader::SymbolType::Func);
  const auto* term_record = font->export_symbols->FindByNid("h6hIgxXEiEc", Loader::SymbolType::Func);
  const auto* selector_record = ft->export_symbols->FindByNid("oM+XCzVG3oM", Loader::SymbolType::Func);
  const auto* renderer_create_record = font->export_symbols->FindByNid("WaSFJoRWXaI", Loader::SymbolType::Func);
  const auto* renderer_destroy_record = font->export_symbols->FindByNid("exAxkyVLt0s", Loader::SymbolType::Func);
  const auto* renderer_selector_record = ft->export_symbols->FindByNid("Xx974EW-QFY", Loader::SymbolType::Func);
  Check(init_record && create_record && destroy_record && term_record && selector_record &&
        renderer_create_record && renderer_destroy_record && renderer_selector_record,
        "creation and cleanup call only provider exports");
  const auto init = reinterpret_cast<NativeFontMemoryInit>(init_record->vaddr);
  const auto create = reinterpret_cast<NativeFontLibraryCreate>(create_record->vaddr);
  const auto destroy = reinterpret_cast<NativeFontLibraryDestroy>(destroy_record->vaddr);
  const auto term = reinterpret_cast<NativeFontMemoryTerm>(term_record->vaddr);
  const auto select = reinterpret_cast<NativeFontSelector>(selector_record->vaddr);
  const auto create_renderer = reinterpret_cast<NativeFontLibraryCreate>(renderer_create_record->vaddr);
  const auto destroy_renderer = reinterpret_cast<NativeFontLibraryDestroy>(renderer_destroy_record->vaddr);
  const auto select_renderer = reinterpret_cast<NativeFontSelector>(renderer_selector_record->vaddr);
  const uint64_t control_address = Libs::LibKernel::Memory::AllocateProgramMemory(0, 0x4000,
      Common::VirtualMemory::Mode::ReadWrite, "native_font_control");
  if (control_address == 0) return finish(2);
  std::memset(reinterpret_cast<void*>(control_address), 0, 0x4000);
  auto* control = reinterpret_cast<NativeFontControl*>(control_address);
  NativeFontHeap heap;
  heap.allocations.reserve(64);
  control->callbacks = {NativeFontAllocate, NativeFontFree, nullptr, nullptr};
  const int initialized = init(&control->memory, nullptr, 0, &control->callbacks,
      &heap, nullptr, nullptr);
  int created = -1;
  int destroyed = -1;
  uint16_t library_magic = 0;
  if (initialized == 0 && control->memory.type == 0x0f00) {
    void* descriptor = select(0);
    Check(reinterpret_cast<uint64_t>(descriptor) == ft->base_vaddr + 0x1c000,
        "create uses FontFt descriptor");
    std::printf("NATIVE_FONT_CREATE before_create address=0x%llx descriptor=0x%llx edition=0\n",
        static_cast<unsigned long long>(create_record->vaddr),
        static_cast<unsigned long long>(reinterpret_cast<uint64_t>(descriptor)));
    NativeFontCreateFlush();
    created = create(&control->memory, descriptor, 0, &control->library);
    const auto library_address = reinterpret_cast<uint64_t>(control->library);
    const auto allocation = std::find_if(heap.allocations.begin(), heap.allocations.end(),
        [&](const auto& item) { return item.live && item.address == library_address && item.requested >= 0x100; });
    if (allocation != heap.allocations.end()) std::memcpy(&library_magic, control->library, 2);
    std::printf("NATIVE_FONT_CREATE after_create result=0x%08x library=0x%llx magic=0x%04x allocations=%llu\n",
        static_cast<uint32_t>(created), static_cast<unsigned long long>(library_address), library_magic,
        static_cast<unsigned long long>(heap.allocations.size()));
    NativeFontCreateFlush();
    if (created == 0 && library_magic == 0x0f01) {
      destroyed = destroy(&control->library);
      std::printf("NATIVE_FONT_CREATE after_destroy result=0x%08x caller_handle_null=%d\n",
          static_cast<uint32_t>(destroyed), control->library == nullptr);
      NativeFontCreateFlush();
    }
  }
  const bool caller_cleared = control->library == nullptr;
  int renderer_created = -1;
  int renderer_destroyed = -1;
  uint16_t renderer_magic = 0;
  if (initialized == 0 && created == 0 && destroyed == 0 && caller_cleared) {
    void* descriptor = select_renderer(0);
    Check(reinterpret_cast<uint64_t>(descriptor) == ft->base_vaddr + 0x1c740,
          "renderer uses the FontFt descriptor");
    std::printf("NATIVE_FONT_RENDERER before_create descriptor=0x%llx edition=0xffffffff00000000\n",
                static_cast<unsigned long long>(reinterpret_cast<uint64_t>(descriptor)));
    NativeFontCreateFlush();
    renderer_created = create_renderer(&control->memory, descriptor, 0xffffffff00000000ull, &control->renderer);
    const auto address = reinterpret_cast<uint64_t>(control->renderer);
    const auto allocation = std::find_if(heap.allocations.begin(), heap.allocations.end(),
        [&](const auto& item) { return item.live && item.address == address && item.requested >= 0x168; });
    if (allocation != heap.allocations.end()) std::memcpy(&renderer_magic, control->renderer, 2);
    std::printf("NATIVE_FONT_RENDERER after_create result=0x%08x handle=0x%llx magic=0x%04x\n",
                static_cast<uint32_t>(renderer_created), static_cast<unsigned long long>(address), renderer_magic);
    NativeFontCreateFlush();
    if (renderer_created == 0 && renderer_magic == 0x0f07) {
      renderer_destroyed = destroy_renderer(&control->renderer);
      std::printf("NATIVE_FONT_RENDERER after_destroy result=0x%08x caller_handle_null=%d\n",
                  static_cast<uint32_t>(renderer_destroyed), control->renderer == nullptr);
      NativeFontCreateFlush();
    }
  }
  const bool renderer_cleared = control->renderer == nullptr;
  const int terminated = initialized == 0 ? term(&control->memory) : -1;
  const auto live = std::count_if(heap.allocations.begin(), heap.allocations.end(),
      [](const auto& item) { return item.live; });
  const bool passed = initialized == 0 && created == 0 && library_magic == 0x0f01 &&
      destroyed == 0 && caller_cleared && terminated == 0 && control->memory.type == 0 &&
      renderer_created == 0 && renderer_magic == 0x0f07 && renderer_destroyed == 0 && renderer_cleared &&
      live == 0 && heap.invalid_frees == 0 && heap.failed_allocations == 0 &&
      heap.frees == heap.allocations.size();
  std::printf("NATIVE_FONT_CREATE natural_cleanup live=%llu allocs=%llu frees=%u invalid_frees=%u failed_allocs=%u term=0x%08x pass=%d normal_boot=0\n",
      static_cast<unsigned long long>(live), static_cast<unsigned long long>(heap.allocations.size()),
      heap.frees, heap.invalid_frees, heap.failed_allocations, static_cast<uint32_t>(terminated), passed);
  NativeFontCreateFlush();
  for (auto& allocation: heap.allocations) {
    if (!allocation.live) continue;
    const bool freed = Libs::LibKernel::Memory::FreeGuestMemory(allocation.address, allocation.mapped);
    std::printf("NATIVE_FONT_CREATE diagnostic_recovery address=0x%llx mapped=0x%llx result=%d natural_cleanup=0\n",
        static_cast<unsigned long long>(allocation.address),
        static_cast<unsigned long long>(allocation.mapped), freed);
    if (freed) allocation.live = false;
  }
  const bool control_freed = Libs::LibKernel::Memory::FreeGuestMemory(control_address, 0x4000);
  NativeFontCreateFlush();
  return finish(passed && control_freed ? 0 : 1);
}
