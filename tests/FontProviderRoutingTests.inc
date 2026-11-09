struct FontRoutingMemory {
  uint16_t type;
  uint16_t attr;
  uint32_t size;
  void* address;
  void* mspace;
  const void* memory_interface;
  void* destroy;
  void* destroy_object;
  void* user;
  void* parent;
};

static_assert(sizeof(FontRoutingMemory) == 64);
static_assert(offsetof(FontRoutingMemory, memory_interface) == 0x18);
using FontRoutingInit = int (KYTY_SYSV_ABI *)(FontRoutingMemory*, void*, uint32_t,
    const void*, void*, void*, void*);
using FontRoutingSelector = void* (KYTY_SYSV_ABI *)(uint32_t);
constexpr uint64_t FontRoutingSlots = 0x1b00;
constexpr uint64_t FontRoutingMemoryCall = 0x4100;
constexpr uint64_t FontRoutingSelectorCall = 0x4140;

void WriteFontRoutingConsumer(const std::filesystem::path& path,
                              uint16_t font_version = 1,
                              const char* memory_nid = "whrS4oksXc4") {
  using namespace Loader;
  WriteModuleLifetimeElf(path, 1);
  Common::File input;
  Check(input.Open(path, Common::File::Mode::Read) && input.Size() == 0x8000,
        "font consumer reuses module lifetime ELF layout");
  std::vector<uint8_t> image(0x8000);
  uint32_t bytes_read = 0;
  input.Read(image.data(), static_cast<uint32_t>(image.size()), &bytes_read);
  Check(bytes_read == image.size(), "read complete module lifetime ELF fixture");
  input.Close();
  const auto put = [&](uint64_t offset, const void* data, size_t size) {
    Check(offset <= image.size() && size <= image.size() - offset,
          "font consumer field fits synthetic image");
    std::memcpy(image.data() + offset, data, size);
  };
  std::string strings(1, '\0');
  const auto text = [&](const std::string& value) {
    const auto offset = strings.size();
    strings += value;
    strings.push_back('\0');
    return static_cast<uint32_t>(offset);
  };
  const auto soname = text(path.filename().string());
  const auto font = text("libSceFont");
  const auto ft = text("libSceFontFt");
  const auto kernel = text("libkernel");
  const auto font_needed = text("libSceFont-module.prx");
  const auto ft_needed = text("libSceFontFt-module.prx");
  const std::array<uint32_t, 3> names {{
      text(std::string(memory_nid) + "#A#A"),
      text("oM+XCzVG3oM#B#B"), text("3k6kx-zOOSQ#C#C")}};
  Check(strings.size() <= 0x200, "font consumer strings do not overlap symbols");
  put(0x1000, strings.data(), strings.size());
  std::array<Elf64_Sym, 4> symbols {};
  std::array<Elf64_Rela, 3> relocations {};
  for (size_t i = 0; i < names.size(); ++i) {
    symbols[i + 1].st_name = names[i];
    symbols[i + 1].st_info = (STB_GLOBAL << 4) | STT_FUNC;
    relocations[i].r_offset = FontRoutingSlots + i * sizeof(uint64_t);
    relocations[i].r_info = (uint64_t {i + 1} << 32) | R_X86_64_JUMP_SLOT;
  }
  put(0x1200, symbols.data(), sizeof(symbols));
  put(0x1300, relocations.data(), sizeof(relocations));
  std::vector<Elf64_Dyn> dynamic;
  const auto tag = [&](Elf64_Sxword key, uint64_t value) {
    Elf64_Dyn entry {};
    entry.d_tag = key;
    entry.d_un.d_val = value;
    dynamic.push_back(entry);
  };
  tag(DT_STRTAB, 0x1000);
  tag(DT_STRSZ, strings.size());
  tag(DT_SYMTAB, 0x1200);
  tag(DT_SYMENT, sizeof(Elf64_Sym));
  tag(DT_OS_SYMTABSZ, sizeof(symbols));
  tag(DT_JMPREL, 0x1300);
  tag(DT_PLTRELSZ, sizeof(relocations));
  tag(DT_PLTREL, DT_RELA);
  tag(DT_RELA, 0x1400);
  tag(DT_RELASZ, 0);
  tag(DT_RELAENT, sizeof(Elf64_Rela));
  tag(DT_SONAME, soname);
  tag(DT_NEEDED, font_needed);
  tag(DT_NEEDED, ft_needed);
  for (const auto& [offset, id]:
       std::array<std::pair<uint32_t, uint16_t>, 3>{{{font, 0}, {ft, 1}, {kernel, 2}}}) {
    tag(DT_OS_NEEDED_MODULE, (uint64_t {id} << 48) | (uint64_t {1} << 40) |
        (uint64_t {1} << 32) | offset);
    tag(DT_OS_IMPORT_LIB, (uint64_t {id} << 48) |
        (static_cast<uint64_t>(id == 0 ? font_version : 1) << 32) | offset);
  }
  tag(DT_INIT, ModuleLifetimeInitOffset);
  tag(DT_FINI, ModuleLifetimeFiniOffset);
  tag(0, 0);
  Check(dynamic.size() * sizeof(Elf64_Dyn) <= 0xc00,
        "font consumer dynamic table fits its original segment");
  put(0x400, dynamic.data(), dynamic.size() * sizeof(Elf64_Dyn));
  auto* header = reinterpret_cast<Elf64_Ehdr*>(image.data());
  auto* segments = reinterpret_cast<Elf64_Phdr*>(image.data() + header->e_phoff);
  segments[2].p_filesz = dynamic.size() * sizeof(Elf64_Dyn);
  segments[2].p_memsz = segments[2].p_filesz;
  const auto forward = [&](uint64_t entry, uint64_t slot) {
    std::array<uint8_t, 6> code {{0xff, 0x25, 0, 0, 0, 0}};
    const auto displacement = static_cast<int32_t>(static_cast<int64_t>(slot) -
        static_cast<int64_t>(entry + code.size()));
    std::memcpy(code.data() + 2, &displacement, sizeof(displacement));
    put(entry, code.data(), code.size());
  };
  forward(FontRoutingMemoryCall, FontRoutingSlots);
  forward(FontRoutingSelectorCall, FontRoutingSlots + 8);
  Common::File output;
  Check(output.Create(path), "create synthetic qualified font consumer");
  uint32_t written = 0;
  output.Write(image.data(), static_cast<uint32_t>(image.size()), &written);
  Check(written == image.size() && output.Flush(), "write qualified font consumer");
  output.Close();
}

uint64_t FontRoutingSlot(const Loader::Program* program, size_t index) {
  uint64_t value = 0;
  std::memcpy(&value, reinterpret_cast<const void*>(
      program->base_vaddr + FontRoutingSlots + index * 8), sizeof(value));
  return value;
}

bool FontRoutingResolved(const Loader::Program* program, size_t index) {
  return !program->rela_bits.empty() &&
      (program->rela_bits[index >> 3] & (1u << (index & 7))) != 0;
}

void CheckFontRoutingUnready(const std::filesystem::path& root) {
  const auto path = root / "libSceFont.native.sprx";
  WriteModuleLifetimeElf(path, 1);
  Loader::RuntimeLinker isolated;
  auto* linker = &isolated;
  auto* program = linker->LoadProgram(path);
  Check(program->module_state == Loader::Program::ModuleState::NotStarted &&
        !program->native_init_attempted, "unready control has never executed its fixture init");
  linker->EnableOriginalFontProvider(program->unique_id);
  Check(!program->original_font_provider,
        "mapped but unstarted original-named fixture cannot activate font routing");
  std::printf("FontProviderRoutingTests: unready_provider=pass host_fixture_only=1\n");
}

int AuditNativeFontRouting(const std::filesystem::path& firmware,
                          const std::filesystem::path& root) {
  Check(std::filesystem::is_directory(firmware), "native routing audit requires the firmware sysroot");
  CheckFontRoutingUnready(root);
  auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
  Libs::InitAll(linker->Symbols());
  FileSystem::MountReadOnly(firmware, "/");
  const auto native_font = firmware / "system/common/lib/libSceFont.native.sprx";
  const auto native_ft = firmware / "system/common/lib/libSceFontFt.sprx";
  Check(!linker->FindProgramByFileName(native_font) && !linker->FindProgramByFileName(native_ft),
        "font providers have not been preloaded before ID calls");
  const auto consumer_path = root / "font_consumer.sprx";
  WriteFontRoutingConsumer(consumer_path);
  auto* consumer = linker->LoadProgram(consumer_path);
  linker->RelocateProgram(consumer);
  const auto* hle_memory = linker->Symbols()->FindByNid("whrS4oksXc4", Loader::SymbolType::Func);
  const auto* hle_selector = linker->Symbols()->FindByNid("oM+XCzVG3oM", Loader::SymbolType::Func);
  const auto* kernel_control = linker->Symbols()->FindByNid("3k6kx-zOOSQ", Loader::SymbolType::Func);
  const auto* load_symbol = linker->Symbols()->FindByNid("g8cM39EUZ6o", Loader::SymbolType::Func);
  Check(hle_memory && hle_selector && kernel_control && load_symbol,
        "resolve baseline HLE API records and ID loader");
  Check(FontRoutingSlot(consumer, 0) == hle_memory->vaddr &&
        FontRoutingSlot(consumer, 1) == hle_selector->vaddr &&
        FontRoutingSlot(consumer, 2) == kernel_control->vaddr &&
        FontRoutingResolved(consumer, 0) && FontRoutingResolved(consumer, 1),
        "consumer starts with cached resolved HLE font slots and kernel control");
  const auto init = reinterpret_cast<FontRoutingInit>(consumer->base_vaddr + FontRoutingMemoryCall);
  const auto select = reinterpret_cast<FontRoutingSelector>(consumer->base_vaddr + FontRoutingSelectorCall);
  std::array<uint8_t, 64> backing {};
  FontRoutingMemory memory {};
  Check(init(&memory, backing.data(), static_cast<uint32_t>(backing.size()),
             nullptr, nullptr, nullptr, nullptr) == 0 && memory.type == 1,
        "same consumer GOT initially calls HLE memory-init representation");
  const auto old_selector = select(0);
  Check(old_selector != nullptr && select(1) != nullptr,
        "baseline consumer reaches existing HLE selector behavior");
  const auto load = reinterpret_cast<int (KYTY_SYSV_ABI *)(uint16_t)>(load_symbol->vaddr);
  Check(load(0x84) == 0, "ID84 load succeeds before activation checks");
  auto* font = linker->FindProgramByFileName(native_font);
  Check(font && font->module_state == Loader::Program::ModuleState::Started &&
        font->native_init_attempted && font->original_font_provider,
        "initialized Font provider becomes eligible");
  const auto* original_memory = font->export_symbols->FindByNid("whrS4oksXc4", Loader::SymbolType::Func);
  Check(original_memory && FontRoutingSlot(consumer, 0) == original_memory->vaddr &&
        FontRoutingSlot(consumer, 0) != hle_memory->vaddr,
        "already-resolved consumer memory slot rebinds to Font export");
  memory = {};
  Check(init(&memory, backing.data(), static_cast<uint32_t>(backing.size()),
             nullptr, nullptr, nullptr, nullptr) == 0 && memory.type == 0x0f00 &&
        memory.size == backing.size() && memory.address == backing.data(),
        "same GOT now executes memory-init byte layout");
  Check(load(0x98) == 0, "ID98 load succeeds before selector checks");
  auto* ft = linker->FindProgramByFileName(native_ft);
  Check(ft && ft->module_state == Loader::Program::ModuleState::Started &&
        ft->native_init_attempted && ft->original_font_provider,
        "initialized FontFt provider becomes eligible");
  const auto* original_selector = ft->export_symbols->FindByNid("oM+XCzVG3oM", Loader::SymbolType::Func);
  Check(original_selector && FontRoutingSlot(consumer, 1) == original_selector->vaddr &&
        FontRoutingSlot(consumer, 1) != hle_selector->vaddr &&
        reinterpret_cast<uint64_t>(select(0)) == ft->base_vaddr + 0x1c000 &&
        select(0) != old_selector && select(1) == nullptr,
        "same consumer selector slot executes native descriptor selection");
  Check(FontRoutingSlot(consumer, 2) == kernel_control->vaddr && FontRoutingResolved(consumer, 2),
        "font activation preserves the existing libkernel HLE binding");
  struct NegativeControl {
    const char* name;
    uint16_t version;
    const char* nid;
  };
  for (const auto& [name, version, nid]:
       std::array<NegativeControl, 2>{{
          {"font_version_consumer.sprx", 2, "whrS4oksXc4"},
          {"font_missing_consumer.sprx", 1, "g8cM39EUZ6o"}}}) {
    const auto path = root / name;
    WriteFontRoutingConsumer(path, version, nid);
    auto* control = linker->LoadProgram(path);
    linker->RelocateProgram(control);
    const auto* fallback = linker->Symbols()->FindByNid(nid, Loader::SymbolType::Func);
    Check(fallback && !FontRoutingResolved(control, 0) &&
          FontRoutingSlot(control, 0) != fallback->vaddr &&
          FontRoutingSlot(control, 0) != original_memory->vaddr,
          "activated namespace rejects version mismatch or missing qualified export without HLE fallback");
    Check(FontRoutingSlot(control, 2) == kernel_control->vaddr,
          "negative qualified-font controls preserve unrelated kernel imports");
  }
  std::printf("NATIVE_FONT_ROUTING_AUDIT cached_rebind=pass native_memory=0x0f00 native_descriptor=pass kernel_preserved=pass version_missing=pass normal_boot=0\n");
  std::fflush(stdout);
  Log::Flush();
  linker->Clear();
  FileSystem::Umount("/");
  return 0;
}
