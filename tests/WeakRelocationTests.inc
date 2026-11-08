constexpr uint64_t WeakRelocationSlots = 0x1900;

uint32_t KYTY_SYSV_ABI WeakRelocationProvider() {
  return 73;
}

void WriteWeakRelocationElf(const std::filesystem::path& path) {
  using namespace Loader;
  WriteModuleLifetimeElf(path, 1);
  Common::File input(path, Common::File::Mode::Read);
  std::vector<uint8_t> image(0x8000);
  uint32_t read = 0;
  input.Read(image.data(), static_cast<uint32_t>(image.size()), &read);
  Check(read == image.size(), "read weak relocation fixture");
  input.Close();
  const auto put = [&](uint64_t offset, const void* data, size_t size) {
    Check(offset <= image.size() && size <= image.size() - offset,
          "weak relocation fixture bounds");
    std::memcpy(image.data() + offset, data, size);
  };
  std::string strings(1, '\0');
  const auto text = [&](const std::string& value) {
    const auto offset = static_cast<uint32_t>(strings.size());
    strings += value;
    strings.push_back('\0');
    return offset;
  };
  const auto soname = text(path.filename().string());
  const auto library = text("WeakFixture");
  std::array<Elf64_Sym, 5> symbols {};
  const std::array<const char*, 4> names {{"MissingWeakFunction#A#A",
      "MissingWeakObject#A#A", "AvailableWeakFunction#A#A", "MissingRequiredFunction#A#A"}};
  for (size_t i = 0; i < names.size(); ++i) {
    symbols[i + 1].st_name = text(names[i]);
    symbols[i + 1].st_info = ((i == 3 ? STB_GLOBAL : STB_WEAK) << 4) |
        (i == 1 ? STT_OBJECT : STT_FUNC);
  }
  Check(strings.size() <= 0x200, "weak relocation strings fit fixture");
  put(0x1000, strings.data(), strings.size());
  put(0x1200, symbols.data(), sizeof(symbols));
  std::array<Elf64_Rela, 4> rela {{
      {WeakRelocationSlots, (uint64_t {1} << 32) | R_X86_64_GLOB_DAT, 0},
      {WeakRelocationSlots + 8, (uint64_t {2} << 32) | R_X86_64_GLOB_DAT, 0},
      {WeakRelocationSlots + 16, (uint64_t {1} << 32) | R_X86_64_64, 0x35},
      {WeakRelocationSlots + 24, (uint64_t {4} << 32) | R_X86_64_GLOB_DAT, 0}}};
  std::array<Elf64_Rela, 2> plt {{
      {WeakRelocationSlots + 32, (uint64_t {1} << 32) | R_X86_64_JUMP_SLOT, 0},
      {WeakRelocationSlots + 40, (uint64_t {3} << 32) | R_X86_64_JUMP_SLOT, 0}}};
  put(0x1300, rela.data(), sizeof(rela));
  put(0x1400, plt.data(), sizeof(plt));
  std::vector<Elf64_Dyn> dynamic;
  const auto tag = [&](Elf64_Sxword key, uint64_t value) {
    Elf64_Dyn entry {};
    entry.d_tag = key;
    entry.d_un.d_val = value;
    dynamic.push_back(entry);
  };
  tag(DT_STRTAB, 0x1000); tag(DT_STRSZ, strings.size());
  tag(DT_SYMTAB, 0x1200); tag(DT_SYMENT, sizeof(Elf64_Sym));
  tag(DT_OS_SYMTABSZ, sizeof(symbols));
  tag(DT_RELA, 0x1300); tag(DT_RELASZ, sizeof(rela)); tag(DT_RELAENT, sizeof(Elf64_Rela));
  tag(DT_JMPREL, 0x1400); tag(DT_PLTRELSZ, sizeof(plt)); tag(DT_PLTREL, DT_RELA);
  tag(DT_SONAME, soname);
  tag(DT_OS_NEEDED_MODULE, (uint64_t {1} << 40) | (uint64_t {1} << 32) | library);
  tag(DT_OS_IMPORT_LIB, (uint64_t {1} << 32) | library);
  tag(0, 0);
  put(0x400, dynamic.data(), dynamic.size() * sizeof(Elf64_Dyn));
  auto* header = reinterpret_cast<Elf64_Ehdr*>(image.data());
  auto* segments = reinterpret_cast<Elf64_Phdr*>(image.data() + header->e_phoff);
  segments[2].p_filesz = dynamic.size() * sizeof(Elf64_Dyn);
  segments[2].p_memsz = segments[2].p_filesz;
  std::array<uint8_t, 13> guard {{0x31, 0xc0, 0x48, 0x83, 0x3d,
      0, 0, 0, 0, 0, 0x0f, 0x94, 0xc0}};
  const auto displacement = static_cast<int32_t>(WeakRelocationSlots - (ModuleLifetimeCallOffset + 10));
  std::memcpy(guard.data() + 5, &displacement, sizeof(displacement));
  put(ModuleLifetimeCallOffset, guard.data(), guard.size());
  image[ModuleLifetimeCallOffset + guard.size()] = 0xc3;
  Common::File output;
  Check(output.Create(path), "create weak relocation ELF");
  uint32_t written = 0;
  output.Write(image.data(), static_cast<uint32_t>(image.size()), &written);
  Check(written == image.size() && output.Flush(), "write weak relocation ELF");
}

void CheckWeakRelocations(const std::filesystem::path& root) {
  using namespace Loader;
  const auto path = root / "weak_relocations.sprx";
  WriteWeakRelocationElf(path);
  RuntimeLinker linker;
  SymbolResolve provider {"AvailableWeakFunction", "WeakFixture", 1, "WeakFixture", 1, 1, SymbolType::Func};
  linker.Symbols()->Add(provider, reinterpret_cast<uint64_t>(&WeakRelocationProvider));
  auto* program = linker.LoadProgram(path);
  linker.RelocateProgram(program);
  const auto slot = [&](size_t index) {
    uint64_t value = 0;
    std::memcpy(&value, reinterpret_cast<const void*>(program->base_vaddr +
        WeakRelocationSlots + index * sizeof(value)), sizeof(value));
    return value;
  };
  using Call = uint32_t (KYTY_SYSV_ABI *)();
  const auto guard = reinterpret_cast<Call>(program->base_vaddr + ModuleLifetimeCallOffset);
  Check(guard() == 1, "ELF optional weak function guard sees no provider");
  Check(slot(0) == 0 && slot(1) == 0 && slot(2) == 0x35 && slot(4) == 0,
        "missing weak function and object relocations use zero symbol value and retain addend");
  Check(slot(5) == reinterpret_cast<uint64_t>(&WeakRelocationProvider) &&
            reinterpret_cast<Call>(slot(5))() == 73,
        "available weak import retains its executable provider");
  Check(slot(3) != 0 && (program->rela_bits[0] & 8u) == 0,
        "required missing import remains unresolved with existing failure target");
  Check((program->rela_bits[0] & 0x37u) == 0x37u,
        "weak zero and provider relocations are resolved");
  linker.RelocateProgram(program);
  Check(guard() == 1 && slot(2) == 0x35 && reinterpret_cast<Call>(slot(5))() == 73,
        "repeated relocation preserves weak absence and provider identity");
  linker.Clear();
  std::printf("WeakRelocationTests: optional guard, function/object zero, addend and actual provider passed\n");
}
