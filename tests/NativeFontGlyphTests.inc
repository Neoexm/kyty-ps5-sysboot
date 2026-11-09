struct NativeFontGlyphControl {
  NativeFontControl base;
  void* font;
  alignas(32) std::array<uint8_t, 0x60> surface;
  alignas(32) std::array<uint8_t, 0x40> metrics;
  alignas(32) std::array<uint8_t, 0x60> result;
};

using NativeFontSupportExternal = int (KYTY_SYSV_ABI *)(void*, uint32_t, uint32_t);
using NativeFontOpenMemory = int (KYTY_SYSV_ABI *)(void*, const void*, uint32_t, const void*, void**);
using NativeFontOpenSet = int (KYTY_SYSV_ABI *)(void*, uint32_t, uint32_t, const void*, void**);
using NativeFontOpenFile = int (KYTY_SYSV_ABI *)(void*, const char*, uint32_t, const void*, void**);
using NativeFontScale = int (KYTY_SYSV_ABI *)(void*, float, float);
using NativeFontBind = int (KYTY_SYSV_ABI *)(void*, void*);
using NativeFontHandleOperation = int (KYTY_SYSV_ABI *)(void*);
using NativeFontSurfaceInit = void (KYTY_SYSV_ABI *)(void*, void*, int32_t, int8_t, int32_t, int32_t);
using NativeFontRenderHorizontal = int (KYTY_SYSV_ABI *)(void*, uint32_t, void*, float, float, void*, void*);

bool NativeFontGlyphStep(const char* operation, int result) {
  std::printf("NATIVE_FONT_GLYPH operation=%s result=0x%08x normal_boot=0\n",
      operation, static_cast<uint32_t>(result));
  NativeFontCreateFlush();
  return result == 0;
}

uint16_t NativeFontTrackedMagic(const NativeFontHeap& heap, const void* pointer, uint64_t minimum) {
  const auto address = reinterpret_cast<uint64_t>(pointer);
  const auto allocation = std::find_if(heap.allocations.begin(), heap.allocations.end(),
      [&](const auto& item) { return item.live && item.address == address && item.requested >= minimum; });
  uint16_t magic = 0;
  if (allocation != heap.allocations.end()) std::memcpy(&magic, pointer, sizeof(magic));
  return magic;
}

int AuditNativeFontGlyph(const std::filesystem::path& root,
                         const std::filesystem::path& asset_relative, uint32_t codepoint,
                         const std::filesystem::path& pixel_output = {}, bool system_font = false,
                         bool file_font = false) {
  Check(!(system_font && file_font), "select one font source");
  Check(std::filesystem::is_directory(root), "glyph audit requires the firmware sysroot");
  Check(asset_relative == "system_ex/common_ex/font2/PS4Icon.ttf" ||
        asset_relative == "system_ex/common_ex/font2/SceWebKitSupplemental.otf",
        "glyph audit takes an explicit owned diagnostic font asset");
  Check(codepoint > 0 && codepoint <= 0x10ffff && !(codepoint >= 0xd800 && codepoint <= 0xdfff),
        "glyph audit takes an explicit supported Unicode scalar from the font cmap");
  auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
  for (const char* file: {"libSceFont.native.sprx", "libSceFontFt.sprx", "libSceFreeTypeOt.sprx"}) {
    Check(linker->FindProgramByFileName(root / "system/common/lib" / file) == nullptr,
          "glyph audit starts without preloaded font providers");
  }
  FileSystem::MountReadOnly(root, "/");
  Libs::InitAll(linker->Symbols());
  const auto finish = [&](int result) {
    linker->Clear();
    FileSystem::Umount("/");
    return result;
  };
  const auto* load_symbol = linker->Symbols()->FindByNid("g8cM39EUZ6o", Loader::SymbolType::Func);
  Check(load_symbol != nullptr, "resolve public ID loader");
  const auto load = reinterpret_cast<int (KYTY_SYSV_ABI *)(uint16_t)>(load_symbol->vaddr);
  for (uint16_t id: {0x84, 0x98, 0x99}) {
    std::printf("NATIVE_FONT_GLYPH before_load id=0x%02x\n", id);
    NativeFontCreateFlush();
    if (!NativeFontGlyphStep("actual_id_load", load(id))) return finish(2);
  }
  auto* font = linker->FindProgramByFileName(root / "system/common/lib/libSceFont.native.sprx");
  auto* ft = linker->FindProgramByFileName(root / "system/common/lib/libSceFontFt.sprx");
  auto* ot = linker->FindProgramByFileName(root / "system/common/lib/libSceFreeTypeOt.sprx");
  for (auto* provider: {font, ft, ot}) {
    if (provider == nullptr || provider->module_state != Loader::Program::ModuleState::Started ||
        !provider->native_init_attempted || provider->module_start_result < 0) return finish(2);
  }
  if (!font->original_font_provider || !ft->original_font_provider ||
      !NativeFontVerifyBindings(linker, font, ft, ot)) return finish(2);
  const auto address = [&](Loader::Program* provider, const char* nid) {
    const auto* record = provider->export_symbols->FindByNid(nid, Loader::SymbolType::Func);
    Check(record != nullptr, "glyph audit invokes only provider exports");
    return record->vaddr;
  };
  const auto init = reinterpret_cast<NativeFontMemoryInit>(address(font, "whrS4oksXc4"));
  const auto create_library = reinterpret_cast<NativeFontLibraryCreate>(address(font, "n590hj5Oe-k"));
  const auto destroy_library = reinterpret_cast<NativeFontLibraryDestroy>(address(font, "FXP359ygujs"));
  const auto term = reinterpret_cast<NativeFontMemoryTerm>(address(font, "h6hIgxXEiEc"));
  const auto library_selector = reinterpret_cast<NativeFontSelector>(address(ft, "oM+XCzVG3oM"));
  const auto renderer_selector = reinterpret_cast<NativeFontSelector>(address(ft, "Xx974EW-QFY"));
  const auto create_renderer = reinterpret_cast<NativeFontLibraryCreate>(address(font, "WaSFJoRWXaI"));
  const auto destroy_renderer = reinterpret_cast<NativeFontLibraryDestroy>(address(font, "exAxkyVLt0s"));
  const auto support = reinterpret_cast<NativeFontSupportExternal>(address(font, "mz2iTY0MK4A"));
  const auto support_system = reinterpret_cast<NativeFontHandleOperation>(address(font, "SsRbbCiWoGw"));
  const auto open = reinterpret_cast<NativeFontOpenMemory>(address(font, "KXUpebrFk1U"));
  const auto open_set = reinterpret_cast<NativeFontOpenSet>(address(font, "cKYtVmeSTcw"));
  const auto open_file = reinterpret_cast<NativeFontOpenFile>(address(font, "RvXyHMUiLhE"));
  const auto scale = reinterpret_cast<NativeFontScale>(address(font, "N1EBMeGhf7E"));
  const auto bind = reinterpret_cast<NativeFontBind>(address(font, "3OdRkSjOcog"));
  const auto unbind = reinterpret_cast<NativeFontHandleOperation>(address(font, "1QjhKxrsOB8"));
  const auto close = reinterpret_cast<NativeFontHandleOperation>(address(font, "vzHs3C8lWJk"));
  const auto surface_init = reinterpret_cast<NativeFontSurfaceInit>(address(font, "gdUCnU0gHdI"));
  const auto render = reinterpret_cast<NativeFontRenderHorizontal>(address(font, "3G4zhgKuxE8"));
  Common::File asset;
  const auto asset_path = root / asset_relative;
  if (!asset.Open(asset_path, Common::File::Mode::Read)) return finish(2);
  const auto font_size = asset.Size();
  if (font_size == 0 || font_size > UINT32_MAX) return finish(2);
  const uint64_t font_mapped = (font_size + 0x3fff) & ~uint64_t{0x3fff};
  const uint64_t control_address = Libs::LibKernel::Memory::AllocateProgramMemory(0, 0x4000,
      Common::VirtualMemory::Mode::ReadWrite, "native_glyph_control");
  const uint64_t font_address = Libs::LibKernel::Memory::AllocateProgramMemory(0, font_mapped,
      Common::VirtualMemory::Mode::ReadWrite, "native_font_original_asset");
  const uint64_t pixels_address = Libs::LibKernel::Memory::AllocateProgramMemory(0, 0x4000,
      Common::VirtualMemory::Mode::ReadWrite, "native_glyph_pixels");
  if (control_address == 0 || font_address == 0 || pixels_address == 0) {
    if (control_address) Libs::LibKernel::Memory::FreeGuestMemory(control_address, 0x4000);
    if (font_address) Libs::LibKernel::Memory::FreeGuestMemory(font_address, font_mapped);
    if (pixels_address) Libs::LibKernel::Memory::FreeGuestMemory(pixels_address, 0x4000);
    return finish(2);
  }
  std::memset(reinterpret_cast<void*>(control_address), 0, 0x4000);
  std::memset(reinterpret_cast<void*>(font_address), 0xa5, static_cast<size_t>(font_mapped));
  auto* pixels = reinterpret_cast<uint8_t*>(pixels_address);
  std::memset(pixels, 0xcd, 0x4000);
  std::memset(pixels, 0, 64 * 64);
  auto* control = reinterpret_cast<NativeFontGlyphControl*>(control_address);
  const std::string guest_path = "/" + asset_relative.generic_string();
  Check(guest_path.size() + 1 <= 0x3000, "file path fits owned control page");
  auto* file_path = reinterpret_cast<char*>(control_address + 0x1000);
  std::memcpy(file_path, guest_path.c_str(), guest_path.size() + 1);
  control->surface.fill(0xcd);
  control->metrics.fill(0xcd);
  control->result.fill(0xcd);
  std::memset(control->surface.data(), 0, 0x40);
  std::memset(control->metrics.data(), 0, 0x20);
  std::memset(control->result.data(), 0, 0x40);
  uint32_t bytes_read = 0;
  asset.Read(reinterpret_cast<void*>(font_address), static_cast<uint32_t>(font_size), &bytes_read);
  asset.Close();
  NativeFontHeap heap;
  control->base.callbacks = {NativeFontAllocate, NativeFontFree, nullptr, nullptr};
  bool passed = bytes_read == font_size;
  bool initialized = false;
  bool bound = false;
  int rendered = -1;
  uint32_t ink_pixels = 0;
  uint64_t pixel_hash = 14695981039346656037ull;
  std::printf("NATIVE_FONT_GLYPH original_asset=%s size=%llu codepoint=U+%04x default_shellui_font=0\n",
      Common::PathToString(asset_path).c_str(), static_cast<unsigned long long>(font_size), codepoint);
  NativeFontCreateFlush();
  const uint64_t library_edition = 0xffffffff00000000ull;
  const uint64_t renderer_edition = 0xffffffff00000000ull;
  if (passed) {
    initialized = NativeFontGlyphStep("memory_init", init(&control->base.memory, nullptr, 0,
        &control->base.callbacks, &heap, nullptr, nullptr));
    passed = initialized && control->base.memory.type == 0x0f00;
  }
  if (passed) passed = NativeFontGlyphStep("library_create", create_library(&control->base.memory,
      library_selector(0), library_edition, &control->base.library)) &&
      NativeFontTrackedMagic(heap, control->base.library, 0x100) == 0x0f01;
  if (passed && system_font) {
    std::printf("NATIVE_FONT_SYSTEM before_original_system_support default_type=0x1807bcd4 mode=2 aliases=0\n");
    NativeFontCreateFlush();
    passed = NativeFontGlyphStep("support_system_original", support_system(control->base.library));
  }
  if (passed) passed = NativeFontGlyphStep("support_external_max10_formats52",
      support(control->base.library, 0x10, 0x52));
  if (passed) passed = NativeFontGlyphStep("renderer_create", create_renderer(&control->base.memory,
      renderer_selector(0), renderer_edition, &control->base.renderer)) &&
      NativeFontTrackedMagic(heap, control->base.renderer, 0x168) == 0x0f07;
  if (passed) {
    int result = -1;
    const char* operation = "open_original_memory";
    if (system_font) {
      operation = "open_original_default_set";
      result = open_set(control->base.library, 0x1807bcd4, 2, nullptr, &control->font);
    } else if (file_font) {
      operation = "open_original_file_mode2";
      result = open_file(control->base.library, file_path, 2, nullptr, &control->font);
    } else {
      result = open(control->base.library, reinterpret_cast<void*>(font_address),
                    static_cast<uint32_t>(font_size), nullptr, &control->font);
    }
    passed = NativeFontGlyphStep(operation, result) &&
        NativeFontTrackedMagic(heap, control->font, sizeof(uint16_t)) == 0x0f02;
  }
  if (passed) passed = NativeFontGlyphStep("set_scale_32_before_bind", scale(control->font, 32.0f, 32.0f));
  if (passed) {
    bound = NativeFontGlyphStep("bind_actual_renderer", bind(control->font, control->base.renderer));
    passed = bound;
  }
  if (passed) {
    surface_init(control->surface.data(), pixels, 64, 1, 64, 64);
    std::printf("NATIVE_FONT_GLYPH before_render actual_font=0x%llx actual_renderer=0x%llx\n",
        static_cast<unsigned long long>(reinterpret_cast<uint64_t>(control->font)),
        static_cast<unsigned long long>(reinterpret_cast<uint64_t>(control->base.renderer)));
    NativeFontCreateFlush();
    rendered = render(control->font, codepoint, control->surface.data(),
        16.0f, 32.0f, control->metrics.data(), control->result.data());
    passed = NativeFontGlyphStep("render_horizontal", rendered);
    for (size_t i = 0; i < 64 * 64; ++i) {
      if (pixels[i] != 0) ++ink_pixels;
      pixel_hash = (pixel_hash ^ pixels[i]) * 1099511628211ull;
    }
    passed = passed && ink_pixels != 0;
  }
  const auto tail_intact = [](const auto& bytes, size_t payload) {
    return std::all_of(bytes.begin() + payload, bytes.end(), [](uint8_t value) { return value == 0xcd; });
  };
  const bool guards = tail_intact(control->surface, 0x40) && tail_intact(control->metrics, 0x20) &&
      tail_intact(control->result, 0x40) &&
      std::all_of(pixels + 64 * 64, pixels + 0x4000, [](uint8_t value) { return value == 0xcd; });
  passed = guards && passed;
  std::printf("NATIVE_FONT_GLYPH pixels_nonzero=%u fnv1a64=0x%llx surface40_metrics20_result40_guardtails=%d\n",
      ink_pixels, static_cast<unsigned long long>(pixel_hash), guards);
  NativeFontCreateFlush();
  if (rendered == 0 && guards && !pixel_output.empty()) {
    Common::File bitmap;
    bool written_ok = bitmap.Create(pixel_output);
    uint32_t written = 0;
    if (written_ok) {
      bitmap.Write(pixels, 64 * 64, &written);
      written_ok = written == 64 * 64 && bitmap.Flush();
      bitmap.Close();
    }
    std::printf("NATIVE_FONT_GLYPH raw_pixels=%s width=64 height=64 stride=64 bytes=%u result=%d guest_api_result=0 guards=1\n",
        Common::PathToString(pixel_output).c_str(), written, written_ok);
    NativeFontCreateFlush();
    passed = written_ok && passed;
  }
  if (bound) passed = NativeFontGlyphStep("unbind", unbind(control->font)) && passed;
  if (control->font != nullptr) {
    const bool closed = NativeFontGlyphStep("close_font", close(control->font));
    passed = closed && passed;
    if (closed) control->font = nullptr;
  }
  if (control->base.renderer != nullptr) passed = NativeFontGlyphStep("renderer_destroy",
      destroy_renderer(&control->base.renderer)) && control->base.renderer == nullptr && passed;
  if (control->base.library != nullptr) passed = NativeFontGlyphStep("library_destroy",
      destroy_library(&control->base.library)) && control->base.library == nullptr && passed;
  if (initialized) passed = NativeFontGlyphStep("memory_term", term(&control->base.memory)) &&
      control->base.memory.type == 0 && passed;
  const auto live = std::count_if(heap.allocations.begin(), heap.allocations.end(),
      [](const auto& item) { return item.live; });
  passed = passed && live == 0 && heap.invalid_frees == 0 && heap.failed_allocations == 0 &&
      heap.frees == heap.allocations.size();
  std::printf("NATIVE_FONT_GLYPH natural_cleanup allocs=%llu frees=%u live=%llu invalid=%u failures=%u pass=%d\n",
      static_cast<unsigned long long>(heap.allocations.size()), heap.frees,
      static_cast<unsigned long long>(live), heap.invalid_frees, heap.failed_allocations, passed);
  NativeFontCreateFlush();
  for (auto& allocation: heap.allocations) {
    if (!allocation.live) continue;
    const bool freed = Libs::LibKernel::Memory::FreeGuestMemory(allocation.address, allocation.mapped);
    std::printf("NATIVE_FONT_GLYPH diagnostic_recovery address=0x%llx mapped=0x%llx result=%d natural_cleanup=0\n",
        static_cast<unsigned long long>(allocation.address),
        static_cast<unsigned long long>(allocation.mapped), freed);
    if (freed) allocation.live = false;
  }
  const bool pixels_freed = Libs::LibKernel::Memory::FreeGuestMemory(pixels_address, 0x4000);
  const bool asset_freed = Libs::LibKernel::Memory::FreeGuestMemory(font_address, font_mapped);
  const bool control_freed = Libs::LibKernel::Memory::FreeGuestMemory(control_address, 0x4000);
  if (passed && pixels_freed && asset_freed && control_freed) {
    const auto* unload_symbol = linker->Symbols()->FindByNid("eR2bZFAAU0Q", Loader::SymbolType::Func);
    const auto* loaded_symbol = linker->Symbols()->FindByNid("fMP5NHUOaMk", Loader::SymbolType::Func);
    Check(unload_symbol && loaded_symbol, "resolve public font module unload and status");
    const auto unload = reinterpret_cast<int (KYTY_SYSV_ABI *)(uint16_t)>(unload_symbol->vaddr);
    const auto loaded = reinterpret_cast<int (KYTY_SYSV_ABI *)(uint16_t)>(loaded_symbol->vaddr);
    const std::array<std::pair<uint16_t, const char*>, 3> rows {{
        {0x98, "libSceFontFt.sprx"}, {0x99, "libSceFreeTypeOt.sprx"}, {0x84, "libSceFont.native.sprx"}}};
    for (const auto& [id, name]: rows) {
      auto* provider = linker->FindProgramByFileName(root / "system/common/lib" / name);
      Check(provider != nullptr, "font unload starts with its provider");
      const auto handle = provider->unique_id;
      const auto references = provider->load_count;
      const int released = unload(id);
      const int row_status = loaded(id);
      const auto* retained = linker->FindProgramById(handle);
      std::printf("NATIVE_FONT_GLYPH module_unload id=0x%02x handle=%d references_before=%u"
                  " result=0x%08x row_status=0x%08x retained_mapping=%d normal_boot=0\n",
          id, handle, references, static_cast<uint32_t>(released),
          static_cast<uint32_t>(row_status), retained != nullptr);
      passed = released == 0 && row_status == static_cast<int32_t>(0x805a1001u) && passed;
      NativeFontCreateFlush();
    }
    for (const auto& [id, name]: rows) {
      const auto* retained = linker->FindProgramByFileName(root / "system/common/lib" / name);
      std::printf("NATIVE_FONT_GLYPH module_after_releases id=0x%02x mapped=%d"
                  " references=%u process_owned=%d active_module_calls=%u normal_boot=0\n",
          id, retained != nullptr, retained != nullptr ? retained->load_count : 0,
          retained != nullptr ? retained->process_owned : false,
          retained != nullptr ? retained->active_module_calls : 0);
    }
  }
  NativeFontCreateFlush();
  return finish(passed && pixels_freed && asset_freed && control_freed ? 0 : 1);
}
