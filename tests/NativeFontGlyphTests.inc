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
}
