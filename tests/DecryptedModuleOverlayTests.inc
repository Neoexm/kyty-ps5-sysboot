using Loader::DecryptedModuleOverlay::Entry;
using Loader::DecryptedModuleOverlay::Manifest;
using Loader::DecryptedModuleOverlay::Resolution;

std::vector<uint8_t> OverlayBlob(const std::array<uint8_t, 4>& magic, size_t size, uint8_t fill) {
  std::vector<uint8_t> bytes(size, fill);
  std::memcpy(bytes.data(), magic.data(), magic.size());
  return bytes;
}

Entry OverlayEntryFor(const std::vector<uint8_t>& self_bytes, const std::vector<uint8_t>& elf_bytes,
                      const std::filesystem::path& elf_path) {
  Entry entry;
  entry.self_size = self_bytes.size();
  entry.self_sha256 = Libs::LibKernel::AuthInfo::Sha256(self_bytes.data(), self_bytes.size());
  entry.elf_size = elf_bytes.size();
  entry.elf_sha256 = Libs::LibKernel::AuthInfo::Sha256(elf_bytes.data(), elf_bytes.size());
  entry.elf_path = elf_path;
  return entry;
}

void WriteOverlayFile(const std::filesystem::path& path, const std::vector<uint8_t>& bytes) {
  Common::File out;
  Check(out.Create(path) && !out.IsInvalid(), "create overlay candidate for write");
  out.Write(bytes.data(), static_cast<uint32_t>(bytes.size()));
  out.Close();
}

void CheckSystemExDecryptedOverlayResolution(const std::filesystem::path& root) {
  const std::array<uint8_t, 4> self_magic {0x54, 0x14, 0xf5, 0xee};
  const std::array<uint8_t, 4> elf_magic {0x7f, 0x45, 0x4c, 0x46};
  const auto self_bytes = OverlayBlob(self_magic, 512, 0xab);
  const auto elf_bytes = OverlayBlob(elf_magic, 1024, 0xcd);

  const auto candidate = root / "dec" / "libScePsm.sprx";
  std::filesystem::create_directories(candidate.parent_path());
  WriteOverlayFile(candidate, elf_bytes);

  const std::string guest = "/system_ex/common_ex/lib/libScePsm.sprx";
  Manifest manifest;
  manifest.entries.emplace(guest, OverlayEntryFor(self_bytes, elf_bytes, candidate));

  std::vector<uint8_t> out;
  std::string detail;
  Check(Loader::DecryptedModuleOverlay::ResolveWithManifest(manifest, guest, self_bytes, &out, &detail) ==
            Resolution::Substituted,
        "pinned encrypted SELF resolves to its verified decrypted ELF");
  Check(out == elf_bytes, "substituted image is the decrypted ELF byte-for-byte");
  Check(self_bytes == OverlayBlob(self_magic, 512, 0xab), "the encrypted image is left unmodified");

  Common::File reopen;
  Check(reopen.Open(candidate, Common::File::Mode::Read) && !reopen.IsInvalid(), "reopen decrypted candidate");
  Check(reopen.Size() == elf_bytes.size(), "decrypted candidate size preserved after resolution");
  const auto reread = reopen.ReadWholeBuffer();
  reopen.Close();
  Check(reread.size() == elf_bytes.size() &&
            std::memcmp(reread.data(), elf_bytes.data(), elf_bytes.size()) == 0,
        "decrypted candidate contents preserved after resolution");

  out.clear();
  Check(Loader::DecryptedModuleOverlay::ResolveWithManifest(manifest, guest, elf_bytes, &out, &detail) ==
            Resolution::NotApplicable,
        "an image that is already the decrypted ELF is left alone");
  Check(out.empty(), "NotApplicable leaves the output image empty");

  // source SELF doesn't match the manifest
  auto wrong_self = self_bytes;
  wrong_self[7] ^= 0xff;
  Check(Loader::DecryptedModuleOverlay::ResolveWithManifest(manifest, guest, wrong_self, &out, &detail) ==
            Resolution::NotApplicable,
        "a source image whose hash differs from the pinned SELF is refused");

  Check(Loader::DecryptedModuleOverlay::ResolveWithManifest(
            manifest, "/system_ex/common_ex/lib/other.sprx", self_bytes, &out, &detail) ==
            Resolution::NotApplicable,
        "an unpinned system_ex path is ignored");

  const std::array<std::string, 7> app_guests {
      "/app0/libScePSNowGkp.sprx",
      "/app0/psm/Application/Sce.Vsh.AppContentUtilWrapper.dll.sprx",
      "/app0/psm/Application/Sce.Vsh.Np.AppLaunchLink.dll.sprx",
      "/app0/psm/Application/Sce.Vsh.Np.AppLaunchLink2.dll.sprx",
      "/app0/psm/Application/Sce.Vsh.ShellUI.Ime.dll.sprx",
      "/app0/psm/Application/Sce.Vsh.Sl2.Sl2Manage.dll.sprx",
      "/app0/psm/Application/Sce.Vsh.VideoRecordingWrapper.dll.sprx",
  };
  Manifest app_manifest;
  for (const auto& app_guest : app_guests) {
    app_manifest.entries.emplace(app_guest, OverlayEntryFor(self_bytes, elf_bytes, candidate));
    out.clear();
    Check(Loader::DecryptedModuleOverlay::ResolveWithManifest(
              app_manifest, app_guest, self_bytes, &out, &detail) == Resolution::Substituted,
          "each exact pinned ShellUI app module resolves at native load time");
    Check(out == elf_bytes, "each ShellUI app substitution returns the verified ELF bytes");
  }
  Check(Loader::DecryptedModuleOverlay::ResolveWithManifest(
            app_manifest, "/app0/psm/Application/Sce.Vsh.ShellUI.Ime2.dll.sprx",
            self_bytes, &out, &detail) == Resolution::NotApplicable,
        "a neighboring app0 module is not admitted by the fixed app-module set");
  Check(Loader::DecryptedModuleOverlay::ResolveWithManifest(
            app_manifest, "/app0/psm/Application/sce.vsh.shellui.ime.dll.sprx",
            self_bytes, &out, &detail) == Resolution::NotApplicable,
        "an app-module path with altered case is not admitted");
  Check(Loader::DecryptedModuleOverlay::ResolveWithManifest(
            app_manifest, "/app0/psm/Application/../Application/Sce.Vsh.ShellUI.Ime.dll.sprx",
            self_bytes, &out, &detail) == Resolution::NotApplicable,
        "an app-module traversal alias is not admitted");

  // prefix guard
  Manifest off_tree;
  off_tree.entries.emplace("/system/common/lib/libScePsm.sprx",
                           OverlayEntryFor(self_bytes, elf_bytes, candidate));
  Check(Loader::DecryptedModuleOverlay::ResolveWithManifest(
            off_tree, "/system/common/lib/libScePsm.sprx", self_bytes, &out, &detail) ==
            Resolution::NotApplicable,
        "a non-system_ex guest path is never substituted");

  // Missing decrypted candidate.
  Manifest missing;
  missing.entries.emplace(guest, OverlayEntryFor(self_bytes, elf_bytes, root / "dec" / "absent.sprx"));
  Check(Loader::DecryptedModuleOverlay::ResolveWithManifest(missing, guest, self_bytes, &out, &detail) ==
            Resolution::RejectedMissing,
        "a pinned entry with no decrypted file on disk is rejected");

  // Decrypted candidate with the wrong size.
  const auto short_candidate = root / "dec" / "short.sprx";
  WriteOverlayFile(short_candidate, OverlayBlob(elf_magic, 512, 0xcd));
  Manifest bad_size;
  bad_size.entries.emplace(guest, OverlayEntryFor(self_bytes, elf_bytes, short_candidate));
  Check(Loader::DecryptedModuleOverlay::ResolveWithManifest(bad_size, guest, self_bytes, &out, &detail) ==
            Resolution::RejectedMismatch,
        "a decrypted candidate of the wrong size is rejected");

  // right size, different content
  const auto tampered = root / "dec" / "tampered.sprx";
  WriteOverlayFile(tampered, OverlayBlob(elf_magic, 1024, 0x11));
  Manifest bad_hash;
  bad_hash.entries.emplace(guest, OverlayEntryFor(self_bytes, elf_bytes, tampered));
  Check(Loader::DecryptedModuleOverlay::ResolveWithManifest(bad_hash, guest, self_bytes, &out, &detail) ==
            Resolution::RejectedMismatch,
        "a decrypted candidate whose hash differs from the pin is rejected");

  // hash matches, but not an ELF
  const auto not_elf = root / "dec" / "notelf.sprx";
  const auto not_elf_bytes = OverlayBlob({0x4d, 0x5a, 0x00, 0x00}, 1024, 0xcd);
  WriteOverlayFile(not_elf, not_elf_bytes);
  Manifest not_elf_manifest;
  not_elf_manifest.entries.emplace(guest, OverlayEntryFor(self_bytes, not_elf_bytes, not_elf));
  Check(Loader::DecryptedModuleOverlay::ResolveWithManifest(not_elf_manifest, guest, self_bytes, &out,
                                                            &detail) == Resolution::RejectedMismatch,
        "a matching but non-ELF decrypted candidate is rejected");

  // too short for the 4-byte ELF magic
  const auto tiny = root / "dec" / "tiny.sprx";
  const std::vector<uint8_t> tiny_bytes {0x7f, 0x45};
  WriteOverlayFile(tiny, tiny_bytes);
  Manifest tiny_manifest;
  tiny_manifest.entries.emplace(guest, OverlayEntryFor(self_bytes, tiny_bytes, tiny));
  Check(Loader::DecryptedModuleOverlay::ResolveWithManifest(tiny_manifest, guest, self_bytes, &out,
                                                            &detail) == Resolution::RejectedMismatch,
        "a decrypted candidate shorter than the ELF magic is rejected");
}

void CheckSystemExDecryptedOverlayManifest() {
  const std::array<uint8_t, 4> self_magic {0x54, 0x14, 0xf5, 0xee};
  const std::array<uint8_t, 4> elf_magic {0x7f, 0x45, 0x4c, 0x46};
  const auto self_sha = Libs::LibKernel::AuthInfo::DigestHex(
      Libs::LibKernel::AuthInfo::Sha256(OverlayBlob(self_magic, 512, 0xab).data(), 512));
  const auto elf_sha = Libs::LibKernel::AuthInfo::DigestHex(
      Libs::LibKernel::AuthInfo::Sha256(OverlayBlob(elf_magic, 1024, 0xcd).data(), 1024));

  const std::string host_path = "C:\\dir with spaces\\common_ex\\lib\\libScePsm.sprx";
  const std::string text = "# a comment\n\n"
                           "/system_ex/common_ex/lib/libScePsm.sprx 512 " + self_sha + " 1024 " + elf_sha +
                           " " + host_path + "\n";
  Manifest manifest;
  std::string error;
  Check(Loader::DecryptedModuleOverlay::ParseManifest(text, &manifest, &error), "valid manifest parses");
  Check(manifest.entries.size() == 1, "comment and blank lines are skipped");
  const auto it = manifest.entries.find("/system_ex/common_ex/lib/libScePsm.sprx");
  Check(it != manifest.entries.end(), "manifest entry keyed by guest path");
  Check(it->second.self_size == 512 && it->second.elf_size == 1024, "manifest sizes parsed");
  Check(Common::PathToString(it->second.elf_path) == host_path, "host path keeps embedded spaces");

  Manifest rejected;
  Check(!Loader::DecryptedModuleOverlay::ParseManifest("/system_ex/x 512 deadbeef\n", &rejected, &error),
        "a line with too few fields fails the parse");
  Check(!Loader::DecryptedModuleOverlay::ParseManifest(
            "/system_ex/x 512 nothex 1024 " + elf_sha + " /tmp/x\n", &rejected, &error),
        "a malformed digest fails the parse");
  const std::string dup = "/system_ex/x 512 " + self_sha + " 1024 " + elf_sha + " /tmp/x\n" +
                          "/system_ex/x 512 " + self_sha + " 1024 " + elf_sha + " /tmp/y\n";
  Check(!Loader::DecryptedModuleOverlay::ParseManifest(dup, &rejected, &error),
        "a duplicate guest path fails the parse");
}

void CheckSystemExDecryptedOverlay() {
  TempDirectory overlay_temporary;
  CheckSystemExDecryptedOverlayResolution(overlay_temporary.Path());
  CheckSystemExDecryptedOverlayManifest();

  std::vector<uint8_t> out;
  std::string detail;
  const std::vector<uint8_t> self_bytes(512, 0xab);
  Check(Loader::DecryptedModuleOverlay::ResolveDecryptedModuleImage(
            "/system_ex/common_ex/lib/libScePsm.sprx", self_bytes, &out, &detail) == Resolution::NotApplicable,
        "with no manifest the overlay is inert");
}

void CheckShellUiImeDecryptedOverlayProduction(const char* manifest_path,
                                               const char* self_path) {
  Common::File manifest_file;
  Check(manifest_path != nullptr && manifest_file.Open(Common::PathFromUtf8(manifest_path),
                                                       Common::File::Mode::Read),
        "open the successor decrypted-overlay manifest");
  const auto manifest_bytes = manifest_file.ReadWholeBuffer();
  manifest_file.Close();
  Manifest manifest;
  std::string error;
  Check(Loader::DecryptedModuleOverlay::ParseManifest(
            std::string(reinterpret_cast<const char*>(manifest_bytes.data()), manifest_bytes.size()),
            &manifest, &error),
        "parse the successor decrypted-overlay manifest");

  Common::File self_file;
  Check(self_path != nullptr && self_file.Open(Common::PathFromUtf8(self_path),
                                               Common::File::Mode::Read),
        "open the ShellUI IME SELF");
  const auto self_raw = self_file.ReadWholeBuffer();
  self_file.Close();
  std::vector<uint8_t> self_bytes(self_raw.size());
  std::memcpy(self_bytes.data(), self_raw.data(), self_raw.size());
  Check(self_bytes.size() == 1425291 &&
            Libs::LibKernel::AuthInfo::DigestHex(
                Libs::LibKernel::AuthInfo::Sha256(self_bytes.data(), self_bytes.size())) ==
                "169c9c04fb59544ef011d51762d6ead6a2924cebe2a6d603529206e2b3b5e175",
        "the production fixture is the exact ShellUI IME SELF");

  const std::string guest = "/app0/psm/Application/Sce.Vsh.ShellUI.Ime.dll.sprx";
  std::vector<uint8_t> elf;
  std::string detail;
  Check(Loader::DecryptedModuleOverlay::ResolveWithManifest(
            manifest, guest, self_bytes, &elf, &detail) == Resolution::Substituted,
        "the production IME request resolves through the manifest and captured SELF");
  Check(elf.size() == 4568404 && elf[0] == 0x7f && elf[1] == 'E' && elf[2] == 'L' && elf[3] == 'F' &&
            Libs::LibKernel::AuthInfo::DigestHex(
                Libs::LibKernel::AuthInfo::Sha256(elf.data(), elf.size())) ==
                "c1b8f79c7350d650972bcae959dca5d6802d718a07cd7c923e1eaff26aedcdc2",
        "the production IME request returns the exact validated ELF");

  auto changed_self = self_bytes;
  changed_self.back() ^= uint8_t {1};
  elf.clear();
  Check(Loader::DecryptedModuleOverlay::ResolveWithManifest(
            manifest, guest, changed_self, &elf, &detail) == Resolution::NotApplicable,
        "a changed IME SELF cannot select the production ELF");
}

void CheckShellUiAppDecryptedOverlayProduction(const char* manifest_path,
                                               const char* self_root) {
  struct Spec {
    const char* guest;
    const char* relative;
    uint64_t self_size;
    const char* self_sha256;
    uint64_t elf_size;
    const char* elf_sha256;
  };
  static constexpr std::array<Spec, 7> specs {{
      {"/app0/libScePSNowGkp.sprx", "libScePSNowGkp.sprx", 1907865,
       "4eb79c9a6d02fe4dc18da4345acbded9ddde1b5eac503030d231edbbdffd73f2", 4172468,
       "b17c668fa18cbb6ab2c89fede0b89e9cd98843b3202b59c5c844c2d3dc263e6b"},
      {"/app0/psm/Application/Sce.Vsh.AppContentUtilWrapper.dll.sprx",
       "psm/Application/Sce.Vsh.AppContentUtilWrapper.dll.sprx", 9849,
       "8f05796f8cb49c4a921785edaf5aa350c0e80aebdb186b7b6dea98eb83027301", 70112,
       "0973c04d8e0a646acd852703570b9fb1282360bec306eb81bec8e9a2d92bf3ed"},
      {"/app0/psm/Application/Sce.Vsh.Np.AppLaunchLink.dll.sprx",
       "psm/Application/Sce.Vsh.Np.AppLaunchLink.dll.sprx", 10092,
       "ecc81f48477e722387cc86be852c14c7a8d57811de2cc5a59167747e9e06bd38", 70056,
       "80c5b1a55aba02d886667f56a2695d0e0c27ac47400f8aeca29212335c054fa0"},
      {"/app0/psm/Application/Sce.Vsh.Np.AppLaunchLink2.dll.sprx",
       "psm/Application/Sce.Vsh.Np.AppLaunchLink2.dll.sprx", 10080,
       "40bf9c46aea5c9a1c3d0f632caed5676f7c0ef3c3861d77b48649b617b65007d", 70060,
       "4111fc2704f569b5f5474f19a7a823f2beb42b4be0b083c6146f435571056353"},
      {"/app0/psm/Application/Sce.Vsh.ShellUI.Ime.dll.sprx",
       "psm/Application/Sce.Vsh.ShellUI.Ime.dll.sprx", 1425291,
       "169c9c04fb59544ef011d51762d6ead6a2924cebe2a6d603529206e2b3b5e175", 4568404,
       "c1b8f79c7350d650972bcae959dca5d6802d718a07cd7c923e1eaff26aedcdc2"},
      {"/app0/psm/Application/Sce.Vsh.Sl2.Sl2Manage.dll.sprx",
       "psm/Application/Sce.Vsh.Sl2.Sl2Manage.dll.sprx", 12846,
       "bf5e1f31e696ce76c47845a65f78b33a70ac8a1eb21a7626970269012be54e0a", 70936,
       "c986bd8fea38538720f6320f6eecc9052210e875dc49c05bb1f706a5f5160233"},
      {"/app0/psm/Application/Sce.Vsh.VideoRecordingWrapper.dll.sprx",
       "psm/Application/Sce.Vsh.VideoRecordingWrapper.dll.sprx", 17299,
       "8be1a4e3a51dcf8c59a358932ac94125e6fb822209d582e481636a8c5d5148ff", 89440,
       "bb62794baba351f7f51cae50b684947c0fb39d84767e3793f65a3c9df5eb3792"},
  }};

  Common::File manifest_file;
  Check(manifest_path != nullptr && manifest_file.Open(Common::PathFromUtf8(manifest_path),
                                                       Common::File::Mode::Read),
        "open the successor decrypted-overlay manifest for all app modules");
  const auto manifest_bytes = manifest_file.ReadWholeBuffer();
  manifest_file.Close();
  Manifest manifest;
  std::string error;
  Check(Loader::DecryptedModuleOverlay::ParseManifest(
            std::string(reinterpret_cast<const char*>(manifest_bytes.data()), manifest_bytes.size()),
            &manifest, &error),
        "parse the successor decrypted-overlay manifest for all app modules");

  Check(self_root != nullptr, "the captured ShellUI app root is supplied");
  const auto root = Common::PathFromUtf8(self_root);
  for (const auto& spec : specs) {
    Common::File self_file;
    Check(self_file.Open(root / Common::PathFromUtf8(spec.relative), Common::File::Mode::Read),
          "open each ShellUI app SELF");
    const auto raw = self_file.ReadWholeBuffer();
    self_file.Close();
    std::vector<uint8_t> self_bytes(raw.size());
    std::memcpy(self_bytes.data(), raw.data(), raw.size());
    Check(self_bytes.size() == spec.self_size &&
              Libs::LibKernel::AuthInfo::DigestHex(
                  Libs::LibKernel::AuthInfo::Sha256(self_bytes.data(), self_bytes.size())) == spec.self_sha256,
          "each production fixture is the exact ShellUI app SELF");

    std::vector<uint8_t> elf;
    std::string detail;
    Check(Loader::DecryptedModuleOverlay::ResolveWithManifest(
              manifest, spec.guest, self_bytes, &elf, &detail) == Resolution::Substituted,
          "each production app request resolves through the manifest and captured SELF");
    Check(elf.size() == spec.elf_size && elf[0] == 0x7f && elf[1] == 'E' && elf[2] == 'L' &&
              elf[3] == 'F' &&
              Libs::LibKernel::AuthInfo::DigestHex(
                  Libs::LibKernel::AuthInfo::Sha256(elf.data(), elf.size())) == spec.elf_sha256,
          "each production app request returns its exact validated ELF");

    self_bytes.back() ^= uint8_t {1};
    elf.clear();
    Check(Loader::DecryptedModuleOverlay::ResolveWithManifest(
              manifest, spec.guest, self_bytes, &elf, &detail) == Resolution::NotApplicable,
          "a changed app SELF cannot select a production ELF");
  }
}
