void WriteAudiodExtendedMmapElf(const std::filesystem::path& path) {
  using namespace Loader;
  std::vector<uint8_t> image(0x4000, 0x90);
  const auto put = [&](uint64_t offset, const void* data, size_t size) {
    Check(offset <= image.size() && size <= image.size() - offset,
          "synthetic Audiod libkernel field fits fixture");
    std::memcpy(image.data() + offset, data, size);
  };

  Elf64_Ehdr header {};
  const uint8_t ident[] = {0x7f, 'E', 'L', 'F', ELFCLASS64,
                           ELFDATA2LSB, EV_CURRENT, ELFOSABI_FREEBSD, 2};
  std::memcpy(header.e_ident, ident, sizeof(ident));
  header.e_type = ET_EXEC;
  header.e_machine = EM_X86_64;
  header.e_version = EV_CURRENT;
  header.e_entry = 0x900000000ull + 0x2ce0;
  header.e_phoff = sizeof(Elf64_Ehdr);
  header.e_ehsize = sizeof(Elf64_Ehdr);
  header.e_phentsize = sizeof(Elf64_Phdr);
  header.e_phnum = 1;
  put(0, &header, sizeof(header));

  Elf64_Phdr load {};
  load.p_type = PT_LOAD;
  load.p_flags = PF_R | PF_W | PF_X;
  load.p_offset = 0;
  load.p_vaddr = 0x900000000ull;
  load.p_filesz = image.size();
  load.p_memsz = image.size();
  load.p_align = 0x4000;
  put(header.e_phoff, &load, sizeof(load));

  const std::array<uint8_t, 2> syscall {0x0f, 0x05};
  put(0x186a, syscall.data(), syscall.size());
  put(0x1eaa, syscall.data(), syscall.size());
  const std::array<uint8_t, 26> wrapper {
      0x48, 0xc7, 0xc0, 0xd5, 0x02, 0x00, 0x00,
      0x49, 0x89, 0xca, 0x0f, 0x05,
      0x0f, 0x92, 0xc2, 0x0f, 0xb6, 0xd2,
      0x48, 0xc1, 0xe2, 0x20, 0x48, 0x09, 0xd0, 0xc3};
  put(0x2ce0, wrapper.data(), wrapper.size());

  Common::File file;
  Check(file.Create(path), "create synthetic Audiod libkernel ELF");
  uint32_t written = 0;
  file.Write(image.data(), static_cast<uint32_t>(image.size()), &written);
  Check(written == image.size() && file.Flush(),
        "write synthetic Audiod libkernel ELF");
  file.Close();
}
