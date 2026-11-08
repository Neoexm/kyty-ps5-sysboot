void CheckSandboxWord(const std::filesystem::path& temporary) {
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* record = symbols.FindByNid("JGfTMBOdUJo", Loader::SymbolType::Func);
  Check(record != nullptr, "resolve original filesystem namespace getter");
  const auto query = reinterpret_cast<const char* (KYTY_SYSV_ABI *)()>(record->vaddr);
  auto* error = Libs::Posix::GetErrorAddr();
  *error = Libs::Posix::POSIX_EIO;
  const char* word = query();
  Check(word != nullptr && *word == '\0' && *error == Libs::Posix::POSIX_EIO,
        "empty word describes Kyty rooted namespace and preserves success errno");
  const auto common = temporary / "sandbox_common";
  std::filesystem::create_directories(common);
  Common::File file;
  Check(file.Create(common / "namespace.bin"), "create namespace backing fixture");
  constexpr char content[] = "root-backed";
  uint32_t written = 0;
  file.Write(content, sizeof(content), &written);
  Check(written == sizeof(content) && file.Flush(), "write namespace fixture");
  file.Close();
  FileSystem::MountReadOnly(common, "/common");
  const std::string path = "/" + std::string(word) + "/common/namespace.bin";
  const int fd = FileSystem::KernelOpen(path.c_str(), 0, 0);
  std::array<char, sizeof(content)> received {};
  Check(fd >= 3 && FileSystem::KernelRead(fd, received.data(), received.size()) == received.size() &&
        std::memcmp(received.data(), content, sizeof(content)) == 0,
        "word-composed double-slash path resolves the mounted backing");
  Check(FileSystem::KernelClose(fd) == 0, "close namespace fixture descriptor");
  FileSystem::Umount("/common");
  Check(query() == word && *word == '\0', "repeated root query keeps returned string alive");
  auto child = std::async(std::launch::async, [query] {
    const char* result = query();
    return result != nullptr && *result == '\0';
  });
  Check(child.get(), "namespace query stays consistent on a separate host thread");
  std::printf("SandboxWordTests: native_backend=pass root_backing=pass stable_return=pass concurrent_query=pass\n");
}
