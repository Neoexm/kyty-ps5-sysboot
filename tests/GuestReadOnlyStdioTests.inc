void CheckGuestReadOnlyStdio(const std::filesystem::path& root) {
  using namespace Libs::LibKernel;
  Loader::SymbolDatabase symbols;
  Libs::LibC::InitLibC_1(&symbols);
  auto find = [&](const char* nid) {
    const auto* symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "resolve verified read-only stdio export");
    return symbol->vaddr;
  };
  using Open = void* (KYTY_SYSV_ABI *)(const char*, const char*);
  using Close = int (KYTY_SYSV_ABI *)(void*);
  using Read = size_t (KYTY_SYSV_ABI *)(void*, size_t, size_t, void*);
  using Seek = int (KYTY_SYSV_ABI *)(void*, int64_t, int);
  using Tell = int64_t (KYTY_SYSV_ABI *)(void*);
  const auto open = reinterpret_cast<Open>(find("xeYO4u7uyJ0"));
  const auto close = reinterpret_cast<Close>(find("uodLYyUip20"));
  const auto read = reinterpret_cast<Read>(find("lbB+UlZqVG0"));
  const auto seek = reinterpret_cast<Seek>(find("rQFVBXp-Cxg"));
  const auto tell = reinterpret_cast<Tell>(find("Qazy8LmXTvw"));
  const auto backing = root / "read_only_stdio";
}
