using LibcSimpleCallback = void (KYTY_SYSV_ABI *)();
using LibcObjectCallback = void (KYTY_SYSV_ABI *)(void*);

struct LibcExitExports {
  using RegisterSimple = int (KYTY_SYSV_ABI *)(LibcSimpleCallback);
  using RegisterObject = int (KYTY_SYSV_ABI *)(LibcObjectCallback, void*, void*);
  using Finalize = void (KYTY_SYSV_ABI *)(void*);
  using Exit = void (KYTY_SYSV_ABI *)(int);

  RegisterSimple atexit = nullptr;
  RegisterObject cxa_atexit = nullptr;
  RegisterObject thread_atexit = nullptr;
  Finalize finalize = nullptr;
  Exit exit = nullptr;
};

LibcExitExports g_libc_exit_exports;
std::string g_libc_exit_trace;
std::FILE* g_libc_exit_stream = nullptr;
void* g_libc_exit_module = nullptr;
char g_libc_late_object = 'X';

void InitializeLibcExitExports() {
  Loader::SymbolDatabase symbols;
  Libs::LibC::InitLibC_1(&symbols);
  Libs::LibcInternalExt::InitLibcInternalExt_1(&symbols);
  const auto find = [&](const char* nid) {
    const auto* symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "libc termination export resolves");
    return symbol->vaddr;
  };
  g_libc_exit_exports.atexit =
      reinterpret_cast<LibcExitExports::RegisterSimple>(find("8G2LB+A3rzg"));
  g_libc_exit_exports.cxa_atexit =
      reinterpret_cast<LibcExitExports::RegisterObject>(find("tsvEmnenz48"));
  g_libc_exit_exports.thread_atexit =
      reinterpret_cast<LibcExitExports::RegisterObject>(find("qBS714-Jr3g"));
  g_libc_exit_exports.finalize =
      reinterpret_cast<LibcExitExports::Finalize>(find("H2e8t5ScQGc"));
  g_libc_exit_exports.exit =
      reinterpret_cast<LibcExitExports::Exit>(find("uMei1W9uyNo"));
}

void RecordLibcExit(char value) {
  g_libc_exit_trace.push_back(value);
  if (g_libc_exit_stream != nullptr) {
    Check(std::fputc(value, g_libc_exit_stream) != EOF,
          "termination callback writes buffered evidence");
  }
}

void KYTY_SYSV_ABI LibcSimpleA() { RecordLibcExit('A'); }
void KYTY_SYSV_ABI LibcSimpleC() { RecordLibcExit('C'); }
void KYTY_SYSV_ABI LibcSimpleN() { RecordLibcExit('N'); }

void KYTY_SYSV_ABI LibcObjectRecord(void* object) {
  RecordLibcExit(*static_cast<const char*>(object));
}

void KYTY_SYSV_ABI LibcRegisterWhileFinalizing() {
  RecordLibcExit('R');
  Check(g_libc_exit_exports.cxa_atexit(
            LibcObjectRecord, &g_libc_late_object, g_libc_exit_module) == 0,
        "register CXA callback from a termination callback");
  Check(g_libc_exit_exports.atexit(LibcSimpleN) == 0,
        "register simple callback from a termination callback");
}

void KYTY_SYSV_ABI LibcRecursiveFinalize(void*) {
  RecordLibcExit('R');
  g_libc_exit_exports.finalize(g_libc_exit_module);
  RecordLibcExit('S');
}

void CheckLibcExitTrace(const char* expected, const char* description) {
  if (g_libc_exit_trace != expected) {
    std::fprintf(stderr, "LibcExitTests: expected=%s actual=%s\n",
                 expected, g_libc_exit_trace.c_str());
    Check(false, description);
  }
}

void CheckLibcFinalization() {
  InitializeLibcExitExports();
  int module_a = 0;
  int module_b = 0;
  int unknown_module = 0;
  char value_a = 'A';
  char value_b = 'B';
  char value_c = 'C';
  char value_d = 'D';

  g_libc_exit_trace.clear();
  Check(g_libc_exit_exports.atexit(LibcSimpleA) == 0 &&
            g_libc_exit_exports.cxa_atexit(LibcObjectRecord, &value_b, &module_a) == 0 &&
            g_libc_exit_exports.atexit(LibcSimpleC) == 0 &&
            g_libc_exit_exports.cxa_atexit(LibcObjectRecord, &value_d, &module_b) == 0,
        "register interleaved C and CXA termination callbacks");
  g_libc_exit_exports.finalize(nullptr);
  CheckLibcExitTrace("DCBA", "mixed termination callbacks run in reverse registration order");
  g_libc_exit_exports.finalize(nullptr);
  CheckLibcExitTrace("DCBA", "global finalization consumes every callback at most once");

  g_libc_exit_trace.clear();
  Check(g_libc_exit_exports.atexit(LibcSimpleA) == 0 &&
            g_libc_exit_exports.cxa_atexit(LibcObjectRecord, &value_b, &module_a) == 0 &&
            g_libc_exit_exports.cxa_atexit(LibcObjectRecord, &value_c, &module_b) == 0 &&
            g_libc_exit_exports.cxa_atexit(LibcObjectRecord, &value_d, &module_a) == 0,
        "register two modules and an unowned simple callback");
  g_libc_exit_exports.finalize(&module_a);
  CheckLibcExitTrace("DB", "module finalization runs only matching CXA callbacks in LIFO order");
  g_libc_exit_exports.finalize(&module_a);
  g_libc_exit_exports.finalize(&unknown_module);
  CheckLibcExitTrace("DB", "repeated and unknown-module finalization changes nothing");
  g_libc_exit_exports.finalize(&module_b);
  CheckLibcExitTrace("DBC", "other module remains available for its own finalization");
  g_libc_exit_exports.finalize(nullptr);
  CheckLibcExitTrace("DBCA", "simple callback survives module finalization until global exit");
  g_libc_exit_exports.finalize(nullptr);
  CheckLibcExitTrace("DBCA", "consumed module callbacks are not repeated by global finalization");

  g_libc_exit_trace.clear();
  g_libc_exit_module = &module_a;
  Check(g_libc_exit_exports.cxa_atexit(LibcObjectRecord, &value_a, &module_a) == 0 &&
            g_libc_exit_exports.atexit(LibcRegisterWhileFinalizing) == 0,
        "register callback that adds both callback kinds");
  g_libc_exit_exports.finalize(nullptr);
  CheckLibcExitTrace("RNXA", "new registrations run before older pending callbacks");
  g_libc_exit_exports.finalize(nullptr);
  CheckLibcExitTrace("RNXA", "callbacks added during finalization also run only once");

  g_libc_exit_trace.clear();
  Check(g_libc_exit_exports.cxa_atexit(LibcObjectRecord, &value_a, &module_a) == 0 &&
            g_libc_exit_exports.cxa_atexit(LibcObjectRecord, &value_b, &module_b) == 0 &&
            g_libc_exit_exports.cxa_atexit(LibcRecursiveFinalize, nullptr, &module_a) == 0,
        "register recursive module finalizer");
  g_libc_exit_exports.finalize(&module_a);
  CheckLibcExitTrace("RAS", "recursive finalization consumes current callback before invocation");
  g_libc_exit_exports.finalize(&module_a);
  CheckLibcExitTrace("RAS", "recursive module finalization does not run callbacks twice");
  g_libc_exit_exports.finalize(nullptr);
  CheckLibcExitTrace("RASB", "recursive module finalization preserves other modules");
  g_libc_exit_module = nullptr;
  std::printf("LibcExitTests: mixed LIFO, module filtering, registration and recursion passed\n");
}

int RunLibcExitChild(int argc, char** argv) {
  if (argc < 2 || std::strcmp(argv[1], "--libc-exit-child") != 0) return -1;
  if (argc != 3) return 2;
  Common::InitializeThreads();
  Common::Subsystems subsystems;
  subsystems.Initialize<Config::Lifecycle>();
  Config::ConfigOptions options;
  options.printf_direction = Config::LogDirection::Silent;
  Config::Load(options);
  subsystems.Initialize<Log::Lifecycle>();
  InitializeLibcExitExports();
  const auto path = Common::PathFromUtf8(argv[2]);
#if defined(_WIN32)
  g_libc_exit_stream = _wfopen(path.c_str(), L"wb");
#else
  g_libc_exit_stream = std::fopen(path.c_str(), "wb");
#endif
  if (g_libc_exit_stream == nullptr) return 3;
  static std::array<char, 1024> buffer {};
  if (std::setvbuf(g_libc_exit_stream, buffer.data(), _IOFBF, buffer.size()) != 0) return 4;

  int module = 0;
  char value_b = 'B';
  char value_d = 'D';
  char value_t = 'T';
  char value_u = 'U';
  Check(g_libc_exit_exports.atexit(LibcSimpleA) == 0 &&
            g_libc_exit_exports.cxa_atexit(LibcObjectRecord, &value_b, &module) == 0 &&
            g_libc_exit_exports.atexit(LibcSimpleC) == 0 &&
            g_libc_exit_exports.cxa_atexit(LibcObjectRecord, &value_d, &module) == 0 &&
            g_libc_exit_exports.thread_atexit(LibcObjectRecord, &value_t, &module) == 0 &&
            g_libc_exit_exports.thread_atexit(LibcObjectRecord, &value_u, &module) == 0,
        "register child TLS and mixed process termination callbacks");
  g_libc_exit_exports.exit(0x125);
  return 126;
}

void CheckLibcExitStatus() {
#if defined(_WIN32)
  TempDirectory temporary;
  const auto evidence = temporary.Path() / "libc_exit_order.bin";
  std::wstring executable(32768, L'\0');
  const auto length = GetModuleFileNameW(nullptr, executable.data(),
                                       static_cast<DWORD>(executable.size()));
  Check(length > 0 && length < executable.size(), "locate libc exit child executable");
  executable.resize(length);
  auto command = L"\"" + executable + L"\" --libc-exit-child \"" +
                 evidence.native() + L"\"";
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process {};
  Check(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process),
        "start isolated HLE exit test");
  const auto wait = WaitForSingleObject(process.hProcess, 10000);
  if (wait != WAIT_OBJECT_0) {
    TerminateProcess(process.hProcess, 126);
    WaitForSingleObject(process.hProcess, 1000);
  }
  DWORD exit_code = 0xffffffffu;
  const bool status_read = GetExitCodeProcess(process.hProcess, &exit_code) != FALSE;
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  Check(wait == WAIT_OBJECT_0 && status_read && exit_code == 37,
        "HLE exit terminates the child and preserves guest low-byte exit status");
  Common::File proof(evidence, Common::File::Mode::Read);
  Check(!proof.IsInvalid(), "open completed child callback evidence");
  const auto bytes = proof.ReadWholeBuffer();
  constexpr char expected[] = "UTDCBA";
  Check(bytes.size() == sizeof(expected) - 1 &&
            std::memcmp(bytes.data(), expected, sizeof(expected) - 1) == 0,
        "exit runs current-thread TLS first, mixed callbacks next, and flushes buffered output");
  proof.Close();
  std::printf("LibcExitTests: child exit=37 callback_order=UTDCBA buffered_flush=1\n");
#endif
}
