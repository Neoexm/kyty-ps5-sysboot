using ThreadAtexitRegister = int (KYTY_SYSV_ABI *)(void (KYTY_SYSV_ABI *)(void*), void*, void*);

struct ThreadAtexitOwnerFixture;
struct ThreadAtexitOwnerObject {
  ThreadAtexitOwnerFixture* fixture;
  char value;
};

struct ThreadAtexitOwnerFixture {
  int32_t handle;
  void* dso;
  void (KYTY_SYSV_ABI *callback)(void*);
  ThreadAtexitRegister registration;
  ModuleLifetimeUnload unload;
  std::array<ThreadAtexitOwnerObject, 3> objects;
  std::atomic<bool> ready {false};
  std::atomic<bool> release_thread {false};
  std::atomic<bool> entered {false};
  std::atomic<bool> release_callback {false};
  std::string order;
};

void KYTY_SYSV_ABI ThreadAtexitOwnerRecord(void* argument) {
  auto* object = static_cast<ThreadAtexitOwnerObject*>(argument);
  auto* fixture = object->fixture;
  Check(Common::Singleton<Loader::RuntimeLinker>::Instance()->FindProgramById(fixture->handle) != nullptr,
        "thread destructor executes with its ELF owner mapped");
  fixture->order.push_back(object->value);
  if (object->value == 'B') {
    int result = -1;
    Check(fixture->unload(fixture->handle, 0, nullptr, 0, nullptr, &result) ==
              Libs::LibKernel::KERNEL_ERROR_EBUSY,
          "destructor cannot unmap its own executing module");
    Check(fixture->registration(fixture->callback, &fixture->objects[2], fixture->dso) == 0,
          "destructor registers another callback against the same DSO");
    fixture->entered.store(true, std::memory_order_release);
    while (!fixture->release_callback.load(std::memory_order_acquire)) std::this_thread::yield();
  }
}

void* KYTY_SYSV_ABI ThreadAtexitOwnerEntry(void* argument) {
  auto* fixture = static_cast<ThreadAtexitOwnerFixture*>(argument);
  Check(fixture->registration(fixture->callback, &fixture->objects[0], fixture->dso) == 0 &&
            fixture->registration(fixture->callback, &fixture->objects[1], fixture->dso) == 0,
        "guest Pthread registers native mapped destructor and DSO");
  fixture->ready.store(true, std::memory_order_release);
  while (!fixture->release_thread.load(std::memory_order_acquire)) std::this_thread::yield();
  return nullptr;
}

void CheckThreadAtexitLifetimes(const std::filesystem::path& root) {
  using namespace Libs::LibKernel;
  const auto directory = root / "thread_atexit_owner";
  Check(std::filesystem::create_directory(directory), "create thread destructor ownership fixture");
  FileSystem::MountReadOnly(directory, "/thread_atexit_owner");
  Check(FileSystem::GetRealFilename("/app0/sce_module").empty(),
        "thread destructor fixture does not cover another module mount");
  FileSystem::MountReadOnly(directory, "/app0/sce_module");
  WriteModuleLifetimeElf(directory / "provider.sprx", 1);
  const auto path = directory / "owner.sprx";
  WriteModuleLifetimeElf(path, 3, "provider.sprx");
  Common::File source(path, Common::File::Mode::Read);
  auto bytes = source.ReadWholeBuffer();
  source.Close();
  constexpr uint64_t callback_offset = 0x4200;
  constexpr uint64_t dso_offset = 0x1b00;
  std::array<uint8_t, 12> code {{0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xe0}};
  const auto target = reinterpret_cast<uint64_t>(&ThreadAtexitOwnerRecord);
  std::memcpy(code.data() + 2, &target, sizeof(target));
  std::memcpy(bytes.data() + callback_offset, code.data(), code.size());
  Common::File output;
  Check(output.Create(path), "rewrite owned destructor fixture code");
  uint32_t written = 0;
  output.Write(bytes.data(), static_cast<uint32_t>(bytes.size()), &written);
  Check(written == bytes.size() && output.Flush(), "persist mapped destructor code");
  output.Close();
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  Libs::LibcInternalExt::InitLibcInternalExt_1(&symbols);
  const auto* load_symbol = symbols.FindByNid("wzvqT4UqKX8", Loader::SymbolType::Func);
  const auto* unload_symbol = symbols.FindByNid("QKd0qM58Qes", Loader::SymbolType::Func);
  const auto* register_symbol = symbols.FindByNid("qBS714-Jr3g", Loader::SymbolType::Func);
  Check(load_symbol && unload_symbol && register_symbol, "resolve module and thread destructor APIs");
  const auto load = reinterpret_cast<ModuleLifetimeLoad>(load_symbol->vaddr);
  const auto unload = reinterpret_cast<ModuleLifetimeUnload>(unload_symbol->vaddr);
  const auto registration = reinterpret_cast<ThreadAtexitRegister>(register_symbol->vaddr);
  auto* linker = Common::Singleton<Loader::RuntimeLinker>::Instance();
  g_module_lifetime = {};
  int result = -1;
  const auto provider_handle = load("/thread_atexit_owner/provider.sprx", 0, nullptr, 0, nullptr, &result);
  Check(provider_handle > 0 && result == 0, "load DT_NEEDED provider through public export");
  auto* provider = linker->FindProgramById(provider_handle);
  const auto provider_address = provider->base_vaddr;
  const auto handle = load("/thread_atexit_owner/owner.sprx", 0, nullptr, 0, nullptr, &result);
  Check(handle > 0 && result == 0, "load ELF destructor owner through public export");
  auto* program = linker->FindProgramById(handle);
  const auto address = program->base_vaddr;
  const auto dso = address + dso_offset;
  std::memcpy(reinterpret_cast<void*>(dso), &dso, sizeof(dso));
  ThreadAtexitOwnerFixture fixture {handle, reinterpret_cast<void*>(dso),
      reinterpret_cast<void (KYTY_SYSV_ABI *)(void*)>(address + callback_offset), registration, unload,
      {{{nullptr, 'A'}, {nullptr, 'B'}, {nullptr, 'C'}}}};
  for (auto& object: fixture.objects) object.fixture = &fixture;
  Check(registration(fixture.callback, &fixture.objects[0], nullptr) == -1 &&
            registration(fixture.callback, &fixture.objects[0], reinterpret_cast<void*>(UINT64_MAX)) == -1 &&
            program->pending_thread_atexit == 0,
        "mapped guest destructor cannot register against an absent DSO owner");
  const auto* increment_symbol = symbols.FindByNid("Tz4RNUCBbGI", Loader::SymbolType::Func);
  const auto* decrement_symbol = symbols.FindByNid("8OnWXlgQlvo", Loader::SymbolType::Func);
  Check(increment_symbol && decrement_symbol, "resolve DSO-address lifetime exports");
  using Ownership = int (KYTY_SYSV_ABI *)(uint64_t*);
  const auto increment = reinterpret_cast<Ownership>(increment_symbol->vaddr);
  const auto decrement = reinterpret_cast<Ownership>(decrement_symbol->vaddr);
  Check(increment(nullptr) == -1 && increment(reinterpret_cast<uint64_t*>(dso)) == 0 &&
            program->pending_thread_atexit == 1 &&
            unload(handle, 0, nullptr, 0, nullptr, &result) == KERNEL_ERROR_EBUSY &&
            *reinterpret_cast<const uint64_t*>(dso) == dso,
        "native DSO increment owns the module without writing through the DSO pointer");
  Check(decrement(reinterpret_cast<uint64_t*>(dso)) == 0 && program->pending_thread_atexit == 0,
        "native DSO decrement releases the owner count");
  Pthread child = nullptr;
  Check(PthreadCreate(&child, nullptr, ThreadAtexitOwnerEntry, &fixture, "thread_atexit_owner") == 0,
        "create guest Pthread for mapped destructor ownership");
  while (!fixture.ready.load(std::memory_order_acquire)) std::this_thread::yield();
  const int attempted = unload(handle, 0, nullptr, 0, nullptr, &result);
  if (attempted != KERNEL_ERROR_EBUSY) {
    std::printf("ThreadAtexitLifetimeTests: pending_owner_unload=%d mapped=%d; exiting before dangling callback execution\n",
        attempted, linker->FindProgramById(handle) != nullptr);
    std::fflush(stdout);
    std::quick_exit(1);
  }
  Check(linker->FindProgramById(handle) == program && program->load_count == 1 &&
            g_module_lifetime.stops[3] == 0,
        "other guest thread retains module, acquisition and finalizer before cleanup");
  Check(program->needed_modules.size() == 1 && program->needed_modules[0].provider == provider &&
            linker->StopModule(provider, 0, nullptr, nullptr) == KERNEL_ERROR_EBUSY,
        "pending DSO ownership also prevents dependency finalization");
  linker->StopAllModules();
  linker->Clear();
  Check(linker->FindProgramById(handle) == program && g_module_lifetime.stops[3] == 0 &&
            linker->FindProgramById(provider_handle) == provider && g_module_lifetime.stops[1] == 0,
        "process finalization and clear defer while thread destructor ownership remains");
  fixture.release_thread.store(true, std::memory_order_release);
  while (!fixture.entered.load(std::memory_order_acquire)) std::this_thread::yield();
  Check(unload(handle, 0, nullptr, 0, nullptr, &result) == KERNEL_ERROR_EBUSY &&
            linker->FindProgramById(handle) == program,
        "module remains owned across popped destructor invocation and reentrant registration");
  fixture.release_callback.store(true, std::memory_order_release);
  Check(PthreadJoin(child, nullptr) == 0 && fixture.order == "BCA",
        "guest Pthread cleanup runs LIFO and reentrant destructors exactly once");
  Check(program->pending_thread_atexit == 0,
        "all callback owner references release after guest thread cleanup");
  Check(unload(handle, 0, nullptr, 0, nullptr, &result) == 0 && g_module_lifetime.stops[3] == 1,
        "module can finalize and unload after all thread callbacks return");
  CheckModuleLifetimeUnmapped(handle, address);
  Check(registration(fixture.callback, &fixture.objects[0], fixture.dso) == -1,
        "unmapped guest destructor and DSO cannot become an untracked host callback");
  Check(unload(provider_handle, 0, nullptr, 0, nullptr, &result) == 0 && g_module_lifetime.stops[1] == 1,
        "callback dependency finalizes once after owner cleanup and unload");
  CheckModuleLifetimeUnmapped(provider_handle, provider_address);
  linker->Clear();
  FileSystem::Umount("/thread_atexit_owner");
  FileSystem::Umount("/app0/sce_module");
  std::printf("ThreadAtexitLifetimeTests: mapped_dso=pass pending_owner=pass callback_pin=pass reentry=pass LIFO=pass guest_thread_cleanup=pass\n");
}
