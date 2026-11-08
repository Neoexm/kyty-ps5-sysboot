void CheckNativeMetadbg() {
  using namespace Libs::LibKernel;
  void* storage = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&storage, 0x4000, 3, 0, "metadbg-test") == OK,
        "allocate guest metadbg outputs");
  const char* configured = std::getenv("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS");
  const bool configured_present = configured != nullptr;
  const std::string configured_value = configured_present ? configured : "";
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS", "") == 0,
        "test retail imports without broad syscall guards");
#else
  Check(unsetenv("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS") == 0,
        "test retail imports without broad syscall guards");
#endif
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS", configured_value.c_str()) == 0,
        "restore syscall guard fixture environment");
#else
  Check((configured_present ? setenv("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS", configured_value.c_str(), 1)
                            : unsetenv("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS")) == 0,
        "restore syscall guard fixture environment");
#endif
  auto* log_output = static_cast<uint8_t*>(storage) + 0x800;
  auto* log_size = reinterpret_cast<uint64_t*>(log_output + 0x100);
  Loader::SymbolResolve query {"OX9wtyjVAJY", "libkernel", 1, "libkernel", 1, 1, Loader::SymbolType::Func};
  const auto* query_symbol = symbols.Find(query);
  Check(query_symbol != nullptr, "resolve SysCore syscall-609 wrapper without broad guards");
  using Query = int (KYTY_SYSV_ABI *)(uint64_t);
  const auto query_call = reinterpret_cast<Query>(query_symbol->vaddr);
  std::memset(log_output, 0xa5, 0x100);
  for (uint64_t output : {reinterpret_cast<uint64_t>(log_output), uint64_t {0}, uint64_t {1}}) {
    *Libs::Posix::GetErrorAddr() = 0;
    Check(query_call(output) == KERNEL_ERROR_ENOSYS && *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOSYS &&
              std::all_of(log_output, log_output + 0x100, [](uint8_t x) { return x == 0xa5; }),
          "retail syscall-609 wrapper returns translated ENOSYS before reading or writing an output");
  }
  Loader::SymbolResolve raw {"7KuwdAt0kQQ", "libkernel", 1, "libkernel", 1, 1, Loader::SymbolType::Func};
  const auto* raw_symbol = symbols.Find(raw);
  Check(raw_symbol != nullptr, "resolve SysCore raw mdbg syscall without broad guards");
  using RawCall = int64_t (KYTY_SYSV_ABI *)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
  *Libs::Posix::GetErrorAddr() = 0;
  Check(reinterpret_cast<RawCall>(raw_symbol->vaddr)(1, reinterpret_cast<uint64_t>(log_output), 0x100, 0, 0, 0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOSYS &&
            std::all_of(log_output, log_output + 0x100, [](uint8_t x) { return x == 0xa5; }),
        "retail mdbg import follows cerror ABI and preserves caller storage");
  for (const char* nid : {"ilQLkGlAjWA", "W7Vpt62Xtf4", "JFpAREOJnag"}) {
    Loader::SymbolResolve resolve {nid, "libkernel_devtoollog", 1, "libkernel", 1, 1, Loader::SymbolType::Func};
    const auto* symbol = symbols.Find(resolve);
    Check(symbol != nullptr, "resolve devtool-log library export");
    using Call = int (KYTY_SYSV_ABI *)(uint64_t, uint64_t, uint64_t);
    std::memset(log_output, 0xa5, 0x100);
    *log_size = 0x80;
    *Libs::Posix::GetErrorAddr() = 0;
    const auto result = reinterpret_cast<Call>(symbol->vaddr)(
        reinterpret_cast<uint64_t>(log_output), reinterpret_cast<uint64_t>(log_output + 0x40),
        reinterpret_cast<uint64_t>(log_size));
    Check(result == KERNEL_ERROR_UNKNOWN - 1 && *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOSYS &&
          *log_size == 0x80 && std::all_of(log_output, log_output + 0x100, [](uint8_t x) { return x == 0xa5; }),
          "devtool-log wrappers preserve outputs and translate retail nosys exactly");
  }
  auto* stat = static_cast<FileSystem::FileStat*>(storage);
  Check(FileSystem::KernelStat("/dev/metadbg", stat) == OK && stat->st_mode == 0020600u && stat->st_nlink == 1,
        "metadbg exposes the captured character-device mode");
  Check(FileSystem::KernelStat("/dev/metadbg", reinterpret_cast<FileSystem::FileStat*>(1)) == KERNEL_ERROR_EFAULT,
        "metadbg stat rejects invalid guest output");
  for (const int flags: {3, 0x20000, 0x202, 0x402, 0x802, 0xa, 0x10002}) {
    Check(FileSystem::KernelOpen("/dev/metadbg", flags, 0) ==
              (flags == 0x20000 ? KERNEL_ERROR_ENOTDIR : KERNEL_ERROR_EINVAL),
          "metadbg rejects unsupported access flags");
  }
  const int first = FileSystem::KernelOpen("/dev/metadbg", 0x100002, 0);
  const int second = FileSystem::KernelOpen("/dev/metadbg", 6, 0);
  const int writer = FileSystem::KernelOpen("/dev/metadbg", 1, 0);
  Check(first >= 3 && second >= 3 && writer >= 3 && first != second && first != writer && second != writer,
        "metadbg owns distinct descriptors for its shared stream");
  Check(FileSystem::GetDescriptorFlags(first) == 1 && FileSystem::KernelFstat(first, stat) == OK && stat->st_mode == 0020600u,
        "metadbg preserves close-on-exec and descriptor metadata");
  Check(FileSystem::KernelFstat(first, reinterpret_cast<FileSystem::FileStat*>(1)) == KERNEL_ERROR_EFAULT,
        "metadbg fstat checks guest memory");
  auto* buffer = static_cast<uint8_t*>(storage) + 0x400;
  auto* other_buffer = buffer + 0x40;
  std::memset(buffer, 0xa5, 0x80);
  Check(FileSystem::KernelRead(first, nullptr, 0) == 0 &&
            FileSystem::KernelRead(first, reinterpret_cast<void*>(1), 0x20) == KERNEL_ERROR_EFAULT &&
            FileSystem::KernelRead(writer, buffer, 0x20) == KERNEL_ERROR_EBADF,
        "metadbg validates access and writable read buffers before waiting");
  Check(FileSystem::KernelRead(first, buffer, static_cast<size_t>(std::numeric_limits<int>::max()) + 1) == KERNEL_ERROR_EINVAL &&
            FileSystem::KernelWrite(first, buffer, 1) == KERNEL_ERROR_ENODEV &&
            FileSystem::KernelIoctl(first, 0, buffer) == KERNEL_ERROR_ENODEV &&
            FileSystem::KernelLseek(first, 0, 0) == KERNEL_ERROR_ESPIPE,
        "metadbg rejects unsupported driver operations without data production");
  std::promise<void> first_started, second_started;
  auto first_ready = first_started.get_future();
  auto second_ready = second_started.get_future();
  auto first_read = std::async(std::launch::async, [&] {
    first_started.set_value();
    return FileSystem::KernelRead(first, buffer, 0x20);
  });
  auto second_read = std::async(std::launch::async, [&] {
    second_started.set_value();
    return FileSystem::KernelRead(second, other_buffer, 0x20);
  });
  first_ready.wait();
  second_ready.wait();
  Check(first_read.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout &&
            second_read.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout,
        "empty metadbg reads block for both ordinary and nonblocking open flags");
  Check(std::all_of(buffer, buffer + 0x80, [](uint8_t byte) { return byte == 0xa5; }),
        "empty metadbg stream leaves guest buffers untouched");
  Check(FileSystem::KernelClose(first) == OK, "close first metadbg reader");
  const int reused = FileSystem::KernelOpen("/dev/metadbg", 2, 0);
  Check(reused >= 3 && first_read.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout,
        "closing and reusing a descriptor leaves an already pinned read alive");
  Check(second_read.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout,
        "closing one metadbg handle leaves the shared stream and another reader alive");
  Check(FileSystem::KernelClose(second) == OK &&
            second_read.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout,
        "removing the second descriptor preserves its active file reference");
  Check(std::all_of(buffer, buffer + 0x80, [](uint8_t byte) { return byte == 0xa5; }) &&
            FileSystem::KernelClose(reused) == OK && FileSystem::KernelClose(writer) == OK &&
            FileSystem::KernelRead(first, buffer, 1) == KERNEL_ERROR_EBADF,
        "metadbg closing produces no bytes and retires descriptor numbers");
  FileSystem::EmergencyShutdown();
  Check(first_read.wait_for(std::chrono::seconds(2)) == std::future_status::ready &&
            second_read.wait_for(std::chrono::seconds(2)) == std::future_status::ready &&
            first_read.get() == KERNEL_ERROR_ECANCELED && second_read.get() == KERNEL_ERROR_ECANCELED,
        "explicit host teardown cancels pinned internal waits");
  Check(std::all_of(buffer, buffer + 0x80, [](uint8_t byte) { return byte == 0xa5; }),
        "host teardown writes no debugger record");
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(storage), 0x4000) == OK,
        "release guest metadbg test outputs");
  std::printf("NativeMetadbgTests: empty shared stream blocks; active reads pin files; host teardown cancels internally\n");
}
