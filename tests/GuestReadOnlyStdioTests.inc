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
  using Gets = char* (KYTY_SYSV_ABI *)(char*, int, void*);
  using Seek = int (KYTY_SYSV_ABI *)(void*, int64_t, int);
  using Tell = int64_t (KYTY_SYSV_ABI *)(void*);
  const auto open = reinterpret_cast<Open>(find("xeYO4u7uyJ0"));
  const auto close = reinterpret_cast<Close>(find("uodLYyUip20"));
  const auto read = reinterpret_cast<Read>(find("lbB+UlZqVG0"));
  const auto gets = reinterpret_cast<Gets>(find("KdP-nULpuGw"));
  const auto seek = reinterpret_cast<Seek>(find("rQFVBXp-Cxg"));
  const auto tell = reinterpret_cast<Tell>(find("Qazy8LmXTvw"));
  const auto backing = root / "read_only_stdio";
  Check(std::filesystem::create_directory(backing), "create scoped stdio backing directory");
  const std::array<uint8_t, 13> payload {{'F', 'T', 0, '\r', '\n', 0xff, 0x81, 3, 4, 5, 6, 7, 8}};
  Common::File fixture;
  Check(fixture.Create(backing / "bytes.bin"), "create backed binary fixture");
  fixture.Write(payload.data(), payload.size());
  fixture.Close();
  constexpr char lines[] = "alpha\nbeta\r\nomega";
  Common::File text_fixture;
  Check(text_fixture.Create(backing / "lines.txt"), "create backed text fixture");
  text_fixture.Write(lines, sizeof(lines) - 1);
  text_fixture.Close();
  FileSystem::MountReadOnly(backing, "/stdio_read_test");
  const auto address = Memory::AllocateProgramMemory(0, 0x4000,
      Common::VirtualMemory::Mode::ReadWrite, "stdio_read_test");
  Check(address != 0, "allocate guest read destination");
  auto* bytes = reinterpret_cast<uint8_t*>(address);
  char path[] = "/stdio_read_test/bytes.bin";
  char binary_mode[] = "rb";
  auto* error = Libs::Posix::GetErrorAddr();
  void* line_stream = open("/stdio_read_test/lines.txt", "r");
  Check(line_stream != nullptr, "open mounted text file for fgets");
  Check(gets(reinterpret_cast<char*>(bytes), 4, line_stream) == reinterpret_cast<char*>(bytes) &&
        std::strcmp(reinterpret_cast<char*>(bytes), "alp") == 0 && tell(line_stream) == 3,
        "fgets respects buffer size and advances guest descriptor");
  Check(gets(reinterpret_cast<char*>(bytes), 16, line_stream) == reinterpret_cast<char*>(bytes) &&
        std::strcmp(reinterpret_cast<char*>(bytes), "ha\n") == 0 && tell(line_stream) == 6,
        "fgets stops at newline and preserves unread bytes");
  Check(gets(reinterpret_cast<char*>(bytes), 16, line_stream) == reinterpret_cast<char*>(bytes) &&
        std::strcmp(reinterpret_cast<char*>(bytes), "beta\r\n") == 0 && tell(line_stream) == 12,
        "fgets preserves CRLF from original file");
  Check(gets(reinterpret_cast<char*>(bytes), 16, line_stream) == reinterpret_cast<char*>(bytes) &&
        std::strcmp(reinterpret_cast<char*>(bytes), "omega") == 0 &&
        gets(reinterpret_cast<char*>(bytes), 16, line_stream) == nullptr && tell(line_stream) == 17,
        "fgets returns final unterminated line then EOF");
  Check(seek(line_stream, 0, 0) == 0 && read(bytes, 1, 6, line_stream) == 6 &&
        std::memcmp(bytes, "alpha\n", 6) == 0,
        "fgets and fread share the same guest cursor");
  *error = 0;
  Check(gets(reinterpret_cast<char*>(1), 16, line_stream) == nullptr &&
        *error == Libs::Posix::POSIX_EFAULT && tell(line_stream) == 6 &&
        close(line_stream) == 0,
        "fgets rejects invalid guest buffers before consuming file data");
  *error = Libs::Posix::POSIX_EIO;
  void* stream = open(path, binary_mode);
  Check(stream != nullptr && *error == Libs::Posix::POSIX_EIO,
        "mounted file opens from original-style current stack path and mode");
  Check(seek(stream, 0, 2) == 0 && tell(stream) == static_cast<int64_t>(payload.size()) &&
        seek(stream, 0, 0) == 0 && tell(stream) == 0,
        "FreeType size-query and rewind sequence uses guest descriptor position");
  std::memset(bytes, 0xa7, 64);
  Check(read(bytes + 16, 1, 100, stream) == payload.size() &&
        std::memcmp(bytes + 16, payload.data(), payload.size()) == 0,
        "read returns backed binary bytes including NUL and CRLF without text conversion");
  for (size_t i = 0; i < 16; ++i) Check(bytes[i] == 0xa7, "read preserves leading destination canary");
  for (size_t i = 16 + payload.size(); i < 64; ++i)
    Check(bytes[i] == 0xa7, "short read changes only bytes actually read");
  Check(tell(stream) == static_cast<int64_t>(payload.size()) && read(bytes + 16, 1, 1, stream) == 0,
        "EOF returns zero and position stays at file end");
  Check(seek(stream, 0, 0) == 0 && read(bytes + 16, 4, 4, stream) == 3 &&
        tell(stream) == static_cast<int64_t>(payload.size()),
        "fread returns complete item count while consuming final partial item bytes");
  Check(seek(stream, -3, 2) == 0 && tell(stream) == 10 &&
        read(bytes + 16, 1, 3, stream) == 3 && std::memcmp(bytes + 16, payload.data() + 10, 3) == 0,
        "signed 64-bit end-relative seek and sequential read share one stream position");
  Check(seek(stream, -2, 1) == 0 && tell(stream) == 11,
        "current-relative seek uses descriptor cursor");
  Check(read(bytes + 16, SIZE_MAX, 2, stream) == 0 && *error == Libs::Posix::POSIX_EINVAL &&
        tell(stream) == 11, "native fread multiplication overflow returns EINVAL without reading");
  *error = Libs::Posix::POSIX_EIO;
  Check(read(nullptr, 0, SIZE_MAX, nullptr) == 0 && read(nullptr, SIZE_MAX, 0, nullptr) == 0 &&
        *error == Libs::Posix::POSIX_EIO, "native zero-item read returns before accessing stream or buffer");
  Check(seek(stream, 0, 99) != 0 && *error == Libs::Posix::POSIX_EINVAL && tell(stream) == 11,
        "invalid seek origin reports native errno and preserves cursor");
  Check(seek(stream, int64_t{1} << 34, 0) == 0 && tell(stream) == (int64_t{1} << 34),
        "file cursor retains offsets beyond Windows 32-bit long without writing file data");
  Check(close(stream) == 0 && close(stream) == -1 && *error == Libs::Posix::POSIX_EBADF,
        "close releases descriptor and rejects a retired stream");
  stream = open(path, "r");
  Check(stream != nullptr, "read-only r mode also opens through guest mounts");
  std::array<uint8_t, 13> stack_bytes {};
  Check(read(stack_bytes.data(), 1, stack_bytes.size(), stream) == stack_bytes.size() && stack_bytes == payload,
        "read supports validated current stack destinations");
  Check(seek(stream, 0, 0) == 0 && read(reinterpret_cast<void*>(1), 1, 1, stream) == 0 &&
        *error == Libs::Posix::POSIX_EFAULT && tell(stream) == 0,
        "unowned destination is rejected before consuming file bytes");
  Check(Memory::KernelMprotect(bytes, 0x4000, 1) == 0, "protect registered stdio destination read-only");
  Check(read(bytes, 1, 1, stream) == 0 && *error == Libs::Posix::POSIX_EFAULT && tell(stream) == 0,
        "read cannot write through a read-only registered mapping");
  Check(Memory::KernelMprotect(bytes, 0x4000, 3) == 0, "restore stdio destination permissions");
  Loader::SymbolDatabase heap_symbols;
  Libs::InitJemspace_1(&heap_symbols);
  const auto heap_alloc = reinterpret_cast<void* (KYTY_SYSV_ABI *)(void*, size_t)>(
      heap_symbols.FindByNid("IUMgip-Glc4", Loader::SymbolType::Func)->vaddr);
  const auto heap_free = reinterpret_cast<int (KYTY_SYSV_ABI *)(void*, void*)>(
      heap_symbols.FindByNid("KMxjh6mb1yk", Loader::SymbolType::Func)->vaddr);
  auto* heap_bytes = static_cast<uint8_t*>(heap_alloc(nullptr, 64));
  Check(heap_bytes != nullptr && read(heap_bytes, 1, payload.size(), stream) == payload.size() &&
        std::memcmp(heap_bytes, payload.data(), payload.size()) == 0,
        "read supports tracked Jemspace callback allocations");
  Check(seek(stream, 0, 0) == 0 && read(heap_bytes + 63, 1, 2, stream) == 0 &&
        *error == Libs::Posix::POSIX_EFAULT && tell(stream) == 0,
        "read rejects an interior Jemspace span exceeding the requested allocation");
  Check(heap_free(nullptr, heap_bytes) == 0 && close(stream) == 0,
        "release tracked allocator buffer and read-only stream");
  Check(open("/stdio_read_test/missing.bin", "rb") == nullptr && *error == Libs::Posix::POSIX_ENOENT,
        "missing backed file returns namespace ENOENT");
  const auto host_path = Common::PathToGenericString(backing / "bytes.bin");
  Check(std::filesystem::exists(backing / "bytes.bin") && open(host_path.c_str(), "rb") == nullptr &&
        *error == Libs::Posix::POSIX_ENOENT,
        "an existing unmounted host path remains inaccessible through guest fopen");
  Check(open(path, "invalid") == nullptr && *error == Libs::Posix::POSIX_EINVAL,
        "invalid mode creates no stream");
  Check(open(path, "rb+") == nullptr && *error == Libs::Posix::POSIX_ENOSYS,
        "unsupported update mode is not silently changed to read-only");
#if defined(_WIN32)
  stream = open(path, "rb");
  Check(stream != nullptr, "open stream for host read failure");
  const int failure_fd = FileSystem::KernelOpen(path, 0, 0);
  Check(failure_fd >= 0 && FileSystem::KernelLseek(failure_fd, 3, 0) == 3,
        "open positioned descriptor for host read failure");
  Common::File host_reader(backing / "bytes.bin", Common::File::Mode::Read);
  Check(!host_reader.IsInvalid(), "open direct host reader for raw failure status");
  const HANDLE locker = CreateFileW((backing / "bytes.bin").c_str(), GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
  Check(locker != INVALID_HANDLE_VALUE, "open temporary file range-lock handle");
  OVERLAPPED range {};
  Check(LockFileEx(locker, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0,
        payload.size(), 0, &range) != 0, "lock only the owned fixture byte range");
  std::memset(bytes, 0xa7, 64);
  uint32_t host_bytes = 99;
  std::error_code host_error = std::make_error_code(std::errc::invalid_argument);
  host_reader.Read(bytes, 2, &host_bytes, &host_error);
  const auto failed_read = FileSystem::KernelRead(failure_fd, bytes, 2);
  const auto failed_pread = FileSystem::KernelPread(failure_fd, bytes, 2, 0);
  const FileSystem::KernelIovec failure_iov[] {{bytes, 1}, {bytes + 1, 1}};
  const auto failed_preadv = FileSystem::KernelPreadv(failure_fd, failure_iov, 2, 0);
  *error = 0;
  const auto failed_items = read(bytes, 1, payload.size(), stream);
  const int read_error = *error;
  Check(UnlockFileEx(locker, 0, payload.size(), 0, &range) != 0 && CloseHandle(locker) != 0,
        "release owned host byte-range lock before checking results");
  std::printf("GuestReadOnlyStdioHostFailure: host_error=%d host_bytes=%u read=%lld pread=%lld preadv=%lld items=%zu errno=%d\n",
      host_error.value(), host_bytes, static_cast<long long>(failed_read), static_cast<long long>(failed_pread),
      static_cast<long long>(failed_preadv), failed_items, read_error);
  std::fflush(stdout);
  Check(host_bytes == 0 && host_error == std::error_code(ERROR_LOCK_VIOLATION, std::system_category()),
        "direct host reader preserves the failed ReadFile error code independently of bytes");
  Check(failed_read == KERNEL_ERROR_EIO && failed_pread == KERNEL_ERROR_EIO && failed_preadv == KERNEL_ERROR_EIO &&
        failed_items == 0 && read_error == Libs::Posix::POSIX_EIO,
        "host read failure is an I/O error rather than EOF through read, pread, preadv and fread");
  Check(bytes[0] == 0xa7 && tell(stream) == 0 && FileSystem::KernelLseek(failure_fd, 0, 1) == 3,
        "failed host reads leave destination and independent descriptor positions intact");
  *error = 0;
  Check(read(bytes, 1, payload.size(), stream) == payload.size() &&
        std::memcmp(bytes, payload.data(), payload.size()) == 0 && *error == 0,
        "fread can retry a read error without seeking or falsely retaining EOF");
  Check(FileSystem::KernelPread(failure_fd, bytes, 2, 0) == 2 &&
        std::memcmp(bytes, payload.data(), 2) == 0 && FileSystem::KernelLseek(failure_fd, 0, 1) == 3,
        "pread recovers after lock release while preserving sequential cursor");
  Check(FileSystem::KernelRead(failure_fd, bytes, 2) == 2 && bytes[0] == payload[3] &&
        bytes[1] == payload[4] && FileSystem::KernelLseek(failure_fd, 0, 1) == 5,
        "read recovers after lock release and advances only by successful bytes");
  host_reader.Read(bytes, 64, &host_bytes, &host_error);
  Check(host_bytes == payload.size() && !host_error && host_reader.Tell() == payload.size(),
        "successful short host read clears previous error and reports only backed bytes");
  host_error = std::make_error_code(std::errc::io_error);
  host_reader.Read(bytes, 1, &host_bytes, &host_error);
  Check(host_bytes == 0 && !host_error, "host EOF clears stale error and remains distinct from failure");
  host_reader.Close();
  range.Offset = 2;
  const HANDLE partial_locker = CreateFileW((backing / "bytes.bin").c_str(), GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
  Check(partial_locker != INVALID_HANDLE_VALUE &&
        LockFileEx(partial_locker, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 2, 0, &range) != 0,
        "lock only the second vector range of the owned fixture");
  std::memset(bytes, 0xa7, 64);
  const FileSystem::KernelIovec partial_iov[] {{bytes, 2}, {bytes + 2, 2}};
  const auto partial_bytes = FileSystem::KernelPreadv(failure_fd, partial_iov, 2, 0);
  Check(UnlockFileEx(partial_locker, 0, 2, 0, &range) != 0 && CloseHandle(partial_locker) != 0,
        "release owned partial-read lock before checking result");
  Check(partial_bytes == 2 && std::memcmp(bytes, payload.data(), 2) == 0 && bytes[2] == 0xa7 &&
        FileSystem::KernelLseek(failure_fd, 0, 1) == 5,
        "preadv retains successful first-vector bytes when the later host read fails");
  std::printf("GuestReadOnlyStdioPartialHostFailure: completed_bytes=%lld cursor_preserved=1\n",
      static_cast<long long>(partial_bytes));
  Check(close(stream) == 0 && FileSystem::KernelClose(failure_fd) == 0,
        "close all descriptors from host failure test");
#endif
  auto memory_payload = payload;
  Common::File memory_reader;
  Check(memory_reader.OpenInMem(memory_payload.data(), memory_payload.size()), "open bounded memory backing");
  uint32_t memory_bytes = 0;
  std::error_code memory_error = std::make_error_code(std::errc::io_error);
  memory_reader.Read(bytes, 64, &memory_bytes, &memory_error);
  Check(memory_bytes == payload.size() && !memory_error && std::memcmp(bytes, payload.data(), payload.size()) == 0,
        "memory backing reports successful short bytes separately from stale error status");
  memory_error = std::make_error_code(std::errc::io_error);
  memory_reader.Read(bytes, 1, &memory_bytes, &memory_error);
  Check(memory_bytes == 0 && !memory_error, "memory backing EOF clears stale read error");
  memory_reader.Close();
  Check(Memory::FreeGuestMemory(address, 0x4000), "release guest stdio fixture buffer");
  FileSystem::Umount("/stdio_read_test");
  std::printf("GuestReadOnlyStdioTests: actual_backing=pass binary_bytes=pass seek64=pass partial_items=pass EOF=pass guest_stack_Jemspace_bounds=pass namespace_isolation=pass error_paths=pass\n");
}
