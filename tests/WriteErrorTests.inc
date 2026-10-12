void CheckWriteErrors(const std::filesystem::path& root) {
#if defined(_WIN32)
  using namespace Libs::LibKernel;
  const auto path = root / "write-error.bin";
  FileSystem::Mount(root, "/write-error");
  const int fd = FileSystem::KernelOpen("/write-error/write-error.bin", 0x602, 0600);
  Check(fd >= 3 && FileSystem::KernelWrite(fd, "abcdefgh", 8) == 8 &&
        FileSystem::KernelLseek(fd, 0, 0) == 0, "populate write failure backing");
  HANDLE locker = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
  OVERLAPPED range {};
  Check(locker != INVALID_HANDLE_VALUE &&
        LockFileEx(locker, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                   0, 8, 0, &range) != 0, "lock only disposable write failure bytes");
  const auto written = FileSystem::KernelWrite(fd, "XY", 2);
  const auto positioned = FileSystem::KernelPwrite(fd, "XY", 2, 0);
  FileSystem::KernelIovec vector {const_cast<char*>("XY"), 2};
  const auto vectored = FileSystem::KernelPwritev(fd, &vector, 1, 0);
  Check(UnlockFileEx(locker, 0, 8, 0, &range) != 0,
        "unlock backing before checking write error results");
  std::printf("WriteErrorTests: write=%lld pwrite=%lld pwritev=%lld expected=%d\n",
      static_cast<long long>(written), static_cast<long long>(positioned),
      static_cast<long long>(vectored), KERNEL_ERROR_EIO);
  std::fflush(stdout);
  Check(written == KERNEL_ERROR_EIO && positioned == KERNEL_ERROR_EIO && vectored == KERNEL_ERROR_EIO,
        "host WriteFile failure returns EIO through every regular write path");
  Check(FileSystem::KernelLseek(fd, 0, 1) == 0, "failed writes preserve descriptor cursor");
  range.Offset = 2;
  Check(LockFileEx(locker, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                   0, 2, 0, &range) != 0, "lock only second write vector");
  const FileSystem::KernelIovec partial[] {{const_cast<char*>("XY"), 2}, {const_cast<char*>("ZW"), 2}};
  const auto partial_result = FileSystem::KernelPwritev(fd, partial, 2, 0);
  Check(UnlockFileEx(locker, 0, 2, 0, &range) != 0 && CloseHandle(locker) != 0,
        "release write error host handle");
  std::array<char, 8> bytes {};
  Check(partial_result == 2 && FileSystem::KernelLseek(fd, 0, 1) == 0 &&
        FileSystem::KernelPread(fd, bytes.data(), bytes.size(), 0) == 8 &&
        std::memcmp(bytes.data(), "XYcdefgh", 8) == 0,
        "later vector failure retains only completed bytes and independent cursor");
  Check(FileSystem::KernelPwrite(fd, "ZW", 2, 2) == 2 &&
        FileSystem::KernelPread(fd, bytes.data(), bytes.size(), 0) == 8 &&
        std::memcmp(bytes.data(), "XYZWefgh", 8) == 0,
        "write can retry after the host failure is removed");
  Check(FileSystem::KernelClose(fd) == OK, "close write error descriptor");
  FileSystem::Umount("/write-error");
  std::printf("WriteErrorTests: host_failure=pass partial_bytes=pass retry=pass cursor=pass\n");
#endif
}
