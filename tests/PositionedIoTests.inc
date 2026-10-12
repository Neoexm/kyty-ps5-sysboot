void CheckPositionedIo(const std::filesystem::path& root, const char* selection) {
  namespace Kernel = Libs::LibKernel;
  const bool all = std::strcmp(selection, "all") == 0;
  FileSystem::Mount(root, "/positioned");
  std::array<char, 8> bytes {};
  if (all || std::strcmp(selection, "directory") == 0) {
    const int fd = FileSystem::KernelOpen("/positioned", 0, 0);
    Check(fd >= 3, "open positioned directory fixture");
    std::printf("PositionedIoTests: directory pread begin\n");
    std::fflush(stdout);
    Check(FileSystem::KernelPread(fd, bytes.data(), 1, 0) == Kernel::KERNEL_ERROR_EISDIR,
          "positioned directory read returns EISDIR without host abort");
    Check(FileSystem::KernelClose(fd) == OK, "close positioned directory fixture");
  }
  if (all || std::strcmp(selection, "pipe") == 0) {
    int fds[2] {};
    Check(FileSystem::KernelPipe(fds) == OK, "create positioned pipe fixture");
    const auto result = FileSystem::KernelPread(fds[1], bytes.data(), 1, 0);
    std::printf("PositionedIoTests: pipe pread=%lld expected=%d\n",
                static_cast<long long>(result), Kernel::KERNEL_ERROR_ESPIPE);
    Check(result == Kernel::KERNEL_ERROR_ESPIPE, "positioned pipe read returns ESPIPE");
    FileSystem::KernelIovec vector {bytes.data(), 1};
    Check(FileSystem::KernelPreadv(fds[1], &vector, 1, 0) == Kernel::KERNEL_ERROR_ESPIPE &&
          FileSystem::KernelPwritev(fds[0], &vector, 1, 0) == Kernel::KERNEL_ERROR_ESPIPE,
          "positioned pipe vectors return ESPIPE");
    Check(FileSystem::KernelClose(fds[0]) == OK && FileSystem::KernelClose(fds[1]) == OK,
          "close positioned pipe fixture");
  }
  if (all || std::strcmp(selection, "regular") == 0) {
    const int fd = FileSystem::KernelOpen("/positioned/data", 0x602, 0600);
    Check(fd >= 3 && FileSystem::KernelWrite(fd, "abcdefgh", 8) == 8 &&
          FileSystem::KernelLseek(fd, 3, 0) == 3, "populate positioned regular fixture");
    Check(FileSystem::KernelPread(fd, nullptr, 0, 1) == 0 &&
          FileSystem::KernelPwrite(fd, nullptr, 0, 1) == 0,
          "zero positioned transfer accepts null buffer");
    Check(FileSystem::KernelPread(fd, reinterpret_cast<void*>(1), 1, 0) == Kernel::KERNEL_ERROR_EFAULT &&
          FileSystem::KernelPwrite(fd, reinterpret_cast<void*>(1), 1, 0) == Kernel::KERNEL_ERROR_EFAULT,
          "invalid positioned scalar pointers return EFAULT");
    std::array<FileSystem::KernelIovec, 2> vectors {{{bytes.data(), 1}, {reinterpret_cast<void*>(1), 1}}};
    Check(FileSystem::KernelPreadv(fd, vectors.data(), 2, 0) == Kernel::KERNEL_ERROR_EFAULT &&
          FileSystem::KernelPwritev(fd, vectors.data(), 2, 0) == Kernel::KERNEL_ERROR_EFAULT,
          "invalid positioned vector spans fail before transfer");
    Check(FileSystem::KernelLseek(fd, 0, 1) == 3 &&
          FileSystem::KernelPread(fd, bytes.data(), bytes.size(), 0) == 8 &&
          std::memcmp(bytes.data(), "abcdefgh", 8) == 0,
          "failed positioned transfers preserve cursor and backing");
    Check(FileSystem::KernelPread(fd, bytes.data(), 1, -1) == Kernel::KERNEL_ERROR_EINVAL &&
          FileSystem::KernelPwrite(fd, bytes.data(), 1, -1) == Kernel::KERNEL_ERROR_EINVAL,
          "negative positioned offsets return EINVAL");
    Check(FileSystem::KernelClose(fd) == OK, "close positioned regular fixture");
    Check(FileSystem::KernelPread(fd, bytes.data(), 1, 0) == Kernel::KERNEL_ERROR_EBADF,
          "closed positioned descriptor returns EBADF");
    Check(FileSystem::KernelPread(-1, bytes.data(), 1, 0) == Kernel::KERNEL_ERROR_EBADF,
          "negative positioned descriptor returns EBADF");
  }
  FileSystem::Umount("/positioned");
  std::printf("PositionedIoTests: selection=%s passed\n", selection);
}
