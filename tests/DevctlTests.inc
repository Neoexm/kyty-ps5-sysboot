#if defined(_WIN32)
// /dev/devctl with no record producer: one opener at a time, FIONBIO/FIOASYNC only, no writes. A blocking read would never return, so it is not exercised.
void CheckDevctl() {
  using namespace Libs::LibKernel;
  const int fd = FileSystem::KernelOpen("/dev/devctl", 4, 0);
  Check(fd >= 3, "devctl opens");
  Check(FileSystem::KernelOpen("/dev/devctl", 0, 0) == KERNEL_ERROR_EBUSY, "devctl takes a single opener");
  int32_t on = 1;
  Check(FileSystem::KernelIoctl(fd, 0x8004667e, &on) == OK, "FIONBIO");
  std::array<uint8_t, 0x400> record {};
  Check(FileSystem::KernelRead(fd, record.data(), 0x3ff) == KERNEL_ERROR_EAGAIN, "a nonblocking read of the empty queue is EAGAIN");
  Check(FileSystem::KernelIoctl(fd, 0x8004667d, &on) == OK && FileSystem::KernelIoctl(fd, 0x8004667d, nullptr) == KERNEL_ERROR_EFAULT,
        "FIOASYNC takes an int");
  Check(FileSystem::KernelIoctl(fd, 0x8004667c, &on) == KERNEL_ERROR_ENOSYS && FileSystem::KernelIoctl(fd, 0x4004667b, &on) == KERNEL_ERROR_ENOSYS,
        "the SIGIO owner ioctls are not modelled");
  Check(FileSystem::KernelIoctl(fd, 0xc0044e05, &on) == KERNEL_ERROR_ENOTTY, "other ioctls are ENOTTY");
  Check(FileSystem::KernelWrite(fd, record.data(), 4) == KERNEL_ERROR_EBADF, "a read-only descriptor cannot write");
  Check(FileSystem::KernelClose(fd) == OK, "close devctl");
  const int again = FileSystem::KernelOpen("/dev/devctl", 2, 0);
  Check(again >= 3, "closing devctl frees it");
  Check(FileSystem::KernelWrite(again, record.data(), 4) == KERNEL_ERROR_ENODEV, "devctl has no write");
  Check(FileSystem::KernelClose(again) == OK, "close devctl again");
}
#endif
