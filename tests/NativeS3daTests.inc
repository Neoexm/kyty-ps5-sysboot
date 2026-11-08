void CheckNativeS3da() {
  using namespace Libs::LibKernel;
  void* storage = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&storage, 0x4000, 3, 0, "s3da-stat-test") == OK,
        "allocate guest S3DA stat output");
  auto& path_stat = *static_cast<FileSystem::FileStat*>(storage);
  Check(FileSystem::KernelStat("/dev/s3da", &path_stat) == OK &&
            path_stat.st_mode == 0020666u && path_stat.st_nlink == 1,
        "S3DA cdev has captured character-device permissions");
  Check(FileSystem::KernelStat("/dev/s3da", reinterpret_cast<FileSystem::FileStat*>(1)) == KERNEL_ERROR_EFAULT,
        "S3DA stat validates guest output");
  for (const int flags: {3, 0x20000, 0x202, 0x402, 0x802, 0xa, 0x10002}) {
    Check(FileSystem::KernelOpen("/dev/s3da", flags, 0) ==
              (flags == 0x20000 ? KERNEL_ERROR_ENOTDIR : KERNEL_ERROR_EINVAL),
          "S3DA rejects unsupported descriptor flags");
  }
  int descriptors[3] {};
  for (int access = 0; access != 3; ++access) {
    const int fd = FileSystem::KernelOpen("/dev/s3da", access | 0x100000, 0);
    descriptors[access] = fd;
    Check(fd >= 3 && FileSystem::GetDescriptorFlags(fd) == 1,
          "S3DA opens an owned close-on-exec descriptor");
    auto& descriptor_stat = static_cast<FileSystem::FileStat*>(storage)[1];
    Check(FileSystem::KernelFstat(fd, &descriptor_stat) == OK &&
              descriptor_stat.st_mode == path_stat.st_mode && descriptor_stat.st_nlink == 1,
          "S3DA descriptor stat agrees with its node");
    Check(FileSystem::KernelFstat(fd, reinterpret_cast<FileSystem::FileStat*>(1)) == KERNEL_ERROR_EFAULT,
          "S3DA fstat validates guest output");
    std::array<uint64_t, 3> payload {0x12345678, 0x13579bdf, 0x2468ace0};
    const auto unchanged = payload;
    for (const uint32_t command: {0x8004a603u, 0x8004a604u, 0x8018a601u, 0x8010a602u, 0u}) {
      Check(FileSystem::KernelIoctl(fd, command, payload.data()) == KERNEL_ERROR_ENOTTY && payload == unchanged,
            "S3DA unsupported hardware requests preserve guest payloads");
    }
    char byte = 0;
    Check(FileSystem::KernelRead(fd, &byte, 1) == (access == 1 ? KERNEL_ERROR_EBADF : KERNEL_ERROR_ENOSYS) &&
              FileSystem::KernelWrite(fd, &byte, 1) == (access == 0 ? KERNEL_ERROR_EBADF : KERNEL_ERROR_ENOSYS),
          "S3DA descriptor access transfers no data");
    Check(FileSystem::KernelLseek(fd, 0, 0) == KERNEL_ERROR_ESPIPE,
          "S3DA cdev is not seekable");
  }
  Check(descriptors[0] != descriptors[1] && descriptors[1] != descriptors[2] && descriptors[0] != descriptors[2],
        "S3DA opens own distinct descriptors");
  for (const int fd: descriptors) {
    Check(FileSystem::KernelClose(fd) == OK &&
              FileSystem::KernelIoctl(fd, 0x8004a603u, nullptr) == KERNEL_ERROR_EBADF &&
              FileSystem::KernelClose(fd) == KERNEL_ERROR_EBADF,
          "S3DA close retires only its descriptor");
  }
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(storage), 0x4000) == OK,
        "release S3DA guest test output");
  std::printf("NativeS3daTests: cdev lifecycle passed; hardware requests remain unsupported\n");
}
