#if defined(_WIN32)
// AutoMounter's USB poll: open("/dev"), fstat for st_blksize, then getdents looking for da* nodes.
void CheckDevfsRoot(const std::filesystem::path& temporary) {
  using namespace Libs::LibKernel;
  const auto listing = temporary / "devfs_root.tsv";
  {
    std::ofstream out(listing, std::ios::binary);
    out << "# fixture\n5\t2\tdevctl\n200\t4\tfd\n7\t10\turandom\n201\t4\tdmem\n";
  }
  _putenv_s("KYTY_PS5_DEVFS_LISTING", Common::PathToString(listing).c_str());

  Check(FileSystem::KernelOpen("/dev", 3, 0) == KERNEL_ERROR_EINVAL, "O_ACCMODE on /dev");
  Check(FileSystem::KernelOpen("/dev", 0xa00, 0) == KERNEL_ERROR_EEXIST, "O_CREAT|O_EXCL on /dev");
  Check(FileSystem::KernelOpen("/dev", 2, 0) == KERNEL_ERROR_EISDIR && FileSystem::KernelOpen("/dev", 0x200, 0) == KERNEL_ERROR_EISDIR &&
        FileSystem::KernelOpen("/dev", 0x400, 0) == KERNEL_ERROR_EISDIR, "writing, creating or truncating /dev is EISDIR");

  FileSystem::FileStat stat {};
  Check(FileSystem::KernelStat("/dev/", &stat) == OK && stat.st_mode == 040555 && stat.st_ino == 2 && stat.st_nlink == 4 &&
        stat.st_size == 512 && stat.st_blksize == 0x4000, "stat /dev is the devfs root");
  const int fd = FileSystem::KernelOpen("/dev", 0, 0);
  Check(fd >= 3, "/dev opens read-only");
  stat = {};
  Check(FileSystem::KernelFstat(fd, &stat) == OK && stat.st_mode == 040555 && stat.st_blksize == 0x4000, "fstat /dev");

  std::vector<char> block(stat.st_blksize);
  const int length = FileSystem::KernelGetdents(fd, block.data(), static_cast<int>(block.size()));
  struct Seen { uint32_t inode; uint8_t type; std::string name; };
  std::vector<Seen> seen;
  for (int pos = 0; pos < length;) {
    uint32_t inode = 0;
    uint16_t reclen = 0;
    std::memcpy(&inode, block.data() + pos, 4);
    std::memcpy(&reclen, block.data() + pos + 4, 2);
    seen.push_back({inode, static_cast<uint8_t>(block[pos + 6]), std::string(block.data() + pos + 8, static_cast<uint8_t>(block[pos + 7]))});
    pos += reclen;
  }
  const std::vector<std::string> names {".", "..", "devctl", "fd", "urandom", "dmem"};
  Check(seen.size() == names.size(), "devfs root lists dot, dotdot and the captured nodes");
  for (size_t i = 0; i < seen.size() && i < names.size(); ++i) Check(seen[i].name == names[i], "devfs listing keeps getdents order");
  Check(seen.size() == 6 && seen[0].inode == 2 && seen[1].inode == 2 && seen[0].type == 4 && seen[2].inode == 5 && seen[2].type == 2 &&
        seen[3].inode == 200 && seen[3].type == 4 && seen[4].type == 10, "devfs inodes and d_type come from the listing");
  Check(FileSystem::KernelGetdents(fd, block.data(), static_cast<int>(block.size())) == 0, "second getdents is EOF");
  Check(FileSystem::KernelClose(fd) == OK, "close /dev");

  // SceLncService's sandbox /dev. Root inodes 5,200,7,201 and held 3,4 leave 6 and 8 as the lowest free for fd and dmem.
  const auto subdirs = temporary / "devfs_subdirs.tsv";
  {
    std::ofstream out(subdirs, std::ios::binary);
    out << "# fixture\n3\t2\tfd/0\n4\t0\t\n";
  }
  _putenv_s("KYTY_PS5_DEVFS_SUBDIR_LISTING", Common::PathToString(subdirs).c_str());
  std::filesystem::create_directories(temporary / "host" / "sandbox");
  FileSystem::Mount(temporary / "host", "/devfs-host");
  Check(FileSystem::MountTmpfs("/devfs-host/sandbox", 0755, 65536, 32) == OK && FileSystem::KernelMkdir("/devfs-host/sandbox/dev", 0700) == OK &&
        FileSystem::KernelMkdir("/devfs-host/sandbox/dev2", 0700) == OK && FileSystem::KernelMkdir("/devfs-host/sandbox/file-parent", 0755) == OK,
        "sandbox tmpfs with mountpoints");
  Check(FileSystem::MountDevfs("/devfs-host/sandbox/missing") == KERNEL_ERROR_ENOENT, "devfs mount on a missing directory");
  Check(FileSystem::MountDevfs("/dev") == KERNEL_ERROR_EBUSY, "devfs cannot cover /dev");
  Check(FileSystem::MountDevfs("/devfs-host/sandbox/dev") == OK, "devfs mounts on the sandbox directory");
  Check(FileSystem::MountDevfs("/devfs-host/sandbox/dev") == KERNEL_ERROR_EBUSY && FileSystem::MountDevfs("/devfs-host/sandbox/dev/fd") == KERNEL_ERROR_EBUSY,
        "devfs mountpoint and its descendants are busy");
  stat = {};
  Check(FileSystem::KernelStat("/devfs-host/sandbox/dev", &stat) == OK && stat.st_mode == 040555 && stat.st_ino == 2, "sandbox devfs root stat");
  FileSystem::FileStat host_node {};
  FileSystem::FileStat sandbox_node {};
  const int host_result = FileSystem::KernelStat("/dev/devctl", &host_node);
  Check(FileSystem::KernelStat("/devfs-host/sandbox/dev/devctl", &sandbox_node) == host_result && sandbox_node.st_ino == host_node.st_ino &&
        sandbox_node.st_mode == host_node.st_mode, "sandbox devfs names resolve to the shared cdevs");
  Check(FileSystem::KernelCheckReachability("/devfs-host/sandbox/dev") == OK, "sandbox devfs root is reachable");

  const auto list = [&](const char* path) {
    std::vector<Seen> entries;
    const int handle = FileSystem::KernelOpen(path, 0, 0);
    if (handle < 3) return entries;
    std::vector<char> bytes(0x4000);
    const int size = FileSystem::KernelGetdents(handle, bytes.data(), static_cast<int>(bytes.size()));
    for (int pos = 0; pos < size;) {
      uint32_t inode = 0;
      uint16_t reclen = 0;
      std::memcpy(&inode, bytes.data() + pos, 4);
      std::memcpy(&reclen, bytes.data() + pos + 4, 2);
      entries.push_back({inode, static_cast<uint8_t>(bytes[pos + 6]), std::string(bytes.data() + pos + 8, static_cast<uint8_t>(bytes[pos + 7]))});
      pos += reclen;
    }
    FileSystem::KernelClose(handle);
    return entries;
  };
  auto first = list("/devfs-host/sandbox/dev");
  Check(first.size() == 6 && first[2].inode == 5 && first[3].name == "fd" && first[3].inode == 6 && first[4].inode == 7 &&
        first[5].name == "dmem" && first[5].inode == 8, "sandbox devfs gets fresh directory inodes and shares cdev inodes");
  Check(FileSystem::MountDevfs("/devfs-host/sandbox/dev2") == OK, "second sandbox devfs");
  auto second = list("/devfs-host/sandbox/dev2");
  Check(second.size() == 6 && second[3].inode == 9 && second[5].inode == 10, "live instances keep their directory inodes");
  Check(FileSystem::KernelRmdir("/devfs-host/sandbox/dev") == KERNEL_ERROR_EBUSY, "rmdir of a devfs mountpoint");

  const std::string long_path = "/devfs-host/sandbox/" + std::string(80, 'x');
  Check(FileSystem::KernelUnmount(long_path.c_str(), 0) == KERNEL_ERROR_ENAMETOOLONG, "unmount path longer than MNAMELEN");
  Check(FileSystem::KernelUnmount("/devfs-host/sandbox/dev", 0x08000000) == KERNEL_ERROR_ENOSYS, "unmount MNT_BYFSID is not modelled");
  Check(FileSystem::KernelUnmount("/devfs-host/sandbox/file-parent", 0) == KERNEL_ERROR_EINVAL && FileSystem::KernelUnmount("/", 0) == KERNEL_ERROR_EINVAL &&
        FileSystem::KernelUnmount("/devfs-host/sandbox/nothing", 0) == KERNEL_ERROR_EINVAL, "unmount of a non-mountpoint");
  Check(FileSystem::KernelUnmount("/devfs-host/sandbox", 0) == KERNEL_ERROR_EBUSY, "tmpfs with devfs mounts beneath is busy");
  Check(FileSystem::KernelUnmount("/devfs-host/sandbox/dev", 0) == OK && FileSystem::KernelUnmount("/devfs-host/sandbox/dev", 0) == KERNEL_ERROR_EINVAL,
        "devfs unmounts once");
  stat = {};
  Check(FileSystem::KernelStat("/devfs-host/sandbox/dev", &stat) == OK && stat.st_mode == 040700 && FileSystem::KernelStat("/devfs-host/sandbox/dev/devctl", &stat) == KERNEL_ERROR_ENOENT,
        "unmount uncovers the tmpfs directory");
  Check(FileSystem::MountDevfs("/devfs-host/sandbox/dev") == OK, "remount sandbox devfs");
  auto third = list("/devfs-host/sandbox/dev");
  Check(third.size() == 6 && third[3].inode == 6 && third[5].inode == 8, "released directory inodes are reused");
  Check(FileSystem::KernelUnmount("/devfs-host/sandbox/dev/", 0) == OK && FileSystem::KernelUnmount("/devfs-host/sandbox/dev2", 0) == OK, "unmount both instances");
  Check(FileSystem::KernelRmdir("/devfs-host/sandbox/dev") == OK && FileSystem::KernelUnmount("/devfs-host/sandbox", 0) == OK, "sandbox tmpfs unmounts once empty of mounts");
  Check(FileSystem::KernelUnmount("/devfs-host/sandbox", 0) == KERNEL_ERROR_EINVAL, "tmpfs unmounts once");
  Check(FileSystem::KernelUnmount("/devfs-host", 0) == KERNEL_ERROR_ENOSYS, "unmount of a host-backed mount is not modelled");
  FileSystem::Umount("/devfs-host");
  _putenv_s("KYTY_PS5_DEVFS_SUBDIR_LISTING", "");
  _putenv_s("KYTY_PS5_DEVFS_LISTING", "");
}

void CheckPosixSleep() {
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* symbol = symbols.FindByNid("0wu33hunNdE", Loader::SymbolType::Func);
  Check(symbol != nullptr, "libkernel sleep resolves");
  using Sleep = unsigned int (KYTY_SYSV_ABI *)(unsigned int);
  const auto sleep = reinterpret_cast<Sleep>(symbol->vaddr);
  Check(sleep(0) == 0, "sleep(0) returns 0");
  const auto start = std::chrono::steady_clock::now();
  Check(sleep(1) == 0 && std::chrono::steady_clock::now() - start >= std::chrono::milliseconds(900), "sleep(1) sleeps and returns 0");
}

// libc remove() is rmdir() then unlink(); both must be -1/errno or ShellCore's RemoveRecursive reads a stale errno.
void CheckPosixRemove(const std::filesystem::path& temporary) {
  using namespace Libs::LibKernel;
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* rmdir_symbol = symbols.FindByNid("c7ZnT7V1B98", Loader::SymbolType::Func);
  const auto* unlink_symbol = symbols.FindByNid("VAzswvTOCzI", Loader::SymbolType::Func);
  Check(rmdir_symbol != nullptr && unlink_symbol != nullptr, "libkernel rmdir and unlink resolve");
  using PathCall = int (KYTY_SYSV_ABI *)(const char*);
  const auto rmdir = reinterpret_cast<PathCall>(rmdir_symbol->vaddr);
  const auto unlink = reinterpret_cast<PathCall>(unlink_symbol->vaddr);

  std::filesystem::create_directories(temporary / "remove" / "sandbox");
  FileSystem::Mount(temporary / "remove", "/remove-host");
  Check(FileSystem::MountTmpfs("/remove-host/sandbox", 0755, 65536, 32) == OK && FileSystem::KernelMkdir("/remove-host/sandbox/app0", 0755) == OK &&
        FileSystem::KernelMkdir("/remove-host/sandbox/app0/sce_sys", 0755) == OK, "tmpfs tree for remove");
  const auto error = [] { return *Libs::Posix::GetErrorAddr(); };
  *Libs::Posix::GetErrorAddr() = 0;
  Check(rmdir("/remove-host/sandbox/app0") == -1 && error() == Libs::Posix::POSIX_ENOTEMPTY, "rmdir of a non-empty directory");
  *Libs::Posix::GetErrorAddr() = 0;
  Check(unlink("/remove-host/sandbox/app0/sce_sys") == -1 && error() == Libs::Posix::POSIX_EPERM, "unlink of a directory is EPERM");
  *Libs::Posix::GetErrorAddr() = 0;
  Check(unlink("/remove-host/sandbox/missing") == -1 && error() == Libs::Posix::POSIX_ENOENT, "unlink of a missing name");
  Check(rmdir("/remove-host/sandbox/app0/sce_sys") == 0 && rmdir("/remove-host/sandbox/app0") == 0, "rmdir of empty directories returns 0");
  *Libs::Posix::GetErrorAddr() = 0;
  Check(rmdir("/remove-host/sandbox/app0") == -1 && error() == Libs::Posix::POSIX_ENOENT, "rmdir of a removed directory");
  Check(FileSystem::KernelUnmount("/remove-host/sandbox", 0) == OK, "remove tmpfs unmounts");
  FileSystem::Umount("/remove-host");
}
#endif
