struct NullfsExecRecord {
  std::string point, source;
  uint32_t device = 0, inode = 0;
};

std::string NullfsExecManifest(const std::vector<NullfsExecRecord>& records) {
  std::ostringstream output;
  output << "KYTY_EXEC_NULLFS 1\n";
  for (const auto& record: records) {
    output << "N " << std::quoted(record.point) << ' ' << std::quoted(record.source) << ' '
           << record.device << ' ' << record.inode << '\n';
  }
  output << "END\n";
  return output.str();
}

std::vector<NullfsExecRecord> ParseNullfsExecManifest(const std::string& manifest) {
  std::istringstream input(manifest);
  std::string header, tag;
  Check(std::getline(input, header) && header == "KYTY_EXEC_NULLFS 1",
        "read versioned nullfs fixture manifest");
  std::vector<NullfsExecRecord> records;
  while (input >> tag && tag != "END") {
    NullfsExecRecord record;
    Check(tag == "N" && static_cast<bool>(input >> std::quoted(record.point) >>
              std::quoted(record.source) >> record.device >> record.inode),
          "read canonical nullfs fixture record");
    records.push_back(std::move(record));
  }
  Check(tag == "END" && (input >> std::ws).eof(), "read complete nullfs fixture manifest");
  return records;
}

int RunNullfsExecChild(int argc, char** argv) {
  if (argc < 2 || std::strcmp(argv[1], "--nullfs-exec-child") != 0) return -1;
  if (argc != 4) return 2;
#if defined(_WIN32)
  using namespace Libs::LibKernel;
  const auto root = Common::PathFromUtf8(argv[2]);
  Tmpfs::Shutdown();
  Check(Tmpfs::Initialize(argv[3]) == OK, "child attaches the parent's existing tmpfs namespace");
  FileSystem::MountReadOnly(root / "underlay", "/");
  std::ifstream input(root / "nullfs.txt", std::ios::binary);
  Check(input.good(), "read the parent's exported nullfs snapshot");
  const std::string manifest {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
  const auto records = ParseNullfsExecManifest(manifest);
  Check(records.size() == 20 && records[0].point == "/devlog/system" && records[1].point == "/alternate" &&
            records[2].point == "/user/box/p00" && records[19].point == "/user/box/p17" &&
            !NullfsMount::Contains(records[0].point) && !NullfsMount::Contains(records[1].point) &&
            !NullfsMount::Contains(records[19].point),
        "exec child begins without process-local aliases");
  Check(FileSystem::MountNullfs("/user/log", "/unrelated") == OK,
        "retain an unrelated child alias while validating incoming batches");
  std::string retained;
  Check(FileSystem::ExportExecNullfsMounts(&retained) == OK,
        "snapshot the unrelated child alias before rejected imports");
  const auto rejected = [&](const std::string& value, int expected) {
    std::string after;
    Check(FileSystem::ImportExecNullfsMounts(value) == expected &&
              !NullfsMount::Contains(records[0].point) && !NullfsMount::Contains(records[1].point) &&
              FileSystem::ExportExecNullfsMounts(&after) == OK && after == retained,
          "rejected nullfs batch preserves existing aliases without publishing a prefix");
  };
  rejected("", KERNEL_ERROR_EINVAL);
  rejected("KYTY_EXEC_NULLFS 2\nEND\n", KERNEL_ERROR_EINVAL);
  rejected("KYTY_EXEC_NULLFS 1\n", KERNEL_ERROR_EINVAL);
  rejected(manifest + "trailing\n", KERNEL_ERROR_EINVAL);
  rejected(manifest + std::string(1, '\0'), KERNEL_ERROR_EINVAL);
  rejected(std::string(65537, 'x'), KERNEL_ERROR_E2BIG);
  auto changed = records;
  changed[1].inode ^= 1u;
  rejected(NullfsExecManifest(changed), KERNEL_ERROR_EINVAL);
  changed = records;
  changed[1].device ^= 1u;
  rejected(NullfsExecManifest(changed), KERNEL_ERROR_EINVAL);
  changed = records;
  changed[1].source = "/user/missing";
  rejected(NullfsExecManifest(changed), KERNEL_ERROR_ENOENT);
  changed = records;
  changed[1].point = changed[0].point;
  rejected(NullfsExecManifest(changed), KERNEL_ERROR_EBUSY);
  changed = records;
  changed[0].point += "/.";
  rejected(NullfsExecManifest(changed), KERNEL_ERROR_EINVAL);
  changed = records;
  changed[0].source += "/../log";
  rejected(NullfsExecManifest(changed), KERNEL_ERROR_EINVAL);
  changed = records;
  changed[0].point = "/missing-target";
  rejected(NullfsExecManifest(changed), KERNEL_ERROR_ENOENT);
  changed = records;
  changed[1].point = "/unrelated";
  rejected(NullfsExecManifest(changed), KERNEL_ERROR_EBUSY);
  rejected("KYTY_EXEC_NULLFS 1\nN /devlog/system \"/user/log\" 1 1\nEND\n", KERNEL_ERROR_EINVAL);
  rejected("KYTY_EXEC_NULLFS 1\nN \"/devlog/system\" \"/user/log\" -1 1\nEND\n", KERNEL_ERROR_EINVAL);
  Check(FileSystem::KernelRename("/user/second", "/user/second-old") == OK &&
            FileSystem::KernelMkdir("/user/second", 0755) == OK,
        "replace a lower directory with a different inode at the same canonical path");
  rejected(manifest, KERNEL_ERROR_EINVAL);
  Check(FileSystem::KernelRmdir("/user/second") == OK &&
            FileSystem::KernelRename("/user/second-old", "/user/second") == OK,
        "restore the exact lower directory before importing its snapshot");
  Check(FileSystem::ImportExecNullfsMounts(manifest) == OK,
        "child atomically imports the parent's initial nullfs snapshot");
  Check(NullfsMount::IsMountPoint("/devlog/system") && NullfsMount::IsMountPoint("/devlog/system/.") &&
            !NullfsMount::IsMountPoint("/devlog/system/message"),
        "inherited mount-root identity distinguishes an alias from its ordinary lower children");
  FileSystem::FileStat direct {}, alias {};
  std::array<char, 16> bytes {};
  const int file = FileSystem::KernelOpen("/devlog/system/message", 2, 0);
  Check(file >= 3 && FileSystem::KernelStat("/user/log/message", &direct) == OK &&
            FileSystem::KernelFstat(file, &alias) == OK && direct.st_dev == alias.st_dev &&
            direct.st_ino == alias.st_ino && FileSystem::KernelPread(file, bytes.data(), 6, 0) == 6 &&
            std::memcmp(bytes.data(), "parent", 6) == 0 &&
            FileSystem::KernelPwrite(file, "child", 5, 6) == 5 && FileSystem::KernelClose(file) == OK,
        "independent child reads parent bytes and writes through the inherited alias to the same inode");
  const int created = FileSystem::KernelOpen("/alternate/from-child", 0x202, 0600);
  Check(created >= 3 && FileSystem::KernelWrite(created, "shared", 6) == 6 &&
            FileSystem::KernelClose(created) == OK,
        "child creates shared lower data through its second imported alias");
  FileSystem::FileStat beside {}, nested {};
  Check(FileSystem::KernelStat("/alternate/from-child", &beside) == OK &&
            FileSystem::KernelStat("/user/box/p17/from-child", &nested) == OK &&
            beside.st_dev == nested.st_dev && beside.st_ino == nested.st_ino && NullfsMount::IsMountPoint("/user/box/p17"),
        "aliases covering directories inside the shared tmpfs import past sixteen entries and reach the same lower file");
  Check(FileSystem::ImportExecNullfsMounts(manifest) == KERNEL_ERROR_EBUSY,
        "duplicate import preserves the existing child namespace");
  FileSystem::Umount("/devlog/system");
  FileSystem::Umount("/alternate");
  FileSystem::Umount("/unrelated");
  for (size_t index = 2; index < records.size(); ++index) FileSystem::Umount(records[index].point);
  FileSystem::Umount("/");
  std::printf("NullfsExecTests: child_import=pass identity_rejection=pass batch_rollback=pass shared_rw=pass\n");
  return 0;
#else
  return 2;
#endif
}

void CheckNullfsExec(const std::filesystem::path& root) {
#if defined(_WIN32)
  using namespace Libs::LibKernel;
  const auto underlay = root / "underlay";
  Check(std::filesystem::create_directories(underlay / "devlog" / "system") &&
            std::filesystem::create_directory(underlay / "alternate") &&
            std::filesystem::create_directory(underlay / "unrelated"),
        "create only disposable directories covered by the nullfs fixture");
  const auto scope = "nullfs_exec_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
  Tmpfs::Shutdown();
  Check(Tmpfs::Initialize(scope) == OK && Tmpfs::Mount("/user", 0755, 262144, 64) == OK &&
            FileSystem::KernelMkdir("/user/log", 0755) == OK &&
            FileSystem::KernelMkdir("/user/second", 0755) == OK && FileSystem::KernelMkdir("/user/box", 0755) == OK,
        "create a shared tmpfs lower namespace before exec snapshot");
  FileSystem::MountReadOnly(underlay, "/");
  std::string empty = "unchanged";
  Check(FileSystem::ExportExecNullfsMounts(nullptr) == KERNEL_ERROR_EFAULT &&
            FileSystem::ExportExecNullfsMounts(&empty) == OK && empty == NullfsExecManifest({}) &&
            FileSystem::ImportExecNullfsMounts(empty) == OK,
        "empty alias tables preserve existing no-nullfs exec compatibility");
  const int file = FileSystem::KernelOpen("/user/log/message", 0x202, 0600);
  Check(file >= 3 && FileSystem::KernelWrite(file, "parent", 6) == 6 &&
            FileSystem::KernelClose(file) == OK &&
            FileSystem::MountNullfs("/user/log", "/devlog/system") == OK &&
            FileSystem::MountNullfs("/user/second", "/alternate") == OK,
        "parent publishes two aliases over shared lower directories");
  std::vector<std::string> boxed;
  for (int index = 0; index < 18; ++index) {
    char point[32];
    std::snprintf(point, sizeof(point), "/user/box/p%02d", index);
    Check(FileSystem::KernelMkdir(point, 0755) == OK && FileSystem::MountNullfs("/user/second", point) == OK,
          "a sandbox-style alias covers a directory inside the tmpfs instead of colliding with its mount");
    boxed.push_back(point);
  }
  Check(FileSystem::MountNullfs("/user/log", "/user") == KERNEL_ERROR_EBUSY &&
            FileSystem::MountNullfs("/user/log", "/user/box") == KERNEL_ERROR_EBUSY &&
            FileSystem::MountNullfs("/user/log", "/user/box/p00") == KERNEL_ERROR_EBUSY,
        "nullfs still refuses a tmpfs mount root, hiding existing aliases and stacking on an alias root");
  FileSystem::Umount("/user");
  Check(Tmpfs::Contains("/user") && NullfsMount::IsMountPoint("/user/box/p00"),
        "a tmpfs with aliases still covering its directories stays mounted");
  std::string manifest;
  Check(FileSystem::ExportExecNullfsMounts(&manifest) == OK,
        "export canonical nullfs paths and their lower device and inode identities");
  { std::ofstream output(root / "nullfs.txt", std::ios::binary); output << manifest;
    Check(output.good(), "write the exact parent nullfs snapshot for its child"); }
  std::array<wchar_t, 32768> executable {};
  const DWORD length = GetModuleFileNameW(nullptr, executable.data(), executable.size());
  Check(length != 0 && length < executable.size(), "locate independent nullfs child executable");
  std::wstring command = L"\"" + std::wstring(executable.data(), length) + L"\" --nullfs-exec-child \"" +
      root.wstring() + L"\" " + std::wstring(scope.begin(), scope.end());
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  Check(job != nullptr && SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)),
        "contain the independent nullfs child in an owned job");
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process {};
  Check(CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED,
                       nullptr, nullptr, &startup, &process) &&
            AssignProcessToJobObject(job, process.hProcess) && ResumeThread(process.hThread) != DWORD(-1),
        "launch the isolated child before replaying its alias table");
  const DWORD wait = WaitForSingleObject(process.hProcess, 30000);
  if (wait != WAIT_OBJECT_0) {
    TerminateJobObject(job, 10);
    WaitForSingleObject(process.hProcess, 1000);
  }
  DWORD code = 1;
  const bool exited = GetExitCodeProcess(process.hProcess, &code) != FALSE;
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  CloseHandle(job);
  Check(wait == WAIT_OBJECT_0 && exited && code == 0,
        "child completes shared alias reads, writes and whole-batch rejection checks");
  std::array<char, 16> bytes {};
  const int changed = FileSystem::KernelOpen("/user/log/message", 0, 0);
  const int created = FileSystem::KernelOpen("/alternate/from-child", 0, 0);
  std::string after;
  Check(changed >= 3 && FileSystem::KernelPread(changed, bytes.data(), 11, 0) == 11 &&
            std::memcmp(bytes.data(), "parentchild", 11) == 0 && FileSystem::KernelClose(changed) == OK &&
            created >= 3 && FileSystem::KernelPread(created, bytes.data(), 6, 0) == 6 &&
            std::memcmp(bytes.data(), "shared", 6) == 0 && FileSystem::KernelClose(created) == OK &&
            FileSystem::ExportExecNullfsMounts(&after) == OK && after == manifest,
        "parent sees child lower writes while child-local unmounts leave the initial parent aliases intact");
  FileSystem::Umount("/devlog/system");
  FileSystem::Umount("/alternate");
  for (const auto& point: boxed) FileSystem::Umount(point);
  Check(Tmpfs::Unmount("/user") == OK, "release only the nullfs fixture's lower filesystem");
  FileSystem::Umount("/");
  std::printf("NullfsExecTests: cross_process_rw=pass source_identity=pass rollback=pass parent_isolation=pass\n");
#else
  (void)root;
#endif
}

// ShellCore's sandbox helper mounts system_tmp with MNT_NOEXEC and its callers add MNT_RDONLY for read-only aliases.
void CheckNullfsMountFlags(const std::filesystem::path& root) {
#if defined(_WIN32)
  using namespace Libs::LibKernel;
  using FileSystem::KernelOpen;
  const auto underlay = root / "underlay";
  for (const char* name: {"ro", "nx", "plain", "stacked", "unflagged"})
    Check(std::filesystem::create_directories(underlay / name), "create disposable alias targets");
  const auto scope = "nullfs_flags_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
  Tmpfs::Shutdown();
  Check(Tmpfs::Initialize(scope) == OK && Tmpfs::Mount("/user", 0755, 262144, 64) == OK &&
            FileSystem::KernelMkdir("/user/lower", 0755) == OK && FileSystem::KernelMkdir("/user/lower/dir", 0755) == OK,
        "create the shared lower directory");
  FileSystem::MountReadOnly(underlay, "/");
  const int seeded = KernelOpen("/user/lower/eboot.bin", 0x202, 0700);
  Check(seeded >= 3 && FileSystem::KernelWrite(seeded, "image", 5) == 5 && FileSystem::KernelClose(seeded) == OK,
        "seed a lower image");
  Check(FileSystem::MountNullfs("/user/lower", "/plain", 0x2) == KERNEL_ERROR_EOPNOTSUPP && !NullfsMount::Contains("/plain"),
        "an unmodelled mount flag is refused without publishing an alias");
  Check(FileSystem::MountNullfs("/user/lower", "/ro", NullfsMount::FlagReadOnly) == OK &&
            FileSystem::MountNullfs("/user/lower", "/nx", NullfsMount::FlagNoExec) == OK,
        "publish read-only and noexec aliases of one lower directory");

  const int readable = KernelOpen("/ro/eboot.bin", 0, 0);
  Check(readable >= 3 && FileSystem::KernelClose(readable) == OK, "a read-only alias still opens for reading");
  const int created_existing = KernelOpen("/ro/eboot.bin", 0x200, 0600);
  Check(created_existing >= 3 && FileSystem::KernelClose(created_existing) == OK,
        "O_CREAT without write access opens an existing file through a read-only alias");
  Check(KernelOpen("/ro/eboot.bin", 2, 0) == KERNEL_ERROR_EROFS && KernelOpen("/ro/eboot.bin", 0x400, 0) == KERNEL_ERROR_EROFS &&
            KernelOpen("/ro/new", 0x201, 0600) == KERNEL_ERROR_EROFS && KernelOpen("/ro/eboot.bin", 0xa01, 0600) == KERNEL_ERROR_EEXIST &&
            KernelOpen("/ro/dir", 1, 0) == KERNEL_ERROR_EISDIR &&
            KernelOpen("/ro/missing/new", 0x201, 0600) == KERNEL_ERROR_ENOENT && KernelOpen("/ro/missing", 0, 0) == KERNEL_ERROR_ENOENT,
        "open through a read-only alias follows vn_open_cred ordering");
  Check(FileSystem::KernelMkdir("/ro/dir", 0755) == KERNEL_ERROR_EEXIST && FileSystem::KernelMkdir("/ro/fresh", 0755) == KERNEL_ERROR_EROFS &&
            FileSystem::KernelMkdir("/ro/missing/fresh", 0755) == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelUnlink("/ro/eboot.bin") == KERNEL_ERROR_EROFS && FileSystem::KernelUnlink("/ro/missing") == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelRmdir("/ro/dir") == KERNEL_ERROR_EROFS,
        "namespace changes through a read-only alias fail in lookup");
  Check(FileSystem::KernelRename("/ro/eboot.bin", "/ro/renamed") == KERNEL_ERROR_EROFS &&
            FileSystem::KernelRename("/user/lower/eboot.bin", "/ro/renamed") == KERNEL_ERROR_EROFS &&
            FileSystem::KernelRename("/user/lower/missing", "/ro/renamed") == KERNEL_ERROR_ENOENT,
        "rename out of or into a read-only alias fails before the cross-mount check");
  FileSystem::FileStat stat {};
  Check(FileSystem::KernelStat("/user/lower/eboot.bin", &stat) == OK && FileSystem::KernelStat("/user/lower/fresh", &stat) == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelStat("/user/lower/new", &stat) == KERNEL_ERROR_ENOENT && FileSystem::KernelStat("/user/lower/dir", &stat) == OK,
        "refused writes leave the lower directory untouched");

  const int writable = KernelOpen("/nx/eboot.bin", 2, 0);
  Check(writable >= 3 && FileSystem::KernelPwrite(writable, "IMAGE", 5, 0) == 5 && FileSystem::KernelClose(writable) == OK &&
            FileSystem::KernelMkdir("/nx/made", 0755) == OK && FileSystem::KernelRmdir("/nx/made") == OK,
        "a noexec alias stays writable");
  Check(FileSystem::IsNullfsNoExec("/nx/eboot.bin") && FileSystem::IsNullfsNoExec("/nx") &&
            !FileSystem::IsNullfsNoExec("/ro/eboot.bin") && !FileSystem::IsNullfsNoExec("/user/lower/eboot.bin"),
        "noexec belongs to the alias the path entered");

  Check(FileSystem::MountNullfs("/ro", "/stacked", NullfsMount::FlagNoExec) == OK &&
            FileSystem::MountNullfs("/nx", "/unflagged") == OK,
        "stack aliases over the flagged ones");
  Check(FileSystem::KernelMkdir("/stacked/fresh", 0755) == KERNEL_ERROR_EROFS && FileSystem::IsNullfsNoExec("/stacked/eboot.bin") &&
            FileSystem::KernelMkdir("/unflagged/fresh", 0755) == OK && FileSystem::KernelRmdir("/unflagged/fresh") == OK &&
            !FileSystem::IsNullfsNoExec("/unflagged/eboot.bin"),
        "a read-only layer below stays in effect while noexec does not carry upward");

  FileSystem::FileStat lower {};
  std::string manifest;
  Check(FileSystem::KernelStat("/user/lower", &lower) == OK && FileSystem::ExportExecNullfsMounts(&manifest) == OK,
        "export the flagged alias table");
  const auto identity = " " + std::to_string(lower.st_dev) + " " + std::to_string(lower.st_ino);
  Check(manifest == "KYTY_EXEC_NULLFS 1\nF \"/ro\" \"/user/lower\"" + identity + " 1\nF \"/nx\" \"/user/lower\"" + identity +
                        " 4\nF \"/stacked\" \"/user/lower\"" + identity + " 5\nN \"/unflagged\" \"/user/lower\"" + identity + "\nEND\n",
        "flagged aliases export as F records with their effective flags while unflagged ones stay N");
  for (const char* point: {"/ro", "/nx", "/stacked", "/unflagged"}) FileSystem::Umount(point);
  const auto replaced = [&](const std::string& from, const std::string& to) {
    auto value = manifest;
    value.replace(value.find(from), from.size(), to);
    return value;
  };
  const std::string ro_tail = " 1\nF \"/nx\"";
  for (const auto& bad: {replaced(ro_tail, " 0\nF \"/nx\""), replaced(ro_tail, " 2\nF \"/nx\""), replaced(ro_tail, "\nF \"/nx\""),
                         replaced(ro_tail, " 01\nF \"/nx\""),
                         replaced("N \"/unflagged\" \"/user/lower\"" + identity, "N \"/unflagged\" \"/user/lower\"" + identity + " 4")}) {
    Check(FileSystem::ImportExecNullfsMounts(bad) == KERNEL_ERROR_EINVAL && !NullfsMount::Contains("/ro") && !NullfsMount::Contains("/nx"),
          "a malformed flag record rejects the whole batch");
  }
  std::string after;
  Check(FileSystem::ImportExecNullfsMounts(manifest) == OK && FileSystem::ExportExecNullfsMounts(&after) == OK && after == manifest &&
            FileSystem::KernelMkdir("/ro/fresh", 0755) == KERNEL_ERROR_EROFS && FileSystem::KernelMkdir("/stacked/fresh", 0755) == KERNEL_ERROR_EROFS &&
            FileSystem::IsNullfsNoExec("/nx/eboot.bin") && !FileSystem::IsNullfsNoExec("/unflagged/eboot.bin"),
        "an exec child re-imports the same flags and enforces them");
  for (const char* point: {"/ro", "/nx", "/stacked", "/unflagged"}) FileSystem::Umount(point);
  Check(Tmpfs::Unmount("/user") == OK, "release the flags fixture's lower filesystem");
  FileSystem::Umount("/");
  std::printf("NullfsExecTests: mount_flags=pass rdonly_lookup=pass noexec_top_layer=pass flag_manifest=pass\n");
#else
  (void)root;
#endif
}
