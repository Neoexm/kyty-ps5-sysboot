void CheckDirectoryPassthroughJunctionRoots(const std::filesystem::path& root) {
#if defined(_WIN32)
  namespace Mount = Libs::LibKernel::DirectoryPassthrough;
  namespace Kernel = Libs::LibKernel;
  const auto composite = root / "passthrough-junction-composite";
  const auto target = root / "passthrough-junction-target";
  const auto sibling = root / "passthrough-junction-target-sibling";
  Check(std::filesystem::create_directory(composite) &&
            std::filesystem::create_directory(target) &&
            std::filesystem::create_directory(sibling),
        "create isolated composite, target and sibling roots");
  std::array<uint8_t, 8112> payload {};
  for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<uint8_t>(i * 37u + 11u);
  { std::ofstream output(target / "app_info.dat", std::ios::binary);
    output.write(reinterpret_cast<const char*>(payload.data()), payload.size());
    Check(output.good(), "write exact junction-target fixture bytes"); }
  { std::ofstream output(sibling / "secret.bin", std::ios::binary);
    output.write("SIBLING", 7);
    Check(output.good(), "write distinct sibling fixture bytes"); }
  { std::ofstream output(sibling / "app_info.dat", std::ios::binary);
    output.write("REPLACED", 8);
    Check(output.good(), "write replacement-root fixture bytes"); }
  const auto junction = composite / "mbus";
  const auto escape = target / "escape";
  const auto contained = target / "contained";
  const auto contained_alias = target / "contained-alias";
  Check(std::filesystem::create_directory(contained),
        "create contained junction target");
  { std::ofstream output(contained / "identity.bin", std::ios::binary);
    output.write("IDENTITY", 8);
    Check(output.good(), "write contained identity fixture"); }
  CreateInitialDirectoryJunction(junction, target);
  CreateInitialDirectoryJunction(escape, sibling);
  CreateInitialDirectoryJunction(contained_alias, contained);
  std::error_code error;
  const auto selected = std::filesystem::canonical(junction, error);
  Check(!error && selected == std::filesystem::canonical(target),
        "explicitly selected root is the existing junction target");

  std::shared_ptr<Mount::Handle> file, failed;
  Check(Mount::Mount("/pt-composite", composite) == OK &&
            Mount::Open("/pt-composite/mbus/app_info.dat", 0, &failed) == Kernel::KERNEL_ERROR_ENOENT &&
            Mount::Open("/pt-composite/mbus", 0x20000, &failed) == Kernel::KERNEL_ERROR_ENOENT &&
            Mount::Unmount("/pt-composite") == OK,
        "composite root rejects a junction escaping its declared backing root");
  Check(Mount::Mount("/pt-explicit", selected) == OK &&
            Mount::Open("/pt-explicit/app_info.dat", 0, &file) == OK,
        "explicit target-root registration exposes its existing file");
  std::filesystem::path resolved_alias;
  Check(Mount::ResolveHostPath("/pt-explicit/contained-alias/identity.bin",
                               &resolved_alias) == OK &&
            resolved_alias == std::filesystem::canonical(contained / "identity.bin"),
        "provider resolution returns the canonical contained identity");
  Mount::FileSnapshot alias_snapshot;
  Check(Mount::OpenFileSnapshot("/pt-explicit/contained-alias/identity.bin",
                                &alias_snapshot) == OK &&
            alias_snapshot.handle != nullptr &&
            alias_snapshot.host_path == resolved_alias &&
            alias_snapshot.bytes.size() == 8 &&
            std::memcmp(alias_snapshot.bytes.data(), "IDENTITY", 8) == 0,
        "provider snapshot pins the canonical contained file and exact bytes");
  alias_snapshot.handle.reset();
  std::array<uint8_t, 8112> actual {};
  Mount::NodeStat stat {};
  Check(Mount::Fstat(file, &stat) == OK && stat.size == payload.size() &&
            Mount::Pread(file, actual.data(), actual.size(), 0) == actual.size() && actual == payload,
        "explicit read-only root returns the exact binary payload");
  Check(Mount::Open("/pt-explicit/escape/secret.bin", 0, &failed) == Kernel::KERNEL_ERROR_ENOENT &&
            Mount::Open("/pt-explicit/escape", 0x20000, &failed) == Kernel::KERNEL_ERROR_ENOENT,
        "explicit root still rejects a junction into its similarly named sibling");
  Check(Mount::Open("/pt-explicit/app_info.dat", 2, &failed) == Kernel::KERNEL_ERROR_EROFS &&
            Mount::Open("/pt-explicit/app_info.dat", 0x401, &failed) == Kernel::KERNEL_ERROR_EROFS &&
            Mount::Open("/pt-explicit/new.dat", 0x202, &failed) == Kernel::KERNEL_ERROR_EROFS,
        "explicit target registration preserves write, truncate and create rejection");
  Check(Mount::Close(file) == OK && Mount::Unmount("/pt-explicit") == OK,
        "release the explicitly selected fixture root");
  Check(Mount::Mount("/pt-fixed-root", junction) == OK,
        "mount a provider through its selected junction generation");
  Check(RemoveDirectoryW(junction.c_str()) != FALSE,
        "remove the mounted junction namespace");
  CreateInitialDirectoryJunction(junction, sibling);
  Mount::FileSnapshot fixed_root_snapshot;
  Check(Mount::OpenFileSnapshot("/pt-fixed-root/app_info.dat", &fixed_root_snapshot) == OK &&
            fixed_root_snapshot.host_path == std::filesystem::canonical(target / "app_info.dat") &&
            fixed_root_snapshot.bytes.size() == payload.size() &&
            std::equal(payload.begin(), payload.end(), fixed_root_snapshot.bytes.begin()),
        "mounted provider generation stays on its canonical root after junction replacement");
  Check(Mount::Unmount("/pt-fixed-root") == OK,
        "unmount the fixed provider generation while its snapshot remains pinned");
  fixed_root_snapshot.handle.reset();
  { std::ifstream original(target / "app_info.dat", std::ios::binary);
    original.read(reinterpret_cast<char*>(actual.data()), actual.size());
    Check(original.gcount() == actual.size() && original.peek() == std::char_traits<char>::eof() &&
              actual == payload && !std::filesystem::exists(target / "new.dat") &&
              std::filesystem::file_size(sibling / "secret.bin") == 7,
          "rejected guest writes preserve the target and sibling files"); }
  Check(RemoveDirectoryW(contained_alias.c_str()) != FALSE &&
            RemoveDirectoryW(escape.c_str()) != FALSE &&
            RemoveDirectoryW(junction.c_str()) != FALSE,
        "remove only disposable junction entries before recursive fixture cleanup");
  std::printf("KernelFileSystemTests: directory passthrough junction-root cases passed\n");
#endif
}

struct ReadOnlyProviderRecord {
  std::string provider, point, root, identity, guest_fstype, guest_source;
  uint32_t device = 0;
  uint64_t guest_flags = 0;
};

std::string ReadOnlyProviderManifest(const std::vector<ReadOnlyProviderRecord>& records,
                                   unsigned version = 3) {
  std::ostringstream output;
  output << "KYTY_EXEC_RO_PROVIDERS " << version << '\n';
  for (const auto& record: records) {
    output << "P " << std::quoted(record.provider) << ' ' << std::quoted(record.point) << ' '
           << std::quoted(record.root) << ' ' << std::quoted(record.identity) << ' '
           << record.device << " G " << std::quoted(record.guest_fstype) << ' '
           << std::quoted(record.guest_source) << ' ' << record.guest_flags << '\n';
  }
  output << "END\n";
  return output.str();
}

ReadOnlyProviderRecord ParseReadOnlyProviderRecord(const std::string& manifest) {
  std::istringstream input(manifest);
  std::string header, tag, guest_tag, end;
  unsigned version = 0;
  ReadOnlyProviderRecord record;
  Check(static_cast<bool>(input >> header >> version >> tag >> std::quoted(record.provider) >>
            std::quoted(record.point) >> std::quoted(record.root) >> std::quoted(record.identity) >>
            record.device >> guest_tag >> std::quoted(record.guest_fstype) >>
            std::quoted(record.guest_source) >> record.guest_flags >> end) &&
            header == "KYTY_EXEC_RO_PROVIDERS" && version == 3 && tag == "P" &&
            guest_tag == "G" && end == "END" && (input >> std::ws).eof(),
        "export contains exactly one versioned read-only provider record");
  return record;
}

std::array<uint8_t, 8112> ReadOnlyProviderBytes() {
  std::array<uint8_t, 8112> bytes {};
  for (size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<uint8_t>(i * 37u + 11u);
  return bytes;
}

std::string ReadOnlyProviderFixtureFile(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  Check(input.good(), "open provider child fixture file");
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void CheckReadOnlyProviderContents(const FileSystem::FileStat& expected) {
  namespace Kernel = Libs::LibKernel;
  const auto bytes = ReadOnlyProviderBytes();
  std::array<uint8_t, 8112> actual {};
  const int file = FileSystem::KernelOpen("/system_ex_b/mbus/app_info.dat", 0, 0);
  FileSystem::FileStat stat {}, by_path {};
  Check(file >= 3 && FileSystem::KernelFstat(file, &stat) == OK &&
            FileSystem::KernelPread(file, actual.data(), actual.size(), 0) == actual.size() &&
            actual == bytes && stat.st_size == bytes.size() &&
            stat.st_dev == expected.st_dev && stat.st_ino == expected.st_ino &&
            FileSystem::KernelStat("/SYSTEM_EX_B/MBUS/APP_INFO.DAT", &by_path) == OK &&
            by_path.st_dev == stat.st_dev && by_path.st_ino == stat.st_ino,
        "replayed provider exposes all original fixture bytes with stable device and inode");
  void* statfs_memory = nullptr;
  Check(Kernel::Memory::KernelMapNamedFlexibleMemory(
            &statfs_memory, 0x4000, 3, 0, "provider_exec_fstatfs_fixture") == OK,
        "map provider exec fstatfs output fixture");
  auto* statfs = static_cast<FileSystem::KernelStatfs*>(statfs_memory);
  std::memset(statfs, 0xa5, sizeof(*statfs));
  Check(FileSystem::KernelFstatfs(file, statfs) == OK &&
            statfs->f_version == 0x20030518 && statfs->f_flags == 1 &&
            std::strcmp(statfs->f_fstypename, "exfatfs") == 0 &&
            std::strcmp(statfs->f_mntfromname, "/dev/ssd0.system_ex_b") == 0 &&
            std::strcmp(statfs->f_mntonname, "/system_ex_b") == 0 &&
            (statfs->f_flags & 0x20) == 0,
        "provider exec handoff preserves exact guest fstatfs identity");
  Check(Kernel::Memory::KernelMunmap(reinterpret_cast<uint64_t>(statfs_memory), 0x4000) == OK &&
            FileSystem::KernelClose(file) == OK,
        "release provider exec fstatfs fixture and descriptor");
  Check(FileSystem::KernelOpen("/system_ex_b/mbus/app_info.dat", 2, 0) == Kernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelOpen("/system_ex_b/mbus/app_info.dat", 0x401, 0) == Kernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelOpen("/system_ex_b/mbus/new.dat", 0x202, 0600) == Kernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelUnlink("/system_ex_b/mbus/app_info.dat") == Kernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelMkdir("/system_ex_b/mbus/new", 0700) == Kernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelRename("/system_ex_b/mbus/app_info.dat", "/system_ex_b/mbus/new.dat") ==
                Kernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelOpen("/system_ex_b/escape/secret.bin", 0, 0) == Kernel::KERNEL_ERROR_ENOENT,
        "replayed provider keeps writes read-only and rejects a sibling junction escape");
}

void CheckInitialRootRelativeProviderPaths(const std::filesystem::path& root) {
  namespace Kernel = Libs::LibKernel;
  namespace Mount = Kernel::DirectoryPassthrough;
  const auto system = root / "initial-root-system";
  const auto system_data = root / "initial-root-system-data";
  Check(std::filesystem::create_directories(system / "priv" / "resource_arbitrator_ro") &&
            std::filesystem::create_directories(system_data / "priv" / "resource_arbitrator"),
        "create isolated initial-root provider trees");
  const std::string json = "{\"version\":1267}";
  const std::string env = "version=1267\n";
  { std::ofstream output(system / "priv" / "resource_arbitrator_ro" / "ra-config.json",
                         std::ios::binary);
    output.write(json.data(), static_cast<std::streamsize>(json.size()));
    Check(output.good(), "write initial-root JSON fixture"); }
  { std::ofstream output(system_data / "priv" / "resource_arbitrator" / "ra-config.env",
                         std::ios::binary);
    output.write(env.data(), static_cast<std::streamsize>(env.size()));
    Check(output.good(), "write initial-root environment fixture"); }
  Check(Mount::Mount("/system", system) == OK &&
            Mount::Mount("/system_data", system_data) == OK,
        "mount exact ResourceArbitrator provider namespaces");
  FileSystem::FileStat relative {}, absolute {}, environment {};
  Check(FileSystem::KernelStat("system/priv/resource_arbitrator_ro/ra-config.json",
                               &relative) == OK &&
            FileSystem::KernelStat("/system/priv/resource_arbitrator_ro/ra-config.json",
                                   &absolute) == OK &&
            relative.st_dev == absolute.st_dev && relative.st_ino == absolute.st_ino &&
            relative.st_size == json.size() &&
            FileSystem::KernelStat("system_data/priv/resource_arbitrator/ra-config.env",
                                   &environment) == OK &&
            environment.st_size == env.size(),
        "initial root resolves the original slashless stat paths to the same provider objects");
  std::array<char, 32> bytes {};
  const int json_fd = FileSystem::KernelOpen(
      "system/priv/resource_arbitrator_ro/ra-config.json", 0, 0);
  Check(json_fd >= 3 &&
            FileSystem::KernelPread(json_fd, bytes.data(), json.size(), 0) ==
                static_cast<int64_t>(json.size()) &&
            std::memcmp(bytes.data(), json.data(), json.size()) == 0 &&
            FileSystem::KernelClose(json_fd) == OK,
        "slashless open reads the exact JSON backing bytes");
  bytes.fill(0);
  const int env_fd = FileSystem::KernelOpen(
      "system_data/priv/resource_arbitrator/ra-config.env", 0, 0);
  Check(env_fd >= 3 &&
            FileSystem::KernelPread(env_fd, bytes.data(), env.size(), 0) ==
                static_cast<int64_t>(env.size()) &&
            std::memcmp(bytes.data(), env.data(), env.size()) == 0 &&
            FileSystem::KernelClose(env_fd) == OK,
        "slashless open reads the exact environment backing bytes");
  Check(FileSystem::KernelOpen("system/priv/resource_arbitrator_ro/ra-config.json", 2, 0) ==
                Kernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelOpen("system/priv/resource_arbitrator_ro/missing.json", 0, 0) ==
                Kernel::KERNEL_ERROR_ENOENT &&
            Mount::ValidateTraversal("system/priv/resource_arbitrator_ro/ra-config.json") ==
                Kernel::KERNEL_ERROR_EINVAL,
        "relative-root correction preserves read-only, missing-file and backend validation errors");
  Check(Mount::Unmount("/system_data") == OK && Mount::Unmount("/system") == OK,
        "release exact ResourceArbitrator provider namespaces");
  std::printf("KernelFileSystemTests: initial-root provider cases passed\n");
}

void CheckReadOnlyProviderBatchRollback(const std::filesystem::path& root,
                                       ReadOnlyProviderRecord first,
                                       const ReadOnlyProviderTmpfsState& shared) {
  namespace Kernel = Libs::LibKernel;
  namespace Mount = Kernel::DirectoryPassthrough;
  Check(FileSystem::RegisterDiagnosticPartitionPassthrough("/dev/ssd0.update_b", root / "provider-batch-root") == OK &&
            FileSystem::MountRegisteredPartitionPassthrough("/dev/ssd0.update_b", "/update_b") == OK,
        "publish a second valid registered provider to obtain its exact provenance");
  std::string exported;
  Check(FileSystem::ExportExecReadOnlyProviders(&exported) == OK,
        "export the second valid base provider");
  auto second = ParseReadOnlyProviderRecord(exported);
  Check(second.provider == "/dev/ssd0.update_b" && second.point == "/update_b",
        "second rollback record has registered provider provenance");
  FileSystem::Umount("/update_b");
  Check(Mount::Mount("/provider-unrelated", root / "provider-conflict") == OK,
        "mount an unrelated read-only backend before the batch collision");
  Mount::MountInfo unrelated;
  Mount::NodeStat before {};
  std::shared_ptr<Mount::Handle> pinned;
  Check(Mount::DescribeMount("/provider-unrelated", &unrelated) == OK &&
            Mount::Open("/provider-unrelated/marker", 0, &pinned) == OK &&
            Mount::Fstat(pinned, &before) == OK,
        "pin the unrelated mount's original device, inode and file handle");
  first.device = UINT32_MAX - 1;
  second.device = unrelated.device;
  Check(FileSystem::ImportExecReadOnlyProviders(ReadOnlyProviderManifest({first, second})) ==
            Kernel::KERNEL_ERROR_EBUSY && !Mount::Contains(first.point) && !Mount::Contains(second.point) &&
            FileSystem::KernelOpen("/system_ex_b/mbus/app_info.dat", 0, 0) == Kernel::KERNEL_ERROR_ENOENT &&
            FileSystem::KernelOpen("/update_b/marker", 0, 0) == Kernel::KERNEL_ERROR_ENOENT,
        "second-record device collision rejects the whole otherwise valid high-ID batch");
  std::string after;
  Check(FileSystem::ExportExecReadOnlyProviders(&after) == OK && after == ReadOnlyProviderManifest({}),
        "failed batch leaves no published provider records");
  Mount::MountInfo retained;
  Mount::NodeStat stat {};
  std::array<char, 8> bytes {};
  Check(Mount::DescribeMount("/provider-unrelated", &retained) == OK &&
            retained.device == unrelated.device && retained.host_root == unrelated.host_root &&
            Mount::Fstat(pinned, &stat) == OK && stat.device == before.device &&
            stat.inode == before.inode && stat.size == before.size &&
            Mount::Pread(pinned, bytes.data(), bytes.size(), 0) == bytes.size() &&
            std::memcmp(bytes.data(), "CONFLICT", bytes.size()) == 0,
        "failed batch preserves the unrelated mount and its already-open handle");
  CheckReadOnlyProviderTmpfs(shared);
  Mount::MountInfo ordinary;
  Check(Mount::Mount("/provider-after-batch", root / "provider-conflict") == OK &&
            Mount::DescribeMount("/provider-after-batch", &ordinary) == OK &&
            ordinary.device == unrelated.device + 1 && ordinary.device != first.device,
        "failed high-ID batch leaves ordinary device allocation usable and noncolliding");
  Check(Mount::Unmount("/provider-after-batch") == OK && Mount::Close(pinned) == OK &&
            Mount::Unmount("/provider-unrelated") == OK,
        "release only the batch collision fixture's unrelated mounts and handle");
  CheckReadOnlyProviderTmpfs(shared);
}

int RunReadOnlyProviderChild(int argc, char** argv) {
  if (argc < 2 || std::strcmp(argv[1], "--readonly-provider-child") != 0) return -1;
  if (argc != 4) return 2;
#if defined(_WIN32)
  namespace Kernel = Libs::LibKernel;
  namespace Mount = Kernel::DirectoryPassthrough;
  namespace Tmpfs = Kernel::Tmpfs;
  const auto root = Common::PathFromUtf8(argv[2]);
  const auto manifest = ReadOnlyProviderFixtureFile(root / "providers.txt");
  const auto record = ParseReadOnlyProviderRecord(manifest);
  FileSystem::FileStat expected {};
  ReadOnlyProviderTmpfsState shared;
  shared.scope = argv[3];
  { std::ifstream input(root / "provider-identity.txt");
    Check(static_cast<bool>(input >> expected.st_dev >> expected.st_ino >> shared.stat.device >>
              shared.stat.inode >> shared.stat.size), "read parent provider and tmpfs identities"); }
  Tmpfs::Shutdown();
  Check(Tmpfs::Initialize(shared.scope) == OK &&
            Tmpfs::Open("/provider-shared/sentinel", 0, 0, &shared.handle) == OK,
        "attach the child to its parent's already-live shared tmpfs");
  CheckReadOnlyProviderTmpfs(shared);
  FileSystem::MountReadOnly(root / "provider-underlay", "/");
  FileSystem::FileStat data_stat {}, data_fstat {};
  const int data_fd = FileSystem::KernelOpen("/data", 0x20000, 0);
  std::array<char, 512> data_entries {};
  Check(data_fd >= 3 && FileSystem::KernelStat("/data", &data_stat) == OK &&
            FileSystem::KernelFstat(data_fd, &data_fstat) == OK &&
            data_stat.st_dev == data_fstat.st_dev && data_stat.st_ino == data_fstat.st_ino &&
            FileSystem::KernelGetdents(data_fd, data_entries.data(), data_entries.size()) == 0 &&
            FileSystem::GetRealFilename("/data").empty() &&
            FileSystem::KernelClose(data_fd) == OK,
        "child reconstructs empty data topology from its read-only root mount");
  auto rejected = [&](const std::string& value, int error) {
    Check(FileSystem::ImportExecReadOnlyProviders(value) == error &&
              !Mount::Contains("/system_ex_b") &&
              FileSystem::KernelOpen("/system_ex_b/mbus/app_info.dat", 0, 0) == Kernel::KERNEL_ERROR_ENOENT,
          "rejected provider import publishes no partial mount");
    CheckReadOnlyProviderTmpfs(shared);
  };
  rejected("", Kernel::KERNEL_ERROR_EINVAL);
  rejected("KYTY_EXEC_RO_PROVIDERS 3\n", Kernel::KERNEL_ERROR_EINVAL);
  rejected(ReadOnlyProviderManifest({record}, 1), Kernel::KERNEL_ERROR_EINVAL);
  rejected(ReadOnlyProviderManifest({record}, 2), Kernel::KERNEL_ERROR_EINVAL);
  rejected(std::string(65537, 'x'), Kernel::KERNEL_ERROR_E2BIG);
  rejected(manifest + std::string(1, '\0'), Kernel::KERNEL_ERROR_EINVAL);
  rejected(manifest, Kernel::KERNEL_ERROR_ENOENT);
  Check(FileSystem::RegisterDiagnosticPartitionPassthrough("/dev/ssd0.system_ex_b", root / "provider-root") == OK,
        "child re-registers only its explicitly selected canonical provider root");
  rejected(manifest + "trailing\n", Kernel::KERNEL_ERROR_EINVAL);
  rejected(manifest.substr(0, manifest.rfind("END\n")), Kernel::KERNEL_ERROR_EINVAL);
  rejected(ReadOnlyProviderManifest({record, record}), Kernel::KERNEL_ERROR_EINVAL);
  const std::array<std::string, 4> fields {record.provider, record.point, record.root, record.identity};
  for (size_t unquoted = 0; unquoted < fields.size(); ++unquoted) {
    std::ostringstream malformed;
    malformed << "KYTY_EXEC_RO_PROVIDERS 3\nP ";
    for (size_t i = 0; i < fields.size(); ++i) {
      if (i == unquoted) malformed << fields[i];
      else malformed << std::quoted(fields[i]);
      malformed << ' ';
    }
    malformed << record.device << " G " << std::quoted(record.guest_fstype) << ' '
              << std::quoted(record.guest_source) << ' ' << record.guest_flags << "\nEND\n";
    rejected(malformed.str(), Kernel::KERNEL_ERROR_EINVAL);
  }
  for (size_t missing = 0; missing <= fields.size(); ++missing) {
    std::ostringstream malformed;
    malformed << "KYTY_EXEC_RO_PROVIDERS 3\nP";
    for (size_t i = 0; i < fields.size(); ++i) {
      if (i != missing) malformed << ' ';
      malformed << std::quoted(fields[i]);
    }
    if (missing != fields.size()) malformed << ' ';
    malformed << record.device << " G " << std::quoted(record.guest_fstype) << ' '
              << std::quoted(record.guest_source) << ' ' << record.guest_flags << "\nEND\n";
    rejected(malformed.str(), Kernel::KERNEL_ERROR_EINVAL);
  }
  const auto number = manifest.find(' ' + std::to_string(record.device) + " G ");
  const auto number_end = number == manifest.npos ? manifest.npos : number + 1 + std::to_string(record.device).size();
  Check(number != manifest.npos && number_end != manifest.npos, "locate the exported decimal device token");
  for (const auto& token: std::vector<std::string> {
      "+" + std::to_string(record.device), "-1", "-18446744069414584322",
      "4294967296", "18446744073709551616", "0" + std::to_string(record.device),
      "0xEF100000", "junk" + std::to_string(record.device),
      std::to_string(record.device) + "junk", std::to_string(record.device) + ".0", "4e9"}) {
    auto malformed = manifest;
    malformed.replace(number + 1, number_end - number - 1, token);
    rejected(malformed, Kernel::KERNEL_ERROR_EINVAL);
  }
  auto changed = record;
  changed.root = (root / "provider-root-sibling").generic_string();
  rejected(ReadOnlyProviderManifest({changed}), Kernel::KERNEL_ERROR_EINVAL);
  changed = record;
  changed.identity += "changed";
  rejected(ReadOnlyProviderManifest({changed}), Kernel::KERNEL_ERROR_EINVAL);
  changed = record;
  changed.point = "/system_ex_b/mbus";
  rejected(ReadOnlyProviderManifest({changed}), Kernel::KERNEL_ERROR_EINVAL);
  changed = record;
  changed.provider = "/dev/unsupported";
  rejected(ReadOnlyProviderManifest({changed}), Kernel::KERNEL_ERROR_EINVAL);
  changed = record;
  changed.guest_fstype = "ufs";
  rejected(ReadOnlyProviderManifest({changed}), Kernel::KERNEL_ERROR_EINVAL);
  changed = record;
  changed.guest_source = "/dev/ssd0.system_ex";
  rejected(ReadOnlyProviderManifest({changed}), Kernel::KERNEL_ERROR_EINVAL);
  changed = record;
  changed.guest_flags = 0;
  rejected(ReadOnlyProviderManifest({changed}), Kernel::KERNEL_ERROR_EINVAL);
  changed = record;
  changed.provider = "/dev/ssd0.update_b";
  changed.point = "/update_b";
  ++changed.device;
  rejected(ReadOnlyProviderManifest({record, changed}), Kernel::KERNEL_ERROR_ENOENT);
  CheckReadOnlyProviderBatchRollback(root, record, shared);
  Check(Mount::Mount("/system_ex_b", root / "provider-conflict") == OK &&
            FileSystem::ImportExecReadOnlyProviders(manifest) == Kernel::KERNEL_ERROR_EBUSY,
        "provider import rejects an occupied guest mount point");
  std::shared_ptr<Mount::Handle> occupied;
  std::array<char, 8> conflict {};
  Check(Mount::Open("/system_ex_b/marker", 0, &occupied) == OK &&
            Mount::Pread(occupied, conflict.data(), conflict.size(), 0) == conflict.size() &&
            std::memcmp(conflict.data(), "CONFLICT", conflict.size()) == 0 &&
            Mount::Close(occupied) == OK && Mount::Unmount("/system_ex_b") == OK,
        "conflicting provider import leaves the occupied root unchanged");
  Check(FileSystem::ImportExecReadOnlyProviders(manifest) == OK,
        "separate process imports the parent's exported provider manifest");
  CheckReadOnlyProviderContents(expected);
  CheckReadOnlyProviderTmpfs(shared);
  Check(FileSystem::ImportExecReadOnlyProviders(manifest) == Kernel::KERNEL_ERROR_EBUSY,
        "duplicate live provider import is rejected");
  CheckReadOnlyProviderContents(expected);
  CheckReadOnlyProviderTmpfs(shared);
  Check(Tmpfs::Close(shared.handle) == OK, "release child shared tmpfs handle");
  FileSystem::Umount("/system_ex_b");
  FileSystem::Umount("/");
  Check(FileSystem::KernelStat("/data", &data_stat) == Kernel::KERNEL_ERROR_ENOENT,
        "child root unmount removes reconstructed data topology");
  std::printf("KernelFileSystemTests: separate-process read-only provider cases passed\n");
  return 0;
#else
  return 2;
#endif
}

void CheckReadOnlyProviderExec(const std::filesystem::path& root) {
#if defined(_WIN32)
  namespace Kernel = Libs::LibKernel;
  namespace Mount = Kernel::DirectoryPassthrough;
  namespace Tmpfs = Kernel::Tmpfs;
  const auto host = root / "provider-root";
  const auto sibling = root / "provider-root-sibling";
  const auto underlay = root / "provider-underlay";
  Check(std::filesystem::create_directories(host / "mbus") &&
            std::filesystem::create_directory(sibling) &&
            std::filesystem::create_directories(underlay / "system_ex_b") &&
            std::filesystem::create_directory(underlay / "update_b") &&
            std::filesystem::create_directory(root / "provider-batch-root") &&
            std::filesystem::create_directory(root / "provider-conflict"),
        "create explicit base-provider, sibling and covered mount roots");
  const auto bytes = ReadOnlyProviderBytes();
  { std::ofstream output(host / "mbus" / "app_info.dat", std::ios::binary);
    output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    Check(output.good(), "write exact provider fixture bytes"); }
  { std::ofstream output(sibling / "secret.bin", std::ios::binary); output << "SIBLING";
    Check(output.good(), "write sibling escape fixture bytes"); }
  { std::ofstream output(root / "provider-conflict" / "marker", std::ios::binary); output << "CONFLICT";
    Check(output.good(), "write occupied provider fixture bytes"); }
  CreateInitialDirectoryJunction(host / "escape", sibling);
  FileSystem::MountReadOnly(underlay, "/");
  Check(FileSystem::RegisterDiagnosticPartitionPassthrough("/dev/ssd0.system_ex_b", host) == OK &&
            FileSystem::RegisterDiagnosticPartitionPassthrough("/dev/ssd0.system_ex_b", host) == Kernel::KERNEL_ERROR_EEXIST &&
            FileSystem::MountRegisteredPartitionPassthrough("/dev/ssd0.system_ex_b", "/system_ex_b") == OK &&
            FileSystem::MountRegisteredPartitionPassthrough("/dev/ssd0.system_ex_b", "/system_ex_b") == Kernel::KERNEL_ERROR_EBUSY,
        "publish one explicit base provider and reject duplicate registration and mount");
  FileSystem::FileStat stat {};
  Check(FileSystem::KernelStat("/system_ex_b/mbus/app_info.dat", &stat) == OK,
        "stat the parent provider before export");
  CheckReadOnlyProviderContents(stat);
  auto shared = CreateReadOnlyProviderTmpfs();
  std::string manifest = "unchanged";
  Check(FileSystem::ExportExecReadOnlyProviders(nullptr) == Kernel::KERNEL_ERROR_EFAULT &&
            FileSystem::ExportExecReadOnlyProviders(&manifest) == OK,
        "export the live explicitly registered provider");
  const auto record = ParseReadOnlyProviderRecord(manifest);
  Check(record.provider == "/dev/ssd0.system_ex_b" && record.point == "/system_ex_b" &&
            Common::PathFromUtf8(record.root) == std::filesystem::canonical(host) &&
            !record.identity.empty() && record.device == stat.st_dev &&
            record.guest_fstype == "exfatfs" &&
            record.guest_source == "/dev/ssd0.system_ex_b" && record.guest_flags == 1,
        "export records canonical provenance and stable identity without replaying tmpfs");
  const auto moved = root / "provider-original";
  std::filesystem::rename(host, moved);
  Check(std::filesystem::create_directory(host), "temporarily replace only the disposable provider root");
  std::string unchanged = "unchanged";
  Check(FileSystem::ExportExecReadOnlyProviders(&unchanged) == Kernel::KERNEL_ERROR_EINVAL &&
            unchanged == "unchanged", "changed backing-root identity rejects export without changing its output");
  Check(std::filesystem::remove(host), "remove only the empty replacement provider root");
  std::filesystem::rename(moved, host);
  CheckReadOnlyProviderContents(stat);
  CheckReadOnlyProviderTmpfs(shared);
  { std::ofstream output(root / "providers.txt", std::ios::binary); output << manifest;
    Check(output.good(), "save the parent-exported provider manifest for its child"); }
  { std::ofstream output(root / "provider-identity.txt");
    output << stat.st_dev << ' ' << stat.st_ino << ' ' << shared.stat.device << ' '
           << shared.stat.inode << ' ' << shared.stat.size;
    Check(output.good(), "save expected provider and existing tmpfs identities"); }
  std::wstring executable(32768, L'\0');
  const auto length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
  Check(length > 0 && length < executable.size(), "locate provider child executable");
  executable.resize(length);
  const std::wstring scope(shared.scope.begin(), shared.scope.end());
  auto command = L"\"" + executable + L"\" --readonly-provider-child \"" + root.wstring() + L"\" " + scope;
  STARTUPINFOW startup {};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process {};
  Check(CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                       nullptr, nullptr, &startup, &process), "start independent provider manifest reader");
  const auto wait = WaitForSingleObject(process.hProcess, 30000);
  if (wait != WAIT_OBJECT_0) {
    TerminateProcess(process.hProcess, 10);
    WaitForSingleObject(process.hProcess, 1000);
  }
  DWORD exit_code = 1;
  const bool exited = GetExitCodeProcess(process.hProcess, &exit_code) != FALSE;
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  Check(wait == WAIT_OBJECT_0 && exited && exit_code == 0,
        "independent process validates provider replay and rejection without extra mounts");
  CheckReadOnlyProviderContents(stat);
  CheckReadOnlyProviderTmpfs(shared);
  std::string after;
  Check(FileSystem::ExportExecReadOnlyProviders(&after) == OK && after == manifest &&
            FileSystem::ImportExecReadOnlyProviders(manifest) == Kernel::KERNEL_ERROR_EBUSY,
        "child import and duplicate rejection leave the parent provider unchanged");
  CheckReadOnlyProviderTmpfs(shared);
  Check(Tmpfs::Close(shared.handle) == OK && Tmpfs::Unmount("/provider-shared") == OK,
        "release only the provider fixture's shared tmpfs mount");
  FileSystem::Umount("/system_ex_b");
  Check(!Mount::Contains("/system_ex_b"), "provider unmount leaves no inherited mount in the parent");
  FileSystem::Umount("/");
  Check(RemoveDirectoryW((host / "escape").c_str()) != FALSE,
        "remove the disposable provider junction before fixture cleanup");
  std::array<uint8_t, 8112> original {};
  { std::ifstream input(host / "mbus" / "app_info.dat", std::ios::binary);
    input.read(reinterpret_cast<char*>(original.data()), original.size());
    Check(input.gcount() == original.size() && input.peek() == std::char_traits<char>::eof() && original == bytes &&
              !std::filesystem::exists(host / "mbus" / "new.dat") &&
              std::filesystem::file_size(sibling / "secret.bin") == 7,
          "provider replay and rejected writes preserve all host fixture bytes"); }
  std::printf("KernelFileSystemTests: read-only provider exec cases passed\n");
#else
  (void)root;
#endif
}

void CheckDirectoryPassthroughBackend(const std::filesystem::path& root) {
  namespace Mount = Libs::LibKernel::DirectoryPassthrough;
  namespace Kernel = Libs::LibKernel;
  const auto host = root / "passthrough-backend";
  Check(std::filesystem::create_directories(host / "SysDir") &&
        std::filesystem::create_directories(host / "SysDir" / "nested"),
        "create backend host-root tree");
  { std::ofstream payload(host / "SysDir" / "payload.bin", std::ios::binary);
    payload.write("PAYLOAD", 7);
    Check(payload.good(), "write backend sample payload"); }
  { std::ofstream empty(host / "SysDir" / "nested" / "zero.bin", std::ios::binary);
    Check(empty.good(), "create empty file in nested dir"); }
  Check(Mount::Mount("/pt-test", host) == OK &&
        Mount::Mount("/pt-test", host) == Kernel::KERNEL_ERROR_EBUSY &&
        Mount::Mount("/PT-TEST", host) == Kernel::KERNEL_ERROR_EBUSY &&
        Mount::Mount("/pt-test/child", host) == Kernel::KERNEL_ERROR_EBUSY &&
        Mount::Mount("/pt-missing", host / "no-such") == Kernel::KERNEL_ERROR_ENOENT &&
        Mount::Contains("/pt-test") && Mount::Contains("/pt-test/anything") &&
        !Mount::Contains("/pt-tests/anything"),
        "mount registry rejects overlap and component boundaries");
  std::shared_ptr<Mount::Handle> file_handle, dir_handle, nested_handle;
  Check(Mount::Open("/pt-test/sysdir/PAYLOAD.BIN", 0, &file_handle) == OK &&
        Mount::Open("/PT-TEST/SysDir", 0x20000, &dir_handle) == OK &&
        Mount::Open("/pt-test/SysDir/nested", 0x20000, &nested_handle) == OK,
        "case-insensitive resolution through mount prefix and components");
  std::array<char, 32> bytes {};
  Check(Mount::Read(file_handle, bytes.data(), 3) == 3 &&
        std::memcmp(bytes.data(), "PAY", 3) == 0 &&
        Mount::Seek(file_handle, 0, 1) == 3 &&
        Mount::Pread(file_handle, bytes.data(), 7, 0) == 7 &&
        std::memcmp(bytes.data(), "PAYLOAD", 7) == 0 &&
        Mount::Seek(file_handle, 0, 1) == 3 &&
        Mount::Read(file_handle, bytes.data(), bytes.size()) == 4 &&
        std::memcmp(bytes.data(), "LOAD", 4) == 0,
        "sequential and positioned reads keep independent offsets");
  Check(Mount::Seek(file_handle, 0, 2) == 7 &&
        Mount::Seek(file_handle, -8, 2) == Kernel::KERNEL_ERROR_EINVAL &&
        Mount::Seek(file_handle, INT64_MAX, 1) == Kernel::KERNEL_ERROR_EOVERFLOW,
        "end-anchored seek clamps and overflow stays explicit");
  Mount::NodeStat stat {}, by_path {};
  Check(Mount::Fstat(file_handle, &stat) == OK && stat.size == 7 &&
        (stat.mode & 0170000u) == 0100000u &&
        Mount::Stat("/pt-test/sysdir/payload.bin", &by_path) == OK &&
        stat.inode == by_path.inode && stat.device == by_path.device,
        "fstat and stat identify the same inode on casing variants");
  std::vector<Mount::DirectoryEntry> entries;
  Check(Mount::Entries(dir_handle, &entries) == OK && entries.size() == 2,
        "directory enumeration surfaces host children");
  bool saw_payload = false, saw_nested = false;
  for (const auto& entry: entries) {
    if (entry.name == "payload.bin" && !entry.directory) saw_payload = true;
    if (entry.name == "PAYLOAD.BIN" && !entry.directory) saw_payload = true;
    if (entry.name == "nested" && entry.directory) saw_nested = true;
  }
  Check(saw_payload && saw_nested, "payload and nested dir surface with host casing");
  std::shared_ptr<Mount::Handle> failed;
  Check(Mount::Open("/pt-test/sysdir/payload.bin", 2, &failed) == Kernel::KERNEL_ERROR_EROFS &&
        Mount::Open("/pt-test/sysdir/payload.bin", 1, &failed) == Kernel::KERNEL_ERROR_EROFS &&
        Mount::Open("/pt-test/sysdir/missing", 0x200, &failed) == Kernel::KERNEL_ERROR_EROFS &&
        Mount::Open("/pt-test/sysdir/payload.bin", 3, &failed) == Kernel::KERNEL_ERROR_EINVAL &&
        Mount::Open("/pt-test/sysdir/payload.bin", 0x20000, &failed) == Kernel::KERNEL_ERROR_ENOTDIR &&
        Mount::Open("/pt-test/sysdir/missing", 0, &failed) == Kernel::KERNEL_ERROR_ENOENT &&
        Mount::Open("/pt-test/sysdir/payload.bin", 0, nullptr) == Kernel::KERNEL_ERROR_EFAULT,
        "readonly backend rejects writes and reports exact errors");
  Check(Mount::ValidateTraversal("/pt-test/sysdir") == OK &&
        Mount::ValidateTraversal("relative") == Kernel::KERNEL_ERROR_EINVAL &&
        Mount::ValidateTraversal("/with\\back") == Kernel::KERNEL_ERROR_EINVAL &&
        Mount::ValidateTraversal(std::string(1024, '/')) == Kernel::KERNEL_ERROR_ENAMETOOLONG,
        "traversal validation rejects relative, backslash and oversized paths");
  Check(Mount::Unmount("/PT-TEST") == OK &&
        Mount::Open("/pt-test/sysdir/payload.bin", 0, &failed) == Kernel::KERNEL_ERROR_ENOENT &&
        Mount::Pread(file_handle, bytes.data(), 3, 0) == 3 &&
        std::memcmp(bytes.data(), "PAY", 3) == 0,
        "unmount hides namespace but pinned handles stay usable");
  Check(Mount::Mount("/pt-test", host) == OK, "remount after unmount");
  Mount::NodeStat remounted {};
  Check(Mount::Stat("/pt-test/sysdir/payload.bin", &remounted) == OK &&
        remounted.device != stat.device,
        "remount gets a distinct device identity");
  Check(Mount::Unmount("/pt-test") == OK && Mount::Close(file_handle) == OK &&
        Mount::Close(dir_handle) == OK && Mount::Close(nested_handle) == OK &&
        Mount::Close(file_handle) == Kernel::KERNEL_ERROR_EBADF,
        "release independent handles");
  const auto escape = root / "passthrough-escape";
  std::error_code sym_ec;
  std::filesystem::create_directory(escape, sym_ec);
  { std::ofstream secret(escape / "secret.bin", std::ios::binary);
    secret.write("ESCAPE", 6); }
  const auto link = host / "SysDir" / "symlink";
  std::filesystem::create_directory_symlink(escape, link, sym_ec);
  // mklink needs SeCreateSymbolicLinkPrivilege (admin or Developer Mode); skipped if it fails
  if (!sym_ec) {
    Check(Mount::Mount("/pt-esc", host) == OK, "mount for escape test");
    std::shared_ptr<Mount::Handle> escaped;
    Check(Mount::Open("/pt-esc/SysDir/symlink/secret.bin", 0, &escaped) == Kernel::KERNEL_ERROR_ENOENT &&
          Mount::Open("/pt-esc/SysDir/symlink", 0x20000, &escaped) == Kernel::KERNEL_ERROR_ENOENT,
          "symlink out of host_root is rejected");
    Check(Mount::Unmount("/pt-esc") == OK, "unmount escape test");
  }
  CheckDirectoryPassthroughJunctionRoots(root);
}

void CheckDirectoryPassthroughGuestMount(const std::filesystem::path& root) {
  namespace Kernel = Libs::LibKernel;
  const auto host = root / "passthrough-guest";
  Check(std::filesystem::create_directories(host / "boot") &&
        std::filesystem::create_directories(host / "boot" / "sub"),
        "create guest-mount host root");
  { std::ofstream payload(host / "boot" / "hello.bin", std::ios::binary);
    payload.write("HELLO", 5);
    Check(payload.good(), "write guest mount payload"); }
  const auto underlay = root / "passthrough-underlay";
  Check(std::filesystem::create_directory(underlay) &&
        std::filesystem::create_directory(underlay / "system"),
        "create existing passthrough mountpoint underlay");
  { std::ofstream hidden(underlay / "system" / "hello.bin", std::ios::binary);
    hidden.write("UNDERLAY", 8);
    Check(hidden.good(), "create covered host file"); }
  FileSystem::MountReadOnly(underlay, "/pt-underlay");
  Check(FileSystem::RegisterDiagnosticPartitionPassthrough("/dev/not.a.whitelist", host) == Kernel::KERNEL_ERROR_EINVAL,
        "registration whitelist rejects unknown device");
  Check(FileSystem::RegisterDiagnosticPartitionPassthrough("/dev/ssd0.system", host / "no-such") == Kernel::KERNEL_ERROR_ENOENT,
        "registration rejects missing host root");
  Check(FileSystem::RegisterDiagnosticPartitionPassthrough("/dev/ssd0.system", host) == OK &&
        FileSystem::RegisterDiagnosticPartitionPassthrough("/dev/ssd0.system", host) == Kernel::KERNEL_ERROR_EEXIST,
        "second register for same device fails");
  Check(FileSystem::MountRegisteredPartitionPassthrough("/dev/ssd0.system_b", "/pt-underlay/system") == Kernel::KERNEL_ERROR_ENOENT &&
        FileSystem::MountRegisteredPartitionPassthrough("/dev/ssd0.system", "/pt-underlay/missing") == Kernel::KERNEL_ERROR_ENOENT,
        "mount fails without registration or without existing mount point");
  Check(FileSystem::MountRegisteredPartitionPassthrough("/dev/ssd0.system", "/pt-underlay/system") == OK,
        "mount binds registered host root to existing mount point");
  const int fd = FileSystem::KernelOpen("/pt-underlay/system/BOOT/HELLO.BIN", 0, 0);
  std::array<char, 32> bytes {};
  Check(fd >= 3 && FileSystem::KernelRead(fd, bytes.data(), 2) == 2 &&
        std::memcmp(bytes.data(), "HE", 2) == 0 &&
        FileSystem::KernelPread(fd, bytes.data(), 5, 0) == 5 &&
        std::memcmp(bytes.data(), "HELLO", 5) == 0 &&
        FileSystem::KernelLseek(fd, 0, 1) == 2,
        "guest descriptor reads payload through case variants");
  FileSystem::FileStat stat {}, by_path {};
  Check(FileSystem::KernelFstat(fd, &stat) == OK && stat.st_size == 5 &&
        FileSystem::KernelStat("/pt-underlay/SYSTEM/boot/hello.bin", &by_path) == OK &&
        stat.st_ino == by_path.st_ino,
        "fstat and stat agree across the mount");
  const int directory = FileSystem::KernelOpen("/pt-underlay/system/boot", 0x20000, 0);
  std::array<char, 512> dirent_buf {};
  Check(directory >= 3, "open passthrough directory before fstatfs");
#if defined(_WIN32)
  const char* previous_guard_text = std::getenv("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS");
  const std::string previous_guard = previous_guard_text ? previous_guard_text : "";
  Check(_putenv_s("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS", "") == 0,
        "disable broad raw syscall guards for production fstatfs binding fixture");
  Loader::SymbolDatabase statfs_symbols;
  Libs::InitLibKernel_1(&statfs_symbols);
  Check(_putenv_s("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS",
                  previous_guard.c_str()) == 0,
        "restore raw syscall guard environment after production fstatfs binding");
  using Fstatfs = int (KYTY_SYSV_ABI *)(int, FileSystem::KernelStatfs*);
  const auto resolve_fstatfs = [&](const char* nid) {
    const auto* symbol = statfs_symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "raw syscall397 fstatfs NID resolves");
    return reinterpret_cast<Fstatfs>(symbol->vaddr);
  };
  const std::array<Fstatfs, 2> fstatfs_exports {
      resolve_fstatfs("17Mfe1B3X6U"), resolve_fstatfs("+rWFNYiNaEM")};
  void* statfs_memory = nullptr;
  Check(Kernel::Memory::KernelMapNamedFlexibleMemory(
            &statfs_memory, 0x4000, 3, 0, "passthrough_fstatfs_fixture") == OK,
        "map guest fstatfs output fixture");
  auto* guest_statfs = static_cast<FileSystem::KernelStatfs*>(statfs_memory);
  const auto check_fstatfs = [&](Fstatfs call, int descriptor, const char* label) {
    std::memset(guest_statfs, 0xa5, sizeof(*guest_statfs));
    *Libs::Posix::GetErrorAddr() = Libs::Posix::POSIX_EBUSY;
    Check(call(descriptor, guest_statfs) == 0 &&
              *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EBUSY &&
              guest_statfs->f_version == 0x20030518 &&
              guest_statfs->f_type == 0 && guest_statfs->f_flags == 1 &&
              std::strcmp(guest_statfs->f_fstypename, "exfatfs") == 0 &&
              std::strcmp(guest_statfs->f_mntfromname, "/dev/ssd0.system") == 0 &&
              std::strcmp(guest_statfs->f_mntonname, "/pt-underlay/system") == 0 &&
              guest_statfs->f_bsize == 0 && guest_statfs->f_blocks == 0 &&
              (guest_statfs->f_flags & 0x20) == 0,
          label);
  };
  for (const auto call: fstatfs_exports) {
    check_fstatfs(call, fd, "both syscall397 NIDs report exact regular-file mount identity");
    check_fstatfs(call, directory, "both syscall397 NIDs report exact directory mount identity");
  }
  const int closed_statfs = FileSystem::KernelOpen("/pt-underlay/system/boot/hello.bin", 0, 0);
  Check(closed_statfs >= 3 && FileSystem::KernelClose(closed_statfs) == OK,
        "create closed descriptor for fstatfs failure fixture");
  const auto check_fstatfs_failure = [&](int descriptor, int expected_errno) {
    std::memset(guest_statfs, 0x5a, sizeof(*guest_statfs));
    std::array<uint8_t, sizeof(FileSystem::KernelStatfs)> before {};
    std::memcpy(before.data(), guest_statfs, before.size());
    *Libs::Posix::GetErrorAddr() = 0;
    Check(fstatfs_exports[0](descriptor, guest_statfs) == -1 &&
              *Libs::Posix::GetErrorAddr() == expected_errno &&
              std::memcmp(before.data(), guest_statfs, before.size()) == 0,
          "fstatfs descriptor failures preserve the complete output");
  };
  check_fstatfs_failure(closed_statfs, Libs::Posix::POSIX_EBADF);
  check_fstatfs_failure(0x7ffffffe, Libs::Posix::POSIX_EBADF);
  const int ordinary_statfs = FileSystem::KernelOpen("/pt-underlay", 0x20000, 0);
  Check(ordinary_statfs >= 3, "open direct mount descriptor for unsupported fstatfs fixture");
  check_fstatfs_failure(ordinary_statfs, Libs::Posix::POSIX_ENOSYS);
  *Libs::Posix::GetErrorAddr() = 0;
  Check(fstatfs_exports[0](fd, reinterpret_cast<FileSystem::KernelStatfs*>(1)) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT,
        "fstatfs rejects an invalid guest output pointer");
  Check(FileSystem::KernelClose(ordinary_statfs) == OK,
        "close unsupported direct-mount fstatfs descriptor");
  auto* getdirentries_output = static_cast<char*>(statfs_memory) + 0x1000;
  auto* getdirentries_base = reinterpret_cast<int64_t*>(static_cast<char*>(statfs_memory) + 0x3000);
  std::memset(getdirentries_output, 0, 0x200);
  *getdirentries_base = -1;
  Check(FileSystem::KernelGetdirentries(directory, getdirentries_output, 0x200,
                                        getdirentries_base) > 0 &&
            *getdirentries_base == 0 && FileSystem::KernelLseek(directory, 0, 0) == 0,
        "fstatfs leaves the directory ready for getdirentries");
#endif
  Check(FileSystem::KernelGetdents(directory, dirent_buf.data(), dirent_buf.size()) > 0,
        "getdents surfaces passthrough directory entries");
  Check(FileSystem::KernelFsync(directory) == OK, "read-only passthrough directory fsync succeeds");
  Check(FileSystem::GetRealFilename("/pt-underlay/system/boot/hello.bin").empty(),
        "passthrough does not expose host paths through GetRealFilename");
  Check(FileSystem::KernelOpen("/pt-underlay/system/boot/hello.bin", 2, 0) == Kernel::KERNEL_ERROR_EROFS &&
        FileSystem::KernelUnlink("/pt-underlay/system/boot/hello.bin") == Kernel::KERNEL_ERROR_EROFS &&
        FileSystem::KernelMkdir("/pt-underlay/system/boot/new", 0777) == Kernel::KERNEL_ERROR_EROFS &&
        FileSystem::KernelRmdir("/pt-underlay/system/boot/sub") == Kernel::KERNEL_ERROR_EROFS &&
        FileSystem::KernelRename("/pt-underlay/system/boot/hello.bin", "/pt-underlay/system/boot/new") == Kernel::KERNEL_ERROR_EROFS &&
        FileSystem::KernelWrite(fd, bytes.data(), 1) == Kernel::KERNEL_ERROR_EBADF &&
        FileSystem::KernelPwrite(fd, bytes.data(), 1, 0) == Kernel::KERNEL_ERROR_EBADF &&
        FileSystem::KernelFtruncate(fd, 0) == Kernel::KERNEL_ERROR_EBADF,
        "mutation paths return EROFS or EBADF without touching host files");
  Check(FileSystem::KernelOpen("/pt-underlay/system/boot/hello.bin/../../outside", 0, 0) == Kernel::KERNEL_ERROR_ENOENT,
        "guest paths cannot escape through host-only directories");
  FileSystem::Umount("/pt-underlay/system");
#if defined(_WIN32)
  for (const auto call: fstatfs_exports) {
    check_fstatfs(call, fd, "open regular descriptor pins fstatfs identity past unmount");
    check_fstatfs(call, directory, "open directory descriptor pins fstatfs identity past unmount");
  }
#endif
  const int restored = FileSystem::KernelOpen("/pt-underlay/system/hello.bin", 0, 0);
  Check(restored >= 3 && FileSystem::KernelRead(restored, bytes.data(), 8) == 8 &&
        std::memcmp(bytes.data(), "UNDERLAY", 8) == 0 && FileSystem::KernelClose(restored) == OK,
        "unmount restores covered host file");
  Check(FileSystem::KernelPread(fd, bytes.data(), 5, 0) == 5 && std::memcmp(bytes.data(), "HELLO", 5) == 0 &&
        FileSystem::KernelClose(fd) == OK && FileSystem::KernelClose(directory) == OK,
        "pinned descriptors stay usable past unmount");
#if defined(_WIN32)
  Check(Kernel::Memory::KernelMunmap(reinterpret_cast<uint64_t>(statfs_memory), 0x4000) == OK,
        "release guest fstatfs output fixture");
#endif
  FileSystem::Umount("/pt-underlay");
}

void CheckDirectoryPassthroughGetdentsBoundary(const std::filesystem::path& root) {
  namespace Kernel = Libs::LibKernel;
  const auto small_root = root / "pt-getdents-small";
  Check(std::filesystem::create_directories(small_root / "sub"), "create small-dir host root");
  { std::ofstream a(small_root / "a.bin", std::ios::binary); a.write("A", 1); }
  { std::ofstream b(small_root / "b.bin", std::ios::binary); b.write("B", 1); }
  { std::ofstream child(small_root / "sub" / "child.bin", std::ios::binary); child.write("C", 1); }
  const auto underlay = root / "pt-getdents-underlay";
  Check(std::filesystem::create_directory(underlay) &&
        std::filesystem::create_directory(underlay / "small") &&
        std::filesystem::create_directory(underlay / "big") &&
        std::filesystem::create_directory(underlay / "tmp"),
        "create getdents underlay");
  FileSystem::MountReadOnly(underlay, "/pt-dents");
  Check(FileSystem::RegisterDiagnosticPartitionPassthrough("/dev/ssd0.system_b", small_root) == OK &&
        FileSystem::MountRegisteredPartitionPassthrough("/dev/ssd0.system_b", "/pt-dents/small") == OK,
        "register and mount small passthrough");
  const int small_fd = FileSystem::KernelOpen("/pt-dents/small", 0x20000, 0);
  Check(small_fd >= 3, "open small passthrough directory");
  const uint64_t syscall_memory = Kernel::Memory::AllocateRuntimeMemory(
      0, 0x4000, Common::VirtualMemory::Mode::ReadWrite, "raw_getdirentries");
  Check(syscall_memory != 0, "map raw getdirentries syscall buffers");
  auto* raw = reinterpret_cast<char*>(syscall_memory);
  auto* base = reinterpret_cast<int64_t*>(raw + 0x1000);
  auto dispatch = [&](int fd, uint64_t buffer, uint64_t count, uint64_t basep) {
    return Libs::NativeKernelBridge::DispatchSyscall(
        {0xc4, {static_cast<uint64_t>(static_cast<int64_t>(fd)), buffer, count, basep}});
  };
  struct PackedEntry {
    uint32_t inode;
    uint16_t reclen;
    uint8_t type;
    std::string name;
  };
  auto parse = [&](const char* bytes, size_t size) {
    std::vector<PackedEntry> entries;
    size_t offset = 0;
    while (offset < size) {
      uint32_t inode = 0;
      uint16_t reclen = 0;
      std::memcpy(&inode, bytes + offset, sizeof(inode));
      std::memcpy(&reclen, bytes + offset + 4, sizeof(reclen));
      const auto type = static_cast<uint8_t>(bytes[offset + 6]);
      const auto namlen = static_cast<uint8_t>(bytes[offset + 7]);
      Check(reclen >= 8 + static_cast<uint16_t>(namlen) + 1 &&
                reclen % 4 == 0 && offset + reclen <= size &&
                bytes[offset + 8 + namlen] == '\0',
            "raw getdirentries emits bounded aligned FreeBSD dirents");
      entries.push_back({inode, reclen, type,
                         std::string(bytes + offset + 8, namlen)});
      offset += reclen;
    }
    return entries;
  };
  std::memset(raw, 0, 0x1200);
  *base = -1;
  const auto raw_first = dispatch(small_fd, reinterpret_cast<uint64_t>(raw), 512,
                                  reinterpret_cast<uint64_t>(base));
  auto root_entries = parse(raw, raw_first.value == 512 ? 512 : 0);
  std::sort(root_entries.begin(), root_entries.end(),
            [](const auto& left, const auto& right) { return left.name < right.name; });
  Check(raw_first.value == 512 && raw_first.posix_errno == 0 && *base == 0 &&
            root_entries.size() == 3 && root_entries[0].name == "a.bin" &&
            root_entries[0].type == 8 && root_entries[0].inode != 0 &&
            root_entries[1].name == "b.bin" && root_entries[1].type == 8 &&
            root_entries[1].inode != 0 && root_entries[2].name == "sub" &&
            root_entries[2].type == 4 && root_entries[2].inode != 0,
        "raw syscall 0xc4 enumerates captured root names and types");
  *base = -1;
  const auto raw_eof = dispatch(small_fd, reinterpret_cast<uint64_t>(raw), 512,
                                reinterpret_cast<uint64_t>(base));
  Check(raw_eof.value == 0 && raw_eof.posix_errno == 0 && *base == 512,
        "raw syscall 0xc4 preserves base offset and EOF");
  Check(FileSystem::KernelLseek(small_fd, 0, 0) == 0,
        "rewind after raw captured-root enumeration");

  const int nested_fd = FileSystem::KernelOpen("/pt-dents/small/sub", 0x20000, 0);
  std::memset(raw, 0, 512);
  *base = -1;
  const auto nested_reply = dispatch(nested_fd, reinterpret_cast<uint64_t>(raw), 512,
                                     reinterpret_cast<uint64_t>(base));
  const auto nested_entries = parse(raw, nested_reply.value == 512 ? 512 : 0);
  Check(nested_fd >= 3 && nested_reply.value == 512 && nested_reply.posix_errno == 0 &&
            *base == 0 && nested_entries.size() == 1 &&
            nested_entries[0].name == "child.bin" && nested_entries[0].type == 8 &&
            nested_entries[0].inode != 0 && FileSystem::KernelClose(nested_fd) == OK,
        "raw syscall 0xc4 traverses a nested captured directory");

  const int regular_fd = FileSystem::KernelOpen("/pt-dents/small/a.bin", 0, 0);
  std::memset(raw, 0xa5, 512);
  *base = 0x123456789abcdef;
  const auto regular_reply = dispatch(regular_fd, reinterpret_cast<uint64_t>(raw), 512,
                                      reinterpret_cast<uint64_t>(base));
  const auto regular_bad_pointer = dispatch(regular_fd, 1, 512, 1);
  Check(regular_fd >= 3 && regular_reply.value == -1 &&
            regular_reply.posix_errno == Libs::Posix::POSIX_EINVAL &&
            regular_bad_pointer.value == -1 &&
            regular_bad_pointer.posix_errno == Libs::Posix::POSIX_EINVAL &&
            static_cast<unsigned char>(raw[0]) == 0xa5 && *base == 0x123456789abcdef &&
            FileSystem::KernelClose(regular_fd) == OK,
        "raw syscall 0xc4 rejects regular descriptors without output mutation");
  const auto closed_reply = dispatch(regular_fd, reinterpret_cast<uint64_t>(raw), 512,
                                     reinterpret_cast<uint64_t>(base));
  const auto closed_bad_pointer = dispatch(regular_fd, 1, 512, 1);
  const auto invalid_reply = dispatch(-1, reinterpret_cast<uint64_t>(raw), 512,
                                      reinterpret_cast<uint64_t>(base));
  const auto invalid_bad_pointer = dispatch(-1, 1, 512, 1);
  const auto short_reply = dispatch(small_fd, reinterpret_cast<uint64_t>(raw), 511,
                                    reinterpret_cast<uint64_t>(base));
  const auto bad_buffer = dispatch(small_fd, 1, 512, reinterpret_cast<uint64_t>(base));
  const auto bad_base = dispatch(small_fd, reinterpret_cast<uint64_t>(raw), 512, 1);
  const auto huge_count = dispatch(small_fd, 1, static_cast<uint64_t>(INT_MAX) + 1, 0);
  Check(closed_reply.value == -1 && closed_reply.posix_errno == Libs::Posix::POSIX_EBADF &&
            closed_bad_pointer.value == -1 &&
            closed_bad_pointer.posix_errno == Libs::Posix::POSIX_EBADF &&
            invalid_reply.value == -1 && invalid_reply.posix_errno == Libs::Posix::POSIX_EBADF &&
            invalid_bad_pointer.value == -1 &&
            invalid_bad_pointer.posix_errno == Libs::Posix::POSIX_EBADF &&
            short_reply.value == -1 && short_reply.posix_errno == Libs::Posix::POSIX_EINVAL &&
            bad_buffer.value == -1 && bad_buffer.posix_errno == Libs::Posix::POSIX_EFAULT &&
            bad_base.value == -1 && bad_base.posix_errno == Libs::Posix::POSIX_EFAULT &&
            huge_count.value == -1 && huge_count.posix_errno == Libs::Posix::POSIX_EINVAL &&
            static_cast<unsigned char>(raw[0]) == 0xa5 && *base == 0x123456789abcdef,
        "raw syscall 0xc4 preserves descriptor, count and pointer error contracts");

  Check(FileSystem::MountTmpfs("/pt-dents/tmp", 0755, 65536, 32) == OK,
        "mount tmpfs for retained raw getdirentries coverage");
  const int tmp_file = FileSystem::KernelOpen("/pt-dents/tmp/entry", 0x202, 0666);
  Check(tmp_file >= 3 && FileSystem::KernelClose(tmp_file) == OK,
        "create tmpfs entry for raw getdirentries");
  const int tmp_fd = FileSystem::KernelOpen("/pt-dents/tmp", 0x20000, 0);
  std::memset(raw, 0, 512);
  *base = -1;
  const auto tmp_reply = dispatch(tmp_fd, reinterpret_cast<uint64_t>(raw), 512,
                                  reinterpret_cast<uint64_t>(base));
  auto tmp_entries = parse(raw, tmp_reply.value == 512 ? 512 : 0);
  std::sort(tmp_entries.begin(), tmp_entries.end(),
            [](const auto& left, const auto& right) { return left.name < right.name; });
  Check(tmp_fd >= 3 && tmp_reply.value == 512 && tmp_reply.posix_errno == 0 &&
            *base == 0 && tmp_entries.size() == 3 && tmp_entries[0].name == "." &&
            tmp_entries[0].type == 4 && tmp_entries[1].name == ".." &&
            tmp_entries[1].type == 4 && tmp_entries[2].name == "entry" &&
            tmp_entries[2].type == 8 && FileSystem::KernelClose(tmp_fd) == OK,
        "generic raw syscall 0xc4 retains tmpfs enumeration");
  FileSystem::Umount("/pt-dents/tmp");

  std::array<char, 2048> buf {};
  Check(FileSystem::KernelGetdents(small_fd, buf.data(), 256) == Kernel::KERNEL_ERROR_EINVAL,
        "getdents rejects sub-block buffer");
  Check(FileSystem::KernelGetdents(small_fd, buf.data(), 511) == Kernel::KERNEL_ERROR_EINVAL,
        "getdents rejects one-less-than-block buffer");
  const auto first = FileSystem::KernelGetdents(small_fd, buf.data(), 512);
  Check(first == 512, "first getdents returns exactly one block");
  Check(FileSystem::KernelLseek(small_fd, 0, 1) == 512,
        "dents_offset advances by exactly one block after a 512-byte read");
  Check(FileSystem::KernelGetdents(small_fd, buf.data(), 512) == 0,
        "second getdents on exhausted small dir returns zero");
  Check(FileSystem::KernelGetdents(small_fd, buf.data(), 2048) == 0,
        "oversized getdents on exhausted small dir still returns zero");
  Check(FileSystem::KernelLseek(small_fd, 0, 0) == 0, "rewind small directory");
  Check(FileSystem::KernelGetdents(small_fd, buf.data(), 2048) == 512,
        "oversized buffer on rewound small dir returns one block (no over-pack)");
  Check(FileSystem::KernelLseek(small_fd, 0, 0) == 0, "rewind small directory again");
  Check(FileSystem::KernelGetdents(small_fd, buf.data(), 700) == 512,
        "unaligned nbytes rounds down to one 512 block");
  Check(FileSystem::KernelLseek(small_fd, 256, 0) == 256,
        "lseek to a misaligned offset is accepted by seek");
  Check(FileSystem::KernelGetdents(small_fd, buf.data(), 512) == Kernel::KERNEL_ERROR_EINVAL,
        "getdents from a misaligned offset is refused");
  Check(FileSystem::KernelLseek(small_fd, 0, 0) == 0, "rewind for post-unmount check");
  const auto before_unmount = FileSystem::KernelGetdents(small_fd, buf.data(), 512);
  Check(before_unmount == 512, "pre-unmount block read");
  FileSystem::Umount("/pt-dents/small");
  Check(FileSystem::KernelLseek(small_fd, 0, 0) == 0, "rewind pinned fd past unmount");
  Check(FileSystem::KernelGetdents(small_fd, buf.data(), 512) == 512,
        "pinned directory fd still services getdents past unmount");
  Check(FileSystem::KernelClose(small_fd) == OK, "close small passthrough fd");

  // Two-block case: 20-char filenames at reclen=32 pack 16 per block, so 17 entries force a second block.
  const auto big = root / "pt-getdents-big";
  Check(std::filesystem::create_directory(big), "create two-block host root");
  for (int i = 0; i < 17; ++i) {
    char name[32];
    std::snprintf(name, sizeof(name), "entry_%02d_payload.bin", i);
    std::ofstream f(big / name, std::ios::binary);
    f.write("x", 1);
  }
  Check(FileSystem::RegisterDiagnosticPartitionPassthrough("/dev/ssd0.system_ex", big) == OK &&
        FileSystem::MountRegisteredPartitionPassthrough("/dev/ssd0.system_ex", "/pt-dents/big") == OK,
        "register and mount two-block passthrough");
  const int big_fd = FileSystem::KernelOpen("/pt-dents/big", 0x20000, 0);
  Check(big_fd >= 3, "open big passthrough directory");
  Check(FileSystem::KernelGetdents(big_fd, buf.data(), 512) == 512,
        "two-block directory first getdents returns one block");
  Check(FileSystem::KernelLseek(big_fd, 0, 1) == 512,
        "two-block dents_offset advances to 512 after first block");
  Check(FileSystem::KernelGetdents(big_fd, buf.data(), 512) == 512,
        "two-block directory second getdents returns the second block");
  Check(FileSystem::KernelLseek(big_fd, 0, 1) == 1024,
        "two-block dents_offset advances to 1024 after the second block");
  Check(FileSystem::KernelGetdents(big_fd, buf.data(), 512) == 0,
        "two-block directory third getdents returns zero");
  Check(FileSystem::KernelLseek(big_fd, 0, 0) == 0, "rewind big directory");
  Check(FileSystem::KernelGetdents(big_fd, buf.data(), 1024) == 1024,
        "two-block getdents returns both blocks in a 1024 buffer");
  Check(FileSystem::KernelClose(big_fd) == OK, "close big passthrough fd");
  FileSystem::Umount("/pt-dents/big");
  Check(Kernel::Memory::FreeGuestMemory(syscall_memory, 0x4000),
        "release raw getdirentries syscall buffers");
  FileSystem::Umount("/pt-dents");
}

void CheckPassthroughUpperStore(const std::filesystem::path& root) {
  using namespace Libs::LibKernel;
  namespace Mount = DirectoryPassthrough;
  const auto storage = root / "upper-capture";
  const auto host = storage / "files";
  const auto upper = root / "upper-store";
  Check(std::filesystem::create_directories(host / "nobackup" / "temp") && std::filesystem::create_directories(host / "priv") &&
            std::filesystem::create_directory(upper),
        "create captured system_data fixture and an empty upper store");
  constexpr char lower[] = "CAPTURED";
  { std::ofstream output(host / "nobackup" / "temp" / "old.db", std::ios::binary); output.write(lower, 8);
    Check(output.good(), "write captured lower file bytes"); }
  std::vector<uint8_t> large((2 * 1024 * 1024) + 17);
  for (size_t i = 0; i < large.size(); ++i) large[i] = static_cast<uint8_t>((i * 29 + 7) & 0xff);
  const auto write_large = [&] {
    std::ofstream output(host / "priv" / "large.bin", std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(large.data()), static_cast<std::streamsize>(large.size()));
    Check(output.good(), "write multi-chunk captured lower file bytes");
  };
  write_large();
  const auto node = [](std::string path, unsigned inode, unsigned mode, unsigned size) {
    return nlohmann::json {{"path", path}, {"inode", inode}, {"mode", mode}, {"size", size}, {"uid", 0u}, {"gid", 5u},
        {"mtime", 315532800}, {"type", (mode & 0170000u) >> 12}, {"metadata", true}, {"complete", true}};
  };
  auto file = node("/nobackup/temp/old.db", 704u, 0100644u, 8u);
  file["complete"] = false;
  file["file"] = "files/nobackup/temp/old.db";
  file["sha256"] = AuthInfo::DigestHex(AuthInfo::Sha256(lower, 8));
  auto large_file = node("/priv/large.bin", 705u, 0100644u, static_cast<unsigned>(large.size()));
  large_file["complete"] = false;
  large_file["file"] = "files/priv/large.bin";
  large_file["sha256"] = AuthInfo::DigestHex(AuthInfo::Sha256(large.data(), large.size()));
  const auto entries = nlohmann::json::array({node("/", 700u, 0040755u, 512u), node("/nobackup", 701u, 0040777u, 512u),
      node("/nobackup/temp", 702u, 0040777u, 512u), file, node("/priv", 703u, 0040755u, 512u), large_file});
  const auto volume = nlohmann::json {{"point", "/system_data"}, {"host_root", Common::PathToString(host)},
      {"case_sensitive", true}, {"entries", entries}};
  const auto manifest = nlohmann::json {{"version", 1}, {"storage", Common::PathToString(storage)},
      {"volumes", nlohmann::json::array({volume})}};
  const auto digest = SaveCapturedDirectoryManifest(storage / "manifest.json", manifest);
  CapturedDirectory::Clear();
  Check(CapturedDirectory::Load(storage / "manifest.json", digest) == OK, "load case-sensitive captured system_data metadata");
  const char* selected = std::getenv("KYTY_DIAGNOSTIC_PASSTHROUGH_UPPER");
  const std::string saved_upper = selected ? selected : "";
  Mount::MountInfo info;
  Check(_putenv_s("KYTY_DIAGNOSTIC_PASSTHROUGH_UPPER", "") == 0 && Mount::Mount("/pt-upper", host, true) == OK &&
            Mount::DescribeMount("/pt-upper", &info) == OK && !info.writable &&
            Mount::Mkdir("/pt-upper/TRASH", 0770) == KERNEL_ERROR_EROFS && Mount::Unmount("/pt-upper") == OK,
        "a writable nmount without an upper store stays read-only");
  Check(_putenv_s("KYTY_DIAGNOSTIC_PASSTHROUGH_UPPER", Common::PathToString(upper).c_str()) == 0 &&
            Mount::Mount("/pt-upper", host, true) == OK && Mount::DescribeMount("/pt-upper", &info) == OK && info.writable,
        "a writable captured mount attaches the upper store");
  Mount::NodeStat stat {};
  const auto object_count = [&] {
    return std::distance(std::filesystem::directory_iterator(upper / "_pt-upper" / "objects"), {});
  };
  std::shared_ptr<Mount::Handle> large_copy, failed_large;
  std::filesystem::resize_file(host / "priv" / "large.bin", large.size() - 1);
  Check(Mount::Open("/pt-upper/priv/large.bin", 2, &failed_large) == KERNEL_ERROR_EIO &&
            object_count() == 0 && Mount::Stat("/pt-upper/priv/large.bin", &stat) == OK && stat.size == large.size(),
        "a short captured source fails verification without publishing or leaking an upper object");
  write_large();
  { std::ofstream output(host / "priv" / "large.bin", std::ios::binary | std::ios::app); output.put('x');
    Check(output.good(), "append a captured-source overrun byte"); }
  Check(Mount::Open("/pt-upper/priv/large.bin", 2, &failed_large) == KERNEL_ERROR_EIO && object_count() == 0,
        "a long captured source fails exact-length verification without leaking an upper object");
  write_large();
  { std::fstream output(host / "priv" / "large.bin", std::ios::binary | std::ios::in | std::ios::out); output.put('x');
    Check(output.good(), "tamper with a captured-source byte"); }
  Check(Mount::Open("/pt-upper/priv/large.bin", 2, &failed_large) == KERNEL_ERROR_EIO && object_count() == 0,
        "same-length multi-chunk corruption fails its digest without leaking an upper object");
  write_large();
  std::array<uint8_t, 5> boundary {};
  const uint64_t boundary_offset = (1024 * 1024) - 2;
  Check(Mount::Open("/pt-upper/priv/large.bin", 2, &large_copy) == OK && object_count() == 1 &&
            Mount::Pwrite(large_copy, "Z", 1, boundary_offset + 2) == 1 &&
            Mount::Pread(large_copy, boundary.data(), boundary.size(), boundary_offset) == boundary.size() &&
            boundary[0] == large[boundary_offset] && boundary[1] == large[boundary_offset + 1] &&
            boundary[2] == 'Z' && boundary[3] == large[boundary_offset + 3] &&
            boundary[4] == large[boundary_offset + 4] && Mount::Fstat(large_copy, &stat) == OK &&
            stat.size == large.size() && Mount::Close(large_copy) == OK &&
            Mount::Unlink("/pt-upper/priv/large.bin") == OK && object_count() == 0,
        "multi-chunk captured copy-up preserves bytes across the chunk boundary and cleans its last upper object");
  Check(Mount::Mkdir("/pt-upper/TRASH", 0770) == OK && Mount::Mkdir("/pt-upper/TRASH", 0770) == KERNEL_ERROR_EEXIST &&
            Mount::Mkdir("/pt-upper", 0777) == KERNEL_ERROR_EEXIST &&
            Mount::Mkdir("/pt-upper/absent/child", 0777) == KERNEL_ERROR_ENOENT &&
            Mount::Mkdir("/pt-upper/nobackup/temp/old.db/child", 0777) == KERNEL_ERROR_ENOTDIR &&
            Mount::Stat("/pt-upper/TRASH", &stat) == OK && stat.mode == 0040770u && stat.uid == 0 && stat.gid == 5,
        "mkdir creates an upper directory with the requested mode and the parent's group");
  Check(Mount::Rename("/pt-upper/nobackup/temp", "/pt-upper/nobackup/temp.old") == OK &&
            Mount::Stat("/pt-upper/nobackup/temp", &stat) == KERNEL_ERROR_ENOENT &&
            Mount::Stat("/pt-upper/nobackup/temp.old/old.db", &stat) == OK && stat.size == 8 && stat.inode == 704u &&
            Mount::Mkdir("/pt-upper/nobackup/temp", 0777) == OK &&
            Mount::Stat("/pt-upper/nobackup/temp", &stat) == OK && stat.mode == 0040777u &&
            Mount::Stat("/pt-upper/nobackup/temp/old.db", &stat) == KERNEL_ERROR_ENOENT &&
            Mount::Rename("/pt-upper/nobackup/temp.old", "/pt-upper/TRASH/1") == OK &&
            Mount::Stat("/pt-upper/TRASH/1/old.db", &stat) == OK && stat.size == 8,
        "ShellCore's temp rotation moves the captured tree aside and recreates an empty directory");
  Check(Mount::Rename("/pt-upper/TRASH", "/pt-upper/TRASH/1/inner") == KERNEL_ERROR_EINVAL &&
            Mount::Rename("/pt-upper/priv", "/pt-upper/TRASH/1/old.db") == KERNEL_ERROR_ENOTDIR &&
            Mount::Rename("/pt-upper/TRASH/1/old.db", "/pt-upper/priv") == KERNEL_ERROR_EISDIR &&
            Mount::Rename("/pt-upper/nobackup", "/pt-upper/TRASH") == KERNEL_ERROR_ENOTEMPTY &&
            Mount::Rename("/pt-upper", "/pt-upper/moved") == KERNEL_ERROR_EBUSY &&
            Mount::Rename("/pt-upper/priv", "/pt-elsewhere/priv") == KERNEL_ERROR_EXDEV,
        "rename rejects cycles, type mismatches, busy roots and cross-mount moves");
  const char* database = "/pt-upper/nobackup/temp/sqlite/system/a.db";
  std::shared_ptr<Mount::Handle> created, appended, reader, copied, failed;
  std::array<char, 16> bytes {};
  Check(Mount::Mkdir("/pt-upper/nobackup/temp/sqlite", 0770) == OK &&
            Mount::Mkdir("/pt-upper/nobackup/temp/sqlite/system", 0770) == OK &&
            Mount::Open(database, 0x202, &created, 0666) == OK && Mount::Write(created, "HELLO", 5) == 5 &&
            Mount::Pwrite(created, "J", 1, 0) == 1 && Mount::Pread(created, bytes.data(), bytes.size(), 0) == 5 &&
            std::memcmp(bytes.data(), "JELLO", 5) == 0 && Mount::Fstat(created, &stat) == OK && stat.size == 5 &&
            stat.mode == 0100666u && stat.gid == 5,
        "O_CREAT makes an upper object that reads back what was written");
  Check(Mount::Open(database, 0xa02, &failed, 0666) == KERNEL_ERROR_EEXIST &&
            Mount::Open(database, 0x20000, &failed) == KERNEL_ERROR_ENOTDIR &&
            Mount::Open("/pt-upper/nobackup/temp/sqlite", 2, &failed) == KERNEL_ERROR_EISDIR &&
            Mount::Open("/pt-upper/nobackup/missing/a.db", 0x202, &failed, 0666) == KERNEL_ERROR_ENOENT,
        "O_EXCL, O_DIRECTORY, directory writes and missing parents fail exactly");
  Check(Mount::Open(database, 0x9, &appended) == OK && Mount::Pwrite(appended, "!", 1, 0) == 1 &&
            Mount::Pread(created, bytes.data(), bytes.size(), 0) == 6 && std::memcmp(bytes.data(), "JELLO!", 6) == 0 &&
            Mount::Open(database, 0, &reader) == OK && Mount::Write(reader, "x", 1) == KERNEL_ERROR_EBADF &&
            Mount::Truncate(reader, 0) == KERNEL_ERROR_EINVAL && Mount::Truncate(created, 2) == OK &&
            Mount::Stat(database, &stat) == OK && stat.size == 2,
        "O_APPEND governs pwrite and ftruncate needs a writable descriptor");
  Check(Mount::Open("/pt-upper/TRASH/1/old.db", 2, &copied) == OK && Mount::Pwrite(copied, "X", 1, 0) == 1 &&
            Mount::Pread(copied, bytes.data(), bytes.size(), 0) == 8 && std::memcmp(bytes.data(), "XAPTURED", 8) == 0 &&
            Mount::Stat("/pt-upper/TRASH/1/old.db", &stat) == OK && stat.inode == 704u && stat.size == 8,
        "writing a captured file copies it up and keeps its observed inode");
  const auto names = [&](const char* path) {
    std::shared_ptr<Mount::Handle> directory;
    std::vector<Mount::DirectoryEntry> listed;
    Check(Mount::Open(path, 0x20000, &directory) == OK && Mount::Entries(directory, &listed) == OK &&
              Mount::Close(directory) == OK, "list a merged upper directory");
    std::vector<std::string> result;
    for (const auto& entry: listed) result.push_back(entry.name);
    std::sort(result.begin(), result.end());
    return result;
  };
  Check(names("/pt-upper/nobackup") == std::vector<std::string> {"temp"} &&
            names("/pt-upper/TRASH/1") == std::vector<std::string> {"old.db"} &&
            names("/pt-upper") == std::vector<std::string> {"TRASH", "nobackup", "priv"},
        "merged listings show upper entries and hide the renamed captured ones");
  Check(Mount::Rmdir("/pt-upper/TRASH/1") == KERNEL_ERROR_ENOTEMPTY && Mount::Unlink("/pt-upper/TRASH/1") == KERNEL_ERROR_EPERM &&
            Mount::Rmdir("/pt-upper/TRASH/1/old.db") == KERNEL_ERROR_ENOTDIR && Mount::Unlink("/pt-upper") == KERNEL_ERROR_EPERM &&
            Mount::Rmdir("/pt-upper") == KERNEL_ERROR_EBUSY && Mount::Close(copied) == OK &&
            Mount::Unlink("/pt-upper/TRASH/1/old.db") == OK &&
            Mount::Stat("/pt-upper/TRASH/1/old.db", &stat) == KERNEL_ERROR_ENOENT && Mount::Rmdir("/pt-upper/TRASH/1") == OK &&
            Mount::Rmdir("/pt-upper/priv") == OK && Mount::Stat("/pt-upper/priv", &stat) == KERNEL_ERROR_ENOENT,
        "unlink and rmdir leave whiteouts over captured entries");
  Check(Mount::Close(created) == OK && Mount::Close(appended) == OK && Mount::Close(reader) == OK &&
            Mount::Unmount("/pt-upper") == OK && Mount::Mount("/pt-upper", host, true) == OK &&
            Mount::Stat(database, &stat) == OK && stat.size == 2 && stat.mode == 0100666u &&
            Mount::Stat("/pt-upper/TRASH", &stat) == OK && stat.mode == 0040770u &&
            Mount::Stat("/pt-upper/priv", &stat) == KERNEL_ERROR_ENOENT &&
            Mount::Stat("/pt-upper/nobackup/temp.old", &stat) == KERNEL_ERROR_ENOENT &&
            names("/pt-upper") == std::vector<std::string> {"TRASH", "nobackup"} &&
            std::distance(std::filesystem::directory_iterator(upper / "_pt-upper" / "objects"), {}) == 1,
        "a remount reloads the upper index and unlinked objects are gone");
  Check(Mount::Unmount("/pt-upper") == OK, "release the direct upper mount");
  const auto underlay = root / "upper-root";
  Check(std::filesystem::create_directories(underlay / "system_data") &&
            std::filesystem::create_directories(underlay / "mnt" / "rnps"),
        "create the guest root for system_data and the RNPS mount point");
  FileSystem::MountReadOnly(underlay, "/");
  const char* passthrough = std::getenv("KYTY_DIAGNOSTIC_FSCK_PARTITION_PASSTHROUGH");
  const std::string saved_passthrough = passthrough ? passthrough : "";
  void* memory = nullptr;
  Check(_putenv_s("KYTY_DIAGNOSTIC_FSCK_PARTITION_PASSTHROUGH", "1") == 0 &&
            FileSystem::RegisterDiagnosticPartitionPassthrough("/dev/ssd0.system_data", host) == OK &&
            Memory::KernelMapNamedFlexibleMemory(&memory, 0x4000, 3, 0, "upper-nmount") == OK,
        "register captured system_data and map nmount vectors");
  struct Iovec { uint64_t address, length; };
  auto* vectors = static_cast<Iovec*>(memory);
  auto* strings = static_cast<char*>(memory) + 0x1000;
  const char* options[] = {"fstype", "ufs", "fspath", "/system_data", "from", "/dev/ssd0.system_data"};
  for (size_t i = 0; i < 6; ++i) {
    const auto length = std::strlen(options[i]) + 1;
    std::memcpy(strings, options[i], length);
    vectors[i] = {reinterpret_cast<uint64_t>(strings), length};
    strings += length;
  }
  Libs::NativeKernelBridge::SyscallRequest request;
  request.number = 0x17a;
  request.args = {reinterpret_cast<uint64_t>(memory), 6, 0};
  const auto mounted = Libs::NativeKernelBridge::DispatchSyscall(request);
  std::string providers;
  Check(mounted.value == 0 && mounted.posix_errno == 0 && FileSystem::ExportExecReadOnlyProviders(&providers) == OK &&
            providers.find(" G \"exfatfs\" \"/dev/ssd0.system_data\" 0 W C " + digest) != providers.npos,
        "a ufs nmount without MNT_RDONLY publishes a writable provider to exec children");
  Loader::SymbolDatabase rnps_symbols;
  Libs::InitLibKernel_1(&rnps_symbols);
  using NativeOpen = int (KYTY_SYSV_ABI *)(const char*, int, uint16_t);
  using NativeFtruncate = int (KYTY_SYSV_ABI *)(int, int64_t);
  using NativeFsync = int (KYTY_SYSV_ABI *)(int);
  using NativeIoctl = int (KYTY_SYSV_ABI *)(int, uint64_t, void*);
  using NativeClose = int (KYTY_SYSV_ABI *)(int);
  const auto resolve = [&](const char* nid) {
    const auto* symbol = rnps_symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "RNPS native file-operation NID resolves");
    return symbol->vaddr;
  };
  const auto native_open = reinterpret_cast<NativeOpen>(resolve("1G3lF1Gg1k8"));
  const auto native_ftruncate = reinterpret_cast<NativeFtruncate>(resolve("VW3TVZiM4-E"));
  const auto native_fsync = reinterpret_cast<NativeFsync>(resolve("fTx66l5iWIA"));
  const auto native_ioctl = reinterpret_cast<NativeIoctl>(resolve("PfccT7qURYE"));
  const auto native_close = reinterpret_cast<NativeClose>(resolve("UK2Tl2DWUns"));
  const int image_fd = native_open("/system_data/nobackup/rnps_apps.img", 0x601, 0770);
  FileSystem::FileStat image_stat {};
  Check(image_fd >= 3 &&
            native_ftruncate(image_fd, 0x40000000) == OK &&
            FileSystem::KernelFstat(image_fd, &image_stat) == OK &&
            image_stat.st_size == 0x40000000 &&
            native_fsync(image_fd) == OK && native_close(image_fd) == OK,
        "RNPS CreateFile ABI creates, grows, syncs and closes the 1 GiB image");
  struct LvdAttachRequest {
    uint32_t version;
    int32_t unit;
    uint32_t sector_size;
    uint32_t granularity;
    uint16_t flags;
    uint16_t image_type;
    uint32_t layer_count;
    uint64_t device_size;
    uint64_t layers;
  };
  struct LvdLayer {
    uint16_t source_type;
    uint16_t flags;
    uint32_t reserved;
    uint64_t path;
    uint64_t offset;
    uint64_t end;
    uint64_t bitmap_path;
    uint64_t bitmap_offset;
    uint64_t bitmap_size;
  };
  static_assert(sizeof(LvdAttachRequest) == 0x28 && offsetof(LvdAttachRequest, unit) == 4 &&
                offsetof(LvdAttachRequest, layers) == 0x20 && sizeof(LvdLayer) == 0x38);
  auto* lvd_request = reinterpret_cast<LvdAttachRequest*>(static_cast<char*>(memory) + 0x800);
  auto* lvd_layer = reinterpret_cast<LvdLayer*>(static_cast<char*>(memory) + 0x880);
  auto* lvd_path = static_cast<char*>(memory) + 0x900;
  auto set_attach = [&](const char* path) {
    std::memset(lvd_request, 0, sizeof(*lvd_request));
    std::memset(lvd_layer, 0, sizeof(*lvd_layer));
    std::strcpy(lvd_path, path);
    lvd_layer->source_type = 1;
    lvd_layer->flags = 1;
    lvd_layer->path = reinterpret_cast<uint64_t>(lvd_path);
    lvd_layer->end = 0x40000000;
    lvd_request->sector_size = 0x200;
    lvd_request->granularity = 0x10000;
    lvd_request->flags = 0x14;
    lvd_request->layer_count = 1;
    lvd_request->device_size = 0x40000000;
    lvd_request->layers = reinterpret_cast<uint64_t>(lvd_layer);
  };
  const int ctl = native_open("/dev/lvdctl", 2, 0);
  Check(ctl >= 3 && FileSystem::KernelOpen("/dev/lvdctl", 0, 0) == KERNEL_ERROR_EINVAL,
        "LVD controller admits only the exact original read-write open tuple");
  set_attach("/system_data/nobackup/rnps_apps.img");
  Check(native_ioctl(ctl, 0xc0286d00u, lvd_request) == 0 && lvd_request->unit == 0,
        "the 0x28/0x38 attach ABI publishes the first dynamic LVD unit");
  auto* lvd_stat = reinterpret_cast<FileSystem::FileStat*>(static_cast<char*>(memory) + 0xb00);
  std::memset(lvd_stat, 0, sizeof(*lvd_stat));
  const int lvd0 = native_open("/dev/lvd0", 2, 0);
  auto* sector = reinterpret_cast<uint32_t*>(static_cast<char*>(memory) + 0xa00);
  auto* capacity = reinterpret_cast<uint64_t*>(static_cast<char*>(memory) + 0xa08);
  *sector = 0xa5a5a5a5u;
  *capacity = 0xa5a5a5a5a5a5a5a5ull;
  Check(lvd0 >= 3 && FileSystem::KernelFstat(lvd0, lvd_stat) == OK &&
            (lvd_stat->st_mode & 0170000u) == 0060000u,
        "the attached node reports the block-device type required by the formatter");
  Check(native_ioctl(lvd0, 0x40046480u, sector) == 0 && *sector == 0x200 &&
            native_ioctl(lvd0, 0x40086481u, capacity) == 0 && *capacity == 0x40000000ull,
        "the attached node reports the formatter geometry");
  Check(FileSystem::KernelRead(lvd0, nullptr, 0) == 0 &&
            FileSystem::KernelWrite(lvd0, nullptr, 0) == 0,
        "zero-length LVD I/O accepts a null buffer without touching backing state");
  auto* lvd_io = static_cast<char*>(memory) + 0x2400;
  std::memset(lvd_io, 0, 0x100);
  std::memcpy(lvd_io, "LVD0", 4);
  Check(FileSystem::KernelPwrite(lvd0, lvd_io, 4, 0x20000) == 4 &&
            FileSystem::KernelLseek(lvd0, 0x20000, 0) == 0x20000 &&
            FileSystem::KernelRead(lvd0, lvd_io + 0x20, 4) == 4 &&
            std::memcmp(lvd_io + 0x20, "LVD0", 4) == 0,
        "dynamic LVD positioned and sequential I/O share the retained image backing");
  const int second_image = native_open("/system_data/nobackup/rnps_bgs.img", 0x601, 0770);
  Check(second_image >= 3 && native_ftruncate(second_image, 0x40000000) == OK &&
            native_fsync(second_image) == OK && native_close(second_image) == OK,
        "create a distinct second image through the RNPS file ABI");
  set_attach("/system_data/nobackup/rnps_bgs.img");
  Check(native_ioctl(ctl, 0xc0286d00u, lvd_request) == 0 && lvd_request->unit == 1,
        "a second anonymous attachment receives an independent unit");
  const int lvd1 = native_open("/dev/lvd1", 2, 0);
  std::memset(lvd_io + 0x40, 0xa5, 4);
  Check(lvd1 >= 3 && FileSystem::KernelPread(lvd1, lvd_io + 0x40, 4, 0x20000) == 4 &&
            std::memcmp(lvd_io + 0x40, "\0\0\0\0", 4) == 0 &&
            FileSystem::KernelPread(lvd0, lvd_io + 0x40, 4, 0x20000) == 4 &&
            std::memcmp(lvd_io + 0x40, "LVD0", 4) == 0,
        "distinct LVD units do not alias their sparse image contents");
  const auto valid_layer = *lvd_layer;
  lvd_layer->path = 1;
  lvd_request->unit = 0;
  Check(native_ioctl(ctl, 0xc0286d00u, lvd_request) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT && lvd_request->unit == 0 &&
            FileSystem::KernelStat("/dev/lvd2", lvd_stat) == KERNEL_ERROR_ENOENT,
        "a malformed layer path preserves output and publishes no LVD namespace");
  *lvd_layer = valid_layer;
  const auto valid_attach = *lvd_request;
  lvd_request->unit = 0x12345678;
  Check(native_ioctl(ctl, 0xc0286d00u, lvd_request) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL && lvd_request->unit == 0x12345678,
        "a rejected attach preserves the caller output field");
  *lvd_request = valid_attach;
  uint64_t ioctl_guard = 0xa5a5a5a5a5a5a5a5ull;
  Check(native_ioctl(ctl, 0xdeadbeefu, &ioctl_guard) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOTTY &&
            ioctl_guard == 0xa5a5a5a5a5a5a5a5ull &&
            native_ioctl(ctl, 0xc0286d00u, static_cast<char*>(memory) + 0x3ff0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT,
        "the production ioctl wrapper returns minus one plus errno without corrupting output");
  auto rnps_nmount = [&](uint32_t flags) {
    auto* rnps_vectors = reinterpret_cast<Iovec*>(static_cast<char*>(memory) + 0x500);
    auto* rnps_strings = static_cast<char*>(memory) + 0x1200;
    const char* rnps_options[] = {"fstype", "ufs", "fspath", "/mnt/rnps", "from", "/dev/lvd0"};
    for (size_t i = 0; i < 6; ++i) {
      const auto length = std::strlen(rnps_options[i]) + 1;
      std::memcpy(rnps_strings, rnps_options[i], length);
      rnps_vectors[i] = {reinterpret_cast<uint64_t>(rnps_strings), length};
      rnps_strings += length;
    }
    Libs::NativeKernelBridge::SyscallRequest rnps_request;
    rnps_request.number = 0x17a;
    rnps_request.args = {reinterpret_cast<uint64_t>(rnps_vectors), 6, flags};
    return Libs::NativeKernelBridge::DispatchSyscall(rnps_request);
  };
  Check(FileSystem::RegisterDiagnosticPartitionPassthrough("/dev/lvd0", host) == OK,
        "register the captured RNPS directory as an explicitly diagnostic compatibility provider");
  const auto unformatted_mount = rnps_nmount(0x10000000u);
  const auto unformatted_wrong_flags = rnps_nmount(0);
  Check(unformatted_mount.value == -1 && unformatted_mount.posix_errno == Libs::Posix::POSIX_EINVAL &&
            unformatted_wrong_flags.value == -1 &&
            unformatted_wrong_flags.posix_errno == Libs::Posix::POSIX_EOPNOTSUPP,
        "native RNPS nmount requires the exact flag and a formatted attached image");
  const uint32_t ufs_magic = 0x19540119u;
  std::memcpy(lvd_io + 0x80, &ufs_magic, sizeof(ufs_magic));
  Check(FileSystem::KernelPwrite(lvd0, lvd_io + 0x80, sizeof(ufs_magic), 0x1055c) == sizeof(ufs_magic),
        "write the observed UFS superblock signature through the LVD device");
  const auto wrong_flags = rnps_nmount(0);
  const auto mounted_rnps = rnps_nmount(0x10000000u);
  Check(wrong_flags.value == -1 && wrong_flags.posix_errno == Libs::Posix::POSIX_EOPNOTSUPP &&
            mounted_rnps.value == 0 && mounted_rnps.posix_errno == 0,
        "only exact native flags publish the formatted compatibility mount");
  std::memset(lvd_request, 0, sizeof(*lvd_request));
  lvd_request->unit = 0;
  Check(native_ioctl(ctl, 0xc0286d01u, lvd_request) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EBUSY,
        "detach rejects a mounted LVD namespace");
  FileSystem::Umount("/mnt/rnps");
  Check(native_ioctl(ctl, 0xc0286d01u, lvd_request) == 0 &&
            FileSystem::KernelStat("/dev/lvd0", lvd_stat) == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelPread(lvd0, lvd_io + 0x40, 4, 0x20000) == 4 &&
            std::memcmp(lvd_io + 0x40, "LVD0", 4) == 0,
        "detach removes its namespace while open descriptors retain backing");
  set_attach("/system_data/nobackup/rnps_apps.img");
  Check(native_ioctl(ctl, 0xc0286d00u, lvd_request) == 0 && lvd_request->unit == 0,
        "detached LVD unit numbers are reused without aliasing live unit one");
  std::memset(lvd_request, 0, sizeof(*lvd_request));
  lvd_request->unit = 0;
  Check(native_ioctl(ctl, 0xc0286d01u, lvd_request) == 0,
        "release the reused first LVD namespace");
  lvd_request->unit = 1;
  Check(native_ioctl(ctl, 0xc0286d01u, lvd_request) == 0 &&
            native_ioctl(ctl, 0xc0286d01u, lvd_request) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOENT &&
            native_close(lvd1) == OK && native_close(lvd0) == OK && native_close(ctl) == OK,
        "detach releases the second namespace and reports a missing repeated detach exactly");
  const int readonly_image = native_open("/system_data/nobackup/rnps_apps.img", 0, 0);
  Check(native_ftruncate(-1, 0x40000000) == KERNEL_ERROR_EBADF &&
            native_fsync(-1) == KERNEL_ERROR_EBADF &&
            readonly_image >= 3 &&
            native_ftruncate(readonly_image, 0x20000000) == KERNEL_ERROR_EBADF &&
            native_ftruncate(readonly_image, -1) == KERNEL_ERROR_EINVAL &&
            native_fsync(readonly_image) == OK && native_close(readonly_image) == OK &&
            native_fsync(readonly_image) == KERNEL_ERROR_EBADF &&
            FileSystem::KernelUnlink("/system_data/nobackup/rnps_apps.img") == OK &&
            FileSystem::KernelUnlink("/system_data/nobackup/rnps_bgs.img") == OK,
        "RNPS native ftruncate/fsync preserve vnode access and descriptor error semantics");
  auto* io = static_cast<char*>(memory) + 0x2000;
  std::memcpy(io, "GUESTg", 6);
  FileSystem::FileStat guest {};
  const int fd = FileSystem::KernelOpen("/system_data/nobackup/temp/b.db", 0x202, 0666);
  Check(FileSystem::KernelMkdir("/system_data/nobackup/other", 0777) == OK &&
            FileSystem::KernelStat("/system_data/nobackup/other", &guest) == OK && guest.st_mode == 0040777u &&
            fd >= 3 && FileSystem::KernelWrite(fd, io, 5) == 5 && FileSystem::KernelPwrite(fd, io + 5, 1, 0) == 1 &&
            FileSystem::KernelLseek(fd, 0, 0) == 0 && FileSystem::KernelRead(fd, io + 8, 5) == 5 &&
            std::memcmp(io + 8, "gUEST", 5) == 0 && FileSystem::KernelFtruncate(fd, 3) == OK &&
            FileSystem::KernelFstat(fd, &guest) == OK && guest.st_size == 3 && guest.st_mode == 0100666u,
        "guest mkdir, create, write, pwrite, read and ftruncate reach the upper store with a zero creation mask");
  auto* writable_statfs = reinterpret_cast<FileSystem::KernelStatfs*>(static_cast<char*>(memory) + 0x3000);
  std::memset(writable_statfs, 0xa5, sizeof(*writable_statfs));
  Check(FileSystem::KernelFstatfs(fd, writable_statfs) == OK && writable_statfs->f_flags == 0 &&
            std::strcmp(writable_statfs->f_fstypename, "exfatfs") == 0 &&
            std::strcmp(writable_statfs->f_mntfromname, "/dev/ssd0.system_data") == 0 &&
            std::strcmp(writable_statfs->f_mntonname, "/system_data") == 0 &&
            FileSystem::KernelClose(fd) == OK,
        "writable upper descriptor reports the authenticated guest filesystem identity without readonly flags");
  Check(FileSystem::KernelRename("/system_data/nobackup/temp/b.db", "/system_data/nobackup/c.db") == OK &&
            FileSystem::KernelStat("/system_data/nobackup/c.db", &guest) == OK && guest.st_size == 3 &&
            FileSystem::KernelUnlink("/system_data/nobackup/c.db") == OK &&
            FileSystem::KernelRmdir("/system_data/nobackup/other") == OK &&
            FileSystem::KernelStat("/system_data/nobackup/other", &guest) == KERNEL_ERROR_ENOENT,
        "guest rename, unlink and rmdir reach the upper store");
  FileSystem::Umount("/system_data");
  FileSystem::Umount("/");
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), 0x4000) == OK &&
            _putenv_s("KYTY_DIAGNOSTIC_FSCK_PARTITION_PASSTHROUGH", saved_passthrough.c_str()) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_PASSTHROUGH_UPPER", saved_upper.c_str()) == 0,
        "restore the upper store selection");
  std::vector<std::string> host_files;
  for (const auto& item: std::filesystem::recursive_directory_iterator(host))
    host_files.push_back(item.path().lexically_relative(host).generic_string());
  std::sort(host_files.begin(), host_files.end());
  std::array<char, 9> original {};
  { std::ifstream input(host / "nobackup" / "temp" / "old.db", std::ios::binary); input.read(original.data(), original.size());
    Check(input.gcount() == 8 && std::memcmp(original.data(), lower, 8) == 0 &&
              host_files == std::vector<std::string> {"nobackup", "nobackup/temp", "nobackup/temp/old.db", "priv", "priv/large.bin"},
          "the captured mirror is never written"); }
  std::vector<uint8_t> large_after(large.size());
  { std::ifstream input(host / "priv" / "large.bin", std::ios::binary);
    input.read(reinterpret_cast<char*>(large_after.data()), static_cast<std::streamsize>(large_after.size()));
    Check(input.gcount() == static_cast<std::streamsize>(large_after.size()) && input.peek() == EOF &&
              large_after == large, "the multi-chunk captured mirror remains byte-exact after copy-up"); }
  CapturedDirectory::Clear();
  std::printf("KernelFileSystemTests: passthrough upper store cases passed\n");
}

void CheckFactoryStorageView(const std::filesystem::path& root) {
  using namespace Libs::LibKernel;
  namespace Mount = DirectoryPassthrough;
  const auto storage = root / "factory-storage-capture";
  const auto host = storage / "files";
  const auto upper = root / "factory-storage-upper";
  Check(std::filesystem::create_directories(host / "priv" / "home" / "16f326cf") &&
            std::filesystem::create_directories(host / "priv" / "home" / "000000ff") &&
            std::filesystem::create_directories(host / "priv" / "mms") && std::filesystem::create_directory(upper),
        "create configured-user capture and empty factory upper");
  auto node = [](std::string path, unsigned inode, unsigned mode, unsigned size) {
    return nlohmann::json {{"path", path}, {"inode", inode}, {"mode", mode}, {"size", size}, {"uid", 0u}, {"gid", 5u},
        {"mtime", 315532800}, {"type", (mode & 0170000u) >> 12}, {"metadata", true}, {"complete", true}};
  };
  auto entries = nlohmann::json::array({node("/", 800u, 0040755u, 512u), node("/priv", 801u, 0040755u, 512u),
      node("/priv/home", 802u, 0040755u, 512u), node("/priv/home/16f326cf", 803u, 0040700u, 512u),
      node("/priv/home/000000ff", 804u, 0040700u, 512u), node("/priv/mms", 805u, 0040755u, 512u)});
  unsigned inode = 806;
  const auto add_file = [&](const std::string& guest, const std::filesystem::path& relative, std::string_view bytes) {
    const auto file_path = host / relative;
    { std::ofstream output(file_path, std::ios::binary); output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
      Check(output.good(), "write configured-user capture file"); }
    auto file = node(guest, inode++, 0100600u, static_cast<unsigned>(bytes.size()));
    file["complete"] = false;
    file["file"] = "files/" + relative.generic_string();
    file["sha256"] = AuthInfo::DigestHex(AuthInfo::Sha256(bytes.data(), bytes.size()));
    entries.push_back(std::move(file));
  };
  add_file("/priv/home/user_list.dat", "priv/home/user_list.dat", "CAPTURED-LIST");
  add_file("/priv/home/16f326cf/config.dat", "priv/home/16f326cf/config.dat", "CAPTURED-USER");
  add_file("/priv/home/000000ff/system.dat", "priv/home/000000ff/system.dat", "SYSTEM");
  add_file("/priv/mms/av_content.db", "priv/mms/av_content.db", "CAPTURED-AV");
  add_file("/priv/mms/notification2.db", "priv/mms/notification2.db", "CAPTURED-NOTIFY");
  add_file("/priv/mms/app.db", "priv/mms/app.db", "PRESERVED-APP");
  const auto volume = nlohmann::json {{"point", "/system_data"}, {"host_root", Common::PathToString(host)},
      {"case_sensitive", true}, {"entries", entries}};
  const auto manifest = nlohmann::json {{"version", 1}, {"storage", Common::PathToString(storage)},
      {"volumes", nlohmann::json::array({volume})}};
  const auto digest = SaveCapturedDirectoryManifest(storage / "manifest.json", manifest);
  CapturedDirectory::Clear();
  Check(CapturedDirectory::Load(storage / "manifest.json", digest) == OK, "load configured-user capture metadata");
  const char* selected_upper = std::getenv("KYTY_DIAGNOSTIC_PASSTHROUGH_UPPER");
  const char* selected_factory = std::getenv("KYTY_DIAGNOSTIC_FACTORY_STORAGE_VIEW");
  const char* selected_registry = std::getenv("KYTY_DIAGNOSTIC_REGMGR_SESSION_STORE");
  const std::string saved_upper = selected_upper ? selected_upper : "";
  const std::string saved_factory = selected_factory ? selected_factory : "";
  const std::string saved_registry = selected_registry ? selected_registry : "";
  Mount::NodeStat stat {};
  Check(_putenv_s("KYTY_DIAGNOSTIC_PASSTHROUGH_UPPER", Common::PathToString(upper).c_str()) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_FACTORY_STORAGE_VIEW", "1") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_REGMGR_SESSION_STORE", "") == 0 && Mount::Mount("/system_data", host, true) == OK &&
            Mount::Stat("/system_data/priv/home/user_list.dat", &stat) == OK && Mount::Unmount("/system_data") == OK,
        "factory storage view rejects a hybrid process-local registry configuration");
  Check(_putenv_s("KYTY_DIAGNOSTIC_REGMGR_SESSION_STORE", "1") == 0 && Mount::Mount("/system_data", host, true) == OK,
        "attach coherent factory registry and storage views");
  const auto names = [&](const char* path) {
    std::shared_ptr<Mount::Handle> directory;
    std::vector<Mount::DirectoryEntry> listed;
    Check(Mount::Open(path, 0x20000, &directory) == OK && Mount::Entries(directory, &listed) == OK &&
              Mount::Close(directory) == OK, "list factory-view directory");
    std::vector<std::string> result;
    for (const auto& entry: listed) result.push_back(entry.name);
    std::sort(result.begin(), result.end());
    return result;
  };
  Check(Mount::Stat("/system_data/priv/home/user_list.dat", &stat) == KERNEL_ERROR_ENOENT &&
            Mount::Stat("/system_data/priv/home/16f326cf/config.dat", &stat) == KERNEL_ERROR_ENOENT &&
            Mount::Stat("/system_data/priv/mms/av_content.db", &stat) == OK && stat.size == 11 &&
            Mount::Stat("/system_data/priv/mms/notification2.db", &stat) == KERNEL_ERROR_ENOENT &&
            Mount::Stat("/system_data/priv/home/000000ff/system.dat", &stat) == OK &&
            Mount::Stat("/system_data/priv/mms/app.db", &stat) == OK &&
            names("/system_data/priv/home") == std::vector<std::string> {"000000ff"} &&
            names("/system_data/priv/mms") == std::vector<std::string> {"app.db", "av_content.db"},
        "factory view hides captured account state while preserving system and catalog state");
  std::shared_ptr<Mount::Handle> list, config, notification;
  Check(Mount::Open("/system_data/priv/home/user_list.dat", 0x202, &list, 0600) == OK && Mount::Write(list, "NEW-LIST", 8) == 8 &&
            Mount::Mkdir("/system_data/priv/home/16f326cf", 0700) == OK &&
            Mount::Open("/system_data/priv/home/16f326cf/config.dat", 0x202, &config, 0600) == OK &&
            Mount::Write(config, "NEW-USER", 8) == 8 &&
            Mount::Open("/system_data/priv/mms/notification2.db", 0x202, &notification, 0600) == OK &&
            Mount::Write(notification, "NEW-NOTIFY", 10) == 10 && Mount::Close(list) == OK && Mount::Close(config) == OK &&
            Mount::Close(notification) == OK &&
            Mount::Stat("/system_data/priv/home/user_list.dat", &stat) == OK && stat.size == 8 &&
            Mount::Unlink("/system_data/priv/mms/notification2.db") == OK &&
            Mount::Stat("/system_data/priv/mms/notification2.db", &stat) == KERNEL_ERROR_ENOENT,
        "guest-created upper state is visible and deleting it never reveals the hidden capture");
  Check(Mount::Unmount("/system_data") == OK && Mount::Mount("/system_data", host, true) == OK &&
            Mount::Stat("/system_data/priv/home/user_list.dat", &stat) == OK && stat.size == 8 &&
            Mount::Stat("/system_data/priv/home/16f326cf/config.dat", &stat) == OK && stat.size == 8 &&
            Mount::Stat("/system_data/priv/mms/av_content.db", &stat) == OK && stat.size == 11 &&
            Mount::Stat("/system_data/priv/mms/notification2.db", &stat) == KERNEL_ERROR_ENOENT &&
            names("/system_data/priv/home") == std::vector<std::string> {"000000ff", "16f326cf", "user_list.dat"} &&
            names("/system_data/priv/mms") == std::vector<std::string> {"app.db", "av_content.db"} &&
            Mount::Unmount("/system_data") == OK,
        "factory upper state and whiteouts survive another imported-view mount");
  Check(_putenv_s("KYTY_DIAGNOSTIC_PASSTHROUGH_UPPER", saved_upper.c_str()) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_FACTORY_STORAGE_VIEW", saved_factory.c_str()) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_REGMGR_SESSION_STORE", saved_registry.c_str()) == 0,
        "restore factory storage environment");
  std::array<char, 16> original {};
  { std::ifstream input(host / "priv" / "home" / "user_list.dat", std::ios::binary); input.read(original.data(), original.size());
    Check(input.gcount() == 13 && std::memcmp(original.data(), "CAPTURED-LIST", 13) == 0,
          "factory view leaves the captured user list byte-exact"); }
  { std::ifstream input(host / "priv" / "mms" / "av_content.db", std::ios::binary); input.read(original.data(), original.size());
    Check(input.gcount() == 11 && std::memcmp(original.data(), "CAPTURED-AV", 11) == 0,
          "factory view leaves the captured AV catalog byte-exact"); }
  CapturedDirectory::Clear();
  std::printf("KernelFileSystemTests: factory storage view cases passed\n");
}
