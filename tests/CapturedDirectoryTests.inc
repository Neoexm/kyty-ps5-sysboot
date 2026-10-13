std::string SaveCapturedDirectoryManifest(const std::filesystem::path& path, const nlohmann::json& value) {
  const auto bytes = value.dump();
  std::ofstream output(path, std::ios::binary);
  output.write(bytes.data(), bytes.size());
  output.close();
  Check(output.good(), "save disposable captured directory manifest");
  return Libs::LibKernel::AuthInfo::DigestHex(Libs::LibKernel::AuthInfo::Sha256(bytes.data(), bytes.size()));
}

void CheckCapturedDirectory(const std::filesystem::path& root) {
  using namespace Libs::LibKernel;
  namespace Mount = DirectoryPassthrough;
  const auto storage = root / "captured-directory";
  const auto host = storage / "files";
  Check(std::filesystem::create_directories(host), "create captured directory fixture storage");
  constexpr char contents[] = "captured fixture bytes";
  const auto put = [&](const char* name, const char* bytes, size_t size) {
    std::ofstream output(host / name, std::ios::binary);
    output.write(bytes, size);
    Check(output.good(), "write disposable captured fixture bytes");
  };
  put("Movie.Bin", contents, sizeof(contents));
  put("host-only", contents, sizeof(contents));
  const auto node = [](std::string path, unsigned inode, unsigned mode, unsigned size, bool complete) {
    return nlohmann::json {{"path", path}, {"inode", inode}, {"mode", mode}, {"size", size},
        {"uid", 17u}, {"gid", 18u}, {"mtime", 315532800}, {"type", (mode & 0170000u) >> 12},
        {"metadata", true}, {"complete", complete}};
  };
  auto file = node("/Movie.Bin", 4026532774u, 0100640u, sizeof(contents), false);
  file["file"] = "files/Movie.Bin";
  file["sha256"] = AuthInfo::DigestHex(AuthInfo::Sha256(contents, sizeof(contents)));
  auto uppercase_digest = file["sha256"].get<std::string>();
  for (auto& ch: uppercase_digest) if (ch >= 'a' && ch <= 'f') ch -= 'a' - 'A';
  file["sha256"] = uppercase_digest;
  nlohmann::json entries = nlohmann::json::array({node("/", 394u, 0040750u, 65536u, true), file,
      node("/Empty", 395u, 0040755u, 512u, true), node("/Omitted", 396u, 0040755u, 512u, false),
      node("/Unavailable", 397u, 0100600u, 9u, false), node("/Link", 398u, 0120777u, 7u, false)});
  entries.push_back({{"path", "/KnownLibs"}, {"type", 4u}, {"metadata", false}, {"complete", true}});
  entries.push_back({{"path", "/UnknownLibs"}, {"type", 4u}, {"metadata", false}, {"complete", false}});
  auto nested_file = file;
  nested_file["path"] = "/KnownLibs/Movie.Bin";
  entries.push_back(nested_file);
  const auto volume = nlohmann::json {{"point", "/capture-fixture"}, {"host_root", Common::PathToString(host)},
      {"case_sensitive", false}, {"entries", entries}};
  auto manifest = nlohmann::json {{"version", 1}, {"storage", Common::PathToString(storage)},
      {"volumes", nlohmann::json::array({volume})}};
  const auto path = storage / "manifest.json";
  auto digest = SaveCapturedDirectoryManifest(path, manifest);
  Check(CapturedDirectory::Load(path, std::string(64, '0')) == KERNEL_ERROR_EINVAL,
        "reject a capture manifest whose complete hash is wrong");
  for (int kind = 0; kind < 4; ++kind) {
    auto malformed = manifest;
    if (kind == 0) malformed["volumes"][0]["entries"][1]["inode"] = -1;
    if (kind == 1) malformed["volumes"][0]["entries"].push_back(file);
    if (kind == 2) malformed["volumes"][0]["entries"][1]["path"] = "/missing/child";
    if (kind == 3) malformed["volumes"][0]["entries"][1]["file"] = "../../outside";
    const auto bad_digest = SaveCapturedDirectoryManifest(path, malformed);
    Check(CapturedDirectory::Load(path, bad_digest) == KERNEL_ERROR_EINVAL &&
              !CapturedDirectory::ForRoot(std::filesystem::canonical(host)),
          "invalid capture metadata never publishes a partial volume");
  }
  digest = SaveCapturedDirectoryManifest(path, manifest);
  Check(CapturedDirectory::Load(path, digest) == OK && Mount::Mount("/capture-fixture", host) == OK,
        "mount verified captured metadata and bytes");
  FileSystem::FileStat stat {};
  Check(FileSystem::KernelStat("/capture-fixture/movie.bin", &stat) == OK &&
            stat.st_ino == 4026532774u && stat.st_mode == 0100640u && stat.st_size == sizeof(contents) &&
            stat.st_uid == 17 && stat.st_gid == 18 && stat.st_mtim.tv_sec == 315532800,
        "guest stat preserves observed inode, mode, owners, size and timestamp");
  Check(FileSystem::KernelOpen("/capture-fixture/KnownLibs/Missing.sprx", 0, 0) == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelStat("/capture-fixture/KnownLibs/Movie.Bin", &stat) == OK &&
            stat.st_ino == 4026532774u && stat.st_size == sizeof(contents),
        "captured child names remain authoritative without parent stat metadata");
  const int nested = FileSystem::KernelOpen("/capture-fixture/KnownLibs/Movie.Bin", 0, 0);
  std::array<char, sizeof(contents)> nested_bytes {};
  Check(nested >= 3 && FileSystem::KernelRead(nested, nested_bytes.data(), nested_bytes.size()) == nested_bytes.size() &&
            std::memcmp(nested_bytes.data(), contents, nested_bytes.size()) == 0 && FileSystem::KernelClose(nested) == OK &&
            FileSystem::KernelOpen("/capture-fixture/UnknownLibs/Missing.sprx", 0, 0) == KERNEL_ERROR_EIO,
        "traversal reads only verified child bytes and preserves incomplete directory uncertainty");
  stat.st_ino = 0x12345678;
  Check(FileSystem::KernelStat("/capture-fixture/KnownLibs", &stat) == KERNEL_ERROR_EIO &&
            stat.st_ino == 0x12345678 &&
            FileSystem::KernelOpen("/capture-fixture/KnownLibs", 0x20000, 0) == KERNEL_ERROR_EIO,
        "a complete name listing does not supply missing directory stat fields");
  Check(FileSystem::KernelStat("/capture-fixture/host-only", &stat) == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelStat("/capture-fixture/Omitted/unknown", &stat) == KERNEL_ERROR_EIO &&
            FileSystem::KernelStat("/capture-fixture/Link", &stat) == KERNEL_ERROR_EIO &&
            FileSystem::KernelStat("/capture-fixture/missing/../movie.bin", &stat) == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelStat("/capture-fixture/Movie.Bin/../../", &stat) == KERNEL_ERROR_ENOTDIR,
        "host extras, uncaptured directories, unresolved symlinks and raw traversal keep their distinctions");
  Check(Mount::Mount("/outside-capture", root) == OK &&
            FileSystem::KernelStat("/capture-fixture/Movie.Bin/../../outside-capture", &stat) == KERNEL_ERROR_ENOTDIR &&
            Mount::Unmount("/outside-capture") == OK,
        "captured traversal still checks a file ancestor when normalization enters a plain provider");
  const int fd = FileSystem::KernelOpen("/capture-fixture/Movie.Bin", 0, 0);
  std::array<char, sizeof(contents)> bytes {};
  Check(fd >= 3 && FileSystem::KernelPread(fd, bytes.data(), bytes.size(), 0) == bytes.size() &&
            std::memcmp(bytes.data(), contents, bytes.size()) == 0 &&
            FileSystem::KernelFstat(fd, &stat) == OK && stat.st_ino == 4026532774u &&
            FileSystem::KernelOpen("/capture-fixture/Movie.Bin", 2, 0) == KERNEL_ERROR_EROFS &&
            FileSystem::KernelOpen("/capture-fixture/Unavailable", 0, 0) == KERNEL_ERROR_EIO,
        "guest reads pinned bytes while writes and uncaptured file contents remain unavailable");
  std::shared_ptr<Mount::Handle> directory;
  std::vector<Mount::DirectoryEntry> children;
  Check(Mount::Open("/capture-fixture", 0, &directory) == OK && Mount::Entries(directory, &children) == OK &&
            children.size() == 7 && std::any_of(children.begin(), children.end(), [](const auto& child) {
              return child.name == "Movie.Bin" && child.inode == 4026532774u && child.type == 8;
            }), "complete captured listing preserves original casing and hides unrelated host files");
  directory.reset();
  Check(Mount::Open("/capture-fixture/Empty", 0, &directory) == OK && Mount::Entries(directory, &children) == OK &&
            children.empty(), "a captured empty directory needs no host directory");
  directory.reset();
  Check(Mount::Open("/capture-fixture/Omitted", 0, &directory) == OK &&
            Mount::Entries(directory, &children) == KERNEL_ERROR_EIO, "excluded content is not an empty directory");
}

void CheckCapturedDirectoryFallback(const std::filesystem::path& root) {
  using namespace Libs::LibKernel;
  namespace Mount = DirectoryPassthrough;
  const auto storage = root / "captured-directory-fallback";
  const auto captured = storage / "files" / "system";
  const auto primary = root / "decrypted-system-primary";
  const auto outside = root / "captured-fallback-outside";
  Check(std::filesystem::create_directories(captured / "priv" / "resource_arbitrator_ro") &&
            std::filesystem::create_directories(
                captured / "priv" / "resource_arbitrator_ro" / "block") &&
            std::filesystem::create_directories(
                captured / "priv" / "resource_arbitrator_ro" / "escape") &&
            std::filesystem::create_directories(
                primary / "priv" / "resource_arbitrator_ro") &&
            std::filesystem::create_directories(captured / "priv" / "psnow_ro") &&
            std::filesystem::create_directories(captured / "priv" / "unadmitted") &&
            std::filesystem::create_directories(captured / "sys") &&
            std::filesystem::create_directories(primary / "sys") &&
            std::filesystem::create_directories(outside),
        "create isolated primary and captured fallback trees");
  const std::string configuration = "{\"version\":1267,\"source\":\"captured\"}";
  const std::string captured_collision = "captured-original";
  const std::string primary_collision = "decrypted-primary";
  const std::string blocked_child = "must-not-bypass-primary-file";
  const std::string escaped_child = "must-not-bypass-primary-junction";
  const auto put = [](const std::filesystem::path& path, const std::string& bytes) {
    std::ofstream output(path, std::ios::binary);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    Check(output.good(), "write captured fallback fixture bytes");
  };
  put(captured / "priv" / "resource_arbitrator_ro" / "ra-config.json", configuration);
  put(captured / "priv" / "resource_arbitrator_ro" / "collision.sprx",
      captured_collision);
  put(captured / "priv" / "resource_arbitrator_ro" / "block" / "child",
      blocked_child);
  put(captured / "priv" / "resource_arbitrator_ro" / "escape" / "missing.json",
      escaped_child);
  put(primary / "priv" / "resource_arbitrator_ro" / "collision.sprx",
      primary_collision);
  put(primary / "priv" / "resource_arbitrator_ro" / "block", "primary-file");
  const std::string envelope = "PSNOW_ENVELOPE=captured";
  const std::string prefetch = "prefetch-list";
  put(captured / "priv" / "psnow_ro" / "psnow-config.env", envelope);
  put(captured / "priv" / "unadmitted" / "hidden.env", "not-admitted");
  put(captured / "sys" / "vsh_prefetch_list.dat", prefetch);
  put(captured / "sys" / "other.dat", "not-admitted");
#if defined(_WIN32)
  const auto escape = primary / "priv" / "resource_arbitrator_ro" / "escape";
  CreateInitialDirectoryJunction(escape, outside);
#endif
  const auto node = [](std::string path, unsigned inode, unsigned mode, unsigned size,
                       bool complete) {
    return nlohmann::json {{"path", path}, {"inode", inode}, {"mode", mode},
        {"size", size}, {"uid", 0u}, {"gid", 0u}, {"mtime", 315532800},
        {"type", (mode & 0170000u) >> 12}, {"metadata", true},
        {"complete", complete}};
  };
  const auto file = [&](std::string path, std::string relative, unsigned inode,
                        const std::string& bytes) {
    auto value = node(std::move(path), inode, 0100777u,
                      static_cast<unsigned>(bytes.size()), false);
    value["file"] = std::move(relative);
    value["sha256"] = AuthInfo::DigestHex(AuthInfo::Sha256(bytes.data(), bytes.size()));
    return value;
  };
  nlohmann::json entries = nlohmann::json::array({
      node("/", 100u, 0040777u, 65536u, true),
      node("/priv", 101u, 0040777u, 65536u, true),
      node("/priv/resource_arbitrator_ro", 102u, 0040777u, 65536u, true),
      file("/priv/resource_arbitrator_ro/ra-config.json",
           "files/system/priv/resource_arbitrator_ro/ra-config.json", 103u,
           configuration),
      file("/priv/resource_arbitrator_ro/collision.sprx",
           "files/system/priv/resource_arbitrator_ro/collision.sprx", 104u,
           captured_collision),
      node("/priv/resource_arbitrator_ro/block", 105u, 0040777u, 65536u, true),
      file("/priv/resource_arbitrator_ro/block/child",
           "files/system/priv/resource_arbitrator_ro/block/child", 106u,
           blocked_child),
      node("/priv/resource_arbitrator_ro/escape", 107u, 0040777u, 65536u, true),
      file("/priv/resource_arbitrator_ro/escape/missing.json",
           "files/system/priv/resource_arbitrator_ro/escape/missing.json", 108u,
           escaped_child),
      node("/priv/psnow_ro", 109u, 0040777u, 65536u, true),
      file("/priv/psnow_ro/psnow-config.env", "files/system/priv/psnow_ro/psnow-config.env",
           110u, envelope),
      node("/priv/unadmitted", 111u, 0040777u, 65536u, true),
      file("/priv/unadmitted/hidden.env", "files/system/priv/unadmitted/hidden.env", 112u,
           "not-admitted"),
      node("/sys", 113u, 0040777u, 65536u, true),
      file("/sys/vsh_prefetch_list.dat", "files/system/sys/vsh_prefetch_list.dat", 114u,
           prefetch),
      file("/sys/other.dat", "files/system/sys/other.dat", 115u, "not-admitted")});
  const auto volume = nlohmann::json {{"point", "/system"},
      {"host_root", Common::PathToString(captured)}, {"case_sensitive", true},
      {"entries", entries}};
  const auto manifest = nlohmann::json {{"version", 1},
      {"storage", Common::PathToString(storage)},
      {"volumes", nlohmann::json::array({volume})}};
  const auto path = storage / "manifest.json";
  const auto digest = SaveCapturedDirectoryManifest(path, manifest);
  Check(CapturedDirectory::Load(path, digest) == OK &&
            Mount::Mount("/system", primary) == OK &&
            Mount::AttachCapturedFallback(
                "/system", "/priv/resource_arbitrator_ro", digest) == OK,
        "mount decrypted primary with manifest-verified captured fallback");
  Check(Mount::AttachCapturedFallback("/system", "/priv/psnow_ro", digest) == OK &&
            Mount::AttachCapturedFallback("/system", "/sys/vsh_prefetch_list.dat", digest) == OK &&
            Mount::AttachCapturedFallback("/system", "/priv/psnow_ro/psnow-config.env", digest) ==
                KERNEL_ERROR_EBUSY &&
            Mount::AttachCapturedFallback("/system", "/priv", digest) == KERNEL_ERROR_EBUSY &&
            Mount::AttachCapturedFallback("/system", "/priv/absent", digest) == KERNEL_ERROR_ENOENT &&
            Mount::AttachCapturedFallback("/system", "/", digest) == KERNEL_ERROR_EINVAL &&
            Mount::AttachCapturedFallback("/system", "/priv/unadmitted", std::string(64, '0')) ==
                KERNEL_ERROR_EINVAL,
        "further fallback prefixes are exact, disjoint and bound to the same manifest");
  Mount::MountInfo exported;
  FileSystem::FileStat relative {}, absolute {}, dotted {}, parented {};
  Check(Mount::DescribeMount("/system", &exported) == OK &&
            exported.host_root == primary && exported.manifest_sha256.empty() &&
            exported.fallback_prefixes == std::vector<std::string> {"/priv/resource_arbitrator_ro",
                "/priv/psnow_ro", "/sys/vsh_prefetch_list.dat"} &&
            exported.fallback_manifest_sha256 == digest &&
            FileSystem::KernelStat(
                "system/priv/resource_arbitrator_ro/ra-config.json", &relative) == OK &&
            FileSystem::KernelStat(
                "/system/priv/resource_arbitrator_ro/ra-config.json", &absolute) == OK &&
            FileSystem::KernelStat(
                "./system/priv/resource_arbitrator_ro/ra-config.json", &dotted) == OK &&
            FileSystem::KernelStat(
                "../system/priv/resource_arbitrator_ro/ra-config.json", &parented) == OK &&
            relative.st_dev == absolute.st_dev && relative.st_ino == 103u &&
            dotted.st_ino == relative.st_ino && parented.st_ino == relative.st_ino &&
            relative.st_size == configuration.size(),
        "relative ResourceArbitrator stat reaches the pinned captured lower file");
  std::array<char, 64> bytes {};
  const int config = FileSystem::KernelOpen(
      "system/priv/resource_arbitrator_ro/ra-config.json", 0, 0);
  Check(config >= 3 &&
            FileSystem::KernelPread(config, bytes.data(), configuration.size(), 0) ==
                static_cast<int64_t>(configuration.size()) &&
            std::memcmp(bytes.data(), configuration.data(), configuration.size()) == 0 &&
            FileSystem::KernelFstat(config, &relative) == OK && relative.st_ino == 103u &&
            FileSystem::KernelClose(config) == OK,
        "relative ResourceArbitrator open reads exact verified lower bytes");
  bytes.fill(0);
  const int collision = FileSystem::KernelOpen(
      "/system/priv/resource_arbitrator_ro/collision.sprx", 0, 0);
  Check(collision >= 3 &&
            FileSystem::KernelPread(collision, bytes.data(), primary_collision.size(), 0) ==
                static_cast<int64_t>(primary_collision.size()) &&
            std::memcmp(bytes.data(), primary_collision.data(), primary_collision.size()) == 0 &&
            FileSystem::KernelFstat(collision, &relative) == OK &&
            relative.st_size == primary_collision.size() &&
            FileSystem::KernelClose(collision) == OK,
        "decrypted primary bytes win captured-name collisions");
  std::string overlong(1100, 'a');
  Check(FileSystem::KernelOpen(
            "/system/priv/resource_arbitrator_ro/block/child", 0, 0) ==
                KERNEL_ERROR_ENOTDIR &&
            FileSystem::KernelOpen("system/priv/resource_arbitrator_ro/missing.json", 0, 0) ==
                KERNEL_ERROR_ENOENT &&
            FileSystem::KernelOpen("system/priv/resource_arbitrator_ro/ra-config.json", 2, 0) ==
                KERNEL_ERROR_EROFS &&
            FileSystem::KernelStat(("system/" + overlong).c_str(), &relative) ==
                KERNEL_ERROR_ENAMETOOLONG &&
            FileSystem::KernelStat("", &relative) == KERNEL_ERROR_ENOENT &&
            FileSystem::KernelOpen("system\\priv\\resource_arbitrator_ro\\ra-config.json", 0, 0) ==
                KERNEL_ERROR_EINVAL,
        "fallback preserves primary conflicts, absence, read-only flags and path bounds");
  bytes.fill(0);
  const int envelope_fd = FileSystem::KernelOpen("/system/priv/psnow_ro/psnow-config.env", 0, 0);
  Check(envelope_fd >= 3 &&
            FileSystem::KernelPread(envelope_fd, bytes.data(), envelope.size(), 0) ==
                static_cast<int64_t>(envelope.size()) &&
            std::memcmp(bytes.data(), envelope.data(), envelope.size()) == 0 &&
            FileSystem::KernelClose(envelope_fd) == OK &&
            FileSystem::KernelStat("/system/sys/vsh_prefetch_list.dat", &relative) == OK &&
            relative.st_ino == 114u && relative.st_size == prefetch.size() &&
            FileSystem::KernelStat("/system/priv/unadmitted/hidden.env", &relative) ==
                KERNEL_ERROR_ENOENT &&
            FileSystem::KernelStat("/system/sys/other.dat", &relative) == KERNEL_ERROR_ENOENT,
        "directory and single-file prefixes serve captured bytes while unadmitted captured paths stay absent");
  {
    std::shared_ptr<Mount::Handle> directory;
    std::vector<Mount::DirectoryEntry> children;
    const auto names = [&]() {
      std::vector<std::string> output;
      for (const auto& child: children) output.push_back(child.name);
      std::sort(output.begin(), output.end());
      return output;
    };
    Check(Mount::Open("/system/priv", 0, &directory) == OK &&
              Mount::Entries(directory, &children) == OK &&
              names() == std::vector<std::string> {"psnow_ro", "resource_arbitrator_ro"} &&
              std::count_if(children.begin(), children.end(), [](const auto& child) {
                return child.name == "psnow_ro" && child.inode == 109u && child.directory;
              }) == 1,
          "primary listing adds admitted captured children once and hides unadmitted ones");
    directory.reset();
    Check(Mount::Open("/system/sys", 0, &directory) == OK &&
              Mount::Entries(directory, &children) == OK &&
              names() == std::vector<std::string> {"vsh_prefetch_list.dat"},
          "single-file prefix lists only that captured file beside the primary");
  }
#if defined(_WIN32)
  Check(FileSystem::KernelOpen(
            "/system/priv/resource_arbitrator_ro/escape/missing.json", 0, 0) ==
                KERNEL_ERROR_ENOENT &&
            RemoveDirectoryW(escape.c_str()) != FALSE,
        "out-of-root junction miss never reaches the captured fallback");
#endif
  auto tampered = configuration;
}

void AuditResourceArbitratorCapture(const std::filesystem::path& primary,
                                    const std::filesystem::path& manifest,
                                    const std::string& digest) {
  using namespace Libs::LibKernel;
  namespace Mount = DirectoryPassthrough;
  constexpr std::string_view expected_manifest =
      "a45253eea9da61dc2b3c7bfd50905aa64995646fcee782cc680517879be612b0";
  constexpr std::string_view expected_file =
      "d9479085076615484a2a443b7b1ee6725a9f7701225696a63581a636b328c71a";
  constexpr std::string_view expected_primary =
      "d1eb1fe2cdedc8eca69399a79b9c5fe44c78f12c055728515acd6f5f74272a45";
  Check(digest == expected_manifest, "pin the exact retained captured-storage manifest");
  FileSystem::MountReadOnly(primary.parent_path(), "/");
  FileSystem::FileStat pre_mount {};
  Check(FileSystem::KernelStat("/system", &pre_mount) == OK &&
            (pre_mount.st_mode & 0170000u) == 0040000u,
        "decrypted root exposes the system mount point");
  Check(FileSystem::RegisterDiagnosticPartitionPassthrough(
            "/dev/ssd0.system", primary) == OK,
        "register the exact decrypted system provider root");
  TempDirectory rejected;
  const auto rejected_storage = rejected.Path() / "capture";
  const auto rejected_root = rejected_storage / "files" / "system";
  Check(std::filesystem::create_directories(rejected_root),
        "create isolated rejected system capture root");
  const auto directory = [](std::string path, unsigned inode, bool complete) {
    return nlohmann::json {{"path", path}, {"inode", inode}, {"mode", 0040777u},
        {"size", 65536u}, {"uid", 0u}, {"gid", 0u}, {"mtime", 315532800},
        {"type", 4u}, {"metadata", true}, {"complete", complete}};
  };
  const auto rejected_volume = nlohmann::json {{"point", "/system"},
      {"host_root", Common::PathToString(rejected_root)}, {"case_sensitive", true},
      {"entries", nlohmann::json::array({directory("/", 1u, true),
          directory("/priv", 2u, true),
          directory("/priv/resource_arbitrator_ro", 3u, true)})}};
  const auto rejected_manifest = nlohmann::json {{"version", 1},
      {"storage", Common::PathToString(rejected_storage)},
      {"volumes", nlohmann::json::array({rejected_volume})}};
  const auto rejected_path = rejected_storage / "manifest.json";
  const auto rejected_digest = SaveCapturedDirectoryManifest(
      rejected_path, rejected_manifest);
}

void AuditCapturedStorage(const std::filesystem::path& manifest, const std::string& digest) {
  using namespace Libs::LibKernel;
  namespace Mount = DirectoryPassthrough;
  Check(CapturedDirectory::Load(manifest, digest) == OK, "load the capture manifest");
  const char* passthrough = std::getenv("KYTY_DIAGNOSTIC_FSCK_PARTITION_PASSTHROUGH");
  const std::string saved_passthrough = passthrough ? passthrough : "";
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_FSCK_PARTITION_PASSTHROUGH", "1") == 0,
#else
  Check(setenv("KYTY_DIAGNOSTIC_FSCK_PARTITION_PASSTHROUGH", "1", 1) == 0,
#endif
        "select captured filesystem compatibility mounts for the bounded audit");
  const auto value = nlohmann::json::parse(std::ifstream(manifest));
  void* memory = nullptr;
  Check(Memory::KernelMapNamedFlexibleMemory(&memory, 0x8000, 3, 0, "capture-audit") == OK,
        "map guest mount vectors and file I/O buffer");
  struct Iovec { uint64_t address, length; };
  auto* vectors = static_cast<Iovec*>(memory);
  for (const auto& volume: value.at("volumes")) {
    const auto point = volume.at("point").get<std::string>();
    if (point != "/preinst" && point != "/system_data" && point != "/mnt/rnps") continue;
    const auto device = point == "/preinst" ? "/dev/ssd0.preinst" : point == "/mnt/rnps" ? "/dev/lvd0" : "/dev/ssd0.system_data";
    Check(FileSystem::RegisterDiagnosticPartitionPassthrough(device, Common::PathFromUtf8(volume.at("host_root").get<std::string>())) == OK,
          "register a captured filesystem tree");
    std::vector<std::string> options {"fstype", point == "/preinst" ? "exfatfs" : "ufs", "fspath", point, "from", device};
    if (point == "/preinst") options.insert(options.end(), {"large", "yes", "timezone", "static", "async", "", "ignoreacl", "", "dirmask", "511", "mask", "511"});
    auto* strings = static_cast<char*>(memory) + 0x1000;
    for (size_t i = 0; i < options.size(); ++i) {
      const auto length = options[i].size() + 1;
      std::memcpy(strings, options[i].c_str(), length);
      vectors[i] = {reinterpret_cast<uint64_t>(strings), length};
      strings += length;
    }
    Libs::NativeKernelBridge::SyscallRequest request;
    request.number = 0x17a;
    request.args = {reinterpret_cast<uint64_t>(memory), options.size(), point == "/preinst" ? 1u : 0u};
    const auto result = Libs::NativeKernelBridge::DispatchSyscall(request);
    std::fprintf(stderr, "CapturedStorageAudit: point=%s mount_result=%lld errno=%d\n", point.c_str(),
        static_cast<long long>(result.value), result.posix_errno);
    Check(result.value == 0 && result.posix_errno == 0, "native guest mount publishes captured bytes");
  }
  const char* movie = "/preinst/vsh_asset/initial_boot_movie.mp4";
  const int fd = FileSystem::KernelOpen(movie, 0, 0);
  auto* buffer = static_cast<uint8_t*>(memory) + 0x4000;
  FileSystem::FileStat stat {};
  Check(fd >= 3 && FileSystem::KernelFstat(fd, &stat) == OK && stat.st_size == 107830082 &&
            stat.st_ino == 4026532774u && stat.st_mode == 0100777u && stat.st_mtim.tv_sec == 315532800 &&
            FileSystem::KernelPread(fd, buffer, 4096, 0) == 4096 &&
            FileSystem::KernelPread(fd, buffer, 4096, stat.st_size - 4096) == 4096 && FileSystem::KernelClose(fd) == OK,
        "movie is available at its exact guest path with verified whole-file bytes and observed metadata");
  std::string providers;
  Check(FileSystem::ExportExecReadOnlyProviders(&providers) == OK && providers.find(" C " + digest) != providers.npos,
        "exec provider handoff pins the capture manifest");
  Check(Memory::KernelMunmap(reinterpret_cast<uint64_t>(memory), 0x8000) == OK, "release capture audit guest buffers");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_FSCK_PARTITION_PASSTHROUGH", saved_passthrough.c_str()) == 0,
#else
  Check(passthrough ? setenv("KYTY_DIAGNOSTIC_FSCK_PARTITION_PASSTHROUGH", saved_passthrough.c_str(), 1) == 0
                    : unsetenv("KYTY_DIAGNOSTIC_FSCK_PARTITION_PASSTHROUGH") == 0,
#endif
        "restore the capture audit mount selection");
  std::printf("CapturedStorageAudit: native_mounts=3 movie_bytes=107830082 movie_whole_hash_verified=1 captured_metadata=pass exec_manifest_pinned=pass firmware_movie_request_executed=0 movie_playback=0\n");
}

void SetCapturedLazyFiles(const char* value) {
#if defined(_WIN32)
  Check(_putenv_s("KYTY_PS5_CAPTURED_STORAGE_LAZY_FILES", value) == 0, "set captured lazy-file gate");
#else
  Check((value[0] == '\0' ? unsetenv("KYTY_PS5_CAPTURED_STORAGE_LAZY_FILES")
                          : setenv("KYTY_PS5_CAPTURED_STORAGE_LAZY_FILES", value, 1)) == 0,
        "set captured lazy-file gate");
#endif
}

void CheckCapturedDirectoryLazyFiles(const std::filesystem::path& root) {
  using namespace Libs::LibKernel;
  namespace Mount = DirectoryPassthrough;
  const auto storage = root / "captured-lazy";
  const auto host = storage / "files";
  Check(std::filesystem::create_directories(host), "create lazy captured fixture storage");
  constexpr char contents[] = "present lazy fixture bytes";
  {
    std::ofstream output(host / "Present.Bin", std::ios::binary);
    output.write(contents, sizeof(contents));
    Check(output.good(), "write lazy captured fixture bytes");
  }
  const auto file = [&](std::string path, std::string relative, unsigned inode) {
    return nlohmann::json {{"path", path}, {"inode", inode}, {"mode", 0100640u}, {"size", sizeof(contents)},
        {"uid", 0u}, {"gid", 0u}, {"mtime", 315532800}, {"type", 8u}, {"metadata", true}, {"complete", false},
        {"file", relative}, {"sha256", AuthInfo::DigestHex(AuthInfo::Sha256(contents, sizeof(contents)))}};
  };
  auto entries = nlohmann::json::array({{{"path", "/"}, {"inode", 500u}, {"mode", 0040755u}, {"size", 512u},
      {"uid", 0u}, {"gid", 0u}, {"mtime", 315532800}, {"type", 4u}, {"metadata", true}, {"complete", true}},
      file("/Present.Bin", "files/Present.Bin", 501u), file("/Absent.Bin", "files/Absent.Bin", 502u)});
  const auto volume = nlohmann::json {{"point", "/capture-lazy"}, {"host_root", Common::PathToString(host)},
      {"case_sensitive", true}, {"entries", entries}};
  const auto manifest = nlohmann::json {{"version", 1}, {"storage", Common::PathToString(storage)},
      {"volumes", nlohmann::json::array({volume})}};
  const auto path = storage / "manifest.json";
  const auto digest = SaveCapturedDirectoryManifest(path, manifest);
  CapturedDirectory::Clear();
  SetCapturedLazyFiles("");
  Check(CapturedDirectory::Load(path, digest) == KERNEL_ERROR_EINVAL,
        "default loading still rejects a manifest whose payload is absent on the host");
  SetCapturedLazyFiles("1");
  Check(CapturedDirectory::Load(path, digest) == OK && Mount::Mount("/capture-lazy", host) == OK,
        "lazy loading admits a manifest whose payload is absent on the host");
  FileSystem::FileStat stat {};
  Check(FileSystem::KernelStat("/capture-lazy/Absent.Bin", &stat) == OK && stat.st_ino == 502u,
        "an absent payload keeps its captured metadata");
  Check(FileSystem::KernelOpen("/capture-lazy/Absent.Bin", 0, 0) == KERNEL_ERROR_EIO,
        "opening an absent payload fails only that open");
  const int fd = FileSystem::KernelOpen("/capture-lazy/Present.Bin", 0, 0);
  std::array<char, sizeof(contents)> bytes {};
  Check(fd >= 3 && FileSystem::KernelRead(fd, bytes.data(), bytes.size()) == bytes.size() &&
            std::memcmp(bytes.data(), contents, bytes.size()) == 0 && FileSystem::KernelClose(fd) == OK,
        "present payloads still read their verified bytes");
  {
    auto changed = std::string(contents, sizeof(contents));
    changed[0] ^= 1;
    std::ofstream output(host / "Present.Bin", std::ios::binary);
    output.write(changed.data(), changed.size());
  }
  Check(FileSystem::KernelOpen("/capture-lazy/Present.Bin", 0, 0) == KERNEL_ERROR_EIO,
        "lazy loading still rejects corrupted payload bytes at open");
  Check(Mount::Unmount("/capture-lazy") == OK, "release the lazy captured mount");
  CapturedDirectory::Clear();
  SetCapturedLazyFiles("");
}

void SetCapturedStartupCache(const std::filesystem::path& directory, const std::string& build_id) {
#if defined(_WIN32)
  Check(_putenv_s("KYTY_PS5_STARTUP_CACHE_DIR", directory.empty() ? "" : Common::PathToString(directory).c_str()) == 0 &&
            _putenv_s("KYTY_PS5_STARTUP_CACHE_BUILD_ID", build_id.c_str()) == 0,
        "configure immutable metadata startup cache");
#else
  const auto path = Common::PathToString(directory);
  Check((directory.empty() ? unsetenv("KYTY_PS5_STARTUP_CACHE_DIR")
                           : setenv("KYTY_PS5_STARTUP_CACHE_DIR", path.c_str(), 1)) == 0 &&
            (build_id.empty() ? unsetenv("KYTY_PS5_STARTUP_CACHE_BUILD_ID")
                              : setenv("KYTY_PS5_STARTUP_CACHE_BUILD_ID", build_id.c_str(), 1)) == 0,
        "configure immutable metadata startup cache");
#endif
}

std::vector<std::filesystem::path> CapturedStartupCacheFiles(const std::filesystem::path& root) {
  std::vector<std::filesystem::path> files;
  std::error_code error;
  if (!std::filesystem::exists(root, error)) return files;
  for (const auto& item: std::filesystem::recursive_directory_iterator(root))
    if (item.is_regular_file() && item.path().extension() == ".bin") files.push_back(item.path());
  return files;
}

void FlipCapturedStartupCacheByte(const std::filesystem::path& path, std::streamoff offset) {
  std::fstream file(path, std::ios::binary | std::ios::in | std::ios::out);
  Check(file.good(), "open disposable startup cache for corruption test");
  file.seekg(offset, offset < 0 ? std::ios::end : std::ios::beg);
  char byte = 0;
  file.read(&byte, 1);
  Check(file.good(), "read disposable startup cache byte");
  byte ^= 0x5a;
  file.seekp(offset, offset < 0 ? std::ios::end : std::ios::beg);
  file.write(&byte, 1);
  file.flush();
  Check(file.good(), "corrupt disposable startup cache byte");
}

void CheckCapturedDirectoryStartupCache(const std::filesystem::path& root) {
  using namespace Libs::LibKernel;
  const auto storage = root / "captured-startup-cache";
  const auto host = storage / "files";
  const auto cache = root / "immutable-metadata-cache";
  Check(std::filesystem::create_directories(host), "create startup-cache captured storage");
  const auto root_entry = nlohmann::json {{"path", "/"}, {"inode", 701u}, {"mode", 0040755u},
      {"size", 512u}, {"uid", 0u}, {"gid", 0u}, {"mtime", 315532800}, {"type", 4u},
      {"metadata", true}, {"complete", true}};
  const auto volume = nlohmann::json {{"point", "/startup-cache"},
      {"host_root", Common::PathToString(host)}, {"case_sensitive", true},
      {"entries", nlohmann::json::array({root_entry})}};
  const auto manifest = nlohmann::json {{"version", 1}, {"storage", Common::PathToString(storage)},
      {"volumes", nlohmann::json::array({volume})}};
  const auto path = storage / "manifest.json";
  const auto digest = SaveCapturedDirectoryManifest(path, manifest);
  const auto original_write = std::filesystem::last_write_time(path);
  std::ifstream source(path, std::ios::binary);
  const std::string original((std::istreambuf_iterator<char>(source)), std::istreambuf_iterator<char>());
  const auto build_a = std::string(64, 'a');
  const auto build_b = std::string(64, 'b');

  CapturedDirectory::Clear();
  SetCapturedStartupCache({}, {});
  Check(CapturedDirectory::Load(path, digest) == OK &&
            !CapturedDirectory::LastLoadUsedStartupCache() && CapturedStartupCacheFiles(cache).empty(),
        "disabled startup cache preserves the authenticated manifest path without writing state");
  CapturedDirectory::Clear();

  SetCapturedStartupCache(cache, build_a);
  Check(CapturedDirectory::Load(path, digest) == OK &&
            !CapturedDirectory::LastLoadUsedStartupCache(),
        "first immutable metadata load validates the source before priming cache");
  auto files = CapturedStartupCacheFiles(cache);
  Check(files.size() == 1, "first immutable metadata load writes one content-keyed artifact");
  CapturedDirectory::Clear();
  Check(CapturedDirectory::Load(path, digest) == OK && CapturedDirectory::LastLoadUsedStartupCache() &&
            CapturedDirectory::ForPoint("/startup-cache") != nullptr,
        "unchanged immutable metadata reloads from persistent cache");

  for (const auto offset: {std::streamoff(0), std::streamoff(-1)}) {
    CapturedDirectory::Clear();
    FlipCapturedStartupCacheByte(files.front(), offset);
    Check(CapturedDirectory::Load(path, digest) == OK &&
              !CapturedDirectory::LastLoadUsedStartupCache(),
          "corrupt immutable metadata cache falls through to full source validation");
  }

  {
    std::string changed = original;
    changed[0] ^= 1;
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(changed.data(), changed.size());
  }
  std::filesystem::last_write_time(path, original_write);
  CapturedDirectory::Clear();
  Check(CapturedDirectory::Load(path, digest) == KERNEL_ERROR_EINVAL &&
            !CapturedDirectory::ForPoint("/startup-cache"),
        "file identity change invalidates cache even when size and write time are restored");
  {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(original.data(), original.size());
  }
  std::filesystem::last_write_time(path, original_write);
  Check(CapturedDirectory::Load(path, digest) == OK &&
            !CapturedDirectory::LastLoadUsedStartupCache(),
        "restored source is revalidated before replacing its invalidated cache entry");
  CapturedDirectory::Clear();
  Check(CapturedDirectory::Load(path, digest) == OK && CapturedDirectory::LastLoadUsedStartupCache(),
        "revalidated source produces a reusable replacement cache entry");

  CapturedDirectory::Clear();
  SetCapturedStartupCache(cache, build_b);
  Check(CapturedDirectory::Load(path, digest) == OK &&
            !CapturedDirectory::LastLoadUsedStartupCache(),
        "a different emulator build cannot consume another build's metadata cache");
  CapturedDirectory::Clear();
  Check(CapturedDirectory::Load(path, digest) == OK && CapturedDirectory::LastLoadUsedStartupCache(),
        "the isolated build namespace reuses only its own validated artifact");
  files = CapturedStartupCacheFiles(cache);
  bool temporary_found = false;
  for (const auto& item: std::filesystem::recursive_directory_iterator(cache))
    temporary_found |= item.path().filename().string().find(".tmp.") != std::string::npos;
  Check(files.size() >= 2 && std::filesystem::is_directory(cache / build_a.substr(0, 16)) &&
            std::filesystem::is_directory(cache / build_b.substr(0, 16)) && !temporary_found,
        "atomic cache writes leave no temporary artifact behind");
  CapturedDirectory::Clear();
  SetCapturedStartupCache({}, {});
  std::printf("CapturedDirectoryStartupCacheTests: disabled=pass hit=pass corruption_fallback=pass source_identity=pass build_isolation=pass atomic_write=pass\n");
}
