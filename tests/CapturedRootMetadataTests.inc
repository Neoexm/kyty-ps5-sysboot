struct CapturedRootFixture {
  Libs::LibKernel::CapturedRootMetadata::Layout layout {0x100000000ull, 0x100, 0x800, 6};
  std::vector<uint8_t> bytes = std::vector<uint8_t>(0x800 + 6 * 0x2f0);

  void Put(size_t offset, size_t size, uint64_t value) {
    for (size_t n = 0; n < size; ++n) bytes[offset + n] = static_cast<uint8_t>(value >> (8 * n));
  }

  void Text(size_t offset, const char* text) {
    std::memcpy(bytes.data() + offset, text, std::strlen(text));
  }

  size_t Node(size_t index) const { return layout.nodes_offset + index * 0x2f0; }
  uint64_t Vnode(size_t index) const { return 0xffff800000001000ull + index * 0x100; }

  void Name(size_t index, const char* name) {
    const auto offset = Node(index);
    std::fill(bytes.begin() + offset, bytes.begin() + offset + 0x208, 0);
    for (size_t n = 0; name[n] != '\0'; ++n) Put(offset + n * 2, 2, name[n]);
    Put(offset + 0x208, 8, layout.virtual_base + offset + (index == 0 ? 2 : 0));
  }

  CapturedRootFixture() {
    const auto fs = layout.filesystem_offset;
    Put(fs + 0x18, 8, layout.virtual_base + 0x300);
    Put(fs + 0x2c, 4, 12);
    Put(fs + 0x40, 4, 0x1d01);
    Put(fs + 0x44, 4, 1);
    Put(fs + 0x4c, 4, 512);
    Put(fs + 0x50, 4, 8);
    Text(0x303, "SCEI    ");
    Text(0x300 + 43, "ORBIS ROOT ");
    Text(0x300 + 54, "FAT12   ");
    Put(0x300 + 11, 2, 512);
    Put(0x300 + 13, 1, 8);
    Put(0x300 + 14, 2, 1);
    Put(0x300 + 16, 1, 2);
    Put(0x300 + 17, 2, 512);
    Put(0x300 + 19, 2, 14336);
    Put(0x300 + 22, 2, 6);
    Put(0x300 + 510, 2, 0xaa55);
    const std::array<const char*, 6> names {"/", "devlog", "system", "app", "original_user", "mini-syscore.elf"};
    const std::array<uint32_t, 6> clusters {0, 0xc3, 0xc2, 0xc1, 0x189, 0x23};
    for (size_t n = 0; n < names.size(); ++n) {
      Name(n, names[n]);
      const auto offset = Node(n);
      const size_t parent = n == 2 || n == 3 ? 1 : 0;
      Put(offset + 0x210, 8, layout.virtual_base + fs);
      Put(offset + 0x21a, 2, n == 5 ? 0 : 6);
      Put(offset + 0x220, 8, n == 0 ? 0x4000 : n == 5 ? 123 : 0x1000);
      Put(offset + 0x260, 4, clusters[n]);
      Put(offset + 0x265, 1, n == 0 ? 0x10 : n == 5 ? 0x26 : 0x16);
      Put(offset + 0x278, 4, n == 0 ? 0xfffffffeu : clusters[parent]);
      Put(offset + 0x2e0, 8, Vnode(n));
      Put(offset + 0x2e8, 8, n == 0 ? 0 : Vnode(parent));
    }
  }
};

void CheckCapturedRootMetadata(const std::filesystem::path& root) {
  namespace Metadata = Libs::LibKernel::CapturedRootMetadata;
  using namespace Libs::LibKernel;
  CapturedRootFixture fixture;
  Metadata::Snapshot snapshot;
  Check(Metadata::Decode(fixture.bytes, fixture.layout, &snapshot) == OK &&
            snapshot.root_node_count == 6 && snapshot.directories.size() == 5,
        "pure captured-root decoder selects directory records from the same root filesystem");
  FileSystem::FileStat stat {};
  Check(Metadata::Lookup(snapshot, "/devlog/system", &stat) == OK &&
            stat.st_mode == 0040777u && stat.st_ino == 0xc2 && stat.st_dev == UINT32_MAX &&
            stat.st_rdev == UINT32_MAX && stat.st_uid == 0 && stat.st_gid == 0 && stat.st_nlink == 1 &&
            stat.st_size == 4096 && stat.st_blocks == 8 && stat.st_blksize == 4096 &&
            stat.st_flags == 0x10000u && stat.st_atim.tv_sec == -1 && stat.st_birthtim.tv_sec == -1,
        "captured-root metadata follows directory type, cluster inode, permissions and size conversion");
  Check(Metadata::Lookup(snapshot, "/", &stat) == OK && stat.st_ino == 1 && stat.st_size == 0x4000 &&
            Metadata::Lookup(snapshot, "/devlog//system/", &stat) == OK &&
            Metadata::Lookup(snapshot, "/devlog/app/../system/.", &stat) == OK && stat.st_ino == 0xc2 &&
            Metadata::Lookup(snapshot, "/devlog/app/..", &stat) == OK && stat.st_ino == 0xc3,
        "root inode is special while repeated separators preserve a known directory path");
  auto read_only = fixture;
  read_only.Put(read_only.Node(3) + 0x265, 1, 0x17);
  Metadata::Snapshot read_only_snapshot;
  Check(Metadata::Decode(read_only.bytes, read_only.layout, &read_only_snapshot) == OK &&
            Metadata::Lookup(read_only_snapshot, "/devlog/app", &stat) == OK && stat.st_mode == 0040555u,
        "attribute low bit changes directory permission metadata without enabling mutations");
  const auto rejects = [&](CapturedRootFixture changed) {
    Check(Metadata::Decode(changed.bytes, changed.layout, &snapshot) == KERNEL_ERROR_EINVAL &&
              snapshot.root_node_count == 6 && snapshot.directories.size() == 5 &&
              Metadata::Lookup(snapshot, "/devlog/system", &stat) == OK && stat.st_ino == 0xc2,
          "malformed root metadata leaves the previously decoded snapshot unchanged");
  };
  auto changed = fixture;
  changed.bytes.resize(changed.bytes.size() - 1);
  rejects(changed);
  changed = fixture;
  changed.Put(changed.layout.filesystem_offset + 0x18, 8, UINT64_MAX);
  rejects(changed);
  changed = fixture;
  changed.Put(0x300 + 510, 2, 0);
  rejects(changed);
  changed = fixture;
  changed.Put(changed.Node(2) + 0x278, 4, 0);
  rejects(changed);
  changed = fixture;
  changed.Put(changed.Node(2) + 0x2e8, 8, 0x12345);
  rejects(changed);
  changed = fixture;
  changed.Put(changed.Node(2) + 0x2e0, 8, changed.Vnode(1));
  rejects(changed);
  changed = fixture;
  changed.Name(3, "system");
  rejects(changed);
  changed = fixture;
  changed.Put(changed.Node(1) + 0x278, 4, 0xc2);
  changed.Put(changed.Node(1) + 0x2e8, 8, changed.Vnode(2));
  rejects(changed);
  changed = fixture;
  changed.Put(changed.Node(3) + 0x260, 4, 0xc2);
  rejects(changed);
  changed = fixture;
  changed.Put(changed.Node(2) + 0x265, 1, 0x06);
  rejects(changed);
  changed = fixture;
  changed.Put(changed.Node(2) + 0x208, 8, changed.layout.virtual_base + changed.Node(2) + 4);
  rejects(changed);
  changed = fixture;
  changed.Name(2, std::string(256, 'A').c_str());
  rejects(changed);
  changed = fixture;
  for (size_t n = 0; n < 0x104; ++n) changed.Put(changed.Node(2) + n * 2, 2, 'A');
  rejects(changed);
  Check(Metadata::Decode(fixture.bytes, fixture.layout, nullptr) == KERNEL_ERROR_EFAULT &&
            Metadata::Lookup(snapshot, "/", nullptr) == KERNEL_ERROR_EFAULT,
        "captured-root decoder and lookup validate their output arguments");
  for (const auto& path: std::vector<std::string> {
      "", "relative", "/devlog\\system", std::string("/devlog\0/system", 15), std::string(4096, '/')}) {
    std::memset(&stat, 0x61, sizeof(stat));
    const auto before = stat;
    Check(Metadata::Lookup(snapshot, path, &stat) == KERNEL_ERROR_EINVAL &&
              std::memcmp(&stat, &before, sizeof(stat)) == 0,
          "malformed captured paths preserve their output metadata");
  }
  for (const auto* path: {"/missing", "/devlog/system/not-captured", "/mini-syscore.elf",
      "/missing/../devlog/system", "/devlog/x/../system", "/mini-syscore.elf/../devlog"}) {
    std::memset(&stat, 0x61, sizeof(stat));
    const auto before = stat;
    Check(Metadata::Lookup(snapshot, path, &stat) == KERNEL_ERROR_EIO &&
              std::memcmp(&stat, &before, sizeof(stat)) == 0,
          "incomplete cached listings and uncaptured contents return missing-data errors without empty-file synthesis");
  }
  Check(Metadata::Lookup(snapshot, "/" + std::string(256, 'x'), &stat) == KERNEL_ERROR_ENAMETOOLONG,
        "captured root lookup bounds each raw component before traversing it");
  const auto bad_image = root / "captured-root-invalid.bin";
  { std::ofstream output(bad_image, std::ios::binary);
    output.write(reinterpret_cast<const char*>(fixture.bytes.data()), fixture.bytes.size());
    Check(output.good(), "write a bounded synthetic image that cannot satisfy production authentication"); }
  const bool enabled = Metadata::Enabled();
  Check(Metadata::Load(bad_image) == KERNEL_ERROR_EINVAL && Metadata::Enabled() == enabled &&
            Metadata::Load(root / "captured-root-missing.bin") == KERNEL_ERROR_ENOENT &&
            Metadata::Enabled() == enabled,
        "production loader rejects synthetic and absent inputs without changing its published-state flag");
  std::printf("CapturedRootMetadataTests: pure_decode=pass parent_vnode_cluster_agreement=pass cycle_duplicate_rejection=pass raw_traversal=pass partial_errors=pass authentication=pass\n");
}
