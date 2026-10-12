void CheckMemoryFileBounds() {
  std::array<uint8_t, 16> storage {};
  storage.fill(0xa5);
  Common::File bounded;
  Check(bounded.OpenInMem(storage.data(), 4) && bounded.Seek(8),
        "open and seek past a fixed memory backing");
  std::array<uint8_t, 2> bytes {0x5a, 0x5a};
  uint32_t actual = 99;
  std::error_code error;
  bounded.Read(bytes.data(), bytes.size(), &actual, &error);
  Check(actual == 0 && !error && bytes[0] == 0x5a && bytes[1] == 0x5a && bounded.Tell() == 8,
        "fixed memory read after EOF preserves destination and cursor");
  bounded.Write("XX", 2, &actual, &error);
  Check(actual == 0 && error == std::errc::no_space_on_device && storage[8] == 0xa5,
        "fixed memory write after capacity cannot overwrite trailing storage");
  Check(bounded.Seek(3), "seek to final fixed memory byte");
  bounded.Write("YZ", 2, &actual, &error);
  Check(actual == 1 && error == std::errc::no_space_on_device && storage[3] == 'Y' &&
        storage[4] == 0xa5 && bounded.Size() == 4,
        "partial fixed memory write preserves canary and reports its capacity limit");
  bounded.Close();
  Check(bounded.OpenInMem(storage.data(), 0), "open an empty fixed memory backing");
  bounded.Read(bytes.data(), 1, &actual, &error);
  Check(actual == 0 && !error && bounded.Tell() == 0,
        "empty fixed memory backing cannot expose underlying storage");
  bounded.Write("X", 1, &actual, &error);
  Check(actual == 0 && error == std::errc::no_space_on_device && storage[0] == 0xa5,
        "empty fixed memory backing has no writable capacity");
  bounded.Close();
  Common::File dynamic;
  Check(dynamic.CreateInMem() && dynamic.Seek(8), "seek past an empty dynamic memory backing");
  dynamic.Read(bytes.data(), 1, &actual, &error);
  Check(actual == 0 && !error && dynamic.Tell() == 8, "dynamic memory seek after EOF returns no bytes");
  dynamic.Write("XY", 2, &actual, &error);
  Check(actual == 2 && !error && dynamic.Size() == 10 && dynamic.Tell() == 10 && dynamic.Seek(0),
        "dynamic memory write extends from its integer cursor");
  std::array<uint8_t, 10> content {};
  content.fill(0xff);
  dynamic.Read(content.data(), content.size(), &actual, &error);
  Check(actual == 10 && !error && std::all_of(content.begin(), content.begin() + 8,
        [](uint8_t byte) { return byte == 0; }) && content[8] == 'X' && content[9] == 'Y',
        "dynamic memory holes are initialized and data survives growth");
  Check(dynamic.Seek(UINT64_MAX), "large memory cursor remains an integer");
  dynamic.Read(bytes.data(), bytes.size(), &actual, &error);
  Check(actual == 0 && !error && dynamic.Tell() == UINT64_MAX,
        "large memory read cannot wrap into the allocation");
  dynamic.Write("X", 1, &actual, &error);
  Check(actual == 0 && error == std::errc::file_too_large && dynamic.Size() == 10,
        "dynamic memory growth overflow preserves allocation and length");
  dynamic.Write(nullptr, 0, &actual, &error);
  Check(actual == 0 && !error, "zero memory write has no allocation or pointer requirement");
  dynamic.Close();
  std::printf("MemoryFileTests: bounded_read=pass bounded_write=pass empty=pass holes=pass overflow=pass\n");
}
