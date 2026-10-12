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



