#ifndef KYTY_KERNEL_CAPTURED_DIRECTORY_H_
#define KYTY_KERNEL_CAPTURED_DIRECTORY_H_

#include "kernel/directoryPassthrough.h"

#include <map>
#include <string_view>

namespace Libs::LibKernel::CapturedDirectory {

struct Entry {
	DirectoryPassthrough::NodeStat stat;
	std::filesystem::path          file;
	std::string                    sha256;
	std::string                    name;
	bool                           metadata = false;
	bool                           complete = false;
	uint8_t                        type     = 0;
};

struct Snapshot {
	std::string                  point;
	std::string                  manifest_sha256;
	std::string                  supplement_sha256;
	std::filesystem::path        root;
	std::filesystem::path        storage;
	bool                         case_sensitive = true;
	std::map<std::string, Entry> entries;
};

int Load(const std::filesystem::path& manifest, const std::string& sha256);
// Fills in directories the base manifest listed without metadata; each entry must still lack it.
int  Supplement(const std::filesystem::path& file, const std::string& sha256);
void Clear();
bool LastLoadUsedStartupCache();
std::shared_ptr<const Snapshot> ForRoot(const std::filesystem::path& root);
std::shared_ptr<const Snapshot> ForPoint(std::string_view point);
int Find(const Snapshot& snapshot, std::string_view path, const Entry** entry);
int FindDirectory(const Snapshot& snapshot, std::string_view path, const Entry** entry);
int List(const Snapshot& snapshot, std::string_view path,
         std::vector<DirectoryPassthrough::DirectoryEntry>* entries);
int RootMetadata(const std::string& point, DirectoryPassthrough::NodeStat* stat);

} // namespace Libs::LibKernel::CapturedDirectory
#endif
