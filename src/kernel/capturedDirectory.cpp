#include "kernel/capturedDirectory.h"
#include "kernel/authInfo.h"
#include "kernel/capturedMetadataCache.h"
#include "libs/errno.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>

namespace Libs::LibKernel::CapturedDirectory {
namespace {
std::mutex                                   mutex;
std::vector<std::shared_ptr<const Snapshot>> snapshots;
std::string Key(std::string_view path, bool sensitive) {
	std::string key(path);
	if (!sensitive)
		for (auto& ch: key)
			if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
	return key;
}
} // namespace
std::shared_ptr<const Snapshot> ForRoot(const std::filesystem::path& root) {
	std::lock_guard lock(mutex);
	for (const auto& snapshot: snapshots)
		if (snapshot->root == root) return snapshot;
	return {};
}
std::shared_ptr<const Snapshot> ForPoint(std::string_view point) {
	std::lock_guard lock(mutex);
	for (const auto& snapshot: snapshots)
		if (snapshot->point == point) return snapshot;
	return {};
}
int FindDirectory(const Snapshot& snapshot, std::string_view path, const Entry** entry) {
	const auto found =
	    snapshot.entries.find(Key(path.empty() ? "/" : path, snapshot.case_sensitive));
	if (found == snapshot.entries.end()) return KERNEL_ERROR_ENOENT;
	if (found->second.type != 4) return KERNEL_ERROR_ENOTDIR;
	*entry = &found->second;
	return OK;
}
} // namespace Libs::LibKernel::CapturedDirectory
