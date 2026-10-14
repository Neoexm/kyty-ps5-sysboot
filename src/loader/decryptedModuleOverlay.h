#ifndef EMULATOR_INCLUDE_EMULATOR_LOADER_DECRYPTED_MODULE_OVERLAY_H_
#define EMULATOR_INCLUDE_EMULATOR_LOADER_DECRYPTED_MODULE_OVERLAY_H_

#include "common/common.h"

#include "kernel/authInfo.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

namespace Loader::DecryptedModuleOverlay {
struct Entry {
	uint64_t                          self_size = 0;
	Libs::LibKernel::AuthInfo::Digest self_sha256 {};
	uint64_t                          elf_size = 0;
	Libs::LibKernel::AuthInfo::Digest elf_sha256 {};
	std::filesystem::path             elf_path;
};
struct Manifest {
	std::unordered_map<std::string, Entry> entries;
};
// true when the manifest lists a SELF for guest_path; the fs read side then serves it over the
// decrypted host file
bool ManifestCoversPath(const std::string& guest_path);
} // namespace Loader::DecryptedModuleOverlay
#endif
