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
} // namespace Loader::DecryptedModuleOverlay
#endif
