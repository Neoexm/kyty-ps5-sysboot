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

enum class Resolution {
	NotApplicable,    // no manifest entry for this path and image
	Substituted,      // SELF matched, decrypted ELF swapped in
	RejectedMissing,  // decrypted candidate unreadable
	RejectedMismatch, // decrypted candidate failed its hash
};

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

// Each non-empty, non-'#' line pins one library:
//   <guest_path> <self_size> <self_sha256> <elf_size> <elf_sha256> <elf_host_path> The host path is
//   the line remainder so it may contain spaces. Any malformed line fails the parse.
bool ParseManifest(const std::string& text, Manifest* manifest, std::string* error);

// Swap a needed-module image for its decrypted ELF only if the image hashes to the manifest SELF
// and the file on disk to its ELF.
Resolution ResolveWithManifest(const Manifest& manifest, const std::string& guest_path,
                               const std::vector<uint8_t>& original_image,
                               std::vector<uint8_t>* decrypted, std::string* detail,
                               std::filesystem::path* elf_path = nullptr);

// Loads KYTY_DIAGNOSTIC_SYSTEM_EX_DECRYPTED_MANIFEST once
// (KYTY_DIAGNOSTIC_SYSTEM_EX_DECRYPTED_MANIFEST_SHA256 optional). No manifest: always
// NotApplicable.
Resolution ResolveDecryptedModuleImage(const std::string&          guest_path,
                                       const std::vector<uint8_t>& original_image,
                                       std::vector<uint8_t>* decrypted, std::string* detail,
                                       std::filesystem::path* elf_path = nullptr);

// true when the manifest lists a SELF for guest_path; the fs read side then serves it over the
// decrypted host file
bool ManifestCoversPath(const std::string& guest_path);

} // namespace Loader::DecryptedModuleOverlay

#endif
