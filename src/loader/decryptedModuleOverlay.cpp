#include "loader/decryptedModuleOverlay.h"

#include "common/file.h"
#include "common/logging/log.h"
#include "common/stringUtils.h"

#include <cerrno>
#include <array>
#include <cstdlib>
#include <mutex>
#include <string_view>
#include <system_error>

#include <fmt/format.h>

namespace Loader::DecryptedModuleOverlay {

using Libs::LibKernel::AuthInfo::Digest;
static bool NextField(const std::string& line, size_t* pos, std::string* field) {
	size_t i = *pos;
	while (i < line.size() && (line[i] == ' ' || line[i] == '\t'))
		i++;
	if (i >= line.size()) return false;
	const size_t start = i;
	while (i < line.size() && line[i] != ' ' && line[i] != '\t')
		i++;
	field->assign(line, start, i - start);
	*pos = i;
	return true;
}
static bool ParseU64(const std::string& text, uint64_t* value) {
	if (text.empty()) return false;
	char* end                       = nullptr;
	errno                           = 0;
	const unsigned long long parsed = std::strtoull(text.c_str(), &end, 10);
	if (errno != 0 || end != text.c_str() + text.size()) return false;
	*value = static_cast<uint64_t>(parsed);
	return true;
}
bool ParseManifest(const std::string& text, Manifest* manifest, std::string* error) {
	if (manifest == nullptr) return false;
	manifest->entries.clear();
	size_t line_start = 0;
	int    line_no    = 0;
	while (line_start <= text.size()) {
		size_t line_end = text.find('\n', line_start);
		if (line_end == std::string::npos) line_end = text.size();
		std::string line = text.substr(line_start, line_end - line_start);
		line_start       = line_end + 1;
		line_no++;
		if (!line.empty() && line.back() == '\r') line.pop_back();
		size_t first = line.find_first_not_of(" \t");
		if (first == std::string::npos || line[first] == '#') {
			if (line_end == text.size()) break;
			continue;
		}

		size_t      pos = 0;
		std::string guest_path;
		std::string self_size_text;
		std::string self_sha_text;
		std::string elf_size_text;
		std::string elf_sha_text;
		if (!NextField(line, &pos, &guest_path) || !NextField(line, &pos, &self_size_text) ||
		    !NextField(line, &pos, &self_sha_text) || !NextField(line, &pos, &elf_size_text) ||
		    !NextField(line, &pos, &elf_sha_text)) {
			if (error != nullptr) *error = fmt::format("line {}: too few fields", line_no);
			return false;
		}
		while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t'))
			pos++;
		size_t path_end = line.find_last_not_of(" \t");
		if (pos > path_end || path_end == std::string::npos) {
			if (error != nullptr) *error = fmt::format("line {}: missing decrypted path", line_no);
			return false;
		}
		std::string elf_path_text = line.substr(pos, path_end - pos + 1);

		Entry entry;
		if (!ParseU64(self_size_text, &entry.self_size) ||
		    !Libs::LibKernel::AuthInfo::ParseDigestHex(self_sha_text, &entry.self_sha256) ||
		    !ParseU64(elf_size_text, &entry.elf_size) ||
		    !Libs::LibKernel::AuthInfo::ParseDigestHex(elf_sha_text, &entry.elf_sha256)) {
			if (error != nullptr)
				*error = fmt::format("line {}: malformed size or digest", line_no);
			return false;
		}
		entry.elf_path = Common::PathFromUtf8(elf_path_text);
		if (!manifest->entries.emplace(guest_path, std::move(entry)).second) {
			if (error != nullptr)
				*error = fmt::format("line {}: duplicate path {}", line_no, guest_path);
			return false;
		}
		if (line_end == text.size()) break;
	}
	return true;
}
static const Manifest* ConfiguredManifest() {
	static std::once_flag once;
	static bool           loaded = false;
	static Manifest       manifest;
	std::call_once(once, [] {
		const char* path = std::getenv("KYTY_DIAGNOSTIC_SYSTEM_EX_DECRYPTED_MANIFEST");
		if (path == nullptr || path[0] == '\0') return;
		Common::File file;
		if (!file.Open(Common::PathFromUtf8(path), Common::File::Mode::Read) || file.IsInvalid()) {
			LOGF("SYSTEM_EX_DECRYPTED_OVERLAY_MANIFEST open_failed path=%s\n",
			     Log::EscapeField(path).c_str());
			return;
		}
		const auto  raw = file.ReadWholeBuffer();
		std::string text(reinterpret_cast<const char*>(raw.data()), raw.size());
		if (const char* expected =
		        std::getenv("KYTY_DIAGNOSTIC_SYSTEM_EX_DECRYPTED_MANIFEST_SHA256");
		    expected != nullptr && expected[0] != '\0') {
			Digest want {};
			if (!Libs::LibKernel::AuthInfo::ParseDigestHex(expected, &want) ||
			    Libs::LibKernel::AuthInfo::Sha256(raw.data(), raw.size()) != want) {
				LOGF("SYSTEM_EX_DECRYPTED_OVERLAY_MANIFEST sha256_rejected path=%s\n",
				     Log::EscapeField(path).c_str());
				return;
			}
		}
		std::string error;
		if (!ParseManifest(text, &manifest, &error)) {
			LOGF("SYSTEM_EX_DECRYPTED_OVERLAY_MANIFEST parse_failed path=%s %s\n",
			     Log::EscapeField(path).c_str(), error.c_str());
			manifest.entries.clear();
			return;
		}
		// Relative decrypted paths belong to the manifest's own tree, wherever that has been
		// copied.
		const auto base = Common::PathFromUtf8(path).parent_path();
		for (auto& [guest_path, entry]: manifest.entries) {
			if (entry.elf_path.is_relative())
				entry.elf_path = (base / entry.elf_path).lexically_normal();
		}
		loaded = true;
		LOGF("SYSTEM_EX_DECRYPTED_OVERLAY_MANIFEST loaded entries=%zu path=%s\n",
		     manifest.entries.size(), Log::EscapeField(path).c_str());
	});
	return loaded ? &manifest : nullptr;
}
bool ManifestCoversPath(const std::string& guest_path) {
	const Manifest* manifest = ConfiguredManifest();
	return manifest != nullptr && manifest->entries.count(guest_path) != 0;
}
} // namespace Loader::DecryptedModuleOverlay
