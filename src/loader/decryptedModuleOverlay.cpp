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

static bool IsAllowedGuestPath(const std::string& guest_path) {
	if (guest_path.rfind("/system_ex/", 0) == 0) return true;
	// rl-80 vsh daemons exec from /system/vsh/app; the rest of /system stays on its own decrypted
	// tree.
	if (guest_path.rfind("/system/vsh/app/", 0) == 0) return true;
	static constexpr std::array<std::string_view, 7> app_paths {
	    "/app0/libScePSNowGkp.sprx",
	    "/app0/psm/Application/Sce.Vsh.AppContentUtilWrapper.dll.sprx",
	    "/app0/psm/Application/Sce.Vsh.Np.AppLaunchLink.dll.sprx",
	    "/app0/psm/Application/Sce.Vsh.Np.AppLaunchLink2.dll.sprx",
	    "/app0/psm/Application/Sce.Vsh.ShellUI.Ime.dll.sprx",
	    "/app0/psm/Application/Sce.Vsh.Sl2.Sl2Manage.dll.sprx",
	    "/app0/psm/Application/Sce.Vsh.VideoRecordingWrapper.dll.sprx",
	};
	for (const auto path: app_paths) {
		if (guest_path == path) return true;
	}
	return false;
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

Resolution ResolveWithManifest(const Manifest& manifest, const std::string& guest_path,
                               const std::vector<uint8_t>& original_image,
                               std::vector<uint8_t>* decrypted, std::string* detail,
                               std::filesystem::path* elf_path) {
	if (detail != nullptr) detail->clear();
	if (!IsAllowedGuestPath(guest_path)) return Resolution::NotApplicable;
	const auto it = manifest.entries.find(guest_path);
	if (it == manifest.entries.end()) return Resolution::NotApplicable;
	const Entry& entry = it->second;

	// encrypted original only; anything else here, decrypted ELF included, is left alone
	if (original_image.size() != entry.self_size) return Resolution::NotApplicable;
	if (Libs::LibKernel::AuthInfo::Sha256(original_image.data(), original_image.size()) !=
	    entry.self_sha256) {
		return Resolution::NotApplicable;
	}

	Common::File file;
	if (!file.Open(entry.elf_path, Common::File::Mode::Read) || file.IsInvalid()) {
		if (detail != nullptr) {
			*detail = "reason=decrypted_unreadable elf_path=" +
			          Log::EscapeField(Common::PathToString(entry.elf_path));
		}
		return Resolution::RejectedMissing;
	}
	const uint64_t size = file.Size();
	if (size != entry.elf_size) {
		if (detail != nullptr)
			*detail =
			    fmt::format("reason=decrypted_size_mismatch have={} want={}", size, entry.elf_size);
		return Resolution::RejectedMismatch;
	}
	if (size > UINT32_MAX) {
		if (detail != nullptr) *detail = fmt::format("reason=decrypted_too_large bytes={}", size);
		return Resolution::RejectedMismatch;
	}
	if (size < 4) {
		if (detail != nullptr) *detail = fmt::format("reason=decrypted_too_small bytes={}", size);
		return Resolution::RejectedMismatch;
	}
	std::vector<uint8_t> bytes(static_cast<size_t>(size));
	uint32_t             actual = 0;
	std::error_code      read_error;
	file.Read(bytes.data(), static_cast<uint32_t>(bytes.size()), &actual, &read_error);
	if (read_error || actual != bytes.size()) {
		if (detail != nullptr) *detail = "reason=decrypted_read_error";
		return Resolution::RejectedMismatch;
	}
	if (Libs::LibKernel::AuthInfo::Sha256(bytes.data(), bytes.size()) != entry.elf_sha256) {
		if (detail != nullptr) *detail = "reason=decrypted_sha256_mismatch";
		return Resolution::RejectedMismatch;
	}
	if (bytes[0] != 0x7f || bytes[1] != 'E' || bytes[2] != 'L' || bytes[3] != 'F') {
		if (detail != nullptr) *detail = "reason=decrypted_not_elf";
		return Resolution::RejectedMismatch;
	}

	if (detail != nullptr) {
		*detail = fmt::format("self_sha256={} elf_sha256={} elf_bytes={} elf_path={}",
		                      Libs::LibKernel::AuthInfo::DigestHex(entry.self_sha256),
		                      Libs::LibKernel::AuthInfo::DigestHex(entry.elf_sha256), bytes.size(),
		                      Log::EscapeField(Common::PathToString(entry.elf_path)));
	}
	if (elf_path != nullptr) *elf_path = entry.elf_path;
	*decrypted = std::move(bytes);
	return Resolution::Substituted;
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

Resolution ResolveDecryptedModuleImage(const std::string&          guest_path,
                                       const std::vector<uint8_t>& original_image,
                                       std::vector<uint8_t>* decrypted, std::string* detail,
                                       std::filesystem::path* elf_path) {
	const Manifest* manifest = ConfiguredManifest();
	if (manifest == nullptr) return Resolution::NotApplicable;
	return ResolveWithManifest(*manifest, guest_path, original_image, decrypted, detail, elf_path);
}

bool ManifestCoversPath(const std::string& guest_path) {
	const Manifest* manifest = ConfiguredManifest();
	return manifest != nullptr && manifest->entries.count(guest_path) != 0;
}

} // namespace Loader::DecryptedModuleOverlay
