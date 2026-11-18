#include "kernel/execProcess.h"

#include "common/assert.h"
#include "common/logging/log.h"
#include "common/stringUtils.h"
#include "emulator.h"
#include "kernel/authInfo.h"
#include "kernel/fileSystem.h"
#include "kernel/process.h"
#include "kernel/pthread.h"
#include "libs/errno.h"
#include "loader/elf.h"
#include "loader/jit.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string_view>
#include <thread>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <crtdbg.h>
#endif

namespace Libs::LibKernel::Process {
namespace {
using Json = nlohmann::json;
Emulator::RunOptions     g_options;
Json                     g_child_request;
std::vector<std::string> g_arguments;
std::vector<std::string> g_environment;
bool                     g_exec_child = false;
// sandbox root (chroot) and randomized word the spawn trampoline assigned to an rfork child before
// its execve
std::mutex                                         g_spawn_sandbox_mutex;
std::map<int, std::pair<std::string, std::string>> g_spawn_sandboxes;
#if defined(_WIN32)
HANDLE g_validated_original_self = INVALID_HANDLE_VALUE;
HANDLE g_validated_exec_elf      = INVALID_HANDLE_VALUE;

bool SameValidatedImageFile(HANDLE validated, const std::filesystem::path& path) {
	if (validated == INVALID_HANDLE_VALUE || path.empty()) return false;
	HANDLE candidate = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
	                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (candidate == INVALID_HANDLE_VALUE) return false;
	BY_HANDLE_FILE_INFORMATION validated_info {};
	BY_HANDLE_FILE_INFORMATION candidate_info {};
	const bool same = GetFileInformationByHandle(validated, &validated_info) &&
	                  GetFileInformationByHandle(candidate, &candidate_info) &&
	                  validated_info.dwVolumeSerialNumber == candidate_info.dwVolumeSerialNumber &&
	                  validated_info.nFileIndexHigh == candidate_info.nFileIndexHigh &&
	                  validated_info.nFileIndexLow == candidate_info.nFileIndexLow;
	CloseHandle(candidate);
	return same;
}
#endif

bool ValidApp0ElfPath(const std::string& path) {
	if (!path.starts_with("/app0/") || path.size() <= 6 || path.find('\\') != std::string::npos ||
	    path.find(':') != std::string::npos)
		return false;
	const auto parsed = Common::PathFromUtf8(path);
	for (const auto& component: parsed) {
		if (component == "." || component == "..") return false;
	}
	return true;
}

bool SameHostPath(const std::filesystem::path& first, const std::filesystem::path& second) {
	if (first.empty() || second.empty()) return false;
	std::error_code first_error;
	std::error_code second_error;
	const auto      first_actual  = std::filesystem::weakly_canonical(first, first_error);
	const auto      second_actual = std::filesystem::weakly_canonical(second, second_error);
	if (first_error || second_error) return false;
#if defined(_WIN32)
	return Common::EqualNoCase(Common::PathToGenericString(first_actual),
	                           Common::PathToGenericString(second_actual));
#else
	return first_actual == second_actual;
#endif
}

void TransferConfig(Json& json, Config::ConfigOptions& config, bool encode) {
	auto transfer = [&](const char* key, auto& value) {
		if (encode)
			json[key] = value;
		else
			json.at(key).get_to(value);
	};
#define TRANSFER_CONFIG_FIELD(field) transfer(#field, config.field)
	TRANSFER_CONFIG_FIELD(screen_width);
	TRANSFER_CONFIG_FIELD(screen_height);
	TRANSFER_CONFIG_FIELD(user_name);
	TRANSFER_CONFIG_FIELD(user_id);
	TRANSFER_CONFIG_FIELD(audio_input_device);
	TRANSFER_CONFIG_FIELD(controller_speaker_volume);
	TRANSFER_CONFIG_FIELD(controller_vibration_intensity);
	TRANSFER_CONFIG_FIELD(present_mode);
	TRANSFER_CONFIG_FIELD(gpu_index);
	TRANSFER_CONFIG_FIELD(fullscreen_enabled);
	TRANSFER_CONFIG_FIELD(hide_cursor_enabled);
	TRANSFER_CONFIG_FIELD(vr_enabled);
	TRANSFER_CONFIG_FIELD(amd_cpu_enabled);
	TRANSFER_CONFIG_FIELD(vblank_frequency);
	TRANSFER_CONFIG_FIELD(console_language);
	TRANSFER_CONFIG_FIELD(vulkan_validation_enabled);
	TRANSFER_CONFIG_FIELD(shader_validation_enabled);
	TRANSFER_CONFIG_FIELD(shader_optimization_type);
	TRANSFER_CONFIG_FIELD(shader_log_direction);
	TRANSFER_CONFIG_FIELD(command_buffer_dump_enabled);
	TRANSFER_CONFIG_FIELD(graphics_debug_dump_enabled);
	TRANSFER_CONFIG_FIELD(printf_direction);
	TRANSFER_CONFIG_FIELD(profiler_enabled);
	TRANSFER_CONFIG_FIELD(spirv_debug_printf_enabled);
	TRANSFER_CONFIG_FIELD(gpu_assisted_validation_enabled);
	TRANSFER_CONFIG_FIELD(renderdoc_enabled);
	TRANSFER_CONFIG_FIELD(readback_linear_images);
	TRANSFER_CONFIG_FIELD(tessellation_enabled);
	TRANSFER_CONFIG_FIELD(trophy_enabled);
	TRANSFER_CONFIG_FIELD(playgo_hack_enabled);
	TRANSFER_CONFIG_FIELD(keymap);
#if defined(_WIN32)
	TRANSFER_CONFIG_FIELD(red_zone_protection_enabled);
#endif
#undef TRANSFER_CONFIG_FIELD
	auto path = [&](const char* key, std::filesystem::path& value) {
		if (encode)
			json[key] = Common::PathToString(value);
		else
			value = std::filesystem::u8path(json.at(key).get<std::string>());
	};
	path("shader_log_folder", config.shader_log_folder);
	path("command_buffer_dump_folder", config.command_buffer_dump_folder);
	path("printf_output_file", config.printf_output_file);
	if (encode) {
		json["controller_color"] =
		    config.controller_color ? Json(*config.controller_color) : Json();
	} else if (json.at("controller_color").is_null()) {
		config.controller_color.reset();
	} else {
		config.controller_color = json.at("controller_color").get<Config::ControllerColor>();
	}
}

#if defined(_WIN32)
constexpr uint32_t kExecMagic         = 0x45584543;
constexpr uint32_t kExecVersion       = 2;
constexpr size_t   kRequestCapacity   = 1024 * 1024;
constexpr DWORD    kPrepareTimeout    = 20000;
constexpr DWORD    kMaxPrepareTimeout = 300000;

DWORD ExecPrepareTimeout() {
	const auto* raw = std::getenv("KYTY_DIAGNOSTIC_GUEST_EXEC_PREPARE_TIMEOUT_MS");
	if (raw == nullptr) return kPrepareTimeout;
	const std::string_view value(raw);
	if (value.empty() ||
	    !std::all_of(value.begin(), value.end(), [](char ch) { return ch >= '0' && ch <= '9'; }))
		return kPrepareTimeout;
	char*      end    = nullptr;
	const auto parsed = std::strtoul(raw, &end, 10);
	if (end == raw || *end != '\0' || parsed < kPrepareTimeout || parsed > kMaxPrepareTimeout) {
		return kPrepareTimeout;
	}
	return static_cast<DWORD>(parsed);
}

struct ExecHandoff {
	uint32_t      magic;
	uint32_t      version;
	uint32_t      request_bytes;
	int32_t       error;
	uint32_t      guest_pid;
	uint32_t      parent_host_pid;
	uint32_t      child_host_pid;
	volatile LONG state;
	uint64_t      entry;
	uint64_t      stack;
	uint64_t      params;
	volatile LONG guest_exit_known;
	uint32_t      guest_wait_status;
	uint64_t      reboot_options;
	uint32_t      reboot_kind;
	uint32_t      reboot_exit_code;
	uint32_t      auth_info_present;
	uint32_t      auth_info_bytes;
	uint8_t       auth_info_sha256[AuthInfo::kDigestSize];
	uint8_t       auth_info_capture[AuthInfo::kCaptureEnvelopeSize];
	char          request[kRequestCapacity];
	volatile LONG startup_stage;
};

static_assert(offsetof(ExecHandoff, auth_info_present) == 80);
static_assert(offsetof(ExecHandoff, request) == 384);

void WipeAuthInfoSlot(ExecHandoff* shared) {
	if (shared == nullptr) return;
	SecureZeroMemory(&shared->auth_info_present,
	                 sizeof(shared->auth_info_present) + sizeof(shared->auth_info_bytes) +
	                     sizeof(shared->auth_info_sha256) + sizeof(shared->auth_info_capture));
}

void WipeRequest(ExecHandoff* shared) {
	if (shared == nullptr) return;
	const size_t size = std::min<size_t>(shared->request_bytes, kRequestCapacity);
	if (size != 0) SecureZeroMemory(shared->request, size);
	shared->request_bytes = 0;
}

void WipeJsonStrings(Json* value) {
	if (value->is_string()) {
		auto& text = value->get_ref<std::string&>();
		if (!text.empty()) SecureZeroMemory(text.data(), text.size());
		return;
	}
	if (value->is_array() || value->is_object()) {
		for (auto& child: *value)
			WipeJsonStrings(&child);
	}
}

bool WipeLegacyAuthInfoValues(Json* value) {
	bool found = false;
	if (value->is_object()) {
		for (auto child = value->begin(); child != value->end();) {
			if (child.key() == "auth_info_capture" || child.key() == "auth_info_capture_sha256") {
				WipeJsonStrings(&child.value());
				child = value->erase(child);
				found = true;
			} else {
				found = WipeLegacyAuthInfoValues(&child.value()) || found;
				++child;
			}
		}
	} else if (value->is_array()) {
		for (auto& child: *value)
			found = WipeLegacyAuthInfoValues(&child) || found;
	}
	return found;
}

int JsonHexDigit(char value) {
	if (value >= '0' && value <= '9') return value - '0';
	if (value >= 'a' && value <= 'f') return value - 'a' + 10;
	if (value >= 'A' && value <= 'F') return value - 'A' + 10;
	return -1;
}

bool HasLegacyAuthInfoJsonKey(std::string_view encoded) {
	constexpr std::string_view capture = "auth_info_capture";
	constexpr std::string_view digest  = "auth_info_capture_sha256";
	for (size_t offset = 0; offset < encoded.size();) {
		if (encoded[offset++] != '"') continue;
		bool   capture_match = true;
		bool   digest_match  = true;
		bool   valid         = true;
		bool   closed        = false;
		size_t decoded_size  = 0;
		while (offset < encoded.size()) {
			uint32_t decoded = static_cast<unsigned char>(encoded[offset++]);
			if (decoded == '"') {
				closed = true;
				break;
			}
			if (decoded == '\\') {
				if (offset == encoded.size()) {
					valid = false;
					break;
				}
				const char escape = encoded[offset++];
				switch (escape) {
					case '"': decoded = '"'; break;
					case '\\': decoded = '\\'; break;
					case '/': decoded = '/'; break;
					case 'b': decoded = '\b'; break;
					case 'f': decoded = '\f'; break;
					case 'n': decoded = '\n'; break;
					case 'r': decoded = '\r'; break;
					case 't': decoded = '\t'; break;
					case 'u': {
						if (encoded.size() - offset < 4) {
							valid  = false;
							offset = encoded.size();
							break;
						}
						decoded = 0;
						for (size_t digit = 0; digit < 4; ++digit) {
							const int value = JsonHexDigit(encoded[offset + digit]);
							if (value < 0)
								valid = false;
							else
								decoded = (decoded << 4) | static_cast<uint32_t>(value);
						}
						offset += 4;
						break;
					}
					default:
						valid   = false;
						decoded = 0xffffffffu;
						break;
				}
			} else if (decoded < 0x20) {
				valid = false;
			}
			if (decoded_size >= capture.size() ||
			    decoded != static_cast<unsigned char>(capture[decoded_size])) {
				capture_match = false;
			}
			if (decoded_size >= digest.size() ||
			    decoded != static_cast<unsigned char>(digest[decoded_size])) {
				digest_match = false;
			}
			++decoded_size;
		}
		if (!closed) return false;
		size_t next = offset;
		while (next < encoded.size() && (encoded[next] == ' ' || encoded[next] == '\t' ||
		                                 encoded[next] == '\r' || encoded[next] == '\n'))
			++next;
		if (valid && next < encoded.size() && encoded[next] == ':' &&
		    ((capture_match && decoded_size == capture.size()) ||
		     (digest_match && decoded_size == digest.size())))
			return true;
	}
	return false;
}

struct SensitiveCapture {
	AuthInfo::Capture value {};

	~SensitiveCapture() { Clear(); }
	void Clear() { SecureZeroMemory(&value, sizeof(value)); }
};

struct SensitiveAuthInfoSlot {
	uint32_t                                            present = 0;
	uint32_t                                            bytes   = 0;
	AuthInfo::Digest                                    sha256 {};
	std::array<uint8_t, AuthInfo::kCaptureEnvelopeSize> capture {};

	~SensitiveAuthInfoSlot() { Clear(); }
	void Clear() { SecureZeroMemory(this, sizeof(*this)); }
};

struct SensitiveString {
	std::string value;

	~SensitiveString() { Clear(); }
	void Clear() {
		if (!value.empty()) SecureZeroMemory(value.data(), value.size());
		value.clear();
	}
};

struct HostImage {
	HANDLE       mapping      = nullptr;
	HANDLE       prepared     = nullptr;
	HANDLE       release      = nullptr;
	HANDLE       process      = nullptr;
	HANDLE       job          = nullptr;
	HANDLE       monitor_gate = nullptr;
	ExecHandoff* shared       = nullptr;
	bool         committed    = false;

	~HostImage() {
		if (shared != nullptr) {
			WipeAuthInfoSlot(shared);
			WipeRequest(shared);
			UnmapViewOfFile(shared);
		}
		for (auto handle: {mapping, prepared, release, process, job, monitor_gate}) {
			if (handle != nullptr && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
		}
	}
};

std::shared_ptr<HostImage>                g_child_image;
std::mutex                                g_images_mutex;
std::map<int, std::shared_ptr<HostImage>> g_images;

struct ExecChildPhase {
	uint32_t stage;
	uint64_t monotonic_ms;
};

ExecChildPhase g_child_phases[16];
size_t         g_child_phase_count  = 0;
size_t         g_child_phase_logged = 0;
uint64_t       g_child_start_ms     = 0;

std::wstring ObjectName(const std::string& token, const wchar_t* suffix) {
	return L"Local\\KytyExec_" + std::wstring(token.begin(), token.end()) + suffix;
}

std::wstring Quote(const std::wstring& value) {
	std::wstring result  = L"\"";
	size_t       slashes = 0;
	for (wchar_t character: value) {
		if (character == L'\\') {
			++slashes;
			continue;
		}
		result.append(slashes * (character == L'"' ? 2 : 1), L'\\');
		slashes = 0;
		if (character == L'"') result += L'\\';
		result += character;
	}
	result.append(slashes * 2, L'\\');
	result += L'"';
	return result;
}

bool IsAuthInfoEnvironmentKey(std::wstring_view key) {
	const auto matches = [key](const wchar_t* base) {
		const size_t size = std::wcslen(base);
		return key.size() >= size && _wcsnicmp(key.data(), base, size) == 0 &&
		       (key.size() == size || key[size] == L'_');
	};
	return matches(L"KYTY_PS5_CAPTURED_AUTHINFO") || matches(L"KYTY_PS5_CAPTURED_AUTHINFO_SHA256");
}

bool StripAuthInfoEnvironment() {
	auto* block = GetEnvironmentStringsW();
	if (block == nullptr) return false;
	std::vector<std::wstring> names;
	for (const auto* item = block; *item != 0; item += std::wcslen(item) + 1) {
		const std::wstring_view entry(item);
		const auto              equal = entry.find(L'=', entry[0] == L'=' ? 1 : 0);
		if (equal != std::wstring_view::npos && IsAuthInfoEnvironmentKey(entry.substr(0, equal))) {
			names.emplace_back(entry.substr(0, equal));
		}
	}
	FreeEnvironmentStringsW(block);
	for (const auto& name: names) {
		if (_wputenv_s(name.c_str(), L"") != 0) return false;
	}
	return true;
}

bool NewToken(std::string* token) {
	std::array<unsigned char, 16> bytes {};
	if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
	                    BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
		return false;
	constexpr char digits[] = "0123456789abcdef";
	token->clear();
	for (auto byte: bytes) {
		token->push_back(digits[byte >> 4]);
		token->push_back(digits[byte & 15]);
	}
	return true;
}

int ValidateOriginalSelf(const std::filesystem::path& original,
                         const std::filesystem::path& host_path, bool retain_image_locks,
                         AuthInfo::ImageIdentity* identity, std::string* reason) {
	*identity = {};
#if defined(_WIN32)
	HANDLE self_handle = INVALID_HANDLE_VALUE;
	HANDLE elf_handle  = INVALID_HANDLE_VALUE;
#endif
	auto fail = [&](const char* message) {
#if defined(_WIN32)
		if (self_handle != INVALID_HANDLE_VALUE) CloseHandle(self_handle);
		if (elf_handle != INVALID_HANDLE_VALUE) CloseHandle(elf_handle);
#endif
		*reason = message;
		return KERNEL_ERROR_ENOEXEC;
	};
	std::error_code error;
#if defined(_WIN32)
	self_handle = CreateFileW(original.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
	                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	LARGE_INTEGER self_length {};
	if (self_handle == INVALID_HANDLE_VALUE || !GetFileSizeEx(self_handle, &self_length) ||
	    self_length.QuadPart < 0) {
		return fail("original SELF size unavailable");
	}
	const auto self_size = static_cast<uint64_t>(self_length.QuadPart);
#else
	const auto self_size = std::filesystem::file_size(original, error);
	if (error) return fail("original SELF size unavailable");
#endif
	if (self_size > std::numeric_limits<size_t>::max() ||
	    self_size > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
		return fail("original SELF too large");
	}
	std::vector<uint8_t> self(static_cast<size_t>(self_size));
#if defined(_WIN32)
	size_t self_read = 0;
	while (self_read != self.size()) {
		const auto  remaining = self.size() - self_read;
		const DWORD requested =
		    static_cast<DWORD>(std::min<size_t>(remaining, std::numeric_limits<DWORD>::max()));
		DWORD count = 0;
		if (!ReadFile(self_handle, self.data() + self_read, requested, &count, nullptr) ||
		    count != requested) {
			return fail("original SELF changed while reading");
		}
		self_read += count;
	}
	LARGE_INTEGER retained_self_length {};
	if (!GetFileSizeEx(self_handle, &retained_self_length) ||
	    retained_self_length.QuadPart != self_length.QuadPart) {
		return fail("original SELF changed while reading");
	}
#else
	std::ifstream self_file(original, std::ios::binary);
	if (!self_file ||
	    (self_size != 0 && !self_file.read(reinterpret_cast<char*>(self.data()),
	                                       static_cast<std::streamsize>(self.size()))) ||
	    self_file.peek() != std::char_traits<char>::eof())
		return fail("original SELF changed while reading");
#endif
	uint64_t             elf_size = 0;
	std::vector<uint8_t> elf;
#if defined(_WIN32)
	elf_handle = CreateFileW(host_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
	                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	LARGE_INTEGER elf_length {};
	if (elf_handle == INVALID_HANDLE_VALUE || !GetFileSizeEx(elf_handle, &elf_length) ||
	    elf_length.QuadPart < 0 ||
	    static_cast<uint64_t>(elf_length.QuadPart) > std::numeric_limits<size_t>::max()) {
		return fail("exec ELF snapshot unavailable");
	}
	elf_size = static_cast<uint64_t>(elf_length.QuadPart);
	elf.resize(static_cast<size_t>(elf_size));
	size_t elf_read = 0;
	while (elf_read != elf.size()) {
		const auto  remaining = elf.size() - elf_read;
		const DWORD requested =
		    static_cast<DWORD>(std::min<size_t>(remaining, std::numeric_limits<DWORD>::max()));
		DWORD count = 0;
		if (!ReadFile(elf_handle, elf.data() + elf_read, requested, &count, nullptr) ||
		    count != requested) {
			return fail("exec ELF snapshot read failed");
		}
		elf_read += count;
	}
	LARGE_INTEGER retained_length {};
	if (!GetFileSizeEx(elf_handle, &retained_length) ||
	    retained_length.QuadPart != elf_length.QuadPart) {
		return fail("exec ELF changed while reading");
	}
#else
	const auto file_size = std::filesystem::file_size(host_path, error);
	if (error || file_size > std::numeric_limits<size_t>::max() ||
	    file_size > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max())) {
		return fail("exec ELF size unavailable");
	}
	elf_size = file_size;
	elf.resize(static_cast<size_t>(elf_size));
	std::ifstream elf_file(host_path, std::ios::binary);
	if (!elf_file ||
	    (elf_size != 0 && !elf_file.read(reinterpret_cast<char*>(elf.data()),
	                                     static_cast<std::streamsize>(elf.size()))) ||
	    elf_file.peek() != std::char_traits<char>::eof())
		return fail("exec ELF changed while reading");
#endif
	if (!AuthInfo::ValidateImageIdentity(self.data(), self.size(), elf.data(), elf.size(), identity,
	                                     reason)) {
#if defined(_WIN32)
		CloseHandle(self_handle);
		self_handle = INVALID_HANDLE_VALUE;
		if (elf_handle != INVALID_HANDLE_VALUE) CloseHandle(elf_handle);
#endif
		return KERNEL_ERROR_ENOEXEC;
	}
#if defined(_WIN32)
	if (retain_image_locks) {
		if (g_validated_original_self != INVALID_HANDLE_VALUE)
			CloseHandle(g_validated_original_self);
		if (g_validated_exec_elf != INVALID_HANDLE_VALUE) CloseHandle(g_validated_exec_elf);
		g_validated_original_self = self_handle;
		g_validated_exec_elf      = elf_handle;
		self_handle               = INVALID_HANDLE_VALUE;
		elf_handle                = INVALID_HANDLE_VALUE;
	} else {
		CloseHandle(self_handle);
		self_handle = INVALID_HANDLE_VALUE;
		CloseHandle(elf_handle);
		elf_handle = INVALID_HANDLE_VALUE;
	}
#else
	(void)retain_image_locks;
#endif
	return 0;
}

int ResolveOriginalSelf(const std::string& guest_path, const std::filesystem::path& host_path,
                        const std::filesystem::path& system_root, std::string_view prefix,
                        std::filesystem::path* original, AuthInfo::ImageIdentity* identity,
                        std::string* reason) {
	original->clear();
	*identity = {};
	if (!guest_path.starts_with(prefix)) return 0;
	const auto suffix = guest_path.substr(prefix.size());
	auto       fail   = [&](int error, const char* message) {
		*reason = message;
		return error;
	};
	if (suffix.empty() || suffix.find_first_of("\\:") != std::string::npos ||
	    suffix.find('\0') != std::string::npos) {
		return fail(KERNEL_ERROR_EINVAL, "invalid /system path");
	}
	size_t start = 0;
	while (start < suffix.size()) {
		const auto end       = suffix.find('/', start);
		const auto component = suffix.substr(start, end == std::string::npos ? end : end - start);
		if (component.empty() || component == "." || component == ".." || component.back() == '.' ||
		    component.back() == ' ')
			return fail(KERNEL_ERROR_EINVAL, "unsafe /system path component");
		if (end == std::string::npos) break;
		start = end + 1;
	}
	if (suffix.back() == '/') return fail(KERNEL_ERROR_EINVAL, "empty /system filename");
	std::error_code error;
	const auto      root = std::filesystem::canonical(system_root, error);
	if (error || !std::filesystem::is_directory(root, error))
		return fail(KERNEL_ERROR_EINVAL, "original SELF system root unavailable");
	const auto candidate =
	    std::filesystem::canonical(root / std::filesystem::u8path(suffix), error);
	if (error) return fail(KERNEL_ERROR_ENOENT, "mapped original SELF unavailable");
	auto root_part      = root.begin();
	auto candidate_part = candidate.begin();
	while (root_part != root.end() && candidate_part != candidate.end() &&
	       _wcsicmp(root_part->c_str(), candidate_part->c_str()) == 0) {
		++root_part;
		++candidate_part;
	}
	if (root_part != root.end() || candidate_part == candidate.end())
		return fail(KERNEL_ERROR_EINVAL, "mapped SELF escapes system root");
	if (!std::filesystem::is_regular_file(candidate, error))
		return fail(KERNEL_ERROR_ENOEXEC, "mapped SELF is not a regular file");
	const int result = ValidateOriginalSelf(candidate, host_path, false, identity, reason);
	if (result == 0) *original = candidate;
	return result;
}

int StaticExecRange(const std::filesystem::path& path, const Config::ConfigOptions& config,
                    uint64_t* base, uint64_t* size) {
	*base = 0;
	*size = 0;
	std::ifstream input(path, std::ios::binary | std::ios::ate);
	if (!input) return KERNEL_ERROR_EACCES;
	const auto end = input.tellg();
	if (end < static_cast<std::streamoff>(sizeof(Loader::Elf64_Ehdr))) return KERNEL_ERROR_ENOEXEC;
	const auto file_size = static_cast<uint64_t>(end);
	input.seekg(0);
	Loader::Elf64_Ehdr header {};
	input.read(reinterpret_cast<char*>(&header), sizeof(header));
	if (!input) return KERNEL_ERROR_ENOEXEC;
	if (header.e_type != Loader::ET_EXEC) return 0;
	const uint64_t table_size = static_cast<uint64_t>(header.e_phnum) * sizeof(Loader::Elf64_Phdr);
	if (header.e_ehsize != sizeof(header) || header.e_phentsize != sizeof(Loader::Elf64_Phdr) ||
	    header.e_phnum == 0 || header.e_phoff > file_size ||
	    table_size > file_size - header.e_phoff) {
		return KERNEL_ERROR_ENOEXEC;
	}
	std::vector<Loader::Elf64_Phdr> segments(header.e_phnum);
	input.seekg(static_cast<std::streamoff>(header.e_phoff));
	input.read(reinterpret_cast<char*>(segments.data()), static_cast<std::streamsize>(table_size));
	if (!input) return KERNEL_ERROR_ENOEXEC;
	uint64_t first = UINT64_MAX;
	for (const auto& segment: segments) {
		if (segment.p_type == Loader::PT_DYNAMIC) return KERNEL_ERROR_ENOEXEC;
		if (segment.p_type == Loader::PT_LOAD && segment.p_memsz != 0) {
			first = std::min(first, segment.p_vaddr);
		}
	}
	if (first == 0 || first == UINT64_MAX || (first & 0xffff) != 0) return KERNEL_ERROR_ENOEXEC;
	uint64_t last         = first;
	bool     entry_mapped = false;
	for (const auto& segment: segments) {
		if (segment.p_memsz == 0 ||
		    (segment.p_type != Loader::PT_LOAD && segment.p_type != Loader::PT_OS_RELRO))
			continue;
		if (segment.p_filesz > segment.p_memsz || segment.p_offset > file_size ||
		    segment.p_filesz > file_size - segment.p_offset || segment.p_vaddr < first ||
		    (segment.p_align != 0 && (segment.p_align & (segment.p_align - 1)) != 0)) {
			return KERNEL_ERROR_ENOEXEC;
		}
		const uint64_t mask = segment.p_align == 0 ? 0 : segment.p_align - 1;
		if (segment.p_memsz > UINT64_MAX - mask) return KERNEL_ERROR_ENOEXEC;
		const uint64_t span = (segment.p_memsz + mask) & ~mask;
		if (span > UINT64_MAX - segment.p_vaddr) return KERNEL_ERROR_ENOEXEC;
		last = std::max(last, segment.p_vaddr + span);
		if (segment.p_type == Loader::PT_LOAD && (segment.p_flags & Loader::PF_X) != 0 &&
		    header.e_entry >= segment.p_vaddr &&
		    header.e_entry - segment.p_vaddr < segment.p_filesz) {
			entry_mapped = true;
		}
	}
	const uint64_t extra =
	    Loader::Jit::SafeCall::GetSize() +
	    (config.amd_cpu_enabled || config.red_zone_protection_enabled ? 8u * 1024u * 1024u : 0);
	const uint64_t span = last - first;
	if (!entry_mapped || span > UINT64_MAX - 0x3fff - extra - 0xffff) return KERNEL_ERROR_ENOEXEC;
	const uint64_t reserved =
	    (((span + 0x3fff) & ~uint64_t(0x3fff)) + extra + 0xffff) & ~uint64_t(0xffff);
	if (first > 0x7fffffffffff || reserved > 0x7fffffffffff - first) return KERNEL_ERROR_ENOEXEC;
	*base = first;
	*size = reserved;
	return 0;
}

std::vector<wchar_t> ChildEnvironment(int pid, const std::filesystem::path& original_self,
                                      bool static_exec) {
	auto* block = GetEnvironmentStringsW();
	if (block == nullptr) return {};
	std::vector<std::wstring> entries;
	for (const auto* item = block; *item != 0; item += std::wcslen(item) + 1) {
		std::wstring entry(item);
		const auto   equal = entry.find(L'=', entry[0] == L'=' ? 1 : 0);
		const auto   key   = entry.substr(0, equal);
		if (_wcsicmp(key.c_str(), L"KYTY_DIAGNOSTIC_GUEST_PID") == 0 ||
		    _wcsicmp(key.c_str(), L"KYTY_DIAGNOSTIC_ORIGINAL_SELF") == 0 ||
		    IsAuthInfoEnvironmentKey(key) ||
		    _wcsicmp(key.c_str(), L"KYTY_DIAGNOSTIC_MINI_SYSCORE_NATIVE_TRAPS") == 0 ||
		    _wcsicmp(key.c_str(), L"KYTY_DIAGNOSTIC_MINI_SYSCORE_LIVE_RFORK") == 0 ||
		    _wcsicmp(key.c_str(), L"KYTY_DIAGNOSTIC_STATIC_EXEC_PRE_RESERVED") == 0 ||
		    (static_exec &&
		     _wcsicmp(key.c_str(), L"KYTY_DIAGNOSTIC_NATIVE_SYSCALL_HOST_STACK") == 0) ||
		    key.find(L"SELFTEST") != std::wstring::npos)
			continue;
		entries.push_back(std::move(entry));
	}
	FreeEnvironmentStringsW(block);
	entries.push_back(L"KYTY_DIAGNOSTIC_GUEST_PID=" + std::to_wstring(pid));
	if (static_exec) {
		entries.push_back(L"KYTY_DIAGNOSTIC_STATIC_EXEC_PRE_RESERVED=1");
		entries.push_back(L"KYTY_DIAGNOSTIC_NATIVE_SYSCALL_HOST_STACK=1");
	}
	if (!original_self.empty())
		entries.push_back(L"KYTY_DIAGNOSTIC_ORIGINAL_SELF=" + original_self.wstring());
	std::sort(entries.begin(), entries.end(), [](const auto& lhs, const auto& rhs) {
		return _wcsicmp(lhs.c_str(), rhs.c_str()) < 0;
	});
	std::vector<wchar_t> result;
	for (const auto& entry: entries) {
		result.insert(result.end(), entry.begin(), entry.end());
		result.push_back(0);
	}
	result.push_back(0);
	return result;
}

int AbortPreparation(const std::shared_ptr<HostImage>& image, int error) {
	if (image->process != nullptr && WaitForSingleObject(image->process, 0) == WAIT_TIMEOUT) {
		TerminateProcess(image->process, static_cast<UINT>(error));
		WaitForSingleObject(image->process, 5000);
	}
	return error;
}

void ReportChildError(int error) {
	if (!g_child_image) return;
	g_child_image->shared->error = error;
	InterlockedExchange(&g_child_image->shared->state, 2);
	SetEvent(g_child_image->prepared);
}

const char* StartupStageName(LONG stage) {
	switch (stage) {
		case 0: return "not_started";
		case 1: return "handoff_mapped";
		case 2: return "request_accepted";
		case 3: return "runtime_init";
		case 4: return "log_opened";
		case 5: return "runtime_ready";
		case 6: return "fs_ready";
		case 7: return "main_image_loaded";
		case 8: return "needed_modules";
		case 9: return "reloc_done";
		case 10: return "commit_wait";
		case 11: return "released";
		case 12: return "modules_started";
		default: return "unknown";
	}
}

// Child stdout/stderr is all there is before the child log opens; keep its tail.
struct ChildOutput {
	HANDLE      read = nullptr;
	HANDLE      done = nullptr;
	std::mutex  mutex;
	std::string tail;
	uint64_t    total = 0;

	~ChildOutput() {
		if (read != nullptr) CloseHandle(read);
		if (done != nullptr) CloseHandle(done);
	}
};

constexpr size_t kChildOutputTail = 4096;

void DrainChildOutput(const std::shared_ptr<ChildOutput>& output) {
	// Forward to the console, not our own stdout: that is a pipe in nested children and may carry
	// JSON in tools.
	const HANDLE console =
	    CreateFileW(L"CONOUT$", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
		            OPEN_EXISTING, 0, nullptr);
	char  buffer[1024];
	DWORD bytes = 0;
	while (ReadFile(output->read, buffer, sizeof(buffer), &bytes, nullptr) && bytes != 0) {
		{
			std::lock_guard lock(output->mutex);
			output->total += bytes;
			output->tail.append(buffer, bytes);
			if (output->tail.size() > kChildOutputTail)
				output->tail.erase(0, output->tail.size() - kChildOutputTail);
		}
		// A console write can stall (QuickEdit selection), so the tail is recorded first.
		if (console != INVALID_HANDLE_VALUE) {
			DWORD written = 0;
			WriteFile(console, buffer, bytes, &written, nullptr);
		}
	}
	if (console != INVALID_HANDLE_VALUE) CloseHandle(console);
	SetEvent(output->done);
}

std::string EscapeChildOutput(const std::string& text) {
	std::string result;
	char        hex[8];
	for (unsigned char ch: text) {
		if (ch == '\n') {
			result += "\\n";
		} else if (ch == '\\' || ch == '"') {
			result += '\\';
			result += static_cast<char>(ch);
		} else if (ch >= 0x20 && ch < 0x7f) {
			result += static_cast<char>(ch);
		} else if (ch != '\r') {
			std::snprintf(hex, sizeof(hex), "\\x%02x", ch);
			result += hex;
		}
	}
	return result;
}

void LogChildStartupFailure(int pid, const std::shared_ptr<HostImage>& image,
                            const std::shared_ptr<ChildOutput>& output, int error) {
	const auto  stage     = InterlockedCompareExchange(&image->shared->startup_stage, 0, 0);
	const char* outcome   = "killed_by_parent";
	DWORD       exit_code = static_cast<DWORD>(error);
	if (WaitForSingleObject(image->process, 0) == WAIT_OBJECT_0) {
		GetExitCodeProcess(image->process, &exit_code);
		outcome = exit_code >= 0xC0000000u ? "crashed" : "exited";
	}
	AbortPreparation(image, error);
	WaitForSingleObject(output->done, 1000);
	std::string tail;
	uint64_t    total = 0;
	{
		std::lock_guard lock(output->mutex);
		tail  = output->tail;
		total = output->total;
	}
	LOGF("GUEST_EXEC_CHILD_DIAGNOSTIC guest_pid=%d host_pid=%lu created=1 startup_stage=%ld(%s) "
	     "outcome=%s"
	     " exit_code=0x%08lx output_bytes=%llu output_truncated=%d\n",
	     pid, image->shared->child_host_pid, stage, StartupStageName(stage), outcome, exit_code,
	     static_cast<unsigned long long>(total), total > tail.size() ? 1 : 0);
	if (!tail.empty())
		LOGF("GUEST_EXEC_CHILD_OUTPUT guest_pid=%d text=\"%s\"\n", pid,
		     EscapeChildOutput(tail).c_str());
}
#endif
} // namespace

uint32_t ExecPrepareTimeoutForTests() {
#if defined(_WIN32)
	return ExecPrepareTimeout();
#else
	return 0;
#endif
}

void ConfigureExecRuntime(const Emulator::RunOptions& options) {
	g_options = options;
#if defined(_WIN32)
	if (std::getenv("KYTY_DIAGNOSTIC_GUEST_EXECVE") != nullptr &&
	    std::getenv("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE") == nullptr) {
		const auto scope = "exec" + std::to_string(GetCurrentProcessId());
		_putenv_s("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE", scope.c_str());
		_putenv_s("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY", "1");
	}
#endif
}

void InstallRootOriginalSelf(const Emulator::RunOptions& options) {
#if defined(_WIN32)
	// mini-syscore has no exec request, so it binds its own SELF like an exec child
	const auto* root_self = std::getenv("KYTY_DIAGNOSTIC_ORIGINAL_SELF");
	if (!options.exec_endpoint.empty() || root_self == nullptr) return;
	AuthInfo::ImageIdentity identity;
	std::string             reason;
	// options.elf is the /app0 path from --game; the host file is app0_dir/<name>
	const int error =
	    ValidateOriginalSelf(std::filesystem::u8path(root_self),
		                     options.app0_dir / options.elf.filename(), true, &identity, &reason);
	if (error != 0) {
		LOGF("ROOT_ORIGINAL_SELF_REJECTED reason=%s error=0x%08x\n", reason.c_str(),
		     static_cast<uint32_t>(error));
		EXIT("root original SELF rejected\n");
	}
	InstallVerifiedOriginalSelf(identity);
	AuthInfo::Observation observation;
	const auto result = AuthInfo::LoadObservationFromEnvironment(identity, &observation, &reason);
	if (result == AuthInfo::CaptureLoadResult::Rejected ||
	    (result == AuthInfo::CaptureLoadResult::Verified &&
	     !InstallVerifiedAuthorizationObservation(observation))) {
		LOGF("AUTHORIZATION_OBSERVATION_INPUT status=rejected root=1 reason=%s\n", reason.c_str());
		EXIT("root authorization observation rejected\n");
	}
	LOGF("ROOT_ORIGINAL_SELF_VERIFIED self_sha256=%s authority=0x%016llx observation=%s\n",
	     AuthInfo::DigestHex(identity.self_sha256).c_str(),
	     static_cast<unsigned long long>(identity.authority_id),
	     result == AuthInfo::CaptureLoadResult::Verified ? "verified" : "absent");
	if (result == AuthInfo::CaptureLoadResult::Verified) {
		LOGF("AUTHORIZATION_OBSERVATION_INPUT status=verified root=1 envelope_sha256=%s "
		     "evidence_sha256=%s"
		     " known_capability_mask=%016llx root_prison_known=%d root_prison=%d\n",
		     AuthInfo::DigestHex(observation.envelope_sha256).c_str(),
		     AuthInfo::DigestHex(observation.evidence_sha256).c_str(),
		     static_cast<unsigned long long>(observation.facts.known_capability0),
		     observation.facts.root_prison_known ? 1 : 0, observation.facts.root_prison ? 1 : 0);
	}
#endif
}

bool RootOriginalSelfIsLoadedFile(const std::filesystem::path& host_path) {
#if defined(_WIN32)
	return SameValidatedImageFile(g_validated_exec_elf, host_path);
#else
	(void)host_path;
	return false;
#endif
}

void ReleaseValidatedElfForTests() {
#if defined(_WIN32)
	if (g_validated_original_self != INVALID_HANDLE_VALUE) CloseHandle(g_validated_original_self);
	if (g_validated_exec_elf != INVALID_HANDLE_VALUE) CloseHandle(g_validated_exec_elf);
	g_validated_original_self = INVALID_HANDLE_VALUE;
	g_validated_exec_elf      = INVALID_HANDLE_VALUE;
#endif
}

bool IsExecChild() {
	return g_exec_child;
}
bool ResolveExecChildImagePath(const std::string& guest_path, std::filesystem::path* host_path) {
	if (!g_exec_child || host_path == nullptr) return false;
	try {
		const auto app0_elf = g_child_request.value("app0_elf", std::string {});
		if (app0_elf.empty() || guest_path != app0_elf) return false;
		const auto image =
		    std::filesystem::u8path(g_child_request.at("host_path").get<std::string>());
		if (image.empty()) return false;
		*host_path = image;
		return true;
	} catch (...) {
		return false;
	}
}

bool IsExecChildImagePath(const std::filesystem::path& host_path) {
	if (!g_exec_child) return false;
	try {
		if (g_child_request.value("app0_elf", std::string {}).empty()) return false;
		return SameHostPath(
		    host_path, std::filesystem::u8path(g_child_request.at("host_path").get<std::string>()));
	} catch (...) {
		return false;
	}
}

bool ResolveExecChildApp0PackageTarget(const std::string&     package_name,
                                       std::filesystem::path* app0_dir) {
	if (!g_exec_child || package_name.empty() || app0_dir == nullptr) return false;
	try {
		const auto candidate =
		    std::filesystem::u8path(g_child_request.value("app0_dir", std::string {}));
		const auto app0_elf   = g_child_request.value("app0_elf", std::string {});
		const auto guest_path = g_child_request.value("guest_path", std::string {});
		const auto original_self =
		    std::filesystem::u8path(g_child_request.value("original_self", std::string {}));
		const auto      expected_guest_path = "/system_ex/app/" + package_name + "/eboot.bin";
		std::error_code canonical_error;
		const auto      canonical = std::filesystem::weakly_canonical(candidate, canonical_error);
		std::error_code self_error;
		const bool      package_self =
		    !original_self.empty() &&
		    std::filesystem::equivalent(original_self, canonical / "eboot.bin", self_error) &&
		    !self_error;
		const bool canonical_candidate =
		    !canonical_error &&
#if defined(_WIN32)
		    Common::EqualNoCase(Common::PathToGenericString(candidate),
			                    Common::PathToGenericString(canonical));
#else
		    candidate == canonical;
#endif
		const bool matches =
		    candidate.is_absolute() && canonical_candidate && package_self &&
		    app0_elf == "/app0/eboot.bin" && guest_path == expected_guest_path &&
#if defined(_WIN32)
		    Common::EqualNoCase(Common::PathToString(candidate.filename()), package_name);
#else
		    Common::PathToString(candidate.filename()) == package_name;
#endif
		if (!matches) return false;
		*app0_dir = canonical;
		return true;
	} catch (...) {
		return false;
	}
}

bool ResolveExecChildApp0Package(const std::string& package_name, std::filesystem::path* app0_dir) {
	std::filesystem::path target;
	if (!ResolveExecChildApp0PackageTarget(package_name, &target)) return false;
	try {
		const auto original_self =
		    std::filesystem::u8path(g_child_request.value("original_self", std::string {}));
		AuthInfo::ImageIdentity identity {};
		AuthInfo::Digest        expected_self {};
		AuthInfo::Digest        expected_elf {};
		const bool              exact_identity =
		    GetVerifiedOriginalSelfIdentity(&identity) && identity.self_size == 9425466 &&
		    identity.elf_size == 21878316 &&
		    AuthInfo::ParseDigestHex(
		        "73fd5ed27d0341620f7431598f2828f7206665b39675739dec942740bd703130",
		        &expected_self) &&
		    AuthInfo::ParseDigestHex(
		        "7c0c5df979adf0945ee9385a67b77c50af461511bc5d8719939d34141093d3f5",
		        &expected_elf) &&
		    identity.self_sha256 == expected_self && identity.elf_sha256 == expected_elf;
#if defined(_WIN32)
		const bool retained_self = SameValidatedImageFile(g_validated_original_self, original_self);
#else
		const bool retained_self = true;
#endif
		if (!retained_self || !exact_identity) return false;
		*app0_dir = target;
		return true;
	} catch (...) {
		return false;
	}
}

bool IsExecChildApp0Package(const std::string& package_name) {
	std::filesystem::path app0_dir;
	return ResolveExecChildApp0Package(package_name, &app0_dir);
}
const std::vector<std::string>& GetExecChildArguments() {
	return g_arguments;
}
const std::vector<std::string>& GetExecChildEnvironment() {
	return g_environment;
}

void RecordSpawnSandbox(int pid, const std::string* root, const std::string* word) {
	std::lock_guard lock(g_spawn_sandbox_mutex);
	auto&           sandbox = g_spawn_sandboxes[pid];
	if (root != nullptr) sandbox.first = *root;
	if (word != nullptr) sandbox.second = *word;
}

std::string GetExecChildSandboxWord() {
	if (!g_exec_child) return {};
	return g_child_request.value("sandbox_word", std::string {});
}

bool InitializeExecChild(const std::string& endpoint) {
#if defined(_WIN32)
	g_child_start_ms = GetTickCount64();
	// an abort before the child log opens has to reach the parent's pipe, not a dialog
	setvbuf(stdout, nullptr, _IONBF, 0);
	_set_abort_behavior(0, _CALL_REPORTFAULT);
#if defined(_DEBUG)
	_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
	_CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
	_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
	_CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
#endif
	ClearVerifiedOriginalSelf();
	struct ChildIdentityGuard {
		bool committed = false;
		~ChildIdentityGuard() {
			if (!committed) ClearVerifiedOriginalSelf();
		}
	} identity_guard;
	if (endpoint.size() != 32 || !std::all_of(endpoint.begin(), endpoint.end(), [](char ch) {
		    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
	    }))
		return false;
	if (!StripAuthInfoEnvironment()) return false;
	auto image = std::make_shared<HostImage>();
	image->mapping =
	    OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, ObjectName(endpoint, L"_map").c_str());
	image->prepared =
	    OpenEventW(EVENT_MODIFY_STATE, FALSE, ObjectName(endpoint, L"_prepared").c_str());
	image->release = OpenEventW(SYNCHRONIZE, FALSE, ObjectName(endpoint, L"_release").c_str());
	if (!image->mapping || !image->prepared || !image->release) return false;
	image->shared = static_cast<ExecHandoff*>(
	    MapViewOfFile(image->mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ExecHandoff)));
	if (!image->shared || image->shared->magic != kExecMagic ||
	    image->shared->version != kExecVersion ||
	    image->shared->request_bytes >= kRequestCapacity ||
	    image->shared->child_host_pid != GetCurrentProcessId())
		return false;
	SensitiveAuthInfoSlot auth_info_slot;
	auth_info_slot.present = image->shared->auth_info_present;
	auth_info_slot.bytes   = image->shared->auth_info_bytes;
	std::memcpy(auth_info_slot.sha256.data(), image->shared->auth_info_sha256,
	            auth_info_slot.sha256.size());
	std::memcpy(auth_info_slot.capture.data(), image->shared->auth_info_capture,
	            auth_info_slot.capture.size());
	WipeAuthInfoSlot(image->shared);
	g_child_image = image;
	MarkExecChildStartupStage(1);
	SensitiveString encoded_request;
	try {
		encoded_request.value.assign(image->shared->request,
		                             image->shared->request + image->shared->request_bytes);
		WipeRequest(image->shared);
		if (HasLegacyAuthInfoJsonKey(encoded_request.value)) {
			encoded_request.Clear();
			LOGF("AUTHINFO_CAPTURE_HANDOFF provenance=exec status=rejected "
			     "reason=legacy_json_fields\n");
			ReportChildError(KERNEL_ERROR_ENOEXEC);
			return false;
		}
		Json request = Json::parse(encoded_request.value);
		encoded_request.Clear();
		if (WipeLegacyAuthInfoValues(&request)) {
			LOGF("AUTHINFO_CAPTURE_HANDOFF provenance=exec status=rejected "
			     "reason=legacy_json_fields\n");
			ReportChildError(KERNEL_ERROR_ENOEXEC);
			return false;
		}
		auto       arguments   = request.at("argv").get<std::vector<std::string>>();
		auto       environment = request.at("envp").get<std::vector<std::string>>();
		const auto pid         = request.at("guest_pid").get<int>();
		if (pid <= 0 || static_cast<uint32_t>(pid) != image->shared->guest_pid) {
			ReportChildError(KERNEL_ERROR_EINVAL);
			return false;
		}
		const auto host_path = std::filesystem::u8path(request.at("host_path").get<std::string>());
		const auto app0_dir_text = request.value("app0_dir", std::string {});
		const auto app0_elf      = request.value("app0_elf", std::string {});
		std::error_code path_error;
		const bool      has_app0 = !app0_dir_text.empty() || !app0_elf.empty();
		if (host_path.empty() || !std::filesystem::is_regular_file(host_path, path_error) ||
		    path_error || (has_app0 && (app0_dir_text.empty() || app0_elf.empty()))) {
			ReportChildError(KERNEL_ERROR_ENOEXEC);
			return false;
		}
		if (has_app0) {
			const auto app0_dir = std::filesystem::u8path(app0_dir_text);
			path_error.clear();
			if (!app0_dir.is_absolute() || !std::filesystem::is_directory(app0_dir, path_error) ||
			    path_error || !ValidApp0ElfPath(app0_elf)) {
				ReportChildError(KERNEL_ERROR_ENOEXEC);
				return false;
			}
		}
		const auto original_self =
		    std::filesystem::u8path(request.value("original_self", std::string {}));
		const bool slot_empty =
		    auth_info_slot.present == 0 && auth_info_slot.bytes == 0 &&
		    std::all_of(auth_info_slot.sha256.begin(), auth_info_slot.sha256.end(),
			            [](uint8_t byte) { return byte == 0; }) &&
		    std::all_of(auth_info_slot.capture.begin(), auth_info_slot.capture.end(),
			            [](uint8_t byte) { return byte == 0; });
		const bool has_capture =
		    auth_info_slot.present == 1 && auth_info_slot.bytes == AuthInfo::kCaptureEnvelopeSize;
		if ((!slot_empty && !has_capture) || (has_capture && original_self.empty())) {
			auth_info_slot.Clear();
			LOGF("AUTHINFO_CAPTURE_HANDOFF provenance=exec status=rejected "
			     "reason=binding_missing\n");
			ReportChildError(KERNEL_ERROR_ENOEXEC);
			return false;
		}
		AuthInfo::ImageIdentity self_identity;
		if (!original_self.empty()) {
			std::string reason;
			const int   error =
			    ValidateOriginalSelf(original_self, host_path, true, &self_identity, &reason);
			if (error != 0) {
				LOGF("GUEST_EXEC_ORIGINAL_SELF_REJECTED guest_pid=%d reason=%s error=0x%08x\n", pid,
				     reason.c_str(), static_cast<uint32_t>(error));
				ReportChildError(error);
				return false;
			}
			InstallVerifiedOriginalSelf(self_identity);
		}
		if (has_capture) {
			SensitiveCapture capture;
			std::string      reason;
			const bool       decoded = AuthInfo::ParseCaptureEnvelope(
			    auth_info_slot.capture.data(), auth_info_slot.capture.size(), auth_info_slot.sha256,
			    self_identity.self_sha256, self_identity.elf_sha256, self_identity.authority_id,
			    &capture.value, &reason);
			auth_info_slot.Clear();
			if (decoded && !InstallVerifiedAuthInfo(capture.value))
				reason = "verified identity mismatch";
			if (!decoded || reason != "verified") {
				capture.Clear();
				LOGF("AUTHINFO_CAPTURE_HANDOFF provenance=exec status=rejected reason=%s\n",
				     reason.c_str());
				ReportChildError(KERNEL_ERROR_ENOEXEC);
				return false;
			}
			const auto envelope = AuthInfo::DigestHex(capture.value.envelope_sha256);
			const auto self     = AuthInfo::DigestHex(capture.value.self_sha256);
			const auto elf      = AuthInfo::DigestHex(capture.value.elf_sha256);
			capture.Clear();
			LOGF("AUTHINFO_CAPTURE_HANDOFF provenance=exec envelope_sha256=%s self_sha256=%s "
			     "elf_sha256=%s status=verified\n",
			     envelope.c_str(), self.c_str(), elf.c_str());
		} else {
			auth_info_slot.Clear();
			ClearVerifiedAuthInfo();
		}
		if (request.contains("authorization_observation")) {
			const auto&      source = request.at("authorization_observation");
			const auto&      bytes  = source.at("bytes");
			AuthInfo::Digest digest;
			if (original_self.empty() || !bytes.is_array() ||
			    bytes.size() != AuthInfo::kObservationSize ||
			    !AuthInfo::ParseDigestHex(source.at("sha256").get<std::string>(), &digest)) {
				ReportChildError(KERNEL_ERROR_ENOEXEC);
				return false;
			}
			std::array<uint8_t, AuthInfo::kObservationSize> encoded {};
			for (size_t i = 0; i != encoded.size(); ++i) {
				if (!bytes[i].is_number_unsigned() || bytes[i].get<uint64_t>() > 255) {
					ReportChildError(KERNEL_ERROR_ENOEXEC);
					return false;
				}
				encoded[i] = bytes[i].get<uint8_t>();
			}
			AuthInfo::Observation observation;
			std::string           reason;
			if (!AuthInfo::ParseObservation(encoded.data(), encoded.size(), digest, self_identity,
			                                &observation, &reason) ||
			    !InstallVerifiedAuthorizationObservation(observation)) {
				LOGF("AUTHORIZATION_OBSERVATION_HANDOFF status=rejected reason=%s\n",
				     reason.c_str());
				ReportChildError(KERNEL_ERROR_ENOEXEC);
				return false;
			}
			LOGF("AUTHORIZATION_OBSERVATION_HANDOFF status=verified envelope_sha256=%s "
			     "evidence_sha256=%s"
			     " known_capability_mask=%016llx root_prison_known=%d root_prison=%d\n",
			     AuthInfo::DigestHex(digest).c_str(),
			     AuthInfo::DigestHex(observation.evidence_sha256).c_str(),
			     static_cast<unsigned long long>(observation.facts.known_capability0),
			     observation.facts.root_prison_known ? 1 : 0,
			     observation.facts.root_prison ? 1 : 0);
		}
		if (_wputenv_s(L"KYTY_DIAGNOSTIC_ORIGINAL_SELF", original_self.c_str()) != 0) {
			ReportChildError(KERNEL_ERROR_EINVAL);
			return false;
		}
		_putenv_s("KYTY_DIAGNOSTIC_GUEST_PID", std::to_string(pid).c_str());
		if (const char* readback = std::getenv("KYTY_DIAGNOSTIC_PRESENT_READBACK")) {
			const std::string prefix = std::string(readback) + ".pid-" + std::to_string(pid);
			_putenv_s("KYTY_DIAGNOSTIC_PRESENT_READBACK", prefix.c_str());
		}
		g_arguments   = std::move(arguments);
		g_environment = std::move(environment);
		g_child_request.swap(request);
		g_exec_child             = true;
		identity_guard.committed = true;
		MarkExecChildStartupStage(2);
		return true;
	} catch (...) {
		WipeRequest(image->shared);
		ReportChildError(KERNEL_ERROR_EINVAL);
	}
#endif
	return false;
}

void MarkExecChildStartupStage(uint32_t stage) {
#if defined(_WIN32)
	if (!g_child_image) return;
	InterlockedExchange(&g_child_image->shared->startup_stage, static_cast<LONG>(stage));
	if (g_child_phase_count < std::size(g_child_phases)) {
		g_child_phases[g_child_phase_count++] = {stage, GetTickCount64()};
		if (stage >= 4) {
			while (g_child_phase_logged < g_child_phase_count) {
				const auto& phase = g_child_phases[g_child_phase_logged++];
				LOGF("EXEC_PHASE stage=%u(%s) monotonic_ms=%llu elapsed_ms=%llu\n", phase.stage,
				     StartupStageName(static_cast<LONG>(phase.stage)),
				     static_cast<unsigned long long>(phase.monotonic_ms),
				     static_cast<unsigned long long>(phase.monotonic_ms - g_child_start_ms));
			}
		}
	}
#else
	(void)stage;
#endif
}

void ApplyExecChildOptions(Emulator::RunOptions* options) {
	if (!g_exec_child || options == nullptr) return;
	TransferConfig(g_child_request["config"], options->config, false);
	const auto host_path =
	    std::filesystem::u8path(g_child_request.at("host_path").get<std::string>());
	const auto app0_dir = g_child_request.value("app0_dir", std::string {});
	const auto app0_elf = g_child_request.value("app0_elf", std::string {});
	if (!app0_dir.empty() && !app0_elf.empty()) {
		options->app0_dir = std::filesystem::u8path(app0_dir);
		options->elf      = Common::PathFromUtf8(app0_elf);
		LOGF("GUEST_EXEC_APP0_PROVIDER root=%s elf=%s image=%s\n",
		     Common::PathToString(options->app0_dir).c_str(), app0_elf.c_str(),
		     Common::PathToString(host_path).c_str());
	} else {
		options->app0_dir = host_path.parent_path();
		options->elf      = std::filesystem::path("/app0") / host_path.filename();
	}
	options->sysroot_dir =
	    std::filesystem::u8path(g_child_request.at("sysroot").get<std::string>());
	options->game_patch.clear();
}

bool InstallExecChildDescriptors() {
	if (!g_exec_child) return true;
	const int result =
	    FileSystem::ImportExecDescriptors(g_child_request.at("descriptors").get<std::string>());
#if defined(_WIN32)
	if (result != 0) ReportChildError(result);
#endif
	return result == 0;
}

bool InstallExecChildReadOnlyProviders() {
	if (!g_exec_child) return true;
	int result = KERNEL_ERROR_EINVAL;
	try {
		result = FileSystem::ImportExecReadOnlyProviders(
		    g_child_request.at("read_only_providers").get<std::string>());
		if (result == 0 && g_child_request.contains("nullfs_mounts")) {
			result = FileSystem::ImportExecNullfsMounts(
			    g_child_request.at("nullfs_mounts").get<std::string>());
		}
		if (result == 0 && g_child_request.contains("sandbox_root")) {
			FileSystem::ImportExecSandboxMounts(
			    g_child_request.at("sandbox_root").get<std::string>(),
			    g_child_request.value("sandbox_word", std::string {}));
		}
	} catch (...) {
		result = KERNEL_ERROR_EINVAL;
	}
#if defined(_WIN32)
	if (result != 0) ReportChildError(result);
#endif
	return result == 0;
}

void SignalExecChildImageCommitted(uint64_t entry) {
#if defined(_WIN32)
	// sc_spawn (sub_40CA60) = rfork_thread into the execve trampoline sub_40D0F0; exec's kernel
	// side ends at image map
	if (!g_exec_child || !g_child_image || entry == 0) return;
	g_child_image->shared->entry = entry;
	if (InterlockedCompareExchange(&g_child_image->shared->state, 1, 0) == 0) {
		SetEvent(g_child_image->prepared);
	}
#else
	(void)entry;
#endif
}

bool AwaitExecChildCommit(uint64_t entry, uint64_t stack, uint64_t params) {
	if (!g_exec_child) return true;
#if defined(_WIN32)
	if (!g_child_image || entry == 0 || stack == 0 || params == 0) {
		ReportChildError(KERNEL_ERROR_ENOEXEC);
		return false;
	}
	auto& image          = *g_child_image;
	image.shared->entry  = entry;
	image.shared->stack  = stack;
	image.shared->params = params;
	image.shared->error  = 0;
	// prepared normally fired at main-image map; arm it here only if that signal did not run.
	InterlockedCompareExchange(&image.shared->state, 1, 0);
	SetEvent(image.prepared);
	if (WaitForSingleObject(image.release, 30000) != WAIT_OBJECT_0 ||
	    InterlockedCompareExchange(&image.shared->state, 0, 0) != 3)
		return false;
	LOGF("GUEST_EXEC_IMAGE_RELEASED guest_pid=%d host_pid=%lu entry=0x%016" PRIx64
	     " stack=0x%016" PRIx64 " params=0x%016" PRIx64 " argc=%zu envc=%zu\n",
	     GetPid(), GetCurrentProcessId(), entry, stack, params, g_arguments.size(),
	     g_environment.size());
	return true;
#else
	return false;
#endif
}

void RecordExecChildExitStatus(uint32_t wait_status) {
#if defined(_WIN32)
	if (!g_exec_child || !g_child_image) return;
	g_child_image->shared->guest_wait_status = wait_status;
	InterlockedExchange(&g_child_image->shared->guest_exit_known, 1);
#endif
}

void RecordExecChildRebootOptions(uint64_t options, uint32_t kind, uint32_t exit_code) {
#if defined(_WIN32)
	if (!g_exec_child || !g_child_image) return;
	g_child_image->shared->reboot_options   = options;
	g_child_image->shared->reboot_kind      = kind;
	g_child_image->shared->reboot_exit_code = exit_code;
#else
	(void)options;
	(void)kind;
	(void)exit_code;
#endif
}

void ReleaseCommittedExecChild(int pid) {
#if defined(_WIN32)
	std::lock_guard lock(g_images_mutex);
	const auto      found = g_images.find(pid);
	if (found == g_images.end()) return;
	auto& image = *found->second;
	InterlockedExchange(&image.shared->state, 3);
	SetEvent(image.release);
	LOGF("GUEST_EXEC_OLD_CONTEXT_RETIRED guest_pid=%d host_pid=%lu\n", pid,
	     image.shared->child_host_pid);
#endif
}

int KillCommittedExecChild(int pid) {
#if defined(_WIN32)
	std::shared_ptr<HostImage> image;
	{
		std::lock_guard lock(g_images_mutex);
		const auto      found = g_images.find(pid);
		if (found == g_images.end() || !found->second->committed) return KERNEL_ERROR_ESRCH;
		image = found->second;
	}
	// A guest that already reached exit keeps its own status; otherwise the monitor reports a plain SIGKILL termination (wait status 9) like psignal(p, SIGKILL) in sys_process_terminate.
	if (InterlockedCompareExchange(&image->shared->guest_exit_known, 0, 0) == 0) {
		image->shared->guest_wait_status = 9;
		InterlockedExchange(&image->shared->guest_exit_known, 1);
	}
	const BOOL  killed = TerminateProcess(image->process, 9);
	const DWORD error  = killed ? 0 : GetLastError();
	LOGF("GUEST_EXEC_TERMINATE guest_pid=%d host_pid=%lu killed=%d error=%lu\n", pid,
	     image->shared->child_host_pid, killed ? 1 : 0, error);
	// ERROR_ACCESS_DENIED here is the host process having exited already; the monitor still reports it
	if (!killed && WaitForSingleObject(image->process, 0) != WAIT_OBJECT_0) return KERNEL_ERROR_EPERM;
	return 0;
#else
	return KERNEL_ERROR_ENOSYS;
#endif
}

int ExecImage(const std::string& guest_path, const std::filesystem::path& host_path,
              const std::vector<std::string>& argv, const std::vector<std::string>& envp,
              const std::filesystem::path& app0_dir, const std::string& app0_elf) {
#if defined(_WIN32)
	const int pid = GetPid();
	if (std::getenv("KYTY_DIAGNOSTIC_GUEST_EXECVE") == nullptr || !IsTrackedRforkChild(pid)) {
		return KERNEL_ERROR_ENOSYS;
	}
	const bool      has_app0 = !app0_dir.empty() || !app0_elf.empty();
	std::error_code app0_error;
	if (has_app0 && (app0_dir.empty() || app0_elf.empty() || !app0_dir.is_absolute() ||
	                 !std::filesystem::is_directory(app0_dir, app0_error) || app0_error ||
	                 !ValidApp0ElfPath(app0_elf)))
		return KERNEL_ERROR_EINVAL;
	uint64_t  static_base = 0;
	uint64_t  static_size = 0;
	const int layout_error =
	    StaticExecRange(host_path, g_options.config, &static_base, &static_size);
	if (layout_error != 0) return layout_error;
	std::filesystem::path   original_self;
	AuthInfo::ImageIdentity self_identity;
	const bool              system_image = guest_path.starts_with("/system/");
	const auto* self_root = std::getenv(system_image ? "KYTY_DIAGNOSTIC_ORIGINAL_SELF_SYSTEM_ROOT"
	                                                 : "KYTY_DIAGNOSTIC_ORIGINAL_SELF_BOOT_ROOT");
	if (self_root != nullptr) {
		std::string reason;
		int         error = 0;
		try {
			error = ResolveOriginalSelf(guest_path, host_path, std::filesystem::u8path(self_root),
			                            system_image ? "/system/" : "/", &original_self,
			                            &self_identity, &reason);
		} catch (const std::exception& exception) {
			error  = KERNEL_ERROR_EINVAL;
			reason = exception.what();
		}
		if (error != 0) {
			LOGF("GUEST_EXEC_ORIGINAL_SELF_REJECTED guest_pid=%d path=%s reason=%s error=0x%08x\n",
			     pid, guest_path.c_str(), reason.c_str(), static_cast<uint32_t>(error));
			return error;
		}
		if (!original_self.empty()) {
			LOGF("GUEST_EXEC_ORIGINAL_SELF_VERIFIED guest_pid=%d path=%s original=%s "
			     "elf_headers_match=1\n",
			     pid, guest_path.c_str(), Common::PathToString(original_self).c_str());
		}
	}
	SensitiveCapture            auth_info_capture;
	std::string                 auth_info_reason;
	AuthInfo::CaptureLoadResult auth_info_result     = AuthInfo::CaptureLoadResult::Absent;
	const char*                 auth_info_provenance = IsExecChild() ? "installed" : "environment";
	if (!original_self.empty()) {
		if (IsExecChild()) {
			if (GetVerifiedAuthInfoForImage(self_identity, &auth_info_capture.value)) {
				auth_info_result = AuthInfo::CaptureLoadResult::Verified;
			}
		} else {
			auth_info_result = AuthInfo::LoadCaptureFromEnvironment(
			    self_identity.self_sha256, self_identity.elf_sha256, self_identity.authority_id,
			    &auth_info_capture.value, &auth_info_reason);
		}
	}
	if (auth_info_result == AuthInfo::CaptureLoadResult::Rejected) {
		LOGF("AUTHINFO_CAPTURE_INPUT provenance=%s status=rejected reason=%s\n",
		     auth_info_provenance, auth_info_reason.c_str());
		return KERNEL_ERROR_ENOEXEC;
	}
	if (auth_info_result == AuthInfo::CaptureLoadResult::Verified) {
		const auto envelope = AuthInfo::DigestHex(auth_info_capture.value.envelope_sha256);
		const auto self     = AuthInfo::DigestHex(auth_info_capture.value.self_sha256);
		const auto elf      = AuthInfo::DigestHex(auth_info_capture.value.elf_sha256);
		LOGF("AUTHINFO_CAPTURE_INPUT provenance=%s envelope_sha256=%s self_sha256=%s elf_sha256=%s "
		     "status=verified\n",
		     auth_info_provenance, envelope.c_str(), self.c_str(), elf.c_str());
	}
	AuthInfo::Observation observation;
	const auto observation_result = original_self.empty()
	                                    ? AuthInfo::CaptureLoadResult::Absent
	                                    : AuthInfo::LoadObservationFromEnvironment(
	                                          self_identity, &observation, &auth_info_reason);
	if (observation_result == AuthInfo::CaptureLoadResult::Rejected) {
		LOGF("AUTHORIZATION_OBSERVATION_INPUT status=rejected reason=%s\n",
		     auth_info_reason.c_str());
		return KERNEL_ERROR_ENOEXEC;
	}
	if (observation_result == AuthInfo::CaptureLoadResult::Verified) {
		LOGF("AUTHORIZATION_OBSERVATION_INPUT status=verified guest_pid=%d envelope_sha256=%s"
		     " evidence_sha256=%s known_capability_mask=%016llx root_prison_known=%d"
		     " root_prison=%d\n",
		     pid, AuthInfo::DigestHex(observation.envelope_sha256).c_str(),
		     AuthInfo::DigestHex(observation.evidence_sha256).c_str(),
		     static_cast<unsigned long long>(observation.facts.known_capability0),
		     observation.facts.root_prison_known ? 1 : 0, observation.facts.root_prison ? 1 : 0);
		Log::Flush();
	}
	std::string descriptors;
	const int   descriptor_error = FileSystem::ExportExecDescriptors(&descriptors);
	if (descriptor_error != 0) return descriptor_error;
	std::string read_only_providers;
	const int   provider_error = FileSystem::ExportExecReadOnlyProviders(&read_only_providers);
	if (provider_error != 0) return provider_error;
	std::string nullfs_mounts;
	const int   nullfs_error = FileSystem::ExportExecNullfsMounts(&nullfs_mounts);
	if (nullfs_error != 0) return nullfs_error;
	std::string token;
	if (!NewToken(&token)) return KERNEL_ERROR_EIO;
	auto image     = std::make_shared<HostImage>();
	image->mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
	                                    sizeof(ExecHandoff), ObjectName(token, L"_map").c_str());
	if (!image->mapping || GetLastError() == ERROR_ALREADY_EXISTS) return KERNEL_ERROR_ENOMEM;
	image->prepared = CreateEventW(nullptr, TRUE, FALSE, ObjectName(token, L"_prepared").c_str());
	image->release  = CreateEventW(nullptr, TRUE, FALSE, ObjectName(token, L"_release").c_str());
	image->monitor_gate = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	image->job          = CreateJobObjectW(nullptr, nullptr);
	if (!image->prepared || !image->release || !image->monitor_gate || !image->job)
		return KERNEL_ERROR_ENOMEM;
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
	limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	if (!SetInformationJobObject(image->job, JobObjectExtendedLimitInformation, &limits,
	                             sizeof(limits))) {
		return KERNEL_ERROR_EIO;
	}
	image->shared = static_cast<ExecHandoff*>(
	    MapViewOfFile(image->mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ExecHandoff)));
	if (!image->shared) return KERNEL_ERROR_ENOMEM;
	std::memset(image->shared, 0, sizeof(*image->shared));
	if (auth_info_result == AuthInfo::CaptureLoadResult::Verified) {
		image->shared->auth_info_present = 1;
		image->shared->auth_info_bytes =
		    static_cast<uint32_t>(auth_info_capture.value.envelope.size());
		std::memcpy(image->shared->auth_info_sha256, auth_info_capture.value.envelope_sha256.data(),
		            auth_info_capture.value.envelope_sha256.size());
		std::memcpy(image->shared->auth_info_capture, auth_info_capture.value.envelope.data(),
		            auth_info_capture.value.envelope.size());
		auth_info_capture.Clear();
	}
	auto config = g_options.config;
	auto log    = std::filesystem::absolute(config.printf_output_file);
	log += ".exec-" + std::to_string(pid) + "-" + token.substr(0, 8) + ".log";
	config.printf_direction   = Config::LogDirection::File;
	config.printf_output_file = log;
	Json request {{"guest_pid", pid},
	              {"guest_path", guest_path},
	              {"host_path", Common::PathToString(host_path)},
	              {"original_self", Common::PathToString(original_self)},
	              {"sysroot", Common::PathToString(g_options.sysroot_dir)},
	              {"argv", argv},
	              {"envp", envp},
	              {"descriptors", descriptors},
	              {"read_only_providers", read_only_providers},
	              {"nullfs_mounts", nullfs_mounts}};
	if (has_app0) {
		request["app0_dir"] = Common::PathToString(app0_dir);
		request["app0_elf"] = app0_elf;
	}
	{
		std::lock_guard lock(g_spawn_sandbox_mutex);
		const auto      sandbox = g_spawn_sandboxes.find(pid);
		if (sandbox != g_spawn_sandboxes.end()) {
			if (!sandbox->second.first.empty()) request["sandbox_root"] = sandbox->second.first;
			if (!sandbox->second.second.empty()) request["sandbox_word"] = sandbox->second.second;
			g_spawn_sandboxes.erase(sandbox);
		}
	}
	if (observation_result == AuthInfo::CaptureLoadResult::Verified) {
		request["authorization_observation"] = {
		    {"sha256", AuthInfo::DigestHex(observation.envelope_sha256)},
		    {"bytes", observation.encoded}};
	}
	TransferConfig(request["config"], config, true);
	const auto encoded = request.dump();
	if (encoded.size() >= kRequestCapacity) return KERNEL_ERROR_E2BIG;
	image->shared->magic           = kExecMagic;
	image->shared->version         = kExecVersion;
	image->shared->guest_pid       = static_cast<uint32_t>(pid);
	image->shared->parent_host_pid = GetCurrentProcessId();
	image->shared->request_bytes   = static_cast<uint32_t>(encoded.size());
	std::memcpy(image->shared->request, encoded.data(), encoded.size());
	std::vector<wchar_t> executable(32768);
	const auto           length =
	    GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
	if (length == 0 || length >= executable.size()) return KERNEL_ERROR_EIO;
	std::wstring command     = Quote(std::wstring(executable.data(), length)) + L" --game " +
	                           Quote(host_path.wstring()) + L" --sysroot " +
	                           Quote(g_options.sysroot_dir.wstring()) + L" --exec-child " +
	                           Quote(std::wstring(token.begin(), token.end()));
	auto         environment = ChildEnvironment(pid, original_self, static_base != 0);
	if (environment.empty()) return KERNEL_ERROR_ENOMEM;
	auto                output       = std::make_shared<ChildOutput>();
	HANDLE              output_write = nullptr;
	SECURITY_ATTRIBUTES inherit {sizeof(inherit), nullptr, TRUE};
	output->done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	if (!output->done || !CreatePipe(&output->read, &output_write, &inherit, 0))
		return KERNEL_ERROR_ENOMEM;
	SetHandleInformation(output->read, HANDLE_FLAG_INHERIT, 0);
	SIZE_T attribute_size = 0;
	InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size);
	std::vector<uint8_t> attribute_storage(attribute_size);
	auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_storage.data());
	if (!InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_size)) {
		CloseHandle(output_write);
		return KERNEL_ERROR_ENOMEM;
	}
	// Only the pipe is inherited; every other parent handle stays out of the child.
	if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &output_write,
	                               sizeof(output_write), nullptr, nullptr)) {
		DeleteProcThreadAttributeList(attributes);
		CloseHandle(output_write);
		return KERNEL_ERROR_ENOMEM;
	}
	STARTUPINFOEXW startup {};
	startup.StartupInfo.cb         = sizeof(startup);
	startup.StartupInfo.dwFlags    = STARTF_USESTDHANDLES;
	startup.StartupInfo.hStdOutput = output_write;
	startup.StartupInfo.hStdError  = output_write;
	startup.lpAttributeList        = attributes;
	PROCESS_INFORMATION process {};
	const BOOL          created =
	    CreateProcessW(executable.data(), command.data(), nullptr, nullptr, TRUE,
		               CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
		               environment.data(), nullptr, &startup.StartupInfo, &process);
	const DWORD create_error = created ? 0 : GetLastError();
	DeleteProcThreadAttributeList(attributes);
	CloseHandle(output_write);
	if (!created) {
		LOGF("GUEST_EXEC_CHILD_CREATE_FAILED guest_pid=%d path=%s win32_error=%lu\n", pid,
		     guest_path.c_str(), create_error);
		return KERNEL_ERROR_EAGAIN;
	}
	image->process                = process.hProcess;
	image->shared->child_host_pid = process.dwProcessId;
	try {
		std::thread([output] { DrainChildOutput(output); }).detach();
	} catch (...) {
		CloseHandle(process.hThread);
		return AbortPreparation(image, KERNEL_ERROR_EAGAIN);
	}
	if (!AssignProcessToJobObject(image->job, image->process)) {
		LOGF("GUEST_EXEC_CHILD_LAUNCH_FAILED guest_pid=%d host_pid=%lu step=assign_job "
		     "win32_error=%lu\n",
		     pid, process.dwProcessId, GetLastError());
		CloseHandle(process.hThread);
		return AbortPreparation(image, KERNEL_ERROR_EIO);
	}
	if (static_base != 0) {
		using Allocate      = PVOID(WINAPI*)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, PVOID, ULONG);
		const auto allocate = reinterpret_cast<Allocate>(
		    GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "VirtualAlloc2"));
		const auto address = reinterpret_cast<void*>(static_base);
		if (!allocate || allocate(image->process, address, static_size, MEM_RESERVE | 0x40000,
		                          PAGE_NOACCESS, nullptr, 0) != address) {
			LOGF("GUEST_EXEC_CHILD_LAUNCH_FAILED guest_pid=%d host_pid=%lu step=static_reserve "
			     "win32_error=%lu\n",
			     pid, process.dwProcessId, GetLastError());
			CloseHandle(process.hThread);
			return AbortPreparation(image, KERNEL_ERROR_ENOMEM);
		}
		LOGF("GUEST_EXEC_STATIC_IMAGE_RESERVED guest_pid=%d host_pid=%lu base=%016" PRIx64
		     " size=%016" PRIx64 "\n",
		     pid, process.dwProcessId, static_base, static_size);
	}
	if (ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
		LOGF("GUEST_EXEC_CHILD_LAUNCH_FAILED guest_pid=%d host_pid=%lu step=resume "
		     "win32_error=%lu\n",
		     pid, process.dwProcessId, GetLastError());
		CloseHandle(process.hThread);
		return AbortPreparation(image, KERNEL_ERROR_EIO);
	}
	CloseHandle(process.hThread);
	const auto prepare_timeout = ExecPrepareTimeout();
	const auto prepare_started = GetTickCount64();
	LOGF("GUEST_EXEC_PREPARING guest_pid=%d host_pid=%lu path=%s log=%s log_path_chars=%zu "
	     "timeout_ms=%lu monotonic_ms=%llu\n",
	     pid, process.dwProcessId, guest_path.c_str(), Common::PathToString(log).c_str(),
	     log.wstring().size(), prepare_timeout, static_cast<unsigned long long>(prepare_started));
	LOGF("GUEST_EXEC_CHILD_COMMAND guest_pid=%d exe=%s args=--game %s --sysroot %s --exec-child "
	     "<redacted>\n",
	     pid,
	     Common::PathToString(std::filesystem::path(std::wstring(executable.data(), length)))
	         .c_str(),
	     Common::PathToString(host_path).c_str(),
	     Common::PathToString(g_options.sysroot_dir).c_str());
	HANDLE     waits[] {image->prepared, image->process};
	const auto wait            = WaitForMultipleObjects(2, waits, FALSE, prepare_timeout);
	const auto prepare_elapsed = GetTickCount64() - prepare_started;
	const auto state           = InterlockedCompareExchange(&image->shared->state, 0, 0);
	if (wait != WAIT_OBJECT_0 || state != 1 || image->shared->error != 0 ||
	    image->shared->entry == 0 || WaitForSingleObject(image->process, 0) != WAIT_TIMEOUT) {
		const int   error  = image->shared->error != 0 ? image->shared->error
		                     : wait == WAIT_TIMEOUT    ? KERNEL_ERROR_EAGAIN
		                                               : KERNEL_ERROR_ENOEXEC;
		const char* reason = wait == WAIT_TIMEOUT                      ? "timeout"
		                     : wait == WAIT_FAILED                     ? "wait_failed"
		                     : state == 2 || image->shared->error != 0 ? "child_reported_error"
		                     : state == 0                ? "child_exited_before_prepared"
		                     : image->shared->entry == 0 ? "prepared_without_entry"
		                                                 : "child_exited_after_prepared";
		LOGF("GUEST_EXEC_PREPARATION_FAILED guest_pid=%d host_pid=%lu wait=%lu state=%ld"
		     " error=0x%08x reason=%s elapsed_ms=%llu timeout_ms=%lu\n",
		     pid, process.dwProcessId, wait, state, static_cast<uint32_t>(error), reason,
		     static_cast<unsigned long long>(prepare_elapsed), prepare_timeout);
		LogChildStartupFailure(pid, image, output, error);
		return error;
	}
	{
		std::lock_guard lock(g_images_mutex);
		if (!g_images.emplace(pid, image).second)
			return AbortPreparation(image, KERNEL_ERROR_EBUSY);
	}
	std::thread monitor;
	try {
		monitor = std::thread([image, pid] {
			WaitForSingleObject(image->monitor_gate, INFINITE);
			if (image->committed) {
				WaitForSingleObject(image->process, INFINITE);
				DWORD exit_code = 0;
				if (GetExitCodeProcess(image->process, &exit_code)) {
					const bool known =
					    InterlockedCompareExchange(&image->shared->guest_exit_known, 0, 0) != 0;
					LOGF("GUEST_EXEC_HOST_EXIT guest_pid=%d host_pid=%lu host_code=0x%08lx "
					     "guest_status_known=%u\n",
					     pid, image->shared->child_host_pid, exit_code, known ? 1u : 0u);
					if (known) {
						NotifyRforkChildExited(pid, image->shared->guest_wait_status);
					} else if (std::getenv(
					               "KYTY_DIAGNOSTIC_SYSCORE_SYNTHESIZE_HOST_EXIT_WAIT_STATUS") !=
					           nullptr) {
						// EXIT() (SEH or hard assert) skipped the exit syscall. SIGSEGV + core so
						// the parent's EVFILT_PROC NOTE_EXIT fires.
						const uint32_t synthesized = 0x8bu;
						LOGF("SYSCORE_HOST_EXIT_SYNTHESIZED guest_pid=%d host_pid=%lu "
						     "host_code=0x%08lx wait_status=0x%08x NON_AUTHENTIC\n",
						     pid, image->shared->child_host_pid, exit_code, synthesized);
						NotifyRforkChildExited(pid, synthesized);
					}
				}
			}
			std::lock_guard lock(g_images_mutex);
			g_images.erase(pid);
		});
	} catch (...) {
		std::lock_guard lock(g_images_mutex);
		g_images.erase(pid);
		return AbortPreparation(image, KERNEL_ERROR_EAGAIN);
	}
	if (!MarkRforkChildExecCommitted(pid, process.dwProcessId, guest_path)) {
		SetEvent(image->monitor_gate);
		monitor.join();
		return AbortPreparation(image, KERNEL_ERROR_EBUSY);
	}
	image->committed = true;
	SetEvent(image->monitor_gate);
	monitor.detach();
	LOGF("GUEST_EXEC_IMAGE_COMMITTED guest_pid=%d host_pid=%lu entry=0x%016" PRIx64
	     " path=%s prepare_elapsed_ms=%llu timeout_ms=%lu monotonic_ms=%llu\n",
	     pid, process.dwProcessId, image->shared->entry, guest_path.c_str(),
	     static_cast<unsigned long long>(prepare_elapsed), prepare_timeout,
	     static_cast<unsigned long long>(GetTickCount64()));
	return 0;
#else
	return KERNEL_ERROR_ENOSYS;
#endif
}

} // namespace Libs::LibKernel::Process
