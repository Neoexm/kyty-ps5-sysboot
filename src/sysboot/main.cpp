#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>

#include "sysboot/provider.h"
#include "sysboot/resource.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <bcrypt.h>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <set>
#include <shobjidl.h>
#include <sstream>
#include <string>
#include <thread>
#include <tlhelp32.h>
#include <tuple>
#include <vector>

namespace fs = std::filesystem;
using nlohmann::json;

namespace {

constexpr UINT wm_app_log    = WM_APP + 1;
constexpr UINT wm_app_report = WM_APP + 2;
constexpr UINT wm_app_status = WM_APP + 3;
constexpr UINT wm_app_fail   = WM_APP + 4;
constexpr UINT wm_app_done   = WM_APP + 5;
// the emulator posts this when its visible window changes
constexpr UINT focus_visible_child_message = 0x804B;

constexpr char psnow_self_sha256[] =
    "a6826c981e0227552f1cd08c59dd2e9995b69e9b10b568138a08dcc28a509a18";
constexpr char psnow_observation_sha256[] =
    "3a899ca1e3334410138c2986a9085cc032ca202bbc78cf47a1edf82e1ab9f65c";
constexpr uint64_t error_object_limit = 4 * 1024 * 1024;

const wchar_t idle_hint[] = L"File > Boot sys starts the saved PS5 system.\nNo PS5 connection is needed.";

struct Settings {
	std::wstring ip;
	uint16_t     port = 9035;
	std::wstring token_file;
	std::wstring repo;
	bool         readbacks     = false;
	bool         show_services = false;
	uint32_t     timeout_ms    = 300000;
};

HINSTANCE         g_instance = nullptr;
HWND              g_main     = nullptr;
HWND              g_log      = nullptr;
HWND              g_log_edit = nullptr;
HFONT             g_log_font = nullptr;
Settings          g_settings;
std::thread       g_worker;
std::atomic<bool> g_stop {false};
bool              g_running              = false;
bool              g_quit                 = false;
bool              g_log_opened_for_error = false;
std::wstring      g_status               = idle_hint;

void ResetConsoleState(HWND owner);

std::wstring Wide(const std::string& s) {
	if (s.empty()) return {};
	const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
	std::wstring w(n, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
	return w;
}

std::string Utf8(const std::wstring& w) {
	if (w.empty()) return {};
	const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0,
	                                  nullptr, nullptr);
	std::string s(n, '\0');
	WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr,
	                    nullptr);
	return s;
}

template <typename S>
S Trim(const S& s) {
	size_t b = 0;
	size_t e = s.size();
	while (b < e && (s[b] == ' ' || (s[b] >= '\t' && s[b] <= '\r')))
		b++;
	while (e > b && (s[e - 1] == ' ' || (s[e - 1] >= '\t' && s[e - 1] <= '\r')))
		e--;
	return s.substr(b, e - b);
}

fs::path ExeDir() {
	std::wstring buffer(32768, L'\0');
	const DWORD  n = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
	buffer.resize(n);
	return fs::path(buffer).parent_path();
}

fs::path ConsoleStateDir() {
	return L"D:\\PS5_Backups\\13.60_2026-11-20\\kyty_console_state\\npmanager_native_replay_20261120_1455";
}

std::wstring IniPath() {
	return (ExeDir() / L"kyty_sysboot.ini").wstring();
}

Settings LoadSettings() {
	const std::wstring ini = IniPath();
	auto read = [&](const wchar_t* section, const wchar_t* key, const wchar_t* fallback) {
		wchar_t buffer[4096];
		GetPrivateProfileStringW(section, key, fallback, buffer, 4096, ini.c_str());
		return Trim(std::wstring(buffer));
	};
	auto flag = [&](const wchar_t* section, const wchar_t* key) {
		const std::wstring v = read(section, key, L"no");
		return v == L"1" || _wcsicmp(v.c_str(), L"yes") == 0 || _wcsicmp(v.c_str(), L"true") == 0 ||
		       _wcsicmp(v.c_str(), L"on") == 0;
	};
	Settings s;
	s.ip                  = read(L"console", L"ip", L"");
	const unsigned long p = wcstoul(read(L"console", L"port", L"9035").c_str(), nullptr, 10);
	if (p >= 1 && p <= 65535) s.port = static_cast<uint16_t>(p);
	s.token_file          = read(L"console", L"token_file", L"");
	s.repo                = read(L"paths", L"repo", L"");
	s.readbacks           = flag(L"boot", L"readbacks");
	s.show_services       = flag(L"boot", L"show_services");
	const unsigned long t = wcstoul(read(L"boot", L"timeout_ms", L"300000").c_str(), nullptr, 10);
	if (t != 0) s.timeout_ms = static_cast<uint32_t>(t);
	return s;
}

void SaveSettings(const Settings& s) {
	const std::wstring ini = IniPath();
	// WritePrivateProfileString only keeps non-ASCII paths when the file already starts with a UTF-16 BOM
	if (GetFileAttributesW(ini.c_str()) == INVALID_FILE_ATTRIBUTES) {
		HANDLE file = CreateFileW(ini.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
		                          FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file != INVALID_HANDLE_VALUE) {
			const uint8_t bom[]   = {0xFF, 0xFE};
			DWORD         written = 0;
			WriteFile(file, bom, 2, &written, nullptr);
			CloseHandle(file);
		}
	}
	WritePrivateProfileStringW(L"paths", L"repo", s.repo.c_str(), ini.c_str());
	WritePrivateProfileStringW(L"boot", L"readbacks", s.readbacks ? L"yes" : L"no", ini.c_str());
	WritePrivateProfileStringW(L"boot", L"show_services", s.show_services ? L"yes" : L"no",
	                           ini.c_str());
	WritePrivateProfileStringW(L"boot", L"timeout_ms", std::to_wstring(s.timeout_ms).c_str(),
	                           ini.c_str());
}

void Post(UINT message, std::wstring text) {
	auto* heap = new std::wstring(std::move(text));
	if (!PostMessageW(g_main, message, 0, reinterpret_cast<LPARAM>(heap))) delete heap;
}

void Log(const std::wstring& text) {
	Post(wm_app_log, text);
}

bool ReadFileBytes(const fs::path& path, std::string* out) {
	std::ifstream in(path, std::ios::binary);
	if (!in) return false;
	out->assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
	return !in.bad();
}

bool Sha256File(const fs::path& path, std::string* hex) {
	std::ifstream in(path, std::ios::binary);
	if (!in) return false;
	BCRYPT_ALG_HANDLE  algorithm = nullptr;
	BCRYPT_HASH_HANDLE hash      = nullptr;
	bool ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0 &&
	          BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0;
	std::vector<char> chunk(1024 * 1024);
	while (ok && in) {
		in.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
		const auto n = in.gcount();
		if (n > 0)
			ok = BCryptHashData(hash, reinterpret_cast<PUCHAR>(chunk.data()), static_cast<ULONG>(n),
			                    0) >= 0;
	}
	ok = ok && !in.bad();
	uint8_t digest[32];
	if (ok) ok = BCryptFinishHash(hash, digest, 32, 0) >= 0;
	if (hash != nullptr) BCryptDestroyHash(hash);
	if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
	if (!ok) return false;
	hex->clear();
	for (uint8_t b: digest) {
		char pair[3];
		snprintf(pair, sizeof(pair), "%02x", b);
		hex->append(pair);
	}
	return true;
}

std::string Timestamp(const char* format) {
	const std::time_t now = std::time(nullptr);
	std::tm           local {};
	localtime_s(&local, &now);
	char buffer[64];
	std::strftime(buffer, sizeof(buffer), format, &local);
	return buffer;
}

bool Truthy(const json& v) {
	if (v.is_null()) return false;
	if (v.is_boolean()) return v.get<bool>();
	if (v.is_number_integer()) return v.get<int64_t>() != 0;
	if (v.is_number_unsigned()) return v.get<uint64_t>() != 0;
	if (v.is_number_float()) return v.get<double>() != 0.0;
	if (v.is_string()) return !v.get_ref<const std::string&>().empty();
	return !v.empty();
}

// str() of a decoded JSON value, close enough for the fields these records carry
std::string Str(const json& v) {
	if (v.is_string()) return v.get<std::string>();
	if (v.is_boolean()) return v.get<bool>() ? "True" : "False";
	if (v.is_null()) return "None";
	return v.dump();
}

std::string Field(const json& object, const char* key, const char* fallback) {
	const auto it = object.find(key);
	return it != object.end() && Truthy(*it) ? Str(*it) : fallback;
}

std::string ErrorRecordText(const json& record) {
	if (!record.is_object()) return {};
	const json short_error = record.value("shortError", json());
	const json message     = record.value("messageBuffer", json());
	if (Truthy(short_error) && Truthy(message)) {
		const json  code = record.value("internalErrorCode", json());
		std::string internal;
		if (code.is_number_integer() || code.is_boolean()) {
			const uint32_t value = code.is_boolean()
			                           ? (code.get<bool>() ? 1 : 0)
			                           : static_cast<uint32_t>(code.get<int64_t>() & 0xffffffff);
			char           text[16];
			snprintf(text, sizeof(text), "0x%08X", value);
			internal = text;
		} else if (Truthy(code)) {
			internal = Str(code);
		}
		return "PS5 guest error " + Str(short_error) + " (" + internal + ", " +
		       Field(record, "titleId", "unknown title") + "): " + Str(message);
	}

	const json event_id = record.value("eventId", json());
	json       event    = record.value("eventStr", json());
	if (event.is_string()) {
		event = json::parse(event.get<std::string>(), nullptr, false);
		if (event.is_discarded()) event = json::object();
	}
	if (!event.is_object()) return {};
	if (event_id == "ErrorDialog") {
		return "PS5 guest error dialog " + Field(event, "shortErrorCode", "unknown code") + " (" +
		       Field(event, "vshErrorHexCode", "unknown internal code") + ", " +
		       Field(event, "titleId", "unknown title") +
		       "): " + Field(event, "description", "error dialog");
	}
	if (event_id == "ApplicationError") {
		std::string severity = event.contains("severity") ? Str(event["severity"]) : "";
		for (char& c: severity)
			c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
		if (severity != "major" && severity != "critical" && severity != "fatal") return {};
		const std::string kind =
		    Field(event, "errorType", (severity + " application error").c_str());
		std::string text = "PS5 guest " + kind + " (" +
		                   Field(event, "vshErrorHexCode", "unknown code") + ", " +
		                   Field(event, "appTitleId", "unknown title") +
		                   "): " + Trim(Field(event, "errorMessage", ""));
		while (!text.empty() &&
		       (text.back() == ' ' || (text.back() >= '\t' && text.back() <= '\r')))
			text.pop_back();
		return text;
	}
	return {};
}

// Port of start_kyty_ps5.py's ErrorReporter: surfaces guest error records, host exit notes and fatal log blocks while the boot runs.
class ErrorReporter {
public:
	explicit ErrorReporter(fs::path run_dir)
	    : m_run_dir(std::move(run_dir)), m_error_log(m_run_dir / "error_report.log") {}

	void BeginExpectedShutdown() {
		if (m_expected_shutdown) return;
		Poll(true);
		m_expected_shutdown = true;
	}

	void Poll(bool final) {
		PollObjects();
		PollExitNotes();
		std::error_code       ec;
		std::vector<fs::path> logs;
		for (const auto& entry: fs::directory_iterator(m_run_dir, ec)) {
			const std::wstring name = entry.path().filename().wstring();
			if (name.rfind(L"kyty.log", 0) == 0 && entry.is_regular_file(ec))
				logs.push_back(entry.path());
		}
		for (const auto& path: logs)
			PollLog(path, final);
		const fs::path host_console = m_run_dir / "host_console.log";
		if (fs::is_regular_file(host_console, ec)) PollLog(host_console, final);
	}

private:
	void Report(const std::string& raw, const std::string& key_override = {}) {
		const std::string text = Trim(raw);
		const std::string key  = key_override.empty() ? text : key_override;
		if (text.empty() || !m_reported.insert(key).second) return;
		std::ofstream out(m_error_log, std::ios::binary | std::ios::app);
		if (out) out << Timestamp("%Y-%m-%dT%H:%M:%S") << ' ' << text << '\n';
		Post(wm_app_report, Wide(text));
	}

	static std::string FailureKey(const std::string& line) {
		std::map<std::string, std::string> fields;
		std::istringstream                 tokens(line);
		std::string                        token;
		while (tokens >> token) {
			const size_t eq = token.find('=');
			if (eq != std::string::npos) fields[token.substr(0, eq)] = token.substr(eq + 1);
		}
		auto f = [&](const char* name) {
			const auto it = fields.find(name);
			return it == fields.end() ? std::string("\x02") : it->second;
		};
		if (line.find("GUEST_EXEC_FATAL_SIGNAL") != std::string::npos)
			return "\x01guest_fatal\x1f" + f("guest_rva") + "\x1f" + f("signal") + "\x1f" +
			       f("source");
		if (line.find("outcome=crashed") != std::string::npos)
			return "\x01crashed\x1f" + f("path") + "\x1f" + f("status") + "\x1f" + f("reason");
		if (line.find("HOST_EXIT path=") != std::string::npos)
			return "\x01host_exit\x1f" + f("path") + "\x1f" + f("status");
		return line;
	}

	static bool FatalSourceLine(const std::string& line) {
		const size_t colon = line.rfind(':');
		if (colon == std::string::npos) return false;
		const std::string number = line.substr(colon + 1);
		if (number.empty()) return false;
		for (char c: number)
			if (c < '0' || c > '9') return false;
		return line.substr(0, colon).find(" in ") != std::string::npos;
	}

	void PollObjects() {
		const fs::path  objects = m_run_dir / "upper/_system_data/objects";
		std::error_code ec;
		if (!fs::is_directory(objects, ec)) return;
		for (const auto& entry: fs::directory_iterator(objects, ec)) {
			std::error_code e;
			if (!entry.is_regular_file(e)) continue;
			const uint64_t size = entry.file_size(e);
			if (e) continue;
			const auto mtime = entry.last_write_time(e).time_since_epoch().count();
			if (e) continue;
			const std::wstring key = entry.path().wstring();
			if (size == 0 || size > error_object_limit) continue;
			const auto known = m_object_versions.find(key);
			if (known != m_object_versions.end() && known->second.first == size &&
			    known->second.second == mtime)
				continue;
			m_object_versions[key] = {size, mtime};
			std::string text;
			if (!ReadFileBytes(entry.path(), &text)) continue;
			if (text.rfind("\xEF\xBB\xBF", 0) == 0) text.erase(0, 3);
			std::istringstream in(text);
			for (;;) {
				in >> std::ws;
				if (in.peek() == std::char_traits<char>::eof()) break;
				json record;
				try {
					in >> record;
				} catch (const json::exception&) {
					break;
				}
				const std::string message = ErrorRecordText(record);
				if (!message.empty()) Report(message);
			}
		}
	}

	void PollExitNotes() {
		std::error_code ec;
		for (const auto& entry: fs::directory_iterator(m_run_dir, ec)) {
			const std::wstring name = entry.path().filename().wstring();
			if (name.rfind(L"fault_provenance.exitnote.", 0) != 0 ||
			    entry.path().extension() != L".txt")
				continue;
			std::string text;
			if (!ReadFileBytes(entry.path(), &text)) continue;
			text = Trim(text);
			if (!text.empty() &&
			    !(m_expected_shutdown && text.find("HOST_EXIT path=") != std::string::npos))
				Report("Kyty host crash: " + text);
		}
	}

	void ReportFatalBlock(const std::vector<std::string>& block) {
		if (m_expected_shutdown) {
			for (const auto& line: block)
				if (line.find("ErrorSurfaceLostKHR") != std::string::npos) return;
		}
		for (const auto& line: block)
			Report("Kyty fatal report: " + line);
	}

	void PollLog(const fs::path& path, bool final) {
		std::error_code ec;
		const uint64_t  size = fs::file_size(path, ec);
		if (ec) return;
		const std::wstring key    = path.wstring();
		uint64_t           offset = m_log_offsets[key];
		if (size < offset) {
			offset = 0;
			m_log_partial[key].clear();
		}
		if (size == offset && !final) return;
		std::string data;
		if (size != offset) {
			std::ifstream in(path, std::ios::binary);
			if (!in) return;
			in.seekg(static_cast<std::streamoff>(offset));
			data.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
			m_log_offsets[key] = offset + data.size();
		}
		const std::string        text = m_log_partial[key] + data;
		std::vector<std::string> lines;
		size_t                   start = 0;
		for (size_t i = 0; i < text.size(); i++) {
			if (text[i] != '\n' && text[i] != '\r') continue;
			if (text[i] == '\r' && i + 1 < text.size() && text[i + 1] == '\n') i++;
			lines.push_back(text.substr(start, i + 1 - start));
			start = i + 1;
		}
		if (start < text.size()) lines.push_back(text.substr(start));
		m_log_partial[key].clear();
		if (!final && !lines.empty() && lines.back().back() != '\n' &&
		    lines.back().back() != '\r') {
			m_log_partial[key] = lines.back();
			lines.pop_back();
		}
		std::vector<std::string> block = std::move(m_fatal_blocks[key]);
		m_fatal_blocks.erase(key);
		for (const auto& raw: lines) {
			const std::string line = Trim(raw);
			if (line == "--- Fatal Error ---" || line == "--- Error ---") {
				if (!block.empty()) ReportFatalBlock(block);
				block = {line};
				continue;
			}
			if (!block.empty() && !line.empty()) {
				block.push_back(line);
				if (FatalSourceLine(line) || block.size() >= 3) {
					ReportFatalBlock(block);
					block.clear();
				}
				continue;
			}
			if (line.find("GUEST_EXEC_FATAL_SIGNAL") != std::string::npos ||
			    line.find("outcome=crashed") != std::string::npos ||
			    line.find("HOST_EXIT path=") != std::string::npos) {
				if (m_expected_shutdown && line.find("HOST_EXIT path=") != std::string::npos)
					continue;
				Report("Kyty failure: " + line, FailureKey(line));
			}
		}
		if (final && !block.empty()) {
			ReportFatalBlock(block);
			block.clear();
		}
		if (!block.empty()) m_fatal_blocks[key] = std::move(block);
	}

	fs::path                                             m_run_dir;
	fs::path                                             m_error_log;
	std::map<std::wstring, std::pair<uint64_t, int64_t>> m_object_versions;
	std::map<std::wstring, uint64_t>                     m_log_offsets;
	std::map<std::wstring, std::string>                  m_log_partial;
	std::map<std::wstring, std::vector<std::string>>     m_fatal_blocks;
	std::set<std::string>                                m_reported;
	bool                                                 m_expected_shutdown = false;
};

std::wstring ExitErrorText(uint32_t value) {
	const wchar_t* description = nullptr;
	switch (value) {
		case 0xC0000005: description = L"access violation"; break;
		case 0xC000001D: description = L"illegal instruction"; break;
		case 0xC0000374: description = L"heap corruption"; break;
		case 0xC0000409: description = L"stack buffer overrun or fail-fast"; break;
		default: break;
	}
	wchar_t text[128];
	swprintf(text, 128, L"Kyty host terminated with exit code 0x%08X%s%s%s.", value,
	         description != nullptr ? L" (" : L"", description != nullptr ? description : L"",
	         description != nullptr ? L")" : L"");
	return text;
}

std::vector<DWORD> EmulatorPids() {
	std::vector<DWORD> found;
	HANDLE             snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) return found;
	PROCESSENTRY32W entry {};
	entry.dwSize = sizeof(entry);
	for (BOOL present = Process32FirstW(snapshot, &entry); present;
	     present      = Process32NextW(snapshot, &entry))
		if (_wcsicmp(entry.szExeFile, L"kyty_emulator.exe") == 0)
			found.push_back(entry.th32ProcessID);
	CloseHandle(snapshot);
	return found;
}

bool IsRepo(const fs::path& dir) {
	std::error_code ec;
	return fs::is_regular_file(dir / "scripts/boot_profile.json", ec) &&
	       fs::is_directory(dir / "firmware", ec);
}

bool ReadToken(const fs::path& path, std::string* token, std::wstring* failure) {
	std::string bytes;
	if (!ReadFileBytes(path, &bytes)) {
		*failure = L"Could not read the token file:\n" + path.wstring() +
		           L"\n\nCheck the path under File > Preferences.";
		return false;
	}
	if (bytes.rfind("\xEF\xBB\xBF", 0) == 0) bytes.erase(0, 3);
	// the payload's own state file is {"bind", "port", "token"}; a bare token file works too
	const json parsed = json::parse(bytes, nullptr, false);
	if (!parsed.is_discarded() && parsed.is_object()) {
		const auto it = parsed.find("token");
		if (it != parsed.end() && it->is_string()) *token = it->get<std::string>();
	} else {
		*token = Trim(bytes);
	}
	SecureZeroMemory(bytes.data(), bytes.size());
	if (token->size() < 32) {
		*failure = L"The token file does not hold a ps5-mcp owner token:\n" + path.wstring();
		return false;
	}
	return true;
}

struct CiLess {
	bool operator()(const std::wstring& a, const std::wstring& b) const {
		return CompareStringOrdinal(a.c_str(), static_cast<int>(a.size()), b.c_str(),
		                            static_cast<int>(b.size()), TRUE) == CSTR_LESS_THAN;
	}
};

using PVirtualAlloc2 = PVOID(WINAPI*)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, void*, ULONG);

// Mirrors start_kyty_ps5.py main() and launch(), with the bridge's envelope provider served in-process.
[[maybe_unused]] bool BootSysLive(const Settings& settings, std::wstring* failure) {
	auto fail = [&](std::wstring text) {
		*failure = std::move(text);
		return false;
	};
	if (settings.ip.empty())
		return fail(L"No PS5 IP address is set.\n\nOpen File > Preferences, enter the PS5's IP "
		            L"address and try Boot sys again.");
	if (settings.token_file.empty())
		return fail(L"No token file is set.\n\nOpen File > Preferences and choose the ps5-mcp "
		            L"payload's token file.");

	const fs::path exe_dir = ExeDir();
	fs::path       repo;
	if (!settings.repo.empty()) {
		repo = settings.repo;
		if (!IsRepo(repo))
			return fail(L"The repository folder set in Preferences does not hold "
			            L"scripts\\boot_profile.json and firmware\\:\n" +
			            repo.wstring());
	} else {
		for (fs::path dir = exe_dir;; dir = dir.parent_path()) {
			if (IsRepo(dir)) {
				repo = dir;
				break;
			}
			if (dir == dir.parent_path()) break;
		}
		if (repo.empty())
			return fail(L"Could not find the kyty-ps5-sysboot checkout above " + exe_dir.wstring() +
			            L".\n\nSet the repository folder under File > Preferences.");
	}

	std::string token;
	if (!ReadToken(settings.token_file, &token, failure)) return false;

	const fs::path profile_path = repo / "scripts/boot_profile.json";
	std::string    profile_text;
	if (!ReadFileBytes(profile_path, &profile_text))
		return fail(L"Could not read " + profile_path.wstring());
	const json profile = json::parse(profile_text, nullptr, false);
	if (profile.is_discarded() || !profile.is_object() || !profile.contains("environment") ||
	    !profile["environment"].is_object() || !profile.value("game", json()).is_string() ||
	    !profile.value("sysroot", json()).is_string())
		return fail(L"Malformed boot profile: " + profile_path.wstring());

	std::error_code ec;
	const fs::path  firmware_root = fs::weakly_canonical(repo / "firmware", ec);
	if (ec) return fail(L"Could not resolve " + (repo / "firmware").wstring());
	std::vector<fs::path> firmware_paths;
	auto                  expand = [&](const std::string& value) {
		std::wstring w = Wide(value);
		if (w.find(L"{firmware}") == std::wstring::npos) return w;
		for (size_t at = w.find(L"{firmware}"); at != std::wstring::npos;
		     at        = w.find(L"{firmware}", at)) {
			w.replace(at, 10, firmware_root.wstring());
			at += firmware_root.wstring().size();
		}
		fs::path path = fs::path(w).lexically_normal();
		if (!path.has_filename() && path.has_relative_path()) path = path.parent_path();
		firmware_paths.push_back(path);
		return path.wstring();
	};
	std::map<std::wstring, std::wstring, CiLess> profile_env;
	for (const auto& [key, value]: profile["environment"].items()) {
		if (!value.is_string()) return fail(L"Malformed boot profile entry " + Wide(key));
		profile_env[Wide(key)] = expand(value.get<std::string>());
	}
	const fs::path game     = expand(profile["game"].get<std::string>());
	const fs::path sysroot  = expand(profile["sysroot"].get<std::string>());
	const auto     psnow_it = profile_env.find(
	    Wide(std::string("KYTY_PS5_AUTHORIZATION_OBSERVATION_") + psnow_self_sha256));
	if (psnow_it == profile_env.end())
		return fail(L"The boot profile has no PsNow authorization observation entry.");
	const fs::path psnow = psnow_it->second;

	const fs::path        emulator = exe_dir / "kyty_emulator.exe";
	std::vector<fs::path> required = {emulator, exe_dir / "libwinpthread-1.dll"};
	required.insert(required.end(), firmware_paths.begin(), firmware_paths.end());
	std::wstring missing;
	size_t       missing_count = 0;
	for (const auto& path: required) {
		if (fs::exists(path, ec)) continue;
		if (++missing_count <= 8) missing += L"\n" + path.wstring();
	}
	if (missing_count > 8) missing += L"\n(" + std::to_wstring(missing_count - 8) + L" more)";
	if (missing_count != 0) return fail(L"Missing Kyty boot input:" + missing);

	std::string head;
	{
		std::ifstream in(game, std::ios::binary);
		head.resize(24);
		in.read(head.data(), 24);
		head.resize(static_cast<size_t>(in.gcount()));
	}
	if (head.rfind("version https://git-lfs", 0) == 0)
		return fail(L"firmware\\ holds Git LFS pointer files instead of the firmware.\n\nRun \"git "
		            L"lfs pull\" in " +
		            repo.wstring() + L" and try again.");

	std::string psnow_sha;
	if (fs::file_size(psnow, ec) != 200 || ec || !Sha256File(psnow, &psnow_sha) ||
	    psnow_sha != psnow_observation_sha256)
		return fail(L"PsNow authorization observation identity mismatch:\n" + psnow.wstring());
	const auto active = EmulatorPids();
	if (!active.empty()) {
		std::wstring pids;
		for (DWORD pid: active)
			pids += (pids.empty() ? L"" : L", ") + std::to_wstring(pid);
		return fail(L"Kyty is already running: " + pids);
	}

	const std::wstring where = settings.ip + L":" + std::to_wstring(settings.port);
	Post(wm_app_status, L"Connecting to the PS5 at " + where);
	Log(L"Checking the ps5-mcp payload at " + where);
	const Sysboot::NativeTarget target {Utf8(settings.ip), settings.port, token};
	SecureZeroMemory(token.data(), token.size());
	json health;
	json error;
	if (!Sysboot::NativeCall(target, "health", json::object(), 10000, &g_stop, &health, &error)) {
		if (g_stop) return true;
		const std::string code    = error.value("code", std::string());
		const std::string message = error.value("message", std::string());
		if (code == "NATIVE_UNREACHABLE")
			return fail(L"Could not connect to the PS5 at " + where +
			            L".\n\nCheck the IP address under File > Preferences, that the console is "
			            L"on the same network, and that the ps5-mcp payload is running on it.");
		if (code == "AUTH_FAILED")
			return fail(L"The PS5 at " + where + L" rejected the owner token from:\n" +
			            settings.token_file +
			            L"\n\nUse the token file of the payload that is running now.");
		return fail(L"The PS5 at " + where + L" did not answer the health check: " + Wide(code) +
		            L": " + Wide(message));
	}
	auto text_field = [&](const char* key) {
		const auto it = health.find(key);
		return it != health.end() && it->is_string() ? it->get<std::string>() : std::string();
	};
	if (text_field("payload") != "ps5-mcp")
		return fail(L"Something answered at " + where + L", but it is not the ps5-mcp payload.");
	const std::string build_id    = text_field("build_id");
	const std::string instance_id = text_field("instance_id");
	if (build_id.empty() || instance_id.size() != 32)
		return fail(L"The ps5-mcp payload at " + where + L" returned a malformed health record.");
	Log(L"ps5-mcp " + Wide(text_field("version")) + L" build " + Wide(build_id) + L" instance " +
	    Wide(instance_id));
	if (health.value("worker_busy", false))
		Log(L"ps5-mcp worker is busy with " + Wide(text_field("current_operation")));

	const std::string       stamp = Timestamp("%Y%m%d_%H%M%S_");
	std::array<uint8_t, 32> key {};
	uint8_t                 random[8];
	if (BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 ||
	    BCryptGenRandom(nullptr, key.data(), static_cast<ULONG>(key.size()),
	                    BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
		return fail(L"BCryptGenRandom failed");
	char hex[16];
	snprintf(hex, sizeof(hex), "%02x%02x", random[0], random[1]);
	const fs::path run_dir = exe_dir / "runs" / (stamp + hex);
	snprintf(hex, sizeof(hex), "%02x%02x%02x", random[2], random[3], random[4]);
	std::string scope = std::string("boot_") + hex;
	snprintf(hex, sizeof(hex), "%02x%02x%02x", random[5], random[6], random[7]);
	scope += hex;
	if (!fs::create_directories(run_dir, ec) || ec)
		return fail(L"Could not create " + run_dir.wstring());
	const fs::path cache = exe_dir / "runtime/cache/immutable_metadata";
	const fs::path log   = run_dir / "kyty.log";

	std::string binary_sha256;
	std::string profile_sha256;
	if (!Sha256File(emulator, &binary_sha256) || !Sha256File(profile_path, &profile_sha256))
		return fail(L"Could not hash the emulator and boot profile.");

	const fs::path token_path = run_dir / "provider.token";
	{
		std::string line;
		for (uint8_t b: key) {
			snprintf(hex, sizeof(hex), "%02x", b);
			line += hex;
		}
		line += '\n';
		std::ofstream out(token_path, std::ios::binary | std::ios::trunc);
		out << line;
		SecureZeroMemory(line.data(), line.size());
		if (!out) return fail(L"Could not write " + token_path.wstring());
	}
	auto wipe_token = [&] {
		std::error_code e;
		const auto      size = fs::file_size(token_path, e);
		if (!e) {
			std::ofstream out(token_path, std::ios::binary | std::ios::trunc);
			out << std::string(static_cast<size_t>(size), '\0');
		}
		fs::remove(token_path, e);
	};

	Sysboot::EnvelopeProvider provider;
	std::wstring              provider_error;
	const bool started = provider.Start(target, build_id, 120000, key, &provider_error);
	SecureZeroMemory(key.data(), key.size());
	if (!started) {
		wipe_token();
		return fail(L"Could not start the envelope provider: " + provider_error);
	}
	Log(L"Envelope provider listening on 127.0.0.1:" + std::to_wstring(provider.Port()));

	std::map<std::wstring, std::wstring, CiLess> env;
	if (wchar_t* block = GetEnvironmentStringsW(); block != nullptr) {
		for (const wchar_t* p = block; *p != L'\0'; p += wcslen(p) + 1) {
			const std::wstring entry = p;
			const size_t       eq    = entry.find(L'=', 1);
			if (eq == std::wstring::npos) continue;
			const std::wstring name = entry.substr(0, eq);
			if (_wcsnicmp(name.c_str(), L"KYTY_", 5) == 0) continue;
			env[name] = entry.substr(eq + 1);
		}
		FreeEnvironmentStringsW(block);
	}
	for (const auto& [name, value]: profile_env)
		env[name] = value;
	wchar_t hwnd_text[32];
	swprintf(hwnd_text, 32, L"0x%llx",
	         static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(g_main)));
	env[L"KYTY_DIAGNOSTIC_IPMI_SHARED_SCOPE"]    = Wide(scope);
	env[L"KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE"] = Wide(scope);
	env[L"KYTY_PS5_ICCNVS4_OVERLAY"]             = (run_dir / "mini_a53_nvram.kytycow").wstring();
	env[L"KYTY_DIAGNOSTIC_PASSTHROUGH_UPPER"]    = (run_dir / "upper").wstring();
	env[L"KYTY_DIAGNOSTIC_UNHANDLED_HOST_PROVENANCE_PREFIX"] =
	    (run_dir / "fault_provenance").wstring();
	env[L"KYTY_DIAGNOSTIC_HOST_DISPLAY_WINDOW"]   = hwnd_text;
	env[L"KYTY_PS5_STARTUP_CACHE_DIR"]            = cache.wstring();
	env[L"KYTY_PS5_STARTUP_CACHE_BUILD_ID"]       = Wide(binary_sha256);
	env[L"KYTY_PS5_ENVELOPE_PROVIDER_TOKEN_FILE"] = token_path.wstring();
	env[L"KYTY_PS5_ENVELOPE_PROVIDER_PORT"]       = std::to_wstring(provider.Port());
	env[L"KYTY_PS5_ENVELOPE_PROVIDER_TIMEOUT_MS"] = std::to_wstring(settings.timeout_ms);
	if (settings.readbacks) {
		env[L"KYTY_DIAGNOSTIC_PRESENT_READBACK"]             = (run_dir / "present").wstring();
		env[L"KYTY_DIAGNOSTIC_PRESENT_READBACK_INTERVAL_MS"] = L"200";
	} else {
		env.erase(L"KYTY_DIAGNOSTIC_PRESENT_READBACK");
		env.erase(L"KYTY_DIAGNOSTIC_PRESENT_READBACK_INTERVAL_MS");
	}
	if (settings.show_services)
		env[L"KYTY_SHOW_SERVICE_WINDOWS"] = L"1";
	else
		env.erase(L"KYTY_SHOW_SERVICE_WINDOWS");
	std::wstring env_block;
	for (const auto& [name, value]: env)
		env_block += name + L"=" + value + L'\0';
	env_block += L'\0';

	auto env_text = [&](const wchar_t* name) {
		const auto it = env.find(name);
		return it == env.end() ? json() : json(Utf8(it->second));
	};
	auto env_one = [&](const wchar_t* name) {
		const auto it = env.find(name);
		return it != env.end() && it->second == L"1";
	};
	nlohmann::ordered_json manifest;
	manifest["created_host_unix"]        = static_cast<int64_t>(std::time(nullptr));
	manifest["binary"]                   = Utf8(emulator.wstring());
	manifest["binary_sha256"]            = binary_sha256;
	manifest["firmware"]                 = Utf8(game.wstring());
	manifest["firmware_root"]            = Utf8(firmware_root.wstring());
	manifest["boot_profile_sha256"]      = profile_sha256;
	manifest["scope"]                    = scope;
	manifest["log"]                      = Utf8(log.wstring());
	manifest["host_console_log"]         = Utf8((run_dir / "host_console.log").wstring());
	manifest["error_report_log"]         = Utf8((run_dir / "error_report.log").wstring());
	manifest["window_telemetry_enabled"] = false;
	manifest["single_visible_window"]    = !settings.show_services;
	manifest["persistent_host_display"]  = true;
	manifest["present_readbacks"]        = settings.readbacks;
	manifest["diagnostic_ipmi_capability62_standin"] =
	    env_text(L"KYTY_DIAGNOSTIC_IPMI_CAPABILITY62_STANDIN");
	manifest["diagnostic_authinfo_compositor_client"] =
	    env_text(L"KYTY_DIAGNOSTIC_AUTHINFO_COMPOSITOR_CLIENT");
	manifest["diagnostic_vdeccore"]           = env_one(L"KYTY_DIAGNOSTIC_VDECCORE");
	manifest["diagnostic_host_input_hid_pad"] = env_one(L"KYTY_DIAGNOSTIC_HOST_INPUT_HID_PAD");
	manifest["diagnostic_mbus_uninitialized_guard"] =
	    env_one(L"KYTY_DIAGNOSTIC_MBUS_UNINITIALIZED_GUARD");
	manifest["diagnostic_puputil_ipmi_admission"] =
	    env_one(L"KYTY_DIAGNOSTIC_PUPUTIL_IPMI_ADMISSION");
	manifest["diagnostic_video_arbitration_coordination_wait"] =
	    env_one(L"KYTY_DIAGNOSTIC_VIDEO_ARBITRATION_INIT");
	manifest["psnow_authorization_observation"]        = Utf8(psnow.wstring());
	manifest["psnow_authorization_observation_sha256"] = psnow_observation_sha256;
	manifest["immutable_metadata_cache"]               = Utf8(cache.wstring());
	manifest["envelope_provider_timeout_ms"]           = settings.timeout_ms;
	manifest["envelope_provider"]                      = "kyty_sysboot";
	{
		std::ofstream out(run_dir / "boot.json", std::ios::binary);
		out << manifest.dump(2) << '\n';
	}
	Log(L"Boot directory: " + run_dir.wstring());
	Log(L"Binary SHA-256: " + Wide(binary_sha256));
	Log(L"Mode: diagnostic coordinated PS5 boot; this is not a fully authentic firmware claim.");

	ErrorReporter reporter(run_dir);
	HANDLE        job = CreateJobObjectW(nullptr, nullptr);
	if (job == nullptr) {
		provider.Stop();
		wipe_token();
		return fail(L"CreateJobObjectW failed: " + std::to_wstring(GetLastError()));
	}
	PROCESS_INFORMATION process {};
	bool                created  = false;
	bool                assigned = false;
	std::wstring        launch_error;
	uint32_t            code = 1;
	do {
		JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
		limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
		if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits,
		                             sizeof(limits))) {
			launch_error = L"SetInformationJobObject failed: " + std::to_wstring(GetLastError());
			break;
		}
		std::wstring command = L"\"" + emulator.wstring() + L"\" --game \"" + game.wstring() +
		                       L"\" --sysroot \"" + sysroot.wstring() +
		                       L"\" --printf-direction File --printf-output-file \"" +
		                       log.wstring() + L"\"";
		SECURITY_ATTRIBUTES inherit {sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
		HANDLE null_input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		                                &inherit, OPEN_EXISTING, 0, nullptr);
		HANDLE console_output =
		    CreateFileW((run_dir / "host_console.log").c_str(), FILE_APPEND_DATA,
			            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &inherit,
			            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		STARTUPINFOW startup {};
		startup.cb         = sizeof(startup);
		startup.dwFlags    = STARTF_USESTDHANDLES;
		startup.hStdInput  = null_input;
		startup.hStdOutput = console_output;
		startup.hStdError  = console_output;
		if (null_input != INVALID_HANDLE_VALUE && console_output != INVALID_HANDLE_VALUE)
			created =
			    CreateProcessW(emulator.c_str(), command.data(), nullptr, nullptr, TRUE,
				               CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
				               env_block.data(), run_dir.c_str(), &startup, &process) != FALSE;
		const DWORD create_error = GetLastError();
		if (null_input != INVALID_HANDLE_VALUE) CloseHandle(null_input);
		if (console_output != INVALID_HANDLE_VALUE) CloseHandle(console_output);
		if (!created) {
			launch_error = L"CreateProcessW failed: " + std::to_wstring(create_error);
			break;
		}
		if (!AssignProcessToJobObject(job, process.hProcess)) {
			launch_error = L"AssignProcessToJobObject failed: " + std::to_wstring(GetLastError());
			break;
		}
		assigned = true;
		// the guest's static exec image sits at 0x400000; claim it before the host's own allocations can land there
		auto virtual_alloc2 = reinterpret_cast<PVirtualAlloc2>(
		    GetProcAddress(GetModuleHandleW(L"KernelBase.dll"), "VirtualAlloc2"));
		void* reserved =
		    virtual_alloc2 != nullptr
		        ? virtual_alloc2(process.hProcess, reinterpret_cast<PVOID>(0x400000), 0x110000,
		                         MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, nullptr, 0)
		        : nullptr;
		if (reserved != reinterpret_cast<void*>(0x400000)) {
			launch_error = L"static exec reservation failed";
			break;
		}
		const DWORD previous = ResumeThread(process.hThread);
		if (previous != 1) {
			launch_error = L"ResumeThread returned " + std::to_wstring(previous);
			break;
		}
		Log(L"Kyty host process " + std::to_wstring(process.dwProcessId) + L" started.");
		Post(wm_app_status, L"Kyty is running. File > Stop sys stops the boot job.");
		for (;;) {
			const DWORD wait = WaitForSingleObject(process.hProcess, 500);
			if (g_stop) {
				reporter.BeginExpectedShutdown();
				TerminateJobObject(job, 0xC000013A);
				WaitForSingleObject(process.hProcess, 5000);
				Log(L"Boot job stopped.");
				code = 130;
				break;
			}
			reporter.Poll(false);
			if (wait == WAIT_OBJECT_0) {
				DWORD exit_code = 0;
				if (!GetExitCodeProcess(process.hProcess, &exit_code)) {
					launch_error = L"GetExitCodeProcess failed: " + std::to_wstring(GetLastError());
					break;
				}
				reporter.Poll(true);
				code = exit_code;
				break;
			}
			if (wait != WAIT_TIMEOUT) {
				launch_error = L"WaitForSingleObject returned " + std::to_wstring(wait);
				break;
			}
		}
	} while (false);
	if (!launch_error.empty()) {
		if (assigned)
			TerminateJobObject(job, 1);
		else if (created)
			TerminateProcess(process.hProcess, 1);
	}
	reporter.Poll(true);
	if (created) {
		CloseHandle(process.hThread);
		CloseHandle(process.hProcess);
	}
	CloseHandle(job);
	provider.Stop();
	wipe_token();
	Log(L"Envelope provider served " + std::to_wstring(provider.Completed()) +
	    L" requests, rejected " + std::to_wstring(provider.Rejected()) + L".");
	if (!launch_error.empty()) return fail(L"Kyty boot failed: " + launch_error);

	wchar_t exit_text[64];
	swprintf(exit_text, 64, L"Kyty host exit code: 0x%08x", code);
	Log(exit_text);
	if (code != 0 && code != 130)
		return fail(ExitErrorText(code) + L"\n\nSee " + (run_dir / "error_report.log").wstring() +
		            L" and View > Log.");
	return true;
}

bool BootSysOffline(const Settings& settings, std::wstring* failure) {
	auto fail = [&](std::wstring text) {
		*failure = std::move(text);
		return false;
	};
	const fs::path exe_dir = ExeDir();
	fs::path repo;
	if (!settings.repo.empty()) {
		repo = settings.repo;
		if (!IsRepo(repo))
			return fail(L"The repository folder in Preferences does not contain the firmware and boot profile:\n" +
			            repo.wstring());
	} else {
		for (fs::path dir = exe_dir;; dir = dir.parent_path()) {
			if (IsRepo(dir)) {
				repo = dir;
				break;
			}
			if (dir == dir.parent_path()) break;
		}
		if (repo.empty())
			return fail(L"Could not find the project folder. Set it under File > Preferences.");
	}
	const fs::path profile = repo / "scripts/boot_profile_offline_completed.json";
	const fs::path store = L"D:\\PS5_Backups\\13.60_2026-11-20\\preupdate_rnps_replay_store_20261120_derived";
	const fs::path runner = repo / "scripts/start_kyty_ps5_tokenless_replay.py";
	const fs::path launcher = repo / "scripts/start_kyty_ps5_offline_visual.py";
	const fs::path emulator = exe_dir / "kyty_emulator.exe";
	const fs::path state_dir = ConsoleStateDir();
	for (const fs::path& path: {profile, runner, launcher, emulator, exe_dir / "libwinpthread-1.dll"}) {
		std::error_code ec;
		if (!fs::is_regular_file(path, ec)) return fail(L"Missing offline boot file:\n" + path.wstring());
	}
	if (!fs::is_directory(store)) return fail(L"Missing saved console replay data:\n" + store.wstring());
	if (!EmulatorPids().empty()) return fail(L"Kyty is already running. Stop it before starting another boot.");
	std::wstring python(32768, L'\0');
	const DWORD python_length =
	    SearchPathW(nullptr, L"python.exe", nullptr, static_cast<DWORD>(python.size()), python.data(), nullptr);
	if (python_length == 0 || python_length >= python.size())
		return fail(L"Python was not found. Install Python or add python.exe to PATH.");
	python.resize(python_length);
	const fs::path log_root = state_dir.parent_path() / "launcher_logs";
	std::error_code ec;
	fs::create_directories(log_root, ec);
	if (ec) return fail(L"Could not create launcher log folder:\n" + log_root.wstring());
	const fs::path log_path = log_root /
	    (L"gui_" + Wide(Timestamp("%Y%m%d_%H%M%S")) + L"_" +
	     std::to_wstring(GetCurrentProcessId()) + L"_" + std::to_wstring(GetTickCount64()) + L".log");
	SECURITY_ATTRIBUTES inherit {sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
	HANDLE output = CreateFileW(log_path.c_str(), FILE_APPEND_DATA,
	                            FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, CREATE_NEW,
	                            FILE_ATTRIBUTE_NORMAL, nullptr);
	if (output == INVALID_HANDLE_VALUE)
		return fail(L"Could not create launcher log:\n" + log_path.wstring());
	HANDLE input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
	                           &inherit, OPEN_EXISTING, 0, nullptr);
	if (input == INVALID_HANDLE_VALUE) {
		CloseHandle(output);
		return fail(L"Could not open NUL for offline boot.");
	}
	std::wstring command = L"\"" + python + L"\" \"" + runner.wstring() +
	    L"\" --project \"" + repo.wstring() + L"\" --profile \"" + profile.wstring() +
	    L"\" --emulator \"" + emulator.wstring() + L"\" --store \"" + store.wstring() +
	    L"\" --proxy-port 0 --runtime-store-root \"" +
	    (state_dir.parent_path() / "replay_runtime_stores").wstring() +
	    L"\" --launcher-source \"" + launcher.wstring() +
	    L"\" --timeout 100 --max-bytes 268435456 --diagnostic-virtual-usb-pad --state-dir \"" +
	    state_dir.wstring() + L"\" --host-window-hwnd " +
	    std::to_wstring(reinterpret_cast<uintptr_t>(g_main));
	if (settings.readbacks) command += L" --readbacks";
	if (settings.show_services) command += L" --show-services";
	STARTUPINFOW startup {};
	startup.cb = sizeof(startup);
	startup.dwFlags = STARTF_USESTDHANDLES;
	startup.hStdInput = input;
	startup.hStdOutput = output;
	startup.hStdError = output;
	HANDLE job = CreateJobObjectW(nullptr, nullptr);
	if (job == nullptr) {
		CloseHandle(input);
		CloseHandle(output);
		return fail(L"Could not create offline boot job.");
	}
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
	limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
		CloseHandle(input);
		CloseHandle(output);
		CloseHandle(job);
		return fail(L"Could not configure offline boot job.");
	}
	PROCESS_INFORMATION process {};
	const bool created = CreateProcessW(python.c_str(), command.data(), nullptr, nullptr, TRUE,
	                                   CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, repo.c_str(),
	                                   &startup, &process) != FALSE;
	CloseHandle(input);
	CloseHandle(output);
	if (!created) {
		const DWORD error = GetLastError();
		CloseHandle(job);
		return fail(L"Could not start offline boot: Windows error " + std::to_wstring(error));
	}
	if (!AssignProcessToJobObject(job, process.hProcess)) {
		TerminateProcess(process.hProcess, 1);
		CloseHandle(process.hThread);
		CloseHandle(process.hProcess);
		CloseHandle(job);
		return fail(L"Could not attach offline boot to its stop job.");
	}
	if (ResumeThread(process.hThread) != 1) {
		TerminateJobObject(job, 1);
		CloseHandle(process.hThread);
		CloseHandle(process.hProcess);
		CloseHandle(job);
		return fail(L"Could not resume offline boot.");
	}
	Log(L"Offline boot started. Saved state: " + state_dir.wstring());
	Log(L"Launcher log: " + log_path.wstring());
	Post(wm_app_status, L"Kyty is running offline. File > Stop sys stops it.");
	uint64_t read_offset = 0;
	std::string partial;
	auto poll_output = [&] {
		std::ifstream stream(log_path, std::ios::binary);
		if (!stream) return;
		stream.seekg(static_cast<std::streamoff>(read_offset));
		const std::string chunk(std::istreambuf_iterator<char>(stream), {});
		read_offset += chunk.size();
		partial += chunk;
		for (size_t newline = partial.find('\n'); newline != std::string::npos;
		     newline = partial.find('\n')) {
			std::string line = partial.substr(0, newline);
			if (!line.empty() && line.back() == '\r') line.pop_back();
			if (!line.empty()) Log(Wide(line));
			partial.erase(0, newline + 1);
		}
	};
	DWORD exit_code = 0;
	for (;;) {
		const DWORD wait = WaitForSingleObject(process.hProcess, 500);
		poll_output();
		if (g_stop) {
			TerminateJobObject(job, 0xC000013A);
			WaitForSingleObject(process.hProcess, 5000);
			exit_code = 130;
			break;
		}
		if (wait == WAIT_OBJECT_0) {
			if (!GetExitCodeProcess(process.hProcess, &exit_code)) exit_code = 1;
			break;
		}
		if (wait != WAIT_TIMEOUT) {
			exit_code = 1;
			break;
		}
	}
	poll_output();
	if (!partial.empty()) Log(Wide(partial));
	CloseHandle(process.hThread);
	CloseHandle(process.hProcess);
	CloseHandle(job);
	if (exit_code == 130) {
		Log(L"Offline boot stopped.");
		return true;
	}
	if (exit_code != 0)
		return fail(L"Offline boot stopped with exit code " + std::to_wstring(exit_code) +
		            L". See launcher log:\n" + log_path.wstring());
	Log(L"Offline boot completed.");
	return true;
}

void AppendLog(const std::wstring& text) {
	std::wstring line = text;
	for (size_t at = line.find(L'\n'); at != std::wstring::npos; at = line.find(L'\n', at + 2))
		if (at == 0 || line[at - 1] != L'\r') line.insert(at++, 1, L'\r');
	line += L"\r\n";
	const int length = GetWindowTextLengthW(g_log_edit);
	if (length > 4 * 1024 * 1024) {
		SendMessageW(g_log_edit, EM_SETSEL, 0, length / 2);
		SendMessageW(g_log_edit, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(L""));
	}
	SendMessageW(g_log_edit, EM_SETSEL, static_cast<WPARAM>(-1), -1);
	SendMessageW(g_log_edit, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(line.c_str()));
}

void ShowLog() {
	ShowWindow(g_log, SW_SHOWNORMAL);
	SetForegroundWindow(g_log);
}

bool Browse(HWND owner, bool folder, std::wstring* path) {
	IFileOpenDialog* dialog = nullptr;
	if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
	                            IID_PPV_ARGS(&dialog))))
		return false;
	FILEOPENDIALOGOPTIONS options = 0;
	dialog->GetOptions(&options);
	dialog->SetOptions(options | FOS_FORCEFILESYSTEM | (folder ? FOS_PICKFOLDERS : 0));
	if (!folder) {
		const COMDLG_FILTERSPEC filters[] = {
		    {L"Token files (*.json, *.txt, *.token)", L"*.json;*.txt;*.token"},
		    {L"All files", L"*.*"}};
		dialog->SetFileTypes(2, filters);
	}
	bool picked = false;
	if (SUCCEEDED(dialog->Show(owner))) {
		IShellItem* item = nullptr;
		if (SUCCEEDED(dialog->GetResult(&item))) {
			PWSTR name = nullptr;
			if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &name))) {
				*path  = name;
				picked = true;
				CoTaskMemFree(name);
			}
			item->Release();
		}
	}
	dialog->Release();
	return picked;
}

std::wstring DialogText(HWND dialog, int id) {
	std::wstring text(GetWindowTextLengthW(GetDlgItem(dialog, id)) + 1, L'\0');
	text.resize(GetDlgItemTextW(dialog, id, text.data(), static_cast<int>(text.size())));
	return Trim(text);
}

INT_PTR CALLBACK PreferencesProc(HWND dialog, UINT message, WPARAM wparam, LPARAM /*lparam*/) {
	switch (message) {
		case WM_INITDIALOG:
			SetDlgItemTextW(dialog, IDC_REPO, g_settings.repo.c_str());
			CheckDlgButton(dialog, IDC_READBACKS,
			               g_settings.readbacks ? BST_CHECKED : BST_UNCHECKED);
			CheckDlgButton(dialog, IDC_SHOW_SERVICES,
			               g_settings.show_services ? BST_CHECKED : BST_UNCHECKED);
			EnableWindow(GetDlgItem(dialog, IDC_RESET_STATE),
			             !g_running && EmulatorPids().empty());
			return TRUE;
		case WM_COMMAND:
			switch (LOWORD(wparam)) {
				case IDC_RESET_STATE: ResetConsoleState(dialog); return TRUE;
				case IDC_REPO_BROWSE: {
					std::wstring path;
					if (Browse(dialog, true, &path))
						SetDlgItemTextW(dialog, IDC_REPO, path.c_str());
					return TRUE;
				}
				case IDOK: {
					g_settings.repo       = DialogText(dialog, IDC_REPO);
					g_settings.readbacks = IsDlgButtonChecked(dialog, IDC_READBACKS) == BST_CHECKED;
					g_settings.show_services =
					    IsDlgButtonChecked(dialog, IDC_SHOW_SERVICES) == BST_CHECKED;
					SaveSettings(g_settings);
					EndDialog(dialog, IDOK);
					return TRUE;
				}
				case IDCANCEL: EndDialog(dialog, IDCANCEL); return TRUE;
				default: break;
			}
			break;
		default: break;
	}
	return FALSE;
}

HWND VisibleChild(HWND window) {
	for (HWND child = GetWindow(window, GW_CHILD); child != nullptr;
	     child      = GetWindow(child, GW_HWNDNEXT))
		if (IsWindowVisible(child)) return child;
	return nullptr;
}

void FocusVisibleChild(HWND window) {
	static std::tuple<HWND, DWORD, bool, bool> last_focus {};
	if (GetForegroundWindow() != window) return;
	HWND child = VisibleChild(window);
	if (child == nullptr) return;
	const DWORD broker_thread = GetCurrentThreadId();
	const DWORD child_thread  = GetWindowThreadProcessId(child, nullptr);
	if (child_thread == 0) return;
	const bool attached = child_thread == broker_thread ||
	                      AttachThreadInput(broker_thread, child_thread, TRUE) != FALSE;
	bool       focused  = false;
	if (attached) {
		SetFocus(child);
		focused = GetFocus() == child;
		if (child_thread != broker_thread) AttachThreadInput(broker_thread, child_thread, FALSE);
	}
	const auto result = std::make_tuple(child, child_thread, attached, focused);
	if (result != last_focus) {
		wchar_t text[160];
		swprintf(text, 160,
		         L"NON_AUTHENTIC_INPUT_BRIDGE HOST_DISPLAY_FOCUS child=0x%llx child_thread=%lu "
		         L"attached=%d focused=%d",
		         static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(child)), child_thread,
		         attached ? 1 : 0, focused ? 1 : 0);
		AppendLog(text);
		last_focus = result;
	}
}

BOOL CALLBACK ResizeChild(HWND window, LPARAM packed_size) {
	SetWindowPos(window, nullptr, 0, 0, LOWORD(packed_size), HIWORD(packed_size),
	             SWP_NOZORDER | SWP_NOACTIVATE);
	return TRUE;
}

void StartBoot() {
	if (g_running) return;
	if (g_worker.joinable()) g_worker.join();
	g_stop                 = false;
	g_running              = true;
	g_log_opened_for_error = false;
	AppendLog(L"Boot sys");
	g_worker = std::thread([settings = g_settings] {
		std::wstring failure;
		if (!BootSysOffline(settings, &failure)) Post(wm_app_fail, failure);
		Post(wm_app_done, {});
	});
}

void ResetConsoleState(HWND owner) {
	if (g_running || !EmulatorPids().empty()) {
		MessageBoxW(owner, L"Stop Kyty before resetting the saved console state.",
		            L"Reset console state", MB_ICONWARNING);
		return;
	}
	const fs::path state = ConsoleStateDir();
	const fs::path root = state.parent_path();
	std::error_code ec;
	const fs::path resolved_root = fs::weakly_canonical(root, ec);
	if (ec || !resolved_root.is_absolute()) {
		MessageBoxW(owner, L"Saved state folder is unavailable.", L"Reset console state",
		            MB_ICONERROR);
		return;
	}
	const fs::path resolved_state = fs::weakly_canonical(state, ec);
	if (ec || resolved_state.parent_path() != resolved_root) {
		MessageBoxW(owner, L"Saved state path failed its safety check.",
		            L"Reset console state", MB_ICONERROR);
		return;
	}
	if (!fs::is_directory(state, ec)) {
		MessageBoxW(owner, L"There is no saved console state to reset.",
		            L"Reset console state", MB_OK);
		return;
	}
	const fs::path archive = root /
	    (state.filename().wstring() + L".archive." + Wide(Timestamp("%Y%m%d_%H%M%S")) + L"." +
	     std::to_wstring(GetTickCount64()));
	const fs::path resolved_archive = fs::weakly_canonical(archive, ec);
	if (ec || resolved_archive.parent_path() != resolved_root || fs::exists(archive, ec)) {
		MessageBoxW(owner, L"Could not select a safe archive path for saved state.",
		            L"Reset console state", MB_ICONERROR);
		return;
	}
	fs::rename(state, archive, ec);
	if (ec) {
		MessageBoxW(owner, L"Could not archive saved state. Nothing was reset.",
		            L"Reset console state", MB_ICONERROR);
		return;
	}
	fs::create_directory(state, ec);
	Log(L"Saved console state archived at " + archive.wstring());
	if (ec)
		MessageBoxW(owner, (L"Saved state was archived, but a new folder could not be created:\n" +
		                     archive.wstring()).c_str(), L"Reset console state", MB_ICONERROR);
	else
		MessageBoxW(owner, L"Saved console state was reset. The previous state is archived.",
		            L"Reset console state", MB_OK);
}

LRESULT CALLBACK MainProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
	switch (message) {
		case WM_SIZE: EnumChildWindows(window, ResizeChild, lparam); return 0;
		case WM_SETFOCUS:
		case focus_visible_child_message: FocusVisibleChild(window); return 0;
		case WM_KEYDOWN:
		case WM_KEYUP:
		case WM_CHAR:
		case WM_SYSKEYDOWN:
		case WM_SYSKEYUP:
		case WM_SYSCHAR:
			if (HWND child = VisibleChild(window); child != nullptr) {
				PostMessageW(child, message, wparam, lparam);
				return 0;
			}
			break;
		case WM_PAINT: {
			PAINTSTRUCT paint;
			HDC         dc = BeginPaint(window, &paint);
			if (VisibleChild(window) == nullptr) {
				RECT client;
				GetClientRect(window, &client);
				SetBkMode(dc, TRANSPARENT);
				SetTextColor(dc, RGB(0xA0, 0xA0, 0xA0));
				HGDIOBJ old     = SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
				RECT    measure = client;
				DrawTextW(dc, g_status.c_str(), -1, &measure,
				          DT_CENTER | DT_WORDBREAK | DT_CALCRECT);
				const int height = measure.bottom - measure.top;
				client.top       = (client.bottom - height) / 2;
				DrawTextW(dc, g_status.c_str(), -1, &client, DT_CENTER | DT_WORDBREAK);
				SelectObject(dc, old);
			}
			EndPaint(window, &paint);
			return 0;
		}
		case WM_INITMENUPOPUP: {
			HMENU menu = reinterpret_cast<HMENU>(wparam);
			EnableMenuItem(menu, IDM_BOOT, MF_BYCOMMAND | (g_running ? MF_GRAYED : MF_ENABLED));
			EnableMenuItem(menu, IDM_STOP, MF_BYCOMMAND | (g_running ? MF_ENABLED : MF_GRAYED));
			EnableMenuItem(menu, IDM_RESET_STATE,
			               MF_BYCOMMAND | (g_running || !EmulatorPids().empty() ? MF_GRAYED : MF_ENABLED));
			CheckMenuItem(menu, IDM_LOG,
			              MF_BYCOMMAND | (IsWindowVisible(g_log) ? MF_CHECKED : MF_UNCHECKED));
			return 0;
		}
		case WM_COMMAND:
			switch (LOWORD(wparam)) {
				case IDM_BOOT: StartBoot(); return 0;
				case IDM_STOP:
					if (g_running) {
						AppendLog(L"Stop sys");
						g_stop = true;
					}
					return 0;
				case IDM_RESET_STATE: ResetConsoleState(window); return 0;
				case IDM_PREFERENCES:
					DialogBoxParamW(g_instance, MAKEINTRESOURCEW(IDD_PREFERENCES), window,
					                PreferencesProc, 0);
					return 0;
				case IDM_EXIT: PostMessageW(window, WM_CLOSE, 0, 0); return 0;
				case IDM_LOG:
					if (IsWindowVisible(g_log))
						ShowWindow(g_log, SW_HIDE);
					else
						ShowLog();
					return 0;
				default: break;
			}
			break;
		case wm_app_log:
		case wm_app_report:
		case wm_app_status:
		case wm_app_fail: {
			std::unique_ptr<std::wstring> text(reinterpret_cast<std::wstring*>(lparam));
			if (message == wm_app_status) {
				g_status = *text;
				InvalidateRect(window, nullptr, TRUE);
			} else if (message == wm_app_fail) {
				AppendLog(L"Boot failed: " + *text);
				if (!g_quit) MessageBoxW(window, text->c_str(), L"Kyty PS5", MB_ICONERROR);
			} else {
				AppendLog(*text);
				if (message == wm_app_report && !g_log_opened_for_error && !g_quit) {
					g_log_opened_for_error = true;
					ShowWindow(g_log, SW_SHOWNOACTIVATE);
				}
			}
			return 0;
		}
		case wm_app_done: {
			delete reinterpret_cast<std::wstring*>(lparam);
			if (g_worker.joinable()) g_worker.join();
			g_running = false;
			g_status  = idle_hint;
			SetWindowTextW(window, L"Kyty PS5");
			InvalidateRect(window, nullptr, TRUE);
			if (g_quit) DestroyWindow(window);
			return 0;
		}
		case WM_CLOSE:
			if (g_running) {
				// the emulator's windows are children of this one; keep pumping until the job is gone
				g_quit = true;
				g_stop = true;
				ShowWindow(window, SW_HIDE);
				ShowWindow(g_log, SW_HIDE);
				return 0;
			}
			DestroyWindow(window);
			return 0;
		case WM_DESTROY: PostQuitMessage(0); return 0;
		default: break;
	}
	return DefWindowProcW(window, message, wparam, lparam);
}

LRESULT CALLBACK LogProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
	switch (message) {
		case WM_SIZE: MoveWindow(g_log_edit, 0, 0, LOWORD(lparam), HIWORD(lparam), TRUE); return 0;
		case WM_CLOSE: ShowWindow(window, SW_HIDE); return 0;
		default: break;
	}
	return DefWindowProcW(window, message, wparam, lparam);
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE /*previous*/, PWSTR /*command_line*/, int show) {
	g_instance = instance;
	SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
	CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	g_settings = LoadSettings();

	WNDCLASSW main_class {};
	main_class.style         = CS_HREDRAW | CS_VREDRAW;
	main_class.lpfnWndProc   = MainProc;
	main_class.hInstance     = instance;
	main_class.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
	main_class.hbrBackground = static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
	main_class.lpszClassName = L"KytySysboot";
	main_class.lpszMenuName  = MAKEINTRESOURCEW(IDR_MENU);
	WNDCLASSW log_class {};
	log_class.lpfnWndProc   = LogProc;
	log_class.hInstance     = instance;
	log_class.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
	log_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
	log_class.lpszClassName = L"KytySysbootLog";
	if (RegisterClassW(&main_class) == 0 || RegisterClassW(&log_class) == 0) return 1;

	const DWORD style = WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN;
	RECT        rect  = {0, 0, 1280, 720};
	AdjustWindowRectExForDpi(&rect, style, TRUE, 0, GetDpiForSystem());
	const int width  = rect.right - rect.left;
	const int height = rect.bottom - rect.top;
	g_main = CreateWindowExW(0, L"KytySysboot", L"Kyty PS5", style,
	                         std::max(0, (GetSystemMetrics(SM_CXSCREEN) - width) / 2),
	                         std::max(0, (GetSystemMetrics(SM_CYSCREEN) - height) / 2), width,
	                         height, nullptr, nullptr, instance, nullptr);
	if (g_main == nullptr) return 1;
	const UINT dpi = GetDpiForWindow(g_main);
	g_log          = CreateWindowExW(0, L"KytySysbootLog", L"Kyty PS5 log", WS_OVERLAPPEDWINDOW,
	                                 CW_USEDEFAULT, CW_USEDEFAULT, MulDiv(900, dpi, 96),
	                                 MulDiv(500, dpi, 96), g_main, nullptr, instance, nullptr);
	g_log_edit = CreateWindowExW(0, L"EDIT", L"",
	                             WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
	                                 ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
	                             0, 0, 0, 0, g_log, nullptr, instance, nullptr);
	g_log_font = CreateFontW(-MulDiv(9, dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
	                         DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
	                         CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
	SendMessageW(g_log_edit, WM_SETFONT, reinterpret_cast<WPARAM>(g_log_font), FALSE);
	SendMessageW(g_log_edit, EM_SETLIMITTEXT, 0, 0);
	RECT client;
	GetClientRect(g_log, &client);
	MoveWindow(g_log_edit, 0, 0, client.right, client.bottom, FALSE);

	ShowWindow(g_main, show);
	UpdateWindow(g_main);
	MSG message;
	while (GetMessageW(&message, nullptr, 0, 0) > 0) {
		TranslateMessage(&message);
		DispatchMessageW(&message);
	}
	if (g_worker.joinable()) g_worker.join();
	DeleteObject(g_log_font);
	CoUninitialize();
	return static_cast<int>(message.wParam);
}
