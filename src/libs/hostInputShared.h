#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif
namespace Libs::Controller::HostInputShared {
struct Touch {
	uint8_t  id   = 0;
	uint8_t  down = 0;
	uint16_t x    = 0;
	uint16_t y    = 0;
};
struct State {
	uint32_t             buttons = 0;
	std::array<int, 6>   axes {128, 128, 128, 128, 0, 0};
	std::array<Touch, 2> touch {};
};
struct Reader {
	uint64_t sequence = 0;
	bool     attached = false;
};
#ifdef _WIN32
namespace Detail {
constexpr uint32_t MAGIC           = 0x4b484953;
constexpr uint32_t VERSION         = 1;
constexpr size_t   CAPACITY        = 128;
constexpr DWORD    LOCK_TIMEOUT_MS = 25;
struct Record {
	uint64_t sequence = 0;
	State    state;
};
struct SharedState {
	uint32_t                     magic      = 0;
	uint32_t                     version    = 0;
	uint64_t                     scope_hash = 0;
	uint64_t                     sequence   = 0;
	std::array<Record, CAPACITY> records;
};
inline uint64_t Hash(const std::string& text) {
	uint64_t hash = 0xcbf29ce484222325ull;
	for (const unsigned char value: text) {
		hash = (hash ^ value) * 0x100000001b3ull;
	}
	return hash;
}
inline std::string Environment(const char* name) {
	const auto size = GetEnvironmentVariableA(name, nullptr, 0);
	if (size == 0) return {};
	std::string value(size, '\0');
	const auto  length = GetEnvironmentVariableA(name, value.data(), size);
	if (length == 0 || length >= size) return {};
	value.resize(length);
	return value;
}
inline std::string Scope() {
	const auto scope       = Environment("KYTY_DIAGNOSTIC_PSM_LOCAL_UNIX_SCOPE");
	const auto coordinated = Environment("KYTY_DIAGNOSTIC_PROCESS_REGISTRY_SCOPE_ONLY");
	return !scope.empty() && coordinated == "1" ? scope : std::string();
}
struct Context {
	std::string  scope;
	HANDLE       mutex   = nullptr;
	HANDLE       mapping = nullptr;
	SharedState* state   = nullptr;

	Context()                          = default;
	Context(const Context&)            = delete;
	Context& operator=(const Context&) = delete;
	~Context() { Close(); }

	void Close() {
		if (state != nullptr) UnmapViewOfFile(state);
		if (mapping != nullptr) CloseHandle(mapping);
		if (mutex != nullptr) CloseHandle(mutex);
		scope.clear();
		mutex   = nullptr;
		mapping = nullptr;
		state   = nullptr;
	}

	bool Open(const std::string& requested) {
		if (requested == scope && state != nullptr) return true;
		Close();
		if (requested.empty()) return false;

		const auto hash = Hash(requested);
		const auto base = "Local\\KytyHostInput." + std::to_string(hash);
		mutex           = CreateMutexA(nullptr, FALSE, (base + ".mutex").c_str());
		if (mutex == nullptr) return false;
		mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
		                             sizeof(SharedState), (base + ".state").c_str());
		if (mapping == nullptr) {
			Close();
			return false;
		}
		const bool created = GetLastError() != ERROR_ALREADY_EXISTS;
		state              = static_cast<SharedState*>(
		    MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(SharedState)));
		if (state == nullptr) {
			Close();
			return false;
		}
		const auto wait = WaitForSingleObject(mutex, LOCK_TIMEOUT_MS);
		if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
			Close();
			return false;
		}
		if (created) {
			std::memset(state, 0, sizeof(*state));
			state->magic      = MAGIC;
			state->version    = VERSION;
			state->scope_hash = hash;
		}
		const bool valid =
		    state->magic == MAGIC && state->version == VERSION && state->scope_hash == hash;
		ReleaseMutex(mutex);
		if (!valid) {
			Close();
			return false;
		}
		scope = requested;
		return true;
	}
};
class Lock {
public:
	explicit Lock(HANDLE mutex): m_mutex(mutex) {
		const auto wait = WaitForSingleObject(mutex, Detail::LOCK_TIMEOUT_MS);
		m_locked        = wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED;
	}
	Lock(const Lock&)            = delete;
	Lock& operator=(const Lock&) = delete;
	~Lock() {
		if (m_locked) ReleaseMutex(m_mutex);
	}
	[[nodiscard]] bool Locked() const { return m_locked; }

private:
	HANDLE m_mutex  = nullptr;
	bool   m_locked = false;
};
} // namespace Detail
#else
#endif
} // namespace Libs::Controller::HostInputShared
