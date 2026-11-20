#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef small
#undef small
#endif
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
	uint8_t              physical_connected = 0;
	uint8_t              physical_ps5 = 0;
	uint8_t              physical_transport = 0;
	uint8_t              reserved = 0;
	uint32_t             physical_connected_count = 0;
};

struct Reader {
	uint64_t sequence = 0;
	bool     attached = false;
	uint32_t neutralized_producer_pid = 0;
	uint64_t neutralized_sequence = 0;
#ifdef _WIN32
	uint32_t producer_pid = 0;
	HANDLE producer_process = nullptr;
	Reader() = default;
	Reader(const Reader&) = delete;
	Reader& operator=(const Reader&) = delete;
	Reader(Reader&& other) noexcept { *this = std::move(other); }
	Reader& operator=(Reader&& other) noexcept {
		if (this == &other) return *this;
		if (producer_process != nullptr) CloseHandle(producer_process);
		sequence = other.sequence;
		attached = other.attached;
		neutralized_producer_pid = other.neutralized_producer_pid;
		neutralized_sequence = other.neutralized_sequence;
		producer_pid = other.producer_pid;
		producer_process = other.producer_process;
		other.producer_process = nullptr;
		return *this;
	}
	~Reader() {
		if (producer_process != nullptr) CloseHandle(producer_process);
	}
#endif
};

#ifdef _WIN32
namespace Detail {

constexpr uint32_t MAGIC           = 0x4b484953;
constexpr uint32_t VERSION         = 3;
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
	uint32_t                     producer_pid = 0;
	uint32_t                     reserved = 0;
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

inline Context& GetContext() {
	static Context context;
	return context;
}

inline std::mutex& GetContextMutex() {
	static std::mutex mutex;
	return mutex;
}

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

inline uint64_t Publish(const State& input) {
	std::lock_guard context_lock(Detail::GetContextMutex());
	auto&           context = Detail::GetContext();
	if (!context.Open(Detail::Scope())) return 0;
	Detail::Lock lock(context.mutex);
	if (!lock.Locked()) return 0;
	context.state->producer_pid = GetCurrentProcessId();
	const auto sequence = ++context.state->sequence;
	auto&      record   = context.state->records[(sequence - 1) % Detail::CAPACITY];
	record.state        = input;
	record.sequence     = sequence;
	return sequence;
}

inline size_t Read(Reader* reader, State* output, size_t capacity) {
	if (reader == nullptr || output == nullptr || capacity == 0) return 0;
	std::lock_guard context_lock(Detail::GetContextMutex());
	auto&           context = Detail::GetContext();
	if (!context.Open(Detail::Scope())) return 0;
	Detail::Lock lock(context.mutex);
	if (!lock.Locked()) return 0;

	const auto latest = context.state->sequence;
	const auto producer_pid = context.state->producer_pid;
	if (reader->producer_pid != producer_pid) {
		if (reader->producer_process != nullptr) CloseHandle(reader->producer_process);
		reader->producer_process = nullptr;
		reader->producer_pid = producer_pid;
	}
	if (reader->producer_process == nullptr && producer_pid != 0 &&
	    producer_pid != GetCurrentProcessId()) {
		reader->producer_process = OpenProcess(SYNCHRONIZE, FALSE, producer_pid);
	}
	if (reader->producer_process != nullptr &&
	    WaitForSingleObject(reader->producer_process, 0) == WAIT_OBJECT_0) {
		if (reader->neutralized_producer_pid == producer_pid &&
		    reader->neutralized_sequence == latest) return 0;
		reader->neutralized_producer_pid = producer_pid;
		reader->neutralized_sequence = latest;
		reader->attached = true;
		reader->sequence = latest;
		output[0] = {};
		return 1;
	}
	reader->neutralized_producer_pid = 0;
	reader->neutralized_sequence = 0;
	if (!reader->attached) {
		reader->attached = true;
		reader->sequence = latest;
		if (latest == 0) return 0;
		const auto& record = context.state->records[(latest - 1) % Detail::CAPACITY];
		if (record.sequence != latest) return 0;
		output[0] = record.state;
		return 1;
	}
	if (reader->sequence >= latest) return 0;
	auto next = reader->sequence + 1;
	if (latest - next + 1 > Detail::CAPACITY) next = latest - Detail::CAPACITY + 1;

	size_t count = 0;
	while (next <= latest && count < capacity) {
		const auto& record = context.state->records[(next - 1) % Detail::CAPACITY];
		if (record.sequence == next) output[count++] = record.state;
		reader->sequence = next++;
	}
	return count;
}

#else

inline uint64_t Publish(const State&) {
	return 0;
}

inline size_t Read(Reader*, State*, size_t) {
	return 0;
}

#endif

} // namespace Libs::Controller::HostInputShared
