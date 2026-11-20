#include "kernel/regMgr.h"

#include "common/logging/log.h"
#include "common/threads.h"
#include "kernel/authInfo.h"
#include "kernel/process.h"
#include "libs/errno.h"

#include <algorithm>
#include <array>
#include <cinttypes>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace Libs::LibKernel::RegMgr {

// 13.60 registry row. Table at kernel text +0x3cf7e50, u16 count 0x10 bytes before it
struct Row {
	uint32_t key;
	uint16_t type;
	uint16_t size;
	uint16_t w8;
	uint8_t  a;
	uint8_t  b;
	int32_t  live;
	uint16_t nvs;
	uint16_t flags;
	uint8_t  unknown14;
	uint8_t  arr;
	uint8_t  shift;
	uint8_t  modified;
	uint8_t  perm;
	uint8_t  unknown19[4];
	uint8_t  access;
	uint8_t  unknown1e[2];
	uint16_t sel;
	uint16_t pad;
	int32_t  dflt;
};
static_assert(sizeof(Row) == 40 && offsetof(Row, access) == 0x1d && offsetof(Row, sel) == 0x20 &&
              offsetof(Row, dflt) == 0x24);

// What a registry write changes; one copy per scope, mapped by every guest process in it.
struct ScopeRegistry {
	static constexpr uint32_t MaxRows   = 1024;
	static constexpr uint32_t MaxPool   = 0x40000;
	static constexpr uint32_t NvsSize   = 0x590;
	static constexpr uint64_t Signature = 0x324745525954594bull;

	uint64_t         signature;
	AuthInfo::Digest manifest;
	uint32_t         count;
	uint32_t         pool_size;
	Row              rows[MaxRows];
	uint8_t          pool[MaxPool];
	uint8_t          nvs[2][NvsSize];
	// Hardware-key images A (K+0x35387d0) and B (K+0x3538810) with their dirty bytes at
	// K+0x35387b8.
	uint8_t hw[2][0x40];
	uint8_t hw_dirty[2];
	// kern.backup_restore_mode cache K+0x1ad1270, -1 until the first read
	int32_t backup_restore_mode;
};

struct Snapshot {
	std::string                                                dir;
	std::string                                                sha;
	bool                                                       valid = false;
	AuthInfo::Digest                                           manifest {};
	std::vector<Row>                                           rows;
	std::vector<uint8_t>                                       pool;
	std::vector<uint8_t>                                       pool2;
	std::array<std::array<uint8_t, ScopeRegistry::NvsSize>, 2> nvs {};
	std::array<uint8_t, 0x60>                                  globals {};
	uint32_t                                                   mode_mask = 0;
	std::array<uint8_t, 0x400>                                 rodata {};
	std::array<uint8_t, 0x80>                                  hw {};
	// K+0x18de560 {u32 id, char code[4]} x15 then the 4-byte default at K+0x1362cf1.
	std::array<uint8_t, 0x7c> region {};
	// K+0x3d0be60..+0x28; op 0 reads +0 for key 2 and +0x24 otherwise.
	std::array<uint8_t, 0x28> version {};
};

struct RegistryContext {
	ScopeRegistry* table = nullptr;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	HANDLE mutex   = nullptr;
	HANDLE section = nullptr;
	~RegistryContext() {
		if (section != nullptr && table != nullptr) UnmapViewOfFile(table);
		if (section != nullptr) CloseHandle(section);
		if (mutex != nullptr) CloseHandle(mutex);
	}
#endif
};

static Common::Mutex                                           g_mutex;
static Snapshot                                                g_snapshot;
static std::unique_ptr<ScopeRegistry>                          g_local;
static std::map<std::string, std::unique_ptr<RegistryContext>> g_contexts;

namespace {

struct View {
	const uint8_t* data;
	uint64_t       size;
};

constexpr int32_t Code(uint32_t value) {
	return static_cast<int32_t>(value);
}

uint32_t Read32(const uint8_t* p) {
	uint32_t value = 0;
	std::memcpy(&value, p, sizeof(value));
	return value;
}

bool ReadFile(const std::filesystem::path& path, uint64_t max, std::vector<uint8_t>* out) try {
	std::ifstream input(path, std::ios::binary | std::ios::ate);
	if (!input) return false;
	const auto size = static_cast<uint64_t>(input.tellg());
	if (size > max) return false;
	out->resize(size);
	input.seekg(0);
	if (size != 0 &&
	    !input.read(reinterpret_cast<char*>(out->data()), static_cast<std::streamsize>(size)))
		return false;
	return input.peek() == std::ifstream::traits_type::eof();
} catch (const std::bad_alloc&) {
	return false;
} catch (const std::filesystem::filesystem_error&) {
	return false;
}

const char* Decode(Snapshot* s) {
	struct File {
		const char* name;
		uint64_t    min;
		uint64_t    max;
	};
	constexpr File files[] = {
	    {"live_regmgr_head.bin", 16, 16},
	    {"live_regmgr_table.bin", sizeof(Row), sizeof(Row) * ScopeRegistry::MaxRows},
	    {"live_regmgr_pool.bin", 0, ScopeRegistry::MaxPool},
	    {"live_regmgr_pool2.bin", 0, 0x2000},
	    {"live_regmgr_nvs_a.bin", ScopeRegistry::NvsSize, ScopeRegistry::NvsSize},
	    {"live_regmgr_nvs_b.bin", ScopeRegistry::NvsSize, ScopeRegistry::NvsSize},
	    {"live_regmgr_globals.bin", 0x60, 0x60},
	    {"live_regmgr_modemask.bin", 4, 4},
	    {"live_regmgr_rodata.bin", 0x400, 0x400},
	    {"live_regmgr_hw.bin", 0x80, 0x80},
	    {"live_regmgr_region.bin", 0x7c, 0x7c},
	    {"live_regmgr_version.bin", 0x28, 0x28},
	};
	const std::filesystem::path dir = s->dir;
	AuthInfo::Digest            expected {};
	if (!AuthInfo::ParseDigestHex(s->sha, &expected)) return "manifest_sha256_format";
	std::vector<uint8_t> manifest;
	if (!ReadFile(dir / "regmgr_snapshot.sha256", 0x1000, &manifest)) return "manifest_unreadable";
	if (AuthInfo::Sha256(manifest.data(), manifest.size()) != expected)
		return "manifest_sha256_mismatch";
	std::map<std::string, AuthInfo::Digest> listed;
	const std::string                       text(manifest.begin(), manifest.end());
	for (size_t at = 0; at < text.size();) {
		const auto end = text.find('\n', at);
		if (end == std::string::npos) return "manifest_format";
		const auto line = text.substr(at, end - at);
		at              = end + 1;
		AuthInfo::Digest digest {};
		if (line.size() < 67 || line.compare(64, 2, " *") != 0 ||
		    !AuthInfo::ParseDigestHex(line.substr(0, 64), &digest))
			return "manifest_format";
		if (!listed.emplace(line.substr(66), digest).second) return "manifest_duplicate";
	}
	if (listed.size() != std::size(files)) return "manifest_file_set";
	std::map<std::string, std::vector<uint8_t>> data;
	for (const auto& file: files) {
		const auto found = listed.find(file.name);
		if (found == listed.end()) return "manifest_file_set";
		auto& bytes = data[file.name];
		if (!ReadFile(dir / file.name, file.max, &bytes)) return "file_unreadable";
		if (bytes.size() < file.min) return "file_size";
		if (AuthInfo::Sha256(bytes.data(), bytes.size()) != found->second)
			return "file_sha256_mismatch";
	}
	uint16_t count = 0;
	std::memcpy(&count, data["live_regmgr_head.bin"].data(), sizeof(count));
	const auto& table = data["live_regmgr_table.bin"];
	if (count == 0 || table.size() != uint64_t {count} * sizeof(Row)) return "table_size";
	s->rows.resize(count);
	std::memcpy(s->rows.data(), table.data(), table.size());
	for (const auto& row: s->rows) {
		if (row.size > 0x800) return "row_size";
	}
	s->pool  = std::move(data["live_regmgr_pool.bin"]);
	s->pool2 = std::move(data["live_regmgr_pool2.bin"]);
	std::memcpy(s->nvs[0].data(), data["live_regmgr_nvs_a.bin"].data(), ScopeRegistry::NvsSize);
	std::memcpy(s->nvs[1].data(), data["live_regmgr_nvs_b.bin"].data(), ScopeRegistry::NvsSize);
	std::memcpy(s->globals.data(), data["live_regmgr_globals.bin"].data(), s->globals.size());
	s->mode_mask = Read32(data["live_regmgr_modemask.bin"].data());
	std::memcpy(s->rodata.data(), data["live_regmgr_rodata.bin"].data(), s->rodata.size());
	std::memcpy(s->hw.data(), data["live_regmgr_hw.bin"].data(), s->hw.size());
	std::memcpy(s->region.data(), data["live_regmgr_region.bin"].data(), s->region.size());
	std::memcpy(s->version.data(), data["live_regmgr_version.bin"].data(), s->version.size());
	s->manifest = expected;
	return nullptr;
}

const Snapshot* Load() {
	const char* dir = std::getenv(kSnapshotEnvironment);
	const char* sha = std::getenv(kSnapshotSha256Environment);
	if (dir == nullptr || *dir == '\0' || sha == nullptr || *sha == '\0') return nullptr;
	if (g_snapshot.dir == dir && g_snapshot.sha == sha)
		return g_snapshot.valid ? &g_snapshot : nullptr;
	g_snapshot     = Snapshot {};
	g_snapshot.dir = dir;
	g_snapshot.sha = sha;
	g_local.reset();
	if (const char* reason = Decode(&g_snapshot); reason != nullptr) {
		LOGF("REGMGR_SNAPSHOT_REJECTED reason=%s\n", reason);
		return nullptr;
	}
	g_snapshot.valid = true;
	LOGF("REGMGR_SNAPSHOT_LOADED rows=%zu pool=%zu pool2=%zu manifest=%.16s\n",
	     g_snapshot.rows.size(), g_snapshot.pool.size(), g_snapshot.pool2.size(),
	     AuthInfo::DigestHex(g_snapshot.manifest).c_str());
	return &g_snapshot;
}

void Initialize(ScopeRegistry* table) {
	table->signature = ScopeRegistry::Signature;
	table->manifest  = g_snapshot.manifest;
	table->count     = static_cast<uint32_t>(g_snapshot.rows.size());
	table->pool_size = static_cast<uint32_t>(g_snapshot.pool.size());
	std::memcpy(table->rows, g_snapshot.rows.data(), g_snapshot.rows.size() * sizeof(Row));
	std::memcpy(table->pool, g_snapshot.pool.data(), g_snapshot.pool.size());
	std::memcpy(table->nvs[0], g_snapshot.nvs[0].data(), ScopeRegistry::NvsSize);
	std::memcpy(table->nvs[1], g_snapshot.nvs[1].data(), ScopeRegistry::NvsSize);
	std::memcpy(table->hw, g_snapshot.hw.data(), sizeof(table->hw));
	table->hw_dirty[0]         = 0;
	table->hw_dirty[1]         = 0;
	table->backup_restore_mode = -1;
	if (std::getenv("KYTY_DIAGNOSTIC_REGMGR_FACTORY_STATE") == nullptr) return;
	// no registry file: file-backed rows take their default. NVS rows (flash) and handler defaults
	// (sel & 0x80) keep the snapshot value
	uint32_t reset   = 0;
	uint32_t changed = 0;
	uint32_t kept    = 0;
	for (uint32_t i = 0; i < table->count; i++) {
		auto& row = table->rows[i];
		if (row.b != 2 || row.nvs != 0 || row.a == 0) continue;
		std::vector<uint8_t> value(row.size, 0);
		if (row.sel == 1 && row.type == 0) {
			if (row.size != sizeof(row.dflt)) {
				kept++;
				continue;
			}
			std::memcpy(value.data(), &row.dflt, sizeof(row.dflt));
		} else if (row.sel == 1) {
			if (row.dflt < 0 || static_cast<uint64_t>(row.dflt) >= g_snapshot.pool2.size()) {
				kept++;
				continue;
			}
			const auto available = std::min<uint64_t>(row.size, g_snapshot.pool2.size() - row.dflt);
			const uint8_t* source = g_snapshot.pool2.data() + row.dflt;
			const auto n = row.type == 1 ? strnlen(reinterpret_cast<const char*>(source), available)
			                             : available;
			if (row.type != 1 && n != row.size) {
				kept++;
				continue;
			}
			std::memcpy(value.data(), source, n);
		} else if (row.sel == 0 && row.dflt >= 0 && row.dflt <= 0xff) {
			std::memset(value.data(), static_cast<uint8_t>(row.dflt), row.size);
		} else {
			kept++;
			continue;
		}
		const uint32_t entries = std::max<uint32_t>(row.arr, 1);
		bool           differs = false;
		if (row.a == 1) {
			if (row.size > sizeof(row.live)) {
				kept++;
				continue;
			}
			differs = std::memcmp(&row.live, value.data(), row.size) != 0;
			std::memcpy(&row.live, value.data(), row.size);
		} else if (row.a == 2 || row.a == 16) {
			const int64_t end = int64_t {row.live} + int64_t {entries} * row.size;
			if (row.live < 0 || end > table->pool_size) {
				kept++;
				continue;
			}
			for (uint32_t j = 0; j < entries; j++) {
				uint8_t* slot = table->pool + row.live + j * row.size;
				differs |= std::memcmp(slot, value.data(), row.size) != 0;
				std::memcpy(slot, value.data(), row.size);
			}
		} else {
			kept++;
			continue;
		}
		reset++;
		if (differs) {
			changed++;
			LOGF("REGMGR_FACTORY_ROW key=0x%08" PRIx32 " entries=%" PRIu32 " NON_AUTHENTIC\n",
			     row.key, entries);
		}
	}
	LOGF("REGMGR_FACTORY_STATE reset=%" PRIu32 " changed=%" PRIu32 " kept_capture=%" PRIu32
	     " NON_AUTHENTIC\n",
	     reset, changed, kept);
}

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
struct PersistHeader {
	uint64_t         signature;
	uint32_t         version;
	uint32_t         size;
	AuthInfo::Digest sha256;
};

constexpr uint64_t kPersistSignature = 0x315347525954594bull;

bool LoadPersistent(const std::filesystem::path& path, ScopeRegistry* table) {
	std::vector<uint8_t> raw;
	if (!ReadFile(path, sizeof(PersistHeader) + sizeof(ScopeRegistry), &raw) ||
	    raw.size() != sizeof(PersistHeader) + sizeof(ScopeRegistry))
		return false;
	PersistHeader header {};
	std::memcpy(&header, raw.data(), sizeof(header));
	const uint8_t* state = raw.data() + sizeof(header);
	if (header.signature != kPersistSignature || header.version != 1 ||
	    header.size != sizeof(ScopeRegistry) ||
	    AuthInfo::Sha256(state, sizeof(ScopeRegistry)) != header.sha256)
		return false;
	auto saved = std::make_unique<ScopeRegistry>();
	std::memcpy(saved.get(), state, sizeof(*saved));
	if (saved->signature != ScopeRegistry::Signature || saved->manifest != g_snapshot.manifest ||
	    saved->count != static_cast<uint32_t>(g_snapshot.rows.size()) ||
	    saved->pool_size != static_cast<uint32_t>(g_snapshot.pool.size()))
		return false;
	for (uint32_t i = 0; i < saved->count; i++) {
		const Row& actual = saved->rows[i];
		const Row& original = g_snapshot.rows[i];
		if (actual.key != original.key || actual.type != original.type ||
		    actual.size != original.size || actual.nvs != original.nvs)
			return false;
	}
	*table = *saved;
	table->backup_restore_mode = -1;
	return true;
}

bool SavePersistent(const std::filesystem::path& path, const ScopeRegistry& table) {
	PersistHeader header {};
	header.signature = kPersistSignature;
	header.version   = 1;
	header.size      = static_cast<uint32_t>(sizeof(table));
	header.sha256    = AuthInfo::Sha256(&table, sizeof(table));
	std::vector<uint8_t> raw(sizeof(header) + sizeof(table));
	std::memcpy(raw.data(), &header, sizeof(header));
	std::memcpy(raw.data() + sizeof(header), &table, sizeof(table));
	const auto temp = std::filesystem::path(path.wstring() + L".tmp." +
	                                        std::to_wstring(GetCurrentProcessId()) + L"." +
	                                        std::to_wstring(GetCurrentThreadId()));
	const HANDLE file = CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
	                                FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file == INVALID_HANDLE_VALUE) return false;
	DWORD written = 0;
	const bool ok = WriteFile(file, raw.data(), static_cast<DWORD>(raw.size()), &written, nullptr) &&
	                written == static_cast<DWORD>(raw.size()) && FlushFileBuffers(file);
	CloseHandle(file);
	if (ok && MoveFileExW(temp.c_str(), path.c_str(),
	                      MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
		return true;
	DeleteFileW(temp.c_str());
	return false;
}
#endif

RegistryContext* GetContext() {
	std::string scope;
	if (!Process::GetScope(&scope)) {
		static RegistryContext local;
		if (g_local == nullptr) {
			g_local = std::make_unique<ScopeRegistry>();
			Initialize(g_local.get());
		}
		local.table = g_local.get();
		return &local;
	}
	// manifest in the name so another snapshot gets its own mapping
	const std::string name  = "Local\\kyty_ps5_" + scope + "_regmgr_" +
	                          AuthInfo::DigestHex(g_snapshot.manifest).substr(0, 16);
	const auto        found = g_contexts.find(name);
	if (found != g_contexts.end()) return found->second.get();
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	auto context   = std::make_unique<RegistryContext>();
	context->mutex = CreateMutexA(nullptr, FALSE, (name + "_lock").c_str());
	if (context->mutex == nullptr) return nullptr;
	const auto wait = WaitForSingleObject(context->mutex, INFINITE);
	if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) return nullptr;
	context->section   = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
	                                        sizeof(ScopeRegistry), (name + "_state").c_str());
	const bool created = GetLastError() != ERROR_ALREADY_EXISTS;
	if (context->section != nullptr) {
		context->table = static_cast<ScopeRegistry*>(MapViewOfFile(
		    context->section, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(ScopeRegistry)));
	}
	bool state_valid = true;
	if (context->table != nullptr && created) {
		Initialize(context->table);
		if (const char* configured = std::getenv("KYTY_DIAGNOSTIC_REGMGR_PERSIST_PATH");
		    configured != nullptr && configured[0] != '\0') {
			const std::filesystem::path path = configured;
			std::error_code error;
			const bool exists = std::filesystem::exists(path, error);
			if (error || (exists && !LoadPersistent(path, context->table))) {
				LOGF("REGMGR_PERSIST_REJECTED invalid_or_unreadable_state\n");
				context->table->signature = 0;
				state_valid = false;
			} else if (exists) {
				LOGF("REGMGR_PERSIST_LOADED snapshot_matched=1\n");
			}
		}
	}
	ReleaseMutex(context->mutex);
	if (!state_valid || context->table == nullptr ||
	    context->table->signature != ScopeRegistry::Signature ||
	    context->table->manifest != g_snapshot.manifest)
		return nullptr;
	auto* result = context.get();
	g_contexts.emplace(name, std::move(context));
	return result;
#else
	return nullptr;
#endif
}

class RegistryLock {
public:
	RegistryLock() {
		g_mutex.Lock();
		if (Load() == nullptr) return;
		auto* context = GetContext();
		if (context == nullptr) {
			LOGF("REGMGR_TABLE_UNAVAILABLE no_registry_state\n");
			return;
		}
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		if (context->mutex != nullptr) {
			const auto result = WaitForSingleObject(context->mutex, INFINITE);
			if (result != WAIT_OBJECT_0 && result != WAIT_ABANDONED) {
				LOGF("REGMGR_TABLE_UNAVAILABLE wait=%lu no_registry_state\n",
				     static_cast<unsigned long>(result));
				return;
			}
			mutex = context->mutex;
		}
#endif
		table = context->table;
	}
	~RegistryLock() {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		if (mutex != nullptr) ReleaseMutex(mutex);
#endif
		g_mutex.Unlock();
	}
	ScopeRegistry* table = nullptr;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	HANDLE mutex = nullptr;
#endif
	KYTY_CLASS_NO_COPY(RegistryLock);
};

// Keys 0x9eedc3e0 answers from hardware state instead of the table.
bool HardwareKey(uint32_t key) {
	switch (key) {
		case 0x02470000:
		case 0x02460000:
		case 0x19e00300:
		case 0x19e00100:
		case 0x01050000:
		case 0x02010000:
		case 0x02130000:
		case 0x02860100:
		case 0x02860200:
		case 0x02860300:
		case 0x02801700:
		case 0x02820e00:
		case 0x19e02000:
		case 0x78020300: return true;
		default: return false;
	}
}

// Keys whose store is followed by a driver or kernel-global update in storewrite's tail switch.
bool SideEffectKey(uint32_t key) {
	switch (key) {
		case 0x01050000:
		case 0x01090000:
		case 0x02010000:
		case 0x02130000:
		case 0x02460000:
		case 0x02470000:
		case 0x02801700:
		case 0x02820e00:
		case 0x02860100:
		case 0x02860200:
		case 0x02860300:
		case 0x19e00100:
		case 0x19e00300:
		case 0x19e02000:
		case 0x78020300:
		case 0x78028800:
		case 0x01400000:
		case 0x07030000:
		case 0x78020200:
		case 0x7802a500:
		case 0x7802b200: return true;
		default: return false;
	}
}

class Registry {
public:
	Registry(const Snapshot& snapshot, ScopeRegistry& table): s(snapshot), t(table) {}

	int Find(uint32_t key, uint32_t* index) const {
		for (uint32_t i = 0; i < t.count; i++) {
			const auto& row = t.rows[i];
			if (key == row.key) {
				*index = 0;
				return static_cast<int>(i);
			}
			for (uint32_t j = 1; j < row.arr; j++) {
				if (key == row.key + (j << (row.shift & 31u))) {
					*index = j;
					return static_cast<int>(i);
				}
			}
		}
		return -1;
	}

	int32_t Op11() {
		if (const int32_t rc = Ready(); rc != 0) return rc;
		if (Global(0x54) != 0) return -3;
		if (Global(0x58) != 0) return -2;
		if (Global(0x5c) != 0) return Leave("op11_c0c");
		return 0;
	}

	// 0x9eed8a30. Next-gen callers pass the key unmapped, so ShellCore's key 1 reads the +0x24
	// dword.
	int32_t Op0(uint32_t key) const {
		if (const int32_t rc = Ready(); rc != 0) return rc;
		if ((G() & 2) == 0) return Code(0x800d0201);
		return static_cast<int32_t>(Read32(s.version.data() + (key == 2 ? 0 : 0x24)));
	}

	// 0x9e9fab90, region id.
	int32_t Op12() const {
		if (const int32_t rc = Ready(); rc != 0) return rc;
		return Global(0);
	}

	// 0x9e9fac00, region string; a positive return is the id and the caller copies size bytes out.
	int32_t Op13(uint8_t* buf, uint64_t size) {
		if (const int32_t rc = Ready(); rc != 0) return rc;
		const int32_t n = Global(0);
		if (n <= 0) return Code(0x800d0114);
		if (size < 4 || n >= 0x13) return Code(0x800d0202);
		const uint8_t* code = s.region.data() + 0x78;
		for (uint32_t i = 0; i < 15; i++) {
			const auto id = Read32(s.region.data() + i * 8);
			if (id == 0) break;
			if (id == static_cast<uint32_t>(n)) {
				code = s.region.data() + i * 8 + 4;
				break;
			}
		}
		if (!CopyStr(buf, {code, 4}, size)) return -1;
		return n;
	}

	int32_t GetInt(int inst, uint32_t key, uint8_t* buf) {
		if (const int32_t rc = Ready(); rc != 0) return rc;
		uint32_t  index = 0;
		uint32_t  flags = 0;
		const int idx   = Lookup(inst, 2, key, 0, 4, &index, &flags);
		if (idx < 0) return idx;
		if (Defaulted(flags)) {
			const uint8_t* value = Bytes(Default(idx), 4);
			if (value == nullptr) return -1;
			std::memcpy(buf, value, 4);
			return 0;
		}
		return Read(key, buf, 4);
	}

	int32_t GetStr(int inst, uint32_t key, uint8_t* buf, uint64_t size) {
		uint32_t  index = 0;
		const int found = Find(key, &index);
		if (found < 0) return Code(0x800d0203);
		const uint16_t row_size = t.rows[found].size;
		if ((t.rows[found].flags & 0x200) != 0) return Code(0x800d020e);
		if ((t.rows[found].flags & 0x100) != 0) {
			if (row_size == 0) return Code(0x800d0202);
			const uint64_t m = std::min<uint64_t>(size, row_size);
			if (m == 0) return Code(0x800d0208);
			int32_t rc = 0;
			if (size >= row_size) {
				rc = GetBinCore(1, key, buf, row_size);
			} else {
				std::vector<uint8_t> tmp(row_size);
				rc = GetBinCore(1, key, tmp.data(), row_size);
				if (rc == 0) std::memcpy(buf, tmp.data(), m);
			}
			if (rc != 0) return rc;
			buf[m - 1] = 0;
			return 0;
		}
		if (const int32_t rc = Ready(); rc != 0) return rc;
		uint32_t  flags = 0;
		const int idx   = Lookup(inst, 4, key, 1, size, &index, &flags);
		if (idx < 0) return idx;
		const uint64_t n = std::min<uint64_t>(size, t.rows[idx].size);
		if (Defaulted(flags)) {
			const auto value = Default(idx);
			if (value.data == nullptr || !CopyStr(buf, value, n)) return -1;
			return 0;
		}
		return Read(key, buf, n);
	}

	int32_t GetBin(int inst, uint32_t key, uint8_t* buf, uint64_t size) {
		uint32_t  index = 0;
		const int found = Find(key, &index);
		if (found < 0) return Code(0x800d0203);
		const uint16_t row_size = t.rows[found].size;
		if ((t.rows[found].flags & 0x200) != 0) return Code(0x800d020e);
		if ((t.rows[found].flags & 0x100) == 0) return GetBinCore(inst, key, buf, size);
		if (row_size == 0) return Code(0x800d0202);
		if (size - 1 >= row_size) return Code(0x800d0208);
		if (size == row_size) return GetBinCore(1, key, buf, row_size);
		std::vector<uint8_t> tmp(row_size);
		const int32_t        rc = GetBinCore(1, key, tmp.data(), row_size);
		if (rc == 0) std::memcpy(buf, tmp.data(), size);
		return rc;
	}

	int32_t Op7(int inst, uint32_t key, uint8_t* buf) {
		if (const int32_t rc = Ready(); rc != 0) return rc;
		uint32_t  index = 0;
		const int idx   = Lookup(inst, 7, key, 0, 4, &index, nullptr);
		if (idx < 0) return idx;
		const uint8_t* value = Bytes(Default(idx), 4);
		if (value == nullptr) return -1;
		std::memcpy(buf, value, 4);
		return 0;
	}

	int32_t Op8(int inst, uint32_t key, uint8_t* buf, uint64_t size) {
		uint32_t  index = 0;
		const int found = Find(key, &index);
		if (found < 0) return Code(0x800d0203);
		const uint16_t row_size = t.rows[found].size;
		if ((t.rows[found].flags & 0x200) != 0) return Code(0x800d020e);
		if ((t.rows[found].flags & 0x100) != 0) {
			if (row_size == 0) return Code(0x800d0202);
			if (size - 1 >= row_size) return Code(0x800d0208);
			int32_t rc = 0;
			if (size == row_size) {
				rc = Op9Core(1, key, buf, row_size);
			} else {
				std::vector<uint8_t> tmp(row_size);
				rc = Op9Core(1, key, tmp.data(), row_size);
				if (rc == 0) std::memcpy(buf, tmp.data(), size);
			}
			if (rc != 0) return rc;
			buf[size - 1] = 0;
			return 0;
		}
		if (const int32_t rc = Ready(); rc != 0) return rc;
		const int idx = Lookup(inst, 8, key, 1, size, &index, nullptr);
		if (idx < 0) return idx;
		const auto value = Default(idx);
		if (value.data == nullptr) return -1;
		// size may exceed the row here; the bytes after the copied string stay as the handler
		// zeroed them.
		if (!CopyStr(buf, value, size)) return -1;
		return 0;
	}

	int32_t Op9(int inst, uint32_t key, uint8_t* buf, uint64_t size) {
		uint32_t  index = 0;
		const int found = Find(key, &index);
		if (found < 0) return Code(0x800d0203);
		const uint16_t row_size = t.rows[found].size;
		if ((t.rows[found].flags & 0x200) != 0) return Code(0x800d020e);
		if ((t.rows[found].flags & 0x100) == 0) return Op9Core(inst, key, buf, size);
		if (row_size == 0) return Code(0x800d0202);
		if (size - 1 >= row_size) return Code(0x800d0208);
		if (size == row_size) return Op9Core(1, key, buf, row_size);
		std::vector<uint8_t> tmp(row_size);
		const int32_t        rc = Op9Core(1, key, tmp.data(), row_size);
		if (rc == 0) std::memcpy(buf, tmp.data(), size);
		return rc;
	}

	int32_t SetInt(int inst, uint32_t key, const uint8_t* buf) {
		if (const int32_t rc = Ready(); rc != 0) return rc;
		uint32_t  flags = 0;
		const int idx   = Lookup(inst, 1, key, 0, 4, nullptr, &flags);
		if (idx < 0) return idx;
		if (Defaulted(flags)) return 0;
		if (key == 0x7802c500 && Global(8) == 2) return Leave("setint_7802c500");
		return Write(inst, key, buf, 4);
	}

	int32_t SetStr(int inst, uint32_t key, const uint8_t* buf, uint64_t size) {
		uint32_t  index = 0;
		const int found = Find(key, &index);
		if (found < 0) return Code(0x800d0203);
		const uint16_t row_size = t.rows[found].size;
		if ((t.rows[found].flags & 0x200) != 0) return Code(0x800d020e);
		const uint64_t length = strnlen(reinterpret_cast<const char*>(buf), size) + 1;
		if ((t.rows[found].flags & 0x100) != 0) {
			if (length > size) return Code(0x800d0208);
			return SetCore100(key, buf, size, row_size);
		}
		if (const int32_t rc = Ready(); rc != 0) return rc;
		uint32_t  flags = 0;
		const int idx   = Lookup(inst, 3, key, 1, size, nullptr, &flags);
		if (idx < 0) return idx;
		if (Defaulted(flags)) return 0;
		if (length > size || length > t.rows[idx].size) return Code(0x800d0208);
		return Write(inst, key, buf, length);
	}

	int32_t SetBin(int inst, uint32_t key, const uint8_t* buf, uint64_t size) {
		uint32_t  index = 0;
		const int found = Find(key, &index);
		if (found < 0) return Code(0x800d0203);
		if ((t.rows[found].flags & 0x200) != 0) return Code(0x800d020e);
		if ((t.rows[found].flags & 0x100) != 0)
			return SetCore100(key, buf, size, t.rows[found].size);
		if (const int32_t rc = Ready(); rc != 0) return rc;
		uint32_t  flags = 0;
		const int idx   = Lookup(inst, 5, key, 2, size, nullptr, &flags);
		if (idx < 0) return idx;
		if (Defaulted(flags)) return 0;
		return Write(inst, key, buf, size);
	}

	const char* unmodelled = nullptr;

private:
	// no throw: calls can run on the guest stack, where Windows won't unwind to a C++ handler.
	int32_t Leave(const char* why) {
		if (unmodelled == nullptr) unmodelled = why;
		return -1;
	}

	int32_t Global(size_t offset) const {
		return static_cast<int32_t>(Read32(s.globals.data() + offset));
	}

	uint32_t G() const { return static_cast<uint32_t>(Global(0x50)); }

	int32_t Ready() const {
		if (G() == 0) return Code(0x800d0201);
		const int32_t r = Global(0x54);
		if (r == 0 || Global(0x10) == 1) return 0;
		return r <= 0 ? r : Code(0x800d020d);
	}

	static bool Defaulted(uint32_t flags) { return (flags & 0x800d00f0u) == 0x800d0000u; }

	static bool Class7(uint32_t key, uint32_t index) {
		return (key & 0xff000000u) == 0x07000000u && ((key >> 18) & 0x3fu) - 32u < 5u &&
		       index >= 16;
	}

	int Lookup(int inst, uint32_t mode, uint32_t key, uint16_t type, uint64_t size, uint32_t* index,
	           uint32_t* flags) {
		const uint32_t g = G();
		if ((g & 2) == 0) return Code(0x800d0201);
		if (t.count == 0) return Code(0x800d0203);
		uint32_t  at  = 0;
		const int idx = Find(key, &at);
		if (idx < 0) return Code(0x800d0203);
		if (index != nullptr) *index = at;
		if (flags != nullptr) *flags = 0;
		const auto& row = t.rows[idx];
		if ((~g & 7) != 0 && row.nvs == 0) {
			if ((g & 1) == 0 || (key & ~0x8000u) == 0x78020100) return Code(0x800d0201);
			return Leave("lookup_wait");
		}
		const uint32_t m = mode - 1;
		if (m >= 0x1b || ((0x44001ffu >> m) & 1) == 0) return Code(0x800d0202);
		if (type != row.type) return Code(0x800d0207);
		switch (type) {
			case 0:
			case 2:
				if (size != row.size) return Code(0x800d0208);
				break;
			case 1:
				if (((0x400015u >> m) & 1) != 0 ? size > row.size : size < row.size)
					return Code(0x800d0208);
				break;
			default: return Code(0x800d0207);
		}
		int32_t err = 0;
		if ((inst & 1) != 0) {
			if ((row.perm & 1) != 0) return idx;
			err = Code(0x800d0119);
			if ((inst & 2) != 0) {
				err = Code(0x800d0203);
				if ((row.perm & 2) != 0) return idx;
			}
		} else {
			if ((inst & 2) == 0) return idx;
			err = Code(0x800d0203);
			if ((row.perm & 2) != 0) return idx;
		}
		const int32_t q = Global(0x48);
		if ((q & 1) != 0) return err;
		if (flags == nullptr) return idx;
		*flags = static_cast<uint32_t>(q) | 0x800d0000u;
		return idx;
	}

	// 0x9eeddc20. sel 0 fills a kernel static buffer, so only the row's own bytes of it are
	// defined.
	View Default(int idx) {
		const auto& row = t.rows[idx];
		if ((row.sel & 0x80) != 0) {
			Leave("default_handler");
			return {};
		}
		if (row.sel == 1) {
			if (row.type == 0)
				return {reinterpret_cast<const uint8_t*>(&row.dflt), sizeof(row.dflt)};
			if (row.dflt < 0 || static_cast<uint64_t>(row.dflt) >= s.pool2.size()) {
				Leave("default_pool2_range");
				return {};
			}
			return {s.pool2.data() + row.dflt, s.pool2.size() - row.dflt};
		}
		if (row.sel != 0 || row.dflt > 0xff) {
			Leave(row.sel != 0 ? "default_sel" : "default_fill");
			return {};
		}
		std::memset(fill.data(), static_cast<uint8_t>(row.dflt), row.size);
		return {fill.data(), row.size};
	}

	// nullptr only after Leave; a failed Default has no data and reaches here as {nullptr, 0}.
	const uint8_t* Bytes(View view, uint64_t n) {
		if (n > view.size) {
			Leave("value_overrun");
			return nullptr;
		}
		return view.data;
	}

	// strlcpy when the string ends inside n, otherwise n-1 bytes and a NUL.
	bool CopyStr(uint8_t* dst, View src, uint64_t n) {
		if (n == 0) return true;
		const auto length = strnlen(reinterpret_cast<const char*>(src.data), std::min(n, src.size));
		if (length < std::min(n, src.size)) {
			std::memcpy(dst, src.data, length + 1);
			return true;
		}
		const uint8_t* head = Bytes(src, n - 1);
		if (head == nullptr) return false;
		std::memcpy(dst, head, n - 1);
		dst[n - 1] = 0;
		return true;
	}

	uint8_t* Pool(int64_t offset, uint64_t size) {
		if (offset < 0 || static_cast<uint64_t>(offset) + size > t.pool_size) {
			Leave("pool_range");
			return nullptr;
		}
		return t.pool + offset;
	}

	// Region A is nvs 0x40-0x5ff, region B 0x640-0xbff; arrays share one slot.
	uint8_t* Nvs(const Row& row) {
		uint32_t offset = 0;
		uint8_t* region = nullptr;
		if (row.nvs - 0x40u < 0x5c0u) {
			region = t.nvs[0];
			offset = row.nvs - 0x40u;
		} else if (row.nvs - 0x640u < 0x5c0u) {
			region = t.nvs[1];
			offset = row.nvs - 0x640u;
		}
		if (region == nullptr || offset + row.size > 0x58f) return nullptr;
		return region + offset;
	}

	// 0x9eedc3e0
	int32_t HardwareRead(uint32_t key, uint8_t* out, uint64_t size) {
		if (out == nullptr) return Code(0x800d0202);
		const uint8_t* a      = t.hw[0];
		uint32_t       offset = 0;
		switch (key) {
			case 0x02860100: offset = 0; break;
			case 0x02010000: offset = 1; break;
			case 0x01050000: offset = 3; break;
			case 0x02860300: offset = 9; break;
			case 0x02820e00: offset = 0xb; break;
			case 0x02130000: offset = 0xc; break;
			case 0x02801700: offset = 0x22; break;
			default: return Code(0x800d0203);
		}
		if (size != 4) return Code(0x800d0108);
		int32_t value = 0;
		if (key == 0x02130000 || key == 0x02801700) {
			value = static_cast<int32_t>(Read32(a + offset));
			if (value == -1) value = 0;
		} else if ((key == 0x02010000 || key == 0x02820e00) && a[offset] == 0xff) {
			value = 0;
		} else {
			value = static_cast<int8_t>(a[offset]);
		}
		std::memcpy(out, &value, sizeof(value));
		LOGF("REGMGR_HW_READ key=0x%08" PRIx32 " offset=0x%" PRIx32 " source=live_regmgr_hw\n", key,
		     offset);
		return 0;
	}

	// 0x9eedc070
	int32_t Read(uint32_t key, uint8_t* buf, uint64_t bufsize) {
		if (HardwareKey(key)) {
			// other keys have no 13.60 row and fail in Lookup first
			if (HardwareRead(key, buf, bufsize) == 0) return 0;
			switch (key) {
				case 0x02860100:
				case 0x02010000:
				case 0x01050000:
				case 0x02860300:
				case 0x02820e00:
				case 0x02130000:
				case 0x02801700: break;
				default: return Leave("storeread_hardware_key");
			}
		}
		uint32_t  index = 0;
		const int idx   = Find(key, &index);
		if (idx < 0) return Code(0x800d0203);
		auto& row = t.rows[idx];
		if (bufsize < row.size) return Code(0x800d0208);
		View src {};
		if (row.b == 2 && (row.a == 16 || row.a == 2)) {
			const uint8_t* live =
			    Pool(int64_t {row.live} + static_cast<int32_t>(index * row.size), row.size);
			if (live == nullptr) return -1;
			src = {live, row.size};
		} else if (row.b == 2 && row.a == 1) {
			src = {reinterpret_cast<const uint8_t*>(&row.live), sizeof(row.live)};
		} else if ((row.w8 & 0x19ff) == 0x1000 || (Class7(row.key, index) && row.a != 0)) {
			const uint8_t* value = Bytes(Default(idx), row.size);
			if (value == nullptr) return -1;
			std::memcpy(buf, value, row.size);
			return 0;
		} else {
			if (row.nvs == 0) return Leave("storeread_persistent");
			const auto* nvs = Nvs(row);
			if (nvs == nullptr) return Code(0x800d0002);
			src = {nvs, row.size};
		}
		if (row.type == 1) {
			if (!CopyStr(buf, src, row.size)) return -1;
		} else {
			const uint8_t* value = Bytes(src, row.size);
			if (value == nullptr) return -1;
			std::memcpy(buf, value, row.size);
		}
		return 0;
	}

	// 0x9eedcd70. Anything that would leave the model is decided before the first byte changes.
	int32_t Write(int inst, uint32_t key, const uint8_t* buf, uint64_t size) {
		const uint32_t g = G();
		if ((g & 2) != 0 && (key == 0xb060000 || key == 0xb070000)) {
			if ((s.mode_mask & Read32(s.rodata.data() + (key == 0xb060000 ? 8 : 0x18))) != 0)
				return 0;
		}
		uint32_t  index = 0;
		const int idx   = Find(key, &index);
		if (idx < 0) return Code(0x800d0203);
		auto& row = t.rows[idx];
		if (size > row.size) return Code(0x800d0208);
		if (inst == 1 && row.type == 0) {
			const auto value = static_cast<int32_t>(Read32(buf));
			for (uint32_t i = 0; i < 61; i++) {
				const uint8_t* entry = s.rodata.data() + 0x30 + i * 16;
				if (Read32(entry) != row.key) continue;
				const auto min         = static_cast<int32_t>(Read32(entry + 8));
				const auto max         = static_cast<int32_t>(Read32(entry + 0xc));
				const bool is_unsigned = entry[4] != 0;
				if (entry[5] == 1 &&
				    (is_unsigned ? static_cast<uint32_t>(min) > static_cast<uint32_t>(value)
				                 : min > value))
					return Code(0x800d0224);
				if (entry[6] == 1 &&
				    (is_unsigned ? static_cast<uint32_t>(max) < static_cast<uint32_t>(value)
				                 : max < value))
					return Code(0x800d0225);
				break;
			}
		}
		if (row.a != 0 && (row.size < 5 || (g & 0x100) == 0)) {
			std::vector<uint8_t> current(std::max<size_t>(row.size, 4));
			if (const int32_t rc = Read(key, current.data(), row.size); rc != 0) return rc;
			const bool same =
			    row.type == 1 ? strncmp(reinterpret_cast<const char*>(buf),
				                        reinterpret_cast<const char*>(current.data()), size) == 0
				              : std::memcmp(buf, current.data(), size) == 0;
			if (same) return 0;
		}
		if (SideEffectKey(key)) return Leave("storewrite_side_effect_key");
		uint8_t* memory = nullptr;
		int32_t  late   = 0;
		if (row.b == 1 || row.b == 2) {
			if (row.a == 1 && row.size <= 4) {
				memory = reinterpret_cast<uint8_t*>(&row.live);
			} else if (row.a == 1 || row.a == 2 || row.a == 16) {
				memory =
				    Pool(int64_t {row.live} + static_cast<int32_t>(index * row.size), row.size);
				if (memory == nullptr) return -1;
			} else if (row.a != 0) {
				late = Code(0x800d0109);
			}
		}
		uint8_t* nvs          = nullptr;
		bool     session_only = false;
		if (!((row.w8 & 0x19ff) == 0x1000 || (Class7(row.key, index) && row.a != 0))) {
			if (row.nvs == 0) {
				if (memory == nullptr ||
				    std::getenv("KYTY_DIAGNOSTIC_REGMGR_SESSION_STORE") == nullptr)
					return Leave("storewrite_persistent");
				session_only = true;
			} else {
				nvs = Nvs(row);
				if (nvs == nullptr) return Code(0x800d0002);
			}
		}
		const View src {buf, row.size};
		if (nvs != nullptr) {
			if (row.type == 1)
				CopyStr(nvs, src, row.size);
			else
				std::memcpy(nvs, buf, row.size);
		}
		if (late != 0) return late;
		if (memory != nullptr) {
			if (row.type == 1)
				CopyStr(memory, src, row.size);
			else
				std::memcpy(memory, buf, row.size);
		}
		row.modified = 0xff;
		if (session_only) {
			LOGF("REGMGR_SESSION_WRITE key=0x%08" PRIx32 " index=%" PRIu32 " bytes=%" PRIu64
			     " scope_shared=1 NON_AUTHENTIC\n",
			     key, index, size);
		}
		if (row.a != 0) LOGF("REGMGR_NOTIFY_UNDELIVERED key=0x%08" PRIx32 "\n", key);
		return 0;
	}

	int32_t GetBinCore(int inst, uint32_t key, uint8_t* buf, uint64_t size) {
		if (const int32_t rc = Ready(); rc != 0) return rc;
		uint32_t  index = 0;
		uint32_t  flags = 0;
		const int idx   = Lookup(inst, 6, key, 2, size, &index, &flags);
		if (idx < 0) return idx;
		if (Defaulted(flags)) {
			const uint8_t* value = Bytes(Default(idx), size);
			if (value == nullptr) return -1;
			std::memcpy(buf, value, size);
			return 0;
		}
		return Read(key, buf, size);
	}

	int32_t Op9Core(int inst, uint32_t key, uint8_t* buf, uint64_t size) {
		if (const int32_t rc = Ready(); rc != 0) return rc;
		uint32_t  index = 0;
		const int idx   = Lookup(inst, 9, key, 2, size, &index, nullptr);
		if (idx < 0) return idx;
		const uint8_t* value = Bytes(Default(idx), size);
		if (value == nullptr) return -1;
		std::memcpy(buf, value, size);
		return 0;
	}

	int32_t SetCore100(uint32_t key, const uint8_t* buf, uint64_t size, uint16_t row_size) {
		if (row_size == 0) return Code(0x800d0202);
		if (size - 1 >= row_size) return Code(0x800d0208);
		std::vector<uint8_t> tmp;
		if (size != row_size) {
			tmp.assign(row_size, 0);
			std::memcpy(tmp.data(), buf, size);
			buf = tmp.data();
		}
		if (const int32_t rc = Ready(); rc != 0) return rc;
		uint32_t  flags = 0;
		const int idx   = Lookup(1, 5, key, 2, row_size, nullptr, &flags);
		if (idx < 0) return idx;
		if (Defaulted(flags)) return 0;
		return Write(1, key, buf, row_size);
	}

	const Snapshot&            s;
	ScopeRegistry&             t;
	std::array<uint8_t, 0x800> fill {};
};

} // namespace

bool Enabled() {
	Common::LockGuard lock(g_mutex);
	return Load() != nullptr;
}

int Call(uint32_t op, uint32_t key, uint64_t size, const Guest& guest, int32_t* status,
         const char** reason) {
	RegistryLock lock;
	if (lock.table == nullptr) {
		*reason = "snapshot_unavailable";
		return -1;
	}
	Registry           registry(g_snapshot, *lock.table);
	constexpr uint64_t bit   = uint64_t {1} << 62;
	const auto         facts = Process::GetCurrentAuthorizationFacts();
	if (!facts.has_authority || (facts.known_capability0 & bit) == 0) {
		*reason = "caps0_bit62_unobserved";
		return -1;
	}
	// priv 0x2aa; these ops carry on without it.
	if ((facts.capability0 & bit) == 0 && !((op >= 0x18 && op <= 0x1e) || op == 0x20 || op == 0x2f))
		return Posix::POSIX_EPERM;
	auto finish = [&](int32_t rc) {
		if (guest.status == 0 || !guest.write(guest.status, &rc, sizeof(rc)))
			return Posix::POSIX_EFAULT;
		*status = rc;
		return 0;
	};
	const bool reads  = op == 2 || op == 4 || op == 6 || op == 7 || op == 8 || op == 9;
	const bool writes = op == 1 || op == 3 || op == 5;
	if (facts.authority_id == 0x4800000000010003ull) {
		int32_t denied = Code(0x800d0218);
		if (reads || writes || op == 0x1f) {
			uint32_t  index = 0;
			const int idx   = registry.Find(key, &index);
			if (idx < 0)
				denied = Code(0x800d0203);
			else if ((lock.table->rows[idx].access & (writes ? 2 : 1)) != 0)
				denied = 0;
		} else if (op == 0xc || op == 0x20) {
			denied = 0;
		}
		if (denied != 0) return finish(denied);
	}
	if (!reads && !writes && op != 0 && op != 0x11 && op != 0x12 && op != 0x13) {
		*reason = "op";
		return -1;
	}
	// Ops 0, 0x11 and 0x12 take no value pointer.
	if (op == 0 || op == 0x11 || op == 0x12) {
		const int32_t rc = op == 0      ? registry.Op0(key)
		                   : op == 0x11 ? registry.Op11()
		                                : registry.Op12();
		if (registry.unmodelled == nullptr) return finish(rc);
	} else {
		if (guest.status == 0) return Posix::POSIX_EFAULT;
		if (guest.value == 0) return finish(Code(0x800d0202));
		if (size >= 0x801) return finish(Code(0x800d0208));
		// LoadProgramToMemory only takes next-gen main programs, so proc+0xc81 is set
		constexpr int              inst = 1;
		std::array<uint8_t, 0x818> kbuf {};
		if (writes && !guest.read(guest.value, kbuf.data(), op == 1 ? 4 : size))
			return finish(Code(0x800d020f));
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		std::unique_ptr<ScopeRegistry> before;
		if (const char* configured = std::getenv("KYTY_DIAGNOSTIC_REGMGR_PERSIST_PATH");
		    writes && configured != nullptr && configured[0] != '\0')
			before = std::make_unique<ScopeRegistry>(*lock.table);
#endif
		int32_t rc = 0;
		switch (op) {
			case 1: rc = registry.SetInt(inst, key, kbuf.data()); break;
			case 2: rc = registry.GetInt(inst, key, kbuf.data()); break;
			case 3: rc = registry.SetStr(inst, key, kbuf.data(), size); break;
			case 4: rc = registry.GetStr(inst, key, kbuf.data(), size); break;
			case 5: rc = registry.SetBin(inst, key, kbuf.data(), size); break;
			case 6: rc = registry.GetBin(inst, key, kbuf.data(), size); break;
			case 7: rc = registry.Op7(inst, key, kbuf.data()); break;
			case 8: rc = registry.Op8(inst, key, kbuf.data(), size); break;
			case 9: rc = registry.Op9(inst, key, kbuf.data(), size); break;
			case 0x13: rc = registry.Op13(kbuf.data(), size); break;
		}
		if (registry.unmodelled == nullptr) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
			if (rc == 0 && before != nullptr &&
			    std::memcmp(before.get(), lock.table, sizeof(ScopeRegistry)) != 0 &&
			    !SavePersistent(std::getenv("KYTY_DIAGNOSTIC_REGMGR_PERSIST_PATH"),
			                    *lock.table)) {
				*lock.table = *before;
				LOGF("REGMGR_PERSIST_WRITE_FAILED key=0x%08" PRIx32 " op=%" PRIu32 "\n",
				     key, static_cast<uint32_t>(op));
				return finish(Code(0x800d0002));
			}
#endif
			if (rc == 0 && reads &&
			    !guest.write(guest.value, kbuf.data(), op == 2 || op == 7 ? 4 : size))
				rc = Code(0x800d0210);
			if (op == 0x13 && rc > 0)
				rc = guest.write(guest.value, kbuf.data(), size) ? 0 : Code(0x800d0210);
			return finish(rc);
		}
	}
	*reason = registry.unmodelled;
	return -1;
}

// kern.backup_restore_mode OID 0x7ffffeb8. Cache comes from 0x020c0000 via the internal getint,
// without the syscall's caller checks
int BackupRestoreMode(int32_t* value, int32_t* status, const char** reason) {
	RegistryLock lock;
	if (lock.table == nullptr) {
		*reason = "snapshot_unavailable";
		return -1;
	}
	if (lock.table->backup_restore_mode < 0) {
		Registry               registry(g_snapshot, *lock.table);
		std::array<uint8_t, 4> buf {};
		const int32_t          rc = registry.GetInt(1, 0x020c0000, buf.data());
		if (registry.unmodelled != nullptr) {
			*reason = registry.unmodelled;
			return -1;
		}
		*status = rc;
		if (rc != 0) return 0;
		std::memcpy(&lock.table->backup_restore_mode, buf.data(), sizeof(int32_t));
	}
	*status = 0;
	*value  = lock.table->backup_restore_mode;
	return 0;
}

} // namespace Libs::LibKernel::RegMgr
