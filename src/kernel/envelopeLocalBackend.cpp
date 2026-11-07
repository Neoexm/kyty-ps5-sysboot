#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#endif

#include "kernel/envelopeLocalBackend.h"

#include "common/logging/log.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <vector>

namespace Libs::LibKernel::EnvelopeSecureProcessor {

namespace {

constexpr std::array<uint8_t, 8> table_magic {'K', 'Y', 'T', 'Y', 'M', 'K', 'V', '1'};
constexpr uint32_t               wildcard_cid        = 0xffffffff;
constexpr uint32_t               derivation_id_limit = 0x80000000;

struct TableEntry {
	uint32_t             derivation = 0;
	std::vector<uint8_t> material;
};

using Key = std::pair<uint32_t, uint32_t>; // (cid, mkv)

bool DiagnosticDerivationEnabled() {
	const char* flag = std::getenv("KYTY_DIAGNOSTIC_ENVELOPE_LOCAL");
	return flag != nullptr && flag[0] == '1' && flag[1] == '\0';
}

#if defined(_WIN32)

bool LoadTable(const char* path, std::map<Key, TableEntry>* entries, std::string* error) {
	std::ifstream              input(path, std::ios::binary);
	const std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)),
	                                 std::istreambuf_iterator<char>());
	if (bytes.size() < 12 || !std::equal(table_magic.begin(), table_magic.end(), bytes.begin())) {
		if (error != nullptr) *error = "invalid local key table";
		return false;
	}
	auto u32 = [&](size_t offset) {
		return static_cast<uint32_t>(bytes[offset]) |
		       (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
		       (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
		       (static_cast<uint32_t>(bytes[offset + 3]) << 24);
	};
	const uint32_t count  = u32(8);
	size_t         cursor = 12;
	for (uint32_t i = 0; i < count; i++) {
		if (bytes.size() - cursor < 48) {
			if (error != nullptr) *error = "truncated local key table";
			return false;
		}
		const uint32_t cid           = u32(cursor);
		const uint32_t mkv           = u32(cursor + 4);
		const uint32_t derivation    = u32(cursor + 8);
		const uint32_t material_size = u32(cursor + 12);
		TableEntry     entry;
		entry.derivation = derivation;
		if (material_size > 32) {
			if (error != nullptr) *error = "invalid local key material size";
			return false;
		}
		entry.material.assign(bytes.begin() + cursor + 16,
		                      bytes.begin() + cursor + 16 + material_size);
		(*entries)[{cid, mkv}] = std::move(entry);
		cursor += 48;
	}
	return true;
}

bool Aes128(bool decrypt, bool cbc, std::span<const uint8_t, 16> secret,
            std::span<const uint8_t> input, std::span<uint8_t> output, std::span<uint8_t> iv = {}) {
	if (input.empty() || input.size() != output.size() || input.size() > ULONG_MAX ||
	    (cbc && (iv.data() == nullptr || iv.size() != 16)))
		return false;
	BCRYPT_ALG_HANDLE algorithm     = nullptr;
	BCRYPT_KEY_HANDLE key           = nullptr;
	DWORD             object_size   = 0;
	DWORD             property_size = 0;
	const wchar_t*    mode          = cbc ? BCRYPT_CHAIN_MODE_CBC : BCRYPT_CHAIN_MODE_ECB;
	const ULONG mode_size = cbc ? sizeof(BCRYPT_CHAIN_MODE_CBC) : sizeof(BCRYPT_CHAIN_MODE_ECB);
	bool        ok =
	    BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0) >= 0 &&
	    BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
		                  reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(mode)), mode_size,
		                  0) >= 0 &&
	    BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size),
		                  sizeof(object_size), &property_size, 0) >= 0 &&
	    property_size == sizeof(object_size) && object_size != 0;
	std::vector<uint8_t> object(ok ? object_size : 0);
	if (ok)
		ok = BCryptGenerateSymmetricKey(algorithm, &key, object.data(), object_size,
		                                const_cast<PUCHAR>(secret.data()), secret.size(), 0) >= 0;
	ULONG written = 0;
	if (ok) {
		const auto status =
		    decrypt ? BCryptDecrypt(key, const_cast<PUCHAR>(input.data()),
			                        static_cast<ULONG>(input.size()), nullptr,
			                        cbc ? iv.data() : nullptr, cbc ? iv.size() : 0, output.data(),
			                        static_cast<ULONG>(output.size()), &written, 0)
			        : BCryptEncrypt(key, const_cast<PUCHAR>(input.data()),
			                        static_cast<ULONG>(input.size()), nullptr,
			                        cbc ? iv.data() : nullptr, cbc ? iv.size() : 0, output.data(),
			                        static_cast<ULONG>(output.size()), &written, 0);
		ok = status >= 0 && written == output.size();
	}
	if (key != nullptr) BCryptDestroyKey(key);
	if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
	if (!object.empty()) SecureZeroMemory(object.data(), object.size());
	return ok;
}

#endif

} // namespace

struct LocalSecureBackend::Impl {
	std::mutex                                  mutex;
	std::map<Key, TableEntry>                   table;
	std::map<uint16_t, std::array<uint8_t, 16>> slots;
	uint32_t                                    derives   = 0;
	uint32_t                                    chunks    = 0;
	uint32_t                                    residuals = 0;
	uint32_t                                    releases  = 0;
	~Impl() {
		for (auto& [id, key]: slots)
			Wipe(key);
		for (auto& [id, entry]: table)
			Wipe(entry.material);
	}
};

LocalSecureBackend::LocalSecureBackend(): impl(std::make_unique<Impl>()) {}
LocalSecureBackend::~LocalSecureBackend() = default;

CommandResult LocalSecureBackend::DeriveKey(const Context& context, uint16_t* slot) noexcept {
#if defined(_WIN32)
	std::lock_guard lock(impl->mutex);
	auto            it = impl->table.find({context.cid, context.mkv});
	if (it == impl->table.end()) it = impl->table.find({wildcard_cid, context.mkv});
	if (it == impl->table.end() || it->second.material.size() < 16) {
		return {Status::Unavailable, unavailable_result};
	}
	const TableEntry&       entry = it->second;
	std::array<uint8_t, 16> derived {};
	bool                    ok = false;
	if (entry.derivation == derivation_diagnostic_ecb_salt) {
		// Stand-in, not the command-0x401 derivation.
		if (!DiagnosticDerivationEnabled()) return {Status::Unavailable, unavailable_result};
		LOGF("SBL_ENVELOPE_LOCAL_DERIVE derivation=diagnostic_ecb_salt NON_AUTHENTIC=1 cid=0x%x "
		     "mkv=%u\n",
		     context.cid, context.mkv);
		std::array<uint8_t, 16> material {};
		std::memcpy(material.data(), entry.material.data(), material.size());
		ok = Aes128(false, false, material, std::span<const uint8_t>(context.salt.data(), 16),
		            derived);
		Wipe(material);
	} else {
		// nothing registered besides the stand-in
		return {Status::Unavailable, unavailable_result};
	}
	if (!ok) return {Status::OperationError, unavailable_result};
	uint16_t candidate = 0;
	for (uint32_t i = 1; i <= 0xffff; i++) {
		if (impl->slots.count(static_cast<uint16_t>(i)) == 0) {
			candidate = static_cast<uint16_t>(i);
			break;
		}
	}
	if (candidate == 0) {
		Wipe(derived);
		return {Status::Unavailable, unavailable_result};
	}
	impl->slots.emplace(candidate, derived);
	impl->derives++;
	*slot = candidate;
	return {Status::Success, 0};
#else
	return {Status::Unavailable, unavailable_result};
#endif
}

CommandResult LocalSecureBackend::DecryptBlocks(uint16_t slot, std::span<uint8_t, 16> state,
                                                std::span<const uint8_t> input,
                                                std::span<uint8_t>       output) noexcept {
#if defined(_WIN32)
	std::lock_guard lock(impl->mutex);
	const auto      it = impl->slots.find(slot);
	if (it == impl->slots.end() || input.empty() || input.size() % 16 != 0 ||
	    input.size() > crypt_chunk_size || input.size() != output.size()) {
		return {Status::OperationError, unavailable_result};
	}
	std::array<uint8_t, 16> chain {};
	std::memcpy(chain.data(), state.data(), chain.size());
	// carried state is the last ciphertext block, as on the console
	std::array<uint8_t, 16> next {};
	std::memcpy(next.data(), input.data() + input.size() - next.size(), next.size());
	const bool ok = Aes128(true, true, it->second, input, output, chain);
	if (!ok) {
		Wipe(chain);
		Wipe(next);
		return {Status::OperationError, unavailable_result};
	}
	std::memcpy(state.data(), next.data(), state.size());
	impl->chunks++;
	return {Status::Success, 0};
#else
	return {Status::OperationError, unavailable_result};
#endif
}

CommandResult LocalSecureBackend::EncryptBlock(uint16_t               slot,
                                               std::span<uint8_t, 16> state) noexcept {
#if defined(_WIN32)
	std::lock_guard lock(impl->mutex);
	const auto      it = impl->slots.find(slot);
	if (it == impl->slots.end()) return {Status::OperationError, unavailable_result};
	std::array<uint8_t, 16>  encrypted {};
	std::span<const uint8_t> block(state.data(), state.size());
	std::span<uint8_t>       out(encrypted.data(), encrypted.size());
	const bool               ok = Aes128(false, false, it->second, block, out);
	if (!ok) {
		Wipe(encrypted);
		return {Status::OperationError, unavailable_result};
	}
	std::memcpy(state.data(), encrypted.data(), state.size());
	Wipe(encrypted);
	impl->residuals++;
	return {Status::Success, 0};
#else
	return {Status::OperationError, unavailable_result};
#endif
}

void LocalSecureBackend::ReleaseKey(uint16_t slot) noexcept {
	std::lock_guard lock(impl->mutex);
	const auto      it = impl->slots.find(slot);
	if (it == impl->slots.end()) return;
	Wipe(it->second);
	impl->slots.erase(it);
	impl->releases++;
}

bool LocalSecureBackend::LoadKeyTable(const char* path, std::string* error) noexcept {
#if defined(_WIN32)
	std::map<Key, TableEntry> entries;
	if (!LoadTable(path, &entries, error)) {
		for (auto& [domain, entry]: entries)
			Wipe(entry.material);
		return false;
	}
	std::lock_guard lock(impl->mutex);
	for (auto& [domain, entry]: impl->table)
		Wipe(entry.material);
	impl->table = std::move(entries);
	return true;
#else
	if (error != nullptr) *error = "local backend is only implemented on Windows";
	return false;
#endif
}

void LocalSecureBackend::TableCounts(size_t* total, uint32_t* authentic,
                                     uint32_t* diagnostic) const noexcept {
	std::lock_guard lock(impl->mutex);
	if (total != nullptr) *total = impl->table.size();
	if (authentic != nullptr) *authentic = 0;
	if (diagnostic != nullptr) *diagnostic = 0;
	for (const auto& [domain, entry]: impl->table) {
		if (entry.derivation >= derivation_id_limit) {
			if (diagnostic != nullptr) (*diagnostic)++;
		} else if (authentic != nullptr) {
			(*authentic)++;
		}
	}
}

ConfigurationStatus CreateLocalBackendFromEnvironment(std::shared_ptr<Backend>* backend,
                                                      std::string*              error) {
	if (backend == nullptr) return ConfigurationStatus::Invalid;
#if defined(_WIN32)
	const char* table_path = std::getenv("KYTY_PS5_ENVELOPE_LOCAL_KEYTABLE");
	if (table_path == nullptr || table_path[0] == '\0') {
		if (error != nullptr) *error = "local backend requires KYTY_PS5_ENVELOPE_LOCAL_KEYTABLE";
		return ConfigurationStatus::Invalid;
	}
	auto local = std::make_shared<LocalSecureBackend>();
	if (!local->LoadKeyTable(table_path, error)) return ConfigurationStatus::Invalid;
	size_t   total      = 0;
	uint32_t authentic  = 0;
	uint32_t diagnostic = 0;
	local->TableCounts(&total, &authentic, &diagnostic);
	LOGF(
	    "SBL_ENVELOPE_LOCAL_TABLE entries=%zu authentic_derivations=%u diagnostic_derivations=%u\n",
	    total, authentic, diagnostic);
	*backend = std::move(local);
	return ConfigurationStatus::Configured;
#else
	if (error != nullptr) *error = "local backend is only implemented on Windows";
	return ConfigurationStatus::Invalid;
#endif
}

} // namespace Libs::LibKernel::EnvelopeSecureProcessor
