#include "kernel/sectorBacking.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#endif

namespace Libs::LibKernel {

using Result = SectorBacking::Result;

struct SectorBacking::State {
	uint32_t   sector_size     = 0;
	uint64_t   capacity        = 0;
	uint64_t   source_bytes    = 0;
	bool       captured_prefix = false;
	std::mutex mutex;
#if defined(_WIN32)
	HANDLE source  = INVALID_HANDLE_VALUE;
	HANDLE overlay = INVALID_HANDLE_VALUE;
	struct Header {
		char                    magic[8];
		uint32_t                version;
		uint32_t                sector_size;
		uint64_t                capacity;
		uint64_t                source_bytes;
		std::array<uint8_t, 32> hash;
	} header {};
	struct Transaction {
		char                    magic[8];
		uint64_t                count;
		uint64_t                length;
		std::array<uint8_t, 32> hash;
	};
	static_assert(sizeof(Header) == 64 && sizeof(Transaction) == 56);
	static constexpr uint64_t              max_request = 16 * 1024 * 1024;
	static constexpr uint64_t              max_overlay = 256 * 1024 * 1024;
	std::unordered_map<uint64_t, uint64_t> sectors;
	uint64_t                               journal_end = 0;
#if defined(KYTY_SECTOR_BACKING_TESTING)
	bool fail_commit   = false;
	bool fail_flush    = false;
	bool fail_rollback = false;
#endif

	struct FileLock {
		HANDLE     file;
		OVERLAPPED position {};
		bool       locked;
		explicit FileLock(HANDLE handle)
		    : file(handle), locked(handle == INVALID_HANDLE_VALUE ||
			                       LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD,
			                                  MAXDWORD, &position)) {}
		~FileLock() {
			if (locked && file != INVALID_HANDLE_VALUE)
				UnlockFileEx(file, 0, MAXDWORD, MAXDWORD, &position);
		}
	};

	static bool Transfer(HANDLE file, uint64_t offset, void* bytes, size_t length, bool write) {
		LARGE_INTEGER position;
		position.QuadPart = static_cast<LONGLONG>(offset);
		if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN)) return false;
		auto* cursor = static_cast<uint8_t*>(bytes);
		while (length) {
			const DWORD count = static_cast<DWORD>(std::min<size_t>(length, 1024 * 1024));
			DWORD       done  = 0;
			if (!(write ? WriteFile(file, cursor, count, &done, nullptr)
			            : ReadFile(file, cursor, count, &done, nullptr)) ||
			    done != count)
				return false;
			cursor += done;
			length -= done;
		}
		return true;
	}

	static bool Hash(HANDLE file, uint64_t length, const void* bytes, size_t count,
	                 std::array<uint8_t, 32>* output) {
		BCRYPT_ALG_HANDLE  algorithm = nullptr;
		BCRYPT_HASH_HANDLE hash      = nullptr;
		if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
			return false;
		bool ok = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0;
		if (ok && file != INVALID_HANDLE_VALUE) {
			std::vector<uint8_t> chunk(1024 * 1024);
			for (uint64_t offset = 0; ok && offset < length;) {
				const auto size =
				    static_cast<size_t>(std::min<uint64_t>(chunk.size(), length - offset));
				ok = Transfer(file, offset, chunk.data(), size, false) &&
				     BCryptHashData(hash, chunk.data(), static_cast<ULONG>(size), 0) >= 0;
				offset += size;
			}
		} else if (ok) {
			ok = count <= UINT32_MAX &&
			     BCryptHashData(hash, static_cast<PUCHAR>(const_cast<void*>(bytes)),
			                    static_cast<ULONG>(count), 0) >= 0;
		}
		if (ok) ok = BCryptFinishHash(hash, output->data(), output->size(), 0) >= 0;
		if (hash) BCryptDestroyHash(hash);
		BCryptCloseAlgorithmProvider(algorithm, 0);
		return ok;
	}

	Result Refresh() {
		sectors.clear();
		if (overlay == INVALID_HANDLE_VALUE) return Result::Ok;
		LARGE_INTEGER size;
		if (!GetFileSizeEx(overlay, &size) || size.QuadPart < sizeof(Header) ||
		    size.QuadPart > max_overlay)
			return Result::Io;
		Header actual {};
		if (!Transfer(overlay, 0, &actual, sizeof(actual), false) ||
		    std::memcmp(&header, &actual, sizeof(header)))
			return Result::Io;
		uint64_t offset = sizeof(Header);
		while (offset < static_cast<uint64_t>(size.QuadPart)) {
			Transaction transaction {};
			if (static_cast<uint64_t>(size.QuadPart) - offset < sizeof(transaction) ||
			    !Transfer(overlay, offset, &transaction, sizeof(transaction), false) ||
			    std::memcmp(transaction.magic, "KYTYTXN1", 8) || !transaction.count ||
			    transaction.count > max_request / sector_size + 2 ||
			    transaction.length != transaction.count * (sector_size + sizeof(uint64_t)) ||
			    transaction.length + sizeof(transaction) + 8 >
			        static_cast<uint64_t>(size.QuadPart) - offset)
				return Result::Io;
			std::vector<uint8_t>    payload(static_cast<size_t>(transaction.length));
			std::array<uint8_t, 32> hash;
			char                    commit[8];
			if (!Transfer(overlay, offset + sizeof(transaction), payload.data(), payload.size(),
			              false) ||
			    !Hash(INVALID_HANDLE_VALUE, 0, payload.data(), payload.size(), &hash) ||
			    hash != transaction.hash ||
			    !Transfer(overlay, offset + sizeof(transaction) + payload.size(), commit, 8,
			              false) ||
			    std::memcmp(commit, "COMMIT01", 8))
				return Result::Io;
			uint64_t previous = 0;
			for (uint64_t i = 0; i < transaction.count; ++i) {
				uint64_t       sector = 0;
				const uint64_t record = i * (sector_size + sizeof(sector));
				std::memcpy(&sector, payload.data() + record, sizeof(sector));
				if (sector >= capacity / sector_size || (i && sector <= previous))
					return Result::Io;
				sectors[sector] = offset + sizeof(transaction) + record + sizeof(sector);
				previous        = sector;
			}
			offset += sizeof(transaction) + payload.size() + 8;
		}
		journal_end = offset;
		return Result::Ok;
	}

	Result ReadSector(uint64_t sector, void* bytes) {
		const auto found = sectors.find(sector);
		if (found != sectors.end())
			return Transfer(overlay, found->second, bytes, sector_size, false) ? Result::Ok
			                                                                   : Result::Io;
		if (sector >= source_bytes / sector_size) return Result::MissingData;
		return Transfer(source, sector * sector_size, bytes, sector_size, false) ? Result::Ok
		                                                                         : Result::Io;
	}
#endif
	~State() {
#if defined(_WIN32)
		if (overlay != INVALID_HANDLE_VALUE) CloseHandle(overlay);
		if (source != INVALID_HANDLE_VALUE) CloseHandle(source);
#endif
	}
};

SectorBacking::SectorBacking(std::unique_ptr<State> state): m_state(std::move(state)) {}
SectorBacking::~SectorBacking() = default;
uint64_t SectorBacking::Capacity() const {
	return m_state->capacity;
}
uint64_t SectorBacking::SourceBytes() const {
	return m_state->source_bytes;
}
uint32_t SectorBacking::SectorSize() const {
	return m_state->sector_size;
}
bool SectorBacking::ReadOnly() const {
#if defined(_WIN32)
	return m_state->overlay == INVALID_HANDLE_VALUE;
#else
	return true;
#endif
}
#if defined(KYTY_SECTOR_BACKING_TESTING)
void SectorBacking::FailNextCommit(bool flush, bool rollback) {
	m_state->fail_commit   = true;
	m_state->fail_flush    = flush;
	m_state->fail_rollback = rollback;
}
#endif

std::unique_ptr<SectorBacking> SectorBacking::Open(const std::filesystem::path& source,
                                                   const std::filesystem::path& overlay,
                                                   uint32_t sector_size, uint64_t capacity,
                                                   const std::string& sha256, Result* result) {
	return OpenInternal(source, overlay, sector_size, capacity, sha256, result, false);
}

std::unique_ptr<SectorBacking>
SectorBacking::OpenCapturedPrefix(const std::filesystem::path& source,
                                  const std::filesystem::path& overlay, const std::string& sha256,
                                  Result* result) {
	return OpenInternal(source, overlay, 512, 0, sha256, result, true);
}

std::unique_ptr<SectorBacking> SectorBacking::OpenInternal(const std::filesystem::path& source,
                                                           const std::filesystem::path& overlay,
                                                           uint32_t sector_size, uint64_t capacity,
                                                           const std::string& sha256,
                                                           Result* result, bool captured_prefix) {
	*result = Result::Invalid;
#if defined(_WIN32)
	const bool identify_read_only = captured_prefix && overlay.empty() && sha256.empty();
	if ((sector_size != 512 && sector_size != 4096) ||
	    (!captured_prefix && (!capacity || capacity > INT64_MAX || capacity % sector_size)) ||
	    (!identify_read_only && sha256.size() != 64) || !source.is_absolute() ||
	    (!overlay.empty() && (!overlay.is_absolute() || overlay.extension() != ".kytycow")))
		return {};
	std::error_code error;
	if (!std::filesystem::is_regular_file(source, error) || error) return {};
	const auto original = std::filesystem::canonical(source, error);
	if (error) return {};
	std::filesystem::path output;
	if (!overlay.empty()) {
		output = std::filesystem::weakly_canonical(overlay, error);
		if (error || output == original ||
		    !std::filesystem::is_directory(output.parent_path(), error) || error)
			return {};
	}
	auto                    state = std::make_unique<State>();
	std::array<uint8_t, 32> expected {};
	auto                    digit = [](char value) {
		return value >= '0' && value <= '9'   ? value - '0'
		       : value >= 'a' && value <= 'f' ? value - 'a' + 10
		                                      : -1;
	};
	for (size_t i = 0; !identify_read_only && i < expected.size(); ++i) {
		const int high = digit(sha256[i * 2]), low = digit(sha256[i * 2 + 1]);
		if (high < 0 || low < 0) return {};
		expected[i] = static_cast<uint8_t>(high * 16 + low);
	}
	*result       = Result::Io;
	state->source = CreateFileW(original.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
	                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	LARGE_INTEGER size;
	if (state->source == INVALID_HANDLE_VALUE || GetFileType(state->source) != FILE_TYPE_DISK ||
	    !GetFileSizeEx(state->source, &size) || size.QuadPart <= 0)
		return {};
	if (captured_prefix) {
		if (size.QuadPart > INT64_MAX - sector_size) return {};
		capacity =
		    (static_cast<uint64_t>(size.QuadPart) + sector_size - 1) / sector_size * sector_size;
	} else if (static_cast<uint64_t>(size.QuadPart) > capacity || size.QuadPart % sector_size)
		return {};
	state->sector_size     = sector_size;
	state->capacity        = capacity;
	state->source_bytes    = static_cast<uint64_t>(size.QuadPart);
	state->captured_prefix = captured_prefix;
	std::memcpy(state->header.magic, "KYTYCOW1", 8);
	state->header.version      = 1;
	state->header.sector_size  = sector_size;
	state->header.capacity     = capacity;
	state->header.source_bytes = state->source_bytes;
	if (!State::Hash(state->source, state->source_bytes, nullptr, 0, &state->header.hash) ||
	    (!identify_read_only && state->header.hash != expected))
		return {};
	if (!overlay.empty()) {
		state->overlay = CreateFileW(output.c_str(), GENERIC_READ | GENERIC_WRITE,
		                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
		                             FILE_ATTRIBUTE_NORMAL, nullptr);
		if (state->overlay == INVALID_HANDLE_VALUE || GetFileType(state->overlay) != FILE_TYPE_DISK)
			return {};
		State::FileLock lock(state->overlay);
		if (!lock.locked || !GetFileSizeEx(state->overlay, &size)) return {};
		if (size.QuadPart == 0 &&
		    (!State::Transfer(state->overlay, 0, &state->header, sizeof(state->header), true) ||
		     !FlushFileBuffers(state->overlay)))
			return {};
		if (state->Refresh() != Result::Ok) return {};
	}
	*result = Result::Ok;
	return std::unique_ptr<SectorBacking>(new SectorBacking(std::move(state)));
#else
	*result = Result::Unsupported;
	return {};
#endif
}

Result SectorBacking::Read(uint64_t offset, void* bytes, size_t length) {
#if defined(_WIN32)
	auto& state = *m_state;
	if (offset > state.capacity || length > state.capacity - offset ||
	    length > State::max_request || (length && !bytes))
		return Result::Invalid;
	if (!length) return Result::Ok;
	if (state.captured_prefix &&
	    (offset > state.source_bytes || length > state.source_bytes - offset))
		return Result::MissingData;
	std::lock_guard guard(state.mutex);
	State::FileLock lock(state.overlay);
	if (!lock.locked || state.Refresh() != Result::Ok) return Result::Io;
	std::vector<uint8_t> output(length), sector(state.sector_size);
	for (size_t done = 0; done < length;) {
		const uint64_t position = offset + done;
		const size_t   inside   = position % state.sector_size;
		const size_t   count    = std::min(length - done, state.sector_size - inside);
		const auto     result   = state.ReadSector(position / state.sector_size, sector.data());
		if (result != Result::Ok) {
			if (result == Result::MissingData && position < state.source_bytes &&
			    count <= state.source_bytes - position) {
				if (!State::Transfer(state.source, position, output.data() + done, count, false))
					return Result::Io;
				done += count;
				continue;
			}
			return result;
		}
		std::memcpy(output.data() + done, sector.data() + inside, count);
		done += count;
	}
	std::memcpy(bytes, output.data(), length);
	return Result::Ok;
#else
	return Result::Unsupported;
#endif
}

Result SectorBacking::Write(uint64_t offset, const void* bytes, size_t length) {
#if defined(_WIN32)
	auto& state = *m_state;
	if (offset > state.capacity || length > state.capacity - offset ||
	    length > State::max_request || (length && !bytes))
		return Result::Invalid;
	if (state.overlay == INVALID_HANDLE_VALUE) return Result::ReadOnly;
	if (!length) return Result::Ok;
	if (state.captured_prefix &&
	    (offset > state.source_bytes || length > state.source_bytes - offset))
		return Result::MissingData;
	std::lock_guard guard(state.mutex);
	State::FileLock lock(state.overlay);
	if (!lock.locked || state.Refresh() != Result::Ok) return Result::Io;
	const uint64_t     first = offset / state.sector_size;
	const uint64_t     count = (offset + length - 1) / state.sector_size - first + 1;
	State::Transaction transaction {};
	std::memcpy(transaction.magic, "KYTYTXN1", 8);
	transaction.count  = count;
	transaction.length = count * (sizeof(uint64_t) + state.sector_size);
	if (sizeof(transaction) + transaction.length + 8 > State::max_overlay - state.journal_end)
		return Result::NoSpace;
	std::vector<uint8_t> record(sizeof(transaction) + transaction.length + 8);
	auto*                payload = record.data() + sizeof(transaction);
	for (uint64_t i = 0; i < count; ++i) {
		const uint64_t index = first + i;
		auto*          entry = payload + i * (sizeof(index) + state.sector_size);
		std::memcpy(entry, &index, sizeof(index));
		const uint64_t begin = std::max(offset, index * state.sector_size);
		const uint64_t end   = std::min(offset + length, (index + 1) * state.sector_size);
		if (end - begin != state.sector_size) {
			const auto result = state.ReadSector(index, entry + sizeof(index));
			if (result != Result::Ok) {
				const uint64_t source_offset = index * state.sector_size;
				if (result != Result::MissingData || !state.captured_prefix ||
				    source_offset >= state.source_bytes)
					return result;
				// padding completes the journal record
				if (!State::Transfer(state.source, source_offset, entry + sizeof(index),
				                     static_cast<size_t>(state.source_bytes - source_offset),
				                     false))
					return Result::Io;
			}
		}
		std::memcpy(entry + sizeof(index) + begin - index * state.sector_size,
		            static_cast<const uint8_t*>(bytes) + begin - offset,
		            static_cast<size_t>(end - begin));
	}
	if (!State::Hash(INVALID_HANDLE_VALUE, 0, payload, transaction.length, &transaction.hash))
		return Result::Io;
	std::memcpy(record.data(), &transaction, sizeof(transaction));
	std::memcpy(record.data() + record.size() - 8, "COMMIT01", 8);
	bool transferred;
	bool flushed;
#if defined(KYTY_SECTOR_BACKING_TESTING)
	const bool fail = std::exchange(state.fail_commit, false);
	if (fail && !state.fail_flush) {
		State::Transfer(state.overlay, state.journal_end, record.data(), record.size() - 8, true);
		transferred = false;
	} else
#endif
		transferred =
		    State::Transfer(state.overlay, state.journal_end, record.data(), record.size(), true);
	flushed = transferred && FlushFileBuffers(state.overlay);
#if defined(KYTY_SECTOR_BACKING_TESTING)
	if (fail && state.fail_flush) flushed = false;
#endif
	if (!transferred || !flushed) {
		LARGE_INTEGER previous;
		previous.QuadPart = static_cast<LONGLONG>(state.journal_end);
#if defined(KYTY_SECTOR_BACKING_TESTING)
		if (fail && state.fail_rollback) return Result::Io;
#endif
		if (SetFilePointerEx(state.overlay, previous, nullptr, FILE_BEGIN) &&
		    SetEndOfFile(state.overlay))
			FlushFileBuffers(state.overlay);
		return Result::Io;
	}
	return state.Refresh();
#else
	return Result::Unsupported;
#endif
}

} // namespace Libs::LibKernel
