#include "common/common.h"

#if KYTY_PLATFORM != KYTY_PLATFORM_WINDOWS
// #error "KYTY_PLATFORM != KYTY_PLATFORM_WINDOWS"
#else

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h> // IWYU pragma: keep

#include "common/platform/sysFileIO.h"
#include "common/platform/sysTimer.h"
#include "common/stringUtils.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <vector>

// NOLINTNEXTLINE(readability-identifier-naming)
enum sys_file_type_t {
	SYS_FILE_ERROR,       // NOLINT(readability-identifier-naming)
	SYS_FILE_MEMORY_STAT, // NOLINT(readability-identifier-naming)
	SYS_FILE_FILE,        // NOLINT(readability-identifier-naming)
	SYS_FILE_MEMORY_DYN   // NOLINT(readability-identifier-naming)
};

// NOLINTNEXTLINE(readability-identifier-naming)
struct sys_file_mem_buf_t {
	uint8_t* base;
	uint64_t position;
	uint32_t size;
};

// NOLINTNEXTLINE(readability-identifier-naming)
struct sys_file_t {
	sys_file_type_t type;
	union {
		HANDLE              handle;
		sys_file_mem_buf_t* buf;
	};
};

// IWYU pragma: no_include <fileapi.h>
// IWYU pragma: no_include <handleapi.h>
// IWYU pragma: no_include <minwinbase.h>
// IWYU pragma: no_include <minwindef.h>
// IWYU pragma: no_include <winbase.h>

constexpr DWORD FILE_SHARE_POSIX = static_cast<DWORD>(FILE_SHARE_READ) |
                                   static_cast<DWORD>(FILE_SHARE_WRITE) |
                                   static_cast<DWORD>(FILE_SHARE_DELETE);

static DWORD GetCacheAccessType(sys_file_cache_type_t t) {
	if (t == SYS_FILE_CACHE_RANDOM_ACCESS) {
		return FILE_FLAG_RANDOM_ACCESS;
	}

	if (t == SYS_FILE_CACHE_SEQUENTIAL_SCAN) {
		return FILE_FLAG_SEQUENTIAL_SCAN;
	}

	return FILE_ATTRIBUTE_NORMAL;
}

void SysFileRead(void* data, uint32_t size, sys_file_t& f, uint32_t* bytes_read,
                 std::error_code* read_error) {
	if (bytes_read != nullptr) *bytes_read = 0;
	if (read_error != nullptr) read_error->clear();
	if (f.type == SYS_FILE_FILE) {
		DWORD w = 0;
		const BOOL  success = ReadFile(f.handle, data, size, &w, nullptr);
		const DWORD error   = success ? ERROR_SUCCESS : GetLastError();
		if (bytes_read != nullptr) {
			*bytes_read = w;
		}
		if (read_error != nullptr && !success && error != ERROR_HANDLE_EOF) {
			*read_error = std::error_code(static_cast<int>(error), std::system_category());
		}
	} else if (f.type == SYS_FILE_MEMORY_STAT || f.type == SYS_FILE_MEMORY_DYN) {
		const uint64_t remaining =
		    f.buf->position < f.buf->size ? f.buf->size - f.buf->position : 0;
		const auto count = static_cast<uint32_t>(std::min<uint64_t>(size, remaining));
		if (count != 0) std::memcpy(data, f.buf->base + f.buf->position, count);
		f.buf->position += count;
		if (bytes_read != nullptr) *bytes_read = count;
	} else if (read_error != nullptr) {
		*read_error = std::make_error_code(std::errc::bad_file_descriptor);
	}
}

void SysFileWrite(const void* data, uint32_t size, sys_file_t& f, uint32_t* bytes_written,
                  std::error_code* write_error) {
	if (bytes_written != nullptr) *bytes_written = 0;
	if (write_error != nullptr) write_error->clear();
	if (f.type == SYS_FILE_FILE) {
		DWORD w = 0;
		const BOOL  success = WriteFile(f.handle, data, size, &w, nullptr);
		const DWORD error   = success ? ERROR_SUCCESS : GetLastError();
		if (bytes_written != nullptr) {
			*bytes_written = w;
		}
		if (write_error != nullptr && !success) {
			*write_error = std::error_code(static_cast<int>(error), std::system_category());
		}
	} else if (f.type == SYS_FILE_MEMORY_STAT) {
		const uint64_t remaining =
		    f.buf->position < f.buf->size ? f.buf->size - f.buf->position : 0;
		const auto count = static_cast<uint32_t>(std::min<uint64_t>(size, remaining));
		if (count != 0) std::memcpy(f.buf->base + f.buf->position, data, count);
		f.buf->position += count;
		if (bytes_written != nullptr) *bytes_written = count;
		if (write_error != nullptr && count != size) {
			*write_error = std::make_error_code(std::errc::no_space_on_device);
		}
	} else if (f.type == SYS_FILE_MEMORY_DYN) {
		if (size == 0) return;
		const auto position = f.buf->position;
		if (position > UINT32_MAX || size > UINT32_MAX - position) {
			if (write_error != nullptr)
				*write_error = std::make_error_code(std::errc::file_too_large);
			return;
		}
		const auto end = static_cast<uint32_t>(position + size);
		if (f.buf->size < end) {
			auto* allocation = static_cast<uint8_t*>(std::realloc(f.buf->base, end));
			if (allocation == nullptr) {
				if (write_error != nullptr)
					*write_error = std::make_error_code(std::errc::not_enough_memory);
				return;
			}
			std::memset(allocation + f.buf->size, 0, end - f.buf->size);
			f.buf->base = allocation;
			f.buf->size = end;
		}
		std::memcpy(f.buf->base + position, data, size);
		f.buf->position = end;
		if (bytes_written != nullptr) *bytes_written = size;
	} else if (write_error != nullptr) {
		*write_error = std::make_error_code(std::errc::bad_file_descriptor);
	}
}

sys_file_t* SysFileCreate(const std::filesystem::path& file_name) {
	auto* ret = new sys_file_t;

	auto   wide   = file_name.wstring();
	HANDLE h_file = nullptr;
	h_file = CreateFileW(wide.c_str(),
	                     static_cast<DWORD>(GENERIC_READ) | static_cast<DWORD>(GENERIC_WRITE) |
	                         static_cast<DWORD>(DELETE),
	                     FILE_SHARE_POSIX, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	ret->handle = h_file;
	ret->type   = SYS_FILE_FILE;

	return ret;
}

sys_file_t* SysFileOpenR(const std::filesystem::path& file_name, sys_file_cache_type_t cache_type) {
	auto* ret = new sys_file_t;

	auto   wide   = file_name.wstring();
	HANDLE h_file = nullptr;
	h_file = CreateFileW(wide.c_str(), GENERIC_READ, FILE_SHARE_POSIX, nullptr, OPEN_EXISTING,
	                     GetCacheAccessType(cache_type), nullptr);

	if (h_file == INVALID_HANDLE_VALUE) {
		ret->type = SYS_FILE_ERROR;
	} else {
		ret->type = SYS_FILE_FILE;
	}

	ret->handle = h_file;

	return ret;
}

sys_file_t* SysFileOpen(uint8_t* buf, uint32_t buf_size) {
	auto* ret = new sys_file_t;

	ret->type      = SYS_FILE_MEMORY_STAT;
	ret->buf       = new sys_file_mem_buf_t;
	ret->buf->base = buf;
	ret->buf->position = 0;
	ret->buf->size = buf_size;

	return ret;
}

sys_file_t* SysFileCreate() {
	auto* ret = new sys_file_t;

	ret->type      = SYS_FILE_MEMORY_DYN;
	ret->buf       = new sys_file_mem_buf_t;
	ret->buf->base = nullptr;
	ret->buf->position = 0;
	ret->buf->size = 0;

	return ret;
}

sys_file_t* SysFileOpenW(const std::filesystem::path& file_name, sys_file_cache_type_t cache_type) {
	auto* ret = new sys_file_t;

	auto   wide   = file_name.wstring();
	HANDLE h_file = nullptr;
	h_file        = CreateFileW(
	    wide.c_str(), static_cast<DWORD>(GENERIC_WRITE) | static_cast<DWORD>(DELETE),
	    FILE_SHARE_POSIX, nullptr, OPEN_EXISTING, GetCacheAccessType(cache_type), nullptr);

	if (h_file == INVALID_HANDLE_VALUE) {
		ret->type = SYS_FILE_ERROR;
	} else {
		ret->type = SYS_FILE_FILE;
	}

	ret->handle = h_file;

	return ret;
}

sys_file_t* SysFileOpenRw(const std::filesystem::path& file_name,
                          sys_file_cache_type_t        cache_type) {
	auto* ret = new sys_file_t;

	auto   wide   = file_name.wstring();
	HANDLE h_file = nullptr;
	h_file = CreateFileW(wide.c_str(),
	                     static_cast<DWORD>(GENERIC_READ) | static_cast<DWORD>(GENERIC_WRITE) |
	                         static_cast<DWORD>(DELETE),
	                     FILE_SHARE_POSIX, nullptr, OPEN_EXISTING, GetCacheAccessType(cache_type),
	                     nullptr);

	if (h_file == INVALID_HANDLE_VALUE) {
		ret->type = SYS_FILE_ERROR;
	} else {
		ret->type = SYS_FILE_FILE;
	}

	ret->handle = h_file;

	return ret;
}

void SysFileClose(sys_file_t* f) {
	if (f->type == SYS_FILE_FILE) {
		CloseHandle(f->handle);
	} else if (f->type == SYS_FILE_MEMORY_STAT) {
		delete f->buf;
	} else if (f->type == SYS_FILE_MEMORY_DYN) {
		std::free(f->buf->base);
		delete f->buf;
	}

	// f.type = SYS_FILE_ERROR;
	delete f;
}

uint64_t SysFileSize(sys_file_t& f) {
	if (f.type == SYS_FILE_FILE) {
		LARGE_INTEGER s;
		GetFileSizeEx(f.handle, &s);
		return s.QuadPart;
	}

	if (f.type == SYS_FILE_MEMORY_STAT || f.type == SYS_FILE_MEMORY_DYN) {
		return f.buf->size;
	}

	return 0;
}

bool SysFileGetInfo(const std::filesystem::path& name, bool* is_file, uint64_t* size) {
	const bool directory_path = !name.empty() && !name.has_filename() && name != name.root_path();
	WIN32_FILE_ATTRIBUTE_DATA info {};
	if (GetFileAttributesExW(directory_path ? name.parent_path().c_str() : name.c_str(),
	                         GetFileExInfoStandard, &info) == 0) {
		return false;
	}
	const bool file = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
	if (directory_path && file) {
		return false;
	}
	*is_file = file;
	*size = *is_file ? ((static_cast<uint64_t>(info.nFileSizeHigh) << 32u) | info.nFileSizeLow) : 0;
	return true;
}

uint64_t SysFileSize(const std::filesystem::path& file_name) {
	bool is_file;
	uint64_t size = 0;
	SysFileGetInfo(file_name, &is_file, &size);
	return size;
}

bool SysFileTruncate(sys_file_t& f, uint64_t size) {
	bool ok = false;
	if (f.type == SYS_FILE_FILE) {
		LARGE_INTEGER s {};
		LARGE_INTEGER r {};
		s.QuadPart = 0;
		SetFilePointerEx(f.handle, s, &r, FILE_CURRENT);
		s.QuadPart = static_cast<LONGLONG>(size);
		ok         = (SetFilePointerEx(f.handle, s, nullptr, FILE_BEGIN) != 0 &&
		              SetEndOfFile(f.handle) != 0);
		SetFilePointerEx(f.handle, r, nullptr, FILE_BEGIN);
	}

	return ok;
}

bool SysFileUnlink(sys_file_t& f, const std::filesystem::path& name) {
	// By name first: since 1809, DeleteFileW on NTFS frees the name at once. A disposition on f
	// leaves it delete-pending until f closes.
	if (SysFileDeleteFile(name)) {
		return true;
	}

	if (f.type == SYS_FILE_FILE) {
		FILE_DISPOSITION_INFO info {};
		info.DeleteFile = TRUE;
		if (SetFileInformationByHandle(f.handle, FileDispositionInfo, &info, sizeof(info)) != 0) {
			return true;
		}
	}

	return false;
}

bool SysFileSeek(sys_file_t& f, uint64_t offset) {
	bool ok = true;
	if (f.type == SYS_FILE_FILE) {
		LARGE_INTEGER s;
		s.QuadPart = static_cast<LONGLONG>(offset);
		ok         = (SetFilePointerEx(f.handle, s, nullptr, FILE_BEGIN) != 0);
		// printf("seek: %u\n", offset);
	} else if (f.type == SYS_FILE_MEMORY_STAT || f.type == SYS_FILE_MEMORY_DYN) {
		f.buf->position = offset;
	}

	return ok;
}

uint64_t SysFileTell(sys_file_t& f) {
	if (f.type == SYS_FILE_FILE) {
		LARGE_INTEGER s {};
		LARGE_INTEGER r {};
		s.QuadPart = 0;
		SetFilePointerEx(f.handle, s, &r, FILE_CURRENT);
		// printf("tell: %u\n", r.QuadPart);
		return r.QuadPart;
	}

	if (f.type == SYS_FILE_MEMORY_STAT || f.type == SYS_FILE_MEMORY_DYN) {
		return f.buf->position;
	}

	return 0;
}

bool SysFileIsError(sys_file_t& f) {
	return f.type == SYS_FILE_ERROR ||
	       (f.type == SYS_FILE_FILE && f.handle == INVALID_HANDLE_VALUE);
}

bool SysFileIsDirectoryExisting(const std::filesystem::path& path) {
	bool is_file;
	uint64_t size;
	return SysFileGetInfo(path, &is_file, &size) && !is_file;
}

bool SysFileIsFileExisting(const std::filesystem::path& name) {
	bool is_file;
	uint64_t size;
	return SysFileGetInfo(name, &is_file, &size) && is_file;
}

bool SysFileCreateDirectory(const std::filesystem::path& path) {
	auto wide = path.wstring();
	return CreateDirectoryW(wide.c_str(), nullptr) != 0;
}

bool SysFileDeleteDirectory(const std::filesystem::path& path) {
	auto wide = path.wstring();
	return RemoveDirectoryW(wide.c_str()) != 0;
}

bool SysFileDeleteFile(const std::filesystem::path& name) {
	auto wide = name.wstring();
	return DeleteFileW(wide.c_str()) != 0;
}

bool SysFileFlush(sys_file_t& f) {
	if (f.type == SYS_FILE_FILE && f.handle != INVALID_HANDLE_VALUE) {
		return (FlushFileBuffers(f.handle) != 0);
	}

	return false;
}

SysFileTimeStruct SysFileGetLastAccessTimeUtc(const std::filesystem::path& name) {
	SysFileTimeStruct r {};
	sys_file_t*       f = SysFileOpenR(name);
	r.is_invalid =
	    (f->type == SYS_FILE_ERROR || (GetFileTime(f->handle, nullptr, &r.time, nullptr) == 0));
	SysFileClose(f);
	return r;
}

SysFileTimeStruct SysFileGetLastWriteTimeUtc(const std::filesystem::path& name) {
	SysFileTimeStruct r {};
	sys_file_t*       f = SysFileOpenR(name);
	r.is_invalid =
	    (f->type == SYS_FILE_ERROR || (GetFileTime(f->handle, nullptr, nullptr, &r.time) == 0));
	SysFileClose(f);
	return r;
}

void SysFileGetLastAccessAndWriteTimeUtc(const std::filesystem::path& name, SysFileTimeStruct& a,
                                         SysFileTimeStruct& w) {
	// TODO() open file with dwDesiredAccess = 0
	// TODO() open directory
	sys_file_t* f = SysFileOpenR(name);
	a.is_invalid  = w.is_invalid =
	    (f->type == SYS_FILE_ERROR || (GetFileTime(f->handle, nullptr, &a.time, &w.time) == 0));
	SysFileClose(f);
}

void SysFileGetLastAccessAndWriteTimeUtc(sys_file_t& f, SysFileTimeStruct& a,
                                         SysFileTimeStruct& w) {
	if (f.type == SYS_FILE_FILE) {
		a.is_invalid = w.is_invalid = (GetFileTime(f.handle, nullptr, &a.time, &w.time) == 0);
	} else if (f.type == SYS_FILE_MEMORY_STAT || f.type == SYS_FILE_MEMORY_DYN) {
		SysTimeStruct t {};
		SysGetSystemTimeUtc(t);
		SysSystemToFileTimeUtc(t, a);
		SysSystemToFileTimeUtc(t, w);
	} else {
		a.is_invalid = w.is_invalid = true;
	}
}

bool SysFileSetLastAccessTimeUtc(const std::filesystem::path& name, SysFileTimeStruct& access) {
	if (access.is_invalid) {
		return false;
	}

	bool ok = true;

	sys_file_t* f = SysFileOpenW(name);

	ok = !(f->type == SYS_FILE_ERROR ||
	       (SetFileTime(f->handle, nullptr, &access.time, nullptr) == 0));

	SysFileClose(f);

	return ok;
}

bool SysFileSetLastWriteTimeUtc(const std::filesystem::path& name, SysFileTimeStruct& write) {
	if (write.is_invalid) {
		return false;
	}

	bool ok = true;

	sys_file_t* f = SysFileOpenW(name);

	ok = !(f->type == SYS_FILE_ERROR ||
	       (SetFileTime(f->handle, nullptr, nullptr, &write.time) == 0));

	SysFileClose(f);

	return ok;
}

bool SysFileSetLastAccessAndWriteTimeUtc(const std::filesystem::path& name,
                                         SysFileTimeStruct& access, SysFileTimeStruct& write) {
	if (access.is_invalid || write.is_invalid) {
		return false;
	}

	bool ok = true;

	sys_file_t* f = SysFileOpenW(name);

	ok = !(f->type == SYS_FILE_ERROR ||
	       (SetFileTime(f->handle, nullptr, &access.time, &write.time) == 0));

	SysFileClose(f);

	return ok;
}

void SysFileGetDents(const std::filesystem::path& path, std::vector<sys_dir_entry_t>& out) {
	const auto pattern = path / L"*";

	WIN32_FIND_DATAW data {};
	HANDLE h = FindFirstFileW(pattern.c_str(), &data);

	if (h == INVALID_HANDLE_VALUE) {
		return;
	}

	do {
		std::filesystem::path file_name(data.cFileName);

		sys_dir_entry_t r {};

		r.is_file = ((data.dwFileAttributes & static_cast<DWORD>(FILE_ATTRIBUTE_DIRECTORY)) == 0u);
		r.name    = Common::PathToString(file_name);

		out.push_back(std::move(r));

	} while (FindNextFileW(h, &data) != 0);

	FindClose(h);
}

bool SysFileCopyFile(const std::filesystem::path& src, const std::filesystem::path& dst) {
	auto src_wide = src.wstring();
	auto dst_wide = dst.wstring();
	return CopyFileW(src_wide.c_str(), dst_wide.c_str(), FALSE) != 0;
}

bool SysFileRenameFile(const std::filesystem::path& src, const std::filesystem::path& dst) {
	auto src_wide = src.wstring();
	auto dst_wide = dst.wstring();
	return MoveFileW(src_wide.c_str(), dst_wide.c_str()) != 0;
}

void SysFileRemoveReadonly(const std::filesystem::path& name) {
	auto wide = name.wstring();
	SetFileAttributesW(wide.c_str(), GetFileAttributesW(wide.c_str()) &
	                                     (~static_cast<DWORD>(FILE_ATTRIBUTE_READONLY)));
}

#endif
