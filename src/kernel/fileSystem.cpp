#include "kernel/fileSystem.h"

#include "common/archive.h"
#include "common/assert.h"
#include "common/common.h"
#include "common/dateTime.h"
#include "common/emulatorConfig.h"
#include "common/file.h"
#include "common/hash.h"
#include "common/logging/log.h"
#include "common/stringUtils.h"
#include "common/threads.h"
#include "kernel/memory.h"
#include "kernel/authInfo.h"
#include "kernel/envelopeSecureProcessor.h"
#include "kernel/eventQueue.h"
#include "kernel/execProcess.h"
#include "kernel/process.h"
#include "kernel/pthread.h"
#include "kernel/sectorBacking.h"
#include "kernel/tmpfs.h"
#include "kernel/nullfsMount.h"
#include "kernel/directoryPassthrough.h"
#include "kernel/exfatMount.h"
#include "kernel/bfsMount.h"
#include "kernel/bfsVolume.h"
#include "kernel/capturedRootMetadata.h"
#include "kernel/capturedDirectory.h"
#include "libs/errno.h"
#include "libs/hostInputShared.h"
#include "libs/libs.h"
#include "libs/network.h"
#include "graphics/presentation/videoOut.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <climits>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <mutex>
#include <thread>
#include <random>
#include <sstream>
#include <system_error>
#include <unordered_map>
#include <vector>

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#undef DeleteFile
#undef CreateDirectory
#else
#include <sys/stat.h>
#endif

namespace Libs::Posix {
int64_t KYTY_SYSV_ABI send(int s, const void* buf, uint64_t len, int flags);
int64_t KYTY_SYSV_ABI recv(int s, void* buf, uint64_t len, int flags);
int KYTY_SYSV_ABI     select(int nfds, void* readfds, void* writefds, void* exceptfds,
                             const void* timeout);
} // namespace Libs::Posix

namespace Libs::LibKernel::FileSystem {

static std::recursive_mutex g_mount_publication_mutex;


static std::string EscapeLogPath(const char* path) {
	return path != nullptr ? Log::EscapeField(path) : "(null)";
}

static std::string EscapeLogPath(const std::filesystem::path& path) {
	return Log::EscapeField(Common::PathToString(path));
}

static int ValidateMountedTraversal(const std::string& path) {
	NullfsMount::Resolution resolution;
	const int               resolved = NullfsMount::Resolve(path, &resolution);
	if (resolved != OK) return resolved;
	const auto& actual    = resolution.mounted ? resolution.path : path;
	const int   temporary = Tmpfs::ValidateTraversal(actual);
	if (temporary != OK) return temporary;
	const int exfat = ExfatMount::ValidateTraversal(actual);
	if (exfat != OK) return exfat;
	const int bfs = BfsMount::ValidateTraversal(actual);
	return bfs != OK ? bfs : DirectoryPassthrough::ValidateTraversal(actual);
}

static int ValidateNullfsTraversal(const std::string& path) {
	if (path.empty() || path[0] != '/') return OK;
	if (path == "/") return OK;
	if (path.back() != '/' && path.find("/.") == path.npos) return OK;
	bool alias      = NullfsMount::Contains(path);
	bool needs_walk = path.back() == '/';
	for (size_t start = 1; start <= path.size();) {
		const auto end  = path.find('/', start);
		const auto part = path.substr(start, end == path.npos ? path.npos : end - start);
		needs_walk |= part == "." || part == "..";
		alias |= NullfsMount::Contains(path.substr(0, end));
		if (end == path.npos) break;
		start = end + 1;
	}
	if ((!alias && !CapturedRootMetadata::Enabled() &&
	     !DirectoryPassthrough::Contains(path, true)) ||
	    !needs_walk)
		return OK;
	const auto directory = [](const std::string& name) {
		FileStat  stat {};
		const int result = KernelStat(name.c_str(), &stat);
		if (result != OK) return result;
		return (stat.st_mode & 0170000u) == 0040000u ? OK : KERNEL_ERROR_ENOTDIR;
	};
	std::string walked = "/";
	for (size_t start = 1; start <= path.size();) {
		const auto end  = path.find('/', start);
		const auto part = path.substr(start, end == path.npos ? path.npos : end - start);
		if (!part.empty()) {
			if (walked != "/") {
				const int result = directory(walked);
				if (result != OK) return result;
			}
			if (part == "..") {
				const auto slash = walked.rfind('/');
				walked.resize(slash == 0 ? 1 : slash);
			} else if (part != ".") {
				if (walked.size() > 1) walked += '/';
				walked += part;
			}
		}
		if (end == path.npos) break;
		start = end + 1;
	}
	if (path.back() == '/' || path.ends_with("/.") || path.ends_with("/.."))
		return directory(walked);
	return OK;
}

static bool SpecialFinalComponent(const std::string& path) {
	std::string_view value(path);
	while (!value.empty() && value.back() == '/')
		value.remove_suffix(1);
	const auto slash = value.rfind('/');
	if (slash != std::string_view::npos) value.remove_prefix(slash + 1);
	return value == "." || value == "..";
}

struct DevfsInstance {
	std::string point;
	// inodes of the root listing's directories, in listing order
	std::vector<uint32_t> directories;
};

static std::mutex                 g_devfs_instances_mutex;
static std::vector<DevfsInstance> g_devfs_instances;

static bool DevfsInstanceAt(const std::string& path, std::vector<uint32_t>* directories = nullptr) {
	std::string normalized;
	if (path.empty() || path[0] != '/' || Tmpfs::NormalizePath(path, &normalized) != OK)
		return false;
	std::lock_guard lock(g_devfs_instances_mutex);
	for (const auto& instance: g_devfs_instances) {
		if (instance.point != normalized) continue;
		if (directories != nullptr) *directories = instance.directories;
		return true;
	}
	return false;
}

static bool DevfsInstanceOverlaps(const std::string& normalized) {
	std::lock_guard lock(g_devfs_instances_mutex);
	return std::any_of(
	    g_devfs_instances.begin(), g_devfs_instances.end(), [&](const auto& instance) {
		    const auto& a =
		        instance.point.size() <= normalized.size() ? instance.point : normalized;
		    const auto& b =
		        instance.point.size() <= normalized.size() ? normalized : instance.point;
		    return b.starts_with(a) && (b.size() == a.size() || a == "/" || b[a.size()] == '/');
	    });
}

// every devfs mount serves the same cdev set as /dev
static void ResolveDevfsInstancePath(const char** path, std::string* storage) {
	std::lock_guard lock(g_devfs_instances_mutex);
	if (g_devfs_instances.empty()) return;
	std::string normalized;
	if (Tmpfs::NormalizePath(*path, &normalized) != OK) return;
	for (const auto& instance: g_devfs_instances) {
		const auto& point = instance.point;
		if (normalized.size() > point.size() + 1 && normalized.starts_with(point) &&
		    normalized[point.size()] == '/') {
			*storage = "/dev" + normalized.substr(point.size());
			*path    = storage->c_str();
			return;
		}
	}
}

// PSM stand-ins in MountPoints::ResolvePath expect the empty-word namespace, so the word is dropped
// only for their names
static void StripPsmSandboxWord(const char** path, std::string* storage) {
	const bool pe  = std::getenv("KYTY_DIAGNOSTIC_SONY_MSCORLIB_PE") != nullptr ||
	                 std::getenv("KYTY_DIAGNOSTIC_SONY_MANAGED_PE_DIR") != nullptr;
	const bool aot = std::getenv("KYTY_DIAGNOSTIC_PSM_NATIVE_AOT_MOUNT") != nullptr;
	if (!pe && !aot) return;
	const auto word = Process::GetExecChildSandboxWord();
	if (word.empty()) return;
	const std::string_view value(*path);
	const auto             prefix = "/" + word + "/common_ex/lib/";
	if (!value.starts_with(prefix)) return;
	const auto rest = value.substr(prefix.size());
	const bool mono = rest.starts_with("mono/2.1/") && rest.find('/', 9) == std::string_view::npos;
	if (!((pe && rest.ends_with(".dll") && (mono || rest.find('/') == std::string_view::npos)) ||
	      (aot && mono && rest.ends_with(".sprx"))))
		return;
	*storage = std::string(value.substr(word.size() + 1));
	static std::atomic_uint32_t count {0};
	if (count.fetch_add(1) < 24) {
		LOGF("FIRST_FRAME_AUDIT PSM_SANDBOX_WORD_STRIP guest=%s diagnostic=%s NON_AUTHENTIC\n",
		     Log::EscapeField(*path).c_str(), Log::EscapeField(*storage).c_str());
	}
	*path = storage->c_str();
}

static int ResolveNullfsPath(const char** path, std::string* storage,
                             uint64_t* generation = nullptr, bool* mounted = nullptr,
                             bool* read_only = nullptr) {
	if (path == nullptr || *path == nullptr || storage == nullptr) return KERNEL_ERROR_EINVAL;
	if (read_only != nullptr) *read_only = false;
	StripPsmSandboxWord(path, storage);
	if ((*path)[0] != '/') {
		if (generation != nullptr) *generation = 0;
		if (mounted != nullptr) *mounted = false;
		return OK;
	}
	const int traversal = ValidateNullfsTraversal(*path);
	if (traversal != OK) return traversal;
	NullfsMount::Resolution resolution;
	const int               result = NullfsMount::Resolve(*path, &resolution);
	if (result != OK) return result;
	if (generation != nullptr) *generation = resolution.generation;
	if (mounted != nullptr) *mounted = resolution.mounted;
	if (read_only != nullptr) *read_only = resolution.read_only;
	if (resolution.mounted) {
		*storage = std::move(resolution.path);
		*path    = storage->c_str();
	}
	ResolveDevfsInstancePath(path, storage);
	return OK;
}

// lookup() on an MNT_RDONLY mount: an existing last component fails DELETE/RENAME with EROFS and
// CREATE with EEXIST, a missing one fails CREATE with EROFS only once its parent resolves to a
// directory.
static int NullfsReadOnlyLookup(const char* path, bool create) try {
	FileStat  stat {};
	const int found = KernelStat(path, &stat);
	if (found == OK) return create ? KERNEL_ERROR_EEXIST : KERNEL_ERROR_EROFS;
	if (found != KERNEL_ERROR_ENOENT || !create) return found;
	std::string parent(path);
	while (parent.size() > 1 && parent.back() == '/')
		parent.pop_back();
	const auto slash = parent.find_last_of('/');
	if (slash == parent.npos) return KERNEL_ERROR_EROFS;
	parent.resize(slash == 0 ? 1 : slash);
	const int parent_found = KernelStat(parent.c_str(), &stat);
	if (parent_found != OK) return parent_found;
	return (stat.st_mode & 0170000u) == 0040000u ? KERNEL_ERROR_EROFS : KERNEL_ERROR_ENOTDIR;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

static int ResolveInitialWorkingDirectoryPath(const char** path, std::string* storage) try {
	if (path == nullptr || *path == nullptr || storage == nullptr) return KERNEL_ERROR_EINVAL;
	if ((*path)[0] == '/' || (*path)[0] == '\0') return OK;
	storage->assign(1, '/');
	storage->append(*path);
	*path = storage->c_str();
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

LIB_NAME("libkernel", "libkernel");

constexpr int      DESCRIPTOR_MIN = 3;
constexpr uint64_t DIR_BLOCK_SIZE = 512;

enum class SpecialFile {
	None,
	Random,
	Dipsw,
	Console,
	DeciStdin,
	DeciStdout,
	DeciStderr,
	Npdrm,
	SharedMemory,
	GcDiagnostic,
	NativeSshot,
	PipeRead,
	PipeWrite,
	NativeKqueue,
	NativeEqueueDescriptor,
	GuestSocketPair,
	NativeDce,
	NativeDmem,
	NativeMbus,
	NativeSystemMbus,
	NativeAvDevice,
	NativeAvProbe,
	NativeS3daProbe,
	NativeS3da,
	NativeMetadbg,
	NativeA53Io,
	NativeNsidCtl,
	NativeSsd,
	BfsCtl,
	Temporary,
	Devctl,
	Envelope,
	Rnps,
	Hid,
	LvdCtl,
	LvdDevice,
	M2Ctl,
};

struct LvdDevice;


// Shared by descriptor aliases. Bounded, writers block when full.

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
struct SharedGuestPipe {
	static constexpr uint32_t capacity = 1024 * 1024;
	static constexpr uint32_t magic    = 0x4b475031;
	struct Owner {
		DWORD    pid;
		uint64_t created;
		uint32_t readers;
		uint32_t writers;
	};
	struct State {
		uint32_t signature;
		uint32_t version;
		uint32_t head;
		uint32_t size;
		Owner    owners[64];
		uint8_t  bytes[capacity];
	};
	std::string name;
	HANDLE      mapping  = nullptr;
	HANDLE      mutex    = nullptr;
	HANDLE      readable = nullptr;
	HANDLE      writable = nullptr;
	State*      state    = nullptr;

	~SharedGuestPipe() {
		if (state != nullptr) {
			UnmapViewOfFile(state);
		}
		if (writable != nullptr) {
			CloseHandle(writable);
		}
		if (readable != nullptr) {
			CloseHandle(readable);
		}
		if (mutex != nullptr) {
			CloseHandle(mutex);
		}
		if (mapping != nullptr) {
			CloseHandle(mapping);
		}
	}

	static uint64_t Created(HANDLE process) {
		FILETIME start {}, end {}, kernel {}, user {};
		if (!GetProcessTimes(process, &start, &end, &kernel, &user)) {
			return 0;
		}
		return (static_cast<uint64_t>(start.dwHighDateTime) << 32) | start.dwLowDateTime;
	}

	bool Lock() {
		const auto result = WaitForSingleObject(mutex, INFINITE);
		return result == WAIT_OBJECT_0 || result == WAIT_ABANDONED;
	}

	bool Valid() const {
		return state->signature == magic && state->version == 1 && state->head < capacity &&
		       state->size <= capacity;
	}

	std::pair<uint64_t, uint64_t> Owners(bool prune) {
		uint64_t readers = 0, writers = 0;
		for (auto& owner: state->owners) {
			if (owner.pid == 0) {
				continue;
			}
			if (prune && owner.pid == GetCurrentProcessId() &&
			    owner.created != Created(GetCurrentProcess())) {
				owner = {};
				continue;
			}
			if (prune && owner.pid != GetCurrentProcessId()) {
				HANDLE process =
				    OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, owner.pid);
				bool dead = process == nullptr && GetLastError() == ERROR_INVALID_PARAMETER;
				if (process != nullptr) {
					const uint64_t created = Created(process);
					dead                   = WaitForSingleObject(process, 0) == WAIT_OBJECT_0 ||
					                         (created != 0 && created != owner.created);
					CloseHandle(process);
				}
				if (dead) {
					owner = {};
					continue;
				}
			}
			readers += owner.readers;
			writers += owner.writers;
		}
		return {readers, writers};
	}

	void Notify(uint64_t readers, uint64_t writers) {
		if (state->size != 0 || writers == 0) {
			SetEvent(readable);
		} else {
			ResetEvent(readable);
		}
		if (state->size < capacity || readers == 0) {
			SetEvent(writable);
		} else {
			ResetEvent(writable);
		}
	}

	int Reference(bool read, int delta) {
		if (!Lock()) {
			return KERNEL_ERROR_EIO;
		}
		if (!Valid()) {
			ReleaseMutex(mutex);
			return KERNEL_ERROR_EIO;
		}
		Owners(true);
		const DWORD    pid       = GetCurrentProcessId();
		const uint64_t created   = Created(GetCurrentProcess());
		Owner*         found     = nullptr;
		Owner*         available = nullptr;
		for (auto& owner: state->owners) {
			if (owner.pid == pid && owner.created == created) {
				found = &owner;
				break;
			}
			if (owner.pid == 0 && available == nullptr) {
				available = &owner;
			}
		}
		if (found == nullptr && delta > 0 && available != nullptr) {
			found          = available;
			found->pid     = pid;
			found->created = created;
		}
		if (found == nullptr) {
			ReleaseMutex(mutex);
			return delta > 0 ? KERNEL_ERROR_EMFILE : KERNEL_ERROR_EIO;
		}
		auto& count = read ? found->readers : found->writers;
		if ((delta > 0 && count == UINT32_MAX) || (delta < 0 && count == 0)) {
			ReleaseMutex(mutex);
			return KERNEL_ERROR_EIO;
		}
		if (delta > 0) {
			++count;
		} else {
			--count;
		}
		if (found->readers == 0 && found->writers == 0) {
			*found = {};
		}
		const auto [readers, writers] = Owners(false);
		Notify(readers, writers);
		ReleaseMutex(mutex);
		return OK;
	}

	static std::shared_ptr<SharedGuestPipe> Open(const std::string& name, bool create) {
		if (!name.starts_with("Local\\KytyGuestPipe.") || name.size() > 160 ||
		    name.find_first_not_of(
		        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._\\") !=
		        std::string::npos) {
			return {};
		}
		auto pipe  = std::make_shared<SharedGuestPipe>();
		pipe->name = name;
		if (create) {
			pipe->mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
			                                   sizeof(State), name.c_str());
			if (pipe->mapping == nullptr || GetLastError() == ERROR_ALREADY_EXISTS) {
				return {};
			}
			pipe->mutex    = CreateMutexA(nullptr, FALSE, (name + ".mutex").c_str());
			pipe->readable = CreateEventA(nullptr, TRUE, FALSE, (name + ".read").c_str());
			pipe->writable = CreateEventA(nullptr, TRUE, TRUE, (name + ".write").c_str());
		} else {
			pipe->mapping = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, name.c_str());
			pipe->mutex =
			    OpenMutexA(SYNCHRONIZE | MUTEX_MODIFY_STATE, FALSE, (name + ".mutex").c_str());
			pipe->readable =
			    OpenEventA(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, (name + ".read").c_str());
			pipe->writable =
			    OpenEventA(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, (name + ".write").c_str());
		}
		if (pipe->mapping == nullptr || pipe->mutex == nullptr || pipe->readable == nullptr ||
		    pipe->writable == nullptr) {
			return {};
		}
		pipe->state = static_cast<State*>(
		    MapViewOfFile(pipe->mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(State)));
		if (pipe->state == nullptr || !pipe->Lock()) {
			return {};
		}
		if (create) {
			std::memset(pipe->state, 0, sizeof(State));
			pipe->state->signature = magic;
			pipe->state->version   = 1;
			pipe->state->owners[0] = {GetCurrentProcessId(), Created(GetCurrentProcess()), 1, 1};
		}
		const bool valid = pipe->Valid();
		ReleaseMutex(pipe->mutex);
		return valid ? pipe : nullptr;
	}

	static std::shared_ptr<SharedGuestPipe> Create() {
		static std::atomic_uint64_t sequence {0};
		const auto                  name = std::string("Local\\KytyGuestPipe.") +
		                                   std::to_string(GetCurrentProcessId()) + "." +
		                                   std::to_string(Created(GetCurrentProcess())) + "." +
		                                   std::to_string(sequence.fetch_add(1));
		return Open(name, true);
	}

};
#endif

struct GuestPipe {
	std::mutex              mutex;
	std::condition_variable cv;
	std::deque<uint8_t>     data;
	uint32_t                readers = 1;
	uint32_t                writers = 1;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	std::shared_ptr<SharedGuestPipe> shared;
#endif
};

struct GuestSocketReadSource {
	explicit GuestSocketReadSource(std::shared_ptr<GuestPipe> queue): pipe(std::move(queue)) {}
	std::mutex                 mutex;
	bool                       closed = false;
	std::shared_ptr<GuestPipe> pipe;
};

struct NativeMetadbgStream {
	std::mutex              mutex;
	std::condition_variable cv;
	std::deque<uint8_t>     received;
	bool                    shutting_down = false;
};


static std::shared_ptr<NativeMetadbgStream>   g_native_metadbg_stream;
static std::shared_ptr<NativeSystemMbusState> g_native_system_mbus;

class MountPoints {
public:
	struct MountPair {
		std::filesystem::path dir;
		std::string           point;
		std::shared_ptr<Common::ArchiveReader> archive;
		bool                                   read_only = false;
	};

	MountPoints() { EXIT_NOT_IMPLEMENTED(!Common::Thread::IsMainThread()); }
	virtual ~MountPoints() = default;

	KYTY_CLASS_NO_COPY(MountPoints);

	void Mount(const std::filesystem::path& folder, const std::string& point,
	           bool read_only = false);
	bool IsReadOnly(const std::filesystem::path& path);
	bool HasReadOnlyRoot();
	bool HasNonRootMountForPath(const std::string& path);
	bool GetMountDirectory(const std::string& point, std::filesystem::path* directory);
	bool HasSubmount(const std::string& point);
	void Umount(const std::string& folder_or_point);

	[[nodiscard]] std::filesystem::path ResolvePath(const std::string& mounted_name);
	std::vector<Common::File::DirEntry> DirectoryEntries(const std::string&           mounted_name,
	                                                     const std::filesystem::path& directory);

private:
	std::vector<MountPair> m_mount_pairs;
	std::vector<std::filesystem::path> m_read_only_roots;
	Common::Mutex          m_mutex;
};

struct NativeDceLeaseIdentity {
	uint64_t generation                                      = 0;
	uint64_t host_created                                    = 0;
	uint32_t host_pid                                        = 0;
	int32_t  guest_pid                                       = 0;
	uint32_t cookie                                          = 0;
	uint32_t port                                            = 0;
	uint32_t bus                                             = 0;
	uint32_t reserved                                        = 0;
	bool     operator==(const NativeDceLeaseIdentity&) const = default;
};
static_assert(sizeof(NativeDceLeaseIdentity) == 40);

struct NativeDceScope {
#if defined(_WIN32)
	static constexpr uint64_t magic = 0x314543445954594bULL;
	struct State {
		uint64_t               magic;
		uint32_t               version;
		uint32_t               bytes;
		uint64_t               next_generation;
		uint64_t               next_cookie_sequence;
		NativeDceLeaseIdentity ports[7];
	};
	static_assert(sizeof(State) == 312);
	HANDLE mutex   = nullptr;
	HANDLE file    = INVALID_HANDLE_VALUE;
	HANDLE mapping = nullptr;
	State* state   = nullptr;
	~NativeDceScope() {
		if (state != nullptr) UnmapViewOfFile(state);
		if (mapping != nullptr) CloseHandle(mapping);
		if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
		if (mutex != nullptr) CloseHandle(mutex);
	}
	bool Lock() const {
		const DWORD waited = WaitForSingleObject(mutex, 20000);
		return waited == WAIT_OBJECT_0 || waited == WAIT_ABANDONED;
	}
	bool Valid() const {
		if (state == nullptr || state->magic != magic || state->version != 1 ||
		    state->bytes != sizeof(State) || state->next_generation == 0 ||
		    state->next_generation != state->next_cookie_sequence)
			return false;
		for (size_t i = 0; i < std::size(state->ports); ++i) {
			const auto& owner = state->ports[i];
			if (owner == NativeDceLeaseIdentity {}) continue;
			if (owner.generation == 0 || owner.host_created == 0 || owner.host_pid == 0 ||
			    owner.guest_pid <= 0 || owner.port != i || owner.bus != 0 || owner.reserved != 0 ||
			    owner.generation >= state->next_generation ||
			    owner.cookie !=
			        (static_cast<uint32_t>(owner.generation & 0x7fffffffu) ^ 0x2babcdcdu))
				return false;
		}
		return true;
	}
	bool Flush() const { return FlushViewOfFile(state, sizeof(State)) && FlushFileBuffers(file); }
	static bool CreatedAt(HANDLE process, uint64_t* created) {
		FILETIME creation {}, exit {}, kernel {}, user {};
		if (!GetProcessTimes(process, &creation, &exit, &kernel, &user)) return false;
		*created = (uint64_t {creation.dwHighDateTime} << 32) | creation.dwLowDateTime;
		return *created != 0;
	}
	static bool ProvenDead(const NativeDceLeaseIdentity& owner) {
		HANDLE process =
		    OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, owner.host_pid);
		if (process == nullptr) return GetLastError() == ERROR_INVALID_PARAMETER;
		uint64_t   created = 0;
		const bool dead    = WaitForSingleObject(process, 0) == WAIT_OBJECT_0 ||
		                     (CreatedAt(process, &created) && created != owner.host_created);
		CloseHandle(process);
		return dead;
	}
	static std::shared_ptr<NativeDceScope> Open(const std::string& scope) {
		auto              view = std::make_shared<NativeDceScope>();
		const std::string name = "Local\\kyty_ps5_" + scope + "_dce_leases_v1";
		std::error_code   error;
		const auto        temporary = std::filesystem::temp_directory_path(error);
		if (error) return nullptr;
		const auto path = temporary / ("kyty_ps5_" + scope + "_dce_leases_v1.bin");
		view->mutex     = CreateMutexA(nullptr, FALSE, (name + "_lock").c_str());
		if (view->mutex == nullptr || !view->Lock()) return nullptr;
		view->file = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
		                         FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
		                         FILE_ATTRIBUTE_NORMAL, nullptr);
		const bool created =
		    view->file != INVALID_HANDLE_VALUE && GetLastError() != ERROR_ALREADY_EXISTS;
		LARGE_INTEGER length {};
		bool valid = view->file != INVALID_HANDLE_VALUE && GetFileSizeEx(view->file, &length);
		if (valid && created) {
			length.QuadPart = sizeof(State);
			valid           = SetFilePointerEx(view->file, length, nullptr, FILE_BEGIN) &&
			                  SetEndOfFile(view->file);
		}
		if (valid && length.QuadPart == sizeof(State)) {
			view->mapping = CreateFileMappingA(view->file, nullptr, PAGE_READWRITE, 0,
			                                   sizeof(State), name.c_str());
			if (view->mapping != nullptr && created && GetLastError() == ERROR_ALREADY_EXISTS)
				valid = false;
			if (valid && view->mapping != nullptr)
				view->state = static_cast<State*>(
				    MapViewOfFile(view->mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(State)));
		}
		if (created && view->state != nullptr) {
			*view->state                      = State {};
			view->state->version              = 1;
			view->state->bytes                = sizeof(State);
			view->state->next_generation      = 1;
			view->state->next_cookie_sequence = 1;
			view->state->magic                = magic;
			valid                             = view->Flush();
		}
		valid = valid && view->Valid();
		ReleaseMutex(view->mutex);
		return valid ? view : nullptr;
	}
	int Validate(const NativeDceLeaseIdentity& identity) const {
		if (identity.generation == 0 || identity.port >= 7 || !Lock()) return KERNEL_ERROR_EIO;
		const int result = !Valid()                                  ? KERNEL_ERROR_EIO
		                   : state->ports[identity.port] == identity ? OK
		                                                             : KERNEL_ERROR_EINVAL;
		ReleaseMutex(mutex);
		return result;
	}
	int Release(const NativeDceLeaseIdentity& identity) const {
		if (identity.generation == 0 || identity.port >= 7 || !Lock()) return KERNEL_ERROR_EIO;
		int result = KERNEL_ERROR_EIO;
		if (Valid()) {
			auto& owner = state->ports[identity.port];
			result      = KERNEL_ERROR_EINVAL;
			if (owner == identity) {
				owner  = {};
				result = Flush() ? OK : KERNEL_ERROR_EIO;
				if (result != OK) {
					owner = identity;
					static_cast<void>(Flush());
					LOGF("NATIVE_DCE_SCOPE_RELEASE_PERSIST_FAILED occupied_owner_preserved=1 "
					     "generation=%" PRIu64 "\n",
					     identity.generation);
				}
			}
		}
		ReleaseMutex(mutex);
		return result;
	}
#else
	static std::shared_ptr<NativeDceScope> Open(const std::string&) { return nullptr; }
	int Release(const NativeDceLeaseIdentity&) const { return KERNEL_ERROR_ENOSYS; }
#endif
};

// devsoftc of /dev/devctl (subr_bus.c, K+0x2d58170) is one per kernel, so the single-open lease is
// shared by the whole scope
struct DevctlSoftc {
#if defined(_WIN32)
	struct State {
		uint32_t inuse;
		uint32_t nonblock;
		uint32_t async;
		int32_t  owner_guest_pid;
		uint64_t owner_host_created;
		uint32_t owner_host_pid;
		uint32_t reserved;
	};
	HANDLE mutex   = nullptr;
	HANDLE mapping = nullptr;
	State* state   = nullptr;
	~DevctlSoftc() {
		if (state != nullptr) UnmapViewOfFile(state);
		if (mapping != nullptr) CloseHandle(mapping);
		if (mutex != nullptr) CloseHandle(mutex);
	}
	static std::shared_ptr<DevctlSoftc> Open(const std::string& scope) {
		auto              softc = std::make_shared<DevctlSoftc>();
		const std::string name  = "Local\\kyty_ps5_" + scope + "_devctl_v1";
		softc->mutex            = CreateMutexA(nullptr, FALSE, (name + "_lock").c_str());
		softc->mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
		                                    sizeof(State), name.c_str());
		if (softc->mutex == nullptr || softc->mapping == nullptr) return nullptr;
		softc->state = static_cast<State*>(
		    MapViewOfFile(softc->mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(State)));
		return softc->state != nullptr ? softc : nullptr;
	}
	bool Lock() const {
		const DWORD waited = WaitForSingleObject(mutex, 20000);
		return waited == WAIT_OBJECT_0 || waited == WAIT_ABANDONED;
	}
	// devopen ignores the open flags, so O_NONBLOCK at open does not set nonblock.
	int Acquire(int guest_pid) {
		uint64_t created = 0;
		if (!NativeDceScope::CreatedAt(GetCurrentProcess(), &created) || !Lock())
			return KERNEL_ERROR_EIO;
		int result = OK;
		if (state->inuse != 0) {
			NativeDceLeaseIdentity owner;
			owner.host_created = state->owner_host_created;
			owner.host_pid     = state->owner_host_pid;
			if (!NativeDceScope::ProvenDead(owner)) {
				LOGF("DEVCTL_OPEN_BUSY guest_pid=%d owner_pid=%d\n", guest_pid,
				     state->owner_guest_pid);
				result = KERNEL_ERROR_EBUSY;
			} else {
				LOGF("DEVCTL_OWNER_DEAD_RELEASE owner_pid=%d\n", state->owner_guest_pid);
				state->nonblock = 0;
				state->async    = 0;
			}
		}
		if (result == OK) {
			state->inuse              = 1;
			state->owner_guest_pid    = guest_pid;
			state->owner_host_created = created;
			state->owner_host_pid     = GetCurrentProcessId();
		}
		ReleaseMutex(mutex);
		return result;
	}
	void Close() {
		if (!Lock()) return;
		if (state->inuse != 0 && state->owner_host_pid == GetCurrentProcessId()) *state = State {};
		ReleaseMutex(mutex);
	}
	int Nonblock() const {
		if (!Lock()) return -1;
		const int nonblock = state->nonblock != 0 ? 1 : 0;
		ReleaseMutex(mutex);
		return nonblock;
	}
	bool Set(bool nonblock, bool on) {
		if (!Lock()) return false;
		(nonblock ? state->nonblock : state->async) = on ? 1 : 0;
		ReleaseMutex(mutex);
		return true;
	}
#else
	static std::shared_ptr<DevctlSoftc> Open(const std::string&) { return nullptr; }
	int                                 Acquire(int) { return KERNEL_ERROR_ENOSYS; }
	void                                Close() {}
	int                                 Nonblock() const { return -1; }
	bool                                Set(bool, bool) { return false; }
#endif
};




static bool EnvelopeDigestMatches(std::span<const uint8_t> plaintext, const uint8_t* expected) {
	const auto digest    = AuthInfo::Sha256(plaintext.data(), plaintext.size());
	uint8_t    different = 0;
	for (size_t i = 0; i < digest.size(); i++)
		different |= digest[i] ^ expected[i];
	return different == 0;
}



struct NativeDceEnvelope;

struct NativeDceClient {
	Common::Mutex                             mutex;
	int                                       pid    = 0;
	uint32_t                                  port   = 0;
	uint32_t                                  bus    = 0;
	uint32_t                                  cookie = 0;
	std::shared_ptr<NativeDceScope>           scope;
	NativeDceLeaseIdentity                    lease;
	void*                                     shared             = nullptr;
	uint64_t                                  memory_token       = 0;
	bool                                      live               = true;
	int                                       display_handle     = -1;
	uint64_t                                  display_generation = 0;
	bool                                      attributes         = false;
	std::array<uint64_t, 4>                   buffers {};
	bool                                      has_flip_sequence  = false;
	uint64_t                                  last_flip_sequence = 0;
	std::vector<std::pair<int64_t, uint64_t>> flip_events;
	int                                       Ioctl(const NativeDceEnvelope& envelope);
	int                                       Close() {
		Common::LockGuard lock(mutex);
		if (live) {
			live = false;
			for (const auto& [queue, ident]: flip_events) {
				const int rc = EventQueue::KernelDeleteEvent(queue, ident,
				                                             EventQueue::KERNEL_EVFILT_VIDEO_OUT);
				if (rc != OK && rc != KERNEL_ERROR_EBADF && rc != KERNEL_ERROR_ENOENT)
					LOGF("NATIVE_DCE_CLIENT_EVENT_REMOVE_FAILED cookie=0x%x result=0x%x\n", cookie,
					     rc);
			}
			flip_events.clear();
			VideoOut::VideoOutNativeReleaseClientHandle(&display_handle, display_generation);
			if (shared != nullptr && memory_token != 0) {
				const int rc = Memory::UnmapOwnedFlexibleMemory(reinterpret_cast<uint64_t>(shared),
				                                                0x4000, memory_token);
				if (rc != OK && rc != KERNEL_ERROR_ENOENT)
					LOGF("NATIVE_DCE_CLIENT_UNMAP_FAILED cookie=0x%x result=0x%x\n", cookie, rc);
			}
			shared       = nullptr;
			memory_token = 0;
		}
		if (scope != nullptr && lease.generation != 0) {
			const int rc = scope->Release(lease);
			if (rc != OK) {
				LOGF("NATIVE_DCE_SCOPE_RELEASE_PRESERVED cookie=0x%x generation=%" PRIu64
				     " result=0x%x retryable=1\n",
				     cookie, lease.generation, rc);
				return rc;
			}
			lease = {};
		}
		return OK;
	}

	~NativeDceClient() { static_cast<void>(Close()); }
};

static std::mutex g_native_dce_client_mutex;
static uint64_t g_native_dce_client_sequence = 1;


struct File {
	Common::File                        f;
	std::string                         name;
	std::filesystem::path               real_name;
	std::atomic_bool                    opened;
	std::atomic_bool                    directory;
	std::atomic_bool                    readable;
	std::atomic_bool                    writable;
	std::atomic_bool                    append;
	std::atomic_bool                    sync_writes;
	SpecialFile                         special;
	int                                            descriptor_flags = 0;
	uint64_t                                       special_size;
	int                                            scope_shared;
	bool                                           shared_mapped;
	Common::Mutex                       mutex;
	std::vector<uint8_t>                dirents;
	uint64_t                            dents_offset;
	std::shared_ptr<GuestPipe>                     pipe;
	std::shared_ptr<Memory::AnonymousSharedMemory> anonymous_shared;
	std::shared_ptr<GuestPipe>                     socket_send;
	std::shared_ptr<GuestSocketReadSource>         socket_read_source;
	std::shared_ptr<SectorBacking>                 sector_backing;
	std::shared_ptr<Tmpfs::Handle>                 tmpfs;
	std::shared_ptr<ExfatMount::Handle>            exfat;
	std::shared_ptr<BfsMount::Handle>              bfs;
	std::shared_ptr<DirectoryPassthrough::Handle>  passthrough;
	std::shared_ptr<LvdDevice>                     lvd;
	int32_t                                        hid_next_pad_handle   = 1;
	uint32_t                                       hid_unknown_log_count = 0;
	bool                                           data_topology          = false;
	bool                                           devfs_root             = false;
	uint64_t                                       sector_position        = 0;
	bool                                           iccnvs4_snapshot       = false;
	uint64_t                                       iccnvs4_snapshot_bytes = 0;
	std::shared_ptr<SectorBacking>                 iccnvs4_backing;
	int                                            native_dce_display_handle                = -1;
	uint64_t                                       native_dce_display_generation            = 0;
	uint32_t                                       native_dce_display_id                    = 0;
	bool                                           native_dce_display_id_set                = false;
	bool                                           native_dce_original_videoout_client_open = false;
	uint64_t                                       native_dce_original_videoout_resource    = 0;
	uint64_t                                       native_dce_buffers[4] {};
	uint64_t                                       native_scanin_buffers[72] {};
	uint64_t                                       native_scanin_base       = 0;
	uint64_t                                       native_scanin_length     = 0;
	bool                                           native_scanin_registered = false;
	int                                            native_sshot_owner_pid   = 0;
	bool                                           native_sshot_active      = false;
	uint64_t                                       native_sshot_region      = 0;
	uint32_t                                       native_sshot_size        = 0;
	uint32_t                                       native_sshot_block_size  = 0;
	uint32_t                                       native_sshot_value       = 0;
};

class FileDescriptors {
public:
	explicit FileDescriptors(bool child = false): m_explicit_standard(child) {
		EXIT_NOT_IMPLEMENTED(!child && !Common::Thread::IsMainThread());
	}
	virtual ~FileDescriptors() { CloseAll(); }

	KYTY_CLASS_NO_COPY(FileDescriptors);

	int   CreateDescriptor();
	bool  OpenStandardDeci(int fd);
	int   OpenStandardConsole(int flags);
	bool  HasStandardConsole(int fd);
	void  BindStandardConsole(int fd);
	bool  HasStandardDeci(int fd);
	bool  CloseStandardDeci(int fd);
	void  DeleteDescriptor(int d);
	File* GetFile(int d);
	File* GetFile(const std::filesystem::path& real_name);
	void  CloseAll();
	int  GetFlags(int fd);
	int  SetFlags(int fd, int flags);
	int  Export(std::string* manifest);
	int  Import(const std::string& manifest);
	bool HasExplicitStandardTable() const { return m_explicit_standard; }

private:
	std::vector<File*> m_files;
	std::array<bool, 3>                                m_standard_deci {};
	std::array<bool, 3>                                m_standard_console {};
	std::array<int, 3>                                 m_standard_flags {};
	bool                                               m_explicit_standard = false;
	Common::Mutex      m_mutex;
};

static MountPoints*     g_mount_points = nullptr;
static int              g_tmpfs_status = KERNEL_ERROR_ENOSYS;
// ShellCore mkdirs nobackup/temp 0777 with no chmod and it ends up 040777, so umask 0
static std::atomic<int>                                                    g_creation_mask {0};
static std::mutex                                                          g_sector_payload_mutex;
static std::vector<std::pair<std::string, std::shared_ptr<SectorBacking>>> g_sector_payloads;
static std::mutex g_passthrough_registration_mutex;
struct PassthroughRegistration {
	std::string           device;
	std::filesystem::path supplied_root;
	std::filesystem::path root;
	std::string           identity;
};
struct PublishedReadOnlyProvider {
	std::string device;
	std::string point;
};
static std::vector<PassthroughRegistration>   g_passthrough_registrations;
static std::vector<PublishedReadOnlyProvider> g_published_read_only_providers;

struct LvdDevice {
	int                                           unit        = -1;
	int                                           owner_pid   = 0;
	uint32_t                                      sector_size = 0;
	uint32_t                                      granularity = 0;
	uint64_t                                      capacity    = 0;
	std::string                                   image_path;
	std::shared_ptr<DirectoryPassthrough::Handle> backing;
};

static std::mutex                                          g_lvd_mutex;
static std::unordered_map<int, std::shared_ptr<LvdDevice>> g_lvd_devices;

// Env-gated A53/NAND controller stand-in for mini-syscore cold storage init:
//   open /dev/a53io O_RDONLY, NAND-init ioctl 0x80046101 (bit 0x10000 selects force-format), close;
//   open /dev/nsid1.ctl O_RDWR, namespace-create ioctl 0x20003102 (no payload);
//   reopen /dev/ssd0 until present;
//   open /dev/a53io again, A53-enable ioctl 0x80046103 (payload ignored by the driver), close;
//   open /dev/ssd0, partition-geometry ioctls 0x40086481 (u64 whole-media capacity) and 0x40043105
//   (u32 is-nand-for-T).
// Media state outlives the descriptors (NAND fd closes at 0x426402, enable fd at 0x402023).
// /dev/ssd0 only opens once the namespace exists.
struct A53StorageController {
	std::mutex mutex;
	bool       nand_initialized  = false;
	bool       namespace_present = false;
	bool       a53_enabled       = false;
};
static A53StorageController g_a53_controller;

// 0x40086481 whole-media capacity. Minus the 0x4c9710 partition sum (0xab15c0000) this leaves the
// user partition.
static constexpr uint64_t A53_WHOLE_MEDIA_CAPACITY = 681405841408ull;
static constexpr uint64_t A53_BD_RVLIST_CAPACITY   = 0x100000ull;
static constexpr uint64_t A53_SWAP_CAPACITY        = 0x200000000ull;
static constexpr uint64_t A53_SWAPX0_CAPACITY      = 0x1fff00000ull;
static constexpr uint64_t A53_SWAPX1_CAPACITY      = 0x7fe00ull;
static constexpr uint64_t A53_SWAPX2_CAPACITY      = 0x80000ull;
// partition sizes from mini-syscore table 0x4c9710, standard variant; sub_428BD0 returns EINVAL on
// a mismatch
static constexpr uint64_t A53_SYSTEM_CAPACITY      = 0x28000000ull;
static constexpr uint64_t A53_SYSTEM_EX_CAPACITY   = 0x60000000ull;
static constexpr uint64_t A53_PREINST_CAPACITY     = 0x9400000ull;
static constexpr uint64_t A53_APP_TEMP0_CAPACITY   = 0x40000000ull;
static constexpr uint64_t A53_SYSTEM_DATA_CAPACITY = 0x200000000ull;
static constexpr uint64_t A53_UPDATE_CAPACITY      = 0x100000000ull;
static constexpr uint64_t A53_APP_SWAP_CAPACITY    = 0x380000000ull;
static constexpr uint64_t A53_HIBERNATION_CAPACITY = 0xd8000000ull;
static constexpr uint64_t A53_USER_CAPACITY        = A53_WHOLE_MEDIA_CAPACITY - 0xab15c0000ull;

static bool A53StorageEnabled() {
	return std::getenv("KYTY_DIAGNOSTIC_A53_STORAGE") != nullptr;
}

static bool IsA53SsdDevice(const std::string& path) {
	return path == "/dev/ssd0" || path == "/dev/ssd0.preinst" || path == "/dev/ssd0.system" ||
	       path == "/dev/ssd0.system_b" || path == "/dev/ssd0.system_ex" ||
	       path == "/dev/ssd0.system_ex_b" || path == "/dev/ssd0.swap" ||
	       path == "/dev/ssd0.system_data" || path == "/dev/ssd0.update" ||
	       path == "/dev/ssd0.user" || path == "/dev/ssd0.app_temp0" ||
	       path == "/dev/ssd0.app_swap" || path == "/dev/ssd0.hibernation" ||
	       path == "/dev/ssd0.bd_rvlist" || path == "/dev/ssd0.swapx0" ||
	       path == "/dev/ssd0.swapx1" || path == "/dev/ssd0.swapx2";
}

int RegisterDiagnosticSectorPayload(const std::string&             device,
                                    std::shared_ptr<SectorBacking> backing) {
	if (!backing || (device != "/dev/ssd0.system" && device != "/dev/ssd0.system_b" &&
	                 device != "/dev/ssd0.system_ex" && device != "/dev/ssd0.system_ex_b" &&
	                 device != "/dev/ssd0.user"))
		return KERNEL_ERROR_EINVAL;
	std::lock_guard lock(g_sector_payload_mutex);
	for (const auto& entry: g_sector_payloads)
		if (entry.first == device) return KERNEL_ERROR_EEXIST;
	g_sector_payloads.emplace_back(device, std::move(backing));
	LOGF("STORAGE_PAYLOAD_REGISTERED device=%s\n", device.c_str());
	return OK;
}

static std::shared_ptr<SectorBacking> FindSectorPayload(const std::string& device) {
	const auto name = Common::PathToGenericString(
	    Common::PathFromUtf8(Common::FixFilenameSlash(device)).lexically_normal());
	std::lock_guard lock(g_sector_payload_mutex);
	for (const auto& entry: g_sector_payloads)
		if (entry.first == name) return entry.second;
	return {};
}

static void FillSectorPayloadStat(FileStat* stat) {
	*stat            = {};
	stat->st_mode    = 0020640u;
	stat->st_nlink   = 1;
	stat->st_blksize = 16384u;
}

static FileDescriptors*              g_primary_files        = nullptr;
static thread_local FileDescriptors* g_guest_files_override = nullptr;

struct ActiveDescriptorDispatch {
	FileDescriptors* operator->() const {
		return g_guest_files_override ? g_guest_files_override : g_primary_files;
	}
	operator FileDescriptors*() const {
		return g_guest_files_override ? g_guest_files_override : g_primary_files;
	}
	ActiveDescriptorDispatch& operator=(FileDescriptors* table) {
		g_primary_files = table;
		return *this;
	}
};
static ActiveDescriptorDispatch g_files {};

ScopedGuestDescriptorTable::ScopedGuestDescriptorTable() {
	previous               = g_guest_files_override;
	owned                  = new FileDescriptors(true);
	g_guest_files_override = owned;
}
ScopedGuestDescriptorTable::~ScopedGuestDescriptorTable() {
	owned->CloseAll();
	g_guest_files_override = previous;
	delete owned;
}
static std::mutex                 g_standard_pipe_mutex;
static std::shared_ptr<GuestPipe> g_standard_pipes[3];
static SpecialFile                g_standard_pipe_types[3] {};

static int ReferenceGuestPipe(const std::shared_ptr<GuestPipe>& pipe, bool read, int delta) {
	if (!pipe) {
		return KERNEL_ERROR_EBADF;
	}
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (pipe->shared) {
		return pipe->shared->Reference(read, delta);
	}
#endif
	std::lock_guard lock(pipe->mutex);
	auto&           count = read ? pipe->readers : pipe->writers;
	if ((delta > 0 && count == UINT32_MAX) || (delta < 0 && count == 0)) {
		return KERNEL_ERROR_EIO;
	}
	if (delta > 0) {
		++count;
	} else {
		--count;
	}
	pipe->cv.notify_all();
	return OK;
}




static std::atomic_bool g_diagnostic_gc_device_ready = false;
static Common::Mutex    g_hmd_shm_mutex;
static bool             g_hmd_shm_exists = false;
static constexpr char   HMD_SHM_PATH[]   = "/tmp/SceHmd/Vr2d_shm_pass";

static bool IsRandomDevice(const std::string& path) {
	return path == "/dev/random" || path == "/dev/urandom";
}

static bool IsDipswDevice(const std::string& path) {
	return path == "/dev/dipsw";
}

static bool IsConsoleDevice(const std::string& path) {
	return path == "/dev/console";
}

static bool IsNpdrmDevice(const std::string& path) {
	return path == "/dev/npdrm";
}

static void FillRandomBuffer(void* buf, size_t nbytes) {
	auto*              out = reinterpret_cast<uint8_t*>(buf);
	std::random_device random;

	for (size_t i = 0; i < nbytes; i++) {
		out[i] = static_cast<uint8_t>(random());
	}
}

static void SecToTimespec(KernelTimespec* ts, double sec) {
	ts->tv_sec  = static_cast<int64_t>(sec);
	ts->tv_nsec = static_cast<int64_t>((sec - static_cast<double>(ts->tv_sec)) * 1000000000.0);
}

static uint64_t AlignDown(uint64_t value, uint64_t alignment) {
	return (alignment != 0 ? value & ~(alignment - 1) : value);
}

static uint64_t AlignUp(uint64_t value, uint64_t alignment) {
	return (alignment != 0 ? (value + alignment - 1) & ~(alignment - 1) : value);
}

static std::vector<uint8_t> PackDirents(const std::vector<Common::File::DirEntry>& entries) {
	std::vector<uint8_t> dirents;
	uint64_t             offset             = 0;
	uint64_t             last_reclen_offset = 0;
	for (const auto& entry: entries) {
		const auto& name = entry.name;
		EXIT_NOT_IMPLEMENTED(name.size() > 255);
		const auto reclen = AlignUp(8 + name.size() + 1, 4);
		if (offset + reclen > dirents.size()) {
			if (!dirents.empty()) {
				auto* last_reclen =
				    reinterpret_cast<uint16_t*>(dirents.data() + last_reclen_offset);
				*last_reclen += static_cast<uint16_t>(dirents.size() - offset);
			}
			offset = dirents.size();
			dirents.resize(offset + DIR_BLOCK_SIZE);
		}
		*reinterpret_cast<uint32_t*>(dirents.data() + offset) =
		    Common::hash(name.data(), static_cast<uint32_t>(name.size()));
		*reinterpret_cast<uint16_t*>(dirents.data() + offset + 4) = static_cast<uint16_t>(reclen);
		dirents[offset + 6]                                       = entry.is_file ? 8 : 4;
		dirents[offset + 7] = static_cast<uint8_t>(name.size());
		memcpy(dirents.data() + offset + 8, name.c_str(), name.size() + 1);
		last_reclen_offset = offset + 4;
		offset += reclen;
	}
	if (!dirents.empty()) {
		auto* last_reclen = reinterpret_cast<uint16_t*>(dirents.data() + last_reclen_offset);
		*last_reclen += static_cast<uint16_t>(dirents.size() - offset);
	}
	return dirents;
}

static int RefreshTmpfsDirectory(File* file) {
	std::vector<Tmpfs::DirectoryEntry> entries;
	const int                          result = Tmpfs::Entries(file->tmpfs, &entries);
	if (result != OK) return result;
	std::vector<Common::File::DirEntry> directory;
	directory.reserve(entries.size());
	for (const auto& entry: entries) {
		Common::File::DirEntry value {};
		value.name    = entry.name;
		value.is_file = entry.type == 8;
		directory.push_back(std::move(value));
	}
	auto   packed = PackDirents(directory);
	size_t offset = 0;
	for (const auto& entry: entries) {
		const auto inode = static_cast<uint32_t>(entry.inode);
		std::memcpy(packed.data() + offset, &inode, sizeof(inode));
		packed[offset + 6] = entry.type;
		uint16_t length    = 0;
		std::memcpy(&length, packed.data() + offset + 4, sizeof(length));
		offset += length;
	}
	file->dirents = std::move(packed);
	return OK;
}

static int RefreshPassthroughDirectory(File* file) {
	std::vector<DirectoryPassthrough::DirectoryEntry> entries;
	const int result = DirectoryPassthrough::Entries(file->passthrough, &entries);
	if (result != OK) return result;
	std::vector<Common::File::DirEntry> directory;
	for (const auto& entry: entries)
		directory.push_back({entry.name, !entry.directory});
	auto   packed = PackDirents(directory);
	size_t offset = 0;
	for (const auto& entry: entries) {
		std::memcpy(packed.data() + offset, &entry.inode, sizeof(entry.inode));
		if (entry.type) packed[offset + 6] = entry.type;
		uint16_t length = 0;
		std::memcpy(&length, packed.data() + offset + 4, sizeof(length));
		offset += length;
	}
	file->dirents = std::move(packed);
	return OK;
}

static int RefreshExfatDirectory(File* file) {
	std::vector<ExfatMount::DirectoryEntry> entries;
	const int                               result = ExfatMount::Entries(file->exfat, &entries);
	if (result != OK) return result;
	std::vector<Common::File::DirEntry> directory;
	for (const auto& entry: entries)
		directory.push_back({entry.name, !entry.directory});
	auto   packed = PackDirents(directory);
	size_t offset = 0;
	for (const auto& entry: entries) {
		std::memcpy(packed.data() + offset, &entry.inode, sizeof(entry.inode));
		uint16_t length = 0;
		std::memcpy(&length, packed.data() + offset + 4, sizeof(length));
		offset += length;
	}
	file->dirents = std::move(packed);
	return OK;
}

static int RefreshBfsDirectory(File* file) {
	std::vector<BfsMount::DirectoryEntry> entries;
	const int                             result = BfsMount::Entries(file->bfs, &entries);
	if (result != OK) return result;
	std::vector<Common::File::DirEntry> directory;
	for (const auto& entry: entries)
		directory.push_back({entry.name, !entry.directory});
	auto   packed = PackDirents(directory);
	size_t offset = 0;
	for (const auto& entry: entries) {
		std::memcpy(packed.data() + offset, &entry.inode, sizeof(entry.inode));
		uint16_t length = 0;
		std::memcpy(&length, packed.data() + offset + 4, sizeof(length));
		offset += length;
	}
	file->dirents = std::move(packed);
	return OK;
}

static uint64_t ReadDirectory(File* file, void* buf, uint64_t count) {
	const auto remaining =
	    file->dents_offset < file->dirents.size() ? file->dirents.size() - file->dents_offset : 0;
	const auto bytes = std::min(count, remaining);
	if (bytes != 0) {
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(buf), bytes);
		memcpy(buf, file->dirents.data() + file->dents_offset, bytes);
		file->dents_offset += bytes;
	}
	return bytes;
}

static int PosixToKernel(int posix_errno) {
	return KERNEL_ERROR_UNKNOWN + posix_errno;
}

int FileDescriptors::CreateDescriptor() {
	Common::LockGuard lock(m_mutex);

	auto* file        = new File {};
	file->opened      = false;
	file->directory   = false;
	file->readable    = false;
	file->writable    = false;
	file->append      = false;
	file->sync_writes = false;
	file->special     = SpecialFile::None;
	file->special_size = 0;
	file->scope_shared = -1;

	int files_num = static_cast<int>(m_files.size());
	for (int index = 0; index < files_num; index++) {
		if (m_files[index] == nullptr) {
			m_files[index] = file;
			return index + DESCRIPTOR_MIN;
		}
	}

	m_files.push_back(file);
	return static_cast<int>(m_files.size()) + DESCRIPTOR_MIN - 1;
}

bool FileDescriptors::OpenStandardDeci(int fd) {
	if (fd < 0 || fd > 2) {
		return false;
	}
	Common::LockGuard lock(m_mutex);
	if (m_standard_deci[fd]) {
		return false;
	}
	m_standard_deci[fd]    = true;
	m_standard_console[fd] = false;
	m_standard_flags[fd]   = 0;
	return true;
}

bool FileDescriptors::HasStandardDeci(int fd) {
	if (fd < 0 || fd > 2) {
		return false;
	}
	Common::LockGuard lock(m_mutex);
	return m_standard_deci[fd];
}

int FileDescriptors::OpenStandardConsole(int flags) {
	Common::LockGuard lock(m_mutex);
	for (int fd = 0; fd < DESCRIPTOR_MIN; ++fd) {
		if (m_standard_deci[fd]) continue;
		m_standard_deci[fd]    = true;
		m_standard_console[fd] = true;
		m_standard_flags[fd]   = flags;
		return fd;
	}
	return -1;
}

bool FileDescriptors::HasStandardConsole(int fd) {
	if (fd < 0 || fd >= DESCRIPTOR_MIN) return false;
	Common::LockGuard lock(m_mutex);
	return m_standard_deci[fd] && m_standard_console[fd];
}

void FileDescriptors::BindStandardConsole(int fd) {
	Common::LockGuard lock(m_mutex);
	m_standard_deci[fd]    = true;
	m_standard_console[fd] = true;
	m_standard_flags[fd]   = 0;
}

bool FileDescriptors::CloseStandardDeci(int fd) {
	if (fd < 0 || fd > 2) {
		return false;
	}
	Common::LockGuard lock(m_mutex);
	if (!m_standard_deci[fd]) {
		return false;
	}
	m_standard_deci[fd]    = false;
	m_standard_console[fd] = false;
	m_standard_flags[fd]   = 0;
	return true;
}








static bool NativeDceReadable(uint64_t addr, uint64_t size, bool need_write);

static bool GuestSocketBufferAccessible(const void* buf, uint64_t len, bool writable) {
	if (len == 0) {
		return true;
	}
	const auto address = reinterpret_cast<uint64_t>(buf);
	if (address == 0 || len > UINT64_MAX - address) {
		return false;
	}
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	return NativeDceReadable(address, len, writable);
#else
	const uint64_t end = address + len;
	for (uint64_t current = address; current < end;) {
		Memory::VirtualQueryInfo region {};
		if (Memory::KernelVirtualQuery(reinterpret_cast<const void*>(current), 0, &region,
		                               sizeof(region)) != OK ||
		    !region.is_committed || region.start > current || region.end <= current ||
		    (region.protection & (writable ? 2 : 1)) == 0) {
			return false;
		}
		current = std::min<uint64_t>(region.end, end);
	}
	return true;
#endif
}

struct LvdAttachRequest {
	uint32_t version;
	int32_t  unit;
	uint32_t sector_size;
	uint32_t granularity;
	uint16_t flags;
	uint16_t image_type;
	uint32_t layer_count;
	uint64_t device_size;
	uint64_t layers;
};
static_assert(sizeof(LvdAttachRequest) == 0x28);
static_assert(offsetof(LvdAttachRequest, unit) == 0x04);
static_assert(offsetof(LvdAttachRequest, layers) == 0x20);

struct LvdLayer {
	uint16_t source_type;
	uint16_t flags;
	uint32_t reserved;
	uint64_t path;
	uint64_t offset;
	uint64_t end;
	uint64_t bitmap_path;
	uint64_t bitmap_offset;
	uint64_t bitmap_size;
};
static_assert(sizeof(LvdLayer) == 0x38);

static bool ParseLvdDevicePath(const std::string& path, int* unit) {
	constexpr const char* prefix = "/dev/lvd";
	if (!path.starts_with(prefix) || path.size() == std::strlen(prefix)) return false;
	int value = 0;
	for (size_t i = std::strlen(prefix); i < path.size(); ++i) {
		if (path[i] < '0' || path[i] > '9' || value > 25) return false;
		value = value * 10 + path[i] - '0';
	}
	if (value > 255) return false;
	if (path != std::string(prefix) + std::to_string(value)) return false;
	if (unit != nullptr) *unit = value;
	return true;
}

static std::shared_ptr<LvdDevice> FindLvdDevice(int unit) {
	std::lock_guard lock(g_lvd_mutex);
	const auto      found = g_lvd_devices.find(unit);
	return found == g_lvd_devices.end() ? nullptr : found->second;
}

static std::shared_ptr<LvdDevice> FindLvdDevice(const std::string& path) {
	int unit = -1;
	return ParseLvdDevicePath(path, &unit) ? FindLvdDevice(unit) : nullptr;
}

static void FillLvdStat(FileStat* stat, bool block_device) {
	*stat            = {};
	stat->st_mode    = block_device ? 0060600u : 0020600u;
	stat->st_nlink   = 1;
	stat->st_blksize = 0x4000;
}

static void LogLvdAttach(const LvdDevice& device, const std::string& image) noexcept {
	try {
		LOGF("LVD_ATTACH guest_pid=%d unit=%d image=%s capacity=0x%016" PRIx64
		     " sector=0x%x granularity=0x%x layers=1 retained_backing=1\n",
		     device.owner_pid, device.unit, image.c_str(), device.capacity, device.sector_size,
		     device.granularity);
	} catch (...) {
	}
}

static void LogLvdDetach(int guest_pid, int owner_pid, int unit) noexcept {
	try {
		LOGF("LVD_DETACH guest_pid=%d creator_pid=%d unit=%d namespace_removed=1 "
		     "open_descriptors_retain_backing=1\n",
		     guest_pid, owner_pid, unit);
	} catch (...) {
	}
}

static int CopyLvdGuestPath(uint64_t address, std::string* path) try {
	if (address == 0 || path == nullptr) return KERNEL_ERROR_EFAULT;
	std::array<char, 0x400> bytes {};
	for (size_t i = 0; i < bytes.size(); ++i) {
		if (!Memory::CopyFromGuest(&bytes[i], reinterpret_cast<const void*>(address + i), 1)) {
			return KERNEL_ERROR_EFAULT;
		}
		if (bytes[i] == '\0') {
			if (i == 0 || bytes[0] != '/') return KERNEL_ERROR_EINVAL;
			path->assign(bytes.data(), i);
			return OK;
		}
	}
	return KERNEL_ERROR_ENAMETOOLONG;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

static int64_t TransferLvd(const std::shared_ptr<LvdDevice>& device, void* bytes, size_t length,
                           uint64_t offset, bool write) try {
	if (!device || !device->backing) return KERNEL_ERROR_ENXIO;
	if (offset > device->capacity) return KERNEL_ERROR_EINVAL;
	if (length == 0) return 0;
	if (!GuestSocketBufferAccessible(bytes, length, !write)) return KERNEL_ERROR_EFAULT;
	const uint64_t remaining = device->capacity - offset;
	if (write && length > remaining) return KERNEL_ERROR_ENOSPC;
	const size_t requested = static_cast<size_t>(std::min<uint64_t>(length, remaining));
	if (requested == 0) return 0;
	std::vector<uint8_t> chunk(std::min<size_t>(requested, 1024 * 1024));
	size_t               transferred = 0;
	while (transferred < requested) {
		const size_t count  = std::min(chunk.size(), requested - transferred);
		int64_t      actual = 0;
		if (write) {
			if (!Memory::CopyFromGuest(chunk.data(),
			                           static_cast<const uint8_t*>(bytes) + transferred, count)) {
				return KERNEL_ERROR_EFAULT;
			}
			actual = DirectoryPassthrough::Pwrite(device->backing, chunk.data(), count,
			                                      offset + transferred);
		} else {
			actual = DirectoryPassthrough::Pread(device->backing, chunk.data(), count,
			                                     offset + transferred);
			if (actual > 0 && !Memory::CopyToGuest(static_cast<uint8_t*>(bytes) + transferred,
			                                       chunk.data(), static_cast<size_t>(actual))) {
				return KERNEL_ERROR_EFAULT;
			}
		}
		if (actual < 0) return transferred == 0 ? actual : static_cast<int64_t>(transferred);
		transferred += static_cast<size_t>(actual);
		if (static_cast<size_t>(actual) != count) break;
	}
	return static_cast<int64_t>(transferred);
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

static int AttachLvd(void* arg) try {
	LvdAttachRequest request {};
	if (!Memory::CopyFromGuest(&request, arg, sizeof(request)) ||
	    !GuestSocketBufferAccessible(static_cast<uint8_t*>(arg) + offsetof(LvdAttachRequest, unit),
	                                 sizeof(request.unit), true)) {
		return KERNEL_ERROR_EFAULT;
	}
	if (request.version != 0 || request.unit != 0 || request.sector_size != 0x200 ||
	    request.granularity != 0x10000 || request.flags != 0x14 || request.image_type != 0 ||
	    request.layer_count != 1 || request.device_size == 0 ||
	    request.device_size > static_cast<uint64_t>(INT64_MAX) ||
	    request.device_size % request.sector_size != 0 || request.layers == 0) {
		return KERNEL_ERROR_EINVAL;
	}
	LvdLayer layer {};
	if (!Memory::CopyFromGuest(&layer, reinterpret_cast<const void*>(request.layers),
	                           sizeof(layer))) {
		return KERNEL_ERROR_EFAULT;
	}
	if (layer.source_type != 1 || layer.flags != 1 || layer.reserved != 0 || layer.path == 0 ||
	    layer.offset != 0 || layer.end != request.device_size || layer.bitmap_path != 0 ||
	    layer.bitmap_offset != 0 || layer.bitmap_size != 0) {
		return KERNEL_ERROR_EINVAL;
	}
	std::string image_path;
	const int   copied = CopyLvdGuestPath(layer.path, &image_path);
	if (copied != OK) return copied;
	if (!DirectoryPassthrough::Contains(image_path)) return KERNEL_ERROR_ENOTSUP;
	std::shared_ptr<DirectoryPassthrough::Handle> backing;
	int result = DirectoryPassthrough::Open(image_path, 2, &backing);
	if (result != OK) return result;
	DirectoryPassthrough::NodeStat stat {};
	result = DirectoryPassthrough::Fstat(backing, &stat);
	if (result != OK) return result;
	if ((stat.mode & 0170000u) != 0100000u || stat.size < request.device_size)
		return KERNEL_ERROR_EINVAL;

	auto device             = std::make_shared<LvdDevice>();
	device->owner_pid       = Process::GetPid();
	device->sector_size     = request.sector_size;
	device->granularity     = request.granularity;
	device->capacity        = request.device_size;
	device->image_path      = std::move(image_path);
	device->backing         = std::move(backing);
	const auto logged_image = Log::EscapeField(device->image_path);

	std::lock_guard lock(g_lvd_mutex);
	int             unit = 0;
	while (unit < 256 && g_lvd_devices.contains(unit))
		++unit;
	if (unit == 256) return KERNEL_ERROR_ENOSPC;
	device->unit = unit;
	g_lvd_devices.emplace(unit, device);
	if (!Memory::CopyToGuest(static_cast<uint8_t*>(arg) + offsetof(LvdAttachRequest, unit), &unit,
	                         sizeof(unit))) {
		g_lvd_devices.erase(unit);
		return KERNEL_ERROR_EFAULT;
	}
	LogLvdAttach(*device, logged_image);
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

static int DetachLvd(void* arg) try {
	LvdAttachRequest request {};
	if (!Memory::CopyFromGuest(&request, arg, sizeof(request))) return KERNEL_ERROR_EFAULT;
	if (request.version != 0 || request.unit < 0 || request.sector_size != 0 ||
	    request.granularity != 0 || request.flags != 0 || request.image_type != 0 ||
	    request.layer_count != 0 || request.device_size != 0 || request.layers != 0) {
		return KERNEL_ERROR_EINVAL;
	}
	const std::string name = "/dev/lvd" + std::to_string(request.unit);
	std::lock_guard   publication(g_mount_publication_mutex);
	if (std::any_of(g_published_read_only_providers.begin(), g_published_read_only_providers.end(),
	                [&](const auto& binding) { return binding.device == name; })) {
		return KERNEL_ERROR_EBUSY;
	}
	std::lock_guard lock(g_lvd_mutex);
	const auto      found = g_lvd_devices.find(request.unit);
	if (found == g_lvd_devices.end()) return KERNEL_ERROR_ENOENT;
	const int owner = found->second->owner_pid;
	g_lvd_devices.erase(found);
	LogLvdDetach(Process::GetPid(), owner, request.unit);
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

static int LvdIoctl(uint64_t request, void* arg) {
	if (request == 0xc0286d00u) return AttachLvd(arg);
	if (request == 0xc0286d01u) return DetachLvd(arg);
	return KERNEL_ERROR_ENOTTY;
}

static int ValidateLvdUfsPassthrough(const std::string& device) {
	const auto lvd = FindLvdDevice(device);
	if (!lvd) return KERNEL_ERROR_ENOENT;
	constexpr uint64_t magic_offset = 0x1055c;
	if (lvd->capacity < magic_offset + sizeof(uint32_t)) return KERNEL_ERROR_EINVAL;
	uint32_t   magic = 0;
	const auto read =
	    DirectoryPassthrough::Pread(lvd->backing, &magic, sizeof(magic), magic_offset);
	return read == sizeof(magic) && magic == 0x19540119u ? OK : KERNEL_ERROR_EINVAL;
}

static void FillTmpfsStat(const Tmpfs::NodeStat& node, FileStat* stat) {
	*stat                    = {};
	stat->st_dev             = node.device;
	stat->st_ino             = static_cast<uint32_t>(node.inode);
	stat->st_mode            = static_cast<uint16_t>(node.mode);
	stat->st_nlink           = static_cast<uint16_t>(node.links);
	stat->st_uid             = node.uid;
	stat->st_gid             = node.gid;
	stat->st_size            = static_cast<int64_t>(node.size);
	stat->st_blocks          = static_cast<int64_t>(node.allocated_bytes / 512);
	stat->st_blksize         = Tmpfs::PageSize;
	stat->st_atim.tv_sec     = node.accessed;
	stat->st_mtim.tv_sec     = node.modified;
	stat->st_ctim.tv_sec     = node.changed;
	stat->st_birthtim.tv_sec = node.created;
}

static int64_t TransferTmpfs(File* file, void* bytes, size_t length, uint64_t offset,
                             bool sequential, bool write) {
	if (write ? !file->writable : !file->readable) return KERNEL_ERROR_EBADF;
	if (file->directory) return KERNEL_ERROR_EISDIR;
	if (length > INT64_MAX) return KERNEL_ERROR_EINVAL;
	if (!GuestSocketBufferAccessible(bytes, length, !write)) return KERNEL_ERROR_EFAULT;
	if (!write && length != 0) Memory::InvalidateMemory(reinterpret_cast<uint64_t>(bytes), length);
	if (write)
		return sequential ? Tmpfs::Write(file->tmpfs, bytes, length)
		                  : Tmpfs::Pwrite(file->tmpfs, bytes, length, offset);
	return sequential ? Tmpfs::Read(file->tmpfs, bytes, length)
	                  : Tmpfs::Pread(file->tmpfs, bytes, length, offset);
}

static void FillExfatStat(const ExfatMount::NodeStat& node, FileStat* stat) {
	*stat            = {};
	stat->st_dev     = node.device;
	stat->st_ino     = node.inode;
	stat->st_mode    = static_cast<uint16_t>(node.mode);
	stat->st_nlink   = 1;
	stat->st_size    = static_cast<int64_t>(node.size);
	stat->st_blocks  = static_cast<int64_t>(node.allocated_size / 512);
	stat->st_blksize = 512;
}

static int64_t TransferExfat(File* file, void* bytes, size_t length, uint64_t offset,
                             bool sequential) {
	if (!file->readable) return KERNEL_ERROR_EBADF;
	if (file->directory) return KERNEL_ERROR_EISDIR;
	if (length > 16 * 1024 * 1024) return KERNEL_ERROR_EINVAL;
	if (!GuestSocketBufferAccessible(bytes, length, true)) return KERNEL_ERROR_EFAULT;
	if (length) Memory::InvalidateMemory(reinterpret_cast<uint64_t>(bytes), length);
	return sequential ? ExfatMount::Read(file->exfat, bytes, length)
	                  : ExfatMount::Pread(file->exfat, bytes, length, offset);
}

static void FillBfsStat(const BfsMount::NodeStat& node, FileStat* stat) {
	*stat            = {};
	stat->st_dev     = node.device;
	stat->st_ino     = node.inode;
	stat->st_mode    = static_cast<uint16_t>(node.mode);
	stat->st_nlink   = 1;
	stat->st_size    = static_cast<int64_t>(node.size);
	stat->st_blocks  = static_cast<int64_t>(node.allocated_size / 512);
	stat->st_blksize = 512;
}

static int64_t TransferBfs(File* file, void* bytes, size_t length, uint64_t offset,
                           bool sequential) {
	if (!file->readable) return KERNEL_ERROR_EBADF;
	if (file->directory) return KERNEL_ERROR_EISDIR;
	if (length > 16 * 1024 * 1024) return KERNEL_ERROR_EINVAL;
	if (!GuestSocketBufferAccessible(bytes, length, true)) return KERNEL_ERROR_EFAULT;
	if (length) Memory::InvalidateMemory(reinterpret_cast<uint64_t>(bytes), length);
	return sequential ? BfsMount::Read(file->bfs, bytes, length)
	                  : BfsMount::Pread(file->bfs, bytes, length, offset);
}

static int64_t TransferPassthrough(File* file, void* bytes, size_t length, uint64_t offset,
                                   bool sequential) {
	if (!file->readable) return KERNEL_ERROR_EBADF;
	if (file->directory) return KERNEL_ERROR_EISDIR;
	if (length > 16 * 1024 * 1024) return KERNEL_ERROR_EINVAL;
	if (!GuestSocketBufferAccessible(bytes, length, true)) return KERNEL_ERROR_EFAULT;
	if (length) Memory::InvalidateMemory(reinterpret_cast<uint64_t>(bytes), length);
	return sequential ? DirectoryPassthrough::Read(file->passthrough, bytes, length)
	                  : DirectoryPassthrough::Pread(file->passthrough, bytes, length, offset);
}

static int64_t WritePassthrough(File* file, const void* bytes, size_t length, uint64_t offset,
                                bool sequential) {
	if (length > INT64_MAX) return KERNEL_ERROR_EINVAL;
	if (!GuestSocketBufferAccessible(bytes, length, false)) return KERNEL_ERROR_EFAULT;
	return sequential ? DirectoryPassthrough::Write(file->passthrough, bytes, length)
	                  : DirectoryPassthrough::Pwrite(file->passthrough, bytes, length, offset);
}

static void FillPassthroughStat(const DirectoryPassthrough::NodeStat& node, FileStat* stat) {
	*stat            = {};
	stat->st_dev     = node.device;
	stat->st_ino     = node.inode;
	stat->st_mode    = static_cast<uint16_t>(node.mode);
	stat->st_nlink   = 1;
	stat->st_size    = static_cast<int64_t>(node.size);
	stat->st_blocks  = static_cast<int64_t>(node.allocated_size / 512);
	stat->st_blksize = 512;
	if (node.captured) {
		stat->st_uid         = node.uid;
		stat->st_gid         = node.gid;
		stat->st_mtim.tv_sec = node.mtime;
	}
}

static bool IsExfatDescriptor(int descriptor) {
	if (descriptor < DESCRIPTOR_MIN || g_files == nullptr) return false;
	const auto* file = g_files->GetFile(descriptor);
	return file != nullptr && file->opened && file->exfat != nullptr;
}

static bool IsPassthroughDescriptor(int descriptor) {
	if (descriptor < DESCRIPTOR_MIN || g_files == nullptr) return false;
	const auto* file = g_files->GetFile(descriptor);
	return file != nullptr && file->opened && file->passthrough != nullptr;
}

static bool IsLvdDescriptor(int descriptor) {
	if (descriptor < DESCRIPTOR_MIN || g_files == nullptr) return false;
	const auto* file = g_files->GetFile(descriptor);
	return file != nullptr && file->opened && file->lvd != nullptr;
}

bool IsTmpfsDescriptor(int descriptor) {
	if (descriptor < DESCRIPTOR_MIN || g_files == nullptr) return false;
	const auto* file = g_files->GetFile(descriptor);
	return file != nullptr && file->opened && file->tmpfs != nullptr;
}

static int64_t TransferSectorPayload(File* file, uint64_t offset, void* bytes, size_t length,
                                     bool write) {
	if (write ? !file->writable : !file->readable) return KERNEL_ERROR_EBADF;
	if (length > 16 * 1024 * 1024) return KERNEL_ERROR_EINVAL;
	const auto capacity    = file->sector_backing->Capacity();
	const auto sector_size = file->sector_backing->SectorSize();
	if (offset % sector_size || length % sector_size) return KERNEL_ERROR_EINVAL;
	if (offset > capacity) return KERNEL_ERROR_EIO;
	length = static_cast<size_t>(std::min<uint64_t>(length, capacity - offset));
	if (!length) return 0;
	if (!GuestSocketBufferAccessible(bytes, length, !write)) return KERNEL_ERROR_EFAULT;
	if (!write) Memory::InvalidateMemory(reinterpret_cast<uint64_t>(bytes), length);
	const auto result = write ? file->sector_backing->Write(offset, bytes, length)
	                          : file->sector_backing->Read(offset, bytes, length);
	switch (result) {
		case SectorBacking::Result::Ok: return static_cast<int64_t>(length);
		case SectorBacking::Result::Invalid: return KERNEL_ERROR_EINVAL;
		case SectorBacking::Result::ReadOnly: return KERNEL_ERROR_EROFS;
		case SectorBacking::Result::NoSpace: return KERNEL_ERROR_ENOSPC;
		case SectorBacking::Result::Unsupported: return KERNEL_ERROR_ENOTSUP;
		default: return KERNEL_ERROR_EIO;
	}
}

static void ApplyIccnvs4NodeStat(FileStat* stat) {
	stat->st_mode   = 0020000u | 0000640u;
	stat->st_uid    = 0;
	stat->st_gid    = 5;
	stat->st_size   = 0;
	stat->st_blocks = 0;
}

static int64_t TransferIccnvs4Snapshot(File* file, void* buf, size_t length, uint64_t offset,
                                       bool sequential, bool write) {
	if (write ? !file->writable : !file->readable) return KERNEL_ERROR_EBADF;
	if (length > 16 * 1024 * 1024) return KERNEL_ERROR_EINVAL;
	if (!length) return 0;
	if (!GuestSocketBufferAccessible(buf, length, !write)) return KERNEL_ERROR_EFAULT;
	Common::LockGuard lock(file->mutex);
	const auto        position = file->f.Tell();
	if (sequential) offset = position;
	if (offset > file->iccnvs4_snapshot_bytes || length > file->iccnvs4_snapshot_bytes - offset) {
		return KERNEL_ERROR_EIO;
	}
	if (file->f.IsInvalid()) return KERNEL_ERROR_EIO;
	std::vector<uint8_t> data(write ? 0 : length);
	const auto           result = write ? file->iccnvs4_backing->Write(offset, buf, length)
	                                    : file->iccnvs4_backing->Read(offset, data.data(), length);
	if (result != SectorBacking::Result::Ok) {
		if (result == SectorBacking::Result::NoSpace) return KERNEL_ERROR_ENOSPC;
		if (result == SectorBacking::Result::ReadOnly) return KERNEL_ERROR_EROFS;
		return KERNEL_ERROR_EIO;
	}
	if (sequential && !file->f.Seek(offset + length)) return KERNEL_ERROR_EIO;
	if (!write) {
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(buf), length);
		if (std::getenv("KYTY_DIAGNOSTIC_ICCNVS4_CLEAN_NVS") != nullptr) {
			constexpr uint64_t patch_offset = 0x23;
			if (offset <= patch_offset && patch_offset < offset + length) {
				const auto    local    = static_cast<size_t>(patch_offset - offset);
				const uint8_t original = data[local];
				data[local]            = 0;
				LOGF("FIRST_FRAME_AUDIT ICCNVS4_CLEAN_NVS_READ_OVERRIDE transfer_offset=%" PRIu64
				     " requested=%zu patched_offset=0x%" PRIx64
				     " original=0x%02x overridden_value=0x00 NON_AUTHENTIC\n",
				     offset, length, patch_offset, original);
			}
		}
		std::memcpy(buf, data.data(), length);
	}
	LOGF("ICCNVS4_SNAPSHOT_%s offset=%" PRIu64 " requested=%zu actual=%zu\n",
	     write ? "WRITE" : "READ", offset, length, length);
	return static_cast<int64_t>(length);
}

static std::atomic_bool g_guest_socket_fixture_trace {false};





int FileDescriptors::GetFlags(int fd) {
	if (fd < 0) {
		return KERNEL_ERROR_EBADF;
	}
	Common::LockGuard lock(m_mutex);
	if (fd >= 0 && fd < DESCRIPTOR_MIN) {
		return m_standard_deci[fd] || !m_explicit_standard ? m_standard_flags[fd]
		                                                   : KERNEL_ERROR_EBADF;
	}
	const size_t index = static_cast<size_t>(fd - DESCRIPTOR_MIN);
	if (index >= m_files.size() || m_files[index] == nullptr || !m_files[index]->opened) {
		return KERNEL_ERROR_EBADF;
	}
	return m_files[index]->descriptor_flags;
}

int FileDescriptors::SetFlags(int fd, int flags) {
	if (fd < 0) {
		return KERNEL_ERROR_EBADF;
	}
	if ((flags & ~1) != 0) {
		return KERNEL_ERROR_EINVAL;
	}
	Common::LockGuard lock(m_mutex);
	if (fd >= 0 && fd < DESCRIPTOR_MIN) {
		if (!m_standard_deci[fd] && m_explicit_standard) {
			return KERNEL_ERROR_EBADF;
		}
		m_standard_flags[fd] = flags;
		return OK;
	}
	const size_t index = static_cast<size_t>(fd - DESCRIPTOR_MIN);
	if (index >= m_files.size() || m_files[index] == nullptr || !m_files[index]->opened) {
		return KERNEL_ERROR_EBADF;
	}
	m_files[index]->descriptor_flags = flags;
	return OK;
}

int GetDescriptorFlags(int fd) {
	return g_files == nullptr ? KERNEL_ERROR_EBADF : g_files->GetFlags(fd);
}

int SetDescriptorFlags(int fd, int flags) {
	return g_files == nullptr ? KERNEL_ERROR_EBADF : g_files->SetFlags(fd, flags);
}

int FileDescriptors::Export(std::string* manifest) {
	if (manifest == nullptr) {
		return KERNEL_ERROR_EFAULT;
	}
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	Common::LockGuard lock(m_mutex);
	if (!m_explicit_standard) {
		return KERNEL_ERROR_ENOSYS;
	}
	std::ostringstream output;
	output << "KYTY_EXEC_FDS 1\n";
	for (int fd = 0; fd < DESCRIPTOR_MIN; ++fd) {
		if (m_standard_deci[fd] && (m_standard_flags[fd] & 1) == 0) {
			output << (m_standard_console[fd] ? "C " : "D ") << fd << " 0 " << fd << "\n";
		}
	}
	for (size_t index = 0; index < m_files.size(); ++index) {
		const auto* file = m_files[index];
		if (file == nullptr || !file->opened || (file->descriptor_flags & 1) != 0) {
			continue;
		}
		const size_t fd = index + DESCRIPTOR_MIN;
		if (fd > 65535) {
			return KERNEL_ERROR_EMFILE;
		}
		if (file->special == SpecialFile::GuestSocketPair && file->pipe && file->socket_send &&
		    file->pipe->shared && file->socket_send->shared) {
			output << "S " << fd << " 0 " << file->pipe->shared->name << " "
			       << file->socket_send->shared->name << "\n";
			LOGF(
			    "GUEST_SOCKET_DESCRIPTOR guest_pid=%d fd=%zu operation=export receive=%s send=%s\n",
			    Process::GetPid(), fd, file->pipe->shared->name.c_str(),
			    file->socket_send->shared->name.c_str());
		} else if (file->special == SpecialFile::DeciStdin ||
		           file->special == SpecialFile::DeciStdout ||
		           file->special == SpecialFile::DeciStderr) {
			const int stream = file->special == SpecialFile::DeciStdin    ? 0
			                   : file->special == SpecialFile::DeciStdout ? 1
			                                                              : 2;
			output << "D " << fd << " 0 " << stream << "\n";
		} else {
			LOGF("GUEST_EXEC_DESCRIPTOR_UNSUPPORTED fd=%zu type=%d path=%s\n", fd,
			     static_cast<int>(file->special), file->name.c_str());
			return KERNEL_ERROR_ENOSYS;
		}
	}
	output << "END\n";
	auto serialized = output.str();
	if (serialized.size() > 1024 * 1024) {
		return KERNEL_ERROR_E2BIG;
	}
	*manifest = std::move(serialized);
	return OK;
#else
	return KERNEL_ERROR_ENOSYS;
#endif
}

int FileDescriptors::Import(const std::string& manifest) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	if (manifest.size() > 1024 * 1024) {
		return KERNEL_ERROR_E2BIG;
	}
	std::istringstream input(manifest);
	std::string        line;
	if (!std::getline(input, line) || line != "KYTY_EXEC_FDS 1") {
		return KERNEL_ERROR_EINVAL;
	}
	FileDescriptors staged(true);
	bool            complete = false;
	while (std::getline(input, line)) {
		if (line == "END") {
			complete = true;
			break;
		}
		std::istringstream record(line);
		char               kind = 0;
		int                fd = -1, flags = -1;
		if (!(record >> kind >> fd >> flags) || fd < 0 || fd > 65535 || flags != 0) {
			return KERNEL_ERROR_EINVAL;
		}
		if (fd < DESCRIPTOR_MIN) {
			int stream = -1;
			if ((kind != 'D' && kind != 'C') || !(record >> stream) || stream != fd ||
			    staged.m_standard_deci[fd]) {
				return KERNEL_ERROR_EINVAL;
			}
			record >> std::ws;
			if (!record.eof()) {
				return KERNEL_ERROR_EINVAL;
			}
			staged.m_standard_deci[fd]    = true;
			staged.m_standard_console[fd] = kind == 'C';
			continue;
		}
		const size_t index = static_cast<size_t>(fd - DESCRIPTOR_MIN);
		if (index >= staged.m_files.size()) {
			staged.m_files.resize(index + 1);
		}
		if (staged.m_files[index] != nullptr) {
			return KERNEL_ERROR_EINVAL;
		}
		auto file          = std::make_unique<File>();
		file->scope_shared = -1;
		if (kind == 'D') {
			int stream = -1;
			if (!(record >> stream) || stream < 0 || stream > 2) {
				return KERNEL_ERROR_EINVAL;
			}
			file->special   = stream == 0   ? SpecialFile::DeciStdin
			                  : stream == 1 ? SpecialFile::DeciStdout
			                                : SpecialFile::DeciStderr;
			file->name      = stream == 0   ? "/dev/deci_stdin"
			                  : stream == 1 ? "/dev/deci_stdout"
			                                : "/dev/deci_stderr";
			file->real_name = file->name;
			file->readable  = stream == 0;
			file->writable  = stream != 0;
		} else if (kind == 'S') {
			std::string receive_name, send_name;
			if (!(record >> receive_name >> send_name) || receive_name == send_name) {
				return KERNEL_ERROR_EINVAL;
			}
			auto receive = SharedGuestPipe::Open(receive_name, false);
			auto send    = SharedGuestPipe::Open(send_name, false);
			if (!receive || !send) {
				return KERNEL_ERROR_EIO;
			}
			auto receive_pipe          = std::make_shared<GuestPipe>();
			auto send_pipe             = std::make_shared<GuestPipe>();
			receive_pipe->shared       = std::move(receive);
			send_pipe->shared          = std::move(send);
			const int retained_receive = ReferenceGuestPipe(receive_pipe, true, 1);
			if (retained_receive != OK) {
				return retained_receive;
			}
			const int retained_send = ReferenceGuestPipe(send_pipe, false, 1);
			if (retained_send != OK) {
				ReferenceGuestPipe(receive_pipe, true, -1);
				return retained_send;
			}
			file->special            = SpecialFile::GuestSocketPair;
			file->name               = "guest-socketpair";
			file->real_name          = "/dev/socketpair";
			file->pipe               = std::move(receive_pipe);
			file->socket_send        = std::move(send_pipe);
			file->socket_read_source = std::make_shared<GuestSocketReadSource>(file->pipe);
			file->readable           = true;
			file->writable           = true;
			LOGF("GUEST_SOCKET_DESCRIPTOR guest_pid=%d fd=%d operation=import receive=%s send=%s\n",
			     Process::GetPid(), fd, receive_name.c_str(), send_name.c_str());
		} else {
			return KERNEL_ERROR_ENOSYS;
		}
		file->opened          = true;
		staged.m_files[index] = file.release();
		record >> std::ws;
		if (!record.eof()) {
			return KERNEL_ERROR_EINVAL;
		}
	}
	input >> std::ws;
	if (!complete || !input.eof()) {
		return KERNEL_ERROR_EINVAL;
	}
	{
		Common::LockGuard lock(m_mutex);
		m_files.swap(staged.m_files);
		m_standard_deci.swap(staged.m_standard_deci);
		m_standard_console.swap(staged.m_standard_console);
		m_standard_flags.swap(staged.m_standard_flags);
		std::swap(m_explicit_standard, staged.m_explicit_standard);
	}
	return OK;
#else
	return KERNEL_ERROR_ENOSYS;
#endif
}

int ExportExecDescriptors(std::string* manifest) {
	const char* enabled = std::getenv("KYTY_DIAGNOSTIC_GUEST_EXECVE");
	if (enabled == nullptr || std::strcmp(enabled, "1") != 0) {
		return KERNEL_ERROR_ENOSYS;
	}
	return g_files == nullptr ? KERNEL_ERROR_EBADF : g_files->Export(manifest);
}

int ImportExecDescriptors(const std::string& manifest) {
	const char* enabled = std::getenv("KYTY_DIAGNOSTIC_GUEST_EXECVE");
	if (enabled == nullptr || std::strcmp(enabled, "1") != 0) {
		return KERNEL_ERROR_ENOSYS;
	}
	return g_files == nullptr ? KERNEL_ERROR_EBADF : g_files->Import(manifest);
}

void FileDescriptors::DeleteDescriptor(int d) {
	Common::LockGuard lock(m_mutex);

	auto index = static_cast<size_t>(d - DESCRIPTOR_MIN);

	EXIT_IF(index >= m_files.size());
	EXIT_IF(m_files[index] == nullptr);
	EXIT_IF(m_files[index]->opened);

#if KYTY_PLATFORM != KYTY_PLATFORM_WINDOWS
	m_files[index]->f.Close();
#endif

	delete m_files[index];
	m_files[index] = nullptr;
}

File* FileDescriptors::GetFile(int d) {
	Common::LockGuard lock(m_mutex);

	auto index = static_cast<size_t>(d - DESCRIPTOR_MIN);

	if (index >= m_files.size()) {
		return nullptr;
	}

	return m_files[index];
}

File* FileDescriptors::GetFile(const std::filesystem::path& real_name) {
	Common::LockGuard lock(m_mutex);

	for (auto* f: m_files) {
		if (f != nullptr && f->real_name == real_name) {
			return f;
		}
	}

	return nullptr;
}

void FileDescriptors::CloseAll() {
	Common::LockGuard lock(m_mutex);

	for (auto& f: m_files) {
		if (f != nullptr) {
			if (f->opened) {
				f->f.Close();
			}
			delete f;
			f = nullptr;
		}
	}
}

void MountPoints::Mount(const std::filesystem::path& folder, const std::string& point,
                        bool read_only) {
	if (ExfatMount::Contains(point)) {
		LOGF("HOST_MOUNT_UNSUPPORTED path=%s existing_exfat_mount=1\n", point.c_str());
		return;
	}
	if (BfsMount::Contains(point)) {
		LOGF("HOST_MOUNT_UNSUPPORTED path=%s existing_bfs_mount=1\n", point.c_str());
		return;
	}
	if (DirectoryPassthrough::Contains(point)) {
		LOGF("HOST_MOUNT_UNSUPPORTED path=%s existing_passthrough_mount=1\n", point.c_str());
		return;
	}
	if (NullfsMount::Contains(point)) {
		LOGF("HOST_MOUNT_UNSUPPORTED path=%s existing_nullfs_mount=1\n", point.c_str());
		return;
	}
	Common::LockGuard lock(m_mutex);

	auto point_str = Common::FixDirectorySlash(point);

	Umount(point_str);

	MountPair p;
	p.dir       = folder;
	p.point     = point_str;
	p.archive   = Common::OpenArchive(folder);
	p.read_only = read_only;

	m_mount_pairs.push_back(std::move(p));
	if (read_only) {
		std::error_code error;
		auto            root = std::filesystem::weakly_canonical(folder, error);
		EXIT_IF(error);
		m_read_only_roots.push_back(std::move(root));
	}
}

bool MountPoints::HasReadOnlyRoot() {
	Common::LockGuard lock(m_mutex);
	return std::any_of(m_mount_pairs.begin(), m_mount_pairs.end(),
	                   [](const auto& mount) { return mount.point == "/" && mount.read_only; });
}

bool MountPoints::HasNonRootMountForPath(const std::string& path) {
	Common::LockGuard lock(m_mutex);
	auto              guest = Common::FixFilenameSlash(path);
	while (guest.starts_with("//"))
		guest.erase(0, 1);
	const auto normalized = Common::FixDirectorySlash(
	    Common::PathToGenericString(Common::PathFromUtf8(guest).lexically_normal()));
	return std::any_of(m_mount_pairs.begin(), m_mount_pairs.end(), [&](const auto& mount) {
		return mount.point != "/" && normalized.starts_with(mount.point);
	});
}

bool MountPoints::GetMountDirectory(const std::string& point, std::filesystem::path* directory) {
	Common::LockGuard lock(m_mutex);
	const auto        normalized = Common::FixDirectorySlash(point);
	const auto mount = std::find_if(m_mount_pairs.begin(), m_mount_pairs.end(),
	                                [&](const auto& entry) { return entry.point == normalized; });
	if (mount == m_mount_pairs.end()) return false;
	*directory = mount->dir;
	return true;
}

bool MountPoints::HasSubmount(const std::string& point) {
	Common::LockGuard lock(m_mutex);
	const auto        normalized = Common::FixDirectorySlash(point);
	return std::any_of(m_mount_pairs.begin(), m_mount_pairs.end(), [&](const auto& mount) {
		return mount.point.size() > normalized.size() &&
		       std::equal(normalized.begin(), normalized.end(), mount.point.begin(),
		                  [](char left, char right) {
			                  if (left >= 'A' && left <= 'Z') left += 'a' - 'A';
			                  if (right >= 'A' && right <= 'Z') right += 'a' - 'A';
			                  return left == right;
		                  });
	});
}

std::vector<Common::File::DirEntry>
MountPoints::DirectoryEntries(const std::string&           mounted_name,
                              const std::filesystem::path& directory) {
	const bool data_covered =
	    Tmpfs::Contains("/data") || ExfatMount::Contains("/data") || BfsMount::Contains("/data") ||
	    DirectoryPassthrough::Contains("/data") || NullfsMount::Contains("/data");
	Common::LockGuard lock(m_mutex);
	auto              entries = Common::File::GetDirEntries(directory);
	auto              guest   = Common::FixFilenameSlash(mounted_name);
	while (guest.starts_with("//"))
		guest.erase(0, 1);
	const auto parent = Common::FixDirectorySlash(
	    Common::PathToGenericString(Common::PathFromUtf8(guest).lexically_normal()));
	for (const auto& mount: m_mount_pairs) {
		if (!mount.point.starts_with(parent)) continue;
		auto name = mount.point.substr(parent.size());
		if (name.ends_with('/')) name.pop_back();
		if (name.empty() || name.find('/') != std::string::npos) continue;
		const auto info = Common::File::GetInfo(mount.dir);
		if (!mount.archive && (!info || info->is_file)) continue;
		auto existing = std::find_if(entries.begin(), entries.end(),
		                             [&](const auto& entry) { return entry.name == name; });
		if (existing == entries.end())
			entries.push_back({std::move(name), false});
		else
			existing->is_file = false;
	}
	if (parent == "/") {
		const bool read_only_root =
		    std::any_of(m_mount_pairs.begin(), m_mount_pairs.end(),
			            [](const auto& mount) { return mount.point == "/" && mount.read_only; });
		if (read_only_root) {
			auto data = std::find_if(entries.begin(), entries.end(), [](const auto& entry) {
				return Common::EqualNoCase(entry.name, "data");
			});
			if (data == entries.end())
				entries.push_back({"data", false});
			else if (data_covered)
				data->is_file = false;
		}
	}
	return entries;
}

struct PsmShellUiApplicationRoute {
	const char* guest_path;
	const char* source_environment;
	const char* sha256_environment;
	uint64_t    expected_size;
	const char* expected_sha256;
};

static constexpr PsmShellUiApplicationRoute kPsmShellUiApplicationRoutes[] = {
    {"/app0/psm/Application/app.exe", "KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_PE",
	 "KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_PE_SHA256", 9728,
	 "74f76c80c6dd44d27d706748d9746500ab9b9e0f863cb843fcd096536b507f84"},
    {"/app0/psm/Application/app.exe.sprx", "KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_AOT",
	 "KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_AOT_SHA256", 127876,
	 "31fe344c9b7570fd3a49c8d2031d88db5c90e050f261bad866463894ecc55426"},
};

struct PsmShellUiApplicationLease {
	std::filesystem::path source;
	std::vector<uint8_t>  bytes;
	AuthInfo::Digest      sha256 {};
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	HANDLE handle = INVALID_HANDLE_VALUE;
#endif
	bool active = false;
};

static std::mutex g_psm_shellui_application_lease_mutex;
static std::array<PsmShellUiApplicationLease, std::size(kPsmShellUiApplicationRoutes) + 1>
    g_psm_shellui_application_leases;

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
static bool SamePsmShellUiFile(HANDLE left, HANDLE right) {
	BY_HANDLE_FILE_INFORMATION left_info {};
	BY_HANDLE_FILE_INFORMATION right_info {};
	return left != INVALID_HANDLE_VALUE && right != INVALID_HANDLE_VALUE &&
	       GetFileInformationByHandle(left, &left_info) &&
	       GetFileInformationByHandle(right, &right_info) &&
	       left_info.dwVolumeSerialNumber == right_info.dwVolumeSerialNumber &&
	       left_info.nFileIndexHigh == right_info.nFileIndexHigh &&
	       left_info.nFileIndexLow == right_info.nFileIndexLow;
}

#else
static bool SamePsmShellUiFile(const std::filesystem::path& left,
                               const std::filesystem::path& right) {
	std::error_code error;
	return std::filesystem::equivalent(left, right, error) && !error;
}
#endif


static void ReleasePsmShellUiApplicationLeases() {
	std::lock_guard lock(g_psm_shellui_application_lease_mutex);
	for (auto& lease: g_psm_shellui_application_leases) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		if (lease.handle != INVALID_HANDLE_VALUE) CloseHandle(lease.handle);
		lease.handle = INVALID_HANDLE_VALUE;
#endif
		lease.source.clear();
		lease.bytes.clear();
		lease.sha256 = {};
		lease.active = false;
	}
}





static bool IsPsmShellUiApplicationHostPath(const std::filesystem::path& path) {
	if (path.empty()) return false;
	std::lock_guard lock(g_psm_shellui_application_lease_mutex);
	for (size_t slot = 0; slot < std::size(kPsmShellUiApplicationRoutes); ++slot) {
		const auto& lease = g_psm_shellui_application_leases[slot];
		if (!lease.active) continue;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		const HANDLE candidate = CreateFileW(
		    path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		const bool same = SamePsmShellUiFile(candidate, lease.handle);
		if (candidate != INVALID_HANDLE_VALUE) CloseHandle(candidate);
		if (same) return true;
#else
		if (SamePsmShellUiFile(path, lease.source)) return true;
#endif
	}
	return false;
}



bool MountPoints::IsReadOnly(const std::filesystem::path& path) {
	if (Process::IsExecChildImagePath(path) || IsPsmShellUiApplicationHostPath(path)) return true;
	Common::LockGuard lock(m_mutex);
	if (path.empty() || m_read_only_roots.empty()) return false;
	std::error_code error;
	const auto      actual = std::filesystem::weakly_canonical(path, error);
	if (error) return true;
	for (const auto& root: m_read_only_roots) {
		auto target    = actual.begin();
		auto component = root.begin();
		for (; component != root.end() && target != actual.end(); ++component, ++target) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
			if (_wcsicmp(component->c_str(), target->c_str()) != 0) break;
#else
			if (*component != *target) break;
#endif
		}
		if (component == root.end()) return true;
	}
	return false;
}

void MountPoints::Umount(const std::string& folder_or_point) {
	Common::LockGuard lock(m_mutex);

	auto folder_or_point_str = Common::FixDirectorySlash(folder_or_point);

	const auto it = std::find_if(
	    m_mount_pairs.begin(), m_mount_pairs.end(), [&folder_or_point_str](const MountPair& p) {
		    return Common::FixDirectorySlash(Common::PathToGenericString(p.dir)) ==
			           folder_or_point_str ||
			       p.point == folder_or_point_str;
	    });
	if (it != m_mount_pairs.end()) {
		m_mount_pairs.erase(it);
	}
}

#if KYTY_PLATFORM != KYTY_PLATFORM_WINDOWS
// Resolve guest paths case-insensitively on case-sensitive hosts.
static std::filesystem::path ResolvePathIgnoringCase(const std::filesystem::path& path) {
	std::error_code ec;
	if (std::filesystem::exists(path, ec)) {
		return path;
	}

	std::filesystem::path resolved =
	    path.has_root_path() ? path.root_path() : std::filesystem::path(".");
	bool matched = true;

	for (const auto& component: path.relative_path()) {
		if (component.empty()) {
			continue;
		}

		auto candidate = resolved / component;
		if (!matched || std::filesystem::exists(candidate, ec)) {
			resolved = std::move(candidate);
			continue;
		}

		bool found = false;
		for (std::filesystem::directory_iterator entry(resolved, ec), end; entry != end;
		     entry.increment(ec)) {
			if (ec) {
				break;
			}
			if (Common::EqualNoCase(entry->path().filename().string(), component.string())) {
				resolved = entry->path();
				found    = true;
				break;
			}
		}

		if (!found) {
			resolved = std::move(candidate);
			matched  = false;
		}
	}

	return resolved;
}
#else
static bool HasWindowsForbiddenFilenameCharacter(const std::string& relative_path) {
	return relative_path.find_first_of("<>:\"|?*") != std::string::npos;
}
#endif

std::filesystem::path MountPoints::ResolvePath(const std::string& mounted_name) {
	Common::LockGuard lock(m_mutex);
	// PSM's Mono loads /common_ex/lib/mono/2.1/<assembly>.dll.sprx, but the AOT ELF is at
	// /system_ex/common_ex/lib/<assembly>.dll.sprx
	if (std::getenv("KYTY_DIAGNOSTIC_PSM_NATIVE_AOT_MOUNT") != nullptr) {
		auto guest = Common::FixFilenameSlash(mounted_name);
		while (!guest.empty() && guest[0] == '/') {
			guest.erase(0, 1);
		}
		// P/Invoke looks for the already loaded libmonosgen under these names; same ELF so the
		// program handle is reused
		if (guest == "common_ex/lib/mono/2.1/libmonosgen-2.0.sprx" ||
		    guest == "libmonosgen-2.0.sprx") {
			for (const auto& mount: m_mount_pairs) {
				if (mount.point != "/") {
					continue;
				}
				const auto native =
				    mount.dir / "system_ex" / "common_ex" / "lib" / "libmonosgen-2.0.sprx";
				if (Common::File::IsFileExisting(native)) {
					static std::atomic_uint32_t count {0};
					if (count.fetch_add(1) < 12) {
						LOGF("FIRST_FRAME_AUDIT PSM_MONO_NATIVE_ALIAS guest=%s sony=%s\n",
						     Log::EscapeField(mounted_name).c_str(), EscapeLogPath(native).c_str());
					}
					return native;
				}
			}
		}
		constexpr const char* aot_prefix        = "common_ex/lib/mono/2.1/";
		constexpr const char* shared_aot_prefix = "common_ex/lib/";
		const char* accepted_prefix = guest.starts_with(aot_prefix)          ? aot_prefix
		                              : guest.starts_with(shared_aot_prefix) ? shared_aot_prefix
		                                                                     : nullptr;
		if (accepted_prefix != nullptr) {
			const auto name = guest.substr(std::strlen(accepted_prefix));
			bool safe_name  = name.size() >= 9 && name.size() <= 128 && name.ends_with(".sprx") &&
			                  name.find("..") == std::string::npos;
			for (const char ch: name) {
				if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
				      (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.')) {
					safe_name = false;
					break;
				}
			}
			if (safe_name) {
				for (const auto& mount: m_mount_pairs) {
					if (mount.point != "/") {
						continue;
					}
					const auto native =
					    mount.dir / "system_ex" / "common_ex" / "lib" / Common::PathFromUtf8(name);
					if (!Common::File::IsFileExisting(native)) {
						break;
					}
					static std::atomic_uint32_t trace_count {0};
					if (trace_count.fetch_add(1) < 30) {
						LOGF("FIRST_FRAME_AUDIT PSM_NATIVE_AOT_MOUNT guest=%s native=%s\n",
						     Log::EscapeField(mounted_name).c_str(), EscapeLogPath(native).c_str());
					}
					return native;
				}
			}
		}
	}
	if (const char* mscorlib_pe = std::getenv("KYTY_DIAGNOSTIC_SONY_MSCORLIB_PE");
	    mscorlib_pe != nullptr && mscorlib_pe[0] != '\0') {
		if (mounted_name == "/common_ex/lib/mono/2.1/mscorlib.dll") {
			const auto original_pe = std::filesystem::path(mscorlib_pe);
			if (!Common::File::IsFileExisting(original_pe)) {
				return {};
			}
			LOGF("FIRST_FRAME_AUDIT SONY_MSCORLIB_PE_MAP guest=%s host=%s\n",
			     Log::EscapeField(mounted_name).c_str(), EscapeLogPath(original_pe).c_str());
			return original_pe;
		}
	}
	// managed PEs live inside the *.dll.sprx ELFs, but PSM looks up /common_ex/lib/mono/2.1/*.dll
	if (const char* pe_dir = std::getenv("KYTY_DIAGNOSTIC_SONY_MANAGED_PE_DIR");
	    pe_dir != nullptr && pe_dir[0] != '\0') {
		auto guest = Common::FixFilenameSlash(mounted_name);
		while (!guest.empty() && guest[0] == '/') {
			guest.erase(0, 1);
		}
		constexpr const char* prefixes[] = {
		    "common_ex/lib/mono/2.1/",
		    "system_ex/common_ex/lib/mono/2.1/",
		    "common_ex/lib/",
		};
		for (const char* prefix: prefixes) {
			if (!guest.starts_with(prefix)) {
				continue;
			}
			const auto filename = guest.substr(std::strlen(prefix));
			if (!filename.empty() && filename.size() <= 128 &&
			    filename.find_first_of("/\\:") == std::string::npos && filename != "." &&
			    filename != ".." && filename.ends_with(".dll")) {
				auto staged = std::filesystem::path(pe_dir) / Common::PathFromUtf8(filename);
				if (Common::File::IsFileExisting(staged)) {
					static std::atomic_uint32_t trace_count {0};
					if (trace_count.fetch_add(1) < 24) {
						LOGF("FIRST_FRAME_AUDIT SONY_MANAGED_PE_MAP guest=%s host=%s\n",
						     Log::EscapeField(mounted_name).c_str(), EscapeLogPath(staged).c_str());
					}
					return staged;
				}
			}
			break;
		}
	}
	if (std::getenv("KYTY_DIAGNOSTIC_PSM_COMMON_LIB_ALIAS") != nullptr) {
		auto guest = Common::FixFilenameSlash(mounted_name);
		while (!guest.empty() && guest[0] == '/') {
			guest.erase(0, 1);
		}
		constexpr const char* prefix = "common/lib";
		if (guest == prefix || guest.starts_with("common/lib/")) {
			// a tail with its leading slash would join onto the host drive root
			auto tail = guest.substr(std::strlen(prefix));
			while (tail.starts_with('/')) {
				tail.erase(0, 1);
			}
			const auto relative = Common::PathFromUtf8(tail);
			bool safe = tail.find(':') == std::string::npos && tail.find('\\') == std::string::npos;
			for (const auto& component: relative) {
				if (component == "..") {
					safe = false;
				}
			}
			if (safe) {
				for (const auto& mount: m_mount_pairs) {
					if (mount.point != "/") {
						continue;
					}
					const auto actual = mount.dir / "system" / "common" / "lib" / relative;
					static std::atomic_uint32_t trace_count {0};
					if (trace_count.fetch_add(1) < 20) {
						LOGF("FIRST_FRAME_AUDIT PSM_COMMON_LIB_ALIAS guest=%s native=%s\n",
						     Log::EscapeField(mounted_name).c_str(), EscapeLogPath(actual).c_str());
					}
					return actual;
				}
			}
		}
	}

	// Repeated leading slashes count as one, //priv/mms has to reach the /priv mount.
	auto guest_name = Common::FixFilenameSlash(mounted_name);
	while (guest_name.starts_with("//")) {
		guest_name.erase(0, 1);
	}
	guest_name = Common::PathToGenericString(Common::PathFromUtf8(guest_name).lexically_normal());
	const auto mounted_path = Common::FixDirectorySlash(guest_name);
	auto       it           = m_mount_pairs.end();
	for (auto candidate = m_mount_pairs.begin(); candidate != m_mount_pairs.end(); ++candidate) {
		if (mounted_path.starts_with(candidate->point) &&
		    (it == m_mount_pairs.end() || candidate->point.size() >= it->point.size())) {
			it = candidate;
		}
	}
	if (it != m_mount_pairs.end()) {
		const auto& p        = *it;
		auto        rel_path = Common::RemoveFirst(guest_name, p.point.size());
		while (rel_path.starts_with('/')) {
			rel_path = Common::RemoveFirst(rel_path, 1);
		}

		const auto native_rel_path = Common::PathFromUtf8(rel_path);
		if (Common::IsArchivePath(p.dir)) {
			return p.dir / native_rel_path;
		}

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		if (HasWindowsForbiddenFilenameCharacter(rel_path)) {
			LOGF("FileSystem: Windows-incompatible guest filename: %s\n",
			     Log::EscapeField(mounted_name).c_str());
			return {};
		}
		auto actual = p.dir / native_rel_path;
#else
		auto actual = ResolvePathIgnoringCase(p.dir / native_rel_path);
#endif
	}

	return {};
}

enum class DataTopologyPath {
	None,
	Directory,
	Missing,
};

static bool UseCapturedRootMetadata(const char* path) {
	if (path == nullptr || !CapturedRootMetadata::Enabled()) return false;
	std::string normalized;
	if (Tmpfs::NormalizePath(path, &normalized) != OK || normalized.starts_with("/dev/"))
		return false;
	return !g_mount_points->HasNonRootMountForPath(normalized);
}

static bool HasDataTopology() {
	if (g_mount_points == nullptr || !g_mount_points->HasReadOnlyRoot()) return false;
	if (Tmpfs::Contains("/data") || ExfatMount::Contains("/data") || BfsMount::Contains("/data") ||
	    DirectoryPassthrough::Contains("/data") || NullfsMount::Contains("/data"))
		return false;
	const auto direct = g_mount_points->ResolvePath("/data");
	return direct.empty() || !Common::File::GetInfo(direct).has_value();
}

static DataTopologyPath ResolveDataTopologyPath(const std::string& path) {
	if (path.empty() || path[0] != '/' || !HasDataTopology()) return DataTopologyPath::None;
	bool data = false;
	for (size_t start = 1; start <= path.size();) {
		const auto end       = path.find('/', start);
		const auto component = path.substr(start, end == std::string::npos ? end : end - start);
		if (!component.empty() && component != ".") {
			if (component == "..") {
				data = false;
			} else if (!data && component == "data") {
				data = true;
			} else if (data) {
				const auto prefix = "/data/" + component;
				if (g_mount_points->HasNonRootMountForPath(prefix)) {
					return DataTopologyPath::None;
				}
				return DataTopologyPath::Missing;
			} else {
				return DataTopologyPath::None;
			}
		}
		if (end == std::string::npos) break;
		start = end + 1;
	}
	return data ? DataTopologyPath::Directory : DataTopologyPath::None;
}

static void FillDataTopologyStat(FileStat* stat) {
	*stat            = {};
	stat->st_dev     = 0x4b445441u;
	stat->st_ino     = 0x64617461u;
	stat->st_mode    = 0040555u;
	stat->st_nlink   = 2;
	stat->st_blksize = DIR_BLOCK_SIZE;
}

struct DevfsRootEntry {
	uint32_t    inode;
	uint8_t     type;
	std::string name;
};

// root image only has the empty /dev mountpoint, so devfs contents come from a console listing
static const std::vector<DevfsRootEntry>* DevfsRootListing() {
	static const std::vector<DevfsRootEntry>* listing = []() -> const std::vector<DevfsRootEntry>* {
		const char* source = std::getenv("KYTY_PS5_DEVFS_LISTING");
		if (source == nullptr || source[0] == '\0') return nullptr;
		std::ifstream input(Common::PathFromUtf8(source));
		auto          entries = std::make_unique<std::vector<DevfsRootEntry>>();
		std::string   line;
		while (input && std::getline(input, line)) {
			if (line.empty() || line[0] == '#') continue;
			const auto tab  = line.find('\t');
			const auto tab2 = tab == std::string::npos ? tab : line.find('\t', tab + 1);
			if (tab2 == std::string::npos) return nullptr;
			DevfsRootEntry entry {};
			entry.inode =
			    static_cast<uint32_t>(std::strtoul(line.substr(0, tab).c_str(), nullptr, 10));
			const auto type =
			    std::strtoul(line.substr(tab + 1, tab2 - tab - 1).c_str(), nullptr, 10);
			entry.name = line.substr(tab2 + 1);
			if (entry.inode == 0 || (type != 2 && type != 4 && type != 10) || entry.name.empty() ||
			    entry.name.size() > 255 || entry.name == "." || entry.name == ".." ||
			    entry.name.find('/') != std::string::npos) {
				LOGF("DEVFS_ROOT_LISTING rejected line=%zu\n", entries->size() + 1);
				return nullptr;
			}
			entry.type = static_cast<uint8_t>(type);
			entries->push_back(std::move(entry));
		}
		if (!input.eof() || entries->empty()) {
			LOGF("DEVFS_ROOT_LISTING unreadable\n");
			return nullptr;
		}
		LOGF("DEVFS_ROOT_LISTING entries=%zu source=console_observation\n", entries->size());
		return entries.release();
	}();
	return listing;
}

static bool IsDevfsRoot(const char* path) {
	std::string normalized;
	return path != nullptr && path[0] == '/' && Tmpfs::NormalizePath(path, &normalized) == OK &&
	       normalized == "/dev" && DevfsRootListing() != nullptr;
}

// devfs_getattr for the root directory, through vn_stat's max(PAGE_SIZE, va_blocksize)
static void FillDevfsRootStat(FileStat* stat) {
	*stat          = {};
	stat->st_ino   = 2;
	stat->st_mode  = 0040555u;
	stat->st_nlink = 2;
	for (const auto& entry: *DevfsRootListing())
		if (entry.type == 4) stat->st_nlink++;
	stat->st_size    = 512;
	stat->st_blocks  = 1;
	stat->st_blksize = 0x4000;
}

// Subdirectory cdevs plus inodes of unlisted entries (type 0, no name). With the root listing these
// are the devfs_inos in use when a new devfs mount allocates.
static const std::vector<uint32_t>* DevfsHeldInodes() {
	static const std::vector<uint32_t>* held = []() -> const std::vector<uint32_t>* {
		const char* source = std::getenv("KYTY_PS5_DEVFS_SUBDIR_LISTING");
		const auto* root   = DevfsRootListing();
		if (source == nullptr || source[0] == '\0' || root == nullptr) return nullptr;
		std::ifstream input(Common::PathFromUtf8(source));
		auto          inodes = std::make_unique<std::vector<uint32_t>>();
		std::string   line;
		while (input && std::getline(input, line)) {
			if (line.empty() || line[0] == '#') continue;
			const auto tab  = line.find('\t');
			const auto tab2 = tab == std::string::npos ? tab : line.find('\t', tab + 1);
			if (tab2 == std::string::npos) return nullptr;
			const auto inode = std::strtoul(line.substr(0, tab).c_str(), nullptr, 10);
			const auto type =
			    std::strtoul(line.substr(tab + 1, tab2 - tab - 1).c_str(), nullptr, 10);
			const auto name  = line.substr(tab2 + 1);
			const auto slash = name.find('/');
			bool       valid =
			    inode > 2 && (type == 0 ? name.empty()
				                        : type == 2 && slash != std::string::npos && slash > 0 &&
				                              slash + 1 < name.size() &&
				                              name.find('/', slash + 1) == std::string::npos);
			if (valid && type != 0) {
				const auto subdir = name.substr(0, slash);
				valid             = std::any_of(root->begin(), root->end(), [&](const auto& entry) {
					return entry.type == 4 && entry.name == subdir;
				});
			}
			if (!valid) {
				LOGF("DEVFS_SUBDIR_LISTING rejected line=%zu\n", inodes->size() + 1);
				return nullptr;
			}
			inodes->push_back(static_cast<uint32_t>(inode));
		}
		if (!input.eof()) {
			LOGF("DEVFS_SUBDIR_LISTING unreadable\n");
			return nullptr;
		}
		LOGF("DEVFS_SUBDIR_LISTING entries=%zu source=console_observation\n", inodes->size());
		return inodes.release();
	}();
	return held;
}

static std::vector<uint8_t> PackDevfsRoot(const std::vector<uint32_t>* directories = nullptr) {
	std::vector<DevfsRootEntry> entries {{2, 4, "."}, {2, 4, ".."}};
	size_t                      next = 0;
	for (auto entry: *DevfsRootListing()) {
		if (directories != nullptr && entry.type == 4) entry.inode = (*directories)[next++];
		entries.push_back(std::move(entry));
	}
	std::vector<Common::File::DirEntry> directory;
	for (const auto& entry: entries)
		directory.push_back({entry.name, entry.type != 4});
	auto   packed = PackDirents(directory);
	size_t offset = 0;
	for (const auto& entry: entries) {
		std::memcpy(packed.data() + offset, &entry.inode, sizeof(entry.inode));
		packed[offset + 6] = entry.type;
		uint16_t length    = 0;
		std::memcpy(&length, packed.data() + offset + 4, sizeof(length));
		offset += length;
	}
	return packed;
}

void Initialize() {
	g_diagnostic_gc_device_ready = false;
	{
		std::lock_guard lock(g_lvd_mutex);
		g_lvd_devices.clear();
	}
	g_native_metadbg_stream = std::make_shared<NativeMetadbgStream>();
	g_native_system_mbus    = std::make_shared<NativeSystemMbusState>();
	g_mount_points          = new MountPoints;
	g_files                 = new FileDescriptors;
	std::string scope;
	if (!Process::GetScope(&scope)) {
		scope = "fs_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
	}
	g_tmpfs_status = Tmpfs::Initialize(scope);
	if (g_tmpfs_status != OK) LOGF("TMPFS_NAMESPACE initialization_error=0x%x\n", g_tmpfs_status);
}

void EmergencyShutdown() {
	if (g_files != nullptr) {
		g_files->CloseAll();
	}
	Common::LockGuard lock(g_hmd_shm_mutex);
	g_hmd_shm_exists = false;
}

void Shutdown() {
	EmergencyShutdown();
	delete g_files;
	delete g_mount_points;
	Tmpfs::Shutdown();
	ExfatMount::Shutdown();
	BfsMount::Shutdown();
	DirectoryPassthrough::Shutdown();
	NullfsMount::Shutdown();
	CapturedRootMetadata::Shutdown();
	g_published_read_only_providers.clear();
	{
		std::lock_guard lock(g_passthrough_registration_mutex);
		g_passthrough_registrations.clear();
	}
	g_tmpfs_status = KERNEL_ERROR_ENOSYS;
	g_files        = nullptr;
	g_mount_points = nullptr;
}

void Mount(const std::filesystem::path& folder, const std::string& point) {
	std::lock_guard publication(g_mount_publication_mutex);

	g_mount_points->Mount(folder, point);
}

void MountReadOnly(const std::filesystem::path& folder, const std::string& point) {
	std::lock_guard publication(g_mount_publication_mutex);
	g_mount_points->Mount(folder, point, true);
}

int MountInitialSystemTmpDirectory(const std::filesystem::path& sysroot,
                                   const std::filesystem::path& directory) {
	std::lock_guard publication(g_mount_publication_mutex);
	if (g_mount_points == nullptr) return KERNEL_ERROR_ENOSYS;
	const auto host_error = [](const std::error_code& error) {
		if (error == std::errc::no_such_file_or_directory) return KERNEL_ERROR_ENOENT;
		if (error == std::errc::not_a_directory) return KERNEL_ERROR_ENOTDIR;
		if (error == std::errc::permission_denied) return KERNEL_ERROR_EACCES;
		if (error == std::errc::too_many_symbolic_link_levels) return KERNEL_ERROR_ELOOP;
		return KERNEL_ERROR_EIO;
	};
	const auto ordinary_directory = [&](const std::filesystem::path& path) {
		if (!path.is_absolute()) return KERNEL_ERROR_EINVAL;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		const auto drive = path.root_name().native();
		if (drive.size() != 2 || drive[1] != L':' ||
		    !((drive[0] >= L'A' && drive[0] <= L'Z') || (drive[0] >= L'a' && drive[0] <= L'z')))
			return KERNEL_ERROR_EINVAL;
#endif
		auto       current         = path.root_path();
		const auto check_component = [&]() {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
			const auto attributes = GetFileAttributesW(current.c_str());
			if (attributes == INVALID_FILE_ATTRIBUTES) {
				const auto error = GetLastError();
				if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
					return KERNEL_ERROR_ENOENT;
				if (error == ERROR_ACCESS_DENIED) return KERNEL_ERROR_EACCES;
				return KERNEL_ERROR_EIO;
			}
			if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) return KERNEL_ERROR_ELOOP;
			if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) return KERNEL_ERROR_ENOTDIR;
#else
			std::error_code error;
			const auto      status = std::filesystem::symlink_status(current, error);
			if (error) return host_error(error);
			if (std::filesystem::is_symlink(status)) return KERNEL_ERROR_ELOOP;
			if (!std::filesystem::exists(status)) return KERNEL_ERROR_ENOENT;
			if (!std::filesystem::is_directory(status)) return KERNEL_ERROR_ENOTDIR;
#endif
			return OK;
		};
		int status = check_component();
		if (status != OK) return status;
		for (const auto& component: path.relative_path()) {
			if (component.empty()) continue;
			if (component == "." || component == "..") return KERNEL_ERROR_EINVAL;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
			const auto name = component.native();
			if (name.find_first_of(L":<>\"|?*") != std::wstring::npos || name.back() == L'.' ||
			    name.back() == L' ')
				return KERNEL_ERROR_EINVAL;
#endif
			current /= component;
			status = check_component();
			if (status != OK) return status;
		}
		return OK;
	};
	int status = ordinary_directory(sysroot);
	if (status != OK) return status;
	if (!g_mount_points->IsReadOnly(sysroot)) return KERNEL_ERROR_EINVAL;
	std::error_code error;
	if (!std::filesystem::equivalent(sysroot, g_mount_points->ResolvePath("/"), error))
		return error ? host_error(error) : KERNEL_ERROR_EINVAL;
	const auto supplied           = sysroot / "system_tmp";
	status                        = ordinary_directory(supplied);
	const bool supplied_directory = status == OK;
	if (!supplied_directory && status != KERNEL_ERROR_ENOENT) return status;
	auto underlay = supplied;
	if (!supplied_directory) {
		status = ordinary_directory(directory);
		if (status != OK) return status;
		const auto source = std::filesystem::canonical(sysroot, error);
		if (error) return host_error(error);
		underlay = std::filesystem::canonical(directory, error);
		if (error) return host_error(error);
		const auto within = [](const std::filesystem::path& child,
		                       const std::filesystem::path& parent) {
			auto target = child.begin();
			for (auto part = parent.begin(); part != parent.end(); ++part, ++target) {
				if (target == child.end()) return false;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
				if (_wcsicmp(part->c_str(), target->c_str()) != 0) return false;
#else
				if (*part != *target) return false;
#endif
			}
			return true;
		};
		if (within(underlay, source) || within(source, underlay)) return KERNEL_ERROR_EINVAL;
		const bool empty = std::filesystem::is_empty(underlay, error);
		if (error) return host_error(error);
		if (!empty) return KERNEL_ERROR_ENOTEMPTY;
	}
	std::filesystem::path existing;
	if (g_mount_points->GetMountDirectory("/system_tmp", &existing)) {
		if (ordinary_directory(existing) != OK || !g_mount_points->IsReadOnly(existing) ||
		    !std::filesystem::equivalent(existing, underlay, error) || error)
			return KERNEL_ERROR_EBUSY;
	} else if (!supplied_directory) {
		MountReadOnly(underlay, "/system_tmp");
	}
	LOGF("INITIAL_SYSTEM_TMP_DIRECTORY source=%s guest=/system_tmp host=%s\n",
	     supplied_directory ? "supplied_sysroot" : "modeled_empty_underlay",
	     Common::PathToString(underlay).c_str());
	return OK;
}

uint16_t GetUmask() {
	return static_cast<uint16_t>(g_creation_mask.load(std::memory_order_relaxed));
}

int KYTY_SYSV_ABI KernelUmask(int mask) {
	return g_creation_mask.exchange(mask & 0777, std::memory_order_relaxed);
}

int MountTmpfs(const std::string& point, uint32_t mode, uint64_t byte_limit, uint32_t inode_limit) {
	std::lock_guard publication(g_mount_publication_mutex);
	if (g_tmpfs_status != OK) return g_tmpfs_status;
	if (ExfatMount::Overlaps(point) || BfsMount::Overlaps(point) ||
	    DirectoryPassthrough::Overlaps(point) || NullfsMount::Overlaps(point))
		return KERNEL_ERROR_EBUSY;
	const int traversal = ValidateMountedTraversal(point);
	if (traversal != OK) return traversal;
	std::string normalized;
	const int   parsed = Tmpfs::NormalizePath(point, &normalized);
	if (parsed != OK) return parsed;
	FileStat    covered {};
	std::string walked = "/";
	for (size_t start = 1; start <= point.size();) {
		const auto end       = point.find('/', start);
		const auto component = point.substr(start, end == std::string::npos ? end : end - start);
		if (!component.empty() && component != ".") {
			if (component == "..") {
				const auto slash = walked.find_last_of('/');
				walked.resize(slash == 0 ? 1 : slash);
			} else {
				if (walked.size() > 1) walked += '/';
				walked += component;
			}
		}
		const int status = KernelStat(walked.c_str(), &covered);
		if (status != OK) return status;
		if ((covered.st_mode & 0170000u) != 0040000u) return KERNEL_ERROR_ENOTDIR;
		if (end == std::string::npos) break;
		start = end + 1;
	}
	const int result =
	    Tmpfs::Mount(normalized, mode, byte_limit, inode_limit, covered.st_uid, covered.st_gid);
	if (result == OK)
		LOGF("TMPFS_MOUNTED path=%s mode=%o byte_limit=%" PRIu64
		     " inode_limit=%u backing=shared_memory\n",
		     normalized.c_str(), mode, byte_limit, inode_limit);
	return result;
}

int MountExfatReadOnly(const std::string& point, std::shared_ptr<ExfatVolume> volume) {
	std::lock_guard publication(g_mount_publication_mutex);
	if (g_mount_points == nullptr) return KERNEL_ERROR_ENOSYS;
	if (!volume) return KERNEL_ERROR_EINVAL;
	const int traversal = ValidateMountedTraversal(point);
	if (traversal != OK) return traversal;
	std::string normalized;
	const int   parsed = Tmpfs::NormalizePath(point, &normalized);
	if (parsed != OK) return parsed;
	if (Tmpfs::Overlaps(normalized) || DirectoryPassthrough::Overlaps(normalized) ||
	    BfsMount::Overlaps(normalized) || NullfsMount::Overlaps(normalized) ||
	    g_mount_points->HasSubmount(normalized))
		return KERNEL_ERROR_EBUSY;
	FileStat  covered {};
	const int existing = KernelStat(point.c_str(), &covered);
	if (existing != OK) return existing;
	if ((covered.st_mode & 0170000u) != 0040000u) return KERNEL_ERROR_ENOTDIR;
	return ExfatMount::Mount(normalized, std::move(volume));
}

int MountBfsReadOnly(const std::string& point, std::shared_ptr<BfsVolume> volume) {
	std::lock_guard publication(g_mount_publication_mutex);
	if (g_mount_points == nullptr) return KERNEL_ERROR_ENOSYS;
	if (!volume) return KERNEL_ERROR_EINVAL;
	const int traversal = ValidateMountedTraversal(point);
	if (traversal != OK) return traversal;
	std::string normalized;
	const int   parsed = Tmpfs::NormalizePath(point, &normalized);
	if (parsed != OK) return parsed;
	if (Tmpfs::Overlaps(normalized) || DirectoryPassthrough::Overlaps(normalized) ||
	    ExfatMount::Overlaps(normalized) || NullfsMount::Overlaps(normalized) ||
	    g_mount_points->HasSubmount(normalized))
		return KERNEL_ERROR_EBUSY;
	FileStat  covered {};
	const int existing = KernelStat(point.c_str(), &covered);
	if (existing != OK) return existing;
	if ((covered.st_mode & 0170000u) != 0040000u) return KERNEL_ERROR_ENOTDIR;
	return BfsMount::Mount(normalized, std::move(volume));
}

// nullfs may cover any directory vnode; stacking on a mount root or over submounts is refused
static bool NullfsPointBusy(const std::string& point) {
	const auto slash  = point.rfind('/');
	const auto parent = slash == 0 ? std::string("/") : point.substr(0, slash);
	const bool inside = Tmpfs::Contains(parent) || ExfatMount::Contains(parent) ||
	                    BfsMount::Contains(parent) || DirectoryPassthrough::Contains(parent);
	std::filesystem::path occupied;
	return (!inside && (Tmpfs::Overlaps(point) || ExfatMount::Overlaps(point) ||
	                    BfsMount::Overlaps(point) || DirectoryPassthrough::Overlaps(point))) ||
	       NullfsMount::Overlaps(point) || DevfsInstanceOverlaps(point) ||
	       g_mount_points->HasSubmount(point) ||
	       g_mount_points->GetMountDirectory(point, &occupied);
}

// fresh directory vnodes per devfs mount, inodes from the global devfs_inos unrhdr (lowest free);
// cdev inodes shared with /dev
int MountDevfs(const std::string& point) {
	std::lock_guard publication(g_mount_publication_mutex);
	if (g_mount_points == nullptr || DevfsRootListing() == nullptr || DevfsHeldInodes() == nullptr)
		return KERNEL_ERROR_EOPNOTSUPP;
	int result = ValidateNullfsTraversal(point);
	if (result != OK) return result;
	std::string normalized;
	result = Tmpfs::NormalizePath(point, &normalized);
	if (result != OK) return result;
	if (normalized == "/dev" || NullfsPointBusy(normalized)) return KERNEL_ERROR_EBUSY;
	FileStat target {};
	result = KernelStat(normalized.c_str(), &target);
	if (result != OK) return result;
	if ((target.st_mode & 0170000u) != 0040000u) return KERNEL_ERROR_ENOTDIR;
	std::vector<uint32_t> used = *DevfsHeldInodes();
	for (const auto& entry: *DevfsRootListing())
		used.push_back(entry.inode);
	DevfsInstance   instance {normalized, {}};
	std::lock_guard lock(g_devfs_instances_mutex);
	for (const auto& live: g_devfs_instances)
		used.insert(used.end(), live.directories.begin(), live.directories.end());
	std::sort(used.begin(), used.end());
	uint32_t candidate = 3;
	for (const auto& entry: *DevfsRootListing()) {
		if (entry.type != 4) continue;
		while (std::binary_search(used.begin(), used.end(), candidate))
			candidate++;
		instance.directories.push_back(candidate++);
	}
	std::string inodes;
	for (auto inode: instance.directories)
		inodes += (inodes.empty() ? "" : ",") + std::to_string(inode);
	LOGF("DEVFS_INSTANCE_MOUNTED path=%s dir_inodes=%s\n", normalized.c_str(), inodes.c_str());
	g_devfs_instances.push_back(std::move(instance));
	return OK;
}

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
// nullfs mounts are kernel-global on the console. ShellCore builds /mnt/sandbox in its own process
// while SysCore execs the app, so they're published run-wide and the app imports those under its
// chroot.
struct SharedSandboxMounts {
	static constexpr uint64_t Signature = 0x3176534d42444e53ull;
	struct Entry {
		uint32_t used;
		uint32_t device;
		uint32_t inode;
		uint32_t reserved;
		uint64_t flags;
		char     point[512];
		char     source[512];
	};
	uint64_t signature;
	Entry    entries[1024];
};

class SharedSandboxLock {
public:
	SharedSandboxLock() {
		static std::once_flag       once;
		static HANDLE               mutex = nullptr;
		static SharedSandboxMounts* table = nullptr;
		std::call_once(once, [] {
			std::string scope;
			if (!Process::GetScope(&scope)) return;
			const auto name          = "Local\\kyty_ps5_" + scope + "_sandbox_mounts_v1";
			HANDLE     created_mutex = CreateMutexA(nullptr, FALSE, (name + "_lock").c_str());
			HANDLE     section =
			    CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
				                   sizeof(SharedSandboxMounts), (name + "_state").c_str());
			if (created_mutex == nullptr || section == nullptr) {
				LOGF("SANDBOX_MOUNT_TABLE unavailable error=%lu\n", GetLastError());
				return;
			}
			auto* view = static_cast<SharedSandboxMounts*>(MapViewOfFile(
			    section, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(SharedSandboxMounts)));
			if (view == nullptr) return;
			mutex = created_mutex;
			table = view;
		});
		if (mutex == nullptr) return;
		const DWORD wait = WaitForSingleObject(mutex, INFINITE);
		if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) return;
		m_mutex = mutex;
		if (table->signature == 0) table->signature = SharedSandboxMounts::Signature;
		if (table->signature == SharedSandboxMounts::Signature) m_table = table;
	}
	~SharedSandboxLock() {
		if (m_mutex != nullptr) ReleaseMutex(m_mutex);
	}
	SharedSandboxMounts* table() const { return m_table; }

private:
	HANDLE               m_mutex = nullptr;
	SharedSandboxMounts* m_table = nullptr;
};

static void PublishSandboxMount(const std::string& point, const std::string& source, uint64_t flags,
                                uint32_t device, uint32_t inode) {
	if (!point.starts_with("/mnt/sandbox/")) return;
	if (point.size() >= sizeof(SharedSandboxMounts::Entry::point) ||
	    source.size() >= sizeof(SharedSandboxMounts::Entry::source)) {
		LOGF("SANDBOX_MOUNT_PUBLISH path=%s skipped=name_too_long\n", point.c_str());
		return;
	}
	SharedSandboxLock lock;
	if (lock.table() == nullptr) return;
	SharedSandboxMounts::Entry* slot = nullptr;
	for (auto& entry: lock.table()->entries) {
		if (entry.used != 0 && point == entry.point) {
			slot = &entry;
			break;
		}
		if (entry.used == 0 && slot == nullptr) slot = &entry;
	}
	if (slot == nullptr) {
		LOGF("SANDBOX_MOUNT_PUBLISH path=%s skipped=table_full\n", point.c_str());
		return;
	}
	std::memset(slot, 0, sizeof(*slot));
	std::memcpy(slot->point, point.c_str(), point.size());
	std::memcpy(slot->source, source.c_str(), source.size());
	slot->flags  = flags;
	slot->device = device;
	slot->inode  = inode;
	slot->used   = 1;
}

static void RetractSandboxMount(const std::string& point) {
	if (!point.starts_with("/mnt/sandbox/")) return;
	SharedSandboxLock lock;
	if (lock.table() == nullptr) return;
	for (auto& entry: lock.table()->entries) {
		if (entry.used != 0 && point == entry.point) entry.used = 0;
	}
}
#else
static void PublishSandboxMount(const std::string&, const std::string&, uint64_t, uint32_t,
                                uint32_t) {}
static void RetractSandboxMount(const std::string&) {}
#endif

int ImportExecSandboxMounts(const std::string& root, const std::string& word) try {
	std::string normalized_root;
	int         result = Tmpfs::NormalizePath(root, &normalized_root);
	if (result != OK || normalized_root == "/" || word.empty() || word.find('/') != word.npos) {
		LOGF("GUEST_EXEC_SANDBOX_MOUNTS root=%s word=%s imported=0 rejected=0 "
		     "skipped=unusable_root_or_word\n",
		     root.c_str(), word.c_str());
		return KERNEL_ERROR_EINVAL;
	}
	// only the randomized system tree, the child mounts app0, dev and system_tmp itself
	const std::string                       prefix = normalized_root + "/" + word;
	std::vector<SharedSandboxMounts::Entry> selected;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	{
		SharedSandboxLock lock;
		if (lock.table() == nullptr) return KERNEL_ERROR_ENOSYS;
		for (const auto& entry: lock.table()->entries) {
			if (entry.used == 0) continue;
			const std::string_view point(entry.point);
			if (point == prefix || (point.starts_with(prefix) && point[prefix.size()] == '/'))
				selected.push_back(entry);
		}
	}
#endif
	std::lock_guard publication(g_mount_publication_mutex);
	if (g_mount_points == nullptr) return KERNEL_ERROR_ENOSYS;
	size_t imported = 0, rejected = 0;
	for (const auto& entry: selected) {
		const std::string point = std::string(entry.point).substr(normalized_root.size());
		FileStat          lower {};
		result = KernelStat(entry.source, &lower);
		if (result == OK && (lower.st_dev != entry.device || lower.st_ino != entry.inode))
			result = KERNEL_ERROR_ESTALE;
		if (result == OK) result = NullfsMount::Mount(point, entry.source, entry.flags);
		if (result != OK) {
			rejected++;
			LOGF("GUEST_EXEC_SANDBOX_MOUNT_REJECTED path=%s source=%s error=0x%x\n", point.c_str(),
			     entry.source, result);
			continue;
		}
		imported++;
	}
	LOGF("GUEST_EXEC_SANDBOX_MOUNTS root=%s word=%s imported=%zu rejected=%zu\n",
	     normalized_root.c_str(), word.c_str(), imported, rejected);
	return rejected == 0 ? OK : KERNEL_ERROR_EINVAL;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int MountNullfs(const std::string& source, const std::string& point, uint64_t flags) {
	std::lock_guard publication(g_mount_publication_mutex);
	if (g_mount_points == nullptr) return KERNEL_ERROR_ENOSYS;
	int traversal = ValidateNullfsTraversal(source);
	if (traversal != OK) return traversal;
	traversal = ValidateNullfsTraversal(point);
	if (traversal != OK) return traversal;
	std::string normalized_source;
	std::string normalized_point;
	int         result = Tmpfs::NormalizePath(source, &normalized_source);
	if (result != OK) return result;
	result = Tmpfs::NormalizePath(point, &normalized_point);
	if (result != OK) return result;
	if (NullfsPointBusy(normalized_point)) return KERNEL_ERROR_EBUSY;
	FileStat target {};
	result = KernelStat(normalized_point.c_str(), &target);
	if (result != OK) {
		LOGF("NULLFS_REJECTED path=%s source=%s stage=target_stat error=0x%x\n",
		     normalized_point.c_str(), normalized_source.c_str(), result);
		return result;
	}
	if ((target.st_mode & 0170000u) != 0040000u) {
		LOGF("NULLFS_REJECTED path=%s source=%s stage=target_type error=0x%x\n",
		     normalized_point.c_str(), normalized_source.c_str(), KERNEL_ERROR_ENOTDIR);
		return KERNEL_ERROR_ENOTDIR;
	}
	result = ValidateMountedTraversal(source);
	if (result != OK) return result;
	FileStat lower {};
	result = KernelStat(normalized_source.c_str(), &lower);
	if (result != OK) {
		LOGF("NULLFS_REJECTED path=%s source=%s stage=source_stat error=0x%x\n",
		     normalized_point.c_str(), normalized_source.c_str(), result);
		return result;
	}
	if ((lower.st_mode & 0170000u) != 0040000u) {
		LOGF("NULLFS_REJECTED path=%s source=%s stage=source_type error=0x%x\n",
		     normalized_point.c_str(), normalized_source.c_str(), KERNEL_ERROR_ENOTDIR);
		return KERNEL_ERROR_ENOTDIR;
	}
	result = NullfsMount::Mount(normalized_point, normalized_source, flags);
	if (result == OK) {
		LOGF("NULLFS_MOUNTED path=%s source=%s lower_dev=0x%x lower_inode=0x%x flags=0x%llx\n",
		     normalized_point.c_str(), normalized_source.c_str(), lower.st_dev, lower.st_ino,
		     static_cast<unsigned long long>(flags));
		PublishSandboxMount(normalized_point, normalized_source, flags, lower.st_dev, lower.st_ino);
	}
	return result;
}

int MountRegisteredExfatReadOnly(const std::string& device, const std::string& point) {
	auto backing = FindSectorPayload(device);
	if (!backing) return KERNEL_ERROR_ENOENT;
	if (!backing->ReadOnly()) return KERNEL_ERROR_EROFS;
	ExfatVolume::Result          opened;
	std::shared_ptr<ExfatVolume> volume = ExfatVolume::Open(std::move(backing), &opened);
	if (!volume) {
		switch (opened) {
			case ExfatVolume::Result::Invalid: return KERNEL_ERROR_EINVAL;
			case ExfatVolume::Result::NotFound: return KERNEL_ERROR_ENOENT;
			case ExfatVolume::Result::NotDirectory: return KERNEL_ERROR_ENOTDIR;
			case ExfatVolume::Result::IsDirectory: return KERNEL_ERROR_EISDIR;
			case ExfatVolume::Result::Unsupported: return KERNEL_ERROR_ENOTSUP;
			default: return KERNEL_ERROR_EIO;
		}
	}
	return MountExfatReadOnly(point, std::move(volume));
}

int MountRegisteredBfs(const std::string& device, const std::string& point) {
	auto backing = FindSectorPayload(device);
	if (!backing) return KERNEL_ERROR_ENOENT;
	if (!backing->ReadOnly()) return KERNEL_ERROR_EROFS;
	BfsVolume::Options options;
	const auto         slash = device.rfind('/');
	options.partition_name   = slash == std::string::npos ? device : device.substr(slash + 1);
	BfsVolume::Result          opened;
	std::shared_ptr<BfsVolume> volume = BfsVolume::Open(std::move(backing), options, &opened);
	if (!volume) {
		switch (opened) {
			case BfsVolume::Result::Invalid: return KERNEL_ERROR_EINVAL;
			case BfsVolume::Result::NotFound: return KERNEL_ERROR_ENOENT;
			case BfsVolume::Result::NotDirectory: return KERNEL_ERROR_ENOTDIR;
			case BfsVolume::Result::IsDirectory: return KERNEL_ERROR_EISDIR;
			case BfsVolume::Result::Unsupported: return KERNEL_ERROR_ENOTSUP;
			case BfsVolume::Result::MissingData: return KERNEL_ERROR_EIO;
			case BfsVolume::Result::Corrupt: return KERNEL_ERROR_EIO;
			default: return KERNEL_ERROR_EIO;
		}
	}
	const int result = MountBfsReadOnly(point, std::move(volume));
	if (result == OK) {
		LOGF("BFS_MOUNTED device=%s point=%s partition=%s\n", device.c_str(), point.c_str(),
		     options.partition_name.c_str());
	}
	return result;
}

static std::string ReadOnlyProviderPoint(const std::string& device) {
	if (device == "/dev/lvd0") return "/mnt/rnps";
	if (device != "/dev/ssd0.system" && device != "/dev/ssd0.system_b" &&
	    device != "/dev/ssd0.system_ex" && device != "/dev/ssd0.system_ex_b" &&
	    device != "/dev/ssd0.system_data" && device != "/dev/ssd0.system_data_b" &&
	    device != "/dev/ssd0.update" && device != "/dev/ssd0.update_b" &&
	    device != "/dev/ssd0.preinst" && device != "/dev/ssd0.preinst_b" &&
	    device != "/dev/ssd0.user")
		return {};
	return "/" + device.substr(sizeof("/dev/ssd0.") - 1);
}

static std::string ReadOnlyProviderFileSystemType(const std::string& device) {
	return device.starts_with("/dev/ssd0.") ? "exfatfs" : "";
}

static bool SameProviderRoot(const std::filesystem::path& left,
                             const std::filesystem::path& right) {
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	return _wcsicmp(left.c_str(), right.c_str()) == 0;
#else
	return left == right;
#endif
}

static int ReadProviderRoot(const std::filesystem::path& supplied, std::filesystem::path* root,
                            std::string* identity) {
	if (!supplied.is_absolute() || supplied.native().find(std::filesystem::path::value_type {}) !=
	                                   std::filesystem::path::string_type::npos)
		return KERNEL_ERROR_EINVAL;
	if (Common::PathToString(supplied).find_first_of("\r\n") != std::string::npos)
		return KERNEL_ERROR_EINVAL;
	std::error_code error;
	auto            canonical = std::filesystem::canonical(supplied, error);
	if (error || !std::filesystem::is_directory(canonical, error)) return KERNEL_ERROR_ENOENT;
	if (Common::PathToString(canonical).find_first_of("\r\n") != std::string::npos)
		return KERNEL_ERROR_EINVAL;
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	const auto handle =
	    CreateFileW(canonical.c_str(), FILE_READ_ATTRIBUTES,
		            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
		            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
	if (handle == INVALID_HANDLE_VALUE) return KERNEL_ERROR_EIO;
	BY_HANDLE_FILE_INFORMATION info {};
	const bool                 inspected = GetFileInformationByHandle(handle, &info) != FALSE;
	CloseHandle(handle);
	if (!inspected) return KERNEL_ERROR_EIO;
	if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) return KERNEL_ERROR_ELOOP;
	*identity = std::to_string(info.dwVolumeSerialNumber) + ":" +
	            std::to_string(info.nFileIndexHigh) + ":" + std::to_string(info.nFileIndexLow);
#else
	struct stat info {};
	if (::stat(canonical.c_str(), &info) != 0) return KERNEL_ERROR_EIO;
	*identity = std::to_string(info.st_dev) + ":" + std::to_string(info.st_ino);
#endif
	*root = std::move(canonical);
	return OK;
}

static bool FindPassthroughRegistration(const std::string&       device,
                                        PassthroughRegistration* registration) {
	std::lock_guard lock(g_passthrough_registration_mutex);
	for (const auto& entry: g_passthrough_registrations) {
		if (entry.device == device) {
			*registration = entry;
			return true;
		}
	}
	return false;
}

static int ValidateProviderRegistration(const PassthroughRegistration& registration) {
	std::filesystem::path root;
	std::string           identity;
	const int             result = ReadProviderRoot(registration.supplied_root, &root, &identity);
	if (result != OK) return result;
	return SameProviderRoot(root, registration.root) && identity == registration.identity
	           ? OK
			   : KERNEL_ERROR_EINVAL;
}

bool HasCapturedPartitionPassthrough(const std::string& device) {
	PassthroughRegistration registration;
	return FindPassthroughRegistration(device, &registration) &&
	       CapturedDirectory::ForRoot(registration.root) != nullptr;
}

static int AttachSystemResourceArbitratorCapture(const std::string& device,
                                                 const std::string& point) {
	if (device != "/dev/ssd0.system" || point != "/system") return OK;
	constexpr std::string_view captured_manifest_sha256 =
	    "a45253eea9da61dc2b3c7bfd50905aa64995646fcee782cc680517879be612b0";
	// derived manifest (some payloads withheld) has its own digest
	const char* derived_manifest_sha256 = std::getenv("KYTY_PS5_CAPTURED_STORAGE_DERIVED_SHA256");
	const std::string manifest_sha256 =
	    derived_manifest_sha256 != nullptr && derived_manifest_sha256[0] != '\0'
	        ? std::string(derived_manifest_sha256)
	        : std::string(captured_manifest_sha256);
	constexpr std::string_view prefix = "/priv/resource_arbitrator_ro";
	constexpr std::string_view file   = "/priv/resource_arbitrator_ro/ra-config.json";
	constexpr std::string_view file_sha256 =
	    "d9479085076615484a2a443b7b1ee6725a9f7701225696a63581a636b328c71a";
	const auto snapshot = CapturedDirectory::ForPoint(point);
	if (!snapshot) return OK;
	if (snapshot->manifest_sha256 != manifest_sha256) return KERNEL_ERROR_EINVAL;
	const CapturedDirectory::Entry* entry = nullptr;
	const int                       found = CapturedDirectory::Find(*snapshot, file, &entry);
	if (found != OK) return found;
	if (!entry->metadata || entry->type != 8 || entry->stat.size != 10333 || entry->file.empty() ||
	    entry->sha256 != file_sha256)
		return KERNEL_ERROR_EINVAL;
	const int attached =
	    DirectoryPassthrough::AttachCapturedFallback(point, std::string(prefix), manifest_sha256);
	if (attached != OK) return attached;
	LOGF("STORAGE_CAPTURED_FALLBACK_MOUNTED point=/system prefix=/priv/resource_arbitrator_ro "
	     "manifest_sha256=%s file_sha256=%s read_only=1 derived=%d\n",
	     manifest_sha256.c_str(), file_sha256.data(),
	     manifest_sha256 != captured_manifest_sha256 ? 1 : 0);
	// what the decrypted primary lacks, data only
	static constexpr std::string_view data_prefixes[] = {
	    "/common/cert",
	    "/common/etc",
	    "/common/font2",
	    "/common/mms_ro",
	    "/common/psml_package",
	    "/common/text_to_speech",
	    "/common/lib/0VCZq_7VjvwjsFYg8xirSTau96ShhC6SD95Lnjb2tCE.sbin",
	    "/common/lib/0VCZq_7VjvwjsFYg8xirSTau96ShhC6SD95Lnjb2tCE_r2.sbin",
	    "/common/lib/N4pyqHm8htvejpjmzEmWm0JvkKU60YeyEEPs4BodCBw.sbin",
	    "/common/lib/N4pyqHm8htvejpjmzEmWm0JvkKU60YeyEEPs4BodCBw_r2.sbin",
	    "/common/lib/ScePlayReady4.sbin",
	    "/common/lib/ScePlayReady4_r2.sbin",
	    "/priv/bd",
	    "/priv/bgdc_ro",
	    "/priv/etc",
	    "/priv/hid_config_service_ro",
	    "/priv/mms_ro",
	    "/priv/ps4appcategory_ro",
	    "/priv/ps4sisrctl_ro",
	    "/priv/psnow_ro",
	    "/priv/system_logger2_ro",
	    "/priv/title_separation_ro",
	    "/priv/tts",
	    "/priv/voice_and_agent_ro",
	    "/priv/vr_hand_ro",
	    "/priv/workaround_ctl_ro",
	    "/sys/minimum_hrtf.dat",
	    "/sys/minimum_tri_table.dat",
	    "/sys/preset1.srtf",
	    "/sys/preset2.srtf",
	    "/sys/preset3.srtf",
	    "/sys/preset4.srtf",
	    "/sys/preset5.srtf",
	    "/sys/preset_tri_table.dat",
	    "/sys/vsh_prefetch_list.dat",
	    "/vsh/app",
	    "/vsh_asset",
	};
	for (const auto data_prefix: data_prefixes) {
		const int data = DirectoryPassthrough::AttachCapturedFallback(
		    point, std::string(data_prefix), manifest_sha256);
		if (data != OK) return data;
	}
	LOGF("STORAGE_CAPTURED_FALLBACK_DATA_MOUNTED point=/system prefixes=%zu manifest_sha256=%s "
	     "read_only=1\n",
	     std::size(data_prefixes), manifest_sha256.c_str());
	return OK;
}

int RegisterDiagnosticPartitionPassthrough(const std::string&           device,
                                           const std::filesystem::path& host_root) try {
	if (ReadOnlyProviderPoint(device).empty()) return KERNEL_ERROR_EINVAL;
	PassthroughRegistration registration {device, host_root, {}, {}};
	const int result = ReadProviderRoot(host_root, &registration.root, &registration.identity);
	if (result != OK) return result;
	std::lock_guard lock(g_passthrough_registration_mutex);
	for (const auto& entry: g_passthrough_registrations)
		if (entry.device == device) return KERNEL_ERROR_EEXIST;
	g_passthrough_registrations.push_back(std::move(registration));
	const auto u8 = host_root.u8string();
	LOGF("STORAGE_PASSTHROUGH_REGISTERED device=%s host_root=%s NON_AUTHENTIC=1\n", device.c_str(),
	     reinterpret_cast<const char*>(u8.c_str()));
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int MountRegisteredPartitionPassthrough(const std::string& device, const std::string& point,
                                        bool writable) try {
	PassthroughRegistration registration;
	if (!FindPassthroughRegistration(device, &registration)) return KERNEL_ERROR_ENOENT;
	const int valid = ValidateProviderRegistration(registration);
	if (valid != OK) return valid;
	std::lock_guard publication(g_mount_publication_mutex);
	if (device.starts_with("/dev/lvd")) {
		const int lvd = ValidateLvdUfsPassthrough(device);
		if (lvd != OK) return lvd;
	}
	if (g_mount_points == nullptr) return KERNEL_ERROR_ENOSYS;
	const int traversal = ValidateMountedTraversal(point);
	if (traversal != OK) return traversal;
	std::string normalized;
	const int   parsed = Tmpfs::NormalizePath(point, &normalized);
	if (parsed != OK) return parsed;
	if (Tmpfs::Overlaps(normalized) || ExfatMount::Overlaps(normalized) ||
	    BfsMount::Overlaps(normalized) || NullfsMount::Overlaps(normalized) ||
	    g_mount_points->HasSubmount(normalized))
		return KERNEL_ERROR_EBUSY;
	FileStat  covered {};
	const int existing = KernelStat(point.c_str(), &covered);
	if (existing != OK) return existing;
	if ((covered.st_mode & 0170000u) != 0040000u) return KERNEL_ERROR_ENOTDIR;
	auto published = g_published_read_only_providers;
	if (normalized == ReadOnlyProviderPoint(device)) published.push_back({device, normalized});
	const auto     guest_fstype = ReadOnlyProviderFileSystemType(device);
	const auto     guest_source = guest_fstype.empty() ? std::string {} : device;
	const uint64_t guest_flags  = guest_fstype.empty() || writable ? 0 : 1;
	int result = DirectoryPassthrough::Mount(normalized, registration.root, writable, guest_fstype,
	                                         guest_source, guest_flags);
	if (result == OK) {
		result = AttachSystemResourceArbitratorCapture(device, normalized);
		if (result != OK) {
			DirectoryPassthrough::Unmount(normalized);
			return result;
		}
		g_published_read_only_providers.swap(published);
		const auto u8 = registration.root.u8string();
		LOGF("STORAGE_PASSTHROUGH_MOUNTED device=%s point=%s host_root=%s NON_AUTHENTIC=1\n",
		     device.c_str(), point.c_str(), reinterpret_cast<const char*>(u8.c_str()));
	}
	return result;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int ExportExecReadOnlyProviders(std::string* manifest) try {
	if (!manifest) return KERNEL_ERROR_EFAULT;
	std::lock_guard publication(g_mount_publication_mutex);
	if (g_mount_points == nullptr) return KERNEL_ERROR_ENOSYS;
	if (g_published_read_only_providers.size() > 16) return KERNEL_ERROR_E2BIG;
	std::ostringstream output;
	output << "KYTY_EXEC_RO_PROVIDERS 3\n";
	for (const auto& binding: g_published_read_only_providers) {
		PassthroughRegistration registration;
		if (!FindPassthroughRegistration(binding.device, &registration)) return KERNEL_ERROR_ENOENT;
		const int valid = ValidateProviderRegistration(registration);
		if (valid != OK) return valid;
		DirectoryPassthrough::MountInfo info;
		const int described = DirectoryPassthrough::DescribeMount(binding.point, &info);
		if (described != OK) return described;
		const auto     guest_fstype = ReadOnlyProviderFileSystemType(binding.device);
		const auto     guest_source = guest_fstype.empty() ? std::string {} : binding.device;
		const uint64_t guest_flags  = guest_fstype.empty() || info.writable ? 0 : 1;
		if (binding.point != ReadOnlyProviderPoint(binding.device) ||
		    !SameProviderRoot(info.host_root, registration.root) ||
		    info.guest_fstype != guest_fstype || info.guest_source != guest_source ||
		    info.guest_flags != guest_flags)
			return KERNEL_ERROR_EINVAL;
		output << "P " << std::quoted(binding.device) << ' ' << std::quoted(binding.point) << ' '
		       << std::quoted(Common::PathToString(registration.root)) << ' '
		       << std::quoted(registration.identity) << ' ' << info.device << " G "
		       << std::quoted(info.guest_fstype) << ' ' << std::quoted(info.guest_source) << ' '
		       << info.guest_flags;
		if (info.writable) output << " W";
		if (!info.manifest_sha256.empty()) output << " C " << info.manifest_sha256;
		if (!info.fallback_prefixes.empty()) {
			if (info.fallback_manifest_sha256.empty()) return KERNEL_ERROR_EINVAL;
			output << " F ";
			for (const auto& prefix: info.fallback_prefixes)
				output << std::quoted(prefix) << ' ';
			output << info.fallback_manifest_sha256;
		} else if (!info.fallback_manifest_sha256.empty()) {
			return KERNEL_ERROR_EINVAL;
		}
		output << '\n';
	}
	output << "END\n";
	auto encoded = output.str();
	if (encoded.size() > 65536) return KERNEL_ERROR_E2BIG;
	*manifest = std::move(encoded);
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int ImportExecReadOnlyProviders(const std::string& manifest) try {
	if (manifest.size() > 65536) return KERNEL_ERROR_E2BIG;
	if (manifest.find('\0') != manifest.npos) return KERNEL_ERROR_EINVAL;
	struct Binding {
		PublishedReadOnlyProvider       provider;
		DirectoryPassthrough::MountInfo mount;
	};
	std::vector<Binding> bindings;
	std::istringstream   input(manifest);
	std::string          line;
	if (!std::getline(input, line) || line != "KYTY_EXEC_RO_PROVIDERS 3")
		return KERNEL_ERROR_EINVAL;
	bool            complete = false;
	std::lock_guard publication(g_mount_publication_mutex);
	if (g_mount_points == nullptr) return KERNEL_ERROR_ENOSYS;
	while (std::getline(input, line)) {
		if (line == "END") {
			complete = true;
			break;
		}
		if (bindings.size() >= 16) return KERNEL_ERROR_E2BIG;
		if (!line.starts_with("P ")) return KERNEL_ERROR_EINVAL;
		size_t     cursor = 2;
		const auto quoted = [&](std::string* value) {
			if (cursor == line.size() || line[cursor++] != '"') return false;
			while (cursor < line.size()) {
				char character = line[cursor++];
				if (character == '"') return true;
				if (character == '\\') {
					if (cursor == line.size() || (line[cursor] != '\\' && line[cursor] != '"'))
						return false;
					character = line[cursor++];
				}
				value->push_back(character);
			}
			return false;
		};
		const auto separator = [&]() {
			const size_t start = cursor;
			while (cursor < line.size() && (line[cursor] == ' ' || line[cursor] == '\t'))
				++cursor;
			return cursor != start;
		};
		std::string device, point, root_text, identity;
		if (!quoted(&device) || !separator() || !quoted(&point) || !separator() ||
		    !quoted(&root_text) || !separator() || !quoted(&identity) || !separator())
			return KERNEL_ERROR_EINVAL;
		const size_t digits       = cursor;
		uint32_t     mount_device = 0;
		while (cursor < line.size() && line[cursor] >= '0' && line[cursor] <= '9') {
			const uint32_t digit = static_cast<uint32_t>(line[cursor++] - '0');
			if (mount_device > (UINT32_MAX - digit) / 10) return KERNEL_ERROR_EINVAL;
			mount_device = mount_device * 10 + digit;
		}
		const size_t digit_end = cursor;
		if (line.compare(cursor, 3, " G ") != 0) return KERNEL_ERROR_EINVAL;
		cursor += 3;
		std::string guest_fstype, guest_source;
		if (!quoted(&guest_fstype) || !separator() || !quoted(&guest_source) || !separator()) {
			return KERNEL_ERROR_EINVAL;
		}
		const size_t flag_digits = cursor;
		uint64_t     guest_flags = 0;
		while (cursor < line.size() && line[cursor] >= '0' && line[cursor] <= '9') {
			const uint64_t digit = static_cast<uint64_t>(line[cursor++] - '0');
			if (guest_flags > (UINT64_MAX - digit) / 10) return KERNEL_ERROR_EINVAL;
			guest_flags = guest_flags * 10 + digit;
		}
		const size_t flag_end = cursor;
		const bool   writable = line.compare(cursor, 2, " W") == 0 &&
		                        (cursor + 2 == line.size() || line[cursor + 2] == ' ');
		if (writable) cursor += 2;
		std::string              metadata_sha256, fallback_sha256;
		std::vector<std::string> fallback_prefixes;
		if (line.substr(cursor, 3) == " C ") {
			cursor += 3;
			if (line.size() - cursor < 64) return KERNEL_ERROR_EINVAL;
			metadata_sha256 = line.substr(cursor, 64);
			AuthInfo::Digest digest;
			if (!AuthInfo::ParseDigestHex(metadata_sha256, &digest)) return KERNEL_ERROR_EINVAL;
			cursor += 64;
		}
		if (cursor != line.size()) {
			if (line.substr(cursor, 3) != " F ") return KERNEL_ERROR_EINVAL;
			cursor += 3;
			do {
				if (fallback_prefixes.size() >= 64) return KERNEL_ERROR_EINVAL;
				if (!quoted(&fallback_prefixes.emplace_back()) || !separator())
					return KERNEL_ERROR_EINVAL;
			} while (cursor < line.size() && line[cursor] == '"');
			fallback_sha256 = line.substr(cursor);
			AuthInfo::Digest digest;
			if (!AuthInfo::ParseDigestHex(fallback_sha256, &digest)) return KERNEL_ERROR_EINVAL;
			cursor = line.size();
		}
		if (digit_end == digits || flag_end == flag_digits || cursor != line.size() ||
		    (digit_end - digits > 1 && line[digits] == '0') ||
		    (flag_end - flag_digits > 1 && line[flag_digits] == '0') ||
		    point != ReadOnlyProviderPoint(device) || point.empty() || mount_device < 0xef100000u ||
		    mount_device >= UINT32_MAX)
			return KERNEL_ERROR_EINVAL;
		for (const auto& binding: bindings) {
			if (binding.provider.point == point || binding.mount.device == mount_device)
				return KERNEL_ERROR_EINVAL;
		}
		PassthroughRegistration registration;
		if (!FindPassthroughRegistration(device, &registration)) return KERNEL_ERROR_ENOENT;
		const int valid = ValidateProviderRegistration(registration);
		if (valid != OK) return valid;
		const auto root = Common::PathFromUtf8(root_text);
		if (!SameProviderRoot(root, registration.root) || identity != registration.identity)
			return KERNEL_ERROR_EINVAL;
		const auto snapshot = CapturedDirectory::ForRoot(registration.root);
		if ((snapshot ? snapshot->manifest_sha256 : "") != metadata_sha256)
			return KERNEL_ERROR_EINVAL;
		std::filesystem::path occupied;
		if (Tmpfs::Overlaps(point) || ExfatMount::Overlaps(point) || BfsMount::Overlaps(point) ||
		    DirectoryPassthrough::Overlaps(point) || NullfsMount::Overlaps(point) ||
		    g_mount_points->HasSubmount(point) ||
		    g_mount_points->GetMountDirectory(point, &occupied))
			return KERNEL_ERROR_EBUSY;
		const int traversal = ValidateMountedTraversal(point);
		if (traversal != OK) return traversal;
		FileStat  stat {};
		const int existing = KernelStat(point.c_str(), &stat);
		if (existing != OK) return existing;
		if ((stat.st_mode & 0170000u) != 0040000u) return KERNEL_ERROR_ENOTDIR;
		const auto     expected_fstype = ReadOnlyProviderFileSystemType(device);
		const auto     expected_source = expected_fstype.empty() ? std::string {} : device;
		const uint64_t expected_flags  = expected_fstype.empty() || writable ? 0 : 1;
		if (guest_fstype != expected_fstype || guest_source != expected_source ||
		    guest_flags != expected_flags)
			return KERNEL_ERROR_EINVAL;
		bindings.push_back(
		    {{device, point},
			 {point, registration.root, mount_device, metadata_sha256, fallback_prefixes,
			  fallback_sha256, writable, guest_fstype, guest_source, guest_flags}});
	}
	input >> std::ws;
	if (!complete || !input.eof()) return KERNEL_ERROR_EINVAL;
	auto published = g_published_read_only_providers;
	published.reserve(published.size() + bindings.size());
	for (const auto& binding: bindings)
		published.push_back(binding.provider);
	std::vector<DirectoryPassthrough::MountInfo> mounts;
	mounts.reserve(bindings.size());
	for (const auto& binding: bindings)
		mounts.push_back(binding.mount);
	const int result = DirectoryPassthrough::ImportReadOnlyMounts(mounts);
	if (result != OK) return result;
	g_published_read_only_providers.swap(published);
	LOGF("GUEST_EXEC_READ_ONLY_PROVIDERS imported=%zu mutable_mounts_transferred=%zu\n",
	     bindings.size(),
	     static_cast<size_t>(std::count_if(mounts.begin(), mounts.end(),
	                                       [](const auto& mount) { return mount.writable; })));
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
} catch (const std::filesystem::filesystem_error&) {
	return KERNEL_ERROR_EINVAL;
}

int ExportExecNullfsMounts(std::string* manifest) try {
	if (manifest == nullptr) return KERNEL_ERROR_EFAULT;
	std::lock_guard publication(g_mount_publication_mutex);
	if (g_mount_points == nullptr) return KERNEL_ERROR_ENOSYS;
	std::vector<NullfsMount::MountInfo> mounts;
	const int                           snapshot = NullfsMount::SnapshotMounts(&mounts);
	if (snapshot != OK) return snapshot;
	std::ostringstream output;
	output << "KYTY_EXEC_NULLFS 1\n";
	for (const auto& mount: mounts) {
		if (mount.point.find_first_of("\r\n") != mount.point.npos ||
		    mount.source.find_first_of("\r\n") != mount.source.npos)
			return KERNEL_ERROR_EINVAL;
		FileStat  lower {};
		const int result = KernelStat(mount.source.c_str(), &lower);
		if (result != OK) return result;
		if ((lower.st_mode & 0170000u) != 0040000u) return KERNEL_ERROR_ENOTDIR;
		output << (mount.flags != 0 ? "F " : "N ") << std::quoted(mount.point) << ' '
		       << std::quoted(mount.source) << ' ' << lower.st_dev << ' ' << lower.st_ino;
		if (mount.flags != 0) output << ' ' << mount.flags;
		output << '\n';
	}
	output << "END\n";
	auto encoded = output.str();
	if (encoded.size() > 65536) return KERNEL_ERROR_E2BIG;
	*manifest = std::move(encoded);
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

int ImportExecNullfsMounts(const std::string& manifest) try {
	if (manifest.size() > 65536) return KERNEL_ERROR_E2BIG;
	if (manifest.find('\0') != manifest.npos) return KERNEL_ERROR_EINVAL;
	struct Binding {
		NullfsMount::MountInfo mount;
		uint32_t               device;
		uint32_t               inode;
	};
	std::vector<Binding> bindings;
	std::istringstream   input(manifest);
	std::string          line;
	if (!std::getline(input, line) || line != "KYTY_EXEC_NULLFS 1") return KERNEL_ERROR_EINVAL;
	bool complete = false;
	while (std::getline(input, line)) {
		if (line == "END") {
			complete = true;
			break;
		}
		std::istringstream     record(line);
		char                   tag = 0;
		NullfsMount::MountInfo mount;
		uint64_t               device = 0, inode = 0;
		if (!(record >> tag >> std::quoted(mount.point) >> std::quoted(mount.source) >> device >>
		      inode) ||
		    (tag != 'N' && tag != 'F') || device > UINT32_MAX || inode > UINT32_MAX)
			return KERNEL_ERROR_EINVAL;
		if (tag == 'F' &&
		    (!(record >> mount.flags) || mount.flags == 0 ||
		     (mount.flags & ~(NullfsMount::FlagReadOnly | NullfsMount::FlagNoExec)) != 0))
			return KERNEL_ERROR_EINVAL;
		std::ostringstream canonical;
		canonical << tag << ' ' << std::quoted(mount.point) << ' ' << std::quoted(mount.source)
		          << ' ' << device << ' ' << inode;
		if (tag == 'F') canonical << ' ' << mount.flags;
		if (canonical.str() != line) return KERNEL_ERROR_EINVAL;
		for (const auto* path: {&mount.point, &mount.source}) {
			std::string normalized;
			if (path->find_first_of("\r\n") != path->npos) return KERNEL_ERROR_EINVAL;
			const int parsed = Tmpfs::NormalizePath(*path, &normalized);
			if (parsed != OK) return parsed;
			if (normalized != *path) return KERNEL_ERROR_EINVAL;
		}
		bindings.push_back(
		    {std::move(mount), static_cast<uint32_t>(device), static_cast<uint32_t>(inode)});
	}
	input >> std::ws;
	if (!complete || !input.eof()) return KERNEL_ERROR_EINVAL;
	std::lock_guard publication(g_mount_publication_mutex);
	if (g_mount_points == nullptr) return KERNEL_ERROR_ENOSYS;
	std::vector<NullfsMount::MountInfo> mounts;
	mounts.reserve(bindings.size());
	for (const auto& binding: bindings) {
		const auto& mount = binding.mount;
		if (NullfsPointBusy(mount.point)) return KERNEL_ERROR_EBUSY;
		const int traversal = ValidateMountedTraversal(mount.point);
		if (traversal != OK) return traversal;
		FileStat covered {}, lower {};
		int      result = KernelStat(mount.point.c_str(), &covered);
		if (result != OK) return result;
		if ((covered.st_mode & 0170000u) != 0040000u) return KERNEL_ERROR_ENOTDIR;
		NullfsMount::Resolution source;
		result = NullfsMount::Resolve(mount.source, &source);
		if (result != OK) return result;
		if (source.mounted) return KERNEL_ERROR_EINVAL;
		result = KernelStat(mount.source.c_str(), &lower);
		if (result != OK) return result;
		if ((lower.st_mode & 0170000u) != 0040000u) return KERNEL_ERROR_ENOTDIR;
		if (lower.st_dev != binding.device || lower.st_ino != binding.inode)
			return KERNEL_ERROR_EINVAL;
		mounts.push_back(mount);
	}
	const int result = NullfsMount::ImportMounts(mounts);
	if (result != OK) return result;
	LOGF("GUEST_EXEC_NULLFS_MOUNTS imported=%zu\n", mounts.size());
	return OK;
} catch (const std::bad_alloc&) {
	return KERNEL_ERROR_ENOMEM;
}

bool IsDiagnosticGcDeviceReady() noexcept {
	return g_diagnostic_gc_device_ready.load();
}

void Umount(const std::string& folder_or_point) {
	std::lock_guard publication(g_mount_publication_mutex);

	if (NullfsMount::Contains(folder_or_point)) {
		const int result = NullfsMount::Unmount(folder_or_point);
		if (result != OK)
			LOGF("NULLFS_UNMOUNT path=%s error=0x%x\n", folder_or_point.c_str(), result);
		else
			RetractSandboxMount(folder_or_point);
		return;
	}

	if (NullfsMount::Overlaps(folder_or_point)) {
		LOGF("NULLFS_COVERED_UNMOUNT path=%s error=0x%x\n", folder_or_point.c_str(),
		     KERNEL_ERROR_EBUSY);
		return;
	}

	if (ExfatMount::Contains(folder_or_point)) {
		const int result = ExfatMount::Unmount(folder_or_point);
		if (result != OK)
			LOGF("EXFAT_UNMOUNT path=%s error=0x%x\n", folder_or_point.c_str(), result);
		return;
	}

	if (BfsMount::Contains(folder_or_point)) {
		const int result = BfsMount::Unmount(folder_or_point);
		if (result != OK) LOGF("BFS_UNMOUNT path=%s error=0x%x\n", folder_or_point.c_str(), result);
		return;
	}

	if (DirectoryPassthrough::Contains(folder_or_point)) {
		const int result = DirectoryPassthrough::Unmount(folder_or_point);
		if (result != OK)
			LOGF("PASSTHROUGH_UNMOUNT path=%s error=0x%x\n", folder_or_point.c_str(), result);
		if (result == OK) {
			std::erase_if(g_published_read_only_providers, [](const auto& binding) {
				DirectoryPassthrough::MountInfo info;
				return DirectoryPassthrough::DescribeMount(binding.point, &info) != OK;
			});
		}
		return;
	}

	if (Tmpfs::Contains(folder_or_point)) {
		const int result = Tmpfs::Unmount(folder_or_point);
		if (result != OK)
			LOGF("TMPFS_UNMOUNT path=%s error=0x%x\n", folder_or_point.c_str(), result);
		return;
	}
	g_mount_points->Umount(folder_or_point);
}

bool IsNullfsNoExec(const std::string& mounted_file_name) {
	if (ValidateNullfsTraversal(mounted_file_name) != OK) return false;
	NullfsMount::Resolution resolution;
	return NullfsMount::Resolve(mounted_file_name, &resolution) == OK && resolution.no_exec;
}

std::filesystem::path GetRealFilename(const std::string& mounted_file_name) {
	if (ValidateNullfsTraversal(mounted_file_name) != OK) return {};
	NullfsMount::Resolution resolution;
	if (NullfsMount::Resolve(mounted_file_name, &resolution) != OK) return {};
	const auto& resolved = resolution.mounted ? resolution.path : mounted_file_name;
	if (ResolveDataTopologyPath(resolved) != DataTopologyPath::None) return {};
	return g_mount_points->ResolvePath(resolved);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
int KYTY_SYSV_ABI KernelOpen(const char* path, int flags, uint16_t mode) {
	PRINT_NAME();

	if (path == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}
	std::string working_path;
	const int   working = ResolveInitialWorkingDirectoryPath(&path, &working_path);
	if (working != OK) return working;
	std::string nullfs_path;
	bool        nullfs_read_only = false;
	const int nullfs = ResolveNullfsPath(&path, &nullfs_path, nullptr, nullptr, &nullfs_read_only);
	if (nullfs != OK) return nullfs;
	const bool native_sshot_path = std::strcmp(path, "/dev/sshot") == 0;
	if (native_sshot_path && (flags != 2 || mode != 0)) return KERNEL_ERROR_EINVAL;

	if (path[0] == '/') {
		const int traversal = ValidateMountedTraversal(path);
		if (traversal != OK) return traversal;
	}
	if (nullfs_read_only) {
		// vn_open_cred: CREATE lookup of a missing name, then O_EXCL, then VWRITE for write access
		// or O_TRUNC (EISDIR first for directories)
		const auto flags_u = static_cast<uint32_t>(flags);
		if ((flags_u & 3u) == 3u) return KERNEL_ERROR_EINVAL;
		const bool writes = (flags_u & 3u) != 0 || (flags_u & 0x0400u) != 0;
		if ((flags_u & 0x0200u) != 0 || writes) {
			FileStat  existing {};
			const int found = KernelStat(path, &existing);
			if (found == KERNEL_ERROR_ENOENT && (flags_u & 0x0200u) != 0)
				return NullfsReadOnlyLookup(path, true);
			if (found == OK) {
				if ((flags_u & 0x0a00u) == 0x0a00u) return KERNEL_ERROR_EEXIST;
				if (writes)
					return (existing.st_mode & 0170000u) == 0040000u ? KERNEL_ERROR_EISDIR
					                                                 : KERNEL_ERROR_EROFS;
			}
		}
	}
	std::vector<uint32_t> devfs_directories;
	const bool            devfs_instance = DevfsInstanceAt(path, &devfs_directories);
	if (devfs_instance || IsDevfsRoot(path)) {
		// vn_open_cred order: EINVAL for O_ACCMODE, EEXIST for O_CREAT|O_EXCL, then EISDIR for any
		// write, create or truncate
		const auto flags_u = static_cast<uint32_t>(flags);
		if ((flags_u & 3u) == 3u) return KERNEL_ERROR_EINVAL;
		if ((flags_u & 0x0a00u) == 0x0a00u) return KERNEL_ERROR_EEXIST;
		if ((flags_u & 3u) != 0 || (flags_u & (0x0200u | 0x0400u)) != 0) return KERNEL_ERROR_EISDIR;
		std::string point = "/dev";
		if (devfs_instance) Tmpfs::NormalizePath(path, &point);
		const int descriptor   = g_files->CreateDescriptor();
		auto*     file         = g_files->GetFile(descriptor);
		file->name             = point;
		file->real_name        = Common::PathFromUtf8(point);
		file->directory        = true;
		file->readable         = true;
		file->devfs_root       = true;
		file->dirents          = PackDevfsRoot(devfs_instance ? &devfs_directories : nullptr);
		file->dents_offset     = 0;
		file->descriptor_flags = (flags_u & 0x00100000u) != 0 ? 1 : 0;
		file->opened           = true;
		return descriptor;
	}
	if (ExfatMount::Contains(path)) {
		const int descriptor = g_files->CreateDescriptor();
		auto*     file       = g_files->GetFile(descriptor);
		const int result     = ExfatMount::Open(path, flags, &file->exfat);
		if (result != OK) {
			g_files->DeleteDescriptor(descriptor);
			return result;
		}
		ExfatMount::NodeStat stat {};
		const int            metadata = ExfatMount::Fstat(file->exfat, &stat);
		if (metadata != OK) {
			file->exfat.reset();
			g_files->DeleteDescriptor(descriptor);
			return metadata;
		}
		file->name             = path;
		file->real_name        = Common::PathFromUtf8(path);
		file->directory        = (stat.mode & 0170000u) == 0040000u;
		file->readable         = true;
		file->writable         = false;
		file->descriptor_flags = (flags & 0x00100000) != 0 ? 1 : 0;
		if (file->directory) {
			const int entries = RefreshExfatDirectory(file);
			if (entries != OK) {
				file->exfat.reset();
				g_files->DeleteDescriptor(descriptor);
				return entries;
			}
		}
		file->opened = true;
		return descriptor;
	}
	if (BfsMount::Contains(path)) {
		const int descriptor = g_files->CreateDescriptor();
		auto*     file       = g_files->GetFile(descriptor);
		const int result     = BfsMount::Open(path, flags, &file->bfs);
		if (result != OK) {
			g_files->DeleteDescriptor(descriptor);
			return result;
		}
		BfsMount::NodeStat stat {};
		const int          metadata = BfsMount::Fstat(file->bfs, &stat);
		if (metadata != OK) {
			file->bfs.reset();
			g_files->DeleteDescriptor(descriptor);
			return metadata;
		}
		file->name             = path;
		file->real_name        = Common::PathFromUtf8(path);
		file->directory        = (stat.mode & 0170000u) == 0040000u;
		file->readable         = true;
		file->writable         = false;
		file->descriptor_flags = (flags & 0x00100000) != 0 ? 1 : 0;
		if (file->directory) {
			const int entries = RefreshBfsDirectory(file);
			if (entries != OK) {
				file->bfs.reset();
				g_files->DeleteDescriptor(descriptor);
				return entries;
			}
		}
		file->opened = true;
		return descriptor;
	}
	if (DirectoryPassthrough::Contains(path)) {
		const int descriptor = g_files->CreateDescriptor();
		auto*     file       = g_files->GetFile(descriptor);
		const int result =
		    DirectoryPassthrough::Open(path, flags, &file->passthrough,
			                           mode & ~g_creation_mask.load(std::memory_order_relaxed));
		if (result != OK) {
			g_files->DeleteDescriptor(descriptor);
			return result;
		}
		DirectoryPassthrough::NodeStat stat {};
		const int metadata = DirectoryPassthrough::Fstat(file->passthrough, &stat);
		if (metadata != OK) {
			file->passthrough.reset();
			g_files->DeleteDescriptor(descriptor);
			return metadata;
		}
		file->name             = path;
		file->real_name        = Common::PathFromUtf8(path);
		file->directory        = (stat.mode & 0170000u) == 0040000u;
		file->readable         = (flags & 3) != 1;
		file->writable         = (flags & 3) != 0;
		file->descriptor_flags = (flags & 0x00100000) != 0 ? 1 : 0;
		if (file->directory) {
			const int entries = RefreshPassthroughDirectory(file);
			if (entries != OK) {
				file->passthrough.reset();
				g_files->DeleteDescriptor(descriptor);
				return entries;
			}
		}
		file->opened = true;
		return descriptor;
	}
	if (Tmpfs::Contains(path)) {
		const int descriptor = g_files->CreateDescriptor();
		auto*     file       = g_files->GetFile(descriptor);
		const int opened     = Tmpfs::Open(
		    path, flags, mode & ~g_creation_mask.load(std::memory_order_relaxed), &file->tmpfs);
		if (opened != OK) {
			g_files->DeleteDescriptor(descriptor);
			return opened;
		}
		Tmpfs::NodeStat stat {};
		const int       status = Tmpfs::Fstat(file->tmpfs, &stat);
		if (status != OK) {
			Tmpfs::Close(file->tmpfs);
			g_files->DeleteDescriptor(descriptor);
			return status;
		}
		file->name             = path;
		file->special          = SpecialFile::Temporary;
		file->directory        = (stat.mode & 0170000u) == 0040000u;
		file->readable         = (flags & 3) != 1;
		file->writable         = (flags & 3) != 0;
		file->append           = (flags & 8) != 0;
		file->descriptor_flags = (flags & 0x00100000) != 0 ? 1 : 0;
		file->opened           = true;
		return descriptor;
	}
	const auto data_topology = ResolveDataTopologyPath(path);
	if (data_topology != DataTopologyPath::None) {
		const auto flags_u = static_cast<uint32_t>(flags);
		const auto access  = flags_u & 3u;
		if (access == 3u) return KERNEL_ERROR_EINVAL;
		const bool mutation =
		    access != 0 || (flags_u & (0x0008u | 0x0200u | 0x0400u | 0x0800u)) != 0;
		if (mutation) return KERNEL_ERROR_EROFS;
		if (data_topology == DataTopologyPath::Missing) return KERNEL_ERROR_ENOENT;
		const int descriptor   = g_files->CreateDescriptor();
		auto*     file         = g_files->GetFile(descriptor);
		file->name             = path;
		file->real_name        = Common::PathFromUtf8(path);
		file->directory        = true;
		file->readable         = true;
		file->data_topology    = true;
		file->descriptor_flags = (flags_u & 0x00100000u) != 0 ? 1 : 0;
		file->opened           = true;
		return descriptor;
	}
	auto flags_u = static_cast<uint32_t>(flags);
	if (std::strcmp(path, "/dev/mbus") == 0 &&
	    std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") != nullptr) {
		if ((flags_u & 3u) == 3u) return KERNEL_ERROR_EINVAL;
		if ((flags_u & 0x20000u) != 0) return KERNEL_ERROR_ENOTDIR;
		if ((flags_u & ~0x00100007u) != 0) return KERNEL_ERROR_ENOSYS;
	}

	LOGF("\t path = %s\n"
	     "\t flags = %08" PRIx32 "\n"
	     "\t mode = %04" PRIx16 "\n",
	     EscapeLogPath(path).c_str(), flags_u, mode);

	bool      append           = (flags_u & 0x0008u) != 0;
	bool      fsync            = (flags_u & 0x0080u) != 0;
	bool      sync             = (flags_u & 0x0080u) != 0;
	bool      creat            = (flags_u & 0x0200u) != 0;
	bool      trunc            = (flags_u & 0x0400u) != 0;
	bool      excl             = (flags_u & 0x0800u) != 0;
	bool      dsync            = (flags_u & 0x1000u) != 0;
	bool      direct           = (flags_u & 0x00010000u) != 0;
	bool      directory        = (flags_u & 0x00020000u) != 0;
	const int descriptor_flags = (flags_u & 0x00100000u) != 0 ? 1 : 0;
	const int deci_access      = flags & ~0x00100000;

	if (direct) {
		LOGF("\t O_DIRECT ignored on host file backend\n");
	}

	flags_u &= 0x3u;
	const char* iccnvs4_image       = std::getenv("KYTY_PS5_ICCNVS4_IMAGE");
	const char* iccnvs4_overlay     = std::getenv("KYTY_PS5_ICCNVS4_OVERLAY");
	const bool  iccnvs4_has_overlay = iccnvs4_overlay != nullptr && iccnvs4_overlay[0] != '\0';
	const bool  iccnvs4_requested   = std::strcmp(path, "/dev/iccnvs4") == 0 &&
	                                  iccnvs4_image != nullptr && iccnvs4_image[0] != '\0';
	if (iccnvs4_requested) {
		if (flags_u == 3) return KERNEL_ERROR_EINVAL;
		if (directory) return KERNEL_ERROR_ENOTDIR;
		if ((flags_u == 1 && !iccnvs4_has_overlay) || creat || trunc || append || excl)
			return KERNEL_ERROR_EROFS;
	}
	if (FindSectorPayload(path)) {
		if (flags_u == 3 || creat || trunc || append || excl) return KERNEL_ERROR_EINVAL;
		if (directory) return KERNEL_ERROR_ENOTDIR;
	}
	if (A53StorageEnabled() && IsA53SsdDevice(path) && flags_u == 3) {
		// partition-verify opens /dev/ssd0 with an access mode the switch below rejects
		flags_u = 0;
	}

	Common::File::Mode rw_mode = Common::File::Mode::Read;

	switch (flags_u) {
		case 0: rw_mode = Common::File::Mode::Read; break;
		case 1: rw_mode = Common::File::Mode::Write; break;
		case 2: rw_mode = Common::File::Mode::ReadWrite; break;
		default: EXIT("invalid flag_u: %u\n", flags_u);
	}
	bool exact_shellui_guest = false;
	ClassifyPsmShellUiApplicationRoute(path, &exact_shellui_guest);
	if (exact_shellui_guest && (rw_mode != Common::File::Mode::Read || append || creat || trunc)) {
		return KERNEL_ERROR_EROFS;
	}

	EXIT_NOT_IMPLEMENTED(directory && rw_mode != Common::File::Mode::Read);
	EXIT_NOT_IMPLEMENTED(directory && (trunc || creat));

	int   descriptor = g_files->CreateDescriptor();
	auto* file       = g_files->GetFile(descriptor);

	EXIT_IF(file == nullptr || file->opened || file->directory);

	file->name             = path;
	file->readable         = rw_mode != Common::File::Mode::Write;
	file->writable         = rw_mode != Common::File::Mode::Read;
	file->append           = append;
	file->sync_writes      = fsync || sync || dsync;
	file->descriptor_flags = descriptor_flags;

	if (!directory && file->name == "/dev/lvdctl") {
		if (flags != 2 || mode != 0 || append || creat || trunc || excl || direct) {
			g_files->DeleteDescriptor(descriptor);
			return KERNEL_ERROR_EINVAL;
		}
		file->real_name = file->name;
		file->special   = SpecialFile::LvdCtl;
		file->opened    = true;
		LOGF("LVD_CTL_OPEN guest_pid=%d fd=%d flags=0x%x\n", Process::GetPid(), descriptor, flags);
		return descriptor;
	}
	if (!directory) {
		if (auto lvd = FindLvdDevice(file->name)) {
			if ((flags != 0 && flags != 2) || mode != 0 || append || creat || trunc || excl ||
			    direct) {
				g_files->DeleteDescriptor(descriptor);
				return KERNEL_ERROR_EINVAL;
			}
			file->real_name       = file->name;
			file->special         = SpecialFile::LvdDevice;
			file->special_size    = lvd->capacity;
			file->lvd             = std::move(lvd);
			file->sector_position = 0;
			file->opened          = true;
			LOGF("LVD_DEVICE_OPEN guest_pid=%d fd=%d unit=%d access=%u capacity=0x%016" PRIx64 "\n",
			     Process::GetPid(), descriptor, file->lvd->unit, flags_u, file->lvd->capacity);
			return descriptor;
		}
	}

	if (!directory && IsRandomDevice(file->name)) {
		file->real_name = file->name;
		file->special   = SpecialFile::Random;
		file->opened    = true;

		LOGF_COLOR(Log::Color::Green, "\tOpen device: %s, [ok]\n",
		           Common::PathToString(file->real_name).c_str());

		return descriptor;
	}

	if (!directory && IsDipswDevice(file->name)) {
		file->real_name = file->name;
		file->special   = SpecialFile::Dipsw;
		file->opened    = true;

		LOGF_COLOR(Log::Color::Green, "\tOpen device: %s, [ok]\n",
		           Common::PathToString(file->real_name).c_str());

		return descriptor;
	}

	// SysCore child opens three debug consoles before exec setup, mapped to host stdio
	if (!directory && std::getenv("KYTY_DIAGNOSTIC_SYSCORE_LIVE_RFORK_THREAD") != nullptr &&
	    (file->name == "/dev/deci_stdin" || file->name == "/dev/deci_stdout" ||
	     file->name == "/dev/deci_stderr")) {
		const bool input = file->name == "/dev/deci_stdin";
		const bool error = file->name == "/dev/deci_stderr";
		if ((input && deci_access != 0) || (!input && deci_access != 1)) {
			g_files->DeleteDescriptor(descriptor);
			return KERNEL_ERROR_EINVAL;
		}
		file->real_name = file->name;
		file->special   = input ? SpecialFile::DeciStdin
		                        : (error ? SpecialFile::DeciStderr : SpecialFile::DeciStdout);
		file->opened    = true;
		LOGF("SYSCORE_DECI_STREAM_OPEN guest_fd=%d path=%s"
		     " host_standard_stream_backing=1"
		     " guest_open_flags=%d\n",
		     descriptor, file->name.c_str(), flags);
		return descriptor;
	}
	if (!directory && IsConsoleDevice(file->name)) {
		file->real_name = file->name;
		file->special   = SpecialFile::Console;
		file->opened    = true;

		LOGF_COLOR(Log::Color::Green, "\tOpen device: %s, [ok]\n",
		           Common::PathToString(file->real_name).c_str());

		return descriptor;
	}

	if (!directory && IsNpdrmDevice(file->name)) {
		file->real_name = file->name;
		file->special   = SpecialFile::Npdrm;
		file->opened    = true;

		LOGF_COLOR(Log::Color::Green, "\tOpen device: %s, [ok]\n",
		           Common::PathToString(file->real_name).c_str());

		return descriptor;
	}
	if (!directory && A53StorageEnabled() && file->name == "/dev/bfs/ctl") {
		if (trunc || append || excl || creat) {
			g_files->DeleteDescriptor(descriptor);
			return KERNEL_ERROR_EINVAL;
		}
		file->special   = SpecialFile::BfsCtl;
		file->real_name = file->name;
		file->opened    = true;
		LOGF("BFS_CTL_DEVICE_OPEN fd=%d flags=0x%x NON_AUTHENTIC"
		     " backing_present=%d\n",
		     descriptor, flags, FindSectorPayload("/dev/ssd0.user") != nullptr ? 1 : 0);
		return descriptor;
	}

	if (auto backing = FindSectorPayload(file->name)) {
		if (directory || creat || trunc || append || excl) {
			g_files->DeleteDescriptor(descriptor);
			return KERNEL_ERROR_EINVAL;
		}
		if (backing->ReadOnly() && file->writable) {
			g_files->DeleteDescriptor(descriptor);
			return KERNEL_ERROR_EROFS;
		}
		file->sector_backing = std::move(backing);
		file->real_name      = file->name;
		file->opened         = true;
		return descriptor;
	}

	const bool original_iccnvs4 = !directory && file->name == "/dev/iccnvs4" &&
	                              iccnvs4_image != nullptr && iccnvs4_image[0] != '\0';
	if (original_iccnvs4 && (creat || trunc || append || excl)) {
		g_files->DeleteDescriptor(descriptor);
		return KERNEL_ERROR_EROFS;
	}
	if (original_iccnvs4) {
		file->real_name = std::filesystem::path(iccnvs4_image);
		if (!file->real_name.is_absolute()) {
			g_files->DeleteDescriptor(descriptor);
			return KERNEL_ERROR_ENOENT;
		}
		rw_mode        = Common::File::Mode::Read;
		file->writable = false;
		file->readable = true;
		LOGF("ICCNVS4_SNAPSHOT_MAPPED guest=%s host=%s"
		     " read_only known_ranges_only\n",
		     file->name.c_str(), Common::PathToString(file->real_name).c_str());
	} else {
		file->real_name = g_mount_points->ResolvePath(file->name);
	}
	if (file->real_name.empty()) {
		g_files->DeleteDescriptor(descriptor);
		return KERNEL_ERROR_ENOENT;
	}
	if (Common::IsArchivePath(file->real_name) &&
	    (rw_mode != Common::File::Mode::Read || trunc || creat)) {
		g_files->DeleteDescriptor(descriptor);
		return KERNEL_ERROR_EROFS;
	}
	if (trunc && rw_mode == Common::File::Mode::Read) {
		g_files->DeleteDescriptor(descriptor);
		return KERNEL_ERROR_EACCES;
	}

	const auto info = Common::File::GetInfo(file->real_name);
	if (original_iccnvs4 && (!info || !info->is_file || info->size < 0x24)) {
		g_files->DeleteDescriptor(descriptor);
		return KERNEL_ERROR_ENOENT;
	}
	if (original_iccnvs4) {
		const char*           hash = std::getenv("KYTY_PS5_ICCNVS4_SHA256");
		SectorBacking::Result result;
		file->iccnvs4_backing = SectorBacking::OpenCapturedPrefix(
		    file->real_name,
		    iccnvs4_has_overlay ? std::filesystem::path(iccnvs4_overlay) : std::filesystem::path {},
		    hash ? hash : "", &result);
		if (!file->iccnvs4_backing || file->iccnvs4_backing->SourceBytes() < 0x24) {
			g_files->DeleteDescriptor(descriptor);
			return result == SectorBacking::Result::Invalid ? KERNEL_ERROR_EINVAL
			                                                : KERNEL_ERROR_EIO;
		}
		file->iccnvs4_snapshot       = true;
		file->iccnvs4_snapshot_bytes = file->iccnvs4_backing->SourceBytes();
		file->readable               = flags_u != 1;
		file->writable               = flags_u != 0 && !file->iccnvs4_backing->ReadOnly();
	}
	const bool dir_exist  = info && !info->is_file;
	const bool file_exist = info && info->is_file;
	if (!info && !original_iccnvs4 && UseCapturedRootMetadata(path)) {
		FileStat  captured {};
		const int metadata = CapturedRootMetadata::Stat(path, &captured);
		g_files->DeleteDescriptor(descriptor);
		if (metadata != OK) return metadata;
		return rw_mode != Common::File::Mode::Read || trunc || creat ? KERNEL_ERROR_EROFS
		                                                             : KERNEL_ERROR_EIO;
	}

	if (!creat && !dir_exist && !file_exist) {
		g_files->DeleteDescriptor(descriptor);
		return KERNEL_ERROR_ENOENT;
	}
	if (g_mount_points->IsReadOnly(file->real_name) &&
	    (rw_mode != Common::File::Mode::Read || trunc || creat)) {
		g_files->DeleteDescriptor(descriptor);
		return KERNEL_ERROR_EROFS;
	}

	if (directory || dir_exist) {
		if (!dir_exist) {
			g_files->DeleteDescriptor(descriptor);
			return KERNEL_ERROR_ENOTDIR;
		}

		EXIT_NOT_IMPLEMENTED(!directory && rw_mode != Common::File::Mode::Read);
		EXIT_NOT_IMPLEMENTED(!directory && (trunc || creat));

		const auto entries = g_mount_points->DirectoryEntries(file->name, file->real_name);
		file->dirents      = PackDirents(entries);
		file->dents_offset = 0;
		file->directory    = true;

		LOGF_COLOR(Log::Color::Green, "\tOpen dir: %s, entries = %" PRIu32 ", [ok]\n",
		           EscapeLogPath(file->real_name).c_str(), static_cast<uint32_t>(entries.size()));

		for (const auto& f: entries) {
			LOGF("\t\t%s %s\n", f.is_file ? "[file]" : "[dir ]", Log::EscapeField(f.name).c_str());
		}
	} else {
		bool result = false;

		if (excl && creat && file_exist) {
			g_files->DeleteDescriptor(descriptor);
			return KERNEL_ERROR_EEXIST;
		}

		if (creat && (!file_exist || trunc)) {
			Common::File::CreateDirectories(file->real_name.parent_path());
			result = file->f.Create(file->real_name);

			LOGF_COLOR(result ? Log::Color::Green : Log::Color::Red, "\tCreate: %s, %s\n",
			           EscapeLogPath(file->real_name).c_str(), result ? "[ok]" : "[fail]");
		} else {
			result = file->f.Open(file->real_name, rw_mode);

			LOGF_COLOR(result ? Log::Color::Green : Log::Color::Red, "\tOpen: %s, %s\n",
			           EscapeLogPath(file->real_name).c_str(), result ? "[ok]" : "[fail]");
		}

		if (result && trunc) {
			result = file->f.Truncate(0);
		}

		if (result && append) {
			file->f.Seek(file->f.Size());
		}

		if (!result || file->f.IsInvalid()) {
			g_files->DeleteDescriptor(descriptor);
			return KERNEL_ERROR_EACCES;
		}
	}

	file->opened = true;
	return descriptor;
}


static bool IsReservedPhyshmBackendName(const char* path) {
	constexpr char Root[] = "/.physhm";
	return std::strncmp(path, Root, sizeof(Root) - 1) == 0 &&
	       (path[sizeof(Root) - 1] == '\0' || path[sizeof(Root) - 1] == '/');
}


int KYTY_SYSV_ABI KernelShmUnlink(const char* path) {
	PRINT_NAME();
	if (path == nullptr) {
		*Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
		return -1;
	}
	if (reinterpret_cast<uintptr_t>(path) == 1) {
		*Posix::GetErrorAddr() = Posix::POSIX_EFAULT;
		return -1;
	}
	if (IsReservedPhyshmBackendName(path)) {
		*Posix::GetErrorAddr() = Posix::POSIX_EINVAL;
		return -1;
	}
	std::string scope;
	if (std::strcmp(path, HMD_SHM_PATH) != 0 || Process::GetScope(&scope)) {
		const int error = Memory::UnlinkScopeSharedMemory(path);
		if (error != 0) {
			*Posix::GetErrorAddr() = error;
			return -1;
		}
		return 0;
	}
	Common::LockGuard lock(g_hmd_shm_mutex);
	if (!g_hmd_shm_exists) {
		*Posix::GetErrorAddr() = Posix::POSIX_ENOENT;
		return -1;
	}
	g_hmd_shm_exists = false;
	return 0;
}


bool GetSharedMemorySize(int d, size_t* size) {
	if (size == nullptr || d < DESCRIPTOR_MIN) {
		return false;
	}
	auto* file = g_files->GetFile(d);
	if (file == nullptr || !file->opened || file->special != SpecialFile::SharedMemory) {
		return false;
	}
	*size = file->anonymous_shared
	            ? static_cast<size_t>(Memory::GetAnonymousSharedMemorySize(file->anonymous_shared))
	            : static_cast<size_t>(file->special_size);
	return true;
}

bool IsSharedMemoryNamed(int d, const char* name) {
	if (name == nullptr || d < DESCRIPTOR_MIN) {
		return false;
	}
	auto* file = g_files->GetFile(d);
	if (file == nullptr || !file->opened || file->special != SpecialFile::SharedMemory) {
		return false;
	}
	if (file->anonymous_shared) {
		return false;
	}
	return file->name == name;
}

int KYTY_SYSV_ABI KernelClose(int d) {
	PRINT_NAME();

	if (d < DESCRIPTOR_MIN) {
		if (g_files != nullptr && g_files->CloseStandardDeci(d)) {
			return OK;
		}
		return g_files != nullptr && g_files->HasExplicitStandardTable() ? KERNEL_ERROR_EBADF
		                                                                 : KERNEL_ERROR_EPERM;
	}

	if (::Libs::Network::Net::IsSocket(d)) {
		const auto result = ::Libs::Network::Net::SocketClose(d);
		return (result == OK ? OK : PosixToKernel(::Libs::Network::NetToPosix(result)));
	}

	auto* file = g_files->GetFile(d);

	if (file == nullptr) {
		return KERNEL_ERROR_EBADF;
	}

	EXIT_IF(!file->opened);
	if (file->exfat) {
		const int result = ExfatMount::Close(file->exfat);
		if (result != OK) return result;
		file->opened = false;
		g_files->DeleteDescriptor(d);
		return OK;
	}
	if (file->bfs) {
		const int result = BfsMount::Close(file->bfs);
		if (result != OK) return result;
		file->opened = false;
		g_files->DeleteDescriptor(d);
		return OK;
	}
	if (file->passthrough) {
		const int result = DirectoryPassthrough::Close(file->passthrough);
		if (result != OK) return result;
		file->opened = false;
		g_files->DeleteDescriptor(d);
		return OK;
	}
	if (file->tmpfs) {
		const int result = Tmpfs::Close(file->tmpfs);
		if (result != OK) return result;
		file->opened = false;
		g_files->DeleteDescriptor(d);
		return OK;
	}

	if (file->pipe != nullptr) {
		std::lock_guard pipe_lock(file->pipe->mutex);
		if (file->special == SpecialFile::PipeRead && file->pipe->readers != 0) {
			--file->pipe->readers;
		} else if (file->special == SpecialFile::PipeWrite && file->pipe->writers != 0) {
			--file->pipe->writers;
		}
		file->pipe->cv.notify_all();
	}

	if (!file->directory && file->special == SpecialFile::None) {
		file->f.Close();
	}

	file->opened = false;

	LOGF("\tClose: %s\n", EscapeLogPath(file->real_name).c_str());

	g_files->DeleteDescriptor(d);

	return OK;
}

int CreateEqueueDescriptor(int64_t handle) {
	if (!EventQueue::KernelPinEqueue(handle) || g_files == nullptr) {
		return KERNEL_ERROR_EBADF;
	}
	const int fd   = g_files->CreateDescriptor();
	auto*     file = g_files->GetFile(fd);
	EXIT_IF(file == nullptr);
	file->name         = "equeue-fd";
	file->real_name    = "/dev/kqueue";
	file->special      = SpecialFile::NativeEqueueDescriptor;
	file->special_size = static_cast<uint64_t>(handle);
	file->opened       = true;
	LOGF("SYSCORE_EQUEUE_FD queue=%" PRId64 " fd=%d backing=existing_kernel_equeue\n", handle, fd);
	return fd;
}




bool IsNativeDmemDescriptor(int fd) {
	if (fd < DESCRIPTOR_MIN || g_files == nullptr) {
		return false;
	}
	const auto* file = g_files->GetFile(fd);
	return file != nullptr && file->opened && file->special == SpecialFile::NativeDmem;
}

bool IsSectorPayloadDescriptor(int fd) {
	if (fd < DESCRIPTOR_MIN || g_files == nullptr) return false;
	const auto* file = g_files->GetFile(fd);
	return file != nullptr && file->opened && file->sector_backing != nullptr;
}

bool IsIccnvs4SnapshotDescriptor(int fd) {
	if (fd < DESCRIPTOR_MIN || g_files == nullptr) return false;
	const auto* file = g_files->GetFile(fd);
	return file != nullptr && file->opened && file->iccnvs4_snapshot;
}

bool IsNativeAvProbeDescriptor(int fd) {
	if (fd < DESCRIPTOR_MIN || g_files == nullptr) {
		return false;
	}
	const auto* file = g_files->GetFile(fd);
	return file != nullptr && file->opened && file->special == SpecialFile::NativeAvProbe;
}

bool IsNativeAvDescriptor(int fd) {
	if (fd < DESCRIPTOR_MIN || g_files == nullptr) return false;
	const auto* file = g_files->GetFile(fd);
	return file != nullptr && file->opened &&
	       (file->special == SpecialFile::NativeAvDevice ||
	        file->special == SpecialFile::NativeAvProbe);
}

bool IsA53StorageDescriptor(int fd) {
	if (fd < DESCRIPTOR_MIN || g_files == nullptr) return false;
	const auto* file = g_files->GetFile(fd);
	return file != nullptr && file->opened &&
	       (file->special == SpecialFile::NativeA53Io ||
	        file->special == SpecialFile::NativeNsidCtl ||
	        file->special == SpecialFile::NativeSsd || file->special == SpecialFile::BfsCtl);
}


bool IsNativeDipswDescriptor(int fd) {
	if (fd < DESCRIPTOR_MIN || g_files == nullptr) {
		return false;
	}
	const auto* file = g_files->GetFile(fd);
	return file != nullptr && file->opened && file->special == SpecialFile::Dipsw;
}

int CreateGuestSocketPair(int* fds) {
	if (fds == nullptr || g_files == nullptr) {
		return KERNEL_ERROR_EFAULT;
	}
	const int first          = g_files->CreateDescriptor();
	const int second         = g_files->CreateDescriptor();
	auto      inbound_first  = std::make_shared<GuestPipe>();
	auto      inbound_second = std::make_shared<GuestPipe>();
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	const char* exec_enabled = std::getenv("KYTY_DIAGNOSTIC_GUEST_EXECVE");
	if (exec_enabled != nullptr && std::strcmp(exec_enabled, "1") == 0) {
		inbound_first->shared  = SharedGuestPipe::Create();
		inbound_second->shared = SharedGuestPipe::Create();
		if (!inbound_first->shared || !inbound_second->shared) {
			g_files->DeleteDescriptor(first);
			g_files->DeleteDescriptor(second);
			return KERNEL_ERROR_ENOMEM;
		}
	}
#endif
	auto* left  = g_files->GetFile(first);
	auto* right = g_files->GetFile(second);
	EXIT_IF(left == nullptr || right == nullptr);
	left->name                = "guest-socketpair-0";
	left->real_name           = "/dev/socketpair";
	left->special             = SpecialFile::GuestSocketPair;
	left->pipe                = inbound_first;
	left->socket_send         = inbound_second;
	left->socket_read_source  = std::make_shared<GuestSocketReadSource>(left->pipe);
	left->readable            = true;
	left->writable            = true;
	left->opened              = true;
	right->name               = "guest-socketpair-1";
	right->real_name          = "/dev/socketpair";
	right->special            = SpecialFile::GuestSocketPair;
	right->pipe               = inbound_second;
	right->socket_send        = inbound_first;
	right->socket_read_source = std::make_shared<GuestSocketReadSource>(right->pipe);
	right->readable           = true;
	right->writable           = true;
	right->opened             = true;
	fds[0]                    = first;
	fds[1]                    = second;
	LOGF("SYSCORE_SOCKETPAIR_CREATE fd0=%d fd1=%d"
	     " family=AF_UNIX type=SOCK_STREAM\n",
	     first, second);
	return OK;
}

int KYTY_SYSV_ABI KernelPipe(int* fds) {
	if (fds == nullptr) {
		return KERNEL_ERROR_EFAULT;
	}
	const int reader      = g_files->CreateDescriptor();
	const int writer      = g_files->CreateDescriptor();
	auto      pipe        = std::make_shared<GuestPipe>();
	auto*     read_file   = g_files->GetFile(reader);
	auto*     write_file  = g_files->GetFile(writer);
	read_file->name       = "guest-pipe-read";
	read_file->real_name  = "/dev/pipe-read";
	read_file->special    = SpecialFile::PipeRead;
	read_file->pipe       = pipe;
	read_file->readable   = true;
	read_file->opened     = true;
	write_file->name      = "guest-pipe-write";
	write_file->real_name = "/dev/pipe-write";
	write_file->special   = SpecialFile::PipeWrite;
	write_file->pipe      = std::move(pipe);
	write_file->writable  = true;
	write_file->opened    = true;
	Memory::InvalidateMemory(reinterpret_cast<uint64_t>(fds), sizeof(int) * 2);
	// sceKernelPipe returns (write, read), the reverse of pipe(2). ShellUI dups fd[0] onto
	// stdout/stderr and reads fd[1].
	fds[0] = writer;
	fds[1] = reader;
	LOGF("GUEST_PIPE_CREATE writer=%d reader=%d (guest slots write,read)\n", writer, reader);
	return OK;
}

int64_t KYTY_SYSV_ABI KernelRead(int d, void* buf, size_t nbytes) {
	PRINT_NAME();

// Windows-only. Guest ranges must be committed before memcpy or a VideoOut flip
static bool NativeDceReadable(uint64_t addr, uint64_t size, bool need_write = false) {
	if (addr == 0 || size == 0 || addr > UINT64_MAX - size) {
		return false;
	}
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	const uint64_t end = addr + size;
	for (uint64_t pos = addr; pos < end;) {
		MEMORY_BASIC_INFORMATION mbi {};
		if (VirtualQuery(reinterpret_cast<const void*>(pos), &mbi, sizeof(mbi)) == 0 ||
		    mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) != 0) {
			return false;
		}
		const DWORD access   = mbi.Protect & 0xff;
		const bool  readable = access == PAGE_READONLY || access == PAGE_READWRITE ||
		                       access == PAGE_WRITECOPY || access == PAGE_EXECUTE_READ ||
		                       access == PAGE_EXECUTE_READWRITE || access == PAGE_EXECUTE_WRITECOPY;
		const bool  writable = access == PAGE_READWRITE || access == PAGE_WRITECOPY ||
		                       access == PAGE_EXECUTE_READWRITE || access == PAGE_EXECUTE_WRITECOPY;
		if (!readable || (need_write && !writable)) {
			return false;
		}
		const uint64_t limit = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
		if (limit <= pos) {
			return false;
		}
		pos = std::min(limit, end);
	}
	return true;
#else
	(void)addr;
	(void)size;
	(void)need_write;
	return false;
#endif
}

static bool NativeDceGuestFrameMapped(uint64_t addr, uint64_t size, bool need_write = true) {
	if (addr == 0 || size == 0 || addr > UINT64_MAX - size) {
		return false;
	}
	const uint64_t end = addr + size;
	for (uint64_t current = addr; current < end;) {
		Memory::VirtualQueryInfo info {};
		if (Memory::KernelVirtualQuery(reinterpret_cast<const void*>(current), 0, &info,
		                               sizeof(info)) != 0 ||
		    !info.is_committed || (info.protection & (need_write ? 2u : 1u)) == 0 ||
		    current < info.start || info.end <= current) {
			return false;
		}
		current = std::min<uint64_t>(info.end, end);
	}
	return true;
}

struct NativeDceEnvelope {
	uint64_t command;
	uint32_t display_id;
	uint32_t payload_size;
	uint64_t payload_addr;
	uint64_t index_or_zero;
	uint64_t result_addr;
	uint64_t result_size;
};
static_assert(sizeof(NativeDceEnvelope) == 0x30);
static_assert(offsetof(NativeDceEnvelope, payload_addr) == 0x10);
static_assert(offsetof(NativeDceEnvelope, index_or_zero) == 0x18);

struct NativeDceRegisterPayload {
	uint64_t zero0;
	uint32_t zero8;
	uint32_t register_base_index; // start index, 0 for splash
	uint64_t guest_data;
	uint64_t zero18;
	uint64_t metadata;
	uint64_t zero28;
};
static_assert(sizeof(NativeDceRegisterPayload) == 0x30);
static_assert(offsetof(NativeDceRegisterPayload, guest_data) == 0x10);

// built at SysAv 0x464BE4..0x464C27; the returned 8-byte status doesn't depend on it
struct NativeDceFlipPayload {
	uint64_t zero0;
	int64_t  buffer_index;
	uint32_t flip_mode;
	uint32_t shifted_flags;
	int64_t  flip_arg;
	uint64_t sequence;
	uint32_t extended_flag;
	uint32_t zero2c;
	uint64_t extended_ptr;
	uint64_t zero38;
	uint64_t zero40;
};

int NativeDceClient::Ioctl(const NativeDceEnvelope& envelope) {
	Common::LockGuard lock(mutex);
	if (!live || pid != Process::GetPid() || cookie != envelope.display_id || display_handle < 0 ||
	    display_generation == 0 ||
	    VideoOut::VideoOutNativeGetHandleGeneration(display_handle) != display_generation) {
		return KERNEL_ERROR_EINVAL;
	}
	if (scope != nullptr) {
		const int rc = scope->Validate(lease);
		if (rc != OK) return rc;
	}
	if (envelope.command == 0x38) {
		if (envelope.payload_size != 0x60 || envelope.index_or_zero != 0 ||
		    envelope.result_addr != 0 || envelope.result_size != 0)
			return KERNEL_ERROR_EINVAL;
		if (!NativeDceReadable(envelope.payload_addr, 0x60) ||
		    !NativeDceGuestFrameMapped(envelope.payload_addr, 0x60, false))
			return KERNEL_ERROR_EFAULT;
		if (attributes) return KERNEL_ERROR_EBUSY;
		uint64_t original[12];
		std::memcpy(original, reinterpret_cast<const void*>(envelope.payload_addr),
		            sizeof(original));
		const int rc = VideoOut::VideoOutNativeConfigureSplashAttributes(
		    original, std::size(original), display_handle, display_generation);
		if (rc != OK) return KERNEL_ERROR_EINVAL;
		attributes = true;
		LOGF("NATIVE_DCE_CLIENT_ATTRIBUTES_REGISTERED pid=%d cookie=0x%x group=0"
		     " layout=linear format=0x8000000000000000 width=1920 height=1080 pitch=1920 "
		     "bytes=0x7e9000\n",
		     pid, cookie);
		return OK;
	}
	if (envelope.command == 0x37) {
		if (!attributes || envelope.payload_size != 0x30 ||
		    envelope.index_or_zero >= buffers.size() || envelope.result_addr != 0 ||
		    envelope.result_size != 0)
			return KERNEL_ERROR_EINVAL;
		if (!NativeDceReadable(envelope.payload_addr, sizeof(NativeDceRegisterPayload)) ||
		    !NativeDceGuestFrameMapped(envelope.payload_addr, sizeof(NativeDceRegisterPayload),
		                               false))
			return KERNEL_ERROR_EFAULT;
		NativeDceRegisterPayload payload;
		std::memcpy(&payload, reinterpret_cast<const void*>(envelope.payload_addr),
		            sizeof(payload));
		if (payload.zero0 != 0 || payload.zero8 != 0 || payload.register_base_index != 0 ||
		    payload.zero18 != 0 || payload.metadata != 0 || payload.zero28 != 0)
			return KERNEL_ERROR_EINVAL;
		if ((payload.guest_data & 0xffu) != 0 ||
		    !NativeDceReadable(payload.guest_data, 0x7e9000, true) ||
		    !NativeDceGuestFrameMapped(payload.guest_data, 0x7e9000))
			return KERNEL_ERROR_EFAULT;
		if (buffers[envelope.index_or_zero] != 0) return KERNEL_ERROR_EBUSY;
		const int rc = VideoOut::VideoOutNativeRegisterSplashBuffer(
		    &display_handle, static_cast<int>(envelope.index_or_zero), payload.guest_data,
		    &display_generation);
		if (rc != OK) return KERNEL_ERROR_EINVAL;
		buffers[envelope.index_or_zero] = payload.guest_data;
		LOGF("FIRST_FRAME_AUDIT SYSAV_DCE_REGISTER_CONFIRMED cookie=0x%x index=%" PRIu64
		     " guest_addr=0x%016" PRIx64 "\n",
		     cookie, envelope.index_or_zero, payload.guest_data);
		return OK;
	}
	if (envelope.command == 0x0a) {
		if (envelope.payload_size != 0x80 || envelope.index_or_zero != 0 ||
		    envelope.result_addr != 0 || envelope.result_size != 0)
			return KERNEL_ERROR_EINVAL;
		if (!NativeDceReadable(envelope.payload_addr, 0x80, true) ||
		    !NativeDceGuestFrameMapped(envelope.payload_addr, 0x80))
			return KERNEL_ERROR_EFAULT;
		uint64_t status[16] {};
		if (VideoOut::VideoOutNativeGetFlipStatus(display_handle, status, std::size(status),
		                                          display_generation) != OK)
			return KERNEL_ERROR_EINVAL;
		Memory::InvalidateMemory(envelope.payload_addr, sizeof(status));
		std::memcpy(reinterpret_cast<void*>(envelope.payload_addr), status, sizeof(status));
		return OK;
	}
	if (envelope.command != 0x36 || !attributes || envelope.payload_size != 0x48 ||
	    envelope.index_or_zero != 0 || envelope.result_size != 8)
		return KERNEL_ERROR_EINVAL;
	if (!NativeDceReadable(envelope.payload_addr, sizeof(NativeDceFlipPayload)) ||
	    !NativeDceGuestFrameMapped(envelope.payload_addr, sizeof(NativeDceFlipPayload), false) ||
	    !NativeDceReadable(envelope.result_addr, 8, true) ||
	    !NativeDceGuestFrameMapped(envelope.result_addr, 8))
		return KERNEL_ERROR_EFAULT;
	NativeDceFlipPayload flip;
	std::memcpy(&flip, reinterpret_cast<const void*>(envelope.payload_addr), sizeof(flip));
	if (flip.zero0 != 0 || flip.buffer_index < 0 || flip.buffer_index >= 4 || flip.flip_mode != 1 ||
	    flip.shifted_flags != 0 || flip.extended_flag != 0 || flip.zero2c != 0 ||
	    flip.extended_ptr != 0 || flip.zero38 != 0 || flip.zero40 != 0 ||
	    buffers[flip.buffer_index] == 0 ||
	    (has_flip_sequence && flip.sequence <= last_flip_sequence))
		return KERNEL_ERROR_EINVAL;
	if (!NativeDceReadable(buffers[flip.buffer_index], 0x7e9000, true) ||
	    !NativeDceGuestFrameMapped(buffers[flip.buffer_index], 0x7e9000))
		return KERNEL_ERROR_EFAULT;
	const int rc = VideoOut::VideoOutNativeSubmitSplashFlip(
	    display_handle, static_cast<int>(flip.buffer_index), static_cast<int>(flip.flip_mode),
	    flip.flip_arg, buffers[flip.buffer_index], display_generation);
	if (rc != OK)
		return rc == VideoOut::VIDEO_OUT_ERROR_INVALID_VALUE ? KERNEL_ERROR_EINVAL
		                                                     : KERNEL_ERROR_EBUSY;
	last_flip_sequence    = flip.sequence;
	has_flip_sequence     = true;
	const uint64_t result = 0;
	Memory::InvalidateMemory(envelope.result_addr, sizeof(result));
	std::memcpy(reinterpret_cast<void*>(envelope.result_addr), &result, sizeof(result));
	LOGF("FIRST_FRAME_AUDIT SYSAV_DCE_FLIP_ACCEPTED cookie=0x%x index=%" PRId64
	     " guest_addr=0x%016" PRIx64 " sequence=%" PRIu64 " presentation=async\n",
	     cookie, flip.buffer_index, buffers[flip.buffer_index], flip.sequence);
	return OK;
}

// SysAv 0x476A4F..0x476A86: 0x28-byte in/out for /dev/dmem[0..2] ioctl 0xC0288001, qword 0 returns
// the address
struct NativeDmemAllocatePayload {
	int64_t  search_start;
	int64_t  search_end;
	uint64_t length;
	uint64_t alignment;
	uint32_t memory_type;
	uint32_t reserved;
};
static_assert(sizeof(NativeDmemAllocatePayload) == 0x28);
static_assert(offsetof(NativeDmemAllocatePayload, length) == 0x10);
static_assert(offsetof(NativeDmemAllocatePayload, alignment) == 0x18);
static_assert(offsetof(NativeDmemAllocatePayload, memory_type) == 0x20);

struct NativeSshotRequest {
	uint32_t                  status;
	uint32_t                  reserved04;
	uint64_t                  region;
	uint64_t                  reserved10;
	uint32_t                  size;
	uint32_t                  block_size;
	uint32_t                  value;
	std::array<uint8_t, 0x4c> reserved24;
};
static_assert(sizeof(NativeSshotRequest) == 0x70);
static_assert(offsetof(NativeSshotRequest, region) == 0x08);
static_assert(offsetof(NativeSshotRequest, size) == 0x18);
static_assert(offsetof(NativeSshotRequest, block_size) == 0x1c);
static_assert(offsetof(NativeSshotRequest, value) == 0x20);








int KYTY_SYSV_ABI KernelIoctl(int d, uint64_t request, void* arg) {
	PRINT_NAME();
	if (request == 0x80049301u) {
		int32_t value = 0;
		if (!Memory::CopyFromGuest(&value, arg, sizeof(value))) return KERNEL_ERROR_EFAULT;
		if (::Libs::Network::Net::IsSocket(d)) {
			const int result = ::Libs::Network::Net::SetLocalSocketPolicy(d, value);
			return result >= 0 ? result : PosixToKernel(*Posix::GetErrorAddr());
		}
	}
	if (IsTmpfsDescriptor(d)) return KERNEL_ERROR_ENOTTY;
	if (request == 0xc0048118u && std::getenv("KYTY_DIAGNOSTIC_TRACE_GC_IOCTL") != nullptr) {
		LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_GC_IOCTL_QUERY fd=%d request=0x%08" PRIx64
		     " arg=0x%016" PRIx64 "\n",
		     d, request, reinterpret_cast<uint64_t>(arg));
	}

	if (d < DESCRIPTOR_MIN) {
		return KERNEL_ERROR_EBADF;

	if (::Libs::Network::Net::IsSocket(d)) {
		const auto result = ::Libs::Network::Net::Ioctl(d, request, arg);
		return (result >= 0 ? result : PosixToKernel(*Posix::GetErrorAddr()));
	}

	auto* file = g_files->GetFile(d);
	if (file == nullptr || !file->opened) {
		return KERNEL_ERROR_EBADF;
	}
	if (file->special == SpecialFile::LvdCtl) return LvdIoctl(request, arg);
	if (file->special == SpecialFile::LvdDevice) {
		if (!file->lvd) return KERNEL_ERROR_ENXIO;
		if (request == 0x40046480u) {
			return Memory::CopyToGuest(arg, &file->lvd->sector_size, sizeof(file->lvd->sector_size))
			           ? OK
					   : KERNEL_ERROR_EFAULT;
		}
		if (request == 0x40086481u) {
			return Memory::CopyToGuest(arg, &file->lvd->capacity, sizeof(file->lvd->capacity))
			           ? OK
					   : KERNEL_ERROR_EFAULT;
		}
		return KERNEL_ERROR_ENOTTY;
	}
	if (file->sector_backing) {
		const size_t size = request == 0x40046480u   ? sizeof(uint32_t)
		                    : request == 0x40086481u ? sizeof(uint64_t)
		                                             : 0;
		if (!size) return KERNEL_ERROR_ENOTTY;
		if (!GuestSocketBufferAccessible(arg, size, true)) return KERNEL_ERROR_EFAULT;
		const uint64_t value =
		    size == 4 ? file->sector_backing->SectorSize() : file->sector_backing->Capacity();
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(arg), size);
		std::memcpy(arg, &value, size);
		return OK;
	}

	// runs on the small guest stack, fmt::sprintf can overflow it
	if (std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == nullptr ||
	    std::getenv("KYTY_DIAGNOSTIC_VERBOSE_KERNEL_IOCTL_LOG") != nullptr) {
		LOGF("\t device = %s\n\t request = 0x%08" PRIx64 "\n\t arg = 0x%016" PRIx64 "\n",
		     file->name.c_str(), request, reinterpret_cast<uint64_t>(arg));
	}
	if (file->special == SpecialFile::NativeS3da) {
		LOGF("S3DA_DEVICE_IOCTL_UNSUPPORTED guest_pid=%d fd=%d request=0x%08" PRIx64
		     " arg=0x%016" PRIx64 " error=ENOTTY\n",
		     Process::GetPid(), d, request, reinterpret_cast<uint64_t>(arg));
		return KERNEL_ERROR_ENOTTY;
	}
	if (file->special == SpecialFile::NativeNsidCtl) {
		if (request != 0x20003102u) return KERNEL_ERROR_ENOTTY;
		std::lock_guard lock(g_a53_controller.mutex);
		g_a53_controller.namespace_present = true;
		LOGF("A53_STORAGE_NAMESPACE_CREATE fd=%d"
		     " result=0 NON_AUTHENTIC\n",
		     d);
		return OK;
	}
	if (file->special == SpecialFile::NativeSsd) {
		if (request == 0x40086481u) {
			if (!GuestSocketBufferAccessible(arg, sizeof(uint64_t), true))
				return KERNEL_ERROR_EFAULT;
			uint64_t capacity = A53_WHOLE_MEDIA_CAPACITY;
			if (file->name == "/dev/ssd0.bd_rvlist") capacity = A53_BD_RVLIST_CAPACITY;
			if (file->name == "/dev/ssd0.swap") capacity = A53_SWAP_CAPACITY;
			if (file->name == "/dev/ssd0.swapx0") capacity = A53_SWAPX0_CAPACITY;
			if (file->name == "/dev/ssd0.swapx1") capacity = A53_SWAPX1_CAPACITY;
			if (file->name == "/dev/ssd0.swapx2") capacity = A53_SWAPX2_CAPACITY;
			if (file->name == "/dev/ssd0.system" || file->name == "/dev/ssd0.system_b")
				capacity = A53_SYSTEM_CAPACITY;
			if (file->name == "/dev/ssd0.system_ex" || file->name == "/dev/ssd0.system_ex_b")
				capacity = A53_SYSTEM_EX_CAPACITY;
			if (file->name == "/dev/ssd0.preinst") capacity = A53_PREINST_CAPACITY;
			if (file->name == "/dev/ssd0.app_temp0") capacity = A53_APP_TEMP0_CAPACITY;
			if (file->name == "/dev/ssd0.system_data") capacity = A53_SYSTEM_DATA_CAPACITY;
			if (file->name == "/dev/ssd0.update") capacity = A53_UPDATE_CAPACITY;
			if (file->name == "/dev/ssd0.app_swap") capacity = A53_APP_SWAP_CAPACITY;
			if (file->name == "/dev/ssd0.hibernation") capacity = A53_HIBERNATION_CAPACITY;
			if (file->name == "/dev/ssd0.user") capacity = A53_USER_CAPACITY;
			Memory::InvalidateMemory(reinterpret_cast<uint64_t>(arg), sizeof(capacity));
			std::memcpy(arg, &capacity, sizeof(capacity));
			LOGF("A53_STORAGE_GEOMETRY fd=%d request=0x%08" PRIx64 " capacity=%" PRIu64
			     " firmware_table_or_console_sourced NON_AUTHENTIC\n",
			     d, request, capacity);
			return OK;
		}
		if (request == 0x40043105u) {
			if (!GuestSocketBufferAccessible(arg, sizeof(uint32_t), true))
				return KERNEL_ERROR_EFAULT;
			const uint32_t nand_for_t = 0;
			Memory::InvalidateMemory(reinterpret_cast<uint64_t>(arg), sizeof(nand_for_t));
			std::memcpy(arg, &nand_for_t, sizeof(nand_for_t));
			LOGF("A53_STORAGE_GEOMETRY fd=%d request=0x%08" PRIx64
			     " is_nand_for_t=0 NON_AUTHENTIC\n",
			     d, request);
			return OK;
		}
		return KERNEL_ERROR_ENOTTY;
	}
	if (file->special == SpecialFile::BfsCtl) {
		// SCFSTAT, 256 B out. sub_41A820 rejects qword 0 of 0 ("bad TLC block number"), so NSID1
		// size goes at +0 and +128; SLC/TLC SB sizes at +2/+10 are one 64 KiB superblock.
		if (request == 0x4100BF0Au) {
			if (!GuestSocketBufferAccessible(arg, 256, true)) return KERNEL_ERROR_EFAULT;
			auto       backing = FindSectorPayload("/dev/ssd0.user");
			const bool probe_pass =
			    std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_BFS_PROBE_PASS") != nullptr;
			if (!backing && !probe_pass) return KERNEL_ERROR_ENXIO;
			uint8_t        buffer[256] {};
			const uint32_t sb_blocks = 1;
			std::memcpy(buffer + 2, &sb_blocks, sizeof(sb_blocks));
			std::memcpy(buffer + 10, &sb_blocks, sizeof(sb_blocks));
			const uint64_t nsid1_blocks = backing ? backing->Capacity() / 0x10000 : 0x80000ull;
			std::memcpy(buffer + 0, &nsid1_blocks, sizeof(nsid1_blocks));
			std::memcpy(buffer + 128, &nsid1_blocks, sizeof(nsid1_blocks));
			Memory::InvalidateMemory(reinterpret_cast<uint64_t>(arg), sizeof(buffer));
			std::memcpy(arg, buffer, sizeof(buffer));
			LOGF("BFS_CTL_SCFSTAT fd=%d request=0x%08" PRIx64 " nsid1_blocks=%" PRIu64
			     " sb_blocks=%u %s\n",
			     d, request, nsid1_blocks, sb_blocks,
			     backing ? "NON_AUTHENTIC" : "PROBE_PASS_STANDIN NON_AUTHENTIC");
			return OK;
		}
		// A53IO_READ_BLOCK: 56 B descriptor in, 64 KiB iobuf to the pointer at +24. LBN at +16
		// (byte_offset >> 16), selector at +0 must be 1 (NSID1).
		if (request == 0xC03861A1u) {
			if (!GuestSocketBufferAccessible(arg, 56, false)) return KERNEL_ERROR_EFAULT;
			uint8_t descriptor_bytes[56];
			std::memcpy(descriptor_bytes, arg, sizeof(descriptor_bytes));
			uint32_t selector = 0;
			std::memcpy(&selector, descriptor_bytes + 0, sizeof(selector));
			if (selector != 0x1u) return KERNEL_ERROR_EINVAL;
			int64_t lbn = 0;
			std::memcpy(&lbn, descriptor_bytes + 16, sizeof(lbn));
			if (lbn < 0) return KERNEL_ERROR_EINVAL;
			uint64_t user_ptr = 0;
			std::memcpy(&user_ptr, descriptor_bytes + 24, sizeof(user_ptr));
			if (user_ptr == 0) return KERNEL_ERROR_EFAULT;
			void* user_buf = reinterpret_cast<void*>(user_ptr);
			if (!GuestSocketBufferAccessible(user_buf, 0x10000, true)) return KERNEL_ERROR_EFAULT;
			auto backing = FindSectorPayload("/dev/ssd0.user");
			if (backing) {
				const uint64_t byte_offset = static_cast<uint64_t>(lbn) * 0x10000;
				if (byte_offset + 0x10000 > backing->Capacity()) return KERNEL_ERROR_EIO;
				const auto result = backing->Read(byte_offset, user_buf, 0x10000);
				if (result != SectorBacking::Result::Ok) return KERNEL_ERROR_EIO;
				Memory::InvalidateMemory(user_ptr, 0x10000);
				LOGF("BFS_CTL_A53IO_READ_BLOCK fd=%d request=0x%08" PRIx64 " nsid=%u lbn=%" PRId64
				     " iobuf=0x%016" PRIx64 " NON_AUTHENTIC\n",
				     d, request, selector, lbn, user_ptr);
				return OK;
			}
			if (std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_BFS_PROBE_PASS") == nullptr) {
				return KERNEL_ERROR_ENXIO;
			}
			// probe pass: zero block with BFS magic 0x10f50bf520180705 at +0, so sub_41A140 matches
			// and fsck returns 0x40
			std::memset(user_buf, 0, 0x10000);
			const uint64_t magic = 0x10f50bf520180705ull;
			std::memcpy(user_buf, &magic, sizeof(magic));
			Memory::InvalidateMemory(user_ptr, 0x10000);
			LOGF("BFS_CTL_A53IO_READ_BLOCK_PROBE_PASS_MAGIC_STANDIN fd=%d request=0x%08" PRIx64
			     " nsid=%u lbn=%" PRId64 " iobuf=0x%016" PRIx64 " magic=0x%016" PRIx64
			     " NON_AUTHENTIC\n",
			     d, request, selector, lbn, user_ptr, magic);
			return OK;
		}
		// sub_41B090 metadata-location fast path, 64 B INOUT: metadata LBN at +0, mirror LBN at +8.
		// Both 0, the fixture keeps metadata at LBN 0.
		if (request == 0xC040BF5Bu) {
			if (!GuestSocketBufferAccessible(arg, 64, true)) return KERNEL_ERROR_EFAULT;
			if (!FindSectorPayload("/dev/ssd0.user")) return KERNEL_ERROR_ENXIO;
			uint8_t        buffer[64] {};
			const uint32_t metadata_lbn = 0;
			const uint32_t mirror_lbn   = 0;
			std::memcpy(buffer + 0, &metadata_lbn, sizeof(metadata_lbn));
			std::memcpy(buffer + 8, &mirror_lbn, sizeof(mirror_lbn));
			Memory::InvalidateMemory(reinterpret_cast<uint64_t>(arg), sizeof(buffer));
			std::memcpy(arg, buffer, sizeof(buffer));
			LOGF("BFS_CTL_LOCATE_METADATA fd=%d request=0x%08" PRIx64
			     " metadata_lbn=%u mirror_lbn=%u NON_AUTHENTIC\n",
			     d, request, metadata_lbn, mirror_lbn);
			return OK;
		}
		// 070-head fallback (sub_41B010), 1056 B keyed by path at +0. Caller takes ENOENT as soft
		// success, so the fast path wins
		if (request == 0xC420BF5Bu) {
			if (!GuestSocketBufferAccessible(arg, 1056, false)) return KERNEL_ERROR_EFAULT;
			char dev_path[1024] {};
			std::memcpy(dev_path, arg, sizeof(dev_path) - 1);
			if (std::getenv("KYTY_DIAGNOSTIC_SAFE_MODE_BFS_PROBE_PASS") != nullptr) {
				LOGF("BFS_CTL_LOCATE_METADATA_070_PROBE_PASS_STANDIN fd=%d request=0x%08" PRIx64
				     " path=\"%.1023s\" buffer_zeroed_except_path=1 NON_AUTHENTIC\n",
				     d, request, dev_path);
				return OK;
			}
			LOGF("BFS_CTL_LOCATE_METADATA_070_FALLBACK fd=%d request=0x%08" PRIx64
			     " path=\"%.1023s\" result=ENOENT NON_AUTHENTIC\n",
			     d, request, dev_path);
			return KERNEL_ERROR_ENOENT;
		}
		const unsigned ioc_dir   = static_cast<unsigned>((request >> 30) & 0x3u);
		const unsigned ioc_size  = static_cast<unsigned>((request >> 16) & 0x3fffu);
		const unsigned ioc_group = static_cast<unsigned>((request >> 8) & 0xffu);
		const unsigned ioc_nr    = static_cast<unsigned>(request & 0xffu);
		LOGF("BFS_CTL_UNHANDLED fd=%d request=0x%08" PRIx64
		     " dir=%u size=%u group=0x%02x nr=0x%02x result=ENOTTY\n",
		     d, request, ioc_dir, ioc_size, ioc_group, ioc_nr);
		return KERNEL_ERROR_ENOTTY;
	}
	if (file->special == SpecialFile::GcDiagnostic) {
		if (request != 0xc0048118u && request != 0xc004812eu) {
			LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_GC_UNKNOWN_IOCTL request=0x%08" PRIx64 "\n",
			     request);
			return KERNEL_ERROR_ENOTTY;
		}
		if (arg == nullptr) {
			return KERNEL_ERROR_EFAULT;
		}
		auto* value = static_cast<uint32_t*>(arg);
		if (*value != 0) {
			LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_GC_STATUS_NONZERO value=0x%08" PRIx32 "\n", *value);
			return KERNEL_ERROR_EINVAL;
		}
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(arg), sizeof(uint32_t));
		*value = 0;
		LOGF("FIRST_FRAME_AUDIT DIAGNOSTIC_GC_STATUS_IOCTL request=0x%08" PRIx64
		     " input=0 output=0\n",
		     request);
		return OK;
	}

	if (file->special == SpecialFile::Npdrm) {
		if (request == 0xc0044e05u) {
			if (arg == nullptr) {
				return KERNEL_ERROR_EFAULT;
			}
			Memory::InvalidateMemory(reinterpret_cast<uint64_t>(arg), sizeof(uint32_t));
			*static_cast<uint32_t*>(arg) = 0;
			return OK;
		}
		return KERNEL_ERROR_ENOTTY;
	}

	if (file->special != SpecialFile::Dipsw) {
		return KERNEL_ERROR_ENOTTY;
	}

	if (request == 0x20008800u) {
		return OK;
	}

	if (request == 0xc0088803u) {
		if (arg == nullptr) {
			return KERNEL_ERROR_EFAULT;
		}

		struct DipswBit {
			uint16_t index;
			uint16_t reserved;
			uint32_t value;
		};
		static_assert(sizeof(DipswBit) == 8);

		auto* bit = static_cast<DipswBit*>(arg);
		if (bit->index >= 256) {
			return KERNEL_ERROR_EINVAL;
		}
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(arg), sizeof(DipswBit));
		bit->value = 0;
		return OK;
	}

	if (request == 0x8010880au) {
		struct DipswStateBuffer {
			void*    data;
			uint64_t size;
		};

		if (arg == nullptr) {
			return KERNEL_ERROR_EFAULT;
		}

		auto* state = static_cast<DipswStateBuffer*>(arg);
		if (state->data == nullptr || state->size < 0x20u) {
			return KERNEL_ERROR_EFAULT;
		}

		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(state->data), 0x20u);
		std::memset(state->data, 0, 0x20u);
		return OK;
	}

	return KERNEL_ERROR_ENOTTY;
}



		return KERNEL_ERROR_EPERM;
	}

	if (buf == nullptr) {
		return KERNEL_ERROR_EFAULT;
	}

	if (::Libs::Network::Net::IsSocket(d)) {
		const auto result = ::Libs::Network::Net::Recv(d, buf, nbytes, 0);
		return (result >= 0 ? result : PosixToKernel(*Posix::GetErrorAddr()));
	}

	auto* file = g_files->GetFile(d);

	if (file == nullptr) {
		return KERNEL_ERROR_EBADF;
	}

	EXIT_IF(!file->opened);

	if (nbytes > INT_MAX) {
		return KERNEL_ERROR_EINVAL;
	}
	if (file->directory) {
		Common::LockGuard lock(file->mutex);
		const auto        bytes = ReadDirectory(file, buf, nbytes);
		LOGF("\tRead %" PRIu64 " directory bytes from: %s\n", bytes,
		     Common::PathToString(file->real_name).c_str());
		return static_cast<int64_t>(bytes);
	}

	if (file->special == SpecialFile::Random) {
		FillRandomBuffer(buf, nbytes);

		LOGF("\tRead %" PRIu64 " random bytes from: %s\n", static_cast<uint64_t>(nbytes),
		     Common::PathToString(file->real_name).c_str());

		return static_cast<int64_t>(nbytes);
	}

	file->mutex.Lock();

	bool       is_invalid = file->f.IsInvalid();
	const auto pos        = file->f.Tell();
	const auto file_size  = file->f.Size();
	const auto remaining  = pos < file_size ? file_size - pos : 0;
	Memory::InvalidateMemory(reinterpret_cast<uint64_t>(buf),
	                         std::min<uint64_t>(nbytes, remaining));
	uint32_t bytes_read = 0;
	file->f.Read(buf, static_cast<uint32_t>(nbytes), &bytes_read);

	file->mutex.Unlock();

	if (is_invalid) {
		LOGF("\tfile is invalid\n");
		return KERNEL_ERROR_EIO;
	}

	LOGF("\tRead %u bytes from: %s\n", bytes_read, Common::PathToString(file->real_name).c_str());

	return bytes_read;
}

int64_t KYTY_SYSV_ABI KernelWrite(int d, const void* buf, size_t nbytes) {
	PRINT_NAME();

	if (buf == nullptr &&
	    (nbytes != 0 || (!IsSectorPayloadDescriptor(d) && !IsIccnvs4SnapshotDescriptor(d) &&
	                     !IsTmpfsDescriptor(d) && !IsExfatDescriptor(d) &&
	                     !IsPassthroughDescriptor(d) && !IsLvdDescriptor(d)))) {
		return KERNEL_ERROR_EFAULT;
	}

	if (d == 1 || d == 2) {
		auto*      out      = (d == 1 ? stdout : stderr);
		const auto written  = std::fwrite(buf, 1, nbytes, out);
		const auto flush_ok = std::fflush(out) == 0;

		if (written != nbytes || !flush_ok) {
			return KERNEL_ERROR_EIO;
		}

		return static_cast<int64_t>(written);
	}

	if (d < DESCRIPTOR_MIN) {
		return KERNEL_ERROR_EBADF;
	}

	if (::Libs::Network::Net::IsSocket(d)) {
		const auto result = ::Libs::Network::Net::Send(d, buf, nbytes, 0);
		return (result >= 0 ? result : PosixToKernel(*Posix::GetErrorAddr()));
	}

	auto* file = g_files->GetFile(d);

	if (file == nullptr || !file->opened || !file->writable) {
		return KERNEL_ERROR_EBADF;
	}

	EXIT_NOT_IMPLEMENTED(file->directory);
	EXIT_NOT_IMPLEMENTED(file->special != SpecialFile::None);

	EXIT_IF(!file->opened);
	if (g_mount_points->IsReadOnly(file->real_name)) return KERNEL_ERROR_EROFS;

	if (nbytes > UINT_MAX) return KERNEL_ERROR_EINVAL;
	if (!GuestSocketBufferAccessible(buf, nbytes, false)) return KERNEL_ERROR_EFAULT;

	Common::LockGuard lock(file->mutex);
	if (file->f.IsInvalid()) return KERNEL_ERROR_EIO;
	uint32_t bytes_written = 0;
	if (file->append && !file->f.Seek(file->f.Size())) return KERNEL_ERROR_EIO;
	std::error_code host_error;
	file->f.Write(buf, static_cast<uint32_t>(nbytes), &bytes_written, &host_error);
	const bool flushed = !file->sync_writes || file->f.Flush();
	if (!flushed || (bytes_written == 0 && host_error)) return KERNEL_ERROR_EIO;

	LOGF("\tWrite %u bytes to: %s\n", bytes_written, Common::PathToString(file->real_name).c_str());

	return bytes_written;
}

int64_t KYTY_SYSV_ABI KernelPread(int d, void* buf, size_t nbytes, int64_t offset) {
	PRINT_NAME();

	if (d < DESCRIPTOR_MIN) {
		return d >= 0 ? KERNEL_ERROR_ESPIPE : KERNEL_ERROR_EBADF;
	}

	if (buf == nullptr && nbytes != 0) {
		return KERNEL_ERROR_EFAULT;
	}

	if (offset < 0) {
		return KERNEL_ERROR_EINVAL;
	}

	auto* file = g_files->GetFile(d);

	if (file == nullptr || !file->opened || !file->readable) {
		return KERNEL_ERROR_EBADF;
	}
	if (file->tmpfs)
		return TransferTmpfs(file, buf, nbytes, static_cast<uint64_t>(offset), false, false);
	if (file->exfat) return TransferExfat(file, buf, nbytes, static_cast<uint64_t>(offset), false);
	if (file->bfs) return TransferBfs(file, buf, nbytes, static_cast<uint64_t>(offset), false);
	if (file->passthrough)
		return TransferPassthrough(file, buf, nbytes, static_cast<uint64_t>(offset), false);
	if (file->iccnvs4_snapshot)
		return TransferIccnvs4Snapshot(file, buf, nbytes, static_cast<uint64_t>(offset), false,
		                               false);
	if (file->sector_backing)
		return TransferSectorPayload(file, static_cast<uint64_t>(offset), buf, nbytes, false);
	if (file->lvd) return TransferLvd(file->lvd, buf, nbytes, static_cast<uint64_t>(offset), false);
	if (file->special == SpecialFile::NativeMbus ||
	    file->special == SpecialFile::NativeSystemMbus ||
	    file->special == SpecialFile::NativeAvDevice || file->special == SpecialFile::NativeMetadbg)
		return KERNEL_ERROR_ESPIPE;
	if (file->special == SpecialFile::NativeS3da) {
		return file->readable ? KERNEL_ERROR_ENOSYS : KERNEL_ERROR_EBADF;
	}

	EXIT_NOT_IMPLEMENTED(file->directory);

	EXIT_IF(!file->opened);

	EXIT_NOT_IMPLEMENTED(nbytes > UINT_MAX);

	if (file->special == SpecialFile::Random) {
		FillRandomBuffer(buf, nbytes);

		LOGF("\tRead %" PRIu64 " random bytes (pos = %" PRId64 ") from: %s\n",
		     static_cast<uint64_t>(nbytes), offset, Common::PathToString(file->real_name).c_str());

		return static_cast<int64_t>(nbytes);
	}

	if (!file->readable) return KERNEL_ERROR_EBADF;
	Common::LockGuard lock(file->mutex);
	if (file->f.IsInvalid()) return KERNEL_ERROR_EIO;
	auto       pos        = file->f.Tell();
	const auto file_size  = file->f.Size();
	const auto remaining =
	    static_cast<uint64_t>(offset) < file_size ? file_size - static_cast<uint64_t>(offset) : 0;
	Memory::InvalidateMemory(reinterpret_cast<uint64_t>(buf),
	                         std::min<uint64_t>(nbytes, remaining));
	uint32_t bytes_read = 0;
	if (!file->f.Seek(static_cast<uint64_t>(offset))) return KERNEL_ERROR_EIO;
	std::error_code host_error;
	file->f.Read(buf, static_cast<uint32_t>(nbytes), &bytes_read, &host_error);
	if (!file->f.Seek(pos)) return KERNEL_ERROR_EIO;
	if (bytes_read == 0 && host_error) return KERNEL_ERROR_EIO;

	if (file->name == "/dev/iccnvs4" && std::getenv("KYTY_PS5_ICCNVS4_IMAGE") != nullptr) {
		// printf so it survives the guest-log cap
		static std::atomic<uint32_t> icc_pread_audit {0};
		if (icc_pread_audit.fetch_add(1) < 8) {
			std::printf("ICCNVS4_IMAGE_PREAD"
			            " fd=%d offset=%" PRId64 " requested=%zu"
			            " read=%u first_byte=%s%02x\n",
			            d, offset, nbytes, bytes_read, bytes_read ? "0x" : "none",
			            bytes_read ? static_cast<unsigned>(*reinterpret_cast<const uint8_t*>(buf))
			                       : 0u);
			std::fflush(stdout);
		}
	}
	LOGF("\tRead %u bytes (pos = %" PRId64 ") from: %s\n", bytes_read, offset,
	     EscapeLogPath(file->real_name).c_str());

	return bytes_read;
}

static int ValidateIovecs(const KernelIovec* iov, int iovcnt, int64_t offset,
                          std::vector<KernelIovec>* buffers, size_t* total) {
	constexpr int MaxIov = 1024;
	if (iovcnt < 0 || iovcnt > MaxIov || offset < 0) {
		return KERNEL_ERROR_EINVAL;
	}
	if (iov == nullptr && iovcnt != 0) {
		return KERNEL_ERROR_EFAULT;
	}

	if (iovcnt != 0) {
		if (!GuestSocketBufferAccessible(iov, static_cast<size_t>(iovcnt) * sizeof(*iov), false))
			return KERNEL_ERROR_EFAULT;
		buffers->assign(iov, iov + iovcnt);
	}
	*total = 0;
	for (const auto& buffer: *buffers) {
		if (buffer.iov_len > INT_MAX - *total) {
			return KERNEL_ERROR_EINVAL;
		}
		if (buffer.iov_base == nullptr && buffer.iov_len != 0) {
			return KERNEL_ERROR_EFAULT;
		}
		*total += buffer.iov_len;
	}
	return OK;
}

static int64_t TransferTmpfsVector(File* file, const std::vector<KernelIovec>& buffers,
                                   size_t total, int64_t offset, bool write) {
	if (file->directory) return KERNEL_ERROR_EISDIR;
	for (const auto& buffer: buffers) {
		if (buffer.iov_len != 0 &&
		    !GuestSocketBufferAccessible(buffer.iov_base, buffer.iov_len, !write)) {
			return KERNEL_ERROR_EFAULT;
		}
	}
	if (total == 0) return 0;
	if (static_cast<uint64_t>(offset) > static_cast<uint64_t>(INT64_MAX) - total) {
		return KERNEL_ERROR_EFBIG;
	}
	if (write && total > Tmpfs::MaximumMountBytes) return KERNEL_ERROR_ENOSPC;
	std::vector<uint8_t> data;
	try {
		data.resize(std::min<size_t>(total, Tmpfs::MaximumMountBytes));
	} catch (const std::bad_alloc&) {
		return KERNEL_ERROR_ENOMEM;
	}
	if (write) {
		size_t position = 0;
		for (const auto& buffer: buffers) {
			if (buffer.iov_len != 0)
				std::memcpy(data.data() + position, buffer.iov_base, buffer.iov_len);
			position += buffer.iov_len;
		}
		return Tmpfs::Pwrite(file->tmpfs, data.data(), data.size(), static_cast<uint64_t>(offset));
	}
	const auto result =
	    Tmpfs::Pread(file->tmpfs, data.data(), data.size(), static_cast<uint64_t>(offset));
	if (result <= 0) return result;
	size_t position = 0;
	for (const auto& buffer: buffers) {
		const auto count = std::min<size_t>(buffer.iov_len, static_cast<size_t>(result) - position);
		if (count != 0) {
			Memory::InvalidateMemory(reinterpret_cast<uint64_t>(buffer.iov_base), count);
			std::memcpy(buffer.iov_base, data.data() + position, count);
			position += count;
		}
		if (position == static_cast<size_t>(result)) break;
	}
	return result;
}

int64_t KYTY_SYSV_ABI KernelPreadv(int d, const KernelIovec* iov, int iovcnt, int64_t offset) {
	PRINT_NAME();

	std::vector<KernelIovec> buffers;
	size_t                   total = 0;
	const int                error = ValidateIovecs(iov, iovcnt, offset, &buffers, &total);
	if (error != OK) {
		return error;
	}

	if (d < DESCRIPTOR_MIN) {
		return KERNEL_ERROR_EBADF;
	}
	if (::Libs::Network::Net::IsSocket(d)) {
		return KERNEL_ERROR_ESPIPE;
	}
	auto* file = g_files->GetFile(d);
	if (file == nullptr || !file->opened || !file->readable) {
		return KERNEL_ERROR_EBADF;
	}
	if (file->tmpfs) return TransferTmpfsVector(file, buffers, total, offset, false);
	if (file->sector_backing || file->iccnvs4_snapshot || file->exfat || file->bfs ||
	    file->passthrough)
		return KERNEL_ERROR_ENOTSUP;

	Common::LockGuard lock(file->mutex);
	if (file->directory) {
		return KERNEL_ERROR_EISDIR;
	}
	if (total == 0) {
		return 0;
	}
	if (file->special == SpecialFile::Random) {
		for (const auto& buffer: buffers) {
			if (buffer.iov_len != 0) {
				Memory::InvalidateMemory(reinterpret_cast<uint64_t>(buffer.iov_base),
				                         buffer.iov_len);
				FillRandomBuffer(buffer.iov_base, buffer.iov_len);
			}
		}
		return static_cast<int64_t>(total);
	}
	if (file->f.IsInvalid()) {
		return KERNEL_ERROR_EIO;
	}

	const auto position  = file->f.Tell();
	const auto file_size = file->f.Size();
	if (!file->f.Seek(static_cast<uint64_t>(offset))) {
		return KERNEL_ERROR_EIO;
	}
	auto    remaining  = static_cast<uint64_t>(offset) < file_size ? file_size - offset : 0;
	int64_t bytes_read = 0;
	std::error_code host_error;
	for (const auto& buffer: buffers) {
		if (remaining == 0) {
			break;
		}
		if (buffer.iov_len == 0) {
			continue;
		}
		const auto count = static_cast<uint32_t>(std::min<uint64_t>(buffer.iov_len, remaining));
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(buffer.iov_base), count);
		uint32_t bytes = 0;
		file->f.Read(buffer.iov_base, count, &bytes, &host_error);
		bytes_read += bytes;
		remaining -= bytes;
		if (host_error || bytes < count) {
			break;
		}
	}
	if (!file->f.Seek(position)) {
		return KERNEL_ERROR_EIO;
	}
	if (bytes_read == 0 && host_error) return KERNEL_ERROR_EIO;
	LOGF("\tReadv %" PRId64 " bytes (pos = %" PRId64 ", iovcnt = %d) from: %s\n", bytes_read,
	     offset, iovcnt, Common::PathToString(file->real_name).c_str());
	return bytes_read;
}

int64_t KYTY_SYSV_ABI KernelPwrite(int d, const void* buf, size_t nbytes, int64_t offset) {
	PRINT_NAME();

	if (d < DESCRIPTOR_MIN) {
		return d >= 0 ? KERNEL_ERROR_ESPIPE : KERNEL_ERROR_EBADF;
	}

	if (buf == nullptr && nbytes != 0) {
		return KERNEL_ERROR_EFAULT;
	}

	if (offset < 0) {
		return KERNEL_ERROR_EINVAL;
	}

	auto* file = g_files->GetFile(d);

	if (file == nullptr || !file->opened || !file->writable) {
		return KERNEL_ERROR_EBADF;
	}
	if (file->tmpfs)
		return TransferTmpfs(file, const_cast<void*>(buf), nbytes, static_cast<uint64_t>(offset),
		                     false, true);
	if (file->passthrough)
		return WritePassthrough(file, buf, nbytes, static_cast<uint64_t>(offset), false);
	if (file->iccnvs4_snapshot)
		return TransferIccnvs4Snapshot(file, const_cast<void*>(buf), nbytes,
		                               static_cast<uint64_t>(offset), false, true);
	if (file->sector_backing)
		return TransferSectorPayload(file, static_cast<uint64_t>(offset), const_cast<void*>(buf),
		                             nbytes, true);
	if (file->lvd)
		return TransferLvd(file->lvd, const_cast<void*>(buf), nbytes, static_cast<uint64_t>(offset),
		                   true);
	if (file->special == SpecialFile::NativeS3da) {
		return KERNEL_ERROR_ENOSYS;
	}
	if (file->special == SpecialFile::NativeMetadbg) return KERNEL_ERROR_ENODEV;

	EXIT_NOT_IMPLEMENTED(file->directory);
	EXIT_NOT_IMPLEMENTED(file->special != SpecialFile::None);

	if (g_mount_points->IsReadOnly(file->real_name)) return KERNEL_ERROR_EROFS;
	if (nbytes > UINT_MAX) return KERNEL_ERROR_EINVAL;
	if (!GuestSocketBufferAccessible(buf, nbytes, false)) return KERNEL_ERROR_EFAULT;
	if (nbytes == 0) return 0;

	Common::LockGuard lock(file->mutex);
	if (file->f.IsInvalid()) return KERNEL_ERROR_EIO;
	const auto pos    = file->f.Tell();
	const auto target = file->append ? file->f.Size() : static_cast<uint64_t>(offset);
	if (target > static_cast<uint64_t>(INT64_MAX) - nbytes) return KERNEL_ERROR_EFBIG;
	uint32_t bytes_written = 0;
	if (!file->f.Seek(target)) return KERNEL_ERROR_EIO;
	std::error_code host_error;
	file->f.Write(buf, static_cast<uint32_t>(nbytes), &bytes_written, &host_error);
	const bool flushed  = !file->sync_writes || file->f.Flush();
	const bool restored = file->f.Seek(pos);
	if (!flushed || !restored || (bytes_written == 0 && host_error)) return KERNEL_ERROR_EIO;

	LOGF("\tWrite %u bytes (pos = %" PRId64 ") to: %s\n", bytes_written, offset,
	     Common::PathToString(file->real_name).c_str());

	return bytes_written;
}

int64_t KYTY_SYSV_ABI KernelPwritev(int d, const KernelIovec* iov, int iovcnt, int64_t offset) {
	PRINT_NAME();

	std::vector<KernelIovec> buffers;
	size_t                   total = 0;
	const int                error = ValidateIovecs(iov, iovcnt, offset, &buffers, &total);
	if (error != OK) {
		return error;
	}

	if (d < DESCRIPTOR_MIN) {
		return KERNEL_ERROR_EBADF;
	}
	if (::Libs::Network::Net::IsSocket(d)) {
		return KERNEL_ERROR_ESPIPE;
	}
	auto* file = g_files->GetFile(d);
	if (file == nullptr || !file->opened || !file->writable) {
		return KERNEL_ERROR_EBADF;
	}
	Common::LockGuard lock(file->mutex);
	if (file->directory) {
		return KERNEL_ERROR_EISDIR;
	}
	if (file->special != SpecialFile::None) {
		return KERNEL_ERROR_EINVAL;
	}
	if (g_mount_points->IsReadOnly(file->real_name)) return KERNEL_ERROR_EROFS;
	if (total == 0) {
		return 0;
	}
	if (file->f.IsInvalid()) {
		return KERNEL_ERROR_EIO;
	}

	const auto position = file->f.Tell();
	const auto target   = (file->append ? file->f.Size() : static_cast<uint64_t>(offset));
	if (target > static_cast<uint64_t>(INT64_MAX) - total) {
		return KERNEL_ERROR_EFBIG;
	}
	if (!file->f.Seek(target)) {
		return KERNEL_ERROR_EIO;
	}

	int64_t bytes_written = 0;
	std::error_code host_error;
	for (const auto& buffer: buffers) {
		if (buffer.iov_len == 0) {
			continue;
		}
		uint32_t bytes = 0;
		file->f.Write(buffer.iov_base, static_cast<uint32_t>(buffer.iov_len), &bytes, &host_error);
		bytes_written += bytes;
		if (host_error || bytes < buffer.iov_len) {
			break;
		}
	}
	const bool flushed  = !file->sync_writes || file->f.Flush();
	const bool restored = file->f.Seek(position);
	if (!flushed || !restored || (bytes_written == 0 && host_error)) {
		return KERNEL_ERROR_EIO;
	}

	LOGF("\tWritev %" PRId64 " bytes (pos = %" PRId64 ", iovcnt = %d) to: %s\n", bytes_written,
	     offset, iovcnt, Common::PathToString(file->real_name).c_str());
	return bytes_written;
}

int64_t KYTY_SYSV_ABI KernelLseek(int d, int64_t offset, int whence) {
	PRINT_NAME();

	if (d < DESCRIPTOR_MIN) {
		return KERNEL_ERROR_EBADF;
	}

	auto* file = g_files->GetFile(d);

	if (file == nullptr) {
		return KERNEL_ERROR_EBADF;
	}
	if (file->tmpfs && !file->directory) return Tmpfs::Seek(file->tmpfs, offset, whence);
	if (file->exfat && !file->directory) return ExfatMount::Seek(file->exfat, offset, whence);
	if (file->bfs && !file->directory) return BfsMount::Seek(file->bfs, offset, whence);
	if (file->passthrough && !file->directory)
		return DirectoryPassthrough::Seek(file->passthrough, offset, whence);
	if (file->iccnvs4_snapshot && whence == 2) return KERNEL_ERROR_ENOTSUP;

	EXIT_IF(!file->opened);
	if (file->sector_backing) {
		Common::LockGuard lock(file->mutex);
		const auto        base = whence == 0   ? 0
		                         : whence == 1 ? file->sector_position
		                                       : file->sector_backing->Capacity();
		if (whence < 0 || whence > 2 ||
		    (offset >= 0 &&
		     static_cast<uint64_t>(offset) > file->sector_backing->Capacity() - base))
			return KERNEL_ERROR_EINVAL;
		const uint64_t distance = uint64_t {0} - static_cast<uint64_t>(offset);
		if (offset < 0 && distance > base) return KERNEL_ERROR_EINVAL;
		file->sector_position = offset < 0 ? base - distance : base + static_cast<uint64_t>(offset);
		return static_cast<int64_t>(file->sector_position);
	}
	if (file->lvd) {
		Common::LockGuard lock(file->mutex);
		const auto        base = whence == 0   ? 0
		                         : whence == 1 ? file->sector_position
		                                       : file->lvd->capacity;
		if (whence < 0 || whence > 2 || base > file->lvd->capacity ||
		    (offset >= 0 && static_cast<uint64_t>(offset) > file->lvd->capacity - base))
			return KERNEL_ERROR_EINVAL;
		const uint64_t distance = uint64_t {0} - static_cast<uint64_t>(offset);
		if (offset < 0 && distance > base) return KERNEL_ERROR_EINVAL;
		file->sector_position = offset < 0 ? base - distance : base + static_cast<uint64_t>(offset);
		return static_cast<int64_t>(file->sector_position);
	}

	if (file->special != SpecialFile::None && !file->tmpfs) {
		return KERNEL_ERROR_ESPIPE;
	}

	Common::LockGuard lock(file->mutex);
	if (file->tmpfs && file->directory) {
		const int result = RefreshTmpfsDirectory(file);
		if (result != OK) return result;
	}

	if (!file->directory && file->f.IsInvalid()) {
		LOGF("\tfile is invalid\n");
		return KERNEL_ERROR_EIO;
	}

	uint64_t base = 0;
	switch (whence) {
		case 0: break;
		case 1: base = file->directory ? file->dents_offset : file->f.Tell(); break;
		case 2: base = file->directory ? file->dirents.size() : file->f.Size(); break;
		default: return KERNEL_ERROR_EINVAL;
	}

	uint64_t position = 0;
	if (offset >= 0) {
		if (base > static_cast<uint64_t>(INT64_MAX - offset)) {
			return KERNEL_ERROR_EOVERFLOW;
		}
		position = base + static_cast<uint64_t>(offset);
	} else {
		const auto distance = uint64_t {0} - static_cast<uint64_t>(offset);
		if (base < distance) {
			return KERNEL_ERROR_EINVAL;
		}
		position = base - distance;
		if (position > INT64_MAX) {
			return KERNEL_ERROR_EOVERFLOW;
		}
	}

	if (file->directory) {
		file->dents_offset = position;
	} else {
		file->f.Seek(position);
		EXIT_IF(file->f.Tell() != position);
	}

	LOGF("\tLseek (pos = %" PRIu64 ") to: %s\n", position,
	     Common::PathToString(file->real_name).c_str());

	return static_cast<int64_t>(position);
}

int KYTY_SYSV_ABI KernelStat(const char* path, FileStat* sb) {
	PRINT_NAME();
	if (std::getenv("KYTY_DIAGNOSTIC_PSS_FILESTAT") != nullptr &&
	    (path == nullptr || path[0] == '\0' || std::strncmp(path, "/app0/psm", 9) == 0)) {
		LOGF("PSS_KERNELSTAT caller=0x%016" PRIx64 " guest_path=%s sb=0x%016" PRIx64 "\n",
		     reinterpret_cast<uint64_t>(__builtin_return_address(0)), EscapeLogPath(path).c_str(),
		     reinterpret_cast<uint64_t>(sb));
#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
		void*      trace[12] {};
		const auto depth = CaptureStackBackTrace(0, 12, trace, nullptr);
		for (USHORT i = 0; i < depth; ++i) {
			LOGF("PSS_KERNELSTAT frame=%u pc=0x%016" PRIx64 "\n", i,
			     reinterpret_cast<uint64_t>(trace[i]));
		}
#endif
	}

	if (path == nullptr || sb == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}
	std::string working_path;
	const int   working = ResolveInitialWorkingDirectoryPath(&path, &working_path);
	if (working != OK) return working;
	std::string nullfs_path;
	const int   nullfs = ResolveNullfsPath(&path, &nullfs_path);
	if (nullfs != OK) return nullfs;
	if (path[0] == '/') {
		const int traversal = ValidateMountedTraversal(path);
		if (traversal != OK) return traversal;
	}
	if (DevfsInstanceAt(path) || IsDevfsRoot(path)) {
		if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(sb), sizeof(*sb));
		FillDevfsRootStat(sb);
		return OK;
	}
	if (ExfatMount::Contains(path)) {
		if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
		ExfatMount::NodeStat stat {};
		const int            result = ExfatMount::Stat(path, &stat);
		if (result != OK) return result;
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(sb), sizeof(*sb));
		FillExfatStat(stat, sb);
		return OK;
	}
	if (BfsMount::Contains(path)) {
		if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
		BfsMount::NodeStat stat {};
		const int          result = BfsMount::Stat(path, &stat);
		if (result != OK) return result;
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(sb), sizeof(*sb));
		FillBfsStat(stat, sb);
		return OK;
	}
	if (DirectoryPassthrough::Contains(path)) {
		if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
		DirectoryPassthrough::NodeStat stat {};
		const int                      result = DirectoryPassthrough::Stat(path, &stat);
		if (result != OK) return result;
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(sb), sizeof(*sb));
		FillPassthroughStat(stat, sb);
		return OK;
	}
	if (Tmpfs::Contains(path)) {
		if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
		Tmpfs::NodeStat stat {};
		const int       result = Tmpfs::Stat(path, &stat);
		if (result != OK) return result;
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(sb), sizeof(*sb));
		FillTmpfsStat(stat, sb);
		return OK;
	}
	const auto data_topology = ResolveDataTopologyPath(path);
	if (data_topology == DataTopologyPath::Missing) return KERNEL_ERROR_ENOENT;
	if (data_topology == DataTopologyPath::Directory) {
		if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(sb), sizeof(*sb));
		FillDataTopologyStat(sb);
		return OK;
	}
	if (std::strcmp(path, "/dev/lvdctl") == 0 || FindLvdDevice(path)) {
		FileStat stat {};
		FillLvdStat(&stat, std::strcmp(path, "/dev/lvdctl") != 0);
		return Memory::CopyToGuest(sb, &stat, sizeof(stat)) ? OK : KERNEL_ERROR_EFAULT;
	}
	if (auto backing = FindSectorPayload(path)) {
		if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(sb), sizeof(*sb));
		FillSectorPayloadStat(sb);
		return OK;
	}

	LOGF("\t KernelStat: %s\n", path);

	auto real_file_name = g_mount_points->ResolvePath(path);

	const char* iccnvs4_image    = std::getenv("KYTY_PS5_ICCNVS4_IMAGE");
	const bool  original_iccnvs4 = std::strcmp(path, "/dev/iccnvs4") == 0 &&
	                               iccnvs4_image != nullptr && iccnvs4_image[0] != '\0';
	const auto  real_file_name =
	    original_iccnvs4 ? std::filesystem::path(iccnvs4_image) : g_mount_points->ResolvePath(path);
	if (original_iccnvs4 && !real_file_name.is_absolute()) {
		return KERNEL_ERROR_ENOENT;
	}
	const auto info = Common::File::GetInfo(real_file_name);
	if (original_iccnvs4) {
		if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
		std::printf("ICCNVS4_IMAGE_STAT backing_size=%" PRIu64 " valid_source=%u\n",
		            info ? static_cast<uint64_t>(info->size) : 0,
		            info && info->is_file && info->size >= 0x24 ? 1u : 0u);
		std::fflush(stdout);
	}
	if (!info || (original_iccnvs4 && (!info->is_file || info->size < 0x24))) {
		DirectoryPassthrough::NodeStat directory;
		if (!original_iccnvs4 && CapturedDirectory::RootMetadata(path, &directory) == OK) {
			FileStat captured {};
			FillPassthroughStat(directory, &captured);
			if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
			Memory::InvalidateMemory(reinterpret_cast<uint64_t>(sb), sizeof(*sb));
			*sb = captured;
			return OK;
		}
		if (!original_iccnvs4 && UseCapturedRootMetadata(path)) {
			FileStat  captured {};
			const int metadata = CapturedRootMetadata::Stat(path, &captured);
			if (metadata != OK) return metadata;
			if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
			Memory::InvalidateMemory(reinterpret_cast<uint64_t>(sb), sizeof(*sb));
			*sb = captured;
			LOGF("CAPTURED_ROOT_DIRECTORY_STAT path=%s inode=0x%x mode=0%o size=%" PRId64 "\n",
			     EscapeLogPath(path).c_str(), captured.st_ino, captured.st_mode, captured.st_size);
			return OK;
		}
		LOGF("\t file not found\n");
		return KERNEL_ERROR_ENOENT;
	}

	const bool is_dir = !info->is_file;

	FileStat stat {};
	stat.st_mode =
	    original_iccnvs4 ? (0020000u | 0000660u) : (0000777u | (is_dir ? 0040000u : 0100000u));

	auto at = Common::DateTime::FromSystemUTC();
	auto wt = at;

	if (is_dir) {
		stat.st_size = static_cast<int64_t>(
		    PackDirents(g_mount_points->DirectoryEntries(path, real_file_name)).size());
		stat.st_blksize = 512;
		stat.st_blocks  = stat.st_size / 512;
	} else {
		stat.st_size    = static_cast<int64_t>(info->size);
		stat.st_blksize = 512;
		stat.st_blocks  = (stat.st_size + 511) / 512;

		Common::File::GetLastAccessAndWriteTimeUTC(real_file_name, &at, &wt);
	}

	SecToTimespec(&stat.st_atim, at.ToUnix());
	SecToTimespec(&stat.st_mtim, wt.ToUnix());
	stat.st_ctim     = stat.st_atim;
	stat.st_birthtim = stat.st_mtim;
	if (original_iccnvs4) ApplyIccnvs4NodeStat(&stat);
	*sb              = stat;

	return OK;
}

int KYTY_SYSV_ABI KernelFstat(int d, FileStat* sb) {
	PRINT_NAME();

	if (d < DESCRIPTOR_MIN) {
		return KERNEL_ERROR_EPERM;
	}

	if (sb == nullptr) {
		return KERNEL_ERROR_EFAULT;
	}

	auto* file = g_files->GetFile(d);

	if (file == nullptr) {
		return KERNEL_ERROR_EBADF;
	}

	EXIT_IF(!file->opened);

	LOGF("\tKernelFstat: %s\n", EscapeLogPath(file->real_name).c_str());

	if (file->tmpfs) {
		if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
		Tmpfs::NodeStat stat {};
		const int       result = Tmpfs::Fstat(file->tmpfs, &stat);
		if (result != OK) return result;
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(sb), sizeof(*sb));
		FillTmpfsStat(stat, sb);
		return OK;
	}
	if (file->exfat) {
		if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
		ExfatMount::NodeStat stat {};
		const int            result = ExfatMount::Fstat(file->exfat, &stat);
		if (result != OK) return result;
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(sb), sizeof(*sb));
		FillExfatStat(stat, sb);
		return OK;
	}
	if (file->bfs) {
		if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
		BfsMount::NodeStat stat {};
		const int          result = BfsMount::Fstat(file->bfs, &stat);
		if (result != OK) return result;
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(sb), sizeof(*sb));
		FillBfsStat(stat, sb);
		return OK;
	}
	if (file->passthrough) {
		if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
		DirectoryPassthrough::NodeStat stat {};
		const int result = DirectoryPassthrough::Fstat(file->passthrough, &stat);
		if (result != OK) return result;
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(sb), sizeof(*sb));
		FillPassthroughStat(stat, sb);
		return OK;
	}
	if (file->sector_backing) {
		if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(sb), sizeof(*sb));
		FillSectorPayloadStat(sb);
		return OK;
	}
	if (file->special == SpecialFile::LvdCtl || file->special == SpecialFile::LvdDevice) {
		FileStat stat {};
		FillLvdStat(&stat, file->special == SpecialFile::LvdDevice);
		return Memory::CopyToGuest(sb, &stat, sizeof(stat)) ? OK : KERNEL_ERROR_EFAULT;
	}
	if (file->data_topology) {
		if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(sb), sizeof(*sb));
		FillDataTopologyStat(sb);
		return OK;
	}
	if (file->devfs_root) {
		if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(sb), sizeof(*sb));
		FillDevfsRootStat(sb);
		return OK;
	}
	FileStat stat {};
	const bool original_iccnvs4 = file->iccnvs4_snapshot;
	if (file->special == SpecialFile::SharedMemory && file->anonymous_shared) {
		const auto size = Memory::GetAnonymousSharedMemorySize(file->anonymous_shared);
		stat.st_mode    = static_cast<uint16_t>(
		    0100000u | Memory::GetAnonymousSharedMemoryMode(file->anonymous_shared));
		stat.st_size    = static_cast<int64_t>(size);
		stat.st_blksize = 0x4000;
		stat.st_blocks  = static_cast<int64_t>((size + 0x3fffu) / 0x4000u);
		return Memory::CopyToGuest(sb, &stat, sizeof(stat)) ? OK : KERNEL_ERROR_EFAULT;
	}
	if (file->special == SpecialFile::NativeS3da || file->special == SpecialFile::NativeMetadbg) {
		stat.st_mode  = file->special == SpecialFile::NativeS3da ? 0020666u : 0020600u;
		stat.st_nlink = 1;
		return Memory::CopyToGuest(sb, &stat, sizeof(stat)) ? OK : KERNEL_ERROR_EFAULT;
	}
	if (file->special == SpecialFile::NativeMbus ||
	    file->special == SpecialFile::NativeSystemMbus ||
	    file->special == SpecialFile::NativeAvDevice || file->special == SpecialFile::Envelope ||
	    file->special == SpecialFile::Rnps) {
		stat.st_mode  = 0020600u;
		stat.st_nlink = 1;
		return Memory::CopyToGuest(sb, &stat, sizeof(stat)) ? OK : KERNEL_ERROR_EFAULT;
	}
	if (file->special == SpecialFile::NativeA53Io) {
		stat.st_mode  = 0020600u;
		stat.st_nlink = 1;
		return Memory::CopyToGuest(sb, &stat, sizeof(stat)) ? OK : KERNEL_ERROR_EFAULT;
	}
	if (file->special == SpecialFile::NativeNsidCtl || file->special == SpecialFile::NativeSsd) {
		stat.st_mode    = 0020640u;
		stat.st_nlink   = 1;
		stat.st_blksize = 16384u;
		if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(sb), sizeof(*sb));
		*sb = stat;
		return OK;
	}
	if (file->special == SpecialFile::BfsCtl) {
		stat.st_mode    = 0020640u;
		stat.st_nlink   = 1;
		stat.st_blksize = 0x10000u;
		if (!GuestSocketBufferAccessible(sb, sizeof(*sb), true)) return KERNEL_ERROR_EFAULT;
		Memory::InvalidateMemory(reinterpret_cast<uint64_t>(sb), sizeof(*sb));
		*sb = stat;
		return OK;
	}
	if (original_iccnvs4 && !GuestSocketBufferAccessible(sb, sizeof(*sb), true))
		return KERNEL_ERROR_EFAULT;
	stat.st_mode = (original_iccnvs4 || file->special == SpecialFile::NativeS3da)
	                   ? (0020000u | 0000660u)
	                   : (0000777u | (file->directory ? 0040000u : 0100000u));

	auto at = Common::DateTime::FromSystemUTC();
	auto wt = at;

	if (file->special != SpecialFile::None) {
		stat.st_size    = static_cast<int64_t>(file->special_size);
		stat.st_blksize = 512;
		stat.st_blocks  = 0;
		SecToTimespec(&stat.st_atim, at.ToUnix());
		SecToTimespec(&stat.st_mtim, wt.ToUnix());
		stat.st_ctim     = stat.st_atim;
		stat.st_birthtim = stat.st_mtim;
		*sb              = stat;

		return OK;
	}

	if (!file->directory) {
		file->mutex.Lock();

		bool is_invalid = file->f.IsInvalid();
		auto size       = file->f.Size();
		file->f.GetLastAccessAndWriteTimeUTC(&at, &wt);

		file->mutex.Unlock();

		if (is_invalid) {
			LOGF("\tfile is invalid\n");
			return KERNEL_ERROR_EIO;
		}

		stat.st_size    = static_cast<int64_t>(size);
		stat.st_blksize = 512;
		stat.st_blocks  = (stat.st_size + 511) / 512;
	} else {
		stat.st_size    = static_cast<int64_t>(file->dirents.size());
		stat.st_blksize = 512;
		stat.st_blocks  = stat.st_size / 512;
	}

	SecToTimespec(&stat.st_atim, at.ToUnix());
	SecToTimespec(&stat.st_mtim, wt.ToUnix());
	stat.st_ctim     = stat.st_atim;
	stat.st_birthtim = stat.st_mtim;
	if (original_iccnvs4) ApplyIccnvs4NodeStat(&stat);
	*sb              = stat;

	return OK;
}

int KYTY_SYSV_ABI KernelFstatfs(int d, KernelStatfs* sb) {
	PRINT_NAME();

	if (d < DESCRIPTOR_MIN || g_files == nullptr) return KERNEL_ERROR_EBADF;
	if (sb == nullptr) return KERNEL_ERROR_EFAULT;
	auto* file = g_files->GetFile(d);
	if (file == nullptr || !file->opened) return KERNEL_ERROR_EBADF;
	if (!file->passthrough) return KERNEL_ERROR_ENOSYS;

	DirectoryPassthrough::MountInfo mount;
	const int result = DirectoryPassthrough::Fstatfs(file->passthrough, &mount);
	if (result != OK) return result;
	KernelStatfs stat {};
	if (mount.guest_fstype.empty() || mount.guest_fstype.size() >= sizeof(stat.f_fstypename) ||
	    mount.guest_source.empty() || mount.guest_source.size() >= sizeof(stat.f_mntfromname) ||
	    mount.point.empty() || mount.point.size() >= sizeof(stat.f_mntonname))
		return KERNEL_ERROR_EINVAL;
	stat.f_version = 0x20030518;
	stat.f_flags   = mount.guest_flags;
	std::memcpy(stat.f_fstypename, mount.guest_fstype.data(), mount.guest_fstype.size());
	std::memcpy(stat.f_mntfromname, mount.guest_source.data(), mount.guest_source.size());
	std::memcpy(stat.f_mntonname, mount.point.data(), mount.point.size());
	return Memory::CopyToGuest(sb, &stat, sizeof(stat)) ? OK : KERNEL_ERROR_EFAULT;
}

int KYTY_SYSV_ABI KernelFtruncate(int d, int64_t length) {
	PRINT_NAME();

	if (d < DESCRIPTOR_MIN) {
		return KERNEL_ERROR_EBADF;
	}

	if (length < 0) {
		return KERNEL_ERROR_EINVAL;
	}

	if (::Libs::Network::Net::IsSocket(d)) {
		return KERNEL_ERROR_EINVAL;
	}

	auto* file = g_files->GetFile(d);

	if (file == nullptr || !file->opened) {
		return KERNEL_ERROR_EBADF;
	}

	if (!file->writable) {
		return KERNEL_ERROR_EBADF;
	}
	if (file->tmpfs) return Tmpfs::Truncate(file->tmpfs, static_cast<uint64_t>(length));
	if (file->passthrough)
		return DirectoryPassthrough::Truncate(file->passthrough, static_cast<uint64_t>(length));
	if (file->exfat) return KERNEL_ERROR_EROFS;
	if (file->bfs) return KERNEL_ERROR_EROFS;
	if (file->sector_backing || file->iccnvs4_snapshot) return KERNEL_ERROR_EINVAL;

	if (file->directory) {
		return KERNEL_ERROR_EINVAL;
	}

	Common::LockGuard lock(file->mutex);

	if (file->f.IsInvalid() || !file->f.Truncate(static_cast<uint64_t>(length))) {
		return KERNEL_ERROR_EIO;
	}

	LOGF("\tFtruncate (size = %" PRId64 ") file: %s\n", length,
	     Common::PathToString(file->real_name).c_str());

	return OK;
}

int KYTY_SYSV_ABI KernelFsync(int d) {
	PRINT_NAME();

	if (d < DESCRIPTOR_MIN) return KERNEL_ERROR_EBADF;
	if (::Libs::Network::Net::IsSocket(d)) return KERNEL_ERROR_EINVAL;
	auto* file = g_files->GetFile(d);
	if (file == nullptr || !file->opened) return KERNEL_ERROR_EBADF;
	// kern_fsync only rejects non-vnodes; PlayGoCore/DBR/UserService fsync parent dirs
	if (file->directory) return OK;
	if (file->passthrough) return DirectoryPassthrough::Fsync(file->passthrough);
	if (file->tmpfs) return OK;
	if (file->special != SpecialFile::None || file->exfat || file->bfs || file->sector_backing ||
	    file->data_topology || file->devfs_root || file->iccnvs4_snapshot)
		return KERNEL_ERROR_EINVAL;
	Common::LockGuard lock(file->mutex);
	if (file->f.IsInvalid()) return KERNEL_ERROR_EIO;
	return file->f.Flush() ? OK : KERNEL_ERROR_EIO;
}

int KYTY_SYSV_ABI KernelUnlink(const char* path) {
	PRINT_NAME();

	if (path == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}
	std::string nullfs_path;
	bool        nullfs_read_only = false;
	const int nullfs = ResolveNullfsPath(&path, &nullfs_path, nullptr, nullptr, &nullfs_read_only);
	if (nullfs != OK) return nullfs;

	if (path[0] == '/') {
		const int traversal = ValidateMountedTraversal(path);
		if (traversal != OK) return traversal;
	}
	if (nullfs_read_only) return NullfsReadOnlyLookup(path, false);
	if (Tmpfs::Contains(path)) return Tmpfs::Unlink(path);
	if (ExfatMount::Contains(path)) return KERNEL_ERROR_EROFS;
	if (BfsMount::Contains(path)) return KERNEL_ERROR_EROFS;
	if (DirectoryPassthrough::Contains(path)) return DirectoryPassthrough::Unlink(path);
	if (ResolveDataTopologyPath(path) != DataTopologyPath::None) return KERNEL_ERROR_EROFS;
	auto real_file_name = g_mount_points->ResolvePath(path);
	if (g_mount_points->IsReadOnly(real_file_name)) return KERNEL_ERROR_EROFS;
	if (Common::IsArchivePath(real_file_name)) {
		return KERNEL_ERROR_EROFS;
	}

	bool is_dir  = Common::File::IsDirectoryExisting(real_file_name);
	bool is_file = Common::File::IsFileExisting(real_file_name);

	if (is_dir) {
		return KERNEL_ERROR_EPERM;
	}

	if (!is_file) {
		return KERNEL_ERROR_ENOENT;
	}

	auto* open_file = g_files->GetFile(real_file_name);
	bool  ok        = (open_file != nullptr && open_file->opened && !open_file->directory
	                       ? open_file->f.Unlink()
	                       : Common::File::DeleteFile(real_file_name));

	if (!ok) {
		return KERNEL_ERROR_EIO;
	}

	LOGF("\tKernelUnlink: %s\n", path);

	return OK;
}

int KYTY_SYSV_ABI KernelRename(const char* from, const char* to) {
	PRINT_NAME();

	if (from == nullptr || to == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}
	for (const char* path: {from, to}) {
		const int traversal = ValidateNullfsTraversal(path);
		if (traversal != OK) return traversal;
		if (SpecialFinalComponent(path)) return KERNEL_ERROR_EINVAL;
		if (NullfsMount::IsMountPoint(path)) return KERNEL_ERROR_EBUSY;
	}
	std::string nullfs_from;
	std::string nullfs_to;
	uint64_t    from_generation = 0;
	uint64_t    to_generation   = 0;
	bool        from_mounted    = false;
	bool        to_mounted      = false;
	bool        from_read_only  = false;
	bool        to_read_only    = false;
	int         nullfs =
	    ResolveNullfsPath(&from, &nullfs_from, &from_generation, &from_mounted, &from_read_only);
	if (nullfs != OK) return nullfs;
	nullfs = ResolveNullfsPath(&to, &nullfs_to, &to_generation, &to_mounted, &to_read_only);
	if (nullfs != OK) return nullfs;
	// kern_renameat finishes both lookups (DELETE on the source, RENAME on the target) before
	// comparing mounts
	if (from_read_only) return NullfsReadOnlyLookup(from, false);
	if (to_read_only) {
		FileStat  source {};
		const int found = KernelStat(from, &source);
		if (found != OK) return found;
		const int lookup = NullfsReadOnlyLookup(to, true);
		return lookup == KERNEL_ERROR_EEXIST ? KERNEL_ERROR_EROFS : lookup;
	}
	if (from_mounted != to_mounted || (from_mounted && from_generation != to_generation))
		return KERNEL_ERROR_EXDEV;

	for (const char* path: {from, to}) {
		if (path[0] == '/') {
			const int traversal = ValidateMountedTraversal(path);
			if (traversal != OK) return traversal;
		}
	}
	const bool source_tmpfs       = Tmpfs::Contains(from);
	const bool target_tmpfs       = Tmpfs::Contains(to);
	const bool source_exfat       = ExfatMount::Contains(from);
	const bool target_exfat       = ExfatMount::Contains(to);
	const bool source_bfs         = BfsMount::Contains(from);
	const bool target_bfs         = BfsMount::Contains(to);
	const bool source_passthrough = DirectoryPassthrough::Contains(from);
	const bool target_passthrough = DirectoryPassthrough::Contains(to);
	if (source_exfat || target_exfat)
		return source_exfat && target_exfat ? KERNEL_ERROR_EROFS : KERNEL_ERROR_EXDEV;
	if (source_bfs || target_bfs)
		return source_bfs && target_bfs ? KERNEL_ERROR_EROFS : KERNEL_ERROR_EXDEV;
	if (source_passthrough || target_passthrough) {
		return source_passthrough && target_passthrough ? DirectoryPassthrough::Rename(from, to)
		                                                : KERNEL_ERROR_EXDEV;
	}
	if (source_tmpfs || target_tmpfs) {
		return source_tmpfs && target_tmpfs ? Tmpfs::Rename(from, to) : KERNEL_ERROR_EXDEV;
	}
	const auto source_data_topology = ResolveDataTopologyPath(from);
	const auto target_data_topology = ResolveDataTopologyPath(to);
	if (source_data_topology != DataTopologyPath::None ||
	    target_data_topology != DataTopologyPath::None) {
		return source_data_topology != DataTopologyPath::None &&
		               target_data_topology != DataTopologyPath::None
		           ? KERNEL_ERROR_EROFS
				   : KERNEL_ERROR_EXDEV;
	}
	auto from_path = std::string(from);
	auto to_path   = std::string(to);
	auto real_from = g_mount_points->ResolvePath(from_path);
	auto real_to   = g_mount_points->ResolvePath(to_path);
	if (g_mount_points->IsReadOnly(real_from) || g_mount_points->IsReadOnly(real_to))
		return KERNEL_ERROR_EROFS;
	if (Common::IsArchivePath(real_from) || Common::IsArchivePath(real_to)) {
		return KERNEL_ERROR_EROFS;
	}

	if (real_from.empty() || real_to.empty()) {
		return KERNEL_ERROR_ENOENT;
	}

	std::error_code error;
	if (std::filesystem::equivalent(real_from, real_to, error) && !error) return OK;
	std::filesystem::rename(real_from, real_to, error);
	if (error) {
		if (error == std::errc::no_such_file_or_directory) return KERNEL_ERROR_ENOENT;
		if (error == std::errc::not_a_directory) return KERNEL_ERROR_ENOTDIR;
		if (error == std::errc::is_a_directory) return KERNEL_ERROR_EISDIR;
		if (error == std::errc::directory_not_empty) return KERNEL_ERROR_ENOTEMPTY;
		if (error == std::errc::file_exists) return KERNEL_ERROR_EEXIST;
		if (error == std::errc::permission_denied) return KERNEL_ERROR_EACCES;
		if (error == std::errc::cross_device_link) return KERNEL_ERROR_EXDEV;
		return KERNEL_ERROR_EIO;
	}

	LOGF("\tKernelRename: %s -> %s\n", from, to);

	return OK;
}

int KYTY_SYSV_ABI KernelGetdirentries(int fd, char* buf, int nbytes, int64_t* basep) {
	PRINT_NAME();

	if (fd < DESCRIPTOR_MIN) {
		return KERNEL_ERROR_EBADF;
	}

	auto* file = g_files->GetFile(fd);

	if (file == nullptr) {
		return KERNEL_ERROR_EBADF;
	}

	if (!file->directory || nbytes < static_cast<int>(DIR_BLOCK_SIZE)) {
		return KERNEL_ERROR_EINVAL;
	}

	EXIT_IF(!file->opened);
	Common::LockGuard lock(file->mutex);
	if (file->passthrough) {
		const int result = RefreshPassthroughDirectory(file);
		if (result != OK) return result;
	}
	if (file->tmpfs) {
		const int result = RefreshTmpfsDirectory(file);
		if (result != OK) return result;
	}
	// A refreshed listing can shrink below an offset already handed out; ufs_readdir answers 0
	// (EOF) when uio_offset >= i_size.
	if (file->dents_offset % DIR_BLOCK_SIZE != 0) {
		return KERNEL_ERROR_EINVAL;
	}

	LOGF("\t dir    = %s\n"
	     "\t nbytes = %d\n"
	     "\t offset = %" PRIu64 "\n",
	     Common::PathToString(file->real_name).c_str(), nbytes, file->dents_offset);

	if (basep != nullptr) {
		*basep = static_cast<int64_t>(file->dents_offset);
	}
	return static_cast<int>(
	    ReadDirectory(file, buf, AlignDown(static_cast<uint64_t>(nbytes), DIR_BLOCK_SIZE)));
}

int KYTY_SYSV_ABI KernelGetdents(int fd, char* buf, int nbytes) {
	PRINT_NAME();

	return KernelGetdirentries(fd, buf, nbytes, nullptr);
}

int KYTY_SYSV_ABI KernelMkdir(const char* path, uint16_t mode) {
	PRINT_NAME();

	if (path == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}
	std::string nullfs_path;
	bool        nullfs_read_only = false;
	const int nullfs = ResolveNullfsPath(&path, &nullfs_path, nullptr, nullptr, &nullfs_read_only);
	if (nullfs != OK) return nullfs;

	if (path[0] == '/') {
		const int traversal = ValidateMountedTraversal(path);
		if (traversal != OK) return traversal;
	}
	if (nullfs_read_only) return NullfsReadOnlyLookup(path, true);
	if (Tmpfs::Contains(path))
		return Tmpfs::Mkdir(path, mode & ~g_creation_mask.load(std::memory_order_relaxed));
	if (ExfatMount::Contains(path)) return KERNEL_ERROR_EROFS;
	if (BfsMount::Contains(path)) return KERNEL_ERROR_EROFS;
	if (DirectoryPassthrough::Contains(path))
		return DirectoryPassthrough::Mkdir(path,
		                                   mode & ~g_creation_mask.load(std::memory_order_relaxed));
	if (ResolveDataTopologyPath(path) != DataTopologyPath::None) return KERNEL_ERROR_EROFS;
	if (std::strlen(path) > 255) {
		return KERNEL_ERROR_ENAMETOOLONG;
	}

	LOGF("\t path = %s\n"
	     "\t mode = %04" PRIx16 "\n",
	     path, mode);

	auto real_name = g_mount_points->ResolvePath(std::string(path));
	if (g_mount_points->IsReadOnly(real_name)) return KERNEL_ERROR_EROFS;
	if (real_name.empty()) {
		return KERNEL_ERROR_ENOENT;
	}
	if (Common::IsArchivePath(real_name)) {
		return KERNEL_ERROR_EROFS;
	}

	if (Common::File::IsDirectoryExisting(real_name)) {
		return KERNEL_ERROR_EEXIST;
	}

	if (!Common::File::CreateDirectory(real_name)) {
		return KERNEL_ERROR_EIO;
	}

	if (!Common::File::IsDirectoryExisting(real_name)) {
		return KERNEL_ERROR_ENOENT;
	}

	return OK;
}

int KYTY_SYSV_ABI KernelRmdir(const char* path) {
	PRINT_NAME();

	if (path == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}
	const int traversal = ValidateNullfsTraversal(path);
	if (traversal != OK) return traversal;
	if (SpecialFinalComponent(path)) return KERNEL_ERROR_EINVAL;
	if (NullfsMount::IsMountPoint(path) || DevfsInstanceAt(path)) return KERNEL_ERROR_EBUSY;
	std::string nullfs_path;
	bool        nullfs_read_only = false;
	const int nullfs = ResolveNullfsPath(&path, &nullfs_path, nullptr, nullptr, &nullfs_read_only);
	if (nullfs != OK) return nullfs;

	if (path[0] == '/') {
		const int traversal = ValidateMountedTraversal(path);
		if (traversal != OK) return traversal;
	}
	if (nullfs_read_only) return NullfsReadOnlyLookup(path, false);
	if (Tmpfs::Contains(path)) return Tmpfs::Rmdir(path);
	if (ExfatMount::Contains(path)) return KERNEL_ERROR_EROFS;
	if (BfsMount::Contains(path)) return KERNEL_ERROR_EROFS;
	if (DirectoryPassthrough::Contains(path)) return DirectoryPassthrough::Rmdir(path);
	if (ResolveDataTopologyPath(path) != DataTopologyPath::None) return KERNEL_ERROR_EROFS;
	LOGF("\t path = %s\n", path);

	auto real_name = g_mount_points->ResolvePath(std::string(path));
	if (g_mount_points->IsReadOnly(real_name)) return KERNEL_ERROR_EROFS;
	if (Common::IsArchivePath(real_name)) {
		return KERNEL_ERROR_EROFS;
	}

	if (!Common::File::IsDirectoryExisting(real_name)) {
		return KERNEL_ERROR_ENOENT;
	}

	if (!Common::File::DeleteDirectory(real_name)) {
		return KERNEL_ERROR_EIO;
	}

	return OK;
}

// sys_unmount: match f_mntonname (MNAMELEN 88), newest first. Non-mountpoint is EINVAL, a covered
// mount or nullfs lower is EBUSY.
int KYTY_SYSV_ABI KernelUnmount(const char* path, int flags) {
	if (path == nullptr) return KERNEL_ERROR_EFAULT;
	if (std::strlen(path) >= 88) return KERNEL_ERROR_ENAMETOOLONG;
	const char* backend = "none";
	int         result  = KERNEL_ERROR_EINVAL;
	std::string normalized;
	if ((flags & ~0x00080000) != 0) {
		backend = "unmodeled_flags";
		result  = KERNEL_ERROR_ENOSYS;
	} else if (path[0] == '/' && Tmpfs::NormalizePath(path, &normalized) == OK &&
	           normalized != "/") {
		std::lock_guard       publication(g_mount_publication_mutex);
		const auto            slash  = normalized.rfind('/');
		const auto            parent = slash == 0 ? std::string("/") : normalized.substr(0, slash);
		std::filesystem::path occupied;
		if (DevfsInstanceAt(normalized)) {
			backend = "devfs";
			std::lock_guard lock(g_devfs_instances_mutex);
			std::erase_if(g_devfs_instances,
			              [&](const auto& instance) { return instance.point == normalized; });
			result = OK;
		} else if (NullfsMount::IsMountPoint(normalized)) {
			backend = "nullfs";
			result  = NullfsMount::Unmount(normalized);
			if (result == OK) RetractSandboxMount(normalized);
		} else if (Tmpfs::Contains(normalized) && !Tmpfs::Contains(parent) &&
		           !NullfsMount::Contains(normalized)) {
			backend = "tmpfs";
			std::vector<NullfsMount::MountInfo> nullfs;
			NullfsMount::SnapshotMounts(&nullfs);
			const auto beneath = [&](const std::string& other) {
				return other == normalized ||
				       (other.starts_with(normalized) && other[normalized.size()] == '/');
			};
			const bool upper = std::any_of(nullfs.begin(), nullfs.end(), [&](const auto& mount) {
				return beneath(mount.source);
			});
			const bool submounts =
			    DevfsInstanceOverlaps(normalized) ||
			    std::any_of(nullfs.begin(), nullfs.end(),
				            [&](const auto& mount) { return beneath(mount.point); });
			result = upper || submounts ? KERNEL_ERROR_EBUSY : Tmpfs::Unmount(normalized);
			if (!upper && result == KERNEL_ERROR_EBUSY && (flags & 0x00080000) != 0) {
				backend = "tmpfs_force_unmodeled";
				result  = KERNEL_ERROR_ENOSYS;
			}
		} else if ((ExfatMount::Contains(normalized) && !ExfatMount::Contains(parent)) ||
		           (BfsMount::Contains(normalized) && !BfsMount::Contains(parent)) ||
		           (DirectoryPassthrough::Contains(normalized) &&
		            !DirectoryPassthrough::Contains(parent)) ||
		           g_mount_points->GetMountDirectory(normalized, &occupied)) {
			backend = "unmodeled_mount";
			result  = KERNEL_ERROR_ENOSYS;
		}
	}
	LOGF("NATIVE_UNMOUNT path=%s flags=0x%x backend=%s result=0x%x\n", path,
	     static_cast<uint32_t>(flags), backend, static_cast<uint32_t>(result));
	return result;
}

int KYTY_SYSV_ABI KernelCheckReachability(const char* path) {
	PRINT_NAME();

	if (path == nullptr) {
		return KERNEL_ERROR_EINVAL;
	}
	std::string nullfs_path;
	const int   nullfs = ResolveNullfsPath(&path, &nullfs_path);
	if (nullfs != OK) return nullfs;

	if (path[0] == '/') {
		const int traversal = ValidateMountedTraversal(path);
		if (traversal != OK) return traversal;
	}
	if (DevfsInstanceAt(path)) return OK;
	if (Tmpfs::Contains(path)) {
		Tmpfs::NodeStat stat {};
		return Tmpfs::Stat(path, &stat);
	}
	if (ExfatMount::Contains(path)) {
		ExfatMount::NodeStat stat {};
		return ExfatMount::Stat(path, &stat);
	}
	if (BfsMount::Contains(path)) {
		BfsMount::NodeStat stat {};
		return BfsMount::Stat(path, &stat);
	}
	if (DirectoryPassthrough::Contains(path)) {
		DirectoryPassthrough::NodeStat stat {};
		return DirectoryPassthrough::Stat(path, &stat);
	}
	const auto data_topology = ResolveDataTopologyPath(path);
	if (data_topology == DataTopologyPath::Directory) return OK;
	if (data_topology == DataTopologyPath::Missing) return KERNEL_ERROR_ENOENT;
	if (IsDevfsRoot(path)) return OK;
	if (std::strcmp(path, "/dev/lvdctl") == 0 || FindLvdDevice(path)) return OK;
	if (std::strlen(path) > 255) {
		return KERNEL_ERROR_ENAMETOOLONG;
	}

	LOGF("\t KernelCheckReachability: %s\n", path);

	std::string mounted_path = std::string(path);
	if (FindSectorPayload(mounted_path)) return OK;

	if (IsRandomDevice(mounted_path)) {
		return OK;
	}

	auto real_name = g_mount_points->ResolvePath(mounted_path);

	if (Common::File::IsFileExisting(real_name) || Common::File::IsDirectoryExisting(real_name)) {
		return OK;
	}
	if (UseCapturedRootMetadata(path)) {
		FileStat captured {};
		return CapturedRootMetadata::Stat(path, &captured);
	}

	return KERNEL_ERROR_ENOENT;
}



} // namespace Libs::LibKernel::FileSystem
