#include "common/hostException.h"

#include "common/logging/log.h"

#include <atomic>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#include <windows.h> // IWYU pragma: keep
#include <bcrypt.h>
#include <tlhelp32.h>
#else
#include <algorithm>
#include <csignal>
#include <cstdlib>
#include <initializer_list>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/ucontext.h>
#else
#include <ucontext.h> // IWYU pragma: keep
#endif
#endif

// IWYU pragma: no_include <errhandlingapi.h>
// IWYU pragma: no_include <excpt.h>
// IWYU pragma: no_include <minwinbase.h>
// IWYU pragma: no_include <minwindef.h>
// IWYU pragma: no_include <wtypes.h>

namespace Common::HostException {

#if !defined(__APPLE__)

static std::atomic<Handler> g_handler {nullptr};
static std::atomic_uint32_t g_install_state {0};

static_assert(decltype(g_handler)::is_always_lock_free);
static_assert(decltype(g_install_state)::is_always_lock_free);
#endif

#if KYTY_PLATFORM == KYTY_PLATFORM_LINUX

// macOS uses the same POSIX platform setting and needs a signal stack too.
class ThreadSignalStack {
public:
	ThreadSignalStack() {
		const auto page_size = static_cast<size_t>(::getpagesize());
		const auto stack_size =
		    (std::max<size_t>(64 * 1024, MINSIGSTKSZ) + page_size - 1) & ~(page_size - 1);
		if (::posix_memalign(&m_memory, page_size, stack_size) != 0) {
			return;
		}

		stack_t stack {};
		stack.ss_sp   = m_memory;
		stack.ss_size = stack_size;
		if (::sigaltstack(&stack, &m_previous) != 0) {
			std::free(m_memory);
			m_memory = nullptr;
		}
	}

	~ThreadSignalStack() {
		if (m_memory != nullptr && ::sigaltstack(&m_previous, nullptr) == 0) {
			std::free(m_memory);
		}
	}

	[[nodiscard]] bool IsInitialized() const { return m_memory != nullptr; }

	KYTY_CLASS_NO_COPY(ThreadSignalStack)

private:
	void*   m_memory = nullptr;
	stack_t m_previous {};
};

bool InitializeThreadSignalStack() {
	// Keep fault handling off guest stacks, which GPU tracking can make read-only.
	thread_local ThreadSignalStack signal_stack;
	return signal_stack.IsInitialized();
}

#endif

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS

namespace {

constexpr uint32_t UNHANDLED_FAULT_RECORD_VERSION   = 3;
constexpr uint32_t UNHANDLED_FAULT_RECORD_COMPLETE  = 0x434f4d50;
constexpr uint32_t UNHANDLED_FAULT_NATIVE_MODULES   = 256;
constexpr uint32_t UNHANDLED_FAULT_GUEST_CODE_SLOTS = 4096;
constexpr uint32_t UNHANDLED_FAULT_UCRT_PROBE_RVA   = 0x185200;
constexpr uint32_t UNHANDLED_FAULT_UCRT_PROBE_SIZE  = 64;

struct ImageIdentity {
	uint32_t machine        = 0;
	uint32_t timestamp      = 0;
	uint32_t image_size     = 0;
	uint32_t checksum       = 0;
	uint32_t codeview_valid = 0;
	GUID     pdb_guid {};
	uint32_t pdb_age = 0;
};

struct NativeModuleSnapshot {
	uint64_t          base           = 0;
	uint64_t          size           = 0;
	uint32_t          identity_valid = 0;
	ImageIdentity     identity {};
	FaultFileIdentity file_identity {};
	char              basename[UNHANDLED_FAULT_MODULE_NAME_SIZE] {};
};

struct GuestCodeRegistryEntry {
	std::atomic_uint32_t active {0};
	uint64_t             start         = 0;
	uint64_t             size          = 0;
	uint64_t             owner_base    = 0;
	uint64_t             source_offset = 0;
	FaultGuestCodeKind   kind          = FaultGuestCodeKind::Unavailable;
	uint32_t             generation    = 0;
	char                 owner_basename[UNHANDLED_FAULT_MODULE_NAME_SIZE] {};
	char                 detail[UNHANDLED_FAULT_DETAIL_SIZE] {};
};

std::atomic_uint32_t                   g_provenance_prepare_state {0};
std::atomic_uint32_t                   g_provenance_capture_state {0};
std::atomic_uint32_t                   g_provenance_capture_thread {0};
std::atomic<UnhandledFaultReentryHook> g_provenance_reentry_hook {nullptr};
std::atomic_bool                       g_native_guest_host_stack_enabled {false};
std::atomic_bool                       g_native_guest_host_stack_audit_enabled {false};
HANDLE                                 g_provenance_file = INVALID_HANDLE_VALUE;
UnhandledFaultRecord                   g_provenance_template {};
NativeModuleSnapshot                   g_native_modules[UNHANDLED_FAULT_NATIVE_MODULES] {};
uint32_t                               g_native_module_count = 0;
GuestCodeRegistryEntry                 g_guest_code_registry[UNHANDLED_FAULT_GUEST_CODE_SLOTS] {};
std::atomic_uint32_t                   g_guest_code_registry_count {0};
std::atomic_uint32_t                   g_guest_code_registry_overflow {0};

static_assert(decltype(g_provenance_prepare_state)::is_always_lock_free);
static_assert(decltype(g_provenance_capture_state)::is_always_lock_free);
static_assert(decltype(g_provenance_reentry_hook)::is_always_lock_free);
static_assert(decltype(g_native_guest_host_stack_enabled)::is_always_lock_free);
static_assert(decltype(g_native_guest_host_stack_audit_enabled)::is_always_lock_free);
static_assert(decltype(GuestCodeRegistryEntry::active)::is_always_lock_free);
static_assert(decltype(g_guest_code_registry_count)::is_always_lock_free);
static_assert(decltype(g_guest_code_registry_overflow)::is_always_lock_free);

bool CopyBoundedDiagnosticText(char* output, size_t output_size, const char* input,
                               bool basename_only) noexcept {
	if (output == nullptr || output_size == 0 || input == nullptr || input[0] == '\0') return false;
	size_t i = 0;
	for (; i + 1 < output_size && input[i] != '\0'; i++) {
		const auto c = static_cast<unsigned char>(input[i]);
		if (c < 0x20 || c >= 0x7f || (basename_only && (c == '/' || c == '\\' || c == ':'))) {
			output[0] = '\0';
			return false;
		}
		output[i] = static_cast<char>(c);
	}
	if (input[i] != '\0') {
		output[0] = '\0';
		return false;
	}
	output[i] = '\0';
	return true;
}

void AttachGuestCodeProvenance(uint64_t address, FaultModuleRef* output) noexcept {
	uint32_t count = g_guest_code_registry_count.load(std::memory_order_acquire);
	if (count > UNHANDLED_FAULT_GUEST_CODE_SLOTS) count = UNHANDLED_FAULT_GUEST_CODE_SLOTS;
	for (uint32_t i = 0; i < count; i++) {
		auto& entry = g_guest_code_registry[i];
		if (entry.active.load(std::memory_order_acquire) == 0 || address < entry.start ||
		    address - entry.start >= entry.size) {
			continue;
		}
		auto& guest         = output->guest_code;
		guest.available     = 1;
		guest.kind          = entry.kind;
		guest.generation    = entry.generation;
		guest.region_offset = address - entry.start;
		guest.owner_offset =
		    address >= entry.owner_base ? address - entry.owner_base : entry.source_offset;
		guest.source_offset = entry.source_offset;
		guest.region_size   = entry.size;
		std::memcpy(guest.owner_basename, entry.owner_basename, sizeof(guest.owner_basename));
		std::memcpy(guest.detail, entry.detail, sizeof(guest.detail));
		guest.lifecycle = entry.active.load(std::memory_order_acquire) != 0
		                      ? FaultGuestCodeLifecycle::Active
		                      : FaultGuestCodeLifecycle::RetiredDuringCapture;
		return;
	}
}

FaultGuestCodeKind FindActiveGuestCodeKind(uint64_t address) noexcept {
	uint32_t count = g_guest_code_registry_count.load(std::memory_order_acquire);
	if (count > UNHANDLED_FAULT_GUEST_CODE_SLOTS) count = UNHANDLED_FAULT_GUEST_CODE_SLOTS;
	for (uint32_t i = 0; i < count; i++) {
		auto& entry = g_guest_code_registry[i];
		if (entry.active.load(std::memory_order_acquire) != 0 && address >= entry.start &&
		    address - entry.start < entry.size) {
			return entry.kind;
		}
	}
	return FaultGuestCodeKind::Unavailable;
}

FaultModuleRef FinalizeAddressClassification(uint64_t address, FaultModuleRef output) noexcept {
	AttachGuestCodeProvenance(address, &output);
	return output;
}

void CopyModuleBasename(char* output, const wchar_t* input) {
	const int converted = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input, -1, output,
	                                          UNHANDLED_FAULT_MODULE_NAME_SIZE, nullptr, nullptr);
	if (converted <= 0) {
		output[0] = '\0';
	}
	output[UNHANDLED_FAULT_MODULE_NAME_SIZE - 1] = '\0';
}

bool ReadImageIdentity(uint64_t base, ImageIdentity* output) noexcept {
	IMAGE_DOS_HEADER dos {};
	SIZE_T           copied = 0;
	if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(base), &dos,
	                      sizeof(dos), &copied) == 0 ||
	    copied != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < sizeof(dos) ||
	    dos.e_lfanew > 1024 * 1024) {
		return false;
	}
	IMAGE_NT_HEADERS64 nt {};
	if (ReadProcessMemory(GetCurrentProcess(),
	                      reinterpret_cast<const void*>(base + static_cast<uint32_t>(dos.e_lfanew)),
	                      &nt, sizeof(nt), &copied) == 0 ||
	    copied != sizeof(nt) || nt.Signature != IMAGE_NT_SIGNATURE ||
	    nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return false;
	}
	output->machine    = nt.FileHeader.Machine;
	output->timestamp  = nt.FileHeader.TimeDateStamp;
	output->image_size = nt.OptionalHeader.SizeOfImage;
	output->checksum   = nt.OptionalHeader.CheckSum;
	const auto debug   = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	if (debug.VirtualAddress != 0 && debug.Size >= sizeof(IMAGE_DEBUG_DIRECTORY) &&
	    debug.Size / sizeof(IMAGE_DEBUG_DIRECTORY) <= 32 &&
	    debug.VirtualAddress <= output->image_size &&
	    debug.Size <= output->image_size - debug.VirtualAddress) {
		const uint32_t count = debug.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
		for (uint32_t i = 0; i < count; i++) {
			IMAGE_DEBUG_DIRECTORY entry {};
			const uint64_t        address =
			    base + debug.VirtualAddress + i * sizeof(IMAGE_DEBUG_DIRECTORY);
			if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address),
			                      &entry, sizeof(entry), &copied) == 0 ||
			    copied != sizeof(entry) || entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW ||
			    entry.AddressOfRawData == 0 || entry.SizeOfData < 24 ||
			    entry.AddressOfRawData > output->image_size ||
			    24 > output->image_size - entry.AddressOfRawData) {
				continue;
			}
			struct CodeViewHeader {
				uint32_t signature;
				GUID     guid;
				uint32_t age;
			};
			CodeViewHeader codeview {};
			if (ReadProcessMemory(GetCurrentProcess(),
			                      reinterpret_cast<const void*>(base + entry.AddressOfRawData),
			                      &codeview, sizeof(codeview), &copied) != 0 &&
			    copied == sizeof(codeview) && codeview.signature == 0x53445352) {
				output->codeview_valid = 1;
				output->pdb_guid       = codeview.guid;
				output->pdb_age        = codeview.age;
				break;
			}
		}
	}
	return true;
}

bool HashBytesSha256(const uint8_t* bytes, uint32_t size, uint8_t output[32]) noexcept {
	BCRYPT_ALG_HANDLE  algorithm = nullptr;
	BCRYPT_HASH_HANDLE hash      = nullptr;
	bool ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0 &&
	          BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0 &&
	          BCryptHashData(hash, const_cast<PUCHAR>(bytes), size, 0) >= 0 &&
	          BCryptFinishHash(hash, output, 32, 0) >= 0;
	if (hash != nullptr) BCryptDestroyHash(hash);
	if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
	return ok;
}

bool HashFileSha256(const wchar_t* path, FaultFileIdentity* output) noexcept {
	HANDLE file = CreateFileW(
	    path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
	    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
	if (file == INVALID_HANDLE_VALUE) return false;
	LARGE_INTEGER      size {};
	BCRYPT_ALG_HANDLE  algorithm = nullptr;
	BCRYPT_HASH_HANDLE hash      = nullptr;
	bool ok = GetFileSizeEx(file, &size) != 0 && size.QuadPart >= 0 &&
	          BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0 &&
	          BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0;
	uint8_t buffer[4096] {};
	for (;;) {
		DWORD read = 0;
		if (!ok || ReadFile(file, buffer, sizeof(buffer), &read, nullptr) == 0) {
			ok = false;
			break;
		}
		if (read == 0) break;
		if (BCryptHashData(hash, buffer, read, 0) < 0) {
			ok = false;
			break;
		}
	}
	if (ok) ok = BCryptFinishHash(hash, output->sha256, sizeof(output->sha256), 0) >= 0;
	if (hash != nullptr) BCryptDestroyHash(hash);
	if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
	CloseHandle(file);
	if (!ok) return false;
	output->available    = 1;
	output->sha256_valid = 1;
	output->file_size    = static_cast<uint64_t>(size.QuadPart);
	return true;
}

void CaptureNativeModuleSnapshot() {
	HANDLE snapshot = INVALID_HANDLE_VALUE;
	for (int attempt = 0; attempt < 3 && snapshot == INVALID_HANDLE_VALUE; attempt++) {
		snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
		                                    GetCurrentProcessId());
		if (snapshot == INVALID_HANDLE_VALUE && GetLastError() != ERROR_BAD_LENGTH) {
			break;
		}
	}
	if (snapshot == INVALID_HANDLE_VALUE) {
		return;
	}

	MODULEENTRY32W entry {};
	entry.dwSize = sizeof(entry);
	if (Module32FirstW(snapshot, &entry) != 0) {
		do {
			if (g_native_module_count == UNHANDLED_FAULT_NATIVE_MODULES) {
				break;
			}
			auto& output = g_native_modules[g_native_module_count++];
			output.base  = reinterpret_cast<uint64_t>(entry.modBaseAddr);
			output.size  = entry.modBaseSize;
			CopyModuleBasename(output.basename, entry.szModule);
			output.identity_valid = ReadImageIdentity(output.base, &output.identity) ? 1u : 0u;
			if (_wcsicmp(entry.szModule, L"ucrtbased.dll") == 0) {
				output.file_identity.available = 1;
				HashFileSha256(entry.szExePath, &output.file_identity);
				output.file_identity.loaded_probe_rva  = UNHANDLED_FAULT_UCRT_PROBE_RVA;
				output.file_identity.loaded_probe_size = UNHANDLED_FAULT_UCRT_PROBE_SIZE;
				uint8_t probe[UNHANDLED_FAULT_UCRT_PROBE_SIZE] {};
				SIZE_T  read = 0;
				if (output.identity_valid != 0 &&
				    UNHANDLED_FAULT_UCRT_PROBE_RVA <= output.identity.image_size &&
				    UNHANDLED_FAULT_UCRT_PROBE_SIZE <=
				        output.identity.image_size - UNHANDLED_FAULT_UCRT_PROBE_RVA &&
				    ReadProcessMemory(
				        GetCurrentProcess(),
				        reinterpret_cast<const void*>(output.base + UNHANDLED_FAULT_UCRT_PROBE_RVA),
				        probe, sizeof(probe), &read) != 0 &&
				    read == sizeof(probe) &&
				    HashBytesSha256(probe, sizeof(probe),
				                    output.file_identity.loaded_probe_sha256)) {
					output.file_identity.loaded_probe_valid = 1;
				}
			}
		} while (Module32NextW(snapshot, &entry) != 0);
	}
	CloseHandle(snapshot);
}

const NativeModuleSnapshot* FindSnapshotModule(uint64_t address) noexcept {
	for (uint32_t i = 0; i < g_native_module_count; i++) {
		const auto& module = g_native_modules[i];
		if (address >= module.base && address - module.base < module.size) {
			return &module;
		}
	}
	return nullptr;
}

bool SameImageIdentity(const ImageIdentity& left, const ImageIdentity& right) noexcept {
	return left.machine == right.machine && left.timestamp == right.timestamp &&
	       left.image_size == right.image_size && left.checksum == right.checksum &&
	       left.codeview_valid == right.codeview_valid &&
	       (left.codeview_valid == 0 ||
	        (std::memcmp(&left.pdb_guid, &right.pdb_guid, sizeof(GUID)) == 0 &&
	         left.pdb_age == right.pdb_age));
}

void CopyImageIdentity(const NativeModuleSnapshot& snapshot, FaultModuleRef* output) noexcept {
	output->image_identity_valid = snapshot.identity_valid;
	if (snapshot.identity_valid == 0) return;
	output->image_machine        = snapshot.identity.machine;
	output->image_timestamp      = snapshot.identity.timestamp;
	output->image_size           = snapshot.identity.image_size;
	output->image_checksum       = snapshot.identity.checksum;
	output->image_codeview_valid = snapshot.identity.codeview_valid;
	if (snapshot.identity.codeview_valid != 0) {
		std::memcpy(output->image_pdb_guid, &snapshot.identity.pdb_guid,
		            sizeof(output->image_pdb_guid));
		output->image_pdb_age = snapshot.identity.pdb_age;
	}
}

FaultModuleRef ClassifyAddress(uint64_t address) noexcept {
	FaultModuleRef output {};
	if (address < 0x10000) {
		output.address_class   = FaultAddressClass::LowUnmapped;
		output.relative_offset = address;
		return FinalizeAddressClassification(address, output);
	}

	const auto*              snapshot = FindSnapshotModule(address);
	MEMORY_BASIC_INFORMATION current {};
	if (VirtualQuery(reinterpret_cast<const void*>(address), &current, sizeof(current)) == 0 ||
	    current.State == MEM_FREE) {
		output.address_class =
		    snapshot == nullptr ? FaultAddressClass::Unmapped : FaultAddressClass::StaleImage;
		output.relative_offset = snapshot == nullptr ? (address & 0xfff) : address - snapshot->base;
		if (snapshot != nullptr) {
			std::memcpy(output.module_basename, snapshot->basename,
			            UNHANDLED_FAULT_MODULE_NAME_SIZE);
		}
		return FinalizeAddressClassification(address, output);
	}

	output.current_state      = current.State;
	output.current_type       = current.Type;
	output.current_protection = current.Protect;
	if (snapshot != nullptr) {
		output.relative_offset = address - snapshot->base;
		if (current.Type == MEM_IMAGE &&
		    reinterpret_cast<uint64_t>(current.AllocationBase) == snapshot->base) {
			ImageIdentity identity {};
			if (snapshot->identity_valid == 0 || snapshot->basename[0] == '\0') {
				output.address_class = FaultAddressClass::UnknownImage;
			} else if (!ReadImageIdentity(snapshot->base, &identity)) {
				output.address_class = FaultAddressClass::UnknownImage;
			} else if (!SameImageIdentity(identity, snapshot->identity)) {
				output.address_class = FaultAddressClass::StaleImage;
			} else {
				output.address_class = FaultAddressClass::Image;
				std::memcpy(output.module_basename, snapshot->basename,
				            UNHANDLED_FAULT_MODULE_NAME_SIZE);
				CopyImageIdentity(*snapshot, &output);
			}
		} else {
			output.address_class = FaultAddressClass::StaleImage;
		}
		return FinalizeAddressClassification(address, output);
	}

	const auto allocation_base = reinterpret_cast<uint64_t>(current.AllocationBase);
	output.relative_offset     = address >= allocation_base ? address - allocation_base : 0;
	if (current.Type == MEM_IMAGE) {
		output.address_class = FaultAddressClass::UnknownImage;
	} else if (current.Type == MEM_PRIVATE) {
		output.address_class = FaultAddressClass::Private;
	} else if (current.Type == MEM_MAPPED) {
		output.address_class = FaultAddressClass::Mapped;
	} else {
		output.address_class = FaultAddressClass::Unknown;
	}
	return FinalizeAddressClassification(address, output);
}

void CaptureOriginalFrameChain(const ExceptionInfo& info, UnhandledFaultRecord* output) noexcept {
	struct Frame {
		uint64_t next;
		uint64_t return_address;
	};

	uint64_t frame = info.rbp;
	if (frame < 0x10000 || (frame & 7u) != 0 || frame < info.rsp ||
	    frame - info.rsp > 64u * 1024u * 1024u) {
		return;
	}

	for (uint32_t i = 0; i < UNHANDLED_FAULT_MAX_FRAMES; i++) {
		Frame  values {};
		SIZE_T copied = 0;
		if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(frame), &values,
		                      sizeof(values), &copied) == 0 ||
		    copied != sizeof(values)) {
			output->original_stack_status = output->original_frame_count == 0
			                                    ? FaultStackStatus::Unavailable
			                                    : FaultStackStatus::Partial;
			return;
		}
		if (values.return_address == 0) {
			output->original_stack_status = FaultStackStatus::Complete;
			return;
		}
		output->original_frames[output->original_frame_count++] =
		    ClassifyAddress(values.return_address);
		if (values.next == 0) {
			output->original_stack_status = FaultStackStatus::Complete;
			return;
		}
		if (values.next <= frame || values.next - frame > 1024u * 1024u ||
		    values.next - info.rsp > 64u * 1024u * 1024u || (values.next & 7u) != 0) {
			output->original_stack_status = FaultStackStatus::Partial;
			return;
		}
		frame = values.next;
	}
	output->original_stack_status = FaultStackStatus::Truncated;
}

void CaptureOriginalStackTop(const ExceptionInfo& info, UnhandledFaultRecord* output) noexcept {
	if (info.rsp < 0x10000 || (info.rsp & 7u) != 0) return;
	uint64_t value  = 0;
	SIZE_T   copied = 0;
	if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(info.rsp), &value,
	                      sizeof(value), &copied) == 0 ||
	    copied != sizeof(value)) {
		return;
	}
	if (value == 0) {
		output->original_stack_top_status = FaultStackTopStatus::Zero;
		return;
	}
	output->original_stack_top        = ClassifyAddress(value);
	output->original_stack_top_status = FaultStackTopStatus::Classified;
}

void CaptureEmitterFileIdentity(uint64_t address, UnhandledFaultRecord* output) noexcept {
	const auto* module = FindSnapshotModule(address);
	if (module == nullptr || output->emitter_pc.address_class != FaultAddressClass::Image) return;
	std::memcpy(&output->emitter_file_identity, &module->file_identity,
	            sizeof(output->emitter_file_identity));
}

uint64_t FaultRecordChecksum(const UnhandledFaultRecord& record) noexcept {
	constexpr uint64_t OFFSET = 1469598103934665603ull;
	constexpr uint64_t PRIME  = 1099511628211ull;
	uint64_t           hash   = OFFSET;
	const auto*        bytes  = reinterpret_cast<const uint8_t*>(&record);
	for (size_t i = 0; i < sizeof(record); i++) {
		hash = (hash ^ bytes[i]) * PRIME;
	}
	return hash;
}

} // namespace

FaultGuestCodeKind QueryActiveGuestCodeKind(uint64_t address) noexcept {
	return FindActiveGuestCodeKind(address);
}

bool PrepareUnhandledFaultProvenance(int32_t guest_process_id) {
	uint32_t expected = 0;
	if (!g_provenance_prepare_state.compare_exchange_strong(expected, 1,
	                                                        std::memory_order_acq_rel)) {
		return expected == 2;
	}

	char        prefix[768] {};
	const DWORD prefix_size = GetEnvironmentVariableA(
	    "KYTY_DIAGNOSTIC_UNHANDLED_HOST_PROVENANCE_PREFIX", prefix, sizeof(prefix));
	if (prefix_size == 0 || prefix_size >= sizeof(prefix)) {
		g_provenance_prepare_state.store(3, std::memory_order_release);
		return false;
	}
	char      path[1024] {};
	const int path_size = std::snprintf(path, sizeof(path), "%s.pid-%lu.bin", prefix,
	                                    static_cast<unsigned long>(GetCurrentProcessId()));
	if (path_size <= 0 || static_cast<size_t>(path_size) >= sizeof(path)) {
		g_provenance_prepare_state.store(3, std::memory_order_release);
		return false;
	}

	g_provenance_file = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW,
	                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
	if (g_provenance_file == INVALID_HANDLE_VALUE) {
		g_provenance_prepare_state.store(3, std::memory_order_release);
		return false;
	}

	CaptureNativeModuleSnapshot();
	std::memcpy(g_provenance_template.magic, "KYTYFPV3", sizeof(g_provenance_template.magic));
	g_provenance_template.version               = UNHANDLED_FAULT_RECORD_VERSION;
	g_provenance_template.size                  = sizeof(UnhandledFaultRecord);
	g_provenance_template.complete              = UNHANDLED_FAULT_RECORD_COMPLETE;
	g_provenance_template.native_process_id     = GetCurrentProcessId();
	g_provenance_template.guest_process_id      = guest_process_id;
	g_provenance_template.expected_exit_status  = 321;
	g_provenance_template.module_snapshot_count = g_native_module_count;
	g_provenance_prepare_state.store(2, std::memory_order_release);
	return true;
}

bool IsUnhandledFaultProvenancePrepared() noexcept {
	return g_provenance_prepare_state.load(std::memory_order_acquire) == 2;
}

void SetUnhandledFaultReentryHookForTests(UnhandledFaultReentryHook hook) noexcept {
	g_provenance_reentry_hook.store(hook, std::memory_order_release);
}

bool CaptureUnhandledFaultProvenance(const ExceptionInfo& info) noexcept {
	if (!IsUnhandledFaultProvenancePrepared()) {
		return false;
	}
	uint32_t expected = 0;
	if (!g_provenance_capture_state.compare_exchange_strong(expected, 1,
	                                                        std::memory_order_acq_rel)) {
		// another thread may still be writing the record; re-entry on the same thread means the
		// capture faulted
		if (expected == 1 &&
		    g_provenance_capture_thread.load(std::memory_order_acquire) != info.native_thread_id) {
			for (int i = 0;
			     i < 3000 && g_provenance_capture_state.load(std::memory_order_acquire) == 1; i++) {
				Sleep(1);
			}
		}
		return false;
	}
	g_provenance_capture_thread.store(info.native_thread_id, std::memory_order_release);
	if (const auto hook = g_provenance_reentry_hook.exchange(nullptr, std::memory_order_acq_rel);
	    hook != nullptr) {
		hook();
	}

	UnhandledFaultRecord record {};
	std::memcpy(&record, &g_provenance_template, sizeof(record));
	record.native_thread_id        = info.native_thread_id;
	record.native_code             = info.native_code;
	record.exception_type          = info.type;
	record.normalized_access       = info.access_violation_type;
	record.platform_access_valid   = info.platform_access_valid;
	record.platform_access         = info.platform_access;
	record.native_context_flags    = info.native_context_flags;
	record.original_context_rflags = info.original_context_rflags;
	record.handler_route           = info.handler_route;
	record.emitter_matches_original_pc =
	    info.exception_address == info.original_context_pc ? 1u : 0u;
	record.emitter_pc                = ClassifyAddress(info.exception_address);
	record.pc                        = ClassifyAddress(info.original_context_pc);
	record.context_rax               = ClassifyAddress(info.rax);
	record.context_rbx               = ClassifyAddress(info.rbx);
	record.context_rcx               = ClassifyAddress(info.rcx);
	record.context_rdx               = ClassifyAddress(info.rdx);
	record.context_r13               = ClassifyAddress(info.r13);
	record.context_r14               = ClassifyAddress(info.r14);
	record.context_r15               = ClassifyAddress(info.r15);
	const auto registry_count        = g_guest_code_registry_count.load(std::memory_order_acquire);
	record.guest_code_registry_count = registry_count > UNHANDLED_FAULT_GUEST_CODE_SLOTS
	                                       ? UNHANDLED_FAULT_GUEST_CODE_SLOTS
	                                       : registry_count;
	record.guest_code_registry_overflow =
	    g_guest_code_registry_overflow.load(std::memory_order_acquire);
	CaptureEmitterFileIdentity(info.exception_address, &record);
	if (info.type == ExceptionType::AccessViolation && info.platform_access_valid != 0) {
		record.target = ClassifyAddress(info.access_violation_vaddr);
	}
	CaptureOriginalStackTop(info, &record);
	CaptureOriginalFrameChain(info, &record);
	record.checksum = 0;
	record.checksum = FaultRecordChecksum(record);

	DWORD      written = 0;
	const bool ok = WriteFile(g_provenance_file, &record, sizeof(record), &written, nullptr) != 0 &&
	                written == sizeof(record);
	g_provenance_capture_state.store(2, std::memory_order_release);
	return ok;
}

// Plain WriteFile: the log mutex may be held by a thread a guest GC has suspended.
void NoteHostExit(uint32_t path_id, int exit_status, const ExceptionInfo* info) noexcept {
	char        prefix[768] {};
	const DWORD prefix_size = GetEnvironmentVariableA(
	    "KYTY_DIAGNOSTIC_UNHANDLED_HOST_PROVENANCE_PREFIX", prefix, sizeof(prefix));
	if (prefix_size == 0 || prefix_size >= sizeof(prefix)) return;
	char      path[1024] {};
	const int path_size = std::snprintf(path, sizeof(path), "%s.exitnote.pid-%lu.txt", prefix,
	                                    static_cast<unsigned long>(GetCurrentProcessId()));
	if (path_size <= 0 || static_cast<size_t>(path_size) >= sizeof(path)) return;
	char line[1024] {};
	int  size = 0;
	if (info != nullptr) {
		const auto pc     = ClassifyAddress(info->exception_address);
		const auto target = ClassifyAddress(info->access_violation_vaddr);
		size              = std::snprintf(
		    line, sizeof(line),
		    "HOST_EXIT path=%u status=%d guest_pid=%d tid=%lu code=0x%08x type=%u access=%u"
		    " pc=0x%016" PRIx64 " pc_module=%s+0x%" PRIx64 " pc_guest=%s+0x%" PRIx64
		    " original_pc=0x%016" PRIx64 " vaddr=0x%016" PRIx64 " vaddr_module=%s+0x%" PRIx64
		    " rsp=0x%016" PRIx64 " rbp=0x%016" PRIx64 " rax=0x%016" PRIx64 " rdi=0x%016" PRIx64
		    " rsi=0x%016" PRIx64 " route=%u capture_state=%u capture_tid=%u\r\n",
		    path_id, exit_status, g_provenance_template.guest_process_id,
		    static_cast<unsigned long>(GetCurrentThreadId()), info->native_code,
		    static_cast<unsigned>(info->type), static_cast<unsigned>(info->access_violation_type),
		    info->exception_address, pc.module_basename, pc.relative_offset,
		    pc.guest_code.owner_basename, pc.guest_code.owner_offset, info->original_context_pc,
		    info->access_violation_vaddr, target.module_basename, target.relative_offset, info->rsp,
		    info->rbp, info->rax, info->rdi, info->rsi, static_cast<unsigned>(info->handler_route),
		    g_provenance_capture_state.load(std::memory_order_acquire),
		    g_provenance_capture_thread.load(std::memory_order_acquire));
	} else {
		size = std::snprintf(
		    line, sizeof(line),
		    "HOST_EXIT path=%u status=%d guest_pid=%d tid=%lu no_exception_context\r\n", path_id,
		    exit_status, g_provenance_template.guest_process_id,
		    static_cast<unsigned long>(GetCurrentThreadId()));
	}
	if (size <= 0) return;
	if (static_cast<size_t>(size) >= sizeof(line)) size = sizeof(line) - 1;
	HANDLE file =
	    CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
		            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
	if (file == INVALID_HANDLE_VALUE) return;
	DWORD written = 0;
	WriteFile(file, line, static_cast<DWORD>(size), &written, nullptr);
	CloseHandle(file);
}

uint32_t RegisterGuestCodeProvenance(const GuestCodeProvenance& provenance) noexcept {
	if (provenance.start == 0 || provenance.size == 0 ||
	    provenance.start > UINT64_MAX - provenance.size || provenance.owner_base == 0 ||
	    provenance.kind == FaultGuestCodeKind::Unavailable) {
		return 0;
	}
	char owner[UNHANDLED_FAULT_MODULE_NAME_SIZE] {};
	char detail[UNHANDLED_FAULT_DETAIL_SIZE] {};
	if (!CopyBoundedDiagnosticText(owner, sizeof(owner), provenance.owner_basename, true) ||
	    !CopyBoundedDiagnosticText(detail, sizeof(detail), provenance.detail, false)) {
		return 0;
	}
	const uint32_t index = g_guest_code_registry_count.fetch_add(1, std::memory_order_acq_rel);
	if (index >= UNHANDLED_FAULT_GUEST_CODE_SLOTS) {
		g_guest_code_registry_overflow.fetch_add(1, std::memory_order_relaxed);
		return 0;
	}
	auto& entry         = g_guest_code_registry[index];
	entry.start         = provenance.start;
	entry.size          = provenance.size;
	entry.owner_base    = provenance.owner_base;
	entry.source_offset = provenance.source_offset;
	entry.kind          = provenance.kind;
	entry.generation    = index + 1;
	std::memcpy(entry.owner_basename, owner, sizeof(entry.owner_basename));
	std::memcpy(entry.detail, detail, sizeof(entry.detail));
	entry.active.store(1, std::memory_order_release);
	return index + 1;
}

void UnregisterGuestCodeProvenance(uint32_t token) noexcept {
	if (token == 0 || token > UNHANDLED_FAULT_GUEST_CODE_SLOTS) return;
	g_guest_code_registry[token - 1].active.exchange(0, std::memory_order_acq_rel);
}

// The guest stack is too small for host fs/graphics/IPMI code, so the handler runs on its own fiber
// stack.
struct NativeGuestExceptionFiber {
	void*                        original                    = nullptr;
	void*                        worker                      = nullptr;
	Handler                      callback                    = nullptr;
	const ExceptionInfo*         current                     = nullptr;
	FaultGuestCodeKind           guest_code_kind             = FaultGuestCodeKind::Unavailable;
	bool                         mini_range                  = false;
	bool                         original_rsp_on_guest_stack = false;
	uint64_t                     guest_stack_size            = 0;
	uint64_t                     guest_stack_remaining       = 0;
	NativeGuestPostHandlerAction post_action                 = nullptr;
	void*                        post_action_opaque          = nullptr;
	bool                         handled                     = false;
};
struct NativeGuestStackBounds {
	uint64_t low  = 0;
	uint64_t size = 0;
};
static thread_local NativeGuestExceptionFiber g_native_guest_exception_fiber {};
static thread_local NativeGuestStackBounds    g_native_guest_stack_bounds {};

const char* GuestStackRemainingBucket(uint64_t remaining) noexcept {
	if (remaining < 0x400) return "under_1024";
	if (remaining < 0x1000) return "1024_4095";
	if (remaining < 0x2000) return "4096_8191";
	if (remaining < 0x4000) return "8192_16383";
	return "16384_or_more";
}

static void WINAPI NativeGuestExceptionFiberEntry(void* opaque) {
	auto* state = static_cast<NativeGuestExceptionFiber*>(opaque);
	for (;;) {
		state->handled = state->callback != nullptr && state->current != nullptr &&
		                 state->callback(*state->current);
		if (state->handled && state->current != nullptr &&
		    state->current->type == ExceptionType::IllegalInstruction &&
		    g_native_guest_host_stack_audit_enabled.load(std::memory_order_acquire)) {
			static thread_local bool mini_reported       = false;
			static thread_local bool registered_reported = false;
			static thread_local bool execve_reported     = false;
			const bool               execve              = state->current->rax == 0x3b;
			if ((state->mini_range && !mini_reported) ||
			    (state->guest_code_kind != FaultGuestCodeKind::Unavailable &&
			     !registered_reported) ||
			    (execve && !execve_reported)) {
				LOGF("NATIVE_GUEST_HANDLER_HOST_STACK provider=%s guest_code_kind=%u"
				     " worker_stack_reserve=2097152 original_rsp_domain=%s"
				     " guest_stack_bytes=%" PRIu64 " remaining_bucket=%s"
				     " syscall_class=%s saved_context_forwarded=1\n",
				     state->mini_range ? "mini_range" : "registered_guest_code",
				     static_cast<unsigned>(state->guest_code_kind),
				     state->original_rsp_on_guest_stack ? "guest_stack" : "outside_or_unavailable",
				     state->original_rsp_on_guest_stack ? state->guest_stack_size : 0,
				     state->original_rsp_on_guest_stack
				         ? GuestStackRemainingBucket(state->guest_stack_remaining)
						 : "unavailable",
				     execve ? "execve" : "other");
				mini_reported |= state->mini_range;
				registered_reported |= state->guest_code_kind != FaultGuestCodeKind::Unavailable;
				execve_reported |= execve;
			}
		}
		SwitchToFiber(state->original);
	}
}

bool PrepareNativeGuestHandlerHostStackForCurrentThread() noexcept {
	if (!g_native_guest_host_stack_enabled.load(std::memory_order_acquire)) return true;
	auto& state = g_native_guest_exception_fiber;
	if (state.original == nullptr) {
		state.original = IsThreadAFiber() ? GetCurrentFiber() : ConvertThreadToFiber(nullptr);
		if (state.original == nullptr) return false;
	}
	if (state.worker == nullptr) {
		state.worker = CreateFiberEx(0x10000, 0x200000, 0, NativeGuestExceptionFiberEntry, &state);
		if (state.worker == nullptr) return false;
	}
	return true;
}

bool QueueNativeGuestPostHandlerAction(NativeGuestPostHandlerAction action, void* opaque) noexcept {
	if (action == nullptr) return false;
	auto& state = g_native_guest_exception_fiber;
	if (state.worker == nullptr || !IsThreadAFiber() || GetCurrentFiber() != state.worker ||
	    state.callback == nullptr || state.current == nullptr) {
		return false;
	}
	if (state.post_action != nullptr) {
		NoteHostExit(3, 323, state.current);
		Log::Flush();
		std::_Exit(323);
	}
	state.post_action        = action;
	state.post_action_opaque = opaque;
	return true;
}

void SetCurrentGuestStackBounds(uint64_t low, uint64_t size) noexcept {
	g_native_guest_stack_bounds = {low, size};
}

void ClearCurrentGuestStackBounds() noexcept {
	g_native_guest_stack_bounds = {};
}

static bool InvokeNativeGuestHandlerWithHostStack(Handler handler, const ExceptionInfo& info,
                                                  bool               mini_range,
                                                  FaultGuestCodeKind guest_code_kind,
                                                  bool*              handled) {
	auto& state = g_native_guest_exception_fiber;
	if (state.worker != nullptr && IsThreadAFiber() && GetCurrentFiber() == state.worker) {
		*handled = handler(info);
		return true;
	}
	if (!PrepareNativeGuestHandlerHostStackForCurrentThread()) return false;
	state.callback        = handler;
	state.current         = &info;
	state.mini_range      = mini_range;
	state.guest_code_kind = guest_code_kind;
	const auto bounds     = g_native_guest_stack_bounds;
	state.original_rsp_on_guest_stack =
	    bounds.low != 0 && bounds.size != 0 && bounds.low <= UINT64_MAX - bounds.size &&
	    info.rsp >= bounds.low && info.rsp < bounds.low + bounds.size;
	state.guest_stack_size      = state.original_rsp_on_guest_stack ? bounds.size : 0;
	state.guest_stack_remaining = state.original_rsp_on_guest_stack ? info.rsp - bounds.low : 0;
	state.post_action           = nullptr;
	state.post_action_opaque    = nullptr;
	state.handled               = false;
	SwitchToFiber(state.worker);
	const bool handler_result         = state.handled;
	auto*      post_action            = state.post_action;
	auto*      post_action_opaque     = state.post_action_opaque;
	state.current                     = nullptr;
	state.callback                    = nullptr;
	state.mini_range                  = false;
	state.guest_code_kind             = FaultGuestCodeKind::Unavailable;
	state.original_rsp_on_guest_stack = false;
	state.guest_stack_size            = 0;
	state.guest_stack_remaining       = 0;
	state.post_action                 = nullptr;
	state.post_action_opaque          = nullptr;
	*handled                          = handler_result;
	if (post_action != nullptr) {
		if (!handler_result) {
			NoteHostExit(4, 324, &info);
			Log::Flush();
			std::_Exit(324);
		}
		Log::Flush();
		post_action(post_action_opaque);
		NoteHostExit(5, 325, &info);
		std::_Exit(325);
	}
	return true;
}

static LONG WINAPI ExceptionFilter(PEXCEPTION_POINTERS exception) noexcept {
	auto* exception_record = exception->ExceptionRecord;

	if (exception_record->ExceptionCode == DBG_PRINTEXCEPTION_C ||
	    exception_record->ExceptionCode == DBG_PRINTEXCEPTION_WIDE_C) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	if (exception_record->ExceptionCode == 0x406D1388) {
		// Set a thread name.
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	ExceptionInfo info {};
	info.exception_address = reinterpret_cast<uint64_t>(exception_record->ExceptionAddress);
	info.native_code       = exception_record->ExceptionCode;
	info.native_process_id       = GetCurrentProcessId();
	info.native_thread_id        = GetCurrentThreadId();
	info.native_context_flags    = exception->ContextRecord->ContextFlags;
	info.original_context_pc     = exception->ContextRecord->Rip;
	info.original_context_rflags = exception->ContextRecord->EFlags;
	info.native_context    = exception->ContextRecord;

	if (exception_record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
		info.type = ExceptionType::AccessViolation;
		info.platform_access_valid = exception_record->NumberParameters >= 2 ? 1u : 0u;
		info.platform_access =
		    info.platform_access_valid != 0 ? exception_record->ExceptionInformation[0] : 0;
		if (info.platform_access_valid != 0) {
			switch (info.platform_access) {
				case 0: info.access_violation_type = AccessViolationType::Read; break;
				case 1: info.access_violation_type = AccessViolationType::Write; break;
				case 8: info.access_violation_type = AccessViolationType::Execute; break;
				default: info.access_violation_type = AccessViolationType::Unknown; break;
			}
			info.access_violation_vaddr = exception_record->ExceptionInformation[1];
		}
	} else if (exception_record->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
		info.type = ExceptionType::IllegalInstruction;
	} else {
		if (exception_record->ExceptionCode == EXCEPTION_BREAKPOINT) {
			// Nothing resumes an int3, so the process dies here and would take the buffered log
			// with it.
			const auto* stack = reinterpret_cast<const uint64_t*>(exception->ContextRecord->Rsp);
			LOGF("breakpoint at 0x%016" PRIx64 "\n", info.exception_address);
			for (int i = 0; i < 24; i++) {
				LOGF("\t [rsp+0x%02x] 0x%016" PRIx64 "\n", i * 8, stack[i]);
			}
			Log::Flush();
		}
		return EXCEPTION_CONTINUE_SEARCH;
	}

	info.rax = exception->ContextRecord->Rax;
	info.rbx = exception->ContextRecord->Rbx;
	info.rcx = exception->ContextRecord->Rcx;
	info.rdx = exception->ContextRecord->Rdx;
	info.rsi = exception->ContextRecord->Rsi;
	info.rdi = exception->ContextRecord->Rdi;
	info.rbp = exception->ContextRecord->Rbp;
	info.rsp = exception->ContextRecord->Rsp;
	info.r8  = exception->ContextRecord->R8;
	info.r9  = exception->ContextRecord->R9;
	info.r10 = exception->ContextRecord->R10;
	info.r11 = exception->ContextRecord->R11;
	info.r12 = exception->ContextRecord->R12;
	info.r13 = exception->ContextRecord->R13;
	info.r14 = exception->ContextRecord->R14;
	info.r15 = exception->ContextRecord->R15;

	const auto handler = g_handler.load(std::memory_order_acquire);
	if (handler != nullptr) {
		bool       handled = false;
		const bool mini_guest_pc =
		    info.exception_address >= 0x400000 && info.exception_address < 0x80000000;
		const auto guest_code_kind     = FindActiveGuestCodeKind(info.exception_address);
		const bool registered_guest_pc = guest_code_kind != FaultGuestCodeKind::Unavailable;
		const bool use_host_stack =
		    (mini_guest_pc || registered_guest_pc) &&
		    g_native_guest_host_stack_enabled.load(std::memory_order_acquire);
		if (use_host_stack) {
			const auto& fiber = g_native_guest_exception_fiber;
			const bool  nested =
			    fiber.worker != nullptr && IsThreadAFiber() && GetCurrentFiber() == fiber.worker;
			info.handler_route =
			    nested ? FaultHandlerRoute::HostFiberNested
				       : (mini_guest_pc ? FaultHandlerRoute::HostFiberMiniRange
				                        : FaultHandlerRoute::HostFiberRegisteredGuestCode);
			if (!InvokeNativeGuestHandlerWithHostStack(handler, info, mini_guest_pc,
			                                           guest_code_kind, &handled)) {
				return EXCEPTION_CONTINUE_SEARCH;
			}
		} else {
			handled = handler(info);
		}
		if (handled) return EXCEPTION_CONTINUE_EXECUTION;
	}
	CaptureUnhandledFaultProvenance(info);
	return EXCEPTION_CONTINUE_SEARCH;
}

#elif defined(__APPLE__)

static std::atomic<Handler> g_handler {nullptr};
static std::atomic_uint32_t g_install_state {0};

static_assert(decltype(g_handler)::is_always_lock_free);
static_assert(decltype(g_install_state)::is_always_lock_free);

// Translate the x86-64 page-fault error code (mcontext __es.__err) into an access type.
// bit 1 (0x2) = write, bit 4 (0x10) = instruction fetch, otherwise a read.
static AccessViolationType DecodeAccess(uint64_t err) {
	if ((err & 0x10u) != 0) {
		return AccessViolationType::Execute;
	}
	if ((err & 0x2u) != 0) {
		return AccessViolationType::Write;
	}
	return AccessViolationType::Read;
}

// POSIX signal handler that mirrors the Windows vectored handler: build an ExceptionInfo
// from the mcontext and dispatch. A resolved fault (handler returns true) simply returns,
// re-executing the faulting instruction against the now-fixed protection. An unresolved
// fault restores the default disposition so the retry terminates the process.
static void SignalHandler(int sig, siginfo_t* si, void* uctx) {
	auto*       uc = static_cast<ucontext_t*>(uctx);
	const auto* mc = uc->uc_mcontext;
	const auto& ss = mc->__ss;

	ExceptionInfo info {};
	info.exception_address = ss.__rip;
	info.native_code       = static_cast<uint32_t>(si->si_code);
	info.native_context    = uctx;

	if (sig == SIGILL) {
		info.type = ExceptionType::IllegalInstruction;
	} else {
		info.type                   = ExceptionType::AccessViolation;
		info.access_violation_type  = DecodeAccess(mc->__es.__err);
		info.access_violation_vaddr = reinterpret_cast<uint64_t>(si->si_addr);
	}

	info.rax = ss.__rax;
	info.rbx = ss.__rbx;
	info.rcx = ss.__rcx;
	info.rdx = ss.__rdx;
	info.rsi = ss.__rsi;
	info.rdi = ss.__rdi;
	info.rbp = ss.__rbp;
	info.rsp = ss.__rsp;
	info.r8  = ss.__r8;
	info.r9  = ss.__r9;
	info.r10 = ss.__r10;
	info.r11 = ss.__r11;
	info.r12 = ss.__r12;
	info.r13 = ss.__r13;
	info.r14 = ss.__r14;
	info.r15 = ss.__r15;

	const auto handler = g_handler.load(std::memory_order_acquire);
	if (handler != nullptr && handler(info)) {
		return; // retry the faulting instruction against the fixed mapping
	}

	// Unresolved: restore the default action so the re-executed instruction terminates.
	struct sigaction dfl {};
	dfl.sa_handler = SIG_DFL;
	sigemptyset(&dfl.sa_mask);
	sigaction(sig, &dfl, nullptr);
}

#else

// x86-64 page-fault error bits.
constexpr uint64_t PAGE_FAULT_ERROR_WRITE       = 0x02;
constexpr uint64_t PAGE_FAULT_ERROR_INSTRUCTION = 0x10;

// Let the kernel handle an unresolved fault on retry.
static void ChainToDefault(int signal_number) noexcept {
	struct sigaction restore {};
	restore.sa_handler = SIG_DFL;
	sigemptyset(&restore.sa_mask);
	restore.sa_flags = 0;
	::sigaction(signal_number, &restore, nullptr);
}

static void SignalHandler(int signal_number, siginfo_t* signal_info, void* native_context) {
	auto* context = static_cast<ucontext_t*>(native_context);
	auto* gregs   = context->uc_mcontext.gregs;

	ExceptionInfo info {};
	info.exception_address = static_cast<uint64_t>(gregs[REG_RIP]);
	info.native_code       = static_cast<uint32_t>(signal_number);
	info.native_context    = context;

	if (signal_number == SIGSEGV || signal_number == SIGBUS) {
		info.type             = ExceptionType::AccessViolation;
		const auto error_code = static_cast<uint64_t>(gregs[REG_ERR]);
		if ((error_code & PAGE_FAULT_ERROR_INSTRUCTION) != 0) {
			info.access_violation_type = AccessViolationType::Execute;
		} else if ((error_code & PAGE_FAULT_ERROR_WRITE) != 0) {
			info.access_violation_type = AccessViolationType::Write;
		} else {
			info.access_violation_type = AccessViolationType::Read;
		}
		info.access_violation_vaddr = reinterpret_cast<uint64_t>(signal_info->si_addr);
	} else if (signal_number == SIGILL) {
		info.type = ExceptionType::IllegalInstruction;
	} else {
		ChainToDefault(signal_number);
		return;
	}

	info.rax = static_cast<uint64_t>(gregs[REG_RAX]);
	info.rbx = static_cast<uint64_t>(gregs[REG_RBX]);
	info.rcx = static_cast<uint64_t>(gregs[REG_RCX]);
	info.rdx = static_cast<uint64_t>(gregs[REG_RDX]);
	info.rsi = static_cast<uint64_t>(gregs[REG_RSI]);
	info.rdi = static_cast<uint64_t>(gregs[REG_RDI]);
	info.rbp = static_cast<uint64_t>(gregs[REG_RBP]);
	info.rsp = static_cast<uint64_t>(gregs[REG_RSP]);
	info.r8  = static_cast<uint64_t>(gregs[REG_R8]);
	info.r9  = static_cast<uint64_t>(gregs[REG_R9]);
	info.r10 = static_cast<uint64_t>(gregs[REG_R10]);
	info.r11 = static_cast<uint64_t>(gregs[REG_R11]);
	info.r12 = static_cast<uint64_t>(gregs[REG_R12]);
	info.r13 = static_cast<uint64_t>(gregs[REG_R13]);
	info.r14 = static_cast<uint64_t>(gregs[REG_R14]);
	info.r15 = static_cast<uint64_t>(gregs[REG_R15]);

	const auto handler = g_handler.load(std::memory_order_acquire);
	if (handler != nullptr && handler(info)) {
		return;
	}

	ChainToDefault(signal_number);
}

#endif

#if KYTY_PLATFORM != KYTY_PLATFORM_WINDOWS
bool PrepareUnhandledFaultProvenance(int32_t guest_process_id) {
	(void)guest_process_id;
	return false;
}

bool IsUnhandledFaultProvenancePrepared() noexcept {
	return false;
}

bool CaptureUnhandledFaultProvenance(const ExceptionInfo& info) noexcept {
	(void)info;
	return false;
}

void NoteHostExit(uint32_t path_id, int exit_status, const ExceptionInfo* info) noexcept {
	(void)path_id;
	(void)exit_status;
	(void)info;
}

void SetUnhandledFaultReentryHookForTests(UnhandledFaultReentryHook hook) noexcept {
	(void)hook;
}

uint32_t RegisterGuestCodeProvenance(const GuestCodeProvenance& provenance) noexcept {
	(void)provenance;
	return 0;
}

void UnregisterGuestCodeProvenance(uint32_t token) noexcept {
	(void)token;
}

FaultGuestCodeKind QueryActiveGuestCodeKind(uint64_t address) noexcept {
	(void)address;
	return FaultGuestCodeKind::Unavailable;
}

bool PrepareNativeGuestHandlerHostStackForCurrentThread() noexcept {
	return true;
}

bool QueueNativeGuestPostHandlerAction(NativeGuestPostHandlerAction action, void* opaque) noexcept {
	(void)action;
	(void)opaque;
	return false;
}

void SetCurrentGuestStackBounds(uint64_t low, uint64_t size) noexcept {
	(void)low;
	(void)size;
}

void ClearCurrentGuestStackBounds() noexcept {}
#endif

bool InstallHandler(Handler handler) {
	if (handler == nullptr) {
		return false;
	}

	uint32_t expected_state = 0;
	if (!g_install_state.compare_exchange_strong(expected_state, 1, std::memory_order_acq_rel)) {
		return expected_state == 2 && g_handler.load(std::memory_order_acquire) == handler;
	}

	g_handler.store(handler, std::memory_order_release);

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
	char host_stack_value = 0;
	g_native_guest_host_stack_enabled.store(
	    GetEnvironmentVariableA("KYTY_DIAGNOSTIC_NATIVE_SYSCALL_HOST_STACK", &host_stack_value,
		                        sizeof(host_stack_value)) != 0 ||
	        GetEnvironmentVariableA("KYTY_DIAGNOSTIC_MINI_SYSCORE_LIVE_RFORK", &host_stack_value,
			                        sizeof(host_stack_value)) != 0,
	    std::memory_order_release);
	g_native_guest_host_stack_audit_enabled.store(
	    GetEnvironmentVariableA("KYTY_DIAGNOSTIC_NATIVE_SYSCALL_HOST_STACK_AUDIT",
		                        &host_stack_value, sizeof(host_stack_value)) != 0,
	    std::memory_order_release);
	if (AddVectoredExceptionHandler(0, ExceptionFilter) == nullptr) {
		g_handler.store(nullptr, std::memory_order_release);
		g_install_state.store(0, std::memory_order_release);
		printf("AddVectoredExceptionHandler() failed\n");
		return false;
	}
#elif defined(__APPLE__)
	struct sigaction sa {};
	sa.sa_sigaction = SignalHandler;
	sa.sa_flags     = SA_SIGINFO | SA_ONSTACK;
	sigemptyset(&sa.sa_mask);
	// The guest signal-dispatch path (KernelRaiseException) interrupts threads with
	// SIGUSR1; block it while a fault is being resolved so a stop-the-world request
	// cannot preempt the handler between the protection fix and the retry.
	sigaddset(&sa.sa_mask, SIGUSR1);

	// macOS raises SIGBUS for protection faults on some paths and SIGSEGV on others;
	// SIGILL covers instructions the host cannot execute (routed to the x64 emulator).
	bool ok = sigaction(SIGSEGV, &sa, nullptr) == 0 && sigaction(SIGBUS, &sa, nullptr) == 0 &&
	          sigaction(SIGILL, &sa, nullptr) == 0;
	if (!ok) {
		g_handler.store(nullptr, std::memory_order_release);
		g_install_state.store(0, std::memory_order_release);
		printf("sigaction() failed to install the host fault handler\n");
		return false;
	}
#else
	struct sigaction action {};
	action.sa_sigaction = SignalHandler;
	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;

	for (const int signal_number: {SIGSEGV, SIGBUS, SIGILL}) {
		if (::sigaction(signal_number, &action, nullptr) != 0) {
			g_handler.store(nullptr, std::memory_order_release);
			g_install_state.store(0, std::memory_order_release);
			printf("sigaction(%d) failed\n", signal_number);
			return false;
		}
	}
#endif

	g_install_state.store(2, std::memory_order_release);
	return true;
}

} // namespace Common::HostException
