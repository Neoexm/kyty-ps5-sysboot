#ifndef KYTY_COMMON_HOST_EXCEPTION_H_
#define KYTY_COMMON_HOST_EXCEPTION_H_

#include "common/common.h"

namespace Common::HostException {

enum class ExceptionType : uint32_t { Unknown, AccessViolation, IllegalInstruction };

enum class AccessViolationType : uint32_t { Unknown, Read, Write, Execute };

enum class FaultHandlerRoute : uint32_t {
	Direct,
	HostFiberMiniRange,
	HostFiberRegisteredGuestCode,
	HostFiberNested
};

struct ExceptionInfo {
	ExceptionType       type                   = ExceptionType::Unknown;
	AccessViolationType access_violation_type  = AccessViolationType::Unknown;
	uint64_t            access_violation_vaddr = 0;
	uint64_t            exception_address      = 0;
	uint64_t            rax                    = 0;
	uint64_t            rbx                    = 0;
	uint64_t            rcx                    = 0;
	uint64_t            rdx                    = 0;
	uint64_t            rsi                    = 0;
	uint64_t            rdi                    = 0;
	uint64_t            rbp                    = 0;
	uint64_t            rsp                    = 0;
	uint64_t            r8                     = 0;
	uint64_t            r9                     = 0;
	uint64_t            r10                    = 0;
	uint64_t            r11                    = 0;
	uint64_t            r12                    = 0;
	uint64_t            r13                    = 0;
	uint64_t            r14                    = 0;
	uint64_t            r15                    = 0;
	uint32_t            native_code            = 0;
	uint32_t            native_process_id       = 0;
	uint32_t            native_thread_id        = 0;
	uint32_t            platform_access_valid   = 0;
	uint64_t            platform_access         = 0;
	uint64_t            native_context_flags    = 0;
	uint64_t            original_context_pc     = 0;
	uint64_t            original_context_rflags = 0;
	FaultHandlerRoute   handler_route           = FaultHandlerRoute::Direct;
	// Platform-specific mutable context, valid only for the duration of the handler call.
	void* native_context = nullptr;
};

enum class FaultAddressClass : uint32_t {
	Unavailable,
	Image,
	UnknownImage,
	Private,
	Mapped,
	Unmapped,
	LowUnmapped,
	StaleImage,
	Unknown
};

enum class FaultStackStatus : uint32_t { Unavailable, Complete, Partial, Truncated };

enum class FaultStackTopStatus : uint32_t { Unavailable, Zero, Classified };

enum class HandlerStackStatus : uint32_t { Omitted = 1 };

enum class FaultGuestCodeKind : uint32_t {
	Unavailable,
	ProgramExecutable,
	InstructionTrampoline,
	TlsHandler,
	UnresolvedImportThunk
};

enum class FaultGuestCodeLifecycle : uint32_t { Unavailable, Active, RetiredDuringCapture };

constexpr uint32_t UNHANDLED_FAULT_MODULE_NAME_SIZE = 64;
constexpr uint32_t UNHANDLED_FAULT_DETAIL_SIZE      = 64;
constexpr uint32_t UNHANDLED_FAULT_MAX_FRAMES       = 8;

struct GuestCodeProvenance {
	uint64_t           start          = 0;
	uint64_t           size           = 0;
	uint64_t           owner_base     = 0;
	uint64_t           source_offset  = 0;
	FaultGuestCodeKind kind           = FaultGuestCodeKind::Unavailable;
	const char*        owner_basename = nullptr;
	const char*        detail         = nullptr;
};

#pragma pack(push, 1)
struct FaultGuestCodeRef {
	uint32_t                available     = 0;
	FaultGuestCodeKind      kind          = FaultGuestCodeKind::Unavailable;
	FaultGuestCodeLifecycle lifecycle     = FaultGuestCodeLifecycle::Unavailable;
	uint32_t                generation    = 0;
	uint64_t                region_offset = 0;
	uint64_t                owner_offset  = 0;
	uint64_t                source_offset = 0;
	uint64_t                region_size   = 0;
	char                    owner_basename[UNHANDLED_FAULT_MODULE_NAME_SIZE] {};
	char                    detail[UNHANDLED_FAULT_DETAIL_SIZE] {};
};

struct FaultModuleRef {
	FaultAddressClass address_class        = FaultAddressClass::Unavailable;
	uint32_t          current_state        = 0;
	uint32_t          current_type         = 0;
	uint32_t          current_protection   = 0;
	uint64_t          relative_offset      = 0;
	uint32_t          image_machine        = 0;
	uint32_t          image_timestamp      = 0;
	uint32_t          image_size           = 0;
	uint32_t          image_checksum       = 0;
	uint32_t          image_identity_valid = 0;
	uint32_t          image_codeview_valid = 0;
	uint8_t           image_pdb_guid[16] {};
	uint32_t          image_pdb_age = 0;
	char              module_basename[UNHANDLED_FAULT_MODULE_NAME_SIZE] {};
	FaultGuestCodeRef guest_code {};
};

struct FaultFileIdentity {
	uint32_t available    = 0;
	uint32_t sha256_valid = 0;
	uint64_t file_size    = 0;
	uint8_t  sha256[32] {};
	uint32_t loaded_probe_valid = 0;
	uint32_t loaded_probe_rva   = 0;
	uint32_t loaded_probe_size  = 0;
	uint8_t  loaded_probe_sha256[32] {};
};

struct UnhandledFaultRecord {
	char                magic[8] {};
	uint32_t            version                      = 0;
	uint32_t            size                         = 0;
	uint64_t            checksum                     = 0;
	uint32_t            complete                     = 0;
	uint32_t            native_process_id            = 0;
	uint32_t            native_thread_id             = 0;
	int32_t             guest_process_id             = 0;
	uint32_t            native_code                  = 0;
	ExceptionType       exception_type               = ExceptionType::Unknown;
	AccessViolationType normalized_access            = AccessViolationType::Unknown;
	uint32_t            platform_access_valid        = 0;
	uint64_t            platform_access              = 0;
	uint64_t            native_context_flags         = 0;
	uint64_t            original_context_rflags      = 0;
	uint32_t            expected_exit_status         = 321;
	uint32_t            module_snapshot_count        = 0;
	uint32_t            guest_code_registry_count    = 0;
	uint32_t            guest_code_registry_overflow = 0;
	uint32_t            emitter_matches_original_pc  = 0;
	FaultHandlerRoute   handler_route                = FaultHandlerRoute::Direct;
	FaultModuleRef      emitter_pc {};
	FaultModuleRef      pc {};
	FaultModuleRef      target {};
	FaultModuleRef      context_rax {};
	FaultModuleRef      context_rbx {};
	FaultModuleRef      context_rcx {};
	FaultModuleRef      context_rdx {};
	FaultModuleRef      context_r13 {};
	FaultModuleRef      context_r14 {};
	FaultModuleRef      context_r15 {};
	FaultFileIdentity   emitter_file_identity {};
	FaultStackTopStatus original_stack_top_status   = FaultStackTopStatus::Unavailable;
	uint32_t            original_stack_top_reserved = 0;
	FaultModuleRef      original_stack_top {};
	FaultStackStatus    original_stack_status = FaultStackStatus::Unavailable;
	uint32_t            original_frame_count  = 0;
	HandlerStackStatus  handler_stack_status  = HandlerStackStatus::Omitted;
	uint32_t            reserved              = 0;
	FaultModuleRef      original_frames[UNHANDLED_FAULT_MAX_FRAMES] {};
};
#pragma pack(pop)

static_assert(sizeof(FaultGuestCodeRef) == 176);
static_assert(sizeof(FaultModuleRef) == 308);
static_assert(sizeof(UnhandledFaultRecord) == 6072);

using Handler                      = bool (*)(const ExceptionInfo&);
using NativeGuestPostHandlerAction = void (*)(void*);

bool     InstallHandler(Handler handler);
bool     PrepareUnhandledFaultProvenance(int32_t guest_process_id);
bool     IsUnhandledFaultProvenancePrepared() noexcept;
bool     CaptureUnhandledFaultProvenance(const ExceptionInfo& info) noexcept;
void     NoteHostExit(uint32_t path_id, int exit_status, const ExceptionInfo* info) noexcept;
uint32_t RegisterGuestCodeProvenance(const GuestCodeProvenance& provenance) noexcept;
void     UnregisterGuestCodeProvenance(uint32_t token) noexcept;
FaultGuestCodeKind QueryActiveGuestCodeKind(uint64_t address) noexcept;
bool               PrepareNativeGuestHandlerHostStackForCurrentThread() noexcept;
bool QueueNativeGuestPostHandlerAction(NativeGuestPostHandlerAction action, void* opaque) noexcept;
void SetCurrentGuestStackBounds(uint64_t low, uint64_t size) noexcept;
void ClearCurrentGuestStackBounds() noexcept;
using UnhandledFaultReentryHook = void (*)() noexcept;
void SetUnhandledFaultReentryHookForTests(UnhandledFaultReentryHook hook) noexcept;

#if KYTY_PLATFORM == KYTY_PLATFORM_LINUX
bool InitializeThreadSignalStack();
#endif

} // namespace Common::HostException

#endif /* KYTY_COMMON_HOST_EXCEPTION_H_ */
