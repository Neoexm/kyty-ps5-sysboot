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

enum class FaultGuestCodeKind : uint32_t {
	Unavailable,
	ProgramExecutable,
	InstructionTrampoline,
	TlsHandler,
	UnresolvedImportThunk
};
struct GuestCodeProvenance {
	uint64_t           start          = 0;
	uint64_t           size           = 0;
	uint64_t           owner_base     = 0;
	uint64_t           source_offset  = 0;
	FaultGuestCodeKind kind           = FaultGuestCodeKind::Unavailable;
	const char*        owner_basename = nullptr;
	const char*        detail         = nullptr;
};

using Handler                      = bool (*)(const ExceptionInfo&);
bool InstallHandler(Handler handler);
bool     IsUnhandledFaultProvenancePrepared() noexcept;
bool     CaptureUnhandledFaultProvenance(const ExceptionInfo& info) noexcept;
void     NoteHostExit(uint32_t path_id, int exit_status, const ExceptionInfo* info) noexcept;
FaultGuestCodeKind QueryActiveGuestCodeKind(uint64_t address) noexcept;
void ClearCurrentGuestStackBounds() noexcept;

#if KYTY_PLATFORM == KYTY_PLATFORM_LINUX
bool InitializeThreadSignalStack();
#endif

} // namespace Common::HostException

#endif /* KYTY_COMMON_HOST_EXCEPTION_H_ */
