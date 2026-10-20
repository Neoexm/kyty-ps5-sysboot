#include "kernel/appMount.h"

#include "common/logging/log.h"
#include "common/threads.h"
#include "kernel/process.h"
#include "libs/errno.h"

#include <nlohmann/json.hpp>

#include <bit>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>

#if KYTY_PLATFORM == KYTY_PLATFORM_WINDOWS
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace Libs::LibKernel::AppMount {
namespace {
// Another process's record needs caps0 bit 62 (0x9e9f8f90); self is exempt.
int CheckCapability(int pid) {
	if (pid == Process::GetPid()) return 0;
	constexpr uint64_t bit   = uint64_t {1} << 62;
	const auto         facts = Process::GetCurrentAuthorizationFacts();
	if (!facts.has_authority || (facts.known_capability0 & bit) == 0) {
		LOGF("APP_INFO_CAPABILITY_UNKNOWN caller=%d target=%d bit=62\n", Process::GetPid(), pid);
		return Posix::POSIX_ENOSYS;
	}
	const bool ok = (facts.capability0 & bit) != 0;
	LOGF("APP_INFO_CHECKCAP caller=%d target=%d authority=0x%016" PRIx64 " cap0=0x%016" PRIx64
	     " known0=0x%016" PRIx64 " result=%d\n",
	     Process::GetPid(), pid, facts.authority_id, facts.capability0, facts.known_capability0,
	     ok ? 1 : 0);
	return ok ? 0 : Posix::POSIX_EPERM;
}
} // namespace
} // namespace Libs::LibKernel::AppMount
