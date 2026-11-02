#include "common/abi.h"
#include "common/assert.h"
#include "libs/errno.h"
#include "libs/libs.h"
#include "loader/symbolDatabase.h"

#include <cstdlib>
#include <cinttypes>
#include <cstring>

namespace Libs {

LIB_VERSION("NpCommon", 1, "NpCommon", 1, 1);

namespace NpCommon {

static uint64_t g_native_create = 0;
static uint64_t g_native_config = 0;
static uint64_t g_native_start  = 0;

void SetDiagnosticNativeEntries(uint64_t create, uint64_t config, uint64_t start) {
	g_native_create = create;
	g_native_config = config;
	g_native_start  = start;
	LOGF("NPCOMMON_NATIVE_TRACE targets create=0x%016" PRIx64 " config=0x%016" PRIx64
	     " start=0x%016" PRIx64 "\n",
	     create, config, start);
}

static int KYTY_SYSV_ABI TraceCreate(void* instance, const void* options) {
	LOGF("NPCOMMON_NATIVE_TRACE qFdG8Ucfeqg entry instance=%p options=%p\n", instance, options);
	if (g_native_create == 0) {
		EXIT("NPCOMMON_NATIVE_TRACE create target unavailable\n");
	}
	using func_t     = KYTY_SYSV_ABI int (*)(void*, const void*);
	const int result = reinterpret_cast<func_t>(g_native_create)(instance, options);
	LOGF("NPCOMMON_NATIVE_TRACE qFdG8Ucfeqg return=0x%08x\n", static_cast<uint32_t>(result));
	if (instance != nullptr) {
		// qFdG8Ucfeqg builds a native 0x168-byte NpCommon object
		const auto* bytes = static_cast<const uint8_t*>(instance);
		for (const auto offset: {0x8u, 0x10u, 0x18u, 0x30u, 0x40u, 0x48u, 0x150u, 0x158u, 0x160u}) {
			uint64_t value = 0;
			std::memcpy(&value, bytes + offset, sizeof(value));
			LOGF("NPCOMMON_NATIVE_TRACE instance+0x%03x=0x%016" PRIx64 "\n", offset, value);
		}
	}
	return result;
}

static int KYTY_SYSV_ABI TraceConfig(void* instance, const void* options) {
	LOGF("NPCOMMON_NATIVE_TRACE fqAS9GQTmOU entry instance=%p options=%p\n", instance, options);
	if (g_native_config == 0) {
		EXIT("NPCOMMON_NATIVE_TRACE config target unavailable\n");
	}
	using func_t     = KYTY_SYSV_ABI int (*)(void*, const void*);
	const int result = reinterpret_cast<func_t>(g_native_config)(instance, options);
	LOGF("NPCOMMON_NATIVE_TRACE fqAS9GQTmOU return=0x%08x\n", static_cast<uint32_t>(result));
	return result;
}

static int KYTY_SYSV_ABI TraceStart(void* instance) {
	LOGF("NPCOMMON_NATIVE_TRACE NTPZ5GZIA6U entry instance=%p\n", instance);
	if (g_native_start == 0) {
		EXIT("NPCOMMON_NATIVE_TRACE start target unavailable\n");
	}
	using func_t     = KYTY_SYSV_ABI int (*)(void*);
	const int result = reinterpret_cast<func_t>(g_native_start)(instance);
	LOGF("NPCOMMON_NATIVE_TRACE NTPZ5GZIA6U return=0x%08x\n", static_cast<uint32_t>(result));
	return result;
}

static int KYTY_SYSV_ABI GetEnvironment(char* out, size_t size) {
	PRINT_NAME();

	if (out == nullptr) {
		return static_cast<int32_t>(0x80550003u);
	}

	constexpr char ENV[] = "np";
	if (size < sizeof(ENV)) {
		return static_cast<int32_t>(0x80550602u);
	}

	std::memset(out, 0, size);
	std::memcpy(out, ENV, sizeof(ENV));
	return OK;
}

} // namespace NpCommon

LIB_DEFINE(InitNpCommon_1) {
	LIB_FUNC("kBON3bAtfGs", NpCommon::GetEnvironment);
	if (std::getenv("KYTY_DIAGNOSTIC_NPCOMMON_NATIVE_TRACE") != nullptr) {
		LIB_FUNC("qFdG8Ucfeqg", NpCommon::TraceCreate);
		LIB_FUNC("fqAS9GQTmOU", NpCommon::TraceConfig);
		LIB_FUNC("NTPZ5GZIA6U", NpCommon::TraceStart);
	}
}

} // namespace Libs