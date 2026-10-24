#include "common/abi.h"
#include "common/assert.h"
#include "libs/errno.h"
#include "libs/libs.h"
#include "loader/symbolDatabase.h"

#include <cstdlib>
#include <cinttypes>
#include <cstring>

namespace Libs {
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
} // namespace NpCommon
} // namespace Libs