#include "libs/libs.h"
#include "loader/symbolDatabase.h"

#include <atomic>

namespace Libs {

LIB_VERSION("Hmd", 1, "Hmd", 1, 1);

namespace Hmd {

static uint32_t KYTY_SYSV_ABI HmdInternalMmapIsConnect() {
	PRINT_NAME();

	// libSceHmd reads this from its /dev/hmd_dist page (0 if missing); module start is skipped, so
	// the native reader would hit a null page
	static std::atomic_bool logged = false;
	if (!logged.exchange(true)) {
		LOGF("FIRST_FRAME_AUDIT HMD_MMAP_IS_CONNECT result=0\n");
	}
	return 0;
}

} // namespace Hmd

LIB_DEFINE(InitHmd_1) {
	LIB_FUNC("1PNiQR-7L6k", Hmd::HmdInternalMmapIsConnect);
}

} // namespace Libs
