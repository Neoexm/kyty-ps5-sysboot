#include "libs/libMbus.h"

#include "common/abi.h"
#include "common/logging/log.h"
#include "libs/hostInputMbus.h"
#include "libs/libs.h"
#include "loader/symbolDatabase.h"

#include <atomic>
#include <cstdlib>
#include <cstring>

namespace Libs::Mbus {
static std::atomic<uint64_t> g_original_get_device_info {0};
static std::atomic<uint64_t> g_original_set_volume_down {0};
static std::atomic<uint64_t> g_mbus_client_slot {0};
void SetOriginalGetDeviceInfoByCondition(uint64_t address) {
	g_original_get_device_info.store(address, std::memory_order_release);
}
void SetOriginalSetVolumeDown(uint64_t address, uint64_t client_slot) {
	g_mbus_client_slot.store(client_slot, std::memory_order_release);
	g_original_set_volume_down.store(address, std::memory_order_release);
}
} // namespace Libs::Mbus
