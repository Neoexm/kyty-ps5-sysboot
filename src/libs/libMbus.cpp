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

LIB_VERSION("Mbus", 1, "Mbus", 1, 1);

using GetDeviceInfoByCondition = KYTY_SYSV_ABI int (*)(const void* condition, int start,
                                                       void* output, int capacity, int* total,
                                                       int* remaining, uint32_t record_size);
using GetDeviceInfoById        = KYTY_SYSV_ABI int (*)(uint64_t device_id, void* output,
                                                       uint32_t record_size);
using SetVolumeDown            = KYTY_SYSV_ABI int (*)(int type, int value);

static std::atomic<uint64_t> g_original_get_device_info {0};
static std::atomic<uint64_t> g_original_get_device_info_by_id {0};
static std::atomic<uint64_t> g_original_set_volume_down {0};
static std::atomic<uint64_t> g_mbus_client_slot {0};
static std::atomic<uint32_t> g_injection_log_count {0};
static std::atomic<uint32_t> g_bond_injection_log_count {0};
static std::atomic<uint32_t> g_bond_query_log_count {0};
static std::atomic<uint32_t> g_bond_lookup_log_count {0};
static std::atomic<uint32_t> g_uninitialized_log_count {0};

static constexpr int MBUS_ERROR_INTERNAL = static_cast<int32_t>(0x809b00ffu);

static bool HostInputBridgeEnabled() {
	const auto* value = std::getenv("KYTY_DIAGNOSTIC_HOST_INPUT_HID_PAD");
	return value != nullptr && std::strcmp(value, "1") == 0;
}

static bool VirtualUsbPadEnabled() {
	const auto* value = std::getenv("KYTY_DIAGNOSTIC_VIRTUAL_USB_PAD");
	return value != nullptr && std::strcmp(value, "1") == 0;
}

static bool UninitializedGuardEnabled() {
	const auto* value = std::getenv("KYTY_DIAGNOSTIC_MBUS_UNINITIALIZED_GUARD");
	return value != nullptr && std::strcmp(value, "1") == 0;
}

void SetOriginalGetDeviceInfoByCondition(uint64_t address) {
	g_original_get_device_info.store(address, std::memory_order_release);
}

void SetOriginalGetDeviceInfoById(uint64_t address) {
	g_original_get_device_info_by_id.store(address, std::memory_order_release);
}

void SetOriginalSetVolumeDown(uint64_t address, uint64_t client_slot) {
	g_mbus_client_slot.store(client_slot, std::memory_order_release);
	g_original_set_volume_down.store(address, std::memory_order_release);
}

static bool SetVolumeDownReachesClient(int type, int value) {
	const auto unsigned_type = static_cast<uint32_t>(type);
	if (unsigned_type > 0x20u) return false;
	if ((0x100010116ull & (1ull << unsigned_type)) == 0) return false;
	return static_cast<uint8_t>(value) <= 0x24u;
}

static int KYTY_SYSV_ABI MbusSetVolumeDownGuard(int type, int value) {
	const auto original_address = g_original_set_volume_down.load(std::memory_order_acquire);
	if (original_address == 0) {
		LOGF_COLOR(Log::Color::Red,
		           "NON_AUTHENTIC_MBUS_GUARD sceMbusSetVolumeDown original provider unavailable"
		           " result=0x%08x\n",
		           static_cast<uint32_t>(MBUS_ERROR_INTERNAL));
		return MBUS_ERROR_INTERNAL;
	}

	const auto original = reinterpret_cast<SetVolumeDown>(original_address);
	if (!SetVolumeDownReachesClient(type, value)) return original(type, value);

	const auto client_slot = g_mbus_client_slot.load(std::memory_order_acquire);
	if (client_slot != 0 && *reinterpret_cast<const uint64_t*>(client_slot) != 0) {
		return original(type, value);
	}

	if (g_uninitialized_log_count.fetch_add(1, std::memory_order_relaxed) < 8) {
		LOGF_COLOR(Log::Color::Red,
		           "NON_AUTHENTIC_MBUS_GUARD sceMbusSetVolumeDown rejected before sceMbusInit"
		           " type=%d value=%d client_slot=0x%016" PRIx64 " result=0x%08x\n",
		           type, value, client_slot, static_cast<uint32_t>(MBUS_ERROR_INTERNAL));
	}
	return MBUS_ERROR_INTERNAL;
}

static int KYTY_SYSV_ABI MbusGetDeviceInfoByCondition(const void* condition, int start,
                                                      void* output, int capacity, int* total,
                                                      int* remaining, uint32_t record_size) {
	const bool virtual_usb_pad = VirtualUsbPadEnabled();
	const bool all_devices     = virtual_usb_pad && HostInput::IsAllDeviceCondition(condition);
	const bool trace_query = virtual_usb_pad && !HostInput::IsControllerCondition(condition) &&
	                         g_bond_query_log_count.fetch_add(1, std::memory_order_relaxed) < 16;
	if (trace_query) {
		const auto expected = HostInput::AllDeviceCondition();
		int        mismatch = condition == nullptr ? -2 : -1;
		uint32_t   actual   = 0;
		uint32_t   wanted   = 0;
		if (condition != nullptr) {
			const auto* bytes = static_cast<const uint8_t*>(condition);
			for (size_t offset = 0; offset < expected.size(); offset++) {
				if (bytes[offset] == expected[offset]) continue;
				mismatch = static_cast<int>(offset);
				actual   = bytes[offset];
				wanted   = expected[offset];
				break;
			}
		}
		LOGF("NON_AUTHENTIC_VIRTUAL_USB_PAD MBus condition query entry"
		     " start=%d capacity=%d record_size=0x%x all_devices=%u"
		     " mismatch=%d actual=0x%02x expected=0x%02x"
		     " output=%u total=%u remaining=%u\n",
		     start, capacity, record_size, all_devices ? 1u : 0u, mismatch, actual, wanted,
		     output != nullptr ? 1u : 0u, total != nullptr ? 1u : 0u,
		     remaining != nullptr ? 1u : 0u);
	}
	const auto original_address = g_original_get_device_info.load(std::memory_order_acquire);
	if (original_address == 0) {
		LOGF_COLOR(Log::Color::Red,
		           "NON_AUTHENTIC_INPUT_BRIDGE MBus original provider unavailable\n");
		return MBUS_ERROR_INTERNAL;
	}

	const auto original = reinterpret_cast<GetDeviceInfoByCondition>(original_address);
	const int  result = original(condition, start, output, capacity, total, remaining, record_size);
	if (trace_query) {
		LOGF("NON_AUTHENTIC_VIRTUAL_USB_PAD MBus condition query result=0x%08x"
		     " total=%d remaining=%d\n",
		     static_cast<uint32_t>(result), result >= 0 && total != nullptr ? *total : -1,
		     result >= 0 && remaining != nullptr ? *remaining : -1);
	}
	if (result < 0 || start != 0 || capacity < 1 || output == nullptr || total == nullptr ||
	    record_size != HostInput::RECORD_SIZE) {
		return result;
	}
	if (result == 0 && HostInputBridgeEnabled() && HostInput::IsControllerCondition(condition)) {
		HostInput::FillControllerRecord(output);
		*total = 1;
		if (remaining != nullptr) *remaining = 0;
		if (g_injection_log_count.fetch_add(1, std::memory_order_relaxed) < 8) {
			LOGF("NON_AUTHENTIC_INPUT_BRIDGE MBus controller record injected"
			     " device_id=0x%016" PRIx64 " class=0x%08x subtype=%u assignment=0x%08x\n",
			     HostInput::VIRTUAL_DEVICE_ID, HostInput::CONTROLLER_CLASS,
			     HostInput::CONTROLLER_SUBTYPE, HostInput::CONTROLLER_ASSIGNMENT);
		}
		return 1;
	}
	if (virtual_usb_pad && all_devices &&
	    HostInput::AppendBondUsbRecord(output, result, capacity, total, remaining, record_size)) {
		if (g_bond_injection_log_count.fetch_add(1, std::memory_order_relaxed) < 8) {
			LOGF("NON_AUTHENTIC_VIRTUAL_USB_PAD MBus all-device BOND record appended"
			     " original_result=%d returned=%d total=%d remaining=%d"
			     " device_id=0x%016" PRIx64 " transport=%u class=0x%08x"
			     " remaining_fields=unknown_zero\n",
			     result, result + 1, *total, *remaining, HostInput::VIRTUAL_BOND_DEVICE_ID,
			     HostInput::BOND_USB_TRANSPORT,
			     HostInput::BOND_CLASS);
		}
		return result + 1;
	}
	return result;
}

static int KYTY_SYSV_ABI MbusGetDeviceInfoById(uint64_t device_id, void* output,
                                                uint32_t record_size) {
	const auto original_address = g_original_get_device_info_by_id.load(std::memory_order_acquire);
	if (original_address == 0) {
		LOGF_COLOR(Log::Color::Red,
		           "NON_AUTHENTIC_VIRTUAL_USB_PAD MBus by-id original provider unavailable\n");
		return MBUS_ERROR_INTERNAL;
	}

	const auto original = reinterpret_cast<GetDeviceInfoById>(original_address);
	if (!VirtualUsbPadEnabled() ||
	    !HostInput::IsBondDeviceLookup(device_id, output, record_size)) {
		return original(device_id, output, record_size);
	}
	HostInput::FillBondUsbRecord(output);
	if (g_bond_lookup_log_count.fetch_add(1, std::memory_order_relaxed) < 8) {
		LOGF("NON_AUTHENTIC_VIRTUAL_USB_PAD MBus BOND by-id record injected"
		     " device_id=0x%016" PRIx64 " transport=%u class=0x%08x"
		     " remaining_fields=unknown_zero\n",
		     device_id, HostInput::BOND_USB_TRANSPORT, HostInput::BOND_CLASS);
	}
	return 0;
}

LIB_DEFINE(InitMbus_1) {
	if (HostInputBridgeEnabled() || VirtualUsbPadEnabled()) {
		LIB_FUNC("KRL-S9qBqXw", MbusGetDeviceInfoByCondition);
	}
	if (VirtualUsbPadEnabled()) LIB_FUNC("RsKVKhSWt28", MbusGetDeviceInfoById);
	if (UninitializedGuardEnabled()) {
		LIB_FUNC("DOFWwhLN09E", MbusSetVolumeDownGuard);
	}
}

} // namespace Libs::Mbus
