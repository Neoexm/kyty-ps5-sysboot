#ifndef EMULATOR_INCLUDE_EMULATOR_LIBS_HOSTINPUTMBUS_H_
#define EMULATOR_INCLUDE_EMULATOR_LIBS_HOSTINPUTMBUS_H_

#include "libs/controller.h"

#include <array>
#include <cstdint>
#include <cstring>

namespace Libs::Mbus::HostInput {

constexpr size_t   RECORD_SIZE = 0x100;
constexpr uint64_t VIRTUAL_DEVICE_ID =
    static_cast<uint64_t>(static_cast<int64_t>(Controller::HOST_INPUT_CONTROLLER_ID));
constexpr int      VIRTUAL_DEVICE_TYPE   = 16;
constexpr uint32_t CONTROLLER_CLASS      = 0x0d;
constexpr uint32_t CONTROLLER_SUBTYPE    = 1;
constexpr uint32_t CONTROLLER_ASSIGNMENT = 0xff;
constexpr uint64_t VIRTUAL_BOND_DEVICE_ID = static_cast<uint64_t>(static_cast<int64_t>(-1001));
constexpr uint32_t BOND_USB_TRANSPORT    = 0;
constexpr uint32_t BOND_CLASS            = 0x16;

inline bool IsPadDeviceOpenRequest(uint64_t device_id, int type, int index) {
	return device_id == VIRTUAL_DEVICE_ID && type == VIRTUAL_DEVICE_TYPE && index == 0;
}

inline std::array<uint8_t, RECORD_SIZE> ControllerCondition() {
	std::array<uint8_t, RECORD_SIZE> condition {};
	std::memset(condition.data(), 0xff, 12);
	std::memcpy(condition.data() + 0x0c, &CONTROLLER_CLASS, sizeof(CONTROLLER_CLASS));
	const uint32_t any_assignment = 0xffffffff;
	std::memcpy(condition.data() + 0xc8, &any_assignment, sizeof(any_assignment));
	return condition;
}

inline bool IsControllerCondition(const void* condition) {
	if (condition == nullptr) return false;
	const auto expected = ControllerCondition();
	return std::memcmp(condition, expected.data(), expected.size()) == 0;
}

inline void FillControllerRecord(void* output) {
	std::memset(output, 0, RECORD_SIZE);
	auto* bytes = static_cast<uint8_t*>(output);
	std::memcpy(bytes, &VIRTUAL_DEVICE_ID, sizeof(VIRTUAL_DEVICE_ID));
	std::memcpy(bytes + 0x0c, &CONTROLLER_CLASS, sizeof(CONTROLLER_CLASS));
	std::memcpy(bytes + 0x10, &CONTROLLER_SUBTYPE, sizeof(CONTROLLER_SUBTYPE));
	std::memcpy(bytes + 0xc8, &CONTROLLER_ASSIGNMENT, sizeof(CONTROLLER_ASSIGNMENT));
}

inline std::array<uint8_t, RECORD_SIZE> AllDeviceCondition() {
	std::array<uint8_t, RECORD_SIZE> condition {};
	std::memset(condition.data(), 0xff, 16);
	const uint32_t any = 0xffffffffu;
	for (const size_t offset: {size_t {0x18}, size_t {0x28}, size_t {0x38}, size_t {0x48},
	                           size_t {0x58}, size_t {0x68}, size_t {0x78}, size_t {0x88},
	                           size_t {0x98}, size_t {0xa8}, size_t {0xb8}}) {
		std::memcpy(condition.data() + offset, &any, sizeof(any));
	}
	std::memcpy(condition.data() + 0xc8, &any, sizeof(any));
	return condition;
}

inline bool IsAllDeviceCondition(const void* condition) {
	if (condition == nullptr) return false;
	const auto expected = AllDeviceCondition();
	return std::memcmp(condition, expected.data(), expected.size()) == 0;
}

inline bool IsBondDeviceLookup(uint64_t device_id, const void* output, uint32_t record_size) {
	return device_id == VIRTUAL_BOND_DEVICE_ID && output != nullptr && record_size == RECORD_SIZE;
}

inline void FillBondUsbRecord(void* output) {
	std::memset(output, 0, RECORD_SIZE);
	auto* bytes = static_cast<uint8_t*>(output);
	std::memcpy(bytes, &VIRTUAL_BOND_DEVICE_ID, sizeof(VIRTUAL_BOND_DEVICE_ID));
	std::memcpy(bytes + 0x08, &BOND_USB_TRANSPORT, sizeof(BOND_USB_TRANSPORT));
	std::memcpy(bytes + 0x0c, &BOND_CLASS, sizeof(BOND_CLASS));
}

inline bool AppendBondUsbRecord(void* output, int result, int capacity, int* total,
                                int* remaining, uint32_t record_size) {
	if (output == nullptr || total == nullptr || remaining == nullptr ||
	    record_size != RECORD_SIZE || result < 0 || result >= capacity || *total != result ||
	    *remaining != 0) {
		return false;
	}
	FillBondUsbRecord(static_cast<uint8_t*>(output) + static_cast<size_t>(result) * RECORD_SIZE);
	*total     = result + 1;
	*remaining = 0;
	return true;
}

} // namespace Libs::Mbus::HostInput

#endif /* EMULATOR_INCLUDE_EMULATOR_LIBS_HOSTINPUTMBUS_H_ */
