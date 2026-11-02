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
constexpr uint32_t CONTROLLER_CLASS      = 0x0d;
constexpr uint32_t CONTROLLER_SUBTYPE    = 1;
constexpr uint32_t CONTROLLER_ASSIGNMENT = 0xff;
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
} // namespace Libs::Mbus::HostInput
#endif /* EMULATOR_INCLUDE_EMULATOR_LIBS_HOSTINPUTMBUS_H_ */
