#ifndef EMULATOR_INCLUDE_EMULATOR_LIBS_LIBMBUS_H_
#define EMULATOR_INCLUDE_EMULATOR_LIBS_LIBMBUS_H_

#include "common/common.h"

namespace Loader {
class SymbolDatabase;
}

namespace Libs::Mbus {

void InitMbus_1(Loader::SymbolDatabase* s);
void SetOriginalGetDeviceInfoByCondition(uint64_t address);
void SetOriginalSetVolumeDown(uint64_t address, uint64_t client_slot);

} // namespace Libs::Mbus

#endif /* EMULATOR_INCLUDE_EMULATOR_LIBS_LIBMBUS_H_ */
