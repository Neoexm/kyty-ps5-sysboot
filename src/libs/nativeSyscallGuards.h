#ifndef KYTY_EMULATOR_LIBS_NATIVE_SYSCALL_GUARDS_H_
#define KYTY_EMULATOR_LIBS_NATIVE_SYSCALL_GUARDS_H_
namespace Loader {
class SymbolDatabase;
}
namespace Libs::NativeSyscallGuards {
void Register(Loader::SymbolDatabase* symbols);
}
#endif
