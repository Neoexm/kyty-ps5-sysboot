#include "kernel/execProcess.h"

#include <cstdio>
#include <cstdlib>

namespace {
void Check(bool value, const char* text) {
	if (!value) { std::fprintf(stderr, "RebootDispatchTests: %s\n", text); std::abort(); }
}
}

int main() {
	using Libs::LibKernel::Process::ClassifyMiniSyscoreRebootOptions;

	uint32_t kind = 0xff;
	uint32_t exit_code = 0xff;

	ClassifyMiniSyscoreRebootOptions(0x4000, &kind, &exit_code);
	Check(kind == 0 && exit_code == 0, "RB_POWEROFF -> kind=0 exit=0");

	ClassifyMiniSyscoreRebootOptions(0x50000000, &kind, &exit_code);
	Check(kind == 1 && exit_code == 1, "Sony safe-mode -> kind=1 exit=1");

	ClassifyMiniSyscoreRebootOptions(0, &kind, &exit_code);
	Check(kind == 2 && exit_code == 2, "RB_AUTOBOOT -> kind=2 exit=2");

	ClassifyMiniSyscoreRebootOptions(0xdeadbeef, &kind, &exit_code);
	Check(kind == 3 && exit_code == 1, "unknown options -> kind=3 exit=1");

	ClassifyMiniSyscoreRebootOptions(0x4001, &kind, &exit_code);
	Check(kind == 3, "near-miss on RB_POWEROFF stays OTHER");

	ClassifyMiniSyscoreRebootOptions(0x50000001, &kind, &exit_code);
	Check(kind == 3, "near-miss on Sony safe-mode stays OTHER");

	ClassifyMiniSyscoreRebootOptions(0x4000, nullptr, nullptr);

	return 0;
}
