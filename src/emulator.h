#ifndef EMULATOR_INCLUDE_EMULATOR_EMULATOR_H_
#define EMULATOR_INCLUDE_EMULATOR_EMULATOR_H_

#include "common/emulatorConfig.h"
#include "common/stringUtils.h"

#include <filesystem>
#include <string>

namespace Emulator {

struct RunOptions {
	Config::ConfigOptions config;
	std::filesystem::path app0_dir;
	std::filesystem::path sysroot_dir;
	std::filesystem::path elf;
	std::filesystem::path game_patch;
	std::string           exec_endpoint;
};

void Run(const RunOptions& options);

} // namespace Emulator

#endif /* EMULATOR_INCLUDE_EMULATOR_EMULATOR_H_ */
