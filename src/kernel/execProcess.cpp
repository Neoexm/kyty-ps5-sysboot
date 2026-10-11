#include "kernel/execProcess.h"

#include "common/assert.h"
#include "common/logging/log.h"
#include "common/stringUtils.h"
#include "emulator.h"
#include "kernel/authInfo.h"
#include "kernel/fileSystem.h"
#include "kernel/process.h"
#include "kernel/pthread.h"
#include "libs/errno.h"
#include "loader/elf.h"
#include "loader/jit.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string_view>
#include <thread>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#include <crtdbg.h>
#endif
namespace Libs::LibKernel::Process {
namespace {
using Json = nlohmann::json;
Json                     g_child_request;
bool                     g_exec_child = false;
bool SameHostPath(const std::filesystem::path& first, const std::filesystem::path& second) {
	if (first.empty() || second.empty()) return false;
	std::error_code first_error;
	std::error_code second_error;
	const auto      first_actual  = std::filesystem::weakly_canonical(first, first_error);
	const auto      second_actual = std::filesystem::weakly_canonical(second, second_error);
	if (first_error || second_error) return false;
#if defined(_WIN32)
	return Common::EqualNoCase(Common::PathToGenericString(first_actual),
	                           Common::PathToGenericString(second_actual));
#else
	return first_actual == second_actual;
#endif
}
} // namespace
bool IsExecChildImagePath(const std::filesystem::path& host_path) {
	if (!g_exec_child) return false;
	try {
		if (g_child_request.value("app0_elf", std::string {}).empty()) return false;
		return SameHostPath(
		    host_path, std::filesystem::u8path(g_child_request.at("host_path").get<std::string>()));
	} catch (...) {
		return false;
	}
}
std::string GetExecChildSandboxWord() {
	if (!g_exec_child) return {};
	return g_child_request.value("sandbox_word", std::string {});
}
} // namespace Libs::LibKernel::Process
