#include "kernel/process.h"

#include "common/assert.h"
#include "common/logging/log.h"
#include "kernel/budget.h"
#include "kernel/fileSystem.h"
#include "kernel/eventQueue.h"
#include "kernel/execProcess.h"
#include "kernel/memory.h"
#include "loader/elf.h"
#include "loader/systemContent.h"
#include "libs/errno.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fmt/format.h>
#include <fstream>
#include <limits>
#include <memory>
#include <optional>
#include <thread>

#if defined(_WIN32)
#include <windows.h>
#include <sddl.h>
#pragma comment(lib, "advapi32.lib")
#else
#include <unistd.h>
#endif
namespace Libs::LibKernel::Process {
namespace {
thread_local int g_thread_guest_pid = 0;
} // namespace
int GetPid() {
	if (g_thread_guest_pid != 0) {
		return g_thread_guest_pid;
	}
	static const int pid = [] {
		const char* value = std::getenv("KYTY_DIAGNOSTIC_GUEST_PID");
		return value != nullptr ? std::atoi(value) : 100;
	}();
	return pid;
}
} // namespace Libs::LibKernel::Process
