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
bool                     g_exec_child = false;
} // namespace
} // namespace Libs::LibKernel::Process
