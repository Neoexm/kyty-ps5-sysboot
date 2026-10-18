#include "kernel/ipmiManager.h"
#include "kernel/ipmiScope.h"
#include "kernel/memory.h"
#include "kernel/process.h"
#include "libs/errno.h"
#include "common/logging/log.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <future>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <windows.h>

namespace {
thread_local int test_pid = 101;
}
namespace Libs::LibKernel::Process {
int GetPid() { return test_pid; }
}
#else
#endif
