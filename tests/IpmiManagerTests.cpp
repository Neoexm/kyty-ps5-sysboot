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
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace {
thread_local int test_pid = 101;
}
namespace Log {
}
namespace Libs::Posix {
int* GetErrorAddr() { static thread_local int error = 0; return &error; }
}
namespace Libs::LibKernel::Process {
int GetPid() { return test_pid; }
}
namespace Libs::LibKernel::AppMount {
}
namespace Libs::LibKernel::Budget {
bool Ptype(int pid, int32_t* ptype) { (void)pid; (void)ptype; return false; }
}
namespace Libs::LibKernel::Memory {
}

namespace Libs::LibKernel {
}

namespace Libs::Jemspace {
}
#else
int main() { std::puts("IpmiManagerTests: Windows shared transport required"); }
#endif
