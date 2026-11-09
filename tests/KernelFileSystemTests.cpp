#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <SDL3/SDL.h>
#include <SDL3/SDL_main.h>

#include "common/emulatorConfig.h"
#include "common/archive.h"
#include "common/file.h"
#include "common/hostException.h"
#include "ArchiveTestFixture.h"
#include "common/logging/log.h"
#include "common/singleton.h"
#include "common/subsystems.h"
#include "common/threads.h"
#include "common/stringUtils.h"
#include "emulator.h"
#include "graphics/guest_gpu/graphicsRun.h"
#include "graphics/host_gpu/renderer/renderContext.h"
#include "graphics/presentation/videoOut.h"
#include "graphics/presentation/window/windowInternal.h"
#include "kernel/appMount.h"
#include "kernel/budget.h"
#include "kernel/eventQueue.h"
#include "kernel/eventFlag.h"
#include "kernel/envelopeConsoleProvider.h"
#include "kernel/envelopeConsoleProviderProtocol.h"
#include "kernel/envelopeSecureProcessor.h"
#include "kernel/envelopeLocalBackend.h"
#include "kernel/execProcess.h"
#include "kernel/fileSystem.h"
#include "kernel/capturedRootMetadata.h"
#include "kernel/capturedDirectory.h"
#include "kernel/ipmiManager.h"
#include "kernel/ipmiScope.h"
#include "kernel/memory.h"
#include "kernel/pthread.h"
#include "kernel/process.h"
#include "kernel/regMgr.h"
#include "kernel/semaphore.h"
#include "kernel/socketPolicy.h"
#include "kernel/sectorBacking.h"
#include "kernel/exfatMount.h"
#include "kernel/directoryPassthrough.h"
#include "kernel/nullfsMount.h"
#include "ExfatTestFixture.h"
#include <fstream>
#include "kernel/tmpfs.h"
#include "libs/errno.h"
#include "libs/audio.h"
#include "libs/nativeKernelBridge.h"
#include "libs/network.h"
#include "kernel/authInfo.h"
#include "loader/decryptedModuleOverlay.h"
#include "loader/elf.h"
#include "loader/runtimeLinker.h"
#include "loader/symbolDatabase.h"
#include "loader/systemContent.h"

#include <algorithm>
#include <array>
#include <atomic>

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <future>
#include <iomanip>
#include <iterator>
#include <limits>
#include <memory>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#include <psapi.h>
#endif

namespace Libs::LibKernelApr {
void InitLibKernel_1_Apr(Loader::SymbolDatabase *symbols);
}

namespace Libs::LibKernel {
struct KernelLoadModuleOpt;
void ResetGuestSigactionForTesting();
bool IsPsmNativeAotMscorlibOnlyRequest(const char* module_file_name, size_t args,
                                       const void* argp, uint32_t flags,
                                       const KernelLoadModuleOpt* opt, const int* res);
}

namespace Libs {
void InitAll(Loader::SymbolDatabase *symbols);
void InitUserService_1(Loader::SymbolDatabase* symbols);
void InitLibKernel_1(Loader::SymbolDatabase *symbols);
void InitSysmodule_1(Loader::SymbolDatabase *symbols);
void InitJemspace_1(Loader::SymbolDatabase* symbols);
int KYTY_SYSV_ABI KernelGetAppInfo(int pid, void* info);
int KYTY_SYSV_ABI KernelGetAppInfo2(int pid, void* info, size_t size);
int KYTY_SYSV_ABI KernelGetAppCategoryType(int pid, int* category);
int KYTY_SYSV_ABI KernelGetAuthinfo(int pid, void* info);
int KYTY_SYSV_ABI KernelBeginAppMount2(void* info, uint64_t arg1, uint64_t arg2);
int KYTY_SYSV_ABI KernelSetAppState(int32_t app_id, uint32_t state);
int KYTY_SYSV_ABI KernelGetAppState(int32_t app_id, int32_t* state, int32_t* secondary);
int KYTY_SYSV_ABI KernelGetAppInfoByAppId(int32_t app_id, void* info);
int KYTY_SYSV_ABI KernelCreateBudget(int64_t* id, const char* name, uint32_t ptype, const void* entries, uint32_t count, void* out_entries);
int KYTY_SYSV_ABI KernelDeleteBudget(int32_t budget);
int KYTY_SYSV_ABI KernelGetResourceLimit(uint32_t ptype, void* entries, int32_t* count);
int KYTY_SYSV_ABI KernelGetResourceOne(int32_t budget, uint32_t kind, void* entry);
}

namespace Libs::NativeSyscallGuards {
int KYTY_SYSV_ABI KernelGetBudget(int64_t* out);
int KYTY_SYSV_ABI KernelSetBudget(int id);
}

namespace Libs::Jemspace {
bool ContainsAllocation(const void* pointer, uint64_t size);
bool QueryAllocation(const void* pointer, uint64_t size, uint64_t* offset_out,
                     uint64_t* allocation_size_out);
bool CopyToAllocation(void* destination, const void* source, uint64_t size);
bool CopyFromAllocation(void* destination, const void* source, uint64_t size);
}

namespace Libs::LibAmpr {
void InitAmpr_1(Loader::SymbolDatabase *symbols);
}

namespace Libs::LibNet {
void InitNet_1_Net(Loader::SymbolDatabase *symbols);
}

namespace Libs::LibNpWebApi2 {
void InitNet_1_NpWebApi2(Loader::SymbolDatabase *symbols);
}

namespace Libs::LibJson2 {
void InitNet_1_Json2(Loader::SymbolDatabase *symbols);
}

namespace Libs::LibAudioOut {
void InitAudio_1_AudioOut(Loader::SymbolDatabase* symbols);
}

namespace Libs::LibC {
void InitLibC_1(Loader::SymbolDatabase* symbols);
}

namespace Libs::LibcInternalExt {
void InitLibcInternalExt_1(Loader::SymbolDatabase* symbols);
}

namespace {

namespace FileSystem = Libs::LibKernel::FileSystem;

void Check(bool value, const char *text) {
  if (!value) {
    std::fprintf(stderr, "KernelFileSystemTests: failed: %s\n", text);
    std::abort();
  }
}

void CheckGuestSigactionContract() {
  struct Action {
    uint64_t handler;
    uint32_t flags;
    uint32_t mask[4];
    uint32_t padding;
  };
  static_assert(offsetof(Action, handler) == 0);
  static_assert(offsetof(Action, flags) == 8);
  static_assert(offsetof(Action, mask) == 12);
  static_assert(sizeof(Action) == 32);

  using Sigaction = int (KYTY_SYSV_ABI *)(int, const Action*, Action*);
  Libs::LibKernel::ResetGuestSigactionForTesting();
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_MONO_SIGNAL_TABLE", "") == 0,
        "clear obsolete signal-table gate");
#else
  Check(unsetenv("KYTY_DIAGNOSTIC_MONO_SIGNAL_TABLE") == 0,
        "clear obsolete signal-table gate");
#endif
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* symbol = symbols.FindByNid("KiJEPEWRyUY", Loader::SymbolType::Func);
  Check(symbol != nullptr, "public sigaction export resolves without a diagnostic gate");
  const auto sigaction = reinterpret_cast<Sigaction>(symbol->vaddr);

  const Action zero {};
  for (int signum = 66; signum <= 125; ++signum) {
    Action previous {};
    std::memset(&previous, 0xcd, sizeof(previous));
    *Libs::Posix::GetErrorAddr() = Libs::Posix::POSIX_EBUSY;
    Check(sigaction(signum, nullptr, &previous) == 0 &&
              std::memcmp(&previous, &zero, sizeof(zero)) == 0 &&
              *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EBUSY,
          "realtime signal candidates begin with default dispositions");
  }

  std::array<int, 3> selected {};
  for (size_t reservation = 0; reservation < selected.size(); ++reservation) {
    for (int signum = 66; signum <= 125; ++signum) {
      Action previous {};
      Check(sigaction(signum, nullptr, &previous) == 0,
            "query realtime signal candidate");
      if (previous.handler != 0) continue;
      Action requested {0x10000u + reservation * 0x100u, 0x42,
                        {0x10203040u, 0x50607080u, 0x90a0b0c0u, 0xd0e0f000u},
                        0x55667788u};
      Check(sigaction(signum, &requested, nullptr) == 0,
            "reserve realtime signal candidate");
      selected[reservation] = signum;
      break;
    }
  }
  Check(selected == std::array<int, 3> {66, 67, 68},
        "reservation algorithm selects independent signals 66 through 68");

  Action first {};
  Check(sigaction(66, nullptr, &first) == 0 && first.handler == 0x10000u &&
            first.flags == 0x42 && first.mask[2] == 0x90a0b0c0u &&
            first.padding == 0x55667788u,
        "query returns the exact installed public action");
  const Action replacement {0x2233445566778800ull, 0x2, {1, 2, 3, 4}, 0xaabbccddu};
  Action replaced {};
  Check(sigaction(66, &replacement, &replaced) == 0 &&
            std::memcmp(&replaced, &first, sizeof(first)) == 0,
        "replacement returns the previous public action");

  for (const int signum: {3, 8, 11}) {
    Action action {0x20000u + static_cast<uint64_t>(signum), 0x42,
                   {0xf, 0xe, 0xd, 0xc}, static_cast<uint32_t>(signum)};
    Action previous {};
    Action queried {};
    Check(sigaction(signum, &action, &previous) == 0 &&
              std::memcmp(&previous, &zero, sizeof(zero)) == 0 &&
              sigaction(signum, nullptr, &queried) == 0 &&
              std::memcmp(&queried, &action, sizeof(action)) == 0,
          "synchronous signal dispositions retain exact public state");
  }

  Check(sigaction(70, nullptr, nullptr) == 0,
        "valid null action and null previous pointer is a no-op");
  for (const int signum: {0, 32, 129}) {
    Action untouched {};
    std::memset(&untouched, 0x5a, sizeof(untouched));
    const Action expected = untouched;
    *Libs::Posix::GetErrorAddr() = 0;
    Check(sigaction(signum, nullptr, &untouched) == -1 &&
              *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL &&
              std::memcmp(&untouched, &expected, sizeof(expected)) == 0,
          "invalid signal rejects without changing output");
  }

  Action before_bad_input {};
  Check(sigaction(71, nullptr, &before_bad_input) == 0,
        "capture state before bad action pointer");
  *Libs::Posix::GetErrorAddr() = 0;
  Check(sigaction(71, reinterpret_cast<const Action*>(1), nullptr) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT,
        "bad requested-action pointer returns EFAULT");
  Action after_bad_input {};
  Check(sigaction(71, nullptr, &after_bad_input) == 0 &&
            std::memcmp(&after_bad_input, &before_bad_input, sizeof(after_bad_input)) == 0,
        "bad requested-action pointer does not mutate state");

  const Action committed {0x70000u, 0x42, {7, 7, 7, 7}, 7};
  *Libs::Posix::GetErrorAddr() = 0;
  Check(sigaction(72, &committed, reinterpret_cast<Action*>(1)) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT,
        "bad previous-action pointer returns EFAULT after commit");
  Action after_bad_output {};
  Check(sigaction(72, nullptr, &after_bad_output) == 0 &&
            std::memcmp(&after_bad_output, &committed, sizeof(committed)) == 0,
        "failed previous-action copyout retains the committed action");

  const Action forbidden {0x90000u, 0x42, {}, 0};
  for (const int signum: {9, 17}) {
    *Libs::Posix::GetErrorAddr() = 0;
    Check(sigaction(signum, &forbidden, nullptr) == -1 &&
              *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
          "uncatchable signal rejects a caught disposition");
    Action queried {};
    Check(sigaction(signum, nullptr, &queried) == 0 &&
              std::memcmp(&queried, &zero, sizeof(zero)) == 0,
          "uncatchable signal rejection preserves default disposition");
  }
  const Action bad_flags {0x91000u, 0x80000000u, {}, 0};
  *Libs::Posix::GetErrorAddr() = 0;
  Check(sigaction(73, &bad_flags, nullptr) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
        "unsupported caught-action flags are rejected");

  Libs::LibKernel::ResetGuestSigactionForTesting();
  const Action concurrent_a {0xa0000u, 0x42, {1, 1, 1, 1}, 1};
  const Action concurrent_b {0xb0000u, 0x42, {2, 2, 2, 2}, 2};
  Action old_a {};
  Action old_b {};
  int result_a = -1;
  int result_b = -1;
  std::atomic<int> ready {0};
  std::atomic<bool> go {false};
  auto replace = [&](Action action, Action* output, int* result) {
    Action local_previous {};
    ready.fetch_add(1, std::memory_order_release);
    while (!go.load(std::memory_order_acquire)) std::this_thread::yield();
    *result = sigaction(80, &action, &local_previous);
    *output = local_previous;
  };
  std::thread thread_a(replace, concurrent_a, &old_a, &result_a);
  std::thread thread_b(replace, concurrent_b, &old_b, &result_b);
  while (ready.load(std::memory_order_acquire) != 2) std::this_thread::yield();
  go.store(true, std::memory_order_release);
  thread_a.join();
  thread_b.join();
  Action final {};
  Check(result_a == 0 && result_b == 0 && sigaction(80, nullptr, &final) == 0,
        "concurrent replacements complete through the public export");
  const bool a_then_b = std::memcmp(&old_a, &zero, sizeof(zero)) == 0 &&
                        std::memcmp(&old_b, &concurrent_a, sizeof(old_b)) == 0 &&
                        std::memcmp(&final, &concurrent_b, sizeof(final)) == 0;
  const bool b_then_a = std::memcmp(&old_b, &zero, sizeof(zero)) == 0 &&
                        std::memcmp(&old_a, &concurrent_b, sizeof(old_a)) == 0 &&
                        std::memcmp(&final, &concurrent_a, sizeof(final)) == 0;
  Check(a_then_b || b_then_a,
        "concurrent replacements expose one serializable previous-action chain");

  Libs::LibKernel::ResetGuestSigactionForTesting();
  Action reset {};
  Check(sigaction(66, nullptr, &reset) == 0 &&
            std::memcmp(&reset, &zero, sizeof(reset)) == 0,
        "second in-process guest fixture starts with clean disposition state");
}

void CheckPosixSemSetnameContract() {
  namespace Kernel = Libs::LibKernel;
  struct GuestSem {
    uint16_t magic;
    uint16_t name_id;
    uint32_t waiters;
    uint32_t count;
    uint32_t flags;
  };
  static_assert(sizeof(GuestSem) == 16);

  using Init = int (KYTY_SYSV_ABI *)(void*, int, unsigned int);
  using Setname = int (KYTY_SYSV_ABI *)(void*, const char*);
  using Destroy = int (KYTY_SYSV_ABI *)(void*);
  using Wait = int (KYTY_SYSV_ABI *)(void*);
  using Trywait = int (KYTY_SYSV_ABI *)(void*);
  using Post = int (KYTY_SYSV_ABI *)(void*);
  using Getvalue = int (KYTY_SYSV_ABI *)(void*, int*);
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_MONO_SEM_SETNAME", "") == 0,
        "clear obsolete sem_setname gate");
#else
  Check(unsetenv("KYTY_DIAGNOSTIC_MONO_SEM_SETNAME") == 0,
        "clear obsolete sem_setname gate");
#endif
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto resolve = [&](const char* nid) {
    const auto* symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "POSIX semaphore public export resolves");
    return symbol->vaddr;
  };
  const auto sem_init = reinterpret_cast<Init>(resolve("pDuPEf3m4fI"));
  const auto sem_setname = reinterpret_cast<Setname>(resolve("-wUggz2S5yk"));
  const auto sem_destroy = reinterpret_cast<Destroy>(resolve("cDW233RAwWo"));
  const auto sem_wait = reinterpret_cast<Wait>(resolve("YCV5dGGBcCo"));
  const auto sem_trywait = reinterpret_cast<Trywait>(resolve("WBWzsRifCEA"));
  const auto sem_post = reinterpret_cast<Post>(resolve("IKP8typ0QUk"));
  const auto sem_getvalue = reinterpret_cast<Getvalue>(resolve("Bq+LRV-N6Hk"));

  void* mapping = nullptr;
  Check(Kernel::Memory::KernelMapNamedFlexibleMemory(
            &mapping, 0x8000, 3, 0, "posix_sem_setname_fixture") == OK,
        "map POSIX semaphore guest fixture");
  auto* bytes = static_cast<uint8_t*>(mapping);
  std::memset(bytes, 0, 0x8000);
  auto* first = reinterpret_cast<GuestSem*>(bytes + 0x000);
  auto* second = reinterpret_cast<GuestSem*>(bytes + 0x020);
  auto* third = reinterpret_cast<GuestSem*>(bytes + 0x040);
  auto* fourth = reinterpret_cast<GuestSem*>(bytes + 0x060);
  auto* raced = reinterpret_cast<GuestSem*>(bytes + 0x080);
  auto* forged = reinterpret_cast<GuestSem*>(bytes + 0x0a0);
  auto* rejected = reinterpret_cast<GuestSem*>(bytes + 0x0c0);
  auto* unnamed = reinterpret_cast<GuestSem*>(bytes + 0x0e0);
  auto* duplicate = reinterpret_cast<GuestSem*>(bytes + 0x100);
  auto* hidden = reinterpret_cast<GuestSem*>(bytes + 0x4000);
  auto put_name = [&](size_t offset, const char* text) {
    const size_t length = std::strlen(text) + 1;
    Check(offset + length < 0x4000, "POSIX semaphore name fits readable page");
    std::memcpy(bytes + offset, text, length);
    return reinterpret_cast<const char*>(bytes + offset);
  };
  const char* global_suspend = put_name(0x1000, "__global_suspend");
  const char* suspend = put_name(0x1040, "__suspend");
  const char* finalizer = put_name(0x1080, "__gc_finalizer");
  const char* replacement = put_name(0x10c0, "replacement");
  const char* race_a = put_name(0x1100, "race_a");
  const char* race_b = put_name(0x1140, "race_b");

  Libs::Posix::PosixSemNameSnapshot baseline {};
  Check(!Libs::Posix::PosixSemNameSnapshotForTesting(nullptr, &baseline),
        "untracked POSIX semaphore has no snapshot");
  Check(baseline.live_names == baseline.allocated_ids,
        "baseline metadata rows and allocated ID bitmap agree");

  *Libs::Posix::GetErrorAddr() = Libs::Posix::POSIX_EBUSY;
  Check(sem_init(first, 0, 1) == 0 && first->magic == 0x736d &&
            first->name_id == 0xffff && first->waiters == 0 &&
            first->count == 1 && first->flags == 0 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EBUSY,
        "sem_init writes exact native unnamed ABI without changing errno");
  Check(sem_init(second, 7, 0) == 0 && second->magic == 0x736d &&
            second->name_id == 0xffff && second->count == 0 && second->flags == 1,
        "sem_init normalizes pshared in the native public image");
  std::memset(rejected, 0xa5, sizeof(*rejected));
  *Libs::Posix::GetErrorAddr() = 0;
  Check(sem_init(rejected, 0, 0x80000000u) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL &&
            std::all_of(reinterpret_cast<uint8_t*>(rejected),
                        reinterpret_cast<uint8_t*>(rejected) + sizeof(*rejected),
                        [](uint8_t byte) { return byte == 0xa5; }),
        "sem_init rejects values above native SEM_VALUE_MAX without mutation");
  const GuestSem rejected_state = *rejected;
  *Libs::Posix::GetErrorAddr() = 0;
  Check(sem_setname(rejected, global_suspend) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL &&
            std::memcmp(rejected, &rejected_state, sizeof(rejected_state)) == 0,
        "untracked mapped semaphore pointer is rejected without mutation");
  *Libs::Posix::GetErrorAddr() = 0;
  Check(sem_setname(nullptr, global_suspend) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL &&
            sem_setname(reinterpret_cast<void*>(1), global_suspend) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL &&
            sem_setname(bytes + 0x9000, global_suspend) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL &&
            sem_setname(reinterpret_cast<void*>(UINT64_MAX - 7), global_suspend) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
        "null, low, unmapped and wrapping semaphore pointers are bounded before dereference");

  *Libs::Posix::GetErrorAddr() = Libs::Posix::POSIX_EBUSY;
  Check(sem_setname(first, global_suspend) == 0 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EBUSY,
        "historical global suspend label installs through public export");
  Libs::Posix::PosixSemNameSnapshot first_named {};
  Check(Libs::Posix::PosixSemNameSnapshotForTesting(first, &first_named) &&
            first_named.name_id != 0 && first_named.name_id != 0xffff &&
            first_named.name_id == first->name_id && first_named.name_length == 16 &&
            first_named.live_names == baseline.live_names + 1 &&
            first_named.allocated_ids == baseline.allocated_ids + 1,
        "sem_setname commits one bounded ID-backed metadata record");
  int value = -1;
  Check(sem_getvalue(first, &value) == 0 && value == 1 &&
            sem_post(first) == 0 && sem_trywait(first) == 0 &&
            sem_getvalue(first, &value) == 0 && value == 1 &&
            first->name_id == first_named.name_id,
        "count operations preserve installed semaphore name ID");

  *Libs::Posix::GetErrorAddr() = 0;
  Check(sem_setname(first, reinterpret_cast<const char*>(1)) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EAGAIN &&
            first->name_id == first_named.name_id,
        "already-named check precedes an invalid name pointer");
  const GuestSem first_before_rename = *first;
  const auto first_snapshot_before_rename = first_named;
  *Libs::Posix::GetErrorAddr() = 0;
  Check(sem_setname(first, replacement) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EAGAIN,
        "different valid string cannot rename an already-named semaphore");
  Libs::Posix::PosixSemNameSnapshot first_snapshot_after_rename {};
  Check(Libs::Posix::PosixSemNameSnapshotForTesting(first, &first_snapshot_after_rename) &&
            std::memcmp(first, &first_before_rename, sizeof(first_before_rename)) == 0 &&
            first_snapshot_after_rename.name_id == first_snapshot_before_rename.name_id &&
            first_snapshot_after_rename.name_length == first_snapshot_before_rename.name_length &&
            first_snapshot_after_rename.name_digest == first_snapshot_before_rename.name_digest &&
            first_snapshot_after_rename.live_names == first_snapshot_before_rename.live_names &&
            first_snapshot_after_rename.allocated_ids == first_snapshot_before_rename.allocated_ids,
        "failed rename preserves the full public record and metadata snapshot");
  Check(sem_setname(second, suspend) == 0 && second->name_id != 0xffff,
        "historical suspend label names an independent semaphore");

  Check(sem_init(third, 0, 0) == 0, "initialize pointer-safety semaphore");
  const GuestSem third_unnamed = *third;
  *Libs::Posix::GetErrorAddr() = 0;
  Check(sem_setname(third, nullptr) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT &&
            std::memcmp(third, &third_unnamed, sizeof(third_unnamed)) == 0,
        "null name returns bounded EFAULT without state mutation");
  std::memset(bytes + 0x1800, 'x', 32);
  *Libs::Posix::GetErrorAddr() = 0;
  Check(sem_setname(third, reinterpret_cast<const char*>(bytes + 0x1800)) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENAMETOOLONG &&
            std::memcmp(third, &third_unnamed, sizeof(third_unnamed)) == 0,
        "unterminated name meets the documented emulator safety boundary");
  std::memset(bytes + 0x3ff0, 'g', 16);
  Check(sem_init(hidden, 0, 0) == 0, "initialize tracked inaccessible semaphore fixture");
  const GuestSem hidden_unnamed = *hidden;
  Check(Kernel::Memory::KernelMprotect(bytes + 0x4000, 0x4000, 0) == OK,
        "protect adjacent guest page for name boundary fixture");
  *Libs::Posix::GetErrorAddr() = 0;
  Check(sem_setname(third, reinterpret_cast<const char*>(bytes + 0x3ff0)) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT &&
            std::memcmp(third, &third_unnamed, sizeof(third_unnamed)) == 0,
        "guard-crossing name returns EFAULT without host overread");
  Check(Kernel::Memory::KernelMprotect(bytes + 0x4000, 0x4000, 1) == OK,
        "make tracked semaphore readable but not writable for commit rollback");
  Libs::Posix::PosixSemNameSnapshot before_hidden_failure {};
  Check(Libs::Posix::PosixSemNameSnapshotForTesting(hidden, &before_hidden_failure),
        "capture allocator state before inaccessible semaphore commit");
  *Libs::Posix::GetErrorAddr() = 0;
  Check(sem_setname(hidden, finalizer) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT,
        "tracked no-access semaphore rejects the final ID commit safely");
  Libs::Posix::PosixSemNameSnapshot after_hidden_failure {};
  Check(Libs::Posix::PosixSemNameSnapshotForTesting(hidden, &after_hidden_failure) &&
            after_hidden_failure.live_names == before_hidden_failure.live_names &&
            after_hidden_failure.allocated_ids == before_hidden_failure.allocated_ids,
        "failed inaccessible commit rolls back metadata and allocated ID bitmap");
  Check(Kernel::Memory::KernelMprotect(bytes + 0x4000, 0x4000, 3) == OK &&
            std::memcmp(hidden, &hidden_unnamed, sizeof(hidden_unnamed)) == 0,
        "restore inaccessible semaphore with its full public state unchanged");

  std::atomic<bool> waiter_returned {false};
  int wait_result = -2;
  std::thread blocked_waiter([&] {
    wait_result = sem_wait(third);
    waiter_returned.store(true, std::memory_order_release);
  });
  const auto waiter_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
  while (third->waiters == 0 && std::chrono::steady_clock::now() < waiter_deadline) {
    std::this_thread::yield();
  }
  Check(third->waiters == 1 && sem_setname(third, finalizer) == 0 &&
            third->name_id != 0xffff,
        "valid naming commits while an existing waiter remains blocked");
  std::this_thread::sleep_for(std::chrono::milliseconds(3));
  Check(!waiter_returned.load(std::memory_order_acquire),
        "sem_setname does not wake or satisfy a blocked waiter");
  Check(sem_post(third) == 0, "post releases the blocked waiter");
  blocked_waiter.join();
  Check(wait_result == 0, "blocked waiter returns only after post");

  Check(sem_init(fourth, 0, 0) == 0, "initialize stack-name semaphore");
  char stack_name[] = "stack_label";
  Check(sem_setname(fourth, stack_name) == 0 && fourth->name_id != 0xffff,
        "current host thread stack fallback remains bounded and usable");

  Check(sem_init(forged, 0, 0) == 0, "initialize forged-header semaphore");
  forged->magic = 0x1234;
  *Libs::Posix::GetErrorAddr() = 0;
  Check(sem_setname(forged, replacement) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EAGAIN &&
            forged->name_id == 0xffff,
        "failed native first-dword transition returns EAGAIN without a leaked ID");
  forged->magic = 0x736d;
  Check(sem_setname(forged, replacement) == 0,
        "restored native first word can complete the one-shot transition");

  Check(sem_init(raced, 0, 0) == 0, "initialize concurrent naming semaphore");
  std::array<int, 2> race_results {-2, -2};
  std::array<int, 2> race_errors {};
  std::atomic<int> ready {0};
  std::atomic<bool> go {false};
  auto name_racer = [&](size_t index, const char* name) {
    ready.fetch_add(1, std::memory_order_release);
    while (!go.load(std::memory_order_acquire)) std::this_thread::yield();
    *Libs::Posix::GetErrorAddr() = 0;
    race_results[index] = sem_setname(raced, name);
    race_errors[index] = *Libs::Posix::GetErrorAddr();
  };
  std::thread racer_a(name_racer, 0, race_a);
  std::thread racer_b(name_racer, 1, race_b);
  while (ready.load(std::memory_order_acquire) != 2) std::this_thread::yield();
  go.store(true, std::memory_order_release);
  racer_a.join();
  racer_b.join();
  const bool a_won = race_results[0] == 0 && race_results[1] == -1 &&
                     race_errors[1] == Libs::Posix::POSIX_EAGAIN;
  const bool b_won = race_results[1] == 0 && race_results[0] == -1 &&
                     race_errors[0] == Libs::Posix::POSIX_EAGAIN;
  Libs::Posix::PosixSemNameSnapshot raced_named {};
  Check((a_won || b_won) &&
            Libs::Posix::PosixSemNameSnapshotForTesting(raced, &raced_named) &&
            raced_named.name_id == raced->name_id && raced_named.name_id != 0xffff &&
            raced_named.live_names == baseline.live_names + 6 &&
            raced_named.allocated_ids == baseline.allocated_ids + 6,
        "concurrent naming has one winner, one EAGAIN loser and no metadata leak");

  Check(sem_init(duplicate, 0, 0) == 0 &&
            sem_setname(duplicate, global_suspend) == 0,
        "duplicate text on a distinct semaphore remains independent metadata");
  Libs::Posix::PosixSemNameSnapshot duplicate_named {};
  Check(Libs::Posix::PosixSemNameSnapshotForTesting(duplicate, &duplicate_named) &&
            duplicate_named.name_id != first->name_id &&
            duplicate_named.live_names == baseline.live_names + 7 &&
            duplicate_named.allocated_ids == baseline.allocated_ids + 7,
        "duplicate text receives a distinct live ID without aliasing the object");
  Check(sem_destroy(duplicate) == 0, "destroy duplicate-text semaphore");

  const uint16_t released_id = first->name_id;
  Check(sem_destroy(first) == 0 && first->magic == 0 && first->name_id == released_id,
        "destroy releases metadata and clears only the native magic word");
  Libs::Posix::PosixSemNameSnapshot after_destroy {};
  Check(!Libs::Posix::PosixSemNameSnapshotForTesting(first, &after_destroy) &&
            after_destroy.live_names == baseline.live_names + 5,
        "destroy removes exactly one live name record");
  Check(after_destroy.allocated_ids == baseline.allocated_ids + 5,
        "destroy releases exactly one allocated name ID");
  Check(sem_init(first, 0, 1) == 0 && first->name_id == 0xffff &&
            sem_setname(first, global_suspend) == 0,
        "reinitialized storage starts unnamed and accepts a fresh registration");

  const uint16_t replaced_id = second->name_id;
  Check(sem_init(second, 0, 0) == 0 && second->name_id == 0xffff &&
            second->name_id != replaced_id,
        "reinitialization releases prior metadata and restores unnamed state");
  Check(sem_setname(second, suspend) == 0,
        "reinitialized semaphore installs new metadata without orphaning the old record");

  Check(sem_init(unnamed, 0, 0) == 0, "initialize unnamed destroy fixture");
  const GuestSem unnamed_state = *unnamed;
  unnamed->magic = 0x1234;
  *Libs::Posix::GetErrorAddr() = 0;
  Check(sem_destroy(unnamed) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
        "destroy rejects wrong native magic without erasing tracked state");
  unnamed->magic = unnamed_state.magic;
  unnamed->flags |= 0x2;
  *Libs::Posix::GetErrorAddr() = 0;
  Check(sem_destroy(unnamed) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
        "destroy rejects native named-semaphore flag without cleanup");
  unnamed->flags = unnamed_state.flags;
  Check(sem_destroy(unnamed) == 0 && unnamed->magic == 0,
        "valid unnamed destroy clears only the native magic word");
  const GuestSem destroyed_unnamed = *unnamed;
  *Libs::Posix::GetErrorAddr() = 0;
  Check(sem_destroy(unnamed) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL &&
            std::memcmp(unnamed, &destroyed_unnamed, sizeof(destroyed_unnamed)) == 0,
        "double destroy fails without mutating the destroyed public record");

  hidden->flags |= 0x2;
  const GuestSem hidden_named_flag = *hidden;
  *Libs::Posix::GetErrorAddr() = 0;
  Check(sem_destroy(hidden) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL &&
            std::memcmp(hidden, &hidden_named_flag, sizeof(hidden_named_flag)) == 0,
        "flag-rejected destroy preserves an unnamed tracked object exactly");
  hidden->flags = 0;
  Check(sem_destroy(hidden) == 0, "destroy restored inaccessible-pointer fixture");

  for (GuestSem* sem: {first, second, third, fourth, raced, forged}) {
    Check(sem_destroy(sem) == 0, "destroy named POSIX semaphore fixture");
  }
  Libs::Posix::PosixSemNameSnapshot final_snapshot {};
  Check(!Libs::Posix::PosixSemNameSnapshotForTesting(nullptr, &final_snapshot) &&
            final_snapshot.live_names == baseline.live_names,
        "all POSIX semaphore name IDs and metadata are released");
  Check(final_snapshot.allocated_ids == baseline.allocated_ids,
        "allocated name ID bitmap returns to its exact baseline");
  Check(Kernel::Memory::KernelMunmap(reinterpret_cast<uint64_t>(mapping), 0x8000) == OK,
        "unmap POSIX semaphore guest fixture");
}

void CheckMonoNativeMemoryContract() {
  namespace Kernel = Libs::LibKernel;
  using Libs::NativeKernelBridge::DispatchSyscall;
  const char* trap = std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS");
  const char* native_heap = std::getenv("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP");
  const std::string saved_trap = trap ? trap : "";
  const std::string saved_native_heap = native_heap ? native_heap : "";
  size_t baseline_available = 0;
  Check(Kernel::Memory::KernelAvailableFlexibleMemorySize(&baseline_available) == OK,
        "capture flexible-memory capacity before native reservations");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP", "") == 0,
        "disarm native mmap dispatch fixture");
#else
  Check(unsetenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == 0 &&
            unsetenv("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP") == 0,
        "disarm native mmap dispatch fixture");
#endif
  const auto ungated = DispatchSyscall(
      {0x1dd, {0x200000000ull, 0x4000, 3, 0x1000, UINT32_MAX, 0}});
  size_t ungated_available = 0;
  Check(ungated.value == -1 && ungated.posix_errno == Libs::Posix::POSIX_ENOSYS &&
            Kernel::Memory::KernelAvailableFlexibleMemorySize(&ungated_available) == OK &&
            ungated_available == baseline_available,
        "exact anonymous read-write tuple remains rejected without bounded admission");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP", "1") == 0,
        "arm native mmap dispatch fixture");
#else
  Check(setenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1", 1) == 0 &&
            setenv("KYTY_DIAGNOSTIC_ORBIS_AUDIOD_NATIVE_HEAP", "1", 1) == 0,
        "arm native mmap dispatch fixture");
#endif

  const auto reserve = [&] {
    return DispatchSyscall({0x1dd, {0x200000000ull, 0x60000, 0, 0x1000,
                                    UINT32_MAX, 0}});
  };
  const auto first = reserve();
  const auto second = reserve();
  Check(first.value > 0 && first.posix_errno == 0 && second.value > 0 &&
            second.posix_errno == 0 && first.value != second.value,
        "Mono anonymous reservations receive distinct mappings");
  for (const auto reply: {first, second}) {
    Kernel::Memory::VirtualQueryInfo info {};
    auto* mapped = reinterpret_cast<void*>(static_cast<uintptr_t>(reply.value));
    Check(Kernel::Memory::KernelVirtualQuery(mapped, 0, &info, sizeof(info)) == OK &&
              info.is_committed && info.is_flexible && info.start <= reply.value &&
              info.end >= static_cast<uint64_t>(reply.value) + 0x60000 &&
              (info.protection & 7) == 0 && std::strcmp(info.name, "native_prot_none") == 0,
          "Mono reservation is tracked as bounded PROT_NONE flexible memory");
  }
  size_t mapped_available = 0;
  Check(Kernel::Memory::KernelAvailableFlexibleMemorySize(&mapped_available) == OK &&
            baseline_available >= 0xc0000 && mapped_available == baseline_available - 0xc0000,
        "two native reservations consume exactly their flexible backing");
  auto* writable = reinterpret_cast<uint32_t*>(static_cast<uintptr_t>(first.value + 0x4000));
  Check(Kernel::Memory::KernelMprotect(writable, 0x4000, 3) == OK,
        "reserved Mono page can be committed read-write by the protection path");
  Check(Libs::Posix::sem_init(writable, 0, 0) == 0 &&
            Libs::Posix::sem_destroy(writable) == 0,
        "POSIX semaphore initializes and destroys inside the writable native reservation page");
  *writable = 0x6d6f6e6f;
  Check(*writable == 0x6d6f6e6f &&
            Kernel::Memory::KernelMprotect(writable, 0x4000, 0) == OK,
        "committed Mono page stores bytes and returns to PROT_NONE");
  Kernel::Memory::VirtualQueryInfo restored {};
  Check(Kernel::Memory::KernelVirtualQuery(writable, 0, &restored, sizeof(restored)) == OK &&
            restored.is_committed && restored.is_flexible &&
            (restored.protection & 7) == 0 &&
            std::strcmp(restored.name, "native_prot_none") == 0,
        "post-restore query confirms the committed page is PROT_NONE again");

  const auto rw_reply = DispatchSyscall(
      {0x1dd, {0x200000000ull, 0x4000, 3, 0x1000, UINT32_MAX, 0}});
  Check(rw_reply.value > 0 && rw_reply.posix_errno == 0,
        "Mono lock-free allocator receives anonymous read-write backing");
  auto* rw_mapping = reinterpret_cast<uint32_t*>(static_cast<uintptr_t>(rw_reply.value));
  Kernel::Memory::VirtualQueryInfo rw_info {};
  Check(Kernel::Memory::KernelVirtualQuery(rw_mapping, 0, &rw_info, sizeof(rw_info)) == OK &&
            rw_info.is_committed && rw_info.is_flexible &&
            (rw_info.protection & 7) == 3 &&
            std::strcmp(rw_info.name, "native_anonymous_rw") == 0,
        "lock-free allocator mapping retains bounded read-write classification");
  rw_mapping[0] = 0x64657363;
  rw_mapping[0x3fff / sizeof(uint32_t)] = 0x6d6f6e6f;
  Check(rw_mapping[0] == 0x64657363 &&
            rw_mapping[0x3fff / sizeof(uint32_t)] == 0x6d6f6e6f,
        "lock-free allocator mapping stores bytes across its admitted extent");
  size_t rw_available = 0;
  Check(Kernel::Memory::KernelAvailableFlexibleMemorySize(&rw_available) == OK &&
            mapped_available >= 0x4000 && rw_available == mapped_available - 0x4000,
        "read-write anonymous mapping consumes exactly one flexible-memory page");

  const std::array<Libs::NativeKernelBridge::SyscallRequest, 13> rejected {{
      {0x1dd, {0x200000000ull, 0x60001, 0, 0x1000, UINT32_MAX, 0}},
      {0x1dd, {0x200000000ull, 0x60000, 0, 0x1001, UINT32_MAX, 0}},
      {0x1dd, {0x200000000ull, 0x60000, 0, 0x1000, 1, 0}},
      {0x1dd, {0x200000000ull, 0x60000, 0, 0x1000, UINT32_MAX, 0x4000}},
      {0x1dd, {0x200001000ull, 0x60000, 0, 0x1000, UINT32_MAX, 0}},
      {0x1dd, {0x200000000ull, 0x1004000, 3, 0x1000, UINT32_MAX, 0}},
      {0x1dd, {0x200000000ull, 0x4001, 3, 0x1000, UINT32_MAX, 0}},
      {0x1dd, {0x200000000ull, 0x4000, 3, 0x1001, UINT32_MAX, 0}},
      {0x1dd, {0x200000000ull, 0x4000, 3, 0x1000, 1, 0}},
      {0x1dd, {0x200000000ull, 0x4000, 3, 0x1000, UINT32_MAX, 0x4000}},
      {0x1dd, {0x200001000ull, 0x4000, 3, 0x1000, UINT32_MAX, 0}},
      {0x1dd, {0x200000000ull, 0x4000, 1, 0x1000, UINT32_MAX, 0}},
      {0x1dd, {0x200000000ull, 0x4000, 4, 0x1000, UINT32_MAX, 0}},
  }};
  size_t final_available = 0;
  Check(Kernel::Memory::KernelAvailableFlexibleMemorySize(&final_available) == OK &&
            final_available == baseline_available,
        "native reservation teardown restores exact flexible-memory capacity");

  // libhermes ContiguousVAStorageProvider: 0x9000000 heap + 4 MiB slack at a random 4 MiB-aligned hint, trimmed, named, then committed in 4 MiB MAP_FIXED chunks
  const auto name_page = DispatchSyscall(
      {0x1dd, {0x200000000ull, 0x4000, 3, 0x1000, UINT32_MAX, 0}});
  Check(name_page.value > 0 && name_page.posix_errno == 0,
        "hermes fixture receives a readable page for the heap name");
  std::strcpy(reinterpret_cast<char*>(static_cast<uintptr_t>(name_page.value)), "hermes-free-heap");
  const auto heap = DispatchSyscall(
      {0x1dd, {0x2c0c00000ull, 0x93fc000, 0, 0x1000, UINT32_MAX, 0}});
  size_t heap_available = 0;
  Check(heap.value >= 0x2c0c00000ll && (heap.value & 0x3fff) == 0 && heap.posix_errno == 0 &&
            Kernel::Memory::KernelAvailableFlexibleMemorySize(&heap_available) == OK &&
            heap_available == baseline_available - 0x4000 - 0x93fc000,
        "hermes whole-heap PROT_NONE reservation is admitted above the 16 MiB cap at its hint");
  const uint64_t heap_raw = static_cast<uint64_t>(heap.value);
  const uint64_t heap_base = (heap_raw + 0x3fffff) & ~0x3fffffull;
  const uint64_t heap_head = heap_base - heap_raw;
  if (heap_head != 0) {
    Check(DispatchSyscall({0x49, {heap_raw, heap_head}}).value == 0,
          "hermes head trim releases through munmap");
  }
  if (0x93fc000 != heap_head + 0x9000000) {
    Check(DispatchSyscall({0x49, {heap_base + 0x9000000, 0x93fc000 - heap_head - 0x9000000}}).value == 0,
          "hermes tail trim releases through munmap");
  }
  const size_t heap_floor = baseline_available - 0x4000 - 0x9000000;
  size_t trimmed_available = 0;
  Check(Kernel::Memory::KernelAvailableFlexibleMemorySize(&trimmed_available) == OK &&
            trimmed_available == heap_floor,
        "hermes trims return the alignment slack to the flexible budget");
  const auto named = DispatchSyscall(
      {0x24c, {heap_base, 0x9000000, static_cast<uint64_t>(name_page.value)}});
  Kernel::Memory::VirtualQueryInfo heap_info {};
  Check(named.value == 0 && named.posix_errno == 0 &&
            Kernel::Memory::KernelVirtualQuery(reinterpret_cast<void*>(heap_base), 0, &heap_info,
                                               sizeof(heap_info)) == OK &&
            heap_info.start <= heap_base && heap_info.end >= heap_base + 0x9000000 &&
            std::strcmp(heap_info.name, "hermes-free-heap") == 0,
        "hermes names its whole 144 MiB reservation through raw 0x24c");

  auto* chunk = reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(heap_base + 0x400000));
  const auto commit = [&](uint64_t prot) {
    return DispatchSyscall({0x1dd, {heap_base + 0x400000, 0x400000, prot, 0x1010, UINT32_MAX, 0}});
  };
  const auto committed = commit(3);
  Kernel::Memory::VirtualQueryInfo chunk_info {};
  size_t chunk_available = 0;
  Check(committed.value == static_cast<int64_t>(heap_base + 0x400000) && committed.posix_errno == 0 &&
            Kernel::Memory::KernelVirtualQuery(chunk, 0, &chunk_info, sizeof(chunk_info)) == OK &&
            chunk_info.is_flexible && (chunk_info.protection & 7) == 3 &&
            chunk_info.start == heap_base + 0x400000 && chunk_info.end == heap_base + 0x800000 &&
            Kernel::Memory::KernelAvailableFlexibleMemorySize(&chunk_available) == OK &&
            chunk_available == heap_floor,
        "hermes MAP_FIXED commit replaces one reserved chunk in place without new budget");
  chunk[0] = 0x48;
  chunk[0x3fffff] = 0x43;
  Check(chunk[0] == 0x48 && chunk[0x3fffff] == 0x43, "committed hermes chunk stores bytes");
  const auto uncommitted = commit(0);
  Check(uncommitted.value == static_cast<int64_t>(heap_base + 0x400000) &&
            Kernel::Memory::KernelVirtualQuery(chunk, 0, &chunk_info, sizeof(chunk_info)) == OK &&
            chunk_info.is_flexible && (chunk_info.protection & 7) == 0,
        "hermes MAP_FIXED PROT_NONE releases the chunk back to a reservation");
}

void CheckNativeUserServiceInitProviderGate() {
  const char* current = std::getenv("KYTY_DIAGNOSTIC_NATIVE_USERSERVICE_INIT");
  const bool had_current = current != nullptr;
  const std::string saved = current ? current : "";
#if defined(_WIN32)
  (void)had_current;
  Check(_putenv_s("KYTY_DIAGNOSTIC_NATIVE_USERSERVICE_INIT", "") == 0,
        "clear native UserService initializer gate");
#else
  Check(unsetenv("KYTY_DIAGNOSTIC_NATIVE_USERSERVICE_INIT") == 0,
        "clear native UserService initializer gate");
#endif
  Loader::SymbolDatabase hle;
  Libs::InitUserService_1(&hle);
  Check(hle.FindByNid("j3YMu1MVNNo", Loader::SymbolType::Func) != nullptr &&
            hle.FindByNid("az-0R6eviZ0", Loader::SymbolType::Func) != nullptr &&
            hle.FindByNid("5EiQCnL2G1Y", Loader::SymbolType::Func) == nullptr &&
            hle.FindByNid("wuI7c7UNk0A", Loader::SymbolType::Func) == nullptr,
        "default UserService binding mixes HLE initialization with native callback registration");

#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_NATIVE_USERSERVICE_INIT", "1") == 0,
        "arm native UserService initializer gate");
#else
  Check(setenv("KYTY_DIAGNOSTIC_NATIVE_USERSERVICE_INIT", "1", 1) == 0,
        "arm native UserService initializer gate");
#endif
  Loader::SymbolDatabase native;
  Libs::InitUserService_1(&native);
  Check(native.FindByNid("j3YMu1MVNNo", Loader::SymbolType::Func) == nullptr &&
            native.FindByNid("az-0R6eviZ0", Loader::SymbolType::Func) == nullptr &&
            native.FindByNid("5EiQCnL2G1Y", Loader::SymbolType::Func) == nullptr &&
            native.FindByNid("wuI7c7UNk0A", Loader::SymbolType::Func) == nullptr,
        "native UserService gate leaves the connected stateful family to the provider");
  Check(native.FindByNid("CdWp0oHWGr0", Loader::SymbolType::Func) != nullptr &&
            native.FindByNid("fPhymKNvK-A", Loader::SymbolType::Func) != nullptr,
        "native UserService gate does not broaden to unrelated HLE queries");

#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_NATIVE_USERSERVICE_INIT", saved.c_str()) == 0,
        "restore native UserService initializer gate");
#else
  Check((had_current ? setenv("KYTY_DIAGNOSTIC_NATIVE_USERSERVICE_INIT", saved.c_str(), 1)
                     : unsetenv("KYTY_DIAGNOSTIC_NATIVE_USERSERVICE_INIT")) == 0,
        "restore native UserService initializer gate");
#endif
}

class TempDirectory {
public:
  TempDirectory() {
    const auto unique =
        std::chrono::steady_clock::now().time_since_epoch().count();
    m_path = std::filesystem::temp_directory_path() /
             ("kyty_kernel_file_system_" + std::to_string(unique));
    Check(std::filesystem::create_directories(m_path),
          "create temporary directory");
  }

  ~TempDirectory() {
    std::error_code error;
    std::filesystem::remove_all(m_path, error);
  }

  [[nodiscard]] const std::filesystem::path &Path() const { return m_path; }

  KYTY_CLASS_NO_COPY(TempDirectory);

private:
  std::filesystem::path m_path;
};

void CheckPsmMscorlibAotLoaderIdentity();

void CheckPsmMscorlibAotScope() {
  namespace Kernel = Libs::LibKernel;
  int result = 0x12345678;
  const auto exact = [&](const char* path, size_t args, const void* argp,
                         uint32_t flags, const Kernel::KernelLoadModuleOpt* opt,
                         const int* output) {
    return Kernel::IsPsmNativeAotMscorlibOnlyRequest(
        path, args, argp, flags, opt, output);
  };
  constexpr char Exact[] = "//common_ex/lib/mono/2.1/mscorlib.dll.sprx";
  Check(exact(Exact, 0, nullptr, 0x20000, nullptr, &result),
        "exact Mono mscorlib load tuple is admitted");
  const int marker = 1;
  const auto* option = reinterpret_cast<const Kernel::KernelLoadModuleOpt*>(uintptr_t {1});
  Check(!exact(nullptr, 0, nullptr, 0x20000, nullptr, &result) &&
            !exact("//common_ex/lib/mono/2.1/System.dll.sprx", 0, nullptr, 0x20000, nullptr, &result) &&
            !exact("//common_ex/lib/mscorlib.dll.sprx", 0, nullptr, 0x20000, nullptr, &result) &&
            !exact("/app0/psm/Application/app.exe.sprx", 0, nullptr, 0x20000, nullptr, &result) &&
            !exact("//common_ex/lib/mono/2.1/../mscorlib.dll.sprx", 0, nullptr, 0x20000, nullptr, &result) &&
            !exact(Exact, 1, nullptr, 0x20000, nullptr, &result) &&
            !exact(Exact, 0, &marker, 0x20000, nullptr, &result) &&
            !exact(Exact, 0, nullptr, 0, nullptr, &result) &&
            !exact(Exact, 0, nullptr, 0x20000, option, &result) &&
            !exact(Exact, 0, nullptr, 0x20000, nullptr, nullptr),
        "all path and ABI mutations remain outside the exact mscorlib admission");

#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_MSCORLIB_AOT_LOAD", "1") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_PSM_NATIVE_AOT_LOAD", "1") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_MONO_Y1_ERROR", "") == 0,
        "arm exact mscorlib binding with broad-gate precedence fixture");
#else
  Check(setenv("KYTY_DIAGNOSTIC_PSM_MSCORLIB_AOT_LOAD", "1", 1) == 0 &&
            setenv("KYTY_DIAGNOSTIC_PSM_NATIVE_AOT_LOAD", "1", 1) == 0 &&
            unsetenv("KYTY_DIAGNOSTIC_MONO_Y1_ERROR") == 0,
        "arm exact mscorlib binding with broad-gate precedence fixture");
#endif
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* symbol = symbols.FindByNid("Y1nEpkCieOY", Loader::SymbolType::Func);
  Check(symbol != nullptr, "exact mscorlib loader binds the Y1 NID");
  using Load = int32_t (KYTY_SYSV_ABI *)(const char*, size_t, const void*, uint32_t,
                                        const void*, int*);
  const auto load = reinterpret_cast<Load>(symbol->vaddr);
  result = 0x12345678;
  Check(load(Exact, 0, nullptr, 0, nullptr, &result) == Kernel::KERNEL_ERROR_EINVAL &&
            result == Kernel::KERNEL_ERROR_EINVAL,
        "exact binding rejects a one-field flag mutation without loading a module");

  TempDirectory temporary;
  const auto pe = temporary.Path() / "mscorlib.dll";
  constexpr std::array<uint8_t, 8> PeBytes {0x4d, 0x5a, 0x90, 0, 0x50, 0x45, 0, 0};
  {
    std::ofstream output(pe, std::ios::binary);
    output.write(reinterpret_cast<const char*>(PeBytes.data()), PeBytes.size());
  }
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_SONY_MSCORLIB_PE", pe.string().c_str()) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_SONY_MANAGED_PE_DIR", "") == 0,
        "arm exact managed-PE route without the broad directory route");
#else
  Check(setenv("KYTY_DIAGNOSTIC_SONY_MSCORLIB_PE", pe.string().c_str(), 1) == 0 &&
            unsetenv("KYTY_DIAGNOSTIC_SONY_MANAGED_PE_DIR") == 0,
        "arm exact managed-PE route without the broad directory route");
#endif
  FileSystem::Initialize();
  FileSystem::Mount(temporary.Path(), "/");
  result = 0x12345678;
  Check(load("/app0/psm/Application/app.exe.sprx", 0, nullptr, 0x20000, nullptr,
             &result) == Kernel::KERNEL_ERROR_ENOENT &&
            result == Kernel::KERNEL_ERROR_ENOENT,
        "connected Y1 dispatcher routes the exact app AOT tuple to the missing-source error");

  const auto shellui_dir = temporary.Path() / "shellui-application";
  Check(std::filesystem::create_directories(shellui_dir),
        "create exact ShellUI application source fixture directory");
  const auto shellui_pe = shellui_dir / "app.exe";
  const auto shellui_aot = shellui_dir / "app.exe.sprx";
#if defined(_WIN32)
  const auto shellui_pe_alias = shellui_dir / "app-hardlink.exe";
#endif
  const auto raw_shellui_aot =
      temporary.Path() / "app0" / "psm" / "Application" / "app.exe.sprx";
  const auto raw_shellui_eboot = temporary.Path() / "app0" / "eboot.bin";
  Check(std::filesystem::create_directories(raw_shellui_aot.parent_path()),
        "create captured-package fallback fixture directory");
  std::vector<uint8_t> shellui_pe_bytes(9728, 0x5a);
  std::vector<uint8_t> shellui_aot_bytes(127876, 0x6b);
  shellui_pe_bytes[0] = 'M';
  shellui_pe_bytes[1] = 'Z';
  std::memcpy(shellui_aot_bytes.data(), "SELF", 4);
  {
    std::ofstream output(shellui_pe, std::ios::binary);
    output.write(reinterpret_cast<const char*>(shellui_pe_bytes.data()),
                 static_cast<std::streamsize>(shellui_pe_bytes.size()));
  }
  {
    std::ofstream output(shellui_aot, std::ios::binary);
    output.write(reinterpret_cast<const char*>(shellui_aot_bytes.data()),
                 static_cast<std::streamsize>(shellui_aot_bytes.size()));
  }
#if defined(_WIN32)
  Check(CreateHardLinkW(shellui_pe_alias.c_str(), shellui_pe.c_str(), nullptr),
        "create same-file alternate path for the managed application source");
#endif
  {
    const std::vector<uint8_t> raw_self(27697, 0x53);
    std::ofstream output(raw_shellui_aot, std::ios::binary);
    output.write(reinterpret_cast<const char*>(raw_self.data()),
                 static_cast<std::streamsize>(raw_self.size()));
  }
  {
    const std::vector<uint8_t> raw_self(4096, 0x45);
    std::ofstream output(raw_shellui_eboot, std::ios::binary);
    output.write(reinterpret_cast<const char*>(raw_self.data()),
                 static_cast<std::streamsize>(raw_self.size()));
  }
  const auto shellui_pe_hash = Libs::LibKernel::AuthInfo::DigestHex(
      Libs::LibKernel::AuthInfo::Sha256(shellui_pe_bytes.data(), shellui_pe_bytes.size()));
  const auto shellui_aot_hash = Libs::LibKernel::AuthInfo::DigestHex(
      Libs::LibKernel::AuthInfo::Sha256(shellui_aot_bytes.data(), shellui_aot_bytes.size()));
#if defined(_WIN32)
  Check(_putenv_s("KYTY_TEST_PSM_SHELLUI_APPLICATION_ROUTE", "1") == 0 &&
            _putenv_s("KYTY_TEST_PSM_SHELLUI_PACKAGE_ROOT",
                      (temporary.Path() / "app0").string().c_str()) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_PE", shellui_pe.string().c_str()) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_PE_SHA256", shellui_pe_hash.c_str()) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_AOT", shellui_aot.string().c_str()) == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_AOT_SHA256", shellui_aot_hash.c_str()) == 0,
        "arm exact pinned ShellUI managed and AOT routes");
#else
  Check(setenv("KYTY_TEST_PSM_SHELLUI_APPLICATION_ROUTE", "1", 1) == 0 &&
            setenv("KYTY_TEST_PSM_SHELLUI_PACKAGE_ROOT",
                   (temporary.Path() / "app0").string().c_str(), 1) == 0 &&
            setenv("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_PE", shellui_pe.string().c_str(), 1) == 0 &&
            setenv("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_PE_SHA256", shellui_pe_hash.c_str(), 1) == 0 &&
            setenv("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_AOT", shellui_aot.string().c_str(), 1) == 0 &&
            setenv("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_AOT_SHA256", shellui_aot_hash.c_str(), 1) == 0,
        "arm exact pinned ShellUI managed and AOT routes");
#endif
  constexpr char ShellUiPeGuest[] = "/app0/psm/Application/app.exe";
  constexpr char ShellUiAotGuest[] = "/app0/psm/Application/app.exe.sprx";
  Check(FileSystem::GetRealFilename(ShellUiPeGuest) == shellui_pe &&
            FileSystem::GetRealFilename(ShellUiAotGuest) == shellui_aot,
        "exact ShellUI managed and AOT paths resolve to their separately pinned sources");
  const auto slash_mutation =
      FileSystem::GetRealFilename("//app0/psm/Application/app.exe");
  const auto suffix_mutation =
      FileSystem::GetRealFilename("/app0/psm/Application/app.exe.dll");
  const auto basename_mutation =
      FileSystem::GetRealFilename("/app0/psm/Application/other.exe.sprx");
  Check(slash_mutation.empty() &&
            FileSystem::GetRealFilename("\\app0\\psm\\Application\\app.exe").empty() &&
            FileSystem::GetRealFilename("/APP0/PSM/application/APP.EXE").empty() &&
            FileSystem::GetRealFilename("//app0/psm/Application/app.exe.sprx").empty(),
        "ShellUI application route fails closed on alias-equivalent slash and case mutations");
  const auto traversal_mutation =
      FileSystem::GetRealFilename("/app0/psm/Application/../Application/app.exe");
  Check(traversal_mutation.empty(),
        "ShellUI application route fails closed on an alias-equivalent traversal mutation");
  Check(FileSystem::GetRealFilename("/app0/psm/Application/app.exe.sprx.").empty() &&
            FileSystem::GetRealFilename("/app0/psm/Application/app.exe.sprx ").empty() &&
            FileSystem::GetRealFilename("/app0/eboot.bin").empty() &&
            FileSystem::GetRealFilename("/app0/eboot.bin.").empty() &&
            FileSystem::GetRealFilename("/app0/eboot.bin ").empty(),
        "resolved file identity blocks Win32 trailing aliases to raw package files");
#if defined(_WIN32)
  std::array<wchar_t, 32768> short_path {};
  const DWORD short_length = GetShortPathNameW(
      raw_shellui_aot.c_str(), short_path.data(), static_cast<DWORD>(short_path.size()));
  Check(short_length != 0 && short_length < short_path.size(),
        "query the raw package AOT short-name identity");
  if (short_length != 0 && short_length < short_path.size()) {
    const auto short_name = std::filesystem::path(short_path.data()).filename().string();
    if (!Common::EqualNoCase(short_name, raw_shellui_aot.filename().string())) {
      Check(FileSystem::GetRealFilename(
                "/app0/psm/Application/" + short_name).empty(),
            "resolved file identity blocks the Win32 short-name alias to the raw package AOT");
    }
  }
#endif
  Check(suffix_mutation != shellui_pe && suffix_mutation != shellui_aot,
        "ShellUI application route rejects a suffix mutation");
  Check(basename_mutation != shellui_pe && basename_mutation != shellui_aot,
        "ShellUI application route rejects a basename mutation");
  const int shellui_fd = FileSystem::KernelOpen(ShellUiPeGuest, 0, 0);
  Check(shellui_fd >= 0 && FileSystem::KernelClose(shellui_fd) == OK &&
            FileSystem::KernelOpen(ShellUiPeGuest, 1, 0) == Kernel::KERNEL_ERROR_EROFS,
        "pinned ShellUI managed source is readable and rejects guest writes");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_PE",
                  shellui_pe_alias.string().c_str()) == 0 &&
            FileSystem::GetRealFilename(ShellUiPeGuest) == shellui_pe_alias &&
            FileSystem::KernelOpen(ShellUiPeGuest, 1, 0) == Kernel::KERNEL_ERROR_EROFS &&
            _putenv_s("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_PE",
                      shellui_pe.string().c_str()) == 0,
        "same-file alternate source path remains read-only after lease reuse");
  const HANDLE source_writer = CreateFileW(
      shellui_aot.c_str(), GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  Check(source_writer == INVALID_HANDLE_VALUE &&
            GetLastError() == ERROR_SHARING_VIOLATION &&
            !DeleteFileW(shellui_aot.c_str()),
        "the validated AOT source lease denies writes and deletion");
  const auto replacement_aot = shellui_dir / "replacement-app.exe.sprx";
  {
    std::ofstream output(replacement_aot, std::ios::binary);
    output.write(reinterpret_cast<const char*>(shellui_aot_bytes.data()),
                 static_cast<std::streamsize>(shellui_aot_bytes.size()));
  }
  Check(!MoveFileExW(replacement_aot.c_str(), shellui_aot.c_str(),
                     MOVEFILE_REPLACE_EXISTING),
        "the validated AOT source lease denies path replacement");
  Check(_putenv_s("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_AOT",
                  replacement_aot.string().c_str()) == 0 &&
            FileSystem::GetRealFilename(ShellUiAotGuest).empty() &&
            _putenv_s("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_AOT",
                      shellui_aot.string().c_str()) == 0,
        "a byte-identical file cannot replace the retained AOT source identity");
#endif
  result = 0x12345678;
  Check(load(ShellUiAotGuest, 0, nullptr, 0x20000, nullptr, &result) ==
                Kernel::KERNEL_ERROR_ENOEXEC &&
            result == Kernel::KERNEL_ERROR_ENOEXEC,
        "connected Y1 dispatcher reaches the exact app source and rejects a non-ELF fixture");
  result = 0x12345678;
  Check(load(ShellUiAotGuest, 0, nullptr, 0, nullptr, &result) ==
                Kernel::KERNEL_ERROR_EINVAL &&
            result == Kernel::KERNEL_ERROR_EINVAL,
        "connected Y1 dispatcher preserves the app AOT ABI flags gate");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_AOT_SHA256", std::string(64, '0').c_str()) == 0,
        "mutate the ShellUI AOT pin");
#else
  Check(setenv("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_AOT_SHA256", std::string(64, '0').c_str(), 1) == 0,
        "mutate the ShellUI AOT pin");
#endif
  Check(FileSystem::GetRealFilename(ShellUiAotGuest).empty(),
        "a mismatched ShellUI AOT pin fails closed instead of exposing the package ciphertext");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_AOT_SHA256", shellui_aot_hash.c_str()) == 0,
        "restore the ShellUI AOT pin");
#else
  Check(setenv("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_AOT_SHA256", shellui_aot_hash.c_str(), 1) == 0,
        "restore the ShellUI AOT pin");
#endif
  const auto native = temporary.Path() / "system_ex/common_ex/lib/mscorlib.dll.sprx";
  Check(FileSystem::GetRealFilename("/common_ex/lib/mono/2.1/mscorlib.dll.sprx") != native,
        "native mscorlib alias is not exposed as a general VFS mapping");
  result = 0x12345678;
  Check(load(Exact, 0, nullptr, 0x20000, nullptr, &result) ==
                Kernel::KERNEL_ERROR_ENOENT &&
            result == Kernel::KERNEL_ERROR_ENOENT,
        "exact native-AOT route reports the missing-source error");
  Check(std::filesystem::create_directories(native.parent_path()),
        "create exact native-AOT source fixture directory");
  {
    std::ofstream output(native, std::ios::binary);
    output.write("SELF", 4);
  }
  Check(FileSystem::GetRealFilename("/common_ex/lib/mono/2.1/mscorlib.dll.sprx") != native &&
            FileSystem::GetRealFilename("//common_ex/lib/mono/2.1/mscorlib.dll.sprx") != native &&
            FileSystem::GetRealFilename("///common_ex/lib/mono/2.1/mscorlib.dll.sprx") != native &&
            FileSystem::GetRealFilename("\\common_ex\\lib\\mono\\2.1\\mscorlib.dll.sprx") != native &&
            FileSystem::GetRealFilename("/common_ex/lib/mono/2.1/System.dll.sprx") != native &&
            FileSystem::GetRealFilename("/common_ex/lib/mscorlib.dll.sprx") != native &&
            FileSystem::GetRealFilename("/common_ex/lib/mono/2.1/../mscorlib.dll.sprx") != native,
        "native alias stays inside the loader and rejects slash variants, other assemblies, prefixes, and traversal");
  result = 0x12345678;
  Check(load(Exact, 0, nullptr, 0x20000, nullptr, &result) ==
                Kernel::KERNEL_ERROR_ENOEXEC &&
            result == Kernel::KERNEL_ERROR_ENOEXEC,
        "exact native-AOT route rejects a captured container or other non-ELF source");
  Check(FileSystem::GetRealFilename("/common_ex/lib/mono/2.1/mscorlib.dll") == pe,
        "observed single-slash mscorlib path resolves to the pinned direct file");
  Check(FileSystem::GetRealFilename("//common_ex/lib/mono/2.1/mscorlib.dll") != pe &&
            FileSystem::GetRealFilename("///common_ex/lib/mono/2.1/mscorlib.dll") != pe &&
            FileSystem::GetRealFilename("\\common_ex\\lib\\mono\\2.1\\mscorlib.dll") != pe &&
            FileSystem::GetRealFilename("//common_ex/lib/mono/2.1/System.dll") != pe &&
            FileSystem::GetRealFilename("//common_ex/lib/mscorlib.dll") != pe &&
            FileSystem::GetRealFilename("//common_ex/lib/mono/2.1/../mscorlib.dll") != pe,
        "managed-PE route rejects slash variants, other assemblies, prefixes, and traversal");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_SONY_MSCORLIB_PE",
                  (temporary.Path() / "missing.dll").string().c_str()) == 0,
        "point exact managed-PE route at a missing file");
#else
  Check(setenv("KYTY_DIAGNOSTIC_SONY_MSCORLIB_PE",
               (temporary.Path() / "missing.dll").string().c_str(), 1) == 0,
        "point exact managed-PE route at a missing file");
#endif
  Check(FileSystem::GetRealFilename("/common_ex/lib/mono/2.1/mscorlib.dll").empty(),
        "missing exact managed PE fails closed without a broad fallback");
  CheckPsmMscorlibAotLoaderIdentity();
  FileSystem::Shutdown();
#if defined(_WIN32)
  const HANDLE released_writer = CreateFileW(
      shellui_aot.c_str(), GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  Check(released_writer != INVALID_HANDLE_VALUE,
        "filesystem shutdown releases the validated AOT source lease");
  if (released_writer != INVALID_HANDLE_VALUE) CloseHandle(released_writer);
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_MSCORLIB_AOT_LOAD", "") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_PSM_NATIVE_AOT_LOAD", "") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_SONY_MSCORLIB_PE", "") == 0 &&
            _putenv_s("KYTY_TEST_PSM_SHELLUI_APPLICATION_ROUTE", "") == 0 &&
            _putenv_s("KYTY_TEST_PSM_SHELLUI_PACKAGE_ROOT", "") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_PE", "") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_PE_SHA256", "") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_AOT", "") == 0 &&
            _putenv_s("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_AOT_SHA256", "") == 0,
        "clear exact mscorlib fixture environment");
#else
  Check(unsetenv("KYTY_DIAGNOSTIC_PSM_MSCORLIB_AOT_LOAD") == 0 &&
            unsetenv("KYTY_DIAGNOSTIC_PSM_NATIVE_AOT_LOAD") == 0 &&
            unsetenv("KYTY_DIAGNOSTIC_SONY_MSCORLIB_PE") == 0 &&
            unsetenv("KYTY_TEST_PSM_SHELLUI_APPLICATION_ROUTE") == 0 &&
            unsetenv("KYTY_TEST_PSM_SHELLUI_PACKAGE_ROOT") == 0 &&
            unsetenv("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_PE") == 0 &&
            unsetenv("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_PE_SHA256") == 0 &&
            unsetenv("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_AOT") == 0 &&
            unsetenv("KYTY_DIAGNOSTIC_SONY_SHELLUI_APP_AOT_SHA256") == 0,
        "clear exact mscorlib fixture environment");
#endif
}

void CheckPsmAudioOpenExContract() {
  const char* prior = std::getenv("KYTY_DIAGNOSTIC_PSM_AUDIO_OPENEX");
  const bool had_prior = prior != nullptr;
  const std::string saved = had_prior ? prior : "";
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_AUDIO_OPENEX", "") == 0,
        "clear PSM AudioOutOpenEx gate");
#else
  Check(unsetenv("KYTY_DIAGNOSTIC_PSM_AUDIO_OPENEX") == 0,
        "clear PSM AudioOutOpenEx gate");
#endif
  Loader::SymbolDatabase native_symbols;
  Libs::LibAudioOut::InitAudio_1_AudioOut(&native_symbols);
  Check(native_symbols.FindByNid("qLpSK75lXI4", Loader::SymbolType::Func) == nullptr,
        "AudioOutOpenEx remains native without its exact gate");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_AUDIO_OPENEX", "1") == 0,
        "arm exact PSM AudioOutOpenEx gate");
#else
  Check(setenv("KYTY_DIAGNOSTIC_PSM_AUDIO_OPENEX", "1", 1) == 0,
        "arm exact PSM AudioOutOpenEx gate");
#endif
  Loader::SymbolDatabase symbols;
  Libs::LibAudioOut::InitAudio_1_AudioOut(&symbols);
  const auto* symbol = symbols.FindByNid("qLpSK75lXI4", Loader::SymbolType::Func);
  Check(symbol != nullptr, "exact PSM AudioOutOpenEx export is bound");
  using OpenEx = int (KYTY_SYSV_ABI *)(int, int, int, int, uint32_t, uint32_t, uint32_t);
  const auto open_ex = reinterpret_cast<OpenEx>(symbol->vaddr);

  Check(!Libs::Audio::BackendInitialized(), "audio backend starts outside the fixture");
  Libs::Audio::Initialize();
  const int main = open_ex(0xff, 0, 0, 0, 256, 48000, 0x01010004);
  const int bgm = open_ex(0xff, 1, 0, 0, 256, 48000, 0x00010005);
  Check(main > 0 && bgm > 0 && main != bgm,
        "observed main and BGM tuples allocate distinct audio ports");
  Check(open_ex(0, 0, 0, 0, 256, 48000, 0x01010004) == Libs::LibKernel::KERNEL_ERROR_ENOSYS &&
            open_ex(0xff, 0, 1, 0, 256, 48000, 0x01010004) == Libs::LibKernel::KERNEL_ERROR_ENOSYS &&
            open_ex(0xff, 0, 0, 1, 256, 48000, 0x01010004) == Libs::LibKernel::KERNEL_ERROR_ENOSYS &&
            open_ex(0xff, 0, 0, 0, 255, 48000, 0x01010004) == Libs::LibKernel::KERNEL_ERROR_ENOSYS &&
            open_ex(0xff, 0, 0, 0, 256, 44100, 0x01010004) == Libs::LibKernel::KERNEL_ERROR_ENOSYS &&
            open_ex(0xff, 0, 0, 0, 256, 48000, 0x01010005) == Libs::LibKernel::KERNEL_ERROR_ENOSYS &&
            open_ex(0xff, 2, 0, 0, 256, 48000, 0x00010005) == Libs::LibKernel::KERNEL_ERROR_ENOSYS,
        "mutated PSM AudioOutOpenEx tuples fail without allocating ports");
  Check(Libs::Audio::AudioOut::AudioOutClose(main) == OK &&
            Libs::Audio::AudioOut::AudioOutClose(bgm) == OK &&
            Libs::Audio::AudioOut::AudioOutClose(main) != OK,
        "PSM audio ports close once and reject stale handles");
  Libs::Audio::Shutdown();
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_AUDIO_OPENEX", had_prior ? saved.c_str() : "") == 0,
        "restore PSM AudioOutOpenEx gate");
#else
  Check((had_prior ? setenv("KYTY_DIAGNOSTIC_PSM_AUDIO_OPENEX", saved.c_str(), 1)
                   : unsetenv("KYTY_DIAGNOSTIC_PSM_AUDIO_OPENEX")) == 0,
        "restore PSM AudioOutOpenEx gate");
#endif
}

void CheckPsmNativeMutexContract() {
  const char* prior = std::getenv("KYTY_DIAGNOSTIC_PSM_NATIVE_MUTEX");
  const bool had_prior = prior != nullptr;
  const std::string saved = had_prior ? prior : "";
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_NATIVE_MUTEX", "") == 0,
        "clear PSM native-mutex gate");
#else
  Check(unsetenv("KYTY_DIAGNOSTIC_PSM_NATIVE_MUTEX") == 0,
        "clear PSM native-mutex gate");
#endif
  Loader::SymbolDatabase native_symbols;
  Libs::InitLibKernel_1(&native_symbols);
  Check(native_symbols.FindByNid("ZMn3clnAGBA", Loader::SymbolType::Func) == nullptr &&
            native_symbols.FindByNid("rCTGkBIHfPY", Loader::SymbolType::Func) == nullptr &&
            native_symbols.FindByNid("pw+70ClLYlY", Loader::SymbolType::Func) == nullptr &&
            native_symbols.FindByNid("LEfMMCT+SlM", Loader::SymbolType::Func) == nullptr &&
            native_symbols.FindByNid("IJIggoPZExk", Loader::SymbolType::Func) == nullptr,
        "PSM native-mutex family remains native without its exact gate");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_NATIVE_MUTEX", "1") == 0,
        "arm exact PSM native-mutex gate");
#else
  Check(setenv("KYTY_DIAGNOSTIC_PSM_NATIVE_MUTEX", "1", 1) == 0,
        "arm exact PSM native-mutex gate");
#endif
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto find = [&](const char* nid) {
    const auto* symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "PSM native-mutex export is bound");
    return symbol->vaddr;
  };
  using Init = int (KYTY_SYSV_ABI *)(Libs::LibKernel::PthreadMutex*, int);
  using Operation = int (KYTY_SYSV_ABI *)(Libs::LibKernel::PthreadMutex*);
  const auto init = reinterpret_cast<Init>(find("ZMn3clnAGBA"));
  const auto trylock = reinterpret_cast<Operation>(find("rCTGkBIHfPY"));
  const auto lock = reinterpret_cast<Operation>(find("pw+70ClLYlY"));
  const auto unlock = reinterpret_cast<Operation>(find("LEfMMCT+SlM"));
  const auto destroy = reinterpret_cast<Operation>(find("IJIggoPZExk"));

  Libs::LibKernel::PthreadInitSelfForMainThread();
  Libs::LibKernel::PthreadMutex mutex = nullptr;
  Check(init(nullptr, 0) == Libs::LibKernel::KERNEL_ERROR_EINVAL &&
            init(&mutex, 1) == Libs::LibKernel::KERNEL_ERROR_EINVAL && mutex == nullptr,
        "PSM native-mutex init rejects invalid storage and flags without mutation");
  Check(init(&mutex, 0) == OK && mutex != nullptr,
        "PSM native-mutex init creates guest mutex state");
  const auto created = mutex;
  Check(init(&mutex, 0) == Libs::LibKernel::KERNEL_ERROR_EINVAL && mutex == created,
        "PSM native-mutex duplicate init preserves the owned mutex");
  Check(trylock(&mutex) == OK &&
            trylock(&mutex) == Libs::LibKernel::KERNEL_ERROR_EBUSY &&
            destroy(&mutex) == Libs::LibKernel::KERNEL_ERROR_EBUSY && mutex == created,
        "PSM native-mutex trylock and busy destroy preserve ownership");
  Check(unlock(&mutex) == OK && lock(&mutex) == OK && unlock(&mutex) == OK,
        "PSM native-mutex lock and unlock use the ordinary ownership path");
  Check(destroy(&mutex) == OK && mutex == nullptr &&
            destroy(&mutex) == Libs::LibKernel::KERNEL_ERROR_EINVAL,
        "PSM native-mutex destroy releases once and rejects an empty slot");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_NATIVE_MUTEX", had_prior ? saved.c_str() : "") == 0,
        "restore PSM native-mutex gate");
#else
  Check((had_prior ? setenv("KYTY_DIAGNOSTIC_PSM_NATIVE_MUTEX", saved.c_str(), 1)
                   : unsetenv("KYTY_DIAGNOSTIC_PSM_NATIVE_MUTEX")) == 0,
        "restore PSM native-mutex gate");
#endif
}

struct PsmThreadRenameWorker {
  std::atomic_bool ready {false};
  std::atomic_bool release {false};
};

void* KYTY_SYSV_ABI PsmThreadRenameWorkerEntry(void* argument) {
  auto* worker = static_cast<PsmThreadRenameWorker*>(argument);
  worker->ready.store(true, std::memory_order_release);
  while (!worker->release.load(std::memory_order_acquire)) std::this_thread::yield();
  return nullptr;
}

void CheckPsmNativeThreadRenameContract() {
  const char* prior = std::getenv("KYTY_DIAGNOSTIC_PSM_NATIVE_THREAD_RENAME");
  const bool had_prior = prior != nullptr;
  const std::string saved = had_prior ? prior : "";
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_NATIVE_THREAD_RENAME", "") == 0,
        "clear PSM native-thread-rename gate");
#else
  Check(unsetenv("KYTY_DIAGNOSTIC_PSM_NATIVE_THREAD_RENAME") == 0,
        "clear PSM native-thread-rename gate");
#endif
  Loader::SymbolDatabase native_symbols;
  Libs::InitLibKernel_1(&native_symbols);
  Check(native_symbols.FindByNid("oxMp8uPqa+U", Loader::SymbolType::Func) == nullptr,
        "PSM native-thread rename remains native without its exact gate");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_NATIVE_THREAD_RENAME", "1") == 0,
        "arm exact PSM native-thread-rename gate");
#else
  Check(setenv("KYTY_DIAGNOSTIC_PSM_NATIVE_THREAD_RENAME", "1", 1) == 0,
        "arm exact PSM native-thread-rename gate");
#endif
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* symbol = symbols.FindByNid("oxMp8uPqa+U", Loader::SymbolType::Func);
  Check(symbol != nullptr, "exact PSM native-thread-rename export is bound");
  using Rename = int (KYTY_SYSV_ABI *)(Libs::LibKernel::Pthread, const char*);
  const auto rename = reinterpret_cast<Rename>(symbol->vaddr);

  Libs::LibKernel::PthreadInitSelfForMainThread();
  const auto self = Libs::LibKernel::PthreadSelf();
  char name[32] {};
  Check(self != nullptr && rename(self, "PSMAudioThread") == OK &&
            Libs::LibKernel::PthreadGetname(self, name) == OK &&
            std::strcmp(name, "PSMAudioThread") == 0,
        "PSM native-thread rename updates the guest thread object");
  Check(rename(nullptr, "invalid") == Libs::LibKernel::KERNEL_ERROR_EINVAL,
        "PSM native-thread rename rejects a null thread");
  Check(rename(self, nullptr) == OK &&
            Libs::LibKernel::PthreadGetname(self, name) == OK &&
            std::strcmp(name, "PSMAudioThread") == 0,
        "PSM native-thread rename preserves the name for a null name");
  Common::Singleton<Loader::RuntimeLinker>::Instance();
  PsmThreadRenameWorker worker;
  Libs::LibKernel::Pthread child = nullptr;
  Check(Libs::LibKernel::PthreadCreate(&child, nullptr, PsmThreadRenameWorkerEntry,
                                      &worker, "PSMBeforeRename") == OK,
        "create the live non-self PSM thread-rename target");
  while (!worker.ready.load(std::memory_order_acquire)) std::this_thread::yield();
  Check(rename(child, "PSMAudioThread") == OK &&
            Libs::LibKernel::PthreadGetname(child, name) == OK &&
            std::strcmp(name, "PSMAudioThread") == 0,
        "PSM native-thread rename updates a live non-self guest thread");
  worker.release.store(true, std::memory_order_release);
  Check(Libs::LibKernel::PthreadJoin(child, nullptr) == OK,
        "join the renamed PSM guest thread");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_NATIVE_THREAD_RENAME", had_prior ? saved.c_str() : "") == 0,
        "restore PSM native-thread-rename gate");
#else
  Check((had_prior ? setenv("KYTY_DIAGNOSTIC_PSM_NATIVE_THREAD_RENAME", saved.c_str(), 1)
                   : unsetenv("KYTY_DIAGNOSTIC_PSM_NATIVE_THREAD_RENAME")) == 0,
        "restore PSM native-thread-rename gate");
#endif
}

void CheckPsmSchedRangeContract() {
  const char* prior = std::getenv("KYTY_DIAGNOSTIC_PSM_SCHED_RANGE");
  const bool had_prior = prior != nullptr;
  const std::string saved = had_prior ? prior : "";
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_SCHED_RANGE", "") == 0,
        "clear PSM scheduler-range gate");
#else
  Check(unsetenv("KYTY_DIAGNOSTIC_PSM_SCHED_RANGE") == 0,
        "clear PSM scheduler-range gate");
#endif
  Loader::SymbolDatabase baseline_symbols;
  Libs::InitLibKernel_1(&baseline_symbols);
  const auto bind = [](Loader::SymbolDatabase& symbols, const char* nid) {
    const auto* symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "PSM scheduler export is bound");
    return symbol->vaddr;
  };
  using Query = int (KYTY_SYSV_ABI *)(int);
  const auto baseline_max = reinterpret_cast<Query>(bind(baseline_symbols, "CBNtXOoef-E"));
  const auto baseline_min = reinterpret_cast<Query>(bind(baseline_symbols, "m0iS6jNsXds"));
  Check(baseline_max(1) == 256 && baseline_min(1) == 767,
        "PSM scheduler gate-off preserves the existing policy-one range");
  Check(baseline_max(3) == 256 && baseline_min(3) == 767,
        "PSM scheduler gate-off preserves other policies");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_SCHED_RANGE", "1") == 0,
        "arm exact PSM scheduler-range gate");
#else
  Check(setenv("KYTY_DIAGNOSTIC_PSM_SCHED_RANGE", "1", 1) == 0,
        "arm exact PSM scheduler-range gate");
#endif
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto priority_max = reinterpret_cast<Query>(bind(symbols, "CBNtXOoef-E"));
  const auto priority_min = reinterpret_cast<Query>(bind(symbols, "m0iS6jNsXds"));
  Check(priority_max(1) == 767 && priority_min(1) == 256,
        "PSM scheduler gate reports a coherent policy-one range");
  Check(priority_min(1) <= 520 && 520 <= priority_max(1),
        "PSM audio-driver priority is inside the corrected range");
  Check(priority_max(3) == 256 && priority_min(3) == 767,
        "PSM scheduler gate does not alter other policies");

  struct PsmSchedParam {
    int sched_priority;
  };
  using Get = int (KYTY_SYSV_ABI *)(Libs::LibKernel::Pthread, int*, PsmSchedParam*);
  using Set = int (KYTY_SYSV_ABI *)(Libs::LibKernel::Pthread, int, const PsmSchedParam*);
  const auto get = reinterpret_cast<Get>(bind(symbols, "FIs3-UQT9sg"));
  const auto set = reinterpret_cast<Set>(bind(symbols, "Xs9hdiD7sAA"));
  Common::Singleton<Loader::RuntimeLinker>::Instance();
  PsmThreadRenameWorker worker;
  Libs::LibKernel::Pthread child = nullptr;
  Check(Libs::LibKernel::PthreadCreate(&child, nullptr, PsmThreadRenameWorkerEntry,
                                      &worker, "PSMSchedRange") == OK,
        "create the live PSM scheduler target");
  while (!worker.ready.load(std::memory_order_acquire)) std::this_thread::yield();
  int policy = -1;
  PsmSchedParam param {-1};
  Check(get(child, &policy, &param) == 0 && policy == 1 && param.sched_priority == 700,
        "PSM scheduler query reads the live guest thread state");
  param.sched_priority = 520;
  Check(set(child, policy, &param) == 0,
        "PSM scheduler set accepts the original audio-driver priority");
  policy = -1;
  param.sched_priority = -1;
  Check(get(child, &policy, &param) == 0 && policy == 1 && param.sched_priority == 520,
        "PSM scheduler query observes the updated guest priority");
  Check(set(child, policy, nullptr) != 0 && get(child, &policy, &param) == 0 &&
            policy == 1 && param.sched_priority == 520,
        "PSM scheduler rejects a null parameter without changing live state");
  Check(get(nullptr, &policy, &param) != 0 && get(child, nullptr, &param) != 0 &&
            get(child, &policy, nullptr) != 0,
        "PSM scheduler query rejects invalid arguments");
  worker.release.store(true, std::memory_order_release);
  Check(Libs::LibKernel::PthreadJoin(child, nullptr) == OK,
        "join the PSM scheduler target");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_PSM_SCHED_RANGE", had_prior ? saved.c_str() : "") == 0,
        "restore PSM scheduler-range gate");
#else
  Check((had_prior ? setenv("KYTY_DIAGNOSTIC_PSM_SCHED_RANGE", saved.c_str(), 1)
                   : unsetenv("KYTY_DIAGNOSTIC_PSM_SCHED_RANGE")) == 0,
        "restore PSM scheduler-range gate");
#endif
}

void CheckSaveRename(const std::filesystem::path &root,
                     std::string_view payload) {
  constexpr char Source[] = "/savedata0/STEMP000.DAT";
  constexpr char Target[] = "/savedata0/SDATA000.DAT";
  constexpr char Suffix[] = "-after-rename";

  const int fd = FileSystem::KernelOpen(Source, 0x601, 0777);
  Check(fd >= 3, "open temporary save file");
  Check(FileSystem::KernelWrite(fd, payload.data(), payload.size()) ==
            payload.size(),
        "write save payload");
  Check(FileSystem::KernelRename(Source, Target) == OK,
        "rename open save file");
  Check(FileSystem::KernelWrite(fd, Suffix, sizeof(Suffix) - 1) ==
            sizeof(Suffix) - 1,
        "write through renamed descriptor");
  Check(FileSystem::KernelClose(fd) == OK, "close renamed descriptor");

  Common::File result(root / "SDATA000.DAT", Common::File::Mode::Read);
  Check(!result.IsInvalid(), "open renamed save file");
  const auto data = result.ReadWholeBuffer();
  const std::string expected = std::string(payload) + Suffix;
  Check(data.size() == expected.size(), "renamed save size");
  Check(std::memcmp(data.data(), expected.data(), expected.size()) == 0,
        "renamed save contents");
}

void TestSaveOpenVisibility() {
  constexpr char Path[] = "/savedata0/visible-save.dat";
  constexpr char Payload[] = "saved progress";

  const int fd = FileSystem::KernelOpen(Path, 0xa01, 0777);
  Check(fd >= 3, "create save file exclusively");
  FileSystem::FileStat stat {};
  Check(FileSystem::KernelStat(Path, &stat) == OK && stat.st_size == 0,
        "created save file is visible before close");
  Check(FileSystem::KernelOpen(Path, 0xa01, 0777) ==
            Libs::LibKernel::KERNEL_ERROR_EEXIST,
        "exclusive creation detects an open save file");
  Check(FileSystem::KernelWrite(fd, Payload, sizeof(Payload) - 1) ==
            sizeof(Payload) - 1,
        "populate save file before truncation");
  Check(FileSystem::KernelClose(fd) == OK, "close populated save file");
  Check(FileSystem::KernelStat(Path, &stat) == OK &&
            stat.st_size == sizeof(Payload) - 1,
        "save file contains the truncation fixture");

  const int truncated = FileSystem::KernelOpen(Path, 0x401, 0777);
  Check(truncated >= 3, "truncate existing save file");
  Check(FileSystem::KernelStat(Path, &stat) == OK && stat.st_size == 0,
        "save truncation is visible before close");
  Check(FileSystem::KernelClose(truncated) == OK, "close truncated save file");
}

void TestAioBatches() {
  namespace Kernel = Libs::LibKernel;
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto find = [&](const char *nid) {
    const auto *symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "AIO exports resolve");
    return symbol->vaddr;
  };
  struct Result { int64_t return_value; uint32_t state; };
  struct Request {
    int64_t offset;
    size_t size;
    void *buffer;
    Result *result;
    int32_t fd;
  };
  using Submit = int (KYTY_SYSV_ABI *)(Request *, int32_t, int32_t, int32_t *);
  using Batch = int (KYTY_SYSV_ABI *)(int32_t *, int32_t, int32_t *);
  using Single = int (KYTY_SYSV_ABI *)(int32_t, int32_t *);
  using Wait = int (KYTY_SYSV_ABI *)(int32_t, int32_t *, uint32_t *);
  const auto submit = reinterpret_cast<Submit>(find("HgX7+AORI58"));
  const auto poll = reinterpret_cast<Batch>(find("o7O4z3jwKzo"));
  const auto erase = reinterpret_cast<Batch>(find("Ft3EtsZzAoY"));
  const auto poll_one = reinterpret_cast<Single>(find("2pOuoWoCxdk"));
  const auto erase_one = reinterpret_cast<Single>(find("5TgME6AYty4"));
  const auto wait = reinterpret_cast<Wait>(find("KOF-oJbQVvc"));
  constexpr char Payload[] = "AIO payload";
  const int fd = FileSystem::KernelOpen("/savedata0/aio.dat", 0x602, 0777);
  Check(fd >= 3 && FileSystem::KernelWrite(fd, Payload, sizeof(Payload)) == sizeof(Payload),
        "create AIO read fixture");
  std::array<int32_t, 3> ids {};
  std::array<char, 4> buffer {};
  Result result {};
  Request request {2, buffer.size(), buffer.data(), &result, fd};
  for (int i = 0; i < 2; ++i) {
    Check(submit(&request, 1, 2, &ids[i]) == OK &&
              result.return_value == buffer.size() && result.state == 3 &&
              std::memcmp(buffer.data(), Payload + 2, buffer.size()) == 0,
          "AIO submission reads bytes at the requested offset");
  }
  ids[2] = -1;
  std::array<int32_t, 3> states {-1, -1, -1};
  Check(poll(ids.data(), ids.size(), states.data()) == OK &&
            states[0] == 3 && states[1] == 3 && states[2] == Kernel::KERNEL_ERROR_ESRCH,
        "batch poll writes every state and per-request invalid-ID error");
  Check(poll_one(ids[0], &states[0]) == OK && states[0] == (3 | 0x10000) &&
            poll(ids.data(), 2, states.data()) == OK &&
            states[0] == (3 | 0x10000) && states[1] == (3 | 0x10000) &&
            wait(ids[0], &states[0], nullptr) == OK && states[0] == (3 | 0x10000),
        "single and batch polls and waits share completion notification state");
  Check(erase(ids.data(), ids.size(), states.data()) == OK &&
            states[0] == OK && states[1] == OK && states[2] == Kernel::KERNEL_ERROR_ESRCH,
        "batch deletion writes per-request results");
  Check(poll_one(ids[0], &states[0]) == OK && states[0] == Kernel::KERNEL_ERROR_ESRCH &&
            erase_one(ids[1], &states[1]) == OK && states[1] == Kernel::KERNEL_ERROR_ESRCH,
        "deleted AIO IDs are invalid for single-request APIs");
  for (const auto batch : {poll, erase}) {
    states.fill(42);
    Check(batch(nullptr, 1, states.data()) == Kernel::KERNEL_ERROR_EFAULT &&
              batch(ids.data(), 1, nullptr) == Kernel::KERNEL_ERROR_EFAULT &&
              batch(ids.data(), 0, states.data()) == Kernel::KERNEL_ERROR_EINVAL &&
              batch(ids.data(), 129, states.data()) == Kernel::KERNEL_ERROR_EINVAL &&
              states == std::array<int32_t, 3> {42, 42, 42},
          "invalid batch arguments do not modify outputs");
    std::array<int32_t, 128> invalid_ids {};
    std::array<int32_t, 128> errors {};
    Check(batch(invalid_ids.data(), invalid_ids.size(), errors.data()) == OK &&
              std::all_of(errors.begin(), errors.end(), [](int32_t error) {
                return error == Kernel::KERNEL_ERROR_ESRCH;
              }),
          "maximum-sized batch returns all invalid-ID errors");
  }
  Check(FileSystem::KernelClose(fd) == OK, "close AIO read fixture");
}

void TestNpWebApi2Memory() {
  Loader::SymbolDatabase symbols;
  Libs::LibNpWebApi2::InitNet_1_NpWebApi2(&symbols);
  const auto find = [&](const char *nid) {
    const auto *symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "NpWebApi2 library and memory exports resolve");
    return symbol->vaddr;
  };
  struct Stats { size_t pool, maximum, current; int32_t reserved; };
  static_assert(sizeof(Stats) == 32 && offsetof(Stats, reserved) == 24);
  using Initialize = int (KYTY_SYSV_ABI *)(int, size_t);
  using GetStats = int (KYTY_SYSV_ABI *)(int, Stats *);
  using Terminate = int (KYTY_SYSV_ABI *)(int);
  const auto initialize = reinterpret_cast<Initialize>(find("+o9816YQhqQ"));
  const auto get_stats = reinterpret_cast<GetStats>(find("Xweb+naPZ8Y"));
  const auto terminate = reinterpret_cast<Terminate>(find("bEvXpcEk200"));
  const int first = initialize(1, 65537);
  const int second = initialize(1, 16384);
  Stats stats {1, 2, 3, 4};
  Check(first > 0 && second > 0 && first != second &&
            get_stats(first, &stats) == OK && stats.pool == 81920 &&
            stats.maximum == 0 && stats.current == 0 && stats.reserved == 0 &&
            get_stats(second, &stats) == OK && stats.pool == 16384,
        "NpWebApi2 statistics retain each context's rounded pool capacity");
  Check(get_stats(first, nullptr) == static_cast<int32_t>(0x80553402) &&
            get_stats(0, &stats) == static_cast<int32_t>(0x80553403) &&
            initialize(1, std::numeric_limits<size_t>::max()) == static_cast<int32_t>(0x80553402),
        "NpWebApi2 statistics validate output, context ID, and pool rounding");
  Check(terminate(first) == OK &&
            get_stats(first, &stats) == static_cast<int32_t>(0x80553404) &&
            terminate(first) == static_cast<int32_t>(0x80553404) &&
            terminate(-1) == static_cast<int32_t>(0x80553403) &&
            get_stats(second, &stats) == OK && stats.pool == 16384 &&
            terminate(second) == OK,
        "NpWebApi2 termination removes only the selected library context");
}

// ShellCore's Advpp init passes an HLE lib context to 2hlBNB96saE, so every push entry has to look in the HLE table (the native one is empty, 0x80553404).
void TestNpWebApi2PushOwnership() {
  Loader::SymbolDatabase symbols;
  Libs::LibNpWebApi2::InitNet_1_NpWebApi2(&symbols);
  const auto find = [&](const char *nid) {
    const auto *symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "NpWebApi2 push and request entries are HLE");
    return symbol->vaddr;
  };
  struct InitParam { int32_t http2; size_t pool; const char *name; size_t size; };
  struct Content { uint64_t length; const char *type; };
  using IntInitialize = int (KYTY_SYSV_ABI *)(const InitParam *);
  using ById = int (KYTY_SYSV_ABI *)(int);
  using ByPair = int (KYTY_SYSV_ABI *)(int, int);
  using CtxIndFilter = int (KYTY_SYSV_ABI *)(int, int, const void *, size_t);
  using CreateFilter = int (KYTY_SYSV_ABI *)(int, int, const char *, uint32_t, const void *, size_t);
  using Register = int (KYTY_SYSV_ABI *)(int, int, void *, void *);
  using CreateRequest = int (KYTY_SYSV_ABI *)(int, const char *, const char *, const char *,
                                             const Content *, const void *, int64_t *);
  using SetTimeout = int (KYTY_SYSV_ABI *)(int64_t, uint32_t);
  using SendRequest = int (KYTY_SYSV_ABI *)(int64_t, const void *, size_t, void *);
  using DeleteRequest = int (KYTY_SYSV_ABI *)(int64_t);
  using Presence = int (KYTY_SYSV_ABI *)(int, size_t);
  const auto int_initialize = reinterpret_cast<IntInitialize>(find("zXaFo7euxsQ"));
  const auto terminate = reinterpret_cast<ById>(find("bEvXpcEk200"));
  const auto create_handle = reinterpret_cast<ById>(find("WV1GwM32NgY"));
  const auto delete_handle = reinterpret_cast<ByPair>(find("fIATVMo4Y1w"));
  const auto abort_handle = reinterpret_cast<ByPair>(find("1OLgvahaSco"));
  const auto ctx_ind_filter = reinterpret_cast<CtxIndFilter>(find("2hlBNB96saE"));
  const auto ctx_ind_filter3 = reinterpret_cast<CtxIndFilter>(find("81DkaQt6J30"));
  const auto create_filter = reinterpret_cast<CreateFilter>(find("MsaFhR+lPE4"));
  const auto delete_filter = reinterpret_cast<ByPair>(find("KJdPcOGmK58"));
  const auto create_user = reinterpret_cast<ByPair>(find("sk54bi6FtYM"));
  const auto delete_user = reinterpret_cast<ById>(find("9X9+cneTGUU"));
  const auto register_callback = reinterpret_cast<Register>(find("fY3QqeNkF8k"));
  const auto unregister_callback = reinterpret_cast<ByPair>(find("hOnIlcGrO6g"));
  const auto int_create_request = reinterpret_cast<CreateRequest>(find("qmINYLuqzaA"));
  const auto create_request_ex = reinterpret_cast<CreateRequest>(find("gANJba5v5BI"));
  const auto create_request_flag = reinterpret_cast<CreateRequest>(find("qaMcX2+6ZiA"));
  const auto set_timeout = reinterpret_cast<SetTimeout>(find("TjAutbrkr60"));
  const auto send_request = reinterpret_cast<SendRequest>(find("lQOCF84lvzw"));
  const auto delete_request = reinterpret_cast<DeleteRequest>(find("vvzWO-DvG1s"));
  const auto presence = reinterpret_cast<Presence>(find("dowMWFgowXY"));
  const auto error = [](uint32_t code) { return static_cast<int32_t>(code); };
  Loader::SymbolDatabase kernel;
  Libs::InitLibKernel_1(&kernel);
  Check(kernel.FindByNid("2hlBNB96saE", Loader::SymbolType::Func) == nullptr,
        "libkernel no longer routes 2hlBNB96saE into the native NpWebApi2 module");

  const InitParam advpp {9, 0x40000, "SceNpAdvpp", sizeof(InitParam)};
  const InitParam other {8, 0x40000, "SceNpOther", sizeof(InitParam)};
  const int ctx = int_initialize(&advpp);
  const int ctx2 = int_initialize(&other);
  const int handle = create_handle(ctx);
  const int handle2 = create_handle(ctx2);
  const uint8_t param[16] {};
  const int filter = ctx_ind_filter(ctx, handle, param, 1);
  const int filter2 = ctx_ind_filter3(ctx2, handle2, param, 1);
  Check(ctx > 0 && ctx2 > 0 && handle > 0 && handle2 > 0 && filter > 0 && filter2 > 0 &&
            filter != filter2,
        "Advpp context-independent filter is created on the HLE context and handle");
  Check(create_handle(ctx + 1000) == error(0x80553404) &&
            ctx_ind_filter(ctx + 1000, handle, param, 1) == error(0x80553404) &&
            ctx_ind_filter(ctx, handle2, param, 1) == error(0x8055340d) &&
            ctx_ind_filter(ctx, handle, nullptr, 1) == error(0x80553402) &&
            ctx_ind_filter(ctx, handle, param, 0) == error(0x80553402) &&
            create_filter(ctx, handle, "svc", 0xffffffff, param, 1) == error(0x80553402) &&
            create_filter(ctx, handle, nullptr, 0, param, 1) > 0 &&
            abort_handle(ctx, handle) == OK && abort_handle(ctx, handle2) == error(0x8055340d),
        "push handles and filters are checked against their owning context");

  const int user = create_user(ctx, 1);
  int marker = 0;
  const int callback = register_callback(user, filter, &marker, &marker);
  Check(user > 0 && callback > 0 && create_user(0, 1) == error(0x80553403) &&
            create_user(0x8000, 1) == error(0x80553403) &&
            create_user(ctx, -1) == error(0x80553402) &&
            create_user(ctx + 1000, 1) == error(0x80553404) &&
            register_callback(user, filter2, &marker, nullptr) == error(0x8055340b) &&
            register_callback(user, filter, nullptr, nullptr) == error(0x80553402) &&
            register_callback(user + 12345, filter, &marker, nullptr) == error(0x80553405) &&
            register_callback(user + 12345, filter2, nullptr, nullptr) == error(0x80553402) &&
            unregister_callback(user, callback) == OK &&
            unregister_callback(user, callback) == error(0x8055340c) &&
            unregister_callback(user + 12345, callback) == error(0x80553405),
        "push callbacks need a live user context and a filter of the same library context");

  const Content no_type {1, nullptr};
  const int marker_option = 0;
  int64_t request = -1;
  Check(int_create_request(user, "g", "/p", "GET", &no_type, nullptr, &request) == error(0x80553408) &&
            int_create_request(user, nullptr, "/p", "GET", nullptr, nullptr, &request) == error(0x80553402) &&
            int_create_request(user + 12345, "g", "/p", "GET", nullptr, nullptr, &request) == error(0x80553405) &&
            create_request_ex(user, "g", "/p", "GET", nullptr, nullptr, &request) == error(0x80553402) &&
            request == -1,
        "internal request creation rejects bad arguments without issuing an id");
  Check(int_create_request(user, "g", "/p", "GET", nullptr, nullptr, &request) == OK &&
            set_timeout(request, 30000000) == OK && delete_request(request) == OK &&
            set_timeout(request, 30000000) == error(0x80553406) &&
            create_request_ex(user, "g", "/p", "POST", nullptr, &marker_option, &request) == OK &&
            delete_request(request) == OK &&
            create_request_flag(user, "g", "/p", "GET", nullptr, nullptr, &request) == OK &&
            send_request(request, nullptr, 0, nullptr) == error(0x80553407) &&
            delete_request(request) == OK,
        "internal requests share the HLE request table and stay signed out");

  const int user2 = create_user(ctx2, 2);
  int64_t orphan = -1;
  int64_t orphan2 = -1;
  Check(int_create_request(user, "g", "/p", "GET", nullptr, nullptr, &orphan) == OK &&
            int_create_request(user2, "g", "/p", "GET", nullptr, nullptr, &orphan2) == OK,
        "requests created before teardown");
  // HLE ids are flat: an orphaned request is request-not-found, native returns 0x80553405 first
  Check(register_callback(user, filter, &marker, nullptr) > 0 && delete_user(user) == OK &&
            set_timeout(orphan, 1) == error(0x80553406) && delete_request(orphan) == error(0x80553406) &&
            set_timeout(orphan2, 1) == OK &&
            delete_user(user) == error(0x80553405) && delete_filter(ctx, filter) == OK &&
            delete_filter(ctx, filter) == error(0x8055340b) && delete_handle(ctx, handle) == OK &&
            delete_handle(ctx, handle) == error(0x8055340d) && terminate(ctx) == OK &&
            delete_filter(ctx, filter) == error(0x80553404),
        "Advpp teardown order releases each object once");
  // native gives 0x80553404 for both once the lib context is gone
  Check(user2 > 0 && terminate(ctx2) == OK && delete_user(user2) == error(0x80553405) &&
            set_timeout(orphan2, 1) == error(0x80553406) &&
            delete_handle(ctx2, handle2) == error(0x80553404),
        "terminating a library context drops the user contexts it owns");

  const int presence_ctx = presence(1, 0x10000);
  Check(presence_ctx > 0 && create_handle(presence_ctx) > 0 && terminate(presence_ctx) == OK,
        "presence initialisation shares the HLE context table");
}

void TestJson2ArrayIteratorIncrement() {
  Loader::SymbolDatabase symbols;
  Libs::LibJson2::InitNet_1_Json2(&symbols);
  const auto find = [&](const char *nid) {
    const auto *symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "Json2 array iterator exports resolve");
    return symbol->vaddr;
  };
  using Iterator = const void *const *;
  using Ctor = void *(KYTY_SYSV_ABI *)(void *);
  using IntCtor = void *(KYTY_SYSV_ABI *)(void *, int64_t);
  using PushBack = void *(KYTY_SYSV_ABI *)(void *, const void *);
  using Bound = Iterator *(KYTY_SYSV_ABI *)(Iterator *, const void *);
  using NotEqual = bool (KYTY_SYSV_ABI *)(const Iterator *, const Iterator *);
  using Deref = const void *(KYTY_SYSV_ABI *)(const Iterator *);
  using GetInteger = const int64_t *(KYTY_SYSV_ABI *)(const void *);
  using Prefix = Iterator *(KYTY_SYSV_ABI *)(Iterator *);
  using Postfix = Iterator *(KYTY_SYSV_ABI *)(Iterator *, int);
  using Dtor = void (KYTY_SYSV_ABI *)(void *);
  const auto array_ctor = reinterpret_cast<Ctor>(find("JP-PtKMiI1E"));
  const auto int_ctor = reinterpret_cast<IntCtor>(find("0lLK8+kDqmE"));
  const auto push_back = reinterpret_cast<PushBack>(find("zQtLRTqceMY"));
  const auto begin = reinterpret_cast<Bound>(find("bcH5EnFE2xY"));
  const auto end = reinterpret_cast<Bound>(find("WXF2ihRF+B8"));
  const auto not_equal = reinterpret_cast<NotEqual>(find("5AZPp99ogrc"));
  const auto deref = reinterpret_cast<Deref>(find("wcgr5mte7T8"));
  const auto get_integer = reinterpret_cast<GetInteger>(find("DIxvoy7Ngvk"));
  const auto prefix = reinterpret_cast<Prefix>(find("w5+VCznos5E"));
  const auto postfix = reinterpret_cast<Postfix>(find("GEylwSsiGG8"));
  const auto value_dtor = reinterpret_cast<Dtor>(find("WTtYf+cNnXI"));
  const auto array_dtor = reinterpret_cast<Dtor>(find("HJ8GpRT1aiw"));

  alignas(8) unsigned char array[8] {};
  alignas(8) unsigned char value[32] {};
  array_ctor(array);
  for (int64_t i = 7; i <= 9; i++) {
    int_ctor(value, i);
    push_back(array, value);
    value_dtor(value);
  }
  Iterator it = nullptr;
  Iterator last = nullptr;
  begin(&it, array);
  end(&last, array);
  const Iterator start = it;
  const void *first = deref(&it);
  Check(*get_integer(first) == 7 && postfix(&it, 0) == &it && *get_integer(deref(&it)) == 8 &&
            deref(&start) == first,
        "Json2 postfix increment advances an HLE iterator without rewriting the array slot");
  Check(prefix(&it) == &it && *get_integer(deref(&it)) == 9 && not_equal(&it, &last) &&
            postfix(&it, 0) == &it && !not_equal(&it, &last),
        "Json2 prefix and postfix increments share the HLE iterator layout and reach end");
  array_dtor(array);
}

// ShellCore's PSPLUS check runs these on HLE strings and array iterators; the native bodies read std::string bytes as a char pointer.
// erase/pop: title metadata and entitlement list trimming
void TestJson2StringCompare() {
  Loader::SymbolDatabase symbols;
  Libs::LibJson2::InitNet_1_Json2(&symbols);
  const auto find = [&](const char *nid) {
    const auto *symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "Json2 string compare and iterator copy are HLE");
    return symbol->vaddr;
  };
  using StringCtor = void *(KYTY_SYSV_ABI *)(void *, const char *);
  using Dtor = void (KYTY_SYSV_ABI *)(void *);
  using EqualCString = bool (KYTY_SYSV_ABI *)(const void *, const char *);
  using Equal = bool (KYTY_SYSV_ABI *)(const void *, const void *);
  const auto string_ctor = reinterpret_cast<StringCtor>(find("9KUZFjI1IxA"));
  const auto string_dtor = reinterpret_cast<Dtor>(find("cG1VE2HMl6c"));
  const auto equal_cstr = reinterpret_cast<EqualCString>(find("VbFjEs--uiA"));
  const auto equal = reinterpret_cast<Equal>(find("DM43TNBBfb0"));

  void *psplus = nullptr;
  void *psplus2 = nullptr;
  void *never = nullptr;
  void *empty = nullptr;
  void *unset = nullptr;
  const std::string long_text(40, 'x');
  void *long_str = nullptr;
  string_ctor(&psplus, "PSPLUS");
  string_ctor(&psplus2, "PSPLUS");
  string_ctor(&never, "NEVER");
  string_ctor(&empty, "");
  string_ctor(&long_str, long_text.c_str());
  Check(equal_cstr(&psplus, "PSPLUS") && !equal_cstr(&psplus, "NEVER") &&
            !equal_cstr(&psplus, "PSPLUSX") && equal_cstr(&empty, "") &&
            equal_cstr(&long_str, long_text.c_str()) && !equal_cstr(&unset, ""),
        "Json2 String==(const char*) compares short HLE strings and is false on an unset String");
  Check(equal(&psplus, &psplus2) && !equal(&psplus, &never) && !equal(&psplus, &unset) &&
            !equal(&unset, &unset),
        "Json2 String==(String) compares contents and is false when either side is unset");
  for (void **s : {&psplus, &psplus2, &never, &empty, &long_str}) {
    string_dtor(s);
  }

  using Iterator = const void *const *;
  using Ctor = void *(KYTY_SYSV_ABI *)(void *);
  using IntCtor = void *(KYTY_SYSV_ABI *)(void *, int64_t);
  using PushBack = void *(KYTY_SYSV_ABI *)(void *, const void *);
  using Bound = Iterator *(KYTY_SYSV_ABI *)(Iterator *, const void *);
  using Deref = const void *(KYTY_SYSV_ABI *)(const Iterator *);
  using Assign = Iterator *(KYTY_SYSV_ABI *)(Iterator *, const Iterator *);
  using GetInteger = const int64_t *(KYTY_SYSV_ABI *)(const void *);
  const auto array_ctor = reinterpret_cast<Ctor>(find("JP-PtKMiI1E"));
  const auto int_ctor = reinterpret_cast<IntCtor>(find("0lLK8+kDqmE"));
  const auto push_back = reinterpret_cast<PushBack>(find("zQtLRTqceMY"));
  const auto begin = reinterpret_cast<Bound>(find("bcH5EnFE2xY"));
  const auto end = reinterpret_cast<Bound>(find("WXF2ihRF+B8"));
  const auto deref = reinterpret_cast<Deref>(find("wcgr5mte7T8"));
  const auto arrow = reinterpret_cast<Deref>(find("iAIYn4oAWvI"));
  const auto assign = reinterpret_cast<Assign>(find("T3WReElX4BY"));
  const auto get_integer = reinterpret_cast<GetInteger>(find("DIxvoy7Ngvk"));
  const auto value_dtor = reinterpret_cast<Dtor>(find("WTtYf+cNnXI"));
  const auto array_dtor = reinterpret_cast<Dtor>(find("HJ8GpRT1aiw"));

  alignas(8) unsigned char array[8] {};
  alignas(8) unsigned char value[32] {};
  array_ctor(array);
  for (int64_t i = 3; i <= 4; i++) {
    int_ctor(value, i);
    push_back(array, value);
    value_dtor(value);
  }
  Iterator first = nullptr;
  Iterator last = nullptr;
  begin(&first, array);
  end(&last, array);
  const Iterator start = first;
  const Iterator second = first + 1;
  const void *first_value = deref(&first);
  Check(arrow(&first) == first_value && *get_integer(arrow(&second)) == 4,
        "Json2 Array::iterator-> returns the HLE element like operator*");
  Iterator copy = start;
  Check(assign(&copy, &second) == &copy && copy == second && deref(&start) == first_value &&
            *get_integer(deref(&start)) == 3 && assign(&copy, &last) == &copy && copy == last,
        "Json2 Array::iterator= copies the position without rewriting the array slot");

  // ShellCore's title metadata filter does it = erase(it) on non-string entries.
  using Erase = Iterator *(KYTY_SYSV_ABI *)(Iterator *, void *, const Iterator *);
  using PopFront = void (KYTY_SYSV_ABI *)(void *);
  using Size = size_t (KYTY_SYSV_ABI *)(const void *);
  const auto erase = reinterpret_cast<Erase>(find("2mbVAtshWRI"));
  const auto pop_front = reinterpret_cast<PopFront>(find("pPs3qZTZQvQ"));
  const auto size = reinterpret_cast<Size>(find("rQGJeNjOuUk"));
  for (int64_t i = 5; i <= 6; i++) {
    int_ctor(value, i);
    push_back(array, value);
    value_dtor(value);
  }
  begin(&first, array);
  Iterator next = nullptr;
  Check(erase(&next, array, &first) == &next && size(array) == 3 && *get_integer(deref(&next)) == 4,
        "Json2 Array::erase drops the element and returns the next one");
  end(&last, array);
  const Iterator tail = last - 1;
  Check(erase(&next, array, &tail) == &next && end(&last, array) == &last && next == last &&
            size(array) == 2,
        "Json2 Array::erase of the last element returns end");
  // ShellCore reads front() and then pops in its 32-entry and entitlement list caps.
  pop_front(array);
  begin(&first, array);
  Check(size(array) == 1 && *get_integer(deref(&first)) == 5, "Json2 pPs3qZTZQvQ drops the first element like the native list");
  pop_front(array);
  begin(&first, array);
  end(&last, array);
  Check(size(array) == 0 && first == last, "Json2 pPs3qZTZQvQ empties the array");
  pop_front(array);
  Check(size(array) == 0, "Json2 pPs3qZTZQvQ on an empty array is a no-op");
  array_dtor(array);
}

void TestJson2ArrayCopy() {
  Loader::SymbolDatabase symbols;
  Libs::LibJson2::InitNet_1_Json2(&symbols);
  const auto find = [&](const char *nid) {
    const auto *symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "Json2 array copy, assign and accessors are HLE");
    return symbol->vaddr;
  };
  using Ctor = void *(KYTY_SYSV_ABI *)(void *);
  using CopyCtor = void *(KYTY_SYSV_ABI *)(void *, const void *);
  using IntCtor = void *(KYTY_SYSV_ABI *)(void *, int64_t);
  using PushBack = void *(KYTY_SYSV_ABI *)(void *, const void *);
  using Get = const void *(KYTY_SYSV_ABI *)(const void *);
  using GetInteger = const int64_t *(KYTY_SYSV_ABI *)(const void *);
  using Size = size_t (KYTY_SYSV_ABI *)(const void *);
  using Empty = bool (KYTY_SYSV_ABI *)(const void *);
  using Mutate = void (KYTY_SYSV_ABI *)(void *);
  using SetArray = void (KYTY_SYSV_ABI *)(void *, const void *);
  using GetType = uint32_t (KYTY_SYSV_ABI *)(const void *);
  const auto array_ctor = reinterpret_cast<Ctor>(find("JP-PtKMiI1E"));
  const auto array_copy = reinterpret_cast<CopyCtor>(find("bI5AGFMydrA"));
  const auto array_assign = reinterpret_cast<CopyCtor>(find("w5UbvPLGye0"));
  const auto array_dtor = reinterpret_cast<Mutate>(find("HJ8GpRT1aiw"));
  const auto int_ctor = reinterpret_cast<IntCtor>(find("0lLK8+kDqmE"));
  const auto value_dtor = reinterpret_cast<Mutate>(find("WTtYf+cNnXI"));
  const auto push_back = reinterpret_cast<PushBack>(find("zQtLRTqceMY"));
  const auto front = reinterpret_cast<Get>(find("zcfZQyM7eAE"));
  const auto back = reinterpret_cast<Get>(find("bAM9Qwofus0"));
  const auto get_integer = reinterpret_cast<GetInteger>(find("DIxvoy7Ngvk"));
  const auto size = reinterpret_cast<Size>(find("rQGJeNjOuUk"));
  const auto empty = reinterpret_cast<Empty>(find("9uP25i6ipno"));
  const auto clear = reinterpret_cast<Mutate>(find("qVOSuDRHCpA"));
  const auto set_array = reinterpret_cast<SetArray>(find("195ad-jAsTU"));
  const auto get_type = reinterpret_cast<GetType>(find("SHtAad20YYM"));
  const auto get_array = reinterpret_cast<Get>(find("ONT8As5R1ug"));

  alignas(8) unsigned char src[8] {};
  alignas(8) unsigned char value[32] {};
  array_ctor(src);
  Check(empty(src) && size(src) == 0, "Json2 Array::empty on a new array");
  for (int64_t i = 1; i <= 3; i++) {
    int_ctor(value, i);
    push_back(src, value);
    value_dtor(value);
  }
  Check(!empty(src) && *get_integer(front(src)) == 1 && *get_integer(back(src)) == 3,
        "Json2 Array::front reads the first HLE element");

  alignas(8) unsigned char copy[8] {};
  array_copy(copy, src);
  Check(size(copy) == 3 && front(copy) != front(src) && *get_integer(front(copy)) == 1 &&
            *get_integer(back(copy)) == 3,
        "Json2 Array copy ctor deep-copies an HLE array");
  clear(src);
  Check(empty(src) && size(src) == 0 && size(copy) == 3, "Json2 Array::clear drops the elements of one array only");

  alignas(8) unsigned char unset[8] {};
  alignas(8) unsigned char from_unset[8] {};
  array_copy(from_unset, unset);
  Check(*reinterpret_cast<void **>(from_unset) == nullptr && empty(from_unset),
        "Json2 Array copy of an array with no impl has no impl, like native");

  int_ctor(value, 9);
  push_back(src, value);
  value_dtor(value);
  Check(array_assign(copy, src) == copy && size(copy) == 1 && *get_integer(front(copy)) == 9 &&
            front(copy) != front(src),
        "Json2 Array::operator= replaces the contents with a deep copy");
  Check(array_assign(copy, unset) == copy && size(copy) == 1 && array_assign(from_unset, src) == from_unset &&
            *reinterpret_cast<void **>(from_unset) == nullptr,
        "Json2 Array::operator= is a no-op when either side has no impl");

  int_ctor(value, 4);
  set_array(value, src);
  Check(get_type(value) == 6 && size(get_array(value)) == 1 && *get_integer(front(get_array(value))) == 9 &&
            front(get_array(value)) != front(src),
        "Json2 Value::set(Array) stores a copy and makes the value an array");
  set_array(value, unset);
  Check(get_type(value) == 6 && size(get_array(value)) == 1, "Json2 Value::set(Array) ignores an array with no impl");
  value_dtor(value);

  array_dtor(src);
  array_dtor(copy);
}

void CheckMountRoot(const std::filesystem::path &root) {
  Common::File cache;
  Check(cache.Create(root / "rpf.cache"), "create directory listing fixture");
  cache.Close();
  FileSystem::Mount(root, "/app0");
  Check(FileSystem::GetRealFilename("/app0/rpf.cache") == root / "rpf.cache",
        "resolve mount descendant");
  Check(FileSystem::GetRealFilename("/app01/rpf.cache").empty(),
        "mount prefix must end at a path component");

  for (const char *path : {"/app0", "/app0/"}) {
    for (const int flags : {0, 0x00020000}) {
      const int fd = FileSystem::KernelOpen(path, flags, 0);
      Check(fd >= 3, "open mounted root with O_RDONLY or O_DIRECTORY");
      std::array<char, 512> entries {};
      const int size = FileSystem::KernelGetdents(fd, entries.data(), entries.size());
      Check(size > 0 && size <= entries.size(), "enumerate mounted root");
      bool found = false;
      for (int offset = 0; offset < size;) {
        // Directory record: inode, record length, type, name length, name.
        Check(size - offset >= 8, "directory record header fits");
        uint16_t length = 0;
        std::memcpy(&length, entries.data() + offset + 4, sizeof(length));
        const auto name_length = static_cast<uint8_t>(entries[offset + 7]);
        Check(length >= 8 + name_length + 1 && length <= size - offset,
              "directory record and name fit");
        if (std::string_view(entries.data() + offset + 8, name_length) == "rpf.cache") {
          Check(entries[offset + 6] == 8, "cache directory entry is a regular file");
          found = true;
        }
        offset += length;
      }
      Check(found, "mounted root listing contains rpf.cache");
      Check(FileSystem::KernelClose(fd) == OK, "close mounted root");
    }
  }
  FileSystem::Umount("/app0");
  Check(FileSystem::GetRealFilename("/app0/rpf.cache").empty(),
        "unmount by guest path");
  for (const auto &folder : {root, root / ""}) {
    for (const auto &host : {root, root / ""}) {
      FileSystem::Mount(folder, "/app0");
      FileSystem::Umount(Common::PathToGenericString(host));
      Check(FileSystem::GetRealFilename("/app0/rpf.cache").empty(),
            "unmount by host path with or without trailing separator");
    }
  }
}

void CheckUnmappedPaths(const std::filesystem::path &root) {
  const auto host_file = root / "host-only.dat";
  const auto host_path = Common::PathToGenericString(host_file);
  Common::File fixture;
  Check(fixture.Create(host_file), "create unmapped host file");
  fixture.Close();

  FileSystem::FileStat stat {};
  Check(FileSystem::GetRealFilename(host_path).empty() &&
            FileSystem::KernelOpen(host_path.c_str(), 0, 0) ==
                Libs::LibKernel::KERNEL_ERROR_ENOENT &&
            FileSystem::KernelStat(host_path.c_str(), &stat) ==
                Libs::LibKernel::KERNEL_ERROR_ENOENT &&
            FileSystem::KernelCheckReachability(host_path.c_str()) ==
                Libs::LibKernel::KERNEL_ERROR_ENOENT,
        "existing host files are absent from the guest namespace");
  Check(FileSystem::KernelUnlink(host_path.c_str()) ==
            Libs::LibKernel::KERNEL_ERROR_ENOENT &&
            FileSystem::KernelRmdir(Common::PathToGenericString(root).c_str()) ==
                Libs::LibKernel::KERNEL_ERROR_ENOENT &&
            std::filesystem::exists(host_file),
        "unmapped host files and directories cannot be removed");

  const auto missing = Common::PathToGenericString(root / "unmapped-create");
  Check(FileSystem::KernelOpen(missing.c_str(), 0x601, 0777) ==
            Libs::LibKernel::KERNEL_ERROR_ENOENT &&
            FileSystem::KernelMkdir(missing.c_str(), 0777) ==
                Libs::LibKernel::KERNEL_ERROR_ENOENT &&
            !std::filesystem::exists(root / "unmapped-create"),
        "creation requires a mounted guest destination");

  FileSystem::Mount(root, "/app0");
  Check(FileSystem::KernelRename("/app0/host-only.dat", missing.c_str()) ==
            Libs::LibKernel::KERNEL_ERROR_ENOENT &&
            std::filesystem::exists(host_file) &&
            !std::filesystem::exists(root / "unmapped-create"),
        "rename to an unmapped destination preserves the source");
  FileSystem::Umount("/app0");
}

void CheckReadOnlyBacking(const std::filesystem::path &root) {
  namespace Kernel = Libs::LibKernel;
  const auto source = root / "original";
  const auto writable = root / "overlay";
  Check(std::filesystem::create_directories(source / "directory") &&
            std::filesystem::create_directories(writable), "create backing fixtures");
  constexpr char payload[] = "original bytes";
  Common::File fixture;
  Check(fixture.Create(source / "image.dat"), "create source fixture");
  fixture.Write(payload, sizeof(payload));
  fixture.Close();
  FileSystem::Mount(source, "/alias");
  const int previous = FileSystem::KernelOpen("/alias/image.dat", 2, 0);
  Check(previous >= 3, "open descriptor before protecting source");
  FileSystem::MountReadOnly(source, "/original");
  FileSystem::Mount(writable, "/overlay");
  Check(FileSystem::KernelOpen("/original/image.dat", 2, 0) == Kernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelOpen("/alias/image.dat", 0x401, 0) == Kernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelOpen("/original/new.dat", 0x601, 0777) == Kernel::KERNEL_ERROR_EROFS,
        "protected source and its writable alias reject modifications");
  Check(FileSystem::KernelOpen("/original/missing", 2, 0) == Kernel::KERNEL_ERROR_ENOENT,
        "non-create open preserves file-not-found");
  FileSystem::KernelIovec vector {const_cast<char*>(payload), sizeof(payload)};
  Check(FileSystem::KernelWrite(previous, payload, sizeof(payload)) == Kernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelPwrite(previous, payload, sizeof(payload), 0) == Kernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelPwritev(previous, &vector, 1, 0) == Kernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelFtruncate(previous, 0) == Kernel::KERNEL_ERROR_EROFS,
        "previous descriptors cannot modify protected backing");
  Check(FileSystem::KernelUnlink("/alias/image.dat") == Kernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelRename("/alias/image.dat", "/overlay/moved") == Kernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelMkdir("/original/new", 0777) == Kernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelRmdir("/original/directory") == Kernel::KERNEL_ERROR_EROFS,
        "source namespace operations reject writes");
  Check(FileSystem::GetRealFilename("/original/../../host-only.dat").empty() &&
            FileSystem::GetRealFilename("/original/../overlay/new.dat") == writable / "new.dat",
        "dot-dot traverses the guest namespace without exposing the host parent");
  std::error_code error;
  std::filesystem::create_directory_symlink(writable, source / "outside", error);
  if (!error) {
    Check(FileSystem::GetRealFilename("/original/outside/new.dat").empty(),
          "host links cannot escape the selected mount");
  } else {
    std::printf("KernelFileSystemTests: host-link fixture unavailable: %s\n", error.message().c_str());
  }
  std::array<char, sizeof(payload)> contents {};
  Check(FileSystem::KernelPread(previous, contents.data(), contents.size(), 0) == contents.size() &&
            std::memcmp(contents.data(), payload, contents.size()) == 0 &&
            FileSystem::KernelClose(previous) == OK, "protected source contents remain readable and unchanged");
  const int output = FileSystem::KernelOpen("/overlay/new.dat", 0x601, 0777);
  Check(output >= 3 && FileSystem::KernelWrite(output, payload, sizeof(payload)) == sizeof(payload) &&
            FileSystem::KernelClose(output) == OK, "separate writable backing remains usable");
  FileSystem::Umount("/original");
  Check(FileSystem::KernelOpen("/alias/image.dat", 2, 0) == Kernel::KERNEL_ERROR_EROFS,
        "unmount does not remove backing protection");
  FileSystem::Umount("/alias");
  FileSystem::Umount("/overlay");
}

void CheckIccnvs4Snapshot(const std::filesystem::path &root) {
#if defined(_WIN32)
  namespace Kernel = Libs::LibKernel;
  const char* configured = std::getenv("KYTY_PS5_ICCNVS4_IMAGE");
  const std::string saved = configured ? configured : "";
  const auto image = root / "icc-prefix-fixture.bin";
  std::vector<uint8_t> prefix(0xD82, 0xA7);
  prefix[0x23] = 0x5B;
  Common::File source;
  Check(source.Create(image), "create synthetic ICC prefix fixture");
  source.Write(prefix.data(), prefix.size()); source.Close();
  _putenv_s("KYTY_PS5_ICCNVS4_IMAGE", Common::PathToString(image).c_str());
  Check(FileSystem::KernelOpen("/dev/iccnvs4", 3, 0) == Kernel::KERNEL_ERROR_EINVAL &&
            FileSystem::KernelOpen("/dev/iccnvs4", 0x20000, 0) == Kernel::KERNEL_ERROR_ENOTDIR &&
            FileSystem::KernelOpen("/dev/iccnvs4", 1, 0) == Kernel::KERNEL_ERROR_EROFS,
        "snapshot rejects invalid, directory and pure write opens");
  const int fd = FileSystem::KernelOpen("/dev/iccnvs4", 0x10002, 0);
  Check(fd >= 3, "open ICC read contract against fixture");
  FileSystem::FileStat stat {};
  Check(FileSystem::KernelStat("/dev/iccnvs4", &stat) == OK && stat.st_mode == 020640 &&
            stat.st_uid == 0 && stat.st_gid == 5 && stat.st_size == 0 && stat.st_blocks == 0,
        "node metadata is independent of captured prefix file length");
  _putenv_s("KYTY_PS5_ICCNVS4_IMAGE", "");
  Check(FileSystem::KernelFstat(fd, &stat) == OK && stat.st_mode == 020640 && stat.st_gid == 5 && stat.st_size == 0,
        "descriptor retains ICC identity after configuration changes");
  std::array<uint8_t, 4> buffer {0xCC, 0xCC, 0xCC, 0xCC};
  const auto untouched = buffer;
  Check(FileSystem::KernelPread(fd, buffer.data(), 4, 0xD80) == Kernel::KERNEL_ERROR_EIO && buffer == untouched &&
            FileSystem::KernelPread(fd, buffer.data(), 1, prefix.size()) == Kernel::KERNEL_ERROR_EIO && buffer == untouched,
        "uncaptured and crossing reads fail without exposing stale destination bytes");
  FileSystem::KernelIovec vector {buffer.data(), buffer.size()};
  Check(FileSystem::KernelPreadv(fd, &vector, 1, 0xD80) == Kernel::KERNEL_ERROR_ENOTSUP && buffer == untouched &&
            FileSystem::KernelLseek(fd, 0, 2) == Kernel::KERNEL_ERROR_ENOTSUP,
        "unsupported vector and device-end operations do not bypass captured ranges");
  Check(FileSystem::KernelPread(fd, buffer.data(), 1, 0x23) == 1 && buffer[0] == prefix[0x23],
        "known byte read returns exact fixture byte");
  Check(FileSystem::KernelLseek(fd, 0xD80, 0) == 0xD80, "seek within captured prefix");
  buffer = untouched;
  Check(FileSystem::KernelRead(fd, buffer.data(), 4) == Kernel::KERNEL_ERROR_EIO && buffer == untouched &&
            FileSystem::KernelLseek(fd, 0, 1) == 0xD80,
        "failed sequential read preserves position and destination");
  Check(FileSystem::KernelRead(fd, buffer.data(), 2) == 2 && buffer[0] == prefix[0xD80] &&
            FileSystem::KernelPread(fd, reinterpret_cast<void*>(1), 1, 0x23) == Kernel::KERNEL_ERROR_EFAULT &&
            FileSystem::KernelPread(fd, nullptr, 0, 0x23) == 0 &&
            FileSystem::KernelRead(fd, nullptr, 0) == 0,
        "snapshot validates buffers and zero-length operations");
  Check(FileSystem::KernelPwrite(fd, buffer.data(), 1, 0x40) == Kernel::KERNEL_ERROR_EBADF,
        "immutable snapshot refuses writes");
  FileSystem::Mount(root, "/icc_fixture");
  const int target = FileSystem::KernelOpen("/icc_fixture/icc-prefix-fixture.bin", 0, 0);
  Check(target >= 3 && FileSystem::KernelDup2(fd, target) == Kernel::KERNEL_ERROR_ENOTSUP &&
            FileSystem::KernelFstat(target, &stat) == OK && stat.st_size == prefix.size() &&
            FileSystem::KernelDup2(fd, 0) == Kernel::KERNEL_ERROR_ENOTSUP &&
            FileSystem::KernelDup2(fd, fd) == fd && FileSystem::KernelClose(target) == OK,
        "unsupported aliases preserve destinations and self-dup remains valid");
  FileSystem::Umount("/icc_fixture");
  Check(FileSystem::KernelClose(fd) == OK && FileSystem::KernelPread(fd, buffer.data(), 1, 0x23) == Kernel::KERNEL_ERROR_EBADF,
        "closed ICC descriptor fails normally");
  Check(source.Open(image, Common::File::Mode::Read), "reopen fixture");
  std::vector<uint8_t> unchanged(prefix.size());
  source.Read(unchanged.data(), unchanged.size()); source.Close();
  Check(unchanged == prefix, "negative tests preserve source bytes");
  _putenv_s("KYTY_PS5_ICCNVS4_IMAGE", saved.c_str());
#endif
}

void CheckIccnvs4Overlay(const std::filesystem::path &root) {
#if defined(_WIN32)
  namespace Kernel = Libs::LibKernel;
  const std::array<const char*, 4> names {"KYTY_PS5_ICCNVS4_IMAGE", "KYTY_PS5_ICCNVS4_OVERLAY", "KYTY_PS5_ICCNVS4_SHA256", "KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS"};
  std::array<std::string, 4> saved;
  for (size_t i = 0; i < names.size(); ++i) { const char* value = std::getenv(names[i]); saved[i] = value ? value : ""; }
  const auto image = root / "icc-overlay-fixture.bin", overlay = root / "icc-state.kytycow";
  std::array<uint8_t, 1024> original {};
  for (size_t i = 0; i < original.size(); ++i) original[i] = static_cast<uint8_t>(i);
  Common::File source;
  Check(source.Create(image), "create synthetic ICC overlay fixture");
  source.Write(original.data(), original.size()); source.Close();
  _putenv_s(names[0], Common::PathToString(image).c_str());
  _putenv_s(names[1], Common::PathToString(overlay).c_str());
  _putenv_s(names[2], "");
  Check(FileSystem::KernelOpen("/dev/iccnvs4", 2, 0) == Kernel::KERNEL_ERROR_EINVAL && !std::filesystem::exists(overlay),
        "unbound writable profile cannot create storage");
  _putenv_s(names[2], "0000000000000000000000000000000000000000000000000000000000000000");
  Check(FileSystem::KernelOpen("/dev/iccnvs4", 2, 0) == Kernel::KERNEL_ERROR_EIO && !std::filesystem::exists(overlay),
        "wrong source hash fails before overlay creation");
  _putenv_s(names[2], "785b0751fc2c53dc14a4ce3d800e69ef9ce1009eb327ccf458afe09c242c26c9");
  const int fd = FileSystem::KernelOpen("/dev/iccnvs4", 0x10002, 0);
  Check(fd >= 3, "open SHA-bound writable ICC snapshot");
  uint8_t value = 0x39, actual = 0;
  void* guest_buffer = nullptr;
  Check(Kernel::Memory::KernelMapNamedFlexibleMemory(&guest_buffer, 0x4000, 3, 0, "icc_write_fixture") == OK,
        "allocate registered guest buffer for native writes");
  *static_cast<uint8_t*>(guest_buffer) = value;
  _putenv_s(names[3], "1");
  const auto native = Libs::NativeKernelBridge::DispatchSyscall({0x1dc, {static_cast<uint64_t>(fd), reinterpret_cast<uint64_t>(guest_buffer), 1, 0x40}});
  Check(native.value == 1 && native.posix_errno == 0 && FileSystem::KernelPread(fd, &actual, 1, 0x40) == 1 && actual == value,
        "native pwrite commits supplied byte into virtual overlay");
  Check(FileSystem::IsIccnvs4SnapshotDescriptor(fd), "native ICC descriptor retains captured backing identity");
  *static_cast<uint8_t*>(guest_buffer) = 0xA5;
  const auto native_read = Libs::NativeKernelBridge::DispatchSyscall({0x1db,
      {static_cast<uint64_t>(fd), reinterpret_cast<uint64_t>(guest_buffer), 1, 0x40}});
  Check(native_read.value == 1 && native_read.posix_errno == 0 &&
            *static_cast<uint8_t*>(guest_buffer) == value,
        "native ICC pread returns the backed byte");
  *static_cast<uint8_t*>(guest_buffer) = 0xA5;
  const auto native_unknown = Libs::NativeKernelBridge::DispatchSyscall({0x1db,
      {static_cast<uint64_t>(fd), reinterpret_cast<uint64_t>(guest_buffer), 1, original.size()}});
  Check(native_unknown.value == -1 && native_unknown.posix_errno == Libs::Posix::POSIX_EIO &&
            *static_cast<uint8_t*>(guest_buffer) == 0xA5,
        "native ICC pread preserves the destination for uncaptured ranges");
  const auto invalid = Libs::NativeKernelBridge::DispatchSyscall({0x1dc, {static_cast<uint64_t>(fd), 1, 1, 0x40}});
  Check(invalid.value == -1 && invalid.posix_errno == Libs::Posix::POSIX_EFAULT &&
            FileSystem::KernelPwrite(fd, &value, 1, original.size()) == Kernel::KERNEL_ERROR_EIO &&
            FileSystem::KernelPwrite(fd, &value, 1, -1) == Kernel::KERNEL_ERROR_EINVAL,
        "bad native buffer and uncaptured write ranges fail meaningfully");
  auto* mib = reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(guest_buffer) + 0x100);
  auto* oid = reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(guest_buffer) + 0x120);
  auto* length = reinterpret_cast<size_t*>(static_cast<uint8_t*>(guest_buffer) + 0x140);
  auto* name = reinterpret_cast<char*>(static_cast<uint8_t*>(guest_buffer) + 0x160);
  auto* safe_mode = reinterpret_cast<int32_t*>(static_cast<uint8_t*>(guest_buffer) + 0x180);
  mib[0] = 0; mib[1] = 3; *length = 104;
  std::memcpy(name, "kern.init_safe_mode", 19);
  const auto name_to_oid = Libs::NativeKernelBridge::DispatchSyscall(
      {0xca, {reinterpret_cast<uint64_t>(mib), 2, reinterpret_cast<uint64_t>(oid),
              reinterpret_cast<uint64_t>(length), reinterpret_cast<uint64_t>(name), 19}});
  Check(name_to_oid.value == 0 && name_to_oid.posix_errno == 0 && *length == 8 &&
            oid[0] == 1 && oid[1] == 0x7ffffebb,
        "safe-mode NAME2OID matches the 13.60 kernel object");
  *length = sizeof(*safe_mode); *safe_mode = -1;
  const auto safe_read = Libs::NativeKernelBridge::DispatchSyscall(
      {0xca, {reinterpret_cast<uint64_t>(oid), 2, reinterpret_cast<uint64_t>(safe_mode),
              reinterpret_cast<uint64_t>(length), 0, 0}});
  Check(safe_read.value == 0 && safe_read.posix_errno == 0 && *length == sizeof(*safe_mode) &&
            *safe_mode == original[0x20],
        "safe-mode read uses ICCNVS partition 4 offset 0x20");
  *safe_mode = 0xF1;
  const auto safe_write = Libs::NativeKernelBridge::DispatchSyscall(
      {0xca, {reinterpret_cast<uint64_t>(oid), 2, 0, 0,
              reinterpret_cast<uint64_t>(safe_mode), sizeof(*safe_mode)}});
  *safe_mode = -1; *length = sizeof(*safe_mode);
  const auto safe_read_back = Libs::NativeKernelBridge::DispatchSyscall(
      {0xca, {reinterpret_cast<uint64_t>(oid), 2, reinterpret_cast<uint64_t>(safe_mode),
              reinterpret_cast<uint64_t>(length), 0, 0}});
  Check(safe_write.value == 0 && safe_write.posix_errno == 0 &&
            safe_read_back.value == 0 && safe_read_back.posix_errno == 0 && *safe_mode == 0xF1,
        "safe-mode write persists through the ICCNVS overlay");
  *safe_mode = 0x100;
  const auto safe_invalid = Libs::NativeKernelBridge::DispatchSyscall(
      {0xca, {reinterpret_cast<uint64_t>(oid), 2, 0, 0,
              reinterpret_cast<uint64_t>(safe_mode), sizeof(*safe_mode)}});
  Check(safe_invalid.value == -1 && safe_invalid.posix_errno == Libs::Posix::POSIX_EINVAL,
        "safe-mode handler rejects values above one byte");
  int pipe[2] {-1, -1};
  Check(FileSystem::KernelPipe(pipe) == OK, "create native pwrite negative fixture");
  const auto nonseekable = Libs::NativeKernelBridge::DispatchSyscall({0x1dc,
      {static_cast<uint64_t>(pipe[0]), reinterpret_cast<uint64_t>(guest_buffer), 1, 0}});
  Check(nonseekable.value == -1 && nonseekable.posix_errno == Libs::Posix::POSIX_ESPIPE &&
            FileSystem::KernelWrite(pipe[0], &value, 1) == 1 &&
            FileSystem::KernelRead(pipe[1], &actual, 1) == 1 && actual == value &&
            FileSystem::KernelClose(pipe[0]) == OK && FileSystem::KernelClose(pipe[1]) == OK,
        "nonseekable native write fails without appending pipe data");
  Check(Kernel::Memory::KernelMunmap(reinterpret_cast<uint64_t>(guest_buffer), 0x4000) == OK,
        "release native write guest buffer");
  Check(FileSystem::KernelLseek(fd, 0x41, 0) == 0x41 && FileSystem::KernelWrite(fd, &value, 1) == 1 &&
            FileSystem::KernelLseek(fd, 0, 1) == 0x42 && FileSystem::KernelPread(fd, &actual, 1, 0x41) == 1 && actual == value,
        "sequential overlay writes advance only descriptor position");
  FileSystem::KernelIovec vector {&value, 1};
  uint64_t guessed_capacity = 0xA5;
  Check(FileSystem::KernelPwritev(fd, &vector, 1, 0x40) == Kernel::KERNEL_ERROR_ENOTSUP &&
            FileSystem::KernelFtruncate(fd, 0) == Kernel::KERNEL_ERROR_EINVAL &&
            FileSystem::KernelIoctl(fd, 0x40086481, &guessed_capacity) == Kernel::KERNEL_ERROR_ENOTTY && guessed_capacity == 0xA5,
        "prefix does not expose physical geometry or truncate source");
  FileSystem::FileStat stat {};
  Check(FileSystem::KernelFstat(fd, &stat) == OK && stat.st_mode == 020640 && stat.st_size == 0,
        "writable overlay remains a character node");
  const int reader = FileSystem::KernelOpen("/dev/iccnvs4", 0, 0);
  Check(reader >= 3 && FileSystem::KernelPread(reader, &actual, 1, 0x40) == 1 && actual == value &&
            FileSystem::KernelPwrite(reader, &value, 1, 0x40) == Kernel::KERNEL_ERROR_EBADF,
        "separate reader sees durable data while access flags are enforced");
  const auto native_close = Libs::NativeKernelBridge::DispatchSyscall({0x06, {static_cast<uint64_t>(reader)}});
  Check(native_close.value == 0 && native_close.posix_errno == 0 &&
            !FileSystem::IsIccnvs4SnapshotDescriptor(reader) && FileSystem::KernelClose(fd) == OK,
        "close overlay descriptors");
  const int reopened = FileSystem::KernelOpen("/dev/iccnvs4", 0x10002, 0);
  Check(reopened >= 3 && FileSystem::KernelPread(reopened, &actual, 1, 0x40) == 1 && actual == value &&
            FileSystem::KernelClose(reopened) == OK,
        "overlay survives descriptor lifetime");
  Check(source.Open(image, Common::File::Mode::Read), "verify original fixture");
  std::array<uint8_t, 1024> untouched {};
  source.Read(untouched.data(), untouched.size()); source.Close();
  Check(untouched == original, "overlay writes preserve all original source bytes");
  for (size_t i = 0; i < names.size(); ++i) _putenv_s(names[i], saved[i].c_str());
#endif
}

void CheckNativeSelfAuthInfo(const std::filesystem::path &root) {
  namespace AuthInfo = Libs::LibKernel::AuthInfo;
  namespace Kernel = Libs::LibKernel;
  namespace Process = Libs::LibKernel::Process;
  const char* configured = std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS");
  const bool configured_present = configured != nullptr;
  const std::string configured_value = configured_present ? configured : "";
  const char* guard = std::getenv("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS");
  const bool guard_present = guard != nullptr;
  const std::string guard_value = guard_present ? guard : "";
  const char* provider_audit = std::getenv("KYTY_DIAGNOSTIC_READ_ONLY_PROVIDER_IO_AUDIT");
  const bool provider_audit_present = provider_audit != nullptr;
  const std::string provider_audit_value = provider_audit_present ? provider_audit : "";
  Check(Log::EscapeField("literal\\x0a") == "literal\\x5cx0a" &&
            Log::EscapeField("literal\n") == "literal\\x0a",
        "log field escaping distinguishes literal and encoded control bytes");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1") == 0,
        "enable self auth info fixture");
#else
  Check(setenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1", 1) == 0,
        "enable self auth info fixture");
#endif
  const auto fixture_root = root / "self-auth-info";
  Check(std::filesystem::create_directory(fixture_root),
        "create self auth info fixture directory");
  std::vector<uint8_t> image(0x280);
  Loader::Elf64_Ehdr elf_header {};
  std::memcpy(elf_header.e_ident, "\177ELF", 4);
  elf_header.e_ident[Loader::EI_CLASS] = Loader::ELFCLASS64;
  elf_header.e_ident[Loader::EI_DATA] = Loader::ELFDATA2LSB;
  elf_header.e_ehsize = sizeof(elf_header);
  elf_header.e_phoff = sizeof(elf_header);
  elf_header.e_phentsize = sizeof(Loader::Elf64_Phdr);
  elf_header.e_phnum = 1;
  Loader::Elf64_Phdr program_header {};
  program_header.p_type = Loader::PT_LOAD;
  program_header.p_flags = Loader::PF_R | Loader::PF_X;
  program_header.p_filesz = image.size();
  program_header.p_memsz = image.size();
  program_header.p_align = 0x10;
  std::memcpy(image.data(), &elf_header, sizeof(elf_header));
  std::memcpy(image.data() + elf_header.e_phoff, &program_header,
              sizeof(program_header));
  for (size_t i = sizeof(elf_header) + sizeof(program_header);
       i != image.size(); ++i)
    image[i] = static_cast<uint8_t>(i * 29 + 7);
  auto write = [](const std::filesystem::path& path,
                  const std::vector<uint8_t>& bytes) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
    file.close();
    Check(static_cast<bool>(file), "write self auth info fixture");
  };
  write(fixture_root / "current.elf", image);
  auto other = image;
  other.back() ^= 1;
  write(fixture_root / "other.elf", other);
  auto oversized = image;
  oversized.push_back(0x42);
  write(fixture_root / "oversized.elf", oversized);
  const std::string logged_name = "logged-\x7f.elf";
  write(fixture_root / Common::PathFromUtf8(logged_name), image);
  const std::string provider_name = "provider-\x7f-\xe2\x80\xa8.elf";
  write(fixture_root / Common::PathFromUtf8(provider_name), image);
  std::vector<uint8_t> malformed(64);
  std::memcpy(malformed.data(), "\177ELF", 4);
  write(fixture_root / "malformed.elf", malformed);
  std::vector<uint8_t> malformed_self(0x180);
  Loader::SelfHeader self_header {};
  std::memcpy(self_header.ident, "\x54\x14\xf5\xee", 4);
  self_header.size1 = 0x100;
  self_header.size2 = 0x80;
  self_header.file_size = malformed_self.size();
  self_header.segments_num = 1;
  std::memcpy(malformed_self.data(), &self_header, sizeof(self_header));
  Loader::SelfSegment self_segment {};
  self_segment.offset = malformed_self.size() - 0x10;
  self_segment.compressed_size = 0x20;
  std::memcpy(malformed_self.data() + sizeof(self_header), &self_segment,
              sizeof(self_segment));
  std::memcpy(malformed_self.data() + sizeof(self_header) + sizeof(self_segment),
              &elf_header, sizeof(elf_header));
  write(fixture_root / "malformed.self", malformed_self);
  std::vector<uint8_t> invalid(32, 0xa5);
  write(fixture_root / "invalid.bin", invalid);
  FileSystem::Mount(fixture_root, "/selfauth");
  Check(Kernel::DirectoryPassthrough::Mount("/selfauthpt", fixture_root) == OK,
        "mount self auth info passthrough fixture");

  void* guest = nullptr;
  Check(Kernel::Memory::KernelMapNamedFlexibleMemory(
            &guest, 0x4000, 3, 0, "self_auth_info_fixture") == OK,
        "map self auth info guest fixture");
  auto* bytes = static_cast<uint8_t*>(guest);
  auto* path = reinterpret_cast<char*>(bytes + 0x100);
  auto* output = reinterpret_cast<AuthInfo::Record*>(bytes + 0x400);
  auto set_path = [&](const char* value) {
    std::memset(path, 0, 0x100);
    std::memcpy(path, value, std::strlen(value) + 1);
    output->fill(0xa5);
  };
  auto invoke = [&] {
    return Libs::NativeKernelBridge::DispatchSyscall(
        {0x25f, {reinterpret_cast<uint64_t>(path),
                 reinterpret_cast<uint64_t>(output)}});
  };
  auto untouched = [&] {
    return std::all_of(output->begin(), output->end(),
                       [](uint8_t value) { return value == 0xa5; });
  };

  set_path("/selfauth/current.elf");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "") == 0,
        "disable self auth info fixture");
#else
  Check(unsetenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == 0,
        "disable self auth info fixture");
#endif
  const auto disabled = invoke();
  Check(disabled.value == -1 &&
            disabled.posix_errno == Libs::Posix::POSIX_ENOSYS && untouched(),
        "self auth info remains disabled without the diagnostic gate");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1") == 0,
        "reenable self auth info fixture");
#else
  Check(setenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1", 1) == 0,
        "reenable self auth info fixture");
#endif

  Process::ClearVerifiedOriginalSelf();
  set_path("/selfauth/current.elf");
  const auto no_identity = invoke();
  Check(no_identity.value == -1 &&
            no_identity.posix_errno == Libs::Posix::POSIX_ENOSYS && untouched(),
        "self auth info requires an installed image identity");

  AuthInfo::ImageIdentity identity {};
  identity.authority_id = 0x4800000000000007ull;
  identity.self_size = 4;
  identity.elf_size = image.size();
  identity.self_sha256 = AuthInfo::Sha256("self", 4);
  identity.elf_sha256 = AuthInfo::Sha256(image.data(), image.size());
  Process::InstallVerifiedOriginalSelf(identity);
  const auto no_capture = invoke();
  Check(no_capture.value == -1 &&
            no_capture.posix_errno == Libs::Posix::POSIX_ENOSYS && untouched(),
        "self auth info requires a verified image-bound capture");

  AuthInfo::Record record {};
  auto store64 = [](uint8_t* destination, uint64_t value) {
    for (uint32_t i = 0; i != 8; ++i)
      destination[i] = static_cast<uint8_t>(value >> (i * 8));
  };
  store64(record.data(), identity.authority_id);
  store64(record.data() + 0x28, UINT64_MAX);
  store64(record.data() + 0x38, 4);
  AuthInfo::Capture capture {};
  std::string reason;
  Check(AuthInfo::BuildCaptureEnvelope(record, identity, &capture, &reason) &&
            Process::InstallVerifiedAuthInfo(capture),
        "install self auth info fixture capture");
  AuthInfo::Record expected {};
  Check(AuthInfo::FilterSelfAuthInfo(record, record, &expected),
        "filter self auth info fixture");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS", "1") == 0,
        "enable get_self_auth_info export fixture");
#else
  Check(setenv("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS", "1", 1) == 0,
        "enable get_self_auth_info export fixture");
#endif
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* symbol = symbols.FindByNid("p2xgfB-30g8", Loader::SymbolType::Func);
  Check(symbol != nullptr, "resolve get_self_auth_info export");
  using GetSelfAuthInfo = int (KYTY_SYSV_ABI *)(const char*, void*);
  const auto get_self_auth_info =
      reinterpret_cast<GetSelfAuthInfo>(symbol->vaddr);
  const int success = get_self_auth_info(path, output);
  Check(success == 0 && *output == expected &&
            (*output)[0x38] == 4 && (*output)[0] == 0,
        "get_self_auth_info export returns only the kernel-filtered matching capture");

  const auto path_log = fixture_root / "guest-path-audit.log";
  Config::ConfigOptions log_options;
  log_options.printf_direction = Config::LogDirection::File;
  log_options.printf_output_file = path_log;
  Config::Load(log_options);
  Log::Initialize();
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_READ_ONLY_PROVIDER_IO_AUDIT", "1") == 0,
        "enable read only provider audit");
#else
  Check(setenv("KYTY_DIAGNOSTIC_READ_ONLY_PROVIDER_IO_AUDIT", "1", 1) == 0,
        "enable read only provider audit");
#endif
  const std::string logged_guest = "/selfauth/" + logged_name;
  set_path(logged_guest.c_str());
  const auto logged = invoke();
  Check(logged.value == 0 && logged.posix_errno == 0 && *output == expected,
        "self auth info accepts matching image with a log control byte");
  const std::string provider_guest = "/selfauthpt/" + provider_name;
  set_path(provider_guest.c_str());
  const auto provider = invoke();
  Check(provider.value == 0 && provider.posix_errno == 0 && *output == expected,
        "self auth info accepts matching passthrough image with log control bytes");
  set_path("/selfauth/missing:\nFORGED_AUTHINFO_LOG_ENTRY\xe2\x80\xa8UNICODE_BREAK");
  const auto injected = invoke();
  Check(injected.value == -1 &&
            injected.posix_errno == Libs::Posix::POSIX_ENOENT && untouched(),
        "self auth info rejects a missing control-character path without output");
  Log::Flush();
  Log::Shutdown();
  Common::File captured_log(path_log, Common::File::Mode::Read);
  Check(!captured_log.IsInvalid(), "open self auth info path audit log");
  const auto captured_bytes = captured_log.ReadWholeBuffer();
  const std::string captured_text(
      reinterpret_cast<const char*>(captured_bytes.data()), captured_bytes.size());
  Check(captured_text.find("\nFORGED_AUTHINFO_LOG_ENTRY") == std::string::npos &&
            captured_text.find("\\x0aFORGED_AUTHINFO_LOG_ENTRY") != std::string::npos &&
            captured_text.find("\\xe2\\x80\\xa8UNICODE_BREAK") != std::string::npos &&
            captured_text.find("\\x7f.elf") != std::string::npos &&
            captured_text.find("READ_ONLY_PROVIDER_IO operation=open path=/selfauthpt/provider-\\x7f-\\xe2\\x80\\xa8.elf") != std::string::npos &&
            captured_text.find('\x7f') == std::string::npos &&
            captured_text.find("\xe2\x80\xa8") == std::string::npos,
        "self auth info path logs escape line and control characters");
  log_options.printf_direction = Config::LogDirection::Silent;
  log_options.printf_output_file.clear();
  Config::Load(log_options);
  Log::Initialize();

  set_path("/selfauth/other.elf");
  const auto wrong_image = invoke();
  Check(wrong_image.value == -1 &&
            wrong_image.posix_errno == Libs::Posix::POSIX_ENOSYS && untouched(),
        "self auth info rejects a different valid image without output");
  set_path("/selfauth/oversized.elf");
  const auto oversized_image = invoke();
  Check(oversized_image.value == -1 &&
            oversized_image.posix_errno == Libs::Posix::POSIX_ENOSYS && untouched(),
        "self auth info rejects a valid oversized image before full-image admission");
  set_path("/selfauth/malformed.elf");
  const auto malformed_image = invoke();
  Check(malformed_image.value == -1 &&
            malformed_image.posix_errno == Libs::Posix::POSIX_ENOEXEC && untouched(),
        "self auth info rejects a malformed ELF without output");
  set_path("/selfauth/malformed.self");
  const auto malformed_self_image = invoke();
  Check(malformed_self_image.value == -1 &&
            malformed_self_image.posix_errno == Libs::Posix::POSIX_ENOEXEC && untouched(),
        "self auth info validates bounded SELF segment headers before the identity size gate");
  set_path("/selfauth/invalid.bin");
  const auto invalid_image = invoke();
  Check(invalid_image.value == -1 &&
            invalid_image.posix_errno == Libs::Posix::POSIX_ENOEXEC && untouched(),
        "self auth info rejects a non executable without output");
  set_path("/selfauth");
  const auto directory = invoke();
  Check(directory.value == -1 &&
            directory.posix_errno == Libs::Posix::POSIX_EINVAL && untouched(),
        "self auth info rejects a directory without output");
  set_path("/selfauth/current.elf");
  *Libs::Posix::GetErrorAddr() = 0;
  Check(get_self_auth_info(path, reinterpret_cast<void*>(1)) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT,
        "get_self_auth_info export validates the complete output range");

  Process::ClearVerifiedOriginalSelf();
  Check(Kernel::Memory::KernelMunmap(reinterpret_cast<uint64_t>(guest), 0x4000) == OK,
        "unmap self auth info guest fixture");
  FileSystem::Umount("/selfauth");
  Check(Kernel::DirectoryPassthrough::Unmount("/selfauthpt") == OK,
        "unmount self auth info passthrough fixture");
#if defined(_WIN32)
  Check(_putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS",
                  configured_present ? configured_value.c_str() : "") == 0,
        "restore self auth info fixture environment");
  Check(_putenv_s("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS",
                  guard_present ? guard_value.c_str() : "") == 0,
        "restore get_self_auth_info export environment");
  Check(_putenv_s("KYTY_DIAGNOSTIC_READ_ONLY_PROVIDER_IO_AUDIT",
                  provider_audit_present ? provider_audit_value.c_str() : "") == 0,
        "restore read only provider audit environment");
#else
  Check(configured_present
            ? setenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS",
                     configured_value.c_str(), 1) == 0
            : unsetenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS") == 0,
        "restore self auth info fixture environment");
  Check(guard_present
            ? setenv("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS",
                     guard_value.c_str(), 1) == 0
            : unsetenv("KYTY_DIAGNOSTIC_GUARD_RAW_LIBKERNEL_SYSCALLS") == 0,
        "restore get_self_auth_info export environment");
  Check(provider_audit_present
            ? setenv("KYTY_DIAGNOSTIC_READ_ONLY_PROVIDER_IO_AUDIT",
                     provider_audit_value.c_str(), 1) == 0
            : unsetenv("KYTY_DIAGNOSTIC_READ_ONLY_PROVIDER_IO_AUDIT") == 0,
        "restore read only provider audit environment");
#endif
}

void CheckNativeIpmiTraceHooks() {
#if defined(_WIN32)
  namespace Kernel = Libs::LibKernel;
  const char* configured = std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS");
  const std::string saved = configured ? configured : "";
  void* guest_buffer = nullptr;
  Check(Kernel::Memory::KernelMapNamedFlexibleMemory(&guest_buffer, 0x4000, 3, 0, "ipmi_trace_fixture") == OK,
        "allocate native IPMI trace fixture");
  auto* bytes = static_cast<uint8_t*>(guest_buffer);
  auto* result_word = reinterpret_cast<uint32_t*>(bytes);
  std::memset(bytes + 0x40, 0xA5, 0x40);
  _putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1");
  for (uint64_t suboperation = 0x1f00; suboperation <= 0x1f05; ++suboperation) {
    *result_word = 0xFFFFFFFFu;
    const auto reply = Libs::NativeKernelBridge::DispatchSyscall(
        {0x26e, {0x10, suboperation, reinterpret_cast<uint64_t>(result_word),
                 reinterpret_cast<uint64_t>(bytes + 0x40), 0x40, 0}});
    Check(reply.value == 0 && reply.posix_errno == 0 && *result_word == 0,
          "native IPMI trace hook completes without blocking");
  }
  *result_word = 0xA5A5A5A5u;
  const auto bad_record = Libs::NativeKernelBridge::DispatchSyscall(
      {0x26e, {0x10, 0x1f02, reinterpret_cast<uint64_t>(result_word), 1, 0x40, 0}});
  const auto receive = Libs::NativeKernelBridge::DispatchSyscall(
      {0x26e, {0x201, 1, reinterpret_cast<uint64_t>(result_word),
               reinterpret_cast<uint64_t>(bytes + 0x40), 0x20, 0}});
  Check(bad_record.value == -1 && bad_record.posix_errno == Libs::Posix::POSIX_EFAULT &&
            *result_word == 0xA5A5A5A5u && receive.value == -1 && receive.posix_errno == Libs::Posix::POSIX_ENOSYS,
        "trace validation does not add receive support");
  const uint64_t name_pointer = reinterpret_cast<uint64_t>(bytes + 0x100);
  std::memcpy(bytes + 0x40, &name_pointer, sizeof(name_pointer));
  *result_word = 0xffffffffu;
  const auto failed_name = Libs::NativeKernelBridge::DispatchSyscall(
      {0x26e, {0x46a, 0x8002004e, reinterpret_cast<uint64_t>(result_word),
               reinterpret_cast<uint64_t>(bytes + 0x40), 8, 0}});
  Check(failed_name.value == -1 && failed_name.posix_errno == Libs::Posix::POSIX_EBADF &&
        *result_word == 0xffffffffu && bytes[0x100] == 0,
        "native IPMI failed-server name query leaves outputs untouched");
  // SysAv trap and HLE entry share the IPMI manager
  const uint64_t user_data_pointer = reinterpret_cast<uint64_t>(bytes + 0x100);
  std::memcpy(bytes + 0x40, &user_data_pointer, sizeof(user_data_pointer));
  std::memset(bytes + 0x100, 0x5a, 8);
  *result_word = 0xA5A5A5A5u;
  const Libs::NativeKernelBridge::SyscallRequest user_data_call {
      0x26e, {0x468, 0x30000fff, reinterpret_cast<uint64_t>(result_word), reinterpret_cast<uint64_t>(bytes + 0x40), 8, 0}};
  const auto legacy_user_data = Libs::NativeKernelBridge::DispatchSyscall(user_data_call);
  const char* original_ipmi = std::getenv("KYTY_DIAGNOSTIC_ORIGINAL_SYSCORE_APP_IPMI");
  const std::string saved_original_ipmi = original_ipmi ? original_ipmi : "";
  _putenv_s("KYTY_DIAGNOSTIC_ORIGINAL_SYSCORE_APP_IPMI", "1");
  const auto trapped = Libs::NativeKernelBridge::DispatchSyscall(user_data_call);
  auto* direct_result = reinterpret_cast<int32_t*>(bytes + 0x200);
  *direct_result = static_cast<int32_t>(0xA5A5A5A5u);
  int direct_status = 0;
  *Libs::Posix::GetErrorAddr() = 0;
  const bool direct = Kernel::IpmiManager::TryCall(0x468, 0x30000fff, direct_result, bytes + 0x40, 8, 0, &direct_status) &&
                      direct_status == -1 && *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOENT;
  const auto trapped_fault = Libs::NativeKernelBridge::DispatchSyscall(
      {0x26e, {0x468, 0x30000fff, reinterpret_cast<uint64_t>(result_word), 1, 8, 0}});
  _putenv_s("KYTY_DIAGNOSTIC_ORIGINAL_SYSCORE_APP_IPMI", saved_original_ipmi.c_str());
  Check(legacy_user_data.value == -1 && legacy_user_data.posix_errno == Libs::Posix::POSIX_ENOSYS &&
            trapped.value == -1 && trapped.posix_errno == Libs::Posix::POSIX_ENOENT && direct &&
            *direct_result == static_cast<int32_t>(0xA5A5A5A5u) && trapped_fault.value == -1 &&
            trapped_fault.posix_errno == Libs::Posix::POSIX_EFAULT && *result_word == 0xA5A5A5A5u &&
            bytes[0x100] == 0x5a && bytes[0x107] == 0x5a,
        "SysAv 0x468 trap and the HLE manager answer the same and leave outputs untouched");
  _putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", saved.c_str());
  Check(Kernel::Memory::KernelMunmap(reinterpret_cast<uint64_t>(guest_buffer), 0x4000) == OK,
        "release native IPMI trace fixture");
#endif
}

void CheckSectorDescriptors(const std::filesystem::path &root) {
#if defined(_WIN32)
  namespace Kernel = Libs::LibKernel;
  using Backing = Kernel::SectorBacking;
  const auto image = root / "sectors.bin", overlay = root / "sectors.kytycow";
  std::array<uint8_t, 1024> original {};
  for (size_t i = 0; i < original.size(); ++i) original[i] = static_cast<uint8_t>(i);
  Common::File source;
  Check(source.Create(image), "create diagnostic sector fixture");
  source.Write(original.data(), original.size()); source.Close();
  Backing::Result result;
  const char* hash = "785b0751fc2c53dc14a4ce3d800e69ef9ce1009eb327ccf458afe09c242c26c9";
  std::shared_ptr<Backing> backing = Backing::Open(image, overlay, 512, 2048, hash, &result);
  std::shared_ptr<Backing> read_only = Backing::Open(image, {}, 512, 2048, hash, &result);
  Check(backing && read_only &&
            FileSystem::RegisterDiagnosticSectorPayload("/dev/ssd0.system_b", backing) == OK &&
            FileSystem::RegisterDiagnosticSectorPayload("/dev/ssd0.system_ex_b", read_only) == OK &&
            FileSystem::RegisterDiagnosticSectorPayload("/dev/ssd0.system_b", backing) == Kernel::KERNEL_ERROR_EEXIST &&
            FileSystem::RegisterDiagnosticSectorPayload("/dev/ssd0.swapx2", backing) == Kernel::KERNEL_ERROR_EINVAL,
        "diagnostic registration publishes no swap storage or duplicate providers");
  const char* previous_a53 = std::getenv("KYTY_DIAGNOSTIC_A53_STORAGE");
  const std::string saved_a53 = previous_a53 ? previous_a53 : "";
  _putenv_s("KYTY_DIAGNOSTIC_A53_STORAGE", "1");
  uint32_t a53_input = 1;
  uint32_t ignored_enable_input = 0xdeadbeefu;
  const int a53 = FileSystem::KernelOpen("/dev/a53io", 0, 0);
  const int nsid = FileSystem::KernelOpen("/dev/nsid1.ctl", 2, 0);
  FileSystem::FileStat unpublished {};
  Check(FileSystem::KernelOpen("/dev/ssd0.bd_rvlist", 0, 0) == Kernel::KERNEL_ERROR_ENOENT &&
            FileSystem::KernelStat("/dev/ssd0.swapx2", &unpublished) == Kernel::KERNEL_ERROR_ENOENT,
        "diagnostic SSD providers remain absent before namespace creation");
  Check(a53 >= 3 && nsid >= 3 && FileSystem::KernelIoctl(a53, 0x80046101, &a53_input) == OK &&
            FileSystem::KernelIoctl(nsid, 0x20003102, nullptr) == OK &&
            FileSystem::KernelIoctl(a53, 0x80046103, &ignored_enable_input) == OK &&
            FileSystem::KernelIoctl(a53, 0x80046103, &ignored_enable_input) == Kernel::KERNEL_ERROR_EALREADY &&
            FileSystem::KernelClose(a53) == OK && FileSystem::KernelClose(nsid) == OK,
        "diagnostic controller publishes its bounded namespace");
  const std::array<const char*, 17> observed_ssd_devices = {
      "/dev/ssd0", "/dev/ssd0.preinst", "/dev/ssd0.system", "/dev/ssd0.system_b",
      "/dev/ssd0.system_ex", "/dev/ssd0.system_ex_b", "/dev/ssd0.swap", "/dev/ssd0.system_data",
      "/dev/ssd0.update", "/dev/ssd0.user", "/dev/ssd0.app_temp0", "/dev/ssd0.app_swap",
      "/dev/ssd0.hibernation", "/dev/ssd0.bd_rvlist", "/dev/ssd0.swapx0", "/dev/ssd0.swapx1",
      "/dev/ssd0.swapx2"};
  for (const char* device: observed_ssd_devices) {
    FileSystem::FileStat path_stat {}, fd_stat {};
    const int media = FileSystem::KernelOpen(device, 0, 0);
    const int path_result = FileSystem::KernelStat(device, &path_stat);
    const int fd_result = media >= 3 ? FileSystem::KernelFstat(media, &fd_stat) : Kernel::KERNEL_ERROR_EBADF;
    const int close_result = media >= 3 ? FileSystem::KernelClose(media) : Kernel::KERNEL_ERROR_EBADF;
    Check(media >= 3 && path_result == OK &&
              path_stat.st_mode == 020640 && path_stat.st_size == 0 && path_stat.st_blocks == 0 &&
              path_stat.st_blksize == 16384 && fd_result == OK &&
              fd_stat.st_mode == 020640 && fd_stat.st_size == 0 && fd_stat.st_blocks == 0 &&
              fd_stat.st_blksize == 16384 && close_result == OK,
          device);
  }
  const int bd_rvlist = FileSystem::KernelOpen("/dev/ssd0.bd_rvlist", 0, 0);
  uint64_t bd_rvlist_capacity = 0;
  Check(bd_rvlist >= 3 && FileSystem::KernelIoctl(bd_rvlist, 0x40086481, &bd_rvlist_capacity) == OK &&
            bd_rvlist_capacity == 0x100000 && FileSystem::KernelClose(bd_rvlist) == OK,
        "bd_rvlist geometry matches the Mini-SysCore type-7 table");
  const std::array<std::pair<const char*, uint64_t>, 4> swap_geometry {{
      {"/dev/ssd0.swap", 0x200000000ull}, {"/dev/ssd0.swapx0", 0x1fff00000ull},
      {"/dev/ssd0.swapx1", 0x7fe00ull}, {"/dev/ssd0.swapx2", 0x80000ull}}};
  for (const auto& [device, expected]: swap_geometry) {
    const int media = FileSystem::KernelOpen(device, 0, 0);
    uint64_t capacity = 0;
    Check(media >= 3 && FileSystem::KernelIoctl(media, 0x40086481, &capacity) == OK &&
              capacity == expected && FileSystem::KernelClose(media) == OK,
          device);
  }
  Check(FileSystem::KernelOpen("/dev/ssd0.app_temp1", 0, 0) == Kernel::KERNEL_ERROR_ENOENT &&
            FileSystem::KernelStat("/dev/ssd0.app_temp1", &unpublished) == Kernel::KERNEL_ERROR_ENOENT &&
            FileSystem::KernelOpen("/dev/ssd0.not_real", 0, 0) == Kernel::KERNEL_ERROR_ENOENT,
        "diagnostic controller registers no unobserved partition providers");
  _putenv_s("KYTY_DIAGNOSTIC_A53_STORAGE", saved_a53.c_str());
  const int fd = FileSystem::KernelOpen("/dev/ssd0.system_b", 2, 0);
  Check(fd >= 3 && FileSystem::KernelOpen("/dev/ssd0.system_ex_b", 2, 0) == Kernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelOpen("/dev/ssd0.system_b", 0x601, 0777) == Kernel::KERNEL_ERROR_EINVAL &&
            FileSystem::KernelOpen("/dev/ssd0.system_b", 3, 0) == Kernel::KERNEL_ERROR_EINVAL &&
            FileSystem::KernelOpen("/dev/ssd0.system_b", 0x20002, 0) == Kernel::KERNEL_ERROR_ENOTDIR &&
            FileSystem::KernelOpen("/dev/../dev/ssd0.system_b", 0x20200, 0777) == Kernel::KERNEL_ERROR_EINVAL &&
            FileSystem::KernelDup2(fd, fd) == fd && FileSystem::KernelDup2(fd, 1) == Kernel::KERNEL_ERROR_ENOTSUP,
        "diagnostic media descriptors enforce access and fixed volume lifetime");
  uint32_t sector_size = 0; uint64_t capacity = 0;
  uint32_t nand_for_t = 0xa5a5a5a5;
  Check(FileSystem::KernelIoctl(fd, 0x40046480, &sector_size) == OK && sector_size == 512 &&
            FileSystem::KernelIoctl(fd, 0x40086481, &capacity) == OK && capacity == 2048 &&
            FileSystem::KernelIoctl(fd, 0x40046480, reinterpret_cast<void*>(1)) == Kernel::KERNEL_ERROR_EFAULT &&
            FileSystem::KernelIoctl(fd, 0x40086481, nullptr) == Kernel::KERNEL_ERROR_EFAULT &&
            FileSystem::KernelIoctl(fd, 0x40086481, reinterpret_cast<void*>(UINTPTR_MAX - 3)) == Kernel::KERNEL_ERROR_EFAULT &&
            FileSystem::KernelIoctl(fd, 0x40043105, &nand_for_t) == Kernel::KERNEL_ERROR_ENOTTY && nand_for_t == 0xa5a5a5a5 &&
            FileSystem::KernelIoctl(fd, 0x80046103, nullptr) == Kernel::KERNEL_ERROR_ENOTTY,
        "media queries report configured geometry without implementing a controller ioctl");
  SYSTEM_INFO system {};
  GetSystemInfo(&system);
  auto* guarded = static_cast<uint8_t*>(VirtualAlloc(nullptr, 2 * system.dwPageSize,
                                                    MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  Check(guarded != nullptr, "allocate geometry output span fixture");
  std::memset(guarded, 0xa5, 2 * system.dwPageSize);
  DWORD previous = 0;
  Check(VirtualProtect(guarded + system.dwPageSize, system.dwPageSize, PAGE_READONLY, &previous),
        "protect geometry output tail");
  auto* crossing = guarded + system.dwPageSize - 4;
  Check(FileSystem::KernelIoctl(fd, 0x40086481, crossing) == Kernel::KERNEL_ERROR_EFAULT &&
            FileSystem::KernelIoctl(fd, 0x40086481, guarded + system.dwPageSize) == Kernel::KERNEL_ERROR_EFAULT &&
            std::all_of(crossing, crossing + 8, [](uint8_t byte) { return byte == 0xa5; }),
        "u64 media query validates its complete writable output before modifying any byte");
  const char* previous_flag = std::getenv("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS");
  const std::string saved_flag = previous_flag ? previous_flag : "";
  _putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1");
  capacity = 0;
  const auto native_info = Libs::NativeKernelBridge::DispatchSyscall({0x36, {static_cast<uint64_t>(fd), 0x40086481, reinterpret_cast<uint64_t>(&capacity)}});
  const auto bad_output = Libs::NativeKernelBridge::DispatchSyscall({0x36, {static_cast<uint64_t>(fd), 0x40086481, 1}});
  const auto bad_span = Libs::NativeKernelBridge::DispatchSyscall({0x36, {static_cast<uint64_t>(fd), 0x40086481, reinterpret_cast<uint64_t>(crossing)}});
  const auto unknown_metadata = Libs::NativeKernelBridge::DispatchSyscall({0x36, {static_cast<uint64_t>(fd), 0x40043105, reinterpret_cast<uint64_t>(&nand_for_t)}});
  const auto unsupported = Libs::NativeKernelBridge::DispatchSyscall({0x36, {static_cast<uint64_t>(fd), 0x80046103, 0}});
  _putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", saved_flag.c_str());
  Check(native_info.value == 0 && capacity == 2048 && bad_output.value == -1 &&
            bad_output.posix_errno == Libs::Posix::POSIX_EFAULT && bad_span.value == -1 &&
            bad_span.posix_errno == Libs::Posix::POSIX_EFAULT &&
            std::all_of(crossing, crossing + 8, [](uint8_t byte) { return byte == 0xa5; }) &&
            unknown_metadata.value == -1 && unknown_metadata.posix_errno == Libs::Posix::POSIX_ENOTTY &&
            nand_for_t == 0xa5a5a5a5 && unsupported.value == -1 &&
            unsupported.posix_errno == Libs::Posix::POSIX_ENOTTY,
        "native syscall bridge preserves media results and POSIX errors");
  Check(VirtualFree(guarded, 0, MEM_RELEASE), "release geometry output span fixture");
  FileSystem::FileStat stat {};
  Check(FileSystem::KernelStat("/dev/ssd0.system_b", &stat) == OK && stat.st_mode == 020640 &&
            stat.st_uid == 0 && stat.st_size == 0 && stat.st_blocks == 0 && stat.st_blksize == 16384 &&
            FileSystem::KernelCheckReachability("/dev/ssd0.system_b") == OK &&
            FileSystem::KernelFstat(fd, &stat) == OK && stat.st_mode == 020640 &&
            stat.st_uid == 0 && stat.st_size == 0 && stat.st_blocks == 0 && stat.st_blksize == 16384 &&
            FileSystem::KernelStat("/dev/ssd0.system_ex_b", &stat) == OK && stat.st_mode == 020640 &&
            stat.st_uid == 0 && stat.st_size == 0 && stat.st_blocks == 0 && stat.st_blksize == 16384 &&
            FileSystem::KernelFtruncate(fd, 0) == Kernel::KERNEL_ERROR_EINVAL,
        "native character device metadata remains separate from backed media capacity");
  std::array<uint8_t, 512> bytes {};
  Check(FileSystem::KernelRead(fd, nullptr, 0) == 0 && FileSystem::KernelWrite(fd, nullptr, 0) == 0 &&
            FileSystem::KernelPread(fd, nullptr, 0, 0) == 0 && FileSystem::KernelPwrite(fd, nullptr, 0, 0) == 0,
        "zero-length sector operations do not dereference their unused buffer");
  FileSystem::KernelIovec vector {bytes.data(), bytes.size()};
  Check(FileSystem::KernelPreadv(fd, &vector, 1, 0) == Kernel::KERNEL_ERROR_ENOTSUP &&
            FileSystem::KernelPwritev(fd, &vector, 1, 0) == Kernel::KERNEL_ERROR_ENOTSUP,
        "unsupported vectored payload transfers fail explicitly");
  Check(FileSystem::KernelRead(fd, bytes.data(), bytes.size()) == bytes.size() && bytes[1] == 1 &&
            FileSystem::KernelLseek(fd, 0, 1) == 512 &&
            FileSystem::KernelPread(fd, bytes.data(), bytes.size(), 512) == bytes.size() &&
            FileSystem::KernelLseek(fd, 0, 1) == 512,
        "positioned read preserves descriptor position");
  bytes.fill(0xa5);
  Check(FileSystem::KernelPread(fd, bytes.data(), bytes.size(), 1024) == Kernel::KERNEL_ERROR_EIO && bytes[0] == 0xa5 &&
            FileSystem::KernelPread(fd, reinterpret_cast<void*>(1), bytes.size(), 0) == Kernel::KERNEL_ERROR_EFAULT &&
            FileSystem::KernelPwrite(fd, bytes.data(), 1, 1024) == Kernel::KERNEL_ERROR_EINVAL &&
            FileSystem::KernelPread(fd, bytes.data(), bytes.size(), 1) == Kernel::KERNEL_ERROR_EINVAL &&
            FileSystem::KernelPwrite(fd, reinterpret_cast<void*>(1), bytes.size(), 0) == Kernel::KERNEL_ERROR_EFAULT,
        "invalid buffers and unsupplied sectors fail without returning data");
  Check(FileSystem::KernelPwrite(fd, bytes.data(), bytes.size(), 1024) == bytes.size() &&
            FileSystem::KernelPread(fd, bytes.data(), bytes.size(), 1024) == bytes.size() && bytes[511] == 0xa5 &&
            FileSystem::KernelLseek(fd, 1536, 0) == 1536 &&
            FileSystem::KernelWrite(fd, bytes.data(), bytes.size()) == bytes.size() &&
            FileSystem::KernelLseek(fd, 0, 1) == 2048 &&
            FileSystem::KernelLseek(fd, INT64_MIN, 1) == Kernel::KERNEL_ERROR_EINVAL &&
            FileSystem::KernelRead(fd, bytes.data(), bytes.size()) == 0 &&
            FileSystem::KernelPread(fd, bytes.data(), 1024, 1536) == bytes.size() &&
            FileSystem::KernelPread(fd, bytes.data(), bytes.size(), 2560) == Kernel::KERNEL_ERROR_EIO,
        "writes persist in the disposable overlay and advance position");
  Check(FileSystem::KernelClose(fd) == OK && FileSystem::KernelIoctl(fd, 0x40086481, &capacity) == Kernel::KERNEL_ERROR_EBADF,
        "closed diagnostic media descriptor is invalid");
  _putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", "1");
  const auto closed_info = Libs::NativeKernelBridge::DispatchSyscall({0x36, {static_cast<uint64_t>(fd), 0x40086481, reinterpret_cast<uint64_t>(&capacity)}});
  _putenv_s("KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS", saved_flag.c_str());
  Check(closed_info.value == -1 && closed_info.posix_errno == Libs::Posix::POSIX_EBADF,
        "native geometry query preserves the closed descriptor error");
  const int reopened = FileSystem::KernelOpen("/dev/ssd0.system_b", 0, 0);
  sector_size = 0; capacity = 0;
  Check(reopened >= 3 && FileSystem::KernelIoctl(reopened, 0x40046480, &sector_size) == OK && sector_size == 512 &&
            FileSystem::KernelIoctl(reopened, 0x40086481, &capacity) == OK && capacity == 2048 &&
            FileSystem::KernelFstat(reopened, &stat) == OK && stat.st_mode == 020640 &&
            stat.st_uid == 0 && stat.st_size == 0 && stat.st_blocks == 0 && stat.st_blksize == 16384 &&
            FileSystem::KernelClose(reopened) == OK,
        "backed geometry and native metadata survive descriptor reopen");
  backing.reset(); read_only.reset();
  Common::File verify(image, Common::File::Mode::Read);
  std::array<uint8_t, 1024> unchanged {}; verify.Read(unchanged.data(), unchanged.size());
  Check(unchanged == original, "kernel descriptor writes leave source fixture unchanged");
#endif
}

void CheckArchiveMount(const std::filesystem::path &root) {
  const auto archive = root / u8"game-æ—¥æœ¬èªž.zar";
  std::vector<uint8_t> payload(2 * 64 * 1024 + 33);
  for (size_t i = 0; i < payload.size(); ++i) {
    payload[i] = static_cast<uint8_t>(i * 37 + 11);
  }
  Check(ArchiveTests::CreateArchive(archive, payload), "create mounted archive fixture");
  const auto archive_root = Common::MakeArchivePath(archive);
  const auto host_member = archive_root / "assets/subdir/data.bin";
  Common::File archive_reader(host_member, Common::File::Mode::Read);
  Check(!archive_reader.IsInvalid() && archive_reader.Seek(payload.size() - 3),
        "open archive status fixture near member boundary");
  std::array<uint8_t, 8> archive_bytes {};
  uint32_t archive_count = 0;
  std::error_code archive_error = std::make_error_code(std::errc::io_error);
  archive_reader.Read(archive_bytes.data(), archive_bytes.size(), &archive_count, &archive_error);
  Check(archive_count == 3 && !archive_error &&
        std::equal(archive_bytes.begin(), archive_bytes.begin() + 3, payload.end() - 3),
        "valid archive member short read clears stale status and returns its actual trailing bytes");
  archive_error = std::make_error_code(std::errc::io_error);
  archive_reader.Read(archive_bytes.data(), 1, nullptr, &archive_error);
  Check(!archive_error, "valid archive EOF reports no error even without a byte-count output");
  archive_reader.Close();
  constexpr char GuestMember[] = "/app0/assets/subdir/data.bin";
  FileSystem::Mount(archive_root, "/app0");
  Check(FileSystem::GetRealFilename(GuestMember) == host_member &&
            FileSystem::GetRealFilename("/app01/eboot.bin").empty(),
        "resolve archive mounts at path-component boundaries");
  Check(FileSystem::KernelOpen("/app0/../outside.bin", 0, 0) ==
            Libs::LibKernel::KERNEL_ERROR_ENOENT &&
            FileSystem::KernelOpen("/app0/missing.bin", 0, 0) ==
            Libs::LibKernel::KERNEL_ERROR_ENOENT,
        "reject traversal outside an archive and missing members");

  FileSystem::FileStat path_stat{}, descriptor_stat{};
  Check(FileSystem::KernelStat(GuestMember, &path_stat) == OK &&
            path_stat.st_size == payload.size() &&
            path_stat.st_size == Common::File::Size(host_member) &&
            FileSystem::KernelCheckReachability(GuestMember) == OK,
        "archive path stat and reachability agree with Common::File");
  const int fd = FileSystem::KernelOpen("/app0/ASSETS/subdir/DATA.BIN", 0, 0);
  Check(fd >= 3 && FileSystem::KernelFstat(fd, &descriptor_stat) == OK &&
            descriptor_stat.st_size == path_stat.st_size &&
            descriptor_stat.st_mode == path_stat.st_mode,
        "case-insensitive archive open and descriptor stat agree");
  std::array<uint8_t, 97> bytes{};
  constexpr int64_t Offset = 64 * 1024 - 19;
  Check(FileSystem::KernelPread(fd, bytes.data(), bytes.size(), Offset) == bytes.size() &&
            std::equal(bytes.begin(), bytes.end(), payload.begin() + Offset) &&
            FileSystem::KernelLseek(fd, 0, 1) == 0,
        "archive pread crosses a compression block without moving position");
  Check(FileSystem::KernelLseek(fd, Offset, 0) == Offset &&
            FileSystem::KernelRead(fd, bytes.data(), bytes.size()) == bytes.size() &&
            std::equal(bytes.begin(), bytes.end(), payload.begin() + Offset) &&
            FileSystem::KernelLseek(fd, 0, 1) == Offset + bytes.size(),
        "archive seek and sequential read share descriptor position");
  Check(FileSystem::KernelLseek(fd, -9, 2) == payload.size() - 9 &&
            FileSystem::KernelRead(fd, bytes.data(), bytes.size()) == 9 &&
            std::equal(bytes.begin(), bytes.begin() + 9, payload.end() - 9) &&
            FileSystem::KernelRead(fd, bytes.data(), bytes.size()) == 0,
        "archive reads stop at the member boundary");
  Check(FileSystem::KernelWrite(fd, bytes.data(), 1) ==
            Libs::LibKernel::KERNEL_ERROR_EBADF &&
            FileSystem::KernelPwrite(fd, bytes.data(), 1, 0) ==
            Libs::LibKernel::KERNEL_ERROR_EBADF &&
            FileSystem::KernelFtruncate(fd, 0) ==
            Libs::LibKernel::KERNEL_ERROR_EBADF,
        "archive read-only descriptors reject write and truncate");

  const auto unicode_guest = std::string("/app0/") + std::string(ArchiveTests::UnicodeFilename);
  const int unicode = FileSystem::KernelOpen(unicode_guest.c_str(), 0, 0);
  Check(unicode >= 3 && FileSystem::KernelRead(unicode, bytes.data(), bytes.size()) ==
            ArchiveTests::Eboot.size() &&
            std::memcmp(bytes.data(), ArchiveTests::Eboot.data(), ArchiveTests::Eboot.size()) == 0,
        "open and read a Unicode archive member");
  Check(FileSystem::KernelClose(unicode) == OK, "close Unicode archive member");

  const int directory = FileSystem::KernelOpen("/app0/", 0x00020000, 0);
  Check(directory >= 3, "open mounted archive directory");
  std::array<char, 512> block{};
  const auto expected_entries = Common::File::GetDirEntries(archive_root);
  size_t entries_seen = 0;
  for (;;) {
    const int length = FileSystem::KernelGetdents(directory, block.data(), block.size());
    Check(length >= 0 && length <= block.size(), "read archive directory records");
    if (length == 0) {
      break;
    }
    for (size_t offset = 0; offset < static_cast<size_t>(length);) {
      uint16_t record_length = 0;
      Check(length - offset >= 8, "archive directory record header fits");
      std::memcpy(&record_length, block.data() + offset + 4, sizeof(record_length));
      const auto name_length = static_cast<uint8_t>(block[offset + 7]);
      Check(record_length >= 9 + name_length && record_length <= length - offset,
            "archive directory record fits");
      const std::string_view name(block.data() + offset + 8, name_length);
      Check(std::any_of(expected_entries.begin(), expected_entries.end(), [&](const auto &entry) {
        return entry.name == name && block[offset + 6] == (entry.is_file ? 8 : 4);
      }), "guest directory entry matches Common::File name and type");
      ++entries_seen;
      offset += record_length;
    }
  }
  Check(entries_seen == expected_entries.size(), "guest enumerates every archive directory entry");
  Check(FileSystem::KernelClose(directory) == OK, "close archive directory");

  for (const int flags : {1, 2, 0x0200, 0x0400}) {
    Check(FileSystem::KernelOpen(GuestMember, flags, 0777) ==
              Libs::LibKernel::KERNEL_ERROR_EROFS,
          "archive rejects write, create and truncate open flags");
  }
  Check(FileSystem::KernelUnlink(GuestMember) == Libs::LibKernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelMkdir("/app0/new-dir", 0777) == Libs::LibKernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelRmdir("/app0/assets") == Libs::LibKernel::KERNEL_ERROR_EROFS &&
            FileSystem::KernelRename(GuestMember, "/app0/renamed.bin") ==
                Libs::LibKernel::KERNEL_ERROR_EROFS,
        "archive mount rejects path mutations");
  FileSystem::Umount("/app0");
  Check(FileSystem::GetRealFilename(GuestMember).empty() &&
            FileSystem::KernelOpen(GuestMember, 0, 0) == Libs::LibKernel::KERNEL_ERROR_ENOENT &&
            FileSystem::KernelLseek(fd, 0, 0) == 0 &&
            FileSystem::KernelRead(fd, bytes.data(), bytes.size()) == bytes.size() &&
            std::equal(bytes.begin(), bytes.end(), payload.begin()),
        "unmount hides archive paths while open descriptors retain the reader");
  Check(FileSystem::KernelClose(fd) == OK, "close last archive descriptor");
}

void CheckUnicodePaths(const std::filesystem::path &root) {
  constexpr std::string_view HostDirectory =
      "Test\xc3\xa9-\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e";
  constexpr std::string_view GuestFilename =
      "asset-\xc3\xa9-\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e.bin";

  const auto unicode_root =
      root / Common::PathFromUtf8(HostDirectory);
  const auto nested_root = unicode_root / "nested";

  Check(Common::File::CreateDirectories(nested_root),
        "create nested Unicode host directory");

  CheckMountRoot(nested_root);

  const auto native_file =
      nested_root / Common::PathFromUtf8(GuestFilename);

  Common::File fixture;
  Check(fixture.Create(native_file), "create Unicode filename");
  fixture.Close();

  const auto entries = Common::File::GetDirEntries(nested_root);
  Check(std::any_of(entries.begin(), entries.end(), [&](const auto &entry) {
          return entry.is_file && entry.name == GuestFilename;
        }), "directory enumeration returns UTF-8 filenames");

  FileSystem::Mount(nested_root, "/app0");

  const auto guest_file =
      std::string("/app0/") + std::string(GuestFilename);

  Check(FileSystem::GetRealFilename(guest_file) == native_file,
        "resolve Unicode guest path");

  const int fd = FileSystem::KernelOpen(guest_file.c_str(), 0, 0);
  Check(fd >= 3, "open Unicode guest path");
  Check(FileSystem::KernelClose(fd) == OK,
        "close Unicode guest path");

  FileSystem::Umount("/app0");
}

void CheckUnicodeLogPath(const std::filesystem::path &root) {
  Config::ConfigOptions options;
  options.printf_direction = Config::LogDirection::File;
  options.printf_output_file = root / u8"logs-\u65e5\u672c\u8a9e-\U0001f600" / u8"log-\u00e9.txt";
  Config::Load(options);
  Log::Initialize();
  constexpr std::string_view Payload = "Unicode log path\n";
  Log::Write(Payload);
  Log::Shutdown();

  Common::File result(options.printf_output_file, Common::File::Mode::Read);
  Check(!result.IsInvalid(), "open Unicode log file");
  const auto data = result.ReadWholeBuffer();
  Check(data.size() == Payload.size() &&
            std::memcmp(data.data(), Payload.data(), data.size()) == 0,
        "Unicode log file contains output");
  options.printf_direction = Config::LogDirection::Silent;
  Config::Load(options);
  Log::Initialize();
}

void CheckDirectoryStream(const std::filesystem::path &root) {
  const auto directory = root / "directory-stream";
  Check(std::filesystem::create_directory(directory),
        "create seek fixture directory");
  for (int i = 0; i < 48; ++i) {
    Common::File fixture;
    Check(fixture.Create(directory / ("directory-entry-" + std::to_string(i))),
          "create enough entries to cross directory blocks");
    fixture.Close();
  }
  FileSystem::Mount(directory, "/app0");
  const int fd = FileSystem::KernelOpen("/app0/", 0, 0);
  Check(fd >= 3, "open directory as read-only asset");
  const auto end = FileSystem::KernelLseek(fd, 0, 2);
  Check(end > 512 && end % 512 == 0,
        "directory SEEK_END uses padded stream size");
  FileSystem::FileStat stat{};
  Check(FileSystem::KernelFstat(fd, &stat) == OK && stat.st_size == end &&
            stat.st_blksize == 512,
        "directory stat agrees with seek and enumeration");
  Check(FileSystem::KernelStat("/app0/", &stat) == OK && stat.st_size == end &&
            stat.st_blocks == end / 512,
        "path and descriptor directory stat agree");
  Check(FileSystem::KernelLseek(fd, 0, 0) == 0,
        "rewind directory for asset read");
  std::vector<char> raw(static_cast<size_t>(end));
  Check(FileSystem::KernelRead(fd, raw.data(), raw.size()) == end &&
            FileSystem::KernelRead(fd, raw.data(), 1) == 0,
        "raw directory read reaches EOF");
  Check(FileSystem::KernelLseek(fd, -end, 1) == 0,
        "directory SEEK_CUR uses the position advanced by read");

  std::array<char, 512> block{};
  int64_t base = -1;
  for (int64_t offset = 0; offset < end; offset += block.size()) {
    Check(FileSystem::KernelGetdirentries(fd, block.data(), block.size(),
                                          &base) == block.size() &&
              base == offset &&
              std::memcmp(block.data(), raw.data() + offset, block.size()) == 0,
          "directory enumeration shares raw bytes and reports each block "
          "position");
    for (size_t pos = 0; pos < block.size();) {
      Check(block.size() - pos >= 8, "directory record header fits");
      uint16_t length = 0;
      std::memcpy(&length, block.data() + pos + 4, sizeof(length));
      const auto name_length = static_cast<uint8_t>(block[pos + 7]);
      Check(length >= 9 + name_length && length <= block.size() - pos &&
                block[pos + 8 + name_length] == '\0',
            "directory entries remain complete within every block");
      pos += length;
    }
  }
  Check(FileSystem::KernelGetdirentries(fd, block.data(), block.size(),
                                        &base) == 0 &&
            base == end,
        "directory enumeration reports EOF position");
  Check(FileSystem::KernelLseek(fd, 512, 0) == 512 &&
            FileSystem::KernelGetdirentries(fd, block.data(), block.size(),
                                            &base) == block.size() &&
            base == 512 &&
            std::memcmp(block.data(), raw.data() + 512, block.size()) == 0,
        "restore and reread a directory enumeration position");

  const auto position = FileSystem::KernelLseek(fd, 0, 1);
  Check(
      FileSystem::KernelLseek(fd, 0, 9) ==
              Libs::LibKernel::KERNEL_ERROR_EINVAL &&
          FileSystem::KernelLseek(fd, -1, 0) ==
              Libs::LibKernel::KERNEL_ERROR_EINVAL &&
          FileSystem::KernelLseek(fd, std::numeric_limits<int64_t>::min(), 1) ==
              Libs::LibKernel::KERNEL_ERROR_EINVAL &&
          FileSystem::KernelLseek(fd, std::numeric_limits<int64_t>::max(), 1) ==
              Libs::LibKernel::KERNEL_ERROR_EOVERFLOW &&
          FileSystem::KernelLseek(fd, 0, 1) == position,
      "invalid and overflowing directory seeks preserve the position");
  Check(FileSystem::KernelLseek(fd, -19, 2) == end - 19 &&
            FileSystem::KernelRead(fd, block.data(), block.size()) == 19 &&
            std::memcmp(block.data(), raw.data() + end - 19, 19) == 0,
        "raw directory reads support byte positions and stop at EOF");
  Check(FileSystem::KernelLseek(fd, 1, 0) == 1 &&
            FileSystem::KernelGetdents(fd, block.data(), block.size()) ==
                Libs::LibKernel::KERNEL_ERROR_EINVAL &&
            FileSystem::KernelLseek(fd, 0, 1) == 1,
        "directory enumeration rejects an incomplete record position");
  Check(FileSystem::KernelLseek(fd, 512, 2) == end + 512 &&
            FileSystem::KernelGetdirentries(fd, block.data(), block.size(),
                                            &base) ==
                Libs::LibKernel::KERNEL_ERROR_EINVAL &&
            FileSystem::KernelLseek(fd, 0, 1) == end + 512,
        "directory enumeration rejects a position beyond EOF");
  Check(FileSystem::KernelRead(
            fd, block.data(),
            static_cast<size_t>(std::numeric_limits<int>::max()) + 1) ==
                Libs::LibKernel::KERNEL_ERROR_EINVAL &&
            FileSystem::KernelLseek(fd, 0, 1) == end + 512,
        "oversized read fails without changing the directory position");
  Check(FileSystem::KernelClose(fd) == OK, "close directory stream");
  Check(FileSystem::KernelLseek(fd, 0, 0) ==
            Libs::LibKernel::KERNEL_ERROR_EBADF,
        "seek rejects a closed descriptor");
  FileSystem::Umount("/app0");
}

void CheckAmprOrdering(Loader::SymbolDatabase &symbols, uint32_t file_id) {
  Libs::LibAmpr::InitAmpr_1(&symbols);
  const auto find = [&](const char *nid) {
    const auto *symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "AMPR command and submission exports resolve");
    return symbol->vaddr;
  };
  using Unary = void (KYTY_SYSV_ABI *)(void *);
  using AprConstructor = void (KYTY_SYSV_ABI *)(void *, void *, void *);
  using SetBuffer = int (KYTY_SYSV_ABI *)(void *, void *, uint32_t);
  using Offset = uint64_t (KYTY_SYSV_ABI *)(void *);
  using WaitAddress = int (KYTY_SYSV_ABI *)(void *, volatile uint64_t *, uint64_t,
                                          uint8_t, uint8_t);
  using WriteAddress = int (KYTY_SYSV_ABI *)(void *, volatile uint64_t *, uint64_t);
  using ReadFile = int (KYTY_SYSV_ABI *)(void *, uint64_t, uint64_t, uint32_t,
                                       void *, uint64_t, uint64_t);
  using WriteKernelEvent = int (KYTY_SYSV_ABI *)(void *, uint64_t, uint64_t, uint64_t,
                                               uint64_t, uint64_t);
  struct Result { int32_t result; uint32_t error_offset; };
  using SubmitApr = int (KYTY_SYSV_ABI *)(void *, uint32_t, Result *, uint32_t *);
  using SubmitAmm = int (KYTY_SYSV_ABI *)(void *, uint32_t, uint32_t, uint32_t *);
  using WaitSubmission = int (KYTY_SYSV_ABI *)(uint32_t);
  const auto construct = reinterpret_cast<Unary>(find("8aI7R7WaOlc"));
  const auto construct_apr = reinterpret_cast<AprConstructor>(find("a8uLzYY--tM"));
  const auto construct_amm = reinterpret_cast<Unary>(find("EDq5bqCqYpA"));
  const auto destroy = reinterpret_cast<Unary>(find("GuchCTefuZw"));
  const auto set_buffer = reinterpret_cast<SetBuffer>(find("N-FSPA4S3nI"));
  const auto offset = reinterpret_cast<Offset>(find("GnxKOHEawhk"));
  const auto wait_address = reinterpret_cast<WaitAddress>(find("DLfoNxTFNVk"));
  const auto write_address = reinterpret_cast<WriteAddress>(find("sJXyWHjP-F8"));
  const auto read_file = reinterpret_cast<ReadFile>(find("mQ16-QdKv7k"));
  const auto write_event = reinterpret_cast<WriteKernelEvent>(find("H896Pt-yB4I"));
  const auto submit_apr = reinterpret_cast<SubmitApr>(find("ASoW5WE-UPo"));
  const auto submit_amm = reinterpret_cast<SubmitAmm>(find("NnKhlMJtIsI"));
  const auto wait_apr = reinterpret_cast<WaitSubmission>(find("rqwFKI4PAiM"));
  const auto wait_amm = reinterpret_cast<WaitSubmission>(find("HXymib4T8gc"));
  struct Buffer {
    std::array<uint64_t, 5> header {};
    std::array<uint32_t, 256> data {};
  };
  std::array<Buffer, 4> buffers;
  const auto reset = [&](size_t apr_count) {
    for (size_t i = 0; i < buffers.size(); ++i) {
      auto &buffer = buffers[i];
      construct(buffer.header.data());
      if (i < apr_count) {
        construct_apr(buffer.header.data(), &buffer.header[3], &buffer.header[4]);
      } else {
        construct_amm(buffer.header.data());
      }
      Check(set_buffer(buffer.header.data(), buffer.data.data(), sizeof(buffer.data)) == OK,
            "initialize AMPR command buffer");
    }
  };
  // WaitCompare order: ==, unsigned >/<, !=, wrapped >=, signed >/<.
  struct Comparison { uint8_t compare; uint64_t blocked, reference, released; };
  constexpr std::array comparisons {
      Comparison{0, 1, 2, 2}, Comparison{1, 0x40000000000019c3, 0x40000000000019c3,
                                   0x40000000000019c4},
      Comparison{1, 0, INT64_MAX, uint64_t{1} << 63},
      Comparison{2, UINT64_MAX, uint64_t{1} << 63, INT64_MAX}, Comparison{3, 2, 2, 3},
      Comparison{4, UINT64_MAX - 1, UINT64_MAX, 0},
      Comparison{5, UINT64_MAX, 0, 1}, Comparison{6, 0, 0, UINT64_MAX}};
  for (const auto &comparison : comparisons) {
    reset(3);
    uint64_t fence = comparison.blocked;
    uint64_t blocked_done = 0, read_done = 0, lower_done = 0;
    std::array<char, 3> output {};
    std::array<Result, 3> results {{{1234, 5678}, {1234, 5678}, {1234, 5678}}};
    std::array<uint32_t, 4> ids {};
    auto *blocked = buffers[0].header.data();
    auto *reader = buffers[1].header.data();
    auto *lower = buffers[2].header.data();
    auto *producer = buffers[3].header.data();
    Check(wait_address(blocked, &fence, comparison.reference, comparison.compare, 0) == OK &&
              write_address(blocked, &blocked_done, 1) == OK &&
              read_file(reader, reinterpret_cast<uint64_t>(&buffers[1].header[3]),
                        reinterpret_cast<uint64_t>(&buffers[1].header[4]), file_id,
                        output.data(), output.size(), 0) == OK &&
              write_address(reader, &read_done, 2) == OK &&
              write_address(lower, &lower_done, 3) == OK &&
              write_address(producer, &fence, comparison.released) == OK,
          "build dependent APR read and later AMM fence producer");
    Check(submit_apr(blocked, 3, &results[0], &ids[0]) == OK &&
              submit_apr(reader, 3, &results[1], &ids[1]) == OK &&
              submit_apr(lower, 4, &results[2], &ids[2]) == OK && wait_apr(ids[2]) == OK,
          "APR submit returns while blocked and a lower priority completes");
    Check(lower_done == 3 && blocked_done == 0 && read_done == 0 &&
              output == std::array<char, 3>{} && results[0].result == 1234 &&
              results[1].result == 1234,
          "unsatisfied wait blocks later buffers at its priority without publishing completion");
    Check(submit_amm(buffers[3].data.data(), static_cast<uint32_t>(offset(producer)), 1,
                     &ids[3]) == OK && wait_amm(ids[3]) == OK &&
              wait_apr(ids[0]) == OK && wait_apr(ids[1]) == OK,
          "later AMM submission releases the APR dependency");
    Check(blocked_done == 1 && read_done == 2 && std::memcmp(output.data(), "APR", 3) == 0,
          "APR reads real file bytes only after its dependency completes");
    for (const auto &result : results) {
      Check(result.result == OK,
            "submission wait observes the completed result");
    }
  }
  reset(1);
  namespace EventQueue = Libs::LibKernel::EventQueue;
  EventQueue::KernelEqueue queue = EventQueue::KERNEL_EQUEUE_INVALID;
  uint64_t ampr_user_data = 1, user_data = 2;
  Check(EventQueue::KernelCreateEqueue(&queue, "apr-completion") == OK &&
            EventQueue::KernelAddAmprEvent(queue, 42, &ampr_user_data) == OK &&
            EventQueue::KernelAddUserEventEdge(queue, 42) == OK,
        "AMPR and user events can share an identifier");
  std::array<char, 3> output {};
  Result event_result {1234, 5678};
  uint32_t event_submission = 0;
  auto *reader = buffers[0].header.data();
  Check(read_file(reader, reinterpret_cast<uint64_t>(&buffers[0].header[3]),
                  reinterpret_cast<uint64_t>(&buffers[0].header[4]), file_id,
                  output.data(), output.size(), 0) == OK &&
            write_event(reader, queue, 42, 0x123456789abc, 0, 0) == OK &&
            submit_apr(reader, 3, &event_result, &event_submission) == OK &&
            wait_apr(event_submission) == OK && event_result.result == OK,
        "APR read submits its completion event");
  std::array<EventQueue::KernelEvent, 2> events {};
  int event_count = 0;
  const Libs::LibKernel::KernelUseconds poll = 0;
  Check(EventQueue::KernelWaitEqueue(queue, events.data(), 2, &event_count, &poll) == OK &&
            event_count == 1 && events[0].ident == 42 && events[0].filter == -25 &&
            events[0].data == 0x123456789abc && events[0].udata == &ampr_user_data &&
            std::memcmp(output.data(), "APR", 3) == 0,
        "APR completion reports the AMPR filter, payload and registration user data");
  Check(EventQueue::KernelDeleteAmprEvent(queue, 42) == OK &&
            EventQueue::KernelTriggerEvent(queue, 42, -25, nullptr) ==
                Libs::LibKernel::KERNEL_ERROR_ENOENT &&
            EventQueue::KernelTriggerUserEvent(queue, 42, &user_data) == OK &&
            EventQueue::KernelWaitEqueue(queue, events.data(), 2, &event_count, &poll) == OK &&
            event_count == 1 && events[0].filter == EventQueue::KERNEL_EVFILT_USER &&
            events[0].udata == &user_data,
        "deleting AMPR leaves the user event with the same identifier intact");
  Check(EventQueue::KernelDeleteEqueue(queue) == OK, "delete APR completion queue");
  reset(0);
  uint64_t cpu_fence = 0, amm_done = 0, lower_done = 0;
  std::array<uint32_t, 2> ids {};
  Check(wait_address(buffers[0].header.data(), &cpu_fence, 0, 1, 0) == OK &&
            write_address(buffers[0].header.data(), &amm_done, 1) == OK &&
            write_address(buffers[1].header.data(), &lower_done, 1) == OK &&
            submit_amm(buffers[0].data.data(), static_cast<uint32_t>(offset(buffers[0].header.data())),
                       0, &ids[0]) == OK &&
            submit_amm(buffers[1].data.data(), static_cast<uint32_t>(offset(buffers[1].header.data())),
                       1, &ids[1]) == OK && wait_amm(ids[1]) == OK,
        "AMM lower priority progresses while its high priority waits");
  Check(lower_done == 1 && amm_done == 0, "AMM wait preserves its dependency");
  std::atomic_ref(cpu_fence).store(1, std::memory_order_release);
  Check(wait_amm(ids[0]) == OK && amm_done == 1,
        "AMM observes an external CPU fence store without a submission notification");
  for (auto &buffer : buffers) {
    destroy(buffer.header.data());
  }
}

void CheckAprPaths(const std::filesystem::path &root) {
  Loader::SymbolDatabase symbols;
  Libs::LibKernelApr::InitLibKernel_1_Apr(&symbols);
  const auto *resolve_symbol = symbols.FindByNid("w5fcCG+t31g", Loader::SymbolType::Func);
  const auto *each_symbol = symbols.FindByNid("C+Khtbbx2g8", Loader::SymbolType::Func);
  Check(resolve_symbol && each_symbol, "APR path exports are registered");
  using Resolve = int (KYTY_SYSV_ABI *)(const char *, const char *const *, uint32_t,
                                      uint32_t *, uint64_t *, uint32_t *);
  using ResolveEach = int (KYTY_SYSV_ABI *)(const char *, const char *const *, uint32_t,
                                          uint32_t *, uint64_t *, int *);
  const auto resolve = reinterpret_cast<Resolve>(resolve_symbol->vaddr);
  const auto resolve_each = reinterpret_cast<ResolveEach>(each_symbol->vaddr);
  Common::File fixture;
  Check(fixture.Create(root / "apr.dat"), "create APR fixture");
  fixture.Write("APR", 3);
  fixture.Close();
  FileSystem::Mount(root, "/app0");

  uint32_t expected_id = 0xffffffffu;
  for (const auto &parts : {std::array{"", "/app0/apr.dat"},
                           std::array{"/app0/", "apr.dat"},
                           std::array{"/", "app0/apr.dat"},
                           std::array{"/app", "0/apr.dat"}}) {
    uint32_t id = 0xffffffffu, error_index = 0xffffffffu;
    uint64_t size = 0;
    Check(resolve(parts[0], &parts[1], 1, &id, &size, &error_index) == OK &&
              id != 0xffffffffu && size == 3,
          "APR concatenates empty, one-character and partial-component prefixes");
    if (expected_id == 0xffffffffu) {
      expected_id = id;
    }
    Check(id == expected_id, "equivalent APR paths return the same ID");
  }

  const char *paths[] = {"/app0/missing.dat", "/app0/apr.dat"};
  uint32_t ids[2] = {}, error_index = 0xffffffffu;
  uint64_t sizes[2] = {1, 1};
  int results[2] = {};
  Check(resolve_each("", paths, 2, ids, sizes, results) == 1 &&
            results[0] == Libs::LibKernel::KERNEL_ERROR_ENOENT && results[1] == OK &&
            ids[0] == 0xffffffffu && ids[1] == expected_id && sizes[0] == 0 && sizes[1] == 3,
        "APR foreach reports a missing path and continues to the valid file");

  // PATH_MAX includes NUL; all components remain below NAME_MAX (255).
  std::string longest = "/app0/";
  for (int i = 0; i < 3; ++i) {
    longest += std::string(254, 'a') + '/';
  }
  longest += std::string(1023 - longest.size(), 'b');
  paths[0] = longest.c_str();
  Check(resolve("", paths, 1, ids, sizes, &error_index) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENOENT && error_index == 0,
        "APR accepts a pathname whose final NUL is at PATH_MAX minus one");
  Check(resolve("/", paths, 1, ids, sizes, &error_index) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENAMETOOLONG,
        "APR rejects concatenated paths exceeding PATH_MAX");
  std::array<char, 1024> unterminated;
  unterminated.fill('/');
  paths[0] = unterminated.data();
  Check(resolve("", paths, 1, ids, sizes, &error_index) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENAMETOOLONG,
        "APR rejects an unterminated pathname");
  paths[0] = "apr.dat";
  Check(resolve(unterminated.data(), paths, 1, ids, sizes, &error_index) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ENAMETOOLONG,
        "APR rejects an unterminated prefix");
  CheckAmprOrdering(symbols, expected_id);
  FileSystem::Umount("/app0");
}

std::array<int, 2> CreateTcpPair() {
  namespace Net = Libs::Network::Net;
  // Guest sockaddr_in: length, family, network-order port/address, padding.
  std::array<uint8_t, 16> address {16, 2, 0, 0, 127, 0, 0, 1};
  const int listener = Net::Socket(2, 1, 0);
  Check(listener >= 0, "create loopback listener");
  Check(Net::Bind(listener, address.data(), address.size()) == 0, "bind loopback");
  Check(Net::Listen(listener, 1) == 0, "listen on loopback");
  uint32_t address_size = address.size();
  Check(Net::Getsockname(listener, address.data(), &address_size) == 0,
        "get assigned loopback port");
  const int writer = Net::Socket(2, 1, 0);
  Check(writer >= 0 && Net::Connect(writer, address.data(), address_size) == 0,
        "connect wake socket");
  const int reader = Net::Accept(listener, nullptr, nullptr);
  Check(reader >= 0, "accept wake socket");
  Check(Net::SocketClose(listener) == 0, "close listener");
  return {reader, writer};
}

#if defined(_WIN32)
void CheckSocketReceiveConcurrency() {
  namespace Net = Libs::Network::Net;
  const auto [reader, writer] = CreateTcpPair();
  const int timeout_ms = 3000;
  Check(Net::Setsockopt(reader, 0xffff, 0x1006, &timeout_ms, sizeof(timeout_ms)) == 0,
        "bound the blocked receive concurrency fixture");
  std::promise<void> entered;
  std::promise<int64_t> completed;
  auto entered_future = entered.get_future();
  auto completed_future = completed.get_future();
  std::jthread receiver([&] {
    char byte = 0;
    entered.set_value();
    completed.set_value(Net::Recv(reader, &byte, 1, 0x42));
  });
  Check(entered_future.wait_for(std::chrono::seconds(2)) == std::future_status::ready,
        "start blocked reader");
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  char byte = 0;
  const auto before_nonblocking = std::chrono::steady_clock::now();
  Check(Net::Recv(reader, &byte, 1, 0x80) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EWOULDBLOCK &&
            std::chrono::steady_clock::now() - before_nonblocking < std::chrono::milliseconds(500) &&
            completed_future.wait_for(std::chrono::milliseconds(0)) == std::future_status::timeout,
        "DONTWAIT does not wait behind another blocked reader");
  const auto before_close = std::chrono::steady_clock::now();
  Check(Net::SocketClose(reader) == 0, "close succeeds while another thread receives");
  Check(std::chrono::steady_clock::now() - before_close < std::chrono::seconds(1),
        "close does not wait for the blocked receive timeout");
  Check(completed_future.wait_for(std::chrono::seconds(1)) == std::future_status::ready,
        "close wakes the blocked receive within one second");
  Check(completed_future.get() <= 0, "closed receive reports EOF or error");
  Check(std::chrono::steady_clock::now() - before_close < std::chrono::seconds(1),
        "closing a socket wakes its blocked receive before the receive timeout");
  receiver.join();
  Check(Net::SocketClose(writer) == 0, "close blocked receive writer");

  const auto [shutdown_reader, shutdown_writer] = CreateTcpPair();
  Check(Net::Setsockopt(shutdown_reader, 0xffff, 0x1006, &timeout_ms, sizeof(timeout_ms)) == 0 &&
            Net::Send(shutdown_writer, "x", 1, 0) == 1 &&
            Net::Recv(shutdown_reader, &byte, 1, 0x42) == 1 && byte == 'x' &&
            Net::Shutdown(shutdown_reader, 0) == 0 &&
            Net::Recv(shutdown_reader, &byte, 1, 0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_ESHUTDOWN,
        "receive shutdown rejects bytes retained by an earlier peek");
  Check(Net::SocketClose(shutdown_reader) == 0 && Net::SocketClose(shutdown_writer) == 0,
        "close receive shutdown fixture");
}

void CheckSocketReceiveBuffer(int reader, int writer) {
  namespace Net = Libs::Network::Net;
  constexpr int PeekWaitAll = 0x42;
  constexpr char Payload[] = "abcdef";
  const int timeout_ms = 2000;
  Check(Net::Setsockopt(reader, 0xffff, 0x1006, &timeout_ms, sizeof(timeout_ms)) == 0,
        "bound blocking receive regressions with SO_RCVTIMEO");
  Check(Net::Send(writer, Payload, 2, 0) == 2, "send first TCP fragment");
  std::jthread sender([&] {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    Check(Net::Send(writer, Payload + 2, 4, 0) == 4, "send second TCP fragment");
  });
  std::array<char, 8> received {};
  Check(Net::Recv(reader, received.data(), 6, PeekWaitAll) == 6 &&
            std::memcmp(received.data(), Payload, 6) == 0,
        "combined peek waits for fragmented TCP bytes");
  sender.join();
  received.fill(0);
  Check(Net::Recv(reader, received.data(), 6, PeekWaitAll) == 6 &&
            std::memcmp(received.data(), Payload, 6) == 0,
        "repeated combined peek preserves all bytes");

  const int epoll = Net::EpollCreate("buffered receive", 0);
  Net::NetEpollEvent registration {};
  registration.events = 1;
  registration.data.u64 = 0x12345678;
  Check(epoll >= 0 && Net::EpollControl(epoll, 1, reader, &registration) == 0,
        "register buffered socket readability");
  const auto check_readable = [&](bool expected) {
    std::array<uint64_t, 16> readable {};
    const auto bit = uint64_t {1} << (reader % 64);
    readable[reader / 64] = bit;
    const std::array<int64_t, 2> timeout {expected ? 1 : 0, 0};
    Check(Net::Select(reader + 1, readable.data(), nullptr, nullptr, timeout.data()) ==
              (expected ? 1 : 0) && readable[reader / 64] == (expected ? bit : 0),
          "select reflects buffered bytes and their removal");
    if (expected) {
      auto writable = readable;
      Check(Net::Select(reader + 1, readable.data(), writable.data(), nullptr,
                        timeout.data()) == 2 && readable[reader / 64] == bit &&
                writable[reader / 64] == bit,
            "select counts readable and writable bits once each");
    }
    Net::NetEpollEvent event {};
    Check(Net::EpollWait(epoll, &event, 1, expected ? 1000000 : 0) ==
              (expected ? 1 : 0) &&
              (!expected || (event.events == 1 && event.data.u64 == registration.data.u64)),
          "epoll reflects buffered bytes and preserves registration data");
  };
  check_readable(true);
  std::array<uint8_t, 16> peer {}, expected_peer {};
  uint32_t peer_size = peer.size(), expected_peer_size = expected_peer.size();
  Check(Net::Getsockname(writer, expected_peer.data(), &expected_peer_size) == 0 &&
            Net::Recv(reader, received.data(), 0, PeekWaitAll) == 0 &&
            Net::Recvfrom(reader, received.data(), 2, 0, peer.data(), &peer_size) == 2 &&
            peer_size == expected_peer_size && peer == expected_peer &&
            std::memcmp(received.data(), Payload, 2) == 0 &&
            FileSystem::KernelRead(reader, received.data(), 2) == 2 &&
            std::memcmp(received.data(), Payload + 2, 2) == 0,
        "zero-length peek preserves bytes; recvfrom returns peer and shares kernel read buffer");
  check_readable(true);
  Check(Net::Send(writer, "gh", 2, 0) == 2 &&
            Net::Recv(reader, received.data(), 4, 0x40) == 4 &&
            std::memcmp(received.data(), "efgh", 4) == 0,
        "waitall joins buffered bytes with newly received bytes");
  check_readable(false);
  Check(Net::Send(writer, "mn", 2, 0) == 2, "send plain peek fixture");
  const auto before_peek = std::chrono::steady_clock::now();
  Check(Net::Recv(reader, received.data(), 4, 2) == 2 &&
            std::memcmp(received.data(), "mn", 2) == 0 &&
            std::chrono::steady_clock::now() - before_peek < std::chrono::milliseconds(500) &&
            Net::Recv(reader, received.data(), 4, 0) == 2 &&
            std::memcmp(received.data(), "mn", 2) == 0,
        "plain peek returns available bytes promptly and preserves them for ordinary receive");

  const int enabled = 1, disabled = 0;
  Check(Net::Setsockopt(reader, 0xffff, 0x1200, &enabled, sizeof(enabled)) == 0 &&
            Net::Recv(reader, received.data(), 4, PeekWaitAll) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EWOULDBLOCK,
        "empty nonblocking combined peek returns would-block");
  Check(Net::Send(writer, "ij", 2, 0) == 2, "send nonblocking receive fixture");
  check_readable(true);
  *Libs::Posix::GetErrorAddr() = Libs::Posix::POSIX_EINVAL;
  for (int i = 0; i < 2; ++i) {
    Check(Net::Recv(reader, received.data(), 4, PeekWaitAll) == 2 &&
              std::memcmp(received.data(), "ij", 2) == 0 &&
              *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
          "nonblocking combined peek preserves a short result and successful errno");
  }
  Check(Net::Recv(reader, received.data(), 4, 0) == 2 &&
            std::memcmp(received.data(), "ij", 2) == 0,
        "ordinary receive consumes a short buffered result");
  check_readable(false);
  Check(Net::Setsockopt(reader, 0xffff, 0x1200, &disabled, sizeof(disabled)) == 0 &&
            Net::EpollDestroy(epoll) == 0,
        "restore blocking receives and destroy epoll");
  Check(Net::Recv(reader, received.data(), 4, PeekWaitAll | 0x80) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EWOULDBLOCK,
        "per-call nonblocking combined peek returns would-block on a blocking socket");
  Check(Net::Send(writer, "kl", 2, 0) == 2 && Net::Shutdown(writer, 1) == 0,
        "send a final partial payload and EOF");
  for (int i = 0; i < 2; ++i) {
    Check(Net::Recv(reader, received.data(), 4, PeekWaitAll) == 2 &&
              std::memcmp(received.data(), "kl", 2) == 0,
          "EOF ends waitall while repeated peeks preserve the short payload");
  }
  Check(Net::Recv(reader, received.data(), 4, 0x40) == 2 &&
            std::memcmp(received.data(), "kl", 2) == 0 &&
            Net::Recv(reader, received.data(), 4, PeekWaitAll) == 0,
        "draining the final buffered payload exposes EOF");

  const int datagram = Net::Socket(2, 2, 0);
  const int datagram_writer = Net::Socket(2, 2, 0);
  std::array<uint8_t, 16> address {16, 2, 0, 0, 127, 0, 0, 1};
  uint32_t address_size = address.size();
  Check(datagram >= 0 && datagram_writer >= 0 &&
            Net::Bind(datagram, address.data(), address.size()) == 0 &&
            Net::Getsockname(datagram, address.data(), &address_size) == 0 &&
            Net::Setsockopt(datagram, 0xffff, 0x1006, &timeout_ms, sizeof(timeout_ms)) == 0 &&
            Net::Sendto(datagram_writer, Payload, 6, 0, address.data(), address_size) == 6,
        "create bounded UDP truncation fixture");
  *Libs::Posix::GetErrorAddr() = Libs::Posix::POSIX_EINVAL;
  Check(Net::Recvfrom(datagram, received.data(), 2, 0, nullptr, nullptr) == 2 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL &&
            std::memcmp(received.data(), Payload, 2) == 0 &&
            Net::Setsockopt(datagram, 0xffff, 0x1200, &enabled, sizeof(enabled)) == 0 &&
            Net::Recv(datagram, received.data(), received.size(), 0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EWOULDBLOCK,
        "UDP truncation returns its prefix and discards the rest of the datagram");
  Check(Net::SocketClose(datagram) == 0 && Net::SocketClose(datagram_writer) == 0,
        "close UDP truncation fixture");
}
#endif

void CheckSocketWakeup() {
  namespace Net = Libs::Network::Net;
  Loader::SymbolDatabase symbols;
  Libs::LibNet::InitNet_1_Net(&symbols);
  const auto *send_symbol = symbols.Find(
      {"beRjXBn-z+o", "Net", 1, "Net", 1, 1, Loader::SymbolType::Func});
  const auto *recv_symbol = symbols.Find(
      {"9wO9XrMsNhc", "Net", 1, "Net", 1, 1, Loader::SymbolType::Func});
  const auto *errno_symbol = symbols.Find(
      {"HQOwnfMGipQ", "Net", 1, "Net", 1, 1, Loader::SymbolType::Func});
  Check(send_symbol && recv_symbol && errno_symbol,
        "Net send, receive and errno exports resolve with the guest ABI versions");
  using Send = int (KYTY_SYSV_ABI *)(int, const void *, size_t, int);
  using Recv = int (KYTY_SYSV_ABI *)(int, void *, size_t, int);
  using Errno = int *(KYTY_SYSV_ABI *)();
  const auto net_send = reinterpret_cast<Send>(send_symbol->vaddr);
  const auto net_recv = reinterpret_cast<Recv>(recv_symbol->vaddr);
  auto *net_errno = reinterpret_cast<Errno>(errno_symbol->vaddr)();
  const auto [reader, writer] = CreateTcpPair();
  const int enabled = 1;
  Check(Net::Setsockopt(writer, 6, 1, &enabled, sizeof(enabled)) == 0,
        "enable TCP_NODELAY");
  int socket_error = -1;
  uint32_t error_size = sizeof(socket_error);
  *Libs::Posix::GetErrorAddr() = Libs::Posix::POSIX_EINVAL;
  Check(Net::Getsockopt(writer, 0xffff, 0x1007, &socket_error, &error_size) == 0 &&
            socket_error == 0 && error_size == sizeof(socket_error) &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EINVAL,
        "SO_ERROR reports socket status without changing guest errno");

  std::array<uint64_t, 16> readable {};
  const auto bit = uint64_t {1} << (reader % 64);
  readable[reader / 64] = bit;
  const std::array<int64_t, 2> immediate {0, 0};
  Check(Net::Select(reader + 1, readable.data(), nullptr, nullptr,
                    immediate.data()) == 0 && readable[reader / 64] == 0,
        "empty socket is not readable");
  const char payload[] = "wake";
  *net_errno = Libs::Posix::POSIX_EINVAL;
  Check(net_send(writer, payload, sizeof(payload), 0) == sizeof(payload) &&
            *net_errno == Libs::Posix::POSIX_EINVAL,
        "Net send forwards bytes and preserves errno on success");
  readable[reader / 64] = bit;
  const std::array<int64_t, 2> deadline {1, 0};
  Check(Net::Select(reader + 1, readable.data(), nullptr, nullptr,
                    deadline.data()) == 1 && readable[reader / 64] == bit,
        "select reports the guest descriptor after wake");
  std::array<char, sizeof(payload)> received {};
  Check(net_recv(reader, received.data(), received.size(), 0x42) == sizeof(payload) &&
            std::memcmp(received.data(), payload, sizeof(payload)) == 0 &&
            *net_errno == Libs::Posix::POSIX_EINVAL,
        "Net receive forwards PEEK and WAITALL without consuming bytes");
  received.fill(0);
  Check(net_recv(reader, received.data(), received.size(), 0x40) == sizeof(payload) &&
            std::memcmp(received.data(), payload, sizeof(payload)) == 0,
        "Net receive consumes the same bytes after peeking");
#if !defined(_WIN32)
  Check(Net::Recv(reader, received.data(), received.size(), 0x80) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EWOULDBLOCK,
        "empty nonblocking receive translates guest errno");
  Check(net_recv(reader, received.data(), received.size(), 0x80) ==
            Libs::Network::NET_ERROR_EWOULDBLOCK &&
            *net_errno == Libs::Posix::POSIX_EWOULDBLOCK,
        "Net nonblocking receive translates POSIX failure and Net errno");
#endif
  Check(net_send(-1, payload, sizeof(payload), 0) == Libs::Network::NET_ERROR_EBADF &&
            *net_errno == Libs::Posix::POSIX_EBADF,
        "Net send translates an invalid socket instead of returning POSIX minus one");
  Check(net_recv(reader, nullptr, received.size(), 0) == Libs::Network::NET_ERROR_EFAULT &&
            *net_errno == Libs::Posix::POSIX_EFAULT,
        "Net receive translates an invalid output buffer");
  Check(net_send(writer, payload, sizeof(payload), 0x100000) ==
            Libs::Network::NET_ERROR_EOPNOTSUPP &&
            *net_errno == Libs::Posix::POSIX_EOPNOTSUPP,
        "Net send preserves the backend's unsupported crypto flag error");
#if defined(__linux__)
  const int disconnected = Net::Socket(2, 1, 0);
  Check(disconnected >= 0, "create unconnected socket for broken pipe check");
  const auto previous_sigpipe = std::signal(SIGPIPE, SIG_DFL);
  Check(previous_sigpipe != SIG_ERR, "set default SIGPIPE disposition for Net send");
  const auto broken_send = net_send(disconnected, payload, sizeof(payload), 0);
  std::signal(SIGPIPE, previous_sigpipe);
  Check(broken_send == Libs::Network::NET_ERROR_EPIPE &&
            *net_errno == Libs::Posix::POSIX_EPIPE,
        "Net send reports a broken pipe without raising host SIGPIPE");
  Check(Net::SocketClose(disconnected) == 0, "close unconnected socket");
#endif
#if defined(_WIN32)
  CheckSocketReceiveBuffer(reader, writer);
  CheckSocketReceiveConcurrency();
#endif
  Check(Net::SocketClose(writer) == 0, "close wake writer");
  *net_errno = Libs::Posix::POSIX_EINVAL;
  Check(net_recv(reader, received.data(), received.size(), 0) == 0 &&
            *net_errno == Libs::Posix::POSIX_EINVAL,
        "Net receive returns EOF without replacing errno");
  Check(Net::SocketClose(reader) == 0, "close wake reader");
  readable[reader / 64] = bit;
  Check(Net::Select(reader + 1, readable.data(), nullptr, nullptr,
                    immediate.data()) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EBADF &&
            readable[reader / 64] == bit,
        "closed descriptor fails without clearing input fd_set");
}

bool VerifyCompositorCommand3000Log(const std::filesystem::path& path) {
  std::ifstream diagnostic_log(path, std::ios::binary);
  const std::string text((std::istreambuf_iterator<char>(diagnostic_log)),
                         std::istreambuf_iterator<char>());
  const auto count = [&](std::string_view needle) {
    size_t found = 0;
    for (size_t offset = 0; (offset = text.find(needle, offset)) != std::string::npos;
         offset += needle.size()) ++found;
    return found;
  };
  const auto rate_word = [](uint32_t value) {
    std::ostringstream marker;
    marker << "word0=0x" << std::hex << std::setfill('0') << std::setw(8) << value
           << " word1=0x11223344 word2=0x55667788 word3=0x99aabbcc";
    return marker.str();
  };
  bool rate_bound = true;
  for (uint32_t i = 0; i < 7; ++i) rate_bound = rate_bound && count(rate_word(0xaabb0000u + i)) == 2;
  rate_bound = rate_bound && count(rate_word(0xaabb0007)) == 1 &&
      count(rate_word(0xaabb0008)) == 0 && count(rate_word(0xaabb000b)) == 0;
  return count("GNM_COMMAND3000 kind=") == 30 &&
         count("GNM_COMMAND3000 kind=request endpoint=gnm role=client direction=send version=1 command=0x3000 reserved=0 request_size=0") == 5 &&
         count("GNM_COMMAND3000 kind=request endpoint=gnm role=server direction=recv version=1 command=0x3000 reserved=0 request_size=0") == 5 &&
         count("GNM_COMMAND3000 kind=response_header endpoint=gnm role=server direction=send body_size=16 server_result=0x81234567") == 1 &&
         count("GNM_COMMAND3000 kind=response_header endpoint=gnm role=client direction=recv body_size=16 server_result=0x81234567") == 1 &&
         count("GNM_COMMAND3000 kind=response_header endpoint=gnm role=server direction=send body_size=16 server_result=0x81234568") == 1 &&
         count("GNM_COMMAND3000 kind=response_header endpoint=gnm role=client direction=recv body_size=16 server_result=0x81234568") == 1 &&
         count("GNM_COMMAND3000 kind=response_header endpoint=gnm role=server direction=send body_size=0 server_result=0x81234569") == 1 &&
         count("GNM_COMMAND3000 kind=response_header endpoint=gnm role=client direction=recv body_size=0 server_result=0x81234569") == 1 &&
         count("GNM_COMMAND3000 kind=response_header endpoint=gnm role=server direction=send body_size=16 server_result=0x8123456a") == 1 &&
         count("GNM_COMMAND3000 kind=response_header endpoint=gnm role=client direction=recv body_size=16 server_result=0x8123456a") == 1 &&
         count("GNM_COMMAND3000 kind=response_header endpoint=gnm role=server direction=send body_size=8 server_result=0x8123456b") == 1 &&
         count("GNM_COMMAND3000 kind=response_header endpoint=gnm role=client direction=recv body_size=8 server_result=0x8123456b") == 1 &&
         count("GNM_COMMAND3000 kind=response_body endpoint=gnm role=server direction=send bytes=16 qword_nonzero_mask=0x2") == 1 &&
         count("GNM_COMMAND3000 kind=response_body endpoint=gnm role=client direction=recv bytes=16 qword_nonzero_mask=0x2") == 1 &&
         count("GNM_COMMAND3000 kind=response_body endpoint=gnm role=server direction=send bytes=16 qword_nonzero_mask=0x0") == 1 &&
         count("GNM_COMMAND3000 kind=response_body endpoint=gnm role=client direction=recv bytes=16 qword_nonzero_mask=0x0") == 1 &&
         count("GNM_COMMAND3000 kind=response_body endpoint=gnm role=server direction=send bytes=16 qword_nonzero_mask=0x1") == 1 &&
         count("GNM_COMMAND3000 kind=response_body endpoint=gnm role=client direction=recv bytes=16 qword_nonzero_mask=0x1") == 1 &&
         count("GNM_COMMAND3000 kind=unavailable endpoint=gnm role=server direction=send phase=response_header reason=unsupported_body_size") == 1 &&
         count("GNM_COMMAND3000 kind=unavailable endpoint=gnm role=client direction=recv phase=response_header reason=unsupported_body_size") == 1 &&
         count("GNM_COMMAND3000 kind=unavailable endpoint=gnm role=client direction=send phase=request reason=mismatch") == 1 &&
         count("GNM_COMMAND3000 kind=unavailable endpoint=gnm role=server direction=recv phase=request reason=mismatch") == 1 &&
         count("GNM_HEADER16_DIAGNOSTIC endpoint=gnm role=client guest_pid=") == 14 &&
         count("GNM_HEADER16_DIAGNOSTIC endpoint=gnm role=server guest_pid=") == 14 &&
         count(" direction=send bytes=16 word0=") == 14 &&
         count(" direction=recv bytes=16 word0=") == 14 &&
         count("word0=0x00000002 word1=0x00003000 word2=0x00000001 word3=0x00000000") == 1 &&
         count(" per_socket_cap=8 process_cap=64") == 28 && rate_bound &&
         text.find("GNM_COMMAND3000 kind=") != std::string::npos &&
         text.find("GNM_COMMAND3000 kind=request endpoint=spp") == std::string::npos &&
         text.find("GNM_COMMAND3000 kind=request endpoint=gnmr") == std::string::npos &&
         text.find("GNM_HEADER16_DIAGNOSTIC endpoint=spp") == std::string::npos &&
         text.find("GNM_HEADER16_DIAGNOSTIC endpoint=gnmr") == std::string::npos;
}

} // namespace

int main(int argc, char** argv) {
  Common::InitializeThreads();
  Common::Subsystems subsystems;
  subsystems.Initialize<Config::Lifecycle>();
  const bool guest_wait7_frontier_only =
      argc == 2 && std::strcmp(argv[1], "--guest-wait7-frontier-only") == 0;
  const bool auth_info_scope_only =
      argc == 2 && std::strcmp(argv[1], "--authinfo-scope-lifecycle-only") == 0;
  const bool app_mount_contract_only =
      argc == 2 && std::strcmp(argv[1], "--app-mount-contract-only") == 0;
  const bool app_registration_state_only =
      argc == 2 && std::strcmp(argv[1], "--app-registration-state-only") == 0;
  const bool regmgr_snapshot_only = argc == 2 && std::strcmp(argv[1], "--regmgr-snapshot-only") == 0;
  const bool registry_traps_only = argc == 2 && std::strcmp(argv[1], "--registry-traps-only") == 0;
  const bool sysav_audio_shm_only =
      argc == 2 && std::strcmp(argv[1], "--sysav-audio-shm-only") == 0;
  const bool physhm_only =
      argc == 2 && std::strcmp(argv[1], "--physhm-only") == 0;
  const bool audiod_extended_mmap_only =
      argc == 2 && std::strcmp(argv[1], "--audiod-extended-mmap-only") == 0;
  const bool host_exception_provenance_only =
      argc == 2 && std::strcmp(argv[1], "--host-exception-provenance-only") == 0;
  const bool guest_sigaction_only =
      argc == 2 && std::strcmp(argv[1], "--guest-sigaction-only") == 0;
  const bool posix_sem_setname_only =
      argc == 2 && std::strcmp(argv[1], "--posix-sem-setname-only") == 0;
  const bool mono_native_memory_only =
      argc == 2 && std::strcmp(argv[1], "--mono-native-memory-only") == 0;
  const bool psm_audio_openex_only =
      argc == 2 && std::strcmp(argv[1], "--psm-audio-openex-only") == 0;
  const bool psm_native_mutex_only =
      argc == 2 && std::strcmp(argv[1], "--psm-native-mutex-only") == 0;
  const bool psm_native_thread_rename_only =
      argc == 2 && std::strcmp(argv[1], "--psm-native-thread-rename-only") == 0;
  const bool psm_sched_range_only =
      argc == 2 && std::strcmp(argv[1], "--psm-sched-range-only") == 0;
  const bool sysav_raw_syscall_trap_only =
      argc == 2 && std::strcmp(argv[1], "--sysav-raw-syscall-trap-only") == 0;
  const bool exec_startup_diagnostics_only =
      argc == 2 && std::strcmp(argv[1], "--guest-exec-startup-diagnostics-only") == 0;
  const bool json2_resource_arbitrator_only =
      argc == 4 && std::strcmp(argv[1], "--json2-resource-arbitrator-only") == 0;
  const bool app_classification_only =
      argc == 3 && std::strcmp(argv[1], "--app-classification-only") == 0;
  const bool local_socket_policy_only =
      argc == 2 && std::strcmp(argv[1], "--local-socket-policy-only") == 0;
  const bool compositor_sockets_only =
      argc == 2 && std::strcmp(argv[1], "--compositor-sockets-only") == 0;
  const bool json2_object_iterator_exit_child =
      argc == 4 && std::strcmp(argv[1], "--json2-object-iterator-exit-child") == 0;
  const bool envelope_only = argc == 2 && std::strcmp(argv[1], "--envelope-only") == 0;
  const bool native_sshot_only =
      argc == 2 && std::strcmp(argv[1], "--native-sshot-only") == 0;
  const bool readonly_providers_only =
      argc == 2 && std::strcmp(argv[1], "--readonly-providers-only") == 0;
  const bool readonly_provider_child =
      argc >= 2 && std::strcmp(argv[1], "--readonly-provider-child") == 0;
  std::filesystem::path guest_wait7_log;
  std::filesystem::path exec_startup_log;
  std::filesystem::path app_mount_contract_log;
  std::filesystem::path compositor_sockets_log;
  Config::ConfigOptions options;
  options.printf_direction = Config::LogDirection::Silent;
  if (compositor_sockets_only) {
    compositor_sockets_log = std::filesystem::temp_directory_path() /
        ("kyty_compositor_sockets_" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()) + ".log");
    std::error_code ignored;
    std::filesystem::remove(compositor_sockets_log, ignored);
    options.printf_direction = Config::LogDirection::File;
    options.printf_output_file = compositor_sockets_log;
  }
  const bool native_font_audit = argc == 4 && std::strcmp(argv[1], "--native-font-audit") == 0;
  const bool native_font_routing = argc == 4 && std::strcmp(argv[1], "--native-font-routing-audit") == 0;
  const bool native_font_create = argc == 4 && std::strcmp(argv[1], "--native-font-create-audit") == 0;
  const bool native_font_glyph = argc == 7 && std::strcmp(argv[1], "--native-font-glyph-audit") == 0;
  const bool native_font_system = argc == 7 && std::strcmp(argv[1], "--native-font-system-audit") == 0;
  const bool native_font_file = argc == 7 && std::strcmp(argv[1], "--native-font-file-audit") == 0;
  const bool native_font_exfat = argc == 10 && std::strcmp(argv[1], "--native-font-exfat-audit") == 0;
  if (native_font_audit || native_font_routing || native_font_create || native_font_glyph || native_font_system || native_font_file || native_font_exfat) {
    options.printf_direction = Config::LogDirection::File;
    options.printf_output_file = Common::PathFromUtf8(argv[native_font_exfat ? 8 : (native_font_glyph || native_font_system || native_font_file) ? 5 : 3]);
  }
  if (json2_object_iterator_exit_child) {
    options.printf_direction = Config::LogDirection::File;
    options.printf_output_file = Common::PathFromUtf8(argv[3]);
  }
  if (guest_wait7_frontier_only) {
    guest_wait7_log = std::filesystem::temp_directory_path() /
        ("kyty_wait7_frontier_" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()) + ".log");
    std::error_code ignored;
    std::filesystem::remove(guest_wait7_log, ignored);
    options.printf_direction = Config::LogDirection::File;
    options.printf_output_file = guest_wait7_log;
#if defined(_WIN32)
    Check(_putenv_s("KYTY_DIAGNOSTIC_LOG_TIME_MARKS", "") == 0,
          "clear wait7 focused log time marks");
#else
    Check(unsetenv("KYTY_DIAGNOSTIC_LOG_TIME_MARKS") == 0,
          "clear wait7 focused log time marks");
#endif
  }
  if (exec_startup_diagnostics_only) {
    exec_startup_log = std::filesystem::temp_directory_path() /
        ("kyty_exec_startup_" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()) + ".log");
    options.printf_direction = Config::LogDirection::File;
    options.printf_output_file = exec_startup_log;
  }
  if (app_mount_contract_only) {
    app_mount_contract_log = std::filesystem::temp_directory_path() /
        ("kyty_app_mount_contract_" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()) + ".log");
    std::error_code ignored;
    std::filesystem::remove(app_mount_contract_log, ignored);
    options.printf_direction = Config::LogDirection::File;
    options.printf_output_file = app_mount_contract_log;
  }
  Config::Load(options);
  subsystems.Initialize<Log::Lifecycle>();
  const bool exec_fatal_signal_only =
      argc == 2 && std::strcmp(argv[1], "--exec-fatal-signal-only") == 0;
  const bool exec_fatal_classifier_child =
      argc == 2 && std::strcmp(argv[1], "--guest-exec-fatal-classifier-child") == 0;
  const bool exec_fatal_ud2_child =
      argc == 4 && std::strcmp(argv[1], "--guest-exec-fatal-ud2-child") == 0;
  if (exec_fatal_ud2_child) {
    Check(Libs::LibKernel::Process::InitializeExecChild(argv[2]),
          "initialize the fatal-UD2 exec-child handoff mapping");
  }
  if (!readonly_providers_only && !readonly_provider_child && !guest_wait7_frontier_only && !auth_info_scope_only && !app_mount_contract_only && !app_registration_state_only && !local_socket_policy_only && !compositor_sockets_only &&
      !sysav_audio_shm_only && !physhm_only && !audiod_extended_mmap_only && !host_exception_provenance_only && !guest_sigaction_only && !posix_sem_setname_only && !mono_native_memory_only && !psm_audio_openex_only && !psm_native_mutex_only && !psm_native_thread_rename_only && !psm_sched_range_only && !sysav_raw_syscall_trap_only && !app_classification_only && !envelope_only && !exec_fatal_classifier_child && !exec_fatal_ud2_child) {
    CheckGuestExecAuthInfoSlotRejection();
    CheckRootOriginalSelfFromApp0();
    CheckGuestExecFatalSignalPublication();
    CheckGuestExecFatalSignalTermination();
  }
  if (!readonly_providers_only && !readonly_provider_child && !guest_wait7_frontier_only && !auth_info_scope_only && !app_mount_contract_only && !app_registration_state_only && !local_socket_policy_only && !compositor_sockets_only && !exec_fatal_signal_only &&
      !sysav_audio_shm_only && !physhm_only && !audiod_extended_mmap_only && !host_exception_provenance_only && !guest_sigaction_only && !posix_sem_setname_only && !mono_native_memory_only && !psm_audio_openex_only && !psm_native_mutex_only && !psm_native_thread_rename_only && !psm_sched_range_only && !sysav_raw_syscall_trap_only && !app_classification_only && !envelope_only && !exec_fatal_classifier_child && !exec_fatal_ud2_child) {
    CheckLibcFinalization();
    CheckLibcExitStatus();
  }
  if (posix_sem_setname_only) {
    CheckPosixSemSetnameContract();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: POSIX sem_setname cases passed\n");
    return 0;
  }
  if (mono_native_memory_only) {
    CheckMonoNativeMemoryContract();
    CheckPsmMscorlibAotScope();
    CheckNativeUserServiceInitProviderGate();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: Mono native-memory cases passed\n");
    return 0;
  }
  if (psm_audio_openex_only) {
    CheckPsmAudioOpenExContract();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: PSM AudioOutOpenEx cases passed\n");
    return 0;
  }
  if (psm_native_mutex_only) {
    CheckPsmNativeMutexContract();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: PSM native-mutex cases passed\n");
    return 0;
  }
  if (psm_native_thread_rename_only) {
    CheckPsmNativeThreadRenameContract();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: PSM native-thread-rename cases passed\n");
    return 0;
  }
  if (psm_sched_range_only) {
    CheckPsmSchedRangeContract();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: PSM scheduler-range cases passed\n");
    return 0;
  }
  if (exec_fatal_ud2_child) {
    TriggerGuestExecFatalSignalUd2(Common::PathFromUtf8(argv[3]));
    return 4;
  }
  if (exec_fatal_classifier_child) {
    TempDirectory fatal_signal_temporary;
    RunGuestExecFatalSignalClassifier(fatal_signal_temporary.Path());
    subsystems.Destroy();
    return 0;
  }
  if (!readonly_providers_only && !readonly_provider_child && !guest_wait7_frontier_only && !auth_info_scope_only && !app_mount_contract_only && !app_registration_state_only && !local_socket_policy_only && !compositor_sockets_only && !sysav_audio_shm_only && !physhm_only && !audiod_extended_mmap_only && !host_exception_provenance_only && !psm_audio_openex_only && !psm_native_mutex_only && !psm_native_thread_rename_only && !psm_sched_range_only && !sysav_raw_syscall_trap_only && !app_classification_only && !envelope_only)
    CheckGuestExecFatalSignalClassifier();
  if (exec_fatal_signal_only) {
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: exec-child fatal signal cases passed\n");
    return 0;
  }

  if (app_classification_only) {
    FileSystem::Initialize();
    CheckOriginalAppClassification(Common::PathFromUtf8(argv[2]));
    FileSystem::Shutdown();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: original app-classification cases passed\n");
    return 0;
  }

  if (argc == 1 || audiod_extended_mmap_only) {
    CheckAudiodExtendedMmap();
    TempDirectory audiod_extended_mmap_temporary;
    CheckAudiodExtendedMmapTrap(audiod_extended_mmap_temporary.Path());
    if (audiod_extended_mmap_only) {
      subsystems.Destroy();
      std::printf("KernelFileSystemTests: Audiod extended-mmap cases passed\n");
      return 0;
    }
  }

  if (argc == 1 || host_exception_provenance_only) {
    TempDirectory host_exception_provenance_temporary;
    CheckUnhandledHostExceptionDiagnostics(host_exception_provenance_temporary.Path());
    if (host_exception_provenance_only) {
      subsystems.Destroy();
      std::printf("KernelFileSystemTests: host-exception provenance cases passed\n");
      return 0;
    }
  }

  if (argc == 1 ||
      (argc == 2 && std::strcmp(argv[1], "--authinfo-scope-lifecycle-only") == 0)) {
    CheckAuthInfoScopeLifecycle();
    if (argc == 2) {
      subsystems.Destroy();
      std::printf("KernelFileSystemTests: scoped AuthInfo lifecycle cases passed\n");
      return 0;
    }
  }

  if (argc == 1 || app_mount_contract_only) {
    CheckAppMountContract();
#if defined(_WIN32)
    CheckBudgetContract();
    CheckBudgetModel();
    CheckNativeAppMount();
    CheckSysCoreSpawnAppMount();
#endif
    if (app_mount_contract_only) {
      Log::Flush();
      std::ifstream diagnostic_log(app_mount_contract_log, std::ios::binary);
      const std::string diagnostic_text((std::istreambuf_iterator<char>(diagnostic_log)),
                                        std::istreambuf_iterator<char>());
      Check(diagnostic_text.find("APP_KILL_LIFECYCLE_END app_id=4 guest_pid=7106 process=alive source=rfork_child") != std::string::npos &&
                diagnostic_text.find("APP_KILL_LIFECYCLE_END_SUMMARY app_id=4 associated=1 alive=1 dead=0 unknown=0") != std::string::npos,
            "app-mount lifecycle diagnostic reports exact live state without changing teardown");
      subsystems.Destroy();
      std::error_code ignored;
      std::filesystem::remove(app_mount_contract_log, ignored);
      std::printf("KernelFileSystemTests: app-mount contract cases passed\n");
      return 0;
    }
  }

#if defined(_WIN32)
  if (argc == 1 || regmgr_snapshot_only) {
    TempDirectory regmgr_temporary;
    CheckRegMgrSnapshot(regmgr_temporary.Path());
    if (regmgr_snapshot_only) {
      subsystems.Destroy();
      std::printf("KernelFileSystemTests: registry snapshot cases passed\n");
      return 0;
    }
  }
#endif

  if (argc == 1 || app_registration_state_only) {
    CheckAppRegistrationState();
    if (app_registration_state_only) {
      subsystems.Destroy();
      std::printf("KernelFileSystemTests: application registration state cases passed\n");
      return 0;
    }
  }

  if (argc == 1 || sysav_raw_syscall_trap_only) {
    TempDirectory sysav_raw_syscall_trap_temporary;
    CheckSysAvRawSyscallTrap(sysav_raw_syscall_trap_temporary.Path());
    if (sysav_raw_syscall_trap_only) {
      subsystems.Destroy();
      std::printf("KernelFileSystemTests: SysAv raw-syscall trap naming cases passed\n");
      return 0;
    }
  }

  if (!readonly_providers_only && !readonly_provider_child && !envelope_only)
    CheckGuestWait7Frontier(guest_wait7_frontier_only, guest_wait7_log);
  if (guest_wait7_frontier_only) {
    subsystems.Destroy();
    CheckGuestWait7FrontierLog(guest_wait7_log);
    std::error_code ignored;
    std::filesystem::remove(guest_wait7_log, ignored);
    std::printf("KernelFileSystemTests: guest wait7 frontier cases passed\n");
    return 0;
  }

  Check(SDL_InitSubSystem(SDL_INIT_VIDEO), "initialize Vulkan test video");
  auto graphics = std::make_unique<Libs::Graphics::WindowContext>();
  graphics->graphic_ctx.screen_width = 64;
  graphics->graphic_ctx.screen_height = 64;
  graphics->window = SDL_CreateWindow("KernelFileSystemTests", 64, 64,
                                      SDL_WINDOW_VULKAN | SDL_WINDOW_HIDDEN);
  Check(graphics->window != nullptr, "create hidden Vulkan test window");
  graphics->CreateVulkan();

  TempDirectory temporary;
  FileSystem::Initialize();
  if (registry_traps_only) {
    CheckRegistryTraps(temporary.Path());
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: registry trap and native sysctl cases passed\n");
    return 0;
  }
  const int nullfs_child = RunNullfsExecChild(argc, argv);
  if (nullfs_child >= 0) {
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    return nullfs_child;
  }
  const int provider_child = RunReadOnlyProviderChild(argc, argv);
  if (provider_child >= 0) {
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    return provider_child;
  }
  const int sysav_umd_child = RunSysAvUmdCrossHostChild(argc, argv);
  if (sysav_umd_child >= 0) {
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    return sysav_umd_child;
  }
  if (argc == 1 || readonly_providers_only) {
    {
      TempDirectory provider_temporary;
      CheckReadOnlyProviderExec(provider_temporary.Path());
    }
    if (argc == 2) {
      CheckCapturedDirectoryFallback(temporary.Path());
      CheckInitialRootRelativeProviderPaths(temporary.Path());
      CheckDirectoryPassthroughBackend(temporary.Path());
      CheckDirectoryPassthroughGuestMount(temporary.Path());
      CheckDirectoryPassthroughGetdentsBoundary(temporary.Path());
      CheckPassthroughUpperStore(temporary.Path());
      CheckFactoryStorageView(temporary.Path());
      FileSystem::Shutdown();
      graphics.reset();
      subsystems.Destroy();
      std::printf("KernelFileSystemTests: read-only provider cases passed\n");
      return 0;
    }
  }
  if (argc == 2 && std::strcmp(argv[1], "--mbus-lifetime-only") == 0) {
    CheckMbusDescriptorLifetimes();
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: MBus lifetime cases passed\n");
    return 0;
  }
  if ((argc == 2 || argc == 3) && std::strcmp(argv[1], "--positioned-io-only") == 0) {
    CheckPositionedIo(temporary.Path(), argc == 3 ? argv[2] : "all");
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: positioned I/O cases passed\n");
    return 0;
  }
  if (argc == 6 && std::strcmp(argv[1], "--exfat-original-image") == 0) {
    char* end = nullptr;
    const auto capacity = std::strtoull(argv[3], &end, 0);
    Check(end != argv[3] && *end == '\0' && capacity != 0, "parse exfat declared capacity");
    CheckExfatOriginalGuestMount(temporary.Path(), Common::PathFromUtf8(argv[2]), capacity,
                                argv[4], Common::PathFromUtf8(argv[5]));
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--exfat-publication-race-only") == 0) {
    CheckExfatMountPublicationRace(temporary.Path());
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: exFAT publication race cases passed\n");
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--exfat-mount-only") == 0) {
    CheckExfatMountBackend(temporary.Path());
    CheckExfatGuestMount(temporary.Path());
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: exFAT mount cases passed\n");
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--tmpfs-mounts-only") == 0) {
    CheckTmpfsMounts(temporary.Path());
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--wait-output-counts-only") == 0) {
    CheckWaitOutputCounts();
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: wait output count cases passed\n");
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--sysav-kevent-umd-only") == 0) {
    CheckNativeKeventSafety();
    CheckSysAvKeventUmd();
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: SysAv kevent UMD cases passed\n");
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--nested-readiness-only") == 0) {
    CheckNestedReadiness();
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: nested readiness cases passed\n");
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--write-errors-only") == 0) {
    CheckWriteErrors(temporary.Path());
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: write error cases passed\n");
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--weak-relocations-only") == 0) {
    CheckWeakRelocations(temporary.Path());
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: weak relocation cases passed\n");
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--thread-atexit-lifetime-only") == 0) {
    CheckThreadAtexitLifetimes(temporary.Path());
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: thread atexit lifetime cases passed\n");
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--guest-jump-only") == 0) {
    CheckGuestSignalMasks();
    CheckGuestJumps();
    CheckGuestPendingSignalDelivery();
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: guest jump cases passed\n");
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--guest-signal-mask-only") == 0) {
    CheckGuestSignalMasks();
    CheckGuestPendingSignalDelivery();
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: guest signal mask cases passed\n");
    return 0;
  }
  if (native_font_exfat) {
    char* end = nullptr;
    const auto capacity = std::strtoull(argv[4], &end, 0);
    Check(end != argv[4] && *end == '\0' && capacity != 0, "parse captured font volume capacity");
    const auto codepoint = std::strtoull(argv[7], &end, 0);
    Check(end != argv[7] && *end == '\0' && codepoint <= UINT32_MAX, "parse captured font codepoint");
    Libs::LibKernel::SectorBacking::Result media;
    std::shared_ptr<Libs::LibKernel::SectorBacking> backing = Libs::LibKernel::SectorBacking::Open(
        Common::PathFromUtf8(argv[3]), {}, 4096, capacity, argv[5], &media);
    Check(backing && media == Libs::LibKernel::SectorBacking::Result::Ok,
          "open immutable explicit captured font volume");
    Libs::LibKernel::ExfatVolume::Result indexed;
    std::shared_ptr<Libs::LibKernel::ExfatVolume> volume = Libs::LibKernel::ExfatVolume::Open(backing, &indexed);
    Check(volume && indexed == Libs::LibKernel::ExfatVolume::Result::Ok, "validate font volume metadata");
    const auto root = Common::PathFromUtf8(argv[2]);
    FileSystem::MountReadOnly(root, "/");
    Check(FileSystem::MountExfatReadOnly("/system_ex", volume) == OK,
          "mount explicitly selected captured resources for isolated font audit");
    const auto asset = Common::PathFromUtf8(argv[6]);
    Check(Libs::LibKernel::ExfatMount::Contains("/" + asset.generic_string()) &&
          FileSystem::GetRealFilename("/" + asset.generic_string()).empty(),
          "font file path is backed by sectors without host fallback");
    std::printf("NATIVE_FONT_EXFAT\n");
    const int result = AuditNativeFontGlyph(root, asset, static_cast<uint32_t>(codepoint),
                                         Common::PathFromUtf8(argv[9]), false, true);
    FileSystem::Umount("/system_ex");
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    return result;
  }
  if (native_font_glyph || native_font_system || native_font_file) {
    char* end = nullptr;
    const auto codepoint = std::strtoull(argv[4], &end, 0);
    Check(end != argv[4] && *end == '\0' && codepoint <= UINT32_MAX, "parse explicit glyph codepoint");
    const int result = AuditNativeFontGlyph(Common::PathFromUtf8(argv[2]), Common::PathFromUtf8(argv[3]),
        static_cast<uint32_t>(codepoint), Common::PathFromUtf8(argv[6]), native_font_system, native_font_file);
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    return result;
  }
  if (native_font_create) {
    const int result = AuditNativeFontCreate(Common::PathFromUtf8(argv[2]));
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    return result;
  }
  if (native_font_routing) {
    const int result = AuditNativeFontRouting(Common::PathFromUtf8(argv[2]), temporary.Path());
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    return result;
  }
  if (argc == 5 && std::strcmp(argv[1], "--resource-arbitrator-capture-audit") == 0) {
    AuditResourceArbitratorCapture(Common::PathFromUtf8(argv[2]),
                                   Common::PathFromUtf8(argv[3]), argv[4]);
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    return 0;
  }
  if (argc == 3 && std::strcmp(argv[1], "--captured-root-audit") == 0) {
    CheckCapturedRootIntegration(temporary.Path(), Common::PathFromUtf8(argv[2]));
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    return 0;
  }
  if (argc == 3 && std::strcmp(argv[1], "--captured-root-cache-only") == 0) {
    CheckCapturedRootStartupCache(temporary.Path(), Common::PathFromUtf8(argv[2]));
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--captured-root-only") == 0) {
    CheckCapturedRootMetadata(temporary.Path());
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--sysmodule-dependencies-only") == 0) {
    CheckSysmoduleDependencies(temporary.Path());
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: sysmodule dependency cases passed\n");
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--sysmodule-font-only") == 0) {
    CheckSysmoduleFontProviders(temporary.Path());
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: sysmodule font cases passed\n");
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--native-metadbg-only") == 0) {
    CheckNativeMetadbg();
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: native metadbg cases passed\n");
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--native-ipmi-only") == 0) {
    CheckNativeStrictIpmi();
    CheckImportedIpmiErrors();
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    std::printf("KernelFileSystemTests: native IPMI cases passed\n");
    return 0;
  }
  if (argc == 1 ||
      (argc == 2 && std::strcmp(argv[1], "--native-self-authinfo-only") == 0)) {
    CheckNativeSelfAuthInfo(temporary.Path());
    if (argc == 2) {
      FileSystem::Shutdown();
      graphics.reset();
      subsystems.Destroy();
      std::printf("KernelFileSystemTests: native self auth info cases passed\n");
      return 0;
    }
  }
  if (argc == 1 || (argc == 2 && std::strcmp(argv[1], "--kern-proc-pid-only") == 0)) {
    CheckKernProcPid();
    if (argc == 2) {
      FileSystem::Shutdown();
      graphics.reset();
      subsystems.Destroy();
      std::printf("KernelFileSystemTests: kern.proc.pid cases passed\n");
      return 0;
    }
  }
  if (argc == 1 || (argc == 2 && std::strcmp(argv[1], "--semaphore-lifetimes-only") == 0)) {
    CheckSemaphoreLifetimes();
    if (argc == 2) {
      FileSystem::Shutdown();
      graphics.reset();
      subsystems.Destroy();
      std::printf("KernelFileSystemTests: semaphore lifetime cases passed\n");
      return 0;
    }
  }
  if (argc == 1 || (argc == 2 && std::strcmp(argv[1], "--semaphore-crosshost-only") == 0)) {
    CheckSemaphoreCrossHost();
    if (argc == 2) {
      FileSystem::Shutdown();
      graphics.reset();
      subsystems.Destroy();
      std::printf("KernelFileSystemTests: semaphore cross-host cases passed\n");
      return 0;
    }
  }
  if (argc == 1 || (argc == 2 && std::strcmp(argv[1], "--eventflag-lifetimes-only") == 0)) {
    CheckEventFlagLifetimes();
    if (argc == 2) {
      FileSystem::Shutdown();
      graphics.reset();
      subsystems.Destroy();
      std::printf("KernelFileSystemTests: eventflag lifetime cases passed\n");
      return 0;
    }
  }
  if (argc == 1 || (argc == 2 && std::strcmp(argv[1], "--imported-mount-only") == 0)) {
    CheckImportedMounts(temporary.Path());
    if (argc == 2) {
      FileSystem::Shutdown();
      graphics.reset();
      subsystems.Destroy();
      std::printf("KernelFileSystemTests: imported mount cases passed\n");
      return 0;
    }
  }
  if (argc == 1 || (argc == 2 && std::strcmp(argv[1], "--posix-open-only") == 0)) {
    CheckImportedPosixOpen(temporary.Path());
    if (argc == 2) {
      FileSystem::Shutdown();
      graphics.reset();
      subsystems.Destroy();
      std::printf("KernelFileSystemTests: POSIX open cases passed\n");
      return 0;
    }
  }
#if defined(_WIN32)
  if (argc == 1 || (argc == 2 && std::strcmp(argv[1], "--devctl-only") == 0)) {
    CheckDevctl();
    if (argc == 2) {
      FileSystem::Shutdown();
      graphics.reset();
      subsystems.Destroy();
      std::printf("KernelFileSystemTests: devctl cases passed\n");
      return 0;
    }
  }
  if (argc == 1 || (argc == 2 && std::strcmp(argv[1], "--envelope-only") == 0)) {
    TempDirectory envelope_temporary;
    CheckEnvelope(envelope_temporary.Path());
    if (argc == 2) {
      FileSystem::Shutdown();
      graphics.reset();
      subsystems.Destroy();
      std::printf("KernelFileSystemTests: envelope cases passed\n");
      return 0;
    }
  }
  if (argc == 1 || (argc == 2 && std::strcmp(argv[1], "--devfs-root-only") == 0)) {
    TempDirectory devfs_temporary;
    CheckDevfsRoot(devfs_temporary.Path());
    CheckPosixSleep();
    CheckPosixRemove(devfs_temporary.Path());
    if (argc == 2) {
      FileSystem::Shutdown();
      graphics.reset();
      subsystems.Destroy();
      std::printf("KernelFileSystemTests: devfs root and sleep cases passed\n");
      return 0;
    }
  }
#endif
  if (argc != 1 && !(argc == 2 &&
      (std::strcmp(argv[1], "--native-mbus-only") == 0 ||
       std::strcmp(argv[1], "--native-av-devices-only") == 0))) {
    std::fprintf(stderr, "KernelFileSystemTests: unsupported test arguments\n");
    FileSystem::Shutdown();
    graphics.reset();
    subsystems.Destroy();
    return 2;
  }
  CheckMountRoot(temporary.Path());
  CheckUnmappedPaths(temporary.Path());
  CheckReadOnlyBacking(temporary.Path());
  CheckIccnvs4Snapshot(temporary.Path());
  CheckIccnvs4Overlay(temporary.Path());
  CheckNativeIpmiTraceHooks();
  CheckSectorDescriptors(temporary.Path());
  CheckArchiveMount(temporary.Path());
  CheckUnicodePaths(temporary.Path());
  CheckUnicodeLogPath(temporary.Path());
  CheckDirectoryStream(temporary.Path());
  CheckPositionedIo(temporary.Path(), "all");
  CheckWriteErrors(temporary.Path());
  CheckExfatMountBackend(temporary.Path());
  CheckExfatGuestMount(temporary.Path());
  CheckDirectoryPassthroughBackend(temporary.Path());
  CheckCapturedDirectoryFallback(temporary.Path());
  CheckInitialRootRelativeProviderPaths(temporary.Path());
  CheckDirectoryPassthroughGuestMount(temporary.Path());
  CheckDirectoryPassthroughGetdentsBoundary(temporary.Path());
  CheckExfatMountPublicationRace(temporary.Path());
  CheckAprPaths(temporary.Path());
  FileSystem::Mount(temporary.Path(), "/savedata0");
  TestSaveOpenVisibility();
  TestAioBatches();
  CheckSaveRename(temporary.Path(), "first-save");
  CheckSaveRename(temporary.Path(), "replacement-save");
  FileSystem::Shutdown();
  CheckSocketWakeup();
  TestNpWebApi2Memory();
  TestNpWebApi2PushOwnership();
  TestJson2ArrayIteratorIncrement();
  TestJson2StringCompare();
  TestJson2ArrayCopy();
  TestJson2ResourceArbitratorDerived();
  graphics.reset();
  subsystems.Destroy();

  std::printf("KernelFileSystemTests: all cases passed\n");
  return 0;
}
