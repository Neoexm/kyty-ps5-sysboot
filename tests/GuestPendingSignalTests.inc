using GuestPendingSignalMaskCall = int (KYTY_SYSV_ABI *)(int, const void*, void*);
using GuestPendingSignalInstallCall = int (KYTY_SYSV_ABI *)(int, void*);
using GuestPendingSignalRemoveCall = int (KYTY_SYSV_ABI *)(int);
using GuestPendingSignalRaiseCall = int (KYTY_SYSV_ABI *)(Libs::LibKernel::Pthread, int);

static std::atomic_int g_pending_signal_test_count {0};
static std::atomic_int g_pending_signal_test_number {0};
static std::atomic<Libs::LibKernel::Pthread> g_pending_signal_test_thread {nullptr};
static std::atomic_bool g_pending_signal_test_context {false};

void KYTY_SYSV_ABI GuestPendingSignalTestHandler(int signum, void* context) {
  g_pending_signal_test_number.store(signum, std::memory_order_relaxed);
  g_pending_signal_test_thread.store(Libs::LibKernel::PthreadSelfOrNull(), std::memory_order_relaxed);
  g_pending_signal_test_context.store(context != nullptr, std::memory_order_relaxed);
  g_pending_signal_test_count.fetch_add(1, std::memory_order_release);
}

struct GuestPendingSignalWorker {
  GuestPendingSignalMaskCall mask;
  GuestPendingSignalMaskCall unblock;
  GuestPendingSignalInstallCall install;
  GuestPendingSignalRemoveCall remove;
  GuestPendingSignalRaiseCall raise;
  Libs::LibKernel::PthreadSignalMask* input;
  Libs::LibKernel::PthreadSignalMask* saved;
  Libs::LibKernel::PthreadSignalMask* queried;
  int install_result = -1;
  int remove_result = -1;
  bool blocked_pending = false;
  bool query_keeps_pending = false;
  bool delivered_once = false;
  bool no_replay = false;
  bool restored_mask = false;
  std::atomic_bool complete {false};
};

void* KYTY_SYSV_ABI GuestPendingSignalWorkerEntry(void* argument) {
  using namespace Libs::LibKernel;
  auto* worker = static_cast<GuestPendingSignalWorker*>(argument);
  auto* self = PthreadSelfOrNull();
  worker->install_result = worker->install(30, reinterpret_cast<void*>(GuestPendingSignalTestHandler));
  if (worker->install_result == 0) {
    g_pending_signal_test_count.store(0, std::memory_order_relaxed);
    g_pending_signal_test_number.store(0, std::memory_order_relaxed);
    g_pending_signal_test_thread.store(nullptr, std::memory_order_relaxed);
    g_pending_signal_test_context.store(false, std::memory_order_relaxed);
    const bool saved = self != nullptr && worker->mask(0, nullptr, worker->saved) == 0;
    *worker->input = {{1ull << 29, 0}};
    if (saved && worker->mask(1, worker->input, nullptr) == 0 &&
        worker->raise(self, 30) == 0) {
      worker->blocked_pending = PthreadIsSignalBlocked(self, 30) &&
          PthreadHasPendingSignal(self, 30) &&
          g_pending_signal_test_count.load(std::memory_order_acquire) == 0;
      worker->query_keeps_pending = worker->mask(0, nullptr, worker->queried) == 0 &&
          (worker->queried->words[0] & (1ull << 29)) != 0 &&
          PthreadHasPendingSignal(self, 30) &&
          g_pending_signal_test_count.load(std::memory_order_acquire) == 0;
      const int unblocked = worker->unblock(2, worker->input, nullptr);
      worker->delivered_once = unblocked == 0 && !PthreadIsSignalBlocked(self, 30) &&
          !PthreadHasPendingSignal(self, 30) &&
          g_pending_signal_test_count.load(std::memory_order_acquire) == 1 &&
          g_pending_signal_test_number.load(std::memory_order_relaxed) == 30 &&
          g_pending_signal_test_thread.load(std::memory_order_relaxed) == self &&
          g_pending_signal_test_context.load(std::memory_order_relaxed);
      worker->no_replay = worker->unblock(2, worker->input, nullptr) == 0 &&
          worker->mask(0, nullptr, worker->queried) == 0 &&
          !PthreadHasPendingSignal(self, 30) &&
          g_pending_signal_test_count.load(std::memory_order_acquire) == 1;
    }
    worker->remove_result = worker->remove(30);
    if (saved) {
      worker->restored_mask = worker->mask(3, worker->saved, nullptr) == 0 &&
          worker->mask(0, nullptr, worker->queried) == 0 &&
          std::memcmp(worker->saved, worker->queried, sizeof(PthreadSignalMask)) == 0;
    }
  }
  worker->complete.store(true, std::memory_order_release);
  return nullptr;
}

void CheckGuestPendingSignalDelivery() {
  using namespace Libs::LibKernel;
  GuestNativeSignalMaskScope native_scope;
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* mask_symbol = symbols.FindByNid("6xVpy0Fdq+I", Loader::SymbolType::Func);
  const auto* install_symbol = symbols.FindByNid("WkwEd3N7w0Y", Loader::SymbolType::Func);
  const auto* remove_symbol = symbols.FindByNid("Qhv5ARAoOEc", Loader::SymbolType::Func);
  const auto* raise_symbol = symbols.FindByNid("il03nluKfMk", Loader::SymbolType::Func);
  Check(mask_symbol && install_symbol && remove_symbol && raise_symbol,
        "resolve signal mask and exception handler exports");
  const auto address = Memory::AllocateProgramMemory(0, 0x4000,
      Common::VirtualMemory::Mode::ReadWrite, "pending_signal_test");
  Check(address != 0, "allocate guest pending-signal fixture");
  auto* buffers = reinterpret_cast<PthreadSignalMask*>(address);
  GuestPendingSignalWorker worker {
      reinterpret_cast<GuestPendingSignalMaskCall>(mask_symbol->vaddr),
      GuestNativeSignalMaskCall,
      reinterpret_cast<GuestPendingSignalInstallCall>(install_symbol->vaddr),
      reinterpret_cast<GuestPendingSignalRemoveCall>(remove_symbol->vaddr),
      reinterpret_cast<GuestPendingSignalRaiseCall>(raise_symbol->vaddr),
      buffers, buffers + 1, buffers + 2};
  Pthread thread = nullptr;
  Check(PthreadCreate(&thread, nullptr, GuestPendingSignalWorkerEntry, &worker,
                      "pending_signal_mask") == 0, "create guest signal delivery worker");
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (!worker.complete.load(std::memory_order_acquire) &&
         std::chrono::steady_clock::now() < deadline) std::this_thread::yield();
  Check(worker.complete.load(std::memory_order_acquire), "pending signal worker completes within deadline");
  Check(PthreadJoin(thread, nullptr) == 0, "join guest signal delivery worker");
  Check(worker.install_result == 0, "signal fixture acquires an unused original exception handler slot");
  Check(worker.remove_result == 0 && worker.restored_mask,
        "worker removes its global handler and restores its complete inherited mask");
  Check(worker.blocked_pending && worker.query_keeps_pending,
        "blocked guest SIGUSR1 stays pending without calling its handler");
  Check(worker.delivered_once && worker.no_replay,
        "native unblock delivers once on the owning guest Pthread and consumes the imported pending signal");
  Check(worker.install(30, reinterpret_cast<void*>(GuestPendingSignalTestHandler)) == 0,
        "scoped worker leaves the global handler slot available");
  Check(worker.remove(30) == 0, "release the handler slot after cleanup verification");
  Check(Memory::FreeGuestMemory(address, 0x4000), "release pending signal guest fixture");
  std::printf("GuestPendingSignalTests: blocked_pending=pass query_keeps_pending=pass unblock_delivers_once=pass owning_thread=pass no_replay=pass cleanup=pass\n");
}
