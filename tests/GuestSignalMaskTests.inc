using GuestSignalMaskCall = int (KYTY_SYSV_ABI *)(int, const void*, void*);

class GuestNativeSignalMaskScope {
public:
  explicit GuestNativeSignalMaskScope(bool enabled = true) {
    for (size_t i = 0; i < keys.size(); ++i) {
      const auto* value = std::getenv(keys[i]);
      present[i] = value != nullptr;
      previous[i] = value == nullptr ? "" : value;
      Set(keys[i], enabled && i == 0 ? "1" : nullptr);
    }
  }

  ~GuestNativeSignalMaskScope() {
    for (size_t i = 0; i < keys.size(); ++i) Set(keys[i], present[i] ? previous[i].c_str() : nullptr);
  }

private:
  static void Set(const char* key, const char* value) {
#if defined(_WIN32)
    Check(_putenv_s(key, value == nullptr ? "" : value) == 0, "set scoped native signal-mask environment");
#else
    Check((value == nullptr ? unsetenv(key) : setenv(key, value, 1)) == 0,
          "set scoped native signal-mask environment");
#endif
  }

  const std::array<const char*, 2> keys {"KYTY_DIAGNOSTIC_STATIC_EXEC_TRAP_SYSCALLS",
      "KYTY_DIAGNOSTIC_MINI_SYSCORE_NATIVE_TRAPS"};
  std::array<std::string, 2> previous;
  std::array<bool, 2> present {};
};

Libs::NativeKernelBridge::Reply GuestNativeSignalMaskReply(int how, const void* set, void* oset) {
  return Libs::NativeKernelBridge::DispatchSyscall({0x154,
      {static_cast<uint64_t>(how), reinterpret_cast<uint64_t>(set), reinterpret_cast<uint64_t>(oset)}});
}

int KYTY_SYSV_ABI GuestNativeSignalMaskCall(int how, const void* set, void* oset) {
  const auto reply = GuestNativeSignalMaskReply(how, set, oset);
  return reply.value == 0 && reply.posix_errno == 0 ? 0 : -1;
}

struct GuestSignalMaskWorker {
  GuestSignalMaskCall call;
  Libs::LibKernel::PthreadSignalMask inherited;
  Libs::LibKernel::PthreadSignalMask changed;
  void* input;
  void* output;
  std::atomic_bool ready {false};
  std::atomic_bool release {false};
  bool passed = false;
};

void* KYTY_SYSV_ABI GuestSignalMaskWorkerEntry(void* argument) {
  using namespace Libs::LibKernel;
  auto* worker = static_cast<GuestSignalMaskWorker*>(argument);
  const auto* self = PthreadSelfOrNull();
  worker->passed = self != nullptr && !PthreadHasPendingSignal(PthreadSelfOrNull(), 30) &&
      worker->call(0, nullptr, worker->output) == 0 &&
      std::memcmp(worker->output, &worker->inherited, 16) == 0;
  std::memcpy(worker->input, &worker->changed, 16);
  worker->passed = worker->passed && worker->call(3, worker->input, nullptr) == 0;
  worker->ready.store(true, std::memory_order_release);
  while (!worker->release.load(std::memory_order_acquire)) std::this_thread::yield();
  return nullptr;
}

void CheckGuestSignalMasks() {
  using namespace Libs::LibKernel;
  Common::Singleton<Loader::RuntimeLinker>::Instance();
  Loader::SymbolDatabase symbols;
  Libs::InitLibKernel_1(&symbols);
  const auto* exported = symbols.FindByNid("6xVpy0Fdq+I", Loader::SymbolType::Func);
  Check(exported != nullptr, "resolve sigprocmask export");
  const auto call = reinterpret_cast<GuestSignalMaskCall>(exported->vaddr);
  const auto address = Memory::AllocateProgramMemory(0, 0x8000,
      Common::VirtualMemory::Mode::ReadWrite, "signal_mask_test");
  Check(address != 0, "allocate guest signal-mask fixture");
  auto* page = reinterpret_cast<uint8_t*>(address);
  auto* input = reinterpret_cast<PthreadSignalMask*>(page + 32);
  auto* output = reinterpret_cast<PthreadSignalMask*>(page + 80);
  auto* saved = reinterpret_cast<PthreadSignalMask*>(page + 128);
  Check(call(0, nullptr, saved) == 0, "query initial mask with ignored how");
  const PthreadSignalMask empty {};
  const PthreadSignalMask a {{(1ull << 29) | (1ull << 62), (1ull << 1) | (1ull << 63)}};
  const PthreadSignalMask b {{1ull << 3, (1ull << 5) | (1ull << 40)}};
  auto set = [&](PthreadSignalMask mask) {
    *input = mask;
    Check(call(3, input, nullptr) == 0, "replace guest mask");
  };
  auto query = [&](PthreadSignalMask expected) {
    std::memset(page + 64, 0x71, 48);
    Check(call(-47, nullptr, output) == 0 && std::memcmp(output, &expected, 16) == 0,
          "query all four native mask words");
    for (size_t i = 64; i < 80; ++i) Check(page[i] == 0x71, "query preserves leading canary");
    for (size_t i = 96; i < 112; ++i) Check(page[i] == 0x71, "query preserves trailing canary");
  };
  set(empty);
  query(empty);
  *input = a;
  auto* error = Libs::Posix::GetErrorAddr();
  *error = Libs::Posix::POSIX_EIO;
  Check(call(1, input, output) == 0 && std::memcmp(output, &empty, 16) == 0 &&
        *error == Libs::Posix::POSIX_EIO, "block returns old mask and preserves errno");
  query(a);
  *input = b;
  Check(call(1, input, input) == 0 && std::memcmp(input, &a, 16) == 0,
        "aliased block snapshots request before writing old mask");
  const PthreadSignalMask both {{a.words[0] | b.words[0], a.words[1] | b.words[1]}};
  query(both);
  *input = a;
  Check(call(2, input, input) == 0 && std::memcmp(input, &both, 16) == 0,
        "aliased unblock snapshots all sixteen input bytes");
  query(b);
  *input = a;
  Check(call(3, input, input) == 0 && std::memcmp(input, &b, 16) == 0,
        "aliased replace returns previous mask");
  query(a);
  *input = {{UINT64_MAX, UINT64_MAX}};
  Check(call(3, input, nullptr) == 0, "accept the full native signal set");
  const PthreadSignalMask allowed {{UINT64_MAX & ~((1ull << 8) | (1ull << 16) | (1ull << 31)), UINT64_MAX}};
  query(allowed);
  Check(call(4, input, output) == -1 && *error == Libs::Posix::POSIX_EINVAL,
        "reject invalid mutation how with native errno");
  query(allowed);
  Check(call(3, page + 0x8000 - 8, nullptr) == -1 && *error == Libs::Posix::POSIX_EFAULT,
        "reject partial unmapped input span");
  query(allowed);
  *input = a;
  Check(call(3, input, page + 0x8000 - 8) == -1 && *error == Libs::Posix::POSIX_EFAULT,
        "report failed old-mask copyout after applying native mutation");
  query(a);
  Check(call(3, reinterpret_cast<void*>(UINT64_MAX - 7), nullptr) == -1 &&
        *error == Libs::Posix::POSIX_EFAULT, "reject wrapping mask span");
  PthreadSignalMask stack_output {};
  Check(call(1, nullptr, &stack_output) == 0 && std::memcmp(&stack_output, &a, 16) == 0,
        "libc may query masks into a current host-stack jump buffer");

  {
    GuestNativeSignalMaskScope disabled(false);
    *output = b;
    const auto unavailable = GuestNativeSignalMaskReply(3, input, output);
    Check(unavailable.value == -1 && unavailable.posix_errno == Libs::Posix::POSIX_ENOSYS &&
              std::memcmp(output, &b, sizeof(b)) == 0,
          "native signal masks stay unavailable without the existing syscall gates");
    query(a);
  }
  GuestNativeSignalMaskScope native_scope;
  *input = b;
  *error = Libs::Posix::POSIX_EIO;
  const auto replaced = GuestNativeSignalMaskReply(3, input, output);
  Check(replaced.value == 0 && replaced.posix_errno == 0 &&
            std::memcmp(output, &a, sizeof(a)) == 0 && *error == Libs::Posix::POSIX_EIO,
        "native replacement returns imported state without changing guest libc errno");
  for (size_t i = 64; i < 80; ++i) Check(page[i] == 0x71, "native mask copyout preserves leading canary");
  for (size_t i = 96; i < 112; ++i) Check(page[i] == 0x71, "native mask copyout preserves trailing canary");
  query(b);
  set(a);
  const auto queried = GuestNativeSignalMaskReply(-47, nullptr, output);
  Check(queried.value == 0 && queried.posix_errno == 0 && std::memcmp(output, &a, sizeof(a)) == 0,
        "native query observes imported replacement and ignores how with a null set");
  *input = b;
  const auto blocked = GuestNativeSignalMaskReply(1, input, input);
  Check(blocked.value == 0 && blocked.posix_errno == 0 && std::memcmp(input, &a, sizeof(a)) == 0,
        "native aliased block snapshots the mask before returning previous state");
  query(both);
  *input = b;
  const auto unblocked = GuestNativeSignalMaskReply(2, input, output);
  Check(unblocked.value == 0 && unblocked.posix_errno == 0 &&
            std::memcmp(output, &both, sizeof(both)) == 0,
        "native unblock returns the complete previous mask");
  query(a);
  *input = {{UINT64_MAX, UINT64_MAX}};
  Check(GuestNativeSignalMaskCall(3, input, nullptr) == 0,
        "native replacement filters the same unmaskable signals as imported calls");
  query(allowed);
  set(a);
  const auto bad_how = GuestNativeSignalMaskReply(4, input, output);
  Check(bad_how.value == -1 && bad_how.posix_errno == Libs::Posix::POSIX_EINVAL &&
            *error == Libs::Posix::POSIX_EIO,
        "native invalid mutation reports EINVAL without changing guest libc errno");
  query(a);
  const auto bad_input = GuestNativeSignalMaskReply(3, page + 0x8000 - 8, nullptr);
  const auto wrapped_input = GuestNativeSignalMaskReply(3, reinterpret_cast<void*>(UINT64_MAX - 7), nullptr);
  Check(bad_input.value == -1 && bad_input.posix_errno == Libs::Posix::POSIX_EFAULT &&
            wrapped_input.value == -1 && wrapped_input.posix_errno == Libs::Posix::POSIX_EFAULT,
        "native copyin rejects partial and wrapping signal masks");
  query(a);
  *input = b;
  const auto bad_output = GuestNativeSignalMaskReply(3, input, page + 0x8000 - 8);
  Check(bad_output.value == -1 && bad_output.posix_errno == Libs::Posix::POSIX_EFAULT &&
            *error == Libs::Posix::POSIX_EIO,
        "native failed old-mask copyout preserves errno after applying the mutation");
  query(b);
  Check(GuestNativeSignalMaskCall(3, saved, nullptr) == 0,
        "native restore accepts the complete saved imported mask");
  set(a);

  GuestSignalMaskWorker worker {GuestNativeSignalMaskCall, a, b, page + 192, page + 224};
  Pthread child = nullptr;
  Check(PthreadCreate(&child, nullptr, GuestSignalMaskWorkerEntry, &worker, "signal_mask") == 0,
        "create guest Pthread inheriting creator mask");
  while (!worker.ready.load(std::memory_order_acquire)) std::this_thread::yield();
  Check(worker.passed, "native child inherits imported mask words with no stale pending signals");
  query(a);
  auto* previous_self = PthreadSwapSelfForSignal(child);
  query(b);
  PthreadSwapSelfForSignal(previous_self);
  query(a);
  PthreadQueuePendingSignal(child, 30);
  worker.release.store(true, std::memory_order_release);
  Check(PthreadJoin(child, nullptr) == 0, "join signal-mask fixture Pthread");
  set(b);
  GuestSignalMaskWorker reused {call, b, a, page + 192, page + 224};
  Check(PthreadCreate(&child, nullptr, GuestSignalMaskWorkerEntry, &reused, "signal_mask_reuse") == 0,
        "create another guest Pthread after pool retirement");
  while (!reused.ready.load(std::memory_order_acquire)) std::this_thread::yield();
  Check(reused.passed, "new Pthread resets pending state and inherits current creator mask");
  reused.release.store(true, std::memory_order_release);
  Check(PthreadJoin(child, nullptr) == 0, "join reused signal-mask fixture");
  query(b);
  Check(call(3, saved, nullptr) == 0 && Memory::FreeGuestMemory(address, 0x8000),
        "restore caller mask and release guest fixture");
  std::printf("GuestSignalMaskTests: mask128=pass native_ops=pass alias=pass canaries=pass errno=pass native_import_coherence=pass native_faults=pass inherit=pass thread_isolation=pass reuse=pass\n");
}
