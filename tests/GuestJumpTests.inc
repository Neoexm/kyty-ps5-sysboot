using GuestJumpSet = int (KYTY_SYSV_ABI *)(void*);
using GuestJumpLong = void (KYTY_SYSV_ABI *)(void*, int);
using GuestJumpMask = int (KYTY_SYSV_ABI *)(int, const uint32_t*, uint32_t*);
struct GuestJumpState;
using GuestJumpNestedCall = void (KYTY_SYSV_ABI *)(GuestJumpState*);

struct alignas(16) GuestJumpState {
  GuestJumpSet save;
  GuestJumpLong jump;
  GuestJumpNestedCall mutate;
  GuestJumpNestedCall nested;
  int value;
  uint32_t saved_mxcsr;
  uint32_t changed_mxcsr;
  uint16_t saved_cw;
  uint16_t changed_cw;
  std::array<uint8_t, 88> buffer;
  uint64_t expected_rsp;
  uint64_t expected_rip;
  uint64_t observed_rsp;
  uint64_t observed_rip;
  std::array<uint64_t, 6> observed_gprs;
  uint32_t observed_mxcsr;
  uint16_t observed_cw;
  uint16_t padding;
  int initial_return;
  int resumed_return;
  uint32_t nested_calls;
  uint32_t jump_returned;
  GuestJumpMask sigprocmask;
  std::array<uint32_t, 4> mask_a;
  std::array<uint32_t, 4> mask_b;
  std::array<uint32_t, 4> mask_observed;
  std::array<uint32_t, 4> mask_original;
  int mutation_result;
  uint32_t host_mxcsr;
  uint16_t host_cw;
  std::array<uint32_t, 4> mask_mutation;
};

static_assert(offsetof(GuestJumpState, value) == 0x20);
static_assert(offsetof(GuestJumpState, saved_mxcsr) == 0x24);
static_assert(offsetof(GuestJumpState, changed_mxcsr) == 0x28);
static_assert(offsetof(GuestJumpState, saved_cw) == 0x2c);
static_assert(offsetof(GuestJumpState, changed_cw) == 0x2e);
static_assert(offsetof(GuestJumpState, buffer) == 0x30);
static_assert(offsetof(GuestJumpState, expected_rsp) == 0x88);
static_assert(offsetof(GuestJumpState, expected_rip) == 0x90);
static_assert(offsetof(GuestJumpState, observed_rsp) == 0x98);
static_assert(offsetof(GuestJumpState, observed_rip) == 0xa0);
static_assert(offsetof(GuestJumpState, observed_gprs) == 0xa8);
static_assert(offsetof(GuestJumpState, observed_mxcsr) == 0xd8);
static_assert(offsetof(GuestJumpState, observed_cw) == 0xdc);
static_assert(offsetof(GuestJumpState, initial_return) == 0xe0);
static_assert(offsetof(GuestJumpState, resumed_return) == 0xe4);
static_assert(offsetof(GuestJumpState, nested_calls) == 0xe8);
static_assert(offsetof(GuestJumpState, jump_returned) == 0xec);

void KYTY_SYSV_ABI GuestJumpMutateMask(GuestJumpState* state) {
  state->mutation_result = state->sigprocmask(3, state->mask_b.data(), nullptr);
  if (state->mutation_result == 0) {
    state->mutation_result = state->sigprocmask(0, nullptr, state->mask_mutation.data());
  }
  ++state->nested_calls;
}

[[gnu::naked]] KYTY_SYSV_ABI void GuestJumpNested(GuestJumpState*) {
  asm volatile("subq $24, %rsp\n\t"
               "movq %rdi, (%rsp)\n\t"
               "callq *16(%rdi)\n\t"
               "movq (%rsp), %r10\n\t"
               "ldmxcsr 40(%r10)\n\t"
               "fldcw 46(%r10)\n\t"
               "movq 8(%r10), %r11\n\t"
               "movl 32(%r10), %esi\n\t"
               "leaq 48(%r10), %rdi\n\t"
               "movabsq $0xbad0000000000001, %rbx\n\t"
               "movabsq $0xbad0000000000002, %rbp\n\t"
               "movabsq $0xbad0000000000003, %r12\n\t"
               "movabsq $0xbad0000000000004, %r13\n\t"
               "movabsq $0xbad0000000000005, %r14\n\t"
               "movabsq $0xbad0000000000006, %r15\n\t"
               "callq *%r11\n\t"
               "movq (%rsp), %r10\n\t"
               "movl $1, 236(%r10)\n\t"
               "addq $24, %rsp\n\t"
               "retq\n");
}

[[gnu::naked]] KYTY_SYSV_ABI int GuestJumpCaller(GuestJumpState*) {
  asm volatile("pushq %rbx\n\t"
               "pushq %rbp\n\t"
               "pushq %r12\n\t"
               "pushq %r13\n\t"
               "pushq %r14\n\t"
               "pushq %r15\n\t"
               "subq $56, %rsp\n\t"
               "movq %rdi, (%rsp)\n\t"
               "stmxcsr 8(%rsp)\n\t"
               "fnstcw 12(%rsp)\n\t"
               "ldmxcsr 36(%rdi)\n\t"
               "fldcw 44(%rdi)\n\t"
               "movabsq $0x1234000000000001, %rbx\n\t"
               "movabsq $0x1234000000000002, %rbp\n\t"
               "movabsq $0x1234000000000003, %r12\n\t"
               "movabsq $0x1234000000000004, %r13\n\t"
               "movabsq $0x1234000000000005, %r14\n\t"
               "movabsq $0x1234000000000006, %r15\n\t"
               "leaq -8(%rsp), %r10\n\t"
               "movq %r10, 136(%rdi)\n\t"
               "leaq 1f(%rip), %r10\n\t"
               "movq %r10, 144(%rdi)\n\t"
               "movq (%rdi), %rax\n\t"
               "leaq 48(%rdi), %rdi\n\t"
               "callq *%rax\n\t"
               "1: movq (%rsp), %rcx\n\t"
               "movl %eax, 228(%rcx)\n\t"
               "testl %eax, %eax\n\t"
               "jnz 2f\n\t"
               "movl %eax, 224(%rcx)\n\t"
               "movq %rcx, %rdi\n\t"
               "callq *24(%rdi)\n\t"
               "2: movq (%rsp), %rcx\n\t"
               "movq %rsp, 152(%rcx)\n\t"
               "leaq 1b(%rip), %rax\n\t"
               "movq %rax, 160(%rcx)\n\t"
               "movq %rbx, 168(%rcx)\n\t"
               "movq %rbp, 176(%rcx)\n\t"
               "movq %r12, 184(%rcx)\n\t"
               "movq %r13, 192(%rcx)\n\t"
               "movq %r14, 200(%rcx)\n\t"
               "movq %r15, 208(%rcx)\n\t"
               "stmxcsr 216(%rcx)\n\t"
               "fnstcw 220(%rcx)\n\t"
               "movl 228(%rcx), %eax\n\t"
               "ldmxcsr 8(%rsp)\n\t"
               "fldcw 12(%rsp)\n\t"
               "addq $56, %rsp\n\t"
               "popq %r15\n\t"
               "popq %r14\n\t"
               "popq %r13\n\t"
               "popq %r12\n\t"
               "popq %rbp\n\t"
               "popq %rbx\n\t"
               "retq\n");
}

void CheckGuestJumps() {
  Loader::SymbolDatabase symbols;
  Libs::LibC::InitLibC_1(&symbols);
  Libs::InitLibKernel_1(&symbols);
  const auto* set = symbols.FindByNid("gNQ1V2vfXDE", Loader::SymbolType::Func);
  const auto* jump = symbols.FindByNid("lKEN2IebgJ0", Loader::SymbolType::Func);
  const auto* mask = symbols.FindByNid("6xVpy0Fdq+I", Loader::SymbolType::Func);
  Check(set && jump && mask, "resolve paired jumps and signal mask by exported NID");
  const uint64_t address = Libs::LibKernel::Memory::AllocateProgramMemory(0, 0x4000,
      Common::VirtualMemory::Mode::ReadWrite, "guest_jump_test");
  Check(address != 0, "allocate guest jump/mask records");
  auto* state = reinterpret_cast<GuestJumpState*>(address);
  std::memset(state, 0, sizeof(*state));
  state->save = reinterpret_cast<GuestJumpSet>(set->vaddr);
  state->jump = reinterpret_cast<GuestJumpLong>(jump->vaddr);
  state->mutate = GuestJumpMutateMask;
  state->nested = GuestJumpNested;
  state->sigprocmask = reinterpret_cast<GuestJumpMask>(mask->vaddr);
  state->mask_a = {0x42, 0x80000000, 0x400, 0x08000000};
  state->mask_b = {0x404, 0x10, 0x8000, 0x80000000};
  Check(state->sigprocmask(0, nullptr, state->mask_original.data()) == 0,
        "query initial caller signal mask without modifying it");
  asm volatile("stmxcsr %0" : "=m"(state->host_mxcsr));
  asm volatile("fnstcw %0" : "=m"(state->host_cw));
  state->saved_mxcsr = (state->host_mxcsr & ~uint32_t{0x603f}) | 0x2001;
  state->changed_mxcsr = (state->host_mxcsr & ~uint32_t{0x603f}) | 0x4020;
  state->saved_cw = static_cast<uint16_t>((state->host_cw & ~0x0c00) | 0x0400);
  state->changed_cw = static_cast<uint16_t>((state->host_cw & ~0x0c00) | 0x0800);
  for (const int value: {0, 7}) {
    state->value = value;
    state->initial_return = -71;
    state->resumed_return = -72;
    state->mutation_result = -73;
    state->nested_calls = 0;
    state->jump_returned = 0;
    state->buffer.fill(0xa5);
    Check(state->sigprocmask(3, state->mask_a.data(), nullptr) == 0,
          "set full caller mask before setjmp");
    const int result = GuestJumpCaller(state);
    asm volatile("" ::: "memory");
    Check(result == (value == 0 ? 1 : 7) && state->initial_return == 0 &&
          state->resumed_return == result && state->nested_calls == 1 &&
          state->jump_returned == 0 && state->mutation_result == 0 &&
          state->mask_mutation == state->mask_b,
          "nested longjmp resumes saved caller with zero normalized to one or seven");
    constexpr std::array<size_t, 6> gpr_offsets {0x08, 0x18, 0x20, 0x28, 0x30, 0x38};
    for (size_t i = 0; i < state->observed_gprs.size(); ++i) {
      uint64_t stored = 0;
      std::memcpy(&stored, state->buffer.data() + gpr_offsets[i], sizeof(stored));
      Check(stored == 0x1234000000000001ull + i && state->observed_gprs[i] == stored,
            "paired jumps use GPR buffer offsets and restore every nested clobber");
    }
    uint64_t saved_rip = 0;
    uint64_t saved_rsp = 0;
    std::memcpy(&saved_rip, state->buffer.data(), sizeof(saved_rip));
    std::memcpy(&saved_rsp, state->buffer.data() + 0x10, sizeof(saved_rsp));
    Check(saved_rsp == state->expected_rsp && state->observed_rsp == state->expected_rsp + 8 &&
          saved_rip == state->expected_rip && state->observed_rip == state->expected_rip,
          "original raw return-slot RSP and RIP resume at exact post-setjmp instruction");
    Check(state->observed_cw == state->saved_cw &&
          state->observed_mxcsr == ((state->saved_mxcsr & ~uint32_t{0x3f}) |
                                   (state->changed_mxcsr & uint32_t{0x3f})),
          "restore saved x87 controls and MXCSR controls while retaining current MXCSR status flags");
    Check(state->buffer[0x42] == 0xa5 && state->buffer[0x43] == 0xa5 &&
          std::memcmp(state->buffer.data() + 0x48, state->mask_a.data(), 16) == 0,
          "original88-byte record preserves padding and all128 saved mask bits");
    Check(state->sigprocmask(0, nullptr, state->mask_observed.data()) == 0 &&
          state->mask_observed == state->mask_a,
          "paired jump restores full caller signal mask after nested replacement");
    uint32_t host_mxcsr = 0;
    uint16_t host_cw = 0;
    asm volatile("stmxcsr %0" : "=m"(host_mxcsr));
    asm volatile("fnstcw %0" : "=m"(host_cw));
    Check(host_mxcsr == state->host_mxcsr && host_cw == state->host_cw,
          "native test wrapper restores host floating point environment after observations");
    std::printf("GuestJumpTests: value=%d result=%d nested=1 GPR6=pass RSP_RIP=pass x87=pass MXCSR_controls_current_flags=pass signal128=pass\n",
        value, result);
  }
  Check(state->sigprocmask(3, state->mask_original.data(), nullptr) == 0,
        "restore caller mask after exported paired jump tests");
  Check(Libs::LibKernel::Memory::FreeGuestMemory(address, 0x4000), "release jump fixture mapping");
}
