struct JemspaceRangeExports {
  using Create = void* (KYTY_SYSV_ABI *)(const char*, uint64_t, uint32_t);
  using Destroy = int (KYTY_SYSV_ABI *)(void*);
  using Malloc = void* (KYTY_SYSV_ABI *)(void*, size_t);
  using Free = int (KYTY_SYSV_ABI *)(void*, void*);
  using Calloc = void* (KYTY_SYSV_ABI *)(void*, size_t, size_t);
  using Memalign = void* (KYTY_SYSV_ABI *)(void*, size_t, size_t);
  using Realloc = void* (KYTY_SYSV_ABI *)(void*, void*, size_t);
  using Stats = void (KYTY_SYSV_ABI *)(void*, uint64_t*);

  Create create;
  Destroy destroy;
  Malloc malloc;
  Free free;
  Calloc calloc;
  Memalign memalign;
  Realloc realloc;
  Stats stats;
};

void CheckJemspaceAllocationRanges() {
  Loader::SymbolDatabase symbols;
  Libs::InitJemspace_1(&symbols);
  const auto find = [&](const char* nid) {
    const auto* symbol = symbols.FindByNid(nid, Loader::SymbolType::Func);
    Check(symbol != nullptr, "Jemspace allocation export resolves");
    return symbol->vaddr;
  };
  const JemspaceRangeExports api {
      reinterpret_cast<JemspaceRangeExports::Create>(find("PudtK6jPkKk")),
      reinterpret_cast<JemspaceRangeExports::Destroy>(find("xi1kSeeeHko")),
      reinterpret_cast<JemspaceRangeExports::Malloc>(find("IUMgip-Glc4")),
      reinterpret_cast<JemspaceRangeExports::Free>(find("KMxjh6mb1yk")),
      reinterpret_cast<JemspaceRangeExports::Calloc>(find("Ua4eXAn2rec")),
      reinterpret_cast<JemspaceRangeExports::Memalign>(find("jwK0WHNUz+c")),
      reinterpret_cast<JemspaceRangeExports::Realloc>(find("bmstosXtyt8")),
      reinterpret_cast<JemspaceRangeExports::Stats>(find("uuRDRq3yqII"))};
  const auto contains = Libs::Jemspace::ContainsAllocation;
  const auto query = Libs::Jemspace::QueryAllocation;
  void* context = api.create("stdio allocation ranges", 128, 0);
  Check(context != nullptr, "create bounded Jemspace context");
  auto* original = static_cast<unsigned char*>(api.malloc(context, 64));
  Check(original != nullptr && (reinterpret_cast<uintptr_t>(original) & 15) == 0,
        "Jemspace allocation retains alignment");
  std::memset(original, 0x5a, 64);
  Check(contains(original, 64) && contains(original + 7, 57) &&
        contains(original + 63, 1) && !contains(original, 65) &&
        !contains(original + 63, 2) && contains(original + 64, 0) &&
        !contains(original + 64, 1),
        "registry accepts exact interior spans and rejects allocation overrun");
  uint64_t allocation_offset = UINT64_MAX;
  uint64_t allocation_size = UINT64_MAX;
  Check(query(original + 7, 16, &allocation_offset, &allocation_size) &&
        allocation_offset == 7 && allocation_size == 64,
        "allocation query reports bounded relative identity without exposing its address");
  Check(!query(original + 63, 2, &allocation_offset, &allocation_size) &&
        allocation_offset == 0 && allocation_size == 0,
        "allocation query clears metadata when the requested span crosses the live extent");
  const unsigned char unrelated = 0;
  Check(!contains(nullptr, 0) && !contains(&unrelated, 1) &&
        !contains(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(original) - 1), 1) &&
        !contains(original + 1, UINT64_MAX) &&
        !contains(reinterpret_cast<void*>(UINTPTR_MAX), 2),
        "range validation does not touch invalid untracked or overflowing pointers");

  uint64_t stats[5] {};
  api.stats(context, stats);
  Check(stats[1] == 64, "registry metadata is not charged as guest allocation bytes");
  Check(api.realloc(context, original, 256) == nullptr && contains(original, 64),
        "quota failure preserves the live original allocation record");
  api.stats(context, stats);
  Check(stats[1] == 64 && original[0] == 0x5a && original[63] == 0x5a,
        "failed realloc restores quota and preserves bytes");

  auto* grown = static_cast<unsigned char*>(api.realloc(context, original, 96));
  Check(grown != nullptr && grown != original && contains(grown, 96) &&
        !contains(original, 1),
        "successful moving realloc publishes new extent and removes old record");
  for (size_t i = 0; i < 64; ++i) Check(grown[i] == 0x5a, "growth retains old contents");
  api.stats(context, stats);
  Check(stats[1] == 96, "successful realloc retains existing quota replacement policy");
  auto* shrunk = static_cast<unsigned char*>(api.realloc(context, grown, 17));
  Check(shrunk != nullptr && contains(shrunk, 17) && !contains(shrunk, 18) &&
        !contains(grown, 1), "shrinking realloc exposes only the new requested extent");
  Check(api.free(context, shrunk) == 0 && !contains(shrunk, 1),
        "free removes the allocation before its host storage is reused");
  api.stats(context, stats);
  Check(stats[1] == 0, "free restores context accounting");

  auto* aligned = static_cast<unsigned char*>(api.memalign(context, 256, 16));
  Check(aligned != nullptr && (reinterpret_cast<uintptr_t>(aligned) & 255) == 0 &&
        contains(aligned, 16) && !contains(aligned, 17),
        "registry tracks returned aligned pointer without exposing alignment padding");
  api.free(context, aligned);
  auto* zeroed = static_cast<unsigned char*>(api.calloc(context, 4, 8));
  Check(zeroed != nullptr && contains(zeroed, 32), "calloc uses same live range registry");
  for (size_t i = 0; i < 32; ++i) Check(zeroed[i] == 0, "calloc retains zeroing");
  api.free(context, zeroed);
  void* empty = api.malloc(context, 0);
  Check(empty != nullptr && contains(empty, 0) && !contains(empty, 1),
        "zero allocation keeps physical allocation but exposes zero requested extent");
  api.stats(context, stats);
  Check(stats[1] == 1, "zero allocation retains existing one-byte quota charge");
  api.free(context, empty);
  Check(!contains(empty, 0), "zero allocation record is removed on free");
  Check(api.calloc(context, SIZE_MAX, 2) == nullptr &&
        api.malloc(context, SIZE_MAX) == nullptr,
        "existing allocation overflow checks reject before registry publication");
  Check(api.destroy(context) == 0, "destroy empty context after releasing all live blocks");

  void* unbounded = api.create("unbounded allocation ranges", 0, 0);
  void* large = api.malloc(unbounded, 65537);
  Check(unbounded != nullptr && large != nullptr && contains(large, 65537),
        "range registry adds no arbitrary allocation capacity ceiling");
  api.free(unbounded, large);

  struct EmbeddedSem {
    uint16_t magic;
    uint16_t name_id;
    uint32_t waiters;
    uint32_t count;
    uint32_t flags;
  };
  static_assert(sizeof(EmbeddedSem) == 16);
  auto* mono_object = static_cast<unsigned char*>(api.calloc(unbounded, 1, 1664));
  Check(mono_object != nullptr, "allocate Mono-sized Jemspace object");
  auto* embedded = reinterpret_cast<EmbeddedSem*>(mono_object + 76);
  auto* embedded_name = reinterpret_cast<char*>(mono_object + 192);
  std::memcpy(embedded_name, "mono_resume", 12);
  Check(query(embedded, sizeof(*embedded), &allocation_offset,
              &allocation_size) && allocation_offset == 76 &&
            allocation_size == 1664,
        "Mono-sized Jemspace object exposes its embedded semaphore span");
  Check(Libs::Posix::sem_init(embedded, 0, 0) == 0 && embedded->magic == 0x736d &&
            embedded->name_id == 0xffff && embedded->count == 0 && embedded->flags == 0,
        "production semaphore export initializes the live embedded Jemspace field");
  Check(Libs::Posix::sem_setname(embedded, embedded_name) == 0 &&
            embedded->name_id != 0xffff,
        "semaphore naming reads and updates completely contained Jemspace storage");
  Check(Libs::Posix::sem_post(embedded) == 0 && embedded->count == 1 &&
            Libs::Posix::sem_trywait(embedded) == 0 && embedded->count == 0,
        "semaphore count transitions keep the embedded public image coherent");
  Check(Libs::Posix::sem_destroy(embedded) == 0 && embedded->magic == 0,
        "semaphore teardown clears the embedded public image before allocation release");
  api.free(unbounded, mono_object);

  auto* short_object = static_cast<unsigned char*>(api.calloc(unbounded, 1, 91));
  Check(short_object != nullptr, "allocate short embedded-semaphore negative fixture");
  auto* short_sem = reinterpret_cast<EmbeddedSem*>(short_object + 76);
  std::memset(short_object, 0xa5, 91);
  *Libs::Posix::GetErrorAddr() = 0;
  Check(Libs::Posix::sem_init(short_sem, 0, 0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT &&
            std::all_of(short_object, short_object + 91,
                        [](unsigned char value) { return value == 0xa5; }),
        "embedded semaphore rejects a live allocation whose remaining span is one byte short");
  api.free(unbounded, short_object);

  auto* freed_object = static_cast<unsigned char*>(api.calloc(unbounded, 1, 1664));
  Check(freed_object != nullptr, "allocate freed embedded-semaphore negative fixture");
  auto* freed_sem = freed_object + 76;
  api.free(unbounded, freed_object);
  *Libs::Posix::GetErrorAddr() = 0;
  Check(Libs::Posix::sem_init(freed_sem, 0, 0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT,
        "semaphore publication rejects storage after Jemspace removes its live extent");

  auto* unrelated_heap = static_cast<unsigned char*>(std::malloc(1664));
  Check(unrelated_heap != nullptr, "allocate valid but untracked host storage");
  *Libs::Posix::GetErrorAddr() = 0;
  Check(Libs::Posix::sem_init(unrelated_heap + 76, 0, 0) == -1 &&
            *Libs::Posix::GetErrorAddr() == Libs::Posix::POSIX_EFAULT,
        "semaphore publication does not admit unrelated host heap storage");
  std::free(unrelated_heap);
  api.destroy(unbounded);
}
