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
