#if defined(_WIN32)
Libs::NativeKernelBridge::Reply AppRegistrationSysctl(int selector, int32_t id, void* output,
    uint64_t* length, const void* input = nullptr, uint64_t input_size = 0) {
  const int32_t mib[4] {1, 14, selector, id};
  return Libs::NativeKernelBridge::DispatchSyscall({0xca, {reinterpret_cast<uint64_t>(mib), 4,
      reinterpret_cast<uint64_t>(output), reinterpret_cast<uint64_t>(length),
      reinterpret_cast<uint64_t>(input), input_size}});
}
#endif
