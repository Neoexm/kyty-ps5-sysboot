Libs::NativeKernelBridge::Reply GuestNativeSignalMaskReply(int how, const void* set, void* oset) {
  return Libs::NativeKernelBridge::DispatchSyscall({0x154,
      {static_cast<uint64_t>(how), reinterpret_cast<uint64_t>(set), reinterpret_cast<uint64_t>(oset)}});
}
