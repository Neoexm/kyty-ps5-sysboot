#if defined(_WIN32)
namespace NativeSshotTest {
struct Request {
  uint32_t status;
  uint32_t reserved04;
  uint64_t region;
  uint64_t reserved10;
  uint32_t size;
  uint32_t block_size;
  uint32_t value;
  std::array<uint8_t, 0x4c> reserved24;
};
}
#endif
