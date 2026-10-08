#ifndef KYTY_PS5_KERNEL_AUTH_INFO_H_
#define KYTY_PS5_KERNEL_AUTH_INFO_H_

#include "common/common.h"

#include <array>
#include <string>
#include <string_view>

namespace Libs::LibKernel::AuthInfo {
constexpr size_t   kSize                   = 0x88;
constexpr size_t   kDigestSize             = 32;

using Record = std::array<uint8_t, kSize>;
using Digest = std::array<uint8_t, kDigestSize>;
} // namespace Libs::LibKernel::AuthInfo
#endif
