// Synthetic BFS image: block=0x10000, inode=0x100, metadata TLV at +64 of block 0 (tags 1/0x100/0x1000/0), SB magic 0x20F50BF520190705, clean bit 0x40 at SB+16, 256-byte partition name at SB+32, dinode magic 0xBF10 at inode+0 (mode +16, size +40, first direct LBN +128), dirent 16-byte header + 8-byte-padded name. NON_AUTHENTIC parser fixture.
#include "kernel/bfsVolume.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#endif
