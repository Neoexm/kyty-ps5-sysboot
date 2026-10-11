#ifndef KYTY_TEST_EXFAT_FIXTURE_H_
#define KYTY_TEST_EXFAT_FIXTURE_H_

namespace ExfatTestFixture {

static void Put16(std::vector<uint8_t>& bytes, size_t offset, uint16_t value) {
    bytes.at(offset) = static_cast<uint8_t>(value);
    bytes.at(offset + 1) = static_cast<uint8_t>(value >> 8);
}

static void Put32(std::vector<uint8_t>& bytes, size_t offset, uint32_t value) {
    Put16(bytes, offset, static_cast<uint16_t>(value));
    Put16(bytes, offset + 2, static_cast<uint16_t>(value >> 16));
}

static void Put64(std::vector<uint8_t>& bytes, size_t offset, uint64_t value) {
    Put32(bytes, offset, static_cast<uint32_t>(value));
    Put32(bytes, offset + 4, static_cast<uint32_t>(value >> 32));
}

static void BootChecksum(std::vector<uint8_t>& bytes) {
    for (size_t block: {size_t {0}, size_t {12 * 512}}) {
        uint32_t sum = 0;
        for (size_t i = 0; i < 11 * 512; ++i) {
            if (i != 106 && i != 107 && i != 112) sum = ((sum >> 1) | (sum << 31)) + bytes[block + i];
        }
        for (size_t i = 11 * 512; i < 12 * 512; i += 4) Put32(bytes, block + i, sum);
    }
}

static void SetChecksum(std::vector<uint8_t>& bytes, size_t offset) {
    const size_t size = (size_t(bytes.at(offset + 1)) + 1) * 32;
    uint16_t sum = 0;
    for (size_t i = 0; i < size; ++i) {
        if (i != 2 && i != 3) sum = static_cast<uint16_t>((sum >> 1) | (sum << 15)) + bytes.at(offset + i);
    }
    Put16(bytes, offset + 2, sum);
}

static std::vector<uint8_t> Fixture() {
    std::vector<uint8_t> bytes(2048 * 512);
    bytes[0] = 0xeb; bytes[1] = 0x76; bytes[2] = 0x90;
    std::memcpy(bytes.data() + 3, "EXFAT   ", 8);
    Put64(bytes, 72, 2048);
    Put32(bytes, 80, 24);
    Put32(bytes, 84, 16);
    Put32(bytes, 88, 40);
    Put32(bytes, 92, 2008);
    Put32(bytes, 96, 2);
    Put16(bytes, 104, 0x100);
    bytes[108] = 9; bytes[109] = 0; bytes[110] = 1;
    bytes[510] = 0x55; bytes[511] = 0xaa;
    for (size_t i = 1; i <= 8; ++i) Put32(bytes, (i + 1) * 512 - 4, 0xaa550000);
    std::copy_n(bytes.begin(), 12 * 512, bytes.begin() + 12 * 512);
    BootChecksum(bytes);
    Put32(bytes, 24 * 512, 0xfffffff8);
    Put32(bytes, 24 * 512 + 4, 0xffffffff);
    for (size_t cluster = 2; cluster <= 8; ++cluster) Put32(bytes, 24 * 512 + cluster * 4, 0xffffffff);
    Put32(bytes, 24 * 512 + 6 * 4, 8);
    bytes[41 * 512] = 0x7f;
    const std::array<uint16_t, 34> table = [] {
        std::array<uint16_t, 34> values {};
        values[0] = 0xffff; values[1] = 97;
        for (size_t i = 0; i < 26; ++i) values[i + 2] = static_cast<uint16_t>('A' + i);
        values[28] = 0xffff; values[29] = 65412;
        values[30] = 0xffff;
        return values;
    }();
    for (size_t i = 0; i < 31; ++i) Put16(bytes, 42 * 512 + i * 2, table[i]);
    uint32_t upper_sum = 0;
    for (size_t i = 0; i < 62; ++i) upper_sum = ((upper_sum >> 1) | (upper_sum << 31)) + bytes[42 * 512 + i];
    const size_t root = 40 * 512;
    bytes[root] = 0x81;
    Put32(bytes, root + 20, 3); Put64(bytes, root + 24, 251);
    bytes[root + 32] = 0x82;
    Put32(bytes, root + 36, upper_sum); Put32(bytes, root + 52, 4); Put64(bytes, root + 56, 62);
    const auto file = [&](size_t offset, const std::u16string& name, uint32_t first, uint64_t size, uint64_t valid, uint8_t flags, uint16_t attributes) {
        bytes[offset] = 0x85; bytes[offset + 1] = 2;
        Put16(bytes, offset + 4, attributes);
        bytes[offset + 32] = 0xc0; bytes[offset + 33] = flags; bytes[offset + 35] = static_cast<uint8_t>(name.size());
        uint16_t hash = 0;
        for (auto c: name) {
            if (c >= u'a' && c <= u'z') c -= 32;
            hash = static_cast<uint16_t>((hash >> 1) | (hash << 15)) + (c & 0xff);
            hash = static_cast<uint16_t>((hash >> 1) | (hash << 15)) + (c >> 8);
        }
        Put16(bytes, offset + 36, hash); Put64(bytes, offset + 40, valid);
        Put32(bytes, offset + 52, first); Put64(bytes, offset + 56, size);
        bytes[offset + 64] = 0xc1;
        for (size_t i = 0; i < name.size(); ++i) Put16(bytes, offset + 66 + i * 2, name[i]);
        SetChecksum(bytes, offset);
    };
    file(root + 64, u"hello.bin", 5, 5, 5, 3, 0x20);
    file(root + 160, u"chain.bin", 6, 700, 600, 1, 0x20);
    file(root + 256, u"sub", 7, 512, 512, 3, 0x10);
    file(45 * 512, u"empty", 0, 0, 0, 1, 0x20);
    std::memcpy(bytes.data() + 43 * 512, "HELLO", 5);
    std::fill_n(bytes.begin() + 44 * 512, 512, 0x61);
    std::fill_n(bytes.begin() + 46 * 512, 512, 0x62);
    return bytes;
}


}
#endif

