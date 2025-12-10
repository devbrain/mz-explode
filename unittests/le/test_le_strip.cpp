// Test LE/LX DOS extender stripping
#include <doctest/doctest.h>
#include <libexe/formats/le_file.hpp>
#include <vector>
#include <cstring>
#include <span>

using namespace libexe;

// Embedded DOOM.EXE test data
namespace data {
    extern size_t doom_le_len;
    extern unsigned char doom_le[];
}

namespace {

// Create a minimal bound LE executable for testing
// Structure:
//   0x0000-0x003F: MZ header (64 bytes)
//   0x0040-0x007F: DOS stub placeholder (64 bytes)
//   0x0080+:       LE header (176 bytes minimum)
std::vector<uint8_t> create_bound_le(uint32_t data_pages_offset = 0x200,
                                      uint32_t nonres_offset = 0x180,
                                      uint32_t debug_offset = 0) {
    // Total size: at least 0x80 (MZ) + 0xB0 (LE header) + some data
    std::vector<uint8_t> data(0x300, 0);

    // MZ header
    data[0x00] = 0x4D;  // 'M'
    data[0x01] = 0x5A;  // 'Z'
    data[0x02] = 0x80;  // bytes on last page (128)
    data[0x03] = 0x00;
    data[0x04] = 0x01;  // pages (1 * 512 = 512 bytes, but we only use 128)
    data[0x05] = 0x00;
    data[0x18] = 0x40;  // relocation table offset (>= 0x40 for new format)
    data[0x19] = 0x00;
    data[0x3C] = 0x80;  // e_lfanew = 0x80 (offset to LE header)
    data[0x3D] = 0x00;
    data[0x3E] = 0x00;
    data[0x3F] = 0x00;

    // LE header at offset 0x80
    size_t le_off = 0x80;
    data[le_off + 0x00] = 0x4C;  // 'L'
    data[le_off + 0x01] = 0x45;  // 'E'
    data[le_off + 0x02] = 0x00;  // byte order
    data[le_off + 0x03] = 0x00;  // word order
    data[le_off + 0x04] = 0x00;  // format level
    data[le_off + 0x05] = 0x00;
    data[le_off + 0x06] = 0x00;
    data[le_off + 0x07] = 0x00;
    data[le_off + 0x08] = 0x02;  // CPU type = 386
    data[le_off + 0x09] = 0x00;
    data[le_off + 0x0A] = 0x03;  // OS type = DOS
    data[le_off + 0x0B] = 0x00;

    // Module version
    data[le_off + 0x0C] = 0x00;
    data[le_off + 0x0D] = 0x00;
    data[le_off + 0x0E] = 0x00;
    data[le_off + 0x0F] = 0x00;

    // Module flags
    data[le_off + 0x10] = 0x00;
    data[le_off + 0x11] = 0x00;
    data[le_off + 0x12] = 0x00;
    data[le_off + 0x13] = 0x00;

    // Page count = 1
    data[le_off + 0x14] = 0x01;
    data[le_off + 0x15] = 0x00;
    data[le_off + 0x16] = 0x00;
    data[le_off + 0x17] = 0x00;

    // Entry CS object = 1
    data[le_off + 0x18] = 0x01;
    data[le_off + 0x19] = 0x00;
    data[le_off + 0x1A] = 0x00;
    data[le_off + 0x1B] = 0x00;

    // Initial EIP = 0
    data[le_off + 0x1C] = 0x00;
    data[le_off + 0x1D] = 0x00;
    data[le_off + 0x1E] = 0x00;
    data[le_off + 0x1F] = 0x00;

    // Initial SS object = 1
    data[le_off + 0x20] = 0x01;
    data[le_off + 0x21] = 0x00;
    data[le_off + 0x22] = 0x00;
    data[le_off + 0x23] = 0x00;

    // Initial ESP = 0
    data[le_off + 0x24] = 0x00;
    data[le_off + 0x25] = 0x00;
    data[le_off + 0x26] = 0x00;
    data[le_off + 0x27] = 0x00;

    // Page size = 4096
    data[le_off + 0x28] = 0x00;
    data[le_off + 0x29] = 0x10;
    data[le_off + 0x2A] = 0x00;
    data[le_off + 0x2B] = 0x00;

    // Bytes on last page (LE) / Page offset shift (LX)
    data[le_off + 0x2C] = 0x00;
    data[le_off + 0x2D] = 0x00;
    data[le_off + 0x2E] = 0x00;
    data[le_off + 0x2F] = 0x00;

    // Fixup section size = 0
    data[le_off + 0x30] = 0x00;
    data[le_off + 0x31] = 0x00;
    data[le_off + 0x32] = 0x00;
    data[le_off + 0x33] = 0x00;

    // Object table offset (relative) = 0xB0 (right after header)
    data[le_off + 0x40] = 0xB0;
    data[le_off + 0x41] = 0x00;
    data[le_off + 0x42] = 0x00;
    data[le_off + 0x43] = 0x00;

    // Object count = 1
    data[le_off + 0x44] = 0x01;
    data[le_off + 0x45] = 0x00;
    data[le_off + 0x46] = 0x00;
    data[le_off + 0x47] = 0x00;

    // Object page table offset = 0xC8
    data[le_off + 0x48] = 0xC8;
    data[le_off + 0x49] = 0x00;
    data[le_off + 0x4A] = 0x00;
    data[le_off + 0x4B] = 0x00;

    // Data pages offset (ABSOLUTE file offset) - 0x80
    data[le_off + 0x80] = static_cast<uint8_t>(data_pages_offset & 0xFF);
    data[le_off + 0x81] = static_cast<uint8_t>((data_pages_offset >> 8) & 0xFF);
    data[le_off + 0x82] = static_cast<uint8_t>((data_pages_offset >> 16) & 0xFF);
    data[le_off + 0x83] = static_cast<uint8_t>((data_pages_offset >> 24) & 0xFF);

    // Preload pages count = 0
    data[le_off + 0x84] = 0x00;
    data[le_off + 0x85] = 0x00;
    data[le_off + 0x86] = 0x00;
    data[le_off + 0x87] = 0x00;

    // Non-resident name table offset (ABSOLUTE) - 0x88
    data[le_off + 0x88] = static_cast<uint8_t>(nonres_offset & 0xFF);
    data[le_off + 0x89] = static_cast<uint8_t>((nonres_offset >> 8) & 0xFF);
    data[le_off + 0x8A] = static_cast<uint8_t>((nonres_offset >> 16) & 0xFF);
    data[le_off + 0x8B] = static_cast<uint8_t>((nonres_offset >> 24) & 0xFF);

    // Non-resident name table size = 0
    data[le_off + 0x8C] = 0x00;
    data[le_off + 0x8D] = 0x00;
    data[le_off + 0x8E] = 0x00;
    data[le_off + 0x8F] = 0x00;

    // Debug info offset (ABSOLUTE) - 0x98
    data[le_off + 0x98] = static_cast<uint8_t>(debug_offset & 0xFF);
    data[le_off + 0x99] = static_cast<uint8_t>((debug_offset >> 8) & 0xFF);
    data[le_off + 0x9A] = static_cast<uint8_t>((debug_offset >> 16) & 0xFF);
    data[le_off + 0x9B] = static_cast<uint8_t>((debug_offset >> 24) & 0xFF);

    // Add object table entry at le_off + 0xB0
    size_t obj_off = le_off + 0xB0;
    // Virtual size = 0x1000
    data[obj_off + 0x00] = 0x00;
    data[obj_off + 0x01] = 0x10;
    data[obj_off + 0x02] = 0x00;
    data[obj_off + 0x03] = 0x00;
    // Base address = 0x10000
    data[obj_off + 0x04] = 0x00;
    data[obj_off + 0x05] = 0x00;
    data[obj_off + 0x06] = 0x01;
    data[obj_off + 0x07] = 0x00;
    // Flags = 0x0005 (readable + executable)
    data[obj_off + 0x08] = 0x05;
    data[obj_off + 0x09] = 0x00;
    data[obj_off + 0x0A] = 0x00;
    data[obj_off + 0x0B] = 0x00;
    // Page table index = 1
    data[obj_off + 0x0C] = 0x01;
    data[obj_off + 0x0D] = 0x00;
    data[obj_off + 0x0E] = 0x00;
    data[obj_off + 0x0F] = 0x00;
    // Page count = 1
    data[obj_off + 0x10] = 0x01;
    data[obj_off + 0x11] = 0x00;
    data[obj_off + 0x12] = 0x00;
    data[obj_off + 0x13] = 0x00;

    // Add page table entry at le_off + 0xC8
    size_t page_off = le_off + 0xC8;
    // LE page entry: 3-byte offset (big-endian) + 1-byte flags
    // Page 1: offset high=0, mid=0, low=1, flags=0
    data[page_off + 0] = 0x00;  // high
    data[page_off + 1] = 0x00;  // med
    data[page_off + 2] = 0x01;  // low (page number 1)
    data[page_off + 3] = 0x00;  // flags (legal)

    return data;
}

// Helper to read uint32_t from buffer
uint32_t read_u32(const std::vector<uint8_t>& data, size_t offset) {
    if (offset + 4 > data.size()) return 0;
    return static_cast<uint32_t>(data[offset]) |
           (static_cast<uint32_t>(data[offset + 1]) << 8) |
           (static_cast<uint32_t>(data[offset + 2]) << 16) |
           (static_cast<uint32_t>(data[offset + 3]) << 24);
}

} // anonymous namespace

TEST_CASE("LE stub stripping: basic functionality") {
    SUBCASE("Bound LE is detected correctly") {
        auto data = create_bound_le();
        auto le = le_file::from_memory(data);

        CHECK(le.is_bound());
        CHECK(le.le_header_offset() == 0x80);
        CHECK(le.stub_size() == 0x80);
        CHECK_FALSE(le.is_lx());
    }

    SUBCASE("Raw LE returns empty from strip_extender") {
        // Create raw LE (starts with LE magic directly)
        std::vector<uint8_t> raw_data(0x200, 0);
        raw_data[0] = 0x4C;  // 'L'
        raw_data[1] = 0x45;  // 'E'
        raw_data[0x08] = 0x02;  // CPU type = 386
        raw_data[0x0A] = 0x03;  // OS type = DOS
        raw_data[0x28] = 0x00;  // page size
        raw_data[0x29] = 0x10;  // 4096
        raw_data[0x44] = 0x00;  // object count = 0

        auto le = le_file::from_memory(raw_data);

        CHECK_FALSE(le.is_bound());
        CHECK(le.le_header_offset() == 0);

        auto stripped = le.strip_extender();
        CHECK(stripped.empty());
    }
}

TEST_CASE("LE stub stripping: offset adjustment") {
    SUBCASE("Data pages offset is adjusted correctly") {
        // Create bound LE with data_pages_offset = 0x200
        auto data = create_bound_le(0x200, 0, 0);
        auto le = le_file::from_memory(data);

        CHECK(le.is_bound());
        CHECK(le.stub_size() == 0x80);

        auto stripped = le.strip_extender();
        REQUIRE(!stripped.empty());

        // Verify LE magic at start
        CHECK(stripped[0] == 0x4C);  // 'L'
        CHECK(stripped[1] == 0x45);  // 'E'

        // Verify data pages offset was adjusted
        // Original: 0x200, stub size: 0x80, expected: 0x180
        uint32_t new_data_pages = read_u32(stripped, 0x80);
        CHECK(new_data_pages == 0x180);  // 0x200 - 0x80
    }

    SUBCASE("Non-resident name table offset is adjusted when non-zero") {
        auto data = create_bound_le(0x200, 0x180, 0);
        auto le = le_file::from_memory(data);

        auto stripped = le.strip_extender();
        REQUIRE(!stripped.empty());

        uint32_t new_nonres = read_u32(stripped, 0x88);
        CHECK(new_nonres == 0x100);  // 0x180 - 0x80
    }

    SUBCASE("Non-resident name table offset stays zero if originally zero") {
        auto data = create_bound_le(0x200, 0, 0);
        auto le = le_file::from_memory(data);

        auto stripped = le.strip_extender();
        REQUIRE(!stripped.empty());

        uint32_t new_nonres = read_u32(stripped, 0x88);
        CHECK(new_nonres == 0);
    }

    SUBCASE("Debug info offset is adjusted when non-zero") {
        auto data = create_bound_le(0x200, 0, 0x280);
        auto le = le_file::from_memory(data);

        auto stripped = le.strip_extender();
        REQUIRE(!stripped.empty());

        uint32_t new_debug = read_u32(stripped, 0x98);
        CHECK(new_debug == 0x200);  // 0x280 - 0x80
    }

    SUBCASE("All offsets adjusted together") {
        auto data = create_bound_le(0x300, 0x200, 0x280);
        auto le = le_file::from_memory(data);

        auto stripped = le.strip_extender();
        REQUIRE(!stripped.empty());

        CHECK(read_u32(stripped, 0x80) == 0x280);  // 0x300 - 0x80
        CHECK(read_u32(stripped, 0x88) == 0x180);  // 0x200 - 0x80
        CHECK(read_u32(stripped, 0x98) == 0x200);  // 0x280 - 0x80
    }
}

TEST_CASE("LE stub stripping: output validation") {
    SUBCASE("Output size is correct") {
        auto data = create_bound_le();
        auto le = le_file::from_memory(data);

        auto stripped = le.strip_extender();
        REQUIRE(!stripped.empty());

        // Output should be original size minus stub size
        CHECK(stripped.size() == data.size() - 0x80);
    }

    SUBCASE("Stripped file can be re-parsed as raw LE") {
        auto data = create_bound_le(0x200, 0x180, 0);
        auto le = le_file::from_memory(data);

        auto stripped = le.strip_extender();
        REQUIRE(!stripped.empty());

        // Parse the stripped data as a new LE file
        auto raw_le = le_file::from_memory(stripped);

        CHECK_FALSE(raw_le.is_bound());
        CHECK(raw_le.le_header_offset() == 0);
        CHECK_FALSE(raw_le.is_lx());
    }
}

// =============================================================================
// DOOM.EXE Tests - Real DOS/4GW LE executable
// =============================================================================

TEST_CASE("LE DOOM.EXE: format detection") {
    std::span<const uint8_t> input(data::doom_le, data::doom_le_len);
    auto le = le_file::from_memory(input);

    CHECK_FALSE(le.is_lx());           // LE, not LX
    CHECK(le.is_bound());              // Bound to DOS/4GW extender
    CHECK(le.get_format() == format_type::LE_DOS32_BOUND);
}

TEST_CASE("LE DOOM.EXE: header fields") {
    std::span<const uint8_t> input(data::doom_le, data::doom_le_len);
    auto le = le_file::from_memory(input);

    CHECK(le.cpu_type() == 0x02);      // i386
    CHECK(le.os_type() == 0x01);       // OS/2 (standard for DOS/4GW LE files)
    CHECK(le.page_size() == 4096);
    CHECK(le.stub_size() > 0);

}

TEST_CASE("LE DOOM.EXE: strip extender") {
    std::span<const uint8_t> input(data::doom_le, data::doom_le_len);
    auto le = le_file::from_memory(input);

    REQUIRE(le.is_bound());

    uint32_t stub_size = le.stub_size();

    auto stripped = le.strip_extender();
    REQUIRE(!stripped.empty());

    // Output size should be original minus stub
    CHECK(stripped.size() == data::doom_le_len - stub_size);

    // Verify LE magic at start
    CHECK(stripped[0] == 0x4C);  // 'L'
    CHECK(stripped[1] == 0x45);  // 'E'

}

TEST_CASE("LE DOOM.EXE: stripped file is valid LE") {
    std::span<const uint8_t> input(data::doom_le, data::doom_le_len);
    auto le = le_file::from_memory(input);

    auto stripped = le.strip_extender();
    REQUIRE(!stripped.empty());

    // Parse the stripped file
    auto raw_le = le_file::from_memory(stripped);

    // Should now be raw LE (no longer bound)
    CHECK_FALSE(raw_le.is_bound());
    CHECK(raw_le.le_header_offset() == 0);
    CHECK_FALSE(raw_le.is_lx());

    // Should have same structure
    CHECK(raw_le.cpu_type() == le.cpu_type());
    CHECK(raw_le.os_type() == le.os_type());
    CHECK(raw_le.page_size() == le.page_size());
    CHECK(raw_le.objects().size() == le.objects().size());
    CHECK(raw_le.page_count() == le.page_count());
}

TEST_CASE("LE DOOM.EXE: offset adjustments are correct") {
    std::span<const uint8_t> input(data::doom_le, data::doom_le_len);
    auto le = le_file::from_memory(input);

    auto stripped = le.strip_extender();
    REQUIRE(!stripped.empty());

    // Re-parse the stripped file
    auto raw_le = le_file::from_memory(stripped);

    // Parse should succeed without errors indicating offsets are valid
    CHECK(raw_le.objects().size() > 0);

    // Module name should still be accessible
    auto name = raw_le.module_name();
}
