// Test LE/LX fixup table parsing
#include <doctest/doctest.h>
#include <libexe/formats/le_file.hpp>
#include <vector>
#include <cstring>

using namespace libexe;

namespace {

// Create a minimal LE executable with fixup tables for testing
std::vector<uint8_t> create_le_with_fixups() {
    // Total size with room for tables
    std::vector<uint8_t> data(0x500, 0);

    // MZ header
    data[0x00] = 0x4D;  // 'M'
    data[0x01] = 0x5A;  // 'Z'
    data[0x02] = 0x80;  // bytes on last page
    data[0x03] = 0x00;
    data[0x04] = 0x01;  // pages
    data[0x05] = 0x00;
    data[0x18] = 0x40;  // relocation table offset
    data[0x19] = 0x00;
    data[0x3C] = 0x80;  // e_lfanew = 0x80
    data[0x3D] = 0x00;
    data[0x3E] = 0x00;
    data[0x3F] = 0x00;

    // LE header at offset 0x80
    size_t le_off = 0x80;
    data[le_off + 0x00] = 0x4C;  // 'L'
    data[le_off + 0x01] = 0x45;  // 'E'
    data[le_off + 0x02] = 0x00;  // byte order
    data[le_off + 0x03] = 0x00;  // word order
    data[le_off + 0x08] = 0x02;  // CPU type = 386
    data[le_off + 0x09] = 0x00;
    data[le_off + 0x0A] = 0x03;  // OS type = DOS
    data[le_off + 0x0B] = 0x00;

    // Page count = 2
    data[le_off + 0x14] = 0x02;
    data[le_off + 0x15] = 0x00;
    data[le_off + 0x16] = 0x00;
    data[le_off + 0x17] = 0x00;

    // Page size = 4096
    data[le_off + 0x28] = 0x00;
    data[le_off + 0x29] = 0x10;
    data[le_off + 0x2A] = 0x00;
    data[le_off + 0x2B] = 0x00;

    // Object table offset (relative) = 0xB0
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

    // Fixup page table offset (relative) = 0xE0
    data[le_off + 0x68] = 0xE0;
    data[le_off + 0x69] = 0x00;
    data[le_off + 0x6A] = 0x00;
    data[le_off + 0x6B] = 0x00;

    // Fixup record table offset (relative) = 0xF0
    data[le_off + 0x6C] = 0xF0;
    data[le_off + 0x6D] = 0x00;
    data[le_off + 0x6E] = 0x00;
    data[le_off + 0x6F] = 0x00;

    // Data pages offset (ABSOLUTE file offset) = 0x200
    data[le_off + 0x80] = 0x00;
    data[le_off + 0x81] = 0x02;
    data[le_off + 0x82] = 0x00;
    data[le_off + 0x83] = 0x00;

    // Add object table entry at le_off + 0xB0
    size_t obj_off = le_off + 0xB0;
    // Virtual size = 0x2000
    data[obj_off + 0x00] = 0x00;
    data[obj_off + 0x01] = 0x20;
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
    // Page count = 2
    data[obj_off + 0x10] = 0x02;
    data[obj_off + 0x11] = 0x00;
    data[obj_off + 0x12] = 0x00;
    data[obj_off + 0x13] = 0x00;

    // Add page table entries at le_off + 0xC8
    size_t page_off = le_off + 0xC8;
    // Page 1
    data[page_off + 0] = 0x00;
    data[page_off + 1] = 0x00;
    data[page_off + 2] = 0x01;
    data[page_off + 3] = 0x00;
    // Page 2
    data[page_off + 4] = 0x00;
    data[page_off + 5] = 0x00;
    data[page_off + 6] = 0x02;
    data[page_off + 7] = 0x00;

    // Fixup page table at le_off + 0xE0
    // Array of uint32_t offsets into fixup record table
    // page_count + 1 entries to allow calculating size
    size_t fpt_off = le_off + 0xE0;
    // Page 1 starts at offset 0 in fixup record table
    data[fpt_off + 0] = 0x00;
    data[fpt_off + 1] = 0x00;
    data[fpt_off + 2] = 0x00;
    data[fpt_off + 3] = 0x00;
    // Page 2 starts at offset 7 (after page 1's fixups)
    data[fpt_off + 4] = 0x07;
    data[fpt_off + 5] = 0x00;
    data[fpt_off + 6] = 0x00;
    data[fpt_off + 7] = 0x00;
    // End marker at offset 14 (after page 2's fixups)
    data[fpt_off + 8] = 0x0E;
    data[fpt_off + 9] = 0x00;
    data[fpt_off + 10] = 0x00;
    data[fpt_off + 11] = 0x00;

    // Fixup record table at le_off + 0xF0
    size_t frt_off = le_off + 0xF0;

    // === Page 1 fixups (offsets 0-6) ===
    // Fixup 1: Internal 32-bit offset fixup
    // Source: type=7 (OFFSET_32), no flags
    // Target: type=0 (INTERNAL), object=1, 16-bit offset
    data[frt_off + 0] = 0x07;  // source: OFFSET_32
    data[frt_off + 1] = 0x00;  // target: INTERNAL, no flags
    data[frt_off + 2] = 0x00;  // source offset low
    data[frt_off + 3] = 0x01;  // source offset high = 0x0100
    data[frt_off + 4] = 0x01;  // target object = 1
    data[frt_off + 5] = 0x50;  // target offset low
    data[frt_off + 6] = 0x00;  // target offset high = 0x0050

    // === Page 2 fixups (offsets 7-13) ===
    // Fixup 2: Import by ordinal
    // Source: type=7 (OFFSET_32)
    // Target: type=1 (IMPORT_ORDINAL), 8-bit ordinals
    data[frt_off + 7] = 0x07;   // source: OFFSET_32
    data[frt_off + 8] = 0x81;   // target: IMPORT_ORDINAL | 8-bit ordinal flag
    data[frt_off + 9] = 0x00;   // source offset low
    data[frt_off + 10] = 0x02;  // source offset high = 0x0200
    data[frt_off + 11] = 0x01;  // module ordinal = 1
    data[frt_off + 12] = 0x05;  // import ordinal = 5
    // Total: 6 bytes

    return data;
}

} // anonymous namespace

TEST_CASE("LE fixup table: internal fixups") {
    auto data = create_le_with_fixups();
    auto le = le_file::from_memory(data);

    SUBCASE("Has fixups") {
        CHECK(le.has_fixups());
        CHECK(le.fixup_count() >= 1);
    }

    SUBCASE("Page 1 fixup is parsed correctly") {
        auto page_fixups = le.get_page_fixups(1);
        REQUIRE(page_fixups.size() >= 1);

        auto& fixup = page_fixups[0];
        CHECK(fixup.page_index == 1);
        CHECK(fixup.source_offset == 0x0100);
        CHECK(fixup.source_type == le_fixup_source_type::OFFSET_32);
        CHECK(fixup.target_type == le_fixup_target_type::INTERNAL);
        CHECK(fixup.target_object == 1);
        CHECK(fixup.target_offset == 0x0050);
    }
}

TEST_CASE("LE fixup table: import fixups") {
    auto data = create_le_with_fixups();
    auto le = le_file::from_memory(data);

    SUBCASE("Page 2 fixup is parsed correctly") {
        auto page_fixups = le.get_page_fixups(2);
        REQUIRE(page_fixups.size() >= 1);

        auto& fixup = page_fixups[0];
        CHECK(fixup.page_index == 2);
        CHECK(fixup.source_offset == 0x0200);
        CHECK(fixup.source_type == le_fixup_source_type::OFFSET_32);
        CHECK(fixup.target_type == le_fixup_target_type::IMPORT_ORDINAL);
        CHECK(fixup.module_ordinal == 1);
        CHECK(fixup.import_ordinal == 5);
    }
}

TEST_CASE("LE fixup table: no fixups") {
    auto data = create_le_with_fixups();
    size_t le_off = 0x80;

    // Set fixup page table offset to 0
    data[le_off + 0x68] = 0x00;
    data[le_off + 0x69] = 0x00;
    data[le_off + 0x6A] = 0x00;
    data[le_off + 0x6B] = 0x00;

    auto le = le_file::from_memory(data);
    CHECK_FALSE(le.has_fixups());
    CHECK(le.fixup_count() == 0);
}

TEST_CASE("LE fixup table: fixups accessor") {
    auto data = create_le_with_fixups();
    auto le = le_file::from_memory(data);

    const auto& fixups = le.fixups();
    CHECK(fixups.size() == 2);

    // Verify both fixups are present
    bool found_page1 = false;
    bool found_page2 = false;
    for (const auto& f : fixups) {
        if (f.page_index == 1) found_page1 = true;
        if (f.page_index == 2) found_page2 = true;
    }
    CHECK(found_page1);
    CHECK(found_page2);
}

TEST_CASE("LE fixup table: get_page_fixups returns empty for nonexistent page") {
    auto data = create_le_with_fixups();
    auto le = le_file::from_memory(data);

    auto fixups = le.get_page_fixups(100);
    CHECK(fixups.empty());
}
