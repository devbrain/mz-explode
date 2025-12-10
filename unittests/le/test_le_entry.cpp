// Test LE/LX entry table parsing
#include <doctest/doctest.h>
#include <libexe/formats/le_file.hpp>
#include <vector>
#include <cstring>

using namespace libexe;

namespace {

// Create a minimal LE executable with entry table for testing
// Structure:
//   0x0000-0x003F: MZ header (64 bytes)
//   0x0040-0x007F: DOS stub placeholder (64 bytes)
//   0x0080-0x012F: LE header (176 bytes)
//   0x0130+:       Object table, page table, entry table, data
std::vector<uint8_t> create_le_with_entries() {
    // Total size with room for tables
    std::vector<uint8_t> data(0x400, 0);

    // MZ header
    data[0x00] = 0x4D;  // 'M'
    data[0x01] = 0x5A;  // 'Z'
    data[0x02] = 0x80;  // bytes on last page (128)
    data[0x03] = 0x00;
    data[0x04] = 0x01;  // pages (1 * 512 = 512 bytes)
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
    data[le_off + 0x02] = 0x00;  // byte order (little endian)
    data[le_off + 0x03] = 0x00;  // word order (little endian)
    data[le_off + 0x08] = 0x02;  // CPU type = 386
    data[le_off + 0x09] = 0x00;
    data[le_off + 0x0A] = 0x03;  // OS type = DOS
    data[le_off + 0x0B] = 0x00;

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

    // Initial EIP = 0x1000
    data[le_off + 0x1C] = 0x00;
    data[le_off + 0x1D] = 0x10;
    data[le_off + 0x1E] = 0x00;
    data[le_off + 0x1F] = 0x00;

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

    // Entry table offset (relative) = 0xD0
    data[le_off + 0x5C] = 0xD0;
    data[le_off + 0x5D] = 0x00;
    data[le_off + 0x5E] = 0x00;
    data[le_off + 0x5F] = 0x00;

    // Data pages offset (ABSOLUTE file offset) - 0x80
    data[le_off + 0x80] = 0x00;
    data[le_off + 0x81] = 0x02;  // 0x200
    data[le_off + 0x82] = 0x00;
    data[le_off + 0x83] = 0x00;

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
    data[page_off + 0] = 0x00;  // high
    data[page_off + 1] = 0x00;  // med
    data[page_off + 2] = 0x01;  // low (page number 1)
    data[page_off + 3] = 0x00;  // flags (legal)

    // Entry table at le_off + 0xD0
    // Format: bundles of (count, type) + object + entries
    size_t entry_off = le_off + 0xD0;

    // Bundle 1: Two 32-bit entries in object 1
    // count = 2, type = 3 (32-bit)
    data[entry_off + 0] = 0x02;  // count = 2
    data[entry_off + 1] = 0x03;  // type = 32-bit
    // Object number (2 bytes for 32-bit type)
    data[entry_off + 2] = 0x01;  // object 1
    data[entry_off + 3] = 0x00;
    // Entry 1: flags=0x01 (exported), offset=0x1000
    data[entry_off + 4] = 0x01;  // flags (exported)
    data[entry_off + 5] = 0x00;  // offset low
    data[entry_off + 6] = 0x10;  // offset
    data[entry_off + 7] = 0x00;  // offset
    data[entry_off + 8] = 0x00;  // offset high
    // Entry 2: flags=0x00, offset=0x2000
    data[entry_off + 9] = 0x00;   // flags
    data[entry_off + 10] = 0x00;  // offset low
    data[entry_off + 11] = 0x20;  // offset
    data[entry_off + 12] = 0x00;  // offset
    data[entry_off + 13] = 0x00;  // offset high

    // Bundle 2: Skip 3 ordinals
    data[entry_off + 14] = 0x03;  // count = 3
    data[entry_off + 15] = 0x00;  // type = unused (skip)

    // Bundle 3: One 32-bit entry
    data[entry_off + 16] = 0x01;  // count = 1
    data[entry_off + 17] = 0x03;  // type = 32-bit
    data[entry_off + 18] = 0x01;  // object 1
    data[entry_off + 19] = 0x00;
    // Entry: flags=0x01 (exported), offset=0x3000
    data[entry_off + 20] = 0x01;  // flags (exported)
    data[entry_off + 21] = 0x00;  // offset low
    data[entry_off + 22] = 0x30;  // offset
    data[entry_off + 23] = 0x00;  // offset
    data[entry_off + 24] = 0x00;  // offset high

    // End of entry table
    data[entry_off + 25] = 0x00;  // count = 0 (end)
    data[entry_off + 26] = 0x00;  // type (unused)

    return data;
}

// Create LE with 16-bit entries
std::vector<uint8_t> create_le_with_16bit_entries() {
    auto data = create_le_with_entries();

    // Override entry table at le_off + 0xD0
    size_t le_off = 0x80;
    size_t entry_off = le_off + 0xD0;

    // Bundle: Two 16-bit entries
    data[entry_off + 0] = 0x02;  // count = 2
    data[entry_off + 1] = 0x01;  // type = 16-bit
    // Object number (1 byte for 16-bit type)
    data[entry_off + 2] = 0x01;  // object 1
    // Entry 1: flags=0x01 (exported), offset=0x0100
    data[entry_off + 3] = 0x01;  // flags (exported)
    data[entry_off + 4] = 0x00;  // offset low
    data[entry_off + 5] = 0x01;  // offset high
    // Entry 2: flags=0x00, offset=0x0200
    data[entry_off + 6] = 0x00;  // flags
    data[entry_off + 7] = 0x00;  // offset low
    data[entry_off + 8] = 0x02;  // offset high

    // End of entry table
    data[entry_off + 9] = 0x00;   // count = 0 (end)
    data[entry_off + 10] = 0x00;  // type

    return data;
}

// Create LE with forwarder entries
std::vector<uint8_t> create_le_with_forwarder_entries() {
    auto data = create_le_with_entries();

    // Override entry table at le_off + 0xD0
    size_t le_off = 0x80;
    size_t entry_off = le_off + 0xD0;

    // Bundle: One forwarder entry
    data[entry_off + 0] = 0x01;  // count = 1
    data[entry_off + 1] = 0x04;  // type = forwarder
    // Reserved (2 bytes)
    data[entry_off + 2] = 0x00;
    data[entry_off + 3] = 0x00;
    // Entry: flags=0x00, module_ordinal=0x0001, import_ordinal=0x00000005
    data[entry_off + 4] = 0x00;  // flags
    data[entry_off + 5] = 0x01;  // module ordinal low
    data[entry_off + 6] = 0x00;  // module ordinal high
    data[entry_off + 7] = 0x05;  // import ordinal byte 0
    data[entry_off + 8] = 0x00;  // import ordinal byte 1
    data[entry_off + 9] = 0x00;  // import ordinal byte 2
    data[entry_off + 10] = 0x00; // import ordinal byte 3

    // End of entry table
    data[entry_off + 11] = 0x00;  // count = 0 (end)
    data[entry_off + 12] = 0x00;  // type

    return data;
}

} // anonymous namespace

TEST_CASE("LE entry table: 32-bit entries") {
    auto data = create_le_with_entries();
    auto le = le_file::from_memory(data);

    SUBCASE("Entry count is correct") {
        CHECK(le.entry_count() == 3);
    }

    SUBCASE("First entry is parsed correctly") {
        auto entry = le.get_entry(1);
        REQUIRE(entry.has_value());
        CHECK(entry->ordinal == 1);
        CHECK(entry->type == le_entry_type::ENTRY_32);
        CHECK(entry->object == 1);
        CHECK(entry->offset == 0x1000);
        CHECK(entry->is_exported());
    }

    SUBCASE("Second entry is parsed correctly") {
        auto entry = le.get_entry(2);
        REQUIRE(entry.has_value());
        CHECK(entry->ordinal == 2);
        CHECK(entry->type == le_entry_type::ENTRY_32);
        CHECK(entry->object == 1);
        CHECK(entry->offset == 0x2000);
        CHECK_FALSE(entry->is_exported());
    }

    SUBCASE("Ordinal gap is respected") {
        // Entries 1, 2, then skip 3, 4, 5, so next is ordinal 6
        auto entry = le.get_entry(6);
        REQUIRE(entry.has_value());
        CHECK(entry->ordinal == 6);
        CHECK(entry->type == le_entry_type::ENTRY_32);
        CHECK(entry->offset == 0x3000);
        CHECK(entry->is_exported());
    }

    SUBCASE("Non-existent ordinal returns nullopt") {
        CHECK_FALSE(le.get_entry(3).has_value());
        CHECK_FALSE(le.get_entry(4).has_value());
        CHECK_FALSE(le.get_entry(5).has_value());
        CHECK_FALSE(le.get_entry(100).has_value());
    }

    SUBCASE("Entries vector is accessible") {
        const auto& entries = le.entries();
        CHECK(entries.size() == 3);
        CHECK(entries[0].ordinal == 1);
        CHECK(entries[1].ordinal == 2);
        CHECK(entries[2].ordinal == 6);
    }
}

TEST_CASE("LE entry table: 16-bit entries") {
    auto data = create_le_with_16bit_entries();
    auto le = le_file::from_memory(data);

    SUBCASE("Entry count is correct") {
        CHECK(le.entry_count() == 2);
    }

    SUBCASE("16-bit entries are parsed correctly") {
        auto entry1 = le.get_entry(1);
        REQUIRE(entry1.has_value());
        CHECK(entry1->type == le_entry_type::ENTRY_16);
        CHECK(entry1->object == 1);
        CHECK(entry1->offset == 0x0100);
        CHECK(entry1->is_exported());

        auto entry2 = le.get_entry(2);
        REQUIRE(entry2.has_value());
        CHECK(entry2->type == le_entry_type::ENTRY_16);
        CHECK(entry2->offset == 0x0200);
        CHECK_FALSE(entry2->is_exported());
    }
}

TEST_CASE("LE entry table: forwarder entries") {
    auto data = create_le_with_forwarder_entries();
    auto le = le_file::from_memory(data);

    SUBCASE("Forwarder entry is parsed correctly") {
        CHECK(le.entry_count() == 1);

        auto entry = le.get_entry(1);
        REQUIRE(entry.has_value());
        CHECK(entry->type == le_entry_type::FORWARDER);
        CHECK(entry->module_ordinal == 1);
        CHECK(entry->import_ordinal == 5);
    }
}

TEST_CASE("LE entry table: empty table") {
    auto data = create_le_with_entries();
    size_t le_off = 0x80;
    size_t entry_off = le_off + 0xD0;

    // Set entry table to immediately terminate
    data[entry_off + 0] = 0x00;  // count = 0 (end)
    data[entry_off + 1] = 0x00;

    auto le = le_file::from_memory(data);
    CHECK(le.entry_count() == 0);
    CHECK(le.entries().empty());
}

TEST_CASE("LE entry table: no entry table") {
    auto data = create_le_with_entries();
    size_t le_off = 0x80;

    // Set entry table offset to 0
    data[le_off + 0x5C] = 0x00;
    data[le_off + 0x5D] = 0x00;
    data[le_off + 0x5E] = 0x00;
    data[le_off + 0x5F] = 0x00;

    auto le = le_file::from_memory(data);
    CHECK(le.entry_count() == 0);
    CHECK(le.entries().empty());
}

TEST_CASE("LE entry table: entry flags") {
    auto data = create_le_with_entries();
    size_t le_off = 0x80;
    size_t entry_off = le_off + 0xD0;

    // Modify first entry to have param count
    // flags = 0x01 | (3 << 3) = 0x19 (exported, 3 params)
    data[entry_off + 4] = 0x19;

    auto le = le_file::from_memory(data);
    auto entry = le.get_entry(1);
    REQUIRE(entry.has_value());
    CHECK(entry->is_exported());
    CHECK(entry->param_count() == 3);
}
