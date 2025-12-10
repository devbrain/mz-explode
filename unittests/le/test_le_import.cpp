// Test LE/LX import module table parsing
#include <doctest/doctest.h>
#include <libexe/formats/le_file.hpp>
#include <vector>
#include <cstring>

using namespace libexe;

namespace {

// Create a minimal LE executable with import module table for testing
std::vector<uint8_t> create_le_with_imports() {
    // Total size with room for tables
    std::vector<uint8_t> data(0x400, 0);

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

    // Page count = 1
    data[le_off + 0x14] = 0x01;
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

    // Import module table offset (relative) = 0xE0
    data[le_off + 0x70] = 0xE0;
    data[le_off + 0x71] = 0x00;
    data[le_off + 0x72] = 0x00;
    data[le_off + 0x73] = 0x00;

    // Import module count = 3
    data[le_off + 0x74] = 0x03;
    data[le_off + 0x75] = 0x00;
    data[le_off + 0x76] = 0x00;
    data[le_off + 0x77] = 0x00;

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

    // Import module table at le_off + 0xE0
    // Format: length-prefixed strings
    size_t import_off = le_off + 0xE0;

    // Module 1: "DOS4GW" (6 chars)
    data[import_off + 0] = 0x06;  // length
    data[import_off + 1] = 'D';
    data[import_off + 2] = 'O';
    data[import_off + 3] = 'S';
    data[import_off + 4] = '4';
    data[import_off + 5] = 'G';
    data[import_off + 6] = 'W';

    // Module 2: "KERNEL32" (8 chars)
    data[import_off + 7] = 0x08;  // length
    data[import_off + 8] = 'K';
    data[import_off + 9] = 'E';
    data[import_off + 10] = 'R';
    data[import_off + 11] = 'N';
    data[import_off + 12] = 'E';
    data[import_off + 13] = 'L';
    data[import_off + 14] = '3';
    data[import_off + 15] = '2';

    // Module 3: "USER32" (6 chars)
    data[import_off + 16] = 0x06;  // length
    data[import_off + 17] = 'U';
    data[import_off + 18] = 'S';
    data[import_off + 19] = 'E';
    data[import_off + 20] = 'R';
    data[import_off + 21] = '3';
    data[import_off + 22] = '2';

    return data;
}

} // anonymous namespace

TEST_CASE("LE import module table: basic parsing") {
    auto data = create_le_with_imports();
    auto le = le_file::from_memory(data);

    SUBCASE("Module count is correct") {
        CHECK(le.import_module_count() == 3);
    }

    SUBCASE("First module is parsed correctly") {
        auto mod = le.get_import_module(1);
        REQUIRE(mod.has_value());
        CHECK(*mod == "DOS4GW");
    }

    SUBCASE("Second module is parsed correctly") {
        auto mod = le.get_import_module(2);
        REQUIRE(mod.has_value());
        CHECK(*mod == "KERNEL32");
    }

    SUBCASE("Third module is parsed correctly") {
        auto mod = le.get_import_module(3);
        REQUIRE(mod.has_value());
        CHECK(*mod == "USER32");
    }

    SUBCASE("Invalid index returns nullopt") {
        CHECK_FALSE(le.get_import_module(0).has_value());
        CHECK_FALSE(le.get_import_module(4).has_value());
        CHECK_FALSE(le.get_import_module(100).has_value());
    }

    SUBCASE("Import modules vector is accessible") {
        const auto& modules = le.import_modules();
        CHECK(modules.size() == 3);
        CHECK(modules[0] == "DOS4GW");
        CHECK(modules[1] == "KERNEL32");
        CHECK(modules[2] == "USER32");
    }
}

TEST_CASE("LE import module table: empty table") {
    auto data = create_le_with_imports();
    size_t le_off = 0x80;

    // Set import module count to 0
    data[le_off + 0x74] = 0x00;
    data[le_off + 0x75] = 0x00;
    data[le_off + 0x76] = 0x00;
    data[le_off + 0x77] = 0x00;

    auto le = le_file::from_memory(data);
    CHECK(le.import_module_count() == 0);
    CHECK(le.import_modules().empty());
}

TEST_CASE("LE import module table: no table") {
    auto data = create_le_with_imports();
    size_t le_off = 0x80;

    // Set import module table offset to 0
    data[le_off + 0x70] = 0x00;
    data[le_off + 0x71] = 0x00;
    data[le_off + 0x72] = 0x00;
    data[le_off + 0x73] = 0x00;

    auto le = le_file::from_memory(data);
    CHECK(le.import_module_count() == 0);
    CHECK(le.import_modules().empty());
}

TEST_CASE("LE import module table: single module") {
    auto data = create_le_with_imports();
    size_t le_off = 0x80;

    // Set import module count to 1
    data[le_off + 0x74] = 0x01;
    data[le_off + 0x75] = 0x00;
    data[le_off + 0x76] = 0x00;
    data[le_off + 0x77] = 0x00;

    auto le = le_file::from_memory(data);
    CHECK(le.import_module_count() == 1);

    auto mod = le.get_import_module(1);
    REQUIRE(mod.has_value());
    CHECK(*mod == "DOS4GW");
}
