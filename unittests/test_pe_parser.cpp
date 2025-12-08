// Test PE file parser functionality
#include <doctest/doctest.h>
#include <libexe/pe_file.hpp>
#include <libexe/pe_types.hpp>
#include <vector>

using namespace libexe;

TEST_CASE("PE file parser: basic validation") {
    SUBCASE("Rejects files that are too small") {
        std::vector<uint8_t> tiny_data = {0x4D, 0x5A};  // Just MZ signature
        CHECK_THROWS_AS(pe_file::from_memory(tiny_data), std::runtime_error);
    }

    SUBCASE("Rejects non-MZ files") {
        std::vector<uint8_t> bad_data(128, 0xFF);
        CHECK_THROWS_AS(pe_file::from_memory(bad_data), std::runtime_error);
    }

    SUBCASE("Rejects MZ files without PE header") {
        // Valid MZ header but e_lfanew = 0 (pure DOS, not PE)
        std::vector<uint8_t> dos_only(128);
        dos_only[0] = 0x4D;  // 'M'
        dos_only[1] = 0x5A;  // 'Z'
        // e_lfanew at offset 0x3C is 0
        CHECK_THROWS_AS(pe_file::from_memory(dos_only), std::runtime_error);
    }
}

TEST_CASE("PE section structure") {
    SUBCASE("Section structure fields are accessible") {
        pe_section section;
        section.name = ".text";
        section.type = section_type::CODE;
        section.virtual_address = 0x1000;
        section.virtual_size = 0x2000;
        section.raw_data_offset = 0x400;
        section.raw_data_size = 0x2000;
        section.characteristics = static_cast<uint32_t>(pe_section_characteristics::CNT_CODE) |
                                  static_cast<uint32_t>(pe_section_characteristics::MEM_EXECUTE) |
                                  static_cast<uint32_t>(pe_section_characteristics::MEM_READ);
        section.alignment = 4096;

        CHECK(section.name == ".text");
        CHECK(section.virtual_address == 0x1000);
        CHECK(section.virtual_size == 0x2000);
        CHECK(section.raw_data_offset == 0x400);
        CHECK(section.raw_data_size == 0x2000);
        CHECK(section.is_code());
        CHECK(section.is_executable());
        CHECK(section.is_readable());
    }
}
