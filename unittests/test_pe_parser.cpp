// Test PE file parser functionality
#include <doctest/doctest.h>
#include <libexe/pe_file.hpp>
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

TEST_CASE("PE file parser: API completeness") {
    // This test verifies the API compiles and has all expected methods
    // We can't test actual parsing without real PE files, but we can
    // verify the interface exists and compiles

    SUBCASE("API methods exist and compile") {
        // This just verifies the API compiles - it will throw at runtime
        // without valid data, which is expected
        std::vector<uint8_t> dummy_data(256, 0);

        bool caught_exception = false;
        try {
            auto pe = pe_file::from_memory(dummy_data);

            // If we somehow get here, verify methods exist
            (void)pe.is_64bit();
            (void)pe.machine_type();
            (void)pe.section_count();
            (void)pe.timestamp();
            (void)pe.characteristics();
            (void)pe.image_base();
            (void)pe.entry_point_rva();
            (void)pe.section_alignment();
            (void)pe.file_alignment();
            (void)pe.size_of_image();
            (void)pe.size_of_headers();
            (void)pe.subsystem();
            (void)pe.dll_characteristics();
            (void)pe.sections();
            (void)pe.find_section(".text");
            (void)pe.get_code_section();
            (void)pe.get_format();
            (void)pe.format_name();
            (void)pe.code_section();

        } catch (const std::runtime_error&) {
            // Expected - invalid data
            caught_exception = true;
        }

        CHECK(caught_exception);
    }
}

TEST_CASE("PE section structure") {
    SUBCASE("Section structure fields are accessible") {
        pe_section section;
        section.name = ".text";
        section.virtual_address = 0x1000;
        section.virtual_size = 0x2000;
        section.raw_data_offset = 0x400;
        section.raw_data_size = 0x2000;
        section.characteristics = 0x60000020;  // CODE | EXECUTE | READ

        CHECK(section.name == ".text");
        CHECK(section.virtual_address == 0x1000);
        CHECK(section.virtual_size == 0x2000);
        CHECK(section.raw_data_offset == 0x400);
        CHECK(section.raw_data_size == 0x2000);
        CHECK(section.characteristics == 0x60000020);
    }
}
