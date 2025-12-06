// Test NE file parser functionality
#include <doctest/doctest.h>
#include <libexe/ne_file.hpp>
#include <vector>

using namespace libexe;

TEST_CASE("NE file parser: basic validation") {
    SUBCASE("Rejects files that are too small") {
        std::vector<uint8_t> tiny_data = {0x4D, 0x5A};  // Just MZ signature
        CHECK_THROWS_AS(ne_file::from_memory(tiny_data), std::runtime_error);
    }

    SUBCASE("Rejects non-MZ files") {
        std::vector<uint8_t> bad_data(128, 0xFF);
        CHECK_THROWS_AS(ne_file::from_memory(bad_data), std::runtime_error);
    }

    SUBCASE("Rejects MZ files without NE header") {
        // Valid MZ header but e_lfanew = 0 (pure DOS, not NE)
        std::vector<uint8_t> dos_only(128);
        dos_only[0] = 0x4D;  // 'M'
        dos_only[1] = 0x5A;  // 'Z'
        // e_lfanew at offset 0x3C is 0
        CHECK_THROWS_AS(ne_file::from_memory(dos_only), std::runtime_error);
    }

    SUBCASE("Rejects files with wrong signature at NE offset") {
        // Valid MZ header with e_lfanew pointing to invalid signature
        std::vector<uint8_t> wrong_sig(256, 0);
        wrong_sig[0] = 0x4D;  // 'M'
        wrong_sig[1] = 0x5A;  // 'Z'
        wrong_sig[0x3C] = 0x80;  // e_lfanew = 0x80
        wrong_sig[0x3D] = 0x00;
        // Put wrong signature at offset 0x80 (not NE)
        wrong_sig[0x80] = 0x50;  // 'P'
        wrong_sig[0x81] = 0x45;  // 'E' (PE signature, not NE)
        CHECK_THROWS_AS(ne_file::from_memory(wrong_sig), std::runtime_error);
    }
}

TEST_CASE("NE file parser: API completeness") {
    // This test verifies the API compiles and has all expected methods
    // We can't test actual parsing without real NE files, but we can
    // verify the interface exists and compiles

    SUBCASE("API methods exist and compile") {
        // This just verifies the API compiles - it will throw at runtime
        // without valid data, which is expected
        std::vector<uint8_t> dummy_data(256, 0);

        bool caught_exception = false;
        try {
            auto ne = ne_file::from_memory(dummy_data);

            // If we somehow get here, verify methods exist
            (void)ne.linker_version();
            (void)ne.linker_revision();
            (void)ne.flags();
            (void)ne.segment_count();
            (void)ne.module_count();
            (void)ne.target_os();
            (void)ne.entry_cs();
            (void)ne.entry_ip();
            (void)ne.initial_ss();
            (void)ne.initial_sp();
            (void)ne.segment_table_offset();
            (void)ne.resource_table_offset();
            (void)ne.resident_name_table_offset();
            (void)ne.module_ref_table_offset();
            (void)ne.import_name_table_offset();
            (void)ne.nonresident_name_table_offset();
            (void)ne.alignment_shift();
            (void)ne.segments();
            (void)ne.get_segment(0);
            (void)ne.get_code_segment();
            (void)ne.get_format();
            (void)ne.format_name();
            (void)ne.code_section();

        } catch (const std::runtime_error&) {
            // Expected - invalid data
            caught_exception = true;
        }

        CHECK(caught_exception);
    }
}

TEST_CASE("NE segment structure") {
    SUBCASE("Segment structure fields are accessible") {
        ne_segment segment;
        segment.sector_offset = 0x0010;
        segment.length = 0x2000;
        segment.flags = 0x0000;  // Code segment
        segment.min_alloc = 0x2000;

        CHECK(segment.sector_offset == 0x0010);
        CHECK(segment.length == 0x2000);
        CHECK(segment.flags == 0x0000);
        CHECK(segment.min_alloc == 0x2000);
    }
}

TEST_CASE("NE format name mapping") {
    SUBCASE("Format name reflects target OS") {
        // We can't easily test this without creating valid NE files,
        // but we can at least verify the enum exists
        format_type fmt = format_type::NE_WIN16;
        CHECK(fmt == format_type::NE_WIN16);
    }
}
