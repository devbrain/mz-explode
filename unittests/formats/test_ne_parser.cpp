// Test NE file parser functionality
#include <doctest/doctest.h>
#include <libexe/formats/ne_file.hpp>
#include <libexe/ne/types.hpp>
#include <vector>

using namespace libexe;

TEST_CASE("NE file parser: basic validation") {
    SUBCASE("Rejects files that are too small") {
        std::vector<uint8_t> tiny_data = {0x4D, 0x5A};  // Just MZ signature
        CHECK_THROWS_AS((void)ne_file::from_memory(tiny_data), std::runtime_error);
    }

    SUBCASE("Rejects non-MZ files") {
        std::vector<uint8_t> bad_data(128, 0xFF);
        CHECK_THROWS_AS((void)ne_file::from_memory(bad_data), std::runtime_error);
    }

    SUBCASE("Rejects MZ files without NE header") {
        // Valid MZ header but e_lfanew = 0 (pure DOS, not NE)
        std::vector<uint8_t> dos_only(128);
        dos_only[0] = 0x4D;  // 'M'
        dos_only[1] = 0x5A;  // 'Z'
        // e_lfanew at offset 0x3C is 0
        CHECK_THROWS_AS((void)ne_file::from_memory(dos_only), std::runtime_error);
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
        CHECK_THROWS_AS((void)ne_file::from_memory(wrong_sig), std::runtime_error);
    }
}

TEST_CASE("NE segment structure") {
    SUBCASE("Segment structure fields are accessible") {
        ne_segment segment;
        segment.index = 1;
        segment.type = section_type::CODE;
        segment.file_offset = 0x0010 << 4;  // sector 0x10 with alignment shift 4 = 0x100
        segment.file_size = 0x2000;
        segment.flags = static_cast<uint16_t>(ne_segment_flags::CODE);  // Code segment
        segment.min_alloc_size = 0x2000;

        CHECK(segment.index == 1);
        CHECK(segment.file_offset == 0x100);
        CHECK(segment.file_size == 0x2000);
        CHECK(segment.is_code());  // Use helper method instead of has_flag
        CHECK(segment.min_alloc_size == 0x2000);
    }
}
