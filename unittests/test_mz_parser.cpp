// Unit tests for MZ file parsing
#include <doctest/doctest.h>
#include <libexe/formats/mz_file.hpp>
#include <vector>
#include <cstring>

using namespace libexe;

// Helper to create a minimal valid MZ header
static std::vector<uint8_t> create_minimal_mz_file() {
    std::vector<uint8_t> data(512, 0);  // Minimum size with some padding

    // MZ signature (offset 0)
    data[0] = 0x4D;  // 'M'
    data[1] = 0x5A;  // 'Z'

    // e_cblp - bytes on last page (offset 2)
    data[2] = 0x90;
    data[3] = 0x00;

    // e_cp - pages in file (offset 4)
    data[4] = 0x03;
    data[5] = 0x00;

    // e_crlc - relocations (offset 6)
    data[6] = 0x00;
    data[7] = 0x00;

    // e_cparhdr - size of header in paragraphs (offset 8)
    data[8] = 0x04;  // 4 paragraphs = 64 bytes
    data[9] = 0x00;

    // e_minalloc - minimum extra paragraphs (offset 10)
    data[10] = 0x00;
    data[11] = 0x00;

    // e_maxalloc - maximum extra paragraphs (offset 12)
    data[12] = 0xFF;
    data[13] = 0xFF;

    // e_ss - initial SS (offset 14)
    data[14] = 0x00;
    data[15] = 0x00;

    // e_sp - initial SP (offset 16)
    data[16] = 0xB8;
    data[17] = 0x00;

    // e_csum - checksum (offset 18)
    data[18] = 0x00;
    data[19] = 0x00;

    // e_ip - initial IP (offset 20)
    data[20] = 0x00;
    data[21] = 0x00;

    // e_cs - initial CS (offset 22)
    data[22] = 0x00;
    data[23] = 0x00;

    // e_lfarlc - file address of relocation table (offset 24)
    data[24] = 0x40;
    data[25] = 0x00;

    // e_ovno - overlay number (offset 26)
    data[26] = 0x00;
    data[27] = 0x00;

    // Rest of extended header (reserved fields + e_lfanew)
    // ... zeros are fine for basic test

    return data;
}

TEST_CASE("mz_file: basic parsing") {
    SUBCASE("parse minimal valid MZ file") {
        auto data = create_minimal_mz_file();

        REQUIRE_NOTHROW([&]() {
            auto mz = mz_file::from_memory(data);

            CHECK(mz.get_format() == format_type::MZ_DOS);
            CHECK(mz.format_name() == "MZ (DOS Executable)");
            CHECK(mz.is_compressed() == false);
            CHECK(mz.get_compression() == compression_type::NONE);
        }());
    }

    SUBCASE("reject file that's too small") {
        std::vector<uint8_t> tiny_data(10, 0);

        CHECK_THROWS_AS(
            mz_file::from_memory(tiny_data),
            std::runtime_error
        );
    }

    SUBCASE("reject file with invalid signature") {
        auto data = create_minimal_mz_file();
        data[0] = 0x00;  // Corrupt MZ signature
        data[1] = 0x00;

        CHECK_THROWS_WITH(
            mz_file::from_memory(data),
            doctest::Contains("Invalid MZ file")
        );
    }
}

TEST_CASE("mz_file: DOS header accessors") {
    auto data = create_minimal_mz_file();

    // Set specific values for testing
    data[8] = 0x04;   // e_cparhdr = 4 (header is 64 bytes)
    data[9] = 0x00;

    data[10] = 0x10;  // e_minalloc = 16 paragraphs
    data[11] = 0x00;

    data[12] = 0xFF;  // e_maxalloc = 65535 paragraphs
    data[13] = 0xFF;

    data[14] = 0x34;  // e_ss = 0x1234
    data[15] = 0x12;

    data[16] = 0x00;  // e_sp = 0x0100
    data[17] = 0x01;

    data[20] = 0x00;  // e_ip = 0x0000
    data[21] = 0x00;

    data[22] = 0x00;  // e_cs = 0x0000
    data[23] = 0x00;

    data[6] = 0x05;   // e_crlc = 5 relocations
    data[7] = 0x00;

    auto mz = mz_file::from_memory(data);

    SUBCASE("header size") {
        CHECK(mz.header_paragraphs() == 4);
    }

    SUBCASE("memory requirements") {
        CHECK(mz.min_extra_paragraphs() == 16);
        CHECK(mz.max_extra_paragraphs() == 65535);
    }

    SUBCASE("initial register values") {
        CHECK(mz.initial_ss() == 0x1234);
        CHECK(mz.initial_sp() == 0x0100);
        CHECK(mz.initial_cs() == 0x0000);
        CHECK(mz.initial_ip() == 0x0000);
    }

    SUBCASE("relocation count") {
        CHECK(mz.relocation_count() == 5);
    }
}

TEST_CASE("mz_file: code section") {
    auto data = create_minimal_mz_file();

    // Set header to 4 paragraphs (64 bytes)
    data[8] = 0x04;
    data[9] = 0x00;

    // Fill code section with recognizable pattern
    for (size_t i = 64; i < 128; i++) {
        data[i] = static_cast<uint8_t>(i);
    }

    auto mz = mz_file::from_memory(data);
    auto code = mz.code_section();

    SUBCASE("code section starts after header") {
        REQUIRE(code.size() == data.size() - 64);
        CHECK(code[0] == 64);   // First byte of code section
        CHECK(code[1] == 65);
        CHECK(code[63] == 127);
    }
}

TEST_CASE("mz_file: format detection") {
    auto data = create_minimal_mz_file();
    auto mz = mz_file::from_memory(data);

    SUBCASE("format type enum") {
        CHECK(mz.get_format() == format_type::MZ_DOS);
    }

    SUBCASE("format name string") {
        CHECK(mz.format_name() == "MZ (DOS Executable)");
    }
}
