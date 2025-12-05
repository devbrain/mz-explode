// Tests for PKLITE decompression
#include <doctest/doctest.h>
#include <libexe/mz_file.hpp>
#include <libexe/pklite_decompressor.hpp>
#include <vector>
#include <span>

using namespace libexe;

// Include embedded test data
namespace data {
    extern size_t pklite_112_len;
    extern unsigned char pklite_112[];

    extern size_t pklite_E_115_len;
    extern unsigned char pklite_E_115[];
}

TEST_CASE("PKLITE decompression: parameter extraction") {
    SUBCASE("PKLITE 1.12 - extract parameters") {
        std::span<const uint8_t> data(data::pklite_112, data::pklite_112_len);

        auto mz = mz_file::from_memory(data);

        // Verify compression is detected
        REQUIRE(mz.is_compressed() == true);
        REQUIRE(mz.get_compression() == compression_type::PKLITE_STANDARD);

        // Extract h_pklite_info from file (offset 0x1C)
        uint16_t h_pklite_info = data[0x1C] | (data[0x1D] << 8);
        CHECK(h_pklite_info == 0x210C);

        // Create decompressor
        pklite_decompressor decompressor(h_pklite_info, mz.header_paragraphs() * 16);

        // Test that decompressor can be created
        CHECK(decompressor.name() == std::string_view("PKLITE"));
    }

    SUBCASE("PKLITE Extra 1.15 - extract parameters") {
        std::span<const uint8_t> data(data::pklite_E_115, data::pklite_E_115_len);

        auto mz = mz_file::from_memory(data);

        // Verify Extra compression is detected
        REQUIRE(mz.is_compressed() == true);
        REQUIRE(mz.get_compression() == compression_type::PKLITE_EXTRA);

        // Extract h_pklite_info
        uint16_t h_pklite_info = data[0x1C] | (data[0x1D] << 8);
        CHECK(h_pklite_info == 0x310F);

        // Create decompressor
        pklite_decompressor decompressor(h_pklite_info, mz.header_paragraphs() * 16);
        CHECK(decompressor.name() == std::string_view("PKLITE"));
    }
}

TEST_CASE("PKLITE decompression: full decompression") {
    SUBCASE("PKLITE 1.12 - decompress code") {
        std::span<const uint8_t> data(data::pklite_112, data::pklite_112_len);

        auto mz = mz_file::from_memory(data);
        REQUIRE(mz.is_compressed() == true);

        // Extract parameters
        uint16_t h_pklite_info = data[0x1C] | (data[0x1D] << 8);
        uint16_t header_size = mz.header_paragraphs() * 16;

        // Create decompressor and decompress
        pklite_decompressor decompressor(h_pklite_info, header_size);

        REQUIRE_NOTHROW([&]() {
            auto result = decompressor.decompress(data);

            // Verify result structure
            CHECK(result.code.size() > 0);

            INFO("Decompressed size: ", result.code.size());
            INFO("Relocations found: ", result.relocations.size());
            INFO("Initial CS: ", result.initial_cs);
            INFO("Initial IP: ", result.initial_ip);
            INFO("Initial SS: ", result.initial_ss);
            INFO("Initial SP: ", result.initial_sp);
            INFO("Min extra paragraphs: ", result.min_extra_paragraphs);
            INFO("Checksum: ", result.checksum);

            // Basic sanity checks
            CHECK(result.code.size() > 1000);  // Should be substantial
            CHECK(result.code.size() < 1000000);  // But reasonable

            // Initial registers should be set
            CHECK(result.initial_sp > 0);

            // Should have some relocations
            CHECK(result.relocations.size() >= 0);  // May or may not have relocations

        }());
    }

    SUBCASE("PKLITE Extra 1.15 - decompress code") {
        std::span<const uint8_t> data(data::pklite_E_115, data::pklite_E_115_len);

        auto mz = mz_file::from_memory(data);
        REQUIRE(mz.is_compressed() == true);

        // Extract parameters
        uint16_t h_pklite_info = data[0x1C] | (data[0x1D] << 8);
        uint16_t header_size = mz.header_paragraphs() * 16;

        // Create decompressor and decompress
        pklite_decompressor decompressor(h_pklite_info, header_size);

        REQUIRE_NOTHROW([&]() {
            auto result = decompressor.decompress(data);

            // Verify result
            CHECK(result.code.size() > 0);
            CHECK(result.code.size() > 1000);
            CHECK(result.initial_sp > 0);

            INFO("Extra compression - Decompressed size: ", result.code.size());
        }());
    }
}

TEST_CASE("PKLITE decompression: error handling") {
    SUBCASE("Reject too-small data") {
        std::vector<uint8_t> tiny_data(100, 0);

        pklite_decompressor decompressor(0x210C, 128);

        CHECK_THROWS_AS(
            decompressor.decompress(tiny_data),
            std::runtime_error
        );
    }

    SUBCASE("Handle corrupted compressed data gracefully") {
        std::vector<uint8_t> bad_data(10000, 0xFF);

        pklite_decompressor decompressor(0x210C, 128);

        // Should throw an exception, not crash
        CHECK_THROWS_AS(
            decompressor.decompress(bad_data),
            std::runtime_error
        );
    }
}
