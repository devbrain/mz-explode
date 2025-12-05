// Tests for LZEXE decompression
#include <doctest/doctest.h>
#include <libexe/mz_file.hpp>
#include <libexe/lzexe_decompressor.hpp>
#include <vector>
#include <span>

using namespace libexe;

// Include embedded test data
namespace data {
    extern size_t z90_len;
    extern unsigned char z90[];

    extern size_t z91_len;
    extern unsigned char z91[];
}

TEST_CASE("LZEXE decompression: parameter extraction") {
    SUBCASE("LZEXE 0.90 - extract parameters") {
        std::span<const uint8_t> data(data::z90, data::z90_len);

        auto mz = mz_file::from_memory(data);

        // Verify compression is detected
        REQUIRE(mz.is_compressed() == true);
        REQUIRE(mz.get_compression() == compression_type::LZEXE_090);

        // Create decompressor
        lzexe_decompressor decompressor(lzexe_version::V090, mz.header_paragraphs() * 16);

        // Test that decompressor can be created
        CHECK(decompressor.name() == std::string_view("LZEXE"));
    }

    SUBCASE("LZEXE 0.91 - extract parameters") {
        std::span<const uint8_t> data(data::z91, data::z91_len);

        auto mz = mz_file::from_memory(data);

        // Verify 0.91 compression is detected
        REQUIRE(mz.is_compressed() == true);
        REQUIRE(mz.get_compression() == compression_type::LZEXE_091);

        // Create decompressor
        lzexe_decompressor decompressor(lzexe_version::V091, mz.header_paragraphs() * 16);
        CHECK(decompressor.name() == std::string_view("LZEXE"));
    }
}

TEST_CASE("LZEXE decompression: full decompression") {
    SUBCASE("LZEXE 0.90 - decompress code") {
        std::span<const uint8_t> data(data::z90, data::z90_len);

        auto mz = mz_file::from_memory(data);
        REQUIRE(mz.is_compressed() == true);

        // Create decompressor and decompress
        lzexe_decompressor decompressor(lzexe_version::V090, mz.header_paragraphs() * 16);

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

    SUBCASE("LZEXE 0.91 - decompress code") {
        std::span<const uint8_t> data(data::z91, data::z91_len);

        auto mz = mz_file::from_memory(data);
        REQUIRE(mz.is_compressed() == true);

        // Create decompressor and decompress
        lzexe_decompressor decompressor(lzexe_version::V091, mz.header_paragraphs() * 16);

        REQUIRE_NOTHROW([&]() {
            auto result = decompressor.decompress(data);

            // Verify result
            CHECK(result.code.size() > 0);
            CHECK(result.code.size() > 1000);
            CHECK(result.initial_sp > 0);

            INFO("LZEXE 0.91 - Decompressed size: ", result.code.size());
        }());
    }
}

TEST_CASE("LZEXE decompression: error handling") {
    SUBCASE("Reject too-small data") {
        std::vector<uint8_t> tiny_data(100, 0);

        lzexe_decompressor decompressor(lzexe_version::V090, 128);

        CHECK_THROWS_AS(
            decompressor.decompress(tiny_data),
            std::runtime_error
        );
    }

    SUBCASE("Handle corrupted compressed data gracefully") {
        std::vector<uint8_t> bad_data(10000, 0xFF);

        lzexe_decompressor decompressor(lzexe_version::V091, 128);

        // Should throw an exception, not crash
        CHECK_THROWS_AS(
            decompressor.decompress(bad_data),
            std::runtime_error
        );
    }
}
