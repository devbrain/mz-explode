// Tests for Knowledge Dynamics decompression
#include <doctest/doctest.h>
#include <libexe/mz_file.hpp>
#include <libexe/knowledge_dynamics_decompressor.hpp>
#include <vector>
#include <span>

using namespace libexe;

// Include embedded test data
namespace data {
    extern size_t knowledge_dynamics_DOT_len;
    extern unsigned char knowledge_dynamics_DOT[];
}

TEST_CASE("Knowledge Dynamics decompression: parameter extraction") {
    SUBCASE("Knowledge Dynamics DOT - extract parameters") {
        std::span<const uint8_t> data(data::knowledge_dynamics_DOT,
                                     data::knowledge_dynamics_DOT_len);

        auto mz = mz_file::from_memory(data);

        // Verify compression is detected
        REQUIRE(mz.is_compressed() == true);
        REQUIRE(mz.get_compression() == compression_type::KNOWLEDGE_DYNAMICS);

        // Create decompressor
        knowledge_dynamics_decompressor decompressor(mz.header_paragraphs() * 16);

        // Test that decompressor can be created
        CHECK(decompressor.name() == std::string_view("Knowledge Dynamics"));
    }
}

TEST_CASE("Knowledge Dynamics decompression: full decompression") {
    SUBCASE("Knowledge Dynamics DOT - decompress code") {
        std::span<const uint8_t> data(data::knowledge_dynamics_DOT,
                                     data::knowledge_dynamics_DOT_len);

        auto mz = mz_file::from_memory(data);
        REQUIRE(mz.is_compressed() == true);

        // Create decompressor and decompress
        knowledge_dynamics_decompressor decompressor(mz.header_paragraphs() * 16);

        REQUIRE_NOTHROW([&]() {
            auto result = decompressor.decompress(data);

            // Verify result structure
            CHECK(result.code.size() > 0);

            INFO("Decompressed size: ", result.code.size());
            INFO("Initial CS: ", result.initial_cs);
            INFO("Initial IP: ", result.initial_ip);
            INFO("Initial SS: ", result.initial_ss);
            INFO("Initial SP: ", result.initial_sp);
            INFO("Min extra paragraphs: ", result.min_extra_paragraphs);

            // Basic sanity checks
            CHECK(result.code.size() > 1000);  // Should be substantial
            CHECK(result.code.size() < 1000000);  // But reasonable

            // Initial registers should be set
            CHECK(result.initial_sp > 0);

        }());
    }
}

TEST_CASE("Knowledge Dynamics decompression: error handling") {
    SUBCASE("Reject too-small data") {
        std::vector<uint8_t> tiny_data(100, 0);

        knowledge_dynamics_decompressor decompressor(128);

        CHECK_THROWS_AS(
            decompressor.decompress(tiny_data),
            std::runtime_error
        );
    }

    SUBCASE("Handle corrupted compressed data gracefully") {
        std::vector<uint8_t> bad_data(10000, 0xFF);

        knowledge_dynamics_decompressor decompressor(128);

        // Should throw an exception, not crash
        CHECK_THROWS_AS(
            decompressor.decompress(bad_data),
            std::runtime_error
        );
    }
}
