// Tests for Knowledge Dynamics decompression
#include <doctest/doctest.h>
#include <libexe/formats/mz_file.hpp>
#include <libexe/decompressors/knowledge_dynamics.hpp>
#include "test_helpers/md5.h"
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
using namespace libexe;

// Expected MD5 digests from legacy unittest (gold standard)
static const char* digest_knowledge_dynamics_LEX = "03703e056977944b007eb2ecccf3f1c4";
static const char* digest_knowledge_dynamics_DOT = "3b1429a7224c868b4725228b1a4ffb66";
static const char* digest_knowledge_dynamics_TNT = "d813b5ac3095c24c3eba559bac22a32d";

// Helper to convert MD5 digest to hex string
static std::string md5_to_string(const unsigned char* digest) {
    std::ostringstream oss;
    for (int i = 0; i < 16; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    return oss.str();
}

// Build complete MZ file from decompression result (matching legacy format)
static std::vector<uint8_t> build_exe_file(const decompression_result& result) {
    std::vector<uint8_t> output;

    // Calculate header size (Knowledge Dynamics uses standard MZ calculation, not PKLITE's)
    // hsize = sizeof(header) + relocations_size
    // header_size_para = (hsize + 15) / 16  (round up to paragraph)
    size_t hsize = 28 + result.relocations.size() * 4;  // 28-byte header + relocations
    uint16_t header_size_para = static_cast<uint16_t>((hsize + 15) / 16);
    uint32_t code_size = static_cast<uint32_t>(result.code.size());
    uint32_t total_size = header_size_para * 16 + code_size;

    uint16_t num_pages = static_cast<uint16_t>(total_size / 512);
    uint16_t bytes_last_page = static_cast<uint16_t>(total_size % 512);
    if (bytes_last_page) {
        num_pages++;
    }

    // Build MZ header (28 bytes)
    uint16_t header[14] = {0};
    header[0] = 0x5A4D;  // MZ signature
    header[1] = bytes_last_page;
    header[2] = num_pages;
    header[3] = static_cast<uint16_t>(result.relocations.size());
    header[4] = header_size_para;
    header[5] = result.min_extra_paragraphs;
    header[6] = result.max_extra_paragraphs;  // Knowledge Dynamics preserves this
    header[7] = result.initial_ss;
    header[8] = result.initial_sp;
    header[9] = result.checksum;
    header[10] = result.initial_ip;
    header[11] = result.initial_cs;
    header[12] = 14 * sizeof(uint16_t);  // Reloc offset (after header)
    header[13] = 0;  // Overlay

    // Write header (little-endian)
    for (int i = 0; i < 14; i++) {
        output.push_back(header[i] & 0xFF);
        output.push_back((header[i] >> 8) & 0xFF);
    }

    // Write relocations (pair is segment:offset)
    for (const auto& reloc : result.relocations) {
        // Legacy writes offset first, then segment
        output.push_back(reloc.second & 0xFF);  // offset low
        output.push_back((reloc.second >> 8) & 0xFF);  // offset high
        output.push_back(reloc.first & 0xFF);  // segment low
        output.push_back((reloc.first >> 8) & 0xFF);  // segment high
    }

    // Pad to header size
    while (output.size() < static_cast<size_t>(header_size_para) * 16) {
        output.push_back(0);
    }

    // Write code
    output.insert(output.end(), result.code.begin(), result.code.end());

    return output;
}

// Helper to decompress and compute MD5
static std::string decompress_and_md5(
    const unsigned char* compressed_data,
    size_t compressed_size,
    const char* expected_digest
) {
    // Parse MZ file
    std::span<const uint8_t> data(compressed_data, compressed_size);
    auto mz = mz_file::from_memory(data);

    // Verify compression type
    auto compression = mz.get_compression();
    REQUIRE(compression == compression_type::KNOWLEDGE_DYNAMICS);

    // Decompress
    knowledge_dynamics_decompressor decompressor(mz.header_paragraphs() * 16);
    auto result = decompressor.decompress(data);
    REQUIRE(result.code.size() > 0);

    // Build complete EXE file
    std::vector<uint8_t> exe_file = build_exe_file(result);

    // Compute MD5 of complete EXE
    unsigned char digest[16];
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, exe_file.data(), exe_file.size());
    MD5_Final(digest, &ctx);

    return md5_to_string(digest);
}

// Test data declared in legacy_data_wrapper.cpp
namespace data {
    extern size_t knowledge_dynamics_LEX_len;
    extern unsigned char knowledge_dynamics_LEX[];

    extern size_t knowledge_dynamics_DOT_len;
    extern unsigned char knowledge_dynamics_DOT[];

    extern size_t knowledge_dynamics_TNT_len;
    extern unsigned char knowledge_dynamics_TNT[];
}

TEST_CASE("Knowledge Dynamics MD5 verification against legacy implementation") {
    SUBCASE("Knowledge Dynamics LEX produces identical output") {
        std::string actual = decompress_and_md5(
            data::knowledge_dynamics_LEX,
            data::knowledge_dynamics_LEX_len,
            digest_knowledge_dynamics_LEX
        );
        std::string expected(digest_knowledge_dynamics_LEX);
        CHECK(actual == expected);
    }

    SUBCASE("Knowledge Dynamics DOT produces identical output") {
        std::string actual = decompress_and_md5(
            data::knowledge_dynamics_DOT,
            data::knowledge_dynamics_DOT_len,
            digest_knowledge_dynamics_DOT
        );
        std::string expected(digest_knowledge_dynamics_DOT);
        CHECK(actual == expected);
    }

    SUBCASE("Knowledge Dynamics TNT produces identical output") {
        std::string actual = decompress_and_md5(
            data::knowledge_dynamics_TNT,
            data::knowledge_dynamics_TNT_len,
            digest_knowledge_dynamics_TNT
        );
        std::string expected(digest_knowledge_dynamics_TNT);
        CHECK(actual == expected);
    }
}
