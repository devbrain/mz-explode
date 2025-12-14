// Tests for PKLITE decompression
#include <doctest/doctest.h>
#include <libexe/formats/mz_file.hpp>
#include <libexe/decompressors/pklite.hpp>
#include <vector>
#include <span>
#include "test_helpers/md5.h"
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
        std::span<const uint8_t> input(data::pklite_112, data::pklite_112_len);

        auto mz = mz_file::from_memory(input);

        // Verify compression is detected
        REQUIRE(mz.is_compressed() == true);
        REQUIRE(mz.get_compression() == compression_type::PKLITE_STANDARD);

        // Extract h_pklite_info from file (offset 0x1C)
        uint16_t h_pklite_info = input[0x1C] | (input[0x1D] << 8);
        CHECK(h_pklite_info == 0x210C);

        // Create decompressor using pattern-based detection
        pklite_decompressor decompressor(input, mz.header_paragraphs());

        // Test that decompressor can be created
        CHECK(decompressor.name() == std::string_view("PKLITE"));
    }

    SUBCASE("PKLITE Extra 1.15 - extract parameters") {
        std::span<const uint8_t> input(data::pklite_E_115, data::pklite_E_115_len);

        auto mz = mz_file::from_memory(input);

        // Verify Extra compression is detected
        REQUIRE(mz.is_compressed() == true);
        REQUIRE(mz.get_compression() == compression_type::PKLITE_EXTRA);

        // Extract h_pklite_info
        uint16_t h_pklite_info = input[0x1C] | (input[0x1D] << 8);
        CHECK(h_pklite_info == 0x310F);

        // Create decompressor using pattern-based detection
        pklite_decompressor decompressor(input, mz.header_paragraphs());
        CHECK(decompressor.name() == std::string_view("PKLITE"));
    }
}

TEST_CASE("PKLITE decompression: full decompression") {
    SUBCASE("PKLITE 1.12 - decompress code") {
        std::span<const uint8_t> input(data::pklite_112, data::pklite_112_len);

        auto mz = mz_file::from_memory(input);
        REQUIRE(mz.is_compressed() == true);

        // Create decompressor and decompress using pattern-based detection
        pklite_decompressor decompressor(input, mz.header_paragraphs());

        REQUIRE_NOTHROW([&]() {
            auto result = decompressor.decompress(input);

            // Verify result structure
            CHECK(result.code.size() > 0);

            // Basic sanity checks
            CHECK(result.code.size() > 1000);  // Should be substantial
            CHECK(result.code.size() < 1000000);  // But reasonable

            // Initial registers should be set
            CHECK(result.initial_sp > 0);

            // Relocations may or may not be present - just verify we can access them
            // INFO shows the count, no assertion needed since it's file-dependent

        }());
    }

    SUBCASE("PKLITE Extra 1.15 - decompress code") {
        std::span<const uint8_t> input(data::pklite_E_115, data::pklite_E_115_len);

        auto mz = mz_file::from_memory(input);
        REQUIRE(mz.is_compressed() == true);

        // Create decompressor and decompress using pattern-based detection
        pklite_decompressor decompressor(input, mz.header_paragraphs());

        REQUIRE_NOTHROW([&]() {
            auto result = decompressor.decompress(input);

            // Verify result
            CHECK(result.code.size() > 0);
            CHECK(result.code.size() > 1000);
            CHECK(result.initial_sp > 0);
        }());
    }
}

TEST_CASE("PKLITE decompression: error handling") {
    SUBCASE("Reject too-small data") {
        std::vector<uint8_t> tiny_data(100, 0);
        // Add minimal MZ header
        tiny_data[0] = 'M';
        tiny_data[1] = 'Z';

        // Pattern-based detection fails for invalid data,
        // which is detected during decompress()
        pklite_decompressor decompressor(tiny_data, 2);
        CHECK_THROWS_AS(
            decompressor.decompress(tiny_data),
            std::runtime_error
        );
    }

    SUBCASE("Reject file that's too small for MZ header") {
        std::vector<uint8_t> very_tiny_data(20, 0);
        very_tiny_data[0] = 'M';
        very_tiny_data[1] = 'Z';

        // File smaller than MZ header should throw in constructor
        CHECK_THROWS_AS(
            pklite_decompressor(very_tiny_data, 1),
            std::runtime_error
        );
    }

    SUBCASE("Handle corrupted compressed data gracefully") {
        // Create corrupted data by modifying the compressed data stream
        std::vector<uint8_t> bad_data(data::pklite_112, data::pklite_112 + data::pklite_112_len);

        // Corrupt the compressed data area (after the decompressor code)
        // This should cause decompression errors like invalid Huffman codes
        // or invalid back-references
        size_t corrupt_start = 1000;  // Well into the compressed data
        std::fill(bad_data.begin() + corrupt_start, bad_data.begin() + corrupt_start + 1000, 0x00);

        // The decompressor should throw when it encounters invalid data
        pklite_decompressor decompressor(bad_data, 8);  // header_paragraphs from original file
        CHECK_THROWS_AS(
            decompressor.decompress(bad_data),
            std::runtime_error
        );
    }
}

// Include embedded test data from legacy unittest
namespace data {
    extern size_t pklite_112_len;
    extern unsigned char pklite_112[];

    extern size_t pklite_115_len;
    extern unsigned char pklite_115[];

    extern size_t pklite_E_112_len;
    extern unsigned char pklite_E_112[];

    extern size_t pklite_E_115_len;
    extern unsigned char pklite_E_115[];

    extern size_t pklite_150_len;
    extern unsigned char pklite_150[];
}

// Expected MD5 digests (pattern-based decompressor output)
static const char* digest_pklite_112   = "e1c49d3724e1a2e32145c190f2b1de91";
static const char* digest_pklite_115   = "979710b9d9a8e0959f1a1b01b11ebab6";
static const char* digest_pklite_E_112 = "0a9361ed529e0a79aca35f48b1a79e07";
static const char* digest_pklite_E_115 = "8eb7a708616c66843d51443b2231f2c7";
static const char* digest_pklite_150   = "4f15d2d239890fa482bfe8336ea83aec";

// Helper to convert MD5 digest to hex string
static std::string md5_to_string(const unsigned char* digest) {
    std::string result;
    result.reserve(32);
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", digest[i]);
        result += buf;
    }
    return result;
}

// Build complete MZ file from decompression result (matching legacy format)
static std::vector<uint8_t> build_exe_file(
    const decompression_result& result,
    uint16_t h_pklite_info)
{
    std::vector<uint8_t> output;

    // Calculate header size (legacy formula)
    uint16_t relloc_bytes = static_cast<uint16_t>(result.relocations.size() * 4);
    uint16_t par_size = (relloc_bytes + 0x1FF) & 0xFE00;
    par_size >>= 4;

    uint16_t header_size_para = par_size;
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
    header[6] = 0xFFFF;  // max mem
    header[7] = result.initial_ss;
    header[8] = result.initial_sp;
    header[9] = result.checksum;
    header[10] = result.initial_ip;
    header[11] = result.initial_cs;
    header[12] = 14 * sizeof(uint16_t) + 2;  // Reloc offset = 30
    header[13] = 0;  // Overlay

    // Write header (little-endian)
    for (int i = 0; i < 14; i++) {
        output.push_back(header[i] & 0xFF);
        output.push_back((header[i] >> 8) & 0xFF);
    }

    // Write h_pklite_info (2 bytes) - this is what makes each version differ
    output.push_back(h_pklite_info & 0xFF);
    output.push_back((h_pklite_info >> 8) & 0xFF);

    // Write relocations (pair is segment:offset)
    for (const auto& reloc : result.relocations) {
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

// Test helper that decompresses with new code and checks MD5
static void test_pklite_md5(
    const unsigned char* data, size_t len,
    const char* expected_digest,
    [[maybe_unused]] const char* test_name)
{
    std::span<const uint8_t> input(data, len);

    // Parse the compressed file
    auto mz = mz_file::from_memory(input);
    REQUIRE(mz.is_compressed());

    // Extract h_pklite_info from input file (offset 0x1C)
    uint16_t h_pklite_info = input[0x1C] | (input[0x1D] << 8);

    // Decompress using pattern-based detection
    pklite_decompressor decompressor(input, mz.header_paragraphs());
    decompression_result result = decompressor.decompress(input);

    // Build complete EXE (legacy format with h_pklite_info)
    std::vector<uint8_t> output = build_exe_file(result, h_pklite_info);

    // Compute MD5
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, output.data(), static_cast<unsigned long>(output.size()));

    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5_Final(digest, &ctx);

    std::string actual = md5_to_string(digest);

    CHECK(actual == expected_digest);
}

TEST_CASE("PKLITE decompressor: MD5 verification vs legacy") {
    SUBCASE("PKLITE 1.12 - standard compression") {
        test_pklite_md5(data::pklite_112, data::pklite_112_len,
                        digest_pklite_112, "PKLITE 1.12");
    }

    SUBCASE("PKLITE 1.15 - standard compression") {
        test_pklite_md5(data::pklite_115, data::pklite_115_len,
                        digest_pklite_115, "PKLITE 1.15");
    }

    SUBCASE("PKLITE Extra 1.12 - extra compression") {
        test_pklite_md5(data::pklite_E_112, data::pklite_E_112_len,
                        digest_pklite_E_112, "PKLITE Extra 1.12");
    }

    SUBCASE("PKLITE Extra 1.15 - extra compression") {
        test_pklite_md5(data::pklite_E_115, data::pklite_E_115_len,
                        digest_pklite_E_115, "PKLITE Extra 1.15");
    }

    SUBCASE("PKLITE 1.50 - newer version") {
        test_pklite_md5(data::pklite_150, data::pklite_150_len,
                        digest_pklite_150, "PKLITE 1.50");
    }
}
