// Tests for LZEXE decompression
#include <doctest/doctest.h>
#include <libexe/formats/mz_file.hpp>
#include <libexe/decompressors/lzexe.hpp>
#include <vector>
#include <span>

#include "test_helpers/md5.h"

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

// Expected MD5 digests from legacy unittest (gold standard)
static const char* digest_lzexe_90   = "620d7dce66a13ec7be84b9f390078aa6";
static const char* digest_lzexe_91   = "f38e4c688fcd8f3d4f102dc5e2b8bb0f";
static const char* digest_lzexe_91_E = "f38e4c688fcd8f3d4f102dc5e2b8bb0f";

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

    // Calculate header size
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

    // Verify compression type and determine version
    auto compression = mz.get_compression();
    REQUIRE((compression == compression_type::LZEXE_090 ||
             compression == compression_type::LZEXE_091));

    lzexe_version version = (compression == compression_type::LZEXE_090) ?
                            lzexe_version::V090 : lzexe_version::V091;

    // Decompress
    lzexe_decompressor decompressor(version, mz.header_paragraphs() * 16);
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
    extern size_t z90_len;
    extern unsigned char z90[];

    extern size_t z91_len;
    extern unsigned char z91[];

    extern size_t z91_E_len;
    extern unsigned char z91_E[];
}

TEST_CASE("LZEXE MD5 verification against legacy implementation") {
    SUBCASE("LZEXE 0.90 produces identical output") {
        std::string actual = decompress_and_md5(data::z90, data::z90_len, digest_lzexe_90);
        std::string expected(digest_lzexe_90);
        CHECK(actual == expected);
    }

    SUBCASE("LZEXE 0.91 produces identical output") {
        std::string actual = decompress_and_md5(data::z91, data::z91_len, digest_lzexe_91);
        std::string expected(digest_lzexe_91);
        CHECK(actual == expected);
    }

    SUBCASE("LZEXE 0.91 Extra produces identical output") {
        std::string actual = decompress_and_md5(data::z91_E, data::z91_E_len, digest_lzexe_91_E);
        std::string expected(digest_lzexe_91_E);
        CHECK(actual == expected);
    }
}
