// Equivalence test: EXEPACK decompressor vs reference implementation
// Follows exepack-1.4.0 test logic: allows up to 15 bytes of zero padding
#include <doctest/doctest.h>
#include <libexe/formats/mz_file.hpp>
#include <libexe/decompressors/exepack.hpp>
#include <string>
#include <algorithm>

using namespace libexe;

// Forward declaration of test data
namespace data {
    extern size_t exepack_hello_len;
    extern unsigned char exepack_hello[];

    extern size_t exepack_masm400_len;
    extern unsigned char exepack_masm400[];

    extern size_t exepack_masm500_len;
    extern unsigned char exepack_masm500[];

    extern size_t exepack_masm510_len;
    extern unsigned char exepack_masm510[];
}

// Reference output from exepack-1.4.0 tests/hello.exe (embedded)
static std::vector<uint8_t> read_reference_file() {
    return std::vector<uint8_t>(
        data::exepack_hello,
        data::exepack_hello + data::exepack_hello_len
    );
}

// Equivalence check following exepack-1.4.0 test logic
// Allows up to 15 bytes of zero padding at the end
static void assert_files_equivalent(
    const std::vector<uint8_t>& expected_file,
    const std::vector<uint8_t>& actual_file,
    const char* test_name
) {
    // Parse both MZ files to compare code sections
    uint16_t expected_header_paras = expected_file[0x08] | (expected_file[0x09] << 8);
    size_t expected_header_size = expected_header_paras * 16;
    std::vector<uint8_t> expected_code(
        expected_file.begin() + expected_header_size,
        expected_file.end()
    );

    uint16_t actual_header_paras = actual_file[0x08] | (actual_file[0x09] << 8);
    size_t actual_header_size = actual_header_paras * 16;
    std::vector<uint8_t> actual_code(
        actual_file.begin() + actual_header_size,
        actual_file.end()
    );

    // Ensure expected is the shorter one
    if (actual_code.size() < expected_code.size()) {
        std::swap(expected_code, actual_code);
    }

    // Check size difference (must be <= 15 bytes)
    size_t diff = actual_code.size() - expected_code.size();
    REQUIRE(diff <= 15);

    // Check that first N bytes are identical (where N = shorter length)
    bool match = std::equal(expected_code.begin(), expected_code.end(), actual_code.begin());
    REQUIRE(match);

    // Check that padding bytes are all zeros
    for (size_t i = expected_code.size(); i < actual_code.size(); i++) {
        REQUIRE(actual_code[i] == 0x00);
    }

    // Check that other header fields match
    CHECK(expected_file[0x16] == actual_file[0x16]);  // e_cs
    CHECK(expected_file[0x17] == actual_file[0x17]);
    CHECK(expected_file[0x14] == actual_file[0x14]);  // e_ip
    CHECK(expected_file[0x15] == actual_file[0x15]);
    CHECK(expected_file[0x0E] == actual_file[0x0E]);  // e_ss
    CHECK(expected_file[0x0F] == actual_file[0x0F]);
    CHECK(expected_file[0x10] == actual_file[0x10]);  // e_sp
    CHECK(expected_file[0x11] == actual_file[0x11]);
}

// Build complete MZ file from decompression result (matching legacy format)
static std::vector<uint8_t> build_exe_file(const decompression_result& result) {
    std::vector<uint8_t> output;

    // Calculate header size
    uint16_t header_size_para;
    if (result.header_paragraphs > 0) {
        // Use preserved header size (for EXEPACK)
        header_size_para = result.header_paragraphs;
    } else {
        // Calculate from relocations (standard MZ calculation)
        size_t hsize = 28 + result.relocations.size() * 4;
        header_size_para = static_cast<uint16_t>((hsize + 15) / 16);
    }
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
    header[6] = result.max_extra_paragraphs;
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
        // Write offset first, then segment
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

// Helper to decompress and build EXE file
static std::vector<uint8_t> decompress_to_exe(
    const unsigned char* compressed_data,
    size_t compressed_size,
    const char* test_name
) {
    // Parse MZ file
    std::span<const uint8_t> data(compressed_data, compressed_size);
    auto mz = mz_file::from_memory(data);

    // Verify compression type
    auto compression = mz.get_compression();
    REQUIRE(compression == compression_type::EXEPACK);

    // Decompress
    exepack_decompressor decompressor(mz.header_paragraphs() * 16);
    auto result = decompressor.decompress(data);
    REQUIRE(result.code.size() > 0);

    // Build complete EXE file
    return build_exe_file(result);
}

TEST_CASE("EXEPACK equivalence test against reference implementation") {
    // Load reference file once
    auto expected = read_reference_file();

    SUBCASE("EXEPACK MASM 4.00 produces equivalent output") {
        auto actual = decompress_to_exe(
            data::exepack_masm400,
            data::exepack_masm400_len,
            "MASM 4.00"
        );
        assert_files_equivalent(expected, actual, "MASM 4.00");
    }

    SUBCASE("EXEPACK MASM 5.00 produces equivalent output") {
        auto actual = decompress_to_exe(
            data::exepack_masm500,
            data::exepack_masm500_len,
            "MASM 5.00"
        );
        assert_files_equivalent(expected, actual, "MASM 5.00");
    }

    SUBCASE("EXEPACK MASM 5.10 produces equivalent output") {
        auto actual = decompress_to_exe(
            data::exepack_masm510,
            data::exepack_masm510_len,
            "MASM 5.10"
        );
        assert_files_equivalent(expected, actual, "MASM 5.10");
    }
}
