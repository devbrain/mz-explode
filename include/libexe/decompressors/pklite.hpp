// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_DECOMPRESSORS_PKLITE_HPP
#define LIBEXE_DECOMPRESSORS_PKLITE_HPP

#include <libexe/decompressors/decompressor.hpp>
#include <cstdint>
#include <array>

namespace libexe {

/// PKLITE intro class - identifies the version/variant from entry point code
enum class pklite_intro_class : uint8_t {
    UNKNOWN = 0,
    BETA = 8,           // v1.00 beta (data before decoder)
    BETA_LH = 9,        // v1.00 beta load-high
    V100 = 10,          // v1.00
    V112 = 12,          // v1.03-1.12
    V114 = 14,          // v1.14-1.15
    V150 = 50,          // v1.50-2.01
    UN2PACK = 100,      // UN2PACK variant
    MEGALITE = 101      // MEGALITE variant
};

/// PKLITE descrambler class - for encrypted decompressor stubs
enum class pklite_descrambler_class : uint8_t {
    NONE = 0,
    V114 = 14,
    V150 = 50,
    V150_IBM = 51,
    V120_VAR1A = 101,
    V120_VAR1B = 102,
    V120_VAR2 = 103,
    PKZIP204C_LIKE = 105,
    PKLITE201_LIKE = 110,
    CHK4LITE201_LIKE = 111
};

/// PKLITE decompressor class - identifies main decompression routine variant
enum class pklite_decompr_class : uint8_t {
    UNKNOWN = 0,
    COMMON = 1,         // Standard decompressor (most versions)
    BETA = 9,           // Beta version
    V115 = 15,          // v1.15 variant (16-bit offset)
    V120_SMALL_OLD = 50,
    V120_SMALL = 51
};

/// PKLITE copier class - identifies the copier routine variant
enum class pklite_copier_class : uint8_t {
    UNKNOWN = 0,
    COMMON = 1,
    V150_SCR = 2,
    V120_VAR1_SMALL = 10,
    PKLITE201_LIKE = 20,
    UN2PACK = 100,
    MEGALITE = 101,
    OTHER = 200
};

/// Scramble method for encrypted decompressor stubs
enum class pklite_scramble_method : uint8_t {
    NONE = 0,
    XOR = 1,
    ADD = 2
};

/// PKLITE decompressor for DOS executables
/// Uses pattern-based detection like deark for reliable version identification
class LIBEXE_EXPORT pklite_decompressor final : public decompressor {
public:
    /// Construct from raw file data (pattern-based detection)
    explicit pklite_decompressor(std::span<const uint8_t> file_data, uint16_t header_paragraphs);

    decompression_result decompress(std::span<const uint8_t> compressed_data) override;
    [[nodiscard]] const char* name() const override { return "PKLITE"; }

    /// Get detected intro class
    [[nodiscard]] pklite_intro_class get_intro_class() const { return intro_class_; }

    /// Check if decompressor stub is scrambled
    [[nodiscard]] bool is_scrambled() const { return scrambled_decompressor_; }

    /// Check if v1.20 compression is used
    [[nodiscard]] bool is_v120_compression() const { return v120_cmpr_; }

    /// Check if large compression model is used
    [[nodiscard]] bool is_large_compression() const { return large_cmpr_; }

private:
    // Decompression parameters (determined by pattern analysis)
    struct decompr_params {
        size_t cmpr_data_pos = 0;   // Absolute position of compressed data
        uint8_t extra_cmpr = 0;     // 0=no, 1=XOR with bit count, 2=XOR with 0xFF
        bool large_cmpr = false;    // Large compression model
        bool v120_cmpr = false;     // v1.20 special compression
        uint8_t offset_xor_key = 0; // XOR key for obfuscated offsets (v1.20)
    };

    // Pattern matching helpers
    static bool mem_match(const uint8_t* mem, const uint8_t* pattern, size_t len, uint8_t wildcard);
    static bool search_match(const uint8_t* mem, size_t mem_len,
                            size_t start, size_t end,
                            const uint8_t* pattern, size_t pattern_len,
                            uint8_t wildcard, size_t* found_pos);

    // Analysis stages (following deark's approach)
    void analyze_file();
    void analyze_intro();
    void analyze_descrambler();
    void descramble_decompressor();
    void analyze_copier();
    void analyze_decompressor();
    void analyze_detect_extra_cmpr();
    void analyze_detect_large_and_v120_cmpr();
    void analyze_detect_obf_offsets();

    // Decompression helpers
    void do_decompress(decompression_result& result);
    void read_reloc_table_short(decompression_result& result, size_t start_pos);
    void read_reloc_table_long(decompression_result& result, size_t start_pos);
    uint16_t calculate_min_mem(size_t code_size);

    // Huffman tree helpers
    struct huffman_entry {
        uint8_t bits;
        uint16_t code;
    };

    // Input data
    std::span<const uint8_t> file_data_;
    size_t header_size_;
    size_t entry_point_;
    size_t start_of_dos_code_;
    size_t end_of_dos_code_;

    // Entry point bytes (up to 1000 bytes for pattern matching)
    static constexpr size_t EPBYTES_LEN = 1000;
    std::array<uint8_t, EPBYTES_LEN> epbytes_{};
    size_t epbytes_valid_ = 0;

    // Analysis results
    pklite_intro_class intro_class_ = pklite_intro_class::UNKNOWN;
    pklite_descrambler_class descrambler_class_ = pklite_descrambler_class::NONE;
    pklite_copier_class copier_class_ = pklite_copier_class::UNKNOWN;
    pklite_decompr_class decompr_class_ = pklite_decompr_class::UNKNOWN;

    bool data_before_decoder_ = false;
    bool load_high_ = false;
    bool scrambled_decompressor_ = false;
    pklite_scramble_method scramble_method_ = pklite_scramble_method::NONE;

    uint16_t initial_key_ = 0;
    size_t position2_ = 0;          // Position after intro
    size_t copier_pos_ = 0;
    size_t decompr_pos_ = 0;
    size_t approx_end_of_decompressor_ = 0;

    // Scrambler state
    size_t scrambled_word_count_ = 0;
    size_t pos_of_last_scrambled_word_ = 0;

    // Final decompression parameters
    decompr_params dparams_;

    // Compression flags
    bool large_cmpr_ = false;
    bool v120_cmpr_ = false;
    uint8_t extra_cmpr_ = 0;

    // Error state
    bool error_ = false;

    // Position tracking for relocation table and footer
    size_t cmpr_data_endpos_ = 0;
    size_t reloc_tbl_endpos_ = 0;
};

} // namespace libexe

#endif // LIBEXE_DECOMPRESSORS_PKLITE_HPP
