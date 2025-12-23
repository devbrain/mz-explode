// libexe - Modern executable file analysis library
// DIET decompressor - supports versions 1.00 through 1.45f

#ifndef LIBEXE_DECOMPRESSORS_DIET_HPP
#define LIBEXE_DECOMPRESSORS_DIET_HPP

#include <libexe/decompressors/decompressor.hpp>
#include <cstdint>
#include <span>

// Disable MSVC warning C4251: 'member': class 'std::...' needs to have dll-interface
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

namespace libexe {

/**
 * @brief DIET format version enumeration.
 *
 * DIET (by Teddy Matsumoto) went through several versions:
 * - v1.00, 1.00d: Early formats with different header structure
 * - v1.02b, 1.10a, 1.20: Intermediate versions with "dlz" signature
 * - v1.44, 1.45f: Later versions with improved compression
 */
enum class diet_version {
    V100,   ///< v1.00/1.00d format
    V102,   ///< v1.02b/1.10a/1.20 format
    V144,   ///< v1.44 format
    V145F   ///< v1.45f format
};

/**
 * @brief DIET file type enumeration.
 */
enum class diet_file_type {
    DATA,   ///< Data file (not executable)
    COM,    ///< DOS COM file
    EXE     ///< DOS EXE file
};

/**
 * @brief DIET decompressor implementation.
 *
 * DIET uses a custom LZ77-variant algorithm with an 8KB sliding window.
 * The compressed data uses a bit-stream with variable-length codes for
 * literals, match lengths, and match positions.
 *
 * Key algorithm characteristics:
 * - 8KB (8192 byte) sliding window/ring buffer
 * - LSB-first bit reading
 * - Variable-length match encoding
 * - Special "segment refresh" codes for EXE files
 * - CRC-16 checksum on compressed data
 *
 * @par Supported Formats:
 * - EXE files compressed with DIET 1.00 through 1.45f
 * - COM files compressed with DIET
 * - Data files compressed with DIET
 */
class LIBEXE_EXPORT diet_decompressor final : public decompressor {
public:
    /**
     * @brief Construct a DIET decompressor.
     * @param version DIET version detected in the file.
     * @param file_type Type of file (EXE, COM, or DATA).
     * @param header_size Size of MZ header in bytes (for EXE files).
     */
    explicit diet_decompressor(diet_version version, diet_file_type file_type,
                               uint16_t header_size);

    decompression_result decompress(std::span<const uint8_t> compressed_data) override;
    [[nodiscard]] const char* name() const override { return "DIET"; }

    /**
     * @brief Detect DIET compression and return format details.
     *
     * @param data File data to analyze.
     * @param[out] version Detected DIET version.
     * @param[out] file_type Detected file type.
     * @param[out] cmpr_pos Position of compressed data.
     * @param[out] crc_pos Position of CRC-16 checksum.
     * @return true if DIET compression detected, false otherwise.
     */
    static bool detect(std::span<const uint8_t> data,
                       diet_version& version,
                       diet_file_type& file_type,
                       size_t& cmpr_pos,
                       size_t& crc_pos);

private:
    struct diet_params {
        size_t cmpr_pos = 0;        ///< Position of compressed data
        size_t cmpr_len = 0;        ///< Length of compressed data
        size_t orig_len = 0;        ///< Original decompressed length
        size_t crc_pos = 0;         ///< Position of CRC-16 checksum
        size_t dlz_pos = 0;         ///< Position of "dlz" signature (if present)
        uint8_t hdr_flags1 = 0;     ///< Header flags byte 1
        uint8_t hdr_flags2 = 0;     ///< Header flags byte 2
        uint16_t crc_reported = 0;  ///< Reported CRC-16 value
        bool has_dlz_sig = false;   ///< Whether "dlz" signature is present
        bool is_com2exe = false;    ///< COM file converted to EXE
    };

    diet_params read_parameters(std::span<const uint8_t> data) const;
    std::vector<uint8_t> decompress_lz77(std::span<const uint8_t> data,
                                          const diet_params& params) const;
    void reconstruct_exe(std::span<const uint8_t> original_data,
                         std::span<const uint8_t> decompressed,
                         const diet_params& params,
                         decompression_result& result) const;

    diet_version version_;
    diet_file_type file_type_;
};

} // namespace libexe

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // LIBEXE_DECOMPRESSORS_DIET_HPP
