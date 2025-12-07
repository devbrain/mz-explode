// EXEPACK decompressor - Modern C++20 implementation
// Based on exepack-1.4.0 by David Fifield (https://www.bamsoftware.com/software/exepack/)
// Algorithm: Backward decompression with FILL and COPY commands

#ifndef LIBEXE_EXEPACK_DECOMPRESSOR_HPP
#define LIBEXE_EXEPACK_DECOMPRESSOR_HPP

#include <libexe/export.hpp>
#include <libexe/decompressor.hpp>
#include <cstdint>
#include <span>

namespace libexe {

class LIBEXE_EXPORT exepack_decompressor : public decompressor {
public:
    explicit exepack_decompressor(uint16_t header_size);

    decompression_result decompress(std::span<const uint8_t> compressed_data) override;
    const char* name() const override { return "EXEPACK"; }

private:
    struct exepack_header {
        uint16_t real_ip;
        uint16_t real_cs;
        uint16_t mem_start;     // Scratch space for decompressor (ignored)
        uint16_t exepack_size;
        uint16_t real_sp;
        uint16_t real_ss;
        uint16_t dest_len;      // Destination length in paragraphs
        uint16_t skip_len;      // Skip length (1 = 0 paragraphs padding)
        uint16_t signature;     // Must be 0x4252 (0x52 0x42 = "RB")
    };

    struct exepack_params {
        exepack_header header;
        uint32_t exepack_header_offset;
        size_t exepack_header_len;
        size_t compressed_len;
        size_t uncompressed_len;
    };

    exepack_params read_parameters(std::span<const uint8_t> data);

    // Core decompression algorithm - works backwards
    void decompress_data(std::vector<uint8_t>& buf, size_t compressed_len, size_t uncompressed_len);

    // Skip up to 15 bytes of 0xff padding
    static size_t unpad(std::span<const uint8_t> buf, size_t pos);

    uint16_t header_size_;
};

} // namespace libexe

#endif // LIBEXE_EXEPACK_DECOMPRESSOR_HPP
