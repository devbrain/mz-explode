// LZEXE decompressor - Modern C++20 implementation
// Supports LZEXE 0.90 and 0.91 compression formats

#ifndef LIBEXE_LZEXE_DECOMPRESSOR_HPP
#define LIBEXE_LZEXE_DECOMPRESSOR_HPP

#include <libexe/export.hpp>
#include <libexe/decompressor.hpp>
#include <cstdint>
#include <span>

namespace libexe {

enum class lzexe_version {
    V090,
    V091
};

class LIBEXE_EXPORT lzexe_decompressor final : public decompressor {
public:
    explicit lzexe_decompressor(lzexe_version version, uint16_t header_size);

    decompression_result decompress(std::span<const uint8_t> compressed_data) override;
    [[nodiscard]] const char* name() const override { return "LZEXE"; }

private:
    struct lzexe_params {
        uint16_t initial_ip;
        uint16_t initial_cs;
        uint16_t initial_sp;
        uint16_t initial_ss;
        uint16_t compressed_size;
        uint16_t inc_size;
        uint16_t decompressor_size;
        uint16_t checksum;
        uint32_t reloc_offset;
        uint32_t code_offset;
    };

    lzexe_params read_parameters(std::span<const uint8_t> data) const;
    void parse_relocations_v090(std::span<const uint8_t> data, uint32_t offset,
                                decompression_result& result);
    void parse_relocations_v091(std::span<const uint8_t> data, uint32_t offset,
                                decompression_result& result);

    lzexe_version version_;
    uint16_t header_size_;
};

} // namespace libexe

#endif // LIBEXE_LZEXE_DECOMPRESSOR_HPP
