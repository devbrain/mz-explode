// libexe - Modern executable file analysis library
// LZEXE decompressor - supports 0.90 and 0.91 formats

#ifndef LIBEXE_DECOMPRESSORS_LZEXE_HPP
#define LIBEXE_DECOMPRESSORS_LZEXE_HPP

#include <libexe/decompressors/decompressor.hpp>
#include <cstdint>
#include <span>

// Disable MSVC warning C4251: 'member': class 'std::...' needs to have dll-interface
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

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

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // LIBEXE_DECOMPRESSORS_LZEXE_HPP
