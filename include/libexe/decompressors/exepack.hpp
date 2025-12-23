// libexe - Modern executable file analysis library
// EXEPACK decompressor - backward decompression with FILL and COPY commands

#ifndef LIBEXE_DECOMPRESSORS_EXEPACK_HPP
#define LIBEXE_DECOMPRESSORS_EXEPACK_HPP

#include <libexe/decompressors/decompressor.hpp>
#include <cstdint>
#include <span>

namespace libexe {

class LIBEXE_EXPORT exepack_decompressor final : public decompressor {
public:
    explicit exepack_decompressor(uint16_t header_size);

    decompression_result decompress(std::span<const uint8_t> compressed_data) override;
    [[nodiscard]] const char* name() const override { return "EXEPACK"; }

private:
    struct exepack_header {
        uint16_t real_ip;
        uint16_t real_cs;
        uint16_t mem_start;
        uint16_t exepack_size;
        uint16_t real_sp;
        uint16_t real_ss;
        uint16_t dest_len;
        uint16_t skip_len;
        uint16_t signature;
    };

    struct exepack_params {
        exepack_header header;
        uint32_t exepack_header_offset;
        size_t exepack_header_len;
        size_t compressed_len;
        size_t uncompressed_len;
    };

    static exepack_params read_parameters(std::span<const uint8_t> data);
    static void decompress_data(std::vector<uint8_t>& buf, size_t compressed_len, size_t uncompressed_len);
    static size_t unpad(std::span<const uint8_t> buf, size_t pos);
    static size_t locate_stub_end(std::span<const uint8_t> stub);
    static std::vector<std::pair<uint16_t, uint16_t>>
        parse_packed_relocations(std::span<const uint8_t> reloc_data);
};

} // namespace libexe

#endif // LIBEXE_DECOMPRESSORS_EXEPACK_HPP
