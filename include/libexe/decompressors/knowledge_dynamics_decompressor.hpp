// Knowledge Dynamics decompressor - Modern C++20 implementation
// Uses LZW (Lempel-Ziv-Welch) dictionary-based compression

#ifndef LIBEXE_KNOWLEDGE_DYNAMICS_DECOMPRESSOR_HPP
#define LIBEXE_KNOWLEDGE_DYNAMICS_DECOMPRESSOR_HPP

#include <libexe/export.hpp>
#include <libexe/decompressor.hpp>
#include <span>

namespace libexe {

class LIBEXE_EXPORT knowledge_dynamics_decompressor final : public decompressor {
public:
    explicit knowledge_dynamics_decompressor(uint16_t header_size);

    decompression_result decompress(std::span<const uint8_t> compressed_data) override;
    [[nodiscard]] const char* name() const override { return "Knowledge Dynamics"; }

private:
    struct kd_params {
        uint32_t expected_size;
        uint32_t code_offset;
        uint16_t initial_cs;
        uint16_t initial_ip;
        uint16_t initial_ss;
        uint16_t initial_sp;
        uint16_t checksum;
        uint16_t max_mem_para;
        uint16_t min_mem_para;
        uint32_t relocation_offset;
        uint16_t num_relocations;
    };

    static kd_params read_parameters(std::span<const uint8_t> data);

    uint16_t header_size_;
};

} // namespace libexe

#endif // LIBEXE_KNOWLEDGE_DYNAMICS_DECOMPRESSOR_HPP
