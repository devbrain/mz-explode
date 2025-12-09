// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_DECOMPRESSORS_PKLITE_HPP
#define LIBEXE_DECOMPRESSORS_PKLITE_HPP

#include <libexe/decompressors/decompressor.hpp>
#include <cstdint>

namespace libexe {
    /// PKLITE decompressor for DOS executables
    class LIBEXE_EXPORT pklite_decompressor final : public decompressor {
        public:
            explicit pklite_decompressor(uint16_t h_pklite_info, uint16_t header_size);

            decompression_result decompress(std::span <const uint8_t> compressed_data) override;
            [[nodiscard]] const char* name() const override { return "PKLITE"; }

        private:
            struct pklite_params {
                uint32_t decomp_size;
                uint32_t compressed_size;
                uint32_t decompressor_size;
                uint32_t data_offset;
                bool uncompressed_region;
                bool has_checksum;
                bool use_xor;
                bool large_compression;
            };

            [[nodiscard]] pklite_params read_parameters(std::span <const uint8_t> data) const;

            uint16_t h_pklite_info_;
            uint16_t header_size_;
    };
} // namespace libexe

#endif // LIBEXE_DECOMPRESSORS_PKLITE_HPP
