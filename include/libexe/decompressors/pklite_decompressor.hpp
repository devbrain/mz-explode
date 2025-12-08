// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_PKLITE_DECOMPRESSOR_HPP
#define LIBEXE_PKLITE_DECOMPRESSOR_HPP

#include <libexe/decompressor.hpp>
#include <cstdint>

namespace libexe {
    /// PKLITE decompressor for DOS executables
    /// Supports PKLITE standard and extra compression
    class LIBEXE_EXPORT pklite_decompressor final : public decompressor {
        public:
            /// Create PKLITE decompressor with parameters from MZ header
            /// @param h_pklite_info PKLITE info word from offset 0x1C
            /// @param header_size MZ header size in bytes
            explicit pklite_decompressor(uint16_t h_pklite_info, uint16_t header_size);

            decompression_result decompress(std::span <const uint8_t> compressed_data) override;

            [[nodiscard]] const char* name() const override { return "PKLITE"; }

        private:
            // Extract decompression parameters from PKLITE header
            struct pklite_params {
                uint32_t decomp_size; // Decompressed size
                uint32_t compressed_size; // Compressed size
                uint32_t decompressor_size; // Size of decompressor stub
                uint32_t data_offset; // Offset to compressed data
                bool uncompressed_region; // Has uncompressed region
                bool has_checksum; // Has checksum
                bool use_xor; // XOR encryption (bit 0x1000 set)
                bool large_compression; // Large compression model (bit 0x2000 set)
            };

            [[nodiscard]] pklite_params read_parameters(std::span <const uint8_t> data) const;

            uint16_t h_pklite_info_;
            uint16_t header_size_;
    };
} // namespace libexe

#endif // LIBEXE_PKLITE_DECOMPRESSOR_HPP
