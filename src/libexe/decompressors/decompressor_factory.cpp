// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/decompressors/decompressor.hpp>
#include <libexe/decompressors/pklite.hpp>
#include <libexe/decompressors/lzexe.hpp>
#include <libexe/decompressors/exepack.hpp>
#include <libexe/decompressors/knowledge_dynamics.hpp>
#include <stdexcept>

namespace libexe {

std::unique_ptr<decompressor> create_decompressor(compression_type type) {
    switch (type) {
        case compression_type::PKLITE_STANDARD:
            // Default parameters for standard PKLITE
            // h_pklite_info with bit 12 clear = standard, header size = 8 paragraphs
            return std::make_unique<pklite_decompressor>(0x210C, 128);

        case compression_type::PKLITE_EXTRA:
            // h_pklite_info with bit 12 set = extra compression
            return std::make_unique<pklite_decompressor>(0x310F, 128);

        case compression_type::LZEXE_090:
            // Default header size = 2 paragraphs (32 bytes)
            return std::make_unique<lzexe_decompressor>(lzexe_version::V090, 32);

        case compression_type::LZEXE_091:
            // Default header size = 2 paragraphs (32 bytes)
            return std::make_unique<lzexe_decompressor>(lzexe_version::V091, 32);

        case compression_type::EXEPACK:
            // Default header size = 2 paragraphs (32 bytes)
            return std::make_unique<exepack_decompressor>(32);

        case compression_type::KNOWLEDGE_DYNAMICS:
            // Default header size = 32 bytes
            return std::make_unique<knowledge_dynamics_decompressor>(32);

        case compression_type::NONE:
        default:
            return nullptr;
    }
}

} // namespace libexe
