// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/decompressors/decompressor.hpp>
#include <libexe/decompressors/pklite.hpp>
#include <libexe/decompressors/lzexe.hpp>
#include <libexe/decompressors/exepack.hpp>
#include <libexe/decompressors/knowledge_dynamics.hpp>
#include <libexe/decompressors/diet.hpp>
#include <stdexcept>

namespace libexe {

std::unique_ptr<decompressor> create_decompressor(compression_type type) {
    switch (type) {
        case compression_type::PKLITE_STANDARD:
        case compression_type::PKLITE_EXTRA:
            // PKLITE requires file data for pattern-based detection
            // Use create_pklite_decompressor() instead
            throw std::runtime_error(
                "PKLITE decompressor requires file data - use create_pklite_decompressor()");

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

        case compression_type::DIET:
            // Default: EXE format, v1.44, header size = 32 bytes
            return std::make_unique<diet_decompressor>(
                diet_version::V144, diet_file_type::EXE, 32);

        case compression_type::NONE:
        default:
            return nullptr;
    }
}

std::unique_ptr<decompressor> create_pklite_decompressor(
    std::span<const uint8_t> file_data, uint16_t header_paragraphs) {
    return std::make_unique<pklite_decompressor>(file_data, header_paragraphs);
}

} // namespace libexe
