// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/decompressors/decompressor.hpp>
#if defined(MZEXPLODE_HAS_DECOMPRESSOR_PKLITE)
#include <libexe/decompressors/pklite.hpp>
#endif
#if defined(MZEXPLODE_HAS_DECOMPRESSOR_LZEXE)
#include <libexe/decompressors/lzexe.hpp>
#endif
#if defined(MZEXPLODE_HAS_DECOMPRESSOR_EXEPACK)
#include <libexe/decompressors/exepack.hpp>
#endif
#if defined(MZEXPLODE_HAS_DECOMPRESSOR_KD)
#include <libexe/decompressors/knowledge_dynamics.hpp>
#endif
#if defined(MZEXPLODE_HAS_DECOMPRESSOR_DIET)
#include <libexe/decompressors/diet.hpp>
#endif
#include <stdexcept>
#include <string>

namespace libexe {

namespace {
[[noreturn]] void throw_decompressor_disabled(const char* name) {
    throw std::runtime_error(
        std::string{name} +
        " decompressor not built in (NEUTRINO_MZEXPLODE_DECOMPRESSOR_* gates it out)");
}
}  // namespace

std::unique_ptr<decompressor> create_decompressor(compression_type type) {
    switch (type) {
        case compression_type::PKLITE_STANDARD:
        case compression_type::PKLITE_EXTRA:
#if defined(MZEXPLODE_HAS_DECOMPRESSOR_PKLITE)
            // PKLITE requires file data for pattern-based detection
            // Use create_pklite_decompressor() instead
            throw std::runtime_error(
                "PKLITE decompressor requires file data - use create_pklite_decompressor()");
#else
            throw_decompressor_disabled("PKLITE");
#endif

        case compression_type::LZEXE_090:
#if defined(MZEXPLODE_HAS_DECOMPRESSOR_LZEXE)
            // Default header size = 2 paragraphs (32 bytes)
            return std::make_unique<lzexe_decompressor>(lzexe_version::V090, uint16_t{32});
#else
            throw_decompressor_disabled("LZEXE");
#endif

        case compression_type::LZEXE_091:
#if defined(MZEXPLODE_HAS_DECOMPRESSOR_LZEXE)
            // Default header size = 2 paragraphs (32 bytes)
            return std::make_unique<lzexe_decompressor>(lzexe_version::V091, uint16_t{32});
#else
            throw_decompressor_disabled("LZEXE");
#endif

        case compression_type::EXEPACK:
#if defined(MZEXPLODE_HAS_DECOMPRESSOR_EXEPACK)
            // Default header size = 2 paragraphs (32 bytes)
            return std::make_unique<exepack_decompressor>(uint16_t{32});
#else
            throw_decompressor_disabled("EXEPACK");
#endif

        case compression_type::KNOWLEDGE_DYNAMICS:
#if defined(MZEXPLODE_HAS_DECOMPRESSOR_KD)
            // Default header size = 32 bytes
            return std::make_unique<knowledge_dynamics_decompressor>(uint16_t{32});
#else
            throw_decompressor_disabled("Knowledge Dynamics");
#endif

        case compression_type::DIET:
#if defined(MZEXPLODE_HAS_DECOMPRESSOR_DIET)
            // Default: EXE format, v1.44, header size = 32 bytes
            return std::make_unique<diet_decompressor>(
                diet_version::V144, diet_file_type::EXE, uint16_t{32});
#else
            throw_decompressor_disabled("DIET");
#endif

        case compression_type::NONE:
        default:
            return nullptr;
    }
}

#if defined(MZEXPLODE_HAS_DECOMPRESSOR_PKLITE)
std::unique_ptr<decompressor> create_pklite_decompressor(
    std::span<const uint8_t> file_data, uint16_t header_paragraphs) {
    return std::make_unique<pklite_decompressor>(file_data, header_paragraphs);
}
#endif

} // namespace libexe
