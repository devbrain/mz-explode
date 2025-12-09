// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_DECOMPRESSORS_DECOMPRESSOR_HPP
#define LIBEXE_DECOMPRESSORS_DECOMPRESSOR_HPP

#include <libexe/export.hpp>
#include <span>
#include <vector>
#include <memory>

namespace libexe {
    /// Compression algorithms used in DOS executables
    enum class compression_type {
        NONE,
        PKLITE_STANDARD,
        PKLITE_EXTRA,
        LZEXE_090,
        LZEXE_091,
        EXEPACK,
        KNOWLEDGE_DYNAMICS
    };

    /// Result of decompression operation
    struct decompression_result {
        std::vector <uint8_t> code;
        std::vector <uint8_t> extra_header;
        uint16_t initial_cs = 0;
        uint16_t initial_ip = 0;
        uint16_t initial_ss = 0;
        uint16_t initial_sp = 0;
        uint16_t min_extra_paragraphs = 0;
        uint16_t max_extra_paragraphs = 0xFFFF;
        uint16_t header_paragraphs = 0;
        uint16_t checksum = 0;
        std::vector <std::pair <uint16_t, uint16_t>> relocations;
    };

    /// Base class for all decompressors
    class LIBEXE_EXPORT decompressor {
        public:
            decompressor(const decompressor&) = delete;
            decompressor& operator=(const decompressor&) = delete;
            virtual ~decompressor() = default;

            virtual decompression_result decompress(std::span <const uint8_t> compressed_data) = 0;
            [[nodiscard]] virtual const char* name() const = 0;

        protected:
            decompressor() = default;
            decompressor(decompressor&&) = default;
            decompressor& operator=(decompressor&&) = default;
    };

    /// Factory for creating decompressors
    LIBEXE_EXPORT std::unique_ptr <decompressor>
    create_decompressor(compression_type type);
} // namespace libexe

#endif // LIBEXE_DECOMPRESSORS_DECOMPRESSOR_HPP
