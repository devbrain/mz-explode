// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_FORMATS_MZ_FILE_HPP
#define LIBEXE_FORMATS_MZ_FILE_HPP

#include <libexe/export.hpp>
#include <libexe/core/executable_file.hpp>
#include <libexe/decompressors/decompressor.hpp>
#include <filesystem>
#include <vector>
#include <span>
#include <cstdint>

namespace libexe {
    /// MZ (DOS) executable file
    class LIBEXE_EXPORT mz_file final : public executable_file {
        public:
            /// Load MZ file from filesystem
            static mz_file from_file(const std::filesystem::path& path);

            /// Load MZ file from memory
            static mz_file from_memory(std::span <const uint8_t> data);

            // Implement base class interface
            [[nodiscard]] format_type get_format() const override;
            [[nodiscard]] std::string_view format_name() const override;
            [[nodiscard]] std::span <const uint8_t> code_section() const override;

            /// Check if this executable is compressed
            [[nodiscard]] bool is_compressed() const;

            /// Get the compression type (if any)
            [[nodiscard]] compression_type get_compression() const;

            /// DOS header accessors
            [[nodiscard]] uint16_t initial_cs() const; // Code segment
            [[nodiscard]] uint16_t initial_ip() const; // Instruction pointer
            [[nodiscard]] uint16_t initial_ss() const; // Stack segment
            [[nodiscard]] uint16_t initial_sp() const; // Stack pointer

            [[nodiscard]] uint16_t min_extra_paragraphs() const;
            [[nodiscard]] uint16_t max_extra_paragraphs() const;
            [[nodiscard]] uint16_t relocation_count() const;
            [[nodiscard]] uint16_t header_paragraphs() const;

        private:
            mz_file() = default; // Use factory methods

            // Detect compression by examining signatures in code section
            [[nodiscard]] compression_type detect_compression() const;

            std::vector <uint8_t> data_;
            compression_type compression_ = compression_type::NONE;

            // Cached offsets from MZ header
            uint16_t header_size_ = 0;
            uint16_t code_offset_ = 0;
    };
} // namespace libexe

#endif // LIBEXE_FORMATS_MZ_FILE_HPP
