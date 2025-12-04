// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_MZ_FILE_HPP
#define LIBEXE_MZ_FILE_HPP

#include <libexe/export.hpp>
#include <libexe/executable_file.hpp>
#include <libexe/decompressor.hpp>
#include <filesystem>
#include <vector>
#include <span>
#include <cstdint>

namespace libexe {

/// MZ (DOS) executable file
class LIBEXE_EXPORT mz_file : public executable_file {
public:
    /// Load MZ file from filesystem
    static mz_file from_file(const std::filesystem::path& path);

    /// Load MZ file from memory
    static mz_file from_memory(std::span<const uint8_t> data);

    // Implement base class interface
    format_type get_format() const override;
    std::string_view format_name() const override;
    std::span<const uint8_t> code_section() const override;

    /// Check if this executable is compressed
    bool is_compressed() const;

    /// Get the compression type (if any)
    compression_type get_compression() const;

    /// DOS header accessors
    uint16_t initial_cs() const;  // Code segment
    uint16_t initial_ip() const;  // Instruction pointer
    uint16_t initial_ss() const;  // Stack segment
    uint16_t initial_sp() const;  // Stack pointer

    uint16_t min_extra_paragraphs() const;
    uint16_t max_extra_paragraphs() const;
    uint16_t relocation_count() const;
    uint16_t header_paragraphs() const;

private:
    mz_file() = default;  // Use factory methods

    // Detect compression by examining signatures in code section
    compression_type detect_compression() const;

    std::vector<uint8_t> data_;
    compression_type compression_ = compression_type::NONE;

    // Cached offsets from MZ header
    uint16_t header_size_ = 0;
    uint16_t code_offset_ = 0;
};

} // namespace libexe

#endif // LIBEXE_MZ_FILE_HPP
