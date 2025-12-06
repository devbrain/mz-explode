// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_NE_FILE_HPP
#define LIBEXE_NE_FILE_HPP

#include <libexe/export.hpp>
#include <libexe/executable_file.hpp>
#include <filesystem>
#include <vector>
#include <span>
#include <cstdint>
#include <string>
#include <optional>

namespace libexe {

/// NE segment information
struct LIBEXE_EXPORT ne_segment {
    uint16_t sector_offset;      // File offset (in sectors, multiply by alignment shift)
    uint16_t length;             // Segment length in bytes (0 = 65536)
    uint16_t flags;              // Segment flags
    uint16_t min_alloc;          // Minimum allocation size
    std::span<const uint8_t> data;  // Segment data
};

/// NE (New Executable) file - 16-bit Windows (Windows 3.x) and OS/2
class LIBEXE_EXPORT ne_file : public executable_file {
public:
    /// Load NE file from filesystem
    static ne_file from_file(const std::filesystem::path& path);

    /// Load NE file from memory
    static ne_file from_memory(std::span<const uint8_t> data);

    // Implement base class interface
    format_type get_format() const override;
    std::string_view format_name() const override;
    std::span<const uint8_t> code_section() const override;

    /// NE Header accessors
    uint8_t linker_version() const;      // Major version
    uint8_t linker_revision() const;     // Minor version
    uint16_t flags() const;              // NE flags
    uint16_t segment_count() const;      // Number of segments
    uint16_t module_count() const;       // Number of module references
    uint8_t target_os() const;           // Target operating system

    /// Entry point and stack
    uint16_t entry_cs() const;           // Entry point code segment
    uint16_t entry_ip() const;           // Entry point instruction pointer
    uint16_t initial_ss() const;         // Initial stack segment
    uint16_t initial_sp() const;         // Initial stack pointer

    /// Table offsets (relative to NE header start)
    uint16_t segment_table_offset() const;
    uint16_t resource_table_offset() const;
    uint16_t resident_name_table_offset() const;
    uint16_t module_ref_table_offset() const;
    uint16_t import_name_table_offset() const;
    uint32_t nonresident_name_table_offset() const;  // Absolute file offset

    /// Segment access
    const std::vector<ne_segment>& segments() const;
    std::optional<ne_segment> get_segment(size_t index) const;

    /// Get first code segment (entry point segment)
    std::optional<ne_segment> get_code_segment() const;

    /// Get segment alignment shift factor (actual offset = sector_offset << alignment_shift)
    uint16_t alignment_shift() const;

private:
    ne_file() = default;  // Use factory methods

    // Parse NE headers and segments
    void parse_ne_headers();
    void parse_segments();

    std::vector<uint8_t> data_;
    std::vector<ne_segment> segments_;

    // Parsed header information
    uint32_t ne_offset_ = 0;      // Offset to NE header in file

    // Cached values from header
    uint8_t linker_ver_ = 0;
    uint8_t linker_rev_ = 0;
    uint16_t flags_ = 0;
    uint16_t segment_count_ = 0;
    uint16_t module_count_ = 0;
    uint8_t target_os_ = 0;
    uint16_t entry_cs_ = 0;
    uint16_t entry_ip_ = 0;
    uint16_t initial_ss_ = 0;
    uint16_t initial_sp_ = 0;
    uint16_t alignment_shift_ = 0;

    // Table offsets (relative to NE header)
    uint16_t segment_table_offset_ = 0;
    uint16_t resource_table_offset_ = 0;
    uint16_t resident_name_table_offset_ = 0;
    uint16_t module_ref_table_offset_ = 0;
    uint16_t import_name_table_offset_ = 0;
    uint32_t nonresident_name_table_offset_ = 0;
};

} // namespace libexe

#endif // LIBEXE_NE_FILE_HPP
