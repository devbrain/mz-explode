// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_NE_FILE_HPP
#define LIBEXE_NE_FILE_HPP

#include <libexe/export.hpp>
#include <libexe/executable_file.hpp>
#include <libexe/ne_types.hpp>
#include <filesystem>
#include <vector>
#include <span>
#include <optional>

namespace libexe {
    /// NE segment information
    struct LIBEXE_EXPORT ne_segment {
        uint16_t sector_offset; // File offset (in sectors, multiply by alignment shift)
        uint16_t length; // Segment length in bytes (0 = 65536)
        ne_segment_flags flags; // Segment flags
        uint16_t min_alloc; // Minimum allocation size
        std::span <const uint8_t> data; // Segment data
    };

    /// NE (New Executable) file - 16-bit Windows (Windows 3.x) and OS/2
    class LIBEXE_EXPORT ne_file final : public executable_file {
        public:
            /// Load NE file from filesystem
            static ne_file from_file(const std::filesystem::path& path);

            /// Load NE file from memory
            static ne_file from_memory(std::span <const uint8_t> data);

            // Implement base class interface
            [[nodiscard]] format_type get_format() const override;
            [[nodiscard]] std::string_view format_name() const override;
            [[nodiscard]] std::span <const uint8_t> code_section() const override;

            /// NE Header accessors
            [[nodiscard]] uint8_t linker_version() const; // Major version
            [[nodiscard]] uint8_t linker_revision() const; // Minor version
            [[nodiscard]] ne_file_flags flags() const; // NE flags
            [[nodiscard]] uint16_t segment_count() const; // Number of segments
            [[nodiscard]] uint16_t module_count() const; // Number of module references
            [[nodiscard]] ne_target_os target_os() const; // Target operating system

            /// Entry point and stack
            [[nodiscard]] uint16_t entry_cs() const; // Entry point code segment
            [[nodiscard]] uint16_t entry_ip() const; // Entry point instruction pointer
            [[nodiscard]] uint16_t initial_ss() const; // Initial stack segment
            [[nodiscard]] uint16_t initial_sp() const; // Initial stack pointer

            /// Table offsets (relative to NE header start)
            [[nodiscard]] uint16_t segment_table_offset() const;
            [[nodiscard]] uint16_t resource_table_offset() const;
            [[nodiscard]] uint16_t resident_name_table_offset() const;
            [[nodiscard]] uint16_t module_ref_table_offset() const;
            [[nodiscard]] uint16_t import_name_table_offset() const;
            [[nodiscard]] uint32_t nonresident_name_table_offset() const; // Absolute file offset

            /// Segment access
            [[nodiscard]] const std::vector <ne_segment>& segments() const;
            [[nodiscard]] std::optional <ne_segment> get_segment(size_t index) const;

            /// Get first code segment (entry point segment)
            [[nodiscard]] std::optional <ne_segment> get_code_segment() const;

            /// Get segment alignment shift factor (actual offset = sector_offset << alignment_shift)
            [[nodiscard]] uint16_t alignment_shift() const;

        private:
            ne_file() = default; // Use factory methods

            // Parse NE headers and segments
            void parse_ne_headers();
            void parse_segments();

            std::vector <uint8_t> data_;
            std::vector <ne_segment> segments_;

            // Parsed header information
            uint32_t ne_offset_ = 0; // Offset to NE header in file

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
