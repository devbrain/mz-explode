// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_FORMATS_NE_FILE_HPP
#define LIBEXE_FORMATS_NE_FILE_HPP

#include <libexe/export.hpp>
#include <libexe/core/executable_file.hpp>
#include <libexe/ne/types.hpp>
#include <libexe/pe/section.hpp>
#include <filesystem>
#include <vector>
#include <span>
#include <optional>
#include <memory>

namespace libexe {
    // Forward declarations
    class resource_directory;

    /// NE (New Executable) file - 16-bit Windows (Windows 3.x) and OS/2
    class LIBEXE_EXPORT ne_file final : public executable_file {
        public:
            /// Load NE file from filesystem
            [[nodiscard]] static ne_file from_file(const std::filesystem::path& path);

            /// Load NE file from memory
            [[nodiscard]] static ne_file from_memory(std::span <const uint8_t> data);

            // Implement base class interface
            [[nodiscard]] format_type get_format() const override;
            [[nodiscard]] std::string_view format_name() const override;
            [[nodiscard]] std::span <const uint8_t> code_section() const override;

            /// NE Header accessors
            [[nodiscard]] uint8_t linker_version() const;
            [[nodiscard]] uint8_t linker_revision() const;
            [[nodiscard]] ne_file_flags flags() const;
            [[nodiscard]] uint16_t segment_count() const;
            [[nodiscard]] uint16_t module_count() const;
            [[nodiscard]] ne_target_os target_os() const;

            /// Entry point and stack
            [[nodiscard]] uint16_t entry_cs() const;
            [[nodiscard]] uint16_t entry_ip() const;
            [[nodiscard]] uint16_t initial_ss() const;
            [[nodiscard]] uint16_t initial_sp() const;

            /// Table offsets (relative to NE header start)
            [[nodiscard]] uint16_t segment_table_offset() const;
            [[nodiscard]] uint16_t resource_table_offset() const;
            [[nodiscard]] uint16_t resident_name_table_offset() const;
            [[nodiscard]] uint16_t module_ref_table_offset() const;
            [[nodiscard]] uint16_t import_name_table_offset() const;
            [[nodiscard]] uint32_t nonresident_name_table_offset() const;

            /// Segment access
            [[nodiscard]] const std::vector <ne_segment>& segments() const;
            [[nodiscard]] std::optional <ne_segment> get_segment(size_t index) const;
            [[nodiscard]] std::optional <ne_segment> get_code_segment() const;
            [[nodiscard]] uint16_t alignment_shift() const;

            /// Resource access
            [[nodiscard]] bool has_resources() const;
            [[nodiscard]] std::shared_ptr<resource_directory> resources() const;

        private:
            ne_file() = default;

            void parse_ne_headers();
            void parse_segments();

            std::vector <uint8_t> data_;
            std::vector <ne_segment> segments_;

            uint32_t ne_offset_ = 0;
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

            uint16_t segment_table_offset_ = 0;
            uint16_t resource_table_offset_ = 0;
            uint16_t resident_name_table_offset_ = 0;
            uint16_t module_ref_table_offset_ = 0;
            uint16_t import_name_table_offset_ = 0;
            uint32_t nonresident_name_table_offset_ = 0;
    };
} // namespace libexe

#endif // LIBEXE_FORMATS_NE_FILE_HPP
