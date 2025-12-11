// libexe - Modern executable file analysis library
// Copyright (c) 2024

/**
 * @file ne_file.hpp
 * @brief NE (New Executable) file parser for 16-bit Windows and OS/2.
 *
 * This header provides the ne_file class for parsing and analyzing NE format
 * executables. NE is the 16-bit executable format used by:
 * - Windows 3.x applications and DLLs
 * - OS/2 1.x applications
 * - Windows 3.x device drivers (.DRV files)
 * - Some Windows 9x components for backward compatibility
 *
 * NE files are identified by the "NE" signature (0x4E 0x45) at the offset
 * specified by e_lfanew in the DOS MZ header.
 *
 * @note NE files always begin with an MZ DOS stub that displays an error
 *       message when run in pure DOS mode.
 *
 * @see mz_file, pe_file, executable_factory
 */

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

/**
 * @brief NE (New Executable) file parser for 16-bit Windows/OS2.
 *
 * Parses NE format executables and provides access to header fields,
 * segment information, and resources. This format was used for 16-bit
 * Windows applications before the transition to PE format.
 *
 * @par NE Structure Overview:
 * - DOS MZ stub header (error message for DOS)
 * - NE header at offset specified by e_lfanew
 * - Segment table (code and data segments)
 * - Resource table
 * - Resident/Non-resident name tables
 * - Entry table
 * - Module reference table
 *
 * @par Example Usage:
 * @code
 * auto ne = libexe::ne_file::from_file("program.exe");
 *
 * std::cout << "Target OS: ";
 * switch (ne.target_os()) {
 *     case ne_target_os::WINDOWS: std::cout << "Windows"; break;
 *     case ne_target_os::OS2: std::cout << "OS/2"; break;
 * }
 *
 * std::cout << "\nSegments: " << ne.segment_count() << std::endl;
 * for (const auto& seg : ne.segments()) {
 *     std::cout << "  Segment " << seg.index
 *               << (seg.is_code() ? " [CODE]" : " [DATA]") << std::endl;
 * }
 * @endcode
 *
 * @see ne_segment, ne_file_flags, ne_target_os
 */
class LIBEXE_EXPORT ne_file final : public executable_file {
    public:
        // =====================================================================
        // Factory Methods
        // =====================================================================

        /**
         * @brief Load NE file from filesystem.
         *
         * @param path Path to the executable file.
         * @return Parsed ne_file object.
         * @throws std::runtime_error If file cannot be read or is not valid NE format.
         */
        [[nodiscard]] static ne_file from_file(const std::filesystem::path& path);

        /**
         * @brief Load NE file from memory buffer.
         *
         * @param data Span containing the raw file data.
         * @return Parsed ne_file object.
         * @throws std::runtime_error If data is not valid NE format.
         */
        [[nodiscard]] static ne_file from_memory(std::span <const uint8_t> data);

        // =====================================================================
        // Base Class Interface Implementation
        // =====================================================================

        /**
         * @brief Get the format type.
         * @return format_type::NE_WIN16
         */
        [[nodiscard]] format_type get_format() const override;

        /**
         * @brief Get human-readable format name.
         * @return "NE" or "NE (OS/2)" depending on target OS.
         */
        [[nodiscard]] std::string_view format_name() const override;

        /**
         * @brief Get the primary code section data.
         *
         * Returns the data from the first code segment (segment with
         * the DATA flag cleared).
         *
         * @return Span containing the code segment bytes.
         */
        [[nodiscard]] std::span <const uint8_t> code_section() const override;

        // =====================================================================
        // NE Header Accessors
        // =====================================================================

        /**
         * @brief Get linker major version number.
         * @return Linker version (major part).
         */
        [[nodiscard]] uint8_t linker_version() const;

        /**
         * @brief Get linker minor revision number.
         * @return Linker version (minor/revision part).
         */
        [[nodiscard]] uint8_t linker_revision() const;

        /**
         * @brief Get NE file flags.
         *
         * Flags indicate properties like single/multiple data segments,
         * global initialization, protected mode only, etc.
         *
         * @return Bitmask of ne_file_flags values.
         */
        [[nodiscard]] ne_file_flags flags() const;

        /**
         * @brief Get number of segments.
         * @return Total segment count.
         */
        [[nodiscard]] size_t segment_count() const;

        /**
         * @brief Get number of module references.
         *
         * Module references are imported DLLs that this executable depends on.
         *
         * @return Count of referenced modules.
         */
        [[nodiscard]] size_t module_count() const;

        /**
         * @brief Get target operating system.
         * @return ne_target_os value (WINDOWS, OS2, etc.).
         */
        [[nodiscard]] ne_target_os target_os() const;

        // =====================================================================
        // Entry Point and Stack
        // =====================================================================

        /**
         * @brief Get entry point code segment number.
         *
         * This is the 1-based segment number containing the entry point.
         * A value of 0 indicates no entry point (library without startup).
         *
         * @return Entry point segment number (1-based), or 0.
         */
        [[nodiscard]] uint16_t entry_cs() const;

        /**
         * @brief Get entry point offset within the code segment.
         * @return Offset to entry point within entry_cs().
         */
        [[nodiscard]] uint16_t entry_ip() const;

        /**
         * @brief Get entry stack segment number.
         * @return Stack segment number (1-based), or 0 for automatic.
         */
        [[nodiscard]] uint16_t entry_ss() const;

        /**
         * @brief Get entry stack pointer value.
         * @return Entry SP offset within stack segment.
         */
        [[nodiscard]] uint16_t entry_sp() const;

        // =====================================================================
        // Table Offsets (relative to NE header start)
        // =====================================================================

        /**
         * @brief Get offset to segment table.
         * @return Byte offset from NE header start to segment table.
         */
        [[nodiscard]] uint16_t segment_table_offset() const;

        /**
         * @brief Get offset to resource table.
         * @return Byte offset from NE header start to resource table.
         */
        [[nodiscard]] uint16_t resource_table_offset() const;

        /**
         * @brief Get offset to resident name table.
         *
         * Contains the module name and exported function names that
         * remain resident in memory.
         *
         * @return Byte offset from NE header start.
         */
        [[nodiscard]] uint16_t resident_name_table_offset() const;

        /**
         * @brief Get offset to module reference table.
         * @return Byte offset from NE header start.
         */
        [[nodiscard]] uint16_t module_ref_table_offset() const;

        /**
         * @brief Get offset to import name table.
         * @return Byte offset from NE header start.
         */
        [[nodiscard]] uint16_t import_name_table_offset() const;

        /**
         * @brief Get offset to non-resident name table.
         *
         * Contains additional exported names that can be discarded.
         * This offset is absolute (from file start), not relative.
         *
         * @return Absolute byte offset from file start.
         */
        [[nodiscard]] uint32_t nonresident_name_table_offset() const;

        // =====================================================================
        // Segment Access
        // =====================================================================

        /**
         * @brief Get all segments.
         * @return Const reference to vector of ne_segment structures.
         */
        [[nodiscard]] const std::vector <ne_segment>& segments() const;

        /**
         * @brief Get a segment by index.
         *
         * @param index Zero-based segment index.
         * @return Optional containing the segment, or nullopt if out of range.
         */
        [[nodiscard]] std::optional <ne_segment> get_segment(size_t index) const;

        /**
         * @brief Get the first code segment.
         *
         * Finds and returns the first segment that has the DATA flag cleared.
         *
         * @return Optional containing the code segment, or nullopt if none found.
         */
        [[nodiscard]] std::optional <ne_segment> get_code_segment() const;

        /**
         * @brief Get the first data segment.
         *
         * Finds and returns the first segment that has the DATA flag set.
         *
         * @return Optional containing the data segment, or nullopt if none found.
         */
        [[nodiscard]] std::optional <ne_segment> get_data_segment() const;

        /**
         * @brief Get segment alignment shift count.
         *
         * Segment file offsets are shifted left by this value to get
         * the actual byte offset. Typical value is 9 (512-byte alignment).
         *
         * @return Alignment shift count.
         */
        [[nodiscard]] uint16_t alignment_shift() const;

        // =====================================================================
        // Resource Access
        // =====================================================================

        /**
         * @brief Check if file contains resources.
         * @return true if resource table is present and non-empty.
         */
        [[nodiscard]] bool has_resources() const;

        /**
         * @brief Get the resource directory.
         *
         * Provides access to icons, cursors, dialogs, menus, and other
         * resources embedded in the executable.
         *
         * @return Shared pointer to resource_directory, or nullptr if no resources.
         */
        [[nodiscard]] std::shared_ptr<resource_directory> resources() const;

        // =====================================================================
        // Entropy Analysis (Packing Detection)
        // =====================================================================

        /**
         * @brief Calculate entropy of the entire file.
         * @return Entropy value in bits (0.0 - 8.0).
         */
        [[nodiscard]] double file_entropy() const;

        /**
         * @brief Calculate entropy of a specific segment.
         *
         * @param segment_index Zero-based segment index.
         * @return Entropy value in bits (0.0 - 8.0), or 0.0 if invalid index.
         */
        [[nodiscard]] double segment_entropy(size_t segment_index) const;

        /**
         * @brief Get entropy analysis for all segments.
         * @return Vector of (segment_index, entropy) pairs.
         */
        [[nodiscard]] std::vector<std::pair<size_t, double>> all_segment_entropies() const;

        /**
         * @brief Check if any segment has high entropy.
         * @return true if any segment has entropy >= 7.0 bits.
         */
        [[nodiscard]] bool has_high_entropy_segments() const;

        /**
         * @brief Check if file appears to be packed.
         *
         * Uses entropy-based heuristics to detect packing.
         *
         * @return true if file appears to be packed.
         */
        [[nodiscard]] bool is_likely_packed() const;

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
