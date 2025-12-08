#ifndef LIBEXE_EXPORT_DIRECTORY_PARSER_HPP
#define LIBEXE_EXPORT_DIRECTORY_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/export_directory.hpp>
#include <libexe/section.hpp>
#include <cstdint>
#include <span>
#include <vector>
#include <string>
#include <optional>

namespace libexe {

/**
 * Export Directory Parser
 *
 * Parses PE export directory (data directory index 0) to extract
 * all exported functions from a DLL or executable. Handles named exports,
 * ordinal-only exports, and forwarders.
 *
 * Export directory structure:
 * - IMAGE_EXPORT_DIRECTORY: Main header with counts and RVAs
 * - Export Address Table (EAT): Array of function RVAs
 * - Name Pointer Table: Array of RVAs to function names
 * - Ordinal Table: Array of ordinals corresponding to names
 */
class LIBEXE_EXPORT export_directory_parser {
public:
    /**
     * Parse export directory from PE file
     *
     * Reads IMAGE_EXPORT_DIRECTORY and all associated tables to extract
     * all exported functions (named, ordinal-only, and forwarders).
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections (for RVA to offset conversion)
     * @param export_dir_rva RVA to export directory
     * @param export_dir_size Size of export directory (for forwarder detection)
     * @return Parsed export directory with all functions
     * @throws std::runtime_error if export directory is malformed
     */
    static export_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t export_dir_rva,
        uint32_t export_dir_size
    );

private:
    /**
     * Read Export Address Table (EAT)
     *
     * Reads array of function RVAs from Export Address Table.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections
     * @param table_rva RVA to Export Address Table
     * @param count Number of entries (number_of_functions)
     * @return Vector of function RVAs
     */
    static std::vector<uint32_t> read_address_table(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t table_rva,
        uint32_t count
    );

    /**
     * Read Name Pointer Table
     *
     * Reads array of RVAs pointing to function name strings.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections
     * @param table_rva RVA to Name Pointer Table
     * @param count Number of entries (number_of_names)
     * @return Vector of name RVAs
     */
    static std::vector<uint32_t> read_name_pointer_table(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t table_rva,
        uint32_t count
    );

    /**
     * Read Ordinal Table
     *
     * Reads array of ordinals corresponding to named exports.
     * These are offsets (not actual ordinals) - add ordinal_base to get actual ordinal.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections
     * @param table_rva RVA to Ordinal Table
     * @param count Number of entries (number_of_names)
     * @return Vector of ordinal offsets
     */
    static std::vector<uint16_t> read_ordinal_table(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t table_rva,
        uint32_t count
    );

    /**
     * Check if RVA points to a forwarder
     *
     * Forwarders are exports that redirect to another DLL.
     * If the function RVA points within the export section itself
     * (not to code), it's a forwarder string like "NTDLL.RtlAllocateHeap".
     *
     * @param rva Function RVA from Export Address Table
     * @param export_section_rva Export section start RVA
     * @param export_section_size Export section size
     * @return true if this is a forwarder
     */
    static bool is_forwarder_rva(
        uint32_t rva,
        uint32_t export_section_rva,
        uint32_t export_section_size
    );

    /**
     * Read forwarder string
     *
     * Reads the forwarder string (e.g., "NTDLL.RtlAllocateHeap")
     * from the export section.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections
     * @param forwarder_rva RVA to forwarder string
     * @return Forwarder string
     */
    static std::string read_forwarder_string(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t forwarder_rva
    );

    /**
     * Read null-terminated ASCII string at RVA
     *
     * Converts RVA to file offset and reads string.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections
     * @param rva RVA to string
     * @return String content (without null terminator)
     * @throws std::runtime_error if RVA is invalid or string is unterminated
     */
    static std::string read_string_at_rva(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t rva
    );

    /**
     * Convert RVA to file offset
     *
     * Helper that wraps pe_section_parser::rva_to_file_offset()
     * and throws on failure.
     *
     * @param sections Parsed PE sections
     * @param rva RVA to convert
     * @return File offset
     * @throws std::runtime_error if RVA is not in any section
     */
    static size_t rva_to_offset(
        const std::vector<pe_section>& sections,
        uint32_t rva
    );
};

} // namespace libexe

#endif // LIBEXE_EXPORT_DIRECTORY_PARSER_HPP
