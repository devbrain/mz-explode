#ifndef LIBEXE_IMPORT_DIRECTORY_PARSER_HPP
#define LIBEXE_IMPORT_DIRECTORY_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/import_directory.hpp>
#include <libexe/section.hpp>
#include <cstdint>
#include <span>
#include <vector>
#include <string>
#include <optional>

namespace libexe {

/**
 * Import Directory Parser
 *
 * Parses PE import directory (data directory index 1) to extract
 * all imported DLLs and functions. Handles both PE32 and PE32+ formats.
 */
class LIBEXE_EXPORT import_directory_parser {
public:
    /**
     * Parse import directory from PE file
     *
     * Reads IMAGE_IMPORT_DESCRIPTOR array and all referenced data
     * (DLL names, function names, ordinals). The import directory is
     * an array of descriptors terminated by a null entry.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections (for RVA to offset conversion)
     * @param import_dir_rva RVA to import directory
     * @param import_dir_size Size of import directory (may be 0 if unknown)
     * @param is_64bit true for PE32+, false for PE32
     * @return Parsed import directory with all DLLs and functions
     * @throws std::runtime_error if import directory is malformed
     */
    static import_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t import_dir_rva,
        uint32_t import_dir_size,
        bool is_64bit
    );

private:
    /**
     * Parse single IMAGE_IMPORT_DESCRIPTOR
     *
     * Reads one DLL's import information including DLL name and all functions.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections
     * @param descriptor_rva RVA to IMAGE_IMPORT_DESCRIPTOR
     * @param is_64bit true for PE32+
     * @return Parsed import DLL
     */
    static import_dll parse_import_descriptor(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t descriptor_rva,
        bool is_64bit
    );

    /**
     * Parse Import Lookup Table (ILT)
     *
     * Reads array of IMAGE_THUNK_DATA structures. Each entry points to
     * either an IMAGE_IMPORT_BY_NAME structure (name import) or contains
     * an ordinal value (ordinal import).
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections
     * @param ilt_rva RVA to Import Lookup Table
     * @param iat_rva RVA to Import Address Table (for recording IAT RVAs)
     * @param is_64bit true for PE32+ (64-bit thunks)
     * @return Vector of import entries
     */
    static std::vector<import_entry> parse_ilt(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t ilt_rva,
        uint32_t iat_rva,
        bool is_64bit
    );

    /**
     * Parse IMAGE_IMPORT_BY_NAME structure
     *
     * Reads hint and function name for a named import.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections
     * @param rva RVA to IMAGE_IMPORT_BY_NAME
     * @param iat_rva RVA in Import Address Table (for this entry)
     * @param ordinal Ordinal value (for ordinal-only imports)
     * @param is_ordinal true if this is an ordinal import
     * @return Parsed import entry
     */
    static import_entry parse_import_by_name(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t rva,
        uint64_t iat_rva,
        uint16_t ordinal,
        bool is_ordinal
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

    // Ordinal flag masks
    static constexpr uint32_t ORDINAL_FLAG_32 = 0x80000000;  // Bit 31
    static constexpr uint64_t ORDINAL_FLAG_64 = 0x8000000000000000ULL;  // Bit 63
    static constexpr uint16_t ORDINAL_MASK = 0xFFFF;  // Low 16 bits
};

} // namespace libexe

#endif // LIBEXE_IMPORT_DIRECTORY_PARSER_HPP
