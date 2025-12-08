#ifndef LIBEXE_PE_SECTION_PARSER_HPP
#define LIBEXE_PE_SECTION_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/section.hpp>
#include <libexe/pe_file.hpp>
#include <cstdint>
#include <span>
#include <vector>
#include <string_view>
#include <optional>

namespace libexe {

/**
 * PE Section Parser
 *
 * Provides comprehensive PE section analysis and data extraction.
 * Parses IMAGE_SECTION_HEADER structures and provides enhanced metadata
 * and helper functions for section analysis.
 */
class LIBEXE_EXPORT pe_section_parser {
public:
    /**
     * Parse all sections from PE file
     *
     * Reads the section table from PE headers and creates enhanced
     * pe_section structures with full metadata and data access.
     *
     * @param file_data Complete PE file data
     * @param pe_offset Offset to PE signature in file
     * @param num_sections Number of sections (from COFF header)
     * @param size_of_optional_header Size of optional header (from COFF header)
     * @return Vector of parsed sections with metadata
     */
    static std::vector<pe_section> parse_sections(
        std::span<const uint8_t> file_data,
        uint32_t pe_offset,
        uint16_t num_sections,
        uint16_t size_of_optional_header
    );

    /**
     * Classify section type based on name and characteristics
     *
     * Uses heuristics to determine section purpose:
     * - Name matching (.text, .data, .idata, etc.)
     * - Characteristics flags (code, data, resources)
     *
     * @param name Section name (up to 8 bytes)
     * @param characteristics Section characteristics flags
     * @return Classified section type
     */
    static section_type classify_section(
        std::string_view name,
        uint32_t characteristics
    );

    /**
     * Convert RVA to file offset using section table
     *
     * Finds the section containing the given RVA and computes
     * the corresponding file offset.
     *
     * @param sections All PE sections
     * @param rva Relative Virtual Address
     * @return File offset, or nullopt if RVA not in any section
     */
    static std::optional<size_t> rva_to_file_offset(
        const std::vector<pe_section>& sections,
        uint32_t rva
    );

    /**
     * Find section containing RVA
     *
     * @param sections All PE sections
     * @param rva Relative Virtual Address
     * @return Pointer to section, or nullptr if not found
     */
    static const pe_section* find_section_by_rva(
        const std::vector<pe_section>& sections,
        uint32_t rva
    );

    /**
     * Find section by name
     *
     * @param sections All PE sections
     * @param name Section name to search for (case-sensitive)
     * @return Pointer to section, or nullptr if not found
     */
    static const pe_section* find_section_by_name(
        const std::vector<pe_section>& sections,
        std::string_view name
    );

    /**
     * Extract section alignment from characteristics
     *
     * Decodes the ALIGN bits from section characteristics.
     * Returns alignment in bytes (e.g., 4096 for PAGE alignment).
     *
     * @param characteristics Section characteristics flags
     * @return Alignment in bytes (1, 2, 4, ..., 8192)
     */
    static uint32_t extract_alignment(uint32_t characteristics);

    /**
     * Get section name from IMAGE_SECTION_HEADER
     *
     * Section names are 8-byte ASCII fields, not necessarily null-terminated.
     * This function safely extracts the name.
     *
     * @param name_bytes 8-byte name field from section header
     * @return Section name as string (up to 8 characters)
     */
    static std::string get_section_name(const uint8_t* name_bytes);
};

} // namespace libexe

#endif // LIBEXE_PE_SECTION_PARSER_HPP
