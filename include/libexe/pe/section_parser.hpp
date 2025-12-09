// libexe - Modern executable file analysis library
// PE Section Parser

#ifndef LIBEXE_PE_SECTION_PARSER_HPP
#define LIBEXE_PE_SECTION_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/pe/section.hpp>
#include <cstdint>
#include <span>
#include <vector>
#include <string_view>
#include <optional>

namespace libexe {

// Forward declaration
class pe_file;

/**
 * PE Section Parser
 *
 * Provides comprehensive PE section analysis and data extraction.
 */
class LIBEXE_EXPORT pe_section_parser {
public:
    /**
     * Parse all sections from PE file
     */
    static std::vector<pe_section> parse_sections(
        std::span<const uint8_t> file_data,
        uint32_t pe_offset,
        uint16_t num_sections,
        uint16_t size_of_optional_header,
        uint32_t file_alignment = 0x200
    );

    /**
     * Classify section type based on name and characteristics
     */
    static section_type classify_section(
        std::string_view name,
        uint32_t characteristics
    );

    /**
     * Convert RVA to file offset using section table
     */
    static std::optional<size_t> rva_to_file_offset(
        const std::vector<pe_section>& sections,
        uint32_t rva
    );

    /**
     * Find section containing RVA
     */
    static const pe_section* find_section_by_rva(
        const std::vector<pe_section>& sections,
        uint32_t rva
    );

    /**
     * Find section by name
     */
    static const pe_section* find_section_by_name(
        const std::vector<pe_section>& sections,
        std::string_view name
    );

    /**
     * Extract section alignment from characteristics
     */
    static uint32_t extract_alignment(uint32_t characteristics);

    /**
     * Get section name from IMAGE_SECTION_HEADER
     */
    static std::string get_section_name(const uint8_t* name_bytes);
};

} // namespace libexe

#endif // LIBEXE_PE_SECTION_PARSER_HPP
