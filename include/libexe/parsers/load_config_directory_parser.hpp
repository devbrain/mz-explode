// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_LOAD_CONFIG_DIRECTORY_PARSER_HPP
#define LIBEXE_LOAD_CONFIG_DIRECTORY_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/load_config_directory.hpp>
#include <libexe/section.hpp>
#include <cstdint>
#include <span>
#include <vector>

namespace libexe {

/**
 * Load Configuration Directory Parser
 *
 * Parses PE Load Configuration Directory (data directory index 10) to extract
 * runtime configuration and security features.
 *
 * The load config structure has evolved significantly across Windows versions.
 * The parser handles variable structure sizes by:
 * 1. Reading the Size field first
 * 2. Only reading fields that fit within the reported size
 * 3. Gracefully handling missing fields (leaving them as zero)
 *
 * Important security features:
 * - Security cookie (stack buffer overrun detection)
 * - SafeSEH (32-bit structured exception handling)
 * - Control Flow Guard (CFG)
 * - eXtended Flow Guard (XFG)
 * - Cast Guard
 */
class LIBEXE_EXPORT load_config_directory_parser {
public:
    /**
     * Parse load configuration directory from PE file
     *
     * Reads IMAGE_LOAD_CONFIG_DIRECTORY32/64 structure.
     * Handles variable structure sizes across Windows versions.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections (for RVA to offset conversion)
     * @param load_config_rva RVA to load config directory
     * @param load_config_size Size of load config directory
     * @param is_64bit true for PE32+ (64-bit), false for PE32 (32-bit)
     * @return Parsed load configuration directory
     * @throws std::runtime_error if load config directory is malformed
     */
    static load_config_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t load_config_rva,
        uint32_t load_config_size,
        bool is_64bit
    );

private:
    /**
     * Parse 32-bit load config directory
     *
     * Reads IMAGE_LOAD_CONFIG_DIRECTORY32 with variable size handling.
     *
     * @param ptr Pointer to load config data
     * @param end End of data
     * @param structure_size Size field from structure (indicates available fields)
     * @return Parsed load config directory
     */
    static load_config_directory parse_32bit(
        const uint8_t* ptr,
        const uint8_t* end,
        uint32_t structure_size
    );

    /**
     * Parse 64-bit load config directory
     *
     * Reads IMAGE_LOAD_CONFIG_DIRECTORY64 with variable size handling.
     *
     * @param ptr Pointer to load config data
     * @param end End of data
     * @param structure_size Size field from structure (indicates available fields)
     * @return Parsed load config directory
     */
    static load_config_directory parse_64bit(
        const uint8_t* ptr,
        const uint8_t* end,
        uint32_t structure_size
    );

    /**
     * Read uint32 at offset if available
     *
     * Helper to safely read fields based on structure size.
     *
     * @param ptr Base pointer
     * @param offset Offset from base
     * @param structure_size Total structure size
     * @return Value if available, 0 otherwise
     */
    static uint32_t read_uint32_if_available(
        const uint8_t* ptr,
        size_t offset,
        uint32_t structure_size
    );

    /**
     * Read uint64 at offset if available
     *
     * Helper to safely read fields based on structure size.
     *
     * @param ptr Base pointer
     * @param offset Offset from base
     * @param structure_size Total structure size
     * @return Value if available, 0 otherwise
     */
    static uint64_t read_uint64_if_available(
        const uint8_t* ptr,
        size_t offset,
        uint32_t structure_size
    );

    /**
     * Read uint16 at offset if available
     *
     * Helper to safely read fields based on structure size.
     *
     * @param ptr Base pointer
     * @param offset Offset from base
     * @param structure_size Total structure size
     * @return Value if available, 0 otherwise
     */
    static uint16_t read_uint16_if_available(
        const uint8_t* ptr,
        size_t offset,
        uint32_t structure_size
    );

    /**
     * Convert RVA to file offset
     *
     * Helper that wraps pe_section_parser::rva_to_file_offset()
     * and returns 0 if RVA is not in any section.
     *
     * @param sections Parsed PE sections
     * @param rva RVA to convert
     * @return File offset or 0 if not mapped
     */
    static size_t rva_to_offset(
        const std::vector<pe_section>& sections,
        uint32_t rva
    );
};

} // namespace libexe

#endif // LIBEXE_LOAD_CONFIG_DIRECTORY_PARSER_HPP
