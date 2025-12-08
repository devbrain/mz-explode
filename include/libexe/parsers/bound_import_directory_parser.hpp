// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_BOUND_IMPORT_DIRECTORY_PARSER_HPP
#define LIBEXE_BOUND_IMPORT_DIRECTORY_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/bound_import_directory.hpp>
#include <libexe/section.hpp>
#include <span>
#include <cstdint>
#include <vector>

namespace libexe {

/**
 * Parser for PE Bound Import Directory (Data Directory Index 11)
 *
 * The bound import directory contains pre-resolved import addresses for
 * optimization. This parser extracts bound import descriptors and validates
 * their structure.
 *
 * Bound imports work by storing DLL timestamps. At load time, the loader
 * checks if the DLL timestamp matches. If so, the pre-resolved addresses
 * in the IAT can be used directly. If not, normal import resolution is used.
 *
 * Structure:
 * - Array of IMAGE_BOUND_IMPORT_DESCRIPTOR entries (8 bytes each)
 * - Each descriptor may be followed by IMAGE_BOUND_FORWARDER_REF entries
 * - Null-terminated (descriptor with TimeDateStamp = 0)
 * - Module names are null-terminated ASCII strings at offsets within directory
 */
class LIBEXE_EXPORT bound_import_directory_parser {
public:
    /**
     * Parse bound import directory from PE file data
     *
     * @param file_data Complete PE file data
     * @param sections Vector of parsed PE sections (for RVA to file offset conversion)
     * @param bound_import_rva RVA of bound import directory
     * @param bound_import_size Size of bound import directory in bytes
     * @return Parsed bound import directory
     * @throws std::runtime_error if parsing fails or data is invalid
     */
    static bound_import_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t bound_import_rva,
        uint32_t bound_import_size
    );

private:
    /**
     * Check if descriptor is null (marks end of array)
     * @param ptr Pointer to descriptor data (must be at least 8 bytes)
     * @return True if TimeDateStamp is zero (null descriptor)
     */
    static bool is_null_descriptor(const uint8_t* ptr);

    /**
     * Parse a single bound import descriptor
     * @param ptr Pointer to descriptor data
     * @param end End of valid data range
     * @param dir_start Start of bound import directory (for name offsets)
     * @param dir_end End of bound import directory
     * @return Parsed descriptor
     * @throws std::runtime_error if data is invalid
     */
    static bound_import_descriptor parse_descriptor(
        const uint8_t* ptr,
        const uint8_t* end,
        const uint8_t* dir_start,
        const uint8_t* dir_end
    );

    /**
     * Parse forwarder references for a descriptor
     * @param ptr Pointer to start of forwarder array
     * @param end End of valid data range
     * @param count Number of forwarders to parse
     * @param dir_start Start of bound import directory (for name offsets)
     * @param dir_end End of bound import directory
     * @return Vector of parsed forwarder references
     * @throws std::runtime_error if data is invalid
     */
    static std::vector<bound_forwarder_ref> parse_forwarders(
        const uint8_t* ptr,
        const uint8_t* end,
        uint16_t count,
        const uint8_t* dir_start,
        const uint8_t* dir_end
    );

    /**
     * Read module name at given offset
     * @param dir_start Start of bound import directory
     * @param dir_end End of bound import directory
     * @param offset Offset from dir_start to name string
     * @return Module name string
     * @throws std::runtime_error if offset is invalid or name is malformed
     */
    static std::string read_module_name(
        const uint8_t* dir_start,
        const uint8_t* dir_end,
        uint16_t offset
    );

    /**
     * Convert RVA to file offset using section table
     * @param sections Vector of PE sections
     * @param rva Relative Virtual Address
     * @return File offset, or 0 if RVA not found in any section
     */
    static uint32_t rva_to_file_offset(
        const std::vector<pe_section>& sections,
        uint32_t rva
    );
};

} // namespace libexe

#endif // LIBEXE_BOUND_IMPORT_DIRECTORY_PARSER_HPP
