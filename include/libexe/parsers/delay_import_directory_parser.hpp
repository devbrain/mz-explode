// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_DELAY_IMPORT_DIRECTORY_PARSER_HPP
#define LIBEXE_DELAY_IMPORT_DIRECTORY_PARSER_HPP

#include <libexe/delay_import_directory.hpp>
#include <libexe/section.hpp>
#include <span>
#include <vector>
#include <cstdint>

namespace libexe {

/**
 * Delay Import Directory Parser
 *
 * Parses the PE delay import directory (data directory index 13).
 *
 * Delay imports allow DLLs to be loaded on demand (lazy loading) rather than
 * at process startup. This improves startup time and reduces memory usage.
 *
 * The delay import directory contains an array of IMAGE_DELAYLOAD_DESCRIPTOR
 * structures (32 bytes each), terminated by a null descriptor.
 *
 * There are two versions:
 * - Version 1 (attributes = 0): RVA-based (recommended, most common)
 * - Version 2 (attributes = 1): VA-based (deprecated, requires rebasing)
 */
class delay_import_directory_parser {
public:
    /**
     * Parse delay import directory from PE file data
     *
     * @param file_data Complete PE file data
     * @param sections Section headers for RVA-to-offset conversion
     * @param delay_import_rva RVA of delay import directory
     * @param delay_import_size Size of delay import directory in bytes
     * @param is_64bit True if this is a PE32+ (64-bit) file
     * @param image_base Image base address (for VA-based descriptors)
     * @return Parsed delay_import_directory structure
     * @throws std::runtime_error if parsing fails
     */
    static delay_import_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t delay_import_rva,
        uint32_t delay_import_size,
        bool is_64bit,
        uint64_t image_base
    );

private:
    /**
     * Parse a single delay import descriptor
     *
     * @param ptr Pointer to IMAGE_DELAYLOAD_DESCRIPTOR data
     * @param end Pointer to end of data
     * @param file_data Complete PE file data
     * @param sections Section headers
     * @param is_64bit True if PE32+
     * @param image_base Image base address
     * @return Parsed delay_import_descriptor
     */
    static delay_import_descriptor parse_descriptor(
        const uint8_t* ptr,
        const uint8_t* end,
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        bool is_64bit,
        uint64_t image_base
    );

    /**
     * Parse delay import name table (INT)
     *
     * @param file_data Complete PE file data
     * @param sections Section headers
     * @param int_rva RVA of delay import name table
     * @param is_64bit True if PE32+
     * @return Vector of imported functions
     */
    static std::vector<delay_imported_function> parse_delay_int(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t int_rva,
        bool is_64bit
    );

    /**
     * Parse IMAGE_IMPORT_BY_NAME structure
     *
     * @param file_data Complete PE file data
     * @param sections Section headers
     * @param name_rva RVA of IMAGE_IMPORT_BY_NAME
     * @return Imported function with name and hint
     */
    static delay_imported_function parse_import_by_name(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t name_rva
    );

    /**
     * Read null-terminated ASCII string
     *
     * @param file_data Complete PE file data
     * @param offset File offset to string
     * @param max_length Maximum string length to read
     * @return String (empty if offset invalid)
     */
    static std::string read_string(
        std::span<const uint8_t> file_data,
        size_t offset,
        size_t max_length = 256
    );

    /**
     * Convert RVA to file offset
     *
     * @param sections Section headers
     * @param rva Relative Virtual Address
     * @return File offset, or 0 if RVA is invalid
     */
    static size_t rva_to_offset(
        const std::vector<pe_section>& sections,
        uint32_t rva
    );

    /**
     * Check if descriptor is null (terminator)
     *
     * @param ptr Pointer to descriptor data (32 bytes)
     * @return True if all fields are zero
     */
    static bool is_null_descriptor(const uint8_t* ptr);
};

} // namespace libexe

#endif // LIBEXE_DELAY_IMPORT_DIRECTORY_PARSER_HPP
