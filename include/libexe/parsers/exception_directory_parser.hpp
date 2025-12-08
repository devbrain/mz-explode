// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_EXCEPTION_DIRECTORY_PARSER_HPP
#define LIBEXE_EXCEPTION_DIRECTORY_PARSER_HPP

#include <libexe/exception_directory.hpp>
#include <libexe/section.hpp>
#include <span>
#include <vector>
#include <cstdint>

namespace libexe {

/**
 * Exception Directory Parser
 *
 * Parses the PE exception directory (data directory index 3).
 *
 * The exception directory contains exception handling information:
 * - For x64: Array of RUNTIME_FUNCTION entries (IMAGE_RUNTIME_FUNCTION_ENTRY)
 * - For ARM/ARM64: Procedure data (PDATA) entries
 * - For x86: Not used (stack-based exception handling)
 *
 * This parser supports x64 exception tables. Each RUNTIME_FUNCTION entry
 * is 12 bytes and describes the exception handling for one function.
 */
class exception_directory_parser {
public:
    /**
     * Parse exception directory from PE file data
     *
     * @param file_data Complete PE file data
     * @param sections Section headers for RVA-to-offset conversion
     * @param exception_rva RVA of exception directory
     * @param exception_size Size of exception directory in bytes
     * @param is_64bit True if this is a PE32+ (64-bit) file
     * @return Parsed exception_directory structure
     * @throws std::runtime_error if parsing fails
     */
    static exception_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t exception_rva,
        uint32_t exception_size,
        bool is_64bit
    );

private:
    /**
     * Parse x64 exception directory (array of RUNTIME_FUNCTION entries)
     *
     * @param ptr Pointer to exception directory data
     * @param end Pointer to end of data
     * @param entry_count Number of RUNTIME_FUNCTION entries
     * @return Vector of runtime_function entries
     */
    static std::vector<runtime_function> parse_x64_runtime_functions(
        const uint8_t* ptr,
        const uint8_t* end,
        size_t entry_count
    );

    /**
     * Parse a single RUNTIME_FUNCTION entry
     *
     * @param ptr Pointer to RUNTIME_FUNCTION data (12 bytes)
     * @param end Pointer to end of data
     * @return runtime_function entry
     */
    static runtime_function parse_runtime_function_entry(
        const uint8_t* ptr,
        const uint8_t* end
    );

    /**
     * Parse UNWIND_INFO structure (optional, for detailed analysis)
     *
     * Note: This is optional and not called by default. The UNWIND_INFO
     * structure is variable-length and complex. Most applications only
     * need the RUNTIME_FUNCTION entries.
     *
     * @param file_data Complete PE file data
     * @param sections Section headers for RVA-to-offset conversion
     * @param unwind_info_rva RVA of UNWIND_INFO structure
     * @return Parsed unwind_info structure
     */
    static unwind_info parse_unwind_info(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t unwind_info_rva
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
};

} // namespace libexe

#endif // LIBEXE_EXCEPTION_DIRECTORY_PARSER_HPP
