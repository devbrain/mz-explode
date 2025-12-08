// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_DEBUG_DIRECTORY_PARSER_HPP
#define LIBEXE_DEBUG_DIRECTORY_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/debug_directory.hpp>
#include <libexe/section.hpp>
#include <cstdint>
#include <span>
#include <vector>

namespace libexe {

/**
 * Debug Directory Parser
 *
 * Parses PE Debug Directory (data directory index 6) to extract
 * debug information entries including CodeView (PDB) information.
 *
 * The debug directory contains an array of IMAGE_DEBUG_DIRECTORY entries,
 * each describing a different type of debug information (CodeView, FPO, etc.).
 *
 * Most executables have at least one CodeView entry containing PDB file path.
 */
class LIBEXE_EXPORT debug_directory_parser {
public:
    /**
     * Parse debug directory from PE file
     *
     * Reads array of IMAGE_DEBUG_DIRECTORY entries and their associated data.
     * For CodeView entries, parses PDB 7.0 (RSDS) or PDB 2.0 (NB10) format.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections (for RVA to offset conversion)
     * @param debug_dir_rva RVA to debug directory
     * @param debug_dir_size Size of debug directory (multiple of 28 bytes)
     * @return Parsed debug directory with all entries
     * @throws std::runtime_error if debug directory is malformed
     */
    static debug_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t debug_dir_rva,
        uint32_t debug_dir_size
    );

private:
    /**
     * Parse a single debug entry
     *
     * Reads IMAGE_DEBUG_DIRECTORY and parses associated debug data.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections
     * @param ptr Pointer to IMAGE_DEBUG_DIRECTORY
     * @param end End of file data
     * @return Parsed debug entry
     */
    static debug_entry parse_entry(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        const uint8_t*& ptr,
        const uint8_t* end
    );

    /**
     * Parse CodeView debug data
     *
     * Reads CodeView signature and parses PDB 7.0 (RSDS) or PDB 2.0 (NB10).
     *
     * @param file_data Complete PE file data
     * @param offset File offset to CodeView data
     * @param size Size of CodeView data
     * @param entry Debug entry to populate
     */
    static void parse_codeview_data(
        std::span<const uint8_t> file_data,
        size_t offset,
        uint32_t size,
        debug_entry& entry
    );

    /**
     * Parse CodeView PDB 7.0 (RSDS)
     *
     * Modern PDB format with GUID.
     *
     * @param ptr Pointer to CV_INFO_PDB70
     * @param end End of data
     * @return Parsed PDB 7.0 info
     */
    static codeview_pdb70 parse_pdb70(
        const uint8_t* ptr,
        const uint8_t* end
    );

    /**
     * Parse CodeView PDB 2.0 (NB10)
     *
     * Older PDB format with timestamp signature.
     *
     * @param ptr Pointer to CV_INFO_PDB20
     * @param end End of data
     * @return Parsed PDB 2.0 info
     */
    static codeview_pdb20 parse_pdb20(
        const uint8_t* ptr,
        const uint8_t* end
    );

    /**
     * Read null-terminated string
     *
     * Reads ANSI string until null terminator or end of data.
     *
     * @param ptr Pointer to string start
     * @param end End of data
     * @return Parsed string
     */
    static std::string read_null_terminated_string(
        const uint8_t* ptr,
        const uint8_t* end
    );

    /**
     * Convert RVA to file offset
     *
     * Helper that wraps pe_section_parser::rva_to_file_offset()
     * and returns 0 if RVA is not in any section (debug data may not be mapped).
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

#endif // LIBEXE_DEBUG_DIRECTORY_PARSER_HPP
