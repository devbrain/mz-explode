#ifndef LIBEXE_BASE_RELOCATION_PARSER_HPP
#define LIBEXE_BASE_RELOCATION_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/base_relocation.hpp>
#include <libexe/section.hpp>
#include <cstdint>
#include <span>
#include <vector>

namespace libexe {

/**
 * Base Relocation Parser
 *
 * Parses PE base relocation directory (data directory index 5) to extract
 * all base relocations used for ASLR (Address Space Layout Randomization).
 *
 * Base relocations allow the Windows loader to adjust addresses when a module
 * is loaded at a different address than its preferred ImageBase. This enables
 * ASLR security features.
 *
 * Structure:
 * - Series of IMAGE_BASE_RELOCATION blocks (variable size)
 * - Each block covers one 4KB page
 * - Each block contains header + array of type/offset entries
 * - Blocks are contiguous until all relocation data is consumed
 */
class LIBEXE_EXPORT base_relocation_parser {
public:
    /**
     * Parse base relocation directory from PE file
     *
     * Reads all IMAGE_BASE_RELOCATION blocks and their associated
     * type/offset entries to extract complete relocation information.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections (for RVA to offset conversion)
     * @param reloc_dir_rva RVA to base relocation directory
     * @param reloc_dir_size Size of relocation directory in bytes
     * @return Parsed base relocation directory with all blocks
     * @throws std::runtime_error if relocation directory is malformed
     */
    static base_relocation_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t reloc_dir_rva,
        uint32_t reloc_dir_size
    );

private:
    /**
     * Parse single relocation block
     *
     * Reads IMAGE_BASE_RELOCATION header and all type/offset entries
     * for one 4KB page.
     *
     * @param data Pointer to block start
     * @param end Pointer to end of relocation data
     * @param bytes_read Output: number of bytes consumed
     * @return Parsed relocation block
     * @throws std::runtime_error if block is malformed
     */
    static relocation_block parse_block(
        const uint8_t* data,
        const uint8_t* end,
        size_t& bytes_read
    );

    /**
     * Parse type/offset entry
     *
     * Extracts relocation type and offset from 16-bit entry.
     *
     * @param type_offset 16-bit type/offset value
     * @param page_rva Base RVA of the page
     * @return Parsed relocation entry
     */
    static relocation_entry parse_type_offset(
        uint16_t type_offset,
        uint32_t page_rva
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

    // Bit masks for type/offset entry
    static constexpr uint16_t OFFSET_MASK = 0x0FFF;  // Low 12 bits (offset)
    static constexpr uint16_t TYPE_SHIFT = 12;       // High 4 bits (type)
};

} // namespace libexe

#endif // LIBEXE_BASE_RELOCATION_PARSER_HPP
