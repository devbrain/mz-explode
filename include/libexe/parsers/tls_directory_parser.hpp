#ifndef LIBEXE_TLS_DIRECTORY_PARSER_HPP
#define LIBEXE_TLS_DIRECTORY_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/tls_directory.hpp>
#include <libexe/section.hpp>
#include <cstdint>
#include <span>
#include <vector>

namespace libexe {

/**
 * TLS Directory Parser
 *
 * Parses PE Thread Local Storage (TLS) directory (data directory index 9)
 * to extract TLS configuration and callback functions.
 *
 * TLS directories use virtual addresses (VAs) instead of RVAs, so we need
 * the image base to convert them. There are two formats:
 * - PE32: 32-bit pointers (IMAGE_TLS_DIRECTORY32)
 * - PE32+: 64-bit pointers (IMAGE_TLS_DIRECTORY64)
 */
class LIBEXE_EXPORT tls_directory_parser {
public:
    /**
     * Parse TLS directory from PE file
     *
     * Reads IMAGE_TLS_DIRECTORY and TLS callback array.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections (for VA to offset conversion)
     * @param tls_dir_rva RVA to TLS directory
     * @param tls_dir_size Size of TLS directory
     * @param is_64bit true for PE32+ (64-bit), false for PE32 (32-bit)
     * @param image_base Image base address (for VA to RVA conversion)
     * @return Parsed TLS directory with callbacks
     * @throws std::runtime_error if TLS directory is malformed
     */
    static tls_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t tls_dir_rva,
        uint32_t tls_dir_size,
        bool is_64bit,
        uint64_t image_base
    );

private:
    /**
     * Parse TLS callbacks array
     *
     * Reads null-terminated array of callback function pointers.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections
     * @param callbacks_va Virtual address of callback array
     * @param is_64bit true for 64-bit pointers, false for 32-bit
     * @param image_base Image base address
     * @return Vector of TLS callbacks
     */
    static std::vector<tls_callback> parse_callbacks(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint64_t callbacks_va,
        bool is_64bit,
        uint64_t image_base
    );

    /**
     * Convert virtual address to file offset
     *
     * TLS uses VAs (not RVAs), so we need to convert VA to RVA first,
     * then RVA to file offset.
     *
     * @param sections Parsed PE sections
     * @param va Virtual address
     * @param image_base Image base address
     * @return File offset
     * @throws std::runtime_error if VA is invalid
     */
    static size_t va_to_offset(
        const std::vector<pe_section>& sections,
        uint64_t va,
        uint64_t image_base
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

#endif // LIBEXE_TLS_DIRECTORY_PARSER_HPP
