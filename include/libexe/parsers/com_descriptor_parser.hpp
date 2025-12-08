// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_COM_DESCRIPTOR_PARSER_HPP
#define LIBEXE_COM_DESCRIPTOR_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/com_descriptor.hpp>
#include <libexe/section.hpp>
#include <span>
#include <cstdint>
#include <vector>

namespace libexe {

/**
 * Parser for PE COM Descriptor (CLR Runtime Header) - Data Directory Index 14
 *
 * The COM descriptor (IMAGE_COR20_HEADER) is present in all .NET assemblies.
 * It describes the Common Language Runtime (CLR) metadata for managed code.
 *
 * This parser extracts:
 * - CLR version information
 * - Metadata location and size
 * - Assembly flags (IL-only, 32-bit required, strong-name signed, etc.)
 * - Entry point (managed token or native RVA)
 * - Managed resources location
 * - Strong name signature location
 * - VTable fixups for COM interop
 *
 * The presence of a valid COM descriptor indicates that the PE file is a
 * .NET assembly that requires the CLR to execute.
 */
class LIBEXE_EXPORT com_descriptor_parser {
public:
    /**
     * Parse COM descriptor from PE file data
     *
     * @param file_data Complete PE file data
     * @param sections Vector of parsed PE sections (for RVA to file offset conversion)
     * @param com_descriptor_rva RVA of COM descriptor
     * @param com_descriptor_size Size of COM descriptor (usually 72 bytes)
     * @return Parsed COM descriptor
     * @throws std::runtime_error if parsing fails or data is invalid
     */
    static com_descriptor parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t com_descriptor_rva,
        uint32_t com_descriptor_size
    );

private:
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

#endif // LIBEXE_COM_DESCRIPTOR_PARSER_HPP
