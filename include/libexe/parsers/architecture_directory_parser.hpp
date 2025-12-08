// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_ARCHITECTURE_DIRECTORY_PARSER_HPP
#define LIBEXE_ARCHITECTURE_DIRECTORY_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/architecture_directory.hpp>
#include <cstdint>

namespace libexe {

/**
 * Parser for PE Architecture Directory
 *
 * The architecture directory is reserved and should always be zero.
 * This parser simply captures the RVA and size values for validation.
 */
class LIBEXE_EXPORT architecture_directory_parser {
public:
    /**
     * Parse architecture directory from data directory entry
     *
     * Note: According to PE/COFF spec, both RVA and size should be zero.
     * This parser captures the values for validation purposes.
     *
     * @param arch_rva RVA from data directory (should be 0)
     * @param arch_size Size from data directory (should be 0)
     * @return Parsed architecture directory structure
     */
    static architecture_directory parse(
        uint32_t arch_rva,
        uint32_t arch_size
    );
};

} // namespace libexe

#endif // LIBEXE_ARCHITECTURE_DIRECTORY_PARSER_HPP
