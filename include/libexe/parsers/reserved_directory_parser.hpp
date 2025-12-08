// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_RESERVED_DIRECTORY_PARSER_HPP
#define LIBEXE_RESERVED_DIRECTORY_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/reserved_directory.hpp>
#include <cstdint>

namespace libexe {

/**
 * Parser for PE Reserved Directory
 *
 * The reserved directory is reserved and must always be zero.
 * This parser simply captures the RVA and size values for validation.
 */
class LIBEXE_EXPORT reserved_directory_parser {
public:
    /**
     * Parse reserved directory from data directory entry
     *
     * Note: According to PE/COFF spec, both RVA and size must be zero.
     * This parser captures the values for validation purposes.
     *
     * @param reserved_rva RVA from data directory (must be 0)
     * @param reserved_size Size from data directory (must be 0)
     * @return Parsed reserved directory structure
     */
    static reserved_directory parse(
        uint32_t reserved_rva,
        uint32_t reserved_size
    );
};

} // namespace libexe

#endif // LIBEXE_RESERVED_DIRECTORY_PARSER_HPP
