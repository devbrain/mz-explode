// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_IAT_DIRECTORY_PARSER_HPP
#define LIBEXE_IAT_DIRECTORY_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/iat_directory.hpp>
#include <libexe/section.hpp>
#include <span>
#include <cstdint>
#include <vector>

namespace libexe {

/**
 * Parser for PE Import Address Table (IAT)
 *
 * The IAT is an array of function pointers (32-bit or 64-bit) used for
 * dynamic linking. The Windows loader overwrites these at load time with
 * actual function addresses.
 */
class LIBEXE_EXPORT iat_directory_parser {
public:
    /**
     * Parse IAT directory from PE file data
     *
     * @param file_data Complete PE file data
     * @param sections Section headers for RVA to file offset conversion
     * @param iat_rva RVA of IAT array
     * @param iat_size Size of IAT array in bytes
     * @param is_64bit True for PE32+ (64-bit), false for PE32 (32-bit)
     * @return Parsed IAT directory structure
     * @throws std::runtime_error if IAT is invalid or cannot be parsed
     */
    static iat_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t iat_rva,
        uint32_t iat_size,
        bool is_64bit
    );
};

} // namespace libexe

#endif // LIBEXE_IAT_DIRECTORY_PARSER_HPP
