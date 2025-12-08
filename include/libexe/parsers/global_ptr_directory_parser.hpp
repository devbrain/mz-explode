// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_GLOBAL_PTR_DIRECTORY_PARSER_HPP
#define LIBEXE_GLOBAL_PTR_DIRECTORY_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/global_ptr_directory.hpp>
#include <cstdint>

namespace libexe {

/**
 * Parser for PE Global Pointer Directory
 *
 * The global pointer directory is specific to IA64 (Itanium) architecture.
 * Unlike other data directories, the RVA field contains the actual value
 * to be stored in the global pointer register, not a pointer to data.
 *
 * The size field should always be 0.
 */
class LIBEXE_EXPORT global_ptr_directory_parser {
public:
    /**
     * Parse global pointer directory from data directory entry
     *
     * Note: This directory doesn't point to data in the file. The RVA
     * field itself is the value to be used as the global pointer.
     *
     * @param global_ptr_rva RVA from data directory (the GP value itself)
     * @param global_ptr_size Size from data directory (should be 0)
     * @return Parsed global pointer directory structure
     */
    static global_ptr_directory parse(
        uint32_t global_ptr_rva,
        uint32_t global_ptr_size
    );
};

} // namespace libexe

#endif // LIBEXE_GLOBAL_PTR_DIRECTORY_PARSER_HPP
