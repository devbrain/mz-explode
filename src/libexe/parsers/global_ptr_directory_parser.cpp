// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/parsers/global_ptr_directory_parser.hpp>

namespace libexe {

global_ptr_directory global_ptr_directory_parser::parse(
    uint32_t global_ptr_rva,
    uint32_t global_ptr_size
) {
    global_ptr_directory result;

    // The RVA field contains the global pointer value itself,
    // not a pointer to data in the file
    result.global_ptr_rva = global_ptr_rva;

    // Note: According to PE/COFF spec, the size should always be 0
    // for the global pointer directory. We don't use it.
    (void)global_ptr_size;

    return result;
}

} // namespace libexe
