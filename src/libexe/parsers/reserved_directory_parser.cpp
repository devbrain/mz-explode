// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/pe/directories/reserved.hpp>

namespace libexe {

reserved_directory reserved_directory_parser::parse(
    uint32_t reserved_rva,
    uint32_t reserved_size
) {
    reserved_directory result;

    // Simply capture the RVA and size values
    // According to PE/COFF spec, both must be zero
    result.rva = reserved_rva;
    result.size = reserved_size;

    return result;
}

} // namespace libexe
