// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/pe/directories/architecture.hpp>

namespace libexe {

architecture_directory architecture_directory_parser::parse(
    uint32_t arch_rva,
    uint32_t arch_size
) {
    architecture_directory result;

    // Simply capture the RVA and size values
    // According to PE/COFF spec, both should be zero
    result.rva = arch_rva;
    result.size = arch_size;

    return result;
}

} // namespace libexe
