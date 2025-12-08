// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_GLOBAL_PTR_DIRECTORY_HPP
#define LIBEXE_GLOBAL_PTR_DIRECTORY_HPP

#include <libexe/export.hpp>
#include <cstdint>

namespace libexe {

/**
 * Global Pointer Directory
 *
 * Data directory index: 8 (IMAGE_DIRECTORY_ENTRY_GLOBALPTR)
 *
 * The global pointer directory contains the RVA of the value to be stored
 * in the global pointer register. This is specific to IA64 (Itanium)
 * architecture executables.
 *
 * From Microsoft PE/COFF Specification:
 * "The RVA in this data directory is the address of a value to be stored
 * in the global pointer register. The size must be set to 0."
 *
 * This directory is rarely used and only applies to IA64 executables.
 * Most modern PE files (x86, x64, ARM) will not have this directory set.
 *
 * Note: The size field in the data directory should always be 0.
 * The RVA field contains the actual global pointer value (not a pointer
 * to data).
 */
struct LIBEXE_EXPORT global_ptr_directory {
    /// RVA of global pointer value (IA64 only)
    uint32_t global_ptr_rva = 0;

    /**
     * Check if global pointer is set
     * @return True if global_ptr_rva is non-zero
     */
    [[nodiscard]] bool is_set() const {
        return global_ptr_rva != 0;
    }

    /**
     * Check if this is valid
     * @return True if RVA is non-zero (indicating an IA64 executable)
     */
    [[nodiscard]] bool is_valid() const {
        return global_ptr_rva != 0;
    }
};

} // namespace libexe

#endif // LIBEXE_GLOBAL_PTR_DIRECTORY_HPP
