// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_PE_DIRECTORIES_GLOBAL_PTR_HPP
#define LIBEXE_PE_DIRECTORIES_GLOBAL_PTR_HPP

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

#endif // LIBEXE_PE_DIRECTORIES_GLOBAL_PTR_HPP
