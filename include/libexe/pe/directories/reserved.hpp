// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_PE_DIRECTORIES_RESERVED_HPP
#define LIBEXE_PE_DIRECTORIES_RESERVED_HPP

#include <libexe/export.hpp>
#include <cstdint>

namespace libexe {

/**
 * Reserved Directory
 *
 * Data directory index: 15 (IMAGE_DIRECTORY_ENTRY_RESERVED)
 *
 * From Microsoft PE/COFF Specification:
 * "Reserved, must be zero."
 *
 * This data directory entry is reserved and should not be used in any
 * PE files. Both the RVA and size fields must be zero.
 *
 * This is the last (16th) data directory entry in the PE optional header.
 * It serves as a placeholder for potential future extensions to the PE
 * format, but currently has no defined purpose.
 *
 * When validating PE files, this directory must always have:
 * - RVA = 0
 * - Size = 0
 *
 * If non-zero values are found, it may indicate:
 * - A malformed PE file
 * - A non-standard or experimental PE extension
 * - Data corruption
 * - A future PE format extension (unlikely, as the format is stable)
 */
struct LIBEXE_EXPORT reserved_directory {
    /// RVA from data directory (must always be 0)
    uint32_t rva = 0;

    /// Size from data directory (must always be 0)
    uint32_t size = 0;

    /**
     * Check if this directory is properly reserved (zero)
     * @return True if both RVA and size are zero (correct)
     */
    [[nodiscard]] bool is_reserved() const {
        return rva == 0 && size == 0;
    }

    /**
     * Check if this directory has non-zero values (invalid)
     * @return True if RVA or size are non-zero (indicates non-standard PE)
     */
    [[nodiscard]] bool is_set() const {
        return rva != 0 || size != 0;
    }
};

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

#endif // LIBEXE_PE_DIRECTORIES_RESERVED_HPP
