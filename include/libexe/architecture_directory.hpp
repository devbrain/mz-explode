// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_ARCHITECTURE_DIRECTORY_HPP
#define LIBEXE_ARCHITECTURE_DIRECTORY_HPP

#include <libexe/export.hpp>
#include <cstdint>

namespace libexe {

/**
 * Architecture Directory
 *
 * Data directory index: 7 (IMAGE_DIRECTORY_ENTRY_ARCHITECTURE)
 *
 * From Microsoft PE/COFF Specification:
 * "Reserved, must be zero."
 *
 * This data directory entry is reserved and should not be used in any
 * modern PE files. Both the RVA and size fields should be zero.
 *
 * Historical note: This may have been intended for architecture-specific
 * data in early PE implementations, but it was never used and is now
 * officially reserved.
 *
 * When validating PE files, this directory should always have:
 * - RVA = 0
 * - Size = 0
 *
 * If non-zero values are found, it may indicate:
 * - A malformed PE file
 * - A non-standard or experimental PE extension
 * - Data corruption
 */
struct LIBEXE_EXPORT architecture_directory {
    /// RVA from data directory (should always be 0)
    uint32_t rva = 0;

    /// Size from data directory (should always be 0)
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

} // namespace libexe

#endif // LIBEXE_ARCHITECTURE_DIRECTORY_HPP
