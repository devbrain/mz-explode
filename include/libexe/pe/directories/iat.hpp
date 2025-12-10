// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_PE_DIRECTORIES_IAT_HPP
#define LIBEXE_PE_DIRECTORIES_IAT_HPP

#include <libexe/export.hpp>
#include <libexe/pe/section.hpp>
#include <cstdint>
#include <vector>
#include <span>

namespace libexe {

/**
 * Import Address Table Entry
 *
 * Each entry is either:
 * - For PE32: 32-bit value (RVA or ordinal)
 * - For PE32+: 64-bit value (RVA or ordinal)
 *
 * Before loading:
 * - Points to Import Name Table entry (function name)
 *
 * After loading:
 * - Contains actual function address filled in by Windows loader
 */
struct LIBEXE_EXPORT iat_entry {
    /// Raw value from IAT (address or RVA depending on load state)
    uint64_t value = 0;

    /// True if this is PE32+ (64-bit), false for PE32 (32-bit)
    bool is_64bit = false;

    /**
     * Check if entry is null (end of IAT)
     * @return True if value is 0
     */
    [[nodiscard]] bool is_null() const {
        return value == 0;
    }

    /**
     * Check if entry is import by ordinal
     * @return True if high bit is set
     */
    [[nodiscard]] bool is_ordinal() const {
        if (is_64bit) {
            return (value & 0x8000000000000000ULL) != 0;
        } else {
            return (value & 0x80000000UL) != 0;
        }
    }

    /**
     * Get ordinal number (if import by ordinal)
     * @return Ordinal value (lower 16 bits)
     */
    [[nodiscard]] uint16_t ordinal() const {
        return static_cast<uint16_t>(value & 0xFFFF);
    }

    /**
     * Get RVA of import name (if import by name)
     * @return RVA pointing to IMAGE_IMPORT_BY_NAME structure
     */
    [[nodiscard]] uint32_t name_rva() const {
        if (is_64bit) {
            return static_cast<uint32_t>(value & 0x7FFFFFFFFFFFFFFFULL);
        } else {
            return static_cast<uint32_t>(value & 0x7FFFFFFFUL);
        }
    }
};

/**
 * Import Address Table (IAT) Directory
 *
 * Data directory index: 12 (IMAGE_DIRECTORY_ENTRY_IAT)
 *
 * The IAT is an array of function pointers used for dynamic linking.
 * Before the PE file is loaded:
 * - IAT entries point to function names (via Import Name Table)
 *
 * After the PE file is loaded by Windows:
 * - Loader overwrites IAT entries with actual function addresses
 * - This is how dynamic linking works at runtime
 *
 * The IAT is referenced by the Import Directory (directory index 1).
 * Each import descriptor has an FirstThunk field pointing into the IAT.
 *
 * Note: The IAT data directory (index 12) points to the beginning of the
 * entire IAT, which may span multiple DLLs. Individual import descriptors
 * point to their own portion of the IAT.
 */
struct LIBEXE_EXPORT iat_directory {
    /// Array of IAT entries (function pointers)
    std::vector<iat_entry> entries;

    /// True if this is PE32+ (64-bit), false for PE32 (32-bit)
    bool is_64bit = false;

    /**
     * Get number of IAT entries
     * @return Number of entries (including null terminator if present)
     */
    [[nodiscard]] size_t entry_count() const {
        return entries.size();
    }

    /**
     * Get number of non-null IAT entries
     * @return Number of actual function pointers (excluding null terminators)
     */
    [[nodiscard]] size_t function_count() const {
        size_t count = 0;
        for (const auto& entry : entries) {
            if (!entry.is_null()) {
                count++;
            }
        }
        return count;
    }

    /**
     * Check if IAT is empty
     * @return True if no entries
     */
    [[nodiscard]] bool empty() const {
        return entries.empty();
    }

    /**
     * Get number of ordinal imports
     * @return Count of imports by ordinal
     */
    [[nodiscard]] size_t ordinal_import_count() const {
        size_t count = 0;
        for (const auto& entry : entries) {
            if (!entry.is_null() && entry.is_ordinal()) {
                count++;
            }
        }
        return count;
    }

    /**
     * Get number of named imports
     * @return Count of imports by name
     */
    [[nodiscard]] size_t named_import_count() const {
        size_t count = 0;
        for (const auto& entry : entries) {
            if (!entry.is_null() && !entry.is_ordinal()) {
                count++;
            }
        }
        return count;
    }
};

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

#endif // LIBEXE_PE_DIRECTORIES_IAT_HPP
