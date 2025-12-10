// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_PE_DIRECTORIES_BOUND_IMPORT_HPP
#define LIBEXE_PE_DIRECTORIES_BOUND_IMPORT_HPP

#include <libexe/export.hpp>
#include <libexe/pe/section.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include <span>

namespace libexe {

/**
 * Bound Forwarder Reference
 *
 * Represents a forwarder reference in a bound import descriptor.
 * Forwarders redirect imports from one DLL to another (e.g., KERNEL32 -> NTDLL).
 */
struct LIBEXE_EXPORT bound_forwarder_ref {
    /// Timestamp of the forwarder DLL
    uint32_t time_date_stamp = 0;

    /// Offset to forwarder DLL name (relative to bound import directory start)
    uint16_t offset_module_name = 0;

    /// Reserved, should be zero
    uint16_t reserved = 0;

    /// Name of the forwarder DLL
    std::string module_name;

    /**
     * Check if this forwarder reference is valid
     * @return True if module name is non-empty
     */
    [[nodiscard]] bool is_valid() const {
        return !module_name.empty();
    }
};

/**
 * Bound Import Descriptor
 *
 * Represents a bound import for a single DLL.
 * Contains timestamp and module name for validation.
 *
 * Binding is an optimization that pre-resolves import addresses at bind time
 * (after linking but before distribution). At load time, the loader checks if
 * the DLL timestamp matches. If so, the pre-resolved addresses can be used
 * directly, avoiding the overhead of symbol lookup.
 *
 * If timestamps don't match (DLL was updated), the loader falls back to normal
 * import resolution via the import directory.
 */
struct LIBEXE_EXPORT bound_import_descriptor {
    /// Timestamp of the bound DLL (for validation)
    uint32_t time_date_stamp = 0;

    /// Offset to DLL name (relative to bound import directory start)
    uint16_t offset_module_name = 0;

    /// Number of forwarder references for this module
    uint16_t number_of_module_forwarder_refs = 0;

    /// Name of the bound DLL
    std::string module_name;

    /// Forwarder references (redirected imports)
    std::vector<bound_forwarder_ref> forwarder_refs;

    /**
     * Check if this descriptor is valid
     * @return True if module name is non-empty
     */
    [[nodiscard]] bool is_valid() const {
        return !module_name.empty();
    }

    /**
     * Get number of forwarder references
     * @return Count of forwarder references
     */
    [[nodiscard]] size_t forwarder_count() const {
        return forwarder_refs.size();
    }

    /**
     * Check if this descriptor has forwarder references
     * @return True if at least one forwarder exists
     */
    [[nodiscard]] bool has_forwarders() const {
        return !forwarder_refs.empty();
    }
};

/**
 * Bound Import Directory
 *
 * Contains pre-bound import information for optimization.
 * Data directory index: 11 (IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)
 *
 * Bound imports are an optional optimization. Not all executables have them.
 * Modern executables often skip binding due to ASLR (Address Space Layout
 * Randomization), which makes pre-resolved addresses invalid.
 *
 * The bound import directory is an array of IMAGE_BOUND_IMPORT_DESCRIPTOR
 * structures, terminated by a null entry (timestamp = 0).
 */
struct LIBEXE_EXPORT bound_import_directory {
    /// Bound import descriptors (one per DLL)
    std::vector<bound_import_descriptor> descriptors;

    /**
     * Get number of bound DLLs
     * @return Count of bound import descriptors
     */
    [[nodiscard]] size_t dll_count() const {
        return descriptors.size();
    }

    /**
     * Check if directory is empty
     * @return True if no descriptors exist
     */
    [[nodiscard]] bool empty() const {
        return descriptors.empty();
    }

    /**
     * Find a bound descriptor by DLL name (case-insensitive)
     * @param dll_name Name of DLL to find (e.g., "KERNEL32.dll")
     * @return Pointer to descriptor if found, nullptr otherwise
     */
    [[nodiscard]] const bound_import_descriptor* find_dll(const std::string& dll_name) const;

    /**
     * Get list of all bound DLL names
     * @return Vector of DLL names
     */
    [[nodiscard]] std::vector<std::string> dll_names() const;

    /**
     * Check if any descriptors have forwarder references
     * @return True if at least one descriptor has forwarders
     */
    [[nodiscard]] bool has_forwarders() const;

    /**
     * Get total count of forwarder references across all descriptors
     * @return Total forwarder count
     */
    [[nodiscard]] size_t total_forwarder_count() const;
};

/**
 * Parser for PE Bound Import Directory (Data Directory Index 11)
 *
 * The bound import directory contains pre-resolved import addresses for
 * optimization. This parser extracts bound import descriptors and validates
 * their structure.
 *
 * Bound imports work by storing DLL timestamps. At load time, the loader
 * checks if the DLL timestamp matches. If so, the pre-resolved addresses
 * in the IAT can be used directly. If not, normal import resolution is used.
 *
 * Structure:
 * - Array of IMAGE_BOUND_IMPORT_DESCRIPTOR entries (8 bytes each)
 * - Each descriptor may be followed by IMAGE_BOUND_FORWARDER_REF entries
 * - Null-terminated (descriptor with TimeDateStamp = 0)
 * - Module names are null-terminated ASCII strings at offsets within directory
 */
class LIBEXE_EXPORT bound_import_directory_parser {
public:
    /**
     * Parse bound import directory from PE file data
     *
     * @param file_data Complete PE file data
     * @param sections Vector of parsed PE sections (for RVA to file offset conversion)
     * @param bound_import_rva RVA of bound import directory
     * @param bound_import_size Size of bound import directory in bytes
     * @return Parsed bound import directory
     * @throws std::runtime_error if parsing fails or data is invalid
     */
    static bound_import_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t bound_import_rva,
        uint32_t bound_import_size
    );

private:
    /**
     * Check if descriptor is null (marks end of array)
     * @param ptr Pointer to descriptor data (must be at least 8 bytes)
     * @return True if TimeDateStamp is zero (null descriptor)
     */
    static bool is_null_descriptor(const uint8_t* ptr);

    /**
     * Parse a single bound import descriptor
     * @param ptr Pointer to descriptor data
     * @param end End of valid data range
     * @param dir_start Start of bound import directory (for name offsets)
     * @param dir_end End of bound import directory
     * @return Parsed descriptor
     * @throws std::runtime_error if data is invalid
     */
    static bound_import_descriptor parse_descriptor(
        const uint8_t* ptr,
        const uint8_t* end,
        const uint8_t* dir_start,
        const uint8_t* dir_end
    );

    /**
     * Parse forwarder references for a descriptor
     * @param ptr Pointer to start of forwarder array
     * @param end End of valid data range
     * @param count Number of forwarders to parse
     * @param dir_start Start of bound import directory (for name offsets)
     * @param dir_end End of bound import directory
     * @return Vector of parsed forwarder references
     * @throws std::runtime_error if data is invalid
     */
    static std::vector<bound_forwarder_ref> parse_forwarders(
        const uint8_t* ptr,
        const uint8_t* end,
        uint16_t count,
        const uint8_t* dir_start,
        const uint8_t* dir_end
    );

    /**
     * Read module name at given offset
     * @param dir_start Start of bound import directory
     * @param dir_end End of bound import directory
     * @param offset Offset from dir_start to name string
     * @return Module name string
     * @throws std::runtime_error if offset is invalid or name is malformed
     */
    static std::string read_module_name(
        const uint8_t* dir_start,
        const uint8_t* dir_end,
        uint16_t offset
    );

    /**
     * Convert RVA to file offset using section table
     * @param sections Vector of PE sections
     * @param rva Relative Virtual Address
     * @return File offset, or 0 if RVA not found in any section
     */
    static uint32_t rva_to_file_offset(
        const std::vector<pe_section>& sections,
        uint32_t rva
    );
};

} // namespace libexe

#endif // LIBEXE_PE_DIRECTORIES_BOUND_IMPORT_HPP
