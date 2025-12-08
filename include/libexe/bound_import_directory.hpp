// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_BOUND_IMPORT_DIRECTORY_HPP
#define LIBEXE_BOUND_IMPORT_DIRECTORY_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <string>
#include <vector>

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

} // namespace libexe

#endif // LIBEXE_BOUND_IMPORT_DIRECTORY_HPP
