#ifndef LIBEXE_IMPORT_DIRECTORY_HPP
#define LIBEXE_IMPORT_DIRECTORY_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include <string_view>

namespace libexe {

/**
 * Imported function or ordinal
 *
 * Represents a single function imported from a DLL. Can be imported
 * by name (with optional hint) or by ordinal number only.
 */
struct LIBEXE_EXPORT import_entry {
    std::string name;           // Function name (empty if imported by ordinal only)
    uint16_t ordinal;           // Ordinal number
    uint16_t hint;              // Hint index into export name table
    bool is_ordinal;            // true if imported by ordinal only, false if by name
    uint64_t iat_rva;           // RVA in Import Address Table

    /**
     * Get display name for this import
     *
     * Returns function name if available, otherwise "#ordinal"
     */
    [[nodiscard]] std::string display_name() const {
        if (is_ordinal || name.empty()) {
            return "#" + std::to_string(ordinal);
        }
        return name;
    }
};

/**
 * Imported DLL with all its functions
 *
 * Represents a single DLL that this executable imports from,
 * along with all the functions imported from that DLL.
 */
struct LIBEXE_EXPORT import_dll {
    std::string name;                     // DLL name (e.g., "kernel32.dll")
    std::vector<import_entry> functions;  // Imported functions from this DLL
    uint32_t ilt_rva;                     // Import Lookup Table RVA (OriginalFirstThunk)
    uint32_t iat_rva;                     // Import Address Table RVA (FirstThunk)
    uint32_t name_rva;                    // DLL name RVA
    uint32_t timestamp;                   // Bind timestamp (0 if not bound)
    uint32_t forwarder_chain;             // Forwarder chain (-1 if no forwarders)

    /**
     * Get number of imported functions
     */
    [[nodiscard]] size_t function_count() const {
        return functions.size();
    }

    /**
     * Find function by name
     *
     * @param function_name Function name to search for
     * @return Pointer to import entry, or nullptr if not found
     */
    [[nodiscard]] const import_entry* find_function(std::string_view function_name) const {
        for (const auto& func : functions) {
            if (func.name == function_name) {
                return &func;
            }
        }
        return nullptr;
    }

    /**
     * Check if this DLL is bound
     *
     * Bound imports have pre-calculated addresses from bind time
     */
    [[nodiscard]] bool is_bound() const {
        return timestamp != 0;
    }
};

/**
 * Complete import directory
 *
 * Contains all DLLs and functions imported by this executable.
 * Parsed from the PE import directory (data directory index 1).
 */
struct LIBEXE_EXPORT import_directory {
    std::vector<import_dll> dlls;  // All imported DLLs

    /**
     * Get number of imported DLLs
     */
    [[nodiscard]] size_t dll_count() const {
        return dlls.size();
    }

    /**
     * Get total number of imported functions across all DLLs
     */
    [[nodiscard]] size_t total_imports() const {
        size_t count = 0;
        for (const auto& dll : dlls) {
            count += dll.function_count();
        }
        return count;
    }

    /**
     * Find DLL by name
     *
     * @param dll_name DLL name to search for (case-insensitive comparison recommended)
     * @return Pointer to import DLL, or nullptr if not found
     */
    [[nodiscard]] const import_dll* find_dll(std::string_view dll_name) const {
        for (const auto& dll : dlls) {
            if (dll.name == dll_name) {
                return &dll;
            }
        }
        return nullptr;
    }

    /**
     * Check if specific function is imported
     *
     * @param dll_name DLL name (e.g., "kernel32.dll")
     * @param function_name Function name (e.g., "CreateFileW")
     * @return true if this executable imports the specified function
     */
    [[nodiscard]] bool imports_function(std::string_view dll_name, std::string_view function_name) const {
        auto dll = find_dll(dll_name);
        if (!dll) {
            return false;
        }
        return dll->find_function(function_name) != nullptr;
    }

    /**
     * Check if any DLL is bound
     */
    [[nodiscard]] bool has_bound_imports() const {
        for (const auto& dll : dlls) {
            if (dll.is_bound()) {
                return true;
            }
        }
        return false;
    }
};

} // namespace libexe

#endif // LIBEXE_IMPORT_DIRECTORY_HPP
