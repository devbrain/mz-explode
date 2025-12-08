// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_DELAY_IMPORT_DIRECTORY_HPP
#define LIBEXE_DELAY_IMPORT_DIRECTORY_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <vector>
#include <string>

namespace libexe {

/**
 * Delay Import Descriptor Attributes
 *
 * The attributes field indicates the format of the delay load descriptor.
 */
enum class delay_import_attributes : uint32_t {
    RVA_BASED = 0,      // Delay load version 1 (addresses are RVAs)
    VA_BASED = 1        // Delay load version 2 (addresses are VAs, need rebasing)
};

/**
 * Imported Function (Delay Load)
 *
 * Represents a single function imported from a delay-loaded DLL.
 * Similar to regular imports but loaded on first use.
 */
struct LIBEXE_EXPORT delay_imported_function {
    std::string name;           // Function name (if imported by name)
    uint16_t ordinal = 0;       // Function ordinal (if imported by ordinal)
    uint16_t hint = 0;          // Hint index into export name table
    bool import_by_ordinal = false; // True if imported by ordinal, false if by name

    /**
     * Check if this is an ordinal import
     */
    [[nodiscard]] bool is_ordinal() const {
        return import_by_ordinal;
    }

    /**
     * Get import identifier (name or ordinal)
     */
    [[nodiscard]] std::string identifier() const {
        if (import_by_ordinal) {
            return "Ordinal_" + std::to_string(ordinal);
        }
        return name;
    }
};

/**
 * Delay Import Descriptor
 *
 * Describes imports from a single delay-loaded DLL.
 *
 * Delay-loaded DLLs are not loaded at process startup. Instead, the OS
 * loads them on the first call to any function from that DLL. This reduces
 * startup time and memory usage.
 *
 * Reference: Microsoft PE/COFF specification, section 5.8
 */
struct LIBEXE_EXPORT delay_import_descriptor {
    uint32_t attributes = 0;                    // Delay load attributes (version)
    std::string dll_name;                       // Name of delay-loaded DLL
    uint32_t module_handle_rva = 0;             // RVA to module handle (HMODULE)
    uint32_t delay_import_address_table_rva = 0; // RVA to delay IAT
    uint32_t delay_import_name_table_rva = 0;   // RVA to delay INT
    uint32_t bound_delay_import_table_rva = 0;  // RVA to bound delay import table
    uint32_t unload_delay_import_table_rva = 0; // RVA to unload delay import table
    uint32_t time_date_stamp = 0;               // Timestamp

    std::vector<delay_imported_function> functions; // Functions imported from this DLL

    /**
     * Check if this descriptor uses RVA-based addressing
     */
    [[nodiscard]] bool is_rva_based() const {
        return attributes == static_cast<uint32_t>(delay_import_attributes::RVA_BASED);
    }

    /**
     * Check if this descriptor uses VA-based addressing
     */
    [[nodiscard]] bool is_va_based() const {
        return attributes == static_cast<uint32_t>(delay_import_attributes::VA_BASED);
    }

    /**
     * Get number of imported functions
     */
    [[nodiscard]] size_t function_count() const {
        return functions.size();
    }

    /**
     * Check if this is an empty descriptor
     */
    [[nodiscard]] bool is_empty() const {
        return dll_name.empty() && functions.empty();
    }
};

/**
 * Delay Import Directory
 *
 * Contains all delay-loaded DLL imports for the executable.
 *
 * Delay loading improves application startup time by deferring DLL loading
 * until the first call to a function from that DLL. The loader stub handles
 * the actual loading and binding when needed.
 *
 * Data directory index: 13 (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
 */
struct LIBEXE_EXPORT delay_import_directory {
    std::vector<delay_import_descriptor> descriptors;

    /**
     * Check if this is an empty delay import directory
     */
    [[nodiscard]] bool is_empty() const {
        return descriptors.empty();
    }

    /**
     * Get number of delay-loaded DLLs
     */
    [[nodiscard]] size_t dll_count() const {
        return descriptors.size();
    }

    /**
     * Get total number of delay-imported functions across all DLLs
     */
    [[nodiscard]] size_t total_function_count() const {
        size_t count = 0;
        for (const auto& desc : descriptors) {
            count += desc.function_count();
        }
        return count;
    }

    /**
     * Find descriptor for a specific DLL
     */
    [[nodiscard]] const delay_import_descriptor* find_dll(const std::string& dll_name) const {
        for (const auto& desc : descriptors) {
            if (desc.dll_name == dll_name) {
                return &desc;
            }
        }
        return nullptr;
    }

    /**
     * Get list of all delay-loaded DLL names
     */
    [[nodiscard]] std::vector<std::string> dll_names() const {
        std::vector<std::string> names;
        names.reserve(descriptors.size());
        for (const auto& desc : descriptors) {
            names.push_back(desc.dll_name);
        }
        return names;
    }
};

} // namespace libexe

#endif // LIBEXE_DELAY_IMPORT_DIRECTORY_HPP
