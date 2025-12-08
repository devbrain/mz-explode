#ifndef LIBEXE_EXPORT_DIRECTORY_HPP
#define LIBEXE_EXPORT_DIRECTORY_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include <string_view>
#include <optional>

namespace libexe {

/**
 * Exported function or ordinal
 *
 * Represents a single function exported by a DLL or executable.
 * Functions can be exported by name, by ordinal, or both.
 * Some exports are "forwarders" that redirect to another DLL.
 */
struct LIBEXE_EXPORT export_entry {
    std::string name;           // Function name (empty if exported by ordinal only)
    uint16_t ordinal;           // Ordinal number (offset from base)
    uint32_t rva;               // RVA to function code (or forwarder string if is_forwarder)
    bool has_name;              // true if exported by name
    bool is_forwarder;          // true if this is a forwarder (redirects to another DLL)
    std::string forwarder_name; // Forwarder string (e.g., "NTDLL.RtlAllocateHeap")

    /**
     * Get display name for this export
     *
     * Returns function name if available, otherwise "Ordinal ordinal"
     */
    [[nodiscard]] std::string display_name() const {
        if (has_name && !name.empty()) {
            return name;
        }
        return "Ordinal " + std::to_string(ordinal);
    }

    /**
     * Get full export identifier
     *
     * Returns "name (ordinal N)" or "Ordinal N" if no name
     */
    [[nodiscard]] std::string full_name() const {
        if (has_name && !name.empty()) {
            return name + " (ordinal " + std::to_string(ordinal) + ")";
        }
        return "Ordinal " + std::to_string(ordinal);
    }
};

/**
 * Complete export directory
 *
 * Contains all functions exported by a DLL or executable.
 * Parsed from the PE export directory (data directory index 0).
 */
struct LIBEXE_EXPORT export_directory {
    std::string module_name;          // DLL/module name (e.g., "KERNEL32.dll")
    std::vector<export_entry> exports; // All exported functions
    uint32_t ordinal_base;            // Base ordinal number (usually 1)
    uint32_t timestamp;               // Export creation timestamp
    uint16_t major_version;           // Major version
    uint16_t minor_version;           // Minor version

    /**
     * Get number of exported functions
     */
    [[nodiscard]] size_t export_count() const {
        return exports.size();
    }

    /**
     * Get number of named exports
     */
    [[nodiscard]] size_t named_export_count() const {
        size_t count = 0;
        for (const auto& exp : exports) {
            if (exp.has_name) {
                count++;
            }
        }
        return count;
    }

    /**
     * Get number of forwarder exports
     */
    [[nodiscard]] size_t forwarder_count() const {
        size_t count = 0;
        for (const auto& exp : exports) {
            if (exp.is_forwarder) {
                count++;
            }
        }
        return count;
    }

    /**
     * Find export by name
     *
     * @param export_name Function name to search for
     * @return Pointer to export entry, or nullptr if not found
     */
    [[nodiscard]] const export_entry* find_export(std::string_view export_name) const {
        for (const auto& exp : exports) {
            if (exp.has_name && exp.name == export_name) {
                return &exp;
            }
        }
        return nullptr;
    }

    /**
     * Find export by ordinal
     *
     * @param ordinal Ordinal number (actual ordinal, not offset)
     * @return Pointer to export entry, or nullptr if not found
     */
    [[nodiscard]] const export_entry* find_export_by_ordinal(uint16_t ordinal) const {
        for (const auto& exp : exports) {
            if (exp.ordinal == ordinal) {
                return &exp;
            }
        }
        return nullptr;
    }

    /**
     * Check if specific function is exported
     *
     * @param export_name Function name (e.g., "CreateFileW")
     * @return true if this module exports the specified function
     */
    [[nodiscard]] bool exports_function(std::string_view export_name) const {
        return find_export(export_name) != nullptr;
    }

    /**
     * Check if any exports are forwarders
     */
    [[nodiscard]] bool has_forwarders() const {
        for (const auto& exp : exports) {
            if (exp.is_forwarder) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get all export names (sorted)
     *
     * Returns list of all function names that are exported by name.
     * Useful for listing available functions.
     */
    [[nodiscard]] std::vector<std::string> get_export_names() const {
        std::vector<std::string> names;
        names.reserve(named_export_count());

        for (const auto& exp : exports) {
            if (exp.has_name && !exp.name.empty()) {
                names.push_back(exp.name);
            }
        }

        return names;
    }
};

} // namespace libexe

#endif // LIBEXE_EXPORT_DIRECTORY_HPP
