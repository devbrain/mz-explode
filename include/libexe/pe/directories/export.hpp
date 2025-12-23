// libexe - Modern executable file analysis library
// PE Export Directory - Types and Parser

#ifndef LIBEXE_PE_DIRECTORIES_EXPORT_HPP
#define LIBEXE_PE_DIRECTORIES_EXPORT_HPP

#include <libexe/export.hpp>
#include <libexe/pe/section.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include <string_view>
#include <span>
#include <optional>

// Disable MSVC warning C4251: 'member': class 'std::...' needs to have dll-interface
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

namespace libexe {

// =============================================================================
// Export Directory Types
// =============================================================================

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

// =============================================================================
// Export Directory Parser
// =============================================================================

/**
 * Export Directory Parser
 *
 * Parses PE export directory (data directory index 0) to extract
 * all exported functions from a DLL or executable. Handles named exports,
 * ordinal-only exports, and forwarders.
 */
class LIBEXE_EXPORT export_directory_parser {
public:
    /**
     * Parse export directory from PE file
     *
     * Reads IMAGE_EXPORT_DIRECTORY and all associated tables to extract
     * all exported functions (named, ordinal-only, and forwarders).
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections (for RVA to offset conversion)
     * @param export_dir_rva RVA to export directory
     * @param export_dir_size Size of export directory (for forwarder detection)
     * @return Parsed export directory with all functions
     * @throws std::runtime_error if export directory is malformed
     */
    static export_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t export_dir_rva,
        uint32_t export_dir_size
    );

private:
    static std::vector<uint32_t> read_address_table(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t table_rva,
        uint32_t count
    );

    static std::vector<uint32_t> read_name_pointer_table(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t table_rva,
        uint32_t count
    );

    static std::vector<uint16_t> read_ordinal_table(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t table_rva,
        uint32_t count
    );

    static bool is_forwarder_rva(
        uint32_t rva,
        uint32_t export_section_rva,
        uint32_t export_section_size
    );

    static std::string read_forwarder_string(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t forwarder_rva
    );

    static std::string read_string_at_rva(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t rva
    );

    static size_t rva_to_offset(
        const std::vector<pe_section>& sections,
        uint32_t rva
    );
};

} // namespace libexe

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // LIBEXE_PE_DIRECTORIES_EXPORT_HPP
