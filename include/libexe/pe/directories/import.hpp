// libexe - Modern executable file analysis library
// PE Import Directory - Types and Parser

#ifndef LIBEXE_PE_DIRECTORIES_IMPORT_HPP
#define LIBEXE_PE_DIRECTORIES_IMPORT_HPP

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
// Import Directory Types
// =============================================================================

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
    bool truncated = false;        // True if import directory was truncated (missing null terminator)

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

// =============================================================================
// Import Directory Parser
// =============================================================================

/**
 * Import Directory Parser
 *
 * Parses PE import directory (data directory index 1) to extract
 * all imported DLLs and functions. Handles both PE32 and PE32+ formats.
 */
class LIBEXE_EXPORT import_directory_parser {
public:
    /**
     * Parse import directory from PE file
     *
     * Reads IMAGE_IMPORT_DESCRIPTOR array and all referenced data
     * (DLL names, function names, ordinals). The import directory is
     * an array of descriptors terminated by a null entry.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections (for RVA to offset conversion)
     * @param import_dir_rva RVA to import directory
     * @param import_dir_size Size of import directory (may be 0 if unknown)
     * @param is_64bit true for PE32+, false for PE32
     * @return Parsed import directory with all DLLs and functions
     * @throws std::runtime_error if import directory is malformed
     */
    static import_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t import_dir_rva,
        uint32_t import_dir_size,
        bool is_64bit
    );

private:
    static import_dll parse_import_descriptor(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t descriptor_rva,
        bool is_64bit
    );

    static std::vector<import_entry> parse_ilt(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t ilt_rva,
        uint32_t iat_rva,
        bool is_64bit
    );

    static import_entry parse_import_by_name(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t rva,
        uint64_t iat_rva,
        uint16_t ordinal,
        bool is_ordinal
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

    // Ordinal flag masks
    static constexpr uint32_t ORDINAL_FLAG_32 = 0x80000000;
    static constexpr uint64_t ORDINAL_FLAG_64 = 0x8000000000000000ULL;
    static constexpr uint16_t ORDINAL_MASK = 0xFFFF;
};

} // namespace libexe

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // LIBEXE_PE_DIRECTORIES_IMPORT_HPP
