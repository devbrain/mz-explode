// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_DEBUG_DIRECTORY_HPP
#define LIBEXE_DEBUG_DIRECTORY_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <optional>

namespace libexe {

/**
 * Debug directory type
 *
 * IMAGE_DEBUG_TYPE_* constants from PE specification.
 */
enum class debug_type : uint32_t {
    UNKNOWN = 0,
    COFF = 1,           // COFF debug information
    CODEVIEW = 2,       // CodeView debug information (most common)
    FPO = 3,            // Frame pointer omission information
    MISC = 4,           // DBG file path
    EXCEPTION = 5,      // Exception information
    FIXUP = 6,          // Fixup information
    OMAP_TO_SRC = 7,    // OMAP mapping to source
    OMAP_FROM_SRC = 8,  // OMAP mapping from source
    BORLAND = 9,        // Borland debug information
    RESERVED10 = 10,    // Reserved
    CLSID = 11,         // CLSID
    VC_FEATURE = 12,    // Visual C++ feature info
    POGO = 13,          // Profile guided optimization
    ILTCG = 14,         // Incremental link-time code generation
    MPX = 15,           // Memory protection extensions
    REPRO = 16,         // PE determinism/reproducibility
    EMBEDDED_PORTABLE_PDB = 17,  // Embedded portable PDB
    SPGO = 18,          // Sample-based PGO
    PDBCHECKSUM = 19,   // PDB checksum
    EX_DLLCHARACTERISTICS = 20  // Extended DLL characteristics
};

/**
 * CodeView signature
 *
 * Identifies the format of CodeView debug information.
 */
enum class codeview_signature : uint32_t {
    NB09 = 0x3930424E,  // 'NB09' - older format
    NB10 = 0x3031424E,  // 'NB10' - older format
    NB11 = 0x3131424E,  // 'NB11' - older format
    RSDS = 0x53445352   // 'RSDS' - modern PDB 7.0 format
};

/**
 * CodeView PDB 7.0 information (CV_INFO_PDB70)
 *
 * Most common debug format - contains PDB file path and GUID.
 */
struct LIBEXE_EXPORT codeview_pdb70 {
    std::array<uint8_t, 16> guid;  // PDB GUID
    uint32_t age = 0;              // PDB age
    std::string pdb_path;          // Path to PDB file

    /**
     * Format GUID as string (e.g., "12345678-1234-1234-1234-123456789ABC")
     */
    [[nodiscard]] std::string guid_string() const;

    /**
     * Check if this is valid (has non-zero GUID)
     */
    [[nodiscard]] bool is_valid() const;
};

/**
 * CodeView PDB 2.0 information (CV_INFO_PDB20)
 *
 * Older PDB format - contains PDB file path and signature.
 */
struct LIBEXE_EXPORT codeview_pdb20 {
    uint32_t signature = 0;  // PDB signature (timestamp)
    uint32_t age = 0;        // PDB age
    std::string pdb_path;    // Path to PDB file

    /**
     * Check if this is valid (has non-zero signature)
     */
    [[nodiscard]] bool is_valid() const {
        return signature != 0;
    }
};

/**
 * Debug directory entry
 *
 * Represents a single IMAGE_DEBUG_DIRECTORY entry.
 */
struct LIBEXE_EXPORT debug_entry {
    uint32_t characteristics = 0;      // Reserved, must be 0
    uint32_t time_date_stamp = 0;      // Timestamp
    uint16_t major_version = 0;        // Major version
    uint16_t minor_version = 0;        // Minor version
    debug_type type = debug_type::UNKNOWN;  // Debug type
    uint32_t size_of_data = 0;         // Size of debug data
    uint32_t address_of_raw_data = 0;  // RVA of debug data (0 if not mapped)
    uint32_t pointer_to_raw_data = 0;  // File offset of debug data

    // Parsed CodeView information (if type == CODEVIEW)
    std::optional<codeview_pdb70> codeview_pdb70_info;
    std::optional<codeview_pdb20> codeview_pdb20_info;

    // Raw debug data (for types other than CodeView)
    std::vector<uint8_t> raw_data;

    /**
     * Check if this is CodeView debug info
     */
    [[nodiscard]] bool is_codeview() const {
        return type == debug_type::CODEVIEW;
    }

    /**
     * Check if this has PDB 7.0 info
     */
    [[nodiscard]] bool has_pdb70() const {
        return codeview_pdb70_info.has_value();
    }

    /**
     * Check if this has PDB 2.0 info
     */
    [[nodiscard]] bool has_pdb20() const {
        return codeview_pdb20_info.has_value();
    }

    /**
     * Get PDB path (from either PDB70 or PDB20)
     */
    [[nodiscard]] std::string get_pdb_path() const;

    /**
     * Get debug type name
     */
    [[nodiscard]] std::string type_name() const;

    /**
     * Check if debug data is mapped to memory (RVA != 0)
     */
    [[nodiscard]] bool is_mapped() const {
        return address_of_raw_data != 0;
    }

    /**
     * Check if this entry has debug data
     */
    [[nodiscard]] bool has_data() const {
        return size_of_data > 0;
    }
};

/**
 * Debug directory
 *
 * Contains all debug information entries from PE file.
 */
struct LIBEXE_EXPORT debug_directory {
    std::vector<debug_entry> entries;

    /**
     * Check if debug directory is empty
     */
    [[nodiscard]] bool empty() const {
        return entries.empty();
    }

    /**
     * Get number of debug entries
     */
    [[nodiscard]] size_t size() const {
        return entries.size();
    }

    /**
     * Find first entry of specific type
     */
    [[nodiscard]] std::optional<debug_entry> find_type(debug_type type) const;

    /**
     * Get all entries of specific type
     */
    [[nodiscard]] std::vector<debug_entry> find_all_type(debug_type type) const;

    /**
     * Check if directory contains specific debug type
     */
    [[nodiscard]] bool has_type(debug_type type) const;

    /**
     * Get first CodeView entry (most common)
     */
    [[nodiscard]] std::optional<debug_entry> get_codeview() const {
        return find_type(debug_type::CODEVIEW);
    }

    /**
     * Get PDB path from first CodeView entry
     */
    [[nodiscard]] std::string get_pdb_path() const;

    /**
     * Check if directory has CodeView debug info
     */
    [[nodiscard]] bool has_codeview() const {
        return has_type(debug_type::CODEVIEW);
    }

    /**
     * Check if directory has PDB information
     */
    [[nodiscard]] bool has_pdb() const;
};

} // namespace libexe

#endif // LIBEXE_DEBUG_DIRECTORY_HPP
