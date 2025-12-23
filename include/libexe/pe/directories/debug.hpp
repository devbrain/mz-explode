// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_PE_DIRECTORIES_DEBUG_HPP
#define LIBEXE_PE_DIRECTORIES_DEBUG_HPP

#include <libexe/export.hpp>
#include <libexe/pe/section.hpp>
#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <optional>
#include <span>

// Disable MSVC warning C4251: 'member': class 'std::...' needs to have dll-interface
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

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

/**
 * Debug Directory Parser
 *
 * Parses PE Debug Directory (data directory index 6) to extract
 * debug information entries including CodeView (PDB) information.
 *
 * The debug directory contains an array of IMAGE_DEBUG_DIRECTORY entries,
 * each describing a different type of debug information (CodeView, FPO, etc.).
 *
 * Most executables have at least one CodeView entry containing PDB file path.
 */
class LIBEXE_EXPORT debug_directory_parser {
public:
    /**
     * Parse debug directory from PE file
     *
     * Reads array of IMAGE_DEBUG_DIRECTORY entries and their associated data.
     * For CodeView entries, parses PDB 7.0 (RSDS) or PDB 2.0 (NB10) format.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections (for RVA to offset conversion)
     * @param debug_dir_rva RVA to debug directory
     * @param debug_dir_size Size of debug directory (multiple of 28 bytes)
     * @return Parsed debug directory with all entries
     * @throws std::runtime_error if debug directory is malformed
     */
    static debug_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t debug_dir_rva,
        uint32_t debug_dir_size
    );

private:
    /**
     * Parse a single debug entry
     *
     * Reads IMAGE_DEBUG_DIRECTORY and parses associated debug data.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections
     * @param ptr Pointer to IMAGE_DEBUG_DIRECTORY
     * @param end End of file data
     * @return Parsed debug entry
     */
    static debug_entry parse_entry(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        const uint8_t*& ptr,
        const uint8_t* end
    );

    /**
     * Parse CodeView debug data
     *
     * Reads CodeView signature and parses PDB 7.0 (RSDS) or PDB 2.0 (NB10).
     *
     * @param file_data Complete PE file data
     * @param offset File offset to CodeView data
     * @param size Size of CodeView data
     * @param entry Debug entry to populate
     */
    static void parse_codeview_data(
        std::span<const uint8_t> file_data,
        size_t offset,
        uint32_t size,
        debug_entry& entry
    );

    /**
     * Parse CodeView PDB 7.0 (RSDS)
     *
     * Modern PDB format with GUID.
     *
     * @param ptr Pointer to CV_INFO_PDB70
     * @param end End of data
     * @return Parsed PDB 7.0 info
     */
    static codeview_pdb70 parse_pdb70(
        const uint8_t* ptr,
        const uint8_t* end
    );

    /**
     * Parse CodeView PDB 2.0 (NB10)
     *
     * Older PDB format with timestamp signature.
     *
     * @param ptr Pointer to CV_INFO_PDB20
     * @param end End of data
     * @return Parsed PDB 2.0 info
     */
    static codeview_pdb20 parse_pdb20(
        const uint8_t* ptr,
        const uint8_t* end
    );

    /**
     * Read null-terminated string
     *
     * Reads ANSI string until null terminator or end of data.
     *
     * @param ptr Pointer to string start
     * @param end End of data
     * @return Parsed string
     */
    static std::string read_null_terminated_string(
        const uint8_t* ptr,
        const uint8_t* end
    );

    /**
     * Convert RVA to file offset
     *
     * Helper that wraps pe_section_parser::rva_to_file_offset()
     * and returns 0 if RVA is not in any section (debug data may not be mapped).
     *
     * @param sections Parsed PE sections
     * @param rva RVA to convert
     * @return File offset or 0 if not mapped
     */
    static size_t rva_to_offset(
        const std::vector<pe_section>& sections,
        uint32_t rva
    );
};

} // namespace libexe

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // LIBEXE_PE_DIRECTORIES_DEBUG_HPP
