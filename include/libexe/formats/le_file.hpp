// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_FORMATS_LE_FILE_HPP
#define LIBEXE_FORMATS_LE_FILE_HPP

#include <libexe/export.hpp>
#include <libexe/core/executable_file.hpp>
#include <libexe/core/diagnostic_collector.hpp>
#include <libexe/le/types.hpp>
#include <filesystem>
#include <vector>
#include <span>
#include <string>
#include <optional>
#include <memory>

namespace libexe {

/// LE/LX object (segment) information
struct le_object {
    uint32_t index;              // 1-based object number
    uint32_t virtual_size;       // Size in memory
    uint32_t base_address;       // Preferred load address
    uint32_t flags;              // Object flags
    uint32_t page_table_index;   // First page in page table (1-based)
    uint32_t page_count;         // Number of page entries

    [[nodiscard]] bool is_readable() const { return (flags & 0x0001) != 0; }
    [[nodiscard]] bool is_writable() const { return (flags & 0x0002) != 0; }
    [[nodiscard]] bool is_executable() const { return (flags & 0x0004) != 0; }
    [[nodiscard]] bool is_resource() const { return (flags & 0x0008) != 0; }
    [[nodiscard]] bool is_discardable() const { return (flags & 0x0010) != 0; }
    [[nodiscard]] bool is_shared() const { return (flags & 0x0020) != 0; }
    [[nodiscard]] bool is_preload() const { return (flags & 0x0040) != 0; }
    [[nodiscard]] bool is_32bit() const { return (flags & 0x2000) != 0; }  // BIG flag
};

/// Page table entry (unified for LE and LX)
struct le_page_entry {
    uint32_t page_number;        // Page number in object (1-based for display)
    uint32_t file_offset;        // Actual file offset to page data
    uint16_t data_size;          // Actual size in file (LX only, LE uses page_size)
    uint16_t flags;              // Page flags

    [[nodiscard]] bool is_legal() const { return flags == 0x0000; }
    [[nodiscard]] bool is_iterated() const { return flags == 0x0001; }
    [[nodiscard]] bool is_invalid() const { return flags == 0x0002; }
    [[nodiscard]] bool is_zerofill() const { return flags == 0x0003; }
    [[nodiscard]] bool is_compressed() const { return flags == 0x0005; }
};

/// Resident/Non-resident name entry
struct le_name_entry {
    std::string name;            // Name string
    uint16_t ordinal;            // Entry ordinal
};

/// Resource table entry
struct le_resource {
    uint16_t type_id;            // Resource type ID (see OS/2 resource types)
    uint16_t name_id;            // Resource name ID
    uint32_t size;               // Resource size in bytes
    uint16_t object;             // Object number containing resource (1-based)
    uint32_t offset;             // Offset within object

    // Standard OS/2 resource types
    static constexpr uint16_t RT_POINTER    = 1;   // Mouse pointer
    static constexpr uint16_t RT_BITMAP     = 2;   // Bitmap
    static constexpr uint16_t RT_MENU       = 3;   // Menu template
    static constexpr uint16_t RT_DIALOG     = 4;   // Dialog template
    static constexpr uint16_t RT_STRING     = 5;   // String table
    static constexpr uint16_t RT_FONTDIR    = 6;   // Font directory
    static constexpr uint16_t RT_FONT       = 7;   // Font
    static constexpr uint16_t RT_ACCELTABLE = 8;   // Accelerator table
    static constexpr uint16_t RT_RCDATA     = 9;   // Binary data
    static constexpr uint16_t RT_MESSAGE    = 10;  // Error message table
    static constexpr uint16_t RT_DLGINCLUDE = 11;  // Dialog include file name
    static constexpr uint16_t RT_VKEYTBL    = 12;  // Virtual key table
    static constexpr uint16_t RT_KEYTBL     = 13;  // Key table
    static constexpr uint16_t RT_CHARTBL    = 14;  // Char table
    static constexpr uint16_t RT_DISPLAYINFO= 15;  // Display info
    static constexpr uint16_t RT_FKASHORT   = 16;  // FKA short
    static constexpr uint16_t RT_FKALONG    = 17;  // FKA long
    static constexpr uint16_t RT_HELPTABLE  = 18;  // Help table
    static constexpr uint16_t RT_HELPSUBTABLE = 19;// Help subtable
    static constexpr uint16_t RT_FDDIR      = 20;  // Font directory (alternate)
    static constexpr uint16_t RT_FD         = 21;  // Font
};

/// Entry table entry type
enum class le_entry_type : uint8_t {
    UNUSED    = 0x00,     // Empty/skip (used to skip ordinal numbers)
    ENTRY_16  = 0x01,     // 16-bit entry point
    GATE_286  = 0x02,     // 286 call gate entry
    ENTRY_32  = 0x03,     // 32-bit entry point
    FORWARDER = 0x04      // Forwarder entry (import)
};

/// Fixup source type
enum class le_fixup_source_type : uint8_t {
    BYTE           = 0x00,   // 8-bit byte
    SELECTOR_16    = 0x02,   // 16-bit selector
    POINTER_16_16  = 0x03,   // 16:16 far pointer
    OFFSET_16      = 0x05,   // 16-bit offset
    POINTER_16_32  = 0x06,   // 16:32 far pointer
    OFFSET_32      = 0x07,   // 32-bit offset
    RELATIVE_32    = 0x08    // 32-bit self-relative offset
};

/// Fixup target type
enum class le_fixup_target_type : uint8_t {
    INTERNAL        = 0x00,  // Internal reference (object + offset)
    IMPORT_ORDINAL  = 0x01,  // Import by ordinal
    IMPORT_NAME     = 0x02,  // Import by name
    INTERNAL_ENTRY  = 0x03   // Internal entry table reference
};

/// Fixup record
struct le_fixup {
    uint32_t page_index;             // Page this fixup applies to (1-based)
    uint16_t source_offset;          // Offset within page where fixup is applied
    le_fixup_source_type source_type; // Type of fixup
    le_fixup_target_type target_type; // Target type

    // Target info (depends on target_type)
    uint16_t target_object;          // Target object (INTERNAL)
    uint32_t target_offset;          // Target offset (INTERNAL, or proc offset for IMPORT_NAME)
    uint16_t module_ordinal;         // Import module ordinal (IMPORT_*)
    uint32_t import_ordinal;         // Import ordinal (IMPORT_ORDINAL)

    // Flags
    bool is_alias;                   // Alias (16:16 pointer)
    bool is_additive;                // Additive fixup (add value instead of replace)
    int32_t additive_value;          // Additive value if is_additive
};

/// Entry point information
struct le_entry {
    uint16_t ordinal;            // Entry ordinal (1-based)
    le_entry_type type;          // Entry type
    uint16_t object;             // Object number containing entry (1-based)
    uint32_t offset;             // Offset within object
    uint8_t flags;               // Entry flags
    uint16_t callgate;           // Call gate selector (286 gate only)
    // Forwarder fields
    uint16_t module_ordinal;     // Module ordinal for forwarder
    uint32_t import_ordinal;     // Import ordinal or proc offset for forwarder

    [[nodiscard]] bool is_exported() const { return (flags & 0x01) != 0; }
    [[nodiscard]] bool is_shared_data() const { return (flags & 0x02) != 0; }
    [[nodiscard]] uint8_t param_count() const { return (flags >> 3) & 0x1F; }
};

/// LE/LX (Linear Executable) file - DOS/4GW, DOS/32A, OS/2, VxD
class LIBEXE_EXPORT le_file final : public executable_file {
public:
    /// Load LE/LX file from filesystem
    [[nodiscard]] static le_file from_file(const std::filesystem::path& path);

    /// Load LE/LX file from memory
    [[nodiscard]] static le_file from_memory(std::span<const uint8_t> data);

    // =========================================================================
    // Base class interface
    // =========================================================================

    [[nodiscard]] format_type get_format() const override;
    [[nodiscard]] std::string_view format_name() const override;
    [[nodiscard]] std::span<const uint8_t> code_section() const override;

    // =========================================================================
    // Format identification
    // =========================================================================

    /// Check if this is LX (OS/2) vs LE (DOS/VxD)
    [[nodiscard]] bool is_lx() const;

    /// Check if this is a VxD (Virtual Device Driver)
    [[nodiscard]] bool is_vxd() const;

    /// Check if this is a DLL/library module
    [[nodiscard]] bool is_library() const;

    /// Check if file was bound to a DOS extender (has MZ stub)
    [[nodiscard]] bool is_bound() const;

    /// Get detected DOS extender type (if bound)
    [[nodiscard]] dos_extender_type extender_type() const;

    // =========================================================================
    // Header accessors
    // =========================================================================

    /// CPU type required
    [[nodiscard]] uint16_t cpu_type() const;

    /// Target operating system
    [[nodiscard]] uint16_t os_type() const;

    /// Module version
    [[nodiscard]] uint32_t module_version() const;

    /// Module flags
    [[nodiscard]] uint32_t module_flags() const;

    /// Memory page size (usually 4096)
    [[nodiscard]] uint32_t page_size() const;

    /// Page offset shift (LX only, LE uses 0)
    [[nodiscard]] uint32_t page_offset_shift() const;

    /// Total number of memory pages
    [[nodiscard]] uint32_t page_count() const;

    // =========================================================================
    // Entry point
    // =========================================================================

    /// Initial EIP (entry point offset within object)
    [[nodiscard]] uint32_t entry_eip() const;

    /// Object number containing EIP (1-based)
    [[nodiscard]] uint32_t entry_object() const;

    /// Initial ESP (stack pointer offset within object)
    [[nodiscard]] uint32_t entry_esp() const;

    /// Object number containing ESP (1-based)
    [[nodiscard]] uint32_t stack_object() const;

    // =========================================================================
    // Object (segment) access
    // =========================================================================

    /// Get all objects
    [[nodiscard]] const std::vector<le_object>& objects() const;

    /// Get object by 1-based index
    [[nodiscard]] std::optional<le_object> get_object(uint32_t index) const;

    /// Find first code object
    [[nodiscard]] std::optional<le_object> get_code_object() const;

    /// Find first data object
    [[nodiscard]] std::optional<le_object> get_data_object() const;

    /// Get object containing entry point
    [[nodiscard]] std::optional<le_object> get_entry_object() const;

    /// Get object page table entries for an object
    [[nodiscard]] std::vector<le_page_entry> get_object_pages(uint32_t object_index) const;

    /// Read object data (decompresses if needed)
    [[nodiscard]] std::vector<uint8_t> read_object_data(uint32_t object_index) const;

    // =========================================================================
    // Name Tables
    // =========================================================================

    /// Resident name table
    [[nodiscard]] std::vector<le_name_entry> resident_names() const;

    /// Non-resident name table
    [[nodiscard]] std::vector<le_name_entry> nonresident_names() const;

    /// Get module name (first entry in resident name table)
    [[nodiscard]] std::string module_name() const;

    // =========================================================================
    // Entry Table
    // =========================================================================

    /// Get all entry points
    [[nodiscard]] const std::vector<le_entry>& entries() const;

    /// Get entry by ordinal (1-based)
    [[nodiscard]] std::optional<le_entry> get_entry(uint16_t ordinal) const;

    /// Get number of entry points
    [[nodiscard]] size_t entry_count() const;

    // =========================================================================
    // Import Tables
    // =========================================================================

    /// Get imported module names
    [[nodiscard]] const std::vector<std::string>& import_modules() const;

    /// Get number of imported modules
    [[nodiscard]] size_t import_module_count() const;

    /// Get import module name by index (1-based)
    [[nodiscard]] std::optional<std::string> get_import_module(uint16_t index) const;

    // =========================================================================
    // Fixup Tables
    // =========================================================================

    /// Get all fixup records
    [[nodiscard]] const std::vector<le_fixup>& fixups() const;

    /// Get fixups for a specific page (1-based page index)
    [[nodiscard]] std::vector<le_fixup> get_page_fixups(uint32_t page_index) const;

    /// Get number of fixup records
    [[nodiscard]] size_t fixup_count() const;

    /// Check if file has fixups
    [[nodiscard]] bool has_fixups() const;

    // =========================================================================
    // Resource Table
    // =========================================================================

    /// Get all resources
    [[nodiscard]] const std::vector<le_resource>& resources() const;

    /// Get number of resources
    [[nodiscard]] size_t resource_count() const;

    /// Check if file has resources
    [[nodiscard]] bool has_resources() const;

    /// Get resources by type ID
    [[nodiscard]] std::vector<le_resource> resources_by_type(uint16_t type_id) const;

    /// Get resource by type and name ID
    [[nodiscard]] std::optional<le_resource> get_resource(uint16_t type_id, uint16_t name_id) const;

    /// Read resource data
    [[nodiscard]] std::vector<uint8_t> read_resource_data(const le_resource& resource) const;

    // =========================================================================
    // Debug information
    // =========================================================================

    /// Check if debug info present
    [[nodiscard]] bool has_debug_info() const;

    /// Debug info file offset
    [[nodiscard]] uint32_t debug_info_offset() const;

    /// Debug info size
    [[nodiscard]] uint32_t debug_info_size() const;

    // =========================================================================
    // DOS Extender Stripping
    // =========================================================================

    /// Strip DOS extender stub and return raw LE/LX data
    /// This removes the MZ stub and adjusts absolute file offsets.
    /// Returns empty vector if not bound (no stub to strip).
    [[nodiscard]] std::vector<uint8_t> strip_extender() const;

    /// Get offset to LE/LX header (0 if raw, >0 if bound)
    [[nodiscard]] uint32_t le_header_offset() const;

    /// Get the size of the DOS extender stub (0 if not bound)
    [[nodiscard]] uint32_t stub_size() const;

    // =========================================================================
    // Diagnostics
    // =========================================================================

    /// Get all diagnostics generated during parsing
    [[nodiscard]] const diagnostic_collector& diagnostics() const;

    /// Check if a specific diagnostic code exists
    [[nodiscard]] bool has_diagnostic(diagnostic_code code) const;

private:
    le_file() = default;

    void parse_le_headers();
    void parse_objects();
    void parse_page_table();
    void parse_entry_table();
    void parse_import_module_table();
    void parse_fixup_tables();
    void parse_resource_table();
    void detect_extender_type();

    std::vector<uint8_t> data_;
    std::vector<le_object> objects_;
    std::vector<le_page_entry> page_table_;
    std::vector<le_entry> entries_;
    std::vector<std::string> import_modules_;
    std::vector<le_fixup> fixups_;
    std::vector<le_resource> resources_;

    // Format identification
    bool is_lx_ = false;
    bool is_bound_ = false;
    dos_extender_type extender_type_ = dos_extender_type::NONE;
    uint32_t le_header_offset_ = 0;  // Offset to LE/LX header in file

    // Header fields (extracted from DataScript-parsed header)
    uint16_t cpu_type_ = 0;
    uint16_t os_type_ = 0;
    uint32_t module_version_ = 0;
    uint32_t module_flags_ = 0;
    uint32_t page_size_ = 4096;
    uint32_t page_offset_shift_ = 0;  // LX only
    uint32_t page_count_ = 0;

    // Entry point
    uint32_t eip_object_ = 0;
    uint32_t eip_ = 0;
    uint32_t esp_object_ = 0;
    uint32_t esp_ = 0;

    // Table offsets (relative to LE header)
    uint32_t object_table_offset_ = 0;
    uint32_t object_count_ = 0;
    uint32_t page_table_offset_ = 0;
    uint32_t resource_table_offset_ = 0;
    uint32_t resource_count_ = 0;
    uint32_t resident_name_table_offset_ = 0;
    uint32_t entry_table_offset_ = 0;
    uint32_t import_module_table_offset_ = 0;
    uint32_t import_module_count_ = 0;
    uint32_t import_proc_table_offset_ = 0;
    uint32_t fixup_page_table_offset_ = 0;
    uint32_t fixup_record_table_offset_ = 0;

    // Absolute file offsets
    uint32_t data_pages_offset_ = 0;
    uint32_t nonresident_name_table_offset_ = 0;
    uint32_t nonresident_name_table_size_ = 0;
    uint32_t debug_info_offset_ = 0;
    uint32_t debug_info_size_ = 0;

    // Diagnostics collector
    mutable diagnostic_collector diagnostics_;
};

} // namespace libexe

#endif // LIBEXE_FORMATS_LE_FILE_HPP
