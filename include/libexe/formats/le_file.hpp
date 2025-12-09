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

/// LE/LX (Linear Executable) file - DOS/4GW, DOS/32A, OS/2, VxD
class LIBEXE_EXPORT le_file final : public executable_file {
public:
    /// Load LE/LX file from filesystem
    static le_file from_file(const std::filesystem::path& path);

    /// Load LE/LX file from memory
    static le_file from_memory(std::span<const uint8_t> data);

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
    // Debug information
    // =========================================================================

    /// Check if debug info present
    [[nodiscard]] bool has_debug_info() const;

    /// Debug info file offset
    [[nodiscard]] uint32_t debug_info_offset() const;

    /// Debug info size
    [[nodiscard]] uint32_t debug_info_size() const;

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
    void detect_extender_type();

    std::vector<uint8_t> data_;
    std::vector<le_object> objects_;
    std::vector<le_page_entry> page_table_;

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
    uint32_t resident_name_table_offset_ = 0;
    uint32_t entry_table_offset_ = 0;

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
