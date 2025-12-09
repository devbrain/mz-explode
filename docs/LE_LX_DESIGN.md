# LE/LX File Support - Design Document

Design specification for adding Linear Executable (LE/LX) format support to libexe,
following the established patterns for MZ, NE, and PE file support.

## Overview

LE (Linear Executable) and LX (Linear eXecutable extended) are 32-bit executable
formats used by:
- **LE**: DOS extenders (DOS/4GW, DOS/32A, PMODE/W), Windows VxD drivers
- **LX**: OS/2 2.0+ executables and DLLs

Both formats share the same basic structure but differ in page table entry format
and some header field interpretations.

## Architecture Patterns

Following existing libexe patterns:

```
include/libexe/
├── formats/
│   ├── le_file.hpp          # Main LE/LX file class (like pe_file.hpp)
│   └── executable_factory.hpp  # Update to include le_file
├── le/
│   ├── types.hpp            # Enums: le_cpu_type, le_os_type, le_module_flags, etc.
│   ├── object.hpp           # Object/segment representation (like pe/section.hpp)
│   └── directories/
│       ├── fixup.hpp        # Fixup/relocation records
│       ├── entry.hpp        # Entry table
│       └── resource.hpp     # LE resource table
├── core/
│   └── executable_file.hpp  # Add LE_DOS32, LX_OS2 to format_type enum

src/libexe/
├── formats/
│   └── le/
│       └── le_header.ds     # DataScript format specification
├── le_file.cpp              # Main implementation
└── parsers/
    ├── le_object_parser.cpp
    ├── le_fixup_parser.cpp
    └── le_entry_parser.cpp
```

## Format Type Extension

The `format_type` enum is extended to distinguish between bound (with DOS extender stub)
and raw (unbound) LE/LX executables. This allows callers to know at a glance whether
the file contains a DOS extender that can be stripped.

```cpp
// core/executable_file.hpp
enum class format_type {
    UNKNOWN,
    MZ_DOS,              // DOS MZ executable (plain, no extended header)
    NE_WIN16,            // 16-bit Windows/OS2
    PE_WIN32,            // 32-bit Windows PE
    PE_PLUS_WIN64,       // 64-bit Windows PE32+

    // LE/LX formats - distinguish bound vs raw
    LE_DOS32_BOUND,      // 32-bit DOS with extender stub (DOS/4GW, DOS/32A, etc.) - NEW
    LE_DOS32_RAW,        // 32-bit DOS, raw LE (no MZ stub) - NEW
    LE_VXD,              // Windows VxD driver - NEW
    LX_OS2_BOUND,        // OS/2 2.0+ with MZ stub - NEW
    LX_OS2_RAW,          // OS/2 2.0+ raw LX - NEW
};
```

**Rationale for BOUND/RAW distinction:**
- `LE_DOS32_BOUND`: File starts with MZ header, LE header at offset from 0x3C. Contains
  DOS extender code (DOS/4GW, DOS/32A, PMODE/W, etc.) that must be accounted for when
  adjusting absolute file offsets.
- `LE_DOS32_RAW`: File starts directly with 'LE' signature. Already stripped or was
  never bound. No offset adjustment needed.
- Same logic applies to LX format with `LX_OS2_BOUND` and `LX_OS2_RAW`.

**Detection logic:**
```cpp
if (data[0] == 'L' && data[1] == 'E') {
    return format_type::LE_DOS32_RAW;  // Raw LE, no MZ stub
}
if (data[0] == 'L' && data[1] == 'X') {
    return format_type::LX_OS2_RAW;    // Raw LX, no MZ stub
}
if (data[0] == 'M' && data[1] == 'Z') {
    uint32_t ext_offset = read_u32_le(data + 0x3C);
    uint16_t magic = read_u16_le(data + ext_offset);
    switch (magic) {
        case 0x454C: return format_type::LE_DOS32_BOUND;  // 'LE' with MZ stub
        case 0x584C: return format_type::LX_OS2_BOUND;    // 'LX' with MZ stub
        case 0x4550: return format_type::PE_WIN32;        // or PE_PLUS_WIN64
        case 0x454E: return format_type::NE_WIN16;
        default:     return format_type::MZ_DOS;          // Plain MZ
    }
}
```

## Executable Factory Update

```cpp
// formats/executable_factory.hpp
using executable_variant = std::variant<mz_file, ne_file, pe_file, le_file>;

// Detection logic addition:
// After MZ header check at offset 0x3C:
// - 'PE' (0x4550) -> PE format (PE_WIN32 or PE_PLUS_WIN64)
// - 'NE' (0x454E) -> NE format
// - 'LE' (0x454C) -> LE format (LE_DOS32_BOUND) - NEW
// - 'LX' (0x584C) -> LX format (LX_OS2_BOUND) - NEW
// Direct 'LE'/'LX' at offset 0:
// - 'LE' -> LE_DOS32_RAW
// - 'LX' -> LX_OS2_RAW
```

## Type Definitions

### le/types.hpp

```cpp
#ifndef LIBEXE_LE_TYPES_HPP
#define LIBEXE_LE_TYPES_HPP

#include <libexe/core/enum_bitmask.hpp>
#include <cstdint>

namespace libexe {

/// LE/LX executable format variant
enum class le_format_type : uint8_t {
    LE,     // Standard LE (DOS, VxD)
    LX      // Extended LX (OS/2)
};

/// CPU type (header offset 0x08)
enum class le_cpu_type : uint16_t {
    I286    = 0x01,   // Intel 80286 or upwardly compatible
    I386    = 0x02,   // Intel 80386 or upwardly compatible
    I486    = 0x03,   // Intel 80486 or upwardly compatible
    I586    = 0x04,   // Intel 80586 (Pentium) or upwardly compatible
    I860_N10= 0x20,   // Intel i860 (N10) or compatible
    I860_N11= 0x21,   // Intel "N11" or compatible
    MIPS_I  = 0x40,   // MIPS Mark I (R2000, R3000) or compatible
    MIPS_II = 0x41,   // MIPS Mark II (R6000) or compatible
    MIPS_III= 0x42,   // MIPS Mark III (R4000) or compatible
};

/// Target operating system (header offset 0x0A)
enum class le_os_type : uint16_t {
    UNKNOWN = 0x00,
    OS2 = 0x01,         // OS/2
    WINDOWS = 0x02,     // Windows (VxD)
    DOS4 = 0x03,        // European DOS 4.x
    WINDOWS386 = 0x04   // Windows 386 enhanced mode
};

/// Module type flags (header offset 0x10)
enum class le_module_flags : uint32_t {
    // Library flags
    PER_PROCESS_INIT = 0x00000004,  // Per-process library init (DLL)
    INTERNAL_FIXUPS  = 0x00000010,  // Internal fixups applied
    EXTERNAL_FIXUPS  = 0x00000020,  // External fixups applied

    // PM compatibility
    PM_INCOMPATIBLE  = 0x00000100,
    PM_COMPATIBLE    = 0x00000200,
    PM_USES_API      = 0x00000300,

    // Module type
    NOT_LOADABLE     = 0x00002000,  // Module has errors
    LIBRARY          = 0x00008000,  // Library module (DLL)
    PROTECTED_LIB    = 0x00018000,  // Protected memory library
    PHYS_DRIVER      = 0x00020000,  // Physical device driver
    VIRT_DRIVER      = 0x00028000,  // Virtual device driver (VxD)
};

/// Object/segment flags (object table entry offset 0x08)
enum class le_object_flags : uint32_t {
    READABLE         = 0x0001,
    WRITABLE         = 0x0002,
    EXECUTABLE       = 0x0004,
    RESOURCE         = 0x0008,
    DISCARDABLE      = 0x0010,
    SHARED           = 0x0020,
    PRELOAD          = 0x0040,
    INVALID_PAGES    = 0x0080,
    ZEROFILL_PAGES   = 0x0100,
    RESIDENT         = 0x0200,
    RESIDENT_CONTIG  = 0x0300,
    RESIDENT_LOCKABLE= 0x0400,
    ALIAS_16_16      = 0x1000,
    BIG              = 0x2000,      // USE32 segment
    CONFORMING       = 0x4000,
    IOPL             = 0x8000,
};

/// Page flags (object page table entry)
enum class le_page_flags : uint16_t {
    // LX format flags
    LEGAL            = 0x0000,      // Legal physical page
    ITERATED         = 0x0001,      // Iterated data page
    INVALID          = 0x0002,      // Invalid (not present)
    ZEROFILL         = 0x0003,      // Zero-filled
    RANGE            = 0x0004,      // Range of pages
    COMPRESSED       = 0x0005,      // Compressed page (LX only)
};

/// Fixup source type
enum class le_fixup_source : uint8_t {
    BYTE             = 0x00,        // 8-bit offset
    SELECTOR_16      = 0x02,        // 16-bit selector
    POINTER_32       = 0x03,        // 16:16 pointer
    OFFSET_16        = 0x05,        // 16-bit offset
    POINTER_48       = 0x06,        // 16:32 pointer
    OFFSET_32        = 0x07,        // 32-bit offset
    RELATIVE_32      = 0x08,        // 32-bit self-relative
};

/// Fixup target type
enum class le_fixup_target : uint8_t {
    INTERNAL         = 0x00,        // Internal reference
    IMPORT_ORDINAL   = 0x01,        // Import by ordinal
    IMPORT_NAME      = 0x02,        // Import by name
    INTERNAL_ENTRY   = 0x03,        // Entry table reference
    ADDITIVE         = 0x04,        // Additive fixup (flag)
};

/// DOS extender type (detected from stub)
enum class dos_extender_type {
    UNKNOWN,
    DOS32A,
    STUB32A,
    STUB32C,
    DOS4G,
    DOS4GW,
    PMODEW,
    CAUSEWAY,
    WDOSX
};

// Enable bitmask operators
template<> struct enable_bitmask_operators<le_module_flags> { static constexpr bool enable = true; };
template<> struct enable_bitmask_operators<le_object_flags> { static constexpr bool enable = true; };
template<> struct enable_bitmask_operators<le_page_flags> { static constexpr bool enable = true; };

} // namespace libexe

#endif // LIBEXE_LE_TYPES_HPP
```

### le/object.hpp

```cpp
#ifndef LIBEXE_LE_OBJECT_HPP
#define LIBEXE_LE_OBJECT_HPP

#include <libexe/le/types.hpp>
#include <cstdint>
#include <string>
#include <vector>

namespace libexe {

/// LE/LX object (segment) - analogous to PE section
struct le_object {
    uint32_t index;              // 1-based object number
    uint32_t virtual_size;       // Size in memory
    uint32_t base_address;       // Preferred load address
    le_object_flags flags;       // Object attributes
    uint32_t page_table_index;   // First page in page table (1-based)
    uint32_t page_count;         // Number of pages

    // Computed properties
    [[nodiscard]] bool is_code() const {
        return has_flag(le_object_flags::EXECUTABLE);
    }
    [[nodiscard]] bool is_data() const {
        return !is_code() && has_flag(le_object_flags::READABLE);
    }
    [[nodiscard]] bool is_readable() const {
        return has_flag(le_object_flags::READABLE);
    }
    [[nodiscard]] bool is_writable() const {
        return has_flag(le_object_flags::WRITABLE);
    }
    [[nodiscard]] bool is_executable() const {
        return has_flag(le_object_flags::EXECUTABLE);
    }
    [[nodiscard]] bool is_32bit() const {
        return has_flag(le_object_flags::BIG);
    }

private:
    [[nodiscard]] bool has_flag(le_object_flags f) const {
        return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(f)) != 0;
    }
};

/// Page table entry (unified for LE and LX)
struct le_page_entry {
    uint32_t offset;             // File offset to page data
    uint16_t size;               // Actual size in file (LX only, LE assumes page_size)
    le_page_flags flags;         // Page type
};

} // namespace libexe

#endif // LIBEXE_LE_OBJECT_HPP
```

## Main Class Design

### include/libexe/formats/le_file.hpp

```cpp
#ifndef LIBEXE_FORMATS_LE_FILE_HPP
#define LIBEXE_FORMATS_LE_FILE_HPP

#include <libexe/export.hpp>
#include <libexe/core/executable_file.hpp>
#include <libexe/core/diagnostic_collector.hpp>
#include <libexe/le/types.hpp>
#include <libexe/le/object.hpp>
#include <filesystem>
#include <vector>
#include <span>
#include <string>
#include <optional>
#include <memory>

namespace libexe {

// Forward declarations
struct le_fixup_directory;
struct le_entry_table;
struct le_resource_table;
struct le_import_module_table;
struct le_import_procedure_table;

/// LE/LX (Linear Executable) file - DOS/4GW, DOS/32A, OS/2, VxD
class LIBEXE_EXPORT le_file final : public executable_file {
public:
    /// Load LE/LX file from filesystem
    static le_file from_file(const std::filesystem::path& path);

    /// Load LE/LX file from memory
    static le_file from_memory(std::span<const uint8_t> data);

    /// Load LE/LX from memory, optionally stripping DOS extender stub
    /// If auto_strip is true and file is bound, extracts the LE/LX portion
    static le_file from_memory(std::span<const uint8_t> data, bool auto_strip);

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

    /// Check if file was bound to a DOS extender (stub stripped on load)
    [[nodiscard]] bool was_bound() const;

    /// Get detected DOS extender type (if was bound)
    [[nodiscard]] dos_extender_type extender_type() const;

    // =========================================================================
    // Header accessors
    // =========================================================================

    /// CPU type required
    [[nodiscard]] le_cpu_type cpu_type() const;

    /// Target operating system
    [[nodiscard]] le_os_type os_type() const;

    /// Module version
    [[nodiscard]] uint32_t module_version() const;

    /// Module flags
    [[nodiscard]] le_module_flags module_flags() const;

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
    // Tables and directories (lazy-parsed)
    // =========================================================================

    /// Fixup/relocation records
    [[nodiscard]] std::shared_ptr<le_fixup_directory> fixups() const;

    /// Entry table (exports)
    [[nodiscard]] std::shared_ptr<le_entry_table> entries() const;

    /// Resource table (if present)
    [[nodiscard]] std::shared_ptr<le_resource_table> resources() const;

    /// Import module name table
    [[nodiscard]] std::shared_ptr<le_import_module_table> import_modules() const;

    /// Import procedure name table
    [[nodiscard]] std::shared_ptr<le_import_procedure_table> import_procedures() const;

    /// Resident name table
    [[nodiscard]] std::vector<std::pair<std::string, uint16_t>> resident_names() const;

    /// Non-resident name table
    [[nodiscard]] std::vector<std::pair<std::string, uint16_t>> nonresident_names() const;

    // =========================================================================
    // VxD-specific (Windows Virtual Device Drivers)
    // =========================================================================

    /// VxD device ID (if VxD)
    [[nodiscard]] uint16_t vxd_device_id() const;

    /// DDK version (if VxD)
    [[nodiscard]] uint16_t vxd_ddk_version() const;

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

    void parse_headers();
    void parse_objects();
    void detect_extender_type();
    void adjust_offsets_for_stripped_stub(uint32_t stub_size);

    std::vector<uint8_t> data_;
    std::vector<le_object> objects_;
    std::vector<le_page_entry> page_table_;

    // Format identification
    bool is_lx_ = false;
    bool was_bound_ = false;
    dos_extender_type extender_type_ = dos_extender_type::UNKNOWN;
    uint32_t le_header_offset_ = 0;  // Offset to LE/LX header in file

    // Header fields
    le_cpu_type cpu_type_ = le_cpu_type::I386;
    le_os_type os_type_ = le_os_type::UNKNOWN;
    uint32_t module_version_ = 0;
    le_module_flags module_flags_ = {};
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
    uint32_t fixup_page_table_offset_ = 0;
    uint32_t fixup_record_table_offset_ = 0;
    uint32_t import_module_table_offset_ = 0;
    uint32_t import_module_count_ = 0;
    uint32_t import_procedure_table_offset_ = 0;

    // Absolute file offsets
    uint32_t data_pages_offset_ = 0;
    uint32_t nonresident_name_table_offset_ = 0;
    uint32_t nonresident_name_table_size_ = 0;
    uint32_t debug_info_offset_ = 0;
    uint32_t debug_info_size_ = 0;

    // VxD-specific
    uint16_t vxd_device_id_ = 0;
    uint16_t vxd_ddk_version_ = 0;

    // Lazy-parsed directories
    mutable std::shared_ptr<le_fixup_directory> fixups_;
    mutable std::shared_ptr<le_entry_table> entries_;
    mutable std::shared_ptr<le_resource_table> resources_;
    mutable std::shared_ptr<le_import_module_table> import_modules_;
    mutable std::shared_ptr<le_import_procedure_table> import_procedures_;

    mutable diagnostic_collector diagnostics_;
};

} // namespace libexe

#endif // LIBEXE_FORMATS_LE_FILE_HPP
```

## DataScript Format Specification

### src/libexe/formats/le/le_header.ds

```datascript
// LE/LX Linear Executable Header Format
// Used by DOS/4GW, DOS/32A, OS/2 2.0+, Windows VxD

package com.example.le;

// LE header magic values
const LE_MAGIC = 0x454C;  // 'LE'
const LX_MAGIC = 0x584C;  // 'LX'

// LE/LX Header (at offset from MZ header 0x3C)
struct LEHeader {
    uint16 magic;                       // 0x00: 'LE' or 'LX'
    uint8  byte_order;                  // 0x02: 0=little endian
    uint8  word_order;                  // 0x03: 0=little endian
    uint32 format_level;                // 0x04: Format version (0)
    uint16 cpu_type;                    // 0x08: 1=286, 2=386, 3=486
    uint16 os_type;                     // 0x0A: 0=unknown, 1=OS/2, 2=Win, 3=DOS4, 4=Win386
    uint32 module_version;              // 0x0C: User-defined version
    uint32 module_flags;                // 0x10: Module type flags
    uint32 page_count;                  // 0x14: Number of memory pages
    uint32 eip_object;                  // 0x18: Object # for EIP (1-based)
    uint32 eip;                         // 0x1C: Entry point offset
    uint32 esp_object;                  // 0x20: Object # for ESP (1-based)
    uint32 esp;                         // 0x24: Stack pointer offset
    uint32 page_size;                   // 0x28: Memory page size (4096)
    uint32 page_offset_shift;           // 0x2C: LE: bytes on last page, LX: shift
    uint32 fixup_section_size;          // 0x30: Total fixup data size
    uint32 fixup_section_checksum;      // 0x34
    uint32 loader_section_size;         // 0x38
    uint32 loader_section_checksum;     // 0x3C
    uint32 object_table_offset;         // 0x40: Relative to LE header
    uint32 object_count;                // 0x44: Number of objects
    uint32 page_table_offset;           // 0x48: Object page table
    uint32 iter_pages_offset;           // 0x4C: Iterated pages offset
    uint32 resource_table_offset;       // 0x50
    uint32 resource_count;              // 0x54
    uint32 resident_name_table_offset;  // 0x58
    uint32 entry_table_offset;          // 0x5C
    uint32 directives_offset;           // 0x60: Module directives
    uint32 directives_count;            // 0x64
    uint32 fixup_page_table_offset;     // 0x68
    uint32 fixup_record_table_offset;   // 0x6C
    uint32 import_module_table_offset;  // 0x70
    uint32 import_module_count;         // 0x74
    uint32 import_proc_table_offset;    // 0x78
    uint32 per_page_checksum_offset;    // 0x7C
    uint32 data_pages_offset;           // 0x80: ABSOLUTE file offset
    uint32 preload_page_count;          // 0x84
    uint32 nonresident_name_offset;     // 0x88: ABSOLUTE file offset
    uint32 nonresident_name_size;       // 0x8C
    uint32 nonresident_name_checksum;   // 0x90
    uint32 auto_data_object;            // 0x94
    uint32 debug_info_offset;           // 0x98: ABSOLUTE file offset
    uint32 debug_info_size;             // 0x9C
    uint32 instance_preload;            // 0xA0
    uint32 instance_demand;             // 0xA4
    uint32 heap_size;                   // 0xA8
    uint32 stack_size;                  // 0xAC (0xAC for LE, more for LX)
};

// Object Table Entry (24 bytes)
struct ObjectTableEntry {
    uint32 virtual_size;                // 0x00
    uint32 base_address;                // 0x04: Relocation base
    uint32 flags;                       // 0x08: Object flags
    uint32 page_table_index;            // 0x0C: 1-based index into page table
    uint32 page_count;                  // 0x10: Number of page entries
    uint32 reserved;                    // 0x14: Must be 0
};

// LE Object Page Table Entry (4 bytes) - Direct offsets
struct LEPageEntry {
    uint24 offset;                      // Page data offset (direct)
    uint8  flags;                       // Page flags
};

// LX Object Page Table Entry (8 bytes) - Shifted offsets
struct LXPageEntry {
    uint32 offset;                      // Page data offset (shifted by page_offset_shift)
    uint16 size;                        // Actual data size in file
    uint16 flags;                       // Page flags
};

// Resource Table Entry
struct ResourceEntry {
    uint16 type_id;                     // Resource type
    uint16 name_id;                     // Resource name
    uint32 resource_size;               // Size in bytes
    uint16 object;                      // Object containing resource
    uint32 offset;                      // Offset within object
};

// Resident/Non-Resident Name Table Entry
struct NameEntry {
    uint8  length;                      // String length (0 = end of table)
    char   name[length];                // Name string
    uint16 ordinal;                     // Entry point ordinal
};
```

## Diagnostic Codes

Add to `include/libexe/core/diagnostic.hpp`:

```cpp
// LE/LX format diagnostics
LE_INVALID_MAGIC,           // Magic is not 'LE' or 'LX'
LE_INVALID_BYTE_ORDER,      // Unsupported byte order
LE_INVALID_PAGE_SIZE,       // Page size not power of 2
LE_INVALID_OBJECT_INDEX,    // Object index out of bounds
LE_OVERLAPPING_OBJECTS,     // Objects have overlapping addresses
LE_INVALID_PAGE_OFFSET,     // Page offset beyond file
LE_COMPRESSED_PAGE,         // Compressed page (not supported)
LE_FIXUP_OVERFLOW,          // Fixup target overflow
LE_IMPORT_UNRESOLVED,       // Unresolved import reference
LE_ENTRY_INVALID,           // Invalid entry table record
LE_STUB_DETECTED,           // DOS extender stub detected
LE_VXD_NO_DDB,              // VxD missing Device Descriptor Block
```

## DOS Extender Stripping

The `le_file` class transparently handles bound executables:

```cpp
// Detection at load time
le_file le_file::from_memory(std::span<const uint8_t> data, bool auto_strip) {
    le_file result;

    // Check if this is a bound MZ+LE file
    if (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z') {
        // Find LE header offset from MZ header
        uint32_t le_offset = find_le_header_offset(data);

        if (le_offset > 0 && auto_strip) {
            // Detect extender type before stripping
            result.detect_extender_type(data);
            result.was_bound_ = true;

            // Strip stub and adjust offsets
            result.data_.assign(data.begin() + le_offset, data.end());
            result.adjust_offsets_for_stripped_stub(le_offset);
        } else {
            result.data_.assign(data.begin(), data.end());
            result.le_header_offset_ = le_offset;
        }
    } else {
        // Already unbound LE/LX
        result.data_.assign(data.begin(), data.end());
        result.le_header_offset_ = 0;
    }

    result.parse_headers();
    result.parse_objects();
    return result;
}
```

## File Structure

```
include/libexe/
├── formats/
│   ├── le_file.hpp              # Main class
│   └── executable_factory.hpp   # Updated variant
├── le/
│   ├── types.hpp                # Enums and flags
│   ├── object.hpp               # Object/page structures
│   └── directories/
│       ├── fixup.hpp            # Fixup records
│       ├── entry.hpp            # Entry table
│       └── resource.hpp         # Resources

src/libexe/
├── formats/le/
│   └── le_header.ds             # DataScript spec
├── le_file.cpp                  # Main implementation
├── le_object_parser.cpp         # Object/page parsing
└── parsers/
    ├── le_fixup_parser.cpp
    ├── le_entry_parser.cpp
    └── le_name_parser.cpp

unittests/
├── test_le_file.cpp             # Unit tests
└── fixtures/
    └── le/                      # Test executables
```

## Implementation Priority

1. **Phase 1: Core Header Parsing**
   - `le_file` basic structure
   - Header parsing (LE and LX variants)
   - Object table parsing
   - Page table parsing (both LE 4-byte and LX 8-byte formats)

2. **Phase 2: DOS Extender Support**
   - Stub detection and stripping
   - Offset adjustment
   - Extender type identification

3. **Phase 3: Tables**
   - Entry table parsing
   - Import module/procedure tables
   - Resident/non-resident name tables

4. **Phase 4: Fixups**
   - Fixup page table
   - Fixup record parsing
   - All fixup source/target types

5. **Phase 5: Advanced**
   - Resource table
   - VxD-specific fields
   - Iterated/compressed pages
   - Debug information

## Test Files

Recommended test corpus:
- DOS/4GW executables (games)
- DOS/32A bound executables
- PMODE/W executables
- OS/2 LX executables
- Windows VxD drivers

## References

- `docs/DOS_EXTENDER_STRIPPING.md` - Extender detection/stripping
- `docs/le_exe_headers.h` - C structure definitions
- `docs/32-bit Linear eXecutable Module Format (LX) Specification.pdf` - **Official IBM LX spec (Rev 11, 2001)**
- `docs/lxexe.doc` - IBM LX specification (1992)
- `docs/le-1.html` - LE format reference (CPU types including i860, MIPS)
- DOS/32A source (`1/dos32a/src/sb/`) - Reference implementation
- https://www.retroreversing.com/WindowsExecutables - Historical context (LE based on NE, primarily used by DOS extenders)
