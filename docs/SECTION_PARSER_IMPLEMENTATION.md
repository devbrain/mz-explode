# Section Parser Implementation Plan

**Date:** 2025-12-08
**Status:** Planning Phase
**Goal:** Implement comprehensive parsers for all PE and NE executable sections

---

## Executive Summary

This document outlines the implementation strategy for parsing executable file sections in both PE (Portable Executable) and NE (New Executable) formats. Section parsing is critical for:

- Code and data extraction
- Import/Export analysis
- Relocation processing
- Debug information access
- TLS (Thread Local Storage) handling
- Resource location and extraction

---

## Table of Contents

1. [PE Format Sections](#pe-format-sections)
2. [NE Format Segments](#ne-format-segments)
3. [Implementation Architecture](#implementation-architecture)
4. [API Design](#api-design)
5. [Phase 1: Core Section Parsing](#phase-1-core-section-parsing)
6. [Phase 2: Data Directory Parsing](#phase-2-data-directory-parsing)
7. [Phase 3: Advanced Features](#phase-3-advanced-features)
8. [Testing Strategy](#testing-strategy)

---

## PE Format Sections

### Overview

PE files organize data into **sections** (also called "segments" in some contexts). Each section has:
- **Name**: 8-byte ASCII name (e.g., `.text`, `.data`, `.rdata`)
- **Virtual Address**: RVA (Relative Virtual Address) where section loads in memory
- **Virtual Size**: Size of section in memory
- **Raw Data Pointer**: Offset in file where section data begins
- **Raw Data Size**: Size of section data in file
- **Characteristics**: Flags indicating permissions and properties

### Standard PE Sections

| Section Name | Purpose | Characteristics |
|--------------|---------|-----------------|
| `.text` | Executable code | `IMAGE_SCN_CNT_CODE`, `IMAGE_SCN_MEM_EXECUTE`, `IMAGE_SCN_MEM_READ` |
| `.data` | Initialized data | `IMAGE_SCN_CNT_INITIALIZED_DATA`, `IMAGE_SCN_MEM_READ`, `IMAGE_SCN_MEM_WRITE` |
| `.rdata` | Read-only data, import tables | `IMAGE_SCN_CNT_INITIALIZED_DATA`, `IMAGE_SCN_MEM_READ` |
| `.bss` | Uninitialized data | `IMAGE_SCN_CNT_UNINITIALIZED_DATA`, `IMAGE_SCN_MEM_READ`, `IMAGE_SCN_MEM_WRITE` |
| `.idata` | Import directory | `IMAGE_SCN_CNT_INITIALIZED_DATA`, `IMAGE_SCN_MEM_READ`, `IMAGE_SCN_MEM_WRITE` |
| `.edata` | Export directory | `IMAGE_SCN_CNT_INITIALIZED_DATA`, `IMAGE_SCN_MEM_READ` |
| `.pdata` | Exception information (x64) | `IMAGE_SCN_CNT_INITIALIZED_DATA`, `IMAGE_SCN_MEM_READ` |
| `.rsrc` | Resources | `IMAGE_SCN_CNT_INITIALIZED_DATA`, `IMAGE_SCN_MEM_READ` |
| `.reloc` | Base relocations | `IMAGE_SCN_CNT_INITIALIZED_DATA`, `IMAGE_SCN_MEM_READ`, `IMAGE_SCN_MEM_DISCARDABLE` |
| `.tls` | Thread Local Storage | `IMAGE_SCN_CNT_INITIALIZED_DATA`, `IMAGE_SCN_MEM_READ`, `IMAGE_SCN_MEM_WRITE` |
| `.debug` | Debug information | `IMAGE_SCN_CNT_INITIALIZED_DATA`, `IMAGE_SCN_MEM_READ`, `IMAGE_SCN_MEM_DISCARDABLE` |

### Section Characteristics Flags

```cpp
enum class section_characteristics : uint32_t {
    // Content type
    CNT_CODE                = 0x00000020,  // Section contains code
    CNT_INITIALIZED_DATA    = 0x00000040,  // Section contains initialized data
    CNT_UNINITIALIZED_DATA  = 0x00000080,  // Section contains uninitialized data

    // Alignment
    ALIGN_1BYTES            = 0x00100000,
    ALIGN_2BYTES            = 0x00200000,
    ALIGN_4BYTES            = 0x00300000,
    ALIGN_8BYTES            = 0x00400000,
    ALIGN_16BYTES           = 0x00500000,
    ALIGN_32BYTES           = 0x00600000,
    ALIGN_64BYTES           = 0x00700000,
    ALIGN_128BYTES          = 0x00800000,
    ALIGN_256BYTES          = 0x00900000,
    ALIGN_512BYTES          = 0x00A00000,
    ALIGN_1024BYTES         = 0x00B00000,
    ALIGN_2048BYTES         = 0x00C00000,
    ALIGN_4096BYTES         = 0x00D00000,
    ALIGN_8192BYTES         = 0x00E00000,

    // Section properties
    LNK_NRELOC_OVFL         = 0x01000000,  // Section contains extended relocations
    MEM_DISCARDABLE         = 0x02000000,  // Section can be discarded
    MEM_NOT_CACHED          = 0x04000000,  // Section is not cacheable
    MEM_NOT_PAGED           = 0x08000000,  // Section is not pageable
    MEM_SHARED              = 0x10000000,  // Section is shared
    MEM_EXECUTE             = 0x20000000,  // Section is executable
    MEM_READ                = 0x40000000,  // Section is readable
    MEM_WRITE               = 0x80000000   // Section is writable
};
```

---

## NE Format Segments

### Overview

NE files organize code and data into **segments**. Each segment has:
- **Sector**: File offset in 512-byte sectors (or alignment-shifted bytes)
- **Length**: Segment size in bytes
- **Flags**: Segment properties (code/data, moveable/fixed, preload, etc.)
- **Minimum Allocation**: Minimum memory allocation size

### NE Segment Types

| Segment Type | Flags | Purpose |
|--------------|-------|---------|
| **Code Segment** | `0x0000` (data=0) | Executable code |
| **Data Segment** | `0x0001` (data=1) | Initialized/uninitialized data |

### NE Segment Flags

```cpp
enum class ne_segment_flags : uint16_t {
    DATA            = 0x0001,  // 0=code, 1=data
    ALLOCATED       = 0x0002,  // Segment is allocated
    LOADED          = 0x0004,  // Segment is loaded
    MOVEABLE        = 0x0010,  // Segment is moveable (can relocate)
    PURE            = 0x0020,  // Segment is pure/shareable (for code segments)
    PRELOAD         = 0x0040,  // Segment should be preloaded
    READ_ONLY       = 0x0080,  // Execute-only (code) or read-only (data)
    RELOC_INFO      = 0x0100,  // Segment has relocation info
    CONFORMING      = 0x0200,  // Conforming segment (code only)
    PRIVILEGE       = 0x0C00,  // Privilege level (ring 0-3) - mask
    DISCARDABLE     = 0x1000   // Segment is discardable
};
```

### NE Segment Table Structure

Each entry in the NE segment table:
```cpp
struct ne_segment_entry {
    uint16_t sector;          // File sector (or byte offset >> alignment_shift)
    uint16_t length;          // Segment length in bytes (0 = 65536)
    uint16_t flags;           // Segment flags
    uint16_t min_alloc;       // Minimum allocation size (0 = 65536)
};
```

**Important**: The `sector` field's interpretation depends on the alignment shift:
- **Alignment Shift**: Stored in NE header (`ne_align`)
- **Byte Offset**: `sector << alignment_shift`
- **Common values**: 4 (16-byte alignment), 9 (512-byte sectors)

---

## Implementation Architecture

### Current State

**Existing Implementation** (as of Phase 1-5):

```cpp
// include/libexe/pe_file.hpp
class pe_file {
    // Basic section access
    std::vector<section> sections() const;
    std::optional<section> find_section(std::string_view name) const;
    std::optional<section> get_code_section() const;

    // Current section structure (minimal)
    struct section {
        std::string name;
        uint32_t virtual_address;
        uint32_t virtual_size;
        std::span<const uint8_t> data;
        uint32_t characteristics;
    };
};

// include/libexe/ne_file.hpp
class ne_file {
    // Basic segment access
    std::vector<ne_segment> segments() const;
    std::optional<ne_segment> get_segment(size_t index) const;
    std::optional<ne_segment> get_code_segment() const;

    // Current segment structure (minimal)
    struct ne_segment {
        uint16_t sector;
        uint16_t length;
        uint16_t flags;
        uint16_t min_alloc;
        std::span<const uint8_t> data;
    };
};
```

**Limitations**:
- No characteristic flag parsing/interpretation
- No RVA-to-file-offset conversion
- No data directory parsing
- Limited metadata extraction

---

### Proposed Enhanced Architecture

```cpp
// include/libexe/section.hpp
namespace libexe {

/**
 * Section type classification
 */
enum class section_type {
    CODE,               // Executable code
    DATA,               // Initialized data
    BSS,                // Uninitialized data
    IMPORT,             // Import directory
    EXPORT,             // Export directory
    RESOURCE,           // Resources
    RELOCATION,         // Base relocations
    DEBUG,              // Debug information
    TLS,                // Thread Local Storage
    EXCEPTION,          // Exception handling (pdata)
    UNKNOWN             // Unknown/custom section
};

/**
 * PE Section - Enhanced metadata
 */
struct LIBEXE_EXPORT pe_section {
    // Basic info
    std::string name;                    // Section name (e.g., ".text")
    section_type type;                   // Classified section type

    // Memory layout
    uint32_t virtual_address;            // RVA where section loads
    uint32_t virtual_size;               // Size in memory
    uint32_t raw_data_offset;            // File offset
    uint32_t raw_data_size;              // Size in file

    // Properties
    uint32_t characteristics;            // Raw characteristics flags
    uint32_t alignment;                  // Section alignment (bytes)

    // Data access
    std::span<const uint8_t> data;       // Section data

    // Characteristics helpers
    [[nodiscard]] bool is_code() const;
    [[nodiscard]] bool is_data() const;
    [[nodiscard]] bool is_readable() const;
    [[nodiscard]] bool is_writable() const;
    [[nodiscard]] bool is_executable() const;
    [[nodiscard]] bool is_discardable() const;
    [[nodiscard]] bool is_shared() const;

    // RVA conversion
    [[nodiscard]] std::optional<size_t> rva_to_offset(uint32_t rva) const;
    [[nodiscard]] bool contains_rva(uint32_t rva) const;
};

/**
 * NE Segment - Enhanced metadata
 */
struct LIBEXE_EXPORT ne_segment {
    // Basic info
    uint16_t index;                      // Segment index (1-based)
    section_type type;                   // Code or data

    // File layout
    uint32_t file_offset;                // Computed: sector << alignment_shift
    uint16_t file_size;                  // Length in file (0 = 65536)

    // Memory layout
    uint16_t min_alloc_size;             // Minimum allocation (0 = 65536)

    // Properties
    uint16_t flags;                      // Raw segment flags

    // Data access
    std::span<const uint8_t> data;       // Segment data

    // Flag helpers
    [[nodiscard]] bool is_code() const;
    [[nodiscard]] bool is_data() const;
    [[nodiscard]] bool is_moveable() const;
    [[nodiscard]] bool is_preload() const;
    [[nodiscard]] bool is_read_only() const;
    [[nodiscard]] bool is_discardable() const;
    [[nodiscard]] bool has_relocations() const;
};

} // namespace libexe
```

---

## API Design

### PE Section Parser API

```cpp
// include/libexe/pe_section_parser.hpp
namespace libexe {

/**
 * PE Section Parser
 *
 * Provides comprehensive PE section analysis and data extraction
 */
class LIBEXE_EXPORT pe_section_parser {
public:
    /**
     * Parse all sections from PE file
     *
     * @param file_data Complete PE file data
     * @param pe PE file wrapper
     * @return Vector of parsed sections with metadata
     */
    static std::vector<pe_section> parse_sections(
        std::span<const uint8_t> file_data,
        const pe_file& pe
    );

    /**
     * Classify section type based on name and characteristics
     *
     * @param name Section name
     * @param characteristics Section characteristics flags
     * @return Classified section type
     */
    static section_type classify_section(
        std::string_view name,
        uint32_t characteristics
    );

    /**
     * Convert RVA to file offset using section table
     *
     * @param sections All PE sections
     * @param rva Relative Virtual Address
     * @return File offset, or nullopt if RVA not in any section
     */
    static std::optional<size_t> rva_to_file_offset(
        const std::vector<pe_section>& sections,
        uint32_t rva
    );

    /**
     * Find section containing RVA
     *
     * @param sections All PE sections
     * @param rva Relative Virtual Address
     * @return Pointer to section, or nullptr if not found
     */
    static const pe_section* find_section_by_rva(
        const std::vector<pe_section>& sections,
        uint32_t rva
    );

    /**
     * Extract section alignment from characteristics
     *
     * @param characteristics Section characteristics flags
     * @return Alignment in bytes (e.g., 4096 for PAGE alignment)
     */
    static uint32_t extract_alignment(uint32_t characteristics);
};

} // namespace libexe
```

### NE Segment Parser API

```cpp
// include/libexe/ne_segment_parser.hpp
namespace libexe {

/**
 * NE Segment Parser
 *
 * Provides comprehensive NE segment analysis and data extraction
 */
class LIBEXE_EXPORT ne_segment_parser {
public:
    /**
     * Parse all segments from NE file
     *
     * @param file_data Complete NE file data
     * @param ne NE file wrapper
     * @return Vector of parsed segments with metadata
     */
    static std::vector<ne_segment> parse_segments(
        std::span<const uint8_t> file_data,
        const ne_file& ne
    );

    /**
     * Compute segment file offset from sector and alignment
     *
     * @param sector Sector value from segment table
     * @param alignment_shift Alignment shift from NE header
     * @return File offset in bytes
     */
    static uint32_t compute_file_offset(
        uint16_t sector,
        uint16_t alignment_shift
    );

    /**
     * Classify segment type based on flags
     *
     * @param flags Segment flags
     * @return Code or data classification
     */
    static section_type classify_segment(uint16_t flags);

    /**
     * Get actual segment size (handles 0 = 65536 special case)
     *
     * @param length Raw length from segment table
     * @return Actual size in bytes
     */
    static uint32_t get_actual_size(uint16_t length);
};

} // namespace libexe
```

---

## Phase 1: Core Section Parsing

### Objective

Implement basic section/segment parsing with enhanced metadata extraction.

### Tasks

#### 1.1 Create Section Header Files

**File**: `include/libexe/section.hpp`

```cpp
#ifndef LIBEXE_SECTION_HPP
#define LIBEXE_SECTION_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <span>
#include <string>
#include <optional>
#include <vector>

namespace libexe {

// Enum definitions (section_type, section_characteristics)
// Struct definitions (pe_section, ne_segment)
// Inline helper methods

} // namespace libexe

#endif // LIBEXE_SECTION_HPP
```

#### 1.2 Implement PE Section Parser

**File**: `include/libexe/pe_section_parser.hpp` + `src/libexe/pe_section_parser.cpp`

**Implementation**:
- Parse IMAGE_SECTION_HEADER array from PE
- Extract all metadata fields
- Compute file offsets and validate bounds
- Implement characteristic flag interpretation
- Add RVA-to-offset conversion logic

**Key Algorithm** (RVA to File Offset):
```cpp
std::optional<size_t> rva_to_file_offset(
    const std::vector<pe_section>& sections,
    uint32_t rva
) {
    for (const auto& section : sections) {
        if (rva >= section.virtual_address &&
            rva < section.virtual_address + section.virtual_size) {
            // RVA is within this section
            uint32_t offset_in_section = rva - section.virtual_address;
            return section.raw_data_offset + offset_in_section;
        }
    }
    return std::nullopt;  // RVA not found
}
```

#### 1.3 Implement NE Segment Parser

**File**: `include/libexe/ne_segment_parser.hpp` + `src/libexe/ne_segment_parser.cpp`

**Implementation**:
- Parse segment table from NE header
- Use `ne_align` to compute file offsets: `sector << alignment_shift`
- Extract segment flags and classify
- Handle special cases: length=0 means 65536 bytes
- Validate segment bounds against file size

**Key Algorithm** (Segment Offset Calculation):
```cpp
uint32_t compute_file_offset(uint16_t sector, uint16_t alignment_shift) {
    return static_cast<uint32_t>(sector) << alignment_shift;
}

uint32_t get_actual_size(uint16_t length) {
    return (length == 0) ? 65536 : length;
}
```

#### 1.4 Update pe_file and ne_file Classes

Enhance existing classes to use new parsers:

```cpp
// pe_file.hpp additions
class pe_file {
    // New methods
    std::vector<pe_section> parse_sections() const;
    std::optional<size_t> rva_to_offset(uint32_t rva) const;
    const pe_section* find_section_by_rva(uint32_t rva) const;
};

// ne_file.hpp additions
class ne_file {
    // New methods
    std::vector<ne_segment> parse_segments() const;
    uint32_t get_segment_file_offset(uint16_t segment_index) const;
};
```

#### 1.5 Write Comprehensive Tests

**Test Files**:
- `unittests/test_pe_section_parser.cpp`
- `unittests/test_ne_segment_parser.cpp`

**Test Coverage**:
- Section/segment count validation
- Characteristic flag parsing
- RVA-to-offset conversion (PE)
- Sector-to-offset calculation (NE)
- Special cases (length=0, alignment shifts)
- Boundary conditions

---

## Phase 2: Data Directory Parsing

### Overview

PE files have a **Data Directory** in the Optional Header that points to important structures:

| Directory Index | Name | Purpose |
|----------------|------|---------|
| 0 | Export Table | `IMAGE_DIRECTORY_ENTRY_EXPORT` |
| 1 | Import Table | `IMAGE_DIRECTORY_ENTRY_IMPORT` |
| 2 | Resource Table | `IMAGE_DIRECTORY_ENTRY_RESOURCE` |
| 3 | Exception Table | `IMAGE_DIRECTORY_ENTRY_EXCEPTION` |
| 4 | Certificate Table | `IMAGE_DIRECTORY_ENTRY_SECURITY` |
| 5 | Base Relocation Table | `IMAGE_DIRECTORY_ENTRY_BASERELOC` |
| 6 | Debug Directory | `IMAGE_DIRECTORY_ENTRY_DEBUG` |
| 7 | Architecture Data | `IMAGE_DIRECTORY_ENTRY_ARCHITECTURE` |
| 8 | Global Pointer | `IMAGE_DIRECTORY_ENTRY_GLOBALPTR` |
| 9 | TLS Table | `IMAGE_DIRECTORY_ENTRY_TLS` |
| 10 | Load Config Table | `IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG` |
| 11 | Bound Import Table | `IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT` |
| 12 | Import Address Table | `IMAGE_DIRECTORY_ENTRY_IAT` |
| 13 | Delay Import Descriptor | `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT` |
| 14 | CLR Runtime Header | `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` |
| 15 | Reserved | (must be zero) |

### Tasks

#### 2.1 Import Directory Parser

**File**: `include/libexe/import_parser.hpp` + `src/libexe/import_parser.cpp`

Parse `IMAGE_IMPORT_DESCRIPTOR` array:
```cpp
struct import_entry {
    std::string dll_name;
    std::vector<std::string> function_names;  // By name
    std::vector<uint32_t> ordinals;           // By ordinal
};

std::vector<import_entry> parse_imports(
    std::span<const uint8_t> file_data,
    const pe_file& pe
);
```

#### 2.2 Export Directory Parser

**File**: `include/libexe/export_parser.hpp` + `src/libexe/export_parser.cpp`

Parse `IMAGE_EXPORT_DIRECTORY`:
```cpp
struct export_entry {
    std::string function_name;
    uint32_t ordinal;
    uint32_t rva;
    bool is_forwarded;
    std::string forwarder;  // If forwarded (e.g., "NTDLL.RtlFreeHeap")
};

struct export_directory {
    std::string dll_name;
    uint32_t base_ordinal;
    std::vector<export_entry> exports;
};

std::optional<export_directory> parse_exports(
    std::span<const uint8_t> file_data,
    const pe_file& pe
);
```

#### 2.3 Relocation Parser

**File**: `include/libexe/relocation_parser.hpp` + `src/libexe/relocation_parser.cpp`

Parse base relocation blocks:
```cpp
enum class relocation_type : uint8_t {
    ABSOLUTE    = 0,  // No relocation
    HIGH        = 1,  // High 16 bits
    LOW         = 2,  // Low 16 bits
    HIGHLOW     = 3,  // 32-bit field
    HIGHADJ     = 4,  // High 16 bits adjusted
    DIR64       = 10  // 64-bit field
};

struct relocation_entry {
    uint32_t rva;
    relocation_type type;
};

std::vector<relocation_entry> parse_relocations(
    std::span<const uint8_t> file_data,
    const pe_file& pe
);
```

#### 2.4 TLS Parser

**File**: `include/libexe/tls_parser.hpp` + `src/libexe/tls_parser.cpp`

Parse TLS directory:
```cpp
struct tls_directory {
    uint64_t raw_data_start;
    uint64_t raw_data_end;
    uint64_t index_address;
    uint64_t callbacks_address;
    uint32_t zero_fill_size;
    uint32_t characteristics;
    std::vector<uint64_t> callback_addresses;
};

std::optional<tls_directory> parse_tls(
    std::span<const uint8_t> file_data,
    const pe_file& pe
);
```

#### 2.5 Debug Directory Parser

**File**: `include/libexe/debug_parser.hpp` + `src/libexe/debug_parser.cpp`

Parse debug directory entries:
```cpp
enum class debug_type : uint32_t {
    UNKNOWN     = 0,
    COFF        = 1,
    CODEVIEW    = 2,
    FPO         = 3,
    MISC        = 4,
    EXCEPTION   = 5,
    FIXUP       = 6,
    BORLAND     = 9,
    REPRO       = 16
};

struct debug_entry {
    debug_type type;
    uint32_t timestamp;
    uint16_t major_version;
    uint16_t minor_version;
    std::span<const uint8_t> data;
};

std::vector<debug_entry> parse_debug_info(
    std::span<const uint8_t> file_data,
    const pe_file& pe
);
```

---

## Phase 3: Advanced Features

### 3.1 Section Entropy Analysis

For packer/protector detection:

```cpp
// include/libexe/entropy_analyzer.hpp
class LIBEXE_EXPORT entropy_analyzer {
public:
    /**
     * Calculate Shannon entropy of data
     *
     * @param data Data to analyze
     * @return Entropy value (0.0 = no entropy, 8.0 = maximum for bytes)
     */
    static double calculate_entropy(std::span<const uint8_t> data);

    /**
     * Analyze all sections for high entropy (possible packing)
     *
     * @param sections PE sections
     * @return Map of section name to entropy
     */
    static std::map<std::string, double> analyze_sections(
        const std::vector<pe_section>& sections
    );
};
```

**High entropy (>7.0)** suggests:
- Compressed/packed data
- Encrypted data
- Protector/packer usage

### 3.2 Overlay Detection

Detect data appended after PE/NE file:

```cpp
// include/libexe/overlay_detector.hpp
struct overlay_info {
    size_t offset;          // Offset where overlay starts
    size_t size;            // Overlay size in bytes
    std::span<const uint8_t> data;
};

std::optional<overlay_info> detect_overlay(
    std::span<const uint8_t> file_data,
    const pe_file& pe
);
```

**Algorithm**:
1. Calculate expected file size from PE headers
2. Compare with actual file size
3. If larger, overlay exists

### 3.3 Rich Header Parser

Parse undocumented Rich header (build tool signature):

```cpp
// include/libexe/rich_header_parser.hpp
struct rich_header_entry {
    uint16_t product_id;    // Visual Studio component ID
    uint16_t build_number;  // Build number
    uint32_t use_count;     // Number of objects built with this tool
};

struct rich_header {
    uint32_t checksum;
    std::vector<rich_header_entry> entries;
};

std::optional<rich_header> parse_rich_header(
    std::span<const uint8_t> file_data
);
```

**Location**: Between DOS stub and PE header

---

## Testing Strategy

### Test Data Requirements

#### PE Test Files
- **Simple PE32**: Basic executable with `.text`, `.data` sections
- **Complex PE32+**: 64-bit with multiple data directories
- **Packed PE**: UPX-packed executable (high entropy `.text`)
- **DLL**: Export table parsing
- **TLS PE**: Thread Local Storage usage
- **Debug PE**: Debug directory and PDB info

#### NE Test Files
- **Windows 3.x Executable**: Multiple code/data segments
- **Windows 3.x DLL**: Export table
- **OS/2 Application**: Different alignment shift
- **Real-world samples**: PROGMAN.EXE, etc.

### Test Cases

#### PE Section Parser Tests
```cpp
TEST_CASE("PE Section Parser - Basic") {
    auto pe = pe_file::from_file("test32.exe");
    auto sections = pe_section_parser::parse_sections(file_data, pe);

    // Verify section count
    CHECK(sections.size() >= 3);  // Minimum: .text, .data, .rsrc

    // Verify .text section
    auto text_section = std::find_if(sections.begin(), sections.end(),
        [](const auto& s) { return s.name == ".text"; });
    REQUIRE(text_section != sections.end());
    CHECK(text_section->is_code());
    CHECK(text_section->is_executable());
    CHECK(text_section->is_readable());
    CHECK_FALSE(text_section->is_writable());
}

TEST_CASE("PE Section Parser - RVA Conversion") {
    auto pe = pe_file::from_file("test32.exe");
    auto sections = pe_section_parser::parse_sections(file_data, pe);

    // Test RVA in .text section
    uint32_t text_rva = sections[0].virtual_address + 0x100;
    auto offset = pe_section_parser::rva_to_file_offset(sections, text_rva);

    REQUIRE(offset.has_value());
    CHECK(offset.value() == sections[0].raw_data_offset + 0x100);
}
```

#### NE Segment Parser Tests
```cpp
TEST_CASE("NE Segment Parser - Offset Calculation") {
    auto ne = ne_file::from_file("PROGMAN.EXE");
    auto segments = ne_segment_parser::parse_segments(file_data, ne);

    // Verify segment count
    CHECK(segments.size() > 0);

    // Test offset calculation with alignment shift
    uint16_t alignment_shift = ne.alignment_shift();
    uint32_t expected_offset = segments[0].sector << alignment_shift;
    CHECK(segments[0].file_offset == expected_offset);
}

TEST_CASE("NE Segment Parser - Flag Interpretation") {
    auto ne = ne_file::from_file("PROGMAN.EXE");
    auto segments = ne_segment_parser::parse_segments(file_data, ne);

    // Find code segment
    auto code_seg = std::find_if(segments.begin(), segments.end(),
        [](const auto& s) { return s.is_code(); });

    REQUIRE(code_seg != segments.end());
    CHECK(code_seg->type == section_type::CODE);
    CHECK_FALSE(code_seg->is_data());
}
```

---

## Implementation Timeline

### Week 1: Phase 1 - Core Section Parsing
- Day 1-2: Create `section.hpp`, implement structures
- Day 3-4: Implement `pe_section_parser`
- Day 5-6: Implement `ne_segment_parser`
- Day 7: Write comprehensive tests

### Week 2: Phase 2 - Data Directory Parsing (Part 1)
- Day 1-2: Implement import parser
- Day 3-4: Implement export parser
- Day 5-6: Implement relocation parser
- Day 7: Write tests for parsers

### Week 3: Phase 2 - Data Directory Parsing (Part 2)
- Day 1-2: Implement TLS parser
- Day 3-4: Implement debug directory parser
- Day 5-7: Integration testing, documentation

### Week 4: Phase 3 - Advanced Features (Optional)
- Day 1-2: Entropy analysis
- Day 3-4: Overlay detection
- Day 5-6: Rich header parsing
- Day 7: Final testing and documentation

---

## Success Criteria

1. **Correctness**: All section metadata accurately parsed
2. **Coverage**: 100% of PE sections and NE segments accessible
3. **RVA Conversion**: Accurate RVA-to-offset translation for all valid RVAs
4. **Test Coverage**: ≥95% code coverage with comprehensive tests
5. **Documentation**: Complete API documentation and usage examples
6. **Performance**: Section parsing adds <10ms overhead to file loading

---

## References

- **Microsoft PE/COFF Specification**: `docs/pecoff.docx`
- **NE Format Specification**: `docs/ne.fmt`
- **DataScript Generated Headers**: `build/generated/libexe_format_pe.hh`, `libexe_format_ne.hh`
- **Existing Code**: `src/libexe/pe_file.cpp`, `src/libexe/ne_file.cpp`

---

**Last Updated**: 2025-12-08
**Status**: Planning Phase - Ready for Implementation
**Next Step**: Begin Phase 1 - Core Section Parsing
