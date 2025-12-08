# Phase 2: Data Directory Parsing - Implementation Plan

**Status**: 🚧 In Progress
**Started**: 2025-12-08
**Prerequisites**: Phase 1 (Section Parsing) ✅ Complete

## Overview

Phase 2 focuses on parsing PE data directories - specialized structures that provide metadata about imports, exports, relocations, and other critical executable features. These directories are referenced by RVAs in the PE optional header.

## PE Data Directory Structure

The PE optional header contains an array of 16 data directory entries:

```cpp
struct data_directory {
    uint32_t virtual_address;  // RVA to directory
    uint32_t size;             // Size of directory
};

// Standard directory indices
enum class directory_entry : uint32_t {
    EXPORT          = 0,   // Export directory
    IMPORT          = 1,   // Import directory
    RESOURCE        = 2,   // Resource directory (already implemented)
    EXCEPTION       = 3,   // Exception directory (.pdata)
    CERTIFICATE     = 4,   // Certificate table (digital signatures)
    BASE_RELOC      = 5,   // Base relocation table
    DEBUG           = 6,   // Debug directory
    ARCHITECTURE    = 7,   // Architecture-specific data
    GLOBAL_PTR      = 8,   // Global pointer register (IA64)
    TLS             = 9,   // Thread Local Storage
    LOAD_CONFIG     = 10,  // Load configuration directory
    BOUND_IMPORT    = 11,  // Bound import directory
    IAT             = 12,  // Import Address Table
    DELAY_IMPORT    = 13,  // Delay-load import directory
    CLR_HEADER      = 14,  // .NET CLR header
    RESERVED        = 15   // Reserved
};
```

## Implementation Priority

### High Priority (Week 2)
1. **Import Directory** - Most commonly used, critical for understanding dependencies
2. **Export Directory** - Essential for DLLs
3. **Base Relocations** - Required for ASLR understanding

### Medium Priority (Week 3)
4. **TLS Directory** - Thread-local storage information
5. **Exception Directory** - Exception handling (x64)
6. **Debug Directory** - Debug information metadata

### Low Priority (Future)
7. Load Configuration
8. Bound Imports
9. Delay-load Imports
10. Certificate Table

## Task 1: Import Directory Parser

### 1.1 Import Directory Structures

```cpp
// include/libexe/import_directory.hpp

namespace libexe {

/**
 * Imported function or ordinal
 */
struct import_entry {
    std::string name;           // Function name (empty if by ordinal)
    uint16_t ordinal;           // Ordinal number
    uint16_t hint;              // Index into export name table
    bool is_ordinal;            // true if imported by ordinal only
    uint64_t iat_rva;           // RVA in Import Address Table
};

/**
 * Imported DLL with all its functions
 */
struct import_dll {
    std::string name;                     // DLL name (e.g., "kernel32.dll")
    std::vector<import_entry> functions;  // Imported functions
    uint32_t ilt_rva;                     // Import Lookup Table RVA
    uint32_t iat_rva;                     // Import Address Table RVA
    uint32_t name_rva;                    // DLL name RVA
    uint32_t timestamp;                   // Bind timestamp
    uint32_t forwarder_chain;             // Forwarder chain
};

/**
 * Complete import directory
 */
struct import_directory {
    std::vector<import_dll> dlls;

    // Helper methods
    [[nodiscard]] size_t dll_count() const { return dlls.size(); }
    [[nodiscard]] size_t total_imports() const;
    [[nodiscard]] const import_dll* find_dll(std::string_view name) const;
    [[nodiscard]] bool imports_function(std::string_view dll, std::string_view function) const;
};

} // namespace libexe
```

### 1.2 Import Directory Parser

```cpp
// include/libexe/parsers/import_directory_parser.hpp

namespace libexe {

class LIBEXE_EXPORT import_directory_parser {
public:
    /**
     * Parse import directory from PE file
     *
     * Reads IMAGE_IMPORT_DESCRIPTOR array and all referenced data
     * (DLL names, function names, ordinals)
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections (for RVA conversion)
     * @param import_dir_rva RVA to import directory
     * @param import_dir_size Size of import directory
     * @param is_64bit true for PE32+, false for PE32
     * @return Parsed import directory
     */
    static import_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t import_dir_rva,
        uint32_t import_dir_size,
        bool is_64bit
    );

private:
    // Parse single IMAGE_IMPORT_DESCRIPTOR
    static import_dll parse_import_descriptor(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t descriptor_rva,
        bool is_64bit
    );

    // Parse Import Lookup Table (array of IMAGE_THUNK_DATA)
    static std::vector<import_entry> parse_ilt(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t ilt_rva,
        uint32_t iat_rva,
        bool is_64bit
    );

    // Parse IMAGE_IMPORT_BY_NAME structure
    static import_entry parse_import_by_name(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t rva,
        uint64_t iat_rva,
        bool is_ordinal
    );

    // Read null-terminated string at RVA
    static std::string read_string_at_rva(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t rva
    );
};

} // namespace libexe
```

### 1.3 DataScript Structures

Add to `src/libexe/formats/pe/pe_imports.ds`:

```datascript
package formats.pe.imports;

little;

/**
 * IMAGE_IMPORT_DESCRIPTOR
 *
 * Describes a single DLL import
 */
struct image_import_descriptor {
    uint32 OriginalFirstThunk;  // RVA to Import Lookup Table (ILT)
    uint32 TimeDateStamp;       // Bind timestamp (0 if not bound)
    uint32 ForwarderChain;      // Forwarder chain (usually -1)
    uint32 Name;                // RVA to DLL name
    uint32 FirstThunk;          // RVA to Import Address Table (IAT)
};

/**
 * IMAGE_THUNK_DATA32
 *
 * Entry in Import Lookup Table or Import Address Table (32-bit)
 */
struct image_thunk_data32 {
    uint32 u1;  // Union: AddressOfData (if bit 31 clear) or Ordinal (if bit 31 set)
};

/**
 * IMAGE_THUNK_DATA64
 *
 * Entry in Import Lookup Table or Import Address Table (64-bit)
 */
struct image_thunk_data64 {
    uint64 u1;  // Union: AddressOfData (if bit 63 clear) or Ordinal (if bit 63 set)
};

/**
 * IMAGE_IMPORT_BY_NAME
 *
 * Function name and hint
 */
struct image_import_by_name {
    uint16 Hint;       // Index into export name pointer table
    // Followed by null-terminated ASCII name
};
```

### 1.4 Implementation Steps

**Day 1-2: Core Import Parser**
1. Create DataScript structures for IMAGE_IMPORT_DESCRIPTOR
2. Implement `import_directory_parser::parse()`
3. Handle both PE32 and PE32+ (32-bit vs 64-bit thunks)
4. Parse Import Lookup Table (ILT)
5. Parse Import Address Table (IAT)

**Day 3: Import Entry Parsing**
1. Parse IMAGE_IMPORT_BY_NAME structures
2. Handle ordinal imports (bit 31/63 set)
3. Handle name imports (bit 31/63 clear)
4. Read DLL names and function names

**Day 4: Testing**
1. Write comprehensive tests for import parsing
2. Test with real PE files (kernel32.dll imports, etc.)
3. Test ordinal imports
4. Test both PE32 and PE32+ formats

### 1.5 Usage Example

```cpp
#include <libexe/pe_file.hpp>
#include <libexe/parsers/import_directory_parser.hpp>

auto pe = pe_file::from_file("program.exe");

// Get import directory RVA from data directories
uint32_t import_rva = pe.data_directory_rva(directory_entry::IMPORT);
uint32_t import_size = pe.data_directory_size(directory_entry::IMPORT);

if (import_rva != 0) {
    auto imports = import_directory_parser::parse(
        pe.file_data(),
        pe.sections(),
        import_rva,
        import_size,
        pe.is_64bit()
    );

    std::cout << "Imports from " << imports.dll_count() << " DLLs:\n";
    for (const auto& dll : imports.dlls) {
        std::cout << "  " << dll.name << " (" << dll.functions.size() << " functions)\n";
        for (const auto& func : dll.functions) {
            if (func.is_ordinal) {
                std::cout << "    #" << func.ordinal << "\n";
            } else {
                std::cout << "    " << func.name << "\n";
            }
        }
    }
}
```

## Task 2: Export Directory Parser

### 2.1 Export Directory Structures

```cpp
// include/libexe/export_directory.hpp

struct export_entry {
    std::string name;           // Function name (may be empty for unnamed)
    uint32_t ordinal;           // Ordinal number
    uint32_t rva;               // RVA to function code
    bool is_forwarded;          // true if forwarded to another DLL
    std::string forward_name;   // Forwarder string (e.g., "ntdll.RtlFreeHeap")
};

struct export_directory {
    std::string name;                       // DLL name
    uint32_t base;                          // Ordinal base
    uint32_t timestamp;                     // Export timestamp
    uint16_t major_version;                 // DLL version
    uint16_t minor_version;
    std::vector<export_entry> functions;    // Exported functions

    // Helper methods
    [[nodiscard]] size_t function_count() const { return functions.size(); }
    [[nodiscard]] const export_entry* find_by_name(std::string_view name) const;
    [[nodiscard]] const export_entry* find_by_ordinal(uint32_t ordinal) const;
};
```

### 2.2 DataScript Structures

Add to `src/libexe/formats/pe/pe_exports.ds`:

```datascript
package formats.pe.exports;

little;

/**
 * IMAGE_EXPORT_DIRECTORY
 *
 * Describes DLL exports
 */
struct image_export_directory {
    uint32 Characteristics;       // Reserved, must be 0
    uint32 TimeDateStamp;         // Time/date stamp
    uint16 MajorVersion;          // Major version
    uint16 MinorVersion;          // Minor version
    uint32 Name;                  // RVA to DLL name
    uint32 Base;                  // Ordinal base
    uint32 NumberOfFunctions;     // Number of entries in EAT
    uint32 NumberOfNames;         // Number of entries in name pointer table
    uint32 AddressOfFunctions;    // RVA to Export Address Table (EAT)
    uint32 AddressOfNames;        // RVA to name pointer table
    uint32 AddressOfNameOrdinals; // RVA to ordinal table
};
```

## Task 3: Base Relocation Parser

### 3.1 Relocation Structures

```cpp
// include/libexe/relocation_directory.hpp

struct relocation_entry {
    uint16_t offset;            // Offset within page
    uint8_t type;               // Relocation type (IMAGE_REL_BASED_*)
};

struct relocation_block {
    uint32_t page_rva;                         // Page RVA
    uint32_t block_size;                       // Block size in bytes
    std::vector<relocation_entry> entries;     // Relocations for this page
};

struct relocation_directory {
    std::vector<relocation_block> blocks;

    [[nodiscard]] size_t block_count() const { return blocks.size(); }
    [[nodiscard]] size_t total_relocations() const;
};
```

## Task 4: TLS Directory Parser

### 4.1 TLS Structures

```cpp
// include/libexe/tls_directory.hpp

struct tls_callback {
    uint64_t rva;
    std::string name;  // If available from exports
};

struct tls_directory {
    uint64_t raw_data_start_va;     // Start of TLS data
    uint64_t raw_data_end_va;       // End of TLS data
    uint64_t address_of_index;      // Address of TLS index
    uint64_t address_of_callbacks;  // Address of callback array
    uint32_t size_of_zero_fill;     // Size of zero fill
    uint32_t characteristics;       // Alignment
    std::vector<tls_callback> callbacks;
};
```

## Implementation Timeline

### Week 2 (Days 1-5)
- **Day 1-2**: Import directory parser + structures
- **Day 3**: Export directory parser + structures
- **Day 4**: Base relocation parser
- **Day 5**: Testing & integration

### Week 3 (Days 6-10)
- **Day 6**: TLS directory parser
- **Day 7**: Exception directory parser
- **Day 8**: Debug directory parser
- **Day 9**: Comprehensive testing
- **Day 10**: Documentation & code review

## Integration with pe_file

Add methods to `pe_file` class:

```cpp
class pe_file {
public:
    // Data directory accessors
    [[nodiscard]] uint32_t data_directory_rva(directory_entry entry) const;
    [[nodiscard]] uint32_t data_directory_size(directory_entry entry) const;
    [[nodiscard]] bool has_data_directory(directory_entry entry) const;

    // Parsed directories (cached)
    [[nodiscard]] std::shared_ptr<import_directory> imports() const;
    [[nodiscard]] std::shared_ptr<export_directory> exports() const;
    [[nodiscard]] std::shared_ptr<relocation_directory> relocations() const;
    [[nodiscard]] std::shared_ptr<tls_directory> tls() const;

private:
    // Cache parsed directories
    mutable std::shared_ptr<import_directory> imports_;
    mutable std::shared_ptr<export_directory> exports_;
    mutable std::shared_ptr<relocation_directory> relocations_;
    mutable std::shared_ptr<tls_directory> tls_;
};
```

## Success Criteria

✅ Import directory parser handles:
- Multiple DLLs
- Ordinal imports
- Name imports with hints
- Both PE32 and PE32+
- Null terminator detection

✅ Export directory parser handles:
- Named exports
- Ordinal-only exports
- Forwarded exports
- Export versioning

✅ Relocation parser handles:
- Multiple relocation blocks
- All relocation types
- Page-based organization

✅ All parsers:
- Use RVA-to-offset conversion from Phase 1
- Have comprehensive test coverage
- Are well-documented
- Follow snake_case naming

## Notes

- All data directories use RVAs, not file offsets
- Must use `pe_section_parser::rva_to_file_offset()` for conversions
- Import/Export parsing requires string reading at arbitrary RVAs
- Relocation blocks are variable-length (must parse size)
- TLS directory structure differs between PE32 and PE32+

---

**Next**: Start with Task 1 (Import Directory Parser)
