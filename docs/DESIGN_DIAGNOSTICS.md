# Diagnostics System Design

## Overview

The diagnostics system provides a unified way to report warnings, anomalies, and informational messages during PE/NE/MZ file parsing. Unlike exceptions (which indicate fatal parsing errors), diagnostics capture non-fatal observations that may be relevant for analysis.

## Design Goals

1. **Non-intrusive**: Diagnostics don't interrupt parsing flow
2. **Categorized**: Different severity levels and categories
3. **Locatable**: Each diagnostic knows where in the file it occurred
4. **Extensible**: Easy to add new diagnostic types
5. **Queryable**: Filter by severity, category, or location
6. **Zero-cost when disabled**: No overhead if diagnostics aren't collected

## Severity Levels

```cpp
enum class diagnostic_severity {
    INFO,       // Informational (unusual but valid)
    WARNING,    // Suspicious (potentially malformed)
    ANOMALY,    // Definite anomaly (malformation that still loads)
    ERROR       // Parsing error (recovered, but data may be incomplete)
};
```

### Severity Semantics

| Level | Meaning | Example |
|-------|---------|---------|
| INFO | Unusual but valid per spec | Non-standard alignment values |
| WARNING | Suspicious, possible evasion | Empty import entries |
| ANOMALY | Violates spec but loads | Zero sections, EP outside image |
| ERROR | Parse failure, recovered | Truncated import table |

## Categories

```cpp
enum class diagnostic_category : uint32_t {
    // Header categories
    DOS_HEADER      = 0x0100,
    PE_HEADER       = 0x0200,
    COFF_HEADER     = 0x0300,
    OPTIONAL_HEADER = 0x0400,
    SECTION_TABLE   = 0x0500,

    // Data directory categories
    IMPORT          = 0x1000,
    EXPORT          = 0x1100,
    RELOCATION      = 0x1200,
    RESOURCE        = 0x1300,
    EXCEPTION       = 0x1400,
    SECURITY        = 0x1500,
    DEBUG           = 0x1600,
    TLS             = 0x1700,
    LOAD_CONFIG     = 0x1800,
    BOUND_IMPORT    = 0x1900,
    DELAY_IMPORT    = 0x1A00,
    CLR             = 0x1B00,

    // Special categories
    RICH_HEADER     = 0x2000,
    OVERLAY         = 0x2100,
    ALIGNMENT       = 0x2200,
    ENTRY_POINT     = 0x2300,

    // NE-specific
    NE_HEADER       = 0x3000,
    NE_SEGMENT      = 0x3100,
    NE_RESOURCE     = 0x3200,
};
```

## Diagnostic Codes

Each diagnostic has a unique code combining category and specific issue:

```cpp
enum class diagnostic_code : uint32_t {
    // =========================================================================
    // PE Header (0x02xx)
    // =========================================================================
    PE_HEADER_IN_OVERLAY        = 0x0201,  // PE header beyond mapped region
    PE_DUAL_HEADER              = 0x0202,  // Different header on disk vs memory
    PE_WRITABLE_HEADER          = 0x0203,  // Header is RWX (low alignment)

    // =========================================================================
    // COFF Header (0x03xx)
    // =========================================================================
    COFF_ZERO_SECTIONS          = 0x0301,  // NumberOfSections = 0
    COFF_EXCESSIVE_SECTIONS     = 0x0302,  // NumberOfSections > 96
    COFF_RELOCS_STRIPPED_IGNORED = 0x0303, // Flag set but relocs present

    // =========================================================================
    // Optional Header (0x04xx)
    // =========================================================================
    OPT_ZERO_ENTRY_POINT        = 0x0401,  // AddressOfEntryPoint = 0
    OPT_EP_OUTSIDE_IMAGE        = 0x0402,  // EP beyond SizeOfImage
    OPT_EP_IN_HEADER            = 0x0403,  // EP within header region
    OPT_INVALID_IMAGEBASE       = 0x0404,  // ImageBase = 0 or kernel space
    OPT_UNALIGNED_IMAGEBASE     = 0x0405,  // ImageBase not 64KB aligned
    OPT_LOW_ALIGNMENT           = 0x0406,  // FileAlignment == SectionAlignment <= 0x200
    OPT_OVERSIZED_OPTIONAL_HDR  = 0x0407,  // SizeOfOptionalHeader > expected

    // =========================================================================
    // Section Table (0x05xx)
    // =========================================================================
    SECT_OVERLAP                = 0x0501,  // Sections overlap in file/memory
    SECT_BEYOND_FILE            = 0x0502,  // Section raw data beyond file end
    SECT_ZERO_RAW_SIZE          = 0x0503,  // PointerToRawData != 0 but SizeOfRawData = 0
    SECT_UNALIGNED              = 0x0504,  // Section not aligned to FileAlignment

    // =========================================================================
    // Import Directory (0x10xx)
    // =========================================================================
    IMP_EMPTY_IAT               = 0x1001,  // IAT empty, DLL skipped
    IMP_MISSING_DLL             = 0x1002,  // DLL name points to non-existent file
    IMP_BINARY_NAME             = 0x1003,  // Import name contains non-printable chars
    IMP_SELF_IMPORT             = 0x1004,  // Imports from own module
    IMP_TRUNCATED               = 0x1005,  // Missing null terminator
    IMP_FORWARDER_LOOP          = 0x1006,  // Circular forwarder chain

    // =========================================================================
    // Export Directory (0x11xx)
    // =========================================================================
    EXP_FORWARDER_LOOP          = 0x1101,  // Circular forwarder
    EXP_BINARY_NAME             = 0x1102,  // Non-printable export name
    EXP_ORDINAL_GAP             = 0x1103,  // Large gap in ordinal numbers

    // =========================================================================
    // Relocation Directory (0x12xx)
    // =========================================================================
    RELOC_UNUSUAL_TYPE          = 0x1201,  // Types 1,2,4,5,9 (rare/obfuscation)
    RELOC_INVALID_TYPE          = 0x1202,  // Type 8 or >10
    RELOC_HEADER_TARGET         = 0x1203,  // Relocation targets header
    RELOC_HIGH_DENSITY          = 0x1204,  // Many relocations to same region
    RELOC_VIRTUAL_CODE          = 0x1205,  // Virtual code pattern detected

    // =========================================================================
    // Rich Header (0x20xx)
    // =========================================================================
    RICH_CHECKSUM_MISMATCH      = 0x2001,  // XOR checksum doesn't validate
    RICH_TRUNCATED              = 0x2002,  // Incomplete Rich header

    // =========================================================================
    // Entry Point (0x23xx)
    // =========================================================================
    EP_IN_OVERLAY               = 0x2301,  // Entry point in overlay
    EP_NON_EXECUTABLE           = 0x2302,  // EP in non-executable section

    // =========================================================================
    // General (0xFFxx)
    // =========================================================================
    OVERLAPPING_DIRECTORIES     = 0xFF01,  // Multiple directories share region
    DIRECTORY_IN_HEADER         = 0xFF02,  // Data directory within header
    TRUNCATED_FILE              = 0xFF03,  // File smaller than declared
};
```

## Diagnostic Structure

```cpp
struct diagnostic {
    diagnostic_code code;           // Unique identifier
    diagnostic_severity severity;   // INFO/WARNING/ANOMALY/ERROR
    diagnostic_category category;   // What component generated this

    uint64_t file_offset;          // Where in file (0 if N/A)
    uint32_t rva;                  // RVA if applicable (0 if N/A)

    std::string message;           // Human-readable description
    std::string details;           // Additional context (optional)

    // Convenience methods
    [[nodiscard]] bool is_anomaly() const;
    [[nodiscard]] bool is_error() const;
    [[nodiscard]] std::string to_string() const;
};
```

## Diagnostic Collector

```cpp
class diagnostic_collector {
public:
    /// Add a diagnostic
    void add(diagnostic diag);

    /// Add diagnostic with builder pattern
    void add(diagnostic_code code, diagnostic_severity severity,
             std::string message, uint64_t offset = 0, uint32_t rva = 0);

    /// Query methods
    [[nodiscard]] const std::vector<diagnostic>& all() const;
    [[nodiscard]] std::vector<diagnostic> by_severity(diagnostic_severity sev) const;
    [[nodiscard]] std::vector<diagnostic> by_category(diagnostic_category cat) const;
    [[nodiscard]] std::vector<diagnostic> errors() const;
    [[nodiscard]] std::vector<diagnostic> anomalies() const;

    /// Summary
    [[nodiscard]] size_t count() const;
    [[nodiscard]] size_t error_count() const;
    [[nodiscard]] size_t anomaly_count() const;
    [[nodiscard]] bool has_errors() const;
    [[nodiscard]] bool has_anomalies() const;

    /// Clear all diagnostics
    void clear();

private:
    std::vector<diagnostic> diagnostics_;
};
```

## Integration with Parsers

### Option 1: Pass collector to parser (Dependency Injection)

```cpp
class pe_file {
public:
    static pe_file from_memory(std::span<const uint8_t> data,
                               diagnostic_collector* collector = nullptr);

    // Collector is optional - if null, diagnostics are discarded
};
```

### Option 2: Store in parsed object (Current Favorite)

```cpp
class pe_file {
public:
    /// Get all diagnostics generated during parsing
    [[nodiscard]] const diagnostic_collector& diagnostics() const;

    /// Check for specific diagnostic
    [[nodiscard]] bool has_diagnostic(diagnostic_code code) const;

    /// Quick checks
    [[nodiscard]] bool has_anomalies() const;
    [[nodiscard]] bool has_parse_errors() const;
};
```

### Option 3: Thread-local collector (Global)

Not recommended - makes testing harder and isn't thread-safe.

## Usage Example

```cpp
auto pe = pe_file::from_memory(data);

// Check for issues
if (pe.has_anomalies()) {
    std::cout << "Detected " << pe.diagnostics().anomaly_count() << " anomalies:\n";
    for (const auto& diag : pe.diagnostics().anomalies()) {
        std::cout << "  [" << std::hex << diag.file_offset << "] "
                  << diag.message << "\n";
    }
}

// Check specific condition
if (pe.has_diagnostic(diagnostic_code::RELOC_VIRTUAL_CODE)) {
    std::cout << "Warning: Virtual code technique detected\n";
}

// Filter by category
for (const auto& diag : pe.diagnostics().by_category(diagnostic_category::IMPORT)) {
    // Handle import-related diagnostics
}
```

## Convenience Macros (Internal Use)

For parser implementation:

```cpp
// In parser implementation
#define DIAG_ADD(collector, code, severity, msg, ...) \
    do { \
        if (collector) { \
            collector->add(diagnostic_code::code, \
                          diagnostic_severity::severity, \
                          msg, ##__VA_ARGS__); \
        } \
    } while(0)

// Usage in parser
if (num_sections == 0) {
    DIAG_ADD(diag_, COFF_ZERO_SECTIONS, ANOMALY,
             "NumberOfSections is zero - section-less PE file",
             pe_offset + 6, 0);
}
```

## Output Formats

### Human-Readable

```
[ANOMALY] 0x00000080: NumberOfSections is zero - section-less PE file
[WARNING] 0x00001000: Import name contains non-printable characters: "\x00\x01test"
[ERROR]   0x00002000: Import table truncated at file boundary
```

### JSON (for tooling)

```json
{
  "diagnostics": [
    {
      "code": "COFF_ZERO_SECTIONS",
      "severity": "ANOMALY",
      "category": "COFF_HEADER",
      "file_offset": 128,
      "rva": 0,
      "message": "NumberOfSections is zero - section-less PE file"
    }
  ],
  "summary": {
    "total": 3,
    "errors": 1,
    "anomalies": 1,
    "warnings": 1,
    "info": 0
  }
}
```

## Implementation Plan

### Phase 1: Core Infrastructure
1. Create `include/libexe/core/diagnostic.hpp`
2. Create `include/libexe/core/diagnostic_collector.hpp`
3. Create `src/libexe/core/diagnostic.cpp`
4. Add `diagnostics()` to `pe_file` class

### Phase 2: PE Header Diagnostics
5. Add diagnostics to `pe_file::parse_pe_headers()`
6. Add diagnostics to `pe_section_parser`

### Phase 3: Data Directory Diagnostics
7. Add diagnostics to import parser
8. Add diagnostics to export parser
9. Add diagnostics to relocation parser

### Phase 4: Advanced Detection
10. Implement virtual code detection
11. Implement forwarder loop detection
12. Implement overlay analysis

## Backward Compatibility

- All diagnostic methods are additive
- Existing code continues to work unchanged
- Exceptions still thrown for truly fatal errors (invalid file, I/O errors)
- Diagnostics supplement, not replace, exception handling

## Performance Considerations

- `diagnostic_collector` can be null pointer (zero overhead)
- String messages created only when diagnostic is added
- No runtime cost if collector not requested
- Lazy evaluation where possible

## Thread Safety

- Each `pe_file` has its own `diagnostic_collector`
- Thread-safe if each thread parses different files
- No global state
