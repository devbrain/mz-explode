// libexe - Modern executable file analysis library
// Diagnostics system for reporting non-fatal warnings and anomalies
// Copyright (c) 2024

#ifndef LIBEXE_CORE_DIAGNOSTIC_HPP
#define LIBEXE_CORE_DIAGNOSTIC_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <string>
#include <string_view>

namespace libexe {

/// Diagnostic severity levels
enum class diagnostic_severity {
    INFO,       // Informational (unusual but valid per spec)
    WARNING,    // Suspicious (potentially malformed or evasive)
    ANOMALY,    // Definite anomaly (violates spec but may still load)
    ERROR       // Parsing error (recovered, but data may be incomplete)
};

/// Diagnostic category codes (high byte indicates major category)
enum class diagnostic_category : uint32_t {
    // Header categories (0x01xx - 0x04xx)
    DOS_HEADER      = 0x0100,
    PE_HEADER       = 0x0200,
    COFF_HEADER     = 0x0300,
    OPTIONAL_HEADER = 0x0400,
    SECTION_TABLE   = 0x0500,

    // Data directory categories (0x10xx - 0x1Bxx)
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

    // Special categories (0x20xx - 0x23xx)
    RICH_HEADER     = 0x2000,
    OVERLAY         = 0x2100,
    ALIGNMENT       = 0x2200,
    ENTRY_POINT     = 0x2300,

    // NE-specific (0x30xx - 0x32xx)
    NE_HEADER       = 0x3000,
    NE_SEGMENT      = 0x3100,
    NE_RESOURCE     = 0x3200,

    // LE/LX-specific (0x40xx - 0x44xx)
    LE_HEADER       = 0x4000,
    LE_OBJECT       = 0x4100,
    LE_PAGE         = 0x4200,
    LE_FIXUP        = 0x4300,
    LE_ENTRY        = 0x4400,

    // General (0xFFxx)
    GENERAL         = 0xFF00,
};

/// Specific diagnostic codes (combines category + specific issue)
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
    OPT_NON_POWER2_ALIGNMENT    = 0x0408,  // Alignment not power of 2

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
    // LE/LX Header (0x40xx)
    // =========================================================================
    LE_INVALID_MAGIC            = 0x4001,  // Magic is not 'LE' or 'LX'
    LE_INVALID_BYTE_ORDER       = 0x4002,  // Unsupported byte order
    LE_INVALID_PAGE_SIZE        = 0x4003,  // Page size not power of 2
    LE_STUB_DETECTED            = 0x4004,  // DOS extender stub detected

    // =========================================================================
    // LE/LX Object (0x41xx)
    // =========================================================================
    LE_INVALID_OBJECT_INDEX     = 0x4101,  // Object index out of bounds
    LE_OVERLAPPING_OBJECTS      = 0x4102,  // Objects have overlapping addresses

    // =========================================================================
    // LE/LX Page (0x42xx)
    // =========================================================================
    LE_INVALID_PAGE_OFFSET      = 0x4201,  // Page offset beyond file
    LE_COMPRESSED_PAGE          = 0x4202,  // Compressed page (not supported)

    // =========================================================================
    // LE/LX Fixup (0x43xx)
    // =========================================================================
    LE_FIXUP_OVERFLOW           = 0x4301,  // Fixup target overflow
    LE_IMPORT_UNRESOLVED        = 0x4302,  // Unresolved import reference

    // =========================================================================
    // LE/LX Entry (0x44xx)
    // =========================================================================
    LE_ENTRY_INVALID            = 0x4401,  // Invalid entry table record
    LE_VXD_NO_DDB               = 0x4402,  // VxD missing Device Descriptor Block

    // =========================================================================
    // General (0xFFxx)
    // =========================================================================
    OVERLAPPING_DIRECTORIES     = 0xFF01,  // Multiple directories share region
    DIRECTORY_IN_HEADER         = 0xFF02,  // Data directory within header
    TRUNCATED_FILE              = 0xFF03,  // File smaller than declared
};

/// A single diagnostic message
struct LIBEXE_EXPORT diagnostic {
    diagnostic_code code;           // Unique identifier
    diagnostic_severity severity;   // INFO/WARNING/ANOMALY/ERROR
    diagnostic_category category;   // What component generated this

    uint64_t file_offset;          // Where in file (0 if N/A)
    uint32_t rva;                  // RVA if applicable (0 if N/A)

    std::string message;           // Human-readable description
    std::string details;           // Additional context (optional)

    /// Check if this is an anomaly
    [[nodiscard]] bool is_anomaly() const {
        return severity == diagnostic_severity::ANOMALY;
    }

    /// Check if this is an error
    [[nodiscard]] bool is_error() const {
        return severity == diagnostic_severity::ERROR;
    }

    /// Check if this is a warning or worse
    [[nodiscard]] bool is_warning_or_worse() const {
        return severity >= diagnostic_severity::WARNING;
    }

    /// Get the category from the diagnostic code
    [[nodiscard]] static diagnostic_category category_from_code(diagnostic_code code) {
        return static_cast<diagnostic_category>(static_cast<uint32_t>(code) & 0xFF00);
    }

    /// Format as human-readable string
    [[nodiscard]] std::string to_string() const;
};

/// Get severity name as string
[[nodiscard]] LIBEXE_EXPORT std::string_view severity_name(diagnostic_severity sev);

/// Get category name as string
[[nodiscard]] LIBEXE_EXPORT std::string_view category_name(diagnostic_category cat);

/// Get diagnostic code name as string
[[nodiscard]] LIBEXE_EXPORT std::string_view code_name(diagnostic_code code);

} // namespace libexe

#endif // LIBEXE_CORE_DIAGNOSTIC_HPP
