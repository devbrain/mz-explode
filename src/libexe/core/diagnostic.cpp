// libexe - Modern executable file analysis library
// Diagnostics implementation
// Copyright (c) 2024

#include <libexe/core/diagnostic.hpp>
#include <sstream>
#include <iomanip>

namespace libexe {

std::string diagnostic::to_string() const {
    std::ostringstream oss;

    // Format: [SEVERITY] 0xOFFSET: message
    oss << "[" << severity_name(severity) << "] ";

    if (file_offset != 0) {
        oss << "0x" << std::hex << std::setfill('0') << std::setw(8)
            << file_offset << std::dec << ": ";
    }

    oss << message;

    if (!details.empty()) {
        oss << " (" << details << ")";
    }

    return oss.str();
}

std::string_view severity_name(diagnostic_severity sev) {
    switch (sev) {
        case diagnostic_severity::INFO:    return "INFO";
        case diagnostic_severity::WARNING: return "WARNING";
        case diagnostic_severity::ANOMALY: return "ANOMALY";
        case diagnostic_severity::ERROR:   return "ERROR";
    }
    return "UNKNOWN";
}

std::string_view category_name(diagnostic_category cat) {
    switch (cat) {
        case diagnostic_category::DOS_HEADER:      return "DOS_HEADER";
        case diagnostic_category::PE_HEADER:       return "PE_HEADER";
        case diagnostic_category::COFF_HEADER:     return "COFF_HEADER";
        case diagnostic_category::OPTIONAL_HEADER: return "OPTIONAL_HEADER";
        case diagnostic_category::SECTION_TABLE:   return "SECTION_TABLE";
        case diagnostic_category::IMPORT:          return "IMPORT";
        case diagnostic_category::EXPORT:          return "EXPORT";
        case diagnostic_category::RELOCATION:      return "RELOCATION";
        case diagnostic_category::RESOURCE:        return "RESOURCE";
        case diagnostic_category::EXCEPTION:       return "EXCEPTION";
        case diagnostic_category::SECURITY:        return "SECURITY";
        case diagnostic_category::DEBUG:           return "DEBUG";
        case diagnostic_category::TLS:             return "TLS";
        case diagnostic_category::LOAD_CONFIG:     return "LOAD_CONFIG";
        case diagnostic_category::BOUND_IMPORT:    return "BOUND_IMPORT";
        case diagnostic_category::DELAY_IMPORT:    return "DELAY_IMPORT";
        case diagnostic_category::CLR:             return "CLR";
        case diagnostic_category::RICH_HEADER:     return "RICH_HEADER";
        case diagnostic_category::OVERLAY:         return "OVERLAY";
        case diagnostic_category::ALIGNMENT:       return "ALIGNMENT";
        case diagnostic_category::ENTRY_POINT:     return "ENTRY_POINT";
        case diagnostic_category::NE_HEADER:       return "NE_HEADER";
        case diagnostic_category::NE_SEGMENT:      return "NE_SEGMENT";
        case diagnostic_category::NE_RESOURCE:     return "NE_RESOURCE";
        case diagnostic_category::GENERAL:         return "GENERAL";
    }
    return "UNKNOWN";
}

std::string_view code_name(diagnostic_code code) {
    switch (code) {
        // PE Header
        case diagnostic_code::PE_HEADER_IN_OVERLAY:        return "PE_HEADER_IN_OVERLAY";
        case diagnostic_code::PE_DUAL_HEADER:              return "PE_DUAL_HEADER";
        case diagnostic_code::PE_WRITABLE_HEADER:          return "PE_WRITABLE_HEADER";

        // COFF Header
        case diagnostic_code::COFF_ZERO_SECTIONS:          return "COFF_ZERO_SECTIONS";
        case diagnostic_code::COFF_EXCESSIVE_SECTIONS:     return "COFF_EXCESSIVE_SECTIONS";
        case diagnostic_code::COFF_RELOCS_STRIPPED_IGNORED: return "COFF_RELOCS_STRIPPED_IGNORED";
        case diagnostic_code::COFF_DEPRECATED_FLAG:        return "COFF_DEPRECATED_FLAG";
        case diagnostic_code::COFF_SYMBOL_TABLE_PRESENT:   return "COFF_SYMBOL_TABLE_PRESENT";

        // Optional Header
        case diagnostic_code::OPT_ZERO_ENTRY_POINT:        return "OPT_ZERO_ENTRY_POINT";
        case diagnostic_code::OPT_EP_OUTSIDE_IMAGE:        return "OPT_EP_OUTSIDE_IMAGE";
        case diagnostic_code::OPT_EP_IN_HEADER:            return "OPT_EP_IN_HEADER";
        case diagnostic_code::OPT_INVALID_IMAGEBASE:       return "OPT_INVALID_IMAGEBASE";
        case diagnostic_code::OPT_UNALIGNED_IMAGEBASE:     return "OPT_UNALIGNED_IMAGEBASE";
        case diagnostic_code::OPT_LOW_ALIGNMENT:           return "OPT_LOW_ALIGNMENT";
        case diagnostic_code::OPT_OVERSIZED_OPTIONAL_HDR:  return "OPT_OVERSIZED_OPTIONAL_HDR";
        case diagnostic_code::OPT_NON_POWER2_ALIGNMENT:    return "OPT_NON_POWER2_ALIGNMENT";
        case diagnostic_code::OPT_RESERVED_NONZERO:        return "OPT_RESERVED_NONZERO";
        case diagnostic_code::OPT_FILE_ALIGNMENT_RANGE:    return "OPT_FILE_ALIGNMENT_RANGE";
        case diagnostic_code::OPT_SECTION_LT_FILE_ALIGN:   return "OPT_SECTION_LT_FILE_ALIGN";
        case diagnostic_code::OPT_SIZE_OF_IMAGE_UNALIGNED: return "OPT_SIZE_OF_IMAGE_UNALIGNED";
        case diagnostic_code::OPT_SIZE_OF_HEADERS_UNALIGNED: return "OPT_SIZE_OF_HEADERS_UNALIGNED";
        case diagnostic_code::OPT_CHECKSUM_MISMATCH:       return "OPT_CHECKSUM_MISMATCH";
        case diagnostic_code::OPT_RESERVED_DLL_CHAR:       return "OPT_RESERVED_DLL_CHAR";

        // Section Table
        case diagnostic_code::SECT_OVERLAP:                return "SECT_OVERLAP";
        case diagnostic_code::SECT_BEYOND_FILE:            return "SECT_BEYOND_FILE";
        case diagnostic_code::SECT_ZERO_RAW_SIZE:          return "SECT_ZERO_RAW_SIZE";
        case diagnostic_code::SECT_UNALIGNED:              return "SECT_UNALIGNED";

        // Import Directory
        case diagnostic_code::IMP_EMPTY_IAT:               return "IMP_EMPTY_IAT";
        case diagnostic_code::IMP_MISSING_DLL:             return "IMP_MISSING_DLL";
        case diagnostic_code::IMP_BINARY_NAME:             return "IMP_BINARY_NAME";
        case diagnostic_code::IMP_SELF_IMPORT:             return "IMP_SELF_IMPORT";
        case diagnostic_code::IMP_TRUNCATED:               return "IMP_TRUNCATED";
        case diagnostic_code::IMP_FORWARDER_LOOP:          return "IMP_FORWARDER_LOOP";

        // Export Directory
        case diagnostic_code::EXP_FORWARDER_LOOP:          return "EXP_FORWARDER_LOOP";
        case diagnostic_code::EXP_BINARY_NAME:             return "EXP_BINARY_NAME";
        case diagnostic_code::EXP_ORDINAL_GAP:             return "EXP_ORDINAL_GAP";

        // Relocation Directory
        case diagnostic_code::RELOC_UNUSUAL_TYPE:          return "RELOC_UNUSUAL_TYPE";
        case diagnostic_code::RELOC_INVALID_TYPE:          return "RELOC_INVALID_TYPE";
        case diagnostic_code::RELOC_HEADER_TARGET:         return "RELOC_HEADER_TARGET";
        case diagnostic_code::RELOC_HIGH_DENSITY:          return "RELOC_HIGH_DENSITY";
        case diagnostic_code::RELOC_VIRTUAL_CODE:          return "RELOC_VIRTUAL_CODE";

        // Rich Header
        case diagnostic_code::RICH_CHECKSUM_MISMATCH:      return "RICH_CHECKSUM_MISMATCH";
        case diagnostic_code::RICH_TRUNCATED:              return "RICH_TRUNCATED";

        // Entry Point
        case diagnostic_code::EP_IN_OVERLAY:               return "EP_IN_OVERLAY";
        case diagnostic_code::EP_NON_EXECUTABLE:           return "EP_NON_EXECUTABLE";

        // LE/LX Header
        case diagnostic_code::LE_INVALID_MAGIC:            return "LE_INVALID_MAGIC";
        case diagnostic_code::LE_INVALID_BYTE_ORDER:       return "LE_INVALID_BYTE_ORDER";
        case diagnostic_code::LE_INVALID_PAGE_SIZE:        return "LE_INVALID_PAGE_SIZE";
        case diagnostic_code::LE_STUB_DETECTED:            return "LE_STUB_DETECTED";

        // LE/LX Object
        case diagnostic_code::LE_INVALID_OBJECT_INDEX:     return "LE_INVALID_OBJECT_INDEX";
        case diagnostic_code::LE_OVERLAPPING_OBJECTS:      return "LE_OVERLAPPING_OBJECTS";

        // LE/LX Page
        case diagnostic_code::LE_INVALID_PAGE_OFFSET:      return "LE_INVALID_PAGE_OFFSET";
        case diagnostic_code::LE_COMPRESSED_PAGE:          return "LE_COMPRESSED_PAGE";

        // LE/LX Fixup
        case diagnostic_code::LE_FIXUP_OVERFLOW:           return "LE_FIXUP_OVERFLOW";
        case diagnostic_code::LE_IMPORT_UNRESOLVED:        return "LE_IMPORT_UNRESOLVED";

        // LE/LX Entry
        case diagnostic_code::LE_ENTRY_INVALID:            return "LE_ENTRY_INVALID";
        case diagnostic_code::LE_VXD_NO_DDB:               return "LE_VXD_NO_DDB";

        // General
        case diagnostic_code::OVERLAPPING_DIRECTORIES:     return "OVERLAPPING_DIRECTORIES";
        case diagnostic_code::DIRECTORY_IN_HEADER:         return "DIRECTORY_IN_HEADER";
        case diagnostic_code::TRUNCATED_FILE:              return "TRUNCATED_FILE";
    }
    return "UNKNOWN";
}

} // namespace libexe
