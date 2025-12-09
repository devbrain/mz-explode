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

        // Optional Header
        case diagnostic_code::OPT_ZERO_ENTRY_POINT:        return "OPT_ZERO_ENTRY_POINT";
        case diagnostic_code::OPT_EP_OUTSIDE_IMAGE:        return "OPT_EP_OUTSIDE_IMAGE";
        case diagnostic_code::OPT_EP_IN_HEADER:            return "OPT_EP_IN_HEADER";
        case diagnostic_code::OPT_INVALID_IMAGEBASE:       return "OPT_INVALID_IMAGEBASE";
        case diagnostic_code::OPT_UNALIGNED_IMAGEBASE:     return "OPT_UNALIGNED_IMAGEBASE";
        case diagnostic_code::OPT_LOW_ALIGNMENT:           return "OPT_LOW_ALIGNMENT";
        case diagnostic_code::OPT_OVERSIZED_OPTIONAL_HDR:  return "OPT_OVERSIZED_OPTIONAL_HDR";
        case diagnostic_code::OPT_NON_POWER2_ALIGNMENT:    return "OPT_NON_POWER2_ALIGNMENT";

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

        // General
        case diagnostic_code::OVERLAPPING_DIRECTORIES:     return "OVERLAPPING_DIRECTORIES";
        case diagnostic_code::DIRECTORY_IN_HEADER:         return "DIRECTORY_IN_HEADER";
        case diagnostic_code::TRUNCATED_FILE:              return "TRUNCATED_FILE";
    }
    return "UNKNOWN";
}

} // namespace libexe
