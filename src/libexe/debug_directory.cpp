// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/pe/directories/debug.hpp>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace libexe {

// =============================================================================
// CodeView PDB 7.0
// =============================================================================

std::string codeview_pdb70::guid_string() const {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');

    // Format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    // Data1 (4 bytes)
    oss << std::setw(2) << static_cast<int>(guid[3])
        << std::setw(2) << static_cast<int>(guid[2])
        << std::setw(2) << static_cast<int>(guid[1])
        << std::setw(2) << static_cast<int>(guid[0]) << '-';

    // Data2 (2 bytes)
    oss << std::setw(2) << static_cast<int>(guid[5])
        << std::setw(2) << static_cast<int>(guid[4]) << '-';

    // Data3 (2 bytes)
    oss << std::setw(2) << static_cast<int>(guid[7])
        << std::setw(2) << static_cast<int>(guid[6]) << '-';

    // Data4 (2 bytes)
    oss << std::setw(2) << static_cast<int>(guid[8])
        << std::setw(2) << static_cast<int>(guid[9]) << '-';

    // Data4 (6 bytes)
    oss << std::setw(2) << static_cast<int>(guid[10])
        << std::setw(2) << static_cast<int>(guid[11])
        << std::setw(2) << static_cast<int>(guid[12])
        << std::setw(2) << static_cast<int>(guid[13])
        << std::setw(2) << static_cast<int>(guid[14])
        << std::setw(2) << static_cast<int>(guid[15]);

    return oss.str();
}

bool codeview_pdb70::is_valid() const {
    // Check if GUID is non-zero
    return std::any_of(guid.begin(), guid.end(), [](uint8_t b) { return b != 0; });
}

// =============================================================================
// Debug Entry
// =============================================================================

std::string debug_entry::get_pdb_path() const {
    if (codeview_pdb70_info) {
        return codeview_pdb70_info->pdb_path;
    }
    if (codeview_pdb20_info) {
        return codeview_pdb20_info->pdb_path;
    }
    return "";
}

std::string debug_entry::type_name() const {
    switch (type) {
        case debug_type::UNKNOWN: return "Unknown";
        case debug_type::COFF: return "COFF";
        case debug_type::CODEVIEW: return "CodeView";
        case debug_type::FPO: return "FPO";
        case debug_type::MISC: return "MISC";
        case debug_type::EXCEPTION: return "Exception";
        case debug_type::FIXUP: return "Fixup";
        case debug_type::OMAP_TO_SRC: return "OMAP to Source";
        case debug_type::OMAP_FROM_SRC: return "OMAP from Source";
        case debug_type::BORLAND: return "Borland";
        case debug_type::RESERVED10: return "Reserved";
        case debug_type::CLSID: return "CLSID";
        case debug_type::VC_FEATURE: return "VC Feature";
        case debug_type::POGO: return "POGO";
        case debug_type::ILTCG: return "ILTCG";
        case debug_type::MPX: return "MPX";
        case debug_type::REPRO: return "Repro";
        case debug_type::EMBEDDED_PORTABLE_PDB: return "Embedded Portable PDB";
        case debug_type::SPGO: return "SPGO";
        case debug_type::PDBCHECKSUM: return "PDB Checksum";
        case debug_type::EX_DLLCHARACTERISTICS: return "Extended DLL Characteristics";
        default: return "Unknown (" + std::to_string(static_cast<uint32_t>(type)) + ")";
    }
}

// =============================================================================
// Debug Directory
// =============================================================================

std::optional<debug_entry> debug_directory::find_type(debug_type type) const {
    for (const auto& entry : entries) {
        if (entry.type == type) {
            return entry;
        }
    }
    return std::nullopt;
}

std::vector<debug_entry> debug_directory::find_all_type(debug_type type) const {
    std::vector<debug_entry> result;
    for (const auto& entry : entries) {
        if (entry.type == type) {
            result.push_back(entry);
        }
    }
    return result;
}

bool debug_directory::has_type(debug_type type) const {
    return find_type(type).has_value();
}

std::string debug_directory::get_pdb_path() const {
    auto codeview = get_codeview();
    if (codeview) {
        return codeview->get_pdb_path();
    }
    return "";
}

bool debug_directory::has_pdb() const {
    auto codeview = get_codeview();
    if (!codeview) {
        return false;
    }
    return codeview->has_pdb70() || codeview->has_pdb20();
}

} // namespace libexe
