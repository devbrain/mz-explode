// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/pe/rich_header.hpp>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace libexe {

namespace {
    // Read 32-bit little-endian value
    uint32_t read_u32(const uint8_t* ptr) {
        return static_cast<uint32_t>(ptr[0]) |
               (static_cast<uint32_t>(ptr[1]) << 8) |
               (static_cast<uint32_t>(ptr[2]) << 16) |
               (static_cast<uint32_t>(ptr[3]) << 24);
    }

    // Minimum offset for Rich header (after DOS header minimum)
    constexpr uint32_t MIN_RICH_OFFSET = 0x40;
}

// =============================================================================
// rich_entry implementation
// =============================================================================

rich_component_type rich_entry::component_type() const {
    return get_component_type(product_id);
}

std::string rich_entry::product_name() const {
    auto type = static_cast<rich_product_type>(product_id);
    auto name = rich_product_type_name(type);
    if (!name.empty()) {
        return std::string(name);
    }
    // Unknown product ID
    std::ostringstream oss;
    oss << "Unknown (0x" << std::hex << std::setw(4) << std::setfill('0') << product_id << ")";
    return oss.str();
}

std::string rich_entry::vs_version() const {
    return get_vs_version_for_build(build_number);
}

bool rich_entry::is_compiler() const {
    auto type = component_type();
    return type == rich_component_type::C_COMPILER ||
           type == rich_component_type::CPP_COMPILER;
}

bool rich_entry::is_linker() const {
    return component_type() == rich_component_type::LINKER;
}

// =============================================================================
// rich_header implementation
// =============================================================================

bool rich_header::is_valid() const {
    // Must have at least one entry
    if (entries.empty()) {
        return false;
    }
    // XOR mask should be non-zero (0 would mean no encryption)
    if (xor_mask == 0) {
        return false;
    }
    // All entries should have reasonable values
    for (const auto& entry : entries) {
        // Build numbers are typically 1000-60000
        // Counts should be reasonable (< 100000)
        if (entry.count > 100000) {
            return false;
        }
    }
    return true;
}

uint32_t rich_header::total_count() const {
    uint32_t total = 0;
    for (const auto& entry : entries) {
        total += entry.count;
    }
    return total;
}

const rich_entry* rich_header::primary_compiler() const {
    const rich_entry* best = nullptr;
    for (const auto& entry : entries) {
        if (entry.is_compiler()) {
            if (!best || entry.count > best->count) {
                best = &entry;
            }
        }
    }
    return best;
}

const rich_entry* rich_header::linker() const {
    for (const auto& entry : entries) {
        if (entry.is_linker()) {
            return &entry;
        }
    }
    return nullptr;
}

std::optional<uint16_t> rich_header::vs_major_version() const {
    // Try to determine VS version from linker or compiler entries
    const rich_entry* ref = linker();
    if (!ref) {
        ref = primary_compiler();
    }
    if (!ref) {
        return std::nullopt;
    }

    uint16_t product_id = ref->product_id;
    uint16_t build = ref->build_number;

    // First check product ID ranges to determine the VS version family
    // VS2015+ (14.0+) all use the same product IDs (0xFD-0x10E)
    // For these, use build number to distinguish versions
    if (product_id >= 0xFD && product_id <= 0x10E) {
        // VS2015+ unified product IDs - use build number
        if (build >= 35109) return 2026;  // VS2026 Insiders
        if (build >= 30159) return 2022;  // VS2022
        if (build >= 27508) return 2019;  // VS2019
        if (build >= 25017) return 2017;  // VS2017
        return 2015;  // VS2015 baseline
    }

    // VS2013 (12.0) uses product IDs 0xD9-0xEA
    if (product_id >= 0xD9 && product_id <= 0xEA) {
        return 2013;
    }

    // VS2012 (11.0) uses product IDs 0xC7-0xD8
    if (product_id >= 0xC7 && product_id <= 0xD8) {
        return 2012;
    }

    // VS2010 (10.0) uses product IDs 0x98-0xB4
    if (product_id >= 0x98 && product_id <= 0xB4) {
        return 2010;
    }

    // VS2008 (9.0) uses product IDs 0x83-0x96
    if (product_id >= 0x83 && product_id <= 0x96) {
        return 2008;
    }

    // VS2005 (8.0) uses product IDs 0x6D-0x82
    if (product_id >= 0x6D && product_id <= 0x82) {
        return 2005;
    }

    // VS2003 (7.10) uses product IDs 0x5A-0x6B
    if (product_id >= 0x5A && product_id <= 0x6B) {
        return 2003;
    }

    // VS2002 (7.0) uses product IDs 0x19-0x45 (with gaps)
    if ((product_id >= 0x19 && product_id <= 0x1D) ||
        (product_id >= 0x3D && product_id <= 0x45)) {
        return 2002;
    }

    // VS98 (6.0) uses product IDs 0x02-0x16
    if (product_id >= 0x02 && product_id <= 0x16) {
        return 1998;
    }

    return std::nullopt;
}

std::vector<const rich_entry*> rich_header::find_by_type(rich_product_type type) const {
    std::vector<const rich_entry*> result;
    uint16_t type_id = static_cast<uint16_t>(type);
    for (const auto& entry : entries) {
        if (entry.product_id == type_id) {
            result.push_back(&entry);
        }
    }
    return result;
}

std::string rich_header::to_string() const {
    std::ostringstream oss;
    oss << "Rich Header:\n";
    oss << "  XOR Mask: 0x" << std::hex << std::setw(8) << std::setfill('0') << xor_mask << "\n";
    oss << "  Offset: 0x" << std::hex << file_offset << "\n";
    oss << "  Size: " << std::dec << size << " bytes\n";
    oss << "  Entries: " << entries.size() << "\n";

    auto vs_ver = vs_major_version();
    if (vs_ver) {
        oss << "  Visual Studio: " << *vs_ver << "\n";
    }

    oss << "\n  Components:\n";
    for (const auto& entry : entries) {
        oss << "    [" << std::hex << std::setw(4) << std::setfill('0') << entry.product_id
            << ":" << std::setw(4) << entry.build_number << "] "
            << std::dec << std::setw(5) << std::setfill(' ') << entry.count << "x "
            << entry.product_name() << "\n";
    }

    return oss.str();
}

// =============================================================================
// rich_header_parser implementation
// =============================================================================

std::optional<rich_header> rich_header_parser::parse(
    std::span<const uint8_t> file_data,
    uint32_t pe_offset
) {
    // Find "Rich" marker
    uint32_t rich_offset = find_rich_marker(file_data, pe_offset);
    if (rich_offset == 0) {
        return std::nullopt;
    }

    // Read XOR mask (immediately after "Rich")
    if (rich_offset + 8 > file_data.size()) {
        return std::nullopt;
    }
    uint32_t xor_mask = read_u32(file_data.data() + rich_offset + 4);

    // Find "DanS" header
    uint32_t dans_offset = find_dans_header(file_data, rich_offset, xor_mask);
    if (dans_offset == 0) {
        return std::nullopt;
    }

    rich_header result;
    result.xor_mask = xor_mask;
    result.file_offset = dans_offset;
    result.size = rich_offset + 8 - dans_offset;

    // Parse entries between DanS and Rich
    // Entries start at dans_offset + 16 (skip DanS + 3 padding DWORDs)
    const uint8_t* ptr = file_data.data() + dans_offset + 16;
    const uint8_t* end = file_data.data() + rich_offset;

    // Safety limit on entries
    constexpr size_t MAX_ENTRIES = 1000;

    while (ptr + 8 <= end && result.entries.size() < MAX_ENTRIES) {
        // Read encrypted data
        uint32_t data1_enc = read_u32(ptr);
        uint32_t data2_enc = read_u32(ptr + 4);

        // Decrypt
        uint32_t data1 = data1_enc ^ xor_mask;
        uint32_t data2 = data2_enc ^ xor_mask;

        // Check for padding zeros (decrypted zeros mean we've hit padding)
        if (data1 == 0 && data2 == 0) {
            ptr += 8;
            continue;
        }

        // Parse entry
        rich_entry entry;
        entry.product_id = static_cast<uint16_t>(data1 >> 16);
        entry.build_number = static_cast<uint16_t>(data1 & 0xFFFF);
        entry.count = data2;

        // Skip entries with zero count (shouldn't happen, but be safe)
        if (entry.count > 0) {
            result.entries.push_back(entry);
        }

        ptr += 8;
    }

    if (result.entries.empty()) {
        return std::nullopt;
    }

    return result;
}

bool rich_header_parser::has_rich_header(
    std::span<const uint8_t> file_data,
    uint32_t pe_offset
) {
    return find_rich_marker(file_data, pe_offset) != 0;
}

uint32_t rich_header_parser::find_rich_marker(
    std::span<const uint8_t> file_data,
    uint32_t pe_offset
) {
    // Search backwards from PE header for "Rich" signature
    // Rich header must be after DOS header (0x40) and before PE header
    if (pe_offset < MIN_RICH_OFFSET + 8 || pe_offset >= file_data.size()) {
        return 0;
    }

    // Search in DWORD-aligned positions
    for (uint32_t offset = pe_offset - 4; offset >= MIN_RICH_OFFSET; offset -= 4) {
        if (offset + 4 > file_data.size()) {
            continue;
        }
        uint32_t value = read_u32(file_data.data() + offset);
        if (value == RICH_SIGNATURE) {
            return offset;
        }
    }

    return 0;
}

uint32_t rich_header_parser::find_dans_header(
    std::span<const uint8_t> file_data,
    uint32_t rich_offset,
    uint32_t xor_mask
) {
    // "DanS" is XOR encrypted
    uint32_t dans_encrypted = DANS_SIGNATURE ^ xor_mask;

    // Search backwards from Rich for encrypted DanS
    // DanS should be before Rich and after offset 0x40
    for (uint32_t offset = rich_offset - 4; offset >= MIN_RICH_OFFSET; offset -= 4) {
        if (offset + 4 > file_data.size()) {
            continue;
        }
        uint32_t value = read_u32(file_data.data() + offset);
        if (value == dans_encrypted) {
            return offset;
        }
    }

    return 0;
}

// =============================================================================
// Helper function implementations
// =============================================================================

std::string_view rich_product_type_name(rich_product_type type) {
    switch (type) {
        // VS2015+ unified
        case rich_product_type::UTC_C_1900:         return "VS2015+ C compiler";
        case rich_product_type::UTC_CPP_1900:       return "VS2015+ C++ compiler";
        case rich_product_type::LINKER_1400:        return "VS2015+ Linker";
        case rich_product_type::MASM_1400:          return "VS2015+ MASM";
        case rich_product_type::CVTRES_1400:        return "VS2015+ Resource compiler";
        case rich_product_type::IMPLIB_1400:        return "VS2015+ Import library";
        case rich_product_type::EXPORT_1400:        return "VS2015+ Export";
        case rich_product_type::UTC_LTCG_C_1900:    return "VS2015+ LTCG C";
        case rich_product_type::UTC_LTCG_CPP_1900:  return "VS2015+ LTCG C++";
        case rich_product_type::UTC_LTCG_MSIL_1900: return "VS2015+ LTCG MSIL";
        case rich_product_type::UTC_POGO_I_C_1900:  return "VS2015+ POGO I C";
        case rich_product_type::UTC_POGO_I_CPP_1900:return "VS2015+ POGO I C++";
        case rich_product_type::UTC_POGO_O_C_1900:  return "VS2015+ POGO O C";
        case rich_product_type::UTC_POGO_O_CPP_1900:return "VS2015+ POGO O C++";
        case rich_product_type::UTC_CVTCIL_C_1900:  return "VS2015+ CVTCIL C";
        case rich_product_type::UTC_CVTCIL_CPP_1900:return "VS2015+ CVTCIL C++";
        case rich_product_type::ALIASOBJ_1400:      return "VS2015+ AliasObj";
        case rich_product_type::CVTPGD_1900:        return "VS2015+ CVTPGD";

        // VS2013
        case rich_product_type::UTC_C_1800:         return "VS2013 C compiler";
        case rich_product_type::UTC_CPP_1800:       return "VS2013 C++ compiler";
        case rich_product_type::LINKER_1200:        return "VS2013 Linker";
        case rich_product_type::MASM_1200:          return "VS2013 MASM";
        case rich_product_type::CVTRES_1200:        return "VS2013 Resource compiler";
        case rich_product_type::IMPLIB_1200:        return "VS2013 Import library";
        case rich_product_type::EXPORT_1200:        return "VS2013 Export";

        // VS2012
        case rich_product_type::UTC_C_1700:         return "VS2012 C compiler";
        case rich_product_type::UTC_CPP_1700:       return "VS2012 C++ compiler";
        case rich_product_type::LINKER_1100:        return "VS2012 Linker";
        case rich_product_type::MASM_1100:          return "VS2012 MASM";
        case rich_product_type::CVTRES_1100:        return "VS2012 Resource compiler";
        case rich_product_type::IMPLIB_1100:        return "VS2012 Import library";
        case rich_product_type::EXPORT_1100:        return "VS2012 Export";

        // VS2010
        case rich_product_type::UTC_C_1600:         return "VS2010 C compiler";
        case rich_product_type::UTC_CPP_1600:       return "VS2010 C++ compiler";
        case rich_product_type::LINKER_1000:        return "VS2010 Linker";
        case rich_product_type::MASM_1000:          return "VS2010 MASM";
        case rich_product_type::CVTRES_1000:        return "VS2010 Resource compiler";
        case rich_product_type::IMPLIB_1000:        return "VS2010 Import library";
        case rich_product_type::EXPORT_1000:        return "VS2010 Export";

        // VS2008
        case rich_product_type::UTC_C_1500:         return "VS2008 C compiler";
        case rich_product_type::UTC_CPP_1500:       return "VS2008 C++ compiler";
        case rich_product_type::LINKER_900:         return "VS2008 Linker";
        case rich_product_type::MASM_900:           return "VS2008 MASM";
        case rich_product_type::CVTRES_900:         return "VS2008 Resource compiler";
        case rich_product_type::IMPLIB_900:         return "VS2008 Import library";
        case rich_product_type::EXPORT_900:         return "VS2008 Export";

        // VS2005
        case rich_product_type::UTC_C_1400:         return "VS2005 C compiler";
        case rich_product_type::UTC_CPP_1400:       return "VS2005 C++ compiler";
        case rich_product_type::LINKER_800:         return "VS2005 Linker";
        case rich_product_type::MASM_800:           return "VS2005 MASM";
        case rich_product_type::CVTRES_800:         return "VS2005 Resource compiler";
        case rich_product_type::IMPLIB_800:         return "VS2005 Import library";
        case rich_product_type::EXPORT_800:         return "VS2005 Export";

        // VS2003
        case rich_product_type::UTC_C_1310:         return "VS2003 C compiler";
        case rich_product_type::UTC_CPP_1310:       return "VS2003 C++ compiler";
        case rich_product_type::LINKER_710:         return "VS2003 Linker";
        case rich_product_type::CVTRES_710:         return "VS2003 Resource compiler";
        case rich_product_type::IMPLIB_710:         return "VS2003 Import library";
        case rich_product_type::EXPORT_710:         return "VS2003 Export";

        // VS2002
        case rich_product_type::UTC_C_1300:         return "VS2002 C compiler";
        case rich_product_type::UTC_CPP_1300:       return "VS2002 C++ compiler";
        case rich_product_type::LINKER_700:         return "VS2002 Linker";
        case rich_product_type::CVTRES_700:         return "VS2002 Resource compiler";
        case rich_product_type::IMPLIB_700:         return "VS2002 Import library";
        case rich_product_type::EXPORT_700:         return "VS2002 Export";
        case rich_product_type::MASM_700:           return "VS2002 MASM";

        // VS98/6.0
        case rich_product_type::UTC_C_1200:         return "VS98 C compiler";
        case rich_product_type::UTC_CPP_1200:       return "VS98 C++ compiler";
        case rich_product_type::LINKER_600:         return "VS98 Linker";
        case rich_product_type::CVTRES_600:         return "VS98 Resource compiler";
        case rich_product_type::IMPLIB_600:         return "VS98 Import library";
        case rich_product_type::EXPORT_600:         return "VS98 Export";
        case rich_product_type::MASM_613:           return "VS98 MASM 6.13";
        case rich_product_type::MASM_614:           return "VS98 MASM 6.14";

        // Unmarked
        case rich_product_type::UNMARKED:           return "Unmarked (legacy)";
        case rich_product_type::UNMARKED_MODERN:    return "Unmarked";

        default:
            return "";
    }
}

rich_component_type get_component_type(uint16_t product_id) {
    auto type = static_cast<rich_product_type>(product_id);

    switch (type) {
        // C compilers
        case rich_product_type::UTC_C_1900:
        case rich_product_type::UTC_C_1800:
        case rich_product_type::UTC_C_1700:
        case rich_product_type::UTC_C_1600:
        case rich_product_type::UTC_C_1500:
        case rich_product_type::UTC_C_1400:
        case rich_product_type::UTC_C_1310:
        case rich_product_type::UTC_C_1300:
        case rich_product_type::UTC_C_1200:
            return rich_component_type::C_COMPILER;

        // C++ compilers
        case rich_product_type::UTC_CPP_1900:
        case rich_product_type::UTC_CPP_1800:
        case rich_product_type::UTC_CPP_1700:
        case rich_product_type::UTC_CPP_1600:
        case rich_product_type::UTC_CPP_1500:
        case rich_product_type::UTC_CPP_1400:
        case rich_product_type::UTC_CPP_1310:
        case rich_product_type::UTC_CPP_1300:
        case rich_product_type::UTC_CPP_1200:
            return rich_component_type::CPP_COMPILER;

        // Linkers
        case rich_product_type::LINKER_1400:
        case rich_product_type::LINKER_1200:
        case rich_product_type::LINKER_1100:
        case rich_product_type::LINKER_1000:
        case rich_product_type::LINKER_900:
        case rich_product_type::LINKER_800:
        case rich_product_type::LINKER_710:
        case rich_product_type::LINKER_700:
        case rich_product_type::LINKER_612:
        case rich_product_type::LINKER_600:
        case rich_product_type::LINKER_511:
        case rich_product_type::LINKER_510:
            return rich_component_type::LINKER;

        // Assemblers
        case rich_product_type::MASM_1400:
        case rich_product_type::MASM_1200:
        case rich_product_type::MASM_1100:
        case rich_product_type::MASM_1000:
        case rich_product_type::MASM_900:
        case rich_product_type::MASM_800:
        case rich_product_type::MASM_700:
        case rich_product_type::MASM_614:
        case rich_product_type::MASM_613:
        case rich_product_type::MASM_611:
            return rich_component_type::ASSEMBLER;

        // Resource compilers
        case rich_product_type::CVTRES_1400:
        case rich_product_type::CVTRES_1200:
        case rich_product_type::CVTRES_1100:
        case rich_product_type::CVTRES_1000:
        case rich_product_type::CVTRES_900:
        case rich_product_type::CVTRES_800:
        case rich_product_type::CVTRES_710:
        case rich_product_type::CVTRES_700:
        case rich_product_type::CVTRES_600:
            return rich_component_type::RESOURCE;

        // Import libraries
        case rich_product_type::IMPLIB_1400:
        case rich_product_type::IMPLIB_1200:
        case rich_product_type::IMPLIB_1100:
        case rich_product_type::IMPLIB_1000:
        case rich_product_type::IMPLIB_900:
        case rich_product_type::IMPLIB_800:
        case rich_product_type::IMPLIB_710:
        case rich_product_type::IMPLIB_700:
        case rich_product_type::IMPLIB_600:
            return rich_component_type::IMPORT_LIB;

        // Exports
        case rich_product_type::EXPORT_1400:
        case rich_product_type::EXPORT_1200:
        case rich_product_type::EXPORT_1100:
        case rich_product_type::EXPORT_1000:
        case rich_product_type::EXPORT_900:
        case rich_product_type::EXPORT_800:
        case rich_product_type::EXPORT_710:
        case rich_product_type::EXPORT_700:
        case rich_product_type::EXPORT_600:
            return rich_component_type::EXPORT;

        // LTCG
        case rich_product_type::UTC_LTCG_C_1900:
        case rich_product_type::UTC_LTCG_CPP_1900:
        case rich_product_type::UTC_LTCG_MSIL_1900:
        case rich_product_type::UTC_LTCG_C_1800:
        case rich_product_type::UTC_LTCG_CPP_1800:
        case rich_product_type::UTC_LTCG_MSIL_1800:
        case rich_product_type::UTC_LTCG_C_1700:
        case rich_product_type::UTC_LTCG_CPP_1700:
        case rich_product_type::UTC_LTCG_MSIL_1700:
        case rich_product_type::UTC_LTCG_C_1600:
        case rich_product_type::UTC_LTCG_CPP_1600:
        case rich_product_type::UTC_LTCG_MSIL_1600:
        case rich_product_type::UTC_LTCG_C_1500:
        case rich_product_type::UTC_LTCG_CPP_1500:
        case rich_product_type::UTC_LTCG_MSIL_1500:
        case rich_product_type::UTC_LTCG_C_1400:
        case rich_product_type::UTC_LTCG_CPP_1400:
        case rich_product_type::UTC_LTCG_MSIL_1400:
        case rich_product_type::UTC_LTCG_C_1310:
        case rich_product_type::UTC_LTCG_CPP_1310:
            return rich_component_type::LTCG;

        // POGO
        case rich_product_type::UTC_POGO_I_C_1900:
        case rich_product_type::UTC_POGO_I_CPP_1900:
        case rich_product_type::UTC_POGO_O_C_1900:
        case rich_product_type::UTC_POGO_O_CPP_1900:
        case rich_product_type::UTC_POGO_I_C_1800:
        case rich_product_type::UTC_POGO_I_CPP_1800:
        case rich_product_type::UTC_POGO_O_C_1800:
        case rich_product_type::UTC_POGO_O_CPP_1800:
        case rich_product_type::UTC_POGO_I_C_1700:
        case rich_product_type::UTC_POGO_I_CPP_1700:
        case rich_product_type::UTC_POGO_O_C_1700:
        case rich_product_type::UTC_POGO_O_CPP_1700:
        case rich_product_type::UTC_POGO_I_C_1600:
        case rich_product_type::UTC_POGO_I_CPP_1600:
        case rich_product_type::UTC_POGO_O_C_1600:
        case rich_product_type::UTC_POGO_O_CPP_1600:
        case rich_product_type::UTC_POGO_I_C_1500:
        case rich_product_type::UTC_POGO_I_CPP_1500:
        case rich_product_type::UTC_POGO_O_C_1500:
        case rich_product_type::UTC_POGO_O_CPP_1500:
        case rich_product_type::UTC_POGO_I_C_1400:
        case rich_product_type::UTC_POGO_I_CPP_1400:
        case rich_product_type::UTC_POGO_O_C_1400:
        case rich_product_type::UTC_POGO_O_CPP_1400:
        case rich_product_type::UTC_POGO_I_C_1310:
        case rich_product_type::UTC_POGO_I_CPP_1310:
        case rich_product_type::UTC_POGO_O_C_1310:
        case rich_product_type::UTC_POGO_O_CPP_1310:
            return rich_component_type::POGO;

        // CVTCIL
        case rich_product_type::UTC_CVTCIL_C_1900:
        case rich_product_type::UTC_CVTCIL_CPP_1900:
        case rich_product_type::UTC_CVTCIL_C_1800:
        case rich_product_type::UTC_CVTCIL_CPP_1800:
        case rich_product_type::UTC_CVTCIL_C_1700:
        case rich_product_type::UTC_CVTCIL_CPP_1700:
        case rich_product_type::UTC_CVTCIL_C_1600:
        case rich_product_type::UTC_CVTCIL_CPP_1600:
        case rich_product_type::UTC_CVTCIL_C_1500:
        case rich_product_type::UTC_CVTCIL_CPP_1500:
        case rich_product_type::UTC_CVTCIL_C_1400:
        case rich_product_type::UTC_CVTCIL_CPP_1400:
            return rich_component_type::CVTCIL;

        // AliasObj
        case rich_product_type::ALIASOBJ_1400:
        case rich_product_type::ALIASOBJ_1200:
        case rich_product_type::ALIASOBJ_1100:
        case rich_product_type::ALIASOBJ_1000:
        case rich_product_type::ALIASOBJ_900:
        case rich_product_type::ALIASOBJ_800:
        case rich_product_type::ALIASOBJ_710:
            return rich_component_type::ALIAS_OBJ;

        // CVTPGD
        case rich_product_type::CVTPGD_1900:
        case rich_product_type::CVTPGD_1800:
        case rich_product_type::CVTPGD_1700:
        case rich_product_type::CVTPGD_1600:
        case rich_product_type::CVTPGD_1500:
        case rich_product_type::CVTPGD_1400:
        case rich_product_type::CVTPGD_1310:
            return rich_component_type::CVTPGD;

        // CVTOMF
        case rich_product_type::CVTOMF_800:
        case rich_product_type::CVTOMF_710:
        case rich_product_type::CVTOMF_612:
        case rich_product_type::CVTOMF_600:
        case rich_product_type::CVTOMF_511:
        case rich_product_type::CVTOMF_510:
            return rich_component_type::CVTOMF;

        default:
            return rich_component_type::UNKNOWN;
    }
}

std::string get_vs_version_for_build(uint16_t build_number) {
    // Note: Build numbers alone cannot reliably identify VS versions before VS2015
    // because different VS versions can have overlapping build number ranges.
    // This function is primarily useful for VS2015+ where all toolchains share
    // the same product IDs (0xFD-0x10E) and build numbers distinguish versions.
    //
    // For accurate version detection, use rich_header::vs_major_version() which
    // considers both product ID and build number.

    // VS2015+ build number ranges (23026-65535)
    // These are reliable because VS2015+ share the same product IDs
    if (build_number >= 23026) {
        if (build_number >= 35109) return "VS2026";  // VS2026 Insiders
        if (build_number >= 30159) return "VS2022";  // VS2022 (17.0+)
        if (build_number >= 27508) return "VS2019";  // VS2019 (16.0+)
        if (build_number >= 25017) return "VS2017";  // VS2017 (15.0+)
        return "VS2015";  // VS2015 (14.0+)
    }

    // Pre-VS2015 build numbers (unreliable without product ID context)
    // Return empty string - caller should use product ID for accurate detection
    return "";
}

} // namespace libexe
