#include <libexe/resources/parsers/version_info_parser.hpp>
#include "libexe_format_version.hh"  // Generated DataScript parser (modular)
#include <sstream>
#include <cstring>

namespace libexe {

namespace {

// Helper to read uint16_t little-endian
uint16_t read_u16(const uint8_t* ptr) {
    return static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8);
}

// Helper to read uint32_t little-endian
uint32_t read_u32(const uint8_t* ptr) {
    return static_cast<uint32_t>(ptr[0]) |
           (static_cast<uint32_t>(ptr[1]) << 8) |
           (static_cast<uint32_t>(ptr[2]) << 16) |
           (static_cast<uint32_t>(ptr[3]) << 24);
}

// Helper to align pointer to DWORD boundary
const uint8_t* align_dword(const uint8_t* ptr, const uint8_t* base) {
    size_t offset = ptr - base;
    size_t aligned = (offset + 3) & ~3;
    return base + aligned;
}

// Helper to read null-terminated UTF-16 string
std::u16string read_utf16_string(const uint8_t*& ptr, const uint8_t* end) {
    std::u16string result;

    while (ptr + 1 < end) {
        uint16_t ch = read_u16(ptr);
        ptr += 2;

        if (ch == 0) {
            break;
        }

        result.push_back(static_cast<char16_t>(ch));
    }

    return result;
}

// Helper to convert UTF-16 to UTF-8
std::string utf16_to_utf8(const std::u16string& str) {
    std::string result;

    for (char16_t ch : str) {
        if (ch < 0x80) {
            result.push_back(static_cast<char>(ch));
        } else if (ch < 0x800) {
            result.push_back(static_cast<char>(0xC0 | (ch >> 6)));
            result.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
        } else {
            result.push_back(static_cast<char>(0xE0 | (ch >> 12)));
            result.push_back(static_cast<char>(0x80 | ((ch >> 6) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
        }
    }

    return result;
}

// Helper to parse StringFileInfo section
void parse_string_file_info(const uint8_t* ptr, const uint8_t* end, const uint8_t* base,
                            std::map<std::string, std::string>& strings) {
    if (ptr + 6 > end) return;

    uint16_t length = read_u16(ptr);
    // uint16_t value_length = read_u16(ptr + 2);  // Not used for StringFileInfo
    // uint16_t type = read_u16(ptr + 4);  // Should be 1 (text)

    const uint8_t* section_end = ptr + length;
    if (section_end > end) section_end = end;

    ptr += 6;

    // Skip "StringFileInfo" key
    auto key = read_utf16_string(ptr, end);
    ptr = align_dword(ptr, base);

    // Parse StringTable children
    while (ptr + 6 < section_end) {
        uint16_t table_len = read_u16(ptr);
        if (table_len == 0) break;

        const uint8_t* table_end = ptr + table_len;
        if (table_end > section_end) table_end = section_end;

        ptr += 6;

        // Skip language ID (e.g., "040904b0")
        read_utf16_string(ptr, table_end);
        ptr = align_dword(ptr, base);

        // Parse String children (key-value pairs)
        while (ptr + 6 < table_end) {
            uint16_t string_len = read_u16(ptr);
            if (string_len == 0) break;

            uint16_t value_len = read_u16(ptr + 2);
            // uint16_t string_type = read_u16(ptr + 4);

            const uint8_t* string_end = ptr + string_len;
            if (string_end > table_end) string_end = table_end;

            ptr += 6;

            // Read key
            auto key_u16 = read_utf16_string(ptr, string_end);
            std::string key_str = utf16_to_utf8(key_u16);
            ptr = align_dword(ptr, base);

            // Read value
            std::string value_str;
            if (value_len > 0 && ptr < string_end) {
                auto value_u16 = read_utf16_string(ptr, string_end);
                value_str = utf16_to_utf8(value_u16);
            }

            strings[key_str] = value_str;

            ptr = align_dword(string_end, base);
        }

        ptr = align_dword(table_end, base);
    }
}

} // anonymous namespace

std::optional<version_info> version_info_parser::parse(std::span<const uint8_t> data) {
    // Minimum size check (VS_VERSIONINFO header + VS_FIXEDFILEINFO)
    if (data.size() < 58) {  // 6 + 52
        return std::nullopt;
    }

    try {
        const uint8_t* ptr = data.data();
        const uint8_t* end = data.data() + data.size();
        const uint8_t* base = data.data();

        // Parse VS_VERSIONINFO header
        uint16_t vs_info_len = read_u16(ptr);
        uint16_t value_len = read_u16(ptr + 2);
        // uint16_t type = read_u16(ptr + 4);  // Should be 0 (binary)

        ptr += 6;

        // Skip "VS_VERSION_INFO" key
        auto vs_key = read_utf16_string(ptr, end);
        ptr = align_dword(ptr, base);

        // Parse VS_FIXEDFILEINFO using DataScript
        if (ptr + 52 > end) {
            return std::nullopt;
        }

        auto ds_fixed_info = formats::resources::version::vs_fixed_file_info::read(ptr, end);

        version_info result;

        // Convert DataScript structure to our public API
        result.fixed_info.signature = ds_fixed_info.signature;
        result.fixed_info.struct_version = ds_fixed_info.struct_version;

        // File version
        result.fixed_info.file_version_major = static_cast<uint16_t>(ds_fixed_info.file_version_ms >> 16);
        result.fixed_info.file_version_minor = static_cast<uint16_t>(ds_fixed_info.file_version_ms & 0xFFFF);
        result.fixed_info.file_version_patch = static_cast<uint16_t>(ds_fixed_info.file_version_ls >> 16);
        result.fixed_info.file_version_build = static_cast<uint16_t>(ds_fixed_info.file_version_ls & 0xFFFF);

        // Product version
        result.fixed_info.product_version_major = static_cast<uint16_t>(ds_fixed_info.product_version_ms >> 16);
        result.fixed_info.product_version_minor = static_cast<uint16_t>(ds_fixed_info.product_version_ms & 0xFFFF);
        result.fixed_info.product_version_patch = static_cast<uint16_t>(ds_fixed_info.product_version_ls >> 16);
        result.fixed_info.product_version_build = static_cast<uint16_t>(ds_fixed_info.product_version_ls & 0xFFFF);

        result.fixed_info.file_flags_mask = ds_fixed_info.file_flags_mask;
        result.fixed_info.file_flags = ds_fixed_info.file_flags;
        result.fixed_info.file_os = ds_fixed_info.file_os;
        result.fixed_info.file_type = ds_fixed_info.file_type;
        result.fixed_info.file_subtype = ds_fixed_info.file_subtype;
        result.fixed_info.file_date = (static_cast<uint64_t>(ds_fixed_info.file_date_ms) << 32) |
                                       ds_fixed_info.file_date_ls;

        // Move past VS_FIXEDFILEINFO
        ptr = align_dword(ptr, base);

        // Parse children (StringFileInfo, VarFileInfo)
        const uint8_t* vs_info_end = base + vs_info_len;
        if (vs_info_end > end) vs_info_end = end;

        while (ptr + 6 < vs_info_end) {
            uint16_t child_len = read_u16(ptr);
            if (child_len == 0) break;

            const uint8_t* child_end = ptr + child_len;
            if (child_end > vs_info_end) child_end = vs_info_end;

            // Peek at key to determine child type
            const uint8_t* key_ptr = ptr + 6;
            auto child_key = read_utf16_string(key_ptr, child_end);
            std::string child_key_str = utf16_to_utf8(child_key);

            if (child_key_str == "StringFileInfo") {
                parse_string_file_info(ptr, child_end, base, result.strings);
            }
            // VarFileInfo is not commonly used, skip for now

            ptr = align_dword(child_end, base);
        }

        return result;
    }
    catch (const std::exception&) {
        // Parse error - return nullopt
        return std::nullopt;
    }
}

std::string fixed_file_info::file_version_string() const {
    std::ostringstream oss;
    oss << file_version_major << "."
        << file_version_minor << "."
        << file_version_patch << "."
        << file_version_build;
    return oss.str();
}

std::string fixed_file_info::product_version_string() const {
    std::ostringstream oss;
    oss << product_version_major << "."
        << product_version_minor << "."
        << product_version_patch << "."
        << product_version_build;
    return oss.str();
}

} // namespace libexe
