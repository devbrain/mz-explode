#include <libexe/resources/parsers/menu_parser.hpp>
#include "libexe_format_menus.hh"
#include "../../core/utf_convert.hpp"

namespace libexe {

namespace {

// Helper to read uint16 from buffer (little-endian)
uint16_t read_uint16_le(const uint8_t*& ptr, const uint8_t* end) {
    if (ptr + 2 > end) {
        throw std::runtime_error("Buffer underrun reading uint16");
    }
    uint16_t value = static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8);
    ptr += 2;
    return value;
}

// Helper to read null-terminated ANSI string (NE format)
std::string read_ansi_string(const uint8_t*& ptr, const uint8_t* end) {
    std::string result;

    while (ptr < end && *ptr != 0) {
        result.push_back(static_cast<char>(*ptr));
        ptr++;
    }

    if (ptr < end && *ptr == 0) {
        ptr++;
    }

    return result;
}

// Helper to read null-terminated UTF-16LE string and convert to UTF-8 (PE format)
std::string read_u16string(const uint8_t*& ptr, const uint8_t* end) {
    std::vector<uint16_t> u16data;

    while (ptr + 2 <= end) {
        uint16_t wchar = static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8);
        ptr += 2;

        if (wchar == 0) {
            break;
        }

        u16data.push_back(wchar);
    }

    return utf16_to_utf8(u16data);
}

// Detect menu format (NE=ANSI or PE=UTF-16)
// Heuristic: Check if string appears to be UTF-16 (alternating pattern with nulls)
bool is_utf16_format(const uint8_t* ptr, const uint8_t* end) {
    // Need at least a few characters to check
    if (ptr + 6 > end) {
        return false;
    }

    // Skip flags
    ptr += 2;

    // Check if next bytes look like UTF-16 ASCII (every other byte is 0)
    int ascii_count = 0;
    int null_count = 0;

    for (int i = 0; i < 6 && ptr + i < end; i++) {
        if (i % 2 == 0) {
            // Even position: should be ASCII character (0x20-0x7E)
            if (ptr[i] >= 0x20 && ptr[i] <= 0x7E) {
                ascii_count++;
            }
        } else {
            // Odd position: should be 0 for ASCII in UTF-16
            if (ptr[i] == 0) {
                null_count++;
            }
        }
    }

    // If most odd positions are 0, it's probably UTF-16
    return (null_count >= 2 && ascii_count >= 2);
}

// Forward declaration for recursive parsing
bool parse_menu_items(const uint8_t*& ptr, const uint8_t* end, std::vector<menu_item>& items, bool use_utf16);

// Parse a single menu item and its children
bool parse_menu_item(const uint8_t*& ptr, const uint8_t* end, menu_item& item, bool use_utf16) {
    // Read flags
    if (ptr + 2 > end) {
        return false;
    }
    item.flags = read_uint16_le(ptr, end);

    // Check if this is a popup menu or normal item
    if (item.flags & static_cast<uint16_t>(menu_flags::POPUP)) {
        // Popup menu: flags + text + children
        item.command_id = 0;  // Popups don't have command IDs
        item.text = use_utf16 ? read_u16string(ptr, end) : read_ansi_string(ptr, end);

        // Parse child items recursively
        if (!parse_menu_items(ptr, end, item.children, use_utf16)) {
            return false;
        }
    } else {
        // Normal menu item: flags + command_id + text
        if (ptr + 2 > end) {
            return false;
        }
        item.command_id = read_uint16_le(ptr, end);
        item.text = use_utf16 ? read_u16string(ptr, end) : read_ansi_string(ptr, end);
    }

    return true;
}

// Parse a sequence of menu items at the same level
bool parse_menu_items(const uint8_t*& ptr, const uint8_t* end, std::vector<menu_item>& items, bool use_utf16) {
    while (ptr < end) {
        menu_item item;

        if (!parse_menu_item(ptr, end, item, use_utf16)) {
            return false;
        }

        bool is_end = (item.flags & static_cast<uint16_t>(menu_flags::END)) != 0;
        items.push_back(std::move(item));

        // If this is the last item at this level, stop
        if (is_end) {
            break;
        }
    }

    return true;
}

} // anonymous namespace

std::optional<menu_template> menu_parser::parse(std::span<const uint8_t> data, windows_resource_format format) {
    // Minimum size check (header is 4 bytes)
    if (data.size() < 4) {
        return std::nullopt;
    }

    try {
        menu_template result;

        // Parse header using generated DataScript parser
        const uint8_t* ptr = data.data();
        const uint8_t* end = data.data() + data.size();
        auto ds_header = formats::resources::menus::menu_header::read(ptr, end);

        result.version = ds_header.version;
        result.header_size = ds_header.header_size;

        // Use format discriminator for string encoding
        bool use_utf16 = (format == windows_resource_format::PE);

        // Parse menu items recursively
        if (!parse_menu_items(ptr, end, result.items, use_utf16)) {
            return std::nullopt;
        }

        return result;
    }
    catch (const std::exception&) {
        // Parse error - return nullopt
        return std::nullopt;
    }
}

} // namespace libexe
