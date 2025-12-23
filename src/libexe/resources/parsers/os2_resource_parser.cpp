// libexe - Modern executable file analysis library
// Copyright (c) 2024
//
// OS/2 Presentation Manager resource parsers

#include <libexe/resources/parsers/os2_resource_parser.hpp>
#include <formats/resources/os2/os2.hh>
#include <cstring>

namespace libexe {

// Use generated DataScript parsers
namespace ds = formats::resources::os2;

// =============================================================================
// Helper functions
// =============================================================================

namespace {

/// Extract null-terminated string from buffer at offset
std::string extract_string(std::span<const uint8_t> data, size_t offset, size_t max_len) {
    if (offset >= data.size()) return {};

    std::string result;
    size_t pos = offset;
    while (pos < data.size() && pos < offset + max_len && data[pos] != 0) {
        result.push_back(static_cast<char>(data[pos]));
        ++pos;
    }
    return result;
}

/// Extract fixed-size string (may not be null-terminated)
std::string extract_fixed_string(const uint8_t* data, size_t len) {
    // Find actual length (up to first null or end)
    size_t actual_len = 0;
    while (actual_len < len && data[actual_len] != 0) {
        ++actual_len;
    }
    return std::string(reinterpret_cast<const char*>(data), actual_len);
}

} // anonymous namespace

// =============================================================================
// OS/2 Accelerator Table Parser
// =============================================================================

std::optional<os2_accel_table> parse_os2_accel_table(std::span<const uint8_t> data) {
    if (data.size() < 4) {
        return std::nullopt;  // Too small for header
    }

    try {
        const uint8_t* p = data.data();
        const uint8_t* end = data.data() + data.size();

        auto parsed = ds::os2_accel_table::read(p, end);

        os2_accel_table result;
        result.codepage = parsed.codepage;
        result.entries.reserve(parsed.entries.size());

        for (const auto& e : parsed.entries) {
            os2_accel_entry entry;
            entry.flags = e.fs;
            entry.key = e.key;
            entry.cmd = e.cmd;
            result.entries.push_back(entry);
        }

        return result;
    } catch (...) {
        return std::nullopt;
    }
}

// =============================================================================
// OS/2 Dialog Parser
// =============================================================================

std::optional<os2_dialog_template> parse_os2_dialog(std::span<const uint8_t> data) {
    if (data.size() < 14) {
        return std::nullopt;  // Too small for template header
    }

    try {
        const uint8_t* p = data.data();
        const uint8_t* end = data.data() + data.size();

        // Parse header using DataScript
        auto header = ds::os2_dialog_template::read(p, end);

        os2_dialog_template result;
        result.type = header.type;
        result.codepage = header.codepage;
        result.status = header.fs_template_status;
        result.focus_item = header.i_item_focus;

        // Calculate number of items from template size
        // Each DLGTITEM is 26 bytes, items start at off_adlgti
        if (header.off_adlgti >= header.cb_template) {
            return result;  // No items
        }

        size_t items_start = header.off_adlgti;
        const uint8_t* items_ptr = data.data() + items_start;
        const uint8_t* items_end = data.data() + std::min(static_cast<size_t>(header.cb_template), data.size());

        // Parse items
        while (items_ptr + 26 <= items_end) {
            auto item = ds::os2_dialog_item::read(items_ptr, items_end);

            os2_dialog_item parsed_item;
            parsed_item.status = item.fs_item_status;
            parsed_item.children = item.c_children;
            parsed_item.style = item.fl_style;
            parsed_item.x = item.x;
            parsed_item.y = item.y;
            parsed_item.cx = item.cx;
            parsed_item.cy = item.cy;
            parsed_item.id = item.id;

            // Extract strings from offsets
            if (item.cch_class_name > 0 && item.off_class_name < data.size()) {
                parsed_item.class_name = extract_string(data, item.off_class_name, item.cch_class_name);
            }
            if (item.cch_text > 0 && item.off_text < data.size()) {
                parsed_item.text = extract_string(data, item.off_text, item.cch_text);
            }

            result.items.push_back(std::move(parsed_item));
        }

        return result;
    } catch (...) {
        return std::nullopt;
    }
}

// =============================================================================
// OS/2 Menu Parser
// =============================================================================

namespace {

/// Parse a submenu child item (6 bytes header: style, attr, id + text)
/// Returns the position after parsing, or 0 on error
size_t parse_submenu_child(std::span<const uint8_t> data, size_t pos,
                           std::vector<os2_menu_item>& items) {
    // Check for separator marker: 04 00 00 00 FF FF
    if (pos + 6 <= data.size() &&
        data[pos] == 0x04 && data[pos+1] == 0x00 &&
        data[pos+2] == 0x00 && data[pos+3] == 0x00 &&
        data[pos+4] == 0xFF && data[pos+5] == 0xFF) {
        // Add separator item
        os2_menu_item sep;
        sep.position = -1;
        sep.style = 0x0004;  // MIS_SEPARATOR
        sep.attribute = 0;
        sep.id = 0;
        items.push_back(std::move(sep));
        return pos + 6;
    }

    if (pos + 6 > data.size()) {
        return 0;
    }

    // Submenu child items have 6-byte header (no child_count field)
    // style(2) + attr(2) + id(2) + text
    uint16_t style = static_cast<uint16_t>(data[pos]) |
                    (static_cast<uint16_t>(data[pos+1]) << 8);
    uint16_t attr = static_cast<uint16_t>(data[pos+2]) |
                   (static_cast<uint16_t>(data[pos+3]) << 8);
    uint16_t id = static_cast<uint16_t>(data[pos+4]) |
                 (static_cast<uint16_t>(data[pos+5]) << 8);

    // Validate style
    if ((style & 0x0001) == 0) {
        return 0;  // Not a TEXT item
    }

    // Find null-terminated text
    size_t text_start = pos + 6;
    size_t text_end = text_start;
    while (text_end < data.size() && data[text_end] != 0) {
        ++text_end;
    }
    if (text_end >= data.size()) {
        return 0;
    }

    os2_menu_item item;
    item.position = -1;
    item.style = style;
    item.attribute = attr;
    item.id = id;
    item.text = std::string(reinterpret_cast<const char*>(&data[text_start]),
                            text_end - text_start);

    items.push_back(std::move(item));
    return text_end + 1;
}

/// Parse a top-level menu item (8 bytes header: count, style, attr, id + text)
/// Returns the position after parsing, or 0 on error
size_t parse_menu_item(std::span<const uint8_t> data, size_t pos,
                       std::vector<os2_menu_item>& items, int depth) {
    // Safety limits
    if (depth > 10 || pos + 8 > data.size()) {
        return 0;
    }

    // Read item header (8 bytes for top-level/submenu items)
    // child_count(2) + style(2) + attr(2) + id(2) + text
    uint16_t child_count = static_cast<uint16_t>(data[pos]) |
                          (static_cast<uint16_t>(data[pos+1]) << 8);
    uint16_t style = static_cast<uint16_t>(data[pos+2]) |
                    (static_cast<uint16_t>(data[pos+3]) << 8);
    uint16_t attr = static_cast<uint16_t>(data[pos+4]) |
                   (static_cast<uint16_t>(data[pos+5]) << 8);
    uint16_t id = static_cast<uint16_t>(data[pos+6]) |
                 (static_cast<uint16_t>(data[pos+7]) << 8);

    // Validate style - should have at least TEXT or SUBMENU flag
    if ((style & 0x0011) == 0) {
        return 0;  // Invalid item
    }

    // Find null-terminated text
    size_t text_start = pos + 8;
    size_t text_end = text_start;
    while (text_end < data.size() && data[text_end] != 0) {
        ++text_end;
    }
    if (text_end >= data.size()) {
        return 0;  // No null terminator found
    }

    os2_menu_item item;
    item.position = -1;  // Position not stored in resource
    item.style = style;
    item.attribute = attr;
    item.id = id;
    item.text = std::string(reinterpret_cast<const char*>(&data[text_start]),
                            text_end - text_start);

    size_t next_pos = text_end + 1;

    // If this is a submenu, parse children
    bool is_submenu = (style & 0x0010) != 0;
    if (is_submenu && next_pos + 10 <= data.size()) {
        // Submenu header: len(2), reserved(2), codepage(2), flags(2), child_count(2)
        uint16_t submenu_len = static_cast<uint16_t>(data[next_pos]) |
                              (static_cast<uint16_t>(data[next_pos+1]) << 8);
        // Skip reserved, codepage, flags (6 bytes)
        uint16_t num_children = static_cast<uint16_t>(data[next_pos+8]) |
                               (static_cast<uint16_t>(data[next_pos+9]) << 8);

        next_pos += 10;  // Skip submenu header

        // Parse child items (children use 6-byte format, not 8-byte)
        for (uint16_t i = 0; i < num_children && next_pos < data.size(); ++i) {
            size_t child_end = parse_submenu_child(data, next_pos, item.submenu);
            if (child_end == 0) {
                break;  // Error parsing child
            }
            next_pos = child_end;
        }

        (void)submenu_len;  // Could validate against actual bytes used
        (void)child_count;  // Top-level child_count field (different from submenu's num_children)
    }

    items.push_back(std::move(item));
    return next_pos;
}

} // anonymous namespace

std::optional<os2_menu> parse_os2_menu(std::span<const uint8_t> data) {
    // OS/2 Menu Template Format:
    // Header (8 bytes):
    //   uint16 total_size
    //   uint16 reserved (0)
    //   uint16 codepage (e.g., 437)
    //   uint16 top_level_item_count
    // Followed by menu items

    if (data.size() < 8) {
        return std::nullopt;
    }

    // Parse header
    uint16_t total_size = static_cast<uint16_t>(data[0]) |
                         (static_cast<uint16_t>(data[1]) << 8);
    // uint16_t reserved = ...
    // uint16_t codepage = ...
    uint16_t item_count = static_cast<uint16_t>(data[6]) |
                         (static_cast<uint16_t>(data[7]) << 8);

    // Sanity check
    if (item_count == 0 || item_count > 100) {
        return std::nullopt;
    }

    (void)total_size;  // Could validate against data.size()

    os2_menu result;

    // Parse top-level items
    size_t pos = 8;
    for (uint16_t i = 0; i < item_count && pos < data.size(); ++i) {
        size_t next_pos = parse_menu_item(data, pos, result.items, 0);
        if (next_pos == 0) {
            break;  // Error or end of data
        }
        pos = next_pos;
    }

    return result;
}

// =============================================================================
// OS/2 Bitmap Parser
// =============================================================================

std::optional<os2_bitmap_info> parse_os2_bitmap(std::span<const uint8_t> data) {
    if (data.size() < 26) {
        return std::nullopt;  // Too small for file header + minimal info header
    }

    try {
        os2_bitmap_info result;

        // Parse file header manually (14 bytes)
        result.type = static_cast<os2_bitmap_type>(
            static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8));
        result.file_size = static_cast<uint32_t>(data[2]) |
                          (static_cast<uint32_t>(data[3]) << 8) |
                          (static_cast<uint32_t>(data[4]) << 16) |
                          (static_cast<uint32_t>(data[5]) << 24);
        result.hotspot_x = static_cast<int16_t>(
            static_cast<uint16_t>(data[6]) | (static_cast<uint16_t>(data[7]) << 8));
        result.hotspot_y = static_cast<int16_t>(
            static_cast<uint16_t>(data[8]) | (static_cast<uint16_t>(data[9]) << 8));
        result.bits_offset = static_cast<uint32_t>(data[10]) |
                            (static_cast<uint32_t>(data[11]) << 8) |
                            (static_cast<uint32_t>(data[12]) << 16) |
                            (static_cast<uint32_t>(data[13]) << 24);

        // Info header starts at offset 14 - check its size to determine format
        uint32_t header_size = static_cast<uint32_t>(data[14]) |
                              (static_cast<uint32_t>(data[15]) << 8) |
                              (static_cast<uint32_t>(data[16]) << 16) |
                              (static_cast<uint32_t>(data[17]) << 24);

        size_t palette_entry_size;
        size_t palette_start;

        if (header_size == 12) {
            // OS/2 1.x BITMAPINFOHEADER (12 bytes)
            if (data.size() < 26) return std::nullopt;

            result.width = static_cast<uint16_t>(data[18]) | (static_cast<uint16_t>(data[19]) << 8);
            result.height = static_cast<uint16_t>(data[20]) | (static_cast<uint16_t>(data[21]) << 8);
            result.planes = static_cast<uint16_t>(data[22]) | (static_cast<uint16_t>(data[23]) << 8);
            result.bit_count = static_cast<uint16_t>(data[24]) | (static_cast<uint16_t>(data[25]) << 8);
            result.compression = 0;
            palette_entry_size = 3;  // RGB (no padding)
            palette_start = 14 + 12;
        } else {
            // OS/2 2.0+ or Windows BITMAPINFOHEADER2 (>= 16 bytes)
            if (data.size() < 14 + header_size) return std::nullopt;

            result.width = static_cast<uint32_t>(data[18]) |
                          (static_cast<uint32_t>(data[19]) << 8) |
                          (static_cast<uint32_t>(data[20]) << 16) |
                          (static_cast<uint32_t>(data[21]) << 24);
            result.height = static_cast<uint32_t>(data[22]) |
                           (static_cast<uint32_t>(data[23]) << 8) |
                           (static_cast<uint32_t>(data[24]) << 16) |
                           (static_cast<uint32_t>(data[25]) << 24);
            result.planes = static_cast<uint16_t>(data[26]) | (static_cast<uint16_t>(data[27]) << 8);
            result.bit_count = static_cast<uint16_t>(data[28]) | (static_cast<uint16_t>(data[29]) << 8);

            if (header_size > 16) {
                result.compression = static_cast<uint32_t>(data[30]) |
                                    (static_cast<uint32_t>(data[31]) << 8) |
                                    (static_cast<uint32_t>(data[32]) << 16) |
                                    (static_cast<uint32_t>(data[33]) << 24);
            } else {
                result.compression = 0;
            }
            palette_entry_size = 4;  // RGBX (with reserved byte)
            palette_start = 14 + header_size;
        }

        // Calculate palette size
        size_t palette_entries = 0;
        if (result.bit_count <= 8) {
            palette_entries = static_cast<size_t>(1) << result.bit_count;
        }

        // Read palette
        if (palette_entries > 0 && palette_start + palette_entries * palette_entry_size <= data.size()) {
            result.palette.reserve(palette_entries);
            for (size_t i = 0; i < palette_entries; ++i) {
                const uint8_t* entry = data.data() + palette_start + i * palette_entry_size;
                os2_bitmap_info::rgb rgb;
                rgb.blue = entry[0];
                rgb.green = entry[1];
                rgb.red = entry[2];
                result.palette.push_back(rgb);
            }
        }

        // Copy bitmap bits
        if (result.bits_offset < data.size()) {
            size_t bits_size = data.size() - result.bits_offset;
            result.bits.assign(
                data.data() + result.bits_offset,
                data.data() + result.bits_offset + bits_size
            );
        }

        return result;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<os2_bitmap_array> parse_os2_bitmap_array(std::span<const uint8_t> data) {
    if (data.size() < 14) {
        return std::nullopt;
    }

    try {
        os2_bitmap_array result;

        const uint8_t* p = data.data();
        const uint8_t* end = data.data() + data.size();

        // Check for bitmap array signature
        uint16_t type = static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
        if (type != 0x4142) {  // 'BA'
            // Not a bitmap array - try as single bitmap
            auto single = parse_os2_bitmap(data);
            if (single) {
                result.bitmaps.push_back(std::move(*single));
            }
            return result;
        }

        // Parse array entries
        size_t offset = 0;
        while (offset + 14 <= data.size()) {
            auto header = ds::os2_bitmap_array_header::read(p, end);

            // Parse the embedded bitmap
            size_t bmp_offset = offset + 14;  // After array header
            if (bmp_offset + 26 <= data.size()) {
                auto bmp = parse_os2_bitmap(data.subspan(bmp_offset));
                if (bmp) {
                    result.bitmaps.push_back(std::move(*bmp));
                }
            }

            // Move to next entry
            if (header.off_next == 0) {
                break;  // Last entry
            }
            offset = header.off_next;
            if (offset >= data.size()) {
                break;
            }
            p = data.data() + offset;
        }

        return result;
    } catch (...) {
        return std::nullopt;
    }
}

// =============================================================================
// OS/2 Font Parser
// =============================================================================

std::optional<os2_font> parse_os2_font(std::span<const uint8_t> data) {
    if (data.size() < 20) {
        return std::nullopt;  // Too small for font start signature
    }

    try {
        const uint8_t* p = data.data();
        const uint8_t* end = data.data() + data.size();

        // Parse font start signature
        auto font_start = ds::os2_font_start::read(p, end);

        os2_font result;
        result.signature = extract_fixed_string(font_start.ach_signature.data(), 12);

        // Parse metrics
        if (p + 136 > end) {
            return std::nullopt;
        }
        auto metrics = ds::os2_foca_metrics::read(p, end);

        result.metrics.family_name = extract_fixed_string(metrics.sz_familyname.data(), 32);
        result.metrics.face_name = extract_fixed_string(metrics.sz_facename.data(), 32);
        result.metrics.registry_id = metrics.us_registry_id;
        result.metrics.codepage = metrics.us_code_page;
        result.metrics.em_height = metrics.y_em_height;
        result.metrics.x_height = metrics.y_x_height;
        result.metrics.max_ascender = metrics.y_max_ascender;
        result.metrics.max_descender = metrics.y_max_descender;
        result.metrics.internal_leading = metrics.y_internal_leading;
        result.metrics.external_leading = metrics.y_external_leading;
        result.metrics.ave_char_width = metrics.x_ave_char_width;
        result.metrics.max_char_inc = metrics.x_max_char_inc;
        result.metrics.em_inc = metrics.x_em_inc;
        result.metrics.weight_class = metrics.us_weight_class;
        result.metrics.width_class = metrics.us_width_class;
        result.metrics.device_res_x = metrics.x_device_res;
        result.metrics.device_res_y = metrics.y_device_res;
        result.metrics.first_char = metrics.us_first_char;
        result.metrics.last_char = metrics.us_last_char;
        result.metrics.default_char = metrics.us_default_char;
        result.metrics.break_char = metrics.us_break_char;
        result.metrics.nominal_point_size = metrics.us_nominal_point_size;

        // Parse font definition header
        if (p + 24 > end) {
            return result;  // Return what we have
        }
        auto font_def = ds::os2_font_def_header::read(p, end);

        result.font_type = font_def.fs_fontdef;
        result.cell_height = font_def.y_cell_height;
        result.baseline_offset = font_def.p_cell_base_offset;

        // Parse character definitions
        int num_chars = metrics.us_last_char + 1;  // us_last_char is offset from first
        size_t char_data_size = font_def.ul_size - 24;  // Subtract header size

        // Determine character definition type
        bool is_type3 = (font_def.fs_chardef == 0xB8);  // OS2FONTDEF_CHAR3
        size_t char_def_size = is_type3 ? 10 : 6;

        result.characters.reserve(num_chars);
        for (int i = 0; i < num_chars && p + char_def_size <= end; ++i) {
            os2_char_def char_def;
            if (is_type3) {
                auto def = ds::os2_char_def3::read(p, end);
                char_def.bitmap_offset = def.ul_offset;
                char_def.width = 0;
                char_def.a_space = def.a_space;
                char_def.b_space = def.b_space;
                char_def.c_space = def.c_space;
            } else {
                auto def = ds::os2_char_def1::read(p, end);
                char_def.bitmap_offset = def.ul_offset;
                char_def.width = def.ul_width;
                char_def.a_space = 0;
                char_def.b_space = 0;
                char_def.c_space = 0;
            }
            result.characters.push_back(char_def);
        }

        // The remaining data is bitmap data
        // Character offsets are absolute from resource start, so we need to adjust them
        // to be relative to bitmap_data start
        if (p < end) {
            size_t bitmap_base = static_cast<size_t>(p - data.data());
            for (auto& ch : result.characters) {
                if (ch.bitmap_offset >= bitmap_base) {
                    ch.bitmap_offset -= static_cast<uint32_t>(bitmap_base);
                }
            }
            result.bitmap_data.assign(p, end);
        }

        // Try to parse PANOSE from additional metrics at end
        // (Skip for now - would need to scan for SIG_OS2ADDMETRICS)

        return result;
    } catch (...) {
        return std::nullopt;
    }
}

std::vector<os2_font_dir_entry> parse_os2_font_directory(std::span<const uint8_t> data) {
    std::vector<os2_font_dir_entry> result;

    if (data.size() < 6) {
        return result;  // Too small for header
    }

    try {
        const uint8_t* p = data.data();
        const uint8_t* end = data.data() + data.size();

        auto header = ds::os2_font_directory_header::read(p, end);

        result.reserve(header.us_n_fonts);
        for (uint16_t i = 0; i < header.us_n_fonts && p + 150 <= end; ++i) {
            auto entry = ds::os2_font_dir_entry::read(p, end);

            os2_font_dir_entry parsed;
            parsed.resource_id = entry.us_index;
            parsed.metrics.family_name = extract_fixed_string(entry.metrics.sz_familyname.data(), 32);
            parsed.metrics.face_name = extract_fixed_string(entry.metrics.sz_facename.data(), 32);
            parsed.metrics.registry_id = entry.metrics.us_registry_id;
            parsed.metrics.codepage = entry.metrics.us_code_page;
            parsed.metrics.em_height = entry.metrics.y_em_height;
            parsed.metrics.x_height = entry.metrics.y_x_height;
            parsed.metrics.max_ascender = entry.metrics.y_max_ascender;
            parsed.metrics.max_descender = entry.metrics.y_max_descender;
            parsed.metrics.internal_leading = entry.metrics.y_internal_leading;
            parsed.metrics.external_leading = entry.metrics.y_external_leading;
            parsed.metrics.ave_char_width = entry.metrics.x_ave_char_width;
            parsed.metrics.max_char_inc = entry.metrics.x_max_char_inc;
            parsed.metrics.em_inc = entry.metrics.x_em_inc;
            parsed.metrics.weight_class = entry.metrics.us_weight_class;
            parsed.metrics.width_class = entry.metrics.us_width_class;
            parsed.metrics.device_res_x = entry.metrics.x_device_res;
            parsed.metrics.device_res_y = entry.metrics.y_device_res;
            parsed.metrics.first_char = entry.metrics.us_first_char;
            parsed.metrics.last_char = entry.metrics.us_last_char;
            parsed.metrics.default_char = entry.metrics.us_default_char;
            parsed.metrics.break_char = entry.metrics.us_break_char;
            parsed.metrics.nominal_point_size = entry.metrics.us_nominal_point_size;
            std::memcpy(parsed.metrics.panose, entry.panose.data(), 12);

            result.push_back(std::move(parsed));
        }
    } catch (...) {
        // Return what we have
    }

    return result;
}

// =============================================================================
// OS/2 String Table Parser
// =============================================================================

std::vector<std::string> parse_os2_string_table(std::span<const uint8_t> data) {
    std::vector<std::string> result;

    if (data.size() < 3) {
        return result;
    }

    // OS/2 string table format:
    // - uint16 codepage (e.g., 437 for US codepage)
    // - Repeated entries: uint8 length, string data (NOT null-terminated in length)
    //   followed by null terminator

    size_t pos = 2;  // Skip codepage

    while (pos < data.size()) {
        uint8_t len = data[pos];
        ++pos;

        if (len == 0) {
            // Empty string - just add it and skip null terminator if present
            result.emplace_back("");
            if (pos < data.size() && data[pos] == 0) {
                ++pos;
            }
            continue;
        }

        if (pos + len > data.size()) {
            break;  // Not enough data
        }

        // Extract string (length bytes)
        result.emplace_back(reinterpret_cast<const char*>(&data[pos]), len);
        pos += len;

        // Skip null terminator if present
        if (pos < data.size() && data[pos] == 0) {
            ++pos;
        }
    }

    return result;
}

} // namespace libexe
