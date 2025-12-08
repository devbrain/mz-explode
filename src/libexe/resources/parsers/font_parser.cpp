#include <libexe/resources/parsers/font_parser.hpp>
#include "libexe_format_fonts.hh"  // Generated DataScript parser (modular)
#include <cstring>
#include <algorithm>

namespace libexe {

namespace {

// Helper to extract null-terminated string from byte array
std::string extract_string(const uint8_t* data, size_t max_len) {
    size_t len = 0;
    while (len < max_len && data[len] != 0) {
        ++len;
    }
    return std::string(reinterpret_cast<const char*>(data), len);
}

// Helper to read null-terminated string from offset
std::string read_string_at_offset(std::span<const uint8_t> data, uint32_t offset) {
    if (offset == 0 || offset >= data.size()) {
        return "";
    }

    const uint8_t* ptr = data.data() + offset;
    const uint8_t* end = data.data() + data.size();

    std::string result;
    while (ptr < end && *ptr != 0) {
        result.push_back(static_cast<char>(*ptr));
        ++ptr;
    }

    return result;
}

} // anonymous namespace

std::optional<font_data> font_parser::parse(std::span<const uint8_t> data) {
    // Minimum size check (header is 118 bytes)
    if (data.size() < 118) {
        return std::nullopt;
    }

    try {
        // Parse using generated DataScript parser
        const uint8_t* ptr = data.data();
        const uint8_t* end = data.data() + data.size();
        auto ds_font = formats::resources::fonts::font_header::read(ptr, end);

        // Convert to our public API structure
        font_data result;

        // Metadata
        result.version = ds_font.version;
        result.size = ds_font.size;
        result.copyright = extract_string(ds_font.copyright.data(), ds_font.copyright.size());
        result.type = static_cast<font_type>(ds_font.type);

        // Metrics
        result.points = ds_font.points;
        result.vertical_res = ds_font.vert_res;
        result.horizontal_res = ds_font.horiz_res;
        result.ascent = ds_font.ascent;
        result.internal_leading = ds_font.internal_leading;
        result.external_leading = ds_font.external_leading;

        // Appearance
        result.italic = ds_font.italic != 0;
        result.underline = ds_font.underline != 0;
        result.strikeout = ds_font.strike_out != 0;
        result.weight = ds_font.weight;
        result.charset = ds_font.char_set;

        // Dimensions
        result.pixel_width = ds_font.pix_width;
        result.pixel_height = ds_font.pix_height;
        result.avg_width = ds_font.avg_width;
        result.max_width = ds_font.max_width;

        // Character range
        result.first_char = ds_font.first_char;
        result.last_char = ds_font.last_char;
        result.default_char = ds_font.default_char;
        result.break_char = ds_font.break_char;

        // Pitch and family
        result.pitch = static_cast<font_pitch>(ds_font.pitch_and_family & 0x0F);
        result.family = static_cast<font_family>(ds_font.pitch_and_family & 0xF0);

        // Face name (stored at face offset)
        result.face_name = read_string_at_offset(data, ds_font.face);

        // Parse glyph table
        // The glyph table immediately follows the header
        size_t char_count = result.character_count() + 1;  // +1 for sentinel
        result.glyphs.reserve(char_count);

        // Reset pointer to parse glyph table
        ptr = data.data() + 118;  // Start of glyph table (after header)

        // Determine glyph entry size based on version and flags
        bool has_abc_spacing = (ds_font.flags & 0x0001) != 0;  // DFF_ABCFIXED or DFF_ABCPROPORTIONAL
        bool is_color = (ds_font.flags & 0x0004) != 0;         // DFF_COLORFONT

        for (size_t i = 0; i < char_count && ptr + 6 <= end; ++i) {
            glyph_entry glyph;

            if (result.version == 0x0200) {
                // Windows 2.x: 2-byte width + 2-byte offset
                if (ptr + 4 > end) break;
                glyph.width = static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8);
                glyph.offset = static_cast<uint16_t>(ptr[2]) | (static_cast<uint16_t>(ptr[3]) << 8);
                ptr += 4;
            } else {
                // Windows 3.0: 2-byte width + 4-byte offset
                if (ptr + 6 > end) break;
                glyph.width = static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8);
                glyph.offset = static_cast<uint32_t>(ptr[2]) |
                              (static_cast<uint32_t>(ptr[3]) << 8) |
                              (static_cast<uint32_t>(ptr[4]) << 16) |
                              (static_cast<uint32_t>(ptr[5]) << 24);
                ptr += 6;

                // Parse ABC spacing if present
                if (has_abc_spacing && ptr + 6 <= end) {
                    glyph.a_space = static_cast<int16_t>(
                        static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8)
                    );
                    glyph.b_space = static_cast<uint16_t>(ptr[2]) | (static_cast<uint16_t>(ptr[3]) << 8);
                    glyph.c_space = static_cast<int16_t>(
                        static_cast<uint16_t>(ptr[4]) | (static_cast<uint16_t>(ptr[5]) << 8)
                    );
                    ptr += 6;
                }
            }

            result.glyphs.push_back(glyph);
        }

        // The bitmap data starts after the glyph table
        // For simplicity, we store everything from bits_offset to end of file
        if (ds_font.bits_offset < data.size()) {
            const uint8_t* bitmap_start = data.data() + ds_font.bits_offset;
            size_t bitmap_size = data.size() - ds_font.bits_offset;
            result.bitmap_data.assign(bitmap_start, bitmap_start + bitmap_size);
        }

        return result;
    }
    catch (const std::exception&) {
        // Parse error - return nullopt
        return std::nullopt;
    }
}

std::span<const uint8_t> font_data::get_char_bitmap(uint8_t c) const {
    // Check if character is in range
    if (c < first_char || c > last_char) {
        return {};
    }

    // Get glyph index
    size_t glyph_index = c - first_char;
    if (glyph_index >= glyphs.size()) {
        return {};
    }

    const auto& glyph = glyphs[glyph_index];

    // Calculate bitmap size
    size_t bytes_per_row = (glyph.width + 7) / 8;  // Round up to bytes
    size_t bitmap_size = bytes_per_row * pixel_height;

    // Check bounds
    if (glyph.offset + bitmap_size > bitmap_data.size()) {
        return {};
    }

    return std::span<const uint8_t>(
        bitmap_data.data() + glyph.offset,
        bitmap_size
    );
}

} // namespace libexe
