#include <libexe/resources/parsers/font_parser.hpp>
#include <formats/resources/fonts/fonts.hh>
#include <cstring>

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

// Parse Windows 2.x font using DataScript
std::optional<font_data> parse_font_2x(std::span<const uint8_t> data) {
    const uint8_t* ptr = data.data();
    const uint8_t* end = data.data() + data.size();

    auto ds_font = formats::resources::fonts::font_2x::read(ptr, end);

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

    // Face name
    result.face_name = read_string_at_offset(data, ds_font.face);

    // Convert glyph table from DataScript
    result.glyphs.reserve(ds_font.glyphs.size());
    for (const auto& ds_glyph : ds_font.glyphs) {
        glyph_entry glyph;
        glyph.width = ds_glyph.width;
        glyph.offset = ds_glyph.offset;
        result.glyphs.push_back(glyph);
    }

    // Bitmap data: use the first glyph offset as the start of bitmap data
    // In 2.x fonts, glyph offsets are absolute from start of font file
    if (!result.glyphs.empty() && result.glyphs[0].offset < data.size()) {
        uint32_t bits_start = result.glyphs[0].offset;
        const uint8_t* bitmap_start = data.data() + bits_start;
        size_t bitmap_size = data.size() - bits_start;
        result.bitmap_data.assign(bitmap_start, bitmap_start + bitmap_size);
    }

    return result;
}

// Parse Windows 3.x font using DataScript
std::optional<font_data> parse_font_3x(std::span<const uint8_t> data) {
    const uint8_t* ptr = data.data();
    const uint8_t* end = data.data() + data.size();

    auto ds_font = formats::resources::fonts::font_3x::read(ptr, end);

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

    // Face name
    result.face_name = read_string_at_offset(data, ds_font.face);

    // Convert glyph table from DataScript
    result.glyphs.reserve(ds_font.glyphs.size());
    for (const auto& ds_glyph : ds_font.glyphs) {
        glyph_entry glyph;
        glyph.width = ds_glyph.width;
        glyph.offset = ds_glyph.offset;
        result.glyphs.push_back(glyph);
    }

    // Bitmap data starts at bits_offset
    if (ds_font.bits_offset < data.size()) {
        const uint8_t* bitmap_start = data.data() + ds_font.bits_offset;
        size_t bitmap_size = data.size() - ds_font.bits_offset;
        result.bitmap_data.assign(bitmap_start, bitmap_start + bitmap_size);
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
        // Check version to determine which parser to use
        uint16_t version = static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);

        if (version == 0x0200) {
            return parse_font_2x(data);
        } else if (version == 0x0300) {
            return parse_font_3x(data);
        } else {
            // Unknown version - try 2.x format as fallback
            return parse_font_2x(data);
        }
    }
    catch (const std::exception&) {
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
    size_t bytes_per_row = (glyph.width + 7) / 8;
    size_t bitmap_size = bytes_per_row * pixel_height;

    // For 2.x fonts, offset is relative to bits_offset which we've already handled
    // The bitmap_data already starts at bits_offset, so we need to adjust
    // Actually, in 2.x format, offset is absolute from start of file
    // But we stored bitmap_data starting from bits_offset
    // So we need to subtract bits_offset from the glyph offset

    // The glyph offset points to the bitmap data relative to file start
    // Our bitmap_data starts at bits_offset from file start
    // So the index into bitmap_data is: glyph.offset - bits_offset
    // But we don't have bits_offset stored... let's check if offset is already relative

    // Actually, looking at the font format, for character bitmaps in 2.x:
    // The offset in glyph entry is the byte offset from start of file to the bitmap
    // We need to compute relative to where bitmap_data starts

    // For simplicity, let's compute assuming offsets are into the original file
    // and bitmap_data contains everything from bits_offset onwards

    // Get the minimum offset from all glyphs to determine bits_offset
    uint32_t min_offset = UINT32_MAX;
    for (const auto& g : glyphs) {
        if (g.offset > 0 && g.offset < min_offset) {
            min_offset = g.offset;
        }
    }

    if (min_offset == UINT32_MAX || glyph.offset < min_offset) {
        return {};
    }

    size_t relative_offset = glyph.offset - min_offset;

    // Check bounds
    if (relative_offset + bitmap_size > bitmap_data.size()) {
        return {};
    }

    return std::span<const uint8_t>(
        bitmap_data.data() + relative_offset,
        bitmap_size
    );
}

} // namespace libexe
