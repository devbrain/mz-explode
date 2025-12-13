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

// Helper to read little-endian uint16
uint16_t read_u16(const uint8_t* ptr) {
    return static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8);
}

// Helper to read little-endian uint32
uint32_t read_u32(const uint8_t* ptr) {
    return static_cast<uint32_t>(ptr[0]) |
           (static_cast<uint32_t>(ptr[1]) << 8) |
           (static_cast<uint32_t>(ptr[2]) << 16) |
           (static_cast<uint32_t>(ptr[3]) << 24);
}

// Pen-up marker for vector fonts
constexpr uint8_t PEN_UP_MARKER = 0x80;

// Decode stroke data into stroke commands
std::vector<stroke_command> decode_strokes(const uint8_t* data, size_t len) {
    std::vector<stroke_command> result;
    bool need_move = true;  // First point after pen-up is a move

    size_t i = 0;
    while (i < len) {
        if (data[i] == PEN_UP_MARKER) {
            stroke_command cmd;
            cmd.cmd = stroke_command::type::PEN_UP;
            cmd.x = 0;
            cmd.y = 0;
            result.push_back(cmd);
            need_move = true;
            i++;
        } else {
            if (i + 1 >= len) break;

            stroke_command cmd;
            cmd.cmd = need_move ? stroke_command::type::MOVE_TO : stroke_command::type::LINE_TO;
            cmd.x = static_cast<int8_t>(data[i]);
            cmd.y = static_cast<int8_t>(data[i + 1]);
            result.push_back(cmd);
            need_move = false;
            i += 2;
        }
    }

    return result;
}

// Parse Windows 1.x raster font (manually, no DataScript)
// Windows 1.x uses a row-major bitmap format where all glyphs are in a single bitmap.
// The glyph table contains pixel offsets into each row. We convert this to the
// column-major per-glyph format used by Windows 2.x/3.x for API consistency.
std::optional<font_data> parse_font_1x_raster(std::span<const uint8_t> data) {
    // FNT 1.x header is 117 bytes
    if (data.size() < 117) {
        return std::nullopt;
    }

    const uint8_t* ptr = data.data();

    font_data result;

    // Metadata
    result.version = read_u16(ptr + 0);
    result.size = read_u32(ptr + 2);
    result.copyright = extract_string(ptr + 6, 60);
    result.type = static_cast<font_type>(read_u16(ptr + 66));

    // Metrics
    result.points = read_u16(ptr + 68);
    result.vertical_res = read_u16(ptr + 70);
    result.horizontal_res = read_u16(ptr + 72);
    result.ascent = read_u16(ptr + 74);
    result.internal_leading = read_u16(ptr + 76);
    result.external_leading = read_u16(ptr + 78);

    // Appearance
    result.italic = ptr[80] != 0;
    result.underline = ptr[81] != 0;
    result.strikeout = ptr[82] != 0;
    result.weight = read_u16(ptr + 83);
    result.charset = ptr[85];

    // Dimensions
    result.pixel_width = read_u16(ptr + 86);
    result.pixel_height = read_u16(ptr + 88);
    uint8_t pitch_and_family = ptr[90];
    result.avg_width = read_u16(ptr + 91);
    result.max_width = read_u16(ptr + 93);

    // Character range
    result.first_char = ptr[95];
    result.last_char = ptr[96];
    result.default_char = ptr[97];
    result.break_char = ptr[98];

    // Width bytes (bytes per row in the combined bitmap)
    result.width_bytes = read_u16(ptr + 99);

    // Device and face name offsets
    uint32_t face_offset = read_u32(ptr + 105);
    uint32_t bits_offset = read_u32(ptr + 113);

    // Pitch and family
    result.pitch = static_cast<font_pitch>(pitch_and_family & 0x0F);
    result.family = static_cast<font_family>(pitch_and_family & 0xF0);

    // Face name
    result.face_name = read_string_at_offset(data, face_offset);

    size_t num_glyphs = result.last_char - result.first_char + 1;
    size_t glyph_table_start = 117;
    uint16_t height = result.pixel_height;
    uint16_t row_bytes = result.width_bytes;

    // Validate bitmap data availability
    size_t bitmap_size = static_cast<size_t>(row_bytes) * height;
    if (bits_offset + bitmap_size > data.size()) {
        return std::nullopt;
    }

    // Windows 1.x fonts store all glyphs in a single row-major bitmap.
    // Format: row 0 (row_bytes), row 1 (row_bytes), ..., row height-1 (row_bytes)
    // Glyph table entries contain pixel/bit offsets into each row.
    // We convert to column-major per-glyph format for compatibility with 2.x/3.x.

    // First, determine pixel offsets for each glyph
    std::vector<uint16_t> pixel_offsets;
    std::vector<uint16_t> glyph_widths;

    if (result.pixel_width != 0) {
        // Fixed-pitch font: all glyphs have the same width
        // No glyph table; offsets are calculated
        pixel_offsets.reserve(num_glyphs);
        glyph_widths.reserve(num_glyphs);
        for (size_t i = 0; i < num_glyphs; i++) {
            pixel_offsets.push_back(static_cast<uint16_t>(i * result.pixel_width));
            glyph_widths.push_back(result.pixel_width);
        }
    } else {
        // Variable-pitch font: glyph table has 2-byte pixel offset entries
        size_t glyph_table_size = (num_glyphs + 1) * 2;  // +1 for sentinel

        if (glyph_table_start + glyph_table_size > data.size()) {
            return std::nullopt;
        }

        // Read all pixel offsets including sentinel
        std::vector<uint16_t> offsets;
        offsets.reserve(num_glyphs + 1);
        for (size_t i = 0; i <= num_glyphs; i++) {
            size_t entry_offset = glyph_table_start + i * 2;
            offsets.push_back(read_u16(ptr + entry_offset));
        }

        pixel_offsets.reserve(num_glyphs);
        glyph_widths.reserve(num_glyphs);
        for (size_t i = 0; i < num_glyphs; i++) {
            pixel_offsets.push_back(offsets[i]);
            glyph_widths.push_back(offsets[i + 1] - offsets[i]);
        }
    }

    // Convert row-major combined bitmap to column-major per-glyph bitmaps
    //
    // Windows 2.x/3.x column-major format expected by draw():
    // For each byte-column (group of 8 horizontal pixels), store all rows sequentially.
    // Each byte represents one row's worth of 8 horizontal pixels (MSB = leftmost).
    //
    // Layout for glyph with width=10, height=16:
    //   Bytes 0-15:  byte-column 0, rows 0-15 (pixels 0-7 of each row)
    //   Bytes 16-31: byte-column 1, rows 0-15 (pixels 8-9 of each row, padded)
    //
    const uint8_t* src_bitmap = data.data() + bits_offset;

    result.glyphs.reserve(num_glyphs);
    result.bitmap_data.clear();

    for (size_t g = 0; g < num_glyphs; g++) {
        uint16_t px_offset = pixel_offsets[g];
        uint16_t width = glyph_widths[g];

        glyph_entry ge;
        ge.width = width;
        ge.offset = result.bitmap_data.size();  // Offset into our converted bitmap_data
        result.glyphs.push_back(ge);

        // Calculate number of byte-columns (ceil(width / 8))
        uint16_t byte_cols = (width + 7) / 8;

        // For each byte-column
        for (uint16_t bc = 0; bc < byte_cols; bc++) {
            // For each row
            for (uint16_t row = 0; row < height; row++) {
                uint8_t dest_byte = 0;

                // Pack 8 horizontal pixels into this byte
                for (uint8_t bit = 0; bit < 8; bit++) {
                    uint16_t pixel_x = bc * 8 + bit;
                    if (pixel_x >= width) break;  // Past glyph width

                    uint16_t src_pixel_x = px_offset + pixel_x;

                    // Find the pixel in source row-major bitmap
                    // Source format: row y starts at row * row_bytes
                    // Pixel x is at byte (x / 8), bit (7 - x % 8) within that byte (MSB = leftmost)
                    size_t src_byte_offset = static_cast<size_t>(row) * row_bytes + src_pixel_x / 8;
                    uint8_t src_bit_pos = 7 - (src_pixel_x % 8);

                    if (src_byte_offset < bitmap_size) {
                        uint8_t src_byte = src_bitmap[src_byte_offset];
                        if ((src_byte >> src_bit_pos) & 1) {
                            // Set bit in dest byte (MSB = leftmost)
                            dest_byte |= (1 << (7 - bit));
                        }
                    }
                }
                result.bitmap_data.push_back(dest_byte);
            }
        }
    }

    return result;
}

// Parse Windows 1.x vector font (manually, no DataScript)
std::optional<font_data> parse_font_1x_vector(std::span<const uint8_t> data) {
    // FNT 1.x header is 117 bytes
    if (data.size() < 117) {
        return std::nullopt;
    }

    const uint8_t* ptr = data.data();

    font_data result;

    // Metadata
    result.version = read_u16(ptr + 0);
    result.size = read_u32(ptr + 2);
    result.copyright = extract_string(ptr + 6, 60);
    result.type = static_cast<font_type>(read_u16(ptr + 66));

    // Check this is actually a vector font
    if ((static_cast<uint16_t>(result.type) & 0x0001) == 0) {
        return std::nullopt;  // Not a vector font
    }

    // Metrics
    result.points = read_u16(ptr + 68);
    result.vertical_res = read_u16(ptr + 70);
    result.horizontal_res = read_u16(ptr + 72);
    result.ascent = read_u16(ptr + 74);
    result.internal_leading = read_u16(ptr + 76);
    result.external_leading = read_u16(ptr + 78);

    // Appearance
    result.italic = ptr[80] != 0;
    result.underline = ptr[81] != 0;
    result.strikeout = ptr[82] != 0;
    result.weight = read_u16(ptr + 83);
    result.charset = ptr[85];

    // Dimensions
    result.pixel_width = read_u16(ptr + 86);
    result.pixel_height = read_u16(ptr + 88);
    uint8_t pitch_and_family = ptr[90];
    result.avg_width = read_u16(ptr + 91);
    result.max_width = read_u16(ptr + 93);

    // Character range
    result.first_char = ptr[95];
    result.last_char = ptr[96];
    result.default_char = ptr[97];
    result.break_char = ptr[98];

    // Width bytes (not used for vector fonts)
    result.width_bytes = read_u16(ptr + 99);

    // Device and face name offsets
    uint32_t face_offset = read_u32(ptr + 105);
    uint32_t bits_offset = read_u32(ptr + 113);

    // Pitch and family
    result.pitch = static_cast<font_pitch>(pitch_and_family & 0x0F);
    result.family = static_cast<font_family>(pitch_and_family & 0xF0);

    // Face name
    result.face_name = read_string_at_offset(data, face_offset);

    // Parse glyph table (starts at offset 117)
    // Windows 1.x vector font glyph table format:
    // - Fixed-pitch (dfPixWidth != 0): 2-byte entries (offset only)
    // - Variable-pitch (dfPixWidth == 0): 4-byte entries (offset + width)
    size_t num_glyphs = result.last_char - result.first_char + 1;
    size_t glyph_table_start = 117;

    // Parse glyph entries and decode stroke data
    result.vector_glyphs.reserve(num_glyphs);
    result.glyphs.reserve(num_glyphs);

    if (result.pixel_width != 0) {
        // Fixed-pitch vector font: 2-byte entries (offset only)
        size_t glyph_table_size = (num_glyphs + 1) * 2;  // +1 for sentinel

        if (glyph_table_start + glyph_table_size > data.size()) {
            return std::nullopt;
        }

        // Read all offsets including sentinel
        std::vector<uint16_t> offsets;
        offsets.reserve(num_glyphs + 1);
        for (size_t i = 0; i <= num_glyphs; i++) {
            size_t entry_offset = glyph_table_start + i * 2;
            offsets.push_back(read_u16(ptr + entry_offset));
        }

        for (size_t i = 0; i < num_glyphs; i++) {
            uint16_t stroke_offset = offsets[i];
            uint16_t next_stroke_offset = offsets[i + 1];

            // Store basic glyph info
            glyph_entry ge;
            ge.width = result.pixel_width;  // Fixed width
            ge.offset = stroke_offset;
            result.glyphs.push_back(ge);

            // Decode stroke data
            vector_glyph vg;
            vg.width = result.pixel_width;

            size_t abs_offset = bits_offset + stroke_offset;
            size_t abs_next = bits_offset + next_stroke_offset;

            if (abs_offset < data.size() && abs_next <= data.size() && abs_next > abs_offset) {
                size_t stroke_len = abs_next - abs_offset;
                vg.strokes = decode_strokes(ptr + abs_offset, stroke_len);
            }

            result.vector_glyphs.push_back(std::move(vg));
        }
    } else {
        // Variable-pitch vector font: 4-byte entries (offset + width)
        size_t glyph_table_size = (num_glyphs + 1) * 4;  // +1 for sentinel

        if (glyph_table_start + glyph_table_size > data.size()) {
            return std::nullopt;
        }

        for (size_t i = 0; i < num_glyphs; i++) {
            size_t entry_offset = glyph_table_start + i * 4;
            uint16_t stroke_offset = read_u16(ptr + entry_offset);
            uint16_t glyph_width = read_u16(ptr + entry_offset + 2);

            // Get next glyph's offset to determine stroke data length
            uint16_t next_stroke_offset = read_u16(ptr + entry_offset + 4);

            // Store basic glyph info
            glyph_entry ge;
            ge.width = glyph_width;
            ge.offset = stroke_offset;
            result.glyphs.push_back(ge);

            // Decode stroke data
            vector_glyph vg;
            vg.width = glyph_width;

            size_t abs_offset = bits_offset + stroke_offset;
            size_t abs_next = bits_offset + next_stroke_offset;

            if (abs_offset < data.size() && abs_next <= data.size() && abs_next > abs_offset) {
                size_t stroke_len = abs_next - abs_offset;
                vg.strokes = decode_strokes(ptr + abs_offset, stroke_len);
            }

            result.vector_glyphs.push_back(std::move(vg));
        }
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
    result.width_bytes = ds_font.width_bytes;

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

    // Find the minimum glyph offset to determine bits_start
    // In 2.x fonts, glyph offsets are absolute from start of font file
    uint32_t bits_start = UINT32_MAX;
    for (const auto& ds_glyph : ds_font.glyphs) {
        if (ds_glyph.offset > 0 && ds_glyph.offset < bits_start) {
            bits_start = ds_glyph.offset;
        }
    }

    // Convert glyph table from DataScript, making offsets relative to bits_start
    result.glyphs.reserve(ds_font.glyphs.size());
    for (const auto& ds_glyph : ds_font.glyphs) {
        glyph_entry glyph;
        glyph.width = ds_glyph.width;
        // Make offset relative to bitmap_data start
        glyph.offset = (bits_start != UINT32_MAX && ds_glyph.offset >= bits_start)
                       ? (ds_glyph.offset - bits_start) : 0;
        result.glyphs.push_back(glyph);
    }

    // Bitmap data: copy from bits_start to end of file
    if (bits_start != UINT32_MAX && bits_start < data.size()) {
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
    result.width_bytes = ds_font.width_bytes;

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

    // For 3.x fonts, use bits_offset from header as the base for bitmap data
    uint32_t bits_start = ds_font.bits_offset;

    // Convert glyph table from DataScript, making offsets relative to bits_offset
    result.glyphs.reserve(ds_font.glyphs.size());
    for (const auto& ds_glyph : ds_font.glyphs) {
        glyph_entry glyph;
        glyph.width = ds_glyph.width;
        // Make offset relative to bitmap_data start
        glyph.offset = (ds_glyph.offset >= bits_start)
                       ? (ds_glyph.offset - bits_start) : 0;
        result.glyphs.push_back(glyph);
    }

    // Bitmap data starts at bits_offset
    if (bits_start < data.size()) {
        const uint8_t* bitmap_start = data.data() + bits_start;
        size_t bitmap_size = data.size() - bits_start;
        result.bitmap_data.assign(bitmap_start, bitmap_start + bitmap_size);
    }

    return result;
}

} // anonymous namespace

std::optional<font_data> font_parser::parse(std::span<const uint8_t> data) {
    // Minimum size check (header is 117 bytes for 1.x, 118 for 2.x/3.x)
    if (data.size() < 117) {
        return std::nullopt;
    }

    try {
        // Check version to determine which parser to use
        uint16_t version = static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);

        if (version == 0x0100) {
            // Windows 1.x format - check if it's a vector or raster font
            uint16_t font_type = static_cast<uint16_t>(data[66]) | (static_cast<uint16_t>(data[67]) << 8);
            if ((font_type & 0x0001) != 0) {
                return parse_font_1x_vector(data);
            } else {
                return parse_font_1x_raster(data);
            }
        }

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

    // Calculate bitmap size for column-major format:
    // Each column is ceil(pixel_height / 8) bytes
    // Total size is width * bytes_per_column
    size_t bytes_per_column = (pixel_height + 7) / 8;
    size_t bitmap_size = glyph.width * bytes_per_column;

    // Glyph offset is now relative to bitmap_data start
    if (glyph.offset + bitmap_size > bitmap_data.size()) {
        return {};
    }

    return std::span<const uint8_t>(
        bitmap_data.data() + glyph.offset,
        bitmap_size
    );
}

} // namespace libexe
