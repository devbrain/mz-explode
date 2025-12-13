#ifndef LIBEXE_FONT_PARSER_HPP
#define LIBEXE_FONT_PARSER_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <span>
#include <vector>
#include <string>
#include <optional>

namespace libexe {

/**
 * Font type enumeration (Windows 2.x/3.x raster fonts)
 */
enum class font_type : uint16_t {
    RASTER = 0x0000,      // Bitmap (raster) font
    VECTOR = 0x0001,      // Vector font (not supported in resources)
    MEMORY = 0x0004 | 0x0080,  // Memory font
    DEVICE = 0x0002       // Device font
};

/**
 * Font family enumeration
 */
enum class font_family : uint8_t {
    DONTCARE = 0x00,
    ROMAN = 0x10,         // Times Roman, Century Schoolbook, etc.
    SWISS = 0x20,         // Helvetica, Swiss, etc.
    MODERN = 0x30,        // Courier, Pica, Elite, etc.
    SCRIPT = 0x40,        // Script, Cursive, etc.
    DECORATIVE = 0x50     // Old English, ITC Zapf Dingbats, etc.
};

/**
 * Font pitch enumeration
 */
enum class font_pitch : uint8_t {
    DEFAULT = 0x00,
    FIXED = 0x01,         // Fixed-pitch font (all chars same width)
    VARIABLE = 0x02       // Variable-pitch font
};

/**
 * Single glyph entry in a font.
 *
 * Provides access to glyph width and offset into bitmap data.
 * Different Windows font versions use different glyph entry formats.
 */
struct LIBEXE_EXPORT glyph_entry {
    uint16_t width;       // Character width in pixels
    uint32_t offset;      // Offset into bitmap/stroke data

    // Optional ABC spacing (Windows 3.0+)
    std::optional<int16_t> a_space;  // Distance from current position to left edge
    std::optional<uint16_t> b_space; // Width of character
    std::optional<int16_t> c_space;  // Distance from right edge to next position
};

/**
 * Stroke command for vector fonts.
 *
 * Vector fonts store glyphs as a series of pen movements.
 * Each command is either a move/line to a point, or a pen-up marker.
 */
struct LIBEXE_EXPORT stroke_command {
    enum class type : uint8_t {
        MOVE_TO,    // Move to point without drawing (first point or after pen-up)
        LINE_TO,    // Draw line to point
        PEN_UP      // Lift pen (end of polyline segment)
    };

    type cmd;
    int8_t x;     // X coordinate (relative or absolute depending on context)
    int8_t y;     // Y coordinate
};

/**
 * Vector glyph entry.
 *
 * Contains the stroke data for a single vector glyph.
 */
struct LIBEXE_EXPORT vector_glyph {
    uint16_t width;                        // Character width
    std::vector<stroke_command> strokes;   // Stroke commands for this glyph
};

/**
 * Windows 2.x/3.x raster font data (RT_FONT).
 *
 * Represents a bitmap font resource from Windows executables.
 * These fonts are stored in the .FNT file format embedded as resources.
 *
 * The font contains:
 * - Header with font metrics (size, resolution, character range)
 * - Glyph table mapping characters to bitmap offsets
 * - Bitmap data for all characters
 * - Face name string
 *
 * Note: This parser extracts and structures the font data.
 * Actual rendering (converting to modern formats like TTF/OTF/PNG)
 * is the responsibility of upper layers.
 */
struct LIBEXE_EXPORT font_data {
    // =========================================================================
    // Font Metadata
    // =========================================================================

    uint16_t version;             // Font version (0x0200 = Windows 2.x, 0x0300 = Windows 3.0)
    uint32_t size;                // Total font file size
    std::string copyright;        // Copyright string (up to 60 chars)
    font_type type;               // Font type (raster, vector, etc.)

    // =========================================================================
    // Font Metrics
    // =========================================================================

    uint16_t points;              // Nominal point size
    uint16_t vertical_res;        // Vertical resolution (DPI)
    uint16_t horizontal_res;      // Horizontal resolution (DPI)
    uint16_t ascent;              // Distance from baseline to top
    uint16_t internal_leading;    // Accent marks space
    uint16_t external_leading;    // Line spacing

    // =========================================================================
    // Font Appearance
    // =========================================================================

    bool italic;                  // Italic font
    bool underline;               // Underlined font
    bool strikeout;               // Strikeout font
    uint16_t weight;              // Font weight (100-900, 400=normal, 700=bold)
    uint8_t charset;              // Character set

    // =========================================================================
    // Character Dimensions
    // =========================================================================

    uint16_t pixel_width;         // Character width (0 = variable-pitch)
    uint16_t pixel_height;        // Character height
    uint16_t avg_width;           // Average character width
    uint16_t max_width;           // Maximum character width
    uint16_t width_bytes;         // Bytes per row of the combined bitmap

    // =========================================================================
    // Character Range
    // =========================================================================

    uint8_t first_char;           // First character code in font
    uint8_t last_char;            // Last character code in font
    uint8_t default_char;         // Default character (for missing chars)
    uint8_t break_char;           // Break character (usually space)

    // =========================================================================
    // Font Family & Pitch
    // =========================================================================

    font_pitch pitch;             // Fixed or variable pitch
    font_family family;           // Font family
    std::string face_name;        // Font face name (e.g., "Courier", "Helv")

    // =========================================================================
    // Glyph Data (Raster fonts)
    // =========================================================================

    std::vector<glyph_entry> glyphs;    // Glyph table (one per character)
    std::vector<uint8_t> bitmap_data;   // Raw bitmap data for all characters

    // =========================================================================
    // Glyph Data (Vector fonts)
    // =========================================================================

    std::vector<vector_glyph> vector_glyphs;  // Vector glyph data (when type == VECTOR)

    /**
     * Get character count in font.
     */
    [[nodiscard]] size_t character_count() const {
        return static_cast<size_t>(last_char) - static_cast<size_t>(first_char) + 1;
    }

    /**
     * Check if font is fixed-pitch (monospace).
     */
    [[nodiscard]] bool is_fixed_pitch() const {
        return pitch == font_pitch::FIXED;
    }

    /**
     * Check if font is variable-pitch (proportional).
     */
    [[nodiscard]] bool is_variable_pitch() const {
        return pitch == font_pitch::VARIABLE;
    }

    /**
     * Check if this is a vector (stroke) font.
     */
    [[nodiscard]] bool is_vector() const {
        return (static_cast<uint16_t>(type) & 0x0001) != 0;
    }

    /**
     * Check if this is a raster (bitmap) font.
     */
    [[nodiscard]] bool is_raster() const {
        return !is_vector();
    }

    /**
     * Get vector glyph for a specific character.
     *
     * @param c Character code
     * @return Pointer to vector glyph, or nullptr if not found or not a vector font
     */
    [[nodiscard]] const vector_glyph* get_vector_glyph(uint8_t c) const {
        if (!is_vector() || c < first_char || c > last_char) {
            return nullptr;
        }
        size_t idx = c - first_char;
        if (idx >= vector_glyphs.size()) {
            return nullptr;
        }
        return &vector_glyphs[idx];
    }

    /**
     * Get bitmap data for a specific character.
     *
     * @param c Character code
     * @return Span of bitmap data, or empty span if character not in font
     */
    [[nodiscard]] std::span<const uint8_t> get_char_bitmap(uint8_t c) const;
};

/**
 * Parser for RT_FONT resources.
 *
 * Parses Windows 2.x/3.x raster font (.FNT) format from resources.
 * Supports both Windows 2.x and Windows 3.0 font formats.
 *
 * Example:
 * @code
 * auto font_entry = resources->find_resource(resource_type::RT_FONT, 1);
 * if (font_entry.has_value()) {
 *     auto font = font_parser::parse(font_entry->data());
 *     if (font.has_value()) {
 *         std::cout << "Font: " << font->face_name << "\n";
 *         std::cout << "Size: " << font->points << " pt\n";
 *         std::cout << "Chars: " << static_cast<int>(font->first_char)
 *                   << "-" << static_cast<int>(font->last_char) << "\n";
 *
 *         // Get bitmap for letter 'A'
 *         auto bitmap = font->get_char_bitmap('A');
 *         // ... render or convert to PNG ...
 *     }
 * }
 * @endcode
 */
class LIBEXE_EXPORT font_parser {
public:
    /**
     * Parse a font resource.
     *
     * @param data Raw resource data from RT_FONT resource
     * @return Parsed font data on success, std::nullopt on parse error
     */
    [[nodiscard]] static std::optional<font_data> parse(std::span<const uint8_t> data);
};

} // namespace libexe

#endif // LIBEXE_FONT_PARSER_HPP
