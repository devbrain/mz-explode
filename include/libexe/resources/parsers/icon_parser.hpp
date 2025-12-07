#ifndef LIBEXE_ICON_PARSER_HPP
#define LIBEXE_ICON_PARSER_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <span>
#include <vector>
#include <optional>

namespace libexe {

/**
 * DIB (Device Independent Bitmap) header.
 *
 * Icons are stored as DIB format (bitmap without file header).
 * This is the BITMAPINFOHEADER structure.
 */
struct LIBEXE_EXPORT dib_header {
    uint32_t size;              // Size of this header (40 bytes)
    int32_t width;              // Image width in pixels
    int32_t height;             // Image height in pixels (includes AND mask)
    uint16_t planes;            // Number of color planes (always 1)
    uint16_t bit_count;         // Bits per pixel
    uint32_t compression;       // Compression method (0 = BI_RGB)
    uint32_t size_image;        // Image size in bytes (can be 0 for BI_RGB)
    int32_t x_pels_per_meter;   // Horizontal resolution
    int32_t y_pels_per_meter;   // Vertical resolution
    uint32_t clr_used;          // Number of colors in color table
    uint32_t clr_important;     // Number of important colors

    /**
     * Get actual height of XOR bitmap (excluding AND mask).
     * Icon height is typically doubled to include AND mask.
     */
    [[nodiscard]] uint32_t xor_height() const {
        return static_cast<uint32_t>(height / 2);
    }

    /**
     * Get color table size in bytes.
     */
    [[nodiscard]] uint32_t color_table_size() const {
        if (bit_count > 8) {
            return 0;  // No color table for >8bpp
        }
        uint32_t num_colors = clr_used;
        if (num_colors == 0) {
            num_colors = 1U << bit_count;  // 2^bit_count
        }
        return num_colors * 4;  // Each entry is 4 bytes (RGBQUAD)
    }
};

/**
 * RGBQUAD color table entry.
 */
struct LIBEXE_EXPORT rgb_quad {
    uint8_t blue;
    uint8_t green;
    uint8_t red;
    uint8_t reserved;
};

/**
 * Represents an icon image resource (RT_ICON).
 *
 * Icons are stored in DIB (Device Independent Bitmap) format.
 * The structure is:
 * - BITMAPINFOHEADER (40 bytes)
 * - Color table (for <= 8bpp images)
 * - XOR mask (color bitmap data)
 * - AND mask (transparency bitmap)
 *
 * Note: The icon does NOT have a BITMAPFILEHEADER (14 bytes) that
 * standalone .ICO files have. This class provides a method to export
 * to standalone .ICO format.
 */
struct LIBEXE_EXPORT icon_image {
    dib_header header;
    std::vector<rgb_quad> color_table;
    std::vector<uint8_t> xor_mask;  // Color bitmap data
    std::vector<uint8_t> and_mask;  // Transparency mask

    /**
     * Get raw DIB data (for upper layers to convert to PNG, etc.)
     *
     * Returns the complete DIB data: header + color table + XOR mask.
     * This is NOT a standalone .ICO file (missing file header).
     */
    [[nodiscard]] std::vector<uint8_t> raw_dib_data() const;

    /**
     * Export to standalone .ICO file format.
     *
     * Adds the ICONDIR and ICONDIRENTRY structures plus
     * BITMAPFILEHEADER to make a valid .ICO file.
     *
     * Note: This creates a single-icon .ICO file. For multi-icon
     * files, use icon_group and combine multiple icon_images.
     *
     * @return Complete .ICO file data ready to write to disk
     */
    [[nodiscard]] std::vector<uint8_t> to_ico_file() const;
};

/**
 * Parser for RT_ICON resources.
 *
 * Parses individual icon images (DIB format) from Windows executable resources.
 * The actual pixel data for icons referenced by RT_GROUP_ICON.
 *
 * Example:
 * @code
 * // Find icon group and get first icon's resource ID
 * auto group = icon_group_parser::parse(group_entry->data());
 * uint16_t icon_id = group->entries[0].resource_id;
 *
 * // Parse the icon image
 * auto icon_entry = resources->find_resource(resource_type::RT_ICON, icon_id);
 * if (icon_entry.has_value()) {
 *     auto icon = icon_parser::parse(icon_entry->data());
 *     if (icon.has_value()) {
 *         // Export to .ICO file
 *         auto ico_data = icon->to_ico_file();
 *         // Write ico_data to file or convert to PNG...
 *     }
 * }
 * @endcode
 */
class LIBEXE_EXPORT icon_parser {
public:
    /**
     * Parse an icon image resource.
     *
     * @param data Raw resource data from RT_ICON resource
     * @return Parsed icon image on success, std::nullopt on parse error
     */
    static std::optional<icon_image> parse(std::span<const uint8_t> data);
};

} // namespace libexe

#endif // LIBEXE_ICON_PARSER_HPP
