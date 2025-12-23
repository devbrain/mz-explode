#ifndef LIBEXE_BITMAP_PARSER_HPP
#define LIBEXE_BITMAP_PARSER_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <span>
#include <vector>
#include <optional>

// Disable MSVC warning C4251: 'member': class 'std::...' needs to have dll-interface
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

namespace libexe {

/**
 * Bitmap compression types
 */
enum class bitmap_compression : uint32_t {
    RGB       = 0,  // Uncompressed RGB
    RLE8      = 1,  // 8-bit RLE compression
    RLE4      = 2,  // 4-bit RLE compression
    BITFIELDS = 3,  // Uncompressed RGB with color masks
    JPEG      = 4,  // JPEG compression (not typically in DIB)
    PNG       = 5   // PNG compression (not typically in DIB)
};

/**
 * RGB color quad (BGRA format)
 */
struct LIBEXE_EXPORT rgb_quad {
    uint8_t blue;       // Blue component (0-255)
    uint8_t green;      // Green component (0-255)
    uint8_t red;        // Red component (0-255)
    uint8_t reserved;   // Reserved (must be 0)
};

/**
 * Bitmap information header (Windows 3.0+ format)
 */
struct LIBEXE_EXPORT bitmap_info {
    uint32_t header_size;           // Structure size (40 bytes)
    int32_t width;                  // Image width in pixels
    int32_t height;                 // Image height (positive=bottom-up, negative=top-down)
    uint16_t planes;                // Color planes (must be 1)
    uint16_t bit_count;             // Bits per pixel (1, 4, 8, 16, 24, 32)
    bitmap_compression compression; // Compression type
    uint32_t size_image;            // Image size in bytes (may be 0 for RGB)
    int32_t x_pels_per_meter;       // Horizontal resolution
    int32_t y_pels_per_meter;       // Vertical resolution
    uint32_t clr_used;              // Colors in palette (0 = use maximum)
    uint32_t clr_important;         // Important colors (0 = all important)

    /**
     * Get number of colors in palette
     */
    [[nodiscard]] uint32_t palette_size() const {
        if (clr_used > 0) {
            return clr_used;
        }
        if (bit_count <= 8) {
            return 1u << bit_count;  // 2^bit_count
        }
        return 0;  // No palette for > 8bpp
    }

    /**
     * Check if image is top-down (negative height)
     */
    [[nodiscard]] bool is_top_down() const {
        return height < 0;
    }

    /**
     * Get absolute height
     */
    [[nodiscard]] uint32_t abs_height() const {
        return static_cast<uint32_t>(height < 0 ? -height : height);
    }
};

/**
 * Bitmap data (parsed from RT_BITMAP resource)
 */
struct LIBEXE_EXPORT bitmap_data {
    bitmap_info info;                   // Bitmap info header
    std::vector<rgb_quad> palette;      // Color palette (if bit_count <= 8)
    std::vector<uint8_t> pixel_data;    // Raw pixel data

    /**
     * Get row size in bytes (including padding to DWORD boundary)
     */
    [[nodiscard]] uint32_t row_size() const {
        uint32_t bits_per_row = static_cast<uint32_t>(info.width) * info.bit_count;
        return (bits_per_row + 31) / 32 * 4;  // Round up to DWORD
    }

    /**
     * Check if bitmap has palette
     */
    [[nodiscard]] bool has_palette() const {
        return !palette.empty();
    }
};

/**
 * Parser for RT_BITMAP resources.
 *
 * Parses Windows Device Independent Bitmap (DIB) format from executable resources.
 * Note: RT_BITMAP does NOT include the BITMAPFILEHEADER (that's only in .BMP files).
 *
 * Supports:
 * - BITMAPINFOHEADER (40 bytes) - Windows 3.0+ format
 * - BITMAPCOREHEADER (12 bytes) - OS/2 1.x format
 * - Various bit depths: 1, 4, 8, 16, 24, 32 bpp
 * - Uncompressed RGB, RLE4, RLE8 compression
 *
 * Example:
 * @code
 * auto bitmap_resources = resources->resources_by_type(resource_type::RT_BITMAP);
 * if (!bitmap_resources.empty()) {
 *     auto bmp = bitmap_parser::parse(bitmap_resources[0].data());
 *     if (bmp.has_value()) {
 *         std::cout << "Bitmap: " << bmp->info.width << "x" << bmp->info.abs_height()
 *                   << " (" << bmp->info.bit_count << " bpp)\n";
 *         if (bmp->has_palette()) {
 *             std::cout << "Palette: " << bmp->palette.size() << " colors\n";
 *         }
 *     }
 * }
 * @endcode
 */
class LIBEXE_EXPORT bitmap_parser {
public:
    /**
     * Parse a bitmap resource.
     *
     * @param data Raw resource data from RT_BITMAP resource
     * @return Parsed bitmap data on success, std::nullopt on parse error
     */
    [[nodiscard]] static std::optional<bitmap_data> parse(std::span<const uint8_t> data);
};

} // namespace libexe

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // LIBEXE_BITMAP_PARSER_HPP
