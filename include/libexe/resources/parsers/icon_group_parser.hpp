#ifndef LIBEXE_ICON_GROUP_PARSER_HPP
#define LIBEXE_ICON_GROUP_PARSER_HPP

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
 * Represents a single icon entry within an icon group.
 *
 * This corresponds to GRPICONDIRENTRY in Win32 resource format.
 * Each entry describes one icon image (width, height, colors, etc.)
 * and references the actual icon bitmap by resource ID.
 */
struct LIBEXE_EXPORT icon_directory_entry {
    uint8_t width;           // Width in pixels (0 means 256)
    uint8_t height;          // Height in pixels (0 means 256)
    uint8_t color_count;     // Number of colors (0 if >= 8bpp)
    uint8_t reserved;        // Reserved, must be 0
    uint16_t planes;         // Color planes
    uint16_t bit_count;      // Bits per pixel
    uint32_t size_in_bytes;  // Size of icon image data
    uint16_t resource_id;    // Resource ID for this icon (RT_ICON)

    /**
     * Get actual width (handles 0 = 256 special case)
     */
    [[nodiscard]] uint16_t actual_width() const {
        return width == 0 ? 256 : width;
    }

    /**
     * Get actual height (handles 0 = 256 special case)
     */
    [[nodiscard]] uint16_t actual_height() const {
        return height == 0 ? 256 : height;
    }
};

/**
 * Represents an icon group resource (RT_GROUP_ICON).
 *
 * Icon groups contain metadata about a set of icon images.
 * The actual pixel data is stored in separate RT_ICON resources,
 * referenced by resource_id in each icon_directory_entry.
 *
 * This is the standard Windows .ICO file format when embedded in
 * executable resources.
 */
struct LIBEXE_EXPORT icon_group {
    uint16_t reserved;       // Reserved, currently 0
    uint16_t type;           // Resource type: 1 for cursors, 2 for icons
    uint16_t count;          // Number of images in group
    std::vector<icon_directory_entry> entries;  // Directory entries

    /**
     * Check if this is an icon group (type == 2)
     */
    [[nodiscard]] bool is_icon() const {
        return type == 2;
    }

    /**
     * Check if this is a cursor group (type == 1)
     */
    [[nodiscard]] bool is_cursor() const {
        return type == 1;
    }
};

/**
 * Parser for RT_GROUP_ICON resources.
 *
 * Parses icon group structures from Windows executable resources.
 * The icon group contains metadata about available icon sizes/formats,
 * with references to the actual pixel data in RT_ICON resources.
 *
 * Example:
 * @code
 * auto entry = resources->find_resource(resource_type::RT_GROUP_ICON, 1);
 * if (entry.has_value()) {
 *     auto icon_grp = icon_group_parser::parse(entry->data());
 *     if (icon_grp.has_value()) {
 *         for (const auto& icon_entry : icon_grp->entries) {
 *             std::cout << "Icon " << icon_entry.resource_id
 *                       << ": " << icon_entry.actual_width()
 *                       << "x" << icon_entry.actual_height() << "\n";
 *         }
 *     }
 * }
 * @endcode
 */
class LIBEXE_EXPORT icon_group_parser {
public:
    /**
     * Parse an icon group resource.
     *
     * @param data Raw resource data from RT_GROUP_ICON resource
     * @return Parsed icon group on success, std::nullopt on parse error
     */
    [[nodiscard]] static std::optional<icon_group> parse(std::span<const uint8_t> data);
};

} // namespace libexe

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // LIBEXE_ICON_GROUP_PARSER_HPP
