#ifndef LIBEXE_MENU_PARSER_HPP
#define LIBEXE_MENU_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/resources/resource.hpp>
#include <cstdint>
#include <span>
#include <vector>
#include <optional>
#include <string>

namespace libexe {

/**
 * Menu item flags (MF_* constants).
 *
 * These flags determine the appearance and behavior of menu items.
 * The MF_POPUP flag distinguishes popup menus from normal command items.
 * The MF_END flag marks the last item at each nesting level.
 */
enum class menu_flags : uint16_t {
    GRAYED       = 0x0001,  // Item is inactive and grayed out
    INACTIVE     = 0x0002,  // Item is inactive (same as GRAYED)
    BITMAP       = 0x0004,  // Item displays a bitmap
    CHECKED      = 0x0008,  // Item has a checkmark
    POPUP        = 0x0010,  // Item is a popup submenu
    MENUBARBREAK = 0x0020,  // New column with vertical separator
    MENUBREAK    = 0x0040,  // New column without separator
    END          = 0x0080,  // Last item in popup level
    OWNERDRAW    = 0x0100   // Owner-drawn item
};

/**
 * Single menu item (either popup or normal command item).
 *
 * A menu item can be one of:
 * - Popup menu: Has children, no command ID
 * - Normal item: Has command ID, no children
 * - Separator: Empty text, command ID = 0, flags = 0
 */
struct LIBEXE_EXPORT menu_item {
    uint16_t flags = 0;              // Menu flags (menu_flags enum)
    uint16_t command_id = 0;         // Command ID (0 for popup/separator)
    std::string text;                // Menu text (empty for separator)
    std::vector<menu_item> children; // Child items (for popup menus)

    /**
     * Check if this is a popup menu item.
     */
    [[nodiscard]] bool is_popup() const {
        return (flags & static_cast<uint16_t>(menu_flags::POPUP)) != 0;
    }

    /**
     * Check if this is a separator.
     */
    [[nodiscard]] bool is_separator() const {
        return text.empty() && command_id == 0 && flags == 0;
    }

    /**
     * Check if this item is grayed out.
     */
    [[nodiscard]] bool is_grayed() const {
        return (flags & static_cast<uint16_t>(menu_flags::GRAYED)) != 0;
    }

    /**
     * Check if this item is checked.
     */
    [[nodiscard]] bool is_checked() const {
        return (flags & static_cast<uint16_t>(menu_flags::CHECKED)) != 0;
    }

    /**
     * Check if this is the last item at its level.
     */
    [[nodiscard]] bool is_end() const {
        return (flags & static_cast<uint16_t>(menu_flags::END)) != 0;
    }
};

/**
 * Menu template (RT_MENU resource).
 *
 * Represents a complete menu hierarchy from a Windows executable.
 * The menu is stored as a flat list of top-level items, where each
 * popup item contains its children recursively.
 */
struct LIBEXE_EXPORT menu_template {
    uint16_t version = 0;       // Menu version (usually 0)
    uint16_t header_size = 0;   // Header size (usually 0)
    std::vector<menu_item> items; // Top-level menu items

    /**
     * Count total number of items recursively.
     */
    [[nodiscard]] size_t count_all_items() const {
        size_t count = items.size();
        for (const auto& item : items) {
            count += count_items_recursive(item);
        }
        return count;
    }

private:
    static size_t count_items_recursive(const menu_item& item) {
        size_t count = item.children.size();
        for (const auto& child : item.children) {
            count += count_items_recursive(child);
        }
        return count;
    }
};

/**
 * Parser for RT_MENU resources (Windows formats only).
 *
 * Parses menu templates from Windows executables.
 * PE uses UTF-16 strings, NE Windows uses ANSI strings.
 *
 * For OS/2 menus (NE OS/2, LE, LX), use parse_os2_menu() from
 * os2_resource_parser.hpp instead, as OS/2 menus have a completely
 * different binary structure.
 *
 * Example:
 * @code
 * auto menu_resources = resources->resources_by_type(resource_type::RT_MENU);
 * if (!menu_resources.empty()) {
 *     auto menu = menu_parser::parse(menu_resources[0].data(), windows_resource_format::PE);
 *     if (menu.has_value()) {
 *         for (const auto& item : menu->items) {
 *             std::cout << "Menu: " << item.text << "\n";
 *             if (item.is_popup()) {
 *                 for (const auto& child : item.children) {
 *                     std::cout << "  Item: " << child.text << "\n";
 *                 }
 *             }
 *         }
 *     }
 * }
 * @endcode
 */
class LIBEXE_EXPORT menu_parser {
public:
    /**
     * Parse a Windows menu template resource.
     *
     * Uses the specified format discriminator to select the correct
     * string encoding (UTF-16 for PE, ANSI for NE).
     *
     * @param data Raw resource data from RT_MENU resource
     * @param format Windows resource format (PE or NE)
     * @return Parsed menu template on success, std::nullopt on parse error
     *
     * @note For OS/2 menus (NE OS/2, LE, LX), use parse_os2_menu() from
     *       os2_resource_parser.hpp instead.
     */
    static std::optional<menu_template> parse(std::span<const uint8_t> data, windows_resource_format format);
};

} // namespace libexe

#endif // LIBEXE_MENU_PARSER_HPP
