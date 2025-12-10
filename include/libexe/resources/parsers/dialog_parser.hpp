#ifndef LIBEXE_DIALOG_PARSER_HPP
#define LIBEXE_DIALOG_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/resources/resource.hpp>
#include <cstdint>
#include <span>
#include <vector>
#include <optional>
#include <string>
#include <variant>

namespace libexe {

/**
 * Dialog box styles (DS_* flags).
 * These are combined with WS_* window styles in the style field.
 */
namespace dialog_style {
    // DS_* Dialog-specific styles (low bits)
    constexpr uint32_t DS_ABSALIGN      = 0x0001;  // Absolute alignment
    constexpr uint32_t DS_SYSMODAL      = 0x0002;  // System modal (obsolete)
    constexpr uint32_t DS_3DLOOK        = 0x0004;  // 3D look (obsolete)
    constexpr uint32_t DS_FIXEDSYS      = 0x0008;  // Use SYSTEM_FIXED_FONT
    constexpr uint32_t DS_NOFAILCREATE  = 0x0010;  // Don't fail on errors
    constexpr uint32_t DS_LOCALEDIT     = 0x0020;  // Local edit controls
    constexpr uint32_t DS_SETFONT       = 0x0040;  // Custom font specified
    constexpr uint32_t DS_MODALFRAME    = 0x0080;  // Modal frame
    constexpr uint32_t DS_NOIDLEMSG     = 0x0100;  // No WM_ENTERIDLE
    constexpr uint32_t DS_SETFOREGROUND = 0x0200;  // Bring to foreground
    constexpr uint32_t DS_CONTROL       = 0x0400;  // Child dialog
    constexpr uint32_t DS_CENTER        = 0x0800;  // Center on screen
    constexpr uint32_t DS_CENTERMOUSE   = 0x1000;  // Center on mouse
    constexpr uint32_t DS_CONTEXTHELP   = 0x2000;  // Context help button
    constexpr uint32_t DS_SHELLFONT     = 0x0048;  // DS_SETFONT | DS_FIXEDSYS

    // WS_* Window styles (high bits, commonly used with dialogs)
    constexpr uint32_t WS_POPUP         = 0x80000000;  // Popup window
    constexpr uint32_t WS_CHILD         = 0x40000000;  // Child window
    constexpr uint32_t WS_MINIMIZE      = 0x20000000;  // Minimized
    constexpr uint32_t WS_VISIBLE       = 0x10000000;  // Visible
    constexpr uint32_t WS_DISABLED      = 0x08000000;  // Disabled
    constexpr uint32_t WS_CLIPSIBLINGS  = 0x04000000;  // Clip siblings
    constexpr uint32_t WS_CLIPCHILDREN  = 0x02000000;  // Clip children
    constexpr uint32_t WS_MAXIMIZE      = 0x01000000;  // Maximized
    constexpr uint32_t WS_CAPTION       = 0x00C00000;  // Title bar (WS_BORDER | WS_DLGFRAME)
    constexpr uint32_t WS_BORDER        = 0x00800000;  // Thin border
    constexpr uint32_t WS_DLGFRAME      = 0x00400000;  // Dialog frame
    constexpr uint32_t WS_VSCROLL       = 0x00200000;  // Vertical scrollbar
    constexpr uint32_t WS_HSCROLL       = 0x00100000;  // Horizontal scrollbar
    constexpr uint32_t WS_SYSMENU       = 0x00080000;  // System menu
    constexpr uint32_t WS_THICKFRAME    = 0x00040000;  // Sizing border
    constexpr uint32_t WS_GROUP         = 0x00020000;  // Group start
    constexpr uint32_t WS_TABSTOP       = 0x00010000;  // Tab stop
    constexpr uint32_t WS_MINIMIZEBOX   = 0x00020000;  // Minimize button
    constexpr uint32_t WS_MAXIMIZEBOX   = 0x00010000;  // Maximize button
}

/**
 * Format dialog/window style flags as human-readable string.
 *
 * @param style The combined DS_* and WS_* style flags
 * @return String like "WS_POPUP | WS_CAPTION | DS_MODALFRAME | DS_SETFONT"
 */
LIBEXE_EXPORT std::string format_dialog_style(uint32_t style);

/**
 * Predefined control classes (both NE and PE formats use the same IDs).
 */
enum class control_class : uint8_t {
    BUTTON      = 0x80,  // Button control (pushbutton, checkbox, radio, etc.)
    EDIT        = 0x81,  // Edit control (text input field)
    STATIC      = 0x82,  // Static control (text label, icon, image)
    LISTBOX     = 0x83,  // List box control
    SCROLLBAR   = 0x84,  // Scroll bar control
    COMBOBOX    = 0x85,  // Combo box control (dropdown list)
};

/**
 * Get human-readable name for a predefined control class.
 *
 * @param cls The control class enum value
 * @return String like "BUTTON", "EDIT", "STATIC", etc.
 */
LIBEXE_EXPORT const char* control_class_name(control_class cls);

/**
 * Name or resource ID (can be either a string or numeric ID).
 */
using name_or_id = std::variant<std::string, uint16_t>;

/**
 * Single dialog control.
 */
struct LIBEXE_EXPORT dialog_control {
    int16_t x = 0;           // X position in dialog units
    int16_t y = 0;           // Y position in dialog units
    int16_t width = 0;       // Width in dialog units
    int16_t height = 0;      // Height in dialog units
    uint16_t id = 0;         // Control ID
    uint32_t style = 0;      // Control style flags

    // Class can be either predefined enum or custom string
    std::variant<control_class, std::string> control_class_id;

    // Text/caption (can be string or resource ID)
    name_or_id text;

    // Extra creation data (rarely used)
    std::vector<uint8_t> extra_data;

    /**
     * Check if this control uses a predefined class.
     */
    [[nodiscard]] bool is_predefined_class() const {
        return std::holds_alternative<control_class>(control_class_id);
    }

    /**
     * Get the predefined class (if applicable).
     */
    [[nodiscard]] std::optional<control_class> get_predefined_class() const {
        if (auto* cls = std::get_if<control_class>(&control_class_id)) {
            return *cls;
        }
        return std::nullopt;
    }

    /**
     * Get the custom class name (if applicable).
     */
    [[nodiscard]] std::optional<std::string> get_class_name() const {
        if (auto* name = std::get_if<std::string>(&control_class_id)) {
            return *name;
        }
        return std::nullopt;
    }

    /**
     * Check if text is a string (vs resource ID).
     */
    [[nodiscard]] bool has_text_string() const {
        return std::holds_alternative<std::string>(text);
    }

    /**
     * Get text string (if applicable).
     */
    [[nodiscard]] std::optional<std::string> get_text_string() const {
        if (auto* str = std::get_if<std::string>(&text)) {
            return *str;
        }
        return std::nullopt;
    }

    /**
     * Get text resource ID (if applicable).
     */
    [[nodiscard]] std::optional<uint16_t> get_text_id() const {
        if (auto* id = std::get_if<uint16_t>(&text)) {
            return *id;
        }
        return std::nullopt;
    }
};

/**
 * Dialog template (NE format).
 *
 * Represents a dialog box resource from an NE (16-bit Windows) executable.
 */
struct LIBEXE_EXPORT dialog_template {
    uint32_t style = 0;          // Dialog style flags
    uint8_t num_controls = 0;    // Number of controls
    int16_t x = 0;               // X position
    int16_t y = 0;               // Y position
    int16_t width = 0;           // Width in dialog units
    int16_t height = 0;          // Height in dialog units

    // Menu can be name or resource ID
    name_or_id menu;

    // Window class (usually empty for standard dialogs)
    std::string window_class;

    // Dialog caption/title
    std::string caption;

    // Font info (only if DS_SETFONT is set)
    uint16_t point_size = 0;     // Font point size
    std::string font_name;       // Font face name

    // Child controls
    std::vector<dialog_control> controls;

    /**
     * Check if this dialog uses a custom font.
     */
    [[nodiscard]] bool has_font() const {
        return (style & dialog_style::DS_SETFONT) != 0;
    }

    /**
     * Check if menu is a string (vs resource ID).
     */
    [[nodiscard]] bool has_menu_name() const {
        return std::holds_alternative<std::string>(menu);
    }

    /**
     * Get menu name (if applicable).
     */
    [[nodiscard]] std::optional<std::string> get_menu_name() const {
        if (auto* name = std::get_if<std::string>(&menu)) {
            return *name;
        }
        return std::nullopt;
    }

    /**
     * Get menu resource ID (if applicable).
     */
    [[nodiscard]] std::optional<uint16_t> get_menu_id() const {
        if (auto* id = std::get_if<uint16_t>(&menu)) {
            return *id;
        }
        return std::nullopt;
    }
};

/**
 * Parser for RT_DIALOG resources (Windows formats only).
 *
 * Parses dialog templates from Windows executables.
 * Supports PE (32/64-bit) and NE Windows (16-bit) formats.
 *
 * For OS/2 dialogs (NE OS/2, LE, LX), use parse_os2_dialog() from
 * os2_resource_parser.hpp instead, as OS/2 dialogs have a completely
 * different binary structure.
 *
 * Example:
 * @code
 * auto dialog_resources = resources->resources_by_type(resource_type::RT_DIALOG);
 * if (!dialog_resources.empty()) {
 *     auto dlg = dialog_parser::parse(dialog_resources[0].data(), windows_resource_format::PE);
 *     if (dlg.has_value()) {
 *         std::cout << "Dialog: " << dlg->caption << "\n";
 *         std::cout << "  Size: " << dlg->width << "x" << dlg->height << "\n";
 *         std::cout << "  Controls: " << dlg->controls.size() << "\n";
 *     }
 * }
 * @endcode
 */
class LIBEXE_EXPORT dialog_parser {
public:
    /**
     * Parse a Windows dialog template resource.
     *
     * Uses the specified format discriminator to select the correct parser.
     *
     * @param data Raw resource data from RT_DIALOG resource
     * @param format Windows resource format (PE or NE)
     * @return Parsed dialog template on success, std::nullopt on parse error
     */
    static std::optional<dialog_template> parse(std::span<const uint8_t> data, windows_resource_format format);
};

} // namespace libexe

#endif // LIBEXE_DIALOG_PARSER_HPP
