#ifndef LIBEXE_DIALOG_PARSER_HPP
#define LIBEXE_DIALOG_PARSER_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <span>
#include <vector>
#include <optional>
#include <string>
#include <variant>

namespace libexe {

/**
 * Dialog box styles (DS_* flags for both NE and PE dialogs).
 */
enum class dialog_style : uint32_t {
    DS_ABSALIGN     = 0x0001,  // Absolute alignment
    DS_SYSMODAL     = 0x0002,  // System modal
    DS_LOCALEDIT    = 0x0020,  // Local edit controls
    DS_SETFONT      = 0x0040,  // Dialog has custom font
    DS_MODALFRAME   = 0x0080,  // Modal frame
    DS_NOIDLEMSG    = 0x0100,  // No idle messages
};

/**
 * Predefined control classes (both NE and PE formats use the same IDs).
 */
enum class control_class : uint8_t {
    BUTTON      = 0x80,  // Button control
    EDIT        = 0x81,  // Edit control
    STATIC      = 0x82,  // Static text/image
    LISTBOX     = 0x83,  // List box
    SCROLLBAR   = 0x84,  // Scroll bar
    COMBOBOX    = 0x85,  // Combo box
};

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
        return (style & static_cast<uint32_t>(dialog_style::DS_SETFONT)) != 0;
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
 * Parser for RT_DIALOG resources (NE format).
 *
 * Parses dialog templates from 16-bit Windows (NE) executables.
 * Note: This parser is for NE format only. PE dialogs use a different format.
 *
 * Example:
 * @code
 * auto dialog_resources = resources->resources_by_type(resource_type::RT_DIALOG);
 * if (!dialog_resources.empty()) {
 *     auto dlg = dialog_parser::parse(dialog_resources[0].data());
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
     * Parse a dialog template resource (auto-detects NE or PE format).
     *
     * Supports both NE (16-bit Windows) DLGTEMPLATE and PE (32/64-bit Windows)
     * DLGTEMPLATEEX formats. Format is detected by checking for the PE signature
     * (version=1, signature=0xFFFF).
     *
     * @param data Raw resource data from RT_DIALOG resource
     * @return Parsed dialog template on success, std::nullopt on parse error
     */
    static std::optional<dialog_template> parse(std::span<const uint8_t> data);
};

} // namespace libexe

#endif // LIBEXE_DIALOG_PARSER_HPP
