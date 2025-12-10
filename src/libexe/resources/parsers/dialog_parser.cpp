#include <libexe/resources/parsers/dialog_parser.hpp>
#include <formats/resources/dialogs/dialogs.hh>
#include "../../core/utf_convert.hpp"
#include <cstring>

namespace libexe {

namespace {

// Convert DataScript resource_name_or_id to libexe name_or_id
name_or_id convert_resource_name_or_id(const formats::resources::dialogs::resource_name_or_id& src) {
    if (auto* ordinal = src.as_ordinal()) {
        return ordinal->value;
    } else if (auto* name = src.as_name()) {
        return utf16_to_utf8(name->value);
    }
    return std::string("");
}

// Convert DataScript ne_name_or_id to libexe name_or_id
name_or_id convert_ne_name_or_id(const formats::resources::dialogs::ne_name_or_id& src) {
    if (auto* ordinal = src.as_ordinal_value()) {
        return ordinal->value.ordinal;
    } else if (auto* str_val = src.as_string_value()) {
        return std::string(str_val->value.chars.begin(), str_val->value.chars.end());
    }
    return std::string("");
}

// Convert DataScript ne_control_class to libexe control class variant
std::variant<control_class, std::string> convert_ne_control_class(
    formats::resources::dialogs::ne_control_class& src) {
    // ne_control_class uses range-based discriminator: >= 0x80 is predefined, else custom string
    if (auto* predefined = src.as_predefined_class()) {
        uint8_t class_id = predefined->value.class_id;
        if (class_id >= 0x80 && class_id <= 0x85) {
            return static_cast<control_class>(class_id);
        }
        // Unknown predefined class (0x86-0xFF) - return as string
        return std::string("Class_") + std::to_string(class_id);
    } else if (auto* custom = src.as_custom_class()) {
        return custom->value;  // Null-terminated string
    }
    return std::string("");
}

// Convert DataScript ne_control_text to libexe name_or_id
name_or_id convert_ne_control_text(const formats::resources::dialogs::ne_control_text& src) {
    if (auto* ordinal = src.as_ordinal_value()) {
        return ordinal->value.ordinal;
    } else if (auto* str_val = src.as_text()) {
        return str_val->value;  // Already a std::string
    }
    return std::string("");
}

// Parse PE extended dialog (DLGTEMPLATEEX)
std::optional<dialog_template> parse_pe_dialog_ex(std::span<const uint8_t> data) {
    try {
        const uint8_t* ptr = data.data();
        const uint8_t* end = data.data() + data.size();

        auto ds_dialog = formats::resources::dialogs::dialog_template_ex::read(ptr, end);

        dialog_template result;
        result.style = ds_dialog.style;
        result.num_controls = static_cast<uint8_t>(ds_dialog.item_count > 255 ? 255 : ds_dialog.item_count);
        result.x = ds_dialog.x;
        result.y = ds_dialog.y;
        result.width = ds_dialog.cx;
        result.height = ds_dialog.cy;
        result.menu = convert_resource_name_or_id(ds_dialog.menu);

        // Convert window class
        if (auto* ordinal = ds_dialog.window_class.as_ordinal()) {
            result.window_class = "Class_" + std::to_string(ordinal->value);
        } else if (auto* name = ds_dialog.window_class.as_name()) {
            result.window_class = utf16_to_utf8(name->value);
        }

        result.caption = utf16_to_utf8(ds_dialog.title);

        // Font info (conditional in DataScript, always parsed if DS_SETFONT)
        if (result.has_font()) {
            result.point_size = ds_dialog.point_size;
            result.font_name = utf16_to_utf8(ds_dialog.typeface);
        }

        // Parse controls using dialog_item_ex
        const uint8_t* start_for_align = data.data();
        for (uint16_t i = 0; i < ds_dialog.item_count && ptr < end; i++) {
            // Align to DWORD boundary before each control
            size_t offset = ptr - start_for_align;
            size_t aligned = (offset + 3) & ~size_t(3);
            ptr = start_for_align + aligned;

            if (ptr >= end) break;

            try {
                auto ds_item = formats::resources::dialogs::dialog_item_ex::read(ptr, end);

                dialog_control control;
                control.x = ds_item.x;
                control.y = ds_item.y;
                control.width = ds_item.cx;
                control.height = ds_item.cy;
                control.id = static_cast<uint16_t>(ds_item.id & 0xFFFF);
                control.style = ds_item.style;

                // Convert control class
                if (auto* ordinal = ds_item.window_class.as_ordinal()) {
                    uint16_t class_ord = ordinal->value;
                    if (class_ord >= 0x80 && class_ord <= 0x85) {
                        control.control_class_id = static_cast<control_class>(class_ord);
                    } else {
                        control.control_class_id = std::string("Class_") + std::to_string(class_ord);
                    }
                } else if (auto* name = ds_item.window_class.as_name()) {
                    control.control_class_id = utf16_to_utf8(name->value);
                }

                // Convert control text
                control.text = convert_resource_name_or_id(ds_item.title);

                // Extra data
                control.extra_data = ds_item.creation_data;

                result.controls.push_back(std::move(control));
            } catch (...) {
                break; // Stop on parse error
            }
        }

        return result;
    } catch (...) {
        return std::nullopt;
    }
}

// Parse PE standard dialog (DLGTEMPLATE)
std::optional<dialog_template> parse_pe_dialog_standard(std::span<const uint8_t> data) {
    try {
        const uint8_t* ptr = data.data();
        const uint8_t* end = data.data() + data.size();

        auto ds_dialog = formats::resources::dialogs::dialog_template::read(ptr, end);

        dialog_template result;
        result.style = ds_dialog.style;
        result.num_controls = static_cast<uint8_t>(ds_dialog.item_count > 255 ? 255 : ds_dialog.item_count);
        result.x = ds_dialog.x;
        result.y = ds_dialog.y;
        result.width = ds_dialog.cx;
        result.height = ds_dialog.cy;
        result.menu = convert_resource_name_or_id(ds_dialog.menu);

        // Convert window class
        if (auto* ordinal = ds_dialog.window_class.as_ordinal()) {
            result.window_class = "Class_" + std::to_string(ordinal->value);
        } else if (auto* name = ds_dialog.window_class.as_name()) {
            result.window_class = utf16_to_utf8(name->value);
        }

        result.caption = utf16_to_utf8(ds_dialog.title);

        // Font info
        if (result.has_font()) {
            result.point_size = ds_dialog.point_size;
            result.font_name = utf16_to_utf8(ds_dialog.typeface);
        }

        // Parse controls using dialog_item
        const uint8_t* start_for_align = data.data();
        for (uint16_t i = 0; i < ds_dialog.item_count && ptr < end; i++) {
            // Align to DWORD boundary
            size_t offset = ptr - start_for_align;
            size_t aligned = (offset + 3) & ~size_t(3);
            ptr = start_for_align + aligned;

            if (ptr >= end) break;

            try {
                auto ds_item = formats::resources::dialogs::dialog_item::read(ptr, end);

                dialog_control control;
                control.x = ds_item.x;
                control.y = ds_item.y;
                control.width = ds_item.cx;
                control.height = ds_item.cy;
                control.id = ds_item.id;
                control.style = ds_item.style;

                // Convert control class
                if (auto* ordinal = ds_item.window_class.as_ordinal()) {
                    uint16_t class_ord = ordinal->value;
                    if (class_ord >= 0x80 && class_ord <= 0x85) {
                        control.control_class_id = static_cast<control_class>(class_ord);
                    } else {
                        control.control_class_id = std::string("Class_") + std::to_string(class_ord);
                    }
                } else if (auto* name = ds_item.window_class.as_name()) {
                    control.control_class_id = utf16_to_utf8(name->value);
                }

                control.text = convert_resource_name_or_id(ds_item.title);
                control.extra_data = ds_item.creation_data;

                result.controls.push_back(std::move(control));
            } catch (...) {
                break;
            }
        }

        return result;
    } catch (...) {
        return std::nullopt;
    }
}

// Parse NE dialog (16-bit Windows DLGTEMPLATE)
std::optional<dialog_template> parse_ne_dialog(std::span<const uint8_t> data) {
    try {
        const uint8_t* ptr = data.data();
        const uint8_t* end = data.data() + data.size();

        auto ds_dialog = formats::resources::dialogs::ne_dialog_template::read(ptr, end);

        dialog_template result;
        result.style = ds_dialog.style;
        result.num_controls = ds_dialog.item_count;
        result.x = ds_dialog.x;
        result.y = ds_dialog.y;
        result.width = ds_dialog.cx;
        result.height = ds_dialog.cy;
        result.menu = convert_ne_name_or_id(ds_dialog.menu);
        result.window_class = ds_dialog.window_class;
        result.caption = ds_dialog.title;

        // Font info
        if (result.has_font()) {
            result.point_size = ds_dialog.point_size;
            result.font_name = ds_dialog.typeface;
        }

        // Parse NE controls
        for (uint8_t i = 0; i < ds_dialog.item_count && ptr < end; i++) {
            try {
                auto ds_item = formats::resources::dialogs::ne_dialog_item::read(ptr, end);

                dialog_control control;
                control.x = ds_item.x;
                control.y = ds_item.y;
                control.width = ds_item.cx;
                control.height = ds_item.cy;
                control.id = ds_item.id;
                control.style = ds_item.style;
                control.control_class_id = convert_ne_control_class(ds_item.window_class);
                control.text = convert_ne_control_text(ds_item.text);
                control.extra_data = ds_item.creation_data;

                result.controls.push_back(std::move(control));
            } catch (...) {
                break;
            }
        }

        return result;
    } catch (...) {
        return std::nullopt;
    }
}

} // anonymous namespace

std::optional<dialog_template> dialog_parser::parse(std::span<const uint8_t> data, windows_resource_format format) {
    if (data.size() < 18) {
        return std::nullopt;  // Too small for any dialog format
    }

    switch (format) {
        case windows_resource_format::PE: {
            // Check for DLGTEMPLATEEX signature (PE extended format)
            // Signature is: version (WORD) = 1, signature (WORD) = 0xFFFF
            const uint8_t* ptr = data.data();
            uint16_t version = static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8);
            uint16_t signature = static_cast<uint16_t>(ptr[2]) | (static_cast<uint16_t>(ptr[3]) << 8);

            if (version == 1 && signature == 0xFFFF) {
                return parse_pe_dialog_ex(data);
            }
            return parse_pe_dialog_standard(data);
        }

        case windows_resource_format::NE:
            return parse_ne_dialog(data);
    }

    return std::nullopt;
}

const char* control_class_name(control_class cls) {
    switch (cls) {
        case control_class::BUTTON:    return "BUTTON";
        case control_class::EDIT:      return "EDIT";
        case control_class::STATIC:    return "STATIC";
        case control_class::LISTBOX:   return "LISTBOX";
        case control_class::SCROLLBAR: return "SCROLLBAR";
        case control_class::COMBOBOX:  return "COMBOBOX";
        default:                       return "UNKNOWN";
    }
}

std::string format_dialog_style(uint32_t style) {
    std::string result;
    uint32_t remaining = style;

    // Helper to append flag name
    auto append_flag = [&](uint32_t flag, const char* name) {
        if ((remaining & flag) == flag) {
            if (!result.empty()) {
                result += " | ";
            }
            result += name;
            remaining &= ~flag;
        }
    };

    // Check WS_* window styles (high bits) first
    // Note: WS_CAPTION = WS_BORDER | WS_DLGFRAME, so check it before its components
    append_flag(dialog_style::WS_POPUP, "WS_POPUP");
    append_flag(dialog_style::WS_CHILD, "WS_CHILD");
    append_flag(dialog_style::WS_MINIMIZE, "WS_MINIMIZE");
    append_flag(dialog_style::WS_VISIBLE, "WS_VISIBLE");
    append_flag(dialog_style::WS_DISABLED, "WS_DISABLED");
    append_flag(dialog_style::WS_CLIPSIBLINGS, "WS_CLIPSIBLINGS");
    append_flag(dialog_style::WS_CLIPCHILDREN, "WS_CLIPCHILDREN");
    append_flag(dialog_style::WS_MAXIMIZE, "WS_MAXIMIZE");
    append_flag(dialog_style::WS_CAPTION, "WS_CAPTION");  // Check before BORDER/DLGFRAME
    append_flag(dialog_style::WS_BORDER, "WS_BORDER");
    append_flag(dialog_style::WS_DLGFRAME, "WS_DLGFRAME");
    append_flag(dialog_style::WS_VSCROLL, "WS_VSCROLL");
    append_flag(dialog_style::WS_HSCROLL, "WS_HSCROLL");
    append_flag(dialog_style::WS_SYSMENU, "WS_SYSMENU");
    append_flag(dialog_style::WS_THICKFRAME, "WS_THICKFRAME");
    // Note: WS_GROUP and WS_MINIMIZEBOX share 0x00020000
    // Note: WS_TABSTOP and WS_MAXIMIZEBOX share 0x00010000
    if ((remaining & 0x00020000) != 0) {
        append_flag(0x00020000, "WS_GROUP");  // or WS_MINIMIZEBOX
    }
    if ((remaining & 0x00010000) != 0) {
        append_flag(0x00010000, "WS_TABSTOP");  // or WS_MAXIMIZEBOX
    }

    // Check DS_* dialog styles (low bits)
    append_flag(dialog_style::DS_CONTEXTHELP, "DS_CONTEXTHELP");
    append_flag(dialog_style::DS_CENTERMOUSE, "DS_CENTERMOUSE");
    append_flag(dialog_style::DS_CENTER, "DS_CENTER");
    append_flag(dialog_style::DS_CONTROL, "DS_CONTROL");
    append_flag(dialog_style::DS_SETFOREGROUND, "DS_SETFOREGROUND");
    append_flag(dialog_style::DS_NOIDLEMSG, "DS_NOIDLEMSG");
    append_flag(dialog_style::DS_MODALFRAME, "DS_MODALFRAME");
    append_flag(dialog_style::DS_SETFONT, "DS_SETFONT");
    append_flag(dialog_style::DS_LOCALEDIT, "DS_LOCALEDIT");
    append_flag(dialog_style::DS_NOFAILCREATE, "DS_NOFAILCREATE");
    append_flag(dialog_style::DS_FIXEDSYS, "DS_FIXEDSYS");
    append_flag(dialog_style::DS_3DLOOK, "DS_3DLOOK");
    append_flag(dialog_style::DS_SYSMODAL, "DS_SYSMODAL");
    append_flag(dialog_style::DS_ABSALIGN, "DS_ABSALIGN");

    // If there are remaining unknown bits, show them as hex
    if (remaining != 0) {
        if (!result.empty()) {
            result += " | ";
        }
        char hex_buf[16];
        snprintf(hex_buf, sizeof(hex_buf), "0x%X", remaining);
        result += hex_buf;
    }

    // If nothing matched, just show the raw value
    if (result.empty()) {
        result = "0";
    }

    return result;
}

} // namespace libexe
