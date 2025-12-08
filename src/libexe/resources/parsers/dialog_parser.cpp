#include <libexe/resources/parsers/dialog_parser.hpp>
#include <cstring>

namespace libexe {

namespace {

// Helper to read uint16_t little-endian
uint16_t read_u16(const uint8_t* ptr) {
    return static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8);
}

// Helper to read int16_t little-endian
int16_t read_i16(const uint8_t* ptr) {
    return static_cast<int16_t>(read_u16(ptr));
}

// Helper to read uint32_t little-endian
uint32_t read_u32(const uint8_t* ptr) {
    return static_cast<uint32_t>(ptr[0]) |
           (static_cast<uint32_t>(ptr[1]) << 8) |
           (static_cast<uint32_t>(ptr[2]) << 16) |
           (static_cast<uint32_t>(ptr[3]) << 24);
}

// Align pointer to DWORD boundary (PE dialogs require this)
const uint8_t* align_dword(const uint8_t* ptr, const uint8_t* base) {
    size_t offset = ptr - base;
    size_t aligned = (offset + 3) & ~3;
    return base + aligned;
}

// Read null-terminated UTF-16 string, advance pointer (PE format)
std::string read_utf16_string(const uint8_t*& ptr, const uint8_t* end) {
    std::string result;

    while (ptr + 1 < end) {
        uint16_t ch = read_u16(ptr);
        ptr += 2;

        if (ch == 0) break;

        // Simple UTF-16 to UTF-8 conversion (BMP only)
        if (ch < 0x80) {
            result.push_back(static_cast<char>(ch));
        } else if (ch < 0x800) {
            result.push_back(static_cast<char>(0xC0 | (ch >> 6)));
            result.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
        } else {
            result.push_back(static_cast<char>(0xE0 | (ch >> 12)));
            result.push_back(static_cast<char>(0x80 | ((ch >> 6) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
        }
    }

    return result;
}

// Read PE name or ordinal: 0xFFFF prefix means ordinal follows, otherwise Unicode string
name_or_id read_pe_name_or_ordinal(const uint8_t*& ptr, const uint8_t* end) {
    if (ptr + 1 >= end) {
        return std::string("");
    }

    uint16_t first = read_u16(ptr);

    if (first == 0xFFFF) {
        // Ordinal follows
        ptr += 2;
        if (ptr + 1 < end) {
            uint16_t ordinal = read_u16(ptr);
            ptr += 2;
            return ordinal;
        }
        return uint16_t(0);
    } else {
        // Unicode string (already started reading it)
        if (first == 0) {
            ptr += 2;
            return std::string("");
        }

        // Put first character back and read full string
        std::string result;

        // Convert first character
        if (first < 0x80) {
            result.push_back(static_cast<char>(first));
        } else if (first < 0x800) {
            result.push_back(static_cast<char>(0xC0 | (first >> 6)));
            result.push_back(static_cast<char>(0x80 | (first & 0x3F)));
        } else {
            result.push_back(static_cast<char>(0xE0 | (first >> 12)));
            result.push_back(static_cast<char>(0x80 | ((first >> 6) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | (first & 0x3F)));
        }

        ptr += 2;
        result += read_utf16_string(ptr, end);
        return result;
    }
}

// Read null-terminated string, advance pointer (PE format)
std::string read_string(const uint8_t*& ptr, const uint8_t* end) {
    std::string result;

    while (ptr < end && *ptr != 0) {
        result.push_back(static_cast<char>(*ptr));
        ptr++;
    }

    if (ptr < end) {
        ptr++;  // Skip null terminator
    }

    return result;
}

// Read length-prefixed string (NE format: [length byte][characters])
// Implements the ne_pstring structure from dialogs.ds
//
// Format per dialogs.ds:
//   struct ne_pstring {
//       uint8 length;
//       uint8 chars[length];
//   };
//
// NE format uses Pascal-style strings (NOT null-terminated).
// Per ne.fmt specification (line 273): "String table follows (length-prefixed, NOT null-terminated)"
std::string read_length_prefixed_string(const uint8_t*& ptr, const uint8_t* end) {
    if (ptr >= end) {
        return std::string();
    }

    uint8_t length = *ptr++;

    if (length == 0) {
        return std::string();
    }

    if (ptr + length > end) {
        // Not enough data - return what we can
        length = static_cast<uint8_t>(end - ptr);
    }

    std::string result(reinterpret_cast<const char*>(ptr), length);
    ptr += length;

    return result;
}

// Read name or ID: 0xFF prefix means ID follows, otherwise length-prefixed string (NE format)
// Implements the ne_name_or_id pattern from dialogs.ds
name_or_id read_name_or_id(const uint8_t*& ptr, const uint8_t* end, bool is_word_id = true) {
    if (ptr >= end) {
        return std::string("");
    }

    if (*ptr == 0xFF) {
        // ID follows
        ptr++;
        if (is_word_id) {
            if (ptr + 2 > end) return uint16_t(0);
            uint16_t id = read_u16(ptr);
            ptr += 2;
            return id;
        } else {
            // Byte ID (for control classes)
            if (ptr >= end) return uint16_t(0);
            uint16_t id = *ptr;
            ptr++;
            return id;
        }
    } else {
        // Length-prefixed string follows (NE format per dialogs.ds ne_pstring)
        return read_length_prefixed_string(ptr, end);
    }
}

// Parse PE DLGTEMPLATEEX format (32/64-bit Windows)
std::optional<dialog_template> parse_pe_dialog(std::span<const uint8_t> data) {
    const uint8_t* base = data.data();
    const uint8_t* ptr = base;
    const uint8_t* end = base + data.size();

    dialog_template result;

    // Read DLGTEMPLATEEX header
    uint16_t version = read_u16(ptr);
    ptr += 2;

    uint16_t signature = read_u16(ptr);
    ptr += 2;

    if (version != 1 || signature != 0xFFFF) {
        return std::nullopt;  // Not DLGTEMPLATEEX
    }

    // Read help ID (DLGTEMPLATEEX only)
    uint32_t help_id = read_u32(ptr);
    ptr += 4;

    // Read extended style
    uint32_t ex_style = read_u32(ptr);
    ptr += 4;

    // Read style
    result.style = read_u32(ptr);
    ptr += 4;

    // Read control count (WORD, not BYTE like NE)
    result.num_controls = read_u16(ptr);
    ptr += 2;

    // Read position and size
    result.x = read_i16(ptr);
    ptr += 2;

    result.y = read_i16(ptr);
    ptr += 2;

    result.width = read_i16(ptr);
    ptr += 2;

    result.height = read_i16(ptr);
    ptr += 2;

    // Read menu (Unicode string or ordinal)
    result.menu = read_pe_name_or_ordinal(ptr, end);

    // Read window class (Unicode string or ordinal)
    auto class_name_or_id = read_pe_name_or_ordinal(ptr, end);
    if (std::holds_alternative<std::string>(class_name_or_id)) {
        result.window_class = std::get<std::string>(class_name_or_id);
    } else {
        result.window_class = "Class_" + std::to_string(std::get<uint16_t>(class_name_or_id));
    }

    // Read caption (Unicode string)
    result.caption = read_utf16_string(ptr, end);

    // If DS_SETFONT, read font info (extended for PE)
    if (result.has_font()) {
        if (ptr + 2 <= end) {
            result.point_size = read_u16(ptr);
            ptr += 2;

            // DLGTEMPLATEEX has weight, italic, charset
            if (ptr + 4 <= end) {
                // uint16_t weight = read_u16(ptr);
                ptr += 2;  // Skip weight

                // uint8_t italic = *ptr;
                // uint8_t charset = *(ptr + 1);
                ptr += 2;  // Skip italic and charset
            }

            result.font_name = read_utf16_string(ptr, end);
        }
    }

    // Align to DWORD before controls
    ptr = align_dword(ptr, base);

    // Parse controls
    for (size_t i = 0; i < result.num_controls; i++) {
        if (ptr + 24 > end) break;  // Minimum control size

        dialog_control control;

        // Read help ID (DLGITEMTEMPLATEEX only)
        // uint32_t ctrl_help_id = read_u32(ptr);
        ptr += 4;

        // Read extended style
        // uint32_t ctrl_ex_style = read_u32(ptr);
        ptr += 4;

        // Read style
        control.style = read_u32(ptr);
        ptr += 4;

        // Read position and size
        control.x = read_i16(ptr);
        ptr += 2;

        control.y = read_i16(ptr);
        ptr += 2;

        control.width = read_i16(ptr);
        ptr += 2;

        control.height = read_i16(ptr);
        ptr += 2;

        // Read control ID (DWORD in DLGITEMTEMPLATEEX, but we store as uint16)
        uint32_t id32 = read_u32(ptr);
        ptr += 4;
        control.id = static_cast<uint16_t>(id32 & 0xFFFF);

        // Read control class (Unicode string or ordinal)
        auto ctrl_class = read_pe_name_or_ordinal(ptr, end);
        if (std::holds_alternative<std::string>(ctrl_class)) {
            control.control_class_id = std::get<std::string>(ctrl_class);
        } else {
            uint16_t class_ord = std::get<uint16_t>(ctrl_class);
            // Map predefined classes
            if (class_ord >= 0x80 && class_ord <= 0x85) {
                control.control_class_id = static_cast<control_class>(class_ord);
            } else {
                control.control_class_id = std::string("Class_") + std::to_string(class_ord);
            }
        }

        // Read control text
        control.text = read_pe_name_or_ordinal(ptr, end);

        // Read extra data
        if (ptr + 1 < end) {
            uint16_t extra_len = read_u16(ptr);
            ptr += 2;

            if (extra_len > 0 && ptr + extra_len <= end) {
                control.extra_data.assign(ptr, ptr + extra_len);
                ptr += extra_len;
            }
        }

        // Align to DWORD before next control
        ptr = align_dword(ptr, base);

        result.controls.push_back(std::move(control));
    }

    return result;
}

// Parse NE DLGTEMPLATE format (16-bit Windows)
std::optional<dialog_template> parse_ne_dialog(std::span<const uint8_t> data) {
    const uint8_t* ptr = data.data();
    const uint8_t* end = data.data() + data.size();

    dialog_template result;

    // Read fixed header
    result.style = read_u32(ptr);
    ptr += 4;

    result.num_controls = *ptr++;

    result.x = read_i16(ptr);
    ptr += 2;

    result.y = read_i16(ptr);
    ptr += 2;

    result.width = read_i16(ptr);
    ptr += 2;

    result.height = read_i16(ptr);
    ptr += 2;

    // Read menu name or ID
    result.menu = read_name_or_id(ptr, end);

    // Read window class (usually empty)
    // NE format: null-terminated string OR 0xFF + byte ID
    if (ptr < end) {
        if (*ptr == 0xFF) {
            // Class ID (rarely used)
            ptr++;
            if (ptr + 1 <= end) {
                result.window_class = std::string("Class_") + std::to_string(*ptr);
                ptr++;
            }
        } else {
            // Class name string (null-terminated, NOT length-prefixed)
            result.window_class = read_string(ptr, end);
        }
    }

    // Read caption (null-terminated, NOT length-prefixed!)
    if (ptr < end) {
        result.caption = read_string(ptr, end);
    }

    // If DS_SETFONT, read font info
    if (result.has_font()) {
        if (ptr + 2 <= end) {
            result.point_size = read_u16(ptr);
            ptr += 2;

            // Font name (null-terminated, NOT length-prefixed)
            if (ptr < end) {
                result.font_name = read_string(ptr, end);
            }
        }
    }

    // Read controls
    for (size_t i = 0; i < result.num_controls && ptr + 14 <= end; i++) {
        dialog_control control;

        // Read control position and size
        control.x = read_i16(ptr);
        ptr += 2;

        control.y = read_i16(ptr);
        ptr += 2;

        control.width = read_i16(ptr);
        ptr += 2;

        control.height = read_i16(ptr);
        ptr += 2;

        // Read control ID
        control.id = read_u16(ptr);
        ptr += 2;

        // Read control style
        control.style = read_u32(ptr);
        ptr += 4;

        // Read control class (can be predefined or custom string)
        // Implements ne_control_class pattern from dialogs.ds
        if (ptr < end) {
            if (*ptr == 0xFF) {
                // Predefined class
                ptr++;
                if (ptr < end) {
                    uint8_t class_id = *ptr++;
                    // Map to enum if it's a known predefined class
                    if (class_id >= 0x80 && class_id <= 0x85) {
                        control.control_class_id = static_cast<control_class>(class_id);
                    } else {
                        control.control_class_id = std::string("Class_") + std::to_string(class_id);
                    }
                }
            } else {
                // Custom class name (length-prefixed per dialogs.ds ne_pstring)
                control.control_class_id = read_length_prefixed_string(ptr, end);
            }
        }

        // Read control text
        if (ptr < end) {
            control.text = read_name_or_id(ptr, end);
        }

        // Read extra data length and data
        if (ptr < end) {
            uint8_t extra_len = *ptr++;
            if (extra_len > 0 && ptr + extra_len <= end) {
                control.extra_data.assign(ptr, ptr + extra_len);
                ptr += extra_len;
            }
        }

        result.controls.push_back(std::move(control));
    }

    return result;
}

} // anonymous namespace

std::optional<dialog_template> dialog_parser::parse(std::span<const uint8_t> data) {
    if (data.size() < 18) {
        return std::nullopt;  // Too small for any dialog format
    }

    // Check for DLGTEMPLATEEX signature (PE format)
    // Signature is: version (WORD) = 1, signature (WORD) = 0xFFFF
    const uint8_t* ptr = data.data();
    uint16_t version = read_u16(ptr);
    uint16_t signature = read_u16(ptr + 2);

    if (version == 1 && signature == 0xFFFF) {
        // PE format (DLGTEMPLATEEX)
        return parse_pe_dialog(data);
    } else {
        // NE format (DLGTEMPLATE) - starts with style DWORD
        return parse_ne_dialog(data);
    }
}

} // namespace libexe
