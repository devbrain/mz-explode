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

// Read null-terminated string, advance pointer
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

// Read name or ID: 0xFF prefix means ID follows, otherwise string
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
        // String follows
        return read_string(ptr, end);
    }
}

} // anonymous namespace

std::optional<dialog_template> dialog_parser::parse(std::span<const uint8_t> data) {
    // Minimum size check (header = 13 bytes minimum)
    if (data.size() < 13) {
        return std::nullopt;
    }

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
    if (ptr < end) {
        if (*ptr == 0xFF) {
            // Class ID (rarely used)
            ptr++;
            if (ptr + 1 <= end) {
                result.window_class = std::string("Class_") + std::to_string(*ptr);
                ptr++;
            }
        } else {
            // Class name string
            result.window_class = read_string(ptr, end);
        }
    }

    // Read caption
    if (ptr < end) {
        result.caption = read_string(ptr, end);
    }

    // If DS_SETFONT, read font info
    if (result.has_font()) {
        if (ptr + 2 <= end) {
            result.point_size = read_u16(ptr);
            ptr += 2;

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
                // Custom class name
                control.control_class_id = read_string(ptr, end);
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

} // namespace libexe
