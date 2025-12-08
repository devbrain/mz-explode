#include <libexe/resources/parsers/accelerator_parser.hpp>
#include "exe_format.hh"  // Generated DataScript parser
#include <sstream>

namespace libexe {

namespace {

// Virtual key names (subset of common VK_* codes)
const char* vk_name(uint16_t vk) {
    switch (vk) {
        case 0x08: return "Backspace";
        case 0x09: return "Tab";
        case 0x0D: return "Enter";
        case 0x1B: return "Esc";
        case 0x20: return "Space";
        case 0x21: return "PgUp";
        case 0x22: return "PgDn";
        case 0x23: return "End";
        case 0x24: return "Home";
        case 0x25: return "Left";
        case 0x26: return "Up";
        case 0x27: return "Right";
        case 0x28: return "Down";
        case 0x2D: return "Insert";
        case 0x2E: return "Delete";
        case 0x70: return "F1";
        case 0x71: return "F2";
        case 0x72: return "F3";
        case 0x73: return "F4";
        case 0x74: return "F5";
        case 0x75: return "F6";
        case 0x76: return "F7";
        case 0x77: return "F8";
        case 0x78: return "F9";
        case 0x79: return "F10";
        case 0x7A: return "F11";
        case 0x7B: return "F12";
        default: return nullptr;
    }
}

} // anonymous namespace

std::string accelerator_entry::to_string() const {
    std::ostringstream oss;

    // Add modifiers
    if (requires_control()) {
        oss << "Ctrl+";
    }
    if (requires_shift()) {
        oss << "Shift+";
    }
    if (requires_alt()) {
        oss << "Alt+";
    }

    // Add key
    if (is_virtkey()) {
        const char* name = vk_name(key);
        if (name) {
            oss << name;
        } else if (key >= 'A' && key <= 'Z') {
            // Letter keys (VK_A to VK_Z are same as ASCII)
            oss << static_cast<char>(key);
        } else if (key >= '0' && key <= '9') {
            // Number keys
            oss << static_cast<char>(key);
        } else {
            // Unknown virtual key
            oss << "VK_" << std::hex << key;
        }
    } else {
        // ASCII character
        if (key >= 32 && key < 127) {
            oss << static_cast<char>(key);
        } else {
            oss << "0x" << std::hex << key;
        }
    }

    return oss.str();
}

std::optional<accelerator_table> accelerator_parser::parse(std::span<const uint8_t> data) {
    // Minimum size check (at least one entry = 8 bytes)
    if (data.size() < 8) {
        return std::nullopt;
    }

    try {
        accelerator_table result;

        const uint8_t* ptr = data.data();
        const uint8_t* end = data.data() + data.size();

        // Parse entries until we hit the end flag or run out of data
        while (ptr + 8 <= end) {
            // Parse entry using DataScript
            auto ds_entry = formats::exe_format_complete::AccelTableEntry::read(ptr, end);

            accelerator_entry entry;
            entry.flags = ds_entry.fFlags;
            entry.key = ds_entry.wEvent;
            entry.command_id = ds_entry.wId;

            result.entries.push_back(entry);

            // Check for END flag
            if ((ds_entry.fFlags & static_cast<uint16_t>(accelerator_flags::END)) != 0) {
                break;
            }
        }

        // Ensure we got at least one entry
        if (result.entries.empty()) {
            return std::nullopt;
        }

        return result;
    }
    catch (const std::exception&) {
        // Parse error - return nullopt
        return std::nullopt;
    }
}

} // namespace libexe
