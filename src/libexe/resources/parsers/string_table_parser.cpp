#include <libexe/resources/parsers/string_table_parser.hpp>
#include <vector>

namespace libexe {

namespace {

// UTF-16LE to UTF-8 conversion helper
std::string utf16le_to_utf8(const uint8_t* data, size_t num_chars) {
    std::string result;
    result.reserve(num_chars);  // Estimate size

    for (size_t i = 0; i < num_chars; i++) {
        uint16_t wchar = static_cast<uint16_t>(static_cast<uint16_t>(data[i * 2]) |
                        (static_cast<uint16_t>(data[i * 2 + 1]) << 8));

        if (wchar < 0x80) {
            result.push_back(static_cast<char>(wchar));
        } else if (wchar < 0x800) {
            result.push_back(static_cast<char>(0xC0 | (wchar >> 6)));
            result.push_back(static_cast<char>(0x80 | (wchar & 0x3F)));
        } else {
            result.push_back(static_cast<char>(0xE0 | (wchar >> 12)));
            result.push_back(static_cast<char>(0x80 | ((wchar >> 6) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | (wchar & 0x3F)));
        }
    }

    return result;
}

// Parse PE format string table (UTF-16LE, length is char count)
std::optional<string_table> parse_pe_string_table(std::span<const uint8_t> data, uint16_t block_id) {
    string_table result;
    result.block_id = block_id;

    const uint8_t* ptr = data.data();
    const uint8_t* end = data.data() + data.size();

    // Calculate base string ID for this block
    uint16_t base_id = static_cast<uint16_t>((block_id - 1) * 16);

    // Parse up to 16 strings in this block
    for (size_t i = 0; i < 16 && ptr + 2 <= end; i++) {
        // Read length (WORD = character count, not byte count)
        uint16_t length = static_cast<uint16_t>(
            static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8));
        ptr += 2;

        // Check if we have enough data for the string (length * 2 bytes for UTF-16)
        size_t byte_length = static_cast<size_t>(length) * 2;
        if (ptr + byte_length > end) {
            break;  // Not enough data, stop parsing
        }

        // Skip empty strings
        if (length > 0) {
            uint16_t string_id = base_id + static_cast<uint16_t>(i);
            result.strings[string_id] = utf16le_to_utf8(ptr, length);
        }

        ptr += byte_length;
    }

    return result;
}

// Parse NE Windows format string table (ANSI, length is byte count)
std::optional<string_table> parse_ne_string_table(std::span<const uint8_t> data, uint16_t block_id) {
    string_table result;
    result.block_id = block_id;

    const uint8_t* ptr = data.data();
    const uint8_t* end = data.data() + data.size();

    // Calculate base string ID for this block
    uint16_t base_id = static_cast<uint16_t>((block_id - 1) * 16);

    // Parse up to 16 strings in this block
    for (size_t i = 0; i < 16 && ptr < end; i++) {
        // Check for minimum size (1 byte for length)
        if (ptr >= end) break;

        // Read length byte
        uint8_t length = *ptr++;

        // Check if we have enough data for the string
        if (ptr + length > end) {
            break;  // Not enough data, stop parsing
        }

        // Skip empty strings
        if (length > 0) {
            uint16_t string_id = base_id + static_cast<uint16_t>(i);
            // NE strings are ASCII/ANSI, not Unicode
            result.strings[string_id] = std::string(
                reinterpret_cast<const char*>(ptr),
                length
            );
        }

        ptr += length;
    }

    return result;
}

} // anonymous namespace

std::optional<string_table> string_table_parser::parse(std::span<const uint8_t> data, uint16_t block_id, windows_resource_format format) {
    if (data.empty()) {
        return std::nullopt;
    }

    switch (format) {
        case windows_resource_format::PE:
            return parse_pe_string_table(data, block_id);

        case windows_resource_format::NE:
            return parse_ne_string_table(data, block_id);
    }

    return std::nullopt;
}

} // namespace libexe
