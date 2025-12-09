#include <libexe/resources/parsers/string_table_parser.hpp>

namespace libexe {

std::optional<string_table> string_table_parser::parse(std::span<const uint8_t> data, uint16_t block_id) {
    if (data.empty()) {
        return std::nullopt;
    }

    string_table result;
    result.block_id = block_id;

    const uint8_t* ptr = data.data();
    const uint8_t* end = data.data() + data.size();

    // Calculate base string ID for this block
    uint16_t base_id = (block_id - 1) * 16;

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

} // namespace libexe
