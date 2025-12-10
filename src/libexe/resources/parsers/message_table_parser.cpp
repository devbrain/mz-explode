#include <libexe/resources/parsers/message_table_parser.hpp>
#include <formats/resources/tables/tables.hh>
#include "../../core/utf_convert.hpp"

namespace libexe {

namespace {

// Helper to read uint16 little-endian
uint16_t read_uint16_le(const uint8_t* ptr) {
    return static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8);
}

} // anonymous namespace

std::optional<message_table> message_table_parser::parse(std::span<const uint8_t> data) {
    // Minimum size check (header is at least 4 bytes)
    if (data.size() < 4) {
        return std::nullopt;
    }

    try {
        message_table result;

        const uint8_t* ptr = data.data();
        const uint8_t* end = data.data() + data.size();
        const uint8_t* base = data.data();  // For offset calculations

        // Parse message resource data header using DataScript
        auto ds_header = formats::resources::tables::message_resource_data::read(ptr, end);

        uint32_t num_blocks = ds_header.number_of_blocks;

        // Reserve space for blocks
        result.blocks.reserve(num_blocks);

        // Parse each block
        for (uint32_t block_idx = 0; block_idx < num_blocks; ++block_idx) {
            if (block_idx >= ds_header.blocks.size()) {
                break;
            }

            const auto& ds_block = ds_header.blocks[block_idx];

            message_block block;
            block.low_id = ds_block.low_id;
            block.high_id = ds_block.high_id;

            // Calculate number of messages in this block
            uint32_t message_count = block.high_id - block.low_id + 1;

            // Navigate to message entries using offset
            if (ds_block.offset_to_entries >= data.size()) {
                continue;  // Invalid offset
            }

            const uint8_t* entry_ptr = base + ds_block.offset_to_entries;

            // Parse message entries sequentially (they are variable-length)
            for (uint32_t msg_idx = 0; msg_idx < message_count; ++msg_idx) {
                if (entry_ptr + 4 > end) {
                    break;  // Not enough data
                }

                // Read message entry header
                uint16_t length = read_uint16_le(entry_ptr);
                uint16_t flags = read_uint16_le(entry_ptr + 2);

                if (length < 4 || entry_ptr + length > end) {
                    break;  // Invalid length
                }

                message_entry msg;
                msg.message_id = block.low_id + msg_idx;
                msg.flags = static_cast<message_flags>(flags);

                // Text starts after the 4-byte header
                const uint8_t* text_ptr = entry_ptr + 4;
                size_t text_size = length - 4;

                if (msg.flags == message_flags::UNICODE) {
                    // UTF-16 text (WCHAR)
                    size_t char_count = text_size / 2;
                    if (char_count > 0) {
                        std::u16string u16str;
                        u16str.reserve(char_count);

                        for (size_t i = 0; i < char_count; ++i) {
                            if (text_ptr + 2 > end) break;
                            uint16_t wchar = read_uint16_le(text_ptr);
                            text_ptr += 2;

                            if (wchar == 0) break;  // Null terminator
                            u16str.push_back(static_cast<char16_t>(wchar));
                        }

                        msg.text = utf16_to_utf8(u16str.data(), u16str.size());
                    }
                } else {
                    // ANSI text (CHAR)
                    if (text_size > 0) {
                        msg.text.assign(reinterpret_cast<const char*>(text_ptr), text_size);

                        // Remove null terminator if present
                        if (!msg.text.empty() && msg.text.back() == '\0') {
                            msg.text.pop_back();
                        }
                    }
                }

                block.messages.push_back(std::move(msg));

                // Move to next entry
                entry_ptr += length;
            }

            result.blocks.push_back(std::move(block));
        }

        return result;
    }
    catch (const std::exception&) {
        // Parse error - return nullopt
        return std::nullopt;
    }
}

} // namespace libexe
