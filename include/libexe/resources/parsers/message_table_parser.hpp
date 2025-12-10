#ifndef LIBEXE_MESSAGE_TABLE_PARSER_HPP
#define LIBEXE_MESSAGE_TABLE_PARSER_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <span>
#include <vector>
#include <map>
#include <optional>
#include <string>

namespace libexe {

/**
 * Message resource flags
 */
enum class message_flags : uint16_t {
    ANSI    = 0x0000,  // Message text is ANSI
    UNICODE = 0x0001   // Message text is Unicode (UTF-16)
};

/**
 * Single message entry
 */
struct LIBEXE_EXPORT message_entry {
    uint32_t message_id;     // Message ID
    message_flags flags;     // Message flags (ANSI or Unicode)
    std::string text;        // Message text (converted to UTF-8)

    /**
     * Check if message is Unicode
     */
    [[nodiscard]] bool is_unicode() const {
        return flags == message_flags::UNICODE;
    }

    /**
     * Check if message is ANSI
     */
    [[nodiscard]] bool is_ansi() const {
        return flags == message_flags::ANSI;
    }
};

/**
 * Message resource block
 *
 * Defines a contiguous range of message IDs.
 * Message tables organize messages in blocks for efficient lookup.
 */
struct LIBEXE_EXPORT message_block {
    uint32_t low_id;         // First message ID in this block
    uint32_t high_id;        // Last message ID in this block
    std::vector<message_entry> messages;  // Messages in this block

    /**
     * Check if this block contains a given message ID
     */
    [[nodiscard]] bool contains(uint32_t message_id) const {
        return message_id >= low_id && message_id <= high_id;
    }

    /**
     * Get number of messages in this block
     */
    [[nodiscard]] uint32_t message_count() const {
        return high_id - low_id + 1;
    }
};

/**
 * Message table resource (RT_MESSAGETABLE)
 *
 * Contains messages organized into blocks for efficient lookup.
 * Used primarily in Windows event logging (Event Viewer messages).
 */
struct LIBEXE_EXPORT message_table {
    std::vector<message_block> blocks;  // Message blocks

    /**
     * Find a message by ID
     *
     * @param message_id Message ID to look up
     * @return Message entry if found, std::nullopt otherwise
     */
    [[nodiscard]] std::optional<message_entry> find_message(uint32_t message_id) const {
        for (const auto& block : blocks) {
            if (block.contains(message_id)) {
                // Find message in block
                for (const auto& msg : block.messages) {
                    if (msg.message_id == message_id) {
                        return msg;
                    }
                }
            }
        }
        return std::nullopt;
    }

    /**
     * Get all messages as a map (message_id -> text)
     */
    [[nodiscard]] std::map<uint32_t, std::string> all_messages() const {
        std::map<uint32_t, std::string> result;
        for (const auto& block : blocks) {
            for (const auto& msg : block.messages) {
                result[msg.message_id] = msg.text;
            }
        }
        return result;
    }

    /**
     * Get total number of messages
     */
    [[nodiscard]] size_t message_count() const {
        size_t count = 0;
        for (const auto& block : blocks) {
            count += block.messages.size();
        }
        return count;
    }
};

/**
 * Parser for RT_MESSAGETABLE resources.
 *
 * Message tables are used primarily in Windows event logging to store
 * event log messages. Each message is identified by a 32-bit message ID
 * and can be in ANSI or Unicode format.
 *
 * Messages are organized into blocks, where each block covers a contiguous
 * range of message IDs. This allows efficient storage and lookup.
 *
 * Example:
 * @code
 * auto msg_resources = resources->resources_by_type(resource_type::RT_MESSAGETABLE);
 * if (!msg_resources.empty()) {
 *     auto msg_table = message_table_parser::parse(msg_resources[0].data());
 *     if (msg_table.has_value()) {
 *         // Find specific message
 *         auto msg = msg_table->find_message(0x1000);
 *         if (msg.has_value()) {
 *             std::cout << "Message 0x1000: " << msg->text << "\n";
 *         }
 *
 *         // List all messages
 *         for (const auto& [id, text] : msg_table->all_messages()) {
 *             std::cout << "0x" << std::hex << id << ": " << text << "\n";
 *         }
 *     }
 * }
 * @endcode
 */
class LIBEXE_EXPORT message_table_parser {
public:
    /**
     * Parse a message table resource.
     *
     * @param data Raw resource data from RT_MESSAGETABLE resource
     * @return Parsed message table on success, std::nullopt on parse error
     */
    [[nodiscard]] static std::optional<message_table> parse(std::span<const uint8_t> data);
};

} // namespace libexe

#endif // LIBEXE_MESSAGE_TABLE_PARSER_HPP
