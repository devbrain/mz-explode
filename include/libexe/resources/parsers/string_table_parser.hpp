#ifndef LIBEXE_STRING_TABLE_PARSER_HPP
#define LIBEXE_STRING_TABLE_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/resources/resource.hpp>
#include <cstdint>
#include <span>
#include <string>
#include <map>
#include <optional>

// Disable MSVC warning C4251: 'member': class 'std::...' needs to have dll-interface
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

namespace libexe {

/**
 * String table resource (RT_STRING).
 *
 * String tables are organized in blocks of 16 strings. Each block has a resource ID,
 * and the actual string IDs are calculated as: (block_id - 1) * 16 + index
 *
 * For example, block ID 1 contains strings 0-15, block ID 2 contains strings 16-31, etc.
 *
 * Strings are stored as length-prefixed Unicode (UTF-16) strings.
 * Empty slots have length = 0.
 */
struct LIBEXE_EXPORT string_table {
    uint16_t block_id;                    // Resource ID of this block
    std::map<uint16_t, std::string> strings;  // String ID -> UTF-8 string

    /**
     * Get the number of strings in this block (non-empty only).
     */
    [[nodiscard]] size_t count() const {
        return strings.size();
    }

    /**
     * Get a string by ID.
     *
     * @param string_id String ID (0-based)
     * @return String value if exists, empty string otherwise
     */
    [[nodiscard]] std::string get_string(uint16_t string_id) const {
        auto it = strings.find(string_id);
        return it != strings.end() ? it->second : "";
    }

    /**
     * Check if a string exists.
     *
     * @param string_id String ID (0-based)
     * @return true if string exists (non-empty), false otherwise
     */
    [[nodiscard]] bool has_string(uint16_t string_id) const {
        return strings.find(string_id) != strings.end();
    }

    /**
     * Get the base string ID for this block.
     * Strings in this block have IDs from base_id to base_id+15.
     */
    [[nodiscard]] uint16_t base_string_id() const {
        return static_cast<uint16_t>((block_id - 1) * 16);
    }
};

/**
 * Parser for RT_STRING resources (Windows formats only).
 *
 * Parses string table blocks from Windows executables.
 * - PE format: Length-prefixed UTF-16 strings (16 strings per block)
 * - NE Windows format: Length-prefixed ANSI strings (16 strings per block)
 *
 * For OS/2 string tables (NE OS/2, LE, LX), use parse_os2_string_table()
 * from os2_resource_parser.hpp instead, as OS/2 string tables have a
 * different binary structure.
 *
 * Example:
 * @code
 * auto string_blocks = resources->resources_by_type(resource_type::RT_STRING);
 * for (const auto& block_entry : string_blocks) {
 *     auto table = string_table_parser::parse(block_entry.data(), block_entry.id().value(), windows_resource_format::PE);
 *     if (table.has_value()) {
 *         std::cout << "Block " << table->block_id
 *                   << " (" << table->count() << " strings):\n";
 *
 *         for (const auto& [id, text] : table->strings) {
 *             std::cout << "  String " << id << ": " << text << "\n";
 *         }
 *     }
 * }
 * @endcode
 */
class LIBEXE_EXPORT string_table_parser {
public:
    /**
     * Parse a Windows string table resource block.
     *
     * Uses the specified format discriminator to select the correct
     * string encoding (UTF-16 for PE, ANSI for NE).
     *
     * @param data Raw resource data from RT_STRING resource
     * @param block_id Resource ID of this block (used to calculate string IDs)
     * @param format Windows resource format (PE or NE)
     * @return Parsed string table on success, std::nullopt on parse error
     */
    [[nodiscard]] static std::optional<string_table> parse(std::span<const uint8_t> data, uint16_t block_id, windows_resource_format format);
};

} // namespace libexe

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // LIBEXE_STRING_TABLE_PARSER_HPP
