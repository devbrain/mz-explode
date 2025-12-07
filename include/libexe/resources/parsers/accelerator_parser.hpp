#ifndef LIBEXE_ACCELERATOR_PARSER_HPP
#define LIBEXE_ACCELERATOR_PARSER_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <span>
#include <vector>
#include <optional>
#include <string>

namespace libexe {

/**
 * Accelerator key flags.
 */
enum class accelerator_flags : uint16_t {
    NONE = 0,
    VIRTKEY = 0x0001,     // Virtual key code (not ASCII)
    NOINVERT = 0x0002,    // No invert on activation
    SHIFT = 0x0004,       // Shift key must be held
    CONTROL = 0x0008,     // Control key must be held
    ALT = 0x0010,         // Alt key must be held
    END = 0x0080          // Last entry in table (internal flag)
};

/**
 * Single accelerator table entry.
 *
 * Represents a keyboard shortcut mapped to a command ID.
 */
struct LIBEXE_EXPORT accelerator_entry {
    uint16_t flags;       // Accelerator flags (VIRTKEY, SHIFT, CONTROL, ALT, etc.)
    uint16_t key;         // ASCII character or virtual key code
    uint16_t command_id;  // Command ID to execute

    /**
     * Check if this is a virtual key (VK_* code) or ASCII character.
     */
    [[nodiscard]] bool is_virtkey() const {
        return (flags & static_cast<uint16_t>(accelerator_flags::VIRTKEY)) != 0;
    }

    /**
     * Check if Shift modifier is required.
     */
    [[nodiscard]] bool requires_shift() const {
        return (flags & static_cast<uint16_t>(accelerator_flags::SHIFT)) != 0;
    }

    /**
     * Check if Control modifier is required.
     */
    [[nodiscard]] bool requires_control() const {
        return (flags & static_cast<uint16_t>(accelerator_flags::CONTROL)) != 0;
    }

    /**
     * Check if Alt modifier is required.
     */
    [[nodiscard]] bool requires_alt() const {
        return (flags & static_cast<uint16_t>(accelerator_flags::ALT)) != 0;
    }

    /**
     * Get a human-readable string representation of the accelerator.
     *
     * Examples:
     * - "Ctrl+S" (Control + S key)
     * - "Ctrl+Shift+F1" (Control + Shift + F1 key)
     * - "Alt+X" (Alt + X key)
     *
     * @return String representation of the key combination
     */
    [[nodiscard]] std::string to_string() const;
};

/**
 * Accelerator table resource (RT_ACCELERATOR).
 *
 * Contains keyboard shortcuts for menu commands and other actions.
 */
struct LIBEXE_EXPORT accelerator_table {
    std::vector<accelerator_entry> entries;

    /**
     * Get the number of accelerators in this table.
     */
    [[nodiscard]] size_t count() const {
        return entries.size();
    }

    /**
     * Check if table is empty.
     */
    [[nodiscard]] bool empty() const {
        return entries.empty();
    }

    /**
     * Find accelerator by command ID.
     *
     * @param command_id Command ID to search for
     * @return Pointer to accelerator entry if found, nullptr otherwise
     */
    [[nodiscard]] const accelerator_entry* find_by_command(uint16_t command_id) const {
        for (const auto& entry : entries) {
            if (entry.command_id == command_id) {
                return &entry;
            }
        }
        return nullptr;
    }
};

/**
 * Parser for RT_ACCELERATOR resources.
 *
 * Parses accelerator tables from Windows executables.
 * Each entry defines a keyboard shortcut and its associated command ID.
 *
 * Example:
 * @code
 * auto accel_resources = resources->resources_by_type(resource_type::RT_ACCELERATOR);
 * if (!accel_resources.empty()) {
 *     auto table = accelerator_parser::parse(accel_resources[0].data());
 *     if (table.has_value()) {
 *         std::cout << "Accelerators (" << table->count() << " entries):\n";
 *
 *         for (const auto& entry : table->entries) {
 *             std::cout << "  " << entry.to_string()
 *                       << " -> Command " << entry.command_id << "\n";
 *         }
 *     }
 * }
 * @endcode
 */
class LIBEXE_EXPORT accelerator_parser {
public:
    /**
     * Parse an accelerator table resource.
     *
     * @param data Raw resource data from RT_ACCELERATOR resource
     * @return Parsed accelerator table on success, std::nullopt on parse error
     */
    static std::optional<accelerator_table> parse(std::span<const uint8_t> data);
};

} // namespace libexe

#endif // LIBEXE_ACCELERATOR_PARSER_HPP
