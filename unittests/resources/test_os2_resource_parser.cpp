// libexe - Modern executable file analysis library
// Copyright (c) 2024
// Tests for OS/2 Presentation Manager resource parsers

#include <doctest/doctest.h>
#include <libexe/formats/le_file.hpp>
#include <libexe/resources/parsers/os2_resource_parser.hpp>
#include <span>

using namespace libexe;

// External embedded test data
namespace data {
    extern size_t os2chess_lx_len;
    extern unsigned char os2chess_lx[];
}

// =============================================================================
// OS2CHESS.EXE Resource Tests
// Ground truth: 73 resources across 8 types
// =============================================================================

TEST_CASE("OS/2 Resource Parser: OS2CHESS.EXE accelerator table") {
    std::span<const uint8_t> input(data::os2chess_lx, data::os2chess_lx_len);
    auto le = le_file::from_memory(input);

    REQUIRE(le.has_resources());

    // Get accelerator table resource (RT_ACCELTABLE = 8)
    auto accels = le.resources_by_type(le_resource::RT_ACCELTABLE);
    REQUIRE(accels.size() == 1);

    auto data = le.read_resource_data(accels[0]);
    REQUIRE_FALSE(data.empty());

    // Parse accelerator table
    auto parsed = parse_os2_accel_table(data);
    REQUIRE(parsed.has_value());

    MESSAGE("Accelerator table: ", parsed->entries.size(), " entries, codepage=", parsed->codepage);

    // Should have at least some accelerators
    CHECK(parsed->entries.size() > 0);

    // Check first entry has valid data
    if (!parsed->entries.empty()) {
        const auto& first = parsed->entries[0];
        MESSAGE("First accel: flags=0x", std::hex, first.flags,
                ", key=0x", first.key, ", cmd=", std::dec, first.cmd);
        CHECK(first.cmd > 0);  // Should have a valid command ID
    }
}

TEST_CASE("OS/2 Resource Parser: OS2CHESS.EXE bitmap resource") {
    std::span<const uint8_t> input(data::os2chess_lx, data::os2chess_lx_len);
    auto le = le_file::from_memory(input);

    REQUIRE(le.has_resources());

    // Get bitmap resources (RT_BITMAP = 2)
    auto bitmaps = le.resources_by_type(le_resource::RT_BITMAP);
    REQUIRE(bitmaps.size() == 14);

    // Parse first bitmap
    auto data = le.read_resource_data(bitmaps[0]);
    REQUIRE_FALSE(data.empty());

    auto parsed = parse_os2_bitmap(data);
    REQUIRE(parsed.has_value());

    MESSAGE("Bitmap: ", parsed->width, "x", parsed->height,
            ", ", parsed->bit_count, " bpp, type=0x", std::hex, static_cast<uint16_t>(parsed->type));

    CHECK(parsed->width > 0);
    CHECK(parsed->height > 0);
    CHECK(parsed->bit_count > 0);
    CHECK(parsed->planes == 1);
}

TEST_CASE("OS/2 Resource Parser: OS2CHESS.EXE dialog resource") {
    std::span<const uint8_t> input(data::os2chess_lx, data::os2chess_lx_len);
    auto le = le_file::from_memory(input);

    REQUIRE(le.has_resources());

    // Get dialog resources (RT_DIALOG = 4)
    auto dialogs = le.resources_by_type(le_resource::RT_DIALOG);
    REQUIRE(dialogs.size() == 23);

    // Parse first dialog
    auto data = le.read_resource_data(dialogs[0]);
    REQUIRE_FALSE(data.empty());

    auto parsed = parse_os2_dialog(data);
    REQUIRE(parsed.has_value());

    MESSAGE("Dialog: type=", parsed->type,
            ", codepage=", parsed->codepage,
            ", items=", parsed->items.size());

    // Should have some items
    CHECK(parsed->items.size() > 0);
}

TEST_CASE("OS/2 Resource Parser: OS2CHESS.EXE pointer resource") {
    std::span<const uint8_t> input(data::os2chess_lx, data::os2chess_lx_len);
    auto le = le_file::from_memory(input);

    REQUIRE(le.has_resources());

    // Get pointer resources (RT_POINTER = 1)
    auto pointers = le.resources_by_type(le_resource::RT_POINTER);
    REQUIRE(pointers.size() == 5);

    // Parse first pointer
    auto data = le.read_resource_data(pointers[0]);
    REQUIRE_FALSE(data.empty());

    // Pointers use bitmap format
    auto parsed = parse_os2_bitmap(data);
    REQUIRE(parsed.has_value());

    MESSAGE("Pointer: ", parsed->width, "x", parsed->height,
            ", hotspot=(", parsed->hotspot_x, ",", parsed->hotspot_y, ")");

    CHECK(parsed->width > 0);
    CHECK(parsed->height > 0);
}

TEST_CASE("OS/2 Resource Parser: OS2CHESS.EXE string table") {
    std::span<const uint8_t> input(data::os2chess_lx, data::os2chess_lx_len);
    auto le = le_file::from_memory(input);

    REQUIRE(le.has_resources());

    // Get string table resources (RT_STRING = 5)
    auto strings = le.resources_by_type(le_resource::RT_STRING);
    REQUIRE(strings.size() == 8);

    // Parse first string table
    auto data = le.read_resource_data(strings[0]);
    REQUIRE_FALSE(data.empty());

    auto parsed = parse_os2_string_table(data);

    MESSAGE("String table: ", parsed.size(), " strings");

    // Should have some strings
    CHECK(parsed.size() > 0);

    // Print first few non-empty strings
    int shown = 0;
    for (size_t i = 0; i < parsed.size() && shown < 5; ++i) {
        if (!parsed[i].empty()) {
            MESSAGE("  String[", i, "]: \"", parsed[i], "\"");
            ++shown;
        }
    }
}

// =============================================================================
// Accelerator Flag Tests
// =============================================================================

TEST_CASE("OS/2 accel_entry flag helpers") {
    os2_accel_entry entry;

    entry.flags = 0x0001;  // AF_CHAR
    CHECK(entry.is_char());
    CHECK_FALSE(entry.is_virtual_key());

    entry.flags = 0x0002;  // AF_VIRTUALKEY
    CHECK(entry.is_virtual_key());
    CHECK_FALSE(entry.is_char());

    entry.flags = 0x0038;  // AF_SHIFT | AF_CONTROL | AF_ALT
    CHECK(entry.requires_shift());
    CHECK(entry.requires_control());
    CHECK(entry.requires_alt());

    entry.flags = 0x0100;  // AF_SYSCOMMAND
    CHECK(entry.is_syscommand());

    entry.flags = 0x0200;  // AF_HELP
    CHECK(entry.is_help());
}

// =============================================================================
// Menu Item Flag Tests
// =============================================================================

TEST_CASE("OS/2 menu_item flag helpers") {
    os2_menu_item item;

    item.style = 0x0004;  // MIS_SEPARATOR
    CHECK(item.is_separator());

    item.style = 0x0010;  // MIS_SUBMENU
    CHECK(item.has_submenu());

    item.style = 0x0040;  // MIS_SYSCOMMAND
    CHECK(item.is_syscommand());

    item.style = 0x0080;  // MIS_HELP
    CHECK(item.is_help());

    item.attribute = 0x2000;  // MIA_CHECKED
    CHECK(item.is_checked());

    item.attribute = 0x4000;  // MIA_DISABLED
    CHECK(item.is_disabled());

    item.attribute = 0x8000;  // MIA_HILITED
    CHECK(item.is_highlighted());
}

// =============================================================================
// Menu Resource Tests
// =============================================================================

TEST_CASE("OS/2 Resource Parser: OS2CHESS.EXE menu resource") {
    std::span<const uint8_t> input(data::os2chess_lx, data::os2chess_lx_len);
    auto le = le_file::from_memory(input);

    REQUIRE(le.has_resources());

    // Get menu resources (RT_MENU = 3)
    auto menus = le.resources_by_type(le_resource::RT_MENU);
    REQUIRE(menus.size() == 2);

    // Parse first menu (larger one with ~Game submenu)
    auto data = le.read_resource_data(menus[0]);
    REQUIRE_FALSE(data.empty());

    auto parsed = parse_os2_menu(data);
    REQUIRE(parsed.has_value());

    MESSAGE("Menu: ", parsed->items.size(), " top-level items");

    // Should have top-level items
    CHECK(parsed->items.size() > 0);

    // First item should be ~Game with submenu
    if (!parsed->items.empty()) {
        const auto& game_menu = parsed->items[0];
        MESSAGE("First menu item: \"", game_menu.text, "\", style=0x", std::hex, game_menu.style,
                ", id=", std::dec, game_menu.id);
        CHECK(game_menu.text.find("Game") != std::string::npos);
        CHECK(game_menu.has_submenu());
        CHECK(game_menu.id == 8100);

        // Check submenu items
        MESSAGE("  Submenu has ", game_menu.submenu.size(), " items");
        CHECK(game_menu.submenu.size() > 0);

        // Print submenu items for verification
        for (size_t i = 0; i < std::min(game_menu.submenu.size(), size_t(5)); ++i) {
            const auto& sub = game_menu.submenu[i];
            if (sub.is_separator()) {
                MESSAGE("  [", i, "] SEPARATOR");
            } else {
                MESSAGE("  [", i, "] \"", sub.text, "\", id=", sub.id);
            }
        }
    }
}
