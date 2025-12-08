#include <doctest/doctest.h>
#include <libexe/ne_file.hpp>
#include <libexe/resources/resource.hpp>
#include <libexe/resources/parsers/menu_parser.hpp>
#include <filesystem>
#include <iostream>
#include <iomanip>
#include <vector>

// External test data (embedded PROGMAN.EXE)
namespace data {
    extern size_t progman_len;
    extern unsigned char progman[];
}

namespace {
    // Load PROGMAN.EXE from embedded data
    std::vector<uint8_t> load_progman() {
        return std::vector<uint8_t>(
            data::progman,
            data::progman + data::progman_len
        );
    }
}

TEST_SUITE("Menu Parser") {
    /**
     * Test parsing menu from NE executable (progman.exe).
     *
     * This test verifies that the menu parser can correctly parse
     * the hierarchical menu structure from a real Windows 3.1 executable.
     */
    TEST_CASE("Parse NE menu resource") {
        auto data = load_progman();
        REQUIRE(!data.empty());

        auto ne = libexe::ne_file::from_memory(data);
        REQUIRE(ne.has_resources());

        auto rsrc = ne.resources();
        REQUIRE(rsrc != nullptr);

        // Get menu resource (should be exactly 1)
        auto menus = rsrc->resources_by_type(libexe::resource_type::RT_MENU);
        REQUIRE(menus.size() == 1);

        // Parse the menu
        auto menu_opt = libexe::menu_parser::parse(menus[0].data());
        REQUIRE(menu_opt.has_value());

        const auto& menu = menu_opt.value();

        // Validate menu header
        CHECK(menu.version == 0);
        CHECK(menu.header_size == 0);

        // Validate top-level menu items exist
        CHECK(menu.items.size() > 0);

        // Check that we have popup menus
        size_t popup_count = 0;
        size_t normal_count = 0;

        for (const auto& item : menu.items) {
            if (item.is_popup()) {
                popup_count++;
                // Popup menus should have children
                CHECK(item.children.size() > 0);
                // Popup menus should have no command ID
                CHECK(item.command_id == 0);
                // Popup menus should have text
                CHECK_FALSE(item.text.empty());

                // Validate child items
                for (const auto& child : item.children) {
                    if (!child.is_separator()) {
                        // Normal items should have command ID
                        CHECK(child.command_id != 0);
                        // Normal items should have text
                        CHECK_FALSE(child.text.empty());
                    }
                    normal_count++;
                }
            }
        }

        // Should have at least some popup menus (File, Edit, etc.)
        CHECK(popup_count > 0);
        // Should have at least some normal menu items
        CHECK(normal_count > 0);

        MESSAGE("Found ", popup_count, " popup menus with ", normal_count, " total items");
    }

    /**
     * Test menu item flag detection.
     *
     * Verifies that menu item helper methods correctly identify
     * popup menus, separators, and other item types.
     */
    TEST_CASE("Menu item flag detection") {
        libexe::menu_item popup_item;
        popup_item.flags = static_cast<uint16_t>(libexe::menu_flags::POPUP);
        popup_item.text = "File";
        popup_item.command_id = 0;

        CHECK(popup_item.is_popup());
        CHECK_FALSE(popup_item.is_separator());
        CHECK_FALSE(popup_item.is_grayed());
        CHECK_FALSE(popup_item.is_checked());

        libexe::menu_item separator;
        separator.flags = 0;
        separator.text = "";
        separator.command_id = 0;

        CHECK_FALSE(separator.is_popup());
        CHECK(separator.is_separator());

        libexe::menu_item grayed_item;
        grayed_item.flags = static_cast<uint16_t>(libexe::menu_flags::GRAYED);
        grayed_item.text = "Disabled Item";
        grayed_item.command_id = 100;

        CHECK(grayed_item.is_grayed());
        CHECK_FALSE(grayed_item.is_popup());
        CHECK_FALSE(grayed_item.is_separator());

        libexe::menu_item checked_item;
        checked_item.flags = static_cast<uint16_t>(libexe::menu_flags::CHECKED);
        checked_item.text = "Checked Item";
        checked_item.command_id = 101;

        CHECK(checked_item.is_checked());
        CHECK_FALSE(checked_item.is_grayed());

        libexe::menu_item end_item;
        end_item.flags = static_cast<uint16_t>(libexe::menu_flags::END);
        end_item.text = "Last Item";
        end_item.command_id = 102;

        CHECK(end_item.is_end());
    }

    /**
     * Test parsing invalid/empty menu data.
     *
     * Verifies that the parser handles edge cases gracefully.
     */
    TEST_CASE("Parse invalid menu data") {
        // Empty data
        std::vector<uint8_t> empty_data;
        auto result = libexe::menu_parser::parse(empty_data);
        CHECK_FALSE(result.has_value());

        // Too small (less than header size)
        std::vector<uint8_t> small_data = {0x00, 0x01};
        result = libexe::menu_parser::parse(small_data);
        CHECK_FALSE(result.has_value());

        // Header only (valid but no items)
        std::vector<uint8_t> header_only = {
            0x00, 0x00,  // version
            0x00, 0x00   // header_size
        };
        result = libexe::menu_parser::parse(header_only);
        // This should succeed with an empty menu
        if (result.has_value()) {
            CHECK(result->items.empty());
        }
    }

    /**
     * Test menu template item counting.
     *
     * Verifies that the recursive item counting works correctly.
     */
    TEST_CASE("Menu template item counting") {
        libexe::menu_template menu;
        menu.version = 0;
        menu.header_size = 0;

        // Create a simple menu structure
        libexe::menu_item file_menu;
        file_menu.flags = static_cast<uint16_t>(libexe::menu_flags::POPUP);
        file_menu.text = "File";
        file_menu.command_id = 0;

        libexe::menu_item new_item;
        new_item.flags = 0;
        new_item.text = "New";
        new_item.command_id = 100;

        libexe::menu_item open_item;
        open_item.flags = 0;
        open_item.text = "Open";
        open_item.command_id = 101;

        file_menu.children.push_back(new_item);
        file_menu.children.push_back(open_item);

        menu.items.push_back(file_menu);

        // Should count: 1 popup + 2 children = 3 total
        CHECK(menu.count_all_items() == 3);

        // Add another top-level item
        libexe::menu_item edit_menu;
        edit_menu.flags = static_cast<uint16_t>(libexe::menu_flags::POPUP);
        edit_menu.text = "Edit";
        edit_menu.command_id = 0;

        libexe::menu_item cut_item;
        cut_item.flags = 0;
        cut_item.text = "Cut";
        cut_item.command_id = 200;

        edit_menu.children.push_back(cut_item);
        menu.items.push_back(edit_menu);

        // Should count: 2 popups + 3 children = 5 total
        CHECK(menu.count_all_items() == 5);
    }
}
