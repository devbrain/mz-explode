// libexe - Modern executable file analysis library
// Unit tests for RT_STRING and RT_ACCELERATOR resource parsers

#include <doctest/doctest.h>
#include <libexe/formats/ne_file.hpp>
#include <libexe/resources/resource.hpp>
#include <libexe/resources/parsers/string_table_parser.hpp>
#include <libexe/resources/parsers/accelerator_parser.hpp>
#include <filesystem>
#include <vector>

using namespace libexe;

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

TEST_CASE("RT_STRING and RT_ACCELERATOR parsers - PROGMAN.EXE") {
    auto data = load_progman();
    REQUIRE(!data.empty());

    auto exe = ne_file::from_memory(data);
    REQUIRE(exe.has_resources());

    auto rsrc = exe.resources();
    REQUIRE(rsrc != nullptr);

    auto all_resources = rsrc->all_resources();

    SUBCASE("String table resources exist") {
        auto string_resources = all_resources.filter_by_type(resource_type::RT_STRING);
        CHECK_FALSE(string_resources.empty());
        CHECK(string_resources.size() == 9);  // PROGMAN has 9 string blocks

        for (size_t i = 0; i < string_resources.size(); i++) {
            const auto& res = string_resources[i];
            CHECK(res.standard_type() == resource_type::RT_STRING);
            CHECK(res.size() > 0);
        }
    }

    SUBCASE("Parse string table blocks") {
        auto string_resources = all_resources.filter_by_type(resource_type::RT_STRING);
        REQUIRE(string_resources.size() > 0);

        size_t total_strings = 0;

        for (size_t block_idx = 0; block_idx < string_resources.size(); block_idx++) {
            const auto& res = string_resources[block_idx];
            auto string_table = string_table_parser::parse(
                res.data(),
                res.id().value(),
                windows_resource_format::NE  // PROGMAN.EXE is an NE Windows file
            );

            CHECK(string_table.has_value());
            if (string_table.has_value()) {
                // Verify block ID matches resource ID
                CHECK(string_table->block_id == res.id().value());

                // Verify base string ID calculation
                uint16_t expected_base = (string_table->block_id - 1) * 16;
                CHECK(string_table->base_string_id() == expected_base);

                // Count strings in this block
                size_t block_string_count = string_table->strings.size();
                total_strings += block_string_count;

                CHECK(block_string_count > 0);
                CHECK(block_string_count <= 16);  // Max 16 strings per block

                // Verify each string
                for (const auto& [string_id, text] : string_table->strings) {
                    // String ID should be in valid range for this block
                    CHECK(string_id >= expected_base);
                    CHECK(string_id < expected_base + 16);

                    // String should not be empty
                    CHECK_FALSE(text.empty());

                    // has_string() should work
                    CHECK(string_table->has_string(string_id));

                    // get_string() should return the same text
                    CHECK(string_table->get_string(string_id) == text);
                }

                // Test get_string() with non-existent ID
                uint16_t invalid_id = expected_base + 100;
                CHECK(string_table->get_string(invalid_id) == "");
                CHECK_FALSE(string_table->has_string(invalid_id));
            }
        }

        CHECK(total_strings > 0);
    }

    SUBCASE("Use convenience method as_string_table()") {
        auto string_resources = all_resources.filter_by_type(resource_type::RT_STRING);
        REQUIRE(string_resources.size() > 0);

        const auto& first_block = string_resources[0];
        auto string_table = first_block.as_string_table();

        CHECK(string_table.has_value());
        if (string_table.has_value()) {
            CHECK(string_table->block_id == first_block.id().value());
            CHECK_FALSE(string_table->strings.empty());
        }
    }

    SUBCASE("Accelerator table resources exist") {
        auto accel_resources = all_resources.filter_by_type(resource_type::RT_ACCELERATOR);
        CHECK_FALSE(accel_resources.empty());
        CHECK(accel_resources.size() == 1);  // PROGMAN has 1 accelerator table

        if (!accel_resources.empty()) {
            const auto& res = accel_resources[0];
            CHECK(res.standard_type() == resource_type::RT_ACCELERATOR);
            CHECK(res.size() > 0);
            CHECK((res.size() % 8) == 0);  // Each entry is 8 bytes
        }
    }

    SUBCASE("Parse accelerator table") {
        auto accel_resources = all_resources.filter_by_type(resource_type::RT_ACCELERATOR);
        REQUIRE(accel_resources.size() > 0);

        const auto& res = accel_resources[0];
        auto accel_table = accelerator_parser::parse(res.data());

        CHECK(accel_table.has_value());
        if (accel_table.has_value()) {
            CHECK_FALSE(accel_table->empty());
            CHECK(accel_table->count() > 0);

            // Verify each accelerator entry
            for (const auto& entry : accel_table->entries) {
                // Check flag accessors
                bool has_modifiers = entry.requires_control() ||
                                   entry.requires_shift() ||
                                   entry.requires_alt();

                // Command ID 0 is valid (can be used for disabled/separator entries)
                // Just verify it's within uint16 range (always true, but documents intent)
                CHECK(entry.command_id >= 0);

                // Key code should be valid
                CHECK(entry.key != 0);

                // Get string representation
                std::string key_combo = entry.to_string();
                CHECK_FALSE(key_combo.empty());

                // If has modifiers, string should contain '+'
                if (has_modifiers) {
                    CHECK(key_combo.find('+') != std::string::npos);
                }
            }

            // Test find_by_command()
            if (accel_table->count() > 0) {
                uint16_t first_cmd = accel_table->entries[0].command_id;
                const auto* found = accel_table->find_by_command(first_cmd);
                CHECK(found != nullptr);
                if (found) {
                    CHECK(found->command_id == first_cmd);
                }

                // Test with non-existent command
                const auto* not_found = accel_table->find_by_command(0xFFFF);
                CHECK(not_found == nullptr);
            }
        }
    }

    SUBCASE("Use convenience method as_accelerator_table()") {
        auto accel_resources = all_resources.filter_by_type(resource_type::RT_ACCELERATOR);
        REQUIRE(accel_resources.size() > 0);

        const auto& res = accel_resources[0];
        auto accel_table = res.as_accelerator_table();

        CHECK(accel_table.has_value());
        if (accel_table.has_value()) {
            CHECK_FALSE(accel_table->empty());
        }
    }

    SUBCASE("Verify accelerator flag enums") {
        auto accel_resources = all_resources.filter_by_type(resource_type::RT_ACCELERATOR);
        REQUIRE(accel_resources.size() > 0);

        auto accel_table = accelerator_parser::parse(accel_resources[0].data());
        REQUIRE(accel_table.has_value());

        // Verify flag checking is consistent
        for (const auto& entry : accel_table->entries) {
            bool virtkey = (entry.flags & static_cast<uint16_t>(accelerator_flags::VIRTKEY)) != 0;
            CHECK(entry.is_virtkey() == virtkey);

            bool shift = (entry.flags & static_cast<uint16_t>(accelerator_flags::SHIFT)) != 0;
            CHECK(entry.requires_shift() == shift);

            bool control = (entry.flags & static_cast<uint16_t>(accelerator_flags::CONTROL)) != 0;
            CHECK(entry.requires_control() == control);

            bool alt = (entry.flags & static_cast<uint16_t>(accelerator_flags::ALT)) != 0;
            CHECK(entry.requires_alt() == alt);
        }
    }

    SUBCASE("Test accelerator to_string() formatting") {
        auto accel_resources = all_resources.filter_by_type(resource_type::RT_ACCELERATOR);
        REQUIRE(accel_resources.size() > 0);

        auto accel_table = accelerator_parser::parse(accel_resources[0].data());
        REQUIRE(accel_table.has_value());

        // Count different modifier combinations
        size_t ctrl_only = 0, shift_only = 0, alt_only = 0;
        size_t ctrl_shift = 0, ctrl_alt = 0, shift_alt = 0;
        size_t all_mods = 0, no_mods = 0;

        for (const auto& entry : accel_table->entries) {
            bool c = entry.requires_control();
            bool s = entry.requires_shift();
            bool a = entry.requires_alt();

            if (c && s && a) all_mods++;
            else if (c && s) ctrl_shift++;
            else if (c && a) ctrl_alt++;
            else if (s && a) shift_alt++;
            else if (c) ctrl_only++;
            else if (s) shift_only++;
            else if (a) alt_only++;
            else no_mods++;

            // Verify string format
            std::string str = entry.to_string();
            if (c) CHECK(str.find("Ctrl") != std::string::npos);
            if (s) CHECK(str.find("Shift") != std::string::npos);
            if (a) CHECK(str.find("Alt") != std::string::npos);
        }

        // Just verify we found some entries
        CHECK((ctrl_only + shift_only + alt_only + ctrl_shift + ctrl_alt +
               shift_alt + all_mods + no_mods) == accel_table->count());
    }
}

TEST_CASE("String table parser - error handling") {
    SUBCASE("Empty data") {
        std::vector<uint8_t> empty;
        auto result = string_table_parser::parse(empty, 1, windows_resource_format::PE);
        CHECK_FALSE(result.has_value());
    }

    SUBCASE("Block ID calculation") {
        // Create minimal valid string table (empty strings)
        std::vector<uint8_t> data;
        for (int i = 0; i < 16; i++) {
            data.push_back(0x00);  // length = 0
            data.push_back(0x00);
        }

        // Test various block IDs
        for (uint16_t block_id = 1; block_id <= 10; block_id++) {
            auto result = string_table_parser::parse(data, block_id, windows_resource_format::PE);
            if (result.has_value()) {
                CHECK(result->block_id == block_id);
                uint16_t expected_base = (block_id - 1) * 16;
                CHECK(result->base_string_id() == expected_base);
            }
        }
    }
}

TEST_CASE("Accelerator parser - error handling") {
    SUBCASE("Empty data") {
        std::vector<uint8_t> empty;
        auto result = accelerator_parser::parse(empty);
        CHECK_FALSE(result.has_value());
    }

    SUBCASE("Too small data") {
        std::vector<uint8_t> small = {0x01, 0x02, 0x03};  // Less than 8 bytes
        auto result = accelerator_parser::parse(small);
        CHECK_FALSE(result.has_value());
    }

    SUBCASE("Single entry with END flag") {
        std::vector<uint8_t> data = {
            0x80, 0x00,  // flags = END
            0x41, 0x00,  // key = 'A'
            0x01, 0x00,  // command_id = 1
            0x00, 0x00   // padding
        };

        auto result = accelerator_parser::parse(data);
        CHECK(result.has_value());
        if (result.has_value()) {
            CHECK(result->count() == 1);
            CHECK(result->entries[0].command_id == 1);
        }
    }
}

TEST_CASE("Accelerator entry - key name formatting") {
    SUBCASE("Virtual key names") {
        accelerator_entry entry;
        entry.flags = static_cast<uint16_t>(accelerator_flags::VIRTKEY);
        entry.command_id = 1;

        // Test function keys
        entry.key = 0x70;  // F1
        CHECK(entry.to_string() == "F1");

        entry.key = 0x7B;  // F12
        CHECK(entry.to_string() == "F12");

        // Test special keys
        entry.key = 0x0D;  // Enter
        CHECK(entry.to_string() == "Enter");

        entry.key = 0x1B;  // Esc
        CHECK(entry.to_string() == "Esc");

        entry.key = 0x2E;  // Delete
        CHECK(entry.to_string() == "Delete");
    }

    SUBCASE("Modifier combinations") {
        accelerator_entry entry;
        entry.flags = static_cast<uint16_t>(accelerator_flags::VIRTKEY) |
                     static_cast<uint16_t>(accelerator_flags::CONTROL);
        entry.key = 'S';
        entry.command_id = 1;

        CHECK(entry.to_string() == "Ctrl+S");

        // Add Shift
        entry.flags |= static_cast<uint16_t>(accelerator_flags::SHIFT);
        CHECK(entry.to_string() == "Ctrl+Shift+S");

        // Add Alt
        entry.flags |= static_cast<uint16_t>(accelerator_flags::ALT);
        CHECK(entry.to_string() == "Ctrl+Shift+Alt+S");
    }

    SUBCASE("ASCII characters") {
        accelerator_entry entry;
        entry.flags = 0;  // Not VIRTKEY
        entry.command_id = 1;

        entry.key = 'X';
        CHECK(entry.to_string() == "X");

        entry.key = '5';
        CHECK(entry.to_string() == "5");
    }
}
