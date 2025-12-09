#include <doctest/doctest.h>
#include <libexe/formats/ne_file.hpp>
#include <libexe/resources/resource.hpp>
#include <libexe/resources/parsers/icon_group_parser.hpp>
#include <libexe/resources/parsers/icon_parser.hpp>

using namespace libexe;

// External test data - PROGMAN.EXE (Windows 3.11 Program Manager)
namespace data {
    extern size_t progman_len;
    extern unsigned char progman[];
}

namespace {

std::vector<uint8_t> load_progman() {
    return std::vector<uint8_t>(
        data::progman,
        data::progman + data::progman_len
    );
}

} // anonymous namespace

TEST_SUITE("Icon Resource Parsers") {
    TEST_CASE("Parse RT_GROUP_ICON from PROGMAN.EXE") {
        // Load PROGMAN.EXE from embedded data
        auto data = load_progman();
        auto ne = ne_file::from_memory(data);

        REQUIRE(ne.has_resources());

        auto rsrc = ne.resources();
        REQUIRE(rsrc != nullptr);

        SUBCASE("Find and parse first icon group") {
            // PROGMAN.EXE has icon groups - find the first one
            auto icon_groups = rsrc->resources_by_type(resource_type::RT_GROUP_ICON);
            REQUIRE(!icon_groups.empty());

            auto& first_group = icon_groups[0];
            auto parsed = icon_group_parser::parse(first_group.data());

            REQUIRE(parsed.has_value());
            // Note: RT_GROUP_ICON can contain both icons (type=2) and cursors (type=1)
            CHECK((parsed->type == 1 || parsed->type == 2));
            CHECK(parsed->count > 0);
            CHECK(parsed->entries.size() == parsed->count);
        }

        SUBCASE("Use convenience method as_icon_group()") {
            // Test the convenience API
            auto icon_groups = rsrc->resources_by_type(resource_type::RT_GROUP_ICON);
            REQUIRE(!icon_groups.empty());

            // Use convenience method instead of explicit parser call
            auto parsed = icon_groups[0].as_icon_group();

            REQUIRE(parsed.has_value());
            CHECK((parsed->type == 1 || parsed->type == 2));
            CHECK(parsed->count > 0);
            CHECK(parsed->entries.size() == parsed->count);
        }

        SUBCASE("Verify all icon groups parse successfully") {
            auto icon_groups = rsrc->resources_by_type(resource_type::RT_GROUP_ICON);

            for (const auto& group_entry : icon_groups) {
                auto parsed = icon_group_parser::parse(group_entry.data());
                REQUIRE(parsed.has_value());

                // Verify structure
                // Note: type can be 1 (cursor) or 2 (icon) - both are valid
                CHECK((parsed->type == 1 || parsed->type == 2));
                CHECK(parsed->count == parsed->entries.size());

                // Verify each entry
                for (const auto& entry : parsed->entries) {
                    // Resource ID can be 0 for some entries
                    CHECK(entry.size_in_bytes > 0);

                    // Width/height should be reasonable (1-256)
                    uint16_t width = entry.actual_width();
                    uint16_t height = entry.actual_height();
                    CHECK(width >= 1);
                    CHECK(width <= 256);
                    CHECK(height >= 1);
                    CHECK(height <= 256);
                }
            }
        }

        SUBCASE("Parse RT_ICON directly") {
            // Get any RT_ICON resource
            auto icons = rsrc->resources_by_type(resource_type::RT_ICON);
            REQUIRE(!icons.empty());

            // Parse first icon image
            auto icon = icon_parser::parse(icons[0].data());
            REQUIRE(icon.has_value());

            // Verify DIB header
            CHECK(icon->header.size == 40);  // BITMAPINFOHEADER
            CHECK(icon->header.width > 0);
            CHECK(icon->header.height > 0);
            CHECK(icon->header.planes == 1);

            // Verify XOR and AND masks exist
            CHECK(!icon->xor_mask.empty());
            CHECK(!icon->and_mask.empty());
        }

        SUBCASE("Use convenience method as_icon()") {
            // Test the convenience API
            auto icons = rsrc->resources_by_type(resource_type::RT_ICON);
            REQUIRE(!icons.empty());

            // Use convenience method instead of explicit parser call
            auto icon = icons[0].as_icon();
            REQUIRE(icon.has_value());

            // Verify it works the same way
            CHECK(icon->header.size == 40);
            CHECK(icon->header.width > 0);
            CHECK(icon->header.height > 0);
            CHECK(icon->header.planes == 1);
            CHECK(!icon->xor_mask.empty());
            CHECK(!icon->and_mask.empty());
        }

        SUBCASE("Export icon to .ICO file format") {
            // Get any icon
            auto icons = rsrc->resources_by_type(resource_type::RT_ICON);
            REQUIRE(!icons.empty());

            auto icon = icon_parser::parse(icons[0].data());
            REQUIRE(icon.has_value());

            // Export to .ICO format
            auto ico_data = icon->to_ico_file();

            // Verify .ICO file structure
            REQUIRE(ico_data.size() > 22);  // At least ICONDIR + ICONDIRENTRY

            // Check .ICO header
            uint16_t reserved = ico_data[0] | (ico_data[1] << 8);
            uint16_t type = ico_data[2] | (ico_data[3] << 8);
            uint16_t count = ico_data[4] | (ico_data[5] << 8);

            CHECK(reserved == 0);
            CHECK(type == 2);  // Icon type
            CHECK(count == 1);  // Single icon
        }

        SUBCASE("Verify all icons can be parsed") {
            auto icons = rsrc->resources_by_type(resource_type::RT_ICON);

            for (const auto& icon_entry : icons) {
                auto parsed = icon_parser::parse(icon_entry.data());
                REQUIRE(parsed.has_value());

                // Basic validation
                CHECK(parsed->header.size == 40);
                CHECK(!parsed->xor_mask.empty());
                CHECK(!parsed->and_mask.empty());
            }
        }

    }

    TEST_CASE("Icon parser error handling") {
        SUBCASE("Empty data") {
            std::vector<uint8_t> empty;
            auto result = icon_group_parser::parse(empty);
            CHECK_FALSE(result.has_value());

            auto icon_result = icon_parser::parse(empty);
            CHECK_FALSE(icon_result.has_value());
        }

        SUBCASE("Truncated data") {
            // Icon group header needs at least 8 bytes, but if wCount > 0,
            // it needs more. Test with 5 bytes which is definitely too small.
            std::vector<uint8_t> truncated(5, 0);
            auto result = icon_group_parser::parse(truncated);
            CHECK_FALSE(result.has_value());

            // Icon parser needs at least 40 bytes for BITMAPINFOHEADER
            std::vector<uint8_t> icon_truncated(10, 0);
            auto icon_result = icon_parser::parse(icon_truncated);
            CHECK_FALSE(icon_result.has_value());
        }

        SUBCASE("Invalid DIB header size") {
            std::vector<uint8_t> bad_header(40, 0);
            bad_header[0] = 50;  // Invalid size (should be 40)
            auto result = icon_parser::parse(bad_header);
            CHECK_FALSE(result.has_value());
        }
    }
}
