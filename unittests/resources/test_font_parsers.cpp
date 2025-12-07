#include <doctest/doctest.h>
#include <libexe/ne_file.hpp>
#include <libexe/resources/resource.hpp>
#include <libexe/resources/parsers/font_parser.hpp>

using namespace libexe;

// External test data - CGA40WOA.FON (Windows 3.11 CGA font)
namespace data {
    extern size_t cga40woa_fon_len;
    extern unsigned char cga40woa_fon[];
}

namespace {

std::vector<uint8_t> load_cga40woa() {
    return std::vector<uint8_t>(
        data::cga40woa_fon,
        data::cga40woa_fon + data::cga40woa_fon_len
    );
}

} // anonymous namespace

TEST_SUITE("Font Resource Parsers") {
    TEST_CASE("Parse RT_FONT from CGA40WOA.FON") {
        // Load CGA40WOA.FON from embedded data
        auto data = load_cga40woa();
        auto ne = ne_file::from_memory(data);

        REQUIRE(ne.has_resources());

        auto rsrc = ne.resources();
        REQUIRE(rsrc != nullptr);

        SUBCASE("Find and parse font resource") {
            // CGA40WOA.FON has font resources
            auto fonts = rsrc->resources_by_type(resource_type::RT_FONT);
            REQUIRE(!fonts.empty());

            auto& first_font = fonts[0];
            auto parsed = font_parser::parse(first_font.data());

            REQUIRE(parsed.has_value());

            // Verify font metadata
            CHECK(parsed->version >= 0x0200);  // Windows 2.x or later
            CHECK(parsed->size > 0);

            // Verify font metrics
            CHECK(parsed->points > 0);
            CHECK(parsed->pixel_height > 0);

            // Verify character range
            CHECK(parsed->first_char <= parsed->last_char);
            CHECK(parsed->character_count() > 0);

            // Verify glyph table
            CHECK(parsed->glyphs.size() >= parsed->character_count());

            // Verify bitmap data exists
            CHECK(!parsed->bitmap_data.empty());
        }

        SUBCASE("Verify font properties") {
            auto fonts = rsrc->resources_by_type(resource_type::RT_FONT);
            REQUIRE(!fonts.empty());

            auto font = font_parser::parse(fonts[0].data());
            REQUIRE(font.has_value());

            // CGA fonts are typically fixed-pitch raster fonts
            CHECK(font->type == font_type::RASTER);

            // Check that face name is not empty
            CHECK(!font->face_name.empty());

            // Verify dimensions are reasonable
            CHECK(font->pixel_height >= 1);
            CHECK(font->pixel_height <= 100);  // Reasonable upper limit

            if (font->pixel_width > 0) {
                CHECK(font->pixel_width <= 100);
            }

            // Verify character range is ASCII or extended ASCII
            CHECK(font->first_char >= 0);
            CHECK(font->last_char <= 255);
        }

        SUBCASE("Extract character bitmaps") {
            auto fonts = rsrc->resources_by_type(resource_type::RT_FONT);
            REQUIRE(!fonts.empty());

            auto font = font_parser::parse(fonts[0].data());
            REQUIRE(font.has_value());

            // Try to get bitmap for a common character (space, 'A', etc.)
            for (uint8_t c = font->first_char; c <= font->last_char; ++c) {
                auto bitmap = font->get_char_bitmap(c);

                // Not all characters may have bitmaps, but the method should not crash
                if (!bitmap.empty()) {
                    // Calculate expected size
                    size_t glyph_index = c - font->first_char;
                    if (glyph_index < font->glyphs.size()) {
                        const auto& glyph = font->glyphs[glyph_index];
                        size_t bytes_per_row = (glyph.width + 7) / 8;
                        size_t expected_size = bytes_per_row * font->pixel_height;

                        CHECK(bitmap.size() == expected_size);
                    }
                }

                // Only check a few characters to keep test fast
                if (c > font->first_char + 10) {
                    break;
                }
            }
        }

        SUBCASE("Get bitmap for specific characters") {
            auto fonts = rsrc->resources_by_type(resource_type::RT_FONT);
            REQUIRE(!fonts.empty());

            auto font = font_parser::parse(fonts[0].data());
            REQUIRE(font.has_value());

            // Try letter 'A' if it's in range
            if ('A' >= font->first_char && 'A' <= font->last_char) {
                auto bitmap = font->get_char_bitmap('A');
                CHECK(!bitmap.empty());
            }

            // Try space character
            if (' ' >= font->first_char && ' ' <= font->last_char) {
                auto bitmap = font->get_char_bitmap(' ');
                // Space might be empty or have a bitmap
            }

            // Try character outside range - should return empty span
            // Only test if there's a character code outside the font's range
            uint8_t out_of_range = 0;
            if (font->first_char > 0) {
                out_of_range = font->first_char - 1;
            } else if (font->last_char < 255) {
                out_of_range = font->last_char + 1;
            }

            if (out_of_range < font->first_char || out_of_range > font->last_char) {
                auto bitmap = font->get_char_bitmap(out_of_range);
                CHECK(bitmap.empty());
            }
        }

        SUBCASE("Verify all fonts parse successfully") {
            auto fonts = rsrc->resources_by_type(resource_type::RT_FONT);

            for (const auto& font_entry : fonts) {
                auto parsed = font_parser::parse(font_entry.data());
                REQUIRE(parsed.has_value());

                // Basic validation
                CHECK(parsed->version >= 0x0200);
                CHECK(parsed->size > 0);
                CHECK(!parsed->glyphs.empty());
                CHECK(!parsed->bitmap_data.empty());
            }
        }

        SUBCASE("Check font weight values") {
            auto fonts = rsrc->resources_by_type(resource_type::RT_FONT);
            REQUIRE(!fonts.empty());

            auto font = font_parser::parse(fonts[0].data());
            REQUIRE(font.has_value());

            // Font weight should be in valid range (100-900)
            // Common values: 400 = normal, 700 = bold
            CHECK(font->weight >= 100);
            CHECK(font->weight <= 900);
        }
    }

    TEST_CASE("Font parser error handling") {
        SUBCASE("Empty data") {
            std::vector<uint8_t> empty;
            auto result = font_parser::parse(empty);
            CHECK_FALSE(result.has_value());
        }

        SUBCASE("Truncated data") {
            // Font header is 118 bytes
            std::vector<uint8_t> truncated(50, 0);
            auto result = font_parser::parse(truncated);
            CHECK_FALSE(result.has_value());
        }

        SUBCASE("Invalid version") {
            // Create minimal header with invalid version
            std::vector<uint8_t> bad_header(118, 0);
            // Version at offset 0: set to 0x0000 (invalid)
            bad_header[0] = 0x00;
            bad_header[1] = 0x00;
            auto result = font_parser::parse(bad_header);
            // Parser might still parse it, just verify it doesn't crash
        }
    }
}
