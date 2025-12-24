#include <doctest/doctest.h>
#include <libexe/formats/ne_file.hpp>
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

        // CGA40WOA.FON has 1 font resource
        auto fonts = rsrc->resources_by_type(resource_type::RT_FONT);
        REQUIRE(fonts.size() == 1);

        auto parsed = font_parser::parse(fonts[0].data());
        REQUIRE(parsed.has_value());

        SUBCASE("Verify font metadata") {
            // Expected values from dewinfont.py reference implementation:
            // version: 512 (0x0200 = Windows 2.x)
            // size: 5219
            // copyright: '(c) Copyright Bitstream Inc. 1984. All rights reserved.'
            // type: 0 (RASTER)
            CHECK(parsed->version == 0x0200);
            CHECK(parsed->size == 5219);
            CHECK(parsed->copyright == "(c) Copyright Bitstream Inc. 1984. All rights reserved.");
            CHECK(parsed->type == font_type::RASTER);
        }

        SUBCASE("Verify font metrics") {
            // Expected values from dewinfont.py:
            // points: 9
            // vert_res: 48
            // horiz_res: 160
            // ascent: 7
            // internal_leading: 0
            // external_leading: 0
            CHECK(parsed->points == 9);
            CHECK(parsed->vertical_res == 48);
            CHECK(parsed->horizontal_res == 160);
            CHECK(parsed->ascent == 7);
            CHECK(parsed->internal_leading == 0);
            CHECK(parsed->external_leading == 0);
        }

        SUBCASE("Verify font appearance") {
            // Expected values from dewinfont.py:
            // italic: False
            // underline: False
            // strikeout: False
            // weight: 400
            // charset: 255
            CHECK(parsed->italic == false);
            CHECK(parsed->underline == false);
            CHECK(parsed->strikeout == false);
            CHECK(parsed->weight == 400);
            CHECK(parsed->charset == 255);
        }

        SUBCASE("Verify character dimensions") {
            // Expected values from dewinfont.py:
            // pixel_width: 16
            // pixel_height: 8
            // avg_width: 16
            // max_width: 16
            CHECK(parsed->pixel_width == 16);
            CHECK(parsed->pixel_height == 8);
            CHECK(parsed->avg_width == 16);
            CHECK(parsed->max_width == 16);
        }

        SUBCASE("Verify character range") {
            // Expected values from dewinfont.py:
            // first_char: 1
            // last_char: 254
            // default_char: 31
            // break_char: 31
            // char_count: 254
            CHECK(parsed->first_char == 1);
            CHECK(parsed->last_char == 254);
            CHECK(parsed->default_char == 31);
            CHECK(parsed->break_char == 31);
            CHECK(parsed->character_count() == 254);
        }

        SUBCASE("Verify font family and face name") {
            // Expected values from dewinfont.py:
            // pitch_and_family: 48 (0x30 = MODERN family)
            // face_name: 'Terminal'
            CHECK(parsed->family == font_family::MODERN);
            CHECK(parsed->face_name == "Terminal");
        }

        SUBCASE("Verify glyph table") {
            // Should have at least as many glyphs as characters
            CHECK(parsed->glyphs.size() >= parsed->character_count());

            // Verify bitmap data exists
            CHECK(!parsed->bitmap_data.empty());
        }

        SUBCASE("Verify character bitmaps") {
            // This is a fixed-width font (pixel_width > 0 means fixed pitch)
            // Note: pixel_width = 16 means all chars are 16 pixels wide
            CHECK(parsed->pixel_width == 16);

            // Check a few character widths - all should be 16
            for (size_t i = 0; i < std::min(size_t(10), parsed->glyphs.size()); ++i) {
                CHECK(parsed->glyphs[i].width == 16);
            }

            // Get bitmap for letter 'A' (should be 16x8 = 2 bytes/row * 8 rows = 16 bytes)
            auto bitmap_A = parsed->get_char_bitmap('A');
            CHECK(!bitmap_A.empty());
            CHECK(bitmap_A.size() == 16);  // 2 bytes/row * 8 rows

            // Get bitmap for space character
            auto bitmap_space = parsed->get_char_bitmap(' ');
            CHECK(!bitmap_space.empty());
        }

        SUBCASE("Verify out-of-range character returns empty") {
            // Character 0 is before first_char (1)
            auto bitmap_0 = parsed->get_char_bitmap(0);
            CHECK(bitmap_0.empty());

            // Character 255 is after last_char (254)
            auto bitmap_255 = parsed->get_char_bitmap(255);
            CHECK(bitmap_255.empty());
        }
    }

    TEST_CASE("Font parser error handling") {
        SUBCASE("Empty data") {
            std::vector<uint8_t> empty;
            auto result = font_parser::parse(empty);
            CHECK_FALSE(result.has_value());
        }

        SUBCASE("Truncated data") {
            // Font header is 118 bytes minimum
            std::vector<uint8_t> truncated(50, 0);
            auto result = font_parser::parse(truncated);
            CHECK_FALSE(result.has_value());
        }
    }
}
