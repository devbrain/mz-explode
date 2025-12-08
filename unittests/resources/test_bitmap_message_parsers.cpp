#include <doctest/doctest.h>
#include <libexe/resources/parsers/bitmap_parser.hpp>
#include <libexe/resources/parsers/message_table_parser.hpp>

TEST_SUITE("Bitmap and Message Table Parsers") {
    /**
     * Test bitmap parser with minimal valid bitmap
     */
    TEST_CASE("Parse minimal bitmap (BITMAPINFOHEADER)") {
        // Create a minimal 1x1 24-bit bitmap (BITMAPINFOHEADER + pixel data)
        std::vector<uint8_t> bitmap_data = {
            // BITMAPINFOHEADER (40 bytes)
            40, 0, 0, 0,        // header_size = 40
            1, 0, 0, 0,         // width = 1
            1, 0, 0, 0,         // height = 1
            1, 0,               // planes = 1
            24, 0,              // bit_count = 24 (24 bpp)
            0, 0, 0, 0,         // compression = BI_RGB
            0, 0, 0, 0,         // size_image = 0 (can be 0 for RGB)
            0, 0, 0, 0,         // x_pels_per_meter = 0
            0, 0, 0, 0,         // y_pels_per_meter = 0
            0, 0, 0, 0,         // clr_used = 0
            0, 0, 0, 0,         // clr_important = 0
            // Pixel data (1 pixel * 3 bytes + 1 padding byte = 4 bytes)
            0xFF, 0xFF, 0xFF, 0x00  // White pixel (BGR) + padding
        };

        auto result = libexe::bitmap_parser::parse(bitmap_data);
        REQUIRE(result.has_value());

        const auto& bmp = result.value();
        CHECK(bmp.info.header_size == 40);
        CHECK(bmp.info.width == 1);
        CHECK(bmp.info.height == 1);
        CHECK(bmp.info.planes == 1);
        CHECK(bmp.info.bit_count == 24);
        CHECK(bmp.info.compression == libexe::bitmap_compression::RGB);
        CHECK_FALSE(bmp.has_palette());
        CHECK(bmp.pixel_data.size() == 4);
        CHECK(bmp.row_size() == 4);  // 1 pixel * 3 bytes = 3, padded to 4
    }

    /**
     * Test bitmap parser with palette
     */
    TEST_CASE("Parse 8-bit bitmap with palette") {
        std::vector<uint8_t> bitmap_data = {
            // BITMAPINFOHEADER (40 bytes)
            40, 0, 0, 0,        // header_size = 40
            2, 0, 0, 0,         // width = 2
            2, 0, 0, 0,         // height = 2
            1, 0,               // planes = 1
            8, 0,               // bit_count = 8 (256 colors)
            0, 0, 0, 0,         // compression = BI_RGB
            0, 0, 0, 0,         // size_image = 0
            0, 0, 0, 0,         // x_pels_per_meter = 0
            0, 0, 0, 0,         // y_pels_per_meter = 0
            2, 0, 0, 0,         // clr_used = 2 (only 2 colors used)
            0, 0, 0, 0,         // clr_important = 0
            // Color palette (2 colors * 4 bytes = 8 bytes)
            0x00, 0x00, 0x00, 0x00,  // Black (BGRA)
            0xFF, 0xFF, 0xFF, 0x00,  // White (BGRA)
            // Pixel data (2x2 pixels, 8 bpp, padded to DWORD)
            0, 1, 0, 0,         // Row 0: Black, White, padding
            1, 0, 0, 0          // Row 1: White, Black, padding
        };

        auto result = libexe::bitmap_parser::parse(bitmap_data);
        REQUIRE(result.has_value());

        const auto& bmp = result.value();
        CHECK(bmp.info.bit_count == 8);
        CHECK(bmp.has_palette());
        CHECK(bmp.palette.size() == 2);
        CHECK(bmp.palette[0].red == 0x00);    // Black
        CHECK(bmp.palette[1].red == 0xFF);    // White
        CHECK(bmp.pixel_data.size() == 8);
    }

    /**
     * Test bitmap parser with top-down DIB (negative height)
     */
    TEST_CASE("Parse top-down bitmap (negative height)") {
        std::vector<uint8_t> bitmap_data = {
            // BITMAPINFOHEADER with negative height
            40, 0, 0, 0,            // header_size = 40
            1, 0, 0, 0,             // width = 1
            0xFF, 0xFF, 0xFF, 0xFF, // height = -1 (top-down)
            1, 0,                   // planes = 1
            24, 0,                  // bit_count = 24
            0, 0, 0, 0,             // compression = BI_RGB
            0, 0, 0, 0,             // size_image = 0
            0, 0, 0, 0,             // x_pels_per_meter = 0
            0, 0, 0, 0,             // y_pels_per_meter = 0
            0, 0, 0, 0,             // clr_used = 0
            0, 0, 0, 0,             // clr_important = 0
            // Pixel data
            0xFF, 0xFF, 0xFF, 0x00
        };

        auto result = libexe::bitmap_parser::parse(bitmap_data);
        REQUIRE(result.has_value());

        const auto& bmp = result.value();
        CHECK(bmp.info.height == -1);
        CHECK(bmp.info.is_top_down());
        CHECK(bmp.info.abs_height() == 1);
    }

    /**
     * Test bitmap parser with invalid data
     */
    TEST_CASE("Parse invalid bitmap data") {
        // Empty data
        std::vector<uint8_t> empty_data;
        auto result = libexe::bitmap_parser::parse(empty_data);
        CHECK_FALSE(result.has_value());

        // Too small
        std::vector<uint8_t> too_small = {1, 2, 3};
        result = libexe::bitmap_parser::parse(too_small);
        CHECK_FALSE(result.has_value());

        // Invalid header size
        std::vector<uint8_t> invalid_header = {
            99, 0, 0, 0,  // Invalid header size
            1, 0, 0, 0, 1, 0, 0, 0
        };
        result = libexe::bitmap_parser::parse(invalid_header);
        CHECK_FALSE(result.has_value());
    }

    /**
     * Test message table parser with basic message table
     */
    TEST_CASE("Parse basic message table") {
        // Create a simple message table with 1 block and 2 messages
        std::vector<uint8_t> msg_table_data;

        // message_resource_data header
        msg_table_data.push_back(1);  // number_of_blocks (low byte)
        msg_table_data.push_back(0);
        msg_table_data.push_back(0);
        msg_table_data.push_back(0);  // number_of_blocks = 1

        // message_resource_block
        // low_id = 0x1000
        msg_table_data.push_back(0x00);
        msg_table_data.push_back(0x10);
        msg_table_data.push_back(0x00);
        msg_table_data.push_back(0x00);

        // high_id = 0x1001
        msg_table_data.push_back(0x01);
        msg_table_data.push_back(0x10);
        msg_table_data.push_back(0x00);
        msg_table_data.push_back(0x00);

        // offset_to_entries = 16 (after header + block)
        msg_table_data.push_back(0x10);
        msg_table_data.push_back(0x00);
        msg_table_data.push_back(0x00);
        msg_table_data.push_back(0x00);

        // Message entries start at offset 16
        // Message 0x1000 (ANSI)
        msg_table_data.push_back(14);  // length = 14 (4 header + 10 text)
        msg_table_data.push_back(0);
        msg_table_data.push_back(0);   // flags = ANSI
        msg_table_data.push_back(0);
        // Text: "Message 1\0" (10 bytes)
        const char* msg1 = "Message 1";
        for (size_t i = 0; i < 10; ++i) {
            msg_table_data.push_back(static_cast<uint8_t>(msg1[i]));
        }

        // Message 0x1001 (ANSI)
        msg_table_data.push_back(14);  // length = 14
        msg_table_data.push_back(0);
        msg_table_data.push_back(0);   // flags = ANSI
        msg_table_data.push_back(0);
        // Text: "Message 2\0" (10 bytes)
        const char* msg2 = "Message 2";
        for (size_t i = 0; i < 10; ++i) {
            msg_table_data.push_back(static_cast<uint8_t>(msg2[i]));
        }

        auto result = libexe::message_table_parser::parse(msg_table_data);
        REQUIRE(result.has_value());

        const auto& table = result.value();
        CHECK(table.blocks.size() == 1);
        CHECK(table.message_count() == 2);

        const auto& block = table.blocks[0];
        CHECK(block.low_id == 0x1000);
        CHECK(block.high_id == 0x1001);
        CHECK(block.contains(0x1000));
        CHECK(block.contains(0x1001));
        CHECK_FALSE(block.contains(0x1002));

        // Test find_message
        auto msg = table.find_message(0x1000);
        REQUIRE(msg.has_value());
        CHECK(msg->message_id == 0x1000);
        CHECK(msg->is_ansi());
        CHECK_FALSE(msg->is_unicode());

        // Test all_messages
        auto all_msgs = table.all_messages();
        CHECK(all_msgs.size() == 2);
        CHECK(all_msgs.count(0x1000) == 1);
        CHECK(all_msgs.count(0x1001) == 1);
    }

    /**
     * Test message table parser with invalid data
     */
    TEST_CASE("Parse invalid message table data") {
        // Empty data
        std::vector<uint8_t> empty_data;
        auto result = libexe::message_table_parser::parse(empty_data);
        CHECK_FALSE(result.has_value());

        // Too small
        std::vector<uint8_t> too_small = {1, 2};
        result = libexe::message_table_parser::parse(too_small);
        CHECK_FALSE(result.has_value());
    }

    /**
     * Test message table with multiple blocks
     */
    TEST_CASE("Parse message table with multiple blocks") {
        std::vector<uint8_t> msg_table_data;

        // 2 blocks
        msg_table_data.push_back(2);  // number_of_blocks
        msg_table_data.push_back(0);
        msg_table_data.push_back(0);
        msg_table_data.push_back(0);

        // Block 1: messages 0x100-0x100
        msg_table_data.push_back(0x00);
        msg_table_data.push_back(0x01);
        msg_table_data.push_back(0x00);
        msg_table_data.push_back(0x00);  // low_id = 0x100

        msg_table_data.push_back(0x00);
        msg_table_data.push_back(0x01);
        msg_table_data.push_back(0x00);
        msg_table_data.push_back(0x00);  // high_id = 0x100

        msg_table_data.push_back(0x1C);  // offset = 28
        msg_table_data.push_back(0x00);
        msg_table_data.push_back(0x00);
        msg_table_data.push_back(0x00);

        // Block 2: messages 0x200-0x200
        msg_table_data.push_back(0x00);
        msg_table_data.push_back(0x02);
        msg_table_data.push_back(0x00);
        msg_table_data.push_back(0x00);  // low_id = 0x200

        msg_table_data.push_back(0x00);
        msg_table_data.push_back(0x02);
        msg_table_data.push_back(0x00);
        msg_table_data.push_back(0x00);  // high_id = 0x200

        msg_table_data.push_back(0x24);  // offset = 36
        msg_table_data.push_back(0x00);
        msg_table_data.push_back(0x00);
        msg_table_data.push_back(0x00);

        // Message at offset 28 (block 1, ID 0x100)
        msg_table_data.push_back(8);   // length = 8 (4 header + 4 text)
        msg_table_data.push_back(0);
        msg_table_data.push_back(0);   // flags = ANSI
        msg_table_data.push_back(0);
        msg_table_data.push_back('F');
        msg_table_data.push_back('o');
        msg_table_data.push_back('o');
        msg_table_data.push_back(0);

        // Message at offset 36 (block 2, ID 0x200)
        msg_table_data.push_back(8);   // length = 8
        msg_table_data.push_back(0);
        msg_table_data.push_back(0);   // flags = ANSI
        msg_table_data.push_back(0);
        msg_table_data.push_back('B');
        msg_table_data.push_back('a');
        msg_table_data.push_back('r');
        msg_table_data.push_back(0);

        auto result = libexe::message_table_parser::parse(msg_table_data);
        REQUIRE(result.has_value());

        const auto& table = result.value();
        CHECK(table.blocks.size() == 2);
        CHECK(table.message_count() == 2);

        auto msg1 = table.find_message(0x100);
        REQUIRE(msg1.has_value());
        CHECK(msg1->message_id == 0x100);

        auto msg2 = table.find_message(0x200);
        REQUIRE(msg2.has_value());
        CHECK(msg2->message_id == 0x200);

        // Non-existent message
        auto msg3 = table.find_message(0x300);
        CHECK_FALSE(msg3.has_value());
    }
}
