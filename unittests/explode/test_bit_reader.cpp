// Tests for bit_reader utility
#include <doctest/doctest.h>
#include "../../src/libexe/decompressors/bit_reader.hpp"
#include <vector>

using namespace libexe;

TEST_CASE("bit_reader: basic bit reading") {
    SUBCASE("Read bits LSB-first from 16-bit word") {
        // Word 0x00AB (little-endian: 0xAB, 0x00)
        // First byte 0xAB = 0b10101011, LSB-first: 1,1,0,1,0,1,0,1
        std::vector<uint8_t> data = {0xAB, 0x00};
        bit_reader reader(data);

        CHECK(reader.read_bit() == 1);  // LSB
        CHECK(reader.read_bit() == 1);
        CHECK(reader.read_bit() == 0);
        CHECK(reader.read_bit() == 1);
        CHECK(reader.read_bit() == 0);
        CHECK(reader.read_bit() == 1);
        CHECK(reader.read_bit() == 0);
        CHECK(reader.read_bit() == 1);  // MSB
    }

    SUBCASE("Read bits across byte boundary") {
        // 0x12 = 0b00010010, LSB-first: 0,1,0,0,1,0,0,0
        // 0x34 = 0b00110100, LSB-first: 0,0,1,0,1,1,0,0
        std::vector<uint8_t> data = {0x12, 0x34};
        bit_reader reader(data);

        // Read from first byte
        CHECK(reader.read_bit() == 0);
        CHECK(reader.read_bit() == 1);
        CHECK(reader.read_bit() == 0);
        CHECK(reader.read_bit() == 0);
        CHECK(reader.read_bit() == 1);
        CHECK(reader.read_bit() == 0);
        CHECK(reader.read_bit() == 0);
        CHECK(reader.read_bit() == 0);

        // Read from second byte
        CHECK(reader.read_bit() == 0);
        CHECK(reader.read_bit() == 0);
        CHECK(reader.read_bit() == 1);
    }
}

TEST_CASE("bit_reader: byte and word reading") {
    SUBCASE("Read full bytes") {
        std::vector<uint8_t> data = {0x12, 0x34, 0x56};
        bit_reader reader(data);

        CHECK(reader.read_byte() == 0x12);
        CHECK(reader.read_byte() == 0x34);
        CHECK(reader.read_byte() == 0x56);
    }

    SUBCASE("Read words little-endian") {
        std::vector<uint8_t> data = {0x12, 0x34, 0x56, 0x78};
        bit_reader reader(data);

        CHECK(reader.read_word() == 0x3412);  // Little-endian
        CHECK(reader.read_word() == 0x7856);
    }

    SUBCASE("Mix bit and byte reading") {
        // With 16-bit buffering: word at 0-1 is loaded for bit reads,
        // then byte reads come from position 2 onward
        std::vector<uint8_t> data = {0xAB, 0xCD, 0xEF, 0x12};
        bit_reader reader(data);

        // Read 3 bits from first word (0xCDAB little-endian)
        // 0xAB = 0b10101011, LSB-first: 1,1,0,...
        CHECK(reader.read_bit() == 1);
        CHECK(reader.read_bit() == 1);
        CHECK(reader.read_bit() == 0);

        // Read a full byte (should come from position 2, after the loaded word)
        CHECK(reader.read_byte() == 0xEF);
    }
}

TEST_CASE("bit_reader: seek functionality") {
    SUBCASE("Seek to different positions") {
        std::vector<uint8_t> data = {0x11, 0x22, 0x33, 0x44};
        bit_reader reader(data);

        reader.seek(2);
        CHECK(reader.read_byte() == 0x33);

        reader.seek(0);
        CHECK(reader.read_byte() == 0x11);

        reader.seek(3);
        CHECK(reader.read_byte() == 0x44);
    }
}

TEST_CASE("bit_reader: error handling") {
    SUBCASE("Read past end throws") {
        std::vector<uint8_t> data = {0x12, 0x34};
        bit_reader reader(data);

        reader.read_byte();  // OK
        reader.read_byte();  // OK
        CHECK_THROWS_AS(reader.read_byte(), std::runtime_error);
    }

    SUBCASE("Read bits past end throws") {
        // bit_reader uses 16-bit word buffering with EAGER refill (like legacy)
        // After reading the 16th bit, it tries to eagerly refill, which throws
        std::vector<uint8_t> data = {0x12, 0x34};
        bit_reader reader(data);

        // Read 15 bits successfully (no eager refill yet)
        for (int i = 0; i < 15; i++) {
            reader.read_bit();  // OK
        }

        // Reading the 16th bit triggers eager refill which throws
        CHECK_THROWS_AS(reader.read_bit(), std::runtime_error);
    }
}
