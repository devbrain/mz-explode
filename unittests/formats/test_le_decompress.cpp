// libexe - Modern executable file analysis library
// Copyright (c) 2024
// Tests for LE/LX page decompression (EXEPACK1/EXEPACK2)

#include <doctest/doctest.h>
#include <libexe/formats/le_file.hpp>
#include <span>

using namespace libexe;

// External embedded test data
namespace data {
    extern size_t os2chess_lx_len;
    extern unsigned char os2chess_lx[];
    extern size_t strace_lx_len;
    extern unsigned char strace_lx[];
    extern size_t cmd_lx_len;
    extern unsigned char cmd_lx[];
    extern size_t sevenz_lx_len;
    extern unsigned char sevenz_lx[];
}

// =============================================================================
// EXEPACK1 (iterated pages) - OS2CHESS.EXE has 39 iterated pages
// =============================================================================

TEST_CASE("LX OS2CHESS.EXE: has iterated pages") {
    std::span<const uint8_t> input(data::os2chess_lx, data::os2chess_lx_len);
    auto le = le_file::from_memory(input);

    // Check that some pages are iterated
    bool found_iterated = false;
    for (const auto& obj : le.objects()) {
        auto pages = le.get_object_pages(obj.index);
        for (const auto& page : pages) {
            if (page.is_iterated()) {
                found_iterated = true;
                break;
            }
        }
        if (found_iterated) break;
    }

    CHECK(found_iterated);
    MESSAGE("OS2CHESS.EXE has iterated (EXEPACK1) pages");
}

TEST_CASE("LX OS2CHESS.EXE: read object with iterated pages") {
    std::span<const uint8_t> input(data::os2chess_lx, data::os2chess_lx_len);
    auto le = le_file::from_memory(input);

    // Find an object with iterated pages and read it
    for (const auto& obj : le.objects()) {
        auto pages = le.get_object_pages(obj.index);
        bool has_iterated = false;
        for (const auto& page : pages) {
            if (page.is_iterated()) {
                has_iterated = true;
                break;
            }
        }

        if (has_iterated) {
            auto data = le.read_object_data(obj.index);
            CHECK_FALSE(data.empty());
            // Decompressed size should match or be close to virtual_size
            CHECK(data.size() <= obj.virtual_size);
            MESSAGE("Object ", obj.index, ": virtual_size=", obj.virtual_size,
                   ", decompressed=", data.size());
            break;
        }
    }
}

TEST_CASE("LX STRACE.EXE: read object with iterated pages") {
    std::span<const uint8_t> input(data::strace_lx, data::strace_lx_len);
    auto le = le_file::from_memory(input);

    // STRACE.EXE has 4 iterated pages
    bool found_iterated = false;
    for (const auto& obj : le.objects()) {
        auto pages = le.get_object_pages(obj.index);
        for (const auto& page : pages) {
            if (page.is_iterated()) {
                found_iterated = true;
                auto data = le.read_object_data(obj.index);
                CHECK_FALSE(data.empty());
                MESSAGE("STRACE.EXE object ", obj.index, ": decompressed ", data.size(), " bytes");
                break;
            }
        }
        if (found_iterated) break;
    }

    CHECK(found_iterated);
}

// =============================================================================
// EXEPACK2 (compressed pages) - CMD.EXE has 27, 7z.exe has 98 compressed pages
// =============================================================================

TEST_CASE("LX CMD.EXE: has compressed pages") {
    std::span<const uint8_t> input(data::cmd_lx, data::cmd_lx_len);
    auto le = le_file::from_memory(input);

    // Check that some pages are compressed
    bool found_compressed = false;
    for (const auto& obj : le.objects()) {
        auto pages = le.get_object_pages(obj.index);
        for (const auto& page : pages) {
            if (page.is_compressed()) {
                found_compressed = true;
                break;
            }
        }
        if (found_compressed) break;
    }

    CHECK(found_compressed);
    MESSAGE("CMD.EXE has compressed (EXEPACK2) pages");
}

TEST_CASE("LX CMD.EXE: read object with compressed pages") {
    std::span<const uint8_t> input(data::cmd_lx, data::cmd_lx_len);
    auto le = le_file::from_memory(input);

    // Find an object with compressed pages and read it
    for (const auto& obj : le.objects()) {
        auto pages = le.get_object_pages(obj.index);
        bool has_compressed = false;
        for (const auto& page : pages) {
            if (page.is_compressed()) {
                has_compressed = true;
                break;
            }
        }

        if (has_compressed) {
            auto data = le.read_object_data(obj.index);
            CHECK_FALSE(data.empty());
            CHECK(data.size() <= obj.virtual_size);
            MESSAGE("CMD.EXE object ", obj.index, ": virtual_size=", obj.virtual_size,
                   ", decompressed=", data.size());
            break;
        }
    }
}

TEST_CASE("LX 7z.exe: read object with compressed pages") {
    std::span<const uint8_t> input(data::sevenz_lx, data::sevenz_lx_len);
    auto le = le_file::from_memory(input);

    // 7z.exe has 98 compressed pages - all objects should have them
    bool found_compressed = false;
    for (const auto& obj : le.objects()) {
        auto pages = le.get_object_pages(obj.index);
        for (const auto& page : pages) {
            if (page.is_compressed()) {
                found_compressed = true;
                auto data = le.read_object_data(obj.index);
                CHECK_FALSE(data.empty());
                MESSAGE("7z.exe object ", obj.index, ": virtual_size=", obj.virtual_size,
                       ", decompressed=", data.size());
                break;
            }
        }
        if (found_compressed) break;
    }

    CHECK(found_compressed);
}

// =============================================================================
// Resource reading with compressed pages
// =============================================================================

TEST_CASE("LX OS2CHESS.EXE: read resource from compressed object") {
    std::span<const uint8_t> input(data::os2chess_lx, data::os2chess_lx_len);
    auto le = le_file::from_memory(input);

    // OS2CHESS has resources in objects 6 and 7 which may have iterated pages
    REQUIRE(le.has_resources());

    // Get a bitmap resource and verify we can read it
    auto bmp = le.get_resource(le_resource::RT_BITMAP, 1);
    REQUIRE(bmp.has_value());

    auto data = le.read_resource_data(*bmp);
    CHECK_FALSE(data.empty());
    CHECK(data.size() == bmp->size);

    MESSAGE("Read bitmap resource: ", data.size(), " bytes from object ", bmp->object);
}
