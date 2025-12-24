// libexe - Modern executable file analysis library
// Copyright (c) 2024
// Tests for LE/LX resource table parsing

#include <doctest/doctest.h>
#include <libexe/formats/le_file.hpp>
#include <span>

using namespace libexe;

// External embedded test data
namespace data {
    extern size_t makeini_lx_len;
    extern unsigned char makeini_lx[];
    extern size_t os2chess_lx_len;
    extern unsigned char os2chess_lx[];
    extern size_t strace_lx_len;
    extern unsigned char strace_lx[];
    extern size_t doom_le_len;
    extern unsigned char doom_le[];
}

// =============================================================================
// MAKEINI.EXE - LX file with 1 resource (RT_STRING)
// Ground truth from manual inspection:
//   Resource count: 1
//   Resource[0]: type=5 (RT_STRING), name=1, size=323, object=2, offset varies
// =============================================================================

TEST_CASE("LX MAKEINI.EXE: resource detection") {
    std::span<const uint8_t> input(data::makeini_lx, data::makeini_lx_len);
    auto le = le_file::from_memory(input);

    CHECK(le.is_lx());
    CHECK(le.has_resources());
    CHECK(le.resource_count() == 1);
}

TEST_CASE("LX MAKEINI.EXE: resource properties") {
    std::span<const uint8_t> input(data::makeini_lx, data::makeini_lx_len);
    auto le = le_file::from_memory(input);

    REQUIRE(le.resource_count() >= 1);

    const auto& resources = le.resources();
    const auto& res = resources[0];

    // Resource type 5 = RT_STRING
    CHECK(res.type_id == le_resource::RT_STRING);
    CHECK(res.name_id == 1);
    CHECK(res.size == 323);

    // Object should be valid (1 or 2 typically)
    CHECK(res.object > 0);
    CHECK(res.object <= le.objects().size());
}

TEST_CASE("LX MAKEINI.EXE: resource by type lookup") {
    std::span<const uint8_t> input(data::makeini_lx, data::makeini_lx_len);
    auto le = le_file::from_memory(input);

    // Should find 1 string table resource
    auto string_resources = le.resources_by_type(le_resource::RT_STRING);
    CHECK(string_resources.size() == 1);

    // Should find 0 bitmap resources
    auto bitmap_resources = le.resources_by_type(le_resource::RT_BITMAP);
    CHECK(bitmap_resources.empty());
}

TEST_CASE("LX MAKEINI.EXE: get resource by type and name") {
    std::span<const uint8_t> input(data::makeini_lx, data::makeini_lx_len);
    auto le = le_file::from_memory(input);

    // Should find RT_STRING with name 1
    auto res = le.get_resource(le_resource::RT_STRING, 1);
    REQUIRE(res.has_value());
    CHECK(res->type_id == le_resource::RT_STRING);
    CHECK(res->name_id == 1);

    // Should not find RT_STRING with name 999
    auto missing = le.get_resource(le_resource::RT_STRING, 999);
    CHECK_FALSE(missing.has_value());
}

TEST_CASE("LX MAKEINI.EXE: read resource data") {
    std::span<const uint8_t> input(data::makeini_lx, data::makeini_lx_len);
    auto le = le_file::from_memory(input);

    auto res = le.get_resource(le_resource::RT_STRING, 1);
    REQUIRE(res.has_value());

    auto data = le.read_resource_data(*res);

    // Resource size should match (or be close - may be limited by object size)
    CHECK_FALSE(data.empty());
    CHECK(data.size() <= res->size);
}

// =============================================================================
// OS2CHESS.EXE - LX file with 73 resources (comprehensive test)
// Ground truth from manual inspection:
//   Resource count: 73
//   Types: RT_POINTER (1), RT_BITMAP (2), RT_MENU (3), RT_STRING (5), etc.
//   Resources span objects 6 and 7
// =============================================================================

TEST_CASE("LX OS2CHESS.EXE: resource detection") {
    std::span<const uint8_t> input(data::os2chess_lx, data::os2chess_lx_len);
    auto le = le_file::from_memory(input);

    CHECK(le.is_lx());
    CHECK(le.has_resources());
    CHECK(le.resource_count() == 73);
}

TEST_CASE("LX OS2CHESS.EXE: resource type distribution") {
    std::span<const uint8_t> input(data::os2chess_lx, data::os2chess_lx_len);
    auto le = le_file::from_memory(input);

    // Ground truth from binary inspection:
    // type=1 (RT_POINTER): 5 resources
    // type=2 (RT_BITMAP): 14 resources
    // type=3 (RT_MENU): 2 resources
    // type=4 (RT_DIALOG): 23 resources
    // type=5 (RT_STRING): 8 resources
    // type=8 (RT_ACCELTABLE): 1 resource
    // type=18 (RT_HELPTABLE): 1 resource
    // type=19 (RT_HELPSUBTABLE): 19 resources

    auto pointers = le.resources_by_type(le_resource::RT_POINTER);
    auto bitmaps = le.resources_by_type(le_resource::RT_BITMAP);
    auto menus = le.resources_by_type(le_resource::RT_MENU);
    auto dialogs = le.resources_by_type(le_resource::RT_DIALOG);
    auto strings = le.resources_by_type(le_resource::RT_STRING);
    auto accels = le.resources_by_type(le_resource::RT_ACCELTABLE);
    auto helptables = le.resources_by_type(le_resource::RT_HELPTABLE);
    auto helpsubtables = le.resources_by_type(le_resource::RT_HELPSUBTABLE);

    CHECK(pointers.size() == 5);
    CHECK(bitmaps.size() == 14);
    CHECK(menus.size() == 2);
    CHECK(dialogs.size() == 23);
    CHECK(strings.size() == 8);
    CHECK(accels.size() == 1);
    CHECK(helptables.size() == 1);
    CHECK(helpsubtables.size() == 19);

    // Total should match
    size_t total = pointers.size() + bitmaps.size() + menus.size() + dialogs.size() +
                   strings.size() + accels.size() + helptables.size() + helpsubtables.size();
    CHECK(total == 73);
}

TEST_CASE("LX OS2CHESS.EXE: resources span multiple objects") {
    std::span<const uint8_t> input(data::os2chess_lx, data::os2chess_lx_len);
    auto le = le_file::from_memory(input);

    // Resources are in objects 6 and 7
    bool found_obj6 = false;
    bool found_obj7 = false;

    for (const auto& res : le.resources()) {
        if (res.object == 6) found_obj6 = true;
        if (res.object == 7) found_obj7 = true;
    }

    CHECK(found_obj6);
    CHECK(found_obj7);
}

TEST_CASE("LX OS2CHESS.EXE: specific resource lookup") {
    std::span<const uint8_t> input(data::os2chess_lx, data::os2chess_lx_len);
    auto le = le_file::from_memory(input);

    // First pointer resource: type=1, name=6, size=1643
    auto ptr = le.get_resource(le_resource::RT_POINTER, 6);
    REQUIRE(ptr.has_value());
    CHECK(ptr->size == 1643);
    CHECK(ptr->object == 6);

    // First bitmap resource: type=2, name=1, size=3151
    auto bmp = le.get_resource(le_resource::RT_BITMAP, 1);
    REQUIRE(bmp.has_value());
    CHECK(bmp->size == 3151);

    // Menu resource: type=3, name=1000, size=778
    auto menu = le.get_resource(le_resource::RT_MENU, 1000);
    REQUIRE(menu.has_value());
    CHECK(menu->size == 778);
}

TEST_CASE("LX OS2CHESS.EXE: read bitmap resource data") {
    std::span<const uint8_t> input(data::os2chess_lx, data::os2chess_lx_len);
    auto le = le_file::from_memory(input);

    auto bmp = le.get_resource(le_resource::RT_BITMAP, 1);
    REQUIRE(bmp.has_value());

    auto data = le.read_resource_data(*bmp);
    CHECK_FALSE(data.empty());
    CHECK(data.size() <= bmp->size);

}

// =============================================================================
// Files without resources
// =============================================================================

TEST_CASE("LX STRACE.EXE: no resources") {
    std::span<const uint8_t> input(data::strace_lx, data::strace_lx_len);
    auto le = le_file::from_memory(input);

    CHECK_FALSE(le.has_resources());
    CHECK(le.resource_count() == 0);
    CHECK(le.resources().empty());
}

TEST_CASE("LE DOOM.EXE: no resources") {
    std::span<const uint8_t> input(data::doom_le, data::doom_le_len);
    auto le = le_file::from_memory(input);

    CHECK_FALSE(le.has_resources());
    CHECK(le.resource_count() == 0);
    CHECK(le.resources().empty());
}

// =============================================================================
// Resource type constants
// =============================================================================

TEST_CASE("LE resource type constants") {
    // Verify the OS/2 resource type constants are correctly defined
    CHECK(le_resource::RT_POINTER == 1);
    CHECK(le_resource::RT_BITMAP == 2);
    CHECK(le_resource::RT_MENU == 3);
    CHECK(le_resource::RT_DIALOG == 4);
    CHECK(le_resource::RT_STRING == 5);
    CHECK(le_resource::RT_FONTDIR == 6);
    CHECK(le_resource::RT_FONT == 7);
    CHECK(le_resource::RT_ACCELTABLE == 8);
    CHECK(le_resource::RT_RCDATA == 9);
    CHECK(le_resource::RT_MESSAGE == 10);
}
