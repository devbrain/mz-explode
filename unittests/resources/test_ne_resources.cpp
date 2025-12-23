// Test NE Resource Extraction
#include <doctest/doctest.h>
#include <libexe/formats/ne_file.hpp>
#include <libexe/resources/resource.hpp>
#include <algorithm>

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

TEST_CASE("NE Resource Extraction - PROGMAN.EXE") {
    auto data = load_progman();
    auto ne = ne_file::from_memory(data);

    SUBCASE("File has resources") {
        CHECK(ne.has_resources());
    }

    SUBCASE("Resource directory is accessible") {
        auto rsrc = ne.resources();
        CHECK(rsrc != nullptr);
    }

    SUBCASE("Resource enumeration") {
        auto rsrc = ne.resources();
        auto all = rsrc->all_resources();

        CHECK(all.size() > 0);
    }

    SUBCASE("Resource type filtering") {
        auto rsrc = ne.resources();

        // Verify we can filter by type (counts validated in detail in next subcase)
        CHECK(rsrc->resources_by_type(resource_type::RT_ICON).size() > 0);
        CHECK(rsrc->resources_by_type(resource_type::RT_GROUP_ICON).size() > 0);
        CHECK(rsrc->resources_by_type(resource_type::RT_MENU).size() > 0);
        CHECK(rsrc->resources_by_type(resource_type::RT_DIALOG).size() > 0);
        CHECK(rsrc->resources_by_type(resource_type::RT_ACCELERATOR).size() > 0);
        CHECK(rsrc->resources_by_type(resource_type::RT_STRING).size() > 0);
    }

    SUBCASE("Validate against wrestool output") {
        auto rsrc = ne.resources();

        // Total resource count should match wrestool
        // wrestool --list PROGMAN.EXE reports 157 resources
        CHECK(rsrc->resource_count() == 157);

        // Validate counts by type (verified with wrestool)
        CHECK(rsrc->resources_by_type(resource_type::RT_ICON).size() == 92);
        CHECK(rsrc->resources_by_type(resource_type::RT_MENU).size() == 1);
        CHECK(rsrc->resources_by_type(resource_type::RT_DIALOG).size() == 7);
        CHECK(rsrc->resources_by_type(resource_type::RT_STRING).size() == 9);
        CHECK(rsrc->resources_by_type(resource_type::RT_ACCELERATOR).size() == 1);
        CHECK(rsrc->resources_by_type(resource_type::RT_GROUP_ICON).size() == 46);
        CHECK(rsrc->resources_by_type(resource_type::RT_VERSION).size() == 1);

        // Verify named icon groups exist
        auto named_icons = rsrc->resources_by_type(resource_type::RT_GROUP_ICON);
        std::vector<std::string> expected_names = {
            "SHEETICON", "DATAICON", "COMMICON", "MSDOSICON"
        };

        for (const auto& expected_name : expected_names) {
            auto found = rsrc->find_resource(resource_type::RT_GROUP_ICON, expected_name);
            CHECK(found.has_value());
            if (found) {
            }
        }
    }

    SUBCASE("Find specific resource") {
        auto rsrc = ne.resources();

        // Try to find menu resource (typically ID 1)
        auto menu = rsrc->find_resource(resource_type::RT_MENU, 1);

        if (menu) {
            CHECK(menu->size() > 0);
            CHECK(menu->type_id() == 4);  // RT_MENU
        }
    }

    SUBCASE("Resource data access") {
        auto rsrc = ne.resources();
        auto all = rsrc->all_resources();

        if (!all.empty()) {
            auto first = all.first();
            CHECK(first.has_value());

            if (first) {
                auto data = first->data();
                CHECK(data.size() > 0);
                CHECK(data.data() != nullptr);
                CHECK(data.size() == first->size());
            }
        }
    }

    SUBCASE("Low-level tree navigation") {
        auto rsrc = ne.resources();

        // Get all types
        auto types = rsrc->types();
        CHECK(types.size() > 0);

        // For each type, verify we can enumerate IDs and names
        for (auto type_id : types) {
            auto ids = rsrc->ids_for_type(type_id);
            auto names = rsrc->names_for_type(type_id);
            // Each type should have at least one ID or name
            CHECK((ids.size() > 0 || names.size() > 0));
        }
    }

    SUBCASE("NE resources are language-neutral") {
        auto rsrc = ne.resources();
        auto all = rsrc->all_resources();

        // All NE resources should have language 0 (neutral)
        for (const auto& entry : all) {
            CHECK(entry.language() == 0);
            CHECK(entry.is_language_neutral());
        }
    }

    SUBCASE("Language enumeration") {
        auto rsrc = ne.resources();

        // Get all languages present in the file
        auto langs = rsrc->languages();

        // NE resources should only have language 0 (neutral)
        CHECK(langs.size() == 1);
        if (!langs.empty()) {
            CHECK(langs[0] == 0);
        }

        // Get languages for a specific type
        auto icon_langs = rsrc->languages_for_type(static_cast<uint16_t>(resource_type::RT_ICON));

        // Should also be just language 0
        CHECK(icon_langs.size() == 1);
        if (!icon_langs.empty()) {
            CHECK(icon_langs[0] == 0);
        }
    }
}

// =============================================================================
// OS/2 NE Resource Tests
// =============================================================================

// External embedded test data - OS/2 SYSFONT.DLL
namespace data {
    extern size_t sysfont_ne_len;
    extern unsigned char sysfont_ne[];
}

TEST_CASE("NE Resource Extraction - OS/2 SYSFONT.DLL") {
    std::vector<uint8_t> file_data(
        data::sysfont_ne,
        data::sysfont_ne + data::sysfont_ne_len
    );

    auto ne = ne_file::from_memory(file_data);

    SUBCASE("File is recognized as OS/2") {
        CHECK(ne.target_os() == ne_target_os::OS2);
    }

    SUBCASE("File has resources") {
        CHECK(ne.has_resources());
    }

    SUBCASE("OS/2 compact resource format is parsed") {
        auto rsrc = ne.resources();
        CHECK(rsrc != nullptr);

        // SYSFONT.DLL has 6 resources (7 segments but truncated resource table)
        CHECK(rsrc->resource_count() == 6);
    }

    SUBCASE("Resources are type RT_FONT (7)") {
        auto rsrc = ne.resources();
        auto types = rsrc->types();

        // Should have only 1 type: RT_FONT (7)
        CHECK(types.size() == 1);
        if (!types.empty()) {
            CHECK(types[0] == 7);
        }
    }

    SUBCASE("Font resources have correct IDs") {
        auto rsrc = ne.resources();
        auto fonts = rsrc->resources_by_type_id(7);

        CHECK(fonts.size() == 6);

        // Expected IDs: 1 (fontdir), 101-105 (fonts)
        std::vector<uint16_t> expected_ids = {1, 101, 102, 103, 104, 105};
        std::vector<uint16_t> actual_ids;

        for (const auto& font : fonts) {
            if (font.id()) {
                actual_ids.push_back(*font.id());
            }
        }

        std::sort(actual_ids.begin(), actual_ids.end());
        CHECK(actual_ids == expected_ids);
    }

    SUBCASE("Resource data comes from segments") {
        auto rsrc = ne.resources();

        // Font ID 101 should have data from segment 2
        auto font = rsrc->find_resource_by_type_id(7, 101);
        REQUIRE(font.has_value());

        // Check font data is accessible
        auto data = font->data();
        CHECK(data.size() > 0);

        // Font data should start with OS/2 GPI font signature (0xFFFFFFFE)
        if (data.size() >= 4) {
            uint32_t sig = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
            CHECK(sig == 0xFFFFFFFE);
        }
    }
}
