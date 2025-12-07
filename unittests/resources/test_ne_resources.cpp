// Test NE Resource Extraction
#include <doctest/doctest.h>
#include <libexe/ne_file.hpp>
#include <libexe/resources/resource.hpp>

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

        // Get all icons
        auto icons = rsrc->resources_by_type(resource_type::RT_ICON);

        // Get all group icons
        auto icon_groups = rsrc->resources_by_type(resource_type::RT_GROUP_ICON);

        // Get menus
        auto menus = rsrc->resources_by_type(resource_type::RT_MENU);

        // Get dialogs
        auto dialogs = rsrc->resources_by_type(resource_type::RT_DIALOG);

        // Get accelerators
        auto accels = rsrc->resources_by_type(resource_type::RT_ACCELERATOR);

        // Get strings
        auto strings = rsrc->resources_by_type(resource_type::RT_STRING);
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

        for (auto type_id : types) {

            // Get IDs for this type
            auto ids = rsrc->ids_for_type(type_id);
            if (!ids.empty()) {
            }

            // Get names for this type
            auto names = rsrc->names_for_type(type_id);
            if (!names.empty()) {
                for (const auto& name : names) {
                }
            }
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
