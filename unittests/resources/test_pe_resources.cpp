// Test PE Resource Extraction
#include <doctest/doctest.h>
#include <libexe/pe_file.hpp>
#include <libexe/resources/resource.hpp>

using namespace libexe;

// External test data - use existing PE32 executable
namespace data {
    extern size_t tcmdx32_len;
    extern unsigned char tcmdx32[];
}

namespace {

std::vector<uint8_t> load_tcmdx32() {
    return std::vector<uint8_t>(
        data::tcmdx32,
        data::tcmdx32 + data::tcmdx32_len
    );
}

} // anonymous namespace

TEST_CASE("PE32 Resource Extraction - TCMDX32.EXE") {
    auto data = load_tcmdx32();
    auto pe = pe_file::from_memory(data);

    SUBCASE("File has resources") {
        CHECK(pe.has_resources());
    }

    SUBCASE("Resource directory is accessible") {
        auto rsrc = pe.resources();
        CHECK(rsrc != nullptr);
    }

    SUBCASE("Resource enumeration") {
        auto rsrc = pe.resources();
        auto all = rsrc->all_resources();

        CHECK(all.size() > 0);
    }

    SUBCASE("Resource type filtering") {
        auto rsrc = pe.resources();

        // Get all icons
        auto icons = rsrc->resources_by_type(resource_type::RT_ICON);

        // Get all group icons
        auto icon_groups = rsrc->resources_by_type(resource_type::RT_GROUP_ICON);

        // Get version info
        auto versions = rsrc->resources_by_type(resource_type::RT_VERSION);

        // Get manifests
        auto manifests = rsrc->resources_by_type(resource_type::RT_MANIFEST);
    }

    SUBCASE("Validate against wrestool output") {
        auto rsrc = pe.resources();

        // Total resource count should match wrestool
        // wrestool --list TCMDX32.EXE reports 7 resources
        CHECK(rsrc->resource_count() == 7);

        // Validate counts by type (verified with wrestool)
        CHECK(rsrc->resources_by_type(resource_type::RT_ICON).size() == 4);
        CHECK(rsrc->resources_by_type(resource_type::RT_GROUP_ICON).size() == 1);
        CHECK(rsrc->resources_by_type(resource_type::RT_VERSION).size() == 1);
        CHECK(rsrc->resources_by_type(resource_type::RT_MANIFEST).size() == 1);

        // Verify specific resources exist
        auto group_icon = rsrc->find_resource(resource_type::RT_GROUP_ICON, 101);
        CHECK(group_icon.has_value());

        auto version = rsrc->find_resource(resource_type::RT_VERSION, 1);
        CHECK(version.has_value());
        if (version) {
            CHECK(version->size() == 1136);  // Exact size from wrestool
        }

        auto manifest = rsrc->find_resource(resource_type::RT_MANIFEST, 1);
        CHECK(manifest.has_value());
        if (manifest) {
            CHECK(manifest->size() == 1052);  // Exact size from wrestool
        }
    }

    SUBCASE("Find specific resource") {
        auto rsrc = pe.resources();

        // Try to find version resource (typically ID 1)
        auto version = rsrc->find_resource(resource_type::RT_VERSION, 1);

        if (version) {
            CHECK(version->size() > 0);
            CHECK(version->type_id() == 16);  // RT_VERSION
        }
    }

    SUBCASE("Resource data access") {
        auto rsrc = pe.resources();
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
        auto rsrc = pe.resources();

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
            }
        }
    }

    SUBCASE("Language enumeration") {
        auto rsrc = pe.resources();

        // Get all languages present in the file
        auto langs = rsrc->languages();

        for (auto lang : langs) {
        }

        // Get languages for a specific type
        auto icon_langs = rsrc->languages_for_type(static_cast<uint16_t>(resource_type::RT_ICON));

        // PE resources should have language IDs
        CHECK(langs.size() > 0);
    }
}
