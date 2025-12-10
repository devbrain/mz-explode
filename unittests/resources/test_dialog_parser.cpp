// Dialog parser tests - both NE and PE formats
#include <doctest/doctest.h>
#include <libexe/formats/ne_file.hpp>
#include <libexe/formats/pe_file.hpp>
#include <libexe/resources/resource.hpp>
#include <libexe/resources/parsers/dialog_parser.hpp>
#include <vector>

using namespace libexe;

// External test data (embedded PROGMAN.EXE)
namespace data {
    extern size_t progman_len;
    extern unsigned char progman[];
}

namespace {
    // Load PROGMAN.EXE from embedded data
    std::vector<uint8_t> load_progman() {
        return std::vector<uint8_t>(
            data::progman,
            data::progman + data::progman_len
        );
    }
}

TEST_CASE("Parse dialog resources in PROGMAN.EXE") {
    auto data = load_progman();
    REQUIRE(!data.empty());

    auto exe = ne_file::from_memory(data);
    REQUIRE(exe.has_resources());

    auto rsrc = exe.resources();
    REQUIRE(rsrc != nullptr);

    auto all_resources = rsrc->all_resources();
    auto dialogs = all_resources.filter_by_type(resource_type::RT_DIALOG);

    REQUIRE(dialogs.size() == 7);

    size_t total_controls = 0;

    for (size_t i = 0; i < dialogs.size(); i++) {
        const auto& dlg_res = dialogs[i];
        auto dlg = dlg_res.as_dialog();

        REQUIRE(dlg.has_value());

        total_controls += dlg->controls.size();

        // Verify controls were parsed
        CHECK(dlg->controls.size() > 0);
        CHECK(dlg->controls.size() <= 20);  // Reasonable upper limit
    }

    CHECK(total_controls > 0);
}

// External test data (embedded scheduler.exe)
namespace data {
    extern size_t scheduler_len;
    extern unsigned char scheduler[];
}

namespace {
    // Load scheduler.exe from embedded data
    std::vector<uint8_t> load_scheduler() {
        return std::vector<uint8_t>(
            data::scheduler,
            data::scheduler + data::scheduler_len
        );
    }
}

TEST_CASE("Parse PE dialog resources in scheduler.exe") {
    auto data_vec = load_scheduler();
    REQUIRE(!data_vec.empty());

    auto exe = pe_file::from_memory(data_vec);
    REQUIRE(exe.has_resources());

    auto rsrc = exe.resources();
    REQUIRE(rsrc != nullptr);

    auto all_resources = rsrc->all_resources();
    auto dialogs = all_resources.filter_by_type(resource_type::RT_DIALOG);

    REQUIRE(dialogs.size() == 4);

    // Test first dialog (should be the main scheduler dialog)
    const auto& dlg_res = dialogs[0];
    auto dlg = dlg_res.as_dialog();

    REQUIRE(dlg.has_value());
    CHECK(dlg_res.id().value() == 101);
    CHECK(dlg->caption == "Teleport Scheduler");
    CHECK(dlg->has_font());
    CHECK(dlg->font_name == "MS Sans Serif");
    CHECK(dlg->point_size == 8);
    CHECK(dlg->controls.size() == 3);

    // Verify all dialogs parse successfully
    size_t total_controls = 0;
    for (size_t i = 0; i < dialogs.size(); i++) {
        auto parsed = dialogs[i].as_dialog();
        REQUIRE(parsed.has_value());
        total_controls += parsed->controls.size();
    }

    CHECK(total_controls > 0);
}
