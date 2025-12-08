// Dialog parser tests - both NE and PE formats
#include <doctest/doctest.h>
#include <libexe/ne_file.hpp>
#include <libexe/pe_file.hpp>
#include <libexe/resources/resource.hpp>
#include <libexe/resources/parsers/dialog_parser.hpp>
#include <filesystem>
#include <iomanip>
#include <iostream>
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

    std::cout << "\nFound " << dialogs.size() << " dialog resources\n\n";
    REQUIRE(dialogs.size() == 7);

    size_t total_controls = 0;

    for (size_t i = 0; i < dialogs.size(); i++) {
        const auto& dlg_res = dialogs[i];
        auto dlg = dlg_res.as_dialog();

        REQUIRE(dlg.has_value());

        std::cout << "Dialog " << i << " (ID: " << dlg_res.id().value_or(0) << "):\n";
        std::cout << "  Caption: \"" << dlg->caption << "\"\n";
        std::cout << "  Position: (" << dlg->x << ", " << dlg->y << ")\n";
        std::cout << "  Size: " << dlg->width << " x " << dlg->height << "\n";
        std::cout << "  Style: 0x" << std::hex << dlg->style << std::dec << "\n";
        std::cout << "  Controls: " << dlg->controls.size() << "\n";

        if (dlg->has_font()) {
            std::cout << "  Font: " << dlg->font_name << " (" << dlg->point_size << " pt)\n";
        }

        total_controls += dlg->controls.size();

        // Verify controls were parsed
        CHECK(dlg->controls.size() > 0);
        CHECK(dlg->controls.size() <= 20);  // Reasonable upper limit

        // Display first few controls
        size_t control_limit = std::min(size_t(3), dlg->controls.size());
        for (size_t j = 0; j < control_limit; j++) {
            const auto& ctrl = dlg->controls[j];
            std::cout << "    Control " << j << ": ";

            if (ctrl.is_predefined_class()) {
                auto cls = ctrl.get_predefined_class().value();
                std::cout << "Class=" << static_cast<int>(cls);
            } else {
                std::cout << "Class=\"" << ctrl.get_class_name().value_or("?") << "\"";
            }

            std::cout << ", ID=" << ctrl.id;

            if (ctrl.has_text_string()) {
                std::cout << ", Text=\"" << ctrl.get_text_string().value() << "\"";
            }

            std::cout << "\n";
        }

        std::cout << "\n";
    }

    std::cout << "Total controls across all dialogs: " << total_controls << "\n";
    CHECK(total_controls > 0);
}

TEST_CASE("Parse PE dialog resources in scheduler.exe") {
    const std::filesystem::path test_file = "../data/scheduler.exe";

    if (!std::filesystem::exists(test_file)) {
        std::cout << "scheduler.exe not found, skipping PE dialog test\n";
        return;
    }

    auto exe = pe_file::from_file(test_file);
    REQUIRE(exe.has_resources());

    auto rsrc = exe.resources();
    REQUIRE(rsrc != nullptr);

    auto all_resources = rsrc->all_resources();
    auto dialogs = all_resources.filter_by_type(resource_type::RT_DIALOG);

    std::cout << "\nFound " << dialogs.size() << " PE dialog resources\n\n";
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

    std::cout << "First PE dialog:\n";
    std::cout << "  ID: " << dlg_res.id().value_or(0) << "\n";
    std::cout << "  Caption: \"" << dlg->caption << "\"\n";
    std::cout << "  Position: (" << dlg->x << ", " << dlg->y << ")\n";
    std::cout << "  Size: " << dlg->width << " x " << dlg->height << "\n";
    std::cout << "  Style: 0x" << std::hex << dlg->style << std::dec << "\n";
    std::cout << "  Controls: " << dlg->controls.size() << "\n";
    std::cout << "  Font: " << dlg->font_name << " (" << dlg->point_size << " pt)\n";

    // Verify all dialogs parse successfully
    size_t total_controls = 0;
    for (size_t i = 0; i < dialogs.size(); i++) {
        auto parsed = dialogs[i].as_dialog();
        REQUIRE(parsed.has_value());
        total_controls += parsed->controls.size();
    }

    std::cout << "\nTotal PE controls across all dialogs: " << total_controls << "\n";
    CHECK(total_controls > 0);
}
