// Temporary test to examine dialog structure
#include <doctest/doctest.h>
#include <libexe/ne_file.hpp>
#include <libexe/resources/resource.hpp>
#include <libexe/resources/parsers/dialog_parser.hpp>
#include <filesystem>
#include <iomanip>
#include <iostream>

using namespace libexe;

TEST_CASE("Parse dialog resources in PROGMAN.EXE") {
    const std::filesystem::path test_file = "../data/PROGMAN.EXE";
    REQUIRE(std::filesystem::exists(test_file));

    auto exe = ne_file::from_file(test_file);
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
