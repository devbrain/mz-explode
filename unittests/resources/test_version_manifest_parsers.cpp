#include <doctest/doctest.h>
#include <libexe/formats/pe_file.hpp>
#include <libexe/resources/resource.hpp>
#include <libexe/resources/parsers/version_info_parser.hpp>
#include <libexe/resources/parsers/manifest_parser.hpp>

using namespace libexe;

// External test data - TCMDX32.EXE (PE32 executable with resources)
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

TEST_SUITE("Version Info Parser") {
    TEST_CASE("Parse RT_VERSION from TCMDX32.EXE") {
        // Load TCMDX32.EXE from embedded data
        auto data = load_tcmdx32();
        auto pe = pe_file::from_memory(data);

        REQUIRE(pe.has_resources());

        auto rsrc = pe.resources();
        REQUIRE(rsrc != nullptr);

        SUBCASE("Find and parse version resource") {
            auto versions = rsrc->resources_by_type(resource_type::RT_VERSION);
            REQUIRE(!versions.empty());

            auto& version_entry = versions[0];
            auto parsed = version_info_parser::parse(version_entry.data());

            REQUIRE(parsed.has_value());

            SUBCASE("Validate VS_FIXEDFILEINFO") {
                const auto& fixed = parsed->fixed_info;

                // Check signature
                CHECK(fixed.signature == 0xFEEF04BD);

                // File version should be non-zero
                bool has_file_version = (fixed.file_version_major > 0) || (fixed.file_version_minor > 0);
                CHECK(has_file_version);

                // Product version should be non-zero
                bool has_product_version = (fixed.product_version_major > 0) || (fixed.product_version_minor > 0);
                CHECK(has_product_version);

                // Version string should be formatted correctly
                auto file_ver = fixed.file_version_string();
                CHECK(!file_ver.empty());
                CHECK(file_ver.find('.') != std::string::npos);

                auto prod_ver = fixed.product_version_string();
                CHECK(!prod_ver.empty());
                CHECK(prod_ver.find('.') != std::string::npos);
            }

            SUBCASE("Test file flags methods") {
                const auto& fixed = parsed->fixed_info;

                // These methods should not crash
                bool is_debug = fixed.is_debug();
                bool is_prerelease = fixed.is_prerelease();
                bool is_patched = fixed.is_patched();
                bool is_private = fixed.is_private_build();
                bool is_special = fixed.is_special_build();

                // Flags are boolean, so any value is valid
                (void)is_debug;
                (void)is_prerelease;
                (void)is_patched;
                (void)is_private;
                (void)is_special;
            }

            SUBCASE("Validate StringFileInfo") {
                const auto& strings = parsed->strings;

                // Version resources typically have these standard strings
                // (though not all are guaranteed to be present)

                // Check if we can retrieve strings without crashing
                auto company = parsed->company_name();
                auto product = parsed->product_name();
                auto file_desc = parsed->file_description();
                auto file_ver = parsed->file_version();
                auto prod_ver = parsed->product_version();
                auto copyright = parsed->legal_copyright();
                auto internal = parsed->internal_name();
                auto original = parsed->original_filename();

                // At least one string should be present
                bool has_strings = !company.empty() ||
                                   !product.empty() ||
                                   !file_desc.empty() ||
                                   !copyright.empty();
                CHECK(has_strings);
            }

            SUBCASE("Test get_string method") {
                // get_string should return empty string for non-existent keys
                auto non_existent = parsed->get_string("NonExistentKey12345");
                CHECK(non_existent.empty());

                // If any strings exist, verify get_string works
                if (!parsed->strings.empty()) {
                    auto first_key = parsed->strings.begin()->first;
                    auto value = parsed->get_string(first_key);
                    CHECK(value == parsed->strings.begin()->second);
                }
            }
        }

        SUBCASE("Validate version resource size") {
            auto version_opt = rsrc->find_resource(resource_type::RT_VERSION, 1);
            REQUIRE(version_opt.has_value());

            // TCMDX32.EXE version resource is 1136 bytes (verified with wrestool)
            CHECK(version_opt->size() == 1136);
        }

        SUBCASE("Parse error handling - empty data") {
            std::vector<uint8_t> empty;
            auto result = version_info_parser::parse(empty);
            CHECK(!result.has_value());
        }

        SUBCASE("Parse error handling - invalid data") {
            std::vector<uint8_t> invalid = {0x00, 0x01, 0x02, 0x03};
            auto result = version_info_parser::parse(invalid);
            CHECK(!result.has_value());
        }

        SUBCASE("Use convenience method as_version_info()") {
            auto versions = rsrc->resources_by_type(resource_type::RT_VERSION);
            REQUIRE(!versions.empty());

            auto parsed = versions[0].as_version_info();
            REQUIRE(parsed.has_value());

            // Verify it's the same as direct parsing
            CHECK(parsed->fixed_info.signature == 0xFEEF04BD);
            CHECK(!parsed->strings.empty());
        }
    }
}

TEST_SUITE("Manifest Parser") {
    TEST_CASE("Parse RT_MANIFEST from TCMDX32.EXE") {
        // Load TCMDX32.EXE from embedded data
        auto data = load_tcmdx32();
        auto pe = pe_file::from_memory(data);

        REQUIRE(pe.has_resources());

        auto rsrc = pe.resources();
        REQUIRE(rsrc != nullptr);

        SUBCASE("Find and parse manifest resource") {
            auto manifests = rsrc->resources_by_type(resource_type::RT_MANIFEST);
            REQUIRE(!manifests.empty());

            auto& manifest_entry = manifests[0];
            auto parsed = manifest_parser::parse(manifest_entry.data());

            REQUIRE(parsed.has_value());

            SUBCASE("Validate XML content") {
                const auto& xml = parsed->xml;

                // Manifest should not be empty
                CHECK(!xml.empty());
                CHECK(!parsed->empty());
                CHECK(parsed->size() > 0);

                // Should look like XML
                CHECK(xml.find('<') != std::string::npos);
                CHECK(xml.find('>') != std::string::npos);

                // Should contain manifest-specific elements
                bool has_manifest_elements = (xml.find("assembly") != std::string::npos) ||
                                              (xml.find("manifest") != std::string::npos);
                CHECK(has_manifest_elements);
            }

            SUBCASE("Test contains method") {
                // contains() should work for basic string search
                CHECK(parsed->contains("<"));

                bool has_assembly_or_manifest = parsed->contains("assembly") || parsed->contains("manifest");
                CHECK(has_assembly_or_manifest);

                // Should return false for strings not in manifest
                CHECK(!parsed->contains("ThisStringDoesNotExistInManifest12345"));
            }

            SUBCASE("Test UAC/execution level detection methods") {
                // UAC methods
                bool needs_admin = parsed->requires_admin();
                bool highest_avail = parsed->requires_highest_available();
                bool as_invoker = parsed->runs_as_invoker();
                bool auto_elevate = parsed->is_auto_elevate();

                // Methods return boolean, any value is valid
                (void)needs_admin;
                (void)highest_avail;
                (void)as_invoker;
                (void)auto_elevate;

                // If manifest contains requestedExecutionLevel, check for consistency
                if (parsed->contains("requestedExecutionLevel")) {
                    // requires_admin() should only be true if "requireAdministrator" is present
                    if (parsed->requires_admin()) {
                        CHECK(parsed->contains("requireAdministrator"));
                    }
                    if (parsed->requires_highest_available()) {
                        CHECK(parsed->contains("highestAvailable"));
                    }
                    if (parsed->runs_as_invoker()) {
                        CHECK(parsed->contains("asInvoker"));
                    }
                }
            }

            SUBCASE("Test DPI awareness methods") {
                // Legacy dpiAware
                bool dpi_aware = parsed->is_dpi_aware();
                (void)dpi_aware;

                // Windows 10+ dpiAwareness
                bool has_awareness = parsed->has_dpi_awareness();
                bool per_mon_v2 = parsed->is_per_monitor_v2_aware();
                bool per_mon = parsed->is_per_monitor_aware();
                bool system_aware = parsed->is_system_aware();
                bool gdi_scaling = parsed->has_gdi_scaling();

                (void)has_awareness;
                (void)per_mon_v2;
                (void)per_mon;
                (void)system_aware;
                (void)gdi_scaling;

                // If manifest contains dpiAware, is_dpi_aware() should return true
                if (parsed->contains("dpiAware")) {
                    CHECK(parsed->is_dpi_aware());
                }

                // Check consistency for Per-Monitor V2
                if (parsed->is_per_monitor_v2_aware()) {
                    CHECK(parsed->contains("PerMonitorV2"));
                }
            }

            SUBCASE("Test Windows version compatibility methods") {
                bool vista = parsed->supports_windows_vista();
                bool win7 = parsed->supports_windows7();
                bool win8 = parsed->supports_windows8();
                bool win81 = parsed->supports_windows8_1();
                bool win10 = parsed->supports_windows10();
                bool win11 = parsed->supports_windows11();

                (void)vista;
                (void)win7;
                (void)win8;
                (void)win81;
                (void)win10;
                (void)win11;

                // Check consistency with GUIDs
                if (parsed->supports_windows10()) {
                    CHECK(parsed->contains("{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"));
                }
                if (parsed->supports_windows11()) {
                    CHECK(parsed->contains("{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9b}"));
                }
            }

            SUBCASE("Test high resolution input methods") {
                bool high_res_scroll = parsed->is_high_resolution_scrolling_aware();
                bool ultra_high_res_scroll = parsed->is_ultra_high_resolution_scrolling_aware();

                (void)high_res_scroll;
                (void)ultra_high_res_scroll;
            }

            SUBCASE("Test other Windows settings methods") {
                bool disable_theme = parsed->disables_theming();
                bool disable_filter = parsed->disables_window_filtering();
                bool printer_isolation = parsed->has_printer_driver_isolation();
                bool long_path = parsed->is_long_path_aware();
                bool active_cp = parsed->has_active_code_page();
                bool utf8 = parsed->is_utf8_enabled();
                bool heap_type = parsed->has_heap_type();
                bool segment_heap = parsed->uses_segment_heap();
                bool arch = parsed->has_supported_architectures();

                (void)disable_theme;
                (void)disable_filter;
                (void)printer_isolation;
                (void)long_path;
                (void)active_cp;
                (void)utf8;
                (void)heap_type;
                (void)segment_heap;
                (void)arch;

                // Check UTF-8 consistency
                if (parsed->is_utf8_enabled()) {
                    CHECK(parsed->has_active_code_page());
                    CHECK(parsed->contains("UTF-8"));
                }

                // Check segment heap consistency
                if (parsed->uses_segment_heap()) {
                    CHECK(parsed->has_heap_type());
                    CHECK(parsed->contains("SegmentHeap"));
                }
            }
        }

        SUBCASE("Validate manifest resource size") {
            auto manifest_opt = rsrc->find_resource(resource_type::RT_MANIFEST, 1);
            REQUIRE(manifest_opt.has_value());

            // TCMDX32.EXE manifest is 1052 bytes (verified with wrestool)
            CHECK(manifest_opt->size() == 1052);
        }

        SUBCASE("Parse error handling - empty data") {
            std::vector<uint8_t> empty;
            auto result = manifest_parser::parse(empty);
            CHECK(!result.has_value());
        }

        SUBCASE("Parse error handling - non-XML data") {
            std::vector<uint8_t> not_xml = {'H', 'e', 'l', 'l', 'o'};
            auto result = manifest_parser::parse(not_xml);
            // Parser should reject data without '<' character
            CHECK(!result.has_value());
        }

        SUBCASE("Parse null-padded manifest") {
            // Create manifest with trailing nulls (common in resources)
            std::string xml_content = "<?xml version=\"1.0\"?><manifest></manifest>";
            std::vector<uint8_t> padded_data(xml_content.begin(), xml_content.end());
            padded_data.push_back('\0');
            padded_data.push_back('\0');
            padded_data.push_back('\0');

            auto result = manifest_parser::parse(padded_data);
            REQUIRE(result.has_value());

            // Trailing nulls should be trimmed
            CHECK(!result->xml.empty());
            CHECK(result->xml.back() != '\0');
            CHECK(result->xml == xml_content);
        }

        SUBCASE("Use convenience method as_manifest()") {
            auto manifests = rsrc->resources_by_type(resource_type::RT_MANIFEST);
            REQUIRE(!manifests.empty());

            auto parsed = manifests[0].as_manifest();
            REQUIRE(parsed.has_value());

            // Verify it's the same as direct parsing
            CHECK(!parsed->xml.empty());

            bool has_manifest_elements = (parsed->xml.find("assembly") != std::string::npos) ||
                                          (parsed->xml.find("manifest") != std::string::npos);
            CHECK(has_manifest_elements);
        }

        SUBCASE("Test enum-based UAC API") {
            auto manifests = rsrc->resources_by_type(resource_type::RT_MANIFEST);
            REQUIRE(!manifests.empty());
            auto parsed = manifests[0].as_manifest();
            REQUIRE(parsed.has_value());

            // Use the new enum-based API
            auto uac_level = parsed->get_uac_execution_level();

            // Should be one of the valid enum values
            bool is_valid = (uac_level == uac_execution_level::UNSPECIFIED ||
                            uac_level == uac_execution_level::AS_INVOKER ||
                            uac_level == uac_execution_level::HIGHEST_AVAILABLE ||
                            uac_level == uac_execution_level::REQUIRE_ADMINISTRATOR);
            CHECK(is_valid);

            // Verify consistency with bool methods
            if (uac_level == uac_execution_level::REQUIRE_ADMINISTRATOR) {
                CHECK(parsed->requires_admin());
            } else if (uac_level == uac_execution_level::HIGHEST_AVAILABLE) {
                CHECK(parsed->requires_highest_available());
            } else if (uac_level == uac_execution_level::AS_INVOKER) {
                CHECK(parsed->runs_as_invoker());
            }
        }

        SUBCASE("Test enum-based DPI awareness API") {
            auto manifests = rsrc->resources_by_type(resource_type::RT_MANIFEST);
            REQUIRE(!manifests.empty());
            auto parsed = manifests[0].as_manifest();
            REQUIRE(parsed.has_value());

            // Use the new enum-based API
            auto dpi_mode = parsed->get_dpi_awareness();

            // Should be one of the valid enum values
            bool is_valid = (dpi_mode == dpi_awareness_mode::UNSPECIFIED ||
                            dpi_mode == dpi_awareness_mode::UNAWARE ||
                            dpi_mode == dpi_awareness_mode::SYSTEM_AWARE ||
                            dpi_mode == dpi_awareness_mode::PER_MONITOR ||
                            dpi_mode == dpi_awareness_mode::PER_MONITOR_V2);
            CHECK(is_valid);

            // Verify consistency with bool methods
            if (dpi_mode == dpi_awareness_mode::PER_MONITOR_V2) {
                CHECK(parsed->is_per_monitor_v2_aware());
            } else if (dpi_mode == dpi_awareness_mode::PER_MONITOR) {
                CHECK(parsed->is_per_monitor_aware());
            } else if (dpi_mode == dpi_awareness_mode::SYSTEM_AWARE) {
                CHECK(parsed->is_system_aware());
            }
        }

        SUBCASE("Test bitmask-based Windows version API") {
            auto manifests = rsrc->resources_by_type(resource_type::RT_MANIFEST);
            REQUIRE(!manifests.empty());
            auto parsed = manifests[0].as_manifest();
            REQUIRE(parsed.has_value());

            // Use the new bitmask-based API
            auto versions = parsed->get_windows_compatibility();

            // Verify consistency with individual bool methods
            CHECK(has_flag(versions, windows_version_flags::VISTA) == parsed->supports_windows_vista());
            CHECK(has_flag(versions, windows_version_flags::WIN7) == parsed->supports_windows7());
            CHECK(has_flag(versions, windows_version_flags::WIN8) == parsed->supports_windows8());
            CHECK(has_flag(versions, windows_version_flags::WIN8_1) == parsed->supports_windows8_1());
            CHECK(has_flag(versions, windows_version_flags::WIN10) == parsed->supports_windows10());
            CHECK(has_flag(versions, windows_version_flags::WIN11) == parsed->supports_windows11());
        }

        SUBCASE("Test bitmask-based manifest flags API") {
            auto manifests = rsrc->resources_by_type(resource_type::RT_MANIFEST);
            REQUIRE(!manifests.empty());
            auto parsed = manifests[0].as_manifest();
            REQUIRE(parsed.has_value());

            // Use the new bitmask-based API
            auto flags = parsed->get_flags();

            // Verify consistency with individual bool methods
            CHECK(has_flag(flags, manifest_flags::AUTO_ELEVATE) == parsed->is_auto_elevate());
            CHECK(has_flag(flags, manifest_flags::DISABLE_THEMING) == parsed->disables_theming());
            CHECK(has_flag(flags, manifest_flags::DISABLE_WINDOW_FILTERING) == parsed->disables_window_filtering());
            CHECK(has_flag(flags, manifest_flags::PRINTER_DRIVER_ISOLATION) == parsed->has_printer_driver_isolation());
            CHECK(has_flag(flags, manifest_flags::LONG_PATH_AWARE) == parsed->is_long_path_aware());
            CHECK(has_flag(flags, manifest_flags::UTF8_CODE_PAGE) == parsed->is_utf8_enabled());
            CHECK(has_flag(flags, manifest_flags::SEGMENT_HEAP) == parsed->uses_segment_heap());
            CHECK(has_flag(flags, manifest_flags::GDI_SCALING) == parsed->has_gdi_scaling());
            CHECK(has_flag(flags, manifest_flags::HIGH_RESOLUTION_SCROLLING) == parsed->is_high_resolution_scrolling_aware());
            CHECK(has_flag(flags, manifest_flags::ULTRA_HIGH_RESOLUTION_SCROLLING) == parsed->is_ultra_high_resolution_scrolling_aware());
        }
    }
}
