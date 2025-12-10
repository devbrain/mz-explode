// Test PE security analysis (ASLR/DEP/CFG) and import/export analysis
#include <doctest/doctest.h>
#include <libexe/formats/pe_file.hpp>
#include <libexe/pe/types.hpp>
#include <libexe/pe/directories/import.hpp>
#include <libexe/pe/directories/export.hpp>
#include <libexe/pe/directories/load_config.hpp>
#include <vector>

using namespace libexe;

// External test data - 64-bit PE with modern security features
namespace data {
    extern size_t tcmadm64_len;
    extern unsigned char tcmadm64[];
}

namespace {

std::vector<uint8_t> load_tcmadm64() {
    return std::vector<uint8_t>(
        data::tcmadm64,
        data::tcmadm64 + data::tcmadm64_len
    );
}

} // anonymous namespace

// =============================================================================
// Security Feature Analysis Tests
// =============================================================================

TEST_CASE("PE Security Analysis: TCMADM64.EXE (modern 64-bit PE)") {
    auto data = load_tcmadm64();
    auto pe = pe_file::from_memory(data);

    SUBCASE("ASLR detection") {
        // Modern Windows executables should have ASLR enabled
        // Check DllCharacteristics for DYNAMIC_BASE (0x0040)
        bool has_aslr = pe.has_aslr();
        MESSAGE("ASLR enabled: ", has_aslr);
        // Most modern PEs have ASLR, but test data may vary
    }

    SUBCASE("High-entropy ASLR detection") {
        // 64-bit PEs can use high-entropy ASLR for better randomization
        bool has_he_aslr = pe.has_high_entropy_aslr();
        MESSAGE("High-entropy ASLR enabled: ", has_he_aslr);
    }

    SUBCASE("DEP/NX detection") {
        // NX_COMPAT (0x0100) - Data Execution Prevention
        bool has_dep = pe.has_dep();
        MESSAGE("DEP/NX enabled: ", has_dep);
    }

    SUBCASE("CFG detection") {
        // GUARD_CF (0x4000) - Control Flow Guard
        bool has_cfg = pe.has_cfg();
        MESSAGE("CFG enabled: ", has_cfg);
    }

    SUBCASE("SEH analysis") {
        // NO_SEH flag or SafeSEH via load config
        bool no_seh = pe.has_no_seh();
        bool safe_seh = pe.has_safe_seh();
        MESSAGE("NO_SEH flag: ", no_seh);
        MESSAGE("SafeSEH enabled: ", safe_seh);

        // 64-bit executables don't use SafeSEH (it's 32-bit only)
        CHECK(pe.is_64bit());
        CHECK_FALSE(safe_seh);  // Always false for 64-bit
    }

    SUBCASE("Authenticode signature detection") {
        bool has_sig = pe.has_authenticode();
        MESSAGE("Authenticode signature present: ", has_sig);
    }

    SUBCASE(".NET assembly detection") {
        bool is_dotnet = pe.is_dotnet();
        MESSAGE("Is .NET assembly: ", is_dotnet);
        // TCMADM64 is native code, not .NET
        CHECK_FALSE(is_dotnet);
    }

    SUBCASE("File type detection") {
        bool is_dll = pe.is_dll();
        bool is_laa = pe.is_large_address_aware();

        MESSAGE("Is DLL: ", is_dll);
        MESSAGE("Large Address Aware: ", is_laa);

        // TCMADM64 is an executable, not a DLL
        CHECK_FALSE(is_dll);
        // 64-bit PEs are inherently large-address aware
        CHECK(is_laa);
    }

    SUBCASE("AppContainer and Terminal Server") {
        bool is_appcontainer = pe.is_appcontainer();
        bool is_ts_aware = pe.is_terminal_server_aware();

        MESSAGE("AppContainer: ", is_appcontainer);
        MESSAGE("Terminal Server Aware: ", is_ts_aware);
    }

    SUBCASE("Force integrity") {
        bool force_integrity = pe.has_force_integrity();
        MESSAGE("Force Integrity: ", force_integrity);
    }

    SUBCASE("Subsystem detection") {
        bool is_gui = pe.is_gui();
        bool is_console = pe.is_console();
        bool is_native = pe.is_native();
        bool is_efi = pe.is_efi();

        MESSAGE("Is GUI: ", is_gui);
        MESSAGE("Is Console: ", is_console);
        MESSAGE("Is Native: ", is_native);
        MESSAGE("Is EFI: ", is_efi);

        // TCMADM64.EXE is a GUI application
        CHECK(is_gui);
        CHECK_FALSE(is_console);
        CHECK_FALSE(is_native);
        CHECK_FALSE(is_efi);

        // Subsystem enum value should match
        CHECK(pe.subsystem() == pe_subsystem::WINDOWS_GUI);
    }
}

TEST_CASE("PE Security Analysis: DllCharacteristics flags") {
    auto data = load_tcmadm64();
    auto pe = pe_file::from_memory(data);

    // Get raw DllCharacteristics for verification
    auto dll_char = pe.dll_characteristics();

    SUBCASE("Flag consistency check") {
        // Verify that helper methods match raw flag checks
        bool aslr_via_helper = pe.has_aslr();
        bool aslr_via_flag = has_flag(dll_char, pe_dll_characteristics::DYNAMIC_BASE);
        CHECK(aslr_via_helper == aslr_via_flag);

        bool dep_via_helper = pe.has_dep();
        bool dep_via_flag = has_flag(dll_char, pe_dll_characteristics::NX_COMPAT);
        CHECK(dep_via_helper == dep_via_flag);

        bool cfg_via_helper = pe.has_cfg();
        bool cfg_via_flag = has_flag(dll_char, pe_dll_characteristics::GUARD_CF);
        CHECK(cfg_via_helper == cfg_via_flag);
    }
}

// =============================================================================
// Import Analysis Tests
// =============================================================================

TEST_CASE("PE Import Analysis: TCMADM64.EXE") {
    auto data = load_tcmadm64();
    auto pe = pe_file::from_memory(data);

    SUBCASE("Imported DLLs list") {
        auto dlls = pe.imported_dlls();
        MESSAGE("Number of imported DLLs: ", dlls.size());

        CHECK(dlls.size() > 0);

        for (const auto& dll : dlls) {
            MESSAGE("  Imports from: ", dll);
        }
    }

    SUBCASE("Import function count") {
        size_t count = pe.imported_function_count();
        MESSAGE("Total imported functions: ", count);
        CHECK(count > 0);
    }

    SUBCASE("Check for specific DLL imports") {
        // Windows executables typically import from kernel32.dll
        bool imports_kernel32 = pe.imports_dll("kernel32.dll");
        bool imports_kernel32_upper = pe.imports_dll("KERNEL32.DLL");
        bool imports_kernel32_mixed = pe.imports_dll("Kernel32.dll");

        MESSAGE("Imports kernel32.dll: ", imports_kernel32);

        // Case-insensitive comparison should work
        CHECK(imports_kernel32 == imports_kernel32_upper);
        CHECK(imports_kernel32 == imports_kernel32_mixed);
    }

    SUBCASE("Check for specific function imports") {
        // Look for common Windows API functions
        bool imports_exitprocess = pe.imports_function("ExitProcess");
        bool imports_getlasterror = pe.imports_function("GetLastError");

        MESSAGE("Imports ExitProcess: ", imports_exitprocess);
        MESSAGE("Imports GetLastError: ", imports_getlasterror);
    }

    SUBCASE("Check for function from specific DLL") {
        // More precise check: function from specific DLL
        bool exitprocess_from_kernel32 = pe.imports_function("kernel32.dll", "ExitProcess");
        MESSAGE("ExitProcess from kernel32.dll: ", exitprocess_from_kernel32);
    }

    SUBCASE("Full import directory access") {
        auto imports = pe.imports();
        if (imports) {
            MESSAGE("Import directory parsed successfully");
            MESSAGE("  DLL count: ", imports->dll_count());
            MESSAGE("  Total imports: ", imports->total_imports());
            MESSAGE("  Has bound imports: ", imports->has_bound_imports());

            CHECK(imports->dll_count() == pe.imported_dlls().size());
        }
    }
}

// =============================================================================
// Export Analysis Tests
// =============================================================================

TEST_CASE("PE Export Analysis: TCMADM64.EXE") {
    auto data = load_tcmadm64();
    auto pe = pe_file::from_memory(data);

    SUBCASE("Exported functions list") {
        auto exports = pe.exported_functions();
        MESSAGE("Number of exported functions: ", exports.size());

        // TCMADM64.EXE is an executable, may not have exports
        for (const auto& name : exports) {
            MESSAGE("  Exports: ", name);
        }
    }

    SUBCASE("Export function count") {
        size_t count = pe.exported_function_count();
        MESSAGE("Total exported functions: ", count);
    }

    SUBCASE("Full export directory access") {
        auto exports = pe.exports();
        if (exports && exports->export_count() > 0) {
            MESSAGE("Export directory parsed successfully");
            MESSAGE("  Module name: ", exports->module_name);
            MESSAGE("  Export count: ", exports->export_count());
            MESSAGE("  Named exports: ", exports->named_export_count());
            MESSAGE("  Forwarder count: ", exports->forwarder_count());
            MESSAGE("  Ordinal base: ", exports->ordinal_base);
        }
    }
}

// =============================================================================
// Combined Security Report Tests
// =============================================================================

TEST_CASE("PE Security Report: comprehensive analysis") {
    auto data = load_tcmadm64();
    auto pe = pe_file::from_memory(data);

    MESSAGE("=== Security Analysis Report ===");
    MESSAGE("File: TCMADM64.EXE");
    MESSAGE("Format: ", pe.format_name());
    MESSAGE("");

    MESSAGE("Security Features:");
    MESSAGE("  ASLR:              ", pe.has_aslr() ? "Enabled" : "Disabled");
    MESSAGE("  High-Entropy ASLR: ", pe.has_high_entropy_aslr() ? "Enabled" : "Disabled");
    MESSAGE("  DEP/NX:            ", pe.has_dep() ? "Enabled" : "Disabled");
    MESSAGE("  CFG:               ", pe.has_cfg() ? "Enabled" : "Disabled");
    MESSAGE("  SafeSEH:           ", pe.has_safe_seh() ? "Enabled" : "N/A (64-bit)");
    MESSAGE("  NO_SEH:            ", pe.has_no_seh() ? "Yes" : "No");
    MESSAGE("  Force Integrity:   ", pe.has_force_integrity() ? "Yes" : "No");
    MESSAGE("  Authenticode:      ", pe.has_authenticode() ? "Present" : "Not present");
    MESSAGE("");

    MESSAGE("File Properties:");
    MESSAGE("  Is DLL:            ", pe.is_dll() ? "Yes" : "No");
    MESSAGE("  Is .NET:           ", pe.is_dotnet() ? "Yes" : "No");
    MESSAGE("  Large Addr Aware:  ", pe.is_large_address_aware() ? "Yes" : "No");
    MESSAGE("  AppContainer:      ", pe.is_appcontainer() ? "Yes" : "No");
    MESSAGE("  TS Aware:          ", pe.is_terminal_server_aware() ? "Yes" : "No");
    MESSAGE("");

    MESSAGE("Subsystem:");
    MESSAGE("  Is GUI:            ", pe.is_gui() ? "Yes" : "No");
    MESSAGE("  Is Console:        ", pe.is_console() ? "Yes" : "No");
    MESSAGE("  Is Native:         ", pe.is_native() ? "Yes" : "No");
    MESSAGE("  Is EFI:            ", pe.is_efi() ? "Yes" : "No");
    MESSAGE("");

    MESSAGE("Import/Export Summary:");
    MESSAGE("  Imported DLLs:     ", pe.imported_dlls().size());
    MESSAGE("  Imported functions:", pe.imported_function_count());
    MESSAGE("  Exported functions:", pe.exported_function_count());

    // Basic sanity checks
    CHECK(pe.is_64bit());
    CHECK_FALSE(pe.is_dll());
    CHECK_FALSE(pe.is_dotnet());
}
