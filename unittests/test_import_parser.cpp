// libexe - Modern executable file analysis library
// Import directory parser tests with ground truth from objdump
//
// Ground truth for scheduler.exe (objdump -p):
//   - 9 imported DLLs: KERNEL32.dll, USER32.dll, GDI32.dll, COMDLG32.dll,
//     SHELL32.dll, SHLWAPI.dll, COMCTL32.dll, ADVAPI32.dll, ole32.dll
//   - Import directory at RVA 0x6ccd4, size 0xc8 (200 bytes)
//   - IAT at RVA 0x5c000, size 0x3d4

#include <libexe/formats/pe_file.hpp>
#include <libexe/pe/directories/import.hpp>
#include <libexe/pe/types.hpp>
#include <doctest/doctest.h>
#include <algorithm>

using namespace libexe;

// External test data (embedded scheduler.exe)
namespace data {
    extern size_t scheduler_len;
    extern unsigned char scheduler[];
}

static std::vector<uint8_t> load_scheduler() {
    return std::vector<uint8_t>(
        data::scheduler,
        data::scheduler + data::scheduler_len
    );
}

// =============================================================================
// Import Directory Tests - Ground Truth from objdump
// =============================================================================

TEST_CASE("Import parser - Data directory location") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);

    // Ground truth from objdump: Entry 1 0006ccd4 000000c8 Import Directory
    CHECK(pe.has_data_directory(directory_entry::IMPORT));
    CHECK(pe.data_directory_rva(directory_entry::IMPORT) == 0x6ccd4);
    CHECK(pe.data_directory_size(directory_entry::IMPORT) == 0xc8);

    // Ground truth: Entry c 0005c000 000003d4 Import Address Table
    CHECK(pe.has_data_directory(directory_entry::IAT));
    CHECK(pe.data_directory_rva(directory_entry::IAT) == 0x5c000);
    CHECK(pe.data_directory_size(directory_entry::IAT) == 0x3d4);
}

TEST_CASE("Import parser - DLL count and names") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto imports = pe.imports();
    REQUIRE(imports != nullptr);

    // Ground truth from objdump: 9 DLLs
    CHECK(imports->dll_count() == 9);

    // Ground truth: exact DLL names (case-insensitive comparison)
    const std::vector<std::string> expected_dlls = {
        "KERNEL32.dll", "USER32.dll", "GDI32.dll", "COMDLG32.dll",
        "SHELL32.dll", "SHLWAPI.dll", "COMCTL32.dll", "ADVAPI32.dll", "ole32.dll"
    };

    for (const auto& expected : expected_dlls) {
        bool found = false;
        for (const auto& dll : imports->dlls) {
            // Case-insensitive comparison
            std::string dll_lower = dll.name;
            std::string exp_lower = expected;
            std::transform(dll_lower.begin(), dll_lower.end(), dll_lower.begin(), ::tolower);
            std::transform(exp_lower.begin(), exp_lower.end(), exp_lower.begin(), ::tolower);
            if (dll_lower == exp_lower) {
                found = true;
                break;
            }
        }
        CHECK_MESSAGE(found, "Missing DLL: " << expected);
    }
}

TEST_CASE("Import parser - KERNEL32.dll imports") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto imports = pe.imports();
    REQUIRE(imports != nullptr);

    auto kernel32 = imports->find_dll("KERNEL32.dll");
    REQUIRE(kernel32 != nullptr);

    // Ground truth from objdump: KERNEL32.dll has many imports
    // Some specific ones from objdump output:
    CHECK(kernel32->find_function("SetStdHandle") != nullptr);
    CHECK(kernel32->find_function("GetDriveTypeA") != nullptr);
    CHECK(kernel32->find_function("GetCurrentProcessId") != nullptr);
    CHECK(kernel32->find_function("GetTickCount") != nullptr);
    CHECK(kernel32->find_function("QueryPerformanceCounter") != nullptr);
    CHECK(kernel32->find_function("GetEnvironmentStringsW") != nullptr);
    CHECK(kernel32->find_function("FreeEnvironmentStringsW") != nullptr);
    CHECK(kernel32->find_function("FlushFileBuffers") != nullptr);
    CHECK(kernel32->find_function("SetFilePointer") != nullptr);

    // Check hints match objdump output
    auto set_std_handle = kernel32->find_function("SetStdHandle");
    if (set_std_handle) {
        CHECK(set_std_handle->hint == 1020);
    }

    auto get_drive_type = kernel32->find_function("GetDriveTypeA");
    if (get_drive_type) {
        CHECK(get_drive_type->hint == 442);
    }

    auto get_current_pid = kernel32->find_function("GetCurrentProcessId");
    if (get_current_pid) {
        CHECK(get_current_pid->hint == 426);
    }
}

TEST_CASE("Import parser - USER32.dll imports") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto imports = pe.imports();
    REQUIRE(imports != nullptr);

    auto user32 = imports->find_dll("USER32.dll");
    REQUIRE(user32 != nullptr);

    // Ground truth from objdump: GetActiveWindow with hint 249
    auto get_active_window = user32->find_function("GetActiveWindow");
    CHECK(get_active_window != nullptr);
    if (get_active_window) {
        CHECK(get_active_window->hint == 249);
    }
}

TEST_CASE("Import parser - GDI32.dll imports") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto imports = pe.imports();
    REQUIRE(imports != nullptr);

    auto gdi32 = imports->find_dll("GDI32.dll");
    REQUIRE(gdi32 != nullptr);

    // Ground truth from objdump: MoveToEx with hint 545
    auto move_to_ex = gdi32->find_function("MoveToEx");
    CHECK(move_to_ex != nullptr);
    if (move_to_ex) {
        CHECK(move_to_ex->hint == 545);
    }
}

TEST_CASE("Import parser - COMDLG32.dll imports") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto imports = pe.imports();
    REQUIRE(imports != nullptr);

    auto comdlg32 = imports->find_dll("COMDLG32.dll");
    REQUIRE(comdlg32 != nullptr);

    // Ground truth from objdump: GetOpenFileNameA with hint 11
    auto get_open_filename = comdlg32->find_function("GetOpenFileNameA");
    CHECK(get_open_filename != nullptr);
    if (get_open_filename) {
        CHECK(get_open_filename->hint == 11);
    }
}

TEST_CASE("Import parser - Total import count") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto imports = pe.imports();
    REQUIRE(imports != nullptr);

    // Ground truth from objdump: 236 total imports
    CHECK(imports->total_imports() == 236);
}

TEST_CASE("Import parser - Import entry validation") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto imports = pe.imports();
    REQUIRE(imports != nullptr);

    // All imports should have valid IAT RVAs
    for (const auto& dll : imports->dlls) {
        CHECK(dll.iat_rva != 0);
        CHECK(!dll.name.empty());

        for (const auto& func : dll.functions) {
            if (!func.is_ordinal) {
                CHECK(!func.name.empty());
            }
            CHECK(func.iat_rva > 0);
        }
    }
}

TEST_CASE("Import parser - Function lookup") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto imports = pe.imports();
    REQUIRE(imports != nullptr);

    // Test imports_function helper (case-sensitive DLL names)
    CHECK(imports->imports_function("KERNEL32.dll", "SetStdHandle"));
    CHECK(imports->imports_function("USER32.dll", "GetActiveWindow"));
    CHECK(imports->imports_function("GDI32.dll", "MoveToEx"));

    // Non-existent function
    CHECK_FALSE(imports->imports_function("KERNEL32.dll", "FakeFunction12345"));

    // Non-existent DLL
    CHECK_FALSE(imports->imports_function("fake.dll", "ExitProcess"));
}

// =============================================================================
// Import Entry Display Name Tests
// =============================================================================

TEST_CASE("Import entry - display_name()") {
    SUBCASE("Named import") {
        import_entry entry;
        entry.name = "CreateFileW";
        entry.ordinal = 0;
        entry.is_ordinal = false;

        CHECK(entry.display_name() == "CreateFileW");
    }

    SUBCASE("Ordinal import") {
        import_entry entry;
        entry.name = "";
        entry.ordinal = 42;
        entry.is_ordinal = true;

        CHECK(entry.display_name() == "#42");
    }
}
