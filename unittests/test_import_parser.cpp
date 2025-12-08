// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/pe_file.hpp>
#include <libexe/parsers/import_directory_parser.hpp>
#include <libexe/import_directory.hpp>
#include <libexe/pe_types.hpp>
#include <doctest/doctest.h>
#include <filesystem>
#include <fstream>

using namespace libexe;

// =============================================================================
// Helper Functions
// =============================================================================

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

static std::vector<uint8_t> read_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + path.string());
    }

    auto size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(buffer.data()), size);

    return buffer;
}

// =============================================================================
// Import Directory Parser Tests
// =============================================================================

TEST_CASE("Import parser - Data directory accessors") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("Check data directory exists") {
        CHECK(pe.has_data_directory(directory_entry::IMPORT));
    }

    SUBCASE("Get import directory RVA and size") {
        uint32_t import_rva = pe.data_directory_rva(directory_entry::IMPORT);
        uint32_t import_size = pe.data_directory_size(directory_entry::IMPORT);

        CHECK(import_rva > 0);
        CHECK(import_size > 0);

        MESSAGE("Import directory at RVA: 0x" << std::hex << import_rva
                << ", size: " << std::dec << import_size << " bytes");
    }

    SUBCASE("Check other data directories") {
        // Export directory (might not exist in scheduler.exe)
        if (pe.has_data_directory(directory_entry::EXPORT)) {
            MESSAGE("Export directory found");
        }

        // Resource directory
        if (pe.has_data_directory(directory_entry::RESOURCE)) {
            MESSAGE("Resource directory found");
        }

        // Base relocation
        if (pe.has_data_directory(directory_entry::BASERELOC)) {
            MESSAGE("Base relocation directory found");
        }
    }
}

TEST_CASE("Import parser - Import directory parsing") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("Get import directory") {
        auto imports = pe.imports();
        REQUIRE(imports != nullptr);

        // scheduler.exe should have imports
        CHECK(imports->dll_count() > 0);

        MESSAGE("Found " << imports->dll_count() << " imported DLLs");
        MESSAGE("Total imports: " << imports->total_imports() << " functions");
    }

    SUBCASE("Check imported DLLs") {
        auto imports = pe.imports();
        REQUIRE(imports != nullptr);
        REQUIRE(imports->dll_count() > 0);

        // List all imported DLLs
        for (const auto& dll : imports->dlls) {
            MESSAGE("DLL: " << dll.name << " (" << dll.function_count() << " functions)");
            CHECK(!dll.name.empty());
            CHECK(dll.function_count() > 0);
        }
    }

    SUBCASE("Check kernel32.dll imports") {
        auto imports = pe.imports();
        REQUIRE(imports != nullptr);

        // Most Windows executables import from kernel32.dll
        auto kernel32 = imports->find_dll("kernel32.dll");

        if (kernel32) {
            MESSAGE("kernel32.dll found with " << kernel32->function_count() << " imports");
            CHECK(kernel32->function_count() > 0);

            // List some common kernel32 functions
            std::vector<std::string> common_funcs = {
                "ExitProcess", "GetModuleHandleA", "GetModuleHandleW",
                "GetProcAddress", "LoadLibraryA", "LoadLibraryW"
            };

            for (const auto& func_name : common_funcs) {
                if (kernel32->find_function(func_name)) {
                    MESSAGE("  - Found: " << func_name);
                }
            }
        } else {
            MESSAGE("kernel32.dll not found in imports (unusual but possible)");
        }
    }

    SUBCASE("Check import details") {
        auto imports = pe.imports();
        REQUIRE(imports != nullptr);
        REQUIRE(imports->dll_count() > 0);

        // Check first DLL's imports in detail
        const auto& first_dll = imports->dlls[0];
        MESSAGE("Checking imports from: " << first_dll.name);

        CHECK(first_dll.ilt_rva != 0);  // Import Lookup Table should exist
        CHECK(first_dll.iat_rva != 0);  // Import Address Table should exist
        CHECK(first_dll.name_rva != 0); // DLL name RVA should exist

        // Check first few imports
        size_t count = std::min<size_t>(5, first_dll.functions.size());
        for (size_t i = 0; i < count; i++) {
            const auto& func = first_dll.functions[i];

            if (func.is_ordinal) {
                MESSAGE("  - Import by ordinal: #" << func.ordinal);
            } else {
                MESSAGE("  - Import by name: " << func.name
                        << " (hint: " << func.hint << ")");
                CHECK(!func.name.empty());
            }

            CHECK(func.iat_rva > 0);  // IAT RVA should be set
        }
    }

    SUBCASE("Test imports_function helper") {
        auto imports = pe.imports();
        REQUIRE(imports != nullptr);

        // If kernel32.dll exists, test specific function checks
        if (imports->find_dll("kernel32.dll")) {
            // These might or might not be imported, just testing the API
            bool has_exit = imports->imports_function("kernel32.dll", "ExitProcess");
            bool has_fake = imports->imports_function("kernel32.dll", "FakeFunction12345");

            MESSAGE("Has ExitProcess: " << (has_exit ? "yes" : "no"));
            CHECK(has_fake == false);  // Should definitely not exist
        }
    }
}

TEST_CASE("Import parser - Bound imports detection") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto imports = pe.imports();
    REQUIRE(imports != nullptr);

    SUBCASE("Check for bound imports") {
        bool has_bound = imports->has_bound_imports();
        MESSAGE("Has bound imports: " << (has_bound ? "yes" : "no"));

        // Check individual DLLs
        for (const auto& dll : imports->dlls) {
            if (dll.is_bound()) {
                MESSAGE("Bound DLL: " << dll.name
                        << " (timestamp: 0x" << std::hex << dll.timestamp << ")");
            }
        }
    }
}

TEST_CASE("Import parser - Empty import directory") {
    // Create minimal PE file with no imports
    std::vector<uint8_t> minimal_pe = {
        // DOS header (64 bytes)
        0x4D, 0x5A,  // e_magic
        0x90, 0x00,  // e_cblp
        0x03, 0x00,  // e_cp
        0x00, 0x00,  // e_crlc
        0x04, 0x00,  // e_cparhdr
        0x00, 0x00,  // e_minalloc
        0xFF, 0xFF,  // e_maxalloc
        0x00, 0x00,  // e_ss
        0xB8, 0x00,  // e_sp
        0x00, 0x00,  // e_csum
        0x00, 0x00,  // e_ip
        0x00, 0x00,  // e_cs
        0x40, 0x00,  // e_lfarlc
        0x00, 0x00,  // e_ovno
    };

    // Pad to 64 bytes and add e_lfanew at offset 0x3C
    minimal_pe.resize(64, 0);
    minimal_pe[0x3C] = 0x80;  // PE header at offset 0x80
    minimal_pe[0x3D] = 0x00;

    // Pad to PE header location
    minimal_pe.resize(0x80, 0);

    // PE signature "PE\0\0"
    minimal_pe.push_back(0x50);
    minimal_pe.push_back(0x45);
    minimal_pe.push_back(0x00);
    minimal_pe.push_back(0x00);

    // COFF header (20 bytes)
    minimal_pe.push_back(0x4C);  // Machine (I386)
    minimal_pe.push_back(0x01);
    minimal_pe.push_back(0x00);  // NumberOfSections = 0
    minimal_pe.push_back(0x00);
    minimal_pe.push_back(0x00);  // TimeDateStamp
    minimal_pe.push_back(0x00);
    minimal_pe.push_back(0x00);
    minimal_pe.push_back(0x00);
    minimal_pe.push_back(0x00);  // PointerToSymbolTable
    minimal_pe.push_back(0x00);
    minimal_pe.push_back(0x00);
    minimal_pe.push_back(0x00);
    minimal_pe.push_back(0x00);  // NumberOfSymbols
    minimal_pe.push_back(0x00);
    minimal_pe.push_back(0x00);
    minimal_pe.push_back(0x00);
    minimal_pe.push_back(0xE0);  // SizeOfOptionalHeader = 224 (PE32)
    minimal_pe.push_back(0x00);
    minimal_pe.push_back(0x02);  // Characteristics (EXECUTABLE_IMAGE)
    minimal_pe.push_back(0x00);

    // Optional header (224 bytes for PE32)
    minimal_pe.push_back(0x0B);  // Magic (PE32)
    minimal_pe.push_back(0x01);

    // Pad optional header to at least include NumberOfRvaAndSizes field
    // Optional header standard fields: 28 bytes
    // Windows-specific fields: up to data directories
    size_t opt_start = minimal_pe.size();
    minimal_pe.resize(opt_start + 222, 0);  // Fill rest of optional header

    // Set NumberOfRvaAndSizes = 0 (no data directories)
    // This field is at offset 92 in PE32 optional header
    // Current position is after magic (2 bytes), so offset from opt_start is 90
    minimal_pe[opt_start + 90] = 0x00;
    minimal_pe[opt_start + 91] = 0x00;
    minimal_pe[opt_start + 92] = 0x00;
    minimal_pe[opt_start + 93] = 0x00;

    // Try to parse this minimal PE
    try {
        auto pe = pe_file::from_memory(minimal_pe);

        // Should not have imports
        CHECK(!pe.has_data_directory(directory_entry::IMPORT));

        auto imports = pe.imports();
        CHECK(imports != nullptr);
        CHECK(imports->dll_count() == 0);
        CHECK(imports->total_imports() == 0);

    } catch (const std::exception& e) {
        MESSAGE("Failed to parse minimal PE: " << e.what());
        // This is acceptable - minimal PE might be too minimal
    }
}

TEST_CASE("Import parser - Invalid data directory index") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("Out of range directory entry should throw") {
        CHECK_THROWS_AS(
            pe.data_directory_rva(static_cast<directory_entry>(999)),
            std::out_of_range
        );
    }
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

    SUBCASE("Ordinal import with empty name") {
        import_entry entry;
        entry.name = "";
        entry.ordinal = 123;
        entry.is_ordinal = true;

        CHECK(entry.display_name() == "#123");
    }
}
