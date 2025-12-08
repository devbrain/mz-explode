// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/pe_file.hpp>
#include <libexe/parsers/export_directory_parser.hpp>
#include <libexe/export_directory.hpp>
#include <libexe/pe_types.hpp>
#include <doctest/doctest.h>
#include <filesystem>
#include <fstream>

using namespace libexe;

// =============================================================================
// Helper Functions
// =============================================================================

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
// Export Directory Parser Tests
// =============================================================================

TEST_CASE("Export parser - Data directory accessors") {
    std::filesystem::path test_file = "data/scheduler.exe";

    if (!std::filesystem::exists(test_file)) {
        MESSAGE("Test file not found: " << test_file << " (skipping test)");
        return;
    }

    auto pe = pe_file::from_file(test_file);

    SUBCASE("Check if export directory exists") {
        // Most EXE files don't export functions (only DLLs do)
        bool has_exports = pe.has_data_directory(directory_entry::EXPORT);
        MESSAGE("Has exports: " << (has_exports ? "yes" : "no"));

        if (has_exports) {
            uint32_t export_rva = pe.data_directory_rva(directory_entry::EXPORT);
            uint32_t export_size = pe.data_directory_size(directory_entry::EXPORT);

            CHECK(export_rva > 0);
            CHECK(export_size > 0);

            MESSAGE("Export directory at RVA: 0x" << std::hex << export_rva
                    << ", size: " << std::dec << export_size << " bytes");
        }
    }
}

TEST_CASE("Export parser - Export directory parsing (EXE without exports)") {
    std::filesystem::path test_file = "data/scheduler.exe";

    if (!std::filesystem::exists(test_file)) {
        MESSAGE("Test file not found: " << test_file << " (skipping test)");
        return;
    }

    auto pe = pe_file::from_file(test_file);

    SUBCASE("Get export directory from EXE") {
        auto exports = pe.exports();
        REQUIRE(exports != nullptr);

        // scheduler.exe is an EXE, likely has no exports
        if (exports->export_count() == 0) {
            MESSAGE("No exports (expected for EXE file)");
            CHECK(exports->named_export_count() == 0);
            CHECK(exports->forwarder_count() == 0);
        } else {
            MESSAGE("Found " << exports->export_count() << " exports (unusual for EXE)");
            MESSAGE("Module: " << exports->module_name);

            // List all exports
            for (const auto& exp : exports->exports) {
                MESSAGE("Export: " << exp.display_name());
            }
        }
    }
}

TEST_CASE("Export parser - Export counts") {
    // Create test export directory
    export_directory exports;
    exports.module_name = "TEST.dll";
    exports.ordinal_base = 1;

    SUBCASE("Empty export directory") {
        CHECK(exports.export_count() == 0);
        CHECK(exports.named_export_count() == 0);
        CHECK(exports.forwarder_count() == 0);
        CHECK(!exports.has_forwarders());
    }

    SUBCASE("Named exports") {
        export_entry exp1;
        exp1.name = "Function1";
        exp1.ordinal = 1;
        exp1.has_name = true;
        exp1.is_forwarder = false;
        exp1.rva = 0x1000;

        export_entry exp2;
        exp2.name = "Function2";
        exp2.ordinal = 2;
        exp2.has_name = true;
        exp2.is_forwarder = false;
        exp2.rva = 0x2000;

        exports.exports.push_back(exp1);
        exports.exports.push_back(exp2);

        CHECK(exports.export_count() == 2);
        CHECK(exports.named_export_count() == 2);
        CHECK(exports.forwarder_count() == 0);
    }

    SUBCASE("Ordinal-only exports") {
        export_entry exp1;
        exp1.name = "";
        exp1.ordinal = 1;
        exp1.has_name = false;
        exp1.is_forwarder = false;
        exp1.rva = 0x1000;

        export_entry exp2;
        exp2.name = "";
        exp2.ordinal = 2;
        exp2.has_name = false;
        exp2.is_forwarder = false;
        exp2.rva = 0x2000;

        exports.exports.push_back(exp1);
        exports.exports.push_back(exp2);

        CHECK(exports.export_count() == 2);
        CHECK(exports.named_export_count() == 0);
        CHECK(exports.forwarder_count() == 0);
    }

    SUBCASE("Mixed exports with forwarders") {
        export_entry exp1;
        exp1.name = "ForwardedFunc";
        exp1.ordinal = 1;
        exp1.has_name = true;
        exp1.is_forwarder = true;
        exp1.forwarder_name = "NTDLL.RtlAllocateHeap";
        exp1.rva = 0x1000;

        export_entry exp2;
        exp2.name = "RegularFunc";
        exp2.ordinal = 2;
        exp2.has_name = true;
        exp2.is_forwarder = false;
        exp2.rva = 0x2000;

        export_entry exp3;
        exp3.name = "";
        exp3.ordinal = 3;
        exp3.has_name = false;
        exp3.is_forwarder = false;
        exp3.rva = 0x3000;

        exports.exports.push_back(exp1);
        exports.exports.push_back(exp2);
        exports.exports.push_back(exp3);

        CHECK(exports.export_count() == 3);
        CHECK(exports.named_export_count() == 2);
        CHECK(exports.forwarder_count() == 1);
        CHECK(exports.has_forwarders());
    }
}

TEST_CASE("Export parser - Find exports") {
    export_directory exports;
    exports.module_name = "TEST.dll";
    exports.ordinal_base = 1;

    export_entry exp1;
    exp1.name = "CreateFileW";
    exp1.ordinal = 1;
    exp1.has_name = true;
    exp1.is_forwarder = false;
    exp1.rva = 0x1000;

    export_entry exp2;
    exp2.name = "CloseHandle";
    exp2.ordinal = 2;
    exp2.has_name = true;
    exp2.is_forwarder = false;
    exp2.rva = 0x2000;

    export_entry exp3;
    exp3.name = "";
    exp3.ordinal = 10;
    exp3.has_name = false;
    exp3.is_forwarder = false;
    exp3.rva = 0x3000;

    exports.exports.push_back(exp1);
    exports.exports.push_back(exp2);
    exports.exports.push_back(exp3);

    SUBCASE("Find by name") {
        auto found = exports.find_export("CreateFileW");
        REQUIRE(found != nullptr);
        CHECK(found->name == "CreateFileW");
        CHECK(found->ordinal == 1);
        CHECK(found->rva == 0x1000);

        found = exports.find_export("CloseHandle");
        REQUIRE(found != nullptr);
        CHECK(found->name == "CloseHandle");
        CHECK(found->ordinal == 2);

        // Not found
        found = exports.find_export("NonExistentFunction");
        CHECK(found == nullptr);
    }

    SUBCASE("Find by ordinal") {
        auto found = exports.find_export_by_ordinal(1);
        REQUIRE(found != nullptr);
        CHECK(found->ordinal == 1);
        CHECK(found->name == "CreateFileW");

        found = exports.find_export_by_ordinal(10);
        REQUIRE(found != nullptr);
        CHECK(found->ordinal == 10);
        CHECK(found->has_name == false);

        // Not found
        found = exports.find_export_by_ordinal(999);
        CHECK(found == nullptr);
    }

    SUBCASE("exports_function helper") {
        CHECK(exports.exports_function("CreateFileW"));
        CHECK(exports.exports_function("CloseHandle"));
        CHECK(!exports.exports_function("NonExistentFunction"));
    }

    SUBCASE("Get export names") {
        auto names = exports.get_export_names();
        CHECK(names.size() == 2);

        // Check that both named exports are in the list
        bool has_create = false;
        bool has_close = false;
        for (const auto& name : names) {
            if (name == "CreateFileW") has_create = true;
            if (name == "CloseHandle") has_close = true;
        }
        CHECK(has_create);
        CHECK(has_close);
    }
}

TEST_CASE("Export entry - display names") {
    SUBCASE("Named export") {
        export_entry entry;
        entry.name = "CreateFileW";
        entry.ordinal = 42;
        entry.has_name = true;

        CHECK(entry.display_name() == "CreateFileW");
        CHECK(entry.full_name() == "CreateFileW (ordinal 42)");
    }

    SUBCASE("Ordinal-only export") {
        export_entry entry;
        entry.name = "";
        entry.ordinal = 123;
        entry.has_name = false;

        CHECK(entry.display_name() == "Ordinal 123");
        CHECK(entry.full_name() == "Ordinal 123");
    }

    SUBCASE("Forwarder export") {
        export_entry entry;
        entry.name = "HeapAlloc";
        entry.ordinal = 10;
        entry.has_name = true;
        entry.is_forwarder = true;
        entry.forwarder_name = "NTDLL.RtlAllocateHeap";

        CHECK(entry.display_name() == "HeapAlloc");
        CHECK(entry.full_name() == "HeapAlloc (ordinal 10)");
        CHECK(entry.is_forwarder);
        CHECK(entry.forwarder_name == "NTDLL.RtlAllocateHeap");
    }
}

TEST_CASE("Export parser - Invalid data directory index") {
    std::filesystem::path test_file = "data/scheduler.exe";

    if (!std::filesystem::exists(test_file)) {
        MESSAGE("Test file not found: " << test_file << " (skipping test)");
        return;
    }

    auto pe = pe_file::from_file(test_file);

    SUBCASE("Out of range directory entry should throw") {
        CHECK_THROWS_AS(
            pe.data_directory_rva(static_cast<directory_entry>(999)),
            std::out_of_range
        );
    }
}

TEST_CASE("Export parser - Empty export directory handling") {
    export_directory exports;

    SUBCASE("Empty directory is valid") {
        CHECK(exports.export_count() == 0);
        CHECK(exports.named_export_count() == 0);
        CHECK(exports.forwarder_count() == 0);
        CHECK(!exports.has_forwarders());
        CHECK(exports.find_export("anything") == nullptr);
        CHECK(exports.find_export_by_ordinal(1) == nullptr);
        CHECK(!exports.exports_function("anything"));

        auto names = exports.get_export_names();
        CHECK(names.empty());
    }
}
