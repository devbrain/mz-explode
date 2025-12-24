// libexe - Modern executable file analysis library
// Copyright (c) 2024
// Unit tests for Bound Import Directory Parser

#include <doctest/doctest.h>
#include <libexe/formats/pe_file.hpp>
#include <libexe/pe/directories/bound_import.hpp>
#include "test_helpers/pe_test_builder.hpp"
#include <vector>

using namespace libexe;
using namespace test_helpers;

namespace {

/**
 * Create a minimal PE32 file with bound import directory
 *
 * Structure:
 * - DOS header + stub (128 bytes)
 * - PE signature (4 bytes)
 * - COFF header (20 bytes)
 * - Optional header PE32 (224 bytes)
 * - Section table: 1 section (40 bytes)
 * - Padding to 0x400 (file alignment)
 * - Section .rdata at RVA 0x2000, file offset 0x400
 *   - Bound import directory at RVA 0x2000
 */
static std::vector<uint8_t> create_test_pe32_with_bound_imports() {
    std::vector<uint8_t> data;

    // DOS header at offset 0
    create_dos_header(data, 128);

    // PE signature at offset 128
    create_pe_signature(data, 128);

    // COFF header at offset 132
    create_coff_header(data, 132, false); // PE32

    // Optional header at offset 152
    // Bound import directory at RVA 0x2000, size 200 bytes
    create_optional_header_pe32(data, 152, directory_entry::BOUND_IMPORT, 0x2000, 200);

    // Section table at offset 376 (152 + 224)
    // .rdata section: RVA 0x2000, VirtualSize 0x1000, FileOffset 0x400, FileSize 0x1000
    create_section_header(data, 376, ".rdata", 0x2000, 0x1000, 0x400, 0x1000);

    // Ensure file is large enough
    data.resize(0x400 + 0x1000);

    // Create bound import directory at file offset 0x400 (RVA 0x2000)
    uint32_t dir_offset = 0x400;

    // Module names will be stored after descriptors
    // Descriptor 1: USER32.dll at offset 0x30 (48 bytes from start)
    // Descriptor 2: KERNEL32.dll at offset 0x3B (59 bytes from start) with 1 forwarder
    // Forwarder: KERNELBASE.dll at offset 0x48 (72 bytes from start)
    // Null descriptor to terminate
    //
    // String layout:
    // 0x30: "USER32.dll" (11 bytes including null: 0x30-0x3A)
    // 0x3B: "KERNEL32.dll" (13 bytes including null: 0x3B-0x47)
    // 0x48: "KERNELBASE.dll" (15 bytes including null: 0x48-0x56)

    // Descriptor 1: USER32.dll (timestamp 0x50000000, name offset 0x30, 0 forwarders)
    write_u32(data, dir_offset + 0, 0x50000000); // TimeDateStamp
    write_u16(data, dir_offset + 4, 0x0030);     // OffsetModuleName
    write_u16(data, dir_offset + 6, 0);          // NumberOfModuleForwarderRefs

    // Descriptor 2: KERNEL32.dll (timestamp 0x51000000, name offset 0x3B, 1 forwarder)
    write_u32(data, dir_offset + 8, 0x51000000);  // TimeDateStamp
    write_u16(data, dir_offset + 12, 0x003B);     // OffsetModuleName
    write_u16(data, dir_offset + 14, 1);          // NumberOfModuleForwarderRefs

    // Forwarder for KERNEL32: KERNELBASE.dll (timestamp 0x52000000, name offset 0x48)
    write_u32(data, dir_offset + 16, 0x52000000); // TimeDateStamp
    write_u16(data, dir_offset + 20, 0x0048);     // OffsetModuleName (fixed: was 0x44)
    write_u16(data, dir_offset + 22, 0);          // Reserved

    // Null descriptor (all zeros)
    write_u32(data, dir_offset + 24, 0);
    write_u32(data, dir_offset + 28, 0);

    // Module names (properly spaced to avoid overlap)
    write_string(data, dir_offset + 0x30, "USER32.dll");     // Offset 0x30, 11 bytes
    write_string(data, dir_offset + 0x3B, "KERNEL32.dll");   // Offset 0x3B, 13 bytes
    write_string(data, dir_offset + 0x48, "KERNELBASE.dll"); // Offset 0x48, 15 bytes

    return data;
}

/**
 * Create a minimal PE32 file with empty bound import directory
 */
static std::vector<uint8_t> create_test_pe32_empty_bound_imports() {
    std::vector<uint8_t> data;

    create_dos_header(data, 128);
    create_pe_signature(data, 128);
    create_coff_header(data, 132, false);
    create_optional_header_pe32(data, 152, directory_entry::BOUND_IMPORT, 0x2000, 100);
    create_section_header(data, 376, ".rdata", 0x2000, 0x1000, 0x400, 0x1000);

    data.resize(0x400 + 0x1000);

    // Create bound import directory with only null descriptor
    uint32_t dir_offset = 0x400;
    write_u32(data, dir_offset, 0); // Null descriptor (TimeDateStamp = 0)
    write_u32(data, dir_offset + 4, 0);

    return data;
}

/**
 * Create PE32 with bound imports but no data directory entry
 */
static std::vector<uint8_t> create_test_pe32_no_bound_imports_directory() {
    std::vector<uint8_t> data;

    create_dos_header(data, 128);
    create_pe_signature(data, 128);
    create_coff_header(data, 132, false);

    // Set bound import directory RVA and size to 0 (no directory)
    create_optional_header_pe32(data, 152, directory_entry::BOUND_IMPORT, 0, 0);
    create_section_header(data, 376, ".rdata", 0x2000, 0x1000, 0x400, 0x1000);

    data.resize(0x400 + 0x1000);

    return data;
}

} // anonymous namespace

// =============================================================================
// Test Cases
// =============================================================================

TEST_CASE("Bound Import Parser - PE32 with bound imports") {
    auto pe_data = create_test_pe32_with_bound_imports();
    auto pe = pe_file::from_memory(pe_data);

    SUBCASE("PE file loads successfully") {
        CHECK(pe.get_format() == format_type::PE_WIN32);
        CHECK_FALSE(pe.is_64bit());
    }

    SUBCASE("Bound import directory exists") {
        auto bound = pe.bound_imports();
        REQUIRE(bound != nullptr);
        CHECK_FALSE(bound->empty());
        CHECK(bound->dll_count() == 2);
    }

    SUBCASE("First descriptor: USER32.dll") {
        auto bound = pe.bound_imports();
        const auto& desc = bound->descriptors[0];

        CHECK(desc.is_valid());
        CHECK(desc.module_name == "USER32.dll");
        CHECK(desc.time_date_stamp == 0x50000000);
        CHECK(desc.offset_module_name == 0x0030);
        CHECK(desc.number_of_module_forwarder_refs == 0);
        CHECK(desc.forwarder_count() == 0);
        CHECK_FALSE(desc.has_forwarders());
    }

    SUBCASE("Second descriptor: KERNEL32.dll with forwarder") {
        auto bound = pe.bound_imports();
        const auto& desc = bound->descriptors[1];

        CHECK(desc.is_valid());
        CHECK(desc.module_name == "KERNEL32.dll");
        CHECK(desc.time_date_stamp == 0x51000000);
        CHECK(desc.offset_module_name == 0x003B);
        CHECK(desc.number_of_module_forwarder_refs == 1);
        CHECK(desc.forwarder_count() == 1);
        CHECK(desc.has_forwarders());

        SUBCASE("Forwarder: KERNELBASE.dll") {
            REQUIRE(desc.forwarder_refs.size() == 1);
            const auto& fwd = desc.forwarder_refs[0];

            CHECK(fwd.is_valid());
            CHECK(fwd.module_name == "KERNELBASE.dll");
            CHECK(fwd.time_date_stamp == 0x52000000);
            CHECK(fwd.offset_module_name == 0x0048); // Fixed: was 0x44
            CHECK(fwd.reserved == 0);
        }
    }

    SUBCASE("DLL lookup") {
        auto bound = pe.bound_imports();

        // Case-insensitive lookup
        auto user32 = bound->find_dll("USER32.dll");
        REQUIRE(user32 != nullptr);
        CHECK(user32->module_name == "USER32.dll");

        auto kernel32 = bound->find_dll("kernel32.dll"); // lowercase
        REQUIRE(kernel32 != nullptr);
        CHECK(kernel32->module_name == "KERNEL32.dll");

        // Not found
        auto missing = bound->find_dll("NONEXISTENT.dll");
        CHECK(missing == nullptr);
    }

    SUBCASE("DLL names list") {
        auto bound = pe.bound_imports();
        auto names = bound->dll_names();

        REQUIRE(names.size() == 2);
        CHECK(names[0] == "USER32.dll");
        CHECK(names[1] == "KERNEL32.dll");
    }

    SUBCASE("Forwarder queries") {
        auto bound = pe.bound_imports();

        CHECK(bound->has_forwarders());
        CHECK(bound->total_forwarder_count() == 1);
    }
}

TEST_CASE("Bound Import Parser - Empty bound import directory") {
    auto pe_data = create_test_pe32_empty_bound_imports();
    auto pe = pe_file::from_memory(pe_data);

    auto bound = pe.bound_imports();
    REQUIRE(bound != nullptr);

    CHECK(bound->empty());
    CHECK(bound->dll_count() == 0);
    CHECK_FALSE(bound->has_forwarders());
    CHECK(bound->total_forwarder_count() == 0);

    // Empty directory operations
    auto names = bound->dll_names();
    CHECK(names.empty());

    auto dll = bound->find_dll("USER32.dll");
    CHECK(dll == nullptr);
}

TEST_CASE("Bound Import Parser - No bound import directory") {
    auto pe_data = create_test_pe32_no_bound_imports_directory();
    auto pe = pe_file::from_memory(pe_data);

    auto bound = pe.bound_imports();
    REQUIRE(bound != nullptr);

    // Should return empty directory (graceful handling)
    CHECK(bound->empty());
    CHECK(bound->dll_count() == 0);
}

TEST_CASE("Bound Import Parser - Lazy parsing and caching") {
    auto pe_data = create_test_pe32_with_bound_imports();
    auto pe = pe_file::from_memory(pe_data);

    // First access - should parse
    auto bound1 = pe.bound_imports();
    REQUIRE(bound1 != nullptr);
    CHECK(bound1->dll_count() == 2);

    // Second access - should return cached result
    auto bound2 = pe.bound_imports();
    REQUIRE(bound2 != nullptr);
    CHECK(bound2.get() == bound1.get()); // Same pointer (cached)
    CHECK(bound2->dll_count() == 2);
}
