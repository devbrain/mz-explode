// libexe - Modern executable file analysis library
// Copyright (c) 2024
//
// Tests for Exception Directory Parser

#include <doctest/doctest.h>
#include <libexe/formats/pe_file.hpp>
#include <libexe/pe/directories/exception.hpp>
#include <vector>
#include <cstring>

using namespace libexe;

// =============================================================================
// Helper Functions - Create Test PE Files
// =============================================================================

/**
 * Create PE32+ (64-bit) file with exception directory
 */
static std::vector<uint8_t> create_test_pe64_with_exceptions() {
    std::vector<uint8_t> data;
    data.resize(4096);

    // DOS Header
    data[0] = 'M'; data[1] = 'Z';
    uint32_t pe_offset = 0x80;
    std::memcpy(&data[0x3C], &pe_offset, 4);

    // PE Signature
    std::memcpy(&data[pe_offset], "PE\0\0", 4);

    // COFF File Header
    uint16_t machine = 0x8664;  // IMAGE_FILE_MACHINE_AMD64
    std::memcpy(&data[pe_offset + 4], &machine, 2);
    uint16_t num_sections = 1;
    std::memcpy(&data[pe_offset + 6], &num_sections, 2);
    uint16_t opt_hdr_size = 240;  // PE32+
    std::memcpy(&data[pe_offset + 20], &opt_hdr_size, 2);

    // Optional Header
    uint16_t magic = 0x020B;  // PE32+
    std::memcpy(&data[pe_offset + 24], &magic, 2);
    uint64_t image_base = 0x0000000140000000ULL;
    std::memcpy(&data[pe_offset + 48], &image_base, 8);
    uint32_t section_alignment = 0x1000;
    std::memcpy(&data[pe_offset + 56], &section_alignment, 4);
    uint32_t file_alignment = 0x200;
    std::memcpy(&data[pe_offset + 60], &file_alignment, 4);
    uint32_t num_rva_sizes = 16;
    std::memcpy(&data[pe_offset + 24 + 108], &num_rva_sizes, 4);

    // Data Directory - EXCEPTION (index 3)
    uint32_t exception_rva = 0x2000;
    uint32_t exception_size = 36;  // 3 RUNTIME_FUNCTION entries (12 bytes each)
    std::memcpy(&data[pe_offset + 24 + 112 + 3 * 8], &exception_rva, 4);
    std::memcpy(&data[pe_offset + 24 + 112 + 3 * 8 + 4], &exception_size, 4);

    // Section Header
    uint32_t section_offset = pe_offset + 24 + opt_hdr_size;
    std::memcpy(&data[section_offset], ".pdata\0\0", 8);
    uint32_t virtual_size = 0x1000;
    std::memcpy(&data[section_offset + 8], &virtual_size, 4);
    uint32_t virtual_address = 0x2000;
    std::memcpy(&data[section_offset + 12], &virtual_address, 4);
    uint32_t raw_size = 0x200;
    std::memcpy(&data[section_offset + 16], &raw_size, 4);
    uint32_t raw_offset = 0x400;
    std::memcpy(&data[section_offset + 20], &raw_offset, 4);
    uint32_t characteristics = 0x40000040;  // CNT_INITIALIZED_DATA | MEM_READ
    std::memcpy(&data[section_offset + 36], &characteristics, 4);

    // RUNTIME_FUNCTION entries at file offset 0x400
    uint32_t func_offset = 0x400;

    // Function 1: 0x1000 - 0x1050
    uint32_t begin1 = 0x1000;
    uint32_t end1 = 0x1050;
    uint32_t unwind1 = 0x2100;
    std::memcpy(&data[func_offset], &begin1, 4);
    std::memcpy(&data[func_offset + 4], &end1, 4);
    std::memcpy(&data[func_offset + 8], &unwind1, 4);

    // Function 2: 0x1060 - 0x10A0
    uint32_t begin2 = 0x1060;
    uint32_t end2 = 0x10A0;
    uint32_t unwind2 = 0x2110;
    std::memcpy(&data[func_offset + 12], &begin2, 4);
    std::memcpy(&data[func_offset + 16], &end2, 4);
    std::memcpy(&data[func_offset + 20], &unwind2, 4);

    // Function 3: 0x10B0 - 0x1100
    uint32_t begin3 = 0x10B0;
    uint32_t end3 = 0x1100;
    uint32_t unwind3 = 0x2120;
    std::memcpy(&data[func_offset + 24], &begin3, 4);
    std::memcpy(&data[func_offset + 28], &end3, 4);
    std::memcpy(&data[func_offset + 32], &unwind3, 4);

    return data;
}

/**
 * Create PE32 (32-bit) file without exception directory
 * (Exception directory is not used on x86)
 */
static std::vector<uint8_t> create_test_pe32_without_exceptions() {
    std::vector<uint8_t> data;
    data.resize(2048);

    // DOS Header
    data[0] = 'M'; data[1] = 'Z';
    uint32_t pe_offset = 0x80;
    std::memcpy(&data[0x3C], &pe_offset, 4);

    // PE Signature
    std::memcpy(&data[pe_offset], "PE\0\0", 4);

    // COFF File Header
    uint16_t machine = 0x014C;  // IMAGE_FILE_MACHINE_I386
    std::memcpy(&data[pe_offset + 4], &machine, 2);
    uint16_t num_sections = 1;
    std::memcpy(&data[pe_offset + 6], &num_sections, 2);
    uint16_t opt_hdr_size = 224;  // PE32
    std::memcpy(&data[pe_offset + 20], &opt_hdr_size, 2);

    // Optional Header
    uint16_t magic = 0x010B;  // PE32
    std::memcpy(&data[pe_offset + 24], &magic, 2);
    uint32_t image_base = 0x00400000;
    std::memcpy(&data[pe_offset + 52], &image_base, 4);
    uint32_t section_alignment = 0x1000;
    std::memcpy(&data[pe_offset + 56], &section_alignment, 4);
    uint32_t file_alignment = 0x200;
    std::memcpy(&data[pe_offset + 60], &file_alignment, 4);
    uint32_t num_rva_sizes = 16;
    std::memcpy(&data[pe_offset + 24 + 92], &num_rva_sizes, 4);

    // No exception directory (RVA = 0, Size = 0)
    uint32_t exception_rva = 0;
    uint32_t exception_size = 0;
    std::memcpy(&data[pe_offset + 24 + 96 + 3 * 8], &exception_rva, 4);
    std::memcpy(&data[pe_offset + 24 + 96 + 3 * 8 + 4], &exception_size, 4);

    // Section Header
    uint32_t section_offset = pe_offset + 24 + opt_hdr_size;
    std::memcpy(&data[section_offset], ".text\0\0\0", 8);
    uint32_t virtual_size = 0x1000;
    std::memcpy(&data[section_offset + 8], &virtual_size, 4);
    uint32_t virtual_address = 0x1000;
    std::memcpy(&data[section_offset + 12], &virtual_address, 4);
    uint32_t raw_size = 0x200;
    std::memcpy(&data[section_offset + 16], &raw_size, 4);
    uint32_t raw_offset = 0x400;
    std::memcpy(&data[section_offset + 20], &raw_offset, 4);
    uint32_t characteristics = 0x60000020;  // CNT_CODE | MEM_EXECUTE | MEM_READ
    std::memcpy(&data[section_offset + 36], &characteristics, 4);

    return data;
}

/**
 * Create PE32+ file with empty exception directory
 */
static std::vector<uint8_t> create_test_pe64_without_exceptions() {
    std::vector<uint8_t> data;
    data.resize(2048);

    // DOS Header
    data[0] = 'M'; data[1] = 'Z';
    uint32_t pe_offset = 0x80;
    std::memcpy(&data[0x3C], &pe_offset, 4);

    // PE Signature
    std::memcpy(&data[pe_offset], "PE\0\0", 4);

    // COFF File Header
    uint16_t machine = 0x8664;  // IMAGE_FILE_MACHINE_AMD64
    std::memcpy(&data[pe_offset + 4], &machine, 2);
    uint16_t num_sections = 1;
    std::memcpy(&data[pe_offset + 6], &num_sections, 2);
    uint16_t opt_hdr_size = 240;  // PE32+
    std::memcpy(&data[pe_offset + 20], &opt_hdr_size, 2);

    // Optional Header
    uint16_t magic = 0x020B;  // PE32+
    std::memcpy(&data[pe_offset + 24], &magic, 2);
    uint64_t image_base = 0x0000000140000000ULL;
    std::memcpy(&data[pe_offset + 48], &image_base, 8);
    uint32_t section_alignment = 0x1000;
    std::memcpy(&data[pe_offset + 56], &section_alignment, 4);
    uint32_t file_alignment = 0x200;
    std::memcpy(&data[pe_offset + 60], &file_alignment, 4);
    uint32_t num_rva_sizes = 16;
    std::memcpy(&data[pe_offset + 24 + 108], &num_rva_sizes, 4);

    // No exception directory (RVA = 0, Size = 0)
    uint32_t exception_rva = 0;
    uint32_t exception_size = 0;
    std::memcpy(&data[pe_offset + 24 + 112 + 3 * 8], &exception_rva, 4);
    std::memcpy(&data[pe_offset + 24 + 112 + 3 * 8 + 4], &exception_size, 4);

    // Section Header
    uint32_t section_offset = pe_offset + 24 + opt_hdr_size;
    std::memcpy(&data[section_offset], ".text\0\0\0", 8);
    uint32_t virtual_size = 0x1000;
    std::memcpy(&data[section_offset + 8], &virtual_size, 4);
    uint32_t virtual_address = 0x1000;
    std::memcpy(&data[section_offset + 12], &virtual_address, 4);
    uint32_t raw_size = 0x200;
    std::memcpy(&data[section_offset + 16], &raw_size, 4);
    uint32_t raw_offset = 0x400;
    std::memcpy(&data[section_offset + 20], &raw_offset, 4);
    uint32_t characteristics = 0x60000020;  // CNT_CODE | MEM_EXECUTE | MEM_READ
    std::memcpy(&data[section_offset + 36], &characteristics, 4);

    return data;
}

// =============================================================================
// Test Cases
// =============================================================================

TEST_CASE("Exception parser - PE32+ with exception directory") {
    auto data = create_test_pe64_with_exceptions();
    auto pe = pe_file::from_memory(data);

    REQUIRE(pe.is_64bit());

    SUBCASE("Data directory accessors") {
        CHECK(pe.has_data_directory(directory_entry::EXCEPTION));
        CHECK(pe.data_directory_rva(directory_entry::EXCEPTION) == 0x2000);
        CHECK(pe.data_directory_size(directory_entry::EXCEPTION) == 36);
    }

    SUBCASE("Exception directory parsing") {
        auto exceptions = pe.exceptions();
        REQUIRE(exceptions != nullptr);
        CHECK_FALSE(exceptions->is_empty());

        // Check exception handling type
        CHECK(exceptions->type == exception_handling_type::X64_SEH);
        CHECK(exceptions->type_name() == "x64 SEH");

        // Check function count
        CHECK(exceptions->function_count() == 3);
        CHECK(exceptions->runtime_functions.size() == 3);
    }

    SUBCASE("RUNTIME_FUNCTION entries") {
        auto exceptions = pe.exceptions();
        const auto& functions = exceptions->runtime_functions;

        REQUIRE(functions.size() == 3);

        // Function 1
        CHECK(functions[0].begin_address == 0x1000);
        CHECK(functions[0].end_address == 0x1050);
        CHECK(functions[0].unwind_info_address == 0x2100);
        CHECK(functions[0].is_valid());
        CHECK(functions[0].function_size() == 0x50);

        // Function 2
        CHECK(functions[1].begin_address == 0x1060);
        CHECK(functions[1].end_address == 0x10A0);
        CHECK(functions[1].unwind_info_address == 0x2110);
        CHECK(functions[1].is_valid());
        CHECK(functions[1].function_size() == 0x40);

        // Function 3
        CHECK(functions[2].begin_address == 0x10B0);
        CHECK(functions[2].end_address == 0x1100);
        CHECK(functions[2].unwind_info_address == 0x2120);
        CHECK(functions[2].is_valid());
        CHECK(functions[2].function_size() == 0x50);
    }

    SUBCASE("Find function by RVA") {
        auto exceptions = pe.exceptions();

        // Find function containing RVA 0x1010 (in function 1)
        const runtime_function* func = exceptions->find_function(0x1010);
        REQUIRE(func != nullptr);
        CHECK(func->begin_address == 0x1000);
        CHECK(func->end_address == 0x1050);

        // Find function containing RVA 0x1070 (in function 2)
        func = exceptions->find_function(0x1070);
        REQUIRE(func != nullptr);
        CHECK(func->begin_address == 0x1060);
        CHECK(func->end_address == 0x10A0);

        // Find function containing RVA 0x10C0 (in function 3)
        func = exceptions->find_function(0x10C0);
        REQUIRE(func != nullptr);
        CHECK(func->begin_address == 0x10B0);
        CHECK(func->end_address == 0x1100);

        // RVA not in any function
        func = exceptions->find_function(0x2000);
        CHECK(func == nullptr);
    }

    SUBCASE("Lazy parsing and caching") {
        // First access - parses exception directory
        auto exceptions1 = pe.exceptions();
        REQUIRE(exceptions1 != nullptr);
        CHECK(exceptions1->function_count() == 3);

        // Second access - returns cached result
        auto exceptions2 = pe.exceptions();
        CHECK(exceptions1 == exceptions2);  // Same shared_ptr
    }
}

TEST_CASE("Exception parser - PE32 (32-bit) without exception directory") {
    auto data = create_test_pe32_without_exceptions();
    auto pe = pe_file::from_memory(data);

    REQUIRE_FALSE(pe.is_64bit());

    SUBCASE("Data directory accessors") {
        CHECK_FALSE(pe.has_data_directory(directory_entry::EXCEPTION));
        CHECK(pe.data_directory_rva(directory_entry::EXCEPTION) == 0);
        CHECK(pe.data_directory_size(directory_entry::EXCEPTION) == 0);
    }

    SUBCASE("Exception directory is empty for x86") {
        auto exceptions = pe.exceptions();
        REQUIRE(exceptions != nullptr);
        CHECK(exceptions->is_empty());
        CHECK(exceptions->type == exception_handling_type::NONE);
        CHECK(exceptions->type_name() == "None");
        CHECK(exceptions->function_count() == 0);
    }
}

TEST_CASE("Exception parser - PE32+ without exception directory") {
    auto data = create_test_pe64_without_exceptions();
    auto pe = pe_file::from_memory(data);

    REQUIRE(pe.is_64bit());

    SUBCASE("Data directory accessors") {
        CHECK_FALSE(pe.has_data_directory(directory_entry::EXCEPTION));
        CHECK(pe.data_directory_rva(directory_entry::EXCEPTION) == 0);
        CHECK(pe.data_directory_size(directory_entry::EXCEPTION) == 0);
    }

    SUBCASE("Exception directory is empty") {
        auto exceptions = pe.exceptions();
        REQUIRE(exceptions != nullptr);
        CHECK(exceptions->is_empty());
        CHECK(exceptions->type == exception_handling_type::NONE);
        CHECK(exceptions->function_count() == 0);
    }
}

TEST_CASE("Exception parser - Empty exception directory") {
    exception_directory ex;

    CHECK(ex.is_empty());
    CHECK(ex.type == exception_handling_type::NONE);
    CHECK(ex.function_count() == 0);
    CHECK(ex.type_name() == "None");
    CHECK(ex.find_function(0x1000) == nullptr);
}

TEST_CASE("Exception parser - Runtime function validation") {
    runtime_function func;

    SUBCASE("Invalid function (default)") {
        CHECK_FALSE(func.is_valid());
        CHECK(func.function_size() == 0);
    }

    SUBCASE("Invalid function (zero begin address)") {
        func.begin_address = 0;
        func.end_address = 0x100;
        CHECK_FALSE(func.is_valid());
    }

    SUBCASE("Invalid function (end <= begin)") {
        func.begin_address = 0x100;
        func.end_address = 0x100;
        CHECK_FALSE(func.is_valid());

        func.end_address = 0x50;
        CHECK_FALSE(func.is_valid());
    }

    SUBCASE("Valid function") {
        func.begin_address = 0x1000;
        func.end_address = 0x1050;
        func.unwind_info_address = 0x2000;
        CHECK(func.is_valid());
        CHECK(func.function_size() == 0x50);
    }
}
