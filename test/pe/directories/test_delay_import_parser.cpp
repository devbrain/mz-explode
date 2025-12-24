// libexe - Modern executable file analysis library
// Copyright (c) 2024
//
// Tests for Delay Import Directory Parser

#include <doctest/doctest.h>
#include <libexe/formats/pe_file.hpp>
#include <libexe/pe/directories/delay_import.hpp>
#include <vector>
#include <cstring>

using namespace libexe;

// =============================================================================
// Helper Functions - Create Test PE Files
// =============================================================================

/**
 * Create PE32 file with delay imports
 */
static std::vector<uint8_t> create_test_pe32_with_delay_imports() {
    std::vector<uint8_t> data;
    data.resize(4096);

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
    uint16_t opt_hdr_size = 224;
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

    // Data Directory - DELAY_IMPORT (index 13)
    uint32_t delay_import_rva = 0x2000;
    uint32_t delay_import_size = 96;  // 3 descriptors (32 bytes each)
    std::memcpy(&data[pe_offset + 24 + 96 + 13 * 8], &delay_import_rva, 4);
    std::memcpy(&data[pe_offset + 24 + 96 + 13 * 8 + 4], &delay_import_size, 4);

    // Section Header
    uint32_t section_offset = pe_offset + 24 + opt_hdr_size;
    std::memcpy(&data[section_offset], ".rdata\0\0", 8);
    uint32_t virtual_size = 0x2000;
    std::memcpy(&data[section_offset + 8], &virtual_size, 4);
    uint32_t virtual_address = 0x2000;
    std::memcpy(&data[section_offset + 12], &virtual_address, 4);
    uint32_t raw_size = 0x600;
    std::memcpy(&data[section_offset + 16], &raw_size, 4);
    uint32_t raw_offset = 0x400;
    std::memcpy(&data[section_offset + 20], &raw_offset, 4);
    uint32_t characteristics = 0x40000040;
    std::memcpy(&data[section_offset + 36], &characteristics, 4);

    // IMAGE_DELAYLOAD_DESCRIPTOR entries at file offset 0x400
    uint32_t desc_offset = 0x400;

    // Descriptor 1: USER32.dll
    uint32_t attributes1 = 0;  // RVA-based
    std::memcpy(&data[desc_offset], &attributes1, 4);
    uint32_t dll_name_rva1 = 0x2100;
    std::memcpy(&data[desc_offset + 4], &dll_name_rva1, 4);
    uint32_t module_handle_rva1 = 0x3000;
    std::memcpy(&data[desc_offset + 8], &module_handle_rva1, 4);
    uint32_t delay_iat_rva1 = 0x3010;
    std::memcpy(&data[desc_offset + 12], &delay_iat_rva1, 4);
    uint32_t delay_int_rva1 = 0x2200;
    std::memcpy(&data[desc_offset + 16], &delay_int_rva1, 4);
    uint32_t bound_iat_rva1 = 0;
    std::memcpy(&data[desc_offset + 20], &bound_iat_rva1, 4);
    uint32_t unload_iat_rva1 = 0;
    std::memcpy(&data[desc_offset + 24], &unload_iat_rva1, 4);
    uint32_t timestamp1 = 0;
    std::memcpy(&data[desc_offset + 28], &timestamp1, 4);

    // Descriptor 2: KERNEL32.dll
    uint32_t desc_offset2 = desc_offset + 32;
    uint32_t attributes2 = 0;  // RVA-based
    std::memcpy(&data[desc_offset2], &attributes2, 4);
    uint32_t dll_name_rva2 = 0x2110;
    std::memcpy(&data[desc_offset2 + 4], &dll_name_rva2, 4);
    uint32_t module_handle_rva2 = 0x3004;
    std::memcpy(&data[desc_offset2 + 8], &module_handle_rva2, 4);
    uint32_t delay_iat_rva2 = 0x3020;
    std::memcpy(&data[desc_offset2 + 12], &delay_iat_rva2, 4);
    uint32_t delay_int_rva2 = 0x2220;
    std::memcpy(&data[desc_offset2 + 16], &delay_int_rva2, 4);
    uint32_t bound_iat_rva2 = 0;
    std::memcpy(&data[desc_offset2 + 20], &bound_iat_rva2, 4);
    uint32_t unload_iat_rva2 = 0;
    std::memcpy(&data[desc_offset2 + 24], &unload_iat_rva2, 4);
    uint32_t timestamp2 = 0x12345678;
    std::memcpy(&data[desc_offset2 + 28], &timestamp2, 4);

    // Null descriptor (terminator)
    uint32_t desc_offset3 = desc_offset2 + 32;
    std::memset(&data[desc_offset3], 0, 32);

    // DLL Names
    std::memcpy(&data[0x500], "USER32.dll\0", 11);
    std::memcpy(&data[0x510], "KERNEL32.dll\0", 13);

    // Delay INT for USER32.dll (at 0x600)
    // Entry 1: MessageBoxA (by name)
    uint32_t name_rva1 = 0x2300;
    std::memcpy(&data[0x600], &name_rva1, 4);
    // Entry 2: Import by ordinal 100
    uint32_t ordinal_entry = 0x80000064;  // Ordinal 100 with high bit set
    std::memcpy(&data[0x604], &ordinal_entry, 4);
    // Null terminator
    uint32_t null_entry = 0;
    std::memcpy(&data[0x608], &null_entry, 4);

    // Delay INT for KERNEL32.dll (at 0x620)
    // Entry 1: GetProcAddress (by name)
    uint32_t name_rva2 = 0x2320;
    std::memcpy(&data[0x620], &name_rva2, 4);
    // Null terminator
    std::memcpy(&data[0x624], &null_entry, 4);

    // IMAGE_IMPORT_BY_NAME structures
    // MessageBoxA (at 0x700)
    uint16_t hint1 = 42;
    std::memcpy(&data[0x700], &hint1, 2);
    std::memcpy(&data[0x702], "MessageBoxA\0", 12);

    // GetProcAddress (at 0x720)
    uint16_t hint2 = 100;
    std::memcpy(&data[0x720], &hint2, 2);
    std::memcpy(&data[0x722], "GetProcAddress\0", 15);

    return data;
}

/**
 * Create PE32+ (64-bit) file with delay imports
 */
static std::vector<uint8_t> create_test_pe64_with_delay_imports() {
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

    // Data Directory - DELAY_IMPORT (index 13)
    uint32_t delay_import_rva = 0x2000;
    uint32_t delay_import_size = 64;  // 2 descriptors (32 bytes each)
    std::memcpy(&data[pe_offset + 24 + 112 + 13 * 8], &delay_import_rva, 4);
    std::memcpy(&data[pe_offset + 24 + 112 + 13 * 8 + 4], &delay_import_size, 4);

    // Section Header
    uint32_t section_offset = pe_offset + 24 + opt_hdr_size;
    std::memcpy(&data[section_offset], ".rdata\0\0", 8);
    uint32_t virtual_size = 0x2000;
    std::memcpy(&data[section_offset + 8], &virtual_size, 4);
    uint32_t virtual_address = 0x2000;
    std::memcpy(&data[section_offset + 12], &virtual_address, 4);
    uint32_t raw_size = 0x600;
    std::memcpy(&data[section_offset + 16], &raw_size, 4);
    uint32_t raw_offset = 0x400;
    std::memcpy(&data[section_offset + 20], &raw_offset, 4);
    uint32_t characteristics = 0x40000040;
    std::memcpy(&data[section_offset + 36], &characteristics, 4);

    // IMAGE_DELAYLOAD_DESCRIPTOR (at 0x400)
    uint32_t desc_offset = 0x400;
    uint32_t attributes = 0;  // RVA-based
    std::memcpy(&data[desc_offset], &attributes, 4);
    uint32_t dll_name_rva = 0x2100;
    std::memcpy(&data[desc_offset + 4], &dll_name_rva, 4);
    uint32_t module_handle_rva = 0x3000;
    std::memcpy(&data[desc_offset + 8], &module_handle_rva, 4);
    uint32_t delay_iat_rva = 0x3010;
    std::memcpy(&data[desc_offset + 12], &delay_iat_rva, 4);
    uint32_t delay_int_rva = 0x2200;
    std::memcpy(&data[desc_offset + 16], &delay_int_rva, 4);

    // Null descriptor
    std::memset(&data[desc_offset + 32], 0, 32);

    // DLL Name
    std::memcpy(&data[0x500], "ADVAPI32.dll\0", 13);

    // Delay INT (64-bit entries at 0x600)
    // Entry 1: RegOpenKeyExA (by name)
    uint64_t name_rva = 0x2300;
    std::memcpy(&data[0x600], &name_rva, 8);
    // Null terminator
    uint64_t null_entry = 0;
    std::memcpy(&data[0x608], &null_entry, 8);

    // IMAGE_IMPORT_BY_NAME (at 0x700)
    uint16_t hint = 50;
    std::memcpy(&data[0x700], &hint, 2);
    std::memcpy(&data[0x702], "RegOpenKeyExA\0", 14);

    return data;
}

/**
 * Create PE32 file without delay imports
 */
static std::vector<uint8_t> create_test_pe32_without_delay_imports() {
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
    uint16_t opt_hdr_size = 224;
    std::memcpy(&data[pe_offset + 20], &opt_hdr_size, 2);

    // Optional Header
    uint16_t magic = 0x010B;  // PE32
    std::memcpy(&data[pe_offset + 24], &magic, 2);
    uint32_t image_base = 0x00400000;
    std::memcpy(&data[pe_offset + 52], &image_base, 4);
    uint32_t num_rva_sizes = 16;
    std::memcpy(&data[pe_offset + 24 + 92], &num_rva_sizes, 4);

    // No delay import directory (RVA = 0, Size = 0)
    uint32_t delay_import_rva = 0;
    uint32_t delay_import_size = 0;
    std::memcpy(&data[pe_offset + 24 + 96 + 13 * 8], &delay_import_rva, 4);
    std::memcpy(&data[pe_offset + 24 + 96 + 13 * 8 + 4], &delay_import_size, 4);

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
    uint32_t characteristics = 0x60000020;
    std::memcpy(&data[section_offset + 36], &characteristics, 4);

    return data;
}

// =============================================================================
// Test Cases
// =============================================================================

TEST_CASE("Delay import parser - PE32 with delay imports") {
    auto data = create_test_pe32_with_delay_imports();
    auto pe = pe_file::from_memory(data);

    REQUIRE_FALSE(pe.is_64bit());

    SUBCASE("Data directory accessors") {
        CHECK(pe.has_data_directory(directory_entry::DELAY_IMPORT));
        CHECK(pe.data_directory_rva(directory_entry::DELAY_IMPORT) == 0x2000);
        CHECK(pe.data_directory_size(directory_entry::DELAY_IMPORT) == 96);
    }

    SUBCASE("Delay import directory parsing") {
        auto delay_imports = pe.delay_imports();
        REQUIRE(delay_imports != nullptr);
        CHECK_FALSE(delay_imports->is_empty());

        CHECK(delay_imports->dll_count() == 2);
        CHECK(delay_imports->descriptors.size() == 2);
        CHECK(delay_imports->total_function_count() == 3);
    }

    SUBCASE("Descriptor 1 - USER32.dll") {
        auto delay_imports = pe.delay_imports();
        REQUIRE(delay_imports->descriptors.size() >= 1);

        const auto& desc = delay_imports->descriptors[0];
        CHECK(desc.dll_name == "USER32.dll");
        CHECK(desc.attributes == 0);
        CHECK(desc.is_rva_based());
        CHECK_FALSE(desc.is_va_based());
        CHECK(desc.module_handle_rva == 0x3000);
        CHECK(desc.delay_import_address_table_rva == 0x3010);
        CHECK(desc.delay_import_name_table_rva == 0x2200);
        CHECK(desc.time_date_stamp == 0);

        // Functions
        CHECK(desc.function_count() == 2);
        REQUIRE(desc.functions.size() == 2);

        // Function 1: MessageBoxA (by name)
        CHECK(desc.functions[0].name == "MessageBoxA");
        CHECK(desc.functions[0].hint == 42);
        CHECK_FALSE(desc.functions[0].import_by_ordinal);
        CHECK_FALSE(desc.functions[0].is_ordinal());
        CHECK(desc.functions[0].identifier() == "MessageBoxA");

        // Function 2: Import by ordinal 100
        CHECK(desc.functions[1].import_by_ordinal);
        CHECK(desc.functions[1].is_ordinal());
        CHECK(desc.functions[1].ordinal == 100);
        CHECK(desc.functions[1].identifier() == "Ordinal_100");
    }

    SUBCASE("Descriptor 2 - KERNEL32.dll") {
        auto delay_imports = pe.delay_imports();
        REQUIRE(delay_imports->descriptors.size() >= 2);

        const auto& desc = delay_imports->descriptors[1];
        CHECK(desc.dll_name == "KERNEL32.dll");
        CHECK(desc.is_rva_based());
        CHECK(desc.time_date_stamp == 0x12345678);

        // Functions
        CHECK(desc.function_count() == 1);
        REQUIRE(desc.functions.size() == 1);

        // Function 1: GetProcAddress (by name)
        CHECK(desc.functions[0].name == "GetProcAddress");
        CHECK(desc.functions[0].hint == 100);
        CHECK_FALSE(desc.functions[0].import_by_ordinal);
    }

    SUBCASE("Find DLL") {
        auto delay_imports = pe.delay_imports();

        const auto* user32 = delay_imports->find_dll("USER32.dll");
        REQUIRE(user32 != nullptr);
        CHECK(user32->dll_name == "USER32.dll");
        CHECK(user32->function_count() == 2);

        const auto* kernel32 = delay_imports->find_dll("KERNEL32.dll");
        REQUIRE(kernel32 != nullptr);
        CHECK(kernel32->dll_name == "KERNEL32.dll");
        CHECK(kernel32->function_count() == 1);

        const auto* not_found = delay_imports->find_dll("NOTFOUND.dll");
        CHECK(not_found == nullptr);
    }

    SUBCASE("DLL names list") {
        auto delay_imports = pe.delay_imports();
        auto dll_names = delay_imports->dll_names();

        REQUIRE(dll_names.size() == 2);
        CHECK(dll_names[0] == "USER32.dll");
        CHECK(dll_names[1] == "KERNEL32.dll");
    }

    SUBCASE("Lazy parsing and caching") {
        // First access - parses delay imports
        auto delay_imports1 = pe.delay_imports();
        REQUIRE(delay_imports1 != nullptr);
        CHECK(delay_imports1->dll_count() == 2);

        // Second access - returns cached result
        auto delay_imports2 = pe.delay_imports();
        CHECK(delay_imports1 == delay_imports2);  // Same shared_ptr
    }
}

TEST_CASE("Delay import parser - PE32+ with delay imports") {
    auto data = create_test_pe64_with_delay_imports();
    auto pe = pe_file::from_memory(data);

    REQUIRE(pe.is_64bit());

    SUBCASE("Data directory accessors") {
        CHECK(pe.has_data_directory(directory_entry::DELAY_IMPORT));
        CHECK(pe.data_directory_rva(directory_entry::DELAY_IMPORT) == 0x2000);
        CHECK(pe.data_directory_size(directory_entry::DELAY_IMPORT) == 64);
    }

    SUBCASE("Delay import directory parsing") {
        auto delay_imports = pe.delay_imports();
        REQUIRE(delay_imports != nullptr);
        CHECK_FALSE(delay_imports->is_empty());

        CHECK(delay_imports->dll_count() == 1);
        CHECK(delay_imports->total_function_count() == 1);
    }

    SUBCASE("Descriptor - ADVAPI32.dll") {
        auto delay_imports = pe.delay_imports();
        REQUIRE(delay_imports->descriptors.size() == 1);

        const auto& desc = delay_imports->descriptors[0];
        CHECK(desc.dll_name == "ADVAPI32.dll");
        CHECK(desc.is_rva_based());

        // Function
        CHECK(desc.function_count() == 1);
        REQUIRE(desc.functions.size() == 1);

        CHECK(desc.functions[0].name == "RegOpenKeyExA");
        CHECK(desc.functions[0].hint == 50);
        CHECK_FALSE(desc.functions[0].import_by_ordinal);
    }
}

TEST_CASE("Delay import parser - PE32 without delay imports") {
    auto data = create_test_pe32_without_delay_imports();
    auto pe = pe_file::from_memory(data);

    SUBCASE("Data directory accessors") {
        CHECK_FALSE(pe.has_data_directory(directory_entry::DELAY_IMPORT));
        CHECK(pe.data_directory_rva(directory_entry::DELAY_IMPORT) == 0);
        CHECK(pe.data_directory_size(directory_entry::DELAY_IMPORT) == 0);
    }

    SUBCASE("Delay import directory is empty") {
        auto delay_imports = pe.delay_imports();
        REQUIRE(delay_imports != nullptr);
        CHECK(delay_imports->is_empty());
        CHECK(delay_imports->dll_count() == 0);
        CHECK(delay_imports->total_function_count() == 0);
        CHECK(delay_imports->find_dll("USER32.dll") == nullptr);
    }
}

TEST_CASE("Delay import parser - Empty delay import directory") {
    delay_import_directory dir;

    CHECK(dir.is_empty());
    CHECK(dir.dll_count() == 0);
    CHECK(dir.total_function_count() == 0);
    CHECK(dir.find_dll("test.dll") == nullptr);
    CHECK(dir.dll_names().empty());
}

TEST_CASE("Delay import parser - Descriptor validation") {
    delay_import_descriptor desc;

    SUBCASE("Empty descriptor") {
        CHECK(desc.is_empty());
        CHECK(desc.function_count() == 0);
        CHECK(desc.dll_name.empty());
    }

    SUBCASE("RVA-based descriptor") {
        desc.attributes = 0;
        CHECK(desc.is_rva_based());
        CHECK_FALSE(desc.is_va_based());
    }

    SUBCASE("VA-based descriptor") {
        desc.attributes = 1;
        CHECK_FALSE(desc.is_rva_based());
        CHECK(desc.is_va_based());
    }

    SUBCASE("Non-empty descriptor") {
        desc.dll_name = "test.dll";
        delay_imported_function func;
        func.name = "TestFunc";
        desc.functions.push_back(func);

        CHECK_FALSE(desc.is_empty());
        CHECK(desc.function_count() == 1);
    }
}

TEST_CASE("Delay import parser - Imported function") {
    delay_imported_function func;

    SUBCASE("Import by name") {
        func.name = "MessageBoxA";
        func.hint = 42;
        func.import_by_ordinal = false;

        CHECK_FALSE(func.is_ordinal());
        CHECK(func.identifier() == "MessageBoxA");
    }

    SUBCASE("Import by ordinal") {
        func.ordinal = 100;
        func.import_by_ordinal = true;

        CHECK(func.is_ordinal());
        CHECK(func.identifier() == "Ordinal_100");
    }
}
