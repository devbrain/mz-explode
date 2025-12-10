// libexe - Modern executable file analysis library
// Copyright (c) 2024
// Unit tests for IAT (Import Address Table) Parser

#include <doctest/doctest.h>
#include <libexe/formats/pe_file.hpp>
#include <libexe/pe/directories/iat.hpp>
#include <cstring>
#include <vector>

using namespace libexe;

// =============================================================================
// Helper functions to create minimal PE files for testing
// =============================================================================

namespace {

/**
 * Create minimal DOS header (64 bytes)
 */
static void create_dos_header(std::vector<uint8_t>& data, uint32_t pe_offset) {
    data.resize(pe_offset + 512);
    data[0] = 'M';
    data[1] = 'Z';
    data[0x3C] = static_cast<uint8_t>(pe_offset);
    data[0x3D] = static_cast<uint8_t>(pe_offset >> 8);
    data[0x3E] = static_cast<uint8_t>(pe_offset >> 16);
    data[0x3F] = static_cast<uint8_t>(pe_offset >> 24);
}

/**
 * Create PE signature (4 bytes: "PE\0\0")
 */
static void create_pe_signature(std::vector<uint8_t>& data, uint32_t offset) {
    data[offset] = 'P';
    data[offset + 1] = 'E';
    data[offset + 2] = 0;
    data[offset + 3] = 0;
}

/**
 * Create COFF file header (20 bytes)
 */
static void create_coff_header(std::vector<uint8_t>& data, uint32_t offset) {
    uint8_t* header = data.data() + offset;

    // Machine type (I386)
    uint16_t machine = 0x014C;
    std::memcpy(header, &machine, 2);

    // NumberOfSections
    uint16_t num_sections = 1;
    std::memcpy(header + 2, &num_sections, 2);

    // TimeDateStamp
    uint32_t timestamp = 0x12345678;
    std::memcpy(header + 4, &timestamp, 4);

    // PointerToSymbolTable
    uint32_t symbol_table = 0;
    std::memcpy(header + 8, &symbol_table, 4);

    // NumberOfSymbols
    uint32_t num_symbols = 0;
    std::memcpy(header + 12, &num_symbols, 4);

    // SizeOfOptionalHeader
    uint16_t optional_size = 224; // PE32
    std::memcpy(header + 16, &optional_size, 2);

    // Characteristics
    uint16_t characteristics = 0x0002 | 0x0020; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    std::memcpy(header + 18, &characteristics, 2);
}

/**
 * Create PE32 optional header (224 bytes) with IAT directory
 */
static void create_optional_header_pe32(std::vector<uint8_t>& data, uint32_t offset,
                                        uint32_t iat_rva, uint32_t iat_size) {
    uint8_t* header = data.data() + offset;

    // Magic (PE32 = 0x10B)
    uint16_t magic = 0x10B;
    std::memcpy(header, &magic, 2);

    // AddressOfEntryPoint
    uint32_t entry_point = 0x1000;
    std::memcpy(header + 16, &entry_point, 4);

    // ImageBase
    uint32_t image_base = 0x00400000;
    std::memcpy(header + 28, &image_base, 4);

    // SectionAlignment
    uint32_t section_align = 0x1000;
    std::memcpy(header + 32, &section_align, 4);

    // FileAlignment
    uint32_t file_align = 0x200;
    std::memcpy(header + 36, &file_align, 4);

    // SizeOfImage
    uint32_t image_size = 0x10000;
    std::memcpy(header + 56, &image_size, 4);

    // SizeOfHeaders
    uint32_t header_size = 0x400;
    std::memcpy(header + 60, &header_size, 4);

    // Subsystem
    uint16_t subsystem = 3; // IMAGE_SUBSYSTEM_WINDOWS_CUI
    std::memcpy(header + 68, &subsystem, 2);

    // NumberOfRvaAndSizes
    uint32_t num_dirs = 16;
    std::memcpy(header + 92, &num_dirs, 4);

    // Data directories start at offset 96
    // IAT Directory is at index 12 (offset 96 + 12*8 = 192)
    std::memcpy(header + 192, &iat_rva, 4);
    std::memcpy(header + 196, &iat_size, 4);
}

/**
 * Create section table entry (40 bytes)
 */
static void create_section_header(std::vector<uint8_t>& data, uint32_t offset,
                                  const char* name, uint32_t virtual_addr,
                                  uint32_t virtual_size, uint32_t raw_offset,
                                  uint32_t raw_size) {
    uint8_t* section = data.data() + offset;

    // Name (8 bytes, null-padded)
    std::memset(section, 0, 8);
    std::strncpy(reinterpret_cast<char*>(section), name, 8);

    // VirtualSize
    std::memcpy(section + 8, &virtual_size, 4);

    // VirtualAddress
    std::memcpy(section + 12, &virtual_addr, 4);

    // SizeOfRawData
    std::memcpy(section + 16, &raw_size, 4);

    // PointerToRawData
    std::memcpy(section + 20, &raw_offset, 4);

    // Characteristics (readable, executable, code)
    uint32_t characteristics = 0x60000020;
    std::memcpy(section + 36, &characteristics, 4);
}

/**
 * Write 32-bit value at offset
 */
static void write_u32(std::vector<uint8_t>& data, uint32_t offset, uint32_t value) {
    std::memcpy(data.data() + offset, &value, 4);
}

/**
 * Write 64-bit value at offset
 */
static void write_u64(std::vector<uint8_t>& data, uint32_t offset, uint64_t value) {
    std::memcpy(data.data() + offset, &value, 8);
}

/**
 * Create a minimal PE32 with IAT containing imports by name
 *
 * Structure:
 * - DOS header + stub (128 bytes)
 * - PE signature (4 bytes)
 * - COFF header (20 bytes)
 * - Optional header PE32 (224 bytes)
 * - Section table: 1 section (40 bytes)
 * - Padding to 0x400
 * - Section .text at RVA 0x2000, file offset 0x400
 *   - IAT at RVA 0x2000 (3 entries: 2 functions + null terminator)
 */
static std::vector<uint8_t> create_test_pe32_with_iat() {
    std::vector<uint8_t> data;

    // DOS header at offset 0
    create_dos_header(data, 128);

    // PE signature at offset 128
    create_pe_signature(data, 128);

    // COFF header at offset 132
    create_coff_header(data, 132);

    // Optional header at offset 152
    // IAT at RVA 0x2000, size 12 bytes (3 * 4 bytes for PE32)
    create_optional_header_pe32(data, 152, 0x2000, 12);

    // Section table at offset 376 (152 + 224)
    // .text section: RVA 0x2000, VirtualSize 0x1000, FileOffset 0x400, FileSize 0x1000
    create_section_header(data, 376, ".text", 0x2000, 0x1000, 0x400, 0x1000);

    // Ensure file is large enough
    data.resize(0x400 + 0x1000);

    // Create IAT at file offset 0x400 (RVA 0x2000)
    uint32_t iat_offset = 0x400;

    // Entry 0: Import by name (RVA 0x2100)
    write_u32(data, iat_offset + 0, 0x2100);

    // Entry 1: Import by name (RVA 0x2200)
    write_u32(data, iat_offset + 4, 0x2200);

    // Entry 2: Null terminator
    write_u32(data, iat_offset + 8, 0);

    return data;
}

/**
 * Create PE32 with IAT containing ordinal imports
 */
static std::vector<uint8_t> create_test_pe32_with_ordinal_imports() {
    std::vector<uint8_t> data = create_test_pe32_with_iat();

    uint32_t iat_offset = 0x400;

    // Entry 0: Import by ordinal 42 (bit 31 set)
    write_u32(data, iat_offset + 0, 0x8000002A);

    // Entry 1: Import by ordinal 100 (bit 31 set)
    write_u32(data, iat_offset + 4, 0x80000064);

    // Entry 2: Null terminator
    write_u32(data, iat_offset + 8, 0);

    return data;
}

/**
 * Create PE32 with mixed IAT (names and ordinals)
 */
static std::vector<uint8_t> create_test_pe32_with_mixed_iat() {
    std::vector<uint8_t> data = create_test_pe32_with_iat();

    uint32_t iat_offset = 0x400;

    // Entry 0: Import by name (RVA 0x2100)
    write_u32(data, iat_offset + 0, 0x2100);

    // Entry 1: Import by ordinal 42
    write_u32(data, iat_offset + 4, 0x8000002A);

    // Entry 2: Null terminator
    write_u32(data, iat_offset + 8, 0);

    return data;
}

/**
 * Create PE32 with empty IAT (no data directory)
 */
static std::vector<uint8_t> create_test_pe32_no_iat() {
    std::vector<uint8_t> data;

    create_dos_header(data, 128);
    create_pe_signature(data, 128);
    create_coff_header(data, 132);

    // IAT RVA and size = 0 (no IAT)
    create_optional_header_pe32(data, 152, 0, 0);
    create_section_header(data, 376, ".text", 0x1000, 0x200, 0x400, 0x200);

    data.resize(0x1000);

    return data;
}

/**
 * Create COFF file header for PE32+ (20 bytes)
 */
static void create_coff_header_pe64(std::vector<uint8_t>& data, uint32_t offset) {
    uint8_t* header = data.data() + offset;

    // Machine type (AMD64)
    uint16_t machine = 0x8664;
    std::memcpy(header, &machine, 2);

    // NumberOfSections
    uint16_t num_sections = 1;
    std::memcpy(header + 2, &num_sections, 2);

    // TimeDateStamp
    uint32_t timestamp = 0x12345678;
    std::memcpy(header + 4, &timestamp, 4);

    // PointerToSymbolTable
    uint32_t symbol_table = 0;
    std::memcpy(header + 8, &symbol_table, 4);

    // NumberOfSymbols
    uint32_t num_symbols = 0;
    std::memcpy(header + 12, &num_symbols, 4);

    // SizeOfOptionalHeader
    uint16_t optional_size = 240; // PE32+
    std::memcpy(header + 16, &optional_size, 2);

    // Characteristics
    uint16_t characteristics = 0x0002 | 0x0020; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    std::memcpy(header + 18, &characteristics, 2);
}

/**
 * Create PE32+ optional header (240 bytes) with IAT directory
 */
static void create_optional_header_pe64(std::vector<uint8_t>& data, uint32_t offset,
                                        uint32_t iat_rva, uint32_t iat_size) {
    uint8_t* header = data.data() + offset;

    // Magic (PE32+ = 0x20B)
    uint16_t magic = 0x20B;
    std::memcpy(header, &magic, 2);

    // AddressOfEntryPoint
    uint32_t entry_point = 0x1000;
    std::memcpy(header + 16, &entry_point, 4);

    // ImageBase (8 bytes for PE32+)
    uint64_t image_base = 0x0000000140000000ULL;
    std::memcpy(header + 24, &image_base, 8);

    // SectionAlignment
    uint32_t section_align = 0x1000;
    std::memcpy(header + 32, &section_align, 4);

    // FileAlignment
    uint32_t file_align = 0x200;
    std::memcpy(header + 36, &file_align, 4);

    // SizeOfImage
    uint32_t image_size = 0x10000;
    std::memcpy(header + 56, &image_size, 4);

    // SizeOfHeaders
    uint32_t header_size = 0x400;
    std::memcpy(header + 60, &header_size, 4);

    // Subsystem
    uint16_t subsystem = 3; // IMAGE_SUBSYSTEM_WINDOWS_CUI
    std::memcpy(header + 68, &subsystem, 2);

    // NumberOfRvaAndSizes
    uint32_t num_dirs = 16;
    std::memcpy(header + 108, &num_dirs, 4);

    // Data directories start at offset 112
    // IAT Directory is at index 12 (offset 112 + 12*8 = 208)
    std::memcpy(header + 208, &iat_rva, 4);
    std::memcpy(header + 212, &iat_size, 4);
}

/**
 * Create a minimal PE32+ with IAT (64-bit entries)
 */
static std::vector<uint8_t> create_test_pe64_with_iat() {
    std::vector<uint8_t> data;

    create_dos_header(data, 128);
    create_pe_signature(data, 128);
    create_coff_header_pe64(data, 132);

    // IAT at RVA 0x2000, size 24 bytes (3 * 8 bytes for PE32+)
    create_optional_header_pe64(data, 152, 0x2000, 24);

    // Section table at offset 392 (152 + 240)
    create_section_header(data, 392, ".text", 0x2000, 0x1000, 0x400, 0x1000);

    data.resize(0x400 + 0x1000);

    // Create IAT at file offset 0x400 (RVA 0x2000)
    uint32_t iat_offset = 0x400;

    // Entry 0: Import by name (RVA 0x2100)
    write_u64(data, iat_offset + 0, 0x2100);

    // Entry 1: Import by ordinal 42 (bit 63 set)
    write_u64(data, iat_offset + 8, 0x800000000000002AULL);

    // Entry 2: Null terminator
    write_u64(data, iat_offset + 16, 0);

    return data;
}

} // anonymous namespace

// =============================================================================
// Test Cases
// =============================================================================

TEST_CASE("IAT Parser - PE32 with imports by name") {
    auto pe_data = create_test_pe32_with_iat();
    auto pe = pe_file::from_memory(pe_data);

    SUBCASE("PE file loads successfully") {
        CHECK(pe.get_format() == format_type::PE_WIN32);
        CHECK_FALSE(pe.is_64bit());
    }

    SUBCASE("Data directory entry exists") {
        CHECK(pe.has_data_directory(directory_entry::IAT));
        CHECK(pe.data_directory_rva(directory_entry::IAT) == 0x2000);
        CHECK(pe.data_directory_size(directory_entry::IAT) == 12);
    }

    SUBCASE("IAT exists and is valid") {
        auto iat = pe.import_address_table();
        REQUIRE(iat != nullptr);
        CHECK_FALSE(iat->is_64bit);
        CHECK_FALSE(iat->empty());
    }

    SUBCASE("IAT entry count") {
        auto iat = pe.import_address_table();

        CHECK(iat->entry_count() == 3); // 2 functions + null
        CHECK(iat->function_count() == 2); // Excludes null terminator
    }

    SUBCASE("IAT entries are imports by name") {
        auto iat = pe.import_address_table();

        // Entry 0
        CHECK(iat->entries[0].value == 0x2100);
        CHECK_FALSE(iat->entries[0].is_null());
        CHECK_FALSE(iat->entries[0].is_ordinal());
        CHECK(iat->entries[0].name_rva() == 0x2100);

        // Entry 1
        CHECK(iat->entries[1].value == 0x2200);
        CHECK_FALSE(iat->entries[1].is_null());
        CHECK_FALSE(iat->entries[1].is_ordinal());
        CHECK(iat->entries[1].name_rva() == 0x2200);

        // Entry 2 (null terminator)
        CHECK(iat->entries[2].value == 0);
        CHECK(iat->entries[2].is_null());
    }

    SUBCASE("Import counts") {
        auto iat = pe.import_address_table();

        CHECK(iat->named_import_count() == 2);
        CHECK(iat->ordinal_import_count() == 0);
    }
}

TEST_CASE("IAT Parser - PE32 with ordinal imports") {
    auto pe_data = create_test_pe32_with_ordinal_imports();
    auto pe = pe_file::from_memory(pe_data);

    auto iat = pe.import_address_table();
    REQUIRE(iat != nullptr);

    CHECK(iat->entry_count() == 3);
    CHECK(iat->function_count() == 2);

    // Entry 0: ordinal 42
    CHECK(iat->entries[0].value == 0x8000002A);
    CHECK(iat->entries[0].is_ordinal());
    CHECK(iat->entries[0].ordinal() == 42);

    // Entry 1: ordinal 100
    CHECK(iat->entries[1].value == 0x80000064);
    CHECK(iat->entries[1].is_ordinal());
    CHECK(iat->entries[1].ordinal() == 100);

    // Import counts
    CHECK(iat->named_import_count() == 0);
    CHECK(iat->ordinal_import_count() == 2);
}

TEST_CASE("IAT Parser - PE32 with mixed imports") {
    auto pe_data = create_test_pe32_with_mixed_iat();
    auto pe = pe_file::from_memory(pe_data);

    auto iat = pe.import_address_table();
    REQUIRE(iat != nullptr);

    CHECK(iat->entry_count() == 3);
    CHECK(iat->function_count() == 2);

    // Entry 0: import by name
    CHECK_FALSE(iat->entries[0].is_ordinal());
    CHECK(iat->entries[0].name_rva() == 0x2100);

    // Entry 1: import by ordinal
    CHECK(iat->entries[1].is_ordinal());
    CHECK(iat->entries[1].ordinal() == 42);

    // Import counts
    CHECK(iat->named_import_count() == 1);
    CHECK(iat->ordinal_import_count() == 1);
}

TEST_CASE("IAT Parser - PE32 without IAT") {
    auto pe_data = create_test_pe32_no_iat();
    auto pe = pe_file::from_memory(pe_data);

    auto iat = pe.import_address_table();
    REQUIRE(iat != nullptr);

    // Should return empty IAT
    CHECK(iat->empty());
    CHECK(iat->entry_count() == 0);
    CHECK(iat->function_count() == 0);
    CHECK(iat->named_import_count() == 0);
    CHECK(iat->ordinal_import_count() == 0);
}

TEST_CASE("IAT Parser - PE32+ (64-bit)") {
    auto pe_data = create_test_pe64_with_iat();
    auto pe = pe_file::from_memory(pe_data);

    SUBCASE("PE file is 64-bit") {
        CHECK(pe.get_format() == format_type::PE_PLUS_WIN64);
        CHECK(pe.is_64bit());
    }

    SUBCASE("IAT is 64-bit") {
        auto iat = pe.import_address_table();
        REQUIRE(iat != nullptr);

        CHECK(iat->is_64bit);
        CHECK(iat->entry_count() == 3);
        CHECK(iat->function_count() == 2);
    }

    SUBCASE("IAT entries are 64-bit") {
        auto iat = pe.import_address_table();

        // Entry 0: import by name
        CHECK(iat->entries[0].value == 0x2100);
        CHECK(iat->entries[0].is_64bit);
        CHECK_FALSE(iat->entries[0].is_ordinal());
        CHECK(iat->entries[0].name_rva() == 0x2100);

        // Entry 1: import by ordinal 42 (bit 63 set)
        CHECK(iat->entries[1].value == 0x800000000000002AULL);
        CHECK(iat->entries[1].is_64bit);
        CHECK(iat->entries[1].is_ordinal());
        CHECK(iat->entries[1].ordinal() == 42);

        // Entry 2: null terminator
        CHECK(iat->entries[2].value == 0);
        CHECK(iat->entries[2].is_null());
    }

    SUBCASE("Import counts") {
        auto iat = pe.import_address_table();

        CHECK(iat->named_import_count() == 1);
        CHECK(iat->ordinal_import_count() == 1);
    }
}

TEST_CASE("IAT Parser - Lazy parsing and caching") {
    auto pe_data = create_test_pe32_with_iat();
    auto pe = pe_file::from_memory(pe_data);

    // First access - should parse
    auto iat1 = pe.import_address_table();
    REQUIRE(iat1 != nullptr);
    CHECK(iat1->entry_count() == 3);

    // Second access - should return cached result
    auto iat2 = pe.import_address_table();
    REQUIRE(iat2 != nullptr);
    CHECK(iat2.get() == iat1.get()); // Same pointer (cached)
    CHECK(iat2->entry_count() == 3);
}
