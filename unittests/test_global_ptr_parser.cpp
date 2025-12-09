// libexe - Modern executable file analysis library
// Copyright (c) 2024
// Unit tests for Global Pointer Parser (IA64)

#include <doctest/doctest.h>
#include <libexe/formats/pe_file.hpp>
#include <libexe/pe/directories/global_ptr.hpp>
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
static void create_coff_header(std::vector<uint8_t>& data, uint32_t offset, uint16_t machine = 0x014C) {
    uint8_t* header = data.data() + offset;

    // Machine type (default: I386, can be IA64 = 0x0200)
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
 * Create PE32 optional header (224 bytes) with Global Pointer directory
 */
static void create_optional_header_pe32(std::vector<uint8_t>& data, uint32_t offset,
                                        uint32_t global_ptr_rva, uint32_t global_ptr_size) {
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
    // Global Pointer Directory is at index 8 (offset 96 + 8*8 = 160)
    std::memcpy(header + 160, &global_ptr_rva, 4);
    std::memcpy(header + 164, &global_ptr_size, 4);
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
 * Create a minimal PE32 IA64 executable with global pointer
 *
 * Structure:
 * - DOS header + stub (128 bytes)
 * - PE signature (4 bytes)
 * - COFF header (20 bytes) - IA64 machine type
 * - Optional header PE32 (224 bytes)
 * - Section table: 1 section (40 bytes)
 * - Padding to 0x400
 * - Section .text at RVA 0x1000, file offset 0x400
 */
static std::vector<uint8_t> create_test_pe_with_global_ptr() {
    std::vector<uint8_t> data;

    // DOS header at offset 0
    create_dos_header(data, 128);

    // PE signature at offset 128
    create_pe_signature(data, 128);

    // COFF header at offset 132 (IA64 machine type = 0x0200)
    create_coff_header(data, 132, 0x0200);

    // Optional header at offset 152
    // Global Pointer RVA = 0x00005000, Size = 0 (size should always be 0)
    create_optional_header_pe32(data, 152, 0x00005000, 0);

    // Section table at offset 376 (152 + 224)
    // .text section: RVA 0x1000, VirtualSize 0x1000, FileOffset 0x400, FileSize 0x1000
    create_section_header(data, 376, ".text", 0x1000, 0x1000, 0x400, 0x1000);

    // Ensure file is large enough
    data.resize(0x1000);

    return data;
}

/**
 * Create PE32 without global pointer (no data directory)
 */
static std::vector<uint8_t> create_test_pe_no_global_ptr() {
    std::vector<uint8_t> data;

    create_dos_header(data, 128);
    create_pe_signature(data, 128);
    create_coff_header(data, 132); // Regular x86, not IA64

    // Global pointer RVA and size = 0 (no global pointer)
    create_optional_header_pe32(data, 152, 0, 0);
    create_section_header(data, 376, ".text", 0x1000, 0x200, 0x400, 0x200);

    data.resize(0x1000);

    return data;
}

} // anonymous namespace

// =============================================================================
// Test Cases
// =============================================================================

TEST_CASE("Global Pointer Parser - IA64 with global pointer") {
    auto pe_data = create_test_pe_with_global_ptr();
    auto pe = pe_file::from_memory(pe_data);

    SUBCASE("PE file loads successfully") {
        CHECK(pe.get_format() == format_type::PE_WIN32);
        CHECK_FALSE(pe.is_64bit());
    }

    SUBCASE("Data directory entry exists") {
        CHECK(pe.has_data_directory(directory_entry::GLOBALPTR));
        CHECK(pe.data_directory_rva(directory_entry::GLOBALPTR) == 0x00005000);
        CHECK(pe.data_directory_size(directory_entry::GLOBALPTR) == 0);
    }

    SUBCASE("Global pointer exists and is valid") {
        auto gp = pe.global_ptr();
        REQUIRE(gp != nullptr);
        CHECK(gp->is_valid());
        CHECK(gp->is_set());
    }

    SUBCASE("Global pointer value") {
        auto gp = pe.global_ptr();

        CHECK(gp->global_ptr_rva == 0x00005000);
    }
}

TEST_CASE("Global Pointer Parser - PE without global pointer") {
    auto pe_data = create_test_pe_no_global_ptr();
    auto pe = pe_file::from_memory(pe_data);

    SUBCASE("Data directory entry does not exist") {
        CHECK_FALSE(pe.has_data_directory(directory_entry::GLOBALPTR));
        CHECK(pe.data_directory_rva(directory_entry::GLOBALPTR) == 0);
        CHECK(pe.data_directory_size(directory_entry::GLOBALPTR) == 0);
    }

    SUBCASE("Global pointer is not set") {
        auto gp = pe.global_ptr();
        REQUIRE(gp != nullptr);

        CHECK_FALSE(gp->is_valid());
        CHECK_FALSE(gp->is_set());
        CHECK(gp->global_ptr_rva == 0);
    }
}

TEST_CASE("Global Pointer Parser - Lazy parsing and caching") {
    auto pe_data = create_test_pe_with_global_ptr();
    auto pe = pe_file::from_memory(pe_data);

    // First access - should parse
    auto gp1 = pe.global_ptr();
    REQUIRE(gp1 != nullptr);
    CHECK(gp1->is_valid());
    CHECK(gp1->global_ptr_rva == 0x00005000);

    // Second access - should return cached result
    auto gp2 = pe.global_ptr();
    REQUIRE(gp2 != nullptr);
    CHECK(gp2.get() == gp1.get()); // Same pointer (cached)
    CHECK(gp2->global_ptr_rva == 0x00005000);
}

TEST_CASE("Global Pointer Parser - Zero size requirement") {
    auto pe_data = create_test_pe_with_global_ptr();
    auto pe = pe_file::from_memory(pe_data);

    // According to PE/COFF spec, the size field should always be 0
    CHECK(pe.data_directory_size(directory_entry::GLOBALPTR) == 0);

    auto gp = pe.global_ptr();
    REQUIRE(gp != nullptr);
    CHECK(gp->is_valid());
}
