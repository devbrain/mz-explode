// libexe - Modern executable file analysis library
// Copyright (c) 2024
// Unit tests for COM Descriptor Parser (.NET CLR Runtime Header)

#include <doctest/doctest.h>
#include <libexe/formats/pe_file.hpp>
#include <libexe/pe/directories/com_descriptor.hpp>
#include <algorithm>
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
 * Create PE32 optional header (224 bytes) with COM descriptor directory
 */
static void create_optional_header_pe32(std::vector<uint8_t>& data, uint32_t offset,
                                        uint32_t com_descriptor_rva, uint32_t com_descriptor_size) {
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
    // COM Descriptor Directory is at index 14 (offset 96 + 14*8 = 208)
    std::memcpy(header + 208, &com_descriptor_rva, 4);
    std::memcpy(header + 212, &com_descriptor_size, 4);
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
    std::memcpy(section, name, std::min(std::strlen(name), size_t{8}));

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
 * Write 16-bit value at offset
 */
static void write_u16(std::vector<uint8_t>& data, uint32_t offset, uint16_t value) {
    std::memcpy(data.data() + offset, &value, 2);
}

/**
 * Create a minimal PE32 .NET assembly with COM descriptor
 *
 * Structure:
 * - DOS header + stub (128 bytes)
 * - PE signature (4 bytes)
 * - COFF header (20 bytes)
 * - Optional header PE32 (224 bytes)
 * - Section table: 1 section (40 bytes)
 * - Padding to 0x400
 * - Section .text at RVA 0x2000, file offset 0x400
 *   - COM descriptor at RVA 0x2000
 */
static std::vector<uint8_t> create_test_dotnet_assembly() {
    std::vector<uint8_t> data;

    // DOS header at offset 0
    create_dos_header(data, 128);

    // PE signature at offset 128
    create_pe_signature(data, 128);

    // COFF header at offset 132
    create_coff_header(data, 132);

    // Optional header at offset 152
    // COM descriptor at RVA 0x2000, size 72 bytes
    create_optional_header_pe32(data, 152, 0x2000, 72);

    // Section table at offset 376 (152 + 224)
    // .text section: RVA 0x2000, VirtualSize 0x1000, FileOffset 0x400, FileSize 0x1000
    create_section_header(data, 376, ".text", 0x2000, 0x1000, 0x400, 0x1000);

    // Ensure file is large enough
    data.resize(0x400 + 0x1000);

    // Create IMAGE_COR20_HEADER at file offset 0x400 (RVA 0x2000)
    uint32_t cor_offset = 0x400;

    // cb (header size) = 72
    write_u32(data, cor_offset + 0, 72);

    // MajorRuntimeVersion = 2
    write_u16(data, cor_offset + 4, 2);

    // MinorRuntimeVersion = 5
    write_u16(data, cor_offset + 6, 5);

    // MetaData RVA = 0x2100, Size = 0x1000
    write_u32(data, cor_offset + 8, 0x2100);
    write_u32(data, cor_offset + 12, 0x1000);

    // Flags = COMIMAGE_FLAGS_ILONLY (0x00000001)
    write_u32(data, cor_offset + 16, 0x00000001);

    // EntryPointToken = 0x06000001 (MethodDef table, row 1)
    write_u32(data, cor_offset + 20, 0x06000001);

    // Resources RVA = 0, Size = 0 (no resources)
    write_u32(data, cor_offset + 24, 0);
    write_u32(data, cor_offset + 28, 0);

    // StrongNameSignature RVA = 0, Size = 0 (not signed)
    write_u32(data, cor_offset + 32, 0);
    write_u32(data, cor_offset + 36, 0);

    // CodeManagerTable RVA = 0, Size = 0
    write_u32(data, cor_offset + 40, 0);
    write_u32(data, cor_offset + 44, 0);

    // VTableFixups RVA = 0, Size = 0
    write_u32(data, cor_offset + 48, 0);
    write_u32(data, cor_offset + 52, 0);

    // ExportAddressTableJumps RVA = 0, Size = 0
    write_u32(data, cor_offset + 56, 0);
    write_u32(data, cor_offset + 60, 0);

    // ManagedNativeHeader RVA = 0, Size = 0
    write_u32(data, cor_offset + 64, 0);
    write_u32(data, cor_offset + 68, 0);

    return data;
}

/**
 * Create .NET assembly with strong name signature
 */
static std::vector<uint8_t> create_test_signed_dotnet_assembly() {
    std::vector<uint8_t> data = create_test_dotnet_assembly();

    uint32_t cor_offset = 0x400;

    // Update flags to include STRONGNAMESIGNED (0x00000008)
    write_u32(data, cor_offset + 16, 0x00000001 | 0x00000008);

    // StrongNameSignature RVA = 0x3100, Size = 128
    write_u32(data, cor_offset + 32, 0x3100);
    write_u32(data, cor_offset + 36, 128);

    return data;
}

/**
 * Create .NET assembly with managed resources
 */
static std::vector<uint8_t> create_test_dotnet_with_resources() {
    std::vector<uint8_t> data = create_test_dotnet_assembly();

    uint32_t cor_offset = 0x400;

    // Resources RVA = 0x3200, Size = 512
    write_u32(data, cor_offset + 24, 0x3200);
    write_u32(data, cor_offset + 28, 512);

    return data;
}

/**
 * Create native PE (non-.NET)
 */
static std::vector<uint8_t> create_test_native_pe() {
    std::vector<uint8_t> data;

    create_dos_header(data, 128);
    create_pe_signature(data, 128);
    create_coff_header(data, 132);

    // COM descriptor RVA and size = 0 (no .NET)
    create_optional_header_pe32(data, 152, 0, 0);
    create_section_header(data, 376, ".text", 0x1000, 0x200, 0x400, 0x200);

    data.resize(0x1000);

    return data;
}

} // anonymous namespace

// =============================================================================
// Test Cases
// =============================================================================

TEST_CASE("COM Descriptor Parser - .NET assembly") {
    auto pe_data = create_test_dotnet_assembly();
    auto pe = pe_file::from_memory(pe_data);

    SUBCASE("PE file loads successfully") {
        CHECK(pe.get_format() == format_type::PE_WIN32);
        CHECK_FALSE(pe.is_64bit());
    }

    SUBCASE("Data directory entry exists") {
        CHECK(pe.has_data_directory(directory_entry::COM_DESCRIPTOR));
        CHECK(pe.data_directory_rva(directory_entry::COM_DESCRIPTOR) == 0x2000);
        CHECK(pe.data_directory_size(directory_entry::COM_DESCRIPTOR) == 72);
    }

    SUBCASE("COM descriptor exists") {
        auto clr = pe.clr_header();
        REQUIRE(clr != nullptr);
        CHECK(clr->is_valid());
    }

    SUBCASE("Header properties") {
        auto clr = pe.clr_header();

        CHECK(clr->header_size == 72);
        CHECK(clr->major_runtime_version == 2);
        CHECK(clr->minor_runtime_version == 5);
        CHECK(clr->runtime_version() == "2.5");
    }

    SUBCASE("Metadata location") {
        auto clr = pe.clr_header();

        CHECK(clr->metadata_rva == 0x2100);
        CHECK(clr->metadata_size == 0x1000);
    }

    SUBCASE("Assembly flags") {
        auto clr = pe.clr_header();

        CHECK(clr->is_il_only());
        CHECK_FALSE(clr->requires_32bit());
        CHECK_FALSE(clr->prefers_32bit());
        CHECK_FALSE(clr->is_strong_name_signed());
        CHECK_FALSE(clr->has_native_entrypoint());
        CHECK_FALSE(clr->is_library());
    }

    SUBCASE("Entry point") {
        auto clr = pe.clr_header();

        CHECK(clr->entry_point_token_or_rva == 0x06000001);
        CHECK_FALSE(clr->has_native_entrypoint());
    }

    SUBCASE("No resources") {
        auto clr = pe.clr_header();

        CHECK_FALSE(clr->has_resources());
        CHECK(clr->resources_rva == 0);
        CHECK(clr->resources_size == 0);
    }

    SUBCASE("No strong name signature") {
        auto clr = pe.clr_header();

        CHECK_FALSE(clr->is_strong_name_signed());
        CHECK(clr->strong_name_signature_rva == 0);
        CHECK(clr->strong_name_signature_size == 0);
    }

    SUBCASE("No VTable fixups") {
        auto clr = pe.clr_header();

        CHECK_FALSE(clr->has_vtable_fixups());
        CHECK(clr->vtable_fixups_rva == 0);
        CHECK(clr->vtable_fixups_size == 0);
    }
}

TEST_CASE("COM Descriptor Parser - Signed .NET assembly") {
    auto pe_data = create_test_signed_dotnet_assembly();
    auto pe = pe_file::from_memory(pe_data);

    auto clr = pe.clr_header();
    REQUIRE(clr != nullptr);

    CHECK(clr->is_valid());
    CHECK(clr->is_strong_name_signed());
    CHECK(clr->strong_name_signature_rva == 0x3100);
    CHECK(clr->strong_name_signature_size == 128);
}

TEST_CASE("COM Descriptor Parser - .NET assembly with resources") {
    auto pe_data = create_test_dotnet_with_resources();
    auto pe = pe_file::from_memory(pe_data);

    auto clr = pe.clr_header();
    REQUIRE(clr != nullptr);

    CHECK(clr->is_valid());
    CHECK(clr->has_resources());
    CHECK(clr->resources_rva == 0x3200);
    CHECK(clr->resources_size == 512);
}

TEST_CASE("COM Descriptor Parser - Native PE (non-.NET)") {
    auto pe_data = create_test_native_pe();
    auto pe = pe_file::from_memory(pe_data);

    auto clr = pe.clr_header();
    REQUIRE(clr != nullptr);

    // Should return empty COM descriptor for non-.NET executables
    CHECK_FALSE(clr->is_valid());
    CHECK(clr->header_size == 0);
    CHECK(clr->metadata_rva == 0);
    CHECK(clr->metadata_size == 0);
}

TEST_CASE("COM Descriptor Parser - Lazy parsing and caching") {
    auto pe_data = create_test_dotnet_assembly();
    auto pe = pe_file::from_memory(pe_data);

    // First access - should parse
    auto clr1 = pe.clr_header();
    REQUIRE(clr1 != nullptr);
    CHECK(clr1->is_valid());

    // Second access - should return cached result
    auto clr2 = pe.clr_header();
    REQUIRE(clr2 != nullptr);
    CHECK(clr2.get() == clr1.get()); // Same pointer (cached)
    CHECK(clr2->is_valid());
}
