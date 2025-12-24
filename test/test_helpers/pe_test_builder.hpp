// libexe - Modern executable file analysis library
// Copyright (c) 2024
// Shared test helpers for building minimal PE files

#ifndef LIBEXE_TEST_HELPERS_PE_TEST_BUILDER_HPP
#define LIBEXE_TEST_HELPERS_PE_TEST_BUILDER_HPP

#include <libexe/pe/types.hpp>
#include <cstdint>
#include <cstring>
#include <vector>

namespace test_helpers {

/**
 * Create minimal DOS header (64 bytes)
 * Sets MZ signature and PE offset pointer at 0x3C
 */
inline void create_dos_header(std::vector<uint8_t>& data, uint32_t pe_offset) {
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
inline void create_pe_signature(std::vector<uint8_t>& data, uint32_t offset) {
    data[offset] = 'P';
    data[offset + 1] = 'E';
    data[offset + 2] = 0;
    data[offset + 3] = 0;
}

/**
 * Create COFF file header (20 bytes)
 * Sets machine type to I386, 1 section, and standard characteristics
 */
inline void create_coff_header(std::vector<uint8_t>& data, uint32_t offset, bool is_64bit = false) {
    uint8_t* header = data.data() + offset;

    // Machine type (I386 or AMD64)
    uint16_t machine = is_64bit ? 0x8664 : 0x014C;
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

    // SizeOfOptionalHeader (PE32 = 224, PE32+ = 240)
    uint16_t optional_size = is_64bit ? 240 : 224;
    std::memcpy(header + 16, &optional_size, 2);

    // Characteristics
    uint16_t characteristics = 0x0002 | 0x0020; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    std::memcpy(header + 18, &characteristics, 2);
}

/**
 * Create PE32 optional header (224 bytes) with a specific data directory set
 *
 * @param data The PE file buffer
 * @param offset Offset where optional header starts
 * @param dir_entry Which data directory to set (e.g., directory_entry::IMPORT)
 * @param dir_rva RVA of the directory
 * @param dir_size Size of the directory
 */
inline void create_optional_header_pe32(std::vector<uint8_t>& data, uint32_t offset,
                                        libexe::directory_entry dir_entry,
                                        uint32_t dir_rva, uint32_t dir_size) {
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
    // Each directory entry is 8 bytes (RVA + Size)
    uint32_t dir_offset = 96 + static_cast<uint32_t>(dir_entry) * 8;
    std::memcpy(header + dir_offset, &dir_rva, 4);
    std::memcpy(header + dir_offset + 4, &dir_size, 4);
}

/**
 * Create PE32+ optional header (240 bytes) with a specific data directory set
 */
inline void create_optional_header_pe64(std::vector<uint8_t>& data, uint32_t offset,
                                        libexe::directory_entry dir_entry,
                                        uint32_t dir_rva, uint32_t dir_size) {
    uint8_t* header = data.data() + offset;

    // Magic (PE32+ = 0x20B)
    uint16_t magic = 0x20B;
    std::memcpy(header, &magic, 2);

    // AddressOfEntryPoint
    uint32_t entry_point = 0x1000;
    std::memcpy(header + 16, &entry_point, 4);

    // ImageBase (64-bit)
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

    // Data directories start at offset 112 for PE32+
    uint32_t dir_offset = 112 + static_cast<uint32_t>(dir_entry) * 8;
    std::memcpy(header + dir_offset, &dir_rva, 4);
    std::memcpy(header + dir_offset + 4, &dir_size, 4);
}

/**
 * Create section table entry (40 bytes)
 */
inline void create_section_header(std::vector<uint8_t>& data, uint32_t offset,
                                  const char* name, uint32_t virtual_addr,
                                  uint32_t virtual_size, uint32_t raw_offset,
                                  uint32_t raw_size) {
    uint8_t* section = data.data() + offset;

    // Name (8 bytes, null-padded)
    // PE section names are exactly 8 bytes, no null terminator required
    std::memset(section, 0, 8);
    size_t name_len = std::strlen(name);
    if (name_len > 8) name_len = 8;
    std::memcpy(section, name, name_len);

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
 * Create a minimal PE32 file with a specific data directory set
 *
 * Structure:
 * - DOS header + stub (128 bytes)
 * - PE signature (4 bytes)
 * - COFF header (20 bytes)
 * - Optional header PE32 (224 bytes)
 * - Section table: 1 section (40 bytes)
 * - Padding to 0x400
 * - Section .text at RVA 0x1000, file offset 0x400
 *
 * @param dir_entry Which data directory to set
 * @param dir_rva RVA of the directory (0 for reserved/empty)
 * @param dir_size Size of the directory (0 for reserved/empty)
 * @return Complete PE32 file buffer
 */
inline std::vector<uint8_t> create_minimal_pe32(libexe::directory_entry dir_entry,
                                                 uint32_t dir_rva = 0,
                                                 uint32_t dir_size = 0) {
    std::vector<uint8_t> data;

    // DOS header at offset 0
    create_dos_header(data, 128);

    // PE signature at offset 128
    create_pe_signature(data, 128);

    // COFF header at offset 132
    create_coff_header(data, 132, false);

    // Optional header at offset 152
    create_optional_header_pe32(data, 152, dir_entry, dir_rva, dir_size);

    // Section table at offset 376 (152 + 224)
    // .text section: RVA 0x1000, VirtualSize 0x1000, FileOffset 0x400, FileSize 0x1000
    create_section_header(data, 376, ".text", 0x1000, 0x1000, 0x400, 0x1000);

    // Ensure file is large enough
    data.resize(0x1000);

    return data;
}

/**
 * Create a minimal PE32+ (64-bit) file with a specific data directory set
 */
inline std::vector<uint8_t> create_minimal_pe64(libexe::directory_entry dir_entry,
                                                 uint32_t dir_rva = 0,
                                                 uint32_t dir_size = 0) {
    std::vector<uint8_t> data;

    // DOS header at offset 0
    create_dos_header(data, 128);

    // PE signature at offset 128
    create_pe_signature(data, 128);

    // COFF header at offset 132
    create_coff_header(data, 132, true);

    // Optional header at offset 152 (PE32+ is 240 bytes)
    create_optional_header_pe64(data, 152, dir_entry, dir_rva, dir_size);

    // Section table at offset 392 (152 + 240)
    create_section_header(data, 392, ".text", 0x1000, 0x1000, 0x400, 0x1000);

    // Ensure file is large enough
    data.resize(0x1000);

    return data;
}

// =============================================================================
// Utility functions for writing data to PE buffers
// =============================================================================

/**
 * Write 32-bit value at offset (little-endian)
 */
inline void write_u32(std::vector<uint8_t>& data, uint32_t offset, uint32_t value) {
    std::memcpy(data.data() + offset, &value, 4);
}

/**
 * Write 16-bit value at offset (little-endian)
 */
inline void write_u16(std::vector<uint8_t>& data, uint32_t offset, uint16_t value) {
    std::memcpy(data.data() + offset, &value, 2);
}

/**
 * Write 8-bit value at offset
 */
inline void write_u8(std::vector<uint8_t>& data, uint32_t offset, uint8_t value) {
    data[offset] = value;
}

/**
 * Write null-terminated string at offset
 */
inline void write_string(std::vector<uint8_t>& data, uint32_t offset, const char* str) {
    size_t len = std::strlen(str) + 1;  // Include null terminator
    std::memcpy(data.data() + offset, str, len);
}

} // namespace test_helpers

#endif // LIBEXE_TEST_HELPERS_PE_TEST_BUILDER_HPP
