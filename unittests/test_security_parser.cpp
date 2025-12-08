// libexe - Modern executable file analysis library
// Copyright (c) 2024
// Unit tests for Security Directory Parser (Certificate Table)

#include <doctest/doctest.h>
#include <libexe/pe_file.hpp>
#include <libexe/security_directory.hpp>
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
    data.resize(pe_offset + 512); // Ensure enough space
    data[0] = 'M';
    data[1] = 'Z';
    // e_lfanew at offset 0x3C (points to PE signature)
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
 * Create PE32 optional header (224 bytes) with security directory
 */
static void create_optional_header_pe32(std::vector<uint8_t>& data, uint32_t offset,
                                        uint32_t security_offset, uint32_t security_size) {
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
    // Security Directory is at index 4 (offset 96 + 4*8 = 128)
    // IMPORTANT: This is a FILE OFFSET, not an RVA!
    std::memcpy(header + 128, &security_offset, 4);
    std::memcpy(header + 132, &security_size, 4);
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
    uint32_t characteristics = 0x60000020; // IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE
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
 * Create a minimal PE32 file with one Authenticode certificate
 *
 * Structure:
 * - DOS header + stub (128 bytes)
 * - PE signature (4 bytes)
 * - COFF header (20 bytes)
 * - Optional header PE32 (224 bytes)
 * - Section table: 1 section (40 bytes)
 * - Padding to 0x400
 * - Section .text at RVA 0x1000, file offset 0x400
 * - Certificate table at file offset 0x1000
 */
static std::vector<uint8_t> create_test_pe32_with_authenticode() {
    std::vector<uint8_t> data;

    // DOS header at offset 0
    create_dos_header(data, 128);

    // PE signature at offset 128
    create_pe_signature(data, 128);

    // COFF header at offset 132
    create_coff_header(data, 132);

    // Optional header at offset 152
    // Security directory at file offset 0x800, size 56 bytes (one certificate, 8-byte aligned)
    // Certificate length is 50 bytes, aligned to 56 bytes
    create_optional_header_pe32(data, 152, 0x800, 56);

    // Section table at offset 376 (152 + 224)
    // .text section: RVA 0x1000, VirtualSize 0x200, FileOffset 0x400, FileSize 0x200
    create_section_header(data, 376, ".text", 0x1000, 0x200, 0x400, 0x200);

    // Ensure file is large enough for security directory (after section ends at 0x600)
    data.resize(0x1000);

    // Create WIN_CERTIFICATE entry at file offset 0x800
    uint32_t cert_offset = 0x800;

    // WIN_CERTIFICATE header (8 bytes)
    write_u32(data, cert_offset + 0, 50);      // dwLength (8 byte header + 42 bytes data)
    write_u16(data, cert_offset + 4, 0x0200);  // wRevision (WIN_CERT_REVISION_2_0)
    write_u16(data, cert_offset + 6, 0x0002);  // wCertificateType (WIN_CERT_TYPE_PKCS_SIGNED_DATA)

    // Certificate data (42 bytes) - fake PKCS#7 signature
    // In real executables, this would be a DER-encoded PKCS#7 SignedData structure
    for (size_t i = 0; i < 42; ++i) {
        data[cert_offset + 8 + i] = static_cast<uint8_t>(i);
    }

    return data;
}

/**
 * Create PE32 with multiple certificates (including padding)
 */
static std::vector<uint8_t> create_test_pe32_with_multiple_certificates() {
    std::vector<uint8_t> data;

    create_dos_header(data, 128);
    create_pe_signature(data, 128);
    create_coff_header(data, 132);

    // Security directory at file offset 0x800, size 96 bytes (2 certificates)
    // Certificate 1: 50 bytes, aligned to 56
    // Certificate 2: 34 bytes, aligned to 40
    // Total: 96 bytes
    create_optional_header_pe32(data, 152, 0x800, 96);
    create_section_header(data, 376, ".text", 0x1000, 0x200, 0x400, 0x200);

    data.resize(0x1000);

    uint32_t cert_offset = 0x800;

    // Certificate 1: Authenticode (length 50, aligned to 56)
    write_u32(data, cert_offset + 0, 50);      // dwLength
    write_u16(data, cert_offset + 4, 0x0200);  // wRevision
    write_u16(data, cert_offset + 6, 0x0002);  // wCertificateType (PKCS_SIGNED_DATA)
    for (size_t i = 0; i < 42; ++i) {
        data[cert_offset + 8 + i] = static_cast<uint8_t>(i);
    }

    // Certificate 2: X.509 (length 34, aligned to 40) - starts at offset 56
    uint32_t cert2_offset = cert_offset + 56;
    write_u32(data, cert2_offset + 0, 34);      // dwLength
    write_u16(data, cert2_offset + 4, 0x0200);  // wRevision
    write_u16(data, cert2_offset + 6, 0x0001);  // wCertificateType (X509)
    for (size_t i = 0; i < 26; ++i) {
        data[cert2_offset + 8 + i] = static_cast<uint8_t>(0xFF - i);
    }

    return data;
}

/**
 * Create PE32 with no security directory
 */
static std::vector<uint8_t> create_test_pe32_no_security() {
    std::vector<uint8_t> data;

    create_dos_header(data, 128);
    create_pe_signature(data, 128);
    create_coff_header(data, 132);

    // Security directory offset and size = 0 (no directory)
    create_optional_header_pe32(data, 152, 0, 0);
    create_section_header(data, 376, ".text", 0x1000, 0x200, 0x400, 0x200);

    data.resize(0x1000);

    return data;
}

} // anonymous namespace

// =============================================================================
// Test Cases
// =============================================================================

TEST_CASE("Security Parser - PE32 with Authenticode signature") {
    auto pe_data = create_test_pe32_with_authenticode();
    auto pe = pe_file::from_memory(pe_data);

    SUBCASE("PE file loads successfully") {
        CHECK(pe.get_format() == format_type::PE_WIN32);
        CHECK_FALSE(pe.is_64bit());
    }

    SUBCASE("Data directory entry exists") {
        // Check if PE file recognizes security directory in data directories
        CHECK(pe.has_data_directory(directory_entry::SECURITY));
        CHECK(pe.data_directory_rva(directory_entry::SECURITY) == 0x800);
        CHECK(pe.data_directory_size(directory_entry::SECURITY) == 56);
    }

    SUBCASE("Security directory exists") {
        auto security = pe.security();
        REQUIRE(security != nullptr);
        CHECK_FALSE(security->empty());
        CHECK(security->certificate_count() == 1);
    }

    SUBCASE("Certificate properties") {
        auto security = pe.security();
        const auto& cert = security->certificates[0];

        CHECK(cert.is_valid());
        CHECK(cert.length == 50);
        CHECK(cert.revision == certificate_revision::REVISION_2_0);
        CHECK(cert.type == certificate_type::PKCS_SIGNED_DATA);
        CHECK(cert.is_authenticode());
        CHECK_FALSE(cert.is_x509());
        CHECK(cert.data_size() == 42);

        // Verify certificate data
        auto cert_data = cert.data();
        REQUIRE(cert_data.size() == 42);
        for (size_t i = 0; i < 42; ++i) {
            CHECK(cert_data[i] == static_cast<uint8_t>(i));
        }
    }

    SUBCASE("Authenticode query") {
        auto security = pe.security();

        CHECK(security->has_authenticode());

        auto auth_cert = security->get_authenticode();
        REQUIRE(auth_cert != nullptr);
        CHECK(auth_cert->is_authenticode());
        CHECK(auth_cert->length == 50);
    }

    SUBCASE("Total size") {
        auto security = pe.security();
        CHECK(security->total_size() == 50);
    }
}

TEST_CASE("Security Parser - Multiple certificates") {
    auto pe_data = create_test_pe32_with_multiple_certificates();
    auto pe = pe_file::from_memory(pe_data);

    auto security = pe.security();
    REQUIRE(security != nullptr);

    CHECK(security->certificate_count() == 2);
    CHECK_FALSE(security->empty());

    SUBCASE("First certificate: Authenticode") {
        const auto& cert1 = security->certificates[0];

        CHECK(cert1.is_valid());
        CHECK(cert1.length == 50);
        CHECK(cert1.type == certificate_type::PKCS_SIGNED_DATA);
        CHECK(cert1.is_authenticode());
        CHECK(cert1.data_size() == 42);
    }

    SUBCASE("Second certificate: X.509") {
        const auto& cert2 = security->certificates[1];

        CHECK(cert2.is_valid());
        CHECK(cert2.length == 34);
        CHECK(cert2.type == certificate_type::X509);
        CHECK(cert2.is_x509());
        CHECK_FALSE(cert2.is_authenticode());
        CHECK(cert2.data_size() == 26);

        // Verify certificate data
        auto cert_data = cert2.data();
        REQUIRE(cert_data.size() == 26);
        for (size_t i = 0; i < 26; ++i) {
            CHECK(cert_data[i] == static_cast<uint8_t>(0xFF - i));
        }
    }

    SUBCASE("Has Authenticode") {
        CHECK(security->has_authenticode());

        auto auth_cert = security->get_authenticode();
        REQUIRE(auth_cert != nullptr);
        CHECK(auth_cert == &security->certificates[0]); // First cert is Authenticode
    }

    SUBCASE("Total size") {
        CHECK(security->total_size() == 84); // 50 + 34
    }
}

TEST_CASE("Security Parser - No security directory") {
    auto pe_data = create_test_pe32_no_security();
    auto pe = pe_file::from_memory(pe_data);

    auto security = pe.security();
    REQUIRE(security != nullptr);

    CHECK(security->empty());
    CHECK(security->certificate_count() == 0);
    CHECK_FALSE(security->has_authenticode());
    CHECK(security->get_authenticode() == nullptr);
    CHECK(security->total_size() == 0);
}

TEST_CASE("Security Parser - Lazy parsing and caching") {
    auto pe_data = create_test_pe32_with_authenticode();
    auto pe = pe_file::from_memory(pe_data);

    // First access - should parse
    auto security1 = pe.security();
    REQUIRE(security1 != nullptr);
    CHECK(security1->certificate_count() == 1);

    // Second access - should return cached result
    auto security2 = pe.security();
    REQUIRE(security2 != nullptr);
    CHECK(security2.get() == security1.get()); // Same pointer (cached)
    CHECK(security2->certificate_count() == 1);
}
