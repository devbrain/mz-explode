// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <doctest/doctest.h>
#include <libexe/formats/pe_file.hpp>
#include <libexe/pe/directories/tls.hpp>
#include <libexe/pe/directories/tls.hpp>
#include <vector>
#include <cstring>

using namespace libexe;

// =============================================================================
// Test Helpers
// =============================================================================

/**
 * Create minimal valid PE32 file with TLS directory
 */
static std::vector<uint8_t> create_test_pe32_with_tls(
    uint32_t image_base = 0x00400000,
    bool with_callbacks = true
) {
    std::vector<uint8_t> data;
    data.resize(4096);  // 4KB file

    // DOS Header (minimal)
    data[0] = 'M'; data[1] = 'Z';  // e_magic
    uint32_t pe_offset = 0x80;
    std::memcpy(&data[0x3C], &pe_offset, 4);  // e_lfanew

    // PE Signature
    std::memcpy(&data[pe_offset], "PE\0\0", 4);

    // COFF File Header
    uint16_t machine = 0x014C;  // IMAGE_FILE_MACHINE_I386
    std::memcpy(&data[pe_offset + 4], &machine, 2);
    uint16_t num_sections = 1;
    std::memcpy(&data[pe_offset + 6], &num_sections, 2);
    uint16_t opt_hdr_size = 224;  // PE32
    std::memcpy(&data[pe_offset + 20], &opt_hdr_size, 2);

    // Optional Header (PE32)
    uint16_t magic = 0x010B;  // PE32
    std::memcpy(&data[pe_offset + 24], &magic, 2);
    std::memcpy(&data[pe_offset + 52], &image_base, 4);  // ImageBase
    uint32_t section_alignment = 0x1000;
    std::memcpy(&data[pe_offset + 56], &section_alignment, 4);
    uint32_t file_alignment = 0x200;
    std::memcpy(&data[pe_offset + 60], &file_alignment, 4);
    // NumberOfRvaAndSizes - must be at least 10 to include TLS (index 9)
    uint32_t num_rva_sizes = 16;  // Standard number of data directories
    std::memcpy(&data[pe_offset + 24 + 92], &num_rva_sizes, 4);

    // Data Directory - TLS (index 9)
    // DataDirectory is at offset 96 in PE32 optional header
    uint32_t tls_rva = 0x3000;
    uint32_t tls_size = 24;  // sizeof(IMAGE_TLS_DIRECTORY32)
    std::memcpy(&data[pe_offset + 24 + 96 + 9 * 8], &tls_rva, 4);
    std::memcpy(&data[pe_offset + 24 + 96 + 9 * 8 + 4], &tls_size, 4);

    // Section Header (.rdata for TLS)
    uint32_t section_offset = pe_offset + 24 + opt_hdr_size;
    std::memcpy(&data[section_offset], ".rdata\0\0", 8);  // Name
    uint32_t virtual_size = 0x1000;
    std::memcpy(&data[section_offset + 8], &virtual_size, 4);
    uint32_t virtual_address = 0x3000;
    std::memcpy(&data[section_offset + 12], &virtual_address, 4);
    uint32_t raw_size = 0x200;
    std::memcpy(&data[section_offset + 16], &raw_size, 4);
    uint32_t raw_offset = 0x400;
    std::memcpy(&data[section_offset + 20], &raw_offset, 4);
    uint32_t characteristics = 0x40000040;  // CNT_INITIALIZED_DATA | MEM_READ
    std::memcpy(&data[section_offset + 36], &characteristics, 4);

    // TLS Directory (at file offset 0x400, RVA 0x3000)
    uint32_t tls_offset = 0x400;

    // IMAGE_TLS_DIRECTORY32
    uint32_t start_va = image_base + 0x3100;
    uint32_t end_va = image_base + 0x3200;
    uint32_t index_va = image_base + 0x3080;
    uint32_t callbacks_va = with_callbacks ? (image_base + 0x30A0) : 0;
    uint32_t zero_fill = 0x10;
    uint32_t tls_characteristics = 0;

    std::memcpy(&data[tls_offset], &start_va, 4);
    std::memcpy(&data[tls_offset + 4], &end_va, 4);
    std::memcpy(&data[tls_offset + 8], &index_va, 4);
    std::memcpy(&data[tls_offset + 12], &callbacks_va, 4);
    std::memcpy(&data[tls_offset + 16], &zero_fill, 4);
    std::memcpy(&data[tls_offset + 20], &tls_characteristics, 4);

    // TLS Callbacks (at file offset 0x4A0, RVA 0x30A0)
    if (with_callbacks) {
        uint32_t callback_offset = 0x4A0;
        uint32_t callback1 = image_base + 0x1000;
        uint32_t callback2 = image_base + 0x1050;
        uint32_t callback_null = 0;

        std::memcpy(&data[callback_offset], &callback1, 4);
        std::memcpy(&data[callback_offset + 4], &callback2, 4);
        std::memcpy(&data[callback_offset + 8], &callback_null, 4);  // Null terminator
    }

    return data;
}

/**
 * Create minimal valid PE32+ file with TLS directory
 */
static std::vector<uint8_t> create_test_pe64_with_tls(
    uint64_t image_base = 0x0000000140000000ULL,
    bool with_callbacks = true
) {
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

    // Optional Header (PE32+)
    uint16_t magic = 0x020B;  // PE32+
    std::memcpy(&data[pe_offset + 24], &magic, 2);
    std::memcpy(&data[pe_offset + 48], &image_base, 8);  // ImageBase (64-bit)
    uint32_t section_alignment = 0x1000;
    std::memcpy(&data[pe_offset + 56], &section_alignment, 4);
    uint32_t file_alignment = 0x200;
    std::memcpy(&data[pe_offset + 60], &file_alignment, 4);
    // NumberOfRvaAndSizes - must be at least 10 to include TLS (index 9)
    uint32_t num_rva_sizes = 16;  // Standard number of data directories
    std::memcpy(&data[pe_offset + 24 + 108], &num_rva_sizes, 4);

    // Data Directory - TLS (index 9)
    // DataDirectory is at offset 112 in PE32+ optional header
    uint32_t tls_rva = 0x3000;
    uint32_t tls_size = 40;  // sizeof(IMAGE_TLS_DIRECTORY64)
    std::memcpy(&data[pe_offset + 24 + 112 + 9 * 8], &tls_rva, 4);
    std::memcpy(&data[pe_offset + 24 + 112 + 9 * 8 + 4], &tls_size, 4);

    // Section Header
    uint32_t section_offset = pe_offset + 24 + opt_hdr_size;
    std::memcpy(&data[section_offset], ".rdata\0\0", 8);
    uint32_t virtual_size = 0x1000;
    std::memcpy(&data[section_offset + 8], &virtual_size, 4);
    uint32_t virtual_address = 0x3000;
    std::memcpy(&data[section_offset + 12], &virtual_address, 4);
    uint32_t raw_size = 0x200;
    std::memcpy(&data[section_offset + 16], &raw_size, 4);
    uint32_t raw_offset = 0x400;
    std::memcpy(&data[section_offset + 20], &raw_offset, 4);
    uint32_t characteristics = 0x40000040;
    std::memcpy(&data[section_offset + 36], &characteristics, 4);

    // TLS Directory (at file offset 0x400, RVA 0x3000)
    uint32_t tls_offset = 0x400;

    // IMAGE_TLS_DIRECTORY64
    uint64_t start_va = image_base + 0x3100;
    uint64_t end_va = image_base + 0x3200;
    uint64_t index_va = image_base + 0x3080;
    uint64_t callbacks_va = with_callbacks ? (image_base + 0x30A0) : 0;
    uint32_t zero_fill = 0x20;
    uint32_t tls_characteristics = 0;

    std::memcpy(&data[tls_offset], &start_va, 8);
    std::memcpy(&data[tls_offset + 8], &end_va, 8);
    std::memcpy(&data[tls_offset + 16], &index_va, 8);
    std::memcpy(&data[tls_offset + 24], &callbacks_va, 8);
    std::memcpy(&data[tls_offset + 32], &zero_fill, 4);
    std::memcpy(&data[tls_offset + 36], &tls_characteristics, 4);

    // TLS Callbacks (at file offset 0x4A0, RVA 0x30A0)
    if (with_callbacks) {
        uint32_t callback_offset = 0x4A0;
        uint64_t callback1 = image_base + 0x1000;
        uint64_t callback2 = image_base + 0x1050;
        uint64_t callback3 = image_base + 0x10A0;
        uint64_t callback_null = 0;

        std::memcpy(&data[callback_offset], &callback1, 8);
        std::memcpy(&data[callback_offset + 8], &callback2, 8);
        std::memcpy(&data[callback_offset + 16], &callback3, 8);
        std::memcpy(&data[callback_offset + 24], &callback_null, 8);  // Null terminator
    }

    return data;
}

// =============================================================================
// Test Cases
// =============================================================================

TEST_CASE("TLS directory - pe_file accessor methods") {
    SUBCASE("PE32 file with TLS directory") {
        auto data = create_test_pe32_with_tls();
        auto pe = pe_file::from_memory(data);

        // Check data directory
        CHECK(pe.has_data_directory(directory_entry::TLS));
        CHECK(pe.data_directory_rva(directory_entry::TLS) == 0x3000);
        CHECK(pe.data_directory_size(directory_entry::TLS) == 24);

        // Check TLS accessor
        auto tls = pe.tls();
        REQUIRE(tls != nullptr);
    }

    SUBCASE("PE32+ file with TLS directory") {
        auto data = create_test_pe64_with_tls();
        auto pe = pe_file::from_memory(data);

        CHECK(pe.has_data_directory(directory_entry::TLS));
        CHECK(pe.data_directory_rva(directory_entry::TLS) == 0x3000);
        CHECK(pe.data_directory_size(directory_entry::TLS) == 40);

        auto tls = pe.tls();
        REQUIRE(tls != nullptr);
    }

    SUBCASE("PE file without TLS directory") {
        auto data = create_test_pe32_with_tls();

        // Zero out TLS data directory (correct offset: pe_offset + 24 + 96 + 9 * 8)
        uint32_t pe_offset = 0x80;
        uint32_t zero = 0;
        std::memcpy(&data[pe_offset + 24 + 96 + 9 * 8], &zero, 4);
        std::memcpy(&data[pe_offset + 24 + 96 + 9 * 8 + 4], &zero, 4);

        auto pe = pe_file::from_memory(data);

        CHECK_FALSE(pe.has_data_directory(directory_entry::TLS));

        auto tls = pe.tls();
        REQUIRE(tls != nullptr);
        CHECK(tls->callbacks.empty());
    }
}

TEST_CASE("TLS directory - PE32 parsing") {
    auto data = create_test_pe32_with_tls(0x00400000, true);
    auto pe = pe_file::from_memory(data);
    auto tls = pe.tls();

    REQUIRE(tls != nullptr);

    SUBCASE("TLS directory fields") {
        CHECK(tls->start_address_of_raw_data == 0x00403100);
        CHECK(tls->end_address_of_raw_data == 0x00403200);
        CHECK(tls->address_of_index == 0x00403080);
        CHECK(tls->address_of_callbacks == 0x004030A0);
        CHECK(tls->size_of_zero_fill == 0x10);
        CHECK(tls->characteristics == 0);
    }

    SUBCASE("TLS callbacks") {
        REQUIRE(tls->callbacks.size() == 2);
        CHECK(tls->callbacks[0].address == 0x00401000);
        CHECK(tls->callbacks[1].address == 0x00401050);

        CHECK_FALSE(tls->callbacks[0].is_null());
        CHECK_FALSE(tls->callbacks[1].is_null());
    }

    SUBCASE("TLS template size") {
        uint64_t expected_size = 0x00403200 - 0x00403100;
        CHECK(tls->template_size() == expected_size);
        CHECK(tls->template_size() == 0x100);
    }

    SUBCASE("TLS total size") {
        uint64_t expected_total = tls->template_size() + tls->size_of_zero_fill;
        CHECK(tls->total_size() == expected_total);
        CHECK(tls->total_size() == 0x110);
    }

    SUBCASE("VA to RVA conversion") {
        uint32_t rva = tls_directory::va_to_rva(0x00403100, 0x00400000);
        CHECK(rva == 0x3100);

        CHECK(tls->get_start_rva(0x00400000) == 0x3100);
    }
}

TEST_CASE("TLS directory - PE32+ parsing") {
    auto data = create_test_pe64_with_tls(0x0000000140000000ULL, true);
    auto pe = pe_file::from_memory(data);
    auto tls = pe.tls();

    REQUIRE(tls != nullptr);

    SUBCASE("TLS directory fields") {
        CHECK(tls->start_address_of_raw_data == 0x0000000140003100ULL);
        CHECK(tls->end_address_of_raw_data == 0x0000000140003200ULL);
        CHECK(tls->address_of_index == 0x0000000140003080ULL);
        CHECK(tls->address_of_callbacks == 0x00000001400030A0ULL);
        CHECK(tls->size_of_zero_fill == 0x20);
        CHECK(tls->characteristics == 0);
    }

    SUBCASE("TLS callbacks") {
        REQUIRE(tls->callbacks.size() == 3);
        CHECK(tls->callbacks[0].address == 0x0000000140001000ULL);
        CHECK(tls->callbacks[1].address == 0x0000000140001050ULL);
        CHECK(tls->callbacks[2].address == 0x00000001400010A0ULL);

        CHECK_FALSE(tls->callbacks[0].is_null());
        CHECK_FALSE(tls->callbacks[1].is_null());
        CHECK_FALSE(tls->callbacks[2].is_null());
    }

    SUBCASE("TLS template size") {
        CHECK(tls->template_size() == 0x100);
    }

    SUBCASE("TLS total size") {
        CHECK(tls->total_size() == 0x120);  // 0x100 + 0x20
    }
}

TEST_CASE("TLS directory - no callbacks") {
    SUBCASE("PE32 with null callback pointer") {
        auto data = create_test_pe32_with_tls(0x00400000, false);
        auto pe = pe_file::from_memory(data);
        auto tls = pe.tls();

        REQUIRE(tls != nullptr);
        CHECK(tls->address_of_callbacks == 0);
        CHECK(tls->callbacks.empty());
    }

    SUBCASE("PE32+ with null callback pointer") {
        auto data = create_test_pe64_with_tls(0x0000000140000000ULL, false);
        auto pe = pe_file::from_memory(data);
        auto tls = pe.tls();

        REQUIRE(tls != nullptr);
        CHECK(tls->address_of_callbacks == 0);
        CHECK(tls->callbacks.empty());
    }
}

TEST_CASE("TLS directory - alignment extraction") {
    auto data = create_test_pe32_with_tls();

    // Set alignment in characteristics field
    // Alignment = 2^((characteristics >> 20) & 0xF)
    uint32_t tls_offset = 0x400;

    SUBCASE("No alignment (characteristics = 0)") {
        uint32_t characteristics = 0;
        std::memcpy(&data[tls_offset + 20], &characteristics, 4);

        auto pe = pe_file::from_memory(data);
        auto tls = pe.tls();

        CHECK(tls->alignment() == 0);
    }

    SUBCASE("16-byte alignment (characteristics = 0x00400000)") {
        uint32_t characteristics = 0x00400000;  // Bits 20-23 = 4 → 2^4 = 16
        std::memcpy(&data[tls_offset + 20], &characteristics, 4);

        auto pe = pe_file::from_memory(data);
        auto tls = pe.tls();

        CHECK(tls->alignment() == 16);
    }

    SUBCASE("4096-byte alignment (characteristics = 0x00C00000)") {
        uint32_t characteristics = 0x00C00000;  // Bits 20-23 = 12 → 2^12 = 4096
        std::memcpy(&data[tls_offset + 20], &characteristics, 4);

        auto pe = pe_file::from_memory(data);
        auto tls = pe.tls();

        CHECK(tls->alignment() == 4096);
    }
}

TEST_CASE("TLS directory - edge cases") {
    SUBCASE("Empty TLS directory") {
        tls_directory tls{};  // Value initialization (zeroes all members)

        CHECK(tls.start_address_of_raw_data == 0);
        CHECK(tls.end_address_of_raw_data == 0);
        CHECK(tls.address_of_index == 0);
        CHECK(tls.address_of_callbacks == 0);
        CHECK(tls.size_of_zero_fill == 0);
        CHECK(tls.characteristics == 0);
        CHECK(tls.callbacks.empty());

        CHECK(tls.template_size() == 0);
        CHECK(tls.total_size() == 0);
        CHECK(tls.alignment() == 0);
    }

    SUBCASE("Null TLS callback") {
        tls_callback callback{0};
        CHECK(callback.is_null());
        CHECK(callback.address == 0);
    }

    SUBCASE("Non-null TLS callback") {
        tls_callback callback{0x00401000};
        CHECK_FALSE(callback.is_null());
        CHECK(callback.address == 0x00401000);
    }

    SUBCASE("VA to RVA with zero image base") {
        CHECK(tls_directory::va_to_rva(0x00401000, 0) == 0x00401000);
    }

    SUBCASE("VA to RVA with standard image base") {
        CHECK(tls_directory::va_to_rva(0x00403000, 0x00400000) == 0x3000);
    }
}

TEST_CASE("TLS directory - lazy parsing and caching") {
    auto data = create_test_pe32_with_tls();
    auto pe = pe_file::from_memory(data);

    // First access
    auto tls1 = pe.tls();
    REQUIRE(tls1 != nullptr);
    CHECK(tls1->callbacks.size() == 2);

    // Second access (should return cached)
    auto tls2 = pe.tls();
    REQUIRE(tls2 != nullptr);
    CHECK(tls2.get() == tls1.get());  // Same pointer (cached)
}
