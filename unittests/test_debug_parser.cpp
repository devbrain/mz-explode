// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <doctest/doctest.h>
#include <libexe/pe_file.hpp>
#include <libexe/debug_directory.hpp>
#include <libexe/parsers/debug_directory_parser.hpp>
#include <vector>
#include <cstring>

using namespace libexe;

// =============================================================================
// Test Helpers
// =============================================================================

/**
 * Create minimal valid PE32 file with debug directory
 */
static std::vector<uint8_t> create_test_pe32_with_debug(bool with_codeview = true) {
    std::vector<uint8_t> data;
    data.resize(8192);  // 8KB file

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
    uint32_t image_base = 0x00400000;
    std::memcpy(&data[pe_offset + 52], &image_base, 4);  // ImageBase
    uint32_t section_alignment = 0x1000;
    std::memcpy(&data[pe_offset + 56], &section_alignment, 4);
    uint32_t file_alignment = 0x200;
    std::memcpy(&data[pe_offset + 60], &file_alignment, 4);
    // NumberOfRvaAndSizes
    uint32_t num_rva_sizes = 16;
    std::memcpy(&data[pe_offset + 24 + 92], &num_rva_sizes, 4);

    // Data Directory - DEBUG (index 6)
    uint32_t debug_rva = with_codeview ? 0x3000 : 0;  // No RVA if no debug data
    uint32_t debug_size = with_codeview ? 28 : 0;  // sizeof(IMAGE_DEBUG_DIRECTORY)
    std::memcpy(&data[pe_offset + 24 + 96 + 6 * 8], &debug_rva, 4);
    std::memcpy(&data[pe_offset + 24 + 96 + 6 * 8 + 4], &debug_size, 4);

    // Section Header (.rdata for debug)
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

    if (with_codeview) {
        // IMAGE_DEBUG_DIRECTORY (at file offset 0x400, RVA 0x3000)
        uint32_t debug_dir_offset = 0x400;

        uint32_t characteristics_val = 0;
        std::memcpy(&data[debug_dir_offset], &characteristics_val, 4);
        uint32_t timestamp = 0x61234567;
        std::memcpy(&data[debug_dir_offset + 4], &timestamp, 4);
        uint16_t major_ver = 0;
        std::memcpy(&data[debug_dir_offset + 8], &major_ver, 2);
        uint16_t minor_ver = 0;
        std::memcpy(&data[debug_dir_offset + 10], &minor_ver, 2);
        uint32_t type_val = 2;  // IMAGE_DEBUG_TYPE_CODEVIEW
        std::memcpy(&data[debug_dir_offset + 12], &type_val, 4);
        uint32_t size_of_data = 0x80;  // Size of CodeView data
        std::memcpy(&data[debug_dir_offset + 16], &size_of_data, 4);
        uint32_t address_of_raw_data = 0x3100;  // RVA to CodeView data
        std::memcpy(&data[debug_dir_offset + 20], &address_of_raw_data, 4);
        uint32_t pointer_to_raw_data = 0x500;  // File offset to CodeView data
        std::memcpy(&data[debug_dir_offset + 24], &pointer_to_raw_data, 4);

        // CodeView PDB 7.0 (RSDS) data (at file offset 0x500)
        uint32_t cv_offset = 0x500;

        // Signature 'RSDS'
        uint32_t rsds_sig = 0x53445352;
        std::memcpy(&data[cv_offset], &rsds_sig, 4);

        // GUID
        uint8_t guid[16] = {
            0x12, 0x34, 0x56, 0x78,
            0x9A, 0xBC,
            0xDE, 0xF0,
            0x11, 0x22,
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88
        };
        std::memcpy(&data[cv_offset + 4], guid, 16);

        // Age
        uint32_t age = 1;
        std::memcpy(&data[cv_offset + 20], &age, 4);

        // PDB path (null-terminated)
        const char* pdb_path = "C:\\build\\project.pdb";
        std::memcpy(&data[cv_offset + 24], pdb_path, std::strlen(pdb_path) + 1);
    }

    return data;
}

/**
 * Create PE32 file with multiple debug entries
 */
static std::vector<uint8_t> create_test_pe32_with_multiple_debug() {
    std::vector<uint8_t> data;
    data.resize(8192);

    // DOS Header
    data[0] = 'M'; data[1] = 'Z';
    uint32_t pe_offset = 0x80;
    std::memcpy(&data[0x3C], &pe_offset, 4);

    // PE Signature
    std::memcpy(&data[pe_offset], "PE\0\0", 4);

    // COFF File Header
    uint16_t machine = 0x014C;
    std::memcpy(&data[pe_offset + 4], &machine, 2);
    uint16_t num_sections = 1;
    std::memcpy(&data[pe_offset + 6], &num_sections, 2);
    uint16_t opt_hdr_size = 224;
    std::memcpy(&data[pe_offset + 20], &opt_hdr_size, 2);

    // Optional Header
    uint16_t magic = 0x010B;
    std::memcpy(&data[pe_offset + 24], &magic, 2);
    uint32_t image_base = 0x00400000;
    std::memcpy(&data[pe_offset + 52], &image_base, 4);
    uint32_t section_alignment = 0x1000;
    std::memcpy(&data[pe_offset + 56], &section_alignment, 4);
    uint32_t file_alignment = 0x200;
    std::memcpy(&data[pe_offset + 60], &file_alignment, 4);
    uint32_t num_rva_sizes = 16;
    std::memcpy(&data[pe_offset + 24 + 92], &num_rva_sizes, 4);

    // Data Directory - DEBUG (2 entries = 56 bytes)
    uint32_t debug_rva = 0x3000;
    uint32_t debug_size = 56;  // 2 * sizeof(IMAGE_DEBUG_DIRECTORY)
    std::memcpy(&data[pe_offset + 24 + 96 + 6 * 8], &debug_rva, 4);
    std::memcpy(&data[pe_offset + 24 + 96 + 6 * 8 + 4], &debug_size, 4);

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

    // First debug entry - COFF
    uint32_t debug_dir_offset = 0x400;
    uint32_t zero = 0;
    std::memcpy(&data[debug_dir_offset], &zero, 4);  // characteristics
    uint32_t timestamp = 0x61234567;
    std::memcpy(&data[debug_dir_offset + 4], &timestamp, 4);
    uint16_t ver = 0;
    std::memcpy(&data[debug_dir_offset + 8], &ver, 2);
    std::memcpy(&data[debug_dir_offset + 10], &ver, 2);
    uint32_t type_coff = 1;  // IMAGE_DEBUG_TYPE_COFF
    std::memcpy(&data[debug_dir_offset + 12], &type_coff, 4);
    uint32_t size_1 = 0x100;
    std::memcpy(&data[debug_dir_offset + 16], &size_1, 4);
    uint32_t addr_1 = 0x3100;
    std::memcpy(&data[debug_dir_offset + 20], &addr_1, 4);
    uint32_t ptr_1 = 0x500;
    std::memcpy(&data[debug_dir_offset + 24], &ptr_1, 4);

    // Second debug entry - CodeView
    debug_dir_offset += 28;
    std::memcpy(&data[debug_dir_offset], &zero, 4);
    std::memcpy(&data[debug_dir_offset + 4], &timestamp, 4);
    std::memcpy(&data[debug_dir_offset + 8], &ver, 2);
    std::memcpy(&data[debug_dir_offset + 10], &ver, 2);
    uint32_t type_cv = 2;  // IMAGE_DEBUG_TYPE_CODEVIEW
    std::memcpy(&data[debug_dir_offset + 12], &type_cv, 4);
    uint32_t size_2 = 0x50;
    std::memcpy(&data[debug_dir_offset + 16], &size_2, 4);
    uint32_t addr_2 = 0x3200;
    std::memcpy(&data[debug_dir_offset + 20], &addr_2, 4);
    uint32_t ptr_2 = 0x600;
    std::memcpy(&data[debug_dir_offset + 24], &ptr_2, 4);

    // CodeView data (NB10 format)
    uint32_t cv_offset = 0x600;
    uint32_t nb10_sig = 0x3031424E;  // 'NB10'
    std::memcpy(&data[cv_offset], &nb10_sig, 4);
    uint32_t offset_val = 0;
    std::memcpy(&data[cv_offset + 4], &offset_val, 4);
    uint32_t sig = 0x12345678;
    std::memcpy(&data[cv_offset + 8], &sig, 4);
    uint32_t age = 2;
    std::memcpy(&data[cv_offset + 12], &age, 4);
    const char* pdb = "old_style.pdb";
    std::memcpy(&data[cv_offset + 16], pdb, std::strlen(pdb) + 1);

    return data;
}

// =============================================================================
// Test Cases
// =============================================================================

TEST_CASE("Debug parser - pe_file accessor methods") {
    SUBCASE("PE32 file with debug directory") {
        auto data = create_test_pe32_with_debug();
        auto pe = pe_file::from_memory(data);

        // Check data directory
        CHECK(pe.has_data_directory(directory_entry::DEBUG));
        CHECK(pe.data_directory_rva(directory_entry::DEBUG) == 0x3000);
        CHECK(pe.data_directory_size(directory_entry::DEBUG) == 28);

        // Check debug accessor
        auto debug = pe.debug();
        REQUIRE(debug != nullptr);
        CHECK_FALSE(debug->empty());
    }

    SUBCASE("PE file without debug directory") {
        auto data = create_test_pe32_with_debug(false);
        auto pe = pe_file::from_memory(data);

        CHECK_FALSE(pe.has_data_directory(directory_entry::DEBUG));

        auto debug = pe.debug();
        REQUIRE(debug != nullptr);
        CHECK(debug->empty());
        CHECK(debug->size() == 0);
    }
}

TEST_CASE("Debug parser - CodeView PDB 7.0 (RSDS) parsing") {
    auto data = create_test_pe32_with_debug();
    auto pe = pe_file::from_memory(data);
    auto debug = pe.debug();

    REQUIRE(debug != nullptr);
    REQUIRE(debug->size() == 1);

    SUBCASE("Debug entry fields") {
        const auto& entry = debug->entries[0];

        CHECK(entry.characteristics == 0);
        CHECK(entry.time_date_stamp == 0x61234567);
        CHECK(entry.major_version == 0);
        CHECK(entry.minor_version == 0);
        CHECK(entry.type == debug_type::CODEVIEW);
        CHECK(entry.size_of_data == 0x80);
        CHECK(entry.address_of_raw_data == 0x3100);
        CHECK(entry.pointer_to_raw_data == 0x500);

        CHECK(entry.is_codeview());
        CHECK(entry.has_data());
        CHECK(entry.is_mapped());
        CHECK(entry.type_name() == "CodeView");
    }

    SUBCASE("CodeView PDB 7.0 information") {
        const auto& entry = debug->entries[0];

        REQUIRE(entry.has_pdb70());
        CHECK_FALSE(entry.has_pdb20());

        const auto& pdb70 = entry.codeview_pdb70_info.value();

        CHECK(pdb70.age == 1);
        CHECK(pdb70.pdb_path == "C:\\build\\project.pdb");
        CHECK(pdb70.is_valid());

        // Check GUID
        std::string guid = pdb70.guid_string();
        CHECK(guid == "78563412-BC9A-F0DE-1122-334455667788");
    }

    SUBCASE("PDB path accessors") {
        CHECK(debug->has_codeview());
        CHECK(debug->has_pdb());
        CHECK(debug->get_pdb_path() == "C:\\build\\project.pdb");

        const auto& entry = debug->entries[0];
        CHECK(entry.get_pdb_path() == "C:\\build\\project.pdb");
    }
}

TEST_CASE("Debug parser - CodeView PDB 2.0 (NB10) parsing") {
    auto data = create_test_pe32_with_multiple_debug();
    auto pe = pe_file::from_memory(data);
    auto debug = pe.debug();

    REQUIRE(debug != nullptr);
    REQUIRE(debug->size() == 2);

    SUBCASE("Find CodeView entry") {
        auto cv_entry = debug->get_codeview();
        REQUIRE(cv_entry.has_value());
        CHECK(cv_entry->type == debug_type::CODEVIEW);
    }

    SUBCASE("PDB 2.0 information") {
        auto cv_entry = debug->get_codeview();
        REQUIRE(cv_entry.has_value());

        CHECK_FALSE(cv_entry->has_pdb70());
        REQUIRE(cv_entry->has_pdb20());

        const auto& pdb20 = cv_entry->codeview_pdb20_info.value();

        CHECK(pdb20.signature == 0x12345678);
        CHECK(pdb20.age == 2);
        CHECK(pdb20.pdb_path == "old_style.pdb");
        CHECK(pdb20.is_valid());
    }
}

TEST_CASE("Debug parser - Multiple debug entries") {
    auto data = create_test_pe32_with_multiple_debug();
    auto pe = pe_file::from_memory(data);
    auto debug = pe.debug();

    REQUIRE(debug != nullptr);

    SUBCASE("Entry count") {
        CHECK(debug->size() == 2);
        CHECK_FALSE(debug->empty());
        CHECK(debug->entries.size() == 2);
    }

    SUBCASE("Entry types") {
        CHECK(debug->entries[0].type == debug_type::COFF);
        CHECK(debug->entries[1].type == debug_type::CODEVIEW);

        CHECK(debug->entries[0].type_name() == "COFF");
        CHECK(debug->entries[1].type_name() == "CodeView");
    }

    SUBCASE("Find by type") {
        auto coff = debug->find_type(debug_type::COFF);
        REQUIRE(coff.has_value());
        CHECK(coff->size_of_data == 0x100);

        auto cv = debug->find_type(debug_type::CODEVIEW);
        REQUIRE(cv.has_value());
        CHECK(cv->size_of_data == 0x50);

        auto missing = debug->find_type(debug_type::FPO);
        CHECK_FALSE(missing.has_value());
    }

    SUBCASE("Find all by type") {
        auto all_cv = debug->find_all_type(debug_type::CODEVIEW);
        CHECK(all_cv.size() == 1);

        auto all_coff = debug->find_all_type(debug_type::COFF);
        CHECK(all_coff.size() == 1);

        auto all_fpo = debug->find_all_type(debug_type::FPO);
        CHECK(all_fpo.empty());
    }

    SUBCASE("Has type") {
        CHECK(debug->has_type(debug_type::COFF));
        CHECK(debug->has_type(debug_type::CODEVIEW));
        CHECK_FALSE(debug->has_type(debug_type::FPO));
        CHECK_FALSE(debug->has_type(debug_type::POGO));
    }
}

TEST_CASE("Debug parser - Debug type names") {
    SUBCASE("All type names") {
        debug_entry entry;

        entry.type = debug_type::UNKNOWN;
        CHECK(entry.type_name() == "Unknown");

        entry.type = debug_type::COFF;
        CHECK(entry.type_name() == "COFF");

        entry.type = debug_type::CODEVIEW;
        CHECK(entry.type_name() == "CodeView");

        entry.type = debug_type::FPO;
        CHECK(entry.type_name() == "FPO");

        entry.type = debug_type::MISC;
        CHECK(entry.type_name() == "MISC");

        entry.type = debug_type::EXCEPTION;
        CHECK(entry.type_name() == "Exception");

        entry.type = debug_type::FIXUP;
        CHECK(entry.type_name() == "Fixup");

        entry.type = debug_type::OMAP_TO_SRC;
        CHECK(entry.type_name() == "OMAP to Source");

        entry.type = debug_type::OMAP_FROM_SRC;
        CHECK(entry.type_name() == "OMAP from Source");

        entry.type = debug_type::BORLAND;
        CHECK(entry.type_name() == "Borland");

        entry.type = debug_type::POGO;
        CHECK(entry.type_name() == "POGO");

        entry.type = debug_type::REPRO;
        CHECK(entry.type_name() == "Repro");

        entry.type = debug_type::EMBEDDED_PORTABLE_PDB;
        CHECK(entry.type_name() == "Embedded Portable PDB");

        entry.type = debug_type::PDBCHECKSUM;
        CHECK(entry.type_name() == "PDB Checksum");
    }
}

TEST_CASE("Debug parser - GUID formatting") {
    codeview_pdb70 pdb70;

    SUBCASE("Standard GUID") {
        pdb70.guid = {
            0x12, 0x34, 0x56, 0x78,
            0x9A, 0xBC,
            0xDE, 0xF0,
            0x11, 0x22,
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88
        };

        std::string guid = pdb70.guid_string();
        CHECK(guid == "78563412-BC9A-F0DE-1122-334455667788");
        CHECK(pdb70.is_valid());
    }

    SUBCASE("Zero GUID") {
        pdb70.guid = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        std::string guid = pdb70.guid_string();
        CHECK(guid == "00000000-0000-0000-0000-000000000000");
        CHECK_FALSE(pdb70.is_valid());
    }

    SUBCASE("All 0xFF GUID") {
        pdb70.guid = {
            0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF,
            0xFF, 0xFF,
            0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };

        std::string guid = pdb70.guid_string();
        CHECK(guid == "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF");
        CHECK(pdb70.is_valid());
    }
}

TEST_CASE("Debug parser - Edge cases") {
    SUBCASE("Empty debug directory") {
        debug_directory debug;

        CHECK(debug.empty());
        CHECK(debug.size() == 0);
        CHECK_FALSE(debug.has_codeview());
        CHECK_FALSE(debug.has_pdb());
        CHECK(debug.get_pdb_path() == "");

        auto missing = debug.find_type(debug_type::CODEVIEW);
        CHECK_FALSE(missing.has_value());
    }

    SUBCASE("Debug entry without PDB info") {
        debug_entry entry;
        entry.type = debug_type::CODEVIEW;

        CHECK(entry.is_codeview());
        CHECK_FALSE(entry.has_pdb70());
        CHECK_FALSE(entry.has_pdb20());
        CHECK(entry.get_pdb_path() == "");
    }

    SUBCASE("PDB 2.0 validity") {
        codeview_pdb20 pdb20;

        pdb20.signature = 0;
        CHECK_FALSE(pdb20.is_valid());

        pdb20.signature = 0x12345678;
        CHECK(pdb20.is_valid());
    }

    SUBCASE("Debug entry flags") {
        debug_entry entry;

        entry.size_of_data = 0;
        CHECK_FALSE(entry.has_data());

        entry.size_of_data = 100;
        CHECK(entry.has_data());

        entry.address_of_raw_data = 0;
        CHECK_FALSE(entry.is_mapped());

        entry.address_of_raw_data = 0x1000;
        CHECK(entry.is_mapped());
    }
}

TEST_CASE("Debug parser - Lazy parsing and caching") {
    auto data = create_test_pe32_with_debug();
    auto pe = pe_file::from_memory(data);

    // First access
    auto debug1 = pe.debug();
    REQUIRE(debug1 != nullptr);
    CHECK(debug1->size() == 1);

    // Second access (should return cached)
    auto debug2 = pe.debug();
    REQUIRE(debug2 != nullptr);
    CHECK(debug2.get() == debug1.get());  // Same pointer (cached)
}
