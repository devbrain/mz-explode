// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <doctest/doctest.h>
#include <libexe/pe_file.hpp>
#include <libexe/load_config_directory.hpp>
#include <libexe/parsers/load_config_directory_parser.hpp>
#include <vector>
#include <cstring>

using namespace libexe;

// =============================================================================
// Test Helpers
// =============================================================================

/**
 * Create minimal valid PE32 file with load config directory (Windows XP minimal)
 */
static std::vector<uint8_t> create_test_pe32_with_load_config_xp() {
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

    // Data Directory - LOAD_CONFIG (index 10)
    uint32_t load_config_rva = 0x3000;
    uint32_t load_config_size = 64;  // Windows XP size
    std::memcpy(&data[pe_offset + 24 + 96 + 10 * 8], &load_config_rva, 4);
    std::memcpy(&data[pe_offset + 24 + 96 + 10 * 8 + 4], &load_config_size, 4);

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

    // IMAGE_LOAD_CONFIG_DIRECTORY32 (Windows XP - 64 bytes)
    uint32_t lc_offset = 0x400;

    uint32_t size = 64;
    std::memcpy(&data[lc_offset], &size, 4);
    uint32_t timestamp = 0x61234567;
    std::memcpy(&data[lc_offset + 4], &timestamp, 4);
    uint16_t major_ver = 5;
    std::memcpy(&data[lc_offset + 8], &major_ver, 2);
    uint16_t minor_ver = 1;
    std::memcpy(&data[lc_offset + 10], &minor_ver, 2);

    // Security cookie
    uint32_t security_cookie = 0x00403000;
    std::memcpy(&data[lc_offset + 60], &security_cookie, 4);

    return data;
}

/**
 * Create PE32 file with Windows 8+ load config (includes CFG)
 */
static std::vector<uint8_t> create_test_pe32_with_cfg() {
    std::vector<uint8_t> data;
    data.resize(4096);

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

    // Data Directory - LOAD_CONFIG
    uint32_t load_config_rva = 0x3000;
    uint32_t load_config_size = 92;  // Windows 8 size (includes GuardFlags)
    std::memcpy(&data[pe_offset + 24 + 96 + 10 * 8], &load_config_rva, 4);
    std::memcpy(&data[pe_offset + 24 + 96 + 10 * 8 + 4], &load_config_size, 4);

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

    // IMAGE_LOAD_CONFIG_DIRECTORY32 (Windows 8 - 92 bytes)
    uint32_t lc_offset = 0x400;

    uint32_t size = 92;
    std::memcpy(&data[lc_offset], &size, 4);
    uint32_t timestamp = 0x62345678;
    std::memcpy(&data[lc_offset + 4], &timestamp, 4);
    uint16_t major_ver = 6;
    std::memcpy(&data[lc_offset + 8], &major_ver, 2);
    uint16_t minor_ver = 2;
    std::memcpy(&data[lc_offset + 10], &minor_ver, 2);

    // Security cookie
    uint32_t security_cookie = 0x00403000;
    std::memcpy(&data[lc_offset + 60], &security_cookie, 4);

    // SafeSEH
    uint32_t se_handler_table = 0x00404000;
    std::memcpy(&data[lc_offset + 64], &se_handler_table, 4);
    uint32_t se_handler_count = 10;
    std::memcpy(&data[lc_offset + 68], &se_handler_count, 4);

    // CFG function pointers
    uint32_t guard_cf_check = 0x00401000;
    std::memcpy(&data[lc_offset + 72], &guard_cf_check, 4);
    uint32_t guard_cf_dispatch = 0x00401010;
    std::memcpy(&data[lc_offset + 76], &guard_cf_dispatch, 4);
    uint32_t guard_cf_table = 0x00405000;
    std::memcpy(&data[lc_offset + 80], &guard_cf_table, 4);
    uint32_t guard_cf_count = 50;
    std::memcpy(&data[lc_offset + 84], &guard_cf_count, 4);

    // Guard flags (CFG enabled)
    uint32_t guard_flags = 0x00000100 | 0x00000400;  // CF_INSTRUMENTED | CF_FUNCTION_TABLE_PRESENT
    std::memcpy(&data[lc_offset + 88], &guard_flags, 4);

    return data;
}

/**
 * Create PE32+ file with load config
 */
static std::vector<uint8_t> create_test_pe64_with_load_config() {
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

    // Data Directory - LOAD_CONFIG
    uint32_t load_config_rva = 0x3000;
    uint32_t load_config_size = 148;  // Windows 8 x64 size
    std::memcpy(&data[pe_offset + 24 + 112 + 10 * 8], &load_config_rva, 4);
    std::memcpy(&data[pe_offset + 24 + 112 + 10 * 8 + 4], &load_config_size, 4);

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

    // IMAGE_LOAD_CONFIG_DIRECTORY64
    uint32_t lc_offset = 0x400;

    uint32_t size = 148;
    std::memcpy(&data[lc_offset], &size, 4);
    uint32_t timestamp = 0x63456789;
    std::memcpy(&data[lc_offset + 4], &timestamp, 4);
    uint16_t major_ver = 10;
    std::memcpy(&data[lc_offset + 8], &major_ver, 2);
    uint16_t minor_ver = 0;
    std::memcpy(&data[lc_offset + 10], &minor_ver, 2);

    // Security cookie (64-bit VA)
    uint64_t security_cookie = 0x0000000140003000ULL;
    std::memcpy(&data[lc_offset + 88], &security_cookie, 8);

    // CFG function pointers (64-bit VAs)
    uint64_t guard_cf_check = 0x0000000140001000ULL;
    std::memcpy(&data[lc_offset + 112], &guard_cf_check, 8);
    uint64_t guard_cf_dispatch = 0x0000000140001010ULL;
    std::memcpy(&data[lc_offset + 120], &guard_cf_dispatch, 8);
    uint64_t guard_cf_table = 0x0000000140005000ULL;
    std::memcpy(&data[lc_offset + 128], &guard_cf_table, 8);
    uint64_t guard_cf_count = 100;
    std::memcpy(&data[lc_offset + 136], &guard_cf_count, 8);

    // Guard flags (CFG + XFG enabled)
    uint32_t guard_flags = 0x00000100 | 0x00000400 | 0x00800000;  // CF_INSTRUMENTED | CF_FUNCTION_TABLE_PRESENT | XFG_ENABLED
    std::memcpy(&data[lc_offset + 144], &guard_flags, 4);

    return data;
}

// =============================================================================
// Test Cases
// =============================================================================

TEST_CASE("Load config parser - pe_file accessor methods") {
    SUBCASE("PE32 file with load config directory") {
        auto data = create_test_pe32_with_load_config_xp();
        auto pe = pe_file::from_memory(data);

        CHECK(pe.has_data_directory(directory_entry::LOAD_CONFIG));
        CHECK(pe.data_directory_rva(directory_entry::LOAD_CONFIG) == 0x3000);
        CHECK(pe.data_directory_size(directory_entry::LOAD_CONFIG) == 64);

        auto lc = pe.load_config();
        REQUIRE(lc != nullptr);
        CHECK_FALSE(lc->is_empty());
    }

    SUBCASE("PE file without load config directory") {
        auto data = create_test_pe32_with_load_config_xp();

        // Zero out load config data directory
        uint32_t pe_offset = 0x80;
        uint32_t zero = 0;
        std::memcpy(&data[pe_offset + 24 + 96 + 10 * 8], &zero, 4);
        std::memcpy(&data[pe_offset + 24 + 96 + 10 * 8 + 4], &zero, 4);

        auto pe = pe_file::from_memory(data);

        CHECK_FALSE(pe.has_data_directory(directory_entry::LOAD_CONFIG));

        auto lc = pe.load_config();
        REQUIRE(lc != nullptr);
        CHECK(lc->is_empty());
        CHECK(lc->size == 0);
    }
}

TEST_CASE("Load config parser - Windows XP minimal (32-bit)") {
    auto data = create_test_pe32_with_load_config_xp();
    auto pe = pe_file::from_memory(data);
    auto lc = pe.load_config();

    REQUIRE(lc != nullptr);

    SUBCASE("Basic fields") {
        CHECK(lc->size == 64);
        CHECK(lc->time_date_stamp == 0x61234567);
        CHECK(lc->major_version == 5);
        CHECK(lc->minor_version == 1);
    }

    SUBCASE("Security cookie") {
        CHECK(lc->security_cookie == 0x00403000);
        CHECK(lc->has_security_cookie());
    }

    SUBCASE("No CFG (Windows XP)") {
        CHECK_FALSE(lc->has_cfg());
        CHECK_FALSE(lc->has_cfg_function_table());
        CHECK_FALSE(lc->has_xfg());
        CHECK_FALSE(lc->has_cast_guard());
    }

    SUBCASE("No SafeSEH in minimal structure") {
        // SafeSEH fields are at offset 60, structure is only 64 bytes
        // So they may be zero
        CHECK_FALSE(lc->has_safe_seh());
    }
}

TEST_CASE("Load config parser - Windows 8+ with CFG (32-bit)") {
    auto data = create_test_pe32_with_cfg();
    auto pe = pe_file::from_memory(data);
    auto lc = pe.load_config();

    REQUIRE(lc != nullptr);

    SUBCASE("Structure size") {
        CHECK(lc->size == 92);
        CHECK(lc->major_version == 6);
        CHECK(lc->minor_version == 2);
    }

    SUBCASE("Security cookie") {
        CHECK(lc->security_cookie == 0x00403000);
        CHECK(lc->has_security_cookie());
    }

    SUBCASE("SafeSEH (32-bit only)") {
        CHECK(lc->se_handler_table == 0x00404000);
        CHECK(lc->se_handler_count == 10);
        CHECK(lc->has_safe_seh());
    }

    SUBCASE("Control Flow Guard") {
        CHECK(lc->guard_cf_check_function_pointer == 0x00401000);
        CHECK(lc->guard_cf_dispatch_function_pointer == 0x00401010);
        CHECK(lc->guard_cf_function_table == 0x00405000);
        CHECK(lc->guard_cf_function_count == 50);

        CHECK(lc->has_cfg());
        CHECK(lc->has_cfg_function_table());
    }

    SUBCASE("Guard flags") {
        CHECK(lc->guard_flags == 0x00000500);  // CF_INSTRUMENTED | CF_FUNCTION_TABLE_PRESENT

        std::string flags_str = lc->guard_flags_string();
        CHECK(flags_str.find("CF_INSTRUMENTED") != std::string::npos);
        CHECK(flags_str.find("CF_FUNCTION_TABLE_PRESENT") != std::string::npos);
    }
}

TEST_CASE("Load config parser - PE32+ with CFG and XFG") {
    auto data = create_test_pe64_with_load_config();
    auto pe = pe_file::from_memory(data);
    auto lc = pe.load_config();

    REQUIRE(lc != nullptr);

    SUBCASE("Structure size") {
        CHECK(lc->size == 148);
        CHECK(lc->major_version == 10);
        CHECK(lc->minor_version == 0);
    }

    SUBCASE("Security cookie (64-bit)") {
        CHECK(lc->security_cookie == 0x0000000140003000ULL);
        CHECK(lc->has_security_cookie());
    }

    SUBCASE("Control Flow Guard (64-bit pointers)") {
        CHECK(lc->guard_cf_check_function_pointer == 0x0000000140001000ULL);
        CHECK(lc->guard_cf_dispatch_function_pointer == 0x0000000140001010ULL);
        CHECK(lc->guard_cf_function_table == 0x0000000140005000ULL);
        CHECK(lc->guard_cf_function_count == 100);

        CHECK(lc->has_cfg());
        CHECK(lc->has_cfg_function_table());
    }

    SUBCASE("XFG enabled") {
        CHECK(lc->has_xfg());

        std::string flags_str = lc->guard_flags_string();
        CHECK(flags_str.find("XFG_ENABLED") != std::string::npos);
    }
}

TEST_CASE("Load config parser - Guard flags decoding") {
    load_config_directory lc;

    SUBCASE("No flags") {
        lc.guard_flags = 0;
        CHECK(lc.guard_flags_string() == "None");
        CHECK_FALSE(lc.has_cfg());
        CHECK_FALSE(lc.has_xfg());
    }

    SUBCASE("CF_INSTRUMENTED") {
        lc.guard_flags = 0x00000100;
        CHECK(lc.has_cfg());
        CHECK(lc.guard_flags_string() == "CF_INSTRUMENTED");
    }

    SUBCASE("CFW_INSTRUMENTED") {
        lc.guard_flags = 0x00000200;
        CHECK(lc.guard_flags_string() == "CFW_INSTRUMENTED");
    }

    SUBCASE("CF_FUNCTION_TABLE_PRESENT") {
        lc.guard_flags = 0x00000400;
        CHECK(lc.guard_flags_string() == "CF_FUNCTION_TABLE_PRESENT");
    }

    SUBCASE("SECURITY_COOKIE_UNUSED") {
        lc.guard_flags = 0x00000800;
        CHECK(lc.has_cfg_export_suppression());
        CHECK(lc.guard_flags_string() == "SECURITY_COOKIE_UNUSED");
    }

    SUBCASE("PROTECT_DELAYLOAD_IAT") {
        lc.guard_flags = 0x00001000;
        CHECK(lc.has_cfg_longjmp());
        CHECK(lc.guard_flags_string() == "PROTECT_DELAYLOAD_IAT");
    }

    SUBCASE("CF_LONGJUMP_TABLE_PRESENT") {
        lc.guard_flags = 0x00010000;
        CHECK(lc.guard_flags_string() == "CF_LONGJUMP_TABLE_PRESENT");
    }

    SUBCASE("XFG_ENABLED") {
        lc.guard_flags = 0x00800000;
        CHECK(lc.has_xfg());
        CHECK(lc.guard_flags_string() == "XFG_ENABLED");
    }

    SUBCASE("CASTGUARD_PRESENT") {
        lc.guard_flags = 0x01000000;
        CHECK(lc.has_cast_guard());
        CHECK(lc.guard_flags_string() == "CASTGUARD_PRESENT");
    }

    SUBCASE("Multiple flags") {
        lc.guard_flags = 0x00000100 | 0x00000400 | 0x00800000;  // CF_INSTRUMENTED | CF_FUNCTION_TABLE_PRESENT | XFG_ENABLED

        std::string flags_str = lc.guard_flags_string();
        CHECK(flags_str.find("CF_INSTRUMENTED") != std::string::npos);
        CHECK(flags_str.find("CF_FUNCTION_TABLE_PRESENT") != std::string::npos);
        CHECK(flags_str.find("XFG_ENABLED") != std::string::npos);
        CHECK(flags_str.find(" | ") != std::string::npos);  // Flags separated
    }
}

TEST_CASE("Load config parser - Variable structure size handling") {
    SUBCASE("Windows XP size (64 bytes)") {
        auto data = create_test_pe32_with_load_config_xp();
        auto pe = pe_file::from_memory(data);
        auto lc = pe.load_config();

        CHECK(lc->size == 64);
        // Fields beyond 64 bytes should be zero (not read)
        CHECK(lc->guard_address_taken_iat_entry_table == 0);
        CHECK(lc->dynamic_value_reloc_table == 0);
    }

    SUBCASE("Windows 8 size (92 bytes)") {
        auto data = create_test_pe32_with_cfg();
        auto pe = pe_file::from_memory(data);
        auto lc = pe.load_config();

        CHECK(lc->size == 92);
        // CFG fields should be read (within 92 bytes)
        CHECK(lc->guard_cf_function_count == 50);
        // But extended fields should be zero
        CHECK(lc->guard_address_taken_iat_entry_table == 0);
    }
}

TEST_CASE("Load config parser - Security features detection") {
    load_config_directory lc;

    SUBCASE("Security cookie present") {
        lc.security_cookie = 0x00403000;
        CHECK(lc.has_security_cookie());
    }

    SUBCASE("Security cookie absent") {
        lc.security_cookie = 0;
        CHECK_FALSE(lc.has_security_cookie());
    }

    SUBCASE("SafeSEH present") {
        lc.se_handler_table = 0x00404000;
        lc.se_handler_count = 10;
        CHECK(lc.has_safe_seh());
    }

    SUBCASE("SafeSEH absent (no table)") {
        lc.se_handler_table = 0;
        lc.se_handler_count = 10;
        CHECK_FALSE(lc.has_safe_seh());
    }

    SUBCASE("SafeSEH absent (no handlers)") {
        lc.se_handler_table = 0x00404000;
        lc.se_handler_count = 0;
        CHECK_FALSE(lc.has_safe_seh());
    }

    SUBCASE("CFG function table present") {
        lc.guard_cf_function_table = 0x00405000;
        lc.guard_cf_function_count = 50;
        CHECK(lc.has_cfg_function_table());
    }

    SUBCASE("CFG function table absent") {
        lc.guard_cf_function_table = 0;
        lc.guard_cf_function_count = 0;
        CHECK_FALSE(lc.has_cfg_function_table());
    }
}

TEST_CASE("Load config parser - Edge cases") {
    SUBCASE("Empty load config") {
        load_config_directory lc;

        CHECK(lc.is_empty());
        CHECK(lc.size == 0);
        CHECK_FALSE(lc.has_security_cookie());
        CHECK_FALSE(lc.has_safe_seh());
        CHECK_FALSE(lc.has_cfg());
        CHECK_FALSE(lc.has_xfg());
        CHECK_FALSE(lc.has_cast_guard());
        CHECK(lc.guard_flags_string() == "None");
    }

    SUBCASE("Minimum size structures") {
        uint32_t min_32bit = load_config_directory::get_min_size_for_version(false, "XP");
        CHECK(min_32bit == 64);

        uint32_t min_64bit = load_config_directory::get_min_size_for_version(true, "XP");
        CHECK(min_64bit == 112);
    }

    SUBCASE("Version-specific sizes") {
        CHECK(load_config_directory::get_min_size_for_version(false, "Vista") == 72);
        CHECK(load_config_directory::get_min_size_for_version(false, "8") == 92);
        CHECK(load_config_directory::get_min_size_for_version(false, "10") == 148);

        CHECK(load_config_directory::get_min_size_for_version(true, "8") == 148);
        CHECK(load_config_directory::get_min_size_for_version(true, "10") == 256);
    }
}

TEST_CASE("Load config parser - Lazy parsing and caching") {
    auto data = create_test_pe32_with_cfg();
    auto pe = pe_file::from_memory(data);

    // First access
    auto lc1 = pe.load_config();
    REQUIRE(lc1 != nullptr);
    CHECK(lc1->size == 92);

    // Second access (should return cached)
    auto lc2 = pe.load_config();
    REQUIRE(lc2 != nullptr);
    CHECK(lc2.get() == lc1.get());  // Same pointer (cached)
}
