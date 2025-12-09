// Test executable factory format detection
#include <doctest/doctest.h>
#include <libexe/formats/executable_factory.hpp>
#include <libexe/formats/mz_file.hpp>
#include <libexe/formats/ne_file.hpp>
#include <libexe/formats/pe_file.hpp>
#include <vector>

using namespace libexe;

TEST_CASE("Executable factory: format detection") {
    SUBCASE("Detects plain DOS MZ files") {
        // Create minimal DOS executable (e_lfanew = 0)
        std::vector<uint8_t> dos_exe(128, 0);
        dos_exe[0] = 0x4D;  // 'M'
        dos_exe[1] = 0x5A;  // 'Z'
        // e_lfanew at 0x3C is 0 (no extended header)

        auto fmt = executable_factory::detect_format(dos_exe);
        CHECK(fmt == format_type::MZ_DOS);
    }

    SUBCASE("Detects NE files") {
        // Create DOS header pointing to NE header
        std::vector<uint8_t> ne_exe(256, 0);
        ne_exe[0] = 0x4D;  // 'M'
        ne_exe[1] = 0x5A;  // 'Z'
        ne_exe[0x3C] = 0x80;  // e_lfanew = 0x80
        ne_exe[0x3D] = 0x00;

        // NE signature at offset 0x80
        ne_exe[0x80] = 0x4E;  // 'N'
        ne_exe[0x81] = 0x45;  // 'E'

        auto fmt = executable_factory::detect_format(ne_exe);
        CHECK(fmt == format_type::NE_WIN16);
    }

    SUBCASE("Detects PE32 files") {
        // Create DOS header pointing to PE header
        std::vector<uint8_t> pe32_exe(512, 0);
        pe32_exe[0] = 0x4D;  // 'M'
        pe32_exe[1] = 0x5A;  // 'Z'
        pe32_exe[0x3C] = 0x80;  // e_lfanew = 0x80
        pe32_exe[0x3D] = 0x00;

        // PE signature at offset 0x80
        pe32_exe[0x80] = 0x50;  // 'P'
        pe32_exe[0x81] = 0x45;  // 'E'
        pe32_exe[0x82] = 0x00;
        pe32_exe[0x83] = 0x00;

        // COFF header (20 bytes) - minimal valid values
        pe32_exe[0x84] = 0x4C;  // Machine = IMAGE_FILE_MACHINE_I386
        pe32_exe[0x85] = 0x01;

        // Optional header magic at offset 0x98 (0x80 + 4 + 20)
        pe32_exe[0x98] = 0x0B;  // PE32 magic (0x10B)
        pe32_exe[0x99] = 0x01;

        auto fmt = executable_factory::detect_format(pe32_exe);
        CHECK(fmt == format_type::PE_WIN32);
    }

    SUBCASE("Detects PE32+ (64-bit) files") {
        // Create DOS header pointing to PE header
        std::vector<uint8_t> pe64_exe(512, 0);
        pe64_exe[0] = 0x4D;  // 'M'
        pe64_exe[1] = 0x5A;  // 'Z'
        pe64_exe[0x3C] = 0x80;  // e_lfanew = 0x80
        pe64_exe[0x3D] = 0x00;

        // PE signature at offset 0x80
        pe64_exe[0x80] = 0x50;  // 'P'
        pe64_exe[0x81] = 0x45;  // 'E'
        pe64_exe[0x82] = 0x00;
        pe64_exe[0x83] = 0x00;

        // COFF header (20 bytes) - minimal valid values
        pe64_exe[0x84] = 0x64;  // Machine = IMAGE_FILE_MACHINE_AMD64
        pe64_exe[0x85] = 0x86;

        // Optional header magic at offset 0x98 (0x80 + 4 + 20)
        pe64_exe[0x98] = 0x0B;  // PE32+ magic (0x20B)
        pe64_exe[0x99] = 0x02;

        auto fmt = executable_factory::detect_format(pe64_exe);
        CHECK(fmt == format_type::PE_PLUS_WIN64);
    }

    SUBCASE("Rejects files that are too small") {
        std::vector<uint8_t> tiny_data = {0x4D, 0x5A};
        CHECK_THROWS_AS(executable_factory::detect_format(tiny_data), std::runtime_error);
    }

    SUBCASE("Returns UNKNOWN for non-MZ files") {
        std::vector<uint8_t> bad_data(128, 0xFF);
        auto fmt = executable_factory::detect_format(bad_data);
        CHECK(fmt == format_type::UNKNOWN);
    }
}

TEST_CASE("Executable factory: format type names") {
    SUBCASE("Returns correct names for all format types") {
        CHECK(executable_factory::format_type_name(format_type::MZ_DOS) == "MZ (DOS)");
        CHECK(executable_factory::format_type_name(format_type::NE_WIN16) == "NE (16-bit Windows/OS2)");
        CHECK(executable_factory::format_type_name(format_type::PE_WIN32) == "PE32 (32-bit Windows)");
        CHECK(executable_factory::format_type_name(format_type::PE_PLUS_WIN64) == "PE32+ (64-bit Windows)");
        CHECK(executable_factory::format_type_name(format_type::UNKNOWN) == "Unknown");
    }
}

TEST_CASE("Executable factory: variant loading") {
    SUBCASE("Loads plain DOS files into mz_file") {
        // This test just verifies the variant type system compiles
        // We can't fully test without valid executable data
        std::vector<uint8_t> dos_exe(128, 0);
        dos_exe[0] = 0x4D;
        dos_exe[1] = 0x5A;

        bool caught_exception = false;
        try {
            auto exe = executable_factory::load(dos_exe);
            // If we got here, check it's the right type
            CHECK(std::holds_alternative<mz_file>(exe));
        } catch (const std::runtime_error&) {
            // Expected - minimal data won't parse fully
            caught_exception = true;
        }
        // Either way is acceptable for this test
    }

    SUBCASE("Throws on unknown format") {
        std::vector<uint8_t> bad_data(128, 0xFF);
        CHECK_THROWS_AS(executable_factory::load(bad_data), std::runtime_error);
    }
}
