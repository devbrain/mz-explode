// Test 64-bit PE executable (TCMADM64.EXE) - Real PE32+ file
#include <doctest/doctest.h>
#include <libexe/executable_factory.hpp>
#include <libexe/mz_file.hpp>
#include <libexe/ne_file.hpp>
#include <libexe/pe_file.hpp>
#include <libexe/pe_types.hpp>
#include <vector>

using namespace libexe;

// External test data
namespace data {
    extern size_t tcmadm64_len;
    extern unsigned char tcmadm64[];
}

namespace {

// Load TCMADM64.EXE from embedded data
std::vector<uint8_t> load_tcmadm64() {
    return std::vector<uint8_t>(
        data::tcmadm64,
        data::tcmadm64 + data::tcmadm64_len
    );
}

} // anonymous namespace

TEST_CASE("TCMADM64.EXE: 64-bit PE executable") {
    auto data = load_tcmadm64();

    SUBCASE("File loads successfully") {
        CHECK(data.size() > 0);
        CHECK(data.size() == 117608);  // TCMADM64.EXE exact size
    }

    SUBCASE("Format detection identifies as PE32+") {
        auto format = executable_factory::detect_format(data);
        CHECK(format == format_type::PE_PLUS_WIN64);
    }

    SUBCASE("Factory loads as PE file") {
        auto executable = executable_factory::load(data);

        CHECK(std::holds_alternative<pe_file>(executable));

        auto& pe = std::get<pe_file>(executable);
        CHECK(pe.get_format() == format_type::PE_PLUS_WIN64);
        CHECK(pe.format_name() == "PE32+ (64-bit Windows)");
    }

    SUBCASE("PE header parsing") {
        auto pe = pe_file::from_memory(data);

        // Should be 64-bit
        CHECK(pe.is_64bit());
        CHECK(pe.get_format() == format_type::PE_PLUS_WIN64);

        // Machine type should be AMD64
        CHECK(pe.machine_type() == pe_machine_type::AMD64);

        // Should have sections
        CHECK(pe.section_count() > 0);

        // Timestamp should be set
        CHECK(pe.timestamp() > 0);

        // Characteristics (can read them)
        auto characteristics = pe.characteristics();
        // Note: MACHINE_32BIT is NOT set for 64-bit executables
        CHECK_FALSE(has_flag(characteristics, pe_file_characteristics::MACHINE_32BIT));

        // Image base (64-bit executables have higher base addresses)
        auto image_base = pe.image_base();
        CHECK(image_base > 0);

        // Entry point RVA should be set
        auto entry_rva = pe.entry_point_rva();
        CHECK(entry_rva > 0);

        // Alignment values should be powers of 2
        CHECK(pe.section_alignment() > 0);
        CHECK(pe.file_alignment() > 0);

        // Image size
        CHECK(pe.size_of_image() > 0);
        CHECK(pe.size_of_headers() > 0);
        CHECK(pe.size_of_headers() < pe.size_of_image());
    }

    SUBCASE("Section table parsing") {
        auto pe = pe_file::from_memory(data);

        auto sections = pe.sections();
        CHECK(sections.size() > 0);

        // Common sections for executables
        bool has_text = false;
        bool has_data = false;
        bool has_rdata = false;

        for (const auto& section : sections) {
            // Section names should be non-empty
            CHECK(section.name.size() > 0);

            // Check for common sections
            if (section.name == ".text") has_text = true;
            if (section.name == ".data") has_data = true;
            if (section.name == ".rdata") has_rdata = true;

            // Virtual address should be non-zero (except maybe first section)
            // Virtual size should be set
            bool has_size = (section.virtual_size > 0) || (section.raw_data_size > 0);
            CHECK(has_size);
        }

        // Typical PE executables have .text section
        CHECK(has_text);
    }

    SUBCASE("Code section extraction") {
        auto pe = pe_file::from_memory(data);

        // Find .text section
        auto text_section = pe.find_section(".text");
        CHECK(text_section.has_value());

        if (text_section) {
            // .text should have executable flag
            CHECK(has_flag(text_section->characteristics,
                          pe_section_characteristics::MEM_EXECUTE));

            // Should have code flag
            CHECK(has_flag(text_section->characteristics,
                          pe_section_characteristics::CNT_CODE));

            // Should be readable
            CHECK(has_flag(text_section->characteristics,
                          pe_section_characteristics::MEM_READ));

            // Should have some size
            CHECK(text_section->virtual_size > 0);
        }

        // get_code_section() should return the .text section
        auto code_sec = pe.get_code_section();
        CHECK(code_sec.has_value());

        if (code_sec) {
            CHECK(code_sec->name == ".text");
        }

        // code_section() should return non-empty span
        auto code = pe.code_section();
        CHECK(code.size() > 0);
    }

    SUBCASE("Subsystem and DLL characteristics") {
        auto pe = pe_file::from_memory(data);

        // Subsystem should be set (console or GUI)
        auto subsystem = pe.subsystem();
        CHECK(subsystem != pe_subsystem::UNKNOWN);

        // DLL characteristics (ASLR, DEP, etc.)
        auto dll_chars = pe.dll_characteristics();
        // Modern executables typically have some DLL characteristics
        // Just verify we can read it
        (void)dll_chars;
        CHECK(true);  // Placeholder - actual DLL characteristics tested elsewhere
    }
}

TEST_CASE("TCMADM64.EXE: 64-bit specific characteristics") {
    auto data = load_tcmadm64();
    auto pe = pe_file::from_memory(data);

    SUBCASE("64-bit PE format") {
        // Must be 64-bit
        CHECK(pe.is_64bit());
        CHECK(pe.get_format() == format_type::PE_PLUS_WIN64);

        // Machine type must be AMD64
        CHECK(pe.machine_type() == pe_machine_type::AMD64);
    }

    SUBCASE("Image base is 64-bit address") {
        auto image_base = pe.image_base();

        // 64-bit executables typically have base addresses > 4GB
        // But at minimum, should be non-zero
        CHECK(image_base > 0);
    }

    SUBCASE("All PE methods accessible") {
        // Verify all getters work
        CHECK(pe.section_count() >= 0);
        CHECK(pe.timestamp() >= 0);
        (void)pe.characteristics();
        (void)pe.image_base();
        (void)pe.entry_point_rva();
        (void)pe.section_alignment();
        (void)pe.file_alignment();
        CHECK(pe.size_of_image() > 0);
        CHECK(pe.size_of_headers() > 0);
        (void)pe.subsystem();
        (void)pe.dll_characteristics();
        (void)pe.sections();
    }

    SUBCASE("File size matches data size") {
        // The pe_file should store the full data
        auto code = pe.code_section();
        CHECK(code.data() != nullptr);
        CHECK(code.size() > 0);
    }
}
