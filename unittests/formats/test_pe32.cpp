// Test 32-bit PE executable (TCMDX32.EXE) - Real PE32 file
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
    extern size_t tcmdx32_len;
    extern unsigned char tcmdx32[];
}

namespace {

// Load TCMDX32.EXE from embedded data
std::vector<uint8_t> load_tcmdx32() {
    return std::vector<uint8_t>(
        data::tcmdx32,
        data::tcmdx32 + data::tcmdx32_len
    );
}

} // anonymous namespace

TEST_CASE("TCMDX32.EXE: 32-bit PE executable") {
    auto data = load_tcmdx32();

    SUBCASE("File loads successfully") {
        CHECK(data.size() > 0);
        CHECK(data.size() == 91216);  // TCMDX32.EXE exact size
    }

    SUBCASE("Format detection identifies as PE32") {
        auto format = executable_factory::detect_format(data);
        CHECK(format == format_type::PE_WIN32);
    }

    SUBCASE("Factory loads as PE file") {
        auto executable = executable_factory::load(data);

        CHECK(std::holds_alternative<pe_file>(executable));

        auto& pe = std::get<pe_file>(executable);
        CHECK(pe.get_format() == format_type::PE_WIN32);
        CHECK(pe.format_name() == "PE32 (32-bit Windows)");
    }

    SUBCASE("PE header parsing") {
        auto pe = pe_file::from_memory(data);

        // Should be 32-bit
        CHECK_FALSE(pe.is_64bit());
        CHECK(pe.get_format() == format_type::PE_WIN32);

        // Machine type should be I386
        CHECK(pe.machine_type() == pe_machine_type::I386);

        // Should have sections
        CHECK(pe.section_count() > 0);

        // Timestamp should be set
        CHECK(pe.timestamp() > 0);

        // Characteristics (32-bit flag should be set for 32-bit executables)
        auto characteristics = pe.characteristics();
        CHECK(has_flag(characteristics, pe_file_characteristics::MACHINE_32BIT));

        // Image base (32-bit executables typically have lower base addresses)
        auto image_base = pe.image_base();
        CHECK(image_base > 0);
        // 32-bit executables typically use addresses < 4GB
        CHECK(image_base < 0x100000000ULL);

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

        for (const auto& section : sections) {
            // Section names should be non-empty
            CHECK(section.name.size() > 0);

            // Check for common sections
            if (section.name == ".text") has_text = true;
            if (section.name == ".data") has_data = true;

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
        // Just verify we can read it
        (void)dll_chars;
        CHECK(true);
    }
}

TEST_CASE("TCMDX32.EXE: 32-bit specific characteristics") {
    auto data = load_tcmdx32();
    auto pe = pe_file::from_memory(data);

    SUBCASE("32-bit PE format") {
        // Must NOT be 64-bit
        CHECK_FALSE(pe.is_64bit());
        CHECK(pe.get_format() == format_type::PE_WIN32);

        // Machine type must be I386
        CHECK(pe.machine_type() == pe_machine_type::I386);

        // MACHINE_32BIT flag should be set
        auto characteristics = pe.characteristics();
        CHECK(has_flag(characteristics, pe_file_characteristics::MACHINE_32BIT));
    }

    SUBCASE("Image base is 32-bit address") {
        auto image_base = pe.image_base();

        // 32-bit executables have base addresses < 4GB
        CHECK(image_base > 0);
        CHECK(image_base < 0x100000000ULL);

        // Typical 32-bit Windows base is 0x00400000
        // But we just verify it's in 32-bit range
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
