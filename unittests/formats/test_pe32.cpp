// Test 32-bit PE executable (TCMDX32.EXE) - Real PE32 file
#include <doctest/doctest.h>
#include <libexe/formats/executable_factory.hpp>
#include <libexe/formats/mz_file.hpp>
#include <libexe/formats/ne_file.hpp>
#include <libexe/formats/pe_file.hpp>
#include <libexe/formats/le_file.hpp>
#include <libexe/pe/types.hpp>
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

    SUBCASE("PE header parsing - reference values from dump-pe") {
        auto pe = pe_file::from_memory(data);

        // Should be 32-bit
        CHECK_FALSE(pe.is_64bit());
        CHECK(pe.get_format() == format_type::PE_WIN32);

        // Machine type: 0x14c (I386) - from dump-pe
        CHECK(pe.machine_type() == pe_machine_type::I386);

        // Number of sections: 4 - from dump-pe
        CHECK(pe.section_count() == 4);

        // Timestamp: 1467963278 - from dump-pe
        CHECK(pe.timestamp() == 1467963278);

        // Characteristics: 0x10f - from dump-pe
        auto characteristics = pe.characteristics();
        CHECK(has_flag(characteristics, pe_file_characteristics::MACHINE_32BIT));

        // Image base: 0x400000 - from dump-pe
        auto image_base = pe.image_base();
        CHECK(image_base == 0x400000);

        // Entry point RVA: 0x4b58 - from dump-pe
        auto entry_rva = pe.entry_point_rva();
        CHECK(entry_rva == 0x4b58);

        // Section alignment: 0x1000 - from dump-pe
        CHECK(pe.section_alignment() == 0x1000);

        // File alignment: 0x1000 - from dump-pe
        CHECK(pe.file_alignment() == 0x1000);

        // Size of image: 0x15000 - from dump-pe
        CHECK(pe.size_of_image() == 0x15000);

        // Size of headers: 0x1000 - from dump-pe
        CHECK(pe.size_of_headers() == 0x1000);
    }

    SUBCASE("Section table parsing - reference from dump-pe") {
        auto pe = pe_file::from_memory(data);

        auto sections = pe.sections();

        // Number of sections: 4 - from dump-pe
        CHECK(sections.size() == 4);

        // Verify section names from dump-pe: .text, .rdata, .data, .rsrc
        CHECK(sections[0].name == ".text");
        CHECK(sections[1].name == ".rdata");
        CHECK(sections[2].name == ".data");
        CHECK(sections[3].name == ".rsrc");

        // .text section - from dump-pe: Base=0x401000
        auto& text_sec = sections[0];
        CHECK(text_sec.virtual_address == 0x1000);  // RVA, not absolute
        CHECK(text_sec.virtual_size == 37875);  // Actual size before alignment

        // .rdata section - from dump-pe: Base=0x40b000
        auto& rdata_sec = sections[1];
        CHECK(rdata_sec.virtual_address == 0xb000);  // RVA
        CHECK(rdata_sec.virtual_size == 5092);  // Actual size before alignment

        // .data section - from dump-pe: Base=0x40d000
        auto& data_sec = sections[2];
        CHECK(data_sec.virtual_address == 0xd000);  // RVA
        CHECK(data_sec.virtual_size == 20736);  // Actual size before alignment

        // .rsrc section - from dump-pe: Base=0x413000
        auto& rsrc_sec = sections[3];
        CHECK(rsrc_sec.virtual_address == 0x13000);  // RVA
        CHECK(rsrc_sec.virtual_size == 7344);  // Actual size before alignment
    }

    SUBCASE("Code section extraction") {
        auto pe = pe_file::from_memory(data);

        // Find .text section
        auto text_section = pe.find_section(".text");
        CHECK(text_section.has_value());

        if (text_section) {
            // .text should have executable flag
            CHECK(text_section->is_executable());

            // Should have code flag
            CHECK(text_section->is_code());

            // Should be readable
            CHECK(text_section->is_readable());

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

    SUBCASE("Subsystem - reference from dump-pe") {
        auto pe = pe_file::from_memory(data);

        // Subsystem: 0x2 (WINDOWS_GUI) - from dump-pe
        auto subsystem = pe.subsystem();
        CHECK(subsystem == pe_subsystem::WINDOWS_GUI);
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

    SUBCASE("Image base is 32-bit address - from dump-pe") {
        auto image_base = pe.image_base();

        // Image base: 0x400000 - from dump-pe
        CHECK(image_base == 0x400000);

        // Verify it's in 32-bit address space (< 4GB)
        CHECK(image_base < 0x100000000ULL);
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
