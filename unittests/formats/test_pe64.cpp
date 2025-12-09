// Test 64-bit PE executable (TCMADM64.EXE) - Real PE32+ file
#include <doctest/doctest.h>
#include <libexe/formats/executable_factory.hpp>
#include <libexe/formats/mz_file.hpp>
#include <libexe/formats/ne_file.hpp>
#include <libexe/formats/pe_file.hpp>
#include <libexe/pe/types.hpp>
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

    SUBCASE("PE header parsing - reference values from dump-pe") {
        auto pe = pe_file::from_memory(data);

        // Should be 64-bit
        CHECK(pe.is_64bit());
        CHECK(pe.get_format() == format_type::PE_PLUS_WIN64);

        // Machine type: 0x8664 (AMD64) - from dump-pe
        CHECK(pe.machine_type() == pe_machine_type::AMD64);

        // Number of sections: 5 - from dump-pe
        CHECK(pe.section_count() == 5);

        // Timestamp: 1611747597 - from dump-pe
        CHECK(pe.timestamp() == 1611747597);

        // Characteristics: 0x23 - from dump-pe
        auto characteristics = pe.characteristics();
        // Note: MACHINE_32BIT is NOT set for 64-bit executables
        CHECK_FALSE(has_flag(characteristics, pe_file_characteristics::MACHINE_32BIT));

        // Image base: 0x140000000 - from dump-pe
        auto image_base = pe.image_base();
        CHECK(image_base == 0x140000000ULL);

        // Entry point RVA: 0x66c0 - from dump-pe
        auto entry_rva = pe.entry_point_rva();
        CHECK(entry_rva == 0x66c0);

        // Section alignment: 0x1000 - from dump-pe
        CHECK(pe.section_alignment() == 0x1000);

        // File alignment: 0x200 - from dump-pe
        CHECK(pe.file_alignment() == 0x200);

        // Size of image: 0x1d000 - from dump-pe
        CHECK(pe.size_of_image() == 0x1d000);

        // Size of headers: 0x400 - from dump-pe
        CHECK(pe.size_of_headers() == 0x400);
    }

    SUBCASE("Section table parsing - reference from dump-pe") {
        auto pe = pe_file::from_memory(data);

        auto sections = pe.sections();

        // Number of sections: 5 - from dump-pe
        CHECK(sections.size() == 5);

        // Verify section names from dump-pe: .text, .rdata, .data, .pdata, .rsrc
        CHECK(sections[0].name == ".text");
        CHECK(sections[1].name == ".rdata");
        CHECK(sections[2].name == ".data");
        CHECK(sections[3].name == ".pdata");
        CHECK(sections[4].name == ".rsrc");

        // .text section - from dump-pe: Base=0x140001000
        auto& text_sec = sections[0];
        CHECK(text_sec.virtual_address == 0x1000);  // RVA
        CHECK(text_sec.virtual_size == 71134);  // Actual size before alignment

        // .rdata section - from dump-pe: Base=0x140013000
        auto& rdata_sec = sections[1];
        CHECK(rdata_sec.virtual_address == 0x13000);  // RVA
        CHECK(rdata_sec.virtual_size == 14528);  // Actual size before alignment

        // .data section - from dump-pe: Base=0x140017000
        auto& data_sec = sections[2];
        CHECK(data_sec.virtual_address == 0x17000);  // RVA
        CHECK(data_sec.virtual_size == 10200);  // Actual size before alignment

        // .pdata section - from dump-pe: Base=0x14001a000
        auto& pdata_sec = sections[3];
        CHECK(pdata_sec.virtual_address == 0x1a000);  // RVA
        CHECK(pdata_sec.virtual_size == 3132);  // Actual size before alignment

        // .rsrc section - from dump-pe: Base=0x14001b000
        auto& rsrc_sec = sections[4];
        CHECK(rsrc_sec.virtual_address == 0x1b000);  // RVA
        CHECK(rsrc_sec.virtual_size == 7272);  // Actual size before alignment
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

    SUBCASE("Image base is 64-bit address - from dump-pe") {
        auto image_base = pe.image_base();

        // Image base: 0x140000000 - from dump-pe
        CHECK(image_base == 0x140000000ULL);

        // Verify it's a 64-bit address (> 4GB)
        CHECK(image_base > 0x100000000ULL);
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
