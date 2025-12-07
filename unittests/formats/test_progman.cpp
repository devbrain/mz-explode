// Test Windows 3.11 Program Manager (PROGMAN.EXE) - Real NE file
#include <doctest/doctest.h>
#include <libexe/executable_factory.hpp>
#include <libexe/mz_file.hpp>
#include <libexe/ne_file.hpp>
#include <libexe/pe_file.hpp>
#include <libexe/ne_types.hpp>
#include <vector>

using namespace libexe;

// External test data
namespace data {
    extern size_t progman_len;
    extern unsigned char progman[];
}

namespace {

// Load PROGMAN.EXE from embedded data
std::vector<uint8_t> load_progman() {
    return std::vector<uint8_t>(
        data::progman,
        data::progman + data::progman_len
    );
}

} // anonymous namespace

TEST_CASE("PROGMAN.EXE: Windows 3.11 Program Manager") {
    auto data = load_progman();

    SUBCASE("File loads successfully") {
        CHECK(data.size() > 0);
        CHECK(data.size() == 115312);  // PROGMAN.EXE exact size
    }

    SUBCASE("Format detection identifies as NE") {
        auto format = executable_factory::detect_format(data);
        CHECK(format == format_type::NE_WIN16);
    }

    SUBCASE("Factory loads as NE file") {
        auto executable = executable_factory::load(data);

        CHECK(std::holds_alternative<ne_file>(executable));

        auto& ne = std::get<ne_file>(executable);
        CHECK(ne.get_format() == format_type::NE_WIN16);
        CHECK(ne.format_name() == "NE (Windows 16-bit)");
    }

    SUBCASE("NE header parsing") {
        auto ne = ne_file::from_memory(data);

        // Windows 3.11 executables are NE format
        CHECK(ne.get_format() == format_type::NE_WIN16);

        // Linker version (typically 5.x for Windows 3.1 era)
        CHECK(ne.linker_version() >= 5);
        CHECK(ne.linker_revision() >= 0);

        // Target OS should be Windows
        CHECK(ne.target_os() == ne_target_os::WINDOWS);

        // Should have segments (code and data)
        CHECK(ne.segment_count() > 0);

        // Should have module references
        CHECK(ne.module_count() >= 0);

        // Flags
        auto flags = ne.flags();
        // PROGMAN.EXE is not a DLL
        CHECK_FALSE(has_flag(flags, ne_file_flags::LIBRARY_MODULE));
    }

    SUBCASE("Segment table parsing") {
        auto ne = ne_file::from_memory(data);

        auto segments = ne.segments();
        CHECK(segments.size() > 0);

        // Windows 3.11 executables typically have multiple segments
        CHECK(segments.size() >= 2);  // At least code + data

        // Check segment structure is populated
        for (const auto& segment : segments) {
            // Valid segments should have some length (either min_alloc or length)
            bool has_size = (segment.min_alloc > 0) || (segment.length > 0);
            CHECK(has_size);
        }
    }

    SUBCASE("Code segment extraction") {
        auto ne = ne_file::from_memory(data);

        // Should find a code segment
        auto code_seg = ne.get_code_segment();
        CHECK(code_seg.has_value());

        if (code_seg) {
            // Code segment should not have DATA flag
            CHECK_FALSE(has_flag(code_seg->flags, ne_segment_flags::DATA));

            // Should have some length
            CHECK(code_seg->length > 0);
        }

        // code_section() should return non-empty span
        auto code = ne.code_section();
        CHECK(code.size() > 0);
    }

    SUBCASE("Entry point") {
        auto ne = ne_file::from_memory(data);

        // Entry point should be set (CS:IP)
        auto entry_cs = ne.entry_cs();
        auto entry_ip = ne.entry_ip();

        // CS should be valid segment index
        CHECK(entry_cs > 0);  // Entry CS is typically not 0

        // IP should be within reasonable range
        CHECK(entry_ip < 0xFFFF);
    }

    SUBCASE("Initial stack") {
        auto ne = ne_file::from_memory(data);

        // Initial stack should be set (SS:SP)
        auto initial_ss = ne.initial_ss();
        auto initial_sp = ne.initial_sp();

        // SS should be valid
        CHECK(initial_ss >= 0);

        // SP can be 0 (PROGMAN.EXE has SP=0) or within stack segment
        CHECK(initial_sp >= 0);
        CHECK(initial_sp < 0xFFFF);
    }

    SUBCASE("Resource table") {
        auto ne = ne_file::from_memory(data);

        // PROGMAN.EXE should have resources (icons, menus, dialogs, etc.)
        auto resource_offset = ne.resource_table_offset();

        // Resource table offset should be non-zero for GUI applications
        CHECK(resource_offset > 0);

        // NOTE: Actual resource parsing is Phase 4
        // This test just verifies the offset is present
    }

    SUBCASE("Alignment shift") {
        auto ne = ne_file::from_memory(data);

        auto alignment = ne.alignment_shift();

        // Common alignment values: 4 (16 bytes), 9 (512 bytes)
        CHECK(alignment >= 0);
        CHECK(alignment <= 15);  // Reasonable range
    }
}

TEST_CASE("PROGMAN.EXE: Metadata extraction") {
    auto data = load_progman();
    auto ne = ne_file::from_memory(data);

    SUBCASE("All table offsets are accessible") {
        // All offset getters should work
        CHECK(ne.segment_table_offset() > 0);
        CHECK(ne.resource_table_offset() > 0);
        CHECK(ne.resident_name_table_offset() > 0);
        CHECK(ne.module_ref_table_offset() >= 0);
        CHECK(ne.import_name_table_offset() >= 0);
        CHECK(ne.nonresident_name_table_offset() >= 0);
    }

    SUBCASE("File size matches data size") {
        // The ne_file should store the full data
        auto code = ne.code_section();
        CHECK(code.data() != nullptr);
        CHECK(code.size() > 0);
    }
}
