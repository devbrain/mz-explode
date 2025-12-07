// Test Windows 3.11 Font File (CGA40WOA.FON) - Real NE font resource
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
    extern size_t cga40woa_fon_len;
    extern unsigned char cga40woa_fon[];
}

namespace {

// Load CGA40WOA.FON from embedded data
std::vector<uint8_t> load_font() {
    return std::vector<uint8_t>(
        data::cga40woa_fon,
        data::cga40woa_fon + data::cga40woa_fon_len
    );
}

} // anonymous namespace

TEST_CASE("CGA40WOA.FON: Windows 3.11 Font File") {
    auto data = load_font();

    SUBCASE("File loads successfully") {
        CHECK(data.size() > 0);
        CHECK(data.size() == 6336);  // CGA40WOA.FON exact size
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

        // Font files are NE format
        CHECK(ne.get_format() == format_type::NE_WIN16);

        // Linker version
        CHECK(ne.linker_version() >= 0);
        CHECK(ne.linker_revision() >= 0);

        // Target OS should be Windows
        CHECK(ne.target_os() == ne_target_os::WINDOWS);

        // Font files may have fewer segments than executables
        CHECK(ne.segment_count() >= 0);

        // Module references
        CHECK(ne.module_count() >= 0);

        // Flags - font files have different flags than executables
        auto flags = ne.flags();
        // FON files are typically library modules (resources only)
        CHECK(has_flag(flags, ne_file_flags::LIBRARY_MODULE));
    }

    SUBCASE("Resource table") {
        auto ne = ne_file::from_memory(data);

        // Font files MUST have resources (fonts are stored as resources)
        auto resource_offset = ne.resource_table_offset();

        // Resource table offset must be non-zero for font files
        CHECK(resource_offset > 0);

        // NOTE: Actual resource parsing is Phase 4
        // This test verifies the offset is present
    }

    SUBCASE("Segment table") {
        auto ne = ne_file::from_memory(data);

        // Font files may have minimal or no code segments
        auto segments = ne.segments();
        // Just verify we can read the segment table (may be empty)
        CHECK(segments.size() >= 0);
    }

    SUBCASE("Alignment shift") {
        auto ne = ne_file::from_memory(data);

        auto alignment = ne.alignment_shift();

        // Common alignment values: 4 (16 bytes), 9 (512 bytes)
        CHECK(alignment >= 0);
        CHECK(alignment <= 15);  // Reasonable range
    }
}

TEST_CASE("CGA40WOA.FON: Font-specific characteristics") {
    auto data = load_font();
    auto ne = ne_file::from_memory(data);

    SUBCASE("Font files are library modules") {
        // Font files (.FON) are resource-only modules
        auto flags = ne.flags();
        CHECK(has_flag(flags, ne_file_flags::LIBRARY_MODULE));
    }

    SUBCASE("All table offsets are accessible") {
        // All offset getters should work
        CHECK(ne.segment_table_offset() >= 0);
        CHECK(ne.resource_table_offset() > 0);  // Must have resources
        CHECK(ne.resident_name_table_offset() >= 0);
        CHECK(ne.module_ref_table_offset() >= 0);
        CHECK(ne.import_name_table_offset() >= 0);
        CHECK(ne.nonresident_name_table_offset() >= 0);
    }

    SUBCASE("File is small (typical for font files)") {
        // Font files are typically small (< 50KB)
        CHECK(data.size() < 50000);
        CHECK(data.size() == 6336);  // Exact size for CGA40WOA.FON
    }
}
