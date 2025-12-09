// libexe - Modern executable file analysis library
// NE parser tests for PROGMAN.EXE (Windows 3.11 Program Manager) with ground truth
//
// Ground truth for PROGMAN.EXE (115312 bytes):
//   - NE (16-bit Windows) executable
//   - Linker version: 5.20
//   - Target OS: Windows
//   - Expected Windows version: 3.10
//   - Segment count: 8 (7 code + 1 data)
//   - Module references: 5 (KERNEL, GDI, USER, KEYBOARD, SHELL)
//   - Resource types: 7 (GROUP_ICON, MENU, DIALOG, STRING, ACCELERATOR, VERSION, ICON)
//   - Total resources: 157
//   - Entry point: CS:IP = 1:0x299
//   - Stack: SS:SP = 8:0x0 (stack size 0x17D0 = 6096 bytes)
//   - Heap size: 0x200 (512 bytes)
//   - Flags: 0x0312 (MULTIPLEDATA)
//   - File alignment shift: 4 (16-byte alignment)

#include <libexe/formats/executable_factory.hpp>
#include <libexe/formats/mz_file.hpp>
#include <libexe/formats/ne_file.hpp>
#include <libexe/formats/pe_file.hpp>
#include <libexe/formats/le_file.hpp>
#include <libexe/ne/types.hpp>
#include <doctest/doctest.h>
#include <vector>

using namespace libexe;

// External test data (embedded PROGMAN.EXE from Windows 3.11)
namespace data {
    extern size_t progman_len;
    extern unsigned char progman[];
}

static std::vector<uint8_t> load_progman() {
    return std::vector<uint8_t>(
        data::progman,
        data::progman + data::progman_len
    );
}

// =============================================================================
// Basic File and Format Tests
// =============================================================================

TEST_CASE("PROGMAN - File size and format detection") {
    auto data = load_progman();
    REQUIRE(!data.empty());

    // Ground truth: PROGMAN.EXE is exactly 115312 bytes
    CHECK(data.size() == 115312);

    // Ground truth: NE format (Windows 16-bit)
    auto format = executable_factory::detect_format(data);
    CHECK(format == format_type::NE_WIN16);
}

TEST_CASE("PROGMAN - Factory loads as NE file") {
    auto data = load_progman();
    REQUIRE(!data.empty());

    auto executable = executable_factory::load(data);
    CHECK(std::holds_alternative<ne_file>(executable));

    auto& ne = std::get<ne_file>(executable);
    CHECK(ne.get_format() == format_type::NE_WIN16);
    CHECK(ne.format_name() == "NE (Windows 16-bit)");
}

// =============================================================================
// NE Header Tests - Ground Truth from binary analysis
// =============================================================================

TEST_CASE("PROGMAN - NE header") {
    auto data = load_progman();
    REQUIRE(!data.empty());

    auto ne = ne_file::from_memory(data);

    // Ground truth: Linker version 5.20
    CHECK(ne.linker_version() == 5);
    CHECK(ne.linker_revision() == 20);

    // Ground truth: Target OS = Windows (2)
    CHECK(ne.target_os() == ne_target_os::WINDOWS);

    // Ground truth: Flags = 0x0312
    // Bit 1: MULTIPLEDATA (DGROUP type = 2)
    // No LIBRARY_MODULE flag (this is an EXE, not DLL)
    auto flags = ne.flags();
    CHECK_FALSE(has_flag(flags, ne_file_flags::LIBRARY_MODULE));

    // Ground truth: File alignment shift = 4 (sector size = 16 bytes)
    CHECK(ne.alignment_shift() == 4);
}

TEST_CASE("PROGMAN - Entry point") {
    auto data = load_progman();
    REQUIRE(!data.empty());

    auto ne = ne_file::from_memory(data);

    // Ground truth: CS:IP = 0x00010299
    // CS = 1 (segment 1, the first code segment)
    // IP = 0x299 (665)
    CHECK(ne.entry_cs() == 1);
    CHECK(ne.entry_ip() == 0x299);
}

TEST_CASE("PROGMAN - Initial stack") {
    auto data = load_progman();
    REQUIRE(!data.empty());

    auto ne = ne_file::from_memory(data);

    // Ground truth: SS:SP = 0x00080000
    // SS = 8 (segment 8, the data segment)
    // SP = 0 (stack grows down from top of stack allocation)
    CHECK(ne.initial_ss() == 8);
    CHECK(ne.initial_sp() == 0);
}

// =============================================================================
// Segment Table Tests - Ground Truth from binary analysis
// =============================================================================

TEST_CASE("PROGMAN - Segment count") {
    auto data = load_progman();
    REQUIRE(!data.empty());

    auto ne = ne_file::from_memory(data);

    // Ground truth: 8 segments
    CHECK(ne.segment_count() == 8);

    auto segments = ne.segments();
    REQUIRE(segments.size() == 8);
}

TEST_CASE("PROGMAN - Segment details") {
    auto data = load_progman();
    REQUIRE(!data.empty());

    auto ne = ne_file::from_memory(data);
    auto segments = ne.segments();
    REQUIRE(segments.size() == 8);

    // Ground truth: Segment 1 - CODE MOVABLE PRELOAD DISCARDABLE
    // offset=0x00E20, length=0x02F9 (761 bytes)
    CHECK(segments[0].file_offset == 0x0E20);
    CHECK(segments[0].file_size == 0x02F9);
    CHECK(segments[0].is_code());
    CHECK(segments[0].is_moveable());
    CHECK(segments[0].is_preload());
    CHECK(segments[0].is_discardable());

    // Ground truth: Segment 2 - CODE MOVABLE PRELOAD DISCARDABLE
    // offset=0x011E0, length=0x29FF (10751 bytes)
    CHECK(segments[1].file_offset == 0x11E0);
    CHECK(segments[1].file_size == 0x29FF);
    CHECK(segments[1].is_code());

    // Ground truth: Segment 3 - CODE MOVABLE PRELOAD DISCARDABLE
    // offset=0x03F60, length=0x0EF1 (3825 bytes)
    CHECK(segments[2].file_offset == 0x3F60);
    CHECK(segments[2].file_size == 0x0EF1);
    CHECK(segments[2].is_code());

    // Ground truth: Segment 4 - CODE MOVABLE PRELOAD DISCARDABLE
    // offset=0x05040, length=0x2B6D (11117 bytes)
    CHECK(segments[3].file_offset == 0x5040);
    CHECK(segments[3].file_size == 0x2B6D);
    CHECK(segments[3].is_code());

    // Ground truth: Segment 5 - CODE MOVABLE PRELOAD DISCARDABLE
    // offset=0x07DA0, length=0x0CFC (3324 bytes)
    CHECK(segments[4].file_offset == 0x7DA0);
    CHECK(segments[4].file_size == 0x0CFC);
    CHECK(segments[4].is_code());

    // Ground truth: Segment 6 - CODE MOVABLE PRELOAD DISCARDABLE
    // offset=0x08C00, length=0x2FE3 (12259 bytes)
    CHECK(segments[5].file_offset == 0x8C00);
    CHECK(segments[5].file_size == 0x2FE3);
    CHECK(segments[5].is_code());

    // Ground truth: Segment 7 - CODE MOVABLE LOADONCALL DISCARDABLE
    // offset=0x0EE20, length=0x157A (5498 bytes)
    CHECK(segments[6].file_offset == 0xEE20);
    CHECK(segments[6].file_size == 0x157A);
    CHECK(segments[6].is_code());
    CHECK_FALSE(segments[6].is_preload());  // LOADONCALL, not PRELOAD

    // Ground truth: Segment 8 - DATA MOVABLE PRELOAD
    // offset=0x0BF20, length=0x08A3 (2211 bytes)
    CHECK(segments[7].file_offset == 0xBF20);
    CHECK(segments[7].file_size == 0x08A3);
    CHECK(segments[7].is_data());
    CHECK(segments[7].is_moveable());
    CHECK(segments[7].is_preload());
    CHECK_FALSE(segments[7].is_discardable());
}

TEST_CASE("PROGMAN - Code segment extraction") {
    auto data = load_progman();
    REQUIRE(!data.empty());

    auto ne = ne_file::from_memory(data);

    // Should find a code segment (first code segment)
    auto code_seg = ne.get_code_segment();
    REQUIRE(code_seg.has_value());
    CHECK(code_seg->is_code());

    // Ground truth: First code segment is 761 bytes
    CHECK(code_seg->file_size == 0x02F9);

    // code_section() returns first code segment data
    auto code = ne.code_section();
    CHECK(code.size() == 0x02F9);
}

// =============================================================================
// Module Reference Tests - Ground Truth from binary analysis
// =============================================================================

TEST_CASE("PROGMAN - Module count") {
    auto data = load_progman();
    REQUIRE(!data.empty());

    auto ne = ne_file::from_memory(data);

    // Ground truth: 5 imported modules (KERNEL, GDI, USER, KEYBOARD, SHELL)
    CHECK(ne.module_count() == 5);
}

// =============================================================================
// Table Offset Tests - Ground Truth from binary analysis
// =============================================================================

TEST_CASE("PROGMAN - Table offsets") {
    auto data = load_progman();
    REQUIRE(!data.empty());

    auto ne = ne_file::from_memory(data);

    // Ground truth: All offsets are relative to NE header at 0x400
    // Segment table at offset 0x40
    CHECK(ne.segment_table_offset() == 0x40);

    // Resource table at offset 0x80
    CHECK(ne.resource_table_offset() == 0x80);

    // Resident name table at offset 0x83E
    CHECK(ne.resident_name_table_offset() == 0x83E);

    // Module reference table at offset 0x849
    CHECK(ne.module_ref_table_offset() == 0x849);

    // Imported name table at offset 0x853
    CHECK(ne.import_name_table_offset() == 0x853);

    // Non-resident name table at absolute offset 0xCDA
    CHECK(ne.nonresident_name_table_offset() == 0xCDA);
}

// =============================================================================
// Resource Tests - Ground Truth from binary analysis
// =============================================================================

TEST_CASE("PROGMAN - Resource overview") {
    auto data = load_progman();
    REQUIRE(!data.empty());

    auto ne = ne_file::from_memory(data);

    // Ground truth: Has resources (GUI application)
    CHECK(ne.has_resources());

    // Resource table offset should be non-zero
    CHECK(ne.resource_table_offset() > 0);
}
