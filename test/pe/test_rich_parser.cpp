// libexe - Modern executable file analysis library
// Rich Header parser tests with ground truth from richprint
//
// Ground truth for scheduler.exe (from richprint tool):
//   - Machine: x32 (i386)
//   - Rich header entries (comp.id -> product_id:build_number count):
//     [0095:7809]  26x  - VS2008 MASM (0x95=149, build 30729)
//     [0084:521e]   6x  - VS2008 C++ compiler (0x84=132, build 21022)
//     [0083:7809] 162x  - VS2008 C compiler (0x83=131, build 30729)
//     [006d:c627]   3x  - VS2005 C compiler (0x6d=109, build 50727)
//     [007b:c627]  21x  - VS2005 Import library (0x7b=123, build 50727)
//     [0001:0000] 278x  - Unmarked (modern)
//     [0084:7809]  79x  - VS2008 C++ compiler (0x84=132, build 30729)
//     [0094:521e]   1x  - VS2008 Resource compiler (0x94=148, build 21022)
//     [0091:7809]   1x  - VS2008 Linker (0x91=145, build 30729)

#include <libexe/formats/pe_file.hpp>
#include <libexe/pe/rich_header.hpp>
#include <doctest/doctest.h>
#include <vector>

using namespace libexe;

// External test data (embedded scheduler.exe)
namespace data {
    extern size_t scheduler_len;
    extern unsigned char scheduler[];
}

static std::vector<uint8_t> load_scheduler() {
    return std::vector<uint8_t>(
        data::scheduler,
        data::scheduler + data::scheduler_len
    );
}

// =============================================================================
// Basic Rich Header Detection Tests
// =============================================================================

TEST_CASE("Rich header - scheduler.exe detection") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);

    // Ground truth: scheduler.exe has a Rich header
    CHECK(pe.has_rich_header());
}

TEST_CASE("Rich header - scheduler.exe parsing") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto rich = pe.rich();

    // Ground truth: Rich header must exist
    REQUIRE(rich.has_value());
    CHECK(rich->is_valid());

    // Ground truth: 9 entries from richprint output
    CHECK(rich->entry_count() == 9);
}

// =============================================================================
// Rich Header Entry Verification - Ground Truth from richprint
// =============================================================================

TEST_CASE("Rich header - scheduler.exe entry details") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto rich = pe.rich();
    REQUIRE(rich.has_value());

    const auto& entries = rich->entries;
    REQUIRE(entries.size() == 9);

    // Ground truth from richprint output:
    // @comp.id   id version count   description
    // 00957809   95  30729    26
    // 0084521e   84  21022     6
    // 00837809   83  30729   162
    // 006dc627   6d  50727     3
    // 007bc627   7b  50727    21
    // 00010000    1      0   278
    // 00847809   84  30729    79
    // 0094521e   94  21022     1
    // 00917809   91  30729     1

    // Entry 0: [0095:7809] 26x - VS2008 MASM
    CHECK(entries[0].product_id == 0x95);  // 149
    CHECK(entries[0].build_number == 30729);
    CHECK(entries[0].count == 26);

    // Entry 1: [0084:521e] 6x - VS2008 C++ compiler
    CHECK(entries[1].product_id == 0x84);  // 132
    CHECK(entries[1].build_number == 21022);
    CHECK(entries[1].count == 6);

    // Entry 2: [0083:7809] 162x - VS2008 C compiler
    CHECK(entries[2].product_id == 0x83);  // 131
    CHECK(entries[2].build_number == 30729);
    CHECK(entries[2].count == 162);

    // Entry 3: [006d:c627] 3x - VS2005 C compiler
    CHECK(entries[3].product_id == 0x6D);  // 109
    CHECK(entries[3].build_number == 50727);
    CHECK(entries[3].count == 3);

    // Entry 4: [007b:c627] 21x - VS2005 Import library
    CHECK(entries[4].product_id == 0x7B);  // 123
    CHECK(entries[4].build_number == 50727);
    CHECK(entries[4].count == 21);

    // Entry 5: [0001:0000] 278x - Unmarked (modern)
    CHECK(entries[5].product_id == 0x01);  // 1
    CHECK(entries[5].build_number == 0);
    CHECK(entries[5].count == 278);

    // Entry 6: [0084:7809] 79x - VS2008 C++ compiler
    CHECK(entries[6].product_id == 0x84);  // 132
    CHECK(entries[6].build_number == 30729);
    CHECK(entries[6].count == 79);

    // Entry 7: [0094:521e] 1x - VS2008 Resource compiler
    CHECK(entries[7].product_id == 0x94);  // 148
    CHECK(entries[7].build_number == 21022);
    CHECK(entries[7].count == 1);

    // Entry 8: [0091:7809] 1x - VS2008 Linker
    CHECK(entries[8].product_id == 0x91);  // 145
    CHECK(entries[8].build_number == 30729);
    CHECK(entries[8].count == 1);
}

// =============================================================================
// Component Type Classification Tests
// =============================================================================

TEST_CASE("Rich header - scheduler.exe component types") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto rich = pe.rich();
    REQUIRE(rich.has_value());

    const auto& entries = rich->entries;
    REQUIRE(entries.size() == 9);

    // Entry 0: MASM (0x95) - should be ASSEMBLER
    CHECK(entries[0].component_type() == rich_component_type::ASSEMBLER);

    // Entry 1: C++ compiler (0x84) - should be CPP_COMPILER
    CHECK(entries[1].component_type() == rich_component_type::CPP_COMPILER);

    // Entry 2: C compiler (0x83) - should be C_COMPILER
    CHECK(entries[2].component_type() == rich_component_type::C_COMPILER);

    // Entry 3: C compiler (0x6D) - should be C_COMPILER (VS2005)
    CHECK(entries[3].component_type() == rich_component_type::C_COMPILER);

    // Entry 4: Import library (0x7B) - should be IMPORT_LIB
    CHECK(entries[4].component_type() == rich_component_type::IMPORT_LIB);

    // Entry 5: Unmarked (0x01) - should be UNKNOWN
    CHECK(entries[5].component_type() == rich_component_type::UNKNOWN);

    // Entry 6: C++ compiler (0x84) - should be CPP_COMPILER
    CHECK(entries[6].component_type() == rich_component_type::CPP_COMPILER);

    // Entry 7: Resource compiler (0x94) - should be RESOURCE
    CHECK(entries[7].component_type() == rich_component_type::RESOURCE);

    // Entry 8: Linker (0x91) - should be LINKER
    CHECK(entries[8].component_type() == rich_component_type::LINKER);
}

// =============================================================================
// Helper Method Tests
// =============================================================================

TEST_CASE("Rich header - scheduler.exe helper methods") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto rich = pe.rich();
    REQUIRE(rich.has_value());

    // Test total_count()
    // Sum: 26 + 6 + 162 + 3 + 21 + 278 + 79 + 1 + 1 = 577
    CHECK(rich->total_count() == 577);

    // Test linker() - should find entry 8 (0x91, build 30729)
    auto linker = rich->linker();
    REQUIRE(linker != nullptr);
    CHECK(linker->product_id == 0x91);
    CHECK(linker->build_number == 30729);
    CHECK(linker->count == 1);

    // Test primary_compiler() - should be entry 2 (0x83, count 162)
    // Entry 2 has the highest count among compilers
    auto primary = rich->primary_compiler();
    REQUIRE(primary != nullptr);
    CHECK(primary->product_id == 0x83);  // C compiler with highest count
    CHECK(primary->count == 162);
}

// =============================================================================
// Visual Studio Version Detection Tests
// =============================================================================

TEST_CASE("Rich header - scheduler.exe VS version detection") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto rich = pe.rich();
    REQUIRE(rich.has_value());

    // Based on linker build number 30729, this is VS2008 SP1
    auto vs_version = rich->vs_major_version();
    REQUIRE(vs_version.has_value());
    CHECK(*vs_version == 2008);
}

// =============================================================================
// rich_entry Method Tests
// =============================================================================

TEST_CASE("Rich header - rich_entry methods") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto rich = pe.rich();
    REQUIRE(rich.has_value());

    const auto& entries = rich->entries;
    REQUIRE(!entries.empty());

    // Test comp_id() - entry 0: [0095:7809]
    CHECK(entries[0].comp_id() == 0x00957809);

    // Test is_compiler() - entry 1 is C++ compiler
    CHECK(entries[1].is_compiler());
    CHECK_FALSE(entries[0].is_compiler());  // MASM is not a compiler
    CHECK_FALSE(entries[8].is_compiler());  // Linker is not a compiler

    // Test is_linker() - entry 8 is linker
    CHECK(entries[8].is_linker());
    CHECK_FALSE(entries[0].is_linker());  // MASM is not linker
    CHECK_FALSE(entries[1].is_linker());  // Compiler is not linker
}

// =============================================================================
// VS Version String Tests
// =============================================================================

TEST_CASE("Rich header - VS version strings") {
    // Note: get_vs_version_for_build() only works reliably for VS2015+ build numbers.
    // Build numbers >= 23026 are assumed to be from VS2015+ toolchains.
    // For accurate version detection of older toolchains, use rich_header::vs_major_version()
    // which considers both product ID and build number.

    // Pre-VS2015 build numbers (< 23026) return empty
    CHECK(get_vs_version_for_build(21022) == "");  // Below VS2015 threshold
    CHECK(get_vs_version_for_build(6030) == "");   // VS2003 range
    CHECK(get_vs_version_for_build(9466) == "");   // VS2002 range

    // VS2015+ build numbers - these are reliable
    CHECK(get_vs_version_for_build(35719) == "VS2026");  // VS2026 Insiders
    CHECK(get_vs_version_for_build(30159) == "VS2022");
    CHECK(get_vs_version_for_build(27508) == "VS2019");
    CHECK(get_vs_version_for_build(25017) == "VS2017");
    CHECK(get_vs_version_for_build(23026) == "VS2015");

    // Edge case: build numbers that happen to be >= 23026 but from older VS
    // These would be misidentified if only build number is used
    // (30729 from VS2008 SP1 would be identified as VS2022)
    // This demonstrates why product ID is needed for accurate detection
    CHECK(get_vs_version_for_build(30729) == "VS2022");  // Actually VS2008 SP1, but >= 30159
    CHECK(get_vs_version_for_build(50727) == "VS2026");  // Actually VS2005/2012, but >= 35109
}

// =============================================================================
// Product Type Name Tests
// =============================================================================

TEST_CASE("Rich header - product type names") {
    // Test known product types
    CHECK(rich_product_type_name(rich_product_type::UTC_C_1500) == "VS2008 C compiler");
    CHECK(rich_product_type_name(rich_product_type::UTC_CPP_1500) == "VS2008 C++ compiler");
    CHECK(rich_product_type_name(rich_product_type::LINKER_900) == "VS2008 Linker");
    CHECK(rich_product_type_name(rich_product_type::MASM_900) == "VS2008 MASM");
    CHECK(rich_product_type_name(rich_product_type::CVTRES_900) == "VS2008 Resource compiler");

    // Test VS2015+ unified names
    CHECK(rich_product_type_name(rich_product_type::UTC_C_1900) == "VS2015+ C compiler");
    CHECK(rich_product_type_name(rich_product_type::LINKER_1400) == "VS2015+ Linker");
}
