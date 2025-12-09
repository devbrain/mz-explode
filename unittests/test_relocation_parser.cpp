// libexe - Modern executable file analysis library
// Base relocation parser tests with ground truth from objdump
//
// Ground truth for scheduler.exe (objdump -p):
//   - Entry 5 00000000 00000000 Base Relocation Directory
//   - No relocations (built with relocations stripped)
//   - Characteristics 0x103 includes "relocations stripped"

#include <libexe/formats/pe_file.hpp>
#include <libexe/pe/directories/relocation.hpp>
#include <libexe/pe/types.hpp>
#include <doctest/doctest.h>

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
// Base Relocation Tests - Ground Truth from objdump
// =============================================================================

TEST_CASE("Relocation parser - scheduler.exe has no relocations") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);

    // Ground truth from objdump: Entry 5 00000000 00000000 Base Relocation Directory
    CHECK_FALSE(pe.has_data_directory(directory_entry::BASERELOC));
    CHECK(pe.data_directory_rva(directory_entry::BASERELOC) == 0);
    CHECK(pe.data_directory_size(directory_entry::BASERELOC) == 0);

    // relocations() should return empty directory, not nullptr
    auto relocs = pe.relocations();
    REQUIRE(relocs != nullptr);
    CHECK(relocs->block_count() == 0);
    CHECK(relocs->total_relocations() == 0);
}

// =============================================================================
// Relocation Entry Type Name Tests
// =============================================================================

TEST_CASE("Relocation entry - type_name()") {
    SUBCASE("ABSOLUTE (padding)") {
        relocation_entry entry;
        entry.type = relocation_type::ABSOLUTE;
        entry.rva = 0;

        CHECK(entry.type_name() == "ABSOLUTE");
        CHECK(entry.size_bytes() == 0);  // ABSOLUTE is padding
    }

    SUBCASE("HIGHLOW (32-bit)") {
        relocation_entry entry;
        entry.type = relocation_type::HIGHLOW;
        entry.rva = 0x1100;

        CHECK(entry.type_name() == "HIGHLOW");
        CHECK(entry.is_32bit());
        CHECK(entry.size_bytes() == 4);
    }

    SUBCASE("DIR64 (64-bit)") {
        relocation_entry entry;
        entry.type = relocation_type::DIR64;
        entry.rva = 0x1200;

        CHECK(entry.type_name() == "DIR64");
        CHECK(entry.is_64bit());
        CHECK(entry.size_bytes() == 8);
    }
}

TEST_CASE("Relocation block - entry count") {
    relocation_block block;
    block.page_rva = 0x1000;

    relocation_entry entry1;
    entry1.type = relocation_type::HIGHLOW;
    entry1.rva = 0x1050;
    block.entries.push_back(entry1);

    relocation_entry entry2;
    entry2.type = relocation_type::ABSOLUTE;  // padding
    entry2.rva = 0;
    block.entries.push_back(entry2);

    CHECK(block.relocation_count() == 2);
    CHECK(block.active_relocation_count() == 1);  // ABSOLUTE doesn't count
}
