// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/formats/pe_file.hpp>
#include <libexe/pe/directories/relocation.hpp>
#include <libexe/pe/directories/relocation.hpp>
#include <libexe/pe/types.hpp>
#include <doctest/doctest.h>
#include <filesystem>
#include <fstream>

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
// Helper Functions
// =============================================================================

static std::vector<uint8_t> read_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + path.string());
    }

    auto size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(buffer.data()), size);

    return buffer;
}

// =============================================================================
// Base Relocation Parser Tests
// =============================================================================

TEST_CASE("Relocation parser - Data directory accessors") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("Check if base relocation directory exists") {
        bool has_relocs = pe.has_data_directory(directory_entry::BASERELOC);
        MESSAGE("Has relocations: " << (has_relocs ? "yes" : "no"));

        if (has_relocs) {
            uint32_t reloc_rva = pe.data_directory_rva(directory_entry::BASERELOC);
            uint32_t reloc_size = pe.data_directory_size(directory_entry::BASERELOC);

            CHECK(reloc_rva > 0);
            CHECK(reloc_size > 0);

            MESSAGE("Base relocation directory at RVA: 0x" << std::hex << reloc_rva
                    << ", size: " << std::dec << reloc_size << " bytes");
        }
    }
}

TEST_CASE("Relocation parser - Relocation directory parsing") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("Get relocation directory") {
        auto relocs = pe.relocations();
        REQUIRE(relocs != nullptr);

        if (relocs->block_count() > 0) {
            MESSAGE("Found " << relocs->block_count() << " relocation blocks");
            MESSAGE("Total relocations: " << relocs->total_relocations());
            MESSAGE("Active relocations: " << relocs->active_relocations());

            CHECK(relocs->total_relocations() >= relocs->active_relocations());
        } else {
            MESSAGE("No relocations (executable might be built with /FIXED)");
        }
    }

    SUBCASE("Check relocation blocks") {
        auto relocs = pe.relocations();
        REQUIRE(relocs != nullptr);

        if (relocs->block_count() > 0) {
            // Examine first few blocks
            size_t blocks_to_check = std::min<size_t>(5, relocs->block_count());

            for (size_t i = 0; i < blocks_to_check; i++) {
                const auto& block = relocs->blocks[i];
                MESSAGE("Block " << i << ": Page RVA 0x" << std::hex << block.page_rva
                        << ", " << std::dec << block.relocation_count() << " relocations"
                        << " (" << block.active_relocation_count() << " active)");

                CHECK(block.page_rva % 0x1000 == 0);  // Page-aligned
                CHECK(block.relocation_count() > 0);
            }
        }
    }

    SUBCASE("Check relocation types") {
        auto relocs = pe.relocations();
        REQUIRE(relocs != nullptr);

        if (relocs->block_count() > 0) {
            auto type_counts = relocs->get_type_counts();

            MESSAGE("Relocation type distribution:");
            for (const auto& [type, count] : type_counts) {
                relocation_entry dummy;
                dummy.type = type;
                MESSAGE("  " << dummy.type_name() << ": " << count);
            }

            // Most executables use HIGHLOW (PE32) or DIR64 (PE32+)
            bool has_common_type = false;
            for (const auto& [type, count] : type_counts) {
                if (type == relocation_type::HIGHLOW ||
                    type == relocation_type::DIR64) {
                    has_common_type = true;
                    break;
                }
            }

            if (!type_counts.empty()) {
                CHECK(has_common_type);
            }
        }
    }

    SUBCASE("Check relocation details") {
        auto relocs = pe.relocations();
        REQUIRE(relocs != nullptr);

        if (relocs->block_count() > 0) {
            // Check first block in detail
            const auto& first_block = relocs->blocks[0];

            MESSAGE("First block details:");
            MESSAGE("  Page RVA: 0x" << std::hex << first_block.page_rva);
            MESSAGE("  Total entries: " << std::dec << first_block.relocation_count());
            MESSAGE("  Active entries: " << first_block.active_relocation_count());

            // Check first few entries
            size_t entries_to_check = std::min<size_t>(5, first_block.relocation_count());

            for (size_t i = 0; i < entries_to_check; i++) {
                const auto& entry = first_block.entries[i];
                MESSAGE("  Entry " << i << ": Type=" << entry.type_name()
                        << ", RVA=0x" << std::hex << entry.rva
                        << ", Size=" << std::dec << entry.size_bytes() << " bytes");

                // Validate entry
                CHECK(entry.rva >= first_block.page_rva);
                CHECK(entry.rva < first_block.page_rva + 0x1000);  // Within page

                if (entry.type != relocation_type::ABSOLUTE) {
                    CHECK(entry.size_bytes() > 0);
                }
            }
        }
    }
}

TEST_CASE("Relocation parser - Find relocation by RVA") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto relocs = pe.relocations();
    REQUIRE(relocs != nullptr);

    if (relocs->block_count() > 0 && relocs->blocks[0].relocation_count() > 0) {
        const auto& first_block = relocs->blocks[0];
        const auto& first_entry = first_block.entries[0];

        SUBCASE("Find block for RVA") {
            // Should find block for RVA within first block's page
            auto block = relocs->find_block_for_rva(first_entry.rva);
            REQUIRE(block != nullptr);
            CHECK(block->page_rva == first_block.page_rva);

            // Should not find block for RVA far outside any block
            auto no_block = relocs->find_block_for_rva(0xFFFFFFFF);
            CHECK(no_block == nullptr);
        }

        SUBCASE("Check if RVA has relocation") {
            if (first_entry.type != relocation_type::ABSOLUTE) {
                // Should find relocation at actual relocation RVA
                CHECK(relocs->has_relocation_at(first_entry.rva));
            }

            // Should not find relocation at arbitrary RVA
            uint32_t arbitrary_rva = first_block.page_rva + 0x500;
            if (!relocs->has_relocation_at(arbitrary_rva)) {
                // This is fine - not every offset has a relocation
                MESSAGE("No relocation at RVA 0x" << std::hex << arbitrary_rva);
            }
        }
    } else {
        MESSAGE("No relocations to test");
    }
}

TEST_CASE("Relocation entry - Type properties") {
    SUBCASE("ABSOLUTE relocation") {
        relocation_entry entry;
        entry.type = relocation_type::ABSOLUTE;
        entry.rva = 0x1000;

        CHECK(entry.size_bytes() == 0);
        CHECK(!entry.is_32bit());
        CHECK(!entry.is_64bit());
        CHECK(entry.type_name() == "ABSOLUTE");
    }

    SUBCASE("HIGH relocation") {
        relocation_entry entry;
        entry.type = relocation_type::HIGH;
        entry.rva = 0x1000;

        CHECK(entry.size_bytes() == 2);
        CHECK(!entry.is_32bit());
        CHECK(!entry.is_64bit());
        CHECK(entry.type_name() == "HIGH");
    }

    SUBCASE("LOW relocation") {
        relocation_entry entry;
        entry.type = relocation_type::LOW;
        entry.rva = 0x1000;

        CHECK(entry.size_bytes() == 2);
        CHECK(!entry.is_32bit());
        CHECK(!entry.is_64bit());
        CHECK(entry.type_name() == "LOW");
    }

    SUBCASE("HIGHLOW relocation (PE32)") {
        relocation_entry entry;
        entry.type = relocation_type::HIGHLOW;
        entry.rva = 0x1000;

        CHECK(entry.size_bytes() == 4);
        CHECK(entry.is_32bit());
        CHECK(!entry.is_64bit());
        CHECK(entry.type_name() == "HIGHLOW");
    }

    SUBCASE("DIR64 relocation (PE32+)") {
        relocation_entry entry;
        entry.type = relocation_type::DIR64;
        entry.rva = 0x1000;

        CHECK(entry.size_bytes() == 8);
        CHECK(!entry.is_32bit());
        CHECK(entry.is_64bit());
        CHECK(entry.type_name() == "DIR64");
    }
}

TEST_CASE("Relocation block - Statistics") {
    relocation_block block;
    block.page_rva = 0x1000;

    SUBCASE("Empty block") {
        CHECK(block.relocation_count() == 0);
        CHECK(block.active_relocation_count() == 0);
    }

    SUBCASE("Block with relocations") {
        // Add ABSOLUTE (padding)
        relocation_entry absolute;
        absolute.type = relocation_type::ABSOLUTE;
        absolute.rva = 0x1000;
        block.entries.push_back(absolute);

        // Add HIGHLOW (active)
        relocation_entry highlow;
        highlow.type = relocation_type::HIGHLOW;
        highlow.rva = 0x1010;
        block.entries.push_back(highlow);

        // Add another HIGHLOW (active)
        relocation_entry highlow2;
        highlow2.type = relocation_type::HIGHLOW;
        highlow2.rva = 0x1020;
        block.entries.push_back(highlow2);

        CHECK(block.relocation_count() == 3);
        CHECK(block.active_relocation_count() == 2);  // Excludes ABSOLUTE
    }
}

TEST_CASE("Relocation directory - Statistics") {
    base_relocation_directory dir;

    SUBCASE("Empty directory") {
        CHECK(dir.block_count() == 0);
        CHECK(dir.total_relocations() == 0);
        CHECK(dir.active_relocations() == 0);
        CHECK(dir.find_block_for_rva(0x1000) == nullptr);
        CHECK(!dir.has_relocation_at(0x1000));

        auto type_counts = dir.get_type_counts();
        CHECK(type_counts.empty());
    }

    SUBCASE("Directory with blocks") {
        // Block 1
        relocation_block block1;
        block1.page_rva = 0x1000;

        relocation_entry entry1;
        entry1.type = relocation_type::HIGHLOW;
        entry1.rva = 0x1010;
        block1.entries.push_back(entry1);

        relocation_entry entry2;
        entry2.type = relocation_type::ABSOLUTE;
        entry2.rva = 0x1020;
        block1.entries.push_back(entry2);

        // Block 2
        relocation_block block2;
        block2.page_rva = 0x2000;

        relocation_entry entry3;
        entry3.type = relocation_type::HIGHLOW;
        entry3.rva = 0x2030;
        block2.entries.push_back(entry3);

        dir.blocks.push_back(block1);
        dir.blocks.push_back(block2);

        CHECK(dir.block_count() == 2);
        CHECK(dir.total_relocations() == 3);
        CHECK(dir.active_relocations() == 2);  // Excludes ABSOLUTE

        // Test finding blocks
        auto found1 = dir.find_block_for_rva(0x1010);
        REQUIRE(found1 != nullptr);
        CHECK(found1->page_rva == 0x1000);

        auto found2 = dir.find_block_for_rva(0x2030);
        REQUIRE(found2 != nullptr);
        CHECK(found2->page_rva == 0x2000);

        // Test relocation check
        CHECK(dir.has_relocation_at(0x1010));
        CHECK(dir.has_relocation_at(0x2030));
        CHECK(!dir.has_relocation_at(0x1020));  // ABSOLUTE doesn't count
        CHECK(!dir.has_relocation_at(0x3000));  // Not in any block

        // Test type counts
        auto type_counts = dir.get_type_counts();
        CHECK(type_counts.size() == 2);  // ABSOLUTE and HIGHLOW

        bool has_absolute = false;
        bool has_highlow = false;
        for (const auto& [type, count] : type_counts) {
            if (type == relocation_type::ABSOLUTE) {
                has_absolute = true;
                CHECK(count == 1);
            } else if (type == relocation_type::HIGHLOW) {
                has_highlow = true;
                CHECK(count == 2);
            }
        }
        CHECK(has_absolute);
        CHECK(has_highlow);
    }
}
