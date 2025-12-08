// Comprehensive tests for section parsers
#include <doctest/doctest.h>
#include <libexe/pe_section_parser.hpp>
#include <libexe/ne_segment_parser.hpp>
#include <vector>

using namespace libexe;

// =============================================================================
// PE Section Parser Tests
// =============================================================================

TEST_SUITE("PE Section Parser") {
    TEST_CASE("Section name extraction") {
        SUBCASE("Standard null-terminated name") {
            uint8_t name_bytes[8] = {'.', 't', 'e', 'x', 't', 0, 0, 0};
            auto name = pe_section_parser::get_section_name(name_bytes);
            CHECK(name == ".text");
        }

        SUBCASE("Full 8-byte name (not null-terminated)") {
            uint8_t name_bytes[8] = {'.', 'v', 'e', 'r', 'y', 'l', 'n', 'g'};
            auto name = pe_section_parser::get_section_name(name_bytes);
            CHECK(name == ".verylng");
            CHECK(name.size() == 8);
        }

        SUBCASE("Short name") {
            uint8_t name_bytes[8] = {'.', 'b', 's', 's', 0, 0, 0, 0};
            auto name = pe_section_parser::get_section_name(name_bytes);
            CHECK(name == ".bss");
        }

        SUBCASE("Single character name") {
            uint8_t name_bytes[8] = {'C', 0, 0, 0, 0, 0, 0, 0};
            auto name = pe_section_parser::get_section_name(name_bytes);
            CHECK(name == "C");
        }

        SUBCASE("Empty name") {
            uint8_t name_bytes[8] = {0, 0, 0, 0, 0, 0, 0, 0};
            auto name = pe_section_parser::get_section_name(name_bytes);
            CHECK(name.empty());
        }
    }

    TEST_CASE("Section type classification") {
        SUBCASE("Code sections by name") {
            CHECK(pe_section_parser::classify_section(".text", 0) == section_type::CODE);
            CHECK(pe_section_parser::classify_section("CODE", 0) == section_type::CODE);
            CHECK(pe_section_parser::classify_section(".code", 0) == section_type::CODE);
        }

        SUBCASE("Data sections by name") {
            CHECK(pe_section_parser::classify_section(".data", 0) == section_type::DATA);
            CHECK(pe_section_parser::classify_section("DATA", 0) == section_type::DATA);
            CHECK(pe_section_parser::classify_section(".rdata", 0) == section_type::DATA);
            CHECK(pe_section_parser::classify_section(".rodata", 0) == section_type::DATA);
        }

        SUBCASE("BSS section") {
            CHECK(pe_section_parser::classify_section(".bss", 0) == section_type::BSS);
            CHECK(pe_section_parser::classify_section("BSS", 0) == section_type::BSS);
        }

        SUBCASE("Import section") {
            CHECK(pe_section_parser::classify_section(".idata", 0) == section_type::IMPORT);
            CHECK(pe_section_parser::classify_section(".import", 0) == section_type::IMPORT);
        }

        SUBCASE("Export section") {
            CHECK(pe_section_parser::classify_section(".edata", 0) == section_type::EXPORT);
            CHECK(pe_section_parser::classify_section(".export", 0) == section_type::EXPORT);
        }

        SUBCASE("Resource section") {
            CHECK(pe_section_parser::classify_section(".rsrc", 0) == section_type::RESOURCE);
            CHECK(pe_section_parser::classify_section(".resources", 0) == section_type::RESOURCE);
        }

        SUBCASE("Relocation section") {
            CHECK(pe_section_parser::classify_section(".reloc", 0) == section_type::RELOCATION);
            CHECK(pe_section_parser::classify_section(".relocations", 0) == section_type::RELOCATION);
        }

        SUBCASE("Debug and exception sections") {
            CHECK(pe_section_parser::classify_section(".debug", 0) == section_type::DEBUG);
            CHECK(pe_section_parser::classify_section(".xdata", 0) == section_type::DEBUG);
        }

        SUBCASE("Exception section") {
            CHECK(pe_section_parser::classify_section(".pdata", 0) == section_type::EXCEPTION);
        }

        SUBCASE("TLS section") {
            CHECK(pe_section_parser::classify_section(".tls", 0) == section_type::TLS);
            CHECK(pe_section_parser::classify_section(".tls$", 0) == section_type::TLS);
        }

        SUBCASE("Classification by characteristics flags") {
            uint32_t uninit_flag = static_cast<uint32_t>(section_characteristics::CNT_UNINITIALIZED_DATA);
            CHECK(pe_section_parser::classify_section(".custom", uninit_flag) == section_type::BSS);

            uint32_t code_flag = static_cast<uint32_t>(section_characteristics::CNT_CODE);
            CHECK(pe_section_parser::classify_section(".custom", code_flag) == section_type::CODE);

            uint32_t data_flag = static_cast<uint32_t>(section_characteristics::CNT_INITIALIZED_DATA);
            CHECK(pe_section_parser::classify_section(".custom", data_flag) == section_type::DATA);
        }

        SUBCASE("Unknown section") {
            CHECK(pe_section_parser::classify_section(".unknown", 0) == section_type::UNKNOWN);
            CHECK(pe_section_parser::classify_section("", 0) == section_type::UNKNOWN);
        }
    }

    TEST_CASE("Alignment extraction") {
        SUBCASE("No alignment specified") {
            CHECK(pe_section_parser::extract_alignment(0x00000000) == 0);
        }

        SUBCASE("1-byte alignment") {
            uint32_t flags = static_cast<uint32_t>(section_characteristics::ALIGN_1BYTES);
            CHECK(pe_section_parser::extract_alignment(flags) == 1);
        }

        SUBCASE("2-byte alignment") {
            uint32_t flags = static_cast<uint32_t>(section_characteristics::ALIGN_2BYTES);
            CHECK(pe_section_parser::extract_alignment(flags) == 2);
        }

        SUBCASE("4-byte alignment") {
            uint32_t flags = static_cast<uint32_t>(section_characteristics::ALIGN_4BYTES);
            CHECK(pe_section_parser::extract_alignment(flags) == 4);
        }

        SUBCASE("Page alignment (4096 bytes)") {
            uint32_t flags = static_cast<uint32_t>(section_characteristics::ALIGN_4096BYTES);
            CHECK(pe_section_parser::extract_alignment(flags) == 4096);
        }

        SUBCASE("8192-byte alignment") {
            uint32_t flags = static_cast<uint32_t>(section_characteristics::ALIGN_8192BYTES);
            CHECK(pe_section_parser::extract_alignment(flags) == 8192);
        }

        SUBCASE("Alignment with other flags") {
            uint32_t flags = static_cast<uint32_t>(section_characteristics::CNT_CODE) |
                            static_cast<uint32_t>(section_characteristics::MEM_EXECUTE) |
                            static_cast<uint32_t>(section_characteristics::ALIGN_4096BYTES);
            CHECK(pe_section_parser::extract_alignment(flags) == 4096);
        }
    }

    TEST_CASE("RVA to file offset conversion") {
        // Create test sections
        std::vector<pe_section> sections;

        pe_section text;
        text.name = ".text";
        text.virtual_address = 0x1000;
        text.virtual_size = 0x2000;
        text.raw_data_offset = 0x400;
        text.raw_data_size = 0x2000;
        sections.push_back(text);

        pe_section data;
        data.name = ".data";
        data.virtual_address = 0x3000;
        data.virtual_size = 0x1000;
        data.raw_data_offset = 0x2400;
        data.raw_data_size = 0x1000;
        sections.push_back(data);

        SUBCASE("RVA within first section") {
            auto offset = pe_section_parser::rva_to_file_offset(sections, 0x1000);
            REQUIRE(offset.has_value());
            CHECK(offset.value() == 0x400);
        }

        SUBCASE("RVA in middle of section") {
            auto offset = pe_section_parser::rva_to_file_offset(sections, 0x1800);
            REQUIRE(offset.has_value());
            CHECK(offset.value() == 0xC00);  // 0x400 + 0x800
        }

        SUBCASE("RVA within second section") {
            auto offset = pe_section_parser::rva_to_file_offset(sections, 0x3500);
            REQUIRE(offset.has_value());
            CHECK(offset.value() == 0x2900);  // 0x2400 + 0x500
        }

        SUBCASE("RVA not in any section") {
            auto offset = pe_section_parser::rva_to_file_offset(sections, 0x5000);
            CHECK_FALSE(offset.has_value());
        }

        SUBCASE("RVA before all sections") {
            auto offset = pe_section_parser::rva_to_file_offset(sections, 0x100);
            CHECK_FALSE(offset.has_value());
        }
    }

    TEST_CASE("Find section by RVA") {
        std::vector<pe_section> sections;

        pe_section text;
        text.name = ".text";
        text.virtual_address = 0x1000;
        text.virtual_size = 0x2000;
        sections.push_back(text);

        pe_section data;
        data.name = ".data";
        data.virtual_address = 0x3000;
        data.virtual_size = 0x1000;
        sections.push_back(data);

        SUBCASE("Find by RVA in first section") {
            auto section = pe_section_parser::find_section_by_rva(sections, 0x1500);
            REQUIRE(section != nullptr);
            CHECK(section->name == ".text");
        }

        SUBCASE("Find by RVA in second section") {
            auto section = pe_section_parser::find_section_by_rva(sections, 0x3500);
            REQUIRE(section != nullptr);
            CHECK(section->name == ".data");
        }

        SUBCASE("RVA not found") {
            auto section = pe_section_parser::find_section_by_rva(sections, 0x5000);
            CHECK(section == nullptr);
        }
    }

    TEST_CASE("Find section by name") {
        std::vector<pe_section> sections;

        pe_section text;
        text.name = ".text";
        sections.push_back(text);

        pe_section data;
        data.name = ".data";
        sections.push_back(data);

        SUBCASE("Find existing section") {
            auto section = pe_section_parser::find_section_by_name(sections, ".text");
            REQUIRE(section != nullptr);
            CHECK(section->name == ".text");
        }

        SUBCASE("Find second section") {
            auto section = pe_section_parser::find_section_by_name(sections, ".data");
            REQUIRE(section != nullptr);
            CHECK(section->name == ".data");
        }

        SUBCASE("Section not found") {
            auto section = pe_section_parser::find_section_by_name(sections, ".rsrc");
            CHECK(section == nullptr);
        }

        SUBCASE("Case sensitive search") {
            auto section = pe_section_parser::find_section_by_name(sections, ".TEXT");
            CHECK(section == nullptr);
        }
    }
}

// =============================================================================
// NE Segment Parser Tests
// =============================================================================

TEST_SUITE("NE Segment Parser") {
    TEST_CASE("Segment type classification") {
        SUBCASE("Code segment (DATA flag clear)") {
            uint16_t code_flags = 0x0000;  // No flags set
            CHECK(ne_segment_parser::classify_segment(code_flags) == section_type::CODE);
            CHECK(ne_segment_parser::is_code_segment(code_flags) == true);
            CHECK(ne_segment_parser::is_data_segment(code_flags) == false);
        }

        SUBCASE("Data segment (DATA flag set)") {
            uint16_t data_flags = static_cast<uint16_t>(ne_segment_flags::DATA);
            CHECK(ne_segment_parser::classify_segment(data_flags) == section_type::DATA);
            CHECK(ne_segment_parser::is_code_segment(data_flags) == false);
            CHECK(ne_segment_parser::is_data_segment(data_flags) == true);
        }

        SUBCASE("Code segment with other flags") {
            uint16_t flags = static_cast<uint16_t>(ne_segment_flags::MOVEABLE) |
                            static_cast<uint16_t>(ne_segment_flags::PRELOAD);
            CHECK(ne_segment_parser::classify_segment(flags) == section_type::CODE);
        }

        SUBCASE("Data segment with other flags") {
            uint16_t flags = static_cast<uint16_t>(ne_segment_flags::DATA) |
                            static_cast<uint16_t>(ne_segment_flags::MOVEABLE);
            CHECK(ne_segment_parser::classify_segment(flags) == section_type::DATA);
        }
    }

    TEST_CASE("File offset calculation") {
        SUBCASE("Zero sector offset") {
            uint32_t offset = ne_segment_parser::calculate_file_offset(0, 4);
            CHECK(offset == 0);
        }

        SUBCASE("Alignment shift 4 (16-byte sectors)") {
            // sector 10, shift 4 = 10 << 4 = 160
            uint32_t offset = ne_segment_parser::calculate_file_offset(10, 4);
            CHECK(offset == 160);
        }

        SUBCASE("Alignment shift 9 (512-byte sectors)") {
            // sector 8, shift 9 = 8 << 9 = 4096
            uint32_t offset = ne_segment_parser::calculate_file_offset(8, 9);
            CHECK(offset == 4096);
        }

        SUBCASE("Large sector offset") {
            // sector 0x1000, shift 4 = 0x10000
            uint32_t offset = ne_segment_parser::calculate_file_offset(0x1000, 4);
            CHECK(offset == 0x10000);
        }

        SUBCASE("Alignment shift 0 (byte sectors)") {
            uint32_t offset = ne_segment_parser::calculate_file_offset(100, 0);
            CHECK(offset == 100);
        }

        SUBCASE("Invalid alignment shift throws") {
            CHECK_THROWS_AS(
                ne_segment_parser::calculate_file_offset(1, 16),
                std::runtime_error
            );
        }
    }

    TEST_CASE("Segment size calculation") {
        SUBCASE("Normal size") {
            CHECK(ne_segment_parser::calculate_segment_size(1024) == 1024);
            CHECK(ne_segment_parser::calculate_segment_size(4096) == 4096);
            CHECK(ne_segment_parser::calculate_segment_size(1) == 1);
        }

        SUBCASE("Zero means 65536 bytes") {
            CHECK(ne_segment_parser::calculate_segment_size(0) == 65536);
        }

        SUBCASE("Maximum 16-bit size") {
            CHECK(ne_segment_parser::calculate_segment_size(0xFFFF) == 0xFFFF);
        }
    }

    TEST_CASE("Find segment by index") {
        std::vector<ne_segment> segments;

        ne_segment seg1;
        seg1.index = 1;
        seg1.type = section_type::CODE;
        segments.push_back(seg1);

        ne_segment seg2;
        seg2.index = 2;
        seg2.type = section_type::DATA;
        segments.push_back(seg2);

        ne_segment seg3;
        seg3.index = 3;
        seg3.type = section_type::DATA;
        segments.push_back(seg3);

        SUBCASE("Find first segment (index 1)") {
            auto segment = ne_segment_parser::find_segment_by_index(segments, 1);
            REQUIRE(segment != nullptr);
            CHECK(segment->index == 1);
            CHECK(segment->type == section_type::CODE);
        }

        SUBCASE("Find middle segment (index 2)") {
            auto segment = ne_segment_parser::find_segment_by_index(segments, 2);
            REQUIRE(segment != nullptr);
            CHECK(segment->index == 2);
        }

        SUBCASE("Find last segment (index 3)") {
            auto segment = ne_segment_parser::find_segment_by_index(segments, 3);
            REQUIRE(segment != nullptr);
            CHECK(segment->index == 3);
        }

        SUBCASE("Index 0 is invalid") {
            auto segment = ne_segment_parser::find_segment_by_index(segments, 0);
            CHECK(segment == nullptr);
        }

        SUBCASE("Index beyond range") {
            auto segment = ne_segment_parser::find_segment_by_index(segments, 4);
            CHECK(segment == nullptr);
        }

        SUBCASE("Large invalid index") {
            auto segment = ne_segment_parser::find_segment_by_index(segments, 100);
            CHECK(segment == nullptr);
        }
    }

    TEST_CASE("Find first code segment") {
        SUBCASE("Code segment is first") {
            std::vector<ne_segment> segments;

            ne_segment code;
            code.index = 1;
            code.flags = 0;  // No DATA flag = code
            segments.push_back(code);

            ne_segment data;
            data.index = 2;
            data.flags = static_cast<uint16_t>(ne_segment_flags::DATA);
            segments.push_back(data);

            auto segment = ne_segment_parser::find_first_code_segment(segments);
            REQUIRE(segment != nullptr);
            CHECK(segment->index == 1);
        }

        SUBCASE("Code segment is second") {
            std::vector<ne_segment> segments;

            ne_segment data;
            data.index = 1;
            data.flags = static_cast<uint16_t>(ne_segment_flags::DATA);
            segments.push_back(data);

            ne_segment code;
            code.index = 2;
            code.flags = 0;
            segments.push_back(code);

            auto segment = ne_segment_parser::find_first_code_segment(segments);
            REQUIRE(segment != nullptr);
            CHECK(segment->index == 2);
        }

        SUBCASE("No code segment") {
            std::vector<ne_segment> segments;

            ne_segment data1;
            data1.flags = static_cast<uint16_t>(ne_segment_flags::DATA);
            segments.push_back(data1);

            ne_segment data2;
            data2.flags = static_cast<uint16_t>(ne_segment_flags::DATA);
            segments.push_back(data2);

            auto segment = ne_segment_parser::find_first_code_segment(segments);
            CHECK(segment == nullptr);
        }

        SUBCASE("Empty segment list") {
            std::vector<ne_segment> segments;
            auto segment = ne_segment_parser::find_first_code_segment(segments);
            CHECK(segment == nullptr);
        }
    }
}
