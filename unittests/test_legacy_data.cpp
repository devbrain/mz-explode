// Tests with real legacy compressed executable data
#include <doctest/doctest.h>
#include <libexe/mz_file.hpp>
#include <vector>
#include <span>

using namespace libexe;

// Include embedded test data from legacy unittest
namespace data {
    // Forward declarations - data defined in separate compilation units
    extern size_t pklite_112_len;
    extern unsigned char pklite_112[];

    extern size_t pklite_E_115_len;
    extern unsigned char pklite_E_115[];

    extern size_t z90_len;
    extern unsigned char z90[];

    extern size_t z91_len;
    extern unsigned char z91[];

    extern size_t knowledge_dynamics_DOT_len;
    extern unsigned char knowledge_dynamics_DOT[];
}

TEST_CASE("legacy data: PKLITE compressed executables") {
    SUBCASE("PKLITE 1.12 - parse MZ header") {
        std::span<const uint8_t> data(data::pklite_112, data::pklite_112_len);

        auto mz = mz_file::from_memory(data);

        // Verify it's recognized as MZ format
        CHECK(mz.get_format() == format_type::MZ_DOS);
        CHECK(mz.format_name() == "MZ (DOS Executable)");

        // PKLITE files have valid MZ headers
        CHECK(mz.header_paragraphs() > 0);
        CHECK(mz.header_paragraphs() < 1000);  // Reasonable limit

        // Code section should exist
        auto code = mz.code_section();
        CHECK(code.size() > 0);

        // TODO: Once compression detection is implemented:
        // CHECK(mz.get_compression() == compression_type::PKLITE_STANDARD);
    }

    SUBCASE("PKLITE Extra compression - parse MZ header") {
        std::span<const uint8_t> data(data::pklite_E_115, data::pklite_E_115_len);

        REQUIRE_NOTHROW([&]() {
            auto mz = mz_file::from_memory(data);
            CHECK(mz.get_format() == format_type::MZ_DOS);

            // TODO: Once compression detection is implemented:
            // CHECK(mz.get_compression() == compression_type::PKLITE_EXTRA);
        }());
    }
}

TEST_CASE("legacy data: LZEXE compressed executables") {
    SUBCASE("LZEXE 0.90 - parse MZ header") {
        std::span<const uint8_t> data(data::z90, data::z90_len);

        auto mz = mz_file::from_memory(data);
        CHECK(mz.get_format() == format_type::MZ_DOS);

        // TODO: Once compression detection is implemented:
        // CHECK(mz.get_compression() == compression_type::LZEXE_090);
    }

    SUBCASE("LZEXE 0.91 - parse MZ header") {
        std::span<const uint8_t> data(data::z91, data::z91_len);

        REQUIRE_NOTHROW([&]() {
            auto mz = mz_file::from_memory(data);
            CHECK(mz.get_format() == format_type::MZ_DOS);

            // TODO: Once compression detection is implemented:
            // CHECK(mz.get_compression() == compression_type::LZEXE_091);
        }());
    }
}

TEST_CASE("legacy data: Knowledge Dynamics compressed") {
    SUBCASE("Knowledge Dynamics DOT - parse MZ header") {
        std::span<const uint8_t> data(data::knowledge_dynamics_DOT, data::knowledge_dynamics_DOT_len);

        auto mz = mz_file::from_memory(data);
        CHECK(mz.get_format() == format_type::MZ_DOS);

        // TODO: Once compression detection is implemented:
        // CHECK(mz.get_compression() == compression_type::KNOWLEDGE_DYNAMICS);
    }
}

TEST_CASE("legacy data: verify MZ header fields") {
    // Test with PKLITE 1.12 as a concrete example
    std::span<const uint8_t> data(data::pklite_112, data::pklite_112_len);
    auto mz = mz_file::from_memory(data);

    SUBCASE("MZ signature is valid") {
        // If we got here, signature was validated by DataScript
        REQUIRE(mz.get_format() == format_type::MZ_DOS);
    }

    SUBCASE("header contains reasonable values") {
        // Header size should be reasonable (typically 4-64 paragraphs)
        auto header_paras = mz.header_paragraphs();
        CHECK(header_paras >= 2);
        CHECK(header_paras <= 1024);

        // Relocation count should be reasonable
        auto relocs = mz.relocation_count();
        CHECK(relocs < 10000);  // Sanity check

        // Memory requirements
        auto min_mem = mz.min_extra_paragraphs();
        auto max_mem = mz.max_extra_paragraphs();
        CHECK(min_mem <= max_mem);
    }

    SUBCASE("code section is non-empty") {
        auto code = mz.code_section();
        REQUIRE(code.size() > 0);

        // Verify it starts after the header
        size_t header_bytes = mz.header_paragraphs() * 16;
        CHECK(code.size() == data.size() - header_bytes);
    }
}
