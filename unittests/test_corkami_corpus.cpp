// libexe - Modern executable file analysis library
// Copyright (c) 2024
// Integration tests using Corkami PE test corpus (embedded data)

#include <doctest/doctest.h>
#include <libexe/formats/pe_file.hpp>
#include <libexe/pe/directories/import.hpp>
#include <libexe/pe/directories/export.hpp>
#include <libexe/pe/directories/tls.hpp>
#include <libexe/pe/directories/delay_import.hpp>
#include <libexe/pe/directories/bound_import.hpp>
#include <libexe/pe/directories/relocation.hpp>
#include <libexe/pe/directories/debug.hpp>
#include <libexe/pe/directories/security.hpp>
#include <libexe/pe/directories/com_descriptor.hpp>
#include <libexe/pe/directories/load_config.hpp>
#include <vector>

using namespace libexe;

// =============================================================================
// Corkami Test Corpus Integration Tests
//
// These tests use real-world PE files from the Corkami PE corpus:
// https://github.com/corkami/pocs/tree/master/PE
//
// The corpus contains hand-crafted PE files that test edge cases and unusual
// structures in the PE format.
// =============================================================================

// External embedded test data
namespace corkami_data {
    extern size_t imports_len;
    extern unsigned char imports[];
    extern size_t imports_mixed_len;
    extern unsigned char imports_mixed[];
    extern size_t impbyord_len;
    extern unsigned char impbyord[];
    extern size_t dll_len;
    extern unsigned char dll[];
    extern size_t dllord_len;
    extern unsigned char dllord[];
    extern size_t tls_len;
    extern unsigned char tls[];
    extern size_t tls_aoi_len;
    extern unsigned char tls_aoi[];
    extern size_t tls64_len;
    extern unsigned char tls64[];
    extern size_t delayimports_len;
    extern unsigned char delayimports[];
    extern size_t dllbound_len;
    extern unsigned char dllbound[];
    extern size_t ibreloc_len;
    extern unsigned char ibreloc[];
    extern size_t dllnoreloc_len;
    extern unsigned char dllnoreloc[];
    extern size_t debug_len;
    extern unsigned char debug[];
    extern size_t signature_len;
    extern unsigned char signature[];
    extern size_t dotnet20_len;
    extern unsigned char dotnet20[];
    extern size_t tinynet_len;
    extern unsigned char tinynet[];
    extern size_t cfgbogus_len;
    extern unsigned char cfgbogus[];
    extern size_t compiled_len;
    extern unsigned char compiled[];
}

namespace {

// Helper: Load embedded test file
std::vector<uint8_t> load_embedded(const unsigned char* data, size_t len) {
    return std::vector<uint8_t>(data, data + len);
}

} // anonymous namespace

// =============================================================================
// Import Directory Tests
// =============================================================================

TEST_CASE("Corkami - Import directory parsing") {
    SUBCASE("Standard imports") {
        auto data = load_embedded(corkami_data::imports, corkami_data::imports_len);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        CHECK(pe.has_data_directory(directory_entry::IMPORT));

        auto imports = pe.imports();
        REQUIRE(imports != nullptr);
        CHECK(imports->dll_count() > 0);
    }

    SUBCASE("Mixed imports (names and ordinals)") {
        auto data = load_embedded(corkami_data::imports_mixed, corkami_data::imports_mixed_len);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        auto imports = pe.imports();
        REQUIRE(imports != nullptr);

        if (imports->dll_count() > 0) {
            // Check if we can handle mixed imports
            const auto& first_dll = imports->dlls[0];
            CHECK_FALSE(first_dll.name.empty());
        }
    }

    SUBCASE("Imports by ordinal") {
        auto data = load_embedded(corkami_data::impbyord, corkami_data::impbyord_len);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        auto imports = pe.imports();
        CHECK(imports != nullptr);
    }
}

// =============================================================================
// Export Directory Tests
// =============================================================================

TEST_CASE("Corkami - Export directory parsing") {
    SUBCASE("Standard exports") {
        auto data = load_embedded(corkami_data::dll, corkami_data::dll_len);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        if (pe.has_data_directory(directory_entry::EXPORT)) {
            auto exports = pe.exports();
            CHECK(exports != nullptr);
        }
    }

    SUBCASE("Exports with ordinals") {
        auto data = load_embedded(corkami_data::dllord, corkami_data::dllord_len);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        if (pe.has_data_directory(directory_entry::EXPORT)) {
            auto exports = pe.exports();
            REQUIRE(exports != nullptr);
            // Ordinal-only exports should work
            CHECK(exports->export_count() > 0);
        }
    }
}

// =============================================================================
// TLS Directory Tests
// =============================================================================

TEST_CASE("Corkami - TLS directory parsing") {
    SUBCASE("Standard TLS") {
        auto data = load_embedded(corkami_data::tls, corkami_data::tls_len);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        if (pe.has_data_directory(directory_entry::TLS)) {
            auto tls = pe.tls();
            REQUIRE(tls != nullptr);
            CHECK(tls->callback_count() >= 0);
        }
    }

    SUBCASE("TLS with multiple callbacks") {
        auto data = load_embedded(corkami_data::tls_aoi, corkami_data::tls_aoi_len);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        if (pe.has_data_directory(directory_entry::TLS)) {
            auto tls = pe.tls();
            CHECK(tls != nullptr);
        }
    }

    SUBCASE("TLS 64-bit") {
        auto data = load_embedded(corkami_data::tls64, corkami_data::tls64_len);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        CHECK(pe.is_64bit());
        if (pe.has_data_directory(directory_entry::TLS)) {
            auto tls = pe.tls();
            CHECK(tls != nullptr);
        }
    }
}

// =============================================================================
// Delay Import Directory Tests
// =============================================================================

TEST_CASE("Corkami - Delay import directory parsing") {
    SUBCASE("Delay imports") {
        auto data = load_embedded(corkami_data::delayimports, corkami_data::delayimports_len);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        if (pe.has_data_directory(directory_entry::DELAY_IMPORT)) {
            auto delay = pe.delay_imports();
            REQUIRE(delay != nullptr);
            CHECK(delay->dll_count() > 0);
        }
    }
}

// =============================================================================
// Bound Import Directory Tests
// =============================================================================

TEST_CASE("Corkami - Bound import directory parsing") {
    SUBCASE("Bound imports") {
        auto data = load_embedded(corkami_data::dllbound, corkami_data::dllbound_len);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        if (pe.has_data_directory(directory_entry::BOUND_IMPORT)) {
            auto bound = pe.bound_imports();
            REQUIRE(bound != nullptr);
            CHECK(bound->descriptors.size() > 0);
        }
    }
}

// =============================================================================
// Base Relocation Tests
// =============================================================================

TEST_CASE("Corkami - Base relocation parsing") {
    SUBCASE("Standard relocations") {
        auto data = load_embedded(corkami_data::ibreloc, corkami_data::ibreloc_len);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        if (pe.has_data_directory(directory_entry::BASERELOC)) {
            auto relocs = pe.relocations();
            REQUIRE(relocs != nullptr);
            CHECK(relocs->block_count() > 0);
        }
    }

    SUBCASE("No relocations") {
        auto data = load_embedded(corkami_data::dllnoreloc, corkami_data::dllnoreloc_len);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        auto relocs = pe.relocations();
        CHECK(relocs != nullptr);
        // DLL with no relocations
    }
}

// =============================================================================
// Debug Directory Tests
// =============================================================================

TEST_CASE("Corkami - Debug directory parsing") {
    SUBCASE("Debug info") {
        auto data = load_embedded(corkami_data::debug, corkami_data::debug_len);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        if (pe.has_data_directory(directory_entry::DEBUG)) {
            auto debug = pe.debug();
            REQUIRE(debug != nullptr);
            CHECK(debug->entries.size() > 0);
        }
    }
}

// =============================================================================
// Security Directory Tests
// =============================================================================

TEST_CASE("Corkami - Security directory parsing") {
    SUBCASE("Authenticode signature") {
        auto data = load_embedded(corkami_data::signature, corkami_data::signature_len);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        if (pe.has_data_directory(directory_entry::SECURITY)) {
            auto security = pe.security();
            REQUIRE(security != nullptr);
            CHECK(security->certificate_count() > 0);

            if (security->certificate_count() > 0) {
                CHECK(security->has_authenticode());
            }
        }
    }
}

// =============================================================================
// COM Descriptor Tests (.NET)
// =============================================================================

TEST_CASE("Corkami - COM descriptor parsing") {
    SUBCASE(".NET 2.0 assembly") {
        auto data = load_embedded(corkami_data::dotnet20, corkami_data::dotnet20_len);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        CHECK(pe.has_data_directory(directory_entry::COM_DESCRIPTOR));

        auto clr = pe.clr_header();
        REQUIRE(clr != nullptr);
        CHECK(clr->is_valid());
        CHECK(clr->metadata_rva != 0);
        CHECK(clr->metadata_size > 0);
    }

    SUBCASE("Tiny .NET") {
        auto data = load_embedded(corkami_data::tinynet, corkami_data::tinynet_len);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        if (pe.has_data_directory(directory_entry::COM_DESCRIPTOR)) {
            auto clr = pe.clr_header();
            CHECK(clr != nullptr);
            if (clr->is_valid()) {
            }
        }
    }
}

// =============================================================================
// Load Config Directory Tests
// =============================================================================

TEST_CASE("Corkami - Load config directory parsing") {
    SUBCASE("SEH/CFG config") {
        auto data = load_embedded(corkami_data::cfgbogus, corkami_data::cfgbogus_len);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        if (pe.has_data_directory(directory_entry::LOAD_CONFIG)) {
            auto cfg = pe.load_config();
            REQUIRE(cfg != nullptr);
            CHECK_FALSE(cfg->is_empty());
        }
    }
}

// =============================================================================
// Multi-Parser Integration Test
// =============================================================================

TEST_CASE("Corkami - Multi-parser integration") {
    SUBCASE("Complex PE with multiple directories") {
        auto data = load_embedded(corkami_data::compiled, corkami_data::compiled_len);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);


        // Check all parsers work together
        auto imports = pe.imports();
        auto exports = pe.exports();
        auto relocs = pe.relocations();
        auto debug = pe.debug();
        auto tls = pe.tls();
        auto load_cfg = pe.load_config();

        // All should return valid pointers (even if empty)
        CHECK(imports != nullptr);
        CHECK(exports != nullptr);
        CHECK(relocs != nullptr);
        CHECK(debug != nullptr);
        CHECK(tls != nullptr);
        CHECK(load_cfg != nullptr);

        if (pe.has_data_directory(directory_entry::IMPORT)) {
        }

        if (pe.has_data_directory(directory_entry::DEBUG)) {
        }
    }
}
