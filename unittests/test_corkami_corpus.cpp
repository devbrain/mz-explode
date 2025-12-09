// libexe - Modern executable file analysis library
// Copyright (c) 2024
// Integration tests using Corkami PE test corpus

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
#include <filesystem>
#include <fstream>
#include <vector>

using namespace libexe;
namespace fs = std::filesystem;

// =============================================================================
// Corkami Test Corpus Integration Tests
//
// These tests use real-world PE files from the Corkami PE corpus:
// https://github.com/corkami/pocs/tree/master/PE
//
// The corpus contains hand-crafted PE files that test edge cases and unusual
// structures in the PE format.
// =============================================================================

namespace {

/**
 * Load file into memory
 */
std::vector<uint8_t> load_file(const fs::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        return {};
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return {};
    }

    return buffer;
}

/**
 * Check if file exists
 */
bool file_exists(const fs::path& path) {
    return fs::exists(path) && fs::is_regular_file(path);
}

// Path to Corkami corpus
const char* CORKAMI_PATH = "/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/";

} // anonymous namespace

// =============================================================================
// Import Directory Tests
// =============================================================================

TEST_CASE("Corkami - Import directory parsing") {
    fs::path corpus_path(CORKAMI_PATH);

    SUBCASE("Standard imports") {
        fs::path file_path = corpus_path / "imports.exe";
        if (!file_exists(file_path)) {
            MESSAGE("Skipping test - file not found: ", file_path.string());
            return;
        }

        auto data = load_file(file_path);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        CHECK(pe.has_data_directory(directory_entry::IMPORT));

        auto imports = pe.imports();
        REQUIRE(imports != nullptr);
        CHECK(imports->dll_count() > 0);
    }

    SUBCASE("Mixed imports (names and ordinals)") {
        fs::path file_path = corpus_path / "imports_mixed.exe";
        if (!file_exists(file_path)) {
            MESSAGE("Skipping test - file not found");
            return;
        }

        auto data = load_file(file_path);
        if (!data.empty()) {
            auto pe = pe_file::from_memory(data);
            auto imports = pe.imports();
            REQUIRE(imports != nullptr);

            if (imports->dll_count() > 0) {
                // Check if we can handle mixed imports
                const auto& first_dll = imports->dlls[0];
                CHECK_FALSE(first_dll.name.empty());
            }
        }
    }

    SUBCASE("Imports by ordinal") {
        fs::path file_path = corpus_path / "impbyord.exe";
        if (!file_exists(file_path)) {
            MESSAGE("Skipping test - file not found");
            return;
        }

        auto data = load_file(file_path);
        if (!data.empty()) {
            auto pe = pe_file::from_memory(data);
            auto imports = pe.imports();
            CHECK(imports != nullptr);
        }
    }
}

// =============================================================================
// Export Directory Tests
// =============================================================================

TEST_CASE("Corkami - Export directory parsing") {
    fs::path corpus_path(CORKAMI_PATH);

    SUBCASE("Standard exports") {
        fs::path file_path = corpus_path / "dll.dll";
        if (!file_exists(file_path)) {
            MESSAGE("Skipping test - file not found");
            return;
        }

        auto data = load_file(file_path);
        if (!data.empty()) {
            auto pe = pe_file::from_memory(data);
            if (pe.has_data_directory(directory_entry::EXPORT)) {
                auto exports = pe.exports();
                CHECK(exports != nullptr);
            }
        }
    }

    SUBCASE("Exports with ordinals") {
        fs::path file_path = corpus_path / "dllord.dll";
        if (!file_exists(file_path)) {
            MESSAGE("Skipping test - file not found");
            return;
        }

        auto data = load_file(file_path);
        if (!data.empty()) {
            auto pe = pe_file::from_memory(data);
            if (pe.has_data_directory(directory_entry::EXPORT)) {
                auto exports = pe.exports();
                REQUIRE(exports != nullptr);
                // Ordinal-only exports should work
                CHECK(exports->export_count() > 0);
            }
        }
    }
}

// =============================================================================
// TLS Directory Tests
// =============================================================================

TEST_CASE("Corkami - TLS directory parsing") {
    fs::path corpus_path(CORKAMI_PATH);

    SUBCASE("Standard TLS") {
        fs::path file_path = corpus_path / "tls.exe";
        if (!file_exists(file_path)) {
            MESSAGE("Skipping test - file not found");
            return;
        }

        auto data = load_file(file_path);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        if (pe.has_data_directory(directory_entry::TLS)) {
            auto tls = pe.tls();
            REQUIRE(tls != nullptr);
            CHECK(tls->callback_count() >= 0);
        }
    }

    SUBCASE("TLS with multiple callbacks") {
        fs::path file_path = corpus_path / "tls_aoi.exe";
        if (!file_exists(file_path)) {
            MESSAGE("Skipping test - file not found");
            return;
        }

        auto data = load_file(file_path);
        if (!data.empty()) {
            auto pe = pe_file::from_memory(data);
            if (pe.has_data_directory(directory_entry::TLS)) {
                auto tls = pe.tls();
                CHECK(tls != nullptr);
            }
        }
    }

    SUBCASE("TLS 64-bit") {
        fs::path file_path = corpus_path / "tls64.exe";
        if (!file_exists(file_path)) {
            MESSAGE("Skipping test - file not found");
            return;
        }

        auto data = load_file(file_path);
        if (!data.empty()) {
            auto pe = pe_file::from_memory(data);
            CHECK(pe.is_64bit());
            if (pe.has_data_directory(directory_entry::TLS)) {
                auto tls = pe.tls();
                CHECK(tls != nullptr);
            }
        }
    }
}

// =============================================================================
// Delay Import Directory Tests
// =============================================================================

TEST_CASE("Corkami - Delay import directory parsing") {
    fs::path corpus_path(CORKAMI_PATH);

    SUBCASE("Delay imports") {
        fs::path file_path = corpus_path / "delayimports.exe";
        if (!file_exists(file_path)) {
            MESSAGE("Skipping test - file not found");
            return;
        }

        auto data = load_file(file_path);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        if (pe.has_data_directory(directory_entry::DELAY_IMPORT)) {
            auto delay = pe.delay_imports();
            REQUIRE(delay != nullptr);
            CHECK(delay->dll_count() > 0);
            MESSAGE("Delay import DLLs: ", delay->dll_count());
        }
    }
}

// =============================================================================
// Bound Import Directory Tests
// =============================================================================

TEST_CASE("Corkami - Bound import directory parsing") {
    fs::path corpus_path(CORKAMI_PATH);

    SUBCASE("Bound imports") {
        fs::path file_path = corpus_path / "dllbound.dll";
        if (!file_exists(file_path)) {
            MESSAGE("Skipping test - file not found");
            return;
        }

        auto data = load_file(file_path);
        if (!data.empty()) {
            auto pe = pe_file::from_memory(data);
            if (pe.has_data_directory(directory_entry::BOUND_IMPORT)) {
                auto bound = pe.bound_imports();
                REQUIRE(bound != nullptr);
                CHECK(bound->descriptors.size() > 0);
            }
        }
    }
}

// =============================================================================
// Base Relocation Tests
// =============================================================================

TEST_CASE("Corkami - Base relocation parsing") {
    fs::path corpus_path(CORKAMI_PATH);

    SUBCASE("Standard relocations") {
        fs::path file_path = corpus_path / "ibreloc.exe";
        if (!file_exists(file_path)) {
            MESSAGE("Skipping test - file not found");
            return;
        }

        auto data = load_file(file_path);
        if (!data.empty()) {
            auto pe = pe_file::from_memory(data);
            if (pe.has_data_directory(directory_entry::BASERELOC)) {
                auto relocs = pe.relocations();
                REQUIRE(relocs != nullptr);
                CHECK(relocs->block_count() > 0);
                MESSAGE("Relocation blocks: ", relocs->block_count());
            }
        }
    }

    SUBCASE("No relocations") {
        fs::path file_path = corpus_path / "dllnoreloc.dll";
        if (!file_exists(file_path)) {
            MESSAGE("Skipping test - file not found");
            return;
        }

        auto data = load_file(file_path);
        if (!data.empty()) {
            auto pe = pe_file::from_memory(data);
            auto relocs = pe.relocations();
            CHECK(relocs != nullptr);
            // DLL with no relocations
        }
    }
}

// =============================================================================
// Debug Directory Tests
// =============================================================================

TEST_CASE("Corkami - Debug directory parsing") {
    fs::path corpus_path(CORKAMI_PATH);

    SUBCASE("Debug info") {
        fs::path file_path = corpus_path / "debug.exe";
        if (!file_exists(file_path)) {
            MESSAGE("Skipping test - file not found");
            return;
        }

        auto data = load_file(file_path);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        if (pe.has_data_directory(directory_entry::DEBUG)) {
            auto debug = pe.debug();
            REQUIRE(debug != nullptr);
            CHECK(debug->entries.size() > 0);
            MESSAGE("Debug entries: ", debug->entries.size());
        }
    }
}

// =============================================================================
// Security Directory Tests
// =============================================================================

TEST_CASE("Corkami - Security directory parsing") {
    fs::path corpus_path(CORKAMI_PATH);

    SUBCASE("Authenticode signature") {
        fs::path file_path = corpus_path / "signature.exe";
        if (!file_exists(file_path)) {
            MESSAGE("Skipping test - file not found");
            return;
        }

        auto data = load_file(file_path);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        if (pe.has_data_directory(directory_entry::SECURITY)) {
            auto security = pe.security();
            REQUIRE(security != nullptr);
            CHECK(security->certificate_count() > 0);
            MESSAGE("Certificates: ", security->certificate_count());

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
    fs::path corpus_path(CORKAMI_PATH);

    SUBCASE(".NET 2.0 assembly") {
        fs::path file_path = corpus_path / "dotnet20.exe";
        if (!file_exists(file_path)) {
            MESSAGE("Skipping test - file not found");
            return;
        }

        auto data = load_file(file_path);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);
        CHECK(pe.has_data_directory(directory_entry::COM_DESCRIPTOR));

        auto clr = pe.clr_header();
        REQUIRE(clr != nullptr);
        CHECK(clr->is_valid());
        MESSAGE("CLR Runtime Version: ", clr->runtime_version());
        CHECK(clr->metadata_rva != 0);
        CHECK(clr->metadata_size > 0);
    }

    SUBCASE("Tiny .NET") {
        fs::path file_path = corpus_path / "tinynet.exe";
        if (!file_exists(file_path)) {
            MESSAGE("Skipping test - file not found");
            return;
        }

        auto data = load_file(file_path);
        if (!data.empty()) {
            auto pe = pe_file::from_memory(data);
            if (pe.has_data_directory(directory_entry::COM_DESCRIPTOR)) {
                auto clr = pe.clr_header();
                CHECK(clr != nullptr);
                if (clr->is_valid()) {
                    MESSAGE("Tiny .NET - Runtime: ", clr->runtime_version());
                }
            }
        }
    }
}

// =============================================================================
// Load Config Directory Tests
// =============================================================================

TEST_CASE("Corkami - Load config directory parsing") {
    fs::path corpus_path(CORKAMI_PATH);

    SUBCASE("SEH/CFG config") {
        fs::path file_path = corpus_path / "cfgbogus.exe";
        if (!file_exists(file_path)) {
            MESSAGE("Skipping test - file not found");
            return;
        }

        auto data = load_file(file_path);
        if (!data.empty()) {
            auto pe = pe_file::from_memory(data);
            if (pe.has_data_directory(directory_entry::LOAD_CONFIG)) {
                auto cfg = pe.load_config();
                REQUIRE(cfg != nullptr);
                CHECK_FALSE(cfg->is_empty());
            }
        }
    }
}

// =============================================================================
// Multi-Parser Integration Test
// =============================================================================

TEST_CASE("Corkami - Multi-parser integration") {
    fs::path corpus_path(CORKAMI_PATH);

    SUBCASE("Complex PE with multiple directories") {
        fs::path file_path = corpus_path / "compiled.exe";
        if (!file_exists(file_path)) {
            MESSAGE("Skipping test - file not found");
            return;
        }

        auto data = load_file(file_path);
        REQUIRE_FALSE(data.empty());

        auto pe = pe_file::from_memory(data);

        MESSAGE("PE format: ", pe.is_64bit() ? "PE32+" : "PE32");
        MESSAGE("Sections: ", pe.section_count());

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
            MESSAGE("Imported DLLs: ", imports->dll_count());
        }

        if (pe.has_data_directory(directory_entry::DEBUG)) {
            MESSAGE("Debug entries: ", debug->entries.size());
        }
    }
}
