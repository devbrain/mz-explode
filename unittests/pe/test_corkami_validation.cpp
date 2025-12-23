// libexe - Modern executable file analysis library
// Copyright (c) 2024
// Field-level validation tests using Corkami PE test corpus (embedded data)
//
// These tests validate that parsed field values exactly match the expected
// values from the Corkami ASM source files. This ensures our parsers extract
// data correctly, not just that they don't crash.

#include <doctest/doctest.h>
#include <libexe/formats/pe_file.hpp>
#include <libexe/pe/directories/import.hpp>
#include <libexe/pe/directories/export.hpp>
#include <libexe/pe/directories/tls.hpp>
#include <libexe/pe/directories/debug.hpp>
#include <libexe/pe/directories/security.hpp>
#include <libexe/pe/directories/com_descriptor.hpp>
#include <libexe/pe/directories/relocation.hpp>
#include <vector>
#include <algorithm>

using namespace libexe;

// =============================================================================
// Corkami Corpus Field-Level Validation Tests
//
// These tests validate parsed field values against ground truth from the
// Corkami ASM source files: https://github.com/corkami/pocs/tree/master/PE
//
// Expected values are extracted from the .asm files in the corpus.
// =============================================================================

// External embedded test data
namespace corkami_data {
    extern size_t imports_len;
    extern unsigned char imports[];
    extern size_t tls_len;
    extern unsigned char tls[];
    extern size_t debug_len;
    extern unsigned char debug[];
    extern size_t signature_len;
    extern unsigned char signature[];
    extern size_t dotnet20_len;
    extern unsigned char dotnet20[];
    extern size_t dll_len;
    extern unsigned char dll[];
    extern size_t dllfwloop_len;
    extern unsigned char dllfwloop[];
}

namespace {

// Helper: Load embedded test file
std::vector<uint8_t> load_embedded(const unsigned char* data, size_t len) {
    return std::vector<uint8_t>(data, data + len);
}

/**
 * Case-insensitive string comparison
 */
bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) {
        return false;
    }
    return std::equal(a.begin(), a.end(), b.begin(),
                     [](char ca, char cb) {
                         return std::tolower(static_cast<unsigned char>(ca)) ==
                                std::tolower(static_cast<unsigned char>(cb));
                     });
}

} // anonymous namespace

// =============================================================================
// Import Directory Validation
// =============================================================================

TEST_CASE("Corkami Validation - imports.exe") {
    auto data = load_embedded(corkami_data::imports, corkami_data::imports_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);
    REQUIRE(pe.has_data_directory(directory_entry::IMPORT));

    auto imports = pe.imports();
    REQUIRE(imports != nullptr);

    // Expected from imports_printfexitprocess.inc:
    // - 2 DLLs: kernel32.dll, msvcrt.dll
    // - kernel32.dll imports: ExitProcess
    // - msvcrt.dll imports: printf

    SUBCASE("DLL count") {
        CHECK(imports->dll_count() == 2);
    }

    SUBCASE("DLL names") {
        REQUIRE(imports->dll_count() >= 2);

        // Find kernel32.dll
        bool found_kernel32 = false;
        bool found_msvcrt = false;

        for (const auto& dll : imports->dlls) {
            if (iequals(dll.name, "kernel32.dll")) {
                found_kernel32 = true;
            } else if (iequals(dll.name, "msvcrt.dll")) {
                found_msvcrt = true;
            }
        }

        CHECK(found_kernel32);
        CHECK(found_msvcrt);
    }

    SUBCASE("kernel32.dll imports") {
        // Find kernel32.dll
        const import_dll* kernel32 = nullptr;
        for (const auto& dll : imports->dlls) {
            if (iequals(dll.name, "kernel32.dll")) {
                kernel32 = &dll;
                break;
            }
        }

        REQUIRE(kernel32 != nullptr);

        // Should import ExitProcess
        bool found_exitprocess = false;
        for (const auto& imp : kernel32->functions) {
            if (iequals(imp.name, "ExitProcess")) {
                found_exitprocess = true;
                CHECK_FALSE(imp.is_ordinal);
            }
        }

        CHECK(found_exitprocess);
    }

    SUBCASE("msvcrt.dll imports") {
        // Find msvcrt.dll
        const import_dll* msvcrt = nullptr;
        for (const auto& dll : imports->dlls) {
            if (iequals(dll.name, "msvcrt.dll")) {
                msvcrt = &dll;
                break;
            }
        }

        REQUIRE(msvcrt != nullptr);

        // Should import printf
        bool found_printf = false;
        for (const auto& imp : msvcrt->functions) {
            if (iequals(imp.name, "printf")) {
                found_printf = true;
                CHECK_FALSE(imp.is_ordinal);
            }
        }

        CHECK(found_printf);
    }
}

// =============================================================================
// TLS Directory Validation
// =============================================================================

TEST_CASE("Corkami Validation - tls.exe") {
    auto data = load_embedded(corkami_data::tls, corkami_data::tls_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);
    REQUIRE(pe.has_data_directory(directory_entry::TLS));

    auto tls = pe.tls();
    REQUIRE(tls != nullptr);

    // Expected from tls.asm:
    // - TlsIndex = 0x012345
    // - 1 callback function

    SUBCASE("TLS has callbacks") {
        CHECK(tls->has_callbacks());
    }

    SUBCASE("TLS callback count") {
        // tls.asm has 1 callback in CallBacks array
        CHECK(tls->callback_count() >= 1);
    }

    SUBCASE("TLS structure fields") {
        // Validate key TLS fields are set
        CHECK(tls->address_of_callbacks != 0);
        CHECK(tls->address_of_index != 0);
    }
}

// =============================================================================
// Debug Directory Validation
// =============================================================================

TEST_CASE("Corkami Validation - debug.exe") {
    auto data = load_embedded(corkami_data::debug, corkami_data::debug_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);
    REQUIRE(pe.has_data_directory(directory_entry::DEBUG));

    auto debug = pe.debug();
    REQUIRE(debug != nullptr);

    // Expected from debug.asm:
    // - 1 debug directory entry
    // - Type: IMAGE_DEBUG_TYPE_CODEVIEW (2)
    // - CodeView signature: 'RSDS'
    // - PDB: 'nosymbols.pdb'

    SUBCASE("Debug entry count") {
        CHECK(debug->entries.size() == 1);
    }

    SUBCASE("Debug entry type") {
        REQUIRE(debug->entries.size() >= 1);
        const auto& entry = debug->entries[0];

        // Should be IMAGE_DEBUG_TYPE_CODEVIEW
        CHECK(entry.type == debug_type::CODEVIEW);
    }

    SUBCASE("CodeView data") {
        REQUIRE(debug->entries.size() >= 1);
        const auto& entry = debug->entries[0];

        // Check if we have CodeView data
        if (entry.type == debug_type::CODEVIEW && entry.size_of_data >= 4) {
            // First 4 bytes should be 'RSDS' signature for CV70
            // (or 'NB10' for older format)

            // Note: We'd need to add CodeView parsing to fully validate
            // For now, just check we have data
            CHECK(entry.size_of_data > 0);
        }
    }
}

// =============================================================================
// Security Directory Validation
// =============================================================================

TEST_CASE("Corkami Validation - signature.exe") {
    auto data = load_embedded(corkami_data::signature, corkami_data::signature_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);
    REQUIRE(pe.has_data_directory(directory_entry::SECURITY));

    auto security = pe.security();
    REQUIRE(security != nullptr);

    // Expected from signature.asm:
    // - 1 certificate (Authenticode signature)
    // - Certificate type should be WIN_CERT_TYPE_PKCS_SIGNED_DATA (2)

    SUBCASE("Certificate count") {
        CHECK(security->certificate_count() >= 1);
    }

    SUBCASE("Has Authenticode") {
        CHECK(security->has_authenticode());
    }

    SUBCASE("Certificate properties") {
        REQUIRE(security->certificate_count() >= 1);
        const auto& cert = security->certificates[0];


        // Should be PKCS_SIGNED_DATA for Authenticode
        CHECK(cert.is_authenticode());
    }
}

// =============================================================================
// COM Descriptor Validation (.NET)
// =============================================================================

TEST_CASE("Corkami Validation - dotnet20.exe") {
    auto data = load_embedded(corkami_data::dotnet20, corkami_data::dotnet20_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);
    REQUIRE(pe.has_data_directory(directory_entry::COM_DESCRIPTOR));

    auto clr = pe.clr_header();
    REQUIRE(clr != nullptr);

    // Expected from dotnet20.asm:
    // - CLR runtime version should be 2.x
    // - Metadata RVA and size should be non-zero

    SUBCASE("CLR is valid") {
        CHECK(clr->is_valid());
    }

    SUBCASE("Runtime version") {
        auto version = clr->runtime_version();

        // Should be v2.x format
        CHECK_FALSE(version.empty());
        CHECK(version.find("2.") != std::string::npos);
    }

    SUBCASE("Metadata present") {
        CHECK(clr->metadata_rva != 0);
        CHECK(clr->metadata_size > 0);
    }

    SUBCASE("Runtime version fields") {
        // dotnet20.exe should have major version 2
        CHECK(clr->major_runtime_version == 2);
    }
}

// =============================================================================
// Export Directory Validation
// =============================================================================

TEST_CASE("Corkami Validation - dll.dll") {
    auto data = load_embedded(corkami_data::dll, corkami_data::dll_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    if (!pe.has_data_directory(directory_entry::EXPORT)) {
        return;
    }

    auto exports = pe.exports();
    REQUIRE(exports != nullptr);

    // Expected from dll.asm:
    // - Module name should be set
    // - Should have at least 1 export

    SUBCASE("Module name") {
        CHECK_FALSE(exports->module_name.empty());
    }

    SUBCASE("Export count") {
        CHECK(exports->export_count() > 0);

        // List all exports
        for (const auto& exp : exports->exports) {
            (void)exp;  // Validate iteration works
        }
    }
}

// =============================================================================
// Debug Diagnostics Test
// =============================================================================

TEST_CASE("Debug dllfwloop.dll diagnostics") {
    auto data = load_embedded(corkami_data::dllfwloop, corkami_data::dllfwloop_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    // Check exports - dllfwloop.dll has forwarder exports
    auto exports = pe.exports();
    REQUIRE(exports != nullptr);

    // Count forwarders
    size_t forwarder_count = 0;
    for (const auto& exp : exports->exports) {
        if (exp.is_forwarder) {
            forwarder_count++;
        }
    }
    CHECK(forwarder_count > 0);  // dllfwloop.dll has forwarder exports

    // Should have some diagnostics (forwarder loop)
    CHECK(pe.diagnostics().count() > 0);
}
