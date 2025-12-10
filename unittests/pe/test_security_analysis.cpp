// Test PE security analysis (ASLR/DEP/CFG) and import/export analysis
#include <doctest/doctest.h>
#include <libexe/formats/pe_file.hpp>
#include <libexe/pe/types.hpp>
#include <libexe/pe/directories/import.hpp>
#include <libexe/pe/directories/export.hpp>
#include <libexe/pe/directories/load_config.hpp>
#include <libexe/core/entropy.hpp>
#include <vector>

using namespace libexe;

// External test data - 64-bit PE with modern security features
namespace data {
    extern size_t tcmadm64_len;
    extern unsigned char tcmadm64[];
}

namespace {

std::vector<uint8_t> load_tcmadm64() {
    return std::vector<uint8_t>(
        data::tcmadm64,
        data::tcmadm64 + data::tcmadm64_len
    );
}

} // anonymous namespace

// =============================================================================
// Security Feature Analysis Tests
// =============================================================================

TEST_CASE("PE Security Analysis: TCMADM64.EXE (modern 64-bit PE)") {
    auto data = load_tcmadm64();
    auto pe = pe_file::from_memory(data);

    SUBCASE("ASLR detection") {
        // Modern Windows executables should have ASLR enabled
        // Check DllCharacteristics for DYNAMIC_BASE (0x0040)
        bool has_aslr = pe.has_aslr();
        MESSAGE("ASLR enabled: ", has_aslr);
        // Most modern PEs have ASLR, but test data may vary
    }

    SUBCASE("High-entropy ASLR detection") {
        // 64-bit PEs can use high-entropy ASLR for better randomization
        bool has_he_aslr = pe.has_high_entropy_aslr();
        MESSAGE("High-entropy ASLR enabled: ", has_he_aslr);
    }

    SUBCASE("DEP/NX detection") {
        // NX_COMPAT (0x0100) - Data Execution Prevention
        bool has_dep = pe.has_dep();
        MESSAGE("DEP/NX enabled: ", has_dep);
    }

    SUBCASE("CFG detection") {
        // GUARD_CF (0x4000) - Control Flow Guard
        bool has_cfg = pe.has_cfg();
        MESSAGE("CFG enabled: ", has_cfg);
    }

    SUBCASE("SEH analysis") {
        // NO_SEH flag or SafeSEH via load config
        bool no_seh = pe.has_no_seh();
        bool safe_seh = pe.has_safe_seh();
        MESSAGE("NO_SEH flag: ", no_seh);
        MESSAGE("SafeSEH enabled: ", safe_seh);

        // 64-bit executables don't use SafeSEH (it's 32-bit only)
        CHECK(pe.is_64bit());
        CHECK_FALSE(safe_seh);  // Always false for 64-bit
    }

    SUBCASE("Authenticode signature detection") {
        bool has_sig = pe.has_authenticode();
        MESSAGE("Authenticode signature present: ", has_sig);
    }

    SUBCASE(".NET assembly detection") {
        bool is_dotnet = pe.is_dotnet();
        MESSAGE("Is .NET assembly: ", is_dotnet);
        // TCMADM64 is native code, not .NET
        CHECK_FALSE(is_dotnet);
    }

    SUBCASE("File type detection") {
        bool is_dll = pe.is_dll();
        bool is_laa = pe.is_large_address_aware();

        MESSAGE("Is DLL: ", is_dll);
        MESSAGE("Large Address Aware: ", is_laa);

        // TCMADM64 is an executable, not a DLL
        CHECK_FALSE(is_dll);
        // 64-bit PEs are inherently large-address aware
        CHECK(is_laa);
    }

    SUBCASE("AppContainer and Terminal Server") {
        bool is_appcontainer = pe.is_appcontainer();
        bool is_ts_aware = pe.is_terminal_server_aware();

        MESSAGE("AppContainer: ", is_appcontainer);
        MESSAGE("Terminal Server Aware: ", is_ts_aware);
    }

    SUBCASE("Force integrity") {
        bool force_integrity = pe.has_force_integrity();
        MESSAGE("Force Integrity: ", force_integrity);
    }

    SUBCASE("Subsystem detection") {
        bool is_gui = pe.is_gui();
        bool is_console = pe.is_console();
        bool is_native = pe.is_native();
        bool is_efi = pe.is_efi();

        MESSAGE("Is GUI: ", is_gui);
        MESSAGE("Is Console: ", is_console);
        MESSAGE("Is Native: ", is_native);
        MESSAGE("Is EFI: ", is_efi);

        // TCMADM64.EXE is a GUI application
        CHECK(is_gui);
        CHECK_FALSE(is_console);
        CHECK_FALSE(is_native);
        CHECK_FALSE(is_efi);

        // Subsystem enum value should match
        CHECK(pe.subsystem() == pe_subsystem::WINDOWS_GUI);
    }
}

TEST_CASE("PE Security Analysis: DllCharacteristics flags") {
    auto data = load_tcmadm64();
    auto pe = pe_file::from_memory(data);

    // Get raw DllCharacteristics for verification
    auto dll_char = pe.dll_characteristics();

    SUBCASE("Flag consistency check") {
        // Verify that helper methods match raw flag checks
        bool aslr_via_helper = pe.has_aslr();
        bool aslr_via_flag = has_flag(dll_char, pe_dll_characteristics::DYNAMIC_BASE);
        CHECK(aslr_via_helper == aslr_via_flag);

        bool dep_via_helper = pe.has_dep();
        bool dep_via_flag = has_flag(dll_char, pe_dll_characteristics::NX_COMPAT);
        CHECK(dep_via_helper == dep_via_flag);

        bool cfg_via_helper = pe.has_cfg();
        bool cfg_via_flag = has_flag(dll_char, pe_dll_characteristics::GUARD_CF);
        CHECK(cfg_via_helper == cfg_via_flag);
    }
}

// =============================================================================
// Import Analysis Tests
// =============================================================================

TEST_CASE("PE Import Analysis: TCMADM64.EXE") {
    auto data = load_tcmadm64();
    auto pe = pe_file::from_memory(data);

    SUBCASE("Imported DLLs list") {
        auto dlls = pe.imported_dlls();
        MESSAGE("Number of imported DLLs: ", dlls.size());

        CHECK(dlls.size() > 0);

        for (const auto& dll : dlls) {
            MESSAGE("  Imports from: ", dll);
        }
    }

    SUBCASE("Import function count") {
        size_t count = pe.imported_function_count();
        MESSAGE("Total imported functions: ", count);
        CHECK(count > 0);
    }

    SUBCASE("Check for specific DLL imports") {
        // Windows executables typically import from kernel32.dll
        bool imports_kernel32 = pe.imports_dll("kernel32.dll");
        bool imports_kernel32_upper = pe.imports_dll("KERNEL32.DLL");
        bool imports_kernel32_mixed = pe.imports_dll("Kernel32.dll");

        MESSAGE("Imports kernel32.dll: ", imports_kernel32);

        // Case-insensitive comparison should work
        CHECK(imports_kernel32 == imports_kernel32_upper);
        CHECK(imports_kernel32 == imports_kernel32_mixed);
    }

    SUBCASE("Check for specific function imports") {
        // Look for common Windows API functions
        bool imports_exitprocess = pe.imports_function("ExitProcess");
        bool imports_getlasterror = pe.imports_function("GetLastError");

        MESSAGE("Imports ExitProcess: ", imports_exitprocess);
        MESSAGE("Imports GetLastError: ", imports_getlasterror);
    }

    SUBCASE("Check for function from specific DLL") {
        // More precise check: function from specific DLL
        bool exitprocess_from_kernel32 = pe.imports_function("kernel32.dll", "ExitProcess");
        MESSAGE("ExitProcess from kernel32.dll: ", exitprocess_from_kernel32);
    }

    SUBCASE("Full import directory access") {
        auto imports = pe.imports();
        if (imports) {
            MESSAGE("Import directory parsed successfully");
            MESSAGE("  DLL count: ", imports->dll_count());
            MESSAGE("  Total imports: ", imports->total_imports());
            MESSAGE("  Has bound imports: ", imports->has_bound_imports());

            CHECK(imports->dll_count() == pe.imported_dlls().size());
        }
    }
}

// =============================================================================
// Export Analysis Tests
// =============================================================================

TEST_CASE("PE Export Analysis: TCMADM64.EXE") {
    auto data = load_tcmadm64();
    auto pe = pe_file::from_memory(data);

    SUBCASE("Exported functions list") {
        auto exports = pe.exported_functions();
        MESSAGE("Number of exported functions: ", exports.size());

        // TCMADM64.EXE is an executable, may not have exports
        for (const auto& name : exports) {
            MESSAGE("  Exports: ", name);
        }
    }

    SUBCASE("Export function count") {
        size_t count = pe.exported_function_count();
        MESSAGE("Total exported functions: ", count);
    }

    SUBCASE("Full export directory access") {
        auto exports = pe.exports();
        if (exports && exports->export_count() > 0) {
            MESSAGE("Export directory parsed successfully");
            MESSAGE("  Module name: ", exports->module_name);
            MESSAGE("  Export count: ", exports->export_count());
            MESSAGE("  Named exports: ", exports->named_export_count());
            MESSAGE("  Forwarder count: ", exports->forwarder_count());
            MESSAGE("  Ordinal base: ", exports->ordinal_base);
        }
    }
}

// =============================================================================
// Combined Security Report Tests
// =============================================================================

TEST_CASE("PE Security Report: comprehensive analysis") {
    auto data = load_tcmadm64();
    auto pe = pe_file::from_memory(data);

    MESSAGE("=== Security Analysis Report ===");
    MESSAGE("File: TCMADM64.EXE");
    MESSAGE("Format: ", pe.format_name());
    MESSAGE("");

    MESSAGE("Security Features:");
    MESSAGE("  ASLR:              ", pe.has_aslr() ? "Enabled" : "Disabled");
    MESSAGE("  High-Entropy ASLR: ", pe.has_high_entropy_aslr() ? "Enabled" : "Disabled");
    MESSAGE("  DEP/NX:            ", pe.has_dep() ? "Enabled" : "Disabled");
    MESSAGE("  CFG:               ", pe.has_cfg() ? "Enabled" : "Disabled");
    MESSAGE("  SafeSEH:           ", pe.has_safe_seh() ? "Enabled" : "N/A (64-bit)");
    MESSAGE("  NO_SEH:            ", pe.has_no_seh() ? "Yes" : "No");
    MESSAGE("  Force Integrity:   ", pe.has_force_integrity() ? "Yes" : "No");
    MESSAGE("  Authenticode:      ", pe.has_authenticode() ? "Present" : "Not present");
    MESSAGE("");

    MESSAGE("File Properties:");
    MESSAGE("  Is DLL:            ", pe.is_dll() ? "Yes" : "No");
    MESSAGE("  Is .NET:           ", pe.is_dotnet() ? "Yes" : "No");
    MESSAGE("  Large Addr Aware:  ", pe.is_large_address_aware() ? "Yes" : "No");
    MESSAGE("  AppContainer:      ", pe.is_appcontainer() ? "Yes" : "No");
    MESSAGE("  TS Aware:          ", pe.is_terminal_server_aware() ? "Yes" : "No");
    MESSAGE("");

    MESSAGE("Subsystem:");
    MESSAGE("  Is GUI:            ", pe.is_gui() ? "Yes" : "No");
    MESSAGE("  Is Console:        ", pe.is_console() ? "Yes" : "No");
    MESSAGE("  Is Native:         ", pe.is_native() ? "Yes" : "No");
    MESSAGE("  Is EFI:            ", pe.is_efi() ? "Yes" : "No");
    MESSAGE("");

    MESSAGE("Import/Export Summary:");
    MESSAGE("  Imported DLLs:     ", pe.imported_dlls().size());
    MESSAGE("  Imported functions:", pe.imported_function_count());
    MESSAGE("  Exported functions:", pe.exported_function_count());

    // Basic sanity checks
    CHECK(pe.is_64bit());
    CHECK_FALSE(pe.is_dll());
    CHECK_FALSE(pe.is_dotnet());
}

// =============================================================================
// Entropy Analysis Tests
// =============================================================================

TEST_CASE("PE Entropy Analysis: TCMADM64.EXE") {
    auto data = load_tcmadm64();
    auto pe = pe_file::from_memory(data);

    SUBCASE("File entropy") {
        double entropy = pe.file_entropy();
        MESSAGE("File entropy: ", entropy, " bits");

        // File entropy should be reasonable (not empty, not random)
        CHECK(entropy > 0.0);
        CHECK(entropy <= 8.0);
    }

    SUBCASE("Section entropies") {
        auto section_entropies = pe.all_section_entropies();

        MESSAGE("Section entropies:");
        for (const auto& [name, entropy] : section_entropies) {
            MESSAGE("  ", name, ": ", entropy, " bits (",
                   entropy_calculator::classify(entropy), ")");
        }

        CHECK(section_entropies.size() > 0);
    }

    SUBCASE("Individual section entropy") {
        // .text section typically has moderate entropy (compiled code)
        double text_entropy = pe.section_entropy(".text");
        MESSAGE(".text entropy: ", text_entropy, " bits");

        // Code typically has entropy between 5-7
        if (text_entropy > 0.0) {
            CHECK(text_entropy >= 4.0);
            CHECK(text_entropy <= 8.0);
        }
    }

    SUBCASE("High entropy detection") {
        bool has_high = pe.has_high_entropy_sections();
        MESSAGE("Has high entropy sections: ", has_high);

        // TCMADM64 is a normal executable, should not have very high entropy
        // (If it does, it might have embedded resources or data)
    }

    SUBCASE("Packing detection") {
        bool likely_packed = pe.is_likely_packed();
        MESSAGE("Likely packed: ", likely_packed);

        // TCMADM64 is a normal executable, should not be detected as packed
        CHECK_FALSE(likely_packed);
    }
}

TEST_CASE("Entropy Calculator: Unit Tests") {
    SUBCASE("Empty data") {
        std::vector<uint8_t> empty;
        double entropy = entropy_calculator::calculate(empty);
        CHECK(entropy == 0.0);
    }

    SUBCASE("Single byte repeated") {
        std::vector<uint8_t> uniform(1000, 0x00);
        double entropy = entropy_calculator::calculate(uniform);
        MESSAGE("Uniform data entropy: ", entropy);
        CHECK(entropy == 0.0);  // All same bytes = 0 entropy
    }

    SUBCASE("Two byte values") {
        std::vector<uint8_t> two_values;
        for (int i = 0; i < 500; ++i) {
            two_values.push_back(0x00);
            two_values.push_back(0xFF);
        }
        double entropy = entropy_calculator::calculate(two_values);
        MESSAGE("Two values entropy: ", entropy);
        CHECK(entropy == doctest::Approx(1.0).epsilon(0.01));  // log2(2) = 1
    }

    SUBCASE("Maximum entropy (random)") {
        // Perfectly uniform distribution of all 256 byte values
        std::vector<uint8_t> uniform_dist;
        for (int i = 0; i < 256; ++i) {
            uniform_dist.push_back(static_cast<uint8_t>(i));
        }
        double entropy = entropy_calculator::calculate(uniform_dist);
        MESSAGE("Uniform distribution entropy: ", entropy);
        CHECK(entropy == doctest::Approx(8.0).epsilon(0.01));  // log2(256) = 8
    }

    SUBCASE("Classification") {
        CHECK(std::string(entropy_calculator::classify(0.0)) == "Very Low (sparse/empty)");
        CHECK(std::string(entropy_calculator::classify(4.0)) == "Low (text/sparse data)");
        CHECK(std::string(entropy_calculator::classify(6.0)) == "Normal (code/data)");
        CHECK(std::string(entropy_calculator::classify(7.5)) == "High (packed/compressed)");
        CHECK(std::string(entropy_calculator::classify(7.95)) == "Very High (encrypted/random)");
    }
}

// =============================================================================
// Overlay Detection Tests
// =============================================================================

TEST_CASE("PE Overlay Analysis: TCMADM64.EXE") {
    auto data = load_tcmadm64();
    auto pe = pe_file::from_memory(data);

    SUBCASE("Overlay detection") {
        bool has_overlay = pe.has_overlay();
        MESSAGE("Has overlay: ", has_overlay);

        if (has_overlay) {
            MESSAGE("Overlay offset: ", pe.overlay_offset());
            MESSAGE("Overlay size: ", pe.overlay_size(), " bytes");
            MESSAGE("Overlay entropy: ", pe.overlay_entropy(), " bits");

            auto overlay = pe.overlay_data();
            CHECK(overlay.size() == pe.overlay_size());
        }
    }

    SUBCASE("Overlay properties") {
        uint64_t offset = pe.overlay_offset();
        uint64_t size = pe.overlay_size();
        double entropy = pe.overlay_entropy();

        MESSAGE("Overlay offset: ", offset);
        MESSAGE("Overlay size: ", size);
        MESSAGE("Overlay entropy: ", entropy);

        // If no overlay, these should be 0
        if (!pe.has_overlay()) {
            CHECK(size == 0);
            CHECK(entropy == 0.0);
        }
    }
}

// =============================================================================
// Authenticode Signature Analysis Tests
// =============================================================================

TEST_CASE("PE Authenticode Analysis: TCMADM64.EXE") {
    auto data = load_tcmadm64();
    auto pe = pe_file::from_memory(data);

    SUBCASE("Authenticode presence") {
        bool has_sig = pe.has_authenticode();
        MESSAGE("Has Authenticode signature: ", has_sig);

        // TCMADM64.EXE should be signed
        if (has_sig) {
            MESSAGE("  Security directory size: ", pe.data_directory_size(directory_entry::SECURITY));
        }
    }

    SUBCASE("Authenticode info parsing") {
        auto info = pe.authenticode_info();

        if (info) {
            MESSAGE("Authenticode signature parsed successfully");
            MESSAGE("  Content type: ", info->content_type);
            MESSAGE("  Digest algorithm: ", hash_algorithm_name(info->digest_algorithm));
            MESSAGE("  Version: ", info->version);
            MESSAGE("  Signers: ", info->signers.size());
            MESSAGE("  Certificates: ", info->certificates.size());
            MESSAGE("  Has timestamp: ", info->has_timestamp());

            if (info->is_valid()) {
                MESSAGE("  Signature is valid Authenticode");
            }

            // Check for deprecated algorithms
            if (info->uses_deprecated_algorithm()) {
                MESSAGE("  WARNING: Uses deprecated algorithm (MD5/SHA1)");
            }
        } else {
            MESSAGE("No Authenticode signature or parsing failed");
        }
    }

    SUBCASE("Certificate chain analysis") {
        auto info = pe.authenticode_info();

        if (info && !info->certificates.empty()) {
            MESSAGE("Certificate chain:");
            for (size_t i = 0; i < info->certificates.size(); ++i) {
                const auto& cert = info->certificates[i];
                MESSAGE("  [", i, "] Subject: ", cert.subject.to_string());
                MESSAGE("       Issuer:  ", cert.issuer.to_string());
                MESSAGE("       Serial:  ", cert.serial_number);

                if (cert.is_self_signed()) {
                    MESSAGE("       (ROOT CERTIFICATE)");
                }
                if (cert.is_expired()) {
                    MESSAGE("       (EXPIRED)");
                }
            }

            // Verify chain has expected properties
            CHECK(info->certificate_chain_depth() > 0);
        }
    }

    SUBCASE("Signer information") {
        auto info = pe.authenticode_info();

        if (info && !info->signers.empty()) {
            MESSAGE("Signers:");
            for (size_t i = 0; i < info->signers.size(); ++i) {
                const auto& signer = info->signers[i];
                MESSAGE("  [", i, "] Issuer: ", signer.issuer.to_string());
                MESSAGE("       Serial: ", signer.serial_number);
                MESSAGE("       Digest: ", hash_algorithm_name(signer.digest_algorithm));

                if (signer.uses_deprecated_algorithm()) {
                    MESSAGE("       WARNING: Deprecated algorithm");
                }
            }
        }
    }

    SUBCASE("Timestamp analysis") {
        auto info = pe.authenticode_info();

        if (info && info->has_timestamp()) {
            MESSAGE("Timestamp: ", info->timestamp->to_string());
            MESSAGE("  RFC 3161: ", info->timestamp->is_rfc3161);
            MESSAGE("  Digest: ", hash_algorithm_name(info->timestamp->digest_algorithm));
        } else {
            MESSAGE("No timestamp in signature");
        }
    }

    SUBCASE("Security summary") {
        std::string summary = pe.authenticode_security_summary();
        MESSAGE("Security Summary:\n", summary);
    }

    SUBCASE("Helper method consistency") {
        auto info = pe.authenticode_info();

        // Verify helper methods match parsed info
        authenticode_hash_algorithm alg = pe.authenticode_digest_algorithm();
        MESSAGE("Digest algorithm via helper: ", hash_algorithm_name(alg));

        if (info) {
            CHECK(alg == info->digest_algorithm);
            CHECK(pe.authenticode_uses_deprecated_algorithm() == info->uses_deprecated_algorithm());
        }
    }
}

TEST_CASE("Authenticode Analyzer: ASN.1 Parsing") {
    SUBCASE("is_pkcs7_signed_data - empty data") {
        std::vector<uint8_t> empty;
        CHECK_FALSE(authenticode_analyzer::is_pkcs7_signed_data(empty));
    }

    SUBCASE("is_pkcs7_signed_data - too small") {
        std::vector<uint8_t> small = {0x30, 0x03, 0x01, 0x02, 0x03};
        CHECK_FALSE(authenticode_analyzer::is_pkcs7_signed_data(small));
    }

    SUBCASE("algorithm_from_oid") {
        CHECK(authenticode_analyzer::algorithm_from_oid("1.2.840.113549.2.5") ==
              authenticode_hash_algorithm::MD5);
        CHECK(authenticode_analyzer::algorithm_from_oid("1.3.14.3.2.26") ==
              authenticode_hash_algorithm::SHA1);
        CHECK(authenticode_analyzer::algorithm_from_oid("2.16.840.1.101.3.4.2.1") ==
              authenticode_hash_algorithm::SHA256);
        CHECK(authenticode_analyzer::algorithm_from_oid("2.16.840.1.101.3.4.2.2") ==
              authenticode_hash_algorithm::SHA384);
        CHECK(authenticode_analyzer::algorithm_from_oid("2.16.840.1.101.3.4.2.3") ==
              authenticode_hash_algorithm::SHA512);
        CHECK(authenticode_analyzer::algorithm_from_oid("unknown") ==
              authenticode_hash_algorithm::UNKNOWN);
    }

    SUBCASE("hash_algorithm_name") {
        CHECK(std::string(hash_algorithm_name(authenticode_hash_algorithm::MD5)) == "MD5");
        CHECK(std::string(hash_algorithm_name(authenticode_hash_algorithm::SHA1)) == "SHA1");
        CHECK(std::string(hash_algorithm_name(authenticode_hash_algorithm::SHA256)) == "SHA256");
        CHECK(std::string(hash_algorithm_name(authenticode_hash_algorithm::SHA384)) == "SHA384");
        CHECK(std::string(hash_algorithm_name(authenticode_hash_algorithm::SHA512)) == "SHA512");
        CHECK(std::string(hash_algorithm_name(authenticode_hash_algorithm::UNKNOWN)) == "Unknown");
    }
}

TEST_CASE("x509_name: String formatting") {
    x509_name name;

    SUBCASE("Empty name") {
        CHECK(name.empty());
        CHECK(name.to_string() == "");
    }

    SUBCASE("Single component") {
        name.common_name = "Test Company";
        CHECK_FALSE(name.empty());
        CHECK(name.to_string() == "CN=Test Company");
    }

    SUBCASE("Multiple components") {
        name.common_name = "Code Signer";
        name.organization = "Test Corp";
        name.country = "US";

        std::string str = name.to_string();
        CHECK(str.find("CN=Code Signer") != std::string::npos);
        CHECK(str.find("O=Test Corp") != std::string::npos);
        CHECK(str.find("C=US") != std::string::npos);
    }
}

TEST_CASE("authenticode_signer_info: Deprecated algorithm detection") {
    authenticode_signer_info signer;

    SUBCASE("MD5 is deprecated") {
        signer.digest_algorithm = authenticode_hash_algorithm::MD5;
        CHECK(signer.uses_deprecated_algorithm());
    }

    SUBCASE("SHA1 is deprecated") {
        signer.digest_algorithm = authenticode_hash_algorithm::SHA1;
        CHECK(signer.uses_deprecated_algorithm());
    }

    SUBCASE("SHA256 is not deprecated") {
        signer.digest_algorithm = authenticode_hash_algorithm::SHA256;
        CHECK_FALSE(signer.uses_deprecated_algorithm());
    }

    SUBCASE("SHA384 is not deprecated") {
        signer.digest_algorithm = authenticode_hash_algorithm::SHA384;
        CHECK_FALSE(signer.uses_deprecated_algorithm());
    }

    SUBCASE("SHA512 is not deprecated") {
        signer.digest_algorithm = authenticode_hash_algorithm::SHA512;
        CHECK_FALSE(signer.uses_deprecated_algorithm());
    }
}
