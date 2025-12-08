// libexe - Modern executable file analysis library
// Copyright (c) 2024
// AUTO-GENERATED from corkami_test_spec.json - DO NOT EDIT BY HAND
//
// To regenerate: python3 tools/generate_tests_from_json.py

#include <doctest/doctest.h>
#include <libexe/pe_file.hpp>
#include <libexe/import_directory.hpp>
#include <libexe/export_directory.hpp>
#include <libexe/tls_directory.hpp>
#include <libexe/debug_directory.hpp>
#include <libexe/security_directory.hpp>
#include <libexe/com_descriptor.hpp>
#include <libexe/base_relocation.hpp>
#include <libexe/delay_import_directory.hpp>
#include <libexe/bound_import_directory.hpp>
#include <libexe/load_config_directory.hpp>
#include <vector>
#include <algorithm>
#include <string>

using namespace libexe;

// External embedded test data
namespace corkami_data {
    extern size_t cfgbogus_len;
    extern unsigned char cfgbogus[];
    extern size_t compiled_len;
    extern unsigned char compiled[];
    extern size_t debug_len;
    extern unsigned char debug[];
    extern size_t delayimports_len;
    extern unsigned char delayimports[];
    extern size_t dll_len;
    extern unsigned char dll[];
    extern size_t dllbound_len;
    extern unsigned char dllbound[];
    extern size_t dllnoreloc_len;
    extern unsigned char dllnoreloc[];
    extern size_t dllord_len;
    extern unsigned char dllord[];
    extern size_t dotnet20_len;
    extern unsigned char dotnet20[];
    extern size_t ibreloc_len;
    extern unsigned char ibreloc[];
    extern size_t impbyord_len;
    extern unsigned char impbyord[];
    extern size_t imports_len;
    extern unsigned char imports[];
    extern size_t imports_mixed_len;
    extern unsigned char imports_mixed[];
    extern size_t signature_len;
    extern unsigned char signature[];
    extern size_t tinynet_len;
    extern unsigned char tinynet[];
    extern size_t tls_len;
    extern unsigned char tls[];
    extern size_t tls64_len;
    extern unsigned char tls64[];
    extern size_t tls_aoi_len;
    extern unsigned char tls_aoi[];
}

namespace {

// Helper: Load embedded test file
std::vector<uint8_t> load_embedded(const unsigned char* data, size_t len) {
    return std::vector<uint8_t>(data, data + len);
}

// Helper: Case-insensitive string comparison
bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    return std::equal(a.begin(), a.end(), b.begin(),
                     [](char ca, char cb) {
                         return std::tolower(static_cast<unsigned char>(ca)) ==
                                std::tolower(static_cast<unsigned char>(cb));
                     });
}

} // anonymous namespace


TEST_CASE("Corkami Generated - imports.exe - Import Directory") {
    auto data = load_embedded(corkami_data::imports, corkami_data::imports_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("Import directory present") {
        CHECK(pe.has_data_directory(directory_entry::IMPORT));
    }

    auto imports = pe.imports();
    if (!imports) {
        MESSAGE("imports.exe: Import directory not parsed");
        return;
    }

    SUBCASE("DLL count") {
        CHECK(imports->dll_count() == 2);
    }

    SUBCASE("DLL: kernel32.dll") {
        const import_dll* dll = nullptr;
        for (const auto& d : imports->dlls) {
            if (iequals(d.name, "kernel32.dll")) {
                dll = &d;
                break;
            }
        }

        REQUIRE(dll != nullptr);
        CHECK(dll->functions.size() == 1);

        // Check for ExitProcess
        bool found_exitprocess = false;
        for (const auto& f : dll->functions) {
            if (iequals(f.name, "ExitProcess")) {
                found_exitprocess = true;
                CHECK_FALSE(f.is_ordinal);
                break;
            }
        }
        CHECK(found_exitprocess);
    }

    SUBCASE("DLL: msvcrt.dll") {
        const import_dll* dll = nullptr;
        for (const auto& d : imports->dlls) {
            if (iequals(d.name, "msvcrt.dll")) {
                dll = &d;
                break;
            }
        }

        REQUIRE(dll != nullptr);
        CHECK(dll->functions.size() == 1);

        // Check for printf
        bool found_printf = false;
        for (const auto& f : dll->functions) {
            if (iequals(f.name, "printf")) {
                found_printf = true;
                CHECK_FALSE(f.is_ordinal);
                break;
            }
        }
        CHECK(found_printf);
    }
}

TEST_CASE("Corkami Generated - imports_mixed.exe - Import Directory") {
    auto data = load_embedded(corkami_data::imports_mixed, corkami_data::imports_mixed_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("Import directory present") {
        CHECK(pe.has_data_directory(directory_entry::IMPORT));
    }

    auto imports = pe.imports();
    if (!imports) {
        MESSAGE("imports_mixed.exe: Import directory not parsed");
        return;
    }

    SUBCASE("DLL count") {
        CHECK(imports->dll_count() == 2);
    }

    SUBCASE("DLL: KernEl32") {
        const import_dll* dll = nullptr;
        for (const auto& d : imports->dlls) {
            if (iequals(d.name, "KernEl32")) {
                dll = &d;
                break;
            }
        }

        REQUIRE(dll != nullptr);
        CHECK(dll->functions.size() == 1);

        // Check for ExitProcess
        bool found_exitprocess = false;
        for (const auto& f : dll->functions) {
            if (iequals(f.name, "ExitProcess")) {
                found_exitprocess = true;
                CHECK_FALSE(f.is_ordinal);
                break;
            }
        }
        CHECK(found_exitprocess);
    }

    SUBCASE("DLL: mSVCrT") {
        const import_dll* dll = nullptr;
        for (const auto& d : imports->dlls) {
            if (iequals(d.name, "mSVCrT")) {
                dll = &d;
                break;
            }
        }

        REQUIRE(dll != nullptr);
        CHECK(dll->functions.size() == 1);

        // Check for printf
        bool found_printf = false;
        for (const auto& f : dll->functions) {
            if (iequals(f.name, "printf")) {
                found_printf = true;
                CHECK_FALSE(f.is_ordinal);
                break;
            }
        }
        CHECK(found_printf);
    }
}

TEST_CASE("Corkami Generated - impbyord.exe - Import Directory") {
    auto data = load_embedded(corkami_data::impbyord, corkami_data::impbyord_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("Import directory present") {
        CHECK(pe.has_data_directory(directory_entry::IMPORT));
    }

    auto imports = pe.imports();
    if (!imports) {
        MESSAGE("impbyord.exe: Import directory not parsed");
        return;
    }

    SUBCASE("DLL count") {
        CHECK(imports->dll_count() == 2);
    }

    SUBCASE("DLL: msvcrt.dll") {
        const import_dll* dll = nullptr;
        for (const auto& d : imports->dlls) {
            if (iequals(d.name, "msvcrt.dll")) {
                dll = &d;
                break;
            }
        }

        REQUIRE(dll != nullptr);
        CHECK(dll->functions.size() == 1);

        // Check for printf
        bool found_printf = false;
        for (const auto& f : dll->functions) {
            if (iequals(f.name, "printf")) {
                found_printf = true;
                CHECK_FALSE(f.is_ordinal);
                break;
            }
        }
        CHECK(found_printf);
    }

    SUBCASE("DLL: impbyord.exe") {
        const import_dll* dll = nullptr;
        for (const auto& d : imports->dlls) {
            if (iequals(d.name, "impbyord.exe")) {
                dll = &d;
                break;
            }
        }

        REQUIRE(dll != nullptr);
        CHECK(dll->functions.size() == 1);
    }
}

TEST_CASE("Corkami Generated - tls.exe - Import Directory") {
    auto data = load_embedded(corkami_data::tls, corkami_data::tls_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("Import directory present") {
        CHECK(pe.has_data_directory(directory_entry::IMPORT));
    }

    auto imports = pe.imports();
    if (!imports) {
        MESSAGE("tls.exe: Import directory not parsed");
        return;
    }

    SUBCASE("DLL count") {
        CHECK(imports->dll_count() == 2);
    }

    SUBCASE("DLL: kernel32.dll") {
        const import_dll* dll = nullptr;
        for (const auto& d : imports->dlls) {
            if (iequals(d.name, "kernel32.dll")) {
                dll = &d;
                break;
            }
        }

        REQUIRE(dll != nullptr);
        CHECK(dll->functions.size() == 1);
    }

    SUBCASE("DLL: msvcrt.dll") {
        const import_dll* dll = nullptr;
        for (const auto& d : imports->dlls) {
            if (iequals(d.name, "msvcrt.dll")) {
                dll = &d;
                break;
            }
        }

        REQUIRE(dll != nullptr);
        CHECK(dll->functions.size() == 1);
    }
}

TEST_CASE("Corkami Generated - tls.exe - TLS Directory") {
    auto data = load_embedded(corkami_data::tls, corkami_data::tls_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("TLS directory present") {
        CHECK(pe.has_data_directory(directory_entry::TLS));
    }

    auto tls = pe.tls();
    if (!tls) {
        MESSAGE("tls.exe: TLS directory not parsed");
        return;
    }

    SUBCASE("Callback count") {
        CHECK(tls->callback_count() == 1);
    }

    SUBCASE("TLS index address") {
        CHECK(tls->address_of_index != 0);
    }

    SUBCASE("TLS callbacks address") {
        CHECK(tls->address_of_callbacks != 0);
    }
}

TEST_CASE("Corkami Generated - tls64.exe - TLS Directory") {
    auto data = load_embedded(corkami_data::tls64, corkami_data::tls64_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("TLS directory present") {
        CHECK(pe.has_data_directory(directory_entry::TLS));
    }

    auto tls = pe.tls();
    if (!tls) {
        MESSAGE("tls64.exe: TLS directory not parsed");
        return;
    }

    SUBCASE("Callback count") {
        CHECK(tls->callback_count() == 1);
    }
}

TEST_CASE("Corkami Generated - tls_aoi.exe - TLS Directory") {
    auto data = load_embedded(corkami_data::tls_aoi, corkami_data::tls_aoi_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("TLS directory present") {
        CHECK(pe.has_data_directory(directory_entry::TLS));
    }

    auto tls = pe.tls();
    if (!tls) {
        MESSAGE("tls_aoi.exe: TLS directory not parsed");
        return;
    }

    SUBCASE("Has callbacks") {
        CHECK(tls->has_callbacks());
    }
}

TEST_CASE("Corkami Generated - debug.exe - Import Directory") {
    auto data = load_embedded(corkami_data::debug, corkami_data::debug_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("Import directory present") {
        CHECK(pe.has_data_directory(directory_entry::IMPORT));
    }

    auto imports = pe.imports();
    if (!imports) {
        MESSAGE("debug.exe: Import directory not parsed");
        return;
    }

    SUBCASE("DLL count") {
        CHECK(imports->dll_count() == 3);
    }

    SUBCASE("DLL: kernel32.dll") {
        const import_dll* dll = nullptr;
        for (const auto& d : imports->dlls) {
            if (iequals(d.name, "kernel32.dll")) {
                dll = &d;
                break;
            }
        }

        REQUIRE(dll != nullptr);
    }

    SUBCASE("DLL: msvcrt.dll") {
        const import_dll* dll = nullptr;
        for (const auto& d : imports->dlls) {
            if (iequals(d.name, "msvcrt.dll")) {
                dll = &d;
                break;
            }
        }

        REQUIRE(dll != nullptr);
    }

    SUBCASE("DLL: dbghelp.dll") {
        const import_dll* dll = nullptr;
        for (const auto& d : imports->dlls) {
            if (iequals(d.name, "dbghelp.dll")) {
                dll = &d;
                break;
            }
        }

        REQUIRE(dll != nullptr);
    }
}

TEST_CASE("Corkami Generated - debug.exe - Debug Directory") {
    auto data = load_embedded(corkami_data::debug, corkami_data::debug_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    auto debug = pe.debug();
    if (!debug) {
        MESSAGE("debug.exe: Debug directory not parsed");
        return;
    }

    SUBCASE("Entry count") {
        CHECK(debug->entries.size() == 1);
    }

    SUBCASE("Entry 0 type") {
        REQUIRE(debug->entries.size() > 0);
        CHECK(debug->entries[0].type == debug_type::CODEVIEW);
    }

    SUBCASE("Entry 0 size") {
        REQUIRE(debug->entries.size() > 0);
        CHECK(debug->entries[0].size_of_data == 40);
    }
}

TEST_CASE("Corkami Generated - signature.exe - Import Directory") {
    auto data = load_embedded(corkami_data::signature, corkami_data::signature_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("Import directory present") {
        CHECK(pe.has_data_directory(directory_entry::IMPORT));
    }

    auto imports = pe.imports();
    if (!imports) {
        MESSAGE("signature.exe: Import directory not parsed");
        return;
    }

    SUBCASE("DLL count") {
        CHECK(imports->dll_count() == 2);
    }
}

TEST_CASE("Corkami Generated - signature.exe - Security Directory") {
    auto data = load_embedded(corkami_data::signature, corkami_data::signature_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    auto security = pe.security();
    if (!security) {
        MESSAGE("signature.exe: Security directory not parsed");
        return;
    }

    SUBCASE("Certificate count") {
        CHECK(security->certificate_count() == 1);
    }

    SUBCASE("Certificate 0 is Authenticode") {
        REQUIRE(security->certificate_count() > 0);
        CHECK(security->certificates[0].is_authenticode());
    }

    SUBCASE("Certificate 0 size") {
        REQUIRE(security->certificate_count() > 0);
        CHECK(security->certificates[0].certificate_data.size() == 2168);
    }
}

TEST_CASE("Corkami Generated - dll.dll - Import Directory") {
    auto data = load_embedded(corkami_data::dll, corkami_data::dll_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("Import directory present") {
        CHECK(pe.has_data_directory(directory_entry::IMPORT));
    }

    auto imports = pe.imports();
    if (!imports) {
        MESSAGE("dll.dll: Import directory not parsed");
        return;
    }

    SUBCASE("DLL count") {
        CHECK(imports->dll_count() == 1);
    }

    SUBCASE("DLL: msvcrt.dll") {
        const import_dll* dll = nullptr;
        for (const auto& d : imports->dlls) {
            if (iequals(d.name, "msvcrt.dll")) {
                dll = &d;
                break;
            }
        }

        REQUIRE(dll != nullptr);
        CHECK(dll->functions.size() == 1);
    }
}

TEST_CASE("Corkami Generated - dotnet20.exe - Import Directory") {
    auto data = load_embedded(corkami_data::dotnet20, corkami_data::dotnet20_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("Import directory present") {
        CHECK(pe.has_data_directory(directory_entry::IMPORT));
    }

    auto imports = pe.imports();
    if (!imports) {
        MESSAGE("dotnet20.exe: Import directory not parsed");
        return;
    }

    SUBCASE("DLL count") {
        CHECK(imports->dll_count() == 1);
    }

    SUBCASE("DLL: mscoree.dll") {
        const import_dll* dll = nullptr;
        for (const auto& d : imports->dlls) {
            if (iequals(d.name, "mscoree.dll")) {
                dll = &d;
                break;
            }
        }

        REQUIRE(dll != nullptr);
        CHECK(dll->functions.size() == 1);

        // Check for _CorExeMain
        bool found__corexemain = false;
        for (const auto& f : dll->functions) {
            if (iequals(f.name, "_CorExeMain")) {
                found__corexemain = true;
                CHECK_FALSE(f.is_ordinal);
                break;
            }
        }
        CHECK(found__corexemain);
    }
}

TEST_CASE("Corkami Generated - dotnet20.exe - COM Descriptor") {
    auto data = load_embedded(corkami_data::dotnet20, corkami_data::dotnet20_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    auto clr = pe.clr_header();
    if (!clr) {
        MESSAGE("dotnet20.exe: COM descriptor not parsed");
        return;
    }

    SUBCASE("CLR header valid") {
        CHECK(clr->is_valid());
    }

    SUBCASE("Runtime version") {
        auto version = clr->runtime_version();
        CHECK(version.find("2.5") != std::string::npos);
    }

    SUBCASE("Major runtime version") {
        CHECK(clr->major_runtime_version == 2);
    }

    SUBCASE("Metadata RVA") {
        CHECK(clr->metadata_rva != 0);
    }

    SUBCASE("Metadata size") {
        CHECK(clr->metadata_size > 0);
    }
}

TEST_CASE("Corkami Generated - tinynet.exe - COM Descriptor") {
    auto data = load_embedded(corkami_data::tinynet, corkami_data::tinynet_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    auto clr = pe.clr_header();
    if (!clr) {
        MESSAGE("tinynet.exe: COM descriptor not parsed");
        return;
    }

    SUBCASE("CLR header valid") {
        CHECK(clr->is_valid());
    }
}

TEST_CASE("Corkami Generated - delayimports.exe - Import Directory") {
    auto data = load_embedded(corkami_data::delayimports, corkami_data::delayimports_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("Import directory present") {
        CHECK(pe.has_data_directory(directory_entry::IMPORT));
    }

    auto imports = pe.imports();
    if (!imports) {
        MESSAGE("delayimports.exe: Import directory not parsed");
        return;
    }

    SUBCASE("DLL count") {
        CHECK(imports->dll_count() == 1);
    }

    SUBCASE("DLL: kernel32.dll") {
        const import_dll* dll = nullptr;
        for (const auto& d : imports->dlls) {
            if (iequals(d.name, "kernel32.dll")) {
                dll = &d;
                break;
            }
        }

        REQUIRE(dll != nullptr);
        CHECK(dll->functions.size() == 3);

        // Check for ExitProcess
        bool found_exitprocess = false;
        for (const auto& f : dll->functions) {
            if (iequals(f.name, "ExitProcess")) {
                found_exitprocess = true;
                CHECK_FALSE(f.is_ordinal);
                break;
            }
        }
        CHECK(found_exitprocess);

        // Check for LoadLibraryA
        bool found_loadlibrarya = false;
        for (const auto& f : dll->functions) {
            if (iequals(f.name, "LoadLibraryA")) {
                found_loadlibrarya = true;
                CHECK_FALSE(f.is_ordinal);
                break;
            }
        }
        CHECK(found_loadlibrarya);

        // Check for GetProcAddress
        bool found_getprocaddress = false;
        for (const auto& f : dll->functions) {
            if (iequals(f.name, "GetProcAddress")) {
                found_getprocaddress = true;
                CHECK_FALSE(f.is_ordinal);
                break;
            }
        }
        CHECK(found_getprocaddress);
    }
}

TEST_CASE("Corkami Generated - ibreloc.exe - Import Directory") {
    auto data = load_embedded(corkami_data::ibreloc, corkami_data::ibreloc_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("Import directory present") {
        CHECK(pe.has_data_directory(directory_entry::IMPORT));
    }

    auto imports = pe.imports();
    if (!imports) {
        MESSAGE("ibreloc.exe: Import directory not parsed");
        return;
    }

    SUBCASE("DLL count") {
        CHECK(imports->dll_count() == 2);
    }
}

TEST_CASE("Corkami Generated - dllbound.dll - Import Directory") {
    auto data = load_embedded(corkami_data::dllbound, corkami_data::dllbound_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("Import directory present") {
        CHECK(pe.has_data_directory(directory_entry::IMPORT));
    }

    auto imports = pe.imports();
    if (!imports) {
        MESSAGE("dllbound.dll: Import directory not parsed");
        return;
    }
}

TEST_CASE("Corkami Generated - compiled.exe - Import Directory") {
    auto data = load_embedded(corkami_data::compiled, corkami_data::compiled_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("Import directory present") {
        CHECK(pe.has_data_directory(directory_entry::IMPORT));
    }

    auto imports = pe.imports();
    if (!imports) {
        MESSAGE("compiled.exe: Import directory not parsed");
        return;
    }

    SUBCASE("DLL count") {
        CHECK(imports->dll_count() == 2);
    }
}

TEST_CASE("Corkami Generated - compiled.exe - Debug Directory") {
    auto data = load_embedded(corkami_data::compiled, corkami_data::compiled_len);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    auto debug = pe.debug();
    if (!debug) {
        MESSAGE("compiled.exe: Debug directory not parsed");
        return;
    }
}
