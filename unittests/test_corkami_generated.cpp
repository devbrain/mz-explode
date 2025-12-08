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
#include <filesystem>
#include <fstream>
#include <vector>
#include <algorithm>

using namespace libexe;
namespace fs = std::filesystem;

namespace {

std::vector<uint8_t> load_file(const fs::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return {};
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) return {};
    return buffer;
}

bool file_exists(const fs::path& path) {
    return fs::exists(path) && fs::is_regular_file(path);
}

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
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "imports.exe";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - imports.exe not found");
        return;
    }

    auto data = load_file(file_path);
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
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "imports_mixed.exe";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - imports_mixed.exe not found");
        return;
    }

    auto data = load_file(file_path);
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

TEST_CASE("Corkami Generated - impbyord.exe - Import Directory") {
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "impbyord.exe";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - impbyord.exe not found");
        return;
    }

    auto data = load_file(file_path);
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
        CHECK(dll->functions.size() == 2);
    }
}

TEST_CASE("Corkami Generated - tls.exe - Import Directory") {
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "tls.exe";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - tls.exe not found");
        return;
    }

    auto data = load_file(file_path);
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
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "tls.exe";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - tls.exe not found");
        return;
    }

    auto data = load_file(file_path);
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
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "tls64.exe";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - tls64.exe not found");
        return;
    }

    auto data = load_file(file_path);
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
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "tls_aoi.exe";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - tls_aoi.exe not found");
        return;
    }

    auto data = load_file(file_path);
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
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "debug.exe";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - debug.exe not found");
        return;
    }

    auto data = load_file(file_path);
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
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "debug.exe";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - debug.exe not found");
        return;
    }

    auto data = load_file(file_path);
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
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "signature.exe";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - signature.exe not found");
        return;
    }

    auto data = load_file(file_path);
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
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "signature.exe";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - signature.exe not found");
        return;
    }

    auto data = load_file(file_path);
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
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "dll.dll";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - dll.dll not found");
        return;
    }

    auto data = load_file(file_path);
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
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "dotnet20.exe";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - dotnet20.exe not found");
        return;
    }

    auto data = load_file(file_path);
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
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "dotnet20.exe";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - dotnet20.exe not found");
        return;
    }

    auto data = load_file(file_path);
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
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "tinynet.exe";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - tinynet.exe not found");
        return;
    }

    auto data = load_file(file_path);
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
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "delayimports.exe";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - delayimports.exe not found");
        return;
    }

    auto data = load_file(file_path);
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
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "ibreloc.exe";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - ibreloc.exe not found");
        return;
    }

    auto data = load_file(file_path);
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
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "dllbound.dll";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - dllbound.dll not found");
        return;
    }

    auto data = load_file(file_path);
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
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "compiled.exe";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - compiled.exe not found");
        return;
    }

    auto data = load_file(file_path);
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
    fs::path file_path = fs::path("/home/igor/proj/ares/mz-explode/1/pocs/PE/bin/") / "compiled.exe";
    if (!file_exists(file_path)) {
        MESSAGE("Skipping - compiled.exe not found");
        return;
    }

    auto data = load_file(file_path);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    auto debug = pe.debug();
    if (!debug) {
        MESSAGE("compiled.exe: Debug directory not parsed");
        return;
    }
}
