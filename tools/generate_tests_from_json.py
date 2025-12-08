#!/usr/bin/env python3
"""
Generate C++ unit tests from Corkami test specification JSON

This script reads the corkami_test_spec.json file and auto-generates
C++ doctest test cases for field-level validation.

Usage:
    python3 generate_tests_from_json.py

Output:
    unittests/test_corkami_generated.cpp
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any

def load_spec(spec_path: Path) -> Dict[str, Any]:
    """Load the test specification JSON file"""
    with open(spec_path, 'r') as f:
        return json.load(f)

def generate_file_header() -> str:
    """Generate C++ file header with includes"""
    return '''// libexe - Modern executable file analysis library
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

'''

def generate_import_test(test_file: Dict[str, Any], corpus_path: str) -> str:
    """Generate test case for import directory"""
    binary_file = test_file['binary_file']
    description = test_file['description']
    import_spec = test_file['data_directories'].get('IMPORT', {})

    if not import_spec.get('present', False):
        return ''

    test_code = f'''
TEST_CASE("Corkami Generated - {binary_file} - Import Directory") {{
    fs::path file_path = fs::path("{corpus_path}") / "{binary_file}";
    if (!file_exists(file_path)) {{
        MESSAGE("Skipping - {binary_file} not found");
        return;
    }}

    auto data = load_file(file_path);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("Import directory present") {{
        CHECK(pe.has_data_directory(directory_entry::IMPORT));
    }}

    auto imports = pe.imports();
    if (!imports) {{
        MESSAGE("{binary_file}: Import directory not parsed");
        return;
    }}
'''

    # DLL count check
    if 'dll_count' in import_spec:
        dll_count = import_spec['dll_count']
        test_code += f'''
    SUBCASE("DLL count") {{
        CHECK(imports->dll_count() == {dll_count});
    }}
'''

    # DLL-specific checks
    if 'dlls' in import_spec:
        for dll in import_spec['dlls']:
            dll_name = dll['name']
            test_code += f'''
    SUBCASE("DLL: {dll_name}") {{
        const import_dll* dll = nullptr;
        for (const auto& d : imports->dlls) {{
            if (iequals(d.name, "{dll_name}")) {{
                dll = &d;
                break;
            }}
        }}

        REQUIRE(dll != nullptr);
'''

            if 'function_count' in dll:
                func_count = dll['function_count']
                test_code += f'        CHECK(dll->functions.size() == {func_count});\n'

            if 'functions' in dll:
                for func in dll['functions']:
                    func_name = func.get('name')
                    is_ordinal = func.get('is_ordinal', False)

                    if func_name:
                        test_code += f'''
        // Check for {func_name}
        bool found_{func_name.lower()} = false;
        for (const auto& f : dll->functions) {{
            if (iequals(f.name, "{func_name}")) {{
                found_{func_name.lower()} = true;
                CHECK_FALSE(f.is_ordinal);
                break;
            }}
        }}
        CHECK(found_{func_name.lower()});
'''

            test_code += '    }\n'

    test_code += '}\n'
    return test_code

def generate_tls_test(test_file: Dict[str, Any], corpus_path: str) -> str:
    """Generate test case for TLS directory"""
    binary_file = test_file['binary_file']
    tls_spec = test_file['data_directories'].get('TLS', {})

    if not tls_spec.get('present', False):
        return ''

    test_code = f'''
TEST_CASE("Corkami Generated - {binary_file} - TLS Directory") {{
    fs::path file_path = fs::path("{corpus_path}") / "{binary_file}";
    if (!file_exists(file_path)) {{
        MESSAGE("Skipping - {binary_file} not found");
        return;
    }}

    auto data = load_file(file_path);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    SUBCASE("TLS directory present") {{
        CHECK(pe.has_data_directory(directory_entry::TLS));
    }}

    auto tls = pe.tls();
    if (!tls) {{
        MESSAGE("{binary_file}: TLS directory not parsed");
        return;
    }}
'''

    if 'callback_count' in tls_spec:
        callback_count = tls_spec['callback_count']
        test_code += f'''
    SUBCASE("Callback count") {{
        CHECK(tls->callback_count() == {callback_count});
    }}
'''

    if tls_spec.get('has_callbacks', False):
        test_code += '''
    SUBCASE("Has callbacks") {
        CHECK(tls->has_callbacks());
    }
'''

    if tls_spec.get('address_of_index_nonzero', False):
        test_code += '''
    SUBCASE("TLS index address") {
        CHECK(tls->address_of_index != 0);
    }
'''

    if tls_spec.get('address_of_callbacks_nonzero', False):
        test_code += '''
    SUBCASE("TLS callbacks address") {
        CHECK(tls->address_of_callbacks != 0);
    }
'''

    test_code += '}\n'
    return test_code

def generate_debug_test(test_file: Dict[str, Any], corpus_path: str) -> str:
    """Generate test case for debug directory"""
    binary_file = test_file['binary_file']
    debug_spec = test_file['data_directories'].get('DEBUG', {})

    if not debug_spec.get('present', False):
        return ''

    test_code = f'''
TEST_CASE("Corkami Generated - {binary_file} - Debug Directory") {{
    fs::path file_path = fs::path("{corpus_path}") / "{binary_file}";
    if (!file_exists(file_path)) {{
        MESSAGE("Skipping - {binary_file} not found");
        return;
    }}

    auto data = load_file(file_path);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    auto debug = pe.debug();
    if (!debug) {{
        MESSAGE("{binary_file}: Debug directory not parsed");
        return;
    }}
'''

    if 'entry_count' in debug_spec:
        entry_count = debug_spec['entry_count']
        test_code += f'''
    SUBCASE("Entry count") {{
        CHECK(debug->entries.size() == {entry_count});
    }}
'''

    if 'entries' in debug_spec:
        for idx, entry in enumerate(debug_spec['entries']):
            entry_type = entry.get('type')
            test_code += f'''
    SUBCASE("Entry {idx} type") {{
        REQUIRE(debug->entries.size() > {idx});
        CHECK(debug->entries[{idx}].type == debug_type::{entry_type});
    }}
'''

            if 'size_of_data' in entry:
                size = entry['size_of_data']
                test_code += f'''
    SUBCASE("Entry {idx} size") {{
        REQUIRE(debug->entries.size() > {idx});
        CHECK(debug->entries[{idx}].size_of_data == {size});
    }}
'''

    test_code += '}\n'
    return test_code

def generate_security_test(test_file: Dict[str, Any], corpus_path: str) -> str:
    """Generate test case for security directory"""
    binary_file = test_file['binary_file']
    security_spec = test_file['data_directories'].get('SECURITY', {})

    if not security_spec.get('present', False):
        return ''

    test_code = f'''
TEST_CASE("Corkami Generated - {binary_file} - Security Directory") {{
    fs::path file_path = fs::path("{corpus_path}") / "{binary_file}";
    if (!file_exists(file_path)) {{
        MESSAGE("Skipping - {binary_file} not found");
        return;
    }}

    auto data = load_file(file_path);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    auto security = pe.security();
    if (!security) {{
        MESSAGE("{binary_file}: Security directory not parsed");
        return;
    }}
'''

    if 'certificate_count' in security_spec:
        cert_count = security_spec['certificate_count']
        test_code += f'''
    SUBCASE("Certificate count") {{
        CHECK(security->certificate_count() == {cert_count});
    }}
'''

    if 'certificates' in security_spec:
        for idx, cert in enumerate(security_spec['certificates']):
            if cert.get('is_authenticode', False):
                test_code += f'''
    SUBCASE("Certificate {idx} is Authenticode") {{
        REQUIRE(security->certificate_count() > {idx});
        CHECK(security->certificates[{idx}].is_authenticode());
    }}
'''

            if 'data_size' in cert:
                size = cert['data_size']
                test_code += f'''
    SUBCASE("Certificate {idx} size") {{
        REQUIRE(security->certificate_count() > {idx});
        CHECK(security->certificates[{idx}].certificate_data.size() == {size});
    }}
'''

    test_code += '}\n'
    return test_code

def generate_com_descriptor_test(test_file: Dict[str, Any], corpus_path: str) -> str:
    """Generate test case for COM descriptor (.NET)"""
    binary_file = test_file['binary_file']
    com_spec = test_file['data_directories'].get('COM_DESCRIPTOR', {})

    if not com_spec.get('present', False):
        return ''

    test_code = f'''
TEST_CASE("Corkami Generated - {binary_file} - COM Descriptor") {{
    fs::path file_path = fs::path("{corpus_path}") / "{binary_file}";
    if (!file_exists(file_path)) {{
        MESSAGE("Skipping - {binary_file} not found");
        return;
    }}

    auto data = load_file(file_path);
    REQUIRE_FALSE(data.empty());

    auto pe = pe_file::from_memory(data);

    auto clr = pe.clr_header();
    if (!clr) {{
        MESSAGE("{binary_file}: COM descriptor not parsed");
        return;
    }}
'''

    if com_spec.get('is_valid', False):
        test_code += '''
    SUBCASE("CLR header valid") {
        CHECK(clr->is_valid());
    }
'''

    if 'runtime_version' in com_spec:
        version = com_spec['runtime_version']
        test_code += f'''
    SUBCASE("Runtime version") {{
        auto version = clr->runtime_version();
        CHECK(version.find("{version}") != std::string::npos);
    }}
'''

    if 'major_version' in com_spec:
        major = com_spec['major_version']
        test_code += f'''
    SUBCASE("Major runtime version") {{
        CHECK(clr->major_runtime_version == {major});
    }}
'''

    if com_spec.get('metadata_rva_nonzero', False):
        test_code += '''
    SUBCASE("Metadata RVA") {
        CHECK(clr->metadata_rva != 0);
    }
'''

    if com_spec.get('metadata_size_nonzero', False):
        test_code += '''
    SUBCASE("Metadata size") {
        CHECK(clr->metadata_size > 0);
    }
'''

    test_code += '}\n'
    return test_code

def generate_tests(spec: Dict[str, Any]) -> str:
    """Generate all test cases from specification"""
    output = generate_file_header()

    corpus_path = spec['corpus_path']

    for test_file in spec['test_files']:
        # Generate tests for each data directory
        output += generate_import_test(test_file, corpus_path)
        output += generate_tls_test(test_file, corpus_path)
        output += generate_debug_test(test_file, corpus_path)
        output += generate_security_test(test_file, corpus_path)
        output += generate_com_descriptor_test(test_file, corpus_path)

    return output

def main():
    """Main entry point"""
    # Paths
    repo_root = Path(__file__).parent.parent
    spec_path = repo_root / 'docs' / 'corkami_test_spec.json'
    output_path = repo_root / 'unittests' / 'test_corkami_generated.cpp'

    print(f"Loading specification from: {spec_path}")
    spec = load_spec(spec_path)

    print(f"Generating tests for {len(spec['test_files'])} test files...")
    test_code = generate_tests(spec)

    print(f"Writing output to: {output_path}")
    with open(output_path, 'w') as f:
        f.write(test_code)

    print(f"✓ Generated {test_code.count('TEST_CASE')} test cases")
    print(f"✓ Output: {output_path}")

if __name__ == '__main__':
    main()
