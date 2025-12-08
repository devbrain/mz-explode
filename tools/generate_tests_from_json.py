#!/usr/bin/env python3
"""
Generate C++ unit tests from Corkami test specification JSON

This script reads the corkami_test_spec.json file and auto-generates:
1. test_corkami_generated.cpp - C++ doctest test cases
2. corkami_test_data.cc - Embedded binary test data

The test files are embedded at generation time, not loaded at runtime.

Usage:
    python3 generate_tests_from_json.py

Output:
    unittests/test_corkami_generated.cpp
    unittests/testdata/corkami_test_data.cc
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Set

def load_spec(spec_path: Path) -> Dict[str, Any]:
    """Load the test specification JSON file"""
    with open(spec_path, 'r') as f:
        return json.load(f)

def sanitize_name(filename: str) -> str:
    """Convert filename to valid C++ identifier"""
    # Remove extension
    name = Path(filename).stem
    # Replace special characters with underscore
    name = ''.join(c if c.isalnum() else '_' for c in name)
    # Ensure doesn't start with digit
    if name[0].isdigit():
        name = '_' + name
    return name.lower()

def embed_binary_file(file_path: Path, var_name: str) -> str:
    """Read binary file and generate C++ byte array"""
    try:
        data = file_path.read_bytes()
    except FileNotFoundError:
        print(f"Warning: File not found: {file_path}")
        return ''

    size = len(data)

    # Generate hex byte array with 12 bytes per line
    hex_lines = []
    for i in range(0, len(data), 12):
        chunk = data[i:i+12]
        hex_bytes = ', '.join(f'0x{b:02x}' for b in chunk)
        hex_lines.append(f'\t{hex_bytes},')

    # Remove trailing comma from last line
    if hex_lines:
        hex_lines[-1] = hex_lines[-1].rstrip(',')

    hex_data = '\n'.join(hex_lines)

    return f'''// Embedded: {file_path.name} ({size} bytes)
size_t {var_name}_len = {size};
unsigned char {var_name}[{size}] = {{
{hex_data}
}};

'''

def generate_data_file(spec: Dict[str, Any], corpus_path: Path) -> str:
    """Generate corkami_test_data.cc with embedded binary files"""
    output = '''// libexe - Modern executable file analysis library
// Copyright (c) 2024
// AUTO-GENERATED - DO NOT EDIT BY HAND
//
// Embedded Corkami PE test corpus files
// To regenerate: python3 tools/generate_tests_from_json.py

#include <cstddef>

namespace corkami_data {

'''

    # Collect all unique binary files
    binary_files: Set[str] = set()
    for test_file in spec['test_files']:
        binary_files.add(test_file['binary_file'])

    # Embed each file
    for binary_file in sorted(binary_files):
        file_path = corpus_path / binary_file
        var_name = sanitize_name(binary_file)
        output += embed_binary_file(file_path, var_name)

    output += '''} // namespace corkami_data
'''

    return output

def generate_file_header(spec: Dict[str, Any]) -> str:
    """Generate C++ file header with includes and data declarations"""

    # Generate forward declarations for all test files
    declarations = []
    binary_files: Set[str] = set()
    for test_file in spec['test_files']:
        binary_files.add(test_file['binary_file'])

    for binary_file in sorted(binary_files):
        var_name = sanitize_name(binary_file)
        declarations.append(f'    extern size_t {var_name}_len;')
        declarations.append(f'    extern unsigned char {var_name}[];')

    forward_decls = '\n'.join(declarations)

    return f'''// libexe - Modern executable file analysis library
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
namespace corkami_data {{
{forward_decls}
}}

namespace {{

// Helper: Load embedded test file
std::vector<uint8_t> load_embedded(const unsigned char* data, size_t len) {{
    return std::vector<uint8_t>(data, data + len);
}}

// Helper: Case-insensitive string comparison
bool iequals(const std::string& a, const std::string& b) {{
    if (a.size() != b.size()) return false;
    return std::equal(a.begin(), a.end(), b.begin(),
                     [](char ca, char cb) {{
                         return std::tolower(static_cast<unsigned char>(ca)) ==
                                std::tolower(static_cast<unsigned char>(cb));
                     }});
}}

}} // anonymous namespace

'''

def generate_import_test(test_file: Dict[str, Any]) -> str:
    """Generate test case for import directory"""
    binary_file = test_file['binary_file']
    var_name = sanitize_name(binary_file)
    description = test_file['description']
    import_spec = test_file['data_directories'].get('IMPORT', {})

    if not import_spec.get('present', False):
        return ''

    test_code = f'''
TEST_CASE("Corkami Generated - {binary_file} - Import Directory") {{
    auto data = load_embedded(corkami_data::{var_name}, corkami_data::{var_name}_len);
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

def generate_tls_test(test_file: Dict[str, Any]) -> str:
    """Generate test case for TLS directory"""
    binary_file = test_file['binary_file']
    var_name = sanitize_name(binary_file)
    tls_spec = test_file['data_directories'].get('TLS', {})

    if not tls_spec.get('present', False):
        return ''

    test_code = f'''
TEST_CASE("Corkami Generated - {binary_file} - TLS Directory") {{
    auto data = load_embedded(corkami_data::{var_name}, corkami_data::{var_name}_len);
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

def generate_debug_test(test_file: Dict[str, Any]) -> str:
    """Generate test case for debug directory"""
    binary_file = test_file['binary_file']
    var_name = sanitize_name(binary_file)
    debug_spec = test_file['data_directories'].get('DEBUG', {})

    if not debug_spec.get('present', False):
        return ''

    test_code = f'''
TEST_CASE("Corkami Generated - {binary_file} - Debug Directory") {{
    auto data = load_embedded(corkami_data::{var_name}, corkami_data::{var_name}_len);
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

def generate_security_test(test_file: Dict[str, Any]) -> str:
    """Generate test case for security directory"""
    binary_file = test_file['binary_file']
    var_name = sanitize_name(binary_file)
    security_spec = test_file['data_directories'].get('SECURITY', {})

    if not security_spec.get('present', False):
        return ''

    test_code = f'''
TEST_CASE("Corkami Generated - {binary_file} - Security Directory") {{
    auto data = load_embedded(corkami_data::{var_name}, corkami_data::{var_name}_len);
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

def generate_com_descriptor_test(test_file: Dict[str, Any]) -> str:
    """Generate test case for COM descriptor (.NET)"""
    binary_file = test_file['binary_file']
    var_name = sanitize_name(binary_file)
    com_spec = test_file['data_directories'].get('COM_DESCRIPTOR', {})

    if not com_spec.get('present', False):
        return ''

    test_code = f'''
TEST_CASE("Corkami Generated - {binary_file} - COM Descriptor") {{
    auto data = load_embedded(corkami_data::{var_name}, corkami_data::{var_name}_len);
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
    output = generate_file_header(spec)

    for test_file in spec['test_files']:
        # Generate tests for each data directory
        output += generate_import_test(test_file)
        output += generate_tls_test(test_file)
        output += generate_debug_test(test_file)
        output += generate_security_test(test_file)
        output += generate_com_descriptor_test(test_file)

    return output

def main():
    """Main entry point"""
    # Paths
    repo_root = Path(__file__).parent.parent
    spec_path = repo_root / 'docs' / 'corkami_test_spec.json'
    test_output_path = repo_root / 'unittests' / 'test_corkami_generated.cpp'
    data_output_dir = repo_root / 'unittests' / 'testdata'
    data_output_path = data_output_dir / 'corkami_test_data.cc'

    # Create testdata directory if it doesn't exist
    data_output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading specification from: {spec_path}")
    spec = load_spec(spec_path)

    # Get corpus path
    corpus_path = Path(spec['corpus_path'])
    if not corpus_path.is_absolute():
        corpus_path = repo_root / corpus_path

    print(f"Corpus path: {corpus_path}")

    if not corpus_path.exists():
        print(f"ERROR: Corpus path not found: {corpus_path}")
        sys.exit(1)

    # Generate embedded data file
    print(f"Generating embedded test data...")
    data_code = generate_data_file(spec, corpus_path)

    print(f"Writing data file to: {data_output_path}")
    with open(data_output_path, 'w') as f:
        f.write(data_code)

    # Generate test file
    print(f"Generating tests for {len(spec['test_files'])} test files...")
    test_code = generate_tests(spec)

    print(f"Writing test file to: {test_output_path}")
    with open(test_output_path, 'w') as f:
        f.write(test_code)

    print(f"✓ Generated {test_code.count('TEST_CASE')} test cases")
    print(f"✓ Test file: {test_output_path}")
    print(f"✓ Data file: {data_output_path}")

if __name__ == '__main__':
    main()
