# libexe (mz-explode)

**Modern C++20 library for analyzing Windows executable files**

libexe is a comprehensive library for parsing and analyzing DOS MZ, NE (16-bit Windows), PE (32-bit), and PE32+ (64-bit) executable formats. It provides format detection, header parsing, resource extraction, compression detection, and security analysis capabilities.

[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![CMake](https://img.shields.io/badge/CMake-3.20%2B-blue.svg)](https://cmake.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Features

### Format Support

| Format | Description | Status |
|--------|-------------|--------|
| **MZ** | DOS executables (16-bit) | Full support |
| **NE** | Windows 3.x / OS/2 1.x (16-bit) | Full support |
| **PE** | Windows 95+ / NT (32-bit) | Full support |
| **PE32+** | Windows x64 (64-bit) | Full support |
| **LE/LX** | DOS extenders / OS/2 2.x | Full support |

### Core Capabilities

- **Automatic Format Detection** - Identify executable type from file content
- **Header Parsing** - Access all header fields with type-safe APIs
- **Section/Segment Analysis** - Enumerate and analyze code and data sections
- **Import/Export Tables** - Parse DLL dependencies and exported symbols
- **Resource Extraction** - Extract icons, cursors, dialogs, version info, and more
- **Relocation Tables** - Parse fixup information for rebasing

### Compression Detection and Decompression

Detect and decompress packed DOS executables:

| Packer | Versions | Detection | Decompression |
|--------|----------|-----------|---------------|
| **PKLITE** | 1.00 - 2.01 | Yes | Yes |
| **LZEXE** | 0.90, 0.91 | Yes | Yes |
| **EXEPACK** | All | Yes | Yes |
| **Knowledge Dynamics** | DIET-style | Yes | Yes |

### Security Analysis (PE files)

- **ASLR Detection** - Address Space Layout Randomization
- **DEP/NX Detection** - Data Execution Prevention
- **CFG Detection** - Control Flow Guard
- **SEH Analysis** - Structured Exception Handling
- **Authenticode Parsing** - Digital signature verification
- **Rich Header Analysis** - Microsoft build tool metadata

### Advanced Features

- **Entropy Analysis** - Detect packed/encrypted sections
- **Overlay Detection** - Identify appended data after PE image
- **DOS Extender Detection** - Identify DOS/4GW, DOS/32A, PMODE/W, CauseWay
- **Stub Stripping** - Extract protected mode code from LE/LX files
- **Anomaly Detection** - Identify malformed or suspicious structures

---

## Quick Start

### Installation

```bash
git clone https://github.com/devbrain/mz-explode.git
cd libexe
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Basic Usage

```cpp
#include <libexe/libexe.hpp>
#include <iostream>

int main() {
    // Automatic format detection
    auto exe = libexe::executable_factory::from_file("program.exe");

    std::cout << "Format: " << exe->format_name() << "\n";
    std::cout << "Type: ";

    switch (exe->get_format()) {
        case libexe::format_type::MZ_DOS:
            std::cout << "DOS executable\n";
            break;
        case libexe::format_type::NE_WIN16:
            std::cout << "16-bit Windows\n";
            break;
        case libexe::format_type::PE_WIN32:
            std::cout << "32-bit Windows\n";
            break;
        case libexe::format_type::PE_WIN64:
            std::cout << "64-bit Windows\n";
            break;
        case libexe::format_type::LE_DOS:
        case libexe::format_type::LX_OS2:
            std::cout << "DOS extender / OS/2\n";
            break;
    }

    return 0;
}
```

### Working with PE Files

```cpp
#include <libexe/formats/pe_file.hpp>

auto pe = libexe::pe_file::from_file("application.exe");

// Basic information
std::cout << "Machine: " << (pe.is_64bit() ? "x64" : "x86") << "\n";
std::cout << "Subsystem: " << static_cast<int>(pe.subsystem()) << "\n";
std::cout << "Entry point: 0x" << std::hex << pe.entry_point_rva() << "\n";

// Security features
if (pe.has_aslr()) std::cout << "ASLR enabled\n";
if (pe.has_dep()) std::cout << "DEP enabled\n";
if (pe.has_cfg()) std::cout << "CFG enabled\n";

// Sections
for (const auto& section : pe.sections()) {
    std::cout << section.name << " - "
              << section.virtual_size << " bytes\n";
}

// Imports
for (const auto& import : pe.imports()) {
    std::cout << "Import: " << import.dll_name << "\n";
    for (const auto& func : import.functions) {
        std::cout << "  " << func.name << "\n";
    }
}
```

### Decompressing Packed Executables

```cpp
#include <libexe/formats/mz_file.hpp>
#include <libexe/decompressors/decompressor.hpp>

auto mz = libexe::mz_file::from_file("packed.exe");

if (mz.is_compressed()) {
    std::cout << "Compression: ";
    switch (mz.get_compression()) {
        case libexe::compression_type::PKLITE_STANDARD:
            std::cout << "PKLITE\n"; break;
        case libexe::compression_type::LZEXE_091:
            std::cout << "LZEXE 0.91\n"; break;
        case libexe::compression_type::EXEPACK:
            std::cout << "EXEPACK\n"; break;
        default:
            std::cout << "Unknown\n"; break;
    }

    // Decompress
    auto decompressor = libexe::create_decompressor(mz.get_compression());
    auto result = decompressor->decompress(mz.code_section());

    // result.code contains the decompressed executable
    // result.relocations contains the relocation table
}
```

### Resource Extraction

```cpp
#include <libexe/formats/pe_file.hpp>

auto pe = libexe::pe_file::from_file("application.exe");

if (pe.has_resources()) {
    auto resources = pe.resources();

    // Iterate resource types
    for (const auto& type_entry : resources->entries()) {
        std::cout << "Resource type: " << type_entry.id << "\n";

        // Get specific resources
        if (type_entry.id == 3) {  // RT_ICON
            for (const auto& icon : type_entry.entries()) {
                auto data = resources->get_data(icon);
                // Process icon data...
            }
        }
    }
}
```

---

## Building

### Requirements

- C++20 compatible compiler (GCC 10+, Clang 12+, MSVC 2019+)
- CMake 3.20 or later (uses `file(ARCHIVE_EXTRACT)` for portable test data decompression)

### Build Options

```bash
# Shared library (default)
cmake -B build
cmake --build build

# Static library
cmake -B build -DBUILD_SHARED_LIBS=OFF
cmake --build build

# With documentation (requires Doxygen)
cmake -B build -DBUILD_DOCS=ON
cmake --build build --target docs

# Without tests
cmake -B build -DBUILD_TESTING=OFF
cmake --build build
```

### Build Artifacts

| Artifact | Path |
|----------|------|
| Library | `build/lib/libexe.so` (or `.a`) |
| CLI Tool | `build/bin/exeinfo` |
| Unit Tests | `build/bin/libexe_unittest` |
| Documentation | `build/docs/html/` |

---

## Command-Line Tool

The `exeinfo` utility provides command-line access to library functionality:

```bash
# Display executable information
exeinfo program.exe

# Verbose output with all details
exeinfo -v program.exe

# JSON output
exeinfo --json program.exe

# Extract resources
exeinfo --extract-resources output_dir/ program.exe
```

Example output:

```
File: KERNEL32.DLL
Format: PE (Portable Executable)
Machine: x64 (AMD64)
Subsystem: Windows GUI
Characteristics: DLL, Large Address Aware, Dynamic Base, NX Compatible

Sections:
  .text     0x00001000  143360 bytes  [CODE, EXECUTE, READ]
  .rdata    0x00024000   53248 bytes  [INITIALIZED_DATA, READ]
  .data     0x00031000    8192 bytes  [INITIALIZED_DATA, READ, WRITE]
  .rsrc     0x00033000    4096 bytes  [INITIALIZED_DATA, READ]

Security:
  ASLR: Enabled (High Entropy)
  DEP: Enabled
  CFG: Enabled
  Authenticode: Signed (Microsoft Windows)

Imports: 3 DLLs
  NTDLL.DLL (127 functions)
  api-ms-win-core-... (43 functions)

Exports: 1524 functions
```

---

## Project Structure

```
libexe/
├── include/libexe/           # Public API headers
│   ├── core/                 # Base classes and utilities
│   │   ├── executable_file.hpp
│   │   ├── diagnostic.hpp
│   │   └── enum_bitmask.hpp
│   ├── formats/              # Format-specific parsers
│   │   ├── mz_file.hpp
│   │   ├── ne_file.hpp
│   │   ├── pe_file.hpp
│   │   └── le_file.hpp
│   ├── decompressors/        # Unpacking algorithms
│   │   ├── decompressor.hpp
│   │   ├── pklite.hpp
│   │   └── lzexe.hpp
│   ├── pe/                   # PE-specific types
│   ├── ne/                   # NE-specific types
│   └── le/                   # LE/LX-specific types
├── src/libexe/               # Implementation
├── tools/                    # Command-line utilities
├── unittests/                # Test suite
├── docs/                     # Documentation and specs
│   ├── programmers_guide.md  # Comprehensive usage guide
│   ├── pecoff.docx           # Microsoft PE/COFF spec
│   └── ne.fmt                # NE format specification
└── CMakeLists.txt
```

---

## Documentation

- **[Programmer's Guide](docs/programmers_guide.md)** - Comprehensive usage documentation
- **[API Reference](https://user.github.io/libexe/)** - Doxygen-generated API docs

### Building Documentation

```bash
cmake -B build -DBUILD_DOCS=ON
cmake --build build --target docs
# Open build/docs/html/index.html
```

---

## Testing

```bash
# Run all tests
./build/bin/libexe_unittest

# Run specific test suite
./build/bin/libexe_unittest --test-suite="PE Parser"

# Run with verbose output
./build/bin/libexe_unittest -s
```

Test coverage includes:
- Format detection for all supported types
- Header parsing validation
- Compression detection accuracy
- Decompression correctness (known input/output pairs)
- Resource extraction
- Edge cases and malformed files

---

## Architecture

### Design Principles

1. **Format-agnostic base class** - Common interface via `executable_file`
2. **Immutable parsing** - Files are parsed once, data is read-only
3. **Zero-copy where possible** - `std::span` for data views
4. **Exception-based errors** - Clear error messages with context
5. **No global state** - Thread-safe by design

### Class Hierarchy

```
executable_file (abstract base)
├── mz_file     (DOS MZ)
├── ne_file     (16-bit Windows/OS2)
├── pe_file     (32/64-bit Windows)
└── le_file     (DOS extenders/OS2 2.x)
```

### Diagnostic System

The library includes a diagnostic collector for reporting anomalies:

```cpp
libexe::diagnostic_collector collector;
auto pe = libexe::pe_file::from_file("suspicious.exe", &collector);

for (const auto& diag : collector.diagnostics()) {
    std::cout << "[" << to_string(diag.severity) << "] "
              << diag.message << "\n";
}
```

Diagnostic categories include:
- Header anomalies (invalid checksums, unusual values)
- Section anomalies (overlapping, zero-size, suspicious names)
- Import/export anomalies
- Security indicator anomalies

---

## Dependencies

| Dependency | Type | Purpose |
|------------|------|---------|
| [Datascript](https://github.com/devbrain/datascript) | Code generator | Code generator for parsers |
| [doctest](https://github.com/doctest/doctest) | Test only | Unit testing framework |
| [Doxygen](https://www.doxygen.nl/) | Optional | Documentation generation |

All dependencies are fetched automatically via CMake FetchContent.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Contributing

Contributions are welcome. Please ensure:

1. Code follows the project style (snake_case naming)
2. New features include tests
3. Public APIs include Doxygen documentation
4. All tests pass before submitting PR



---


