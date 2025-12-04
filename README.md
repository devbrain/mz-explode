# Modern Executable Analysis Library (mz-explode refactoring)

**Branch**: `refactor/datascript-migration`

This is a comprehensive refactoring of mz-explode to transform it from a specialized MZ decompression tool into a modern, extensible executable analysis library supporting MZ, NE, PE, and PE32+ formats.

## Project Structure

```
├── formats/                    # DataScript binary format specifications
│   └── exe_format_complete.ds  # MZ/NE/PE/PE32+ format definitions
├── generated/                  # Auto-generated parsers (not committed)
├── src/
│   ├── explode/               # Legacy implementation (to be replaced)
│   ├── libexe/                # New modern library (to be created)
│   ├── mzexplode/             # Main decompression tool
│   ├── mzdump/                # Diagnostic tool
│   └── unittest/              # Test suite with embedded test data
├── docs/                      # Official specifications
│   ├── pecoff.docx           # Microsoft PE/COFF specification
│   ├── ne.fmt                # NE (New Executable) format spec
│   ├── resfmt.txt            # Win32 resource formats
│   ├── fon.txt               # Font file formats
│   ├── pklite-114.txt        # PKLite decompression algorithm
│   ├── unlzexe.c             # LZEXE reference implementation
│   └── unexepack.c           # EXEPACK reference implementation
├── CMakeLists.txt            # Build configuration
├── MIGRATION_STRATEGY.md     # Detailed refactoring plan
└── CLAUDE.md                 # AI assistant guidance

```

## Technology Stack

- **C++20**: Modern standard with ranges, concepts, std::span
- **CMake 3.20+**: Modern build system with FetchContent
- **DataScript**: Declarative binary format parser generator
- **failsafe**: Header-only logging and exception handling
- **doctest**: Testing framework

## Documentation

### Specifications Available

**Official Microsoft Documentation:**
- `docs/pecoff.docx` - Complete PE/COFF specification (32/64-bit executables)
- `docs/ne.fmt` - NE format specification (16-bit Windows/OS2)
- `docs/resfmt.txt` - Win32 binary resource formats (icons, dialogs, menus, etc.)
- `docs/fon.txt` - Font file format specification

**Compression Format Documentation:**
- `docs/pklite-114.txt` - PKLite decompression algorithm pseudocode
- `docs/unlzexe.c` - LZEXE reference decompressor implementation
- `docs/unexepack.c` - Microsoft EXEPACK reference decompressor

**DataScript Specification:**
- `formats/exe_format_complete.ds` - Complete executable format definitions (1336 lines)
  - DOS MZ header with validation
  - NE format with segments, resources, relocations
  - PE/PE32+ with COFF headers, sections, data directories
  - Resource structures (icons, dialogs, menus, version info)
  - Import/Export tables
  - Security structures (digital signatures, load config, TLS)

## Current Capabilities

The existing implementation supports decompression of:
- **PKLITE** compressed executables (versions 1.00-2.01, standard and extra compression)
- **LZEXE** compressed executables
- **EXEPACK** compressed executables (Microsoft's packer)
- **Knowledge Dynamics** compressed executables

## Planned Capabilities

### Phase 1-2: Foundation (In Progress)
- DataScript-based parsing for MZ/NE/PE formats
- Separation of format parsing from decompression algorithms
- Modern C++20 API with failsafe error handling

### Phase 3-4: Format Expansion
- Full PE32/PE32+ support with section parsing
- NE format support for 16-bit Windows applications
- Resource extraction (icons, dialogs, menus, strings, version info)

### Phase 5-6: Modernization
- Modern C++20 library interface
- Rewritten command-line tools
- Comprehensive test coverage with doctest

### Phase 7: Advanced Features
- Import/Export table analysis
- Digital signature verification
- Entropy analysis for packing detection
- Debug info (PDB) parsing hooks

## Building (Current/Legacy)

```bash
# Create build directory
mkdir build && cd build

# Debug build
cmake ..
make

# Release build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

Build artifacts:
- Libraries: `build/lib/libexplode.so` (or `.a` for static)
- Executables: `build/bin/mzexplode`, `build/bin/mzdump`, `build/bin/unittest`

## Usage (Current)

### Decompress compressed executable:
```bash
./build/bin/mzexplode input.exe output.exe
```

### Display executable information:
```bash
./build/bin/mzdump input.exe output.exe
```

## Contributing to Refactoring

See `MIGRATION_STRATEGY.md` for the detailed 7-phase refactoring plan.

**Current Focus**: Phase 1 - DataScript integration and proof of concept

## Architecture Evolution

### Current (Legacy)
- Monolithic decoder classes mixing parsing + decompression
- Manual binary parsing with pointer arithmetic
- C-style I/O (FILE*)
- Pre-C++11 patterns

### Target (Modern)
```cpp
// Parsing: Auto-generated from DataScript specs
auto exe = parse_Executable(file_data);

// High-level API: Clean, type-safe wrappers
libexe::PEFile pe(exe);
for (const auto& section : pe.sections()) {
    // Modern C++20 ranges
}

// Decompression: Pure algorithms, testable in isolation
auto decompressed = libexe::decompress::pklite(
    compressed_data,
    header,
    logger
);

// Resource extraction: Built on introspection
for (const auto& resource : pe.resources()) {
    resource.export_to(output_dir);
}
```

## License

[Specify license here]

## References

- [DataScript GitHub](https://github.com/devbrain/datascript)
- [failsafe GitHub](https://github.com/devbrain/failsafe)
- [Microsoft PE/COFF Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
