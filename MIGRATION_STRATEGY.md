# Migration Strategy: Datascript-Based Executable Library

## Vision

Transform mz-explode from a specialized MZ decompression tool into a comprehensive executable analysis library capable of:
- Parsing MZ, NE, PE, PE32+ formats
- Extracting resources from executables
- Decompressing legacy compressed executables
- Providing foundation for PE Explorer and resource extraction tools

## Phase 1: Foundation & Proof of Concept

### 1.1 Datascript Integration
- [ ] Add datascript as submodule or dependency
- [ ] Create `formats/` directory for .ds specifications
- [ ] Set up datascript code generation in CMake build
- [ ] Document datascript build integration

### 1.2 MZ Format Specification
- [ ] Port MZ header definition to datascript (`formats/mz.ds`)
- [ ] Define relocation table structure
- [ ] Add validation constraints (magic numbers, size checks)
- [ ] Generate C++ parser from specification

### 1.3 Proof of Concept
- [ ] Create new `src/libexe/` directory for modern library
- [ ] Implement MZ file reader using generated datascript parser
- [ ] Write comparison tests: old vs new MZ parsing
- [ ] Verify byte-for-byte compatibility with existing code

**Success Criteria**: New datascript-based MZ parser passes all existing unittest test cases.

## Phase 2: Decompression Algorithms Separation

### 2.1 Architecture Redesign
Current architecture mixes parsing and decompression:
```
unpklite class:
  - Format detection ←─ move to datascript
  - Header parsing   ←─ move to datascript
  - Decompression    ←─ keep as algorithm
  - Output generation ←─ modernize
```

New architecture:
```
formats/pklite.ds         → PKLite structure definitions
src/libexe/parsers/       → Generated parsers (from datascript)
src/libexe/decompressors/ → Pure decompression algorithms
src/libexe/builders/      → EXE file builders (output)
```

### 2.2 Decompressor Refactoring
- [ ] Extract PKLITE decompression algorithm to standalone function
- [ ] Extract LZEXE decompression algorithm to standalone function
- [ ] Extract EXEPACK decompression algorithm to standalone function
- [ ] Extract Knowledge Dynamics decompression algorithm
- [ ] Create unified decompressor interface
- [ ] Add comprehensive unit tests for each algorithm

### 2.3 Format Definitions
- [ ] Define PKLITE header structures in datascript
- [ ] Define LZEXE header structures in datascript
- [ ] Define EXEPACK header structures in datascript
- [ ] Define Knowledge Dynamics header structures in datascript
- [ ] Add format detection predicates

**Success Criteria**: Decompression algorithms are pure functions, testable in isolation from file I/O.

## Phase 3: PE/NE Format Support

### 3.1 PE Format Implementation
- [ ] Port PE format from exe_format_complete.ds to `formats/pe.ds`
- [ ] Implement PE32/PE32+ discriminated union
- [ ] Parse COFF header, Optional Header, Section Headers
- [ ] Parse Data Directories (exports, imports, resources, etc.)
- [ ] Create PE file reader class using generated parser

### 3.2 NE Format Implementation
- [ ] Port NE format from exe_format_complete.ds to `formats/ne.ds`
- [ ] Implement NE segment table parsing
- [ ] Implement NE resource table parsing
- [ ] Implement NE entry table parsing
- [ ] Create NE file reader class using generated parser

### 3.3 Format Detection
- [ ] Implement unified format detector (MZ/NE/PE)
- [ ] Handle DOS stub + extended header navigation (e_lfanew)
- [ ] Create factory pattern for format-specific readers
- [ ] Add format identification utility

**Success Criteria**: Library can parse PE and NE files, extract basic metadata and section information.

## Phase 4: Resource Extraction

### 4.1 PE Resources
- [ ] Implement resource directory tree traversal
- [ ] Extract icons (RT_ICON, RT_GROUP_ICON)
- [ ] Extract bitmaps (RT_BITMAP)
- [ ] Extract strings (RT_STRING)
- [ ] Extract dialogs (RT_DIALOG)
- [ ] Extract version info (RT_VERSION)
- [ ] Extract menus (RT_MENU)
- [ ] Extract accelerators (RT_ACCELERATOR)
- [ ] Support custom resource types

### 4.2 NE Resources
- [ ] Implement NE resource enumeration
- [ ] Map NE resource types to PE equivalents
- [ ] Extract common resource types
- [ ] Handle NE-specific resource formats

### 4.3 Resource API
- [ ] Design unified resource enumeration API
- [ ] Implement resource export functionality
- [ ] Support resource metadata queries
- [ ] Add resource modification capability (future)

**Success Criteria**: Can extract all common resource types from PE/NE files.

## Phase 5: Modern C++ Library Design

### 5.1 API Modernization
Replace legacy patterns:
- `FILE*` → `std::filesystem::path`, `std::span<uint8_t>`
- Raw pointers → `std::unique_ptr`, `std::shared_ptr`
- Manual loops → STL algorithms, ranges (C++20)
- `memcpy`/`memset` → `std::copy`, `std::fill`
- C-style casts → static_cast, explicit constructors
- Error codes → exceptions or `std::expected` (C++23)

### 5.2 Library Interface
```cpp
namespace libexe {
  class ExecutableFile;      // Base class for all formats
  class MZFile : public ExecutableFile;
  class NEFile : public ExecutableFile;
  class PEFile : public ExecutableFile;

  class ResourceDirectory;   // Resource access
  class Section;             // Code/data sections
  class ImportTable;         // Import functions
  class ExportTable;         // Export functions
}
```

### 5.3 Testing Strategy
- [ ] Migrate existing unittest data to new test framework
- [ ] Add GoogleTest or Catch2 for modern unit testing
- [ ] Create test fixtures for each format type
- [ ] Add property-based tests for decompression roundtrips
- [ ] Add fuzzing tests for parser robustness

**Success Criteria**: Modern, idiomatic C++17/20 API with comprehensive test coverage.

## Phase 6: Tool Migration

### 6.1 Command-Line Tools
- [ ] Rewrite `mzexplode` using new library
- [ ] Rewrite `mzdump` using new library
- [ ] Add `peinfo` tool for PE analysis
- [ ] Add `resextract` tool for resource extraction
- [ ] Ensure backward compatibility with existing tool interfaces

### 6.2 Documentation
- [ ] API documentation (Doxygen)
- [ ] Format specification references
- [ ] Usage examples and tutorials
- [ ] Migration guide for existing users

**Success Criteria**: All existing tools work with new library, pass regression tests.

## Phase 7: Advanced Features

### 7.1 PE Explorer Functionality
- [ ] Section disassembly integration points
- [ ] Relocation processing
- [ ] Import/Export analysis
- [ ] Digital signature verification
- [ ] Debug info (PDB) parsing hooks
- [ ] ASLR/DEP/CFG flag detection

### 7.2 Analysis Capabilities
- [ ] Entropy analysis for packing detection
- [ ] Overlay detection and extraction
- [ ] Authenticode signature validation
- [ ] Rich header parsing
- [ ] TLS callback enumeration

**Success Criteria**: Library provides all primitives needed for PE analysis tools.

## Migration Phases Timeline

**Phase 1-2**: Core foundation (datascript integration + decompressor separation)
**Phase 3**: PE/NE parsing capability
**Phase 4**: Resource extraction
**Phase 5**: API modernization
**Phase 6**: Tool migration
**Phase 7**: Advanced features

## Backward Compatibility Strategy

During migration, maintain parallel implementations:
- Keep `src/explode/` as-is (legacy)
- Build new library in `src/libexe/` (modern)
- Tools initially link against both
- Gradually switch components to new library
- Remove legacy code when all tests pass

## Success Metrics

1. **Correctness**: All existing test cases pass
2. **Performance**: New library matches or exceeds old performance
3. **Extensibility**: Adding new format takes < 100 lines of datascript
4. **Maintainability**: Code complexity reduced by >50%
5. **Capability**: Supports MZ/NE/PE/PE32+ parsing and resource extraction

## Open Questions

1. Which C++ standard to target? (C++17, C++20, C++23)
2. Datascript integration: submodule, package manager, or bundled?
3. Build system: Keep CMake or consider alternatives?
4. External dependencies: Allow (e.g., for crypto) or stay minimal?
5. Binary compatibility: Shared library ABI stability requirements?

## Next Steps

1. Review and refine this strategy
2. Investigate datascript code generation workflow
3. Create minimal proof-of-concept (Phase 1.3)
4. Evaluate feasibility and adjust plan accordingly
