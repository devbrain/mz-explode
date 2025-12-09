# PE Edge Cases and Implementation Recommendations

This document summarizes edge cases and malformations in PE files that libexe must handle correctly. Based on analysis of:
- "Undocumented PECOFF" (ReversingLabs, BlackHat USA 2011)
- "Virtual Code" (roy g biv, 2012)
- Corkami PE test corpus observations

## 1. DOS & PE Header Edge Cases

### 1.1 e_lfanew Flexibility
**Issue**: The `e_lfanew` field at offset 0x3C can point anywhere in the first 4GB of the file.

**Implications**:
- PE header can be at unusual locations (not immediately after DOS stub)
- PE header can be in file overlay (not mapped to memory)
- PE header can overlap with section data

**Implementation**:
- [x] Already handled: We read from file offset, not memory
- [x] Diagnostic: `PE_HEADER_IN_OVERLAY` when PE header is in overlay region
- [ ] Add validation: Warn if PE header overlaps with mapped sections

### 1.2 Dual PE Header
**Issue**: Different header visible on disk vs in memory when PE header spans section boundary.

**Detection**:
- PE header at offset where `e_lfanew + header_size > SizeOfHeaders`
- Part of header comes from section data in memory

**Implementation**:
- [x] Already handled: We parse from disk
- [x] Diagnostic: `PE_DUAL_HEADER` when header extends beyond SizeOfHeaders

### 1.3 Self-Destructing PE Header
**Issue**: PE header in overlay (beyond SizeOfHeaders) not mapped to memory.

**Implementation**:
- [x] Already handled: We parse from disk
- [x] Diagnostic: `PE_HEADER_IN_OVERLAY` (see 1.1)

### 1.4 Writable PE Header
**Issue**: When `FileAlignment == SectionAlignment <= 0x200`, the header becomes writable (RWX).

**Implementation**:
- [x] Detect low-alignment mode: `is_low_alignment()` method
- [x] Diagnostic: `OPT_LOW_ALIGNMENT` and `PE_WRITABLE_HEADER`

## 2. Section Table Edge Cases

### 2.1 Zero Sections
**Issue**: Windows Vista+ allows `NumberOfSections = 0`. All code/data is in header.

**Requirements**:
- `SizeOfHeaders >= SizeOfImage`
- `FileAlignment == SectionAlignment <= 0x200`

**Implementation**:
- [x] Handle `section_count() == 0` gracefully
- [ ] RVA-to-offset conversion must work without sections
- [x] Diagnostic: `COFF_ZERO_SECTIONS`

### 2.2 Maximum Sections
**Issue**: PECOFF spec says max 96 sections, but Windows allows up to 0xFFFF.

**Implementation**:
- [x] We use `uint16_t` for section count
- [x] Diagnostic: `COFF_EXCESSIVE_SECTIONS` when > 96 sections
- [x] No integer overflow in memory allocation

### 2.3 SizeOfOptionalHeader Abuse
**Issue**: Can be larger than actual optional header, pushing section table to unusual location.

**Implementation**:
- [x] We respect `SizeOfOptionalHeader` for section table offset
- [x] Diagnostic: `OPT_OVERSIZED_OPTIONAL_HDR` for oversized optional header

## 3. Alignment Edge Cases

### 3.1 Low Alignment Mode
**Issue**: When `FileAlignment == SectionAlignment` and both `<= 0x200`:
- Raw addresses equal virtual addresses
- Header becomes writable
- Special handling by loader

**Implementation**:
- [x] Detect low alignment mode: `is_low_alignment()` method
- [ ] Adjust RVA/offset conversion for low alignment
- [x] Diagnostic: `OPT_LOW_ALIGNMENT`

### 3.2 FileAlignment Rounding
**Issue**: Section raw offsets are rounded: `(raw_offset / FileAlignment) * FileAlignment`

**Formula**: Actual offset = `(PointerToRawData / 0x200) * 0x200` when FileAlignment < 0x200

**Implementation**:
- [x] Apply alignment rounding: `pe_section::aligned_raw_offset()` method
- [x] Section stores `file_alignment` for proper rounding
- [x] Used in section data extraction

### 3.3 Non-Power-of-Two Alignment
**Issue**: Loaders may accept non-standard alignment values.

**Implementation**:
- [x] Diagnostic: `OPT_NON_POWER2_ALIGNMENT` when alignment is not power of 2
- [x] Still attempt to parse

## 4. Entry Point Edge Cases

### 4.1 Zero Entry Point
**Issue**: `AddressOfEntryPoint = 0` causes execution at DOS header (MZ = `DEC EBP; POP EDX`).

**Implementation**:
- [x] Diagnostic: `OPT_ZERO_ENTRY_POINT` (INFO level)
- [x] Don't reject file as invalid

### 4.2 Entry Point Outside Image
**Issue**: Entry point can be RVA pointing outside image (e.g., to kernel32).

**Implementation**:
- [x] Diagnostic: `OPT_EP_OUTSIDE_IMAGE`
- [ ] Detect if EP points to known DLL ranges

### 4.3 Entry Point in Header
**Issue**: Entry point within header region (< SizeOfHeaders).

**Implementation**:
- [x] Diagnostic: `OPT_EP_IN_HEADER`

## 5. Relocation Edge Cases

### 5.1 Relocation Types
All 12 relocation types (0-11) and their actual behavior:

| Type | Name | Behavior |
|------|------|----------|
| 0 | IMAGE_REL_BASED_ABSOLUTE | Ignored (padding) |
| 1 | IMAGE_REL_BASED_HIGH | Adds high 16 bits of delta to WORD |
| 2 | IMAGE_REL_BASED_LOW | Adds low 16 bits (always 0 due to 64KB alignment) |
| 3 | IMAGE_REL_BASED_HIGHLOW | Adds 32-bit delta to DWORD |
| 4 | IMAGE_REL_BASED_HIGHADJ | Two slots, complex 28-bit calculation |
| 5 | IMAGE_REL_BASED_MIPS_JMPADDR | MIPS jump encoding (usable for obfuscation) |
| 6 | Same as type 0 | Ignored |
| 7 | Same as type 0 | Ignored |
| 8 | Invalid | Causes load error |
| 9 | IMAGE_REL_BASED_MIPS_JMPADDR16 | 64-bit MIPS encoding |
| 10 | IMAGE_REL_BASED_DIR64 | 64-bit delta (PE32+) |
| 11+ | Reserved | May cause error |

**Implementation**:
- [x] Parse all relocation types
- [x] Diagnostic: `RELOC_UNUSUAL_TYPE` for types 1, 2, 4, 5, 9 on x86/x64
- [x] Diagnostic: `RELOC_INVALID_TYPE` for type 8 or >10

### 5.2 Virtual Code Technique
**Issue**: Relocations can construct code at runtime from zeroed sections.

**Detection**:
- `ImageBase` set to invalid value (0 or >2GB like 0xFFFE0000)
- Forces relocation to 0x10000
- Large number of relocations to same section
- Section is writable but mostly zeros on disk

**Implementation**:
- [x] Detect impossible `ImageBase` values: `effective_image_base()` method
- [x] Diagnostic: `RELOC_VIRTUAL_CODE` when invalid ImageBase + high reloc count
- [x] Diagnostic: `RELOC_HIGH_DENSITY` for sections with unusually high relocation density

### 5.3 Header Modification via Relocations
**Issue**: Relocations can modify PE header if header is writable (low alignment mode).

**Fields that CANNOT be modified** (cached before relocs):
- "MZ" signature
- "PE" signature
- Machine
- NumberOfSections
- SizeOfOptionalHeader
- Magic
- AddressOfEntryPoint (cached, but ImageBase change affects it indirectly)

**Implementation**:
- [x] Diagnostic: `RELOC_HEADER_TARGET` for relocations targeting header region

### 5.4 IMAGE_FILE_RELOCS_STRIPPED Ignored
**Issue**: This flag in Characteristics is ignored by loader; relocations still processed.

**Implementation**:
- [x] Diagnostic: `COFF_RELOCS_STRIPPED_IGNORED` when flag set but relocs present
- [x] Always check for relocation directory regardless of flag

## 6. Import Table Edge Cases

### 6.1 Empty IAT Entries
**Issue**: If IAT is empty/null, DLL is not loaded (DLL name can be non-existent file).

**Implementation**:
- [x] Don't fail on non-existent DLL names if IAT is empty
- [x] Diagnostic: `IMP_EMPTY_IAT` when DLL has no imported functions

### 6.2 Non-ASCII Import Names
**Issue**: Function names can be any byte sequence (not just printable ASCII).

**Implementation**:
- [x] Diagnostic: `IMP_BINARY_NAME` for non-printable characters in DLL/function names
- [ ] Store names as byte vectors, not strings (future enhancement)
- [ ] Provide sanitized string accessor (future enhancement)

### 6.3 Self-Forwarding Exports
**Issue**: File imports from its own exports, which forward to real APIs.

**Detection**:
- Import DLL name matches own module name
- Export has forwarder string pointing to other DLL

**Implementation**:
- [x] Detect self-imports: `IMP_SELF_IMPORT`
- [x] Detect circular forwarders (self-forwarding): `EXP_FORWARDER_LOOP`
- [ ] Resolve forwarder chains (future enhancement)
- [ ] Detect import forwarder loops: `IMP_FORWARDER_LOOP` (future enhancement)

### 6.4 Missing Null Terminator
**Issue**: Last import directory entry may be truncated at file end.

**Implementation**:
- [x] We handle this by checking bounds
- [x] Diagnostic: `IMP_TRUNCATED` when import directory missing null terminator

## 7. ImageBase Edge Cases

### 7.1 Zero ImageBase
**Issue**: `ImageBase = 0` requires relocation table. File loads at 0x10000.

**Windows Versions**:
- Pre-Win7: Allowed
- Win7+: Not allowed (but 0xFFFE0000 works)

**Implementation**:
- [x] Detect zero or kernel-space ImageBase: `effective_image_base()` method
- [x] Calculate actual load address (returns 0x10000 for invalid ImageBase)
- [x] Diagnostic: `OPT_INVALID_IMAGEBASE`

### 7.2 Non-Aligned ImageBase
**Issue**: ImageBase must be 64KB aligned, but invalid values cause predictable relocation.

**Implementation**:
- [x] Diagnostic: `OPT_UNALIGNED_IMAGEBASE`
- [x] `effective_image_base()` returns 0x10000 for unaligned values

## 8. Data Directory Edge Cases

### 8.1 Size Field Semantics
Different directories interpret size differently:
- Some use it strictly (Security)
- Some ignore it (Import, Export - null-terminated)
- Some use it as count (Exception)

**Implementation**:
- [x] Each parser handles size appropriately
- [ ] Document size semantics per directory

### 8.2 Overlapping Directories
**Issue**: Multiple data directories can point to same region.

**Implementation**:
- [x] Detect overlapping directories: `detect_overlapping_directories()`
- [x] Diagnostic: `OVERLAPPING_DIRECTORIES`

### 8.3 Directory in Header
**Issue**: Data directories can be within header region.

**Implementation**:
- [x] Handle directories in header
- [x] Diagnostic: `DIRECTORY_IN_HEADER`

## 9. Implemented Diagnostics API

The diagnostics system uses a comprehensive set of diagnostic codes defined in `include/libexe/core/diagnostic.hpp`:

```cpp
// Key methods on pe_file:
[[nodiscard]] const diagnostic_collector& diagnostics() const;
[[nodiscard]] bool has_diagnostic(diagnostic_code code) const;
[[nodiscard]] bool has_anomalies() const;
[[nodiscard]] bool has_parse_errors() const;
[[nodiscard]] bool is_low_alignment() const;
[[nodiscard]] uint64_t effective_image_base() const;
```

### Implemented Diagnostic Codes

| Code | Severity | Description |
|------|----------|-------------|
| `PE_HEADER_IN_OVERLAY` | ANOMALY | PE header beyond mapped region |
| `PE_DUAL_HEADER` | ANOMALY | Different header on disk vs memory |
| `PE_WRITABLE_HEADER` | WARNING | Header is RWX (low alignment) |
| `COFF_ZERO_SECTIONS` | ANOMALY | NumberOfSections = 0 |
| `COFF_EXCESSIVE_SECTIONS` | WARNING | NumberOfSections > 96 |
| `COFF_RELOCS_STRIPPED_IGNORED` | WARNING | Flag set but relocs present |
| `OPT_ZERO_ENTRY_POINT` | INFO | AddressOfEntryPoint = 0 |
| `OPT_EP_OUTSIDE_IMAGE` | ANOMALY | EP beyond SizeOfImage |
| `OPT_EP_IN_HEADER` | WARNING | EP within header region |
| `OPT_INVALID_IMAGEBASE` | WARNING | ImageBase = 0 or kernel space |
| `OPT_UNALIGNED_IMAGEBASE` | WARNING | ImageBase not 64KB aligned |
| `OPT_LOW_ALIGNMENT` | WARNING | Low alignment mode |
| `OPT_OVERSIZED_OPTIONAL_HDR` | WARNING | SizeOfOptionalHeader > expected |
| `OPT_NON_POWER2_ALIGNMENT` | WARNING | Alignment not power of 2 |
| `IMP_EMPTY_IAT` | WARNING | DLL has empty IAT |
| `IMP_BINARY_NAME` | WARNING | Non-printable chars in import name |
| `IMP_SELF_IMPORT` | WARNING | Module imports from itself |
| `IMP_TRUNCATED` | WARNING | Import directory truncated |
| `EXP_FORWARDER_LOOP` | WARNING | Export forwarder loop detected |
| `EXP_BINARY_NAME` | WARNING | Non-printable chars in export name |
| `EXP_ORDINAL_GAP` | INFO | Large gap in ordinal numbers |
| `RELOC_UNUSUAL_TYPE` | WARNING | Types 1,2,4,5,9 on x86/x64 |
| `RELOC_INVALID_TYPE` | ANOMALY | Type 8 or >10 |
| `RELOC_HEADER_TARGET` | WARNING | Relocation targets header |
| `RELOC_VIRTUAL_CODE` | WARNING | Virtual code pattern detected |
| `RELOC_HIGH_DENSITY` | INFO | High relocation density in section |
| `OVERLAPPING_DIRECTORIES` | WARNING | Multiple directories share region |
| `DIRECTORY_IN_HEADER` | INFO | Data directory within header |

## 10. Implementation Priority

### Phase 1: Critical (Correctness) - COMPLETE ✓
1. ~~Zero-section file handling~~ ✓
2. ~~Low alignment mode detection and handling~~ ✓
3. ~~RVA-to-offset with alignment rounding~~ ✓ (`aligned_raw_offset()` method)
4. ~~Relocation type parsing (all types)~~ ✓

### Phase 2: Important (Robustness) - COMPLETE ✓
5. ~~Anomaly detection framework~~ ✓ (diagnostics system)
6. ~~Import name binary handling~~ ✓ (`IMP_BINARY_NAME`)
7. ~~Self-forwarding export detection~~ ✓ (`EXP_FORWARDER_LOOP`)
8. ~~Header relocation detection~~ ✓

### Phase 3: Nice-to-Have (Analysis) - COMPLETE ✓
9. ~~Virtual code detection~~ ✓
10. ~~Detailed anomaly reporting~~ ✓
11. ~~Relocation density analysis~~ ✓ (`RELOC_HIGH_DENSITY`)
12. ~~Circular forwarder detection~~ ✓ (`EXP_FORWARDER_LOOP`)
13. ~~Self-import detection~~ ✓ (`IMP_SELF_IMPORT`)
14. ~~Truncated import detection~~ ✓ (`IMP_TRUNCATED`)
15. ~~Empty IAT detection~~ ✓ (`IMP_EMPTY_IAT`)
16. ~~Export ordinal gap detection~~ ✓ (`EXP_ORDINAL_GAP`)
17. ~~Non-power-of-2 alignment warning~~ ✓ (`OPT_NON_POWER2_ALIGNMENT`)

## 11. Test Cases Required

From Corkami corpus (already have):
- `65535sects.exe` - Maximum sections
- `lowaldiff.exe` - Low alignment
- `ibreloc.exe` - ImageBase relocation
- `fakerelocs.exe` - Relocation tricks

Additional test cases needed:
- [ ] Zero-section PE file
- [ ] PE header in overlay
- [ ] Virtual code sample
- [ ] Self-importing PE
- [ ] All relocation types

## References

1. "Undocumented PECOFF" - ReversingLabs, BlackHat USA 2011
2. "Virtual Code Windows 7 update" - roy g biv, 2012
3. Microsoft PE/COFF Specification v11.0
4. Corkami PE wiki: https://github.com/corkami/docs/blob/master/PE/PE.md
