# DOS Extender Stripping - Implementation Specification

Based on analysis of SUNSYS Bind Utility (SB) from DOS/32A sources.

## Overview

DOS extenders (DOS/4GW, DOS/32A, PMODE/W, etc.) allow 32-bit protected mode executables to run under DOS. These executables are "bound" - a DOS MZ stub loader is prepended to the actual 32-bit Linear Executable (LE/LX/LC).

**Goal**: Strip the DOS extender stub to expose the raw LE/LX/LC executable for analysis.

## File Structure: Bound Executable

```
Offset      Content
──────────────────────────────────────────────────────────
0x0000      MZ Header (DOS stub)
            ├─ 0x00: Magic 'MZ' (0x5A4D)
            ├─ 0x02: Bytes on last page
            ├─ 0x04: Pages in file (512-byte units)
            ├─ 0x18: Relocation table offset
            └─ 0x3C: Offset to LE/LX header  ◄── KEY FIELD

0x0040+     DOS stub code (extender loader)
            Contains extender signature strings

<offset>    LE/LX/LC Header (32-bit executable)
            ├─ 0x00: Magic 'LE'/'LX'/'LC'
            ├─ 0x80: Data Pages Offset  ◄── NEEDS ADJUSTMENT
            └─ ...sections, fixups, data...
EOF
──────────────────────────────────────────────────────────
```

## Detection Algorithm

### Step 1: Identify File Type

```cpp
enum class bound_exec_type {
    UNKNOWN,
    BOUND_MZ,       // MZ header present, contains LE/LX/LC
    UNBOUND_LE,     // Raw LE (magic 'LE' at offset 0)
    UNBOUND_LX,     // Raw LX (magic 'LX' at offset 0)
    UNBOUND_LC,     // Raw LC (magic 'LC' at offset 0)
    UNBOUND_PE,     // Raw PE (magic 'PE' at offset 0)
    UNBOUND_PMW1    // Raw PMODE/W (magic 'PMW1' at offset 0)
};

// Check first 4 bytes
uint16_t magic = read_u16(0);
uint32_t magic32 = read_u32(0);

if (magic == 0x5A4D) {          // 'MZ'
    return BOUND_MZ;
} else if (magic == 0x454C) {   // 'LE'
    return UNBOUND_LE;
} else if (magic == 0x584C) {   // 'LX'
    return UNBOUND_LX;
} else if (magic == 0x434C) {   // 'LC'
    return UNBOUND_LC;
} else if (magic == 0x4550) {   // 'PE'
    return UNBOUND_PE;
} else if (magic32 == 0x31574D50) { // 'PMW1'
    return UNBOUND_PMW1;
}
```

### Step 2: Locate LE/LX/LC Header in Bound Executable

**Method A: Quick Path (Standard Binding)**

Most bound executables store the LE/LX offset at MZ header offset 0x3C:

```cpp
uint32_t le_offset = 0;

// Check if relocation table is at standard position
uint16_t reloc_offset = read_u16(0x18);
if (reloc_offset >= 0x40) {
    // Check offset at 0x3C (same field as PE uses)
    le_offset = read_u32(0x3C);
    if (le_offset != 0 && le_offset < file_size) {
        // Verify magic at that offset
        uint16_t magic = read_u16(le_offset);
        if (magic == 0x454C || magic == 0x584C || magic == 0x434C) {
            return le_offset;  // Found it
        }
    }
}
```

**Method B: MZ Chain Traversal**

Some files have chained MZ headers. Walk through them:

```cpp
uint32_t offset = 0;

while (offset < file_size) {
    uint16_t magic = read_u16(offset);

    if (magic == 0x5A4D || magic == 0x5742) {  // 'MZ' or 'BW' (Watcom)
        // Calculate size of this MZ block
        uint16_t pages = read_u16(offset + 0x04);
        uint16_t last_page = read_u16(offset + 0x02);
        uint32_t mz_size = (pages * 512);
        if (last_page > 0) {
            mz_size = mz_size - 512 + last_page;
        }
        offset += mz_size;
    } else {
        // Not MZ - check if LE/LX/LC
        break;
    }
}

// Now search from current offset for LE/LX/LC magic
```

**Method C: Linear Search (Fallback)**

If above methods fail, search the entire file:

```cpp
for (uint32_t offset = 0; offset < file_size - 4; offset += 2) {
    uint16_t magic = read_u16(offset);
    uint16_t next = read_u16(offset + 2);

    // LE and LX have 0x00 at offset +2
    if ((magic == 0x454C || magic == 0x584C) && next == 0) {
        return offset;
    }
    // LC doesn't require next == 0
    if (magic == 0x434C) {
        return offset;
    }
}
```

### Step 3: Identify Extender Type (Optional)

Check for signature strings at known offsets in DOS stub:

| Extender   | Offset | Signature                       |
|------------|--------|---------------------------------|
| DOS/32A    | 0x9A   | "DOS/32 Advanced."              |
| DOS/32A    | 0x9C   | "DOS/32A"                       |
| STUB/32C   | 0x6A   | "DOS/32 Advanced!"              |
| STUB/32C   | 0x6C   | "STUB/32C"                      |
| STUB/32A   | 0x40   | "DOS/32 Advanced stub file."    |
| STUB/32A   | 0x40   | "STUB/32A"                      |
| DOS/4G     | 0x25A  | "DOS/4G"                        |
| DOS/4G     | 0x25C  | "DOS/4G"                        |
| PMODE/W    | 0x55   | "PMODE/W"                       |

```cpp
enum class extender_type {
    UNKNOWN,
    DOS32A,
    STUB32C,
    STUB32A,
    DOS4G,
    DOS4GW,
    PMODEW
};
```

## Stripping Algorithm

### Input
- Bound executable (MZ + LE/LX/LC)
- `le_offset`: File offset where LE/LX/LC header begins

### Output
- Raw LE/LX/LC executable (header at offset 0)

### Process

```cpp
std::vector<uint8_t> strip_extender(
    std::span<const uint8_t> bound_file,
    uint32_t le_offset)
{
    // 1. Calculate output size
    size_t output_size = bound_file.size() - le_offset;

    // 2. Copy from LE header to end
    std::vector<uint8_t> output(
        bound_file.begin() + le_offset,
        bound_file.end()
    );

    // 3. Adjust absolute file offsets for LE/LX only
    uint16_t magic = read_u16(output, 0);
    if (magic == 0x454C || magic == 0x584C) {  // LE or LX
        // Offset 0x80: DataPagesOffsetFromTopOfFile (always adjust)
        uint32_t data_pages_offset = read_u32(output, 0x80);
        data_pages_offset -= le_offset;
        write_u32(output, 0x80, data_pages_offset);

        // Offset 0x88: NonResidentNamesTableOffset (adjust if non-zero)
        uint32_t nonres_offset = read_u32(output, 0x88);
        if (nonres_offset != 0) {
            nonres_offset -= le_offset;
            write_u32(output, 0x88, nonres_offset);
        }

        // Offset 0x98: DebugInformationOffset (adjust if non-zero)
        uint32_t debug_offset = read_u32(output, 0x98);
        if (debug_offset != 0) {
            debug_offset -= le_offset;
            write_u32(output, 0x98, debug_offset);
        }
    }

    return output;
}
```

### Critical: Data Pages Offset Adjustment

The LE/LX header contains an absolute file offset at position 0x80 that points to the data pages. When the DOS stub is removed, this offset must be adjusted:

```
Before:  Data Pages Offset = 0x5000 (points to data in original file)
         DOS stub size = 0x3000

After:   Data Pages Offset = 0x5000 - 0x3000 = 0x2000
```

**Note**: LC (Linear Compressed) format does NOT require this adjustment - it uses different offset semantics.

## LE/LX Header Structure (IMAGE_LE_HEADER / IMAGE_LX_HEADER)

Based on `docs/le_exe_headers.h` and `docs/lxexe.doc` (IBM LX specification).

```
Offset  Size  Field                              Notes
────────────────────────────────────────────────────────────────────────
0x00    2     SignatureWord                      'LE' (0x454C) or 'LX' (0x584C)
0x02    1     ByteOrder                          0=Little Endian
0x03    1     WordOrder                          0=Little Endian
0x04    4     ExecutableFormatLevel              0 for initial version
0x08    2     CPUType                            1=286, 2=386, 3=486
0x0A    2     TargetOperatingSystem              0=Unknown, 1=OS/2, 2=Win, 3=DOS4, 4=Win386
0x0C    4     ModuleVersion                      User-specified version
0x10    4     ModuleTypeFlags                    See flag definitions below
0x14    4     NumberOfMemoryPages                Total logical pages
0x18    4     InitialObjectCSNumber              Object # containing EIP (1-based)
0x1C    4     InitialEIP                         Entry point offset
0x20    4     InitialSSObjectNumber              Object # containing ESP (1-based)
0x24    4     InitialESP                         Stack pointer offset
0x28    4     MemoryPageSize                     Usually 4096 (0x1000)
0x2C    4     BytesOnLastPage (LE)               LE: Bytes on last page
              PageOffsetShift (LX)               LX: Shift for page offsets (default 12)
0x30    4     FixupSectionSize                   Size of fixup tables
0x34    4     FixupSectionChecksum
0x38    4     LoaderSectionSize                  Size of loader section
0x3C    4     LoaderSectionChecksum
0x40    4     ObjectTableOffset                  Relative to LX header start
0x44    4     ObjectTableEntries                 Number of objects/segments
0x48    4     ObjectPageMapOffset                Object Page Table offset
0x4C    4     ObjectIterateDataMapOffset         Iterated pages (=0x80 or 0 in OS/2)
0x50    4     ResourceTableOffset
0x54    4     ResourceTableEntries
0x58    4     ResidentNamesTableOffset
0x5C    4     EntryTableOffset
0x60    4     ModuleDirectivesTableOffset
0x64    4     ModuleDirectivesTableEntries
0x68    4     FixupPageTableOffset
0x6C    4     FixupRecordTableOffset
0x70    4     ImportedModulesNameTableOffset
0x74    4     ImportedModulesCount
0x78    4     ImportedProcedureNameTableOffset
0x7C    4     PerPageChecksumTableOffset
0x80    4     DataPagesOffsetFromTopOfFile       ◄── ABSOLUTE FILE OFFSET - ADJUST!
0x84    4     PreloadPagesCount
0x88    4     NonResidentNamesTableOffset        Absolute file offset
0x8C    4     NonResidentNamesTableLength
0x90    4     NonResidentNamesTableChecksum
0x94    4     AutomaticDataObject
0x98    4     DebugInformationOffset
0x9C    4     DebugInformationLength
0xA0    4     PreloadInstancePagesNumber
0xA4    4     DemandInstancePagesNumber
0xA8    4     HeapSize
0xAC    4     StackSize
0xB0    8     Reserved[8]
────────────────────────────────────────────────────────────────────────
        (VxD-specific fields follow at 0xB8 for Windows VxDs)
0xB8    4     WindowsVXDVersionInfoResourceOffset
0xBC    4     WindowsVXDVersionInfoResourceLength
0xC0    2     WindowsVXDDeviceID
0xC2    2     WindowsDDKVersion
────────────────────────────────────────────────────────────────────────
```

### Module Type Flags (offset 0x10)

```
Bit     Meaning
────────────────────────────────────────────────────────
0x0004  Per-Process Library Initialization (DLL only)
0x0010  Internal fixups applied (has preferred load address)
0x0020  External fixups applied
0x0100  Incompatible with PM windowing
0x0200  Compatible with PM windowing
0x0300  Uses PM windowing API
0x2000  Module is not loadable (link errors)
0x8000  Module is a DLL (Library Module)
0x18000 Protected Memory Library Module
0x20000 Physical Device Driver
0x28000 Virtual Device Driver
────────────────────────────────────────────────────────
```

### Key Difference: LE vs LX

**Offset 0x2C interpretation:**
- **LE format**: `BytesOnLastPage` - literal byte count on last page
- **LX format**: `PageOffsetShift` - bit shift for page table offsets (default=12 for 4KB alignment)

**Object Page Table Entry format:**
- **LE format**: 4 bytes per entry (3-byte offset + 1-byte flags) - offset is direct
- **LX format**: 8 bytes per entry (4-byte offset + 2-byte size + 2-byte flags) - offset shifted

### Object Table Entry (24 bytes each)

```cpp
struct LE_OBJECT_TABLE_ENTRY {
    uint32_t VirtualSize;        // 0x00: Virtual segment size
    uint32_t BaseRelocAddress;   // 0x04: Relocation base address
    uint32_t ObjectFlags;        // 0x08: See LE_OBJECT_FLAGS
    uint32_t PageTableIndex;     // 0x0C: Index into Object Page Table (1-based)
    uint32_t PageTableEntries;   // 0x10: Number of page table entries
    uint32_t Reserved;           // 0x14: Reserved (must be 0)
};
```

### Object Flags

```
Flag        Value    Meaning
─────────────────────────────────────────────────────
READABLE    0x0001   Object is readable
WRITABLE    0x0002   Object is writable
EXECUTABLE  0x0004   Object is executable
RESOURCE    0x0008   Object contains resources
DISCARDABLE 0x0010   Object is discardable
SHARED      0x0020   Object is shared
PRELOAD     0x0040   Object has preload pages
INVALID     0x0080   Object has invalid pages
ZEROFILL    0x0100   Object has zero-fill pages
RESIDENT    0x0200   Object is resident
CONTIGUOUS  0x0300   Object is resident & contiguous
LOCKABLE    0x0400   Object is resident & long-lockable
16_16_ALIAS 0x1000   16:16 alias required
BIG         0x2000   Big/default bit setting
CONFORMING  0x4000   Object is conforming for code
IOPL        0x8000   Object has I/O privilege level
─────────────────────────────────────────────────────
```

## Offsets That Need Adjustment When Stripping

When the DOS stub is removed, these **absolute file offsets** must be adjusted:

| Offset | Field                              | Adjustment Needed |
|--------|------------------------------------|--------------------|
| 0x80   | DataPagesOffsetFromTopOfFile       | **YES** - subtract stub size |
| 0x88   | NonResidentNamesTableOffset        | **YES** - subtract stub size |
| 0x98   | DebugInformationOffset             | **YES** - if non-zero |

**Offsets relative to LE/LX header start (no adjustment needed):**
- 0x40: ObjectTableOffset
- 0x48: ObjectPageMapOffset
- 0x4C: ObjectIterateDataMapOffset
- 0x50: ResourceTableOffset
- 0x58: ResidentNamesTableOffset
- 0x5C: EntryTableOffset
- 0x60: ModuleDirectivesTableOffset
- 0x68: FixupPageTableOffset
- 0x6C: FixupRecordTableOffset
- 0x70: ImportedModulesNameTableOffset
- 0x78: ImportedProcedureNameTableOffset
- 0x7C: PerPageChecksumTableOffset

## API Design for libexe

```cpp
namespace libexe {

// Detection
struct dos_extender_info {
    bool is_bound;                    // Has DOS extender stub
    extender_type extender;           // Which extender (if identifiable)
    uint32_t le_header_offset;        // Offset to LE/LX/LC header
    uint16_t exec_type;               // LE, LX, LC, PE, PMW1
};

dos_extender_info detect_dos_extender(std::span<const uint8_t> data);

// Stripping
std::vector<uint8_t> strip_dos_extender(std::span<const uint8_t> data);

// Or integrated into le_file class
class le_file {
public:
    static le_file from_memory(std::span<const uint8_t> data);

    // Returns true if file had DOS extender that was stripped
    bool was_bound() const;
    extender_type get_extender_type() const;

    // Access to raw LE/LX data (after stripping if needed)
    std::span<const uint8_t> data() const;
};

} // namespace libexe
```

## Test Cases

1. **DOS/4GW bound LE** - Standard game executable
2. **DOS/32A bound LE** - With identifiable signature
3. **PMODE/W bound LE** - Different stub format
4. **Unbound LE** - Already stripped, no adjustment needed
5. **Chained MZ headers** - Multiple stubs concatenated
6. **LC compressed** - No data pages adjustment
7. **Offset at 0x3C = 0** - Requires linear search

## References

- DOS/32A source: `1/dos32a/src/sb/`
- LE/LX format: OS/2 Linear Executable specification
- DOS/4G: Tenberry/Rational Systems documentation
