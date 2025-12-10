# Rich Signature in PE Files

## Overview

The **Rich Signature** (also called Rich Header) is an undocumented structure embedded by Microsoft's linker in PE executables. It contains metadata about the build tools, compiler versions, and libraries used during compilation.

**Key Facts:**
- Present since Visual C++ 6.0 (circa 1998)
- Only in native PE executables (not .NET assemblies)
- Located between DOS stub and PE header
- Completely undocumented by Microsoft
- Can be safely removed without affecting execution
- Valuable for forensic and malware analysis

**Source:** [NTCore - The Undocumented Rich Header](https://ntcore.com/files/richsign.htm)

## Location and Structure

### Position in PE File

```
Offset 0x00:  DOS Header (64 bytes)
Offset 0x40:  DOS Stub (variable size, typically padded to 0x80)
              |
              +---> [Rich Signature lives here]
              |
Offset 0x80+: PE Signature ("PE\0\0")
```

The Rich Signature typically starts around offset 0x80, but this can vary. It always ends with the "Rich" marker followed by the XOR mask.

### Binary Format

```
┌─────────────────────────────────────┐
│ "DanS" ⊕ XOR_MASK  (4 bytes)       │ ← Header (encrypted)
├─────────────────────────────────────┤
│ PRODUCT_ID | VERSION  (4 bytes)    │ ← Entry 1 (encrypted)
│ COUNT                (4 bytes)      │
├─────────────────────────────────────┤
│ PRODUCT_ID | VERSION  (4 bytes)    │ ← Entry 2 (encrypted)
│ COUNT                (4 bytes)      │
├─────────────────────────────────────┤
│ ...                                  │ ← More entries
├─────────────────────────────────────┤
│ "Rich"               (4 bytes)      │ ← Terminator (plaintext)
│ XOR_MASK             (4 bytes)      │ ← XOR key (plaintext)
└─────────────────────────────────────┘
```

### Encryption Scheme

The entire Rich Signature (except the final "Rich" marker and XOR mask) is encrypted using a simple XOR cipher:

```
Encrypted_Value = Plaintext_Value ⊕ XOR_MASK
```

To decrypt, apply the same XOR operation:

```
Plaintext_Value = Encrypted_Value ⊕ XOR_MASK
```

The XOR mask is stored in plaintext immediately after the "Rich" terminator, making decryption trivial.

## Data Format

### Header

```c
struct rich_header_start {
    uint32_t dans_encrypted;  // "DanS" ⊕ XOR_MASK
                              // 0x536E6144 ⊕ XOR_MASK
};
```

The header is simply the string "DanS" (0x536E6144) XORed with the mask. This serves as a signature to identify the start of the structure.

### Entry Format

Each entry is 8 bytes (two DWORDs):

```c
struct rich_entry {
    uint32_t data1;  // Encrypted: (product_id << 16) | version
    uint32_t data2;  // Encrypted: usage count
};
```

After decryption:

```c
struct rich_entry_decrypted {
    uint16_t product_id;  // High word of data1
    uint16_t build_number; // Low word of data1
    uint32_t count;        // data2 - how many times this component was used
};
```

### Terminator

```c
struct rich_terminator {
    uint32_t rich_marker;  // "Rich" = 0x68636952 (plaintext, not encrypted)
    uint32_t xor_mask;     // XOR key used for encryption (plaintext)
};
```

## Product IDs

The `product_id` field identifies which Microsoft build tool or library component was used.

**Source:** The comprehensive compiler ID database below is derived from [richprint's comp_id.txt](https://github.com/dishather/richprint/blob/master/comp_id.txt).

### Component Type Markers

The following markers identify the type of object file or tool output:

| Marker | Description |
|--------|-------------|
| `[ C ]` | Object file produced by C compiler |
| `[C++]` / `[CPP]` | Object file produced by C++ compiler |
| `[ASM]` | Object file produced by assembler (MASM) |
| `[RES]` | Object file produced by CVTRES converter |
| `[LNK]` | Linker output |
| `[EXP]` | DLL export record in library file |
| `[IMP]` | DLL import record in library file |
| `[OMF]` | Object file produced by CVTOMF converter |
| `[LTC]` | LTCG C (link-time code generation) |
| `[LT+]` | LTCG C++ |
| `[LTM]` | LTCG MSIL |
| `[PGO]` | Profile-guided optimization, profiling phase, C |
| `[PG+]` | Profile-guided optimization, profiling phase, C++ |
| `[POC]` | Profile-guided optimization, optimized build, C |
| `[PO+]` | Profile-guided optimization, optimized build, C++ |
| `[CIL]` | CVTCIL C (MSIL conversion) |
| `[CI+]` | CVTCIL C++ |
| `[PGD]` | CVTPGD (PGO database) |
| `[AOb]` | AliasObj |
| `[BSC]` | Basic compiler |

### Visual Studio 2015+ (Modern Unified IDs)

Starting with VS 2015, product IDs are unified across versions. The build number distinguishes releases.

| Product ID | Type | Description |
|------------|------|-------------|
| 0x00FD | `[AOb]` | VS2015+ AliasObj |
| 0x00FE | `[PGD]` | VS2015+ CVTPGD |
| 0x00FF | `[RES]` | VS2015+ Resource compiler (CVTRES) |
| 0x0100 | `[EXP]` | VS2015+ Export |
| 0x0101 | `[IMP]` | VS2015+ Import library |
| 0x0102 | `[LNK]` | VS2015+ Linker |
| 0x0103 | `[ASM]` | VS2015+ MASM |
| 0x0104 | `[ C ]` | VS2015+ C compiler |
| 0x0105 | `[C++]` | VS2015+ C++ compiler |
| 0x0106 | `[CIL]` | VS2015+ CVTCIL C |
| 0x0107 | `[CI+]` | VS2015+ CVTCIL C++ |
| 0x0108 | `[LTC]` | VS2015+ LTCG C |
| 0x0109 | `[LT+]` | VS2015+ LTCG C++ |
| 0x010A | `[LTM]` | VS2015+ LTCG MSIL |
| 0x010B | `[PGO]` | VS2015+ POGO I C |
| 0x010C | `[PG+]` | VS2015+ POGO I C++ |
| 0x010D | `[POC]` | VS2015+ POGO O C |
| 0x010E | `[PO+]` | VS2015+ POGO O C++ |

### Visual Studio 2013 (12.x)

| Product ID | Type | Description |
|------------|------|-------------|
| 0x00D9 | `[AOb]` | VS2013 AliasObj |
| 0x00DA | `[PGD]` | VS2013 CVTPGD |
| 0x00DB | `[RES]` | VS2013 Resource compiler |
| 0x00DC | `[EXP]` | VS2013 Export |
| 0x00DD | `[IMP]` | VS2013 Import library |
| 0x00DE | `[LNK]` | VS2013 Linker |
| 0x00DF | `[ASM]` | VS2013 MASM |
| 0x00E0 | `[ C ]` | VS2013 C compiler |
| 0x00E1 | `[C++]` | VS2013 C++ compiler |
| 0x00E2 | `[CIL]` | VS2013 CVTCIL C |
| 0x00E3 | `[CI+]` | VS2013 CVTCIL C++ |
| 0x00E4 | `[LTC]` | VS2013 LTCG C |
| 0x00E5 | `[LT+]` | VS2013 LTCG C++ |
| 0x00E6 | `[LTM]` | VS2013 LTCG MSIL |
| 0x00E7 | `[PGO]` | VS2013 POGO I C |
| 0x00E8 | `[PG+]` | VS2013 POGO I C++ |
| 0x00E9 | `[POC]` | VS2013 POGO O C |
| 0x00EA | `[PO+]` | VS2013 POGO O C++ |

### Visual Studio 2012 (11.0)

| Product ID | Type | Description |
|------------|------|-------------|
| 0x00C7 | `[AOb]` | VS2012 AliasObj |
| 0x00C8 | `[PGD]` | VS2012 CVTPGD |
| 0x00C9 | `[RES]` | VS2012 Resource compiler |
| 0x00CA | `[EXP]` | VS2012 Export |
| 0x00CB | `[IMP]` | VS2012 Import library |
| 0x00CC | `[LNK]` | VS2012 Linker |
| 0x00CD | `[ASM]` | VS2012 MASM |
| 0x00CE | `[ C ]` | VS2012 C compiler |
| 0x00CF | `[C++]` | VS2012 C++ compiler |
| 0x00D0 | `[CIL]` | VS2012 CVTCIL C |
| 0x00D1 | `[CI+]` | VS2012 CVTCIL C++ |
| 0x00D2 | `[LTC]` | VS2012 LTCG C |
| 0x00D3 | `[LT+]` | VS2012 LTCG C++ |
| 0x00D4 | `[LTM]` | VS2012 LTCG MSIL |
| 0x00D5 | `[PGO]` | VS2012 POGO I C |
| 0x00D6 | `[PG+]` | VS2012 POGO I C++ |
| 0x00D7 | `[POC]` | VS2012 POGO O C |
| 0x00D8 | `[PO+]` | VS2012 POGO O C++ |

### Visual Studio 2010 (10.0)

| Product ID | Type | Description |
|------------|------|-------------|
| 0x0098 | `[AOb]` | VS2010 AliasObj |
| 0x0099 | `[PGD]` | VS2010 CVTPGD |
| 0x009A | `[RES]` | VS2010 Resource compiler |
| 0x009B | `[EXP]` | VS2010 Export |
| 0x009C | `[IMP]` | VS2010 Import library |
| 0x009D | `[LNK]` | VS2010 Linker |
| 0x009E | `[ASM]` | VS2010 MASM |
| 0x00AA | `[ C ]` | VS2010 C compiler |
| 0x00AB | `[C++]` | VS2010 C++ compiler |
| 0x00AC | `[CIL]` | VS2010 CVTCIL C |
| 0x00AD | `[CI+]` | VS2010 CVTCIL C++ |
| 0x00AE | `[LTC]` | VS2010 LTCG C |
| 0x00AF | `[LT+]` | VS2010 LTCG C++ |
| 0x00B0 | `[LTM]` | VS2010 LTCG MSIL |
| 0x00B1 | `[PGO]` | VS2010 POGO I C |
| 0x00B2 | `[PG+]` | VS2010 POGO I C++ |
| 0x00B3 | `[POC]` | VS2010 POGO O C |
| 0x00B4 | `[PO+]` | VS2010 POGO O C++ |

### Visual Studio 2008 (9.0)

| Product ID | Type | Description |
|------------|------|-------------|
| 0x0083 | `[ C ]` | VS2008 C compiler |
| 0x0084 | `[C++]` | VS2008 C++ compiler |
| 0x0087 | `[CIL]` | VS2008 CVTCIL C |
| 0x0088 | `[CI+]` | VS2008 CVTCIL C++ |
| 0x0089 | `[LTC]` | VS2008 LTCG C |
| 0x008A | `[LT+]` | VS2008 LTCG C++ |
| 0x008B | `[LTM]` | VS2008 LTCG MSIL |
| 0x008C | `[PGO]` | VS2008 POGO I C |
| 0x008D | `[PG+]` | VS2008 POGO I C++ |
| 0x008E | `[POC]` | VS2008 POGO O C |
| 0x008F | `[PO+]` | VS2008 POGO O C++ |
| 0x0090 | `[PGD]` | VS2008 CVTPGD |
| 0x0091 | `[LNK]` | VS2008 Linker |
| 0x0092 | `[EXP]` | VS2008 Export |
| 0x0093 | `[IMP]` | VS2008 Import library |
| 0x0094 | `[RES]` | VS2008 Resource compiler |
| 0x0095 | `[ASM]` | VS2008 MASM |
| 0x0096 | `[AOb]` | VS2008 AliasObj |

### Visual Studio 2005 (8.0)

| Product ID | Type | Description |
|------------|------|-------------|
| 0x006D | `[ C ]` | VS2005 C compiler |
| 0x006E | `[C++]` | VS2005 C++ compiler |
| 0x0071 | `[LTC]` | VS2005 LTCG C |
| 0x0072 | `[LT+]` | VS2005 LTCG C++ |
| 0x0073 | `[PGO]` | VS2005 POGO I C |
| 0x0074 | `[PG+]` | VS2005 POGO I C++ |
| 0x0075 | `[POC]` | VS2005 POGO O C |
| 0x0076 | `[PO+]` | VS2005 POGO O C++ |
| 0x0077 | `[PGD]` | VS2005 CVTPGD |
| 0x0078 | `[LNK]` | VS2005 Linker |
| 0x0079 | `[OMF]` | VS2005 CVTOMF |
| 0x007A | `[EXP]` | VS2005 Export |
| 0x007B | `[IMP]` | VS2005 Import library |
| 0x007C | `[RES]` | VS2005 Resource compiler |
| 0x007D | `[ASM]` | VS2005 MASM |
| 0x007E | `[AOb]` | VS2005 AliasObj |
| 0x0080 | `[CIL]` | VS2005 CVTCIL C |
| 0x0081 | `[CI+]` | VS2005 CVTCIL C++ |
| 0x0082 | `[LTM]` | VS2005 LTCG MSIL |

### Visual Studio 2003 (7.10)

| Product ID | Type | Description |
|------------|------|-------------|
| 0x005A | `[LNK]` | VS2003 Linker |
| 0x005B | `[OMF]` | VS2003 CVTOMF |
| 0x005C | `[EXP]` | VS2003 Export |
| 0x005D | `[IMP]` | VS2003 Import library |
| 0x005E | `[RES]` | VS2003 Resource compiler |
| 0x005F | `[ C ]` | VS2003 C compiler |
| 0x0060 | `[C++]` | VS2003 C++ compiler |
| 0x0063 | `[LTC]` | VS2003 LTCG C |
| 0x0064 | `[LT+]` | VS2003 LTCG C++ |
| 0x0065 | `[PGO]` | VS2003 POGO I C |
| 0x0066 | `[PG+]` | VS2003 POGO I C++ |
| 0x0067 | `[POC]` | VS2003 POGO O C |
| 0x0068 | `[PO+]` | VS2003 POGO O C++ |
| 0x0069 | `[AOb]` | VS2003 AliasObj |
| 0x006B | `[PGD]` | VS2003 CVTPGD |

### Visual Studio 2002 (7.0)

| Product ID | Type | Description |
|------------|------|-------------|
| 0x0019 | `[IMP]` | VS2002 Import library |
| 0x001C | `[ C ]` | VS2002 C compiler |
| 0x001D | `[C++]` | VS2002 C++ compiler |
| 0x003D | `[LNK]` | VS2002 Linker |
| 0x003F | `[EXP]` | VS2002 Export |
| 0x0040 | `[ASM]` | VS2002 MASM |
| 0x0045 | `[RES]` | VS2002 Resource compiler |

### Visual Studio 98 / 6.0 (6.x)

| Product ID | Type | Description |
|------------|------|-------------|
| 0x0001 | `[IMP]` | Unmarked imports |
| 0x0002 | `[LNK]` | VS97 (5.10) Linker |
| 0x0004 | `[OMF]` | VS97 (5.10) CVTOMF |
| 0x0006 | `[LNK]` | VS98 (6.00) Linker |
| 0x0007 | `[OMF]` | VS98 (6.00) CVTOMF |
| 0x0009 | `[IMP]` | VS98 (6.00) Import library |
| 0x000A | `[RES]` | VS98 (6.00) Resource compiler |
| 0x000B | `[EXP]` | VS98 (6.00) Export |
| 0x000C | `[ASM]` | VS98 (6.11) MASM |
| 0x000D | `[ASM]` | VS98 (6.13) MASM |
| 0x000E | `[ASM]` | VS98 (6.14) MASM |
| 0x000F | `[LNK]` | VS97 SP3 (5.11) Linker |
| 0x0010 | `[OMF]` | VS97 SP3 (5.11) CVTOMF |
| 0x0012 | `[LNK]` | VS98 SP6 (6.12) Linker |
| 0x0013 | `[OMF]` | VS98 SP6 (6.12) CVTOMF |
| 0x0015 | `[ C ]` | VS98 (6.00) C compiler |
| 0x0016 | `[C++]` | VS98 (6.00) C++ compiler |

### Build Number Reference

The build number (low 16 bits of comp.id) corresponds to specific Visual Studio releases:

| Build Range | Visual Studio Version |
|-------------|----------------------|
| 35109-35719 | VS2026 (18.x) Insiders |
| 30159-35221 | VS2022 (17.x) |
| 27508-29110 | VS2019 (16.x) |
| 25017-27030 | VS2017 (15.x) |
| 23026-24215 | VS2015 Update 3 |
| 23506-23918 | VS2015 Update 2 |
| 23026-23506 | VS2015 Update 1 |
| 23026 | VS2015 RTM |
| 21005-21114 | VS2013 Update 5 |
| 60610-61030 | VS2012 Update 4 |
| 50727 | VS2012 RTM / VS2005 RTM |
| 40219 | VS2010 SP1 |
| 30319 | VS2010 RTM |
| 30729 | VS2008 SP1 |
| 21022 | VS2008 RTM |
| 6030 | VS2003 SP1 |
| 3077 | VS2003 RTM |
| 9466 | VS2002 RTM |

### Special Values

| Comp.ID | Description |
|---------|-------------|
| 0x00010000 | Unmarked objects (modern) |
| 0x00000000 | Unmarked objects (legacy) |
| 0x00970000 | Resource |
| 0x00FE0000 | CVTPGD |

**Note:** For the complete and up-to-date database, see [richprint's comp_id.txt](https://github.com/dishather/richprint/blob/master/comp_id.txt).

## XOR Mask Calculation

The XOR mask is derived from two checksums:

### 1. DOS Header Checksum

Checksum covering the first 0x80 bytes of the PE file (DOS header + stub). This ensures the Rich header and beginning of the file are consistent.

### 2. Linked List Checksum

Checksum computed from the Rich header entries themselves. This creates a cryptographic binding between the mask and the data.

**Important:** The XOR mask does NOT provide cryptographic security. It only detects:
- Tampering with the Rich header entries
- Changes to the first 0x80 bytes of the PE file

The mask can be easily recalculated if you modify the header, making it trivial to forge.

## Padding Calculation

The Rich header may have padding bytes (0x00) between the last entry and the "Rich" terminator. The padding size is calculated as:

```c
padding_bytes = ((((xor_mask >> 5) % 3) + item_count) * 8) + 0x20
```

This formula ensures the Rich header ends at a specific alignment before the PE header.

## Parsing Algorithm

### Step 1: Locate the Rich Terminator

Search backward from the PE header (typically at 0x80) for the "Rich" signature (0x68636952):

```cpp
const uint8_t* pe_start = data + pe_offset;
const uint8_t* search = pe_start;

// Search backwards from PE header
while (search > data + 0x40) {  // Don't go before DOS stub
    uint32_t marker = *reinterpret_cast<const uint32_t*>(search);
    if (marker == 0x68636952) {  // "Rich"
        // Found terminator
        uint32_t xor_mask = *reinterpret_cast<const uint32_t*>(search + 4);
        break;
    }
    search--;
}
```

### Step 2: Find the DanS Header

Once you have the XOR mask, search backwards for the encrypted "DanS" header:

```cpp
uint32_t dans_encrypted = 0x536E6144 ^ xor_mask;  // "DanS" XORed
const uint8_t* dans_ptr = search;

while (dans_ptr > data + 0x40) {
    uint32_t value = *reinterpret_cast<const uint32_t*>(dans_ptr);
    if (value == dans_encrypted) {
        // Found header start
        break;
    }
    dans_ptr -= 4;  // Align to DWORD boundaries
}
```

### Step 3: Parse Entries

Parse all entries between DanS and Rich:

```cpp
std::vector<rich_entry> entries;
const uint8_t* ptr = dans_ptr + 4;  // Skip "DanS"

while (ptr < search) {  // Until we reach "Rich"
    uint32_t data1_encrypted = *reinterpret_cast<const uint32_t*>(ptr);
    uint32_t data2_encrypted = *reinterpret_cast<const uint32_t*>(ptr + 4);

    // Decrypt
    uint32_t data1 = data1_encrypted ^ xor_mask;
    uint32_t data2 = data2_encrypted ^ xor_mask;

    // Parse
    rich_entry entry;
    entry.product_id = data1 >> 16;
    entry.build_number = data1 & 0xFFFF;
    entry.count = data2;

    entries.push_back(entry);
    ptr += 8;
}
```

### Step 4: Skip Padding

Handle any padding bytes (0x00) between the last entry and "Rich" terminator.

## Use Cases

### 1. Compiler Fingerprinting

Identify which version of Visual Studio compiled the binary:

```
Rich Entry: Product=0x00F2 (VS 2012 C++), Build=21005, Count=42
Rich Entry: Product=0x0102 (VS 2012 Linker), Build=21005, Count=1
```

**Conclusion:** Compiled with Visual Studio 2012 (build 21005)

### 2. Malware Analysis

Detect inconsistencies between claimed build environment and actual toolchain:

- **PE Header** claims: Linker version 14.0 (VS 2015)
- **Rich Header** shows: Linker 12.0 (VS 2013)
- **Conclusion:** Binary may have been tampered with or headers forged

### 3. Library Usage Detection

Identify which libraries were statically linked:

```
Rich Entry: Product=0x00F2, Count=500  ← Main executable objects
Rich Entry: Product=0x00F2, Count=150  ← CRT library objects
Rich Entry: Product=0x00F2, Count=80   ← Third-party library
```

Higher counts suggest static linking of large libraries (CRT, MFC, ATL, etc.)

### 4. Build Environment Forensics

Determine if malware families share the same build environment:

- Compare Rich headers across samples
- Identical product IDs + build numbers = same toolchain
- Identical counts = possibly same source code / build system

### 5. Stripped Binary Analysis

When symbols are stripped, the Rich header provides clues about:
- Original compiler version
- Optimization settings (LTCG, PGO entries)
- Approximate code complexity (object count)

## Detection and Validation

### Valid Rich Header Indicators

✅ **Must have:**
- DanS header (encrypted) at start
- "Rich" marker at end
- Valid XOR mask after "Rich"
- At least one entry

✅ **Should have:**
- Product IDs within known ranges
- Reasonable build numbers (1000-50000 range)
- Non-zero counts
- Consistent VS version across entries

### Invalid/Suspicious Indicators

❌ **Red flags:**
- XOR mask is 0x00000000 (trivially encrypted)
- Product IDs don't match known Microsoft values
- Huge counts (> 10000) for single components
- Mixed VS versions (e.g., VS 2008 + VS 2019)
- Build numbers that don't correspond to any VS release

### Checksum Validation

To verify the Rich header hasn't been tampered with:

1. Decrypt all entries using the stored XOR mask
2. Compute expected checksum from DOS header (first 0x80 bytes)
3. Compute expected checksum from Rich entries
4. Verify computed mask matches stored mask

**Note:** Since the algorithm is undocumented, exact checksum validation requires reverse engineering Microsoft's linker.

## Security Implications

### Information Disclosure

The Rich header reveals:
- **Build tools** - Exact VS version used
- **Build date** - Build number correlates to release date
- **Code size** - Object counts hint at project size
- **Optimization** - LTCG/PGO usage

This metadata can aid attackers in:
- Identifying vulnerable compiler versions
- Fingerprinting software vendors
- Tracking malware evolution (same toolchain = same author?)

### Removal

The Rich header can be safely removed:

1. Zero out all bytes from DanS to end of Rich
2. Adjust DOS stub size if needed
3. **Important:** Update PE header offset (e_lfanew) if changed

Removal does **not** affect:
- Executable functionality
- Digital signatures (if Rich is before signature)
- Code execution or imports

Many packers/protectors remove Rich headers to hinder analysis.

## Implementation in mz-explode

### Proposed API

```cpp
namespace libexe {

enum class rich_product : uint16_t {
    IMPORT0 = 0x0001,
    LINKER_VS6 = 0x0005,
    MASM_613 = 0x000D,
    LINKER_VS2008 = 0x0091,
    LINKER_VS2010 = 0x00AD,
    LINKER_VS2012 = 0x0102,
    LINKER_VS2013 = 0x011F,
    LINKER_VS2015 = 0x014A,
    // ... more values
};

struct LIBEXE_EXPORT rich_entry {
    uint16_t product_id;     // Product identifier
    uint16_t build_number;   // Build version number
    uint32_t count;          // Usage count

    [[nodiscard]] std::string product_name() const;
    [[nodiscard]] std::string vs_version() const;
};

struct LIBEXE_EXPORT rich_header {
    uint32_t xor_mask;              // XOR encryption mask
    std::vector<rich_entry> entries; // Component entries

    // Validation
    [[nodiscard]] bool is_valid() const;
    [[nodiscard]] bool checksum_valid() const;

    // Analysis helpers
    [[nodiscard]] std::string primary_compiler() const;
    [[nodiscard]] std::string primary_linker() const;
    [[nodiscard]] std::optional<uint16_t> vs_major_version() const;

    // Export for forensics
    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] std::vector<uint8_t> to_bytes() const;
};

class LIBEXE_EXPORT pe_file {
public:
    // Existing methods...

    // Rich header accessor
    [[nodiscard]] std::optional<rich_header> rich() const;
    [[nodiscard]] bool has_rich_header() const;
};

} // namespace libexe
```

### Usage Example

```cpp
#include <libexe/pe_file.hpp>

auto pe = libexe::pe_file::from_file("malware.exe");

if (auto rich = pe.rich()) {
    std::cout << "Rich Header found!\n";
    std::cout << "XOR Mask: 0x" << std::hex << rich->xor_mask << "\n";
    std::cout << "Primary Compiler: " << rich->primary_compiler() << "\n";
    std::cout << "Visual Studio: " << rich->vs_major_version().value_or(0) << "\n\n";

    std::cout << "Components:\n";
    for (const auto& entry : rich->entries) {
        std::cout << "  " << entry.product_name()
                  << " (build " << entry.build_number << ")"
                  << " used " << entry.count << " times\n";
    }

    // Forensics check
    if (!rich->checksum_valid()) {
        std::cout << "WARNING: Rich header checksum invalid (tampered?)\n";
    }
}
```

### Integration Points

**Phase:** Metadata/Forensics (Phase 5)

**Location:** Parse during `pe_file` initialization
- After DOS header
- Before PE header
- Store in `mutable std::optional<rich_header> rich_header_`
- Lazy parsing or eager (since it's small)

**Dependencies:**
- None (self-contained parsing)
- Optional: Checksum validation requires DOS header access

**Testing:**
- Create test files with known Rich headers
- Test decryption with various XOR masks
- Validate product ID recognition
- Test with tampered/invalid headers
- Test with stripped headers (should return std::nullopt)

## Tools and Resources

### Analysis Tools

- **PE-bear** - Displays Rich header in GUI
- **pestudio** - Shows Rich header analysis
- **CFF Explorer** - Rich header viewer
- **richprint** - Command-line Rich header dumper with comprehensive comp_id database
  - https://github.com/dishather/richprint
  - Maintains the most complete known @comp.id mapping
- **LIEF** - Python library with Rich header support

### Research Papers

- **Rich Header: a collection of metadata** - Researchers identifying malware families via Rich headers
- **Tracking malware with Import Hashing** - Using Rich headers alongside import hashing

### Microsoft Documentation

❌ **None** - Microsoft has never officially documented the Rich header

### Reverse Engineering Resources

- **NTCore Article** - Primary source (https://ntcore.com/files/richsign.htm)
- **@comp.id symbols** - Study COFF object files to understand product IDs
- **Linker analysis** - Reverse engineer LINK.EXE to extract product ID mappings

## Future Enhancements

### 1. Product ID Database

Maintain a comprehensive database of all known product IDs:
- Map to VS version, service pack, update
- Include release dates for timeline analysis
- Track deprecated/rare values

### 2. Anomaly Detection

Implement heuristics to detect suspicious Rich headers:
- Unusual product ID combinations
- Impossible build number ranges
- Statistically anomalous counts

### 3. Checksum Validation

Reverse engineer Microsoft's checksum algorithm:
- Validate integrity
- Detect tampering
- Recompute after modifications

### 4. Comparison Tools

Build utilities to compare Rich headers:
- Malware family clustering
- Code reuse detection
- Compiler upgrade tracking

### 5. JSON Export

Export Rich header to JSON for:
- Machine learning features
- Cross-tool integration
- Forensic reports

```json
{
  "rich_header": {
    "xor_mask": "0x12345678",
    "entries": [
      {
        "product_id": "0x00F2",
        "product_name": "VS 2012 C++ Compiler",
        "build_number": 21005,
        "count": 42
      }
    ],
    "vs_version": "11.0",
    "checksum_valid": true
  }
}
```

## References

1. **NTCore - The Undocumented Rich Header**
   https://ntcore.com/files/richsign.htm
   Primary source for Rich header format and structure

2. **richprint - @comp.id Database**
   https://github.com/dishather/richprint
   Comprehensive and actively maintained compiler ID database

3. **Microsoft Visual Studio Build Numbers**
   Track VS releases to map build numbers to dates

4. **PE Format Specification**
   Microsoft PE/COFF documentation (Rich header not included)

5. **@comp.id Symbol Analysis**
   Study COFF object file symbols to understand product IDs

## Conclusion

The Rich Signature is a valuable metadata structure for:
- **Forensic analysis** - Identify build tools and environment
- **Malware research** - Track families and attribution
- **Binary analysis** - Understand stripped executables
- **Security auditing** - Detect forged or tampered binaries

While undocumented and removable, the Rich header provides unique insights into PE file provenance that complement traditional analysis techniques. Its implementation in mz-explode would enhance the library's value for security researchers and malware analysts.

**Recommended Priority:** Medium (after fixing remaining parser issues, before advanced features)

**Estimated Effort:** 2-3 days (parsing, product ID database, tests, documentation)

**Value Proposition:** High for security/forensics use cases, low for general PE parsing
