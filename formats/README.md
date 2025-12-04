# DataScript Format Specifications

This directory contains declarative binary format specifications that are compiled into C++ parsers.

## Current Specifications

### exe_format_complete.ds (1336 lines)
Complete Windows executable format definitions covering:

**DOS MZ Format (MS-DOS executables)**
- `struct ImageDosHeader` - 28-byte DOS header with e_lfanew pointer
- Relocation table structures
- Magic number validation (0x5A4D - "MZ")

**NE Format (16-bit Windows/OS2)**
- `struct ImageNeHeader` - New Executable header
- `struct NeSegmentTableEntry` - Segment definitions
- `struct NeResourceTypeInfo` / `NeResourceNameInfo` - Resource tables
- `struct NeRelocationRecord` - Relocation entries
- Entry point tables and module references

**PE/PE+ Format (32/64-bit Windows)**
- `struct ImageFileHeader` - COFF header
- `struct ImageOptionalHeader32` / `ImageOptionalHeader64` - Architecture-specific headers
- `struct ImageSectionHeader` - Section definitions
- `struct ImageDataDirectory` - Standard data directories (exports, imports, resources, etc.)

**Resource Structures**
- `struct ImageResourceDirectory` - Resource directory tree
- Message tables, string tables
- Icon groups, bitmaps, dialogs, menus, accelerators
- Version info structures

**Import/Export Tables**
- `struct ImageExportDirectory` - Exported functions
- `struct ImageImportDescriptor` - Imported DLLs and functions
- Bound import descriptors

**Security Structures**
- `struct ImageLoadConfigDirectory32` / `ImageLoadConfigDirectory64`
- TLS (Thread Local Storage) directory
- Debug directory entries
- Certificate table

**Top-Level Entry Point**
```datascript
struct Executable {
    ImageDosHeader dos_header;
    dos_header.e_lfanew:  // Navigate to extended header
    union {
        ImageNeHeader ne_header : ne_header.ne_magic == NE_SIGNATURE;
        { /* PE header structures */ } pe_header;
    } extended_header;
};
```

## Planned Specifications

### pklite.ds (To Be Created)
PKLite compressed executable format
- Extends MZ base header
- Compression metadata (version, flags, sizes)
- Compressed data section

### lzexe.ds (To Be Created)
LZEXE compressed executable format
- Decompressor header
- Relocation table offset
- Compressed code/data

### exepack.ds (To Be Created)
Microsoft EXEPACK compressed format
- RB signature validation
- Unpacker metadata
- Packed data structures

### knowledge.ds (To Be Created)
Knowledge Dynamics compressed format
- Format-specific header
- Compression parameters

## Code Generation

### Single-Header Mode (Production)
Generates minimal, self-contained parser:

```bash
ds exe_format_complete.ds -t cpp -o ../generated/
```

Produces: `../generated/com_example_exe_parser.h`

Usage:
```cpp
#include "com_example_exe_parser.h"

std::vector<uint8_t> file_data = read_file("program.exe");
const uint8_t* ptr = file_data.data();
auto exe = Executable::read(ptr, ptr + file_data.size());

// Access parsed structures
std::cout << "DOS Magic: 0x" << std::hex
          << exe.dos_header.e_magic << std::endl;
```

### Library Mode (Analysis/Debugging)
Generates introspection-enabled parser:

```bash
ds exe_format_complete.ds -t cpp --library -o ../generated/
```

Produces:
- `com_example_exe_parser_runtime.h` - Infrastructure
- `com_example_exe_parser.h` - Public API
- `com_example_exe_parser_impl.h` - Implementation + metadata

Usage:
```cpp
#include "com_example_exe_parser_impl.h"

auto exe = parse_Executable(file_data);

// Runtime introspection
StructView<ImageDosHeader> view(&exe.dos_header);
std::cout << "Structure: " << view.type_name() << std::endl;
std::cout << "Field count: " << view.field_count() << std::endl;

// Iterate fields dynamically
for (const auto& field : view.fields()) {
    std::cout << field.name() << " = "
              << field.value_as_string() << std::endl;
}

// Export to JSON for debugging
std::cout << view.to_json() << std::endl;
```

## Validating Against Official Specs

Cross-reference datascript definitions with official documentation:

- **PE/COFF**: Compare structures with `../docs/pecoff.docx`
- **NE Format**: Validate against `../docs/ne.fmt`
- **Resources**: Check resource structures against `../docs/resfmt.txt`

## Adding New Formats

1. Create new `.ds` file in this directory
2. Import base structures if extending existing formats:
   ```datascript
   import com.example.exe_parser.ImageDosHeader;
   ```
3. Define format-specific structures
4. Add validation constraints for format detection
5. Update CMakeLists.txt to generate parser
6. Test with real files

## DataScript Language Features Used

- **Little-endian byte order**: `little;` declaration
- **Constants**: `const uint16 DOS_SIGNATURE = 0x5A4D;`
- **Enumerations**: `enum uint16 ImageFileMachine { ... }`
- **Structures**: `struct ImageDosHeader { ... }`
- **Validation constraints**: `: field == EXPECTED_VALUE`
- **Conditional unions**: Discriminated unions with validation
- **Navigation**: `offset:` for jumping to file positions
- **Variable-length arrays**: `field[count]`

## Best Practices

1. **Always validate magic numbers**: Use constraints to enforce format validity
2. **Document field meanings**: Add comments referencing official specs
3. **Use descriptive enum values**: Match official Microsoft constant names
4. **Align structures properly**: DataScript auto-aligns, but document expected alignment
5. **Test with real files**: Validate against actual executables
6. **Cross-reference docs**: Include spec section numbers in comments

## References

- [DataScript Documentation](https://github.com/devbrain/datascript)
- [Microsoft PE/COFF Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Official Specs in ../docs/](../docs/)
