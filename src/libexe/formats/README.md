# DataScript Format Specifications

This directory contains the modular DataScript specifications for Windows executable formats (MZ, NE, LE/LX, PE/PE32+) and resource types.

## Directory Structure

```
src/libexe/formats/
├── common.ds                    Shared type aliases and constants
│                                (DOS_SIGNATURE, NE_SIGNATURE, PE_SIGNATURE, etc.)
│
├── mz.ds                        DOS MZ header format
│                                (image_dos_header structure)
│
├── le/
│   └── le_header.ds             LE/LX headers for DOS extenders and OS/2 2.x
│                                (Linear Executable format)
│
├── ne/
│   └── ne_header.ds             NE 16-bit Windows/OS2 headers
│                                (Segments, resources, entries, relocations)
│
├── pe/
│   ├── pe_header.ds             PE 32/64-bit Windows headers
│   │                            (COFF headers, optional headers, sections)
│   ├── pe_imports.ds            Import directory structures
│   ├── pe_exports.ds            Export directory structures
│   ├── pe_relocations.ds        Base relocation structures
│   ├── pe_debug.ds              Debug directory structures
│   ├── pe_tls.ds                Thread Local Storage structures
│   ├── pe_load_config.ds        Load configuration structures
│   ├── pe_bound_imports.ds      Bound import structures
│   ├── pe_delay_imports.ds      Delay-load import structures
│   ├── pe_iat.ds                Import Address Table structures
│   ├── pe_exception.ds          Exception handling structures
│   ├── pe_security.ds           Security/Authenticode structures
│   └── pe_com_descriptor.ds     CLR/.NET metadata structures
│
└── resources/
    ├── basic.ds                 Icons, cursors, bitmaps
    │                            (RT_ICON, RT_GROUP_ICON, RT_CURSOR, RT_BITMAP)
    ├── dialogs.ds               Dialog templates and controls
    │                            (RT_DIALOG, includes DIALOGEX extended format)
    ├── fonts.ds                 Font resources and glyph tables
    │                            (RT_FONT, RT_FONTDIR, multiple glyph formats)
    ├── menus.ds                 Menu resources
    │                            (RT_MENU - header + flags, items need manual parsing)
    ├── tables.ds                String, accelerator, message tables
    │                            (RT_STRING, RT_ACCELERATORS, RT_MESSAGETABLE)
    ├── version.ds               Version information structures
    │                            (RT_VERSION, VS_FIXEDFILEINFO)
    └── os2.ds                   OS/2-specific resource structures
```

## Format Parsers

### Executable Headers

| File | Package | Description |
|------|---------|-------------|
| `common.ds` | `formats.common` | Type aliases (DWORD, WORD), magic constants |
| `mz.ds` | `formats.mz` | DOS MZ header (image_dos_header) |
| `le/le_header.ds` | `formats.le.le_header` | LE/LX headers for DOS extenders, OS/2 2.x |
| `ne/ne_header.ds` | `formats.ne.ne_header` | NE headers, segments, resources, entries |
| `pe/pe_header.ds` | `formats.pe.pe_header` | COFF headers, PE32/PE32+ optional headers |

### PE Data Directories

| File | Package | Data Directory |
|------|---------|----------------|
| `pe/pe_imports.ds` | `formats.pe.pe_imports` | Import Directory (1) |
| `pe/pe_exports.ds` | `formats.pe.pe_exports` | Export Directory (0) |
| `pe/pe_relocations.ds` | `formats.pe.pe_relocations` | Base Relocation (5) |
| `pe/pe_debug.ds` | `formats.pe.pe_debug` | Debug Directory (6) |
| `pe/pe_tls.ds` | `formats.pe.pe_tls` | TLS Directory (9) |
| `pe/pe_load_config.ds` | `formats.pe.pe_load_config` | Load Config (10) |
| `pe/pe_bound_imports.ds` | `formats.pe.pe_bound_imports` | Bound Import (11) |
| `pe/pe_iat.ds` | `formats.pe.pe_iat` | IAT Directory (12) |
| `pe/pe_delay_imports.ds` | `formats.pe.pe_delay_imports` | Delay Import (13) |
| `pe/pe_com_descriptor.ds` | `formats.pe.pe_com_descriptor` | CLR Runtime (14) |
| `pe/pe_exception.ds` | `formats.pe.pe_exception` | Exception Directory (3) |
| `pe/pe_security.ds` | `formats.pe.pe_security` | Security/Certificates (4) |

### Resource Formats

| File | Package | Resource Types |
|------|---------|----------------|
| `resources/basic.ds` | `formats.resources.basic` | RT_ICON, RT_CURSOR, RT_BITMAP, RT_GROUP_ICON |
| `resources/dialogs.ds` | `formats.resources.dialogs` | RT_DIALOG, RT_DIALOGEX |
| `resources/fonts.ds` | `formats.resources.fonts` | RT_FONT, RT_FONTDIR |
| `resources/menus.ds` | `formats.resources.menus` | RT_MENU, RT_MENUEX |
| `resources/tables.ds` | `formats.resources.tables` | RT_STRING, RT_ACCELERATORS, RT_MESSAGETABLE |
| `resources/version.ds` | `formats.resources.version` | RT_VERSION (VS_FIXEDFILEINFO) |
| `resources/os2.ds` | `formats.resources.os2` | OS/2-specific resource types |

## Naming Conventions

### Snake Case Everywhere

All DataScript identifiers use **snake_case**:

```datascript
// Correct
struct dialog_template { ... }
struct icon_dir_entry { ... }
enum menu_flags { ... }
choice resource_name_or_id : uint16 { ... }

// Wrong - do not use
struct DialogTemplate { ... }         // PascalCase
struct IconDirEntry { ... }           // PascalCase
```

**Exception**: Enum values use **UPPER_SNAKE_CASE**:
```datascript
enum uint16 menu_flags {
    MF_GRAYED       = 0x0001,
    MF_POPUP        = 0x0010,
};
```

### Package Naming

Packages match directory structure relative to formats/ directory:

```datascript
// File: src/libexe/formats/mz.ds
package formats.mz;

// File: src/libexe/formats/ne/ne_header.ds
package formats.ne.ne_header;

// File: src/libexe/formats/pe/pe_imports.ds
package formats.pe.pe_imports;

// File: src/libexe/formats/resources/dialogs.ds
package formats.resources.dialogs;
```

## DataScript Features

### Choice Types (Discriminated Unions)

```datascript
choice resource_name_or_id : uint16 {
    case 0xFFFF:
        uint16 ordinal;      // Integer ID
    default:
        little u16string name;  // String name
};
```

### Optional Fields

```datascript
struct dialog_template {
    uint32 style;
    // Font fields only present if DS_SETFONT flag is set
    uint16 point_size optional (style & DS_SETFONT) != 0;
    little u16string typeface optional (style & DS_SETFONT) != 0;
};
```

### Constraints (Validation)

```datascript
struct vs_fixed_file_info {
    // Validates magic number at parse time
    uint32 signature : signature == 0xFEEF04BD;
};
```

### Variable-Length Arrays

```datascript
struct icon_group {
    uint16 count;
    icon_dir_entry entries[count];  // Array size from field value
};
```

### DWORD Alignment

```datascript
struct dialog_template {
    uint32 style;
    align(4):  // Ensure DWORD boundary
    resource_name_or_id menu;
};
```

## Code Generation

### CMake Integration

DataScript parsers are generated at build time using `datascript_generate()`:

```cmake
datascript_generate(
    TARGET libexe_parsers
    SCHEMAS
        # Common types
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/common.ds
        # Executable format parsers
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/mz.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/ne/ne_header.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/pe/pe_header.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/le/le_header.ds
        # PE data directory parsers
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/pe/pe_imports.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/pe/pe_exports.ds
        # ... etc
        # Resource format parsers
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/resources/dialogs.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/resources/version.ds
        # ... etc
    OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
    INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}
    PRESERVE_PACKAGE_DIRS ON
)
```

This creates an INTERFACE library `libexe_parsers` that the main library links against.
Generated headers are placed in `build/src/libexe/generated/`.

### Manual Generation

```bash
ds src/libexe/formats/pe/pe_imports.ds -t cpp \
   -o build/generated/ \
   -I src/libexe/formats
```

## Usage Examples

### Parsing a DOS Header

```cpp
#include "libexe_format_mz.hh"

std::vector<uint8_t> file_data = read_file("program.exe");
const uint8_t* ptr = file_data.data();
const uint8_t* end = ptr + file_data.size();

auto dos_header = formats::mz::image_dos_header::read(ptr, end);

if (dos_header.e_lfanew > 0) {
    // Extended format (NE/LE/PE)
    ptr = file_data.data() + dos_header.e_lfanew;
    // Read signature and appropriate header...
}
```

### Parsing PE Import Directory

```cpp
#include "libexe_format_pe_imports.hh"

const uint8_t* import_data = ...;
const uint8_t* end = import_data + size;

auto import_desc = formats::pe::pe_imports::import_descriptor::read(import_data, end);

// Process import descriptor
if (import_desc.name_rva != 0) {
    // Valid import entry
}
```

### Parsing Version Info

```cpp
#include "libexe_format_version.hh"

const uint8_t* ver_data = ...;
const uint8_t* end = ver_data + size;

auto fixed_info = formats::resources::version::vs_fixed_file_info::read(ver_data, end);

std::cout << "File version: "
          << (fixed_info.file_version_ms >> 16) << "."
          << (fixed_info.file_version_ms & 0xFFFF) << "."
          << (fixed_info.file_version_ls >> 16) << "."
          << (fixed_info.file_version_ls & 0xFFFF) << "\n";
```

## Known Limitations

### Variable-Length Menu Items

Menu items have different structures based on runtime flags. DataScript models header and flags; C++ code manually parses items. See `resources/menus.ds` for details.

### Font Structure Alignment

Font structures are NOT DWORD-aligned per Microsoft specification. Font files (.FNT) are copied directly from external files.

### Dialog Creation Data

Control creation data is application-specific variable-length. DataScript provides `creation_data_size` field; C++ reads data separately.

## Compliance

DataScript implementations are verified against:
- **resfmt.txt** - Microsoft Win32 Binary Resource Formats
- **pecoff.docx** - Microsoft PE/COFF Specification
- **ne.fmt** - NE format specification

## References

**Documentation**:
- `docs/programmers_guide.md` - Library usage guide
- `docs/resfmt.txt` - Microsoft Win32 Binary Resource Formats
- `docs/pecoff.docx` - PE/COFF Specification
- `docs/ne.fmt` - NE Format Specification

**DataScript**:
- https://github.com/devbrain/datascript - DataScript language and compiler

---

**Last Updated**: 2025-12-10
