# DataScript Format Specifications - Modular Structure

This directory contains the modular DataScript specifications for Windows executable formats (MZ, NE, PE/PE+).

## Directory Structure

```
src/libexe/formats/
├── common.ds                    ✅ package libexe.formats.common;
│                                   Shared types and magic constants
│
├── mz.ds                        ⏳ package libexe.formats.mz;
│                                   DOS MZ format (complete, ~80 lines)
│
├── ne.ds                        ⏳ package libexe.formats.ne;
│                                   NE 16-bit format entry point (~120 lines)
├── ne/
│   ├── headers.ds               ⏳ package libexe.formats.ne.headers;
│   ├── segments.ds              ⏳ package libexe.formats.ne.segments;
│   ├── resources.ds             ⏳ package libexe.formats.ne.resources;
│   ├── entries.ds               ⏳ package libexe.formats.ne.entries;
│   └── relocations.ds           ⏳ package libexe.formats.ne.relocations;
│
├── pe.ds                        ⏳ package libexe.formats.pe;
│                                   PE 32/64-bit format entry point (~120 lines)
├── pe/
│   ├── core.ds                  ⏳ package libexe.formats.pe.core;
│   │                               Headers + sections combined (~200 lines)
│   ├── imports.ds               ⏳ package libexe.formats.pe.imports;
│   ├── exports.ds               ⏳ package libexe.formats.pe.exports;
│   ├── relocations.ds           ⏳ package libexe.formats.pe.relocations;
│   ├── tls.ds                   ⏳ package libexe.formats.pe.tls;
│   ├── load_config.ds           ⏳ package libexe.formats.pe.load_config;
│   └── advanced.ds              ⏳ package libexe.formats.pe.advanced;
│                                   Debug, exceptions, certificates (~150 lines)
│
└── resources/
    ├── common.ds                ⏳ package libexe.formats.resources.common;
    │                               ResourceType enum, shared structures
    ├── directory.ds             ⏳ package libexe.formats.resources.directory;
    │                               Resource directory tree
    ├── dialogs.ds               ✅ package libexe.formats.resources.dialogs;
    │                               RT_DIALOG (FULL IMPLEMENTATION)
    ├── version.ds               ✅ package libexe.formats.resources.version;
    │                               RT_VERSION
    ├── menus.ds                 ⏳ package libexe.formats.resources.menus;
    │                               RT_MENU (hybrid: header in DS, recursion in C++)
    ├── icons.ds                 ⏳ package libexe.formats.resources.icons;
    │                               RT_ICON, RT_GROUP_ICON, RT_CURSOR
    ├── strings.ds               ⏳ package libexe.formats.resources.strings;
    │                               RT_STRING (both NE and PE)
    ├── fonts.ds                 ✅ package libexe.formats.resources.fonts;
    │                               RT_FONT, RT_FONTDIR
    ├── bitmaps.ds               ⏳ package libexe.formats.resources.bitmaps;
    │                               RT_BITMAP
    ├── accelerators.ds          ⏳ package libexe.formats.resources.accelerators;
    │                               RT_ACCELERATORS
    ├── messages.ds              ⏳ package libexe.formats.resources.messages;
    │                               RT_MESSAGETABLE
    ├── basic.ds                 ✅ package libexe.formats.resources.basic;
    │                               Basic resource structures
    └── tables.ds                ✅ package libexe.formats.resources.tables;
                                    String and accelerator tables

    Legacy:
    └── exe_format_complete.ds   📦 MONOLITHIC (will be deprecated)
                                    Original 1399-line combined specification
```

**Legend:**
- ✅ Exists and complete
- ⏳ Planned (not yet created)
- 📦 Legacy file (to be replaced)

## Key Constraints

### DataScript Module System

**CRITICAL**: DataScript enforces **ONE package per file**:
- Each `.ds` file declares exactly one package
- Directory structure MUST match package hierarchy
- `libexe/formats/pe/core.ds` → `package libexe.formats.pe.core;`

### Naming Conventions

All DataScript identifiers use **snake_case**:
```datascript
struct dialog_template { ... }        // ✅ Correct
choice resource_name_or_id : uint16   // ✅ Correct

struct DialogTemplate { ... }         // ❌ Wrong (PascalCase)
choice ResourceNameOrId               // ❌ Wrong (missing type)
```

### Inline Discriminator Choices (Dec 2025)

**REQUIRED**: Explicit discriminator type must be declared:
```datascript
// ✅ CORRECT (as of Dec 8, 2025)
choice resource_name_or_id : uint16 {
    case 0xFFFF:
        uint16 marker;
        uint16 ordinal;
    default:
        little u16string name;
}

// ❌ INCORRECT (old syntax removed)
choice resource_name_or_id {
    case 0xFFFF:  // ERROR: missing discriminator type
        ...
}
```

## Import Examples

### Wildcard Import (Convenient)
```datascript
package myapp.parser;

import libexe.formats.common.*;          // All common types
import libexe.formats.resources.*;       // All resource types
```

### Specific Import (Explicit)
```datascript
package myapp.parser;

import libexe.formats.common.DOS_SIGNATURE;
import libexe.formats.resources.dialogs.dialog_template;
```

### Hierarchical Import
```datascript
package myapp.parser;

import libexe.formats.pe.*;              // Loads pe.ds + all pe/*.ds files
import libexe.formats.resources.*;       // Loads all resources/*.ds files
```

## Code Generation

### Single File
```bash
# Generate C++ parser for a single DataScript file
ds src/libexe/formats/resources/dialogs.ds -t cpp -o generated/
```

### Multiple Files (Recommended)
```bash
# Generate all parsers in the formats directory
find src/libexe/formats -name "*.ds" -not -name "exe_format_complete.ds" \
  -exec ds {} -t cpp -o generated/ \;
```

### CMake Integration
See `src/libexe/CMakeLists.txt` for automated multi-file compilation.

## Migration Status

### Phase 1: Preparation ✅
- [x] Create directory structure
- [x] Create common.ds with shared constants

### Phase 2: Resource Parsers (HIGH PRIORITY) 🚧
- [x] resources/dialogs.ds - Full dialog template parser
- [x] resources/version.ds - Version info structures
- [ ] resources/menus.ds - Menu resources (hybrid approach)
- [ ] resources/strings.ds - String tables (NE + PE)

### Phase 3: Core Formats ⏳
- [ ] mz.ds - DOS MZ format
- [ ] ne.ds + ne/*.ds - NE 16-bit format modules
- [ ] pe.ds + pe/*.ds - PE 32/64-bit format modules

### Phase 4: Completion ⏳
- [ ] Remaining resource types
- [ ] CMake integration for all modules
- [ ] Deprecate exe_format_complete.ds
- [ ] Update documentation

## References

- **Refactoring Plan**: `docs/DATASCRIPT_REFACTORING_PLAN.md`
- **DataScript Guide**: `cmake-build-debug/_deps/datascript-src/docs/LANGUAGE_GUIDE.md`
- **Module Organization**: `cmake-build-debug/_deps/datascript-src/docs/ORGANIZING_LARGE_SCHEMAS.md`
- **Format Specs**: `docs/pecoff.docx`, `docs/ne.fmt`, `docs/resfmt.txt`

## Notes

- **Type Aliases**: DataScript doesn't support type aliases (Dec 2025). Use native types directly (uint8, uint16, uint32, uint64) with the global `little;` directive.
- **Recursion**: DataScript cannot express unbounded recursion. Use hybrid approach (DataScript headers + C++ recursion) for menus and version info string tables.
- **Performance**: Generated parsers are zero-cost abstractions - as fast as hand-written C++.
