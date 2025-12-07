# Resource Parser Implementation Plan

This document outlines the implementation plan for the comprehensive resource parser system, broken down into testable phases.

## Progress Summary

**Overall Status**: 4 of 9 phases completed (44%)

| Phase | Status | Description | Assertions |
|-------|--------|-------------|------------|
| 4.2.1 | ✅ COMPLETE | Icon & Cursor Group Parsing | 1017 |
| 4.2.2 | ✅ COMPLETE | Font Parsing | 60 |
| 4.2.3 | ✅ COMPLETE | Version Info & Manifest | 915 |
| 4.2.4 | ✅ COMPLETE | String Tables & Accelerators | 584 |
| 4.2.5 | 🔜 NEXT | Dialog Templates | - |
| 4.2.6 | ⏸️ PENDING | Menu Templates | - |
| 4.2.7 | ⏸️ PENDING | Cursor & Bitmap Resources | - |
| 4.2.8 | ⏸️ PENDING | Message Tables | - |
| 4.2.9 | ⏸️ PENDING | Documentation & Polish | - |

**Total Assertions**: 2612 (all passing)

## DataScript Strategy (Updated)

**Key Finding**: Most resource structures already exist in `src/libexe/formats/exe_format_complete.ds`.

### Existing Structures (No new .ds files needed)
- ✅ **Icons/Cursors** (lines 757-799): IconGroup, IconDirEntry, CursorHotspot
- ✅ **Fonts** (lines 925-1073): FontHeader, GlyphEntry2x/30/ABC/Color, all enums
- ✅ **Version Info** (lines 659-754): VsFixedFileInfo, all version enums
- ✅ **Strings** (line 876): StringTableEntry
- ✅ **Accelerators** (lines 843-862): AccelTableEntry, AccelFlags
- ✅ **Message Tables** (lines 885-922): MessageResourceData, MessageResourceBlock, MessageResourceEntry

### Missing Structures (Need to add to exe_format_complete.ds)
- ❌ **Dialogs**: DLGTEMPLATE, DLGTEMPLATEEX, control structures
- ⚠️ **Menus**: MenuHeader exists, but PopupMenuItem and NormalMenuItem are missing

### Implementation Approach
1. **Use existing structures** from generated `exe_format_complete_parser.h`
2. **Add missing structures** to `exe_format_complete.ds` (not separate files)
3. **Regenerate parser** after adding missing structures
4. **Create C++ wrapper classes** that use the generated parser

**No separate .ds files in formats/resources/** - everything stays in `exe_format_complete.ds`.

## Overview

Each phase is designed to be:
- **Self-contained**: Can be implemented and tested independently
- **Testable**: Has clear success criteria with unit tests
- **Incremental**: Builds upon previous phases
- **Deliverable**: Produces working, committable code

## Phase 4.2.1: Parser Infrastructure & Icon Support (HIGH PRIORITY) ✅ COMPLETED

**Status**: ✅ **COMPLETED** - Icon and cursor group parsing fully implemented (1017 assertions passing)

**Goal**: Establish parser architecture and implement icon parsing (most commonly used resource type)

**Note**: Icon structures already exist in `src/libexe/formats/exe_format_complete.ds` (lines 757-799):
- `IconDirEntry` (line 765) - Icon directory entry
- `IconGroup` (line 783) - Icon group header
- `CursorHotspot` (line 796) - Cursor hotspot data

### Tasks

#### 1. Set Up Parser Infrastructure
- [ ] Create `include/libexe/resources/parsers/` directory structure
- [ ] Create `src/libexe/resources/parsers/` directory structure
- [ ] Update CMakeLists.txt for new directories
- [ ] Ensure `exe_format_complete_parser.h` is generated and available

**Files Created**:
```
include/libexe/resources/parsers/
├── resource_parser.hpp       # Base parser interface
└── parser_factory.hpp        # Factory pattern implementation

src/libexe/resources/parsers/
└── parser_factory.cpp        # Factory implementation
```

**Test**: Verify directory structure compiles and generated parser is accessible

#### 2. Verify DataScript Parser Generation
- [ ] Verify `exe_format_complete_parser.h` includes icon structures
- [ ] Test that `IconGroup` and `IconDirEntry` can be parsed
- [ ] No new .ds files needed - structures already defined

**Files Used**:
```
src/libexe/formats/exe_format_complete.ds    # Already contains icon structures
generated/exe_format_complete_parser.h        # Generated parser (verify exists)
```

**Test**: Verify DataScript parser can access icon structures

#### 3. Icon Group Parser Implementation
- [ ] Create `include/libexe/resources/parsers/icon_group_parser.hpp`
- [ ] Define `icon_directory_entry` struct
- [ ] Define `icon_group` struct
- [ ] Implement `icon_group_parser` class
- [ ] Create `src/libexe/resources/parsers/icon_group_parser.cpp`

**Files Created**:
```
include/libexe/resources/parsers/icon_group_parser.hpp
src/libexe/resources/parsers/icon_group_parser.cpp
```

**Test**: Unit test parsing PROGMAN.EXE RT_GROUP_ICON resources
- Verify count of icon directory entries
- Validate icon IDs match wrestool output
- Check width/height/bit_count values

#### 4. Icon Image Parser Implementation
- [ ] Create `include/libexe/resources/parsers/icon_parser.hpp`
- [ ] Define `icon_image` struct with DIB parsing
- [ ] Implement `icon_parser` class
- [ ] Implement `icon_image::to_ico_file()` method
- [ ] Create `src/libexe/resources/parsers/icon_parser.cpp`

**Files Created**:
```
include/libexe/resources/parsers/icon_parser.hpp
src/libexe/resources/parsers/icon_parser.cpp
```

**Test**: Unit test parsing PROGMAN.EXE RT_ICON resources
- Verify DIB header parsing
- Validate image dimensions
- Test .ICO file export matches original
- Compare exported .ICO with known-good icons

#### 5. Factory Integration
- [ ] Update `parser_factory.hpp` with icon parser registration
- [ ] Implement `parser_factory::parse_icon()` convenience method
- [ ] Implement `parser_factory::parse_icon_group()` convenience method
- [ ] Add factory tests

**Test**: Factory creates correct parsers for icon types

#### 6. Resource Entry Integration
- [ ] Add `resource_entry::as_icon_group()` method
- [ ] Add `resource_entry::as_icon()` method
- [ ] Update `include/libexe/resources/resource.hpp`

**Test**: End-to-end test extracting icons from PROGMAN.EXE

### Success Criteria (Phase 4.2.1)

- [ ] All icon resources from PROGMAN.EXE parse successfully (92 icons, 46 groups)
- [ ] Exported .ICO files are valid and viewable
- [ ] Parser handles malformed data gracefully (returns std::nullopt)
- [ ] Unit tests: 100% pass rate
- [ ] Integration test: Extract all icons from PROGMAN.EXE
- [ ] Code compiles with zero warnings

**Deliverable**: Working icon extraction with tests

---

## Phase 4.2.2: Font Support (HIGH PRIORITY) ✅ COMPLETED

**Status**: ✅ **COMPLETED** - Font parsing fully implemented (60 assertions passing)

**Goal**: Implement NE font parsing (Windows 3.x raster fonts)

**Note**: Font structures already exist in `src/libexe/formats/exe_format_complete.ds` (lines 925-1073):
- `FontType` enum (line 933) - Raster/vector/memory/device
- `FontFamily` enum (line 945) - Roman/Swiss/Modern/Script/Decorative
- `FontPitch` enum (line 957) - Fixed/variable pitch
- `FontFlags` enum (line 967) - Bitmap format flags
- `FontHeader` (line 984) - Complete .FNT file header (Windows 2.x/3.0)
- `GlyphEntry2x` (line 1028) - Windows 2.x glyph entry
- `GlyphEntry30` (line 1038) - Windows 3.0 glyph entry
- `GlyphEntryABC` (line 1053) - ABC spacing glyph entry
- `GlyphEntryColor` (line 1066) - Color glyph entry

### Tasks

#### 1. Verify DataScript Font Structures
- [ ] Verify `exe_format_complete_parser.h` includes font structures
- [ ] Test that `FontHeader` and glyph structures can be parsed
- [ ] No new .ds files needed - all structures already defined

**Files Used**:
```
src/libexe/formats/exe_format_complete.ds    # Already contains font structures
generated/exe_format_complete_parser.h        # Generated parser
docs/fon.txt                                   # Reference specification
```

**Test**: Verify DataScript parser can access font structures

#### 2. Font Parser Implementation
- [ ] Create `include/libexe/resources/parsers/font_parser.hpp`
- [ ] Define `glyph_entry` struct
- [ ] Define `font_data` struct with all font header fields
- [ ] Implement `font_parser` class
- [ ] Handle Windows 2.x vs 3.x version differences
- [ ] Parse glyph table (variable offset sizes)
- [ ] Parse bitmap data
- [ ] Create `src/libexe/resources/parsers/font_parser.cpp`

**Files Created**:
```
include/libexe/resources/parsers/font_parser.hpp
src/libexe/resources/parsers/font_parser.cpp
```

**Test**: Unit test parsing CGA40WOA.FON RT_FONT resource
- Verify font header fields (version, points, resolution)
- Validate face name ("CGA 40-column")
- Check glyph table parsing
- Verify bitmap data extraction

#### 3. Font Directory Parser Implementation
- [ ] Create `include/libexe/resources/parsers/fontdir_parser.hpp`
- [ ] Define `font_dir_entry` struct
- [ ] Define `font_directory` struct
- [ ] Implement `fontdir_parser` class
- [ ] Create `src/libexe/resources/parsers/fontdir_parser.cpp`

**Files Created**:
```
include/libexe/resources/parsers/fontdir_parser.hpp
src/libexe/resources/parsers/fontdir_parser.cpp
```

**Test**: Unit test parsing CGA40WOA.FON RT_FONTDIR resource
- Verify font count
- Validate font ordinals
- Check font metadata

#### 4. Factory Integration
- [ ] Update `parser_factory.hpp` with font parser registration
- [ ] Implement `parser_factory::parse_font()` convenience method
- [ ] Implement `parser_factory::parse_fontdir()` convenience method

**Test**: Factory creates correct parsers for font types

#### 5. Resource Entry Integration
- [ ] Add `resource_entry::as_font()` method
- [ ] Add `resource_entry::as_fontdir()` method
- [ ] Update `include/libexe/resources/resource.hpp`

**Test**: End-to-end test extracting fonts from CGA40WOA.FON

### Success Criteria (Phase 4.2.2)

- [ ] All font resources from CGA40WOA.FON parse successfully
- [ ] Font metadata matches reference data (face name, size, weight)
- [ ] Glyph bitmaps extracted correctly
- [ ] Parser handles both Windows 2.x and 3.x formats
- [ ] Unit tests: 100% pass rate
- [ ] Integration test: Extract all fonts from CGA40WOA.FON
- [ ] Code compiles with zero warnings

**Deliverable**: Working font extraction with tests

---

## Phase 4.2.3: Version Info & Manifest (Common Metadata) ✅ COMPLETED

**Status**: ✅ **COMPLETED** - All parsers implemented, tested, and passing

**Goal**: Implement version information and manifest parsing

**Note**: Version structures already exist in `src/libexe/formats/exe_format_complete.ds` (lines 659-754):
- `VsFixedFileInfo` (line 667) - Fixed file information (signature, versions, etc.)
- `VsFileFlags` enum (line 686) - Debug, prerelease, patched flags
- `VsFileOS` enum (line 698) - Target operating system
- `VsFileType` enum (line 719) - App, DLL, driver, font types
- `VsFileSubtypeDrv` enum (line 732) - Driver subtypes
- `VsFileSubtypeFont` enum (line 750) - Font subtypes

**Note**: Full VS_VERSIONINFO parsing requires additional structures (StringFileInfo, VarFileInfo) which are variable-length and may need hand-coded parsing.

### Tasks

#### 1. Integrate xml.h Library ✅
- [x] Download xml.h from https://github.com/mrvladus/xml.h
- [x] Place in `third-party/xml.h`
- [x] Add to CMakeLists.txt include paths
- [x] Verify compilation

**Files Created**:
```
third-party/xml.h (13,828 bytes, MIT license)
```

**Test**: ✅ xml.h compiles and links successfully

#### 2. Verify DataScript Version Structures ✅
- [x] Verify `exe_format_complete_parser.h` includes `VsFixedFileInfo`
- [x] Test that fixed version info can be parsed
- [x] Used DataScript `VsFixedFileInfo::read()` for binary parsing

**Files Used**:
```
src/libexe/formats/exe_format_complete.ds    # Contains VsFixedFileInfo
generated/exe_format.hh                       # Generated parser (renamed from exe_format_complete_parser.h)
docs/resfmt.txt                                # Reference specification
```

**Test**: ✅ DataScript parser successfully parses version structures

#### 3. Version Info Parser Implementation ✅
- [x] Create `include/libexe/resources/parsers/version_info_parser.hpp`
- [x] Define `fixed_file_info` struct
- [x] Define `version_info` struct
- [x] Implement `version_info_parser` class
- [x] Parse nested VS_VERSIONINFO blocks
- [x] Extract string table (CompanyName, FileDescription, etc.) with UTF-16 to UTF-8 conversion
- [x] Parse StringFileInfo sections with DWORD alignment
- [x] Create `src/libexe/resources/parsers/version_info_parser.cpp`

**Files Created**:
```
include/libexe/resources/parsers/version_info_parser.hpp (216 lines)
src/libexe/resources/parsers/version_info_parser.cpp (245 lines)
```

**Test**: ✅ Unit test parsing TCMDX32.EXE RT_VERSION resource
- ✅ Verify fixed file info (signature 0xFEEF04BD)
- ✅ Validate version numbers
- ✅ Check string table extraction
- ✅ Verify known strings (CompanyName, FileVersion)
- ✅ Test convenience methods (company_name(), product_name(), etc.)

#### 4. Manifest Parser Implementation ✅
- [x] Create `include/libexe/resources/parsers/manifest_parser.hpp`
- [x] Define `manifest_data` struct with raw XML storage
- [x] Define enums: `uac_execution_level`, `dpi_awareness_mode`
- [x] Define bitmask enums: `windows_version_flags`, `manifest_flags`
- [x] Implement `manifest_parser` class with comprehensive API
- [x] Implement structured parsing methods: `get_uac_execution_level()`, `get_dpi_awareness()`, `get_windows_compatibility()`, `get_flags()`
- [x] Implement 27 convenience methods for quick boolean checks
- [x] Always extract raw XML
- [x] Create `src/libexe/resources/parsers/manifest_parser.cpp`

**Files Created**:
```
include/libexe/resources/parsers/manifest_parser.hpp (530 lines with comprehensive API)
src/libexe/resources/parsers/manifest_parser.cpp (39 lines)
```

**Test**: ✅ Unit test parsing TCMDX32.EXE RT_MANIFEST resource
- ✅ Verify raw XML extraction
- ✅ Validate enum-based UAC API
- ✅ Check enum-based DPI awareness API
- ✅ Test bitmask-based Windows version compatibility
- ✅ Test bitmask-based manifest flags
- ✅ Verify consistency between enum/bool APIs

#### 5. Factory Integration ✅
- [x] Skipped factory pattern - using direct convenience methods on resource_entry
- [x] Simpler API for users

**Test**: ✅ Direct access via resource_entry methods works perfectly

#### 6. Resource Entry Integration ✅
- [x] Add `resource_entry::as_version_info()` method
- [x] Add `resource_entry::as_manifest()` method
- [x] Add `resource_entry::as_font()` method (bonus - implemented earlier)

**Test**: ✅ End-to-end test extracting version and manifest from TCMDX32.EXE

### Success Criteria (Phase 4.2.3) ✅ ALL MET

- [x] ✅ Version info from TCMDX32.EXE parses successfully (1136 bytes)
- [x] ✅ Manifest XML extracts correctly (1052 bytes)
- [x] ✅ Robust parsing handles all manifest settings
- [x] ✅ Unit tests: **100% pass rate (1992 assertions, all passing)**
- [x] ✅ Integration test: Extract version and manifest from TCMDX32.EXE
- [x] ✅ Code compiles with zero warnings
- [x] ✅ **BONUS**: Type-safe enum/bitmask API using existing `enum_bitmask.hpp`
- [x] ✅ **BONUS**: Comprehensive manifest API with 4 primary getters + 27 convenience methods

**Deliverable**: ✅ Production-ready version and manifest extraction with advanced type-safe API

**Implementation Highlights**:
- Used DataScript `VsFixedFileInfo::read()` for binary parsing of version info
- Implemented manual UTF-16 to UTF-8 conversion for string tables
- Created type-safe enum API for UAC and DPI settings
- Created bitmask API for Windows version compatibility and manifest flags
- All 27 convenience boolean methods preserved for backward compatibility
- Comprehensive tests verify enum/bool API consistency

---

## Phase 4.2.4: String Tables & Accelerators (Simple Structures) ✅ COMPLETED

**Status**: ✅ **COMPLETED** - String table and accelerator parsing fully implemented (584 assertions passing)

**Goal**: Implement simple resource parsers

**Key Discovery**: NE files use ASCII/ANSI strings with single-byte length prefix, not Unicode! DataScript structures are for PE/PE32+ (Win32+).

**Note**: While structures exist in `src/libexe/formats/exe_format_complete.ds`, manual parsing was required for NE format:
- `StringTableEntry` (line 876) - Unicode format (PE only, not used for NE)
- `AccelFlags` enum (line 843) - Usable for both NE and PE
- `AccelTableEntry` (line 857) - Fixed 8-byte format (used directly)

### Tasks

#### 1. String Table Parser Implementation ✅
- [x] Create `include/libexe/resources/parsers/string_table_parser.hpp` (102 lines)
- [x] Define `string_table` struct with block_id and string map
- [x] Implement `string_table_parser` class
- [x] Manual parsing for NE ASCII format (byte-length prefix, not DataScript)
- [x] Parse up to 16 strings per block (block ID = resource ID)
- [x] Handle empty string slots (length = 0)
- [x] No UTF-8 conversion needed (NE strings are already ASCII/ANSI)
- [x] Create `src/libexe/resources/parsers/string_table_parser.cpp` (78 lines)

**Implementation Highlights**:
- **NE Format Discovery**: Length prefix is 1 byte (ASCII), not 2 bytes (Unicode)
- **Direct parsing**: `uint8_t length = *ptr++; string(ptr, length)`
- **String ID calculation**: `(block_id - 1) * 16 + index`
- Helper methods: `get_string()`, `has_string()`, `base_string_id()`

**Files Created**:
```
include/libexe/resources/parsers/string_table_parser.hpp    # 102 lines
src/libexe/resources/parsers/string_table_parser.cpp        # 78 lines
```

**Test Results**: ✅ All 9 string blocks from PROGMAN.EXE parsed successfully
- Multiple strings per block verified
- Empty string slots handled correctly
- String ID mapping validated

#### 2. Verify DataScript Accelerator Structures ✅
- [x] Verified `exe_format_complete_parser.h` includes `AccelTableEntry`
- [x] DataScript `AccelTableEntry::read()` used successfully
- [x] No new .ds files needed - structures already defined

**Files Used**:
```
src/libexe/formats/exe_format_complete.ds (lines 843-862)  # Accelerator structures
generated/exe_format_complete_parser.h                     # Generated parser
```

**Test Results**: ✅ DataScript parser successfully parses accelerator structures

#### 3. Accelerator Parser Implementation ✅
- [x] Create `include/libexe/resources/parsers/accelerator_parser.hpp` (149 lines)
- [x] Define `accelerator_entry` struct with flag checking methods
- [x] Define `accelerator_table` struct with find_by_command()
- [x] Implement `accelerator_parser` class using DataScript
- [x] Implement `to_string()` method for human-readable output ("Ctrl+S", "Alt+F1")
- [x] Create `src/libexe/resources/parsers/accelerator_parser.cpp` (129 lines)

**Implementation Highlights**:
- **DataScript Integration**: `AccelTableEntry::read(ptr, end)` for parsing
- **Virtual Key Mapping**: F1-F12, Enter, Esc, Delete, etc. → readable names
- **Modifier Formatting**: Combines Ctrl+Shift+Alt prefixes correctly
- **Flag Enums**: `accelerator_flags` enum with VIRTKEY, SHIFT, CONTROL, ALT, END
- Helper methods: `is_virtkey()`, `requires_shift/control/alt()`

**Files Created**:
```
include/libexe/resources/parsers/accelerator_parser.hpp    # 149 lines
src/libexe/resources/parsers/accelerator_parser.cpp        # 129 lines
```

**Test Results**: ✅ Accelerator table from PROGMAN.EXE parsed successfully
- 6 accelerator entries verified
- Virtual key names mapped correctly
- Modifier combinations validated
- Command ID 0 supported (disabled/separator entries)

#### 4. Factory Integration & Resource Entry Methods ✅
- [x] No factory pattern used (direct parser usage)
- [x] Add `resource_entry::as_string_table()` method (with block ID handling)
- [x] Add `resource_entry::as_accelerator_table()` method
- [x] Updated `src/libexe/resources/resource.cpp` with implementations

**Test Results**: ✅ End-to-end extraction works via convenience methods

### Success Criteria (Phase 4.2.4) ✅ ALL MET

- [x] String tables parse correctly (all 9 blocks from PROGMAN.EXE) ✅
- [x] Accelerators parse correctly (6 entries from PROGMAN.EXE) ✅
- [x] Unit tests: 100% pass rate (584/584 assertions) ✅
- [x] Code compiles with zero warnings ✅

**Deliverable**: ✅ Working string table and accelerator extraction

**Files Modified/Created**:
```
include/libexe/resources/parsers/string_table_parser.hpp        # 102 lines - NEW
src/libexe/resources/parsers/string_table_parser.cpp            # 78 lines - NEW
include/libexe/resources/parsers/accelerator_parser.hpp         # 149 lines - NEW
src/libexe/resources/parsers/accelerator_parser.cpp             # 129 lines - NEW
src/libexe/resources/resource.cpp                               # +12 lines - MODIFIED
include/libexe/resources/resource.hpp                           # +2 lines - MODIFIED
unittests/resources/test_string_accelerator_parsers.cpp         # 385 lines - NEW
unittests/CMakeLists.txt                                        # +1 line - MODIFIED
src/libexe/CMakeLists.txt                                       # +2 lines - MODIFIED
```

**Total New Code**: ~865 lines across 9 files
**Test Coverage**: 584 assertions validating both parsers

---

## Phase 4.2.5: Dialog Templates (Complex UI)

**Goal**: Implement dialog box resource parsing

**Note**: Dialog structures are **NOT** currently in `exe_format_complete.ds`. Options:
1. Add dialog structures to `exe_format_complete.ds`
2. Create separate `dialog.ds` file
3. Hand-code dialog parser (due to complexity)

**Recommendation**: Add structures to `exe_format_complete.ds` to keep everything in one place.

### Tasks

#### 1. Add Dialog Structures to DataScript
- [ ] Add to `src/libexe/formats/exe_format_complete.ds`:
  - `DLGTEMPLATE` structure
  - `DLGTEMPLATEEX` structure (extended format)
  - Dialog control structures
  - Variable-length Name/Ordinal handling
- [ ] Regenerate parser with DataScript
- [ ] Update CMakeLists.txt if needed

**Files Modified**:
```
src/libexe/formats/exe_format_complete.ds    # Add dialog structures
```

**Files Regenerated**:
```
generated/exe_format_complete_parser.h        # Includes new dialog structures
```

**Test**: DataScript generation succeeds with dialog structures

#### 2. Dialog Parser Implementation
- [ ] Create `include/libexe/resources/parsers/dialog_parser.hpp`
- [ ] Define `dialog_control` struct
- [ ] Define `dialog_template` struct
- [ ] Implement `dialog_parser` class
- [ ] Handle DLGTEMPLATE vs DLGTEMPLATEEX variants
- [ ] Parse variable-length strings
- [ ] Handle DWORD alignment between controls
- [ ] Create `src/libexe/resources/parsers/dialog_parser.cpp`

**Files Created**:
```
include/libexe/resources/parsers/dialog_parser.hpp
src/libexe/resources/parsers/dialog_parser.cpp
```

**Test**: Unit test parsing PROGMAN.EXE RT_DIALOG resources (7 dialogs)
- Verify dialog count and dimensions
- Validate control counts
- Check caption strings
- Verify control types (button, edit, static, etc.)

#### 3. Factory Integration & Resource Entry Methods
- [ ] Update factory with dialog parser
- [ ] Add `resource_entry::as_dialog()` method

**Test**: End-to-end extraction

### Success Criteria (Phase 4.2.5)

- [ ] All 7 dialogs from PROGMAN.EXE parse successfully
- [ ] Control counts match expected values
- [ ] Captions and text extracted correctly
- [ ] Both DLGTEMPLATE and DLGTEMPLATEEX formats supported
- [ ] Unit tests: 100% pass rate
- [ ] Code compiles with zero warnings

**Deliverable**: Working dialog template extraction

---

## Phase 4.2.6: Menu Templates (Hierarchical UI)

**Goal**: Implement menu resource parsing

**Note**: Menu structures partially exist in `src/libexe/formats/exe_format_complete.ds` (lines 804-834):
- `MenuFlags` enum (line 810) - GRAYED, CHECKED, POPUP, etc.
- `MenuHeader` (line 827) - Version and header size
- **Missing**: PopupMenuItem and NormalMenuItem structures (mentioned in comments but not defined)

**Recommendation**: Add missing menu item structures to `exe_format_complete.ds`.

### Tasks

#### 1. Add Missing Menu Structures to DataScript
- [ ] Add to `src/libexe/formats/exe_format_complete.ds`:
  - `PopupMenuItem` structure (flags + text)
  - `NormalMenuItem` structure (flags + ID + text)
  - Handle hierarchical nesting with MF_END flag
- [ ] Regenerate parser with DataScript

**Files Modified**:
```
src/libexe/formats/exe_format_complete.ds    # Add menu item structures
```

**Files Regenerated**:
```
generated/exe_format_complete_parser.h        # Includes new menu structures
```

**Test**: DataScript generation succeeds with menu structures

#### 2. Menu Parser Implementation
- [ ] Create `include/libexe/resources/parsers/menu_parser.hpp`
- [ ] Define `menu_item` struct (supports hierarchy)
- [ ] Define `menu_template` struct
- [ ] Implement `menu_parser` class
- [ ] Handle nested popups
- [ ] Parse menu flags (GRAYED, CHECKED, etc.)
- [ ] Create `src/libexe/resources/parsers/menu_parser.cpp`

**Files Created**:
```
include/libexe/resources/parsers/menu_parser.hpp
src/libexe/resources/parsers/menu_parser.cpp
```

**Test**: Unit test parsing PROGMAN.EXE RT_MENU resource (1 menu)
- Verify menu structure
- Validate item text
- Check popup nesting
- Verify flags

#### 3. Factory Integration & Resource Entry Methods
- [ ] Update factory with menu parser
- [ ] Add `resource_entry::as_menu()` method

**Test**: End-to-end extraction

### Success Criteria (Phase 4.2.6)

- [ ] Menu from PROGMAN.EXE parses successfully
- [ ] Hierarchical structure preserved
- [ ] Menu text extracted correctly
- [ ] Flags parsed correctly
- [ ] Unit tests: 100% pass rate
- [ ] Code compiles with zero warnings

**Deliverable**: Working menu template extraction

---

## Phase 4.2.7: Cursor & Bitmap Resources (Image Data)

**Goal**: Implement cursor and bitmap parsing (similar to icons)

**Note**: Cursor structures already exist in `src/libexe/formats/exe_format_complete.ds` (lines 757-799):
- `IconDirEntry` (line 765) - Same structure for cursors (wPlanes=hotspot X, wBitCount=hotspot Y)
- `IconGroup` (line 783) - Same structure for cursor groups (wType=1 for cursors, 2 for icons)
- `CursorHotspot` (line 796) - Hotspot coordinates (precedes bitmap data)

**Note**: Bitmap parsing uses same DIB format as icons (no special structures needed).

### Tasks

#### 1. Verify DataScript Cursor Structures
- [ ] Verify `exe_format_complete_parser.h` includes cursor structures
- [ ] Note that `IconGroup` handles both icons (wType=2) and cursors (wType=1)
- [ ] Note that `IconDirEntry` fields have different meaning for cursors
- [ ] No new .ds files needed - structures already defined

**Files Used**:
```
src/libexe/formats/exe_format_complete.ds (lines 757-799)  # Icon/Cursor structures
generated/exe_format_complete_parser.h                     # Generated parser
```

**Test**: Verify DataScript parser can access cursor structures

#### 2. Bitmap Parser Implementation
- [ ] Create `include/libexe/resources/parsers/bitmap_parser.hpp`
- [ ] Define `bitmap_data` struct
- [ ] Implement `bitmap_parser` class
- [ ] Handle BITMAPINFOHEADER and BITMAPCOREHEADER
- [ ] Parse color table
- [ ] Create `src/libexe/resources/parsers/bitmap_parser.cpp`

**Files Created**:
```
include/libexe/resources/parsers/bitmap_parser.hpp
src/libexe/resources/parsers/bitmap_parser.cpp
```

**Test**: Unit test with bitmap resources
- Verify DIB header parsing
- Validate color table
- Check bitmap dimensions

#### 3. Factory Integration & Resource Entry Methods
- [ ] Update factory with cursor/bitmap parsers
- [ ] Add `resource_entry::as_cursor()` method
- [ ] Add `resource_entry::as_cursor_group()` method
- [ ] Add `resource_entry::as_bitmap()` method

**Test**: End-to-end extraction

### Success Criteria (Phase 4.2.7)

- [ ] Cursor resources parse successfully
- [ ] Bitmap resources parse successfully
- [ ] Both DIB header formats supported
- [ ] Unit tests: 100% pass rate
- [ ] Code compiles with zero warnings

**Deliverable**: Working cursor and bitmap extraction

---

## Phase 4.2.8: Message Tables (Specialized)

**Goal**: Implement message table parsing

**Note**: Message table structures already exist in `src/libexe/formats/exe_format_complete.ds` (lines 885-922):
- `MessageResourceFlags` enum (line 888) - MESSAGE_RESOURCE_UNICODE flag
- `MessageResourceEntry` (line 897) - Length, flags, and text
- `MessageResourceBlock` (line 908) - ID range and offset to entries
- `MessageResourceData` (line 919) - Top-level structure with blocks array

### Tasks

#### 1. Verify DataScript Message Table Structures
- [ ] Verify `exe_format_complete_parser.h` includes message structures
- [ ] Test that `MessageResourceData` and related structures can be parsed
- [ ] No new .ds files needed - all structures already defined

**Files Used**:
```
src/libexe/formats/exe_format_complete.ds (lines 885-922)  # Message table structures
generated/exe_format_complete_parser.h                     # Generated parser
docs/resfmt.txt                                             # Reference specification
```

**Test**: Verify DataScript parser can access message table structures

#### 2. Message Table Parser Implementation
- [ ] Create `include/libexe/resources/parsers/messagetable_parser.hpp`
- [ ] Define `message_entry` struct
- [ ] Define `message_block` struct
- [ ] Define `message_table` struct
- [ ] Implement `messagetable_parser` class
- [ ] Handle Unicode vs ANSI messages
- [ ] Create `src/libexe/resources/parsers/messagetable_parser.cpp`

**Files Created**:
```
include/libexe/resources/parsers/messagetable_parser.hpp
src/libexe/resources/parsers/messagetable_parser.cpp
```

**Test**: Unit test with message table resources
- Verify message extraction
- Check Unicode vs ANSI handling

#### 3. Factory Integration & Resource Entry Methods
- [ ] Update factory with message table parser
- [ ] Add `resource_entry::as_messagetable()` method

**Test**: End-to-end extraction

### Success Criteria (Phase 4.2.8)

- [ ] Message table resources parse successfully
- [ ] Both Unicode and ANSI messages supported
- [ ] Unit tests: 100% pass rate
- [ ] Code compiles with zero warnings

**Deliverable**: Working message table extraction

---

## Phase 4.2.9: Documentation & Polish

**Goal**: Complete documentation and final testing

### Tasks

#### 1. API Documentation
- [ ] Document all parser classes with Doxygen comments
- [ ] Add usage examples to headers
- [ ] Create `docs/RESOURCE_PARSER_API.md` with examples

#### 2. Comprehensive Testing
- [ ] Run all parsers on multiple real executables
- [ ] Test with PROGMAN.EXE (NE with many resources)
- [ ] Test with TCMDX32.EXE (PE32)
- [ ] Test with CGA40WOA.FON (NE font file)
- [ ] Add fuzz testing for robustness
- [ ] Test with truncated/malformed resources

#### 3. Performance Testing
- [ ] Benchmark parser performance
- [ ] Optimize hot paths if needed
- [ ] Ensure lazy parsing works correctly

#### 4. Error Handling Review
- [ ] Verify all parsers return std::nullopt on failure
- [ ] Ensure no exceptions thrown on malformed data
- [ ] Add error logging (optional)

### Success Criteria (Phase 4.2.9)

- [ ] All parsers documented
- [ ] API documentation complete
- [ ] All tests pass on multiple real executables
- [ ] No crashes on malformed data
- [ ] Performance acceptable (< 1ms per resource)
- [ ] Code review complete

**Deliverable**: Production-ready resource parser system

---

## Testing Strategy

### Unit Tests (Per Phase)
- Test each parser with known-good resource data
- Verify correct field extraction
- Test error handling with malformed data
- Compare against wrestool output

### Integration Tests
- Extract all resources from real executables
- Validate counts match wrestool
- Verify data integrity (sizes, checksums)

### Validation Against Reference Tools
- **wrestool**: Verify resource counts and sizes
- **ResourceHacker**: Cross-check extracted data
- Manual inspection of known resources

### Test Executables
1. **PROGMAN.EXE** (NE, Windows 3.11)
   - 157 resources total
   - Icons, dialogs, menus, strings, accelerators, version
   
2. **TCMDX32.EXE** (PE32)
   - 7 resources total
   - Icons, version, manifest
   
3. **CGA40WOA.FON** (NE font)
   - 3 resources total
   - Font, fontdir, version

### Continuous Testing
- Run tests after each phase completion
- Maintain 100% test pass rate
- No compiler warnings allowed

## Dependencies

### External Libraries
- **xml.h**: Lightweight XML parser (Phase 4.2.3)
  - Source: https://github.com/mrvladus/xml.h
  - License: MIT
  - Size: Single header file

### Build System Changes
- Ensure `exe_format_complete_parser.h` generation is working
- Add `third-party/` to include paths (for xml.h)
- Update CMakeLists.txt for new parser directories (`src/libexe/resources/parsers/`)
- May need to regenerate parser after adding dialog/menu structures to `exe_format_complete.ds`

## Risk Mitigation

### Complex Parsing (Dialogs, Menus)
- **Risk**: Variable-length fields, complex nesting
- **Mitigation**: Use DataScript for structure validation
- **Fallback**: Hand-coded parser if DataScript insufficient

### XML Parsing (Manifests)
- **Risk**: Invalid/malformed XML in real executables
- **Mitigation**: Permissive parsing, always extract raw XML
- **Fallback**: Return raw XML if structured parsing fails

### Performance
- **Risk**: Parsing all resources could be slow
- **Mitigation**: Lazy parsing (only parse when requested)
- **Monitoring**: Benchmark each parser

### Compatibility
- **Risk**: NE vs PE format differences
- **Mitigation**: Same API, format-specific implementation
- **Testing**: Test both NE and PE executables

## Commit Strategy

Each phase should result in **one commit** with:
- All code changes for that phase
- Comprehensive tests
- Updated documentation
- Commit message following project conventions

Example commit message:
```
Complete Phase 4.2.1 - Icon Parser Implementation

Implement comprehensive icon resource parsing for both RT_ICON and
RT_GROUP_ICON resource types.

- Add icon_parser and icon_group_parser classes
- Create DataScript schemas for icon structures
- Implement .ICO file export
- Add parser factory integration
- Comprehensive tests with PROGMAN.EXE (92 icons, 46 groups)

All tests pass (100% success rate).
Validated against wrestool output.

🤖 Generated with Claude Code
Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
```

## Success Metrics

### Code Quality
- Zero compiler warnings
- 100% test pass rate
- Clean architecture (SOLID principles)
- Comprehensive documentation

### Functionality
- All resource types supported
- Parsing matches reference tools
- Robust error handling
- Lazy evaluation

### Performance
- Parse time < 1ms per resource
- Memory efficient (no unnecessary copies)
- Suitable for processing large executables

## Timeline Estimate

**Aggressive Schedule** (full-time work):
- Phase 4.2.1: 2-3 days (icon infrastructure)
- Phase 4.2.2: 2-3 days (fonts)
- Phase 4.2.3: 2 days (version/manifest)
- Phase 4.2.4: 1 day (strings/accelerators)
- Phase 4.2.5: 2 days (dialogs)
- Phase 4.2.6: 1-2 days (menus)
- Phase 4.2.7: 1 day (cursors/bitmaps)
- Phase 4.2.8: 1 day (message tables)
- Phase 4.2.9: 1-2 days (polish)

**Total**: ~14-18 days for complete implementation

**Incremental Development** (part-time):
- Can proceed phase-by-phase
- Each phase is independently valuable
- Phases 4.2.1-4.2.3 cover 80% of use cases
