# OS/2 Presentation Manager Resource Formats

This document describes OS/2 Presentation Manager resource formats for use in the
mz-explode library. These formats differ significantly from Windows resources despite
sharing similar names and concepts.

## References

- **Official IBM Headers**: `1/os2tk45/h/` (IBM OS/2 Developer's Toolkit 4.5)
  - `pmwin.h` - DLGTEMPLATE, DLGTITEM, MENUITEM, ACCELTABLE
  - `os2def.h` - ACCEL
  - `pmbitmap.h` - BITMAPFILEHEADER, BITMAPARRAYFILEHEADER
  - `pmhelp.h` - HELPTABLE, HELPSUBTABLE
  - `bsedos.h` - RT_* resource type constants
- **Font Tools**: `1/os2-gpi-font-tools/include/` (Alexander Taylor, public domain)
  - `gpifont.h` - GPI bitmap font structures
  - `cmbfont.h` - Combined font structures
  - `unifont.h` - Uni-font structures
  - `os2res.h` - LX resource extraction structures

## Resource Types (RT_*)

From `bsedos.h`:

| Type | Value | Description |
|------|-------|-------------|
| RT_POINTER | 1 | Mouse pointer (icon) |
| RT_BITMAP | 2 | Bitmap |
| RT_MENU | 3 | Menu template |
| RT_DIALOG | 4 | Dialog template |
| RT_STRING | 5 | String tables |
| RT_FONTDIR | 6 | Font directory |
| RT_FONT | 7 | Font |
| RT_ACCELTABLE | 8 | Accelerator tables |
| RT_RCDATA | 9 | Binary data |
| RT_MESSAGE | 10 | Error message tables |
| RT_DLGINCLUDE | 11 | Dialog include file name |
| RT_VKEYTBL | 12 | Key to vkey tables |
| RT_KEYTBL | 13 | Key to UGL tables |
| RT_CHARTBL | 14 | Glyph to character tables |
| RT_DISPLAYINFO | 15 | Screen display information |
| RT_FKASHORT | 16 | Function key area short form |
| RT_FKALONG | 17 | Function key area long form |
| RT_HELPTABLE | 18 | Help table |
| RT_HELPSUBTABLE | 19 | Help subtable |
| RT_FDDIR | 20 | DBCS font driver directory |
| RT_FD | 21 | DBCS font driver |

## Key Differences from Windows

| Aspect | Windows | OS/2 PM |
|--------|---------|---------|
| Dialog items | DLGITEMTEMPLATE (no offsets) | DLGTITEM (uses string offsets) |
| Strings | Inline in structure | Offset-based references |
| Codepage | No explicit support | Explicit codepage field |
| Alignment | DWORD alignment common | pack(2) word alignment |
| ACCEL flags | FVIRTKEY, FCONTROL... | AF_VIRTUALKEY, AF_CONTROL... |
| HWND size | 4 bytes (32-bit) | 4 bytes |

---

## 1. Dialog Resources (RT_DIALOG)

### DLGTEMPLATE Structure

From `pmwin.h` (14 bytes header):

```c
#pragma pack(2)
typedef struct _DLGTEMPLATE {
   USHORT   cbTemplate;       // Total length of template (including all items)
   USHORT   type;             // Template format type (usually 0)
   USHORT   codepage;         // Code page for strings
   USHORT   offadlgti;        // Offset to first DLGTITEM from start of template
   USHORT   fsTemplateStatus; // Template status flags
   USHORT   iItemFocus;       // Index of item to receive initial focus
   USHORT   coffPresParams;   // Count of presentation parameter offsets
   // DLGTITEM items follow at offset offadlgti
} DLGTEMPLATE;
#pragma pack()
```

### DLGTITEM Structure

From `pmwin.h` (26 bytes per item):

```c
#pragma pack(2)
typedef struct _DLGTITEM {
   USHORT  fsItemStatus;   // Item status flags
   USHORT  cChildren;      // Number of child items
   USHORT  cchClassName;   // Length of class name string
   USHORT  offClassName;   // Offset to class name (from template start)
   USHORT  cchText;        // Length of text string
   USHORT  offText;        // Offset to text (from template start)
   ULONG   flStyle;        // Window style flags
   SHORT   x;              // X position
   SHORT   y;              // Y position
   SHORT   cx;             // Width
   SHORT   cy;             // Height
   USHORT  id;             // Control ID
   USHORT  offPresParams;  // Offset to presentation parameters
   USHORT  offCtlData;     // Offset to control data
} DLGTITEM;
#pragma pack()
```

### Dialog Template Layout

```
+-------------------+
| DLGTEMPLATE (14)  |  <- cbTemplate = total size
+-------------------+
| DLGTITEM[0] (26)  |  <- at offset offadlgti
+-------------------+
| DLGTITEM[1] (26)  |
+-------------------+
| ...               |
+-------------------+
| String pool       |  <- offClassName, offText point here
+-------------------+
| PresParams (opt)  |
+-------------------+
| CtlData (opt)     |
+-------------------+
```

### DataScript Definition

```datascript
// OS/2 PM Dialog Template (RT_DIALOG)
package formats.resources.os2.dialogs;

little;

// Dialog template header (14 bytes)
struct os2_dialog_template {
    uint16 cb_template;         // Total template size
    uint16 type;                // Format type (0)
    uint16 codepage;            // Code page
    uint16 off_adlgti;          // Offset to first item
    uint16 fs_template_status;  // Status flags
    uint16 i_item_focus;        // Initial focus item index
    uint16 coff_pres_params;    // Presentation param offset count
};

// Dialog item (26 bytes)
struct os2_dialog_item {
    uint16 fs_item_status;      // Item status
    uint16 c_children;          // Child count
    uint16 cch_class_name;      // Class name length
    uint16 off_class_name;      // Class name offset
    uint16 cch_text;            // Text length
    uint16 off_text;            // Text offset
    uint32 fl_style;            // Window style
    int16 x;
    int16 y;
    int16 cx;
    int16 cy;
    uint16 id;                  // Control ID
    uint16 off_pres_params;     // Presentation params offset
    uint16 off_ctl_data;        // Control data offset
};
```

---

## 2. Menu Resources (RT_MENU)

### MENUITEM Structure

From `pmwin.h` (16 bytes):

```c
typedef struct _MENUITEM {
   SHORT   iPosition;      // Position in menu (MIT_END = -1 for last)
   USHORT  afStyle;        // Item style (MIS_* flags)
   USHORT  afAttribute;    // Item attributes (MIA_* flags)
   USHORT  id;             // Menu item ID
   HWND    hwndSubMenu;    // Handle to submenu (4 bytes)
   ULONG   hItem;          // Item handle/data
} MENUITEM;
```

### Menu Style Flags (MIS_*)

```c
#define MIS_TEXT           0x0001  // Text item
#define MIS_BITMAP         0x0002  // Bitmap item
#define MIS_SEPARATOR      0x0004  // Separator
#define MIS_OWNERDRAW      0x0008  // Owner-drawn
#define MIS_SUBMENU        0x0010  // Has submenu
#define MIS_MULTMENU       0x0020  // Multiple choice submenu
#define MIS_SYSCOMMAND     0x0040  // System command
#define MIS_HELP           0x0080  // Help item
#define MIS_STATIC         0x0100  // Static item
#define MIS_BUTTONSEPARATOR 0x0200 // Button separator
#define MIS_BREAK          0x0400  // Column break
#define MIS_BREAKSEPARATOR 0x0800  // Column break with separator
#define MIS_GROUP          0x1000  // Multiple choice group start
#define MIS_SINGLE         0x2000  // Single selection
```

### Menu Attribute Flags (MIA_*)

```c
#define MIA_NODISMISS      0x0020  // Don't dismiss on selection
#define MIA_FRAMED         0x1000  // Framed item
#define MIA_CHECKED        0x2000  // Checkmark
#define MIA_DISABLED       0x4000  // Disabled (grayed)
#define MIA_HILITED        0x8000  // Highlighted
```

### DataScript Definition

```datascript
// OS/2 PM Menu Item
package formats.resources.os2.menus;

little;

enum uint16 os2_menu_style {
    MIS_TEXT           = 0x0001,
    MIS_BITMAP         = 0x0002,
    MIS_SEPARATOR      = 0x0004,
    MIS_OWNERDRAW      = 0x0008,
    MIS_SUBMENU        = 0x0010,
    MIS_SYSCOMMAND     = 0x0040,
    MIS_HELP           = 0x0080,
    MIS_STATIC         = 0x0100,
    MIS_BREAK          = 0x0400,
    MIS_BREAKSEPARATOR = 0x0800
};

enum uint16 os2_menu_attr {
    MIA_NODISMISS      = 0x0020,
    MIA_FRAMED         = 0x1000,
    MIA_CHECKED        = 0x2000,
    MIA_DISABLED       = 0x4000,
    MIA_HILITED        = 0x8000
};

// Menu item structure (16 bytes)
struct os2_menu_item {
    int16 i_position;       // Position (-1 = end)
    uint16 af_style;        // MIS_* flags
    uint16 af_attribute;    // MIA_* flags
    uint16 id;              // Menu item ID
    uint32 hwnd_sub_menu;   // Submenu handle
    uint32 h_item;          // Item handle/data
};
```

---

## 3. Accelerator Resources (RT_ACCELTABLE)

### ACCEL Structure

From `os2def.h` (6 bytes):

```c
#pragma pack(2)
typedef struct _ACCEL {
   USHORT  fs;     // Accelerator flags (AF_*)
   USHORT  key;    // Key code
   USHORT  cmd;    // Command ID
} ACCEL;
#pragma pack()
```

### ACCELTABLE Structure

From `pmwin.h` (4 bytes header + ACCEL array):

```c
#pragma pack(2)
typedef struct _ACCELTABLE {
   USHORT  cAccel;      // Number of accelerator entries
   USHORT  codepage;    // Code page
   ACCEL   aaccel[1];   // Variable-length array of ACCEL
} ACCELTABLE;
#pragma pack()
```

### Accelerator Flags (AF_*)

```c
#define AF_CHAR        0x0001  // Character code
#define AF_VIRTUALKEY  0x0002  // Virtual key code
#define AF_SCANCODE    0x0004  // Scan code
#define AF_SHIFT       0x0008  // Shift key required
#define AF_CONTROL     0x0010  // Control key required
#define AF_ALT         0x0020  // Alt key required
#define AF_LONEKEY     0x0040  // Key alone (no modifiers)
#define AF_SYSCOMMAND  0x0100  // System command
#define AF_HELP        0x0200  // Help key
```

### DataScript Definition

```datascript
// OS/2 PM Accelerator Table (RT_ACCELTABLE)
package formats.resources.os2.accelerators;

little;

enum uint16 os2_accel_flags {
    AF_CHAR        = 0x0001,
    AF_VIRTUALKEY  = 0x0002,
    AF_SCANCODE    = 0x0004,
    AF_SHIFT       = 0x0008,
    AF_CONTROL     = 0x0010,
    AF_ALT         = 0x0020,
    AF_LONEKEY     = 0x0040,
    AF_SYSCOMMAND  = 0x0100,
    AF_HELP        = 0x0200
};

// Single accelerator entry (6 bytes)
struct os2_accel {
    uint16 fs;      // AF_* flags
    uint16 key;     // Key code
    uint16 cmd;     // Command ID
};

// Accelerator table (4 bytes header + entries)
struct os2_accel_table {
    uint16 c_accel;             // Entry count
    uint16 codepage;            // Code page
    os2_accel entries[c_accel]; // Accelerator entries
};
```

---

## 4. Bitmap/Pointer Resources (RT_BITMAP, RT_POINTER)

### BITMAPFILEHEADER Structure

From `pmbitmap.h`:

```c
#pragma pack(1)
typedef struct _BITMAPINFOHEADER {  // 12 bytes (OS/2 1.x)
   ULONG  cbFix;       // Structure size (12)
   USHORT cx;          // Width in pixels
   USHORT cy;          // Height in pixels
   USHORT cPlanes;     // Number of planes (1)
   USHORT cBitCount;   // Bits per pixel (1, 4, 8, 24)
} BITMAPINFOHEADER;

typedef struct _BITMAPFILEHEADER {  // 26 bytes
   USHORT usType;      // File type (BFT_*)
   ULONG  cbSize;      // File size
   SHORT  xHotspot;    // Hotspot X (for pointers)
   SHORT  yHotspot;    // Hotspot Y (for pointers)
   ULONG  offBits;     // Offset to bitmap bits
   BITMAPINFOHEADER bmp;  // Bitmap info header
} BITMAPFILEHEADER;
#pragma pack()
```

### BITMAPINFOHEADER2 Structure

From `pmbitmap.h` (OS/2 2.0+, 64 bytes):

```c
typedef struct _BITMAPINFOHEADER2 {
   ULONG  cbFix;           // Structure size (varies, >= 16)
   ULONG  cx;              // Width in pixels
   ULONG  cy;              // Height in pixels
   USHORT cPlanes;         // Number of planes
   USHORT cBitCount;       // Bits per pixel
   ULONG  ulCompression;   // Compression type (BCA_*)
   ULONG  cbImage;         // Image size in bytes
   ULONG  cxResolution;    // X resolution
   ULONG  cyResolution;    // Y resolution
   ULONG  cclrUsed;        // Colors used
   ULONG  cclrImportant;   // Important colors
   USHORT usUnits;         // Units of measure
   USHORT usReserved;
   USHORT usRecording;     // Recording algorithm
   USHORT usRendering;     // Halftoning algorithm
   ULONG  cSize1;          // Size value 1
   ULONG  cSize2;          // Size value 2
   ULONG  ulColorEncoding; // Color encoding
   ULONG  ulIdentifier;    // Application identifier
} BITMAPINFOHEADER2;
```

### Bitmap File Type Constants (BFT_*)

```c
#define BFT_ICON           0x4349   // 'IC' - Icon
#define BFT_BMAP           0x4D42   // 'BM' - Bitmap
#define BFT_POINTER        0x5450   // 'PT' - Pointer
#define BFT_COLORICON      0x4943   // 'CI' - Color icon
#define BFT_COLORPOINTER   0x5043   // 'CP' - Color pointer
#define BFT_BITMAPARRAY    0x4142   // 'BA' - Bitmap array
```

### DataScript Definition

```datascript
// OS/2 PM Bitmap and Pointer Resources
package formats.resources.os2.bitmaps;

little;

enum uint16 os2_bitmap_type {
    BFT_ICON         = 0x4349,  // 'IC'
    BFT_BMAP         = 0x4D42,  // 'BM'
    BFT_POINTER      = 0x5450,  // 'PT'
    BFT_COLORICON    = 0x4943,  // 'CI'
    BFT_COLORPOINTER = 0x5043,  // 'CP'
    BFT_BITMAPARRAY  = 0x4142   // 'BA'
};

// OS/2 1.x bitmap info header (12 bytes)
struct os2_bitmap_info_header {
    uint32 cb_fix;      // Structure size (12)
    uint16 cx;          // Width
    uint16 cy;          // Height
    uint16 c_planes;    // Planes (1)
    uint16 c_bit_count; // Bits per pixel
};

// RGB triple (3 bytes, OS/2 1.x palette)
struct os2_rgb {
    uint8 b_blue;
    uint8 b_green;
    uint8 b_red;
};

// OS/2 2.0+ bitmap info header (variable size, >= 16 bytes)
struct os2_bitmap_info_header2 {
    uint32 cb_fix;           // Structure size
    uint32 cx;               // Width
    uint32 cy;               // Height
    uint16 c_planes;         // Planes
    uint16 c_bit_count;      // Bits per pixel
    uint32 ul_compression;   // Compression type
    uint32 cb_image;         // Image size
    uint32 cx_resolution;    // X resolution
    uint32 cy_resolution;    // Y resolution
    uint32 cclr_used;        // Colors used
    uint32 cclr_important;   // Important colors
    // Extended fields follow if cb_fix > 40
};

// Bitmap file header
struct os2_bitmap_file_header {
    uint16 us_type;     // BFT_* type
    uint32 cb_size;     // File size
    int16 x_hotspot;    // Hotspot X
    int16 y_hotspot;    // Hotspot Y
    uint32 off_bits;    // Offset to bitmap data
    os2_bitmap_info_header bmp;  // Info header follows
};

// Bitmap array header (for multi-resolution icons/pointers)
struct os2_bitmap_array_header {
    uint16 us_type;     // BFT_BITMAPARRAY (0x4142)
    uint32 cb_size;     // Size of this entry
    uint32 off_next;    // Offset to next entry (0 = last)
    uint16 cx_display;  // Target display width
    uint16 cy_display;  // Target display height
    // BITMAPFILEHEADER follows
};
```

---

## 5. Help Resources (RT_HELPTABLE, RT_HELPSUBTABLE)

### HELPTABLE Structure

From `pmhelp.h`:

```c
#pragma pack(2)
typedef struct _HELPTABLE {
   USHORT          idAppWindow;       // Application window ID
   PHELPSUBTABLE   phstHelpSubTable;  // Pointer to subtable (4 bytes)
   USHORT          idExtPanel;        // Extended help panel ID
} HELPTABLE;
#pragma pack()
```

### HELPSUBTABLE

A HELPSUBTABLE is simply an array of USHORT values (control ID / help panel ID pairs).

```c
typedef USHORT HELPSUBTABLE;  // Array of USHORT
```

### DataScript Definition

```datascript
// OS/2 PM Help Table (RT_HELPTABLE)
package formats.resources.os2.help;

little;

// Help table entry (8 bytes in resource file)
// Note: In resource file, pointer is stored as offset
struct os2_help_table_entry {
    uint16 id_app_window;      // Application window ID
    uint32 offset_subtable;    // Offset to subtable (in resource)
    uint16 id_ext_panel;       // Extended help panel ID
};

// Help subtable is just pairs of USHORTs: [control_id, panel_id]...
// Terminated by 0x0000 (control_id = 0)
```

---

## 6. GPI Font Resources (RT_FONT, RT_FONTDIR)

### Font File Structure

From `gpifont.h` (Alexander Taylor):

```
+---------------------+
| OS2FONTSTART        |  Signature: 0xFFFFFFFE, "OS/2 FONT"
+---------------------+
| OS2FOCAMETRICS      |  Identity: 0x00000001, font metrics
+---------------------+
| OS2FONTDEFHEADER    |  Identity: 0x00000002, glyph definitions
+---------------------+
| Character data      |  OS2CHARDEF1/3 array + bitmap data
+---------------------+
| OS2KERNPAIRTABLE    |  Identity: 0x00000003 (optional)
+---------------------+
| OS2ADDMETRICS       |  Identity: 0x00000004, PANOSE table
+---------------------+
| OS2FONTEND          |  Identity: 0xFFFFFFFF
+---------------------+
```

### OS2FONTSTART Structure

```c
typedef struct _OS2_Font_Header {
    ULONG   Identity;           // 0xFFFFFFFE
    ULONG   ulSize;             // Structure size
    CHAR    achSignature[12];   // "OS/2 FONT" or "OS/2 FONT 2"
} OS2FONTSTART;
```

### OS2FOCAMETRICS Structure

From `gpifont.h` (136 bytes):

```c
typedef struct _OS2_FOCA_Metrics {
    ULONG   Identity;               // 0x00000001
    ULONG   ulSize;                 // Structure size
    CHAR    szFamilyname[32];       // Font family name
    CHAR    szFacename[32];         // Font face name
    SHORT   usRegistryId;           // Registered font ID
    SHORT   usCodePage;             // Font encoding (850 = PMUGL)
    SHORT   yEmHeight;              // Em square height
    SHORT   yXHeight;               // Lowercase x height
    SHORT   yMaxAscender;           // Max ascender
    SHORT   yMaxDescender;          // Max descender
    SHORT   yLowerCaseAscent;       // Lowercase ascender
    SHORT   yLowerCaseDescent;      // Lowercase descender
    SHORT   yInternalLeading;       // Internal leading
    SHORT   yExternalLeading;       // External leading
    SHORT   xAveCharWidth;          // Average char width
    SHORT   xMaxCharInc;            // Max char increment
    SHORT   xEmInc;                 // Em increment
    SHORT   yMaxBaselineExt;        // Max baseline extent
    SHORT   sCharSlope;             // Character slope (degrees)
    SHORT   sInlineDir;             // Inline direction
    SHORT   sCharRot;               // Character rotation
    USHORT  usWeightClass;          // Weight (1000-9000)
    USHORT  usWidthClass;           // Width (1000-9000)
    SHORT   xDeviceRes;             // Target X resolution (dpi)
    SHORT   yDeviceRes;             // Target Y resolution (dpi)
    SHORT   usFirstChar;            // First character codepoint
    SHORT   usLastChar;             // Last character offset
    SHORT   usDefaultChar;          // Default character offset
    SHORT   usBreakChar;            // Break character offset
    SHORT   usNominalPointSize;     // Point size * 10
    SHORT   usMinimumPointSize;     // Min point size * 10
    SHORT   usMaximumPointSize;     // Max point size * 10
    SHORT   fsTypeFlags;            // Type flags
    SHORT   fsDefn;                 // Definition flags
    SHORT   fsSelectionFlags;       // Selection flags
    SHORT   fsCapabilities;         // Capability flags
    SHORT   ySubscriptXSize;        // Subscript X size
    SHORT   ySubscriptYSize;        // Subscript Y size
    SHORT   ySubscriptXOffset;      // Subscript X offset
    SHORT   ySubscriptYOffset;      // Subscript Y offset
    SHORT   ySuperscriptXSize;      // Superscript X size
    SHORT   ySuperscriptYSize;      // Superscript Y size
    SHORT   ySuperscriptXOffset;    // Superscript X offset
    SHORT   ySuperscriptYOffset;    // Superscript Y offset
    SHORT   yUnderscoreSize;        // Underscore thickness
    SHORT   yUnderscorePosition;    // Underscore position
    SHORT   yStrikeoutSize;         // Strikeout thickness
    SHORT   yStrikeoutPosition;     // Strikeout position
    SHORT   usKerningPairs;         // Kerning pair count
    SHORT   sFamilyClass;           // Family class
    ULONG   reserved;               // Reserved
} OS2FOCAMETRICS;
```

### OS2FONTDEFHEADER Structure

```c
typedef struct _OS2_Font_Definition {
    ULONG Identity;             // 0x00000002
    ULONG ulSize;               // Size of struct + all glyph data
    SHORT fsFontdef;            // Font definition flags
    SHORT fsChardef;            // Character definition format
    SHORT usCellSize;           // Character definition size (bytes)
    SHORT xCellWidth;           // Cell width (type 1 only)
    SHORT yCellHeight;          // Cell height
    SHORT xCellIncrement;       // Cell increment (type 1 only)
    SHORT xCellA;               // a_space (type 3 only)
    SHORT xCellB;               // b_space (type 3 only)
    SHORT xCellC;               // c_space (type 3 only)
    SHORT pCellBaseOffset;      // Baseline offset from top
} OS2FONTDEFHEADER;
```

### Character Definitions

```c
// Type 1/2 font character (6 bytes)
typedef struct _OS2_Character_1 {
    ULONG   ulOffset;   // Bitmap offset in font
    USHORT  ulWidth;    // Bitmap width (pixels)
} OS2CHARDEF1;

// Type 3 font character (10 bytes)
typedef struct _OS2_Character_3 {
    ULONG   ulOffset;   // Bitmap offset
    SHORT   aSpace;     // a_space
    SHORT   bSpace;     // b_space (glyph width)
    SHORT   cSpace;     // c_space
} OS2CHARDEF3;
```

### Font Type Constants

```c
#define OS2FONTDEF_FONT1    0x47   // Type 1: Fixed-width
#define OS2FONTDEF_FONT2    0x42   // Type 2: Proportional
#define OS2FONTDEF_FONT3    0x42   // Type 3: Proportional with ABC widths
#define OS2FONTDEF_CHAR1    0x81   // Type 1 char format
#define OS2FONTDEF_CHAR2    0x81   // Type 2 char format
#define OS2FONTDEF_CHAR3    0xB8   // Type 3 char format
```

### DataScript Definition

```datascript
// OS/2 GPI Font Resources (RT_FONT, RT_FONTDIR)
package formats.resources.os2.fonts;

little;

// Font record identity codes
const uint32 SIG_OS2FONTSTART  = 0xFFFFFFFE;
const uint32 SIG_OS2METRICS    = 0x00000001;
const uint32 SIG_OS2FONTDEF    = 0x00000002;
const uint32 SIG_OS2KERN       = 0x00000003;
const uint32 SIG_OS2ADDMETRICS = 0x00000004;
const uint32 SIG_OS2FONTEND    = 0xFFFFFFFF;

// Font start signature (20 bytes)
struct os2_font_start {
    uint32 identity : identity == SIG_OS2FONTSTART;
    uint32 ul_size;
    uint8 ach_signature[12];  // "OS/2 FONT" or "OS/2 FONT 2"
};

// Font metrics (136 bytes)
struct os2_foca_metrics {
    uint32 identity : identity == SIG_OS2METRICS;
    uint32 ul_size;
    uint8 sz_familyname[32];
    uint8 sz_facename[32];
    int16 us_registry_id;
    int16 us_code_page;
    int16 y_em_height;
    int16 y_x_height;
    int16 y_max_ascender;
    int16 y_max_descender;
    int16 y_lowercase_ascent;
    int16 y_lowercase_descent;
    int16 y_internal_leading;
    int16 y_external_leading;
    int16 x_ave_char_width;
    int16 x_max_char_inc;
    int16 x_em_inc;
    int16 y_max_baseline_ext;
    int16 s_char_slope;
    int16 s_inline_dir;
    int16 s_char_rot;
    uint16 us_weight_class;
    uint16 us_width_class;
    int16 x_device_res;
    int16 y_device_res;
    int16 us_first_char;
    int16 us_last_char;
    int16 us_default_char;
    int16 us_break_char;
    int16 us_nominal_point_size;
    int16 us_minimum_point_size;
    int16 us_maximum_point_size;
    int16 fs_type_flags;
    int16 fs_defn;
    int16 fs_selection_flags;
    int16 fs_capabilities;
    int16 y_subscript_x_size;
    int16 y_subscript_y_size;
    int16 y_subscript_x_offset;
    int16 y_subscript_y_offset;
    int16 y_superscript_x_size;
    int16 y_superscript_y_size;
    int16 y_superscript_x_offset;
    int16 y_superscript_y_offset;
    int16 y_underscore_size;
    int16 y_underscore_position;
    int16 y_strikeout_size;
    int16 y_strikeout_position;
    int16 us_kerning_pairs;
    int16 s_family_class;
    uint32 reserved;
};

// Font definition header (24 bytes)
struct os2_font_def_header {
    uint32 identity : identity == SIG_OS2FONTDEF;
    uint32 ul_size;             // Size includes character data
    int16 fs_fontdef;           // Font definition flags
    int16 fs_chardef;           // Character definition format
    int16 us_cell_size;         // Size of each char def
    int16 x_cell_width;         // Cell width (type 1)
    int16 y_cell_height;        // Cell height
    int16 x_cell_increment;     // Increment (type 1)
    int16 x_cell_a;             // a_space (type 3)
    int16 x_cell_b;             // b_space (type 3)
    int16 x_cell_c;             // c_space (type 3)
    int16 p_cell_base_offset;   // Baseline offset
};

// Type 1/2 character definition (6 bytes)
struct os2_char_def1 {
    uint32 ul_offset;   // Bitmap offset
    uint16 ul_width;    // Bitmap width
};

// Type 3 character definition (10 bytes)
struct os2_char_def3 {
    uint32 ul_offset;   // Bitmap offset
    int16 a_space;      // a_space
    int16 b_space;      // b_space (width)
    int16 c_space;      // c_space
};

// Additional metrics / PANOSE (20 bytes)
struct os2_add_metrics {
    uint32 identity : identity == SIG_OS2ADDMETRICS;
    uint32 ul_size;         // 20
    uint8 panose[12];       // PANOSE data (padded to 12)
};

// Font end signature (8 bytes)
struct os2_font_end {
    uint32 identity : identity == SIG_OS2FONTEND;
    uint32 ul_size;
};

// Font directory entry
struct os2_font_dir_entry {
    uint16 us_index;                // Resource ID
    os2_foca_metrics metrics;       // Font metrics
    uint8 panose[12];               // PANOSE data
};

// Font directory header
struct os2_font_directory {
    uint16 us_header_size;          // Header size
    uint16 us_n_fonts;              // Font count
    uint16 us_i_metrics;            // Metrics size
    os2_font_dir_entry entries[us_n_fonts];
};
```

---

## 7. String Resources (RT_STRING)

OS/2 string tables are stored as arrays of length-prefixed strings.

### DataScript Definition

```datascript
// OS/2 PM String Table (RT_STRING)
package formats.resources.os2.strings;

little;

// Length-prefixed string entry
struct os2_string_entry {
    uint16 length;              // String length in bytes
    uint8 text[length];         // String data (encoding depends on codepage)
};
```

---

## Implementation Notes

### Parsing Strategy

1. **Use DataScript** for fixed-size structures (headers, menu items, accelerators)
2. **Manual parsing** required for:
   - Dialog templates (offset-based string references)
   - Help tables (pointer-to-offset conversion)
   - Font resources (complex nested structure with identity-based records)
   - Bitmap arrays (linked list with offsets)

### Codepage Handling

OS/2 resources include explicit codepage fields. Common codepages:
- 437 - US English
- 850 - Multilingual Latin I
- 932 - Japanese Shift-JIS
- 949 - Korean
- 950 - Traditional Chinese

### Endianness

All OS/2 resource structures are little-endian (Intel x86).

### Alignment

Most OS/2 resource structures use `#pragma pack(2)` (word alignment), not DWORD
alignment like Windows resources.
