# Comprehensive Guide to the Windows Resource Script (RC) Language

This guide provides a comprehensive overview of the Windows Resource Script (RC) language, used for defining an application's user-interface resources.

## Resources

### ACCELERATORS

Defines one or more accelerators for an application. An accelerator is a keystroke that gives the user a quick way to perform a task.

**Syntax**

```rc
acctablename ACCELERATORS [optional-statements] {
    event, idvalue, [type] [options]
    ...
}
```

**Parameters**

*   `acctablename`: Unique name or a 16-bit unsigned integer value that identifies the resource.
*   `optional-statements`: Zero or more of the following:
    *   `CHARACTERISTICS dword`: User-defined information.
    *   `LANGUAGE language, sublanguage`: Specifies the language for the resource.
    *   `VERSION dword`: User-defined version number.
*   `event`: The keystroke to be used as an accelerator. It can be one of the following:
    *   `"char"`: A single character enclosed in double quotation marks. A caret (^) prefix indicates a control character (e.g., `^C`).
    *   `Character`: An integer value representing a character (requires `ASCII` type).
    *   `virtual-key character`: An integer value representing a virtual key (requires `VIRTKEY` type). The virtual key for alphanumeric keys can be specified by placing the uppercase letter or number in double quotation marks (e.g., "9" or "C").
*   `idvalue`: A 16-bit unsigned integer value that identifies the accelerator.
*   `type`: Required when `event` is a character or virtual-key character. Can be `ASCII` or `VIRTKEY`.
*   `options`: One or more of the following:
    *   `NOINVERT`: Prevents a top-level menu item from being highlighted. (Obsolete).
    *   `ALT`: Activates only if the ALT key is down (for virtual keys).
    *   `SHIFT`: Activates only if the SHIFT key is down (for virtual keys).
    *   `CONTROL`: Activates only if the CONTROL key is down (for virtual keys). Equivalent to the `^` prefix.

**Example**

```rc
1 ACCELERATORS
{
  "^C",  IDDCLEAR         ; control C
  "K",   IDDCLEAR         ; shift K
  "k",   IDDELLIPSE, ALT  ; alt k
  98,    IDDRECT, ASCII   ; b
  66,    IDDSTAR, ASCII   ; B (shift b)
  "g",   IDDRECT          ; g
  "G",   IDDSTAR          ; G (shift G)
  VK_F1, IDDCLEAR, VIRTKEY                ; F1
  VK_F1, IDDSTAR, CONTROL, VIRTKEY        ; control F1
  VK_F1, IDDELLIPSE, SHIFT, VIRTKEY       ; shift F1
  VK_F1, IDDRECT, ALT, VIRTKEY            ; alt F1
  VK_F2, IDDCLEAR, ALT, SHIFT, VIRTKEY    ; alt shift F2
  VK_F2, IDDSTAR, CONTROL, SHIFT, VIRTKEY ; ctrl shift F2
  VK_F2, IDDRECT, ALT, CONTROL, VIRTKEY   ; alt control F2
}

### BITMAP

Defines a bitmap that an application uses in its screen display or as an item in a menu or control.

**Syntax**

```rc
nameID BITMAP filename
```

**Parameters**

*   `nameID`: Unique name or a 16-bit unsigned integer value identifying the resource.
*   `filename`: Name of the file that contains the resource. The name must be a valid file name; it must be a full path if the file is not in the current working directory. The path should be a quoted string.

**Example**

```rc
disk1   BITMAP "disk.bmp"
12      BITMAP "diskette.bmp"
```

### CURSOR

Defines a bitmap that defines the shape of the cursor on the display screen or an animated cursor.

**Syntax**

```rc
nameID CURSOR filename
```

**Parameters**

*   `nameID`: Unique name or a 16-bit unsigned integer identifying the resource.
*   `filename`: Name of the file that contains the resource. The name must be a valid file name; it must be a full path if the file is not in the current working directory. The path should be a quoted string.

**Example**

```rc
cursor1 CURSOR "bullseye.cur"
2       CURSOR "d:\\cursor\\arrow.cur"
```

### DIALOG

Defines a dialog box. The statement defines the position and dimensions of the dialog box on the screen as well as the dialog box style. **Note:** `DIALOG` is obsolete. New applications should use `DIALOGEX`.

**Syntax**

```rc
nameID DIALOG x, y, width, height [optional-statements] {
    control-statement
    ...
}
```

**Parameters**

*   `nameID`: Unique name or a unique 16-bit unsigned integer value that identifies the dialog box.
*   `x, y, width, height`: The position and dimensions of the dialog box.
*   `optional-statements`: Zero or more of the following:
    *   `CAPTION "text"`: The caption of the dialog box.
    *   `CHARACTERISTICS dword`: User-defined `DWORD` value.
    *   `CLASS class`: A 16-bit unsigned integer or a string that identifies the class of the dialog box.
    *   `EXSTYLE extended-styles`: Extended window style of the dialog box.
    *   `FONT pointsize, typeface`: The font for the dialog box.
    *   `LANGUAGE language, sublanguage`: The language of the dialog box.
    *   `MENU menuname`: The menu to be used.
    *   `STYLE styles`: The styles of the dialog box.
    *   `VERSION dword`: User-defined `DWORD` value.
*   `control-statement`: Defines a control within the dialog box.

**Example**

```rc
#include <windows.h>

ErrorDialog DIALOG  10, 10, 300, 110
STYLE WS_POPUP | WS_BORDER
CAPTION "Error!"
{
    CTEXT "Select One:", 1, 10, 10, 280, 12
    PUSHBUTTON "&Retry", 2, 75, 30, 60, 12
    PUSHBUTTON "&Abort", 3, 75, 50, 60, 12
    PUSHBUTTON "&Ignore", 4, 75, 80, 60, 12
}
```

### DIALOGEX

Defines an extended dialog box. This is an extension of the `DIALOG` statement and allows for the use of extended styles and more control over the dialog's appearance and behavior.

**Syntax**

```rc
nameID DIALOGEX x, y, width, height [, helpID] [optional-statements] {
    control-statements
}
```

**Parameters**

*   `nameID`: Unique name or a unique 16-bit unsigned integer value that identifies the dialog box.
*   `x, y, width, height`: The position and dimensions of the dialog box in dialog units.
*   `helpID`: (Optional) Numeric expression for the `WM_HELP` processing ID.
*   `optional-statements`: Zero or more of the following:
    *   `CAPTION "text"`: The caption of the dialog box.
    *   `CHARACTERISTICS dword`: User-defined `DWORD` value.
    *   `CLASS class`: A 16-bit unsigned integer or a string that identifies the class of the dialog box.
    *   `EXSTYLE extended-styles`: Extended window style of the dialog box.
    *   `FONT pointsize, "typeface", weight, italic, charset`: Specifies the font, including weight and italic style.
    *   `LANGUAGE language, sublanguage`: The language of the dialog box.
    *   `MENU menuname`: The menu to be used.
    *   `STYLE styles`: The styles of the dialog box.
    *   `VERSION dword`: User-defined `DWORD` value.
*   `control-statements`: Defines the controls within the dialog box.

**Control Statements**

`DIALOGEX` supports various control statements:

*   **Generic Controls:** `CONTROL "text", id, "class", style, x, y, width, height, [extended-style], [help-id]`
*   **Static Controls:** `LTEXT "text", id, x, y, width, height, [style], [extended-style], [help-id]`
*   **Button Controls:** `PUSHBUTTON "text", id, x, y, width, height, [style], [extended-style], [help-id]`
*   **Edit Controls:** `EDITTEXT id, x, y, width, height, [style], [extended-style], [help-id]`

(See the Controls section for more details on each control type.)

### FONT

Defines a file that contains a font.

**Syntax**

```rc
nameID FONT filename
```

**Parameters**

*   `nameID`: Unique 16-bit unsigned integer value identifying the resource.
*   `filename`: Name of the file that contains the resource. The name must be a valid file name; it must be a full path if the file is not in the current working directory. The path should be a quoted string.

**Example**

```rc
5 FONT  "cmroman.fnt"
```

### HTML

Defines an HTML file.

**Syntax**

```rc
nameID HTML filename
```

**Parameters**

*   `nameID`: Unique name or a 16-bit unsigned integer value identifying the resource.
*   `filename`: The name of the HTML file. It must be a full or relative path if the file is not in the current working directory. The path should be a quoted string.

**Example**

```rc
ID_RESPONSE_ERROR_PAGE  HTML "res\\responseerorpage.htm"
```

### ICON

Defines a bitmap that defines the shape of the icon to be used for a given application or an animated icon.

**Syntax**

```rc
nameID ICON filename
```

**Parameters**

*   `nameID`: Unique name or a 16-bit unsigned integer value identifying the resource.
*   `filename`: Name of the file that contains the resource. The name must be a valid file name; it must be a full path if the file is not in the current working directory. The path should be a quoted string.

**Example**

```rc
desk1   ICON "desk.ico"
11      ICON "custom.ico"
```

### MENU

Defines the contents of a menu resource. A menu resource is a collection of information that defines the appearance and function of an application menu.

**Syntax**

```rc
menuID MENU [optional-statements] {
    item-definitions
    ...
}
```

**Parameters**

*   `menuID`: A unique name or a 16-bit unsigned integer value that identifies the menu.
*   `optional-statements`: Zero or more of the following:
    *   `CHARACTERISTICS dword`: User-defined information.
    *   `LANGUAGE language, sublanguage`: The language for the resource.
    *   `VERSION dword`: User-defined version number.
*   `item-definitions`: Defines the menu items. See `MENUITEM` and `POPUP` for more details.

**Example**

```rc
sample MENU
{
     MENUITEM "&Soup", 100
     MENUITEM "S&alad", 101
     POPUP "&Entree"
     {
          MENUITEM "&Fish", 200
          MENUITEM "&Chicken", 201, CHECKED
          POPUP "&Beef"
          {
               MENUITEM "&Steak", 301
               MENUITEM "&Prime Rib", 302
          }
     }
     MENUITEM "&Dessert", 103
}
```

### MENUEX

Defines an extended menu resource, which provides more functionality than the standard `MENU` resource. `MENUEX` allows for the specification of help identifiers, menu identifiers, and the use of `MFT_*` type flags and `MFS_*` state flags.

**Syntax**

```rc
menuID MENUEX {
    MENUITEM itemText [, [id] [, [type] [, [state]]]]
    POPUP itemText [, [id] [, [type] [, [state] [, [helpID]]]]] {
        popupBody
    }
    ...
}
```

**Parameters**

*   `menuID`: A unique name or a 16-bit unsigned integer value that identifies the menu.
*   `MENUITEM`: Defines a menu item.
    *   `itemText`: The text for the menu item.
    *   `id`: The identifier of the menu item.
    *   `type`: The type of the menu item (e.g., `MFT_STRING`).
    *   `state`: The state of the menu item (e.g., `MFS_CHECKED`).
*   `POPUP`: Defines a menu item that has a submenu.
    *   `itemText`: The text for the popup menu item.
    *   `id`: The identifier of the popup menu item.
    *   `type`: The type of the popup menu item.
    *   `state`: The state of the popup menu item.
    *   `helpID`: The identifier used for `WM_HELP` processing.
    *   `popupBody`: Contains `MENUITEM` and `POPUP` statements for the submenu.

### MESSAGETABLE

Defines the ID and file of an application's message table resource. Message tables are special string resources used in event logging and with the `FormatMessage` function.

**Syntax**

```rc
nameID MESSAGETABLE filename
```

**Parameters**

*   `nameID`: Unique name or a 16-bit unsigned integer value identifying the resource.
*   `filename`: Name of the file that contains the resource. The name must be a valid file name; it must be a full path if the file is not in the current working directory.

**Example**

```rc
1  MESSAGETABLE MSG00409.bin
```

### POPUP

Defines a menu item that can contain menu items and submenus. This statement is used within a `MENU` or `MENUEX` block.

**Syntax**

```rc
POPUP text, [optionlist] {
    item-definitions
    ...
}
```

**Parameters**

*   `text`: A string that contains the name of the menu.
*   `optionlist`: (Optional) One or more of the following options:
    *   `CHECKED`: The menu item has a check mark next to it.
    *   `GRAYED`: The menu item is initially inactive.
    *   `HELP`: Identifies a help item, placing it at the rightmost position.
    *   `INACTIVE`: The menu item is displayed but cannot be selected.
    *   `MENUBARBREAK`: For pop-up menus, separates the new column from the old column with a vertical line.
    *   `MENUBREAK`: Places the menu item in a new column.
*   `item-definitions`: Defines the menu items within the popup. See `MENUITEM` and `POPUP`.

**Example**

```rc
chem MENU
{
    POPUP "&Elements"
    {
         MENUITEM "&Oxygen", 200
         MENUITEM "&Carbon", 201, CHECKED
         MENUITEM "&Hydrogen", 202
         MENUITEM SEPARATOR
         MENUITEM "&Sulfur", 203
         MENUITEM "Ch&lorine", 204
    }
    POPUP "&Compounds"
    {
         POPUP "&Sugars"
         {
            MENUITEM "&Glucose", 301
            MENUITEM "&Sucrose", 302, CHECKED
            MENUITEM "&Lactose", 303, MENUBREAK
            MENUITEM "&Fructose", 304
         }
         POPUP "&Acids"
         {
              "&Hydrochloric", 401
              "&Sulfuric", 402
         }
    }
}
```

### PLUGPLAY

Obsolete.

### RCDATA

Defines a raw data resource for an application. Raw data resources permit the inclusion of binary data directly in the executable file.

**Syntax**

```rc
nameID RCDATA [optional-statements] {
    raw-data
    ...
}
```

**Parameters**

*   `nameID`: Unique name or a 16-bit unsigned integer value that identifies the resource.
*   `optional-statements`: Zero or more of the following:
    *   `CHARACTERISTICS dword`: User-defined information.
    *   `LANGUAGE language, sublanguage`: The language for the resource.
    *   `VERSION dword`: User-defined version number.
*   `raw-data`: Raw data consisting of one or more integers (decimal, octal, or hexadecimal) or strings. Integers are stored as `WORD` values unless suffixed with `L` (for `DWORD`). Strings are not null-terminated by default.

**Example**

```rc
resname RCDATA
{
   "Here is an ANSI string\0",    // explicitly null-terminated
   L"Here is a Unicode string\0", // explicitly null-terminated
   1024,                          // integer, stored as WORD
   7L,                            // integer, stored as DWORD
   0x029a,                        // hex integer
   0o733,                         // octal integer
}
```

### STRINGTABLE

Defines one or more string resources for an application. String resources are null-terminated Unicode or ASCII strings that can be loaded from the executable file.

**Syntax**

```rc
STRINGTABLE [optional-statements] {
    stringID string
    ...
}
```
or
```rc
STRINGTABLE [optional-statements]
BEGIN
    stringID string
    ...
END
```

**Parameters**

*   `optional-statements`: Zero or more of the following:
    *   `CHARACTERISTICS dword`: User-defined information.
    *   `LANGUAGE language, sublanguage`: The language for the resource.
    *   `VERSION dword`: User-defined version number.
*   `stringID`: An unsigned 16-bit integer that identifies the resource.
*   `string`: One or more strings, enclosed in quotation marks.

**Example**

```rc
#define IDS_HELLO    1
#define IDS_GOODBYE  2

STRINGTABLE
{
    IDS_HELLO,   "Hello"
    IDS_GOODBYE, "Goodbye"
}

STRINGTABLE
BEGIN
    IDS_CHINESESTRING L"\x5e2e\x52a9"
    IDS_RUSSIANSTRING L"\x0421\x043f\x0440\x0430\x0432\x043a\x0430"
    IDS_ARABICSTRING L"\x062a\x0639\x0644\x064a\x0645\x0627\x062a"
END
```

### TEXTINCLUDE

A special resource that is interpreted by Visual C++.

### TYPELIB

A special resource that is used with the /TLBID and /TLBOUT linker options.

### User-Defined Resource

Defines a resource that contains application-specific data. The data can have any format and can be defined either as the content of a given file or as a series of numbers and strings.

**Syntax**

```rc
nameID typeID filename
```
or
```rc
nameID typeID {
    raw-data
}
```

**Parameters**

*   `nameID`: Unique name or a 16-bit unsigned integer that identifies the resource.
*   `typeID`: Unique name or a 16-bit unsigned integer that identifies the resource type. If a number is given, it must be greater than 255.
*   `filename`: Name of the file that contains the resource data.
*   `raw-data`: Raw data consisting of one or more integers or strings.

**Example**

```rc
array   MYRES   data.res
14      300     custom.res
18 MYRES2
{
   "Here is an ANSI string\0",    // explicitly null-terminated
   L"Here is a Unicode string\0", // explicitly null-terminated
   1024,                          // integer, stored as WORD
   7L,                            // integer, stored as DWORD
   0x029a,                        // hex integer
   0o733,                         // octal integer
}
```

### VERSIONINFO

Defines a version-information resource. The resource contains information about the file such as its version number, its intended operating system, and its original filename.

**Syntax**

```rc
versionID VERSIONINFO fixed-info {
    block-statement
    ...
}
```
or
```rc
versionID VERSIONINFO
fixed-info
BEGIN
    block-statement
    ...
END
```

**Parameters**

*   `versionID`: The version-information resource identifier. This value must be 1.
*   `fixed-info`: Version information, such as the file version and the intended operating system. This consists of the following statements:
    *   `FILEVERSION version`: Binary version number for the file.
    *   `PRODUCTVERSION version`: Binary version number for the product.
    *   `FILEFLAGSMASK fileflagsmask`: Indicates which bits in `FILEFLAGS` are valid.
    *   `FILEFLAGS fileflags`: Attributes of the file.
    *   `FILEOS fileos`: The operating system for which this file was designed.
    *   `FILETYPE filetype`: The general type of file.
    *   `FILESUBTYPE subtype`: The function of the file.
*   `block-statement`: Specifies one or more version-information blocks (`StringFileInfo` or `VarFileInfo`).

**Example**

```rc
#define VER_FILEVERSION             3,10,349,0
#define VER_FILEVERSION_STR         "3.10.349.0\0"

#define VER_PRODUCTVERSION          3,10,0,0
#define VER_PRODUCTVERSION_STR      "3.10\0"

#ifndef DEBUG
#define VER_DEBUG                   0
#else
#define VER_DEBUG                   VS_FF_DEBUG
#endif

VS_VERSION_INFO VERSIONINFO
FILEVERSION     VER_FILEVERSION
PRODUCTVERSION  VER_PRODUCTVERSION
FILEFLAGSMASK   VS_FFI_FILEFLAGSMASK
FILEFLAGS       (VER_PRIVATEBUILD|VER_PRERELEASE|VER_DEBUG)
FILEOS          VOS__WINDOWS32
FILETYPE        VFT_DLL
FILESUBTYPE     VFT2_UNKNOWN
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904E4"
        BEGIN
            VALUE "CompanyName",      VER_COMPANYNAME_STR
            VALUE "FileDescription",  VER_FILEDESCRIPTION_STR
            VALUE "FileVersion",      VER_FILEVERSION_STR
            VALUE "InternalName",     VER_INTERNALNAME_STR
            VALUE "LegalCopyright",   VER_LEGALCOPYRIGHT_STR
            VALUE "OriginalFilename", VER_ORIGINALFILENAME_STR
            VALUE "ProductName",      VER_PRODUCTNAME_STR
            VALUE "ProductVersion",   VER_PRODUCTVERSION_STR
        END
    END

    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1252
    END
END
```

### VXD

Obsolete.

## Controls

### AUTO3STATE

Defines an automatic three-state check box. The control is an open box with the given text positioned to the right of the box. When chosen, the box automatically advances between three states: checked, unchecked, and disabled (grayed).

**Syntax**

```rc
AUTO3STATE text, id, x, y, width, height [, style [, extended-style]]
```

**Parameters**

*   `text`: The text to be displayed to the right of the check box.
*   `id`: The control's identifier.
*   `x, y, width, height`: The position and dimensions of the control.
*   `style`: (Optional) The control's styles. This can be a combination of `BS_AUTO3STATE` and `WS_TABSTOP`, `WS_DISABLED`, `WS_GROUP`. The default is `BS_AUTO3STATE | WS_TABSTOP`.
*   `extended-style`: (Optional) The control's extended styles.

### STATE3

Defines a three-state check box control. The control is identical to a `CHECKBOX`, except that it has three states: checked, unchecked, and disabled (grayed).

**Syntax**

```rc
STATE3 text, id, x, y, width, height [, style [, extended-style]]
```

**Parameters**

*   `text`: The text to be displayed to the right of the control.
*   `id`: The control's identifier.
*   `x, y, width, height`: The position and dimensions of the control.
*   `style`: (Optional) The control's styles. This can be a combination of `BS_3STATE` and `WS_TABSTOP`, `WS_GROUP`. The default is `BS_3STATE | WS_TABSTOP`.
*   `extended-style`: (Optional) The control's extended styles.

### SCROLLBAR

Defines a scroll-bar control. The control is a rectangle that contains a scroll box and has direction arrows at both ends.

**Syntax**

```rc
SCROLLBAR id, x, y, width, height [, style [, extended-style]]
```

**Parameters**

*   `id`: The control's identifier.
*   `x, y, width, height`: The position and dimensions of the control.
*   `style`: (Optional) The control's styles. This can be a combination of the `SCROLLBAR` class styles and `WS_TABSTOP`, `WS_GROUP`, `WS_DISABLED`. The default is `SBS_HORZ`.
*   `extended-style`: (Optional) The control's extended styles.

**Example**

```rc
#define IDC_SCROLLBARV                  1010

SCROLLBAR IDC_SCROLLBARV, 7, 55, 187, 44, SBS_VERT
```

### RTEXT

Defines a right-aligned text control. The control is a simple rectangle displaying the given text right-aligned in the rectangle.

**Syntax**

```rc
RTEXT text, id, x, y, width, height [, style [, extended-style]]
```

**Parameters**

*   `text`: The text to be displayed in the control.
*   `id`: The control's identifier.
*   `x, y, width, height`: The position and dimensions of the control.
*   `style`: (Optional) The control's styles. This can be any combination of `WS_TABSTOP` and `WS_GROUP`. The default is `SS_RIGHT | WS_GROUP`.
*   `extended-style`: (Optional) The control's extended styles.

**Example**

```rc
RTEXT "Number of Messages", 4, 30, 50, 100, 10
```

### RADIOBUTTON

Defines a radio-button control. The control is a small circle that has the given text displayed next to it.

**Syntax**

```rc
RADIOBUTTON text, id, x, y, width, height [, style [, extended-style]]
```

**Parameters**

*   `text`: The text to be displayed to the right of the control.
*   `id`: The control's identifier.
*   `x, y, width, height`: The position and dimensions of the control.
*   `style`: (Optional) The control's styles. This can be a combination of `BS_RADIOBUTTON` and `WS_TABSTOP`, `WS_DISABLED`, `WS_GROUP`. The default is `BS_RADIOBUTTON | WS_TABSTOP`.
*   `extended-style`: (Optional) The control's extended styles.

**Example**

```rc
RADIOBUTTON "Italic", 100, 10, 10, 40, 10
```

### PUSHBUTTON

Defines a push-button control. The control is a round-cornered rectangle containing the given text. The text is centered in the control.

**Syntax**

```rc
PUSHBUTTON text, id, x, y, width, height [, style [, extended-style]]
```

**Parameters**

*   `text`: The text to be displayed in the control.
*   `id`: The control's identifier.
*   `x, y, width, height`: The position and dimensions of the control.
*   `style`: (Optional) The control's styles. This can be a combination of `BS_PUSHBUTTON` and `WS_TABSTOP`, `WS_DISABLED`, `WS_GROUP`. The default is `BS_PUSHBUTTON | WS_TABSTOP`.
*   `extended-style`: (Optional) The control's extended styles.

**Example**

```rc
PUSHBUTTON "ON", 7, 10, 10, 20, 10
```

### PUSHBOX

Defines a push-box control, which is identical to a `PUSHBUTTON`, except that it does not display a button face or frame; only the text appears.

**Syntax**

```rc
PUSHBOX text, id, x, y, width, height [, style [, extended-style]]
```

**Parameters**

*   `text`: The text to be displayed in the control.
*   `id`: The control's identifier.
*   `x, y, width, height`: The position and dimensions of the control.
*   `style`: (Optional) The control's styles. This can be a combination of `BS_PUSHBOX` and `WS_TABSTOP`, `WS_DISABLED`, `WS_GROUP`. The default is `BS_PUSHBOX | WS_TABSTOP`.
*   `extended-style`: (Optional) The control's extended styles.

### AUTOCHECKBOX

Defines an automatic check box control. The control is a small rectangle (check box) that has the specified text displayed next to it. When the user chooses the control, the control highlights the rectangle and sends a message to its parent window.

**Syntax**

```rc
AUTOCHECKBOX text, id, x, y, width, height [, style [, extended-style]]
```

**Parameters**

*   `text`: The text to be displayed to the right of the check box.
*   `id`: The control's identifier.
*   `x, y, width, height`: The position and dimensions of the control.
*   `style`: (Optional) The control's styles. This can be a combination of `BS_AUTOCHECKBOX` and `WS_TABSTOP`, `WS_GROUP`. The default is `BS_AUTOCHECKBOX | WS_TABSTOP`.
*   `extended-style`: (Optional) The control's extended styles.

### AUTORADIOBUTTON

Defines an automatic radio button control. This control automatically performs mutual exclusion with the other `AUTORADIOBUTTON` controls in the same group.

**Syntax**

```rc
AUTORADIOBUTTON text, id, x, y, width, height [, style [, extended-style]]
```

**Parameters**

*   `text`: The text that will appear next to the radio button.
*   `id`: The control's identifier.
*   `x, y, width, height`: The position and dimensions of the control.
*   `style`: (Optional) The control's styles. This can be a combination of `BS_AUTORADIOBUTTON` and `WS_TABSTOP`, `WS_DISABLED`, `WS_GROUP`. The default is `BS_AUTORADIOBUTTON | WS_TABSTOP`.
*   `extended-style`: (Optional) The control's extended styles.

### LTEXT

Defines a left-aligned text control. The control is a simple rectangle displaying the given text left-aligned in the rectangle.

**Syntax**

```rc
LTEXT text, id, x, y, width, height [, style [, extended-style]]
```

**Parameters**

*   `text`: The text to be displayed in the control.
*   `id`: The control's identifier.
*   `x, y, width, height`: The position and dimensions of the control.
*   `style`: (Optional) The control's styles. This can be any combination of `SS_LEFT`, `WS_TABSTOP`, and `WS_GROUP`. The default is `SS_LEFT | WS_GROUP`.
*   `extended-style`: (Optional) The control's extended styles.

**Example**

```rc
LTEXT "Filename", 101, 10, 10, 100, 100
```

## Statements

### CAPTION

Defines the title for a dialog box. The title appears in the box's caption bar (if it has one).

**Syntax**

```rc
CAPTION "captiontext"
```

**Parameters**

*   `captiontext`: A character string enclosed in double quotation marks.

**Example**

```rc
CAPTION "Error!"
```

### CHARACTERISTICS

Defines information about a resource that can be used by tools that read and write resource-definition files.

**Syntax**

```rc
CHARACTERISTICS dword
```

**Parameters**

*   `dword`: A user-defined `DWORD` value.

### EXSTYLE

Defines extended window styles for a dialog box.

**Syntax**

```rc
EXSTYLE extended-style
```

**Parameters**

*   `extended-style`: The extended window style for the dialog box or control.

### FONT

Defines the font with which the system will draw text in the dialog box.

**Syntax**

```rc
FONT pointsize, "typeface", weight, italic, charset
```

**Parameters**

*   `pointsize`: The size of the font, in points.
*   `typeface`: The name of the typeface, enclosed in quotes.
*   `weight`: The weight of the font in the range 0 through 1000.
*   `italic`: `TRUE` for an italic font, `FALSE` otherwise.
*   `charset`: The character set.

**Example**

```rc
FONT 12, "MS Shell Dlg"
```

### LANGUAGE

Defines the language for all resources up to the next `LANGUAGE` statement or to the end of the file.

**Syntax**

```rc
LANGUAGE language, sublanguage
```

**Parameters**

*   `language`: The language identifier.
*   `sublanguage`: The sublanguage identifier.

### VERSION

Defines version information about a resource that can be used by tools that read and write resource files.

**Syntax**

```rc
VERSION dword
```

**Parameters**

*   `dword`: A user-defined `DWORD` value.

### STYLE

Defines the window style of the dialog box.

**Syntax**

```rc
STYLE style
```

**Parameters**

*   `style`: The window style. This can be a combination of window style values (such as `WS_CAPTION`) and dialog box style values (such as `DS_CENTER`).

### MENU

Defines the menu for a dialog box.

**Syntax**

```rc
MENU menuname
```

**Parameters**

*   `menuname`: The name or identifier of the menu to be used.

**Example**

```rc
MENU errmenu
```

### MENUITEM

Defines a menu item.

**Syntax**

```rc
MENUITEM text, result, [optionlist]
MENUITEM SEPARATOR
```

**Parameters**

*   `text`: The name of the menu item.
*   `result`: A number that specifies the result generated when the user selects the menu item.
*   `optionlist`: (Optional) The appearance of the menu item. This can be one or more of the following:
    *   `CHECKED`: The menu item has a check mark next to it.
    *   `GRAYED`: The menu item is initially inactive.
    *   `HELP`: Identifies a help item.
    *   `INACTIVE`: The menu item is displayed but cannot be selected.
    *   `MENUBARBREAK`: Same as `MENUBREAK` except that for pop-up menus, it separates the new column from the old column with a vertical line.
    *   `MENUBREAK`: Places the menu item on a new line.

**Example**

```rc
MENUITEM "&Roman", 206, CHECKED, GRAYED
MENUITEM SEPARATOR
MENUITEM "&Blackletter", 301
```

### CLASS

Defines the class of the dialog box.

**Syntax**

```rc
CLASS class
```

**Parameters**

*   `class`: A 16-bit unsigned integer or a string, enclosed in double quotation marks, that identifies the class of the dialog box.

**Example**

```rc
CLASS "myclass"
```

### COMBOBOX

Defines a combination box control (a combo box). A combo box consists of either a static text box or an edit box combined with a list box.

**Syntax**

```rc
COMBOBOX id, x, y, width, height [, style [, extended-style]]
```

**Parameters**

*   `id`: The control's identifier.
*   `x, y, width, height`: The position and dimensions of the control.
*   `style`: (Optional) The control's styles. This can be a combination of the `COMBOBOX` class styles and `WS_TABSTOP`, `WS_GROUP`, `WS_VSCROLL`, `WS_DISABLED`. The default is `CBS_SIMPLE | WS_TABSTOP`.
*   `extended-style`: (Optional) The control's extended styles.

**Example**

```rc
COMBOBOX 777, 10, 10, 50, 54, CBS_SIMPLE | WS_VSCROLL | WS_TABSTOP
```

### CONTROL

Defines a user-defined control.

**Syntax**

```rc
CONTROL text, id, class, style, x, y, width, height [, extended-style]
```

**Parameters**

*   `text`: The text to be displayed for the control.
*   `id`: The control's identifier.
*   `class`: The control's class. This can be one of the predefined system classes (`BUTTON`, `COMBOBOX`, `EDIT`, `LISTBOX`, `SCROLLBAR`, `STATIC`) or a custom class.
*   `style`: The control's styles.
*   `x, y, width, height`: The position and dimensions of the control.
*   `extended-style`: (Optional) The control's extended styles.

### CTEXT

Defines a centered-text control. The control is a simple rectangle displaying the given text centered in the rectangle.

**Syntax**

```rc
CTEXT text, id, x, y, width, height [, style [, extended-style]]
```

**Parameters**

*   `text`: The text to be centered in the rectangular area of the control.
*   `id`: The control's identifier.
*   `x, y, width, height`: The position and dimensions of the control.
*   `style`: (Optional) The control's styles. This can be any combination of `SS_CENTER`, `WS_TABSTOP`, and `WS_GROUP`. The default is `SS_CENTER | WS_GROUP`.
*   `extended-style`: (Optional) The control's extended styles.

**Example**

```rc
CTEXT "Filename", 101, 10, 10, 100, 100
```

### DEFPUSHBUTTON

Defines a default push-button control. The control is a small rectangle with a bold outline that represents the default response for the user. The given text is displayed inside the button.

**Syntax**

```rc
DEFPUSHBUTTON text, id, x, y, width, height [, style [, extended-style]]
```

**Parameters**

*   `text`: The text to be centered in the rectangular area of the control.
*   `id`: The control's identifier.
*   `x, y, width, height`: The position and dimensions of the control.
*   `style`: (Optional) The control's styles. This can be a combination of `BS_DEFPUSHBUTTON`, `WS_TABSTOP`, `WS_GROUP`, and `WS_DISABLED`. The default is `BS_DEFPUSHBUTTON | WS_TABSTOP`.
*   `extended-style`: (Optional) The control's extended styles.

**Example**

```rc
DEFPUSHBUTTON "Cancel", 101, 10, 10, 24, 50
```

### EDITTEXT

Defines an edit control. It creates a rectangular region in which the user can type and edit text.

**Syntax**

```rc
EDITTEXT id, x, y, width, height [, style [, extended-style]]
```

**Parameters**

*   `id`: The control's identifier.
*   `x, y, width, height`: The position and dimensions of the control.
*   `style`: (Optional) The control's styles. This can be a combination of the `EDIT` class styles and `WS_TABSTOP`, `WS_GROUP`, `WS_VSCROLL`, `WS_HSCROLL`, `WS_DISABLED`. The default is `ES_LEFT | WS_BORDER | WS_TABSTOP`.
*   `extended-style`: (Optional) The control's extended styles.

**Example**

```rc
EDITTEXT  3, 10, 10, 100, 10
```

### GROUPBOX

Defines a group box control. The control is a rectangle that groups other controls together. The controls are grouped by drawing a border around them and displaying the given text in the upper-left corner.

**Syntax**

```rc
GROUPBOX text, id, x, y, width, height [, style [, extended-style]]
```

**Parameters**

*   `text`: The text to be displayed in the upper-left corner of the group box.
*   `id`: The control's identifier.
*   `x, y, width, height`: The position and dimensions of the control.
*   `style`: (Optional) The control's styles. This can be a combination of `BS_GROUPBOX` and `WS_TABSTOP`, `WS_DISABLED`. The default is `BS_GROUPBOX`.
*   `extended-style`: (Optional) The control's extended styles.

**Example**

```rc
GROUPBOX "Options", 101, 10, 10, 100, 100
```

### ICON

Defines an icon control. This control is an icon displayed in a dialog box.

**Syntax**

```rc
ICON text, id, x, y [, width, height, style [, extended-style]]
```

**Parameters**

*   `text`: The name of an icon (not a file name) defined elsewhere in the resource file.
*   `id`: The control's identifier.
*   `x, y`: The position of the control.
*   `width, height`: These values are ignored and should be set to zero.
*   `style`: (Optional) The control's style. The only value that can be specified is `SS_ICON`.
*   `extended-style`: (Optional) The control's extended styles.

**Example**

```rc
ICON "myicon", 901, 30, 30
```

### LISTBOX

Defines a list box control. The control is a rectangle containing a list of strings from which the user can select.

**Syntax**

```rc
LISTBOX id, x, y, width, height [, style [, extended-style]]
```

**Parameters**

*   `id`: The control's identifier.
*   `x, y, width, height`: The position and dimensions of the control.
*   `style`: (Optional) The control's styles. This can be a combination of the `LISTBOX` class styles and `WS_BORDER`, `WS_VSCROLL`. The default is `LBS_NOTIFY | WS_BORDER`.
*   `extended-style`: (Optional) The control's extended styles.

**Example**

```rc
LISTBOX 101, 10, 10, 100, 100
```

### LTEXT

Defines a left-aligned text control. The control is a simple rectangle displaying the given text left-aligned in the rectangle.

**Syntax**

```rc
LTEXT text, id, x, y, width, height [, style [, extended-style]]
```

**Parameters**

*   `text`: The text to be displayed in the control.
*   `id`: The control's identifier.
*   `x, y, width, height`: The position and dimensions of the control.
*   `style`: (Optional) The control's styles. This can be any combination of `SS_LEFT`, `WS_TABSTOP`, and `WS_GROUP`. The default is `SS_LEFT | WS_GROUP`.
*   `extended-style`: (Optional) The control's extended styles.

**Example**

```rc
LTEXT "Filename", 101, 10, 10, 100, 100
```
