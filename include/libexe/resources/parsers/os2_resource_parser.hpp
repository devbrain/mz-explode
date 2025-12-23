// libexe - Modern executable file analysis library
// Copyright (c) 2024
//
// OS/2 Presentation Manager resource parsers

#ifndef LIBEXE_RESOURCES_PARSERS_OS2_RESOURCE_PARSER_HPP
#define LIBEXE_RESOURCES_PARSERS_OS2_RESOURCE_PARSER_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <optional>

// Disable MSVC warning C4251: 'member': class 'std::...' needs to have dll-interface
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

namespace libexe {

// =============================================================================
// OS/2 Accelerator Table Parser (RT_ACCELTABLE)
// =============================================================================

/// Parsed OS/2 accelerator entry
struct os2_accel_entry {
    uint16_t flags;     ///< AF_* flags (AF_CHAR, AF_VIRTUALKEY, AF_SHIFT, etc.)
    uint16_t key;       ///< Key code (virtual key or character)
    uint16_t cmd;       ///< Command ID

    // Flag helpers
    [[nodiscard]] bool is_char() const { return (flags & 0x0001) != 0; }
    [[nodiscard]] bool is_virtual_key() const { return (flags & 0x0002) != 0; }
    [[nodiscard]] bool is_scancode() const { return (flags & 0x0004) != 0; }
    [[nodiscard]] bool requires_shift() const { return (flags & 0x0008) != 0; }
    [[nodiscard]] bool requires_control() const { return (flags & 0x0010) != 0; }
    [[nodiscard]] bool requires_alt() const { return (flags & 0x0020) != 0; }
    [[nodiscard]] bool is_lone_key() const { return (flags & 0x0040) != 0; }
    [[nodiscard]] bool is_syscommand() const { return (flags & 0x0100) != 0; }
    [[nodiscard]] bool is_help() const { return (flags & 0x0200) != 0; }
};

/// Parsed OS/2 accelerator table
struct os2_accel_table {
    uint16_t codepage;                      ///< Code page for key codes
    std::vector<os2_accel_entry> entries;   ///< Accelerator entries
};

/// Parse OS/2 accelerator table resource
LIBEXE_EXPORT std::optional<os2_accel_table> parse_os2_accel_table(
    std::span<const uint8_t> data);

// =============================================================================
// OS/2 Dialog Parser (RT_DIALOG)
// =============================================================================

/// Parsed OS/2 dialog item (control)
struct os2_dialog_item {
    uint16_t status;            ///< Item status flags
    uint16_t children;          ///< Number of child items
    std::string class_name;     ///< Control class name
    std::string text;           ///< Control text
    uint32_t style;             ///< Window style flags
    int16_t x, y, cx, cy;       ///< Position and size
    uint16_t id;                ///< Control ID
    std::vector<uint8_t> pres_params;   ///< Presentation parameters
    std::vector<uint8_t> ctl_data;      ///< Control data
};

/// Parsed OS/2 dialog template
struct os2_dialog_template {
    uint16_t type;              ///< Template format type
    uint16_t codepage;          ///< Code page for strings
    uint16_t status;            ///< Template status flags
    uint16_t focus_item;        ///< Index of item to receive focus
    std::vector<os2_dialog_item> items; ///< Dialog items
};

/// Parse OS/2 dialog resource
LIBEXE_EXPORT std::optional<os2_dialog_template> parse_os2_dialog(
    std::span<const uint8_t> data);

// =============================================================================
// OS/2 Menu Parser (RT_MENU)
// =============================================================================

/// Parsed OS/2 menu item
struct os2_menu_item {
    int16_t position;           ///< Position in menu (-1 = end)
    uint16_t style;             ///< MIS_* style flags
    uint16_t attribute;         ///< MIA_* attribute flags
    uint16_t id;                ///< Menu item ID
    std::string text;           ///< Menu item text

    // Style helpers
    [[nodiscard]] bool is_separator() const { return (style & 0x0004) != 0; }
    [[nodiscard]] bool has_submenu() const { return (style & 0x0010) != 0; }
    [[nodiscard]] bool is_syscommand() const { return (style & 0x0040) != 0; }
    [[nodiscard]] bool is_help() const { return (style & 0x0080) != 0; }

    // Attribute helpers
    [[nodiscard]] bool is_checked() const { return (attribute & 0x2000) != 0; }
    [[nodiscard]] bool is_disabled() const { return (attribute & 0x4000) != 0; }
    [[nodiscard]] bool is_highlighted() const { return (attribute & 0x8000) != 0; }

    std::vector<os2_menu_item> submenu;  ///< Submenu items (if has_submenu())
};

/// Parsed OS/2 menu
struct os2_menu {
    std::vector<os2_menu_item> items;   ///< Top-level menu items
};

/// Parse OS/2 menu resource
/// Note: OS/2 menus in resources use a different binary format than MENUITEM struct
LIBEXE_EXPORT std::optional<os2_menu> parse_os2_menu(
    std::span<const uint8_t> data);

// =============================================================================
// OS/2 Bitmap/Pointer Parser (RT_BITMAP, RT_POINTER)
// =============================================================================

/// OS/2 bitmap header type
enum class os2_bitmap_type : uint16_t {
    ICON           = 0x4349,  // 'IC'
    BITMAP         = 0x4D42,  // 'BM'
    POINTER        = 0x5450,  // 'PT'
    COLOR_ICON     = 0x4943,  // 'CI'
    COLOR_POINTER  = 0x5043,  // 'CP'
    BITMAP_ARRAY   = 0x4142   // 'BA'
};

/// Parsed OS/2 bitmap info
struct os2_bitmap_info {
    os2_bitmap_type type;       ///< Bitmap type
    uint32_t file_size;         ///< Total file size
    int16_t hotspot_x;          ///< Hotspot X (for pointers)
    int16_t hotspot_y;          ///< Hotspot Y (for pointers)
    uint32_t bits_offset;       ///< Offset to bitmap bits

    // Info header fields
    uint32_t width;             ///< Width in pixels
    uint32_t height;            ///< Height in pixels
    uint16_t planes;            ///< Number of planes (1)
    uint16_t bit_count;         ///< Bits per pixel
    uint32_t compression;       ///< Compression type (BCA_*)

    // Palette (if bit_count <= 8)
    struct rgb {
        uint8_t blue, green, red;
    };
    std::vector<rgb> palette;

    // Raw bitmap bits
    std::vector<uint8_t> bits;
};

/// Parsed OS/2 bitmap array (multi-resolution)
struct os2_bitmap_array {
    std::vector<os2_bitmap_info> bitmaps;   ///< Individual bitmaps
};

/// Parse OS/2 bitmap resource
LIBEXE_EXPORT std::optional<os2_bitmap_info> parse_os2_bitmap(
    std::span<const uint8_t> data);

/// Parse OS/2 bitmap array resource
LIBEXE_EXPORT std::optional<os2_bitmap_array> parse_os2_bitmap_array(
    std::span<const uint8_t> data);

// =============================================================================
// OS/2 GPI Font Parser (RT_FONT, RT_FONTDIR)
// =============================================================================

/// Parsed OS/2 GPI font metrics
struct os2_font_metrics {
    std::string family_name;    ///< Font family name
    std::string face_name;      ///< Font face name
    int16_t registry_id;
    int16_t codepage;           ///< Font encoding (850 = PMUGL)
    int16_t em_height;
    int16_t x_height;
    int16_t max_ascender;
    int16_t max_descender;
    int16_t internal_leading;
    int16_t external_leading;
    int16_t ave_char_width;
    int16_t max_char_inc;
    int16_t em_inc;
    uint16_t weight_class;      ///< 1000-9000
    uint16_t width_class;       ///< 1000-9000
    int16_t device_res_x;       ///< Target X resolution (dpi)
    int16_t device_res_y;       ///< Target Y resolution (dpi)
    int16_t first_char;
    int16_t last_char;
    int16_t default_char;
    int16_t break_char;
    int16_t nominal_point_size; ///< Point size * 10
    uint8_t panose[12];         ///< PANOSE data
};

/// Parsed character definition
struct os2_char_def {
    uint32_t bitmap_offset;     ///< Offset to glyph bitmap
    uint16_t width;             ///< Glyph width (type 1/2)
    int16_t a_space;            ///< Leading space (type 3)
    int16_t b_space;            ///< Glyph width (type 3)
    int16_t c_space;            ///< Trailing space (type 3)
};

/// Parsed OS/2 GPI font
struct os2_font {
    std::string signature;      ///< "OS/2 FONT" or "OS/2 FONT 2"
    os2_font_metrics metrics;
    int16_t font_type;          ///< 1=fixed, 2=proportional, 3=ABC
    int16_t cell_height;
    int16_t baseline_offset;
    std::vector<os2_char_def> characters;
    std::vector<uint8_t> bitmap_data;   ///< Raw glyph bitmaps
};

/// Parse OS/2 GPI font resource
LIBEXE_EXPORT std::optional<os2_font> parse_os2_font(
    std::span<const uint8_t> data);

/// Parsed OS/2 font directory entry
struct os2_font_dir_entry {
    uint16_t resource_id;       ///< Resource ID of the font
    os2_font_metrics metrics;   ///< Font metrics
};

/// Parse OS/2 font directory resource
LIBEXE_EXPORT std::vector<os2_font_dir_entry> parse_os2_font_directory(
    std::span<const uint8_t> data);

// =============================================================================
// OS/2 String Table Parser (RT_STRING)
// =============================================================================

/// Parse OS/2 string table resource
/// Returns vector of strings (empty strings for missing IDs)
LIBEXE_EXPORT std::vector<std::string> parse_os2_string_table(
    std::span<const uint8_t> data);

} // namespace libexe

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // LIBEXE_RESOURCES_PARSERS_OS2_RESOURCE_PARSER_HPP
