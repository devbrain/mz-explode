// libexe - Modern executable file analysis library
// Copyright (c) 2024

/**
 * @file le_file.hpp
 * @brief LE/LX (Linear Executable) file parser for DOS extenders and OS/2.
 *
 * This header provides the le_file class for parsing and analyzing LE and LX
 * format executables. These formats are used by:
 * - DOS extenders (DOS/4GW, DOS/32A, PMODE/W, CauseWay)
 * - Windows VxD (Virtual Device Drivers)
 * - OS/2 2.x and later applications
 *
 * @par Format Variants:
 * - **LE (Linear Executable)**: Original format, used by DOS extenders and VxDs
 * - **LX (Linear eXecutable)**: Extended format used by OS/2 2.x+
 *
 * @par Structure Overview:
 * - Optional MZ DOS stub (for "bound" executables)
 * - LE/LX header with format signature ("LE" or "LX")
 * - Object (segment) table
 * - Page table (memory pages mapped to file)
 * - Fixup tables (relocations)
 * - Entry table (exported functions)
 * - Import tables (module and procedure names)
 * - Resource table
 *
 * @see mz_file, pe_file, executable_factory
 */

#ifndef LIBEXE_FORMATS_LE_FILE_HPP
#define LIBEXE_FORMATS_LE_FILE_HPP

#include <libexe/export.hpp>
#include <libexe/core/executable_file.hpp>
#include <libexe/core/diagnostic_collector.hpp>
#include <libexe/le/types.hpp>
#include <filesystem>
#include <vector>
#include <span>
#include <string>
#include <optional>
#include <memory>

namespace libexe {

/**
 * @brief LE/LX object (segment) information.
 *
 * Objects in LE/LX are similar to sections in PE - they define memory
 * regions with specific attributes (readable, writable, executable).
 */
struct le_object {
    uint32_t index;              ///< 1-based object number
    uint32_t virtual_size;       ///< Size in memory
    uint32_t base_address;       ///< Preferred load address
    uint32_t flags;              ///< Object flags
    uint32_t page_table_index;   ///< First page in page table (1-based)
    uint32_t page_count;         ///< Number of page entries

    /// @brief Check if object is readable.
    [[nodiscard]] bool is_readable() const { return (flags & 0x0001) != 0; }

    /// @brief Check if object is writable.
    [[nodiscard]] bool is_writable() const { return (flags & 0x0002) != 0; }

    /// @brief Check if object is executable.
    [[nodiscard]] bool is_executable() const { return (flags & 0x0004) != 0; }

    /// @brief Check if object contains resources.
    [[nodiscard]] bool is_resource() const { return (flags & 0x0008) != 0; }

    /// @brief Check if object is discardable (can be unloaded).
    [[nodiscard]] bool is_discardable() const { return (flags & 0x0010) != 0; }

    /// @brief Check if object is shared between processes.
    [[nodiscard]] bool is_shared() const { return (flags & 0x0020) != 0; }

    /// @brief Check if object should be preloaded.
    [[nodiscard]] bool is_preload() const { return (flags & 0x0040) != 0; }

    /// @brief Check if object uses 32-bit addressing (BIG flag).
    [[nodiscard]] bool is_32bit() const { return (flags & 0x2000) != 0; }
};

/**
 * @brief Page table entry (unified for LE and LX formats).
 *
 * Each page represents a fixed-size memory block (typically 4KB).
 * Pages can be legal (present), iterated (run-length encoded),
 * invalid, zero-filled, or compressed.
 */
struct le_page_entry {
    uint32_t page_number;        ///< Page number in object (1-based for display)
    uint32_t file_offset;        ///< Actual file offset to page data
    uint16_t data_size;          ///< Actual size in file (LX only)
    uint16_t flags;              ///< Page flags

    /// @brief Check if page is legal (present with data).
    [[nodiscard]] bool is_legal() const { return flags == 0x0000; }

    /// @brief Check if page is iterated (run-length encoded).
    [[nodiscard]] bool is_iterated() const { return flags == 0x0001; }

    /// @brief Check if page is invalid (not present).
    [[nodiscard]] bool is_invalid() const { return flags == 0x0002; }

    /// @brief Check if page is zero-filled (no file data).
    [[nodiscard]] bool is_zerofill() const { return flags == 0x0003; }

    /// @brief Check if page is compressed.
    [[nodiscard]] bool is_compressed() const { return flags == 0x0005; }
};

/**
 * @brief Resident/Non-resident name table entry.
 *
 * Names exported by the module for linking purposes.
 */
struct le_name_entry {
    std::string name;            ///< Name string
    uint16_t ordinal;            ///< Entry ordinal
};

/**
 * @brief Resource table entry.
 *
 * Resources embedded in LE/LX executables (OS/2 format).
 */
struct le_resource {
    uint16_t type_id;            ///< Resource type ID (see OS/2 resource types)
    uint16_t name_id;            ///< Resource name ID
    uint32_t size;               ///< Resource size in bytes
    uint16_t object;             ///< Object number containing resource (1-based)
    uint32_t offset;             ///< Offset within object

    // Standard OS/2 resource type constants
    static constexpr uint16_t RT_POINTER    = 1;   ///< Mouse pointer
    static constexpr uint16_t RT_BITMAP     = 2;   ///< Bitmap
    static constexpr uint16_t RT_MENU       = 3;   ///< Menu template
    static constexpr uint16_t RT_DIALOG     = 4;   ///< Dialog template
    static constexpr uint16_t RT_STRING     = 5;   ///< String table
    static constexpr uint16_t RT_FONTDIR    = 6;   ///< Font directory
    static constexpr uint16_t RT_FONT       = 7;   ///< Font
    static constexpr uint16_t RT_ACCELTABLE = 8;   ///< Accelerator table
    static constexpr uint16_t RT_RCDATA     = 9;   ///< Binary data
    static constexpr uint16_t RT_MESSAGE    = 10;  ///< Error message table
    static constexpr uint16_t RT_DLGINCLUDE = 11;  ///< Dialog include file name
    static constexpr uint16_t RT_VKEYTBL    = 12;  ///< Virtual key table
    static constexpr uint16_t RT_KEYTBL     = 13;  ///< Key table
    static constexpr uint16_t RT_CHARTBL    = 14;  ///< Char table
    static constexpr uint16_t RT_DISPLAYINFO= 15;  ///< Display info
    static constexpr uint16_t RT_FKASHORT   = 16;  ///< FKA short
    static constexpr uint16_t RT_FKALONG    = 17;  ///< FKA long
    static constexpr uint16_t RT_HELPTABLE  = 18;  ///< Help table
    static constexpr uint16_t RT_HELPSUBTABLE = 19;///< Help subtable
    static constexpr uint16_t RT_FDDIR      = 20;  ///< Font directory (alternate)
    static constexpr uint16_t RT_FD         = 21;  ///< Font
};

/**
 * @brief Entry table entry type.
 */
enum class le_entry_type : uint8_t {
    UNUSED    = 0x00,     ///< Empty/skip (used to skip ordinal numbers)
    ENTRY_16  = 0x01,     ///< 16-bit entry point
    GATE_286  = 0x02,     ///< 286 call gate entry
    ENTRY_32  = 0x03,     ///< 32-bit entry point
    FORWARDER = 0x04      ///< Forwarder entry (import)
};

/**
 * @brief Fixup source type (what kind of value needs patching).
 */
enum class le_fixup_source_type : uint8_t {
    BYTE           = 0x00,   ///< 8-bit byte
    SELECTOR_16    = 0x02,   ///< 16-bit selector
    POINTER_16_16  = 0x03,   ///< 16:16 far pointer
    OFFSET_16      = 0x05,   ///< 16-bit offset
    POINTER_16_32  = 0x06,   ///< 16:32 far pointer
    OFFSET_32      = 0x07,   ///< 32-bit offset
    RELATIVE_32    = 0x08    ///< 32-bit self-relative offset
};

/**
 * @brief Fixup target type (what the fixup points to).
 */
enum class le_fixup_target_type : uint8_t {
    INTERNAL        = 0x00,  ///< Internal reference (object + offset)
    IMPORT_ORDINAL  = 0x01,  ///< Import by ordinal
    IMPORT_NAME     = 0x02,  ///< Import by name
    INTERNAL_ENTRY  = 0x03   ///< Internal entry table reference
};

/**
 * @brief Fixup record.
 *
 * Describes a location that needs patching at load time.
 */
struct le_fixup {
    uint32_t page_index;             ///< Page this fixup applies to (1-based)
    uint16_t source_offset;          ///< Offset within page where fixup is applied
    le_fixup_source_type source_type; ///< Type of fixup
    le_fixup_target_type target_type; ///< Target type

    // Target info (depends on target_type)
    uint16_t target_object;          ///< Target object (INTERNAL)
    uint32_t target_offset;          ///< Target offset
    uint16_t module_ordinal;         ///< Import module ordinal (IMPORT_*)
    uint32_t import_ordinal;         ///< Import ordinal (IMPORT_ORDINAL)

    // Flags
    bool is_alias;                   ///< Alias (16:16 pointer)
    bool is_additive;                ///< Additive fixup (add value instead of replace)
    int32_t additive_value;          ///< Additive value if is_additive
};

/**
 * @brief Entry point information.
 */
struct le_entry {
    uint16_t ordinal;            ///< Entry ordinal (1-based)
    le_entry_type type;          ///< Entry type
    uint16_t object;             ///< Object number containing entry (1-based)
    uint32_t offset;             ///< Offset within object
    uint8_t flags;               ///< Entry flags
    uint16_t callgate;           ///< Call gate selector (286 gate only)
    uint16_t module_ordinal;     ///< Module ordinal for forwarder
    uint32_t import_ordinal;     ///< Import ordinal for forwarder

    /// @brief Check if entry is exported.
    [[nodiscard]] bool is_exported() const { return (flags & 0x01) != 0; }

    /// @brief Check if entry uses shared data segment.
    [[nodiscard]] bool is_shared_data() const { return (flags & 0x02) != 0; }

    /// @brief Get number of parameters (for call gates).
    [[nodiscard]] uint8_t param_count() const { return (flags >> 3) & 0x1F; }
};

/**
 * @brief LE/LX (Linear Executable) file parser.
 *
 * Parses LE and LX format executables used by DOS extenders (DOS/4GW,
 * DOS/32A, PMODE/W), Windows VxDs, and OS/2 applications.
 *
 * @par DOS Extender Detection:
 * The parser can detect common DOS extenders:
 * - DOS/4GW (Watcom)
 * - DOS/32A
 * - PMODE/W
 * - CauseWay
 *
 * @par Example Usage:
 * @code
 * auto le = libexe::le_file::from_file("game.exe");
 *
 * if (le.is_bound()) {
 *     std::cout << "DOS extender: ";
 *     switch (le.extender_type()) {
 *         case dos_extender_type::DOS4GW: std::cout << "DOS/4GW"; break;
 *         case dos_extender_type::DOS32A: std::cout << "DOS/32A"; break;
 *     }
 * }
 *
 * std::cout << "\nObjects: " << le.objects().size() << std::endl;
 * for (const auto& obj : le.objects()) {
 *     std::cout << "  Object " << obj.index << ": "
 *               << obj.virtual_size << " bytes"
 *               << (obj.is_executable() ? " [CODE]" : " [DATA]") << std::endl;
 * }
 * @endcode
 *
 * @see le_object, le_entry, dos_extender_type
 */
class LIBEXE_EXPORT le_file final : public executable_file {
public:
    // =========================================================================
    // Factory Methods
    // =========================================================================

    /**
     * @brief Load LE/LX file from filesystem.
     *
     * @param path Path to the executable file.
     * @return Parsed le_file object.
     * @throws std::runtime_error If file cannot be read or is not valid LE/LX.
     */
    [[nodiscard]] static le_file from_file(const std::filesystem::path& path);

    /**
     * @brief Load LE/LX file from memory buffer.
     *
     * @param data Span containing the raw file data.
     * @return Parsed le_file object.
     * @throws std::runtime_error If data is not valid LE/LX format.
     */
    [[nodiscard]] static le_file from_memory(std::span<const uint8_t> data);

    // =========================================================================
    // Base Class Interface
    // =========================================================================

    /// @copydoc executable_file::get_format()
    [[nodiscard]] format_type get_format() const override;

    /// @copydoc executable_file::format_name()
    [[nodiscard]] std::string_view format_name() const override;

    /// @copydoc executable_file::code_section()
    [[nodiscard]] std::span<const uint8_t> code_section() const override;

    // =========================================================================
    // Format Identification
    // =========================================================================

    /**
     * @brief Check if this is LX (OS/2) vs LE (DOS/VxD) format.
     * @return true if LX format, false if LE format.
     */
    [[nodiscard]] bool is_lx() const;

    /**
     * @brief Check if this is a VxD (Virtual Device Driver).
     * @return true if file is a Windows VxD.
     */
    [[nodiscard]] bool is_vxd() const;

    /**
     * @brief Check if this is a DLL/library module.
     * @return true if module is a library.
     */
    [[nodiscard]] bool is_library() const;

    /**
     * @brief Check if file was bound to a DOS extender.
     *
     * Bound executables have an MZ stub that loads the DOS extender,
     * followed by the LE/LX executable.
     *
     * @return true if file has a DOS extender stub.
     */
    [[nodiscard]] bool is_bound() const;

    /**
     * @brief Get detected DOS extender type.
     *
     * @return dos_extender_type identifying the extender, or NONE if not bound.
     */
    [[nodiscard]] dos_extender_type extender_type() const;

    // =========================================================================
    // Header Accessors
    // =========================================================================

    /**
     * @brief Get CPU type required.
     *
     * Common values: 1=286, 2=386, 3=486.
     *
     * @return CPU type code.
     */
    [[nodiscard]] uint16_t cpu_type() const;

    /**
     * @brief Get target operating system.
     *
     * Common values: 1=OS/2, 2=Windows, 3=DOS/4GW, 4=Windows 386.
     *
     * @return OS type code.
     */
    [[nodiscard]] uint16_t os_type() const;

    /**
     * @brief Get module version number.
     * @return Version number (user-defined).
     */
    [[nodiscard]] uint32_t module_version() const;

    /**
     * @brief Get module flags.
     * @return Module flags bitmask.
     */
    [[nodiscard]] uint32_t module_flags() const;

    /**
     * @brief Get memory page size.
     * @return Page size in bytes (usually 4096).
     */
    [[nodiscard]] uint32_t page_size() const;

    /**
     * @brief Get page offset shift (LX only).
     *
     * Page offsets in LX are shifted by this amount.
     * LE always uses shift of 0.
     *
     * @return Page offset shift count.
     */
    [[nodiscard]] uint32_t page_offset_shift() const;

    /**
     * @brief Get total number of memory pages.
     * @return Total page count.
     */
    [[nodiscard]] size_t page_count() const;

    /**
     * @brief Get number of preload pages.
     * @return Preload page count.
     */
    [[nodiscard]] size_t preload_page_count() const;

    /**
     * @brief Get heap size in bytes.
     * @return Heap size, or 0 if not specified.
     */
    [[nodiscard]] uint32_t heap_size() const;

    /**
     * @brief Get stack size in bytes.
     * @return Stack size.
     */
    [[nodiscard]] uint32_t stack_size() const;

    /**
     * @brief Get auto data segment object number.
     * @return Object number (1-based), or 0 if none.
     */
    [[nodiscard]] uint32_t auto_data_object() const;

    /**
     * @brief Get instance pages in preload section.
     * @return Instance preload page count.
     */
    [[nodiscard]] uint32_t instance_preload_pages() const;

    /**
     * @brief Get instance pages in demand section.
     * @return Instance demand page count.
     */
    [[nodiscard]] uint32_t instance_demand_pages() const;

    // =========================================================================
    // Entry Point
    // =========================================================================

    /**
     * @brief Get initial EIP (entry point offset).
     * @return Offset within entry object.
     */
    [[nodiscard]] uint32_t entry_eip() const;

    /**
     * @brief Get object number containing entry point.
     * @return Object number (1-based).
     */
    [[nodiscard]] uint32_t entry_object() const;

    /**
     * @brief Get initial ESP (stack pointer offset).
     * @return Stack pointer offset within stack object.
     */
    [[nodiscard]] uint32_t entry_esp() const;

    /**
     * @brief Get object number containing stack.
     * @return Object number (1-based).
     */
    [[nodiscard]] uint32_t stack_object() const;

    // =========================================================================
    // Object (Segment) Access
    // =========================================================================

    /**
     * @brief Get all objects.
     * @return Const reference to vector of le_object structures.
     */
    [[nodiscard]] const std::vector<le_object>& objects() const;

    /**
     * @brief Get object by 1-based index.
     *
     * @param index 1-based object index.
     * @return Optional containing the object, or nullopt if invalid.
     */
    [[nodiscard]] std::optional<le_object> get_object(uint32_t index) const;

    /**
     * @brief Find the first code object.
     * @return Optional containing the code object, or nullopt if none found.
     */
    [[nodiscard]] std::optional<le_object> get_code_object() const;

    /**
     * @brief Find the first data object.
     * @return Optional containing the data object, or nullopt if none found.
     */
    [[nodiscard]] std::optional<le_object> get_data_object() const;

    /**
     * @brief Get object containing entry point.
     * @return Optional containing the entry object, or nullopt if not found.
     */
    [[nodiscard]] std::optional<le_object> get_entry_object() const;

    /**
     * @brief Get page table entries for an object.
     *
     * @param object_index 1-based object index.
     * @return Vector of page entries for this object.
     */
    [[nodiscard]] std::vector<le_page_entry> get_object_pages(uint32_t object_index) const;

    /**
     * @brief Read object data (decompresses if needed).
     *
     * @param object_index 1-based object index.
     * @return Decompressed object data.
     */
    [[nodiscard]] std::vector<uint8_t> read_object_data(uint32_t object_index) const;

    // =========================================================================
    // Name Tables
    // =========================================================================

    /**
     * @brief Get resident name table entries.
     * @return Vector of name entries.
     */
    [[nodiscard]] std::vector<le_name_entry> resident_names() const;

    /**
     * @brief Get non-resident name table entries.
     * @return Vector of name entries.
     */
    [[nodiscard]] std::vector<le_name_entry> nonresident_names() const;

    /**
     * @brief Get module name.
     *
     * The module name is the first entry in the resident name table.
     *
     * @return Module name string.
     */
    [[nodiscard]] std::string module_name() const;

    // =========================================================================
    // Entry Table
    // =========================================================================

    /**
     * @brief Get all entry points.
     * @return Const reference to vector of le_entry structures.
     */
    [[nodiscard]] const std::vector<le_entry>& entries() const;

    /**
     * @brief Get entry by ordinal.
     *
     * @param ordinal 1-based ordinal number.
     * @return Optional containing the entry, or nullopt if not found.
     */
    [[nodiscard]] std::optional<le_entry> get_entry(uint16_t ordinal) const;

    /**
     * @brief Get number of entry points.
     * @return Entry count.
     */
    [[nodiscard]] size_t entry_count() const;

    // =========================================================================
    // Import Tables
    // =========================================================================

    /**
     * @brief Get imported module names.
     * @return Const reference to vector of module names.
     */
    [[nodiscard]] const std::vector<std::string>& import_modules() const;

    /**
     * @brief Get number of imported modules.
     * @return Import module count.
     */
    [[nodiscard]] size_t import_module_count() const;

    /**
     * @brief Get import module name by index.
     *
     * @param index 1-based module index.
     * @return Optional containing the module name, or nullopt if invalid.
     */
    [[nodiscard]] std::optional<std::string> get_import_module(uint16_t index) const;

    // =========================================================================
    // Fixup Tables
    // =========================================================================

    /**
     * @brief Get all fixup records.
     * @return Const reference to vector of le_fixup structures.
     */
    [[nodiscard]] const std::vector<le_fixup>& fixups() const;

    /**
     * @brief Get fixups for a specific page.
     *
     * @param page_index 1-based page index.
     * @return Vector of fixups for this page.
     */
    [[nodiscard]] std::vector<le_fixup> get_page_fixups(uint32_t page_index) const;

    /**
     * @brief Get number of fixup records.
     * @return Fixup count.
     */
    [[nodiscard]] size_t fixup_count() const;

    /**
     * @brief Check if file has fixups.
     * @return true if fixup count > 0.
     */
    [[nodiscard]] bool has_fixups() const;

    // =========================================================================
    // Resource Table
    // =========================================================================

    /**
     * @brief Get all resources.
     * @return Const reference to vector of le_resource structures.
     */
    [[nodiscard]] const std::vector<le_resource>& resources() const;

    /**
     * @brief Get number of resources.
     * @return Resource count.
     */
    [[nodiscard]] size_t resource_count() const;

    /**
     * @brief Check if file has resources.
     * @return true if resource count > 0.
     */
    [[nodiscard]] bool has_resources() const;

    /**
     * @brief Get resources filtered by type ID.
     *
     * @param type_id Resource type (e.g., le_resource::RT_BITMAP).
     * @return Vector of matching resources.
     */
    [[nodiscard]] std::vector<le_resource> resources_by_type(uint16_t type_id) const;

    /**
     * @brief Get resource by type and name ID.
     *
     * @param type_id Resource type.
     * @param name_id Resource name ID.
     * @return Optional containing the resource, or nullopt if not found.
     */
    [[nodiscard]] std::optional<le_resource> get_resource(uint16_t type_id, uint16_t name_id) const;

    /**
     * @brief Read resource data.
     *
     * @param resource The resource to read.
     * @return Resource data bytes.
     */
    [[nodiscard]] std::vector<uint8_t> read_resource_data(const le_resource& resource) const;

    // =========================================================================
    // Module Flag Analysis
    // =========================================================================

    /// @brief Check if per-process library initialization is required.
    [[nodiscard]] bool has_per_process_init() const;

    /// @brief Check if per-process library termination is required.
    [[nodiscard]] bool has_per_process_term() const;

    /// @brief Check if internal fixups have been applied.
    [[nodiscard]] bool has_internal_fixups() const;

    /// @brief Check if external fixups have been applied.
    [[nodiscard]] bool has_external_fixups() const;

    /// @brief Check if module is PM (Presentation Manager) compatible.
    [[nodiscard]] bool is_pm_compatible() const;

    /// @brief Check if module uses PM Windowing API.
    [[nodiscard]] bool uses_pm_api() const;

    /// @brief Check if module is not loadable (has errors).
    [[nodiscard]] bool is_not_loadable() const;

    /// @brief Check if module is multiprocessor safe.
    [[nodiscard]] bool is_mp_safe() const;

    // =========================================================================
    // Entropy Analysis (Packing Detection)
    // =========================================================================

    /**
     * @brief Calculate entropy of entire file.
     * @return Entropy value in bits (0.0 - 8.0).
     */
    [[nodiscard]] double file_entropy() const;

    /**
     * @brief Calculate entropy of a specific object.
     *
     * @param object_index 1-based object index.
     * @return Entropy value in bits.
     */
    [[nodiscard]] double object_entropy(uint32_t object_index) const;

    /**
     * @brief Get entropy analysis for all objects.
     * @return Vector of (object_index, entropy) pairs.
     */
    [[nodiscard]] std::vector<std::pair<uint32_t, double>> all_object_entropies() const;

    /**
     * @brief Check if any object has high entropy.
     * @return true if any object has entropy >= 7.0 bits.
     */
    [[nodiscard]] bool has_high_entropy_objects() const;

    /**
     * @brief Check if file appears to be packed.
     * @return true if file appears packed based on entropy and compression.
     */
    [[nodiscard]] bool is_likely_packed() const;

    // =========================================================================
    // Debug Information
    // =========================================================================

    /// @brief Check if debug info is present.
    [[nodiscard]] bool has_debug_info() const;

    /// @brief Get debug info file offset.
    [[nodiscard]] uint32_t debug_info_offset() const;

    /// @brief Get debug info size.
    [[nodiscard]] uint32_t debug_info_size() const;

    // =========================================================================
    // DOS Extender Stripping
    // =========================================================================

    /**
     * @brief Strip DOS extender stub and return raw LE/LX data.
     *
     * Removes the MZ stub and adjusts absolute file offsets.
     *
     * @return Raw LE/LX data, or empty vector if not bound.
     */
    [[nodiscard]] std::vector<uint8_t> strip_extender() const;

    /**
     * @brief Get offset to LE/LX header.
     * @return Offset (0 if raw, >0 if bound).
     */
    [[nodiscard]] uint32_t le_header_offset() const;

    /**
     * @brief Get the size of the DOS extender stub.
     * @return Stub size in bytes (0 if not bound).
     */
    [[nodiscard]] uint32_t stub_size() const;

    // =========================================================================
    // Diagnostics
    // =========================================================================

    /**
     * @brief Get all diagnostics generated during parsing.
     * @return Const reference to diagnostic_collector.
     */
    [[nodiscard]] const diagnostic_collector& diagnostics() const;

    /**
     * @brief Check if a specific diagnostic code exists.
     *
     * @param code Diagnostic code to check for.
     * @return true if diagnostic was generated.
     */
    [[nodiscard]] bool has_diagnostic(diagnostic_code code) const;

private:
    le_file() = default;

    void parse_le_headers();
    void parse_objects();
    void parse_page_table();
    void parse_entry_table();
    void parse_import_module_table();
    void parse_fixup_tables();
    void parse_resource_table();
    void detect_extender_type();

    std::vector<uint8_t> data_;
    std::vector<le_object> objects_;
    std::vector<le_page_entry> page_table_;
    std::vector<le_entry> entries_;
    std::vector<std::string> import_modules_;
    std::vector<le_fixup> fixups_;
    std::vector<le_resource> resources_;

    // Format identification
    bool is_lx_ = false;
    bool is_bound_ = false;
    dos_extender_type extender_type_ = dos_extender_type::NONE;
    uint32_t le_header_offset_ = 0;

    // Header fields
    uint16_t cpu_type_ = 0;
    uint16_t os_type_ = 0;
    uint32_t module_version_ = 0;
    uint32_t module_flags_ = 0;
    uint32_t page_size_ = 4096;
    uint32_t page_offset_shift_ = 0;
    uint32_t page_count_ = 0;
    uint32_t preload_page_count_ = 0;
    uint32_t heap_size_ = 0;
    uint32_t stack_size_ = 0;
    uint32_t auto_data_object_ = 0;
    uint32_t instance_preload_ = 0;
    uint32_t instance_demand_ = 0;

    // Entry point
    uint32_t eip_object_ = 0;
    uint32_t eip_ = 0;
    uint32_t esp_object_ = 0;
    uint32_t esp_ = 0;

    // Table offsets
    uint32_t object_table_offset_ = 0;
    uint32_t object_count_ = 0;
    uint32_t page_table_offset_ = 0;
    uint32_t resource_table_offset_ = 0;
    uint32_t resource_count_ = 0;
    uint32_t resident_name_table_offset_ = 0;
    uint32_t entry_table_offset_ = 0;
    uint32_t import_module_table_offset_ = 0;
    uint32_t import_module_count_ = 0;
    uint32_t import_proc_table_offset_ = 0;
    uint32_t fixup_page_table_offset_ = 0;
    uint32_t fixup_record_table_offset_ = 0;

    // Absolute file offsets
    uint32_t data_pages_offset_ = 0;
    uint32_t nonresident_name_table_offset_ = 0;
    uint32_t nonresident_name_table_size_ = 0;
    uint32_t debug_info_offset_ = 0;
    uint32_t debug_info_size_ = 0;

    mutable diagnostic_collector diagnostics_;
};

} // namespace libexe

#endif // LIBEXE_FORMATS_LE_FILE_HPP
