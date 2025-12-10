// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_PE_RICH_HEADER_HPP
#define LIBEXE_PE_RICH_HEADER_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <vector>
#include <span>
#include <string>
#include <optional>

namespace libexe {

/**
 * Rich Header Product Type
 *
 * Identifies the type of Microsoft build tool component.
 * The product ID is the high 16 bits of the comp.id value.
 */
enum class rich_product_type : uint16_t {
    // Unmarked / Special
    UNMARKED           = 0x0000,  // Unmarked objects (legacy)
    UNMARKED_MODERN    = 0x0001,  // Unmarked objects (modern)

    // VS97 / VS98 (6.x)
    LINKER_510         = 0x0002,  // VS97 (5.10) Linker
    CVTOMF_510         = 0x0004,  // VS97 (5.10) CVTOMF
    LINKER_600         = 0x0006,  // VS98 (6.00) Linker
    CVTOMF_600         = 0x0007,  // VS98 (6.00) CVTOMF
    IMPLIB_600         = 0x0009,  // VS98 (6.00) Import library
    CVTRES_600         = 0x000A,  // VS98 (6.00) Resource compiler
    EXPORT_600         = 0x000B,  // VS98 (6.00) Export
    MASM_611           = 0x000C,  // VS98 (6.11) MASM
    MASM_613           = 0x000D,  // VS98 (6.13) MASM
    MASM_614           = 0x000E,  // VS98 (6.14) MASM
    LINKER_511         = 0x000F,  // VS97 SP3 (5.11) Linker
    CVTOMF_511         = 0x0010,  // VS97 SP3 (5.11) CVTOMF
    LINKER_612         = 0x0012,  // VS98 SP6 (6.12) Linker
    CVTOMF_612         = 0x0013,  // VS98 SP6 (6.12) CVTOMF
    UTC_C_1200         = 0x0015,  // VS98 (6.00) C compiler
    UTC_CPP_1200       = 0x0016,  // VS98 (6.00) C++ compiler

    // VS2002 (7.0)
    IMPLIB_700         = 0x0019,  // VS2002 Import library
    UTC_C_1300         = 0x001C,  // VS2002 C compiler
    UTC_CPP_1300       = 0x001D,  // VS2002 C++ compiler
    LINKER_700         = 0x003D,  // VS2002 Linker
    EXPORT_700         = 0x003F,  // VS2002 Export
    MASM_700           = 0x0040,  // VS2002 MASM
    CVTRES_700         = 0x0045,  // VS2002 Resource compiler

    // VS2003 (7.10)
    LINKER_710         = 0x005A,  // VS2003 Linker
    CVTOMF_710         = 0x005B,  // VS2003 CVTOMF
    EXPORT_710         = 0x005C,  // VS2003 Export
    IMPLIB_710         = 0x005D,  // VS2003 Import library
    CVTRES_710         = 0x005E,  // VS2003 Resource compiler
    UTC_C_1310         = 0x005F,  // VS2003 C compiler
    UTC_CPP_1310       = 0x0060,  // VS2003 C++ compiler
    UTC_LTCG_C_1310    = 0x0063,  // VS2003 LTCG C
    UTC_LTCG_CPP_1310  = 0x0064,  // VS2003 LTCG C++
    UTC_POGO_I_C_1310  = 0x0065,  // VS2003 POGO I C
    UTC_POGO_I_CPP_1310= 0x0066,  // VS2003 POGO I C++
    UTC_POGO_O_C_1310  = 0x0067,  // VS2003 POGO O C
    UTC_POGO_O_CPP_1310= 0x0068,  // VS2003 POGO O C++
    ALIASOBJ_710       = 0x0069,  // VS2003 AliasObj
    CVTPGD_1310        = 0x006B,  // VS2003 CVTPGD

    // VS2005 (8.0)
    UTC_C_1400         = 0x006D,  // VS2005 C compiler
    UTC_CPP_1400       = 0x006E,  // VS2005 C++ compiler
    UTC_LTCG_C_1400    = 0x0071,  // VS2005 LTCG C
    UTC_LTCG_CPP_1400  = 0x0072,  // VS2005 LTCG C++
    UTC_POGO_I_C_1400  = 0x0073,  // VS2005 POGO I C
    UTC_POGO_I_CPP_1400= 0x0074,  // VS2005 POGO I C++
    UTC_POGO_O_C_1400  = 0x0075,  // VS2005 POGO O C
    UTC_POGO_O_CPP_1400= 0x0076,  // VS2005 POGO O C++
    CVTPGD_1400        = 0x0077,  // VS2005 CVTPGD
    LINKER_800         = 0x0078,  // VS2005 Linker
    CVTOMF_800         = 0x0079,  // VS2005 CVTOMF
    EXPORT_800         = 0x007A,  // VS2005 Export
    IMPLIB_800         = 0x007B,  // VS2005 Import library
    CVTRES_800         = 0x007C,  // VS2005 Resource compiler
    MASM_800           = 0x007D,  // VS2005 MASM
    ALIASOBJ_800       = 0x007E,  // VS2005 AliasObj
    UTC_CVTCIL_C_1400  = 0x0080,  // VS2005 CVTCIL C
    UTC_CVTCIL_CPP_1400= 0x0081,  // VS2005 CVTCIL C++
    UTC_LTCG_MSIL_1400 = 0x0082,  // VS2005 LTCG MSIL

    // VS2008 (9.0)
    UTC_C_1500         = 0x0083,  // VS2008 C compiler
    UTC_CPP_1500       = 0x0084,  // VS2008 C++ compiler
    UTC_CVTCIL_C_1500  = 0x0087,  // VS2008 CVTCIL C
    UTC_CVTCIL_CPP_1500= 0x0088,  // VS2008 CVTCIL C++
    UTC_LTCG_C_1500    = 0x0089,  // VS2008 LTCG C
    UTC_LTCG_CPP_1500  = 0x008A,  // VS2008 LTCG C++
    UTC_LTCG_MSIL_1500 = 0x008B,  // VS2008 LTCG MSIL
    UTC_POGO_I_C_1500  = 0x008C,  // VS2008 POGO I C
    UTC_POGO_I_CPP_1500= 0x008D,  // VS2008 POGO I C++
    UTC_POGO_O_C_1500  = 0x008E,  // VS2008 POGO O C
    UTC_POGO_O_CPP_1500= 0x008F,  // VS2008 POGO O C++
    CVTPGD_1500        = 0x0090,  // VS2008 CVTPGD
    LINKER_900         = 0x0091,  // VS2008 Linker
    EXPORT_900         = 0x0092,  // VS2008 Export
    IMPLIB_900         = 0x0093,  // VS2008 Import library
    CVTRES_900         = 0x0094,  // VS2008 Resource compiler
    MASM_900           = 0x0095,  // VS2008 MASM
    ALIASOBJ_900       = 0x0096,  // VS2008 AliasObj

    // VS2010 (10.0)
    ALIASOBJ_1000      = 0x0098,  // VS2010 AliasObj
    CVTPGD_1600        = 0x0099,  // VS2010 CVTPGD
    CVTRES_1000        = 0x009A,  // VS2010 Resource compiler
    EXPORT_1000        = 0x009B,  // VS2010 Export
    IMPLIB_1000        = 0x009C,  // VS2010 Import library
    LINKER_1000        = 0x009D,  // VS2010 Linker
    MASM_1000          = 0x009E,  // VS2010 MASM
    UTC_C_1600         = 0x00AA,  // VS2010 C compiler
    UTC_CPP_1600       = 0x00AB,  // VS2010 C++ compiler
    UTC_CVTCIL_C_1600  = 0x00AC,  // VS2010 CVTCIL C
    UTC_CVTCIL_CPP_1600= 0x00AD,  // VS2010 CVTCIL C++
    UTC_LTCG_C_1600    = 0x00AE,  // VS2010 LTCG C
    UTC_LTCG_CPP_1600  = 0x00AF,  // VS2010 LTCG C++
    UTC_LTCG_MSIL_1600 = 0x00B0,  // VS2010 LTCG MSIL
    UTC_POGO_I_C_1600  = 0x00B1,  // VS2010 POGO I C
    UTC_POGO_I_CPP_1600= 0x00B2,  // VS2010 POGO I C++
    UTC_POGO_O_C_1600  = 0x00B3,  // VS2010 POGO O C
    UTC_POGO_O_CPP_1600= 0x00B4,  // VS2010 POGO O C++

    // VS2012 (11.0)
    ALIASOBJ_1100      = 0x00C7,  // VS2012 AliasObj
    CVTPGD_1700        = 0x00C8,  // VS2012 CVTPGD
    CVTRES_1100        = 0x00C9,  // VS2012 Resource compiler
    EXPORT_1100        = 0x00CA,  // VS2012 Export
    IMPLIB_1100        = 0x00CB,  // VS2012 Import library
    LINKER_1100        = 0x00CC,  // VS2012 Linker
    MASM_1100          = 0x00CD,  // VS2012 MASM
    UTC_C_1700         = 0x00CE,  // VS2012 C compiler
    UTC_CPP_1700       = 0x00CF,  // VS2012 C++ compiler
    UTC_CVTCIL_C_1700  = 0x00D0,  // VS2012 CVTCIL C
    UTC_CVTCIL_CPP_1700= 0x00D1,  // VS2012 CVTCIL C++
    UTC_LTCG_C_1700    = 0x00D2,  // VS2012 LTCG C
    UTC_LTCG_CPP_1700  = 0x00D3,  // VS2012 LTCG C++
    UTC_LTCG_MSIL_1700 = 0x00D4,  // VS2012 LTCG MSIL
    UTC_POGO_I_C_1700  = 0x00D5,  // VS2012 POGO I C
    UTC_POGO_I_CPP_1700= 0x00D6,  // VS2012 POGO I C++
    UTC_POGO_O_C_1700  = 0x00D7,  // VS2012 POGO O C
    UTC_POGO_O_CPP_1700= 0x00D8,  // VS2012 POGO O C++

    // VS2013 (12.0)
    ALIASOBJ_1200      = 0x00D9,  // VS2013 AliasObj
    CVTPGD_1800        = 0x00DA,  // VS2013 CVTPGD
    CVTRES_1200        = 0x00DB,  // VS2013 Resource compiler
    EXPORT_1200        = 0x00DC,  // VS2013 Export
    IMPLIB_1200        = 0x00DD,  // VS2013 Import library
    LINKER_1200        = 0x00DE,  // VS2013 Linker
    MASM_1200          = 0x00DF,  // VS2013 MASM
    UTC_C_1800         = 0x00E0,  // VS2013 C compiler
    UTC_CPP_1800       = 0x00E1,  // VS2013 C++ compiler
    UTC_CVTCIL_C_1800  = 0x00E2,  // VS2013 CVTCIL C
    UTC_CVTCIL_CPP_1800= 0x00E3,  // VS2013 CVTCIL C++
    UTC_LTCG_C_1800    = 0x00E4,  // VS2013 LTCG C
    UTC_LTCG_CPP_1800  = 0x00E5,  // VS2013 LTCG C++
    UTC_LTCG_MSIL_1800 = 0x00E6,  // VS2013 LTCG MSIL
    UTC_POGO_I_C_1800  = 0x00E7,  // VS2013 POGO I C
    UTC_POGO_I_CPP_1800= 0x00E8,  // VS2013 POGO I C++
    UTC_POGO_O_C_1800  = 0x00E9,  // VS2013 POGO O C
    UTC_POGO_O_CPP_1800= 0x00EA,  // VS2013 POGO O C++

    // VS2015+ (14.0+) - Unified IDs, use build number to distinguish versions
    ALIASOBJ_1400      = 0x00FD,  // VS2015+ AliasObj
    CVTPGD_1900        = 0x00FE,  // VS2015+ CVTPGD
    CVTRES_1400        = 0x00FF,  // VS2015+ Resource compiler
    EXPORT_1400        = 0x0100,  // VS2015+ Export
    IMPLIB_1400        = 0x0101,  // VS2015+ Import library
    LINKER_1400        = 0x0102,  // VS2015+ Linker
    MASM_1400          = 0x0103,  // VS2015+ MASM
    UTC_C_1900         = 0x0104,  // VS2015+ C compiler
    UTC_CPP_1900       = 0x0105,  // VS2015+ C++ compiler
    UTC_CVTCIL_C_1900  = 0x0106,  // VS2015+ CVTCIL C
    UTC_CVTCIL_CPP_1900= 0x0107,  // VS2015+ CVTCIL C++
    UTC_LTCG_C_1900    = 0x0108,  // VS2015+ LTCG C
    UTC_LTCG_CPP_1900  = 0x0109,  // VS2015+ LTCG C++
    UTC_LTCG_MSIL_1900 = 0x010A,  // VS2015+ LTCG MSIL
    UTC_POGO_I_C_1900  = 0x010B,  // VS2015+ POGO I C
    UTC_POGO_I_CPP_1900= 0x010C,  // VS2015+ POGO I C++
    UTC_POGO_O_C_1900  = 0x010D,  // VS2015+ POGO O C
    UTC_POGO_O_CPP_1900= 0x010E,  // VS2015+ POGO O C++
};

/**
 * Rich Header Component Type
 *
 * Classification of build tool types for easier analysis.
 */
enum class rich_component_type {
    UNKNOWN,       // Unknown component
    C_COMPILER,    // C compiler (cl.exe)
    CPP_COMPILER,  // C++ compiler (cl.exe)
    LINKER,        // Linker (link.exe)
    ASSEMBLER,     // Assembler (ml.exe/masm.exe)
    RESOURCE,      // Resource compiler (cvtres.exe)
    IMPORT_LIB,    // Import library (lib.exe)
    EXPORT,        // Export record
    CVTOMF,        // OMF converter
    LTCG,          // Link-time code generation
    POGO,          // Profile-guided optimization
    CVTCIL,        // CIL converter (MSIL)
    ALIAS_OBJ,     // Alias object
    CVTPGD         // PGO database converter
};

/**
 * Rich Header Entry
 *
 * Represents a single component entry in the Rich header.
 * Each entry identifies a tool/component used to build the executable
 * and how many object files were produced by that tool.
 */
struct LIBEXE_EXPORT rich_entry {
    /// Product ID (high 16 bits of comp.id) - identifies the tool
    uint16_t product_id = 0;

    /// Build number (low 16 bits of comp.id) - identifies the tool version
    uint16_t build_number = 0;

    /// Usage count - how many times this tool/version was used
    uint32_t count = 0;

    /**
     * Get component type classification
     * @return The type of build component
     */
    [[nodiscard]] rich_component_type component_type() const;

    /**
     * Get human-readable product name
     * @return Product name string (e.g., "VS2019 C++ compiler")
     */
    [[nodiscard]] std::string product_name() const;

    /**
     * Get Visual Studio version string
     * @return VS version (e.g., "VS2019", "VS2022", or empty if unknown)
     */
    [[nodiscard]] std::string vs_version() const;

    /**
     * Get the full comp.id value
     * @return Combined product_id and build_number as 32-bit value
     */
    [[nodiscard]] uint32_t comp_id() const {
        return (static_cast<uint32_t>(product_id) << 16) | build_number;
    }

    /**
     * Check if this is a compiler entry (C or C++)
     * @return True if product ID indicates a compiler
     */
    [[nodiscard]] bool is_compiler() const;

    /**
     * Check if this is a linker entry
     * @return True if product ID indicates a linker
     */
    [[nodiscard]] bool is_linker() const;
};

/**
 * Rich Header
 *
 * The Rich header is an undocumented structure embedded by Microsoft's linker
 * in PE executables. It contains metadata about the build tools, compiler versions,
 * and libraries used during compilation.
 *
 * Structure:
 * - "DanS" header (XOR encrypted)
 * - Array of entries (XOR encrypted)
 * - "Rich" terminator (plaintext)
 * - XOR mask (plaintext)
 *
 * The XOR mask is used to encrypt all data except the terminator and mask itself.
 */
struct LIBEXE_EXPORT rich_header {
    /// XOR mask used to encrypt the header
    uint32_t xor_mask = 0;

    /// Offset of Rich header start in file (DanS position)
    uint32_t file_offset = 0;

    /// Size of Rich header in bytes (including DanS through mask)
    uint32_t size = 0;

    /// Component entries (decrypted)
    std::vector<rich_entry> entries;

    /**
     * Get number of entries
     * @return Entry count
     */
    [[nodiscard]] size_t entry_count() const {
        return entries.size();
    }

    /**
     * Check if header is empty
     * @return True if no entries
     */
    [[nodiscard]] bool empty() const {
        return entries.empty();
    }

    /**
     * Check if header appears valid
     * @return True if structure looks valid
     */
    [[nodiscard]] bool is_valid() const;

    /**
     * Get total object count (sum of all entry counts)
     * @return Total count across all entries
     */
    [[nodiscard]] uint32_t total_count() const;

    /**
     * Get primary compiler entry (first compiler with highest count)
     * @return Pointer to primary compiler entry, or nullptr if none
     */
    [[nodiscard]] const rich_entry* primary_compiler() const;

    /**
     * Get linker entry
     * @return Pointer to linker entry, or nullptr if none
     */
    [[nodiscard]] const rich_entry* linker() const;

    /**
     * Get Visual Studio major version based on entries
     * @return Major VS version (e.g., 2019, 2022) or nullopt if unknown
     */
    [[nodiscard]] std::optional<uint16_t> vs_major_version() const;

    /**
     * Find entries by product type
     * @param type Product type to search for
     * @return Vector of matching entries
     */
    [[nodiscard]] std::vector<const rich_entry*> find_by_type(rich_product_type type) const;

    /**
     * Get string representation of the header
     * @return Human-readable description of Rich header contents
     */
    [[nodiscard]] std::string to_string() const;
};

/**
 * Parser for PE Rich Header
 *
 * The Rich header is located between the DOS stub and PE header.
 * It is XOR encrypted with a 32-bit key that is stored after the "Rich" marker.
 *
 * Parsing steps:
 * 1. Search backwards from PE header for "Rich" marker
 * 2. Read XOR mask from after "Rich"
 * 3. Search backwards for encrypted "DanS" header
 * 4. Decrypt and parse entries between DanS and Rich
 */
class LIBEXE_EXPORT rich_header_parser {
public:
    /**
     * Parse Rich header from PE file data
     *
     * @param file_data Complete PE file data
     * @param pe_offset Offset to PE header ("PE\0\0" signature)
     * @return Parsed Rich header, or nullopt if not found/invalid
     */
    static std::optional<rich_header> parse(
        std::span<const uint8_t> file_data,
        uint32_t pe_offset
    );

    /**
     * Check if file contains a Rich header
     *
     * @param file_data Complete PE file data
     * @param pe_offset Offset to PE header
     * @return True if Rich header is present
     */
    static bool has_rich_header(
        std::span<const uint8_t> file_data,
        uint32_t pe_offset
    );

private:
    /// "Rich" signature in little-endian (0x68636952 = "Rich")
    static constexpr uint32_t RICH_SIGNATURE = 0x68636952;

    /// "DanS" signature in little-endian (0x536E6144 = "DanS")
    static constexpr uint32_t DANS_SIGNATURE = 0x536E6144;

    /**
     * Search for "Rich" marker backwards from PE header
     * @return Offset of "Rich" marker, or 0 if not found
     */
    static uint32_t find_rich_marker(
        std::span<const uint8_t> file_data,
        uint32_t pe_offset
    );

    /**
     * Search for encrypted "DanS" header
     * @return Offset of "DanS" header, or 0 if not found
     */
    static uint32_t find_dans_header(
        std::span<const uint8_t> file_data,
        uint32_t rich_offset,
        uint32_t xor_mask
    );
};

/**
 * Get human-readable name for a product type
 * @param type Product type
 * @return Name string
 */
LIBEXE_EXPORT std::string_view rich_product_type_name(rich_product_type type);

/**
 * Get component type for a product ID
 * @param product_id Product ID value
 * @return Component type classification
 */
LIBEXE_EXPORT rich_component_type get_component_type(uint16_t product_id);

/**
 * Get Visual Studio version string for a build number
 * @param build_number Build number from comp.id
 * @return VS version string (e.g., "VS2019") or empty if unknown
 */
LIBEXE_EXPORT std::string get_vs_version_for_build(uint16_t build_number);

} // namespace libexe

#endif // LIBEXE_PE_RICH_HEADER_HPP
