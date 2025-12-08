#ifndef LIBEXE_SECTION_HPP
#define LIBEXE_SECTION_HPP

#include <libexe/export.hpp>
#include <libexe/ne_types.hpp>
#include <cstdint>
#include <span>
#include <string>
#include <optional>

namespace libexe {

/**
 * Section type classification
 *
 * Used to identify the purpose of a section/segment
 */
enum class section_type {
    CODE,               // Executable code
    DATA,               // Initialized data
    BSS,                // Uninitialized data
    IMPORT,             // Import directory
    EXPORT,             // Export directory
    RESOURCE,           // Resources
    RELOCATION,         // Base relocations
    DEBUG,              // Debug information
    TLS,                // Thread Local Storage
    EXCEPTION,          // Exception handling (pdata)
    UNKNOWN             // Unknown/custom section
};

/**
 * PE Section characteristics flags
 *
 * From IMAGE_SCN_* constants in PE specification
 */
enum class section_characteristics : uint32_t {
    // Content type
    CNT_CODE                = 0x00000020,  // Section contains code
    CNT_INITIALIZED_DATA    = 0x00000040,  // Section contains initialized data
    CNT_UNINITIALIZED_DATA  = 0x00000080,  // Section contains uninitialized data

    // Link info
    LNK_OTHER               = 0x00000100,  // Reserved
    LNK_INFO                = 0x00000200,  // Section contains comments/info
    LNK_REMOVE              = 0x00000800,  // Section will not become part of image
    LNK_COMDAT              = 0x00001000,  // Section contains COMDAT data

    // Alignment (encoded as power of 2)
    ALIGN_1BYTES            = 0x00100000,  // Align data on 1-byte boundary
    ALIGN_2BYTES            = 0x00200000,  // Align data on 2-byte boundary
    ALIGN_4BYTES            = 0x00300000,  // Align data on 4-byte boundary
    ALIGN_8BYTES            = 0x00400000,  // Align data on 8-byte boundary
    ALIGN_16BYTES           = 0x00500000,  // Align data on 16-byte boundary
    ALIGN_32BYTES           = 0x00600000,  // Align data on 32-byte boundary
    ALIGN_64BYTES           = 0x00700000,  // Align data on 64-byte boundary
    ALIGN_128BYTES          = 0x00800000,  // Align data on 128-byte boundary
    ALIGN_256BYTES          = 0x00900000,  // Align data on 256-byte boundary
    ALIGN_512BYTES          = 0x00A00000,  // Align data on 512-byte boundary
    ALIGN_1024BYTES         = 0x00B00000,  // Align data on 1024-byte boundary
    ALIGN_2048BYTES         = 0x00C00000,  // Align data on 2048-byte boundary
    ALIGN_4096BYTES         = 0x00D00000,  // Align data on 4096-byte boundary
    ALIGN_8192BYTES         = 0x00E00000,  // Align data on 8192-byte boundary
    ALIGN_MASK              = 0x00F00000,  // Mask for alignment bits

    // Extended relocations
    LNK_NRELOC_OVFL         = 0x01000000,  // Section contains extended relocations

    // Memory attributes
    MEM_DISCARDABLE         = 0x02000000,  // Section can be discarded
    MEM_NOT_CACHED          = 0x04000000,  // Section is not cacheable
    MEM_NOT_PAGED           = 0x08000000,  // Section is not pageable
    MEM_SHARED              = 0x10000000,  // Section is shared
    MEM_EXECUTE             = 0x20000000,  // Section is executable
    MEM_READ                = 0x40000000,  // Section is readable
    MEM_WRITE               = 0x80000000   // Section is writable
};

// Note: ne_segment_flags is defined in ne_types.hpp

/**
 * PE Section - Enhanced metadata
 *
 * Represents a section in a PE (Portable Executable) file with
 * complete metadata and helper methods for analysis.
 */
struct LIBEXE_EXPORT pe_section {
    // Basic info
    std::string name;                    // Section name (e.g., ".text", ".data")
    section_type type;                   // Classified section type

    // Memory layout
    uint32_t virtual_address;            // RVA where section loads in memory
    uint32_t virtual_size;               // Size of section in memory
    uint32_t raw_data_offset;            // File offset to section data
    uint32_t raw_data_size;              // Size of section data in file

    // Properties
    uint32_t characteristics;            // Raw characteristics flags
    uint32_t alignment;                  // Section alignment in bytes

    // Data access
    std::span<const uint8_t> data;       // Section data

    /**
     * Check if section contains code
     */
    [[nodiscard]] bool is_code() const {
        return (characteristics & static_cast<uint32_t>(section_characteristics::CNT_CODE)) != 0;
    }

    /**
     * Check if section contains initialized data
     */
    [[nodiscard]] bool is_data() const {
        return (characteristics & static_cast<uint32_t>(section_characteristics::CNT_INITIALIZED_DATA)) != 0;
    }

    /**
     * Check if section is readable
     */
    [[nodiscard]] bool is_readable() const {
        return (characteristics & static_cast<uint32_t>(section_characteristics::MEM_READ)) != 0;
    }

    /**
     * Check if section is writable
     */
    [[nodiscard]] bool is_writable() const {
        return (characteristics & static_cast<uint32_t>(section_characteristics::MEM_WRITE)) != 0;
    }

    /**
     * Check if section is executable
     */
    [[nodiscard]] bool is_executable() const {
        return (characteristics & static_cast<uint32_t>(section_characteristics::MEM_EXECUTE)) != 0;
    }

    /**
     * Check if section is discardable
     */
    [[nodiscard]] bool is_discardable() const {
        return (characteristics & static_cast<uint32_t>(section_characteristics::MEM_DISCARDABLE)) != 0;
    }

    /**
     * Check if section is shared
     */
    [[nodiscard]] bool is_shared() const {
        return (characteristics & static_cast<uint32_t>(section_characteristics::MEM_SHARED)) != 0;
    }

    /**
     * Convert RVA to offset within this section
     *
     * @param rva Relative Virtual Address
     * @return File offset if RVA is within this section, nullopt otherwise
     */
    [[nodiscard]] std::optional<size_t> rva_to_offset(uint32_t rva) const {
        if (rva >= virtual_address && rva < virtual_address + virtual_size) {
            uint32_t offset_in_section = rva - virtual_address;
            // Ensure offset doesn't exceed raw data size
            if (offset_in_section < raw_data_size) {
                return raw_data_offset + offset_in_section;
            }
        }
        return std::nullopt;
    }

    /**
     * Check if RVA is within this section
     *
     * @param rva Relative Virtual Address
     * @return true if RVA is within section's virtual address range
     */
    [[nodiscard]] bool contains_rva(uint32_t rva) const {
        return rva >= virtual_address && rva < virtual_address + virtual_size;
    }
};

/**
 * NE Segment - Enhanced metadata
 *
 * Represents a segment in an NE (New Executable) file with
 * complete metadata and helper methods for analysis.
 */
struct LIBEXE_EXPORT ne_segment {
    // Basic info
    uint16_t index;                      // Segment index (1-based)
    section_type type;                   // Code or data

    // File layout
    uint32_t file_offset;                // Computed: sector << alignment_shift
    uint32_t file_size;                  // Length in file (0 = 65536)

    // Memory layout
    uint32_t min_alloc_size;             // Minimum allocation (0 = 65536)

    // Properties
    uint16_t flags;                      // Raw segment flags

    // Data access
    std::span<const uint8_t> data;       // Segment data

    /**
     * Check if segment contains code
     */
    [[nodiscard]] bool is_code() const {
        return (flags & static_cast<uint16_t>(ne_segment_flags::DATA)) == 0;
    }

    /**
     * Check if segment contains data
     */
    [[nodiscard]] bool is_data() const {
        return (flags & static_cast<uint16_t>(ne_segment_flags::DATA)) != 0;
    }

    /**
     * Check if segment is moveable
     */
    [[nodiscard]] bool is_moveable() const {
        return (flags & static_cast<uint16_t>(ne_segment_flags::MOVEABLE)) != 0;
    }

    /**
     * Check if segment should be preloaded
     */
    [[nodiscard]] bool is_preload() const {
        return (flags & static_cast<uint16_t>(ne_segment_flags::PRELOAD)) != 0;
    }

    /**
     * Check if segment is read-only (or execute-only for code)
     */
    [[nodiscard]] bool is_read_only() const {
        return (flags & static_cast<uint16_t>(ne_segment_flags::READ_ONLY)) != 0;
    }

    /**
     * Check if segment is discardable
     */
    [[nodiscard]] bool is_discardable() const {
        return (flags & static_cast<uint16_t>(ne_segment_flags::DISCARDABLE)) != 0;
    }

    /**
     * Check if segment has relocation information
     */
    [[nodiscard]] bool has_relocations() const {
        return (flags & static_cast<uint16_t>(ne_segment_flags::RELOC_INFO)) != 0;
    }
};

} // namespace libexe

#endif // LIBEXE_SECTION_HPP
