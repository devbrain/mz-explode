// libexe - Modern executable file analysis library
// Copyright (c) 2024
// PE and NE section/segment types

#ifndef LIBEXE_PE_SECTION_HPP
#define LIBEXE_PE_SECTION_HPP

#include <libexe/export.hpp>
#include <libexe/ne/types.hpp>
#include <cstdint>
#include <span>
#include <string>
#include <optional>

// Disable MSVC warning C4251: 'member': class 'std::...' needs to have dll-interface
// This warning is benign for header-only STL types when both library and client
// use the same compiler and runtime
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

namespace libexe {

/**
 * Section type classification
 */
enum class section_type {
    CODE,
    DATA,
    BSS,
    IMPORT,
    EXPORT,
    RESOURCE,
    RELOCATION,
    DEBUG,
    TLS,
    EXCEPTION,
    UNKNOWN
};

/**
 * PE Section characteristics flags
 */
enum class section_characteristics : uint32_t {
    CNT_CODE                = 0x00000020,
    CNT_INITIALIZED_DATA    = 0x00000040,
    CNT_UNINITIALIZED_DATA  = 0x00000080,
    LNK_OTHER               = 0x00000100,
    LNK_INFO                = 0x00000200,
    LNK_REMOVE              = 0x00000800,
    LNK_COMDAT              = 0x00001000,
    ALIGN_1BYTES            = 0x00100000,
    ALIGN_2BYTES            = 0x00200000,
    ALIGN_4BYTES            = 0x00300000,
    ALIGN_8BYTES            = 0x00400000,
    ALIGN_16BYTES           = 0x00500000,
    ALIGN_32BYTES           = 0x00600000,
    ALIGN_64BYTES           = 0x00700000,
    ALIGN_128BYTES          = 0x00800000,
    ALIGN_256BYTES          = 0x00900000,
    ALIGN_512BYTES          = 0x00A00000,
    ALIGN_1024BYTES         = 0x00B00000,
    ALIGN_2048BYTES         = 0x00C00000,
    ALIGN_4096BYTES         = 0x00D00000,
    ALIGN_8192BYTES         = 0x00E00000,
    ALIGN_MASK              = 0x00F00000,
    LNK_NRELOC_OVFL         = 0x01000000,
    MEM_DISCARDABLE         = 0x02000000,
    MEM_NOT_CACHED          = 0x04000000,
    MEM_NOT_PAGED           = 0x08000000,
    MEM_SHARED              = 0x10000000,
    MEM_EXECUTE             = 0x20000000,
    MEM_READ                = 0x40000000,
    MEM_WRITE               = 0x80000000
};

/**
 * PE Section
 */
struct LIBEXE_EXPORT pe_section {
    std::string name;
    section_type type;
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_data_offset;       // Declared offset (may need alignment rounding)
    uint32_t raw_data_size;
    uint32_t characteristics;
    uint32_t alignment;
    uint32_t file_alignment = 0x200; // File alignment for offset rounding (default 0x200)
    std::span<const uint8_t> data;

    [[nodiscard]] bool is_code() const {
        return (characteristics & static_cast<uint32_t>(section_characteristics::CNT_CODE)) != 0;
    }

    [[nodiscard]] bool is_data() const {
        return (characteristics & static_cast<uint32_t>(section_characteristics::CNT_INITIALIZED_DATA)) != 0;
    }

    [[nodiscard]] bool is_readable() const {
        return (characteristics & static_cast<uint32_t>(section_characteristics::MEM_READ)) != 0;
    }

    [[nodiscard]] bool is_writable() const {
        return (characteristics & static_cast<uint32_t>(section_characteristics::MEM_WRITE)) != 0;
    }

    [[nodiscard]] bool is_executable() const {
        return (characteristics & static_cast<uint32_t>(section_characteristics::MEM_EXECUTE)) != 0;
    }

    [[nodiscard]] bool is_discardable() const {
        return (characteristics & static_cast<uint32_t>(section_characteristics::MEM_DISCARDABLE)) != 0;
    }

    [[nodiscard]] bool is_shared() const {
        return (characteristics & static_cast<uint32_t>(section_characteristics::MEM_SHARED)) != 0;
    }

    /// Get aligned raw data offset (applies file alignment rounding)
    [[nodiscard]] uint32_t aligned_raw_offset() const {
        // Per PE/COFF spec: actual offset = (PointerToRawData / FileAlignment) * FileAlignment
        // This is floor rounding to file alignment boundary
        if (file_alignment > 0 && file_alignment <= 0x200) {
            // Apply alignment rounding for low alignment mode
            return (raw_data_offset / file_alignment) * file_alignment;
        }
        return raw_data_offset;
    }

    [[nodiscard]] std::optional<size_t> rva_to_offset(uint32_t rva) const {
        if (rva >= virtual_address && rva < virtual_address + virtual_size) {
            uint32_t offset_in_section = rva - virtual_address;
            if (offset_in_section < raw_data_size) {
                // Use aligned offset for proper file position
                return aligned_raw_offset() + offset_in_section;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] bool contains_rva(uint32_t rva) const {
        return rva >= virtual_address && rva < virtual_address + virtual_size;
    }
};

/**
 * NE Segment
 */
struct LIBEXE_EXPORT ne_segment {
    uint16_t index;
    section_type type;
    uint32_t file_offset;
    uint32_t file_size;
    uint32_t min_alloc_size;
    uint16_t flags;
    std::span<const uint8_t> data;

    [[nodiscard]] bool is_code() const {
        return (flags & static_cast<uint16_t>(ne_segment_flags::DATA)) == 0;
    }

    [[nodiscard]] bool is_data() const {
        return (flags & static_cast<uint16_t>(ne_segment_flags::DATA)) != 0;
    }

    [[nodiscard]] bool is_moveable() const {
        return (flags & static_cast<uint16_t>(ne_segment_flags::MOVEABLE)) != 0;
    }

    [[nodiscard]] bool is_preload() const {
        return (flags & static_cast<uint16_t>(ne_segment_flags::PRELOAD)) != 0;
    }

    [[nodiscard]] bool is_read_only() const {
        return (flags & static_cast<uint16_t>(ne_segment_flags::READ_ONLY)) != 0;
    }

    [[nodiscard]] bool is_discardable() const {
        return (flags & static_cast<uint16_t>(ne_segment_flags::DISCARDABLE)) != 0;
    }

    [[nodiscard]] bool has_relocations() const {
        return (flags & static_cast<uint16_t>(ne_segment_flags::RELOC_INFO)) != 0;
    }
};

} // namespace libexe

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // LIBEXE_PE_SECTION_HPP
