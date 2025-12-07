// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_NE_TYPES_HPP
#define LIBEXE_NE_TYPES_HPP

#include <libexe/enum_bitmask.hpp>
#include <cstdint>

namespace libexe {
    /// NE File Flags (NE header flags at offset 0Ch)
    /// Specifies data segment type and module characteristics
    enum class ne_file_flags : uint16_t {
        NOAUTODATA = 0x0000, // No automatic data segment
        SINGLEDATA = 0x0001, // Shared automatic data segment
        MULTIPLEDATA = 0x0002, // Instanced automatic data segment
        LINK_ERROR = 0x2000, // Errors detected at link time, module will not load
        LIBRARY_MODULE = 0x8000, // Library module (DLL), not a program
    };

    /// NE Target Operating System (at offset 36h)
    /// Specifies which OS the executable is designed for
    enum class ne_target_os : uint8_t {
        UNKNOWN = 0x00, // Unknown target
        OS2 = 0x01, // OS/2
        WINDOWS = 0x02, // Windows 16-bit
        DOS4 = 0x03, // European MS-DOS 4.x
        WIN386 = 0x04, // Windows 386
        BOSS = 0x05, // BOSS (Borland Operating System Services)
    };

    /// NE Segment Flags (segment table entry flags)
    /// Controls segment type, memory management, and relocation
    enum class ne_segment_flags : uint16_t {
        TYPE_MASK = 0x0007, // Segment type field mask
        CODE = 0x0000, // Code segment type
        DATA = 0x0001, // Data segment type
        MOVEABLE = 0x0010, // Segment is not fixed (can be moved)
        PRELOAD = 0x0040, // Segment will be preloaded; read-only if data segment
        RELOCINFO = 0x0100, // Set if segment has relocation records
        DISCARD_MASK = 0xF000, // Discard priority bits (higher = more discardable)
    };

    // ============================================================================
    // Enable bitmask operators for NE flag types
    // ============================================================================

    // Specialize enable_bitmask_operators for NE bitmask types
    template<>
    struct enable_bitmask_operators <ne_file_flags> {
        static constexpr bool enable = true;
    };

    template<>
    struct enable_bitmask_operators <ne_segment_flags> {
        static constexpr bool enable = true;
    };
} // namespace libexe

#endif // LIBEXE_NE_TYPES_HPP
