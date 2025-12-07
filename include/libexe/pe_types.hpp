// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_PE_TYPES_HPP
#define LIBEXE_PE_TYPES_HPP

#include <libexe/enum_bitmask.hpp>
#include <cstdint>

namespace libexe {
    /// PE Machine Type (CPU architecture)
    enum class pe_machine_type : uint16_t {
        UNKNOWN = 0x0000, // Unknown machine
        AM33 = 0x01D3, // Matsushita AM33
        AMD64 = 0x8664, // x64 (AMD64/Intel 64)
        ARM = 0x01C0, // ARM little endian
        ARM64 = 0xAA64, // ARM64 (AArch64)
        ARMNT = 0x01C4, // ARM Thumb-2 little endian
        EBC = 0x0EBC, // EFI byte code
        I386 = 0x014C, // Intel 386 or later (x86)
        IA64 = 0x0200, // Intel Itanium
        M32R = 0x9041, // Mitsubishi M32R little endian
        MIPS16 = 0x0266, // MIPS16
        MIPSFPU = 0x0366, // MIPS with FPU
        MIPSFPU16 = 0x0466, // MIPS16 with FPU
        POWERPC = 0x01F0, // Power PC little endian
        POWERPCFP = 0x01F1, // Power PC with floating point support
        R4000 = 0x0166, // MIPS little endian
        RISCV32 = 0x5032, // RISC-V 32-bit
        RISCV64 = 0x5064, // RISC-V 64-bit
        RISCV128 = 0x5128, // RISC-V 128-bit
        SH3 = 0x01A2, // Hitachi SH3
        SH3DSP = 0x01A3, // Hitachi SH3 DSP
        SH4 = 0x01A6, // Hitachi SH4
        SH5 = 0x01A8, // Hitachi SH5
        THUMB = 0x01C2, // Thumb
        WCEMIPSV2 = 0x0169, // MIPS little-endian WCE v2
    };

    /// PE File Characteristics (COFF header flags)
    enum class pe_file_characteristics : uint16_t {
        RELOCS_STRIPPED = 0x0001, // Relocation info stripped
        EXECUTABLE_IMAGE = 0x0002, // File is executable
        LINE_NUMS_STRIPPED = 0x0004, // Line numbers stripped
        LOCAL_SYMS_STRIPPED = 0x0008, // Local symbols stripped
        AGGRESSIVE_WS_TRIM = 0x0010, // Aggressively trim working set
        LARGE_ADDRESS_AWARE = 0x0020, // Can handle >2GB addresses
        BYTES_REVERSED_LO = 0x0080, // Little endian
        MACHINE_32BIT = 0x0100, // 32-bit machine
        DEBUG_STRIPPED = 0x0200, // Debug info stripped
        REMOVABLE_RUN_FROM_SWAP = 0x0400, // Run from swap if on removable media
        NET_RUN_FROM_SWAP = 0x0800, // Run from swap if on network
        SYSTEM = 0x1000, // System file
        DLL = 0x2000, // Dynamic link library
        UP_SYSTEM_ONLY = 0x4000, // Uniprocessor only
        BYTES_REVERSED_HI = 0x8000, // Big endian
    };

    /// PE Subsystem (Windows subsystem type)
    enum class pe_subsystem : uint16_t {
        UNKNOWN = 0, // Unknown subsystem
        NATIVE = 1, // Device drivers and native processes
        WINDOWS_GUI = 2, // Windows GUI subsystem
        WINDOWS_CUI = 3, // Windows console subsystem
        OS2_CUI = 5, // OS/2 console subsystem
        POSIX_CUI = 7, // POSIX console subsystem
        NATIVE_WINDOWS = 8, // Native Win9x driver
        WINDOWS_CE_GUI = 9, // Windows CE
        EFI_APPLICATION = 10, // EFI application
        EFI_BOOT_SERVICE_DRIVER = 11, // EFI driver with boot services
        EFI_RUNTIME_DRIVER = 12, // EFI driver with runtime services
        EFI_ROM = 13, // EFI ROM image
        XBOX = 14, // XBOX
        WINDOWS_BOOT_APPLICATION = 16, // Windows boot application
    };

    /// PE DLL Characteristics (DLL flags)
    enum class pe_dll_characteristics : uint16_t {
        HIGH_ENTROPY_VA = 0x0020, // Can use high entropy 64-bit VA space
        DYNAMIC_BASE = 0x0040, // DLL can be relocated at load (ASLR)
        FORCE_INTEGRITY = 0x0080, // Code integrity checks enforced
        NX_COMPAT = 0x0100, // Compatible with DEP (Data Execution Prevention)
        NO_ISOLATION = 0x0200, // No isolation
        NO_SEH = 0x0400, // No structured exception handling
        NO_BIND = 0x0800, // Do not bind image
        APPCONTAINER = 0x1000, // Must run in AppContainer
        WDM_DRIVER = 0x2000, // WDM driver
        GUARD_CF = 0x4000, // Control Flow Guard supported
        TERMINAL_SERVER_AWARE = 0x8000, // Terminal Server aware
    };

    /// PE Section Characteristics (section flags)
    enum class pe_section_characteristics : uint32_t {
        TYPE_NO_PAD = 0x00000008, // Section should not be padded
        CNT_CODE = 0x00000020, // Section contains code
        CNT_INITIALIZED_DATA = 0x00000040, // Section contains initialized data
        CNT_UNINITIALIZED_DATA = 0x00000080, // Section contains uninitialized data
        LNK_OTHER = 0x00000100, // Reserved
        LNK_INFO = 0x00000200, // Section contains comments/info
        LNK_REMOVE = 0x00000800, // Section will not be part of image
        LNK_COMDAT = 0x00001000, // Section contains COMDAT data
        GPREL = 0x00008000, // Section contains GP-relative data
        MEM_PURGEABLE = 0x00020000, // Reserved
        MEM_16BIT = 0x00020000, // Reserved
        MEM_LOCKED = 0x00040000, // Reserved
        MEM_PRELOAD = 0x00080000, // Reserved
        ALIGN_1BYTES = 0x00100000, // Align data on 1-byte boundary
        ALIGN_2BYTES = 0x00200000, // Align data on 2-byte boundary
        ALIGN_4BYTES = 0x00300000, // Align data on 4-byte boundary
        ALIGN_8BYTES = 0x00400000, // Align data on 8-byte boundary
        ALIGN_16BYTES = 0x00500000, // Align data on 16-byte boundary
        ALIGN_32BYTES = 0x00600000, // Align data on 32-byte boundary
        ALIGN_64BYTES = 0x00700000, // Align data on 64-byte boundary
        ALIGN_128BYTES = 0x00800000, // Align data on 128-byte boundary
        ALIGN_256BYTES = 0x00900000, // Align data on 256-byte boundary
        ALIGN_512BYTES = 0x00A00000, // Align data on 512-byte boundary
        ALIGN_1024BYTES = 0x00B00000, // Align data on 1024-byte boundary
        ALIGN_2048BYTES = 0x00C00000, // Align data on 2048-byte boundary
        ALIGN_4096BYTES = 0x00D00000, // Align data on 4096-byte boundary
        ALIGN_8192BYTES = 0x00E00000, // Align data on 8192-byte boundary
        LNK_NRELOC_OVFL = 0x01000000, // Section contains extended relocations
        MEM_DISCARDABLE = 0x02000000, // Section can be discarded
        MEM_NOT_CACHED = 0x04000000, // Section cannot be cached
        MEM_NOT_PAGED = 0x08000000, // Section is not pageable
        MEM_SHARED = 0x10000000, // Section can be shared in memory
        MEM_EXECUTE = 0x20000000, // Section can be executed as code
        MEM_READ = 0x40000000, // Section is readable
        MEM_WRITE = 0x80000000, // Section is writable
    };

    // ============================================================================
    // Enable bitmask operators for PE flag types
    // ============================================================================

    // Specialize enable_bitmask_operators for PE bitmask types
    template<>
    struct enable_bitmask_operators <pe_file_characteristics> {
        static constexpr bool enable = true;
    };

    template<>
    struct enable_bitmask_operators <pe_dll_characteristics> {
        static constexpr bool enable = true;
    };

    template<>
    struct enable_bitmask_operators <pe_section_characteristics> {
        static constexpr bool enable = true;
    };
} // namespace libexe

#endif // LIBEXE_PE_TYPES_HPP
