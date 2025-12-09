// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_PE_TYPES_HPP
#define LIBEXE_PE_TYPES_HPP

#include <libexe/core/enum_bitmask.hpp>
#include <cstdint>

namespace libexe {
    /// PE Machine Type (CPU architecture)
    enum class pe_machine_type : uint16_t {
        UNKNOWN = 0x0000,
        AM33 = 0x01D3,
        AMD64 = 0x8664,
        ARM = 0x01C0,
        ARM64 = 0xAA64,
        ARMNT = 0x01C4,
        EBC = 0x0EBC,
        I386 = 0x014C,
        IA64 = 0x0200,
        M32R = 0x9041,
        MIPS16 = 0x0266,
        MIPSFPU = 0x0366,
        MIPSFPU16 = 0x0466,
        POWERPC = 0x01F0,
        POWERPCFP = 0x01F1,
        R4000 = 0x0166,
        RISCV32 = 0x5032,
        RISCV64 = 0x5064,
        RISCV128 = 0x5128,
        SH3 = 0x01A2,
        SH3DSP = 0x01A3,
        SH4 = 0x01A6,
        SH5 = 0x01A8,
        THUMB = 0x01C2,
        WCEMIPSV2 = 0x0169,
    };

    /// PE File Characteristics (COFF header flags)
    enum class pe_file_characteristics : uint16_t {
        RELOCS_STRIPPED = 0x0001,
        EXECUTABLE_IMAGE = 0x0002,
        LINE_NUMS_STRIPPED = 0x0004,
        LOCAL_SYMS_STRIPPED = 0x0008,
        AGGRESSIVE_WS_TRIM = 0x0010,
        LARGE_ADDRESS_AWARE = 0x0020,
        BYTES_REVERSED_LO = 0x0080,
        MACHINE_32BIT = 0x0100,
        DEBUG_STRIPPED = 0x0200,
        REMOVABLE_RUN_FROM_SWAP = 0x0400,
        NET_RUN_FROM_SWAP = 0x0800,
        SYSTEM = 0x1000,
        DLL = 0x2000,
        UP_SYSTEM_ONLY = 0x4000,
        BYTES_REVERSED_HI = 0x8000,
    };

    /// PE Subsystem (Windows subsystem type)
    enum class pe_subsystem : uint16_t {
        UNKNOWN = 0,
        NATIVE = 1,
        WINDOWS_GUI = 2,
        WINDOWS_CUI = 3,
        OS2_CUI = 5,
        POSIX_CUI = 7,
        NATIVE_WINDOWS = 8,
        WINDOWS_CE_GUI = 9,
        EFI_APPLICATION = 10,
        EFI_BOOT_SERVICE_DRIVER = 11,
        EFI_RUNTIME_DRIVER = 12,
        EFI_ROM = 13,
        XBOX = 14,
        WINDOWS_BOOT_APPLICATION = 16,
    };

    /// PE DLL Characteristics (DLL flags)
    enum class pe_dll_characteristics : uint16_t {
        HIGH_ENTROPY_VA = 0x0020,
        DYNAMIC_BASE = 0x0040,
        FORCE_INTEGRITY = 0x0080,
        NX_COMPAT = 0x0100,
        NO_ISOLATION = 0x0200,
        NO_SEH = 0x0400,
        NO_BIND = 0x0800,
        APPCONTAINER = 0x1000,
        WDM_DRIVER = 0x2000,
        GUARD_CF = 0x4000,
        TERMINAL_SERVER_AWARE = 0x8000,
    };

    /// PE Section Characteristics (section flags)
    enum class pe_section_characteristics : uint32_t {
        TYPE_NO_PAD = 0x00000008,
        CNT_CODE = 0x00000020,
        CNT_INITIALIZED_DATA = 0x00000040,
        CNT_UNINITIALIZED_DATA = 0x00000080,
        LNK_OTHER = 0x00000100,
        LNK_INFO = 0x00000200,
        LNK_REMOVE = 0x00000800,
        LNK_COMDAT = 0x00001000,
        GPREL = 0x00008000,
        MEM_PURGEABLE = 0x00020000,
        MEM_16BIT = 0x00020000,
        MEM_LOCKED = 0x00040000,
        MEM_PRELOAD = 0x00080000,
        ALIGN_1BYTES = 0x00100000,
        ALIGN_2BYTES = 0x00200000,
        ALIGN_4BYTES = 0x00300000,
        ALIGN_8BYTES = 0x00400000,
        ALIGN_16BYTES = 0x00500000,
        ALIGN_32BYTES = 0x00600000,
        ALIGN_64BYTES = 0x00700000,
        ALIGN_128BYTES = 0x00800000,
        ALIGN_256BYTES = 0x00900000,
        ALIGN_512BYTES = 0x00A00000,
        ALIGN_1024BYTES = 0x00B00000,
        ALIGN_2048BYTES = 0x00C00000,
        ALIGN_4096BYTES = 0x00D00000,
        ALIGN_8192BYTES = 0x00E00000,
        LNK_NRELOC_OVFL = 0x01000000,
        MEM_DISCARDABLE = 0x02000000,
        MEM_NOT_CACHED = 0x04000000,
        MEM_NOT_PAGED = 0x08000000,
        MEM_SHARED = 0x10000000,
        MEM_EXECUTE = 0x20000000,
        MEM_READ = 0x40000000,
        MEM_WRITE = 0x80000000,
    };

    /// PE Data Directory Entry (indices into DataDirectory array)
    enum class directory_entry : uint32_t {
        EXPORT = 0,
        IMPORT = 1,
        RESOURCE = 2,
        EXCEPTION = 3,
        SECURITY = 4,
        BASERELOC = 5,
        DEBUG = 6,
        ARCHITECTURE = 7,
        GLOBALPTR = 8,
        TLS = 9,
        LOAD_CONFIG = 10,
        BOUND_IMPORT = 11,
        IAT = 12,
        DELAY_IMPORT = 13,
        COM_DESCRIPTOR = 14,
        RESERVED = 15
    };

    // Enable bitmask operators
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
