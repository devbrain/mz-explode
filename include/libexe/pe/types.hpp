// libexe - Modern executable file analysis library
// Copyright (c) 2024

/**
 * @file types.hpp
 * @brief PE (Portable Executable) type definitions and enumerations.
 *
 * This header defines the core types and constants used throughout the
 * PE file parser, including machine types, characteristics flags,
 * subsystem types, and data directory indices.
 *
 * All enumerations use bitmask operators where appropriate, enabled via
 * the enable_bitmask_operators template specialization.
 *
 * @see pe_file, enum_bitmask.hpp
 */

#ifndef LIBEXE_PE_TYPES_HPP
#define LIBEXE_PE_TYPES_HPP

#include <libexe/core/enum_bitmask.hpp>
#include <cstdint>

namespace libexe {

/**
 * @brief PE Machine Type (CPU architecture).
 *
 * Identifies the target processor architecture for the executable.
 * The machine type is stored in the COFF file header.
 *
 * @note The most common values are I386 (x86), AMD64 (x64), and ARM64.
 */
enum class pe_machine_type : uint16_t {
    UNKNOWN   = 0x0000,  ///< Unknown or not specified
    AM33      = 0x01D3,  ///< Matsushita AM33
    AMD64     = 0x8664,  ///< x64 (AMD64/Intel 64)
    ARM       = 0x01C0,  ///< ARM little endian
    ARM64     = 0xAA64,  ///< ARM64 little endian
    ARMNT     = 0x01C4,  ///< ARM Thumb-2 little endian
    EBC       = 0x0EBC,  ///< EFI byte code
    I386      = 0x014C,  ///< Intel 386 or later (x86)
    IA64      = 0x0200,  ///< Intel Itanium
    M32R      = 0x9041,  ///< Mitsubishi M32R little endian
    MIPS16    = 0x0266,  ///< MIPS16
    MIPSFPU   = 0x0366,  ///< MIPS with FPU
    MIPSFPU16 = 0x0466,  ///< MIPS16 with FPU
    POWERPC   = 0x01F0,  ///< PowerPC little endian
    POWERPCFP = 0x01F1,  ///< PowerPC with floating point support
    R4000     = 0x0166,  ///< MIPS R4000
    RISCV32   = 0x5032,  ///< RISC-V 32-bit address space
    RISCV64   = 0x5064,  ///< RISC-V 64-bit address space
    RISCV128  = 0x5128,  ///< RISC-V 128-bit address space
    SH3       = 0x01A2,  ///< Hitachi SH3
    SH3DSP    = 0x01A3,  ///< Hitachi SH3 DSP
    SH4       = 0x01A6,  ///< Hitachi SH4
    SH5       = 0x01A8,  ///< Hitachi SH5
    THUMB     = 0x01C2,  ///< ARM Thumb
    WCEMIPSV2 = 0x0169,  ///< MIPS WCE v2
};

/**
 * @brief PE File Characteristics (COFF header flags).
 *
 * Flags indicating properties of the executable file.
 * These flags are stored in the COFF file header's Characteristics field.
 *
 * @par Common combinations:
 * - Executable: EXECUTABLE_IMAGE
 * - DLL: EXECUTABLE_IMAGE | DLL
 * - Large address aware 32-bit: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
 */
enum class pe_file_characteristics : uint16_t {
    RELOCS_STRIPPED       = 0x0001,  ///< Relocations stripped (fixed base only)
    EXECUTABLE_IMAGE      = 0x0002,  ///< File is executable (no unresolved refs)
    LINE_NUMS_STRIPPED    = 0x0004,  ///< COFF line numbers removed (deprecated)
    LOCAL_SYMS_STRIPPED   = 0x0008,  ///< COFF symbol table stripped (deprecated)
    AGGRESSIVE_WS_TRIM    = 0x0010,  ///< Aggressively trim working set (deprecated)
    LARGE_ADDRESS_AWARE   = 0x0020,  ///< Can handle >2GB addresses
    BYTES_REVERSED_LO     = 0x0080,  ///< Little endian (deprecated)
    MACHINE_32BIT         = 0x0100,  ///< 32-bit word machine
    DEBUG_STRIPPED        = 0x0200,  ///< Debug info removed from image
    REMOVABLE_RUN_FROM_SWAP = 0x0400,  ///< Copy to swap if on removable media
    NET_RUN_FROM_SWAP     = 0x0800,  ///< Copy to swap if on network
    SYSTEM                = 0x1000,  ///< System file (e.g., driver)
    DLL                   = 0x2000,  ///< File is a DLL
    UP_SYSTEM_ONLY        = 0x4000,  ///< Uniprocessor machine only
    BYTES_REVERSED_HI     = 0x8000,  ///< Big endian (deprecated)
};

/**
 * @brief PE Subsystem (Windows subsystem type).
 *
 * Identifies the Windows subsystem required to run the executable.
 * This determines how Windows treats the process at startup.
 */
enum class pe_subsystem : uint16_t {
    UNKNOWN                  = 0,   ///< Unknown subsystem
    NATIVE                   = 1,   ///< Device drivers and native NT processes
    WINDOWS_GUI              = 2,   ///< Windows GUI application
    WINDOWS_CUI              = 3,   ///< Windows console application
    OS2_CUI                  = 5,   ///< OS/2 console application
    POSIX_CUI                = 7,   ///< POSIX console application
    NATIVE_WINDOWS           = 8,   ///< Native Windows 9x driver
    WINDOWS_CE_GUI           = 9,   ///< Windows CE GUI application
    EFI_APPLICATION          = 10,  ///< EFI application
    EFI_BOOT_SERVICE_DRIVER  = 11,  ///< EFI boot service driver
    EFI_RUNTIME_DRIVER       = 12,  ///< EFI runtime driver
    EFI_ROM                  = 13,  ///< EFI ROM image
    XBOX                     = 14,  ///< Xbox application
    WINDOWS_BOOT_APPLICATION = 16,  ///< Windows boot application
};

/**
 * @brief PE DLL Characteristics (security and loader flags).
 *
 * Flags controlling security features and loader behavior.
 * These are critical for security analysis as they indicate
 * which exploit mitigations are enabled.
 *
 * @par Security-relevant flags:
 * - HIGH_ENTROPY_VA: High-entropy 64-bit ASLR
 * - DYNAMIC_BASE: ASLR enabled
 * - NX_COMPAT: DEP/NX enabled
 * - GUARD_CF: Control Flow Guard enabled
 */
enum class pe_dll_characteristics : uint16_t {
    HIGH_ENTROPY_VA     = 0x0020,  ///< 64-bit ASLR with high entropy
    DYNAMIC_BASE        = 0x0040,  ///< ASLR enabled (can be relocated)
    FORCE_INTEGRITY     = 0x0080,  ///< Require code signing verification
    NX_COMPAT           = 0x0100,  ///< DEP/NX compatible
    NO_ISOLATION        = 0x0200,  ///< No isolation (side-by-side assemblies)
    NO_SEH              = 0x0400,  ///< No structured exception handling
    NO_BIND             = 0x0800,  ///< Do not bind image
    APPCONTAINER        = 0x1000,  ///< Must run in AppContainer
    WDM_DRIVER          = 0x2000,  ///< WDM driver
    GUARD_CF            = 0x4000,  ///< Control Flow Guard enabled
    TERMINAL_SERVER_AWARE = 0x8000,  ///< Terminal Server aware
};

/**
 * @brief PE Section Characteristics (section flags).
 *
 * Flags describing section properties including content type,
 * memory permissions, and alignment requirements.
 *
 * @par Memory permission flags:
 * - MEM_EXECUTE: Execute permission
 * - MEM_READ: Read permission
 * - MEM_WRITE: Write permission
 *
 * @par Content type flags:
 * - CNT_CODE: Contains executable code
 * - CNT_INITIALIZED_DATA: Contains initialized data
 * - CNT_UNINITIALIZED_DATA: Contains uninitialized data (BSS)
 */
enum class pe_section_characteristics : uint32_t {
    TYPE_NO_PAD           = 0x00000008,  ///< Don't pad to next boundary (deprecated)
    CNT_CODE              = 0x00000020,  ///< Contains executable code
    CNT_INITIALIZED_DATA  = 0x00000040,  ///< Contains initialized data
    CNT_UNINITIALIZED_DATA = 0x00000080, ///< Contains uninitialized data
    LNK_OTHER             = 0x00000100,  ///< Reserved for linker use
    LNK_INFO              = 0x00000200,  ///< Contains comments or other info
    LNK_REMOVE            = 0x00000800,  ///< Will not become part of image
    LNK_COMDAT            = 0x00001000,  ///< Contains COMDAT data
    GPREL                 = 0x00008000,  ///< Contains data referenced via GP
    MEM_PURGEABLE         = 0x00020000,  ///< Reserved (same as MEM_16BIT)
    MEM_16BIT             = 0x00020000,  ///< Reserved (same as MEM_PURGEABLE)
    MEM_LOCKED            = 0x00040000,  ///< Reserved
    MEM_PRELOAD           = 0x00080000,  ///< Reserved
    ALIGN_1BYTES          = 0x00100000,  ///< Align to 1-byte boundary
    ALIGN_2BYTES          = 0x00200000,  ///< Align to 2-byte boundary
    ALIGN_4BYTES          = 0x00300000,  ///< Align to 4-byte boundary
    ALIGN_8BYTES          = 0x00400000,  ///< Align to 8-byte boundary
    ALIGN_16BYTES         = 0x00500000,  ///< Align to 16-byte boundary
    ALIGN_32BYTES         = 0x00600000,  ///< Align to 32-byte boundary
    ALIGN_64BYTES         = 0x00700000,  ///< Align to 64-byte boundary
    ALIGN_128BYTES        = 0x00800000,  ///< Align to 128-byte boundary
    ALIGN_256BYTES        = 0x00900000,  ///< Align to 256-byte boundary
    ALIGN_512BYTES        = 0x00A00000,  ///< Align to 512-byte boundary
    ALIGN_1024BYTES       = 0x00B00000,  ///< Align to 1024-byte boundary
    ALIGN_2048BYTES       = 0x00C00000,  ///< Align to 2048-byte boundary
    ALIGN_4096BYTES       = 0x00D00000,  ///< Align to 4096-byte boundary
    ALIGN_8192BYTES       = 0x00E00000,  ///< Align to 8192-byte boundary
    LNK_NRELOC_OVFL       = 0x01000000,  ///< Contains extended relocations
    MEM_DISCARDABLE       = 0x02000000,  ///< Can be discarded as needed
    MEM_NOT_CACHED        = 0x04000000,  ///< Cannot be cached
    MEM_NOT_PAGED         = 0x08000000,  ///< Not pageable
    MEM_SHARED            = 0x10000000,  ///< Can be shared in memory
    MEM_EXECUTE           = 0x20000000,  ///< Can be executed as code
    MEM_READ              = 0x40000000,  ///< Can be read
    MEM_WRITE             = 0x80000000,  ///< Can be written to
};

/**
 * @brief PE Data Directory Entry (indices into DataDirectory array).
 *
 * The PE optional header contains an array of 16 data directory entries.
 * Each entry describes the location and size of a specific data structure.
 *
 * @par Commonly used directories:
 * - EXPORT: Exported functions
 * - IMPORT: Imported functions
 * - RESOURCE: Resources (icons, dialogs, etc.)
 * - BASERELOC: Base relocations
 * - SECURITY: Authenticode signature
 * - DEBUG: Debug information
 */
enum class directory_entry : uint32_t {
    EXPORT          = 0,   ///< Export directory
    IMPORT          = 1,   ///< Import directory
    RESOURCE        = 2,   ///< Resource directory
    EXCEPTION       = 3,   ///< Exception directory (.pdata)
    SECURITY        = 4,   ///< Security directory (Authenticode)
    BASERELOC       = 5,   ///< Base relocation table
    DEBUG           = 6,   ///< Debug directory
    ARCHITECTURE    = 7,   ///< Architecture-specific data (reserved)
    GLOBALPTR       = 8,   ///< Global pointer register RVA
    TLS             = 9,   ///< Thread local storage directory
    LOAD_CONFIG     = 10,  ///< Load configuration directory
    BOUND_IMPORT    = 11,  ///< Bound import directory
    IAT             = 12,  ///< Import address table
    DELAY_IMPORT    = 13,  ///< Delay import descriptor
    COM_DESCRIPTOR  = 14,  ///< CLR runtime header (.NET)
    RESERVED        = 15   ///< Reserved (must be zero)
};

// Enable bitmask operators for flag enums

/// @brief Enable bitmask operators for pe_file_characteristics.
template<>
struct enable_bitmask_operators <pe_file_characteristics> {
    static constexpr bool enable = true;
};

/// @brief Enable bitmask operators for pe_dll_characteristics.
template<>
struct enable_bitmask_operators <pe_dll_characteristics> {
    static constexpr bool enable = true;
};

/// @brief Enable bitmask operators for pe_section_characteristics.
template<>
struct enable_bitmask_operators <pe_section_characteristics> {
    static constexpr bool enable = true;
};

} // namespace libexe

#endif // LIBEXE_PE_TYPES_HPP
