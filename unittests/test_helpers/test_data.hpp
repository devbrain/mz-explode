// libexe - Modern executable file analysis library
// Copyright (c) 2024
// Shared declarations for embedded test data
//
// All test data is embedded as byte arrays in .cc files and linked
// into the test executable. This header provides declarations for
// all embedded test files to avoid duplication across test files.

#ifndef LIBEXE_TEST_HELPERS_TEST_DATA_HPP
#define LIBEXE_TEST_HELPERS_TEST_DATA_HPP

#include <cstddef>
#include <cstdint>

namespace data {

// =============================================================================
// PE Format Test Files
// =============================================================================

// scheduler.exe - PE32 Windows executable (Teleport Scheduler)
// Used for: import parser, export parser, relocation parser, dialog parser, etc.
extern size_t scheduler_len;
extern unsigned char scheduler[];

// tcmadm64.exe - PE32+ (64-bit) Total Commander admin helper
// Used for: PE64 format tests, section parser tests
extern size_t tcmadm64_len;
extern unsigned char tcmadm64[];

// tcmdx32.exe - PE32 Total Commander x32 plugin
// Used for: PE32 format tests
extern size_t tcmdx32_len;
extern unsigned char tcmdx32[];

// =============================================================================
// NE Format Test Files (Windows 16-bit)
// =============================================================================

// PROGMAN.EXE - Windows 3.11 Program Manager
// Used for: NE format tests, resource tests, dialog/menu/string tests
extern size_t progman_len;
extern unsigned char progman[];

// CGA40WOA.FON - Windows 3.11 CGA font
// Used for: NE font tests
extern size_t cga40woa_fon_len;
extern unsigned char cga40woa_fon[];

// SYSFONT.NE - System font (NE OS/2 format)
extern size_t sysfont_ne_len;
extern unsigned char sysfont_ne[];

// =============================================================================
// LE/LX Format Test Files (OS/2 and DOS Extenders)
// =============================================================================

// STRACE.EXE - OS/2 LX executable
extern size_t strace_lx_len;
extern unsigned char strace_lx[];

// CMD.EXE - OS/2 LX command processor
extern size_t cmd_lx_len;
extern unsigned char cmd_lx[];

// 7Z.EXE - 7-Zip for OS/2 (LX format)
extern size_t sevenz_lx_len;
extern unsigned char sevenz_lx[];

// DOOM.EXE - DOS4GW LE executable
extern size_t doom_le_len;
extern unsigned char doom_le[];

// MAKEINI.EXE - OS/2 LX with resources
extern size_t makeini_lx_len;
extern unsigned char makeini_lx[];

// OS2CHESS.EXE - OS/2 chess game (LX with resources)
// Used for: OS/2 resource parser tests (dialogs, menus, accelerators, etc.)
extern size_t os2chess_lx_len;
extern unsigned char os2chess_lx[];

// =============================================================================
// Corkami PE Test Corpus
// https://github.com/corkami/pocs/tree/master/PE
// =============================================================================

extern size_t _65535sects_len;
extern unsigned char _65535sects[];

extern size_t cfgbogus_len;
extern unsigned char cfgbogus[];

extern size_t compiled_len;
extern unsigned char compiled[];

extern size_t debug_len;
extern unsigned char debug[];

extern size_t delayimports_len;
extern unsigned char delayimports[];

extern size_t dll_len;
extern unsigned char dll[];

extern size_t dllbound_len;
extern unsigned char dllbound[];

extern size_t dllfwloop_len;
extern unsigned char dllfwloop[];

extern size_t dllnoreloc_len;
extern unsigned char dllnoreloc[];

extern size_t dllord_len;
extern unsigned char dllord[];

extern size_t dotnet20_len;
extern unsigned char dotnet20[];

extern size_t fakerelocs_len;
extern unsigned char fakerelocs[];

extern size_t ibreloc_len;
extern unsigned char ibreloc[];

extern size_t impbyord_len;
extern unsigned char impbyord[];

extern size_t imports_len;
extern unsigned char imports[];

extern size_t imports_mixed_len;
extern unsigned char imports_mixed[];

extern size_t maxsec_lowaligw7_len;
extern unsigned char maxsec_lowaligw7[];

extern size_t signature_len;
extern unsigned char signature[];

extern size_t tinynet_len;
extern unsigned char tinynet[];

extern size_t tls_len;
extern unsigned char tls[];

extern size_t tls64_len;
extern unsigned char tls64[];

extern size_t tls_aoi_len;
extern unsigned char tls_aoi[];

// =============================================================================
// Compressed Executable Test Files (Decompressor Tests)
// =============================================================================

// PKLITE compressed files
extern size_t pklite_112_len;
extern unsigned char pklite_112[];

extern size_t pklite_115_len;
extern unsigned char pklite_115[];

extern size_t pklite_150_len;
extern unsigned char pklite_150[];

extern size_t pklite_E_112_len;
extern unsigned char pklite_E_112[];

extern size_t pklite_E_115_len;
extern unsigned char pklite_E_115[];

// LZEXE compressed files
extern size_t z90_len;
extern unsigned char z90[];

extern size_t z91_len;
extern unsigned char z91[];

extern size_t z91_E_len;
extern unsigned char z91_E[];

// Knowledge Dynamics compressed files
extern size_t knowledge_dynamics_DOT_len;
extern unsigned char knowledge_dynamics_DOT[];

extern size_t knowledge_dynamics_LEX_len;
extern unsigned char knowledge_dynamics_LEX[];

extern size_t knowledge_dynamics_TNT_len;
extern unsigned char knowledge_dynamics_TNT[];

// EXEPACK compressed files
extern size_t exepack_hello_len;
extern unsigned char exepack_hello[];

extern size_t exepack_masm400_len;
extern unsigned char exepack_masm400[];

extern size_t exepack_masm500_len;
extern unsigned char exepack_masm500[];

extern size_t exepack_masm510_len;
extern unsigned char exepack_masm510[];

} // namespace data

#endif // LIBEXE_TEST_HELPERS_TEST_DATA_HPP
