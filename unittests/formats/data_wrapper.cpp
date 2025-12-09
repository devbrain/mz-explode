// Data wrapper for PE/NE/LX format test files
// Includes all test data arrays with proper headers

#include <cstddef>

namespace data {
    // Forward declarations - NE format
    extern size_t progman_len;
    extern unsigned char progman[];

    extern size_t cga40woa_fon_len;
    extern unsigned char cga40woa_fon[];

    // Forward declarations - PE format
    extern size_t tcmadm64_len;
    extern unsigned char tcmadm64[];

    extern size_t tcmdx32_len;
    extern unsigned char tcmdx32[];

    // Forward declarations - LX format (OS/2)
    extern size_t strace_lx_len;
    extern unsigned char strace_lx[];

    extern size_t cmd_lx_len;
    extern unsigned char cmd_lx[];

    extern size_t sevenz_lx_len;
    extern unsigned char sevenz_lx[];

    // Forward declarations - LE format (DOS extenders)
    extern size_t doom_le_len;
    extern unsigned char doom_le[];
}

// Include test data implementations
#include "testdata/progman.cc"
#include "testdata/cga40woa_fon.cc"
#include "testdata/tcmadm64.cc"
#include "testdata/tcmdx32.cc"
#include "testdata/strace_lx.cc"
#include "testdata/cmd_lx.cc"
#include "testdata/7z_lx.cc"
#include "testdata/doom_le.cc"
