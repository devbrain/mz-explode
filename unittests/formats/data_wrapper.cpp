// Data wrapper for PE/NE format test files
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
}

// Include test data implementations
#include "testdata/progman.cc"
#include "testdata/cga40woa_fon.cc"
#include "testdata/tcmadm64.cc"
#include "testdata/tcmdx32.cc"
