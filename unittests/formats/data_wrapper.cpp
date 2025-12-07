// Data wrapper for PE/NE format test files
// Includes all test data arrays with proper headers

#include <cstddef>

namespace data {
    // Forward declarations
    extern size_t progman_len;
    extern unsigned char progman[];

    extern size_t cga40woa_fon_len;
    extern unsigned char cga40woa_fon[];
}

// Include test data implementations
#include "testdata/progman.cc"
#include "testdata/cga40woa_fon.cc"
