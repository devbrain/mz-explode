// Data wrapper for PE/NE format test files
// Includes all test data arrays with proper headers

#include <cstddef>

namespace data {
    // Forward declarations
    extern size_t progman_len;
    extern unsigned char progman[];
}

// Include test data implementations
#include "testdata/progman.cc"
