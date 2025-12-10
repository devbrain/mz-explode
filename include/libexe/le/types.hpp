// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_LE_TYPES_HPP
#define LIBEXE_LE_TYPES_HPP

#include <cstdint>

namespace libexe {

/// DOS extender type (detected from MZ stub signature)
/// This is not part of the LE/LX format itself, but detected from the stub
enum class dos_extender_type : uint8_t {
    NONE,               // No extender / not applicable (raw LE/LX)
    UNKNOWN,            // Has extender but type unknown
    DOS32A,             // DOS/32 Advanced
    STUB32A,            // DOS/32A stub variant
    STUB32C,            // DOS/32A compressed stub
    DOS4G,              // DOS/4G
    DOS4GW,             // DOS/4G Professional (Watcom)
    PMODEW,             // PMODE/W
    CAUSEWAY,           // CauseWay
    WDOSX,              // WDOSX
    CWSDPMI,            // CWSDPMI (DJGPP)
};

} // namespace libexe

#endif // LIBEXE_LE_TYPES_HPP
