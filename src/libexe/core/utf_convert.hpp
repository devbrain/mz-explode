/**
 * UTF-8 / UTF-16 conversion utilities
 *
 * Based on utf8-utf16-converter by Davipb (MIT License)
 * https://github.com/Davipb/utf8-utf16-converter
 *
 * Copyright 2019 Davipb
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies
 * or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef LIBEXE_UTF_CONVERT_HPP
#define LIBEXE_UTF_CONVERT_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace libexe {
namespace detail {

// Unicode codepoint type
using codepoint_t = uint32_t;

// Constants for UTF-16 surrogate handling
constexpr uint16_t BMP_END = 0xFFFF;
constexpr codepoint_t UNICODE_MAX = 0x10FFFF;
constexpr codepoint_t INVALID_CODEPOINT = 0xFFFD;

constexpr uint16_t GENERIC_SURROGATE_VALUE = 0xD800;
constexpr uint16_t GENERIC_SURROGATE_MASK = 0xF800;
constexpr uint16_t HIGH_SURROGATE_VALUE = 0xD800;
constexpr uint16_t LOW_SURROGATE_VALUE = 0xDC00;
constexpr uint16_t SURROGATE_MASK = 0xFC00;
constexpr codepoint_t SURROGATE_CODEPOINT_OFFSET = 0x10000;
constexpr uint16_t SURROGATE_CODEPOINT_MASK = 0x03FF;
constexpr int SURROGATE_CODEPOINT_BITS = 10;

// Constants for UTF-8 encoding
constexpr codepoint_t UTF8_1_MAX = 0x7F;
constexpr codepoint_t UTF8_2_MAX = 0x7FF;
constexpr codepoint_t UTF8_3_MAX = 0xFFFF;
constexpr codepoint_t UTF8_4_MAX = 0x10FFFF;

constexpr uint8_t UTF8_CONTINUATION_VALUE = 0x80;
constexpr uint8_t UTF8_CONTINUATION_MASK = 0xC0;
constexpr int UTF8_CONTINUATION_CODEPOINT_BITS = 6;

// UTF-8 leading byte patterns
struct utf8_pattern {
    uint8_t mask;
    uint8_t value;
};

constexpr utf8_pattern utf8_leading_bytes[] = {
    { 0x80, 0x00 }, // 0xxxxxxx (1 byte)
    { 0xE0, 0xC0 }, // 110xxxxx (2 bytes)
    { 0xF0, 0xE0 }, // 1110xxxx (3 bytes)
    { 0xF8, 0xF0 }  // 11110xxx (4 bytes)
};

// Decode a codepoint from UTF-16
inline codepoint_t decode_utf16(const uint16_t* utf16, size_t len, size_t& index) {
    uint16_t high = utf16[index];

    // BMP character
    if ((high & GENERIC_SURROGATE_MASK) != GENERIC_SURROGATE_VALUE)
        return high;

    // Unmatched low surrogate
    if ((high & SURROGATE_MASK) != HIGH_SURROGATE_VALUE)
        return INVALID_CODEPOINT;

    // String ended with unmatched high surrogate
    if (index == len - 1)
        return INVALID_CODEPOINT;

    uint16_t low = utf16[index + 1];

    // Unmatched high surrogate
    if ((low & SURROGATE_MASK) != LOW_SURROGATE_VALUE)
        return INVALID_CODEPOINT;

    // Consume both surrogates
    index++;

    codepoint_t result = high & SURROGATE_CODEPOINT_MASK;
    result <<= SURROGATE_CODEPOINT_BITS;
    result |= low & SURROGATE_CODEPOINT_MASK;
    result += SURROGATE_CODEPOINT_OFFSET;

    return result;
}

// Calculate UTF-8 length for a codepoint
inline int calculate_utf8_len(codepoint_t codepoint) {
    if (codepoint <= UTF8_1_MAX) return 1;
    if (codepoint <= UTF8_2_MAX) return 2;
    if (codepoint <= UTF8_3_MAX) return 3;
    return 4;
}

// Encode a codepoint as UTF-8
inline size_t encode_utf8(codepoint_t codepoint, std::string& out) {
    int size = calculate_utf8_len(codepoint);

    if (size == 1) {
        out.push_back(static_cast<char>(codepoint));
        return 1;
    }

    // Build bytes in reverse order
    char bytes[4];
    for (int i = size - 1; i > 0; i--) {
        bytes[i] = static_cast<char>((codepoint & ~UTF8_CONTINUATION_MASK) | UTF8_CONTINUATION_VALUE);
        codepoint >>= UTF8_CONTINUATION_CODEPOINT_BITS;
    }

    // Leading byte
    utf8_pattern pattern = utf8_leading_bytes[size - 1];
    bytes[0] = static_cast<char>((codepoint & ~pattern.mask) | pattern.value);

    out.append(bytes, size);
    return size;
}

} // namespace detail

/**
 * Convert UTF-16 string to UTF-8
 *
 * @param utf16 UTF-16 string (little-endian)
 * @return UTF-8 encoded string
 */
inline std::string utf16_to_utf8(const std::u16string& utf16) {
    std::string result;
    result.reserve(utf16.size());  // Minimum size estimate

    const uint16_t* data = reinterpret_cast<const uint16_t*>(utf16.data());
    size_t len = utf16.size();

    for (size_t i = 0; i < len; i++) {
        detail::codepoint_t cp = detail::decode_utf16(data, len, i);
        detail::encode_utf8(cp, result);
    }

    return result;
}

/**
 * Convert UTF-16 vector to UTF-8
 *
 * @param utf16 UTF-16 data as vector of uint16_t
 * @return UTF-8 encoded string
 */
inline std::string utf16_to_utf8(const std::vector<uint16_t>& utf16) {
    std::string result;
    result.reserve(utf16.size());

    for (size_t i = 0; i < utf16.size(); i++) {
        detail::codepoint_t cp = detail::decode_utf16(utf16.data(), utf16.size(), i);
        detail::encode_utf8(cp, result);
    }

    return result;
}

/**
 * Convert UTF-16 raw pointer to UTF-8
 *
 * @param utf16 Pointer to UTF-16 data
 * @param len Length in 16-bit units
 * @return UTF-8 encoded string
 */
inline std::string utf16_to_utf8(const uint16_t* utf16, size_t len) {
    std::string result;
    result.reserve(len);

    for (size_t i = 0; i < len; i++) {
        detail::codepoint_t cp = detail::decode_utf16(utf16, len, i);
        detail::encode_utf8(cp, result);
    }

    return result;
}

/**
 * Convert UTF-16 raw pointer (char16_t) to UTF-8
 *
 * @param utf16 Pointer to UTF-16 data
 * @param len Length in 16-bit units
 * @return UTF-8 encoded string
 */
inline std::string utf16_to_utf8(const char16_t* utf16, size_t len) {
    return utf16_to_utf8(reinterpret_cast<const uint16_t*>(utf16), len);
}

} // namespace libexe

#endif // LIBEXE_UTF_CONVERT_HPP
