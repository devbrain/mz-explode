// libexe - Modern executable file analysis library
// Copyright (c) 2024
// Internal file utilities

#ifndef LIBEXE_CORE_FILE_UTILS_HPP
#define LIBEXE_CORE_FILE_UTILS_HPP

#include <cstdint>
#include <climits>

namespace libexe::internal {

/**
 * Safe multiplication with overflow check
 *
 * @param a First operand
 * @param b Second operand
 * @param result Output parameter for result
 * @return true if multiplication succeeded, false if it would overflow
 */
inline bool safe_multiply(uint32_t a, uint32_t b, uint32_t& result) {
    if (a != 0 && b > UINT32_MAX / a) {
        return false;  // Would overflow
    }
    result = a * b;
    return true;
}

/**
 * Safe addition with overflow check
 *
 * @param a First operand
 * @param b Second operand
 * @param result Output parameter for result
 * @return true if addition succeeded, false if it would overflow
 */
inline bool safe_add(uint32_t a, uint32_t b, uint32_t& result) {
    if (a > UINT32_MAX - b) {
        return false;  // Would overflow
    }
    result = a + b;
    return true;
}

} // namespace libexe::internal

#endif // LIBEXE_CORE_FILE_UTILS_HPP
