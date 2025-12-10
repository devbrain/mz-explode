// libexe - Modern executable file analysis library
// Copyright (c) 2024

/**
 * @file enum_bitmask.hpp
 * @brief Type-safe bitmask operators for enum classes.
 *
 * This header provides template utilities for enabling bitwise operations
 * on strongly-typed enum classes. By specializing enable_bitmask_operators,
 * you can use |, &, ^, ~ operators on enum types while maintaining type safety.
 *
 * @par Usage:
 * @code
 * enum class my_flags : uint32_t {
 *     NONE = 0,
 *     FLAG_A = 1,
 *     FLAG_B = 2,
 *     FLAG_C = 4
 * };
 *
 * // Enable bitmask operators for this enum
 * template<>
 * struct libexe::enable_bitmask_operators<my_flags> {
 *     static constexpr bool enable = true;
 * };
 *
 * // Now you can use bitwise operators
 * my_flags combined = my_flags::FLAG_A | my_flags::FLAG_B;
 * if (libexe::has_flag(combined, my_flags::FLAG_A)) {
 *     // FLAG_A is set
 * }
 * @endcode
 */

#ifndef LIBEXE_CORE_ENUM_BITMASK_HPP
#define LIBEXE_CORE_ENUM_BITMASK_HPP

#include <type_traits>

namespace libexe {

/**
 * @brief Trait to enable bitmask operators for specific enum types.
 *
 * Specialize this template with `enable = true` for enum types that
 * should support bitwise operations. By default, bitmask operators
 * are disabled for all enums.
 *
 * @tparam E The enum type.
 *
 * @par Example:
 * @code
 * template<>
 * struct enable_bitmask_operators<pe_file_characteristics> {
 *     static constexpr bool enable = true;
 * };
 * @endcode
 */
template<typename E>
struct enable_bitmask_operators {
    static constexpr bool enable = false;  ///< Set to true to enable operators
};

/**
 * @brief Bitwise OR operator for enabled enum bitmasks.
 *
 * @tparam E Enum type with bitmask operators enabled.
 * @param lhs Left operand.
 * @param rhs Right operand.
 * @return Combined flags (lhs | rhs).
 */
template<typename E>
constexpr typename std::enable_if <enable_bitmask_operators <E>::enable, E>::type
operator|(E lhs, E rhs) {
    using underlying = typename std::underlying_type <E>::type;
    return static_cast <E>(
        static_cast <underlying>(lhs) | static_cast <underlying>(rhs)
    );
}

/**
 * @brief Bitwise AND operator for enabled enum bitmasks.
 *
 * @tparam E Enum type with bitmask operators enabled.
 * @param lhs Left operand.
 * @param rhs Right operand.
 * @return Intersection of flags (lhs & rhs).
 */
template<typename E>
constexpr typename std::enable_if <enable_bitmask_operators <E>::enable, E>::type
operator&(E lhs, E rhs) {
    using underlying = typename std::underlying_type <E>::type;
    return static_cast <E>(
        static_cast <underlying>(lhs) & static_cast <underlying>(rhs)
    );
}

/**
 * @brief Bitwise XOR operator for enabled enum bitmasks.
 *
 * @tparam E Enum type with bitmask operators enabled.
 * @param lhs Left operand.
 * @param rhs Right operand.
 * @return XOR of flags (lhs ^ rhs).
 */
template<typename E>
constexpr typename std::enable_if <enable_bitmask_operators <E>::enable, E>::type
operator^(E lhs, E rhs) {
    using underlying = typename std::underlying_type <E>::type;
    return static_cast <E>(
        static_cast <underlying>(lhs) ^ static_cast <underlying>(rhs)
    );
}

/**
 * @brief Bitwise NOT operator for enabled enum bitmasks.
 *
 * @tparam E Enum type with bitmask operators enabled.
 * @param value The value to invert.
 * @return Inverted flags (~value).
 */
template<typename E>
constexpr typename std::enable_if <enable_bitmask_operators <E>::enable, E>::type
operator~(E value) {
    using underlying = typename std::underlying_type <E>::type;
    return static_cast <E>(~static_cast <underlying>(value));
}

/**
 * @brief Bitwise OR assignment operator for enabled enum bitmasks.
 *
 * @tparam E Enum type with bitmask operators enabled.
 * @param lhs Reference to left operand (modified in place).
 * @param rhs Right operand.
 * @return Reference to modified lhs.
 */
template<typename E>
typename std::enable_if <enable_bitmask_operators <E>::enable, E&>::type
operator|=(E& lhs, E rhs) {
    lhs = lhs | rhs;
    return lhs;
}

/**
 * @brief Bitwise AND assignment operator for enabled enum bitmasks.
 *
 * @tparam E Enum type with bitmask operators enabled.
 * @param lhs Reference to left operand (modified in place).
 * @param rhs Right operand.
 * @return Reference to modified lhs.
 */
template<typename E>
typename std::enable_if <enable_bitmask_operators <E>::enable, E&>::type
operator&=(E& lhs, E rhs) {
    lhs = lhs & rhs;
    return lhs;
}

/**
 * @brief Bitwise XOR assignment operator for enabled enum bitmasks.
 *
 * @tparam E Enum type with bitmask operators enabled.
 * @param lhs Reference to left operand (modified in place).
 * @param rhs Right operand.
 * @return Reference to modified lhs.
 */
template<typename E>
typename std::enable_if <enable_bitmask_operators <E>::enable, E&>::type
operator^=(E& lhs, E rhs) {
    lhs = lhs ^ rhs;
    return lhs;
}

/**
 * @brief Check if a specific flag is set in a bitmask value.
 *
 * @tparam E Enum type with bitmask operators enabled.
 * @param value The bitmask value to test.
 * @param flag The flag to check for.
 * @return true if the flag is set in value.
 *
 * @par Example:
 * @code
 * if (has_flag(characteristics, pe_file_characteristics::DLL)) {
 *     // This is a DLL
 * }
 * @endcode
 */
template<typename E>
constexpr typename std::enable_if <enable_bitmask_operators <E>::enable, bool>::type
has_flag(E value, E flag) {
    using underlying = typename std::underlying_type <E>::type;
    return (static_cast <underlying>(value) & static_cast <underlying>(flag)) != 0;
}

/**
 * @brief Convert an enum value to its underlying integral type.
 *
 * This is a type-safe way to get the numeric value of an enum,
 * useful for formatting or comparison operations.
 *
 * @tparam E The enum type.
 * @param value The enum value to convert.
 * @return The underlying integral value.
 *
 * @par Example:
 * @code
 * auto raw_value = to_underlying(pe_machine_type::AMD64);
 * // raw_value is 0x8664
 * @endcode
 */
template<typename E>
constexpr typename std::underlying_type <E>::type
to_underlying(E value) {
    return static_cast <typename std::underlying_type <E>::type>(value);
}

} // namespace libexe

#endif // LIBEXE_CORE_ENUM_BITMASK_HPP
