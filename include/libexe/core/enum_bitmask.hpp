// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_CORE_ENUM_BITMASK_HPP
#define LIBEXE_CORE_ENUM_BITMASK_HPP

#include <type_traits>

namespace libexe {
    // ============================================================================
    // Bitmask operator support for flag enums
    // ============================================================================

    /// Enable bitmask operators for specific enum types
    /// Specialize this template with enable = true for enums that should support bitmask operations
    template<typename E>
    struct enable_bitmask_operators {
        static constexpr bool enable = false;
    };

    /// Bitwise OR operator
    template<typename E>
    constexpr typename std::enable_if <enable_bitmask_operators <E>::enable, E>::type
    operator|(E lhs, E rhs) {
        using underlying = typename std::underlying_type <E>::type;
        return static_cast <E>(
            static_cast <underlying>(lhs) | static_cast <underlying>(rhs)
        );
    }

    /// Bitwise AND operator
    template<typename E>
    constexpr typename std::enable_if <enable_bitmask_operators <E>::enable, E>::type
    operator&(E lhs, E rhs) {
        using underlying = typename std::underlying_type <E>::type;
        return static_cast <E>(
            static_cast <underlying>(lhs) & static_cast <underlying>(rhs)
        );
    }

    /// Bitwise XOR operator
    template<typename E>
    constexpr typename std::enable_if <enable_bitmask_operators <E>::enable, E>::type
    operator^(E lhs, E rhs) {
        using underlying = typename std::underlying_type <E>::type;
        return static_cast <E>(
            static_cast <underlying>(lhs) ^ static_cast <underlying>(rhs)
        );
    }

    /// Bitwise NOT operator
    template<typename E>
    constexpr typename std::enable_if <enable_bitmask_operators <E>::enable, E>::type
    operator~(E value) {
        using underlying = typename std::underlying_type <E>::type;
        return static_cast <E>(~static_cast <underlying>(value));
    }

    /// Bitwise OR assignment operator
    template<typename E>
    typename std::enable_if <enable_bitmask_operators <E>::enable, E&>::type
    operator|=(E& lhs, E rhs) {
        lhs = lhs | rhs;
        return lhs;
    }

    /// Bitwise AND assignment operator
    template<typename E>
    typename std::enable_if <enable_bitmask_operators <E>::enable, E&>::type
    operator&=(E& lhs, E rhs) {
        lhs = lhs & rhs;
        return lhs;
    }

    /// Bitwise XOR assignment operator
    template<typename E>
    typename std::enable_if <enable_bitmask_operators <E>::enable, E&>::type
    operator^=(E& lhs, E rhs) {
        lhs = lhs ^ rhs;
        return lhs;
    }

    /// Check if a specific flag is set in a bitmask value
    template<typename E>
    constexpr typename std::enable_if <enable_bitmask_operators <E>::enable, bool>::type
    has_flag(E value, E flag) {
        using underlying = typename std::underlying_type <E>::type;
        return (static_cast <underlying>(value) & static_cast <underlying>(flag)) != 0;
    }

    /// Convert enum to underlying type
    template<typename E>
    constexpr typename std::underlying_type <E>::type
    to_underlying(E value) {
        return static_cast <typename std::underlying_type <E>::type>(value);
    }
} // namespace libexe

#endif // LIBEXE_CORE_ENUM_BITMASK_HPP
