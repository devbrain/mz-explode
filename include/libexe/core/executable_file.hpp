// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_CORE_EXECUTABLE_FILE_HPP
#define LIBEXE_CORE_EXECUTABLE_FILE_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <span>
#include <string_view>

namespace libexe {
    /// Executable format types
    enum class format_type {
        UNKNOWN,
        MZ_DOS,        // DOS MZ executable
        NE_WIN16,      // 16-bit Windows/OS2
        PE_WIN32,      // 32-bit Windows
        PE_PLUS_WIN64  // 64-bit Windows
    };

    /// Base class for all executable file formats
    class LIBEXE_EXPORT executable_file {
        public:
            virtual ~executable_file() = default;

            /// Get the format type of this executable
            [[nodiscard]] virtual format_type get_format() const = 0;

            /// Get human-readable format name
            [[nodiscard]] virtual std::string_view format_name() const = 0;

            /// Get the code section data
            [[nodiscard]] virtual std::span <const uint8_t> code_section() const = 0;

        protected:
            executable_file() = default;
            executable_file(const executable_file&) = default;
            executable_file& operator=(const executable_file&) = default;
            executable_file(executable_file&&) = default;
            executable_file& operator=(executable_file&&) = default;
    };
} // namespace libexe

#endif // LIBEXE_CORE_EXECUTABLE_FILE_HPP
