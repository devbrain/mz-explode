// libexe - Modern executable file analysis library
// Copyright (c) 2024

/**
 * @file executable_file.hpp
 * @brief Base class and types for executable file analysis.
 *
 * This header defines the base interface that all executable file format
 * classes derive from, as well as the format_type enumeration for identifying
 * specific executable formats.
 */

#ifndef LIBEXE_CORE_EXECUTABLE_FILE_HPP
#define LIBEXE_CORE_EXECUTABLE_FILE_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <span>
#include <string_view>

// Disable MSVC warning C4251: 'member': class 'std::...' needs to have dll-interface
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

namespace libexe {

/**
 * @brief Executable file format types.
 *
 * Identifies the specific executable format detected during parsing.
 * This enumeration distinguishes between different executable formats
 * including DOS MZ, Windows NE/PE, and OS/2 LE/LX variants.
 *
 * @note LE/LX formats are distinguished by whether they have an MZ stub
 *       (bound) or are raw format without the DOS stub.
 */
enum class format_type {
    UNKNOWN,          ///< Format could not be determined
    MZ_DOS,           ///< DOS MZ executable (plain, no extended header)
    NE_WIN16,         ///< 16-bit Windows/OS2 New Executable
    PE_WIN32,         ///< 32-bit Windows Portable Executable
    PE_PLUS_WIN64,    ///< 64-bit Windows PE32+ executable

    // LE/LX formats - distinguish bound (with MZ stub) vs raw
    LE_DOS32_BOUND,   ///< 32-bit DOS with extender stub (DOS/4GW, DOS/32A, etc.)
    LE_DOS32_RAW,     ///< 32-bit DOS, raw LE (no MZ stub)
    LE_VXD,           ///< Windows Virtual Device Driver (VxD)
    LX_OS2_BOUND,     ///< OS/2 2.0+ with MZ stub
    LX_OS2_RAW        ///< OS/2 2.0+ raw LX format
};

/**
 * @brief Abstract base class for all executable file formats.
 *
 * This class defines the common interface that all executable file parsers
 * must implement. It provides methods for format detection, format naming,
 * and code section access.
 *
 * @note Derived classes are:
 *       - mz_file - DOS MZ executables
 *       - ne_file - 16-bit Windows/OS2 NE executables
 *       - pe_file - 32/64-bit Windows PE executables
 *       - le_file - LE/LX DOS extender and OS/2 executables
 *
 * @par Example Usage:
 * @code
 * auto exe = libexe::executable_factory::from_file("program.exe");
 * std::cout << "Format: " << exe->format_name() << std::endl;
 * std::cout << "Code size: " << exe->code_section().size() << " bytes" << std::endl;
 * @endcode
 *
 * @see mz_file, ne_file, pe_file, le_file, executable_factory
 */
class LIBEXE_EXPORT executable_file {
    public:
        /**
         * @brief Virtual destructor for proper cleanup of derived classes.
         */
        virtual ~executable_file() = default;

        /**
         * @brief Get the format type of this executable.
         *
         * Returns the specific executable format detected during parsing.
         * This can be used for format-specific processing or to safely
         * downcast to the appropriate derived class.
         *
         * @return The format_type identifying this executable's format.
         *
         * @par Example:
         * @code
         * if (exe->get_format() == libexe::format_type::PE_WIN32) {
         *     auto& pe = static_cast<libexe::pe_file&>(*exe);
         *     // PE-specific operations...
         * }
         * @endcode
         */
        [[nodiscard]] virtual format_type get_format() const = 0;

        /**
         * @brief Get human-readable format name.
         *
         * Returns a string describing the executable format in a
         * human-readable form suitable for display.
         *
         * @return A string_view containing the format name (e.g., "PE32+", "DOS MZ").
         */
        [[nodiscard]] virtual std::string_view format_name() const = 0;

        /**
         * @brief Get the primary code section data.
         *
         * Returns a view to the raw bytes of the executable's main code section.
         * For PE files, this is typically the .text section. For DOS MZ files,
         * this is the code segment following the header.
         *
         * @return A span containing the code section bytes. May be empty if
         *         no code section exists or could not be determined.
         *
         * @note The returned span is valid only while this executable_file
         *       object remains alive and unmodified.
         */
        [[nodiscard]] virtual std::span <const uint8_t> code_section() const = 0;

    protected:
        /// @brief Default constructor (protected, use factory methods in derived classes).
        executable_file() = default;

        /// @brief Copy constructor (protected).
        executable_file(const executable_file&) = default;

        /// @brief Copy assignment operator (protected).
        executable_file& operator=(const executable_file&) = default;

        /// @brief Move constructor (protected).
        executable_file(executable_file&&) = default;

        /// @brief Move assignment operator (protected).
        executable_file& operator=(executable_file&&) = default;
};

} // namespace libexe

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // LIBEXE_CORE_EXECUTABLE_FILE_HPP
