// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_FORMATS_EXECUTABLE_FACTORY_HPP
#define LIBEXE_FORMATS_EXECUTABLE_FACTORY_HPP

#include <libexe/export.hpp>
#include <libexe/core/executable_file.hpp>
#include <libexe/core/data_source.hpp>
#include <filesystem>
#include <span>
#include <variant>

// Forward declarations
namespace libexe {
    class mz_file;
    class ne_file;
    class pe_file;
    class le_file;
}

namespace libexe {
    /// Result type for executable factory - holds one of the supported formats
    using executable_variant = std::variant<mz_file, ne_file, pe_file, le_file>;

    /// Factory for auto-detecting and loading executable files
    class LIBEXE_EXPORT executable_factory {
        public:
            /// Detect format type from file header without full parsing
            static format_type detect_format(std::span <const uint8_t> data);

            /// Detect format type from file
            static format_type detect_format(const std::filesystem::path& path);

            /// Detect format type from data source
            static format_type detect_format(const data_source& source);

            /// Load executable from memory with automatic format detection
            /// Returns std::variant containing the appropriate type (mz_file, ne_file, pe_file, or le_file)
            static executable_variant from_memory(std::span<const uint8_t> data);

            /// Load executable from file with automatic format detection
            /// Returns std::variant containing the appropriate type (mz_file, ne_file, pe_file, or le_file)
            static executable_variant from_file(const std::filesystem::path& path);

            /// Load executable from data source with automatic format detection
            /// Takes ownership of the data source
            static executable_variant from_data_source(std::unique_ptr<data_source> source);

            /// Get human-readable format name for a format_type
            static std::string_view format_type_name(format_type type);
    };
} // namespace libexe

#endif // LIBEXE_FORMATS_EXECUTABLE_FACTORY_HPP
