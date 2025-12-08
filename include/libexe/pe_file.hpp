// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_PE_FILE_HPP
#define LIBEXE_PE_FILE_HPP

#include <libexe/export.hpp>
#include <libexe/executable_file.hpp>
#include <libexe/pe_types.hpp>
#include <libexe/section.hpp>
#include <filesystem>
#include <vector>
#include <span>
#include <string>
#include <optional>
#include <memory>
#include <array>

namespace libexe {
    // Forward declarations
    class resource_directory;
    struct import_directory;
    struct export_directory;
    struct base_relocation_directory;
    struct tls_directory;
    struct debug_directory;
    struct load_config_directory;
    struct exception_directory;
    struct delay_import_directory;
    struct bound_import_directory;
    struct security_directory;
    struct com_descriptor;
    struct iat_directory;
    struct global_ptr_directory;
    struct architecture_directory;
    struct reserved_directory;

    /// PE (Portable Executable) file - Windows PE32/PE32+
    class LIBEXE_EXPORT pe_file final : public executable_file {
        public:
            /// Load PE file from filesystem
            static pe_file from_file(const std::filesystem::path& path);

            /// Load PE file from memory
            static pe_file from_memory(std::span <const uint8_t> data);

            // Implement base class interface
            [[nodiscard]] format_type get_format() const override;
            [[nodiscard]] std::string_view format_name() const override;
            [[nodiscard]] std::span <const uint8_t> code_section() const override;

            /// Check if this is PE32+ (64-bit) vs PE32 (32-bit)
            [[nodiscard]] bool is_64bit() const;

            /// COFF File Header accessors
            [[nodiscard]] pe_machine_type machine_type() const;
            [[nodiscard]] uint16_t section_count() const;
            [[nodiscard]] uint32_t timestamp() const;
            [[nodiscard]] pe_file_characteristics characteristics() const;

            /// Optional Header accessors
            [[nodiscard]] uint64_t image_base() const;
            [[nodiscard]] uint32_t entry_point_rva() const;
            [[nodiscard]] uint32_t section_alignment() const;
            [[nodiscard]] uint32_t file_alignment() const;
            [[nodiscard]] uint32_t size_of_image() const;
            [[nodiscard]] uint32_t size_of_headers() const;
            [[nodiscard]] pe_subsystem subsystem() const;
            [[nodiscard]] pe_dll_characteristics dll_characteristics() const;

            /// Section access
            [[nodiscard]] const std::vector <pe_section>& sections() const;
            [[nodiscard]] std::optional <pe_section> find_section(const std::string& name) const;

            /// Get section containing code (.text typically)
            [[nodiscard]] std::optional <pe_section> get_code_section() const;

            /// Resource access
            [[nodiscard]] bool has_resources() const;
            [[nodiscard]] std::shared_ptr<resource_directory> resources() const;

            /// Data directory accessors
            [[nodiscard]] uint32_t data_directory_rva(directory_entry entry) const;
            [[nodiscard]] uint32_t data_directory_size(directory_entry entry) const;
            [[nodiscard]] bool has_data_directory(directory_entry entry) const;

            /// Import directory access (lazy-parsed)
            [[nodiscard]] std::shared_ptr<import_directory> imports() const;

            /// Export directory access (lazy-parsed)
            [[nodiscard]] std::shared_ptr<export_directory> exports() const;

            /// Base relocation directory access (lazy-parsed)
            [[nodiscard]] std::shared_ptr<base_relocation_directory> relocations() const;

            /// TLS directory access (lazy-parsed)
            [[nodiscard]] std::shared_ptr<tls_directory> tls() const;

            /// Debug directory access (lazy-parsed)
            [[nodiscard]] std::shared_ptr<debug_directory> debug() const;

            /// Load configuration directory access (lazy-parsed)
            [[nodiscard]] std::shared_ptr<load_config_directory> load_config() const;

            /// Exception directory access (lazy-parsed)
            [[nodiscard]] std::shared_ptr<exception_directory> exceptions() const;

            /// Delay import directory access (lazy-parsed)
            [[nodiscard]] std::shared_ptr<delay_import_directory> delay_imports() const;

            /// Bound import directory access (lazy-parsed)
            [[nodiscard]] std::shared_ptr<bound_import_directory> bound_imports() const;

            /// Security directory access (lazy-parsed)
            [[nodiscard]] std::shared_ptr<security_directory> security() const;

            /// COM descriptor access (CLR runtime header, lazy-parsed)
            [[nodiscard]] std::shared_ptr<com_descriptor> clr_header() const;

            /// Import Address Table (IAT) access (lazy-parsed)
            [[nodiscard]] std::shared_ptr<iat_directory> import_address_table() const;

            /// Global Pointer directory access (IA64 only, lazy-parsed)
            [[nodiscard]] std::shared_ptr<global_ptr_directory> global_ptr() const;

            /// Architecture directory access (reserved, should be zero, lazy-parsed)
            [[nodiscard]] std::shared_ptr<architecture_directory> architecture() const;

            /// Reserved directory access (reserved, must be zero, lazy-parsed)
            [[nodiscard]] std::shared_ptr<reserved_directory> reserved() const;

        private:
            pe_file() = default; // Use factory methods

            // Parse PE headers and sections
            void parse_pe_headers();
            void parse_sections();

            std::vector <uint8_t> data_;
            std::vector <pe_section> sections_;

            // Parsed header information
            bool is_64bit_ = false;
            uint32_t pe_offset_ = 0; // Offset to PE signature
            uint32_t optional_header_offset_ = 0;

            // Cached values from headers
            uint16_t machine_type_ = 0;
            uint16_t section_count_ = 0;
            uint32_t timestamp_ = 0;
            uint16_t characteristics_ = 0;
            uint64_t image_base_ = 0;
            uint32_t entry_point_rva_ = 0;
            uint32_t section_alignment_ = 0;
            uint32_t file_alignment_ = 0;
            uint32_t size_of_image_ = 0;
            uint32_t size_of_headers_ = 0;
            uint16_t subsystem_ = 0;
            uint16_t dll_characteristics_ = 0;

            // Data directories (RVA and size pairs)
            struct data_directory_entry {
                uint32_t rva = 0;
                uint32_t size = 0;
            };
            std::array<data_directory_entry, 16> data_directories_;

            // Lazy-parsed data directories (mutable for lazy initialization)
            mutable std::shared_ptr<import_directory> imports_;
            mutable std::shared_ptr<export_directory> exports_;
            mutable std::shared_ptr<base_relocation_directory> relocations_;
            mutable std::shared_ptr<tls_directory> tls_;
            mutable std::shared_ptr<debug_directory> debug_;
            mutable std::shared_ptr<load_config_directory> load_config_;
            mutable std::shared_ptr<exception_directory> exceptions_;
            mutable std::shared_ptr<delay_import_directory> delay_imports_;
            mutable std::shared_ptr<bound_import_directory> bound_imports_;
            mutable std::shared_ptr<security_directory> security_;
            mutable std::shared_ptr<com_descriptor> com_descriptor_;
            mutable std::shared_ptr<iat_directory> iat_;
            mutable std::shared_ptr<global_ptr_directory> global_ptr_;
            mutable std::shared_ptr<architecture_directory> architecture_;
            mutable std::shared_ptr<reserved_directory> reserved_;
    };
} // namespace libexe

#endif // LIBEXE_PE_FILE_HPP
