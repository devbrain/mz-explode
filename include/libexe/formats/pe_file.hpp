// libexe - Modern executable file analysis library
// Copyright (c) 2024

/**
 * @file pe_file.hpp
 * @brief PE (Portable Executable) file parser for Windows executables.
 *
 * This header provides the pe_file class for parsing and analyzing PE format
 * executables. PE is the standard executable format for Windows operating systems,
 * including:
 * - Windows applications (.exe)
 * - Dynamic Link Libraries (.dll)
 * - Windows drivers (.sys)
 * - ActiveX controls (.ocx)
 *
 * @par Format Support:
 * - **PE32**: 32-bit Windows executables (IMAGE_NT_OPTIONAL_HDR32_MAGIC)
 * - **PE32+**: 64-bit Windows executables (IMAGE_NT_OPTIONAL_HDR64_MAGIC)
 *
 * @par Key Features:
 * - Complete header parsing (DOS, COFF, Optional headers)
 * - Section table analysis
 * - All 16 data directories supported
 * - Import/Export analysis
 * - Security feature detection (ASLR, DEP, CFG, etc.)
 * - Entropy analysis for packer detection
 * - Authenticode signature parsing
 * - Rich header extraction
 * - Overlay detection
 *
 * @par Anomaly Detection:
 * The parser generates diagnostics for specification violations and
 * suspicious patterns often used by malware:
 * - Header anomalies (overlapping sections, invalid alignments)
 * - Import/Export anomalies
 * - Relocation anomalies
 * - Entry point anomalies
 *
 * @see mz_file, ne_file, executable_factory, diagnostic_collector
 */

#ifndef LIBEXE_FORMATS_PE_FILE_HPP
#define LIBEXE_FORMATS_PE_FILE_HPP

#include <libexe/export.hpp>
#include <libexe/core/executable_file.hpp>
#include <libexe/core/diagnostic_collector.hpp>
#include <libexe/pe/types.hpp>
#include <libexe/pe/section.hpp>
#include <libexe/pe/rich_header.hpp>
#include <libexe/pe/overlay.hpp>
#include <libexe/pe/authenticode.hpp>
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

/**
 * @brief PE (Portable Executable) file parser for Windows PE32/PE32+.
 *
 * Parses PE format executables and provides comprehensive access to all
 * PE structures including headers, sections, data directories, imports,
 * exports, resources, and security information.
 *
 * @par PE Structure Overview:
 * - DOS MZ stub header (compatibility for DOS)
 * - PE signature ("PE\\0\\0") at offset specified by e_lfanew
 * - COFF File Header (machine type, section count, characteristics)
 * - Optional Header (entry point, image base, alignments, data directories)
 * - Section Table (code, data, resources, etc.)
 * - Data Directories (imports, exports, resources, relocations, etc.)
 *
 * @par Example Usage:
 * @code
 * auto pe = libexe::pe_file::from_file("program.exe");
 *
 * // Basic info
 * std::cout << "Format: " << pe.format_name()
 *           << "\nMachine: " << static_cast<int>(pe.machine_type())
 *           << "\nEntry: 0x" << std::hex << pe.entry_point_rva() << std::endl;
 *
 * // Security features
 * std::cout << "ASLR: " << (pe.has_aslr() ? "Yes" : "No")
 *           << "\nDEP: " << (pe.has_dep() ? "Yes" : "No")
 *           << "\nCFG: " << (pe.has_cfg() ? "Yes" : "No") << std::endl;
 *
 * // Import analysis
 * for (const auto& dll : pe.imported_dlls()) {
 *     std::cout << "Imports: " << dll << std::endl;
 * }
 *
 * // Check for anomalies
 * if (pe.has_anomalies()) {
 *     for (const auto& diag : pe.diagnostics().anomalies()) {
 *         std::cout << "ANOMALY: " << diag.message << std::endl;
 *     }
 * }
 * @endcode
 *
 * @see pe_section, pe_machine_type, pe_subsystem, diagnostic_collector
 */
class LIBEXE_EXPORT pe_file final : public executable_file {
    public:
        // =====================================================================
        // Factory Methods
        // =====================================================================

        /**
         * @brief Load PE file from filesystem.
         *
         * @param path Path to the PE executable file.
         * @return Parsed pe_file object.
         * @throws std::runtime_error If file cannot be read or is not valid PE format.
         */
        [[nodiscard]] static pe_file from_file(const std::filesystem::path& path);

        /**
         * @brief Load PE file from memory buffer.
         *
         * @param data Span containing the raw PE file data.
         * @return Parsed pe_file object.
         * @throws std::runtime_error If data is not valid PE format.
         */
        [[nodiscard]] static pe_file from_memory(std::span <const uint8_t> data);

        // =====================================================================
        // Base Class Interface Implementation
        // =====================================================================

        /// @copydoc executable_file::get_format()
        [[nodiscard]] format_type get_format() const override;

        /// @copydoc executable_file::format_name()
        [[nodiscard]] std::string_view format_name() const override;

        /// @copydoc executable_file::code_section()
        [[nodiscard]] std::span <const uint8_t> code_section() const override;

        // =====================================================================
        // Format Identification
        // =====================================================================

        /**
         * @brief Check if this is PE32+ (64-bit) vs PE32 (32-bit).
         *
         * PE32+ uses different structure sizes for addresses (64-bit vs 32-bit).
         *
         * @return true if PE32+ (64-bit), false if PE32 (32-bit).
         */
        [[nodiscard]] bool is_64bit() const;

        // =====================================================================
        // COFF File Header Accessors
        // =====================================================================

        /**
         * @brief Get target machine (CPU) type.
         * @return pe_machine_type identifying the target architecture.
         */
        [[nodiscard]] pe_machine_type machine_type() const;

        /**
         * @brief Get number of sections in the section table.
         * @return Section count.
         */
        [[nodiscard]] uint16_t section_count() const;

        /**
         * @brief Get file creation timestamp (Unix epoch).
         * @return Timestamp as seconds since January 1, 1970.
         */
        [[nodiscard]] uint32_t timestamp() const;

        /**
         * @brief Get file characteristics flags.
         * @return Bitmask of pe_file_characteristics values.
         */
        [[nodiscard]] pe_file_characteristics characteristics() const;

        // =====================================================================
        // Optional Header Accessors
        // =====================================================================

        /**
         * @brief Get preferred image base address.
         *
         * The address where the executable prefers to be loaded. If this
         * address is unavailable, the loader will relocate the image.
         *
         * @return Preferred base address (64-bit for PE32+, 32-bit for PE32).
         */
        [[nodiscard]] uint64_t image_base() const;

        /**
         * @brief Get entry point RVA.
         *
         * Relative Virtual Address of the entry point function.
         * This is where execution begins when the image is loaded.
         *
         * @return Entry point RVA, or 0 for DLLs without entry points.
         */
        [[nodiscard]] uint32_t entry_point_rva() const;

        /**
         * @brief Get section alignment in memory.
         *
         * Sections are aligned to this boundary when loaded into memory.
         * Must be >= FileAlignment, typically 4096 (0x1000).
         *
         * @return Section alignment in bytes.
         */
        [[nodiscard]] uint32_t section_alignment() const;

        /**
         * @brief Get file alignment for raw section data.
         *
         * Raw data in sections is aligned to this boundary in the file.
         * Typically 512 (0x200) or 4096 (0x1000).
         *
         * @return File alignment in bytes.
         */
        [[nodiscard]] uint32_t file_alignment() const;

        /**
         * @brief Get total size of loaded image.
         *
         * Size of the image in memory, including headers and all sections,
         * rounded up to SectionAlignment.
         *
         * @return Size of image in bytes.
         */
        [[nodiscard]] uint32_t size_of_image() const;

        /**
         * @brief Get size of all headers.
         *
         * Combined size of DOS header, PE signature, COFF header, optional
         * header, and section headers, rounded up to FileAlignment.
         *
         * @return Size of headers in bytes.
         */
        [[nodiscard]] uint32_t size_of_headers() const;

        /**
         * @brief Get Windows subsystem type.
         * @return pe_subsystem identifying the required subsystem.
         */
        [[nodiscard]] pe_subsystem subsystem() const;

        /**
         * @brief Get DLL characteristics flags.
         * @return Bitmask of pe_dll_characteristics values.
         */
        [[nodiscard]] pe_dll_characteristics dll_characteristics() const;

            // =========================================================================
            // Edge Case Detection Methods
            // =========================================================================

            /// Check if file uses low alignment mode (FileAlignment == SectionAlignment <= 0x200)
            /// In low alignment mode, the PE header is writable and raw addresses equal virtual addresses
            [[nodiscard]] bool is_low_alignment() const;

            /// Get effective image base considering invalid values
            /// If ImageBase is 0 or in kernel space, file will be relocated to 0x10000
            [[nodiscard]] uint64_t effective_image_base() const;

            /// Section access
            [[nodiscard]] const std::vector <pe_section>& sections() const;
            [[nodiscard]] std::optional <pe_section> find_section(const std::string& name) const;
            [[nodiscard]] std::optional <pe_section> get_code_section() const;

            /// Resource access
            [[nodiscard]] bool has_resources() const;
            [[nodiscard]] std::shared_ptr<resource_directory> resources() const;

            /// Data directory accessors
            [[nodiscard]] uint32_t data_directory_rva(directory_entry entry) const;
            [[nodiscard]] uint32_t data_directory_size(directory_entry entry) const;
            [[nodiscard]] bool has_data_directory(directory_entry entry) const;

            /// Directory access (lazy-parsed)
            [[nodiscard]] std::shared_ptr<import_directory> imports() const;
            [[nodiscard]] std::shared_ptr<export_directory> exports() const;
            [[nodiscard]] std::shared_ptr<base_relocation_directory> relocations() const;
            [[nodiscard]] std::shared_ptr<tls_directory> tls() const;
            [[nodiscard]] std::shared_ptr<debug_directory> debug() const;
            [[nodiscard]] std::shared_ptr<load_config_directory> load_config() const;
            [[nodiscard]] std::shared_ptr<exception_directory> exceptions() const;
            [[nodiscard]] std::shared_ptr<delay_import_directory> delay_imports() const;
            [[nodiscard]] std::shared_ptr<bound_import_directory> bound_imports() const;
            [[nodiscard]] std::shared_ptr<security_directory> security() const;
            [[nodiscard]] std::shared_ptr<com_descriptor> clr_header() const;
            [[nodiscard]] std::shared_ptr<iat_directory> import_address_table() const;
            [[nodiscard]] std::shared_ptr<global_ptr_directory> global_ptr() const;
            [[nodiscard]] std::shared_ptr<architecture_directory> architecture() const;
            [[nodiscard]] std::shared_ptr<reserved_directory> reserved() const;

            /// Rich header access (undocumented Microsoft build metadata)
            [[nodiscard]] std::optional<rich_header> rich() const;

            /// Check if file has a Rich header
            [[nodiscard]] bool has_rich_header() const;

            // =========================================================================
            // Security Analysis (ASLR/DEP/CFG/etc.)
            // =========================================================================

            /// Check if ASLR (Address Space Layout Randomization) is enabled
            /// Corresponds to IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040)
            [[nodiscard]] bool has_aslr() const;

            /// Check if high-entropy ASLR is enabled (64-bit only, better randomization)
            /// Corresponds to IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA (0x0020)
            [[nodiscard]] bool has_high_entropy_aslr() const;

            /// Check if DEP/NX (Data Execution Prevention) is enabled
            /// Corresponds to IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x0100)
            [[nodiscard]] bool has_dep() const;

            /// Check if CFG (Control Flow Guard) is enabled
            /// Corresponds to IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000)
            [[nodiscard]] bool has_cfg() const;

            /// Check if SEH (Structured Exception Handling) is disabled
            /// Corresponds to IMAGE_DLLCHARACTERISTICS_NO_SEH (0x0400)
            [[nodiscard]] bool has_no_seh() const;

            /// Check if SafeSEH is enabled (32-bit only, via load config)
            [[nodiscard]] bool has_safe_seh() const;

            /// Check if Authenticode signature is present
            /// True if security directory (data directory index 4) is non-empty
            [[nodiscard]] bool has_authenticode() const;

            /// Get parsed Authenticode signature information
            /// Returns nullopt if no signature or parsing fails
            [[nodiscard]] std::optional<authenticode_signature> authenticode_info() const;

            /// Get digest algorithm used in Authenticode signature
            [[nodiscard]] authenticode_hash_algorithm authenticode_digest_algorithm() const;

            /// Check if Authenticode signature uses deprecated algorithms (MD5, SHA1)
            [[nodiscard]] bool authenticode_uses_deprecated_algorithm() const;

            /// Get Authenticode signature security summary
            [[nodiscard]] std::string authenticode_security_summary() const;

            /// Check if this is a .NET/CLR assembly
            /// True if COM descriptor directory (data directory index 14) is non-empty
            [[nodiscard]] bool is_dotnet() const;

            /// Check if Force Integrity flag is set (requires signature verification)
            /// Corresponds to IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (0x0080)
            [[nodiscard]] bool has_force_integrity() const;

            /// Check if AppContainer execution is required
            /// Corresponds to IMAGE_DLLCHARACTERISTICS_APPCONTAINER (0x1000)
            [[nodiscard]] bool is_appcontainer() const;

            /// Check if Terminal Server aware
            /// Corresponds to IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE (0x8000)
            [[nodiscard]] bool is_terminal_server_aware() const;

            /// Check if this is a DLL (vs executable)
            /// Corresponds to IMAGE_FILE_DLL characteristic (0x2000)
            [[nodiscard]] bool is_dll() const;

            /// Check if Large Address Aware (can use >2GB address space on 32-bit)
            /// Corresponds to IMAGE_FILE_LARGE_ADDRESS_AWARE (0x0020)
            [[nodiscard]] bool is_large_address_aware() const;

            // =========================================================================
            // Subsystem Detection
            // =========================================================================

            /// Check if this is a GUI application (WINDOWS_GUI subsystem)
            [[nodiscard]] bool is_gui() const;

            /// Check if this is a console application (WINDOWS_CUI subsystem)
            [[nodiscard]] bool is_console() const;

            /// Check if this is a native application (NATIVE subsystem, e.g., drivers)
            [[nodiscard]] bool is_native() const;

            /// Check if this is an EFI application or driver
            [[nodiscard]] bool is_efi() const;

            // =========================================================================
            // Entropy Analysis (Packing Detection)
            // =========================================================================

            /// Calculate entropy of entire file
            [[nodiscard]] double file_entropy() const;

            /// Calculate entropy of a specific section by name
            [[nodiscard]] double section_entropy(const std::string& section_name) const;

            /// Get entropy analysis for all sections
            [[nodiscard]] std::vector<std::pair<std::string, double>> all_section_entropies() const;

            /// Check if any section has high entropy (likely packed/compressed)
            [[nodiscard]] bool has_high_entropy_sections() const;

            /// Check if file appears to be packed (heuristic based on entropy + other indicators)
            [[nodiscard]] bool is_likely_packed() const;

            // =========================================================================
            // Overlay Detection
            // =========================================================================

            /// Check if file has an overlay (data after last section)
            [[nodiscard]] bool has_overlay() const;

            /// Get overlay offset (0 if no overlay)
            [[nodiscard]] uint64_t overlay_offset() const;

            /// Get overlay size in bytes (0 if no overlay)
            [[nodiscard]] uint64_t overlay_size() const;

            /// Get overlay data as span (empty if no overlay)
            [[nodiscard]] std::span<const uint8_t> overlay_data() const;

            /// Get overlay entropy (0.0 if no overlay)
            [[nodiscard]] double overlay_entropy() const;

            // =========================================================================
            // Import/Export Analysis
            // =========================================================================

            /// Get list of all imported DLL names
            [[nodiscard]] std::vector<std::string> imported_dlls() const;

            /// Get total count of imported functions
            [[nodiscard]] size_t imported_function_count() const;

            /// Check if a specific DLL is imported
            [[nodiscard]] bool imports_dll(std::string_view dll_name) const;

            /// Check if a specific function is imported from any DLL
            [[nodiscard]] bool imports_function(std::string_view function_name) const;

            /// Check if a specific function is imported from a specific DLL
            [[nodiscard]] bool imports_function(std::string_view dll_name, std::string_view function_name) const;

            /// Get list of all exported function names
            [[nodiscard]] std::vector<std::string> exported_functions() const;

            /// Get total count of exported functions
            [[nodiscard]] size_t exported_function_count() const;

            /// Check if a specific function is exported
            [[nodiscard]] bool exports_function(std::string_view function_name) const;

            // =========================================================================
            // Diagnostics
            // =========================================================================

            /// Get all diagnostics generated during parsing
            [[nodiscard]] const diagnostic_collector& diagnostics() const;

            /// Check if a specific diagnostic code exists
            [[nodiscard]] bool has_diagnostic(diagnostic_code code) const;

            /// Check if file has any anomalies
            [[nodiscard]] bool has_anomalies() const;

            /// Check if there were any parse errors (recovered)
            [[nodiscard]] bool has_parse_errors() const;

        private:
            pe_file() = default;

            void parse_pe_headers();
            void parse_sections();
            void detect_overlapping_directories();
            void detect_directories_in_header();
            void check_relocation_anomalies(const base_relocation_directory& relocs) const;
            void check_import_anomalies(const import_directory& imports, const std::string& module_name = "") const;
            void check_export_anomalies(const export_directory& exports) const;

            std::vector <uint8_t> data_;
            std::vector <pe_section> sections_;

            bool is_64bit_ = false;
            uint32_t pe_offset_ = 0;
            uint32_t optional_header_offset_ = 0;

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

            struct data_directory_entry {
                uint32_t rva = 0;
                uint32_t size = 0;
            };
            std::array<data_directory_entry, 16> data_directories_;

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

            // Rich header cache
            mutable bool rich_header_parsed_ = false;
            mutable std::optional<rich_header> rich_header_;

            // Overlay cache
            mutable bool overlay_parsed_ = false;
            mutable overlay_info overlay_info_;

            // Size of optional header (needed for overlay detection)
            uint16_t optional_header_size_ = 0;

            // Diagnostics collector (mutable because diagnostics can be added during lazy parsing)
            mutable diagnostic_collector diagnostics_;
    };
} // namespace libexe

#endif // LIBEXE_FORMATS_PE_FILE_HPP
