// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_PE_FILE_HPP
#define LIBEXE_PE_FILE_HPP

#include <libexe/export.hpp>
#include <libexe/executable_file.hpp>
#include <filesystem>
#include <vector>
#include <span>
#include <cstdint>
#include <string>
#include <optional>

namespace libexe {

/// PE section information
struct LIBEXE_EXPORT pe_section {
    std::string name;                    // Section name (e.g., ".text", ".data")
    uint32_t virtual_address;            // RVA where section is loaded
    uint32_t virtual_size;               // Size in memory
    uint32_t raw_data_offset;            // File offset
    uint32_t raw_data_size;              // Size on disk
    uint32_t characteristics;            // Section flags
    std::span<const uint8_t> data;       // Section data
};

/// PE (Portable Executable) file - Windows PE32/PE32+
class LIBEXE_EXPORT pe_file : public executable_file {
public:
    /// Load PE file from filesystem
    static pe_file from_file(const std::filesystem::path& path);

    /// Load PE file from memory
    static pe_file from_memory(std::span<const uint8_t> data);

    // Implement base class interface
    format_type get_format() const override;
    std::string_view format_name() const override;
    std::span<const uint8_t> code_section() const override;

    /// Check if this is PE32+ (64-bit) vs PE32 (32-bit)
    bool is_64bit() const;

    /// COFF File Header accessors
    uint16_t machine_type() const;
    uint16_t section_count() const;
    uint32_t timestamp() const;
    uint16_t characteristics() const;

    /// Optional Header accessors
    uint32_t image_base() const;
    uint32_t entry_point_rva() const;
    uint32_t section_alignment() const;
    uint32_t file_alignment() const;
    uint32_t size_of_image() const;
    uint32_t size_of_headers() const;
    uint16_t subsystem() const;
    uint16_t dll_characteristics() const;

    /// Section access
    const std::vector<pe_section>& sections() const;
    std::optional<pe_section> find_section(const std::string& name) const;

    /// Get section containing code (.text typically)
    std::optional<pe_section> get_code_section() const;

private:
    pe_file() = default;  // Use factory methods

    // Parse PE headers and sections
    void parse_pe_headers();
    void parse_sections();

    std::vector<uint8_t> data_;
    std::vector<pe_section> sections_;

    // Parsed header information
    bool is_64bit_ = false;
    uint32_t pe_offset_ = 0;      // Offset to PE signature
    uint32_t optional_header_offset_ = 0;

    // Cached values from headers
    uint16_t machine_type_ = 0;
    uint16_t section_count_ = 0;
    uint32_t timestamp_ = 0;
    uint16_t characteristics_ = 0;
    uint32_t image_base_ = 0;
    uint32_t entry_point_rva_ = 0;
    uint32_t section_alignment_ = 0;
    uint32_t file_alignment_ = 0;
    uint32_t size_of_image_ = 0;
    uint32_t size_of_headers_ = 0;
    uint16_t subsystem_ = 0;
    uint16_t dll_characteristics_ = 0;
};

} // namespace libexe

#endif // LIBEXE_PE_FILE_HPP
