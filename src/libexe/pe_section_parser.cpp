#include <libexe/pe/section_parser.hpp>
#include "libexe_format_pe.hh"  // Generated DataScript parser
#include "libexe_format_mz.hh"  // For DOS header
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace libexe {

std::vector<pe_section> pe_section_parser::parse_sections(
    std::span<const uint8_t> file_data,
    uint32_t pe_offset,
    uint16_t num_sections,
    uint16_t size_of_optional_header
) {
    std::vector<pe_section> sections;

    if (num_sections == 0) {
        return sections;
    }

    sections.reserve(num_sections);

    // Calculate section table offset
    // Section table = PE offset + 4 (PE signature) + 20 (COFF header) + optional header size
    const size_t section_table_offset = pe_offset + 4 + 20 + size_of_optional_header;

    if (section_table_offset >= file_data.size()) {
        throw std::runtime_error("Invalid section table offset");
    }

    const uint8_t* ptr = file_data.data() + section_table_offset;
    const uint8_t* end = file_data.data() + file_data.size();

    for (uint16_t i = 0; i < num_sections; ++i) {
        // Parse IMAGE_SECTION_HEADER using DataScript
        auto section_header = formats::pe::pe_header::image_section_header::read(ptr, end);

        pe_section section;

        // Extract section name (up to 8 bytes, not null-terminated)
        section.name = get_section_name(section_header.Name.data());

        // Memory layout
        section.virtual_address = section_header.VirtualAddress;
        section.virtual_size = section_header.VirtualSize;
        section.raw_data_offset = section_header.PointerToRawData;
        section.raw_data_size = section_header.SizeOfRawData;

        // Properties
        section.characteristics = static_cast<uint32_t>(section_header.Characteristics);
        section.alignment = extract_alignment(static_cast<uint32_t>(section_header.Characteristics));

        // Classify section type
        section.type = classify_section(section.name, section.characteristics);

        // Extract section data from file
        if (section.raw_data_offset > 0 &&
            section.raw_data_size > 0 &&
            section.raw_data_offset < file_data.size()) {

            const size_t data_start = section.raw_data_offset;
            const size_t data_end = std::min(
                data_start + section.raw_data_size,
                file_data.size()
            );

            section.data = file_data.subspan(data_start, data_end - data_start);
        }

        sections.push_back(std::move(section));

        // Note: ptr is automatically advanced by DataScript's read() method
    }

    return sections;
}

section_type pe_section_parser::classify_section(
    std::string_view name,
    uint32_t characteristics
) {
    // Check characteristics flags first
    const bool has_code = (characteristics & static_cast<uint32_t>(section_characteristics::CNT_CODE)) != 0;
    const bool has_data = (characteristics & static_cast<uint32_t>(section_characteristics::CNT_INITIALIZED_DATA)) != 0;
    const bool has_uninit = (characteristics & static_cast<uint32_t>(section_characteristics::CNT_UNINITIALIZED_DATA)) != 0;

    // Name-based classification (common PE section names)
    if (name == ".text" || name == "CODE" || name == ".code") {
        return section_type::CODE;
    }
    if (name == ".data" || name == "DATA") {
        return section_type::DATA;
    }
    if (name == ".bss" || name == "BSS") {
        return section_type::BSS;
    }
    if (name == ".rdata" || name == ".rodata") {
        return section_type::DATA;  // Read-only data
    }
    if (name == ".idata" || name == ".import") {
        return section_type::IMPORT;
    }
    if (name == ".edata" || name == ".export") {
        return section_type::EXPORT;
    }
    if (name == ".rsrc" || name == ".resources") {
        return section_type::RESOURCE;
    }
    if (name == ".reloc" || name == ".relocations") {
        return section_type::RELOCATION;
    }
    if (name == ".pdata") {
        return section_type::EXCEPTION;  // Exception handling data (x64)
    }
    if (name == ".debug" || name == ".xdata") {
        return section_type::DEBUG;
    }
    if (name == ".tls" || name == ".tls$") {
        return section_type::TLS;
    }

    // Fallback to characteristics-based classification
    if (has_uninit) {
        return section_type::BSS;
    }
    if (has_code) {
        return section_type::CODE;
    }
    if (has_data) {
        return section_type::DATA;
    }

    return section_type::UNKNOWN;
}

std::optional<size_t> pe_section_parser::rva_to_file_offset(
    const std::vector<pe_section>& sections,
    uint32_t rva
) {
    for (const auto& section : sections) {
        if (auto offset = section.rva_to_offset(rva)) {
            return offset;
        }
    }
    return std::nullopt;
}

const pe_section* pe_section_parser::find_section_by_rva(
    const std::vector<pe_section>& sections,
    uint32_t rva
) {
    for (const auto& section : sections) {
        if (section.contains_rva(rva)) {
            return &section;
        }
    }
    return nullptr;
}

const pe_section* pe_section_parser::find_section_by_name(
    const std::vector<pe_section>& sections,
    std::string_view name
) {
    for (const auto& section : sections) {
        if (section.name == name) {
            return &section;
        }
    }
    return nullptr;
}

uint32_t pe_section_parser::extract_alignment(uint32_t characteristics) {
    // Extract alignment bits (bits 20-23)
    const uint32_t align_bits = (characteristics & static_cast<uint32_t>(section_characteristics::ALIGN_MASK));

    // Decode alignment value
    switch (align_bits) {
        case static_cast<uint32_t>(section_characteristics::ALIGN_1BYTES):    return 1;
        case static_cast<uint32_t>(section_characteristics::ALIGN_2BYTES):    return 2;
        case static_cast<uint32_t>(section_characteristics::ALIGN_4BYTES):    return 4;
        case static_cast<uint32_t>(section_characteristics::ALIGN_8BYTES):    return 8;
        case static_cast<uint32_t>(section_characteristics::ALIGN_16BYTES):   return 16;
        case static_cast<uint32_t>(section_characteristics::ALIGN_32BYTES):   return 32;
        case static_cast<uint32_t>(section_characteristics::ALIGN_64BYTES):   return 64;
        case static_cast<uint32_t>(section_characteristics::ALIGN_128BYTES):  return 128;
        case static_cast<uint32_t>(section_characteristics::ALIGN_256BYTES):  return 256;
        case static_cast<uint32_t>(section_characteristics::ALIGN_512BYTES):  return 512;
        case static_cast<uint32_t>(section_characteristics::ALIGN_1024BYTES): return 1024;
        case static_cast<uint32_t>(section_characteristics::ALIGN_2048BYTES): return 2048;
        case static_cast<uint32_t>(section_characteristics::ALIGN_4096BYTES): return 4096;
        case static_cast<uint32_t>(section_characteristics::ALIGN_8192BYTES): return 8192;
        default: return 0;  // No alignment specified
    }
}

std::string pe_section_parser::get_section_name(const uint8_t* name_bytes) {
    // Section names are 8-byte ASCII fields, not necessarily null-terminated
    // Find actual length (up to 8 bytes, stopping at first null or non-printable)
    size_t len = 0;
    while (len < 8 && name_bytes[len] != 0 && name_bytes[len] >= 32 && name_bytes[len] < 127) {
        ++len;
    }

    return std::string(reinterpret_cast<const char*>(name_bytes), len);
}

} // namespace libexe
