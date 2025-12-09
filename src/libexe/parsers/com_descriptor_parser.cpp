// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/pe/directories/com_descriptor.hpp>
#include <stdexcept>
#include <cstring>

namespace libexe {

namespace {
    // Read 16-bit little-endian value
    uint16_t read_u16(const uint8_t* ptr) {
        return static_cast<uint16_t>(ptr[0]) |
               (static_cast<uint16_t>(ptr[1]) << 8);
    }

    // Read 32-bit little-endian value
    uint32_t read_u32(const uint8_t* ptr) {
        return static_cast<uint32_t>(ptr[0]) |
               (static_cast<uint32_t>(ptr[1]) << 8) |
               (static_cast<uint32_t>(ptr[2]) << 16) |
               (static_cast<uint32_t>(ptr[3]) << 24);
    }
}

com_descriptor com_descriptor_parser::parse(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t com_descriptor_rva,
    uint32_t com_descriptor_size
) {
    com_descriptor result;

    // Empty directory is valid (non-.NET executable)
    if (com_descriptor_rva == 0 || com_descriptor_size == 0) {
        return result;
    }

    // Convert RVA to file offset
    uint32_t com_descriptor_offset = rva_to_file_offset(sections, com_descriptor_rva);
    if (com_descriptor_offset == 0) {
        throw std::runtime_error("COM descriptor RVA not found in any section");
    }

    // Validate bounds
    if (com_descriptor_offset >= file_data.size() ||
        com_descriptor_offset + com_descriptor_size > file_data.size()) {
        throw std::runtime_error("COM descriptor exceeds file bounds");
    }

    // IMAGE_COR20_HEADER is 72 bytes
    const size_t expected_size = 72;
    if (com_descriptor_size < expected_size) {
        throw std::runtime_error("COM descriptor size too small (expected 72 bytes)");
    }

    const uint8_t* ptr = file_data.data() + com_descriptor_offset;

    // Parse IMAGE_COR20_HEADER structure
    result.header_size = read_u32(ptr);
    result.major_runtime_version = read_u16(ptr + 4);
    result.minor_runtime_version = read_u16(ptr + 6);
    result.metadata_rva = read_u32(ptr + 8);
    result.metadata_size = read_u32(ptr + 12);
    result.flags = read_u32(ptr + 16);
    result.entry_point_token_or_rva = read_u32(ptr + 20);
    result.resources_rva = read_u32(ptr + 24);
    result.resources_size = read_u32(ptr + 28);
    result.strong_name_signature_rva = read_u32(ptr + 32);
    result.strong_name_signature_size = read_u32(ptr + 36);
    result.code_manager_table_rva = read_u32(ptr + 40);
    result.code_manager_table_size = read_u32(ptr + 44);
    result.vtable_fixups_rva = read_u32(ptr + 48);
    result.vtable_fixups_size = read_u32(ptr + 52);
    result.export_address_table_jumps_rva = read_u32(ptr + 56);
    result.export_address_table_jumps_size = read_u32(ptr + 60);
    result.managed_native_header_rva = read_u32(ptr + 64);
    result.managed_native_header_size = read_u32(ptr + 68);

    // Validate header size
    if (result.header_size != expected_size) {
        throw std::runtime_error("Invalid COM descriptor header size");
    }

    return result;
}

uint32_t com_descriptor_parser::rva_to_file_offset(
    const std::vector<pe_section>& sections,
    uint32_t rva
) {
    for (const auto& section : sections) {
        uint32_t section_start = section.virtual_address;
        uint32_t section_end = section_start + section.virtual_size;

        if (rva >= section_start && rva < section_end) {
            uint32_t offset_in_section = rva - section_start;
            return section.raw_data_offset + offset_in_section;
        }
    }
    return 0; // Not found
}

} // namespace libexe
