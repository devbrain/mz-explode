// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/pe/directories/bound_import.hpp>
#include <stdexcept>
#include <cstring>
#include <algorithm>

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

bound_import_directory bound_import_directory_parser::parse(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t bound_import_rva,
    uint32_t bound_import_size
) {
    bound_import_directory result;

    // Empty directory is valid
    if (bound_import_rva == 0 || bound_import_size == 0) {
        return result;
    }

    // Convert RVA to file offset
    uint32_t bound_import_offset = rva_to_file_offset(sections, bound_import_rva);
    if (bound_import_offset == 0) {
        throw std::runtime_error("Bound import directory RVA not found in any section");
    }

    // Validate bounds
    if (bound_import_offset >= file_data.size() ||
        bound_import_offset + bound_import_size > file_data.size()) {
        throw std::runtime_error("Bound import directory exceeds file bounds");
    }

    const uint8_t* dir_start = file_data.data() + bound_import_offset;
    const uint8_t* dir_end = dir_start + bound_import_size;
    const uint8_t* ptr = dir_start;

    // Parse descriptors until null descriptor
    const size_t descriptor_size = 8;
    size_t descriptor_count = 0;

    while (ptr + descriptor_size <= dir_end) {
        // Check for null descriptor (end of array)
        if (is_null_descriptor(ptr)) {
            break;
        }

        // Parse descriptor
        bound_import_descriptor desc = parse_descriptor(ptr, dir_end, dir_start, dir_end);

        // Advance past descriptor
        ptr += descriptor_size;

        // Parse forwarder references if present
        if (desc.number_of_module_forwarder_refs > 0) {
            desc.forwarder_refs = parse_forwarders(
                ptr, dir_end, desc.number_of_module_forwarder_refs,
                dir_start, dir_end
            );
            // Advance past forwarders
            ptr += descriptor_size * desc.number_of_module_forwarder_refs;
        }

        if (desc.is_valid()) {
            result.descriptors.push_back(std::move(desc));
        }

        descriptor_count++;

        // Safety limit: max 1000 bound DLLs
        if (descriptor_count >= 1000) {
            break;
        }
    }

    return result;
}

bool bound_import_directory_parser::is_null_descriptor(const uint8_t* ptr) {
    // Null descriptor has TimeDateStamp = 0 (first 4 bytes)
    return read_u32(ptr) == 0;
}

bound_import_descriptor bound_import_directory_parser::parse_descriptor(
    const uint8_t* ptr,
    const uint8_t* end,
    const uint8_t* dir_start,
    const uint8_t* dir_end
) {
    bound_import_descriptor desc;

    // Ensure we have enough data for descriptor (8 bytes)
    if (ptr + 8 > end) {
        throw std::runtime_error("Insufficient data for bound import descriptor");
    }

    // Parse IMAGE_BOUND_IMPORT_DESCRIPTOR
    desc.time_date_stamp = read_u32(ptr);
    desc.offset_module_name = read_u16(ptr + 4);
    desc.number_of_module_forwarder_refs = read_u16(ptr + 6);

    // Read module name
    try {
        desc.module_name = read_module_name(dir_start, dir_end, desc.offset_module_name);
    } catch (const std::exception& e) {
        // If we can't read the module name, the descriptor is invalid
        desc.module_name.clear();
    }

    return desc;
}

std::vector<bound_forwarder_ref> bound_import_directory_parser::parse_forwarders(
    const uint8_t* ptr,
    const uint8_t* end,
    uint16_t count,
    const uint8_t* dir_start,
    const uint8_t* dir_end
) {
    std::vector<bound_forwarder_ref> forwarders;
    forwarders.reserve(count);

    const size_t forwarder_size = 8;

    for (uint16_t i = 0; i < count; ++i) {
        if (ptr + forwarder_size > end) {
            break;
        }

        bound_forwarder_ref fwd;

        // Parse IMAGE_BOUND_FORWARDER_REF
        fwd.time_date_stamp = read_u32(ptr);
        fwd.offset_module_name = read_u16(ptr + 4);
        fwd.reserved = read_u16(ptr + 6);

        // Read forwarder module name
        try {
            fwd.module_name = read_module_name(dir_start, dir_end, fwd.offset_module_name);
        } catch (const std::exception&) {
            // If we can't read the name, skip this forwarder
            ptr += forwarder_size;
            continue;
        }

        if (fwd.is_valid()) {
            forwarders.push_back(std::move(fwd));
        }

        ptr += forwarder_size;
    }

    return forwarders;
}

std::string bound_import_directory_parser::read_module_name(
    const uint8_t* dir_start,
    const uint8_t* dir_end,
    uint16_t offset
) {
    // Calculate actual pointer to name
    const uint8_t* name_ptr = dir_start + offset;

    // Validate offset is within directory
    if (name_ptr >= dir_end) {
        throw std::runtime_error("Module name offset exceeds directory bounds");
    }

    // Find null terminator
    const uint8_t* null_term = static_cast<const uint8_t*>(
        std::memchr(name_ptr, 0, dir_end - name_ptr)
    );

    if (!null_term) {
        throw std::runtime_error("Module name not null-terminated");
    }

    // Calculate name length
    size_t name_len = null_term - name_ptr;

    // Safety limit: max 256 characters
    if (name_len > 256) {
        throw std::runtime_error("Module name too long");
    }

    // Convert to string
    return std::string(reinterpret_cast<const char*>(name_ptr), name_len);
}

uint32_t bound_import_directory_parser::rva_to_file_offset(
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
