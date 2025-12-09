#include <libexe/pe/directories/import.hpp>
#include <libexe/pe/section_parser.hpp>
#include "libexe_format_pe_imports.hh"  // Generated DataScript parser
#include <stdexcept>
#include <algorithm>
#include <cstring>  // For memchr

namespace libexe {

import_directory import_directory_parser::parse(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t import_dir_rva,
    uint32_t import_dir_size,
    bool is_64bit
) {
    import_directory result;

    if (import_dir_rva == 0) {
        // No import directory
        return result;
    }

    // Convert RVA to file offset
    size_t import_dir_offset = rva_to_offset(sections, import_dir_rva);

    const uint8_t* ptr = file_data.data() + import_dir_offset;
    const uint8_t* end = file_data.data() + file_data.size();

    // Parse array of IMAGE_IMPORT_DESCRIPTOR structures
    // Array is terminated by a null entry (all zeros)
    uint32_t descriptor_rva = import_dir_rva;

    while (true) {
        // Check if we can read another descriptor
        if (ptr + 20 > end) {
            break;
        }

        // Parse IMAGE_IMPORT_DESCRIPTOR
        auto descriptor = formats::pe::pe_imports::image_import_descriptor::read(ptr, end);

        // Check for null terminator (all fields zero)
        if (descriptor.original_first_thunk == 0 &&
            descriptor.time_date_stamp == 0 &&
            descriptor.forwarder_chain == 0 &&
            descriptor.name == 0 &&
            descriptor.first_thunk == 0) {
            // End of import directory
            break;
        }

        // Parse this DLL's imports
        auto dll = parse_import_descriptor(file_data, sections, descriptor_rva, is_64bit);
        result.dlls.push_back(std::move(dll));

        // Advance to next descriptor
        descriptor_rva += 20;  // sizeof(IMAGE_IMPORT_DESCRIPTOR)

        // Safety check: if size is known, don't exceed it
        if (import_dir_size > 0 && (descriptor_rva - import_dir_rva) >= import_dir_size) {
            break;
        }
    }

    return result;
}

import_dll import_directory_parser::parse_import_descriptor(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t descriptor_rva,
    bool is_64bit
) {
    import_dll result;

    // Read IMAGE_IMPORT_DESCRIPTOR
    size_t descriptor_offset = rva_to_offset(sections, descriptor_rva);
    const uint8_t* ptr = file_data.data() + descriptor_offset;
    const uint8_t* end = file_data.data() + file_data.size();

    auto descriptor = formats::pe::pe_imports::image_import_descriptor::read(ptr, end);

    // Store descriptor fields
    result.ilt_rva = descriptor.original_first_thunk;
    result.iat_rva = descriptor.first_thunk;
    result.name_rva = descriptor.name;
    result.timestamp = descriptor.time_date_stamp;
    result.forwarder_chain = descriptor.forwarder_chain;

    // Read DLL name
    if (descriptor.name != 0) {
        result.name = read_string_at_rva(file_data, sections, descriptor.name);
    }

    // Parse Import Lookup Table (ILT)
    // Use ILT if present, otherwise use IAT
    uint32_t ilt_rva = descriptor.original_first_thunk;
    if (ilt_rva == 0) {
        ilt_rva = descriptor.first_thunk;
    }

    if (ilt_rva != 0) {
        result.functions = parse_ilt(
            file_data,
            sections,
            ilt_rva,
            descriptor.first_thunk,
            is_64bit
        );
    }

    return result;
}

std::vector<import_entry> import_directory_parser::parse_ilt(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t ilt_rva,
    uint32_t iat_rva,
    bool is_64bit
) {
    std::vector<import_entry> functions;

    size_t ilt_offset = rva_to_offset(sections, ilt_rva);
    const uint8_t* ptr = file_data.data() + ilt_offset;
    const uint8_t* end = file_data.data() + file_data.size();

    uint32_t current_iat_rva = iat_rva;

    if (is_64bit) {
        // Parse 64-bit thunks
        while (ptr + 8 <= end) {
            auto thunk = formats::pe::pe_imports::image_thunk_data64::read(ptr, end);

            // Check for null terminator
            if (thunk.u1 == 0) {
                break;
            }

            // Check if this is an ordinal import (bit 63 set)
            bool is_ordinal = (thunk.u1 & ORDINAL_FLAG_64) != 0;
            uint16_t ordinal = static_cast<uint16_t>(thunk.u1 & ORDINAL_MASK);
            uint32_t name_rva = static_cast<uint32_t>(thunk.u1 & 0x7FFFFFFF);

            import_entry entry = parse_import_by_name(
                file_data,
                sections,
                name_rva,
                current_iat_rva,
                ordinal,
                is_ordinal
            );

            functions.push_back(std::move(entry));
            current_iat_rva += 8;  // Advance IAT RVA
        }
    } else {
        // Parse 32-bit thunks
        while (ptr + 4 <= end) {
            auto thunk = formats::pe::pe_imports::image_thunk_data32::read(ptr, end);

            // Check for null terminator
            if (thunk.u1 == 0) {
                break;
            }

            // Check if this is an ordinal import (bit 31 set)
            bool is_ordinal = (thunk.u1 & ORDINAL_FLAG_32) != 0;
            uint16_t ordinal = static_cast<uint16_t>(thunk.u1 & ORDINAL_MASK);
            uint32_t name_rva = thunk.u1 & 0x7FFFFFFF;

            import_entry entry = parse_import_by_name(
                file_data,
                sections,
                name_rva,
                current_iat_rva,
                ordinal,
                is_ordinal
            );

            functions.push_back(std::move(entry));
            current_iat_rva += 4;  // Advance IAT RVA
        }
    }

    return functions;
}

import_entry import_directory_parser::parse_import_by_name(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t rva,
    uint64_t iat_rva,
    uint16_t ordinal,
    bool is_ordinal
) {
    import_entry entry;
    entry.iat_rva = iat_rva;
    entry.is_ordinal = is_ordinal;
    entry.ordinal = ordinal;
    entry.hint = 0;

    if (is_ordinal) {
        // Ordinal import - no name
        return entry;
    }

    // Name import - read IMAGE_IMPORT_BY_NAME
    size_t offset = rva_to_offset(sections, rva);
    const uint8_t* ptr = file_data.data() + offset;
    const uint8_t* end = file_data.data() + file_data.size();

    // Read hint (2 bytes)
    auto import_by_name = formats::pe::pe_imports::image_import_by_name::read(ptr, end);
    entry.hint = import_by_name.hint;

    // Read function name (null-terminated string immediately after hint)
    // ptr is now positioned after the hint field
    entry.name = read_string_at_rva(file_data, sections, rva + 2);

    return entry;
}

std::string import_directory_parser::read_string_at_rva(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t rva
) {
    size_t offset = rva_to_offset(sections, rva);

    // Find null terminator
    const uint8_t* start = file_data.data() + offset;
    const uint8_t* end = file_data.data() + file_data.size();
    const uint8_t* null_pos = static_cast<const uint8_t*>(
        ::memchr(start, 0, end - start)
    );

    if (!null_pos) {
        throw std::runtime_error("Unterminated string at RVA 0x" + std::to_string(rva));
    }

    size_t length = null_pos - start;
    return std::string(reinterpret_cast<const char*>(start), length);
}

size_t import_directory_parser::rva_to_offset(
    const std::vector<pe_section>& sections,
    uint32_t rva
) {
    auto offset = pe_section_parser::rva_to_file_offset(sections, rva);
    if (!offset) {
        throw std::runtime_error("RVA 0x" + std::to_string(rva) + " not found in any section");
    }
    return offset.value();
}

} // namespace libexe
