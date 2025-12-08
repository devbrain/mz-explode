// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/parsers/debug_directory_parser.hpp>
#include <libexe/pe_section_parser.hpp>
#include "libexe_format_pe_debug.hh"  // Generated DataScript parser
#include <stdexcept>
#include <cstring>

namespace libexe {

debug_directory debug_directory_parser::parse(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t debug_dir_rva,
    uint32_t debug_dir_size
) {
    debug_directory result;

    if (debug_dir_rva == 0 || debug_dir_size == 0) {
        // No debug directory
        return result;
    }

    // Convert RVA to file offset
    size_t debug_dir_offset = rva_to_offset(sections, debug_dir_rva);
    if (debug_dir_offset == 0) {
        // Debug directory not mapped to file
        return result;
    }

    // Calculate number of entries
    // Each IMAGE_DEBUG_DIRECTORY is 28 bytes
    constexpr size_t entry_size = 28;
    size_t num_entries = debug_dir_size / entry_size;

    if (num_entries == 0 || num_entries > 100) {
        throw std::runtime_error("Invalid debug directory size: " + std::to_string(debug_dir_size));
    }

    const uint8_t* ptr = file_data.data() + debug_dir_offset;
    const uint8_t* end = file_data.data() + file_data.size();

    // Parse each entry
    for (size_t i = 0; i < num_entries; i++) {
        if (ptr + entry_size > end) {
            throw std::runtime_error("Debug directory truncated at entry " + std::to_string(i));
        }

        auto entry = parse_entry(file_data, sections, ptr, end);
        result.entries.push_back(std::move(entry));
    }

    return result;
}

debug_entry debug_directory_parser::parse_entry(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    const uint8_t*& ptr,
    const uint8_t* end
) {
    debug_entry entry;

    // Parse IMAGE_DEBUG_DIRECTORY using DataScript
    auto debug_dir = formats::pe::pe_debug::image_debug_directory::read(ptr, end);

    entry.characteristics = debug_dir.characteristics;
    entry.time_date_stamp = debug_dir.time_date_stamp;
    entry.major_version = debug_dir.major_version;
    entry.minor_version = debug_dir.minor_version;
    entry.type = static_cast<debug_type>(debug_dir.type_);
    entry.size_of_data = debug_dir.size_of_data;
    entry.address_of_raw_data = debug_dir.address_of_raw_data;
    entry.pointer_to_raw_data = debug_dir.pointer_to_raw_data;

    // Parse debug data based on type
    if (entry.size_of_data > 0 && entry.pointer_to_raw_data > 0) {
        // Use file offset (PointerToRawData) to read debug data
        size_t data_offset = entry.pointer_to_raw_data;

        if (data_offset < file_data.size() &&
            data_offset + entry.size_of_data <= file_data.size()) {

            if (entry.type == debug_type::CODEVIEW) {
                // Parse CodeView debug data (PDB info)
                parse_codeview_data(file_data, data_offset, entry.size_of_data, entry);
            } else {
                // Store raw data for other types
                entry.raw_data.assign(
                    file_data.begin() + data_offset,
                    file_data.begin() + data_offset + entry.size_of_data
                );
            }
        }
    }

    return entry;
}

void debug_directory_parser::parse_codeview_data(
    std::span<const uint8_t> file_data,
    size_t offset,
    uint32_t size,
    debug_entry& entry
) {
    if (size < 4) {
        // Too small to contain signature
        return;
    }

    const uint8_t* ptr = file_data.data() + offset;
    const uint8_t* end = ptr + size;

    // Read CodeView signature (first 4 bytes)
    uint32_t signature;
    std::memcpy(&signature, ptr, 4);

    codeview_signature cv_sig = static_cast<codeview_signature>(signature);

    if (cv_sig == codeview_signature::RSDS) {
        // PDB 7.0 format (modern)
        entry.codeview_pdb70_info = parse_pdb70(ptr, end);
    } else if (cv_sig == codeview_signature::NB10 ||
               cv_sig == codeview_signature::NB09 ||
               cv_sig == codeview_signature::NB11) {
        // PDB 2.0 format (older)
        entry.codeview_pdb20_info = parse_pdb20(ptr, end);
    }
    // else: Unknown CodeView signature, leave empty
}

codeview_pdb70 debug_directory_parser::parse_pdb70(
    const uint8_t* ptr,
    const uint8_t* end
) {
    codeview_pdb70 result;

    // CV_INFO_PDB70 structure:
    // - Signature (4 bytes) - already read
    // - GUID (16 bytes)
    // - Age (4 bytes)
    // - PDB path (null-terminated string)

    constexpr size_t min_size = 4 + 16 + 4;  // 24 bytes minimum
    if (ptr + min_size > end) {
        throw std::runtime_error("PDB70 data truncated");
    }

    // Skip signature (already checked)
    ptr += 4;

    // Read GUID (16 bytes)
    std::memcpy(result.guid.data(), ptr, 16);
    ptr += 16;

    // Read age
    std::memcpy(&result.age, ptr, 4);
    ptr += 4;

    // Read PDB path (null-terminated string)
    result.pdb_path = read_null_terminated_string(ptr, end);

    return result;
}

codeview_pdb20 debug_directory_parser::parse_pdb20(
    const uint8_t* ptr,
    const uint8_t* end
) {
    codeview_pdb20 result;

    // CV_INFO_PDB20 structure:
    // - Signature (4 bytes) - already read
    // - Offset (4 bytes)
    // - Signature/timestamp (4 bytes)
    // - Age (4 bytes)
    // - PDB path (null-terminated string)

    constexpr size_t min_size = 4 + 4 + 4 + 4;  // 16 bytes minimum
    if (ptr + min_size > end) {
        throw std::runtime_error("PDB20 data truncated");
    }

    // Skip signature (already checked)
    ptr += 4;

    // Skip offset (usually 0)
    ptr += 4;

    // Read signature (timestamp)
    std::memcpy(&result.signature, ptr, 4);
    ptr += 4;

    // Read age
    std::memcpy(&result.age, ptr, 4);
    ptr += 4;

    // Read PDB path (null-terminated string)
    result.pdb_path = read_null_terminated_string(ptr, end);

    return result;
}

std::string debug_directory_parser::read_null_terminated_string(
    const uint8_t* ptr,
    const uint8_t* end
) {
    std::string result;

    while (ptr < end && *ptr != 0) {
        result.push_back(static_cast<char>(*ptr));
        ptr++;

        // Safety limit: max 2048 characters
        if (result.size() > 2048) {
            throw std::runtime_error("String too long (> 2048 characters)");
        }
    }

    return result;
}

size_t debug_directory_parser::rva_to_offset(
    const std::vector<pe_section>& sections,
    uint32_t rva
) {
    if (rva == 0) {
        return 0;
    }

    auto offset = pe_section_parser::rva_to_file_offset(sections, rva);
    if (!offset) {
        return 0;  // Not mapped to file
    }
    return offset.value();
}

} // namespace libexe
