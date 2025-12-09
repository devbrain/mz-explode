// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/pe/directories/delay_import.hpp>
#include <libexe_format_pe_delay_imports.hh>
#include <stdexcept>
#include <cstring>

namespace libexe {

delay_import_directory delay_import_directory_parser::parse(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t delay_import_rva,
    uint32_t delay_import_size,
    bool is_64bit,
    uint64_t image_base
) {
    delay_import_directory result;

    // Empty delay import directory
    if (delay_import_rva == 0 || delay_import_rva == 0xFFFFFFFF) {
        return result;
    }

    // NOTE: Don't check delay_import_size == 0, many PE files set size=0
    // for null-terminated arrays of descriptors.

    // Convert RVA to file offset - return empty on invalid RVA
    size_t offset = rva_to_offset(sections, delay_import_rva);
    if (offset == 0 || offset >= file_data.size()) {
        return result;  // Invalid RVA - return empty directory
    }

    // Calculate effective end - if size is 0 or invalid, scan to end of file
    size_t effective_size = delay_import_size;
    if (effective_size == 0 || offset + effective_size > file_data.size()) {
        effective_size = file_data.size() - offset;
    }

    const uint8_t* ptr = file_data.data() + offset;
    const uint8_t* end = ptr + effective_size;

    // Parse delay import descriptors until null descriptor
    const size_t descriptor_size = 32;  // sizeof(IMAGE_DELAYLOAD_DESCRIPTOR)

    while (ptr + descriptor_size <= end) {
        // Check for null descriptor (terminator)
        if (is_null_descriptor(ptr)) {
            break;
        }

        try {
            delay_import_descriptor desc = parse_descriptor(
                ptr,
                end,
                file_data,
                sections,
                is_64bit,
                image_base
            );

            if (!desc.is_empty()) {
                result.descriptors.push_back(std::move(desc));
            }
        } catch (const std::exception&) {
            // Skip malformed descriptors
            break;
        }

        ptr += descriptor_size;

        // Safety limit: max 1000 delay-loaded DLLs
        if (result.descriptors.size() >= 1000) {
            break;
        }
    }

    return result;
}

// Helper to convert VA to RVA if needed
static uint32_t va_to_rva(uint32_t value, uint64_t image_base, bool use_rva) {
    if (use_rva || value == 0 || value == 0xFFFFFFFF) {
        return value;  // Already RVA or invalid
    }
    // Check if value looks like an absolute VA (>= image_base)
    if (value >= image_base && value < image_base + 0x80000000) {
        return static_cast<uint32_t>(value - image_base);
    }
    return value;  // Might already be RVA
}

delay_import_descriptor delay_import_directory_parser::parse_descriptor(
    const uint8_t* ptr,
    const uint8_t* end,
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    bool is_64bit,
    uint64_t image_base
) {
    delay_import_descriptor desc;

    if (ptr + 32 > end) {
        return desc;
    }

    // Use DataScript to parse the descriptor
    formats::pe::pe_delay_imports::image_delayload_descriptor delayload;
    try {
        delayload = formats::pe::pe_delay_imports::image_delayload_descriptor::read(ptr, end);
    } catch (...) {
        return desc;
    }

    desc.attributes = delayload.attributes;

    // Bit 0 of attributes indicates if addresses are RVAs (1) or VAs (0)
    // However, many tools set attributes=0 but still use VAs
    // We detect this by checking if the dll_name field looks like a VA
    bool use_rva = (delayload.attributes & 1) != 0;

    // Heuristic: if dll_name looks like an absolute VA (>= image_base), treat all as VAs
    if (!use_rva && delayload.dll_name_rva >= image_base &&
        delayload.dll_name_rva < image_base + 0x80000000) {
        use_rva = false;  // Use VA-to-RVA conversion
    } else if (delayload.dll_name_rva != 0 && delayload.dll_name_rva < 0x10000000) {
        use_rva = true;  // Looks like an RVA already
    }

    // Convert all address fields from VA to RVA if needed
    desc.module_handle_rva = va_to_rva(delayload.module_handle_rva, image_base, use_rva);
    desc.delay_import_address_table_rva = va_to_rva(delayload.delay_import_address_table_rva, image_base, use_rva);
    desc.delay_import_name_table_rva = va_to_rva(delayload.delay_import_name_table_rva, image_base, use_rva);
    desc.bound_delay_import_table_rva = va_to_rva(delayload.bound_delay_import_table_rva, image_base, use_rva);
    desc.unload_delay_import_table_rva = va_to_rva(delayload.unload_delay_import_table_rva, image_base, use_rva);
    desc.time_date_stamp = delayload.time_date_stamp;

    // Read DLL name
    uint32_t dll_name_rva = va_to_rva(delayload.dll_name_rva, image_base, use_rva);
    if (dll_name_rva != 0 && dll_name_rva != 0xFFFFFFFF) {
        size_t dll_name_offset = rva_to_offset(sections, dll_name_rva);
        if (dll_name_offset > 0 && dll_name_offset < file_data.size()) {
            desc.dll_name = read_string(file_data, dll_name_offset);
        }
    }

    // Parse delay import name table (INT)
    if (desc.delay_import_name_table_rva != 0 && desc.delay_import_name_table_rva != 0xFFFFFFFF) {
        desc.functions = parse_delay_int(
            file_data,
            sections,
            desc.delay_import_name_table_rva,
            is_64bit
        );
    }

    return desc;
}

std::vector<delay_imported_function> delay_import_directory_parser::parse_delay_int(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t int_rva,
    bool is_64bit
) {
    std::vector<delay_imported_function> functions;

    // Convert INT RVA to file offset
    size_t int_offset = rva_to_offset(sections, int_rva);
    if (int_offset == 0 || int_offset >= file_data.size()) {
        return functions;
    }

    const uint8_t* ptr = file_data.data() + int_offset;
    const uint8_t* end = file_data.data() + file_data.size();

    // Size of INT entry (pointer to IMAGE_IMPORT_BY_NAME or ordinal)
    const size_t entry_size = is_64bit ? 8 : 4;

    // Parse INT entries until null entry
    while (ptr + entry_size <= end) {
        uint64_t entry_value = 0;

        if (is_64bit) {
            std::memcpy(&entry_value, ptr, 8);
        } else {
            uint32_t value32 = 0;
            std::memcpy(&value32, ptr, 4);
            entry_value = value32;
        }

        // Null entry terminates the table
        if (entry_value == 0) {
            break;
        }

        delay_imported_function func;

        // Check if import is by ordinal
        const uint64_t ordinal_flag = is_64bit ? 0x8000000000000000ULL : 0x80000000UL;

        if (entry_value & ordinal_flag) {
            // Import by ordinal
            func.import_by_ordinal = true;
            func.ordinal = static_cast<uint16_t>(entry_value & 0xFFFF);
        } else {
            // Import by name
            func.import_by_ordinal = false;

            // Entry value is RVA to IMAGE_IMPORT_BY_NAME
            uint32_t name_rva = static_cast<uint32_t>(entry_value);
            func = parse_import_by_name(file_data, sections, name_rva);
        }

        functions.push_back(func);

        ptr += entry_size;

        // Safety limit: max 10000 functions per DLL
        if (functions.size() >= 10000) {
            break;
        }
    }

    return functions;
}

delay_imported_function delay_import_directory_parser::parse_import_by_name(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t name_rva
) {
    delay_imported_function func;

    // Convert name RVA to file offset
    size_t name_offset = rva_to_offset(sections, name_rva);
    if (name_offset == 0 || name_offset + 2 >= file_data.size()) {
        return func;
    }

    const uint8_t* ptr = file_data.data() + name_offset;
    const uint8_t* end = file_data.data() + file_data.size();

    // Parse IMAGE_IMPORT_BY_NAME header
    auto import_by_name = formats::pe::pe_delay_imports::image_import_by_name_header::read(ptr, end);
    func.hint = import_by_name.hint;

    // Read function name (null-terminated string after hint)
    func.name = read_string(file_data, name_offset + 2);

    return func;
}

std::string delay_import_directory_parser::read_string(
    std::span<const uint8_t> file_data,
    size_t offset,
    size_t max_length
) {
    if (offset >= file_data.size()) {
        return "";
    }

    size_t remaining = file_data.size() - offset;
    size_t max_read = std::min(max_length, remaining);

    const char* str = reinterpret_cast<const char*>(file_data.data() + offset);
    size_t length = 0;

    // Find null terminator
    while (length < max_read && str[length] != '\0') {
        length++;
    }

    return std::string(str, length);
}

size_t delay_import_directory_parser::rva_to_offset(
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

    return 0;  // RVA not found in any section
}

bool delay_import_directory_parser::is_null_descriptor(const uint8_t* ptr) {
    // Check if all 32 bytes are zero
    for (size_t i = 0; i < 32; ++i) {
        if (ptr[i] != 0) {
            return false;
        }
    }
    return true;
}

} // namespace libexe
