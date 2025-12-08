// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/parsers/exception_directory_parser.hpp>
#include <libexe_format_pe_exception.hh>
#include <stdexcept>
#include <cstring>

namespace libexe {

exception_directory exception_directory_parser::parse(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t exception_rva,
    uint32_t exception_size,
    bool is_64bit
) {
    exception_directory result;

    // Empty exception directory
    if (exception_rva == 0 || exception_size == 0) {
        result.type = exception_handling_type::NONE;
        return result;
    }

    // x86 (32-bit) doesn't use exception directory
    if (!is_64bit) {
        result.type = exception_handling_type::NONE;
        return result;
    }

    // Convert RVA to file offset
    size_t offset = rva_to_offset(sections, exception_rva);
    if (offset == 0 || offset >= file_data.size()) {
        throw std::runtime_error("Exception directory RVA is invalid or not mapped");
    }

    // Validate size
    if (offset + exception_size > file_data.size()) {
        throw std::runtime_error("Exception directory extends beyond file bounds");
    }

    // x64: Exception directory is an array of RUNTIME_FUNCTION entries (12 bytes each)
    const size_t entry_size = 12;  // sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)

    if (exception_size % entry_size != 0) {
        throw std::runtime_error("Exception directory size is not a multiple of RUNTIME_FUNCTION size");
    }

    size_t entry_count = exception_size / entry_size;

    // Sanity check: limit to reasonable number of entries
    if (entry_count > 100000) {
        throw std::runtime_error("Exception directory has too many entries");
    }

    const uint8_t* ptr = file_data.data() + offset;
    const uint8_t* end = ptr + exception_size;

    // Parse x64 runtime functions
    result.type = exception_handling_type::X64_SEH;
    result.runtime_functions = parse_x64_runtime_functions(ptr, end, entry_count);

    return result;
}

std::vector<runtime_function> exception_directory_parser::parse_x64_runtime_functions(
    const uint8_t* ptr,
    const uint8_t* end,
    size_t entry_count
) {
    std::vector<runtime_function> functions;
    functions.reserve(entry_count);

    for (size_t i = 0; i < entry_count; ++i) {
        if (ptr + 12 > end) {
            break;  // Truncated entry
        }

        runtime_function func = parse_runtime_function_entry(ptr, end);

        // Only add valid entries
        if (func.is_valid()) {
            functions.push_back(func);
        }

        ptr += 12;
    }

    return functions;
}

runtime_function exception_directory_parser::parse_runtime_function_entry(
    const uint8_t* ptr,
    const uint8_t* end
) {
    runtime_function func;

    if (ptr + 12 > end) {
        return func;  // Return empty function
    }

    // Use DataScript to parse the structure
    auto entry = formats::pe::pe_exception::image_runtime_function_entry::read(ptr, end);

    func.begin_address = entry.begin_address;
    func.end_address = entry.end_address;
    func.unwind_info_address = entry.unwind_info_address;

    return func;
}

unwind_info exception_directory_parser::parse_unwind_info(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t unwind_info_rva
) {
    unwind_info info;

    // Convert RVA to file offset
    size_t offset = rva_to_offset(sections, unwind_info_rva);
    if (offset == 0 || offset >= file_data.size()) {
        return info;  // Return empty info
    }

    if (offset + 4 > file_data.size()) {
        return info;  // Not enough space for header
    }

    const uint8_t* ptr = file_data.data() + offset;
    const uint8_t* end = file_data.data() + file_data.size();

    // Parse UNWIND_INFO header (4 bytes)
    auto header = formats::pe::pe_exception::unwind_info_header::read(ptr, end);

    info.version = header.version_and_flags & 0x07;
    info.flags = (header.version_and_flags >> 3) & 0x1F;
    info.size_of_prolog = header.size_of_prolog;
    info.count_of_codes = header.count_of_codes;
    info.frame_register = header.frame_register_and_offset;

    ptr += 4;

    // Parse unwind codes (2 bytes each, count must be even for alignment)
    size_t code_count = info.count_of_codes;
    if (code_count % 2 != 0) {
        code_count++;  // Padded to DWORD boundary
    }

    for (size_t i = 0; i < info.count_of_codes && ptr + 2 <= end; ++i) {
        auto code_entry = formats::pe::pe_exception::unwind_code_entry::read(ptr, end);

        unwind_code code;
        code.code_offset = code_entry.code_offset;
        code.unwind_op = code_entry.unwind_op_and_info;

        info.unwind_codes.push_back(code);
        ptr += 2;
    }

    // Skip to DWORD boundary
    ptr += (code_count - info.count_of_codes) * 2;

    // Check for exception handler (if flags indicate)
    if (info.has_exception_handler() || info.has_termination_handler()) {
        if (ptr + 4 <= end) {
            std::memcpy(&info.exception_handler_rva, ptr, 4);
            ptr += 4;
        }
    }

    return info;
}

size_t exception_directory_parser::rva_to_offset(
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

} // namespace libexe
