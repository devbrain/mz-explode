#include <libexe/parsers/tls_directory_parser.hpp>
#include <libexe/pe_section_parser.hpp>
#include "libexe_format_pe_tls.hh"  // Generated DataScript parser
#include <stdexcept>

namespace libexe {

tls_directory tls_directory_parser::parse(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t tls_dir_rva,
    uint32_t tls_dir_size,
    bool is_64bit,
    uint64_t image_base
) {
    tls_directory result;

    if (tls_dir_rva == 0 || tls_dir_size == 0) {
        // No TLS directory
        return result;
    }

    // Convert RVA to file offset
    size_t tls_dir_offset = rva_to_offset(sections, tls_dir_rva);

    const uint8_t* ptr = file_data.data() + tls_dir_offset;
    const uint8_t* end = file_data.data() + file_data.size();

    if (is_64bit) {
        // Parse IMAGE_TLS_DIRECTORY64
        auto tls_dir = formats::pe::pe_tls::image_tls_directory64::read(ptr, end);

        result.start_address_of_raw_data = tls_dir.start_address_of_raw_data;
        result.end_address_of_raw_data = tls_dir.end_address_of_raw_data;
        result.address_of_index = tls_dir.address_of_index;
        result.address_of_callbacks = tls_dir.address_of_callbacks;
        result.size_of_zero_fill = tls_dir.size_of_zero_fill;
        result.characteristics = tls_dir.characteristics;

        // Parse callbacks if present
        if (tls_dir.address_of_callbacks != 0) {
            result.callbacks = parse_callbacks(
                file_data,
                sections,
                tls_dir.address_of_callbacks,
                true,  // 64-bit
                image_base
            );
        }

    } else {
        // Parse IMAGE_TLS_DIRECTORY32
        auto tls_dir = formats::pe::pe_tls::image_tls_directory32::read(ptr, end);

        result.start_address_of_raw_data = tls_dir.start_address_of_raw_data;
        result.end_address_of_raw_data = tls_dir.end_address_of_raw_data;
        result.address_of_index = tls_dir.address_of_index;
        result.address_of_callbacks = tls_dir.address_of_callbacks;
        result.size_of_zero_fill = tls_dir.size_of_zero_fill;
        result.characteristics = tls_dir.characteristics;

        // Parse callbacks if present
        if (tls_dir.address_of_callbacks != 0) {
            result.callbacks = parse_callbacks(
                file_data,
                sections,
                tls_dir.address_of_callbacks,
                false,  // 32-bit
                image_base
            );
        }
    }

    return result;
}

std::vector<tls_callback> tls_directory_parser::parse_callbacks(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint64_t callbacks_va,
    bool is_64bit,
    uint64_t image_base
) {
    std::vector<tls_callback> callbacks;

    if (callbacks_va == 0) {
        return callbacks;
    }

    // Convert VA to file offset
    size_t callbacks_offset = va_to_offset(sections, callbacks_va, image_base);

    const uint8_t* ptr = file_data.data() + callbacks_offset;
    const uint8_t* end = file_data.data() + file_data.size();

    // Read array of callback pointers (null-terminated)
    while (ptr < end) {
        tls_callback callback;

        if (is_64bit) {
            // Read 64-bit pointer
            if (ptr + 8 > end) {
                break;
            }

            uint64_t callback_va = static_cast<uint64_t>(ptr[0]) |
                                  (static_cast<uint64_t>(ptr[1]) << 8) |
                                  (static_cast<uint64_t>(ptr[2]) << 16) |
                                  (static_cast<uint64_t>(ptr[3]) << 24) |
                                  (static_cast<uint64_t>(ptr[4]) << 32) |
                                  (static_cast<uint64_t>(ptr[5]) << 40) |
                                  (static_cast<uint64_t>(ptr[6]) << 48) |
                                  (static_cast<uint64_t>(ptr[7]) << 56);

            callback.address = callback_va;
            ptr += 8;

            // Check for null terminator
            if (callback_va == 0) {
                break;
            }

        } else {
            // Read 32-bit pointer
            if (ptr + 4 > end) {
                break;
            }

            uint32_t callback_va = static_cast<uint32_t>(ptr[0]) |
                                  (static_cast<uint32_t>(ptr[1]) << 8) |
                                  (static_cast<uint32_t>(ptr[2]) << 16) |
                                  (static_cast<uint32_t>(ptr[3]) << 24);

            callback.address = callback_va;
            ptr += 4;

            // Check for null terminator
            if (callback_va == 0) {
                break;
            }
        }

        callbacks.push_back(callback);

        // Safety limit: prevent infinite loop on malformed data
        if (callbacks.size() > 1000) {
            throw std::runtime_error("TLS callback array too large (> 1000 entries)");
        }
    }

    return callbacks;
}

size_t tls_directory_parser::va_to_offset(
    const std::vector<pe_section>& sections,
    uint64_t va,
    uint64_t image_base
) {
    // Convert VA to RVA
    if (va < image_base) {
        throw std::runtime_error(
            "Invalid VA 0x" + std::to_string(va) +
            " (less than image base 0x" + std::to_string(image_base) + ")"
        );
    }

    uint32_t rva = static_cast<uint32_t>(va - image_base);

    // Convert RVA to file offset
    return rva_to_offset(sections, rva);
}

size_t tls_directory_parser::rva_to_offset(
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
