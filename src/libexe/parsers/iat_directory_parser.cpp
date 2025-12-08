// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/parsers/iat_directory_parser.hpp>
#include <libexe/pe_section_parser.hpp>
#include <stdexcept>
#include <cstring>

namespace libexe {

namespace {

/**
 * Read 32-bit little-endian value
 */
uint32_t read_u32(const uint8_t* ptr) {
    uint32_t value;
    std::memcpy(&value, ptr, sizeof(value));
    return value;
}

/**
 * Read 64-bit little-endian value
 */
uint64_t read_u64(const uint8_t* ptr) {
    uint64_t value;
    std::memcpy(&value, ptr, sizeof(value));
    return value;
}

} // anonymous namespace

iat_directory iat_directory_parser::parse(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t iat_rva,
    uint32_t iat_size,
    bool is_64bit
) {
    iat_directory result;
    result.is_64bit = is_64bit;

    // Empty IAT (no data directory or size is 0)
    if (iat_rva == 0 || iat_size == 0) {
        return result;
    }

    // Convert RVA to file offset
    auto iat_offset_opt = pe_section_parser::rva_to_file_offset(sections, iat_rva);
    if (!iat_offset_opt) {
        // Invalid RVA
        return result;
    }
    uint32_t iat_offset = static_cast<uint32_t>(*iat_offset_opt);

    // Validate file offset
    if (iat_offset >= file_data.size()) {
        return result;
    }

    // Calculate number of entries based on size
    const size_t entry_size = is_64bit ? 8 : 4;
    const size_t entry_count = iat_size / entry_size;

    // Sanity check: limit to reasonable number of entries
    if (entry_count > 100000) {
        return result;
    }

    // Validate we have enough data
    if (iat_offset + iat_size > file_data.size()) {
        return result;
    }

    const uint8_t* ptr = file_data.data() + iat_offset;
    result.entries.reserve(entry_count);

    // Parse entries
    for (size_t i = 0; i < entry_count; ++i) {
        iat_entry entry;
        entry.is_64bit = is_64bit;

        if (is_64bit) {
            entry.value = read_u64(ptr);
            ptr += 8;
        } else {
            entry.value = read_u32(ptr);
            ptr += 4;
        }

        result.entries.push_back(entry);

        // Note: We don't stop at null entries here because the IAT
        // data directory specifies the exact size. There may be
        // multiple null entries or the IAT may not be null-terminated.
    }

    return result;
}

} // namespace libexe
