#include <libexe/parsers/export_directory_parser.hpp>
#include <libexe/pe_section_parser.hpp>
#include "libexe_format_pe_exports.hh"  // Generated DataScript parser
#include <stdexcept>
#include <algorithm>
#include <cstring>  // For memchr
#include <set>

namespace libexe {

export_directory export_directory_parser::parse(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t export_dir_rva,
    uint32_t export_dir_size
) {
    export_directory result;

    if (export_dir_rva == 0) {
        // No export directory
        return result;
    }

    // Convert RVA to file offset
    size_t export_dir_offset = rva_to_offset(sections, export_dir_rva);

    const uint8_t* ptr = file_data.data() + export_dir_offset;
    const uint8_t* end = file_data.data() + file_data.size();

    // Parse IMAGE_EXPORT_DIRECTORY
    auto export_dir = formats::pe::pe_exports::image_export_directory::read(ptr, end);

    // Store directory information
    result.ordinal_base = export_dir.base;
    result.timestamp = export_dir.time_date_stamp;
    result.major_version = export_dir.major_version;
    result.minor_version = export_dir.minor_version;

    // Read module name
    if (export_dir.name != 0) {
        result.module_name = read_string_at_rva(file_data, sections, export_dir.name);
    }

    // Read the three tables
    auto address_table = read_address_table(
        file_data,
        sections,
        export_dir.address_of_functions,
        export_dir.number_of_functions
    );

    auto name_pointer_table = read_name_pointer_table(
        file_data,
        sections,
        export_dir.address_of_names,
        export_dir.number_of_names
    );

    auto ordinal_table = read_ordinal_table(
        file_data,
        sections,
        export_dir.address_of_name_ordinals,
        export_dir.number_of_names
    );

    // Build set of ordinals that have names (for identifying ordinal-only exports)
    std::set<uint16_t> named_ordinals;
    for (uint16_t ordinal_offset : ordinal_table) {
        named_ordinals.insert(ordinal_offset);
    }

    // Process named exports first
    for (size_t i = 0; i < export_dir.number_of_names; i++) {
        export_entry entry;

        // Get ordinal offset from ordinal table
        uint16_t ordinal_offset = ordinal_table[i];

        // Calculate actual ordinal
        entry.ordinal = static_cast<uint16_t>(ordinal_offset + export_dir.base);
        entry.has_name = true;

        // Get function name from name pointer table
        uint32_t name_rva = name_pointer_table[i];
        entry.name = read_string_at_rva(file_data, sections, name_rva);

        // Get function RVA from address table
        if (ordinal_offset < address_table.size()) {
            entry.rva = address_table[ordinal_offset];

            // Check if this is a forwarder
            entry.is_forwarder = is_forwarder_rva(
                entry.rva,
                export_dir_rva,
                export_dir_size
            );

            if (entry.is_forwarder) {
                entry.forwarder_name = read_forwarder_string(file_data, sections, entry.rva);
            }
        } else {
            // Invalid ordinal offset
            entry.rva = 0;
            entry.is_forwarder = false;
        }

        result.exports.push_back(std::move(entry));
    }

    // Process ordinal-only exports (those not in name table)
    for (uint32_t i = 0; i < export_dir.number_of_functions; i++) {
        // Check if this ordinal has a name
        uint16_t ordinal_offset = static_cast<uint16_t>(i);
        if (named_ordinals.find(ordinal_offset) != named_ordinals.end()) {
            // This export has a name, already processed
            continue;
        }

        // Check if there's a valid function at this ordinal
        if (address_table[i] == 0) {
            // No function at this ordinal (gap in export table)
            continue;
        }

        export_entry entry;
        entry.ordinal = static_cast<uint16_t>(i + export_dir.base);
        entry.has_name = false;
        entry.name = "";  // No name
        entry.rva = address_table[i];

        // Check if this is a forwarder
        entry.is_forwarder = is_forwarder_rva(
            entry.rva,
            export_dir_rva,
            export_dir_size
        );

        if (entry.is_forwarder) {
            entry.forwarder_name = read_forwarder_string(file_data, sections, entry.rva);
        }

        result.exports.push_back(std::move(entry));
    }

    return result;
}

std::vector<uint32_t> export_directory_parser::read_address_table(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t table_rva,
    uint32_t count
) {
    std::vector<uint32_t> table;
    table.reserve(count);

    if (table_rva == 0 || count == 0) {
        return table;
    }

    size_t table_offset = rva_to_offset(sections, table_rva);
    const uint8_t* ptr = file_data.data() + table_offset;
    const uint8_t* end = file_data.data() + file_data.size();

    // Read array of uint32 RVAs
    for (uint32_t i = 0; i < count; i++) {
        if (ptr + 4 > end) {
            throw std::runtime_error("Export address table truncated");
        }

        // Read uint32 little-endian
        uint32_t rva = static_cast<uint32_t>(ptr[0]) |
                       (static_cast<uint32_t>(ptr[1]) << 8) |
                       (static_cast<uint32_t>(ptr[2]) << 16) |
                       (static_cast<uint32_t>(ptr[3]) << 24);

        table.push_back(rva);
        ptr += 4;
    }

    return table;
}

std::vector<uint32_t> export_directory_parser::read_name_pointer_table(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t table_rva,
    uint32_t count
) {
    // Name pointer table has same format as address table (array of uint32 RVAs)
    return read_address_table(file_data, sections, table_rva, count);
}

std::vector<uint16_t> export_directory_parser::read_ordinal_table(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t table_rva,
    uint32_t count
) {
    std::vector<uint16_t> table;
    table.reserve(count);

    if (table_rva == 0 || count == 0) {
        return table;
    }

    size_t table_offset = rva_to_offset(sections, table_rva);
    const uint8_t* ptr = file_data.data() + table_offset;
    const uint8_t* end = file_data.data() + file_data.size();

    // Read array of uint16 ordinals
    for (uint32_t i = 0; i < count; i++) {
        if (ptr + 2 > end) {
            throw std::runtime_error("Export ordinal table truncated");
        }

        // Read uint16 little-endian
        uint16_t ordinal = static_cast<uint16_t>(ptr[0]) |
                          (static_cast<uint16_t>(ptr[1]) << 8);

        table.push_back(ordinal);
        ptr += 2;
    }

    return table;
}

bool export_directory_parser::is_forwarder_rva(
    uint32_t rva,
    uint32_t export_section_rva,
    uint32_t export_section_size
) {
    // Forwarder check: if RVA points within the export section itself,
    // it's a forwarder string (not code)
    if (rva >= export_section_rva && rva < export_section_rva + export_section_size) {
        return true;
    }
    return false;
}

std::string export_directory_parser::read_forwarder_string(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t forwarder_rva
) {
    return read_string_at_rva(file_data, sections, forwarder_rva);
}

std::string export_directory_parser::read_string_at_rva(
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

size_t export_directory_parser::rva_to_offset(
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
