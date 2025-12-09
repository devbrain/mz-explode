#include <libexe/pe/directories/export.hpp>
#include <libexe/pe/section_parser.hpp>
#include "libexe_format_pe_exports.hh"  // Generated DataScript parser
#include <stdexcept>
#include <algorithm>
#include <cstring>  // For memchr
#include <set>

namespace libexe {

// Maximum reasonable values to prevent malformed data from causing issues
static constexpr uint32_t MAX_EXPORT_FUNCTIONS = 65536;
static constexpr uint32_t MAX_EXPORT_NAMES = 65536;

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

    // Convert RVA to file offset - return empty if invalid
    auto export_dir_offset_opt = pe_section_parser::rva_to_file_offset(sections, export_dir_rva);
    if (!export_dir_offset_opt) {
        return result;
    }
    size_t export_dir_offset = *export_dir_offset_opt;

    if (export_dir_offset + 40 > file_data.size()) {
        // Not enough data for IMAGE_EXPORT_DIRECTORY (40 bytes)
        return result;
    }

    const uint8_t* ptr = file_data.data() + export_dir_offset;
    const uint8_t* end = file_data.data() + file_data.size();

    // Parse IMAGE_EXPORT_DIRECTORY
    formats::pe::pe_exports::image_export_directory export_dir;
    try {
        export_dir = formats::pe::pe_exports::image_export_directory::read(ptr, end);
    } catch (...) {
        // Malformed header
        return result;
    }

    // Validate counts - reject obviously malformed values
    uint32_t num_functions = export_dir.number_of_functions;
    uint32_t num_names = export_dir.number_of_names;

    if (num_functions > MAX_EXPORT_FUNCTIONS) {
        // Try to infer reasonable count from available space in EAT
        if (export_dir.address_of_functions != 0 &&
            export_dir.address_of_functions != 0xFFFFFFFF) {
            // Calculate how many function entries could fit
            auto eat_offset_opt = pe_section_parser::rva_to_file_offset(sections, export_dir.address_of_functions);
            if (eat_offset_opt) {
                size_t available = file_data.size() - *eat_offset_opt;
                // Limit to a reasonable maximum based on available space
                num_functions = std::min(static_cast<uint32_t>(available / 4), MAX_EXPORT_FUNCTIONS);
                // Further limit to avoid reading garbage - scan for valid entries
                // For malformed files, assume a small reasonable count
                num_functions = std::min(num_functions, 256u);
            } else {
                num_functions = 0;
            }
        } else {
            num_functions = 0;
        }
    }

    if (num_names > MAX_EXPORT_NAMES || num_names > num_functions) {
        num_names = 0;  // Malformed - names can't exceed functions
    }

    // Store directory information
    result.ordinal_base = export_dir.base;
    result.timestamp = export_dir.time_date_stamp;
    result.major_version = export_dir.major_version;
    result.minor_version = export_dir.minor_version;

    // Read module name (with validation)
    if (export_dir.name != 0 && export_dir.name != 0xFFFFFFFF) {
        try {
            result.module_name = read_string_at_rva(file_data, sections, export_dir.name);
        } catch (...) {
            // Invalid module name RVA - continue without it
        }
    }

    // Read the three tables with validated counts
    std::vector<uint32_t> address_table;
    std::vector<uint32_t> name_pointer_table;
    std::vector<uint16_t> ordinal_table;

    try {
        address_table = read_address_table(
            file_data,
            sections,
            export_dir.address_of_functions,
            num_functions
        );
    } catch (...) {
        // Failed to read address table - try to continue with what we have
    }

    try {
        name_pointer_table = read_name_pointer_table(
            file_data,
            sections,
            export_dir.address_of_names,
            num_names
        );
    } catch (...) {
        // Failed to read name pointer table
        name_pointer_table.clear();
    }

    try {
        ordinal_table = read_ordinal_table(
            file_data,
            sections,
            export_dir.address_of_name_ordinals,
            num_names
        );
    } catch (...) {
        // Failed to read ordinal table
        ordinal_table.clear();
    }

    // If we have no address table, we can't process any exports
    if (address_table.empty()) {
        return result;
    }

    // Build set of ordinals that have names (for identifying ordinal-only exports)
    std::set<uint16_t> named_ordinals;
    for (uint16_t ordinal_offset : ordinal_table) {
        named_ordinals.insert(ordinal_offset);
    }

    // Process named exports first
    size_t num_named = std::min({
        name_pointer_table.size(),
        ordinal_table.size(),
        static_cast<size_t>(num_names)
    });

    for (size_t i = 0; i < num_named; i++) {
        try {
            export_entry entry;

            // Get ordinal offset from ordinal table
            uint16_t ordinal_offset = ordinal_table[i];

            // Calculate actual ordinal
            entry.ordinal = static_cast<uint16_t>(ordinal_offset + export_dir.base);
            entry.has_name = true;

            // Get function name from name pointer table
            uint32_t name_rva = name_pointer_table[i];
            if (name_rva != 0 && name_rva != 0xFFFFFFFF) {
                entry.name = read_string_at_rva(file_data, sections, name_rva);
            }

            // Get function RVA from address table
            if (ordinal_offset < address_table.size()) {
                entry.rva = address_table[ordinal_offset];

                // Skip invalid RVAs
                if (entry.rva == 0 || entry.rva == 0xFFFFFFFF) {
                    continue;
                }

                // Check if this is a forwarder
                entry.is_forwarder = is_forwarder_rva(
                    entry.rva,
                    export_dir_rva,
                    export_dir_size
                );

                if (entry.is_forwarder) {
                    try {
                        entry.forwarder_name = read_forwarder_string(file_data, sections, entry.rva);
                    } catch (...) {
                        entry.is_forwarder = false;  // Can't read forwarder string
                    }
                }
            } else {
                // Invalid ordinal offset
                continue;
            }

            result.exports.push_back(std::move(entry));
        } catch (...) {
            // Skip malformed entry
            continue;
        }
    }

    // Process ordinal-only exports (those not in name table)
    for (size_t i = 0; i < address_table.size(); i++) {
        // Check if this ordinal has a name
        uint16_t ordinal_offset = static_cast<uint16_t>(i);
        if (named_ordinals.find(ordinal_offset) != named_ordinals.end()) {
            // This export has a name, already processed
            continue;
        }

        // Check if there's a valid function at this ordinal
        uint32_t func_rva = address_table[i];
        if (func_rva == 0 || func_rva == 0xFFFFFFFF) {
            // No function at this ordinal (gap in export table or invalid)
            continue;
        }

        try {
            export_entry entry;
            entry.ordinal = static_cast<uint16_t>(i + export_dir.base);
            entry.has_name = false;
            entry.name = "";  // No name
            entry.rva = func_rva;

            // Check if this is a forwarder
            entry.is_forwarder = is_forwarder_rva(
                entry.rva,
                export_dir_rva,
                export_dir_size
            );

            if (entry.is_forwarder) {
                try {
                    entry.forwarder_name = read_forwarder_string(file_data, sections, entry.rva);
                } catch (...) {
                    entry.is_forwarder = false;
                }
            }

            result.exports.push_back(std::move(entry));
        } catch (...) {
            // Skip malformed entry
            continue;
        }
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

    if (table_rva == 0 || table_rva == 0xFFFFFFFF || count == 0) {
        return table;
    }

    // Cap count to prevent excessive memory allocation
    count = std::min(count, MAX_EXPORT_FUNCTIONS);
    table.reserve(count);

    auto table_offset_opt = pe_section_parser::rva_to_file_offset(sections, table_rva);
    if (!table_offset_opt) {
        return table;  // Invalid RVA
    }
    size_t table_offset = *table_offset_opt;

    const uint8_t* ptr = file_data.data() + table_offset;
    const uint8_t* end = file_data.data() + file_data.size();

    // Read array of uint32 RVAs
    for (uint32_t i = 0; i < count; i++) {
        if (ptr + 4 > end) {
            break;  // Table truncated - return what we have
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

    if (table_rva == 0 || table_rva == 0xFFFFFFFF || count == 0) {
        return table;
    }

    // Cap count to prevent excessive memory allocation
    count = std::min(count, MAX_EXPORT_NAMES);
    table.reserve(count);

    auto table_offset_opt = pe_section_parser::rva_to_file_offset(sections, table_rva);
    if (!table_offset_opt) {
        return table;  // Invalid RVA
    }
    size_t table_offset = *table_offset_opt;

    const uint8_t* ptr = file_data.data() + table_offset;
    const uint8_t* end = file_data.data() + file_data.size();

    // Read array of uint16 ordinals
    for (uint32_t i = 0; i < count; i++) {
        if (ptr + 2 > end) {
            break;  // Table truncated - return what we have
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
    if (rva == 0 || rva == 0xFFFFFFFF) {
        return "";
    }

    auto offset_opt = pe_section_parser::rva_to_file_offset(sections, rva);
    if (!offset_opt) {
        throw std::runtime_error("RVA 0x" + std::to_string(rva) + " not found in any section");
    }
    size_t offset = *offset_opt;

    if (offset >= file_data.size()) {
        return "";
    }

    // Find null terminator (limit search to reasonable length)
    const uint8_t* start = file_data.data() + offset;
    const uint8_t* end = file_data.data() + file_data.size();
    size_t max_len = std::min(static_cast<size_t>(end - start), static_cast<size_t>(4096));

    const uint8_t* null_pos = static_cast<const uint8_t*>(
        ::memchr(start, 0, max_len)
    );

    if (!null_pos) {
        // No null terminator found within limit - truncate
        return std::string(reinterpret_cast<const char*>(start), max_len);
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
