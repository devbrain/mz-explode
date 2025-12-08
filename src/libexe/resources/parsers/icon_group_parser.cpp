#include <libexe/resources/parsers/icon_group_parser.hpp>
#include "exe_format.hh"  // Generated DataScript parser
#include <stdexcept>

namespace libexe {

std::optional<icon_group> icon_group_parser::parse(std::span<const uint8_t> data) {
    if (data.empty()) {
        return std::nullopt;
    }

    try {
        // Parse using generated DataScript parser
        const uint8_t* ptr = data.data();
        const uint8_t* end = data.data() + data.size();
        auto ds_group = formats::exe_format_complete::IconGroup::read(ptr, end);

        // Convert to our public API structure
        icon_group result;
        result.reserved = ds_group.wReserved;
        result.type = ds_group.wType;
        result.count = ds_group.wCount;

        // Convert entries
        result.entries.reserve(ds_group.entries.size());
        for (const auto& ds_entry : ds_group.entries) {
            icon_directory_entry entry;
            entry.width = ds_entry.bWidth;
            entry.height = ds_entry.bHeight;
            entry.color_count = ds_entry.bColorCount;
            entry.reserved = ds_entry.bReserved;
            entry.planes = ds_entry.wPlanes;
            entry.bit_count = ds_entry.wBitCount;
            entry.size_in_bytes = ds_entry.dwBytesInRes;
            entry.resource_id = ds_entry.wNameOrdinal;

            result.entries.push_back(entry);
        }

        return result;
    }
    catch (const std::exception&) {
        // Parse error - return nullopt
        return std::nullopt;
    }
}

} // namespace libexe
