#include <libexe/resources/parsers/icon_group_parser.hpp>
#include <formats/resources/basic/basic.hh>  // Generated DataScript parser (modular)
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
        auto ds_group = formats::resources::basic::icon_group::read(ptr, end);

        // Convert to our public API structure
        icon_group result;
        result.reserved = ds_group.reserved;
        result.type = ds_group.type;
        result.count = ds_group.count;

        // Convert entries
        result.entries.reserve(ds_group.entries.size());
        for (const auto& ds_entry : ds_group.entries) {
            icon_directory_entry entry;
            entry.width = ds_entry.width;
            entry.height = ds_entry.height;
            entry.color_count = ds_entry.color_count;
            entry.reserved = ds_entry.reserved;
            entry.planes = ds_entry.planes;
            entry.bit_count = ds_entry.bit_count;
            entry.size_in_bytes = ds_entry.bytes_in_res;
            entry.resource_id = ds_entry.name_ordinal;

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
