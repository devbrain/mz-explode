// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/resources/ne_resource_directory.hpp>
#include "exe_format.hh"  // Generated DataScript parser
#include <algorithm>
#include <stdexcept>
#include <cstring>

namespace libexe {
    // =============================================================================
    // ne_resource_directory Implementation
    // =============================================================================

    struct ne_resource_directory::impl {
        std::vector <uint8_t> rsrc_table_data; // Resource table data
        std::vector <uint8_t> file_data; // Full file data
        uint32_t ne_offset = 0; // NE header offset
        uint16_t alignment_shift = 0; // Alignment shift for file offsets
        resource_collection all_resources_;

        impl(std::span <const uint8_t> rsrc_data,
             std::span <const uint8_t> full_file_data,
             uint32_t ne_off)
            : rsrc_table_data(rsrc_data.begin(), rsrc_data.end()),
              file_data(full_file_data.begin(), full_file_data.end()),
              ne_offset(ne_off) {
            parse_resource_table();
        }

        void parse_resource_table();
        [[nodiscard]] std::string read_string(size_t offset) const;
        [[nodiscard]] std::span <const uint8_t> get_resource_data(uint16_t offset, uint16_t length) const;
    };

    ne_resource_directory::ne_resource_directory(
        std::span <const uint8_t> rsrc_table_data,
        std::span <const uint8_t> file_data,
        uint32_t ne_offset
    )
        : impl_(std::make_unique <impl>(rsrc_table_data, file_data, ne_offset)) {
    }

    // Destructor must be defined in .cpp file for pimpl idiom to work
    ne_resource_directory::~ne_resource_directory() = default;

    // =============================================================================
    // Resource Table Parsing
    // =============================================================================

    void ne_resource_directory::impl::parse_resource_table() {
        if (rsrc_table_data.size() < 2) {
            return; // Empty or invalid resource table
        }

        const uint8_t* ptr = rsrc_table_data.data();
        const uint8_t* end = rsrc_table_data.data() + rsrc_table_data.size();

        try {
            // Read alignment shift count (first word in resource table)
            alignment_shift = static_cast <uint16_t>(ptr[0]) | (static_cast <uint16_t>(ptr[1]) << 8);
            ptr += 2;

            // Parse resource type information blocks
            while (ptr + 8 <= end) {
                // Need at least 8 bytes for NeResourceTypeInfo
                // Read type info
                auto type_info = formats::exe_format_complete::NeResourceTypeInfo::read(ptr, end);

                // Type ID of 0 marks end of resource table
                if (type_info.type_id == 0) {
                    break;
                }

                // Determine if type is integer ID or string offset
                bool is_integer_type = (type_info.type_id & 0x8000) != 0;
                uint16_t type_id = is_integer_type ? (type_info.type_id & 0x7FFF) : type_info.type_id;

                // If type is a string offset, we could read it here, but for now
                // we'll just use the numeric type ID

                // Parse resource entries for this type
                for (uint16_t i = 0; i < type_info.resource_count; ++i) {
                    if (ptr + 8 > end) {
                        break; // Not enough data
                    }

                    // Read resource name info
                    auto name_info = formats::exe_format_complete::NeResourceNameInfo::read(ptr, end);

                    // Determine if resource name is integer ID or string offset
                    bool is_integer_id = (name_info.id & 0x8000) != 0;
                    std::optional <uint16_t> resource_id;
                    std::optional <std::string> resource_name;

                    if (is_integer_id) {
                        resource_id = name_info.id & 0x7FFF;
                    } else {
                        // String offset relative to beginning of resource table
                        resource_name = read_string(name_info.id);
                    }

                    // Get resource data
                    auto data = get_resource_data(name_info.offset, name_info.length);

                    // Create resource entry
                    // NOTE: NE resources don't have language IDs, so we use 0 (language-neutral)
                    // Codepage is also not specified in NE format, use 0
                    auto resource = resource_entry::create(
                        type_id,
                        resource_id,
                        resource_name,
                        0, // language = 0 (neutral)
                        0, // codepage = 0 (not specified)
                        data
                    );

                    all_resources_.entries_.push_back(std::move(resource));
                }
            }
        } catch (const std::exception& e) {
            // Resource parsing errors are non-fatal - just means no resources available
            // Could log error here if logging system available
        }
    }

    std::string ne_resource_directory::impl::read_string(size_t offset) const {
        if (offset >= rsrc_table_data.size()) {
            return "";
        }

        const uint8_t* ptr = rsrc_table_data.data() + offset;
        const uint8_t* end = rsrc_table_data.data() + rsrc_table_data.size();

        if (ptr >= end) {
            return "";
        }

        // First byte is length (NE strings are length-prefixed, NOT null-terminated)
        uint8_t length = *ptr;
        ptr++;

        if (ptr + length > end) {
            return "";
        }

        // Copy string data
        return std::string(reinterpret_cast <const char*>(ptr), length);
    }

    std::span <const uint8_t> ne_resource_directory::impl::get_resource_data(
        uint16_t offset,
        uint16_t length
    ) const {
        if (length == 0) {
            return {};
        }

        // Calculate actual file offset using alignment shift
        // Per docs/ne.fmt line 342-345: "File offset... in terms of alignment shift count"
        size_t actual_offset = static_cast <size_t>(offset) << alignment_shift;

        // NOTE: Despite docs saying length is in bytes, empirical testing with wrestool shows
        // that length is ALSO in alignment shift units (just like offset).
        // Example: CGA40WOA.FON has alignment_shift=4, length field=8, actual data=128 bytes (8*16=128)
        size_t actual_length = static_cast <size_t>(length) << alignment_shift;

        if (actual_offset + actual_length > file_data.size()) {
            return {}; // Data extends beyond file
        }

        return std::span <const uint8_t>(
            file_data.data() + actual_offset,
            actual_length
        );
    }

    // =============================================================================
    // Metadata
    // =============================================================================

    uint32_t ne_resource_directory::timestamp() const {
        // NE resources don't have timestamps
        return 0;
    }

    size_t ne_resource_directory::resource_count() const {
        return impl_->all_resources_.size();
    }

    // =============================================================================
    // High-Level Enumeration
    // =============================================================================

    resource_collection ne_resource_directory::all_resources() const {
        return impl_->all_resources_;
    }

    resource_collection ne_resource_directory::resources_by_type(resource_type type) const {
        return impl_->all_resources_.filter_by_type(type);
    }

    resource_collection ne_resource_directory::resources_by_type_id(uint16_t type_id) const {
        return impl_->all_resources_.filter_by_type_id(type_id);
    }

    // =============================================================================
    // Resource Lookup
    // =============================================================================

    std::optional <resource_entry> ne_resource_directory::find_resource(
        resource_type type,
        uint16_t id
    ) const {
        return impl_->all_resources_
                    .filter_by_type(type)
                    .filter_by_id(id)
                    .first();
    }

    std::optional <resource_entry> ne_resource_directory::find_resource(
        resource_type type,
        uint16_t id,
        uint16_t language
    ) const {
        // NE resources don't have language IDs - all are language 0
        // If specific language requested, filter by it; otherwise just match type+id
        auto filtered = impl_->all_resources_
                             .filter_by_type(type)
                             .filter_by_id(id);

        if (language == 0) {
            return filtered.first();
        }

        return filtered.filter_by_language(language).first();
    }

    std::optional <resource_entry> ne_resource_directory::find_resource(
        resource_type type,
        const std::string& name
    ) const {
        return impl_->all_resources_
                    .filter_by_type(type)
                    .filter_by_name(name)
                    .first();
    }

    std::optional <resource_entry> ne_resource_directory::find_resource(
        resource_type type,
        const std::string& name,
        uint16_t language
    ) const {
        auto filtered = impl_->all_resources_
                             .filter_by_type(type)
                             .filter_by_name(name);

        if (language == 0) {
            return filtered.first();
        }

        return filtered.filter_by_language(language).first();
    }

    std::optional <resource_entry> ne_resource_directory::find_resource_by_type_id(
        uint16_t type_id,
        uint16_t id
    ) const {
        return impl_->all_resources_
                    .filter_by_type_id(type_id)
                    .filter_by_id(id)
                    .first();
    }

    std::optional <resource_entry> ne_resource_directory::find_resource_by_type_id(
        uint16_t type_id,
        uint16_t id,
        uint16_t language
    ) const {
        auto filtered = impl_->all_resources_
                             .filter_by_type_id(type_id)
                             .filter_by_id(id);

        if (language == 0) {
            return filtered.first();
        }

        return filtered.filter_by_language(language).first();
    }

    // =============================================================================
    // Multi-Language Lookup
    // =============================================================================

    resource_collection ne_resource_directory::find_all_languages(
        resource_type type,
        uint16_t id
    ) const {
        return impl_->all_resources_
                    .filter_by_type(type)
                    .filter_by_id(id);
    }

    resource_collection ne_resource_directory::find_all_languages(
        resource_type type,
        const std::string& name
    ) const {
        return impl_->all_resources_
                    .filter_by_type(type)
                    .filter_by_name(name);
    }

    // =============================================================================
    // Low-Level Tree Navigation
    // =============================================================================

    std::vector <uint16_t> ne_resource_directory::types() const {
        std::vector <uint16_t> result;

        for (const auto& entry : impl_->all_resources_) {
            uint16_t type_id = entry.type_id();

            if (std::find(result.begin(), result.end(), type_id) == result.end()) {
                result.push_back(type_id);
            }
        }

        std::sort(result.begin(), result.end());
        return result;
    }

    std::vector <uint16_t> ne_resource_directory::ids_for_type(uint16_t type_id) const {
        std::vector <uint16_t> result;

        for (const auto& entry : impl_->all_resources_.filter_by_type_id(type_id)) {
            auto id = entry.id();
            if (id && std::find(result.begin(), result.end(), id.value()) == result.end()) {
                result.push_back(id.value());
            }
        }

        std::sort(result.begin(), result.end());
        return result;
    }

    std::vector <std::string> ne_resource_directory::names_for_type(uint16_t type_id) const {
        std::vector <std::string> result;

        for (const auto& entry : impl_->all_resources_.filter_by_type_id(type_id)) {
            auto name = entry.name();
            if (name && std::find(result.begin(), result.end(), name.value()) == result.end()) {
                result.push_back(name.value());
            }
        }

        std::sort(result.begin(), result.end());
        return result;
    }

    std::vector <uint16_t> ne_resource_directory::languages_for_id(
        uint16_t type_id,
        uint16_t id
    ) const {
        std::vector <uint16_t> result;

        for (const auto& entry : impl_->all_resources_
                                      .filter_by_type_id(type_id)
                                      .filter_by_id(id)) {
            uint16_t lang = entry.language();
            if (std::find(result.begin(), result.end(), lang) == result.end()) {
                result.push_back(lang);
            }
        }

        std::sort(result.begin(), result.end());
        return result;
    }

    std::vector <uint16_t> ne_resource_directory::languages_for_name(
        uint16_t type_id,
        const std::string& name
    ) const {
        std::vector <uint16_t> result;

        for (const auto& entry : impl_->all_resources_
                                      .filter_by_type_id(type_id)
                                      .filter_by_name(name)) {
            uint16_t lang = entry.language();
            if (std::find(result.begin(), result.end(), lang) == result.end()) {
                result.push_back(lang);
            }
        }

        std::sort(result.begin(), result.end());
        return result;
    }

    std::vector <uint16_t> ne_resource_directory::languages() const {
        std::vector <uint16_t> result;

        for (const auto& entry : impl_->all_resources_) {
            uint16_t lang = entry.language();
            if (std::find(result.begin(), result.end(), lang) == result.end()) {
                result.push_back(lang);
            }
        }

        std::sort(result.begin(), result.end());
        return result;
    }

    std::vector <uint16_t> ne_resource_directory::languages_for_type(uint16_t type_id) const {
        std::vector <uint16_t> result;

        for (const auto& entry : impl_->all_resources_.filter_by_type_id(type_id)) {
            uint16_t lang = entry.language();
            if (std::find(result.begin(), result.end(), lang) == result.end()) {
                result.push_back(lang);
            }
        }

        std::sort(result.begin(), result.end());
        return result;
    }
} // namespace libexe
