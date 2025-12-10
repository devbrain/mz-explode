// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/resources/ne_resource_directory.hpp>
#include <formats/ne/ne_header/ne_header.hh>  // Generated DataScript parser (modular)
#include <algorithm>
#include <stdexcept>
#include <cstring>

namespace libexe {
    // =============================================================================
    // ne_resource_directory Implementation
    // =============================================================================

    struct ne_resource_directory::impl {
        std::vector<uint8_t> rsrc_table_data;    // Resource table data
        std::vector<uint8_t> file_data;          // Full file data
        uint32_t ne_offset = 0;                  // NE header offset
        uint16_t alignment_shift = 0;            // Alignment shift for file offsets
        ne_target_os target_os = ne_target_os::WINDOWS;  // Target OS
        std::vector<ne_segment> segments;        // Segment table (for OS/2)
        resource_collection all_resources_;

        // Windows format constructor
        impl(std::span<const uint8_t> rsrc_data,
             std::span<const uint8_t> full_file_data,
             uint32_t ne_off)
            : rsrc_table_data(rsrc_data.begin(), rsrc_data.end()),
              file_data(full_file_data.begin(), full_file_data.end()),
              ne_offset(ne_off),
              target_os(ne_target_os::WINDOWS) {
            parse_windows_resource_table();
        }

        // OS/2 format constructor
        impl(std::span<const uint8_t> rsrc_data,
             std::span<const uint8_t> full_file_data,
             uint32_t ne_off,
             ne_target_os os,
             const std::vector<ne_segment>& segs)
            : rsrc_table_data(rsrc_data.begin(), rsrc_data.end()),
              file_data(full_file_data.begin(), full_file_data.end()),
              ne_offset(ne_off),
              target_os(os),
              segments(segs) {
            if (target_os == ne_target_os::OS2) {
                parse_os2_resource_table();
            } else {
                parse_windows_resource_table();
            }
        }

        void parse_windows_resource_table();
        void parse_os2_resource_table();
        [[nodiscard]] std::string read_string(size_t offset) const;
        [[nodiscard]] std::span<const uint8_t> get_resource_data(uint16_t offset, uint16_t length) const;
        [[nodiscard]] std::span<const uint8_t> get_segment_data(size_t segment_index) const;
    };

    ne_resource_directory::ne_resource_directory(
        std::span<const uint8_t> rsrc_table_data,
        std::span<const uint8_t> file_data,
        uint32_t ne_offset
    )
        : impl_(std::make_unique<impl>(rsrc_table_data, file_data, ne_offset)) {
    }

    ne_resource_directory::ne_resource_directory(
        std::span<const uint8_t> rsrc_table_data,
        std::span<const uint8_t> file_data,
        uint32_t ne_offset,
        ne_target_os target_os,
        const std::vector<ne_segment>& segments
    )
        : impl_(std::make_unique<impl>(rsrc_table_data, file_data, ne_offset, target_os, segments)) {
    }

    // Destructor must be defined in .cpp file for pimpl idiom to work
    ne_resource_directory::~ne_resource_directory() = default;

    // =============================================================================
    // Resource Table Parsing - Windows Format
    // =============================================================================

    void ne_resource_directory::impl::parse_windows_resource_table() {
        if (rsrc_table_data.size() < 2) {
            return; // Empty or invalid resource table
        }

        const uint8_t* ptr = rsrc_table_data.data();
        const uint8_t* end = rsrc_table_data.data() + rsrc_table_data.size();

        try {
            // Read alignment shift count (first word in resource table)
            alignment_shift = static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8);
            ptr += 2;

            // Parse resource type information blocks
            while (ptr + 8 <= end) {
                // Need at least 8 bytes for NeResourceTypeInfo
                // Read type info
                auto type_info = formats::ne::ne_header::ne_resource_type_info::read(ptr, end);

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
                    auto name_info = formats::ne::ne_header::ne_resource_name_info::read(ptr, end);

                    // Determine if resource name is integer ID or string offset
                    bool is_integer_id = (name_info.id & 0x8000) != 0;
                    std::optional<uint16_t> resource_id;
                    std::optional<std::string> resource_name;

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
                    // NOTE: For OS/2 NE files, the convenience parsing methods (as_dialog, etc.)
                    // won't work correctly - use the OS/2 parsers directly instead.
                    auto resource = resource_entry::create(
                        type_id,
                        resource_id,
                        resource_name,
                        0, // language = 0 (neutral)
                        0, // codepage = 0 (not specified)
                        data,
                        windows_resource_format::NE
                    );

                    all_resources_.entries_.push_back(std::move(resource));
                }
            }
        } catch (const std::exception& e) {
            // Resource parsing errors are non-fatal - just means no resources available
            // Could log error here if logging system available
        }
    }

    // =============================================================================
    // Resource Table Parsing - OS/2 Compact Format
    // =============================================================================

    void ne_resource_directory::impl::parse_os2_resource_table() {
        // OS/2 NE resource table format:
        // WORD alignment_shift
        // (WORD resource_id, WORD type_id)[] - pairs until end of table
        //
        // Resource data is stored in segments, mapped by order:
        // First resource -> first DATA segment, etc.

        if (rsrc_table_data.size() < 2) {
            return; // Empty or invalid resource table
        }

        const uint8_t* ptr = rsrc_table_data.data();
        const uint8_t* end = rsrc_table_data.data() + rsrc_table_data.size();

        // Read alignment shift count (first word)
        alignment_shift = static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8);
        ptr += 2;

        // Collect data segments for resource data mapping
        std::vector<size_t> data_segment_indices;
        for (size_t i = 0; i < segments.size(); ++i) {
            if (segments[i].is_data()) {
                data_segment_indices.push_back(i);
            }
        }

        // Parse (resource_id, type_id) pairs
        size_t resource_index = 0;
        while (ptr + 4 <= end) {
            uint16_t resource_id = static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8);
            uint16_t type_id = static_cast<uint16_t>(ptr[2]) | (static_cast<uint16_t>(ptr[3]) << 8);
            ptr += 4;

            // Get resource data from corresponding segment
            std::span<const uint8_t> data;
            if (resource_index < data_segment_indices.size()) {
                size_t seg_idx = data_segment_indices[resource_index];
                data = get_segment_data(seg_idx);
            }

            // Create resource entry
            // NOTE: For OS/2 resources, the convenience parsing methods (as_dialog, etc.)
            // won't work correctly - use the OS/2 parsers directly from os2_resource_parser.hpp
            auto resource = resource_entry::create(
                type_id,
                resource_id,  // Always integer ID in OS/2 format
                std::nullopt, // No string names in compact format
                0,            // language = 0 (neutral)
                0,            // codepage = 0 (not specified)
                data,
                windows_resource_format::NE  // Stored as NE, but use OS/2 parsers for parsing
            );

            all_resources_.entries_.push_back(std::move(resource));
            ++resource_index;
        }
    }

    // =============================================================================
    // Helper: Get segment data for OS/2 resource lookup
    // =============================================================================

    std::span<const uint8_t> ne_resource_directory::impl::get_segment_data(size_t segment_index) const {
        if (segment_index >= segments.size()) {
            return {};
        }

        const auto& seg = segments[segment_index];

        // Use the segment's data span if available
        if (!seg.data.empty()) {
            return seg.data;
        }

        // Otherwise calculate from file offset
        if (seg.file_offset + seg.file_size > file_data.size()) {
            return {};
        }

        return std::span<const uint8_t>(
            file_data.data() + seg.file_offset,
            seg.file_size
        );
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

    windows_resource_format ne_resource_directory::format() const {
        // This interface is for Windows resources only.
        // OS/2 NE files should use the OS/2 parsers directly from os2_resource_parser.hpp
        // instead of using the convenience methods on resource_entry.
        return windows_resource_format::NE;
    }

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
