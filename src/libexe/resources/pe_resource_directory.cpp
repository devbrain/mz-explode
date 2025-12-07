// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/resources/pe_resource_directory.hpp>
#include "exe_format.hh"  // Generated DataScript parser
#include <algorithm>
#include <stdexcept>
#include <cstring>

namespace libexe {
    // =============================================================================
    // pe_resource_directory Implementation
    // =============================================================================

    struct pe_resource_directory::impl {
        std::vector <uint8_t> rsrc_data; // Complete .rsrc section
        uint32_t rsrc_rva = 0; // RVA of .rsrc section
        uint32_t timestamp_ = 0;
        resource_collection all_resources_;

        impl(std::span <const uint8_t> data, uint32_t rva)
            : rsrc_data(data.begin(), data.end()), rsrc_rva(rva) {
            parse_resource_tree();
        }

        void parse_resource_tree();

        void parse_directory_level(
            size_t dir_offset,
            int level,
            uint16_t type_id,
            std::optional <uint16_t> name_id,
            std::optional <std::string> name_str
        );

        [[nodiscard]] std::string read_unicode_string(size_t offset) const;
        [[nodiscard]] std::span <const uint8_t> get_resource_data(size_t data_entry_offset) const;
    };

    pe_resource_directory::pe_resource_directory(std::span <const uint8_t> rsrc_data, uint32_t rsrc_rva)
        : impl_(std::make_unique <impl>(rsrc_data, rsrc_rva)) {
    }

    // Destructor must be defined in .cpp file for pimpl idiom to work
    pe_resource_directory::~pe_resource_directory() = default;

    // =============================================================================
    // Resource Tree Parsing
    // =============================================================================

    void pe_resource_directory::impl::parse_resource_tree() {
        if (rsrc_data.empty()) {
            return;
        }

        try {
            // Start parsing at root directory (offset 0)
            parse_directory_level(0, 1, 0, std::nullopt, std::nullopt);
        } catch (const std::exception& e) {
            // Resource parsing errors are non-fatal - just means no resources available
            // Could log error here if logging system available
        }
    }

    void pe_resource_directory::impl::parse_directory_level(
        size_t dir_offset,
        int level,
        uint16_t type_id,
        std::optional <uint16_t> name_id,
        std::optional <std::string> name_str
    ) {
        if (dir_offset + 16 > rsrc_data.size()) {
            return; // Not enough data for directory header
        }

        const uint8_t* ptr = rsrc_data.data() + dir_offset;
        const uint8_t* end = rsrc_data.data() + rsrc_data.size();

        // Parse directory header using DataScript
        auto dir = libexe::format::ImageResourceDirectory::read(ptr, end);

        // Save timestamp from root directory
        if (level == 1) {
            timestamp_ = dir.TimeDateStamp;
        }

        // Calculate total entries
        uint16_t total_entries = dir.NumberOfNamedEntries + dir.NumberOfIdEntries;

        // Entries immediately follow the directory header
        size_t entry_offset = dir_offset + 16;

        for (uint16_t i = 0; i < total_entries; ++i) {
            if (entry_offset + 8 > rsrc_data.size()) {
                break; // Not enough data for entry
            }

            const uint8_t* entry_ptr = rsrc_data.data() + entry_offset;

            // Parse directory entry using DataScript
            auto entry = libexe::format::ImageResourceDirectoryEntry::read(entry_ptr, end);

            // Extract name/ID from Name field
            bool is_named = (entry.Name & 0x80000000) != 0;
            uint32_t name_offset = entry.Name & 0x7FFFFFFF;
            uint16_t entry_id = static_cast <uint16_t>(entry.Name & 0xFFFF);

            // Extract offset and check if it points to subdirectory or data
            bool is_subdirectory = (entry.Offset & 0x80000000) != 0;
            uint32_t offset = entry.Offset & 0x7FFFFFFF;

            // Determine values for next level
            uint16_t next_type_id = type_id;
            std::optional <uint16_t> next_name_id = name_id;
            std::optional <std::string> next_name_str = name_str;

            if (level == 1) {
                // Type level - store type ID
                next_type_id = entry_id;
            } else if (level == 2) {
                // Name level - store name or ID
                if (is_named) {
                    next_name_str = read_unicode_string(name_offset);
                } else {
                    next_name_id = entry_id;
                }
            }

            if (is_subdirectory) {
                // Recursively parse subdirectory
                if (level < 3) {
                    // Don't go deeper than language level
                    parse_directory_level(offset, level + 1, next_type_id, next_name_id, next_name_str);
                }
            } else if (level == 3) {
                // Language level - this is a data entry
                uint16_t language = entry_id;

                auto data = get_resource_data(offset);
                if (!data.empty()) {
                    // Get codepage from data entry
                    if (offset + 16 <= rsrc_data.size()) {
                        const uint8_t* data_entry_ptr = rsrc_data.data() + offset;
                        auto data_entry = libexe::format::ImageResourceDataEntry::read(data_entry_ptr, end);

                        // Build resource entry
                        auto resource = resource_entry::create(
                            next_type_id,
                            next_name_id,
                            next_name_str,
                            language,
                            data_entry.CodePage,
                            data
                        );

                        all_resources_.entries_.push_back(std::move(resource));
                    }
                }
            }

            entry_offset += 8; // Move to next entry
        }
    }

    std::string pe_resource_directory::impl::read_unicode_string(size_t offset) const {
        if (offset + 2 > rsrc_data.size()) {
            return "";
        }

        const uint8_t* ptr = rsrc_data.data() + offset;
        const uint8_t* end = rsrc_data.data() + rsrc_data.size();

        try {
            auto str = libexe::format::ImageResourceDirStringU::read(ptr, end);

            // Convert Unicode (UTF-16LE) to UTF-8 (simplified - just take low byte)
            std::string result;
            result.reserve(str.Length);

            for (uint16_t i = 0; i < str.Length && i < str.NameString.size(); ++i) {
                uint16_t wchar = str.NameString[i];
                if (wchar < 128) {
                    result.push_back(static_cast <char>(wchar));
                } else {
                    // For non-ASCII, use '?' (full Unicode conversion would require more work)
                    result.push_back('?');
                }
            }

            return result;
        } catch (...) {
            return "";
        }
    }

    std::span <const uint8_t> pe_resource_directory::impl::get_resource_data(size_t data_entry_offset) const {
        if (data_entry_offset + 16 > rsrc_data.size()) {
            return {};
        }

        const uint8_t* ptr = rsrc_data.data() + data_entry_offset;
        const uint8_t* end = rsrc_data.data() + rsrc_data.size();

        try {
            auto data_entry = libexe::format::ImageResourceDataEntry::read(ptr, end);

            // Convert RVA to offset within .rsrc section
            if (data_entry.OffsetToData < rsrc_rva) {
                return {}; // Invalid RVA
            }

            size_t offset = data_entry.OffsetToData - rsrc_rva;

            if (offset + data_entry.Size > rsrc_data.size()) {
                return {}; // Data extends beyond section
            }

            return std::span <const uint8_t>(
                rsrc_data.data() + offset,
                data_entry.Size
            );
        } catch (...) {
            return {};
        }
    }

    // =============================================================================
    // Metadata
    // =============================================================================

    uint32_t pe_resource_directory::timestamp() const {
        return impl_->timestamp_;
    }

    size_t pe_resource_directory::resource_count() const {
        return impl_->all_resources_.size();
    }

    // =============================================================================
    // High-Level Enumeration
    // =============================================================================

    resource_collection pe_resource_directory::all_resources() const {
        return impl_->all_resources_;
    }

    resource_collection pe_resource_directory::resources_by_type(resource_type type) const {
        return impl_->all_resources_.filter_by_type(type);
    }

    resource_collection pe_resource_directory::resources_by_type_id(uint16_t type_id) const {
        return impl_->all_resources_.filter_by_type_id(type_id);
    }

    // =============================================================================
    // Resource Lookup
    // =============================================================================

    std::optional <resource_entry> pe_resource_directory::find_resource(
        resource_type type,
        uint16_t id
    ) const {
        return impl_->all_resources_
                    .filter_by_type(type)
                    .filter_by_id(id)
                    .first();
    }

    std::optional <resource_entry> pe_resource_directory::find_resource(
        resource_type type,
        uint16_t id,
        uint16_t language
    ) const {
        auto filtered = impl_->all_resources_
                             .filter_by_type(type)
                             .filter_by_id(id);

        if (language == 0) {
            return filtered.first();
        }

        return filtered.filter_by_language(language).first();
    }

    std::optional <resource_entry> pe_resource_directory::find_resource(
        resource_type type,
        const std::string& name
    ) const {
        return impl_->all_resources_
                    .filter_by_type(type)
                    .filter_by_name(name)
                    .first();
    }

    std::optional <resource_entry> pe_resource_directory::find_resource(
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

    std::optional <resource_entry> pe_resource_directory::find_resource_by_type_id(
        uint16_t type_id,
        uint16_t id
    ) const {
        return impl_->all_resources_
                    .filter_by_type_id(type_id)
                    .filter_by_id(id)
                    .first();
    }

    std::optional <resource_entry> pe_resource_directory::find_resource_by_type_id(
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

    resource_collection pe_resource_directory::find_all_languages(
        resource_type type,
        uint16_t id
    ) const {
        return impl_->all_resources_
                    .filter_by_type(type)
                    .filter_by_id(id);
    }

    resource_collection pe_resource_directory::find_all_languages(
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

    std::vector <uint16_t> pe_resource_directory::types() const {
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

    std::vector <uint16_t> pe_resource_directory::ids_for_type(uint16_t type_id) const {
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

    std::vector <std::string> pe_resource_directory::names_for_type(uint16_t type_id) const {
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

    std::vector <uint16_t> pe_resource_directory::languages_for_id(
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

    std::vector <uint16_t> pe_resource_directory::languages_for_name(
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

    std::vector <uint16_t> pe_resource_directory::languages() const {
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

    std::vector <uint16_t> pe_resource_directory::languages_for_type(uint16_t type_id) const {
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
