// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/resources/resource.hpp>
#include <libexe/resources/parsers/icon_group_parser.hpp>
#include <libexe/resources/parsers/icon_parser.hpp>
#include <libexe/resources/parsers/font_parser.hpp>
#include <libexe/resources/parsers/version_info_parser.hpp>
#include <libexe/resources/parsers/manifest_parser.hpp>
#include <libexe/resources/parsers/string_table_parser.hpp>
#include <libexe/resources/parsers/accelerator_parser.hpp>
#include <libexe/resources/parsers/dialog_parser.hpp>
#include <algorithm>
#include <sstream>

namespace libexe {

// =============================================================================
// Resource Type Name Conversion
// =============================================================================

std::string_view resource_type_name(resource_type type) {
    switch (type) {
        case resource_type::RT_CURSOR: return "RT_CURSOR";
        case resource_type::RT_BITMAP: return "RT_BITMAP";
        case resource_type::RT_ICON: return "RT_ICON";
        case resource_type::RT_MENU: return "RT_MENU";
        case resource_type::RT_DIALOG: return "RT_DIALOG";
        case resource_type::RT_STRING: return "RT_STRING";
        case resource_type::RT_FONTDIR: return "RT_FONTDIR";
        case resource_type::RT_FONT: return "RT_FONT";
        case resource_type::RT_ACCELERATOR: return "RT_ACCELERATOR";
        case resource_type::RT_RCDATA: return "RT_RCDATA";
        case resource_type::RT_MESSAGETABLE: return "RT_MESSAGETABLE";
        case resource_type::RT_GROUP_CURSOR: return "RT_GROUP_CURSOR";
        case resource_type::RT_GROUP_ICON: return "RT_GROUP_ICON";
        case resource_type::RT_VERSION: return "RT_VERSION";
        case resource_type::RT_DLGINCLUDE: return "RT_DLGINCLUDE";
        case resource_type::RT_PLUGPLAY: return "RT_PLUGPLAY";
        case resource_type::RT_VXD: return "RT_VXD";
        case resource_type::RT_ANICURSOR: return "RT_ANICURSOR";
        case resource_type::RT_ANIICON: return "RT_ANIICON";
        case resource_type::RT_HTML: return "RT_HTML";
        case resource_type::RT_MANIFEST: return "RT_MANIFEST";
        default: return "RT_UNKNOWN";
    }
}

// =============================================================================
// resource_entry Implementation
// =============================================================================

struct resource_entry::impl {
    uint16_t type_id = 0;
    std::optional<uint16_t> id;
    std::optional<std::string> name;
    uint16_t language = 0;
    uint32_t codepage = 0;
    windows_resource_format format = windows_resource_format::PE;  // Resource format for parsing
    std::vector<uint8_t> data_storage;  // Owns the data
    std::span<const uint8_t> data_view; // View into data_storage
};

bool resource_entry::is_standard_type() const {
    if (!impl_) return false;

    uint16_t tid = impl_->type_id;
    return (tid >= 1 && tid <= 24 && tid != 13);  // 13 is reserved
}

std::optional<resource_type> resource_entry::standard_type() const {
    if (!is_standard_type()) return std::nullopt;
    return static_cast<resource_type>(impl_->type_id);
}

uint16_t resource_entry::type_id() const {
    return impl_ ? impl_->type_id : 0;
}

std::string resource_entry::type_name() const {
    if (!impl_) return "UNKNOWN";

    if (is_standard_type()) {
        return std::string(resource_type_name(standard_type().value()));
    }

    return "Type " + std::to_string(impl_->type_id);
}

bool resource_entry::is_named() const {
    return impl_ && impl_->name.has_value();
}

std::optional<uint16_t> resource_entry::id() const {
    return impl_ ? impl_->id : std::nullopt;
}

std::optional<std::string> resource_entry::name() const {
    return impl_ ? impl_->name : std::nullopt;
}

std::string resource_entry::name_string() const {
    if (!impl_) return "";

    if (impl_->name) {
        return impl_->name.value();
    }

    if (impl_->id) {
        return "#" + std::to_string(impl_->id.value());
    }

    return "";
}

uint16_t resource_entry::language() const {
    return impl_ ? impl_->language : 0;
}

bool resource_entry::is_language_neutral() const {
    return language() == 0;
}

std::span<const uint8_t> resource_entry::data() const {
    return impl_ ? impl_->data_view : std::span<const uint8_t>();
}

size_t resource_entry::size() const {
    return impl_ ? impl_->data_view.size() : 0;
}

uint32_t resource_entry::codepage() const {
    return impl_ ? impl_->codepage : 0;
}

std::optional<icon_group> resource_entry::as_icon_group() const {
    return icon_group_parser::parse(data());
}

std::optional<icon_image> resource_entry::as_icon() const {
    return icon_parser::parse(data());
}

std::optional<font_data> resource_entry::as_font() const {
    return font_parser::parse(data());
}

std::optional<version_info> resource_entry::as_version_info() const {
    return version_info_parser::parse(data());
}

std::optional<manifest_data> resource_entry::as_manifest() const {
    return manifest_parser::parse(data());
}

std::optional<string_table> resource_entry::as_string_table() const {
    // String tables need the block ID to calculate string IDs
    // The resource ID IS the block ID
    auto res_id = id();
    if (!res_id || !impl_) return std::nullopt;
    return string_table_parser::parse(data(), res_id.value(), impl_->format);
}

std::optional<accelerator_table> resource_entry::as_accelerator_table() const {
    return accelerator_parser::parse(data());
}

std::optional<dialog_template> resource_entry::as_dialog() const {
    if (!impl_) return std::nullopt;
    return dialog_parser::parse(data(), impl_->format);
}

resource_entry resource_entry::create(
    uint16_t type_id,
    std::optional<uint16_t> id,
    std::optional<std::string> name,
    uint16_t language,
    uint32_t codepage,
    std::span<const uint8_t> data,
    windows_resource_format format
) {
    resource_entry entry;
    entry.impl_ = std::make_shared<impl>();

    entry.impl_->type_id = type_id;
    entry.impl_->id = id;
    entry.impl_->name = name;
    entry.impl_->language = language;
    entry.impl_->codepage = codepage;
    entry.impl_->format = format;

    // Copy data into storage
    entry.impl_->data_storage.assign(data.begin(), data.end());
    entry.impl_->data_view = entry.impl_->data_storage;

    return entry;
}

// =============================================================================
// resource_collection Implementation
// =============================================================================

resource_collection resource_collection::filter_by_type(resource_type type) const {
    return filter_by_type_id(static_cast<uint16_t>(type));
}

resource_collection resource_collection::filter_by_type_id(uint16_t type_id) const {
    resource_collection result;

    std::copy_if(entries_.begin(), entries_.end(),
                 std::back_inserter(result.entries_),
                 [type_id](const resource_entry& entry) {
                     return entry.type_id() == type_id;
                 });

    return result;
}

resource_collection resource_collection::filter_by_id(uint16_t id) const {
    resource_collection result;

    std::copy_if(entries_.begin(), entries_.end(),
                 std::back_inserter(result.entries_),
                 [id](const resource_entry& entry) {
                     auto entry_id = entry.id();
                     return entry_id && entry_id.value() == id;
                 });

    return result;
}

resource_collection resource_collection::filter_by_name(const std::string& name) const {
    resource_collection result;

    std::copy_if(entries_.begin(), entries_.end(),
                 std::back_inserter(result.entries_),
                 [&name](const resource_entry& entry) {
                     auto entry_name = entry.name();
                     return entry_name && entry_name.value() == name;
                 });

    return result;
}

resource_collection resource_collection::filter_by_language(uint16_t lang) const {
    resource_collection result;

    std::copy_if(entries_.begin(), entries_.end(),
                 std::back_inserter(result.entries_),
                 [lang](const resource_entry& entry) {
                     return entry.language() == lang;
                 });

    return result;
}

std::optional<resource_entry> resource_collection::first() const {
    if (entries_.empty()) return std::nullopt;
    return entries_.front();
}

std::optional<resource_entry> resource_collection::at(size_t index) const {
    if (index >= entries_.size()) return std::nullopt;
    return entries_[index];
}

const resource_entry& resource_collection::operator[](size_t index) const {
    return entries_.at(index);  // Throws if out of bounds
}

} // namespace libexe
