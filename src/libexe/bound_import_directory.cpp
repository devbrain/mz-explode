// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/pe/directories/bound_import.hpp>
#include <algorithm>
#include <cctype>

namespace libexe {

// Helper function for case-insensitive string comparison
static bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) {
        return false;
    }
    return std::equal(a.begin(), a.end(), b.begin(),
                     [](char ca, char cb) {
                         return std::tolower(static_cast<unsigned char>(ca)) ==
                                std::tolower(static_cast<unsigned char>(cb));
                     });
}

const bound_import_descriptor* bound_import_directory::find_dll(const std::string& dll_name) const {
    for (const auto& desc : descriptors) {
        if (iequals(desc.module_name, dll_name)) {
            return &desc;
        }
    }
    return nullptr;
}

std::vector<std::string> bound_import_directory::dll_names() const {
    std::vector<std::string> names;
    names.reserve(descriptors.size());
    for (const auto& desc : descriptors) {
        names.push_back(desc.module_name);
    }
    return names;
}

bool bound_import_directory::has_forwarders() const {
    return std::any_of(descriptors.begin(), descriptors.end(),
                      [](const bound_import_descriptor& desc) {
                          return desc.has_forwarders();
                      });
}

size_t bound_import_directory::total_forwarder_count() const {
    size_t total = 0;
    for (const auto& desc : descriptors) {
        total += desc.forwarder_count();
    }
    return total;
}

} // namespace libexe
