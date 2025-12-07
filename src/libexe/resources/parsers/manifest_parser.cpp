#include <libexe/resources/parsers/manifest_parser.hpp>
#include <algorithm>

namespace libexe {

std::optional<manifest_data> manifest_parser::parse(std::span<const uint8_t> data) {
    if (data.empty()) {
        return std::nullopt;
    }

    try {
        manifest_data result;

        // Manifest is stored as UTF-8 text
        // Convert byte span to string
        result.xml.assign(
            reinterpret_cast<const char*>(data.data()),
            data.size()
        );

        // Trim trailing null bytes (some manifests are null-padded)
        while (!result.xml.empty() && result.xml.back() == '\0') {
            result.xml.pop_back();
        }

        // Basic validation - check if it looks like XML
        if (result.xml.find('<') == std::string::npos) {
            return std::nullopt;  // Doesn't look like XML
        }

        return result;
    }
    catch (const std::exception&) {
        return std::nullopt;
    }
}

} // namespace libexe
