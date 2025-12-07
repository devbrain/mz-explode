#ifndef LIBEXE_VERSION_INFO_PARSER_HPP
#define LIBEXE_VERSION_INFO_PARSER_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <span>
#include <map>
#include <string>
#include <optional>

namespace libexe {

/**
 * Fixed file information from version resource.
 *
 * Contains version numbers, file flags, OS type, and file type.
 * This is the VS_FIXEDFILEINFO structure.
 */
struct LIBEXE_EXPORT fixed_file_info {
    uint32_t signature;          // 0xFEEF04BD
    uint32_t struct_version;     // Structure version

    // File version (e.g., 1.2.3.4)
    uint16_t file_version_major;
    uint16_t file_version_minor;
    uint16_t file_version_patch;
    uint16_t file_version_build;

    // Product version (e.g., 2.0.0.0)
    uint16_t product_version_major;
    uint16_t product_version_minor;
    uint16_t product_version_patch;
    uint16_t product_version_build;

    uint32_t file_flags_mask;    // Valid bits in file_flags
    uint32_t file_flags;         // File flags (debug, prerelease, etc.)
    uint32_t file_os;            // Target OS
    uint32_t file_type;          // File type (app, DLL, driver, etc.)
    uint32_t file_subtype;       // File subtype (driver/font type)
    uint64_t file_date;          // File creation date (rarely used)

    /**
     * Get file version as string (e.g., "1.2.3.4").
     */
    [[nodiscard]] std::string file_version_string() const;

    /**
     * Get product version as string (e.g., "2.0.0.0").
     */
    [[nodiscard]] std::string product_version_string() const;

    /**
     * Check if file is a debug build.
     */
    [[nodiscard]] bool is_debug() const {
        return (file_flags & 0x00000001) != 0;  // VS_FF_DEBUG
    }

    /**
     * Check if file is prerelease.
     */
    [[nodiscard]] bool is_prerelease() const {
        return (file_flags & 0x00000002) != 0;  // VS_FF_PRERELEASE
    }

    /**
     * Check if file has been patched.
     */
    [[nodiscard]] bool is_patched() const {
        return (file_flags & 0x00000004) != 0;  // VS_FF_PATCHED
    }

    /**
     * Check if file is a private build.
     */
    [[nodiscard]] bool is_private_build() const {
        return (file_flags & 0x00000008) != 0;  // VS_FF_PRIVATEBUILD
    }

    /**
     * Check if file is a special build.
     */
    [[nodiscard]] bool is_special_build() const {
        return (file_flags & 0x00000010) != 0;  // VS_FF_SPECIALBUILD
    }
};

/**
 * Version information resource (RT_VERSION).
 *
 * Contains file and product version numbers, plus string metadata
 * like company name, file description, copyright, etc.
 *
 * The version resource has a complex structure:
 * - Fixed file info (VS_FIXEDFILEINFO)
 * - String file info (language-specific strings)
 * - Var file info (language/codepage pairs)
 *
 * This parser extracts the fixed info and string tables.
 */
struct LIBEXE_EXPORT version_info {
    fixed_file_info fixed_info;

    // String table (key-value pairs)
    // Common keys: CompanyName, FileDescription, FileVersion,
    //              InternalName, LegalCopyright, OriginalFilename,
    //              ProductName, ProductVersion
    std::map<std::string, std::string> strings;

    /**
     * Get string value by key.
     *
     * @param key String key (e.g., "CompanyName")
     * @return String value if exists, empty string otherwise
     */
    [[nodiscard]] std::string get_string(const std::string& key) const {
        auto it = strings.find(key);
        return it != strings.end() ? it->second : "";
    }

    /**
     * Get company name.
     */
    [[nodiscard]] std::string company_name() const {
        return get_string("CompanyName");
    }

    /**
     * Get file description.
     */
    [[nodiscard]] std::string file_description() const {
        return get_string("FileDescription");
    }

    /**
     * Get file version string from StringFileInfo.
     */
    [[nodiscard]] std::string file_version() const {
        return get_string("FileVersion");
    }

    /**
     * Get internal name.
     */
    [[nodiscard]] std::string internal_name() const {
        return get_string("InternalName");
    }

    /**
     * Get legal copyright.
     */
    [[nodiscard]] std::string legal_copyright() const {
        return get_string("LegalCopyright");
    }

    /**
     * Get original filename.
     */
    [[nodiscard]] std::string original_filename() const {
        return get_string("OriginalFilename");
    }

    /**
     * Get product name.
     */
    [[nodiscard]] std::string product_name() const {
        return get_string("ProductName");
    }

    /**
     * Get product version string from StringFileInfo.
     */
    [[nodiscard]] std::string product_version() const {
        return get_string("ProductVersion");
    }
};

/**
 * Parser for RT_VERSION resources.
 *
 * Parses version information from Windows executables.
 * Extracts both fixed version info and string metadata.
 *
 * Example:
 * @code
 * auto version_entry = resources->find_resource(resource_type::RT_VERSION, 1);
 * if (version_entry.has_value()) {
 *     auto version = version_info_parser::parse(version_entry->data());
 *     if (version.has_value()) {
 *         std::cout << "Product: " << version->product_name() << "\n";
 *         std::cout << "Version: " << version->fixed_info.file_version_string() << "\n";
 *         std::cout << "Company: " << version->company_name() << "\n";
 *         std::cout << "Copyright: " << version->legal_copyright() << "\n";
 *
 *         if (version->fixed_info.is_debug()) {
 *             std::cout << "Debug build\n";
 *         }
 *     }
 * }
 * @endcode
 */
class LIBEXE_EXPORT version_info_parser {
public:
    /**
     * Parse a version information resource.
     *
     * @param data Raw resource data from RT_VERSION resource
     * @return Parsed version info on success, std::nullopt on parse error
     */
    static std::optional<version_info> parse(std::span<const uint8_t> data);
};

} // namespace libexe

#endif // LIBEXE_VERSION_INFO_PARSER_HPP
