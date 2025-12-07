// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_NE_RESOURCE_DIRECTORY_HPP
#define LIBEXE_NE_RESOURCE_DIRECTORY_HPP

#include <libexe/export.hpp>
#include <libexe/resources/resource.hpp>
#include <span>
#include <memory>

namespace libexe {

/**
 * NE (New Executable) Resource Directory Implementation
 *
 * Parses the NE resource table format used in Windows 3.x executables.
 *
 * NE Resource Table Structure (per docs/ne.fmt lines 308-370):
 * - Alignment shift count (2 bytes)
 * - Resource type information blocks (variable):
 *   - Type ID (2 bytes) - 0x8000+ = integer, else string offset, 0 = end
 *   - Resource count (2 bytes)
 *   - Reserved (4 bytes)
 *   - Resource entries (8 bytes each):
 *     - Offset (2 bytes) in alignment shift units
 *     - Length (2 bytes) in bytes
 *     - Flags (2 bytes) - MOVEABLE, PURE, PRELOAD
 *     - ID (2 bytes) - 0x8000+ = integer, else string offset
 *     - Reserved (4 bytes)
 * - Type and name strings (length-prefixed, NOT null-terminated)
 */
class LIBEXE_EXPORT ne_resource_directory final : public resource_directory {
public:
    /**
     * Construct NE resource directory from resource table data
     *
     * @param rsrc_table_data Resource table data (starting at alignment shift count)
     * @param file_data Full file data (for reading resource data at calculated offsets)
     * @param ne_offset Offset to NE header in file (for calculating absolute offsets)
     */
    ne_resource_directory(
        std::span<const uint8_t> rsrc_table_data,
        std::span<const uint8_t> file_data,
        uint32_t ne_offset
    );

    ~ne_resource_directory() override;

    // Delete copy/move to avoid issues with pimpl
    ne_resource_directory(const ne_resource_directory&) = delete;
    ne_resource_directory& operator=(const ne_resource_directory&) = delete;

    // =========================================================================
    // Metadata
    // =========================================================================

    [[nodiscard]] uint32_t timestamp() const override;
    [[nodiscard]] size_t resource_count() const override;

    // =========================================================================
    // High-Level Enumeration
    // =========================================================================

    [[nodiscard]] resource_collection all_resources() const override;
    [[nodiscard]] resource_collection resources_by_type(resource_type type) const override;
    [[nodiscard]] resource_collection resources_by_type_id(uint16_t type_id) const override;

    // =========================================================================
    // Resource Lookup
    // =========================================================================

    [[nodiscard]] std::optional<resource_entry> find_resource(
        resource_type type,
        uint16_t id
    ) const override;

    [[nodiscard]] std::optional<resource_entry> find_resource(
        resource_type type,
        uint16_t id,
        uint16_t language
    ) const override;

    [[nodiscard]] std::optional<resource_entry> find_resource(
        resource_type type,
        const std::string& name
    ) const override;

    [[nodiscard]] std::optional<resource_entry> find_resource(
        resource_type type,
        const std::string& name,
        uint16_t language
    ) const override;

    [[nodiscard]] std::optional<resource_entry> find_resource_by_type_id(
        uint16_t type_id,
        uint16_t id
    ) const override;

    [[nodiscard]] std::optional<resource_entry> find_resource_by_type_id(
        uint16_t type_id,
        uint16_t id,
        uint16_t language
    ) const override;

    // =========================================================================
    // Multi-Language Lookup
    // =========================================================================

    [[nodiscard]] resource_collection find_all_languages(
        resource_type type,
        uint16_t id
    ) const override;

    [[nodiscard]] resource_collection find_all_languages(
        resource_type type,
        const std::string& name
    ) const override;

    // =========================================================================
    // Low-Level Tree Navigation
    // =========================================================================

    [[nodiscard]] std::vector<uint16_t> types() const override;
    [[nodiscard]] std::vector<uint16_t> ids_for_type(uint16_t type_id) const override;
    [[nodiscard]] std::vector<std::string> names_for_type(uint16_t type_id) const override;

    [[nodiscard]] std::vector<uint16_t> languages_for_id(
        uint16_t type_id,
        uint16_t id
    ) const override;

    [[nodiscard]] std::vector<uint16_t> languages_for_name(
        uint16_t type_id,
        const std::string& name
    ) const override;

    [[nodiscard]] std::vector<uint16_t> languages() const override;
    [[nodiscard]] std::vector<uint16_t> languages_for_type(uint16_t type_id) const override;

private:
    struct impl;
    std::unique_ptr<impl> impl_;
};

} // namespace libexe

#endif // LIBEXE_NE_RESOURCE_DIRECTORY_HPP
