// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_NE_RESOURCE_DIRECTORY_HPP
#define LIBEXE_NE_RESOURCE_DIRECTORY_HPP

#include <libexe/export.hpp>
#include <libexe/resources/resource.hpp>
#include <libexe/ne/types.hpp>
#include <libexe/pe/section.hpp>  // For ne_segment
#include <span>
#include <memory>
#include <vector>

// Disable MSVC warning C4251: 'member': class 'std::...' needs to have dll-interface
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

namespace libexe {

/**
 * NE (New Executable) Resource Directory Implementation
 *
 * Parses NE resource table format for both Windows and OS/2 executables.
 *
 * Windows NE Resource Table Structure (per docs/ne.fmt lines 308-370):
 * - Alignment shift count (2 bytes)
 * - Resource type information blocks (variable):
 *   - Type ID (2 bytes) - 0x8000+ = integer, else string offset, 0 = end
 *   - Resource count (2 bytes)
 *   - Reserved (4 bytes)
 *   - Resource entries (12 bytes each):
 *     - Offset (2 bytes) in alignment shift units
 *     - Length (2 bytes) in alignment shift units
 *     - Flags (2 bytes) - MOVEABLE, PURE, PRELOAD
 *     - ID (2 bytes) - 0x8000+ = integer, else string offset
 *     - Handle (2 bytes) - reserved
 *     - Usage (2 bytes) - reserved
 * - Type and name strings (length-prefixed, NOT null-terminated)
 *
 * OS/2 NE Resource Table Structure (compact format):
 * - Alignment shift count (2 bytes)
 * - (Resource ID, Type ID) pairs (4 bytes each) until end of table
 * - Resource data is stored in segments, not embedded in resource area
 */
class LIBEXE_EXPORT ne_resource_directory final : public resource_directory {
public:
    /**
     * Construct NE resource directory from resource table data (Windows format)
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

    /**
     * Construct NE resource directory with target OS and segment info (OS/2 support)
     *
     * @param rsrc_table_data Resource table data (starting at alignment shift count)
     * @param file_data Full file data
     * @param ne_offset Offset to NE header in file
     * @param target_os Target operating system (OS2, WINDOWS, etc.)
     * @param segments Segment table (for OS/2 resource data lookup)
     */
    ne_resource_directory(
        std::span<const uint8_t> rsrc_table_data,
        std::span<const uint8_t> file_data,
        uint32_t ne_offset,
        ne_target_os target_os,
        const std::vector<ne_segment>& segments
    );

    ~ne_resource_directory() override;

    // Delete copy/move to avoid issues with pimpl
    ne_resource_directory(const ne_resource_directory&) = delete;
    ne_resource_directory& operator=(const ne_resource_directory&) = delete;

    // =========================================================================
    // Metadata
    // =========================================================================

    [[nodiscard]] windows_resource_format format() const override;
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

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // LIBEXE_NE_RESOURCE_DIRECTORY_HPP
