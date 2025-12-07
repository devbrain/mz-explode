// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_PE_RESOURCE_DIRECTORY_HPP
#define LIBEXE_PE_RESOURCE_DIRECTORY_HPP

#include <libexe/export.hpp>
#include <libexe/resources/resource.hpp>
#include <span>
#include <vector>
#include <cstdint>

namespace libexe {

/**
 * PE resource directory implementation
 *
 * Parses PE resource directory tree (3-level hierarchy):
 * - Level 1: Type (RT_ICON, RT_STRING, etc.)
 * - Level 2: Name/ID (resource identifier)
 * - Level 3: Language (LCID)
 *
 * Uses DataScript-generated ImageResourceDirectory structures.
 */
class LIBEXE_EXPORT pe_resource_directory final : public resource_directory {
public:
    /**
     * Create PE resource directory from .rsrc section data
     *
     * @param rsrc_data Complete .rsrc section data
     * @param rsrc_rva RVA of .rsrc section (for offset calculations)
     */
    pe_resource_directory(std::span<const uint8_t> rsrc_data, uint32_t rsrc_rva);

    ~pe_resource_directory() override;

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

#endif // LIBEXE_PE_RESOURCE_DIRECTORY_HPP
