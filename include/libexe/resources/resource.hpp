// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_RESOURCE_HPP
#define LIBEXE_RESOURCE_HPP

#include <libexe/export.hpp>
#include <string>
#include <string_view>
#include <span>
#include <vector>
#include <optional>
#include <memory>

namespace libexe {
    // =============================================================================
    // Resource Type Enumeration (Standard Windows Resource Types)
    // =============================================================================

    /**
     * Standard resource types (RT_* constants from Windows SDK)
     *
     * Supports all 24 standard Windows resource types.
     * Custom/user-defined types use integer IDs > 256.
     */
    enum class resource_type : uint16_t {
        RT_CURSOR = 1, // Hardware-dependent cursor
        RT_BITMAP = 2, // Bitmap
        RT_ICON = 3, // Hardware-dependent icon
        RT_MENU = 4, // Menu
        RT_DIALOG = 5, // Dialog box
        RT_STRING = 6, // String table entry
        RT_FONTDIR = 7, // Font directory
        RT_FONT = 8, // Font
        RT_ACCELERATOR = 9, // Accelerator table
        RT_RCDATA = 10, // Application-defined resource (raw data)
        RT_MESSAGETABLE = 11, // Message table entry
        RT_GROUP_CURSOR = 12, // Hardware-independent cursor
        RT_GROUP_ICON = 14, // Hardware-independent icon (note: 13 is reserved)
        RT_VERSION = 16, // Version information
        RT_DLGINCLUDE = 17, // Dialog include file
        RT_PLUGPLAY = 19, // Plug and Play resource
        RT_VXD = 20, // VxD driver
        RT_ANICURSOR = 21, // Animated cursor
        RT_ANIICON = 22, // Animated icon
        RT_HTML = 23, // HTML document
        RT_MANIFEST = 24, // Side-by-side assembly manifest
    };

    /**
     * Convert resource type to string name
     *
     * @param type Resource type enum value
     * @return String representation (e.g., "RT_ICON")
     */
    LIBEXE_EXPORT std::string_view resource_type_name(resource_type type);

    // =============================================================================
    // Resource Entry - Single Resource Instance
    // =============================================================================

    /**
     * Represents a single resource extracted from an executable.
     *
     * Resources are identified by a three-level hierarchy:
     * - Type: RT_ICON, RT_STRING, or custom integer type ID
     * - Name: Integer ID or string name
     * - Language: LCID (e.g., 0x0409 = en-US, 0 = language-neutral)
     *
     * Provides access to raw resource data. Parsing into structured formats
     * (e.g., version info, icons) is handled by separate parser functions.
     */
    class LIBEXE_EXPORT resource_entry {
        public:
            resource_entry() = default;

            // =========================================================================
            // Resource Type Accessors
            // =========================================================================

            /**
             * Check if this is a standard resource type (RT_* enum value)
             * @return true if type is RT_CURSOR through RT_MANIFEST
             */
            [[nodiscard]] bool is_standard_type() const;

            /**
             * Get standard resource type (RT_ICON, RT_STRING, etc.)
             * @return resource_type enum if is_standard_type(), otherwise std::nullopt
             */
            [[nodiscard]] std::optional <resource_type> standard_type() const;

            /**
             * Get raw type ID (works for both standard and custom types)
             * @return Type ID as uint16_t
             */
            [[nodiscard]] uint16_t type_id() const;

            /**
             * Get human-readable type name
             * @return "RT_ICON" for standard types, "Type 256" for custom types
             */
            [[nodiscard]] std::string type_name() const;

            // =========================================================================
            // Resource Name/ID Accessors
            // =========================================================================

            /**
             * Check if resource is identified by string name (vs integer ID)
             * @return true if named resource, false if ID-based
             */
            [[nodiscard]] bool is_named() const;

            /**
             * Get resource integer ID
             * @return ID if !is_named(), otherwise std::nullopt
             */
            [[nodiscard]] std::optional <uint16_t> id() const;

            /**
             * Get resource string name
             * @return Name if is_named(), otherwise std::nullopt
             */
            [[nodiscard]] std::optional <std::string> name() const;

            /**
             * Get name as string (works for both ID and named resources)
             * @return String name or "#123" for ID-based resources
             */
            [[nodiscard]] std::string name_string() const;

            // =========================================================================
            // Language Accessors
            // =========================================================================

            /**
             * Get resource language/locale ID
             * @return LCID (0x0409 = en-US, 0 = language-neutral)
             */
            [[nodiscard]] uint16_t language() const;

            /**
             * Check if resource is language-neutral
             * @return true if language() == 0
             */
            [[nodiscard]] bool is_language_neutral() const;

            // =========================================================================
            // Data Accessors
            // =========================================================================

            /**
             * Get raw resource data
             * @return Byte span of resource data
             */
            [[nodiscard]] std::span <const uint8_t> data() const;

            /**
             * Get resource data size
             * @return Size in bytes
             */
            [[nodiscard]] size_t size() const;

            /**
             * Get resource codepage (for string resources)
             * @return Codepage ID (e.g., 1252 = Windows Latin-1)
             */
            [[nodiscard]] uint32_t codepage() const;

            // =========================================================================
            // Implementation Details (for internal use)
            // =========================================================================

            struct impl;

            // Factory method for internal use by resource_directory implementations
            static resource_entry create(
                uint16_t type_id,
                std::optional <uint16_t> id,
                std::optional <std::string> name,
                uint16_t language,
                uint32_t codepage,
                std::span <const uint8_t> data
            );

        private:
            friend class resource_directory;
            friend class pe_resource_directory;
            friend class ne_resource_directory;

            std::shared_ptr <impl> impl_;
    };

    // =============================================================================
    // Resource Collection - Query Results
    // =============================================================================

    /**
     * Collection of resources (result of enumeration or filtering)
     *
     * Supports iteration, filtering, and indexed access.
     * Filtering operations are chainable.
     */
    class LIBEXE_EXPORT resource_collection {
        public:
            resource_collection() = default;

            // =========================================================================
            // Iteration
            // =========================================================================

            [[nodiscard]] auto begin() const { return entries_.begin(); }
            [[nodiscard]] auto end() const { return entries_.end(); }
            [[nodiscard]] size_t size() const { return entries_.size(); }
            [[nodiscard]] bool empty() const { return entries_.empty(); }

            // =========================================================================
            // Filtering (chainable queries)
            // =========================================================================

            /**
             * Filter by standard resource type
             * @param type Resource type (RT_ICON, RT_STRING, etc.)
             * @return New collection containing only matching resources
             */
            [[nodiscard]] resource_collection filter_by_type(resource_type type) const;

            /**
             * Filter by custom type ID
             * @param type_id Type ID (e.g., 256 for custom types)
             * @return New collection containing only matching resources
             */
            [[nodiscard]] resource_collection filter_by_type_id(uint16_t type_id) const;

            /**
             * Filter by integer ID
             * @param id Resource ID
             * @return New collection containing only matching resources
             */
            [[nodiscard]] resource_collection filter_by_id(uint16_t id) const;

            /**
             * Filter by string name
             * @param name Resource name
             * @return New collection containing only matching resources
             */
            [[nodiscard]] resource_collection filter_by_name(const std::string& name) const;

            /**
             * Filter by language
             * @param lang Language ID (LCID)
             * @return New collection containing only matching resources
             */
            [[nodiscard]] resource_collection filter_by_language(uint16_t lang) const;

            // =========================================================================
            // Access
            // =========================================================================

            /**
             * Get first resource in collection
             * @return First resource if exists, otherwise std::nullopt
             */
            [[nodiscard]] std::optional <resource_entry> first() const;

            /**
             * Get resource at index
             * @param index Zero-based index
             * @return Resource if index valid, otherwise std::nullopt
             */
            [[nodiscard]] std::optional <resource_entry> at(size_t index) const;

            /**
             * Get resource by array indexing
             * @param index Zero-based index
             * @return Resource reference (throws if out of bounds)
             */
            [[nodiscard]] const resource_entry& operator[](size_t index) const;

        private:
            friend class resource_directory;
            friend class pe_resource_directory;
            friend class ne_resource_directory;

            std::vector <resource_entry> entries_;
    };

    // =============================================================================
    // Resource Directory - Abstract Resource Tree Interface
    // =============================================================================

    /**
     * Abstract interface for resource directory (PE and NE agnostic)
     *
     * Provides unified access to resources regardless of underlying format.
     * Both pe_file and ne_file return implementations of this interface.
     *
     * Resource directory structure (3-level tree):
     * - Level 1: Type (RT_ICON, RT_STRING, custom types)
     * - Level 2: Name/ID (specific resource identifier)
     * - Level 3: Language (LCID for localization)
     */
    class LIBEXE_EXPORT resource_directory {
        public:
            virtual ~resource_directory() = default;

            // =========================================================================
            // Metadata
            // =========================================================================

            /**
             * Get resource directory timestamp
             * @return Unix timestamp (0 if not available)
             */
            [[nodiscard]] virtual uint32_t timestamp() const = 0;

            /**
             * Get total number of resources
             * @return Resource count
             */
            [[nodiscard]] virtual size_t resource_count() const = 0;

            // =========================================================================
            // High-Level Enumeration (Sugar API)
            // =========================================================================

            /**
             * Get all resources
             * @return Collection of all resources in directory
             */
            [[nodiscard]] virtual resource_collection all_resources() const = 0;

            /**
             * Get all resources of standard type
             * @param type Resource type (RT_ICON, RT_STRING, etc.)
             * @return Collection of matching resources
             */
            [[nodiscard]] virtual resource_collection resources_by_type(resource_type type) const = 0;

            /**
             * Get all resources of custom type
             * @param type_id Custom type ID
             * @return Collection of matching resources
             */
            [[nodiscard]] virtual resource_collection resources_by_type_id(uint16_t type_id) const = 0;

            // =========================================================================
            // Resource Lookup (Option A: Separate Type/Name/Language)
            // =========================================================================

            /**
             * Find resource by standard type and integer ID (any language)
             * @param type Resource type
             * @param id Resource ID
             * @return First matching resource, or std::nullopt
             */
            [[nodiscard]] virtual std::optional <resource_entry> find_resource(
                resource_type type,
                uint16_t id
            ) const = 0;

            /**
             * Find resource by standard type, integer ID, and language (Option A)
             * @param type Resource type
             * @param id Resource ID
             * @param language Language ID (0 = any language)
             * @return Matching resource, or std::nullopt
             */
            [[nodiscard]] virtual std::optional <resource_entry> find_resource(
                resource_type type,
                uint16_t id,
                uint16_t language
            ) const = 0;

            /**
             * Find resource by standard type and string name (any language)
             * @param type Resource type
             * @param name Resource name
             * @return First matching resource, or std::nullopt
             */
            [[nodiscard]] virtual std::optional <resource_entry> find_resource(
                resource_type type,
                const std::string& name
            ) const = 0;

            /**
             * Find resource by standard type, string name, and language (Option A)
             * @param type Resource type
             * @param name Resource name
             * @param language Language ID (0 = any language)
             * @return Matching resource, or std::nullopt
             */
            [[nodiscard]] virtual std::optional <resource_entry> find_resource(
                resource_type type,
                const std::string& name,
                uint16_t language
            ) const = 0;

            /**
             * Find resource by custom type ID and integer ID (any language)
             * @param type_id Custom type ID
             * @param id Resource ID
             * @return First matching resource, or std::nullopt
             */
            [[nodiscard]] virtual std::optional <resource_entry> find_resource_by_type_id(
                uint16_t type_id,
                uint16_t id
            ) const = 0;

            /**
             * Find resource by custom type ID, integer ID, and language (Option A)
             * @param type_id Custom type ID
             * @param id Resource ID
             * @param language Language ID (0 = any language)
             * @return Matching resource, or std::nullopt
             */
            [[nodiscard]] virtual std::optional <resource_entry> find_resource_by_type_id(
                uint16_t type_id,
                uint16_t id,
                uint16_t language
            ) const = 0;

            // =========================================================================
            // Multi-Language Lookup (Option C: Return all languages)
            // =========================================================================

            /**
             * Find all language variants of a resource (Option C)
             * @param type Resource type
             * @param id Resource ID
             * @return Collection of all language variants
             */
            [[nodiscard]] virtual resource_collection find_all_languages(
                resource_type type,
                uint16_t id
            ) const = 0;

            /**
             * Find all language variants of a named resource (Option C)
             * @param type Resource type
             * @param name Resource name
             * @return Collection of all language variants
             */
            [[nodiscard]] virtual resource_collection find_all_languages(
                resource_type type,
                const std::string& name
            ) const = 0;

            // =========================================================================
            // Low-Level Tree Navigation (Full-Fledged Tree API)
            // =========================================================================

            /**
             * Get all resource types present in directory
             * @return Vector of type IDs (both standard and custom)
             */
            [[nodiscard]] virtual std::vector <uint16_t> types() const = 0;

            /**
             * Get all integer IDs for a given type
             * @param type_id Type ID
             * @return Vector of resource IDs
             */
            [[nodiscard]] virtual std::vector <uint16_t> ids_for_type(uint16_t type_id) const = 0;

            /**
             * Get all string names for a given type
             * @param type_id Type ID
             * @return Vector of resource names
             */
            [[nodiscard]] virtual std::vector <std::string> names_for_type(uint16_t type_id) const = 0;

            /**
             * Get all languages for a specific type and ID
             * @param type_id Type ID
             * @param id Resource ID
             * @return Vector of language IDs
             */
            [[nodiscard]] virtual std::vector <uint16_t> languages_for_id(
                uint16_t type_id,
                uint16_t id
            ) const = 0;

            /**
             * Get all languages for a specific type and name
             * @param type_id Type ID
             * @param name Resource name
             * @return Vector of language IDs
             */
            [[nodiscard]] virtual std::vector <uint16_t> languages_for_name(
                uint16_t type_id,
                const std::string& name
            ) const = 0;

            /**
             * Get all languages present in the resource directory
             * @return Vector of all unique language IDs across all resources
             */
            [[nodiscard]] virtual std::vector <uint16_t> languages() const = 0;

            /**
             * Get all languages for a specific resource type
             * @param type_id Type ID
             * @return Vector of all unique language IDs for this type
             */
            [[nodiscard]] virtual std::vector <uint16_t> languages_for_type(uint16_t type_id) const = 0;
    };
} // namespace libexe

#endif // LIBEXE_RESOURCE_HPP
