// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_PE_DIRECTORIES_LOAD_CONFIG_HPP
#define LIBEXE_PE_DIRECTORIES_LOAD_CONFIG_HPP

#include <libexe/export.hpp>
#include <libexe/pe/section.hpp>
#include <cstdint>
#include <string>
#include <span>
#include <vector>

namespace libexe {

/**
 * Load Configuration Directory
 *
 * Contains PE runtime configuration and security features.
 * The structure size varies by Windows version (XP, Vista, 8, 10, etc.).
 *
 * Important fields:
 * - Security cookie for stack buffer overrun detection
 * - SafeSEH handler table (32-bit only)
 * - Control Flow Guard (CFG) settings
 * - Code integrity settings
 * - Guard flags (CFG, XFG, etc.)
 *
 * Data directory index: 10 (IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
 */
struct LIBEXE_EXPORT load_config_directory {
    // Structure size (varies by Windows version)
    uint32_t size = 0;

    // Timestamp
    uint32_t time_date_stamp = 0;
    uint16_t major_version = 0;
    uint16_t minor_version = 0;

    // Global flags
    uint32_t global_flags_clear = 0;
    uint32_t global_flags_set = 0;
    uint32_t critical_section_default_timeout = 0;

    // Memory management
    uint64_t de_commit_free_block_threshold = 0;
    uint64_t de_commit_total_free_threshold = 0;
    uint64_t lock_prefix_table = 0;  // VA
    uint64_t maximum_allocation_size = 0;
    uint64_t virtual_memory_threshold = 0;
    uint64_t process_affinity_mask = 0;
    uint32_t process_heap_flags = 0;
    uint16_t csd_version = 0;
    uint16_t dependent_load_flags = 0;

    // Edit list (VA)
    uint64_t edit_list = 0;

    // Security cookie (VA) - for stack buffer overrun detection
    uint64_t security_cookie = 0;

    // SafeSEH (32-bit only)
    uint64_t se_handler_table = 0;  // VA to handler table
    uint64_t se_handler_count = 0;  // Number of handlers

    // Control Flow Guard (CFG)
    uint64_t guard_cf_check_function_pointer = 0;  // VA
    uint64_t guard_cf_dispatch_function_pointer = 0;  // VA
    uint64_t guard_cf_function_table = 0;  // VA to CFG function table
    uint64_t guard_cf_function_count = 0;  // Number of CFG functions
    uint32_t guard_flags = 0;  // CFG flags

    // Code integrity
    uint16_t code_integrity_flags = 0;
    uint16_t code_integrity_catalog = 0;
    uint32_t code_integrity_catalog_offset = 0;
    uint32_t code_integrity_reserved = 0;

    // Additional CFG fields (Windows 10+)
    uint64_t guard_address_taken_iat_entry_table = 0;  // VA
    uint64_t guard_address_taken_iat_entry_count = 0;
    uint64_t guard_long_jump_target_table = 0;  // VA
    uint64_t guard_long_jump_target_count = 0;

    // Dynamic value relocations (Windows 10 RS2+)
    uint64_t dynamic_value_reloc_table = 0;  // VA
    uint64_t chpe_metadata_pointer = 0;  // VA (ARM64X)

    // Additional guard fields (Windows 10 RS3+)
    uint64_t guard_rf_failure_routine = 0;  // VA
    uint64_t guard_rf_failure_routine_function_pointer = 0;  // VA
    uint32_t dynamic_value_reloc_table_offset = 0;
    uint16_t dynamic_value_reloc_table_section = 0;
    uint16_t reserved2 = 0;

    // More guard fields (Windows 10 RS4+)
    uint64_t guard_rf_verify_stack_pointer_function_pointer = 0;  // VA
    uint32_t hot_patch_table_offset = 0;
    uint32_t reserved3 = 0;

    // Enclave configuration (Windows 10 RS5+)
    uint64_t enclave_configuration_pointer = 0;  // VA

    // Volatile metadata (Windows 10 20H1+)
    uint64_t volatile_metadata_pointer = 0;  // VA

    // Guard EH continuation table (Windows 10 21H1+)
    uint64_t guard_eh_continuation_table = 0;  // VA
    uint64_t guard_eh_continuation_count = 0;

    // XFG fields (Windows 11+)
    uint64_t guard_xfg_check_function_pointer = 0;  // VA
    uint64_t guard_xfg_dispatch_function_pointer = 0;  // VA
    uint64_t guard_xfg_table_dispatch_function_pointer = 0;  // VA

    // Cast Guard (Windows 11 22H2+)
    uint64_t cast_guard_os_determined_failure_mode = 0;  // VA

    /**
     * Check if security cookie is present
     */
    [[nodiscard]] bool has_security_cookie() const {
        return security_cookie != 0;
    }

    /**
     * Check if SafeSEH is enabled (32-bit only)
     */
    [[nodiscard]] bool has_safe_seh() const {
        return se_handler_table != 0 && se_handler_count > 0;
    }

    /**
     * Check if Control Flow Guard (CFG) is enabled
     */
    [[nodiscard]] bool has_cfg() const {
        return (guard_flags & 0x00000100) != 0;  // IMAGE_GUARD_CF_INSTRUMENTED
    }

    /**
     * Check if CFG function table is present
     */
    [[nodiscard]] bool has_cfg_function_table() const {
        return guard_cf_function_table != 0 && guard_cf_function_count > 0;
    }

    /**
     * Check if CFG export suppression is enabled
     */
    [[nodiscard]] bool has_cfg_export_suppression() const {
        return (guard_flags & 0x00000800) != 0;
    }

    /**
     * Check if CFG longjmp is enabled
     */
    [[nodiscard]] bool has_cfg_longjmp() const {
        return (guard_flags & 0x00001000) != 0;
    }

    /**
     * Check if XFG (eXtended Flow Guard) is enabled
     */
    [[nodiscard]] bool has_xfg() const {
        return (guard_flags & 0x00800000) != 0;  // IMAGE_GUARD_XFG_ENABLED
    }

    /**
     * Check if Cast Guard is enabled
     */
    [[nodiscard]] bool has_cast_guard() const {
        return (guard_flags & 0x01000000) != 0;  // IMAGE_GUARD_CASTGUARD_PRESENT
    }

    /**
     * Get guard flags as string
     */
    [[nodiscard]] std::string guard_flags_string() const;

    /**
     * Check if this is an empty/default load config
     */
    [[nodiscard]] bool is_empty() const {
        return size == 0;
    }

    /**
     * Get minimum structure size for Windows version
     */
    [[nodiscard]] static uint32_t get_min_size_for_version(bool is_64bit, const char* version);
};

/**
 * Load Configuration Directory Parser
 *
 * Parses PE Load Configuration Directory (data directory index 10) to extract
 * runtime configuration and security features.
 *
 * The load config structure has evolved significantly across Windows versions.
 * The parser handles variable structure sizes by:
 * 1. Reading the Size field first
 * 2. Only reading fields that fit within the reported size
 * 3. Gracefully handling missing fields (leaving them as zero)
 *
 * Important security features:
 * - Security cookie (stack buffer overrun detection)
 * - SafeSEH (32-bit structured exception handling)
 * - Control Flow Guard (CFG)
 * - eXtended Flow Guard (XFG)
 * - Cast Guard
 */
class LIBEXE_EXPORT load_config_directory_parser {
public:
    /**
     * Parse load configuration directory from PE file
     *
     * Reads IMAGE_LOAD_CONFIG_DIRECTORY32/64 structure.
     * Handles variable structure sizes across Windows versions.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections (for RVA to offset conversion)
     * @param load_config_rva RVA to load config directory
     * @param load_config_size Size of load config directory
     * @param is_64bit true for PE32+ (64-bit), false for PE32 (32-bit)
     * @return Parsed load configuration directory
     * @throws std::runtime_error if load config directory is malformed
     */
    static load_config_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t load_config_rva,
        uint32_t load_config_size,
        bool is_64bit
    );

private:
    /**
     * Parse 32-bit load config directory
     *
     * Reads IMAGE_LOAD_CONFIG_DIRECTORY32 with variable size handling.
     *
     * @param ptr Pointer to load config data
     * @param end End of data
     * @param structure_size Size field from structure (indicates available fields)
     * @return Parsed load config directory
     */
    static load_config_directory parse_32bit(
        const uint8_t* ptr,
        const uint8_t* end,
        uint32_t structure_size
    );

    /**
     * Parse 64-bit load config directory
     *
     * Reads IMAGE_LOAD_CONFIG_DIRECTORY64 with variable size handling.
     *
     * @param ptr Pointer to load config data
     * @param end End of data
     * @param structure_size Size field from structure (indicates available fields)
     * @return Parsed load config directory
     */
    static load_config_directory parse_64bit(
        const uint8_t* ptr,
        const uint8_t* end,
        uint32_t structure_size
    );

    /**
     * Read uint32 at offset if available
     *
     * Helper to safely read fields based on structure size.
     *
     * @param ptr Base pointer
     * @param offset Offset from base
     * @param structure_size Total structure size
     * @return Value if available, 0 otherwise
     */
    static uint32_t read_uint32_if_available(
        const uint8_t* ptr,
        size_t offset,
        uint32_t structure_size
    );

    /**
     * Read uint64 at offset if available
     *
     * Helper to safely read fields based on structure size.
     *
     * @param ptr Base pointer
     * @param offset Offset from base
     * @param structure_size Total structure size
     * @return Value if available, 0 otherwise
     */
    static uint64_t read_uint64_if_available(
        const uint8_t* ptr,
        size_t offset,
        uint32_t structure_size
    );

    /**
     * Read uint16 at offset if available
     *
     * Helper to safely read fields based on structure size.
     *
     * @param ptr Base pointer
     * @param offset Offset from base
     * @param structure_size Total structure size
     * @return Value if available, 0 otherwise
     */
    static uint16_t read_uint16_if_available(
        const uint8_t* ptr,
        size_t offset,
        uint32_t structure_size
    );

    /**
     * Convert RVA to file offset
     *
     * Helper that wraps pe_section_parser::rva_to_file_offset()
     * and returns 0 if RVA is not in any section.
     *
     * @param sections Parsed PE sections
     * @param rva RVA to convert
     * @return File offset or 0 if not mapped
     */
    static size_t rva_to_offset(
        const std::vector<pe_section>& sections,
        uint32_t rva
    );
};

} // namespace libexe

#endif // LIBEXE_PE_DIRECTORIES_LOAD_CONFIG_HPP
