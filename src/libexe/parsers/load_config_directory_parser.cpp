// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/pe/directories/load_config.hpp>
#include <libexe/pe/section_parser.hpp>
#include "libexe_format_pe_load_config.hh"  // Generated DataScript parser
#include <stdexcept>
#include <cstring>
#include <algorithm>

namespace libexe {

load_config_directory load_config_directory_parser::parse(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t load_config_rva,
    uint32_t load_config_size,
    bool is_64bit
) {
    load_config_directory result;

    if (load_config_rva == 0 || load_config_size == 0) {
        // No load config directory
        return result;
    }

    // Convert RVA to file offset
    size_t load_config_offset = rva_to_offset(sections, load_config_rva);
    if (load_config_offset == 0) {
        // Load config not mapped to file
        return result;
    }

    const uint8_t* ptr = file_data.data() + load_config_offset;
    const uint8_t* end = file_data.data() + file_data.size();

    // Read Size field first (first 4 bytes)
    if (ptr + 4 > end) {
        throw std::runtime_error("Load config directory truncated");
    }

    uint32_t structure_size;
    std::memcpy(&structure_size, ptr, 4);

    // Validate structure size
    if (structure_size == 0 || structure_size > 4096) {
        throw std::runtime_error("Invalid load config size: " + std::to_string(structure_size));
    }

    // Parse based on architecture
    if (is_64bit) {
        return parse_64bit(ptr, end, structure_size);
    } else {
        return parse_32bit(ptr, end, structure_size);
    }
}

load_config_directory load_config_directory_parser::parse_32bit(
    const uint8_t* ptr,
    const uint8_t* end,
    uint32_t structure_size
) {
    load_config_directory result;
    result.size = structure_size;

    // Minimum structure size for 32-bit is 64 bytes (Windows XP)
    if (structure_size < 64 || ptr + structure_size > end) {
        throw std::runtime_error("Load config structure too small or truncated");
    }

    // Use DataScript to parse the fixed fields
    auto load_config = formats::pe::pe_load_config::image_load_config_directory32::read(ptr, end);

    // Copy all fields from DataScript structure
    result.time_date_stamp = load_config.time_date_stamp;
    result.major_version = load_config.major_version;
    result.minor_version = load_config.minor_version;
    result.global_flags_clear = load_config.global_flags_clear;
    result.global_flags_set = load_config.global_flags_set;
    result.critical_section_default_timeout = load_config.critical_section_default_timeout;
    result.de_commit_free_block_threshold = load_config.de_commit_free_block_threshold;
    result.de_commit_total_free_threshold = load_config.de_commit_total_free_threshold;
    result.lock_prefix_table = load_config.lock_prefix_table;
    result.maximum_allocation_size = load_config.maximum_allocation_size;
    result.virtual_memory_threshold = load_config.virtual_memory_threshold;
    result.process_heap_flags = load_config.process_heap_flags;
    result.process_affinity_mask = load_config.process_affinity_mask;
    result.csd_version = load_config.csd_version;
    result.dependent_load_flags = load_config.dependent_load_flags;
    result.edit_list = load_config.edit_list;
    result.security_cookie = load_config.security_cookie;
    result.se_handler_table = load_config.se_handler_table;
    result.se_handler_count = load_config.se_handler_count;
    result.guard_cf_check_function_pointer = load_config.guard_cf_check_function_pointer;
    result.guard_cf_dispatch_function_pointer = load_config.guard_cf_dispatch_function_pointer;
    result.guard_cf_function_table = load_config.guard_cf_function_table;
    result.guard_cf_function_count = load_config.guard_cf_function_count;
    result.guard_flags = load_config.guard_flags;
    result.code_integrity_flags = load_config.code_integrity_flags;
    result.code_integrity_catalog = load_config.code_integrity_catalog;
    result.code_integrity_catalog_offset = load_config.code_integrity_catalog_offset;
    result.code_integrity_reserved = load_config.code_integrity_reserved;

    // Read additional fields if structure is large enough (Windows 10+)
    // These fields are not in the DataScript structure (too many variations)

    // GuardAddressTakenIatEntryTable (offset 96, size 4)
    result.guard_address_taken_iat_entry_table = read_uint32_if_available(ptr, 96, structure_size);

    // GuardAddressTakenIatEntryCount (offset 100, size 4)
    result.guard_address_taken_iat_entry_count = read_uint32_if_available(ptr, 100, structure_size);

    // GuardLongJumpTargetTable (offset 104, size 4)
    result.guard_long_jump_target_table = read_uint32_if_available(ptr, 104, structure_size);

    // GuardLongJumpTargetCount (offset 108, size 4)
    result.guard_long_jump_target_count = read_uint32_if_available(ptr, 108, structure_size);

    // DynamicValueRelocTable (offset 112, size 4)
    result.dynamic_value_reloc_table = read_uint32_if_available(ptr, 112, structure_size);

    // CHPEMetadataPointer (offset 116, size 4)
    result.chpe_metadata_pointer = read_uint32_if_available(ptr, 116, structure_size);

    // GuardRFFailureRoutine (offset 120, size 4)
    result.guard_rf_failure_routine = read_uint32_if_available(ptr, 120, structure_size);

    // GuardRFFailureRoutineFunctionPointer (offset 124, size 4)
    result.guard_rf_failure_routine_function_pointer = read_uint32_if_available(ptr, 124, structure_size);

    // DynamicValueRelocTableOffset (offset 128, size 4)
    result.dynamic_value_reloc_table_offset = read_uint32_if_available(ptr, 128, structure_size);

    // DynamicValueRelocTableSection (offset 132, size 2)
    result.dynamic_value_reloc_table_section = read_uint16_if_available(ptr, 132, structure_size);

    // GuardRFVerifyStackPointerFunctionPointer (offset 136, size 4)
    result.guard_rf_verify_stack_pointer_function_pointer = read_uint32_if_available(ptr, 136, structure_size);

    // HotPatchTableOffset (offset 140, size 4)
    result.hot_patch_table_offset = read_uint32_if_available(ptr, 140, structure_size);

    // EnclaveConfigurationPointer (offset 148, size 4)
    result.enclave_configuration_pointer = read_uint32_if_available(ptr, 148, structure_size);

    // VolatileMetadataPointer (offset 152, size 4)
    result.volatile_metadata_pointer = read_uint32_if_available(ptr, 152, structure_size);

    // GuardEHContinuationTable (offset 156, size 4)
    result.guard_eh_continuation_table = read_uint32_if_available(ptr, 156, structure_size);

    // GuardEHContinuationCount (offset 160, size 4)
    result.guard_eh_continuation_count = read_uint32_if_available(ptr, 160, structure_size);

    // GuardXFGCheckFunctionPointer (offset 164, size 4)
    result.guard_xfg_check_function_pointer = read_uint32_if_available(ptr, 164, structure_size);

    // GuardXFGDispatchFunctionPointer (offset 168, size 4)
    result.guard_xfg_dispatch_function_pointer = read_uint32_if_available(ptr, 168, structure_size);

    // GuardXFGTableDispatchFunctionPointer (offset 172, size 4)
    result.guard_xfg_table_dispatch_function_pointer = read_uint32_if_available(ptr, 172, structure_size);

    // CastGuardOsDeterminedFailureMode (offset 176, size 4)
    result.cast_guard_os_determined_failure_mode = read_uint32_if_available(ptr, 176, structure_size);

    return result;
}

load_config_directory load_config_directory_parser::parse_64bit(
    const uint8_t* ptr,
    const uint8_t* end,
    uint32_t structure_size
) {
    load_config_directory result;
    result.size = structure_size;

    // Minimum structure size for 64-bit is 112 bytes (Windows XP x64)
    if (structure_size < 112 || ptr + structure_size > end) {
        throw std::runtime_error("Load config structure too small or truncated");
    }

    // Use DataScript to parse the fixed fields
    auto load_config = formats::pe::pe_load_config::image_load_config_directory64::read(ptr, end);

    // Copy all fields from DataScript structure
    result.time_date_stamp = load_config.time_date_stamp;
    result.major_version = load_config.major_version;
    result.minor_version = load_config.minor_version;
    result.global_flags_clear = load_config.global_flags_clear;
    result.global_flags_set = load_config.global_flags_set;
    result.critical_section_default_timeout = load_config.critical_section_default_timeout;
    result.de_commit_free_block_threshold = load_config.de_commit_free_block_threshold;
    result.de_commit_total_free_threshold = load_config.de_commit_total_free_threshold;
    result.lock_prefix_table = load_config.lock_prefix_table;
    result.maximum_allocation_size = load_config.maximum_allocation_size;
    result.virtual_memory_threshold = load_config.virtual_memory_threshold;
    result.process_affinity_mask = load_config.process_affinity_mask;
    result.process_heap_flags = load_config.process_heap_flags;
    result.csd_version = load_config.csd_version;
    result.dependent_load_flags = load_config.dependent_load_flags;
    result.edit_list = load_config.edit_list;
    result.security_cookie = load_config.security_cookie;
    result.se_handler_table = load_config.se_handler_table;
    result.se_handler_count = load_config.se_handler_count;
    result.guard_cf_check_function_pointer = load_config.guard_cf_check_function_pointer;
    result.guard_cf_dispatch_function_pointer = load_config.guard_cf_dispatch_function_pointer;
    result.guard_cf_function_table = load_config.guard_cf_function_table;
    result.guard_cf_function_count = load_config.guard_cf_function_count;
    result.guard_flags = load_config.guard_flags;
    result.code_integrity_flags = load_config.code_integrity_flags;
    result.code_integrity_catalog = load_config.code_integrity_catalog;
    result.code_integrity_catalog_offset = load_config.code_integrity_catalog_offset;
    result.code_integrity_reserved = load_config.code_integrity_reserved;

    // Read additional fields if structure is large enough (Windows 10+)
    // Offsets are different for 64-bit

    // GuardAddressTakenIatEntryTable (offset 160, size 8)
    result.guard_address_taken_iat_entry_table = read_uint64_if_available(ptr, 160, structure_size);

    // GuardAddressTakenIatEntryCount (offset 168, size 8)
    result.guard_address_taken_iat_entry_count = read_uint64_if_available(ptr, 168, structure_size);

    // GuardLongJumpTargetTable (offset 176, size 8)
    result.guard_long_jump_target_table = read_uint64_if_available(ptr, 176, structure_size);

    // GuardLongJumpTargetCount (offset 184, size 8)
    result.guard_long_jump_target_count = read_uint64_if_available(ptr, 184, structure_size);

    // DynamicValueRelocTable (offset 192, size 8)
    result.dynamic_value_reloc_table = read_uint64_if_available(ptr, 192, structure_size);

    // CHPEMetadataPointer (offset 200, size 8)
    result.chpe_metadata_pointer = read_uint64_if_available(ptr, 200, structure_size);

    // GuardRFFailureRoutine (offset 208, size 8)
    result.guard_rf_failure_routine = read_uint64_if_available(ptr, 208, structure_size);

    // GuardRFFailureRoutineFunctionPointer (offset 216, size 8)
    result.guard_rf_failure_routine_function_pointer = read_uint64_if_available(ptr, 216, structure_size);

    // DynamicValueRelocTableOffset (offset 224, size 4)
    result.dynamic_value_reloc_table_offset = read_uint32_if_available(ptr, 224, structure_size);

    // DynamicValueRelocTableSection (offset 228, size 2)
    result.dynamic_value_reloc_table_section = read_uint16_if_available(ptr, 228, structure_size);

    // GuardRFVerifyStackPointerFunctionPointer (offset 232, size 8)
    result.guard_rf_verify_stack_pointer_function_pointer = read_uint64_if_available(ptr, 232, structure_size);

    // HotPatchTableOffset (offset 240, size 4)
    result.hot_patch_table_offset = read_uint32_if_available(ptr, 240, structure_size);

    // EnclaveConfigurationPointer (offset 248, size 8)
    result.enclave_configuration_pointer = read_uint64_if_available(ptr, 248, structure_size);

    // VolatileMetadataPointer (offset 256, size 8)
    result.volatile_metadata_pointer = read_uint64_if_available(ptr, 256, structure_size);

    // GuardEHContinuationTable (offset 264, size 8)
    result.guard_eh_continuation_table = read_uint64_if_available(ptr, 264, structure_size);

    // GuardEHContinuationCount (offset 272, size 8)
    result.guard_eh_continuation_count = read_uint64_if_available(ptr, 272, structure_size);

    // GuardXFGCheckFunctionPointer (offset 280, size 8)
    result.guard_xfg_check_function_pointer = read_uint64_if_available(ptr, 280, structure_size);

    // GuardXFGDispatchFunctionPointer (offset 288, size 8)
    result.guard_xfg_dispatch_function_pointer = read_uint64_if_available(ptr, 288, structure_size);

    // GuardXFGTableDispatchFunctionPointer (offset 296, size 8)
    result.guard_xfg_table_dispatch_function_pointer = read_uint64_if_available(ptr, 296, structure_size);

    // CastGuardOsDeterminedFailureMode (offset 304, size 8)
    result.cast_guard_os_determined_failure_mode = read_uint64_if_available(ptr, 304, structure_size);

    return result;
}

uint32_t load_config_directory_parser::read_uint32_if_available(
    const uint8_t* ptr,
    size_t offset,
    uint32_t structure_size
) {
    if (offset + 4 <= structure_size) {
        uint32_t value;
        std::memcpy(&value, ptr + offset, 4);
        return value;
    }
    return 0;
}

uint64_t load_config_directory_parser::read_uint64_if_available(
    const uint8_t* ptr,
    size_t offset,
    uint32_t structure_size
) {
    if (offset + 8 <= structure_size) {
        uint64_t value;
        std::memcpy(&value, ptr + offset, 8);
        return value;
    }
    return 0;
}

uint16_t load_config_directory_parser::read_uint16_if_available(
    const uint8_t* ptr,
    size_t offset,
    uint32_t structure_size
) {
    if (offset + 2 <= structure_size) {
        uint16_t value;
        std::memcpy(&value, ptr + offset, 2);
        return value;
    }
    return 0;
}

size_t load_config_directory_parser::rva_to_offset(
    const std::vector<pe_section>& sections,
    uint32_t rva
) {
    if (rva == 0) {
        return 0;
    }

    auto offset = pe_section_parser::rva_to_file_offset(sections, rva);
    if (!offset) {
        return 0;  // Not mapped to file
    }
    return offset.value();
}

} // namespace libexe
