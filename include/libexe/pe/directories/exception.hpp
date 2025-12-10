// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_PE_DIRECTORIES_EXCEPTION_HPP
#define LIBEXE_PE_DIRECTORIES_EXCEPTION_HPP

#include <libexe/export.hpp>
#include <libexe/pe/section.hpp>
#include <cstdint>
#include <vector>
#include <string>
#include <span>

namespace libexe {

/**
 * Exception handling method
 */
enum class exception_handling_type {
    NONE,           // No exception handling
    X64_SEH,        // x64 Structured Exception Handling (RUNTIME_FUNCTION table)
    ARM_PDATA,      // ARM/ARM64 procedure data
    UNKNOWN         // Unknown or unsupported
};

/**
 * RUNTIME_FUNCTION entry (x64)
 *
 * Used for x64 Structured Exception Handling (SEH).
 * Each entry describes a function's exception handling information.
 *
 * Reference: Microsoft PE/COFF specification, section 6.5
 */
struct runtime_function {
    uint32_t begin_address = 0;      // RVA of function start
    uint32_t end_address = 0;        // RVA of function end
    uint32_t unwind_info_address = 0; // RVA to UNWIND_INFO structure

    /**
     * Check if this entry is valid
     */
    [[nodiscard]] bool is_valid() const {
        return begin_address != 0 && end_address > begin_address;
    }

    /**
     * Get function size in bytes
     */
    [[nodiscard]] uint32_t function_size() const {
        return end_address - begin_address;
    }
};

/**
 * UNWIND_CODE structure (x64)
 *
 * Describes a single unwind operation in the prolog.
 */
struct unwind_code {
    uint8_t code_offset = 0;    // Offset of end of prolog
    uint8_t unwind_op = 0;      // Unwind operation code (4 bits) + operation info (4 bits)
    uint16_t frame_offset = 0;  // Frame offset or allocation size
};

/**
 * Unwind operation codes
 */
enum class unwind_op_code : uint8_t {
    PUSH_NONVOL = 0,     // Push nonvolatile register
    ALLOC_LARGE = 1,     // Allocate large-sized area on stack
    ALLOC_SMALL = 2,     // Allocate small-sized area on stack
    SET_FPREG = 3,       // Establish frame pointer register
    SAVE_NONVOL = 4,     // Save nonvolatile register using MOV
    SAVE_NONVOL_FAR = 5, // Save nonvolatile register using MOV (far)
    SAVE_XMM128 = 8,     // Save all 128 bits of XMM register
    SAVE_XMM128_FAR = 9, // Save all 128 bits of XMM register (far)
    PUSH_MACHFRAME = 10  // Push a machine frame
};

/**
 * UNWIND_INFO structure (x64)
 *
 * Contains the unwind information for a function.
 */
struct unwind_info {
    uint8_t version = 0;              // Unwind info version (should be 1 or 2)
    uint8_t flags = 0;                // Unwind info flags
    uint8_t size_of_prolog = 0;       // Size of function prolog in bytes
    uint8_t count_of_codes = 0;       // Count of unwind codes
    uint8_t frame_register = 0;       // Frame pointer register (4 bits) + offset (4 bits)

    std::vector<unwind_code> unwind_codes; // Unwind operations

    // Optional fields (present if flags indicate)
    uint32_t exception_handler_rva = 0;    // RVA of exception handler
    uint32_t exception_data_rva = 0;       // RVA of exception-specific data
    std::vector<uint8_t> exception_data;   // Exception-specific data

    /**
     * Check if chained unwind info is present
     */
    [[nodiscard]] bool has_chained_info() const {
        return (flags & 0x04) != 0;  // UNW_FLAG_CHAININFO
    }

    /**
     * Check if exception handler is present
     */
    [[nodiscard]] bool has_exception_handler() const {
        return (flags & 0x01) != 0;  // UNW_FLAG_EHANDLER
    }

    /**
     * Check if termination handler is present
     */
    [[nodiscard]] bool has_termination_handler() const {
        return (flags & 0x02) != 0;  // UNW_FLAG_UHANDLER
    }

    /**
     * Get frame pointer register number
     */
    [[nodiscard]] uint8_t get_frame_register() const {
        return frame_register & 0x0F;
    }

    /**
     * Get frame pointer offset (scaled by 16)
     */
    [[nodiscard]] uint8_t get_frame_offset() const {
        return (frame_register >> 4) & 0x0F;
    }
};

/**
 * Exception Directory
 *
 * Contains exception handling information for the executable.
 *
 * For x64: Array of RUNTIME_FUNCTION entries
 * For ARM/ARM64: Procedure data (PDATA) entries
 * For x86: Not used (stack-based exception handling)
 *
 * Data directory index: 3 (IMAGE_DIRECTORY_ENTRY_EXCEPTION)
 */
struct LIBEXE_EXPORT exception_directory {
    exception_handling_type type = exception_handling_type::NONE;

    // x64 exception data
    std::vector<runtime_function> runtime_functions;

    /**
     * Check if this is an empty exception directory
     */
    [[nodiscard]] bool is_empty() const {
        return runtime_functions.empty();
    }

    /**
     * Get number of runtime functions
     */
    [[nodiscard]] size_t function_count() const {
        return runtime_functions.size();
    }

    /**
     * Find runtime function containing the given RVA
     */
    [[nodiscard]] const runtime_function* find_function(uint32_t rva) const {
        for (const auto& func : runtime_functions) {
            if (rva >= func.begin_address && rva < func.end_address) {
                return &func;
            }
        }
        return nullptr;
    }

    /**
     * Get exception handling type as string
     */
    [[nodiscard]] std::string type_name() const {
        switch (type) {
            case exception_handling_type::NONE: return "None";
            case exception_handling_type::X64_SEH: return "x64 SEH";
            case exception_handling_type::ARM_PDATA: return "ARM PDATA";
            case exception_handling_type::UNKNOWN: return "Unknown";
            default: return "Invalid";
        }
    }
};

/**
 * Exception Directory Parser
 *
 * Parses the PE exception directory (data directory index 3).
 *
 * The exception directory contains exception handling information:
 * - For x64: Array of RUNTIME_FUNCTION entries (IMAGE_RUNTIME_FUNCTION_ENTRY)
 * - For ARM/ARM64: Procedure data (PDATA) entries
 * - For x86: Not used (stack-based exception handling)
 *
 * This parser supports x64 exception tables. Each RUNTIME_FUNCTION entry
 * is 12 bytes and describes the exception handling for one function.
 */
class exception_directory_parser {
public:
    /**
     * Parse exception directory from PE file data
     *
     * @param file_data Complete PE file data
     * @param sections Section headers for RVA-to-offset conversion
     * @param exception_rva RVA of exception directory
     * @param exception_size Size of exception directory in bytes
     * @param is_64bit True if this is a PE32+ (64-bit) file
     * @return Parsed exception_directory structure
     * @throws std::runtime_error if parsing fails
     */
    static exception_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t exception_rva,
        uint32_t exception_size,
        bool is_64bit
    );

private:
    /**
     * Parse x64 exception directory (array of RUNTIME_FUNCTION entries)
     *
     * @param ptr Pointer to exception directory data
     * @param end Pointer to end of data
     * @param entry_count Number of RUNTIME_FUNCTION entries
     * @return Vector of runtime_function entries
     */
    static std::vector<runtime_function> parse_x64_runtime_functions(
        const uint8_t* ptr,
        const uint8_t* end,
        size_t entry_count
    );

    /**
     * Parse a single RUNTIME_FUNCTION entry
     *
     * @param ptr Pointer to RUNTIME_FUNCTION data (12 bytes)
     * @param end Pointer to end of data
     * @return runtime_function entry
     */
    static runtime_function parse_runtime_function_entry(
        const uint8_t* ptr,
        const uint8_t* end
    );

    /**
     * Parse UNWIND_INFO structure (optional, for detailed analysis)
     *
     * Note: This is optional and not called by default. The UNWIND_INFO
     * structure is variable-length and complex. Most applications only
     * need the RUNTIME_FUNCTION entries.
     *
     * @param file_data Complete PE file data
     * @param sections Section headers for RVA-to-offset conversion
     * @param unwind_info_rva RVA of UNWIND_INFO structure
     * @return Parsed unwind_info structure
     */
    static unwind_info parse_unwind_info(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t unwind_info_rva
    );

    /**
     * Convert RVA to file offset
     *
     * @param sections Section headers
     * @param rva Relative Virtual Address
     * @return File offset, or 0 if RVA is invalid
     */
    static size_t rva_to_offset(
        const std::vector<pe_section>& sections,
        uint32_t rva
    );
};

} // namespace libexe

#endif // LIBEXE_PE_DIRECTORIES_EXCEPTION_HPP
