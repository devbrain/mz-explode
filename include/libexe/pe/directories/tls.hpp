// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_PE_DIRECTORIES_TLS_HPP
#define LIBEXE_PE_DIRECTORIES_TLS_HPP

#include <libexe/export.hpp>
#include <libexe/pe/section.hpp>
#include <cstdint>
#include <vector>
#include <span>

// Disable MSVC warning C4251: 'member': class 'std::...' needs to have dll-interface
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

namespace libexe {

/**
 * TLS callback function pointer
 *
 * Points to a function that will be called for TLS initialization/cleanup.
 * Callback signature: void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
 */
struct LIBEXE_EXPORT tls_callback {
    uint64_t address;  // Virtual address of callback function (VA, not RVA)

    /**
     * Check if this is a null terminator
     *
     * TLS callback array is null-terminated
     */
    [[nodiscard]] bool is_null() const {
        return address == 0;
    }
};

/**
 * Thread Local Storage (TLS) Directory
 *
 * Contains information for thread-local storage support. TLS allows each
 * thread to have its own copy of certain variables. This is parsed from
 * the PE TLS directory (data directory index 9).
 *
 * TLS is architecture-specific:
 * - PE32: Uses 32-bit addresses
 * - PE32+: Uses 64-bit addresses
 */
struct LIBEXE_EXPORT tls_directory {
    // TLS data range (virtual addresses, not RVAs)
    uint64_t start_address_of_raw_data;  // VA of TLS template start
    uint64_t end_address_of_raw_data;    // VA of TLS template end
    uint64_t address_of_index;           // VA of TLS index variable
    uint64_t address_of_callbacks;       // VA of TLS callback array

    // TLS characteristics
    uint32_t size_of_zero_fill;          // Size of zero-initialized TLS data (BSS)
    uint32_t characteristics;            // Alignment characteristics

    // Parsed callback functions
    std::vector<tls_callback> callbacks;  // TLS callback functions

    /**
     * Get size of TLS template data
     *
     * Returns the size of initialized TLS data (from file).
     */
    [[nodiscard]] uint64_t template_size() const {
        if (end_address_of_raw_data > start_address_of_raw_data) {
            return end_address_of_raw_data - start_address_of_raw_data;
        }
        return 0;
    }

    /**
     * Get total TLS data size
     *
     * Returns initialized data size + zero-fill size.
     */
    [[nodiscard]] uint64_t total_size() const {
        return template_size() + size_of_zero_fill;
    }

    /**
     * Get number of TLS callbacks
     */
    [[nodiscard]] size_t callback_count() const {
        return callbacks.size();
    }

    /**
     * Check if TLS has callbacks
     */
    [[nodiscard]] bool has_callbacks() const {
        return !callbacks.empty();
    }

    /**
     * Check if TLS directory is empty/invalid
     */
    [[nodiscard]] bool is_empty() const {
        return start_address_of_raw_data == 0 &&
               end_address_of_raw_data == 0 &&
               address_of_index == 0;
    }

    /**
     * Get alignment from characteristics
     *
     * Returns TLS data alignment in bytes.
     * Characteristics bits 20-23 encode alignment as power of 2.
     */
    [[nodiscard]] uint32_t alignment() const {
        // Extract alignment bits (20-23)
        uint32_t align_bits = (characteristics >> 20) & 0x0F;
        if (align_bits == 0) {
            return 0;  // Default or no specific alignment
        }
        return 1u << align_bits;  // 2^(bits)
    }

    /**
     * Convert virtual address to RVA
     *
     * Helper to convert TLS VA to RVA using image base.
     *
     * @param va Virtual address
     * @param image_base Image base address
     * @return RVA (va - image_base)
     */
    [[nodiscard]] static uint32_t va_to_rva(uint64_t va, uint64_t image_base) {
        if (va < image_base) {
            return 0;  // Invalid VA
        }
        return static_cast<uint32_t>(va - image_base);
    }

    /**
     * Get TLS data start RVA
     *
     * @param image_base Image base address
     */
    [[nodiscard]] uint32_t get_start_rva(uint64_t image_base) const {
        return va_to_rva(start_address_of_raw_data, image_base);
    }

    /**
     * Get TLS data end RVA
     *
     * @param image_base Image base address
     */
    [[nodiscard]] uint32_t get_end_rva(uint64_t image_base) const {
        return va_to_rva(end_address_of_raw_data, image_base);
    }

    /**
     * Get TLS index RVA
     *
     * @param image_base Image base address
     */
    [[nodiscard]] uint32_t get_index_rva(uint64_t image_base) const {
        return va_to_rva(address_of_index, image_base);
    }

    /**
     * Get TLS callbacks RVA
     *
     * @param image_base Image base address
     */
    [[nodiscard]] uint32_t get_callbacks_rva(uint64_t image_base) const {
        return va_to_rva(address_of_callbacks, image_base);
    }
};

/**
 * TLS Directory Parser
 *
 * Parses PE Thread Local Storage (TLS) directory (data directory index 9)
 * to extract TLS configuration and callback functions.
 *
 * TLS directories use virtual addresses (VAs) instead of RVAs, so we need
 * the image base to convert them. There are two formats:
 * - PE32: 32-bit pointers (IMAGE_TLS_DIRECTORY32)
 * - PE32+: 64-bit pointers (IMAGE_TLS_DIRECTORY64)
 */
class LIBEXE_EXPORT tls_directory_parser {
public:
    /**
     * Parse TLS directory from PE file
     *
     * Reads IMAGE_TLS_DIRECTORY and TLS callback array.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections (for VA to offset conversion)
     * @param tls_dir_rva RVA to TLS directory
     * @param tls_dir_size Size of TLS directory
     * @param is_64bit true for PE32+ (64-bit), false for PE32 (32-bit)
     * @param image_base Image base address (for VA to RVA conversion)
     * @return Parsed TLS directory with callbacks
     * @throws std::runtime_error if TLS directory is malformed
     */
    static tls_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t tls_dir_rva,
        uint32_t tls_dir_size,
        bool is_64bit,
        uint64_t image_base
    );

private:
    /**
     * Parse TLS callbacks array
     *
     * Reads null-terminated array of callback function pointers.
     *
     * @param file_data Complete PE file data
     * @param sections Parsed PE sections
     * @param callbacks_va Virtual address of callback array
     * @param is_64bit true for 64-bit pointers, false for 32-bit
     * @param image_base Image base address
     * @return Vector of TLS callbacks
     */
    static std::vector<tls_callback> parse_callbacks(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint64_t callbacks_va,
        bool is_64bit,
        uint64_t image_base
    );

    /**
     * Convert virtual address to file offset
     *
     * TLS uses VAs (not RVAs), so we need to convert VA to RVA first,
     * then RVA to file offset.
     *
     * @param sections Parsed PE sections
     * @param va Virtual address
     * @param image_base Image base address
     * @return File offset
     * @throws std::runtime_error if VA is invalid
     */
    static size_t va_to_offset(
        const std::vector<pe_section>& sections,
        uint64_t va,
        uint64_t image_base
    );

    /**
     * Convert RVA to file offset
     *
     * Helper that wraps pe_section_parser::rva_to_file_offset()
     * and throws on failure.
     *
     * @param sections Parsed PE sections
     * @param rva RVA to convert
     * @return File offset
     * @throws std::runtime_error if RVA is not in any section
     */
    static size_t rva_to_offset(
        const std::vector<pe_section>& sections,
        uint32_t rva
    );
};

} // namespace libexe

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // LIBEXE_PE_DIRECTORIES_TLS_HPP
