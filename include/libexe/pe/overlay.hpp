// libexe - Modern executable file analysis library
// PE Overlay detection and extraction

#ifndef LIBEXE_PE_OVERLAY_HPP
#define LIBEXE_PE_OVERLAY_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <span>
#include <vector>
#include <optional>

// Disable MSVC warning C4251: 'member': class 'std::...' needs to have dll-interface
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

namespace libexe {

/**
 * PE Overlay Information
 *
 * An overlay is data appended to a PE file after the last section's raw data.
 * This area is not loaded into memory by the Windows loader.
 *
 * Common uses of overlays:
 * - Self-extracting archives (SFX): compressed data
 * - Installers: embedded payload data
 * - Packed executables: original executable or additional data
 * - Digital signatures: Authenticode (though usually in security directory)
 * - License data: registration keys, etc.
 */
struct LIBEXE_EXPORT overlay_info {
    /// File offset where overlay data begins
    uint64_t offset = 0;

    /// Size of overlay data in bytes
    uint64_t size = 0;

    /// Entropy of overlay data (0.0-8.0 bits)
    double entropy = 0.0;

    /**
     * Check if overlay exists
     * @return true if overlay size > 0
     */
    [[nodiscard]] bool exists() const {
        return size > 0;
    }

    /**
     * Check if overlay appears to be compressed/encrypted
     * @return true if entropy >= 7.0
     */
    [[nodiscard]] bool is_high_entropy() const {
        return entropy >= 7.0;
    }

    /**
     * Get overlay as percentage of total file size
     * @param file_size Total file size
     * @return Percentage (0.0-100.0)
     */
    [[nodiscard]] double percentage_of_file(uint64_t file_size) const {
        if (file_size == 0) return 0.0;
        return (static_cast<double>(size) / static_cast<double>(file_size)) * 100.0;
    }
};

/**
 * PE Overlay Detector
 *
 * Detects and extracts overlay data from PE files.
 *
 * The overlay starts immediately after the last byte of raw section data.
 * It's calculated as: max(section.raw_offset + section.raw_size) for all sections.
 *
 * The security directory (Authenticode signatures) is NOT considered part of
 * the overlay, even though it's also stored at the end of the file.
 */
class LIBEXE_EXPORT overlay_detector {
public:
    /**
     * Detect overlay in PE file
     *
     * @param file_data Complete PE file data
     * @param pe_offset Offset to PE header ("PE\0\0" signature)
     * @param section_count Number of sections
     * @param optional_header_size Size of optional header
     * @return Overlay information (size=0 if no overlay)
     */
    [[nodiscard]] static overlay_info detect(
        std::span<const uint8_t> file_data,
        uint32_t pe_offset,
        uint16_t section_count,
        uint16_t optional_header_size
    );

    /**
     * Calculate end of PE image (excluding overlay)
     *
     * This is the first byte after all section raw data.
     *
     * @param file_data Complete PE file data
     * @param pe_offset Offset to PE header
     * @param section_count Number of sections
     * @param optional_header_size Size of optional header
     * @return File offset of first overlay byte (or file size if no overlay)
     */
    [[nodiscard]] static uint64_t calculate_image_end(
        std::span<const uint8_t> file_data,
        uint32_t pe_offset,
        uint16_t section_count,
        uint16_t optional_header_size
    );

    /**
     * Extract overlay data
     *
     * @param file_data Complete PE file data
     * @param info Overlay info from detect()
     * @return Copy of overlay data (empty if no overlay)
     */
    [[nodiscard]] static std::vector<uint8_t> extract(
        std::span<const uint8_t> file_data,
        const overlay_info& info
    );

    /**
     * Get span view of overlay data (no copy)
     *
     * @param file_data Complete PE file data
     * @param info Overlay info from detect()
     * @return Span view of overlay data (empty if no overlay)
     */
    [[nodiscard]] static std::span<const uint8_t> view(
        std::span<const uint8_t> file_data,
        const overlay_info& info
    );
};

} // namespace libexe

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // LIBEXE_PE_OVERLAY_HPP
