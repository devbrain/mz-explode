// libexe - Modern executable file analysis library
// NE Segment Parser

#ifndef LIBEXE_NE_SEGMENT_PARSER_HPP
#define LIBEXE_NE_SEGMENT_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/pe/section.hpp>
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
 * NE Segment Parser
 *
 * Provides comprehensive NE segment analysis and data extraction.
 */
class LIBEXE_EXPORT ne_segment_parser {
public:
    /**
     * Parse all segments from NE file
     */
    static std::vector<ne_segment> parse_segments(
        std::span<const uint8_t> file_data,
        uint32_t ne_offset,
        uint16_t segment_table_offset,
        uint16_t num_segments,
        uint16_t alignment_shift
    );

    /**
     * Classify segment type based on flags
     */
    static section_type classify_segment(uint16_t flags);

    /**
     * Calculate file offset from sector offset
     */
    static uint32_t calculate_file_offset(
        uint16_t sector_offset,
        uint16_t alignment_shift
    );

    /**
     * Calculate actual segment size (0 means 65536)
     */
    static uint32_t calculate_segment_size(uint16_t length);

    /**
     * Find segment by index (1-based)
     */
    static const ne_segment* find_segment_by_index(
        const std::vector<ne_segment>& segments,
        uint16_t index
    );

    /**
     * Find first code segment
     */
    static const ne_segment* find_first_code_segment(
        const std::vector<ne_segment>& segments
    );

    static bool is_code_segment(uint16_t flags);
    static bool is_data_segment(uint16_t flags);
};

} // namespace libexe

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // LIBEXE_NE_SEGMENT_PARSER_HPP
