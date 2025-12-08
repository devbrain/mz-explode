#ifndef LIBEXE_NE_SEGMENT_PARSER_HPP
#define LIBEXE_NE_SEGMENT_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/section.hpp>
#include <cstdint>
#include <span>
#include <vector>
#include <optional>

namespace libexe {

/**
 * NE Segment Parser
 *
 * Provides comprehensive NE segment analysis and data extraction.
 * Parses NE segment table entries and provides enhanced metadata
 * and helper functions for segment analysis.
 */
class LIBEXE_EXPORT ne_segment_parser {
public:
    /**
     * Parse all segments from NE file
     *
     * Reads the segment table from NE headers and creates enhanced
     * ne_segment structures with full metadata and data access.
     *
     * @param file_data Complete NE file data
     * @param ne_offset Offset to NE signature in file
     * @param segment_table_offset Offset to segment table (from NE header)
     * @param num_segments Number of segments (from NE header)
     * @param alignment_shift Segment alignment shift factor
     * @return Vector of parsed segments with metadata
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
     *
     * Uses segment flags to determine if segment contains code or data.
     * NE segments: bit 0 clear = code, bit 0 set = data
     *
     * @param flags Segment flags
     * @return Classified segment type (CODE or DATA)
     */
    static section_type classify_segment(uint16_t flags);

    /**
     * Calculate file offset from sector offset
     *
     * NE segments use sector-based offsets with an alignment shift.
     * file_offset = sector_offset << alignment_shift
     *
     * @param sector_offset Sector offset from segment table entry
     * @param alignment_shift Alignment shift factor (0-15)
     * @return File offset in bytes
     */
    static uint32_t calculate_file_offset(
        uint16_t sector_offset,
        uint16_t alignment_shift
    );

    /**
     * Calculate actual segment size
     *
     * NE segment length field: 0 means 65536 bytes
     *
     * @param length Length field from segment table entry
     * @return Actual segment size in bytes
     */
    static uint32_t calculate_segment_size(uint16_t length);

    /**
     * Find segment by index (1-based)
     *
     * NE uses 1-based segment indices (e.g., in entry point CS field)
     *
     * @param segments All NE segments
     * @param index 1-based segment index
     * @return Pointer to segment, or nullptr if not found
     */
    static const ne_segment* find_segment_by_index(
        const std::vector<ne_segment>& segments,
        uint16_t index
    );

    /**
     * Find first code segment
     *
     * Returns the first segment with CODE type (DATA flag clear)
     *
     * @param segments All NE segments
     * @return Pointer to first code segment, or nullptr if not found
     */
    static const ne_segment* find_first_code_segment(
        const std::vector<ne_segment>& segments
    );

    /**
     * Check if segment flags indicate code segment
     *
     * @param flags Segment flags
     * @return true if code segment (DATA flag clear)
     */
    static bool is_code_segment(uint16_t flags);

    /**
     * Check if segment flags indicate data segment
     *
     * @param flags Segment flags
     * @return true if data segment (DATA flag set)
     */
    static bool is_data_segment(uint16_t flags);
};

} // namespace libexe

#endif // LIBEXE_NE_SEGMENT_PARSER_HPP
