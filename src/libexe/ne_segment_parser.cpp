#include <libexe/ne/segment_parser.hpp>
#include "libexe_format_ne.hh"  // Generated DataScript parser
#include <algorithm>
#include <stdexcept>

namespace libexe {

std::vector<ne_segment> ne_segment_parser::parse_segments(
    std::span<const uint8_t> file_data,
    uint32_t ne_offset,
    uint16_t segment_table_offset,
    uint16_t num_segments,
    uint16_t alignment_shift
) {
    std::vector<ne_segment> segments;

    if (num_segments == 0) {
        return segments;
    }

    segments.reserve(num_segments);

    // Calculate absolute segment table offset
    const size_t table_offset = ne_offset + segment_table_offset;

    if (table_offset >= file_data.size()) {
        throw std::runtime_error("Invalid segment table offset");
    }

    const uint8_t* ptr = file_data.data() + table_offset;
    const uint8_t* end = file_data.data() + file_data.size();

    // Parse each segment table entry (8 bytes per entry)
    for (uint16_t i = 0; i < num_segments; ++i) {
        if (ptr + 8 > end) {
            throw std::runtime_error("Segment table truncated");
        }

        // Parse NE_SEGMENT_TABLE_ENTRY using DataScript
        auto seg_entry = formats::ne::ne_header::ne_segment_table_entry::read(ptr, end);

        ne_segment segment;

        // Basic info
        segment.index = i + 1;  // 1-based index

        // File layout
        segment.file_offset = calculate_file_offset(seg_entry.sector_offset, alignment_shift);
        segment.file_size = calculate_segment_size(seg_entry.length);

        // Memory layout
        segment.min_alloc_size = (seg_entry.min_alloc == 0) ? 65536 : seg_entry.min_alloc;

        // Properties
        segment.flags = static_cast<uint16_t>(seg_entry.flags);

        // Classify segment type
        segment.type = classify_segment(segment.flags);

        // Extract segment data from file
        if (seg_entry.sector_offset > 0 && segment.file_size > 0) {
            const size_t data_start = segment.file_offset;

            if (data_start < file_data.size()) {
                const size_t data_end = std::min(
                    data_start + segment.file_size,
                    file_data.size()
                );

                segment.data = file_data.subspan(data_start, data_end - data_start);
            }
        }

        segments.push_back(std::move(segment));

        // Note: ptr is automatically advanced by DataScript's read() method
    }

    return segments;
}

section_type ne_segment_parser::classify_segment(uint16_t flags) {
    // NE segment classification is simple: bit 0 determines type
    // Bit 0 clear (0) = code segment
    // Bit 0 set (1) = data segment
    return is_data_segment(flags) ? section_type::DATA : section_type::CODE;
}

uint32_t ne_segment_parser::calculate_file_offset(
    uint16_t sector_offset,
    uint16_t alignment_shift
) {
    // NE uses sector-based offsets with alignment shift
    // file_offset = sector_offset << alignment_shift
    // alignment_shift is typically 4 (16-byte alignment) or 9 (512-byte alignment)

    if (sector_offset == 0) {
        return 0;
    }

    // Validate alignment shift (should be 0-15)
    if (alignment_shift > 15) {
        throw std::runtime_error("Invalid alignment shift value");
    }

    return static_cast<uint32_t>(sector_offset) << alignment_shift;
}

uint32_t ne_segment_parser::calculate_segment_size(uint16_t length) {
    // NE segment length: 0 means 65536 bytes (64KB)
    return (length == 0) ? 65536 : static_cast<uint32_t>(length);
}

const ne_segment* ne_segment_parser::find_segment_by_index(
    const std::vector<ne_segment>& segments,
    uint16_t index
) {
    // NE uses 1-based segment indices
    if (index == 0 || index > segments.size()) {
        return nullptr;
    }

    // Convert to 0-based array index
    return &segments[index - 1];
}

const ne_segment* ne_segment_parser::find_first_code_segment(
    const std::vector<ne_segment>& segments
) {
    for (const auto& segment : segments) {
        if (segment.is_code()) {
            return &segment;
        }
    }
    return nullptr;
}

bool ne_segment_parser::is_code_segment(uint16_t flags) {
    // Code segment: DATA flag (bit 0) is NOT set
    return (flags & static_cast<uint16_t>(ne_segment_flags::DATA)) == 0;
}

bool ne_segment_parser::is_data_segment(uint16_t flags) {
    // Data segment: DATA flag (bit 0) is set
    return (flags & static_cast<uint16_t>(ne_segment_flags::DATA)) != 0;
}

} // namespace libexe
