// libexe - Modern executable file analysis library
// PE Overlay detection implementation

#include <libexe/pe/overlay.hpp>
#include <libexe/core/entropy.hpp>
#include <algorithm>
#include <stdexcept>

namespace libexe {

namespace {

// Section header is 40 bytes
constexpr size_t SECTION_HEADER_SIZE = 40;

// Offsets within section header
constexpr size_t SECTION_RAW_SIZE_OFFSET = 16;    // SizeOfRawData
constexpr size_t SECTION_RAW_OFFSET_OFFSET = 20;  // PointerToRawData

uint32_t read_u32(const uint8_t* ptr) {
    return static_cast<uint32_t>(ptr[0]) |
           (static_cast<uint32_t>(ptr[1]) << 8) |
           (static_cast<uint32_t>(ptr[2]) << 16) |
           (static_cast<uint32_t>(ptr[3]) << 24);
}

} // anonymous namespace

uint64_t overlay_detector::calculate_image_end(
    std::span<const uint8_t> file_data,
    uint32_t pe_offset,
    uint16_t section_count,
    uint16_t optional_header_size
) {
    if (file_data.empty()) {
        return 0;
    }

    // Calculate section table offset
    // PE header: 4 (signature) + 20 (COFF header) + optional_header_size
    uint64_t section_table_offset = pe_offset + 4 + 20 + optional_header_size;

    if (section_table_offset + section_count * SECTION_HEADER_SIZE > file_data.size()) {
        // Section table extends beyond file
        return file_data.size();
    }

    // Find the section with the highest raw data end
    uint64_t max_end = 0;

    for (uint16_t i = 0; i < section_count; ++i) {
        const uint8_t* section_ptr = file_data.data() + section_table_offset + i * SECTION_HEADER_SIZE;

        uint32_t raw_size = read_u32(section_ptr + SECTION_RAW_SIZE_OFFSET);
        uint32_t raw_offset = read_u32(section_ptr + SECTION_RAW_OFFSET_OFFSET);

        // Skip sections with no raw data
        if (raw_offset == 0 || raw_size == 0) {
            continue;
        }

        uint64_t section_end = static_cast<uint64_t>(raw_offset) + static_cast<uint64_t>(raw_size);
        if (section_end > max_end) {
            max_end = section_end;
        }
    }

    // If no sections have raw data, the image ends after headers
    if (max_end == 0) {
        // Use section table end as minimum
        max_end = section_table_offset + section_count * SECTION_HEADER_SIZE;
    }

    return max_end;
}

overlay_info overlay_detector::detect(
    std::span<const uint8_t> file_data,
    uint32_t pe_offset,
    uint16_t section_count,
    uint16_t optional_header_size
) {
    overlay_info info;

    if (file_data.empty()) {
        return info;
    }

    uint64_t image_end = calculate_image_end(file_data, pe_offset, section_count, optional_header_size);
    uint64_t file_size = file_data.size();

    if (image_end >= file_size) {
        // No overlay
        return info;
    }

    info.offset = image_end;
    info.size = file_size - image_end;

    // Calculate entropy of overlay
    if (info.size > 0) {
        auto overlay_data = view(file_data, info);
        info.entropy = entropy_calculator::calculate(overlay_data);
    }

    return info;
}

std::vector<uint8_t> overlay_detector::extract(
    std::span<const uint8_t> file_data,
    const overlay_info& info
) {
    if (!info.exists() || info.offset >= file_data.size()) {
        return {};
    }

    uint64_t available = file_data.size() - info.offset;
    uint64_t copy_size = std::min(info.size, available);

    return std::vector<uint8_t>(
        file_data.begin() + info.offset,
        file_data.begin() + info.offset + copy_size
    );
}

std::span<const uint8_t> overlay_detector::view(
    std::span<const uint8_t> file_data,
    const overlay_info& info
) {
    if (!info.exists() || info.offset >= file_data.size()) {
        return {};
    }

    uint64_t available = file_data.size() - info.offset;
    uint64_t view_size = std::min(info.size, available);

    return file_data.subspan(info.offset, view_size);
}

} // namespace libexe
