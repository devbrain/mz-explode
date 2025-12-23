#include <libexe/resources/parsers/icon_parser.hpp>
#include <formats/resources/basic/basic.hh>  // Generated DataScript parser (modular)
#include <cstring>
#include <algorithm>

namespace libexe {

namespace {

// Helper to read uint16_t little-endian
[[maybe_unused]] uint16_t read_u16_le(const uint8_t* ptr) {
    return static_cast<uint16_t>(ptr[0]) |
           (static_cast<uint16_t>(ptr[1]) << 8);
}

// Helper to read uint32_t little-endian
uint32_t read_u32_le(const uint8_t* ptr) {
    return static_cast<uint32_t>(ptr[0]) |
           (static_cast<uint32_t>(ptr[1]) << 8) |
           (static_cast<uint32_t>(ptr[2]) << 16) |
           (static_cast<uint32_t>(ptr[3]) << 24);
}

// Helper to read int32_t little-endian
[[maybe_unused]] int32_t read_i32_le(const uint8_t* ptr) {
    return static_cast<int32_t>(read_u32_le(ptr));
}

// Helper to write uint16_t little-endian
void write_u16_le(uint8_t* ptr, uint16_t value) {
    ptr[0] = static_cast<uint8_t>(value & 0xFF);
    ptr[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
}

// Helper to write uint32_t little-endian
void write_u32_le(uint8_t* ptr, uint32_t value) {
    ptr[0] = static_cast<uint8_t>(value & 0xFF);
    ptr[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    ptr[2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    ptr[3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

// Calculate row size in bytes (must be DWORD-aligned)
uint32_t calculate_row_size(uint32_t width, uint16_t bit_count) {
    uint32_t bits_per_row = width * bit_count;
    return ((bits_per_row + 31) / 32) * 4;  // Round up to nearest DWORD
}

} // anonymous namespace

std::optional<icon_image> icon_parser::parse(std::span<const uint8_t> data) {
    // Minimum size: BITMAPINFOHEADER (40 bytes)
    if (data.size() < 40) {
        return std::nullopt;
    }

    try {
        // Parse using generated DataScript parser
        const uint8_t* ptr = data.data();
        const uint8_t* end = data.data() + data.size();
        auto ds_header = formats::resources::basic::bitmap_info_header::read(ptr, end);

        icon_image result;

        // Convert DataScript structure to our public API
        result.header.size = ds_header.size;
        result.header.width = ds_header.width;
        result.header.height = ds_header.height;
        result.header.planes = ds_header.planes;
        result.header.bit_count = ds_header.bit_count;
        result.header.compression = ds_header.compression;
        result.header.size_image = ds_header.size_image;
        result.header.x_pels_per_meter = ds_header.x_pels_per_meter;
        result.header.y_pels_per_meter = ds_header.y_pels_per_meter;
        result.header.clr_used = ds_header.clr_used;
        result.header.clr_important = ds_header.clr_important;

        // Validate dimensions
        if (result.header.width <= 0 || result.header.height <= 0) {
            return std::nullopt;  // Invalid dimensions
        }

        ptr = data.data() + 40;  // Move past header

    // Parse color table (for <= 8bpp)
    uint32_t color_table_size = result.header.color_table_size();
    if (color_table_size > 0) {
        if (ptr + color_table_size > data.data() + data.size()) {
            return std::nullopt;  // Not enough data
        }

        uint32_t num_colors = color_table_size / 4;
        result.color_table.reserve(num_colors);

        for (uint32_t i = 0; i < num_colors; ++i) {
            rgb_quad color;
            color.blue = ptr[0];
            color.green = ptr[1];
            color.red = ptr[2];
            color.reserved = ptr[3];
            result.color_table.push_back(color);
            ptr += 4;
        }
    }

    // Calculate bitmap sizes
    uint32_t xor_height = result.header.xor_height();
    uint32_t xor_row_size = calculate_row_size(result.header.width, result.header.bit_count);
    uint32_t xor_size = xor_row_size * xor_height;

    uint32_t and_row_size = calculate_row_size(result.header.width, 1);  // AND mask is always 1bpp
    uint32_t and_size = and_row_size * xor_height;

    // Parse XOR mask (color data)
    if (ptr + xor_size > data.data() + data.size()) {
        return std::nullopt;  // Not enough data
    }

    result.xor_mask.assign(ptr, ptr + xor_size);
    ptr += xor_size;

    // Parse AND mask (transparency)
    if (ptr + and_size > data.data() + data.size()) {
        return std::nullopt;  // Not enough data
    }

    result.and_mask.assign(ptr, ptr + and_size);

        return result;
    }
    catch (const std::exception&) {
        // Parse error - return nullopt
        return std::nullopt;
    }
}

std::vector<uint8_t> icon_image::raw_dib_data() const {
    std::vector<uint8_t> result;

    // Reserve space
    size_t total_size = 40 + (color_table.size() * 4) + xor_mask.size();
    result.reserve(total_size);

    // Write header
    result.resize(40);
    write_u32_le(&result[0], header.size);
    write_u32_le(&result[4], static_cast<uint32_t>(header.width));
    write_u32_le(&result[8], static_cast<uint32_t>(header.height));
    write_u16_le(&result[12], header.planes);
    write_u16_le(&result[14], header.bit_count);
    write_u32_le(&result[16], header.compression);
    write_u32_le(&result[20], header.size_image);
    write_u32_le(&result[24], static_cast<uint32_t>(header.x_pels_per_meter));
    write_u32_le(&result[28], static_cast<uint32_t>(header.y_pels_per_meter));
    write_u32_le(&result[32], header.clr_used);
    write_u32_le(&result[36], header.clr_important);

    // Write color table
    for (const auto& color : color_table) {
        result.push_back(color.blue);
        result.push_back(color.green);
        result.push_back(color.red);
        result.push_back(color.reserved);
    }

    // Write XOR mask
    result.insert(result.end(), xor_mask.begin(), xor_mask.end());

    return result;
}

std::vector<uint8_t> icon_image::to_ico_file() const {
    std::vector<uint8_t> result;

    // Calculate sizes
    uint32_t xor_height = header.xor_height();
    uint32_t image_size = 40 + (color_table.size() * 4) + xor_mask.size() + and_mask.size();
    uint32_t file_offset = 6 + 16;  // ICONDIR (6) + ICONDIRENTRY (16)

    // Reserve space
    result.reserve(file_offset + image_size);

    // Write ICONDIR (6 bytes)
    result.resize(6);
    write_u16_le(&result[0], 0);    // Reserved (must be 0)
    write_u16_le(&result[2], 2);    // Type (2 = icon)
    write_u16_le(&result[4], 1);    // Count (1 image)

    // Write ICONDIRENTRY (16 bytes)
    result.resize(6 + 16);
    result[6] = static_cast<uint8_t>(header.width == 256 ? 0 : header.width);
    result[7] = static_cast<uint8_t>(xor_height == 256 ? 0 : xor_height);
    result[8] = header.bit_count >= 8 ? 0 : static_cast<uint8_t>(1 << header.bit_count);  // Color count
    result[9] = 0;  // Reserved
    write_u16_le(&result[10], header.planes);
    write_u16_le(&result[12], header.bit_count);
    write_u32_le(&result[14], image_size);
    write_u32_le(&result[18], file_offset);

    // Write image data (DIB without file header)
    auto dib_data = raw_dib_data();
    result.insert(result.end(), dib_data.begin(), dib_data.end());

    // Write AND mask
    result.insert(result.end(), and_mask.begin(), and_mask.end());

    return result;
}

} // namespace libexe
