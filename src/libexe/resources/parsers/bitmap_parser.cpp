#include <libexe/resources/parsers/bitmap_parser.hpp>
#include <formats/resources/basic/basic.hh>

namespace libexe {

std::optional<bitmap_data> bitmap_parser::parse(std::span<const uint8_t> data) {
    // Minimum size check (header is at least 12 bytes for BITMAPCOREHEADER)
    if (data.size() < 12) {
        return std::nullopt;
    }

    try {
        bitmap_data result;

        const uint8_t* ptr = data.data();
        const uint8_t* end = data.data() + data.size();

        // Read header size to determine format
        uint32_t header_size = static_cast<uint32_t>(ptr[0]) |
                              (static_cast<uint32_t>(ptr[1]) << 8) |
                              (static_cast<uint32_t>(ptr[2]) << 16) |
                              (static_cast<uint32_t>(ptr[3]) << 24);

        if (header_size == 40) {
            // BITMAPINFOHEADER (Windows 3.0+ format) with palette
            auto ds_bitmap = formats::resources::basic::bitmap_with_palette::read(ptr, end);

            result.info.header_size = ds_bitmap.size;
            result.info.width = ds_bitmap.width;
            result.info.height = ds_bitmap.height;
            result.info.planes = ds_bitmap.planes;
            result.info.bit_count = ds_bitmap.bit_count;
            result.info.compression = static_cast<bitmap_compression>(ds_bitmap.compression);
            result.info.size_image = ds_bitmap.size_image;
            result.info.x_pels_per_meter = ds_bitmap.x_pels_per_meter;
            result.info.y_pels_per_meter = ds_bitmap.y_pels_per_meter;
            result.info.clr_used = ds_bitmap.clr_used;
            result.info.clr_important = ds_bitmap.clr_important;

            // Convert palette from DataScript
            result.palette.reserve(ds_bitmap.palette.size());
            for (const auto& ds_color : ds_bitmap.palette) {
                rgb_quad color;
                color.blue = ds_color.blue;
                color.green = ds_color.green;
                color.red = ds_color.red;
                color.reserved = ds_color.reserved;
                result.palette.push_back(color);
            }

        } else if (header_size == 12) {
            // BITMAPCOREHEADER (OS/2 1.x format)
            auto ds_header = formats::resources::basic::bitmap_core_header::read(ptr, end);

            result.info.header_size = ds_header.size;
            result.info.width = ds_header.width;
            result.info.height = ds_header.height;
            result.info.planes = ds_header.planes;
            result.info.bit_count = ds_header.bit_count;
            result.info.compression = bitmap_compression::RGB;  // Always uncompressed
            result.info.size_image = 0;
            result.info.x_pels_per_meter = 0;
            result.info.y_pels_per_meter = 0;
            result.info.clr_used = 0;
            result.info.clr_important = 0;

            // OS/2 1.x uses rgb_triple (3 bytes) not rgb_quad (4 bytes)
            // Parse palette manually for this format
            uint32_t palette_size = result.info.palette_size();
            if (palette_size > 0 && ptr + palette_size * 3 <= end) {
                result.palette.reserve(palette_size);

                for (uint32_t i = 0; i < palette_size; ++i) {
                    if (ptr + 3 > end) break;

                    rgb_quad color;
                    color.blue = ptr[0];
                    color.green = ptr[1];
                    color.red = ptr[2];
                    color.reserved = 0;
                    result.palette.push_back(color);

                    ptr += 3;
                }
            }
        } else {
            // Unknown bitmap format
            return std::nullopt;
        }

        // Parse pixel data (rest of the resource)
        if (ptr < end) {
            size_t pixel_data_size = end - ptr;
            result.pixel_data.assign(ptr, ptr + pixel_data_size);
        }

        return result;
    }
    catch (const std::exception&) {
        // Parse error - return nullopt
        return std::nullopt;
    }
}

} // namespace libexe
