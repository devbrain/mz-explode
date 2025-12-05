// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/pklite_decompressor.hpp>
#include "bit_reader.hpp"
#include <stdexcept>
#include <vector>
#include <cstring>

namespace libexe {

namespace {

// Helper functions for PKLITE decompression algorithm

/// Adjust length code for standard compression (bit 0x2000 clear)
void adjust_length_code_standard(uint16_t& length_code, bit_reader& reader, bool uncompressed_region) {
    while (true) {
        bool handled = true;

        switch (length_code) {
            case 4:  length_code = 3; break;
            case 0x0a: length_code = 2; break;
            case 0x0b: {
                length_code = static_cast<uint16_t>(0x0A + reader.read_byte());
                if (length_code == 0x109) {
                    length_code = 0xFFFF;
                }
                if (length_code == 0x108 && uncompressed_region) {
                    length_code = 0xFFFD;
                }
                break;
            }
            case 0x0c: length_code = 4; break;
            case 0x0d: length_code = 5; break;
            case 0x1c: length_code = 6; break;
            case 0x1d: length_code = 7; break;
            case 0x1e: length_code = 8; break;
            case 0x1f: length_code = 9; break;
            default:
                length_code = static_cast<uint16_t>(reader.read_bit() | (length_code << 1));
                handled = false;
                break;
        }

        if (handled) break;
    }
}

/// Adjust length code for large compression (bit 0x2000 set)
void adjust_length_code_large(uint16_t& length_code, bit_reader& reader, bool uncompressed_region) {
    while (true) {
        bool handled = true;

        switch (length_code) {
            case 6:    length_code = 2; break;
            case 7:    length_code = 3; break;
            case 8:    length_code = 4; break;
            case 0x12: length_code = 5; break;
            case 0x13: length_code = 6; break;
            case 0x14: length_code = 7; break;
            case 0x2a: length_code = 8; break;
            case 0x2b: length_code = 9; break;
            case 0x2c: length_code = 0xa; break;
            case 0x5a: length_code = 0xb; break;
            case 0x5b: length_code = 0xc; break;
            case 0x5c: {
                length_code = static_cast<uint16_t>(0x19 + reader.read_byte());
                if (length_code == 0x118) {
                    length_code = 0xFFFF;
                }
                if (length_code == 0x117) {
                    length_code = 0xFFFE;
                }
                if (length_code == 0x116 && !uncompressed_region) {
                    length_code = 0xFFFD;
                }
                break;
            }
            case 0xba: length_code = 0xd; break;
            case 0xbb: length_code = 0xe; break;
            case 0xbc: length_code = 0xf; break;
            case 0x17a: length_code = 0x10; break;
            case 0x17b: length_code = 0x11; break;
            case 0x17c: length_code = 0x12; break;
            case 0x2fa: length_code = 0x13; break;
            case 0x2fb: length_code = 0x14; break;
            case 0x2fc: length_code = 0x15; break;
            case 0x2fd: length_code = 0x16; break;
            case 0x2fe: length_code = 0x17; break;
            case 0x2ff: length_code = 0x18; break;
            default:
                length_code = static_cast<uint16_t>(reader.read_bit() | (length_code << 1));
                handled = false;
                break;
        }

        if (handled) break;
    }
}

/// Get base offset for back-reference
uint16_t get_base_offset(bit_reader& reader) {
    while (true) {
        uint16_t offs = reader.read_bit();
        if (offs == 1) {
            return 0;
        }

        offs = static_cast<uint16_t>(reader.read_bit() | (offs << 1));
        offs = static_cast<uint16_t>(reader.read_bit() | (offs << 1));
        offs = static_cast<uint16_t>(reader.read_bit() | (offs << 1));

        switch (offs) {
            case 0: return 0x100;
            case 1: return 0x200;
            default:
                offs = static_cast<uint16_t>(reader.read_bit() | (offs << 1));
                switch (offs) {
                    case 4: return 0x300;
                    case 5: return 0x400;
                    case 6: return 0x500;
                    case 7: return 0x600;
                    default:
                        offs = static_cast<uint16_t>(reader.read_bit() | (offs << 1));
                        switch (offs) {
                            case 0x10: return 0x700;
                            case 0x11: return 0x800;
                            case 0x12: return 0x900;
                            case 0x13: return 0xA00;
                            case 0x14: return 0xB00;
                            case 0x15: return 0xC00;
                            case 0x16: return 0xD00;
                            default:
                                offs = static_cast<uint16_t>(reader.read_bit() | (offs << 1));
                                if (offs >= 0x2E) {
                                    return static_cast<uint16_t>((offs & 0x1f) << 8);
                                }
                        }
                }
        }
    }
}

} // anonymous namespace

pklite_decompressor::pklite_decompressor(uint16_t h_pklite_info, uint16_t header_size)
    : h_pklite_info_(h_pklite_info), header_size_(header_size) {}

pklite_decompressor::pklite_params
pklite_decompressor::read_parameters(std::span<const uint8_t> data) {
    pklite_params params{};

    // Helper to read bytes at offset (relative to header_size_)
    auto read_u8 = [&](size_t offset) -> uint32_t {
        size_t pos = header_size_ + offset;
        if (pos >= data.size()) return 0;
        return data[pos];
    };

    auto read_u16 = [&](size_t offset) -> uint32_t {
        return read_u8(offset) | (read_u8(offset + 1) << 8);
    };

    // Extract flags from h_pklite_info
    params.use_xor = (h_pklite_info_ & 0x1000) != 0;
    params.large_compression = (h_pklite_info_ & 0x2000) != 0;

    uint16_t info_lower = h_pklite_info_ & 0xFFF;

    // Handle different PKLITE versions based on h_pklite_info patterns
    // This follows the legacy code's parameter extraction logic

    if (h_pklite_info_ == 0x100 || h_pklite_info_ == 0x103 ||
        h_pklite_info_ == 0x1103 || h_pklite_info_ == 0x2103 ||
        h_pklite_info_ == 0x3103 || h_pklite_info_ == 0x105 ||
        h_pklite_info_ == 0x2105) {

        params.decomp_size = (read_u8(1) << 4) + (read_u8(2) << 12);
        params.compressed_size = (read_u8(4) << 4) + (read_u8(5) << 12);
        params.decompressor_size = (read_u8(0x21) << 1) + (read_u8(0x22) << 9);
        params.decompressor_size += read_u8(0x27) + (read_u8(0x28) << 8);

        if (h_pklite_info_ == 0x1103) {
            params.data_offset = 0x1E0;
        } else if (h_pklite_info_ == 0x2103 || h_pklite_info_ == 0x2105) {
            params.data_offset = 0x290;
        } else if (h_pklite_info_ == 0x3103) {
            params.data_offset = 0x2A0;
        } else {
            params.data_offset = 0x1D0;
        }
    }
    else if (h_pklite_info_ == 0x210A) {
        params.decomp_size = (read_u8(1) << 4) + (read_u8(2) << 12) + 0x100;
        params.compressed_size = (read_u8(4) << 4) + (read_u8(5) << 12);
        params.decompressor_size = (read_u8(0x37) << 1) + (read_u8(0x38) << 9);
        params.decompressor_size += read_u8(0x3C) + (read_u8(0x3D) << 8);
        params.data_offset = 0x290;
    }
    else if (info_lower == 0x10C || info_lower == 0x10D) {
        params.decomp_size = (read_u8(1) << 4) + (read_u8(2) << 12) + 0x100;
        params.compressed_size = (read_u8(4) << 4) + (read_u8(5) << 12);
        params.decompressor_size = (read_u8(0x1D) << 1) + (read_u8(0x1E) << 9);
        params.decompressor_size += read_u8(0x23) + (read_u8(0x24) << 8);

        if ((h_pklite_info_ & 0x2000) != 0 || (h_pklite_info_ & 0x3000) != 0) {
            params.data_offset = 0x290;
        } else if ((h_pklite_info_ & 0x1000) != 0) {
            params.data_offset = 0x1E0;
        } else {
            params.data_offset = 0x1D0;
        }
    }
    else if (info_lower == 0x10E || info_lower == 0x10F) {
        // Check for SYS file marker
        uint32_t type = read_u8(0);
        if (type == 0xEB && info_lower == 0x10F) {
            // SYS file - adjust header
            // Note: would need to handle this properly
        }

        params.decomp_size = (read_u8(1) << 4) + (read_u8(2) << 12) + 0x100;
        params.compressed_size = (read_u8(4) << 4) + (read_u8(5) << 12);
        params.decompressor_size = (read_u8(0x37) << 1) + (read_u8(0x38) << 9);
        params.decompressor_size += read_u8(0x3D) + (read_u8(0x3E) << 8);

        if ((h_pklite_info_ & 0x2000) != 0) {
            params.data_offset = 0x290;
        } else {
            params.data_offset = 0x1D0;
        }
    }
    else if ((h_pklite_info_ & 0xF0FF) == 0x10E || (h_pklite_info_ & 0xF0FF) == 0x10F) {
        params.decomp_size = (read_u8(1) << 4) + (read_u8(2) << 12) + 0x100;
        params.compressed_size = (read_u8(4) << 4) + (read_u8(5) << 12);
        params.decompressor_size = (read_u8(0x35) << 1) + (read_u8(0x36) << 9);
        params.decompressor_size += read_u8(0x38) + (read_u8(0x39) << 8);

        if ((h_pklite_info_ & 0x3000) != 0) {
            params.data_offset = 0x2C0;
        } else {
            params.data_offset = 0x200;
        }
    }
    else if (h_pklite_info_ == 0x210E) {
        params.decomp_size = (read_u8(1) << 4) + (read_u8(2) << 12) + 0x100;
        params.compressed_size = (read_u8(4) << 4) + (read_u8(5) << 12);
        params.decompressor_size = (read_u8(0x36) << 1) + (read_u8(0x37) << 9);
        params.decompressor_size += read_u8(0x3C) + (read_u8(0x3D) << 8);
        params.data_offset = 0x290;
    }
    else if (info_lower == 0x114) {
        uint32_t type = read_u8(0);
        if (type != 0x50) {
            params.decomp_size = (read_u8(1) << 4) + (read_u8(2) << 12) + 0x100;
            params.compressed_size = read_u8(4) + (read_u8(5) << 8);
            params.decompressor_size = (read_u8(0x34) << 1) + (read_u8(0x35) << 9);

            uint32_t temp = read_u8(0x37) + (read_u8(0x38) << 8);
            temp = temp + 0xFF10;
            temp = temp + 0xFFFF0000;
            temp = temp & 0xFFFFFFF0;
            params.data_offset = temp;
        }
    }
    else if (info_lower == 0x132) {
        params.decomp_size = (read_u8(2) << 4) + (read_u8(3) << 12) + 0x100;
        params.compressed_size = read_u8(5) + (read_u8(6) << 8);
        params.decompressor_size = (read_u8(0x48) << 1) + (read_u8(0x49) << 9);

        uint32_t temp = params.decompressor_size << 1;
        uint32_t lo = temp & 0xFFFF;
        if ((temp & 0xFFFF0000) == 0 && (lo == 0x0E || lo == 0x13F)) {
            params.uncompressed_region = true;
        }

        params.decompressor_size += 0x62;
        params.decompressor_size = params.decompressor_size & 0xFFFFFFF0;
        params.data_offset = params.decompressor_size;
    }
    else {
        // Fallback for unknown versions
        params.decomp_size = 0x10000;
        params.data_offset = 0x1D0;
    }

    return params;
}

decompression_result pklite_decompressor::decompress(std::span<const uint8_t> compressed_data) {
    decompression_result result;

    try {
        pklite_params params = read_parameters(compressed_data);

        bit_reader reader(compressed_data);
        // data_offset is relative to start of code section (after MZ header)
        reader.seek(header_size_ + params.data_offset);

        std::vector<uint8_t> decompressed;
        decompressed.reserve(params.decomp_size);

        // Choose length code adjustment function based on compression model
        auto adjust_length_code = params.large_compression
            ? adjust_length_code_large
            : adjust_length_code_standard;

        // Main decompression loop
        while (decompressed.size() < params.decomp_size) {
            uint8_t bit = reader.read_bit();

            if (bit == 0) {
                // Literal byte
                uint8_t byte = reader.read_byte();
                if (params.use_xor) {
                    byte ^= reader.bit_count();
                }
                decompressed.push_back(byte);
            } else {
                // Back-reference (LZ77-style)
                uint16_t length_code = reader.read_bit();
                length_code = static_cast<uint16_t>(reader.read_bit() | (length_code << 1));
                length_code = static_cast<uint16_t>(reader.read_bit() | (length_code << 1));

                adjust_length_code(length_code, reader, params.uncompressed_region);

                if (length_code == 0xFFFF) {
                    // End marker
                    break;
                }

                if (length_code == 0xFFFD) {
                    throw std::runtime_error("PKLITE: uncompressed region not implemented");
                }

                if (length_code != 0xFFFE) {
                    // Get offset for back-reference
                    uint16_t base_offset = 0;
                    if (length_code != 2) {
                        base_offset = get_base_offset(reader);
                    }
                    base_offset = static_cast<uint16_t>(base_offset + reader.read_byte());

                    // Copy from earlier in the decompressed stream
                    if (base_offset == 0 || base_offset > decompressed.size()) {
                        throw std::runtime_error("PKLITE: invalid back-reference offset: " +
                            std::to_string(base_offset) + " > " + std::to_string(decompressed.size()));
                    }

                    size_t src_pos = decompressed.size() - base_offset;

                    // Handle overlapping copies (source and destination can overlap)
                    // Must copy byte-by-byte to handle run-length encoding correctly
                    for (uint16_t i = 0; i < length_code; i++) {
                        if (src_pos + i >= decompressed.size()) {
                            // This can happen with run-length encoding where we repeat recent bytes
                            // Copy from the beginning of the back-reference pattern
                            decompressed.push_back(decompressed[src_pos + (i % base_offset)]);
                        } else {
                            decompressed.push_back(decompressed[src_pos + i]);
                        }
                    }
                }
            }
        }

        result.code = std::move(decompressed);

        // Parse relocations and metadata from end of compressed stream
        // The reader is now positioned after compressed data

        // Parse relocations based on h_pklite_info format
        if ((h_pklite_info_ & 0x1000) == 0) {
            // Standard relocation format
            while (true) {
                uint8_t count = reader.read_byte();
                if (count == 0) break;

                uint16_t segment = reader.read_word();

                for (uint8_t i = 0; i < count; i++) {
                    uint16_t offset = reader.read_word();
                    result.relocations.emplace_back(segment, offset);
                }
            }
        } else {
            // Large executable relocation format
            uint16_t segment = 0;
            while (true) {
                uint16_t count = reader.read_word();
                if (count == 0xFFFF) break;

                if (count != 0) {
                    for (uint16_t i = 0; i < count; i++) {
                        uint16_t offset = reader.read_word();
                        result.relocations.emplace_back(segment, offset);
                    }
                }
                segment += 0x0FFF;
            }
        }

        // Read initial register values and metadata
        result.initial_ss = reader.read_word();
        result.initial_sp = reader.read_word();
        result.initial_cs = reader.read_word();
        result.initial_ip = 0;  // PKLITE always sets IP to 0

        // Calculate min_extra_paragraphs
        uint32_t extra_bytes = (params.decomp_size > decompressed.size())
            ? (params.decomp_size - static_cast<uint32_t>(decompressed.size()))
            : 0;
        result.min_extra_paragraphs = static_cast<uint16_t>((extra_bytes + 0x0F) >> 4);

        // Read checksum
        result.checksum = reader.read_word();

        // Store h_pklite_info in extra header (for compatibility)
        uint8_t info_lo = h_pklite_info_ & 0xFF;
        uint8_t info_hi = (h_pklite_info_ >> 8) & 0xFF;
        result.extra_header.push_back(info_lo);
        result.extra_header.push_back(info_hi);

    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("PKLITE decompression failed: ") + e.what());
    }

    return result;
}

} // namespace libexe
