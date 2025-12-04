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

    // Helper to read uint32_t from specific offset
    auto read_u32_at = [&](size_t offset) -> uint32_t {
        if (offset + 1 >= data.size()) return 0;
        return data[offset] | (data[offset + 1] << 8);
    };

    // Determine parameters based on h_pklite_info
    uint16_t info_lower = h_pklite_info_ & 0xFFF;

    // This is a simplified version - full version would handle all PKLITE variants
    // For now, handle common cases from legacy code

    if (info_lower == 0x10C || info_lower == 0x10D) {
        params.decomp_size = (read_u32_at(1) << 4) + (read_u32_at(2) << 12) + 0x100;
        params.compressed_size = (read_u32_at(4) << 4) + (read_u32_at(5) << 12);
        params.decompressor_size = (read_u32_at(0x1D) << 1) + (read_u32_at(0x1E) << 9);
        params.decompressor_size += read_u32_at(0x23) + (read_u32_at(0x24) << 8);

        if ((h_pklite_info_ & 0x2000) != 0) {
            params.data_offset = 0x290;
        } else {
            params.data_offset = 0x1D0;
        }
    } else {
        // Default for testing - will need full parameter extraction
        params.decomp_size = 0x10000;  // 64KB default
        params.data_offset = 0x1D0;
    }

    params.use_xor = (h_pklite_info_ & 0x1000) != 0;
    params.large_compression = (h_pklite_info_ & 0x2000) != 0;

    return params;
}

decompression_result pklite_decompressor::decompress(std::span<const uint8_t> compressed_data) {
    decompression_result result;

    try {
        pklite_params params = read_parameters(compressed_data);

        bit_reader reader(compressed_data);
        reader.seek(params.data_offset);

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
                    if (base_offset > decompressed.size()) {
                        throw std::runtime_error("PKLITE: invalid back-reference offset");
                    }

                    size_t src_pos = decompressed.size() - base_offset;
                    for (uint16_t i = 0; i < length_code; i++) {
                        decompressed.push_back(decompressed[src_pos + i]);
                    }
                }
            }
        }

        result.code = std::move(decompressed);

        // TODO: Parse relocations and other metadata
        // For now, just return the decompressed code

    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("PKLITE decompression failed: ") + e.what());
    }

    return result;
}

} // namespace libexe
