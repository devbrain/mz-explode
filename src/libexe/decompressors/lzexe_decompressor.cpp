// LZEXE decompressor implementation
// Based on LZEXE 0.90 and 0.91 decompression algorithms

#include <libexe/decompressors/lzexe.hpp>
#include "bit_reader.hpp"
#include <stdexcept>
#include <cstring>
#include <algorithm>

namespace libexe {
    lzexe_decompressor::lzexe_decompressor(lzexe_version version, uint16_t header_size)
        : version_(version), header_size_(header_size) {
    }

    lzexe_decompressor::lzexe_params lzexe_decompressor::read_parameters(
        std::span <const uint8_t> data) const {
        lzexe_params params{};

        // Extract initial CS and header size from MZ header to locate LZEXE header
        if (data.size() < 0x18) {
            throw std::runtime_error("LZEXE: file too small for MZ header");
        }

        uint16_t initial_cs = static_cast<uint16_t>(data[0x16] | (data[0x17] << 8));

        // LZEXE header is at (HEADER_SIZE_PARA + INITIAL_CS) << 4
        uint32_t header_pos = static_cast<uint32_t>((header_size_ / 16 + initial_cs)) << 4;

        if (data.size() < header_pos + 16) {
            throw std::runtime_error("LZEXE: file too small for LZEXE header");
        }

        // Read LZEXE header (8 words, little-endian)
        params.initial_ip = static_cast<uint16_t>(data[header_pos + 0] | (data[header_pos + 1] << 8));
        params.initial_cs = static_cast<uint16_t>(data[header_pos + 2] | (data[header_pos + 3] << 8));
        params.initial_sp = static_cast<uint16_t>(data[header_pos + 4] | (data[header_pos + 5] << 8));
        params.initial_ss = static_cast<uint16_t>(data[header_pos + 6] | (data[header_pos + 7] << 8));
        params.compressed_size = static_cast<uint16_t>(data[header_pos + 8] | (data[header_pos + 9] << 8));
        params.inc_size = static_cast<uint16_t>(data[header_pos + 10] | (data[header_pos + 11] << 8));
        params.decompressor_size = static_cast<uint16_t>(data[header_pos + 12] | (data[header_pos + 13] << 8));
        params.checksum = static_cast<uint16_t>(data[header_pos + 14] | (data[header_pos + 15] << 8));

        // Calculate offsets based on version
        if (version_ == lzexe_version::V090) {
            params.reloc_offset = header_pos + 0x19D;
        } else {
            params.reloc_offset = header_pos + 0x158;
        }

        // Code offset = (INITIAL_CS - COMPRESSED_SIZE + HEADER_SIZE_PARA) << 4
        uint16_t mz_initial_cs = static_cast<uint16_t>(data[0x16] | (data[0x17] << 8));
        uint16_t header_size_para = header_size_ / 16;
        params.code_offset = static_cast <uint32_t>(
                                 mz_initial_cs - params.compressed_size + header_size_para) << 4;

        return params;
    }

    void lzexe_decompressor::parse_relocations_v090(
        std::span <const uint8_t> data, uint32_t offset, decompression_result& result) {
        bit_reader reader(data);
        reader.seek(offset);

        int16_t seg = 0;
        do {
            uint16_t count = reader.read_word();

            for (int i = 0; i < count; i++) {
                uint16_t offs = reader.read_word();
                result.relocations.emplace_back(static_cast <uint16_t>(seg), offs);
            }

            seg = static_cast <int16_t>(seg + 0x1000);
        }
        while (seg != 0);
    }

    void lzexe_decompressor::parse_relocations_v091(
        std::span <const uint8_t> data, uint32_t offset, decompression_result& result) {
        bit_reader reader(data);
        reader.seek(offset);

        int16_t seg = 0;
        int16_t offs = 0;

        while (true) {
            uint8_t span_byte = reader.read_byte();
            int16_t span = static_cast <int16_t>(span_byte & 0xFF);

            if (span == 0) {
                span = static_cast<int16_t>(reader.read_word());

                if (span == 0) {
                    seg = static_cast <int16_t>(seg + 0x0FFF);
                    continue;
                } else if (span == 1) {
                    break; // End of relocations
                }
            }

            offs = static_cast <int16_t>(offs + span);
            seg = static_cast <int16_t>(seg + static_cast <int16_t>((offs & ~0x0F) >> 4));
            offs &= 0x0F;

            result.relocations.emplace_back(static_cast <uint16_t>(seg),
                                            static_cast <uint16_t>(offs));
        }
    }

    decompression_result lzexe_decompressor::decompress(std::span <const uint8_t> compressed_data) {
        decompression_result result;

        // Read parameters
        lzexe_params params = read_parameters(compressed_data);

        // Set metadata from LZEXE header
        result.initial_ip = params.initial_ip;
        result.initial_cs = params.initial_cs;
        result.initial_sp = params.initial_sp;
        result.initial_ss = params.initial_ss;

        // Checksum comes from ORIGINAL MZ header, not LZEXE header
        // LZEXE header's checksum is for decompressor validation only
        result.checksum = static_cast<uint16_t>(compressed_data[0x12] | (compressed_data[0x13] << 8));

        // Compute min_extra_paragraphs from original MZ header
        // Legacy: oexe[MIN_MEM_PARA] = m_exe_file[MIN_MEM_PARA] - delta
        // where delta = eINC_SIZE + ((eDECOMPRESSOR_SIZE + 15) >> 4) + 9
        uint16_t original_min_mem = static_cast<uint16_t>(compressed_data[0x0A] | (compressed_data[0x0B] << 8));
        uint16_t original_max_mem = static_cast<uint16_t>(compressed_data[0x0C] | (compressed_data[0x0D] << 8));

        if (original_max_mem != 0) {
            int32_t delta = params.inc_size + ((params.decompressor_size + 15) >> 4) + 9;
            result.min_extra_paragraphs = static_cast <uint16_t>(original_min_mem - delta);
        } else {
            result.min_extra_paragraphs = original_min_mem;
        }

        // Parse relocations
        if (version_ == lzexe_version::V090) {
            parse_relocations_v090(compressed_data, params.reloc_offset, result);
        } else {
            parse_relocations_v091(compressed_data, params.reloc_offset, result);
        }

        // Decompress code
        bit_reader reader(compressed_data);
        reader.seek(params.code_offset);

        // Decompression buffer (0x4500 bytes as in original algorithm)
        std::vector <uint8_t> buffer(0x4500);
        uint8_t* p = buffer.data();

        while (true) {
            // Flush buffer when it reaches 0x4000 bytes
            if (p - buffer.data() >= 0x4000) {
                size_t copy_size = 0x2000;
                result.code.insert(result.code.end(),
                                   buffer.data(),
                                   buffer.data() + copy_size);
                p -= copy_size;
                std::memmove(buffer.data(), buffer.data() + copy_size,
                             static_cast <size_t>(p - buffer.data()));
            }

            // Read control bit
            if (reader.read_bit()) {
                // Literal byte
                *p++ = reader.read_byte();
                continue;
            }

            int16_t len = 0;
            int16_t span = 0;

            if (!reader.read_bit()) {
                // Short match: 2 bits for length (2-5), 1 byte for offset
                len = static_cast <int16_t>(reader.read_bit() << 1);
                len = static_cast <int16_t>(len | reader.read_bit());
                len = static_cast <int16_t>(len + 2);
                span = static_cast <int16_t>(
                    (static_cast <uint16_t>(reader.read_byte()) & 0xFFFF) | 0xFF00);
            } else {
                // Long match: variable length encoding
                uint8_t span_low = reader.read_byte();
                uint8_t len_byte = reader.read_byte();

                span = static_cast <int16_t>(span_low);
                span = static_cast <int16_t>(
                    span | static_cast <int16_t>(((len_byte & ~0x07) << 5) | 0xE000));

                len = static_cast <int16_t>((len_byte & 0x07) + 2);

                if (len == 2) {
                    len = static_cast <int16_t>(reader.read_byte() & 0xFF);

                    if (len == 0) {
                        break; // End of compressed data
                    }
                    if (len == 1) {
                        continue; // Skip this iteration
                    }

                    len++;
                }
            }

            // Copy back-reference
            for (; len > 0; len--, p++) {
                *p = *(p + span);
            }
        }

        // Flush remaining buffer
        if (p != buffer.data()) {
            auto remaining = static_cast <size_t>(p - buffer.data());
            result.code.insert(result.code.end(),
                               buffer.data(),
                               buffer.data() + remaining);
        }

        return result;
    }
} // namespace libexe
