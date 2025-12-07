// Knowledge Dynamics decompressor implementation
// LZW (Lempel-Ziv-Welch) dictionary-based compression

#include <libexe/decompressors/knowledge_dynamics_decompressor.hpp>
#include <stdexcept>
#include <cstring>
#include <array>

namespace libexe {
    knowledge_dynamics_decompressor::knowledge_dynamics_decompressor(uint16_t header_size)
        : header_size_(header_size) {
    }

    knowledge_dynamics_decompressor::kd_params knowledge_dynamics_decompressor::read_parameters(
        std::span <const uint8_t> data) {
        kd_params params{};

        // Calculate extra_data_start (end of file data)
        if (data.size() < 0x06) {
            throw std::runtime_error("Knowledge Dynamics: file too small for MZ header");
        }

        uint16_t num_pages = data[0x04] | (data[0x05] << 8);
        uint16_t bytes_in_last_page = data[0x02] | (data[0x03] << 8);

        uint32_t extra_data_start = num_pages * 512;
        if (bytes_in_last_page) {
            extra_data_start -= (512 - bytes_in_last_page);
        }

        // Read second MZ header at end of file
        if (data.size() < extra_data_start + 0x25) {
            throw std::runtime_error("Knowledge Dynamics: file too small for embedded header");
        }

        // Parse embedded MZ header
        const uint8_t* inner_header = data.data() + extra_data_start;

        uint16_t inner_header_size_para = inner_header[0x08] | (inner_header[0x09] << 8);
        uint16_t inner_num_pages = inner_header[0x04] | (inner_header[0x05] << 8);
        uint16_t inner_bytes_in_last = inner_header[0x02] | (inner_header[0x03] << 8);

        uint32_t exe_data_start2 = inner_header_size_para * 16;
        uint32_t extra_data_start2 = inner_num_pages * 512;
        if (inner_bytes_in_last) {
            extra_data_start2 -= (512 - inner_bytes_in_last);
        }

        params.expected_size = extra_data_start2 - exe_data_start2;
        params.code_offset = extra_data_start + exe_data_start2;

        // Extract initial register values from embedded header
        params.initial_ip = inner_header[0x14] | (inner_header[0x15] << 8);
        params.initial_cs = inner_header[0x16] | (inner_header[0x17] << 8);
        params.initial_sp = inner_header[0x10] | (inner_header[0x11] << 8);
        params.initial_ss = inner_header[0x0E] | (inner_header[0x0F] << 8);
        params.checksum = inner_header[0x12] | (inner_header[0x13] << 8);
        params.max_mem_para = inner_header[0x0C] | (inner_header[0x0D] << 8);
        params.min_mem_para = (params.expected_size + 0x20) / 64;

        // Read relocations from inner embedded header
        uint16_t num_relocs = inner_header[0x06] | (inner_header[0x07] << 8);
        uint16_t reloc_offset = inner_header[0x18] | (inner_header[0x19] << 8);

        params.relocation_offset = extra_data_start + reloc_offset;
        params.num_relocations = num_relocs;

        return params;
    }

    decompression_result knowledge_dynamics_decompressor::decompress(
        std::span <const uint8_t> compressed_data) {
        decompression_result result;

        // Read parameters
        kd_params params = read_parameters(compressed_data);

        // Set metadata from embedded header
        result.initial_ip = params.initial_ip;
        result.initial_cs = params.initial_cs;
        result.initial_sp = params.initial_sp;
        result.initial_ss = params.initial_ss;
        result.checksum = params.checksum;
        result.min_extra_paragraphs = params.min_mem_para;
        result.max_extra_paragraphs = params.max_mem_para;

        // Parse relocations from inner embedded header
        if (params.num_relocations > 0) {
            uint32_t reloc_pos = params.relocation_offset;
            for (uint16_t i = 0; i < params.num_relocations; i++) {
                if (compressed_data.size() < reloc_pos + 4) {
                    throw std::runtime_error("Knowledge Dynamics: relocation table truncated");
                }

                uint16_t offset = compressed_data[reloc_pos] | (compressed_data[reloc_pos + 1] << 8);
                uint16_t segment = compressed_data[reloc_pos + 2] | (compressed_data[reloc_pos + 3] << 8);
                result.relocations.emplace_back(segment, offset);
                reloc_pos += 4;
            }
        }

        // LZW decompression setup
        constexpr size_t BUFFER_SIZE = 1024;
        constexpr size_t BUFFER_EDGE = BUFFER_SIZE - 3;

        std::array <uint8_t, BUFFER_SIZE> buffer{};

        // Read initial buffer
        if (compressed_data.size() < params.code_offset + BUFFER_SIZE) {
            throw std::runtime_error("Knowledge Dynamics: compressed data truncated");
        }

        std::memcpy(buffer.data(), compressed_data.data() + params.code_offset, BUFFER_SIZE);

        size_t file_pos = params.code_offset + BUFFER_SIZE;
        size_t bit_pos = 0;
        bool reset_hack = false;
        size_t step = 9; // Variable bit width (9-12 bits)

        // Dictionary - LZW tree structure
        std::array <uint16_t, 768 * 16> dict_key{};
        std::array <uint8_t, 768 * 16> dict_val{};
        uint16_t dict_index = 0x0102; // Start populating from 0x0102
        uint16_t dict_range = 0x0200; // Increase step when this is reached

        // Output queue (LZW produces output backwards)
        std::array <uint8_t, 0xFF> queue{};
        size_t queued = 0;

        uint16_t last_index = 0;
        uint8_t last_char = 0;

        constexpr uint16_t keyMask[4] = {
            0x01FF, // 9 bits
            0x03FF, // 10 bits
            0x07FF, // 11 bits
            0x0FFF // 12 bits
        };

        while (true) {
            // Handle dictionary reset
            if (reset_hack) {
                step = 9;
                dict_range = 0x0200;
                dict_index = 0x0102;
            }

            size_t byte_pos = bit_pos / 8;
            size_t bit_offset = bit_pos % 8;

            bit_pos += step; // Advance to next code

            // Refill buffer if needed
            if (byte_pos >= BUFFER_EDGE) {
                size_t bytes_extra = BUFFER_SIZE - byte_pos;
                size_t bytes_left = BUFFER_SIZE - bytes_extra;

                // Move leftover bytes to beginning
                std::memmove(buffer.data(), buffer.data() + bytes_left, bytes_extra);

                // Read more data
                size_t bytes_to_read = std::min(bytes_left,
                                                compressed_data.size() - file_pos);
                if (bytes_to_read > 0) {
                    std::memcpy(buffer.data() + bytes_extra,
                                compressed_data.data() + file_pos,
                                bytes_to_read);
                    file_pos += bytes_to_read;
                }

                // Reset cursor (matching legacy logic exactly)
                bit_pos = bit_offset + step; // Recalculate from bit offset
                byte_pos = 0;

                // On dictionary reset, use byte offset as bit offset (legacy comment)
                if (reset_hack) {
                    bit_offset = bytes_extra;
                }
            }

            // Read variable-width code
            uint32_t big_index =
                (static_cast <uint32_t>(buffer[byte_pos + 2]) << 16) |
                (static_cast <uint32_t>(buffer[byte_pos + 1]) << 8) |
                static_cast <uint32_t>(buffer[byte_pos]);

            big_index >>= bit_offset;
            auto next_index = static_cast <uint16_t>(big_index);

            if (step - 9 >= 4) {
                throw std::runtime_error("Knowledge Dynamics: invalid step value");
            }
            next_index &= keyMask[step - 9];

            // Handle reset hack continuation
            if (reset_hack) {
                last_index = next_index;
                last_char = static_cast <uint8_t>(next_index & 0xFF);
                result.code.push_back(last_char);
                reset_hack = false;
                continue;
            }

            // Check special codes
            if (next_index == 0x0101) {
                // End of file
                break;
            }

            if (next_index == 0x0100) {
                // Reset dictionary
                reset_hack = true;
                continue;
            }

            uint16_t keep_index = next_index;

            // Handle unknown dictionary entry
            if (next_index >= dict_index) {
                next_index = last_index;
                if (queued >= queue.size()) {
                    throw std::runtime_error("Knowledge Dynamics: queue overflow");
                }
                queue[queued++] = last_char;
            }

            // Follow dictionary chain
            while (next_index > 0x00FF) {
                if (queued >= queue.size()) {
                    throw std::runtime_error("Knowledge Dynamics: queue overflow");
                }
                if (next_index >= dict_val.size()) {
                    throw std::runtime_error("Knowledge Dynamics: dictionary overflow");
                }
                queue[queued++] = dict_val[next_index];
                next_index = dict_key[next_index];
            }

            // Final character
            last_char = static_cast <uint8_t>(next_index & 0xFF);
            if (queued >= queue.size()) {
                throw std::runtime_error("Knowledge Dynamics: queue overflow");
            }
            queue[queued++] = last_char;

            // Output queue (in reverse order)
            while (queued > 0) {
                result.code.push_back(queue[--queued]);
            }

            // Add to dictionary
            if (dict_index >= dict_val.size()) {
                throw std::runtime_error("Knowledge Dynamics: dictionary full");
            }
            dict_key[dict_index] = last_index;
            dict_val[dict_index] = last_char;
            dict_index++;

            last_index = keep_index;

            // Increase bit width if dictionary is growing
            if (dict_index >= dict_range && step < 12) {
                step++;
                dict_range *= 2;
            }
        }

        return result;
    }
} // namespace libexe
