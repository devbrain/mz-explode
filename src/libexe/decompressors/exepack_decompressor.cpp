// EXEPACK decompressor implementation
// Based on exepack-1.4.0 by David Fifield (https://www.bamsoftware.com/software/exepack/)
// Algorithm: Backward decompression with FILL and COPY commands

#include <libexe/decompressors/exepack.hpp>
#include <stdexcept>
#include <cstring>
#include <algorithm>

namespace libexe {
    exepack_decompressor::exepack_decompressor(uint16_t header_size)
        : header_size_(header_size) {
    }

    // Skip up to 15 bytes of 0xff padding
    size_t exepack_decompressor::unpad(std::span <const uint8_t> buf, size_t pos) {
        // The compressed data may have up to 15 bytes of 0xff padding at the end
        // Skip backwards over these bytes
        for (size_t i = 0; i < 15 && pos > 0; i++) {
            if (pos == 0 || buf[pos - 1] != 0xff) {
                break;
            }
            pos--;
        }
        return pos;
    }

    exepack_decompressor::exepack_params exepack_decompressor::read_parameters(
        std::span <const uint8_t> data) {
        exepack_params params{};

        // Read MZ header to find code section
        if (data.size() < 0x1C) {
            throw std::runtime_error("EXEPACK: file too small for MZ header");
        }

        const uint16_t num_pages = data[0x04] | (data[0x05] << 8);
        const uint16_t bytes_in_last_page = data[0x02] | (data[0x03] << 8);
        const uint16_t header_paragraphs = data[0x08] | (data[0x09] << 8);

        // Calculate file data range
        const uint32_t file_start = header_paragraphs * 16;
        uint32_t file_end = num_pages * 512;
        if (bytes_in_last_page) {
            file_end -= (512 - bytes_in_last_page);
        }

        // Read initial CS:IP to find decompressor stub
        const uint16_t initial_ip = data[0x14] | (data[0x15] << 8);
        const uint16_t initial_cs = data[0x16] | (data[0x17] << 8);

        // EXEPACK header is at CS:0000 (beginning of code segment)
        uint32_t header_offset = file_start + (initial_cs * 16);

        if (data.size() < header_offset + 16) {
            throw std::runtime_error("EXEPACK: file too small for EXEPACK header");
        }

        // Read EXEPACK header (can be 16 or 18 bytes)
        const uint8_t* hdr = data.data() + header_offset;

        // Determine header variant by checking signature location
        bool uses_skip_len = false;
        if (data.size() >= header_offset + 18 &&
            hdr[16] == 0x52 && hdr[17] == 0x42) {
            // 18-byte header (with skip_len)
            uses_skip_len = true;
        } else if (hdr[14] == 0x52 && hdr[15] == 0x42) {
            // 16-byte header (without skip_len)
            uses_skip_len = false;
        } else {
            throw std::runtime_error("EXEPACK: invalid signature (expected 'RB')");
        }

        params.header.real_ip = hdr[0] | (hdr[1] << 8);
        params.header.real_cs = hdr[2] | (hdr[3] << 8);
        params.header.mem_start = hdr[4] | (hdr[5] << 8); // Ignored
        params.header.exepack_size = hdr[6] | (hdr[7] << 8);
        params.header.real_sp = hdr[8] | (hdr[9] << 8);
        params.header.real_ss = hdr[10] | (hdr[11] << 8);
        params.header.dest_len = hdr[12] | (hdr[13] << 8);

        if (uses_skip_len) {
            params.header.skip_len = hdr[14] | (hdr[15] << 8);
            params.header.signature = hdr[16] | (hdr[17] << 8);
        } else {
            params.header.skip_len = 1; // Default value
            params.header.signature = hdr[14] | (hdr[15] << 8);
        }

        // Calculate compression parameters
        params.exepack_header_offset = header_offset;
        params.exepack_header_len = initial_ip; // Header length is CS:IP offset

        // Compressed data is from file_start to CS:0000
        // skip_len is 1-based: skip_len=1 means 0 paragraphs of padding
        size_t skip_padding = 0;
        if (params.header.skip_len > 0) {
            skip_padding = (params.header.skip_len - 1) * 16;
        }

        // Compressed data length (from start of code to CS:0000, minus skip padding)
        size_t compressed_with_padding = initial_cs * 16; // Offset to CS:0000
        if (compressed_with_padding < skip_padding) {
            throw std::runtime_error("EXEPACK: invalid skip_len");
        }
        params.compressed_len = compressed_with_padding - skip_padding;

        // Uncompressed length in bytes (dest_len is in paragraphs, minus skip padding)
        size_t uncompressed_with_padding = params.header.dest_len * 16;
        if (uncompressed_with_padding < skip_padding) {
            throw std::runtime_error("EXEPACK: invalid dest_len");
        }
        params.uncompressed_len = uncompressed_with_padding - skip_padding;

        return params;
    }

    // Core decompression algorithm - works backwards
    void exepack_decompressor::decompress_data(
        std::vector <uint8_t>& buf,
        size_t compressed_len,
        size_t uncompressed_len) {
        size_t src = compressed_len;
        size_t dst = uncompressed_len;

        // Expand buffer if needed
        if (dst > buf.size()) {
            buf.resize(dst, 0);
        }

        // Skip over 0xff padding
        src = unpad(buf, src);

        // Backward decompression loop
        while (true) {
            // Read command byte (at src-1)
            if (src < 1) {
                throw std::runtime_error("EXEPACK: source underflow reading command");
            }
            src--;
            uint8_t command = buf[src];

            // Read 16-bit length (little-endian, at src-2)
            if (src < 2) {
                throw std::runtime_error("EXEPACK: source underflow reading length");
            }
            src -= 2;
            uint16_t length = buf[src] | (buf[src + 1] << 8);

            // Process command (mask off the 0x01 final flag)
            switch (command & 0xfe) {
                case 0xb0: {
                    // FILL command
                    // Read fill byte
                    if (src < 1) {
                        throw std::runtime_error("EXEPACK: source underflow in FILL");
                    }
                    src--;
                    uint8_t fill_byte = buf[src];

                    // Fill destination
                    if (dst < length) {
                        throw std::runtime_error("EXEPACK: destination underflow in FILL");
                    }
                    dst -= length;
                    std::fill(buf.begin() + dst, buf.begin() + dst + length, fill_byte);
                    break;
                }

                case 0xb2: {
                    // COPY command
                    // Copy from source to destination
                    if (src < length) {
                        throw std::runtime_error("EXEPACK: source underflow in COPY");
                    }
                    if (dst < length) {
                        throw std::runtime_error("EXEPACK: destination underflow in COPY");
                    }

                    src -= length;
                    dst -= length;

                    // Copy backwards to match reference implementation
                    for (size_t i = 0; i < length; i++) {
                        buf[dst + length - i - 1] = buf[src + length - i - 1];
                    }
                    break;
                }

                default:
                    throw std::runtime_error("EXEPACK: unknown command byte 0x" +
                                             std::to_string(command));
            }

            // Check for final command (bit 0x01 set)
            if (command & 0x01) {
                break;
            }
        }

        // Check for gap (like reference implementation)
        // dst should have reached at least compressed_len
        if (compressed_len < dst) {
            throw std::runtime_error("EXEPACK: decompression left a gap (dst=" +
                                     std::to_string(dst) + ", compressed_len=" + std::to_string(compressed_len) + ")");
        }

        // Truncate to final uncompressed size
        buf.resize(uncompressed_len);
    }

    // Locate the end of the EXEPACK decompressor stub by pattern matching
    // Returns the offset immediately after the stub, or 0 if not found
    size_t exepack_decompressor::locate_stub_end(std::span<const uint8_t> stub) {
        // EXEPACK stubs end with: int 0x21; mov ax, 0x4cff; int 0x21
        // Followed by 22-byte error message (typically "Packed file is corrupt")
        static const uint8_t SUFFIX[] = {0xCD, 0x21, 0xB8, 0xFF, 0x4C, 0xCD, 0x21};
        static constexpr size_t SUFFIX_LEN = sizeof(SUFFIX);
        static constexpr size_t ERROR_MSG_LEN = 22;

        // Search for the suffix pattern
        if (stub.size() < SUFFIX_LEN + ERROR_MSG_LEN) {
            return 0;
        }

        for (size_t i = 0; i <= stub.size() - SUFFIX_LEN - ERROR_MSG_LEN; i++) {
            if (std::memcmp(stub.data() + i, SUFFIX, SUFFIX_LEN) == 0) {
                return i + SUFFIX_LEN + ERROR_MSG_LEN;
            }
        }

        return 0;  // Stub end not found
    }

    // Parse packed EXEPACK relocation table
    // Format: For each of 16 segments (0x0000, 0x1000, 0x2000, ..., 0xF000):
    //   [uint16_le: count] followed by [count] uint16_le offsets
    std::vector<std::pair<uint16_t, uint16_t>>
    exepack_decompressor::parse_packed_relocations(std::span<const uint8_t> reloc_data) {
        std::vector<std::pair<uint16_t, uint16_t>> relocations;
        size_t pos = 0;

        // Process 16 segments (0x0000, 0x1000, 0x2000, ..., 0xF000)
        for (uint16_t segment_idx = 0; segment_idx < 16; segment_idx++) {
            if (pos + 2 > reloc_data.size()) {
                throw std::runtime_error("EXEPACK: relocation table truncated");
            }

            // Read count of relocations for this segment
            uint16_t count = reloc_data[pos] | (reloc_data[pos + 1] << 8);
            pos += 2;

            // Read each offset for this segment
            for (uint16_t i = 0; i < count; i++) {
                if (pos + 2 > reloc_data.size()) {
                    throw std::runtime_error("EXEPACK: relocation table truncated");
                }

                uint16_t offset = reloc_data[pos] | (reloc_data[pos + 1] << 8);
                pos += 2;

                // segment = segment_idx * 0x1000
                uint16_t segment = segment_idx * 0x1000;
                relocations.emplace_back(segment, offset);
            }
        }

        return relocations;
    }

    decompression_result exepack_decompressor::decompress(
        std::span <const uint8_t> compressed_data) {
        decompression_result result;

        // Read parameters from EXEPACK header
        exepack_params params = read_parameters(compressed_data);

        // Set register values from EXEPACK header
        result.initial_ip = params.header.real_ip;
        result.initial_cs = params.header.real_cs;
        result.initial_sp = params.header.real_sp;
        result.initial_ss = params.header.real_ss;

        // Checksum: Set to 0 (EXEPACK doesn't preserve checksums)
        result.checksum = 0;

        // Read original header fields
        uint16_t original_min_mem = compressed_data[0x0A] | (compressed_data[0x0B] << 8);
        uint16_t original_max_mem = compressed_data[0x0C] | (compressed_data[0x0D] << 8);
        uint16_t original_header_para = compressed_data[0x08] | (compressed_data[0x09] << 8);

        // Preserve header size and max_mem from original
        result.header_paragraphs = original_header_para;
        result.max_extra_paragraphs = original_max_mem;

        // Parse EXEPACK relocations from stub area
        // The stub starts at CS:IP and ends with a specific pattern,
        // followed immediately by the packed relocation table

        // Extract compressed data region
        // Compressed data starts at beginning of code section (file_start)
        uint16_t header_paragraphs = compressed_data[0x08] | (compressed_data[0x09] << 8);
        uint32_t file_start = header_paragraphs * 16;
        uint32_t compressed_start = file_start;

        if (compressed_data.size() < compressed_start + params.compressed_len) {
            throw std::runtime_error("EXEPACK: compressed data truncated");
        }

        // Copy compressed data to working buffer
        std::vector <uint8_t> work_buffer(params.compressed_len);
        std::memcpy(work_buffer.data(),
                    compressed_data.data() + compressed_start,
                    params.compressed_len);

        // Decompress
        decompress_data(work_buffer, params.compressed_len, params.uncompressed_len);

        // Move decompressed data to result
        result.code = std::move(work_buffer);

        // Calculate min_extra_paragraphs
        // Formula: (paras(compressed_body) + original_min) - paras(decompressed_body)
        auto paras = [](size_t n) -> size_t { return (n + 15) / 16; };

        // Get compressed body length (from file_start to file_end)
        uint16_t num_pages = compressed_data[0x04] | (compressed_data[0x05] << 8);
        uint16_t bytes_in_last = compressed_data[0x02] | (compressed_data[0x03] << 8);
        size_t file_end = num_pages * 512;
        if (bytes_in_last) {
            file_end -= (512 - bytes_in_last);
        }
        size_t compressed_body_len = file_end - compressed_start;

        size_t input_total_paras = paras(compressed_body_len) + original_min_mem;
        size_t output_body_paras = paras(result.code.size());

        if (input_total_paras >= output_body_paras) {
            result.min_extra_paragraphs = static_cast <uint16_t>(input_total_paras - output_body_paras);
        } else {
            result.min_extra_paragraphs = 0;
        }

        // Extract the stub and relocation table
        // The stub starts at the EXEPACK header offset + header length (CS:IP)
        // It extends for exepack_size bytes (minus the header length already read)
        uint32_t stub_start = params.exepack_header_offset + params.exepack_header_len;
        size_t stub_and_relocs_len = static_cast<size_t>(params.header.exepack_size)
                                     - params.exepack_header_len;

        if (compressed_data.size() < stub_start + stub_and_relocs_len) {
            throw std::runtime_error("EXEPACK: stub area truncated");
        }

        std::span<const uint8_t> stub_and_relocs(
            compressed_data.data() + stub_start,
            stub_and_relocs_len
        );

        // Locate where the stub ends
        size_t stub_len = locate_stub_end(stub_and_relocs);
        if (stub_len == 0 || stub_len > stub_and_relocs.size()) {
            // Unknown stub format - can't parse relocations
            // Leave relocations empty (best effort)
            return result;
        }

        // Parse the packed relocation table that follows the stub
        std::span<const uint8_t> reloc_data(
            stub_and_relocs.data() + stub_len,
            stub_and_relocs.size() - stub_len
        );

        result.relocations = parse_packed_relocations(reloc_data);

        return result;
    }
} // namespace libexe
