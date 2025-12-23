// libexe - Modern executable file analysis library
// Copyright (c) 2024
//
// DIET decompressor implementation
// Based on deark's diet.c by Jason Summers (2023)

#include <libexe/decompressors/diet.hpp>
#include <stdexcept>
#include <vector>
#include <cstring>
#include <algorithm>

namespace libexe {

namespace {

// Maximum decompressed size to prevent memory exhaustion
constexpr size_t MAX_DIET_DCMPR_LEN = 4194304;  // 4MB

// Ring buffer size for LZ77 decompression
constexpr size_t RING_BUFFER_SIZE = 8192;

// Signature bytes for detection
constexpr uint8_t SIG_DLZ[] = {'d', 'l', 'z'};
constexpr uint8_t SIG_9D89[] = {0x9d, 0x89};
constexpr uint8_t SIG_INT21[] = {0xb4, 0x4c, 0xcd, 0x21};
constexpr uint8_t SIG_OLD[] = {0xfd, 0xf3, 0xa5, 0xfc, 0x8b, 0xf7, 0xbf, 0x00};
constexpr uint8_t SIG_8EDB[] = {0x8e, 0xdb, 0x8e, 0xc0, 0x33, 0xf6, 0x33, 0xff, 0xb9};

// Helper to read little-endian uint16
inline uint16_t read_u16le(const uint8_t* ptr) {
    return static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8);
}

// Helper to read little-endian uint32
inline uint32_t read_u32le(const uint8_t* ptr) {
    return static_cast<uint32_t>(ptr[0]) |
           (static_cast<uint32_t>(ptr[1]) << 8) |
           (static_cast<uint32_t>(ptr[2]) << 16) |
           (static_cast<uint32_t>(ptr[3]) << 24);
}

// Helper to compare memory
inline bool mem_eq(const uint8_t* a, const uint8_t* b, size_t len) {
    return std::memcmp(a, b, len) == 0;
}

// Bit reader for DIET's LSB-first bit stream
class diet_bit_reader {
public:
    explicit diet_bit_reader(std::span<const uint8_t> data, size_t start_pos)
        : data_(data), pos_(start_pos), bit_buffer_(0), bits_available_(0) {}

    uint8_t read_bit() {
        if (bits_available_ == 0) {
            refill();
        }
        uint8_t bit = bit_buffer_ & 1;
        bit_buffer_ >>= 1;
        bits_available_--;
        if (bits_available_ == 0) {
            refill();
        }
        return bit;
    }

    uint8_t read_byte() {
        if (pos_ >= data_.size()) {
            throw std::runtime_error("DIET: unexpected end of compressed data");
        }
        return data_[pos_++];
    }

    size_t position() const { return pos_; }
    bool at_end() const { return pos_ >= data_.size(); }

private:
    void refill() {
        if (pos_ + 2 > data_.size()) {
            throw std::runtime_error("DIET: unexpected end of compressed data during refill");
        }
        uint8_t lo = data_[pos_++];
        uint8_t hi = data_[pos_++];
        bit_buffer_ = static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);
        bits_available_ = 16;
    }

    std::span<const uint8_t> data_;
    size_t pos_;
    uint16_t bit_buffer_;
    uint8_t bits_available_;
};

// Read match length using DIET's variable-length encoding
uint32_t read_matchlen(diet_bit_reader& reader) {
    uint32_t nbits_read = 0;

    // Read up to 4 bits, stopping early if we get a 1
    while (nbits_read < 4) {
        uint8_t x = reader.read_bit();
        nbits_read++;
        if (x) {
            return 2 + nbits_read;  // Length 3-6
        }
    }

    // At this point we've read 4 bits, all 0
    uint8_t x1 = reader.read_bit();
    uint8_t x2 = reader.read_bit();

    if (x1 == 1) {
        // Length 7-8
        return 7 + x2;
    }

    if (x2 == 0) {
        // Length 9-16
        uint8_t x3 = reader.read_bit();
        uint8_t x4 = reader.read_bit();
        uint8_t x5 = reader.read_bit();
        return 9 + 4 * static_cast<uint32_t>(x3) + 2 * static_cast<uint32_t>(x4) + x5;
    }

    // Length 17-272 (encoded as single byte + 17)
    uint8_t v = reader.read_byte();
    return 17 + static_cast<uint32_t>(v);
}

} // anonymous namespace

// Static detection function
bool diet_decompressor::detect(std::span<const uint8_t> data,
                                diet_version& version,
                                diet_file_type& file_type,
                                size_t& cmpr_pos,
                                size_t& crc_pos) {
    if (data.size() < 40) {
        return false;
    }

    const uint8_t* ptr = data.data();

    // Check for COM format signatures
    if (ptr[0] == 0xbe) {
        if (data.size() >= 38 && mem_eq(ptr + 35, SIG_DLZ, 3)) {
            if (data.size() >= 25 && mem_eq(ptr + 17, SIG_OLD, 8)) {
                file_type = diet_file_type::COM;
                version = diet_version::V102;
                crc_pos = 35 + 6;
                cmpr_pos = 35 + 11;
                return true;
            }
        }
    }

    if (ptr[0] == 0xbf) {
        if (data.size() >= 25 && mem_eq(ptr + 17, SIG_OLD, 8)) {
            file_type = diet_file_type::COM;
            version = diet_version::V100;
            crc_pos = 35;
            cmpr_pos = 37;
            return true;
        }
    }

    if (ptr[0] == 0xf9) {
        if (data.size() >= 68 && mem_eq(ptr + 65, SIG_DLZ, 3)) {
            if (data.size() >= 12 && mem_eq(ptr + 10, SIG_9D89, 2)) {
                file_type = diet_file_type::COM;
                version = diet_version::V144;
                crc_pos = 65 + 6;
                cmpr_pos = 65 + 11;
                return true;
            }
        }
    }

    // Check for DATA format signatures
    if (ptr[0] == 0xb4) {
        if (mem_eq(ptr, SIG_INT21, 4)) {
            if (mem_eq(ptr + 4, SIG_9D89, 2)) {
                file_type = diet_file_type::DATA;
                if (data.size() >= 9 && mem_eq(ptr + 6, SIG_DLZ, 3)) {
                    version = diet_version::V144;
                    crc_pos = 6 + 6;
                    cmpr_pos = 6 + 11;
                } else {
                    version = diet_version::V100;
                    crc_pos = 6;
                    cmpr_pos = 8;
                }
                return true;
            }
        }
    }

    if (ptr[0] == 0x9d) {
        if (mem_eq(ptr, SIG_9D89, 2)) {
            if (data.size() >= 5 && mem_eq(ptr + 2, SIG_DLZ, 3)) {
                file_type = diet_file_type::DATA;
                version = diet_version::V102;
                crc_pos = 2 + 6;
                cmpr_pos = 2 + 11;
                return true;
            }
        }
    }

    // Check for EXE format
    if ((ptr[0] == 'M' && ptr[1] == 'Z') || (ptr[0] == 'Z' && ptr[1] == 'M')) {
        if (data.size() < 80) {
            return false;
        }

        uint16_t e_cparhdr = read_u16le(ptr + 8);
        size_t codestart = static_cast<size_t>(e_cparhdr) * 16;

        if (codestart < 32 || codestart + 80 > data.size()) {
            return false;
        }

        // Look for the characteristic 8e db 8e... byte pattern
        int64_t sig_pos_rel = 0;

        if (codestart + 77 + 8 <= data.size() && mem_eq(ptr + codestart + 77 - 32, SIG_8EDB, 8)) {
            sig_pos_rel = 77 - 32;
        } else if (codestart + 72 + 8 <= data.size() && mem_eq(ptr + codestart + 72 - 32, SIG_8EDB, 8)) {
            sig_pos_rel = 72 - 32;
        } else if (codestart + 52 + 8 <= data.size() && mem_eq(ptr + codestart + 52 - 32, SIG_8EDB, 8)) {
            sig_pos_rel = 52 - 32;
        } else if (codestart + 55 + 8 <= data.size() && mem_eq(ptr + codestart + 55 - 32, SIG_8EDB, 8)) {
            sig_pos_rel = 55 - 32;
        }

        if (sig_pos_rel == 0) {
            return false;
        }

        file_type = diet_file_type::EXE;

        if (sig_pos_rel == 77 - 32) {
            version = diet_version::V145F;
            size_t dlz_pos = codestart - 32 + 108;
            crc_pos = dlz_pos + 6;
            cmpr_pos = dlz_pos + 11;
            return true;
        }

        if (sig_pos_rel == 72 - 32) {
            version = diet_version::V144;
            size_t dlz_pos = codestart - 32 + 107;
            crc_pos = dlz_pos + 6;
            cmpr_pos = dlz_pos + 11;
            return true;
        }

        if (sig_pos_rel == 52 - 32) {
            version = diet_version::V102;
            size_t dlz_pos = codestart - 32 + 87;
            crc_pos = dlz_pos + 6;
            cmpr_pos = dlz_pos + 11;
            return true;
        }

        if (sig_pos_rel == 55 - 32) {
            version = diet_version::V100;
            crc_pos = 18;
            cmpr_pos = codestart - 32 + 90;
            return true;
        }
    }

    return false;
}

diet_decompressor::diet_decompressor(diet_version version, diet_file_type file_type,
                                     uint16_t header_size)
    : version_(version), file_type_(file_type), header_size_(header_size) {}

diet_decompressor::diet_params
diet_decompressor::read_parameters(std::span<const uint8_t> data) const {
    diet_params params;

    diet_version detected_version;
    diet_file_type detected_type;
    size_t detected_cmpr_pos, detected_crc_pos;

    if (!detect(data, detected_version, detected_type, detected_cmpr_pos, detected_crc_pos)) {
        throw std::runtime_error("DIET: failed to detect format parameters");
    }

    params.cmpr_pos = detected_cmpr_pos;
    params.crc_pos = detected_crc_pos;

    // Read CRC
    if (detected_crc_pos + 2 <= data.size()) {
        params.crc_reported = read_u16le(data.data() + detected_crc_pos);
    }

    // For formats with "dlz" signature, read additional header info
    // The "dlz" signature is 5 bytes before crc_pos (crc_pos = dlz_pos + 6)
    if (detected_version != diet_version::V100 || detected_type != diet_file_type::EXE) {
        size_t dlz_pos = detected_crc_pos - 6;
        params.dlz_pos = dlz_pos;
        params.has_dlz_sig = true;

        if (dlz_pos + 11 <= data.size()) {
            // Flags and compressed length at dlz_pos + 3
            uint8_t flags_and_len = data[dlz_pos + 3];
            params.hdr_flags1 = flags_and_len & 0xf0;
            params.cmpr_len = (static_cast<size_t>(flags_and_len & 0x0f) << 16);
            params.cmpr_len |= read_u16le(data.data() + dlz_pos + 4);

            // Original length at dlz_pos + 8
            uint8_t orig_flags = data[dlz_pos + 8];
            params.orig_len = (static_cast<size_t>(orig_flags & 0xfc) << 14);
            params.hdr_flags2 = orig_flags & 0x03;
            params.orig_len |= read_u16le(data.data() + dlz_pos + 9);
        }
    } else {
        // v1.00 EXE format - read compressed length from offset 32
        params.has_dlz_sig = false;
        if (data.size() >= 36) {
            params.cmpr_len = read_u32le(data.data() + 32) & 0xfffff;
        }
    }

    // For v1.00 DATA format without dlz signature
    if (detected_version == diet_version::V100 && detected_type == diet_file_type::DATA) {
        params.cmpr_len = data.size() - params.cmpr_pos;
    }

    return params;
}

std::vector<uint8_t> diet_decompressor::decompress_lz77(
    std::span<const uint8_t> data, const diet_params& params) const {

    std::vector<uint8_t> output;
    size_t max_output = params.orig_len > 0 ? params.orig_len : MAX_DIET_DCMPR_LEN;
    output.reserve(std::min(max_output, MAX_DIET_DCMPR_LEN));

    // Ring buffer for LZ77 back-references
    std::vector<uint8_t> ringbuf(RING_BUFFER_SIZE, 0);
    size_t ringbuf_pos = 0;

    auto write_byte = [&](uint8_t b) {
        output.push_back(b);
        ringbuf[ringbuf_pos] = b;
        ringbuf_pos = (ringbuf_pos + 1) % RING_BUFFER_SIZE;
    };

    diet_bit_reader reader(data, params.cmpr_pos);

    while (output.size() < max_output) {
        uint8_t x1 = reader.read_bit();

        if (x1) {
            // 1... -> literal byte
            uint8_t b = reader.read_byte();
            write_byte(b);
            continue;
        }

        uint8_t x2 = reader.read_bit();
        uint8_t v = reader.read_byte();

        uint32_t matchpos = 0;
        uint32_t matchlen = 0;

        if (x2 == 0) {
            // 00[v]... -> 2-byte match or special code
            uint8_t a1 = reader.read_bit();

            if (a1) {
                // "Long" two-byte match
                matchlen = 2;
                uint8_t a2 = reader.read_bit();
                uint8_t a3 = reader.read_bit();
                uint8_t a4 = reader.read_bit();
                matchpos = 2303 - (1024 * static_cast<uint32_t>(a2) +
                                   512 * static_cast<uint32_t>(a3) +
                                   256 * static_cast<uint32_t>(a4) + v);
            } else if (v != 0xff) {
                // "Short" two-byte match
                matchlen = 2;
                matchpos = 0xff - static_cast<uint32_t>(v);
            } else {
                // Special code (v == 0xff, a1 == 0)
                uint8_t a2 = reader.read_bit();
                if (a2 == 0) {
                    // 00[FF]00 -> stop code
                    break;
                }
                // 00[FF]01 -> segment refresh (EXE only)
                if (file_type_ == diet_file_type::EXE) {
                    // Segment refresh - continue decompression
                    continue;
                }
                throw std::runtime_error("DIET: unsupported feature in non-EXE file");
            }
        } else {
            // 01[v] -> 3 or more byte match
            uint8_t a1 = reader.read_bit();
            uint8_t a2 = reader.read_bit();

            if (a2) {
                // 01[v]?1
                matchpos = 511 - (256 * static_cast<uint32_t>(a1) + v);
            } else {
                uint8_t a3 = reader.read_bit();
                if (a3) {
                    // 01[v]?01
                    matchpos = 1023 - (256 * static_cast<uint32_t>(a1) + v);
                } else {
                    // 01[v]?00
                    uint8_t a4 = reader.read_bit();
                    uint8_t a5 = reader.read_bit();

                    if (a5) {
                        // 01[v]?00?1
                        matchpos = 2047 - (512 * static_cast<uint32_t>(a1) +
                                           256 * static_cast<uint32_t>(a4) + v);
                    } else {
                        // 01[v]?00?0
                        uint8_t a6 = reader.read_bit();
                        uint8_t a7 = reader.read_bit();

                        if (a7) {
                            // 01[v]?00?0?1
                            matchpos = 4095 - (1024 * static_cast<uint32_t>(a1) +
                                               512 * static_cast<uint32_t>(a4) +
                                               256 * static_cast<uint32_t>(a6) + v);
                        } else {
                            // 01[v]?00?0?0
                            uint8_t a8 = reader.read_bit();
                            matchpos = 8191 - (2048 * static_cast<uint32_t>(a1) +
                                               1024 * static_cast<uint32_t>(a4) +
                                               512 * static_cast<uint32_t>(a6) +
                                               256 * static_cast<uint32_t>(a8) + v);
                        }
                    }
                }
            }

            matchlen = read_matchlen(reader);
        }

        // Copy match from ring buffer
        if (matchlen > 0) {
            // Validate match
            if (matchpos + 1 > output.size()) {
                throw std::runtime_error("DIET: invalid back-reference (before start of data)");
            }

            // Copy from ring buffer
            size_t src_pos = (ringbuf_pos + RING_BUFFER_SIZE - 1 - matchpos) % RING_BUFFER_SIZE;
            for (uint32_t i = 0; i < matchlen; i++) {
                write_byte(ringbuf[src_pos]);
                src_pos = (src_pos + 1) % RING_BUFFER_SIZE;
            }
        }
    }

    return output;
}

void diet_decompressor::reconstruct_exe(
    std::span<const uint8_t> original_data,
    std::span<const uint8_t> decompressed,
    const diet_params& params,
    decompression_result& result) const {

    // For EXE files, the decompressed data contains:
    // 1. The original code (at the beginning, up to mz_pos)
    // 2. The MZ header and relocation table (starting at mz_pos)
    //
    // We need to find the MZ header position and extract:
    // - Original register values
    // - Relocation table

    const uint8_t* ptr = original_data.data();

    // Calculate entry point offset
    size_t entry_offset = 0;
    switch (version_) {
        case diet_version::V100:
        case diet_version::V102:
            entry_offset = 53;
            break;
        case diet_version::V144:
            entry_offset = 73;
            break;
        case diet_version::V145F:
            entry_offset = 26;
            break;
    }

    // Get approximate MZ position in decompressed data
    uint16_t e_cparhdr = read_u16le(ptr + 8);
    size_t entry_point = static_cast<size_t>(e_cparhdr) * 16;

    if (entry_point + entry_offset + 2 > original_data.size()) {
        throw std::runtime_error("DIET: cannot read MZ position parameter");
    }

    uint16_t iparam1 = read_u16le(ptr + entry_point + entry_offset);
    size_t mz_pos_approx = static_cast<size_t>(iparam1) * 16;

    // For v1.02+ with dlz signature, adjust by orig_len mod 16
    size_t mz_pos = mz_pos_approx;
    if (params.has_dlz_sig && (params.hdr_flags1 & 0x20)) {
        mz_pos = mz_pos_approx + (params.orig_len % 16);
    }

    // Validate MZ position
    if (mz_pos + 28 > decompressed.size()) {
        // For v1.00, search for MZ signature
        bool found = false;
        for (size_t i = 0; i < 16 && mz_pos_approx + i + 28 <= decompressed.size(); i++) {
            uint16_t sig = read_u16le(decompressed.data() + mz_pos_approx + i);
            if (sig == 0x5A4D || sig == 0x4D5A) {
                mz_pos = mz_pos_approx + i;
                found = true;
                break;
            }
        }
        if (!found) {
            throw std::runtime_error("DIET: cannot find MZ header in decompressed data");
        }
    }

    // Verify MZ signature
    if (mz_pos + 2 <= decompressed.size()) {
        uint16_t sig = read_u16le(decompressed.data() + mz_pos);
        if (sig != 0x5A4D && sig != 0x4D5A) {
            throw std::runtime_error("DIET: invalid MZ signature in decompressed data");
        }
    }

    // Read MZ header values from decompressed data
    const uint8_t* mz_hdr = decompressed.data() + mz_pos;
    size_t mz_avail = decompressed.size() - mz_pos;

    // Extract header values (with bounds checking)
    auto safe_read_u16 = [&](size_t offset) -> uint16_t {
        if (offset + 2 > mz_avail) return 0;
        return read_u16le(mz_hdr + offset);
    };

    uint16_t e_crlc = safe_read_u16(6);       // Relocation count
    [[maybe_unused]] uint16_t e_cparhdr_new = safe_read_u16(8);
    uint16_t e_ss = safe_read_u16(14);
    uint16_t e_sp = safe_read_u16(16);
    uint16_t e_ip = safe_read_u16(20);
    uint16_t e_cs = safe_read_u16(22);
    uint16_t e_lfarlc = safe_read_u16(24);

    result.initial_ss = e_ss;
    result.initial_sp = e_sp;
    result.initial_ip = e_ip;
    result.initial_cs = e_cs;

    // Calculate relocation table position
    size_t reloc_pos = mz_pos + e_lfarlc;

    // Decode relocation table (DIET uses delta encoding)
    if (e_crlc > 0 && reloc_pos < decompressed.size()) {
        uint16_t seg = 0;
        uint16_t offs = 0;
        size_t pos = reloc_pos;

        for (uint16_t i = 0; i < e_crlc && pos + 2 <= decompressed.size(); i++) {
            uint16_t n = read_u16le(decompressed.data() + pos);
            pos += 2;

            if (n & 0x8000) {
                // Delta encoding: segment stays the same
                if (n >= 0xc000) {
                    offs += n;
                } else {
                    offs = static_cast<uint16_t>(offs + (n - 0x8000));
                }
                offs &= 0xffff;
            } else {
                // Full entry: segment + offset
                seg = n;
                if (pos + 2 <= decompressed.size()) {
                    offs = read_u16le(decompressed.data() + pos);
                    pos += 2;
                }
            }

            result.relocations.emplace_back(seg, offs);
        }
    }

    // The actual code is at the beginning of decompressed data, up to mz_pos
    result.code.assign(decompressed.begin(), decompressed.begin() + static_cast<ptrdiff_t>(mz_pos));
}

decompression_result diet_decompressor::decompress(std::span<const uint8_t> compressed_data) {
    decompression_result result;

    try {
        diet_params params = read_parameters(compressed_data);

        // Check for unsupported features
        if (params.hdr_flags1 & 0x80) {
            throw std::runtime_error("DIET: 'following block' feature not supported");
        }

        // Decompress the LZ77 data
        std::vector<uint8_t> decompressed = decompress_lz77(compressed_data, params);

        if (file_type_ == diet_file_type::EXE && !params.is_com2exe) {
            // Reconstruct EXE file
            reconstruct_exe(compressed_data, decompressed, params, result);
        } else {
            // COM or DATA file - output as-is
            result.code = std::move(decompressed);

            // For COM files, default entry point is 0x100:0x0000
            if (file_type_ == diet_file_type::COM) {
                result.initial_cs = 0;
                result.initial_ip = 0x100;
            }
        }
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("DIET decompression failed: ") + e.what());
    }

    return result;
}

} // namespace libexe
