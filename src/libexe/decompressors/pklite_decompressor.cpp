// libexe - Modern executable file analysis library
// Copyright (c) 2024
//
// PKLITE decompressor using pattern-based version detection
// Based on deark's pklite.c by Jason Summers

#include <libexe/decompressors/pklite.hpp>
#include "bit_reader.hpp"
#include <stdexcept>
#include <vector>
#include <cstring>
#include <algorithm>

namespace libexe {

namespace {
    // Wildcard byte for pattern matching
    constexpr uint8_t WILDCARD = '?';

    // Read 16-bit little-endian value from buffer
    inline uint16_t read_u16le(const uint8_t* p) {
        return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8));
    }

    // Write 16-bit little-endian value to buffer
    inline void write_u16le(uint8_t* p, uint16_t v) {
        p[0] = static_cast<uint8_t>(v & 0xFF);
        p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    }

    // Huffman code tables (high 4 bits = code length, low 12 bits = code)
    // Standard match lengths (small compression)
    constexpr uint16_t MATCHLENGTHS_SM[] = {
        0x2000, 0x3004, 0x3005, 0x400c, 0x400d, 0x400e, 0x400f, 0x3003, 0x3002
    };

    // Standard match lengths (large compression)
    constexpr uint16_t MATCHLENGTHS_LG[] = {
        0x2003, 0x3000, 0x4002, 0x4003, 0x4004, 0x500a, 0x500b, 0x500c,
        0x601a, 0x601b, 0x703a, 0x703b, 0x703c, 0x807a, 0x807b, 0x807c,
        0x90fa, 0x90fb, 0x90fc, 0x90fd, 0x90fe, 0x90ff, 0x601c, 0x2002
    };

    // v1.20 match lengths (small compression)
    constexpr uint16_t MATCHLENGTHS_120_SM[] = {
        0x2003, 0x3000, 0x4004, 0x4005, 0x500e, 0x601e, 0x601f, 0x4006,
        0x2002, 0x4003, 0x4002
    };

    // v1.20 match lengths (large compression)
    constexpr uint16_t MATCHLENGTHS_120_LG[] = {
        0x2003, 0x3000, 0x4005, 0x4006, 0x5006, 0x5007, 0x6008, 0x6009,
        0x7020, 0x7021, 0x7022, 0x7023, 0x8048, 0x8049, 0x804a, 0x9096,
        0x9097, 0x6013, 0x2002, 0x4007, 0x5005
    };

    // Standard offsets
    constexpr uint16_t OFFSETS_STD[] = {
        0x1001, 0x4000, 0x4001, 0x5004, 0x5005, 0x5006, 0x5007, 0x6010,
        0x6011, 0x6012, 0x6013, 0x6014, 0x6015, 0x6016, 0x702e, 0x702f,
        0x7030, 0x7031, 0x7032, 0x7033, 0x7034, 0x7035, 0x7036, 0x7037,
        0x7038, 0x7039, 0x703a, 0x703b, 0x703c, 0x703d, 0x703e, 0x703f
    };

    // v1.20 offsets
    constexpr uint16_t OFFSETS_120[] = {
        0x1001, 0x3000, 0x5004, 0x5005, 0x5006, 0x5007, 0x6010, 0x6011,
        0x6012, 0x6013, 0x6014, 0x6015, 0x702c, 0x702d, 0x702e, 0x702f,
        0x7030, 0x7031, 0x7032, 0x7033, 0x7034, 0x7035, 0x7036, 0x7037,
        0x7038, 0x7039, 0x703a, 0x703b, 0x703c, 0x703d, 0x703e, 0x703f
    };

    // Simple Huffman decoder for PKLITE
    class huffman_decoder {
    public:
        huffman_decoder(const uint16_t* table, size_t count) {
            for (size_t i = 0; i < count; i++) {
                uint8_t bits = static_cast<uint8_t>(table[i] >> 12);
                uint16_t code = table[i] & 0x0FFF;
                entries_.push_back({bits, code, static_cast<uint16_t>(i)});
            }
        }

        // Decode next symbol from bit reader
        uint16_t decode(bit_reader& reader) const {
            uint16_t code = 0;
            uint8_t bits_read = 0;

            while (bits_read < 12) {
                code = static_cast<uint16_t>((code << 1) | reader.read_bit());
                bits_read++;

                // Check all entries for a match
                for (const auto& e : entries_) {
                    if (e.bits == bits_read && e.code == code) {
                        return e.value;
                    }
                }
            }
            throw std::runtime_error("PKLITE: invalid Huffman code");
        }

    private:
        struct entry {
            uint8_t bits;
            uint16_t code;
            uint16_t value;
        };
        std::vector<entry> entries_;
    };

} // anonymous namespace

// Pattern matching: check if memory matches pattern with wildcards
bool pklite_decompressor::mem_match(const uint8_t* mem, const uint8_t* pattern,
                                    size_t len, uint8_t wildcard) {
    for (size_t i = 0; i < len; i++) {
        if (pattern[i] != wildcard && mem[i] != pattern[i]) {
            return false;
        }
    }
    return true;
}

// Search for pattern in memory range
bool pklite_decompressor::search_match(const uint8_t* mem, size_t mem_len,
                                       size_t start, size_t end,
                                       const uint8_t* pattern, size_t pattern_len,
                                       uint8_t wildcard, size_t* found_pos) {
    if (pattern_len == 0 || start >= end || end > mem_len) {
        return false;
    }

    size_t search_end = end - pattern_len + 1;
    if (search_end <= start) {
        return false;
    }

    for (size_t pos = start; pos < search_end; pos++) {
        if (mem_match(&mem[pos], pattern, pattern_len, wildcard)) {
            if (found_pos) *found_pos = pos;
            return true;
        }
    }
    return false;
}

pklite_decompressor::pklite_decompressor(std::span<const uint8_t> file_data,
                                         uint16_t header_paragraphs)
    : file_data_(file_data)
    , header_size_(static_cast<size_t>(header_paragraphs) * 16)
{
    // Calculate DOS code boundaries from MZ header
    if (file_data_.size() < 28) {
        throw std::runtime_error("PKLITE: file too small");
    }

    // Read MZ header fields
    uint16_t e_cblp = read_u16le(&file_data_[2]);    // Bytes in last page
    uint16_t e_cp = read_u16le(&file_data_[4]);      // Pages in file
    uint16_t e_cs = read_u16le(&file_data_[22]);     // Initial CS
    uint16_t e_ip = read_u16le(&file_data_[20]);     // Initial IP

    // Calculate positions
    start_of_dos_code_ = header_size_;
    end_of_dos_code_ = (e_cp > 0) ? ((static_cast<size_t>(e_cp) - 1) * 512 + e_cblp) : 0;
    if (e_cblp == 0 && e_cp > 0) {
        end_of_dos_code_ = static_cast<size_t>(e_cp) * 512;
    }
    if (end_of_dos_code_ > file_data_.size()) {
        end_of_dos_code_ = file_data_.size();
    }

    // Entry point = header + CS*16 + IP
    // CS is signed (can be negative for files where code starts before relocation table)
    int32_t cs_offset = static_cast<int16_t>(e_cs) * 16;
    entry_point_ = static_cast<size_t>(static_cast<int64_t>(header_size_) + cs_offset + e_ip);

    // Read entry point bytes for pattern matching
    if (entry_point_ < file_data_.size()) {
        epbytes_valid_ = std::min(EPBYTES_LEN, file_data_.size() - entry_point_);
        std::memcpy(epbytes_.data(), &file_data_[entry_point_], epbytes_valid_);
    }

    // Analyze the file to determine decompression parameters
    analyze_file();
}

void pklite_decompressor::analyze_file() {
    analyze_intro();
    if (error_) return;

    analyze_descrambler();
    if (error_) return;

    if (scrambled_decompressor_) {
        descramble_decompressor();
        if (error_) return;
    }

    analyze_copier();
    if (error_) return;

    analyze_decompressor();
    if (error_) return;

    if (dparams_.cmpr_data_pos == 0) {
        error_ = true;
        return;
    }

    // Calculate approximate end of decompressor
    if (data_before_decoder_) {
        approx_end_of_decompressor_ = end_of_dos_code_ - entry_point_;
    } else {
        approx_end_of_decompressor_ = dparams_.cmpr_data_pos - entry_point_;
    }

    analyze_detect_extra_cmpr();
    if (error_) return;

    analyze_detect_large_and_v120_cmpr();
    if (error_) return;

    analyze_detect_obf_offsets();
}

void pklite_decompressor::analyze_intro() {
    // Check for initial DX register key (used in scrambling)
    if (mem_match(&epbytes_[0], reinterpret_cast<const uint8_t*>("\xb8??\xba"), 4, WILDCARD)) {
        initial_key_ = read_u16le(&epbytes_[4]);
    } else if (mem_match(&epbytes_[0], reinterpret_cast<const uint8_t*>("\x50\xb8??\xba"), 5, WILDCARD)) {
        initial_key_ = read_u16le(&epbytes_[5]);
    }

    // Detect intro class from entry point patterns
    // v1.00 beta patterns
    if (mem_match(&epbytes_[0],
            reinterpret_cast<const uint8_t*>("\xb8??\x8c\xca\x03\xd0\x8c\xc9\x81\xc1??\x51\x52\xb9??\x8c\xd8\x48\x8e\xc0"), 23, WILDCARD)) {
        intro_class_ = pklite_intro_class::BETA;
        data_before_decoder_ = true;
        return;
    }

    // v1.00 beta load-high
    if (mem_match(&epbytes_[0],
            reinterpret_cast<const uint8_t*>("\x2e\x8c\x1e??\xfc\x8c\xc8\x2e\x2b\x06"), 11, WILDCARD)) {
        intro_class_ = pklite_intro_class::BETA_LH;
        data_before_decoder_ = true;
        load_high_ = true;
        return;
    }

    // v1.00 pattern
    if (mem_match(&epbytes_[0],
            reinterpret_cast<const uint8_t*>("\xb8??\xba??\x05??\x3b\x06\x02\x00\x72\x55\x8b"), 16, WILDCARD)) {
        intro_class_ = pklite_intro_class::V100;
        position2_ = 16;
        return;
    }

    // v1.03-1.12 pattern - check byte 13 for variant
    if (mem_match(&epbytes_[0],
            reinterpret_cast<const uint8_t*>("\xb8??\xba??\x05??\x3b\x06\x02\x00"), 13, WILDCARD)) {
        if (epbytes_[13] == 0x73) {
            intro_class_ = pklite_intro_class::V112;
            position2_ = 15;
            return;
        } else if (epbytes_[13] == 0x72) {
            intro_class_ = pklite_intro_class::V114;
            // Follow 1-byte jump at offset 14
            position2_ = 15 + epbytes_[14];
            return;
        }
    }

    // v1.50-2.01 pattern
    if (mem_match(&epbytes_[0],
            reinterpret_cast<const uint8_t*>("\x50\xb8??\xba??\x05??\x3b\x06\x02\x00"), 14, WILDCARD)) {
        if (epbytes_[14] == 0x72) {
            intro_class_ = pklite_intro_class::V150;
            position2_ = 16 + epbytes_[15];
            return;
        }
    }

    // UN2PACK pattern
    if (mem_match(&epbytes_[0],
            reinterpret_cast<const uint8_t*>("\xb8??\xba??\x05??\x50\x52"), 10, WILDCARD) &&
        mem_match(&epbytes_[30],
            reinterpret_cast<const uint8_t*>("\xb9??\x2b"), 4, WILDCARD)) {
        intro_class_ = pklite_intro_class::UN2PACK;
        position2_ = 34;
        return;
    }

    // MEGALITE pattern
    if (mem_match(&epbytes_[0],
            reinterpret_cast<const uint8_t*>("\xb8??\xba??\x05??\x3b\x06\x02\x00\x72"), 14, WILDCARD)) {
        intro_class_ = pklite_intro_class::MEGALITE;
        position2_ = 15 + epbytes_[14];
        return;
    }

    // If we got here without finding an intro class, check data_before_decoder
    if (!data_before_decoder_ && intro_class_ == pklite_intro_class::UNKNOWN) {
        error_ = true;
    }
}

void pklite_decompressor::analyze_descrambler() {
    // Only certain classes might be scrambled
    switch (intro_class_) {
        case pklite_intro_class::V112:
        case pklite_intro_class::V114:
        case pklite_intro_class::V150:
            break;
        default:
            // Not scrambled, copier_pos is position2_
            if (!data_before_decoder_) {
                copier_pos_ = position2_;
            }
            return;
    }

    size_t pos = position2_;
    if (pos + 200 > EPBYTES_LEN) {
        copier_pos_ = position2_;
        return;
    }

    size_t pos_of_endpos_field = 0;
    size_t pos_of_jmp_field = 0;
    size_t pos_of_op = 0;
    size_t pos_of_scrambled_word_count = 0;

    // Check for various descrambler patterns (from deark)
    if (mem_match(&epbytes_[pos],
            reinterpret_cast<const uint8_t*>("\x2d\x20\x00\x8e\xd0\x2d??\x50\x52\xb9??\xbe??\x8b\xfe"
            "\xfd\x90\x49\x74?\xad\x92\x33\xc2\xab\xeb\xf6"), 30, WILDCARD)) {
        descrambler_class_ = pklite_descrambler_class::V114;
        pos_of_scrambled_word_count = pos + 11;
        pos_of_endpos_field = pos + 14;
        pos_of_jmp_field = pos + 22;
        pos_of_op = pos + 25;
    }
    else if (mem_match(&epbytes_[pos],
            reinterpret_cast<const uint8_t*>("\x8b\xfc\x81\xef??\x57\x57\x52\xb9??\xbe??\x8b\xfe"
            "\xfd\x49\x74?\xad\x92\x03\xc2\xab\xeb\xf6"), 28, WILDCARD)) {
        descrambler_class_ = pklite_descrambler_class::V120_VAR1A;
        pos_of_scrambled_word_count = pos + 10;
        pos_of_endpos_field = pos + 13;
        pos_of_jmp_field = pos + 20;
        pos_of_op = pos + 23;
    }
    else if (mem_match(&epbytes_[pos],
            reinterpret_cast<const uint8_t*>("\x8b\xfc\x81\xef??\x57\x57\x52\xb9??\xbe??\x8b\xfe"
            "\xfd\x90\x49\x74?\xad\x92\x03\xc2\xab\xeb\xf6"), 29, WILDCARD)) {
        descrambler_class_ = pklite_descrambler_class::V120_VAR1B;
        pos_of_scrambled_word_count = pos + 10;
        pos_of_endpos_field = pos + 13;
        pos_of_jmp_field = pos + 21;
        pos_of_op = pos + 24;
    }
    else if (mem_match(&epbytes_[pos],
            reinterpret_cast<const uint8_t*>("\x59\x2d\x20\x00\x8e\xd0\x51??\x00\x50\x80\x3e"
            "\x41\x01\xc3\x75\xe6\x52\xb8??\xbe??\x56\x56\x52\x50\x90"), 30, WILDCARD) &&
            epbytes_[pos + 37] == 0x74) {
        descrambler_class_ = pklite_descrambler_class::V150;
        pos_of_scrambled_word_count = pos + 20;
        pos_of_endpos_field = pos + 23;
        pos_of_jmp_field = pos + 38;
        pos_of_op = pos + 45;
    }
    else if (mem_match(&epbytes_[pos],
            reinterpret_cast<const uint8_t*>("\x2d\x20\x00"), 3, WILDCARD) &&
            epbytes_[pos + 15] == 0xb9 &&
            epbytes_[pos + 18] == 0xbe &&
            epbytes_[pos + 28] == 0x74 &&
            epbytes_[pos + 31] == 0x03) {
        descrambler_class_ = pklite_descrambler_class::V120_VAR2;
        pos_of_scrambled_word_count = pos + 16;
        pos_of_endpos_field = pos + 19;
        pos_of_jmp_field = pos + 28;
        pos_of_op = pos + 31;
    }
    else if (mem_match(&epbytes_[pos],
            reinterpret_cast<const uint8_t*>("\x2d\x20\x00"), 3, WILDCARD) &&
            epbytes_[pos + 16] == 0xb9 &&
            epbytes_[pos + 19] == 0xbe &&
            epbytes_[pos + 29] == 0x74 &&
            epbytes_[pos + 32] == 0x03) {
        descrambler_class_ = pklite_descrambler_class::PKZIP204C_LIKE;
        pos_of_scrambled_word_count = pos + 16;
        pos_of_endpos_field = pos + 19;
        pos_of_jmp_field = pos + 29;
        pos_of_op = pos + 32;
    }
    else if (mem_match(&epbytes_[pos],
            reinterpret_cast<const uint8_t*>("\x2d\x20\x00"), 3, WILDCARD) &&
            epbytes_[pos + 21] == 0xb9 &&
            epbytes_[pos + 24] == 0xbe &&
            epbytes_[pos + 35] == 0x74 &&
            epbytes_[pos + 38] == 0x03) {
        descrambler_class_ = pklite_descrambler_class::PKLITE201_LIKE;
        pos_of_scrambled_word_count = pos + 21;
        pos_of_endpos_field = pos + 24;
        pos_of_jmp_field = pos + 35;
        pos_of_op = pos + 38;
    }
    else if (mem_match(&epbytes_[pos],
            reinterpret_cast<const uint8_t*>("\x8b\xfc\x81"), 3, WILDCARD) &&
            epbytes_[pos + 17] == 0xbb &&
            epbytes_[pos + 20] == 0xbe &&
            epbytes_[pos + 27] == 0x74 &&
            epbytes_[pos + 30] == 0x03) {
        descrambler_class_ = pklite_descrambler_class::CHK4LITE201_LIKE;
        pos_of_scrambled_word_count = pos + 17;
        pos_of_endpos_field = pos + 20;
        pos_of_jmp_field = pos + 27;
        pos_of_op = pos + 30;
    }
    else if (mem_match(&epbytes_[pos],
            reinterpret_cast<const uint8_t*>("\x59\x2d\x20\x00\x8e\xd0\x51\x2d??\x50\x52\xb9??\xbe??\x8b\xfe"
            "\xfd\x90\x49\x74?\xad\x92\x33"), 28, WILDCARD)) {
        descrambler_class_ = pklite_descrambler_class::V150_IBM;
        pos_of_scrambled_word_count = pos + 13;
        pos_of_endpos_field = pos + 16;
        pos_of_jmp_field = pos + 24;
        pos_of_op = pos + 27;
    }

    if (descrambler_class_ == pklite_descrambler_class::NONE) {
        // Not scrambled
        copier_pos_ = position2_;
        return;
    }

    scrambled_decompressor_ = true;

    // Determine scramble method from opcode
    if (epbytes_[pos_of_op] == 0x33) {
        scramble_method_ = pklite_scramble_method::XOR;
    } else if (epbytes_[pos_of_op] == 0x03) {
        scramble_method_ = pklite_scramble_method::ADD;
    } else {
        error_ = true;
        return;
    }

    scrambled_word_count_ = read_u16le(&epbytes_[pos_of_scrambled_word_count]);
    if (scrambled_word_count_ > 0) scrambled_word_count_--;

    // Calculate position of last scrambled word
    uint16_t scrambled_endpos_raw = read_u16le(&epbytes_[pos_of_endpos_field]);
    // Convert IP-relative address to epbytes offset
    pos_of_last_scrambled_word_ = start_of_dos_code_ + scrambled_endpos_raw - 0x100 - entry_point_;

    // Follow jump to copier
    copier_pos_ = pos_of_jmp_field + 1 + epbytes_[pos_of_jmp_field];
}

void pklite_decompressor::descramble_decompressor() {
    if (!scrambled_decompressor_ || scrambled_word_count_ < 1) {
        return;
    }

    if (pos_of_last_scrambled_word_ + 2 > EPBYTES_LEN) {
        error_ = true;
        return;
    }

    size_t startpos = pos_of_last_scrambled_word_ + 2 - scrambled_word_count_ * 2;
    if (startpos > pos_of_last_scrambled_word_) {  // Overflow check
        error_ = true;
        return;
    }

    uint16_t this_word_scr = read_u16le(&epbytes_[startpos]);

    for (size_t pos = startpos; pos <= pos_of_last_scrambled_word_; pos += 2) {
        uint16_t next_word_scr;
        if (pos == pos_of_last_scrambled_word_) {
            next_word_scr = initial_key_;
        } else {
            next_word_scr = read_u16le(&epbytes_[pos + 2]);
        }

        uint16_t this_word_dscr;
        if (scramble_method_ == pklite_scramble_method::ADD) {
            this_word_dscr = (this_word_scr + next_word_scr) & 0xFFFF;
        } else {
            this_word_dscr = this_word_scr ^ next_word_scr;
        }

        write_u16le(&epbytes_[pos], this_word_dscr);
        this_word_scr = next_word_scr;
    }
}

void pklite_decompressor::analyze_copier() {
    if (data_before_decoder_) return;

    if (copier_pos_ == 0 || copier_pos_ + 200 > EPBYTES_LEN) {
        error_ = true;
        return;
    }

    size_t pos = copier_pos_;
    size_t pos_of_decompr_pos_field = 0;
    size_t foundpos = 0;

    // Search for copier patterns
    if (search_match(epbytes_.data(), EPBYTES_LEN, pos, pos + 75,
            reinterpret_cast<const uint8_t*>("\xb9??\x33\xff\x57\xbe??\xfc\xf3\xa5"), 12,
            WILDCARD, &foundpos)) {
        if (epbytes_[foundpos + 12] == 0xcb) {
            copier_class_ = pklite_copier_class::COMMON;
        } else if (epbytes_[foundpos + 12] == 0xca) {
            copier_class_ = pklite_copier_class::V150_SCR;
        } else {
            copier_class_ = pklite_copier_class::OTHER;
        }
        pos_of_decompr_pos_field = foundpos + 7;
    }
    else if (search_match(epbytes_.data(), EPBYTES_LEN, pos, pos + 75,
            reinterpret_cast<const uint8_t*>("\xb9??\x33\xff\x57\xfc\xbe??\xf3\xa5\xcb"), 13,
            WILDCARD, &foundpos)) {
        copier_class_ = pklite_copier_class::PKLITE201_LIKE;
        pos_of_decompr_pos_field = foundpos + 8;
    }
    else if (search_match(epbytes_.data(), EPBYTES_LEN, pos, pos + 75,
            reinterpret_cast<const uint8_t*>("\x57\xb9??\xbe??\xfc\xf3\xa5\xc3"), 11,
            WILDCARD, &foundpos)) {
        copier_class_ = pklite_copier_class::V120_VAR1_SMALL;
        pos_of_decompr_pos_field = foundpos + 5;
    }
    else if (search_match(epbytes_.data(), EPBYTES_LEN, pos, pos + 75,
            reinterpret_cast<const uint8_t*>("\xb9??\x33\xff\x56\xbe??\xfc\xf2\xa5\xca"), 13,
            WILDCARD, &foundpos)) {
        copier_class_ = pklite_copier_class::MEGALITE;
        pos_of_decompr_pos_field = foundpos + 7;
    }
    else if (search_match(epbytes_.data(), EPBYTES_LEN, pos, pos + 75,
            reinterpret_cast<const uint8_t*>("\xb9??\x2b\xff\x57\xbe??\xfc\xf3\xa5\xcb"), 13,
            WILDCARD, &foundpos)) {
        copier_class_ = pklite_copier_class::UN2PACK;
        pos_of_decompr_pos_field = foundpos + 7;
    }

    if (copier_class_ == pklite_copier_class::UNKNOWN) {
        error_ = true;
        return;
    }

    // Extract decompressor position from the copier code
    uint16_t decompr_pos_raw = read_u16le(&epbytes_[pos_of_decompr_pos_field]);
    decompr_pos_ = start_of_dos_code_ + decompr_pos_raw - 0x100 - entry_point_;
}

void pklite_decompressor::analyze_decompressor() {
    // For beta versions, find decompr_pos differently
    if (data_before_decoder_ && decompr_pos_ == 0) {
        // Beta small
        if (mem_match(&epbytes_[0x59],
                reinterpret_cast<const uint8_t*>("\xf3\xa5\x2e\xa1"), 4, WILDCARD) &&
                epbytes_[0x66] == 0xcb && epbytes_[0x67] == 0xfc) {
            decompr_pos_ = 0x66;
        }
        // Beta large
        else if (mem_match(&epbytes_[0x5b],
                reinterpret_cast<const uint8_t*>("\xf3\xa5\x85\xed"), 4, WILDCARD) &&
                epbytes_[0x6b] == 0xcb && epbytes_[0x6c] == 0xfc) {
            decompr_pos_ = 0x6c;
        }
        // Load-high
        else if (mem_match(&epbytes_[0],
                reinterpret_cast<const uint8_t*>("\x2e\x8c\x1e??\xfc\x8c\xc8\x2e\x2b\x06"), 11, WILDCARD)) {
            decompr_pos_ = 0x5;
        }
    }

    size_t pos = decompr_pos_;
    if (pos == 0 || pos + 200 > EPBYTES_LEN) {
        error_ = true;
        return;
    }

    size_t n = 0;

    // Check decompressor patterns
    if (mem_match(&epbytes_[pos],
            reinterpret_cast<const uint8_t*>("\xfd\x8c\xdb\x53\x83\xc3"), 6, WILDCARD)) {
        decompr_class_ = pklite_decompr_class::COMMON;
        n = static_cast<size_t>(epbytes_[pos + 6]) * 16;
        dparams_.cmpr_data_pos = entry_point_ + (start_of_dos_code_ + n - 0x100 - entry_point_);
    }
    else if (mem_match(&epbytes_[pos],
            reinterpret_cast<const uint8_t*>("\xfd\x8c\xdb\x53\x81\xc3"), 6, WILDCARD)) {
        decompr_class_ = pklite_decompr_class::V115;
        n = read_u16le(&epbytes_[pos + 6]) * 16;
        dparams_.cmpr_data_pos = entry_point_ + (start_of_dos_code_ + n - 0x100 - entry_point_);
    }
    else if (mem_match(&epbytes_[pos],
            reinterpret_cast<const uint8_t*>("\xfd\x5f\xc7\x85????\x4f\x4f\xbe??\x03\xf2"
            "\x8b\xca\xd1\xe9\xf3"), 20, WILDCARD)) {
        decompr_class_ = pklite_decompr_class::V120_SMALL;
        n = read_u16le(&epbytes_[pos + 11]);
        dparams_.cmpr_data_pos = entry_point_ + 2 + (start_of_dos_code_ + n - 0x100 - entry_point_);
    }
    else if (mem_match(&epbytes_[pos],
            reinterpret_cast<const uint8_t*>("\xfd\x5f\x4f\x4f\xbe??\x03\xf2\x8b\xca\xd1\xe9\xf3"), 14, WILDCARD)) {
        decompr_class_ = pklite_decompr_class::V120_SMALL_OLD;
        n = read_u16le(&epbytes_[pos + 5]);
        dparams_.cmpr_data_pos = entry_point_ + 2 + (start_of_dos_code_ + n - 0x100 - entry_point_);
    }
    else if (mem_match(&epbytes_[pos],
            reinterpret_cast<const uint8_t*>("\xfc\x8c\xc8\x2e\x2b\x06??\x8e\xd8\xbf"), 11, WILDCARD)) {
        decompr_class_ = pklite_decompr_class::BETA;
        dparams_.cmpr_data_pos = start_of_dos_code_;
    }

    if (decompr_class_ == pklite_decompr_class::UNKNOWN) {
        error_ = true;
    }
}

void pklite_decompressor::analyze_detect_extra_cmpr() {
    if (decompr_pos_ == 0 || approx_end_of_decompressor_ == 0) {
        error_ = true;
        return;
    }

    size_t foundpos;

    // Look for standard (non-extra) compression pattern
    if (search_match(epbytes_.data(), EPBYTES_LEN,
            decompr_pos_, approx_end_of_decompressor_,
            reinterpret_cast<const uint8_t*>("\xad\x95\xb2\x10\x72\x08\xa4\xd1\xed\x4a\x74"), 11,
            WILDCARD, &foundpos)) {
        extra_cmpr_ = 0;
        return;
    }

    // Look for extra compression patterns
    if (search_match(epbytes_.data(), EPBYTES_LEN,
            decompr_pos_, approx_end_of_decompressor_,
            reinterpret_cast<const uint8_t*>("\xad\x95\xb2\x10\x72\x0b\xac??\xaa\xd1\xed\x4a\x74"), 14,
            WILDCARD, &foundpos)) {
        if (epbytes_[foundpos + 7] == 0x32 && epbytes_[foundpos + 8] == 0xc2) {
            extra_cmpr_ = 1;  // XOR with bit count
            return;
        } else if (epbytes_[foundpos + 7] == 0xf6 && epbytes_[foundpos + 8] == 0xd0) {
            extra_cmpr_ = 2;  // XOR with 0xFF (customized v1.23)
            return;
        }
    }

    error_ = true;
}

void pklite_decompressor::analyze_detect_large_and_v120_cmpr() {
    // v1.20 small uses different decompressor classes
    if (decompr_class_ == pklite_decompr_class::V120_SMALL ||
        decompr_class_ == pklite_decompr_class::V120_SMALL_OLD) {
        v120_cmpr_ = true;
        large_cmpr_ = false;
        return;
    }

    // Look for the Huffman table signature to determine large/small
    size_t foundpos;
    if (search_match(epbytes_.data(), EPBYTES_LEN,
            approx_end_of_decompressor_ > 60 ? approx_end_of_decompressor_ - 60 : 0,
            approx_end_of_decompressor_,
            reinterpret_cast<const uint8_t*>("\x01\x02\x00\x00\x03\x04\x05\x06"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x07\x08\x09\x0a\x0b"), 21,
            0x3f, &foundpos)) {
        if (foundpos > 0) {
            uint8_t prec_b = epbytes_[foundpos - 1];
            if (prec_b == 0x09) {
                large_cmpr_ = false;
            } else if (prec_b == 0x18) {
                large_cmpr_ = true;
            } else {
                error_ = true;
            }
        }
        return;
    }

    // v1.20 with large compression always uses extra_cmpr
    if (extra_cmpr_ == 0) {
        error_ = true;
        return;
    }

    // Check for v1.20 pattern
    if (search_match(epbytes_.data(), EPBYTES_LEN,
            approx_end_of_decompressor_ > 50 ? approx_end_of_decompressor_ - 50 : 0,
            approx_end_of_decompressor_,
            reinterpret_cast<const uint8_t*>("\x33\xc0\x8b\xd8\x8b\xc8\x8b\xd0\x8b\xe8\x8b\xf0\x8b"), 13,
            0x3f, &foundpos)) {
        v120_cmpr_ = true;
        large_cmpr_ = true;
        return;
    }

    error_ = true;
}

void pklite_decompressor::analyze_detect_obf_offsets() {
    if (!v120_cmpr_) return;

    size_t foundpos;
    if (search_match(epbytes_.data(), EPBYTES_LEN,
            decompr_pos_ + 200, approx_end_of_decompressor_,
            reinterpret_cast<const uint8_t*>("\xac\x34?\x8a"), 4,
            WILDCARD, &foundpos)) {
        dparams_.offset_xor_key = epbytes_[foundpos + 2];
    }
}

decompression_result pklite_decompressor::decompress(std::span<const uint8_t> compressed_data) {
    decompression_result result;

    if (error_) {
        throw std::runtime_error("PKLITE: analysis failed - unsupported format variant");
    }

    if (dparams_.cmpr_data_pos == 0 || dparams_.cmpr_data_pos >= compressed_data.size()) {
        throw std::runtime_error("PKLITE: invalid compressed data position");
    }

    // Store parameters for decompression
    dparams_.extra_cmpr = extra_cmpr_;
    dparams_.large_cmpr = large_cmpr_;
    dparams_.v120_cmpr = v120_cmpr_;

    do_decompress(result);

    return result;
}

void pklite_decompressor::do_decompress(decompression_result& result) {
    // Select the appropriate Huffman tables
    const uint16_t* lengths_table;
    size_t lengths_count;
    const uint16_t* offsets_table;
    size_t offsets_count;

    if (dparams_.large_cmpr) {
        if (dparams_.v120_cmpr) {
            lengths_table = MATCHLENGTHS_120_LG;
            lengths_count = sizeof(MATCHLENGTHS_120_LG) / sizeof(MATCHLENGTHS_120_LG[0]);
        } else {
            lengths_table = MATCHLENGTHS_LG;
            lengths_count = sizeof(MATCHLENGTHS_LG) / sizeof(MATCHLENGTHS_LG[0]);
        }
    } else {
        if (dparams_.v120_cmpr) {
            lengths_table = MATCHLENGTHS_120_SM;
            lengths_count = sizeof(MATCHLENGTHS_120_SM) / sizeof(MATCHLENGTHS_120_SM[0]);
        } else {
            lengths_table = MATCHLENGTHS_SM;
            lengths_count = sizeof(MATCHLENGTHS_SM) / sizeof(MATCHLENGTHS_SM[0]);
        }
    }

    if (dparams_.v120_cmpr) {
        offsets_table = OFFSETS_120;
        offsets_count = sizeof(OFFSETS_120) / sizeof(OFFSETS_120[0]);
    } else {
        offsets_table = OFFSETS_STD;
        offsets_count = sizeof(OFFSETS_STD) / sizeof(OFFSETS_STD[0]);
    }

    huffman_decoder lengths_decoder(lengths_table, lengths_count);
    huffman_decoder offsets_decoder(offsets_table, offsets_count);

    // Determine special code values based on compression mode
    uint16_t value_of_long_ml_code;
    uint16_t value_of_ml2_0_code;
    uint16_t value_of_ml2_1_code = 0xFFFF;
    uint16_t value_of_lit0_code = 0xFFFF;
    uint16_t long_matchlen_bias;

    if (dparams_.large_cmpr) {
        if (dparams_.v120_cmpr) {
            value_of_long_ml_code = 17;
            value_of_ml2_0_code = 18;
            value_of_ml2_1_code = 19;
            value_of_lit0_code = 20;
            long_matchlen_bias = 20;
        } else {
            value_of_long_ml_code = 22;
            value_of_ml2_0_code = 23;
            long_matchlen_bias = 25;
        }
    } else {
        if (dparams_.v120_cmpr) {
            value_of_long_ml_code = 7;
            value_of_ml2_0_code = 8;
            value_of_ml2_1_code = 9;
            value_of_lit0_code = 10;
            long_matchlen_bias = 10;
        } else {
            value_of_long_ml_code = 7;
            value_of_ml2_0_code = 8;
            long_matchlen_bias = 10;
        }
    }

    // Initialize bit reader
    bit_reader reader(file_data_);
    reader.seek(dparams_.cmpr_data_pos);

    // Output buffer with LZ77 ring buffer semantics
    std::vector<uint8_t> output;
    output.reserve(65536);

    // Main decompression loop
    while (true) {
        uint16_t x = reader.read_bit();

        if (x == 0) {
            // Literal byte
            uint8_t b = reader.read_byte();
            if (dparams_.extra_cmpr == 1) {
                b ^= reader.bit_count();
            } else if (dparams_.extra_cmpr == 2) {
                b ^= 0xFF;
            }
            output.push_back(b);
            continue;
        }

        // Match code
        uint16_t len_raw = lengths_decoder.decode(reader);

        uint16_t matchlen;
        uint16_t offs_hi_bits = 0;
        bool offs_have_hi_bits = false;

        if (len_raw < value_of_long_ml_code) {
            matchlen = len_raw + 3;
        } else if (len_raw == value_of_ml2_0_code) {
            matchlen = 2;
            offs_have_hi_bits = true;
            // offs_hi_bits stays 0
        } else if (len_raw == value_of_long_ml_code) {
            uint8_t b = reader.read_byte();

            if (b >= 0xFD) {
                if (b == 0xFD && dparams_.large_cmpr) {
                    // Uncompressed area - not fully implemented
                    throw std::runtime_error("PKLITE: uncompressed area not implemented");
                }
                if (b == 0xFE && dparams_.large_cmpr) {
                    // Segment separator - no-op
                    continue;
                }
                if (b == 0xFF) {
                    // End of compressed data
                    break;
                }
                throw std::runtime_error("PKLITE: unexpected code");
            }
            matchlen = b + long_matchlen_bias;
        } else if (len_raw == value_of_lit0_code) {
            // Literal 0x00 (v1.20 special)
            output.push_back(0x00);
            continue;
        } else if (len_raw == value_of_ml2_1_code) {
            matchlen = 2;
            offs_hi_bits = 1;
            offs_have_hi_bits = true;
        } else {
            throw std::runtime_error("PKLITE: invalid match length code");
        }

        if (!offs_have_hi_bits) {
            offs_hi_bits = offsets_decoder.decode(reader);
        }

        uint8_t offs_lo_byte = reader.read_byte();
        offs_lo_byte ^= dparams_.offset_xor_key;

        uint16_t matchpos = static_cast<uint16_t>((offs_hi_bits << 8) | offs_lo_byte);

        // Validate match position
        if (matchpos == 0 || matchpos > output.size()) {
            throw std::runtime_error("PKLITE: invalid back-reference offset");
        }

        // Copy match (handles overlapping copies correctly)
        size_t src_pos = output.size() - matchpos;
        for (uint16_t i = 0; i < matchlen; i++) {
            output.push_back(output[src_pos + i]);
        }
    }

    result.code = std::move(output);

    // Position after compressed data
    cmpr_data_endpos_ = reader.position();

    // Read relocation table (starts after compressed data, ends 8 bytes before footer)
    if (dparams_.extra_cmpr) {
        read_reloc_table_long(result, cmpr_data_endpos_);
    } else {
        read_reloc_table_short(result, cmpr_data_endpos_);
    }

    // The footer (SS, SP, CS, IP) is the last 8 bytes of the compressed data area
    // It comes after the relocation table
    size_t footer_pos = reloc_tbl_endpos_;
    if (footer_pos + 8 > file_data_.size()) {
        throw std::runtime_error("PKLITE: footer extends past end of file");
    }

    result.initial_ss = read_u16le(&file_data_[footer_pos]);
    result.initial_sp = read_u16le(&file_data_[footer_pos + 2]);
    result.initial_cs = read_u16le(&file_data_[footer_pos + 4]);
    result.initial_ip = read_u16le(&file_data_[footer_pos + 6]);

    // Calculate min_extra_paragraphs from entry point code
    // Formula from deark: value at entry_point+1 (or +2 if starts with PUSH AX)
    // min_mem = ((n << 4) + 0x100 - code_size + 15) >> 4
    result.min_extra_paragraphs = calculate_min_mem(result.code.size());
}

uint16_t pklite_decompressor::calculate_min_mem(size_t code_size) {
    if (data_before_decoder_ || entry_point_ + 4 > file_data_.size()) {
        return 0;
    }

    size_t pos = entry_point_;
    uint8_t b = file_data_[pos++];

    // Skip PUSH AX (0x50) if present
    if (b == 0x50) {
        if (pos >= file_data_.size()) return 0;
        b = file_data_[pos++];
    }

    // Expect MOV AX, imm16 (0xB8)
    if (b == 0xB8 && pos + 2 <= file_data_.size()) {
        uint16_t n = read_u16le(&file_data_[pos]);
        int64_t mem = (static_cast<int64_t>(n) << 4) + 0x100 - static_cast<int64_t>(code_size);
        if (mem >= 0) {
            // Note: using floor division to match deark's observed behavior
            return static_cast<uint16_t>(mem >> 4);
        }
    }

    return 0;
}

void pklite_decompressor::read_reloc_table_short(decompression_result& result, size_t start_pos) {
    // Short relocation table format:
    // [count:1] [segment:2] [offset:2]... repeated until count=0

    size_t pos = start_pos;

    while (pos < file_data_.size()) {
        uint8_t count = file_data_[pos++];
        if (count == 0) {
            break;  // Normal completion
        }

        if (pos + 2 + count * 2 > file_data_.size()) {
            throw std::runtime_error("PKLITE: relocation table extends past end of file");
        }

        uint16_t segment = read_u16le(&file_data_[pos]);
        pos += 2;

        for (uint8_t i = 0; i < count; i++) {
            uint16_t offset = read_u16le(&file_data_[pos]);
            pos += 2;
            result.relocations.push_back({segment, offset});
        }
    }

    reloc_tbl_endpos_ = pos;
}

void pklite_decompressor::read_reloc_table_long(decompression_result& result, size_t start_pos) {
    // Long relocation table format:
    // [count:2] [offset:2]... segment increments by 0x0FFF each time, until count=0xFFFF

    size_t pos = start_pos;
    uint16_t segment = 0;
    bool use_big_endian = (scramble_method_ == pklite_scramble_method::ADD);  // reversed for some variants

    while (pos + 2 <= file_data_.size()) {
        uint16_t count = read_u16le(&file_data_[pos]);
        pos += 2;

        if (count == 0xFFFF) {
            break;  // Normal completion
        }

        if (pos + count * 2 > file_data_.size()) {
            throw std::runtime_error("PKLITE: relocation table extends past end of file");
        }

        for (uint16_t i = 0; i < count; i++) {
            uint16_t offset;
            if (use_big_endian) {
                offset = static_cast<uint16_t>((file_data_[pos] << 8) | file_data_[pos + 1]);
            } else {
                offset = read_u16le(&file_data_[pos]);
            }
            pos += 2;
            result.relocations.push_back({segment, offset});
        }

        segment += 0x0FFF;
    }

    reloc_tbl_endpos_ = pos;
}

} // namespace libexe
