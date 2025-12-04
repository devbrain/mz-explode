// libexe - Modern executable file analysis library
// Copyright (c) 2024
//
// Bit-level reader for decompression algorithms

#ifndef LIBEXE_BIT_READER_HPP
#define LIBEXE_BIT_READER_HPP

#include <cstdint>
#include <span>
#include <stdexcept>

namespace libexe {

/// Bit-level reader for compressed data streams
/// Reads bits LSB-first within each byte
class bit_reader {
public:
    explicit bit_reader(std::span<const uint8_t> data)
        : data_(data), position_(0), bit_buffer_(0), bits_available_(0) {}

    /// Read a single bit (returns 0 or 1)
    uint8_t read_bit() {
        if (bits_available_ == 0) {
            refill_buffer();
        }
        uint8_t bit = bit_buffer_ & 1;
        bit_buffer_ >>= 1;
        bits_available_--;
        return bit;
    }

    /// Read a full byte
    uint8_t read_byte() {
        if (position_ >= data_.size()) {
            throw std::runtime_error("bit_reader: read past end of data");
        }
        return data_[position_++];
    }

    /// Read a 16-bit word (little-endian)
    uint16_t read_word() {
        uint8_t lo = read_byte();
        uint8_t hi = read_byte();
        return lo | (hi << 8);
    }

    /// Seek to byte offset in the stream
    void seek(size_t byte_offset) {
        if (byte_offset > data_.size()) {
            throw std::runtime_error("bit_reader: seek past end of data");
        }
        position_ = byte_offset;
        bits_available_ = 0;
        bit_buffer_ = 0;
    }

    /// Get current byte position
    size_t position() const { return position_; }

    /// Get total size
    size_t size() const { return data_.size(); }

    /// Get bit counter (for XOR operations in some PKLITE versions)
    uint8_t bit_count() const { return static_cast<uint8_t>(position_ & 0xFF); }

private:
    void refill_buffer() {
        if (position_ >= data_.size()) {
            throw std::runtime_error("bit_reader: unexpected end of compressed data");
        }
        bit_buffer_ = data_[position_++];
        bits_available_ = 8;
    }

    std::span<const uint8_t> data_;
    size_t position_;
    uint8_t bit_buffer_;
    uint8_t bits_available_;
};

} // namespace libexe

#endif // LIBEXE_BIT_READER_HPP
