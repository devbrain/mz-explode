// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_DECOMPRESSOR_HPP
#define LIBEXE_DECOMPRESSOR_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <span>
#include <vector>
#include <memory>

namespace libexe {

/// Compression algorithms used in DOS executables
enum class compression_type {
    NONE,
    PKLITE_STANDARD,
    PKLITE_EXTRA,
    LZEXE_090,
    LZEXE_091,
    EXEPACK,
    KNOWLEDGE_DYNAMICS
};

/// Result of decompression operation
struct decompression_result {
    std::vector<uint8_t> code;              // Decompressed code section
    std::vector<uint8_t> extra_header;      // Extra header data
    uint16_t initial_cs = 0;                // Initial CS register
    uint16_t initial_ip = 0;                // Initial IP register
    uint16_t initial_ss = 0;                // Initial SS register
    uint16_t initial_sp = 0;                // Initial SP register
    uint16_t min_extra_paragraphs = 0;      // Minimum extra memory
    uint16_t max_extra_paragraphs = 0xFFFF; // Maximum extra memory (default = no limit)
    uint16_t checksum = 0;                  // File checksum
    std::vector<std::pair<uint16_t, uint16_t>> relocations;  // Segment:offset pairs
};

/// Base class for all decompressors
/// Pure algorithm implementation - no file I/O
class LIBEXE_EXPORT decompressor {
public:
    virtual ~decompressor() = default;

    /// Decompress the data
    /// @param compressed_data The compressed code section
    /// @return Decompression result with code and metadata
    virtual decompression_result decompress(std::span<const uint8_t> compressed_data) = 0;

    /// Get decompressor name for debugging/logging
    virtual const char* name() const = 0;

protected:
    decompressor() = default;
    decompressor(const decompressor&) = delete;
    decompressor& operator=(const decompressor&) = delete;
    decompressor(decompressor&&) = default;
    decompressor& operator=(decompressor&&) = default;
};

/// Factory for creating decompressors based on compression type
LIBEXE_EXPORT std::unique_ptr<decompressor>
create_decompressor(compression_type type);

} // namespace libexe

#endif // LIBEXE_DECOMPRESSOR_HPP
