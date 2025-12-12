// libexe - Modern executable file analysis library
// Copyright (c) 2024

/**
 * @file mz_file.hpp
 * @brief DOS MZ executable file parser.
 *
 * This header provides the mz_file class for parsing and analyzing DOS MZ
 * executable files. MZ is the original DOS executable format, identified
 * by the "MZ" magic bytes at the start of the file.
 *
 * The parser supports:
 * - Plain DOS executables (no extended header)
 * - Detection of common compression/packing tools:
 *   - PKLITE (standard and extra)
 *   - LZEXE (versions 0.90 and 0.91)
 *   - EXEPACK
 *   - Knowledge Dynamics
 * - Entropy analysis for packing detection
 *
 * @note MZ files with NE/PE/LE/LX extended headers are handled by their
 *       respective parser classes, not mz_file.
 *
 * @see ne_file, pe_file, le_file, executable_factory
 */

#ifndef LIBEXE_FORMATS_MZ_FILE_HPP
#define LIBEXE_FORMATS_MZ_FILE_HPP

#include <libexe/export.hpp>
#include <libexe/core/executable_file.hpp>
#include <libexe/decompressors/decompressor.hpp>
#include <filesystem>
#include <memory>
#include <span>
#include <cstdint>

namespace libexe {


class data_source;  // Forward declaration


/**
 * @brief DOS MZ executable file parser.
 *
 * Parses DOS MZ format executables and provides access to header fields,
 * compression detection, and entropy analysis. MZ files are identified
 * by the signature bytes 0x4D 0x5A ("MZ") or 0x5A 0x4D ("ZM") at offset 0.
 *
 * @par DOS MZ Header Structure:
 * The MZ header contains information needed by DOS to load the executable:
 * - Initial register values (CS:IP, SS:SP)
 * - Relocation table information
 * - Memory requirements (minalloc, maxalloc)
 * - Header size in paragraphs (16-byte units)
 *
 * @par Example Usage:
 * @code
 * auto mz = libexe::mz_file::from_file("game.exe");
 *
 * std::cout << "Entry point: " << std::hex
 *           << mz.entry_cs() << ":" << mz.entry_ip() << std::endl;
 *
 * if (mz.is_compressed()) {
 *     std::cout << "Compressed with: ";
 *     switch (mz.get_compression()) {
 *         case compression_type::PKLITE_STANDARD: std::cout << "PKLITE"; break;
 *         case compression_type::LZEXE_091: std::cout << "LZEXE 0.91"; break;
 *         // ...
 *     }
 * }
 * @endcode
 *
 * @see compression_type, decompressor
 */
class LIBEXE_EXPORT mz_file final : public executable_file {
    public:
        // =====================================================================
        // Factory Methods
        // =====================================================================

        /**
         * @brief Load MZ file from filesystem.
         *
         * @param path Path to the executable file.
         * @return Parsed mz_file object.
         * @throws std::runtime_error If file cannot be read or is not valid MZ format.
         */
        [[nodiscard]] static mz_file from_file(const std::filesystem::path& path);

        /**
         * @brief Load MZ file from memory buffer.
         *
         * @param data Span containing the raw file data.
         * @return Parsed mz_file object.
         * @throws std::runtime_error If data is not valid MZ format.
         */
        [[nodiscard]] static mz_file from_memory(std::span <const uint8_t> data);

        /**
         * @brief Load MZ file from data source, taking ownership.
         *
         * @param source Data source to take ownership of.
         * @return Parsed mz_file object.
         * @throws std::runtime_error If data is not valid MZ format.
         */
        [[nodiscard]] static mz_file from_data_source(std::unique_ptr<data_source> source);

        // =====================================================================
        // Base Class Interface Implementation
        // =====================================================================

        /**
         * @brief Get the format type.
         * @return format_type::MZ_DOS
         */
        [[nodiscard]] format_type get_format() const override;

        /**
         * @brief Get human-readable format name.
         * @return "DOS MZ"
         */
        [[nodiscard]] std::string_view format_name() const override;

        /**
         * @brief Get the code section data.
         *
         * Returns the executable code portion of the file, starting after
         * the MZ header and relocation table.
         *
         * @return Span containing the code section bytes.
         */
        [[nodiscard]] std::span <const uint8_t> code_section() const override;

        // =====================================================================
        // Compression Detection
        // =====================================================================

        /**
         * @brief Check if this executable is compressed.
         *
         * Examines the code section for signatures of common DOS executable
         * compressors including PKLITE, LZEXE, EXEPACK, and Knowledge Dynamics.
         *
         * @return true if compression was detected.
         */
        [[nodiscard]] bool is_compressed() const;

        /**
         * @brief Get the detected compression type.
         *
         * @return The compression_type, or compression_type::NONE if not compressed.
         */
        [[nodiscard]] compression_type get_compression() const;

        // =====================================================================
        // DOS Header Accessors
        // =====================================================================

        /**
         * @brief Get entry Code Segment register value.
         *
         * This is the CS value loaded before execution begins, relative to
         * the start of the loaded executable in memory.
         *
         * @return Entry CS register value.
         */
        [[nodiscard]] uint16_t entry_cs() const;

        /**
         * @brief Get entry Instruction Pointer value.
         *
         * Combined with entry_cs(), this forms the entry point address.
         * Execution begins at CS:IP.
         *
         * @return Entry IP register value.
         */
        [[nodiscard]] uint16_t entry_ip() const;

        /**
         * @brief Get entry Stack Segment register value.
         * @return Entry SS register value.
         */
        [[nodiscard]] uint16_t entry_ss() const;

        /**
         * @brief Get entry Stack Pointer value.
         *
         * Combined with entry_ss(), this forms the initial stack address.
         *
         * @return Entry SP register value.
         */
        [[nodiscard]] uint16_t entry_sp() const;

        /**
         * @brief Get minimum extra paragraphs needed.
         *
         * The minimum number of additional 16-byte paragraphs to allocate
         * beyond the size of the loaded executable.
         *
         * @return Minimum extra paragraphs (e_minalloc).
         */
        [[nodiscard]] uint16_t min_extra_paragraphs() const;

        /**
         * @brief Get maximum extra paragraphs wanted.
         *
         * The maximum number of additional paragraphs the program would like.
         * DOS allocates as much as possible up to this limit.
         *
         * @return Maximum extra paragraphs (e_maxalloc), often 0xFFFF.
         */
        [[nodiscard]] uint16_t max_extra_paragraphs() const;

        /**
         * @brief Get number of relocation entries.
         * @return Count of relocation table entries (e_crlc).
         */
        [[nodiscard]] uint16_t relocation_count() const;

        /**
         * @brief Get header size in paragraphs.
         *
         * The header size includes the MZ header structure and relocation table.
         * Multiply by 16 to get the byte offset to the start of the code section.
         *
         * @return Header size in 16-byte paragraphs (e_cparhdr).
         */
        [[nodiscard]] uint16_t header_paragraphs() const;

        // =====================================================================
        // Entropy Analysis (Packing Detection)
        // =====================================================================

        /**
         * @brief Calculate entropy of the entire file.
         *
         * Shannon entropy ranges from 0.0 (uniform) to 8.0 (random).
         * Higher values indicate more randomness/compression.
         *
         * @return Entropy value in bits (0.0 - 8.0).
         */
        [[nodiscard]] double file_entropy() const;

        /**
         * @brief Calculate entropy of the code section only.
         *
         * @return Entropy value in bits (0.0 - 8.0).
         */
        [[nodiscard]] double code_entropy() const;

        /**
         * @brief Check if code section has high entropy.
         *
         * High entropy (>= 7.0) typically indicates packed or compressed code.
         *
         * @return true if code section entropy >= 7.0 bits.
         */
        [[nodiscard]] bool is_high_entropy() const;

        /**
         * @brief Check if file appears to be packed.
         *
         * Uses heuristics combining entropy analysis and compression signature
         * detection to determine if the file is likely packed.
         *
         * @return true if file appears to be packed/compressed.
         */
        [[nodiscard]] bool is_likely_packed() const;

        mz_file(mz_file&&) noexcept;
        mz_file& operator=(mz_file&&) noexcept;
        ~mz_file();

        mz_file(const mz_file&) = delete;
        mz_file& operator=(const mz_file&) = delete;

    private:
        mz_file();

        void parse_header();
        [[nodiscard]] compression_type detect_compression() const;

        std::unique_ptr<data_source> data_;
        compression_type compression_ = compression_type::NONE;

        // Cached DOS header fields
        uint16_t header_size_ = 0;
        uint16_t code_offset_ = 0;
        uint16_t e_cs_ = 0;
        uint16_t e_ip_ = 0;
        uint16_t e_ss_ = 0;
        uint16_t e_sp_ = 0;
        uint16_t e_minalloc_ = 0;
        uint16_t e_maxalloc_ = 0;
        uint16_t e_crlc_ = 0;
        uint16_t e_cparhdr_ = 0;
};

} // namespace libexe

#endif // LIBEXE_FORMATS_MZ_FILE_HPP
