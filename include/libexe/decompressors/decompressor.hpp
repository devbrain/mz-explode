// libexe - Modern executable file analysis library
// Copyright (c) 2024

/**
 * @file decompressor.hpp
 * @brief Base decompressor interface and compression type definitions.
 *
 * This header defines the common interface for executable decompressors
 * and the compression_type enumeration used to identify different
 * compression schemes used by DOS executable packers.
 *
 * @par Supported Compression Formats:
 * - **PKLITE**: PKWare LITE compression (standard and extra modes)
 * - **LZEXE**: Fabrice Bellard's LZEXE (versions 0.90 and 0.91)
 * - **EXEPACK**: Microsoft's EXE compressor
 * - **Knowledge Dynamics**: DIET-style compression
 *
 * @par Usage Pattern:
 * Decompressors are typically used via the factory function:
 * @code
 * auto mz = libexe::mz_file::from_file("packed.exe");
 * if (mz.is_compressed()) {
 *     auto decomp = libexe::create_decompressor(mz.get_compression());
 *     auto result = decomp->decompress(mz.code_section());
 *     // result.code contains decompressed executable
 *     // result.initial_cs/ip contains entry point
 * }
 * @endcode
 *
 * @see pklite, lzexe, exepack, knowledge_dynamics, mz_file
 */

#ifndef LIBEXE_DECOMPRESSORS_DECOMPRESSOR_HPP
#define LIBEXE_DECOMPRESSORS_DECOMPRESSOR_HPP

#include <libexe/export.hpp>
#include <span>
#include <vector>
#include <memory>

namespace libexe {

/**
 * @brief Compression types for DOS executable packers.
 *
 * Identifies the compression algorithm used to pack a DOS executable.
 * Detection is typically done by examining signature bytes at the
 * entry point of the executable.
 *
 * @note For PE files, different packer types apply (UPX, ASPack, etc.)
 *       which are not covered by this enumeration.
 */
enum class compression_type {
    NONE,                ///< Not compressed
    PKLITE_STANDARD,     ///< PKWare LITE standard compression
    PKLITE_EXTRA,        ///< PKWare LITE with extra/maximum compression
    LZEXE_090,           ///< LZEXE version 0.90
    LZEXE_091,           ///< LZEXE version 0.91
    EXEPACK,             ///< Microsoft EXEPACK
    KNOWLEDGE_DYNAMICS   ///< Knowledge Dynamics DIET-style compressor
};

/**
 * @brief Result of a decompression operation.
 *
 * Contains the decompressed code along with all MZ header values
 * needed to reconstruct the original executable.
 *
 * @par Header Reconstruction:
 * The decompressed executable can be reconstructed by:
 * 1. Creating a new MZ header with the values from this struct
 * 2. Adding the relocation table entries
 * 3. Appending the decompressed code
 */
struct decompression_result {
    std::vector <uint8_t> code;           ///< Decompressed executable code
    std::vector <uint8_t> extra_header;   ///< Additional header data (if any)

    uint16_t initial_cs = 0;              ///< Original CS register value
    uint16_t initial_ip = 0;              ///< Original IP register (entry point)
    uint16_t initial_ss = 0;              ///< Original SS register value
    uint16_t initial_sp = 0;              ///< Original SP register value

    uint16_t min_extra_paragraphs = 0;    ///< Minimum memory (e_minalloc)
    uint16_t max_extra_paragraphs = 0xFFFF; ///< Maximum memory (e_maxalloc)
    uint16_t header_paragraphs = 0;       ///< Header size (e_cparhdr)
    uint16_t checksum = 0;                ///< File checksum (e_csum)

    /**
     * @brief Relocation table entries.
     *
     * Each pair contains (segment, offset) for a relocation entry.
     * These are segment:offset addresses that need fixup when loading.
     */
    std::vector <std::pair <uint16_t, uint16_t>> relocations;
};

/**
 * @brief Abstract base class for executable decompressors.
 *
 * Provides a common interface for decompressing packed DOS executables.
 * Concrete implementations exist for each supported compression format:
 * - pklite_decompressor
 * - lzexe_decompressor
 * - exepack_decompressor
 * - knowledge_dynamics_decompressor
 *
 * @par Thread Safety:
 * Decompressor instances are stateless after construction and can be
 * used concurrently from multiple threads for decompression operations.
 *
 * @par Error Handling:
 * Decompression errors throw std::runtime_error with a descriptive message.
 * Invalid input data or corrupted compressed streams will result in exceptions.
 */
class LIBEXE_EXPORT decompressor {
    public:
        /// @brief Deleted copy constructor (decompressors are non-copyable).
        decompressor(const decompressor&) = delete;

        /// @brief Deleted copy assignment (decompressors are non-copyable).
        decompressor& operator=(const decompressor&) = delete;

        /// @brief Virtual destructor for proper cleanup.
        virtual ~decompressor() = default;

        /**
         * @brief Decompress packed executable data.
         *
         * Takes the compressed code section from an MZ file and returns
         * the decompressed result including the original header values.
         *
         * @param compressed_data The compressed executable data.
         * @return Decompression result containing code and header values.
         * @throws std::runtime_error If decompression fails due to
         *         invalid or corrupted data.
         */
        virtual decompression_result decompress(std::span <const uint8_t> compressed_data) = 0;

        /**
         * @brief Get human-readable name for this decompressor.
         * @return String describing this decompressor (e.g., "PKLITE", "LZEXE 0.91").
         */
        [[nodiscard]] virtual const char* name() const = 0;

    protected:
        /// @brief Default constructor (protected, use create_decompressor factory).
        decompressor() = default;

        /// @brief Move constructor (protected).
        decompressor(decompressor&&) = default;

        /// @brief Move assignment operator (protected).
        decompressor& operator=(decompressor&&) = default;
};

/**
 * @brief Factory function to create a decompressor for the specified type.
 *
 * Creates the appropriate decompressor instance based on the compression
 * type detected in the executable.
 *
 * @param type The compression type to create a decompressor for.
 * @return Unique pointer to the decompressor, or nullptr if type is NONE.
 * @throws std::invalid_argument If type is unknown.
 *
 * @par Example:
 * @code
 * auto decomp = libexe::create_decompressor(compression_type::PKLITE_STANDARD);
 * if (decomp) {
 *     auto result = decomp->decompress(data);
 * }
 * @endcode
 */
LIBEXE_EXPORT std::unique_ptr <decompressor>
create_decompressor(compression_type type);

} // namespace libexe

#endif // LIBEXE_DECOMPRESSORS_DECOMPRESSOR_HPP
