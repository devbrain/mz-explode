// libexe - Modern executable file analysis library
// Entropy calculation for packing/encryption detection

#ifndef LIBEXE_CORE_ENTROPY_HPP
#define LIBEXE_CORE_ENTROPY_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <span>
#include <cmath>
#include <array>
#include <string>

namespace libexe {

/**
 * Entropy calculation utilities
 *
 * Shannon entropy is used to detect packed/encrypted data:
 * - Plain text/code: ~4.5-5.5 bits
 * - Compressed data: ~7.0-7.9 bits
 * - Encrypted data: ~7.9-8.0 bits
 * - Random data: ~8.0 bits (maximum)
 *
 * High entropy sections in executables often indicate:
 * - Packed/compressed code (UPX, ASPack, etc.)
 * - Encrypted data or code
 * - Embedded resources (images, etc.)
 */
class LIBEXE_EXPORT entropy_calculator {
public:
    /// Maximum possible entropy for byte data (log2(256) = 8 bits)
    static constexpr double MAX_ENTROPY = 8.0;

    /// Threshold for considering data as "high entropy" (likely packed/encrypted)
    static constexpr double HIGH_ENTROPY_THRESHOLD = 7.0;

    /// Threshold for considering data as "very high entropy" (likely encrypted/random)
    static constexpr double VERY_HIGH_ENTROPY_THRESHOLD = 7.9;

    /**
     * Calculate Shannon entropy of data
     *
     * Shannon entropy H(X) = -Σ p(x) * log2(p(x))
     * where p(x) is the probability of each byte value.
     *
     * @param data Data to analyze
     * @return Entropy value in range [0.0, 8.0] bits
     */
    [[nodiscard]] static double calculate(std::span<const uint8_t> data);

    /**
     * Check if data has high entropy (likely packed/compressed)
     *
     * @param data Data to analyze
     * @param threshold Entropy threshold (default: HIGH_ENTROPY_THRESHOLD)
     * @return true if entropy exceeds threshold
     */
    [[nodiscard]] static bool is_high_entropy(
        std::span<const uint8_t> data,
        double threshold = HIGH_ENTROPY_THRESHOLD
    );

    /**
     * Check if data appears encrypted or random
     *
     * @param data Data to analyze
     * @return true if entropy is very high (>= 7.9)
     */
    [[nodiscard]] static bool is_encrypted_or_random(std::span<const uint8_t> data);

    /**
     * Get byte frequency distribution
     *
     * @param data Data to analyze
     * @return Array of 256 counts, one for each byte value
     */
    [[nodiscard]] static std::array<size_t, 256> byte_frequency(std::span<const uint8_t> data);

    /**
     * Calculate chi-squared statistic for randomness test
     *
     * The chi-squared test compares observed byte frequencies to expected
     * uniform distribution. Lower values indicate more uniform (random) data.
     *
     * @param data Data to analyze
     * @return Chi-squared statistic
     */
    [[nodiscard]] static double chi_squared(std::span<const uint8_t> data);

    /**
     * Classify data based on entropy
     *
     * @param entropy Entropy value to classify
     * @return Human-readable classification string
     */
    [[nodiscard]] static const char* classify(double entropy);
};

/**
 * Section entropy analysis result
 */
struct LIBEXE_EXPORT section_entropy {
    std::string name;           ///< Section name
    double entropy = 0.0;       ///< Shannon entropy (0.0-8.0 bits)
    size_t size = 0;            ///< Section size in bytes
    bool is_high_entropy = false;      ///< Entropy >= 7.0
    bool is_very_high_entropy = false; ///< Entropy >= 7.9

    /**
     * Get classification string
     * @return "Normal", "High (packed?)", or "Very High (encrypted?)"
     */
    [[nodiscard]] const char* classification() const {
        return entropy_calculator::classify(entropy);
    }
};

} // namespace libexe

#endif // LIBEXE_CORE_ENTROPY_HPP
