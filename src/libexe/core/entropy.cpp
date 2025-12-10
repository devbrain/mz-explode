// libexe - Modern executable file analysis library
// Entropy calculation implementation

#include <libexe/core/entropy.hpp>
#include <cmath>

namespace libexe {

double entropy_calculator::calculate(std::span<const uint8_t> data) {
    if (data.empty()) {
        return 0.0;
    }

    // Count byte frequencies
    auto freq = byte_frequency(data);

    // Calculate entropy: H(X) = -Σ p(x) * log2(p(x))
    double entropy = 0.0;
    double size = static_cast<double>(data.size());

    for (size_t count : freq) {
        if (count > 0) {
            double p = static_cast<double>(count) / size;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

bool entropy_calculator::is_high_entropy(std::span<const uint8_t> data, double threshold) {
    return calculate(data) >= threshold;
}

bool entropy_calculator::is_encrypted_or_random(std::span<const uint8_t> data) {
    return calculate(data) >= VERY_HIGH_ENTROPY_THRESHOLD;
}

std::array<size_t, 256> entropy_calculator::byte_frequency(std::span<const uint8_t> data) {
    std::array<size_t, 256> freq{};
    for (uint8_t byte : data) {
        ++freq[byte];
    }
    return freq;
}

double entropy_calculator::chi_squared(std::span<const uint8_t> data) {
    if (data.empty()) {
        return 0.0;
    }

    auto freq = byte_frequency(data);
    double expected = static_cast<double>(data.size()) / 256.0;
    double chi_sq = 0.0;

    for (size_t count : freq) {
        double diff = static_cast<double>(count) - expected;
        chi_sq += (diff * diff) / expected;
    }

    return chi_sq;
}

const char* entropy_calculator::classify(double entropy) {
    if (entropy >= VERY_HIGH_ENTROPY_THRESHOLD) {
        return "Very High (encrypted/random)";
    } else if (entropy >= HIGH_ENTROPY_THRESHOLD) {
        return "High (packed/compressed)";
    } else if (entropy >= 5.0) {
        return "Normal (code/data)";
    } else if (entropy >= 3.0) {
        return "Low (text/sparse data)";
    } else {
        return "Very Low (sparse/empty)";
    }
}

} // namespace libexe
