// libexe - Modern executable file analysis library
// Copyright (c) 2024
// Internal file utilities

#ifndef LIBEXE_CORE_FILE_UTILS_HPP
#define LIBEXE_CORE_FILE_UTILS_HPP

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <vector>

namespace libexe::internal {

/**
 * Read entire file contents into memory
 *
 * @param path Path to file to read
 * @return Vector containing file contents
 * @throws std::runtime_error if file cannot be opened or read
 */
inline std::vector<uint8_t> read_file_to_memory(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + path.string());
    }

    auto size = file.tellg();
    if (size < 0) {
        throw std::runtime_error("Cannot determine file size: " + path.string());
    }

    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (size > 0 && !file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Cannot read file: " + path.string());
    }

    return buffer;
}

/**
 * Safe multiplication with overflow check
 *
 * @param a First operand
 * @param b Second operand
 * @param result Output parameter for result
 * @return true if multiplication succeeded, false if it would overflow
 */
inline bool safe_multiply(uint32_t a, uint32_t b, uint32_t& result) {
    if (a != 0 && b > UINT32_MAX / a) {
        return false;  // Would overflow
    }
    result = a * b;
    return true;
}

/**
 * Safe addition with overflow check
 *
 * @param a First operand
 * @param b Second operand
 * @param result Output parameter for result
 * @return true if addition succeeded, false if it would overflow
 */
inline bool safe_add(uint32_t a, uint32_t b, uint32_t& result) {
    if (a > UINT32_MAX - b) {
        return false;  // Would overflow
    }
    result = a + b;
    return true;
}

} // namespace libexe::internal

#endif // LIBEXE_CORE_FILE_UTILS_HPP
