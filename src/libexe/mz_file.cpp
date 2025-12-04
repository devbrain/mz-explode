// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/mz_file.hpp>
#include <fstream>
#include <stdexcept>
#include <cstring>

namespace libexe {

// DOS MZ signature
static constexpr uint16_t MZ_SIGNATURE = 0x5A4D;  // "MZ"

// Helper to read file into memory
static std::vector<uint8_t> read_file_to_memory(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + path.string());
    }

    auto size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Cannot read file: " + path.string());
    }

    return buffer;
}

// Factory methods
mz_file mz_file::from_file(const std::filesystem::path& path) {
    auto data = read_file_to_memory(path);
    return from_memory(data);
}

mz_file mz_file::from_memory(std::span<const uint8_t> data) {
    if (data.size() < 28) {  // Minimum MZ header size
        throw std::runtime_error("File too small to be a valid MZ executable");
    }

    // Check MZ signature
    uint16_t signature;
    std::memcpy(&signature, data.data(), sizeof(signature));
    if (signature != MZ_SIGNATURE && signature != 0x4D5A) {  // "ZM" alternate
        throw std::runtime_error("Invalid MZ signature");
    }

    mz_file file;
    file.data_.assign(data.begin(), data.end());

    // TODO: Parse MZ header properly using DataScript-generated parser
    // For now, just store the data
    file.compression_ = compression_type::NONE;

    return file;
}

// Interface implementation
format_type mz_file::get_format() const {
    return format_type::MZ_DOS;
}

std::string_view mz_file::format_name() const {
    return "MZ (DOS Executable)";
}

std::span<const uint8_t> mz_file::code_section() const {
    // TODO: Calculate actual code section from MZ header
    // For now, return everything after minimum header
    if (data_.size() > 28) {
        return std::span<const uint8_t>(data_.data() + 28, data_.size() - 28);
    }
    return std::span<const uint8_t>();
}

// Compression detection
bool mz_file::is_compressed() const {
    return compression_ != compression_type::NONE;
}

compression_type mz_file::get_compression() const {
    return compression_;
}

// DOS header accessors (stub implementations)
uint16_t mz_file::initial_cs() const {
    // TODO: Read from parsed MZ header
    return 0;
}

uint16_t mz_file::initial_ip() const {
    // TODO: Read from parsed MZ header
    return 0;
}

uint16_t mz_file::initial_ss() const {
    // TODO: Read from parsed MZ header
    return 0;
}

uint16_t mz_file::initial_sp() const {
    // TODO: Read from parsed MZ header
    return 0;
}

uint16_t mz_file::min_extra_paragraphs() const {
    // TODO: Read from parsed MZ header
    return 0;
}

uint16_t mz_file::max_extra_paragraphs() const {
    // TODO: Read from parsed MZ header
    return 0;
}

uint16_t mz_file::relocation_count() const {
    // TODO: Read from parsed MZ header
    return 0;
}

uint16_t mz_file::header_paragraphs() const {
    // TODO: Read from parsed MZ header
    return 0;
}

} // namespace libexe
