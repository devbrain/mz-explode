// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/pe/directories/security.hpp>
#include <stdexcept>
#include <cstring>

namespace libexe {

namespace {
    // Read 16-bit little-endian value
    uint16_t read_u16(const uint8_t* ptr) {
        return static_cast<uint16_t>(static_cast<uint16_t>(ptr[0]) |
               (static_cast<uint16_t>(ptr[1]) << 8));
    }

    // Read 32-bit little-endian value
    uint32_t read_u32(const uint8_t* ptr) {
        return static_cast<uint32_t>(ptr[0]) |
               (static_cast<uint32_t>(ptr[1]) << 8) |
               (static_cast<uint32_t>(ptr[2]) << 16) |
               (static_cast<uint32_t>(ptr[3]) << 24);
    }
}

security_directory security_directory_parser::parse(
    std::span<const uint8_t> file_data,
    uint32_t security_offset,
    uint32_t security_size
) {
    security_directory result;

    // Empty directory is valid
    if (security_offset == 0 || security_size == 0) {
        return result;
    }

    // Validate bounds
    if (security_offset >= file_data.size() ||
        security_offset + security_size > file_data.size()) {
        throw std::runtime_error("Security directory exceeds file bounds");
    }

    const uint8_t* ptr = file_data.data() + security_offset;
    const uint8_t* end = ptr + security_size;
    uint32_t bytes_consumed = 0;

    // Parse certificates until we've consumed the entire directory
    while (bytes_consumed < security_size) {
        // Ensure we have enough space for certificate header (8 bytes)
        if (ptr + 8 > end) {
            break;
        }

        // Parse certificate entry
        security_certificate cert = parse_certificate(ptr, end);

        if (cert.is_valid()) {
            // Calculate aligned size for this entry
            uint32_t aligned_size = align_to_8_bytes(cert.length);

            // Move to next certificate (8-byte aligned)
            ptr += aligned_size;
            bytes_consumed += aligned_size;

            result.certificates.push_back(std::move(cert));
        } else {
            // Invalid certificate, stop parsing
            break;
        }

        // Safety limit: max 10 certificates
        if (result.certificates.size() >= 10) {
            break;
        }
    }

    return result;
}

security_certificate security_directory_parser::parse_certificate(
    const uint8_t* ptr,
    const uint8_t* end
) {
    security_certificate cert;

    // Ensure we have enough data for WIN_CERTIFICATE header (8 bytes)
    if (ptr + 8 > end) {
        throw std::runtime_error("Insufficient data for WIN_CERTIFICATE header");
    }

    // Parse WIN_CERTIFICATE header
    cert.length = read_u32(ptr);
    cert.revision = static_cast<certificate_revision>(read_u16(ptr + 4));
    cert.type = static_cast<certificate_type>(read_u16(ptr + 6));

    // Validate length
    if (cert.length < 8) {
        throw std::runtime_error("Invalid certificate length (less than header size)");
    }

    // Calculate certificate data size (length - header size)
    uint32_t data_size = cert.length - 8;

    // Validate we have enough data
    if (ptr + 8 + data_size > end) {
        throw std::runtime_error("Certificate data exceeds directory bounds");
    }

    // Safety limit: max 10 MB per certificate
    if (data_size > 10 * 1024 * 1024) {
        throw std::runtime_error("Certificate data too large (> 10 MB)");
    }

    // Copy certificate data
    if (data_size > 0) {
        cert.certificate_data.resize(data_size);
        std::memcpy(cert.certificate_data.data(), ptr + 8, data_size);
    }

    return cert;
}

uint32_t security_directory_parser::align_to_8_bytes(uint32_t size) {
    return (size + 7) & ~7u;
}

} // namespace libexe
