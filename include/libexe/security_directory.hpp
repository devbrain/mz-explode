// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_SECURITY_DIRECTORY_HPP
#define LIBEXE_SECURITY_DIRECTORY_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <vector>
#include <span>

namespace libexe {

/**
 * Certificate Revision
 *
 * Identifies the version of the WIN_CERTIFICATE structure.
 */
enum class certificate_revision : uint16_t {
    REVISION_1_0 = 0x0100,  // Version 1.0 (legacy)
    REVISION_2_0 = 0x0200   // Version 2.0 (current standard)
};

/**
 * Certificate Type
 *
 * Identifies the type of content in the certificate.
 */
enum class certificate_type : uint16_t {
    X509             = 0x0001,  // X.509 certificate
    PKCS_SIGNED_DATA = 0x0002,  // PKCS#7 SignedData (Authenticode)
    RESERVED_1       = 0x0003,  // Reserved
    TS_STACK_SIGNED  = 0x0004   // Terminal Server Protocol Stack Certificate
};

/**
 * Security Certificate Entry
 *
 * Represents a single certificate entry in the security directory.
 * Used for Authenticode code signing.
 *
 * The certificate data is typically a PKCS#7 SignedData structure containing:
 * - Signer information (who signed the code)
 * - Timestamp (when it was signed)
 * - Certificate chain (root CA, intermediate CAs, code signing cert)
 * - Signature over the PE file hash
 */
struct LIBEXE_EXPORT security_certificate {
    /// Total length of certificate entry (including header and data)
    uint32_t length = 0;

    /// Certificate revision (usually REVISION_2_0)
    certificate_revision revision = certificate_revision::REVISION_2_0;

    /// Certificate type (usually PKCS_SIGNED_DATA for Authenticode)
    certificate_type type = certificate_type::PKCS_SIGNED_DATA;

    /// Raw certificate data (PKCS#7 SignedData for Authenticode)
    std::vector<uint8_t> certificate_data;

    /**
     * Check if this is a valid Authenticode signature
     * @return True if type is PKCS_SIGNED_DATA
     */
    [[nodiscard]] bool is_authenticode() const {
        return type == certificate_type::PKCS_SIGNED_DATA;
    }

    /**
     * Check if this is an X.509 certificate
     * @return True if type is X509
     */
    [[nodiscard]] bool is_x509() const {
        return type == certificate_type::X509;
    }

    /**
     * Get certificate data size in bytes
     * @return Size of certificate data
     */
    [[nodiscard]] size_t data_size() const {
        return certificate_data.size();
    }

    /**
     * Get certificate data as span
     * @return Span view of certificate data
     */
    [[nodiscard]] std::span<const uint8_t> data() const {
        return certificate_data;
    }

    /**
     * Check if certificate entry is valid
     * @return True if length and data are consistent
     */
    [[nodiscard]] bool is_valid() const {
        return length >= 8 && !certificate_data.empty();
    }
};

/**
 * Security Directory (Certificate Table)
 *
 * Contains Authenticode code signing certificates.
 * Data directory index: 4 (IMAGE_DIRECTORY_ENTRY_SECURITY)
 *
 * IMPORTANT: Unlike other data directories, the RVA field in the data directory
 * entry for the security directory is actually a file offset, not an RVA!
 *
 * The security directory is not loaded into memory - it exists only in the PE file.
 * This is because the signature must cover the entire file, including headers,
 * and cannot be part of the loaded image.
 *
 * Structure:
 * - Array of WIN_CERTIFICATE entries
 * - Each entry is 8-byte aligned
 * - Entries are not null-terminated (use size field to find end)
 */
struct LIBEXE_EXPORT security_directory {
    /// Security certificates (typically 1 Authenticode signature)
    std::vector<security_certificate> certificates;

    /**
     * Get number of certificates
     * @return Count of certificates
     */
    [[nodiscard]] size_t certificate_count() const {
        return certificates.size();
    }

    /**
     * Check if directory is empty
     * @return True if no certificates exist
     */
    [[nodiscard]] bool empty() const {
        return certificates.empty();
    }

    /**
     * Check if any certificate is an Authenticode signature
     * @return True if at least one PKCS_SIGNED_DATA certificate exists
     */
    [[nodiscard]] bool has_authenticode() const;

    /**
     * Get first Authenticode certificate
     * @return Pointer to first Authenticode certificate, or nullptr if none
     */
    [[nodiscard]] const security_certificate* get_authenticode() const;

    /**
     * Get total size of all certificates in bytes
     * @return Sum of all certificate lengths
     */
    [[nodiscard]] size_t total_size() const;
};

} // namespace libexe

#endif // LIBEXE_SECURITY_DIRECTORY_HPP
