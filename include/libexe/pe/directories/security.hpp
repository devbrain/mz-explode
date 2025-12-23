// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_PE_DIRECTORIES_SECURITY_HPP
#define LIBEXE_PE_DIRECTORIES_SECURITY_HPP

#include <libexe/export.hpp>
#include <libexe/pe/section.hpp>
#include <cstdint>
#include <vector>
#include <span>

// Disable MSVC warning C4251: 'member': class 'std::...' needs to have dll-interface
// This warning is benign for header-only STL types when both library and client
// use the same compiler and runtime
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

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

/**
 * Parser for PE Security Directory (Certificate Table) - Data Directory Index 4
 *
 * The security directory contains Authenticode code signing certificates used
 * to verify the integrity and authenticity of the executable.
 *
 * CRITICAL: The security directory is special - its "RVA" field in the data
 * directory is actually a FILE OFFSET, not an RVA! This is the only data
 * directory that uses file offsets instead of RVAs.
 *
 * Structure:
 * - Array of WIN_CERTIFICATE entries
 * - Each entry has an 8-byte header followed by variable-length certificate data
 * - Entries are 8-byte aligned (padded if necessary)
 * - No null terminator - parse until directory size is consumed
 *
 * Certificate types:
 * - WIN_CERT_TYPE_PKCS_SIGNED_DATA (0x0002): Most common, PKCS#7 SignedData (Authenticode)
 * - WIN_CERT_TYPE_X509 (0x0001): X.509 certificate (deprecated)
 * - WIN_CERT_TYPE_TS_STACK_SIGNED (0x0004): Terminal Server Protocol Stack
 */
class LIBEXE_EXPORT security_directory_parser {
public:
    /**
     * Parse security directory from PE file data
     *
     * @param file_data Complete PE file data
     * @param security_offset File offset to security directory (NOT an RVA!)
     * @param security_size Size of security directory in bytes
     * @return Parsed security directory
     * @throws std::runtime_error if parsing fails or data is invalid
     */
    static security_directory parse(
        std::span<const uint8_t> file_data,
        uint32_t security_offset,
        uint32_t security_size
    );

private:
    /**
     * Parse a single WIN_CERTIFICATE entry
     * @param ptr Pointer to certificate entry start
     * @param end End of valid data range
     * @return Parsed certificate
     * @throws std::runtime_error if data is invalid
     */
    static security_certificate parse_certificate(
        const uint8_t* ptr,
        const uint8_t* end
    );

    /**
     * Calculate 8-byte aligned size
     * @param size Unaligned size
     * @return Size rounded up to next 8-byte boundary
     */
    static uint32_t align_to_8_bytes(uint32_t size);
};

} // namespace libexe

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // LIBEXE_PE_DIRECTORIES_SECURITY_HPP
