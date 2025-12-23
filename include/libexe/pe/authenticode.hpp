// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_PE_AUTHENTICODE_HPP
#define LIBEXE_PE_AUTHENTICODE_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <vector>
#include <span>
#include <string>
#include <optional>

// Disable MSVC warning C4251: 'member': class 'std::...' needs to have dll-interface
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

namespace libexe {

/**
 * Hash algorithm used in Authenticode signature
 */
enum class authenticode_hash_algorithm {
    UNKNOWN,
    MD5,        // 1.2.840.113549.2.5 (deprecated, insecure)
    SHA1,       // 1.3.14.3.2.26 (deprecated but still common)
    SHA256,     // 2.16.840.1.101.3.4.2.1 (recommended)
    SHA384,     // 2.16.840.1.101.3.4.2.2
    SHA512      // 2.16.840.1.101.3.4.2.3
};

/**
 * Convert hash algorithm to string
 */
LIBEXE_EXPORT const char* hash_algorithm_name(authenticode_hash_algorithm alg);

/**
 * X.509 Distinguished Name components
 */
struct LIBEXE_EXPORT x509_name {
    std::string common_name;         // CN
    std::string organization;        // O
    std::string organizational_unit; // OU
    std::string country;             // C
    std::string state;               // ST
    std::string locality;            // L
    std::string email;               // E or emailAddress

    /// Get formatted string representation
    [[nodiscard]] std::string to_string() const;

    /// Check if name is empty (no components set)
    [[nodiscard]] bool empty() const;
};

/**
 * X.509 Certificate information (extracted from PKCS#7)
 */
struct LIBEXE_EXPORT x509_certificate_info {
    /// Certificate serial number (hex string)
    std::string serial_number;

    /// Subject (who the certificate was issued to)
    x509_name subject;

    /// Issuer (who issued the certificate)
    x509_name issuer;

    /// Validity period - Not Before (Unix timestamp, 0 if unknown)
    int64_t not_before = 0;

    /// Validity period - Not After (Unix timestamp, 0 if unknown)
    int64_t not_after = 0;

    /// Signature algorithm OID
    std::string signature_algorithm;

    /// Raw certificate data (DER encoded)
    std::vector<uint8_t> raw_data;

    /// Check if this appears to be a code signing certificate
    [[nodiscard]] bool is_code_signing() const;

    /// Check if certificate has expired (compared to current time)
    [[nodiscard]] bool is_expired() const;

    /// Check if certificate is self-signed (subject == issuer)
    [[nodiscard]] bool is_self_signed() const;
};

/**
 * Signer information from PKCS#7 SignedData
 */
struct LIBEXE_EXPORT authenticode_signer_info {
    /// Signer's issuer name
    x509_name issuer;

    /// Signer's serial number (hex string)
    std::string serial_number;

    /// Digest algorithm used for signing
    authenticode_hash_algorithm digest_algorithm = authenticode_hash_algorithm::UNKNOWN;

    /// Signature algorithm OID
    std::string signature_algorithm;

    /// Check if this signer uses deprecated algorithms
    [[nodiscard]] bool uses_deprecated_algorithm() const;
};

/**
 * Timestamp information (countersignature)
 */
struct LIBEXE_EXPORT authenticode_timestamp {
    /// Timestamp value (Unix timestamp)
    int64_t timestamp = 0;

    /// Timestamp authority name
    x509_name authority;

    /// Digest algorithm used for timestamp
    authenticode_hash_algorithm digest_algorithm = authenticode_hash_algorithm::UNKNOWN;

    /// Type of timestamp (RFC 3161 or legacy Authenticode)
    bool is_rfc3161 = false;

    /// Check if timestamp is valid (non-zero)
    [[nodiscard]] bool is_valid() const { return timestamp != 0; }

    /// Get timestamp as formatted string
    [[nodiscard]] std::string to_string() const;
};

/**
 * Parsed Authenticode signature information
 *
 * This represents the parsed content of a PKCS#7 SignedData structure
 * used for Authenticode code signing. It extracts key information without
 * performing cryptographic verification (that requires external crypto libs).
 *
 * The analysis includes:
 * - Digest algorithm used
 * - Signer information
 * - Certificate chain
 * - Timestamp (if present)
 * - Security assessment (deprecated algorithms, etc.)
 */
struct LIBEXE_EXPORT authenticode_signature {
    /// Content type OID (should be 1.3.6.1.4.1.311.2.1.4 for Authenticode)
    std::string content_type;

    /// Digest algorithm used for the PE file hash
    authenticode_hash_algorithm digest_algorithm = authenticode_hash_algorithm::UNKNOWN;

    /// Signer information
    std::vector<authenticode_signer_info> signers;

    /// Certificates in the signature (certificate chain)
    std::vector<x509_certificate_info> certificates;

    /// Timestamp (countersignature) if present
    std::optional<authenticode_timestamp> timestamp;

    /// Raw PKCS#7 version number
    int32_t version = 0;

    /// Check if this is a valid Authenticode signature
    /// (has correct content type and at least one signer)
    [[nodiscard]] bool is_valid() const;

    /// Check if signature uses deprecated algorithms (MD5, SHA1)
    [[nodiscard]] bool uses_deprecated_algorithm() const;

    /// Check if signature has a timestamp
    [[nodiscard]] bool has_timestamp() const { return timestamp.has_value(); }

    /// Get the signing certificate (first certificate that matches signer)
    [[nodiscard]] const x509_certificate_info* signing_certificate() const;

    /// Get certificate chain depth
    [[nodiscard]] size_t certificate_chain_depth() const { return certificates.size(); }

    /// Check if certificate chain includes a self-signed root
    [[nodiscard]] bool has_root_certificate() const;

    /// Get security assessment summary
    [[nodiscard]] std::string security_summary() const;
};

/**
 * Authenticode signature analyzer
 *
 * Parses PKCS#7 SignedData structures to extract Authenticode signature
 * information. This is a read-only analysis tool - it does not verify
 * cryptographic signatures (that would require OpenSSL or similar).
 *
 * What it DOES:
 * - Extract digest algorithm (SHA1, SHA256, etc.)
 * - Extract signer information (name, serial number)
 * - Extract certificate chain information
 * - Extract timestamp information
 * - Identify deprecated/weak algorithms
 *
 * What it does NOT do:
 * - Verify cryptographic signatures
 * - Validate certificate chains against root stores
 * - Check certificate revocation
 */
class LIBEXE_EXPORT authenticode_analyzer {
public:
    /**
     * Parse Authenticode signature from PKCS#7 SignedData blob
     *
     * @param pkcs7_data Raw PKCS#7 SignedData (DER encoded)
     * @return Parsed signature information, or nullopt if parsing fails
     */
    [[nodiscard]] static std::optional<authenticode_signature> parse(
        std::span<const uint8_t> pkcs7_data
    );

    /**
     * Check if data appears to be a valid PKCS#7 SignedData structure
     *
     * @param data Data to check
     * @return True if data starts with valid ASN.1 SEQUENCE and contains SignedData OID
     */
    [[nodiscard]] static bool is_pkcs7_signed_data(std::span<const uint8_t> data);

    /**
     * Get digest algorithm from OID
     *
     * @param oid Algorithm OID as string (e.g., "1.2.840.113549.2.5")
     * @return Hash algorithm enum value
     */
    [[nodiscard]] static authenticode_hash_algorithm algorithm_from_oid(const std::string& oid);

private:
    // ASN.1 DER parsing helpers
    struct asn1_element {
        uint8_t tag = 0;
        size_t header_length = 0;
        size_t content_length = 0;
        const uint8_t* content = nullptr;

        [[nodiscard]] bool is_sequence() const { return tag == 0x30; }
        [[nodiscard]] bool is_set() const { return tag == 0x31; }
        [[nodiscard]] bool is_integer() const { return tag == 0x02; }
        [[nodiscard]] bool is_oid() const { return tag == 0x06; }
        [[nodiscard]] bool is_string() const {
            return tag == 0x0C || tag == 0x13 || tag == 0x14 ||
                   tag == 0x16 || tag == 0x1A || tag == 0x1E;
        }
        [[nodiscard]] bool is_utc_time() const { return tag == 0x17; }
        [[nodiscard]] bool is_generalized_time() const { return tag == 0x18; }
        [[nodiscard]] bool is_context_specific(uint8_t n) const {
            return tag == (0xA0 | n);
        }

        [[nodiscard]] std::span<const uint8_t> data() const {
            return {content, content_length};
        }
    };

    static bool parse_asn1_element(const uint8_t* data, size_t length, asn1_element& element);
    static std::string parse_oid(std::span<const uint8_t> data);
    static std::string parse_string(const asn1_element& element);
    static int64_t parse_time(const asn1_element& element);
    static std::string parse_integer_as_hex(std::span<const uint8_t> data);
    static x509_name parse_x509_name(std::span<const uint8_t> data);
    static std::optional<x509_certificate_info> parse_certificate(std::span<const uint8_t> data);
    static std::optional<authenticode_signer_info> parse_signer_info(std::span<const uint8_t> data);
    static std::optional<authenticode_timestamp> find_timestamp(std::span<const uint8_t> signer_info_data);
};

} // namespace libexe

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // LIBEXE_PE_AUTHENTICODE_HPP
