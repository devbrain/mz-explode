// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/pe/authenticode.hpp>
#include <algorithm>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace libexe {

// =============================================================================
// Hash Algorithm Utilities
// =============================================================================

const char* hash_algorithm_name(authenticode_hash_algorithm alg) {
    switch (alg) {
        case authenticode_hash_algorithm::MD5:    return "MD5";
        case authenticode_hash_algorithm::SHA1:   return "SHA1";
        case authenticode_hash_algorithm::SHA256: return "SHA256";
        case authenticode_hash_algorithm::SHA384: return "SHA384";
        case authenticode_hash_algorithm::SHA512: return "SHA512";
        default: return "Unknown";
    }
}

// =============================================================================
// x509_name Implementation
// =============================================================================

std::string x509_name::to_string() const {
    std::ostringstream oss;
    bool first = true;

    auto append = [&](const std::string& label, const std::string& value) {
        if (!value.empty()) {
            if (!first) oss << ", ";
            oss << label << "=" << value;
            first = false;
        }
    };

    append("CN", common_name);
    append("O", organization);
    append("OU", organizational_unit);
    append("L", locality);
    append("ST", state);
    append("C", country);

    return oss.str();
}

bool x509_name::empty() const {
    return common_name.empty() && organization.empty() &&
           organizational_unit.empty() && country.empty() &&
           state.empty() && locality.empty();
}

// =============================================================================
// x509_certificate_info Implementation
// =============================================================================

bool x509_certificate_info::is_code_signing() const {
    // Check if subject contains typical code signing indicators
    return subject.common_name.find("Code Sign") != std::string::npos ||
           subject.organizational_unit.find("Code Sign") != std::string::npos;
}

bool x509_certificate_info::is_expired() const {
    if (not_after == 0) return false;
    return std::time(nullptr) > not_after;
}

bool x509_certificate_info::is_self_signed() const {
    return subject.to_string() == issuer.to_string();
}

// =============================================================================
// authenticode_signer_info Implementation
// =============================================================================

bool authenticode_signer_info::uses_deprecated_algorithm() const {
    return digest_algorithm == authenticode_hash_algorithm::MD5 ||
           digest_algorithm == authenticode_hash_algorithm::SHA1;
}

// =============================================================================
// authenticode_timestamp Implementation
// =============================================================================

std::string authenticode_timestamp::to_string() const {
    if (timestamp == 0) return "No timestamp";

    std::time_t t = static_cast<std::time_t>(timestamp);
    std::tm* tm = std::gmtime(&t);
    if (!tm) return "Invalid timestamp";

    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", tm);
    return buf;
}

// =============================================================================
// authenticode_signature Implementation
// =============================================================================

// Expected Authenticode content type OID: 1.3.6.1.4.1.311.2.1.4 (SPC_INDIRECT_DATA_OBJID)
static constexpr const char* AUTHENTICODE_CONTENT_TYPE_OID = "1.3.6.1.4.1.311.2.1.4";

bool authenticode_signature::is_valid() const {
    return content_type == AUTHENTICODE_CONTENT_TYPE_OID && !signers.empty();
}

bool authenticode_signature::uses_deprecated_algorithm() const {
    if (digest_algorithm == authenticode_hash_algorithm::MD5 ||
        digest_algorithm == authenticode_hash_algorithm::SHA1) {
        return true;
    }

    for (const auto& signer : signers) {
        if (signer.uses_deprecated_algorithm()) {
            return true;
        }
    }

    return false;
}

const x509_certificate_info* authenticode_signature::signing_certificate() const {
    if (signers.empty() || certificates.empty()) {
        return nullptr;
    }

    // Find certificate matching first signer
    const auto& signer = signers[0];
    for (const auto& cert : certificates) {
        if (cert.serial_number == signer.serial_number &&
            cert.issuer.to_string() == signer.issuer.to_string()) {
            return &cert;
        }
    }

    // Return first certificate as fallback
    return &certificates[0];
}

bool authenticode_signature::has_root_certificate() const {
    for (const auto& cert : certificates) {
        if (cert.is_self_signed()) {
            return true;
        }
    }
    return false;
}

std::string authenticode_signature::security_summary() const {
    std::ostringstream oss;

    // Algorithm assessment
    oss << "Digest Algorithm: " << hash_algorithm_name(digest_algorithm);
    if (digest_algorithm == authenticode_hash_algorithm::MD5) {
        oss << " (INSECURE - MD5 is broken)";
    } else if (digest_algorithm == authenticode_hash_algorithm::SHA1) {
        oss << " (DEPRECATED - SHA1 has known weaknesses)";
    } else if (digest_algorithm == authenticode_hash_algorithm::SHA256 ||
               digest_algorithm == authenticode_hash_algorithm::SHA384 ||
               digest_algorithm == authenticode_hash_algorithm::SHA512) {
        oss << " (GOOD)";
    }
    oss << "\n";

    // Signers
    oss << "Signers: " << signers.size() << "\n";
    for (size_t i = 0; i < signers.size(); ++i) {
        oss << "  [" << i << "] " << signers[i].issuer.to_string() << "\n";
    }

    // Certificate chain
    oss << "Certificates: " << certificates.size() << "\n";
    for (size_t i = 0; i < certificates.size(); ++i) {
        oss << "  [" << i << "] " << certificates[i].subject.to_string();
        if (certificates[i].is_self_signed()) {
            oss << " (ROOT)";
        }
        if (certificates[i].is_expired()) {
            oss << " (EXPIRED)";
        }
        oss << "\n";
    }

    // Timestamp
    if (timestamp) {
        oss << "Timestamp: " << timestamp->to_string();
        if (timestamp->is_rfc3161) {
            oss << " (RFC 3161)";
        } else {
            oss << " (Legacy)";
        }
        oss << "\n";
    } else {
        oss << "Timestamp: None (signature may become invalid when certificate expires)\n";
    }

    return oss.str();
}

// =============================================================================
// authenticode_analyzer Implementation
// =============================================================================

// Well-known OIDs
namespace oid {
    // Hash algorithms
    constexpr const char* MD5 = "1.2.840.113549.2.5";
    constexpr const char* SHA1 = "1.3.14.3.2.26";
    constexpr const char* SHA256 = "2.16.840.1.101.3.4.2.1";
    constexpr const char* SHA384 = "2.16.840.1.101.3.4.2.2";
    constexpr const char* SHA512 = "2.16.840.1.101.3.4.2.3";

    // PKCS#7/CMS
    constexpr const char* SIGNED_DATA = "1.2.840.113549.1.7.2";
    constexpr const char* DATA = "1.2.840.113549.1.7.1";

    // Authenticode
    constexpr const char* SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4";

    // X.500 attribute types
    constexpr const char* COMMON_NAME = "2.5.4.3";
    constexpr const char* COUNTRY = "2.5.4.6";
    constexpr const char* LOCALITY = "2.5.4.7";
    constexpr const char* STATE = "2.5.4.8";
    constexpr const char* ORGANIZATION = "2.5.4.10";
    constexpr const char* ORG_UNIT = "2.5.4.11";
    constexpr const char* EMAIL = "1.2.840.113549.1.9.1";

    // PKCS#9 attributes
    constexpr const char* COUNTER_SIGNATURE = "1.2.840.113549.1.9.6";
    constexpr const char* MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
    constexpr const char* SIGNING_TIME = "1.2.840.113549.1.9.5";

    // RFC 3161 timestamp
    constexpr const char* TIMESTAMP_TOKEN = "1.2.840.113549.1.9.16.2.14";
}

bool authenticode_analyzer::parse_asn1_element(
    const uint8_t* data,
    size_t length,
    asn1_element& element
) {
    if (length < 2) return false;

    element.tag = data[0];
    size_t len_byte = data[1];
    size_t offset = 2;

    if (len_byte < 0x80) {
        // Short form length
        element.content_length = len_byte;
    } else if (len_byte == 0x80) {
        // Indefinite length (not supported)
        return false;
    } else {
        // Long form length
        size_t num_bytes = len_byte & 0x7F;
        if (num_bytes > 4 || offset + num_bytes > length) return false;

        element.content_length = 0;
        for (size_t i = 0; i < num_bytes; ++i) {
            element.content_length = (element.content_length << 8) | data[offset + i];
        }
        offset += num_bytes;
    }

    element.header_length = offset;
    element.content = data + offset;

    // Validate we have enough data
    if (offset + element.content_length > length) {
        return false;
    }

    return true;
}

std::string authenticode_analyzer::parse_oid(std::span<const uint8_t> data) {
    if (data.empty()) return "";

    std::ostringstream oss;

    // First byte encodes first two components
    oss << (data[0] / 40) << "." << (data[0] % 40);

    // Remaining bytes encode subsequent components (base-128)
    size_t value = 0;
    for (size_t i = 1; i < data.size(); ++i) {
        value = (value << 7) | (data[i] & 0x7F);
        if ((data[i] & 0x80) == 0) {
            oss << "." << value;
            value = 0;
        }
    }

    return oss.str();
}

std::string authenticode_analyzer::parse_string(const asn1_element& element) {
    if (!element.is_string() || element.content_length == 0) {
        return "";
    }

    // Handle different string types
    if (element.tag == 0x1E) {
        // BMPString (UTF-16BE)
        std::string result;
        for (size_t i = 0; i + 1 < element.content_length; i += 2) {
            uint16_t ch = (static_cast<uint16_t>(element.content[i]) << 8) |
                          element.content[i + 1];
            if (ch < 128) {
                result += static_cast<char>(ch);
            } else {
                result += '?';  // Non-ASCII
            }
        }
        return result;
    }

    // Other string types (UTF8String, PrintableString, IA5String, etc.)
    return std::string(reinterpret_cast<const char*>(element.content), element.content_length);
}

int64_t authenticode_analyzer::parse_time(const asn1_element& element) {
    if (element.content_length == 0) return 0;

    std::string time_str(reinterpret_cast<const char*>(element.content), element.content_length);

    std::tm tm = {};
    int year, month, day, hour, minute, second;

    if (element.is_utc_time()) {
        // YYMMDDhhmmssZ format
        if (time_str.length() < 12) return 0;

        year = (time_str[0] - '0') * 10 + (time_str[1] - '0');
        year += (year >= 50) ? 1900 : 2000;  // RFC 5280
        month = (time_str[2] - '0') * 10 + (time_str[3] - '0');
        day = (time_str[4] - '0') * 10 + (time_str[5] - '0');
        hour = (time_str[6] - '0') * 10 + (time_str[7] - '0');
        minute = (time_str[8] - '0') * 10 + (time_str[9] - '0');
        second = (time_str[10] - '0') * 10 + (time_str[11] - '0');
    } else if (element.is_generalized_time()) {
        // YYYYMMDDhhmmssZ format
        if (time_str.length() < 14) return 0;

        year = (time_str[0] - '0') * 1000 + (time_str[1] - '0') * 100 +
               (time_str[2] - '0') * 10 + (time_str[3] - '0');
        month = (time_str[4] - '0') * 10 + (time_str[5] - '0');
        day = (time_str[6] - '0') * 10 + (time_str[7] - '0');
        hour = (time_str[8] - '0') * 10 + (time_str[9] - '0');
        minute = (time_str[10] - '0') * 10 + (time_str[11] - '0');
        second = (time_str[12] - '0') * 10 + (time_str[13] - '0');
    } else {
        return 0;
    }

    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = second;

    // Use timegm if available, otherwise calculate manually
#if defined(_WIN32)
    return _mkgmtime(&tm);
#else
    return timegm(&tm);
#endif
}

std::string authenticode_analyzer::parse_integer_as_hex(std::span<const uint8_t> data) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');

    // Skip leading zeros but keep at least one byte
    size_t start = 0;
    while (start < data.size() - 1 && data[start] == 0) {
        start++;
    }

    for (size_t i = start; i < data.size(); ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }

    return oss.str();
}

x509_name authenticode_analyzer::parse_x509_name(std::span<const uint8_t> data) {
    x509_name name;

    // X.509 Name is a SEQUENCE of RelativeDistinguishedName (SET of AttributeTypeAndValue)
    asn1_element seq;
    if (!parse_asn1_element(data.data(), data.size(), seq) || !seq.is_sequence()) {
        return name;
    }

    const uint8_t* ptr = seq.content;
    const uint8_t* end = seq.content + seq.content_length;

    while (ptr < end) {
        asn1_element rdn;
        if (!parse_asn1_element(ptr, static_cast<size_t>(end - ptr), rdn) || !rdn.is_set()) {
            break;
        }

        // Parse SET content (AttributeTypeAndValue)
        asn1_element atv;
        if (parse_asn1_element(rdn.content, rdn.content_length, atv) && atv.is_sequence()) {
            // Parse OID
            asn1_element oid_elem;
            if (parse_asn1_element(atv.content, atv.content_length, oid_elem) && oid_elem.is_oid()) {
                std::string attr_oid = parse_oid(oid_elem.data());

                // Parse value
                const uint8_t* value_ptr = atv.content + oid_elem.header_length + oid_elem.content_length;
                size_t remaining = atv.content_length - (oid_elem.header_length + oid_elem.content_length);

                asn1_element value_elem;
                if (parse_asn1_element(value_ptr, remaining, value_elem)) {
                    std::string value = parse_string(value_elem);

                    if (attr_oid == oid::COMMON_NAME) name.common_name = value;
                    else if (attr_oid == oid::ORGANIZATION) name.organization = value;
                    else if (attr_oid == oid::ORG_UNIT) name.organizational_unit = value;
                    else if (attr_oid == oid::COUNTRY) name.country = value;
                    else if (attr_oid == oid::STATE) name.state = value;
                    else if (attr_oid == oid::LOCALITY) name.locality = value;
                    else if (attr_oid == oid::EMAIL) name.email = value;
                }
            }
        }

        ptr += rdn.header_length + rdn.content_length;
    }

    return name;
}

std::optional<x509_certificate_info> authenticode_analyzer::parse_certificate(
    std::span<const uint8_t> data
) {
    x509_certificate_info cert;
    cert.raw_data.assign(data.begin(), data.end());

    // Certificate is a SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    asn1_element cert_seq;
    if (!parse_asn1_element(data.data(), data.size(), cert_seq) || !cert_seq.is_sequence()) {
        return std::nullopt;
    }

    // Parse TBSCertificate
    asn1_element tbs;
    if (!parse_asn1_element(cert_seq.content, cert_seq.content_length, tbs) || !tbs.is_sequence()) {
        return std::nullopt;
    }

    const uint8_t* ptr = tbs.content;
    const uint8_t* end = tbs.content + tbs.content_length;

    // Skip version [0] EXPLICIT if present
    asn1_element elem;
    if (!parse_asn1_element(ptr, static_cast<size_t>(end - ptr), elem)) {
        return std::nullopt;
    }

    if (elem.is_context_specific(0)) {
        ptr += elem.header_length + elem.content_length;
        if (!parse_asn1_element(ptr, static_cast<size_t>(end - ptr), elem)) {
            return std::nullopt;
        }
    }

    // Serial number (INTEGER)
    if (elem.is_integer()) {
        cert.serial_number = parse_integer_as_hex(elem.data());
        ptr += elem.header_length + elem.content_length;
    }

    // Signature algorithm (SEQUENCE)
    if (parse_asn1_element(ptr, static_cast<size_t>(end - ptr), elem) && elem.is_sequence()) {
        // Extract algorithm OID
        asn1_element alg_oid;
        if (parse_asn1_element(elem.content, elem.content_length, alg_oid) && alg_oid.is_oid()) {
            cert.signature_algorithm = parse_oid(alg_oid.data());
        }
        ptr += elem.header_length + elem.content_length;
    }

    // Issuer (Name)
    if (parse_asn1_element(ptr, static_cast<size_t>(end - ptr), elem) && elem.is_sequence()) {
        cert.issuer = parse_x509_name({ptr, elem.header_length + elem.content_length});
        ptr += elem.header_length + elem.content_length;
    }

    // Validity (SEQUENCE { notBefore, notAfter })
    if (parse_asn1_element(ptr, static_cast<size_t>(end - ptr), elem) && elem.is_sequence()) {
        asn1_element time_elem;
        const uint8_t* validity_ptr = elem.content;

        // notBefore
        if (parse_asn1_element(validity_ptr, elem.content_length, time_elem)) {
            cert.not_before = parse_time(time_elem);
            validity_ptr += time_elem.header_length + time_elem.content_length;

            // notAfter
            if (parse_asn1_element(validity_ptr, static_cast<size_t>(elem.content + elem.content_length - validity_ptr), time_elem)) {
                cert.not_after = parse_time(time_elem);
            }
        }

        ptr += elem.header_length + elem.content_length;
    }

    // Subject (Name)
    if (parse_asn1_element(ptr, static_cast<size_t>(end - ptr), elem) && elem.is_sequence()) {
        cert.subject = parse_x509_name({ptr, elem.header_length + elem.content_length});
    }

    return cert;
}

std::optional<authenticode_signer_info> authenticode_analyzer::parse_signer_info(
    std::span<const uint8_t> data
) {
    authenticode_signer_info info;

    // SignerInfo is a SEQUENCE
    asn1_element seq;
    if (!parse_asn1_element(data.data(), data.size(), seq) || !seq.is_sequence()) {
        return std::nullopt;
    }

    const uint8_t* ptr = seq.content;
    const uint8_t* end = seq.content + seq.content_length;

    // Version (INTEGER)
    asn1_element elem;
    if (!parse_asn1_element(ptr, static_cast<size_t>(end - ptr), elem) || !elem.is_integer()) {
        return std::nullopt;
    }
    ptr += elem.header_length + elem.content_length;

    // IssuerAndSerialNumber (SEQUENCE { issuer, serialNumber })
    if (!parse_asn1_element(ptr, static_cast<size_t>(end - ptr), elem) || !elem.is_sequence()) {
        return std::nullopt;
    }

    // Parse issuer and serial from IssuerAndSerialNumber
    const uint8_t* iasn_ptr = elem.content;
    const uint8_t* iasn_end = elem.content + elem.content_length;

    asn1_element issuer_elem;
    if (parse_asn1_element(iasn_ptr, static_cast<size_t>(iasn_end - iasn_ptr), issuer_elem) && issuer_elem.is_sequence()) {
        info.issuer = parse_x509_name({iasn_ptr, issuer_elem.header_length + issuer_elem.content_length});
        iasn_ptr += issuer_elem.header_length + issuer_elem.content_length;

        asn1_element serial_elem;
        if (parse_asn1_element(iasn_ptr, static_cast<size_t>(iasn_end - iasn_ptr), serial_elem) && serial_elem.is_integer()) {
            info.serial_number = parse_integer_as_hex(serial_elem.data());
        }
    }

    ptr += elem.header_length + elem.content_length;

    // DigestAlgorithm (AlgorithmIdentifier)
    if (parse_asn1_element(ptr, static_cast<size_t>(end - ptr), elem) && elem.is_sequence()) {
        asn1_element alg_oid;
        if (parse_asn1_element(elem.content, elem.content_length, alg_oid) && alg_oid.is_oid()) {
            std::string oid_str = parse_oid(alg_oid.data());
            info.digest_algorithm = algorithm_from_oid(oid_str);
        }
        ptr += elem.header_length + elem.content_length;
    }

    return info;
}

std::optional<authenticode_timestamp> authenticode_analyzer::find_timestamp(
    std::span<const uint8_t> signer_info_data
) {
    // Look for countersignature or RFC 3161 timestamp in unsigned attributes
    // This is a simplified search - full parsing would need to traverse the structure

    authenticode_timestamp ts;

    // Search for signing time attribute (simplified approach)
    // Look for OID 1.2.840.113549.1.9.5 (signingTime) or 1.2.840.113549.1.9.16.2.14 (RFC 3161)

    const uint8_t* ptr = signer_info_data.data();
    const uint8_t* end = ptr + signer_info_data.size();

    // Simple pattern search for UTCTime or GeneralizedTime after timestamp OIDs
    while (ptr + 20 < end) {
        asn1_element elem;
        if (parse_asn1_element(ptr, static_cast<size_t>(end - ptr), elem)) {
            if (elem.is_utc_time() || elem.is_generalized_time()) {
                ts.timestamp = parse_time(elem);
                if (ts.timestamp != 0) {
                    return ts;
                }
            }
            ptr += elem.header_length + elem.content_length;
        } else {
            ptr++;
        }
    }

    return std::nullopt;
}

authenticode_hash_algorithm authenticode_analyzer::algorithm_from_oid(const std::string& oid_str) {
    if (oid_str == oid::MD5) return authenticode_hash_algorithm::MD5;
    if (oid_str == oid::SHA1) return authenticode_hash_algorithm::SHA1;
    if (oid_str == oid::SHA256) return authenticode_hash_algorithm::SHA256;
    if (oid_str == oid::SHA384) return authenticode_hash_algorithm::SHA384;
    if (oid_str == oid::SHA512) return authenticode_hash_algorithm::SHA512;
    return authenticode_hash_algorithm::UNKNOWN;
}

bool authenticode_analyzer::is_pkcs7_signed_data(std::span<const uint8_t> data) {
    if (data.size() < 20) return false;

    // Check for SEQUENCE tag
    asn1_element outer;
    if (!parse_asn1_element(data.data(), data.size(), outer) || !outer.is_sequence()) {
        return false;
    }

    // First element should be OID for signedData (1.2.840.113549.1.7.2)
    asn1_element oid_elem;
    if (!parse_asn1_element(outer.content, outer.content_length, oid_elem) || !oid_elem.is_oid()) {
        return false;
    }

    std::string content_type = parse_oid(oid_elem.data());
    return content_type == oid::SIGNED_DATA;
}

std::optional<authenticode_signature> authenticode_analyzer::parse(
    std::span<const uint8_t> pkcs7_data
) {
    if (!is_pkcs7_signed_data(pkcs7_data)) {
        return std::nullopt;
    }

    authenticode_signature sig;

    // Parse outer ContentInfo structure
    asn1_element outer;
    if (!parse_asn1_element(pkcs7_data.data(), pkcs7_data.size(), outer) || !outer.is_sequence()) {
        return std::nullopt;
    }

    // Skip OID, get [0] EXPLICIT content
    const uint8_t* ptr = outer.content;
    const uint8_t* end = outer.content + outer.content_length;

    asn1_element elem;
    if (!parse_asn1_element(ptr, static_cast<size_t>(end - ptr), elem) || !elem.is_oid()) {
        return std::nullopt;
    }
    ptr += elem.header_length + elem.content_length;

    // Get [0] EXPLICIT content
    if (!parse_asn1_element(ptr, static_cast<size_t>(end - ptr), elem) || !elem.is_context_specific(0)) {
        return std::nullopt;
    }

    // Parse SignedData
    asn1_element signed_data;
    if (!parse_asn1_element(elem.content, elem.content_length, signed_data) || !signed_data.is_sequence()) {
        return std::nullopt;
    }

    ptr = signed_data.content;
    end = signed_data.content + signed_data.content_length;

    // Version
    if (!parse_asn1_element(ptr, static_cast<size_t>(end - ptr), elem) || !elem.is_integer()) {
        return std::nullopt;
    }
    if (elem.content_length > 0) {
        sig.version = elem.content[0];
    }
    ptr += elem.header_length + elem.content_length;

    // DigestAlgorithms (SET)
    if (!parse_asn1_element(ptr, static_cast<size_t>(end - ptr), elem) || !elem.is_set()) {
        return std::nullopt;
    }

    // Extract first digest algorithm
    asn1_element alg_seq;
    if (parse_asn1_element(elem.content, elem.content_length, alg_seq) && alg_seq.is_sequence()) {
        asn1_element alg_oid;
        if (parse_asn1_element(alg_seq.content, alg_seq.content_length, alg_oid) && alg_oid.is_oid()) {
            sig.digest_algorithm = algorithm_from_oid(parse_oid(alg_oid.data()));
        }
    }
    ptr += elem.header_length + elem.content_length;

    // EncapsulatedContentInfo (SEQUENCE)
    if (!parse_asn1_element(ptr, static_cast<size_t>(end - ptr), elem) || !elem.is_sequence()) {
        return std::nullopt;
    }

    // Get content type OID
    asn1_element content_oid;
    if (parse_asn1_element(elem.content, elem.content_length, content_oid) && content_oid.is_oid()) {
        sig.content_type = parse_oid(content_oid.data());
    }
    ptr += elem.header_length + elem.content_length;

    // Certificates [0] IMPLICIT (optional)
    if (parse_asn1_element(ptr, static_cast<size_t>(end - ptr), elem) && elem.is_context_specific(0)) {
        // Parse certificates
        const uint8_t* cert_ptr = elem.content;
        const uint8_t* cert_end = elem.content + elem.content_length;

        while (cert_ptr < cert_end) {
            asn1_element cert_elem;
            if (parse_asn1_element(cert_ptr, static_cast<size_t>(cert_end - cert_ptr), cert_elem) && cert_elem.is_sequence()) {
                auto cert = parse_certificate({cert_ptr, cert_elem.header_length + cert_elem.content_length});
                if (cert) {
                    sig.certificates.push_back(std::move(*cert));
                }
                cert_ptr += cert_elem.header_length + cert_elem.content_length;
            } else {
                break;
            }
        }

        ptr += elem.header_length + elem.content_length;
    }

    // CRLs [1] IMPLICIT (optional) - skip
    if (parse_asn1_element(ptr, static_cast<size_t>(end - ptr), elem) && elem.is_context_specific(1)) {
        ptr += elem.header_length + elem.content_length;
    }

    // SignerInfos (SET)
    if (parse_asn1_element(ptr, static_cast<size_t>(end - ptr), elem) && elem.is_set()) {
        const uint8_t* si_ptr = elem.content;
        const uint8_t* si_end = elem.content + elem.content_length;

        while (si_ptr < si_end) {
            asn1_element si_elem;
            if (parse_asn1_element(si_ptr, static_cast<size_t>(si_end - si_ptr), si_elem) && si_elem.is_sequence()) {
                auto signer = parse_signer_info({si_ptr, si_elem.header_length + si_elem.content_length});
                if (signer) {
                    sig.signers.push_back(std::move(*signer));
                }

                // Try to find timestamp in signer info
                if (!sig.timestamp) {
                    sig.timestamp = find_timestamp({si_ptr, si_elem.header_length + si_elem.content_length});
                }

                si_ptr += si_elem.header_length + si_elem.content_length;
            } else {
                break;
            }
        }
    }

    return sig;
}

} // namespace libexe
