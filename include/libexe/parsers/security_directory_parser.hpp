// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_SECURITY_DIRECTORY_PARSER_HPP
#define LIBEXE_SECURITY_DIRECTORY_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/security_directory.hpp>
#include <span>
#include <cstdint>

namespace libexe {

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

#endif // LIBEXE_SECURITY_DIRECTORY_PARSER_HPP
