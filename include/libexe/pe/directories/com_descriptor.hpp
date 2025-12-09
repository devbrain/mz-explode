// libexe - Modern executable file analysis library
// Copyright (c) 2024

#ifndef LIBEXE_PE_DIRECTORIES_COM_DESCRIPTOR_HPP
#define LIBEXE_PE_DIRECTORIES_COM_DESCRIPTOR_HPP

#include <libexe/export.hpp>
#include <libexe/pe/section.hpp>
#include <cstdint>
#include <string>
#include <span>
#include <vector>

namespace libexe {

/**
 * COMIMAGE Flags
 *
 * Flags that describe the characteristics of a .NET assembly.
 */
enum class comimage_flags : uint32_t {
    ILONLY              = 0x00000001,  // Image contains only IL code
    REQUIRED_32BIT      = 0x00000002,  // Image requires 32-bit runtime
    IL_LIBRARY          = 0x00000004,  // Image is a library (not executable)
    STRONGNAMESIGNED    = 0x00000008,  // Image has a strong name signature
    NATIVE_ENTRYPOINT   = 0x00000010,  // Entry point is native code (not IL)
    TRACKDEBUGDATA      = 0x00010000,  // Track debug data
    PREFER_32BIT        = 0x00020000   // Prefers 32-bit even on 64-bit platforms
};

/**
 * COM Descriptor (CLR Runtime Header)
 *
 * Describes the Common Object Runtime (COM+/.NET CLR) metadata for managed executables.
 * Data directory index: 14 (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
 *
 * This header is present in all .NET assemblies (managed code executables).
 * It points to the CLR metadata, which contains:
 * - Type definitions
 * - Method signatures
 * - Intermediate Language (IL) code
 * - Resources
 * - Strong name signature
 *
 * The presence of this directory indicates that the executable is a .NET assembly
 * and requires the CLR to execute.
 */
struct LIBEXE_EXPORT com_descriptor {
    /// Size of this header (usually 72 bytes)
    uint32_t header_size = 0;

    /// Major version of CLR required
    uint16_t major_runtime_version = 0;

    /// Minor version of CLR required
    uint16_t minor_runtime_version = 0;

    /// RVA of CLR metadata
    uint32_t metadata_rva = 0;

    /// Size of CLR metadata in bytes
    uint32_t metadata_size = 0;

    /// COMIMAGE flags (see comimage_flags enum)
    uint32_t flags = 0;

    /// Entry point token (if managed) or RVA (if native)
    /// If NATIVE_ENTRYPOINT flag is set, this is an RVA
    /// Otherwise, it's a metadata token for the entry point method
    uint32_t entry_point_token_or_rva = 0;

    /// RVA of managed resources
    uint32_t resources_rva = 0;

    /// Size of managed resources in bytes
    uint32_t resources_size = 0;

    /// RVA of strong name signature (for signed assemblies)
    uint32_t strong_name_signature_rva = 0;

    /// Size of strong name signature in bytes
    uint32_t strong_name_signature_size = 0;

    /// RVA of code manager table (usually 0, rarely used)
    uint32_t code_manager_table_rva = 0;

    /// Size of code manager table (usually 0)
    uint32_t code_manager_table_size = 0;

    /// RVA of VTable fixups (for COM interop)
    uint32_t vtable_fixups_rva = 0;

    /// Size of VTable fixups in bytes
    uint32_t vtable_fixups_size = 0;

    /// RVA of export address table jumps (usually 0, rarely used)
    uint32_t export_address_table_jumps_rva = 0;

    /// Size of export address table jumps (usually 0)
    uint32_t export_address_table_jumps_size = 0;

    /// RVA of managed native header (usually 0, for NGen images)
    uint32_t managed_native_header_rva = 0;

    /// Size of managed native header (usually 0)
    uint32_t managed_native_header_size = 0;

    /**
     * Check if this is a valid .NET assembly
     * @return True if header_size > 0 and metadata exists
     */
    [[nodiscard]] bool is_valid() const {
        return header_size > 0 && metadata_rva != 0 && metadata_size > 0;
    }

    /**
     * Check if assembly contains only IL code (no native code)
     * @return True if ILONLY flag is set
     */
    [[nodiscard]] bool is_il_only() const {
        return (flags & static_cast<uint32_t>(comimage_flags::ILONLY)) != 0;
    }

    /**
     * Check if assembly requires 32-bit runtime
     * @return True if REQUIRED_32BIT flag is set
     */
    [[nodiscard]] bool requires_32bit() const {
        return (flags & static_cast<uint32_t>(comimage_flags::REQUIRED_32BIT)) != 0;
    }

    /**
     * Check if assembly prefers 32-bit even on 64-bit platforms
     * @return True if PREFER_32BIT flag is set
     */
    [[nodiscard]] bool prefers_32bit() const {
        return (flags & static_cast<uint32_t>(comimage_flags::PREFER_32BIT)) != 0;
    }

    /**
     * Check if assembly has a strong name signature
     * @return True if STRONGNAMESIGNED flag is set
     */
    [[nodiscard]] bool is_strong_name_signed() const {
        return (flags & static_cast<uint32_t>(comimage_flags::STRONGNAMESIGNED)) != 0;
    }

    /**
     * Check if entry point is native code
     * @return True if NATIVE_ENTRYPOINT flag is set
     */
    [[nodiscard]] bool has_native_entrypoint() const {
        return (flags & static_cast<uint32_t>(comimage_flags::NATIVE_ENTRYPOINT)) != 0;
    }

    /**
     * Check if this is a .NET library (DLL)
     * @return True if IL_LIBRARY flag is set
     */
    [[nodiscard]] bool is_library() const {
        return (flags & static_cast<uint32_t>(comimage_flags::IL_LIBRARY)) != 0;
    }

    /**
     * Check if assembly has managed resources
     * @return True if resources RVA and size are non-zero
     */
    [[nodiscard]] bool has_resources() const {
        return resources_rva != 0 && resources_size > 0;
    }

    /**
     * Check if assembly has VTable fixups (COM interop)
     * @return True if vtable fixups RVA and size are non-zero
     */
    [[nodiscard]] bool has_vtable_fixups() const {
        return vtable_fixups_rva != 0 && vtable_fixups_size > 0;
    }

    /**
     * Get CLR runtime version as string
     * @return Version string (e.g., "2.5")
     */
    [[nodiscard]] std::string runtime_version() const;
};

/**
 * Parser for PE COM Descriptor (CLR Runtime Header) - Data Directory Index 14
 *
 * The COM descriptor (IMAGE_COR20_HEADER) is present in all .NET assemblies.
 * It describes the Common Language Runtime (CLR) metadata for managed code.
 *
 * This parser extracts:
 * - CLR version information
 * - Metadata location and size
 * - Assembly flags (IL-only, 32-bit required, strong-name signed, etc.)
 * - Entry point (managed token or native RVA)
 * - Managed resources location
 * - Strong name signature location
 * - VTable fixups for COM interop
 *
 * The presence of a valid COM descriptor indicates that the PE file is a
 * .NET assembly that requires the CLR to execute.
 */
class LIBEXE_EXPORT com_descriptor_parser {
public:
    /**
     * Parse COM descriptor from PE file data
     *
     * @param file_data Complete PE file data
     * @param sections Vector of parsed PE sections (for RVA to file offset conversion)
     * @param com_descriptor_rva RVA of COM descriptor
     * @param com_descriptor_size Size of COM descriptor (usually 72 bytes)
     * @return Parsed COM descriptor
     * @throws std::runtime_error if parsing fails or data is invalid
     */
    static com_descriptor parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t com_descriptor_rva,
        uint32_t com_descriptor_size
    );

private:
    /**
     * Convert RVA to file offset using section table
     * @param sections Vector of PE sections
     * @param rva Relative Virtual Address
     * @return File offset, or 0 if RVA not found in any section
     */
    static uint32_t rva_to_file_offset(
        const std::vector<pe_section>& sections,
        uint32_t rva
    );
};

} // namespace libexe

#endif // LIBEXE_PE_DIRECTORIES_COM_DESCRIPTOR_HPP
