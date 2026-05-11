# =============================================================================
# libexe Library
# =============================================================================

include(GenerateExportHeader)
include(FetchContent)

# =============================================================================
# Dependencies
# =============================================================================

# mio - Cross-platform memory-mapped file I/O library
include(${NEUTRINO_CMAKE_DIR}/deps/mio.cmake)
neutrino_fetch_mio()

# DataScript - binary format parser generator
include(${NEUTRINO_CMAKE_DIR}/deps/datascript.cmake)
neutrino_fetch_datascript()

# =============================================================================
# DataScript Code Generation
# =============================================================================

# Schemas are gathered conditionally per format axis. The pe_header.ds
# pe header schema is always generated because executable_factory.cpp
# reads bytes via formats::pe::pe_header::read_uint16_le for format
# detection even when no other PE machinery is enabled — that helper
# is generic LE-byte reading, just lives in the pe header namespace.
set(_libexe_ds_schemas
    ${CMAKE_CURRENT_SOURCE_DIR}/formats/common.ds
    ${CMAKE_CURRENT_SOURCE_DIR}/formats/mz.ds
    ${CMAKE_CURRENT_SOURCE_DIR}/formats/pe/pe_header.ds
)

if(NEUTRINO_MZEXPLODE_FORMAT_NE)
    list(APPEND _libexe_ds_schemas
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/ne/ne_header.ds)
endif()
if(NEUTRINO_MZEXPLODE_FORMAT_LE)
    list(APPEND _libexe_ds_schemas
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/le/le_header.ds)
endif()
if(NEUTRINO_MZEXPLODE_FORMAT_PE)
    list(APPEND _libexe_ds_schemas
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/pe/pe_imports.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/pe/pe_exports.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/pe/pe_relocations.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/pe/pe_tls.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/pe/pe_debug.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/pe/pe_load_config.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/pe/pe_exception.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/pe/pe_delay_imports.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/pe/pe_bound_imports.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/pe/pe_security.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/pe/pe_com_descriptor.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/pe/pe_iat.ds)
endif()

# Resource schemas are shared by NE and PE; generated if either is on.
if(NEUTRINO_MZEXPLODE_FORMAT_NE OR NEUTRINO_MZEXPLODE_FORMAT_PE)
    list(APPEND _libexe_ds_schemas
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/resources/dialogs.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/resources/version.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/resources/basic.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/resources/tables.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/resources/fonts.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/resources/menus.ds)
endif()

# OS/2 resource schema only needed by NE format reader.
if(NEUTRINO_MZEXPLODE_FORMAT_NE)
    list(APPEND _libexe_ds_schemas
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/resources/os2.ds)
endif()

datascript_generate(
    TARGET libexe_parsers
    SCHEMAS ${_libexe_ds_schemas}
    OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated
    IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
    INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}
    PRESERVE_PACKAGE_DIRS ON
)

# =============================================================================
# Library Target
# =============================================================================

if(NEUTRINO_MZEXPLODE_BUILD_SHARED)
    add_library(libexe SHARED)
else()
    add_library(libexe STATIC)
endif()

# Create neutrino:: alias
add_library(neutrino::libexe ALIAS libexe)

target_sources(libexe PRIVATE
    # Core (always built — these provide the foundation that every
    # other axis sits on, plus MZ format reading which is required to
    # walk the MZ stub at the start of every newer-format file).
    core/data_source.cpp
    core/diagnostic.cpp
    core/entropy.cpp
    executable_file.cpp
    executable_factory.cpp
    mz_file.cpp
    # decompressor_factory is always built; the switch cases inside it
    # are gated per-decompressor via #ifdef MZEXPLODE_HAS_<NAME>.
    decompressors/decompressor_factory.cpp
)

# ------------------------------------------------------------------
# Format-specific source groups
# ------------------------------------------------------------------
if(NEUTRINO_MZEXPLODE_FORMAT_NE)
    target_sources(libexe PRIVATE
        ne_file.cpp
        ne_segment_parser.cpp
        resources/ne_resource_directory.cpp
        resources/parsers/os2_resource_parser.cpp)
endif()

if(NEUTRINO_MZEXPLODE_FORMAT_PE)
    target_sources(libexe PRIVATE
        pe_file.cpp
        pe_section_parser.cpp
        # PE data directory parsers
        parsers/import_directory_parser.cpp
        parsers/export_directory_parser.cpp
        parsers/base_relocation_parser.cpp
        parsers/tls_directory_parser.cpp
        parsers/debug_directory_parser.cpp
        parsers/load_config_directory_parser.cpp
        parsers/exception_directory_parser.cpp
        parsers/delay_import_directory_parser.cpp
        parsers/bound_import_directory_parser.cpp
        parsers/security_directory_parser.cpp
        parsers/com_descriptor_parser.cpp
        parsers/iat_directory_parser.cpp
        parsers/global_ptr_directory_parser.cpp
        parsers/architecture_directory_parser.cpp
        parsers/reserved_directory_parser.cpp
        parsers/rich_header_parser.cpp
        # PE-specific data directory structures
        debug_directory.cpp
        load_config_directory.cpp
        bound_import_directory.cpp
        security_directory.cpp
        com_descriptor.cpp
        # PE utilities
        pe/overlay.cpp
        pe/authenticode.cpp
        # PE resource directory
        resources/pe_resource_directory.cpp)
endif()

if(NEUTRINO_MZEXPLODE_FORMAT_LE)
    target_sources(libexe PRIVATE
        le_file.cpp)
endif()

# Shared resource infrastructure + format-shape resource parsers.
# Used by both NE (16-bit Windows resources) and PE (32-bit Windows
# resources) — same on-disk shape, different containers.
if(NEUTRINO_MZEXPLODE_FORMAT_NE OR NEUTRINO_MZEXPLODE_FORMAT_PE)
    target_sources(libexe PRIVATE
        resources/resource.cpp
        resources/parsers/icon_group_parser.cpp
        resources/parsers/icon_parser.cpp
        resources/parsers/font_parser.cpp
        resources/parsers/version_info_parser.cpp
        resources/parsers/manifest_parser.cpp
        resources/parsers/string_table_parser.cpp
        resources/parsers/accelerator_parser.cpp
        resources/parsers/menu_parser.cpp
        resources/parsers/bitmap_parser.cpp
        resources/parsers/message_table_parser.cpp
        resources/parsers/dialog_parser.cpp)
endif()

# ------------------------------------------------------------------
# Decompressor source groups
# ------------------------------------------------------------------
if(NEUTRINO_MZEXPLODE_DECOMPRESSOR_LZEXE)
    target_sources(libexe PRIVATE decompressors/lzexe_decompressor.cpp)
endif()
if(NEUTRINO_MZEXPLODE_DECOMPRESSOR_PKLITE)
    target_sources(libexe PRIVATE decompressors/pklite_decompressor.cpp)
endif()
if(NEUTRINO_MZEXPLODE_DECOMPRESSOR_EXEPACK)
    target_sources(libexe PRIVATE decompressors/exepack_decompressor.cpp)
endif()
if(NEUTRINO_MZEXPLODE_DECOMPRESSOR_DIET)
    target_sources(libexe PRIVATE decompressors/diet_decompressor.cpp)
endif()
if(NEUTRINO_MZEXPLODE_DECOMPRESSOR_KD)
    target_sources(libexe PRIVATE decompressors/knowledge_dynamics_decompressor.cpp)
endif()

# ------------------------------------------------------------------
# Compile definitions so factories know what's available.
# ------------------------------------------------------------------
# These macros are checked by executable_factory.cpp and
# decompressor_factory.cpp to conditionally compile each switch case;
# disabled formats/decompressors throw "unsupported" at runtime if the
# user calls into the factory.
foreach(_axis FORMAT_NE FORMAT_PE FORMAT_LE
              DECOMPRESSOR_LZEXE DECOMPRESSOR_PKLITE DECOMPRESSOR_EXEPACK
              DECOMPRESSOR_DIET DECOMPRESSOR_KD)
    if(NEUTRINO_MZEXPLODE_${_axis})
        target_compile_definitions(libexe PRIVATE MZEXPLODE_HAS_${_axis}=1)
    endif()
endforeach()

# =============================================================================
# Target Configuration
# =============================================================================

target_compile_features(libexe PUBLIC cxx_std_20)

target_link_libraries(libexe
    PRIVATE
        libexe_parsers
        mio::mio
)

# Generate portable export header
generate_export_header(libexe
    BASE_NAME libexe
    EXPORT_FILE_NAME ${CMAKE_CURRENT_BINARY_DIR}/include/libexe/export.hpp
)

# Include directories
target_include_directories(libexe
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# =============================================================================
# Library Properties
# =============================================================================

set_target_properties(libexe PROPERTIES
    OUTPUT_NAME exe
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    POSITION_INDEPENDENT_CODE ON
    FOLDER "Libraries"
)

# =============================================================================
# Compiler Warnings
# =============================================================================

neutrino_target_warnings(libexe)
