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

datascript_generate(
    TARGET libexe_parsers
    SCHEMAS
        # Common types (no dependencies)
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/common.ds
        # Executable format parsers
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/mz.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/ne/ne_header.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/pe/pe_header.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/le/le_header.ds
        # PE data directory parsers
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
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/pe/pe_iat.ds
        # Resource format parsers
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/resources/dialogs.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/resources/version.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/resources/basic.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/resources/tables.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/resources/fonts.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/resources/menus.ds
        ${CMAKE_CURRENT_SOURCE_DIR}/formats/resources/os2.ds

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
    # Core files
    core/data_source.cpp
    core/diagnostic.cpp
    core/entropy.cpp
    executable_file.cpp
    executable_factory.cpp
    mz_file.cpp
    pe_file.cpp
    ne_file.cpp
    le_file.cpp
    # Section parsers
    pe_section_parser.cpp
    ne_segment_parser.cpp
    # Data directory parsers
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
    # Data directory structures
    debug_directory.cpp
    load_config_directory.cpp
    bound_import_directory.cpp
    security_directory.cpp
    com_descriptor.cpp
    # PE utilities
    pe/overlay.cpp
    pe/authenticode.cpp
    # Resources
    resources/resource.cpp
    resources/pe_resource_directory.cpp
    resources/ne_resource_directory.cpp
    # Resource Parsers
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
    resources/parsers/os2_resource_parser.cpp
    # Decompressors
    decompressors/pklite_decompressor.cpp
    decompressors/lzexe_decompressor.cpp
    decompressors/knowledge_dynamics_decompressor.cpp
    decompressors/exepack_decompressor.cpp
    decompressors/diet_decompressor.cpp
    decompressors/decompressor_factory.cpp
    # Dialog parser
    resources/parsers/dialog_parser.cpp
)

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
