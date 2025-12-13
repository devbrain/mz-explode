# Include required modules
include(GenerateExportHeader)
include(FetchContent)

# =============================================================================
# Dependencies
# =============================================================================

# mio - Cross-platform memory-mapped file I/O library
if (NOT TARGET mio::mio)
    message(STATUS "mio not found, fetching from GitHub...")

    FetchContent_Declare(
            mio
            GIT_REPOSITORY https://github.com/devbrain/mio.git
            GIT_TAG master
    )

    FetchContent_MakeAvailable(mio)
else ()
    message(STATUS "Using existing mio (provided by parent project)")
endif ()

# DataScript - binary format parser generator
# Guard: only fetch if not already available (could be provided by parent project)
if (NOT TARGET ds)
    message(STATUS "DataScript not found, fetching from GitHub...")

    set(DATASCRIPT_BUILD_TESTS OFF CACHE BOOL "" FORCE)

    FetchContent_Declare(
            datascript
            GIT_REPOSITORY https://github.com/devbrain/datascript.git
            GIT_TAG master
    )

    FetchContent_MakeAvailable(datascript)
else ()
    message(STATUS "Using existing DataScript (provided by parent project)")
endif ()

# =============================================================================
# DataScript Code Generation using datascript_generate()
# =============================================================================

# Generate parsers from all DataScript schema files
# The datascript_generate() function creates an INTERFACE library with proper
# include directories and automatic dependency tracking
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
# Main Library
# =============================================================================

add_library(libexe
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
        # Data directory structures (only those with implementation)
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

# Link against the generated parsers INTERFACE library
# This automatically adds the include directories and triggers code generation
target_link_libraries(libexe PRIVATE libexe_parsers mio::mio)

# Generate portable export header
generate_export_header(libexe
        BASE_NAME libexe
        EXPORT_FILE_NAME ${CMAKE_CURRENT_BINARY_DIR}/include/libexe/export.hpp
)

# Include directories
# Note: ${CMAKE_BINARY_DIR}/generated is provided by libexe_parsers INTERFACE library
target_include_directories(libexe
        PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Library properties
set_target_properties(libexe PROPERTIES
        OUTPUT_NAME exe
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Namespace alias for FetchContent compatibility
add_library(mzexplode::libexe ALIAS libexe)
