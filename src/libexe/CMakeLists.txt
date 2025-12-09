# Include required modules
include(GenerateExportHeader)
include(FetchContent)

# =============================================================================
# Dependencies
# =============================================================================

# DataScript - binary format parser generator
# Guard: only fetch if not already available (could be provided by parent project)
if(NOT TARGET ds)
    message(STATUS "DataScript not found, fetching from GitHub...")

    include(FetchContent)
    FetchContent_Declare(
            datascript
            GIT_REPOSITORY https://github.com/devbrain/datascript.git
            GIT_TAG master
    )

    # Check if already populated by parent project
    FetchContent_GetProperties(datascript)
    if(NOT datascript_POPULATED)
        FetchContent_MakeAvailable(datascript)
    endif()
else()
    message(STATUS "Using existing DataScript (provided by parent project)")
endif()
## Failsafe - header-only logging and exception handling
#FetchContent_Declare(
#    failsafe
#    GIT_REPOSITORY https://github.com/devbrain/failsafe.git
#    GIT_TAG master
#)
#
#FetchContent_MakeAvailable(datascript failsafe)



# =============================================================================
# DataScript Code Generation
# =============================================================================

function(add_datascript_parser SCHEMA_FILE OUTPUT_NAME)
    get_filename_component(SCHEMA_NAME ${SCHEMA_FILE} NAME_WE)
    get_filename_component(OUTPUT_NAME_WE ${OUTPUT_NAME} NAME_WE)
    set(GENERATED_HEADER "${CMAKE_BINARY_DIR}/generated/${OUTPUT_NAME}")

    add_custom_command(
            OUTPUT ${GENERATED_HEADER}
            COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/generated
            COMMAND ds ${CMAKE_CURRENT_SOURCE_DIR}/${SCHEMA_FILE} -t cpp -o ${CMAKE_BINARY_DIR}/generated/ --cpp-output-name=${OUTPUT_NAME_WE} -I ${CMAKE_CURRENT_SOURCE_DIR}/formats
            DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${SCHEMA_FILE}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            COMMENT "Generating C++ parser from ${SCHEMA_FILE}"
            VERBATIM
    )

    # Create a custom target to ensure generation happens
    add_custom_target(generate_${SCHEMA_NAME}_parser
            DEPENDS ${GENERATED_HEADER}
    )

    set(GENERATED_PARSER_HEADER ${GENERATED_HEADER} PARENT_SCOPE)
endfunction()

# =============================================================================
# Generate Parsers from Modular DataScript Files
# =============================================================================

# Generate parsers from modular specifications
# Common types (no dependencies, generate first)
add_datascript_parser(formats/common.ds libexe_format_common.hh)

# Executable format parsers (independent, no dependencies)
add_datascript_parser(formats/mz.ds libexe_format_mz.hh)
add_datascript_parser(formats/ne/ne_header.ds libexe_format_ne.hh)
add_datascript_parser(formats/pe/pe_header.ds libexe_format_pe.hh)
add_datascript_parser(formats/le/le_header.ds libexe_format_le.hh)

# PE data directory parsers
add_datascript_parser(formats/pe/pe_imports.ds libexe_format_pe_imports.hh)
add_datascript_parser(formats/pe/pe_exports.ds libexe_format_pe_exports.hh)
add_datascript_parser(formats/pe/pe_relocations.ds libexe_format_pe_relocations.hh)
add_datascript_parser(formats/pe/pe_tls.ds libexe_format_pe_tls.hh)
add_datascript_parser(formats/pe/pe_debug.ds libexe_format_pe_debug.hh)
add_datascript_parser(formats/pe/pe_load_config.ds libexe_format_pe_load_config.hh)
add_datascript_parser(formats/pe/pe_exception.ds libexe_format_pe_exception.hh)
add_datascript_parser(formats/pe/pe_delay_imports.ds libexe_format_pe_delay_imports.hh)
add_datascript_parser(formats/pe/pe_bound_imports.ds libexe_format_pe_bound_imports.hh)
add_datascript_parser(formats/pe/pe_security.ds libexe_format_pe_security.hh)
add_datascript_parser(formats/pe/pe_com_descriptor.ds libexe_format_pe_com_descriptor.hh)
add_datascript_parser(formats/pe/pe_iat.ds libexe_format_pe_iat.hh)

# Resource format parsers (depend on common.ds)
add_datascript_parser(formats/resources/dialogs.ds libexe_format_dialogs.hh)
add_datascript_parser(formats/resources/version.ds libexe_format_version.hh)
add_datascript_parser(formats/resources/basic.ds libexe_format_basic.hh)
add_datascript_parser(formats/resources/tables.ds libexe_format_tables.hh)
add_datascript_parser(formats/resources/fonts.ds libexe_format_fonts.hh)
add_datascript_parser(formats/resources/menus.ds libexe_format_menus.hh)

# Set up dependencies: resource parsers depend on common being generated first
add_dependencies(generate_dialogs_parser generate_common_parser)
add_dependencies(generate_version_parser generate_common_parser)
add_dependencies(generate_basic_parser generate_common_parser)
add_dependencies(generate_tables_parser generate_common_parser)
add_dependencies(generate_fonts_parser generate_common_parser)
add_dependencies(generate_menus_parser generate_common_parser)

# =============================================================================
# Main Library
# =============================================================================

add_library(libexe
        # Core files
        core/diagnostic.cpp
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
        # Decompressors
        decompressors/pklite_decompressor.cpp
        decompressors/lzexe_decompressor.cpp
        decompressors/knowledge_dynamics_decompressor.cpp
        decompressors/exepack_decompressor.cpp
        # Dialog parser
        resources/parsers/dialog_parser.cpp
)

# Make library depend on parser generation
add_dependencies(libexe
    # Modular parsers
    generate_common_parser
    generate_mz_parser
    generate_ne_header_parser
    generate_pe_header_parser
    generate_le_header_parser
    generate_pe_imports_parser
    generate_pe_exports_parser
    generate_pe_relocations_parser
    generate_pe_tls_parser
    generate_pe_debug_parser
    generate_pe_load_config_parser
    generate_pe_exception_parser
    generate_pe_delay_imports_parser
    generate_pe_bound_imports_parser
    generate_pe_security_parser
    generate_pe_com_descriptor_parser
    generate_pe_iat_parser
    generate_dialogs_parser
    generate_version_parser
    generate_basic_parser
    generate_tables_parser
    generate_fonts_parser
    generate_menus_parser
)

# Generate portable export header
generate_export_header(libexe
        BASE_NAME libexe
        EXPORT_FILE_NAME ${CMAKE_CURRENT_BINARY_DIR}/include/libexe/export.hpp
)

# Include directories
target_include_directories(libexe
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE
        ${CMAKE_BINARY_DIR}/generated
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/third-party
)

## Link dependencies
#target_link_libraries(libexe
#        PRIVATE
#        failsafe
#)

# Library properties
set_target_properties(libexe PROPERTIES
        OUTPUT_NAME exe
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
)
