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
            COMMAND ds ${CMAKE_CURRENT_SOURCE_DIR}/${SCHEMA_FILE} -t cpp -o ${CMAKE_BINARY_DIR}/generated/ --cpp-output-name=${OUTPUT_NAME_WE}
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

# Generate parser from executable format specification
add_datascript_parser(formats/exe_format_complete.ds exe_format.hh)

# =============================================================================
# Main Library
# =============================================================================

add_library(libexe
        # Core files
        executable_file.cpp
        executable_factory.cpp
        mz_file.cpp
        pe_file.cpp
        ne_file.cpp
        # Decompressors
        decompressors/pklite_decompressor.cpp
        decompressors/lzexe_decompressor.cpp
        decompressors/knowledge_dynamics_decompressor.cpp
        decompressors/exepack_decompressor.cpp
)

# Make library depend on parser generation
add_dependencies(libexe generate_exe_format_complete_parser)

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
