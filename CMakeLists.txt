cmake_minimum_required(VERSION 3.20)
project(libexe VERSION 2.0.0 LANGUAGES C CXX)

# C++20 standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Include required modules
include(GenerateExportHeader)
include(FetchContent)

# Build options
option(BUILD_SHARED_LIBS "Build shared library instead of static" ON)
option(BUILD_TESTING "Build unit tests" ON)
option(BUILD_TOOLS "Build command-line tools" ON)

# Symbol visibility (hide all by default, like Windows)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)

# =============================================================================
# Dependencies
# =============================================================================

# DataScript - binary format parser generator
FetchContent_Declare(
    datascript
    GIT_REPOSITORY https://github.com/devbrain/datascript.git
    GIT_TAG master
)

# Failsafe - header-only logging and exception handling
FetchContent_Declare(
    failsafe
    GIT_REPOSITORY https://github.com/devbrain/failsafe.git
    GIT_TAG master
)

FetchContent_MakeAvailable(datascript failsafe)

# =============================================================================
# DataScript Code Generation
# =============================================================================

function(add_datascript_parser SCHEMA_FILE)
    get_filename_component(SCHEMA_NAME ${SCHEMA_FILE} NAME_WE)
    set(GENERATED_HEADER "${CMAKE_BINARY_DIR}/generated/${SCHEMA_NAME}.h")

    add_custom_command(
        OUTPUT ${GENERATED_HEADER}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/generated
        COMMAND ds ${CMAKE_CURRENT_SOURCE_DIR}/${SCHEMA_FILE} -t cpp -o ${CMAKE_BINARY_DIR}/generated/
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
add_datascript_parser(formats/exe_format_complete.ds)

# =============================================================================
# Main Library
# =============================================================================

add_library(libexe
    # Core files
    src/libexe/executable_file.cpp
    src/libexe/executable_factory.cpp
    src/libexe/mz_file.cpp
    src/libexe/pe_file.cpp
    src/libexe/ne_file.cpp
    # Decompressors
        src/libexe/decompressors/pklite_decompressor.cpp
        src/libexe/decompressors/lzexe_decompressor.cpp
        src/libexe/decompressors/knowledge_dynamics_decompressor.cpp
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
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}/generated
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Link dependencies
target_link_libraries(libexe
    PRIVATE
        failsafe
)

# Library properties
set_target_properties(libexe PROPERTIES
    OUTPUT_NAME exe
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# =============================================================================
# Tools (Command-line utilities)
# =============================================================================

if(BUILD_TOOLS)
    # mzexplode - decompression tool (legacy compatibility)
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tools/mzexplode/main.cpp)
        add_executable(mzexplode tools/mzexplode/main.cpp)
        target_link_libraries(mzexplode PRIVATE libexe)
    endif()

    # mzdump - diagnostic tool (legacy compatibility)
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tools/mzdump/main.cpp)
        add_executable(mzdump tools/mzdump/main.cpp)
        target_link_libraries(mzdump PRIVATE libexe)
    endif()
endif()

# Legacy code removed - modern implementation complete

# =============================================================================
# Unit Tests
# =============================================================================

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(unittests)
endif()

# =============================================================================
# Output directories
# =============================================================================

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# =============================================================================
# Status Messages
# =============================================================================

message(STATUS "")
message(STATUS "libexe configuration:")
message(STATUS "  Version:        ${PROJECT_VERSION}")
message(STATUS "  C++ Standard:   C++${CMAKE_CXX_STANDARD}")
message(STATUS "  Build type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "  Library type:   ${BUILD_SHARED_LIBS}")
message(STATUS "  Build tools:    ${BUILD_TOOLS}")
message(STATUS "  Build tests:    ${BUILD_TESTING}")
message(STATUS "")
