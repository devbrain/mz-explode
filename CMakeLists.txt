cmake_minimum_required(VERSION 3.20)
project(libexe VERSION 2.0.0 LANGUAGES C CXX)

# C++20 standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)



# Build options
option(BUILD_SHARED_LIBS "Build shared library instead of static" ON)
option(BUILD_TESTING "Build unit tests" ON)
option(BUILD_TOOLS "Build command-line tools" OFF)

# Symbol visibility (hide all by default, like Windows)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)


# =============================================================================
# Output directories (MUST come before add_subdirectory)
# =============================================================================

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# =============================================================================
# Main Library
# =============================================================================

add_subdirectory(src/libexe)

# =============================================================================
# Tools (Command-line utilities)
# =============================================================================

if(BUILD_TOOLS)
    add_subdirectory(tools)
endif()


# =============================================================================
# Unit Tests
# =============================================================================

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(unittests)
endif()

# =============================================================================
# Documentation (Doxygen)
# =============================================================================

option(BUILD_DOCS "Build documentation (requires Doxygen)" OFF)

if(BUILD_DOCS)
    find_package(Doxygen REQUIRED)

    # Set Doxygen configuration variables
    set(DOXYGEN_PROJECT_NAME "${PROJECT_NAME}")
    set(DOXYGEN_PROJECT_VERSION "${PROJECT_VERSION}")
    set(DOXYGEN_PROJECT_BRIEF "Modern C++20 library for analyzing Windows executable files")
    set(DOXYGEN_INPUT_DIR "${CMAKE_SOURCE_DIR}/include")
    set(DOXYGEN_OUTPUT_DIR "${CMAKE_BINARY_DIR}/docs")
    set(DOXYGEN_MAIN_PAGE "${CMAKE_SOURCE_DIR}/README.md")

    # Configure Doxyfile from template
    configure_file(
        ${CMAKE_SOURCE_DIR}/Doxyfile.in
        ${CMAKE_BINARY_DIR}/Doxyfile
        @ONLY
    )

    # Add documentation target
    add_custom_target(docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM
    )

    message(STATUS "Doxygen found: ${DOXYGEN_EXECUTABLE}")
    message(STATUS "Documentation target 'docs' available")
else()
    # Check if Doxygen is available even if not requested
    find_package(Doxygen QUIET)
    if(DOXYGEN_FOUND)
        message(STATUS "Doxygen found but BUILD_DOCS=OFF. Use -DBUILD_DOCS=ON to enable.")
    endif()
endif()

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
message(STATUS "  Build docs:     ${BUILD_DOCS}")
message(STATUS "")
