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

# Tools disabled - legacy code uses old 'explode' library
# TODO: Rewrite mzexplode/mzdump to use modern libexe API
# if(BUILD_TOOLS)
#     add_subdirectory(src/mzexplode)
#     add_subdirectory(src/mzdump)
# endif()

# =============================================================================
# Unit Tests
# =============================================================================

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(unittests)
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
message(STATUS "")
