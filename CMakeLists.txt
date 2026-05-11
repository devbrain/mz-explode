# =============================================================================
# libexe - Windows Executable Format Analysis Library
# =============================================================================

cmake_minimum_required(VERSION 3.20)

project(libexe
    VERSION 2.0.0
    DESCRIPTION "Modern C++20 library for analyzing Windows executable files"
    LANGUAGES C CXX
)

# =============================================================================
# Neutrino CMake Integration
# =============================================================================

include(FetchContent)

if(NOT DEFINED NEUTRINO_CMAKE_DIR)
    FetchContent_Declare(
        neutrino_cmake
        GIT_REPOSITORY https://github.com/devbrain/neutrino-cmake.git
        GIT_TAG master
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(neutrino_cmake)
    set(NEUTRINO_CMAKE_DIR "${neutrino_cmake_SOURCE_DIR}/cmake")
endif()

list(APPEND CMAKE_MODULE_PATH "${NEUTRINO_CMAKE_DIR}")
include(NeutrinoInit)

# =============================================================================
# Options
# =============================================================================

neutrino_define_library_options(mzexplode)

# Runtime tools option - CLI tools that read files from disk
neutrino_is_top_level(_mzexplode_is_top_level)
if(_mzexplode_is_top_level AND NOT CMAKE_CROSSCOMPILING)
    option(NEUTRINO_MZEXPLODE_BUILD_TOOLS "Build command-line tools" OFF)
else()
    option(NEUTRINO_MZEXPLODE_BUILD_TOOLS "Build command-line tools" OFF)
endif()

# -----------------------------------------------------------------------------
# Fine-grained format / decompressor selection
# -----------------------------------------------------------------------------
# libexe supports four executable formats and five decompressors. A typical
# DOS-asset extraction job (e.g. warlords W1) needs only MZ + LZEXE; a
# generic Windows binary analyzer needs everything. Default to ALL ON so
# existing consumers see no change; size-conscious downstreams can do:
#
#   set(NEUTRINO_MZEXPLODE_FORMAT_ALL       OFF CACHE BOOL "" FORCE)
#   set(NEUTRINO_MZEXPLODE_FORMAT_NE        ON  CACHE BOOL "" FORCE)
#   set(NEUTRINO_MZEXPLODE_DECOMPRESSOR_ALL OFF CACHE BOOL "" FORCE)
#   set(NEUTRINO_MZEXPLODE_DECOMPRESSOR_LZEXE ON CACHE BOOL "" FORCE)
#
# MZ format is always on — it's the foundation that all newer formats
# (NE/PE/LE) embed via the MZ stub at the start of the file.

neutrino_option_group(NEUTRINO_MZEXPLODE_FORMAT_ALL
    "Default state for all libexe executable-format readers" ON)
neutrino_option(NEUTRINO_MZEXPLODE_FORMAT_NE
    "Build NE (16-bit Windows / OS/2) format reader" ON
    GROUP NEUTRINO_MZEXPLODE_FORMAT_ALL)
neutrino_option(NEUTRINO_MZEXPLODE_FORMAT_PE
    "Build PE (32/64-bit Windows) format reader + authenticode" ON
    GROUP NEUTRINO_MZEXPLODE_FORMAT_ALL)
neutrino_option(NEUTRINO_MZEXPLODE_FORMAT_LE
    "Build LE/LX (Win9x VxD / OS/2) format reader" ON
    GROUP NEUTRINO_MZEXPLODE_FORMAT_ALL)

neutrino_option_group(NEUTRINO_MZEXPLODE_DECOMPRESSOR_ALL
    "Default state for all libexe decompressors" ON)
neutrino_option(NEUTRINO_MZEXPLODE_DECOMPRESSOR_LZEXE
    "Build LZEXE 0.90/0.91 decompressor" ON
    GROUP NEUTRINO_MZEXPLODE_DECOMPRESSOR_ALL)
neutrino_option(NEUTRINO_MZEXPLODE_DECOMPRESSOR_PKLITE
    "Build PKLITE (standard + extra) decompressor" ON
    GROUP NEUTRINO_MZEXPLODE_DECOMPRESSOR_ALL)
neutrino_option(NEUTRINO_MZEXPLODE_DECOMPRESSOR_EXEPACK
    "Build Microsoft EXEPACK decompressor" ON
    GROUP NEUTRINO_MZEXPLODE_DECOMPRESSOR_ALL)
neutrino_option(NEUTRINO_MZEXPLODE_DECOMPRESSOR_DIET
    "Build DIET decompressor" ON
    GROUP NEUTRINO_MZEXPLODE_DECOMPRESSOR_ALL)
neutrino_option(NEUTRINO_MZEXPLODE_DECOMPRESSOR_KD
    "Build Knowledge Dynamics decompressor" ON
    GROUP NEUTRINO_MZEXPLODE_DECOMPRESSOR_ALL)

# =============================================================================
# C++ Standard
# =============================================================================

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Symbol visibility (hide all by default, like Windows)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)

# =============================================================================
# Output directories
# =============================================================================

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# =============================================================================
# Main Library
# =============================================================================

add_subdirectory(src/libexe)

# Create neutrino:: alias (matches neutrino-cmake recipe)
if(TARGET libexe AND NOT TARGET neutrino::mzexplode)
    add_library(neutrino::mzexplode ALIAS libexe)
endif()

# =============================================================================
# Tools (Command-line utilities)
# =============================================================================

# Runtime tools are disabled when cross-compiling (e.g., Emscripten)
# They require filesystem access and mio memory-mapped I/O
if(NEUTRINO_MZEXPLODE_BUILD_TOOLS)
    if(CMAKE_CROSSCOMPILING)
        message(STATUS "Tools disabled: cross-compiling (mio not available)")
    else()
        add_subdirectory(tools)
    endif()
endif()

# =============================================================================
# Unit Tests
# =============================================================================

if(NEUTRINO_MZEXPLODE_BUILD_TESTS)
    if(CMAKE_CROSSCOMPILING)
        message(STATUS "Tests disabled: cross-compiling (requires filesystem access)")
    else()
        enable_testing()
        add_subdirectory(test)
    endif()
endif()

# =============================================================================
# Documentation (Doxygen)
# =============================================================================

if(NEUTRINO_MZEXPLODE_BUILD_DOCS)
    find_package(Doxygen REQUIRED)

    set(DOXYGEN_PROJECT_NAME "${PROJECT_NAME}")
    set(DOXYGEN_PROJECT_VERSION "${PROJECT_VERSION}")
    set(DOXYGEN_PROJECT_BRIEF "Modern C++20 library for analyzing Windows executable files")
    set(DOXYGEN_INPUT_DIR "${CMAKE_SOURCE_DIR}/include")
    set(DOXYGEN_OUTPUT_DIR "${CMAKE_BINARY_DIR}/docs")
    set(DOXYGEN_MAIN_PAGE "${CMAKE_SOURCE_DIR}/README.md")

    configure_file(
        ${CMAKE_SOURCE_DIR}/Doxyfile.in
        ${CMAKE_BINARY_DIR}/Doxyfile
        @ONLY
    )

    add_custom_target(docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM
    )

    message(STATUS "Documentation target 'docs' available")
endif()

# =============================================================================
# Installation
# =============================================================================

if(NEUTRINO_MZEXPLODE_INSTALL)
    include(GNUInstallDirs)
    include(CMakePackageConfigHelpers)

    # Install library (without export since private deps can't be exported)
    install(TARGETS libexe
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

    # Install headers
    install(DIRECTORY include/libexe
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    # Install generated export header
    install(FILES
        ${CMAKE_BINARY_DIR}/src/libexe/include/libexe/export.hpp
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libexe
    )

    # Install tools (if built)
    if(TARGET exeinfo AND NOT CMAKE_CROSSCOMPILING)
        install(TARGETS exeinfo
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )
    endif()
endif()

# =============================================================================
# Summary
# =============================================================================

neutrino_is_top_level(_mzexplode_is_top_level)
if(_mzexplode_is_top_level)
    neutrino_print_options(mzexplode)
    neutrino_print_summary(mzexplode)
endif()
