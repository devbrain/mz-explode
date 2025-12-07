# =============================================================================
# Fetch doctest if not already available
# =============================================================================

# Guard: check if doctest target already exists (provided by parent project)
if(NOT TARGET doctest::doctest AND NOT TARGET doctest)
    find_package(doctest QUIET)
endif()

if(NOT doctest_FOUND AND NOT TARGET doctest::doctest AND NOT TARGET doctest)
    message(STATUS "doctest not found, fetching from GitHub...")

    include(FetchContent)
    set(FETCHCONTENT_QUIET OFF)

    # Allow FetchContent_Populate to be used (suppress CMP0169 warning)
    if(POLICY CMP0169)
        cmake_policy(SET CMP0169 OLD)
    endif()

    # Configure doctest options
    set(DOCTEST_WITH_TESTS OFF CACHE INTERNAL "")
    set(DOCTEST_WITH_MAIN_IN_STATIC_LIB OFF CACHE INTERNAL "")
    set(DOCTEST_NO_INSTALL ON CACHE INTERNAL "")

    FetchContent_Declare(
            doctest
            GIT_REPOSITORY https://github.com/doctest/doctest.git
            GIT_TAG v2.4.12
            GIT_PROGRESS TRUE
    )

    # Fetch the content first
    FetchContent_GetProperties(doctest)
    if(NOT doctest_POPULATED)
        FetchContent_Populate(doctest)

        # Patch the CMakeLists.txt to fix deprecation warning
        file(READ ${doctest_SOURCE_DIR}/CMakeLists.txt DOCTEST_CMAKE_CONTENT)
        # Replace any version less than 3.10 with 3.10
        string(REGEX REPLACE "cmake_minimum_required\\(VERSION [0-9]+\\.[0-9]+\\)"
                "cmake_minimum_required(VERSION 3.10)"
                DOCTEST_CMAKE_CONTENT "${DOCTEST_CMAKE_CONTENT}")
        file(WRITE ${doctest_SOURCE_DIR}/CMakeLists.txt "${DOCTEST_CMAKE_CONTENT}")

        # Now add the subdirectory
        add_subdirectory(${doctest_SOURCE_DIR} ${doctest_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()

    # Verify doctest::doctest target was created
    if(TARGET doctest::doctest)
        message(STATUS "doctest::doctest target created successfully")
    elseif(TARGET doctest)
        # Create alias if only 'doctest' target exists
        add_library(doctest::doctest ALIAS doctest)
        message(STATUS "Created doctest::doctest alias")
    else()
        message(FATAL_ERROR "doctest failed to create expected targets")
    endif()
else()
    # doctest already available (from system or parent project)
    if(TARGET doctest::doctest)
        message(STATUS "Using existing doctest::doctest target")
    elseif(TARGET doctest)
        message(STATUS "Using existing doctest target, creating alias")
        add_library(doctest::doctest ALIAS doctest)
    else()
        message(STATUS "Using system-provided doctest")
    endif()
endif()

# Unit test executable
add_executable(libexe_unittest
    main.cpp
    test_mz_parser.cpp
    test_pe_parser.cpp
    test_ne_parser.cpp
    test_executable_factory.cpp
    test_progman.cpp  # Real NE file (Windows 3.11 Program Manager)
    explode/test_pklite.cpp
    explode/test_lzexe.cpp
    explode/test_knowledge_dynamics.cpp
    explode/test_exepack.cpp  # MD5 verification - EXEPACK
    explode/test_bit_reader.cpp
    explode/data_wrapper.cpp  # Includes all test data with proper headers
    md5.c  # MD5 implementation for verification
)

target_link_libraries(libexe_unittest
    PRIVATE
        libexe
        doctest::doctest
)

target_include_directories(libexe_unittest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Register tests with CTest
if(DEFINED doctest_SOURCE_DIR AND EXISTS ${doctest_SOURCE_DIR}/scripts/cmake/doctest.cmake)
    # Using FetchContent doctest - can use discovery
    include(${doctest_SOURCE_DIR}/scripts/cmake/doctest.cmake)
    doctest_discover_tests(libexe_unittest)
else()
    # Using system/parent-provided doctest - simple test registration
    add_test(NAME libexe_unittest COMMAND libexe_unittest)
endif()
