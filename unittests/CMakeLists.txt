# =============================================================================
# Fetch doctest if not already available
# =============================================================================

# Guard: check if doctest target already exists (provided by parent project)
if (NOT TARGET doctest::doctest AND NOT TARGET doctest)
    find_package(doctest QUIET)
endif ()

if (NOT doctest_FOUND AND NOT TARGET doctest::doctest AND NOT TARGET doctest)
    message(STATUS "doctest not found, fetching from GitHub...")

    include(FetchContent)
    set(FETCHCONTENT_QUIET OFF)

    # Allow FetchContent_Populate to be used (suppress CMP0169 warning)
    if (POLICY CMP0169)
        cmake_policy(SET CMP0169 OLD)
    endif ()

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
    if (NOT doctest_POPULATED)
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
    endif ()

    # Verify doctest::doctest target was created
    if (TARGET doctest::doctest)
        message(STATUS "doctest::doctest target created successfully")
    elseif (TARGET doctest)
        # Create alias if only 'doctest' target exists
        add_library(doctest::doctest ALIAS doctest)
        message(STATUS "Created doctest::doctest alias")
    else ()
        message(FATAL_ERROR "doctest failed to create expected targets")
    endif ()
else ()
    # doctest already available (from system or parent project)
    if (TARGET doctest::doctest)
        message(STATUS "Using existing doctest::doctest target")
    elseif (TARGET doctest)
        message(STATUS "Using existing doctest target, creating alias")
        add_library(doctest::doctest ALIAS doctest)
    else ()
        message(STATUS "Using system-provided doctest")
    endif ()
endif ()

# Unit test executable
add_executable(libexe_unittest
        main.cpp
        test_mz_parser.cpp
        test_pe_parser.cpp
        test_ne_parser.cpp
        test_executable_factory.cpp
        test_section_parsers.cpp        # Section parser comprehensive tests
        test_import_parser.cpp          # Import directory parser tests
        test_export_parser.cpp          # Export directory parser tests
        test_relocation_parser.cpp      # Base relocation parser tests
        test_tls_parser.cpp             # TLS directory parser tests
        test_debug_parser.cpp           # Debug directory parser tests
        test_load_config_parser.cpp     # Load config directory parser tests
        test_exception_parser.cpp       # Exception directory parser tests
        test_delay_import_parser.cpp    # Delay import directory parser tests
        test_bound_import_parser.cpp    # Bound import directory parser tests
        test_security_parser.cpp        # Security directory parser tests
        test_com_descriptor_parser.cpp  # COM descriptor parser tests (.NET CLR)
        test_iat_parser.cpp             # IAT (Import Address Table) parser tests
        test_global_ptr_parser.cpp      # Global Pointer parser tests (IA64)
        test_architecture_parser.cpp    # Architecture parser tests (reserved)
        test_reserved_parser.cpp        # Reserved parser tests (must be zero)
        resources/test_pe_resources.cpp     # PE resource extraction tests
        resources/test_ne_resources.cpp     # NE resource extraction tests
        resources/test_icon_parsers.cpp     # Icon parser tests
        resources/test_font_parsers.cpp     # Font parser tests
        resources/test_version_manifest_parsers.cpp  # Version & Manifest parser tests
        resources/test_string_accelerator_parsers.cpp  # String & Accelerator parser tests
        resources/test_dialog_parser.cpp    # Dialog parser tests - NE and PE formats
        resources/test_menu_parser.cpp      # Menu parser tests
        resources/test_bitmap_message_parsers.cpp  # Bitmap & Message Table parser tests
        explode/test_pklite.cpp
        explode/test_lzexe.cpp
        explode/test_knowledge_dynamics.cpp
        explode/test_exepack.cpp  # MD5 verification - EXEPACK
        explode/test_bit_reader.cpp
        explode/data_wrapper.cpp  # Includes all decompressor test data
        formats/test_progman.cpp  # Real NE file (Windows 3.11 Program Manager)
        formats/test_ne_font.cpp  # Real NE font (Windows 3.11 CGA font)
        formats/test_pe32.cpp     # Real PE32 file (32-bit executable)
        formats/test_pe64.cpp     # Real PE32+ file (64-bit executable)
        formats/data_wrapper.cpp  # Includes all PE/NE format test data
        md5.c  # MD5 implementation for verification
)

target_link_libraries(libexe_unittest
        PRIVATE
        libexe
        doctest::doctest
)

target_include_directories(libexe_unittest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Register tests with CTest
if (DEFINED doctest_SOURCE_DIR AND EXISTS ${doctest_SOURCE_DIR}/scripts/cmake/doctest.cmake)
    # Using FetchContent doctest - can use discovery
    include(${doctest_SOURCE_DIR}/scripts/cmake/doctest.cmake)
    doctest_discover_tests(libexe_unittest)
else ()
    # Using system/parent-provided doctest - simple test registration
    add_test(NAME libexe_unittest COMMAND libexe_unittest)
endif ()
