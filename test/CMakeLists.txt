# =============================================================================
# libexe Tests
# =============================================================================

# =============================================================================
# Extract compressed test data
# =============================================================================
# Test data is stored compressed to keep repository small (~5MB vs ~200MB)

set(TESTDATA_ARCHIVE "${CMAKE_CURRENT_SOURCE_DIR}/testdata.tar.gz")
set(TESTDATA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/testdata")
set(TESTDATA_STAMP "${CMAKE_CURRENT_BINARY_DIR}/testdata.stamp")

if(EXISTS "${TESTDATA_ARCHIVE}")
    if(NOT EXISTS "${TESTDATA_STAMP}" OR "${TESTDATA_ARCHIVE}" IS_NEWER_THAN "${TESTDATA_STAMP}")
        message(STATUS "Extracting test data from ${TESTDATA_ARCHIVE}...")
        file(ARCHIVE_EXTRACT
            INPUT "${TESTDATA_ARCHIVE}"
            DESTINATION "${CMAKE_CURRENT_SOURCE_DIR}"
        )
        file(TOUCH "${TESTDATA_STAMP}")
        message(STATUS "Test data extracted to ${TESTDATA_DIR}")
    else()
        message(STATUS "Test data already extracted (up to date)")
    endif()
else()
    message(WARNING "Test data archive not found: ${TESTDATA_ARCHIVE}")
endif()

# =============================================================================
# Fetch doctest via neutrino-cmake
# =============================================================================

include(${NEUTRINO_CMAKE_DIR}/deps/doctest.cmake)
neutrino_fetch_doctest()

# =============================================================================
# Test Executable
# =============================================================================

add_executable(libexe_unittest
    main.cpp
    formats/test_mz_parser.cpp
    formats/test_pe_parser.cpp
    formats/test_ne_parser.cpp
    formats/test_executable_factory.cpp
    pe/test_section_parsers.cpp
    pe/directories/test_import_parser.cpp
    pe/directories/test_export_parser.cpp
    pe/directories/test_relocation_parser.cpp
    pe/directories/test_tls_parser.cpp
    pe/directories/test_debug_parser.cpp
    pe/directories/test_load_config_parser.cpp
    pe/directories/test_exception_parser.cpp
    pe/directories/test_delay_import_parser.cpp
    pe/directories/test_bound_import_parser.cpp
    pe/directories/test_security_parser.cpp
    pe/directories/test_com_descriptor_parser.cpp
    pe/directories/test_iat_parser.cpp
    pe/directories/test_global_ptr_parser.cpp
    formats/test_architecture_parser.cpp
    pe/directories/test_reserved_parser.cpp
    resources/test_pe_resources.cpp
    resources/test_ne_resources.cpp
    resources/test_icon_parsers.cpp
    resources/test_font_parsers.cpp
    resources/test_version_manifest_parsers.cpp
    resources/test_string_accelerator_parsers.cpp
    resources/test_dialog_parser.cpp
    resources/test_menu_parser.cpp
    resources/test_bitmap_message_parsers.cpp
    resources/test_os2_resource_parser.cpp
    pe/test_corkami_corpus.cpp
    pe/test_corkami_validation.cpp
    pe/test_corkami_generated.cpp
    explode/test_pklite.cpp
    explode/test_lzexe.cpp
    explode/test_knowledge_dynamics.cpp
    explode/test_exepack.cpp
    explode/test_bit_reader.cpp
    testdata/data_wrapper.cpp
    ne/test_progman.cpp
    ne/test_ne_font.cpp
    pe/test_pe32.cpp
    pe/test_pe64.cpp
    le/test_le_strip.cpp
    le/test_le_entry.cpp
    le/test_le_import.cpp
    le/test_le_fixup.cpp
    le/test_le_resource.cpp
    le/test_le_decompress.cpp
    le/test_lx_real.cpp
    testdata/compressed_data_wrapper.cpp
    pe/test_tcmadm64_parser.cpp
    pe/test_rich_parser.cpp
    pe/test_security_analysis.cpp
    core/test_diagnostics.cpp
    testdata/corkami/corkami_test_data.cc
    testdata/pe/scheduler.cc
    test_helpers/md5.c
)

target_link_libraries(libexe_unittest
    PRIVATE
        libexe
        doctest::doctest
)

target_include_directories(libexe_unittest
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Set target properties
set_target_properties(libexe_unittest PROPERTIES
    FOLDER "Tests"
)

# Register with CTest
include(CTest)
add_test(NAME libexe_tests COMMAND libexe_unittest)
