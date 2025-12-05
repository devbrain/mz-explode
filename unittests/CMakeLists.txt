# Unit tests using doctest framework

# Try to find system doctest first
find_package(doctest QUIET)

if(NOT doctest_FOUND)
    message(STATUS "doctest not found, fetching from GitHub")
    FetchContent_Declare(
        doctest
        GIT_REPOSITORY https://github.com/doctest/doctest.git
        GIT_TAG v2.4.12
    )
    set(DOCTEST_NO_INSTALL ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(doctest)
endif()

# Unit test executable
add_executable(libexe_unittest
    main.cpp
    test_mz_parser.cpp
    test_legacy_data.cpp
    test_pklite_decompress.cpp
    test_lzexe_decompress.cpp
    test_knowledge_dynamics_decompress.cpp
    test_bit_reader.cpp
    legacy_data_wrapper.cpp  # Includes all legacy test data with proper headers
)

target_link_libraries(libexe_unittest
    PRIVATE
        libexe
        doctest::doctest
)

# Provide test data directory path
target_compile_definitions(libexe_unittest
    PRIVATE
        UNITTEST_HOME="${CMAKE_CURRENT_SOURCE_DIR}"
)

# Register tests with CTest
include(${doctest_SOURCE_DIR}/scripts/cmake/doctest.cmake)
doctest_discover_tests(libexe_unittest)
