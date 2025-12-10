# Command-line tools using libexe

# Debug tool
add_executable(debug_pe debug_pe.cpp)
target_link_libraries(debug_pe PRIVATE libexe)
target_include_directories(debug_pe PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Unified executable analyzer (replaces mzexplode, mzdump, peinfo, resextract)
add_subdirectory(exeinfo)
