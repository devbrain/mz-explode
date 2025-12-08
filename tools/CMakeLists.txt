# Debug tools

add_executable(debug_pe debug_pe.cpp)
target_link_libraries(debug_pe PRIVATE libexe)
target_include_directories(debug_pe PRIVATE ${CMAKE_SOURCE_DIR}/include)
