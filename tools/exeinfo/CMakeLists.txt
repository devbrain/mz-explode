add_executable(exeinfo main.cpp)

target_link_libraries(exeinfo PRIVATE libexe)

set_target_properties(exeinfo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
