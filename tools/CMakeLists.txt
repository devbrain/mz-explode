# =============================================================================
# Command-line tools using libexe
# =============================================================================

# Debug tool
add_executable(debug_pe debug_pe.cpp)
target_link_libraries(debug_pe PRIVATE libexe)
set_target_properties(debug_pe PROPERTIES FOLDER "Tools")

# Unified executable analyzer
add_subdirectory(exeinfo)
