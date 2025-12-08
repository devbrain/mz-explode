// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/com_descriptor.hpp>
#include <sstream>

namespace libexe {

std::string com_descriptor::runtime_version() const {
    std::ostringstream oss;
    oss << major_runtime_version << "." << minor_runtime_version;
    return oss.str();
}

} // namespace libexe
