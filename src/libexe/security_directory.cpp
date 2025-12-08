// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/security_directory.hpp>
#include <algorithm>

namespace libexe {

bool security_directory::has_authenticode() const {
    return std::any_of(certificates.begin(), certificates.end(),
                      [](const security_certificate& cert) {
                          return cert.is_authenticode();
                      });
}

const security_certificate* security_directory::get_authenticode() const {
    for (const auto& cert : certificates) {
        if (cert.is_authenticode()) {
            return &cert;
        }
    }
    return nullptr;
}

size_t security_directory::total_size() const {
    size_t total = 0;
    for (const auto& cert : certificates) {
        total += cert.length;
    }
    return total;
}

} // namespace libexe
