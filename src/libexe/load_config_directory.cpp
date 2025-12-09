// libexe - Modern executable file analysis library
// Copyright (c) 2024

#include <libexe/pe/directories/load_config.hpp>
#include <sstream>
#include <cstring>

namespace libexe {

std::string load_config_directory::guard_flags_string() const {
    if (guard_flags == 0) {
        return "None";
    }

    std::ostringstream oss;
    bool first = true;

    auto add_flag = [&](const char* name) {
        if (!first) oss << " | ";
        oss << name;
        first = false;
    };

    // IMAGE_GUARD_CF_INSTRUMENTED (0x00000100)
    if (guard_flags & 0x00000100) {
        add_flag("CF_INSTRUMENTED");
    }

    // IMAGE_GUARD_CFW_INSTRUMENTED (0x00000200)
    if (guard_flags & 0x00000200) {
        add_flag("CFW_INSTRUMENTED");
    }

    // IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT (0x00000400)
    if (guard_flags & 0x00000400) {
        add_flag("CF_FUNCTION_TABLE_PRESENT");
    }

    // IMAGE_GUARD_SECURITY_COOKIE_UNUSED (0x00000800)
    if (guard_flags & 0x00000800) {
        add_flag("SECURITY_COOKIE_UNUSED");
    }

    // IMAGE_GUARD_PROTECT_DELAYLOAD_IAT (0x00001000)
    if (guard_flags & 0x00001000) {
        add_flag("PROTECT_DELAYLOAD_IAT");
    }

    // IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION (0x00002000)
    if (guard_flags & 0x00002000) {
        add_flag("DELAYLOAD_IAT_IN_ITS_OWN_SECTION");
    }

    // IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT (0x00004000)
    if (guard_flags & 0x00004000) {
        add_flag("CF_EXPORT_SUPPRESSION_INFO_PRESENT");
    }

    // IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION (0x00008000)
    if (guard_flags & 0x00008000) {
        add_flag("CF_ENABLE_EXPORT_SUPPRESSION");
    }

    // IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT (0x00010000)
    if (guard_flags & 0x00010000) {
        add_flag("CF_LONGJUMP_TABLE_PRESENT");
    }

    // IMAGE_GUARD_RF_INSTRUMENTED (0x00020000)
    if (guard_flags & 0x00020000) {
        add_flag("RF_INSTRUMENTED");
    }

    // IMAGE_GUARD_RF_ENABLE (0x00040000)
    if (guard_flags & 0x00040000) {
        add_flag("RF_ENABLE");
    }

    // IMAGE_GUARD_RF_STRICT (0x00080000)
    if (guard_flags & 0x00080000) {
        add_flag("RF_STRICT");
    }

    // IMAGE_GUARD_RETPOLINE_PRESENT (0x00100000)
    if (guard_flags & 0x00100000) {
        add_flag("RETPOLINE_PRESENT");
    }

    // IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT (0x00400000)
    if (guard_flags & 0x00400000) {
        add_flag("EH_CONTINUATION_TABLE_PRESENT");
    }

    // IMAGE_GUARD_XFG_ENABLED (0x00800000)
    if (guard_flags & 0x00800000) {
        add_flag("XFG_ENABLED");
    }

    // IMAGE_GUARD_CASTGUARD_PRESENT (0x01000000)
    if (guard_flags & 0x01000000) {
        add_flag("CASTGUARD_PRESENT");
    }

    // IMAGE_GUARD_MEMCPY_PRESENT (0x02000000)
    if (guard_flags & 0x02000000) {
        add_flag("MEMCPY_PRESENT");
    }

    return oss.str();
}

uint32_t load_config_directory::get_min_size_for_version(bool is_64bit, const char* version) {
    // Minimum structure sizes for different Windows versions
    // These are approximate - actual sizes may vary

    if (is_64bit) {
        // 64-bit sizes
        if (std::strcmp(version, "XP") == 0) return 112;
        if (std::strcmp(version, "Vista") == 0) return 112;
        if (std::strcmp(version, "7") == 0) return 112;
        if (std::strcmp(version, "8") == 0) return 148;
        if (std::strcmp(version, "8.1") == 0) return 160;
        if (std::strcmp(version, "10") == 0) return 256;
        return 112;  // Default minimum
    } else {
        // 32-bit sizes
        if (std::strcmp(version, "XP") == 0) return 64;
        if (std::strcmp(version, "Vista") == 0) return 72;
        if (std::strcmp(version, "7") == 0) return 72;
        if (std::strcmp(version, "8") == 0) return 92;
        if (std::strcmp(version, "8.1") == 0) return 96;
        if (std::strcmp(version, "10") == 0) return 148;
        return 64;  // Default minimum
    }
}

} // namespace libexe
