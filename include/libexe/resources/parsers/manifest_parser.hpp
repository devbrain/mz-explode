#ifndef LIBEXE_MANIFEST_PARSER_HPP
#define LIBEXE_MANIFEST_PARSER_HPP

#include <libexe/export.hpp>
#include <libexe/core/enum_bitmask.hpp>
#include <cstdint>
#include <span>
#include <string>
#include <optional>

namespace libexe {

/**
 * UAC execution level requested by the manifest.
 */
enum class uac_execution_level : uint8_t {
    UNSPECIFIED = 0,          // No requestedExecutionLevel element
    AS_INVOKER = 1,           // asInvoker - run with same privileges as parent
    HIGHEST_AVAILABLE = 2,    // highestAvailable - run with highest available privileges
    REQUIRE_ADMINISTRATOR = 3 // requireAdministrator - always elevate to admin
};

/**
 * DPI awareness mode specified in the manifest.
 */
enum class dpi_awareness_mode : uint8_t {
    UNSPECIFIED = 0,        // No DPI awareness specified
    UNAWARE = 1,            // DPI unaware (application uses 96 DPI)
    SYSTEM_AWARE = 2,       // System DPI aware (scales once at logon)
    PER_MONITOR = 3,        // Per-Monitor DPI aware (Windows 8.1+)
    PER_MONITOR_V2 = 4      // Per-Monitor V2 DPI aware (Windows 10 1703+)
};

/**
 * Windows version compatibility flags.
 *
 * Bitmask enum - multiple versions can be supported simultaneously.
 */
enum class windows_version_flags : uint32_t {
    NONE = 0,
    VISTA = 1 << 0,   // Windows Vista / Server 2008
    WIN7 = 1 << 1,    // Windows 7 / Server 2008 R2
    WIN8 = 1 << 2,    // Windows 8 / Server 2012
    WIN8_1 = 1 << 3,  // Windows 8.1 / Server 2012 R2
    WIN10 = 1 << 4,   // Windows 10 / Server 2016+
    WIN11 = 1 << 5    // Windows 11
};

/**
 * Additional manifest settings flags.
 *
 * Bitmask enum - multiple flags can be set simultaneously.
 */
enum class manifest_flags : uint32_t {
    NONE = 0,
    AUTO_ELEVATE = 1 << 0,                      // autoElevate enabled
    DISABLE_THEMING = 1 << 1,                   // disableTheming
    DISABLE_WINDOW_FILTERING = 1 << 2,          // disableWindowFiltering
    PRINTER_DRIVER_ISOLATION = 1 << 3,          // printerDriverIsolation
    LONG_PATH_AWARE = 1 << 4,                   // longPathAware (>260 chars)
    UTF8_CODE_PAGE = 1 << 5,                    // activeCodePage UTF-8
    SEGMENT_HEAP = 1 << 6,                      // heapType SegmentHeap
    GDI_SCALING = 1 << 7,                       // gdiScaling
    HIGH_RESOLUTION_SCROLLING = 1 << 8,         // highResolutionScrollingAware
    ULTRA_HIGH_RESOLUTION_SCROLLING = 1 << 9    // ultraHighResolutionScrollingAware
};

// Enable bitmask operators for flag enums
template<>
struct enable_bitmask_operators<windows_version_flags> {
    static constexpr bool enable = true;
};

template<>
struct enable_bitmask_operators<manifest_flags> {
    static constexpr bool enable = true;
};


/**
 * Application manifest resource (RT_MANIFEST).
 *
 * Contains XML manifest data for side-by-side assembly configuration,
 * UAC settings, DPI awareness, and other application metadata.
 *
 * Note: This parser extracts the raw XML and provides basic access.
 * Full XML parsing and validation is the responsibility of upper layers
 * (using xml.h or other XML libraries).
 */
struct LIBEXE_EXPORT manifest_data {
    std::string xml;  // Raw XML manifest data (UTF-8)

    /**
     * Check if manifest is empty.
     */
    [[nodiscard]] bool empty() const {
        return xml.empty();
    }

    /**
     * Get manifest size in bytes.
     */
    [[nodiscard]] size_t size() const {
        return xml.size();
    }

    /**
     * Check if manifest contains a specific string (case-sensitive).
     *
     * Useful for quick checks like:
     * - contains("requestedExecutionLevel") - has UAC settings
     * - contains("dpiAware") - has DPI awareness
     * - contains("supportedOS") - has OS compatibility info
     *
     * @param str String to search for
     * @return true if found, false otherwise
     */
    [[nodiscard]] bool contains(const std::string& str) const {
        return xml.find(str) != std::string::npos;
    }

    // =========================================================================
    // Primary Getters - Return Enums/Bitmasks
    // =========================================================================

    /**
     * Get UAC execution level requested by manifest.
     *
     * @return Execution level enum value
     */
    [[nodiscard]] uac_execution_level get_uac_execution_level() const {
        if (contains("requireAdministrator")) {
            return uac_execution_level::REQUIRE_ADMINISTRATOR;
        }
        if (contains("highestAvailable")) {
            return uac_execution_level::HIGHEST_AVAILABLE;
        }
        if (contains("asInvoker")) {
            return uac_execution_level::AS_INVOKER;
        }
        return uac_execution_level::UNSPECIFIED;
    }

    /**
     * Get DPI awareness mode specified in manifest.
     *
     * @return DPI awareness mode enum value
     */
    [[nodiscard]] dpi_awareness_mode get_dpi_awareness() const {
        // Check modern dpiAwareness element first (Windows 10+)
        if (contains("PerMonitorV2")) {
            return dpi_awareness_mode::PER_MONITOR_V2;
        }
        if (contains("PerMonitor") && contains("dpiAwareness")) {
            return dpi_awareness_mode::PER_MONITOR;
        }
        if (contains("System") && contains("dpiAwareness")) {
            return dpi_awareness_mode::SYSTEM_AWARE;
        }
        if (contains("dpiAwareness")) {
            return dpi_awareness_mode::UNAWARE;  // Explicitly set to unaware
        }

        // Check legacy dpiAware element
        if (contains("dpiAware")) {
            if (contains("true") || contains("True") || contains("PM") || contains("PerMonitor")) {
                return dpi_awareness_mode::SYSTEM_AWARE;  // Legacy dpiAware=true
            }
        }

        return dpi_awareness_mode::UNSPECIFIED;
    }

    /**
     * Get Windows version compatibility flags.
     *
     * @return Bitmask of supported Windows versions
     */
    [[nodiscard]] windows_version_flags get_windows_compatibility() const {
        windows_version_flags result = windows_version_flags::NONE;

        if (contains("{e2011457-1546-43c5-a5fe-008deee3d3f0}")) {
            result |= windows_version_flags::VISTA;
        }
        if (contains("{35138b9a-5d96-4fbd-8e2d-a2440225f93a}")) {
            result |= windows_version_flags::WIN7;
        }
        if (contains("{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}")) {
            result |= windows_version_flags::WIN8;
        }
        if (contains("{1f676c76-80e1-4239-95bb-83d0f6d0da78}")) {
            result |= windows_version_flags::WIN8_1;
        }
        if (contains("{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}")) {
            result |= windows_version_flags::WIN10;
        }
        if (contains("{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9b}")) {
            result |= windows_version_flags::WIN11;
        }

        return result;
    }

    /**
     * Get additional manifest settings flags.
     *
     * @return Bitmask of manifest settings
     */
    [[nodiscard]] manifest_flags get_flags() const {
        manifest_flags result = manifest_flags::NONE;

        if (contains("autoElevate")) {
            result |= manifest_flags::AUTO_ELEVATE;
        }
        if (contains("disableTheming")) {
            result |= manifest_flags::DISABLE_THEMING;
        }
        if (contains("disableWindowFiltering")) {
            result |= manifest_flags::DISABLE_WINDOW_FILTERING;
        }
        if (contains("printerDriverIsolation")) {
            result |= manifest_flags::PRINTER_DRIVER_ISOLATION;
        }
        if (contains("longPathAware")) {
            result |= manifest_flags::LONG_PATH_AWARE;
        }
        if (contains("activeCodePage") && contains("UTF-8")) {
            result |= manifest_flags::UTF8_CODE_PAGE;
        }
        if (contains("SegmentHeap")) {
            result |= manifest_flags::SEGMENT_HEAP;
        }
        if (contains("gdiScaling")) {
            result |= manifest_flags::GDI_SCALING;
        }
        if (contains("highResolutionScrollingAware")) {
            result |= manifest_flags::HIGH_RESOLUTION_SCROLLING;
        }
        if (contains("ultraHighResolutionScrollingAware")) {
            result |= manifest_flags::ULTRA_HIGH_RESOLUTION_SCROLLING;
        }

        return result;
    }

    // =========================================================================
    // Convenience Methods - UAC / Execution Level
    // =========================================================================

    /**
     * Check if manifest requests admin elevation (requireAdministrator).
     */
    [[nodiscard]] bool requires_admin() const {
        return get_uac_execution_level() == uac_execution_level::REQUIRE_ADMINISTRATOR;
    }

    /**
     * Check if manifest requests highest available privileges (highestAvailable).
     */
    [[nodiscard]] bool requires_highest_available() const {
        return get_uac_execution_level() == uac_execution_level::HIGHEST_AVAILABLE;
    }

    /**
     * Check if manifest runs as invoker (asInvoker).
     */
    [[nodiscard]] bool runs_as_invoker() const {
        return get_uac_execution_level() == uac_execution_level::AS_INVOKER;
    }

    /**
     * Check if manifest has auto-elevate enabled.
     */
    [[nodiscard]] bool is_auto_elevate() const {
        return has_flag(get_flags(), manifest_flags::AUTO_ELEVATE);
    }

    // =========================================================================
    // Convenience Methods - DPI Awareness
    // =========================================================================

    /**
     * Check if manifest is DPI-aware (any mode).
     */
    [[nodiscard]] bool is_dpi_aware() const {
        return get_dpi_awareness() != dpi_awareness_mode::UNSPECIFIED;
    }

    /**
     * Check if manifest has dpiAwareness element (Windows 10 1607+).
     */
    [[nodiscard]] bool has_dpi_awareness() const {
        return contains("dpiAwareness");
    }

    /**
     * Check if manifest is Per-Monitor V2 DPI aware.
     */
    [[nodiscard]] bool is_per_monitor_v2_aware() const {
        return get_dpi_awareness() == dpi_awareness_mode::PER_MONITOR_V2;
    }

    /**
     * Check if manifest is Per-Monitor DPI aware.
     */
    [[nodiscard]] bool is_per_monitor_aware() const {
        return get_dpi_awareness() == dpi_awareness_mode::PER_MONITOR;
    }

    /**
     * Check if manifest is System DPI aware.
     */
    [[nodiscard]] bool is_system_aware() const {
        return get_dpi_awareness() == dpi_awareness_mode::SYSTEM_AWARE;
    }

    /**
     * Check if manifest has GDI scaling enabled.
     */
    [[nodiscard]] bool has_gdi_scaling() const {
        return has_flag(get_flags(), manifest_flags::GDI_SCALING);
    }

    // =========================================================================
    // Convenience Methods - High Resolution Input
    // =========================================================================

    /**
     * Check if manifest is high resolution scrolling aware.
     */
    [[nodiscard]] bool is_high_resolution_scrolling_aware() const {
        return has_flag(get_flags(), manifest_flags::HIGH_RESOLUTION_SCROLLING);
    }

    /**
     * Check if manifest is ultra high resolution scrolling aware.
     */
    [[nodiscard]] bool is_ultra_high_resolution_scrolling_aware() const {
        return has_flag(get_flags(), manifest_flags::ULTRA_HIGH_RESOLUTION_SCROLLING);
    }

    // =========================================================================
    // Convenience Methods - Windows Version Compatibility
    // =========================================================================

    /**
     * Check if manifest declares Windows Vista compatibility.
     */
    [[nodiscard]] bool supports_windows_vista() const {
        return has_flag(get_windows_compatibility(), windows_version_flags::VISTA);
    }

    /**
     * Check if manifest declares Windows 7 compatibility.
     */
    [[nodiscard]] bool supports_windows7() const {
        return has_flag(get_windows_compatibility(), windows_version_flags::WIN7);
    }

    /**
     * Check if manifest declares Windows 8 compatibility.
     */
    [[nodiscard]] bool supports_windows8() const {
        return has_flag(get_windows_compatibility(), windows_version_flags::WIN8);
    }

    /**
     * Check if manifest declares Windows 8.1 compatibility.
     */
    [[nodiscard]] bool supports_windows8_1() const {
        return has_flag(get_windows_compatibility(), windows_version_flags::WIN8_1);
    }

    /**
     * Check if manifest declares Windows 10 compatibility.
     */
    [[nodiscard]] bool supports_windows10() const {
        return has_flag(get_windows_compatibility(), windows_version_flags::WIN10);
    }

    /**
     * Check if manifest declares Windows 11 compatibility.
     */
    [[nodiscard]] bool supports_windows11() const {
        return has_flag(get_windows_compatibility(), windows_version_flags::WIN11);
    }

    // =========================================================================
    // Convenience Methods - Other Settings
    // =========================================================================

    /**
     * Check if manifest disables theming.
     */
    [[nodiscard]] bool disables_theming() const {
        return has_flag(get_flags(), manifest_flags::DISABLE_THEMING);
    }

    /**
     * Check if manifest disables window filtering.
     */
    [[nodiscard]] bool disables_window_filtering() const {
        return has_flag(get_flags(), manifest_flags::DISABLE_WINDOW_FILTERING);
    }

    /**
     * Check if manifest enables printer driver isolation.
     */
    [[nodiscard]] bool has_printer_driver_isolation() const {
        return has_flag(get_flags(), manifest_flags::PRINTER_DRIVER_ISOLATION);
    }

    /**
     * Check if manifest has long path awareness (Windows 10 1607+).
     */
    [[nodiscard]] bool is_long_path_aware() const {
        return has_flag(get_flags(), manifest_flags::LONG_PATH_AWARE);
    }

    /**
     * Check if manifest specifies active code page (UTF-8 support).
     */
    [[nodiscard]] bool has_active_code_page() const {
        return contains("activeCodePage");
    }

    /**
     * Check if manifest is UTF-8 enabled (activeCodePage = UTF-8).
     */
    [[nodiscard]] bool is_utf8_enabled() const {
        return has_flag(get_flags(), manifest_flags::UTF8_CODE_PAGE);
    }

    /**
     * Check if manifest specifies heap type.
     */
    [[nodiscard]] bool has_heap_type() const {
        return contains("heapType");
    }

    /**
     * Check if manifest uses segment heap (Windows 10 2004+).
     */
    [[nodiscard]] bool uses_segment_heap() const {
        return has_flag(get_flags(), manifest_flags::SEGMENT_HEAP);
    }

    /**
     * Check if manifest specifies supported architectures.
     */
    [[nodiscard]] bool has_supported_architectures() const {
        return contains("supportedArchitectures");
    }
};

/**
 * Parser for RT_MANIFEST resources.
 *
 * Parses application manifest XML from Windows executables.
 * Manifests are stored as UTF-8 encoded XML text.
 *
 * Example:
 * @code
 * auto manifest_entry = resources->find_resource(resource_type::RT_MANIFEST, 1);
 * if (manifest_entry.has_value()) {
 *     auto manifest = manifest_parser::parse(manifest_entry->data());
 *     if (manifest.has_value()) {
 *         std::cout << "Manifest size: " << manifest->size() << " bytes\n";
 *
 *         // Check UAC settings (enum-based)
 *         auto uac_level = manifest->get_uac_execution_level();
 *         switch (uac_level) {
 *             case uac_execution_level::REQUIRE_ADMINISTRATOR:
 *                 std::cout << "Requires administrator privileges\n";
 *                 break;
 *             case uac_execution_level::HIGHEST_AVAILABLE:
 *                 std::cout << "Requires highest available privileges\n";
 *                 break;
 *             case uac_execution_level::AS_INVOKER:
 *                 std::cout << "Runs as invoker\n";
 *                 break;
 *             default:
 *                 break;
 *         }
 *
 *         // Check DPI awareness (enum-based)
 *         auto dpi_mode = manifest->get_dpi_awareness();
 *         switch (dpi_mode) {
 *             case dpi_awareness_mode::PER_MONITOR_V2:
 *                 std::cout << "Per-Monitor V2 DPI aware\n";
 *                 break;
 *             case dpi_awareness_mode::PER_MONITOR:
 *                 std::cout << "Per-Monitor DPI aware\n";
 *                 break;
 *             case dpi_awareness_mode::SYSTEM_AWARE:
 *                 std::cout << "System DPI aware\n";
 *                 break;
 *             default:
 *                 break;
 *         }
 *
 *         // Check Windows version compatibility (bitmask-based)
 *         auto versions = manifest->get_windows_compatibility();
 *         if (has_flag(versions, windows_version_flags::WIN11)) {
 *             std::cout << "Supports Windows 11\n";
 *         }
 *         if (has_flag(versions, windows_version_flags::WIN10)) {
 *             std::cout << "Supports Windows 10\n";
 *         }
 *
 *         // Check other settings (bitmask-based)
 *         auto flags = manifest->get_flags();
 *         if (has_flag(flags, manifest_flags::LONG_PATH_AWARE)) {
 *             std::cout << "Long path aware (>260 characters)\n";
 *         }
 *         if (has_flag(flags, manifest_flags::UTF8_CODE_PAGE)) {
 *             std::cout << "UTF-8 code page enabled\n";
 *         }
 *
 *         // Get raw XML for detailed parsing
 *         std::cout << manifest->xml << "\n";
 *     }
 * }
 * @endcode
 */
class LIBEXE_EXPORT manifest_parser {
public:
    /**
     * Parse a manifest resource.
     *
     * @param data Raw resource data from RT_MANIFEST resource
     * @return Parsed manifest on success, std::nullopt on parse error
     */
    static std::optional<manifest_data> parse(std::span<const uint8_t> data);
};

} // namespace libexe

#endif // LIBEXE_MANIFEST_PARSER_HPP
