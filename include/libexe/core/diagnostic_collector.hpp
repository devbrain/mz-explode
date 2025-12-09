// libexe - Modern executable file analysis library
// Diagnostic collector for aggregating diagnostics during parsing
// Copyright (c) 2024

#ifndef LIBEXE_CORE_DIAGNOSTIC_COLLECTOR_HPP
#define LIBEXE_CORE_DIAGNOSTIC_COLLECTOR_HPP

#include <libexe/core/diagnostic.hpp>
#include <libexe/export.hpp>
#include <vector>
#include <algorithm>

namespace libexe {

/// Collects and manages diagnostics generated during parsing
class LIBEXE_EXPORT diagnostic_collector {
public:
    diagnostic_collector() = default;

    /// Add a pre-constructed diagnostic
    void add(diagnostic diag) {
        diagnostics_.push_back(std::move(diag));
    }

    /// Add a diagnostic with individual parameters
    void add(diagnostic_code code,
             diagnostic_severity severity,
             std::string message,
             uint64_t offset = 0,
             uint32_t rva = 0,
             std::string details = "") {
        diagnostics_.push_back(diagnostic{
            .code = code,
            .severity = severity,
            .category = diagnostic::category_from_code(code),
            .file_offset = offset,
            .rva = rva,
            .message = std::move(message),
            .details = std::move(details)
        });
    }

    /// Add INFO level diagnostic
    void info(diagnostic_code code, std::string message,
              uint64_t offset = 0, uint32_t rva = 0) {
        add(code, diagnostic_severity::INFO, std::move(message), offset, rva);
    }

    /// Add WARNING level diagnostic
    void warning(diagnostic_code code, std::string message,
                 uint64_t offset = 0, uint32_t rva = 0) {
        add(code, diagnostic_severity::WARNING, std::move(message), offset, rva);
    }

    /// Add ANOMALY level diagnostic
    void anomaly(diagnostic_code code, std::string message,
                 uint64_t offset = 0, uint32_t rva = 0) {
        add(code, diagnostic_severity::ANOMALY, std::move(message), offset, rva);
    }

    /// Add ERROR level diagnostic
    void error(diagnostic_code code, std::string message,
               uint64_t offset = 0, uint32_t rva = 0) {
        add(code, diagnostic_severity::ERROR, std::move(message), offset, rva);
    }

    // =========================================================================
    // Query methods
    // =========================================================================

    /// Get all diagnostics
    [[nodiscard]] const std::vector<diagnostic>& all() const {
        return diagnostics_;
    }

    /// Get diagnostics by severity
    [[nodiscard]] std::vector<diagnostic> by_severity(diagnostic_severity sev) const {
        std::vector<diagnostic> result;
        for (const auto& d : diagnostics_) {
            if (d.severity == sev) {
                result.push_back(d);
            }
        }
        return result;
    }

    /// Get diagnostics by category
    [[nodiscard]] std::vector<diagnostic> by_category(diagnostic_category cat) const {
        std::vector<diagnostic> result;
        for (const auto& d : diagnostics_) {
            if (d.category == cat) {
                result.push_back(d);
            }
        }
        return result;
    }

    /// Get all errors
    [[nodiscard]] std::vector<diagnostic> errors() const {
        return by_severity(diagnostic_severity::ERROR);
    }

    /// Get all anomalies
    [[nodiscard]] std::vector<diagnostic> anomalies() const {
        return by_severity(diagnostic_severity::ANOMALY);
    }

    /// Get all warnings
    [[nodiscard]] std::vector<diagnostic> warnings() const {
        return by_severity(diagnostic_severity::WARNING);
    }

    /// Check if a specific diagnostic code exists
    [[nodiscard]] bool has_code(diagnostic_code code) const {
        return std::any_of(diagnostics_.begin(), diagnostics_.end(),
            [code](const diagnostic& d) { return d.code == code; });
    }

    // =========================================================================
    // Summary methods
    // =========================================================================

    /// Get total diagnostic count
    [[nodiscard]] size_t count() const {
        return diagnostics_.size();
    }

    /// Get error count
    [[nodiscard]] size_t error_count() const {
        return std::count_if(diagnostics_.begin(), diagnostics_.end(),
            [](const diagnostic& d) { return d.is_error(); });
    }

    /// Get anomaly count
    [[nodiscard]] size_t anomaly_count() const {
        return std::count_if(diagnostics_.begin(), diagnostics_.end(),
            [](const diagnostic& d) { return d.is_anomaly(); });
    }

    /// Get warning count
    [[nodiscard]] size_t warning_count() const {
        return std::count_if(diagnostics_.begin(), diagnostics_.end(),
            [](const diagnostic& d) { return d.severity == diagnostic_severity::WARNING; });
    }

    /// Check if there are any errors
    [[nodiscard]] bool has_errors() const {
        return std::any_of(diagnostics_.begin(), diagnostics_.end(),
            [](const diagnostic& d) { return d.is_error(); });
    }

    /// Check if there are any anomalies
    [[nodiscard]] bool has_anomalies() const {
        return std::any_of(diagnostics_.begin(), diagnostics_.end(),
            [](const diagnostic& d) { return d.is_anomaly(); });
    }

    /// Check if there are any warnings or worse
    [[nodiscard]] bool has_warnings_or_worse() const {
        return std::any_of(diagnostics_.begin(), diagnostics_.end(),
            [](const diagnostic& d) { return d.is_warning_or_worse(); });
    }

    /// Check if empty
    [[nodiscard]] bool empty() const {
        return diagnostics_.empty();
    }

    /// Clear all diagnostics
    void clear() {
        diagnostics_.clear();
    }

    // =========================================================================
    // Iteration support
    // =========================================================================

    auto begin() const { return diagnostics_.begin(); }
    auto end() const { return diagnostics_.end(); }
    auto begin() { return diagnostics_.begin(); }
    auto end() { return diagnostics_.end(); }

private:
    std::vector<diagnostic> diagnostics_;
};

} // namespace libexe

#endif // LIBEXE_CORE_DIAGNOSTIC_COLLECTOR_HPP
