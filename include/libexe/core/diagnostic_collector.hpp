// libexe - Modern executable file analysis library
// Diagnostic collector for aggregating diagnostics during parsing
// Copyright (c) 2024

/**
 * @file diagnostic_collector.hpp
 * @brief Collector for aggregating and querying diagnostics.
 *
 * Provides a container for collecting diagnostic messages generated
 * during executable file parsing, with methods for adding, querying,
 * and iterating over diagnostics.
 */

#ifndef LIBEXE_CORE_DIAGNOSTIC_COLLECTOR_HPP
#define LIBEXE_CORE_DIAGNOSTIC_COLLECTOR_HPP

#include <libexe/core/diagnostic.hpp>
#include <libexe/export.hpp>
#include <vector>
#include <algorithm>

namespace libexe {

/**
 * @brief Collects and manages diagnostics generated during parsing.
 *
 * The diagnostic_collector provides a central repository for all diagnostics
 * generated while parsing an executable file. It supports:
 * - Adding diagnostics at various severity levels
 * - Querying diagnostics by severity, category, or code
 * - Counting diagnostics by type
 * - Iterating over all collected diagnostics
 *
 * @par Example Usage:
 * @code
 * diagnostic_collector collector;
 *
 * // Add diagnostics during parsing
 * collector.warning(diagnostic_code::OPT_ZERO_ENTRY_POINT,
 *                   "Entry point is zero");
 *
 * // Query results
 * if (collector.has_anomalies()) {
 *     std::cout << "Found " << collector.anomaly_count() << " anomalies\n";
 * }
 *
 * // Iterate all diagnostics
 * for (const auto& diag : collector) {
 *     std::cout << diag.to_string() << std::endl;
 * }
 * @endcode
 *
 * @see diagnostic, diagnostic_code, diagnostic_severity
 */
class LIBEXE_EXPORT diagnostic_collector {
public:
    /// @brief Default constructor creates an empty collector.
    diagnostic_collector() = default;

    // =========================================================================
    // Adding diagnostics
    // =========================================================================

    /**
     * @brief Add a pre-constructed diagnostic.
     * @param diag The diagnostic to add.
     */
    void add(diagnostic diag) {
        diagnostics_.push_back(std::move(diag));
    }

    /**
     * @brief Add a diagnostic with individual parameters.
     *
     * @param code    The diagnostic code identifying the issue type.
     * @param severity The severity level.
     * @param message Human-readable description.
     * @param offset  File offset where issue was found (default: 0).
     * @param rva     Relative Virtual Address if applicable (default: 0).
     * @param details Additional context or technical details (default: empty).
     */
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

    /**
     * @brief Add an INFO level diagnostic.
     *
     * @param code    The diagnostic code.
     * @param message Human-readable description.
     * @param offset  File offset (default: 0).
     * @param rva     RVA if applicable (default: 0).
     */
    void info(diagnostic_code code, std::string message,
              uint64_t offset = 0, uint32_t rva = 0) {
        add(code, diagnostic_severity::INFO, std::move(message), offset, rva);
    }

    /**
     * @brief Add a WARNING level diagnostic.
     *
     * @param code    The diagnostic code.
     * @param message Human-readable description.
     * @param offset  File offset (default: 0).
     * @param rva     RVA if applicable (default: 0).
     */
    void warning(diagnostic_code code, std::string message,
                 uint64_t offset = 0, uint32_t rva = 0) {
        add(code, diagnostic_severity::WARNING, std::move(message), offset, rva);
    }

    /**
     * @brief Add an ANOMALY level diagnostic.
     *
     * @param code    The diagnostic code.
     * @param message Human-readable description.
     * @param offset  File offset (default: 0).
     * @param rva     RVA if applicable (default: 0).
     */
    void anomaly(diagnostic_code code, std::string message,
                 uint64_t offset = 0, uint32_t rva = 0) {
        add(code, diagnostic_severity::ANOMALY, std::move(message), offset, rva);
    }

    /**
     * @brief Add an ERROR level diagnostic.
     *
     * @param code    The diagnostic code.
     * @param message Human-readable description.
     * @param offset  File offset (default: 0).
     * @param rva     RVA if applicable (default: 0).
     */
    void error(diagnostic_code code, std::string message,
               uint64_t offset = 0, uint32_t rva = 0) {
        add(code, diagnostic_severity::ERROR, std::move(message), offset, rva);
    }

    // =========================================================================
    // Query methods
    // =========================================================================

    /**
     * @brief Get all collected diagnostics.
     * @return Const reference to the vector of diagnostics.
     */
    [[nodiscard]] const std::vector<diagnostic>& all() const {
        return diagnostics_;
    }

    /**
     * @brief Get diagnostics filtered by severity.
     * @param sev The severity level to filter by.
     * @return Vector of diagnostics matching the specified severity.
     */
    [[nodiscard]] std::vector<diagnostic> by_severity(diagnostic_severity sev) const {
        std::vector<diagnostic> result;
        for (const auto& d : diagnostics_) {
            if (d.severity == sev) {
                result.push_back(d);
            }
        }
        return result;
    }

    /**
     * @brief Get diagnostics filtered by category.
     * @param cat The category to filter by.
     * @return Vector of diagnostics matching the specified category.
     */
    [[nodiscard]] std::vector<diagnostic> by_category(diagnostic_category cat) const {
        std::vector<diagnostic> result;
        for (const auto& d : diagnostics_) {
            if (d.category == cat) {
                result.push_back(d);
            }
        }
        return result;
    }

    /**
     * @brief Get all ERROR level diagnostics.
     * @return Vector of error diagnostics.
     */
    [[nodiscard]] std::vector<diagnostic> errors() const {
        return by_severity(diagnostic_severity::ERROR);
    }

    /**
     * @brief Get all ANOMALY level diagnostics.
     * @return Vector of anomaly diagnostics.
     */
    [[nodiscard]] std::vector<diagnostic> anomalies() const {
        return by_severity(diagnostic_severity::ANOMALY);
    }

    /**
     * @brief Get all WARNING level diagnostics.
     * @return Vector of warning diagnostics.
     */
    [[nodiscard]] std::vector<diagnostic> warnings() const {
        return by_severity(diagnostic_severity::WARNING);
    }

    /**
     * @brief Check if a specific diagnostic code exists in the collection.
     * @param code The diagnostic code to search for.
     * @return true if at least one diagnostic with this code exists.
     */
    [[nodiscard]] bool has_code(diagnostic_code code) const {
        return std::any_of(diagnostics_.begin(), diagnostics_.end(),
            [code](const diagnostic& d) { return d.code == code; });
    }

    // =========================================================================
    // Summary methods
    // =========================================================================

    /**
     * @brief Get the total number of diagnostics.
     * @return Total diagnostic count.
     */
    [[nodiscard]] size_t count() const {
        return diagnostics_.size();
    }

    /**
     * @brief Get the number of ERROR level diagnostics.
     * @return Error count.
     */
    [[nodiscard]] size_t error_count() const {
        return std::count_if(diagnostics_.begin(), diagnostics_.end(),
            [](const diagnostic& d) { return d.is_error(); });
    }

    /**
     * @brief Get the number of ANOMALY level diagnostics.
     * @return Anomaly count.
     */
    [[nodiscard]] size_t anomaly_count() const {
        return std::count_if(diagnostics_.begin(), diagnostics_.end(),
            [](const diagnostic& d) { return d.is_anomaly(); });
    }

    /**
     * @brief Get the number of WARNING level diagnostics.
     * @return Warning count.
     */
    [[nodiscard]] size_t warning_count() const {
        return std::count_if(diagnostics_.begin(), diagnostics_.end(),
            [](const diagnostic& d) { return d.severity == diagnostic_severity::WARNING; });
    }

    /**
     * @brief Check if there are any ERROR level diagnostics.
     * @return true if at least one error exists.
     */
    [[nodiscard]] bool has_errors() const {
        return std::any_of(diagnostics_.begin(), diagnostics_.end(),
            [](const diagnostic& d) { return d.is_error(); });
    }

    /**
     * @brief Check if there are any ANOMALY level diagnostics.
     * @return true if at least one anomaly exists.
     */
    [[nodiscard]] bool has_anomalies() const {
        return std::any_of(diagnostics_.begin(), diagnostics_.end(),
            [](const diagnostic& d) { return d.is_anomaly(); });
    }

    /**
     * @brief Check if there are any WARNING or more severe diagnostics.
     * @return true if at least one warning, anomaly, or error exists.
     */
    [[nodiscard]] bool has_warnings_or_worse() const {
        return std::any_of(diagnostics_.begin(), diagnostics_.end(),
            [](const diagnostic& d) { return d.is_warning_or_worse(); });
    }

    /**
     * @brief Check if the collector is empty.
     * @return true if no diagnostics have been collected.
     */
    [[nodiscard]] bool empty() const {
        return diagnostics_.empty();
    }

    /**
     * @brief Clear all collected diagnostics.
     */
    void clear() {
        diagnostics_.clear();
    }

    // =========================================================================
    // Iteration support
    // =========================================================================

    /// @brief Get const iterator to beginning.
    auto begin() const { return diagnostics_.begin(); }

    /// @brief Get const iterator to end.
    auto end() const { return diagnostics_.end(); }

    /// @brief Get iterator to beginning.
    auto begin() { return diagnostics_.begin(); }

    /// @brief Get iterator to end.
    auto end() { return diagnostics_.end(); }

private:
    std::vector<diagnostic> diagnostics_;  ///< Storage for collected diagnostics
};

} // namespace libexe

#endif // LIBEXE_CORE_DIAGNOSTIC_COLLECTOR_HPP
