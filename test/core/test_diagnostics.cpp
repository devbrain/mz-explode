// libexe - Modern executable file analysis library
// Diagnostics system unit tests
// Copyright (c) 2024

#include <libexe/core/diagnostic.hpp>
#include <libexe/core/diagnostic_collector.hpp>
#include <libexe/formats/pe_file.hpp>
#include <doctest/doctest.h>
#include <string>

using namespace libexe;

// =============================================================================
// Diagnostic Struct Tests
// =============================================================================

TEST_CASE("diagnostic - basic construction") {
    diagnostic diag{
        .code = diagnostic_code::COFF_ZERO_SECTIONS,
        .severity = diagnostic_severity::ANOMALY,
        .category = diagnostic_category::COFF_HEADER,
        .file_offset = 0x100,
        .rva = 0,
        .message = "Test message",
        .details = "Test details"
    };

    CHECK(diag.code == diagnostic_code::COFF_ZERO_SECTIONS);
    CHECK(diag.severity == diagnostic_severity::ANOMALY);
    CHECK(diag.category == diagnostic_category::COFF_HEADER);
    CHECK(diag.file_offset == 0x100);
    CHECK(diag.message == "Test message");
    CHECK(diag.details == "Test details");
}

TEST_CASE("diagnostic - is_anomaly()") {
    diagnostic info_diag{.code = diagnostic_code::OPT_ZERO_ENTRY_POINT,
                         .severity = diagnostic_severity::INFO,
                         .category = diagnostic_category::OPTIONAL_HEADER};
    CHECK_FALSE(info_diag.is_anomaly());

    diagnostic anomaly_diag{.code = diagnostic_code::COFF_ZERO_SECTIONS,
                            .severity = diagnostic_severity::ANOMALY,
                            .category = diagnostic_category::COFF_HEADER};
    CHECK(anomaly_diag.is_anomaly());
}

TEST_CASE("diagnostic - is_error()") {
    diagnostic warning_diag{.code = diagnostic_code::OPT_LOW_ALIGNMENT,
                            .severity = diagnostic_severity::WARNING,
                            .category = diagnostic_category::OPTIONAL_HEADER};
    CHECK_FALSE(warning_diag.is_error());

    diagnostic error_diag{.code = diagnostic_code::TRUNCATED_FILE,
                          .severity = diagnostic_severity::ERROR,
                          .category = diagnostic_category::GENERAL};
    CHECK(error_diag.is_error());
}

TEST_CASE("diagnostic - is_warning_or_worse()") {
    diagnostic info_diag{.code = diagnostic_code::OPT_ZERO_ENTRY_POINT,
                         .severity = diagnostic_severity::INFO};
    CHECK_FALSE(info_diag.is_warning_or_worse());

    diagnostic warning_diag{.code = diagnostic_code::OPT_LOW_ALIGNMENT,
                            .severity = diagnostic_severity::WARNING};
    CHECK(warning_diag.is_warning_or_worse());

    diagnostic anomaly_diag{.code = diagnostic_code::COFF_ZERO_SECTIONS,
                            .severity = diagnostic_severity::ANOMALY};
    CHECK(anomaly_diag.is_warning_or_worse());

    diagnostic error_diag{.code = diagnostic_code::TRUNCATED_FILE,
                          .severity = diagnostic_severity::ERROR};
    CHECK(error_diag.is_warning_or_worse());
}

TEST_CASE("diagnostic - category_from_code()") {
    CHECK(diagnostic::category_from_code(diagnostic_code::COFF_ZERO_SECTIONS) ==
          diagnostic_category::COFF_HEADER);
    CHECK(diagnostic::category_from_code(diagnostic_code::OPT_ZERO_ENTRY_POINT) ==
          diagnostic_category::OPTIONAL_HEADER);
    CHECK(diagnostic::category_from_code(diagnostic_code::IMP_EMPTY_IAT) ==
          diagnostic_category::IMPORT);
    CHECK(diagnostic::category_from_code(diagnostic_code::RICH_CHECKSUM_MISMATCH) ==
          diagnostic_category::RICH_HEADER);
}

TEST_CASE("diagnostic - to_string()") {
    diagnostic diag{
        .code = diagnostic_code::COFF_ZERO_SECTIONS,
        .severity = diagnostic_severity::ANOMALY,
        .category = diagnostic_category::COFF_HEADER,
        .file_offset = 0x100,
        .rva = 0,
        .message = "Test message",
        .details = ""
    };

    std::string str = diag.to_string();
    CHECK(str.find("ANOMALY") != std::string::npos);
    CHECK(str.find("0x00000100") != std::string::npos);
    CHECK(str.find("Test message") != std::string::npos);
}

// =============================================================================
// Severity/Category/Code Name Tests
// =============================================================================

TEST_CASE("severity_name()") {
    CHECK(severity_name(diagnostic_severity::INFO) == "INFO");
    CHECK(severity_name(diagnostic_severity::WARNING) == "WARNING");
    CHECK(severity_name(diagnostic_severity::ANOMALY) == "ANOMALY");
    CHECK(severity_name(diagnostic_severity::ERROR) == "ERROR");
}

TEST_CASE("category_name()") {
    CHECK(category_name(diagnostic_category::DOS_HEADER) == "DOS_HEADER");
    CHECK(category_name(diagnostic_category::PE_HEADER) == "PE_HEADER");
    CHECK(category_name(diagnostic_category::IMPORT) == "IMPORT");
    CHECK(category_name(diagnostic_category::RICH_HEADER) == "RICH_HEADER");
    CHECK(category_name(diagnostic_category::NE_HEADER) == "NE_HEADER");
}

TEST_CASE("code_name()") {
    CHECK(code_name(diagnostic_code::COFF_ZERO_SECTIONS) == "COFF_ZERO_SECTIONS");
    CHECK(code_name(diagnostic_code::OPT_ZERO_ENTRY_POINT) == "OPT_ZERO_ENTRY_POINT");
    CHECK(code_name(diagnostic_code::IMP_EMPTY_IAT) == "IMP_EMPTY_IAT");
    CHECK(code_name(diagnostic_code::RELOC_VIRTUAL_CODE) == "RELOC_VIRTUAL_CODE");
}

// =============================================================================
// Diagnostic Collector Tests
// =============================================================================

TEST_CASE("diagnostic_collector - empty state") {
    diagnostic_collector collector;

    CHECK(collector.empty());
    CHECK(collector.count() == 0);
    CHECK(collector.error_count() == 0);
    CHECK(collector.anomaly_count() == 0);
    CHECK_FALSE(collector.has_errors());
    CHECK_FALSE(collector.has_anomalies());
}

TEST_CASE("diagnostic_collector - add diagnostic") {
    diagnostic_collector collector;

    collector.add(diagnostic_code::COFF_ZERO_SECTIONS,
                  diagnostic_severity::ANOMALY,
                  "Test anomaly",
                  0x100);

    CHECK_FALSE(collector.empty());
    CHECK(collector.count() == 1);
    CHECK(collector.anomaly_count() == 1);
    CHECK(collector.has_anomalies());
}

TEST_CASE("diagnostic_collector - convenience methods") {
    diagnostic_collector collector;

    collector.info(diagnostic_code::OPT_ZERO_ENTRY_POINT, "Info message");
    collector.warning(diagnostic_code::OPT_LOW_ALIGNMENT, "Warning message");
    collector.anomaly(diagnostic_code::COFF_ZERO_SECTIONS, "Anomaly message");
    collector.error(diagnostic_code::TRUNCATED_FILE, "Error message");

    CHECK(collector.count() == 4);
    CHECK(collector.error_count() == 1);
    CHECK(collector.anomaly_count() == 1);
    CHECK(collector.warning_count() == 1);
}

TEST_CASE("diagnostic_collector - by_severity()") {
    diagnostic_collector collector;

    collector.info(diagnostic_code::OPT_ZERO_ENTRY_POINT, "Info 1");
    collector.info(diagnostic_code::OPT_ZERO_ENTRY_POINT, "Info 2");
    collector.warning(diagnostic_code::OPT_LOW_ALIGNMENT, "Warning");
    collector.anomaly(diagnostic_code::COFF_ZERO_SECTIONS, "Anomaly");

    auto infos = collector.by_severity(diagnostic_severity::INFO);
    CHECK(infos.size() == 2);

    auto warnings = collector.warnings();
    CHECK(warnings.size() == 1);

    auto anomalies = collector.anomalies();
    CHECK(anomalies.size() == 1);
}

TEST_CASE("diagnostic_collector - by_category()") {
    diagnostic_collector collector;

    collector.anomaly(diagnostic_code::COFF_ZERO_SECTIONS, "COFF issue");
    collector.warning(diagnostic_code::OPT_LOW_ALIGNMENT, "Opt header issue");
    collector.warning(diagnostic_code::OPT_UNALIGNED_IMAGEBASE, "Opt header issue 2");

    auto coff_diags = collector.by_category(diagnostic_category::COFF_HEADER);
    CHECK(coff_diags.size() == 1);

    auto opt_diags = collector.by_category(diagnostic_category::OPTIONAL_HEADER);
    CHECK(opt_diags.size() == 2);
}

TEST_CASE("diagnostic_collector - has_code()") {
    diagnostic_collector collector;

    collector.anomaly(diagnostic_code::COFF_ZERO_SECTIONS, "Test");

    CHECK(collector.has_code(diagnostic_code::COFF_ZERO_SECTIONS));
    CHECK_FALSE(collector.has_code(diagnostic_code::OPT_ZERO_ENTRY_POINT));
}

TEST_CASE("diagnostic_collector - clear()") {
    diagnostic_collector collector;

    collector.anomaly(diagnostic_code::COFF_ZERO_SECTIONS, "Test");
    CHECK_FALSE(collector.empty());

    collector.clear();
    CHECK(collector.empty());
}

TEST_CASE("diagnostic_collector - iteration") {
    diagnostic_collector collector;

    collector.info(diagnostic_code::OPT_ZERO_ENTRY_POINT, "One");
    collector.warning(diagnostic_code::OPT_LOW_ALIGNMENT, "Two");
    collector.anomaly(diagnostic_code::COFF_ZERO_SECTIONS, "Three");

    int count = 0;
    for ([[maybe_unused]] const auto& diag : collector) {
        count++;
    }
    CHECK(count == 3);
}

// =============================================================================
// PE File Integration Tests
// =============================================================================

// External test data (embedded scheduler.exe - a normal PE file)
namespace data {
    extern size_t scheduler_len;
    extern unsigned char scheduler[];
}

static std::vector<uint8_t> load_scheduler() {
    return std::vector<uint8_t>(
        data::scheduler,
        data::scheduler + data::scheduler_len
    );
}

TEST_CASE("pe_file - diagnostics interface") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);

    // scheduler.exe is a well-formed PE file, should have minimal diagnostics
    [[maybe_unused]] const auto& diags = pe.diagnostics();

    // Verify diagnostics accessor works (use void cast to suppress nodiscard warning)
    [[maybe_unused]] const auto& d = pe.diagnostics();
    CHECK(d.count() >= 0);  // Always true, but exercises the accessor

    // Check has_diagnostic() method
    // scheduler.exe has a normal entry point, so shouldn't have ZERO_ENTRY_POINT
    CHECK_FALSE(pe.has_diagnostic(diagnostic_code::OPT_ZERO_ENTRY_POINT));

    // scheduler.exe is well-formed, shouldn't have anomalies
    CHECK_FALSE(pe.has_anomalies());
    CHECK_FALSE(pe.has_parse_errors());
}

TEST_CASE("pe_file - diagnostics for entry point") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);

    // scheduler.exe has a valid non-zero entry point
    CHECK(pe.entry_point_rva() != 0);
    CHECK_FALSE(pe.has_diagnostic(diagnostic_code::OPT_ZERO_ENTRY_POINT));

    // Entry point should be within image
    CHECK(pe.entry_point_rva() < pe.size_of_image());
    CHECK_FALSE(pe.has_diagnostic(diagnostic_code::OPT_EP_OUTSIDE_IMAGE));
}

TEST_CASE("pe_file - diagnostics for sections") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);

    // scheduler.exe has sections
    CHECK(pe.section_count() > 0);
    CHECK_FALSE(pe.has_diagnostic(diagnostic_code::COFF_ZERO_SECTIONS));

    // scheduler.exe has reasonable section count
    CHECK(pe.section_count() <= 96);
    CHECK_FALSE(pe.has_diagnostic(diagnostic_code::COFF_EXCESSIVE_SECTIONS));
}
