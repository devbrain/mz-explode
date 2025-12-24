// Test LX parser with real OS/2 executables (embedded test data)
#include <doctest/doctest.h>
#include <libexe/formats/le_file.hpp>
#include <vector>
#include <span>

using namespace libexe;

// Embedded test data - OS/2 LX executables
namespace data {
    extern size_t strace_lx_len;
    extern unsigned char strace_lx[];

    extern size_t cmd_lx_len;
    extern unsigned char cmd_lx[];

    extern size_t sevenz_lx_len;
    extern unsigned char sevenz_lx[];
}

// =============================================================================
// STRACE.EXE tests
// =============================================================================

TEST_CASE("LX STRACE.EXE: format detection") {
    std::span<const uint8_t> data(data::strace_lx, data::strace_lx_len);
    auto le = le_file::from_memory(data);

    CHECK(le.is_lx());
    CHECK(le.is_bound());
    CHECK(le.get_format() == format_type::LX_OS2_BOUND);
}

TEST_CASE("LX STRACE.EXE: header fields") {
    std::span<const uint8_t> data(data::strace_lx, data::strace_lx_len);
    auto le = le_file::from_memory(data);

    CHECK(le.cpu_type() == 0x02);  // i386
    CHECK(le.os_type() == 0x01);   // OS/2
    CHECK(le.page_size() == 4096);
}

TEST_CASE("LX STRACE.EXE: objects") {
    std::span<const uint8_t> data(data::strace_lx, data::strace_lx_len);
    auto le = le_file::from_memory(data);

    CHECK(le.objects().size() == 2);

    auto code_obj = le.get_code_object();
    REQUIRE(code_obj.has_value());
    CHECK(code_obj->index == 1);

    auto data_obj = le.get_data_object();
    REQUIRE(data_obj.has_value());
    CHECK(data_obj->index == 2);
}

TEST_CASE("LX STRACE.EXE: module name") {
    std::span<const uint8_t> data(data::strace_lx, data::strace_lx_len);
    auto le = le_file::from_memory(data);

    CHECK(le.module_name() == "strace");
}

TEST_CASE("LX STRACE.EXE: imports") {
    std::span<const uint8_t> data(data::strace_lx, data::strace_lx_len);
    auto le = le_file::from_memory(data);

    CHECK(le.import_module_count() == 1);

    const auto& imports = le.import_modules();
    REQUIRE(imports.size() == 1);
    CHECK(imports[0] == "DOSCALLS");
}

TEST_CASE("LX STRACE.EXE: fixups") {
    std::span<const uint8_t> data(data::strace_lx, data::strace_lx_len);
    auto le = le_file::from_memory(data);

    CHECK(le.has_fixups());
    CHECK(le.fixup_count() == 1002);

    auto page1_fixups = le.get_page_fixups(1);
    CHECK(page1_fixups.size() > 0);
}

// =============================================================================
// CMD.EXE tests
// =============================================================================

TEST_CASE("LX CMD.EXE: format detection") {
    std::span<const uint8_t> data(data::cmd_lx, data::cmd_lx_len);
    auto le = le_file::from_memory(data);

    CHECK(le.is_lx());
    CHECK(le.is_bound());
    CHECK(le.get_format() == format_type::LX_OS2_BOUND);
}

TEST_CASE("LX CMD.EXE: module name") {
    std::span<const uint8_t> data(data::cmd_lx, data::cmd_lx_len);
    auto le = le_file::from_memory(data);

    CHECK(le.module_name() == "cmd");
}

TEST_CASE("LX CMD.EXE: objects and pages") {
    std::span<const uint8_t> data(data::cmd_lx, data::cmd_lx_len);
    auto le = le_file::from_memory(data);

    CHECK(le.objects().size() == 5);
    CHECK(le.page_count() == 31);

    auto code_obj = le.get_code_object();
    REQUIRE(code_obj.has_value());
}

TEST_CASE("LX CMD.EXE: imports") {
    std::span<const uint8_t> data(data::cmd_lx, data::cmd_lx_len);
    auto le = le_file::from_memory(data);

    CHECK(le.import_module_count() == 1);
    const auto& imports = le.import_modules();
    REQUIRE(imports.size() == 1);
    CHECK(imports[0] == "DOSCALLS");
}

TEST_CASE("LX CMD.EXE: fixups") {
    std::span<const uint8_t> data(data::cmd_lx, data::cmd_lx_len);
    auto le = le_file::from_memory(data);

    CHECK(le.has_fixups());
    CHECK(le.fixup_count() > 0);
}

// =============================================================================
// 7z.exe tests
// =============================================================================

TEST_CASE("LX 7z.exe: format detection") {
    std::span<const uint8_t> data(data::sevenz_lx, data::sevenz_lx_len);
    auto le = le_file::from_memory(data);

    CHECK(le.is_lx());
}

TEST_CASE("LX 7z.exe: objects") {
    std::span<const uint8_t> data(data::sevenz_lx, data::sevenz_lx_len);
    auto le = le_file::from_memory(data);

    CHECK(le.objects().size() == 3);
}

TEST_CASE("LX 7z.exe: imports") {
    std::span<const uint8_t> data(data::sevenz_lx, data::sevenz_lx_len);
    auto le = le_file::from_memory(data);

    CHECK(le.import_module_count() == 2);
}

TEST_CASE("LX 7z.exe: fixups") {
    std::span<const uint8_t> data(data::sevenz_lx, data::sevenz_lx_len);
    auto le = le_file::from_memory(data);

    CHECK(le.has_fixups());
    CHECK(le.fixup_count() == 3443);
}
