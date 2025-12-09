// libexe - Modern executable file analysis library
// Export directory parser tests with ground truth from objdump
//
// Ground truth for scheduler.exe (objdump -p):
//   - No export directory (Entry 0 00000000 00000000)
//   - This is expected for a GUI executable

#include <libexe/formats/pe_file.hpp>
#include <libexe/pe/directories/export.hpp>
#include <libexe/pe/types.hpp>
#include <doctest/doctest.h>

using namespace libexe;

// External test data (embedded scheduler.exe)
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

// =============================================================================
// Export Directory Tests - Ground Truth from objdump
// =============================================================================

TEST_CASE("Export parser - scheduler.exe has no exports") {
    auto data = load_scheduler();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);

    // Ground truth from objdump: Entry 0 00000000 00000000 Export Directory
    CHECK_FALSE(pe.has_data_directory(directory_entry::EXPORT));
    CHECK(pe.data_directory_rva(directory_entry::EXPORT) == 0);
    CHECK(pe.data_directory_size(directory_entry::EXPORT) == 0);

    // exports() should return empty directory, not nullptr
    auto exports = pe.exports();
    REQUIRE(exports != nullptr);
    CHECK(exports->export_count() == 0);
    CHECK(exports->module_name.empty());
}

// =============================================================================
// Export Entry Display Name Tests
// =============================================================================

TEST_CASE("Export entry - display_name()") {
    SUBCASE("Named export") {
        export_entry entry;
        entry.name = "CreateFileW";
        entry.ordinal = 1;
        entry.rva = 0x1000;
        entry.has_name = true;
        entry.is_forwarder = false;

        CHECK(entry.display_name() == "CreateFileW");
    }

    SUBCASE("Ordinal-only export") {
        export_entry entry;
        entry.name = "";
        entry.ordinal = 42;
        entry.rva = 0x2000;
        entry.has_name = false;
        entry.is_forwarder = false;

        CHECK(entry.display_name() == "Ordinal 42");
    }

    SUBCASE("Forwarded export") {
        export_entry entry;
        entry.name = "HeapAlloc";
        entry.ordinal = 5;
        entry.rva = 0;
        entry.has_name = true;
        entry.is_forwarder = true;
        entry.forwarder_name = "NTDLL.RtlAllocateHeap";

        CHECK(entry.is_forwarder);
        CHECK(entry.forwarder_name == "NTDLL.RtlAllocateHeap");
    }
}
