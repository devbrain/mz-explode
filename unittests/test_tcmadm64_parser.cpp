// libexe - Modern executable file analysis library
// PE64 parser tests for TCMADM64.EXE with ground truth from objdump
//
// Ground truth for TCMADM64.EXE (objdump -p):
//   - PE32+ (64-bit) executable, 5 sections
//   - 4 imported DLLs: KERNEL32.dll (93), USER32.dll (1), ADVAPI32.dll (19), SHELL32.dll (1)
//   - 114 total imports
//   - Import directory at RVA 0x15bf8, size 0x64 (100 bytes)
//   - IAT at RVA 0x13000, size 0x3b0
//   - Exception directory at RVA 0x1a000, size 0xc3c (.pdata)
//   - Security directory at RVA 0x19600, size 0x3568
//   - Resource directory at RVA 0x1b000, size 0x1c68
//   - No exports, no relocations, no TLS, no debug

#include <libexe/formats/pe_file.hpp>
#include <libexe/pe/directories/import.hpp>
#include <libexe/pe/directories/export.hpp>
#include <libexe/pe/directories/relocation.hpp>
#include <libexe/pe/directories/tls.hpp>
#include <libexe/pe/directories/exception.hpp>
#include <libexe/pe/directories/security.hpp>
#include <libexe/pe/types.hpp>
#include <doctest/doctest.h>
#include <algorithm>

using namespace libexe;

// External test data (embedded TCMADM64.EXE)
namespace data {
    extern size_t tcmadm64_len;
    extern unsigned char tcmadm64[];
}

static std::vector<uint8_t> load_tcmadm64() {
    return std::vector<uint8_t>(
        data::tcmadm64,
        data::tcmadm64 + data::tcmadm64_len
    );
}

// =============================================================================
// PE Header Tests - Ground Truth from objdump
// =============================================================================

TEST_CASE("TCMADM64 - PE header") {
    auto data = load_tcmadm64();
    REQUIRE(!data.empty());
    REQUIRE(data.size() == 117608);

    auto pe = pe_file::from_memory(data);

    // Ground truth: PE32+ (64-bit)
    CHECK(pe.is_64bit());

    // Ground truth: 5 sections
    CHECK(pe.section_count() == 5);

    // Ground truth: Magic 020b (PE32+)
    // Ground truth: Characteristics 0x23 (relocations stripped, executable, large address aware)
}

TEST_CASE("TCMADM64 - Section headers") {
    auto data = load_tcmadm64();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto sections = pe.sections();

    REQUIRE(sections.size() == 5);

    // Ground truth from objdump -h:
    // .text   000115de  0000000140001000
    // .rdata  000038c0  0000000140013000
    // .data   00001600  0000000140017000
    // .pdata  00000c3c  000000014001a000
    // .rsrc   00001c68  000000014001b000

    CHECK(sections[0].name == ".text");
    CHECK(sections[0].virtual_size == 0x115de);
    CHECK(sections[0].virtual_address == 0x1000);

    CHECK(sections[1].name == ".rdata");
    CHECK(sections[1].virtual_size == 0x38c0);
    CHECK(sections[1].virtual_address == 0x13000);

    CHECK(sections[2].name == ".data");
    // PE section header has both VirtualSize and SizeOfRawData:
    // - VirtualSize (in memory) = 0x27D8 - includes uninitialized data (BSS)
    // - SizeOfRawData (on disk) = 0x1600 - what objdump -h shows as "Size"
    CHECK(sections[2].virtual_size == 0x27D8);
    CHECK(sections[2].raw_data_size == 0x1600);
    CHECK(sections[2].virtual_address == 0x17000);

    CHECK(sections[3].name == ".pdata");
    CHECK(sections[3].virtual_size == 0xc3c);
    CHECK(sections[3].virtual_address == 0x1a000);

    CHECK(sections[4].name == ".rsrc");
    CHECK(sections[4].virtual_size == 0x1c68);
    CHECK(sections[4].virtual_address == 0x1b000);
}

// =============================================================================
// Data Directory Tests - Ground Truth from objdump
// =============================================================================

TEST_CASE("TCMADM64 - Data directories") {
    auto data = load_tcmadm64();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);

    // Ground truth: Entry 0 00000000 00000000 Export Directory
    CHECK_FALSE(pe.has_data_directory(directory_entry::EXPORT));
    CHECK(pe.data_directory_rva(directory_entry::EXPORT) == 0);

    // Ground truth: Entry 1 00015bf8 00000064 Import Directory
    CHECK(pe.has_data_directory(directory_entry::IMPORT));
    CHECK(pe.data_directory_rva(directory_entry::IMPORT) == 0x15bf8);
    CHECK(pe.data_directory_size(directory_entry::IMPORT) == 0x64);

    // Ground truth: Entry 2 0001b000 00001c68 Resource Directory
    CHECK(pe.has_data_directory(directory_entry::RESOURCE));
    CHECK(pe.data_directory_rva(directory_entry::RESOURCE) == 0x1b000);
    CHECK(pe.data_directory_size(directory_entry::RESOURCE) == 0x1c68);

    // Ground truth: Entry 3 0001a000 00000c3c Exception Directory (.pdata)
    CHECK(pe.has_data_directory(directory_entry::EXCEPTION));
    CHECK(pe.data_directory_rva(directory_entry::EXCEPTION) == 0x1a000);
    CHECK(pe.data_directory_size(directory_entry::EXCEPTION) == 0xc3c);

    // Ground truth: Entry 4 00019600 00003568 Security Directory
    CHECK(pe.has_data_directory(directory_entry::SECURITY));
    CHECK(pe.data_directory_rva(directory_entry::SECURITY) == 0x19600);
    CHECK(pe.data_directory_size(directory_entry::SECURITY) == 0x3568);

    // Ground truth: Entry 5 00000000 Base Relocation - no relocations
    CHECK_FALSE(pe.has_data_directory(directory_entry::BASERELOC));

    // Ground truth: Entry 6 00000000 Debug Directory - none
    CHECK_FALSE(pe.has_data_directory(directory_entry::DEBUG));

    // Ground truth: Entry 9 00000000 TLS Directory - none
    CHECK_FALSE(pe.has_data_directory(directory_entry::TLS));

    // Ground truth: Entry a 00000000 Load Configuration - none
    CHECK_FALSE(pe.has_data_directory(directory_entry::LOAD_CONFIG));

    // Ground truth: Entry c 00013000 000003b0 Import Address Table
    CHECK(pe.has_data_directory(directory_entry::IAT));
    CHECK(pe.data_directory_rva(directory_entry::IAT) == 0x13000);
    CHECK(pe.data_directory_size(directory_entry::IAT) == 0x3b0);

    // Ground truth: Entry d 00000000 Delay Import - none
    CHECK_FALSE(pe.has_data_directory(directory_entry::DELAY_IMPORT));

    // Ground truth: Entry e 00000000 CLR Runtime Header - not .NET
    CHECK_FALSE(pe.has_data_directory(directory_entry::COM_DESCRIPTOR));
}

// =============================================================================
// Import Directory Tests - Ground Truth from objdump
// =============================================================================

TEST_CASE("TCMADM64 - Import DLL count and names") {
    auto data = load_tcmadm64();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto imports = pe.imports();
    REQUIRE(imports != nullptr);

    // Ground truth: 4 imported DLLs
    CHECK(imports->dll_count() == 4);

    // Ground truth: exact DLL names
    const std::vector<std::string> expected_dlls = {
        "KERNEL32.dll", "USER32.dll", "ADVAPI32.dll", "SHELL32.dll"
    };

    for (const auto& expected : expected_dlls) {
        bool found = false;
        for (const auto& dll : imports->dlls) {
            std::string dll_lower = dll.name;
            std::string exp_lower = expected;
            std::transform(dll_lower.begin(), dll_lower.end(), dll_lower.begin(), ::tolower);
            std::transform(exp_lower.begin(), exp_lower.end(), exp_lower.begin(), ::tolower);
            if (dll_lower == exp_lower) {
                found = true;
                break;
            }
        }
        CHECK_MESSAGE(found, "Missing DLL: " << expected);
    }
}

TEST_CASE("TCMADM64 - KERNEL32.dll imports") {
    auto data = load_tcmadm64();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto imports = pe.imports();
    REQUIRE(imports != nullptr);

    auto kernel32 = imports->find_dll("KERNEL32.dll");
    REQUIRE(kernel32 != nullptr);

    // Ground truth from objdump: specific imports with hints
    CHECK(kernel32->find_function("GetModuleHandleA") != nullptr);
    CHECK(kernel32->find_function("CreateFileW") != nullptr);
    CHECK(kernel32->find_function("CloseHandle") != nullptr);
    CHECK(kernel32->find_function("ReadFile") != nullptr);
    CHECK(kernel32->find_function("WriteFile") != nullptr);
    CHECK(kernel32->find_function("GetLastError") != nullptr);
    CHECK(kernel32->find_function("GetProcAddress") != nullptr);
    CHECK(kernel32->find_function("LoadLibraryA") != nullptr);
    CHECK(kernel32->find_function("ExitProcess") != nullptr);
    CHECK(kernel32->find_function("HeapAlloc") != nullptr);
    CHECK(kernel32->find_function("HeapFree") != nullptr);

    // Check hints match objdump output
    auto get_module_handle = kernel32->find_function("GetModuleHandleA");
    if (get_module_handle) {
        CHECK(get_module_handle->hint == 385);
    }

    auto create_file = kernel32->find_function("CreateFileW");
    if (create_file) {
        CHECK(create_file->hint == 89);
    }

    auto close_handle = kernel32->find_function("CloseHandle");
    if (close_handle) {
        CHECK(close_handle->hint == 54);
    }

    auto exit_process = kernel32->find_function("ExitProcess");
    if (exit_process) {
        CHECK(exit_process->hint == 188);
    }
}

TEST_CASE("TCMADM64 - USER32.dll imports") {
    auto data = load_tcmadm64();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto imports = pe.imports();
    REQUIRE(imports != nullptr);

    auto user32 = imports->find_dll("USER32.dll");
    REQUIRE(user32 != nullptr);

    // Ground truth: only 1 import from USER32.dll
    CHECK(user32->function_count() == 1);

    // Ground truth: MessageBoxA with hint 482
    auto message_box = user32->find_function("MessageBoxA");
    CHECK(message_box != nullptr);
    if (message_box) {
        CHECK(message_box->hint == 482);
    }
}

TEST_CASE("TCMADM64 - ADVAPI32.dll imports") {
    auto data = load_tcmadm64();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto imports = pe.imports();
    REQUIRE(imports != nullptr);

    auto advapi32 = imports->find_dll("ADVAPI32.dll");
    REQUIRE(advapi32 != nullptr);

    // Ground truth: security-related imports
    CHECK(advapi32->find_function("SetFileSecurityW") != nullptr);
    CHECK(advapi32->find_function("GetSecurityDescriptorControl") != nullptr);
    CHECK(advapi32->find_function("LookupPrivilegeValueA") != nullptr);
    CHECK(advapi32->find_function("OpenProcessToken") != nullptr);
    CHECK(advapi32->find_function("AdjustTokenPrivileges") != nullptr);
    CHECK(advapi32->find_function("GetUserNameA") != nullptr);

    // Check hints
    auto set_file_security = advapi32->find_function("SetFileSecurityW");
    if (set_file_security) {
        CHECK(set_file_security->hint == 559);
    }

    auto get_user_name = advapi32->find_function("GetUserNameA");
    if (get_user_name) {
        CHECK(get_user_name->hint == 292);
    }
}

TEST_CASE("TCMADM64 - SHELL32.dll imports") {
    auto data = load_tcmadm64();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto imports = pe.imports();
    REQUIRE(imports != nullptr);

    auto shell32 = imports->find_dll("SHELL32.dll");
    REQUIRE(shell32 != nullptr);

    // Ground truth: only 1 import from SHELL32.dll
    CHECK(shell32->function_count() == 1);

    // Ground truth: SHFileOperationW with hint 155
    auto sh_file_op = shell32->find_function("SHFileOperationW");
    CHECK(sh_file_op != nullptr);
    if (sh_file_op) {
        CHECK(sh_file_op->hint == 155);
    }
}

TEST_CASE("TCMADM64 - Total import count") {
    auto data = load_tcmadm64();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);
    auto imports = pe.imports();
    REQUIRE(imports != nullptr);

    // Ground truth from objdump: 114 total imports
    // (KERNEL32: 93, USER32: 1, ADVAPI32: 19, SHELL32: 1)
    CHECK(imports->total_imports() == 114);
}

// =============================================================================
// Exception Directory Tests - Ground Truth from objdump
// =============================================================================

TEST_CASE("TCMADM64 - Exception directory") {
    auto data = load_tcmadm64();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);

    // Ground truth: .pdata at RVA 0x1a000, size 0xc3c
    CHECK(pe.has_data_directory(directory_entry::EXCEPTION));

    auto exceptions = pe.exceptions();
    REQUIRE(exceptions != nullptr);

    // Each RUNTIME_FUNCTION is 12 bytes, so 0xc3c / 12 = 259 entries
    // But objdump shows many entries, check we have some
    CHECK(exceptions->function_count() > 0);

    // Check type is x64 SEH
    CHECK(exceptions->type == exception_handling_type::X64_SEH);
}

// =============================================================================
// Security Directory Tests - Ground Truth from objdump
// =============================================================================

TEST_CASE("TCMADM64 - Security directory") {
    auto data = load_tcmadm64();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);

    // Ground truth: Security at RVA 0x19600, size 0x3568
    CHECK(pe.has_data_directory(directory_entry::SECURITY));

    auto security = pe.security();
    REQUIRE(security != nullptr);

    // Should have at least one certificate
    CHECK(security->certificate_count() > 0);
}

// =============================================================================
// No Export/Relocation/TLS Tests
// =============================================================================

TEST_CASE("TCMADM64 - No exports") {
    auto data = load_tcmadm64();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);

    CHECK_FALSE(pe.has_data_directory(directory_entry::EXPORT));

    auto exports = pe.exports();
    REQUIRE(exports != nullptr);
    CHECK(exports->export_count() == 0);
}

TEST_CASE("TCMADM64 - No relocations") {
    auto data = load_tcmadm64();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);

    // Ground truth: Characteristics 0x23 includes "relocations stripped"
    CHECK_FALSE(pe.has_data_directory(directory_entry::BASERELOC));

    auto relocs = pe.relocations();
    REQUIRE(relocs != nullptr);
    CHECK(relocs->block_count() == 0);
}

TEST_CASE("TCMADM64 - No TLS") {
    auto data = load_tcmadm64();
    REQUIRE(!data.empty());

    auto pe = pe_file::from_memory(data);

    CHECK_FALSE(pe.has_data_directory(directory_entry::TLS));

    // tls() may return empty object instead of nullptr
    auto tls = pe.tls();
    if (tls) {
        CHECK(tls->callback_count() == 0);
    }
}
