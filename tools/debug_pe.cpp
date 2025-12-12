// Quick debugging tool to check PE parsing
#include <libexe/pe_file.hpp>
#include <libexe/import_directory.hpp>
#include <iostream>
#include <filesystem>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pe_file>\n";
        return 1;
    }

    std::filesystem::path path(argv[1]);
    if (!std::filesystem::exists(path)) {
        std::cerr << "Error: File not found: " << argv[1] << "\n";
        return 1;
    }

    auto size = std::filesystem::file_size(path);
    std::cout << "File: " << argv[1] << "\n";
    std::cout << "Size: " << size << " bytes\n\n";

    // Parse PE using memory-mapped file (no longer reads whole file into memory)
    try {
        auto pe = libexe::pe_file::from_file(path);

        std::cout << "Format: " << static_cast<int>(pe.get_format()) << "\n";
        std::cout << "Is 64-bit: " << (pe.is_64bit() ? "yes" : "no") << "\n";
        std::cout << "Section count: " << pe.section_count() << "\n\n";

        // Check data directories
        std::cout << "Data Directories:\n";

        const char* dir_names[] = {
            "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY",
            "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS",
            "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED"
        };

        for (int i = 0; i < 16; i++) {
            auto entry = static_cast<libexe::directory_entry>(i);
            uint32_t rva = pe.data_directory_rva(entry);
            uint32_t size = pe.data_directory_size(entry);
            bool has = pe.has_data_directory(entry);

            std::cout << "  [" << i << "] " << dir_names[i]
                     << ": RVA=0x" << std::hex << rva
                     << " Size=0x" << size << std::dec
                     << " Has=" << (has ? "YES" : "NO") << "\n";
        }

        // Try to parse imports
        std::cout << "\nImport Directory:\n";
        auto imports = pe.imports();
        if (imports) {
            std::cout << "  Parsed successfully\n";
            std::cout << "  DLL count: " << imports->dll_count() << "\n";
            for (const auto& dll : imports->dlls) {
                std::cout << "    - " << dll.name << " (" << dll.functions.size() << " functions)\n";
            }
        } else {
            std::cout << "  Failed to parse (nullptr)\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
