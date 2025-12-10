// exeinfo - Unified executable analyzer and resource extractor
// Supports MZ, NE, PE/PE32+, LE/LX formats
// Copyright (c) 2024

#include <libexe/formats/mz_file.hpp>
#include <libexe/formats/ne_file.hpp>
#include <libexe/formats/pe_file.hpp>
#include <libexe/formats/le_file.hpp>
#include <libexe/decompressors/decompressor.hpp>
#include <libexe/pe/directories/import.hpp>
#include <libexe/pe/directories/export.hpp>
#include <libexe/pe/rich_header.hpp>
#include <libexe/resources/resource.hpp>
#include <libexe/resources/parsers/version_info_parser.hpp>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <variant>
#include <optional>

namespace fs = std::filesystem;

namespace {

// =============================================================================
// Output formatting helpers
// =============================================================================

void print_header(const char* title) {
    std::cout << "\n" << title << "\n";
    std::cout << std::string(60, '-') << "\n";
}

void print_section(const char* title) {
    std::cout << "\n" << title << "\n";
    std::cout << std::string(60, '=') << "\n";
}

template <typename T>
void print_field(const char* name, T value, int width = 32) {
    std::cout << "  " << std::left << std::setw(width) << name << ": ";
    if constexpr (std::is_integral_v<T>) {
        std::cout << std::hex << "0x" << value << std::dec << " (" << value << ")";
    } else {
        std::cout << value;
    }
    std::cout << "\n";
}

void print_bool(const char* name, bool value, int width = 32) {
    std::cout << "  " << std::left << std::setw(width) << name << ": "
              << (value ? "Yes" : "No") << "\n";
}

void print_address(const char* name, uint16_t seg, uint16_t off) {
    std::cout << "  " << std::left << std::setw(32) << name << ": "
              << std::hex << std::setfill('0')
              << std::setw(4) << seg << ":" << std::setw(4) << off
              << std::setfill(' ') << std::dec << "\n";
}

// =============================================================================
// Name lookup tables
// =============================================================================

const char* compression_name(libexe::compression_type type) {
    switch (type) {
        case libexe::compression_type::NONE:               return "None";
        case libexe::compression_type::PKLITE_STANDARD:    return "PKLITE (Standard)";
        case libexe::compression_type::PKLITE_EXTRA:       return "PKLITE (Extra)";
        case libexe::compression_type::LZEXE_090:          return "LZEXE 0.90";
        case libexe::compression_type::LZEXE_091:          return "LZEXE 0.91";
        case libexe::compression_type::EXEPACK:            return "EXEPACK";
        case libexe::compression_type::KNOWLEDGE_DYNAMICS: return "Knowledge Dynamics";
        default:                                           return "Unknown";
    }
}

const char* machine_name(libexe::pe_machine_type machine) {
    switch (machine) {
        case libexe::pe_machine_type::UNKNOWN:    return "Unknown";
        case libexe::pe_machine_type::I386:       return "Intel 386 (x86)";
        case libexe::pe_machine_type::AMD64:      return "AMD64 (x64)";
        case libexe::pe_machine_type::ARM:        return "ARM";
        case libexe::pe_machine_type::ARM64:      return "ARM64";
        case libexe::pe_machine_type::ARMNT:      return "ARM Thumb-2";
        case libexe::pe_machine_type::IA64:       return "Intel Itanium";
        default:                                   return "Other";
    }
}

const char* subsystem_name(libexe::pe_subsystem subsystem) {
    switch (subsystem) {
        case libexe::pe_subsystem::UNKNOWN:                  return "Unknown";
        case libexe::pe_subsystem::NATIVE:                   return "Native (driver)";
        case libexe::pe_subsystem::WINDOWS_GUI:              return "Windows GUI";
        case libexe::pe_subsystem::WINDOWS_CUI:              return "Windows Console";
        case libexe::pe_subsystem::POSIX_CUI:                return "POSIX Console";
        case libexe::pe_subsystem::WINDOWS_CE_GUI:           return "Windows CE";
        case libexe::pe_subsystem::EFI_APPLICATION:          return "EFI Application";
        case libexe::pe_subsystem::EFI_BOOT_SERVICE_DRIVER:  return "EFI Boot Driver";
        case libexe::pe_subsystem::EFI_RUNTIME_DRIVER:       return "EFI Runtime Driver";
        case libexe::pe_subsystem::EFI_ROM:                  return "EFI ROM";
        case libexe::pe_subsystem::XBOX:                     return "Xbox";
        default:                                              return "Other";
    }
}

const char* resource_type_name(uint16_t type) {
    switch (type) {
        case 1:  return "Cursor";
        case 2:  return "Bitmap";
        case 3:  return "Icon";
        case 4:  return "Menu";
        case 5:  return "Dialog";
        case 6:  return "StringTable";
        case 7:  return "FontDir";
        case 8:  return "Font";
        case 9:  return "Accelerator";
        case 10: return "RCData";
        case 11: return "MessageTable";
        case 12: return "GroupCursor";
        case 14: return "GroupIcon";
        case 16: return "VersionInfo";
        case 17: return "DlgInclude";
        case 19: return "PlugPlay";
        case 20: return "VXD";
        case 21: return "AniCursor";
        case 22: return "AniIcon";
        case 23: return "HTML";
        case 24: return "Manifest";
        default: return "Custom";
    }
}

std::string get_extension(uint16_t type) {
    switch (type) {
        case 2:  return ".bmp";
        case 3:  return ".ico";
        case 14: return ".ico";
        case 8:  return ".fnt";
        case 23: return ".html";
        case 24: return ".manifest";
        case 6:  return ".txt";
        case 16: return ".txt";
        case 11: return ".txt";
        default: return ".bin";
    }
}

// =============================================================================
// MZ format handling
// =============================================================================

void show_mz_info(const libexe::mz_file& mz) {
    print_section("DOS MZ Executable");

    print_header("General Information");
    print_field("Format", mz.format_name().data());
    print_field("Compression", compression_name(mz.get_compression()));
    print_address("Initial CS:IP", mz.initial_cs(), mz.initial_ip());
    print_address("Initial SS:SP", mz.initial_ss(), mz.initial_sp());
    print_field("Min extra paragraphs", mz.min_extra_paragraphs());
    print_field("Max extra paragraphs", mz.max_extra_paragraphs());
    print_field("Header size (paragraphs)", mz.header_paragraphs());
    print_field("Relocation count", mz.relocation_count());
    print_field("Code section size", static_cast<uint32_t>(mz.code_section().size()));

    print_header("Analysis");
    auto entropy = mz.code_entropy();
    std::cout << "  " << std::left << std::setw(32) << "Code Entropy"
              << ": " << std::fixed << std::setprecision(2) << entropy << " bits";
    if (entropy >= 7.0) std::cout << " [HIGH - likely compressed/encrypted]";
    std::cout << "\n";
    print_bool("Is Compressed", mz.is_compressed());
}

std::vector<uint8_t> build_mz_output(const libexe::decompression_result& result) {
    const size_t code_size = result.code.size();
    const size_t reloc_count = result.relocations.size();
    const size_t reloc_size = reloc_count * 4;
    const size_t header_base = 28 + reloc_size;
    const size_t header_size = (header_base + 15) & ~15;
    const size_t total_size = header_size + code_size;
    const uint16_t pages = static_cast<uint16_t>((total_size + 511) / 512);
    const uint16_t last_page = static_cast<uint16_t>(total_size % 512);

    std::vector<uint8_t> output(total_size, 0);
    output[0] = 'M';
    output[1] = 'Z';

    auto write16 = [&output](size_t offset, uint16_t value) {
        output[offset] = static_cast<uint8_t>(value & 0xFF);
        output[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    };

    write16(2, last_page);
    write16(4, pages);
    write16(6, static_cast<uint16_t>(reloc_count));
    write16(8, static_cast<uint16_t>(header_size / 16));
    write16(10, result.min_extra_paragraphs);
    write16(12, 0xFFFF);
    write16(14, result.initial_ss);
    write16(16, result.initial_sp);
    write16(18, 0);
    write16(20, result.initial_ip);
    write16(22, result.initial_cs);
    write16(24, 28);
    write16(26, 0);

    size_t reloc_offset = 28;
    for (const auto& [segment, offset] : result.relocations) {
        write16(reloc_offset, offset);
        write16(reloc_offset + 2, segment);
        reloc_offset += 4;
    }

    std::memcpy(output.data() + header_size, result.code.data(), code_size);
    return output;
}

bool decompress_mz(const libexe::mz_file& mz, const std::string& output_path) {
    if (!mz.is_compressed()) {
        std::cerr << "Error: File is not compressed\n";
        return false;
    }

    auto decompressor = libexe::create_decompressor(mz.get_compression());
    if (!decompressor) {
        std::cerr << "Error: No decompressor available for this format\n";
        return false;
    }

    std::cout << "Decompressing " << compression_name(mz.get_compression()) << "...\n";
    auto result = decompressor->decompress(mz.code_section());

    print_header("Decompression Results");
    print_field("Decompressed size", static_cast<uint32_t>(result.code.size()));
    print_field("Relocation count", static_cast<uint32_t>(result.relocations.size()));
    print_address("Initial CS:IP", result.initial_cs, result.initial_ip);
    print_address("Initial SS:SP", result.initial_ss, result.initial_sp);

    auto output_data = build_mz_output(result);

    std::ofstream out(output_path, std::ios::binary);
    if (!out) {
        std::cerr << "Error: Cannot create output file: " << output_path << "\n";
        return false;
    }
    out.write(reinterpret_cast<const char*>(output_data.data()),
              static_cast<std::streamsize>(output_data.size()));

    std::cout << "\nDecompressed to: " << output_path << " (" << output_data.size() << " bytes)\n";
    return true;
}

// =============================================================================
// NE format handling
// =============================================================================

const char* ne_target_os_name(libexe::ne_target_os os) {
    switch (os) {
        case libexe::ne_target_os::UNKNOWN:  return "Unknown";
        case libexe::ne_target_os::OS2:      return "OS/2";
        case libexe::ne_target_os::WINDOWS:  return "Windows";
        case libexe::ne_target_os::DOS4:     return "DOS 4.x";
        case libexe::ne_target_os::WIN386:   return "Windows 386";
        case libexe::ne_target_os::BOSS:     return "Borland OS Services";
        default:                              return "Other";
    }
}

void show_ne_info(const libexe::ne_file& ne) {
    print_section("NE (16-bit Windows) Executable");

    print_header("General Information");
    print_field("Format", ne.format_name().data());
    print_field("Target OS", ne_target_os_name(ne.target_os()));
    print_field("Segment count", ne.segment_count());
    print_field("Linker Version", static_cast<uint16_t>(ne.linker_version()));
    print_field("Linker Revision", static_cast<uint16_t>(ne.linker_revision()));
    print_bool("Has Resources", ne.has_resources());

    if (ne.has_resources()) {
        auto resources = ne.resources();
        if (resources) {
            auto all = resources->all_resources();
            print_field("Resource count", all.size());
        }
    }

    print_header("Entry Point");
    print_address("Initial CS:IP", ne.entry_cs(), ne.entry_ip());
    print_address("Initial SS:SP", ne.initial_ss(), ne.initial_sp());

    print_header("Analysis");
    auto entropy = ne.file_entropy();
    std::cout << "  " << std::left << std::setw(32) << "File Entropy"
              << ": " << std::fixed << std::setprecision(2) << entropy << " bits";
    if (entropy >= 7.0) std::cout << " [HIGH]";
    std::cout << "\n";
    print_bool("Likely Packed", ne.is_likely_packed());
}

// =============================================================================
// PE format handling
// =============================================================================

void show_pe_info(const libexe::pe_file& pe, bool verbose) {
    print_section("PE Executable");

    print_header("General Information");
    print_field("Format", pe.format_name().data());
    print_field("Architecture", pe.is_64bit() ? "64-bit (PE32+)" : "32-bit (PE32)");
    print_field("Machine", machine_name(pe.machine_type()));
    print_field("Subsystem", subsystem_name(pe.subsystem()));
    print_bool("Is DLL", pe.is_dll());
    print_bool("Is .NET", pe.is_dotnet());

    print_header("Build Information");
    print_field("Timestamp", pe.timestamp());
    print_field("Entry Point RVA", pe.entry_point_rva());
    print_field("Image Base", pe.image_base());
    print_field("Size of Image", pe.size_of_image());
    print_field("Section Count", pe.section_count());

    print_header("Security Features");
    print_bool("ASLR", pe.has_aslr());
    print_bool("High Entropy ASLR", pe.has_high_entropy_aslr());
    print_bool("DEP/NX", pe.has_dep());
    print_bool("CFG (Control Flow Guard)", pe.has_cfg());
    print_bool("SEH Disabled", pe.has_no_seh());
    print_bool("Safe SEH", pe.has_safe_seh());
    print_bool("Force Integrity", pe.has_force_integrity());
    print_bool("AppContainer", pe.is_appcontainer());
    print_bool("Large Address Aware", pe.is_large_address_aware());
    print_bool("Authenticode Signed", pe.has_authenticode());

    print_header("Packing Analysis");
    auto entropy = pe.file_entropy();
    std::cout << "  " << std::left << std::setw(32) << "File Entropy"
              << ": " << std::fixed << std::setprecision(2) << entropy << " bits\n";
    print_bool("High Entropy Sections", pe.has_high_entropy_sections());
    print_bool("Likely Packed", pe.is_likely_packed());

    if (pe.has_overlay()) {
        print_header("Overlay");
        print_field("Overlay Offset", pe.overlay_offset());
        print_field("Overlay Size", pe.overlay_size());
        std::cout << "  " << std::left << std::setw(32) << "Overlay Entropy"
                  << ": " << std::fixed << std::setprecision(2) << pe.overlay_entropy() << " bits\n";
    }

    print_header("Sections");
    const auto& sections = pe.sections();
    std::cout << "  " << std::left << std::setw(10) << "Name"
              << std::setw(12) << "VirtAddr"
              << std::setw(12) << "VirtSize"
              << std::setw(12) << "RawSize"
              << "Characteristics\n";
    std::cout << "  " << std::string(58, '-') << "\n";

    for (const auto& section : sections) {
        std::cout << "  " << std::left << std::setw(10) << section.name
                  << std::hex
                  << std::setw(12) << section.virtual_address
                  << std::setw(12) << section.virtual_size
                  << std::setw(12) << section.raw_data_size
                  << std::setw(12) << section.characteristics
                  << std::dec << "\n";
    }

    if (verbose) {
        auto entropies = pe.all_section_entropies();
        if (!entropies.empty()) {
            std::cout << "\n  Section Entropies:\n";
            for (const auto& [name, ent] : entropies) {
                std::cout << "    " << std::left << std::setw(10) << name
                          << ": " << std::fixed << std::setprecision(2) << ent << " bits";
                if (ent >= 7.0) std::cout << " [HIGH]";
                std::cout << "\n";
            }
        }
    }

    if (pe.has_rich_header()) {
        print_header("Rich Header (Build Tools)");
        auto rich = pe.rich();
        if (rich) {
            std::cout << "  " << std::left << std::setw(8) << "ProdID"
                      << std::setw(10) << "Build"
                      << "Count\n";
            std::cout << "  " << std::string(30, '-') << "\n";
            for (const auto& entry : rich->entries) {
                std::cout << "  " << std::left
                          << std::setw(8) << entry.product_id
                          << std::setw(10) << entry.build_number
                          << entry.count << "\n";
            }
        }
    }

    // Import summary
    auto dlls = pe.imported_dlls();
    auto func_count = pe.imported_function_count();
    if (!dlls.empty()) {
        print_header("Imports Summary");
        print_field("DLL Count", dlls.size());
        print_field("Total Functions", func_count);
    }

    // Export summary
    auto exports = pe.exported_functions();
    if (!exports.empty()) {
        print_header("Exports Summary");
        print_field("Function Count", exports.size());
    }

    if (pe.has_authenticode()) {
        print_header("Authenticode Signature");
        auto auth = pe.authenticode_info();
        if (auth) {
            auto signing_cert = auth->signing_certificate();
            if (signing_cert) {
                print_field("Subject", signing_cert->subject.to_string());
                print_field("Issuer", signing_cert->issuer.to_string());
            }
            print_field("Digest", hash_algorithm_name(auth->digest_algorithm));
            print_bool("Has Timestamp", auth->has_timestamp());
        }
        std::cout << "\n  " << pe.authenticode_security_summary() << "\n";
    }

    if (pe.has_anomalies()) {
        print_header("Anomalies Detected");
        const auto& diag = pe.diagnostics();
        for (const auto& d : diag.all()) {
            std::cout << "  [" << (d.severity == libexe::diagnostic_severity::WARNING ? "WARN" : "ERR ")
                      << "] " << d.message << "\n";
        }
    }
}

void show_pe_imports(const libexe::pe_file& pe) {
    auto imports = pe.imports();
    if (!imports) {
        std::cout << "No imports found\n";
        return;
    }

    print_section("Import Directory");

    for (const auto& dll : imports->dlls) {
        std::cout << dll.name << " (" << dll.functions.size() << " functions)\n";
        std::cout << std::string(50, '-') << "\n";
        for (const auto& func : dll.functions) {
            if (func.ordinal != 0 && func.name.empty()) {
                std::cout << "  [" << func.ordinal << "] (ordinal)\n";
            } else {
                std::cout << "  " << func.name;
                if (func.hint != 0) {
                    std::cout << " (hint: " << func.hint << ")";
                }
                std::cout << "\n";
            }
        }
        std::cout << "\n";
    }
}

void show_pe_exports(const libexe::pe_file& pe) {
    auto exports = pe.exports();
    if (!exports) {
        std::cout << "No exports found\n";
        return;
    }

    print_section("Export Directory");

    print_field("Module Name", exports->module_name);
    print_field("Ordinal Base", exports->ordinal_base);
    print_field("Export Count", exports->exports.size());
    std::cout << "\n";

    std::cout << std::left << std::setw(8) << "Ordinal"
              << std::setw(12) << "RVA"
              << "Name\n";
    std::cout << std::string(50, '-') << "\n";

    for (const auto& exp : exports->exports) {
        std::cout << std::left << std::setw(8) << exp.ordinal
                  << std::hex << std::setw(12) << exp.rva << std::dec
                  << exp.name;
        if (exp.is_forwarder) {
            std::cout << " -> " << exp.forwarder_name;
        }
        std::cout << "\n";
    }
}

// =============================================================================
// LE/LX format handling
// =============================================================================

const char* le_os_type_name(uint16_t os_type) {
    switch (os_type) {
        case 0x0000: return "Unknown";
        case 0x0001: return "OS/2";
        case 0x0002: return "Windows";
        case 0x0003: return "DOS 4.x";
        case 0x0004: return "Windows 386";
        default:     return "Other";
    }
}

const char* le_cpu_type_name(uint16_t cpu_type) {
    switch (cpu_type) {
        case 0x0001: return "80286";
        case 0x0002: return "80386";
        case 0x0003: return "80486";
        case 0x0004: return "Pentium";
        case 0x0020: return "i860 (N10)";
        case 0x0021: return "i860 (N11)";
        case 0x0040: return "MIPS Mark I (R2000/R3000)";
        case 0x0041: return "MIPS Mark II (R6000)";
        case 0x0042: return "MIPS Mark III (R4000)";
        default:     return "Unknown";
    }
}

const char* le_resource_type_name(uint16_t type) {
    switch (type) {
        case 1:  return "Pointer";
        case 2:  return "Bitmap";
        case 3:  return "Menu";
        case 4:  return "Dialog";
        case 5:  return "StringTable";
        case 6:  return "FontDir";
        case 7:  return "Font";
        case 8:  return "AccelTable";
        case 9:  return "RCData";
        case 10: return "Message";
        case 11: return "DlgInclude";
        case 12: return "VKeyTable";
        case 13: return "KeyTable";
        case 14: return "CharTable";
        case 15: return "DisplayInfo";
        case 16: return "FKAShort";
        case 17: return "FKALong";
        case 18: return "HelpTable";
        case 19: return "HelpSubTable";
        default: return "Custom";
    }
}

void list_le_resources(const libexe::le_file& le) {
    print_section("Resources (OS/2 Format)");

    std::cout << std::left
              << std::setw(6) << "Type"
              << std::setw(16) << "Type Name"
              << std::setw(10) << "Name ID"
              << std::setw(10) << "Object"
              << "Size\n";
    std::cout << std::string(60, '-') << "\n";

    const auto& resources = le.resources();
    size_t total_size = 0;

    for (const auto& res : resources) {
        std::cout << std::left
                  << std::setw(6) << res.type_id
                  << std::setw(16) << le_resource_type_name(res.type_id)
                  << std::setw(10) << res.name_id
                  << std::setw(10) << res.object
                  << res.size << " bytes\n";
        total_size += res.size;
    }

    std::cout << std::string(60, '-') << "\n";
    std::cout << "Total: " << resources.size() << " resources, " << total_size << " bytes\n";
}

void extract_le_resources(const libexe::le_file& le,
                          const fs::path& output_dir,
                          uint16_t filter_type,
                          bool verbose) {
    fs::create_directories(output_dir);

    const auto& resources = le.resources();
    size_t extracted = 0;
    size_t skipped = 0;

    for (const auto& res : resources) {
        if (filter_type != 0 && res.type_id != filter_type) {
            skipped++;
            continue;
        }

        std::string type_name = le_resource_type_name(res.type_id);
        std::string filename = type_name + "_" + std::to_string(res.name_id) + ".bin";

        fs::path type_dir = output_dir / type_name;
        fs::create_directories(type_dir);
        fs::path out_path = type_dir / filename;

        std::ofstream out(out_path, std::ios::binary);
        if (!out) {
            std::cerr << "Error: Cannot create file: " << out_path << "\n";
            continue;
        }

        auto data = le.read_resource_data(res);
        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));

        if (verbose) {
            std::cout << "Extracted: " << out_path << " (" << data.size() << " bytes)\n";
        }

        extracted++;
    }

    std::cout << "\nExtracted " << extracted << " resources to " << output_dir << "\n";
    if (skipped > 0) {
        std::cout << "Skipped " << skipped << " resources (filtered)\n";
    }
}

void show_le_info(const libexe::le_file& le) {
    print_section("LE/LX Executable");

    print_header("General Information");
    print_field("Format", le.format_name().data());
    print_bool("Is LX (OS/2 2.x)", le.is_lx());
    print_bool("Is VxD", le.is_vxd());
    print_bool("Is Library/DLL", le.is_library());
    print_field("CPU Type", le_cpu_type_name(le.cpu_type()));
    print_field("OS Type", le_os_type_name(le.os_type()));
    print_field("Module Version", le.module_version());

    print_header("Memory Layout");
    print_field("Object Count", le.objects().size());
    print_field("Page Count", le.page_count());
    print_field("Page Size", le.page_size());
    print_field("Heap Size", le.heap_size());
    print_field("Stack Size", le.stack_size());

    print_header("Entry Point");
    print_field("Entry Object", le.entry_object());
    print_field("Entry EIP", le.entry_eip());
    print_field("Stack Object", le.stack_object());
    print_field("Stack ESP", le.entry_esp());

    if (le.is_bound()) {
        print_header("DOS Extender");
        print_bool("Bound to DOS Extender", true);
        print_field("LE Header Offset", le.le_header_offset());
        print_field("Stub Size", le.stub_size());
    }

    // Objects table
    const auto& objects = le.objects();
    if (!objects.empty()) {
        print_header("Objects");
        std::cout << "  " << std::left << std::setw(6) << "#"
                  << std::setw(12) << "VirtSize"
                  << std::setw(12) << "BaseAddr"
                  << std::setw(8) << "Pages"
                  << "Flags\n";
        std::cout << "  " << std::string(50, '-') << "\n";

        for (const auto& obj : objects) {
            std::cout << "  " << std::left << std::setw(6) << obj.index
                      << std::hex
                      << std::setw(12) << obj.virtual_size
                      << std::setw(12) << obj.base_address
                      << std::dec
                      << std::setw(8) << obj.page_count;

            // Print flag letters
            if (obj.is_readable()) std::cout << "R";
            if (obj.is_writable()) std::cout << "W";
            if (obj.is_executable()) std::cout << "X";
            if (obj.is_resource()) std::cout << " [RES]";
            if (obj.is_discardable()) std::cout << " [DISC]";
            if (obj.is_shared()) std::cout << " [SHARED]";
            if (obj.is_32bit()) std::cout << " [32BIT]";
            std::cout << "\n";
        }
    }

    // Imports
    const auto& imports = le.import_modules();
    if (!imports.empty()) {
        print_header("Import Modules");
        for (size_t i = 0; i < imports.size(); ++i) {
            std::cout << "  [" << (i + 1) << "] " << imports[i] << "\n";
        }
    }

    // Entry points summary
    if (le.entry_count() > 0) {
        print_header("Entry Points Summary");
        print_field("Entry Count", le.entry_count());
    }

    // Fixups summary
    if (le.has_fixups()) {
        print_header("Fixups Summary");
        print_field("Fixup Count", le.fixup_count());
    }

    // Resources summary
    if (le.has_resources()) {
        print_header("Resources Summary");
        print_field("Resource Count", le.resource_count());
    }

    // Analysis
    print_header("Analysis");
    auto entropy = le.file_entropy();
    std::cout << "  " << std::left << std::setw(32) << "File Entropy"
              << ": " << std::fixed << std::setprecision(2) << entropy << " bits";
    if (entropy >= 7.0) std::cout << " [HIGH]";
    std::cout << "\n";
    print_bool("Likely Packed", le.is_likely_packed());

    // Diagnostics
    const auto& diag = le.diagnostics();
    if (!diag.all().empty()) {
        print_header("Diagnostics");
        for (const auto& d : diag.all()) {
            std::cout << "  [" << (d.severity == libexe::diagnostic_severity::WARNING ? "WARN" : "ERR ")
                      << "] " << d.message << "\n";
        }
    }
}

// =============================================================================
// Resource handling (shared by PE/NE/LE)
// =============================================================================

void list_resources(const libexe::resource_directory& resources, bool verbose) {
    print_section("Resources");

    std::cout << std::left
              << std::setw(6) << "Type"
              << std::setw(16) << "Type Name"
              << std::setw(15) << "Name/ID"
              << std::setw(10) << "Lang"
              << "Size\n";
    std::cout << std::string(60, '-') << "\n";

    auto all = resources.all_resources();
    size_t total_size = 0;

    for (const auto& entry : all) {
        std::cout << std::left
                  << std::setw(6) << entry.type_id()
                  << std::setw(16) << resource_type_name(entry.type_id())
                  << std::setw(15) << entry.name_string()
                  << std::setw(10) << entry.language()
                  << entry.size() << " bytes\n";

        if (verbose && entry.type_id() == 16) {
            auto version = entry.as_version_info();
            if (version) {
                std::cout << "    File Version: " << version->file_version() << "\n";
            }
        }

        total_size += entry.size();
    }

    std::cout << std::string(60, '-') << "\n";
    std::cout << "Total: " << all.size() << " resources, " << total_size << " bytes\n";
}

void extract_resources(const libexe::resource_directory& resources,
                       const fs::path& output_dir,
                       uint16_t filter_type,
                       bool verbose) {
    fs::create_directories(output_dir);

    auto all = resources.all_resources();
    size_t extracted = 0;
    size_t skipped = 0;

    for (const auto& entry : all) {
        if (filter_type != 0 && entry.type_id() != filter_type) {
            skipped++;
            continue;
        }

        std::string type_name = resource_type_name(entry.type_id());
        std::string ext = get_extension(entry.type_id());
        std::string filename = type_name + "_" + entry.name_string();

        if (entry.language() != 0 && entry.language() != 1033) {
            filename += "_" + std::to_string(entry.language());
        }
        filename += ext;

        fs::path type_dir = output_dir / type_name;
        fs::create_directories(type_dir);
        fs::path out_path = type_dir / filename;

        std::ofstream out(out_path, std::ios::binary);
        if (!out) {
            std::cerr << "Error: Cannot create file: " << out_path << "\n";
            continue;
        }

        auto data = entry.data();

        // For bitmaps, add BITMAPFILEHEADER if needed
        if (entry.type_id() == 2 && data.size() > 4) {
            uint32_t header_size = *reinterpret_cast<const uint32_t*>(data.data());
            if (header_size == 40 || header_size == 12 || header_size == 108 || header_size == 124) {
                uint8_t file_header[14] = {'B', 'M', 0,0,0,0, 0,0, 0,0, 0,0,0,0};
                uint32_t file_size = 14 + static_cast<uint32_t>(data.size());
                uint32_t pixel_offset = 14 + header_size;
                std::memcpy(&file_header[2], &file_size, 4);
                std::memcpy(&file_header[10], &pixel_offset, 4);
                out.write(reinterpret_cast<const char*>(file_header), 14);
            }
        }

        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));

        if (verbose) {
            std::cout << "Extracted: " << out_path << " (" << data.size() << " bytes)\n";
        }

        extracted++;
    }

    std::cout << "\nExtracted " << extracted << " resources to " << output_dir << "\n";
    if (skipped > 0) {
        std::cout << "Skipped " << skipped << " resources (filtered)\n";
    }
}

// =============================================================================
// Format detection and dispatch
// =============================================================================

enum class exe_format {
    UNKNOWN,
    MZ,
    NE,
    PE,
    LE
};

struct loaded_exe {
    exe_format format = exe_format::UNKNOWN;
    std::optional<libexe::mz_file> mz;
    std::optional<libexe::ne_file> ne;
    std::optional<libexe::pe_file> pe;
    std::optional<libexe::le_file> le;
};

loaded_exe load_executable(const char* filename) {
    loaded_exe result;

    // Try PE first (most common)
    try {
        result.pe = libexe::pe_file::from_file(filename);
        result.format = exe_format::PE;
        return result;
    } catch (...) {}

    // Try NE
    try {
        result.ne = libexe::ne_file::from_file(filename);
        result.format = exe_format::NE;
        return result;
    } catch (...) {}

    // Try LE/LX
    try {
        result.le = libexe::le_file::from_file(filename);
        result.format = exe_format::LE;
        return result;
    } catch (...) {}

    // Try plain MZ
    try {
        result.mz = libexe::mz_file::from_file(filename);
        result.format = exe_format::MZ;
        return result;
    } catch (...) {}

    return result;
}

// =============================================================================
// Command-line interface
// =============================================================================

struct options {
    bool list_resources = false;
    bool extract_resources = false;
    bool show_imports = false;
    bool show_exports = false;
    bool decompress = false;
    bool verbose = false;
    uint16_t filter_type = 0;
    const char* input_file = nullptr;
    const char* output_path = nullptr;
};

void print_usage(const char* program) {
    std::cerr << "exeinfo - Unified executable analyzer\n"
              << "Supports MZ, NE, PE/PE32+, LE/LX formats\n\n"
              << "Usage: " << program << " [options] <file> [output]\n\n"
              << "Options:\n"
              << "  -l, --list         List resources without extracting\n"
              << "  -x, --extract      Extract resources to output directory\n"
              << "  -i, --imports      Show detailed import information (PE)\n"
              << "  -e, --exports      Show detailed export information (PE)\n"
              << "  -d, --decompress   Decompress MZ to output file\n"
              << "  -t <type>          Filter resources by type ID (numeric)\n"
              << "  -v, --verbose      Show detailed information\n"
              << "  -h, --help         Show this help message\n\n"
              << "Without options, shows format-appropriate summary.\n"
              << "Output path is required for --extract and --decompress.\n";
}

bool parse_args(int argc, char* argv[], options& opts) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-l" || arg == "--list") {
            opts.list_resources = true;
        } else if (arg == "-x" || arg == "--extract") {
            opts.extract_resources = true;
        } else if (arg == "-i" || arg == "--imports") {
            opts.show_imports = true;
        } else if (arg == "-e" || arg == "--exports") {
            opts.show_exports = true;
        } else if (arg == "-d" || arg == "--decompress") {
            opts.decompress = true;
        } else if (arg == "-v" || arg == "--verbose") {
            opts.verbose = true;
        } else if (arg == "-t" && i + 1 < argc) {
            opts.filter_type = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return false;
        } else if (arg[0] != '-') {
            if (!opts.input_file) {
                opts.input_file = argv[i];
            } else {
                opts.output_path = argv[i];
            }
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return false;
        }
    }

    if (!opts.input_file) {
        std::cerr << "Error: No input file specified\n";
        print_usage(argv[0]);
        return false;
    }

    if (opts.extract_resources && !opts.output_path) {
        opts.output_path = "resources";
    }

    if (opts.decompress && !opts.output_path) {
        std::cerr << "Error: --decompress requires an output file path\n";
        return false;
    }

    return true;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    options opts;
    if (!parse_args(argc, argv, opts)) {
        return 1;
    }

    try {
        auto exe = load_executable(opts.input_file);

        if (exe.format == exe_format::UNKNOWN) {
            std::cerr << "Error: Unrecognized executable format\n";
            return 1;
        }

        // Handle format-specific operations
        switch (exe.format) {
            case exe_format::MZ: {
                if (opts.show_imports || opts.show_exports) {
                    std::cerr << "Error: Imports/exports not available for MZ format\n";
                    return 1;
                }
                if (opts.list_resources || opts.extract_resources) {
                    std::cerr << "Error: Resources not available for plain MZ format\n";
                    return 1;
                }
                if (opts.decompress) {
                    return decompress_mz(*exe.mz, opts.output_path) ? 0 : 1;
                }
                show_mz_info(*exe.mz);
                break;
            }

            case exe_format::NE: {
                if (opts.show_imports || opts.show_exports) {
                    std::cerr << "Error: Detailed imports/exports not yet implemented for NE format\n";
                    return 1;
                }
                if (opts.decompress) {
                    std::cerr << "Error: Decompression not applicable to NE format\n";
                    return 1;
                }
                if (opts.list_resources || opts.extract_resources) {
                    if (!exe.ne->has_resources()) {
                        std::cerr << "Error: NE file has no resources\n";
                        return 1;
                    }
                    auto resources = exe.ne->resources();
                    if (opts.list_resources) {
                        list_resources(*resources, opts.verbose);
                    } else {
                        extract_resources(*resources, opts.output_path, opts.filter_type, opts.verbose);
                    }
                } else {
                    show_ne_info(*exe.ne);
                }
                break;
            }

            case exe_format::PE: {
                if (opts.decompress) {
                    std::cerr << "Error: Decompression not applicable to PE format\n";
                    return 1;
                }
                if (opts.show_imports) {
                    show_pe_imports(*exe.pe);
                } else if (opts.show_exports) {
                    show_pe_exports(*exe.pe);
                } else if (opts.list_resources || opts.extract_resources) {
                    if (!exe.pe->has_resources()) {
                        std::cerr << "Error: PE file has no resources\n";
                        return 1;
                    }
                    auto resources = exe.pe->resources();
                    if (opts.list_resources) {
                        list_resources(*resources, opts.verbose);
                    } else {
                        extract_resources(*resources, opts.output_path, opts.filter_type, opts.verbose);
                    }
                } else {
                    show_pe_info(*exe.pe, opts.verbose);
                }
                break;
            }

            case exe_format::LE: {
                if (opts.show_imports || opts.show_exports) {
                    std::cerr << "Error: Detailed imports/exports not yet implemented for LE/LX format\n";
                    return 1;
                }
                if (opts.decompress) {
                    std::cerr << "Error: Decompression not applicable to LE/LX format\n";
                    return 1;
                }
                if (opts.list_resources || opts.extract_resources) {
                    if (!exe.le->has_resources()) {
                        std::cerr << "Error: LE/LX file has no resources\n";
                        return 1;
                    }
                    if (opts.list_resources) {
                        list_le_resources(*exe.le);
                    } else {
                        extract_le_resources(*exe.le, opts.output_path, opts.filter_type, opts.verbose);
                    }
                } else {
                    show_le_info(*exe.le);
                }
                break;
            }

            default:
                break;
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
