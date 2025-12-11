# libexe Programmer's Guide

A comprehensive guide to using libexe, the modern C++20 library for analyzing Windows executable files.

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Format Detection and Loading](#format-detection-and-loading)
4. [Working with DOS MZ Files](#working-with-dos-mz-files)
5. [Working with NE Files](#working-with-ne-files)
6. [Working with PE Files](#working-with-pe-files)
7. [Working with LE/LX Files](#working-with-lelx-files)
8. [Decompressing Packed Executables](#decompressing-packed-executables)
9. [Resource Extraction](#resource-extraction)
10. [Security Analysis](#security-analysis)
11. [Diagnostics and Anomaly Detection](#diagnostics-and-anomaly-detection)
12. [Advanced Topics](#advanced-topics)
13. [Error Handling](#error-handling)
14. [Thread Safety](#thread-safety)

---

## Introduction

libexe is a modern C++20 library designed for parsing and analyzing Windows executable file formats. It supports:

- **DOS MZ** - Original DOS executables
- **NE (New Executable)** - 16-bit Windows 3.x and OS/2 1.x
- **PE (Portable Executable)** - 32-bit and 64-bit Windows
- **LE/LX (Linear Executable)** - DOS extenders and OS/2 2.x+

The library is designed for:
- Malware analysis and security research
- Reverse engineering tools
- File format validation
- Executable inspection utilities

### Design Philosophy

- **Modern C++20**: Uses `std::span`, `std::filesystem`, `std::optional`, and other modern features
- **Zero manual memory management**: RAII, smart pointers, and STL containers throughout
- **Declarative parsing**: Format specifications drive the parser generation
- **Comprehensive diagnostics**: Detailed anomaly detection for security analysis

---

## Getting Started

### Installation

```cmake
# In your CMakeLists.txt
find_package(libexe REQUIRED)
target_link_libraries(your_target PRIVATE libexe::libexe)
```

Or include as a subdirectory:

```cmake
add_subdirectory(path/to/libexe)
target_link_libraries(your_target PRIVATE libexe)
```

### Basic Usage

```cpp
#include <libexe/libexe.hpp>
#include <iostream>

int main() {
    // Load any executable format
    auto exe = libexe::executable_factory::from_file("program.exe");

    std::cout << "Format: " << exe->format_name() << std::endl;
    std::cout << "Code size: " << exe->code_section().size() << " bytes" << std::endl;

    return 0;
}
```

### Header Organization

```cpp
// Master include - imports entire public API
#include <libexe/libexe.hpp>

// Or include specific components:
#include <libexe/formats/pe_file.hpp>      // PE parser only
#include <libexe/formats/mz_file.hpp>      // MZ parser only
#include <libexe/decompressors/all.hpp>    // All decompressors
#include <libexe/resources/parsers/all.hpp> // All resource parsers
```

---

## Format Detection and Loading

### Automatic Format Detection

The `executable_factory` automatically detects the file format and returns the appropriate parser:

```cpp
#include <libexe/formats/executable_factory.hpp>

// From file path
auto exe = libexe::executable_factory::from_file("unknown.exe");

// From memory buffer
std::vector<uint8_t> data = read_file_somehow();
auto exe = libexe::executable_factory::from_memory(data);

// Check what format was detected
switch (exe->get_format()) {
    case libexe::format_type::MZ_DOS:
        std::cout << "Plain DOS executable" << std::endl;
        break;
    case libexe::format_type::PE_WIN32:
        std::cout << "32-bit Windows PE" << std::endl;
        break;
    case libexe::format_type::PE_PLUS_WIN64:
        std::cout << "64-bit Windows PE" << std::endl;
        break;
    case libexe::format_type::NE_WIN16:
        std::cout << "16-bit Windows/OS2 NE" << std::endl;
        break;
    case libexe::format_type::LE_DOS32_BOUND:
        std::cout << "DOS extender (LE with stub)" << std::endl;
        break;
    // ... other formats
}
```

### Direct Format Loading

If you know the format, load directly for better performance:

```cpp
// Load as specific format (throws if wrong format)
auto pe = libexe::pe_file::from_file("kernel32.dll");
auto mz = libexe::mz_file::from_file("game.exe");
auto ne = libexe::ne_file::from_file("win31app.exe");
auto le = libexe::le_file::from_file("dos4gw_game.exe");
```

### Downcasting from Base Class

```cpp
auto exe = libexe::executable_factory::from_file("program.exe");

if (exe->get_format() == libexe::format_type::PE_WIN32 ||
    exe->get_format() == libexe::format_type::PE_PLUS_WIN64) {
    // Safe to downcast
    auto& pe = static_cast<libexe::pe_file&>(*exe);
    std::cout << "Entry point: 0x" << std::hex << pe.entry_point_rva() << std::endl;
}
```

---

## Working with DOS MZ Files

DOS MZ is the original executable format, identified by the "MZ" signature.

### Basic MZ Analysis

```cpp
#include <libexe/formats/mz_file.hpp>

auto mz = libexe::mz_file::from_file("game.exe");

// Entry point (CS:IP)
std::cout << "Entry: " << std::hex
          << mz.entry_cs() << ":" << mz.entry_ip() << std::endl;

// Stack (SS:SP)
std::cout << "Stack: " << mz.entry_ss() << ":" << mz.entry_sp() << std::endl;

// Memory requirements
std::cout << "Min memory: " << (mz.min_extra_paragraphs() * 16) << " bytes" << std::endl;
std::cout << "Max memory: " << (mz.max_extra_paragraphs() * 16) << " bytes" << std::endl;

// Header size
std::cout << "Header: " << (mz.header_paragraphs() * 16) << " bytes" << std::endl;
```

### Compression Detection

libexe can detect common DOS executable packers:

```cpp
if (mz.is_compressed()) {
    std::cout << "Packed with: ";
    switch (mz.get_compression()) {
        case libexe::compression_type::PKLITE_STANDARD:
            std::cout << "PKLITE (standard)";
            break;
        case libexe::compression_type::PKLITE_EXTRA:
            std::cout << "PKLITE (extra compression)";
            break;
        case libexe::compression_type::LZEXE_090:
            std::cout << "LZEXE 0.90";
            break;
        case libexe::compression_type::LZEXE_091:
            std::cout << "LZEXE 0.91";
            break;
        case libexe::compression_type::EXEPACK:
            std::cout << "Microsoft EXEPACK";
            break;
        case libexe::compression_type::KNOWLEDGE_DYNAMICS:
            std::cout << "Knowledge Dynamics";
            break;
        default:
            std::cout << "Unknown";
    }
    std::cout << std::endl;
}
```

### Entropy Analysis

High entropy often indicates packed or encrypted content:

```cpp
double entropy = mz.file_entropy();
std::cout << "File entropy: " << entropy << " bits" << std::endl;

if (mz.is_high_entropy()) {
    std::cout << "Warning: High entropy detected (likely packed)" << std::endl;
}

if (mz.is_likely_packed()) {
    std::cout << "Heuristic: File appears to be packed" << std::endl;
}
```

---

## Working with NE Files

NE (New Executable) was used for 16-bit Windows 3.x and OS/2 1.x applications.

### Basic NE Analysis

```cpp
#include <libexe/formats/ne_file.hpp>

auto ne = libexe::ne_file::from_file("program.exe");

// Target OS
std::cout << "Target: ";
switch (ne.target_os()) {
    case libexe::ne_target_os::WINDOWS:
        std::cout << "Windows";
        break;
    case libexe::ne_target_os::OS2:
        std::cout << "OS/2";
        break;
    // ... others
}
std::cout << std::endl;

// Entry point (segment:offset)
std::cout << "Entry: segment " << ne.entry_cs()
          << " offset 0x" << std::hex << ne.entry_ip() << std::endl;

// Linker version
std::cout << "Linker: " << (int)ne.linker_version()
          << "." << (int)ne.linker_revision() << std::endl;
```

### Working with Segments

```cpp
std::cout << "Segments: " << ne.segment_count() << std::endl;

for (const auto& seg : ne.segments()) {
    std::cout << "  Segment " << seg.index << ": ";
    std::cout << seg.size << " bytes, ";

    if (seg.is_code()) {
        std::cout << "[CODE]";
    } else {
        std::cout << "[DATA]";
    }

    if (seg.is_moveable()) std::cout << " MOVEABLE";
    if (seg.is_preload()) std::cout << " PRELOAD";
    if (seg.is_discardable()) std::cout << " DISCARDABLE";

    std::cout << std::endl;
}

// Get specific segment
if (auto code_seg = ne.get_code_segment()) {
    std::cout << "First code segment: " << code_seg->size << " bytes" << std::endl;
}
```

### NE Resources

```cpp
if (ne.has_resources()) {
    auto resources = ne.resources();
    // Work with resource directory...
}
```

---

## Working with PE Files

PE (Portable Executable) is the format for modern Windows executables.

### Basic PE Analysis

```cpp
#include <libexe/formats/pe_file.hpp>

auto pe = libexe::pe_file::from_file("program.exe");

// Architecture
std::cout << "Architecture: " << (pe.is_64bit() ? "PE32+ (64-bit)" : "PE32 (32-bit)") << std::endl;

// Machine type
std::cout << "Machine: ";
switch (pe.machine_type()) {
    case libexe::pe_machine_type::I386:
        std::cout << "x86";
        break;
    case libexe::pe_machine_type::AMD64:
        std::cout << "x64";
        break;
    case libexe::pe_machine_type::ARM64:
        std::cout << "ARM64";
        break;
    default:
        std::cout << "Other";
}
std::cout << std::endl;

// Basic info
std::cout << "Entry point: 0x" << std::hex << pe.entry_point_rva() << std::endl;
std::cout << "Image base: 0x" << pe.image_base() << std::endl;
std::cout << "Image size: " << std::dec << pe.size_of_image() << " bytes" << std::endl;
```

### Subsystem Detection

```cpp
std::cout << "Subsystem: ";
switch (pe.subsystem()) {
    case libexe::pe_subsystem::WINDOWS_GUI:
        std::cout << "Windows GUI";
        break;
    case libexe::pe_subsystem::WINDOWS_CUI:
        std::cout << "Windows Console";
        break;
    case libexe::pe_subsystem::NATIVE:
        std::cout << "Native/Driver";
        break;
    case libexe::pe_subsystem::EFI_APPLICATION:
        std::cout << "EFI Application";
        break;
    default:
        std::cout << "Other";
}
std::cout << std::endl;

// Check file type
if (pe.is_dll()) {
    std::cout << "Type: Dynamic Link Library" << std::endl;
} else if (pe.is_driver()) {
    std::cout << "Type: Kernel Driver" << std::endl;
} else {
    std::cout << "Type: Executable" << std::endl;
}
```

### Working with Sections

```cpp
std::cout << "Sections: " << pe.section_count() << std::endl;

for (const auto& section : pe.sections()) {
    std::cout << "  " << section.name << ": ";
    std::cout << "VA=0x" << std::hex << section.virtual_address;
    std::cout << " Size=" << std::dec << section.virtual_size;

    // Permissions
    std::cout << " [";
    if (section.is_readable()) std::cout << "R";
    if (section.is_writable()) std::cout << "W";
    if (section.is_executable()) std::cout << "X";
    std::cout << "]";

    // Content type
    if (section.is_code()) std::cout << " CODE";
    if (section.contains_data()) std::cout << " DATA";

    std::cout << std::endl;
}

// Find section by name
if (auto text = pe.get_section(".text")) {
    std::cout << ".text section found at RVA 0x"
              << std::hex << text->virtual_address << std::endl;
}

// Find section containing an RVA
if (auto sec = pe.section_from_rva(pe.entry_point_rva())) {
    std::cout << "Entry point is in section: " << sec->name << std::endl;
}
```

### Import Analysis

```cpp
// List imported DLLs
std::cout << "Imports:" << std::endl;
for (const auto& dll : pe.imported_dlls()) {
    std::cout << "  " << dll << std::endl;
}

// Detailed import information
if (auto imports = pe.imports()) {
    for (const auto& desc : imports->descriptors()) {
        std::cout << desc.dll_name << ":" << std::endl;
        for (const auto& func : desc.functions) {
            if (func.is_ordinal) {
                std::cout << "    Ordinal " << func.ordinal << std::endl;
            } else {
                std::cout << "    " << func.name;
                if (func.hint != 0) {
                    std::cout << " (hint: " << func.hint << ")";
                }
                std::cout << std::endl;
            }
        }
    }
}
```

### Export Analysis

```cpp
if (auto exports = pe.exports()) {
    std::cout << "Module name: " << exports->dll_name() << std::endl;
    std::cout << "Exports:" << std::endl;

    for (const auto& exp : exports->functions()) {
        std::cout << "  [" << exp.ordinal << "] ";
        if (!exp.name.empty()) {
            std::cout << exp.name;
        } else {
            std::cout << "(unnamed)";
        }
        std::cout << " -> 0x" << std::hex << exp.rva;

        if (exp.is_forwarder) {
            std::cout << " -> " << exp.forwarder_name;
        }
        std::cout << std::endl;
    }
}
```

### Rich Header Analysis

PE files built with Microsoft tools contain a Rich header with build information:

```cpp
if (pe.has_rich_header()) {
    auto rich = pe.rich_header();

    std::cout << "Rich Header:" << std::endl;
    std::cout << "  Checksum valid: " << (rich->checksum_valid() ? "Yes" : "No") << std::endl;

    for (const auto& entry : rich->entries()) {
        std::cout << "  Product: " << entry.product_id
                  << " Build: " << entry.build_number
                  << " Count: " << entry.use_count << std::endl;
    }
}
```

### Overlay Detection

Data appended after the PE image is called an overlay:

```cpp
if (pe.has_overlay()) {
    auto overlay = pe.overlay();

    std::cout << "Overlay detected:" << std::endl;
    std::cout << "  Offset: 0x" << std::hex << overlay->file_offset() << std::endl;
    std::cout << "  Size: " << std::dec << overlay->size() << " bytes" << std::endl;
    std::cout << "  Entropy: " << overlay->entropy() << " bits" << std::endl;

    // Get overlay data
    auto data = overlay->data();
}
```

---

## Working with LE/LX Files

LE (Linear Executable) and LX are formats used by DOS extenders and OS/2.

### Basic LE/LX Analysis

```cpp
#include <libexe/formats/le_file.hpp>

auto le = libexe::le_file::from_file("game.exe");

// Format variant
std::cout << "Format: " << (le.is_lx() ? "LX (OS/2)" : "LE") << std::endl;

// Special types
if (le.is_vxd()) {
    std::cout << "Type: Windows VxD (Virtual Device Driver)" << std::endl;
} else if (le.is_library()) {
    std::cout << "Type: Library/DLL" << std::endl;
} else {
    std::cout << "Type: Executable" << std::endl;
}

// Entry point
std::cout << "Entry: Object " << le.entry_object()
          << " Offset 0x" << std::hex << le.entry_eip() << std::endl;

// Memory info
std::cout << "Page size: " << std::dec << le.page_size() << " bytes" << std::endl;
std::cout << "Stack size: " << le.stack_size() << " bytes" << std::endl;
```

### DOS Extender Detection

LE files are often "bound" to a DOS extender stub:

```cpp
if (le.is_bound()) {
    std::cout << "DOS extender stub detected: ";
    switch (le.extender_type()) {
        case libexe::dos_extender_type::DOS4GW:
            std::cout << "DOS/4GW (Watcom)";
            break;
        case libexe::dos_extender_type::DOS32A:
            std::cout << "DOS/32A";
            break;
        case libexe::dos_extender_type::PMODEW:
            std::cout << "PMODE/W";
            break;
        case libexe::dos_extender_type::CAUSEWAY:
            std::cout << "CauseWay";
            break;
        default:
            std::cout << "Unknown";
    }
    std::cout << std::endl;

    std::cout << "Stub size: " << le.stub_size() << " bytes" << std::endl;
}
```

### Stripping DOS Extender Stubs

You can extract the raw LE/LX data without the DOS extender stub:

```cpp
if (le.is_bound()) {
    // Get raw LE/LX data without DOS stub
    auto raw_le = le.strip_extender();

    if (!raw_le.empty()) {
        // Save or process the stripped executable
        std::ofstream out("stripped.le", std::ios::binary);
        out.write(reinterpret_cast<const char*>(raw_le.data()), raw_le.size());
    }
}
```

### Working with Objects (Segments)

```cpp
std::cout << "Objects:" << std::endl;
for (const auto& obj : le.objects()) {
    std::cout << "  Object " << obj.index << ": ";
    std::cout << obj.virtual_size << " bytes at 0x" << std::hex << obj.base_address;

    std::cout << " [";
    if (obj.is_readable()) std::cout << "R";
    if (obj.is_writable()) std::cout << "W";
    if (obj.is_executable()) std::cout << "X";
    std::cout << "]";

    if (obj.is_32bit()) std::cout << " 32-bit";
    if (obj.is_preload()) std::cout << " PRELOAD";

    std::cout << std::endl;
}

// Read object data (handles page decompression)
if (auto code_obj = le.get_code_object()) {
    auto data = le.read_object_data(code_obj->index);
    std::cout << "Code object: " << data.size() << " bytes" << std::endl;
}
```

### LE/LX Imports and Exports

```cpp
// Imported modules
std::cout << "Imports " << le.import_module_count() << " modules:" << std::endl;
for (const auto& mod : le.import_modules()) {
    std::cout << "  " << mod << std::endl;
}

// Entry points (exports)
std::cout << "Entries: " << le.entry_count() << std::endl;
for (const auto& entry : le.entries()) {
    std::cout << "  Ordinal " << entry.ordinal << ": ";
    std::cout << "Object " << entry.object << " + 0x" << std::hex << entry.offset;
    if (entry.is_exported()) std::cout << " [EXPORTED]";
    std::cout << std::endl;
}

// Module name
std::cout << "Module name: " << le.module_name() << std::endl;
```

---

## Decompressing Packed Executables

libexe includes decompressors for common DOS executable packers.

### Using the Decompressor Factory

```cpp
#include <libexe/decompressors/all.hpp>

auto mz = libexe::mz_file::from_file("packed.exe");

if (mz.is_compressed()) {
    // Create appropriate decompressor
    auto decomp = libexe::create_decompressor(mz.get_compression());

    if (decomp) {
        std::cout << "Decompressing with " << decomp->name() << "..." << std::endl;

        try {
            auto result = decomp->decompress(mz.code_section());

            std::cout << "Decompressed " << result.code.size() << " bytes" << std::endl;
            std::cout << "Original entry: " << std::hex
                      << result.initial_cs << ":" << result.initial_ip << std::endl;
            std::cout << "Relocations: " << result.relocations.size() << std::endl;

            // result.code contains the decompressed executable code
            // result contains header values to reconstruct the MZ file

        } catch (const std::runtime_error& e) {
            std::cerr << "Decompression failed: " << e.what() << std::endl;
        }
    }
}
```

### Reconstructing the Original Executable

```cpp
void save_decompressed(const libexe::decompression_result& result,
                       const std::string& output_path) {
    std::ofstream out(output_path, std::ios::binary);

    // Calculate header size (MZ header + relocations)
    uint16_t reloc_size = result.relocations.size() * 4;
    uint16_t header_size = 0x20 + reloc_size;  // Minimum MZ header + relocations
    uint16_t header_paragraphs = (header_size + 15) / 16;
    header_size = header_paragraphs * 16;  // Align to paragraph

    // Calculate file size
    uint32_t file_size = header_size + result.code.size();

    // Write MZ header
    uint8_t header[0x20] = {0};
    header[0] = 'M'; header[1] = 'Z';  // Magic
    header[2] = file_size & 0xFF;
    header[3] = (file_size >> 8) & 0xFF;
    // ... fill in other header fields from result

    out.write(reinterpret_cast<const char*>(header), 0x20);

    // Write relocations
    for (const auto& [seg, off] : result.relocations) {
        uint8_t reloc[4] = {
            static_cast<uint8_t>(off & 0xFF),
            static_cast<uint8_t>((off >> 8) & 0xFF),
            static_cast<uint8_t>(seg & 0xFF),
            static_cast<uint8_t>((seg >> 8) & 0xFF)
        };
        out.write(reinterpret_cast<const char*>(reloc), 4);
    }

    // Pad to header size
    std::vector<uint8_t> padding(header_size - 0x20 - reloc_size, 0);
    out.write(reinterpret_cast<const char*>(padding.data()), padding.size());

    // Write decompressed code
    out.write(reinterpret_cast<const char*>(result.code.data()), result.code.size());
}
```

---

## Resource Extraction

libexe provides parsers for Windows resource formats.

### Accessing Resources

```cpp
auto pe = libexe::pe_file::from_file("program.exe");

if (pe.has_resources()) {
    auto resources = pe.resources();

    // Iterate all resources
    for (const auto& type : resources->types()) {
        std::cout << "Resource type: " << type.name_or_id() << std::endl;

        for (const auto& name : type.names()) {
            for (const auto& lang : name.languages()) {
                std::cout << "  " << name.name_or_id()
                          << " (lang: " << lang.language_id() << ")"
                          << " Size: " << lang.size() << std::endl;
            }
        }
    }
}
```

### Extracting Icons

```cpp
#include <libexe/resources/parsers/icon_parser.hpp>
#include <libexe/resources/parsers/icon_group_parser.hpp>

auto pe = libexe::pe_file::from_file("program.exe");

if (pe.has_resources()) {
    auto resources = pe.resources();

    // Get icon groups
    libexe::icon_group_parser group_parser;
    auto groups = group_parser.parse_all(*resources);

    for (const auto& group : groups) {
        std::cout << "Icon group with " << group.icons.size() << " icons" << std::endl;

        for (const auto& icon : group.icons) {
            std::cout << "  " << icon.width << "x" << icon.height
                      << " " << icon.bit_count << "bpp" << std::endl;
        }
    }

    // Extract individual icons
    libexe::icon_parser icon_parser;
    // ... extract and save icon data
}
```

### Extracting Version Information

```cpp
#include <libexe/resources/parsers/version_info_parser.hpp>

auto pe = libexe::pe_file::from_file("program.exe");

if (pe.has_resources()) {
    libexe::version_info_parser parser;
    auto version = parser.parse(*pe.resources());

    if (version) {
        std::cout << "File Version: "
                  << version->file_version_major() << "."
                  << version->file_version_minor() << "."
                  << version->file_version_build() << "."
                  << version->file_version_revision() << std::endl;

        // String table values
        if (auto company = version->get_string("CompanyName")) {
            std::cout << "Company: " << *company << std::endl;
        }
        if (auto product = version->get_string("ProductName")) {
            std::cout << "Product: " << *product << std::endl;
        }
        if (auto desc = version->get_string("FileDescription")) {
            std::cout << "Description: " << *desc << std::endl;
        }
    }
}
```

### Extracting Manifests

```cpp
#include <libexe/resources/parsers/manifest_parser.hpp>

auto pe = libexe::pe_file::from_file("program.exe");

if (pe.has_resources()) {
    libexe::manifest_parser parser;
    auto manifest = parser.parse(*pe.resources());

    if (manifest) {
        std::cout << "Manifest:" << std::endl;
        std::cout << manifest->xml_content() << std::endl;

        // Parsed values
        if (manifest->requires_admin()) {
            std::cout << "Requires administrator privileges" << std::endl;
        }
    }
}
```

---

## Security Analysis

libexe provides tools for security analysis of executables.

### Security Feature Detection

```cpp
auto pe = libexe::pe_file::from_file("program.exe");

std::cout << "Security Features:" << std::endl;

// ASLR (Address Space Layout Randomization)
std::cout << "  ASLR: " << (pe.has_aslr() ? "Enabled" : "Disabled") << std::endl;
if (pe.has_high_entropy_aslr()) {
    std::cout << "  High-entropy ASLR: Enabled" << std::endl;
}

// DEP/NX (Data Execution Prevention)
std::cout << "  DEP/NX: " << (pe.has_dep() ? "Enabled" : "Disabled") << std::endl;

// CFG (Control Flow Guard)
std::cout << "  CFG: " << (pe.has_cfg() ? "Enabled" : "Disabled") << std::endl;

// SEH (Structured Exception Handling)
std::cout << "  SafeSEH: " << (pe.has_safe_seh() ? "Enabled" : "N/A or Disabled") << std::endl;
std::cout << "  No SEH: " << (pe.has_no_seh() ? "Yes" : "No") << std::endl;

// Code signing
std::cout << "  Force Integrity: " << (pe.has_force_integrity() ? "Yes" : "No") << std::endl;

// AppContainer
std::cout << "  AppContainer: " << (pe.is_app_container() ? "Yes" : "No") << std::endl;
```

### Authenticode Signature Analysis

```cpp
if (pe.has_authenticode()) {
    auto auth = pe.authenticode();

    std::cout << "Authenticode Signature:" << std::endl;
    std::cout << "  Valid: " << (auth->is_valid() ? "Yes" : "No") << std::endl;
    std::cout << "  Signer: " << auth->signer_name() << std::endl;
    std::cout << "  Issuer: " << auth->issuer_name() << std::endl;

    // Certificate chain
    for (const auto& cert : auth->certificate_chain()) {
        std::cout << "  Certificate: " << cert.subject << std::endl;
        std::cout << "    Serial: " << cert.serial_number << std::endl;
        std::cout << "    Valid: " << cert.not_before << " to " << cert.not_after << std::endl;
    }

    // Timestamp
    if (auth->has_timestamp()) {
        std::cout << "  Timestamp: " << auth->timestamp() << std::endl;
    }
}
```

### Entropy Analysis

```cpp
// File-level entropy
double file_entropy = pe.file_entropy();
std::cout << "File entropy: " << file_entropy << " bits" << std::endl;

// Section-level entropy
for (const auto& section : pe.sections()) {
    double entropy = pe.section_entropy(section.name);
    std::cout << section.name << " entropy: " << entropy << " bits";

    if (entropy > 7.0) {
        std::cout << " [HIGH - possibly packed/encrypted]";
    } else if (entropy > 6.0) {
        std::cout << " [elevated]";
    }
    std::cout << std::endl;
}

// Overall packing assessment
if (pe.is_likely_packed()) {
    std::cout << "Warning: File appears to be packed" << std::endl;
}
```

---

## Diagnostics and Anomaly Detection

libexe generates detailed diagnostics about format violations and anomalies.

### Accessing Diagnostics

```cpp
auto pe = libexe::pe_file::from_file("suspicious.exe");

const auto& diags = pe.diagnostics();

// Summary
std::cout << "Diagnostics: " << diags.count() << " total" << std::endl;
std::cout << "  Errors: " << diags.error_count() << std::endl;
std::cout << "  Anomalies: " << diags.anomaly_count() << std::endl;
std::cout << "  Warnings: " << diags.warning_count() << std::endl;

// Check for specific conditions
if (diags.has_anomalies()) {
    std::cout << "\nAnomalies detected:" << std::endl;
    for (const auto& diag : diags.anomalies()) {
        std::cout << "  [" << libexe::code_name(diag.code) << "] "
                  << diag.message << std::endl;
        if (!diag.details.empty()) {
            std::cout << "    Details: " << diag.details << std::endl;
        }
        if (diag.file_offset != 0) {
            std::cout << "    Offset: 0x" << std::hex << diag.file_offset << std::endl;
        }
    }
}
```

### Filtering Diagnostics

```cpp
// By severity
auto errors = diags.errors();
auto warnings = diags.warnings();

// By category
auto import_issues = diags.by_category(libexe::diagnostic_category::IMPORT);
auto header_issues = diags.by_category(libexe::diagnostic_category::PE_HEADER);

// Check for specific diagnostic codes
if (diags.has_code(libexe::diagnostic_code::OPT_ZERO_ENTRY_POINT)) {
    std::cout << "Warning: Entry point is zero" << std::endl;
}

if (diags.has_code(libexe::diagnostic_code::SECT_OVERLAP)) {
    std::cout << "Error: Overlapping sections detected" << std::endl;
}
```

### Common Anomalies

```cpp
// Header anomalies
// - OPT_ZERO_ENTRY_POINT: Entry point is 0
// - OPT_EP_OUTSIDE_IMAGE: Entry point beyond image
// - OPT_EP_IN_HEADER: Entry point in header region

// Section anomalies
// - SECT_OVERLAP: Sections overlap in file or memory
// - SECT_BEYOND_FILE: Section data beyond file end

// Import anomalies
// - IMP_SELF_IMPORT: Module imports from itself
// - IMP_BINARY_NAME: Non-printable characters in DLL name

// Relocation anomalies
// - RELOC_HEADER_TARGET: Relocation targets header
// - RELOC_UNUSUAL_TYPE: Unusual relocation types
```

---

## Advanced Topics

### Memory-Mapped File Access

For large files, consider memory-mapping:

```cpp
#include <sys/mman.h>
#include <fcntl.h>

// Memory map the file
int fd = open("large.exe", O_RDONLY);
struct stat st;
fstat(fd, &st);
void* mapped = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

// Create span from mapped memory
std::span<const uint8_t> data(static_cast<const uint8_t*>(mapped), st.st_size);

// Parse
auto pe = libexe::pe_file::from_memory(data);

// ... use pe ...

// Cleanup
munmap(mapped, st.st_size);
close(fd);
```

### RVA to File Offset Conversion

```cpp
// Convert RVA to file offset
uint32_t rva = pe.entry_point_rva();
if (auto offset = pe.rva_to_file_offset(rva)) {
    std::cout << "Entry point file offset: 0x" << std::hex << *offset << std::endl;
}

// Convert file offset to RVA
uint32_t file_offset = 0x1000;
if (auto rva = pe.file_offset_to_rva(file_offset)) {
    std::cout << "RVA for offset 0x1000: 0x" << std::hex << *rva << std::endl;
}
```

### Working with Raw Data

```cpp
// Get raw file data
std::span<const uint8_t> raw = pe.raw_data();

// Read data at RVA
if (auto data = pe.read_rva(0x1000, 256)) {
    // data contains 256 bytes starting at RVA 0x1000
}

// Read null-terminated string at RVA
if (auto str = pe.read_string_rva(0x2000)) {
    std::cout << "String: " << *str << std::endl;
}
```

---

## Error Handling

libexe uses exceptions for error reporting.

### Exception Types

```cpp
#include <stdexcept>

try {
    auto pe = libexe::pe_file::from_file("invalid.exe");
} catch (const std::runtime_error& e) {
    // Format validation errors, I/O errors
    std::cerr << "Error: " << e.what() << std::endl;
} catch (const std::invalid_argument& e) {
    // Invalid parameters
    std::cerr << "Invalid argument: " << e.what() << std::endl;
}
```

### Handling Malformed Files

```cpp
// The library is designed to handle malformed files gracefully
// Most parsing errors result in diagnostics rather than exceptions

auto pe = libexe::pe_file::from_file("malformed.exe");

// Check if file is usable despite issues
if (pe.diagnostics().has_errors()) {
    std::cout << "File has errors but was partially parsed" << std::endl;

    // Many methods will still work
    std::cout << "Machine type: " << static_cast<int>(pe.machine_type()) << std::endl;
}
```

---

## Thread Safety

### Read-Only Operations

All read-only operations on parsed executable objects are thread-safe:

```cpp
auto pe = libexe::pe_file::from_file("program.exe");

// Safe to call from multiple threads simultaneously
std::thread t1([&pe]() {
    auto imports = pe.imported_dlls();
});

std::thread t2([&pe]() {
    auto sections = pe.sections();
});

t1.join();
t2.join();
```

### Lazy Initialization

Some data is parsed lazily. The library uses internal synchronization for thread-safe lazy initialization:

```cpp
// These may trigger lazy parsing, but are still thread-safe
auto resources = pe.resources();  // Lazy-parsed
auto exports = pe.exports();      // Lazy-parsed
```

### Factory Functions

The factory functions are thread-safe:

```cpp
// Safe to call from multiple threads
std::thread t1([]() {
    auto pe = libexe::pe_file::from_file("a.exe");
});

std::thread t2([]() {
    auto pe = libexe::pe_file::from_file("b.exe");
});
```

---

## Appendix: Format Quick Reference

### PE Data Directories

| Index | Name | Description |
|-------|------|-------------|
| 0 | EXPORT | Exported functions |
| 1 | IMPORT | Imported functions |
| 2 | RESOURCE | Resources (icons, dialogs, etc.) |
| 3 | EXCEPTION | Exception handling (.pdata) |
| 4 | SECURITY | Authenticode signature |
| 5 | BASERELOC | Base relocations |
| 6 | DEBUG | Debug information |
| 7 | ARCHITECTURE | Reserved |
| 8 | GLOBALPTR | Global pointer register |
| 9 | TLS | Thread local storage |
| 10 | LOAD_CONFIG | Load configuration |
| 11 | BOUND_IMPORT | Bound imports |
| 12 | IAT | Import address table |
| 13 | DELAY_IMPORT | Delay-load imports |
| 14 | COM_DESCRIPTOR | .NET CLR header |
| 15 | RESERVED | Reserved (must be zero) |

### Common Machine Types

| Value | Name | Description |
|-------|------|-------------|
| 0x014C | I386 | Intel 386 (x86) |
| 0x8664 | AMD64 | x64 (AMD64/Intel 64) |
| 0xAA64 | ARM64 | ARM 64-bit |
| 0x01C4 | ARMNT | ARM Thumb-2 |
| 0x0200 | IA64 | Intel Itanium |

### Compression Types

| Type | Description |
|------|-------------|
| PKLITE_STANDARD | PKWare LITE standard compression |
| PKLITE_EXTRA | PKWare LITE maximum compression |
| LZEXE_090 | LZEXE version 0.90 |
| LZEXE_091 | LZEXE version 0.91 |
| EXEPACK | Microsoft EXEPACK |
| KNOWLEDGE_DYNAMICS | Knowledge Dynamics compressor |

---

## See Also

- [API Reference](../build/docs/html/index.html) - Generated Doxygen documentation
- [Microsoft PE/COFF Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [NE Format Reference](ne.fmt)
- [LE/LX Format Reference](le_format.txt)
