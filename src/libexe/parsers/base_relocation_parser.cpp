#include <libexe/pe/directories/relocation.hpp>
#include <libexe/pe/section_parser.hpp>
#include "libexe_format_pe_relocations.hh"
#include <stdexcept>

namespace libexe {

base_relocation_directory base_relocation_parser::parse(
    std::span<const uint8_t> file_data,
    const std::vector<pe_section>& sections,
    uint32_t reloc_dir_rva,
    uint32_t reloc_dir_size
) {
    base_relocation_directory result;

    if (reloc_dir_rva == 0) {
        return result;
    }

    // Convert RVA to file offset
    size_t reloc_dir_offset = rva_to_offset(sections, reloc_dir_rva);

    const uint8_t* ptr = file_data.data() + reloc_dir_offset;
    const uint8_t* end = ptr + reloc_dir_size;

    // Parse blocks until we've consumed all relocation data
    while (ptr + 8 <= end) {
        // Peek at header to check for termination
        auto header = formats::pe::pe_relocations::image_base_relocation::read(ptr, end);

        // Restore pointer - we'll re-read with the full block structure
        ptr -= 8;

        // Check for null block (indicates end)
        if (header.virtual_address == 0 && header.size_of_block == 0) {
            break;
        }

        // Validate block size
        if (header.size_of_block < 8) {
            throw std::runtime_error(
                "Invalid relocation block size: " + std::to_string(header.size_of_block)
            );
        }

        // Check if block fits in available data
        if (ptr + header.size_of_block > end) {
            throw std::runtime_error("Relocation block exceeds directory bounds");
        }

        // Parse complete block with entries using DataScript
        auto ds_block = formats::pe::pe_relocations::relocation_block::read(ptr, end);

        relocation_block block;
        block.page_rva = ds_block.virtual_address;

        // Convert type/offset entries to relocation_entry structs
        block.entries.reserve(ds_block.entries.size());
        for (uint16_t type_offset : ds_block.entries) {
            block.entries.push_back(parse_type_offset(type_offset, ds_block.virtual_address));
        }

        result.blocks.push_back(std::move(block));
    }

    return result;
}

relocation_entry base_relocation_parser::parse_type_offset(
    uint16_t type_offset,
    uint32_t page_rva
) {
    relocation_entry entry;

    // Extract offset (low 12 bits)
    uint16_t offset = type_offset & OFFSET_MASK;

    // Extract type (high 4 bits)
    uint8_t type = static_cast<uint8_t>((type_offset >> TYPE_SHIFT) & 0x0F);

    // Calculate actual RVA
    entry.rva = page_rva + offset;
    entry.type = static_cast<relocation_type>(type);

    return entry;
}

size_t base_relocation_parser::rva_to_offset(
    const std::vector<pe_section>& sections,
    uint32_t rva
) {
    auto offset = pe_section_parser::rva_to_file_offset(sections, rva);
    if (!offset) {
        throw std::runtime_error("RVA 0x" + std::to_string(rva) + " not found in any section");
    }
    return offset.value();
}

} // namespace libexe
