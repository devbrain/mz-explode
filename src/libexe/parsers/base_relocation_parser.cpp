#include <libexe/parsers/base_relocation_parser.hpp>
#include <libexe/pe_section_parser.hpp>
#include "libexe_format_pe_relocations.hh"  // Generated DataScript parser
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
        // No relocations
        return result;
    }

    // NOTE: Don't check reloc_dir_size == 0, many PE files set size=0.
    // Relocation blocks have internal size fields.

    // Convert RVA to file offset
    size_t reloc_dir_offset = rva_to_offset(sections, reloc_dir_rva);

    const uint8_t* ptr = file_data.data() + reloc_dir_offset;
    const uint8_t* end = ptr + reloc_dir_size;

    // Parse blocks until we've consumed all relocation data
    while (ptr < end) {
        // Need at least 8 bytes for header
        if (ptr + 8 > end) {
            break;  // Not enough data for another block
        }

        // Parse one block
        size_t bytes_read = 0;
        auto block = parse_block(ptr, end, bytes_read);

        if (bytes_read == 0) {
            break;  // No more blocks
        }

        result.blocks.push_back(std::move(block));
        ptr += bytes_read;
    }

    return result;
}

relocation_block base_relocation_parser::parse_block(
    const uint8_t* data,
    const uint8_t* end,
    size_t& bytes_read
) {
    relocation_block block;
    bytes_read = 0;

    // Read IMAGE_BASE_RELOCATION header
    auto header = formats::pe::pe_relocations::image_base_relocation::read(data, end);

    // Check for null block (indicates end)
    if (header.virtual_address == 0 && header.size_of_block == 0) {
        return block;  // Empty block signals end
    }

    // Validate block size
    if (header.size_of_block < 8) {
        throw std::runtime_error(
            "Invalid relocation block size: " + std::to_string(header.size_of_block)
        );
    }

    // Check if block size exceeds available data
    if (data + header.size_of_block > end) {
        throw std::runtime_error("Relocation block exceeds directory bounds");
    }

    block.page_rva = header.virtual_address;

    // Calculate number of type/offset entries
    uint32_t entry_count = (header.size_of_block - 8) / 2;

    // Read type/offset entries (array of uint16)
    const uint8_t* entry_ptr = data;  // ptr already advanced by read()
    for (uint32_t i = 0; i < entry_count; i++) {
        if (entry_ptr + 2 > end) {
            throw std::runtime_error("Relocation entry exceeds directory bounds");
        }

        // Read uint16 little-endian
        uint16_t type_offset = static_cast<uint16_t>(entry_ptr[0]) |
                               (static_cast<uint16_t>(entry_ptr[1]) << 8);

        // Parse type/offset entry
        auto entry = parse_type_offset(type_offset, header.virtual_address);
        block.entries.push_back(entry);

        entry_ptr += 2;
    }

    bytes_read = header.size_of_block;
    return block;
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
