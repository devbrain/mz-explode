// libexe - Modern executable file analysis library
// PE Base Relocation Directory - Types and Parser

#ifndef LIBEXE_PE_DIRECTORIES_RELOCATION_HPP
#define LIBEXE_PE_DIRECTORIES_RELOCATION_HPP

#include <libexe/export.hpp>
#include <libexe/pe/section.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include <span>

namespace libexe {

// =============================================================================
// Base Relocation Types
// =============================================================================

/**
 * Base relocation type
 *
 * Defines how the address at the relocation offset should be adjusted
 * when the module is loaded at a different address than ImageBase.
 */
enum class relocation_type : uint8_t {
    ABSOLUTE = 0,      // No operation, used for padding to align blocks
    HIGH = 1,          // Add high 16 bits of delta to 16-bit field
    LOW = 2,           // Add low 16 bits of delta to 16-bit field
    HIGHLOW = 3,       // Add full 32-bit delta to 32-bit field (PE32)
    HIGHADJ = 4,       // Complex adjustment with parameter word
    MIPS_JMPADDR = 5,  // MIPS jump address
    ARM_MOV32 = 5,     // ARM: Move 32-bit address (reuses value 5)
    RISCV_HIGH20 = 5,  // RISC-V: High 20 bits (reuses value 5)
    THUMB_MOV32 = 7,   // ARM Thumb: Move 32-bit address
    RISCV_LOW12I = 7,  // RISC-V: Low 12 bits (I-format, reuses value 7)
    RISCV_LOW12S = 8,  // RISC-V: Low 12 bits (S-format)
    MIPS_JMPADDR16 = 9,// MIPS16 jump address
    DIR64 = 10,        // Add full 64-bit delta to 64-bit field (PE32+)
};

/**
 * Single base relocation entry
 *
 * Represents one location in the executable that needs adjustment
 * when loaded at a different base address (ASLR support).
 */
struct LIBEXE_EXPORT relocation_entry {
    uint32_t rva;              // RVA to the location to be relocated
    relocation_type type;      // Type of relocation to perform

    /**
     * Get size of relocation in bytes
     */
    [[nodiscard]] size_t size_bytes() const {
        switch (type) {
            case relocation_type::ABSOLUTE:
                return 0;
            case relocation_type::HIGH:
            case relocation_type::LOW:
                return 2;
            case relocation_type::HIGHLOW:
            case relocation_type::HIGHADJ:
            case relocation_type::MIPS_JMPADDR:
            case relocation_type::THUMB_MOV32:
            case relocation_type::RISCV_LOW12S:
            case relocation_type::MIPS_JMPADDR16:
                return 4;
            case relocation_type::DIR64:
                return 8;
            default:
                return 0;
        }
    }

    /**
     * Check if this is a 64-bit relocation
     */
    [[nodiscard]] bool is_64bit() const {
        return type == relocation_type::DIR64;
    }

    /**
     * Check if this is a 32-bit relocation
     */
    [[nodiscard]] bool is_32bit() const {
        return type == relocation_type::HIGHLOW ||
               type == relocation_type::HIGHADJ ||
               type == relocation_type::MIPS_JMPADDR ||
               type == relocation_type::THUMB_MOV32 ||
               type == relocation_type::RISCV_LOW12S ||
               type == relocation_type::MIPS_JMPADDR16;
    }

    /**
     * Get type name as string
     */
    [[nodiscard]] std::string type_name() const {
        switch (type) {
            case relocation_type::ABSOLUTE: return "ABSOLUTE";
            case relocation_type::HIGH: return "HIGH";
            case relocation_type::LOW: return "LOW";
            case relocation_type::HIGHLOW: return "HIGHLOW";
            case relocation_type::HIGHADJ: return "HIGHADJ";
            case relocation_type::MIPS_JMPADDR: return "MIPS_JMPADDR";
            case relocation_type::THUMB_MOV32: return "THUMB_MOV32";
            case relocation_type::RISCV_LOW12S: return "RISCV_LOW12S";
            case relocation_type::MIPS_JMPADDR16: return "MIPS_JMPADDR16";
            case relocation_type::DIR64: return "DIR64";
            default: return "UNKNOWN";
        }
    }
};

/**
 * Base relocation block
 *
 * Represents a 4KB page of relocations.
 */
struct LIBEXE_EXPORT relocation_block {
    uint32_t page_rva;
    std::vector<relocation_entry> entries;

    [[nodiscard]] size_t relocation_count() const {
        return entries.size();
    }

    [[nodiscard]] size_t active_relocation_count() const {
        size_t count = 0;
        for (const auto& entry : entries) {
            if (entry.type != relocation_type::ABSOLUTE) {
                count++;
            }
        }
        return count;
    }
};

/**
 * Complete base relocation directory
 *
 * Contains all base relocations for the executable.
 * Parsed from PE data directory index 5.
 */
struct LIBEXE_EXPORT base_relocation_directory {
    std::vector<relocation_block> blocks;

    [[nodiscard]] size_t block_count() const {
        return blocks.size();
    }

    [[nodiscard]] size_t total_relocations() const {
        size_t count = 0;
        for (const auto& block : blocks) {
            count += block.relocation_count();
        }
        return count;
    }

    [[nodiscard]] size_t active_relocations() const {
        size_t count = 0;
        for (const auto& block : blocks) {
            count += block.active_relocation_count();
        }
        return count;
    }

    [[nodiscard]] const relocation_block* find_block_for_rva(uint32_t rva) const {
        for (const auto& block : blocks) {
            if (rva >= block.page_rva && rva < block.page_rva + 0x1000) {
                return &block;
            }
        }
        return nullptr;
    }

    [[nodiscard]] bool has_relocation_at(uint32_t rva) const {
        auto block = find_block_for_rva(rva);
        if (!block) {
            return false;
        }
        for (const auto& entry : block->entries) {
            if (entry.rva == rva && entry.type != relocation_type::ABSOLUTE) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] std::vector<std::pair<relocation_type, size_t>> get_type_counts() const {
        std::vector<std::pair<relocation_type, size_t>> counts;
        size_t type_counts[11] = {0};

        for (const auto& block : blocks) {
            for (const auto& entry : block.entries) {
                uint8_t type_value = static_cast<uint8_t>(entry.type);
                if (type_value <= 10) {
                    type_counts[type_value]++;
                }
            }
        }

        for (size_t i = 0; i <= 10; i++) {
            if (type_counts[i] > 0) {
                counts.emplace_back(static_cast<relocation_type>(i), type_counts[i]);
            }
        }

        return counts;
    }
};

// =============================================================================
// Base Relocation Parser
// =============================================================================

/**
 * Base Relocation Parser
 *
 * Parses PE base relocation directory (data directory index 5).
 */
class LIBEXE_EXPORT base_relocation_parser {
public:
    static base_relocation_directory parse(
        std::span<const uint8_t> file_data,
        const std::vector<pe_section>& sections,
        uint32_t reloc_dir_rva,
        uint32_t reloc_dir_size
    );

private:
    static relocation_entry parse_type_offset(
        uint16_t type_offset,
        uint32_t page_rva
    );

    static size_t rva_to_offset(
        const std::vector<pe_section>& sections,
        uint32_t rva
    );

    static constexpr uint16_t OFFSET_MASK = 0x0FFF;
    static constexpr uint16_t TYPE_SHIFT = 12;
};

} // namespace libexe

#endif // LIBEXE_PE_DIRECTORIES_RELOCATION_HPP
