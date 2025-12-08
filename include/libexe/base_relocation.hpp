#ifndef LIBEXE_BASE_RELOCATION_HPP
#define LIBEXE_BASE_RELOCATION_HPP

#include <libexe/export.hpp>
#include <cstdint>
#include <string>
#include <vector>

namespace libexe {

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
     *
     * Returns the number of bytes that will be modified at the RVA.
     */
    [[nodiscard]] size_t size_bytes() const {
        switch (type) {
            case relocation_type::ABSOLUTE:
                return 0;  // No operation
            case relocation_type::HIGH:
            case relocation_type::LOW:
                return 2;  // 16-bit
            case relocation_type::HIGHLOW:
            case relocation_type::HIGHADJ:
            case relocation_type::MIPS_JMPADDR:  // Value 5 (also ARM_MOV32, RISCV_HIGH20)
            case relocation_type::THUMB_MOV32:   // Value 7 (also RISCV_LOW12I)
            case relocation_type::RISCV_LOW12S:
            case relocation_type::MIPS_JMPADDR16:
                return 4;  // 32-bit
            case relocation_type::DIR64:
                return 8;  // 64-bit
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
               type == relocation_type::MIPS_JMPADDR ||  // Value 5 (also ARM_MOV32, RISCV_HIGH20)
               type == relocation_type::THUMB_MOV32 ||   // Value 7 (also RISCV_LOW12I)
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
 * Represents a 4KB page of relocations. All relocations in a block
 * are relative to the same page base address.
 */
struct LIBEXE_EXPORT relocation_block {
    uint32_t page_rva;                      // RVA of the 4KB page
    std::vector<relocation_entry> entries;  // Relocations within this page

    /**
     * Get number of relocations in this block
     */
    [[nodiscard]] size_t relocation_count() const {
        return entries.size();
    }

    /**
     * Get number of non-ABSOLUTE relocations
     *
     * ABSOLUTE relocations are padding and don't actually modify anything.
     */
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
 * Contains all base relocations for the executable. These are used by
 * the Windows loader to adjust addresses when ASLR relocates the module.
 * Parsed from the PE base relocation directory (data directory index 5).
 */
struct LIBEXE_EXPORT base_relocation_directory {
    std::vector<relocation_block> blocks;  // All relocation blocks

    /**
     * Get total number of relocation blocks
     */
    [[nodiscard]] size_t block_count() const {
        return blocks.size();
    }

    /**
     * Get total number of relocations (including ABSOLUTE padding)
     */
    [[nodiscard]] size_t total_relocations() const {
        size_t count = 0;
        for (const auto& block : blocks) {
            count += block.relocation_count();
        }
        return count;
    }

    /**
     * Get total number of active relocations (excluding ABSOLUTE padding)
     */
    [[nodiscard]] size_t active_relocations() const {
        size_t count = 0;
        for (const auto& block : blocks) {
            count += block.active_relocation_count();
        }
        return count;
    }

    /**
     * Find block containing specific RVA
     *
     * @param rva RVA to search for
     * @return Pointer to block, or nullptr if not found
     */
    [[nodiscard]] const relocation_block* find_block_for_rva(uint32_t rva) const {
        for (const auto& block : blocks) {
            // Each block covers a 4KB page
            if (rva >= block.page_rva && rva < block.page_rva + 0x1000) {
                return &block;
            }
        }
        return nullptr;
    }

    /**
     * Check if specific RVA has a relocation
     *
     * @param rva RVA to check
     * @return true if there's a relocation at this RVA
     */
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

    /**
     * Get relocation statistics by type
     */
    [[nodiscard]] std::vector<std::pair<relocation_type, size_t>> get_type_counts() const {
        std::vector<std::pair<relocation_type, size_t>> counts;

        // Count each type
        size_t type_counts[11] = {0};  // 0-10 are valid types

        for (const auto& block : blocks) {
            for (const auto& entry : block.entries) {
                uint8_t type_value = static_cast<uint8_t>(entry.type);
                if (type_value <= 10) {
                    type_counts[type_value]++;
                }
            }
        }

        // Build result vector
        for (size_t i = 0; i <= 10; i++) {
            if (type_counts[i] > 0) {
                counts.emplace_back(static_cast<relocation_type>(i), type_counts[i]);
            }
        }

        return counts;
    }
};

} // namespace libexe

#endif // LIBEXE_BASE_RELOCATION_HPP
