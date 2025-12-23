// libexe - Modern executable file analysis library
// Copyright (c) 2024
// Data source abstraction for memory-mapped and owned buffer access

#ifndef LIBEXE_CORE_DATA_SOURCE_HPP
#define LIBEXE_CORE_DATA_SOURCE_HPP

#include <cstdint>
#include <cstddef>
#include <memory>
#include <span>
#include <vector>
#include <filesystem>

#include <libexe/export.hpp>

// Disable MSVC warning C4251: 'member': class 'std::...' needs to have dll-interface
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

namespace libexe {
    /**
     * Abstract data source providing unified access to file data
     * regardless of whether it's memory-mapped or stored in a vector.
     */
    class LIBEXE_EXPORT data_source {
        public:
            virtual ~data_source() = default;

            [[nodiscard]] virtual const uint8_t* data() const noexcept = 0;
            [[nodiscard]] virtual size_t size() const noexcept = 0;

            [[nodiscard]] const uint8_t* begin() const noexcept;
            [[nodiscard]] const uint8_t* end() const noexcept;

            [[nodiscard]] bool empty() const noexcept;

            [[nodiscard]] uint8_t operator[](size_t index) const noexcept;

            [[nodiscard]] std::span <const uint8_t> span() const noexcept;

            [[nodiscard]] std::span <const uint8_t> subspan(size_t offset, size_t count) const;

            // Non-copyable
            data_source(const data_source&) = delete;
            data_source& operator=(const data_source&) = delete;

        protected:
            data_source() = default;
            data_source(data_source&&) = default;
            data_source& operator=(data_source&&) = default;
    };

    /**
     * Memory-mapped file data source using mio library.
     * Zero-copy access to file contents.
     */
    class mmap_data_source final : public data_source {
        public:
            ~mmap_data_source() override;
            explicit mmap_data_source(const std::filesystem::path& path);
            [[nodiscard]] const uint8_t* data() const noexcept override;
            [[nodiscard]] size_t size() const noexcept override;
        private:
            struct impl;
            std::unique_ptr<impl> m_pimpl;

    };

    /**
     * Owned vector data source.
     * Used for from_memory() path where we need to copy external data.
     */
    class vector_data_source final : public data_source {
        public:
            explicit vector_data_source(std::span <const uint8_t> source);

            explicit vector_data_source(std::vector <uint8_t>&& source);

            [[nodiscard]] const uint8_t* data() const noexcept override;

            [[nodiscard]] size_t size() const noexcept override;

        private:
            std::vector <uint8_t> buffer_;
    };

    /**
     * Non-owning view data source.
     * Used when caller guarantees data lifetime (e.g., for testing or
     * when data is already managed elsewhere).
     */
    class view_data_source final : public data_source {
        public:
            explicit view_data_source(std::span <const uint8_t> source)
                : data_(source.data()), size_(source.size()) {
            }

            [[nodiscard]] const uint8_t* data() const noexcept override {
                return data_;
            }

            [[nodiscard]] size_t size() const noexcept override {
                return size_;
            }

        private:
            const uint8_t* data_;
            size_t size_;
    };
} // namespace libexe::internal

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // LIBEXE_CORE_DATA_SOURCE_HPP
