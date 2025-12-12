//
// Created by igor on 12/12/2025.
//
#include <libexe/core/data_source.hpp>
#include <stdexcept>
#include <mio/mmap.hpp>

namespace libexe {
    const uint8_t* data_source::begin() const noexcept { return data(); }

    const uint8_t* data_source::end() const noexcept { return data() + size(); }

    bool data_source::empty() const noexcept { return size() == 0; }

    uint8_t data_source::operator[](size_t index) const noexcept {
        return data()[index];
    }

    std::span<const uint8_t> data_source::span() const noexcept {
        return {data(), size()};
    }

    std::span<const uint8_t> data_source::subspan(size_t offset, size_t count) const {
        if (offset > size()) {
            return {};
        }
        if (offset + count > size()) {
            count = size() - offset;
        }
        return {data() + offset, count};
    }

    struct mmap_data_source::impl {
        explicit impl(const std::filesystem::path& path) {
            std::error_code ec;
            mmap_ = mio::make_mmap_source(path.string(), ec);
            if (ec) {
                throw std::runtime_error("Cannot memory-map file: " + path.string() + " (" + ec.message() + ")");
            }
        }
        mio::mmap_source mmap_;
    };

    mmap_data_source::~mmap_data_source() = default;

    mmap_data_source::mmap_data_source(const std::filesystem::path& path)
        : m_pimpl(std::make_unique<impl>(path)) {

    }

    const uint8_t* mmap_data_source::data() const noexcept {
        const auto& mem = m_pimpl->mmap_;
        return reinterpret_cast <const uint8_t*>(mem.data());
    }

    size_t mmap_data_source::size() const noexcept {
        return m_pimpl->mmap_.size();
    }

    vector_data_source::vector_data_source(std::span<const uint8_t> source): buffer_(source.begin(), source.end()) {
    }

    vector_data_source::vector_data_source(std::vector<uint8_t>&& source): buffer_(std::move(source)) {
    }

    const uint8_t* vector_data_source::data() const noexcept {
        return buffer_.data();
    }

    size_t vector_data_source::size() const noexcept {
        return buffer_.size();
    }
}
