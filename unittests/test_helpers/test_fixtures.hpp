// libexe - Modern executable file analysis library
// Copyright (c) 2024
// Shared test fixtures for loading embedded test files

#ifndef LIBEXE_TEST_HELPERS_TEST_FIXTURES_HPP
#define LIBEXE_TEST_HELPERS_TEST_FIXTURES_HPP

#include "test_data.hpp"
#include <cstdint>
#include <span>
#include <vector>

namespace test_fixtures {

// =============================================================================
// Helper to create vector from embedded data
// =============================================================================

inline std::vector<uint8_t> make_vector(const unsigned char* data, size_t len) {
    return std::vector<uint8_t>(data, data + len);
}

inline std::span<const uint8_t> make_span(const unsigned char* data, size_t len) {
    return std::span<const uint8_t>(data, len);
}

// =============================================================================
// PE Format Test Files
// =============================================================================

inline std::vector<uint8_t> load_scheduler() {
    return make_vector(data::scheduler, data::scheduler_len);
}

inline std::span<const uint8_t> scheduler_span() {
    return make_span(data::scheduler, data::scheduler_len);
}

inline std::vector<uint8_t> load_tcmadm64() {
    return make_vector(data::tcmadm64, data::tcmadm64_len);
}

inline std::span<const uint8_t> tcmadm64_span() {
    return make_span(data::tcmadm64, data::tcmadm64_len);
}

inline std::vector<uint8_t> load_tcmdx32() {
    return make_vector(data::tcmdx32, data::tcmdx32_len);
}

inline std::span<const uint8_t> tcmdx32_span() {
    return make_span(data::tcmdx32, data::tcmdx32_len);
}

// =============================================================================
// NE Format Test Files (Windows 16-bit)
// =============================================================================

inline std::vector<uint8_t> load_progman() {
    return make_vector(data::progman, data::progman_len);
}

inline std::span<const uint8_t> progman_span() {
    return make_span(data::progman, data::progman_len);
}

inline std::vector<uint8_t> load_cga40woa_fon() {
    return make_vector(data::cga40woa_fon, data::cga40woa_fon_len);
}

inline std::span<const uint8_t> cga40woa_fon_span() {
    return make_span(data::cga40woa_fon, data::cga40woa_fon_len);
}

inline std::vector<uint8_t> load_sysfont_ne() {
    return make_vector(data::sysfont_ne, data::sysfont_ne_len);
}

inline std::span<const uint8_t> sysfont_ne_span() {
    return make_span(data::sysfont_ne, data::sysfont_ne_len);
}

// =============================================================================
// LE/LX Format Test Files (OS/2 and DOS Extenders)
// =============================================================================

inline std::vector<uint8_t> load_strace_lx() {
    return make_vector(data::strace_lx, data::strace_lx_len);
}

inline std::span<const uint8_t> strace_lx_span() {
    return make_span(data::strace_lx, data::strace_lx_len);
}

inline std::vector<uint8_t> load_cmd_lx() {
    return make_vector(data::cmd_lx, data::cmd_lx_len);
}

inline std::span<const uint8_t> cmd_lx_span() {
    return make_span(data::cmd_lx, data::cmd_lx_len);
}

inline std::vector<uint8_t> load_sevenz_lx() {
    return make_vector(data::sevenz_lx, data::sevenz_lx_len);
}

inline std::span<const uint8_t> sevenz_lx_span() {
    return make_span(data::sevenz_lx, data::sevenz_lx_len);
}

inline std::vector<uint8_t> load_doom_le() {
    return make_vector(data::doom_le, data::doom_le_len);
}

inline std::span<const uint8_t> doom_le_span() {
    return make_span(data::doom_le, data::doom_le_len);
}

inline std::vector<uint8_t> load_makeini_lx() {
    return make_vector(data::makeini_lx, data::makeini_lx_len);
}

inline std::span<const uint8_t> makeini_lx_span() {
    return make_span(data::makeini_lx, data::makeini_lx_len);
}

inline std::vector<uint8_t> load_os2chess_lx() {
    return make_vector(data::os2chess_lx, data::os2chess_lx_len);
}

inline std::span<const uint8_t> os2chess_lx_span() {
    return make_span(data::os2chess_lx, data::os2chess_lx_len);
}

// =============================================================================
// Corkami PE Test Corpus
// =============================================================================

inline std::vector<uint8_t> load_delayimports() {
    return make_vector(data::delayimports, data::delayimports_len);
}

inline std::span<const uint8_t> delayimports_span() {
    return make_span(data::delayimports, data::delayimports_len);
}

inline std::vector<uint8_t> load_imports() {
    return make_vector(data::imports, data::imports_len);
}

inline std::span<const uint8_t> imports_span() {
    return make_span(data::imports, data::imports_len);
}

inline std::vector<uint8_t> load_imports_mixed() {
    return make_vector(data::imports_mixed, data::imports_mixed_len);
}

inline std::span<const uint8_t> imports_mixed_span() {
    return make_span(data::imports_mixed, data::imports_mixed_len);
}

inline std::vector<uint8_t> load_dll() {
    return make_vector(data::dll, data::dll_len);
}

inline std::span<const uint8_t> dll_span() {
    return make_span(data::dll, data::dll_len);
}

inline std::vector<uint8_t> load_dllord() {
    return make_vector(data::dllord, data::dllord_len);
}

inline std::span<const uint8_t> dllord_span() {
    return make_span(data::dllord, data::dllord_len);
}

inline std::vector<uint8_t> load_ibreloc() {
    return make_vector(data::ibreloc, data::ibreloc_len);
}

inline std::span<const uint8_t> ibreloc_span() {
    return make_span(data::ibreloc, data::ibreloc_len);
}

inline std::vector<uint8_t> load_fakerelocs() {
    return make_vector(data::fakerelocs, data::fakerelocs_len);
}

inline std::span<const uint8_t> fakerelocs_span() {
    return make_span(data::fakerelocs, data::fakerelocs_len);
}

inline std::vector<uint8_t> load_tls() {
    return make_vector(data::tls, data::tls_len);
}

inline std::span<const uint8_t> tls_span() {
    return make_span(data::tls, data::tls_len);
}

inline std::vector<uint8_t> load_tls64() {
    return make_vector(data::tls64, data::tls64_len);
}

inline std::span<const uint8_t> tls64_span() {
    return make_span(data::tls64, data::tls64_len);
}

inline std::vector<uint8_t> load_signature() {
    return make_vector(data::signature, data::signature_len);
}

inline std::span<const uint8_t> signature_span() {
    return make_span(data::signature, data::signature_len);
}

// =============================================================================
// Compressed Executable Test Files (Decompressor Tests)
// =============================================================================

// PKLITE compressed files
inline std::vector<uint8_t> load_pklite_112() {
    return make_vector(data::pklite_112, data::pklite_112_len);
}

inline std::span<const uint8_t> pklite_112_span() {
    return make_span(data::pklite_112, data::pklite_112_len);
}

inline std::vector<uint8_t> load_pklite_115() {
    return make_vector(data::pklite_115, data::pklite_115_len);
}

inline std::span<const uint8_t> pklite_115_span() {
    return make_span(data::pklite_115, data::pklite_115_len);
}

inline std::vector<uint8_t> load_pklite_150() {
    return make_vector(data::pklite_150, data::pklite_150_len);
}

inline std::span<const uint8_t> pklite_150_span() {
    return make_span(data::pklite_150, data::pklite_150_len);
}

inline std::vector<uint8_t> load_pklite_E_112() {
    return make_vector(data::pklite_E_112, data::pklite_E_112_len);
}

inline std::span<const uint8_t> pklite_E_112_span() {
    return make_span(data::pklite_E_112, data::pklite_E_112_len);
}

inline std::vector<uint8_t> load_pklite_E_115() {
    return make_vector(data::pklite_E_115, data::pklite_E_115_len);
}

inline std::span<const uint8_t> pklite_E_115_span() {
    return make_span(data::pklite_E_115, data::pklite_E_115_len);
}

// LZEXE compressed files
inline std::vector<uint8_t> load_z90() {
    return make_vector(data::z90, data::z90_len);
}

inline std::span<const uint8_t> z90_span() {
    return make_span(data::z90, data::z90_len);
}

inline std::vector<uint8_t> load_z91() {
    return make_vector(data::z91, data::z91_len);
}

inline std::span<const uint8_t> z91_span() {
    return make_span(data::z91, data::z91_len);
}

inline std::vector<uint8_t> load_z91_E() {
    return make_vector(data::z91_E, data::z91_E_len);
}

inline std::span<const uint8_t> z91_E_span() {
    return make_span(data::z91_E, data::z91_E_len);
}

// Knowledge Dynamics compressed files
inline std::vector<uint8_t> load_knowledge_dynamics_DOT() {
    return make_vector(data::knowledge_dynamics_DOT, data::knowledge_dynamics_DOT_len);
}

inline std::vector<uint8_t> load_knowledge_dynamics_LEX() {
    return make_vector(data::knowledge_dynamics_LEX, data::knowledge_dynamics_LEX_len);
}

inline std::vector<uint8_t> load_knowledge_dynamics_TNT() {
    return make_vector(data::knowledge_dynamics_TNT, data::knowledge_dynamics_TNT_len);
}

// EXEPACK compressed files
inline std::vector<uint8_t> load_exepack_hello() {
    return make_vector(data::exepack_hello, data::exepack_hello_len);
}

inline std::vector<uint8_t> load_exepack_masm400() {
    return make_vector(data::exepack_masm400, data::exepack_masm400_len);
}

inline std::vector<uint8_t> load_exepack_masm500() {
    return make_vector(data::exepack_masm500, data::exepack_masm500_len);
}

inline std::vector<uint8_t> load_exepack_masm510() {
    return make_vector(data::exepack_masm510, data::exepack_masm510_len);
}

} // namespace test_fixtures

#endif // LIBEXE_TEST_HELPERS_TEST_FIXTURES_HPP
