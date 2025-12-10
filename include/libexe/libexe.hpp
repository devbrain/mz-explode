// libexe - Modern executable file analysis library
// Master include - includes the entire public API

#ifndef LIBEXE_HPP
#define LIBEXE_HPP

// Core utilities
#include <libexe/core/enum_bitmask.hpp>
#include <libexe/core/executable_file.hpp>

// Format classes
#include <libexe/formats/mz_file.hpp>
#include <libexe/formats/ne_file.hpp>
#include <libexe/formats/pe_file.hpp>
#include <libexe/formats/executable_factory.hpp>

// NE types
#include <libexe/ne/types.hpp>

// PE types and sections
#include <libexe/pe/types.hpp>
#include <libexe/pe/section.hpp>
#include <libexe/pe/directories.hpp>

// Resources
#include <libexe/resources/resource.hpp>
#include <libexe/resources/ne_resource_directory.hpp>
#include <libexe/resources/pe_resource_directory.hpp>
#include <libexe/resources/parsers/all.hpp>

// Decompressors
#include <libexe/decompressors/all.hpp>

#endif // LIBEXE_HPP
