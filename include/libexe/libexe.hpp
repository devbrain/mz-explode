// libexe - Modern executable file analysis library
// Master include - includes the entire public API

#ifndef LIBEXE_HPP
#define LIBEXE_HPP

// Core utilities
#include <libexe/core/diagnostic.hpp>
#include <libexe/core/diagnostic_collector.hpp>
#include <libexe/core/entropy.hpp>
#include <libexe/core/enum_bitmask.hpp>
#include <libexe/core/executable_file.hpp>

// Format classes
#include <libexe/formats/le_file.hpp>
#include <libexe/formats/mz_file.hpp>
#include <libexe/formats/ne_file.hpp>
#include <libexe/formats/pe_file.hpp>

#include <libexe/formats/executable_factory.hpp>
// LE types
#include <libexe/le/types.hpp>

// NE types
#include <libexe/ne/segment_parser.hpp>
#include <libexe/ne/types.hpp>

// PE types and sections
#include <libexe/pe/authenticode.hpp>
#include <libexe/pe/directories.hpp>
#include <libexe/pe/overlay.hpp>
#include <libexe/pe/rich_header.hpp>
#include <libexe/pe/section.hpp>
#include <libexe/pe/section_parser.hpp>
#include <libexe/pe/types.hpp>

// Resources
#include <libexe/resources/ne_resource_directory.hpp>
#include <libexe/resources/parsers/all.hpp>
#include <libexe/resources/pe_resource_directory.hpp>
#include <libexe/resources/resource.hpp>

// Decompressors
#include <libexe/decompressors/all.hpp>

#endif // LIBEXE_HPP
