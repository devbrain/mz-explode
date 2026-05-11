// libexe - Modern executable file analysis library
// Copyright (c) 2024

/**
 * @file windows_macro_undef.hpp
 * @brief Undefine Windows preprocessor macros that collide with libexe enums.
 *
 * Windows headers (winuser.h and friends) #define RT_BITMAP, RT_MENU,
 * RT_FONT, etc. as `MAKEINTRESOURCE(N)`. When a translation unit includes
 * <windows.h> (often transitively through Win32 platform headers) before
 * any libexe header that declares an `RT_*` enum value, those macros
 * expand inside our enum declarations and break the parse on MSVC.
 *
 * Including this header at the top of any libexe header that defines
 * `RT_*` enumerators undefines the colliding Windows macros for the
 * remainder of the translation unit. This is safe for our consumers
 * because libexe is an executable-format analyzer that doesn't need the
 * Windows runtime's RT_* values — and Windows code that does need them
 * never goes through these libexe headers.
 *
 * If you genuinely need both libexe::resource_type::RT_BITMAP and the
 * Windows MAKEINTRESOURCE(2), include this header AFTER any code that
 * relied on the Windows macros, and refer to the macro via its expanded
 * form (e.g. MAKEINTRESOURCEW(2)) below this point.
 */

#ifndef LIBEXE_DETAIL_WINDOWS_MACRO_UNDEF_HPP
#define LIBEXE_DETAIL_WINDOWS_MACRO_UNDEF_HPP

#ifdef RT_CURSOR
#  undef RT_CURSOR
#endif
#ifdef RT_BITMAP
#  undef RT_BITMAP
#endif
#ifdef RT_ICON
#  undef RT_ICON
#endif
#ifdef RT_MENU
#  undef RT_MENU
#endif
#ifdef RT_DIALOG
#  undef RT_DIALOG
#endif
#ifdef RT_STRING
#  undef RT_STRING
#endif
#ifdef RT_FONTDIR
#  undef RT_FONTDIR
#endif
#ifdef RT_FONT
#  undef RT_FONT
#endif
#ifdef RT_ACCELERATOR
#  undef RT_ACCELERATOR
#endif
#ifdef RT_RCDATA
#  undef RT_RCDATA
#endif
#ifdef RT_MESSAGETABLE
#  undef RT_MESSAGETABLE
#endif
#ifdef RT_GROUP_CURSOR
#  undef RT_GROUP_CURSOR
#endif
#ifdef RT_GROUP_ICON
#  undef RT_GROUP_ICON
#endif
#ifdef RT_VERSION
#  undef RT_VERSION
#endif
#ifdef RT_DLGINCLUDE
#  undef RT_DLGINCLUDE
#endif
#ifdef RT_PLUGPLAY
#  undef RT_PLUGPLAY
#endif
#ifdef RT_VXD
#  undef RT_VXD
#endif
#ifdef RT_ANICURSOR
#  undef RT_ANICURSOR
#endif
#ifdef RT_ANIICON
#  undef RT_ANIICON
#endif
#ifdef RT_HTML
#  undef RT_HTML
#endif
#ifdef RT_MANIFEST
#  undef RT_MANIFEST
#endif

// Other Windows macros that collide with libexe enumerators. Most
// come from objbase.h / wtypes.h / SAL annotations and are bare,
// generically-named tokens that any vendor would reach for.
#ifdef PURE
#  undef PURE         // COM headers: #define PURE = 0
#endif
#ifdef OPTIONAL
#  undef OPTIONAL     // SAL annotation
#endif
#ifdef IN
#  undef IN           // SAL annotation
#endif
#ifdef OUT
#  undef OUT          // SAL annotation
#endif

// `ERROR` from winuser.h was problematic in diagnostic.hpp; it was
// renamed to PARSE_ERROR rather than undef'd because the enumerator
// name was the same as the Windows constant. Add here only if you
// can't / won't rename.

#endif  // LIBEXE_DETAIL_WINDOWS_MACRO_UNDEF_HPP
