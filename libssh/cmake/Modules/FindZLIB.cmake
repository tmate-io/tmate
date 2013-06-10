# - Try to find ZLIB
# Once done this will define
#
#  ZLIB_ROOT_DIR - Set this variable to the root installation of ZLIB
#
# Read-Only variables:
#  ZLIB_FOUND - system has ZLIB
#  ZLIB_INCLUDE_DIRS - the ZLIB include directory
#  ZLIB_LIBRARIES - Link these to use ZLIB
#
#  ZLIB_VERSION_STRING - The version of zlib found (x.y.z)
#  ZLIB_VERSION_MAJOR  - The major version of zlib
#  ZLIB_VERSION_MINOR  - The minor version of zlib
#  ZLIB_VERSION_PATCH  - The patch version of zlib
#  ZLIB_VERSION_TWEAK  - The tweak version of zlib
#
# The following variable are provided for backward compatibility
#
#  ZLIB_MAJOR_VERSION  - The major version of zlib
#  ZLIB_MINOR_VERSION  - The minor version of zlib
#  ZLIB_PATCH_VERSION  - The patch version of zlib
#
#=============================================================================
#  Copyright (c) 2001-2009 Kitware, Inc.
#  Copyright (c) 2011      Andreas Schneider <asn@cryptomilk.org>
#
#  Distributed under the OSI-approved BSD License (the "License");
#  see accompanying file Copyright.txt for details.
#
#  This software is distributed WITHOUT ANY WARRANTY; without even the
#  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the License for more information.
#=============================================================================
#

if (ZLIB_LIBRARIES AND ZLIB_INCLUDE_DIRS)
  # in cache already
  set(ZLIB_FOUND TRUE)
else (ZLIB_LIBRARIES AND ZLIB_INCLUDE_DIRS)

    set(_ZLIB_ROOT_HINTS
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\GnuWin32\\Zlib;InstallPath]/include"
    )

    set(_ZLIB_ROOT_PATHS
        "$ENV{PROGRAMFILES}/zlib"
    )

    find_path(ZLIB_ROOT_DIR
        NAMES
            include/zlib.h
        HINTS
            ${_ZLIB_ROOT_HINTS}
        PATHS
            ${_ZLIB_ROOT_PATHS}
    )
    mark_as_advanced(ZLIB_ROOT_DIR)

    # check for header file
    find_path(ZLIB_INCLUDE_DIR
        NAMES
            zlib.h
        PATHS
            /usr/local/include
            /opt/local/include
            /sw/include
            /usr/lib/sfw/include
            ${ZLIB_ROOT_DIR}/include
    )
    mark_as_advanced(ZLIB_INCLUDE_DIR)

    # check version number
    if (ZLIB_INCLUDE_DIR AND EXISTS "${ZLIB_INCLUDE_DIR}/zlib.h")
        file(STRINGS "${ZLIB_INCLUDE_DIR}/zlib.h" ZLIB_H REGEX "^#define ZLIB_VERSION \"[^\"]*\"$")

        string(REGEX REPLACE "^.*ZLIB_VERSION \"([0-9]+).*$" "\\1" ZLIB_VERSION_MAJOR "${ZLIB_H}")
        string(REGEX REPLACE "^.*ZLIB_VERSION \"[0-9]+\\.([0-9]+).*$" "\\1" ZLIB_VERSION_MINOR  "${ZLIB_H}")
        string(REGEX REPLACE "^.*ZLIB_VERSION \"[0-9]+\\.[0-9]+\\.([0-9]+).*$" "\\1" ZLIB_VERSION_PATCH "${ZLIB_H}")

        set(ZLIB_VERSION_STRING "${ZLIB_VERSION_MAJOR}.${ZLIB_VERSION_MINOR}.${ZLIB_VERSION_PATCH}")

        # only append a TWEAK version if it exists:
        set(ZLIB_VERSION_TWEAK "")
        if ("${ZLIB_H}" MATCHES "^.*ZLIB_VERSION \"[0-9]+\\.[0-9]+\\.[0-9]+\\.([0-9]+).*$")
            set(ZLIB_VERSION_TWEAK "${CMAKE_MATCH_1}")
            set(ZLIB_VERSION_STRING "${ZLIB_VERSION_STRING}.${ZLIB_VERSION_TWEAK}")
        endif ("${ZLIB_H}" MATCHES "^.*ZLIB_VERSION \"[0-9]+\\.[0-9]+\\.[0-9]+\\.([0-9]+).*$")

        set(ZLIB_MAJOR_VERSION "${ZLIB_VERSION_MAJOR}")
        set(ZLIB_MINOR_VERSION "${ZLIB_VERSION_MINOR}")
        set(ZLIB_PATCH_VERSION "${ZLIB_VERSION_PATCH}")
    endif (ZLIB_INCLUDE_DIR AND EXISTS "${ZLIB_INCLUDE_DIR}/zlib.h")

    find_library(ZLIB_LIBRARY
        NAMES
            z
            zdll
            zlib
            zlib1
            zlibd
        PATHS
            /usr/local/lib
            /opt/local/lib
            /sw/lib
            /usr/sfw/lib/64
            /usr/sfw/lib
            ${ZLIB_ROOT_DIR}/lib
    )
    mark_as_advanced(ZLIB_LIBRARY)

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(ZLIB DEFAULT_MSG ZLIB_INCLUDE_DIR ZLIB_LIBRARY)
    #find_package_handle_standard_args(ZLIB REQUIRED_VARS ZLIB_INCLUDE_DIR ZLIB_LIBRARY
    #                                       VERSION_VAR ZLIB_VERSION_STRING)

    if (ZLIB_FOUND)
        set(ZLIB_INCLUDE_DIRS ${ZLIB_INCLUDE_DIR})
        set(ZLIB_LIBRARIES ${ZLIB_LIBRARY})
    endif (ZLIB_FOUND)
endif (ZLIB_LIBRARIES AND ZLIB_INCLUDE_DIRS)
