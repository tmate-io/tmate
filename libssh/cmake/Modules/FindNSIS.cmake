# - Try to find NSIS
# Once done this will define
#
#  NSIS_ROOT_DIR - Set this variable to the root installation of ZLIB
#
# Read-Only variables:
#  NSIS_FOUND - system has NSIS
#  NSIS_MAKE - NSIS creator executable
#
#=============================================================================
#  Copyright (c) 2010-2011 Andreas Schneider <asn@cryptomilk.org>
#
#  Distributed under the OSI-approved BSD License (the "License");
#  see accompanying file Copyright.txt for details.
#
#  This software is distributed WITHOUT ANY WARRANTY; without even the
#  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the License for more information.
#=============================================================================
#

set(_NSIS_ROOT_PATHS
    C:/NSIS/Bin
    "$ENV{PROGRAMFILES}/NSIS"
)

find_program(NSIS_MAKE
    NAMES
        makensis
    PATHS
        ${NSIS_ROOT_PATH}
        ${NSIS_ROOT_PATH}/Bin
        ${_NSIS_ROOT_PATHS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(NSIS DEFAULT_MSG NSIS_MAKE)

mark_as_advanced(NSIS_MAKE)
