# - Try to find Argp
# Once done this will define
#
#  ARGP_FOUND - system has Argp
#  ARGP_INCLUDE_DIRS - the Argp include directory
#  ARGP_LIBRARIES - Link these to use Argp
#  ARGP_DEFINITIONS - Compiler switches required for using Argp
#
#  Copyright (c) 2010 Andreas Schneider <asn@cryptomilk.org>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (ARGP_LIBRARIES AND ARGP_INCLUDE_DIRS)
  # in cache already
  set(ARGP_FOUND TRUE)
else (ARGP_LIBRARIES AND ARGP_INCLUDE_DIRS)

  find_path(ARGP_INCLUDE_DIR
    NAMES
      argp.h
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
  )

  find_library(ARGP_LIBRARY
    NAMES
      argp
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
  )

  set(ARGP_INCLUDE_DIRS
    ${ARGP_INCLUDE_DIR}
  )

  if (ARGP_LIBRARY)
    set(ARGP_LIBRARIES
        ${ARGP_LIBRARIES}
        ${ARGP_LIBRARY}
    )
  endif (ARGP_LIBRARY)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Argp DEFAULT_MSG ARGP_LIBRARIES ARGP_INCLUDE_DIRS)

  # show the ARGP_INCLUDE_DIRS and ARGP_LIBRARIES variables only in the advanced view
  mark_as_advanced(ARGP_INCLUDE_DIRS ARGP_LIBRARIES)

endif (ARGP_LIBRARIES AND ARGP_INCLUDE_DIRS)

