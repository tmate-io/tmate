# - Check whether the C compiler supports a given flag in the
# context of a stack checking compiler option.

# CHECK_C_COMPILER_FLAG_SSP(FLAG VARIABLE)
#
#  FLAG - the compiler flag
#  VARIABLE - variable to store the result
#
#  This actually calls check_c_source_compiles.
#  See help for CheckCSourceCompiles for a listing of variables
#  that can modify the build.

# Copyright (c) 2006, Alexander Neundorf, <neundorf@kde.org>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.


include(CheckCSourceCompiles)

function(CHECK_C_COMPILER_FLAG_SSP _FLAG _RESULT)
   set(SAFE_CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS}")
   set(CMAKE_REQUIRED_DEFINITIONS "${_FLAG}")
   check_c_source_compiles("int main(int argc, char **argv) { char buffer[256]; return buffer[argc]=0;}" ${_RESULT})
   set(CMAKE_REQUIRED_DEFINITIONS "${SAFE_CMAKE_REQUIRED_DEFINITIONS}")
endfunction(CHECK_C_COMPILER_FLAG_SSP)
