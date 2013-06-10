include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckTypeSize)
include(CheckCXXSourceCompiles)
include(TestBigEndian)

set(PACKAGE ${APPLICATION_NAME})
set(VERSION ${APPLICATION_VERSION})
set(DATADIR ${DATA_INSTALL_DIR})
set(LIBDIR ${LIB_INSTALL_DIR})
set(PLUGINDIR "${PLUGIN_INSTALL_DIR}-${LIBRARY_SOVERSION}")
set(SYSCONFDIR ${SYSCONF_INSTALL_DIR})

set(BINARYDIR ${CMAKE_BINARY_DIR})
set(SOURCEDIR ${CMAKE_SOURCE_DIR})

function(COMPILER_DUMPVERSION _OUTPUT_VERSION)
    # Remove whitespaces from the argument.
    # This is needed for CC="ccache gcc" cmake ..
    string(REPLACE " " "" _C_COMPILER_ARG "${CMAKE_C_COMPILER_ARG1}")

    execute_process(
        COMMAND
            ${CMAKE_C_COMPILER} ${_C_COMPILER_ARG} -dumpversion
        OUTPUT_VARIABLE _COMPILER_VERSION
    )

    string(REGEX REPLACE "([0-9])\\.([0-9])(\\.[0-9])?" "\\1\\2"
           _COMPILER_VERSION "${_COMPILER_VERSION}")

    set(${_OUTPUT_VERSION} ${_COMPILER_VERSION} PARENT_SCOPE)
endfunction()

if(CMAKE_COMPILER_IS_GNUCC AND NOT MINGW AND NOT OS2)
    compiler_dumpversion(GNUCC_VERSION)
    if (NOT GNUCC_VERSION EQUAL 34)
        set(CMAKE_REQUIRED_FLAGS "-fvisibility=hidden")
        check_c_source_compiles(
"void __attribute__((visibility(\"default\"))) test() {}
int main(void){ return 0; }
" WITH_VISIBILITY_HIDDEN)
        set(CMAKE_REQUIRED_FLAGS "")
    endif (NOT GNUCC_VERSION EQUAL 34)
endif(CMAKE_COMPILER_IS_GNUCC AND NOT MINGW AND NOT OS2)

# HEADER FILES
check_include_file(argp.h HAVE_ARGP_H)
check_include_file(pty.h HAVE_PTY_H)
check_include_file(termios.h HAVE_TERMIOS_H)

if (WIN32)
  check_include_files("winsock2.h;ws2tcpip.h;wspiapi.h" HAVE_WSPIAPI_H)
  if (NOT HAVE_WSPIAPI_H)
    message(STATUS "WARNING: Without wspiapi.h, this build will only work on Windows XP and newer versions")
  endif (NOT HAVE_WSPIAPI_H)
  check_include_files("winsock2.h;ws2tcpip.h" HAVE_WS2TCPIP_H)
  if (HAVE_WSPIAPI_H OR HAVE_WS2TCPIP_H)
    set(HAVE_GETADDRINFO TRUE)
    set(HAVE_GETHOSTBYNAME TRUE)
  endif (HAVE_WSPIAPI_H OR HAVE_WS2TCPIP_H)

  set(HAVE_SELECT TRUE)
endif (WIN32)

set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIRS})
check_include_file(openssl/aes.h HAVE_OPENSSL_AES_H)

set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIRS})
check_include_file(openssl/blowfish.h HAVE_OPENSSL_BLOWFISH_H)

set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIRS})
check_include_file(openssl/des.h HAVE_OPENSSL_DES_H)

set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIRS})
check_include_file(openssl/ecdh.h HAVE_OPENSSL_ECDH_H)

set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIRS})
check_include_file(openssl/ec.h HAVE_OPENSSL_EC_H)

set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIRS})
check_include_file(openssl/ecdsa.h HAVE_OPENSSL_ECDSA_H)

if (CMAKE_HAVE_PTHREAD_H)
  set(HAVE_PTHREAD_H 1)
endif (CMAKE_HAVE_PTHREAD_H)

if (NOT WITH_GCRYPT)
    if (HAVE_OPENSSL_EC_H AND HAVE_OPENSSL_ECDSA_H)
        set(HAVE_OPENSSL_ECC 1)
    endif (HAVE_OPENSSL_EC_H AND HAVE_OPENSSL_ECDSA_H)

    if (HAVE_OPENSSL_ECC)
        set(HAVE_ECC 1)
    endif (HAVE_OPENSSL_ECC)
endif (NOT WITH_GCRYPT)

# FUNCTIONS

check_function_exists(strncpy HAVE_STRNCPY)
check_function_exists(vsnprintf HAVE_VSNPRINTF)
check_function_exists(snprintf HAVE_SNPRINTF)

if (WIN32)
    check_function_exists(_vsnprintf_s HAVE__VSNPRINTF_S)
    check_function_exists(_vsnprintf HAVE__VSNPRINTF)
    check_function_exists(_snprintf HAVE__SNPRINTF)
    check_function_exists(_snprintf_s HAVE__SNPRINTF_S)
endif (WIN32)

if (UNIX)
    if (NOT LINUX)
        # libsocket (Solaris)
        check_library_exists(socket getaddrinfo "" HAVE_LIBSOCKET)
        if (HAVE_LIBSOCKET)
          set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} socket)
        endif (HAVE_LIBSOCKET)

        # libnsl/inet_pton (Solaris)
        check_library_exists(nsl inet_pton "" HAVE_LIBNSL)
        if (HAVE_LIBNSL)
            set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} nsl)
        endif (HAVE_LIBNSL)

        # librt
        check_library_exists(rt nanosleep "" HAVE_LIBRT)
    endif (NOT LINUX)

    check_library_exists(rt clock_gettime "" HAVE_CLOCK_GETTIME)
    if (HAVE_LIBRT OR HAVE_CLOCK_GETTIME)
        set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} rt)
    endif (HAVE_LIBRT OR HAVE_CLOCK_GETTIME)

    check_library_exists(util forkpty "" HAVE_LIBUTIL)
    check_function_exists(getaddrinfo HAVE_GETADDRINFO)
    check_function_exists(poll HAVE_POLL)
    check_function_exists(select HAVE_SELECT)
    check_function_exists(cfmakeraw HAVE_CFMAKERAW)
    check_function_exists(ntohll HAVE_NTOHLL)
    check_function_exists(htonll HAVE_HTONLL)
    check_function_exists(strtoull HAVE_STRTOULL)
    check_function_exists(__strtoull HAVE___STRTOULL)
endif (UNIX)

set(LIBSSH_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} CACHE INTERNAL "libssh required system libraries")

# LIBRARIES
if (OPENSSL_FOUND)
  set(HAVE_LIBCRYPTO 1)
endif (OPENSSL_FOUND)

if (GCRYPT_FOUND)
    set(HAVE_LIBGCRYPT 1)
    if (GCRYPT_VERSION VERSION_GREATER "1.4.6")
        #set(HAVE_GCRYPT_ECC 1)
        #set(HAVE_ECC 1)
    endif (GCRYPT_VERSION VERSION_GREATER "1.4.6")
endif (GCRYPT_FOUND)

if (CMAKE_HAVE_THREADS_LIBRARY)
    if (CMAKE_USE_PTHREADS_INIT)
        set(HAVE_PTHREAD 1)
    endif (CMAKE_USE_PTHREADS_INIT)
endif (CMAKE_HAVE_THREADS_LIBRARY)

# OPTIONS
if (WITH_DEBUG_CRYPTO)
  set(DEBUG_CRYPTO 1)
endif (WITH_DEBUG_CRYPTO)

if (WITH_DEBUG_CALLTRACE)
  set(DEBUG_CALLTRACE 1)
endif (WITH_DEBUG_CALLTRACE)

# ENDIAN
if (NOT WIN32)
    test_big_endian(WORDS_BIGENDIAN)
endif (NOT WIN32)
