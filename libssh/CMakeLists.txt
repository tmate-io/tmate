project(libssh C)

# Required cmake version
cmake_minimum_required(VERSION 2.6.0)

# global needed variables
set(APPLICATION_NAME ${PROJECT_NAME})

set(APPLICATION_VERSION_MAJOR "0")
set(APPLICATION_VERSION_MINOR "7")
set(APPLICATION_VERSION_PATCH "0")

set(APPLICATION_VERSION "${APPLICATION_VERSION_MAJOR}.${APPLICATION_VERSION_MINOR}.${APPLICATION_VERSION_PATCH}")

# SOVERSION scheme: CURRENT.AGE.REVISION
#   If there was an incompatible interface change:
#     Increment CURRENT. Set AGE and REVISION to 0
#   If there was a compatible interface change:
#     Increment AGE. Set REVISION to 0
#   If the source code was changed, but there were no interface changes:
#     Increment REVISION.
set(LIBRARY_VERSION "4.3.0")
set(LIBRARY_SOVERSION "4")

# where to look first for cmake modules, before ${CMAKE_ROOT}/Modules/ is checked
set(CMAKE_MODULE_PATH
  ${CMAKE_SOURCE_DIR}/cmake/Modules
)

# add definitions
include(DefineCMakeDefaults)
include(DefinePlatformDefaults)
include(DefineCompilerFlags)
include(DefineInstallationPaths)
include(DefineOptions.cmake)
include(CPackConfig.cmake)

# disallow in-source build
include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out of source build. Please create a separate build directory and run 'cmake /path/to/${PROJECT_NAME} [options]' there.")

# search for libraries
if (WITH_ZLIB)
    find_package(ZLIB REQUIRED)
endif (WITH_ZLIB)

if (WITH_GCRYPT)
  find_package(GCrypt 1.5.0 REQUIRED)
  if (NOT GCRYPT_FOUND)
    message(FATAL_ERROR "Could not find GCrypt")
  endif (NOT GCRYPT_FOUND)
else (WITH_GCRYPT)
  find_package(OpenSSL)
  if (NOT OPENSSL_FOUND)
    find_package(GCrypt)
    if (NOT GCRYPT_FOUND)
      message(FATAL_ERROR "Could not find OpenSSL or GCrypt")
    endif (NOT GCRYPT_FOUND)
  endif (NOT OPENSSL_FOUND)
endif(WITH_GCRYPT)

# Find out if we have threading available
set(CMAKE_THREAD_PREFER_PTHREADS ON)
find_package(Threads)

if (WITH_GSSAPI)
    find_package(GSSAPI)
endif (WITH_GSSAPI)

if (WITH_NACL)
    find_package(NaCl)
    if (NOT NACL_FOUND)
        set(WITH_NACL OFF)
    endif (NOT NACL_FOUND)
endif (WITH_NACL)

# config.h checks
include(ConfigureChecks.cmake)
configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# check subdirectories
add_subdirectory(doc)
add_subdirectory(include)
add_subdirectory(src)

# pkg-config file
configure_file(libssh.pc.cmake ${CMAKE_CURRENT_BINARY_DIR}/libssh.pc)
configure_file(libssh_threads.pc.cmake ${CMAKE_CURRENT_BINARY_DIR}/libssh_threads.pc)
install(
  FILES
    ${CMAKE_CURRENT_BINARY_DIR}/libssh.pc
    ${CMAKE_CURRENT_BINARY_DIR}/libssh_threads.pc
  DESTINATION
    ${LIB_INSTALL_DIR}/pkgconfig
  COMPONENT
    pkgconfig
)

# cmake config files
set(LIBSSH_LIBRARY_NAME @CMAKE_SHARED_LIBRARY_PREFIX@ssh@CMAKE_SHARED_LIBRARY_SUFFIX@)
set(LIBSSH_THREADS_LIBRARY_NAME @CMAKE_SHARED_LIBRARY_PREFIX@ssh@CMAKE_SHARED_LIBRARY_SUFFIX@)

configure_file(${PROJECT_NAME}-config.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake @ONLY)
configure_file(${PROJECT_NAME}-config-version.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake @ONLY)
install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake
    DESTINATION
        ${CMAKE_INSTALL_DIR}/${PROJECT_NAME}
    COMPONENT
        devel
)


# in tree build settings
configure_file(libssh-build-tree-settings.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/libssh-build-tree-settings.cmake @ONLY)

if (WITH_EXAMPLES)
    add_subdirectory(examples)
endif (WITH_EXAMPLES)

if (WITH_TESTING)
  find_package(CMocka REQUIRED)
  include(AddCMockaTest)
  add_subdirectory(tests)
endif (WITH_TESTING)


message(STATUS "********************************************")
message(STATUS "********** ${PROJECT_NAME} build options : **********")

message(STATUS "zlib support: ${WITH_ZLIB}")
message(STATUS "libgcrypt support: ${WITH_GCRYPT}")
message(STATUS "libnacl support: ${WITH_NACL}")
message(STATUS "SSH-1 support: ${WITH_SSH1}")
message(STATUS "SFTP support: ${WITH_SFTP}")
message(STATUS "Server support : ${WITH_SERVER}")
message(STATUS "GSSAPI support : ${WITH_GSSAPI}")
message(STATUS "Pcap debugging support : ${WITH_PCAP}")
message(STATUS "With static library: ${WITH_STATIC_LIB}")
message(STATUS "Unit testing: ${WITH_TESTING}")
message(STATUS "Client code Unit testing: ${WITH_CLIENT_TESTING}")
if (WITH_INTERNAL_DOC)
    message(STATUS "Internal documentation generation")
else (WITH_INTERNAL_DOC)
    message(STATUS "Public API documentation generation")
endif (WITH_INTERNAL_DOC)
message(STATUS "Benchmarks: ${WITH_BENCHMARKS}")
message(STATUS "********************************************")

