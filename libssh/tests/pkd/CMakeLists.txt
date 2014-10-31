project(pkd C)

if (WITH_SERVER AND UNIX AND NOT WIN32)

include_directories(
  ${LIBSSH_PUBLIC_INCLUDE_DIRS}
  ${CMOCKA_INCLUDE_DIR}
  ${OPENSSL_INCLUDE_DIRS}
  ${GCRYPT_INCLUDE_DIRS}
  ${ZLIB_INCLUDE_DIRS}
  ${CMAKE_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}
)

set(pkd_hello_src
  pkd_daemon.c
  pkd_hello.c
  pkd_keyutil.c
  pkd_util.c
)

set(pkd_libs
    ${CMOCKA_LIBRARY}
    ${LIBSSH_STATIC_LIBRARY}
    ${LIBSSH_LINK_LIBRARIES}
    ${LIBSSH_THREADS_STATIC_LIBRARY}
    ${LIBSSH_THREADS_LINK_LIBRARIES}
    ${ARGP_LIBRARIES}
)

add_executable(pkd_hello ${pkd_hello_src})
target_link_libraries(pkd_hello ${pkd_libs})

endif (WITH_SERVER AND UNIX AND NOT WIN32)
