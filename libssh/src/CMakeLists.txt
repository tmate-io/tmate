project(libssh-library C)

set(LIBSSH_PUBLIC_INCLUDE_DIRS
  ${CMAKE_SOURCE_DIR}/include
  CACHE INTERNAL "libssh public include directories"
)

set(LIBSSH_PRIVATE_INCLUDE_DIRS
  ${CMAKE_BINARY_DIR}
  ${OPENSSL_INCLUDE_DIRS}
)

set(LIBSSH_LINK_LIBRARIES
  ${LIBSSH_REQUIRED_LIBRARIES}
)

if (WIN32)
  set(LIBSSH_LINK_LIBRARIES
    ${LIBSSH_LINK_LIBRARIES}
    ws2_32
  )
endif (WIN32)

if (HAVE_LIBSOCKET)
  set(LIBSSH_LINK_LIBRARIES
    ${LIBSSH_LINK_LIBRARIES}
    socket
  )
endif (HAVE_LIBSOCKET)

if (OPENSSL_CRYPTO_LIBRARIES)
  set(LIBSSH_PRIVATE_INCLUDE_DIRS
    ${LIBSSH_PRIVATE_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
  )

  set(LIBSSH_LINK_LIBRARIES
    ${LIBSSH_LINK_LIBRARIES}
    ${OPENSSL_CRYPTO_LIBRARIES}
  )
endif (OPENSSL_CRYPTO_LIBRARIES)

if (GCRYPT_LIBRARY)
  set(LIBSSH_PRIVATE_INCLUDE_DIRS
    ${LIBSSH_PRIVATE_INCLUDE_DIRS}
    ${GCRYPT_INCLUDE_DIR}
  )

  set(LIBSSH_LINK_LIBRARIES
    ${LIBSSH_LINK_LIBRARIES}
    ${GCRYPT_LIBRARY}
  )
endif (GCRYPT_LIBRARY)

if (WITH_ZLIB)
  set(LIBSSH_PRIVATE_INCLUDE_DIRS
    ${LIBSSH_PRIVATE_INCLUDE_DIRS}
    ${ZLIB_INCLUDE_DIRS}
  )

  set(LIBSSH_LINK_LIBRARIES
    ${LIBSSH_LINK_LIBRARIES}
    ${ZLIB_LIBRARY}
  )
endif (WITH_ZLIB)

if (WITH_GSSAPI AND GSSAPI_FOUND)
  set(LIBSSH_PRIVATE_INCLUDE_DIRS
    ${LIBSSH_PRIVATE_INCLUDE_DIRS}
    ${GSSAPI_INCLUDE_DIR}
  )

  set(LIBSSH_LINK_LIBRARIES
    ${LIBSSH_LINK_LIBRARIES}
    ${GSSAPI_LIBRARIES}
  )
endif (WITH_GSSAPI AND GSSAPI_FOUND)

if (WITH_NACL AND NACL_FOUND)
  set(LIBSSH_PRIVATE_INCLUDE_DIRS
    ${LIBSSH_PRIVATE_INCLUDE_DIRS}
    ${NACL_INCLUDE_DIR}
  )

  set(LIBSSH_LINK_LIBRARIES
    ${LIBSSH_LINK_LIBRARIES}
    ${NACL_LIBRARY}
  )
endif (WITH_NACL AND NACL_FOUND)

set(LIBSSH_LINK_LIBRARIES
  ${LIBSSH_LINK_LIBRARIES}
  CACHE INTERNAL "libssh link libraries"
)

set(LIBSSH_SHARED_LIBRARY
  ssh_shared
  CACHE INTERNAL "libssh shared library"
)

if (WITH_STATIC_LIB)
  set(LIBSSH_STATIC_LIBRARY
    ssh_static
    CACHE INTERNAL "libssh static library"
  )
endif (WITH_STATIC_LIB)

set(libssh_SRCS
  agent.c
  auth.c
  base64.c
  bignum.c
  buffer.c
  callbacks.c
  channels.c
  client.c
  config.c
  connect.c
  curve25519.c
  dh.c
  ecdh.c
  ed25519.c
  error.c
  fe25519.c
  ge25519.c
  getpass.c
  init.c
  kex.c
  known_hosts.c
  legacy.c
  libcrypto.c
  log.c
  match.c
  messages.c
  misc.c
  options.c
  packet.c
  packet_cb.c
  packet_crypt.c
  pcap.c
  pki.c
  pki_ed25519.c
  poll.c
  session.c
  sc25519.c
  scp.c
  socket.c
  string.c
  threads.c
  wrapper.c
)

if (WITH_GCRYPT)
    set(libssh_SRCS
        ${libssh_SRCS}
        libgcrypt.c
        gcrypt_missing.c
        pki_gcrypt.c
       )
else (WITH_GCRYPT)
    set(libssh_SRCS
        ${libssh_SRCS}
        pki_crypto.c
       )
endif (WITH_GCRYPT)

if (WITH_SFTP)
  set(libssh_SRCS
    ${libssh_SRCS}
    sftp.c
  )

  if (WITH_SERVER)
    set(libssh_SRCS
      ${libssh_SRCS}
      sftpserver.c
    )
  endif (WITH_SERVER)
endif (WITH_SFTP)

if (WITH_SSH1)
  set(libssh_SRCS
    ${libssh_SRCS}
    auth1.c
    channels1.c
    crc32.c
    kex1.c
    packet1.c
  )
endif (WITH_SSH1)

if (WITH_SERVER)
  set(libssh_SRCS
    ${libssh_SRCS}
    server.c
    bind.c
  )
endif (WITH_SERVER)

if (WITH_ZLIB)
  set(libssh_SRCS
    ${libssh_SRCS}
    gzip.c
  )
endif(WITH_ZLIB)

if (WITH_GSSAPI AND GSSAPI_FOUND)
  set(libssh_SRCS
    ${libssh_SRCS}
    gssapi.c
  )
endif (WITH_GSSAPI AND GSSAPI_FOUND)

if (NOT WITH_NACL)
  set(libssh_SRCS
    ${libssh_SRCS}
    curve25519_ref.c
  )
endif (NOT WITH_NACL)

include_directories(
  ${LIBSSH_PUBLIC_INCLUDE_DIRS}
  ${LIBSSH_PRIVATE_INCLUDE_DIRS}
)

add_library(${LIBSSH_SHARED_LIBRARY} SHARED ${libssh_SRCS})

target_link_libraries(${LIBSSH_SHARED_LIBRARY} ${LIBSSH_LINK_LIBRARIES})

set_target_properties(
  ${LIBSSH_SHARED_LIBRARY}
    PROPERTIES
      VERSION
        ${LIBRARY_VERSION}
      SOVERSION
        ${LIBRARY_SOVERSION}
      OUTPUT_NAME
        ssh
      DEFINE_SYMBOL
        LIBSSH_EXPORTS
)

if (WITH_VISIBILITY_HIDDEN)
  set_target_properties(${LIBSSH_SHARED_LIBRARY} PROPERTIES COMPILE_FLAGS "-fvisibility=hidden")
endif (WITH_VISIBILITY_HIDDEN)


install(
  TARGETS
    ${LIBSSH_SHARED_LIBRARY}
  RUNTIME DESTINATION ${BIN_INSTALL_DIR}
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}
  ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
  COMPONENT libraries
)

if (WITH_STATIC_LIB)
  add_library(${LIBSSH_STATIC_LIBRARY} STATIC ${libssh_SRCS})

  if (MSVC)
    set(OUTPUT_SUFFIX static)
  else (MSVC)
    set(OUTPUT_SUFFIX )
  endif (MSVC)
  set_target_properties(
    ${LIBSSH_STATIC_LIBRARY}
      PROPERTIES
        VERSION
          ${LIBRARY_VERSION}
        SOVERSION
          ${LIBRARY_SOVERSION}
        OUTPUT_NAME
          ssh
        ARCHIVE_OUTPUT_DIRECTORY
          ${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT_SUFFIX}
  )

  if (WIN32)
    set_target_properties(
      ${LIBSSH_STATIC_LIBRARY}
        PROPERTIES
          COMPILE_FLAGS
            "-DLIBSSH_STATIC"
    )
  endif (WIN32)

  install(
    TARGETS
      ${LIBSSH_STATIC_LIBRARY}
    DESTINATION
      ${LIB_INSTALL_DIR}/${OUTPUT_SUFFIX}
    COMPONENT
      libraries
  )
endif (WITH_STATIC_LIB)

if (Threads_FOUND)
    add_subdirectory(threads)
endif (Threads_FOUND)
