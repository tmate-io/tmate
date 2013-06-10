project(libssh-threads C)

set(LIBSSH_THREADS_PUBLIC_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
    CACHE INTERNAL "libssh public include directories"
)

set(LIBSSH_THREADS_PRIVATE_INCLUDE_DIRS
    ${CMAKE_BINARY_DIR}
)

set(LIBSSH_THREADS_SHARED_LIBRARY
  ssh_threads_shared
  CACHE INTERNAL "libssh threads shared library"
)

if (WITH_STATIC_LIB)
  set(LIBSSH_THREADS_STATIC_LIBRARY
    ssh_threads_static
    CACHE INTERNAL "libssh threads static library"
  )
endif (WITH_STATIC_LIB)

set(LIBSSH_THREADS_LINK_LIBRARIES
    ${LIBSSH_SHARED_LIBRARY}
)

set(libssh_threads_SRCS
)

# build and link pthread
if (CMAKE_USE_PTHREADS_INIT)
    set(libssh_threads_SRCS
        ${libssh_threads_SRCS}
        pthread.c
    )

    set(LIBSSH_THREADS_LINK_LIBRARIES
        ${LIBSSH_THREADS_LINK_LIBRARIES}
        ${CMAKE_THREAD_LIBS_INIT}
    )
endif (CMAKE_USE_PTHREADS_INIT)

set(LIBSSH_THREADS_LINK_LIBRARIES
  ${LIBSSH_THREADS_LINK_LIBRARIES}
  CACHE INTERNAL "libssh threads link libraries"
)

include_directories(
  ${LIBSSH_THREADS_PUBLIC_INCLUDE_DIRS}
  ${LIBSSH_THREADS_PRIVATE_INCLUDE_DIRS}
)

add_library(${LIBSSH_THREADS_SHARED_LIBRARY} SHARED ${libssh_threads_SRCS})

target_link_libraries(${LIBSSH_THREADS_SHARED_LIBRARY} ${LIBSSH_THREADS_LINK_LIBRARIES})

set_target_properties(
  ${LIBSSH_THREADS_SHARED_LIBRARY}
    PROPERTIES
      VERSION
        ${LIBRARY_VERSION}
      SOVERSION
        ${LIBRARY_SOVERSION}
      OUTPUT_NAME
        ssh_threads
      DEFINE_SYMBOL
        LIBSSH_EXPORTS
)

if (WITH_VISIBILITY_HIDDEN)
  set_target_properties(${LIBSSH_THREADS_SHARED_LIBRARY} PROPERTIES COMPILE_FLAGS "-fvisibility=hidden")
endif (WITH_VISIBILITY_HIDDEN)

install(
  TARGETS
    ${LIBSSH_THREADS_SHARED_LIBRARY}
  RUNTIME DESTINATION ${BIN_INSTALL_DIR}
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}
  ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
  COMPONENT libraries
)

if (WITH_STATIC_LIB)
  add_library(${LIBSSH_THREADS_STATIC_LIBRARY} STATIC ${libssh_threads_SRCS})

  if (MSVC)
    set(OUTPUT_SUFFIX static)
  else (MSVC)
    set(OUTPUT_SUFFIX )
  endif (MSVC)

  set_target_properties(
    ${LIBSSH_THREADS_STATIC_LIBRARY}
      PROPERTIES
        VERSION
          ${LIBRARY_VERSION}
        SOVERSION
          ${LIBRARY_SOVERSION}
        OUTPUT_NAME
          ssh_threads
        ARCHIVE_OUTPUT_DIRECTORY
          ${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT_SUFFIX}
  )

  if (WIN32)
    set_target_properties(
        ${LIBSSH_THREADS_STATIC_LIBRARY}
            PROPERTIES
                COMPILE_FLAGS
                    "-DLIBSSH_STATIC"
  )
  endif (WIN32)

  install(
    TARGETS
      ${LIBSSH_THREADS_STATIC_LIBRARY}
    DESTINATION
      ${LIB_INSTALL_DIR}/${OUTPUT_SUFFIX}
    COMPONENT
      libraries
  )
endif (WITH_STATIC_LIB)
