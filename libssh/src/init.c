/*
 * init.c - initialization and finalization of the library
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"
#include "libssh/priv.h"
#include "libssh/socket.h"
#include "libssh/dh.h"
#include "libssh/poll.h"
#include "libssh/threads.h"

#ifdef _WIN32
#include <winsock2.h>
#endif

/**
 * @defgroup libssh The libssh API
 *
 * The libssh library is implementing the SSH protocols and some of its
 * extensions. This group of functions is mostly used to implment a SSH client.
 * Some function are needed to implement a SSH server too.
 *
 * @{
 */

/**
 * @brief Initialize global cryptographic data structures.
 *
 * This function should only be called once, at the beginning of the program, in
 * the main thread. It may be omitted if your program is not multithreaded.
 *
 * @returns             0 on success, -1 if an error occured.
 */
int ssh_init(void) {
  if(ssh_threads_init())
    return -1;
  if(ssh_crypto_init())
    return -1;
  if(ssh_socket_init())
    return -1;
  return 0;
}


/**
 * @brief Finalize and cleanup all libssh and cryptographic data structures.
 *
 * This function should only be called once, at the end of the program!
 *
 * @returns             0 on succes, -1 if an error occured.
 *
   @returns 0 otherwise
 */
int ssh_finalize(void) {
  ssh_crypto_finalize();
  ssh_socket_cleanup();
  /* It is important to finalize threading after CRYPTO because
   * it still depends on it */
  ssh_threads_finalize();

  return 0;
}

/** @} */

/* vim: set ts=4 sw=4 et cindent: */
