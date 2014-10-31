/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2011 by Aris Adamantiadis
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef ECDH_H_
#define ECDH_H_

#include "config.h"

#ifdef HAVE_LIBCRYPTO
#ifdef HAVE_OPENSSL_ECDH_H

#ifdef HAVE_ECC
#define HAVE_ECDH 1
#endif

#endif /* HAVE_OPENSSL_ECDH_H */
#endif /* HAVE_LIBCRYPTO */

int ssh_client_ecdh_init(ssh_session session);
int ssh_client_ecdh_reply(ssh_session session, ssh_buffer packet);

#ifdef WITH_SERVER
int ssh_server_ecdh_init(ssh_session session, ssh_buffer packet);
#endif /* WITH_SERVER */

#endif /* ECDH_H_ */
