/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis
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

#ifndef DH_H_
#define DH_H_

#include "config.h"

#include "libssh/crypto.h"

int dh_generate_e(ssh_session session);
int dh_generate_f(ssh_session session);
int dh_generate_x(ssh_session session);
int dh_generate_y(ssh_session session);

int ssh_crypto_init(void);
void ssh_crypto_finalize(void);

ssh_string dh_get_e(ssh_session session);
ssh_string dh_get_f(ssh_session session);
int dh_import_f(ssh_session session,ssh_string f_string);
int dh_import_e(ssh_session session, ssh_string e_string);
void dh_import_pubkey(ssh_session session,ssh_string pubkey_string);
int dh_build_k(ssh_session session);
int ssh_client_dh_init(ssh_session session);
int ssh_client_dh_reply(ssh_session session, ssh_buffer packet);

int make_sessionid(ssh_session session);
/* add data for the final cookie */
int hashbufin_add_cookie(ssh_session session, unsigned char *cookie);
int hashbufout_add_cookie(ssh_session session);
int generate_session_keys(ssh_session session);

#endif /* DH_H_ */
