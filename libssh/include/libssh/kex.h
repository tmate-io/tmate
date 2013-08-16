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

#ifndef KEX_H_
#define KEX_H_

#include "libssh/priv.h"
#include "libssh/callbacks.h"

#define SSH_KEX_METHODS 10

struct ssh_kex_struct {
    unsigned char cookie[16];
    char *methods[SSH_KEX_METHODS];
};

SSH_PACKET_CALLBACK(ssh_packet_kexinit);
#ifdef WITH_SSH1
SSH_PACKET_CALLBACK(ssh_packet_publickey1);
#endif

int ssh_send_kex(ssh_session session, int server_kex);
void ssh_list_kex(struct ssh_kex_struct *kex);
int set_client_kex(ssh_session session);
int ssh_kex_select_methods(ssh_session session);
int verify_existing_algo(int algo, const char *name);
char **space_tokenize(const char *chain);
int ssh_get_kex1(ssh_session session);
char *ssh_find_matching(const char *in_d, const char *what_d);
const char *ssh_kex_get_supported_method(uint32_t algo);
const char *ssh_kex_get_description(uint32_t algo);

#endif /* KEX_H_ */
