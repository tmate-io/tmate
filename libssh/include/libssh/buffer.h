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

#ifndef BUFFER_H_
#define BUFFER_H_

#include "libssh/libssh.h"
/*
 * Describes a buffer state
 * [XXXXXXXXXXXXDATA PAYLOAD       XXXXXXXXXXXXXXXXXXXXXXXX]
 * ^            ^                  ^                       ^]
 * \_data points\_pos points here  \_used points here |    /
 *   here                                          Allocated
 */
struct ssh_buffer_struct {
    char *data;
    uint32_t used;
    uint32_t allocated;
    uint32_t pos;
};

LIBSSH_API void ssh_buffer_free(ssh_buffer buffer);
LIBSSH_API void *ssh_buffer_get_begin(ssh_buffer buffer);
LIBSSH_API uint32_t ssh_buffer_get_len(ssh_buffer buffer);
LIBSSH_API ssh_buffer ssh_buffer_new(void);
int buffer_add_ssh_string(ssh_buffer buffer, ssh_string string);
int buffer_add_u8(ssh_buffer buffer, uint8_t data);
int buffer_add_u16(ssh_buffer buffer, uint16_t data);
int buffer_add_u32(ssh_buffer buffer, uint32_t data);
int buffer_add_u64(ssh_buffer buffer, uint64_t data);
int buffer_add_data(ssh_buffer buffer, const void *data, uint32_t len);
int buffer_prepend_data(ssh_buffer buffer, const void *data, uint32_t len);
int buffer_add_buffer(ssh_buffer buffer, ssh_buffer source);
int buffer_reinit(ssh_buffer buffer);

/* buffer_get_rest returns a pointer to the current position into the buffer */
void *buffer_get_rest(ssh_buffer buffer);
/* buffer_get_rest_len returns the number of bytes which can be read */
uint32_t buffer_get_rest_len(ssh_buffer buffer);

/* buffer_read_*() returns the number of bytes read, except for ssh strings */
int buffer_get_u8(ssh_buffer buffer, uint8_t *data);
int buffer_get_u32(ssh_buffer buffer, uint32_t *data);
int buffer_get_u64(ssh_buffer buffer, uint64_t *data);

uint32_t buffer_get_data(ssh_buffer buffer, void *data, uint32_t requestedlen);
/* buffer_get_ssh_string() is an exception. if the String read is too large or invalid, it will answer NULL. */
ssh_string buffer_get_ssh_string(ssh_buffer buffer);
/* gets a string out of a SSH-1 mpint */
ssh_string buffer_get_mpint(ssh_buffer buffer);
/* buffer_pass_bytes acts as if len bytes have been read (used for padding) */
uint32_t buffer_pass_bytes_end(ssh_buffer buffer, uint32_t len);
uint32_t buffer_pass_bytes(ssh_buffer buffer, uint32_t len);

#endif /* BUFFER_H_ */
