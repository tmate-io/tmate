/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
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

/* Since libssh.h includes legacy.h, it's important that libssh.h is included
 * first. we don't define LEGACY_H now because we want it to be defined when
 * included from libssh.h
 * All function calls declared in this header are deprecated and meant to be
 * removed in future.
 */

#ifndef LEGACY_H_
#define LEGACY_H_

typedef struct ssh_private_key_struct* ssh_private_key;
typedef struct ssh_public_key_struct* ssh_public_key;

LIBSSH_API int ssh_auth_list(ssh_session session);
LIBSSH_API int ssh_userauth_offer_pubkey(ssh_session session, const char *username, int type, ssh_string publickey);
LIBSSH_API int ssh_userauth_pubkey(ssh_session session, const char *username, ssh_string publickey, ssh_private_key privatekey);
#ifndef _WIN32
LIBSSH_API int ssh_userauth_agent_pubkey(ssh_session session, const char *username,
    ssh_public_key publickey);
#endif
LIBSSH_API int ssh_userauth_autopubkey(ssh_session session, const char *passphrase);
LIBSSH_API int ssh_userauth_privatekey_file(ssh_session session, const char *username,
    const char *filename, const char *passphrase);

LIBSSH_API void buffer_free(ssh_buffer buffer);
LIBSSH_API void *buffer_get(ssh_buffer buffer);
LIBSSH_API uint32_t buffer_get_len(ssh_buffer buffer);
LIBSSH_API ssh_buffer buffer_new(void);

LIBSSH_API ssh_channel channel_accept_x11(ssh_channel channel, int timeout_ms);
LIBSSH_API int channel_change_pty_size(ssh_channel channel,int cols,int rows);
LIBSSH_API ssh_channel channel_forward_accept(ssh_session session, int timeout_ms);
LIBSSH_API int channel_close(ssh_channel channel);
LIBSSH_API int channel_forward_cancel(ssh_session session, const char *address, int port);
LIBSSH_API int channel_forward_listen(ssh_session session, const char *address, int port, int *bound_port);
LIBSSH_API void channel_free(ssh_channel channel);
LIBSSH_API int channel_get_exit_status(ssh_channel channel);
LIBSSH_API ssh_session channel_get_session(ssh_channel channel);
LIBSSH_API int channel_is_closed(ssh_channel channel);
LIBSSH_API int channel_is_eof(ssh_channel channel);
LIBSSH_API int channel_is_open(ssh_channel channel);
LIBSSH_API ssh_channel channel_new(ssh_session session);
LIBSSH_API int channel_open_forward(ssh_channel channel, const char *remotehost,
    int remoteport, const char *sourcehost, int localport);
LIBSSH_API int channel_open_session(ssh_channel channel);
LIBSSH_API int channel_poll(ssh_channel channel, int is_stderr);
LIBSSH_API int channel_read(ssh_channel channel, void *dest, uint32_t count, int is_stderr);

LIBSSH_API int channel_read_buffer(ssh_channel channel, ssh_buffer buffer, uint32_t count,
    int is_stderr);

LIBSSH_API int channel_read_nonblocking(ssh_channel channel, void *dest, uint32_t count,
    int is_stderr);
LIBSSH_API int channel_request_env(ssh_channel channel, const char *name, const char *value);
LIBSSH_API int channel_request_exec(ssh_channel channel, const char *cmd);
LIBSSH_API int channel_request_pty(ssh_channel channel);
LIBSSH_API int channel_request_pty_size(ssh_channel channel, const char *term,
    int cols, int rows);
LIBSSH_API int channel_request_shell(ssh_channel channel);
LIBSSH_API int channel_request_send_signal(ssh_channel channel, const char *signum);
LIBSSH_API int channel_request_sftp(ssh_channel channel);
LIBSSH_API int channel_request_subsystem(ssh_channel channel, const char *subsystem);
LIBSSH_API int channel_request_x11(ssh_channel channel, int single_connection, const char *protocol,
    const char *cookie, int screen_number);
LIBSSH_API int channel_send_eof(ssh_channel channel);
LIBSSH_API int channel_select(ssh_channel *readchans, ssh_channel *writechans, ssh_channel *exceptchans, struct
        timeval * timeout);
LIBSSH_API void channel_set_blocking(ssh_channel channel, int blocking);
LIBSSH_API int channel_write(ssh_channel channel, const void *data, uint32_t len);

LIBSSH_API void privatekey_free(ssh_private_key prv);
LIBSSH_API ssh_private_key privatekey_from_file(ssh_session session, const char *filename,
    int type, const char *passphrase);
LIBSSH_API void publickey_free(ssh_public_key key);
LIBSSH_API int ssh_publickey_to_file(ssh_session session, const char *file,
    ssh_string pubkey, int type);
LIBSSH_API ssh_string publickey_from_file(ssh_session session, const char *filename,
    int *type);
LIBSSH_API ssh_public_key publickey_from_privatekey(ssh_private_key prv);
LIBSSH_API ssh_string publickey_to_string(ssh_public_key key);
LIBSSH_API int ssh_try_publickey_from_file(ssh_session session, const char *keyfile,
    ssh_string *publickey, int *type);
LIBSSH_API enum ssh_keytypes_e ssh_privatekey_type(ssh_private_key privatekey);

LIBSSH_API ssh_string ssh_get_pubkey(ssh_session session);

LIBSSH_API ssh_message ssh_message_retrieve(ssh_session session, uint32_t packettype);
LIBSSH_API ssh_public_key ssh_message_auth_publickey(ssh_message msg);

LIBSSH_API void string_burn(ssh_string str);
LIBSSH_API ssh_string string_copy(ssh_string str);
LIBSSH_API void *string_data(ssh_string str);
LIBSSH_API int string_fill(ssh_string str, const void *data, size_t len);
LIBSSH_API void string_free(ssh_string str);
LIBSSH_API ssh_string string_from_char(const char *what);
LIBSSH_API size_t string_len(ssh_string str);
LIBSSH_API ssh_string string_new(size_t size);
LIBSSH_API char *string_to_char(ssh_string str);

#endif /* LEGACY_H_ */
