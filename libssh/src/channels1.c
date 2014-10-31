/*
 * channels1.c - Support for SSH-1 type channels
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
 * Copyright (c) 2009      by Andreas Schneider <asn@cryptomilk.org>
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifndef _WIN32
#include <arpa/inet.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "libssh/priv.h"
#include "libssh/ssh1.h"
#include "libssh/buffer.h"
#include "libssh/packet.h"
#include "libssh/channels.h"
#include "libssh/session.h"
#include "libssh/misc.h"

#ifdef WITH_SSH1

/*
 * This is a big hack. In fact, SSH1 doesn't make a clever use of channels.
 * The whole packets concerning shells are sent outside of a channel.
 * Thus, an inside limitation of this behavior is that you can't only
 * request one shell.
 * The question is still how they managed to embed two "channel" into one
 * protocol.
 */

int channel_open_session1(ssh_channel chan) {
  ssh_session session;

  if (chan == NULL) {
    return -1;
  }
  session = chan->session;

  /*
   * We guess we are requesting an *exec* channel. It can only have one exec
   * channel. So we abort with an error if we need more than one.
   */
  if (session->exec_channel_opened) {
    ssh_set_error(session, SSH_REQUEST_DENIED,
        "SSH1 supports only one execution channel. "
        "One has already been opened");
    return -1;
  }
  session->exec_channel_opened = 1;
  chan->request_state = SSH_CHANNEL_REQ_STATE_ACCEPTED;
  chan->state = SSH_CHANNEL_STATE_OPEN;
  chan->local_maxpacket = 32000;
  chan->local_window = 64000;
  SSH_LOG(SSH_LOG_PACKET, "Opened a SSH1 channel session");

  return 0;
}

/*  10 SSH_CMSG_REQUEST_PTY
 *
 *  string       TERM environment variable value (e.g. vt100)
 *  32-bit int   terminal height, rows (e.g., 24)
 *  32-bit int   terminal width, columns (e.g., 80)
 *  32-bit int   terminal width, pixels (0 if no graphics) (e.g., 480)
 *  32-bit int   terminal height, pixels (0 if no graphics) (e.g., 640)
 *  n bytes      tty modes encoded in binary
 *  Some day, someone should have a look at that nasty tty encoded. It's
 *  much simplier under ssh2. I just hope the defaults values are ok ...
 */

int channel_request_pty_size1(ssh_channel channel, const char *terminal, int col,
    int row) {
  ssh_session session;
  ssh_string str = NULL;

  if (channel == NULL) {
    return SSH_ERROR;
  }
  session = channel->session;

  if(channel->request_state != SSH_CHANNEL_REQ_STATE_NONE){
    ssh_set_error(session,SSH_REQUEST_DENIED,"Wrong request state");
    return SSH_ERROR;
  }
  str = ssh_string_from_char(terminal);
  if (str == NULL) {
    ssh_set_error_oom(session);
    return -1;
  }

  if (buffer_add_u8(session->out_buffer, SSH_CMSG_REQUEST_PTY) < 0 ||
      buffer_add_ssh_string(session->out_buffer, str) < 0) {
    ssh_string_free(str);
    return -1;
  }
  ssh_string_free(str);

  if (buffer_add_u32(session->out_buffer, ntohl(row)) < 0 ||
      buffer_add_u32(session->out_buffer, ntohl(col)) < 0 ||
      buffer_add_u32(session->out_buffer, 0) < 0 || /* x */
      buffer_add_u32(session->out_buffer, 0) < 0 || /* y */
      buffer_add_u8(session->out_buffer, 0) < 0) { /* tty things */
    return -1;
  }

  SSH_LOG(SSH_LOG_FUNCTIONS, "Opening a ssh1 pty");
  channel->request_state = SSH_CHANNEL_REQ_STATE_PENDING;
  if (packet_send(session) == SSH_ERROR) {
    return -1;
  }

  while (channel->request_state == SSH_CHANNEL_REQ_STATE_PENDING) {
      ssh_handle_packets(session, SSH_TIMEOUT_INFINITE);
  }

  switch(channel->request_state){
    case SSH_CHANNEL_REQ_STATE_ERROR:
    case SSH_CHANNEL_REQ_STATE_PENDING:
    case SSH_CHANNEL_REQ_STATE_NONE:
      channel->request_state=SSH_CHANNEL_REQ_STATE_NONE;
      return SSH_ERROR;
    case SSH_CHANNEL_REQ_STATE_ACCEPTED:
      channel->request_state=SSH_CHANNEL_REQ_STATE_NONE;
      SSH_LOG(SSH_LOG_RARE, "PTY: Success");
      return SSH_OK;
    case SSH_CHANNEL_REQ_STATE_DENIED:
      channel->request_state=SSH_CHANNEL_REQ_STATE_NONE;
      ssh_set_error(session, SSH_REQUEST_DENIED,
          "Server denied PTY allocation");
      SSH_LOG(SSH_LOG_RARE, "PTY: denied\n");
      return SSH_ERROR;
  }
  // Not reached
  return SSH_ERROR;
}

int channel_change_pty_size1(ssh_channel channel, int cols, int rows) {
  ssh_session session;

  if (channel == NULL) {
    return SSH_ERROR;
  }
  session = channel->session;

  if(channel->request_state != SSH_CHANNEL_REQ_STATE_NONE){
    ssh_set_error(session,SSH_REQUEST_DENIED,"Wrong request state");
    return SSH_ERROR;
  }
  if (buffer_add_u8(session->out_buffer, SSH_CMSG_WINDOW_SIZE) < 0 ||
      buffer_add_u32(session->out_buffer, ntohl(rows)) < 0 ||
      buffer_add_u32(session->out_buffer, ntohl(cols)) < 0 ||
      buffer_add_u32(session->out_buffer, 0) < 0 ||
      buffer_add_u32(session->out_buffer, 0) < 0) {
    return SSH_ERROR;
  }
  channel->request_state=SSH_CHANNEL_REQ_STATE_PENDING;
  if (packet_send(session) == SSH_ERROR) {
    return SSH_ERROR;
  }

  SSH_LOG(SSH_LOG_PROTOCOL, "Change pty size send");
  while(channel->request_state==SSH_CHANNEL_REQ_STATE_PENDING){
    ssh_handle_packets(session, SSH_TIMEOUT_INFINITE);
  }
  switch(channel->request_state){
    case SSH_CHANNEL_REQ_STATE_ERROR:
    case SSH_CHANNEL_REQ_STATE_PENDING:
    case SSH_CHANNEL_REQ_STATE_NONE:
      channel->request_state=SSH_CHANNEL_REQ_STATE_NONE;
      return SSH_ERROR;
    case SSH_CHANNEL_REQ_STATE_ACCEPTED:
      channel->request_state=SSH_CHANNEL_REQ_STATE_NONE;
      SSH_LOG(SSH_LOG_PROTOCOL, "pty size changed");
      return SSH_OK;
    case SSH_CHANNEL_REQ_STATE_DENIED:
      channel->request_state=SSH_CHANNEL_REQ_STATE_NONE;
      SSH_LOG(SSH_LOG_RARE, "pty size change denied");
      ssh_set_error(session, SSH_REQUEST_DENIED, "pty size change denied");
      return SSH_ERROR;
  }
  // Not reached
  return SSH_ERROR;

}

int channel_request_shell1(ssh_channel channel) {
  ssh_session session;

  if (channel == NULL) {
    return -1;
  }
  session = channel->session;

  if (buffer_add_u8(session->out_buffer,SSH_CMSG_EXEC_SHELL) < 0) {
    return -1;
  }

  if (packet_send(session) == SSH_ERROR) {
    return -1;
  }

  SSH_LOG(SSH_LOG_RARE, "Launched a shell");

  return 0;
}

int channel_request_exec1(ssh_channel channel, const char *cmd) {
  ssh_session session;
  ssh_string command = NULL;

  if (channel == NULL) {
    return -1;
  }
  session = channel->session;

  command = ssh_string_from_char(cmd);
  if (command == NULL) {
    return -1;
  }

  if (buffer_add_u8(session->out_buffer, SSH_CMSG_EXEC_CMD) < 0 ||
      buffer_add_ssh_string(session->out_buffer, command) < 0) {
    ssh_string_free(command);
    return -1;
  }
  ssh_string_free(command);

  if(packet_send(session) == SSH_ERROR) {
    return -1;
  }

  SSH_LOG(SSH_LOG_RARE, "Executing %s ...", cmd);

  return 0;
}

SSH_PACKET_CALLBACK(ssh_packet_data1){
    ssh_channel channel = ssh_get_channel1(session);
    ssh_string str = NULL;
    int is_stderr=(type==SSH_SMSG_STDOUT_DATA ? 0 : 1);
    (void)user;

    if (channel == NULL) {
      return SSH_PACKET_NOT_USED;
    }

    str = buffer_get_ssh_string(packet);
    if (str == NULL) {
      SSH_LOG(SSH_LOG_FUNCTIONS, "Invalid data packet !\n");
      return SSH_PACKET_USED;
    }

    SSH_LOG(SSH_LOG_PROTOCOL,
        "Adding %" PRIdS " bytes data in %d",
        ssh_string_len(str), is_stderr);

    if (channel_default_bufferize(channel, ssh_string_data(str), ssh_string_len(str),
          is_stderr) < 0) {
      ssh_string_free(str);
      return SSH_PACKET_USED;
    }
    ssh_string_free(str);

    return SSH_PACKET_USED;
}

SSH_PACKET_CALLBACK(ssh_packet_close1){
  ssh_channel channel = ssh_get_channel1(session);
  uint32_t status;
  int rc;

  (void)type;
  (void)user;

  if (channel == NULL) {
    return SSH_PACKET_NOT_USED;
  }

  buffer_get_u32(packet, &status);
  /*
   * It's much more than a channel closing. spec says it's the last
   * message sent by server (strange)
   */

  /* actually status is lost somewhere */
  channel->state = SSH_CHANNEL_STATE_CLOSED;
  channel->remote_eof = 1;

  rc = buffer_add_u8(session->out_buffer, SSH_CMSG_EXIT_CONFIRMATION);
  if (rc < 0) {
    return SSH_PACKET_NOT_USED;
  }
  packet_send(session);

  return SSH_PACKET_USED;
}

SSH_PACKET_CALLBACK(ssh_packet_exist_status1){
  ssh_channel channel = ssh_get_channel1(session);
  uint32_t status;
  (void)type;
  (void)user;

  if (channel == NULL) {
    return SSH_PACKET_NOT_USED;
  }

  buffer_get_u32(packet, &status);
  channel->state = SSH_CHANNEL_STATE_CLOSED;
  channel->remote_eof = 1;
  channel->exit_status = ntohl(status);

  return SSH_PACKET_USED;
}


int channel_write1(ssh_channel channel, const void *data, int len) {
  ssh_session session;
  int origlen = len;
  int effectivelen;
  const unsigned char *ptr=data;

  if (channel == NULL) {
    return -1;
  }
  session = channel->session;

  while (len > 0) {
    if (buffer_add_u8(session->out_buffer, SSH_CMSG_STDIN_DATA) < 0) {
      return -1;
    }

    effectivelen = len > 32000 ? 32000 : len;

    if (buffer_add_u32(session->out_buffer, htonl(effectivelen)) < 0 ||
        ssh_buffer_add_data(session->out_buffer, ptr, effectivelen) < 0) {
      return -1;
    }

    ptr += effectivelen;
    len -= effectivelen;

    if (packet_send(session) == SSH_ERROR) {
      return -1;
    }
    ssh_handle_packets(session, SSH_TIMEOUT_NONBLOCKING);
    if (channel->counter != NULL) {
        channel->counter->out_bytes += effectivelen;
    }
  }
  if (ssh_blocking_flush(session,SSH_TIMEOUT_USER) == SSH_ERROR)
      return -1;
  return origlen;
}

ssh_channel ssh_get_channel1(ssh_session session){
  struct ssh_iterator *it;

  if (session == NULL) {
    return NULL;
  }

  /* With SSH1, the channel is always the first one */
  if(session->channels != NULL){
    it = ssh_list_get_iterator(session->channels);
    if(it)
      return ssh_iterator_value(ssh_channel, it);
  }
  return NULL;
}
#endif /* WITH_SSH1 */
/* vim: set ts=2 sw=2 et cindent: */
