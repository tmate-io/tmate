/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
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

#include <stdlib.h>

#ifndef _WIN32
#include <netinet/in.h>
#endif /* _WIN32 */

#include "libssh/priv.h"
#include "libssh/ssh1.h"
#include "libssh/crc32.h"
#include "libssh/packet.h"
#include "libssh/session.h"
#include "libssh/buffer.h"
#include "libssh/socket.h"
#include "libssh/kex.h"
#include "libssh/crypto.h"

#ifdef WITH_SSH1

static ssh_packet_callback default_packet_handlers1[]= {
  NULL,                           //SSH_MSG_NONE                        0
  ssh_packet_disconnect1,         //SSH_MSG_DISCONNECT                  1
  ssh_packet_publickey1,          //SSH_SMSG_PUBLIC_KEY                 2
  NULL,                           //SSH_CMSG_SESSION_KEY                3
  NULL,                           //SSH_CMSG_USER                       4
  NULL,                           //SSH_CMSG_AUTH_RHOSTS                5
  NULL,                           //SSH_CMSG_AUTH_RSA                   6
  NULL,                           //SSH_SMSG_AUTH_RSA_CHALLENGE         7
  NULL,                           //SSH_CMSG_AUTH_RSA_RESPONSE          8
  NULL,                           //SSH_CMSG_AUTH_PASSWORD              9
  NULL,                           //SSH_CMSG_REQUEST_PTY                10
  NULL,                           //SSH_CMSG_WINDOW_SIZE                11
  NULL,                           //SSH_CMSG_EXEC_SHELL                 12
  NULL,                           //SSH_CMSG_EXEC_CMD                   13
  ssh_packet_smsg_success1,       //SSH_SMSG_SUCCESS                    14
  ssh_packet_smsg_failure1,       //SSH_SMSG_FAILURE                    15
  NULL,                           //SSH_CMSG_STDIN_DATA                 16
  ssh_packet_data1,               //SSH_SMSG_STDOUT_DATA                17
  ssh_packet_data1,               //SSH_SMSG_STDERR_DATA                18
  NULL,                           //SSH_CMSG_EOF                        19
  ssh_packet_exist_status1,       //SSH_SMSG_EXITSTATUS                 20
  NULL,                           //SSH_MSG_CHANNEL_OPEN_CONFIRMATION   21
  NULL,                           //SSH_MSG_CHANNEL_OPEN_FAILURE        22
  NULL,                           //SSH_MSG_CHANNEL_DATA                23
  ssh_packet_close1,              //SSH_MSG_CHANNEL_CLOSE               24
  NULL,                           //SSH_MSG_CHANNEL_CLOSE_CONFIRMATION  25
  NULL,                           //SSH_CMSG_X11_REQUEST_FORWARDING     26
  NULL,                           //SSH_SMSG_X11_OPEN                   27
  NULL,                           //SSH_CMSG_PORT_FORWARD_REQUEST       28
  NULL,                           //SSH_MSG_PORT_OPEN                   29
  NULL,                           //SSH_CMSG_AGENT_REQUEST_FORWARDING   30
  NULL,                           //SSH_SMSG_AGENT_OPEN                 31
  ssh_packet_ignore_callback,     //SSH_MSG_IGNORE                      32
  NULL,                           //SSH_CMSG_EXIT_CONFIRMATION          33
  NULL,                           //SSH_CMSG_X11_REQUEST_FORWARDING     34
  NULL,                           //SSH_CMSG_AUTH_RHOSTS_RSA            35
  ssh_packet_ignore_callback,     //SSH_MSG_DEBUG                       36
};

/** @internal
 * @brief sets the default packet handlers
 */
void ssh_packet_set_default_callbacks1(ssh_session session){
  session->default_packet_callbacks.start=0;
  session->default_packet_callbacks.n_callbacks=sizeof(default_packet_handlers1)/sizeof(ssh_packet_callback);
  session->default_packet_callbacks.user=session;
  session->default_packet_callbacks.callbacks=default_packet_handlers1;
  ssh_packet_set_callbacks(session, &session->default_packet_callbacks);
}


/** @internal
 * @handles a data received event. It then calls the handlers for the different packet types
 * or and exception handler callback. Adapted for SSH-1 packets.
 * @param user pointer to current ssh_session
 * @param data pointer to the data received
 * @len length of data received. It might not be enough for a complete packet
 * @returns number of bytes read and processed.
 */

int ssh_packet_socket_callback1(const void *data, size_t receivedlen, void *user) {
  void *packet = NULL;
  int to_be_read;
  size_t processed=0;
  uint32_t padding;
  uint32_t crc;
  uint32_t len, buffer_len;
  ssh_session session=(ssh_session)user;

  switch (session->packet_state){
    case PACKET_STATE_INIT:
      memset(&session->in_packet, 0, sizeof(PACKET));

      if (session->in_buffer) {
        if (ssh_buffer_reinit(session->in_buffer) < 0) {
          goto error;
        }
      } else {
        session->in_buffer = ssh_buffer_new();
        if (session->in_buffer == NULL) {
          goto error;
        }
      }
      /* must have at least enough bytes for size */
      if(receivedlen < sizeof(uint32_t)){
        return 0;
      }
      memcpy(&len,data,sizeof(uint32_t));
      processed += sizeof(uint32_t);

      /* len is not encrypted */
      len = ntohl(len);
      if (len > MAX_PACKET_LEN) {
        ssh_set_error(session, SSH_FATAL,
            "read_packet(): Packet len too high (%u %.8x)", len, len);
        goto error;
      }

      SSH_LOG(SSH_LOG_PACKET, "Reading a %d bytes packet", len);

      session->in_packet.len = len;
      session->packet_state = PACKET_STATE_SIZEREAD;
      /* FALL THROUGH */
    case PACKET_STATE_SIZEREAD:
      len = session->in_packet.len;
      /* SSH-1 has a fixed padding lenght */
      padding = 8 - (len % 8);
      to_be_read = len + padding;
      if(to_be_read + processed > receivedlen){
        /* wait for rest of packet */
        return processed;
      }
      /* it is _not_ possible that to_be_read be < 8. */
      packet = (char *)data + processed;

      if (ssh_buffer_add_data(session->in_buffer,packet,to_be_read) < 0) {
        goto error;
      }
      processed += to_be_read;
#ifdef DEBUG_CRYPTO
      ssh_print_hexa("read packet:", ssh_buffer_get_begin(session->in_buffer),
          ssh_buffer_get_len(session->in_buffer));
#endif
      if (session->current_crypto) {
        /*
         * We decrypt everything, missing the lenght part (which was
         * previously read, unencrypted, and is not part of the buffer
         */
        buffer_len = ssh_buffer_get_len(session->in_buffer);
        if (buffer_len > 0) {
          int rc;
          rc = packet_decrypt(session,
                 ssh_buffer_get_begin(session->in_buffer),
                 buffer_len);
          if (rc < 0) {
            ssh_set_error(session, SSH_FATAL, "Packet decrypt error");
            goto error;
          }
        }
      }
#ifdef DEBUG_CRYPTO
      ssh_print_hexa("read packet decrypted:", ssh_buffer_get_begin(session->in_buffer),
          ssh_buffer_get_len(session->in_buffer));
#endif
      SSH_LOG(SSH_LOG_PACKET, "%d bytes padding", padding);
      if(((len + padding) != buffer_get_rest_len(session->in_buffer)) ||
          ((len + padding) < sizeof(uint32_t))) {
        SSH_LOG(SSH_LOG_RARE, "no crc32 in packet");
        ssh_set_error(session, SSH_FATAL, "no crc32 in packet");
        goto error;
      }

      memcpy(&crc,
          (unsigned char *)buffer_get_rest(session->in_buffer) + (len+padding) - sizeof(uint32_t),
          sizeof(uint32_t));
      buffer_pass_bytes_end(session->in_buffer, sizeof(uint32_t));
      crc = ntohl(crc);
      if (ssh_crc32(buffer_get_rest(session->in_buffer),
            (len + padding) - sizeof(uint32_t)) != crc) {
#ifdef DEBUG_CRYPTO
        ssh_print_hexa("crc32 on",buffer_get_rest(session->in_buffer),
            len + padding - sizeof(uint32_t));
#endif
        SSH_LOG(SSH_LOG_RARE, "Invalid crc32");
        ssh_set_error(session, SSH_FATAL,
            "Invalid crc32: expected %.8x, got %.8x",
            crc,
            ssh_crc32(buffer_get_rest(session->in_buffer),
              len + padding - sizeof(uint32_t)));
        goto error;
      }
      /* pass the padding */
      buffer_pass_bytes(session->in_buffer, padding);
      SSH_LOG(SSH_LOG_PACKET, "The packet is valid");

/* TODO FIXME
#ifdef WITH_ZLIB
    if(session->current_crypto && session->current_crypto->do_compress_in){
        decompress_buffer(session,session->in_buffer);
    }
#endif
*/
      session->recv_seq++;
      /* We don't want to rewrite a new packet while still executing the packet callbacks */
      session->packet_state = PACKET_STATE_PROCESSING;
      ssh_packet_parse_type(session);
      /* execute callbacks */
      ssh_packet_process(session, session->in_packet.type);
      session->packet_state = PACKET_STATE_INIT;
      if(processed < receivedlen){
        int rc;
        /* Handle a potential packet left in socket buffer */
        SSH_LOG(SSH_LOG_PACKET,"Processing %" PRIdS " bytes left in socket buffer",
            receivedlen-processed);
        rc = ssh_packet_socket_callback1((char *)data + processed,
            receivedlen - processed,user);
        processed += rc;
      }

      return processed;
    case PACKET_STATE_PROCESSING:
      SSH_LOG(SSH_LOG_PACKET, "Nested packet processing. Delaying.");
      return 0;
  }

error:
  session->session_state=SSH_SESSION_STATE_ERROR;

  return processed;
}


int packet_send1(ssh_session session) {
  unsigned int blocksize = (session->current_crypto ?
      session->current_crypto->out_cipher->blocksize : 8);
  uint32_t currentlen = ssh_buffer_get_len(session->out_buffer) + sizeof(uint32_t);
  char padstring[32] = {0};
  int rc = SSH_ERROR;
  uint32_t finallen;
  uint32_t crc;
  uint8_t padding;

  SSH_LOG(SSH_LOG_PACKET,"Sending a %d bytes long packet",currentlen);

/* TODO FIXME
#ifdef WITH_ZLIB
  if (session->current_crypto && session->current_crypto->do_compress_out) {
    if (compress_buffer(session, session->out_buffer) < 0) {
      goto error;
    }
    currentlen = buffer_get_len(session->out_buffer);
  }
#endif
*/
  padding = blocksize - (currentlen % blocksize);
  if (session->current_crypto) {
    ssh_get_random(padstring, padding, 0);
  } else {
    memset(padstring, 0, padding);
  }

  finallen = htonl(currentlen);
  SSH_LOG(SSH_LOG_PACKET,
      "%d bytes after comp + %d padding bytes = %d bytes packet",
      currentlen, padding, ntohl(finallen));

  if (buffer_prepend_data(session->out_buffer, &padstring, padding) < 0) {
    goto error;
  }
  if (buffer_prepend_data(session->out_buffer, &finallen, sizeof(uint32_t)) < 0) {
    goto error;
  }

  crc = ssh_crc32((char *)ssh_buffer_get_begin(session->out_buffer) + sizeof(uint32_t),
      ssh_buffer_get_len(session->out_buffer) - sizeof(uint32_t));

  if (buffer_add_u32(session->out_buffer, ntohl(crc)) < 0) {
    goto error;
  }

#ifdef DEBUG_CRYPTO
  ssh_print_hexa("Clear packet", ssh_buffer_get_begin(session->out_buffer),
      ssh_buffer_get_len(session->out_buffer));
#endif

  /* session->out_buffer should have more than sizeof(uint32_t) bytes
     in it as required for packet_encrypt */
  packet_encrypt(session, (unsigned char *)ssh_buffer_get_begin(session->out_buffer) + sizeof(uint32_t),
      ssh_buffer_get_len(session->out_buffer) - sizeof(uint32_t));

#ifdef DEBUG_CRYPTO
  ssh_print_hexa("encrypted packet",ssh_buffer_get_begin(session->out_buffer),
      ssh_buffer_get_len(session->out_buffer));
#endif
  rc=ssh_socket_write(session->socket, ssh_buffer_get_begin(session->out_buffer),
      ssh_buffer_get_len(session->out_buffer));
  if(rc== SSH_ERROR) {
    goto error;
  }

  session->send_seq++;

  if (ssh_buffer_reinit(session->out_buffer) < 0) {
    rc = SSH_ERROR;
  }
error:

  return rc;     /* SSH_OK, AGAIN or ERROR */
}

SSH_PACKET_CALLBACK(ssh_packet_disconnect1){
  (void)packet;
  (void)user;
  (void)type;
  SSH_LOG(SSH_LOG_PACKET, "Received SSH_MSG_DISCONNECT");
  ssh_set_error(session, SSH_FATAL, "Received SSH_MSG_DISCONNECT");
  ssh_socket_close(session->socket);
  session->alive = 0;
  session->session_state=SSH_SESSION_STATE_DISCONNECTED;
  return SSH_PACKET_USED;
}

SSH_PACKET_CALLBACK(ssh_packet_smsg_success1){
  if(session->session_state==SSH_SESSION_STATE_KEXINIT_RECEIVED){
    session->session_state=SSH_SESSION_STATE_AUTHENTICATING;
    return SSH_PACKET_USED;
  } else if(session->session_state==SSH_SESSION_STATE_AUTHENTICATING){
    ssh_auth1_handler(session,type);
    return SSH_PACKET_USED;
  } else {
    return ssh_packet_channel_success(session,type,packet,user);
  }
}

SSH_PACKET_CALLBACK(ssh_packet_smsg_failure1){
  if(session->session_state==SSH_SESSION_STATE_KEXINIT_RECEIVED){
    session->session_state=SSH_SESSION_STATE_ERROR;
    ssh_set_error(session,SSH_FATAL,"Key exchange failed: received SSH_SMSG_FAILURE");
    return SSH_PACKET_USED;
  } else if(session->session_state==SSH_SESSION_STATE_AUTHENTICATING){
    ssh_auth1_handler(session,type);
    return SSH_PACKET_USED;
  } else {
    return ssh_packet_channel_failure(session,type,packet,user);
  }
}


#endif /* WITH_SSH1 */

/* vim: set ts=2 sw=2 et cindent: */
