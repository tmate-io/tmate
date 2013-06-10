/*
 * packet.c - packet building functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
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
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "libssh/priv.h"
#include "libssh/ssh2.h"
#include "libssh/crypto.h"
#include "libssh/buffer.h"
#include "libssh/packet.h"
#include "libssh/socket.h"
#include "libssh/channels.h"
#include "libssh/misc.h"
#include "libssh/session.h"
#include "libssh/messages.h"
#include "libssh/pcap.h"
#include "libssh/kex.h"
#include "libssh/auth.h"

#define MACSIZE SHA_DIGEST_LEN

static ssh_packet_callback default_packet_handlers[]= {
  ssh_packet_disconnect_callback,          // SSH2_MSG_DISCONNECT                 1
  ssh_packet_ignore_callback,              // SSH2_MSG_IGNORE	                    2
  ssh_packet_unimplemented,                // SSH2_MSG_UNIMPLEMENTED              3
  ssh_packet_ignore_callback,              // SSH2_MSG_DEBUG	                    4
  ssh_packet_service_request,              // SSH2_MSG_SERVICE_REQUEST	          5
  ssh_packet_service_accept,               // SSH2_MSG_SERVICE_ACCEPT             6
  NULL, NULL, NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL,	NULL, NULL, NULL,      //                                     7-19
  ssh_packet_kexinit,                      // SSH2_MSG_KEXINIT	                  20
  ssh_packet_newkeys,                      // SSH2_MSG_NEWKEYS                    21
  NULL, NULL, NULL, NULL, NULL, NULL, NULL,
  NULL,                                    //                                     22-29
#if WITH_SERVER
  ssh_packet_kexdh_init,                   // SSH2_MSG_KEXDH_INIT                 30
                                           // SSH2_MSG_KEX_DH_GEX_REQUEST_OLD     30
#else
  NULL,
#endif
  ssh_packet_dh_reply,                     // SSH2_MSG_KEXDH_REPLY                31
                                           // SSH2_MSG_KEX_DH_GEX_GROUP           31
  NULL,                                    // SSH2_MSG_KEX_DH_GEX_INIT            32
  NULL,                                    // SSH2_MSG_KEX_DH_GEX_REPLY           33
  NULL,                                    // SSH2_MSG_KEX_DH_GEX_REQUEST         34
  NULL, NULL, NULL, NULL, NULL, NULL,	NULL,
  NULL, NULL, NULL, NULL, NULL, NULL, NULL,
  NULL,                                    //                                     35-49
  ssh_packet_userauth_request,             // SSH2_MSG_USERAUTH_REQUEST           50
  ssh_packet_userauth_failure,             // SSH2_MSG_USERAUTH_FAILURE           51
  ssh_packet_userauth_success,             // SSH2_MSG_USERAUTH_SUCCESS           52
  ssh_packet_userauth_banner,              // SSH2_MSG_USERAUTH_BANNER            53
  NULL,NULL,NULL,NULL,NULL,NULL,           //                                     54-59
  ssh_packet_userauth_pk_ok,               // SSH2_MSG_USERAUTH_PK_OK             60
                                           // SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ  60
                                           // SSH2_MSG_USERAUTH_INFO_REQUEST	    60
  ssh_packet_userauth_info_response,       // SSH2_MSG_USERAUTH_INFO_RESPONSE     61
  NULL, NULL, NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, NULL, NULL,                  //                                     62-79
#ifdef WITH_SERVER
  ssh_packet_global_request,               // SSH2_MSG_GLOBAL_REQUEST             80
#else /* WITH_SERVER */
  NULL,
#endif /* WITH_SERVER */ 
  ssh_request_success,                     // SSH2_MSG_REQUEST_SUCCESS            81
  ssh_request_denied,                      // SSH2_MSG_REQUEST_FAILURE            82
  NULL, NULL, NULL, NULL, NULL, NULL, NULL,//                                     83-89
  ssh_packet_channel_open,                 // SSH2_MSG_CHANNEL_OPEN               90
  ssh_packet_channel_open_conf,            // SSH2_MSG_CHANNEL_OPEN_CONFIRMATION  91
  ssh_packet_channel_open_fail,            // SSH2_MSG_CHANNEL_OPEN_FAILURE       92
  channel_rcv_change_window,               // SSH2_MSG_CHANNEL_WINDOW_ADJUST      93
  channel_rcv_data,                        // SSH2_MSG_CHANNEL_DATA               94
  channel_rcv_data,                        // SSH2_MSG_CHANNEL_EXTENDED_DATA      95
  channel_rcv_eof,                         // SSH2_MSG_CHANNEL_EOF	              96
  channel_rcv_close,                       // SSH2_MSG_CHANNEL_CLOSE              97
  channel_rcv_request,                     // SSH2_MSG_CHANNEL_REQUEST            98
  ssh_packet_channel_success,              // SSH2_MSG_CHANNEL_SUCCESS            99
  ssh_packet_channel_failure,              // SSH2_MSG_CHANNEL_FAILURE            100
};

/* in nonblocking mode, socket_read will read as much as it can, and return */
/* SSH_OK if it has read at least len bytes, otherwise, SSH_AGAIN. */
/* in blocking mode, it will read at least len bytes and will block until it's ok. */

/** @internal
 * @handles a data received event. It then calls the handlers for the different packet types
 * or and exception handler callback.
 * @param user pointer to current ssh_session
 * @param data pointer to the data received
 * @len length of data received. It might not be enough for a complete packet
 * @returns number of bytes read and processed.
 */
int ssh_packet_socket_callback(const void *data, size_t receivedlen, void *user){
  ssh_session session=(ssh_session) user;
  unsigned int blocksize = (session->current_crypto ?
      session->current_crypto->in_cipher->blocksize : 8);
  int current_macsize = session->current_crypto ? MACSIZE : 0;
  unsigned char mac[30] = {0};
  char buffer[16] = {0};
  const void *packet = NULL;
  int to_be_read;
  int rc;
  uint32_t len, compsize, payloadsize;
  uint8_t padding;
  size_t processed=0; /* number of byte processed from the callback */

  if (data == NULL) {
    goto error;
  }

  enter_function();
  if (session->session_state == SSH_SESSION_STATE_ERROR)
	  goto error;
  switch(session->packet_state) {
    case PACKET_STATE_INIT:
    	if(receivedlen < blocksize){
    		/* We didn't receive enough data to read at least one block size, give up */
    		leave_function();
    		return 0;
    	}
      memset(&session->in_packet, 0, sizeof(PACKET));

      if (session->in_buffer) {
        if (buffer_reinit(session->in_buffer) < 0) {
          goto error;
        }
      } else {
        session->in_buffer = ssh_buffer_new();
        if (session->in_buffer == NULL) {
          goto error;
        }
      }

      memcpy(buffer,data,blocksize);
      processed += blocksize;
      len = packet_decrypt_len(session, buffer);

      if (buffer_add_data(session->in_buffer, buffer, blocksize) < 0) {
        goto error;
      }

      if(len > MAX_PACKET_LEN) {
        ssh_set_error(session, SSH_FATAL,
            "read_packet(): Packet len too high(%u %.4x)", len, len);
        goto error;
      }

      to_be_read = len - blocksize + sizeof(uint32_t);
      if (to_be_read < 0) {
        /* remote sshd sends invalid sizes? */
        ssh_set_error(session, SSH_FATAL,
            "given numbers of bytes left to be read < 0 (%d)!", to_be_read);
        goto error;
      }

      /* saves the status of the current operations */
      session->in_packet.len = len;
      session->packet_state = PACKET_STATE_SIZEREAD;
    case PACKET_STATE_SIZEREAD:
      len = session->in_packet.len;
      to_be_read = len - blocksize + sizeof(uint32_t) + current_macsize;
      /* if to_be_read is zero, the whole packet was blocksize bytes. */
      if (to_be_read != 0) {
        if(receivedlen - processed < (unsigned int)to_be_read){
        	/* give up, not enough data in buffer */
            ssh_log(session,SSH_LOG_PACKET,"packet: partial packet (read len) [len=%d]",len);
        	return processed;
        }

        packet = ((unsigned char *)data) + processed;
//        ssh_socket_read(session->socket,packet,to_be_read-current_macsize);

        if (buffer_add_data(session->in_buffer, packet,
              to_be_read - current_macsize) < 0) {
          goto error;
        }
        processed += to_be_read - current_macsize;
      }

      if (session->current_crypto) {
        /*
         * decrypt the rest of the packet (blocksize bytes already
         * have been decrypted)
         */
        if (packet_decrypt(session,
              ((uint8_t*)buffer_get_rest(session->in_buffer) + blocksize),
              buffer_get_rest_len(session->in_buffer) - blocksize) < 0) {
          ssh_set_error(session, SSH_FATAL, "Decrypt error");
          goto error;
        }
        /* copy the last part from the incoming buffer */
        memcpy(mac,(unsigned char *)packet + to_be_read - current_macsize, MACSIZE);

        if (packet_hmac_verify(session, session->in_buffer, mac) < 0) {
          ssh_set_error(session, SSH_FATAL, "HMAC error");
          goto error;
        }
        processed += current_macsize;
      }

      /* skip the size field which has been processed before */
      buffer_pass_bytes(session->in_buffer, sizeof(uint32_t));

      if (buffer_get_u8(session->in_buffer, &padding) == 0) {
        ssh_set_error(session, SSH_FATAL, "Packet too short to read padding");
        goto error;
      }

      if (padding > buffer_get_rest_len(session->in_buffer)) {
        ssh_set_error(session, SSH_FATAL,
            "Invalid padding: %d (%d left)",
            padding,
            buffer_get_rest_len(session->in_buffer));
        goto error;
      }
      buffer_pass_bytes_end(session->in_buffer, padding);
      compsize = buffer_get_rest_len(session->in_buffer);

#ifdef WITH_ZLIB
      if (session->current_crypto
          && session->current_crypto->do_compress_in
          && buffer_get_rest_len(session->in_buffer)) {
        if (decompress_buffer(session, session->in_buffer,MAX_PACKET_LEN) < 0) {
          goto error;
        }
      }
#endif /* WITH_ZLIB */
      payloadsize=buffer_get_rest_len(session->in_buffer);
      session->recv_seq++;
      /* We don't want to rewrite a new packet while still executing the packet callbacks */
      session->packet_state = PACKET_STATE_PROCESSING;
      ssh_packet_parse_type(session);
      ssh_log(session,SSH_LOG_PACKET,
              "packet: read type %hhd [len=%d,padding=%hhd,comp=%d,payload=%d]",
              session->in_packet.type, len, padding, compsize, payloadsize);
      /* execute callbacks */
      ssh_packet_process(session, session->in_packet.type);
      session->packet_state = PACKET_STATE_INIT;
      if(processed < receivedlen){
      	/* Handle a potential packet left in socket buffer */
      	ssh_log(session,SSH_LOG_PACKET,"Processing %" PRIdS " bytes left in socket buffer",
      			receivedlen-processed);
        rc = ssh_packet_socket_callback(((unsigned char *)data) + processed,
      			receivedlen - processed,user);
      	processed += rc;
      }
      leave_function();
      return processed;
    case PACKET_STATE_PROCESSING:
    	ssh_log(session, SSH_LOG_RARE, "Nested packet processing. Delaying.");
    	return 0;
  }

  ssh_set_error(session, SSH_FATAL,
      "Invalid state into packet_read2(): %d",
      session->packet_state);

error:
  session->session_state= SSH_SESSION_STATE_ERROR;
  leave_function();
  return processed;
}

void ssh_packet_register_socket_callback(ssh_session session, ssh_socket s){
	session->socket_callbacks.data=ssh_packet_socket_callback;
	session->socket_callbacks.connected=NULL;
	session->socket_callbacks.controlflow=NULL;
	session->socket_callbacks.exception=NULL;
	session->socket_callbacks.userdata=session;
	ssh_socket_set_callbacks(s,&session->socket_callbacks);
}

/** @internal
 * @brief sets the callbacks for the packet layer
 */
void ssh_packet_set_callbacks(ssh_session session, ssh_packet_callbacks callbacks){
	if(session->packet_callbacks == NULL){
		session->packet_callbacks = ssh_list_new();
	}
  ssh_list_append(session->packet_callbacks, callbacks);
}

/** @internal
 * @brief sets the default packet handlers
 */
void ssh_packet_set_default_callbacks(ssh_session session){
#ifdef WITH_SSH1
  if(session->version==1){
    ssh_packet_set_default_callbacks1(session);
    return;
  }
#endif
	session->default_packet_callbacks.start=1;
	session->default_packet_callbacks.n_callbacks=sizeof(default_packet_handlers)/sizeof(ssh_packet_callback);
	session->default_packet_callbacks.user=session;
	session->default_packet_callbacks.callbacks=default_packet_handlers;
	ssh_packet_set_callbacks(session, &session->default_packet_callbacks);
}

/** @internal
 * @brief dispatch the call of packet handlers callbacks for a received packet
 * @param type type of packet
 */
void ssh_packet_process(ssh_session session, uint8_t type){
	struct ssh_iterator *i;
	int r=SSH_PACKET_NOT_USED;
	ssh_packet_callbacks cb;
	enter_function();
	ssh_log(session,SSH_LOG_PACKET, "Dispatching handler for packet type %d",type);
	if(session->packet_callbacks == NULL){
		ssh_log(session,SSH_LOG_RARE,"Packet callback is not initialized !");
		goto error;
	}
	i=ssh_list_get_iterator(session->packet_callbacks);
	while(i != NULL){
		cb=ssh_iterator_value(ssh_packet_callbacks,i);
		i=i->next;
		if(!cb)
			continue;
		if(cb->start > type)
			continue;
		if(cb->start + cb->n_callbacks <= type)
			continue;
		if(cb->callbacks[type - cb->start]==NULL)
			continue;
		r=cb->callbacks[type - cb->start](session,type,session->in_buffer,cb->user);
		if(r==SSH_PACKET_USED)
			break;
	}
	if(r==SSH_PACKET_NOT_USED){
		ssh_log(session,SSH_LOG_RARE,"Couldn't do anything with packet type %d",type);
		ssh_packet_send_unimplemented(session, session->recv_seq-1);
	}
error:
	leave_function();
}

/** @internal
 * @brief sends a SSH_MSG_UNIMPLEMENTED answer to an unhandled packet
 * @param session the SSH session
 * @param seqnum the sequence number of the unknown packet
 * @return SSH_ERROR on error, else SSH_OK
 */
int ssh_packet_send_unimplemented(ssh_session session, uint32_t seqnum){
  int r;
  enter_function();
  r = buffer_add_u8(session->out_buffer, SSH2_MSG_UNIMPLEMENTED);
  if (r < 0) {
    return SSH_ERROR;
  }
  r = buffer_add_u32(session->out_buffer, htonl(seqnum));
  if (r < 0) {
    return SSH_ERROR;
  }
  r = packet_send(session);
  leave_function();
  return r;
}

/** @internal
 * @brief handles a SSH_MSG_UNIMPLEMENTED packet
 */
SSH_PACKET_CALLBACK(ssh_packet_unimplemented){
  uint32_t seq;
  (void)type;
  (void)user;
  buffer_get_u32(packet,&seq);
  seq=ntohl(seq);
  ssh_log(session,SSH_LOG_RARE,
      "Received SSH_MSG_UNIMPLEMENTED (sequence number %d)",seq);
  return SSH_PACKET_USED;
}

/** @internal
 * @parse the "Type" header field of a packet and updates the session
 */
int ssh_packet_parse_type(ssh_session session) {
  enter_function();

  memset(&session->in_packet, 0, sizeof(PACKET));
  if(session->in_buffer == NULL) {
    leave_function();
    return SSH_ERROR;
  }

  if(buffer_get_u8(session->in_buffer, &session->in_packet.type) == 0) {
    ssh_set_error(session, SSH_FATAL, "Packet too short to read type");
    leave_function();
    return SSH_ERROR;
  }

  session->in_packet.valid = 1;

  leave_function();
  return SSH_OK;
}

/*
 * This function places the outgoing packet buffer into an outgoing
 * socket buffer
 */
static int ssh_packet_write(ssh_session session) {
  int rc = SSH_ERROR;

  enter_function();

  rc=ssh_socket_write(session->socket,
      buffer_get_rest(session->out_buffer),
      buffer_get_rest_len(session->out_buffer));
  leave_function();
  return rc;
}

static int packet_send2(ssh_session session) {
  unsigned int blocksize = (session->current_crypto ?
      session->current_crypto->out_cipher->blocksize : 8);
  uint32_t currentlen = buffer_get_rest_len(session->out_buffer);
  unsigned char *hmac = NULL;
  char padstring[32] = {0};
  int rc = SSH_ERROR;
  uint32_t finallen,payloadsize,compsize;
  uint8_t padding;

  enter_function();

  payloadsize = currentlen;
#ifdef WITH_ZLIB
  if (session->current_crypto
      && session->current_crypto->do_compress_out
      && buffer_get_rest_len(session->out_buffer)) {
    if (compress_buffer(session,session->out_buffer) < 0) {
      goto error;
    }
    currentlen = buffer_get_rest_len(session->out_buffer);
  }
#endif /* WITH_ZLIB */
  compsize = currentlen;
  padding = (blocksize - ((currentlen +5) % blocksize));
  if(padding < 4) {
    padding += blocksize;
  }

  if (session->current_crypto) {
    ssh_get_random(padstring, padding, 0);
  } else {
    memset(padstring,0,padding);
  }

  finallen = htonl(currentlen + padding + 1);

  if (buffer_prepend_data(session->out_buffer, &padding, sizeof(uint8_t)) < 0) {
    goto error;
  }
  if (buffer_prepend_data(session->out_buffer, &finallen, sizeof(uint32_t)) < 0) {
    goto error;
  }
  if (buffer_add_data(session->out_buffer, padstring, padding) < 0) {
    goto error;
  }
#ifdef WITH_PCAP
  if(session->pcap_ctx){
  	ssh_pcap_context_write(session->pcap_ctx,SSH_PCAP_DIR_OUT,
  			buffer_get_rest(session->out_buffer),buffer_get_rest_len(session->out_buffer)
  			,buffer_get_rest_len(session->out_buffer));
  }
#endif
  hmac = packet_encrypt(session, buffer_get_rest(session->out_buffer),
      buffer_get_rest_len(session->out_buffer));
  if (hmac) {
    if (buffer_add_data(session->out_buffer, hmac, 20) < 0) {
      goto error;
    }
  }

  rc = ssh_packet_write(session);
  session->send_seq++;

  ssh_log(session,SSH_LOG_PACKET,
          "packet: wrote [len=%d,padding=%hhd,comp=%d,payload=%d]",
          ntohl(finallen), padding, compsize, payloadsize);
  if (buffer_reinit(session->out_buffer) < 0) {
    rc = SSH_ERROR;
  }
error:
  leave_function();
  return rc; /* SSH_OK, AGAIN or ERROR */
}


int packet_send(ssh_session session) {
#ifdef WITH_SSH1
  if (session->version == 1) {
    return packet_send1(session);
  }
#endif
  return packet_send2(session);
}


/* vim: set ts=2 sw=2 et cindent: */
