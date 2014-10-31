/*
 * messages.c - message parsing for client and server
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2013 by Aris Adamantiadis
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

#include <string.h>
#include <stdlib.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/ssh2.h"
#include "libssh/buffer.h"
#include "libssh/packet.h"
#include "libssh/channels.h"
#include "libssh/session.h"
#include "libssh/misc.h"
#include "libssh/pki.h"
#include "libssh/dh.h"
#include "libssh/messages.h"
#ifdef WITH_SERVER
#include "libssh/server.h"
#include "libssh/gssapi.h"
#endif

/**
 * @defgroup libssh_messages The SSH message functions
 * @ingroup libssh
 *
 * This file contains the message parsing utilities for client and server
 * programs using libssh.
 *
 * On the server the the main loop of the program will call
 * ssh_message_get(session) to get messages as they come. They are not 1-1 with
 * the protocol messages. Then, the user will know what kind of a message it is
 * and use the appropriate functions to handle it (or use the default handlers
 * if you don't know what to do).
 *
 * @{
 */

static ssh_message ssh_message_new(ssh_session session){
  ssh_message msg = malloc(sizeof(struct ssh_message_struct));
  if (msg == NULL) {
    return NULL;
  }
  ZERO_STRUCTP(msg);
  msg->session = session;
  return msg;
}

#ifndef WITH_SERVER

/* Reduced version of the reply default that only reply with
 * SSH_MSG_UNIMPLEMENTED
 */
static int ssh_message_reply_default(ssh_message msg) {
  SSH_LOG(SSH_LOG_FUNCTIONS, "Reporting unknown packet");

  if (buffer_add_u8(msg->session->out_buffer, SSH2_MSG_UNIMPLEMENTED) < 0)
    goto error;
  if (buffer_add_u32(msg->session->out_buffer,
      htonl(msg->session->recv_seq-1)) < 0)
    goto error;
  return packet_send(msg->session);
  error:
  return SSH_ERROR;
}

#endif

#ifdef WITH_SERVER

static int ssh_execute_server_request(ssh_session session, ssh_message msg)
{
    ssh_channel channel = NULL;
    int rc;

    switch(msg->type) {
        case SSH_REQUEST_AUTH:
            if (msg->auth_request.method == SSH_AUTH_METHOD_PASSWORD &&
                ssh_callbacks_exists(session->server_callbacks, auth_password_function)) {
                rc = session->server_callbacks->auth_password_function(session,
                        msg->auth_request.username, msg->auth_request.password,
                        session->server_callbacks->userdata);
                if (rc == SSH_AUTH_SUCCESS || rc == SSH_AUTH_PARTIAL) {
                    ssh_message_auth_reply_success(msg, rc == SSH_AUTH_PARTIAL);
                } else {
                    ssh_message_reply_default(msg);
                }

                return SSH_OK;
            } else if(msg->auth_request.method == SSH_AUTH_METHOD_PUBLICKEY &&
                      ssh_callbacks_exists(session->server_callbacks, auth_pubkey_function)) {
               rc = session->server_callbacks->auth_pubkey_function(session,
                       msg->auth_request.username, msg->auth_request.pubkey,
                       msg->auth_request.signature_state,
                       session->server_callbacks->userdata);
               if (msg->auth_request.signature_state != SSH_PUBLICKEY_STATE_NONE) {
                 if (rc == SSH_AUTH_SUCCESS || rc == SSH_AUTH_PARTIAL) {
                   ssh_message_auth_reply_success(msg, rc == SSH_AUTH_PARTIAL);
                 } else {
                   ssh_message_reply_default(msg);
                 }
               } else {
                 if (rc == SSH_AUTH_SUCCESS) {
                   ssh_message_auth_reply_pk_ok_simple(msg);
                 } else {
                   ssh_message_reply_default(msg);
                 }
               }

               return SSH_OK;
            } else if (msg->auth_request.method == SSH_AUTH_METHOD_NONE &&
                       ssh_callbacks_exists(session->server_callbacks, auth_none_function)) {
                rc = session->server_callbacks->auth_none_function(session,
                    msg->auth_request.username, session->server_callbacks->userdata);
                if (rc == SSH_AUTH_SUCCESS || rc == SSH_AUTH_PARTIAL){
                    ssh_message_auth_reply_success(msg, rc == SSH_AUTH_PARTIAL);
                } else {
                    ssh_message_reply_default(msg);
                }

                return SSH_OK;
            }
            break;
        case SSH_REQUEST_CHANNEL_OPEN:
            if (msg->channel_request_open.type == SSH_CHANNEL_SESSION &&
                ssh_callbacks_exists(session->server_callbacks, channel_open_request_session_function)) {
                channel = session->server_callbacks->channel_open_request_session_function(session,
                        session->server_callbacks->userdata);
                if (channel != NULL) {
                    rc = ssh_message_channel_request_open_reply_accept_channel(msg, channel);
                    return SSH_OK;
                } else {
                    ssh_message_reply_default(msg);
                }

                return SSH_OK;
            }
            break;
        case SSH_REQUEST_CHANNEL:
            channel = msg->channel_request.channel;

            if (msg->channel_request.type == SSH_CHANNEL_REQUEST_PTY &&
                ssh_callbacks_exists(channel->callbacks, channel_pty_request_function)) {
                rc = channel->callbacks->channel_pty_request_function(session, channel,
                        msg->channel_request.TERM,
                        msg->channel_request.width, msg->channel_request.height,
                        msg->channel_request.pxwidth, msg->channel_request.pxheight,
                        channel->callbacks->userdata);
                if (rc == 0) {
                    ssh_message_channel_request_reply_success(msg);
                } else {
                    ssh_message_reply_default(msg);
                }

                return SSH_OK;
            } else if (msg->channel_request.type == SSH_CHANNEL_REQUEST_SHELL &&
                      ssh_callbacks_exists(channel->callbacks, channel_shell_request_function)) {
                rc = channel->callbacks->channel_shell_request_function(session,
                                                                        channel,
                                                                        channel->callbacks->userdata);
                if (rc == 0) {
                    ssh_message_channel_request_reply_success(msg);
                } else {
                    ssh_message_reply_default(msg);
                }

                return SSH_OK;
            } else if (msg->channel_request.type == SSH_CHANNEL_REQUEST_X11 &&
                      ssh_callbacks_exists(channel->callbacks, channel_x11_req_function)) {
                channel->callbacks->channel_x11_req_function(session,
                                                             channel,
                                                             msg->channel_request.x11_single_connection,
                                                             msg->channel_request.x11_auth_protocol,
                                                             msg->channel_request.x11_auth_cookie,
                                                             msg->channel_request.x11_screen_number,
                                                             channel->callbacks->userdata);
                ssh_message_channel_request_reply_success(msg);

                return SSH_OK;
            } else if (msg->channel_request.type == SSH_CHANNEL_REQUEST_WINDOW_CHANGE &&
                       ssh_callbacks_exists(channel->callbacks, channel_pty_window_change_function)) {
                rc = channel->callbacks->channel_pty_window_change_function(session,
                                                                            channel,
                                                                            msg->channel_request.width, msg->channel_request.height,
                                                                            msg->channel_request.pxwidth, msg->channel_request.pxheight,
                                                                            channel->callbacks->userdata);
            } else if (msg->channel_request.type == SSH_CHANNEL_REQUEST_EXEC &&
                       ssh_callbacks_exists(channel->callbacks, channel_exec_request_function)) {
                rc = channel->callbacks->channel_exec_request_function(session,
                                                                       channel,
                                                                       msg->channel_request.command,
                                                                       channel->callbacks->userdata);
                if (rc == 0) {
                    ssh_message_channel_request_reply_success(msg);
                } else {
                    ssh_message_reply_default(msg);
                }

                return SSH_OK;
            } else if (msg->channel_request.type == SSH_CHANNEL_REQUEST_ENV &&
                       ssh_callbacks_exists(channel->callbacks, channel_env_request_function)) {
                rc = channel->callbacks->channel_env_request_function(session,
                                                                      channel,
                                                                      msg->channel_request.var_name, msg->channel_request.var_value,
                                                                      channel->callbacks->userdata);
                if (rc == 0) {
                    ssh_message_channel_request_reply_success(msg);
                } else {
                    ssh_message_reply_default(msg);
                }

                return SSH_OK;
            } else if (msg->channel_request.type == SSH_CHANNEL_REQUEST_SUBSYSTEM &&
                       ssh_callbacks_exists(channel->callbacks, channel_subsystem_request_function)) {
                rc = channel->callbacks->channel_subsystem_request_function(session,
                                                                            channel,
                                                                            msg->channel_request.subsystem,
                                                                            channel->callbacks->userdata);
                if (rc == 0) {
                    ssh_message_channel_request_reply_success(msg);
                } else {
                    ssh_message_reply_default(msg);
                }

                return SSH_OK;
            }
            break;
        case SSH_REQUEST_SERVICE:
            if (ssh_callbacks_exists(session->server_callbacks, service_request_function)) {
                rc = session->server_callbacks->service_request_function(session,
                        msg->service_request.service, session->server_callbacks->userdata);
                if (rc == 0) {
                    ssh_message_reply_default(msg);
                } else {
                    ssh_disconnect(session);
                }

                return SSH_OK;
            }

            return SSH_AGAIN;
        case SSH_REQUEST_GLOBAL:
            break;
    }

    return SSH_AGAIN;
}

static int ssh_execute_client_request(ssh_session session, ssh_message msg)
{
    ssh_channel channel = NULL;
    int rc = SSH_AGAIN;

    if (msg->type == SSH_REQUEST_CHANNEL_OPEN
        && msg->channel_request_open.type == SSH_CHANNEL_X11
        && ssh_callbacks_exists(session->common.callbacks, channel_open_request_x11_function)) {
        channel = session->common.callbacks->channel_open_request_x11_function (session,
                msg->channel_request_open.originator,
                msg->channel_request_open.originator_port,
                session->common.callbacks->userdata);
        if (channel != NULL) {
            rc = ssh_message_channel_request_open_reply_accept_channel(msg, channel);

            return rc;
        } else {
            ssh_message_reply_default(msg);
        }

        return SSH_OK;
    }

    return rc;
}

/** @internal
 * Executes the callbacks defined in session->server_callbacks, out of an ssh_message
 * I don't like ssh_message interface but it works.
 * @returns SSH_OK if the message has been handled, or SSH_AGAIN otherwise.
 */
static int ssh_execute_server_callbacks(ssh_session session, ssh_message msg){
    int rc = SSH_AGAIN;

    if (session->server_callbacks != NULL){
        rc = ssh_execute_server_request(session, msg);
    } else if (session->common.callbacks != NULL) {
        /* This one is in fact a client callback... */
        rc = ssh_execute_client_request(session, msg);
    }

    return rc;
}

#endif /* WITH_SERVER */

static int ssh_execute_message_callback(ssh_session session, ssh_message msg) {
	int ret;
    if(session->ssh_message_callback != NULL) {
        ret = session->ssh_message_callback(session, msg,
                session->ssh_message_callback_data);
        if(ret == 1) {
            ret = ssh_message_reply_default(msg);
            ssh_message_free(msg);
            if(ret != SSH_OK) {
                return ret;
            }
        } else {
            ssh_message_free(msg);
        }
    } else {
        ret = ssh_message_reply_default(msg);
        ssh_message_free(msg);
        if(ret != SSH_OK) {
            return ret;
        }
    }
    return SSH_OK;
}

/**
 * @internal
 *
 * @brief Add a message to the current queue of messages to be parsed and/or call
 * the various callback functions.
 *
 * @param[in]  session  The SSH session to add the message.
 *
 * @param[in]  message  The message to add to the queue.
 */
void ssh_message_queue(ssh_session session, ssh_message message){
    if (message != NULL) {
#ifdef WITH_SERVER
	int ret;
        /* probably not the best place to execute server callbacks, but still better
         * than nothing.
         */
        ret = ssh_execute_server_callbacks(session, message);
        if (ret == SSH_OK){
            ssh_message_free(message);
            return;
        }
#endif /* WITH_SERVER */
        if(session->ssh_message_callback != NULL) {
            ssh_execute_message_callback(session, message);
            return;
        }
        if (session->server_callbacks != NULL){
            /* if we have server callbacks, but nothing was executed, it means we are
             * in non-synchronous mode, and we just don't care about the message we
             * received. Just send a default response. Do not queue it.
             */
            ssh_message_reply_default(message);
            ssh_message_free(message);
            return;
        }
        if(session->ssh_message_list == NULL) {
            session->ssh_message_list = ssh_list_new();
        }
        if (session->ssh_message_list != NULL) {
            ssh_list_append(session->ssh_message_list, message);
        }
    }
}

/**
 * @internal
 *
 * @brief Pop a message from the message list and dequeue it.
 *
 * @param[in]  session  The SSH session to pop the message.
 *
 * @returns             The head message or NULL if it doesn't exist.
 */
ssh_message ssh_message_pop_head(ssh_session session){
  ssh_message msg=NULL;
  struct ssh_iterator *i;
  if(session->ssh_message_list == NULL)
    return NULL;
  i=ssh_list_get_iterator(session->ssh_message_list);
  if(i != NULL){
    msg=ssh_iterator_value(ssh_message,i);
    ssh_list_remove(session->ssh_message_list,i);
  }
  return msg;
}

/* Returns 1 if there is a message available */
static int ssh_message_termination(void *s){
  ssh_session session = s;
  struct ssh_iterator *it;
  if(session->session_state == SSH_SESSION_STATE_ERROR)
    return 1;
  it = ssh_list_get_iterator(session->ssh_message_list);
  if(!it)
    return 0;
  else
    return 1;
}
/**
 * @brief Retrieve a SSH message from a SSH session.
 *
 * @param[in]  session  The SSH session to get the message.
 *
 * @returns             The SSH message received, NULL in case of error, or timeout
 *                      elapsed.
 *
 * @warning This function blocks until a message has been received. Betterset up
 *          a callback if this behavior is unwanted.
 */
ssh_message ssh_message_get(ssh_session session) {
  ssh_message msg = NULL;
  int rc;

  msg=ssh_message_pop_head(session);
  if(msg) {
      return msg;
  }
  if(session->ssh_message_list == NULL) {
      session->ssh_message_list = ssh_list_new();
  }
  rc = ssh_handle_packets_termination(session, SSH_TIMEOUT_USER,
      ssh_message_termination, session);
  if(rc || session->session_state == SSH_SESSION_STATE_ERROR)
    return NULL;
  msg=ssh_list_pop_head(ssh_message, session->ssh_message_list);

  return msg;
}

/**
 * @brief Get the type of the message.
 *
 * @param[in] msg       The message to get the type from.
 *
 * @return              The message type or -1 on error.
 */
int ssh_message_type(ssh_message msg) {
  if (msg == NULL) {
    return -1;
  }

  return msg->type;
}

/**
 * @brief Get the subtype of the message.
 *
 * @param[in] msg       The message to get the subtype from.
 *
 * @return              The message type or -1 on error.
 */
int ssh_message_subtype(ssh_message msg) {
  if (msg == NULL) {
    return -1;
  }

  switch(msg->type) {
    case SSH_REQUEST_AUTH:
      return msg->auth_request.method;
    case SSH_REQUEST_CHANNEL_OPEN:
      return msg->channel_request_open.type;
    case SSH_REQUEST_CHANNEL:
      return msg->channel_request.type;
    case SSH_REQUEST_GLOBAL:
      return msg->global_request.type;
  }

  return -1;
}

/**
 * @brief Free a SSH message.
 *
 * @param[in] msg       The message to release the memory.
 */
void ssh_message_free(ssh_message msg){
  if (msg == NULL) {
    return;
  }

  switch(msg->type) {
    case SSH_REQUEST_AUTH:
      SAFE_FREE(msg->auth_request.username);
      if (msg->auth_request.password) {
        BURN_STRING(msg->auth_request.password);
        SAFE_FREE(msg->auth_request.password);
      }
      ssh_key_free(msg->auth_request.pubkey);
      break;
    case SSH_REQUEST_CHANNEL_OPEN:
      SAFE_FREE(msg->channel_request_open.originator);
      SAFE_FREE(msg->channel_request_open.destination);
      break;
    case SSH_REQUEST_CHANNEL:
      SAFE_FREE(msg->channel_request.TERM);
      SAFE_FREE(msg->channel_request.modes);
      SAFE_FREE(msg->channel_request.var_name);
      SAFE_FREE(msg->channel_request.var_value);
      SAFE_FREE(msg->channel_request.command);
      SAFE_FREE(msg->channel_request.subsystem);
      break;
    case SSH_REQUEST_SERVICE:
      SAFE_FREE(msg->service_request.service);
      break;
    case SSH_REQUEST_GLOBAL:
      SAFE_FREE(msg->global_request.bind_address);
      break;
  }
  ZERO_STRUCTP(msg);
  SAFE_FREE(msg);
}

#ifdef WITH_SERVER

SSH_PACKET_CALLBACK(ssh_packet_service_request){
  ssh_string service = NULL;
  char *service_c = NULL;
  ssh_message msg=NULL;

  (void)type;
  (void)user;
  service = buffer_get_ssh_string(packet);
  if (service == NULL) {
    ssh_set_error(session, SSH_FATAL, "Invalid SSH_MSG_SERVICE_REQUEST packet");
    goto error;
  }

  service_c = ssh_string_to_char(service);
  if (service_c == NULL) {
    goto error;
  }
  SSH_LOG(SSH_LOG_PACKET,
        "Received a SERVICE_REQUEST for service %s", service_c);
  msg=ssh_message_new(session);
  if(!msg){
    SAFE_FREE(service_c);
    goto error;
  }
  msg->type=SSH_REQUEST_SERVICE;
  msg->service_request.service=service_c;
error:
  ssh_string_free(service);
  if(msg != NULL)
    ssh_message_queue(session,msg);

  return SSH_PACKET_USED;
}


/*
 * This function concats in a buffer the values needed to do a signature
 * verification.
 */
static ssh_buffer ssh_msg_userauth_build_digest(ssh_session session,
                                                ssh_message msg,
                                                const char *service)
{
    struct ssh_crypto_struct *crypto =
        session->current_crypto ? session->current_crypto :
                                  session->next_crypto;
    ssh_buffer buffer;
    ssh_string str=NULL;
    int rc;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        return NULL;
    }
    rc = ssh_pki_export_pubkey_blob(msg->auth_request.pubkey, &str);
    if (rc < 0) {
        ssh_buffer_free(buffer);
        return NULL;
    }

    rc = ssh_buffer_pack(buffer,
                         "dPbsssbsS",
                         crypto->digest_len, /* session ID string */
                         (size_t)crypto->digest_len, crypto->session_id,
                         SSH2_MSG_USERAUTH_REQUEST, /* type */
                         msg->auth_request.username,
                         service,
                         "publickey", /* method */
                         1, /* has to be signed (true) */
                         msg->auth_request.pubkey->type_c, /* pubkey algorithm */
                         str); /* public key as a blob */

    ssh_string_free(str);
    if (rc != SSH_OK) {
        ssh_set_error_oom(session);
        ssh_buffer_free(buffer);
        return NULL;
    }

    return buffer;
}

/**
 * @internal
 *
 * @brief Handle a SSH_MSG_MSG_USERAUTH_REQUEST packet and queue a
 * SSH Message
 */
SSH_PACKET_CALLBACK(ssh_packet_userauth_request){
  ssh_message msg = NULL;
  char *service = NULL;
  char *method = NULL;
  int rc;

  (void)user;
  (void)type;

  msg = ssh_message_new(session);
  if (msg == NULL) {
    ssh_set_error_oom(session);
    goto error;
  }
  msg->type = SSH_REQUEST_AUTH;
  rc = ssh_buffer_unpack(packet,
                         "sss",
                         &msg->auth_request.username,
                         &service,
                         &method);

  if (rc != SSH_OK) {
      goto error;
  }

  SSH_LOG(SSH_LOG_PACKET,
      "Auth request for service %s, method %s for user '%s'",
      service, method,
      msg->auth_request.username);


  if (strcmp(method, "none") == 0) {
    msg->auth_request.method = SSH_AUTH_METHOD_NONE;
    goto end;
  }

  if (strcmp(method, "password") == 0) {
    uint8_t tmp;

    msg->auth_request.method = SSH_AUTH_METHOD_PASSWORD;
    rc = ssh_buffer_unpack(packet, "bs", &tmp, &msg->auth_request.password);
    if (rc != SSH_OK) {
      goto error;
    }
    goto end;
  }

  if (strcmp(method, "keyboard-interactive") == 0) {
    ssh_string lang = NULL;
    ssh_string submethods = NULL;

    msg->auth_request.method = SSH_AUTH_METHOD_INTERACTIVE;
    lang = buffer_get_ssh_string(packet);
    if (lang == NULL) {
      goto error;
    }
    /* from the RFC 4256
     * 3.1.  Initial Exchange
     * "The language tag is deprecated and SHOULD be the empty string."
     */
    ssh_string_free(lang);

    submethods = buffer_get_ssh_string(packet);
    if (submethods == NULL) {
      goto error;
    }
    /* from the RFC 4256
     * 3.1.  Initial Exchange
     * "One possible implementation strategy of the submethods field on the
     *  server is that, unless the user may use multiple different
     *  submethods, the server ignores this field."
     */
    ssh_string_free(submethods);

    goto end;
  }

  if (strcmp(method, "publickey") == 0) {
    ssh_string algo = NULL;
    ssh_string pubkey_blob = NULL;
    uint8_t has_sign;

    msg->auth_request.method = SSH_AUTH_METHOD_PUBLICKEY;
    SAFE_FREE(method);
    rc = ssh_buffer_unpack(packet, "bSS",
            &has_sign,
            &algo,
            &pubkey_blob
            );

    if (rc != SSH_OK) {
      goto error;
    }
    ssh_string_free(algo);
    algo = NULL;

    rc = ssh_pki_import_pubkey_blob(pubkey_blob, &msg->auth_request.pubkey);
    ssh_string_free(pubkey_blob);
    pubkey_blob = NULL;
    if (rc < 0) {
        goto error;
    }
    msg->auth_request.signature_state = SSH_PUBLICKEY_STATE_NONE;
    // has a valid signature ?
    if(has_sign) {
        ssh_string sig_blob = NULL;
        ssh_buffer digest = NULL;

        sig_blob = buffer_get_ssh_string(packet);
        if(sig_blob == NULL) {
            SSH_LOG(SSH_LOG_PACKET, "Invalid signature packet from peer");
            msg->auth_request.signature_state = SSH_PUBLICKEY_STATE_ERROR;
            goto error;
        }

        digest = ssh_msg_userauth_build_digest(session, msg, service);
        if (digest == NULL) {
            ssh_string_free(sig_blob);
            SSH_LOG(SSH_LOG_PACKET, "Failed to get digest");
            msg->auth_request.signature_state = SSH_PUBLICKEY_STATE_WRONG;
            goto error;
        }

        rc = ssh_pki_signature_verify_blob(session,
                                           sig_blob,
                                           msg->auth_request.pubkey,
                                           buffer_get_rest(digest),
                                           buffer_get_rest_len(digest));
        ssh_string_free(sig_blob);
        ssh_buffer_free(digest);
        if (rc < 0) {
            SSH_LOG(
                    SSH_LOG_PACKET,
                    "Received an invalid  signature from peer");
            msg->auth_request.signature_state = SSH_PUBLICKEY_STATE_WRONG;
            goto error;
        }

        SSH_LOG(SSH_LOG_PACKET, "Valid signature received");

        msg->auth_request.signature_state = SSH_PUBLICKEY_STATE_VALID;
    }
    goto end;
  }
#ifdef WITH_GSSAPI
  if (strcmp(method, "gssapi-with-mic") == 0) {
     uint32_t n_oid;
     ssh_string *oids;
     ssh_string oid;
     char *hexa;
     int i;
     buffer_get_u32(packet, &n_oid);
     n_oid=ntohl(n_oid);
     if(n_oid > 100){
    	 ssh_set_error(session, SSH_FATAL, "USERAUTH_REQUEST: gssapi-with-mic OID count too big (%d)",n_oid);
    	 goto error;
     }
     SSH_LOG(SSH_LOG_PACKET, "gssapi: %d OIDs", n_oid);
     oids = calloc(n_oid, sizeof(ssh_string));
     if (oids == NULL){
    	 ssh_set_error_oom(session);
    	 goto error;
     }
     for (i=0;i<(int) n_oid;++i){
    	 oid=buffer_get_ssh_string(packet);
    	 if(oid == NULL){
    		 for(i=i-1;i>=0;--i){
    			 SAFE_FREE(oids[i]);
    		 }
    		 SAFE_FREE(oids);
    		 ssh_set_error(session, SSH_LOG_PACKET, "USERAUTH_REQUEST: gssapi-with-mic missing OID");
    		 goto error;
    	 }
    	 oids[i] = oid;
    	 if(session->common.log_verbosity >= SSH_LOG_PACKET){
    		 hexa = ssh_get_hexa(ssh_string_data(oid), ssh_string_len(oid));
    		 SSH_LOG(SSH_LOG_PACKET,"gssapi: OID %d: %s",i, hexa);
    		 SAFE_FREE(hexa);
    	 }
     }
     ssh_gssapi_handle_userauth(session, msg->auth_request.username, n_oid, oids);

     for(i=0;i<(int)n_oid;++i){
    	 SAFE_FREE(oids[i]);
     }
     SAFE_FREE(oids);
     /* bypass the message queue thing */
     SAFE_FREE(service);
     SAFE_FREE(method);
     ssh_message_free(msg);

     return SSH_PACKET_USED;
  }
#endif

  msg->auth_request.method = SSH_AUTH_METHOD_UNKNOWN;
  SAFE_FREE(method);
  goto end;
error:
  SAFE_FREE(service);
  SAFE_FREE(method);

  ssh_message_free(msg);

  return SSH_PACKET_USED;
end:
  SAFE_FREE(service);
  SAFE_FREE(method);

  ssh_message_queue(session,msg);

  return SSH_PACKET_USED;
}

#endif /* WITH_SERVER */
/**
 * @internal
 *
 * @brief Handle a SSH_MSG_MSG_USERAUTH_INFO_RESPONSE packet and queue a
 * SSH Message
 */
#ifndef WITH_SERVER
SSH_PACKET_CALLBACK(ssh_packet_userauth_info_response){
    (void)session;
    (void)type;
    (void)packet;
    (void)user;
    return SSH_PACKET_USED;
}
#else /* WITH_SERVER */
SSH_PACKET_CALLBACK(ssh_packet_userauth_info_response){
  uint32_t nanswers;
  uint32_t i;
  ssh_string tmp;
  int rc;

  ssh_message msg = NULL;

  /* GSSAPI_TOKEN has same packed number. XXX fix this */
#ifdef WITH_GSSAPI
  if (session->gssapi != NULL) {
      return ssh_packet_userauth_gssapi_token(session, type, packet, user);
  }
#endif
  (void)user;
  (void)type;

  msg = ssh_message_new(session);
  if (msg == NULL) {
    ssh_set_error_oom(session);
    goto error;
  }

  /* HACK: we forge a message to be able to handle it in the
   * same switch() as other auth methods */
  msg->type = SSH_REQUEST_AUTH;
  msg->auth_request.method = SSH_AUTH_METHOD_INTERACTIVE;
  msg->auth_request.kbdint_response = 1;
#if 0 // should we wipe the username ?
  msg->auth_request.username = NULL;
#endif

  rc = ssh_buffer_unpack(packet, "d", &nanswers);
  if (rc != SSH_OK) {
      ssh_set_error_invalid(session);
      goto error;
  }

  if (session->kbdint == NULL) {
    SSH_LOG(SSH_LOG_PROTOCOL, "Warning: Got a keyboard-interactive "
                        "response but it seems we didn't send the request.");

    session->kbdint = ssh_kbdint_new();
    if (session->kbdint == NULL) {
      ssh_set_error_oom(session);

      goto error;
    }
  }

  SSH_LOG(SSH_LOG_PACKET,"kbdint: %d answers",nanswers);
  if (nanswers > KBDINT_MAX_PROMPT) {
    ssh_set_error(session, SSH_FATAL,
        "Too much answers received from client: %u (0x%.4x)",
        nanswers, nanswers);
    ssh_kbdint_free(session->kbdint);
    session->kbdint = NULL;

    goto error;
  }

  if(nanswers != session->kbdint->nprompts) {
    /* warn but let the application handle this case */
    SSH_LOG(SSH_LOG_PROTOCOL, "Warning: Number of prompts and answers"
                " mismatch: p=%u a=%u", session->kbdint->nprompts, nanswers);
  }
  session->kbdint->nanswers = nanswers;
  session->kbdint->answers = malloc(nanswers * sizeof(char *));
  if (session->kbdint->answers == NULL) {
    session->kbdint->nanswers = 0;
    ssh_set_error_oom(session);
    ssh_kbdint_free(session->kbdint);
    session->kbdint = NULL;

    goto error;
  }
  memset(session->kbdint->answers, 0, nanswers * sizeof(char *));

  for (i = 0; i < nanswers; i++) {
    tmp = buffer_get_ssh_string(packet);
    if (tmp == NULL) {
      ssh_set_error(session, SSH_FATAL, "Short INFO_RESPONSE packet");
      session->kbdint->nanswers = i;
      ssh_kbdint_free(session->kbdint);
      session->kbdint = NULL;

      goto error;
    }
    session->kbdint->answers[i] = ssh_string_to_char(tmp);
    ssh_string_free(tmp);
    if (session->kbdint->answers[i] == NULL) {
      ssh_set_error_oom(session);
      session->kbdint->nanswers = i;
      ssh_kbdint_free(session->kbdint);
      session->kbdint = NULL;

      goto error;
    }
  }

  ssh_message_queue(session,msg);

  return SSH_PACKET_USED;

error:
  ssh_message_free(msg);

  return SSH_PACKET_USED;
}
#endif /* WITH_SERVER */

SSH_PACKET_CALLBACK(ssh_packet_channel_open){
  ssh_message msg = NULL;
  char *type_c = NULL;
  uint32_t originator_port, destination_port;
  int rc;

  (void)type;
  (void)user;
  msg = ssh_message_new(session);
  if (msg == NULL) {
    ssh_set_error_oom(session);
    goto error;
  }

  msg->type = SSH_REQUEST_CHANNEL_OPEN;
  rc = ssh_buffer_unpack(packet, "s", &type_c);
  if (rc != SSH_OK){
      goto error;
  }

  SSH_LOG(SSH_LOG_PACKET,
      "Clients wants to open a %s channel", type_c);

  ssh_buffer_unpack(packet,"ddd",
          &msg->channel_request_open.sender,
          &msg->channel_request_open.window,
          &msg->channel_request_open.packet_size);

  if (session->session_state != SSH_SESSION_STATE_AUTHENTICATED){
    ssh_set_error(session,SSH_FATAL, "Invalid state when receiving channel open request (must be authenticated)");
    goto error;
  }
  
  if (strcmp(type_c,"session") == 0) {
    msg->channel_request_open.type = SSH_CHANNEL_SESSION;
    SAFE_FREE(type_c);
    goto end;
  }

  if (strcmp(type_c,"direct-tcpip") == 0) {
    rc = ssh_buffer_unpack(packet,
                           "sdsd",
                           &msg->channel_request_open.destination,
                           &destination_port,
                           &msg->channel_request_open.originator,
                           &originator_port);
	if (rc != SSH_OK) {
		goto error;
	}

    msg->channel_request_open.destination_port = (uint16_t) destination_port;
    msg->channel_request_open.originator_port = (uint16_t) originator_port;
    msg->channel_request_open.type = SSH_CHANNEL_DIRECT_TCPIP;
    goto end;
  }

  if (strcmp(type_c,"forwarded-tcpip") == 0) {
    rc = ssh_buffer_unpack(packet, "sdsd",
            &msg->channel_request_open.destination,
            &destination_port,
            &msg->channel_request_open.originator,
            &originator_port
        );
    if (rc != SSH_OK){
        goto error;
    }
    msg->channel_request_open.destination_port = (uint16_t) destination_port;
    msg->channel_request_open.originator_port = (uint16_t) originator_port;
    msg->channel_request_open.type = SSH_CHANNEL_FORWARDED_TCPIP;
    goto end;
  }

  if (strcmp(type_c,"x11") == 0) {
    rc = ssh_buffer_unpack(packet, "sd",
            &msg->channel_request_open.originator,
            &originator_port);
    if (rc != SSH_OK){
        goto error;
    }
    msg->channel_request_open.originator_port = (uint16_t) originator_port;
    msg->channel_request_open.type = SSH_CHANNEL_X11;
    goto end;
  }

  msg->channel_request_open.type = SSH_CHANNEL_UNKNOWN;
  goto end;

error:
  ssh_message_free(msg);
  msg=NULL;
end:
  SAFE_FREE(type_c);
  if(msg != NULL)
    ssh_message_queue(session,msg);

  return SSH_PACKET_USED;
}

int ssh_message_channel_request_open_reply_accept_channel(ssh_message msg, ssh_channel chan) {
    ssh_session session;
    int rc;

    if (msg == NULL) {
        return SSH_ERROR;
    }

    session = msg->session;

    chan->local_channel = ssh_channel_new_id(session);
    chan->local_maxpacket = 35000;
    chan->local_window = 32000;
    chan->remote_channel = msg->channel_request_open.sender;
    chan->remote_maxpacket = msg->channel_request_open.packet_size;
    chan->remote_window = msg->channel_request_open.window;
    chan->state = SSH_CHANNEL_STATE_OPEN;

    rc = ssh_buffer_pack(session->out_buffer,
                         "bdddd",
                         SSH2_MSG_CHANNEL_OPEN_CONFIRMATION,
                         chan->remote_channel,
                         chan->local_channel,
                         chan->local_window,
                         chan->local_maxpacket);
    if (rc != SSH_OK) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }

    SSH_LOG(SSH_LOG_PACKET,
            "Accepting a channel request_open for chan %d",
            chan->remote_channel);

    rc = packet_send(session);

    return rc;
}


ssh_channel ssh_message_channel_request_open_reply_accept(ssh_message msg) {
	ssh_channel chan;
	int rc;

	if (msg == NULL) {
	    return NULL;
	}

	chan = ssh_channel_new(msg->session);
	if (chan == NULL) {
		return NULL;
	}
	rc = ssh_message_channel_request_open_reply_accept_channel(msg, chan);
	if (rc < 0) {
		ssh_channel_free(chan);
		chan = NULL;
	}
	return chan;

}

/**
 * @internal
 *
 * @brief This function parses the last end of a channel request packet.
 *
 * This is normally converted to a SSH message and placed in the queue.
 *
 * @param[in]  session  The SSH session.
 *
 * @param[in]  channel  The channel the request is made on.
 *
 * @param[in]  packet   The rest of the packet to be parsed.
 *
 * @param[in]  request  The type of request.
 *
 * @param[in]  want_reply The want_reply field from the request.
 *
 * @returns             SSH_OK on success, SSH_ERROR if an error occured.
 */
int ssh_message_handle_channel_request(ssh_session session, ssh_channel channel, ssh_buffer packet,
    const char *request, uint8_t want_reply) {
  ssh_message msg = NULL;
  int rc;

  msg = ssh_message_new(session);
  if (msg == NULL) {
    ssh_set_error_oom(session);
    goto error;
  }

  SSH_LOG(SSH_LOG_PACKET,
      "Received a %s channel_request for channel (%d:%d) (want_reply=%hhd)",
      request, channel->local_channel, channel->remote_channel, want_reply);

  msg->type = SSH_REQUEST_CHANNEL;
  msg->channel_request.channel = channel;
  msg->channel_request.want_reply = want_reply;

  if (strcmp(request, "pty-req") == 0) {
    rc = ssh_buffer_unpack(packet, "sddddS",
            &msg->channel_request.TERM,
            &msg->channel_request.width,
            &msg->channel_request.height,
            &msg->channel_request.pxwidth,
            &msg->channel_request.pxheight,
            &msg->channel_request.modes
            );

    msg->channel_request.type = SSH_CHANNEL_REQUEST_PTY;

    if (rc != SSH_OK) {
      goto error;
    }
    goto end;
  }

  if (strcmp(request, "window-change") == 0) {
    msg->channel_request.type = SSH_CHANNEL_REQUEST_WINDOW_CHANGE;
    rc = ssh_buffer_unpack(packet, "dddd",
            &msg->channel_request.width,
            &msg->channel_request.height,
            &msg->channel_request.pxwidth,
            &msg->channel_request.pxheight);
    if (rc != SSH_OK){
        goto error;
    }
    goto end;
  }

  if (strcmp(request, "subsystem") == 0) {
    rc = ssh_buffer_unpack(packet, "s",
            &msg->channel_request.subsystem);
    msg->channel_request.type = SSH_CHANNEL_REQUEST_SUBSYSTEM;
    if (rc != SSH_OK){
        goto error;
    }
    goto end;
  }

  if (strcmp(request, "shell") == 0) {
    msg->channel_request.type = SSH_CHANNEL_REQUEST_SHELL;
    goto end;
  }

  if (strcmp(request, "exec") == 0) {
    rc = ssh_buffer_unpack(packet, "s",
            &msg->channel_request.command);
    msg->channel_request.type = SSH_CHANNEL_REQUEST_EXEC;
    if (rc != SSH_OK) {
      goto error;
    }
    goto end;
  }

  if (strcmp(request, "env") == 0) {
    rc = ssh_buffer_unpack(packet, "ss",
            &msg->channel_request.var_name,
            &msg->channel_request.var_value);
    msg->channel_request.type = SSH_CHANNEL_REQUEST_ENV;
    if (rc != SSH_OK) {
      goto error;
    }
    goto end;
  }

  if (strcmp(request, "x11-req") == 0) {
    rc = ssh_buffer_unpack(packet, "bssd",
            &msg->channel_request.x11_single_connection,
            &msg->channel_request.x11_auth_protocol,
            &msg->channel_request.x11_auth_cookie,
            &msg->channel_request.x11_screen_number);

    msg->channel_request.type = SSH_CHANNEL_REQUEST_X11;
    if (rc != SSH_OK) {
      goto error;
    }

    goto end;
  }

  msg->channel_request.type = SSH_CHANNEL_REQUEST_UNKNOWN;
end:
  ssh_message_queue(session,msg);

  return SSH_OK;
error:
  ssh_message_free(msg);

  return SSH_ERROR;
}

int ssh_message_channel_request_reply_success(ssh_message msg) {
  uint32_t channel;
  int rc;

  if (msg == NULL) {
    return SSH_ERROR;
  }

  if (msg->channel_request.want_reply) {
    channel = msg->channel_request.channel->remote_channel;

    SSH_LOG(SSH_LOG_PACKET,
        "Sending a channel_request success to channel %d", channel);

    rc = ssh_buffer_pack(msg->session->out_buffer,
                         "bd",
                         SSH2_MSG_CHANNEL_SUCCESS,
                         channel);
    if (rc != SSH_OK){
      ssh_set_error_oom(msg->session);
      return SSH_ERROR;
    }

    return packet_send(msg->session);
  }

  SSH_LOG(SSH_LOG_PACKET,
      "The client doesn't want to know the request succeeded");

  return SSH_OK;
}

#ifdef WITH_SERVER
SSH_PACKET_CALLBACK(ssh_packet_global_request){
    ssh_message msg = NULL;
    char *request=NULL;
    uint8_t want_reply;
    int rc = SSH_PACKET_USED;
    int r;
    (void)user;
    (void)type;
    (void)packet;

    SSH_LOG(SSH_LOG_PROTOCOL,"Received SSH_MSG_GLOBAL_REQUEST packet");
    r = ssh_buffer_unpack(packet, "sb",
            &request,
            &want_reply);
    if (r != SSH_OK){
        goto error;
    }

    msg = ssh_message_new(session);
    if (msg == NULL) {
        ssh_set_error_oom(session);
        goto error;
    }
    msg->type = SSH_REQUEST_GLOBAL;

    if (strcmp(request, "tcpip-forward") == 0) {
        r = ssh_buffer_unpack(packet, "sd",
                &msg->global_request.bind_address,
                &msg->global_request.bind_port
                );
        if (r != SSH_OK){
            goto error;
        }
        msg->global_request.type = SSH_GLOBAL_REQUEST_TCPIP_FORWARD;
        msg->global_request.want_reply = want_reply;

        SSH_LOG(SSH_LOG_PROTOCOL, "Received SSH_MSG_GLOBAL_REQUEST %s %d %s:%d", request, want_reply,
                msg->global_request.bind_address,
                msg->global_request.bind_port);

        if(ssh_callbacks_exists(session->common.callbacks, global_request_function)) {
            SSH_LOG(SSH_LOG_PROTOCOL, "Calling callback for SSH_MSG_GLOBAL_REQUEST %s %d %s:%d", request,
                    want_reply, msg->global_request.bind_address,
                    msg->global_request.bind_port);
            session->common.callbacks->global_request_function(session, msg, session->common.callbacks->userdata);
        } else {
            ssh_message_reply_default(msg);
        }
    } else if (strcmp(request, "cancel-tcpip-forward") == 0) {
        r = ssh_buffer_unpack(packet, "sd",
                &msg->global_request.bind_address,
                &msg->global_request.bind_port);
        if (r != SSH_OK){
            goto error;
        }
        msg->global_request.type = SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD;
        msg->global_request.want_reply = want_reply;

        SSH_LOG(SSH_LOG_PROTOCOL, "Received SSH_MSG_GLOBAL_REQUEST %s %d %s:%d", request, want_reply,
                msg->global_request.bind_address,
                msg->global_request.bind_port);

        if(ssh_callbacks_exists(session->common.callbacks, global_request_function)) {
            session->common.callbacks->global_request_function(session, msg, session->common.callbacks->userdata);
        } else {
            ssh_message_reply_default(msg);
        }
    } else {
        SSH_LOG(SSH_LOG_PROTOCOL, "UNKNOWN SSH_MSG_GLOBAL_REQUEST %s %d", request, want_reply);
        rc = SSH_PACKET_NOT_USED;
    }

    SAFE_FREE(msg);
    SAFE_FREE(request);
    return rc;
error:
    SAFE_FREE(msg);
    SAFE_FREE(request);
    SSH_LOG(SSH_LOG_WARNING, "Invalid SSH_MSG_GLOBAL_REQUEST packet");
    return SSH_PACKET_NOT_USED;
}

#endif /* WITH_SERVER */

/** @} */

/* vim: set ts=4 sw=4 et cindent: */
