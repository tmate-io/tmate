/*
 * client.c - SSH client functions
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "libssh/priv.h"
#include "libssh/ssh2.h"
#include "libssh/buffer.h"
#include "libssh/packet.h"
#include "libssh/options.h"
#include "libssh/socket.h"
#include "libssh/session.h"
#include "libssh/dh.h"
#include "libssh/ecdh.h"
#include "libssh/threads.h"
#include "libssh/misc.h"
#include "libssh/pki.h"
#include "libssh/kex.h"

#define set_status(session, status) do {\
        if (session->common.callbacks && session->common.callbacks->connect_status_function) \
            session->common.callbacks->connect_status_function(session->common.callbacks->userdata, status); \
    } while (0)

/**
 * @internal
 * @brief Callback to be called when the socket is connected or had a
 * connection error. Changes the state of the session and updates the error
 * message.
 * @param code one of SSH_SOCKET_CONNECTED_OK or SSH_SOCKET_CONNECTED_ERROR
 * @param user is a pointer to session
 */
static void socket_callback_connected(int code, int errno_code, void *user){
	ssh_session session=(ssh_session)user;

	if (session->session_state != SSH_SESSION_STATE_CONNECTING &&
	    session->session_state != SSH_SESSION_STATE_SOCKET_CONNECTED)
	{
		ssh_set_error(session,SSH_FATAL, "Wrong state in socket_callback_connected : %d",
				session->session_state);

		return;
	}

	SSH_LOG(SSH_LOG_RARE,"Socket connection callback: %d (%d)",code, errno_code);
	if(code == SSH_SOCKET_CONNECTED_OK)
		session->session_state=SSH_SESSION_STATE_SOCKET_CONNECTED;
	else {
		session->session_state=SSH_SESSION_STATE_ERROR;
		ssh_set_error(session,SSH_FATAL,"%s",strerror(errno_code));
	}
	session->ssh_connection_callback(session);
}

/**
 * @internal
 *
 * @brief Gets the banner from socket and saves it in session.
 * Updates the session state
 *
 * @param  data pointer to the beginning of header
 * @param  len size of the banner
 * @param  user is a pointer to session
 * @returns Number of bytes processed, or zero if the banner is not complete.
 */
static int callback_receive_banner(const void *data, size_t len, void *user) {
  char *buffer = (char *)data;
  ssh_session session=(ssh_session) user;
  char *str = NULL;
  size_t i;
  int ret=0;

  if(session->session_state != SSH_SESSION_STATE_SOCKET_CONNECTED){
  	ssh_set_error(session,SSH_FATAL,"Wrong state in callback_receive_banner : %d",session->session_state);

  	return SSH_ERROR;
  }
  for(i=0;i<len;++i){
#ifdef WITH_PCAP
  	if(session->pcap_ctx && buffer[i] == '\n'){
  		ssh_pcap_context_write(session->pcap_ctx,SSH_PCAP_DIR_IN,buffer,i+1,i+1);
  	}
#endif
    if(buffer[i]=='\r') {
        buffer[i]='\0';
    }
    if (buffer[i]=='\n') {
        buffer[i] = '\0';
        str = strdup(buffer);
        if (str == NULL) {
            return SSH_ERROR;
        }
        /* number of bytes read */
        ret = i + 1;
        session->serverbanner = str;
  		session->session_state=SSH_SESSION_STATE_BANNER_RECEIVED;
  		SSH_LOG(SSH_LOG_PACKET,"Received banner: %s",str);
		session->ssh_connection_callback(session);

  		return ret;
  	}
  	if(i>127){
  		/* Too big banner */
  		session->session_state=SSH_SESSION_STATE_ERROR;
  		ssh_set_error(session,SSH_FATAL,"Receiving banner: too large banner");

  		return 0;
  	}
  }

  return ret;
}

/** @internal
 * @brief Sends a SSH banner to the server.
 *
 * @param session      The SSH session to use.
 *
 * @param server       Send client or server banner.
 *
 * @return 0 on success, < 0 on error.
 */
int ssh_send_banner(ssh_session session, int server) {
  const char *banner = NULL;
  char buffer[128] = {0};
  int err=SSH_ERROR;

  banner = session->version == 1 ? CLIENTBANNER1 : CLIENTBANNER2;

  if (server) {
    if(session->opts.custombanner == NULL){
    	session->serverbanner = strdup(banner);
    } else {
    	session->serverbanner = malloc(strlen(session->opts.custombanner) + 9);
    	if(!session->serverbanner)
    		goto end;
    	strcpy(session->serverbanner, "SSH-2.0-");
    	strcat(session->serverbanner, session->opts.custombanner);
    }
    if (session->serverbanner == NULL) {
      goto end;
    }
    snprintf(buffer, 128, "%s\n", session->serverbanner);
  } else {
    session->clientbanner = strdup(banner);
    if (session->clientbanner == NULL) {
      goto end;
    }
    snprintf(buffer, 128, "%s\n", session->clientbanner);
  }

  if (ssh_socket_write(session->socket, buffer, strlen(buffer)) == SSH_ERROR) {
    goto end;
  }
#ifdef WITH_PCAP
  if(session->pcap_ctx)
  	ssh_pcap_context_write(session->pcap_ctx,SSH_PCAP_DIR_OUT,buffer,strlen(buffer),strlen(buffer));
#endif
  err=SSH_OK;
end:

  return err;
}

/** @internal
 * @brief launches the DH handshake state machine
 * @param session session handle
 * @returns SSH_OK or SSH_ERROR
 * @warning this function returning is no proof that DH handshake is
 * completed
 */
static int dh_handshake(ssh_session session) {

  int rc = SSH_AGAIN;

  switch (session->dh_handshake_state) {
    case DH_STATE_INIT:
      switch(session->next_crypto->kex_type){
        case SSH_KEX_DH_GROUP1_SHA1:
        case SSH_KEX_DH_GROUP14_SHA1:
          rc = ssh_client_dh_init(session);
          break;
#ifdef HAVE_ECDH
        case SSH_KEX_ECDH_SHA2_NISTP256:
          rc = ssh_client_ecdh_init(session);
          break;
#endif
#ifdef HAVE_CURVE25519
        case SSH_KEX_CURVE25519_SHA256_LIBSSH_ORG:
          rc = ssh_client_curve25519_init(session);
          break;
#endif
        default:
          rc = SSH_ERROR;
      }

      if (rc == SSH_ERROR) {
          return SSH_ERROR;
      }

      session->dh_handshake_state = DH_STATE_INIT_SENT;
    case DH_STATE_INIT_SENT:
    	/* wait until ssh_packet_dh_reply is called */
    	break;
    case DH_STATE_NEWKEYS_SENT:
    	/* wait until ssh_packet_newkeys is called */
    	break;
    case DH_STATE_FINISHED:
      return SSH_OK;
    default:
      ssh_set_error(session, SSH_FATAL, "Invalid state in dh_handshake(): %d",
          session->dh_handshake_state);

      return SSH_ERROR;
  }

  return rc;
}

static int ssh_service_request_termination(void *s){
  ssh_session session = (ssh_session)s;
  if(session->session_state == SSH_SESSION_STATE_ERROR ||
      session->auth_service_state != SSH_AUTH_SERVICE_SENT)
    return 1;
  else
    return 0;
}

/**
 * @internal
 *
 * @brief Request a service from the SSH server.
 *
 * Service requests are for example: ssh-userauth, ssh-connection, etc.
 *
 * @param  session      The session to use to ask for a service request.
 * @param  service      The service request.
 *
 * @return SSH_OK on success
 * @return SSH_ERROR on error
 * @return SSH_AGAIN No response received yet
 * @bug actually only works with ssh-userauth
 */
int ssh_service_request(ssh_session session, const char *service) {
  int rc=SSH_ERROR;

  if(session->auth_service_state != SSH_AUTH_SERVICE_NONE)
    goto pending;

  rc = ssh_buffer_pack(session->out_buffer,
                       "bs",
                       SSH2_MSG_SERVICE_REQUEST,
                       service);
  if (rc != SSH_OK){
      ssh_set_error_oom(session);
      return SSH_ERROR;
  }
  session->auth_service_state=SSH_AUTH_SERVICE_SENT;
  if (packet_send(session) == SSH_ERROR) {
    ssh_set_error(session, SSH_FATAL,
        "Sending SSH2_MSG_SERVICE_REQUEST failed.");
      return SSH_ERROR;
  }

  SSH_LOG(SSH_LOG_PACKET,
      "Sent SSH_MSG_SERVICE_REQUEST (service %s)", service);
pending:
  rc=ssh_handle_packets_termination(session,SSH_TIMEOUT_USER,
      ssh_service_request_termination, session);
  if (rc == SSH_ERROR) {
      return SSH_ERROR;
  }
  switch(session->auth_service_state){
  case SSH_AUTH_SERVICE_DENIED:
    ssh_set_error(session,SSH_FATAL,"ssh_auth_service request denied");
    break;
  case SSH_AUTH_SERVICE_ACCEPTED:
    rc=SSH_OK;
    break;
  case SSH_AUTH_SERVICE_SENT:
    rc=SSH_AGAIN;
    break;
  case SSH_AUTH_SERVICE_NONE:
  case SSH_AUTH_SERVICE_USER_SENT:
    /* Invalid state, SSH1 specific */
    rc=SSH_ERROR;
    break;
  }

  return rc;
}

/**
 * @addtogroup libssh_session
 *
 * @{
 */

/**
 * @internal
 *
 * @brief A function to be called each time a step has been done in the
 * connection.
 */
static void ssh_client_connection_callback(ssh_session session){
	int ssh1,ssh2;

	switch(session->session_state){
		case SSH_SESSION_STATE_NONE:
		case SSH_SESSION_STATE_CONNECTING:
		case SSH_SESSION_STATE_SOCKET_CONNECTED:
			break;
		case SSH_SESSION_STATE_BANNER_RECEIVED:
		  if (session->serverbanner == NULL) {
		    goto error;
		  }
		  set_status(session, 0.4f);
		  SSH_LOG(SSH_LOG_RARE,
		      "SSH server banner: %s", session->serverbanner);

		  /* Here we analyze the different protocols the server allows. */
		  if (ssh_analyze_banner(session, 0, &ssh1, &ssh2) < 0) {
		    goto error;
		  }
		  /* Here we decide which version of the protocol to use. */
		  if (ssh2 && session->opts.ssh2) {
		    session->version = 2;
#ifdef WITH_SSH1
		    } else if(ssh1 && session->opts.ssh1) {
		    session->version = 1;
#endif
		    } else if(ssh1 && !session->opts.ssh1){
#ifdef WITH_SSH1
		    ssh_set_error(session, SSH_FATAL,
		        "SSH-1 protocol not available (configure session to allow SSH-1)");
		    goto error;
#else
		    ssh_set_error(session, SSH_FATAL,
		        "SSH-1 protocol not available (libssh compiled without SSH-1 support)");
		    goto error;
#endif
		  } else {
		    ssh_set_error(session, SSH_FATAL,
		        "No version of SSH protocol usable (banner: %s)",
		        session->serverbanner);
		    goto error;
		  }
		  /* from now, the packet layer is handling incoming packets */
		  if(session->version==2)
		    session->socket_callbacks.data=ssh_packet_socket_callback;
#ifdef WITH_SSH1
		  else
		    session->socket_callbacks.data=ssh_packet_socket_callback1;
#endif
		  ssh_packet_set_default_callbacks(session);
		  session->session_state=SSH_SESSION_STATE_INITIAL_KEX;
		  ssh_send_banner(session, 0);
		  set_status(session, 0.5f);
		  break;
		case SSH_SESSION_STATE_INITIAL_KEX:
		/* TODO: This state should disappear in favor of get_key handle */
#ifdef WITH_SSH1
			if(session->version==1){
				if (ssh_get_kex1(session) < 0)
					goto error;
				set_status(session,0.6f);
				session->connected = 1;
				break;
			}
#endif
			break;
		case SSH_SESSION_STATE_KEXINIT_RECEIVED:
			set_status(session,0.6f);
			ssh_list_kex(&session->next_crypto->server_kex);
			if (set_client_kex(session) < 0) {
				goto error;
			}
			if (ssh_kex_select_methods(session) == SSH_ERROR)
			    goto error;
			if (ssh_send_kex(session, 0) < 0) {
				goto error;
			}
			set_status(session,0.8f);
			session->session_state=SSH_SESSION_STATE_DH;
			if (dh_handshake(session) == SSH_ERROR) {
				goto error;
			}
            /* FALL THROUGH */
		case SSH_SESSION_STATE_DH:
			if(session->dh_handshake_state==DH_STATE_FINISHED){
				set_status(session,1.0f);
				session->connected = 1;
				if (session->flags & SSH_SESSION_FLAG_AUTHENTICATED)
				    session->session_state = SSH_SESSION_STATE_AUTHENTICATED;
				else
				    session->session_state=SSH_SESSION_STATE_AUTHENTICATING;
			}
			break;
		case SSH_SESSION_STATE_AUTHENTICATING:
			break;
		case SSH_SESSION_STATE_ERROR:
			goto error;
		default:
			ssh_set_error(session,SSH_FATAL,"Invalid state %d",session->session_state);
	}

	return;
error:
	ssh_socket_close(session->socket);
	session->alive = 0;
	session->session_state=SSH_SESSION_STATE_ERROR;

}

/** @internal
 * @brief describe under which conditions the ssh_connect function may stop
 */
static int ssh_connect_termination(void *user){
  ssh_session session = (ssh_session)user;
  switch(session->session_state){
    case SSH_SESSION_STATE_ERROR:
    case SSH_SESSION_STATE_AUTHENTICATING:
    case SSH_SESSION_STATE_DISCONNECTED:
      return 1;
    default:
      return 0;
  }
}

/**
 * @brief Connect to the ssh server.
 *
 * @param[in]  session  The ssh session to connect.
 *
 * @returns             SSH_OK on success, SSH_ERROR on error.
 * @returns 						SSH_AGAIN, if the session is in nonblocking mode,
 * 											and call must be done again.
 *
 * @see ssh_new()
 * @see ssh_disconnect()
 */
int ssh_connect(ssh_session session) {
  int ret;

  if (session == NULL) {
    return SSH_ERROR;
  }

  switch(session->pending_call_state){
  case SSH_PENDING_CALL_NONE:
  	break;
  case SSH_PENDING_CALL_CONNECT:
  	goto pending;
  default:
  	ssh_set_error(session,SSH_FATAL,"Bad call during pending SSH call in ssh_connect");

  	return SSH_ERROR;
  }
  session->alive = 0;
  session->client = 1;

  if (ssh_init() < 0) {
    return SSH_ERROR;
  }
  if (session->opts.fd == SSH_INVALID_SOCKET &&
      session->opts.host == NULL &&
      session->opts.ProxyCommand == NULL) {
    ssh_set_error(session, SSH_FATAL, "Hostname required");
    return SSH_ERROR;
  }

  ret = ssh_options_apply(session);
  if (ret < 0) {
      ssh_set_error(session, SSH_FATAL, "Couldn't apply options");
      return SSH_ERROR;
  }

  SSH_LOG(SSH_LOG_PROTOCOL,
          "libssh %s, using threading %s",
          ssh_copyright(),
          ssh_threads_get_type());

  session->ssh_connection_callback = ssh_client_connection_callback;
  session->session_state=SSH_SESSION_STATE_CONNECTING;
  ssh_socket_set_callbacks(session->socket,&session->socket_callbacks);
  session->socket_callbacks.connected=socket_callback_connected;
  session->socket_callbacks.data=callback_receive_banner;
  session->socket_callbacks.exception=ssh_socket_exception_callback;
  session->socket_callbacks.userdata=session;
  if (session->opts.fd != SSH_INVALID_SOCKET) {
    session->session_state=SSH_SESSION_STATE_SOCKET_CONNECTED;
    ssh_socket_set_fd(session->socket, session->opts.fd);
    ret=SSH_OK;
#ifndef _WIN32
  } else if (session->opts.ProxyCommand != NULL){
    ret = ssh_socket_connect_proxycommand(session->socket,
                                          session->opts.ProxyCommand);
#endif
  } else {
    ret=ssh_socket_connect(session->socket,
                           session->opts.host,
                           session->opts.port,
                           session->opts.bindaddr);
  }
  if (ret == SSH_ERROR) {
    return SSH_ERROR;
  }

  set_status(session, 0.2f);

  session->alive = 1;
  SSH_LOG(SSH_LOG_PROTOCOL,"Socket connecting, now waiting for the callbacks to work");
pending:
  session->pending_call_state=SSH_PENDING_CALL_CONNECT;
  if(ssh_is_blocking(session)) {
      int timeout = (session->opts.timeout * 1000) +
                    (session->opts.timeout_usec / 1000);
      if (timeout == 0) {
          timeout = 10 * 1000;
      }
      SSH_LOG(SSH_LOG_PACKET,"Actual timeout : %d", timeout);
      ret = ssh_handle_packets_termination(session, timeout, ssh_connect_termination, session);
      if (session->session_state != SSH_SESSION_STATE_ERROR &&
          (ret == SSH_ERROR || !ssh_connect_termination(session))) {
          ssh_set_error(session, SSH_FATAL,
                        "Timeout connecting to %s", session->opts.host);
          session->session_state = SSH_SESSION_STATE_ERROR;
      }
  }
  else {
      ret = ssh_handle_packets_termination(session,
                                           SSH_TIMEOUT_NONBLOCKING,
                                           ssh_connect_termination,
                                           session);
      if (ret == SSH_ERROR) {
          session->session_state = SSH_SESSION_STATE_ERROR;
      }
  }
  SSH_LOG(SSH_LOG_PACKET,"current state : %d",session->session_state);
  if(!ssh_is_blocking(session) && !ssh_connect_termination(session)){
    return SSH_AGAIN;
  }

  session->pending_call_state=SSH_PENDING_CALL_NONE;
  if(session->session_state == SSH_SESSION_STATE_ERROR || session->session_state == SSH_SESSION_STATE_DISCONNECTED)
  	return SSH_ERROR;
  return SSH_OK;
}

/**
 * @brief Get the issue banner from the server.
 *
 * This is the banner showing a disclaimer to users who log in,
 * typically their right or the fact that they will be monitored.
 *
 * @param[in]  session  The SSH session to use.
 *
 * @return A newly allocated string with the banner, NULL on error.
 */
char *ssh_get_issue_banner(ssh_session session) {
  if (session == NULL || session->banner == NULL) {
    return NULL;
  }

  return ssh_string_to_char(session->banner);
}

/**
 * @brief Get the version of the OpenSSH server, if it is not an OpenSSH server
 * then 0 will be returned.
 *
 * You can use the SSH_VERSION_INT macro to compare version numbers.
 *
 * @param[in]  session  The SSH session to use.
 *
 * @return The version number if available, 0 otherwise.
 *
 * @code
 * int openssh = ssh_get_openssh_version();
 *
 * if (openssh == SSH_INT_VERSION(6, 1, 0)) {
 *     printf("Version match!\m");
 * }
 * @endcode
 */
int ssh_get_openssh_version(ssh_session session) {
  if (session == NULL) {
    return 0;
  }

  return session->openssh;
}

/**
 * @brief Disconnect from a session (client or server).
 * The session can then be reused to open a new session.
 *
 * @param[in]  session  The SSH session to use.
 */
void ssh_disconnect(ssh_session session) {
  struct ssh_iterator *it;
  int rc;

  if (session == NULL) {
    return;
  }

  if (session->socket != NULL && ssh_socket_is_open(session->socket)) {
    rc = ssh_buffer_pack(session->out_buffer,
                         "bds",
                         SSH2_MSG_DISCONNECT,
                         SSH2_DISCONNECT_BY_APPLICATION,
                         "Bye Bye");
    if (rc != SSH_OK){
      ssh_set_error_oom(session);
      goto error;
    }

    packet_send(session);
    ssh_socket_close(session->socket);
  }
error:
  session->alive = 0;
  if (session->socket != NULL){
    ssh_socket_reset(session->socket);
  }
  session->opts.fd = SSH_INVALID_SOCKET;
  session->session_state=SSH_SESSION_STATE_DISCONNECTED;

  while ((it=ssh_list_get_iterator(session->channels)) != NULL) {
    ssh_channel_do_free(ssh_iterator_value(ssh_channel,it));
    ssh_list_remove(session->channels, it);
  }
  if(session->current_crypto){
    crypto_free(session->current_crypto);
    session->current_crypto=NULL;
  }
  if (session->in_buffer) {
    ssh_buffer_reinit(session->in_buffer);
  }
  if (session->out_buffer) {
    ssh_buffer_reinit(session->out_buffer);
  }
  if (session->in_hashbuf) {
    ssh_buffer_reinit(session->in_hashbuf);
  }
  if (session->out_hashbuf) {
    ssh_buffer_reinit(session->out_hashbuf);
  }
  session->auth_methods = 0;
  SAFE_FREE(session->serverbanner);
  SAFE_FREE(session->clientbanner);

  if(session->ssh_message_list){
    ssh_message msg;
    while((msg=ssh_list_pop_head(ssh_message ,session->ssh_message_list))
        != NULL){
      ssh_message_free(msg);
    }
    ssh_list_free(session->ssh_message_list);
    session->ssh_message_list=NULL;
  }

  if (session->packet_callbacks){
    ssh_list_free(session->packet_callbacks);
    session->packet_callbacks=NULL;
  }
}

const char *ssh_copyright(void) {
    return SSH_STRINGIFY(LIBSSH_VERSION) " (c) 2003-2014 Aris Adamantiadis, Andreas Schneider, "
    "and libssh contributors. Distributed under the LGPL, please refer to COPYING "
    "file for information about your rights";
}
/** @} */

/* vim: set ts=4 sw=4 et cindent: */
