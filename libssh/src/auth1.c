/*
 * auth1.c - authentication with SSH-1 protocol
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2005-2008 by Aris Adamantiadis
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

#include "libssh/priv.h"
#include "libssh/ssh1.h"
#include "libssh/buffer.h"
#include "libssh/packet.h"
#include "libssh/session.h"
#include "libssh/string.h"

#ifdef WITH_SSH1

static int ssh_auth_status_termination(void *s){
    ssh_session session=s;
    if(session->auth_state != SSH_AUTH_STATE_NONE ||
            session->session_state == SSH_SESSION_STATE_ERROR)
        return 1;
    return 0;
}

static int wait_auth1_status(ssh_session session) {
  /* wait for a packet */
  if (ssh_handle_packets_termination(session,SSH_TIMEOUT_USER,
          ssh_auth_status_termination, session) != SSH_OK){

      return SSH_AUTH_ERROR;
  }
  SSH_LOG(SSH_LOG_PROTOCOL,"Auth state : %d",session->auth_state);

  switch(session->auth_state) {
    case SSH_AUTH_STATE_SUCCESS:
      return SSH_AUTH_SUCCESS;
    case SSH_AUTH_STATE_FAILED:
      return SSH_AUTH_DENIED;
    default:
      return SSH_AUTH_AGAIN;
  }
  return SSH_AUTH_ERROR;
}

void ssh_auth1_handler(ssh_session session, uint8_t type){
  if(session->session_state != SSH_SESSION_STATE_AUTHENTICATING){
    ssh_set_error(session,SSH_FATAL,"SSH_SMSG_SUCCESS or FAILED received in wrong state");
    return;
  }
  if(type==SSH_SMSG_SUCCESS){
    session->auth_state=SSH_AUTH_STATE_SUCCESS;
    session->session_state=SSH_SESSION_STATE_AUTHENTICATED;
  } else if(type==SSH_SMSG_FAILURE)
    session->auth_state=SSH_AUTH_STATE_FAILED;
}

static int send_username(ssh_session session, const char *username) {
  ssh_string user = NULL;
  int rc;
  /* returns SSH_AUTH_SUCCESS or SSH_AUTH_DENIED */
  if(session->auth_service_state == SSH_AUTH_SERVICE_USER_SENT) {
    if(session->auth_state == SSH_AUTH_STATE_FAILED)
      return SSH_AUTH_DENIED;
    if(session->auth_state == SSH_AUTH_STATE_SUCCESS)
      return SSH_AUTH_SUCCESS;
    return SSH_AUTH_ERROR;
  }
  if (session->auth_service_state == SSH_AUTH_SERVICE_SENT)
      goto pending;
  if (!username) {
    if(!(username = session->opts.username)) {
      if (ssh_options_set(session, SSH_OPTIONS_USER, NULL) < 0) {
        session->auth_service_state = SSH_AUTH_SERVICE_DENIED;
        return SSH_ERROR;
      } else {
        username = session->opts.username;
      }
    }
  }
  user = ssh_string_from_char(username);
  if (user == NULL) {
    return SSH_AUTH_ERROR;
  }

  if (buffer_add_u8(session->out_buffer, SSH_CMSG_USER) < 0) {
    ssh_string_free(user);
    return SSH_AUTH_ERROR;
  }
  if (buffer_add_ssh_string(session->out_buffer, user) < 0) {
    ssh_string_free(user);
    return SSH_AUTH_ERROR;
  }
  ssh_string_free(user);
  session->auth_state=SSH_AUTH_STATE_NONE;
  session->auth_service_state = SSH_AUTH_SERVICE_SENT;
  if (packet_send(session) == SSH_ERROR) {
    return SSH_AUTH_ERROR;
  }
pending:
  rc = wait_auth1_status(session);
  switch (rc){
  case SSH_AUTH_SUCCESS:
    session->auth_service_state=SSH_AUTH_SERVICE_USER_SENT;
    session->auth_state=SSH_AUTH_STATE_SUCCESS;
    ssh_set_error(session, SSH_NO_ERROR, "Authentication successful");
    return SSH_AUTH_SUCCESS;
  case SSH_AUTH_DENIED:
    session->auth_service_state=SSH_AUTH_SERVICE_USER_SENT;
    ssh_set_error(session,SSH_REQUEST_DENIED,"Password authentication necessary for user %s",username);
    return SSH_AUTH_DENIED;
  case SSH_AUTH_AGAIN:
    return SSH_AUTH_AGAIN;
  default:
    session->auth_service_state = SSH_AUTH_SERVICE_NONE;
    session->auth_state=SSH_AUTH_STATE_ERROR;
    return SSH_AUTH_ERROR;
  }
}

/* use the "none" authentication question */
int ssh_userauth1_none(ssh_session session, const char *username){
    return send_username(session, username);
}

/** \internal
 * \todo implement ssh1 public key
 */
int ssh_userauth1_offer_pubkey(ssh_session session, const char *username,
    int type, ssh_string pubkey) {
  (void) session;
  (void) username;
  (void) type;
  (void) pubkey;

  return SSH_AUTH_DENIED;
}

int ssh_userauth1_password(ssh_session session, const char *username,
    const char *password) {
  ssh_string pwd = NULL;
  int rc;

  rc = send_username(session, username);
  if (rc != SSH_AUTH_DENIED) {
    return rc;
  }
  if (session->pending_call_state == SSH_PENDING_CALL_AUTH_PASSWORD)
      goto pending;
  /* we trick a bit here. A known flaw in SSH1 protocol is that it's
   * easy to guess password sizes.
   * not that sure ...
   */

  /* XXX fix me here ! */
  /* cisco IOS doesn't like when a password is followed by zeroes and random pad. */
  if(1 || strlen(password) >= 128) {
    /* not risky to disclose the size of such a big password .. */
    pwd = ssh_string_from_char(password);
    if (pwd == NULL) {
      return SSH_AUTH_ERROR;
    }
  } else {
    char buf[128] = {0};
    /* fill the password string from random things. the strcpy
     * ensure there is at least a nul byte after the password.
     * most implementation won't see the garbage at end.
     * why garbage ? because nul bytes will be compressed by
     * gzip and disclose password len.
     */
    pwd = ssh_string_new(sizeof(buf));
    if (pwd == NULL) {
      return SSH_AUTH_ERROR;
    }
    ssh_get_random(buf, sizeof(buf), 0);
    strcpy(buf, password);
    ssh_string_fill(pwd, buf, sizeof(buf));
  }

  if (buffer_add_u8(session->out_buffer, SSH_CMSG_AUTH_PASSWORD) < 0) {
    ssh_string_burn(pwd);
    ssh_string_free(pwd);

    return SSH_AUTH_ERROR;
  }
  if (buffer_add_ssh_string(session->out_buffer, pwd) < 0) {
    ssh_string_burn(pwd);
    ssh_string_free(pwd);

    return SSH_AUTH_ERROR;
  }

  ssh_string_burn(pwd);
  ssh_string_free(pwd);
  session->auth_state=SSH_AUTH_STATE_NONE;
  session->pending_call_state = SSH_PENDING_CALL_AUTH_PASSWORD;
  if (packet_send(session) == SSH_ERROR) {
    return SSH_AUTH_ERROR;
  }
pending:
  rc = wait_auth1_status(session);
  if (rc != SSH_AUTH_AGAIN)
      session->pending_call_state = SSH_PENDING_CALL_NONE;

  return rc;
}

#endif /* WITH_SSH1 */
/* vim: set ts=2 sw=2 et cindent: */
