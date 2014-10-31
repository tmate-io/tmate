/*
 * callbacks.c - callback functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009-2013  by Andreas Schneider <asn@cryptomilk.org>
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

#include "libssh/callbacks.h"
#include "libssh/session.h"


/* LEGACY */
static void ssh_legacy_log_callback(int priority,
                                    const char *function,
                                    const char *buffer,
                                    void *userdata)
{
    ssh_session session = (ssh_session)userdata;
    ssh_log_callback log_fn = session->common.callbacks->log_function;
    void *log_data = session->common.callbacks->userdata;

    (void)function; /* unused */

    log_fn(session, priority, buffer, log_data);
}

int ssh_set_callbacks(ssh_session session, ssh_callbacks cb) {
  if (session == NULL || cb == NULL) {
    return SSH_ERROR;
  }

  if(cb->size <= 0 || cb->size > 1024 * sizeof(void *)){
  	ssh_set_error(session,SSH_FATAL,
  			"Invalid callback passed in (badly initialized)");

  	return SSH_ERROR;
  }
  session->common.callbacks = cb;

  /* LEGACY */
  if (ssh_get_log_callback() == NULL && cb->log_function) {
      ssh_set_log_callback(ssh_legacy_log_callback);
      ssh_set_log_userdata(session);
  }

  return 0;
}

int ssh_set_channel_callbacks(ssh_channel channel, ssh_channel_callbacks cb) {
  ssh_session session = NULL;
  if (channel == NULL || cb == NULL) {
    return SSH_ERROR;
  }
  session = channel->session;

  if(cb->size <= 0 || cb->size > 1024 * sizeof(void *)){
  	ssh_set_error(session,SSH_FATAL,
  			"Invalid channel callback passed in (badly initialized)");

  	return SSH_ERROR;
  }
  channel->callbacks = cb;

  return 0;
}

int ssh_set_server_callbacks(ssh_session session, ssh_server_callbacks cb){
	if (session == NULL || cb == NULL) {
		return SSH_ERROR;
	}

	if(cb->size <= 0 || cb->size > 1024 * sizeof(void *)){
		ssh_set_error(session,SSH_FATAL,
				"Invalid callback passed in (badly initialized)");

		return SSH_ERROR;
	}
	session->server_callbacks = cb;

	return 0;
}
